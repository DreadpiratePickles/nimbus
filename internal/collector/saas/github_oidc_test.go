package saas

import "testing"

func TestClassifyOIDCSubject(t *testing.T) {
	cases := []struct{ sub, want string }{
		{"", OIDCSubjectWildcard},
		{"*", OIDCSubjectWildcard},
		{"repo:*", OIDCSubjectWildcard},
		{"repo:nimbus-lab/*", OIDCSubjectWildcard},
		{"repo:nimbus-lab/infra-*:ref:refs/heads/main", OIDCSubjectWildcard},
		{"repo:nimbus-lab/infra-live:*", OIDCSubjectUnpinned},
		{"repo:nimbus-lab/infra-live:ref:refs/heads/*", OIDCSubjectUnpinned},
		{"repo:nimbus-lab/infra-live:pull_request", OIDCSubjectUnpinned},
		{"repo:nimbus-lab/infra-live:ref:refs/heads/main", OIDCSubjectPinned},
		{"repo:nimbus-lab/infra-live:ref:refs/tags/v1.2.0", OIDCSubjectPinned},
		{"repo:nimbus-lab/infra-live:environment:production", OIDCSubjectPinned},
		{"repo:Nimbus-Lab/Infra-Live:environment:prod?", OIDCSubjectUnpinned},
	}
	for _, c := range cases {
		if got, why := ClassifyOIDCSubject(c.sub); got != c.want || why == "" {
			t.Errorf("ClassifyOIDCSubject(%q) = %q (%q), want %q", c.sub, got, why, c.want)
		}
	}
}

func TestGitHubOIDCTrustFromPolicy(t *testing.T) {
	pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity",
	 "Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
	 "Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
	              "StringLike":{"token.actions.githubusercontent.com:sub":["repo:acme/app:*","repo:acme/ops:ref:refs/heads/main"]}}}]}`
	tr, ok := GitHubOIDCTrust(pol)
	if !ok || tr.NoSubject || len(tr.Subjects) != 2 || tr.Subjects[0] != "repo:acme/app:*" {
		t.Fatalf("trust = %+v ok=%v", tr, ok)
	}
	if c := tr.Class(); c != OIDCSubjectUnpinned {
		t.Fatalf("worst class = %q, want unpinned", c)
	}
	// No sub condition: any repository on GitHub.
	nosub := map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": map[string]any{"Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
		"Condition": map[string]any{"StringEquals": map[string]any{"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}}}}
	tr, ok = GitHubOIDCTrust(nosub)
	if !ok || !tr.NoSubject || tr.Class() != OIDCSubjectWildcard {
		t.Fatalf("no-sub trust = %+v ok=%v", tr, ok)
	}
	// Not a GitHub trust.
	if _, ok := GitHubOIDCTrust(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`); ok {
		t.Fatal("ec2 service trust read as GitHub OIDC")
	}
	// Deny statements and garbage never count.
	if _, ok := GitHubOIDCTrust(`{"Statement":[{"Effect":"Deny","Principal":{"Federated":"token.actions.githubusercontent.com"}}]}`); ok {
		t.Fatal("deny statement read as a trust")
	}
	if _, ok := GitHubOIDCTrust("not json"); ok {
		t.Fatal("garbage read as a trust")
	}
}

func TestOIDCSubjectsFromText(t *testing.T) {
	cases := map[string][]string{
		"GitHub OIDC sub repo:nimbus-lab/infra-live:*":                                                 {"repo:nimbus-lab/infra-live:*"},
		"token.actions.githubusercontent.com sub=repo:nimbus-lab/payments-service:ref:refs/heads/main": {"repo:nimbus-lab/payments-service:ref:refs/heads/main"},
		"token.actions.githubusercontent.com aud=sts.amazonaws.com (no sub condition)":                 {""},
		"plain text with no subject":                                                                   nil,
	}
	for in, want := range cases {
		got := OIDCSubjectsFromText(in)
		if len(got) != len(want) || (len(want) > 0 && got[0] != want[0]) {
			t.Errorf("OIDCSubjectsFromText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOIDCSubjectMatchesRepo(t *testing.T) {
	for _, c := range []struct {
		sub, repo string
		want      bool
	}{
		{"repo:acme/app:*", "github.com/acme/app", true},
		{"repo:acme/app:*", "github:repo/acme/app", true},
		{"repo:acme/app:*", "acme/app", true},
		{"repo:acme/*", "github.com/acme/other", true},
		{"", "github.com/acme/app", true},
		{"repo:acme/app:*", "github.com/acme/application", false},
		{"repo:evil/app:*", "github.com/acme/app", false},
	} {
		if got := OIDCSubjectMatchesRepo(c.sub, c.repo); got != c.want {
			t.Errorf("OIDCSubjectMatchesRepo(%q, %q) = %v, want %v", c.sub, c.repo, got, c.want)
		}
	}
}
