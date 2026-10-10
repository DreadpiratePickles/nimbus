package graph_test

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Verify-5 C3/C4/C9: anonymous reach evaluates the S3 public access block (bucket and account,
// full or partial) before the policy, honours Deny statements, Resource / NotAction and
// SourceIp conditions through internal/iam's evaluator, reads organisation conditions by
// operator and value, and honours the collector's acl_public / public flags.
func v5pol(stmts string) string { return `{"Version":"2012-10-17","Statement":[` + stmts + `]}` }

const v5allowGet = `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`

func v5cond(op, k, v string) string {
	return `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"` + op + `":{"` + k + `":"` + v + `"}}}`
}

func v5first(rs []graph.WhoCanResult) string {
	if len(rs) == 0 {
		return "none"
	}
	switch rs[0].Principal {
	case graph.AnonymousPrincipal:
		return "anon"
	case graph.OrgWidePrincipal:
		return "org"
	}
	return "other:" + rs[0].Principal
}

func TestV5WhoCanAnonymous(t *testing.T) {
	type tc struct {
		name, action string
		attrs        map[string]any
		want         string // anon | org | none | notanon | notorg
	}
	pab := func(kv ...string) map[string]any {
		m := map[string]any{}
		for _, k := range kv {
			m[k] = true
		}
		return m
	}
	cases := []tc{
		// verifier's zzv5d probes
		{"a1 acl public-read", "s3:GetObject", map[string]any{"acl": "public-read"}, "anon"},
		{"a2 acl_grantees AllUsers URI", "s3:GetObject", map[string]any{"acl_grantees": []any{"http://acs.amazonaws.com/groups/global/AllUsers"}}, "anon"},
		{"a3 collector acl_public=true public=true", "s3:GetObject", map[string]any{"acl_public": true, "public": true, "public_access_block": false}, "anon"},
		{"b policy * GetObject", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet)}, "anon"},
		{"b2 resource_policy map", "s3:GetObject", map[string]any{"resource_policy": map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}}}}, "anon"},
		{"c1 PrincipalOrgID", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5cond("StringEquals", "aws:PrincipalOrgID", "o-x"))}, "org"},
		{"c2 PrincipalOrgPaths", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5cond("ForAnyValue:StringLike", "aws:PrincipalOrgPaths", "o-x/*"))}, "org"},
		{"c3 PrincipalAccount", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5cond("StringEquals", "aws:PrincipalAccount", "111111111111"))}, "org"},
		{"c4 SourceVpce", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5cond("StringEquals", "aws:SourceVpce", "vpce-1"))}, "org"},
		{"c5 SourceIp", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5cond("IpAddress", "aws:SourceIp", "203.0.113.0/24"))}, "notanon"},
		{"c6 StringNotEquals PrincipalOrgID (inverted)", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5cond("StringNotEquals", "aws:PrincipalOrgID", "o-x"))}, "anon"},
		{"c7 org Get + unconditional Put; ask Get", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5cond("StringEquals", "aws:PrincipalOrgID", "o-x") + `,{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}`)}, "org"},
		{"d1 Principal AWS:*", "s3:GetObject", map[string]any{"bucket_policy": v5pol(`{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`)}, "anon"},
		{"d2 Principal AWS:[*]", "s3:GetObject", map[string]any{"bucket_policy": v5pol(`{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"s3:*","Resource":"*"}`)}, "anon"},
		{"e1 Allow * + Deny * s3:*", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet + `,{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/*"}`)}, "none"},
		{"e2 Allow * + Deny unless PrincipalOrgID", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet + `,{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/*","Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"o-x"}}}`)}, "org"},
		{"e3 Allow * + Deny NotPrincipal role", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet + `,{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111111111111:role/r"},"Action":"s3:*","Resource":"arn:aws:s3:::b/*"}`)}, "none"},
		{"e4 Allow * + Deny SecureTransport false", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet + `,{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}`)}, "anon"},
		{"f1 acl + PAB bool true", "s3:GetObject", map[string]any{"acl": "public-read", "public_access_block": true}, "none"},
		{"f2 acl + PAB map Block/IgnorePublicAcls", "s3:GetObject", map[string]any{"acl": "public-read", "public_access_block": map[string]any{"BlockPublicAcls": true, "IgnorePublicAcls": true, "BlockPublicPolicy": false, "RestrictPublicBuckets": false}}, "none"},
		{"f3 acl + account PAB", "s3:GetObject", map[string]any{"acl": "public-read", "account_public_access_block": true, "public": false}, "none"},
		{"f4 policy + PAB bool true", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet), "public_access_block": true}, "none"},
		{"f5 policy + PAB map Restrict/BlockPublicPolicy", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet), "public_access_block": map[string]any{"RestrictPublicBuckets": true, "BlockPublicPolicy": true, "BlockPublicAcls": false, "IgnorePublicAcls": false}}, "none"},
		{"f6 policy + account PAB (collector)", "s3:GetObject", map[string]any{"resource_policy": v5pol(v5allowGet), "account_public_access_block": true, "public": false, "public_access_block": false}, "none"},
		{"h1 policy only PutObject; ask Get", "s3:GetObject", map[string]any{"bucket_policy": v5pol(`{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}`)}, "none"},
		{"h2 policy only PutObject; ask Put", "s3:PutObject", map[string]any{"bucket_policy": v5pol(`{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}`)}, "anon"},
		{"h3 policy ListBucket; ask ListBucket", "s3:ListBucket", map[string]any{"bucket_policy": v5pol(`{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b"}`)}, "anon"},
		{"h4 policy ListBucket; ask Get", "s3:GetObject", map[string]any{"bucket_policy": v5pol(`{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b"}`)}, "none"},
		{"h5 acl public-read-write; ask Put", "s3:PutObject", map[string]any{"acl": "public-read-write"}, "anon"},
		{"h6 Allow Get on other prefix; ask secret/x", "s3:GetObject", map[string]any{"bucket_policy": v5pol(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/public/*"}`)}, "none"},
		{"i1 org policy + public-read ACL", "s3:GetObject", map[string]any{"acl": "public-read", "bucket_policy": v5pol(v5cond("StringEquals", "aws:PrincipalOrgID", "o-x"))}, "anon"},
		{"i2 NotAction Allow *", "s3:GetObject", map[string]any{"bucket_policy": v5pol(`{"Effect":"Allow","Principal":"*","NotAction":"s3:DeleteObject","Resource":"arn:aws:s3:::b/*"}`)}, "anon"},
		// partial public access block maps (AWS semantics: IgnorePublicAcls neutralises existing
		// public ACLs, RestrictPublicBuckets existing public policies; BlockPublicAcls /
		// BlockPublicPolicy only refuse new ones)
		{"p1 partial PAB RestrictPublicBuckets only + policy", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet), "public_access_block": pab("RestrictPublicBuckets")}, "none"},
		{"p2 partial PAB IgnorePublicAcls only + ACL", "s3:GetObject", map[string]any{"acl": "public-read", "public_access_block": pab("IgnorePublicAcls")}, "none"},
		{"p3 partial PAB IgnorePublicAcls only + policy", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet), "public_access_block": pab("IgnorePublicAcls")}, "anon"},
		{"p4 partial PAB RestrictPublicBuckets only + ACL", "s3:GetObject", map[string]any{"acl": "public-read", "public_access_block": pab("RestrictPublicBuckets")}, "anon"},
		{"p5 account partial PAB map RestrictPublicBuckets + policy", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet), "account_public_access_block": pab("RestrictPublicBuckets")}, "none"},
		{"p6 snake_case partial PAB ignore_public_acls + ACL", "s3:GetObject", map[string]any{"acl": "public-read", "public_access_block": pab("ignore_public_acls")}, "none"},
		{"p7 RestrictPublicBuckets + org-conditioned policy stays org-wide", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5cond("StringEquals", "aws:PrincipalOrgID", "o-x")), "public_access_block": pab("RestrictPublicBuckets")}, "org"},
		{"p8 Restrict + Ignore partial: policy and ACL both neutralised", "s3:GetObject", map[string]any{"acl": "public-read", "bucket_policy": v5pol(v5allowGet), "public_access_block": pab("RestrictPublicBuckets", "IgnorePublicAcls")}, "none"},
		// Deny / Resource / NotAction / SourceIp
		{"q1 Deny * GetObject overrides a public ACL", "s3:GetObject", map[string]any{"acl": "public-read", "bucket_policy": v5pol(`{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`)}, "none"},
		{"q2 Deny on another prefix does not apply", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet + `,{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/other/*"}`)}, "anon"},
		{"q3 Deny NotAction GetObject leaves Get public", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet + `,{"Effect":"Deny","Principal":"*","NotAction":"s3:GetObject","Resource":"*"}`)}, "anon"},
		{"q4 Deny unless corporate SourceIp", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5allowGet + `,{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}`)}, "notanon"},
		{"q5 SourceIp 0.0.0.0/0 is still anonymous", "s3:GetObject", map[string]any{"bucket_policy": v5pol(v5cond("IpAddress", "aws:SourceIp", "0.0.0.0/0"))}, "anon"},
		{"q6 lower-case effect", "s3:GetObject", map[string]any{"bucket_policy": v5pol(`{"Effect":"allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`)}, "anon"},
		// collector flags
		{"r1 collector acl_public neutralised (public=false)", "s3:GetObject", map[string]any{"acl_public": true, "policy_public": false, "public": false, "public_access_block": false, "account_public_access_block": false}, "none"},
		{"r2 collector acl_public public=true", "s3:GetObject", map[string]any{"acl_public": true, "policy_public": false, "public": true, "public_access_block": false, "account_public_access_block": false}, "anon"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := graph.New()
			g.AddNode(&graph.Node{ID: "arn:aws:s3:::b", Type: "aws_s3_bucket", Provider: "aws", Account: "111111111111", Name: "b", Attributes: c.attrs})
			res := "arn:aws:s3:::b/secret/x"
			if c.action == "s3:ListBucket" {
				res = "arn:aws:s3:::b"
			}
			rs := graph.WhoCan(g, c.action, res, 4)
			got := v5first(rs)
			ok := got == c.want || c.want == "notanon" && got != "anon" || c.want == "notorg" && got != "org"
			if !ok {
				why := ""
				if len(rs) > 0 {
					why = rs[0].Because
				}
				t.Errorf("first principal %s, want %s (%s)", got, c.want, why)
			}
		})
	}
}

// The action-less verdict the attack-path entry uses (exposure.go) agrees.
func TestV5AnonymousReachEntry(t *testing.T) {
	for _, c := range []struct {
		name  string
		attrs map[string]any
		want  string
		why   string
	}{
		{"policy + PAB true", map[string]any{"bucket_policy": v5pol(v5allowGet), "public_access_block": true}, graph.AnonPrivate, "public access block"},
		{"policy + partial PAB RestrictPublicBuckets", map[string]any{"bucket_policy": v5pol(v5allowGet), "public_access_block": map[string]any{"RestrictPublicBuckets": true}}, graph.AnonPrivate, "RestrictPublicBuckets"},
		{"Allow * + Deny *", map[string]any{"bucket_policy": v5pol(v5allowGet + `,{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}`)}, graph.AnonPrivate, "deny"},
		{"SourceIp-limited Allow", map[string]any{"bucket_policy": v5pol(v5cond("IpAddress", "aws:SourceIp", "203.0.113.0/24"))}, graph.AnonPrivate, "aws:SourceIp"},
		{"org-conditioned", map[string]any{"bucket_policy": v5pol(v5cond("StringEquals", "aws:PrincipalOrgID", "o-x"))}, graph.AnonPrivate, "org-conditioned"},
		{"StringNotEquals org is anonymous", map[string]any{"bucket_policy": v5pol(v5cond("StringNotEquals", "aws:PrincipalOrgID", "o-x"))}, graph.AnonAnonymous, ""},
		{"public prefix only is still anonymous", map[string]any{"bucket_policy": v5pol(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/public/*"}`)}, graph.AnonAnonymous, ""},
		{"public policy", map[string]any{"bucket_policy": v5pol(v5allowGet)}, graph.AnonAnonymous, ""},
		{"flattened bucket_policy_principal * + PAB", map[string]any{"bucket_policy_principal": "*", "public_access_block": true}, graph.AnonPrivate, "public access block"},
		{"flattened bucket_policy_principal * (lab customer-pii)", map[string]any{"bucket_policy_principal": "*", "public_access_block": false}, graph.AnonAnonymous, ""},
	} {
		n := &graph.Node{ID: "arn:aws:s3:::b", Type: "aws_s3_bucket", Attributes: c.attrs}
		v, why := graph.AnonymousReachOf(n)
		if v != c.want || c.why != "" && !strings.Contains(strings.ToLower(why), strings.ToLower(c.why)) {
			t.Errorf("%s: %q (%s), want %q containing %q", c.name, v, why, c.want, c.why)
		}
	}
}
