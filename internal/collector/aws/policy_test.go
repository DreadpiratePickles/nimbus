package aws

import (
	"net/url"
	"reflect"
	"testing"
)

func TestParsePolicyShapes(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		admin   bool
		actions []string
	}{
		{"single statement object", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, true, []string{"*"}},
		{"url encoded", url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":["*:*"],"Resource":["*"]}]}`), true, []string{"*:*"}},
		{"deny is not admin", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`, false, []string{"*"}},
		{"conditional admin ignored", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, false, []string{"*"}},
		{"scoped", `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`, false, []string{"s3:GetObject"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParsePolicy(tc.doc)
			if err != nil {
				t.Fatal(err)
			}
			if d.IsAdmin() != tc.admin {
				t.Errorf("IsAdmin = %v", d.IsAdmin())
			}
			if !reflect.DeepEqual(d.Statement[0].Action, tc.actions) {
				t.Errorf("actions = %v", d.Statement[0].Action)
			}
		})
	}
	if _, err := ParsePolicy("not json"); err == nil {
		t.Error("expected parse error")
	}
}

func TestDataAccess(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want map[string][]string
	}{
		{"s3 read on bucket objects", `{"Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"arn:aws:s3:::data/*"}]}`, map[string][]string{"s3": {"arn:aws:s3:::data/*"}}},
		{"admin covers everything", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, map[string][]string{"s3": {"*"}, "rds": {"*"}, "secretsmanager": {"*"}}},
		{"secrets only", `{"Statement":[{"Effect":"Allow","Action":["secretsmanager:GetSecretValue"],"Resource":"arn:aws:secretsmanager:us-east-1:1:secret:x"}]}`, map[string][]string{"secretsmanager": {"arn:aws:secretsmanager:us-east-1:1:secret:x"}}},
		{"rds connect", `{"Statement":[{"Effect":"Allow","Action":"rds-db:connect","Resource":"arn:aws:rds-db:us-east-1:1:dbuser:db-ABC/app"}]}`, map[string][]string{"rds": {"arn:aws:rds-db:us-east-1:1:dbuser:db-ABC/app"}}},
		{"unrelated", `{"Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`, map[string][]string{}},
		{"deny ignored", `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`, map[string][]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParsePolicy(tc.doc)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string][]string{}
			for _, da := range d.DataAccess() {
				got[da.Service] = da.Resources
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestMatchesResource(t *testing.T) {
	cases := []struct {
		pattern, arn string
		want         bool
	}{
		{"*", "arn:aws:s3:::x", true},
		{"arn:aws:s3:::prod-*", "arn:aws:s3:::prod-data", true},
		{"arn:aws:s3:::prod-*/*", "arn:aws:s3:::prod-data", true},
		{"arn:aws:s3:::prod-*", "arn:aws:s3:::dev-data", false},
		{"arn:aws:secretsmanager:us-east-1:1:secret:db-*", "arn:aws:secretsmanager:us-east-1:1:secret:db-pass", true},
		{"arn:aws:secretsmanager:us-east-1:1:secret:db-*", "arn:aws:secretsmanager:us-east-1:1:secret:api", false},
		{"arn:aws:rds-db:us-east-1:1:dbuser:*/*", "arn:aws:rds:us-east-1:1:db:orders", true},
		{"arn:aws:rds-db:eu-west-1:1:dbuser:*/*", "arn:aws:rds:us-east-1:1:db:orders", false},
	}
	for _, tc := range cases {
		if got := MatchesResource(tc.pattern, tc.arn); got != tc.want {
			t.Errorf("MatchesResource(%q,%q) = %v", tc.pattern, tc.arn, got)
		}
	}
}

func TestTrustedPrincipals(t *testing.T) {
	doc := `{"Statement":[
	 {"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::222222222222:root","333333333333"],"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"},
	 {"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"x"}}},
	 {"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"},
	 {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::444444444444:root"},"Action":"s3:GetObject"}]}`
	d, err := ParsePolicy(doc)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]TrustedPrincipal{}
	for _, tp := range d.TrustedPrincipals() {
		got[tp.Value] = tp
	}
	if len(got) != 5 {
		t.Fatalf("principals = %v", got)
	}
	if got["arn:aws:iam::222222222222:root"].Account != "222222222222" || got["333333333333"].Account != "333333333333" {
		t.Error("account extraction failed")
	}
	if got["*"].Kind != "any" || !got["*"].Conditional {
		t.Error("wildcard principal should be any + conditional")
	}
	if got["ec2.amazonaws.com"].Kind != "service" {
		t.Error("service principal")
	}
	if _, ok := got["arn:aws:iam::444444444444:root"]; ok {
		t.Error("non-assume statement must be ignored")
	}
}
