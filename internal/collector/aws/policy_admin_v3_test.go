package aws

import "testing"

// Verify-3 defect 8: an Allow that can write or attach any policy to any IAM
// principal (iam:Put*, iam:Attach*, exact PutUserPolicy, ...) on every IAM resource
// (Resource "*" or "arn:aws:iam::*:*") is administrative.
func TestAdminLevelSelfGrantWildcards(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want AdminLevel
	}{
		{"iam:Put* on *", `{"Statement":[{"Effect":"Allow","Action":"iam:Put*","Resource":"*"}]}`, AdminFull},
		{"iam:Attach* on *", `{"Statement":[{"Effect":"Allow","Action":["iam:Attach*"],"Resource":"*"}]}`, AdminFull},
		{"iam:PutUserPolicy on *", `{"Statement":[{"Effect":"Allow","Action":"iam:PutUserPolicy","Resource":"*"}]}`, AdminFull},
		{"iam:CreatePolicyVersion on *", `{"Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion","Resource":"*"}]}`, AdminFull},
		{"iam:* on arn:aws:iam::*:*", `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::*:*"}]}`, AdminFull},
		{"* on arn:aws:iam::*:*", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:iam::*:*"}]}`, AdminFull},
		{"iam:Put* on arn:aws:iam::*:*", `{"Statement":[{"Effect":"Allow","Action":"iam:Put*","Resource":["arn:aws:iam::*:*"]}]}`, AdminFull},
		{"iam:Put* on * with MFA", `{"Statement":[{"Effect":"Allow","Action":"iam:Put*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, AdminConditional},
		{"iam:Put* + Deny iam:Put*", `{"Statement":[{"Effect":"Allow","Action":"iam:Put*","Resource":"*"},{"Effect":"Deny","Action":"iam:Put*","Resource":"arn:aws:iam::*:*"}]}`, AdminNone},
		// not admin
		{"iam:Put* on one role", `{"Statement":[{"Effect":"Allow","Action":"iam:Put*","Resource":"arn:aws:iam::123456789012:role/app"}]}`, AdminNone},
		{"iam:* on roles only of one path", `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::123456789012:role/app/*"}]}`, AdminNone},
		{"iam:PutRolePermissionsBoundary only", `{"Statement":[{"Effect":"Allow","Action":"iam:PutRolePermissionsBoundary","Resource":"*"}]}`, AdminNone},
		{"iam:Get* on *", `{"Statement":[{"Effect":"Allow","Action":"iam:Get*","Resource":"*"}]}`, AdminNone},
		// Integration pass 2 item 5 (deliberate change): one privilege-escalation action on every
		// IAM resource is admin under the evaluator (iam:PassRole on * hands any role to compute).
		{"PassRole + RunInstances", `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"}]}`, AdminFull},
		{"s3:* on arn:aws:iam::*:*", `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:iam::*:*"}]}`, AdminNone},
	}
	for _, c := range cases {
		d, err := ParsePolicy(c.doc)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := d.AdminLevel(); got != c.want {
			t.Errorf("%s: AdminLevel=%v want %v", c.name, got, c.want)
		}
	}
}
