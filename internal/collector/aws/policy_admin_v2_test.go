package aws

import "testing"

// V2 defect 8 (AWS IsAdmin): Deny statements, Conditions, iam:* and broad resource
// patterns. Adapted from the verifier probe zz_verify_policy_test.go.
func TestAdminLevel(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want AdminLevel
	}{
		{"NotAction iam:* only", `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`, AdminNone},
		{"NotAction iam:Put* leaves Attach/PassRole", `{"Statement":[{"Effect":"Allow","NotAction":["iam:Put*"],"Resource":"*"}]}`, AdminFull},
		{"NotAction uppercase IAM:*", `{"Statement":[{"Effect":"Allow","NotAction":["IAM:*"],"Resource":"*"}]}`, AdminNone},
		{"Action *:*", `{"Statement":[{"Effect":"Allow","Action":"*:*","Resource":"*"}]}`, AdminFull},
		{"Action list with *", `{"Statement":[{"Effect":"Allow","Action":["s3:*","*"],"Resource":["arn:aws:s3:::x","*"]}]}`, AdminFull},
		{"Action iam:* on *", `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`, AdminFull},
		{"Action iam:* on one role is not admin", `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::1:role/x"}]}`, AdminNone},
		{"Action * on arn:*", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:*"}]}`, AdminFull},
		{"Allow * + Deny *", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*"}]}`, AdminNone},
		{"Allow * + Deny iam:*", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`, AdminNone},
		{"Allow * + Deny s3:* is still admin", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`, AdminFull},
		// Integration pass 2 item 5 (IAM evaluator switch-over, deliberate change): the Deny may
		// apply, so admin cannot be proven without aws:SecureTransport in the context.
		{"Allow * + conditioned Deny * is conditional", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, AdminConditional},
		{"Allow * + Deny NotAction s3:* (denies iam)", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","NotAction":"s3:*","Resource":"*"}]}`, AdminNone},
		{"Allow * with MFA condition", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, AdminConditional},
		{"Allow * NotResource *", `{"Statement":[{"Effect":"Allow","Action":"*","NotResource":"*"}]}`, AdminNone},
		{"Condition empty object", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{}}]}`, AdminFull},
		{"Condition whitespace object", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{ }}]}`, AdminFull},
		{"Effect lowercase allow (invalid)", `{"Statement":[{"Effect":"allow","Action":"*","Resource":"*"}]}`, AdminNone},
	}
	for _, c := range cases {
		d, err := ParsePolicy(c.doc)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := d.AdminLevel(); got != c.want {
			t.Errorf("%s: AdminLevel=%v want %v", c.name, got, c.want)
		}
		if d.IsAdmin() != (c.want == AdminFull) {
			t.Errorf("%s: IsAdmin=%v", c.name, d.IsAdmin())
		}
	}
}
