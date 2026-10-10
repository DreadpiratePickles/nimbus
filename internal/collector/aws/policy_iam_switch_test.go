package aws

import "testing"

// Integration pass 2 item 5: AdminLevel / IsAdmin delegate to the internal/iam evaluator
// (iam.IsAdmin over the parsed policy). These shapes are decided by the evaluator and were
// misgraded by the statement heuristic.
func TestAdminLevelDelegatesToIAMEvaluator(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want AdminLevel
	}{
		{"single escalation action on *: CreateAccessKey", `{"Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}]}`, AdminFull},
		{"single escalation action on *: UpdateAssumeRolePolicy", `{"Statement":[{"Effect":"Allow","Action":"iam:UpdateAssumeRolePolicy","Resource":"*"}]}`, AdminFull},
		{"conditioned Deny on iam:* leaves admin undecided", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`, AdminConditional},
		{"Allow with an unknown-key condition is conditional", `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`, AdminConditional},
		{"URL-encoded document", `%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22*%22%2C%22Resource%22%3A%22*%22%7D%5D%7D`, AdminFull},
		{"read-only is not admin", `{"Statement":[{"Effect":"Allow","Action":["s3:Get*","ec2:Describe*"],"Resource":"*"}]}`, AdminNone},
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
