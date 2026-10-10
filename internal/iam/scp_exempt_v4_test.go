package iam

import "testing"

// TestV4SCPExemptBeforeDeny ports the verify-4 probes: principals the evaluator
// treats as SCP-exempt (service principals, service-linked roles and their
// sessions) must be exempt from SCP Deny statements too, not only from the
// SCP Allow gate (defect 8, evaluate.go SCP loop).
func TestV4SCPExemptBeforeDeny(t *testing.T) {
	deny := mustParse(t, "scpdeny", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`)
	all := mustParse(t, "id", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	rp := mustParse(t, "rp", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"*"}]}`)
	cases := []struct {
		name string
		req  Request
		ps   PolicySet
		want Effect
	}{
		{"service principal", Request{Principal: "cloudtrail.amazonaws.com", Action: "s3:PutObject", Resource: "arn:aws:s3:::b/k", ResourceAccount: "111111111111"},
			PolicySet{Resource: &rp, SCPs: [][]Policy{{deny}}}, Allow},
		{"service-linked role", Request{Principal: "arn:aws:iam::111111111111:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing", Action: "ec2:DescribeInstances", Resource: "*", ResourceAccount: "111111111111"},
			PolicySet{Identity: []Policy{all}, SCPs: [][]Policy{{deny}}}, Allow},
		{"service-linked role session", Request{Principal: "arn:aws:sts::111111111111:assumed-role/AWSServiceRoleForElasticLoadBalancing/ElasticLoadBalancing", Action: "ec2:DescribeInstances", Resource: "*", ResourceAccount: "111111111111"},
			PolicySet{Identity: []Policy{all}, SCPs: [][]Policy{{deny}}}, Allow},
		{"ordinary role still denied", Request{Principal: "arn:aws:iam::111111111111:role/app", Action: "ec2:DescribeInstances", Resource: "*", ResourceAccount: "111111111111"},
			PolicySet{Identity: []Policy{all}, SCPs: [][]Policy{{deny}}}, ExplicitDeny},
	}
	for _, c := range cases {
		if d := EvaluateSet(c.req, c.ps); d.Effect != c.want {
			t.Errorf("%s: want %s got %s (%v)", c.name, c.want, d.Effect, d.Reasons)
		}
	}
}
