package iam

import (
	"strings"
	"testing"
)

func TestManagedPolicyBuiltins(t *testing.T) {
	admin, exact, ok := ManagedPolicy("arn:aws:iam::aws:policy/AdministratorAccess")
	if !ok || !exact {
		t.Fatalf("AdministratorAccess: ok=%v exact=%v", ok, exact)
	}
	d := Evaluate(Request{Principal: "arn:aws:iam::111111111111:role/r", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", ResourceAccount: "111111111111"}, []Policy{admin}, nil, nil, nil, nil)
	if d.Effect != Allow {
		t.Fatalf("AdministratorAccess s3:GetObject = %s", d.Effect)
	}
	if admin.ID != "arn:aws:iam::aws:policy/AdministratorAccess" {
		t.Errorf("builtin id = %q", admin.ID)
	}
	pu, exact, ok := ManagedPolicy("arn:aws:iam::aws:policy/PowerUserAccess")
	if !ok || exact {
		t.Fatalf("PowerUserAccess: ok=%v exact=%v (documented shape, not exact)", ok, exact)
	}
	if d := Evaluate(Request{Principal: "arn:aws:iam::111111111111:role/r", Action: "iam:PassRole", Resource: "arn:aws:iam::111111111111:role/x"}, []Policy{pu}, nil, nil, nil, nil); d.Effect != ImplicitDeny {
		t.Errorf("PowerUserAccess iam:PassRole = %s, want implicit_deny", d.Effect)
	}
	ro, _, ok := ManagedPolicy("ReadOnlyAccess")
	if !ok {
		t.Fatal("ReadOnlyAccess by bare name")
	}
	for act, want := range map[string]Effect{"s3:GetObject": Allow, "secretsmanager:GetSecretValue": ImplicitDeny, "kms:Decrypt": ImplicitDeny, "sts:AssumeRole": ImplicitDeny} {
		res := "arn:aws:s3:::b/k"
		if !strings.HasPrefix(act, "s3:") {
			res = "*"
		}
		if d := Evaluate(Request{Principal: "arn:aws:iam::111111111111:role/r", Action: act, Resource: res, ResourceAccount: "111111111111"}, []Policy{ro}, nil, nil, nil, nil); d.Effect != want {
			t.Errorf("ReadOnlyAccess %s = %s, want %s", act, d.Effect, want)
		}
	}
	if _, _, ok := ManagedPolicy("arn:aws:iam::123456789012:policy/AdministratorAccess"); ok {
		t.Error("a customer policy named AdministratorAccess is not the AWS managed policy")
	}
}

func TestResourceProbes(t *testing.T) {
	cases := []struct {
		typ, arn string
		tier     Tier
		action   string
		resource string
	}{
		{"aws_s3_bucket", "arn:aws:s3:::pii", TierRead, "s3:GetObject", "arn:aws:s3:::pii/*"},
		{"aws_s3_bucket", "arn:aws:s3:::pii", TierWrite, "s3:PutObject", "arn:aws:s3:::pii/*"},
		{"aws_s3_bucket", "arn:aws:s3:::pii", TierAdmin, "s3:PutBucketPolicy", "arn:aws:s3:::pii"},
		{"aws_dynamodb_table", "arn:aws:dynamodb:us-east-1:111111111111:table/t", TierRead, "dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:111111111111:table/t"},
		{"aws_kms_key", "arn:aws:kms:us-east-1:111111111111:key/k", TierRead, "kms:Decrypt", "arn:aws:kms:us-east-1:111111111111:key/k"},
		{"aws_secretsmanager_secret", "arn:aws:secretsmanager:us-east-1:111111111111:secret:s", TierRead, "secretsmanager:GetSecretValue", "arn:aws:secretsmanager:us-east-1:111111111111:secret:s"},
		{"aws_lambda_function", "arn:aws:lambda:us-east-1:111111111111:function:f", TierInvoke, "lambda:InvokeFunction", "arn:aws:lambda:us-east-1:111111111111:function:f"},
		{"aws_iam_role", "arn:aws:iam::111111111111:role/r", TierAssume, "sts:AssumeRole", "arn:aws:iam::111111111111:role/r"},
		{"aws_iam_role", "arn:aws:iam::111111111111:role/r", TierPass, "iam:PassRole", "arn:aws:iam::111111111111:role/r"},
	}
	for _, c := range cases {
		found := false
		for _, p := range ResourceProbes(c.typ, c.arn) {
			if p.Tier == c.tier && p.Action == c.action {
				found = true
				if p.Resource != c.resource {
					t.Errorf("%s %s resource = %s, want %s", c.typ, c.action, p.Resource, c.resource)
				}
			}
		}
		if !found {
			t.Errorf("%s: no %s probe %s", c.typ, c.tier, c.action)
		}
	}
	for _, p := range ResourceProbes("aws_s3_bucket", "arn:aws:s3:::pii") {
		if p.Tier == TierRead && p.Action == "s3:ListBucket" {
			t.Error("s3:ListBucket is metadata, not a data read")
		}
	}
	if ps := ResourceProbes("aws_vpc", "arn:aws:ec2:us-east-1:1:vpc/v"); len(ps) != 0 {
		t.Errorf("unsupported type probes = %v", ps)
	}
}
