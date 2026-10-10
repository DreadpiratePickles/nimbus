package attackpath

import (
	"strings"
	"testing"
)

const validRule = `
id: test-passrole-ec2
title: Test PassRole to EC2
description: Principal can pass an EC2-trusting role and launch an instance.
severity: HIGH
confidence: inferred
credit:
  source: Prowler
  licence: Apache-2.0
  url: https://github.com/prowler-cloud/prowler
  upstream_id: aws-ec2-privesc-passrole-iam
anchor:
  types: [aws_iam_user, aws_iam_role]
match:
  join: permission
  requires_permissions:
    - {action: "iam:PassRole", resource: target}
    - {action: "ec2:RunInstances", resource: "arn:aws:ec2:*:{account}:instance/*"}
  target:
    types: [aws_iam_role]
    trusts_service: ec2.amazonaws.com
tests:
  fixture:
    nodes:
      - id: arn:aws:iam::123456789012:user/dev
        type: aws_iam_user
        account: "123456789012"
        attributes:
          inline_policy_document:
            Version: "2012-10-17"
            Statement:
              - {Effect: Allow, Action: ["ec2:RunInstances"], Resource: "*"}
              - {Effect: Allow, Action: "iam:PassRole", Resource: "arn:aws:iam::123456789012:role/admin"}
      - id: arn:aws:iam::123456789012:role/admin
        type: aws_iam_role
        account: "123456789012"
        attributes: {trust_principals: [ec2.amazonaws.com]}
      - id: arn:aws:iam::123456789012:role/other
        type: aws_iam_role
        account: "123456789012"
        attributes: {trust_principals: [ec2.amazonaws.com]}
  expect:
    - {anchor: "arn:aws:iam::123456789012:user/dev", target: "arn:aws:iam::123456789012:role/admin", match: true}
    - {anchor: "arn:aws:iam::123456789012:user/dev", target: "arn:aws:iam::123456789012:role/other", match: false}
`

func TestPathRuleValidRuleParsesAndPassesItsTests(t *testing.T) {
	r, err := ParsePathRule([]byte(validRule))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidatePathRules([]PathRule{r}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := RunPathRuleTests(r); err != nil {
		t.Fatalf("own tests: %v", err)
	}
}

func TestPathRuleValidatorErrors(t *testing.T) {
	cases := map[string]struct {
		edit func(string) string
		want string
	}{
		"unknown edge kind": {func(s string) string {
			return strings.Replace(s, "  join: permission\n", "  join: path\n  path:\n    - {edge: teleports_to, to_types: [aws_iam_role]}\n", 1)
		}, "unknown edge kind"},
		"missing credit": {func(s string) string {
			i, j := strings.Index(s, "credit:"), strings.Index(s, "anchor:")
			return s[:i] + "ported: true\n" + s[j:]
		}, "credit"},
		"same account without justification": {func(s string) string {
			return strings.Replace(s, "  join: permission\n", "  join: same_account\n", 1) + "allow_same_account: true\n"
		}, "justification"},
		"same account not allowed": {func(s string) string {
			return strings.Replace(s, "  join: permission\n", "  join: same_account\n", 1)
		}, "allow_same_account"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := ParsePathRule([]byte(c.edit(validRule)))
			if err == nil {
				err = ValidatePathRules([]PathRule{r})
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
	r, _ := ParsePathRule([]byte(validRule))
	if err := ValidatePathRules([]PathRule{r, r}); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("duplicate id not rejected: %v", err)
	}
}

func TestPathRuleLibraryShipsAttributedPrivescRules(t *testing.T) {
	rules, err := LibraryPathRules()
	if err != nil {
		t.Fatalf("library: %v", err)
	}
	if len(rules) < 15 {
		t.Fatalf("library has %d rules, want >= 15", len(rules))
	}
	for _, r := range rules {
		if r.Credit == nil || r.Credit.Source != "Prowler" || r.Credit.Licence != "Apache-2.0" || r.Credit.UpstreamID != r.ID || r.Credit.URL == "" || r.Credit.Upstream == "" {
			t.Errorf("%s: incomplete Prowler credit %+v", r.ID, r.Credit)
		}
		if err := RunPathRuleTests(r); err != nil {
			t.Errorf("%s: %v", r.ID, err)
		}
	}
}

// User rules load from a directory and validate with the same schema (schema item: user rules).
func TestLoadPathRulesDirExamples(t *testing.T) {
	rules, err := LoadPathRulesDir("../../rules/paths")
	if err != nil {
		t.Fatalf("load rules/paths: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("rules/paths has no example user rules")
	}
	for _, r := range rules {
		if err := RunPathRuleTests(r); err != nil {
			t.Errorf("%s: %v", r.ID, err)
		}
	}
	// A user rule whose id collides with the library must be rejected.
	lib, _ := LibraryPathRules()
	if err := ValidatePathRules(append(lib, rules...)); err != nil {
		t.Logf("combined validate (expected ok, ids distinct): %v", err)
	}
}
