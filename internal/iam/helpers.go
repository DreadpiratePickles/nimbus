package iam

import (
	"sort"
	"strings"
)

// AdminLevel grades a principal's administrative reach. The names match the
// aws collector's AdminLevel (none / conditional / full) so it can switch to
// IsAdmin in a later item.
type AdminLevel int

const (
	AdminNone AdminLevel = iota
	// AdminConditional: admin only if undecidable conditions hold (MFA, source IP, ...).
	AdminConditional
	AdminFull
)

func (l AdminLevel) String() string {
	return [...]string{"none", "conditional", "full"}[l]
}

// DecisionFunc evaluates one action on one resource for a fixed principal and
// policy set (typically a closure over Evaluate).
type DecisionFunc func(action, resource string) Decision

// privEscActions are IAM actions that let a principal grant itself (or take
// over a principal with) any permission. Kept in step with the collector.
var privEscActions = []string{
	"iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
	"iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
	"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
	"iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
	"iam:UpdateAssumeRolePolicy", "iam:AddUserToGroup", "iam:PassRole",
}

// adminSampleARNs are resources of unrelated services: a grant must cover
// all of them to count as "on every resource" (as the collector requires).
var adminSampleARNs = []string{
	"arn:aws:iam::123456789012:role/x",
	"arn:aws:s3:::bucket",
	"arn:aws:ec2:us-east-1:123456789012:instance/i-1",
}

func effectTri(e Effect) tri {
	switch e {
	case Allow:
		return yes
	case Unknown:
		return maybe
	}
	return no
}

// IsAdmin is AdminFull when some privilege-escalation action is allowed on
// every sampled resource, AdminConditional when the best such grant is
// Unknown, AdminNone otherwise. Unlike the collector's statement heuristic it
// sees every policy layer the DecisionFunc evaluates (SCPs, boundaries,
// conditioned denies), and a grant of a single escalation action on "*"
// (e.g. iam:PutRolePolicy) counts as admin.
func IsAdmin(fn DecisionFunc) AdminLevel {
	level := AdminNone
	for _, act := range privEscActions {
		worst := yes
		for _, arn := range adminSampleARNs {
			worst = and3(worst, effectTri(fn(act, arn).Effect))
			if worst == no {
				break
			}
		}
		switch worst {
		case yes:
			return AdminFull
		case maybe:
			level = AdminConditional
		}
	}
	return level
}

// sensitiveActions are always probed by AllowedActions in addition to the
// literal actions named in the policies, so wildcard grants (s3:*, NotAction)
// surface the actions later tracks care about (data access, escalation).
var sensitiveActions = append([]string{
	"s3:GetObject", "s3:PutObject", "s3:ListBucket",
	"rds:DescribeDBInstances", "rds:ModifyDBInstance", "rds-db:connect", "rds:CreateDBSnapshot",
	"secretsmanager:GetSecretValue", "kms:Decrypt", "sts:AssumeRole",
}, privEscActions...)

// ActionCatalog returns the literal (wildcard-free) actions named in the
// policies' Action / NotAction elements plus the built-in sensitive actions,
// deduplicated case-insensitively and sorted.
func ActionCatalog(policies ...Policy) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if strings.ContainsAny(a, "*?") || a == "" {
			return
		}
		if l := strings.ToLower(a); !seen[l] {
			seen[l] = true
			out = append(out, a)
		}
	}
	for _, p := range policies {
		for _, st := range p.Statement {
			for _, a := range st.Action {
				add(a)
			}
			for _, a := range st.NotAction {
				add(a)
			}
		}
	}
	for _, a := range sensitiveActions {
		add(a)
	}
	sort.Strings(out)
	return out
}

// AllowedActions evaluates every action of ActionCatalog(principalPolicies...)
// against resourceARN using only the given identity-based policies and an
// empty request context. It returns the actions that are allowed and those
// whose decision is Unknown, both sorted. No full service action list is
// used, so actions not named in the policies (and not built-in sensitive
// actions) are not reported.
func AllowedActions(resourceARN string, principalPolicies ...Policy) (allowed, unknown []string) {
	if len(principalPolicies) == 0 {
		return nil, nil
	}
	for _, act := range ActionCatalog(principalPolicies...) {
		d := EvaluateSet(Request{Action: act, Resource: resourceARN}, PolicySet{Identity: principalPolicies})
		switch d.Effect {
		case Allow:
			allowed = append(allowed, act)
		case Unknown:
			unknown = append(unknown, act)
		}
	}
	return allowed, unknown
}
