package aws

import (
	"encoding/json"
	"net/url"
	"path"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/iam"
)

// PolicyDocument is an IAM policy (identity, resource or trust) document.
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
	// evaluated is the same document parsed by internal/iam (nil when the evaluator could
	// not parse it, or the document was built in code): AdminLevel delegates to it.
	evaluated *iam.Policy
}

// Statement is one IAM statement. String-or-list fields are normalized to slices.
type Statement struct {
	Sid          string
	Effect       string
	Action       []string
	NotAction    []string
	Resource     []string
	NotResource  []string
	Principal    map[string][]string // "AWS" | "Service" | "Federated" | "*" -> values
	HasCondition bool
}

type rawStatement struct {
	Sid         string          `json:"Sid"`
	Effect      string          `json:"Effect"`
	Action      json.RawMessage `json:"Action"`
	NotAction   json.RawMessage `json:"NotAction"`
	Resource    json.RawMessage `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
	Principal   json.RawMessage `json:"Principal"`
	Condition   json.RawMessage `json:"Condition"`
}

// ParsePolicy decodes a policy document; IAM returns them URL-encoded, so a
// percent-encoded input is unescaped first.
func ParsePolicy(doc string) (PolicyDocument, error) {
	doc = strings.TrimSpace(doc)
	if strings.HasPrefix(doc, "%7B") || strings.HasPrefix(doc, "%7b") {
		if d, err := url.QueryUnescape(doc); err == nil {
			doc = d
		}
	}
	var raw struct {
		Version   string          `json:"Version"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		return PolicyDocument{}, err
	}
	var stmts []rawStatement
	if s := strings.TrimSpace(string(raw.Statement)); strings.HasPrefix(s, "{") {
		var one rawStatement
		if err := json.Unmarshal(raw.Statement, &one); err != nil {
			return PolicyDocument{}, err
		}
		stmts = []rawStatement{one}
	} else if len(raw.Statement) > 0 {
		if err := json.Unmarshal(raw.Statement, &stmts); err != nil {
			return PolicyDocument{}, err
		}
	}
	out := PolicyDocument{Version: raw.Version}
	if p, err := iam.ParsePolicy([]byte(doc)); err == nil {
		out.evaluated = &p
	}
	for _, r := range stmts {
		s := Statement{
			Sid: r.Sid, Effect: r.Effect,
			Action: strList(r.Action), NotAction: strList(r.NotAction),
			Resource: strList(r.Resource), NotResource: strList(r.NotResource),
			HasCondition: hasCondition(r.Condition),
		}
		s.Principal = principalMap(r.Principal)
		out.Statement = append(out.Statement, s)
	}
	return out, nil
}

// hasCondition reports a non-empty Condition block ({} / { } / null are no condition).
func hasCondition(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err == nil {
		return len(m) > 0
	}
	return string(raw) != "null"
}

func strList(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

func principalMap(raw json.RawMessage) map[string][]string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var star string
	if err := json.Unmarshal(raw, &star); err == nil {
		return map[string][]string{"*": {star}}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	out := map[string][]string{}
	for k, v := range m {
		out[k] = strList(v)
	}
	return out
}

// wildMatch matches IAM-style globs (* and ?) case-insensitively.
func wildMatch(pattern, value string) bool {
	ok, err := path.Match(strings.ToLower(strings.ReplaceAll(pattern, "/", "\x00")), strings.ToLower(strings.ReplaceAll(value, "/", "\x00")))
	return err == nil && ok
}

// actionAllowed reports whether a statement's Action list covers the action.
func actionAllowed(actions []string, action string) bool {
	for _, a := range actions {
		if a == "*" || wildMatch(a, action) {
			return true
		}
	}
	return false
}

// privEscActions are IAM actions that let a principal grant itself any permission.
// An Allow+NotAction statement that leaves any of them reachable is administrative.
var privEscActions = []string{
	"iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
	"iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
	"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
	"iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
	"iam:UpdateAssumeRolePolicy", "iam:AddUserToGroup", "iam:PassRole",
}

// directGrantActions let a principal write or attach any policy to any IAM principal
// (itself included) in one call: on every IAM resource each one alone is admin.
var directGrantActions = []string{
	"iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
	"iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
	"iam:CreatePolicyVersion",
}

// iamSampleARNs are the IAM resources the privilege-escalation actions act on (users,
// roles, groups, policies). Every privEscAction is an IAM action, so a Resource
// pattern matching all of them ("*", "arn:*", "arn:aws:iam::*:*", ...) is broad
// enough for admin even when it does not match other services' resources.
var iamSampleARNs = []string{
	"arn:aws:iam::123456789012:role/x", "arn:aws:iam::123456789012:role/path/x",
	"arn:aws:iam::123456789012:user/x", "arn:aws:iam::123456789012:group/x",
	"arn:aws:iam::123456789012:policy/x",
}

func patternCoversIAM(p string) bool {
	if p == "*" {
		return true
	}
	for _, arn := range iamSampleARNs {
		if !wildMatch(p, arn) {
			return false
		}
	}
	return true
}

// broadResource reports a statement that applies to every IAM resource: Resource "*"
// (or a pattern such as "arn:*" or "arn:aws:iam::*:*"), or a NotResource exclusion
// that leaves IAM resources (NotResource "*" excludes everything and grants nothing).
func (s Statement) broadResource() bool {
	if len(s.Resource) == 0 && len(s.NotResource) > 0 {
		for _, r := range s.NotResource {
			if patternCoversIAM(r) {
				return false
			}
		}
		return true
	}
	for _, r := range s.Resource {
		if patternCoversIAM(r) {
			return true
		}
	}
	return false
}

// coversAction reports whether the statement's Action / NotAction covers action.
func (s Statement) coversAction(action string) bool {
	if len(s.NotAction) > 0 {
		return !actionAllowed(s.NotAction, action)
	}
	return actionAllowed(s.Action, action)
}

// adminActions reports whether the statement's action set amounts to admin and which
// actions must stay un-denied for it to remain admin: Action "*" / "*:*" / "iam:*" or a
// NotAction that leaves a privilege-escalation action allowed (escalation =
// privEscActions); otherwise an Action list (globs included, e.g. "iam:Put*") that
// covers a direct-grant action (escalation = directGrantActions).
func (s Statement) adminActions() (bool, []string) {
	for _, a := range s.Action {
		if a == "*" || a == "*:*" || strings.EqualFold(a, "iam:*") {
			return true, privEscActions
		}
	}
	if len(s.NotAction) > 0 {
		for _, act := range privEscActions {
			if !actionAllowed(s.NotAction, act) {
				return true, privEscActions
			}
		}
		return false, nil
	}
	for _, act := range directGrantActions {
		if actionAllowed(s.Action, act) {
			return true, directGrantActions
		}
	}
	return false, nil
}

// deniedEverywhere reports an unconditional Deny on every resource for action. A
// conditioned or resource-scoped Deny is not counted (it may not apply).
func (d PolicyDocument) deniedEverywhere(action string) bool {
	for _, s := range d.Statement {
		if s.Effect == "Deny" && !s.HasCondition && s.broadResource() && s.coversAction(action) {
			return true
		}
	}
	return false
}

// AdminLevel grades a policy's administrative reach.
type AdminLevel int

const (
	AdminNone AdminLevel = iota
	// AdminConditional: admin only when an Allow statement's Condition holds (e.g. MFA).
	AdminConditional
	AdminFull
)

func (l AdminLevel) String() string {
	return [...]string{"none", "conditional", "full"}[l]
}

// AdminLevel grades the document with the internal/iam evaluator (integration pass 2 item 5):
// iam.IsAdmin probes every privilege-escalation action, each judged on every IAM resource
// shape (users, roles, groups, policies; the escalation actions are all IAM actions, so a
// grant on "arn:aws:iam::*:*" counts as on every resource). Unknown decisions (conditions
// whose keys are not in the context, including on a Deny that may apply) are
// AdminConditional. Two deliberate differences from the former statement heuristic: an
// Allow * with a conditioned Deny * is conditional (was full), and a single escalation
// action on * — iam:PassRole, iam:CreateAccessKey, ... — is full (was none). A document the
// evaluator could not parse falls back to the heuristic (heuristicAdminLevel). Graph edges
// are not derived from this yet; node attrs admin / admin_level are.
func (d PolicyDocument) AdminLevel() AdminLevel {
	if d.evaluated == nil {
		return d.heuristicAdminLevel()
	}
	pol := *d.evaluated
	decide := func(action, _ string) iam.Decision {
		// Worst decision over the IAM resource shapes: allow only if allowed on all of them.
		var out iam.Decision
		for i, arn := range iamSampleARNs {
			dec := iam.Evaluate(iam.Request{Principal: "arn:aws:iam::123456789012:role/probe", Action: action, Resource: arn}, []iam.Policy{pol}, nil, nil, nil, nil)
			if i == 0 || effectRank(dec.Effect) < effectRank(out.Effect) {
				out = dec
			}
		}
		return out
	}
	switch iam.IsAdmin(decide) {
	case iam.AdminFull:
		return AdminFull
	case iam.AdminConditional:
		return AdminConditional
	}
	return AdminNone
}

// effectRank orders decisions for the worst-of combination: deny < unknown < allow.
func effectRank(e iam.Effect) int {
	switch e {
	case iam.Allow:
		return 2
	case iam.Unknown:
		return 1
	}
	return 0
}

// heuristicAdminLevel is the former statement heuristic: AdminFull for an unconditioned
// Allow statement that grants admin actions (adminActions) on every resource, with at least
// one privilege-escalation action it grants not removed by an unconditioned Deny on every
// resource; AdminConditional when only conditioned Allow statements qualify. Effect is
// case-sensitive, as in IAM. Used only when internal/iam cannot parse the document.
func (d PolicyDocument) heuristicAdminLevel() AdminLevel {
	level := AdminNone
	for _, s := range d.Statement {
		admin, escalation := s.adminActions()
		if s.Effect != "Allow" || !admin || !s.broadResource() {
			continue
		}
		open := false
		for _, act := range escalation {
			if s.coversAction(act) && !d.deniedEverywhere(act) {
				open = true
				break
			}
		}
		if !open {
			continue
		}
		if !s.HasCondition {
			return AdminFull
		}
		level = AdminConditional
	}
	return level
}

// IsAdmin reports full (unconditional) administrative privileges (AdminLevel).
func (d PolicyDocument) IsAdmin() bool { return d.AdminLevel() == AdminFull }

// DataAccess is one datastore grant derived from a policy.
type DataAccess struct {
	Service string // s3 | rds | secretsmanager
	// Resources are ARN patterns; "*" means every datastore of that service in the account.
	Resources []string
	Actions   []string
}

var dataActions = map[string][]string{
	"s3":             {"s3:GetObject", "s3:PutObject", "s3:ListBucket"},
	"rds":            {"rds:DescribeDBInstances", "rds:ModifyDBInstance", "rds-db:connect", "rds:CreateDBSnapshot"},
	"secretsmanager": {"secretsmanager:GetSecretValue"},
}

// DataAccess lists the datastore services this policy grants access to.
func (d PolicyDocument) DataAccess() []DataAccess {
	var out []DataAccess
	for _, svc := range []string{"s3", "rds", "secretsmanager"} {
		da := DataAccess{Service: svc}
		seenRes := map[string]bool{}
		seenAct := map[string]bool{}
		for _, s := range d.Statement {
			if !strings.EqualFold(s.Effect, "Allow") {
				continue
			}
			matched := false
			for _, want := range dataActions[svc] {
				if actionAllowed(s.Action, want) {
					matched = true
					if !seenAct[want] {
						seenAct[want] = true
						da.Actions = append(da.Actions, want)
					}
				}
			}
			if !matched {
				continue
			}
			for _, r := range s.Resource {
				if r == "*" || resourceService(r) == svc || (svc == "rds" && resourceService(r) == "rds-db") {
					if !seenRes[r] {
						seenRes[r] = true
						da.Resources = append(da.Resources, r)
					}
				}
			}
		}
		if len(da.Resources) > 0 {
			out = append(out, da)
		}
	}
	return out
}

func resourceService(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// MatchesResource reports whether an ARN pattern from a policy covers a concrete
// datastore ARN. S3 object patterns (bucket/*) cover their bucket.
func MatchesResource(pattern, arn string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "arn:aws:s3:::") {
		bucketPat := strings.TrimPrefix(pattern, "arn:aws:s3:::")
		if i := strings.Index(bucketPat, "/"); i >= 0 {
			bucketPat = bucketPat[:i]
		}
		return wildMatch(bucketPat, strings.TrimPrefix(arn, "arn:aws:s3:::"))
	}
	if strings.HasPrefix(pattern, "arn:aws:rds-db:") {
		// rds-db:connect resources name the DB resource id, not the instance ARN; match per account/region.
		pp := strings.SplitN(pattern, ":", 6)
		ap := strings.SplitN(arn, ":", 6)
		return len(pp) == 6 && len(ap) == 6 && (pp[3] == "*" || pp[3] == ap[3]) && (pp[4] == "*" || pp[4] == ap[4])
	}
	return wildMatch(pattern, arn)
}

// TrustedPrincipal is one entity allowed to assume a role.
type TrustedPrincipal struct {
	Kind        string // aws | service | federated | any
	Value       string
	Account     string // for aws principals
	Conditional bool
}

// TrustedPrincipals lists the principals an assume-role trust policy allows.
func (d PolicyDocument) TrustedPrincipals() []TrustedPrincipal {
	var out []TrustedPrincipal
	for _, s := range d.Statement {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if !actionAllowed(s.Action, "sts:AssumeRole") && !actionAllowed(s.Action, "sts:AssumeRoleWithWebIdentity") && !actionAllowed(s.Action, "sts:AssumeRoleWithSAML") {
			continue
		}
		for k, vals := range s.Principal {
			for _, v := range vals {
				tp := TrustedPrincipal{Value: v, Conditional: s.HasCondition}
				switch strings.ToLower(k) {
				case "*":
					tp.Kind = "any"
				case "aws":
					tp.Kind = "aws"
					if v == "*" {
						tp.Kind = "any"
					} else {
						tp.Account = principalAccount(v)
					}
				case "service":
					tp.Kind = "service"
				case "federated":
					tp.Kind = "federated"
				default:
					tp.Kind = strings.ToLower(k)
				}
				out = append(out, tp)
			}
		}
	}
	return out
}

func principalAccount(p string) string {
	if len(p) == 12 && strings.Trim(p, "0123456789") == "" {
		return p
	}
	parts := strings.Split(p, ":")
	if len(parts) >= 5 && strings.HasPrefix(p, "arn:") {
		return parts[4]
	}
	return ""
}
