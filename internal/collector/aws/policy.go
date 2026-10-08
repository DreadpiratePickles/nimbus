package aws

import (
	"encoding/json"
	"net/url"
	"path"
	"strings"
)

// PolicyDocument is an IAM policy (identity, resource or trust) document.
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
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
	for _, r := range stmts {
		s := Statement{
			Sid: r.Sid, Effect: r.Effect,
			Action: strList(r.Action), NotAction: strList(r.NotAction),
			Resource: strList(r.Resource), NotResource: strList(r.NotResource),
			HasCondition: len(r.Condition) > 0 && string(r.Condition) != "null" && string(r.Condition) != "{}",
		}
		s.Principal = principalMap(r.Principal)
		out.Statement = append(out.Statement, s)
	}
	return out, nil
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

// IsAdmin reports a statement that allows every action on every resource.
func (d PolicyDocument) IsAdmin() bool {
	for _, s := range d.Statement {
		if !strings.EqualFold(s.Effect, "Allow") || s.HasCondition {
			continue
		}
		allActions := false
		for _, a := range s.Action {
			if a == "*" || a == "*:*" {
				allActions = true
			}
		}
		if !allActions {
			continue
		}
		for _, r := range s.Resource {
			if r == "*" {
				return true
			}
		}
	}
	return false
}

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
