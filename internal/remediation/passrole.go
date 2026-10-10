package remediation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"text/template"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// PassRole scoping (competitive delta r2 #12). A principal that may iam:PassRole an admin role to
// EC2 and run instances escalates to that role (attackpath edge fix PRIVESC_PASSROLE, P13). The
// fix keeps every other permission and scopes PassRole: the escalation role is dropped from the
// passable roles ("*" is replaced by the roles the principal still needs), and the remaining
// grant is conditioned on iam:PassedToService. ScopePassRole computes the policy diff;
// PassRoleFix renders the iam_passrole_scope.tf template and its sidecar.

// PassRoleTemplate is the template file of the PassRole scoping fix.
const PassRoleTemplate = "iam_passrole_scope.tf"

// CanonicalPassRole is the canonical id the synthetic PassRole fix finding carries.
const CanonicalPassRole = "IAM_PASSROLE_ESCALATION"

// PassRoleInput names one escalation edge to cut.
type PassRoleInput struct {
	Principal string   // ARN of the user / role holding iam:PassRole
	Role      string   // the escalation role it must no longer pass
	Technique string   // e.g. iam:PassRole+ec2:RunInstances
	Statement string   // statement reference that grants PassRole (policy#sid)
	PolicyARN string   // managed policy ARN, or "" for an inline policy
	Document  any      // the policy document holding the statement (map or JSON), optional
	KeepRoles []string // roles the principal may still pass (default none)
	Service   string   // the service PassRole is for (default ec2.amazonaws.com)
}

// PolicyDiff is the before / after of a policy document (pretty JSON) and the changed lines.
type PolicyDiff struct {
	Before  string   `json:"before"`
	After   string   `json:"after"`
	Changed bool     `json:"changed"`
	Lines   []string `json:"lines"` // "- old" / "+ new" lines
}

// ScopePassRole rewrites every Allow statement granting iam:PassRole: the PassRole grant is split
// out of mixed statements and its resources become keep (or the statement's own resources minus
// the escalation roles and any wildcard), with Condition StringEquals iam:PassedToService =
// service; with no resource left the grant is removed. A statement that grants PassRole only
// through an action wildcard ("*", "iam:*") is kept and a Deny on the escalation roles is added.
func ScopePassRole(doc any, escalation, keep []string, service string) (PolicyDiff, error) {
	if service == "" {
		service = "ec2.amazonaws.com"
	}
	m, err := policyMap(doc)
	if err != nil {
		return PolicyDiff{}, err
	}
	before, _ := json.MarshalIndent(m, "", "  ")
	stmts := statementList(m["Statement"])
	var out []any
	changed := false
	esc := map[string]bool{}
	for _, r := range escalation {
		esc[r] = true
	}
	var denies []string
	for _, raw := range stmts {
		st, ok := raw.(map[string]any)
		eff, _ := st["Effect"].(string)
		if !ok || !strings.EqualFold(eff, "Allow") || st["NotAction"] != nil {
			out = append(out, raw)
			continue
		}
		var exact, wild, other []string
		for _, a := range strList(st["Action"]) {
			switch la := strings.ToLower(a); {
			case la == "iam:passrole":
				exact = append(exact, a)
			case actionMatches(la, "iam:passrole"):
				wild = append(wild, a)
			default:
				other = append(other, a)
			}
		}
		if len(exact) == 0 && len(wild) == 0 {
			out = append(out, raw)
			continue
		}
		changed = true
		if len(wild) > 0 {
			out = append(out, raw) // keep the wildcard grant; a Deny below removes the escalation
			denies = append(denies, escalation...)
			continue
		}
		if len(other) > 0 {
			rest := copyMap(st)
			rest["Action"] = anyList(other)
			out = append(out, rest)
		}
		res := keep
		if len(res) == 0 {
			for _, r := range strList(st["Resource"]) {
				if !esc[r] && !strings.Contains(r, "*") {
					res = append(res, r)
				}
			}
		}
		var scoped []string
		for _, r := range res {
			if !esc[r] && r != "*" {
				scoped = append(scoped, r)
			}
		}
		if len(scoped) == 0 {
			continue // nothing left to pass: the grant goes
		}
		ps := map[string]any{"Effect": "Allow", "Action": "iam:PassRole", "Resource": anyList(scoped)}
		sid, _ := st["Sid"].(string)
		ps["Sid"] = sid + "Scoped"
		cond := map[string]any{}
		if c, ok := st["Condition"].(map[string]any); ok {
			for k, v := range c {
				cond[k] = v
			}
		}
		se, _ := cond["StringEquals"].(map[string]any)
		if se == nil {
			se = map[string]any{}
		}
		se["iam:PassedToService"] = service
		cond["StringEquals"] = se
		ps["Condition"] = cond
		out = append(out, ps)
	}
	if len(denies) > 0 {
		d := map[string]any{"Sid": "DenyEscalationPassRole", "Effect": "Deny", "Action": "iam:PassRole"}
		if len(uniqStr(denies)) > 0 {
			d["Resource"] = anyList(uniqStr(denies))
		} else {
			d["Resource"] = "*"
		}
		out = append(out, d)
	}
	m2 := copyMap(m)
	m2["Statement"] = out
	after, _ := json.MarshalIndent(m2, "", "  ")
	pd := PolicyDiff{Before: string(before), After: string(after), Changed: changed}
	if changed {
		pd.Lines = lineDiff(pd.Before, pd.After)
	}
	return pd, nil
}

// PassRoleFix renders the PassRole scoping fix for one escalation edge (Terraform).
func PassRoleFix(in PassRoleInput) (*Fix, error) {
	if in.Principal == "" || in.Role == "" {
		return nil, fmt.Errorf("passrole fix: principal and role are required")
	}
	if in.Service == "" {
		in.Service = "ec2.amazonaws.com"
	}
	var diff []string
	if in.Document != nil {
		d, err := ScopePassRole(in.Document, []string{in.Role}, in.KeepRoles, in.Service)
		if err != nil {
			return nil, err
		}
		diff = d.Lines
	}
	keep := make([]any, 0, len(in.KeepRoles))
	for _, r := range in.KeepRoles {
		keep = append(keep, r)
	}
	f := model.Finding{ID: "passrole:" + in.Principal + ">" + in.Role, CanonicalID: CanonicalPassRole, Status: model.Fail, Provider: "aws",
		Title: "iam:PassRole lets " + in.Principal + " escalate to " + in.Role,
		Resource: model.Resource{ID: in.Principal, Type: "aws_iam_principal", Attributes: map[string]any{
			"escalation_role": in.Role, "technique": in.Technique, "statement": in.Statement, "policy_arn": in.PolicyARN,
			"passed_to_service": in.Service, "allowed_roles": keep}}}
	c := buildCtx(f, Terraform)
	c.Attr["policy_diff"] = diff // lines; rendered as comments only
	raw, err := fs.ReadFile(templateFS, path.Join("templates", PassRoleTemplate))
	if err != nil {
		return nil, err
	}
	tpl, err := template.New(PassRoleTemplate).Funcs(funcs).Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("template %s: %w", PassRoleTemplate, err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, c); err != nil {
		return nil, fmt.Errorf("render %s: %w", PassRoleTemplate, err)
	}
	meta, err := renderMetadata(PassRoleTemplate, c)
	if err != nil {
		return nil, err
	}
	fix := &Fix{Finding: f, CanonicalID: CanonicalPassRole, Format: Terraform, Template: PassRoleTemplate, Metadata: meta,
		Content: header(f, Terraform) + buf.String(), FileName: "iam_passrole_scope_" + c.Slug + ".tf"}
	fix.Apply, fix.Steps = applySteps(Terraform, fix.FileName, c, false)
	return fix, nil
}

func policyMap(doc any) (map[string]any, error) {
	switch x := doc.(type) {
	case string:
		var m map[string]any
		if err := json.Unmarshal([]byte(x), &m); err != nil {
			return nil, fmt.Errorf("policy document: %w", err)
		}
		return m, nil
	case []byte:
		return policyMap(string(x))
	case map[string]any:
		return x, nil
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return policyMap(string(b))
}

func statementList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case map[string]any:
		return []any{x}
	}
	return nil
}

func strList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func anyList(ss []string) any {
	if len(ss) == 1 {
		return ss[0]
	}
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func copyMap(m map[string]any) map[string]any {
	c := make(map[string]any, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func uniqStr(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// actionMatches matches a lower-case IAM action pattern (* and ?) against a lower-case action.
func actionMatches(p, a string) bool {
	if p == "" {
		return a == ""
	}
	switch p[0] {
	case '*':
		for i := 0; i <= len(a); i++ {
			if actionMatches(p[1:], a[i:]) {
				return true
			}
		}
		return false
	case '?':
		return a != "" && actionMatches(p[1:], a[1:])
	}
	return a != "" && p[0] == a[0] && actionMatches(p[1:], a[1:])
}

// lineDiff lists the lines only in before ("- ") and only in after ("+ "), in order.
func lineDiff(before, after string) []string {
	b, a := strings.Split(before, "\n"), strings.Split(after, "\n")
	inA, inB := map[string]int{}, map[string]int{}
	for _, l := range a {
		inA[l]++
	}
	for _, l := range b {
		inB[l]++
	}
	var out []string
	for _, l := range b {
		if inA[l] == 0 {
			out = append(out, "- "+l)
		}
	}
	for _, l := range a {
		if inB[l] == 0 {
			out = append(out, "+ "+l)
		}
	}
	return out
}
