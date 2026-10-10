package graph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const pAcct = "111111111111"

func inv(id, typ, acct string, attrs map[string]any, rels ...model.Relation) model.Finding {
	return model.Finding{ID: "inv-" + id, CheckID: "lab_inventory", Status: model.Pass, Provider: "aws", Account: acct,
		Resource: model.Resource{ID: id, Type: typ, Name: lastSegment(id), Attributes: attrs, Relations: rels}}
}

func fail(id, typ, acct string, attrs map[string]any, weak ...string) model.Finding {
	f := inv(id, typ, acct, attrs)
	f.ID, f.Status, f.CheckID, f.Weaknesses = "fail-"+id, model.Fail, "iam_aws_attached_policy_no_administrative_privileges", weak
	return f
}

func rel(kind, to string) model.Relation { return model.Relation{ID: to, Kind: kind} }

func edge(g *Graph, from, to, kind string) *Edge {
	for _, e := range g.Out(from) {
		if e.To == to && e.Kind == kind {
			return e
		}
	}
	return nil
}

func doc(stmts ...map[string]any) map[string]any {
	l := make([]any, len(stmts))
	for i, s := range stmts {
		l[i] = s
	}
	return map[string]any{"Version": "2012-10-17", "Statement": l}
}

var (
	roleA   = "arn:aws:iam::" + pAcct + ":role/intake"
	bucketA = "arn:aws:s3:::claims-pii"
)

// F02: Allow s3:* + explicit Deny s3:GetObject removes the declared read edge, and the role
// node records which statement denied it.
func TestPermissionDenyRemovesReadEdge(t *testing.T) {
	g := New()
	g.AttachFindings([]model.Finding{
		inv(roleA, "aws_iam_role", pAcct, map[string]any{"inline_policy_document": doc(
			map[string]any{"Sid": "ClaimsIntake", "Effect": "Allow", "Action": "s3:*", "Resource": []any{bucketA, bucketA + "/*"}},
			map[string]any{"Sid": "NoClaimsRead", "Effect": "Deny", "Action": "s3:GetObject", "Resource": bucketA + "/*"})},
			rel("grants_access_to", bucketA)),
		inv(bucketA, "aws_s3_bucket", pAcct, nil),
	})
	if e := edge(g, roleA, bucketA, EdgeGrantsAccessTo); e != nil {
		t.Fatalf("explicit Deny s3:GetObject left the read edge: %v", e.Attr)
	}
	n, _ := g.Node(roleA)
	if s := deniedText(n); !strings.Contains(s, "NoClaimsRead") || !strings.Contains(s, bucketA) {
		t.Errorf("denied record = %q", s)
	}
}

func deniedText(n *Node) string {
	b, _ := json.Marshal(n.Attributes[AttrDeniedEdges])
	s, _ := n.Attributes["denied_by"].(string)
	return string(b) + " " + s
}

// An allowed read with exact documents and no conditions is verified and carries the statement.
func TestPermissionVerifiedEdge(t *testing.T) {
	g := New()
	g.AttachFindings([]model.Finding{
		inv(roleA, "aws_iam_role", pAcct, map[string]any{"inline_policy_document": doc(
			map[string]any{"Sid": "Read", "Effect": "Allow", "Action": "s3:GetObject", "Resource": bucketA + "/*"})},
			rel("grants_access_to", bucketA)),
		inv(bucketA, "aws_s3_bucket", pAcct, nil),
	})
	e := edge(g, roleA, bucketA, EdgeGrantsAccessTo)
	if e == nil {
		t.Fatal("read edge missing")
	}
	p, ok := e.Permission()
	if !ok || p.Effect != "Allow" || !strings.HasSuffix(p.Statement, "#Read") || len(p.Actions) == 0 || p.Actions[0] != "s3:GetObject" {
		t.Errorf("permission = %+v", p)
	}
	if c := e.Confidence(); c != model.ConfidenceVerified {
		t.Errorf("confidence = %q, want verified", c)
	}
	if !strings.Contains(e.Because(), "s3:GetObject") {
		t.Errorf("because = %q", e.Because())
	}
}

// A conditioned allow whose key the scan cannot know is inferred, with the key listed.
func TestPermissionConditionalInferred(t *testing.T) {
	g := New()
	g.AttachFindings([]model.Finding{
		inv(roleA, "aws_iam_role", pAcct, map[string]any{"inline_policy_document": doc(
			map[string]any{"Sid": "Office", "Effect": "Allow", "Action": "s3:GetObject", "Resource": bucketA + "/*",
				"Condition": map[string]any{"IpAddress": map[string]any{"aws:SourceIp": "203.0.113.0/24"}}})},
			rel("grants_access_to", bucketA)),
		inv(bucketA, "aws_s3_bucket", pAcct, nil),
	})
	e := edge(g, roleA, bucketA, EdgeGrantsAccessTo)
	if e == nil {
		t.Fatal("conditioned read edge removed (unknown is not deny)")
	}
	p, _ := e.Permission()
	if e.Confidence() != model.ConfidenceInferred || len(p.UnknownConditions) == 0 {
		t.Errorf("confidence %q unknown %v", e.Confidence(), p.UnknownConditions)
	}
}

// Declared edges without documents keep their confidence (typed relation = verified, scanner
// hint = hint); an SCP deny still removes them (F09).
func TestPermissionNoDocumentsAndSCPDeny(t *testing.T) {
	other := "arn:aws:s3:::member-records"
	role2 := "arn:aws:iam::222222222222:role/records"
	g := New()
	g.AttachFindings([]model.Finding{
		inv(roleA, "aws_iam_role", pAcct, map[string]any{"inline_policy": "s3:GetObject on claims"}, rel("grants_access_to", bucketA)),
		inv(bucketA, "aws_s3_bucket", pAcct, nil),
		inv(role2, "aws_iam_role", "222222222222", map[string]any{"inline_policy": "s3:GetObject on records",
			"governing_scps": []any{map[string]any{"id": "p-nodataread", "statement": map[string]any{"Effect": "Deny", "Action": "s3:GetObject", "Resource": other + "/*"}}}},
			rel("grants_access_to", other)),
		inv(other, "aws_s3_bucket", "222222222222", nil),
	})
	e := edge(g, roleA, bucketA, EdgeGrantsAccessTo)
	if e == nil || e.Confidence() != model.ConfidenceVerified {
		t.Fatalf("declared edge without documents: %v", e)
	}
	if e := edge(g, role2, other, EdgeGrantsAccessTo); e != nil {
		t.Fatalf("SCP deny left the read edge: %v", e.Attr)
	}
	n, _ := g.Node(role2)
	if s := deniedText(n); !strings.Contains(s, "p-nodataread") || !strings.Contains(s, "scp") {
		t.Errorf("denied record = %q", s)
	}
}

// S01: an SCP that denies everything to the role neutralises its AdministratorAccess: the
// admin weakness and the admin attachment leave the graph view, the reason stays on the node.
// A sibling role the SCP condition does not match keeps its admin.
func TestPermissionSCPNeutralisesAdmin(t *testing.T) {
	batch := "arn:aws:iam::222222222222:role/batch"
	sib := "arn:aws:iam::222222222222:role/sibling"
	scps := []any{map[string]any{"id": "p-lab0quarantine", "name": "quarantine", "statement": map[string]any{
		"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": map[string]any{"ArnLike": map[string]any{"aws:PrincipalArn": batch}}}}}
	admin := []any{"arn:aws:iam::aws:policy/AdministratorAccess"}
	g := New()
	g.AttachFindings([]model.Finding{
		fail(batch, "aws_iam_role", "222222222222", map[string]any{"attached_policies": admin, "governing_scps": scps}, "OVERPRIVILEGED_IDENTITY"),
		fail(sib, "aws_iam_role", "222222222222", map[string]any{"attached_policies": admin, "governing_scps": scps}, "OVERPRIVILEGED_IDENTITY"),
	})
	n, _ := g.Node(batch)
	if n.HasWeakness("OVERPRIVILEGED_IDENTITY") {
		t.Error("SCP-denied role still carries OVERPRIVILEGED_IDENTITY")
	}
	if l := toStringList(n.Attributes["attached_policies"]); len(l) != 0 {
		t.Errorf("attached_policies still lists %v", l)
	}
	if s, _ := n.Attributes["denied_by"].(string); !strings.Contains(s, "p-lab0quarantine") {
		t.Errorf("denied_by = %q", s)
	}
	if v, _ := n.Attributes["effective_admin"].(string); v != "none" {
		t.Errorf("effective_admin = %q", v)
	}
	s, _ := g.Node(sib)
	if !s.HasWeakness("OVERPRIVILEGED_IDENTITY") || len(toStringList(s.Attributes["attached_policies"])) != 1 {
		t.Errorf("sibling lost its admin: %v %v", s.Weaknesses, s.Attributes["attached_policies"])
	}
	// Idempotent: re-attaching the same findings (scan.go attaches twice) neutralises again.
	g.AttachFindings([]model.Finding{fail(batch, "aws_iam_role", "222222222222", map[string]any{"attached_policies": admin, "governing_scps": scps}, "OVERPRIVILEGED_IDENTITY")})
	if n, _ := g.Node(batch); n.HasWeakness("OVERPRIVILEGED_IDENTITY") {
		t.Error("second AttachFindings restored the admin weakness")
	}
}

// can_assume across accounts needs the caller's sts:AssumeRole: a caller whose policy denies
// it loses the edge; an unknown caller keeps it as inferred with caller_permission unknown.
func TestPermissionCanAssumeCallerSide(t *testing.T) {
	target := "arn:aws:iam::" + pAcct + ":role/vendor"
	caller := "arn:aws:iam::333333333333:role/ci"
	trust := doc(map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": []any{caller, "arn:aws:iam::999999999999:root"}}, "Action": "sts:AssumeRole"})
	g := New()
	g.AttachFindings([]model.Finding{
		inv(target, "aws_iam_role", pAcct, map[string]any{"trust_policy": trust}),
		inv(caller, "aws_iam_role", "333333333333", map[string]any{"inline_policy_document": doc(
			map[string]any{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
			map[string]any{"Sid": "NoAssume", "Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"})},
			rel("can_assume", target)),
		inv("arn:aws:iam::999999999999:root", "aws_iam_root", "999999999999", nil, rel("can_assume", target)),
	})
	if e := edge(g, caller, target, EdgeCanAssume); e != nil {
		t.Fatalf("caller-side Deny sts:AssumeRole left can_assume: %v", e.Attr)
	}
	e := edge(g, "arn:aws:iam::999999999999:root", target, EdgeCanAssume)
	if e == nil {
		t.Fatal("unknown caller lost its can_assume")
	}
	if e.Confidence() != model.ConfidenceInferred || e.Attr["caller_permission"] != "unknown" {
		t.Errorf("unknown caller edge = %v", e.Attr)
	}
}

// iam:PassRole on an EC2-trusting role with an instance profile + ec2:RunInstances is a way
// to obtain the role's credentials (pathfinding.cloud PassRole+RunInstances): can_assume with
// a technique. Admins do not get escalation edges (they already hold everything).
func TestPermissionPassRoleEscalation(t *testing.T) {
	user := "arn:aws:iam::" + pAcct + ":user/dev-sam"
	adminU := "arn:aws:iam::" + pAcct + ":user/ops"
	target := "arn:aws:iam::" + pAcct + ":role/ec2-admin"
	g := New()
	g.AttachFindings([]model.Finding{
		inv(user, "aws_iam_user", pAcct, map[string]any{"inline_policy_document": doc(
			map[string]any{"Sid": "Launch", "Effect": "Allow", "Action": []any{"ec2:RunInstances"}, "Resource": "*"},
			map[string]any{"Sid": "Pass", "Effect": "Allow", "Action": "iam:PassRole", "Resource": target})}),
		inv(adminU, "aws_iam_user", pAcct, map[string]any{"attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}),
		inv(target, "aws_iam_role", pAcct, map[string]any{"trust_principals": []any{"ec2.amazonaws.com"},
			"instance_profile": "arn:aws:iam::" + pAcct + ":instance-profile/p", "attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}),
	})
	e := edge(g, user, target, EdgeCanAssume)
	if e == nil {
		t.Fatal("PassRole+RunInstances escalation edge missing")
	}
	if e.Attr["technique"] != TechniquePassRoleEC2 {
		t.Errorf("technique = %v", e.Attr["technique"])
	}
	if p, _ := e.Permission(); !strings.Contains(p.Statement, "#Pass") {
		t.Errorf("statement = %q", p.Statement)
	}
	if edge(g, adminU, target, EdgeCanAssume) != nil {
		t.Error("admin principal got an escalation edge")
	}
}

func labFindings(t *testing.T) []model.Finding {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "lab", "local", "out", "estate.findings.json"))
	if err != nil {
		t.Fatalf("lab findings: %v", err)
	}
	var fs []model.Finding
	if err := json.Unmarshal(data, &fs); err != nil {
		t.Fatal(err)
	}
	return fs
}

// The lab estate after the permission pass: F02 / F09 read edges gone, S01's batch role no
// longer admin, P06 / P17 read edges kept and verified, P13 escalation derived.
func TestLabPermissionPass(t *testing.T) {
	g := New()
	g.AttachFindings(labFindings(t))
	if edge(g, "arn:aws:iam::111111111111:role/nimbus-lab-claims-intake-role", "arn:aws:s3:::nimbus-lab-claims-pii", EdgeGrantsAccessTo) != nil {
		t.Error("F02: read edge survives the explicit Deny")
	}
	if edge(g, "arn:aws:iam::222222222222:role/nimbus-lab-records-api-role", "arn:aws:s3:::nimbus-lab-member-records", EdgeGrantsAccessTo) != nil {
		t.Error("F09: read edge survives the SCP deny")
	}
	if n, _ := g.Node("arn:aws:iam::222222222222:role/nimbus-lab-batch-role"); n.HasWeakness("OVERPRIVILEGED_IDENTITY") {
		t.Error("S01: batch role still admin")
	}
	for _, p := range [][2]string{
		{"arn:aws:iam::111111111111:role/nimbus-lab-export-lambda-role", "arn:aws:s3:::nimbus-lab-customer-pii"},
		{"arn:aws:iam::111111111111:role/nimbus-lab-report-irsa", "arn:aws:s3:::nimbus-lab-analytics-pii"},
	} {
		e := edge(g, p[0], p[1], EdgeGrantsAccessTo)
		if e == nil || e.Confidence() != model.ConfidenceVerified {
			t.Errorf("%s -> %s: %v", p[0], p[1], e)
		}
	}
	if edge(g, "arn:aws:iam::111111111111:user/nimbus-lab-dev-sam", "arn:aws:iam::111111111111:role/nimbus-lab-ec2-admin-role", EdgeCanAssume) == nil {
		t.Error("P13: PassRole escalation edge missing")
	}
	for _, e := range g.Edges() {
		if _, err := e.Attrs(); err != nil {
			t.Errorf("edge %s -[%s]-> %s: %v", e.From, e.To, e.Kind, err)
		}
	}
}

func TestWhoCan(t *testing.T) {
	g := New()
	g.AttachFindings(labFindings(t))
	res := WhoCan(g, "s3:GetObject", "arn:aws:s3:::nimbus-lab-analytics-pii/report.csv", 4)
	found := map[string]WhoCanResult{}
	for _, r := range res {
		found[r.Principal] = r
	}
	irsa, ok := found["arn:aws:iam::111111111111:role/nimbus-lab-report-irsa"]
	if !ok || len(irsa.Via) != 0 {
		t.Fatalf("direct reader missing: %+v", res)
	}
	if _, ok := found["arn:aws:iam::111111111111:role/nimbus-lab-claims-intake-role"]; ok {
		t.Error("claims-intake role cannot read the analytics bucket")
	}
	// Admins read everything in their account (AdministratorAccess): ops-jane is direct.
	if r, ok := found["arn:aws:iam::111111111111:user/nimbus-lab-ops-jane"]; !ok || !strings.Contains(r.Statement, "AdministratorAccess") {
		t.Errorf("ops-jane = %+v", r)
	}
	// Transitive: the external auditor account assumes the auditor role (ReadOnlyAccess: s3:Get*).
	if r, ok := found["arn:aws:iam::888888888888:root"]; !ok || len(r.Via) == 0 || r.Via[0] != "arn:aws:iam::111111111111:role/nimbus-lab-auditor" {
		t.Errorf("external auditor via the auditor role = %+v", r)
	}
	// SCP-denied batch role in the member account is not a reader of its own account's data.
	for _, r := range WhoCan(g, "s3:GetObject", "arn:aws:s3:::nimbus-lab-member-records/x", 4) {
		if r.Principal == "arn:aws:iam::222222222222:role/nimbus-lab-batch-role" || r.Principal == "arn:aws:iam::222222222222:role/nimbus-lab-records-api-role" {
			t.Errorf("SCP-denied principal listed: %+v", r)
		}
	}
}

func TestWhoCanAssume(t *testing.T) {
	g := New()
	g.AttachFindings(labFindings(t))
	got := map[string]WhoCanResult{}
	for _, r := range WhoCan(g, "sts:AssumeRole", "arn:aws:iam::111111111111:role/nimbus-lab-break-glass", 4) {
		got[r.Principal] = r
	}
	if r, ok := got["arn:aws:iam::111111111111:role/nimbus-lab-auditor"]; !ok || len(r.Via) != 0 {
		t.Errorf("auditor (named in the trust policy) = %+v", r)
	}
	if r, ok := got["arn:aws:iam::888888888888:root"]; !ok || len(r.Via) != 1 {
		t.Errorf("external auditor via the auditor role = %+v", r)
	}
}
