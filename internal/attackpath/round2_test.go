package attackpath

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Engine round 2 (competitive delta review 2026-10-09, shortfalls #1, #9, #11, #12; S01; REACH).

// ---------------------------------------------------------------- #1 one severity everywhere

// A path's severity is the band of its score (model.ScoreBand, the same thresholds as
// risk.BandFor and path Issues): no "CRITICAL 5.2" and no "CRITICAL 7.0" for a High score.
func TestPathSeverityIsScoreBand(t *testing.T) {
	g, fs := labGraph(t, false)
	an := Traverse(g, labOptions())
	rules, err := LoadRules(nil)
	if err != nil {
		t.Fatal(err)
	}
	rulePaths := EvaluateWith(fs, rules, EvalOptions{TrustedCIDRs: []string{labTrustedCIDR}, Graph: g})
	if len(rulePaths) == 0 {
		t.Fatal("lab produced no rule-chain paths; the rule half of this test would be vacuous")
	}
	for _, p := range Merge(an.Paths, rulePaths) {
		if want := PathSeverity(p.Score); p.Severity != want {
			t.Errorf("%s (%s) score %.2f labelled %s, band says %s", p.Name, p.RuleID, p.Score, p.Severity, want)
		}
	}
	for score, want := range map[float64]model.Severity{10: model.Critical, 9: model.Critical, 8.99: model.High, 7: model.High, 6.99: model.Medium, 5.2: model.Medium, 5: model.Medium, 4.99: model.Low, 0.5: model.Low} {
		if got := PathSeverity(score); got != want {
			t.Errorf("PathSeverity(%v) = %s, want %s", score, got, want)
		}
	}
}

// ---------------------------------------------------------------- #11 one row per path Issue

func TestGroupedOneRowPerPathIssue(t *testing.T) {
	g, fs := labGraph(t, false)
	an := Traverse(g, labOptions())
	rules, _ := LoadRules(nil)
	an.Paths = Merge(an.Paths, EvaluateWith(fs, rules, EvalOptions{TrustedCIDRs: []string{labTrustedCIDR}, Graph: g}))
	groups := an.Grouped()
	if len(groups) == 0 || len(groups) >= len(an.Paths) {
		t.Fatalf("grouping %d paths gave %d rows; the lab has SG-entry and instance-entry variants of one Issue", len(an.Paths), len(groups))
	}
	seen := map[string]bool{}
	total := 0
	for i, gr := range groups {
		if seen[gr.IssueID] {
			t.Errorf("Issue %s listed twice", gr.IssueID)
		}
		seen[gr.IssueID] = true
		e, a, r := model.PathIssueKey(gr.Best)
		if gr.IssueID != model.PathIssueID(model.IssuePath, e, a, r) || gr.Entry != e || gr.Anchor != a || gr.Rule != r {
			t.Errorf("group %d: id/key %s %s %s %s do not match its best path", i, gr.IssueID, gr.Entry, gr.Anchor, gr.Rule)
		}
		if len(gr.Paths) != gr.Variants+1 || len(gr.PathIDs) != len(gr.Paths) || gr.Paths[0].ID != gr.Best.ID {
			t.Errorf("group %s: variants %d, paths %d, ids %d", gr.IssueID, gr.Variants, len(gr.Paths), len(gr.PathIDs))
		}
		for _, p := range gr.Paths {
			if p.Score > gr.Best.Score {
				t.Errorf("group %s: best %.2f is not the max (%.2f)", gr.IssueID, gr.Best.Score, p.Score)
			}
		}
		if gr.Score != gr.Best.Score || gr.Band != model.ScoreBand(gr.Score) || gr.Severity != PathSeverity(gr.Score) {
			t.Errorf("group %s: score %.2f band %s severity %s", gr.IssueID, gr.Score, gr.Band, gr.Severity)
		}
		if i > 0 && groups[i-1].Score < gr.Score {
			t.Errorf("groups not sorted by score: %.2f before %.2f", groups[i-1].Score, gr.Score)
		}
		total += len(gr.Paths)
	}
	if total != len(an.Paths) {
		t.Errorf("groups hold %d paths, analysis has %d (--all-variants must be lossless)", total, len(an.Paths))
	}
	multi := 0
	for _, gr := range groups {
		if gr.Variants > 0 {
			multi++
		}
	}
	if multi == 0 {
		t.Error("no group has variants; the lab's web-instance-role Issue has two hop lists")
	}
}

// ---------------------------------------------------------------- #9 KEV / EPSS gate

type fakeIntel struct {
	kev  map[string]bool
	epss map[string]float64
}

func (f fakeIntel) KEV(c string) bool { return f.kev[c] }
func (f fakeIntel) EPSS(c string) (float64, float64, bool) {
	s, ok := f.epss[c]
	return s, s, ok
}

const (
	cveHost   = "arn:aws:ec2:us-east-1:1:instance/i-cve"
	cveRole   = "arn:aws:iam::1:role/cve-host-role"
	cveBucket = "arn:aws:s3:::cve-pii"
)

// cveGraph: internet (wide) → exposed host (no IMDSv1, no remote-login port) → role → PII bucket.
// The only way from the host to its role is code execution through the CVE.
func cveGraph(attrs map[string]any, cveCount int) *graph.Graph {
	g := graph.New()
	if attrs == nil {
		attrs = map[string]any{}
	}
	g.AddNode(&graph.Node{ID: cveHost, Type: "aws_instance", Name: "cve-host", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "UNPATCHED"}, Attributes: attrs, CVECount: cveCount})
	g.AddNode(&graph.Node{ID: cveRole, Type: "aws_iam_role", Name: "cve-host-role"})
	g.AddNode(&graph.Node{ID: cveBucket, Type: "aws_s3_bucket", Name: "cve-pii", Attributes: map[string]any{"data_classification": "pii"}})
	g.AddEdge(graph.InternetNodeID, cveHost, graph.EdgeExposes, map[string]any{"exposure_cidrs": []string{"0.0.0.0/0"}, "ports": "443"})
	g.AddEdge(cveHost, cveRole, graph.EdgeRunsAs, nil)
	g.AddEdge(cveRole, cveBucket, graph.EdgeGrantsAccessTo, nil)
	return g
}

func credStep(p model.AttackPath) model.Step {
	for _, s := range p.Steps {
		if s.Relation == graph.EdgeRunsAs {
			return s
		}
	}
	return model.Step{}
}

// Council decision 5: CVE exploitability is gated on KEV / EPSS. KEV 0.9, EPSS ≥ 0.5 → 0.6,
// EPSS ≥ 0.1 → 0.3, else 0.1 (below the reporting floor unless another route exists); a CVE
// count or UNPATCHED label without ids is 0.3 with confidence hint.
func TestCVEGate(t *testing.T) {
	in := fakeIntel{kev: map[string]bool{"CVE-0000-0001": true}, epss: map[string]float64{"CVE-0000-0002": 0.7, "CVE-0000-0003": 0.2, "CVE-0000-0004": 0.01}}
	cases := []struct {
		name     string
		attrs    map[string]any
		nodeCVEs []string
		count    int
		want     float64 // credential-hop likelihood; 0 = no path reported
		hint     bool
	}{
		{"KEV id on the node", map[string]any{"cves": []any{"CVE-0000-0001"}}, nil, 1, 0.9, false},
		{"kev attribute", map[string]any{"kev": true}, nil, 1, 0.9, false},
		{"KEV id from the finding index", nil, []string{"CVE-0000-0001"}, 1, 0.9, false},
		{"EPSS 0.7", nil, []string{"CVE-0000-0002"}, 1, 0.6, false},
		{"EPSS 0.2", nil, []string{"CVE-0000-0003"}, 1, 0.3, false},
		{"EPSS 0.01", nil, []string{"CVE-0000-0004"}, 1, 0, false},
		{"bare count, no ids", nil, nil, 2, 0.3, true},
		{"id with no KEV/EPSS data", nil, []string{"CVE-0000-0009"}, 1, 0.3, true},
	}
	for _, c := range cases {
		o := DefaultTraversalOptions()
		o.Intel = in
		if c.nodeCVEs != nil {
			o.NodeCVEs = map[string][]string{cveHost: c.nodeCVEs}
		}
		an := Traverse(cveGraph(c.attrs, c.count), o)
		if c.want == 0 {
			if len(an.Paths) != 0 {
				t.Errorf("%s: low-EPSS CVE still reported: %.2f %s", c.name, an.Paths[0].Score, credStep(an.Paths[0]).Summary)
			}
			continue
		}
		if len(an.Paths) != 1 {
			t.Fatalf("%s: %d paths", c.name, len(an.Paths))
		}
		s := credStep(an.Paths[0])
		if got, _ := s.Evidence["likelihood"].(float64); got != c.want {
			t.Errorf("%s: credential hop p=%v, want %v (%s)", c.name, got, c.want, s.Summary)
		}
		if hint := s.Evidence["confidence"] == "hint"; hint != c.hint {
			t.Errorf("%s: confidence hint %v, want %v", c.name, hint, c.hint)
		}
		if !strings.Contains(s.Summary, "KEV") && !strings.Contains(s.Summary, "EPSS") && !strings.Contains(s.Summary, "CVE ids") {
			t.Errorf("%s: step does not cite the gate: %s", c.name, s.Summary)
		}
		// The internet hop is reachability (0.8); only a KEV listing raises it.
		first := an.Paths[0].Steps[0]
		wantFirst := 0.8
		if c.want == 0.9 {
			wantFirst = 0.9
		}
		if got, _ := first.Evidence["likelihood"].(float64); got != wantFirst {
			t.Errorf("%s: internet hop p=%v, want %v (%s)", c.name, got, wantFirst, first.Summary)
		}
	}
}

// Lab: P19 (Log4Shell, KEV) keeps its ≥ 7 band through the gate; the same host shape with a
// non-KEV, low-EPSS CVE (snapshot CVE-2023-0002, EPSS 0.003) is not reported.
func TestCVEGateLab(t *testing.T) {
	g, fs := labGraph(t, false)
	o := labOptions()
	o.NodeCVEs = CVEIndex(fs)
	an := Traverse(g, o)
	gt := groundTruth(t)
	if best := bestFor(an, gt["P19"]); best < 7 {
		t.Errorf("P19 (KEV) best %.2f, want >= 7", best)
	}
	if best := bestFor(an, gt["P16"]); best < 7 {
		t.Errorf("P16 best %.2f, want >= 7", best)
	}
	low := DefaultTraversalOptions()
	low.NodeCVEs = map[string][]string{cveHost: {"CVE-2023-0002"}}
	if an := Traverse(cveGraph(nil, 1), low); len(an.Paths) != 0 {
		t.Errorf("non-KEV low-EPSS host reported: %.2f", an.Paths[0].Score)
	}
}

// bestFor is the best score of a path ending at the label's target and crossing its hops.
func bestFor(an *Analysis, l gtLabel) float64 {
	best := 0.0
	for _, p := range an.Paths {
		if len(p.Steps) == 0 || p.Steps[len(p.Steps)-1].Resource != l.Target {
			continue
		}
		on := map[string]bool{}
		for _, s := range p.Steps {
			on[s.Resource] = true
		}
		ok := true
		for _, h := range l.Hops {
			ok = ok && on[h]
		}
		if ok && p.Score > best {
			best = p.Score
		}
	}
	return best
}

func bestPath(an *Analysis, l gtLabel) (model.AttackPath, bool) {
	var out model.AttackPath
	found := false
	for _, p := range an.Paths {
		if len(p.Steps) == 0 || p.Steps[len(p.Steps)-1].Resource != l.Target {
			continue
		}
		on := map[string]bool{}
		for _, s := range p.Steps {
			on[s.Resource] = true
		}
		ok := true
		for _, h := range l.Hops {
			ok = ok && on[h]
		}
		if ok && (!found || p.Score > out.Score) {
			out, found = p, true
		}
	}
	return out, found
}

// ---------------------------------------------------------------- #12 identity entry + escalation

func TestIdentityEntryFloorsLab(t *testing.T) {
	g, _ := labGraph(t, false)
	an := Traverse(g, labOptions())
	gt := groundTruth(t)
	for _, c := range []struct{ id, tag string }{{"P15", ToxicIdPEntry}, {"P13", ToxicPrivesc}, {"P20", ToxicExternalTrust}, {"P18", ToxicAdmin}} {
		p, ok := bestPath(an, gt[c.id])
		if !ok {
			t.Errorf("%s: not reported", c.id)
			continue
		}
		if p.Score < 7 {
			t.Errorf("%s: best %.2f, want >= 7", c.id, p.Score)
		}
		if got := ToxicCombination(p); got != c.tag {
			t.Errorf("%s: toxic_combination %q, want %q", c.id, got, c.tag)
		}
	}
	// P13: the escalation hop is priced at 0.8 and names its technique.
	p13, _ := bestPath(an, gt["P13"])
	for _, s := range p13.Steps {
		if s.Relation == graph.EdgeCanAssume {
			if got, _ := s.Evidence["likelihood"].(float64); got != EscalationLikelihood {
				t.Errorf("P13 escalation hop p=%v, want %v", got, EscalationLikelihood)
			}
			if s.Evidence[graph.AttrTechnique] != graph.TechniquePassRoleEC2 {
				t.Errorf("P13 escalation hop technique %v", s.Evidence[graph.AttrTechnique])
			}
		}
	}
	// P20: the external-account root trust is an entry at 0.8.
	p20, _ := bestPath(an, gt["P20"])
	if got, _ := p20.Steps[0].Evidence["likelihood"].(float64); got != ExternalRootEntry {
		t.Errorf("P20 entry likelihood %v, want %v (%s)", got, ExternalRootEntry, p20.Steps[0].Because)
	}
	// P18: the agent's runs_as hop is 0.7 (unauthenticated invoke surface).
	p18, _ := bestPath(an, gt["P18"])
	if got, _ := credStep(p18).Evidence["likelihood"].(float64); got != AgentUntrustedInput {
		t.Errorf("P18 agent hop p=%v, want %v", got, AgentUntrustedInput)
	}
}

func idpGraph(userAttrs map[string]any, weak []string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "okta:user/u1", Type: "okta_user", Name: "u1", Provider: "okta", Weaknesses: weak, Attributes: userAttrs})
	g.AddNode(&graph.Node{ID: "okta:group/g1", Type: "okta_group", Name: "g1", Provider: "okta"})
	g.AddNode(&graph.Node{ID: "arn:aws:iam::1:role/sso-admin", Type: "aws_iam_role", Name: "sso-admin", Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"},
		Attributes: map[string]any{"attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}})
	g.AddEdge("okta:user/u1", "okta:group/g1", graph.EdgeMemberOf, nil)
	g.AddEdge("okta:group/g1", "arn:aws:iam::1:role/sso-admin", graph.EdgeCanAssume, nil)
	return g
}

func TestIdPEntryFloor(t *testing.T) {
	active := Traverse(idpGraph(map[string]any{"status": "ACTIVE", "mfa_enrolled": false}, []string{"NO_MFA"}), DefaultTraversalOptions())
	if len(active.Paths) != 1 || active.Paths[0].Score < 7 || ToxicCombination(active.Paths[0]) != ToxicIdPEntry {
		t.Fatalf("active MFA-exempt IdP user → admin: %+v", active.Paths)
	}
	if !strings.Contains(active.Paths[0].Steps[0].Because, "status ACTIVE") {
		t.Errorf("entry because does not say why the credential is usable: %s", active.Paths[0].Steps[0].Because)
	}
	if an := Traverse(idpGraph(map[string]any{"status": "SUSPENDED", "mfa_enrolled": false}, []string{"NO_MFA"}), DefaultTraversalOptions()); len(an.Paths) != 0 {
		t.Errorf("suspended IdP user is an entry: %.2f", an.Paths[0].Score)
	}
	// MFA enforced: no NO_MFA weakness, so no entry at all.
	if an := Traverse(idpGraph(map[string]any{"status": "ACTIVE", "mfa_enrolled": true}, nil), DefaultTraversalOptions()); len(an.Paths) != 0 {
		t.Errorf("MFA-enforced IdP user is an entry: %.2f", an.Paths[0].Score)
	}
	// An IdP user whose usability is unknown (no status) keeps the ×0.5 hint and no floor.
	if an := Traverse(idpGraph(map[string]any{}, []string{"NO_MFA"}), DefaultTraversalOptions()); len(an.Paths) == 1 && (an.Paths[0].Score >= 7 || ToxicCombination(an.Paths[0]) != "") {
		t.Errorf("unknown-status IdP user floored: %.2f %s", an.Paths[0].Score, ToxicCombination(an.Paths[0]))
	}
}

func TestAgentRunsAsLikelihood(t *testing.T) {
	mk := func(attrs map[string]any, exposed bool) *Analysis {
		g := graph.New()
		g.AddNode(&graph.Node{ID: "arn:aws:bedrock:us-east-1:1:agent/A1", Type: "aws_bedrockagent_agent", Name: "agent", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"}, Attributes: attrs})
		g.AddNode(&graph.Node{ID: "arn:aws:iam::1:role/agent-role", Type: "aws_iam_role", Name: "agent-role", Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}})
		if exposed {
			g.AddEdge(graph.InternetNodeID, "arn:aws:bedrock:us-east-1:1:agent/A1", graph.EdgeExposes, map[string]any{"exposure_cidrs": []string{"0.0.0.0/0"}})
		}
		g.AddEdge("arn:aws:bedrock:us-east-1:1:agent/A1", "arn:aws:iam::1:role/agent-role", graph.EdgeRunsAs, nil)
		return Traverse(g, DefaultTraversalOptions())
	}
	pub := mk(map[string]any{"invoked_by": "unauthenticated public chat endpoint"}, true)
	if len(pub.Paths) != 1 || pub.Paths[0].Score < 7 {
		t.Fatalf("public agent → admin role: %+v", pub.Paths)
	}
	if got, _ := credStep(pub.Paths[0]).Evidence["likelihood"].(float64); got != AgentUntrustedInput {
		t.Errorf("public agent hop p=%v", got)
	}
	ev := agentHop(nil, nil, &graph.Node{ID: "a", Type: "aws_bedrock_agent", Name: "a"})
	if ev.exploitability != AgentOtherInput {
		t.Errorf("internal agent with no untrusted input: p=%v, want %v", ev.exploitability, AgentOtherInput)
	}
	ev = agentHop(nil, nil, &graph.Node{ID: "a", Type: "aws_bedrock_agent", Name: "a", Attributes: map[string]any{"action_groups": []any{"web_fetch"}, "untrusted_input": true}})
	if ev.exploitability != AgentUntrustedInput {
		t.Errorf("agent with tool access from untrusted input: p=%v", ev.exploitability)
	}
}

// ---------------------------------------------------------------- S01 rule engine respects effective admin

func TestRuleEngineRespectsEffectiveAdmin(t *testing.T) {
	g, fs := labGraph(t, false)
	rules, _ := LoadRules(nil)
	const batchRole = "arn:aws:iam::222222222222:role/nimbus-lab-batch-role"
	if n, ok := g.Node(batchRole); !ok || n.Attributes["effective_admin"] != "none" {
		t.Fatalf("precondition: the IAM pass should neutralise %s (effective_admin none)", batchRole)
	}
	for name, o := range map[string]EvalOptions{"graph given": {Graph: g}, "graph built from findings": {}} {
		for _, p := range EvaluateWith(fs, rules, o) {
			for _, s := range p.Steps {
				if s.Resource == batchRole && s.Weakness == "OVERPRIVILEGED_IDENTITY" {
					t.Errorf("%s: rule %s still treats the SCP-neutralised %s as admin (%.2f)", name, p.RuleID, batchRole, p.Score)
				}
			}
		}
	}
	// Control: without the SCP the same rule fires.
	var plain []model.Finding
	for _, f := range fs {
		if f.Resource.ID == batchRole {
			f.Resource.Attributes = map[string]any{}
		}
		plain = append(plain, f)
	}
	fired := false
	for _, p := range EvaluateWith(plain, rules, EvalOptions{}) {
		if p.RuleID == "INTERNET_TO_ACCOUNT_ADMIN" && p.Steps[len(p.Steps)-1].Resource == batchRole {
			fired = true
		}
	}
	if !fired {
		t.Error("control: INTERNET_TO_ACCOUNT_ADMIN does not fire on the batch role without its SCP")
	}
}

// ---------------------------------------------------------------- REACH consumption

func reachGraph(edgeAttr, nodeAttr map[string]any) *graph.Graph {
	g := graph.New()
	attrs := map[string]any{}
	for k, v := range nodeAttr {
		attrs[k] = v
	}
	g.AddNode(&graph.Node{ID: "arn:aws:ec2:us-east-1:1:instance/i-r", Type: "aws_instance", Name: "sftp", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "IMDSV1_ENABLED"}, Attributes: attrs})
	g.AddNode(&graph.Node{ID: "arn:aws:iam::1:role/sftp-role", Type: "aws_iam_role", Name: "sftp-role", Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}})
	ea := map[string]any{"exposure_cidrs": []string{"0.0.0.0/0"}, "ports": "22"}
	for k, v := range edgeAttr {
		ea[k] = v
	}
	g.AddEdge(graph.InternetNodeID, "arn:aws:ec2:us-east-1:1:instance/i-r", graph.EdgeExposes, ea)
	g.AddEdge("arn:aws:ec2:us-east-1:1:instance/i-r", "arn:aws:iam::1:role/sftp-role", graph.EdgeRunsAs, nil)
	return g
}

func TestReachabilityConsumed(t *testing.T) {
	base := Traverse(reachGraph(nil, nil), DefaultTraversalOptions())
	if len(base.Paths) != 1 {
		t.Fatalf("control: %d paths", len(base.Paths))
	}
	blocked := map[string]any{"reachability": "blocked", "reach_blocker": "network ACL acl-1 denies tcp/22 inbound", "reach_confidence": "verified"}
	for name, g := range map[string]*graph.Graph{"edge attr": reachGraph(blocked, nil), "node attr": reachGraph(nil, blocked)} {
		an := Traverse(g, DefaultTraversalOptions())
		if len(an.Paths) != 0 {
			t.Errorf("%s: blocked exposure still a path: %.2f", name, an.Paths[0].Score)
		}
		var x *Exposure
		for i := range an.Exposures {
			if an.Exposures[i].NodeID == "arn:aws:ec2:us-east-1:1:instance/i-r" {
				x = &an.Exposures[i]
			}
		}
		if x == nil || x.Reachability != "blocked" || !strings.Contains(x.Reason, "acl-1") {
			t.Errorf("%s: blocked resource not in Exposures with its blocker: %+v", name, an.Exposures)
		}
		for _, s := range an.Suppressed {
			if s.NodeID == "arn:aws:ec2:us-east-1:1:instance/i-r" {
				t.Errorf("%s: blocked resource listed twice (also suppressed)", name)
			}
		}
	}
	unk := Traverse(reachGraph(map[string]any{"reachability": "unknown", "reach_path": "igw-1 > rtb-1 > acl-?"}, nil), DefaultTraversalOptions())
	if len(unk.Paths) != 1 {
		t.Fatalf("unknown reachability dropped the path")
	}
	first := unk.Paths[0].Steps[0]
	if first.Evidence["confidence"] != "inferred" || model.PathConfidence(unk.Paths[0]) == model.ConfidenceVerified {
		t.Errorf("unknown reachability: hop confidence %v", first.Evidence["confidence"])
	}
	reach := Traverse(reachGraph(map[string]any{"reachability": "reachable", "reach_path": "igw-1 > rtb-1 > acl-1 > sg-1"}, nil), DefaultTraversalOptions())
	if len(reach.Paths) != 1 || reach.Paths[0].Steps[0].Evidence["reach_path"] == nil {
		t.Errorf("reachable: reach_path not carried as evidence: %+v", reach.Paths)
	}
}

// The JSON a `paths --format json` consumer reads carries the band-consistent severity.
func TestPathJSONSeverity(t *testing.T) {
	g, _ := labGraph(t, false)
	an := Traverse(g, labOptions())
	b, _ := json.Marshal(an.Paths)
	var out []struct {
		Score    float64 `json:"score"`
		Severity string  `json:"severity"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	for _, p := range out {
		if p.Severity != string(PathSeverity(p.Score)) {
			t.Errorf("JSON severity %s for score %.2f", p.Severity, p.Score)
		}
	}
}

// Lab F03 / F04 with REACH's verdicts applied by hand (the attribute shapes of
// internal/graph/reachability_test.go: status blocked + reach_blocker on the internet edge and the
// node). Once graph.AnnotateReachability lands, AttachFindings sets them and the groundtruth
// harness shows F03 / F04 SUPPRESSED; until then this is the engine half of that check.
func TestReachLabF03F04Synthetic(t *testing.T) {
	g, _ := labGraph(t, false)
	const (
		f03 = "arn:aws:ec2:us-east-1:111111111111:instance/i-0a1b2c3d4e5f60004"
		f04 = "arn:aws:rds:us-east-1:111111111111:db:nimbus-lab-ledger"
	)
	block := map[string]string{
		f03: "NACL acl-0a1b2c3d4e5f60001 rule 90 denies 22/tcp from 0.0.0.0/0",
		f04: "route table rtb-0a1b2c3d4e5f60001 has no route to an internet gateway",
	}
	for id, why := range block {
		n, ok := g.Node(id)
		if !ok {
			t.Fatalf("lab node %s missing", id)
		}
		n.Attributes[AttrReachability], n.Attributes[AttrReachBlocker] = ReachBlocked, why
		for _, e := range g.In(id) {
			if e.From == graph.InternetNodeID {
				e.Attr[AttrReachability], e.Attr[AttrReachBlocker] = ReachBlocked, why
			}
		}
	}
	an := Traverse(g, labOptions())
	gt := groundTruth(t)
	for _, id := range []string{"F03", "F04"} {
		if p, ok := bestPath(an, gt[id]); ok {
			t.Errorf("%s still reported at %.2f with REACH blocked", id, p.Score)
		}
	}
	for id, why := range block {
		found := false
		for _, x := range an.Exposures {
			if x.NodeID == id && x.Reachability == ReachBlocked && x.Reason == why {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not in Exposures with its blocker", id)
		}
	}
	// Everything else the lab reports is untouched.
	for _, id := range []string{"P01", "P02", "P03", "P19"} {
		if best := bestFor(an, gt[id]); best < 7 {
			t.Errorf("%s dropped to %.2f by an unrelated REACH verdict", id, best)
		}
	}
}
