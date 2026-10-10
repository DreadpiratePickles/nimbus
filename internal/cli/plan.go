package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/remediation"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

// planStep is one fix of the minimum fix set with its in-graph re-traversal result and its
// remediation phases (prerequisite → snapshot → fix → verify → rollback, from the sidecar).
type planStep struct {
	Fix                attackpath.Fix `json:"fix"`
	Resolves           int            `json:"resolves"`            // paths this fix alone removes (Simulate)
	Reduces            int            `json:"reduces"`             // paths it is on that survive it (lower risk only)
	RuleChains         int            `json:"rule_chains"`         // rule-chain paths it also breaks (one of their findings)
	CumulativeResolves int            `json:"cumulative_resolves"` // paths removed by steps 1..n together
	RemainingScore     float64        `json:"remaining_score"`     // total path score left after this fix alone
	CumulativeScore    float64        `json:"cumulative_remaining_score"`
	Template           string         `json:"template,omitempty"`
	Phases             []server.Phase `json:"phases"`
}

// ruleChainStep breaks rule-chain paths (finding-rule chains the graph traversal does not
// produce, e.g. INTERNET_TO_ACCOUNT_ADMIN) that no minimum-fix-set step touches.
type ruleChainStep struct {
	FindingID   string         `json:"finding_id"`
	CanonicalID string         `json:"canonical_id"`
	Resource    string         `json:"resource"`
	ResourceID  string         `json:"resource_id"`
	Resolves    int            `json:"resolves"` // rule-chain paths it breaks
	Paths       []string       `json:"paths"`
	Command     string         `json:"command"`
	Template    string         `json:"template,omitempty"`
	Phases      []server.Phase `json:"phases"`
}

// residualPath is a path the printed plan does not break, with the reason.
type residualPath struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
	Kind   string  `json:"kind"` // traversal | rule-chain
	Reason string  `json:"reason"`
}

// planTarget groups the printed steps by the resource they change (the AWS Security Hub
// remediation-plan view): its fixes, the paths they fully break together (Resolves, measured by
// re-traversal, plus rule-chain paths) and the paths they are on that survive (Reduces).
type planTarget struct {
	Resource string   `json:"resource"`
	Name     string   `json:"name"`
	Steps    []string `json:"steps"` // step labels: "3", "R1"
	Fixes    []string `json:"fixes"` // one per step: weakness or canonical id
	Resolves int      `json:"resolves"`
	Reduces  int      `json:"reduces"`
}

type planDoc struct {
	// PathIssues counts the attack path Issues behind TotalPaths (one per entry, impact anchor
	// and rule, like `issues` and the headline); TotalPaths counts their hop variants.
	PathIssues     int             `json:"path_issues"`
	TotalPaths     int             `json:"total_paths"`      // traversal + rule-chain paths (hop variants)
	TraversalPaths int             `json:"traversal_paths"`  // includes path-rule matches
	RuleMatchPaths int             `json:"rule_match_paths"` // traversal paths a path rule produced
	RuleChainPaths int             `json:"rule_chain_paths"`
	TotalScore     float64         `json:"total_score"`
	MinFixSetSize  int             `json:"min_fix_set_size"`
	MinFixExact    bool            `json:"min_fix_exact"`
	MinFixVerified bool            `json:"min_fix_verified"`
	MinFixCoverage float64         `json:"min_fix_coverage"`
	Steps          []planStep      `json:"steps"`
	RuleChainSteps []ruleChainStep `json:"rule_chain_steps"`
	Remaining      []residualPath  `json:"remaining"`
	Targets        []planTarget    `json:"targets"`
}

func stepLabel(i int) string { return fmt.Sprint(i + 1) }

var planFlags struct {
	json bool
	top  int
}

// planCmd: the minimum fix set over the traversal paths, and for its first fixes the "resolves
// N / reduces M / remaining score" measured by re-traversing the graph with the fix applied;
// rule-chain paths no step touches get their own steps; every step carries its remediation
// phases; the paths the printed steps leave are named with the reason.
var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Remediation plan: the minimum fix set, what each fix resolves, its steps (prerequisite → snapshot → fix → verify → rollback) and what remains",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		res, st, err := loadResult(ctx, cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		opts := traversalOptionsFor(cfg, res.Graph, res.Findings)
		an := attackpath.Traverse(res.Graph, opts)
		stored, _ := st.AttackPaths()
		doc := buildPlan(st, res.Graph, opts, an, stored, planFlags.top)
		if planFlags.json {
			return output.JSON(os.Stdout, doc)
		}
		printPlan(os.Stdout, doc)
		return nil
	},
}

// ruleChains are the stored paths that are not graph-traversal paths.
func ruleChains(stored []model.AttackPath) []model.AttackPath {
	var out []model.AttackPath
	for _, p := range stored {
		// Path-rule matches are produced by the traversal itself (and are path Issues already):
		// never a rule chain, or plan counts them twice (W6-ENGINE wiring).
		if _, _, r := model.PathIssueKey(p); r != model.PathRuleTraversal && !attackpath.IsRuleMatch(p) {
			out = append(out, p)
		}
	}
	return out
}

func chainFindings(p model.AttackPath) []string {
	ids := append([]string{}, p.FindingIDs...)
	for _, s := range p.Steps {
		if s.FindingID != "" {
			ids = append(ids, s.FindingID)
		}
	}
	return uniqStrings(ids)
}

func uniqStrings(in []string) []string {
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

// phasesFor renders the remediation phases of the first finding a fix names; it also returns
// that finding (nil when none renders).
func phasesFor(st *store.Store, g *graph.Graph, ids []string) ([]server.Phase, string, *model.Finding, string) {
	for _, id := range ids {
		f, err := st.Finding(id)
		if err != nil || f.Status != model.Fail {
			continue
		}
		// A K8s LoadBalancer fix patches the Service that selects the pod, resolved on the
		// stored graph (W7-ENGINE r5 #7).
		rf := remediation.WithK8sService(*f, g)
		if fx := server.FixFor(rf); fx != nil {
			return fx.Phases, fx.Template, f, stepCommand(fx)
		}
	}
	return []server.Phase{}, "", nil, ""
}

// stepCommand is the plan step headline for a fix rendered in a format other than Terraform: the
// command that prints that typed template (`--generate-terraform` would print a generic stub,
// W7-ENGINE r5 #7); "" keeps the engine's Terraform headline.
func stepCommand(fx *server.PageFix) string {
	if fx == nil || fx.Format == "" || fx.Format == string(remediation.Terraform) {
		return ""
	}
	return fx.Command
}

// issueIndex is what the verify phase needs from the stored Issues: the single/combination
// Issue of each finding and the path Issue ids (cloud-posture verify <issue-id> takes either).
type issueIndex struct {
	byFinding map[string]string
	paths     map[string]bool
	// st keys path Issue ids: ids are HMAC-keyed per database (store.PathIssueIDOf, W5-ISSUES).
	st *store.Store
}

func loadIssueIndex(st *store.Store) issueIndex {
	ix := issueIndex{byFinding: map[string]string{}, paths: map[string]bool{}, st: st}
	if st == nil {
		return ix
	}
	all, err := st.Issues(store.IssueFilter{})
	if err != nil {
		return ix
	}
	for _, is := range all {
		if is.Kind == model.IssuePath {
			ix.paths[is.ID] = true
			continue
		}
		for _, f := range is.FindingIDs {
			if _, ok := ix.byFinding[f]; !ok || is.Kind == model.IssueSingle {
				ix.byFinding[f] = is.ID
			}
		}
	}
	return ix
}

// pathIssues returns the stored path Issue ids of paths (the Issue id is the database-keyed
// PathIssueID(path, entry, anchor, rule), so re-routed paths share one), in order, deduplicated.
func (ix issueIndex) pathIssues(paths []model.AttackPath) []string {
	var out []string
	if ix.st == nil {
		return out
	}
	for _, p := range paths {
		if id := ix.st.PathIssueIDOf(p); ix.paths[id] && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// verifyTarget is what one plan step (or fix) verifies: the finding it fixes and the paths it
// resolves.
type verifyTarget struct {
	finding    *model.Finding // nil for an edge fix (PassRole), whose evidence is the path
	paths      []model.AttackPath
	findingIss string
	pathIss    []string
}

// withIssueVerify puts `cloud-posture verify <issue-id>` at the head of the verify phase — the
// finding's Issue, then the path Issues the step resolves — and keeps the sidecar's query as the
// quick check. Without a stored Issue it prints the placeholder and how to find the id.
func withIssueVerify(phases []server.Phase, vt verifyTarget) []server.Phase {
	var head []string
	if vt.findingIss != "" {
		head = append(head, fmt.Sprintf("cloud-posture verify %s   # finding Issue (%s on %s): re-reads the resource, closes the Issue only once the finding is gone",
			vt.findingIss, vt.finding.CanonicalID, firstNonEmpty(vt.finding.Resource.Name, vt.finding.Resource.ID)))
	}
	const maxPaths = 3
	for i, id := range vt.pathIss {
		if i == maxPaths {
			head = append(head, fmt.Sprintf("… %d more path Issue(s): cloud-posture issues --kind path", len(vt.pathIss)-maxPaths))
			break
		}
		head = append(head, fmt.Sprintf("cloud-posture verify %s   # path Issue it resolves: re-traverses, closes the Issue only once the path is gone", id))
	}
	if len(head) == 0 {
		hint := "the Issue of this finding"
		if vt.finding != nil {
			hint = vt.finding.CanonicalID + " on " + firstNonEmpty(vt.finding.Resource.Name, vt.finding.Resource.ID)
		}
		head = append(head, "cloud-posture verify <issue-id>   # find the id with: cloud-posture issues (look for "+hint+"), or cloud-posture issues --kind path for the path")
	}
	out := make([]server.Phase, 0, len(phases)+1)
	found := false
	for _, ph := range phases {
		if ph.Name != "verify" {
			out = append(out, ph)
			continue
		}
		found = true
		steps := append([]string{}, head...)
		for _, s := range ph.Steps {
			if vt.findingIss != "" {
				s = strings.ReplaceAll(s, "cloud-posture issues show <id>", "cloud-posture issues show "+vt.findingIss)
			}
			steps = append(steps, s)
		}
		out = append(out, server.Phase{Name: ph.Name, Steps: steps})
	}
	if !found {
		out = append(out, server.Phase{Name: "verify", Steps: head})
	}
	return out
}

func (ix issueIndex) target(f *model.Finding, paths []model.AttackPath) verifyTarget {
	vt := verifyTarget{finding: f, paths: paths, pathIss: ix.pathIssues(paths)}
	if f != nil {
		vt.findingIss = ix.byFinding[f.ID]
	}
	return vt
}

func buildPlan(st *store.Store, g *graph.Graph, opts attackpath.TraversalOptions, an *attackpath.Analysis, stored []model.AttackPath, top int) planDoc {
	// Rule chains the traversal already produced (path-rule matches wired into Traverse) are
	// counted once, as traversal paths.
	inTraversal := map[string]bool{}
	for _, p := range an.Paths {
		inTraversal[p.ID] = true
	}
	var chains []model.AttackPath
	for _, p := range ruleChains(stored) {
		if !inTraversal[p.ID] {
			chains = append(chains, p)
		}
	}
	ix := loadIssueIndex(st)
	pathByID := map[string]model.AttackPath{}
	for _, p := range an.Paths {
		pathByID[p.ID] = p
	}
	for _, p := range chains {
		pathByID[p.ID] = p
	}
	pathsOf := func(ids ...[]string) []model.AttackPath {
		var out []model.AttackPath
		for _, l := range ids {
			for _, id := range l {
				if p, ok := pathByID[id]; ok {
					out = append(out, p)
				}
			}
		}
		return out
	}
	matches := 0
	for _, p := range an.Paths {
		if attackpath.IsRuleMatch(p) {
			matches++
		}
	}
	doc := planDoc{TraversalPaths: len(an.Paths), RuleMatchPaths: matches, RuleChainPaths: len(chains), TotalPaths: len(an.Paths) + len(chains), TotalScore: an.TotalScore,
		MinFixSetSize: len(an.MinFixSet), MinFixExact: an.MinFixExact, MinFixVerified: an.MinFixVerified, MinFixCoverage: an.MinFixCoverage,
		Steps: []planStep{}, RuleChainSteps: []ruleChainStep{}, Remaining: []residualPath{}, Targets: []planTarget{}}
	for _, p := range chains {
		doc.TotalScore += p.Score
	}
	doc.PathIssues = len(attackpath.GroupPaths(append(append([]model.AttackPath{}, an.Paths...), chains...)))
	view := newPathIssueView(st, g)
	brokenChain := map[string]bool{}
	breaksChains := func(fids []string) (n int, ids []string) {
		set := map[string]bool{}
		for _, id := range fids {
			set[id] = true
		}
		for _, p := range chains {
			for _, id := range chainFindings(p) {
				if set[id] {
					n++
					ids = append(ids, p.ID)
					break
				}
			}
		}
		return n, ids
	}
	var applied []attackpath.Fix
	stepChains := [][]string{} // rule-chain path ids each traversal step breaks
	for i, fx := range an.MinFixSet {
		if i >= top {
			break
		}
		applied = append(applied, fx)
		n, rem := attackpath.SimulateWith(g, opts, []attackpath.Fix{fx})
		cn, crem := attackpath.SimulateWith(g, opts, an.MinFixSet[:i+1])
		rc, ids := breaksChains(fx.FindingIDs)
		for _, id := range ids {
			brokenChain[id] = true
		}
		phases, tpl, vf, cmd := phasesFor(st, g, fx.FindingIDs)
		if cmd != "" {
			fx.Command = cmd
		}
		if pr, ok := attackpath.PassRoleFixOf(g, fx); ok {
			// The PassRole scoping fix has its own template and sidecar (V4-ENGINE); the
			// principal's other findings (e.g. no MFA) are not what this step changes.
			if rf, err := passRoleRemediation(pr); err == nil {
				phases, tpl, vf = server.RemediationPhases(rf), rf.Template, nil
				fx.Command = passRoleFixCommand(pr)
			}
		}
		phases = withIssueVerify(phases, ix.target(vf, pathsOf(fx.Breaks, ids)))
		stepChains = append(stepChains, ids)
		doc.Steps = append(doc.Steps, planStep{Fix: fx, Resolves: n, Reduces: len(fx.Reduces), RuleChains: rc, RemainingScore: rem, CumulativeResolves: cn, CumulativeScore: crem,
			Template: tpl, Phases: phases})
	}
	// Rule chains the printed steps leave: greedy cover by their findings (fixing any one
	// finding of a chain breaks the chain).
	for {
		count := map[string][]string{}
		for _, p := range chains {
			if brokenChain[p.ID] {
				continue
			}
			for _, id := range chainFindings(p) {
				count[id] = append(count[id], p.ID)
			}
		}
		if len(count) == 0 {
			break
		}
		best := ""
		for id, ps := range count {
			if best == "" || len(ps) > len(count[best]) || (len(ps) == len(count[best]) && id < best) {
				best = id
			}
		}
		f, err := st.Finding(best)
		if err != nil || f.Status != model.Fail {
			// Not fixable from the store (resolved / missing evidence): leave it residual.
			for _, pid := range count[best] {
				brokenChain[pid] = true // handled below as residual via the unfixable set
			}
			for _, pid := range count[best] {
				doc.Remaining = append(doc.Remaining, residualFor(chains, pid, "rule-chain", "its evidence finding "+best+" is not an open finding in the store"))
			}
			continue
		}
		for _, pid := range count[best] {
			brokenChain[pid] = true
		}
		phases, tpl, _, cmd := phasesFor(st, g, []string{best})
		phases = withIssueVerify(phases, ix.target(f, pathsOf(count[best])))
		doc.RuleChainSteps = append(doc.RuleChainSteps, ruleChainStep{FindingID: best, CanonicalID: f.CanonicalID, Resource: firstNonEmpty(f.Resource.Name, f.Resource.ID), ResourceID: f.Resource.ID,
			Resolves: len(count[best]), Paths: count[best], Command: firstNonEmpty(cmd, "cloud-posture fix --id "+best+" --generate-terraform"), Template: tpl, Phases: phases})
	}
	// Traversal paths the printed steps leave.
	if len(applied) > 0 || len(an.Paths) > 0 {
		left := attackpath.Traverse(attackpath.ApplyFixes(g, applied), opts)
		inSet := map[string]bool{}
		for _, fx := range an.MinFixSet {
			for _, id := range fx.Breaks {
				inSet[id] = true
			}
		}
		for _, p := range left.Paths {
			reason := fmt.Sprintf("broken by a later fix of the minimum set (plan --top %d)", len(an.MinFixSet))
			if !inSet[p.ID] && !pathInFixSet(an, p) {
				reason = "no cuttable weakness on the path (no fix template breaks it; see paths --fixes)"
			}
			doc.Remaining = append(doc.Remaining, residualPath{ID: p.ID, Name: view.Row(p), Score: p.Score, Kind: "traversal", Reason: reason})
		}
	}
	for i := range doc.Remaining {
		if doc.Remaining[i].Kind != "traversal" {
			if p, ok := pathByID[doc.Remaining[i].ID]; ok {
				doc.Remaining[i].Name = view.Row(p)
			}
		}
	}
	// Score, then the title, then the id: a tie reads the same on every run (r4 #4).
	sort.SliceStable(doc.Remaining, func(i, j int) bool {
		a, b := doc.Remaining[i], doc.Remaining[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	doc.Targets = planTargets(g, opts, doc, stepChains)
	return doc
}

// fixTarget is the resource a fix changes: the node, or the principal of an edge fix.
func fixTarget(fx attackpath.Fix) (id, name string) {
	id, name = fx.NodeID, fx.Name
	if id == "" && fx.Edge != nil {
		id = fx.Edge.From
		if i := strings.Index(name, " → "); i > 0 {
			name = name[:i]
		}
	}
	return id, firstNonEmpty(name, id)
}

// planTargets groups the printed steps by target resource. Resolves is the number of traversal
// paths the target's fixes remove together (re-traversal) plus the rule-chain paths they break;
// Reduces the paths a fix lies on that survive all of the target's fixes.
func planTargets(g *graph.Graph, opts attackpath.TraversalOptions, d planDoc, stepChains [][]string) []planTarget {
	type acc struct {
		t       planTarget
		fixes   []attackpath.Fix
		steps   []int
		chains  map[string]bool
		breaks  map[string]bool
		reduces map[string]bool
	}
	var order []string
	by := map[string]*acc{}
	get := func(id, name string) *acc {
		if a, ok := by[id]; ok {
			return a
		}
		a := &acc{t: planTarget{Resource: id, Name: name, Steps: []string{}, Fixes: []string{}}, chains: map[string]bool{}, breaks: map[string]bool{}, reduces: map[string]bool{}}
		by[id] = a
		order = append(order, id)
		return a
	}
	for i, s := range d.Steps {
		id, name := fixTarget(s.Fix)
		a := get(id, name)
		a.t.Steps = append(a.t.Steps, stepLabel(i))
		a.t.Fixes = append(a.t.Fixes, strings.ToLower(strings.ReplaceAll(s.Fix.Weakness, "_", " ")))
		a.fixes = append(a.fixes, s.Fix)
		a.steps = append(a.steps, i)
		for _, p := range s.Fix.Breaks {
			a.breaks[p] = true
		}
		for _, p := range s.Fix.Reduces {
			a.reduces[p] = true
		}
		if i < len(stepChains) {
			for _, c := range stepChains[i] {
				a.chains[c] = true
			}
		}
	}
	for i, s := range d.RuleChainSteps {
		a := get(firstNonEmpty(s.ResourceID, s.Resource), s.Resource)
		a.t.Steps = append(a.t.Steps, fmt.Sprintf("R%d", i+1))
		a.t.Fixes = append(a.t.Fixes, s.CanonicalID)
		for _, c := range s.Paths {
			a.chains[c] = true
		}
	}
	out := make([]planTarget, 0, len(order))
	for _, id := range order {
		a := by[id]
		switch len(a.fixes) {
		case 0:
		case 1:
			a.t.Resolves = d.Steps[a.steps[0]].Resolves
		default:
			a.t.Resolves, _ = attackpath.SimulateWith(g, opts, a.fixes)
		}
		a.t.Resolves += len(a.chains)
		for p := range a.reduces {
			if !a.breaks[p] {
				a.t.Reduces++
			}
		}
		out = append(out, a.t)
	}
	return out
}

// pathInFixSet reports whether some minimum-fix-set fix lies on the path (by node or edge).
func pathInFixSet(an *attackpath.Analysis, p model.AttackPath) bool {
	on := map[string]bool{}
	for _, s := range p.Steps {
		on[s.Resource], on[s.WeaknessOn] = true, true
	}
	for _, fx := range an.MinFixSet {
		if on[fx.NodeID] || (fx.Edge != nil && on[fx.Edge.From] && on[fx.Edge.To]) {
			return true
		}
	}
	return false
}

func residualFor(chains []model.AttackPath, id, kind, reason string) residualPath {
	for _, p := range chains {
		if p.ID == id {
			return residualPath{ID: id, Name: p.Name + " → " + p.Impact, Score: p.Score, Kind: kind, Reason: reason}
		}
	}
	return residualPath{ID: id, Name: id, Kind: kind, Reason: reason}
}

func printPhaseList(w io.Writer, phases []server.Phase, indent string) {
	for i, ph := range phases {
		fmt.Fprintf(w, "%s%d. %s\n", indent, i+1, ph.Name)
		for _, s := range ph.Steps {
			fmt.Fprintf(w, "%s     %s\n", indent, s)
		}
	}
}

func printPlan(w io.Writer, d planDoc) {
	match := ""
	if d.RuleMatchPaths > 0 {
		match = fmt.Sprintf(" incl. %d path-rule match", d.RuleMatchPaths)
	}
	fmt.Fprintf(w, "Plan: %d attack path Issues (%d hop variants: %d traversal%s, %d rule-chain), total score %.1f\n", d.PathIssues, d.TotalPaths, d.TraversalPaths, match, d.RuleChainPaths, d.TotalScore)
	fmt.Fprintf(w, "Minimum fix set: %d fix(es) — min_fix_exact=%v (%s), min_fix_verified=%v (%s), removes %.1f%% of traversal path score\n\n",
		d.MinFixSetSize, d.MinFixExact, map[bool]string{true: "provably minimal", false: "greedy fallback"}[d.MinFixExact],
		d.MinFixVerified, map[bool]string{true: "re-traversal confirmed", false: "NOT confirmed by re-traversal"}[d.MinFixVerified], d.MinFixCoverage)
	if len(d.Steps) == 0 && len(d.RuleChainSteps) == 0 {
		fmt.Fprintln(w, "Nothing to fix: no attack path has a cuttable weakness.")
	}
	for i, s := range d.Steps {
		chains := ""
		if s.RuleChains > 0 {
			chains = fmt.Sprintf(" (+%d rule-chain path(s))", s.RuleChains)
		}
		fmt.Fprintf(w, "%d. %s on %s\n   resolves %d path(s) alone%s, reduces %d, remaining score %.1f · steps 1–%d together: resolves %d, remaining score %.1f\n   %s\n",
			i+1, strings.ToLower(strings.ReplaceAll(s.Fix.Weakness, "_", " ")), s.Fix.Name, s.Resolves, chains, s.Reduces, s.RemainingScore, i+1, s.CumulativeResolves, s.CumulativeScore, s.Fix.Command)
		printPhaseList(w, s.Phases, "   ")
	}
	if d.MinFixSetSize > len(d.Steps) {
		fmt.Fprintf(w, "\n… %d more fix(es) in the set (plan --top %d)\n", d.MinFixSetSize-len(d.Steps), d.MinFixSetSize)
	}
	if len(d.RuleChainSteps) > 0 {
		fmt.Fprintf(w, "\nRule-chain paths no step above breaks (%d step(s)):\n", len(d.RuleChainSteps))
		for i, s := range d.RuleChainSteps {
			fmt.Fprintf(w, "R%d. %s on %s — breaks %d rule-chain path(s)\n   %s\n", i+1, s.CanonicalID, s.Resource, s.Resolves, s.Command)
			printPhaseList(w, s.Phases, "   ")
		}
	}
	if len(d.Targets) > 0 {
		fmt.Fprintf(w, "\nBy target resource (%d target(s)):\n", len(d.Targets))
		for _, t := range d.Targets {
			fmt.Fprintf(w, "  %s — resolves %d / reduces %d · steps %s (%s)\n", t.Name, t.Resolves, t.Reduces, strings.Join(t.Steps, ", "), strings.Join(t.Fixes, ", "))
		}
	}
	if n := len(d.Remaining); n > 0 {
		var eg []string
		for i, r := range d.Remaining {
			if i >= 3 {
				break
			}
			eg = append(eg, fmt.Sprintf("%s (%.1f)", r.Name, r.Score))
		}
		fmt.Fprintf(w, "\nremaining: %d paths, e.g. %s\n", n, strings.Join(eg, "; "))
		for i, r := range d.Remaining {
			if i >= 10 {
				fmt.Fprintf(w, "  … %d more (plan --json lists every one)\n", n-10)
				break
			}
			fmt.Fprintf(w, "  - [%s %.1f] %s — %s\n", r.Kind, r.Score, r.Name, r.Reason)
		}
	} else {
		fmt.Fprintln(w, "\nremaining: 0 paths — the steps above break every attack path")
	}
}

func init() {
	planCmd.Flags().BoolVar(&planFlags.json, "json", false, "JSON output")
	planCmd.Flags().IntVar(&planFlags.top, "top", 5, "fixes of the minimum set to simulate and print")
	root.AddCommand(planCmd)
}
