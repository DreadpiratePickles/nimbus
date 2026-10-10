// Package attackpath chains individual misconfigurations into breach scenarios.
package attackpath

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"gopkg.in/yaml.v3"
)

//go:embed rules.yaml
var rulesYAML []byte

type Stage struct {
	Weakness      string   `yaml:"weakness" json:"weakness"`
	Requires      []string `yaml:"requires" json:"requires,omitempty"`
	Relation      string   `yaml:"relation" json:"relation,omitempty"`
	Fallback      string   `yaml:"fallback" json:"fallback,omitempty"`
	ResourceTypes []string `yaml:"resource_types" json:"resource_types,omitempty"`
	Label         string   `yaml:"label" json:"label"`
	// AllowSameAccount permits a same_account / any join for this stage (no graph edge to the
	// previous step). It needs a Justification; such chains are weak_link and score x0.5.
	AllowSameAccount bool   `yaml:"allow_same_account" json:"allow_same_account,omitempty"`
	Justification    string `yaml:"justification" json:"justification,omitempty"`
}

type Rule struct {
	ID     string   `yaml:"id" json:"id"`
	Name   string   `yaml:"name" json:"name"`
	Impact string   `yaml:"impact" json:"impact"`
	Mitre  []string `yaml:"mitre" json:"mitre"`
	Stages []Stage  `yaml:"stages" json:"stages"`
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

func LoadRules(extra []byte) ([]Rule, error) {
	var rf ruleFile
	if err := yaml.Unmarshal(rulesYAML, &rf); err != nil {
		return nil, err
	}
	if len(extra) > 0 {
		var more ruleFile
		if err := yaml.Unmarshal(extra, &more); err != nil {
			return nil, err
		}
		rf.Rules = append(rf.Rules, more.Rules...)
	}
	if err := ValidateRules(rf.Rules); err != nil {
		return nil, err
	}
	return rf.Rules, nil
}

// weakRelation reports joins that are not a graph link: co-tenancy (same_account) or none (any).
func weakRelation(rel string) bool { return rel == "same_account" || rel == "any" }

// ValidateRules rejects stages that join by co-tenancy without saying why (Track B2 item 2):
// relation/fallback same_account or any needs allow_same_account: true and a justification.
func ValidateRules(rules []Rule) error {
	for _, r := range rules {
		for i, st := range r.Stages {
			if i == 0 {
				continue
			}
			weak := weakRelation(st.Relation) || weakRelation(st.Fallback)
			switch {
			case weak && !st.AllowSameAccount:
				return fmt.Errorf("attack rule %s stage %d (%s): relation %q/%q joins by co-tenancy; use related/same_resource or set allow_same_account with a justification", r.ID, i+1, st.Weakness, st.Relation, st.Fallback)
			case st.AllowSameAccount && strings.TrimSpace(st.Justification) == "":
				return fmt.Errorf("attack rule %s stage %d (%s): allow_same_account needs a justification", r.ID, i+1, st.Weakness)
			}
		}
	}
	return nil
}

// Graph indexes findings by weakness and resource relationships.
type Graph struct {
	findings []model.Finding
	byWeak   map[string][]int
	edges    map[string]map[string]bool // resourceID -> neighbours
	byRes    map[string][]int
	relTight map[string]float64
}

func Build(findings []model.Finding) *Graph {
	g := &Graph{
		byWeak:   map[string][]int{},
		edges:    map[string]map[string]bool{},
		byRes:    map[string][]int{},
		relTight: map[string]float64{"same_resource": 1.0, "related": 0.85, "same_account": 0.6, "any": 0.4},
	}
	for _, f := range findings {
		if f.Status != model.Fail {
			continue
		}
		g.findings = append(g.findings, f)
	}
	for i, f := range g.findings {
		for _, w := range f.Weaknesses {
			g.byWeak[w] = append(g.byWeak[w], i)
		}
		g.byRes[f.Resource.ID] = append(g.byRes[f.Resource.ID], i)
		for _, r := range f.Resource.Related {
			g.link(f.Resource.ID, r)
		}
	}
	// Containment edges: ARN/path prefixes (instance i-123 inside vpc path, pod inside namespace...).
	ids := make([]string, 0, len(g.byRes))
	for id := range g.byRes {
		ids = append(ids, id)
	}
	for _, a := range ids {
		for _, b := range ids {
			if a != b && len(a) > 8 && len(b) > 8 && (strings.HasPrefix(b, a+"/") || strings.HasPrefix(b, a+":") || strings.Contains(b, "/"+lastSegment(a))) {
				g.link(a, b)
			}
		}
	}
	return g
}

func (g *Graph) link(a, b string) {
	if a == "" || b == "" || a == b {
		return
	}
	if g.edges[a] == nil {
		g.edges[a] = map[string]bool{}
	}
	if g.edges[b] == nil {
		g.edges[b] = map[string]bool{}
	}
	g.edges[a][b] = true
	g.edges[b][a] = true
}

func lastSegment(s string) string {
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndexAny(s, "/:"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func (g *Graph) related(a, b *model.Finding) bool {
	if a.Resource.ID == b.Resource.ID {
		return true
	}
	if g.edges[a.Resource.ID][b.Resource.ID] {
		return true
	}
	for _, r := range a.Resource.Related {
		if r == b.Resource.ID || r == b.Resource.Name || strings.HasSuffix(b.Resource.ID, "/"+r) || strings.HasSuffix(b.Resource.ID, ":"+r) {
			return true
		}
	}
	for _, r := range b.Resource.Related {
		if r == a.Resource.ID || r == a.Resource.Name {
			return true
		}
	}
	return false
}

// resourceHas reports whether any failing finding on resource id carries weakness w.
func (g *Graph) resourceHas(id, w string) bool {
	if id == "" {
		return false
	}
	for _, i := range g.byRes[id] {
		if g.findings[i].HasWeakness(w) {
			return true
		}
	}
	return false
}

func sameAccount(a, b *model.Finding) bool {
	return a.Provider == b.Provider && a.Account == b.Account
}

// matches tests a candidate against a stage relative to the previous finding; returns the relation used.
func (g *Graph) matches(prev, cand *model.Finding, st Stage) (string, bool) {
	if !cand.HasWeakness(st.Weakness) {
		return "", false
	}
	// requires: AND preconditions on the stage's resource. Each must hold on the candidate
	// finding or on another failing finding for the same resource (e.g. an open-port finding
	// on a database plus the database's own DATABASE-tagged finding).
	for _, req := range st.Requires {
		if !cand.HasWeakness(req) && !g.resourceHas(cand.Resource.ID, req) {
			return "", false
		}
	}
	if len(st.ResourceTypes) > 0 {
		ok := false
		for _, t := range st.ResourceTypes {
			if strings.EqualFold(t, cand.Resource.Type) {
				ok = true
			}
		}
		if !ok {
			return "", false
		}
	}
	if prev == nil {
		return "", true
	}
	if cand.ID == prev.ID {
		return "", false
	}
	check := func(rel string) bool {
		switch rel {
		case "same_resource":
			return prev.Resource.ID != "" && prev.Resource.ID == cand.Resource.ID
		case "related":
			// A declared relationship or ID containment is a real link, across accounts
			// and providers too (repo → OIDC role, EKS cluster → RBAC binding).
			return g.related(prev, cand)
		case "same_account":
			return st.AllowSameAccount && sameAccount(prev, cand)
		case "any":
			return st.AllowSameAccount
		}
		return false
	}
	rel := st.Relation
	if rel == "" {
		rel = "related"
	}
	if check(rel) {
		return rel, true
	}
	if st.Fallback != "" && check(st.Fallback) {
		return st.Fallback, true
	}
	return "", false
}

// EvalOptions tune rule evaluation.
type EvalOptions struct {
	// TrustedCIDRs (config trusted_cidrs): a finding whose exposure evidence
	// (attributes.exposure_cidrs / exposure) is entirely trusted or private does not count as
	// PUBLIC_NETWORK_EXPOSURE / PUBLIC_DATA_STORE for any rule.
	TrustedCIDRs []string
	// Graph is the security graph the traversal uses (after graph.EvaluatePermissions). Rule
	// chains read two verdicts from it (engine round 2, S01): an identity whose admin rights an
	// SCP / permission boundary removes (effective_admin none, denied_by; the weakness moved to
	// neutralised_weaknesses) does not count as OVERPRIVILEGED_IDENTITY, and a resource whose
	// internet exposure REACH marked blocked does not count as PUBLIC_NETWORK_EXPOSURE /
	// PUBLIC_DATA_STORE. Nil: a graph is built from the findings (same verdicts, extra cost;
	// callers that have the graph should pass it).
	Graph *graph.Graph
}

// Evaluate runs every rule and returns scored, de-duplicated attack paths.
func Evaluate(findings []model.Finding, rules []Rule) []model.AttackPath {
	return EvaluateWith(findings, rules, EvalOptions{})
}

// EvaluateWith is Evaluate with options (trusted exposure).
func EvaluateWith(findings []model.Finding, rules []Rule, opts EvalOptions) []model.AttackPath {
	findings = withoutTrustedExposure(findings, opts.TrustedCIDRs)
	findings = withGraphVerdicts(findings, opts.Graph)
	g := Build(findings)
	var paths []model.AttackPath
	seen := map[string]bool{}
	for _, rule := range rules {
		if len(rule.Stages) == 0 {
			continue
		}
		for _, idx := range g.byWeak[rule.Stages[0].Weakness] {
			start := &g.findings[idx]
			if _, ok := g.matches(nil, start, rule.Stages[0]); !ok {
				continue
			}
			for _, chain := range g.extend(rule, 1, []*model.Finding{start}, []string{"entry"}) {
				p := g.toPath(rule, chain.findings, chain.relations)
				if seen[p.ID] {
					continue
				}
				seen[p.ID] = true
				paths = append(paths, p)
			}
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Score != paths[j].Score {
			return paths[i].Score > paths[j].Score
		}
		return paths[i].ID < paths[j].ID
	})
	return paths
}

type chain struct {
	findings  []*model.Finding
	relations []string
}

// extend recursively completes a chain; at each stage it keeps the tightest-related candidates
// (same_resource beats same_account) and caps fan-out so noisy accounts stay readable.
func (g *Graph) extend(rule Rule, stage int, cur []*model.Finding, rels []string) []chain {
	if stage >= len(rule.Stages) {
		return []chain{{findings: cur, relations: rels}}
	}
	st := rule.Stages[stage]
	prev := cur[len(cur)-1]
	type cand struct {
		f   *model.Finding
		rel string
	}
	var cands []cand
	bestTight := 0.0
	for _, idx := range g.byWeak[st.Weakness] {
		c := &g.findings[idx]
		rel, ok := g.matches(prev, c, st)
		if !ok {
			continue
		}
		cands = append(cands, cand{c, rel})
		if g.relTight[rel] > bestTight {
			bestTight = g.relTight[rel]
		}
	}
	var out []chain
	n := 0
	for _, c := range cands {
		if g.relTight[c.rel] < bestTight {
			continue // a tighter link exists; skip looser ones for this step
		}
		if n >= 3 {
			break
		}
		n++
		next := append(append([]*model.Finding{}, cur...), c.f)
		nrels := append(append([]string{}, rels...), c.rel)
		out = append(out, g.extend(rule, stage+1, next, nrels)...)
	}
	return out
}

func (g *Graph) toPath(rule Rule, fs []*model.Finding, rels []string) model.AttackPath {
	var ids []string
	score := 0.0
	var steps []model.Step
	var narrative []string
	for i, f := range fs {
		ids = append(ids, f.ID)
		tight := 1.0
		if i > 0 {
			tight = g.relTight[rels[i]]
		}
		score += float64(f.Severity.Rank()) * tight
		label := rule.Stages[i].Label
		summary := fmt.Sprintf("%s on %s", f.Title, f.Resource.Name)
		if i > 0 && weakRelation(rels[i]) {
			summary += " (" + strings.ReplaceAll(rels[i], "_", " ") + " only; confirm the resources are linked)"
		}
		steps = append(steps, model.Step{Stage: i + 1, FindingID: f.ID, Weakness: rule.Stages[i].Weakness, WeaknessOn: f.Resource.ID, Relation: rels[i], Resource: f.Resource.ID, Title: f.Title, Summary: summary,
			Because: ruleBecause(rule.Stages[i], f, rels[i]), Evidence: map[string]any{"rule_id": rule.ID, "finding_id": f.ID, "canonical_id": f.CanonicalID, "relation": rels[i], "weak_link": i > 0 && weakRelation(rels[i])}})
		narrative = append(narrative, fmt.Sprintf("%d. %s: %s [%s]", i+1, label, f.Resource.Name, f.CanonicalID))
	}
	score = score / float64(len(fs)) * (1 + 0.25*float64(len(fs)-1)) // longer validated chains score higher
	weak := false
	for i := 1; i < len(rels); i++ {
		weak = weak || weakRelation(rels[i])
	}
	if weak {
		score *= 0.5 // weak_link: at least one hop is co-tenancy, not a graph edge
	}
	score = float64(int(score*100)) / 100
	sum := sha256.Sum256([]byte(rule.ID + strings.Join(ids, ",")))
	// Severity is the band of the chain's score (PathSeverity), never the worst finding's
	// severity or a separate "≥ 5.5 is critical" scale (shortfall #1).
	sev := PathSeverity(score)
	return model.AttackPath{
		ID: hex.EncodeToString(sum[:8]), RuleID: rule.ID, Name: rule.Name, Impact: rule.Impact, Mitre: rule.Mitre,
		Provider: fs[0].Provider, Account: fs[0].Account, Score: score, Severity: sev, Steps: steps,
		Narrative: strings.Join(narrative, "\n"), FindingIDs: ids, WeakLink: weak,
	}
}

// Mermaid renders paths as a flowchart for docs, PRs and the VS Code extension.
func Mermaid(paths []model.AttackPath) string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	b.WriteString("  internet((Internet / Attacker))\n")
	for pi, p := range paths {
		prev := "internet"
		for si, s := range p.Steps {
			id := fmt.Sprintf("p%d_s%d", pi, si)
			label := strings.ReplaceAll(fmt.Sprintf("%s<br/>%s", s.Title, shorten(s.Resource, 40)), "\"", "'")
			fmt.Fprintf(&b, "  %s[\"%s\"]\n", id, label)
			fmt.Fprintf(&b, "  %s -->|%s| %s\n", prev, s.Relation, id)
			prev = id
		}
		impact := fmt.Sprintf("p%d_impact", pi)
		fmt.Fprintf(&b, "  %s{{\"%s\"}}\n  %s ==> %s\n", impact, p.Impact, prev, impact)
	}
	return b.String()
}

// DOT renders Graphviz output.
func DOT(paths []model.AttackPath) string {
	var b strings.Builder
	b.WriteString("digraph attack_paths {\n  rankdir=LR;\n  node [shape=box, style=rounded];\n  internet [label=\"Internet / Attacker\", shape=ellipse];\n")
	for pi, p := range paths {
		prev := "internet"
		for si, s := range p.Steps {
			id := fmt.Sprintf("p%d_s%d", pi, si)
			fmt.Fprintf(&b, "  %s [label=\"%s\\n%s\"];\n", id, escape(s.Title), escape(shorten(s.Resource, 40)))
			fmt.Fprintf(&b, "  %s -> %s [label=\"%s\"];\n", prev, id, s.Relation)
			prev = id
		}
		fmt.Fprintf(&b, "  p%d_impact [label=\"%s\", shape=octagon, color=red];\n  %s -> p%d_impact [penwidth=2];\n", pi, escape(p.Impact), prev, pi)
	}
	b.WriteString("}\n")
	return b.String()
}

func escape(s string) string { return strings.ReplaceAll(s, "\"", "\\\"") }

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n+1:]
}

// ruleBecause explains a rule-engine step: which finding satisfied the stage and how it links
// to the previous step (same_account links are flagged as unconfirmed).
func ruleBecause(st Stage, f *model.Finding, rel string) string {
	b := fmt.Sprintf("finding %s (%s) on %s carries %s", f.CanonicalID, f.Title, f.Resource.Name, st.Weakness)
	switch rel {
	case "entry":
	case "same_resource":
		b += "; same resource as the previous step"
	case "related":
		b += "; resource linked to the previous step"
	case "same_account":
		b += "; same account as the previous step only (link not confirmed; weak link: " + st.Justification + ")"
	case "any":
		b += "; no confirmed link to the previous step (weak link: " + st.Justification + ")"
	}
	if len(st.Requires) > 0 {
		b += "; also requires " + strings.Join(st.Requires, " AND ")
	}
	return b
}

// withoutTrustedExposure drops the internet-exposure weaknesses from findings whose exposure
// evidence is trusted or private (copies; the input is not modified).
func withoutTrustedExposure(fs []model.Finding, trusted []string) []model.Finding {
	var out []model.Finding
	changed := false
	for i := range fs {
		f := fs[i]
		if (f.HasWeakness("PUBLIC_NETWORK_EXPOSURE") || f.HasWeakness("PUBLIC_DATA_STORE")) && findingExposureSuppressed(&f, trusted) {
			var keep []string
			for _, w := range f.Weaknesses {
				if w != "PUBLIC_NETWORK_EXPOSURE" && w != "PUBLIC_DATA_STORE" {
					keep = append(keep, w)
				}
			}
			f.Weaknesses = keep
			changed = true
		}
		out = append(out, f)
	}
	if !changed {
		return fs
	}
	return out
}

// withGraphVerdicts drops weaknesses the graph has disproved (copies; the input is not modified):
// OVERPRIVILEGED_IDENTITY on an identity whose admin rights are neutralised (effective_admin none
// or listed in neutralised_weaknesses), and the public-exposure weaknesses of a resource REACH
// marked blocked, and CROSS_ACCOUNT_TRUST on a role whose trust conditions limit it to its own
// organisation / account (W7-ENGINE r5 #15: the same verdict traversal's entry uses). g nil: built from the findings when any finding could be affected.
func withGraphVerdicts(fs []model.Finding, g *graph.Graph) []model.Finding {
	if g == nil {
		need := false
		for i := range fs {
			if fs[i].Status == model.Fail && (fs[i].HasWeakness("OVERPRIVILEGED_IDENTITY") || fs[i].HasWeakness("PUBLIC_NETWORK_EXPOSURE") || fs[i].HasWeakness("PUBLIC_DATA_STORE") || fs[i].HasWeakness("CROSS_ACCOUNT_TRUST")) {
				need = true
				break
			}
		}
		if !need {
			return fs
		}
		g = graph.New()
		g.AttachFindings(fs)
	}
	drop := func(n *graph.Node) map[string]bool {
		out := map[string]bool{}
		if n == nil {
			return out
		}
		if v, _ := n.Attributes["effective_admin"].(string); v == "none" {
			out["OVERPRIVILEGED_IDENTITY"] = true
		}
		for _, w := range toStrings(n.Attributes["neutralised_weaknesses"]) {
			out[w] = true
		}
		blocked := reachBlockedNode(n) != ""
		if !blocked {
			any, all := false, true
			for _, e := range g.In(n.ID) {
				if e.From == graph.InternetNodeID {
					any = true
					all = all && reachBlockedEdge(e, nil) != ""
				}
			}
			blocked = any && all
		}
		if blocked {
			out["PUBLIC_NETWORK_EXPOSURE"], out["PUBLIC_DATA_STORE"] = true, true
		}
		if n.Class == graph.ClassIdentity && trustConditionsOf(g, n).org != "" {
			out["CROSS_ACCOUNT_TRUST"] = true // limited to the own organisation / account: not external
		}
		return out
	}
	var out []model.Finding
	changed := false
	for i := range fs {
		f := fs[i]
		n, _ := g.Node(f.Resource.ID)
		d := drop(n)
		if len(d) > 0 {
			var keep []string
			for _, w := range f.Weaknesses {
				if !d[w] {
					keep = append(keep, w)
				}
			}
			if len(keep) != len(f.Weaknesses) {
				f.Weaknesses = keep
				changed = true
			}
		}
		out = append(out, f)
	}
	if !changed {
		return fs
	}
	return out
}
