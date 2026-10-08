// Package attackpath chains individual misconfigurations into breach scenarios.
package attackpath

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

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
	return rf.Rules, nil
}

// Graph indexes findings by weakness and resource relationships.
type Graph struct {
	findings  []model.Finding
	byWeak    map[string][]int
	edges     map[string]map[string]bool // resourceID -> neighbours
	byRes     map[string][]int
	relTight  map[string]float64
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

func sameAccount(a, b *model.Finding) bool {
	return a.Provider == b.Provider && a.Account == b.Account
}

// matches tests a candidate against a stage relative to the previous finding; returns the relation used.
func (g *Graph) matches(prev, cand *model.Finding, st Stage) (string, bool) {
	if !cand.HasWeakness(st.Weakness) {
		return "", false
	}
	for _, req := range st.Requires {
		if !cand.HasWeakness(req) {
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
			return sameAccount(prev, cand) && g.related(prev, cand)
		case "same_account":
			return sameAccount(prev, cand)
		case "any":
			return true
		}
		return false
	}
	rel := st.Relation
	if rel == "" {
		rel = "same_account"
	}
	if check(rel) {
		return rel, true
	}
	if st.Fallback != "" && check(st.Fallback) {
		return st.Fallback, true
	}
	return "", false
}

// Evaluate runs every rule and returns scored, de-duplicated attack paths.
func Evaluate(findings []model.Finding, rules []Rule) []model.AttackPath {
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
	maxSev := model.Info
	var steps []model.Step
	var narrative []string
	for i, f := range fs {
		ids = append(ids, f.ID)
		tight := 1.0
		if i > 0 {
			tight = g.relTight[rels[i]]
		}
		score += float64(f.Severity.Rank()) * tight
		if f.Severity.Rank() > maxSev.Rank() {
			maxSev = f.Severity
		}
		label := rule.Stages[i].Label
		summary := fmt.Sprintf("%s on %s", f.Title, f.Resource.Name)
		if i > 0 && rels[i] == "same_account" {
			summary += " (same account; confirm the resources are linked)"
		}
		steps = append(steps, model.Step{Stage: i + 1, FindingID: f.ID, Weakness: rule.Stages[i].Weakness, Relation: rels[i], Resource: f.Resource.ID, Title: f.Title, Summary: summary})
		narrative = append(narrative, fmt.Sprintf("%d. %s: %s [%s]", i+1, label, f.Resource.Name, f.CanonicalID))
	}
	score = score / float64(len(fs)) * (1 + 0.25*float64(len(fs)-1)) // longer validated chains score higher
	score = float64(int(score*100)) / 100
	sum := sha256.Sum256([]byte(rule.ID + strings.Join(ids, ",")))
	sev := maxSev
	if score >= 5.5 {
		sev = model.Critical
	}
	return model.AttackPath{
		ID: hex.EncodeToString(sum[:8]), RuleID: rule.ID, Name: rule.Name, Impact: rule.Impact, Mitre: rule.Mitre,
		Provider: fs[0].Provider, Account: fs[0].Account, Score: score, Severity: sev, Steps: steps,
		Narrative: strings.Join(narrative, "\n"), FindingIDs: ids,
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
