package attackpath

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"path"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Graph traversal attack-path analysis.
//
// Scoring follows the most transparent model on the market (Google SCC attack exposure):
//   score = likelihood × priority, on a 0–10 scale
//   likelihood = Π step_exploitability × hop_decay^hops    (AND semantics along a path,
//                OR semantics across alternative paths to the same target)
//   priority   = crown-jewel criticality: 4 → 10, 3 → 5, 2 → 2, 1 → 1
// Each step records which weakness made it exploitable, so "break the path" can tell a
// fix that removes the path from one that only lowers its likelihood.

type JewelRule struct {
	Pattern     string `yaml:"pattern" json:"pattern"` // glob on node name, id or type
	Criticality int    `yaml:"criticality" json:"criticality"`
}

type TraversalOptions struct {
	MaxHops      int
	MaxPaths     int // overall cap, highest-scoring kept
	MinScore     float64
	CrownJewels  []JewelRule
	HopDecay     float64
	MaxBranching int
}

func DefaultTraversalOptions() TraversalOptions {
	return TraversalOptions{MaxHops: 6, MaxPaths: 500, MinScore: 0.5, HopDecay: 0.95, MaxBranching: 25}
}

type ChokePoint struct {
	NodeID     string   `json:"node_id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Paths      int      `json:"paths"`
	ScoreSum   float64  `json:"score_sum"`
	Weaknesses []string `json:"weaknesses"`
}

// Fix is one remediation action and the paths it affects.
type Fix struct {
	NodeID      string   `json:"node_id"`
	Name        string   `json:"name"`
	Weakness    string   `json:"weakness"`
	FindingIDs  []string `json:"finding_ids"`
	Breaks      []string `json:"breaks"`       // path IDs removed entirely
	Reduces     []string `json:"reduces"`      // path IDs whose likelihood drops but survive
	ScoreRemoved float64 `json:"score_removed"`
	Command     string   `json:"command"`
}

type Analysis struct {
	Paths          []model.AttackPath `json:"paths"`
	EntryPoints    []string           `json:"entry_points"`
	Targets        []string           `json:"targets"`
	ChokePoints    []ChokePoint       `json:"choke_points"`
	BreakFixes     []Fix              `json:"break_fixes"`      // "Recommendations": break ≥1 path
	ReduceFixes    []Fix              `json:"reduce_fixes"`     // "Additional": lower risk only
	MinFixSet      []Fix              `json:"min_fix_set"`      // cheapest set cutting every path (greedy weighted set cover)
	MinFixCoverage float64            `json:"min_fix_coverage"` // share of total score removed by MinFixSet
	TotalScore     float64            `json:"total_score"`
}

// Built-in crown-jewel catalog (highest matching rule wins; user rules override).
var defaultJewels = []JewelRule{
	{Pattern: "*secret*", Criticality: 4}, {Pattern: "*vault*", Criticality: 4}, {Pattern: "*prod*db*", Criticality: 4}, {Pattern: "*payment*", Criticality: 4},
	{Pattern: "*pii*", Criticality: 4}, {Pattern: "*customer*", Criticality: 4}, {Pattern: "*root", Criticality: 4}, {Pattern: "*admin*", Criticality: 4},
	{Pattern: "*cluster-admin*", Criticality: 4}, {Pattern: "*prod*", Criticality: 3}, {Pattern: "*backup*", Criticality: 3}, {Pattern: "*finance*", Criticality: 3},
}

// Criticality returns 0 (not a target) .. 4 (tier-0 crown jewel) for a node.
func Criticality(n *graph.Node, rules []JewelRule) int {
	best := 0
	match := func(rs []JewelRule) {
		for _, r := range rs {
			for _, s := range []string{n.Name, n.ID, n.Type} {
				if ok, _ := path.Match(strings.ToLower(r.Pattern), strings.ToLower(s)); ok || strings.Contains(strings.ToLower(s), strings.Trim(strings.ToLower(r.Pattern), "*")) && strings.Trim(r.Pattern, "*") != "" {
					if r.Criticality > best {
						best = r.Criticality
					}
				}
			}
		}
	}
	match(rules)
	if best > 0 {
		return best
	}
	switch n.Class {
	case graph.ClassDataStore:
		if n.Sensitive && n.Criticality == "production" {
			best = 4
		} else if n.Sensitive {
			best = 3
		} else {
			best = 2
		}
	case graph.ClassIdentity:
		if n.HasWeakness("OVERPRIVILEGED_IDENTITY") || n.HasWeakness("CLUSTER_ADMIN") {
			best = 4
		}
	case graph.ClassCluster, graph.ClassAccount:
		best = 3
	}
	match(defaultJewels)
	if n.Class == graph.ClassNetwork || n.Class == graph.ClassInternet {
		return 0
	}
	return best
}

var priorityOf = map[int]float64{4: 10, 3: 5, 2: 2, 1: 1}

// step is an exploitability evaluation of entering `to` via edge `kind` from `from`.
type stepEval struct {
	exploitability float64
	weakness       string // weakness that made it possible ("" when structural, e.g. explicit grant)
	label          string
}

// evaluate returns 0 when the edge is not an attack step.
func evaluate(from, to *graph.Node, kind string, final bool) stepEval {
	has := to.HasWeakness
	switch kind {
	case graph.EdgeExposes:
		switch {
		case has("PUBLIC_DATA_STORE"):
			return stepEval{1.0, "PUBLIC_DATA_STORE", "readable by anyone on the internet"}
		case has("PUBLIC_NETWORK_EXPOSURE") && (has("UNPATCHED") || to.CVECount > 0):
			return stepEval{0.95, "UNPATCHED", "reachable from the internet and runs exploitable software"}
		case has("PUBLIC_NETWORK_EXPOSURE") && has("WEAK_AUTH"):
			return stepEval{0.8, "WEAK_AUTH", "reachable from the internet with weak authentication"}
		case has("PUBLIC_NETWORK_EXPOSURE"):
			return stepEval{0.7, "PUBLIC_NETWORK_EXPOSURE", "reachable from the internet"}
		}
		return stepEval{0.4, "", "exposed to the internet"}
	case graph.EdgeAllowsTrafficTo:
		if from.Class == graph.ClassInternet || from.HasWeakness("PUBLIC_NETWORK_EXPOSURE") {
			e := 0.55
			w := "PUBLIC_NETWORK_EXPOSURE"
			if has("UNPATCHED") || to.CVECount > 0 {
				e, w = 0.95, "UNPATCHED"
			} else if has("WEAK_AUTH") {
				e, w = 0.8, "WEAK_AUTH"
			}
			return stepEval{e, w, "network path allows inbound traffic"}
		}
		return stepEval{0.5, "", "lateral network movement"}
	case graph.EdgeRunsAs, graph.EdgeAttachedTo:
		if to.Class != graph.ClassIdentity {
			return stepEval{}
		}
		if from.HasWeakness("IMDSV1_ENABLED") {
			return stepEval{0.9, "IMDSV1_ENABLED", "role credentials stolen via IMDSv1 (SSRF)"}
		}
		if from.HasWeakness("PRIVILEGED_CONTAINER") || from.HasWeakness("HOST_ACCESS") {
			return stepEval{0.85, "PRIVILEGED_CONTAINER", "container escape exposes node credentials"}
		}
		if from.HasWeakness("SERVICE_ACCOUNT_TOKEN") {
			return stepEval{0.8, "SERVICE_ACCOUNT_TOKEN", "mounted service account token"}
		}
		return stepEval{0.5, "", "workload identity usable after code execution"}
	case graph.EdgeHasPolicy:
		if has("OVERPRIVILEGED_IDENTITY") {
			return stepEval{1.0, "OVERPRIVILEGED_IDENTITY", "wildcard administrative policy"}
		}
		return stepEval{0.9, "", "attached policy"}
	case graph.EdgeGrantsAccessTo, graph.EdgeStoresDataIn:
		if from.HasWeakness("OVERPRIVILEGED_IDENTITY") {
			return stepEval{1.0, "OVERPRIVILEGED_IDENTITY", "admin privileges reach the data"}
		}
		return stepEval{0.85, "", "policy grants data access"}
	case graph.EdgeCanAssume:
		if has("CROSS_ACCOUNT_TRUST") || from.HasWeakness("CROSS_ACCOUNT_TRUST") {
			return stepEval{0.9, "CROSS_ACCOUNT_TRUST", "role assumable by external principals"}
		}
		if has("OVERPRIVILEGED_IDENTITY") {
			return stepEval{0.8, "OVERPRIVILEGED_IDENTITY", "assume into an admin role"}
		}
		return stepEval{0.6, "", "sts:AssumeRole permitted"}
	case graph.EdgeBoundTo:
		if has("CLUSTER_ADMIN") || has("OVERPRIVILEGED_IDENTITY") {
			return stepEval{1.0, "CLUSTER_ADMIN", "bound to cluster-admin"}
		}
		return stepEval{0.6, "", "RBAC binding"}
	case graph.EdgeMemberOf:
		if to.Class == graph.ClassIdentity {
			return stepEval{0.8, "", "group membership"}
		}
		return stepEval{}
	case graph.EdgeTrusts:
		return stepEval{}
	}
	return stepEval{}
}

// entryEval scores identity entry points that need no network path (phished / leaked credentials).
func entryEval(n *graph.Node) stepEval {
	switch {
	case n.Class == graph.ClassIdentity && n.HasWeakness("NO_MFA"):
		return stepEval{0.5, "NO_MFA", "credential phishing succeeds without MFA"}
	case n.Class == graph.ClassIdentity && n.HasWeakness("STALE_CREDENTIALS"):
		return stepEval{0.4, "STALE_CREDENTIALS", "long-lived access key leaked or reused"}
	case n.Class == graph.ClassIdentity && n.HasWeakness("WEAK_AUTH"):
		return stepEval{0.45, "WEAK_AUTH", "legacy or weak authentication"}
	case n.Class == graph.ClassSaaS && n.HasWeakness("BRANCH_UNPROTECTED"):
		return stepEval{0.4, "BRANCH_UNPROTECTED", "unreviewed code lands in the pipeline"}
	case n.HasWeakness("SECRET_EXPOSURE"):
		return stepEval{0.6, "SECRET_EXPOSURE", "hard-coded secret reused"}
	}
	return stepEval{}
}

type frame struct {
	node  *graph.Node
	steps []model.Step
	lik   float64
	seen  map[string]bool
}

// Traverse finds attack paths from entry points to crown jewels over the security graph.
func Traverse(g *graph.Graph, opts TraversalOptions) *Analysis {
	if opts.MaxHops == 0 {
		opts = DefaultTraversalOptions()
	}
	an := &Analysis{}
	crit := map[string]int{}
	for _, n := range g.Nodes() {
		crit[n.ID] = Criticality(n, opts.CrownJewels)
		if crit[n.ID] >= 2 && n.Class != graph.ClassAccount {
			an.Targets = append(an.Targets, n.ID)
		}
	}
	// Entry points: the internet node, plus identities/SaaS nodes with credential weaknesses.
	type entry struct {
		node *graph.Node
		eval stepEval
	}
	var entries []entry
	if inet, ok := g.Node(graph.InternetNodeID); ok {
		entries = append(entries, entry{inet, stepEval{1, "", "attacker on the internet"}})
		an.EntryPoints = append(an.EntryPoints, inet.ID)
	}
	for _, n := range g.Nodes() {
		if ev := entryEval(n); ev.exploitability > 0 {
			entries = append(entries, entry{n, ev})
			an.EntryPoints = append(an.EntryPoints, n.ID)
		}
	}
	var paths []model.AttackPath
	seenPath := map[string]bool{}
	for _, en := range entries {
		start := frame{node: en.node, lik: en.eval.exploitability, seen: map[string]bool{en.node.ID: true}}
		if en.node.ID != graph.InternetNodeID {
			start.steps = []model.Step{stepFor(en.node, 1, "entry", en.eval)}
		}
		stack := []frame{start}
		explored := 0
		for len(stack) > 0 && explored < 20000 {
			fr := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			explored++
			hops := len(fr.steps)
			// Emit a path when we stand on a crown jewel reached through ≥1 attack step.
			if c := crit[fr.node.ID]; c >= 2 && hops >= 1 && fr.node.ID != en.node.ID || (c >= 2 && hops >= 1 && en.node.ID == fr.node.ID && hops > 1) {
				p := buildPath(g, en.node, fr, priorityOf[c])
				if p.Score >= opts.MinScore && !seenPath[p.ID] {
					seenPath[p.ID] = true
					paths = append(paths, p)
				}
				if fr.node.Class == graph.ClassDataStore {
					continue // data is the end of the kill chain
				}
			}
			if hops >= opts.MaxHops {
				continue
			}
			branches := 0
			for _, e := range g.Out(fr.node.ID) {
				if fr.seen[e.To] {
					continue
				}
				to, ok := g.Node(e.To)
				if !ok {
					continue
				}
				ev := evaluate(fr.node, to, e.Kind, false)
				if ev.exploitability == 0 {
					continue
				}
				if branches >= opts.MaxBranching {
					break
				}
				branches++
				lik := fr.lik * ev.exploitability * opts.HopDecay
				if lik < 0.02 {
					continue
				}
				seen := make(map[string]bool, len(fr.seen)+1)
				for k := range fr.seen {
					seen[k] = true
				}
				seen[to.ID] = true
				steps := append(append([]model.Step{}, fr.steps...), stepFor(to, hops+1, e.Kind, ev))
				stack = append(stack, frame{node: to, steps: steps, lik: lik, seen: seen})
			}
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Score != paths[j].Score {
			return paths[i].Score > paths[j].Score
		}
		return paths[i].ID < paths[j].ID
	})
	if opts.MaxPaths > 0 && len(paths) > opts.MaxPaths {
		paths = paths[:opts.MaxPaths]
	}
	an.Paths = paths
	an.analyzeFixes(g)
	return an
}

func stepFor(n *graph.Node, stage int, relation string, ev stepEval) model.Step {
	fid := ""
	if len(n.FindingIDs) > 0 {
		fid = n.FindingIDs[0]
	}
	return model.Step{Stage: stage, FindingID: fid, Weakness: ev.weakness, Relation: relation, Resource: n.ID,
		Title: n.Name, Summary: fmt.Sprintf("%s (%s): %s [p=%.2f]", n.Name, n.Type, ev.label, ev.exploitability)}
}

func buildPath(g *graph.Graph, entry *graph.Node, fr frame, priority float64) model.AttackPath {
	target := fr.node
	score := math.Round(fr.lik*priority*100) / 100
	if score > 10 {
		score = 10
	}
	var ids []string
	var ids2 []string
	for _, s := range fr.steps {
		ids = append(ids, s.Resource)
		if n, ok := g.Node(s.Resource); ok {
			ids2 = append(ids2, n.FindingIDs...)
		}
	}
	sum := sha256.Sum256([]byte(entry.ID + "|" + strings.Join(ids, ">")))
	sev := model.Low
	switch {
	case score >= 7:
		sev = model.Critical
	case score >= 4:
		sev = model.High
	case score >= 2:
		sev = model.Medium
	}
	var narr []string
	narr = append(narr, fmt.Sprintf("Entry: %s", entry.Name))
	for _, s := range fr.steps {
		narr = append(narr, fmt.Sprintf("%d. %s", s.Stage, s.Summary))
	}
	narr = append(narr, fmt.Sprintf("Target: %s (%s) — likelihood %.0f%% × priority %.0f", target.Name, target.Type, fr.lik*100, priority))
	provider, account := target.Provider, target.Account
	if provider == "" || provider == "any" {
		if len(fr.steps) > 0 {
			if n, ok := g.Node(fr.steps[0].Resource); ok {
				provider, account = n.Provider, n.Account
			}
		}
	}
	return model.AttackPath{
		ID: hex.EncodeToString(sum[:8]), RuleID: "GRAPH_TRAVERSAL", Name: fmt.Sprintf("%s → %s", entry.Name, target.Name),
		Impact: impactFor(target), Mitre: mitreFor(fr.steps), Provider: provider, Account: account, Score: score, Severity: sev,
		Steps: fr.steps, Narrative: strings.Join(narr, "\n"), FindingIDs: uniq(ids2),
	}
}

func impactFor(n *graph.Node) string {
	switch n.Class {
	case graph.ClassDataStore:
		if n.Sensitive {
			return "Sensitive data exfiltration from " + n.Name
		}
		return "Data access on " + n.Name
	case graph.ClassIdentity:
		return "Privilege escalation to " + n.Name
	case graph.ClassCluster:
		return "Cluster takeover: " + n.Name
	case graph.ClassAccount:
		return "Account compromise: " + n.Name
	}
	return "Compromise of " + n.Name
}

func mitreFor(steps []model.Step) []string {
	set := map[string]bool{}
	for _, s := range steps {
		switch s.Weakness {
		case "PUBLIC_NETWORK_EXPOSURE", "UNPATCHED", "PUBLIC_DATA_STORE":
			set["T1190"] = true
		case "IMDSV1_ENABLED":
			set["T1552.005"] = true
		case "OVERPRIVILEGED_IDENTITY", "CLUSTER_ADMIN":
			set["T1078.004"] = true
		case "NO_MFA", "WEAK_AUTH":
			set["T1078"] = true
		case "STALE_CREDENTIALS", "SECRET_EXPOSURE":
			set["T1552.001"] = true
		case "CROSS_ACCOUNT_TRUST":
			set["T1098.003"] = true
		case "PRIVILEGED_CONTAINER":
			set["T1611"] = true
		case "SERVICE_ACCOUNT_TOKEN":
			set["T1528"] = true
		case "BRANCH_UNPROTECTED":
			set["T1195.002"] = true
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// analyzeFixes computes choke points, break-the-path fixes and the minimal fix set.
func (an *Analysis) analyzeFixes(g *graph.Graph) {
	type key struct{ node, weak string }
	fixPaths := map[key]map[string]bool{}
	reducePaths := map[key]map[string]bool{}
	choke := map[string]*ChokePoint{}
	for _, p := range an.Paths {
		an.TotalScore += p.Score
		last := len(p.Steps) - 1
		for i, s := range p.Steps {
			n, ok := g.Node(s.Resource)
			if !ok {
				continue
			}
			if i != last && n.Class != graph.ClassInternet {
				cp := choke[n.ID]
				if cp == nil {
					cp = &ChokePoint{NodeID: n.ID, Name: n.Name, Type: n.Type, Weaknesses: n.Weaknesses}
					choke[n.ID] = cp
				}
				cp.Paths++
				cp.ScoreSum += p.Score
			}
			for _, w := range n.Weaknesses {
				k := key{n.ID, w}
				if w == s.Weakness {
					if fixPaths[k] == nil {
						fixPaths[k] = map[string]bool{}
					}
					fixPaths[k][p.ID] = true
				} else {
					if reducePaths[k] == nil {
						reducePaths[k] = map[string]bool{}
					}
					reducePaths[k][p.ID] = true
				}
			}
		}
	}
	scoreOf := map[string]float64{}
	for _, p := range an.Paths {
		scoreOf[p.ID] = p.Score
	}
	mk := func(k key, breaks, reduces map[string]bool) Fix {
		n, _ := g.Node(k.node)
		f := Fix{NodeID: k.node, Weakness: k.weak}
		if n != nil {
			f.Name = n.Name
			f.FindingIDs = n.FindingIDs
		}
		for id := range breaks {
			f.Breaks = append(f.Breaks, id)
			f.ScoreRemoved += scoreOf[id]
		}
		for id := range reduces {
			if !breaks[id] {
				f.Reduces = append(f.Reduces, id)
			}
		}
		sort.Strings(f.Breaks)
		sort.Strings(f.Reduces)
		f.Command = fixCommand(k.weak, n)
		return f
	}
	for k, ps := range fixPaths {
		an.BreakFixes = append(an.BreakFixes, mk(k, ps, reducePaths[k]))
	}
	for k, ps := range reducePaths {
		if _, isBreak := fixPaths[k]; !isBreak {
			an.ReduceFixes = append(an.ReduceFixes, mk(k, nil, ps))
		}
	}
	sort.Slice(an.BreakFixes, func(i, j int) bool {
		if len(an.BreakFixes[i].Breaks) != len(an.BreakFixes[j].Breaks) {
			return len(an.BreakFixes[i].Breaks) > len(an.BreakFixes[j].Breaks)
		}
		return an.BreakFixes[i].ScoreRemoved > an.BreakFixes[j].ScoreRemoved
	})
	sort.Slice(an.ReduceFixes, func(i, j int) bool { return len(an.ReduceFixes[i].Reduces) > len(an.ReduceFixes[j].Reduces) })
	for _, cp := range choke {
		an.ChokePoints = append(an.ChokePoints, *cp)
	}
	sort.Slice(an.ChokePoints, func(i, j int) bool {
		if an.ChokePoints[i].Paths != an.ChokePoints[j].Paths {
			return an.ChokePoints[i].Paths > an.ChokePoints[j].Paths
		}
		return an.ChokePoints[i].ScoreSum > an.ChokePoints[j].ScoreSum
	})
	if len(an.ChokePoints) > 10 {
		an.ChokePoints = an.ChokePoints[:10]
	}
	// Greedy weighted set cover: smallest fix set that cuts every path (min-cut approximation).
	remaining := map[string]bool{}
	for _, p := range an.Paths {
		remaining[p.ID] = true
	}
	cands := append([]Fix{}, an.BreakFixes...)
	removed := 0.0
	for len(remaining) > 0 && len(cands) > 0 {
		bestIdx, bestGain := -1, 0.0
		for i, f := range cands {
			gain := 0.0
			for _, id := range f.Breaks {
				if remaining[id] {
					gain += scoreOf[id]
				}
			}
			if gain > bestGain {
				bestIdx, bestGain = i, gain
			}
		}
		if bestIdx < 0 {
			break
		}
		f := cands[bestIdx]
		for _, id := range f.Breaks {
			if remaining[id] {
				delete(remaining, id)
				removed += scoreOf[id]
			}
		}
		an.MinFixSet = append(an.MinFixSet, f)
		cands = append(cands[:bestIdx], cands[bestIdx+1:]...)
	}
	if an.TotalScore > 0 {
		an.MinFixCoverage = math.Round(removed/an.TotalScore*1000) / 10
	}
}

var weaknessToCanonical = map[string]string{
	"PUBLIC_DATA_STORE": "S3_PUBLIC_BUCKET", "PUBLIC_NETWORK_EXPOSURE": "EC2_SG_OPEN_SSH", "IMDSV1_ENABLED": "EC2_IMDSV1",
	"OVERPRIVILEGED_IDENTITY": "IAM_ADMIN_POLICY", "NO_MFA": "IAM_USER_NO_MFA", "STALE_CREDENTIALS": "IAM_STALE_KEYS",
	"CROSS_ACCOUNT_TRUST": "IAM_CROSS_ACCOUNT_TRUST", "UNENCRYPTED_AT_REST": "RDS_UNENCRYPTED", "NO_LOGGING": "CLOUDTRAIL_DISABLED",
	"PRIVILEGED_CONTAINER": "K8S_PRIVILEGED_CONTAINER", "CLUSTER_ADMIN": "K8S_CLUSTER_ADMIN_BINDING", "SERVICE_ACCOUNT_TOKEN": "K8S_DEFAULT_SA_TOKEN",
}

func fixCommand(weak string, n *graph.Node) string {
	if n != nil && len(n.FindingIDs) > 0 {
		return "cloud-posture fix --id " + n.FindingIDs[0] + " --generate-terraform"
	}
	if c, ok := weaknessToCanonical[weak]; ok {
		return "cloud-posture fix --finding " + c + " --generate-terraform"
	}
	return "cloud-posture fix --weakness " + weak
}

// BlastRadius lists everything reachable from a node within maxHops over attack edges,
// with the sensitive targets called out (the "what if this is compromised" view).
func BlastRadius(g *graph.Graph, nodeID string, maxHops int, jewels []JewelRule) (reachable []string, sensitive []string) {
	start, ok := g.Node(nodeID)
	if !ok {
		return nil, nil
	}
	type item struct {
		id   string
		hops int
	}
	seen := map[string]bool{nodeID: true}
	queue := []item{{nodeID, 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.hops >= maxHops {
			continue
		}
		from, _ := g.Node(cur.id)
		for _, e := range g.Out(cur.id) {
			if seen[e.To] {
				continue
			}
			to, ok := g.Node(e.To)
			if !ok || evaluate(from, to, e.Kind, false).exploitability == 0 {
				continue
			}
			seen[e.To] = true
			reachable = append(reachable, e.To)
			if Criticality(to, jewels) >= 3 {
				sensitive = append(sensitive, e.To)
			}
			queue = append(queue, item{e.To, cur.hops + 1})
		}
	}
	_ = start
	sort.Strings(reachable)
	sort.Strings(sensitive)
	return
}

// Merge combines rule-based and traversal paths, de-duplicated by ID and sorted by score.
func Merge(a, b []model.AttackPath) []model.AttackPath {
	seen := map[string]bool{}
	var out []model.AttackPath
	for _, p := range append(append([]model.AttackPath{}, a...), b...) {
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func uniq(in []string) []string {
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
