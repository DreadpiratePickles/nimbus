package attackpath

import (
	"math"
	"math/bits"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Exact minimum fix set limits: brute-force-sized candidate lists are always solved exactly;
// larger ones are solved exactly by branch and bound when the graph has ≤ exactEdgeMax edges
// and the search fits its budget, otherwise greedy set cover is used (MinFixExact=false).
const (
	exactBruteForceMax = 20
	exactEdgeMax       = 2000
)

// ApplyFixes returns a copy of g with the fixes applied in-graph; g is never modified.
//
// Removing a weakness also removes the edges that weakness creates:
//   - PUBLIC_NETWORK_EXPOSURE / PUBLIC_DATA_STORE: every edge from the internet into the node
//   - OVERPRIVILEGED_IDENTITY: inbound has_policy edges (the admin policy/role is detached)
//     and outbound wildcard grants (actions "*"/"svc:*" or resource "*")
//   - CROSS_ACCOUNT_TRUST: inbound can_assume edges from the internet, account nodes or
//     principals in another account
//   - CLUSTER_ADMIN on an RBAC binding: every bound_to / member_of edge that binding created
//
// Any other weakness is removed from the node only. Fix.Edge deletes that one edge.
func ApplyFixes(g *graph.Graph, fixes []Fix) *graph.Graph {
	c := g.Clone()
	for _, fx := range fixes {
		for _, e := range fixEdges(c, fx) {
			c.RemoveEdge(e.From, e.To, e.Kind)
		}
		if fx.NodeID != "" && fx.Weakness != "" {
			c.RemoveWeakness(fx.NodeID, fx.Weakness)
		}
	}
	return c
}

func fixEdges(g *graph.Graph, fx Fix) []EdgeRef {
	var out []EdgeRef
	if fx.Edge != nil {
		out = append(out, *fx.Edge)
	}
	n, ok := g.Node(fx.NodeID)
	if !ok || fx.Weakness == "" || !n.HasWeakness(fx.Weakness) {
		return out
	}
	ref := func(e *graph.Edge) { out = append(out, EdgeRef{From: e.From, To: e.To, Kind: e.Kind}) }
	switch fx.Weakness {
	case "PUBLIC_NETWORK_EXPOSURE", "PUBLIC_DATA_STORE":
		for _, e := range g.In(n.ID) {
			if e.From == graph.InternetNodeID {
				ref(e)
			}
		}
	case "OVERPRIVILEGED_IDENTITY":
		for _, e := range g.In(n.ID) {
			if e.Kind == graph.EdgeHasPolicy {
				ref(e)
			}
		}
		for _, e := range g.Out(n.ID) {
			if e.Kind == graph.EdgeGrantsAccessTo && wildcardGrant(e.Attr) {
				ref(e)
			}
		}
	case "CROSS_ACCOUNT_TRUST":
		for _, e := range g.In(n.ID) {
			if e.Kind != graph.EdgeCanAssume {
				continue
			}
			src, _ := g.Node(e.From)
			if e.From == graph.InternetNodeID || src == nil || src.Class == graph.ClassAccount || (src.Account != "" && n.Account != "" && src.Account != n.Account) {
				ref(e)
			}
		}
	case "CLUSTER_ADMIN":
		isBinding := false
		for _, e := range g.Out(n.ID) {
			if e.Kind == graph.EdgeBoundTo {
				isBinding = true
				ref(e)
			}
		}
		if !isBinding {
			break
		}
		for _, e := range g.Edges() {
			if e.Kind != graph.EdgeBoundTo && e.Kind != graph.EdgeMemberOf {
				continue
			}
			if b, _ := e.Attr["binding"].(string); b != "" && (b == n.Name || strings.HasSuffix(n.ID, "/"+b)) {
				ref(e)
			}
		}
	}
	return out
}

func wildcardGrant(attr map[string]any) bool {
	if p, _ := attr["resource_pattern"].(string); p == "*" {
		return true
	}
	var acts []string
	switch v := attr["actions"].(type) {
	case string:
		acts = strings.Split(v, ",")
	case []string:
		acts = v
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok {
				acts = append(acts, s)
			}
		}
	}
	for _, a := range acts {
		if a = strings.TrimSpace(a); a == "*" || strings.HasSuffix(a, ":*") {
			return true
		}
	}
	return false
}

// Simulate applies fixes in-graph, re-runs the traversal with default options and returns how
// many of today's complete paths disappear and the total score of the paths that remain.
// It is the plan math behind "resolves N / reduces M"; g is not modified.
func Simulate(g *graph.Graph, fixes []Fix) (removedPaths int, remainingScore float64) {
	return SimulateWith(g, DefaultTraversalOptions(), fixes)
}

// SimulateWith is Simulate with explicit traversal options (crown jewels, limits).
func SimulateWith(g *graph.Graph, opts TraversalOptions, fixes []Fix) (removedPaths int, remainingScore float64) {
	before := traverse(g, opts)
	after := traverse(ApplyFixes(g, fixes), opts)
	return removedCount(before.Paths, after.allPaths), after.TotalScore
}

// removedCount counts paths in before whose ID no longer appears in after.
func removedCount(before, after []model.AttackPath) int {
	still := make(map[string]bool, len(after))
	for _, p := range after {
		still[p.ID] = true
	}
	n := 0
	for _, p := range before {
		if !still[p.ID] {
			n++
		}
	}
	return n
}

// fixView is a graph with fixes applied, used to re-evaluate individual paths.
type fixView struct{ g *graph.Graph }

func newFixView(g *graph.Graph, fixes []Fix) fixView { return fixView{ApplyFixes(g, fixes)} }

// survives re-evaluates p hop by hop on the fixed graph: every edge must still exist and be
// an attack step, the likelihood must stay above the pruning floor, the end must still be a
// crown jewel and the score must still clear MinScore.
func (v fixView) survives(p model.AttackPath, opts TraversalOptions) bool {
	if len(p.Steps) == 0 {
		return false
	}
	g := v.g
	prev, ok := g.Node(pathEntry(p))
	if !ok {
		return false
	}
	lik, i, best := 1.0, 0, 0.0
	entryID, width, compensated := prev.ID, "", false
	if p.Steps[0].Relation == "entry" {
		ev := entryEval(g, prev)
		if ev.exploitability == 0 {
			return false
		}
		lik, i = ev.exploitability, 1
	}
	for ; i < len(p.Steps); i++ {
		s := p.Steps[i]
		to, ok := g.Node(s.Resource)
		if !ok {
			return false
		}
		var edge *graph.Edge
		for _, e := range g.Out(prev.ID) {
			if e.To == to.ID && e.Kind == s.Relation {
				edge = e
				break
			}
		}
		if edge == nil {
			return false
		}
		ev := evaluate(g, &opts, prev, to, edge)
		if ev.exploitability == 0 {
			return false
		}
		if i == 0 {
			width = entryWidthOf(g, prev, edge, opts.TrustedCIDRs)
		}
		if ev.chip != "" {
			compensated = true
		}
		lik *= ev.exploitability * hopDecay(opts, prev, ev)
		if lik < minLik(opts) {
			return false
		}
		prev = to
		if i < len(p.Steps)-1 && to.ID != entryID {
			if c := Criticality(to, opts.CrownJewels); c >= 2 {
				best = pathScore(lik, priorityOf[c], best)
			}
		}
	}
	c := Criticality(prev, opts.CrownJewels)
	if c < 2 {
		return false
	}
	if compensated {
		width = "" // authenticated front door: no toxic floor, as in buildPath
	}
	lik, _, _ = applyToxicFloor(lik, width, prev, opts.CrownJewels) // same floor as traversal
	return pathScore(lik, priorityOf[c], best) >= opts.MinScore
}

// greedyCover is weighted greedy set cover: repeatedly take the set covering the most
// remaining weight. It returns indices into sets.
func greedyCover(sets [][]int, weights []float64) []int {
	covered := map[int]bool{}
	used := map[int]bool{}
	var out []int
	for {
		best, bestGain := -1, 0.0
		for i, s := range sets {
			if used[i] {
				continue
			}
			gain := 0.0
			for _, e := range s {
				if !covered[e] {
					gain += weights[e]
				}
			}
			if gain > bestGain {
				best, bestGain = i, gain
			}
		}
		if best < 0 {
			return out
		}
		used[best] = true
		out = append(out, best)
		for _, e := range sets[best] {
			covered[e] = true
		}
	}
}

type bitset []uint64

func newBitset(n int) bitset { return make(bitset, (n+63)/64) }
func (b bitset) set(i int)   { b[i/64] |= 1 << (uint(i) % 64) }
func (b bitset) has(i int) bool {
	return b[i/64]&(1<<(uint(i)%64)) != 0
}
func (b bitset) or(o bitset) bitset {
	r := make(bitset, len(b))
	for i := range b {
		r[i] = b[i] | o[i]
	}
	return r
}
func (b bitset) count() int {
	n := 0
	for _, w := range b {
		n += bits.OnesCount64(w)
	}
	return n
}

// exactCover returns a minimum-cardinality subset of sets whose union equals the union of all
// sets (elements are 0..n-1). Branch and bound: branch on the uncovered element with the
// fewest covering sets; any cover must use one of them. ok=false when the node budget runs out.
func exactCover(sets [][]int, n, budget int) ([]int, bool) {
	bs := make([]bitset, len(sets))
	universe := newBitset(n)
	coverers := make([][]int, n)
	for i, s := range sets {
		bs[i] = newBitset(n)
		for _, e := range s {
			bs[i].set(e)
			universe.set(e)
			coverers[e] = append(coverers[e], i)
		}
	}
	need := universe.count()
	if need == 0 {
		return nil, true
	}
	// Upper bound from greedy.
	w := make([]float64, n)
	for i := range w {
		w[i] = 1
	}
	best := append([]int(nil), greedyCover(sets, w)...)
	nodes := 0
	aborted := false
	var rec func(covered bitset, chosen []int)
	rec = func(covered bitset, chosen []int) {
		if aborted {
			return
		}
		nodes++
		if nodes > budget {
			aborted = true
			return
		}
		if covered.count() == need {
			if len(chosen) < len(best) {
				best = append([]int(nil), chosen...)
			}
			return
		}
		if len(chosen)+1 >= len(best) {
			return
		}
		pick, fewest := -1, math.MaxInt
		for e := 0; e < n; e++ {
			if universe.has(e) && !covered.has(e) && len(coverers[e]) < fewest {
				pick, fewest = e, len(coverers[e])
			}
		}
		opts := append([]int(nil), coverers[pick]...)
		gain := func(i int) int { return covered.or(bs[i]).count() }
		sort.SliceStable(opts, func(a, b int) bool { return gain(opts[a]) > gain(opts[b]) })
		for _, i := range opts {
			rec(covered.or(bs[i]), append(chosen, i))
		}
	}
	rec(newBitset(n), nil)
	if aborted {
		return nil, false
	}
	sort.Ints(best)
	return best, true
}

// WeaknessPassRoleEscalation is the synthetic weakness of an edge fix on a privilege-escalation
// can_assume edge (technique iam:PassRole+ec2:RunInstances, delta r2 #12): scoping the
// principal's iam:PassRole away from the escalation role removes that one edge. The fix is
// rendered by internal/remediation PassRoleFix (template iam_passrole_scope.tf).
const WeaknessPassRoleEscalation = "PRIVESC_PASSROLE"

// escalationEdge reports a can_assume edge from → to that carries a technique (an IAM
// evaluator privilege-escalation edge, graph.AttrTechnique).
func escalationEdge(g *graph.Graph, from, to string) bool {
	for _, e := range g.Out(from) {
		if e.To == to && e.Kind == graph.EdgeCanAssume {
			if t, _ := e.Attr[graph.AttrTechnique].(string); t != "" {
				return true
			}
		}
	}
	return false
}

// PassRoleEdgeFix describes the PassRole scoping fix of one escalation edge, for the
// remediation renderer (remediation.PassRoleFix) and the CLI: the principal holding the
// permission, the role it must no longer pass, the statement and policy granting it.
type PassRoleEdgeFix struct {
	Principal string `json:"principal"`
	Role      string `json:"role"`
	Technique string `json:"technique"`
	Statement string `json:"statement,omitempty"`
	PolicyARN string `json:"policy_arn,omitempty"`
}

// PassRoleFixOf returns the PassRole fix description of an edge fix (ok=false for other fixes).
func PassRoleFixOf(g *graph.Graph, fx Fix) (PassRoleEdgeFix, bool) {
	if fx.Weakness != WeaknessPassRoleEscalation || fx.Edge == nil {
		return PassRoleEdgeFix{}, false
	}
	out := PassRoleEdgeFix{Principal: fx.Edge.From, Role: fx.Edge.To}
	for _, e := range g.Out(fx.Edge.From) {
		if e.To == fx.Edge.To && e.Kind == graph.EdgeCanAssume {
			out.Technique, _ = e.Attr[graph.AttrTechnique].(string)
			if p, ok := e.Permission(); ok {
				out.Statement, out.PolicyARN = p.Statement, p.PolicyARN
			}
		}
	}
	return out, true
}

func passRoleCommand(g *graph.Graph, from, to string) string {
	fx, _ := PassRoleFixOf(g, Fix{Weakness: WeaknessPassRoleEscalation, Edge: &EdgeRef{From: from, To: to, Kind: graph.EdgeCanAssume}})
	where := "its policies"
	if fx.Statement != "" {
		where = "statement " + fx.Statement
	}
	return "scope iam:PassRole of " + from + " (" + where + "): drop " + to +
		" from the passable roles (that removes the escalation; an iam:PassedToService condition alone does not when it names the exploited service, ec2.amazonaws.com) and condition the remaining grant on iam:PassedToService (template iam_passrole_scope.tf)"
}
