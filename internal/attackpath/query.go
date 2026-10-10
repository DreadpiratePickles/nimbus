package attackpath

import (
	"fmt"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Graph queries (delta r3 #8, matrix IG6 — Wiz Security Graph Explorer / Sysdig SysQL-style
// "from X to Y through Z"): `cloud-posture paths --from --to --through --max-hops`.
//
// A query walks the same security graph the engine traverses and admits a hop only when the
// engine's own step evaluation (evaluate) says it is an attack step, so every hop carries the
// engine's per-hop because, likelihood and weakness. It differs from the engine in what it
// returns: every simple path between the two node sets (not only entry → crown jewel), and a
// --from that is not an engine entry point starts from an assumed foothold, said so in the
// first step.

// DefaultQueryMaxHops is --max-hops when not given.
const DefaultQueryMaxHops = 6

// QueryMaxHopsLimit bounds --max-hops (the search is exponential in hops).
const QueryMaxHopsLimit = 10

// queryExploreCap bounds the number of frames one query expands; Truncated reports a hit.
const queryExploreCap = 100000

// queryMinLikelihood is the query's floor: lower than the engine's reporting floor, because a
// query asks "is there any way", but not zero, so it stays finite on dense graphs.
const queryMinLikelihood = 0.01

// PathQuery selects paths. Each selector is a comma-separated list of: `internet`,
// `type:<node type>`, `class:<node class>`, a node id, an exact node name, or a bare node type
// (used only when no node id or name matches).
type PathQuery struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Through string `json:"through,omitempty"`
	MaxHops int    `json:"max_hops"`
}

// QueryResult is a query's answer.
type QueryResult struct {
	Query     PathQuery          `json:"query"`
	FromNodes int                `json:"from_nodes"`
	ToNodes   int                `json:"to_nodes"`
	Through   int                `json:"through_nodes,omitempty"`
	Paths     []model.AttackPath `json:"paths"`
	Explored  int                `json:"explored"`
	Truncated bool               `json:"truncated,omitempty"`
}

// ResolveSelector returns the node ids a selector names, or an error naming the selector when
// it matches nothing.
func ResolveSelector(g *graph.Graph, sel string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, part := range strings.Split(sel, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n0 := len(out)
		switch {
		case strings.EqualFold(part, "internet"):
			if _, ok := g.Node(graph.InternetNodeID); ok {
				out[graph.InternetNodeID] = true
			}
		case strings.HasPrefix(part, "type:"):
			t := strings.TrimPrefix(part, "type:")
			for _, n := range g.Nodes() {
				if n.Type == t {
					out[n.ID] = true
				}
			}
		case strings.HasPrefix(part, "class:"):
			c := strings.TrimPrefix(part, "class:")
			for _, n := range g.Nodes() {
				if strings.EqualFold(string(n.Class), c) {
					out[n.ID] = true
				}
			}
		default:
			if n, ok := g.Node(part); ok {
				out[n.ID] = true
				break
			}
			for _, n := range g.Nodes() {
				if n.Name == part {
					out[n.ID] = true
				}
			}
			if len(out) == n0 { // a bare node type (`--to aws_s3_bucket`) when no id or name matches
				for _, n := range g.Nodes() {
					if n.Type == part {
						out[n.ID] = true
					}
				}
			}
		}
		if len(out) == n0 {
			return nil, fmt.Errorf("selector %q matches no node in the graph (use internet, type:<type>, class:<class>, a node id or an exact name)", part)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty selector")
	}
	return out, nil
}

// Query enumerates attack-step paths from q.From to q.To (through q.Through when set) of at
// most q.MaxHops hops (1..QueryMaxHopsLimit; DefaultQueryMaxHops is the usual), highest score first.
func Query(g *graph.Graph, opts TraversalOptions, q PathQuery) (*QueryResult, error) {
	if opts.MaxHops == 0 && opts.HopDecay == 0 {
		trusted := opts.TrustedCIDRs
		opts = DefaultTraversalOptions()
		opts.TrustedCIDRs = trusted
	}
	// MaxHops 0 is an error, never a silent default (verification 6): callers that mean "the
	// default" pass DefaultQueryMaxHops (the CLI flag default; MCP when max_hops is omitted).
	if q.MaxHops < 1 || q.MaxHops > QueryMaxHopsLimit {
		return nil, fmt.Errorf("--max-hops must be 1..%d (got %d)", QueryMaxHopsLimit, q.MaxHops)
	}
	if strings.TrimSpace(q.From) == "" || strings.TrimSpace(q.To) == "" {
		return nil, fmt.Errorf("a path query needs --from and --to")
	}
	from, err := ResolveSelector(g, q.From)
	if err != nil {
		return nil, fmt.Errorf("--from: %w", err)
	}
	to, err := ResolveSelector(g, q.To)
	if err != nil {
		return nil, fmt.Errorf("--to: %w", err)
	}
	var through map[string]bool
	if strings.TrimSpace(q.Through) != "" {
		if through, err = ResolveSelector(g, q.Through); err != nil {
			return nil, fmt.Errorf("--through: %w", err)
		}
	}
	res := &QueryResult{Query: q, FromNodes: len(from), ToNodes: len(to), Through: len(through)}
	crit := map[string]int{}
	for _, n := range g.Nodes() {
		crit[n.ID] = Criticality(n, opts.CrownJewels)
	}
	starts := make([]string, 0, len(from))
	for id := range from {
		starts = append(starts, id)
	}
	sort.Strings(starts)
	seenPath := map[string]bool{}
	for _, id := range starts {
		start, _ := g.Node(id)
		fr := frame{node: start, lik: 1, seen: map[string]bool{id: true}}
		entryHops := 0
		if id != graph.InternetNodeID {
			entryHops = 1
			if ev := entryEval(g, start); ev.exploitability > 0 {
				fr.lik = ev.exploitability
				fr.steps = []model.Step{entryStep(start, ev)}
			} else {
				fr.steps = []model.Step{assumedFootholdStep(start)}
			}
		}
		stack := []frame{fr}
		for len(stack) > 0 {
			if res.Explored >= queryExploreCap {
				res.Truncated = true
				break
			}
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			res.Explored++
			hops := len(cur.steps) - entryHops
			if hops >= 1 && to[cur.node.ID] && cur.node.ID != id {
				if through == nil || visitsThrough(cur.steps[entryHops:len(cur.steps)-1], through) {
					pr := priorityOf[crit[cur.node.ID]]
					if pr == 0 {
						pr = 1
					}
					p := buildPath(g, start, cur, pr, opts.CrownJewels)
					p.RuleID = "GRAPH_QUERY"
					if !seenPath[p.ID] {
						seenPath[p.ID] = true
						res.Paths = append(res.Paths, p)
					}
				}
				continue // a path ends at its first --to node
			}
			if hops >= q.MaxHops {
				continue
			}
			for _, e := range g.Out(cur.node.ID) {
				if cur.seen[e.To] {
					continue
				}
				nx, ok := g.Node(e.To)
				if !ok {
					continue
				}
				ev := evaluate(g, &opts, cur.node, nx, e)
				if ev.exploitability == 0 {
					continue
				}
				lik := cur.lik * ev.exploitability * hopDecay(opts, cur.node, ev)
				if lik < queryMinLikelihood {
					continue
				}
				seen := make(map[string]bool, len(cur.seen)+1)
				for k := range cur.seen {
					seen[k] = true
				}
				seen[nx.ID] = true
				steps := append(append([]model.Step{}, cur.steps...), edgeStep(g, cur.node, nx, e, len(cur.steps)+1, ev))
				width, comp := cur.entryWidth, cur.compensated
				if cur.node.ID == graph.InternetNodeID {
					width = entryWidthOf(g, cur.node, e, opts.TrustedCIDRs)
				}
				if ev.chip != "" {
					comp = ev.chip
				}
				stack = append(stack, frame{node: nx, steps: steps, lik: lik, seen: seen, entryWidth: width, compensated: comp})
			}
		}
	}
	sort.SliceStable(res.Paths, func(i, j int) bool {
		if res.Paths[i].Score != res.Paths[j].Score {
			return res.Paths[i].Score > res.Paths[j].Score
		}
		if len(res.Paths[i].Steps) != len(res.Paths[j].Steps) {
			return len(res.Paths[i].Steps) < len(res.Paths[j].Steps)
		}
		return res.Paths[i].ID < res.Paths[j].ID
	})
	if res.Paths == nil {
		res.Paths = []model.AttackPath{}
	}
	return res, nil
}

// visitsThrough reports whether an intermediate step stands on a --through node.
func visitsThrough(steps []model.Step, through map[string]bool) bool {
	for _, s := range steps {
		if through[s.Resource] {
			return true
		}
	}
	return false
}

// assumedFootholdStep starts a query from a node that is not an engine entry point: the query
// assumes it is compromised and says so, so the result is never read as an observed entry.
func assumedFootholdStep(n *graph.Node) model.Step {
	return model.Step{Stage: 1, Relation: "entry", Resource: n.ID, Title: n.Name,
		Summary:  fmt.Sprintf("%s (%s): foothold assumed by the query [p=1.00]", n.Name, n.Type),
		Because:  fmt.Sprintf("query --from %s: assumed compromised (not an entry point the engine observed)", n.Name),
		Evidence: map[string]any{"entry": true, "assumed": true, "node": n.ID, "likelihood": 1.0}}
}
