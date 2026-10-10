package graph

import (
	"fmt"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// relationKinds maps every kind a native `related` object may declare to a graph edge kind.
// reverse=true means the edge runs from the related ID to the declaring resource
// (sts_assume_role_allows on a role: the named principal can assume the role) or, for
// exposed_to_internet, from the internet node to the resource.
var relationKinds = map[string]struct {
	kind    string
	reverse bool
}{
	EdgeAttachedTo:           {EdgeAttachedTo, false},
	EdgeRunsAs:               {EdgeRunsAs, false},
	EdgeBoundTo:              {EdgeBoundTo, false},
	EdgeMemberOf:             {EdgeMemberOf, false},
	EdgeTrusts:               {EdgeTrusts, false},
	EdgeHasPolicy:            {EdgeHasPolicy, false},
	"policy":                 {EdgeHasPolicy, false},
	EdgeGrantsAccessTo:       {EdgeGrantsAccessTo, false},
	"resource":               {EdgeGrantsAccessTo, false}, // policy statement Resource
	EdgeRunsOn:               {EdgeRunsOn, false},
	EdgeAllowsTrafficTo:      {EdgeAllowsTrafficTo, false},
	EdgeCanAssume:            {EdgeCanAssume, false},
	"sts_assume_role_allows": {EdgeCanAssume, true},
	EdgeExposes:              {EdgeExposes, true},
	"exposed_to_internet":    {EdgeExposes, true},
	EdgeContains:             {EdgeContains, false},
	EdgeStoresDataIn:         {EdgeStoresDataIn, false},
}

// RelationEdge resolves a declared relationship kind (case-insensitive) to the graph edge kind
// and whether the edge points from the related ID to the declaring resource.
func RelationEdge(kind string) (edgeKind string, reverse bool, ok bool) {
	k, ok := relationKinds[strings.ToLower(strings.TrimSpace(kind))]
	return k.kind, k.reverse, ok
}

// attachRelations adds the typed edges a finding's resource declares. It returns the IDs it
// handled so the legacy attached_to hint is not added for them as well.
func (g *Graph) attachRelations(f model.Finding, node *Node) map[string]bool {
	handled := map[string]bool{}
	for _, rel := range f.Resource.Relations {
		if rel.ID == "" {
			continue
		}
		attr := map[string]any{"finding_id": f.ID, "declared": true}
		for k, v := range rel.Attr {
			attr[k] = v
		}
		kind, reverse, ok := RelationEdge(rel.Kind)
		if !ok {
			// Unknown kind: keep the link as an unverified hint and say what was declared.
			attr["hint"], attr["declared_kind"] = true, rel.Kind
			g.AddEdge(node.ID, rel.ID, EdgeAttachedTo, withBecause(g, attr, node.ID, rel.ID, EdgeAttachedTo, f,
				fmt.Sprintf("declared relationship %q is not a known edge kind", rel.Kind)))
			handled[rel.ID] = true
			continue
		}
		from, to := node.ID, rel.ID
		switch {
		case kind == EdgeExposes:
			from, to = InternetNodeID, node.ID
			if _, ok := attr["weakness"]; !ok {
				attr["weakness"] = "PUBLIC_NETWORK_EXPOSURE"
			}
		case reverse:
			from, to = rel.ID, node.ID
		}
		g.AddEdge(from, to, kind, withBecause(g, attr, from, to, kind, f, ""))
		if kind == EdgeTrusts {
			// A role that trusts a principal can be assumed by it.
			ca := map[string]any{"finding_id": f.ID, "declared": true, "principal": rel.ID, "derived_from": EdgeTrusts}
			for k, v := range rel.Attr {
				if k != "because" {
					ca[k] = v
				}
			}
			g.AddEdge(rel.ID, node.ID, EdgeCanAssume, withBecause(g, ca, rel.ID, node.ID, EdgeCanAssume, f, ""))
		}
		handled[rel.ID] = true
	}
	return handled
}

// withBecause sets attr["because"]: the declared attr.because when given, otherwise the
// edge description from its attributes; both end with the declaring finding.
func withBecause(g *Graph, attr map[string]any, from, to, kind string, f model.Finding, note string) map[string]any {
	b, _ := attr["because"].(string)
	if b == "" {
		fn, _ := g.Node(from)
		tn, _ := g.Node(to)
		if fn == nil {
			fn = &Node{ID: from, Name: lastSegment(from)}
		}
		if tn == nil {
			tn = &Node{ID: to, Name: lastSegment(to)}
		}
		b = DescribeEdge(fn, tn, kind, attr)
		if v, _ := attr["via"].(string); v != "" && !strings.Contains(b, v) {
			b += " via " + v
		}
	}
	if note != "" {
		b += "; " + note
	}
	attr["because"] = fmt.Sprintf("%s (declared by finding %s %s)", b, firstNon(f.CanonicalID, f.CheckID), f.ID)
	return attr
}

// exposureCIDRs reads attributes.exposure_cidrs (strings or a JSON list) from a finding's resource.
func exposureCIDRs(attrs map[string]any) []string {
	var out []string
	switch v := attrs["exposure_cidrs"].(type) {
	case []string:
		out = append(out, v...)
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case string:
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}
