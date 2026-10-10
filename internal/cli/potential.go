package cli

// Potential escalations on the Issue page (W7-POLISH item 13, r5 #10): inferred path-rule
// matches — the permissions allow an escalation the graph cannot prove (an SSM session onto an
// instance whose role is admin, a role that may rewrite its own policy) — annotate the
// principal's finding Issue. They are never path Issues (verified matches are).
//
// The API / dashboard Issue page is built by internal/server/issuepage.go (W7-VERIFY): it can
// call attackpath.PotentialEscalations(g, rules)[resourceID] directly; potentialEscalationsFor
// is the CLI's adapter with the same inputs (graph + library + customer rules).

import (
	"fmt"
	"io"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// potentialEscalationsFor is the inferred matches anchored on the Issue's principal (finding and
// combination Issues; a path Issue's chains are its hops).
func potentialEscalationsFor(cfg *config.Config, g *graph.Graph, is model.Issue) []attackpath.PathRuleMatch {
	if g == nil || is.Kind == model.IssuePath || is.ResourceID == "" {
		return nil
	}
	return attackpath.PotentialEscalations(g, pathRulesFor(cfg))[is.ResourceID]
}

// printPotentialEscalations appends the "Potential escalation" block to `issues show` (nothing
// when the principal has no inferred match).
func printPotentialEscalations(w io.Writer, cfg *config.Config, st *store.Store, is model.Issue) {
	g, err := loadGraph(st)
	if err != nil {
		return
	}
	ms := potentialEscalationsFor(cfg, g, is)
	if len(ms) == 0 {
		return
	}
	name := func(id string) string {
		if n, ok := g.Node(id); ok && n.Name != "" {
			return n.Name
		}
		return id
	}
	fmt.Fprintf(w, "\nPotential escalation (%d, inferred: the permissions allow it, the graph cannot prove it; not a path Issue):\n", len(ms))
	for _, m := range ms {
		tag := ""
		if m.Custom {
			tag = " [custom rule]"
		}
		fmt.Fprintf(w, "  %s %s → %s%s\n", m.RuleID, firstNonEmpty(m.Title, "escalation"), name(m.Target), tag)
		if len(m.Because) > 0 {
			fmt.Fprintf(w, "      because %s\n", strings.Join(m.Because, "; "))
		}
		if c := m.Credit; c != nil && c.Source != "" {
			fmt.Fprintf(w, "      credit: %s %s (%s)\n", c.Source, c.UpstreamID, c.Licence)
		}
	}
}
