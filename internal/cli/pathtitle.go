package cli

// One title and one order for path Issues on every surface (W6-POLISH item 2, r4 #4 / E7).
// `paths`, `plan`, the dashboard and the API all name a path Issue by its stored title — the
// store titles Issues with model.PathIssueTitle ("credential compromise of dev-sam →
// ec2-admin-role (AdministratorAccess)", never "X → X → Privilege escalation to X") — and list
// path Issues in the store's order (score, then severity, rule and anchor), so a tie reads the
// same in `issues`, `paths`, the dashboard and the copilot.

import (
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// pathIssueView resolves a path to its Issue id, title and list position. st may be nil (no
// database): ids are then the unkeyed digest and titles come from g.
type pathIssueView struct {
	st    *store.Store
	g     *graph.Graph
	pos   map[string]int    // stored Issue id -> position in the store's Issue order
	title map[string]string // stored Issue id -> title
}

func newPathIssueView(st *store.Store, g *graph.Graph) *pathIssueView {
	v := &pathIssueView{st: st, g: g, pos: map[string]int{}, title: map[string]string{}}
	if st == nil {
		return v
	}
	all, err := st.Issues(store.IssueFilter{Kind: model.IssuePath})
	if err != nil {
		return v
	}
	for i, is := range all {
		v.pos[is.ID] = i
		v.title[is.ID] = is.Title
	}
	return v
}

// IssueID is the id of p's path Issue in this database (unkeyed without one).
func (v *pathIssueView) IssueID(p model.AttackPath) string {
	if v != nil && v.st != nil {
		return v.st.PathIssueIDOf(p)
	}
	e, a, r := model.PathIssueKey(p)
	return model.PathIssueID(model.IssuePath, e, a, r)
}

// Title is the title of p's path Issue: the stored one, else model.PathIssueTitle on the graph.
func (v *pathIssueView) Title(p model.AttackPath) string {
	if v != nil {
		if t := v.title[v.IssueID(p)]; t != "" {
			return t
		}
	}
	var g *graph.Graph
	if v != nil {
		g = v.g
	}
	return model.PathIssueTitle(p, graphLookup(g))
}

// Row is the one-line label of a path on a list: the Issue title, then what the path does when
// the title does not already say it ("sensitive data exfiltration", "privilege escalation").
func (v *pathIssueView) Row(p model.AttackPath) string {
	t := v.Title(p)
	if k := impactKind(p); k != "" && !strings.Contains(strings.ToLower(t), k) {
		return t + " — " + k
	}
	return t
}

// SortGroups orders path groups like the stored Issues; groups the store does not know follow,
// by score, then title, then id.
func (v *pathIssueView) SortGroups(groups []attackpath.PathGroup) {
	key := func(g attackpath.PathGroup) (int, bool) {
		if v == nil {
			return 0, false
		}
		i, ok := v.pos[v.IssueID(g.Best)]
		return i, ok
	}
	sort.SliceStable(groups, func(a, b int) bool {
		ia, oka := key(groups[a])
		ib, okb := key(groups[b])
		if oka != okb {
			return oka
		}
		if oka {
			return ia < ib
		}
		if groups[a].Score != groups[b].Score {
			return groups[a].Score > groups[b].Score
		}
		ta, tb := v.Title(groups[a].Best), v.Title(groups[b].Best)
		if ta != tb {
			return ta < tb
		}
		return groups[a].IssueID < groups[b].IssueID
	})
}

// SortPaths orders hop variants by their Issue's position, then score, then path id.
func (v *pathIssueView) SortPaths(paths []model.AttackPath) {
	pos := func(p model.AttackPath) (int, bool) {
		if v == nil {
			return 0, false
		}
		i, ok := v.pos[v.IssueID(p)]
		return i, ok
	}
	sort.SliceStable(paths, func(a, b int) bool {
		ia, oka := pos(paths[a])
		ib, okb := pos(paths[b])
		if oka != okb {
			return oka
		}
		if oka && ia != ib {
			return ia < ib
		}
		if paths[a].Score != paths[b].Score {
			return paths[a].Score > paths[b].Score
		}
		return paths[a].ID < paths[b].ID
	})
}

// impactKind is the impact without its target ("Sensitive data exfiltration from X" →
// "sensitive data exfiltration"): the title already names the target.
func impactKind(p model.AttackPath) string {
	im := strings.TrimSpace(p.Impact)
	if im == "" {
		return ""
	}
	for _, sep := range []string{" from ", " to ", " of ", " on "} {
		if i := strings.Index(im, sep); i > 0 {
			rest := strings.TrimSpace(im[i+len(sep):])
			if rest != "the internet" {
				im = im[:i]
			}
			break
		}
	}
	return strings.ToLower(im)
}

// graphLookup adapts g to model.PathIssueTitle's lookup (nil-safe).
func graphLookup(g *graph.Graph) func(string) (model.PathNode, bool) {
	if g == nil {
		return nil
	}
	return func(id string) (model.PathNode, bool) {
		n, ok := g.Node(id)
		if !ok || n == nil {
			return model.PathNode{}, false
		}
		return model.PathNode{Name: n.Name, Attrs: n.Attributes}, true
	}
}
