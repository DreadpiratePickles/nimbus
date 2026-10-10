// Package pathdiff answers the pull-request question "which attack paths does this change open
// or close?" (P1-PLANDIFF D2, capability AP10).
//
// Diff overlays a Terraform / OpenTofu plan (internal/iac.Plan) on a clone of the live security
// graph, re-runs attackpath.Traverse, and compares paths by path Issue id (model.PathIssueID:
// kind | entry | anchor | rule) refined by the entry they enter at (attackpath.EntryKey: an
// internet path's entry is "internet:<exposed node>"). Identity ignores middle hops, so a plan
// that reroutes an existing path through a new middle hop does not "open" it (it is counted in
// Rerouted), but a new public host in front of an already-reachable anchor is a new entry and is
// opened (verify-4 D5); a path whose score moves is reported in ChangedScore.
//
// Modes and confidence:
//
//	live       a live graph is given (a scan DB): before = the live graph, after = the live graph
//	           with the plan's changes applied. Paths through plan-derived elements are
//	           "inferred" (a prediction from a plan mapped onto live ids).
//	plan-only  no live graph (CI without a DB): before / after are built from the plan's own
//	           before / after values only. Everything is "hint": resources outside the plan
//	           (a role the instance assumes, a repository's branch protection) are invisible.
//
// The overlay never modifies the live graph: it works on graph.Clone() and copies a node's
// attribute map before writing to it (Clone shares attribute maps).
package pathdiff

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/collector/saas"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Modes.
const (
	ModeLive     = "live"
	ModePlanOnly = "plan-only"
)

// Options tune the diff.
type Options struct {
	Traversal attackpath.TraversalOptions
}

// HopRef is one hop of a path.
type HopRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Relation string `json:"relation"` // entry | exposes | runs_as | can_assume | …
	Because  string `json:"because,omitempty"`
	Changed  bool   `json:"changed,omitempty"` // the plan changed this hop
}

// PathRef is one path Issue the plan opens or closes (its best-scoring path).
type PathRef struct {
	IssueID string `json:"issue_id"`
	Entry   string `json:"entry"`
	// EntryKey refines Entry for internet paths with the exposed node they enter at
	// ("internet:<node id>", attackpath.EntryKey); Opened / Closed compare these keys.
	EntryKey         string           `json:"entry_key"`
	Anchor           string           `json:"anchor"`
	Rule             string           `json:"rule"`
	EntryName        string           `json:"entry_name"`
	AnchorName       string           `json:"anchor_name"`
	AnchorType       string           `json:"anchor_type"`
	Score            float64          `json:"score"`
	Band             string           `json:"band"`
	Severity         model.Severity   `json:"severity"`
	Hops             []HopRef         `json:"hops"`
	ChangedHop       int              `json:"changed_hop"` // index into Hops; -1 when no hop is plan-derived
	Why              string           `json:"why,omitempty"`
	ChangedBy        string           `json:"changed_by,omitempty"` // plan address
	ToxicCombination string           `json:"toxic_combination,omitempty"`
	Confidence       model.Confidence `json:"confidence"`
	FixCanonical     string           `json:"fix_canonical,omitempty"`
	FixTemplate      string           `json:"fix_template,omitempty"`
	FixCommand       string           `json:"fix_command,omitempty"`
	PathIDs          []string         `json:"path_ids"`
	FindingIDs       []string         `json:"finding_ids,omitempty"`
	Path             model.AttackPath `json:"-"`
}

// ScoreChange is a path Issue present before and after whose best score moved.
type ScoreChange struct {
	Path       PathRef `json:"path"`
	Before     float64 `json:"before"`
	After      float64 `json:"after"`
	BandBefore string  `json:"band_before"`
	BandAfter  string  `json:"band_after"`
}

var bandRank = map[string]int{"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

// Escalates reports a band-raising score change that ends in High or Critical (competitive delta
// 2026-10-09 shortfall #7): Low/Medium → High/Critical, or High → Critical. Bands are
// model.ScoreBand, the scale every surface uses. Low → Medium is a score change, not an
// escalation; so is any move inside one band or downwards.
func Escalates(before, after float64) bool {
	b, a := bandRank[model.ScoreBand(before)], bandRank[model.ScoreBand(after)]
	return a > b && a >= bandRank["High"]
}

// GateCount is what --fail-on-opened counts: opened path Issues plus escalations, unless
// openedOnly (--opened-only) restricts it to opened paths. The CLI flag is wired by the CLI
// (internal/cli/prcomment.go), this is the semantics.
func (r Result) GateCount(openedOnly bool) int {
	if openedOnly {
		return len(r.Opened)
	}
	return len(r.Opened) + len(r.Escalated)
}

// GateTripped reports whether --fail-on-opened must fail the check.
func (r Result) GateTripped(openedOnly bool) bool { return r.GateCount(openedOnly) > 0 }

// MovedPath is one path whose anchor (same entry) or entry resource (same anchor) was replaced
// by a resource of the same type that did not exist before, while the old one is gone after.
type MovedPath struct {
	From PathRef `json:"from"`
	To   PathRef `json:"to"`
}

// ExposureRef is an internet exposure (not a path) that appeared or disappeared.
type ExposureRef struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Width  string `json:"width"`
}

// Result is the diff.
type Result struct {
	Mode           string           `json:"mode"`
	Confidence     model.Confidence `json:"confidence"`
	ConfidenceNote string           `json:"confidence_note"`
	Opened         []PathRef        `json:"opened"`
	Closed         []PathRef        `json:"closed"`
	ChangedScore   []ScoreChange    `json:"changed_score"`
	// Escalated are the ChangedScore entries whose band rose into High / Critical (Escalates);
	// they gate like Opened (GateCount) and belong in the headline ("escalates E").
	Escalated []ScoreChange `json:"escalated"`
	Rerouted  int           `json:"rerouted"` // (Issue, entry) pairs present on both sides whose hop lists changed
	// Moved are opened/closed pairs that are one path whose anchor or entry resource was renamed
	// or replaced (verify-4/5 D6, blue/green swap): neither opened nor closed, never a gate trip
	// unless the move escalates (then it is also in Escalated).
	Moved            []MovedPath   `json:"moved"`
	ExposuresOpened  []ExposureRef `json:"exposures_opened"`
	ExposuresClosed  []ExposureRef `json:"exposures_closed"`
	ChangedResources []string      `json:"changed_resources"` // plan addresses with an action other than no-op
	Notes            []string      `json:"notes,omitempty"`
	// IDScheme says what the issue_id values are (internal/output ids.go): "unkeyed" — the raw
	// model.PathIssueID digest, as Diff returns them — or "run-keyed" after WithKeyedIDs, which a
	// redacted output must use so no digest of a redacted name is published (W6, r4 #15).
	IDScheme string `json:"id_scheme"`
}

// IDKeyer keys digest ids for one DB-less run (output.RunKeyer satisfies it).
type IDKeyer interface {
	ID(id string) string
	Scheme() string
}

// WithKeyedIDs returns a copy of r whose digest ids — path Issue ids, and each path's
// path_ids and finding_ids (verification 7 #10) — are keyed by k (r is not changed).
func (r Result) WithKeyedIDs(k IDKeyer) Result {
	keyList := func(ids []string) []string {
		if ids == nil {
			return nil
		}
		out := make([]string, len(ids))
		for i, id := range ids {
			out[i] = k.ID(id)
		}
		sort.Strings(out)
		return out
	}
	keyRef := func(p PathRef) PathRef {
		p.IssueID = k.ID(p.IssueID)
		p.PathIDs = keyList(p.PathIDs)
		p.FindingIDs = keyList(p.FindingIDs)
		return p
	}
	key := func(ps []PathRef) []PathRef {
		out := make([]PathRef, len(ps))
		for i, p := range ps {
			out[i] = keyRef(p)
		}
		return out
	}
	keySC := func(cs []ScoreChange) []ScoreChange {
		out := make([]ScoreChange, len(cs))
		for i, c := range cs {
			c.Path = keyRef(c.Path)
			out[i] = c
		}
		return out
	}
	r.Opened, r.Closed = key(r.Opened), key(r.Closed)
	r.ChangedScore, r.Escalated = keySC(r.ChangedScore), keySC(r.Escalated)
	moved := make([]MovedPath, len(r.Moved))
	for i, m := range r.Moved {
		m.From, m.To = keyRef(m.From), keyRef(m.To)
		moved[i] = m
	}
	r.Moved = moved
	r.IDScheme = k.Scheme()
	return r
}

// Diff compares the attack paths of the live graph (or, with live nil, the plan's before state)
// with those after the plan. liveAnalysis may be nil (it is computed); when given it must be a
// traversal of live with the same options.
func Diff(live *graph.Graph, liveAnalysis *attackpath.Analysis, plan *iac.Plan, o Options) Result {
	if o.Traversal.MaxHops == 0 {
		o.Traversal = attackpath.DefaultTraversalOptions()
	}
	res := Result{Opened: []PathRef{}, Closed: []PathRef{}, Moved: []MovedPath{}, ChangedScore: []ScoreChange{}, Escalated: []ScoreChange{}, ExposuresOpened: []ExposureRef{}, ExposuresClosed: []ExposureRef{}, ChangedResources: []string{},
		IDScheme: "unkeyed"}
	if plan == nil {
		plan = &iac.Plan{}
	}
	for _, c := range plan.Changes {
		if c.Action != iac.PlanNoOp {
			res.ChangedResources = append(res.ChangedResources, c.Address)
		}
	}
	var before, after *graph.Graph
	var ov *overlay
	if live == nil {
		res.Mode, res.Confidence = ModePlanOnly, model.ConfidenceHint
		res.ConfidenceNote = "no live graph: paths are built from the plan's own before/after values only (resources outside the plan, such as branch protection or live roles, are not seen); every result is a hint"
		bg := graph.New()
		bo := newOverlay(bg, nil, model.ConfidenceHint)
		bo.applyAll(plan.Resources(iac.SideBefore))
		before = bg
		ag := graph.New()
		ov = newOverlay(ag, nil, model.ConfidenceHint)
		ov.applyAll(plan.Resources(iac.SideAfter))
		ov.markChanged(plan.Resources(iac.SideBefore), plan.Resources(iac.SideAfter))
		after = ag
		liveAnalysis = nil
	} else {
		res.Mode, res.Confidence = ModeLive, model.ConfidenceInferred
		res.ConfidenceNote = "plan overlaid on the live graph: changed hops are inferred from planned values mapped to live resource ids"
		before = live
		ov = applyOverlay(live, plan)
		after = ov.g
	}
	res.Notes = append(res.Notes, ov.notes...)
	anB := liveAnalysis
	if anB == nil {
		anB = attackpath.Traverse(before, o.Traversal)
	}
	anA := attackpath.Traverse(after, o.Traversal)
	bIss, aIss := issues(anB), issues(anA)
	for _, id := range sortedKeys(aIss) {
		a := aIss[id]
		b, ok := bIss[id]
		if !ok {
			res.Opened = append(res.Opened, ov.ref(after, a, res.Mode))
			continue
		}
		if math.Abs(a.best.Score-b.best.Score) >= 0.005 {
			c := ScoreChange{Path: ov.ref(after, a, res.Mode), Before: b.best.Score, After: a.best.Score,
				BandBefore: model.ScoreBand(b.best.Score), BandAfter: model.ScoreBand(a.best.Score)}
			res.ChangedScore = append(res.ChangedScore, c)
			if Escalates(c.Before, c.After) {
				res.Escalated = append(res.Escalated, c)
			}
		}
		if !sameKeys(a.keys, b.keys) {
			res.Rerouted++
		}
	}
	for _, id := range sortedKeys(bIss) {
		if _, ok := aIss[id]; !ok {
			res.Closed = append(res.Closed, ov.ref(before, bIss[id], res.Mode))
		}
	}
	sortRefs(res.Opened)
	sortRefs(res.Closed)
	pairMoved(&res, before, after)
	bx, ax := exposures(anB), exposures(anA)
	for _, id := range sortedKeys(ax) {
		if _, ok := bx[id]; !ok {
			res.ExposuresOpened = append(res.ExposuresOpened, ax[id])
		}
	}
	for _, id := range sortedKeys(bx) {
		if _, ok := ax[id]; !ok {
			res.ExposuresClosed = append(res.ExposuresClosed, bx[id])
		}
	}
	return res
}

// entryNode is the resource an internet path enters at ("internet:<node>"), else the entry.
func entryNode(p PathRef) string {
	if strings.HasPrefix(p.EntryKey, "internet:") {
		return strings.TrimPrefix(p.EntryKey, "internet:")
	}
	return p.Entry
}

// pairMoved folds an opened path and a closed path into one Moved path when they share the
// rule and either the entry (the anchor was replaced) or the anchor (the entry was replaced),
// the old resource is gone after the plan, the new one did not exist before, and both have the
// same type. Pairs are matched one-to-one in order. A move whose band rises is an escalation.
func pairMoved(res *Result, before, after *graph.Graph) {
	gone := func(id string) bool { _, ok := after.Node(id); return !ok }
	isNew := func(id string) bool { _, ok := before.Node(id); return !ok }
	usedC := map[int]bool{}
	var opened []PathRef
	for _, o := range res.Opened {
		match := -1
		for j, c := range res.Closed {
			if usedC[j] || o.Rule != c.Rule || o.Entry != c.Entry && !(strings.HasPrefix(o.EntryKey, "internet:") && strings.HasPrefix(c.EntryKey, "internet:")) {
				continue
			}
			sameEntry := o.EntryKey == c.EntryKey && o.Anchor != c.Anchor && o.AnchorType == c.AnchorType &&
				gone(c.Anchor) && isNew(o.Anchor)
			oe, ce := entryNode(o), entryNode(c)
			sameAnchor := o.Anchor == c.Anchor && o.EntryKey != c.EntryKey && oe != ce &&
				nodeType(after, oe) == nodeType(before, ce) && gone(ce) && isNew(oe)
			if sameEntry || sameAnchor {
				match = j
				break
			}
		}
		if match < 0 {
			opened = append(opened, o)
			continue
		}
		usedC[match] = true
		c := res.Closed[match]
		res.Moved = append(res.Moved, MovedPath{From: c, To: o})
		if math.Abs(o.Score-c.Score) >= 0.005 {
			sc := ScoreChange{Path: o, Before: c.Score, After: o.Score, BandBefore: model.ScoreBand(c.Score), BandAfter: model.ScoreBand(o.Score)}
			res.ChangedScore = append(res.ChangedScore, sc)
			if Escalates(sc.Before, sc.After) {
				res.Escalated = append(res.Escalated, sc)
			}
		}
	}
	var closed []PathRef
	for j, c := range res.Closed {
		if !usedC[j] {
			closed = append(closed, c)
		}
	}
	res.Opened, res.Closed = append([]PathRef{}, opened...), append([]PathRef{}, closed...)
}

// Overlay returns a clone of live with the plan's changes applied (the "after" graph of Diff).
func Overlay(live *graph.Graph, plan *iac.Plan, _ Options) *graph.Graph {
	return applyOverlay(live, plan).g
}

func applyOverlay(live *graph.Graph, plan *iac.Plan) *overlay {
	ov := newOverlay(live.Clone(), live, model.ConfidenceInferred)
	b := ov.resolveAll(plan.Resources(iac.SideBefore))
	a := ov.resolveAll(plan.Resources(iac.SideAfter))
	ov.applyChanges(b, a)
	return ov
}

// ---------------------------------------------------------------- issues

// issueAgg is one (path Issue, entry) pair: paths are keyed by attackpath.EntryKey, so two
// internet paths to the same anchor through different public hosts are two entries of one Issue
// (verify-4 D5: a second public host in front of a reachable anchor is an opened path). id stays
// the Issue id (model.PathIssueID), entry is the refined entry key.
type issueAgg struct {
	id    string
	entry string
	best  model.AttackPath
	keys  map[string]bool
	ids   []string
}

func issues(an *attackpath.Analysis) map[string]*issueAgg {
	out := map[string]*issueAgg{}
	if an == nil {
		return out
	}
	for _, p := range an.Paths {
		if len(p.Steps) == 0 || (p.RuleID != "" && p.RuleID != "GRAPH_TRAVERSAL") {
			continue
		}
		e, a, r := model.PathIssueKey(p)
		id := model.PathIssueID(model.IssuePath, e, a, r)
		ek, _, _ := attackpath.EntryKey(p)
		k := id + "|" + ek
		x, ok := out[k]
		if !ok {
			x = &issueAgg{id: id, entry: ek, best: p, keys: map[string]bool{}}
			out[k] = x
		} else if p.Score > x.best.Score || (p.Score == x.best.Score && model.PathSecondaryKey(p) < model.PathSecondaryKey(x.best)) {
			x.best = p
		}
		x.keys[model.PathSecondaryKey(p)] = true
		x.ids = append(x.ids, p.ID)
	}
	return out
}

func exposures(an *attackpath.Analysis) map[string]ExposureRef {
	out := map[string]ExposureRef{}
	if an == nil {
		return out
	}
	for _, x := range an.Exposures {
		out[x.NodeID] = ExposureRef{NodeID: x.NodeID, Name: x.Name, Type: x.Type, Width: x.Width}
	}
	return out
}

func sameKeys(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortRefs(rs []PathRef) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Score != rs[j].Score {
			return rs[i].Score > rs[j].Score
		}
		return rs[i].IssueID < rs[j].IssueID
	})
}

// ref describes an Issue's best path; g is the graph the path was found on.
func (ov *overlay) ref(g *graph.Graph, x *issueAgg, mode string) PathRef {
	p := x.best
	e, a, r := model.PathIssueKey(p)
	ref := PathRef{IssueID: x.id, Entry: e, EntryKey: x.entry, Anchor: a, Rule: r, Score: p.Score, Band: model.ScoreBand(p.Score), Severity: attackpath.PathSeverity(p.Score),
		ToxicCombination: attackpath.ToxicCombination(p), ChangedHop: -1, PathIDs: uniq(x.ids), FindingIDs: p.FindingIDs, Path: p}
	sort.Strings(ref.PathIDs)
	ref.EntryName = "Internet"
	if e != model.PathEntryInternet {
		ref.EntryName = nodeName(g, e)
	}
	ref.AnchorName, ref.AnchorType = nodeName(g, a), nodeType(g, a)
	for _, s := range p.Steps {
		ref.Hops = append(ref.Hops, HopRef{ID: s.Resource, Name: firstNonEmpty(s.Title, nodeName(g, s.Resource)), Type: nodeType(g, s.Resource), Relation: s.Relation, Because: s.Because})
	}
	// The changed hop: an edge the plan derived (plan_change evidence) wins; then a hop whose
	// resource, or the resource carrying its weakness, the plan changed.
	pick := -1
	for i, s := range p.Steps {
		if _, ok := s.Evidence["plan_change"]; ok {
			pick = i
			break
		}
	}
	if pick < 0 {
		for i, s := range p.Steps {
			if ov.changed[s.Resource] != "" || (s.WeaknessOn != "" && ov.changed[s.WeaknessOn] != "") {
				pick = i
				break
			}
		}
	}
	if pick >= 0 {
		s := p.Steps[pick]
		ref.ChangedHop, ref.Why = pick, s.Because
		ref.Hops[pick].Changed = true
		if src, _ := s.Evidence["plan_change"].(string); src != "" {
			ref.ChangedBy = src
		} else if src := ov.changed[s.Resource]; src != "" {
			ref.ChangedBy = src
		} else {
			ref.ChangedBy = ov.changed[s.WeaknessOn]
		}
		ref.FixCanonical, _ = s.Evidence["fix_canonical"].(string)
		if ref.FixCanonical == "" {
			ref.FixCanonical = ov.fixFor(s)
		}
	}
	if ref.FixCanonical != "" {
		ref.FixTemplate = templateID(ref.FixCanonical)
		ref.FixCommand = "cloud-posture fix --finding " + ref.FixCanonical + " --generate-terraform"
	}
	switch {
	case mode == ModePlanOnly:
		ref.Confidence = model.ConfidenceHint
	default:
		ref.Confidence = model.PathConfidence(p)
		if pick >= 0 && ref.Confidence == model.ConfidenceVerified {
			ref.Confidence = model.ConfidenceInferred
		}
	}
	return ref
}

// templateID is the canonical check's first remediation template, without its extension.
func templateID(canonical string) string {
	e, ok := catalog.Default().Get(canonical)
	if !ok || len(e.Remediation) == 0 {
		return ""
	}
	t := e.Remediation[0]
	for _, ext := range []string{".cfn.yaml", ".bicep", ".tf", ".yaml", ".json"} {
		t = strings.TrimSuffix(t, ext)
	}
	return t
}

func nodeName(g *graph.Graph, id string) string {
	if n, ok := g.Node(id); ok && n.Name != "" {
		return n.Name
	}
	return id
}

func nodeType(g *graph.Graph, id string) string {
	if n, ok := g.Node(id); ok {
		return n.Type
	}
	return ""
}

// ---------------------------------------------------------------- overlay

type overlay struct {
	g       *graph.Graph
	live    *graph.Graph // nil in plan-only mode
	conf    model.Confidence
	after   map[string]iac.PlanResource
	changed map[string]string // node id → plan address that changed it
	checks  map[string][]iac.PlanCheck
	notes   []string
	// live indexes for id resolution
	bySuffix map[string]string
	byName   map[string]string
}

func newOverlay(g, live *graph.Graph, conf model.Confidence) *overlay {
	ov := &overlay{g: g, live: live, conf: conf, after: map[string]iac.PlanResource{}, changed: map[string]string{}, checks: map[string][]iac.PlanCheck{},
		bySuffix: map[string]string{}, byName: map[string]string{}}
	if live != nil {
		for _, n := range live.Nodes() {
			seg := lastSeg(n.ID)
			if strings.HasPrefix(seg, "sg-") || strings.HasPrefix(seg, "i-") {
				ov.bySuffix[seg] = n.ID
			}
			if n.Type != "" && n.Name != "" {
				ov.byName[n.Type+"|"+n.Name] = n.ID
			}
		}
	}
	return ov
}

// resolveID maps a plan node id onto the live graph's id for the same resource.
func (ov *overlay) resolveID(id string) string {
	if ov.live == nil || id == "" {
		return id
	}
	if _, ok := ov.live.Node(id); ok {
		return id
	}
	if x, ok := ov.bySuffix[lastSeg(id)]; ok {
		return x
	}
	if rest, ok := strings.CutPrefix(id, "name:"); ok {
		typ, name, _ := strings.Cut(rest, "/")
		if x, ok := ov.byName[typ+"|"+name]; ok {
			return x
		}
		for _, n := range ov.live.Nodes() {
			if strings.EqualFold(n.Type, typ) && (strings.HasSuffix(n.ID, "/"+name) || strings.HasSuffix(n.ID, ":"+name)) {
				return n.ID
			}
		}
	}
	return id
}

func (ov *overlay) resolveAll(rs []iac.PlanResource) []iac.PlanResource {
	out := make([]iac.PlanResource, 0, len(rs))
	for _, r := range rs {
		r.ID = ov.resolveID(r.ID)
		var rels []model.Relation
		for _, rel := range r.Relations {
			rel.ID = ov.resolveID(rel.ID)
			rels = append(rels, rel)
		}
		r.Relations = rels
		var sgs []string
		for _, s := range r.SecurityGroups {
			sgs = append(sgs, ov.resolveID(s))
		}
		r.SecurityGroups = sgs
		out = append(out, r)
	}
	return out
}

// own gives the node its own attribute map (graph.Clone shares them with the live graph).
func (ov *overlay) own(id string) {
	n, ok := ov.g.Node(id)
	if !ok {
		return
	}
	cp := make(map[string]any, len(n.Attributes))
	for k, v := range n.Attributes {
		cp[k] = v
	}
	n.Attributes = cp
}

// applyAll builds a fragment graph from every resource of one plan side (plan-only mode).
func (ov *overlay) applyAll(rs []iac.PlanResource) {
	for _, r := range rs {
		ov.put(r)
	}
	ov.propagate(keysOf(ov.after))
	ov.ciEdges(keysOf(ov.after))
}

// markChanged records (plan-only) which resources differ between the sides.
func (ov *overlay) markChanged(b, a []iac.PlanResource) {
	bm := map[string]iac.PlanResource{}
	for _, r := range b {
		bm[r.ID] = r
	}
	for _, r := range a {
		if x, ok := bm[r.ID]; !ok || !same(x, r) {
			ov.changed[r.ID] = changeSource(r)
		}
		delete(bm, r.ID)
	}
	for id, r := range bm {
		ov.changed[id] = changeSource(r)
	}
	for id := range ov.changed {
		ov.markAttached(id)
	}
}

// markAttached marks workloads behind a changed security group as changed by it.
func (ov *overlay) markAttached(id string) {
	for _, e := range ov.g.In(id) {
		if e.Kind == graph.EdgeAttachedTo && ov.changed[e.From] == "" {
			ov.changed[e.From] = ov.changed[id]
		}
	}
}

func changeSource(r iac.PlanResource) string {
	if r.Address != "" {
		return r.Address
	}
	for _, c := range r.Checks {
		if c.Source != "" {
			return c.Source
		}
	}
	for _, i := range r.Ingress {
		return i.Source
	}
	keys := keysOf(r.Sources)
	if len(keys) > 0 {
		return keys[0]
	}
	return r.ID
}

// applyChanges applies, to the cloned live graph, every resource whose before and after differ.
func (ov *overlay) applyChanges(b, a []iac.PlanResource) {
	bm, am := map[string]iac.PlanResource{}, map[string]iac.PlanResource{}
	for _, r := range b {
		bm[r.ID] = r
	}
	for _, r := range a {
		am[r.ID] = r
	}
	ids := map[string]bool{}
	for id := range bm {
		ids[id] = true
	}
	for id := range am {
		ids[id] = true
	}
	var touched []string
	for _, id := range sortedKeys(ids) {
		B, hasB := bm[id]
		A, hasA := am[id]
		if hasB && hasA && same(B, A) {
			continue
		}
		src := changeSource(A)
		if !hasA {
			src = changeSource(B)
		}
		ov.changed[id] = src
		touched = append(touched, id)
		if hasB {
			ov.retract(B, A, hasA)
		}
		if !hasA {
			if B.Address != "" && !B.Partial {
				ov.g.RemoveNode(id)
			}
			continue
		}
		if _, ok := ov.g.Node(id); !ok && strings.HasPrefix(id, "name:") {
			ov.notes = append(ov.notes, fmt.Sprintf("%s references %s, which is neither in the plan nor in the live graph", src, id))
		}
		ov.put(A)
	}
	for _, id := range touched {
		ov.markAttached(id)
	}
	ov.propagate(touched)
	ov.ciEdges(touched)
}

// retract removes what only the before side of a changed resource contributed.
func (ov *overlay) retract(B, A iac.PlanResource, hasA bool) {
	id := B.ID
	ov.own(id)
	keepW := map[string]bool{}
	if hasA {
		for _, w := range A.Weaknesses {
			keepW[w] = true
		}
	}
	for _, w := range B.Weaknesses {
		if !keepW[w] {
			ov.g.RemoveWeakness(id, w)
			if w == "PUBLIC_DATA_STORE" || w == "PUBLIC_NETWORK_EXPOSURE" {
				ov.g.RemoveEdge(graph.InternetNodeID, id, graph.EdgeExposes)
			}
		}
	}
	keepR := map[string]bool{}
	if hasA {
		for _, r := range A.Relations {
			keepR[r.Kind+"|"+r.ID] = true
		}
		for _, s := range A.SecurityGroups {
			keepR[graph.EdgeAttachedTo+"|"+s] = true
		}
	}
	for _, r := range B.Relations {
		if keepR[r.Kind+"|"+r.ID] {
			continue
		}
		kind, reverse, ok := graph.RelationEdge(r.Kind)
		if !ok {
			continue
		}
		from, to := id, r.ID
		if reverse {
			from, to = r.ID, id
		}
		ov.g.RemoveEdge(from, to, kind)
	}
	for _, s := range B.SecurityGroups {
		if !keepR[graph.EdgeAttachedTo+"|"+s] {
			ov.g.RemoveEdge(id, s, graph.EdgeAttachedTo)
		}
	}
	if n, ok := ov.g.Node(id); ok && hasA {
		for k := range B.Attributes {
			if _, still := A.Attributes[k]; !still {
				delete(n.Attributes, k)
			}
		}
	}
}

// put adds one after-side resource (findings → weaknesses, attributes, typed relations).
func (ov *overlay) put(r iac.PlanResource) {
	ov.after[r.ID] = r
	ov.checks[r.ID] = r.Checks
	ov.own(r.ID)
	src := changeSource(r)
	fs := r.Findings()
	for i := range fs {
		var rels []model.Relation
		for _, rel := range fs[i].Resource.Relations {
			attr := map[string]any{"confidence": string(ov.conf), "source": "plan", "plan_change": src}
			for k, v := range rel.Attr {
				attr[k] = v
			}
			rel.Attr = attr
			rels = append(rels, rel)
		}
		fs[i].Resource.Relations = rels
	}
	ov.g.AttachFindings(fs)
	for _, s := range r.SecurityGroups {
		ov.g.AddEdge(r.ID, s, graph.EdgeAttachedTo, map[string]any{"source": "plan", "confidence": string(ov.conf),
			"because": fmt.Sprintf("%s uses security group %s (planned by %s)", r.Name, lastSeg(s), src)})
	}
	if r.PublicReachable == iac.ReachYes {
		if n, ok := ov.g.Node(r.ID); ok {
			n.Attributes["public_reachable"] = true
		}
	}
}

// ---------------------------------------------------------------- security-group exposure

type ruleView struct {
	cidrs []string
	ports string
	src   string
	check string
}

// sgRules returns the ingress rules of a security group: the plan's after side, merged with
// the live node's `ingress` attribute for a partial stub; known=false when nothing states them.
func (ov *overlay) sgRules(id string) (rules []ruleView, known bool) {
	if r, ok := ov.after[id]; ok {
		canon := ""
		for _, c := range r.Checks {
			if c.Weakness == "PUBLIC_NETWORK_EXPOSURE" {
				canon = c.CanonicalID
			}
		}
		for _, in := range r.Ingress {
			rules = append(rules, ruleView{cidrs: in.CIDRs, ports: in.Ports(), src: in.Source, check: canon})
		}
		if !r.Partial {
			return rules, !containsStr(r.Unknown, "ingress")
		}
	}
	src := ov.live
	if src == nil {
		src = ov.g
	}
	n, ok := src.Node(id)
	if !ok {
		return rules, false
	}
	raw, ok := n.Attributes["ingress"].([]any)
	if !ok {
		return rules, false
	}
	for _, x := range raw {
		m, _ := x.(map[string]any)
		if m == nil {
			continue
		}
		var cidrs []string
		if c, _ := m["cidr"].(string); c != "" {
			cidrs = append(cidrs, c)
		}
		for _, k := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
			if l, ok := m[k].([]any); ok {
				for _, c := range l {
					if s, ok := c.(string); ok {
						cidrs = append(cidrs, s)
					}
				}
			}
		}
		in := iac.IngressRule{CIDRs: cidrs, Protocol: fmt.Sprint(m["protocol"])}
		if f, ok := m["from_port"].(float64); ok {
			in.FromPort = int(f)
		} else if i, ok := m["from_port"].(int); ok {
			in.FromPort = i
		}
		if f, ok := m["to_port"].(float64); ok {
			in.ToPort = int(f)
		} else if i, ok := m["to_port"].(int); ok {
			in.ToPort = i
		}
		rules = append(rules, ruleView{cidrs: cidrs, ports: in.Ports(), src: "live " + n.Name})
	}
	return rules, true
}

func isSG(g *graph.Graph, id string) bool {
	if n, ok := g.Node(id); ok && strings.Contains(strings.ToLower(n.Type), "security_group") {
		return true
	}
	return strings.Contains(id, "security-group/") || strings.HasPrefix(lastSeg(id), "sg-")
}

// propagate recomputes the internet exposure of every workload behind a touched security group
// (and of every touched workload): the union of its groups' public ingress sources, gated by
// whether the workload is internet-reachable at all. An unknown group never removes exposure.
func (ov *overlay) propagate(touched []string) {
	work := map[string]bool{}
	for _, id := range touched {
		if isSG(ov.g, id) {
			for _, e := range ov.g.In(id) {
				if e.Kind == graph.EdgeAttachedTo {
					work[e.From] = true
				}
			}
			continue
		}
		if r, ok := ov.after[id]; ok && (len(r.SecurityGroups) > 0 || r.PublicReachable != iac.ReachUnknown) {
			work[id] = true
		}
	}
	for _, n := range sortedKeys(work) {
		ov.exposeVia(n)
	}
}

func (ov *overlay) exposeVia(id string) {
	node, ok := ov.g.Node(id)
	if !ok || node.Class == graph.ClassNetwork {
		return
	}
	reach := iac.ReachUnknown
	if r, ok := ov.after[id]; ok {
		reach = r.PublicReachable
	}
	if reach == iac.ReachUnknown {
		if v, _ := node.Attributes["public_ip"].(string); v != "" {
			reach = iac.ReachYes
		}
	}
	var sgs []string
	for _, e := range ov.g.Out(id) {
		if e.Kind == graph.EdgeAttachedTo && isSG(ov.g, e.To) {
			sgs = append(sgs, e.To)
		}
	}
	if len(sgs) == 0 {
		return
	}
	allKnown := true
	var cidrs, ports, srcs, sgNames []string
	canon := ""
	for _, sg := range sgs {
		rules, known := ov.sgRules(sg)
		allKnown = allKnown && known
		sgNames = append(sgNames, nodeName(ov.g, sg))
		for _, r := range rules {
			pub := core.PublicSources(r.cidrs)
			if len(pub) == 0 {
				continue
			}
			cidrs = append(cidrs, pub...)
			ports = append(ports, r.ports)
			srcs = append(srcs, r.src)
			if canon == "" && r.check != "" && (containsStr(pub, "0.0.0.0/0") || containsStr(pub, "::/0")) {
				canon = r.check
			}
		}
	}
	cidrs, ports, srcs = uniq(cidrs), uniq(ports), uniq(srcs)
	_, had := edgeOf(ov.g, graph.InternetNodeID, id, graph.EdgeExposes)
	switch {
	case reach == iac.ReachNo || (len(cidrs) == 0 && allKnown):
		if had {
			ov.g.RemoveEdge(graph.InternetNodeID, id, graph.EdgeExposes)
			ov.g.RemoveWeakness(id, "PUBLIC_NETWORK_EXPOSURE")
		}
		return
	case len(cidrs) == 0:
		return // a group the overlay cannot read: keep whatever the live graph says
	}
	if reach == iac.ReachUnknown && !had && ov.live != nil {
		ov.notes = append(ov.notes, fmt.Sprintf("%s: internet reachability unknown at plan time; exposure through its security groups assumed", node.Name))
	}
	src := ov.changed[id]
	for _, s := range srcs {
		if !strings.HasPrefix(s, "live ") {
			src = s
			break
		}
	}
	attr := map[string]any{
		"exposure_cidrs":  cidrs,
		"ports":           strings.Join(ports, ","),
		"security_groups": sgNames,
		"weakness":        "PUBLIC_NETWORK_EXPOSURE",
		"via":             "plan: " + src + " ingress " + strings.Join(ports, ", ") + " from " + strings.Join(cidrs, ", "),
		"plan_change":     src,
		"confidence":      string(ov.conf),
		"because": fmt.Sprintf("%s is reachable from %s on %s through security group %s (planned by %s)",
			node.Name, strings.Join(cidrs, ", "), strings.Join(ports, ", "), strings.Join(sgNames, ", "), src),
	}
	if canon != "" {
		attr["fix_canonical"] = canon
	}
	ov.own(id)
	ov.g.RemoveEdge(graph.InternetNodeID, id, graph.EdgeExposes)
	ov.g.AddNode(&graph.Node{ID: id, Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"}})
	ov.g.AddEdge(graph.InternetNodeID, id, graph.EdgeExposes, attr)
	if ov.changed[id] == "" {
		ov.changed[id] = src
	}
}

func edgeOf(g *graph.Graph, from, to, kind string) (*graph.Edge, bool) {
	for _, e := range g.Out(from) {
		if e.To == to && e.Kind == kind {
			return e, true
		}
	}
	return nil, false
}

// ---------------------------------------------------------------- CI-entry overlay rule

const maxRepoFanout = 200

// ciEdges derives repository → role can_assume edges from planned GitHub OIDC trusts: for every
// touched role with OIDC subjects, the existing repository edges into it are replaced by one
// edge per repository node whose name a subject matches. The edge carries oidc_subject /
// oidc_subject_class, which the attack-path CI-entry floor reads (attackpath/toxic.go).
func (ov *overlay) ciEdges(touched []string) {
	var repos []*graph.Node
	for _, n := range ov.g.Nodes() {
		if n.Class == graph.ClassSaaS && saas.RepoFullName(firstNonEmpty(n.ID, n.Name)) != "" || n.Class == graph.ClassSaaS && saas.RepoFullName(n.Name) != "" {
			repos = append(repos, n)
		}
	}
	for _, id := range touched {
		r, ok := ov.after[id]
		if !ok || r.Type != "aws_iam_role" {
			continue
		}
		if _, ok := r.Attributes["oidc_subjects"]; !ok && len(r.OIDCSubjects) == 0 {
			continue
		}
		for _, e := range append([]*graph.Edge(nil), ov.g.In(id)...) {
			if e.Kind != graph.EdgeCanAssume {
				continue
			}
			if n, ok := ov.g.Node(e.From); ok && n.Class == graph.ClassSaaS {
				ov.g.RemoveEdge(e.From, id, graph.EdgeCanAssume)
			}
		}
		added := 0
		for _, repo := range repos {
			for _, sub := range r.OIDCSubjects {
				if !saas.OIDCSubjectMatchesRepo(sub, repo.ID) && !saas.OIDCSubjectMatchesRepo(sub, repo.Name) {
					continue
				}
				if added >= maxRepoFanout {
					break
				}
				cls, why := saas.ClassifyOIDCSubject(sub)
				ov.g.AddEdge(repo.ID, id, graph.EdgeCanAssume, map[string]any{
					"oidc_subject": sub, "oidc_subject_class": cls, "via": "GitHub OIDC sub " + firstNonEmpty(sub, "(none)"),
					"source": "plan", "plan_change": changeSource(r), "confidence": string(ov.conf), "derived_from": "planned trust policy",
					"because": fmt.Sprintf("workflows of %s can assume %s through its planned GitHub OIDC trust (%s)", repo.Name, r.Name, why),
				})
				added++
				break
			}
		}
	}
}

// fixFor finds the plan check behind a changed hop's weakness.
func (ov *overlay) fixFor(s model.Step) string {
	for _, id := range []string{s.WeaknessOn, s.Resource} {
		for _, c := range ov.checks[id] {
			if s.Weakness == "" || c.Weakness == s.Weakness {
				return c.CanonicalID
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------- helpers

// same reports whether two sides of one resource contribute the same graph facts.
func same(a, b iac.PlanResource) bool {
	a.Action, b.Action = "", ""
	a.Address, b.Address = "", ""
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func keysOf[V any](m map[string]V) []string { return sortedKeys(m) }

func lastSeg(s string) string {
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndexAny(s, "/:"); i >= 0 && i < len(s)-1 {
		return s[i+1:]
	}
	return s
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
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

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
