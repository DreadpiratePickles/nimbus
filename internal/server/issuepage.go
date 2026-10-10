package server

// The Issue page (integration pass 3, delta shortfall #4; Wiz Issue page bar): one record that
// `cloud-posture issues show`, GET /api/issues/{id} and the dashboard Issue pane all render —
// hops with "because", the score explanation, confidence, owner/SLA/due, linked finding and
// path Issues, the fix with its sidecar steps (prerequisite → snapshot → fix → verify →
// rollback, the AWS Security Hub remediation-plan phases), ticket links, the timeline and the
// suppression state.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/remediation"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// IssuePage is everything one Issue's page shows. Every list is non-nil (JSON arrays).
type IssuePage struct {
	Issue       model.Issue     `json:"issue"`
	Findings    []model.Finding `json:"findings"` // evidence (resolved ones included)
	Hops        []PageHop       `json:"hops"`     // the best path, hop by hop
	Paths       []PagePath      `json:"paths"`    // path variants (path Issue) or paths through the resource
	Score       PageScore       `json:"score"`
	Confidence  PageConfidence  `json:"confidence"`
	Owner       PageOwner       `json:"owner"`
	Linked      []LinkedIssue   `json:"linked_issues"`
	Fixes       []PageFix       `json:"fixes"`
	Ticket      *PageTicket     `json:"ticket"` // the Issue's own ticket (one per Issue); null when none
	Tickets     []PageTicket    `json:"tickets"`
	Timeline    []TimelineEntry `json:"timeline"`
	Suppression PageSuppression `json:"suppression"`
	// ScoreHistory is the Issue's score journey, one point per scan (W7-VERIFY r5 #11).
	ScoreHistory PageScoreHistory `json:"score_history"`
	// PotentialEscalations are the inferred path-rule matches anchored on a finding Issue's
	// principal (r5 #10): permissions allow an escalation the graph cannot prove. Never a path
	// Issue; empty for path Issues (their chains are their hops).
	PotentialEscalations []attackpath.PathRuleMatch `json:"potential_escalations"`
}

// PageScoreHistory is one Issue's per-scan score journey and the one-line text sparkline every
// surface prints (store.ScoreJourneyLine).
type PageScoreHistory struct {
	Points []store.IssueScorePoint `json:"points"`
	Line   string                  `json:"line"`
}

func scoreHistoryOf(st *store.Store, id string) PageScoreHistory {
	h := PageScoreHistory{Points: []store.IssueScorePoint{}}
	if pts, err := st.IssueScoreHistory(id, time.Time{}); err == nil && len(pts) > 0 {
		h.Points, h.Line = pts, store.ScoreJourneyLine(pts)
	}
	return h
}

// PageHop is one step of the best path with the reason it is possible.
type PageHop struct {
	Stage      int    `json:"stage"`
	Relation   string `json:"relation"`
	Resource   string `json:"resource"`
	Summary    string `json:"summary"`
	Because    string `json:"because"`
	Weakness   string `json:"weakness,omitempty"`
	FindingID  string `json:"finding_id,omitempty"`
	Confidence string `json:"confidence,omitempty"` // edge confidence (verified|inferred|hint)
}

type PagePath struct {
	ID       string  `json:"id"`
	IssueID  string  `json:"issue_id"`
	Name     string  `json:"name"`
	Impact   string  `json:"impact"`
	Score    float64 `json:"score"`
	Band     string  `json:"band"`
	Hops     int     `json:"hops"`
	RuleID   string  `json:"rule_id"`
	Toxic    string  `json:"toxic,omitempty"`
	WeakLink bool    `json:"weak_link,omitempty"`
	// Title is the path Issue title of the path (the shared builder: the stored Issue title,
	// else model.PathIssueTitle); Via names the hops between entry and target, so variants of
	// one Issue (same title) read apart.
	Title string `json:"title"`
	Via   string `json:"via"`
}

func pathTitle(st *store.Store, o *IssuePageOptions, p model.AttackPath, is model.Issue) string {
	id := st.PathIssueIDOf(p)
	if id == is.ID && is.Title != "" {
		return is.Title
	}
	for i := range o.Issues {
		if o.Issues[i].ID == id && o.Issues[i].Title != "" {
			return o.Issues[i].Title
		}
	}
	var lookup func(string) (model.PathNode, bool)
	if g := o.Graph; g != nil {
		lookup = func(nid string) (model.PathNode, bool) {
			n, ok := g.Node(nid)
			if !ok || n == nil {
				return model.PathNode{}, false
			}
			return model.PathNode{Name: n.Name, Attrs: n.Attributes}, true
		}
	}
	return model.PathIssueTitle(p, lookup)
}

// pathVia names every hop resource of p after the entry (graph names, ids when unknown).
func pathVia(g *graph.Graph, p model.AttackPath) string {
	var names []string
	for i, s := range p.Steps {
		if i == 0 || s.Resource == "" || s.Resource == graph.InternetNodeID {
			continue
		}
		name := s.Resource
		if g != nil {
			if n, ok := g.Node(s.Resource); ok && n.Name != "" {
				name = n.Name
			}
		}
		if len(names) == 0 || names[len(names)-1] != name {
			names = append(names, name)
		}
	}
	return strings.Join(names, " → ")
}

// PageScore: the Issue's own score (path score for a path Issue) and the published finding
// score explanation (risk.Explanation factors) of its highest-scored evidence finding.
type PageScore struct {
	Kind        string            `json:"kind"` // path | finding
	Score       float64           `json:"score"`
	Band        string            `json:"band"`
	Version     string            `json:"version"`
	FindingID   string            `json:"finding_id,omitempty"`
	FindingRisk float64           `json:"finding_score,omitempty"`
	FindingBand string            `json:"finding_band,omitempty"`
	Explanation *risk.Explanation `json:"explanation,omitempty"`
	Note        string            `json:"note,omitempty"`
}

type PageConfidence struct {
	Label  string  `json:"label"` // verified | inferred | hint (paths) or high|medium|low (findings)
	Value  float64 `json:"value"`
	Reason string  `json:"reason"`
}

// PageOwner is who must act and by when: the governance assignment stored on the Issue
// (rule | tag | codeowners | account | default | unassigned) with its why trail.
type PageOwner struct {
	Owner      string     `json:"owner"`
	Source     string     `json:"source"`
	Rule       string     `json:"rule,omitempty"`
	Why        string     `json:"why,omitempty"`
	SLADays    int        `json:"sla_days"`
	DueAt      *time.Time `json:"due_at,omitempty"`
	GraceUntil *time.Time `json:"grace_until,omitempty"`
	Overdue    bool       `json:"overdue"`
	PastGrace  bool       `json:"past_grace,omitempty"`
}

type LinkedIssue struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	Relation string         `json:"relation"` // "attack path through this resource" | "evidence on this path"
	Title    string         `json:"title"`
	Severity model.Severity `json:"severity"`
	State    string         `json:"state"`
	Score    float64        `json:"score,omitempty"`
	Band     string         `json:"band,omitempty"`
}

// PageFix is one fix for the Issue's evidence: the template and its sidecar metadata, as
// ordered phases.
type PageFix struct {
	FindingID   string                `json:"finding_id"`
	CanonicalID string                `json:"canonical_id"`
	Resource    string                `json:"resource"`
	Template    string                `json:"template"`
	Generic     bool                  `json:"generic"`
	Format      string                `json:"format"`
	Command     string                `json:"command"` // the cloud-posture command that writes it
	Metadata    *remediation.Metadata `json:"metadata,omitempty"`
	Phases      []Phase               `json:"phases"`
}

// Phase is one step of a remediation plan.
type Phase struct {
	Name  string   `json:"name"` // prerequisite | snapshot | fix | verify | rollback
	Steps []string `json:"steps"`
}

type PageTicket struct {
	FindingID string `json:"finding_id,omitempty"`
	State     string `json:"state,omitempty"` // the Issue ticket: open | closed
	Channel   string `json:"channel"`
	Ref       string `json:"ref"`
	URL       string `json:"url,omitempty"`
	SentAt    string `json:"sent_at,omitempty"`
}

type TimelineEntry struct {
	At     time.Time `json:"at"`
	Event  string    `json:"event"`
	Detail string    `json:"detail,omitempty"`
}

type PageSuppression struct {
	Suppressed bool       `json:"suppressed"`
	Reason     string     `json:"reason,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ApprovedBy string     `json:"approved_by,omitempty"`
	Expired    bool       `json:"expired,omitempty"`
}

// IssuePageOptions are the shared inputs; zero values are loaded from the store. Building
// pages for many Issues (dashboard) passes them once.
type IssuePageOptions struct {
	Risk     risk.Options
	Graph    *graph.Graph
	Paths    []model.AttackPath   // stored attack paths (rule chains + traversal)
	Analysis *attackpath.Analysis // optional: the traversal behind Paths (off-path cap input)
	Issues   []model.Issue
	Ranked   []risk.Ranked
	Now      time.Time
	// PathRules are the rules potential escalations are matched with (nil: the library;
	// the CLI passes library + customer rules, pathRulesFor).
	PathRules []attackpath.PathRule

	potential map[string][]attackpath.PathRuleMatch // resource id -> inferred matches (prepare)
}

// prepare fills every missing shared input from the store.
func (o *IssuePageOptions) prepare(st *store.Store) error {
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	if o.Issues == nil {
		is, err := st.Issues(store.IssueFilter{})
		if err != nil {
			return err
		}
		o.Issues = is
	}
	if o.Paths == nil {
		ps, err := st.AttackPaths()
		if err != nil {
			return err
		}
		o.Paths = ps
	}
	if o.Graph == nil {
		g, err := LoadGraph(st)
		if err != nil {
			return err
		}
		o.Graph = g
	}
	if o.Ranked == nil {
		fs, err := st.Findings(store.Filter{Status: "FAIL"})
		if err != nil {
			return err
		}
		ro := o.Risk
		if ro.Analysis == nil && o.Analysis != nil {
			ro.Analysis = o.Analysis
		}
		ro.Top = 0
		o.Ranked = risk.PrioritizeWith(fs, o.Graph, o.Paths, ro)
	}
	if o.potential == nil {
		o.potential = attackpath.PotentialEscalations(o.Graph, o.PathRules)
	}
	return nil
}

// LoadGraph rebuilds the in-memory graph from the store.
func LoadGraph(st *store.Store) (*graph.Graph, error) {
	s := &Server{st: st}
	return s.loadGraph()
}

// BuildIssuePage builds one Issue's page; store.ErrIssueNotFound when the id is unknown.
func BuildIssuePage(st *store.Store, id string, o IssuePageOptions) (*IssuePage, error) {
	if err := o.prepare(st); err != nil {
		return nil, err
	}
	var is *model.Issue
	for i := range o.Issues {
		if o.Issues[i].ID == id {
			is = &o.Issues[i]
			break
		}
	}
	if is == nil {
		return nil, fmt.Errorf("%w: %s", store.ErrIssueNotFound, id)
	}
	return buildPage(st, *is, &o), nil
}

// BuildIssuePages builds every Issue's page with one ranking pass (dashboard payload).
func BuildIssuePages(st *store.Store, o IssuePageOptions) (map[string]*IssuePage, error) {
	if err := o.prepare(st); err != nil {
		return nil, err
	}
	out := make(map[string]*IssuePage, len(o.Issues))
	for _, is := range o.Issues {
		out[is.ID] = buildPage(st, is, &o)
	}
	return out, nil
}

func pathTouches(p model.AttackPath, resource string, fids map[string]bool) bool {
	for _, s := range p.Steps {
		if (resource != "" && (s.Resource == resource || s.WeaknessOn == resource)) || (s.FindingID != "" && fids[s.FindingID]) {
			return true
		}
	}
	for _, f := range p.FindingIDs {
		if fids[f] {
			return true
		}
	}
	return false
}

func hopConfidence(s model.Step) string {
	if e, ok := s.Evidence["edge"].(map[string]any); ok {
		if c, ok := e[model.AttrConfidence].(string); ok {
			return c
		}
	}
	if c, ok := s.Evidence[model.AttrConfidence].(string); ok {
		return c
	}
	return ""
}

func buildPage(st *store.Store, is model.Issue, o *IssuePageOptions) *IssuePage {
	pg := &IssuePage{Issue: is, Findings: []model.Finding{}, Hops: []PageHop{}, Paths: []PagePath{}, Linked: []LinkedIssue{},
		Fixes: []PageFix{}, Tickets: []PageTicket{}, Timeline: []TimelineEntry{}, ScoreHistory: scoreHistoryOf(st, is.ID),
		PotentialEscalations: []attackpath.PathRuleMatch{}}
	if is.Kind != model.IssuePath && is.ResourceID != "" {
		if ms := o.potential[is.ResourceID]; len(ms) > 0 {
			pg.PotentialEscalations = ms
		}
	}

	// Paths: the Issue's own variants (path Issue) or every path through the resource.
	fids := map[string]bool{}
	for _, f := range is.FindingIDs {
		fids[f] = true
	}
	var mine []model.AttackPath
	for _, p := range o.Paths {
		if is.Kind == model.IssuePath {
			if st.PathIssueIDOf(p) == is.ID {
				mine = append(mine, p)
			}
		} else if pathTouches(p, is.ResourceID, fids) {
			mine = append(mine, p)
		}
	}
	sort.SliceStable(mine, func(i, j int) bool { return mine[i].Score > mine[j].Score })
	for _, p := range mine {
		_, _, rule := model.PathIssueKey(p)
		toxic := ""
		if is.Kind == model.IssuePath {
			toxic = is.ToxicCombination
		}
		pg.Paths = append(pg.Paths, PagePath{ID: p.ID, IssueID: st.PathIssueIDOf(p), Name: p.Name, Impact: p.Impact, Score: p.Score,
			Band: risk.BandFor(p.Score), Hops: len(p.Steps), RuleID: rule, Toxic: toxic, WeakLink: p.WeakLink,
			Title: pathTitle(st, o, p, is), Via: pathVia(o.Graph, p)})
	}
	if len(mine) > 0 {
		for _, s := range mine[0].Steps {
			pg.Hops = append(pg.Hops, PageHop{Stage: s.Stage, Relation: s.Relation, Resource: s.Resource, Summary: firstNonEmptyStr(s.Summary, s.Title),
				Because: firstNonEmptyStr(s.Because, "(no reason recorded for this hop)"), Weakness: s.Weakness, FindingID: s.FindingID, Confidence: hopConfidence(s)})
		}
	}

	// Evidence: the Issue's findings; a path Issue's are its paths' findings.
	evIDs := append([]string{}, is.FindingIDs...)
	if is.Kind == model.IssuePath {
		seen := map[string]bool{}
		for _, id := range evIDs {
			seen[id] = true
		}
		for _, p := range mine {
			for _, id := range p.FindingIDs {
				if !seen[id] {
					seen[id] = true
					evIDs = append(evIDs, id)
				}
			}
			for _, s := range p.Steps {
				if s.FindingID != "" && !seen[s.FindingID] {
					seen[s.FindingID] = true
					evIDs = append(evIDs, s.FindingID)
				}
			}
		}
	}
	for _, id := range evIDs {
		if f, err := st.Finding(id); err == nil {
			f.Raw = nil
			pg.Findings = append(pg.Findings, *f)
		}
	}

	// Score: the Issue's own number plus the published explanation of its top evidence.
	rankBy := map[string]risk.Ranked{}
	for _, r := range o.Ranked {
		rankBy[r.Finding.ID] = r
	}
	var top *risk.Ranked
	for _, f := range pg.Findings {
		if r, ok := rankBy[f.ID]; ok && (top == nil || r.Score > top.Score) {
			rr := r
			top = &rr
		}
	}
	pg.Score = PageScore{Kind: "finding", Version: risk.ScoreVersion}
	if is.Kind == model.IssuePath {
		pg.Score.Kind, pg.Score.Score, pg.Score.Band = "path", is.Score, firstNonEmptyStr(is.Band, risk.BandFor(is.Score))
		pg.Score.Note = "path score = max over this Issue's hop variants (likelihood × impact, docs/scoring.md \"Path score\")"
	}
	if top != nil {
		x := risk.Explain(*top)
		pg.Score.FindingID, pg.Score.FindingRisk, pg.Score.FindingBand, pg.Score.Explanation = top.Finding.ID, top.Score, top.Band, &x
		if is.Kind != model.IssuePath {
			pg.Score.Score, pg.Score.Band = top.Score, top.Band
		}
	} else if is.Kind != model.IssuePath {
		pg.Score.Note = "no open evidence finding is ranked (resolved or suppressed evidence)"
	}

	// Confidence.
	if is.Kind == model.IssuePath {
		lbl := firstNonEmptyStr(string(is.ConfidenceLabel), string(model.ConfidenceInferred))
		pg.Confidence = PageConfidence{Label: lbl, Value: is.Confidence, Reason: "weakest edge on the best path: verified = Allow from complete exact policy documents; inferred = unknown or approximate inputs; hint = heuristic fallback"}
	} else {
		n := len(is.Sources)
		lbl := "low"
		switch {
		case is.Confidence >= 0.8:
			lbl = "high"
		case is.Confidence >= 0.5:
			lbl = "medium"
		}
		pg.Confidence = PageConfidence{Label: lbl, Value: is.Confidence, Reason: fmt.Sprintf("%d independent source(s) agree: %s", n, strings.Join(is.Sources, ", "))}
	}

	// Owner / SLA / due: the governance assignment stored on the Issue (resolved on every
	// scan / ingest / prioritize; docs/governance.md).
	pg.Owner = PageOwner{Owner: is.Owner, Source: firstNonEmptyStr(is.OwnerSource, "unresolved (run scan, ingest or prioritize)"),
		Rule: is.OwnerRule, Why: is.OwnerWhy, SLADays: is.SLADays}
	if is.DueAt != nil {
		d := is.DueAt.UTC()
		pg.Owner.DueAt = &d
		pg.Owner.Overdue = is.IsOverdue(o.Now)
	}
	if is.GraceUntil != nil {
		g := is.GraceUntil.UTC()
		pg.Owner.GraceUntil = &g
		pg.Owner.PastGrace = model.IsActive(is.State) && o.Now.After(g)
	}

	// Linked Issues.
	pathOf := map[string]bool{}
	for _, p := range pg.Paths {
		pathOf[p.IssueID] = true
	}
	onPath := map[string]bool{}
	if is.Kind == model.IssuePath {
		for _, p := range mine {
			for _, s := range p.Steps {
				onPath[s.Resource], onPath[s.WeaknessOn] = true, true
			}
		}
		delete(onPath, "")
	}
	evSet := map[string]bool{}
	for _, f := range pg.Findings {
		evSet[f.ID] = true
	}
	for _, other := range o.Issues {
		if other.ID == is.ID {
			continue
		}
		rel := ""
		if is.Kind == model.IssuePath {
			if other.Kind != model.IssuePath && (onPath[other.ResourceID] || intersects(other.FindingIDs, evSet)) {
				rel = "evidence on this path"
			}
		} else if other.Kind == model.IssuePath && pathOf[other.ID] {
			rel = "attack path through this resource"
		}
		if rel != "" {
			pg.Linked = append(pg.Linked, LinkedIssue{ID: other.ID, Kind: other.Kind, Relation: rel, Title: firstNonEmptyStr(other.Title, other.CanonicalID),
				Severity: other.Severity, State: other.State, Score: other.Score, Band: other.Band})
		}
	}
	sort.SliceStable(pg.Linked, func(i, j int) bool {
		if pg.Linked[i].Severity.Rank() != pg.Linked[j].Severity.Rank() {
			return pg.Linked[i].Severity.Rank() > pg.Linked[j].Severity.Rank()
		}
		return pg.Linked[i].ID < pg.Linked[j].ID
	})

	// Fixes: one per template over the open evidence (a path Issue: every cuttable hop).
	seenTpl := map[string]bool{}
	for _, f := range pg.Findings {
		if f.Status != model.Fail {
			continue
		}
		fx := FixFor(f)
		if fx == nil {
			continue
		}
		key := fx.Template + "|" + fx.Resource
		if seenTpl[key] {
			continue
		}
		seenTpl[key] = true
		pg.Fixes = append(pg.Fixes, *fx)
		if len(pg.Fixes) >= 8 {
			break
		}
	}

	// The verify phase starts with the targeted verification of this Issue (r3 E8): it closes the
	// Issue as verified_fixed only on positive evidence and survives later scans.
	for i := range pg.Fixes {
		for j := range pg.Fixes[i].Phases {
			if pg.Fixes[i].Phases[j].Name == "verify" {
				pg.Fixes[i].Phases[j].Steps = append([]string{"cloud-posture verify " + is.ID + "   # targeted re-read; verified_fixed only when the problem is observed gone"},
					pg.Fixes[i].Phases[j].Steps...)
			}
		}
	}

	// Tickets an integration recorded for the evidence.
	pg.Tickets = ticketsFor(st, evIDs)
	if is.TicketKey != "" || is.TicketURL != "" {
		t := PageTicket{Channel: is.TicketSink, Ref: is.TicketKey, URL: is.TicketURL, State: is.TicketState}
		pg.Ticket = &t
		pg.Tickets = append([]PageTicket{t}, pg.Tickets...)
	}

	// Timeline: Issue lifecycle, path history and evidence lifecycle, oldest first.
	pg.Timeline = timelineFor(st, is, evIDs)

	// Suppression.
	if is.State == model.StateSuppressed || is.Reason != "" {
		s := PageSuppression{Suppressed: is.State == model.StateSuppressed, Reason: is.Reason, ApprovedBy: is.ApprovedBy}
		if is.ExpiresAt != nil {
			e := is.ExpiresAt.UTC()
			s.ExpiresAt = &e
			s.Expired = o.Now.After(e)
		}
		pg.Suppression = s
	}
	return pg
}

func intersects(ids []string, set map[string]bool) bool {
	for _, id := range ids {
		if set[id] {
			return true
		}
	}
	return false
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// FixFor renders the typed fix of one finding (Terraform first, else the template's own
// format) as a PageFix with its remediation phases; nil when nothing renders.
func FixFor(f model.Finding) *PageFix {
	format := remediation.Terraform
	if fs := remediation.Formats(f.CanonicalID); len(fs) > 0 {
		format = fs[0]
		for _, x := range fs {
			if x == remediation.Terraform {
				format = x
			}
		}
	}
	fix, err := remediation.Generate(f, format)
	if err != nil || fix == nil {
		return nil
	}
	return &PageFix{FindingID: f.ID, CanonicalID: f.CanonicalID, Resource: firstNonEmptyStr(f.Resource.ID, f.Resource.Name, f.File),
		Template: firstNonEmptyStr(fix.Template, "generic stub"), Generic: fix.Generic, Format: string(fix.Format),
		Command:  fmt.Sprintf("cloud-posture fix --id %s --format %s", f.ID, fix.Format),
		Metadata: fix.Metadata, Phases: RemediationPhases(fix)}
}

// RemediationPhases turns a rendered fix and its sidecar into the ordered plan the AWS
// Security Hub remediation plans use: prerequisite → snapshot → fix → verify → rollback.
func RemediationPhases(fix *remediation.Fix) []Phase {
	m := fix.Metadata
	var pre, snap, apply, verify, back []string
	res := firstNonEmptyStr(fix.Finding.Resource.ID, fix.Finding.Resource.Name, fix.Finding.File)
	if m != nil {
		pre = append(pre, "permissions: "+strings.Join(m.ActionsRequired, ", "))
		bf := "unknown"
		if m.BreaksFunction.Value != nil {
			bf = map[bool]string{true: "yes", false: "no"}[*m.BreaksFunction.Value]
		}
		pre = append(pre, fmt.Sprintf("breaks function: %s — %s", bf, strings.TrimSpace(m.BreaksFunction.Note)))
		pre = append(pre, fmt.Sprintf("effort %s · confidence %s", m.Effort, m.Confidence))
		if strings.TrimSpace(m.Mitigation) != "" {
			pre = append(pre, "mitigation if the fix must wait: "+strings.TrimSpace(m.Mitigation))
		}
	} else {
		pre = append(pre, "generic stub: no typed template for "+fix.CanonicalID+" yet; review the scanner's guidance before changing anything")
	}
	switch fix.Format {
	case remediation.Terraform:
		snap = append(snap, "terraform state pull > nimbus-before.tfstate   # the state the rollback returns to")
	case remediation.CloudFormation:
		snap = append(snap, "aws cloudformation get-template --stack-name \"$STACK\" > nimbus-before.json   # the template the rollback returns to")
	case remediation.Kubernetes:
		snap = append(snap, "kubectl get -o yaml <the object> > nimbus-before.yaml   # the object the rollback returns to")
	case remediation.Bicep:
		snap = append(snap, "az deployment group export -g \"$RESOURCE_GROUP\" > nimbus-before.json   # the deployment the rollback returns to")
	}
	snap = append(snap, "record the current configuration of "+res+" (needed by rollback)")
	apply = append(apply, "write the change: cloud-posture fix --id "+fix.Finding.ID+" --format "+string(fix.Format)+" (file "+fix.FileName+")")
	apply = append(apply, fix.Steps...)
	if m != nil && strings.TrimSpace(m.Validation.SQL) != "" {
		verify = append(verify, "re-scan the resource (cloud-posture scan, or re-ingest the scanner output)")
		verify = append(verify, "cloud-posture query \""+strings.ReplaceAll(m.Validation.SQL, "\"", "\\\"")+"\"   # expect no rows")
		if m.Validation.Note != "" {
			verify = append(verify, "note: "+m.Validation.Note)
		}
	} else {
		verify = append(verify, "re-scan and confirm the finding is resolved: cloud-posture issues show <id>")
	}
	if m != nil && strings.TrimSpace(m.Rollback) != "" {
		back = append(back, strings.TrimSpace(m.Rollback))
	} else {
		back = append(back, "revert the change (git revert of the fix commit) and re-apply the snapshot")
	}
	return []Phase{{"prerequisite", pre}, {"snapshot", snap}, {"fix", apply}, {"verify", verify}, {"rollback", back}}
}

func ticketsFor(st *store.Store, ids []string) []PageTicket {
	out := []PageTicket{}
	if len(ids) == 0 {
		return out
	}
	q := "SELECT finding_id, channel, COALESCE(external_ref,''), COALESCE(sent_at,'') FROM alerts WHERE finding_id IN (?" + strings.Repeat(",?", len(ids)-1) + ") ORDER BY sent_at, channel"
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := st.DB().Query(q, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var t PageTicket
		if rows.Scan(&t.FindingID, &t.Channel, &t.Ref, &t.SentAt) != nil || t.Ref == "" {
			continue
		}
		if strings.HasPrefix(t.Ref, "https://") {
			t.URL = t.Ref
		}
		out = append(out, t)
	}
	return out
}

func timelineFor(st *store.Store, is model.Issue, evIDs []string) []TimelineEntry {
	out := []TimelineEntry{}
	if !is.FirstSeen.IsZero() {
		out = append(out, TimelineEntry{At: is.FirstSeen, Event: "first seen", Detail: "Issue opened (" + is.Kind + ")"})
	}
	// Issue-level transitions (any kind): path hops / rescoring, suppression, pending fix marks,
	// verification and regressions after verify.
	if h, err := st.PathIssueHistory(is.ID); err == nil {
		prefix := "issue "
		if is.Kind == model.IssuePath {
			prefix = "path "
		}
		for _, e := range h {
			var parts []string
			if e.Score != 0 || is.Kind == model.IssuePath {
				parts = append(parts, fmt.Sprintf("score %.1f", e.Score))
			}
			if e.ScanID != "" {
				parts = append(parts, "scan "+e.ScanID)
			}
			if e.SecondaryKey != "" {
				parts = append(parts, "hops "+e.SecondaryKey)
			}
			if e.Detail != "" {
				parts = append(parts, e.Detail)
			}
			ev := prefix + e.State
			if e.RegressedAfterVerify {
				ev = "regressed after verify: " + e.State
			}
			out = append(out, TimelineEntry{At: e.At, Event: ev, Detail: strings.Join(parts, " · ")})
		}
	}
	for _, id := range evIDs {
		h, err := st.History(id)
		if err != nil {
			continue
		}
		for _, e := range h {
			d := "finding " + id
			if e.ScanID != "" {
				d += " · scan " + e.ScanID
			}
			out = append(out, TimelineEntry{At: e.At, Event: "evidence " + e.State, Detail: d})
		}
	}
	if is.ResolvedAt != nil {
		out = append(out, TimelineEntry{At: *is.ResolvedAt, Event: "resolved"})
	}
	if is.State == model.StateSuppressed && is.ExpiresAt != nil {
		out = append(out, TimelineEntry{At: *is.ExpiresAt, Event: "suppression expires", Detail: is.Reason})
	}
	if is.VerifiedAt != nil {
		out = append(out, TimelineEntry{At: *is.VerifiedAt, Event: "verified", Detail: is.VerifiedBy})
	}
	if !is.LastSeen.IsZero() && !is.LastSeen.Equal(is.FirstSeen) {
		out = append(out, TimelineEntry{At: is.LastSeen, Event: "last seen"})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}
