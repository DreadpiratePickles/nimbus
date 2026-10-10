package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/integrations"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

// issueVerdict is the analysis verdict Issue severities derive from (integration pass 2
// item 2): each finding's published risk band and, per resource, the best band of the
// complete attack paths through it. Exposures are not paths and are not an input.
func issueVerdict(ranked []risk.Ranked, an *attackpath.Analysis) *store.IssueVerdict {
	v := &store.IssueVerdict{FindingBand: map[string]string{}, PathBand: map[string]string{}}
	for _, r := range ranked {
		v.FindingBand[r.Finding.ID] = r.Band
	}
	if an == nil {
		return v
	}
	best := map[string]float64{}
	for _, p := range an.Paths {
		for _, s := range p.Steps {
			for _, id := range []string{s.Resource, s.WeaknessOn} {
				if id != "" && p.Score > best[id] {
					best[id] = p.Score
				}
			}
		}
	}
	for id, sc := range best {
		v.PathBand[id] = model.ScoreBand(sc)
	}
	return v
}

// accountKey is the PathScope key of a node ("provider/account").
func accountKey(n *graph.Node) string { return n.Provider + "/" + n.Account }

// observedScope is the PathScope of a scan: the accounts of the nodes the scan itself
// produced (collector graph + this scan's findings), resolved against the final graph g.
// A path Issue of an account this scan did not observe is never written or resolved by it
// (integration pass 2 item 8), so `scan --accounts a` cannot close account b's Issues.
func observedScope(observed map[string]bool, g *graph.Graph) *store.PathScope {
	return &store.PathScope{Accounts: observed, NodeAccount: func(id string) (string, bool) {
		n, ok := g.Node(id)
		if !ok {
			return "", false
		}
		if n.Account == "" {
			return "", true
		}
		return accountKey(n), true
	}}
}

// graphAccounts lists the account keys of g's nodes (empty accounts excluded).
func graphAccounts(g *graph.Graph) map[string]bool {
	m := map[string]bool{}
	if g == nil {
		return m
	}
	for _, n := range g.Nodes() {
		if n.Account != "" {
			m[accountKey(n)] = true
		}
	}
	return m
}

// rebuildIssueViews re-derives finding Issues (severity from the verdict) and path Issues
// (scoped to what the caller's traversal observed).
func rebuildIssueViews(st *store.Store, scanID string, ranked []risk.Ranked, an *attackpath.Analysis, scope *store.PathScope, now time.Time) (*store.PathIssueResult, error) {
	if err := st.RebuildIssuesWithVerdict(now, issueVerdict(ranked, an)); err != nil {
		return nil, err
	}
	var res *store.PathIssueResult
	if an != nil {
		var err error
		if res, err = st.RebuildPathIssuesScoped(scanID, an, now, scope); err != nil {
			return nil, err
		}
	}
	stageIssueScores(st, scanID, ranked)
	return res, nil
}

// stageIssueScores stages every active Issue's score for this scan's issue_score_history points
// (W7-VERIFY r5 #11), written when the scan is saved: a path Issue's score is its stored path
// score; a finding / combination Issue's is the best published risk score of its open evidence
// (the score the Issue page shows). An Issue with no scored evidence has no point.
func stageIssueScores(st *store.Store, scanID string, ranked []risk.Ranked) {
	is, err := st.Issues(store.IssueFilter{})
	if err != nil {
		return
	}
	best := map[string]risk.Ranked{}
	for _, r := range ranked {
		if b, ok := best[r.Finding.ID]; !ok || r.Score > b.Score {
			best[r.Finding.ID] = r
		}
	}
	scores := map[string]store.IssueScore{}
	for _, i := range is {
		if !model.IsActive(i.State) && i.State != model.StatePendingVerification {
			continue
		}
		if i.Kind == model.IssuePath {
			if i.Score > 0 {
				scores[i.ID] = store.IssueScore{Score: i.Score, Band: firstNonEmpty(i.Band, model.ScoreBand(i.Score))}
			}
			continue
		}
		var top *risk.Ranked
		for _, fid := range i.FindingIDs {
			if r, ok := best[fid]; ok && (top == nil || r.Score > top.Score) {
				r := r
				top = &r
			}
		}
		if top != nil {
			scores[i.ID] = store.IssueScore{Score: top.Score, Band: top.Band}
		}
	}
	st.StageIssueScores(scanID, scores)
}

// ---------------------------------------------------------------- issues command

var issuesFlags struct {
	kind, state, severity, band, provider, account string
	json                                           bool
	limit                                          int
	reason, expires, approvedBy                    string
	owner                                          string
	overdue                                        bool
	pendingBy                                      string
	since                                          string
	exportTo, exportURL                            string
	exportDryRun, exportAllowEmpty, exportRecipe   bool
}

var issuesCmd = &cobra.Command{
	Use:   "issues",
	Short: "Issues: one per problem (finding-derived single/combination, and attack-path Issues), with lifecycle and accepted risk",
	Example: `  cloud-posture issues                                  # open Issues, most severe first
  cloud-posture issues --kind path --band High          # attack-path Issues in the High band
  cloud-posture issues --overdue                        # open Issues past their governance due date
  cloud-posture issues --owner @acme/platform           # one owner's Issues ("(unassigned)" for none)
  cloud-posture issues metrics                          # MTTR by severity, on-time rate, overdue by owner
  cloud-posture issues show <id>
  cloud-posture issues suppress <id> --reason "compensated by WAF" --expires 2026-12-31 --approved-by alice
  cloud-posture issues history <id>`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := loadConfig(); err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		is, total, err := filterIssuesTotal(st)
		if err != nil {
			return err
		}
		if issuesFlags.json {
			if is == nil {
				is = []model.Issue{}
			}
			return output.JSON(os.Stdout, is)
		}
		h, _ := st.Headline()
		printIssuesHeader(os.Stdout, is, total, h)
		return nil
	},
}

// issueStateFilter maps --state to the stored states it selects (nil = all).
var issueStateFilter = map[string][]string{
	"open": {model.StateOpen, model.StateReopened}, "active": {model.StateOpen, model.StateReopened},
	"new": {model.StateOpen}, "reopened": {model.StateReopened}, "resolved": {model.StateResolved},
	"suppressed": {model.StateSuppressed}, "all": nil,
	// closure sub-states (W5-ISSUES)
	"pending": {model.StatePendingVerification}, "pending_verification": {model.StatePendingVerification},
	"verified": {model.StateVerifiedFixed}, "verified_fixed": {model.StateVerifiedFixed},
	"closed": {model.StateResolved, model.StateVerifiedFixed},
}

func filterIssues(st *store.Store) ([]model.Issue, error) {
	out, _, err := filterIssuesTotal(st)
	return out, err
}

// filterIssuesTotal is filterIssues plus the number of matches before --limit (the "of M").
func filterIssuesTotal(st *store.Store) ([]model.Issue, int, error) {
	lim := issuesFlags.limit
	issuesFlags.limit = 0
	all, err := filterIssuesAll(st)
	issuesFlags.limit = lim
	if err != nil {
		return nil, 0, err
	}
	if lim > 0 && len(all) > lim {
		return all[:lim], len(all), nil
	}
	return all, len(all), nil
}

func filterIssuesAll(st *store.Store) ([]model.Issue, error) {
	kind := strings.ToLower(strings.TrimSpace(issuesFlags.kind))
	switch kind {
	case "", model.IssueSingle, model.IssueCombination, model.IssuePath:
	default:
		return nil, fmt.Errorf("--kind must be single, combination or path")
	}
	states, ok := issueStateFilter[strings.ToLower(strings.TrimSpace(issuesFlags.state))]
	if !ok {
		return nil, fmt.Errorf("--state must be one of open, new, reopened, pending, verified, resolved, closed, suppressed, all")
	}
	var minSev model.Severity
	if issuesFlags.severity != "" {
		minSev = model.ParseSeverity(issuesFlags.severity)
	}
	band := strings.TrimSpace(issuesFlags.band)
	if band != "" && store.BandSeverity(band) == "" {
		return nil, fmt.Errorf("--band must be one of Critical, High, Medium, Low")
	}
	all, err := st.Issues(store.IssueFilter{Kind: kind, Provider: issuesFlags.provider, Account: issuesFlags.account,
		Owner: issuesFlags.owner, OverdueOnly: issuesFlags.overdue})
	if err != nil {
		return nil, err
	}
	var out []model.Issue
	for _, is := range all {
		if states != nil && !containsExact(states, is.State) {
			continue
		}
		if minSev != "" && is.Severity.Rank() < minSev.Rank() {
			continue
		}
		if band != "" && !strings.EqualFold(is.Band, band) {
			continue
		}
		out = append(out, is)
		if issuesFlags.limit > 0 && len(out) >= issuesFlags.limit {
			break
		}
	}
	return out, nil
}

func containsExact(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// printIssuesHeader prints the headline (the numbers every surface shows), "N of M <state>
// Issues" and the rows (r3 E9).
func printIssuesHeader(w io.Writer, is []model.Issue, total int, h *store.Headline) {
	if h != nil {
		fmt.Fprintln(w, h.Text())
		if c := h.ClosureText(); c != "" {
			fmt.Fprintf(w, "Closed / pending: %s\n", c)
		}
	}
	if len(is) == 0 {
		fmt.Fprintln(w, "No Issues match.")
		return
	}
	state := strings.ToLower(strings.TrimSpace(issuesFlags.state))
	label := "Issues"
	switch state {
	case "", "open", "active":
		label = "open Issues"
	case "all":
	default:
		label = state + " Issues"
	}
	fmt.Fprintf(w, "%d of %d %s (path Issues by score, then finding Issues by severity)\n\n", len(is), total, label)
	printIssueRows(w, is)
}

func printIssues(w io.Writer, is []model.Issue) {
	if len(is) == 0 {
		fmt.Fprintln(w, "No Issues match.")
		return
	}
	fmt.Fprintf(w, "%d Issue(s)\n\n", len(is))
	printIssueRows(w, is)
}

func printIssueRows(w io.Writer, is []model.Issue) {
	for _, i := range is {
		extra := ""
		if i.Kind == model.IssuePath {
			extra = fmt.Sprintf(" score %.1f band %s", i.Score, i.Band)
		}
		gov := "owner " + firstNonEmpty(i.Owner, "(unassigned)")
		if i.DueAt != nil {
			gov += " · due " + i.DueAt.UTC().Format("2006-01-02")
		} else if i.OwnerSource != "" {
			gov += " · no SLA"
		}
		if i.Overdue {
			gov += " · OVERDUE"
		}
		if i.RegressedAfterVerify && model.IsActive(i.State) {
			gov += " · REGRESSED after verify"
		}
		if i.State == model.StatePendingVerification && i.PendingBy != "" {
			gov += " · pending: " + i.PendingBy
		}
		if i.State == model.StateVerifiedFixed && i.VerifiedAt != nil {
			gov += " · verified " + i.VerifiedAt.UTC().Format("2006-01-02")
		}
		fmt.Fprintf(w, "%s  %-8s %-11s %-9s %s%s\n      %s · %s/%s · first seen %s\n      %s\n", i.ID, i.Severity, i.Kind, i.State,
			firstNonEmpty(i.CanonicalID, i.RuleID), extra, firstNonEmpty(i.Title, i.ResourceID), i.Provider, i.Account, i.FirstSeen.Format("2006-01-02"), gov)
	}
}

func findIssue(st *store.Store, id string) (*model.Issue, error) {
	id = st.ResolveIssueID(id) // an id from before the keyed-id migration still resolves
	all, err := st.Issues(store.IssueFilter{})
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %s", store.ErrIssueNotFound, id)
}

var issuesShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "The Issue page: hops with because, score explanation, confidence, owner/SLA, linked Issues, fix steps, tickets, timeline, suppression",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		is, err := findIssue(st, args[0]) // resolves an id from before the keyed-id migration
		if err != nil {
			return err
		}
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		pg, err := buildIssuePage(ctx, cfg, st, is.ID)
		if err != nil {
			return err
		}
		if issuesFlags.json {
			return output.JSON(os.Stdout, pg)
		}
		printIssuePage(os.Stdout, pg)
		printPotentialEscalations(os.Stdout, cfg, st, *is) // W7-POLISH item 13 (cli/potential.go)
		return nil
	},
}

// issuePageOptions are the Issue page inputs the CLI scores with: the stored graph and
// (merged) paths, the traversal analysis behind them, and the published risk options.
func issuePageOptions(ctx context.Context, cfg *config.Config, st *store.Store) (server.IssuePageOptions, error) {
	g, err := loadGraph(st)
	if err != nil {
		return server.IssuePageOptions{}, err
	}
	paths, err := st.AttackPaths()
	if err != nil {
		return server.IssuePageOptions{}, err
	}
	fs, _ := st.Findings(store.Filter{Status: "FAIL"})
	an := attackpath.Traverse(g, traversalOptionsFor(cfg, g, fs))
	an.Paths = attackpath.Merge(an.Paths, paths)
	ro := riskOptions(ctx, cfg)
	ro.Analysis = an
	if paths == nil {
		paths = []model.AttackPath{}
	}
	return server.IssuePageOptions{Risk: ro, Graph: g, Paths: paths, Analysis: an, PathRules: pathRulesFor(cfg)}, nil
}

func buildIssuePage(ctx context.Context, cfg *config.Config, st *store.Store, id string) (*server.IssuePage, error) {
	o, err := issuePageOptions(ctx, cfg, st)
	if err != nil {
		return nil, err
	}
	return server.BuildIssuePage(st, id, o)
}

func shortDate(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02")
}

// printIssuePage renders the Issue page as text (the same record as GET /api/issues/{id}).
func printIssuePage(w io.Writer, pg *server.IssuePage) {
	is := pg.Issue
	fmt.Fprintf(w, "Issue %s (%s)\n  title:     %s\n  severity:  %s\n  state:     %s\n  resource:  %s\n  account:   %s/%s\n  first/last seen: %s / %s\n",
		is.ID, is.Kind, firstNonEmpty(is.Title, is.CanonicalID), is.Severity, is.State, is.ResourceID, is.Provider, is.Account,
		is.FirstSeen.Format(time.RFC3339), is.LastSeen.Format(time.RFC3339))
	if is.Kind == model.IssuePath {
		fmt.Fprintf(w, "  entry:     %s\n  anchor:    %s\n  rule:      %s\n  paths:     %d hop variant(s)\n", is.EntryID, is.AnchorID, is.RuleID, len(pg.Paths))
		if is.ToxicCombination != "" {
			fmt.Fprintf(w, "  toxic:     %s\n", is.ToxicCombination)
		}
	}
	// Score and confidence.
	sc := pg.Score
	fmt.Fprintf(w, "  score:     %.1f (band %s, %s score, version %s)\n", sc.Score, firstNonEmpty(sc.Band, "—"), sc.Kind, sc.Version)
	if sc.Note != "" {
		fmt.Fprintf(w, "             %s\n", sc.Note)
	}
	if pg.ScoreHistory.Line != "" {
		fmt.Fprintf(w, "  score journey: %s\n", pg.ScoreHistory.Line)
	} else {
		fmt.Fprintln(w, "  score journey: no scored scan recorded yet (each scan from now on adds a point)")
	}
	fmt.Fprintf(w, "  confidence: %s (%.2f) — %s\n", pg.Confidence.Label, pg.Confidence.Value, pg.Confidence.Reason)
	// Owner / SLA (governance assignment stored on the Issue).
	o := pg.Owner
	src := o.Source
	if o.Rule != "" {
		src += ", rule " + o.Rule
	}
	fmt.Fprintf(w, "  owner:     %s (%s)\n", firstNonEmpty(o.Owner, "unassigned"), src)
	if o.Why != "" {
		fmt.Fprintf(w, "  why:       %s\n", o.Why)
	}
	if o.DueAt != nil {
		due := "due " + shortDate(o.DueAt)
		if o.Overdue {
			due += " OVERDUE"
		}
		if o.GraceUntil != nil {
			due += ", grace until " + shortDate(o.GraceUntil)
			if o.PastGrace {
				due += " (PAST GRACE)"
			}
		}
		fmt.Fprintf(w, "  SLA:       %d day(s), %s\n", o.SLADays, due)
	} else {
		fmt.Fprintln(w, "  SLA:       none")
	}
	// Suppression.
	if s := pg.Suppression; s.Suppressed || s.Reason != "" {
		state := "suppressed"
		if s.Expired {
			state = "suppression expired"
		} else if !s.Suppressed {
			state = "previously suppressed"
		}
		fmt.Fprintf(w, "  suppression: %s — %s (expires %s, approved by %s)\n", state, s.Reason, shortDate(s.ExpiresAt), firstNonEmpty(s.ApprovedBy, "—"))
	} else {
		fmt.Fprintln(w, "  suppression: none")
	}
	// Tickets: the Issue's own ticket first, then per-finding alerts.
	if t := pg.Ticket; t != nil {
		fmt.Fprintf(w, "  ticket:    %s %s %s (%s)\n", t.Channel, t.Ref, t.URL, firstNonEmpty(t.State, "open"))
	} else if len(pg.Tickets) == 0 {
		fmt.Fprintln(w, "  ticket:    none recorded (cloud-posture alert --to jira|github records one)")
	}
	for _, t := range pg.Tickets {
		fmt.Fprintf(w, "  ticket:    %s %s (finding %s, sent %s)\n", t.Channel, firstNonEmpty(t.URL, t.Ref), t.FindingID, firstNonEmpty(t.SentAt, "—"))
	}

	if x := sc.Explanation; x != nil {
		fmt.Fprintf(w, "\nWhy this score (finding %s: %.1f %s; base %.1f — %s) — factors:\n", sc.FindingID, sc.FindingRisk, sc.FindingBand, x.Base, x.BaseReason)
		for _, f := range x.Factors {
			if f.Status != risk.StatusScored || f.Multiplier == 1 {
				continue
			}
			fmt.Fprintf(w, "  ×%.2f  %-14s %s\n", f.Multiplier, f.Name, f.Reason)
		}
		if len(x.Missing) > 0 {
			fmt.Fprintf(w, "  not scored: %s\n", strings.Join(x.Missing, "; "))
		}
	}

	if len(pg.Hops) > 0 {
		title := "Hops (best path"
		if is.Kind != model.IssuePath {
			title = "Hops (top attack path through this resource"
		}
		fmt.Fprintf(w, "\n%s, %.1f):\n", title, pg.Paths[0].Score)
		for _, h := range pg.Hops {
			conf := ""
			if h.Confidence != "" {
				conf = " [" + h.Confidence + "]"
			}
			fmt.Fprintf(w, "  %d. (%s) %s%s\n     because: %s\n", h.Stage, h.Relation, h.Summary, conf, h.Because)
		}
	}
	if len(pg.Paths) > 0 {
		if is.Kind == model.IssuePath {
			fmt.Fprintf(w, "\nHop variants (%d):\n", len(pg.Paths))
		} else {
			fmt.Fprintf(w, "\nAttack paths through this resource (%d):\n", len(pg.Paths))
		}
		for i, p := range pg.Paths {
			if i >= 10 {
				fmt.Fprintf(w, "  … %d more\n", len(pg.Paths)-10)
				break
			}
			fmt.Fprintf(w, "  %.1f %-8s %s via %s  [issue %s]\n", p.Score, p.Band, firstNonEmpty(p.Title, p.Name), firstNonEmpty(p.Via, "—"), p.IssueID)
		}
	}
	if len(pg.Linked) > 0 {
		if is.Kind == model.IssuePath {
			fmt.Fprintf(w, "\nEvidence Issues on this path (%d):\n", len(pg.Linked))
		} else {
			fmt.Fprintf(w, "\nLinked Issues (%d):\n", len(pg.Linked))
		}
		for _, l := range pg.Linked {
			extra := ""
			if l.Kind == model.IssuePath {
				extra = fmt.Sprintf(" %.1f %s", l.Score, l.Band)
			}
			fmt.Fprintf(w, "  %s  %-8s %-11s %-9s %s%s (%s)\n", l.ID, l.Severity, l.Kind, l.State, l.Title, extra, l.Relation)
		}
	}
	fmt.Fprintf(w, "\nEvidence (%d finding(s)):\n", len(pg.Findings))
	for _, f := range pg.Findings {
		fmt.Fprintf(w, "  - %s %s %s on %s (%s)\n", f.Status, f.Severity, f.CanonicalID, firstNonEmpty(f.Resource.Name, f.Resource.ID, f.File), f.Source)
	}
	if len(pg.Fixes) == 0 {
		fmt.Fprintln(w, "\nFix: no open evidence finding to fix.")
	}
	for i, fx := range pg.Fixes {
		if i == 0 {
			fmt.Fprintln(w, "\nFix")
		}
		printFixPlan(w, fx, "  ")
	}
	if len(pg.Timeline) > 0 {
		fmt.Fprintln(w, "\nTimeline:")
		for _, e := range pg.Timeline {
			fmt.Fprintf(w, "  %s  %-20s %s\n", e.At.UTC().Format(time.RFC3339), e.Event, e.Detail)
		}
	}
}

// printFixPlan prints one fix's template, sidecar metadata and numbered phases
// (prerequisite → snapshot → fix → verify → rollback).
func printFixPlan(w io.Writer, fx server.PageFix, indent string) {
	tag := ""
	if fx.Generic {
		tag = " (generic stub — no typed template yet)"
	}
	fmt.Fprintf(w, "%s%s on %s — template %s (%s)%s\n%s  write it: %s\n", indent, fx.CanonicalID, fx.Resource, fx.Template, fx.Format, tag, indent, fx.Command)
	if m := fx.Metadata; m != nil {
		fmt.Fprintf(w, "%s  effort %s · confidence %s · mitigation: %s\n", indent, m.Effort, m.Confidence, m.Mitigation)
	}
	for i, ph := range fx.Phases {
		fmt.Fprintf(w, "%s  %d. %s\n", indent, i+1, ph.Name)
		for _, s := range ph.Steps {
			fmt.Fprintf(w, "%s       %s\n", indent, s)
		}
	}
}

// parseExpiry accepts RFC 3339, YYYY-MM-DD (end of that day, UTC) or a duration in days
// ("30d") or Go syntax ("720h") from now.
func parseExpiry(v string, now time.Time) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t.Add(24*time.Hour - time.Second), nil
	}
	if strings.HasSuffix(v, "d") {
		var n int
		if _, err := fmt.Sscanf(v, "%dd", &n); err == nil && n > 0 {
			return now.Add(time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return now.Add(d), nil
	}
	return time.Time{}, fmt.Errorf("--expires %q: use RFC 3339, YYYY-MM-DD, Nd or a Go duration", v)
}

var issuesSuppressCmd = &cobra.Command{
	Use:   "suppress <id>",
	Short: "Accept the risk of one Issue until an expiry (reason and expiry required); it reopens afterwards if still observed",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := loadConfig(); err != nil {
			return err
		}
		now := time.Now().UTC()
		exp, err := parseExpiry(issuesFlags.expires, now)
		if err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		id := st.ResolveIssueID(args[0]) // an id from before the keyed-id migration still resolves
		if err := st.SuppressIssue(id, store.Suppression{Reason: issuesFlags.reason, ExpiresAt: exp, ApprovedBy: issuesFlags.approvedBy}, now); err != nil {
			var se *store.SuppressionError
			if errors.As(err, &se) {
				return fmt.Errorf("%s (--reason and --expires are required; the expiry must be in the future)", err)
			}
			return err
		}
		fmt.Printf("suppressed %s until %s\n", id, exp.UTC().Format(time.RFC3339))
		return nil
	},
}

var issuesHistoryCmd = &cobra.Command{
	Use:   "history <id>",
	Short: "State transitions and hop-list changes of a path Issue, oldest first",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := loadConfig(); err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		is, err := findIssue(st, args[0])
		if err != nil {
			return err
		}
		h, err := st.PathIssueHistory(is.ID)
		if err != nil {
			return err
		}
		if issuesFlags.json {
			if h == nil {
				h = []store.PathIssueHistoryEntry{}
			}
			return output.JSON(os.Stdout, h)
		}
		if len(h) == 0 {
			fmt.Println("No Issue-level history (path Issues record every transition; finding Issues record suppression, pending, verification and regressions).")
			return nil
		}
		for _, e := range h {
			extra := ""
			if e.RegressedAfterVerify {
				extra += "  REGRESSED after verify"
			}
			if e.Detail != "" {
				extra += "  (" + e.Detail + ")"
			}
			fmt.Printf("%s  %-10s score %4.1f  scan %s  hops %s%s\n", e.At.Format(time.RFC3339), e.State, e.Score, firstNonEmpty(e.ScanID, "—"), firstNonEmpty(e.SecondaryKey, "—"), extra)
		}
		return nil
	},
}

var issuesMarkPendingCmd = &cobra.Command{
	Use:   "mark-pending <id>",
	Short: "Mark an open Issue pending_verification (a fix was merged / applied); the next scan or `verify` settles it",
	Long: `Moves an open or reopened Issue to pending_verification. It leaves the open queue (not overdue)
until the next scan settles it — still observed: back to open; gone: resolved — or
` + "`cloud-posture verify <id>`" + ` confirms it (verified_fixed).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := loadConfig(); err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		is, err := findIssueByID(st, args[0])
		if err != nil {
			return err
		}
		by := strings.TrimSpace(issuesFlags.pendingBy)
		for _, c := range by {
			if c < 0x20 || c == 0x7f {
				return fmt.Errorf("--by contains control characters")
			}
		}
		if by == "" {
			by = "cli"
		}
		if err := st.MarkPendingVerification(is.ID, by, time.Now().UTC()); err != nil {
			return err
		}
		fmt.Printf("%s → pending_verification (%s); settle it with: cloud-posture verify %s\n", is.ID, by, is.ID)
		return nil
	},
}

var issuesMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Governance metrics from the lifecycle history: MTTR by severity, on-time rate, open and overdue by owner",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := loadConfig(); err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		m, err := server.BuildGovernanceMetrics(st, time.Now().UTC())
		if err != nil {
			return err
		}
		own, _ := storedOwnership(st)
		if issuesFlags.json {
			return output.JSON(os.Stdout, struct {
				*server.GovernanceMetrics
				Ownership ownershipCounts `json:"ownership"`
			}{m, own})
		}
		printGovernanceMetrics(os.Stdout, m)
		fmt.Fprintf(os.Stdout, "\n%s\n", own.Text())
		return nil
	},
}

func init() {
	f := issuesCmd.PersistentFlags()
	f.BoolVar(&issuesFlags.json, "json", false, "JSON output")
	lf := issuesCmd.Flags()
	lf.StringVar(&issuesFlags.kind, "kind", "", "single|combination|path")
	lf.StringVar(&issuesFlags.state, "state", "open", "open|new|reopened|pending|verified|resolved|closed|suppressed|all")
	lf.StringVar(&issuesFlags.severity, "severity", "", "minimum severity (critical|high|medium|low|info)")
	lf.StringVar(&issuesFlags.band, "band", "", "path score band: Critical|High|Medium|Low")
	lf.StringVar(&issuesFlags.provider, "provider", "", "provider")
	lf.StringVar(&issuesFlags.account, "account", "", "account")
	lf.IntVar(&issuesFlags.limit, "limit", 0, "maximum rows (0 = all)")
	sf := issuesSuppressCmd.Flags()
	sf.StringVar(&issuesFlags.reason, "reason", "", "why the risk is accepted (required)")
	sf.StringVar(&issuesFlags.expires, "expires", "", "expiry: RFC 3339, YYYY-MM-DD, Nd or a Go duration (required)")
	sf.StringVar(&issuesFlags.approvedBy, "approved-by", "", "who approved the exception")
	lf.StringVar(&issuesFlags.owner, "owner", "", "only Issues of this governance owner (\"(unassigned)\" for none)")
	lf.BoolVar(&issuesFlags.overdue, "overdue", false, "only open Issues past their governance due date (suppressed Issues are never overdue)")
	issuesMarkPendingCmd.Flags().StringVar(&issuesFlags.pendingBy, "by", "", "what applied the fix: a PR URL, ticket key or name (recorded on the Issue)")
	issuesTrendCmd.Flags().StringVar(&issuesFlags.since, "since", "90d", "lookback: Nd, Nw, Nm (months), Ny, a duration (36h), YYYY-MM-DD, RFC 3339 or all")
	ef := issuesExportCmd.Flags()
	ef.StringVar(&issuesFlags.exportTo, "to", "", "destination: vanta")
	ef.BoolVar(&issuesFlags.exportDryRun, "dry-run", false, "send nothing; print what the full-state sync would add and delete")
	ef.BoolVar(&issuesFlags.exportAllowEmpty, "allow-empty", false, "allow an empty set (deletes every nimbus resource in Vanta)")
	ef.BoolVar(&issuesFlags.exportRecipe, "recipe", false, "print the Vanta custom test recipe and exit")
	ef.StringVar(&issuesFlags.exportURL, "url", "", "dashboard base URL each resource links to (externalUrl), e.g. the `serve` address")
	issuesCmd.AddCommand(issuesShowCmd, issuesSuppressCmd, issuesHistoryCmd, issuesMetricsCmd, issuesMarkPendingCmd, issuesTrendCmd, issuesExportCmd)
	root.AddCommand(issuesCmd)
}

// ---------------------------------------------------------------- issues trend (r5 #11)

// parseTrendSince is store.ParseSince with the flag named in the error.
func parseTrendSince(v string, now time.Time) (time.Time, error) {
	t, err := store.ParseSince(v, now)
	if err != nil {
		return time.Time{}, fmt.Errorf("--since: %w", err)
	}
	return t, nil
}

var issuesTrendCmd = &cobra.Command{
	Use:   "trend",
	Short: "Score trend over a lookback window (--since 90d): per scan, scored open Issues by band, max and summed score, plus the scan cadence",
	Long: `trend reads issue_score_history (one point per scored active Issue per scan) and prints, for every
scan in the window, how many Issues were open and scored, how many were Critical / High / Medium /
Low, the highest score and the summed score, with a sparkline of the summed score and the Issue
lifecycle counts of each scan (new / resolved / verified fixed). The first line states the history
the database holds ("history since <date>, N scans") so a short window is never mistaken for a
quiet estate. One Issue's own journey is in ` + "`cloud-posture issues show <id>`" + ` ("score journey").`,
	Example: `  cloud-posture issues trend                 # last 90 days
  cloud-posture issues trend --since 12w
  cloud-posture issues trend --since 2026-07-01 --json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		since, err := parseTrendSince(issuesFlags.since, time.Now().UTC())
		if err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		rows, err := st.ScoreTrend(since)
		if err != nil {
			return err
		}
		span, err := st.ScoreHistorySpan()
		if err != nil {
			return err
		}
		life := map[string]*store.ScanTrend{}
		if tr, err := st.ScanTrends(1000); err == nil {
			for _, r := range tr {
				life[r.ScanID] = r.Trend
			}
		}
		if rows == nil {
			rows = []store.ScoreTrendRow{}
		}
		if issuesFlags.json {
			doc := map[string]any{"window": issuesFlags.since, "history": span, "cadence": span.Text(), "scans": rows}
			if !since.IsZero() {
				doc["since"] = since.Format(time.RFC3339)
			}
			return output.JSON(os.Stdout, doc)
		}
		printScoreTrend(os.Stdout, issuesFlags.since, since, span, rows, life)
		return nil
	},
}

func printScoreTrend(w io.Writer, window string, since time.Time, span store.HistorySpan, rows []store.ScoreTrendRow, life map[string]*store.ScanTrend) {
	from := "all history"
	if !since.IsZero() {
		from = "since " + since.Format("2006-01-02") + " (" + window + ")"
	}
	fmt.Fprintf(w, "Score trend, %s — %s\n", from, span.Text())
	if len(rows) == 0 {
		fmt.Fprintln(w, "no scan in this window")
		return
	}
	var sums []float64
	for _, r := range rows {
		sums = append(sums, r.Sum)
	}
	// The summed-score sparkline is relative to the window's peak (sums exceed 10).
	peak := 0.0
	for _, v := range sums {
		if v > peak {
			peak = v
		}
	}
	norm := make([]float64, len(sums))
	for i, v := range sums {
		if peak > 0 {
			norm[i] = v / peak * 10
		}
	}
	first, last := rows[0], rows[len(rows)-1]
	fmt.Fprintf(w, "summed score %s %.1f → %.1f over %d scan(s); open scored Issues %d → %d; Critical %d → %d\n\n",
		store.Sparkline(norm), first.Sum, last.Sum, len(rows), first.Issues, last.Issues, first.Critical, last.Critical)
	fmt.Fprintf(w, "%-20s  %-22s %6s %5s %5s %5s %5s %5s %7s  %s\n", "FINISHED", "SCAN", "ISSUES", "CRIT", "HIGH", "MED", "LOW", "MAX", "SUM", "LIFECYCLE")
	for _, r := range rows {
		lc := "—"
		if t := life[r.ScanID]; t != nil {
			lc = fmt.Sprintf("+%d new, %d resolved, %d verified fixed, %d reopened", t.New, t.Resolved, t.VerifiedFixed, t.Reopened)
		}
		scan := r.ScanID
		if len(scan) > 22 {
			scan = scan[:21] + "…"
		}
		fmt.Fprintf(w, "%-20s  %-22s %6d %5d %5d %5d %5d %5.1f %7.1f  %s\n", r.At.UTC().Format("2006-01-02 15:04"), scan, r.Issues, r.Critical, r.High, r.Medium, r.Low, r.Max, r.Sum, lc)
	}
}

// doctorScoreCadence is the cadence statement for `doctor` ("history since <date>, N scans"):
// how far back trend and score journeys can look. A database without scans says so.
func doctorScoreCadence(dbPath string, add func(status, name, detail string)) {
	st, err := store.Open(dbPath)
	if err != nil {
		return
	}
	defer st.Close()
	sp, err := st.ScoreHistorySpan()
	if err != nil {
		return
	}
	status := docOK
	if sp.Scans == 0 {
		status = docWarn
	}
	add(status, "history", sp.Text())
}

// ---------------------------------------------------------------- issues export (r5 #9)

var issuesExportCmd = &cobra.Command{
	Use:   "export --to vanta",
	Short: "Export nimbus resources to a GRC tool: Vanta custom resources (full-state sync), with a dry run and the custom test recipe",
	Long: `export --to vanta pushes one Vanta custom resource per cloud resource nimbus evaluated, with flat
properties (open_issues, open_critical, open_high, failing_checks, passing_checks, on_attack_path,
max_path_score_x10, nimbus_pass, last_seen, provider, account, resource_type), through a Vanta
private integration (VANTA_CLIENT_ID, VANTA_CLIENT_SECRET, VANTA_RESOURCE_ID).

Vanta's resources API is full-state: every sync carries the complete set and a resource omitted
from it is deleted in Vanta. nimbus therefore sends one PUT with every resource, refuses an empty
set (--allow-empty overrides) or one over the cap, and --dry-run prints what the sync would add
and delete against the last successful sync (kept in the state directory). --recipe prints the
Vanta custom test that turns the resources into passing / failing tests.`,
	Example: `  cloud-posture issues export --to vanta --recipe
  cloud-posture issues export --to vanta --dry-run
  cloud-posture issues export --to vanta --url https://nimbus.internal.example.com`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !strings.EqualFold(issuesFlags.exportTo, "vanta") {
			return fmt.Errorf("--to: only vanta is supported (got %q)", issuesFlags.exportTo)
		}
		if issuesFlags.exportRecipe {
			fmt.Println(integrations.VantaCustomTestRecipe())
			return nil
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		fs, err := st.Findings(store.Filter{})
		if err != nil {
			return err
		}
		is, err := st.Issues(store.IssueFilter{})
		if err != nil {
			return err
		}
		rs := integrations.BuildVantaResources(fs, is, integrations.VantaBuildOptions{ExternalURLBase: issuesFlags.exportURL})
		v := integrations.NewVantaFromEnv()
		statePath := filepath.Join(stateDir(), "vanta-"+safeName(firstNonEmpty(v.ResourceID, "default"))+".json")
		var prev []string
		if b, err := os.ReadFile(statePath); err == nil {
			_ = json.Unmarshal(b, &prev)
		}
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		res, err := v.Sync(ctx, rs, integrations.VantaSyncOptions{DryRun: issuesFlags.exportDryRun, Previous: prev, AllowEmpty: issuesFlags.exportAllowEmpty})
		if err != nil {
			return err
		}
		if !res.DryRun {
			ids := make([]string, 0, len(rs))
			for _, r := range rs {
				ids = append(ids, r.UniqueID)
			}
			if b, err := json.Marshal(ids); err == nil {
				_ = os.MkdirAll(stateDir(), 0o700)
				_ = os.WriteFile(statePath, b, 0o600)
			}
		}
		if issuesFlags.json {
			return output.JSON(os.Stdout, res)
		}
		fmt.Println(res.Text())
		if len(res.Removed) > 0 {
			fmt.Printf("  omitted since the last sync (Vanta %s them): %s\n", map[bool]string{true: "would delete", false: "deleted"}[res.DryRun], termSafe(strings.Join(res.Removed, ", ")))
		}
		return nil
	},
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}
