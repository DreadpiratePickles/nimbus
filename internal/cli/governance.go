package cli

// Governance wiring (integration pass 4; docs/governance.md "What the integration pass wires").
// After every Issue rebuild (scan, ingest, prioritize) each Issue is resolved — rules, tags,
// CODEOWNERS under the IaC root, account owner, default — with a fresh SLA clock per open
// episode, and the assignment is persisted on the issues row (store migration 7). Every output
// (CLI, API, dashboard, digest, tickets) reads that one due date.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/governance"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// coRoot is one directory whose CODEOWNERS resolves IaC paths relative to it.
type coRoot struct {
	dir string // absolute
	res *governance.Resolver
}

// govResolver resolves subjects with the CODEOWNERS of the IaC root the finding's file lives
// under: IaC findings carry a path relative to the scanned root, so the file is located under
// each configured IaC root and matched against the first CODEOWNERS whose directory contains
// it; when the file cannot be located the path is matched as is against the first CODEOWNERS.
type govResolver struct {
	plain    *governance.Resolver // no CODEOWNERS
	iacRoots []string             // absolute
	co       []coRoot
}

// iacRootsFor are the IaC roots of this run: --iac, else scan.iac_paths, then the working
// directory (a repository-level CODEOWNERS). A file root contributes its directory.
func iacRootsFor(cfg *config.Config) []string {
	var roots []string
	roots = append(roots, scanFlags.iac...)
	if len(roots) == 0 && cfg != nil {
		roots = append(roots, cfg.Scan.IaCPaths...)
	}
	roots = append(roots, ".")
	seen := map[string]bool{}
	var out []string
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		if fi, err := os.Stat(abs); err == nil && !fi.IsDir() {
			abs = filepath.Dir(abs)
		}
		if !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	return out
}

func newGovResolver(cfg *config.Config) *govResolver {
	var g config.Governance
	if cfg != nil {
		g = cfg.Governance
	}
	gr := &govResolver{plain: governance.NewResolver(g, nil), iacRoots: iacRootsFor(cfg)}
	explicitTried := false
	for _, root := range gr.iacRoots {
		explicit := g.CodeownersFile
		if explicit != "" && filepath.IsAbs(explicit) {
			if explicitTried {
				continue
			}
			explicitTried = true
		}
		co, err := governance.LoadCodeowners(root, explicit)
		if err != nil {
			if !os.IsNotExist(err) {
				logf("governance: CODEOWNERS under %s: %v", root, err)
			}
			continue
		}
		if co == nil {
			continue
		}
		for _, e := range co.Errors {
			logf("governance: %s: %v (line skipped)", co.Path, e)
		}
		gr.co = append(gr.co, coRoot{dir: root, res: governance.NewResolver(g, co)})
	}
	return gr
}

// Resolve picks the CODEOWNERS for s.IaCPath and resolves.
func (gr *govResolver) Resolve(s governance.Subject) governance.Assignment {
	if s.IaCPath == "" || len(gr.co) == 0 {
		return gr.plain.Resolve(s)
	}
	for _, ir := range gr.iacRoots {
		abs := filepath.Join(ir, filepath.FromSlash(s.IaCPath))
		if _, err := os.Stat(abs); err != nil {
			continue
		}
		for _, c := range gr.co {
			if rel, err := filepath.Rel(c.dir, abs); err == nil && !strings.HasPrefix(rel, "..") {
				s.IaCPath = filepath.ToSlash(rel)
				return c.res.Resolve(s)
			}
		}
	}
	return gr.co[0].res.Resolve(s)
}

// accountOwner is accounts.<name>.owner of the configured account an Issue belongs to:
// matched by name, or by the account's identity (AWS account id in role_arn, subscription,
// project, tenant, org, domain, kube context).
func accountOwner(cfg *config.Config, provider, account string) string {
	if cfg == nil || account == "" {
		return ""
	}
	names := make([]string, 0, len(cfg.Accounts))
	for n := range cfg.Accounts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a := cfg.Accounts[n]
		if a == nil || strings.TrimSpace(a.Owner) == "" {
			continue
		}
		if a.Provider != "" && provider != "" && !strings.EqualFold(a.Provider, provider) && !strings.EqualFold(account, n) {
			continue
		}
		ids := []string{n, a.SubscriptionID, a.ProjectID, a.TenantID, a.Org, a.KubeContext, strings.TrimPrefix(strings.TrimPrefix(a.Domain, "https://"), "http://")}
		if parts := strings.Split(a.RoleARN, ":"); len(parts) > 4 {
			ids = append(ids, parts[4])
		}
		for _, id := range ids {
			if id != "" && strings.EqualFold(strings.TrimRight(id, "/"), account) {
				return strings.TrimSpace(a.Owner)
			}
		}
	}
	return ""
}

// pathSubject fills a path Issue's subject from its anchor node: name, owner/team tags.
func pathSubject(is model.Issue, g *graph.Graph) governance.Subject {
	s := governance.SubjectFromIssue(is, nil)
	if g == nil {
		return s
	}
	n, ok := g.Node(firstNonEmpty(is.AnchorID, is.ResourceID))
	if !ok {
		return s
	}
	if n.Name != "" {
		s.Name = n.Name
	}
	tags := map[string]string{}
	if t, ok := n.Attributes["tags"].(map[string]any); ok {
		for k, v := range t {
			tags[k] = fmt.Sprint(v)
		}
	}
	if n.Owner != "" {
		if _, ok := tags["owner"]; !ok {
			tags["owner"] = n.Owner
		}
	}
	if len(tags) > 0 {
		s.Tags = tags
	}
	return s
}

// applyGovernance resolves every stored Issue and persists the assignment (re-run on every
// scan/ingest/prioritize so rule edits apply). g may be nil (loaded from the store).
func applyGovernance(cfg *config.Config, st *store.Store, g *graph.Graph) error {
	issues, err := st.Issues(store.IssueFilter{})
	if err != nil {
		return err
	}
	if len(issues) == 0 {
		return nil
	}
	events, err := governance.CollectEvents(st, nil)
	if err != nil {
		return err
	}
	if g == nil {
		if lg, err := loadGraph(st); err == nil {
			g = lg
		}
	}
	gr := newGovResolver(cfg)
	rows := make([]store.IssueGovernance, 0, len(issues))
	for _, is := range issues {
		s := issueSubject(cfg, st, g, events, is)
		a := gr.Resolve(s)
		row := store.IssueGovernance{ID: is.ID, Owner: a.Owner, Source: a.Source, RuleID: a.RuleID, Why: a.Why, SLADays: a.SLADays}
		if !a.DueAt.IsZero() {
			d, gu := a.DueAt.UTC(), a.GraceUntil.UTC()
			row.DueAt, row.GraceUntil = &d, &gu
		}
		rows = append(rows, row)
	}
	return st.SetIssueGovernance(rows)
}

// issueSubject is the governance subject of one stored Issue: a path Issue's anchor node, or
// a single/combination Issue's evidence findings, with the current episode's opened-at and
// the account owner.
func issueSubject(cfg *config.Config, st *store.Store, g *graph.Graph, events []governance.LifecycleEvent, is model.Issue) governance.Subject {
	var s governance.Subject
	if is.Kind == model.IssuePath {
		s = pathSubject(is, g)
	} else {
		var ev []model.Finding
		for _, id := range is.FindingIDs {
			if f, err := st.Finding(id); err == nil {
				ev = append(ev, *f)
			}
		}
		s = governance.SubjectFromIssue(is, ev)
	}
	if start := governance.CurrentEpisodeStart(events, is.ID); !start.IsZero() {
		s.OpenedAt = start
	}
	s.AccountOwner = accountOwner(cfg, is.Provider, is.Account)
	return s
}

// governIssueViews is rebuildIssueViews followed by governance resolution.
func governIssueViews(cfg *config.Config, st *store.Store, g *graph.Graph) {
	if err := applyGovernance(cfg, st, g); err != nil {
		logf("governance: %v", err)
	}
}

// governStoredRanked fills ranked's owner / SLA / due from the stored Issues.
func governStoredRanked(st *store.Store, ranked []risk.Ranked) {
	if st == nil {
		return
	}
	if is, err := st.Issues(store.IssueFilter{}); err == nil {
		server.GovernRanked(ranked, is)
	}
}

// governFindingRanked resolves ranked findings directly (no store: scan --no-store).
func governFindingRanked(cfg *config.Config, ranked []risk.Ranked) {
	gr := newGovResolver(cfg)
	for i := range ranked {
		r := &ranked[i]
		s := governance.SubjectFromFinding(r.Finding)
		s.AccountOwner = accountOwner(cfg, r.Finding.Provider, r.Finding.Account)
		a := gr.Resolve(s)
		r.Owner, r.SLADays, r.DueAt = a.Owner, a.SLADays, a.DueAt
	}
}

// ---------------------------------------------------------------- issues metrics

func fmtHours(h float64) string {
	switch {
	case h < 48:
		return fmt.Sprintf("%.1fh", h)
	default:
		return fmt.Sprintf("%.1fd", h/24)
	}
}

// printGovernanceMetrics renders server.GovernanceMetrics as text.
func printGovernanceMetrics(w io.Writer, m *server.GovernanceMetrics) {
	fmt.Fprintf(w, "Governance metrics (%s)\n\n", m.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "open %d · overdue %d · past grace %d · suppressed %d\n", m.Open, m.OpenPastDue, m.OpenPastGrace, m.Suppressed)
	rate := "—"
	if m.OnTime+m.Late > 0 {
		rate = fmt.Sprintf("%.0f%%", m.OnTimeRate*100)
	}
	fmt.Fprintf(w, "on-time rate %s (%d on time, %d late)\n", rate, m.OnTime, m.Late)
	if c := m.Closure; c != nil {
		fmt.Fprintf(w, "closure: verified fixed %d · resolved (not verified) %d · pending verification %d · verified share %.0f%%\n",
			c.VerifiedFixed, c.Resolved, c.PendingVerification, c.VerifiedShare*100)
		fmt.Fprintf(w, "regressions after verify: %d (open now: %d)\n", c.RegressionsAfterVerify, c.RegressedOpen)
	}
	fmt.Fprint(w, "\nMTTR by severity:\n")
	for _, sev := range []model.Severity{model.Critical, model.High, model.Medium, model.Low, model.Info} {
		n := m.ResolvedBySeverity[string(sev)]
		mttr := "—"
		if n > 0 {
			mttr = fmtHours(m.MTTRHoursBySeverity[string(sev)])
		}
		fmt.Fprintf(w, "  %-9s %-8s (%d resolved)\n", sev, mttr, n)
	}
	fmt.Fprintln(w, "\nopen / overdue by owner:")
	if len(m.Owners) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, o := range m.Owners {
		fmt.Fprintf(w, "  %-36s open %4d   overdue %4d\n", o.Owner, o.Open, o.Overdue)
	}
	fmt.Fprintln(w, "\noverdue by owner:")
	any := false
	for _, o := range m.Owners {
		if o.Overdue > 0 {
			any = true
			fmt.Fprintf(w, "  %-36s %d\n", o.Owner, o.Overdue)
		}
	}
	if !any {
		fmt.Fprintln(w, "  none")
	}
}

// ---------------------------------------------------------------- tickets and digests

// issueFixCommand is the command that fixes an Issue: the fix of its first evidence finding,
// or the Issue page for a path Issue (its fix is the cheapest cut, shown there).
func issueFixCommand(is model.Issue) string {
	if is.Kind != model.IssuePath && len(is.FindingIDs) > 0 {
		return "cloud-posture fix --id " + is.FindingIDs[0]
	}
	return "cloud-posture issues show " + is.ID
}

// alertableIssues drops kinds that are not tickets yet (reserved kinds) and, with
// --only-attack-paths, Issues that are not on a stored path.
func alertableIssues(issues []model.Issue, paths []model.AttackPath, onlyPaths bool) []model.Issue {
	onPath := map[string]bool{}
	for _, p := range paths {
		for _, f := range p.FindingIDs {
			onPath[f] = true
		}
		for _, st := range p.Steps {
			onPath[st.Resource] = true
		}
	}
	var out []model.Issue
	for _, is := range issues {
		switch is.Kind {
		case model.IssueSingle, model.IssueCombination, model.IssuePath:
		default:
			continue
		}
		if onlyPaths && is.Kind != model.IssuePath {
			hit := onPath[is.ResourceID]
			for _, f := range is.FindingIDs {
				hit = hit || onPath[f]
			}
			if !hit {
				continue
			}
		}
		out = append(out, is)
	}
	return out
}

// parseSince accepts a duration back from now ("168h", "7d") or a date / RFC 3339 time.
func parseSince(v string, now time.Time) (time.Time, error) {
	v = strings.TrimSpace(v)
	if strings.HasSuffix(v, "d") {
		var n int
		if _, err := fmt.Sscanf(v, "%dd", &n); err == nil && n > 0 {
			return now.Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("--since %q: use a duration (168h, 7d), YYYY-MM-DD or RFC 3339", v)
}

// digestLedgerPath is <db dir>/digest-ledger.json.
func digestLedgerPath(st *store.Store) string {
	return filepath.Join(filepath.Dir(st.Path()), "digest-ledger.json")
}
