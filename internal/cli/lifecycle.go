package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector"
	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// tagRoot records which IaC root a finding came from, so a scan of one root never
// resolves findings of another (store.TagScanRoot).
func tagRoot(f *model.Finding, root string) {
	if root == "" {
		return
	}
	if f.Tags == nil {
		f.Tags = map[string]string{}
	}
	f.Tags[store.TagScanRoot] = filepath.Clean(root)
}

// lifecycleScopes decides which scopes this scan re-examined in full: the scopes of
// what it observed plus the stored scopes under its declared targets (IaC roots and
// native accounts that ran), so a target whose last resource disappeared still has
// its findings resolved. A scope is only resolved by absence when nothing suggests the
// scan was partial: IaC scopes are skipped with --changed-only, and native-collector
// scopes are skipped for a provider whose collector reported denied / throttled /
// timed-out calls (absence is not a fix).
func lifecycleScopes(st *store.Store, all []model.Finding, opts scanOptions) (store.ApplyOptions, error) {
	scopes := store.ScopesOf(all)
	if st != nil && len(opts.Targets) > 0 {
		declared, err := st.ScopesForTargets(opts.Targets)
		if err != nil {
			return store.ApplyOptions{}, err
		}
		seen := map[store.Scope]bool{}
		for _, sc := range scopes {
			seen[sc] = true
		}
		for _, sc := range declared {
			if !seen[sc] {
				seen[sc] = true
				scopes = append(scopes, sc)
			}
		}
	}
	partial := map[string]bool{}
	for _, ce := range opts.CollectErrors {
		partial[ce.Provider] = true
	}
	var skip []store.Scope
	for _, sc := range scopes {
		if (opts.ChangedOnly && (sc.Root != "" || sc.Account == "iac")) || (sc.Source == core.Source && partial[sc.Provider]) {
			skip = append(skip, sc)
		}
	}
	return store.ApplyOptions{Scopes: scopes, SkipScopes: skip, SkipFiles: opts.SkipFiles}, nil
}

// rootScopedID qualifies a finding id by the absolute IaC root it was scanned under, so
// the same root-relative file under two roots (prod/a.tf, stg/a.tf) gives two findings.
func rootScopedID(id, root string) string {
	if root == "" || id == "" {
		return id
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = filepath.Clean(root)
	}
	sum := sha256.Sum256([]byte("iac-root:" + filepath.ToSlash(abs) + "|" + id))
	return hex.EncodeToString(sum[:16])
}

// nativeTargets declares every native-collector account whose run completed ("ok"
// and no partial errors); a failed or partial account is not a declared target.
func nativeTargets(specs []collector.AccountSpec, runs []model.ToolRun) []store.Target {
	okRun := map[string]bool{}
	for _, r := range runs {
		if strings.HasPrefix(r.Tool, "nimbus-") && r.Status == "ok" && r.Message == "" {
			okRun[r.Account] = true
		}
	}
	var out []store.Target
	for _, sp := range specs {
		if okRun[sp.Label()] {
			out = append(out, store.Target{Source: core.Source, Provider: model.NormalizeProvider(sp.Provider), AccountLabel: sp.Label()})
		}
	}
	return out
}

// coverageEntries turns tool runs (collectors, external scanners, plugins, ingested
// files) and collector errors into coverage rows.
func coverageEntries(runs []model.ToolRun, opts scanOptions) []store.CoverageEntry {
	var out []store.CoverageEntry
	for _, r := range runs {
		e := store.CoverageEntry{Provider: opts.Providers[r.Account], Account: r.Account, API: "tool:" + r.Tool, Reason: r.Message}
		if e.Provider == "" && strings.HasPrefix(r.Tool, "nimbus-") {
			e.Provider = strings.TrimPrefix(r.Tool, "nimbus-")
		}
		if r.Account == "iac" {
			e.Provider = model.ProviderIaC
		}
		switch r.Status {
		case "ok":
			e.Status = store.CoverageOK
		case "skipped":
			e.Status = store.CoverageSkipped
		default:
			e.Status = runFailureStatus(r.Message)
			if e.Reason == "" {
				e.Reason = r.Status
			}
		}
		out = append(out, e)
	}
	for _, ce := range opts.CollectErrors {
		reason := ce.Reason
		if reason == "" {
			reason = core.ClassifyReason(errors.New(ce.Message))
		}
		out = append(out, store.CoverageEntry{Provider: ce.Provider, Account: ce.Account, API: firstNonEmpty(ce.API, "collector"),
			Status: store.CoverageStatusForReason(reason), Reason: strings.TrimSpace(reason + ": " + ce.Message)})
	}
	return out
}

func runFailureStatus(msg string) string {
	l := strings.ToLower(msg)
	if strings.Contains(l, "timeout") || strings.Contains(l, "deadline exceeded") {
		return store.CoverageTimeout
	}
	return store.CoverageStatusForReason(core.ClassifyReason(errors.New(msg)))
}

// diffWriter keeps machine-readable stdout clean: with json/sarif output the diff goes to stderr.
func diffWriter(format, outFile string) io.Writer {
	if outFile == "" && machineFormat(format) {
		return os.Stderr
	}
	return os.Stdout
}

// machineFormat reports an -o format whose stdout must stay parseable (no human text mixed in).
func machineFormat(format string) bool {
	switch format {
	case "json", "sarif", "ocsf", "asff", "gitlab", "junit", "csv":
		return true
	}
	return false
}

// printDiff prints the scan's new / resolved / reopened counts and ids.
func printDiff(w io.Writer, res *scanResult) {
	d := res.Diff
	if d == nil {
		fmt.Fprintln(w, "\nDiff: unavailable (results were not stored)")
		return
	}
	fmt.Fprintf(w, "\nDiff vs earlier scans (scan %s): %d new, %d resolved, %d reopened findings\n", d.ScanID, len(d.New), len(d.Resolved), len(d.Reopened))
	if res.Headline != nil {
		fmt.Fprintf(w, "Now: %s\n", res.Headline.Text())
	}
	if res.Trend != nil {
		fmt.Fprintln(w, res.Trend.Text())
	}
	for _, g := range []struct {
		label string
		ids   []string
	}{{"new", d.New}, {"resolved", d.Resolved}, {"reopened", d.Reopened}} {
		for _, id := range g.ids {
			f, ok := res.DiffFindings[id]
			if !ok {
				fmt.Fprintf(w, "  %-9s %s\n", g.label, id)
				continue
			}
			fmt.Fprintf(w, "  %-9s %s  %-8s %s on %s (%s/%s, %s)\n", g.label, id, f.Severity, f.CanonicalID, firstNonEmpty(f.Resource.Name, f.Resource.ID, f.File), f.Provider, f.Account, f.Source)
		}
	}
	printPathIssueDiff(w, res)
	printVerifiedDiff(w, res)
}

// diffRescore is one path Issue whose score / band changed in this scan (--diff, --diff-json).
type diffRescore struct {
	ID       string  `json:"id"`
	Title    string  `json:"title,omitempty"`
	OldScore float64 `json:"old_score"`
	OldBand  string  `json:"old_band"`
	NewScore float64 `json:"new_score"`
	NewBand  string  `json:"new_band"`
}

// diffVerified is one Issue verified-fixed (cloud-posture verify) since the previous scan.
type diffVerified struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind,omitempty"`
	Title      string    `json:"title,omitempty"`
	VerifiedAt time.Time `json:"verified_at"`
	VerifiedBy string    `json:"verified_by,omitempty"`
	State      string    `json:"state,omitempty"` // the Issue's state now (a later scan may have moved it)
}

// diffExtras reads, from the store the scan wrote, the path Issues rescored by this scan (not
// opened / reopened by it) and the Issues verified-fixed since the previous scan. Both are
// empty when the results were not stored.
func diffExtras(res *scanResult) ([]diffRescore, []diffVerified) {
	if res.Diff == nil || res.PathIssues == nil {
		return nil, nil
	}
	st, err := openStore()
	if err != nil {
		return nil, nil
	}
	defer st.Close()
	byID := map[string]model.Issue{}
	for _, is := range res.Issues {
		byID[is.ID] = is
	}
	if len(byID) == 0 {
		if all, err := st.Issues(store.IssueFilter{}); err == nil {
			for _, is := range all {
				byID[is.ID] = is
			}
		}
	}
	var rescored []diffRescore
	if ch, err := st.LatestPathScoreChanges(); err == nil {
		skip := map[string]bool{}
		for _, id := range append(append([]string{}, res.PathIssues.OpenedIDs...), res.PathIssues.ReopenedIDs...) {
			skip[id] = true
		}
		for _, id := range res.PathIssues.IDs {
			c, ok := ch[id]
			if !ok || skip[id] {
				continue
			}
			rescored = append(rescored, diffRescore{ID: id, Title: byID[id].Title, OldScore: c.OldScore, OldBand: c.OldBand, NewScore: c.NewScore, NewBand: c.NewBand})
		}
	}
	var verified []diffVerified
	if prev, err := st.PreviousScanFinished(res.Diff.ScanID); err == nil {
		if vs, err := st.VerificationsBetween(prev, time.Now().UTC().Add(time.Minute), store.VerifyFixed); err == nil {
			seen := map[string]bool{}
			for _, v := range vs {
				if seen[v.IssueID] {
					continue
				}
				seen[v.IssueID] = true
				is := byID[v.IssueID]
				verified = append(verified, diffVerified{ID: v.IssueID, Kind: is.Kind, Title: issueLabel(is), VerifiedAt: v.At, VerifiedBy: v.VerifiedBy, State: is.State})
			}
		}
	}
	return rescored, verified
}

// printVerifiedDiff prints the Issues `verify` closed as verified-fixed since the previous scan.
func printVerifiedDiff(w io.Writer, res *scanResult) {
	_, verified := diffExtras(res)
	if len(verified) == 0 {
		return
	}
	fmt.Fprintf(w, "\nVerified fixed since the previous scan: %d\n", len(verified))
	for _, v := range verified {
		fmt.Fprintf(w, "  %-14s %s  %-11s %s (verified_by %s, %s)\n", "verified-fixed", v.ID, v.Kind, v.Title, firstNonEmpty(v.VerifiedBy, "—"), v.VerifiedAt.Format(time.RFC3339))
	}
}

// printPathIssueDiff prints the path-Issue transitions of the scan (opened / reopened /
// resolved), each with its band, score and title.
func printPathIssueDiff(w io.Writer, res *scanResult) {
	p := res.PathIssues
	if p == nil {
		return
	}
	rescored, _ := diffExtras(res)
	fmt.Fprintf(w, "\nPath Issues: %d opened, %d reopened, %d resolved, %d rescored (%d present)\n", p.Opened, p.Reopened, p.Resolved, len(rescored), len(p.IDs))
	byID := map[string]model.Issue{}
	for _, is := range res.Issues {
		byID[is.ID] = is
	}
	// Score / band changes of Issues that stayed open ("customer-pii path 10.0 CRITICAL → 7.0 HIGH").
	for _, r := range rescored {
		fmt.Fprintf(w, "  %-9s %s  %s  %s\n", "rescored", r.ID, scoreChange(r.OldScore, r.OldBand, r.NewScore), r.Title)
	}
	// A verified-fixed path Issue whose path is observed again: reopened, flagged regressed.
	for _, id := range p.RegressedIDs {
		is := byID[id]
		fmt.Fprintf(w, "  %-9s %s  verified-fixed Issue observed again (reopened): %4.1f %s %s\n", "regressed", id, is.Score, is.Band, is.Title)
	}
	for _, g := range []struct {
		label string
		ids   []string
	}{{"opened", p.OpenedIDs}, {"reopened", p.ReopenedIDs}, {"resolved", p.ResolvedIDs}} {
		for _, id := range g.ids {
			is, ok := byID[id]
			if !ok {
				fmt.Fprintf(w, "  %-9s %s\n", g.label, id)
				continue
			}
			fmt.Fprintf(w, "  %-9s %s  %-8s %4.1f %s\n", g.label, id, is.Band, is.Score, is.Title)
		}
	}
}

// collectErrorCoverage adapts a collector error to the store's CollectErrorLike hook.
type collectErrorCoverage collector.CollectError

func (c collectErrorCoverage) CoverageFields() (string, string, string, string, string) {
	return c.Provider, c.Account, c.API, c.Reason, c.Message
}

var _ store.CollectErrorLike = collectErrorCoverage{}

// diffEntry is one finding in the --diff-json document.
type diffEntry struct {
	ID          string         `json:"id"`
	Severity    model.Severity `json:"severity,omitempty"`
	CanonicalID string         `json:"canonical_id,omitempty"`
	Title       string         `json:"title,omitempty"`
	Resource    string         `json:"resource,omitempty"`
	Provider    string         `json:"provider,omitempty"`
	Account     string         `json:"account,omitempty"`
	Source      string         `json:"source,omitempty"`
}

// diffDoc is the machine-readable form of printDiff.
func diffDoc(res *scanResult) map[string]any {
	d := res.Diff
	entries := func(ids []string) []diffEntry {
		out := []diffEntry{}
		for _, id := range ids {
			e := diffEntry{ID: id}
			if f, ok := res.DiffFindings[id]; ok {
				e = diffEntry{ID: id, Severity: f.Severity, CanonicalID: f.CanonicalID, Title: f.Title, Resource: firstNonEmpty(f.Resource.Name, f.Resource.ID, f.File),
					Provider: f.Provider, Account: f.Account, Source: f.Source}
			}
			out = append(out, e)
		}
		return out
	}
	doc := map[string]any{
		"scan_id":  d.ScanID,
		"counts":   map[string]int{"new": len(d.New), "resolved": len(d.Resolved), "reopened": len(d.Reopened)},
		"new":      entries(d.New),
		"resolved": entries(d.Resolved),
		"reopened": entries(d.Reopened),
	}
	if res.Trend != nil {
		doc["issue_trend"] = res.Trend
	}
	if p := res.PathIssues; p != nil {
		ids := func(v []string) []string {
			if v == nil {
				return []string{}
			}
			return v
		}
		rescored, verified := diffExtras(res)
		if rescored == nil {
			rescored = []diffRescore{}
		}
		if verified == nil {
			verified = []diffVerified{}
		}
		doc["path_issues"] = map[string]any{"counts": map[string]int{"opened": p.Opened, "reopened": p.Reopened, "resolved": p.Resolved, "rescored": len(rescored), "present": len(p.IDs)},
			"opened": ids(p.OpenedIDs), "reopened": ids(p.ReopenedIDs), "resolved": ids(p.ResolvedIDs), "rescored": rescored,
			"regressed_after_verify": ids(p.RegressedIDs)}
		doc["verified_fixed"] = verified
	}
	if res.Headline != nil {
		doc["headline"] = res.Headline
	}
	return doc
}

// writeDiffJSON writes the diff document to path ("-" = stdout; "" = nothing).
func writeDiffJSON(path string, res *scanResult) error {
	if path == "" {
		return nil
	}
	if res.Diff == nil {
		return fmt.Errorf("--diff-json: no diff (results were not stored)")
	}
	if path == "-" {
		return output.JSON(os.Stdout, diffDoc(res))
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := output.JSON(f, diffDoc(res)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
