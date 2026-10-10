// Package output renders findings and summaries as table, JSON, SARIF, Markdown.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Table prints findings in aligned columns.
func Table(w io.Writer, findings []model.Finding, max int) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}
	rows := [][]string{{"SEVERITY", "STATUS", "PROVIDER", "ACCOUNT", "CANONICAL", "RESOURCE", "SOURCE"}}
	n := 0
	for _, f := range findings {
		if max > 0 && n >= max {
			break
		}
		n++
		res := f.Resource.Name
		if f.File != "" {
			res = fmt.Sprintf("%s:%d", f.File, f.LineStart)
		}
		rows = append(rows, []string{string(f.Severity), string(f.Status), f.Provider, short(f.Account, 18), f.CanonicalID, short(res, 48), f.Source})
	}
	writeAligned(w, rows)
	if max > 0 && len(findings) > max {
		fmt.Fprintf(w, "... %d more (use --limit 0 for all)\n", len(findings)-max)
	}
}

func Rows(w io.Writer, cols []string, rows [][]any) {
	all := [][]string{cols}
	for _, r := range rows {
		s := make([]string, len(r))
		for i, v := range r {
			if v == nil {
				s[i] = "NULL"
			} else {
				s[i] = short(fmt.Sprint(v), 60)
			}
		}
		all = append(all, s)
	}
	writeAligned(w, all)
	fmt.Fprintf(w, "(%d rows)\n", len(rows))
}

func writeAligned(w io.Writer, rows [][]string) {
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) && len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	for _, r := range rows {
		var parts []string
		for i, c := range r {
			if i < len(widths) {
				parts = append(parts, fmt.Sprintf("%-*s", widths[i], c))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(strings.Join(parts, "  "), " "))
	}
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Summary prints severity/provider counts and attack path totals.
func Summary(w io.Writer, findings []model.Finding, paths []model.AttackPath) {
	bySev := map[model.Severity]int{}
	byProv := map[string]int{}
	fails := 0
	for _, f := range findings {
		if f.Status != model.Fail {
			continue
		}
		fails++
		bySev[f.Severity]++
		byProv[f.Provider]++
	}
	fmt.Fprintf(w, "\nScan complete! Found %d open findings (%d total results):\n", fails, len(findings))
	var gaps []string
	for _, f := range findings {
		if IsScanGap(f) {
			gaps = append(gaps, firstNonEmpty(f.File, f.Resource.Name))
		}
	}
	if len(gaps) > 0 {
		fmt.Fprintf(w, "⚠ %d file(s) not scanned (they fail --fail-on): %s\n", len(gaps), strings.Join(gaps, ", "))
	}
	for _, s := range []model.Severity{model.Critical, model.High, model.Medium, model.Low, model.Info} {
		if bySev[s] > 0 {
			extra := ""
			if s == model.Critical && len(paths) > 0 {
				extra = fmt.Sprintf(" (%d attack paths)", len(paths))
			}
			fmt.Fprintf(w, "- %d %s%s\n", bySev[s], strings.Title(strings.ToLower(string(s))), extra)
		}
	}
	var provs []string
	for p := range byProv {
		provs = append(provs, p)
	}
	sort.Strings(provs)
	var parts []string
	for _, p := range provs {
		parts = append(parts, fmt.Sprintf("%s=%d", p, byProv[p]))
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "By provider: %s\n", strings.Join(parts, "  "))
	}
	if len(paths) > 0 {
		fmt.Fprintf(w, "Attack paths: %d (top: %s → %s, score %.1f)\n", len(paths), paths[0].Name, paths[0].Impact, paths[0].Score)
	}
}

// MaxSARIFResults is GitHub code scanning's per-run result limit (uploads with more results
// are rejected); SARIF keeps the most severe results up to it and records the truncation.
const MaxSARIFResults = 25000

// SARIF renders findings (IaC findings carry file/line) as SARIF 2.1.0 for GitHub code scanning.
// Beyond MaxSARIFResults the most severe results are kept (ties in input order), and the run
// carries a warning notification plus properties.truncated / omitted_results.
func SARIF(findings []model.Finding) map[string]any {
	return sarifWithLimit(findings, MaxSARIFResults)
}

func sarifWithLimit(findings []model.Finding, limit int) map[string]any {
	var eligible []model.Finding
	for _, f := range findings {
		if f.Status == model.Fail || IsScanGap(f) {
			eligible = append(eligible, f)
		}
	}
	total := len(eligible)
	if limit > 0 && total > limit {
		idx := make([]int, total)
		for i := range idx {
			idx[i] = i
		}
		rank := func(f model.Finding) int {
			if IsScanGap(f) {
				return 6 // reported as error whatever its severity
			}
			return f.Severity.Rank()
		}
		sort.SliceStable(idx, func(a, b int) bool { return rank(eligible[idx[a]]) > rank(eligible[idx[b]]) })
		keep := idx[:limit]
		sort.Ints(keep)
		kept := make([]model.Finding, 0, limit)
		for _, i := range keep {
			kept = append(kept, eligible[i])
		}
		eligible = kept
	}
	findings = eligible
	rulesIdx := map[string]int{}
	// SARIF 2.1.0 requires arrays here: a clean scan emits [] (never null).
	rules := []map[string]any{}
	results := []map[string]any{}
	levelOf := func(s model.Severity) string {
		switch s {
		case model.Critical, model.High:
			return "error"
		case model.Medium:
			return "warning"
		}
		return "note"
	}
	for _, f := range findings {
		if f.Status != model.Fail && !IsScanGap(f) {
			continue
		}
		rid := f.CanonicalID
		if _, ok := rulesIdx[rid]; !ok {
			rulesIdx[rid] = len(rules)
			props := map[string]any{"security-severity": secSeverity(f.Severity), "tags": append([]string{"security", f.Provider}, f.Weaknesses...)}
			rules = append(rules, map[string]any{
				"id": rid, "name": rid,
				"shortDescription":     map[string]any{"text": f.Title},
				"fullDescription":      map[string]any{"text": firstNonEmpty(f.Description, f.Title)},
				"help":                 map[string]any{"text": firstNonEmpty(f.Remediation, "See cloud-posture fix --finding "+rid), "markdown": "```\ncloud-posture fix --finding " + rid + " --generate-terraform\n```"},
				"defaultConfiguration": map[string]any{"level": levelOf(f.Severity)},
				"properties":           props,
			})
		}
		loc := map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": firstNonEmpty(f.File, "cloud://"+f.Provider+"/"+f.Resource.ID)}}}
		if f.LineStart > 0 {
			end := f.LineEnd
			if end < f.LineStart {
				end = f.LineStart
			}
			loc["physicalLocation"].(map[string]any)["region"] = map[string]any{"startLine": f.LineStart, "endLine": end}
		}
		level := levelOf(f.Severity)
		if IsScanGap(f) {
			level = "error" // an unexamined file fails closed whatever its nominal severity
		}
		results = append(results, map[string]any{
			"ruleId": rid, "ruleIndex": rulesIdx[rid], "level": level,
			"message":             map[string]any{"text": fmt.Sprintf("%s (%s) — %s", f.Title, f.Resource.Name, f.Source)},
			"locations":           []map[string]any{loc},
			"partialFingerprints": map[string]any{"cloudPostureFingerprint": f.ID},
			"properties":          sarifProps(f),
		})
	}
	run := map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "cloud-posture", "informationUri": "https://github.com/DreadpiratePickles/nimbus", "version": ToolVersion, "rules": rules}},
		"results": results,
		// cloudPostureFingerprint is the unkeyed finding digest (ids.go): this file shows the
		// account and resource it is computed from, so it reveals nothing more — but it is not
		// the keyed id MCP and the API show.
		"properties": map[string]any{"nimbus_id_scheme": IDSchemeUnkeyed},
	}
	if omitted := total - len(results); omitted > 0 {
		run["invocations"] = []map[string]any{{
			"executionSuccessful": true,
			"toolExecutionNotifications": []map[string]any{{
				"level":      "warning",
				"descriptor": map[string]any{"id": "results-truncated"},
				"message":    map[string]any{"text": fmt.Sprintf("SARIF truncated: %d of %d results omitted to stay within GitHub code scanning's %d-result limit; the most severe results were kept. Use --format json or ocsf for the full set.", omitted, total, limit)},
			}},
		}}
		run["properties"] = map[string]any{"truncated": true, "omitted_results": omitted, "total_results": total, "nimbus_id_scheme": IDSchemeUnkeyed}
	}
	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs":    []map[string]any{run},
	}
}

// sarifProps carries the fields a SARIF consumer (and ParseSARIF) needs to rebuild the
// finding's identity: region and resource id are fingerprint inputs.
func sarifProps(f model.Finding) map[string]any {
	p := map[string]any{"severity": f.Severity, "status": f.Status, "provider": f.Provider, "account": f.Account, "source": f.Source, "check_id": f.CheckID}
	if f.Region != "" {
		p["region"] = f.Region
	}
	if f.Resource.ID != "" {
		p["resource_id"] = f.Resource.ID
	}
	if f.Resource.Type != "" {
		p["resource_type"] = f.Resource.Type
	}
	return p
}

func secSeverity(s model.Severity) string {
	return map[model.Severity]string{model.Critical: "9.5", model.High: "8.0", model.Medium: "5.5", model.Low: "3.0", model.Info: "1.0"}[s]
}

// PRMarkdown renders a pull-request comment with a summary table and the top findings.
func PRMarkdown(findings []model.Finding, paths []model.AttackPath, max int) string {
	var b strings.Builder
	b.WriteString("## ☁️ cloud-posture scan results\n\n")
	bySev := map[model.Severity]int{}
	var fails []model.Finding
	var gaps []model.Finding
	for _, f := range findings {
		if f.Status == model.Fail {
			bySev[f.Severity]++
			fails = append(fails, f)
		} else if IsScanGap(f) {
			gaps = append(gaps, f)
		}
	}
	fmt.Fprintf(&b, "| Critical | High | Medium | Low | Attack paths |\n|---|---|---|---|---|\n| %d | %d | %d | %d | %d |\n\n", bySev[model.Critical], bySev[model.High], bySev[model.Medium], bySev[model.Low], len(paths))
	if len(gaps) > 0 {
		fmt.Fprintf(&b, "⚠️ **%d file(s) were not scanned** and fail the gate until fixed:\n\n| Check | File | Reason |\n|---|---|---|\n", len(gaps))
		for _, f := range gaps {
			fmt.Fprintf(&b, "| %s | `%s` | %s |\n", f.CanonicalID, firstNonEmpty(f.File, f.Resource.Name), strings.ReplaceAll(firstNonEmpty(f.Description, f.Title), "|", "\\|"))
		}
		b.WriteString("\n")
	}
	if len(fails) == 0 && len(gaps) == 0 {
		b.WriteString("✅ No open findings.\n")
		return b.String()
	}
	if len(fails) > 0 {
		b.WriteString("| Severity | Finding | Location | Fix |\n|---|---|---|---|\n")
	}
	for i, f := range fails {
		if max > 0 && i >= max {
			fmt.Fprintf(&b, "\n_%d more findings not shown._\n", len(fails)-max)
			break
		}
		loc := f.Resource.Name
		if f.File != "" {
			loc = fmt.Sprintf("`%s:%d`", f.File, f.LineStart)
		}
		fmt.Fprintf(&b, "| %s | **%s** %s | %s | `cloud-posture fix --finding %s` |\n", sevEmoji(f.Severity), f.CanonicalID, f.Title, loc, f.CanonicalID)
	}
	if len(paths) > 0 {
		b.WriteString("\n<details><summary>⚔️ Attack paths</summary>\n\n")
		for i, p := range paths {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&b, "- **%s** → %s (score %.1f)\n", p.Name, p.Impact, p.Score)
		}
		b.WriteString("\n</details>\n")
	}
	return b.String()
}

func sevEmoji(s model.Severity) string {
	return map[model.Severity]string{model.Critical: "🔴 CRITICAL", model.High: "🟠 HIGH", model.Medium: "🟡 MEDIUM", model.Low: "🟢 LOW", model.Info: "⚪ INFO"}[s]
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// WriteFile writes JSON to a path, creating directories.
func WriteFile(path string, v any) error {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return JSON(f, v)
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return "."
}
