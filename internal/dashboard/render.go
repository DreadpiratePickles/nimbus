// Package dashboard renders the single-file HTML dashboard (works offline as a static
// report and as the page served by `cloud-posture serve` with live updates).
package dashboard

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/compliance"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

//go:embed dashboard.html
var tpl string

// The page is assembled from these embedded assets (spec v2.6): the cwm visual language
// (cwm.css), the layout/navigation/pane/live engine (cwm.js), the product views (clients.js)
// and the vendored Cytoscape build.
var (
	//go:embed cwm.css
	cwmCSS string
	//go:embed cwm.js
	cwmJS string
	//go:embed clients.js
	clientsJS string
	//go:embed cytoscape.min.js
	cytoscapeJS string
)

// assetErr is non-nil when an embedded asset is unsafe to inline; Render then refuses.
var assetErr = checkScripts(map[string]string{
	"cwm.css":          cwmCSS,
	"cwm.js":           cwmJS,
	"clients.js":       clientsJS,
	"cytoscape.min.js": cytoscapeJS,
})

// checkScripts rejects empty assets and any asset containing "</script" (case-insensitive),
// which would terminate an inline <script> early. CSS assets (*.css, inlined in <style>) must
// not contain "</style"; script assets must not contain "<!--", which puts the HTML tokenizer
// into script-data-escaped state where a later "<script" can swallow the closing tag.
func checkScripts(assets map[string]string) error {
	names := make([]string, 0, len(assets))
	for n := range assets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		body := assets[n]
		if strings.TrimSpace(body) == "" {
			return fmt.Errorf("dashboard: embedded asset %s is empty", n)
		}
		lower := strings.ToLower(body)
		if strings.Contains(lower, "</script") {
			return fmt.Errorf("dashboard: embedded asset %s contains </script", n)
		}
		if strings.HasSuffix(n, ".css") {
			if strings.Contains(lower, "</style") {
				return fmt.Errorf("dashboard: embedded asset %s contains </style", n)
			}
		} else if strings.Contains(body, "<!--") {
			return fmt.Errorf("dashboard: embedded asset %s contains <!--", n)
		}
	}
	return nil
}

// Data is everything the page needs; it is embedded as JSON and never interpolated as HTML.
type Data struct {
	GeneratedAt string               `json:"generated_at"`
	Mode        string               `json:"mode"` // static | live
	Accounts    []string             `json:"accounts"`
	Findings    []model.Finding      `json:"findings"`
	Paths       []model.AttackPath   `json:"paths"`
	Analysis    *attackpath.Analysis `json:"analysis"`
	Graph       map[string]any       `json:"graph"`
	Risk        []risk.Ranked        `json:"risk"`
	Compliance  []*compliance.Report `json:"compliance"`
	Cost        any                  `json:"cost,omitempty"`
	Scan        *model.ScanSummary   `json:"scan,omitempty"`
	CopilotURL  string               `json:"copilot_url,omitempty"`
	// Lifecycle views (Track G, wired by the CLI). The dashboard JS does not read them yet
	// (Track I).
	Issues   []model.Issue         `json:"issues"`
	Coverage []store.CoverageEntry `json:"coverage"`
	Scans    []model.ScanSummary   `json:"scans"`
	// Exposures (internet-reachable, no impact target behind them: not attack paths) and
	// Suppressed (exposure refused as an entry: trusted or private), mirrored from Analysis
	// at the top level for the views. Render fills them from Analysis; always arrays.
	Exposures  []attackpath.Exposure   `json:"exposures"`
	Suppressed []attackpath.Suppressed `json:"suppressed"`
	// IssuePages is the Issue page record per Issue id (owner/SLA, linked Issues, fixes with
	// remediation phases, tickets, timeline, suppression, confidence, hops) built by the CLI
	// with internal/server.BuildIssuePages; the Issue pane renders it. Always an object.
	IssuePages any `json:"issue_pages"`
	// Governance is the owners panel's metrics (internal/server.GovernanceMetrics: open and
	// overdue by owner, MTTR by severity, on-time rate) built by the CLI from the store; null
	// without a store. Issue due dates and the overdue flag are on Issues.
	Governance any `json:"governance"`
	// PathGroups is the paths view's list: one row per path Issue (attackpath.Analysis.Grouped(),
	// the `paths` CLI's rows), best-scoring first. Render fills it from Analysis.Paths (or Paths
	// without an analysis); always an array. The paths themselves are in Paths, by id.
	PathGroups []PathGroupRow `json:"path_groups"`
	// Headline is the store's Issue headline (internal/store.Headline: open Issues, path Issues
	// and hop variants, finding Issues, critical by Issue severity), the numbers the risk panel
	// prints so they match the CLI and /api/summary; null without a store.
	Headline any `json:"headline"`
	// PathTitles is the one-line label of every path (by path id): its path Issue's title plus
	// what the path does, the label `paths` and `plan` print (W6-POLISH, r4 #4: never
	// "X → X → Privilege escalation to X"). The page falls back to name → impact without it.
	PathTitles map[string]string `json:"path_titles"`
}

// PathGroupRow is one path Issue of the paths view: attackpath.PathGroup without the path
// bodies (the page resolves BestID and PathIDs against Data.Paths).
type PathGroupRow struct {
	IssueID  string         `json:"issue_id"`
	Entry    string         `json:"entry"`
	Anchor   string         `json:"anchor"`
	Rule     string         `json:"rule"`
	BestID   string         `json:"best_id"`
	Name     string         `json:"name"`
	Score    float64        `json:"score"`
	Band     string         `json:"band"`
	Severity model.Severity `json:"severity"`
	Variants int            `json:"variants"` // len(PathIDs) - 1
	PathIDs  []string       `json:"path_ids"` // best first
}

// PathGroupRows converts attackpath groups to the payload rows (always non-nil).
func PathGroupRows(groups []attackpath.PathGroup) []PathGroupRow {
	out := make([]PathGroupRow, 0, len(groups))
	for _, g := range groups {
		out = append(out, PathGroupRow{IssueID: g.IssueID, Entry: g.Entry, Anchor: g.Anchor, Rule: g.Rule, BestID: g.Best.ID, Name: g.Best.Name,
			Score: g.Score, Band: g.Band, Severity: g.Severity, Variants: g.Variants, PathIDs: g.PathIDs})
	}
	return out
}

var page = template.Must(template.New("dashboard").Parse(tpl))

// Render produces the HTML. Finding.Raw is dropped to keep the page small.
func Render(d Data) ([]byte, error) {
	if assetErr != nil {
		return nil, assetErr
	}
	if d.GeneratedAt == "" {
		d.GeneratedAt = time.Now().UTC().Format("2006-01-02 15:04 UTC")
	}
	if d.Mode == "" {
		d.Mode = "static"
	}
	for i := range d.Findings {
		d.Findings[i].Raw = nil
	}
	for i := range d.Risk {
		d.Risk[i].Finding.Raw = nil
	}
	if d.Graph == nil {
		d.Graph = map[string]any{"nodes": []any{}, "edges": []any{}}
	}
	if d.Analysis == nil {
		d.Analysis = &attackpath.Analysis{}
	}
	an := *d.Analysis // never mutate the caller's analysis
	if an.Exposures == nil {
		an.Exposures = []attackpath.Exposure{}
	}
	if an.Suppressed == nil {
		an.Suppressed = []attackpath.Suppressed{}
	}
	d.Analysis = &an
	if d.Exposures == nil {
		d.Exposures = an.Exposures
	}
	if d.Suppressed == nil {
		d.Suppressed = an.Suppressed
	}
	if d.IssuePages == nil {
		d.IssuePages = map[string]any{}
	}
	if d.PathTitles == nil {
		d.PathTitles = map[string]string{}
	}
	if d.PathGroups == nil {
		if len(an.Paths) > 0 {
			d.PathGroups = PathGroupRows(an.Grouped())
		} else {
			d.PathGroups = PathGroupRows(attackpath.GroupPaths(d.Paths))
		}
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	// template.JS / template.CSS values are inserted verbatim (html/template does not escape
	// them): the JSON is made safe by jsonSafe and the assets by checkScripts above.
	var buf bytes.Buffer
	if err := page.Execute(&buf, map[string]any{
		"JSON":      template.JS(jsonSafe(raw)),
		"CSS":       template.CSS(cwmCSS),
		"Cytoscape": template.JS(cytoscapeJS),
		"Clients":   template.JS(clientsJS),
		"App":       template.JS(cwmJS),
	}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// jsonSafe neutralises "</" and U+2028/2029 so cloud-controlled strings cannot break out of the script block.
func jsonSafe(b []byte) string {
	s := string(b)
	out := make([]byte, 0, len(s)+16)
	for i := 0; i < len(s); i++ {
		if s[i] == '<' && i+1 < len(s) && s[i+1] == '/' {
			out = append(out, '<', '\\', '/')
			i++
			continue
		}
		out = append(out, s[i])
	}
	s = string(out)
	s = replaceAll(s, " ", "\\u2028")
	s = replaceAll(s, " ", "\\u2029")
	return s
}

func replaceAll(s, old, new string) string {
	return string(bytes.ReplaceAll([]byte(s), []byte(old), []byte(new)))
}
