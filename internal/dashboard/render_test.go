package dashboard

import (
	"regexp"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func TestRenderEscapes(t *testing.T) {
	html, err := Render(Data{Findings: []model.Finding{{ID: "x", Title: "</script><img src=x onerror=alert(1)>", Status: model.Fail, Severity: model.High, Resource: model.Resource{ID: "r"}}}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	if strings.Contains(s, "</script><img") {
		t.Fatalf("script breakout not neutralised")
	}
	if !strings.Contains(s, `<script id="data" type="application/json">`) || !strings.Contains(s, "cytoscape") {
		t.Errorf("template structure")
	}
}

func renderEmpty(t *testing.T) string {
	t.Helper()
	html, err := Render(Data{})
	if err != nil {
		t.Fatal(err)
	}
	return string(html)
}

// Spec §9 Go test 1: structure, no CDN.
func TestRenderNoExternalSources(t *testing.T) {
	s := renderEmpty(t)
	if !strings.Contains(s, `<script id="data" type="application/json">`) {
		t.Errorf("missing inline data block")
	}
	if !strings.Contains(s, "cytoscape") {
		t.Errorf("cytoscape not embedded")
	}
	if strings.Contains(s, "</script><img") {
		t.Errorf("script breakout")
	}
	if m := regexp.MustCompile(`(?i)src\s*=\s*["']?\s*https?://`).FindString(s); m != "" {
		t.Errorf("external src found: %q", m)
	}
}

// Spec §8: template shell orders the scripts data -> cytoscape -> clients -> cwm.
func TestRenderScriptOrder(t *testing.T) {
	s := renderEmpty(t)
	iData := strings.Index(s, `<script id="data"`)
	iCy := strings.Index(s, cytoscapeJS[:64])
	iCl := strings.Index(s, clientsJS[:min(64, len(clientsJS))])
	iWM := strings.Index(s, cwmJS[:64])
	if iData < 0 || iCy < 0 || iCl < 0 || iWM < 0 {
		t.Fatalf("missing script: data=%d cy=%d clients=%d wm=%d", iData, iCy, iCl, iWM)
	}
	if !(iData < iCy && iCy < iCl && iCl < iWM) {
		t.Errorf("script order wrong: data=%d cy=%d clients=%d wm=%d", iData, iCy, iCl, iWM)
	}
	if !strings.Contains(s, "<title>nimbus</title>") {
		t.Errorf("title must be nimbus")
	}
	if !strings.Contains(s, cwmCSS[:64]) {
		t.Errorf("cwm.css not inlined")
	}
}

// Spec v2.7 Go test: cwm visual-language tokens are present (colours, menu font, guillemets).
func TestRenderCwmTokens(t *testing.T) {
	s := renderEmpty(t)
	for _, want := range []string{"#CCCCCC", "#666666", "#FC8814", "#000000", "#FFFFFF", "bold 14px sans-serif", "»", "«"} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered page lacks %q", want)
		}
	}
	// the nine sections, in nav order, and the hash router live in the engine
	for _, want := range []string{"'overview'", "'attack paths'", "'top risks'", "'findings'", "'compliance'", "'cost'", "'sql'", "'copilot'", "'coverage'", "'nimbus'", "hashchange", "/ws"} {
		if !strings.Contains(cwmJS, want) {
			t.Errorf("engine script lacks %s", want)
		}
	}
}

// Spec v2.3: the window manager is gone. No WM vocabulary in the engine, no xterm/cwmrc views.
func TestNoWindowManager(t *testing.T) {
	for _, bad := range []string{"menu-window", "window-htile", "xlock", "'application'", "'exec'", "'ssh'", "'group'", "cwm-client", "cwm-geom", "clientq"} {
		if strings.Contains(cwmJS, bad) {
			t.Errorf("cwm.js still contains window-manager code: %q", bad)
		}
	}
	for _, bad := range []string{"vXterm", "vCwmrc", "'xterm'", "'cwmrc'", "ksh: "} {
		if strings.Contains(clientsJS, bad) {
			t.Errorf("clients.js still contains %q", bad)
		}
	}
	for _, bad := range []string{".cwm-client", ".cwm-menu", ".cwm-geom", ".cwm-lock"} {
		if strings.Contains(cwmCSS, bad) {
			t.Errorf("cwm.css still contains %q", bad)
		}
	}
	if regexp.MustCompile(`border-radius:\s*[1-9]|box-shadow:\s*[^n\s]|linear-gradient|radial-gradient|@keyframes`).MatchString(cwmCSS) {
		t.Errorf("cwm.css has rounded corners, shadows, gradients or animations")
	}
}

// Spec §9 Go test 3: every embedded asset is non-empty and free of "</script".
func TestEmbeddedAssets(t *testing.T) {
	for name, body := range map[string]string{"cwm.css": cwmCSS, "cwm.js": cwmJS, "clients.js": clientsJS, "cytoscape.min.js": cytoscapeJS} {
		if strings.TrimSpace(body) == "" {
			t.Errorf("%s is empty", name)
		}
		if strings.Contains(strings.ToLower(body), "</script") {
			t.Errorf("%s contains </script", name)
		}
	}
	if assetErr != nil {
		t.Errorf("assetErr = %v", assetErr)
	}
}

// Spec §8: render refuses when an embedded script contains "</script" (any case).
func TestCheckScriptsRefusesScriptClose(t *testing.T) {
	if err := checkScripts(map[string]string{"a.js": "var x = 1;"}); err != nil {
		t.Fatalf("clean script rejected: %v", err)
	}
	for _, bad := range []string{"x='</script>'", "x='</SCRIPT'", "x='</ScRiPt >'"} {
		if err := checkScripts(map[string]string{"a.js": "ok", "b.js": bad}); err == nil || !strings.Contains(err.Error(), "b.js") {
			t.Errorf("checkScripts(%q) = %v, want error naming b.js", bad, err)
		}
	}
	// CSS is inlined in <style>: "</style" (any case) ends it early. Scripts must not
	// contain "<!--", which switches the HTML tokenizer into script-data-escaped state.
	for _, tc := range []struct{ name, body string }{
		{"b.css", "a{}</style><script>alert(1)</script>"},
		{"b.css", "a{}</STYLE >"},
		{"b.js", "var s = '<!--';"},
		{"b.js", "x<!-- y"},
	} {
		if err := checkScripts(map[string]string{"a.js": "ok", tc.name: tc.body}); err == nil || !strings.Contains(err.Error(), tc.name) {
			t.Errorf("checkScripts(%s=%q) = %v, want error naming %s", tc.name, tc.body, err, tc.name)
		}
	}
	if err := checkScripts(map[string]string{"ok.css": "a::after{content:'<!--'}"}); err != nil {
		t.Errorf("<!-- in CSS is harmless inside <style>, got %v", err)
	}
	if err := checkScripts(map[string]string{"empty.js": "  "}); err == nil {
		t.Errorf("empty script accepted")
	}
	saved := assetErr
	defer func() { assetErr = saved }()
	assetErr = checkScripts(map[string]string{"evil.js": "</script>"})
	if _, err := Render(Data{}); err == nil {
		t.Errorf("Render succeeded despite a poisoned asset")
	}
}

// Track I: the views read the lifecycle payload (Issues, coverage, scan history), the risk
// explanation and the path-analysis fields Track B/F/G added, and live mode refetches Issues.
func TestViewsReadTrackIPayload(t *testing.T) {
	for _, want := range []string{
		"D.issues", "D.coverage", "D.scans", ".explanation", ".because", "reaches_crown_jewel", "dead_ends",
		"path_ids", "closes_n", "min_fix_exact", "min_fix_verified", ".incomplete", ".suppressed", "weak_link",
		"score version", "'issue'", "ResizeObserver",
	} {
		if !strings.Contains(clientsJS, want) {
			t.Errorf("clients.js does not read %s", want)
		}
	}
	for _, want := range []string{"issue: true", "/api/issues"} {
		if !strings.Contains(cwmJS, want) {
			t.Errorf("cwm.js lacks %s", want)
		}
	}
}

// The dashboard lists a combination Issue's weaknesses from a mirror of
// model.ToxicCombinations; the mirror must not drift from the Go declaration.
func TestToxicCombinationsMirrored(t *testing.T) {
	re := regexp.MustCompile(`(?s)const TOXIC = \{(.*?)\};`)
	m := re.FindStringSubmatch(clientsJS)
	if m == nil {
		t.Fatalf("clients.js has no TOXIC mirror of model.ToxicCombinations")
	}
	for _, c := range model.ToxicCombinations {
		want := c.ID + ": [" + "'" + strings.Join(c.AllOf, "', '") + "'" + "]"
		if !strings.Contains(m[1], want) {
			t.Errorf("TOXIC mirror lacks %s", want)
		}
	}
	if n := strings.Count(m[1], "TOXIC_"); n != len(model.ToxicCombinations) {
		t.Errorf("TOXIC mirror has %d entries, model declares %d", n, len(model.ToxicCombinations))
	}
}

// The lifecycle views reach the page payload unchanged.
func TestRenderEmbedsLifecycleViews(t *testing.T) {
	html, err := Render(Data{
		Issues:   []model.Issue{{ID: "i1", Kind: model.IssueCombination, CanonicalID: "TOXIC_PUBLIC_ADMIN", State: "open", FindingIDs: []string{"f1"}, Sources: []string{"prowler"}, Confidence: 0.7}},
		Coverage: []store.CoverageEntry{{Provider: "aws", Account: "1", API: "iam:ListRoles", Status: store.CoverageDenied, Reason: "AccessDenied"}},
		Scans:    []model.ScanSummary{{ScanID: "s1", BySeverity: map[model.Severity]int{model.Critical: 2}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	for _, want := range []string{`"kind":"combination"`, `"status":"denied"`, `"reason":"AccessDenied"`, `"scan_id":"s1"`, `"CRITICAL":2`} {
		if !strings.Contains(s, want) {
			t.Errorf("payload lacks %s", want)
		}
	}
}

// Integration pass 2 item 3: the payload carries the exposures (not attack paths) and the
// suppressed exposure at the top level, always as arrays.
func TestRenderEmbedsExposures(t *testing.T) {
	html, err := Render(Data{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	for _, want := range []string{`"exposures":[]`, `"suppressed":[]`} {
		if strings.Count(s, want) != 2 { // top level + inside analysis
			t.Errorf("payload has %d × %s, want 2 (top level and analysis)", strings.Count(s, want), want)
		}
	}
	html, err = Render(Data{Analysis: &attackpath.Analysis{Exposures: []attackpath.Exposure{{NodeID: "n-web", Width: "wide"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(html), `"node_id":"n-web"`) != 2 {
		t.Errorf("exposure not mirrored at the top level")
	}
}
