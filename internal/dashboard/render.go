// Package dashboard renders the single-file HTML dashboard (works offline as a static
// report and as the page served by `cloud-posture serve` with live updates).
package dashboard

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"html/template"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/compliance"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
)

//go:embed dashboard.html
var tpl string

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
}

var page = template.Must(template.New("dashboard").Parse(tpl))

// Render produces the HTML. Finding.Raw is dropped to keep the page small.
func Render(d Data) ([]byte, error) {
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
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	// html/template escapes "</script>" sequences inside the JSON block for us.
	var buf bytes.Buffer
	if err := page.Execute(&buf, map[string]any{"JSON": template.JS(jsonSafe(raw))}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// jsonSafe neutralises "</" and U+2028/2029 so cloud-controlled strings cannot break out of the script block.
func jsonSafe(b []byte) string {
	s := string(b)
	s = bytes.NewBufferString(s).String()
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

func replaceAll(s, old, new string) string { return string(bytes.ReplaceAll([]byte(s), []byte(old), []byte(new))) }
