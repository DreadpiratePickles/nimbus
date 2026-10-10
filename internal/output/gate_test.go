package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 3 defect 2 (HIGH), output side: an IaC file the scanner could not parse is an
// ERROR finding tagged TagScanGap. It must block every --fail-on threshold and appear in SARIF,
// JSON and the PR comment; other ERROR findings (a collector that was denied, a rule that hit its
// panic guard) keep their current treatment.
func gapFinding() model.Finding {
	f := model.Finding{Source: "nimbus-iac", CheckID: "IAC_PARSE_LIMIT", CanonicalID: "IAC_PARSE_LIMIT", Title: "IaC file not scanned: syntax error",
		Severity: model.High, Status: model.Error, Provider: model.ProviderIaC, Account: "iac", File: "main.tf", LineStart: 1,
		Resource: model.Resource{ID: "main.tf", Name: "main.tf"}, Tags: map[string]string{TagScanGap: "syntax"}}
	f.ID = "gapid"
	return f
}

func TestGateCountsScanGapsAtEveryThreshold(t *testing.T) {
	low := gapFinding()
	low.Severity = model.Low
	other := model.Finding{CanonicalID: "X", Status: model.Error, Severity: model.Critical}
	pass := model.Finding{CanonicalID: "Y", Status: model.Pass, Severity: model.Critical}
	fail := model.Finding{CanonicalID: "Z", Status: model.Fail, Severity: model.Medium}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := GateCount([]model.Finding{low, other, pass}, sev); n != 1 {
			t.Errorf("--fail-on %s: gate count %d, want 1 (the scan gap only)", sev, n)
		}
	}
	if n := GateCount([]model.Finding{fail}, "high"); n != 0 {
		t.Errorf("a MEDIUM FAIL counted at --fail-on high: %d", n)
	}
	if n := GateCount([]model.Finding{fail}, "medium"); n != 1 {
		t.Errorf("a MEDIUM FAIL not counted at --fail-on medium: %d", n)
	}
	if n := GateCount([]model.Finding{gapFinding()}, ""); n != 0 {
		t.Errorf("no --fail-on: gate count %d", n)
	}
}

func TestSARIFAndPRIncludeScanGaps(t *testing.T) {
	fs := []model.Finding{gapFinding(), {CanonicalID: "X", Status: model.Error, Severity: model.High, Title: "denied"}}
	var buf bytes.Buffer
	if err := JSON(&buf, SARIF(fs)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
				Locs   []struct {
					Phys struct {
						Art struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	rs := doc.Runs[0].Results
	if len(rs) != 1 || rs[0].RuleID != "IAC_PARSE_LIMIT" || rs[0].Level != "error" || rs[0].Locs[0].Phys.Art.URI != "main.tf" {
		t.Errorf("SARIF results = %+v, want exactly the scan gap at level error on main.tf", rs)
	}
	md := PRMarkdown(fs, nil, 10)
	if !strings.Contains(md, "IAC_PARSE_LIMIT") || !strings.Contains(md, "main.tf") || strings.Contains(md, "No open findings") {
		t.Errorf("PR comment hides the unscanned file:\n%s", md)
	}
	var sum bytes.Buffer
	Summary(&sum, fs, nil)
	if !strings.Contains(sum.String(), "not scanned") {
		t.Errorf("summary does not mention the unscanned file:\n%s", sum.String())
	}
	buf.Reset()
	if err := JSON(&buf, fs); err != nil || !strings.Contains(buf.String(), "IAC_PARSE_LIMIT") || !strings.Contains(buf.String(), TagScanGap) {
		t.Errorf("JSON output lost the gap finding: %v\n%s", err, buf.String())
	}
}
