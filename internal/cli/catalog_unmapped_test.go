package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type unmappedJSON struct {
	Tool           string  `json:"tool"`
	Version        string  `json:"version"`
	Findings       int     `json:"fail_findings"`
	Mapped         int     `json:"mapped"`
	Unmapped       int     `json:"unmapped"`
	MappedPct      float64 `json:"mapped_pct"`
	UnmappedChecks []struct {
		CheckID string `json:"check_id"`
		Count   int    `json:"count"`
	} `json:"unmapped_checks"`
}

// --golden: the lab IaC golden (lab/golden/expectations.yaml), found by walking up from cwd.
func TestCatalogUnmappedGoldenJSON(t *testing.T) {
	for tool, floor := range map[string]float64{"checkov": 80, "trivy": 85} {
		out := run(t, "catalog", "unmapped", "--tool", tool, "--format", "json", "--golden")
		var r unmappedJSON
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("%s: %v\n%s", tool, err, out)
		}
		if r.Tool != tool || r.Version == "" || r.Findings == 0 || r.Mapped+r.Unmapped != r.Findings {
			t.Errorf("%s: report %+v", tool, r)
		}
		if r.MappedPct < floor {
			t.Errorf("%s: %.1f%% mapped, floor %.0f%%", tool, r.MappedPct, floor)
		}
		if len(r.UnmappedChecks) == 0 {
			t.Errorf("%s: golden has unmapped checks, none listed", tool)
		}
	}
}

func TestCatalogUnmappedText(t *testing.T) {
	out := run(t, "catalog", "unmapped", "--tool", "checkov", "--golden")
	for _, want := range []string{"checkov", "mapped", "%", "CKV_AWS_135"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output misses %q:\n%s", want, out)
		}
	}
}

func TestCatalogUnmappedFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scan.json")
	doc := `{"check_type":"terraform","results":{"failed_checks":[
 {"check_id":"CKV_AWS_19","check_name":"S3 encrypted","resource":"aws_s3_bucket.a","file_path":"/main.tf"},
 {"check_id":"CKV_FAKE_9","check_name":"Fake","resource":"aws_s3_bucket.a","file_path":"/main.tf"}]}}`
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	out := run(t, "catalog", "unmapped", "--tool", "checkov", "--from", p, "--format", "json")
	var r unmappedJSON
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if r.Findings != 2 || r.Mapped != 1 || r.MappedPct != 50 || len(r.UnmappedChecks) != 1 || r.UnmappedChecks[0].CheckID != "CKV_FAKE_9" {
		t.Errorf("report %+v", r)
	}
}

func TestCatalogUnmappedRejectsBadTool(t *testing.T) {
	if _, err := runErr(t, "catalog", "unmapped", "--tool", "prowler"); err == nil {
		t.Error("--tool prowler must fail (checkov|trivy only)")
	}
	if _, err := runErr(t, "catalog", "unmapped"); err == nil {
		t.Error("--tool is required")
	}
}

// `catalog [ID]` keeps working next to the subcommand.
func TestCatalogEntryStillRoutes(t *testing.T) {
	out := run(t, "catalog", "S3_PUBLIC_BUCKET")
	if !strings.Contains(out, `"S3_PUBLIC_BUCKET"`) || !strings.Contains(out, "remediation_formats") {
		t.Errorf("catalog ID output:\n%s", out)
	}
	if out := run(t, "catalog"); !strings.Contains(out, "canonical checks") {
		t.Errorf("catalog list output:\n%s", out)
	}
}
