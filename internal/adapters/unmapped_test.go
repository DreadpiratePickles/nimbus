package adapters

import (
	"os"
	"path/filepath"
	"testing"
)

// `cloud-posture catalog unmapped` (shortfall #15): which native check ids of a scanner have no
// canonical mapping, counted over FAIL findings exactly as tests/groundtruth scores the goldens.
func TestMappingCoverageCountsFailFindings(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "checkov.json")
	doc := `{"check_type":"terraform","results":{"failed_checks":[
 {"check_id":"CKV_AWS_19","check_name":"S3 encrypted","resource":"aws_s3_bucket.a","file_path":"/main.tf"},
 {"check_id":"CKV_FAKE_1","check_name":"Fake one","resource":"aws_s3_bucket.a","file_path":"/main.tf"},
 {"check_id":"CKV_FAKE_1","check_name":"Fake one","resource":"aws_s3_bucket.b","file_path":"/main.tf"},
 {"check_id":"CKV_FAKE_2","check_name":"Fake two","resource":"aws_s3_bucket.b","file_path":"/main.tf"}],
 "passed_checks":[{"check_id":"CKV_FAKE_3","check_name":"Passed","resource":"aws_s3_bucket.a","file_path":"/main.tf"}]}}`
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := MappingCoverage("checkov", []string{p})
	if err != nil {
		t.Fatal(err)
	}
	if r.Tool != "checkov" || r.Findings != 4 || r.Mapped != 1 || r.Unmapped != 3 || r.MappedPct != 25 {
		t.Fatalf("report %+v, want 4 FAIL findings, 1 mapped (25%%), 3 unmapped", r)
	}
	if len(r.UnmappedChecks) != 2 {
		t.Fatalf("unmapped checks %+v, want CKV_FAKE_1 (2) then CKV_FAKE_2 (1)", r.UnmappedChecks)
	}
	if c := r.UnmappedChecks[0]; c.CheckID != "CKV_FAKE_1" || c.Count != 2 || c.Title != "Fake one" {
		t.Errorf("first unmapped %+v, want CKV_FAKE_1 ×2 (most frequent first)", c)
	}
	if c := r.UnmappedChecks[1]; c.CheckID != "CKV_FAKE_2" || c.Count != 1 {
		t.Errorf("second unmapped %+v", c)
	}
}

func TestMappingCoverageRejectsUnknownTool(t *testing.T) {
	if _, err := MappingCoverage("nosuchtool", nil); err == nil {
		t.Fatal("unknown tool must be an error")
	}
}

// The default corpus is the lab IaC golden listed in lab/golden/expectations.yaml; the numbers must
// agree with the floors tests/groundtruth enforces (Checkov ≥ 80%, Trivy ≥ 85%).
func TestGoldenCoverageMeetsFloors(t *testing.T) {
	root := filepath.Join("..", "..")
	for tool, floor := range map[string]float64{"checkov": 80, "trivy": 85} {
		files, version, err := GoldenInputs(root, tool)
		if err != nil {
			t.Fatal(err)
		}
		if version == "" || len(files) == 0 {
			t.Fatalf("%s: no golden inputs (version %q)", tool, version)
		}
		r, err := MappingCoverage(tool, files)
		if err != nil {
			t.Fatal(err)
		}
		sum := 0
		for _, c := range r.UnmappedChecks {
			sum += c.Count
		}
		if r.Findings == 0 || r.Mapped+r.Unmapped != r.Findings || sum != r.Unmapped {
			t.Errorf("%s: inconsistent report %+v", tool, r)
		}
		if r.MappedPct < floor {
			t.Errorf("%s golden: %.1f%% mapped (%d/%d), floor %.0f%%", tool, r.MappedPct, r.Mapped, r.Findings, floor)
		}
	}
	if _, _, err := GoldenInputs(root, "prowler"); err == nil {
		t.Error("a tool without a golden must be an error")
	}
}

// The store keeps one row per finding id (fingerprint); a scanner reporting the same check on the same
// resource twice (Trivy does, per module instance) is one finding, as in `cloud-posture ingest`.
func TestMappingCoverageDedupesByFindingID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "checkov.json")
	doc := `{"check_type":"terraform","results":{"failed_checks":[
 {"check_id":"CKV_FAKE_1","check_name":"Fake","resource":"aws_s3_bucket.a","file_path":"/main.tf"},
 {"check_id":"CKV_FAKE_1","check_name":"Fake","resource":"aws_s3_bucket.a","file_path":"/main.tf"}]}}`
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := MappingCoverage("checkov", []string{p})
	if err != nil {
		t.Fatal(err)
	}
	if r.Findings != 1 || r.Unmapped != 1 || len(r.UnmappedChecks) != 1 || r.UnmappedChecks[0].Count != 1 {
		t.Errorf("report %+v, want one finding", r)
	}
}
