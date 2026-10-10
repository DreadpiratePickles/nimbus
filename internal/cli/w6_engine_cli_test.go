package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Coordinator items 12–13 (after W6-ENGINE): `risk list` shows each rule's matches on the stored
// snapshot; `catalog unmapped` reads the stored database by default (works outside the repo, r4
// N10) and the repo goldens only with --golden.

func TestRiskListShowsMatchCountsOnLab(t *testing.T) {
	w6IngestLabNoConfig(t)
	out := run(t, "risk", "list")
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "aws-ec2-privesc-passrole-iam ") {
			line = l
		}
	}
	if !strings.Contains(line, "matches 1 (1 verified)") {
		t.Errorf("risk list must show the lab match count for the PassRole rule: %q\n%s", line, firstLines(out, 4))
	}
	if !strings.Contains(firstLines(out, 1), "stored snapshot") {
		t.Errorf("header must say the counts are a dry run on the stored snapshot:\n%s", firstLines(out, 2))
	}
	var doc []struct {
		ID      string `json:"id"`
		Matches *struct {
			Total    int `json:"total"`
			Verified int `json:"verified"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(run(t, "risk", "list", "--format", "json")), &doc); err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, r := range doc {
		if r.ID == "aws-ec2-privesc-passrole-iam" && r.Matches != nil && r.Matches.Total == 1 && r.Matches.Verified == 1 {
			ok = true
		}
	}
	if !ok {
		t.Error("risk list --format json lacks matches {total 1, verified 1} for aws-ec2-privesc-passrole-iam")
	}
}

func TestCatalogUnmappedReadsTheStoredDatabaseOutsideTheRepo(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	scan := filepath.Join(dir, "results_json.json")
	os.WriteFile(scan, []byte(`{"check_type":"terraform","results":{"failed_checks":[
 {"check_id":"CKV_AWS_19","check_name":"S3 encrypted","resource":"aws_s3_bucket.a","file_path":"/main.tf"},
 {"check_id":"CKV_FAKE_9","check_name":"Fake","resource":"aws_s3_bucket.a","file_path":"/main.tf"}]}}`), 0o644)
	run(t, "ingest", scan, "--source", "checkov", "-o", "summary")
	t.Chdir(dir) // outside the repository: no lab goldens to find
	out := run(t, "catalog", "unmapped", "--tool", "checkov", "--format", "json")
	var r unmappedJSON
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if r.Findings != 2 || r.Mapped != 1 || len(r.UnmappedChecks) != 1 || r.UnmappedChecks[0].CheckID != "CKV_FAKE_9" || r.Version != "" {
		t.Errorf("stored-DB report %+v", r)
	}
	txt := run(t, "catalog", "unmapped", "--tool", "checkov")
	if !strings.Contains(txt, "stored database") {
		t.Errorf("text must name its source:\n%s", txt)
	}
	if _, err := runErr(t, "catalog", "unmapped", "--tool", "trivy"); err == nil || !strings.Contains(err.Error(), "--golden") {
		t.Errorf("no trivy findings stored: the error must point at --golden / --from: %v", err)
	}
}
