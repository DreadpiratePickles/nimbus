package iac

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
)

// Verification 3 defect 2 (HIGH): a file that does not parse (syntax error, over the size limit,
// too deep) failed open. Its IAC_PARSE_LIMIT ERROR finding did not count for --fail-on and was
// left out of SARIF, so appending 300 `[` to a file with a public bucket made
// `scan --iac --fail-on high` exit 0 (scratchpad verify-3/evade/{bad,size,syn}, me/r).
// The scan must name every such file as unscanned (lifecycle must not resolve its findings) and
// emit an ERROR finding that the gate and SARIF/JSON output include.

const publicBucket = "resource \"aws_s3_bucket\" \"pub\" {\n  bucket = \"x\"\n  acl    = \"public-read\"\n}\n"

func evadeShapes() map[string]struct{ src, reason string } {
	return map[string]struct{ src, reason string }{
		// verify-3/evade/bad/main.tf: 300 nested brackets appended.
		"depth": {publicBucket + "locals {\n  pad = " + strings.Repeat("[", 300) + "1" + strings.Repeat("]", 300) + "\n}\n", "nesting"},
		// verify-3/evade/size/main.tf: padded past 2 MiB with whitespace.
		"size": {publicBucket + strings.Repeat(" ", DefaultMaxFileBytes), "size"},
		// verify-3/me/r/a.tf: garbage before the bucket, the file does not parse.
		"syntax": {"}}} garbage(((\n" + publicBucket, "syntax"},
		// verify-3/evade/syn/main.tf: the bucket parses, a later attribute does not.
		"partial": {publicBucket + "locals {\n  x = = \n}\n", "syntax"},
	}
}

func TestUnparseableFileIsUnscannedAndBlocksTheGate(t *testing.T) {
	for name, c := range evadeShapes() {
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			writeTree(t, d, map[string]string{"main.tf": c.src, "ok.tf": "resource \"aws_instance\" \"web\" {\n  ami = \"x\"\n  metadata_options {\n    http_tokens = \"required\"\n  }\n}\n"})
			res, err := ScanTerraformResult(d, time.Unix(0, 0))
			var ue *UnscannedError
			if !errors.As(err, &ue) || len(ue.Files) != 1 || ue.Files[0] != "main.tf" {
				t.Fatalf("want an UnscannedError naming main.tf, got %v", err)
			}
			if len(res.UnscannedFiles) != 1 || res.UnscannedFiles[0] != "main.tf" {
				t.Fatalf("UnscannedFiles = %v, want [main.tf]", res.UnscannedFiles)
			}
			if r := res.UnscannedReasons["main.tf"]; !strings.Contains(r, c.reason) {
				t.Errorf("reason %q does not mention %q", r, c.reason)
			}
			var gap *model.Finding
			for i, f := range res.Findings {
				if f.CanonicalID == "IAC_PARSE_LIMIT" {
					gap = &res.Findings[i]
				}
			}
			if gap == nil {
				t.Fatalf("no IAC_PARSE_LIMIT finding in %+v", res.Findings)
			}
			if gap.Status != model.Error || gap.File != "main.tf" || gap.Severity != model.High || gap.Tags[output.TagScanGap] == "" {
				t.Errorf("gap finding = status %s file %s severity %s tags %v", gap.Status, gap.File, gap.Severity, gap.Tags)
			}
			// --fail-on high (and any lower or higher threshold) must not pass.
			for _, sev := range []string{"critical", "high", "low"} {
				if n := output.GateCount(res.Findings, sev); n == 0 {
					t.Errorf("--fail-on %s: gate count 0, the scan would exit 0", sev)
				}
			}
			sarif := output.SARIF(res.Findings)
			results := sarif["runs"].([]map[string]any)[0]["results"].([]map[string]any)
			found := false
			for _, r := range results {
				if r["ruleId"] == "IAC_PARSE_LIMIT" && r["level"] == "error" {
					found = true
				}
			}
			if !found {
				t.Errorf("SARIF has no error-level IAC_PARSE_LIMIT result: %v", results)
			}
		})
	}
}

// ScanTerraform keeps its signature: findings for every file plus an error naming the unscanned
// ones, so `scan` does not declare a root with an unscanned file as fully examined.
func TestScanTerraformReportsUnscannedAsError(t *testing.T) {
	d := t.TempDir()
	writeTree(t, d, map[string]string{"main.tf": evadeShapes()["syntax"].src, "sub/ok.tf": publicBucket})
	fs, err := ScanTerraform(d, time.Unix(0, 0))
	var ue *UnscannedError
	if !errors.As(err, &ue) || ue.Reasons["main.tf"] == "" {
		t.Fatalf("err = %v", err)
	}
	var fail, gap bool
	for _, f := range fs {
		fail = fail || (f.Status == model.Fail && f.File == "sub/ok.tf")
		gap = gap || (f.Status == model.Error && f.File == "main.tf")
	}
	if !fail || !gap {
		t.Errorf("want the FAIL from sub/ok.tf and the ERROR for main.tf: %+v", fs)
	}
	// A clean root reports no unscanned files and no error.
	clean := t.TempDir()
	writeTree(t, clean, map[string]string{"a.tf": publicBucket})
	if res, err := ScanTerraformResult(clean, time.Unix(0, 0)); err != nil || len(res.UnscannedFiles) != 0 {
		t.Errorf("clean root: err=%v unscanned=%v", err, res.UnscannedFiles)
	}
}

// Verification 3 defect 3 (HIGH): finding ids were derived from the root-relative file, so
// stg/a.tf and prod/a.tf with identical content had the same id and deleting stg/a.tf resolved
// prod's finding (scratchpad verify-3/cli/life/c).
func TestIaCFindingIDsAreDistinctAcrossRoots(t *testing.T) {
	base := t.TempDir()
	writeTree(t, base, map[string]string{"stg/a.tf": publicBucket, "prod/a.tf": publicBucket, "stg/deep.tf": evadeShapes()["depth"].src, "prod/deep.tf": evadeShapes()["depth"].src})
	ids := func(root string) map[string]string {
		fs, _ := ScanTerraform(root, time.Unix(0, 0))
		out := map[string]string{}
		for _, f := range fs {
			if f.Status == model.Fail || f.Status == model.Error {
				out[f.CanonicalID+" "+f.File] = f.ID
			}
		}
		return out
	}
	stg, prod := ids(filepath.Join(base, "stg")), ids(filepath.Join(base, "prod"))
	if len(stg) != 2 || len(prod) != 2 {
		t.Fatalf("stg=%v prod=%v", stg, prod)
	}
	for k, id := range stg {
		if prod[k] == id {
			t.Errorf("%s: stg and prod share id %s", k, id)
		}
	}
	// Stable for the same root, however the path is spelled.
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}
	again := ids("./stg/")
	for k, id := range stg {
		if again[k] != id {
			t.Errorf("%s: id changed between %q and ./stg/: %s vs %s", k, filepath.Join(base, "stg"), id, again[k])
		}
	}
}
