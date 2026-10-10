package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector"
	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Verify-3 defect 3: lifecycle scopes come from declared targets, and a scope never
// spans two IaC roots or two config labels.

// activeByRoot counts open/reopened FAIL findings per IaC scan root.
func activeByRoot(t *testing.T) map[string]int {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.DB().Query(`SELECT COALESCE(json_extract(tags, '$.` + store.TagScanRoot + `'), ''), COUNT(*) FROM findings
	  WHERE status = 'FAIL' AND state IN ('open','reopened') GROUP BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var r string
		var n int
		rows.Scan(&r, &n)
		m[filepath.Base(r)] = n
	}
	return m
}

// 3(a), repro scratchpad verify-3/cli/life/c: prod/a.tf and stg/a.tf are identical
// (same root-relative file and address). Deleting stg/a.tf must not resolve prod's
// finding.
func TestIaCRootsDoNotShareFindings(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	t.Setenv("PATH", "/nonexistent") // no checkov/trivy
	bucket := "resource \"aws_s3_bucket\" \"pub\" {\n  bucket = \"pub\"\n  acl    = \"public-read\"\n}\n"
	sg := "resource \"aws_security_group\" \"sg\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n"
	prod, stg := filepath.Join(dir, "prod"), filepath.Join(dir, "stg")
	for _, d := range []string{prod, stg} {
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "a.tf"), []byte(bucket), 0o644)
	}
	os.WriteFile(filepath.Join(stg, "b.tf"), []byte(sg), 0o644)
	runErr(t, "scan", "--iac", prod, "-o", "summary")
	runErr(t, "scan", "--iac", stg, "-o", "summary")
	before := activeByRoot(t)
	if before["prod"] == 0 || before["stg"] <= before["prod"] {
		t.Fatalf("setup: both roots must hold their own open findings: %v", before)
	}
	os.Remove(filepath.Join(stg, "a.tf"))
	runErr(t, "scan", "--iac", stg, "-o", "summary")
	after := activeByRoot(t)
	if after["prod"] != before["prod"] {
		t.Fatalf("deleting stg/a.tf changed prod's open findings: before %v after %v", before, after)
	}
	if after["stg"] != before["stg"]-before["prod"] {
		t.Errorf("stg's deleted bucket findings not resolved: before %v after %v", before, after)
	}
}

type labelCollector struct{ mode *string }

func (f labelCollector) Name() string     { return "label-aws" }
func (f labelCollector) Provider() string { return "aws" }
func labelF(rid, label string) model.Finding {
	return core.Check{CheckID: "chk_" + rid, Provider: "aws", Account: "123456789012", AccountLabel: label,
		Resource: model.Resource{ID: "arn:aws:s3:::" + rid, Type: "aws_s3_bucket", Name: rid}, Pass: false, Detail: "public"}.Finding(time.Now())
}
func (f labelCollector) Collect(ctx context.Context, spec collector.AccountSpec, g *graph.Graph) (collector.Result, error) {
	switch *f.mode {
	case "prod":
		return collector.Result{Findings: []model.Finding{labelF("a", "prod"), labelF("b", "prod")}}, nil
	case "west":
		return collector.Result{Findings: []model.Finding{labelF("w", "west")}}, nil
	case "west-empty":
		return collector.Result{}, nil
	}
	return collector.Result{}, nil
}

// 3(b), from the verify-3 CLI probe: two config labels for the same AWS account id
// (e.g. different regions). A clean scan of "west" must not resolve "prod"'s findings.
func TestSameAccountConfigLabelsDoNotResolveEachOther(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfg := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(cfg, []byte("accounts:\n  prod:\n    provider: aws\n  west:\n    provider: aws\n"), 0o644)
	mode := "prod"
	old := collectorHook
	t.Cleanup(func() { collectorHook = old; flagConfig = "" })
	collectorHook = func(o *collector.Options) {
		o.Collectors = map[string]collector.Collector{"aws": labelCollector{&mode}}
	}
	scan := func(acct string) {
		runErr(t, "scan", "--config", cfg, "--accounts", acct, "--tools", "native", "-o", "summary")
	}
	scan("prod")
	mode = "west"
	scan("west")
	st := findingStates(t)
	for _, k := range []string{"NIMBUS:chk_a:a", "NIMBUS:chk_b:b", "NIMBUS:chk_w:w"} {
		if !model.IsActive(st[k]) {
			t.Errorf("%s is %q after a clean scan of the other label, want active: %v", k, st[k], st)
		}
	}
	// The west label's own finding still resolves when west comes back clean.
	mode = "west-empty"
	scan("west")
	st = findingStates(t)
	if st["NIMBUS:chk_w:w"] != model.StateResolved || !model.IsActive(st["NIMBUS:chk_a:a"]) {
		t.Errorf("west's clean rescan must resolve only west's finding: %v", st)
	}
}

// 3(c) at the CLI: an uncollected-NSG collector error becomes a coverage row.
func TestUncollectedNSGCoverageRow(t *testing.T) {
	ce := collector.CollectError{Provider: "azure", Account: "corp", API: "network.nsgs", Reason: core.ReasonNotFound,
		Message: "network security group /x/ghost-nsg (referenced by /x/vm) was not collected; internet exposure through it is unknown"}
	rows := coverageEntries(nil, scanOptions{CollectErrors: []collector.CollectError{ce}})
	if len(rows) != 1 || rows[0].API != "network.nsgs" || rows[0].Status == store.CoverageOK || rows[0].Provider != "azure" {
		t.Fatalf("coverage rows = %+v", rows)
	}
}
