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

// V2 defect 3: scopes come from the scan's declared targets, so a target whose last
// resource disappeared still resolves its findings.

func findingStates(t *testing.T) map[string]string {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := map[string]string{}
	rows, err := st.DB().Query("SELECT canonical_id || ':' || resource_name, state FROM findings WHERE status = 'FAIL'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var n, s string
		rows.Scan(&n, &s)
		m[n] = s
	}
	return m
}

func TestIaCRootWithNoResourcesLeftResolves(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	t.Setenv("PATH", "/nonexistent") // no checkov/trivy
	infra := filepath.Join(dir, "infra")
	os.MkdirAll(infra, 0o755)
	tf := filepath.Join(infra, "main.tf")
	os.WriteFile(tf, []byte(`resource "aws_s3_bucket" "pub" {
  bucket = "pub"
  acl    = "public-read"
}
`), 0o644)
	runErr(t, "scan", "--iac", infra, "-o", "summary")
	before := findingStates(t)
	open := 0
	for _, s := range before {
		if model.IsActive(s) {
			open++
		}
	}
	if open == 0 {
		t.Fatalf("setup: the public bucket must produce open findings: %v", before)
	}
	os.WriteFile(tf, []byte("variable \"x\" {}\n"), 0o644) // the bucket block is deleted
	runErr(t, "scan", "--iac", infra, "-o", "summary")
	for k, s := range findingStates(t) {
		if s != model.StateResolved {
			t.Errorf("%s is %s after its resource block was deleted, want resolved", k, s)
		}
	}
}

type declCollector struct{ mode *string }

func (f declCollector) Name() string     { return "decl-aws" }
func (f declCollector) Provider() string { return "aws" }
func declF(rid string) model.Finding {
	return core.Check{CheckID: "chk_" + rid, Provider: "aws", Account: "123456789012", AccountLabel: "prod",
		Resource: model.Resource{ID: "arn:aws:s3:::" + rid, Type: "aws_s3_bucket", Name: rid}, Pass: false, Detail: "public"}.Finding(time.Now())
}
func (f declCollector) Collect(ctx context.Context, spec collector.AccountSpec, g *graph.Graph) (collector.Result, error) {
	switch *f.mode {
	case "both":
		return collector.Result{Findings: []model.Finding{declF("a"), declF("b")}}, nil
	case "denied":
		return collector.Result{Errors: []error{&core.CollectError{Provider: "aws", Account: "prod", API: "s3:ListBuckets", Reason: core.ReasonAccessDenied, Message: "AccessDenied"}}}, nil
	case "fail":
		return collector.Result{}, &core.CollectError{Provider: "aws", Account: "prod", API: "sts", Reason: core.ReasonAccessDenied, Message: "AccessDenied"}
	}
	return collector.Result{}, nil // clean run, nothing left
}

func TestNativeAccountWithNoFindingsLeftResolves(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfg := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(cfg, []byte("accounts:\n  prod:\n    provider: aws\n  other:\n    provider: aws\n"), 0o644)
	mode := "both"
	old := collectorHook
	t.Cleanup(func() { collectorHook = old; flagConfig = "" })
	collectorHook = func(o *collector.Options) {
		o.Collectors = map[string]collector.Collector{"aws": declCollector{&mode}}
	}
	scan := func(accts string) {
		runErr(t, "scan", "--config", cfg, "--accounts", accts, "--tools", "native", "-o", "summary")
	}
	active := func() int {
		n := 0
		for _, s := range findingStates(t) {
			if model.IsActive(s) {
				n++
			}
		}
		return n
	}
	scan("prod")
	if active() == 0 {
		t.Fatalf("setup: no open findings")
	}
	for _, m := range []string{"denied", "fail"} {
		mode = m
		scan("prod")
		if active() != 2 {
			t.Fatalf("mode %s: a partial/failed run must not resolve by absence: %v", m, findingStates(t))
		}
	}
	mode = "none"
	scan("other") // a different account's clean run must not resolve prod's findings
	if active() != 2 {
		t.Fatalf("scanning another account resolved prod's findings: %v", findingStates(t))
	}
	scan("prod")
	if n := active(); n != 0 {
		t.Fatalf("clean run of prod with no findings left: %d still active: %v", n, findingStates(t))
	}
}
