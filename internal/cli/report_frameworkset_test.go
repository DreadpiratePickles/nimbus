package cli

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/compliance"
)

func TestResolveFrameworkSet(t *testing.T) {
	all := compliance.Frameworks()
	got, err := resolveFrameworkSet("default", []string{"aws", "kubernetes", "iac", "aws"}, all)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cis_aws", "cis_k8s", "nist_800_53", "pci_dss", "soc2", "hipaa", "iso_27001", "gdpr"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("default set = %v, want %v", got, want)
	}
	for _, k := range want {
		if _, ok := all[k]; !ok {
			t.Errorf("default key %s is not a loaded framework", k)
		}
	}
	got, _ = resolveFrameworkSet("", nil, all)
	if !reflect.DeepEqual(got, want[2:]) {
		t.Errorf("empty spec, no providers = %v, want %v", got, want[2:])
	}
	got, _ = resolveFrameworkSet("all", nil, all)
	if len(got) != len(all) {
		t.Errorf("all = %d frameworks, want %d", len(got), len(all))
	}
	got, err = resolveFrameworkSet("soc2, pci,c5_aws,soc2", []string{"aws"}, all)
	if err != nil || !reflect.DeepEqual(got, []string{"soc2", "pci_dss", "c5_aws"}) {
		t.Errorf("list = %v, %v", got, err)
	}
	got, _ = resolveFrameworkSet("cis", []string{"azure", "iac"}, all)
	if !reflect.DeepEqual(got, []string{"cis_azure"}) {
		t.Errorf("cis with azure in scope = %v", got)
	}
	if _, err := resolveFrameworkSet("soc2,nope_framework", nil, all); err == nil || !strings.Contains(err.Error(), "nope_framework") {
		t.Errorf("unknown framework must be an error naming it, got %v", err)
	}
}

func TestReportFrameworkSetCLI(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	testdata, _ := filepath.Abs(filepath.Join("..", "..", "testdata"))
	run(t, "ingest", testdata, "-o", "summary")
	m := len(compliance.Frameworks())

	// --framework all (the default) without --framework-set: curated default set + one note line.
	out := run(t, "report")
	note := fmt.Sprintf("of %d frameworks (framework-set default); use --framework-set all for every framework", m)
	if !strings.Contains(out, note) {
		t.Fatalf("default report lacks %q:\n%s", note, out)
	}
	if strings.Contains(out, "c5_aws") || !strings.Contains(out, "soc2") || !strings.Contains(out, "nist_800_53") {
		t.Fatalf("default report should list the curated set only:\n%s", out)
	}
	out2 := run(t, "report", "--framework", "all")
	if !strings.Contains(out2, note) {
		t.Fatalf("--framework all lacks the note:\n%s", out2)
	}

	out = run(t, "report", "--framework-set", "all")
	if !strings.Contains(out, fmt.Sprintf("%d of %d frameworks (framework-set all)", m, m)) || !strings.Contains(out, "c5_aws") {
		t.Fatalf("--framework-set all:\n%s", out)
	}
	if strings.Contains(out, "use --framework-set all") {
		t.Fatalf("explicit set must not print the hint:\n%s", out)
	}

	out = run(t, "report", "--framework-set", "soc2,pci")
	if !strings.Contains(out, fmt.Sprintf("2 of %d frameworks (framework-set soc2,pci)", m)) || !strings.Contains(out, "Frameworks: soc2, pci_dss") {
		t.Fatalf("--framework-set soc2,pci:\n%s", out)
	}

	if out, err := runErr(t, "report", "--framework-set", "nope_framework"); err == nil {
		t.Fatalf("unknown framework set entry must fail:\n%s", out)
	}
	if out, err := runErr(t, "report", "--framework", "soc2", "--framework-set", "all"); err == nil {
		t.Fatalf("--framework <key> with --framework-set must fail:\n%s", out)
	}

	// Existing single-framework behaviour is unchanged.
	out = run(t, "report", "--framework", "cis", "--provider", "aws")
	if !strings.Contains(out, "2.1.4") || strings.Contains(out, "framework-set") {
		t.Fatalf("single framework report changed:\n%s", out)
	}
}
