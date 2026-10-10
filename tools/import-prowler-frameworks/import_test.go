package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const sentinel = "SENTINEL_UPSTREAM_TEXT_7f3a"

// writeTree creates a synthetic prowler/compliance tree with a CIS file, a non-CIS file and a
// universal (top-level, multi-provider) file.
func writeTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	comp := filepath.Join(root, "prowler", "compliance")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(comp, "aws"), 0o755))
	cis := map[string]any{
		"Framework": "CIS", "Name": "CIS Test Benchmark", "Version": "9.0", "Provider": "AWS",
		"Description": "framework " + sentinel,
		"Requirements": []any{
			map[string]any{"Id": "1.10", "Description": "desc " + sentinel, "Checks": []any{"s3_bucket_public_access", "zz_unknown_check", "s3_bucket_public_access"},
				"Attributes": []any{map[string]any{"Section": "1 Section " + sentinel, "RationaleStatement": "why " + sentinel}}},
			map[string]any{"Id": "1.2", "Description": "manual " + sentinel, "Checks": []any{}, "Attributes": []any{map[string]any{"Section": "1 " + sentinel}}},
			map[string]any{"Id": "2.1", "Description": "ingest only " + sentinel, "Checks": []any{"zz_only_prowler"}},
		},
	}
	pci := map[string]any{
		"Framework": "PCI", "Name": "PCI DSS 4.0", "Version": "4.0", "Provider": "AWS", "Description": "pci " + sentinel,
		"Requirements": []any{
			map[string]any{"Id": "1.2.1", "Name": "pci name " + sentinel, "Description": strings.Repeat("d", 300), "Checks": []any{"s3_bucket_public_access"},
				"Attributes": []any{map[string]any{"Section": "1.2: NSC " + sentinel}}},
			map[string]any{"Id": "3.4.1", "Description": strings.Repeat("x", 200) + sentinel, "Checks": []any{"zz_only_prowler"}},
		},
	}
	uni := map[string]any{
		"framework": "CIS-Controls", "name": "CIS Controls v8.1", "version": "8.1", "description": "u " + sentinel,
		"requirements": []any{
			map[string]any{"id": "1.1", "name": "uni name " + sentinel, "description": "d " + sentinel, "attributes": map[string]any{"Section": "1. " + sentinel},
				"checks": map[string]any{"aws": []any{"s3_bucket_public_access"}, "gcp": []any{"zz_gcp_check"}}},
		},
	}
	for p, v := range map[string]any{"aws/cis_9.0_aws.json": cis, "aws/pci_4.0_aws.json": pci, "cis_controls_8.1.json": uni} {
		b, _ := json.MarshalIndent(v, "", " ")
		must(os.WriteFile(filepath.Join(comp, p), b, 0o644))
	}
	return root
}

func runImport(t *testing.T, root string, extra ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "frameworks")
	args := append([]string{"--from-dir", root, "--out", out}, extra...)
	if err := run(args); err != nil {
		t.Fatalf("run: %v", err)
	}
	return out
}

func readAll(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range ents {
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		b.WriteString("=== " + e.Name() + "\n")
		b.Write(data)
	}
	return b.String()
}

func loadOut(t *testing.T, dir, key string) outFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, key+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var f outFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestConvertDefaultsNoUpstreamText(t *testing.T) {
	root := writeTree(t)
	out := runImport(t, root)
	all := readAll(t, out)
	if strings.Contains(all, sentinel) {
		t.Fatalf("upstream text leaked by default:\n%s", all)
	}
	cis := loadOut(t, out, "cis_9.0_aws")
	if cis.License != "Apache-2.0" || !strings.Contains(cis.Attribution, "Prowler") || !strings.HasPrefix(cis.Source, "prowler@5.44.0 (") {
		t.Errorf("provenance: %+v", cis)
	}
	if cis.ReferenceURL == "" || !strings.Contains(cis.ReferenceURL, "cisecurity.org") {
		t.Errorf("CIS reference_url missing: %q", cis.ReferenceURL)
	}
	if cis.UpstreamPath != "prowler/compliance/aws/cis_9.0_aws.json" || !strings.Contains(cis.UpstreamURL, "/blob/") {
		t.Errorf("upstream: %q %q", cis.UpstreamPath, cis.UpstreamURL)
	}
	if len(cis.Requirements) != 3 {
		t.Fatalf("reqs: %+v", cis.Requirements)
	}
	r := cis.Requirements[0]
	if r.ID != "1.10" {
		t.Errorf("ids must be verbatim and in upstream order: %+v", cis.Requirements)
	}
	if strings.Join(r.Checks, ",") != "PROWLER:zz_unknown_check,S3_PUBLIC_BUCKET" {
		t.Errorf("checks: %v", r.Checks)
	}
	if strings.Join(r.ProwlerChecks, ",") != "s3_bucket_public_access,zz_unknown_check" {
		t.Errorf("prowler_checks: %v", r.ProwlerChecks)
	}
	if r.Title == "" || r.Section != "" {
		t.Errorf("title should be the nimbus catalog title, no section: %+v", r)
	}
	if cis.Requirements[1].Title != "" || len(cis.Requirements[1].Checks) != 0 {
		t.Errorf("manual control: %+v", cis.Requirements[1])
	}
	if cis.Requirements[2].Title != "" {
		t.Errorf("prowler-only control must have no title: %+v", cis.Requirements[2])
	}
	uni := loadOut(t, out, "cis_controls_8.1")
	if strings.Join(uni.Requirements[0].Checks, ",") != "PROWLER:zz_gcp_check,S3_PUBLIC_BUCKET" || uni.Provider != "aws,gcp" {
		t.Errorf("universal union: %+v", uni)
	}
	idx, err := os.ReadFile(filepath.Join(out, "index.yaml"))
	if err != nil || !strings.Contains(string(idx), "sha256") || !strings.Contains(string(idx), "cis_9.0_aws") {
		t.Errorf("index: %s %v", idx, err)
	}
}

func TestConvertIsDeterministic(t *testing.T) {
	root := writeTree(t)
	a, b := readAll(t, runImport(t, root)), readAll(t, runImport(t, root))
	if a != b {
		t.Fatal("output differs between runs")
	}
}

func TestCISTextFlag(t *testing.T) {
	root := writeTree(t)
	out := runImport(t, root, "--cis-text")
	cis := loadOut(t, out, "cis_9.0_aws")
	if !strings.Contains(cis.Requirements[0].Title, sentinel) || !strings.Contains(cis.Requirements[0].Section, sentinel) || cis.TextPolicy != "upstream" {
		t.Errorf("--cis-text should copy CIS text: %+v", cis.Requirements[0])
	}
	// --cis-text does not unlock non-CIS text.
	if strings.Contains(readAllKey(t, out, "pci_4.0_aws"), sentinel) {
		t.Error("--cis-text leaked non-CIS text")
	}
}

func TestUpstreamTextFlagIsNonCISOnly(t *testing.T) {
	root := writeTree(t)
	out := runImport(t, root, "--upstream-text")
	pci := loadOut(t, out, "pci_4.0_aws")
	if !strings.Contains(pci.Requirements[0].Title, sentinel) {
		t.Errorf("--upstream-text should copy the requirement Name: %+v", pci.Requirements[0])
	}
	if d := pci.Requirements[1].Title; len([]rune(d)) > 160 || d == "" {
		t.Errorf("description fallback must be truncated to 160 chars: %q", d)
	}
	for _, k := range []string{"cis_9.0_aws", "cis_controls_8.1"} {
		if strings.Contains(readAllKey(t, out, k), sentinel) {
			t.Errorf("--upstream-text leaked CIS text into %s", k)
		}
	}
}

func readAllKey(t *testing.T, dir, key string) string {
	data, err := os.ReadFile(filepath.Join(dir, key+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRefusesFileWithoutRequirements(t *testing.T) {
	root := writeTree(t)
	p := filepath.Join(root, "prowler", "compliance", "aws", "broken_aws.json")
	if err := os.WriteFile(p, []byte(`{"Framework":"X","Name":"x","Version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"--from-dir", root, "--out", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "broken_aws") {
		t.Fatalf("want refusal naming the file, got %v", err)
	}
}

func TestNoNetworkRequiresFromDir(t *testing.T) {
	t.Setenv("CLOUD_POSTURE_NO_NETWORK", "1")
	err := run([]string{"--out", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "--from-dir") {
		t.Fatalf("want refusal, got %v", err)
	}
}

func TestRefusesTagShaMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/git/ref/tags/") {
			w.Write([]byte(`{"object":{"sha":"1111111111111111111111111111111111111111","type":"commit"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	t.Setenv("CLOUD_POSTURE_NO_NETWORK", "")
	err := run([]string{"--out", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "resolves to") {
		t.Fatalf("want sha mismatch refusal, got %v", err)
	}
}
