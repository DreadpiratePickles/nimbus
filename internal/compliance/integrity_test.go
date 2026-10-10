package compliance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"gopkg.in/yaml.v3"
)

const pythonBundle = "../../python/nimbus/frameworks/frameworks.yaml"

func TestImportedFrameworksLoad(t *testing.T) {
	fws := Frameworks()
	imported := 0
	for k, fw := range fws {
		if fw.Provenance == nil {
			continue
		}
		imported++
		p := fw.Provenance
		if p.License == "" || p.Attribution == "" || !strings.HasPrefix(p.Source, "prowler@") {
			t.Errorf("%s: missing provenance: %+v", k, p)
		}
	}
	if imported != 112 {
		t.Errorf("imported frameworks = %d, want 112", imported)
	}
	for _, k := range []string{"cis_aws", "cis_azure", "cis_gcp", "cis_k8s", "cis_github", "nist_800_53", "pci_dss", "hipaa", "gdpr", "iso_27001", "soc2"} {
		if fws[k] == nil || fws[k].Provenance != nil {
			t.Errorf("hand-written framework %s missing or overridden", k)
		}
	}
	// Hand-written contents unchanged.
	if fws["cis_aws"].Controls["1.5"] != "Ensure MFA is enabled for the root user account" || len(fws["cis_aws"].Controls) != 42 {
		t.Errorf("cis_aws changed: %d controls", len(fws["cis_aws"].Controls))
	}
}

func TestBuildMapsFindingsByControlChecks(t *testing.T) {
	fs := []model.Finding{
		{ID: "a", Status: model.Fail, Severity: model.High, CanonicalID: "IAM_USER_NO_MFA", Resource: model.Resource{Name: "alice"}},
		{ID: "b", Status: model.Pass, Severity: model.Low, CanonicalID: "PROWLER:account_maintain_current_contact_details", Resource: model.Resource{Name: "acct"}},
	}
	rep, err := Build("cis_3.0_aws", fs, "")
	if err != nil {
		t.Fatal(err)
	}
	st := map[string]ControlStatus{}
	for _, c := range rep.Controls {
		st[c.ID] = c
	}
	if st["1.10"].Status != "FAIL" || st["1.1"].Status != "PASS" {
		t.Fatalf("1.10=%+v 1.1=%+v", st["1.10"], st["1.1"])
	}
	if rep.Assessed != rep.Passing+rep.Failing || rep.Assessed < 2 {
		t.Errorf("assessed: %+v", rep.Assessed)
	}
	cov := rep.Coverage
	if cov == nil || cov.Native+cov.ProwlerIngest+cov.Manual != rep.Total || cov.Native == 0 || cov.ProwlerIngest == 0 {
		t.Errorf("coverage: %+v total %d", cov, rep.Total)
	}
	md := rep.Markdown()
	want := fmt.Sprintf("%d of %d controls assessed", rep.Assessed, rep.Total)
	if !strings.Contains(md, want) || !strings.Contains(md, fmt.Sprintf("%d assessable natively, %d via Prowler ingest, %d manual", cov.Native, cov.ProwlerIngest, cov.Manual)) {
		t.Errorf("markdown denominator missing:\n%s", md[:400])
	}
	// A finding mapped both by compliance and by checks counts once.
	fs[0].Compliance = map[string][]string{"cis_3.0_aws": {"1.10"}}
	rep2, _ := Build("cis_3.0_aws", fs, "")
	for _, c := range rep2.Controls {
		if c.ID == "1.10" && c.Failed != 1 {
			t.Errorf("double counted: %+v", c)
		}
	}
}

func TestCoverageHelper(t *testing.T) {
	c, ok := Coverage("cis_aws")
	if !ok || c.Native == 0 || c.ProwlerIngest != 0 || c.Native+c.Manual != len(Frameworks()["cis_aws"].Controls) {
		t.Errorf("cis_aws coverage: %+v %v", c, ok)
	}
	if c, ok := Coverage("soc2"); !ok || c.Native == 0 {
		t.Errorf("soc2 coverage should count weakness-derived controls: %+v", c)
	}
	if _, ok := Coverage("no_such_framework"); ok {
		t.Error("unknown framework")
	}
	for k, fw := range Frameworks() {
		c, _ := Coverage(k)
		if c.Native+c.ProwlerIngest+c.Manual != len(fw.Controls) {
			t.Errorf("%s: coverage %+v does not add up to %d", k, c, len(fw.Controls))
		}
	}
}

// TestFrameworkIntegrity parses the YAML sources directly (not through maps, which would hide
// duplicates) and fails with file:line.
func TestFrameworkIntegrity(t *testing.T) {
	cat := catalog.Default()
	files, err := fs.Glob(importedFS, "frameworks/*.yaml")
	if err != nil || len(files) < 100 {
		t.Fatalf("embedded frameworks: %d %v", len(files), err)
	}
	keys := map[string]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "/index.yaml") {
			continue
		}
		data, _ := fs.ReadFile(importedFS, name)
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		root := doc.Content[0]
		top := map[string]*yaml.Node{}
		for i := 0; i+1 < len(root.Content); i += 2 {
			top[root.Content[i].Value] = root.Content[i+1]
		}
		for _, f := range []string{"key", "license", "attribution", "source", "upstream_url", "text_policy"} {
			if n := top[f]; n == nil || strings.TrimSpace(n.Value) == "" {
				t.Errorf("internal/compliance/%s:1: missing %q", name, f)
			}
		}
		if k := top["key"]; k != nil {
			if prev, dup := keys[k.Value]; dup {
				t.Errorf("internal/compliance/%s: key %q also in %s", name, k.Value, prev)
			}
			keys[k.Value] = name
			if want := strings.TrimSuffix(filepath.Base(name), ".yaml"); k.Value != want {
				t.Errorf("internal/compliance/%s:%d: key %q != file name", name, k.Line, k.Value)
			}
		}
		reqs := top["requirements"]
		if reqs == nil || len(reqs.Content) == 0 {
			t.Errorf("internal/compliance/%s: no requirements", name)
			continue
		}
		seen := map[string]int{}
		for _, r := range reqs.Content {
			var id *yaml.Node
			var checks *yaml.Node
			for i := 0; i+1 < len(r.Content); i += 2 {
				switch r.Content[i].Value {
				case "id":
					id = r.Content[i+1]
				case "checks":
					checks = r.Content[i+1]
				}
			}
			if id == nil || id.Value == "" {
				t.Errorf("internal/compliance/%s:%d: requirement without id", name, r.Line)
				continue
			}
			if first, dup := seen[id.Value]; dup {
				t.Errorf("internal/compliance/%s:%d: duplicate requirement id %q (first at line %d)", name, id.Line, id.Value, first)
			}
			seen[id.Value] = id.Line
			if checks == nil {
				continue
			}
			for _, c := range checks.Content {
				if strings.HasPrefix(c.Value, "PROWLER:") {
					continue
				}
				if _, ok := cat.Get(c.Value); !ok {
					t.Errorf("internal/compliance/%s:%d: dangling check ref %q (not in internal/catalog/catalog.yaml)", name, c.Line, c.Value)
				}
			}
		}
	}
	// Imported keys never shadow hand-written ones.
	var hand file
	_ = yaml.Unmarshal(frameworksYAML, &hand)
	var extra file
	_ = yaml.Unmarshal(extraYAML, &extra)
	for k := range keys {
		if hand.Frameworks[k] != nil || extra.Frameworks[k] != nil {
			t.Errorf("imported key %s collides with a hand-written framework", k)
		}
	}
}

// TestGoPythonParity: the Python bundle declares the same frameworks and control counts as Go.
func TestGoPythonParity(t *testing.T) {
	data, err := os.ReadFile(pythonBundle)
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Frameworks map[string]struct {
			ControlCount int            `json:"control_count"`
			Controls     map[string]any `json:"controls"`
		} `json:"frameworks"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("%s: %v", pythonBundle, err)
	}
	fws := Frameworks()
	if len(b.Frameworks) != len(fws) {
		t.Errorf("python has %d frameworks, go %d", len(b.Frameworks), len(fws))
	}
	for k, fw := range fws {
		p, ok := b.Frameworks[k]
		if !ok || len(p.Controls) != len(fw.Controls) || p.ControlCount != len(fw.Controls) {
			t.Errorf("%s: go %d controls, python %d (declared %d)", k, len(fw.Controls), len(p.Controls), p.ControlCount)
		}
	}
}

// TestPythonBundleUpToDate guards the generated Python bundle against drift.
func TestPythonBundleUpToDate(t *testing.T) {
	want, err := BundleJSON()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(pythonBundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("python/nimbus/frameworks/frameworks.yaml is stale; regenerate with: go generate ./internal/compliance/ (or go run ./internal/compliance/gen)")
	}
}

func TestPCI40UsesPCI40Numbering(t *testing.T) {
	letter := regexp.MustCompile(`\.[a-z]$`)
	for _, k := range []string{"pci_4.0_aws", "pci_4.0_azure", "pci_4.0_gcp", "pci_4.0_kubernetes"} {
		fw := Frameworks()[k]
		if fw == nil || fw.Version != "4.0" {
			t.Fatalf("%s missing or wrong version", k)
		}
		var ids []string
		for id := range fw.Controls {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		has125 := false
		for _, id := range ids {
			if letter.MatchString(id) {
				t.Errorf("%s: %q uses PCI DSS 3.2.1 lettered testing-procedure numbering", k, id)
			}
			if strings.Count(id, ".") < 2 {
				t.Errorf("%s: %q is not a PCI DSS 4.0 requirement id", k, id)
			}
			if strings.HasPrefix(id, "1.2.5.") {
				has125 = true
			}
		}
		if !has125 {
			t.Errorf("%s: no 4.0 requirement 1.2.5 sub-ids", k)
		}
	}
	// Contrast: the 3.2.1 file does use lettered ids, so the check above is meaningful.
	n := 0
	for id := range Frameworks()["pci_3.2.1_aws"].Controls {
		if letter.MatchString(id) {
			n++
		}
	}
	if n == 0 {
		t.Error("pci_3.2.1_aws should use 3.2.1 lettered ids")
	}
}
