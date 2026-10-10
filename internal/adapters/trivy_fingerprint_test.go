package adapters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Defect 19b: one CVE in two packages of the same image must stay two findings; the
// fixture's single vulnerability is cloned into a second package and a second path.
// (A second installed version of the same package at the same path is the same finding:
// see TestTrivyVersionBumpStillVulnerableKeepsFingerprint.)
func TestTrivyCVEsInDifferentPackagesDoNotCollapse(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "trivy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var vulns []any
	for _, r := range doc["Results"].([]any) {
		res := r.(map[string]any)
		vs, ok := res["Vulnerabilities"].([]any)
		if !ok || len(vs) == 0 {
			continue
		}
		orig := vs[0].(map[string]any)
		otherPkg := map[string]any{}
		otherVer := map[string]any{}
		for k, v := range orig {
			otherPkg[k], otherVer[k] = v, v
		}
		otherPkg["PkgName"] = "openssh-client"
		otherVer["PkgPath"] = "usr/lib/other/openssh.jar"
		res["Vulnerabilities"] = append(vs, otherPkg, otherVer)
		vulns = res["Vulnerabilities"].([]any)
	}
	if len(vulns) != 3 {
		t.Fatalf("fixture shape changed: %d vulnerabilities", len(vulns))
	}
	mutated, _ := json.Marshal(doc)
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	fs, err := Trivy{}.Parse(mutated, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	Finalize(fs, Options{Now: now})
	ids := map[string]string{}
	for _, f := range fs {
		if f.CheckID != "CVE-2024-6387" {
			continue
		}
		key := f.Tags["pkg"] + "@" + f.Tags["pkg_path"]
		if prev, dup := ids[f.ID]; dup {
			t.Errorf("%s and %s share fingerprint %s", prev, key, f.ID)
		}
		ids[f.ID] = key
	}
	if len(ids) != 3 {
		t.Fatalf("want 3 distinct CVE findings, got %d: %v", len(ids), ids)
	}
	// stable across parses
	again, _ := Trivy{}.Parse(mutated, Options{Now: now.Add(time.Hour)})
	Finalize(again, Options{Now: now.Add(time.Hour)})
	for _, f := range again {
		if f.CheckID == "CVE-2024-6387" {
			if _, ok := ids[f.ID]; !ok {
				t.Errorf("fingerprint not stable across scans: %s", f.ID)
			}
		}
	}
}
