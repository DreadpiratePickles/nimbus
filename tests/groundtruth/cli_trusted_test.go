package groundtruth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// labHome ingests the committed lab output into a fresh store with the lab config
// (trusted_cidrs: [203.0.113.0/24]) and returns the home dir and db path.
func labHome(t *testing.T) (string, string) {
	t.Helper()
	home := t.TempDir()
	db := filepath.Join(home, "posture.db")
	cfg, err := os.ReadFile(filepath.Join(repoRoot, "lab", "local", "cloud-posture.lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cloud-posture.yaml"), cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	cli(t, home, db, "ingest", filepath.Join(repoRoot, "lab", "local", "out", "estate.findings.json"), "--source", "native", "-o", "json")
	return home, db
}

// Track B3 item 2: config trusted_cidrs reaches analysis through the CLI. The seeded false
// positive F01 (SSH open only to the corporate 203.0.113.0/24) yields no path, rule chain or
// traversal, and a trusted suppressed entry with its reason, in JSON and in text. Every suppressed
// entry must be a hop of a seeded false positive (P1-LAB L1 added F06–F08).
func TestTrustedCIDRSuppressedThroughCLI(t *testing.T) {
	var gt groundTruth
	loadYAML(t, "lab/ground_truth.yaml", &gt)
	var f01 gtPath
	for _, p := range gt.Paths {
		if p.ID == "F01" {
			f01 = p
		}
	}
	home, db := labHome(t)

	var reported []*reportedPath
	if err := json.Unmarshal(cli(t, home, db, "paths", "--format", "json", "--limit", "0"), &reported); err != nil {
		t.Fatal(err)
	}
	for _, p := range reported {
		p.normalize()
		if falsePositiveHit(f01, p) || p.hops[f01.Hops[0]] {
			t.Errorf("F01 still reported: %.2f %s [%s]", p.Score, p.chain(), p.RuleID)
		}
	}

	var an struct {
		Suppressed []struct {
			NodeID   string   `json:"node_id"`
			Exposure string   `json:"exposure"`
			CIDRs    []string `json:"exposure_cidrs"`
			Reason   string   `json:"reason"`
		} `json:"suppressed"`
	}
	if err := json.Unmarshal(cli(t, home, db, "paths", "--format", "json", "--fixes"), &an); err != nil {
		t.Fatal(err)
	}
	// Every suppressed node must belong to a seeded false positive (F01, and since P1-LAB L1 the GCP
	// twin F06 (trusted) plus F07 / F08 (private: auth required, org-conditioned)); F01's
	// corporate-only instance must be among them as "trusted" with a reason.
	fpNodes := map[string]string{}
	for _, p := range gt.Paths {
		if p.Status != "false_positive" {
			continue
		}
		for _, h := range append(append([]string{}, p.Hops...), p.OptionalHops...) {
			fpNodes[h] = p.ID
		}
	}
	trusted, f01Seen := 0, false
	for _, s := range an.Suppressed {
		if _, ok := fpNodes[s.NodeID]; !ok {
			t.Errorf("suppressed %s (%s: %s) is not a hop of any false_positive label", s.NodeID, s.Exposure, s.Reason)
		}
		if s.Reason == "" {
			t.Errorf("suppressed %s has no reason", s.NodeID)
		}
		if s.Exposure == "trusted" {
			trusted++
		}
		if s.NodeID == f01.Hops[0] && s.Exposure == "trusted" {
			f01Seen = true
		}
	}
	if !f01Seen {
		t.Errorf("suppressed = %+v, want a trusted entry for %s with a reason", an.Suppressed, f01.Hops[0])
	}

	text := string(cli(t, home, db, "paths"))
	if want := fmt.Sprintf("suppressed (trusted): %d", trusted); trusted == 0 || !strings.Contains(text, want) {
		t.Errorf("paths text output lacks `%s`:\n%s", want, text)
	}
	if !strings.Contains(text, "203.0.113.0/24") || !strings.Contains(text, "nimbus-lab-corp-tools-01") {
		t.Errorf("paths text output does not name the suppressed node and its trusted range:\n%s", text)
	}
}
