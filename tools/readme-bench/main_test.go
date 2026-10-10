package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `{"schema":"nimbus.benchmark/v1","date":"2026-10-09","live_cloud":false,"estates":{
 "labelled_lab":{"threshold":7,"expected_paths":20,"reported_paths":22,"reported_paths_at_threshold":21,"unlabelled_paths":0,
  "labelled":{"precision":{"num":22,"den":22},"precision_at_threshold":{"num":21,"den":21},"recall":{"num":20,"den":20},"recall_at_threshold":{"num":19,"den":20},"recall_in_band":{"num":20,"den":20}},
  "real_world":{"precision":{"num":21,"den":22},"precision_at_threshold":{"num":21,"den":21},"recall":{"num":20,"den":20},"recall_at_threshold":{"num":19,"den":20},"recall_in_band":{"num":20,"den":20}},
  "real_world_false_positives":[{"score":5}],
  "finding_level":{"critical_on_non_exposed":0,"benign_in_top_n":0,"top_n":10,"ranked_findings":62}},
 "noise_estate":{"threshold":7,"expected_paths":3,"reported_paths":4,"reported_paths_at_threshold":4,"unlabelled_paths":0,
  "labelled":{"precision":{"num":4,"den":4},"precision_at_threshold":{"num":4,"den":4},"recall":{"num":3,"den":3},"recall_at_threshold":{"num":3,"den":3}},
  "real_world":{"precision":{"num":4,"den":4},"precision_at_threshold":{"num":4,"den":4},"recall":{"num":3,"den":3},"recall_at_threshold":{"num":3,"den":3}},
  "real_world_false_positives":[]}}}`

func TestRenderUsesJSONNumbers(t *testing.T) {
	var d doc
	if err := json.Unmarshal([]byte(sample), &d); err != nil {
		t.Fatal(err)
	}
	block, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"| precision, real-world | 95.5% (21/22) | 100.0% (4/4) |",
		"| recall@7, labelled / real-world | 95.0% (19/20) / 95.0% (19/20) | 100.0% (3/3) / 100.0% (3/3) |",
		"| real-world false positives | 1 | 0 |",
		"| recall in band, real-world | 100.0% (20/20) | — |",
		"top 10 (target 0) | 0 | — |",
		"`live_cloud: false`", "**2026-10-09**", "in-sample", "20 expected attack paths",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("block lacks %q:\n%s", want, block)
		}
	}
	if !strings.HasPrefix(block, beginMarker) || !strings.HasSuffix(block, endMarker) {
		t.Errorf("markers missing")
	}
}

func TestRewriteAndCheck(t *testing.T) {
	dir := t.TempDir()
	js := filepath.Join(dir, "b.json")
	rd := filepath.Join(dir, "README.md")
	os.WriteFile(js, []byte(sample), 0o644)
	os.WriteFile(rd, []byte("# x\n\n"+beginMarker+" old -->\n| stale | 95.2% |\n"+endMarker+"\n\nReproduce: make groundtruth\n"), 0o644)
	if err := run(js, rd, true); err == nil {
		t.Fatal("-check must fail on a stale block")
	}
	if err := run(js, rd, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(rd)
	if strings.Contains(string(b), "95.2%") || !strings.HasPrefix(string(b), "# x\n\n") || !strings.HasSuffix(string(b), "\n\nReproduce: make groundtruth\n") {
		t.Fatalf("rewrite:\n%s", b)
	}
	if err := run(js, rd, true); err != nil {
		t.Fatalf("-check after rewrite: %v", err)
	}
}

func TestRewriteNeedsMarkers(t *testing.T) {
	if _, err := Rewrite([]byte("# no block\n"), "x"); err == nil {
		t.Fatal("missing markers must be an error")
	}
}
