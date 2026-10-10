package groundtruth

// benchmark.json: the machine-readable form of the labelled-lab and noise-estate tables, written
// after the run so the release pipeline can attach it (competitive delta 2026-10-09 shortfall #2).
// Default path lab/local/out/benchmark.json (git-ignored); GROUNDTRUTH_JSON overrides it.
// Both views are always present: "labelled" counts a reported pending-feature path as a hit;
// "real_world" counts every path matching a false_positive or pending-feature label as a false
// positive and does not credit an expected label met only through such a path.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type benchFrac struct {
	Value *float64 `json:"value"` // null when the denominator is 0
	Num   int      `json:"num"`
	Den   int      `json:"den"`
}

func frac(a, b int) benchFrac {
	f := benchFrac{Num: a, Den: b}
	if b > 0 {
		v := math.Round(float64(a)/float64(b)*10000) / 10000
		f.Value = &v
	}
	return f
}

func fracPtr(a, b int) *benchFrac { f := frac(a, b); return &f }

type benchView struct {
	Precision     benchFrac  `json:"precision"`
	PrecisionHigh benchFrac  `json:"precision_at_threshold"`
	Recall        benchFrac  `json:"recall"`
	RecallHigh    benchFrac  `json:"recall_at_threshold"`
	RecallBand    *benchFrac `json:"recall_in_band,omitempty"` // labelled lab only (noise labels have no band)
}

type benchFP struct {
	Label string  `json:"label,omitempty"` // ground-truth id, empty when unlabelled
	Score float64 `json:"score"`
	Rule  string  `json:"rule,omitempty"`
	Chain string  `json:"chain"`
}

type benchEstate struct {
	Estate                  string    `json:"estate"`
	Truth                   string    `json:"truth"`
	Authored                string    `json:"authored"`
	Threshold               float64   `json:"threshold"`
	Expected                int       `json:"expected_paths"`
	Reported                int       `json:"reported_paths"`
	ReportedHigh            int       `json:"reported_paths_at_threshold"`
	Unlabelled              int       `json:"unlabelled_paths"`
	Labelled                benchView `json:"labelled"`
	RealWorld               benchView `json:"real_world"`
	RealWorldFalsePositives []benchFP `json:"real_world_false_positives"`
	// FindingLevel scores the prioritize ranking (labelled lab only; findinglevel_test.go).
	FindingLevel *benchFindingLevel `json:"finding_level,omitempty"`
}

var (
	benchMu  sync.Mutex
	benchOut = map[string]benchEstate{}
)

func recordBench(name string, e benchEstate) {
	benchMu.Lock()
	defer benchMu.Unlock()
	if e.RealWorldFalsePositives == nil {
		e.RealWorldFalsePositives = []benchFP{}
	}
	benchOut[name] = e
}

// writeBenchJSON runs from TestMain after m.Run; it writes nothing when no estate was scored
// (e.g. -run Golden).
func writeBenchJSON() error {
	benchMu.Lock()
	defer benchMu.Unlock()
	if len(benchOut) == 0 || repoRoot == "" {
		return nil
	}
	out := os.Getenv("GROUNDTRUTH_JSON")
	if out == "" {
		out = filepath.Join(repoRoot, "lab", "local", "out", "benchmark.json")
	}
	doc := map[string]any{
		"schema":     "nimbus.benchmark/v1",
		"date":       time.Now().Format("2006-01-02"),
		"strict":     strict(),
		"live_cloud": false, // no live-cloud run exists yet (gap analysis O1)
		"estates":    benchOut,
		"notes": "labelled: a reported pending-feature path counts as a hit. real_world: a path matching a " +
			"false_positive or pending-feature label is a false positive, and an expected label met only through " +
			"such a path is not found. The labelled lab is authored by the project (self-referential); the noise " +
			"estate was authored independently, but the engine's noise round was tuned on its false positives, so its " +
			"precision is in-sample, not held-out. finding_level scores the prioritize ranking against the same labels " +
			"(risk.CriticalOnNonExposed; target 0).",
	}
	for _, name := range []string{"labelled_lab", "noise_estate"} {
		e, ok := benchOut[name]
		if !ok {
			continue
		}
		fmt.Printf("benchmark %-12s precision labelled %s / real-world %s | precision@%.0f labelled %s / real-world %s | recall@%.0f labelled %s / real-world %s\n",
			name, fracString(e.Labelled.Precision), fracString(e.RealWorld.Precision),
			e.Threshold, fracString(e.Labelled.PrecisionHigh), fracString(e.RealWorld.PrecisionHigh),
			e.Threshold, fracString(e.Labelled.RecallHigh), fracString(e.RealWorld.RecallHigh))
		if e.FindingLevel != nil {
			fmt.Printf("benchmark %-12s finding-level: %s\n", name, e.FindingLevel)
		}
	}
	fmt.Printf("benchmark json: %s\n", out)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, append(data, '\n'), 0o644)
}
