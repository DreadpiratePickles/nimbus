package groundtruth

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenMinMappedPct is the floor (competitive delta 2026-10-09-r2 shortfall #15) on catalog
// coverage of the lab IaC goldens: per tool, the share of FAIL findings that nimbus maps to a
// canonical id (not a raw "<TOOL>:<check>" id). Owned here, not in lab/golden/expectations.yaml.
// Raise it as alias tranches land; never lower it to make a regression pass.
// Per tool: Checkov 80 (alias batch 3, 2026-10-10), Trivy 85.
var goldenMinMappedPct = map[string]float64{
	"checkov": 80,
	"trivy":   85,
}

// goldenFloorDefault applies to a golden tool with no explicit floor.
const goldenFloorDefault = 70

// checkMappedFloor fails the interop test when a tool's mapped share drops below the floor.
func checkMappedFloor(t *testing.T, totals []interopTotals) {
	t.Helper()
	if len(totals) == 0 {
		t.Fatal("no golden tools scored")
	}
	for _, tot := range totals {
		if tot.fail == 0 {
			t.Errorf("%s %s: no FAIL findings ingested from the golden", tot.tool, tot.version)
			continue
		}
		floor, ok := goldenMinMappedPct[tot.tool]
		if !ok {
			floor = goldenFloorDefault
		}
		got := 100 * float64(tot.failMapped) / float64(tot.fail)
		if got < floor {
			t.Errorf("%s %s: %d/%d FAIL findings mapped to a canonical id (%.1f%%), floor is %.0f%%; unmapped checks: %v",
				tot.tool, tot.version, tot.failMapped, tot.fail, got, floor, tot.unmappedChecks)
		}
	}
}

// The floors only ever go up: Checkov ≥ 80 and Trivy ≥ 85 since alias batch 3 (shortfall #15).
func TestGoldenMappedFloors(t *testing.T) {
	for tool, min := range map[string]float64{"checkov": 80, "trivy": 85} {
		if got := goldenMinMappedPct[tool]; got < min {
			t.Errorf("%s golden mapped floor %.0f%%, want >= %.0f%%", tool, got, min)
		}
	}
}

// checkBenchmarkDoc keeps docs/benchmark.md "Scanner interop" in step with the measured numbers
// (verifier item 11: the doc said 36.8% and "Trivy maps nothing" long after both changed). Each
// tool's row ("| Checkov 3.3.26 …") must quote the measured detection and catalog-coverage cells.
func checkBenchmarkDoc(t *testing.T, totals []interopTotals) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "docs", "benchmark.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	if i := strings.Index(doc, "## Scanner interop"); i >= 0 {
		doc = doc[i:]
	} else {
		t.Fatal(`docs/benchmark.md has no "## Scanner interop" section`)
	}
	for _, tot := range totals {
		prefix := "| " + strings.ToUpper(tot.tool[:1]) + tot.tool[1:] + " " + tot.version + " "
		var row string
		for _, line := range strings.Split(doc, "\n") {
			if strings.HasPrefix(line, prefix) {
				row = line
				break
			}
		}
		if row == "" {
			t.Errorf("docs/benchmark.md Scanner interop: no row starting %q", prefix)
			continue
		}
		for _, want := range []string{
			fmt.Sprintf("| %d / %d (%s) |", tot.mapped, tot.detects, pct(ratio(tot.mapped, tot.detects))),
			fmt.Sprintf("| %s (%d/%d) |", pct(ratio(tot.failMapped, tot.fail)), tot.failMapped, tot.fail),
			fmt.Sprintf("| %d (%d) |", tot.fail-tot.failMapped, len(tot.unmappedChecks)),
		} {
			if !strings.Contains(row, want) {
				t.Errorf("docs/benchmark.md Scanner interop row for %s %s is stale: want %q in\n%s\n(update it from `make groundtruth-golden`)", tot.tool, tot.version, want, row)
			}
		}
	}
}
