package adapters

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"gopkg.in/yaml.v3"
)

// coverageTools are the scanners with a lab IaC golden and a catalog-coverage floor.
var coverageTools = map[string]bool{"checkov": true, "trivy": true}

// UnmappedCheck is one native check id with no canonical mapping and how many FAIL findings carry it.
type UnmappedCheck struct {
	CheckID string `json:"check_id"`
	Count   int    `json:"count"`
	Title   string `json:"title,omitempty"`
}

// MappingReport is catalog coverage of one scanner's output: the share of FAIL findings whose native
// check id maps to a canonical id (not the "<TOOL>:<check>" fallback). Same rule as the golden floor
// in tests/groundtruth.
type MappingReport struct {
	Tool           string          `json:"tool"`
	Version        string          `json:"version,omitempty"`
	Inputs         []string        `json:"inputs"`
	Findings       int             `json:"fail_findings"`
	Mapped         int             `json:"mapped"`
	Unmapped       int             `json:"unmapped"`
	MappedPct      float64         `json:"mapped_pct"`
	UnmappedChecks []UnmappedCheck `json:"unmapped_checks"`
}

// MappingCoverage parses scanner output files as tool and reports which check ids stay unmapped.
func MappingCoverage(tool string, paths []string) (MappingReport, error) {
	tool = strings.ToLower(tool)
	if !coverageTools[tool] {
		return MappingReport{}, fmt.Errorf("unknown tool %q (want checkov or trivy)", tool)
	}
	var all []model.Finding
	for _, p := range paths {
		fs, _, err := ParseFile(p, tool, Options{})
		if err != nil {
			return MappingReport{}, fmt.Errorf("%s: %w", p, err)
		}
		all = append(all, fs...)
	}
	r := CoverageOf(tool, all)
	r.Inputs = paths
	return r, nil
}

// CoverageOf scores already-enriched findings (FAIL only), one per finding id as the store keeps them.
func CoverageOf(tool string, findings []model.Finding) MappingReport {
	r := MappingReport{Tool: tool, UnmappedChecks: []UnmappedCheck{}}
	byID := map[string]*UnmappedCheck{}
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Status != model.Fail {
			continue
		}
		if f.ID != "" {
			if seen[f.ID] {
				continue
			}
			seen[f.ID] = true
		}
		r.Findings++
		if f.CanonicalID != "" && !strings.HasPrefix(f.CanonicalID, strings.ToUpper(f.Source)+":") {
			r.Mapped++
			continue
		}
		r.Unmapped++
		c := byID[f.CheckID]
		if c == nil {
			c = &UnmappedCheck{CheckID: f.CheckID, Title: f.Title}
			byID[f.CheckID] = c
		}
		c.Count++
	}
	for _, c := range byID {
		r.UnmappedChecks = append(r.UnmappedChecks, *c)
	}
	sort.Slice(r.UnmappedChecks, func(i, j int) bool {
		a, b := r.UnmappedChecks[i], r.UnmappedChecks[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.CheckID < b.CheckID
	})
	if r.Findings > 0 {
		r.MappedPct = float64(int(1000*float64(r.Mapped)/float64(r.Findings)+0.5)) / 10
	}
	return r
}

// GoldenInputs returns the raw golden files and scanner version lab/golden/expectations.yaml (under
// repo root) lists for tool.
func GoldenInputs(root, tool string) ([]string, string, error) {
	data, err := os.ReadFile(filepath.Join(root, "lab", "golden", "expectations.yaml"))
	if err != nil {
		return nil, "", err
	}
	var doc struct {
		Tools []struct {
			Tool    string   `yaml:"tool"`
			Version string   `yaml:"version"`
			Files   []string `yaml:"files"`
		} `yaml:"tools"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, "", fmt.Errorf("lab/golden/expectations.yaml: %w", err)
	}
	for _, g := range doc.Tools {
		if !strings.EqualFold(g.Tool, tool) {
			continue
		}
		var files []string
		for _, f := range g.Files {
			files = append(files, filepath.Join(root, "lab", "golden", g.Tool, g.Version, f))
		}
		return files, g.Version, nil
	}
	return nil, "", fmt.Errorf("no golden for %q in lab/golden/expectations.yaml", tool)
}

// FindGoldenRoot walks up from dir to the first directory holding lab/golden/expectations.yaml.
func FindGoldenRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "lab", "golden", "expectations.yaml")); err == nil {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("lab/golden/expectations.yaml not found above %s: run from the nimbus repo or pass --from <scanner json>", abs)
		}
	}
}
