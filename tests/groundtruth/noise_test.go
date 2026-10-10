package groundtruth

// P0-NOISE wiring (plan v3 §9 item 5): score the engine against the independently authored
// noise estate (lab/local/noise/estate.yaml, labels in lab/noise_truth.yaml). Only the three
// labelled true-positive chains are attack paths; every other reported path is a false positive.
// This file measures; it never tunes the engine.
//
//	go test ./tests/groundtruth -run Noise -v                  # known noise gaps tolerated
//	GROUNDTRUTH_STRICT=1 go test ./tests/groundtruth -run Noise -v
//	GROUNDTRUTH_NOISE_REPORT=/tmp/noise.md go test ./tests/groundtruth -run Noise -v

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/lab/local/estate"
)

// ---------------------------------------------------------------- noise truth file

type noiseClass struct {
	Slug        string `yaml:"slug"`
	Resources   int    `yaml:"resources"`
	Findings    int    `yaml:"findings"`
	Description string `yaml:"description"`
}

type noiseTP struct {
	ID            string   `yaml:"id"`
	ExpectedPaths int      `yaml:"expected_paths"`
	Kind          string   `yaml:"kind"`
	Entry         string   `yaml:"entry"`
	Target        string   `yaml:"target"`
	Chain         []string `yaml:"chain"`
	Findings      []string `yaml:"findings"`
	Rationale     string   `yaml:"rationale"`
}

type noiseResource struct {
	ID            string   `yaml:"id"`
	Class         string   `yaml:"class"`
	ExpectedPaths int      `yaml:"expected_paths"`
	Findings      []string `yaml:"findings"`
	NearMiss      bool     `yaml:"near_miss"`
	TruePositive  string   `yaml:"true_positive"`
	Why           string   `yaml:"why"`
}

type noiseTruth struct {
	Version            int    `yaml:"version"`
	Estate             string `yaml:"estate"`
	FindingsJSON       string `yaml:"findings_json"`
	Author             string `yaml:"author"`
	Authored           string `yaml:"authored"`
	ExpectedPathsTotal int    `yaml:"expected_paths_total"`
	Summary            struct {
		Resources            int `yaml:"resources"`
		SeededFindings       int `yaml:"seeded_findings"`
		NearMisses           int `yaml:"near_misses"`
		TruePositiveChains   int `yaml:"true_positive_chains"`
		TruePositiveResource int `yaml:"true_positive_resources"`
		BenignResources      int `yaml:"benign_resources"`
	} `yaml:"summary"`
	Classes       map[string]noiseClass `yaml:"classes"`
	TruePositives []noiseTP             `yaml:"true_positives"`
	Resources     []noiseResource       `yaml:"resources"`
}

func loadNoise(t *testing.T) (*estate.Estate, noiseTruth) {
	t.Helper()
	var nt noiseTruth
	loadYAML(t, "lab/noise_truth.yaml", &nt)
	e, err := estate.Load(filepath.Join(repoRoot, filepath.FromSlash(nt.Estate)))
	if err != nil {
		t.Fatal(err)
	}
	return e, nt
}

// ---------------------------------------------------------------- matching

// noiseNetworkTypes are plumbing types: a TP chain that starts at one of them may be reported
// starting at the next chain member (the exposed workload), as optional_hops allow in the main lab.
var noiseNetworkTypes = map[string]bool{
	"aws_security_group": true, "azure_network_security_group": true, "gcp_firewall_rule": true, "google_compute_firewall": true,
}

// matchNoiseTP: the path is the TP chain or a sub-chain of it sharing its entry and target.
// Every reported resource lies on the chain, the last step is the target, and the first step is
// the entry (or the chain member right after a network-control entry, on an internet path).
func matchNoiseTP(tp noiseTP, p *reportedPath, types map[string]string) bool {
	if len(p.Steps) == 0 || p.Steps[len(p.Steps)-1].Resource != tp.Target {
		return false
	}
	on := map[string]bool{}
	for _, c := range tp.Chain {
		on[c] = true
	}
	for h := range p.hops {
		if !on[h] {
			return false
		}
	}
	first := p.Steps[0].Resource
	if first == tp.Entry {
		return true
	}
	return p.entry == "internet" && len(tp.Chain) > 1 && tp.Chain[0] == tp.Entry &&
		noiseNetworkTypes[types[tp.Entry]] && first == tp.Chain[1]
}

// ---------------------------------------------------------------- report rows

type noiseFP struct {
	p        *reportedPath
	key      string // failure key fp:<first resource> -> <target>
	entryHop string // relation weakness (resource type) of step 1
	target   string // resource type of the last step
	class    string // decoy class of the first resource
}

type noiseIssueRow struct {
	ResourceID string
	Severity   string
	Kind       string
}

type noiseReport struct {
	date        string
	reported    int
	tpFound     map[string][]*reportedPath
	tps         []noiseTP
	fps         []noiseFP
	nearMiss    map[string][]*reportedPath
	classOf     map[string]string
	pathSev     map[string]int
	findingSev  map[string]int
	ingested    int
	failed      int
	issues      []noiseIssueRow
	issueErr    string
	tpResources map[string]bool
	rank        map[string]int
	ranked      []string
	tpFindings  map[string]bool
}

func (r *noiseReport) hopList(p *reportedPath) string {
	var parts []string
	if p.entry == "internet" {
		parts = append(parts, "internet")
	}
	for _, s := range p.Steps {
		c := r.classOf[s.Resource]
		if c == "" {
			c = "?"
		}
		parts = append(parts, fmt.Sprintf("%s[%s]", short(s.Resource), c))
	}
	return strings.Join(parts, " > ")
}

func countTable(b *strings.Builder, title, col string, counts map[string]int) {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	fmt.Fprintf(b, "\n%s\n\n| %s | FP paths |\n|---|---|\n", title, col)
	for _, k := range keys {
		fmt.Fprintf(b, "| %s | %d |\n", k, counts[k])
	}
}

func (r *noiseReport) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Noise estate run %s (lab/local/noise/estate.yaml vs lab/noise_truth.yaml)\n\n", r.date)

	fmt.Fprintf(&b, "| TP | kind | matching paths | best score | outcome |\n|---|---|---|---|---|\n")
	found := 0
	for _, tp := range r.tps {
		ms := r.tpFound[tp.ID]
		best, outcome := "-", "MISSED"
		if len(ms) > 0 {
			found++
			bs := ms[0].Score
			for _, p := range ms {
				if p.Score > bs {
					bs = p.Score
				}
			}
			best, outcome = fmt.Sprintf("%.2f", bs), "FOUND"
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %s | %s |\n", tp.ID, tp.Kind, len(ms), best, outcome)
	}

	tpPaths := r.reported - len(r.fps)
	fp5, fp7 := 0, 0
	for _, f := range r.fps {
		if f.p.Score >= 5 {
			fp5++
		}
		if f.p.Score >= 7 {
			fp7++
		}
	}
	fmt.Fprintf(&b, "\n| metric | value |\n|---|---|\n")
	fmt.Fprintf(&b, "| TP chains found / expected | %d / %d |\n", found, len(r.tps))
	fmt.Fprintf(&b, "| reported paths | %d |\n", r.reported)
	fmt.Fprintf(&b, "| paths matching a TP chain | %d |\n", tpPaths)
	fmt.Fprintf(&b, "| false-positive paths | %d |\n", len(r.fps))
	fmt.Fprintf(&b, "| FP rate (FP / reported) | %s (%d/%d) |\n", pct(ratio(len(r.fps), r.reported)), len(r.fps), r.reported)
	fmt.Fprintf(&b, "| precision (TP paths / reported) | %s (%d/%d) |\n", pct(ratio(tpPaths, r.reported)), tpPaths, r.reported)
	v := r.view()
	fmt.Fprintf(&b, "| precision (labelled / real-world) | %s / %s |\n", fracString(v.Precision), fracString(v.Precision))
	fmt.Fprintf(&b, "| precision@7 (labelled / real-world) | %s / %s |\n", fracString(v.PrecisionHigh), fracString(v.PrecisionHigh))
	fmt.Fprintf(&b, "| recall (labelled / real-world) | %s / %s |\n", fracString(v.Recall), fracString(v.Recall))
	fmt.Fprintf(&b, "| recall@7 (labelled / real-world) | %s / %s |\n", fracString(v.RecallHigh), fracString(v.RecallHigh))
	fmt.Fprintf(&b, "| unlabelled paths score >= 5 | %d |\n", fp5)
	fmt.Fprintf(&b, "| unlabelled paths score >= 7 | %d |\n", fp7)
	fmt.Fprintf(&b, "| reported paths by severity | %s |\n", sevString(r.pathSev))
	fmt.Fprintf(&b, "| near-miss resources on a reported path | %d |\n", len(r.nearMiss))

	byHop, byTarget, byClass := map[string]int{}, map[string]int{}, map[string]int{}
	for _, f := range r.fps {
		byHop[f.entryHop]++
		byTarget[f.target]++
		byClass[f.class]++
	}
	b.WriteString("\nlabelled = real-world here: lab/noise_truth.yaml has no pending-feature labels, so every reported path that is not a TP chain already counts as a false positive.\n")
	countTable(&b, "False positives per entry-hop kind (step 1: relation weakness (resource type))", "entry hop", byHop)
	countTable(&b, "False positives per target type", "target type", byTarget)
	countTable(&b, "False positives per decoy class of the first resource", "class", byClass)

	for _, th := range []float64{7, 5} {
		var list []noiseFP
		for _, f := range r.fps {
			if f.p.Score >= th {
				list = append(list, f)
			}
		}
		fmt.Fprintf(&b, "\nUnlabelled paths score >= %.0f: %d\n", th, len(list))
		if len(list) > 0 {
			b.WriteString("\n| score | severity | hops |\n|---|---|---|\n")
		}
		for i, f := range list {
			if i >= 20 {
				fmt.Fprintf(&b, "| … | | %d more |\n", len(list)-20)
				break
			}
			fmt.Fprintf(&b, "| %.2f | %s | %s |\n", f.p.Score, f.p.Severity, r.hopList(f.p))
		}
	}
	fmt.Fprintf(&b, "\nAll false-positive paths: %d\n\n| score | entry hop | hops |\n|---|---|---|\n", len(r.fps))
	for i, f := range r.fps {
		if i >= 20 {
			fmt.Fprintf(&b, "| … | | %d more |\n", len(r.fps)-20)
			break
		}
		fmt.Fprintf(&b, "| %.2f | %s | %s |\n", f.p.Score, f.entryHop, r.hopList(f.p))
	}

	ids := make([]string, 0, len(r.nearMiss))
	for id := range r.nearMiss {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Fprintf(&b, "\nNear-miss resources that produced paths: %d\n", len(ids))
	if len(ids) > 0 {
		b.WriteString("\n| near-miss resource | paths | best score |\n|---|---|---|\n")
	}
	for _, id := range ids {
		best := 0.0
		for _, p := range r.nearMiss[id] {
			if p.Score > best {
				best = p.Score
			}
		}
		fmt.Fprintf(&b, "| %s | %d | %.2f |\n", short(id), len(r.nearMiss[id]), best)
	}

	// alert fatigue proxy
	fmt.Fprintf(&b, "\nFindings and Issues (alert-fatigue proxy)\n\n| measure | value |\n|---|---|\n")
	fmt.Fprintf(&b, "| ingested records / FAIL findings | %d / %d |\n", r.ingested, r.failed)
	fmt.Fprintf(&b, "| FAIL findings by severity | %s |\n", sevString(r.findingSev))
	if r.issueErr != "" {
		fmt.Fprintf(&b, "| open Issues | unavailable: %s |\n", r.issueErr)
	} else {
		bySev, byKind, critHigh, critHighTP := map[string]int{}, map[string]int{}, 0, 0
		for _, is := range r.issues {
			bySev[is.Severity]++
			byKind[is.Kind]++
			if is.Severity == "CRITICAL" || is.Severity == "HIGH" {
				critHigh++
				if r.tpResources[is.ResourceID] {
					critHighTP++
				}
			}
		}
		fmt.Fprintf(&b, "| open Issues | %d |\n", len(r.issues))
		fmt.Fprintf(&b, "| open Issues by severity | %s |\n", sevString(bySev))
		fmt.Fprintf(&b, "| open Issues by kind | %s |\n", kvString(byKind))
		fmt.Fprintf(&b, "| CRITICAL + HIGH open Issues | %d (on a TP-chain resource: %d; on benign resources: %d) |\n", critHigh, critHighTP, critHigh-critHighTP)
	}
	fmt.Fprintf(&b, "| prioritize: ranked findings | %d |\n", len(r.ranked))
	for _, n := range []int{10, 20} {
		hit := 0
		for i := 0; i < n && i < len(r.ranked); i++ {
			if r.tpFindings[r.ranked[i]] {
				hit++
			}
		}
		fmt.Fprintf(&b, "| prioritize: TP-chain findings in top %d | %d of %d TP findings |\n", n, hit, len(r.tpFindings))
	}
	var tpRanks []string
	for _, tp := range r.tps {
		best := 0
		for _, f := range tp.Findings {
			if n, ok := r.rank[estate.FindingID(f)]; ok && (best == 0 || n < best) {
				best = n
			}
		}
		rk := "-"
		if best > 0 {
			rk = fmt.Sprintf("#%d", best)
		}
		tpRanks = append(tpRanks, tp.ID+" "+rk)
	}
	fmt.Fprintf(&b, "| prioritize: best rank of each TP's findings | %s |\n", strings.Join(tpRanks, ", "))
	return b.String()
}

// view: the noise estate's precision/recall. lab/noise_truth.yaml has no pending-feature labels,
// so the labelled and real-world views are identical by construction.
func (r *noiseReport) view() benchView {
	tpPaths, high, tpHigh := 0, 0, 0
	isFP := map[*reportedPath]bool{}
	for _, f := range r.fps {
		isFP[f.p] = true
	}
	for _, ps := range r.tpFound {
		tpPaths += len(ps)
	}
	found, foundHigh := 0, 0
	for _, tp := range r.tps {
		ms := r.tpFound[tp.ID]
		if len(ms) == 0 {
			continue
		}
		found++
		for _, p := range ms {
			if p.Score >= 7 {
				foundHigh++
				break
			}
		}
	}
	for _, ps := range r.tpFound {
		for _, p := range ps {
			if p.Score >= 7 {
				tpHigh++
			}
		}
	}
	for _, f := range r.fps {
		if f.p.Score >= 7 {
			high++
		}
	}
	high += tpHigh
	return benchView{
		Precision: frac(tpPaths, tpPaths+len(r.fps)), PrecisionHigh: frac(tpHigh, high),
		Recall: frac(found, len(r.tps)), RecallHigh: frac(foundHigh, len(r.tps)),
	}
}

func fracString(f benchFrac) string { return pctOf(ratio(f.Num, f.Den), f.Num, f.Den) }

func sevString(m map[string]int) string {
	var parts []string
	for _, s := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if m[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s, m[s]))
		}
	}
	for k, v := range m {
		switch k {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
		default:
			parts = append(parts, fmt.Sprintf("%s %d", k, v))
		}
	}
	return strings.Join(parts, ", ")
}

func kvString(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------- tests

// TestNoiseTruthIntegrity: the noise truth file and the estate agree before anything is scored.
func TestNoiseTruthIntegrity(t *testing.T) {
	e, nt := loadNoise(t)
	var kg knownGaps
	loadYAML(t, "lab/known_gaps.yaml", &kg)

	res := map[string]estate.Resource{}
	for _, r := range e.Resources {
		res[r.ID] = r
	}
	weakOn := map[string][]string{}
	for _, w := range e.Weaknesses {
		weakOn[w.Resource] = append(weakOn[w.Resource], w.ID)
	}
	labelled := map[string]bool{}
	classRes, classFind := map[string]int{}, map[string]int{}
	near, tpRes, findings := 0, 0, 0
	for _, r := range nt.Resources {
		if labelled[r.ID] {
			t.Errorf("noise truth: duplicate resource %s", r.ID)
		}
		labelled[r.ID] = true
		if _, ok := res[r.ID]; !ok {
			t.Errorf("noise truth: %s is not an estate resource", r.ID)
		}
		if _, ok := nt.Classes[r.Class]; !ok {
			t.Errorf("noise truth: %s has unknown class %q", r.ID, r.Class)
		}
		classRes[r.Class]++
		classFind[r.Class] += len(r.Findings)
		findings += len(r.Findings)
		if r.NearMiss {
			near++
		}
		if r.TruePositive != "" {
			tpRes++
		}
		if (r.TruePositive != "") != (r.ExpectedPaths > 0) {
			t.Errorf("noise truth: %s expected_paths %d but true_positive %q", r.ID, r.ExpectedPaths, r.TruePositive)
		}
		got := append([]string(nil), weakOn[r.ID]...)
		want := append([]string(nil), r.Findings...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("noise truth: %s lists findings %v, estate seeds %v", r.ID, want, got)
		}
	}
	for id := range res {
		if !labelled[id] {
			t.Errorf("noise truth: estate resource %s has no label", id)
		}
	}
	for c, cl := range nt.Classes {
		if classRes[c] != cl.Resources || classFind[c] != cl.Findings {
			t.Errorf("noise truth: class %s declares %d resources / %d findings, labels give %d / %d", c, cl.Resources, cl.Findings, classRes[c], classFind[c])
		}
	}
	s := nt.Summary
	if s.Resources != len(e.Resources) || s.Resources != len(nt.Resources) {
		t.Errorf("noise truth: summary.resources %d, estate %d, labels %d", s.Resources, len(e.Resources), len(nt.Resources))
	}
	if s.SeededFindings != len(e.Weaknesses) || findings != len(e.Weaknesses) {
		t.Errorf("noise truth: summary.seeded_findings %d, labels list %d, estate seeds %d", s.SeededFindings, findings, len(e.Weaknesses))
	}
	if s.NearMisses != near || s.TruePositiveResource != tpRes || s.BenignResources != s.Resources-tpRes {
		t.Errorf("noise truth: summary near_misses %d / tp resources %d / benign %d, labels give %d / %d / %d", s.NearMisses, s.TruePositiveResource, s.BenignResources, near, tpRes, len(nt.Resources)-tpRes)
	}
	if s.TruePositiveChains != len(nt.TruePositives) || nt.ExpectedPathsTotal != len(nt.TruePositives) {
		t.Errorf("noise truth: %d TP chains, summary %d, expected_paths_total %d", len(nt.TruePositives), s.TruePositiveChains, nt.ExpectedPathsTotal)
	}
	for _, tp := range nt.TruePositives {
		if len(tp.Chain) == 0 || tp.Chain[0] != tp.Entry || tp.Chain[len(tp.Chain)-1] != tp.Target {
			t.Errorf("noise truth: %s chain must start at entry and end at target", tp.ID)
		}
		for _, c := range tp.Chain {
			if _, ok := res[c]; !ok {
				t.Errorf("noise truth: %s chain member %s is not an estate resource", tp.ID, c)
			}
		}
	}

	// The committed generated JSON, when present, must match the estate (make lab-noise).
	if got, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(nt.FindingsJSON))); err == nil {
		want, err := e.JSON()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale; run `make lab-noise`", nt.FindingsJSON)
		}
	}

	seen := map[string]bool{}
	for _, g := range kg.Noise {
		if seen[g.ID] {
			t.Errorf("duplicate noise known gap %s", g.ID)
		}
		seen[g.ID] = true
		if g.Cause == "" || g.Owner == "" {
			t.Errorf("noise known gap %s: cause and owner are required", g.ID)
		}
	}
}

func goBinary() string {
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(gobin); err != nil {
		return "go"
	}
	return gobin
}

func TestNoiseEstate(t *testing.T) {
	e, nt := loadNoise(t)
	var kg knownGaps
	loadYAML(t, "lab/known_gaps.yaml", &kg)

	types, classOf, nearMiss := map[string]string{}, map[string]string{}, map[string]bool{}
	for _, r := range e.Resources {
		types[r.ID] = r.Type
	}
	for _, r := range nt.Resources {
		classOf[r.ID] = r.Class
		if r.NearMiss {
			nearMiss[r.ID] = true
		}
	}

	// 1. generate the noise estate with the existing generator into a temp dir
	home := t.TempDir()
	findingsFile := filepath.Join(home, "noise.findings.json")
	gen := exec.Command(goBinary(), "run", "./lab/local/gen", "-in", filepath.FromSlash(nt.Estate), "-out", findingsFile)
	gen.Dir = repoRoot
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("go run ./lab/local/gen: %v\n%s", err, out)
	}
	// Neutral config: the noise author supplied none, so the engine gets no trusted CIDRs and
	// no hints (the main lab's trusted_cidrs belong to the main lab's seeded false positive).
	if err := os.WriteFile(filepath.Join(home, "cloud-posture.yaml"), []byte("python:\n  enabled: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Its own DB: the noise estate's lab-inv-NN ids collide with the main lab's.
	db := filepath.Join(home, "noise.db")

	// 2. ingest
	var ingest struct {
		Scan struct {
			Total      int            `json:"total"`
			Failed     int            `json:"failed"`
			BySeverity map[string]int `json:"by_severity"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(cli(t, home, db, "ingest", findingsFile, "--source", "native", "-o", "json"), &ingest); err != nil {
		t.Fatalf("ingest -o json: %v", err)
	}
	if ingest.Scan.Failed != len(e.Weaknesses) {
		t.Errorf("ingest: %d FAIL findings, estate seeds %d", ingest.Scan.Failed, len(e.Weaknesses))
	}

	// 3. paths
	var reported []*reportedPath
	if err := json.Unmarshal(cli(t, home, db, "paths", "--format", "json", "--limit", "0"), &reported); err != nil {
		t.Fatalf("paths --format json: %v", err)
	}
	for _, p := range reported {
		p.normalize()
	}
	reported, dupChains := distinctChains(reported) // r5 #3: one chain counts once
	if dupChains > 0 {
		t.Errorf("noise: %d reported path(s) repeat another path's entry and hops (two Issues for one chain)", dupChains)
	}

	// 4. prioritize
	var ranked []struct {
		Finding struct {
			ID string `json:"id"`
		} `json:"finding"`
	}
	if err := json.Unmarshal(cli(t, home, db, "prioritize", "--json", "--top", "0"), &ranked); err != nil {
		t.Fatalf("prioritize --json: %v", err)
	}
	rep := &noiseReport{
		date: time.Now().Format("2006-01-02"), reported: len(reported), tps: nt.TruePositives, classOf: classOf,
		tpFound: map[string][]*reportedPath{}, nearMiss: map[string][]*reportedPath{}, pathSev: map[string]int{},
		findingSev: ingest.Scan.BySeverity, ingested: ingest.Scan.Total, failed: ingest.Scan.Failed,
		rank: map[string]int{}, tpResources: map[string]bool{}, tpFindings: map[string]bool{},
	}
	for _, tp := range nt.TruePositives {
		for _, c := range tp.Chain {
			rep.tpResources[c] = true
		}
		for _, f := range tp.Findings {
			rep.tpFindings[estate.FindingID(f)] = true
		}
	}
	for i, r := range ranked {
		if _, ok := rep.rank[r.Finding.ID]; !ok {
			rep.rank[r.Finding.ID] = i + 1
			rep.ranked = append(rep.ranked, r.Finding.ID)
		}
	}

	// 5. Issues (current open state)
	var q struct {
		Rows [][]any `json:"rows"`
	}
	if out, err := cliTry(home, db, "query", "SELECT resource_id, severity, kind FROM issues WHERE state IN ('open','reopened')", "-f", "json"); err != nil {
		rep.issueErr = err.Error()
		t.Errorf("issues query: %v", err)
	} else if err := json.Unmarshal(out, &q); err != nil {
		rep.issueErr = err.Error()
		t.Errorf("issues query json: %v", err)
	} else {
		for _, row := range q.Rows {
			if len(row) == 3 {
				rep.issues = append(rep.issues, noiseIssueRow{fmt.Sprint(row[0]), fmt.Sprint(row[1]), fmt.Sprint(row[2])})
			}
		}
	}

	// 6. score
	sort.SliceStable(reported, func(i, j int) bool { return reported[i].Score > reported[j].Score })
	failures := map[string]string{}
	for _, p := range reported {
		rep.pathSev[p.Severity]++
		for _, s := range p.Steps {
			if nearMiss[s.Resource] && !containsPath(rep.nearMiss[s.Resource], p) {
				rep.nearMiss[s.Resource] = append(rep.nearMiss[s.Resource], p)
			}
		}
		matched := false
		for _, tp := range nt.TruePositives {
			if matchNoiseTP(tp, p, types) {
				rep.tpFound[tp.ID] = append(rep.tpFound[tp.ID], p)
				matched = true
				break
			}
		}
		if matched || len(p.Steps) == 0 {
			continue
		}
		first, last := p.Steps[0], p.Steps[len(p.Steps)-1]
		f := noiseFP{
			p:        p,
			key:      fmt.Sprintf("fp:%s -> %s", first.Resource, last.Resource),
			entryHop: fmt.Sprintf("%s %s (%s)", first.Relation, first.Weakness, types[first.Resource]),
			target:   types[last.Resource],
			class:    classOf[first.Resource],
		}
		rep.fps = append(rep.fps, f)
		if prev, ok := failures[f.key]; ok {
			failures[f.key] = prev + fmt.Sprintf("; also %.2f", p.Score)
		} else {
			failures[f.key] = fmt.Sprintf("false positive %.2f [%s]: %s", p.Score, f.class, rep.hopList(p))
		}
	}
	for _, tp := range nt.TruePositives {
		if len(rep.tpFound[tp.ID]) == 0 {
			failures["missed:"+tp.ID] = fmt.Sprintf("%s (%s) not reported", tp.ID, tp.Kind)
		}
	}

	report := rep.render()
	t.Log("\n" + report)
	v := rep.view()
	var fpList []benchFP
	high := 0
	for _, f := range rep.fps {
		fpList = append(fpList, benchFP{Score: f.p.Score, Rule: f.p.RuleID, Chain: rep.hopList(f.p)})
	}
	for _, p := range reported {
		if p.Score >= 7 {
			high++
		}
	}
	recordBench("noise_estate", benchEstate{
		Estate: nt.Estate, Truth: "lab/noise_truth.yaml", Authored: "independent (" + nt.Author + ")",
		Threshold: 7, Expected: len(nt.TruePositives), Reported: len(reported), ReportedHigh: high, Unlabelled: len(rep.fps),
		Labelled: v, RealWorld: v, RealWorldFalsePositives: fpList,
	})
	if out := os.Getenv("GROUNDTRUTH_NOISE_REPORT"); out != "" {
		if err := os.WriteFile(out, []byte(report), 0o644); err != nil {
			t.Errorf("GROUNDTRUTH_NOISE_REPORT: %v", err)
		}
	}

	// 7. gate (same semantics as the labelled lab, list under `noise:` in lab/known_gaps.yaml)
	ids := make([]string, 0, len(failures))
	for id := range failures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if strict() {
		for _, id := range ids {
			t.Errorf("[strict] noise %s: %s", id, failures[id])
		}
		return
	}
	known := map[string]knownGap{}
	for _, g := range kg.Noise {
		known[g.ID] = g
	}
	for _, id := range ids {
		if g, ok := known[id]; ok {
			t.Logf("known noise gap %s (%s): %s", id, g.Owner, failures[id])
			continue
		}
		t.Errorf("NEW noise failure %s: %s (fix it, or label it under noise: in lab/known_gaps.yaml with an owner)", id, failures[id])
	}
	for _, g := range kg.Noise {
		if _, ok := failures[g.ID]; !ok {
			t.Errorf("noise known gap %s no longer reproduces: remove it from lab/known_gaps.yaml (cause was: %s)", g.ID, g.Cause)
		}
	}
}

func containsPath(ps []*reportedPath, p *reportedPath) bool {
	for _, q := range ps {
		if q == p {
			return true
		}
	}
	return false
}

// cliTry runs the CLI and returns its stdout, or an error carrying stderr.
func cliTry(home, db string, args ...string) ([]byte, error) {
	full := append([]string{"--db", db, "-q", "-c", filepath.Join(home, "cloud-posture.yaml")}, args...)
	cmd := exec.Command(binPath, full...)
	cmd.Dir = home
	cmd.Env = append(os.Environ(), "HOME="+home, "CLOUD_POSTURE_PYTHON=/nonexistent/python", "NO_COLOR=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cloud-posture %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
