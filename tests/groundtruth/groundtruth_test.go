// Package groundtruth is the acceptance harness for attack-path detection: it ingests the
// seeded local lab estate (lab/local/estate.yaml) through the real CLI binary and scores
// what the engine reports against the hand-labelled lab/ground_truth.yaml.
//
//	go test ./tests/groundtruth -v                      # known gaps (lab/known_gaps.yaml) tolerated
//	GROUNDTRUTH_STRICT=1 go test ./tests/groundtruth -v # Phase 0 exit criterion: no gaps allowed
//	go test ./tests/groundtruth -v -args -strict        # same as above
//
// The non-strict run fails on any failure not listed in lab/known_gaps.yaml (a regression or
// an unlabelled gap) and on any listed gap that no longer reproduces (prune the list).
package groundtruth

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/lab/local/estate"
	"gopkg.in/yaml.v3"
)

var strictFlag = flag.Bool("strict", false, "ignore lab/known_gaps.yaml (also GROUNDTRUTH_STRICT=1)")

var (
	repoRoot string
	binPath  string
	workDir  string
)

func TestMain(m *testing.M) {
	flag.Parse()
	code, err := setup()
	if err != nil {
		fmt.Fprintln(os.Stderr, "groundtruth setup:", err)
		os.Exit(2)
	}
	code = m.Run()
	if err := writeBenchJSON(); err != nil {
		fmt.Fprintln(os.Stderr, "groundtruth: benchmark.json:", err)
		if code == 0 {
			code = 1
		}
	}
	if workDir != "" {
		os.RemoveAll(workDir)
	}
	os.Exit(code)
}

func setup() (int, error) {
	wd, err := os.Getwd()
	if err != nil {
		return 0, err
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			repoRoot = dir
			break
		}
		if filepath.Dir(dir) == dir {
			return 0, fmt.Errorf("go.mod not found above %s", wd)
		}
	}
	workDir, err = os.MkdirTemp("", "nimbus-groundtruth-")
	if err != nil {
		return 0, err
	}
	binPath = filepath.Join(workDir, "cloud-posture")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(gobin); err != nil {
		gobin = "go"
	}
	cmd := exec.Command(gobin, "build", "-o", binPath, "./cmd/cloud-posture")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("go build ./cmd/cloud-posture: %v\n%s", err, out)
	}
	return 0, nil
}

func strict() bool { return *strictFlag || os.Getenv("GROUNDTRUTH_STRICT") == "1" }

// ---------------------------------------------------------------- ground truth files

type gtPath struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name"`
	Status       string   `yaml:"status"`
	Feature      string   `yaml:"feature"`
	Entry        string   `yaml:"entry"`
	Target       string   `yaml:"target"`
	Hops         []string `yaml:"hops"`
	OptionalHops []string `yaml:"optional_hops"`
	Weaknesses   []string `yaml:"weaknesses"`
	MinScore     float64  `yaml:"min_score"`
	MaxScore     float64  `yaml:"max_score"`   // optional exclusive upper bound of the band
	Band         string   `yaml:"band"`        // band name when below score_threshold (medium)
	BandReason   string   `yaml:"band_reason"` // why the label is not critical
	Claim        string   `yaml:"claim"`
}

// inBand: best lies in [min_score, max_score) (no upper bound without max_score).
func inBand(g gtPath, best float64) bool {
	return best >= g.MinScore && (g.MaxScore == 0 || best < g.MaxScore)
}

// expectedOutcome scores one expected label: its outcome text and the failure key ("" when ok).
func expectedOutcome(g gtPath, found int, best float64) (string, string) {
	switch {
	case found == 0:
		return "MISSED", "missed:" + g.ID
	case best < g.MinScore:
		return fmt.Sprintf("LOW SCORE (%.2f < %.0f)", best, g.MinScore), "low_score:" + g.ID
	case g.MaxScore > 0 && best >= g.MaxScore:
		return fmt.Sprintf("ABOVE BAND (%.2f >= %.0f)", best, g.MaxScore), "above_band:" + g.ID
	}
	return "FOUND", ""
}

type groundTruth struct {
	Version          int     `yaml:"version"`
	Estate           string  `yaml:"estate"`
	ScoreThreshold   float64 `yaml:"score_threshold"`
	ExpectedFindings struct {
		TotalFail     int            `yaml:"total_fail"`
		InventoryPass int            `yaml:"inventory_pass"`
		BySeverity    map[string]int `yaml:"by_severity"`
	} `yaml:"expected_findings"`
	Paths []gtPath `yaml:"paths"`
}

type knownGap struct {
	ID    string `yaml:"id"`
	Cause string `yaml:"cause"`
	Owner string `yaml:"owner"`
	Ref   string `yaml:"ref"`
}

type knownGaps struct {
	Gaps  []knownGap `yaml:"gaps"`
	Noise []knownGap `yaml:"noise"` // gaps against lab/noise_truth.yaml (tests/groundtruth/noise_test.go)
	// Golden scanner-interop gaps (tests/groundtruth/golden_test.go): a lab weakness a scanner
	// detects that nimbus does not map to the expected canonical id.
	Golden []knownGap `yaml:"golden"`
}

func loadYAML(t *testing.T, rel string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
}

func loadEstate(t *testing.T) *estate.Estate {
	t.Helper()
	e, err := estate.Load(filepath.Join(repoRoot, "lab", "local", "estate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// ---------------------------------------------------------------- reported paths

type reportedStep struct {
	Resource string `json:"resource"`
	Relation string `json:"relation"`
	Weakness string `json:"weakness"`
}

type reportedPath struct {
	ID       string         `json:"id"`
	RuleID   string         `json:"rule_id"`
	Name     string         `json:"name"`
	Score    float64        `json:"score"`
	Severity string         `json:"severity"`
	Steps    []reportedStep `json:"steps"`

	entry  string
	target string
	hops   map[string]bool
}

// normalize derives entry, target and the hop set. A path whose first step is not an
// "entry" step starts at the internet (graph traversal); a rule chain whose first stage is a
// public-exposure weakness also starts at the internet; otherwise the first resource is the
// foothold (phished identity, unprotected repo, externally assumable role).
func (p *reportedPath) normalize() {
	p.hops = map[string]bool{}
	for _, s := range p.Steps {
		if s.Resource != "" && s.Resource != "internet" {
			p.hops[s.Resource] = true
		}
	}
	if len(p.Steps) == 0 {
		return
	}
	first := p.Steps[0]
	switch {
	case first.Relation != "entry":
		p.entry = "internet"
	case first.Weakness == "PUBLIC_NETWORK_EXPOSURE" || first.Weakness == "PUBLIC_DATA_STORE":
		p.entry = "internet"
	default:
		p.entry = first.Resource
	}
	p.target = p.Steps[len(p.Steps)-1].Resource
}

// chainKey is the entry plus the ordered hop list: two reported paths with the same key are the
// same chain whatever their rule or id.
func (p *reportedPath) chainKey() string {
	parts := []string{p.entry}
	for _, s := range p.Steps {
		parts = append(parts, s.Resource)
	}
	return strings.Join(parts, ">")
}

// distinctChains collapses reported paths on the same chain (chainKey) into one, keeping the
// highest score (first reported on a tie), in input order; it returns how many were collapsed.
func distinctChains(in []*reportedPath) ([]*reportedPath, int) {
	idx := map[string]int{}
	var out []*reportedPath
	for _, p := range in {
		k := p.chainKey()
		if i, ok := idx[k]; ok {
			if p.Score > out[i].Score {
				out[i] = p
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, p)
	}
	return out, len(in) - len(out)
}

func (p *reportedPath) chain() string {
	var parts []string
	if p.entry == "internet" {
		parts = append(parts, "internet")
	}
	for _, s := range p.Steps {
		parts = append(parts, short(s.Resource))
	}
	return strings.Join(parts, " > ")
}

func matches(g gtPath, p *reportedPath) bool {
	if g.Entry != p.entry || !endsOnTarget(g, p) {
		return false
	}
	allowed := map[string]bool{}
	for _, h := range g.Hops {
		if !p.hops[h] {
			return false
		}
		allowed[h] = true
	}
	for _, h := range g.OptionalHops {
		allowed[h] = true
	}
	for h := range p.hops {
		if !allowed[h] {
			return false
		}
	}
	return true
}

// endsOnTarget: the path's last step is the target, or the target is followed only by
// optional hops (plumbing an engine may render after it, e.g. the ClusterRole behind a binding).
func endsOnTarget(g gtPath, p *reportedPath) bool {
	optional := map[string]bool{}
	for _, h := range g.OptionalHops {
		optional[h] = true
	}
	for i := len(p.Steps) - 1; i >= 0; i-- {
		r := p.Steps[i].Resource
		if r == g.Target {
			return true
		}
		if !optional[r] {
			return false
		}
	}
	return false
}

// falsePositiveHit: the seeded false positive is reported when a path matches it, or when any
// path from the internet passes through its first hop (the resource wrongly treated as public).
func falsePositiveHit(g gtPath, p *reportedPath) bool {
	if matches(g, p) {
		return true
	}
	return g.Entry == "internet" && p.entry == "internet" && len(g.Hops) > 0 && p.hops[g.Hops[0]]
}

func short(id string) string {
	s := strings.TrimRight(id, "/")
	if i := strings.LastIndexAny(s, "/:"); i >= 0 && i < len(s)-1 {
		return s[i+1:]
	}
	return s
}

// ---------------------------------------------------------------- CLI

func cli(t *testing.T, home, db string, args ...string) []byte {
	t.Helper()
	full := append([]string{"--db", db, "-q", "-c", filepath.Join(home, "cloud-posture.yaml")}, args...)
	cmd := exec.Command(binPath, full...)
	cmd.Dir = home
	cmd.Env = append(os.Environ(), "HOME="+home, "CLOUD_POSTURE_PYTHON=/nonexistent/python", "NO_COLOR=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("cloud-posture %s: %v\nstderr:\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes()
}

// ---------------------------------------------------------------- tests

// TestGroundTruthIntegrity keeps the estate, the committed generated JSON and the ground truth
// consistent before anything is scored.
func TestGroundTruthIntegrity(t *testing.T) {
	e := loadEstate(t)
	var gt groundTruth
	loadYAML(t, "lab/ground_truth.yaml", &gt)
	var kg knownGaps
	loadYAML(t, "lab/known_gaps.yaml", &kg)

	want, err := e.JSON()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(repoRoot, "lab", "local", "out", "estate.findings.json"))
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("lab/local/out/estate.findings.json is stale or missing; run `make lab-local` (err=%v)", err)
	}

	res := map[string]bool{}
	for _, r := range e.Resources {
		res[r.ID] = true
	}
	weak := map[string]bool{}
	for _, w := range e.Weaknesses {
		weak[w.ID] = true
	}
	ids := map[string]bool{}
	for _, p := range gt.Paths {
		if ids[p.ID] {
			t.Errorf("duplicate ground-truth path id %s", p.ID)
		}
		ids[p.ID] = true
		switch p.Status {
		case "expected", "false_positive", "pending-feature":
		default:
			t.Errorf("%s: unknown status %q", p.ID, p.Status)
		}
		switch {
		case p.Status == "expected" && p.Band == "" && p.MinScore < gt.ScoreThreshold:
			t.Errorf("%s: expected paths need min_score >= %v (or a band with band_reason)", p.ID, gt.ScoreThreshold)
		case p.Band != "" && (p.BandReason == "" || p.MaxScore == 0 || p.MaxScore > gt.ScoreThreshold || p.MinScore >= p.MaxScore):
			t.Errorf("%s: band %q needs band_reason and min_score < max_score <= %v", p.ID, p.Band, gt.ScoreThreshold)
		}
		if p.Claim == "" {
			t.Errorf("%s: claim is required", p.ID)
		}
		if p.Entry != "internet" && !res[p.Entry] {
			t.Errorf("%s: entry %q is not an estate resource", p.ID, p.Entry)
		}
		for _, h := range append(append([]string{p.Target}, p.Hops...), p.OptionalHops...) {
			if !res[h] {
				t.Errorf("%s: %q is not an estate resource", p.ID, h)
			}
		}
		if len(p.Hops) == 0 || p.Hops[len(p.Hops)-1] != p.Target {
			t.Errorf("%s: last hop must be the target", p.ID)
		}
		for _, w := range p.Weaknesses {
			if !weak[w] {
				t.Errorf("%s: unknown weakness %s", p.ID, w)
			}
		}
	}

	counts := e.SeverityCounts()
	total := 0
	for sev, n := range gt.ExpectedFindings.BySeverity {
		if counts[sev] != n {
			t.Errorf("ground truth says %d %s findings, estate seeds %d", n, sev, counts[sev])
		}
		total += n
	}
	if total != gt.ExpectedFindings.TotalFail || len(e.Weaknesses) != total {
		t.Errorf("total_fail %d, by_severity sums to %d, estate seeds %d", gt.ExpectedFindings.TotalFail, total, len(e.Weaknesses))
	}
	if inv := len(e.Findings()) - len(e.Weaknesses); inv != gt.ExpectedFindings.InventoryPass {
		t.Errorf("inventory_pass %d, estate emits %d", gt.ExpectedFindings.InventoryPass, inv)
	}

	seen := map[string]bool{}
	for _, g := range kg.Gaps {
		if seen[g.ID] {
			t.Errorf("duplicate known gap %s", g.ID)
		}
		seen[g.ID] = true
		if g.Cause == "" || g.Owner == "" {
			t.Errorf("known gap %s: cause and owner are required", g.ID)
		}
	}
}

type benchRow struct {
	gt       gtPath
	found    int
	best     float64
	bestPath *reportedPath
	outcome  string
	// Real-world view (competitive delta 2026-10-09 shortfall #2): only matches through a path
	// that carries no false_positive / pending-feature label count.
	foundReal int
	bestReal  float64
}

// shouldNotReport: label statuses whose reported paths are false positives against real-world
// truth. Every pending-feature label in lab/ground_truth.yaml has "should NOT be reported once the
// feature lands" semantics, so a pending-feature path is wrong in a real estate today.
func shouldNotReport(status string) bool {
	return status == "false_positive" || status == "pending-feature"
}

func TestGroundTruth(t *testing.T) {
	e := loadEstate(t)
	var gt groundTruth
	loadYAML(t, "lab/ground_truth.yaml", &gt)
	var kg knownGaps
	loadYAML(t, "lab/known_gaps.yaml", &kg)
	threshold := gt.ScoreThreshold
	if threshold == 0 {
		threshold = 7
	}

	home := t.TempDir()
	db := filepath.Join(home, "posture.db")
	// Ingest the committed `make lab-local` output (typed relationships, B3 item 1);
	// TestGroundTruthIntegrity fails when it is stale against the estate.
	findingsFile := filepath.Join(repoRoot, "lab", "local", "out", "estate.findings.json")
	cfg, err := os.ReadFile(filepath.Join(repoRoot, "lab", "local", "cloud-posture.lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cloud-posture.yaml"), cfg, 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. ingest through the real pipeline
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
	if ingest.Scan.Failed != gt.ExpectedFindings.TotalFail {
		t.Errorf("ingest: %d FAIL findings, ground truth expects %d", ingest.Scan.Failed, gt.ExpectedFindings.TotalFail)
	}
	if want := gt.ExpectedFindings.TotalFail + gt.ExpectedFindings.InventoryPass; ingest.Scan.Total != want {
		t.Errorf("ingest: %d records, ground truth expects %d", ingest.Scan.Total, want)
	}
	for sev, n := range gt.ExpectedFindings.BySeverity {
		if ingest.Scan.BySeverity[sev] != n {
			t.Errorf("ingest: %d %s findings, ground truth expects %d", ingest.Scan.BySeverity[sev], sev, n)
		}
	}

	// 2. paths
	var reported []*reportedPath
	if err := json.Unmarshal(cli(t, home, db, "paths", "--format", "json", "--limit", "0"), &reported); err != nil {
		t.Fatalf("paths --format json: %v", err)
	}
	for _, p := range reported {
		p.normalize()
	}
	// Two Issues on the same hops are one chain (r5 #3): count it once, report the collapse.
	reported, dupChains := distinctChains(reported)

	// 3. prioritize
	var ranked []struct {
		Finding struct {
			ID string `json:"id"`
		} `json:"finding"`
		Score float64 `json:"risk_score"`
	}
	if err := json.Unmarshal(cli(t, home, db, "prioritize", "--json", "--top", "0"), &ranked); err != nil {
		t.Fatalf("prioritize --json: %v", err)
	}
	rank := map[string]int{}
	for i, r := range ranked {
		if _, ok := rank[r.Finding.ID]; !ok {
			rank[r.Finding.ID] = i + 1
		}
	}
	for _, w := range e.Weaknesses {
		if _, ok := rank[estate.FindingID(w.ID)]; !ok {
			t.Errorf("prioritize: seeded finding %s missing from the ranking", estate.FindingID(w.ID))
		}
	}

	// 4. score
	failures := map[string]string{}
	if dupChains > 0 {
		failures["duplicate_chains"] = fmt.Sprintf("%d reported path(s) repeat another path's entry and hops (two Issues for one chain)", dupChains)
	}
	labelled := map[*reportedPath]string{}
	labelsOf := map[*reportedPath][]string{} // every label status a path matched (labelled keeps the last id)
	var rows []*benchRow
	for _, g := range gt.Paths {
		row := &benchRow{gt: g, best: math.Inf(-1), bestReal: math.Inf(-1)}
		rows = append(rows, row)
		for _, p := range reported {
			hit := matches(g, p)
			if g.Status == "false_positive" {
				hit = falsePositiveHit(g, p)
			}
			if !hit {
				continue
			}
			row.found++
			labelled[p] = g.ID
			labelsOf[p] = append(labelsOf[p], g.Status)
			if p.Score > row.best {
				row.best, row.bestPath = p.Score, p
			}
		}
		switch g.Status {
		case "expected":
			var key string
			row.outcome, key = expectedOutcome(g, row.found, row.best)
			if key != "" {
				failures[key] = fmt.Sprintf("%s (%s): %s", g.ID, g.Name, row.outcome)
			}
		case "false_positive":
			if row.found > 0 {
				row.outcome = "REPORTED (false positive)"
				failures["false_positive_reported:"+g.ID] = fmt.Sprintf("%s reported %d time(s), best %.2f via %s", g.ID, row.found, row.best, row.bestPath.chain())
			} else {
				row.outcome = "SUPPRESSED"
			}
		case "pending-feature":
			if row.found > 0 {
				row.outcome = "REPORTED (pending feature)"
				failures["pending_feature_reported:"+g.ID] = fmt.Sprintf("%s still reported (needs %s)", g.ID, g.Feature)
			} else {
				row.outcome = "SUPPRESSED"
			}
		}
	}
	var extras []*reportedPath
	for _, p := range reported {
		if _, ok := labelled[p]; ok {
			continue
		}
		extras = append(extras, p)
		if p.Score >= threshold {
			key := fmt.Sprintf("unlabelled_high:%s -> %s", p.entry, p.target)
			failures[key] = fmt.Sprintf("unlabelled path scored %.2f: %s [%s]", p.Score, p.chain(), p.RuleID)
		}
	}

	// Real-world view: a path is a real-world hit only when it matched an expected label and no
	// false_positive / pending-feature label; an expected label met only through such a path is
	// not found.
	realGood := func(p *reportedPath) bool {
		exp := false
		for _, st := range labelsOf[p] {
			if shouldNotReport(st) {
				return false
			}
			exp = exp || st == "expected"
		}
		return exp
	}
	for _, r := range rows {
		if r.gt.Status != "expected" {
			continue
		}
		for _, p := range reported {
			if matches(r.gt, p) && realGood(p) {
				r.foundReal++
				if p.Score > r.bestReal {
					r.bestReal = p.Score
				}
			}
		}
	}

	// 5. metrics
	expected, foundAny, foundHigh, foundBand := 0, 0, 0, 0
	foundAnyReal, foundHighReal, foundBandReal := 0, 0, 0
	for _, r := range rows {
		if r.gt.Status != "expected" {
			continue
		}
		expected++
		if r.found > 0 {
			foundAny++
			if r.best >= threshold {
				foundHigh++
			}
			if inBand(r.gt, r.best) {
				foundBand++
			}
		}
		if r.foundReal > 0 {
			foundAnyReal++
			if r.bestReal >= threshold {
				foundHighReal++
			}
			if inBand(r.gt, r.bestReal) {
				foundBandReal++
			}
		}
	}
	tp, tpHigh, nHigh, tpReal, tpRealHigh := 0, 0, 0, 0, 0
	var realFPs []*reportedPath
	for _, p := range reported {
		id, ok := labelled[p]
		good := ok && statusOf(gt, id) != "false_positive"
		rg := realGood(p)
		if good {
			tp++
		}
		if rg {
			tpReal++
		} else {
			realFPs = append(realFPs, p)
		}
		if p.Score >= threshold {
			nHigh++
			if good {
				tpHigh++
			}
			if rg {
				tpRealHigh++
			}
		}
	}
	m := metrics{
		Expected: expected, Reported: len(reported), ReportedHigh: nHigh, TruePositives: tp, TruePositivesHigh: tpHigh,
		Recall: ratio(foundAny, expected), RecallHigh: ratio(foundHigh, expected), RecallBand: ratio(foundBand, expected),
		Precision: ratio(tp, len(reported)), PrecisionHigh: ratio(tpHigh, nHigh), Extras: len(extras),
		FoundAny: foundAny, FoundHigh: foundHigh, FoundBand: foundBand,
		FoundAnyReal: foundAnyReal, FoundHighReal: foundHighReal, FoundBandReal: foundBandReal,
		TruePositivesReal: tpReal, TruePositivesRealHigh: tpRealHigh,
		RecallReal: ratio(foundAnyReal, expected), RecallHighReal: ratio(foundHighReal, expected), RecallBandReal: ratio(foundBandReal, expected),
		PrecisionReal: ratio(tpReal, len(reported)), PrecisionRealHigh: ratio(tpRealHigh, nHigh),
	}
	sort.SliceStable(realFPs, func(i, j int) bool { return realFPs[i].Score > realFPs[j].Score })
	var fpList []benchFP
	for _, p := range realFPs {
		fpList = append(fpList, benchFP{Label: labelled[p], Score: p.Score, Rule: p.RuleID, Chain: p.chain()})
	}
	fl := findingLevel(t, home, db, gt.Paths)
	recordBench("labelled_lab", benchEstate{
		Estate: "lab/local/estate.yaml", Truth: "lab/ground_truth.yaml", Authored: "project (self-referential)",
		Threshold: threshold, Expected: expected, Reported: len(reported), ReportedHigh: nHigh, Unlabelled: len(extras),
		Labelled: benchView{
			Precision: frac(tp, len(reported)), PrecisionHigh: frac(tpHigh, nHigh),
			Recall: frac(foundAny, expected), RecallHigh: frac(foundHigh, expected), RecallBand: fracPtr(foundBand, expected),
		},
		RealWorld: benchView{
			Precision: frac(tpReal, len(reported)), PrecisionHigh: frac(tpRealHigh, nHigh),
			Recall: frac(foundAnyReal, expected), RecallHigh: frac(foundHighReal, expected), RecallBand: fracPtr(foundBandReal, expected),
		},
		RealWorldFalsePositives: fpList,
		FindingLevel:            fl,
	})
	t.Logf("finding-level: %s %v %v", fl, fl.CriticalOnNonExposedIDs, fl.BenignInTopNIDs)
	m.RealFPs = fpList
	m.DuplicateChains = dupChains

	report := renderReport(rows, extras, rank, m, threshold)
	t.Log("\n" + report)
	if out := os.Getenv("GROUNDTRUTH_REPORT"); out != "" {
		if err := os.WriteFile(out, []byte(report), 0o644); err != nil {
			t.Errorf("GROUNDTRUTH_REPORT: %v", err)
		}
	}

	// 6. gate
	ids := make([]string, 0, len(failures))
	for id := range failures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if strict() {
		for _, id := range ids {
			t.Errorf("[strict] %s: %s", id, failures[id])
		}
		return
	}
	known := map[string]knownGap{}
	for _, g := range kg.Gaps {
		known[g.ID] = g
	}
	for _, id := range ids {
		if g, ok := known[id]; ok {
			t.Logf("known gap %s (%s, %s): %s", id, g.Owner, g.Cause, failures[id])
			continue
		}
		t.Errorf("NEW failure %s: %s (fix it, or label it in lab/known_gaps.yaml with an owner)", id, failures[id])
	}
	for _, g := range kg.Gaps {
		if _, ok := failures[g.ID]; !ok {
			t.Errorf("known gap %s no longer reproduces: remove it from lab/known_gaps.yaml (cause was: %s)", g.ID, g.Cause)
		}
	}
}

func statusOf(gt groundTruth, id string) string {
	for _, p := range gt.Paths {
		if p.ID == id {
			return p.Status
		}
	}
	return ""
}

type metrics struct {
	Expected, Reported, ReportedHigh, TruePositives, TruePositivesHigh, Extras int
	Recall, RecallHigh, RecallBand, Precision, PrecisionHigh                   float64

	FoundAny, FoundHigh, FoundBand, FoundAnyReal, FoundHighReal, FoundBandReal   int
	TruePositivesReal, TruePositivesRealHigh                                     int
	RecallReal, RecallHighReal, RecallBandReal, PrecisionReal, PrecisionRealHigh float64
	RealFPs                                                                      []benchFP
	DuplicateChains                                                              int
}

func pctOf(f float64, a, b int) string { return fmt.Sprintf("%s (%d/%d)", pct(f), a, b) }

func ratio(a, b int) float64 {
	if b == 0 {
		return math.NaN()
	}
	return float64(a) / float64(b)
}

func pct(f float64) string {
	if math.IsNaN(f) {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", f*100)
}

func renderReport(rows []*benchRow, extras []*reportedPath, rank map[string]int, m metrics, threshold float64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "| id | status | ground-truth path | matches | best score | outcome | best prioritize rank |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		best := "-"
		if r.found > 0 {
			best = fmt.Sprintf("%.2f", r.best)
		}
		bestRank := 0
		for _, w := range r.gt.Weaknesses {
			if n, ok := rank[estate.FindingID(w)]; ok && (bestRank == 0 || n < bestRank) {
				bestRank = n
			}
		}
		rk := "-"
		if bestRank > 0 {
			rk = fmt.Sprintf("#%d", bestRank)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s | %s | %s |\n", r.gt.ID, r.gt.Status, r.gt.Name, r.found, best, r.outcome, rk)
	}
	fmt.Fprintf(&b, "\nDuplicate chains collapsed (two reported paths on the same entry and hops count once): %d\n", m.DuplicateChains)
	fmt.Fprintf(&b, "\nUnlabelled (extra) paths: %d", len(extras))
	sort.SliceStable(extras, func(i, j int) bool { return extras[i].Score > extras[j].Score })
	for i, p := range extras {
		if i == 0 {
			b.WriteString("\n\n| score | rule | chain |\n|---|---|---|\n")
		}
		if i >= 15 {
			fmt.Fprintf(&b, "| … | | %d more |\n", len(extras)-15)
			break
		}
		fmt.Fprintf(&b, "| %.2f | %s | %s |\n", p.Score, p.RuleID, p.chain())
	}
	fmt.Fprintf(&b, "\n\n| metric | labelled | real-world |\n|---|---|---|\n")
	fmt.Fprintf(&b, "| expected paths | %d | %d |\n", m.Expected, m.Expected)
	fmt.Fprintf(&b, "| reported paths (all / score >= %.0f) | %d / %d | %d / %d |\n", threshold, m.Reported, m.ReportedHigh, m.Reported, m.ReportedHigh)
	fmt.Fprintf(&b, "| recall (found at any score) | %s | %s |\n", pctOf(m.Recall, m.FoundAny, m.Expected), pctOf(m.RecallReal, m.FoundAnyReal, m.Expected))
	fmt.Fprintf(&b, "| recall@%.0f (best score >= %.0f) | %s | %s |\n", threshold, threshold, pctOf(m.RecallHigh, m.FoundHigh, m.Expected), pctOf(m.RecallHighReal, m.FoundHighReal, m.Expected))
	fmt.Fprintf(&b, "| recall in band (min_score <= best < max_score) | %s | %s |\n", pctOf(m.RecallBand, m.FoundBand, m.Expected), pctOf(m.RecallBandReal, m.FoundBandReal, m.Expected))
	fmt.Fprintf(&b, "| precision (all reported) | %s | %s |\n", pctOf(m.Precision, m.TruePositives, m.Reported), pctOf(m.PrecisionReal, m.TruePositivesReal, m.Reported))
	fmt.Fprintf(&b, "| precision@%.0f (reported >= %.0f) | %s | %s |\n", threshold, threshold, pctOf(m.PrecisionHigh, m.TruePositivesHigh, m.ReportedHigh), pctOf(m.PrecisionRealHigh, m.TruePositivesRealHigh, m.ReportedHigh))
	b.WriteString("\nlabelled: a reported pending-feature path counts as a hit (correct for today's engine). " +
		"real-world: any reported path matching a false_positive or pending-feature label (\"should NOT be reported\") " +
		"is a false positive, and an expected label met only through such a path is not found.\n")
	if len(m.RealFPs) > 0 {
		fmt.Fprintf(&b, "\nReal-world false positives: %d\n\n| score | label | rule | chain |\n|---|---|---|---|\n", len(m.RealFPs))
		for _, f := range m.RealFPs {
			label := f.Label
			if label == "" {
				label = "unlabelled"
			}
			fmt.Fprintf(&b, "| %.2f | %s | %s | %s |\n", f.Score, label, f.Rule, f.Chain)
		}
	}
	return b.String()
}
