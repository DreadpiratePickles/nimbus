// Package risk is nimbus's single risk-score implementation. Every surface (CLI, dashboard, API,
// Python reports) shows the number computed here; python/nimbus/risk.py only reads it.
//
// The formula, every multiplier, the bands and the changelog are published in docs/scoring.md
// (a test fails when that table drifts from DefaultWeights):
//
//	raw   = base_severity × Π multiplier_i
//	score = raw                                         raw ≤ 7.0 (the High threshold)
//	        7.0 + 3.0 × (1 − e^(−(raw − 7.0) / 4.5))    above it: diminishing returns, bounded by 10
//	rounded to one decimal; bands: Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 5.0, Low < 5.0
//
// Since 2.2.0 (competitive delta 2026-10-09 shortfall #3) the top of the scale is a bounded,
// strictly increasing combination instead of a flat cap at 10: before, 41 of 62 lab findings tied
// at 10.0 (raw up to 38.22) and the top of the ranking was a hidden tie-breaker.
//
// Each multiplier is a Factor with its value, a human reason and the evidence it used. When an
// input is unknown (no exposure data, no CVE/EPSS data, no classification, no criticality) the
// factor is "not scored" (×1.0) and named in Explanation.Missing — never a silent ×1.0.
//
// Since 2.1.0 the score agrees with the path verdict: a finding on a resource that is on no
// complete attack path and is not a crown jewel, sensitive data store or admin-level identity
// gets the off_path factor (×0.5) and its score is capped at the top of Medium (6.9).
package risk

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/intel"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// ScoreVersion changes whenever the formula or a weight changes (semver: major = formula,
// minor = weights/inputs, patch = explanation-only). Recorded on every Ranked and in docs/scoring.md.
const ScoreVersion = "2.4.0"

// Weights are the published multipliers. Zero value means DefaultWeights.
type Weights struct {
	SevCritical, SevHigh, SevMedium, SevLow, SevInfo float64

	ExposureWide, ExposureNarrow, ExposureTrusted, ExposureNone float64

	IdentityAdmin, IdentityWeak, IdentityCredentialVector float64

	DataSensitive, DataSecrets, DataNonSensitive float64

	JewelVeryHigh, JewelHigh, JewelMedium, JewelLow float64
	EnvProduction, EnvStaging, EnvDev               float64

	ExploitKEV, EPSSTop5, EPSSTop20, EPSSMid, EPSSLow float64

	ComplianceRegulated, CompliancePrivacy float64

	RecentChange, NewFinding float64

	Orphaned float64

	PathPerPoint, PathMax float64

	SCPDenied, CompensatingControl float64

	// OffPath multiplies a finding whose resource is on no complete attack path and is not an
	// impact target; OffPathMax is the score ceiling for such a finding (top of Medium).
	OffPath, OffPathMax float64

	// CombineKnee is where diminishing returns start (2.2.0); CombineScale is how fast the score
	// approaches 10 above it: score = knee + (10 − knee)(1 − e^(−(raw − knee)/scale)).
	CombineKnee, CombineScale float64
}

// DefaultWeights — documented row by row in docs/scoring.md (TestWeightsDocumented). The 2.1.0
// changes (changelog in docs/scoring.md): exposure.none 0.7→0.5, identity.admin 1.4→1.25,
// compliance 1.1/1.05→1.0, new_finding 1.05→1.0, orphaned 1.05→1.0, attack_path 0.05/1.5→0.12/2.0,
// new off_path ×0.5 with a 6.9 ceiling.
var DefaultWeights = Weights{
	SevCritical: 7.0, SevHigh: 5.5, SevMedium: 4.0, SevLow: 2.5, SevInfo: 1.0,
	ExposureWide: 1.4, ExposureNarrow: 1.15, ExposureTrusted: 0.8, ExposureNone: 0.5,
	IdentityAdmin: 1.25, IdentityWeak: 1.2, IdentityCredentialVector: 1.1,
	DataSensitive: 1.5, DataSecrets: 1.3, DataNonSensitive: 0.9,
	JewelVeryHigh: 2.0, JewelHigh: 1.6, JewelMedium: 1.2, JewelLow: 1.0,
	EnvProduction: 1.3, EnvStaging: 1.0, EnvDev: 0.8,
	ExploitKEV: 1.5, EPSSTop5: 1.3, EPSSTop20: 1.15, EPSSMid: 1.0, EPSSLow: 0.85,
	ComplianceRegulated: 1.0, CompliancePrivacy: 1.0,
	RecentChange: 1.1, NewFinding: 1.0,
	Orphaned:     1.0,
	PathPerPoint: 0.12, PathMax: 2.0,
	SCPDenied: 0.5, CompensatingControl: 0.8,
	OffPath: 0.5, OffPathMax: 6.9,
	CombineKnee: 7.0, CombineScale: 4.5,
}

// WeightRow is one published weight: docs/scoring.md renders the same rows.
type WeightRow struct {
	Key, Factor, Evidence string
	Value                 float64
}

// Table lists every weight with the factor it belongs to and the evidence that triggers it.
func (w Weights) Table() []WeightRow {
	return []WeightRow{
		{"severity.critical", "base", "finding severity CRITICAL", w.SevCritical},
		{"severity.high", "base", "finding severity HIGH", w.SevHigh},
		{"severity.medium", "base", "finding severity MEDIUM", w.SevMedium},
		{"severity.low", "base", "finding severity LOW", w.SevLow},
		{"severity.info", "base", "finding severity INFO", w.SevInfo},
		{"exposure.wide", "exposure", "node/edge attr exposure=wide, or an internet edge / PUBLIC_* weakness without width data", w.ExposureWide},
		{"exposure.narrow", "exposure", "attr exposure=narrow (specific, non-trusted CIDRs)", w.ExposureNarrow},
		{"exposure.trusted", "exposure", "attr exposure=trusted (only config trusted_cidrs)", w.ExposureTrusted},
		{"exposure.none", "exposure", "attr exposure=none|internal|private", w.ExposureNone},
		{"identity.admin", "identity", "OVERPRIVILEGED_IDENTITY / CLUSTER_ADMIN / attr admin=true on the resource, or it runs as / assumes such an identity (≤2 hops)", w.IdentityAdmin},
		{"identity.weak", "identity", "NO_MFA / CROSS_ACCOUNT_TRUST / STALE_CREDENTIALS", w.IdentityWeak},
		{"identity.credential_vector", "identity", "IMDSV1_ENABLED / SERVICE_ACCOUNT_TOKEN without an admin identity behind it", w.IdentityCredentialVector},
		{"data.sensitive", "data_sensitivity", "graph node sensitive, attr sensitive=true, or DSPM/classification label pii|phi|pci|confidential|restricted|secret|sensitive", w.DataSensitive},
		{"data.secrets", "data_sensitivity", "SECRET_EXPOSURE weakness", w.DataSecrets},
		{"data.non_sensitive", "data_sensitivity", "classification label public|internal|non-sensitive", w.DataNonSensitive},
		{"criticality.very_high", "criticality", "crown-jewel level very_high (config crown_jewels, else node criticality)", w.JewelVeryHigh},
		{"criticality.high", "criticality", "crown-jewel level high", w.JewelHigh},
		{"criticality.medium", "criticality", "crown-jewel level medium", w.JewelMedium},
		{"criticality.low", "criticality", "crown-jewel level low", w.JewelLow},
		{"criticality.production", "criticality", "node criticality production (no crown-jewel level)", w.EnvProduction},
		{"criticality.staging", "criticality", "node criticality staging", w.EnvStaging},
		{"criticality.dev", "criticality", "node criticality dev|test|sandbox", w.EnvDev},
		{"exploitability.kev", "exploitability", "a CVE on the finding is in CISA KEV", w.ExploitKEV},
		{"exploitability.epss_top5", "exploitability", "max EPSS percentile ≥ 0.95", w.EPSSTop5},
		{"exploitability.epss_top20", "exploitability", "max EPSS percentile ≥ 0.80", w.EPSSTop20},
		{"exploitability.epss_mid", "exploitability", "max EPSS percentile ≥ 0.50", w.EPSSMid},
		{"exploitability.epss_low", "exploitability", "max EPSS percentile < 0.50", w.EPSSLow},
		{"compliance.regulated", "compliance_scope", "mapped to pci_dss or hipaa", w.ComplianceRegulated},
		{"compliance.privacy", "compliance_scope", "mapped to soc2 or gdpr", w.CompliancePrivacy},
		{"recent_change.modified_24h", "recent_change", "node modified_at within 24h", w.RecentChange},
		{"recent_change.new_finding_24h", "recent_change", "finding first_seen within 24h", w.NewFinding},
		{"ownership.orphaned", "ownership", "no owner on the node or owner/team tag", w.Orphaned},
		{"attack_path.per_point", "attack_path", "multiplier = 1 + per_point × max path score", w.PathPerPoint},
		{"attack_path.max", "attack_path", "upper bound of the attack-path multiplier", w.PathMax},
		{"compensating.scp_denied", "compensating_controls", "attr scp_denied=true (Track B: SCP/RCP denies the path's key action)", w.SCPDenied},
		{"compensating.control", "compensating_controls", "attr compensating_controls non-empty (WAF, private endpoint, NetworkPolicy)", w.CompensatingControl},
		{"off_path.multiplier", "off_path", "path analysis ran; the resource is on no complete attack path and is not a crown jewel, sensitive data store or admin-level identity", w.OffPath},
		{"off_path.max_score", "off_path", "score ceiling for such a finding (top of the Medium band)", w.OffPathMax},
		{"combination.knee", "combination", "raw product above which diminishing returns apply (the High threshold)", w.CombineKnee},
		{"combination.scale", "combination", "score = knee + (10 − knee)(1 − e^(−(raw − knee)/scale)) above the knee", w.CombineScale},
	}
}

// Factor statuses.
const (
	StatusScored    = "scored"
	StatusNotScored = "not scored"
)

// Factor is one multiplier in the product. Base × Π Multiplier == Score (within 0.01).
type Factor struct {
	Name       string   `json:"name"`
	Multiplier float64  `json:"multiplier"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason"`
	Evidence   []string `json:"evidence,omitempty"`
}

type PathRef struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// Explanation is the "why this score" record attached to every Ranked.
type Explanation struct {
	Score      float64 `json:"score"`
	Version    string  `json:"version"`
	Base       float64 `json:"base"`
	BaseReason string  `json:"base_reason"`
	Raw        float64 `json:"raw"` // base × multipliers before the combination / cap / rounding factors
	// Combination states the rule that maps raw to the 0–10 score (2.2.0), with this finding's numbers.
	Combination string    `json:"combination"`
	Factors     []Factor  `json:"factors"`
	TopPaths    []PathRef `json:"top_paths,omitempty"`
	Missing     []string  `json:"missing,omitempty"`
}

type Ranked struct {
	Finding      model.Finding `json:"finding"`
	Score        float64       `json:"risk_score"` // 0.0–10.0
	Band         string        `json:"band"`
	ScoreVersion string        `json:"score_version"`
	Reasons      []string      `json:"reasons"`
	Explanation  *Explanation  `json:"explanation,omitempty"`
	AttackPaths  int           `json:"attack_paths"`
	MaxPathScore float64       `json:"max_path_score"`
	// Owner, SLADays and DueAt are kept for one release for JSON compatibility and are filled
	// from the governance assignment of the finding's Issue by the callers that hold a store
	// (cli, server: server.GovernRanked). The scorer no longer derives an SLA from the band
	// (retired in integration pass 4, docs/scoring.md changelog): it sets Owner to the owner/team
	// tag it scored and leaves SLADays 0 and DueAt zero.
	Owner   string    `json:"owner"`
	SLADays int       `json:"sla_days"` // Deprecated: governance sla_days of the finding's Issue
	DueAt   time.Time `json:"due_at"`   // Deprecated: governance due_at of the finding's Issue
}

// Explain returns the explanation recorded when r was scored.
func Explain(r Ranked) Explanation {
	if r.Explanation == nil {
		return Explanation{Score: r.Score, Version: r.ScoreVersion, Missing: []string{"explanation (not produced by this scorer)"}}
	}
	return *r.Explanation
}

// BandFor maps a score to its band (Critical ≥ 9, High ≥ 7, Medium ≥ 5, Low < 5).
func BandFor(score float64) string {
	switch {
	case score >= 9:
		return "Critical"
	case score >= 7:
		return "High"
	case score >= 5:
		return "Medium"
	default:
		return "Low"
	}
}

// Intel is the exploitability data the score consumes (internal/intel implements it).
type Intel interface {
	KEV(cve string) bool
	EPSS(cve string) (score, percentile float64, ok bool)
}

// JewelFunc returns the crown-jewel level (very_high|high|medium|low) for a node and the rule that matched.
type JewelFunc func(n *graph.Node) (level, rule string, ok bool)

// Options for PrioritizeWith. Zero values: DefaultWeights, embedded KEV/EPSS snapshot, no config
// crown jewels, all results, time.Now().
//
// Path verdict (off_path factor): with Analysis set, a resource is on a path when it is a step
// of one of Analysis.Paths or Analysis.ReachesCrownJewel says so, and Analysis.Exposures is
// quoted as evidence. Without it, a non-nil graph means the caller ran the analysis and the
// paths argument holds its complete paths (what every CLI / API caller passes). NoAnalysis (or
// a nil graph) means findings-only: off_path is "not scored" and nothing is capped.
type Options struct {
	Weights    Weights
	Intel      Intel
	CrownJewel JewelFunc
	Top        int
	Now        time.Time
	Analysis   *attackpath.Analysis
	NoAnalysis bool
}

// pathVerdict is what the off_path factor reads: whether analysis ran, which resources and
// findings are on a complete path, and the exposure record of exposure-only resources.
type pathVerdict struct {
	present   bool
	paths     int
	resources map[string]bool
	findings  map[string]bool
	exposures map[string]attackpath.Exposure
}

func newPathVerdict(g *graph.Graph, paths []model.AttackPath, o Options) *pathVerdict {
	v := &pathVerdict{resources: map[string]bool{}, findings: map[string]bool{}, exposures: map[string]attackpath.Exposure{}}
	if o.NoAnalysis || (g == nil && o.Analysis == nil) {
		return v
	}
	v.present = true
	add := func(ps []model.AttackPath) {
		for _, p := range ps {
			for _, s := range p.Steps {
				for _, id := range []string{s.Resource, s.WeaknessOn} {
					if id != "" {
						v.resources[id] = true
					}
				}
				if s.FindingID != "" {
					v.findings[s.FindingID] = true
				}
			}
			for _, id := range p.FindingIDs {
				v.findings[id] = true
			}
		}
	}
	add(paths)
	v.paths = len(paths)
	if an := o.Analysis; an != nil {
		add(an.Paths)
		if len(an.Paths) > v.paths {
			v.paths = len(an.Paths)
		}
		for id, on := range an.ReachesCrownJewel {
			if on {
				v.resources[id] = true
			}
		}
		for _, e := range an.Exposures {
			v.exposures[e.NodeID] = e
		}
	}
	return v
}

var (
	snapOnce sync.Once
	snap     *intel.Feed
)

func defaultIntel() Intel {
	snapOnce.Do(func() { snap = intel.Snapshot() })
	return snap
}

// Prioritize scores every FAIL finding and returns the top N (0 = all), highest first. It uses the
// embedded offline KEV/EPSS snapshot; callers with a live feed or config crown jewels use PrioritizeWith.
func Prioritize(findings []model.Finding, g *graph.Graph, paths []model.AttackPath, w Weights, top int, now time.Time) []Ranked {
	return PrioritizeWith(findings, g, paths, Options{Weights: w, Top: top, Now: now})
}

// PrioritizeWith is Prioritize with explicit intel and crown-jewel inputs.
func PrioritizeWith(findings []model.Finding, g *graph.Graph, paths []model.AttackPath, o Options) []Ranked {
	if o.Weights == (Weights{}) {
		o.Weights = DefaultWeights
	}
	if o.Intel == nil {
		o.Intel = defaultIntel()
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Weights.OffPath == 0 {
		o.Weights.OffPath = DefaultWeights.OffPath
	}
	if o.Weights.OffPathMax == 0 {
		o.Weights.OffPathMax = DefaultWeights.OffPathMax
	}
	if o.Weights.CombineKnee == 0 {
		o.Weights.CombineKnee = DefaultWeights.CombineKnee
	}
	if o.Weights.CombineScale == 0 {
		o.Weights.CombineScale = DefaultWeights.CombineScale
	}
	verdict := newPathVerdict(g, paths, o)
	byFinding := map[string][]model.AttackPath{}
	for _, p := range paths {
		seen := map[string]bool{}
		for _, id := range p.FindingIDs {
			if !seen[id] {
				seen[id] = true
				byFinding[id] = append(byFinding[id], p)
			}
		}
	}
	type scored struct {
		Ranked
		raw float64
	}
	var out []scored
	for _, f := range findings {
		if f.Status != model.Fail {
			continue
		}
		r := score(f, g, byFinding[f.ID], verdict, o)
		out = append(out, scored{r, r.Explanation.Raw})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].raw != out[j].raw {
			return out[i].raw > out[j].raw
		}
		return out[i].Finding.ID < out[j].Finding.ID
	})
	if o.Top > 0 && len(out) > o.Top {
		out = out[:o.Top]
	}
	res := make([]Ranked, len(out))
	for i := range out {
		res[i] = out[i].Ranked
	}
	return res
}

type scorer struct {
	w       Weights
	e       *Explanation
	reasons []string
}

func (s *scorer) scored(name string, m float64, reason string, evidence ...string) {
	s.e.Factors = append(s.e.Factors, Factor{Name: name, Multiplier: m, Status: StatusScored, Reason: reason, Evidence: evidence})
	if m != 1 && reason != "" {
		s.reasons = append(s.reasons, reason)
	}
}

func (s *scorer) notScored(name, why string) {
	s.e.Factors = append(s.e.Factors, Factor{Name: name, Multiplier: 1, Status: StatusNotScored, Reason: "not scored: " + why})
	s.e.Missing = append(s.e.Missing, name+" ("+why+")")
}

func score(f model.Finding, g *graph.Graph, paths []model.AttackPath, verdict *pathVerdict, o Options) Ranked {
	w := o.Weights
	var n *graph.Node
	if g != nil {
		n, _ = g.Node(f.Resource.ID)
	}
	e := &Explanation{Version: ScoreVersion}
	s := &scorer{w: w, e: e}
	e.Base, e.BaseReason = baseFor(f.Severity, w)
	s.reasons = append(s.reasons, e.BaseReason)

	exposure(s, f, g, n, verdict)
	adminID := identity(s, f, g, n)
	sensitive := dataSensitivity(s, f, n)
	jewel := criticality(s, n, o.CrownJewel)
	exploitability(s, f, n, o.Intel)
	compliance(s, f)
	recentChange(s, f, n, o.Now)
	owner := ownerOf(f, n)
	if owner == "" {
		s.scored("ownership", w.Orphaned, "no owner tag (orphaned)")
	} else {
		s.scored("ownership", 1, "owned by "+owner, "owner="+owner)
	}
	maxPath := attackPath(s, paths)
	compensating(s, n)
	offCapped := offPath(s, f, len(paths) > 0, verdict, jewel, sensitive, adminID)

	raw := e.Base
	for _, fc := range e.Factors {
		raw *= fc.Multiplier
	}
	e.Raw = raw
	var clamped float64
	switch {
	case raw <= 0:
		clamped = 0
		e.Combination = "raw ≤ 0: score 0"
	case offCapped:
		clamped = math.Min(w.OffPathMax, raw)
		e.Combination = fmt.Sprintf("off path: score = min(raw, %.1f) = %.2f", w.OffPathMax, clamped)
		if clamped != raw {
			e.Factors = append(e.Factors, Factor{Name: "off_path_cap", Multiplier: clamped / raw, Status: StatusScored,
				Reason: fmt.Sprintf("raw score %.2f capped at %.1f: no attack path reaches an impact target from this resource, so the band is at most Medium", raw, w.OffPathMax)})
		}
	default:
		clamped = combine(raw, w)
		if raw <= w.CombineKnee {
			e.Combination = fmt.Sprintf("raw %.2f ≤ knee %.1f: score = raw (diminishing returns start at %.1f)", raw, w.CombineKnee, w.CombineKnee)
		} else {
			e.Combination = fmt.Sprintf("raw %.2f > knee %.1f: score = %.1f + %.1f × (1 − e^(−(%.2f − %.1f) / %.1f)) = %.2f (diminishing returns, bounded by 10)",
				raw, w.CombineKnee, w.CombineKnee, 10-w.CombineKnee, raw, w.CombineKnee, w.CombineScale, clamped)
			e.Factors = append(e.Factors, Factor{Name: "combination", Multiplier: clamped / raw, Status: StatusScored,
				Reason: fmt.Sprintf("diminishing returns above %.1f: raw %.2f → %.2f (bounded combination, 2.2.0; replaces the flat cap at 10)", w.CombineKnee, raw, clamped)})
		}
	}
	final := math.Round(clamped*10) / 10
	if math.Abs(final-clamped) > 1e-9 && clamped > 0 {
		e.Factors = append(e.Factors, Factor{Name: "rounding", Multiplier: final / clamped, Status: StatusScored,
			Reason: fmt.Sprintf("%.4f rounded to one decimal", clamped)})
	}
	e.Score = final
	sort.SliceStable(paths, func(i, j int) bool { return paths[i].Score > paths[j].Score })
	for i := 0; i < len(paths) && i < 3; i++ {
		e.TopPaths = append(e.TopPaths, PathRef{ID: paths[i].ID, Name: paths[i].Name, Score: paths[i].Score})
	}
	r := Ranked{Finding: f, Score: final, Band: BandFor(final), ScoreVersion: ScoreVersion, Reasons: s.reasons, Explanation: e,
		AttackPaths: len(paths), MaxPathScore: maxPath, Owner: owner}
	return r
}

// combine maps a raw product to the 0–10 score (2.2.0): identity up to the knee, then
// knee + (10 − knee)(1 − e^(−(raw − knee)/scale)). It is continuous, strictly increasing and
// bounded by 10, so findings keep the order of their raw products and few tie at 10.0 (only
// raw ≥ knee + scale·ln((10 − knee)/0.05), ≈ 25.4 with the defaults, rounds to 10.0).
func combine(raw float64, w Weights) float64 {
	if raw <= 0 || math.IsNaN(raw) {
		return 0
	}
	k, sc := w.CombineKnee, w.CombineScale
	if k <= 0 || k >= 10 || sc <= 0 {
		return math.Min(raw, 10)
	}
	if raw <= k {
		return raw
	}
	return k + (10-k)*(1-math.Exp(-(raw-k)/sc))
}

func baseFor(sev model.Severity, w Weights) (float64, string) {
	switch sev {
	case model.Critical:
		return w.SevCritical, "CRITICAL severity"
	case model.High:
		return w.SevHigh, "HIGH severity"
	case model.Medium:
		return w.SevMedium, "MEDIUM severity"
	case model.Low:
		return w.SevLow, "LOW severity"
	default:
		return w.SevInfo, "INFO severity"
	}
}

func attrString(n *graph.Node, keys ...string) string {
	if n == nil || n.Attributes == nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := n.Attributes[k]; ok && v != nil {
			if s := strings.ToLower(strings.TrimSpace(fmt.Sprint(v))); s != "" {
				return s
			}
		}
	}
	return ""
}

func attrTrue(attrs map[string]any, key string) bool {
	if attrs == nil {
		return false
	}
	switch v := attrs[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
	}
	return false
}

func attrList(attrs map[string]any, key string) []string {
	if attrs == nil {
		return nil
	}
	switch v := attrs[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			out = append(out, fmt.Sprint(x))
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return strings.Split(v, ",")
	}
	return nil
}

func hasWeakness(f model.Finding, n *graph.Node, ws ...string) string {
	for _, w := range ws {
		if f.HasWeakness(w) {
			return w
		}
		if n != nil {
			for _, x := range n.Weaknesses {
				if x == w {
					return w
				}
			}
		}
	}
	return ""
}

// exposure reads the one reachability verdict (competitive delta r2 #1; graph.Verdict, the same
// verdict `paths --exposures` prints): a blocked resource is "not exposed (blocked: <reason>)"
// ×ExposureNone whatever its exposure label or PUBLIC_* weakness says; an unknown verdict keeps
// the width multiplier and says the exposure is inferred; reachable / no verdict is unchanged.
func exposure(s *scorer, f model.Finding, g *graph.Graph, n *graph.Node, pv *pathVerdict) {
	w := s.w
	width, evidence := "", ""
	if v := attrString(n, "exposure"); v != "" {
		width, evidence = v, "node attr exposure="+v
	}
	internetEdge := false
	if n != nil && g != nil {
		for _, e := range g.In(n.ID) {
			if e.From != graph.InternetNodeID {
				continue
			}
			internetEdge = true
			if width == "" && e.Attr != nil {
				if v, ok := e.Attr["exposure"].(string); ok && v != "" {
					width, evidence = strings.ToLower(v), "internet edge "+e.Kind+" exposure="+v
				}
			}
		}
	}
	pub := hasWeakness(f, nil, "PUBLIC_NETWORK_EXPOSURE", "PUBLIC_DATA_STORE")
	if width == "" && (internetEdge || pub != "") {
		ev := "graph edge from the internet"
		if pub != "" {
			ev = "weakness " + pub
		}
		width, evidence = "wide-assumed", ev+" (no width data; treated as wide)"
	}
	var rv graph.Verdict
	if n != nil && g != nil {
		rv = g.Verdict(n.ID)
	}
	if pv != nil && n != nil && rv.Status != graph.VerdictBlocked {
		if e, ok := pv.exposures[n.ID]; ok && e.Reachability == attackpath.ReachBlocked {
			rv = graph.Verdict{NodeID: n.ID, Status: graph.VerdictBlocked, Reason: e.Reason}
		}
	}
	if width == "" && rv.Routes > 0 && (rv.Status == graph.VerdictReachable || rv.Status == graph.VerdictUnknown) {
		// Reached only through an internet-exposed network control (internet -> NSG/SG ->
		// node: the jump-01 shape, Verification 5 C11): the graph verdict's route counts.
		width, evidence = rv.Width, "internet route through a network control (graph verdict "+rv.Status+")"
		if width == "" {
			width, evidence = "wide-assumed", evidence+" (no width data; treated as wide)"
		}
	}
	if rv.Status == graph.VerdictBlocked {
		ev := "reachability blocked: " + rv.Reason
		if evidence != "" {
			ev += " (overrides " + evidence + ")"
		}
		s.scored("exposure", w.ExposureNone, "not exposed (blocked: "+rv.Reason+")", ev)
		return
	}
	inferred := ""
	if rv.Status == graph.VerdictUnknown {
		inferred = ", inferred: reachability unknown — " + rv.Reason
		evidence += "; reachability unknown: " + rv.Reason
	}
	switch width {
	case "wide", "wide-assumed", "public", "internet":
		s.scored("exposure", w.ExposureWide, "internet exposed (wide"+inferred+")", evidence)
	case "narrow":
		s.scored("exposure", w.ExposureNarrow, "internet exposed to specific source ranges (narrow"+inferred+")", evidence)
	case "trusted":
		s.scored("exposure", w.ExposureTrusted, "reachable only from trusted CIDRs", evidence)
	case "none", "internal", "private":
		s.scored("exposure", w.ExposureNone, "not internet exposed", evidence)
	case "":
		s.notScored("exposure", "no exposure data for the resource")
	default:
		s.notScored("exposure", "unrecognised exposure value "+width)
	}
}

var adminWeak = []string{"OVERPRIVILEGED_IDENTITY", "CLUSTER_ADMIN"}

func isAdminNode(n *graph.Node) bool {
	if n == nil {
		return false
	}
	if attrTrue(n.Attributes, "admin") {
		return true
	}
	for _, w := range n.Weaknesses {
		if w == adminWeak[0] || w == adminWeak[1] {
			return true
		}
	}
	return false
}

// adminBehind finds an admin identity the workload runs as / assumes within two hops.
func adminBehind(g *graph.Graph, n *graph.Node) string {
	if g == nil || n == nil {
		return ""
	}
	kinds := map[string]bool{graph.EdgeRunsAs: true, graph.EdgeAttachedTo: true, graph.EdgeCanAssume: true, graph.EdgeBoundTo: true}
	frontier := []string{n.ID}
	seen := map[string]bool{n.ID: true}
	for hop := 0; hop < 2; hop++ {
		var next []string
		for _, id := range frontier {
			for _, e := range g.Out(id) {
				if !kinds[e.Kind] || seen[e.To] {
					continue
				}
				seen[e.To] = true
				if m, ok := g.Node(e.To); ok && isAdminNode(m) {
					return m.ID
				}
				next = append(next, e.To)
			}
		}
		frontier = next
	}
	return ""
}

// identity scores the identity factor and reports whether the resource itself is an
// admin-level identity (an impact target for off_path; running as one does not count).
func identity(s *scorer, f model.Finding, g *graph.Graph, n *graph.Node) bool {
	w := s.w
	if wk := hasWeakness(f, n, adminWeak...); wk != "" {
		s.scored("identity", w.IdentityAdmin, "administrative privileges", "weakness "+wk)
		return true
	}
	if n != nil && attrTrue(n.Attributes, "admin") {
		s.scored("identity", w.IdentityAdmin, "administrative privileges", "node attr admin=true")
		return true
	}
	if id := adminBehind(g, n); id != "" {
		s.scored("identity", w.IdentityAdmin, "workload runs as an administrative identity", "runs as / assumes "+id)
		return false
	}
	if wk := hasWeakness(f, n, "NO_MFA", "CROSS_ACCOUNT_TRUST", "STALE_CREDENTIALS"); wk != "" {
		s.scored("identity", w.IdentityWeak, "weak or long-lived identity", "weakness "+wk)
		return false
	}
	if wk := hasWeakness(f, n, "IMDSV1_ENABLED", "SERVICE_ACCOUNT_TOKEN"); wk != "" {
		s.scored("identity", w.IdentityCredentialVector, "credential theft vector", "weakness "+wk)
		return false
	}
	s.scored("identity", 1, "no identity weakness or privileged identity found")
	return false
}

// Label vocabularies. Since 2.1.0 they match the path engine's explicit classification
// (internal/attackpath sensitiveClassValues / nonSensitiveClass), plus "internal".
var (
	sensitiveLabels    = map[string]bool{"pii": true, "phi": true, "pci": true, "confidential": true, "restricted": true, "secret": true, "sensitive": true, "high": true}
	nonSensitiveLabels = map[string]bool{"public": true, "internal": true, "non-sensitive": true, "nonsensitive": true, "non_sensitive": true, "none": true,
		"synthetic": true, "test": true, "dummy": true, "open": true}
)

// labelsOf collects DSPM / classification labels from node attrs and finding resource tags.
func labelsOf(f model.Finding, n *graph.Node) []string {
	var out []string
	add := func(attrs map[string]any) {
		for _, k := range []string{"dspm_labels", "data_labels", "classification", "data_sensitivity", "data_classification"} {
			for _, v := range attrList(attrs, k) {
				out = append(out, strings.ToLower(strings.TrimSpace(v)))
			}
		}
		if tags, ok := attrs["tags"].(map[string]any); ok {
			for k, v := range tags {
				lk := strings.ToLower(k)
				if strings.Contains(lk, "classif") || strings.Contains(lk, "sensitiv") {
					out = append(out, strings.ToLower(fmt.Sprint(v)))
				}
			}
		}
	}
	if n != nil && n.Attributes != nil {
		add(n.Attributes)
	}
	if f.Resource.Attributes != nil {
		add(f.Resource.Attributes)
	}
	return out
}

// dataSensitivity scores the data factor and reports whether the resource holds sensitive data
// (an impact target for off_path). An explicit non-sensitive classification (public, none,
// synthetic, test, …) wins over the graph's name-heuristic Sensitive flag, as in the path
// engine: a bucket named public-pii-redacted-reports classified public is not sensitive.
func dataSensitivity(s *scorer, f model.Finding, n *graph.Node) bool {
	w := s.w
	labels := labelsOf(f, n)
	for _, l := range labels {
		if sensitiveLabels[l] {
			s.scored("data_sensitivity", w.DataSensitive, "sensitive data ("+strings.ToUpper(l)+")", "label "+l)
			return true
		}
	}
	nonSensitive := ""
	for _, l := range labels {
		if nonSensitiveLabels[l] {
			nonSensitive = l
			break
		}
	}
	if n != nil && attrTrue(n.Attributes, "sensitive") {
		s.scored("data_sensitivity", w.DataSensitive, "sensitive data (attr sensitive=true)", "node attr sensitive=true")
		return true
	}
	if n != nil && n.Sensitive && nonSensitive == "" {
		s.scored("data_sensitivity", w.DataSensitive, "sensitive data (graph marks the resource sensitive)", "node sensitive=true")
		return true
	}
	if wk := hasWeakness(f, n, "SECRET_EXPOSURE"); wk != "" {
		s.scored("data_sensitivity", w.DataSecrets, "exposes secrets", "weakness "+wk)
		return false
	}
	if nonSensitive != "" {
		ev := "label " + nonSensitive
		if n != nil && n.Sensitive {
			ev += " (overrides the graph's name-based sensitive flag)"
		}
		s.scored("data_sensitivity", w.DataNonSensitive, "classified non-sensitive ("+nonSensitive+")", ev)
		return false
	}
	class := ""
	if n != nil {
		class = n.Class
	}
	if class == "" {
		class = graph.ClassFor(f.Resource.Type)
	}
	if class == graph.ClassDataStore || f.HasWeakness("DATABASE") {
		s.notScored("data_sensitivity", "data store without a classification or DSPM label")
		return false
	}
	s.scored("data_sensitivity", 1, "not a data store", "class "+class)
	return false
}

var jewelLevels = map[string]bool{"very_high": true, "high": true, "medium": true, "low": true}

func normLevel(l string) string {
	l = strings.ToLower(strings.TrimSpace(l))
	l = strings.ReplaceAll(strings.ReplaceAll(l, "-", "_"), " ", "_")
	if l == "veryhigh" || l == "critical" {
		l = "very_high"
	}
	return l
}

func (w Weights) jewel(level string) float64 {
	switch level {
	case "very_high":
		return w.JewelVeryHigh
	case "high":
		return w.JewelHigh
	case "medium":
		return w.JewelMedium
	default:
		return w.JewelLow
	}
}

// criticality scores the criticality factor and reports whether the resource is a crown jewel
// (any level; an impact target for off_path).
func criticality(s *scorer, n *graph.Node, jf JewelFunc) bool {
	w := s.w
	if jf != nil && n != nil {
		if level, rule, ok := jf(n); ok {
			if l := normLevel(level); jewelLevels[l] {
				s.scored("criticality", w.jewel(l), "crown jewel ("+l+")", "config crown_jewels: "+rule)
				return true
			}
		}
	}
	if n == nil {
		s.notScored("criticality", "no graph node, no crown-jewel match")
		return false
	}
	if l := normLevel(attrString(n, "crown_jewel", "crown_jewel_level")); jewelLevels[l] {
		s.scored("criticality", w.jewel(l), "crown jewel ("+l+")", "node attr crown_jewel="+l)
		return true
	}
	c := normLevel(n.Criticality)
	switch {
	case jewelLevels[c]:
		s.scored("criticality", w.jewel(c), "crown jewel ("+c+")", "node criticality="+c)
		return true
	case c == "production" || c == "prod":
		s.scored("criticality", w.EnvProduction, "production workload", "node criticality="+c)
	case c == "staging" || c == "stage" || c == "stg":
		s.scored("criticality", w.EnvStaging, "staging workload", "node criticality="+c)
	case c == "dev" || c == "development" || c == "test" || c == "sandbox":
		s.scored("criticality", w.EnvDev, "non-production workload ("+c+")", "node criticality="+c)
	default:
		s.notScored("criticality", "no crown-jewel level or environment criticality")
	}
	return false
}

var cveRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

// CVEsOf returns the CVE IDs a finding refers to (check/canonical ID and cve/cves attributes).
func CVEsOf(f model.Finding, n *graph.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		for _, m := range cveRe.FindAllString(s, -1) {
			m = strings.ToUpper(m)
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	add(f.CheckID)
	add(f.CanonicalID)
	for _, attrs := range []map[string]any{f.Resource.Attributes, nodeAttrs(n)} {
		for _, k := range []string{"cve", "cves", "vulnerability_id"} {
			for _, v := range attrList(attrs, k) {
				add(v)
			}
		}
	}
	return out
}

func nodeAttrs(n *graph.Node) map[string]any {
	if n == nil {
		return nil
	}
	return n.Attributes
}

func exploitability(s *scorer, f model.Finding, n *graph.Node, in Intel) {
	w := s.w
	cves := CVEsOf(f, n)
	if len(cves) == 0 {
		if n != nil && n.CVECount > 0 {
			s.notScored("exploitability", fmt.Sprintf("%d CVE(s) counted on the resource but no CVE IDs to look up in KEV/EPSS", n.CVECount))
			return
		}
		s.notScored("exploitability", "no CVE data on this finding")
		return
	}
	for _, c := range cves {
		if in.KEV(c) {
			s.scored("exploitability", w.ExploitKEV, c+" is in CISA KEV (known exploited)", "KEV "+c)
			return
		}
	}
	best, bestCVE, bestScore, any := -1.0, "", 0.0, false
	for _, c := range cves {
		if sc, p, ok := in.EPSS(c); ok && p > best {
			best, bestCVE, bestScore, any = p, c, sc, true
		}
	}
	if !any {
		s.notScored("exploitability", "no EPSS data for "+strings.Join(cves, ", ")+" and not in KEV")
		return
	}
	ev := fmt.Sprintf("EPSS %s score %.4f percentile %.3f", bestCVE, bestScore, best)
	switch {
	case best >= 0.95:
		s.scored("exploitability", w.EPSSTop5, fmt.Sprintf("%s in the top 5%% of EPSS exploit likelihood", bestCVE), ev)
	case best >= 0.80:
		s.scored("exploitability", w.EPSSTop20, fmt.Sprintf("%s in the top 20%% of EPSS exploit likelihood", bestCVE), ev)
	case best >= 0.50:
		s.scored("exploitability", w.EPSSMid, fmt.Sprintf("%s has median EPSS exploit likelihood", bestCVE), ev)
	default:
		s.scored("exploitability", w.EPSSLow, fmt.Sprintf("%s has low EPSS exploit likelihood", bestCVE), ev)
	}
}

func compliance(s *scorer, f model.Finding) {
	w := s.w
	var fws []string
	m := 1.0
	for fw, ctrls := range f.Compliance {
		if len(ctrls) == 0 {
			continue
		}
		fws = append(fws, fw)
		switch strings.ToLower(fw) {
		case "pci_dss", "hipaa":
			m = math.Max(m, w.ComplianceRegulated)
		case "soc2", "gdpr":
			m = math.Max(m, w.CompliancePrivacy)
		}
	}
	sort.Strings(fws)
	switch {
	case len(fws) == 0:
		s.scored("compliance_scope", 1, "no compliance framework mapped")
	case m == 1:
		s.scored("compliance_scope", 1, "in scope for "+strings.Join(fws, ", ")+" (no regulated framework)", fws...)
	default:
		s.scored("compliance_scope", m, "in scope for "+strings.Join(fws, ", "), fws...)
	}
}

func recentChange(s *scorer, f model.Finding, n *graph.Node, now time.Time) {
	w := s.w
	if n != nil && n.ModifiedAt != "" {
		if t, err := time.Parse(time.RFC3339, n.ModifiedAt); err == nil && now.Sub(t) >= 0 && now.Sub(t) < 24*time.Hour {
			s.scored("recent_change", w.RecentChange, "changed in the last 24h", "modified_at "+n.ModifiedAt)
			return
		}
	}
	if f.FirstSeen.IsZero() {
		if n == nil || n.ModifiedAt == "" {
			s.notScored("recent_change", "no modified_at or first_seen timestamp")
			return
		}
	} else if d := now.Sub(f.FirstSeen); d >= 0 && d < 24*time.Hour {
		s.scored("recent_change", w.NewFinding, "new finding (first seen < 24h)", "first_seen "+f.FirstSeen.UTC().Format(time.RFC3339))
		return
	}
	s.scored("recent_change", 1, "no change in the last 24h")
}

func ownerOf(f model.Finding, n *graph.Node) string {
	if n != nil && n.Owner != "" {
		return n.Owner
	}
	if f.Resource.Attributes != nil {
		if tags, ok := f.Resource.Attributes["tags"].(map[string]any); ok {
			for _, key := range []string{"owner", "team"} {
				for k, v := range tags {
					if strings.ToLower(k) == key {
						return fmt.Sprint(v)
					}
				}
			}
		}
	}
	return ""
}

func attackPath(s *scorer, paths []model.AttackPath) float64 {
	w := s.w
	if len(paths) == 0 {
		s.scored("attack_path", 1, "not on any attack path")
		return 0
	}
	max, best := 0.0, ""
	for _, p := range paths {
		if p.Score > max {
			max, best = p.Score, p.ID
		}
	}
	m := math.Min(w.PathMax, 1+w.PathPerPoint*max)
	s.scored("attack_path", m, fmt.Sprintf("on %d attack path(s), max score %.1f", len(paths), max), "path "+best)
	return max
}

func compensating(s *scorer, n *graph.Node) {
	w := s.w
	var attrs map[string]any
	if n != nil {
		attrs = n.Attributes
	}
	if attrTrue(attrs, "scp_denied") {
		s.scored("compensating_controls", w.SCPDenied, "an SCP/RCP denies the key action", "node attr scp_denied=true")
		return
	}
	if cs := attrList(attrs, "compensating_controls"); len(cs) > 0 {
		s.scored("compensating_controls", w.CompensatingControl, "compensating control: "+strings.Join(cs, ", "), cs...)
		return
	}
	s.scored("compensating_controls", 1, "no compensating control recorded")
}

// offPath scores the off_path factor (2.1.0) and reports whether the Medium ceiling applies.
// The finding score agrees with the path verdict: when path analysis ran and the finding's
// resource is on no complete attack path, the finding is ×OffPath and capped at OffPathMax —
// unless the resource is itself an impact target (crown jewel, sensitive data store,
// admin-level identity), whose findings matter even when no path reaches them yet.
func offPath(s *scorer, f model.Finding, onFindingPath bool, v *pathVerdict, jewel, sensitive, admin bool) bool {
	w := s.w
	if v == nil || !v.present {
		s.notScored("off_path", "no attack-path analysis (findings-only); no off-path cap applied")
		return false
	}
	rid := f.Resource.ID
	if onFindingPath || v.findings[f.ID] || v.resources[rid] {
		s.scored("off_path", 1, "on a complete attack path", "resource "+rid)
		return false
	}
	var target []string
	if jewel {
		target = append(target, "crown jewel")
	}
	if sensitive {
		target = append(target, "sensitive data store")
	}
	if admin {
		target = append(target, "admin-level identity")
	}
	if len(target) > 0 {
		s.scored("off_path", 1, "on no attack path, but the resource is an impact target ("+strings.Join(target, ", ")+"): not capped",
			fmt.Sprintf("not a step of any of %d complete path(s)", v.paths))
		return false
	}
	ev := []string{fmt.Sprintf("not a step of any of %d complete path(s)", v.paths)}
	if e, ok := v.exposures[rid]; ok {
		ev = append(ev, "exposure only ("+e.Width+"): "+e.Because)
	}
	ev = append(ev, fmt.Sprintf("score capped at %.1f (Medium)", w.OffPathMax))
	s.scored("off_path", w.OffPath, "no attack path reaches an impact target from this resource", ev...)
	return true
}
