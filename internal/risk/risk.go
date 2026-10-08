// Package risk is the context-aware prioritization engine (Go fallback; the Python model in
// python/nimbus/risk.py is preferred when available and uses the same published formula).
//
// Score (1.0–10.0, Orca-style bands: Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0, Low < 4.0):
//   base      = severity weight                     (CRITICAL 1.0, HIGH .8, MEDIUM .55, LOW .3, INFO .1)
//   context   = Σ weight_i × feature_i  over: exposure, identity, data sensitivity, criticality,
//               vulnerabilities, compliance scope, recent change, orphaned ownership, attack paths
//   score     = 1 + 9 × sigmoid(k × (0.45 × base + 0.55 × context) − b)
// Every contributing feature is returned as a human-readable reason (Defender-style "why this ranks").
package risk

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

type Weights struct {
	Exposure     float64 `json:"exposure"`
	Identity     float64 `json:"identity"`
	Data         float64 `json:"data_sensitivity"`
	Criticality  float64 `json:"criticality"`
	Vulns        float64 `json:"vulnerabilities"`
	Compliance   float64 `json:"compliance_scope"`
	RecentChange float64 `json:"recent_change"`
	Orphaned     float64 `json:"orphaned"`
	AttackPaths  float64 `json:"attack_paths"`
}

// DefaultWeights are published so users can reason about rankings (and override via config).
var DefaultWeights = Weights{Exposure: 0.22, Identity: 0.16, Data: 0.16, Criticality: 0.12, Vulns: 0.08, Compliance: 0.06, RecentChange: 0.05, Orphaned: 0.03, AttackPaths: 0.12}

type Ranked struct {
	Finding     model.Finding `json:"finding"`
	Score       float64       `json:"risk_score"` // 1.0–10.0
	Band        string        `json:"band"`
	Reasons     []string      `json:"reasons"`
	AttackPaths int           `json:"attack_paths"`
	MaxPathScore float64      `json:"max_path_score"`
	Owner       string        `json:"owner"`
	SLADays     int           `json:"sla_days"`
	DueAt       time.Time     `json:"due_at"`
}

var slaDays = map[string]int{"Critical": 7, "High": 30, "Medium": 90, "Low": 180}

func sigmoid(x float64) float64 { return 1 / (1 + math.Exp(-x)) }

// Prioritize scores every FAIL finding and returns the top N (0 = all), highest first.
func Prioritize(findings []model.Finding, g *graph.Graph, paths []model.AttackPath, w Weights, top int, now time.Time) []Ranked {
	if w == (Weights{}) {
		w = DefaultWeights
	}
	pathCount := map[string]int{}
	pathMax := map[string]float64{}
	for _, p := range paths {
		for _, id := range p.FindingIDs {
			pathCount[id]++
			if p.Score > pathMax[id] {
				pathMax[id] = p.Score
			}
		}
	}
	var out []Ranked
	for _, f := range findings {
		if f.Status != model.Fail {
			continue
		}
		var n *graph.Node
		if g != nil {
			n, _ = g.Node(f.Resource.ID)
		}
		r := Ranked{Finding: f, AttackPaths: pathCount[f.ID], MaxPathScore: pathMax[f.ID]}
		base := map[model.Severity]float64{model.Critical: 1, model.High: .8, model.Medium: .55, model.Low: .3, model.Info: .1}[f.Severity]
		ctx := 0.0
		add := func(weight, val float64, reason string) {
			if val <= 0 {
				return
			}
			ctx += weight * val
			r.Reasons = append(r.Reasons, reason)
		}
		// exposure
		exposed := f.HasWeakness("PUBLIC_NETWORK_EXPOSURE") || f.HasWeakness("PUBLIC_DATA_STORE")
		if !exposed && n != nil {
			for _, e := range g.In(n.ID) {
				if e.From == graph.InternetNodeID {
					exposed = true
				}
			}
		}
		if exposed {
			add(w.Exposure, 1, "internet exposed")
		}
		// identity
		switch {
		case f.HasWeakness("OVERPRIVILEGED_IDENTITY") || f.HasWeakness("CLUSTER_ADMIN"):
			add(w.Identity, 1, "administrative privileges")
		case f.HasWeakness("NO_MFA") || f.HasWeakness("CROSS_ACCOUNT_TRUST") || f.HasWeakness("STALE_CREDENTIALS"):
			add(w.Identity, .7, "weak or long-lived identity")
		case f.HasWeakness("IMDSV1_ENABLED") || f.HasWeakness("SERVICE_ACCOUNT_TOKEN"):
			add(w.Identity, .5, "credential theft vector")
		}
		// data sensitivity
		sens := n != nil && n.Sensitive
		if !sens && f.HasWeakness("DATABASE") {
			sens = true
		}
		if !sens && f.Resource.Attributes != nil {
			if tags, ok := f.Resource.Attributes["tags"].(map[string]any); ok {
				for k, v := range tags {
					lk := strings.ToLower(k)
					lv := strings.ToLower(fmt.Sprint(v))
					if (strings.Contains(lk, "classif") || strings.Contains(lk, "sensitiv")) && (lv == "pii" || lv == "phi" || lv == "pci" || lv == "confidential" || lv == "restricted") {
						sens = true
					}
				}
			}
		}
		if sens {
			add(w.Data, 1, "sensitive data (PII/secrets/production database)")
		} else if f.HasWeakness("UNENCRYPTED_AT_REST") || f.HasWeakness("SECRET_EXPOSURE") {
			add(w.Data, .5, "data protection weakness")
		}
		// criticality
		crit := "unknown"
		if n != nil && n.Criticality != "" {
			crit = n.Criticality
		} else if lbl := f.Tags["account_label"]; strings.Contains(strings.ToLower(lbl+f.Account+f.Resource.Name), "prod") {
			crit = "production"
		}
		switch crit {
		case "production":
			add(w.Criticality, 1, "production workload")
		case "staging":
			add(w.Criticality, .6, "staging workload")
		case "unknown":
			add(w.Criticality, .5, "")
			r.Reasons = r.Reasons[:len(r.Reasons)-1]
		case "dev":
			add(w.Criticality, .3, "")
			r.Reasons = r.Reasons[:len(r.Reasons)-1]
		}
		// vulnerabilities
		if n != nil && n.CVECount > 0 {
			add(w.Vulns, math.Min(1, float64(n.CVECount)/5), fmt.Sprintf("%d known vulnerabilities on the resource", n.CVECount))
		} else if f.HasWeakness("UNPATCHED") {
			add(w.Vulns, .8, "exploitable vulnerability")
		}
		// compliance scope
		cw := 0.0
		var fws []string
		for fw := range f.Compliance {
			switch fw {
			case "pci_dss", "hipaa":
				cw = math.Max(cw, 1)
			case "soc2", "gdpr":
				cw = math.Max(cw, .8)
			default:
				cw = math.Max(cw, .6)
			}
			fws = append(fws, fw)
		}
		if cw > 0 {
			sort.Strings(fws)
			add(w.Compliance, cw, "in scope for "+strings.Join(fws, ", "))
		}
		// recent change
		if n != nil && n.ModifiedAt != "" {
			if t, err := time.Parse(time.RFC3339, n.ModifiedAt); err == nil && now.Sub(t) < 24*time.Hour {
				add(w.RecentChange, 1, "changed in the last 24h")
			}
		}
		if now.Sub(f.FirstSeen) < 24*time.Hour && !f.FirstSeen.IsZero() {
			add(w.RecentChange, .5, "new finding (first seen < 24h)")
		}
		// ownership
		owner := ""
		if n != nil {
			owner = n.Owner
		}
		if owner == "" && f.Resource.Attributes != nil {
			if tags, ok := f.Resource.Attributes["tags"].(map[string]any); ok {
				for k, v := range tags {
					if lk := strings.ToLower(k); lk == "owner" || lk == "team" {
						owner = fmt.Sprint(v)
					}
				}
			}
		}
		r.Owner = owner
		if owner == "" {
			add(w.Orphaned, 1, "no owner tag (orphaned)")
		}
		// attack paths
		if r.AttackPaths > 0 {
			add(w.AttackPaths, math.Min(1, r.MaxPathScore/10+float64(r.AttackPaths)/20), fmt.Sprintf("on %d attack path(s), max score %.1f", r.AttackPaths, r.MaxPathScore))
		}
		x := 0.45*base + 0.55*ctx
		r.Score = math.Round((1+9*sigmoid(7*(x-0.42)))*10) / 10
		switch {
		case r.Score >= 9:
			r.Band = "Critical"
		case r.Score >= 7:
			r.Band = "High"
		case r.Score >= 4:
			r.Band = "Medium"
		default:
			r.Band = "Low"
		}
		r.SLADays = slaDays[r.Band]
		r.DueAt = f.FirstSeen.Add(time.Duration(r.SLADays) * 24 * time.Hour)
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Finding.ID < out[j].Finding.ID
	})
	if top > 0 && len(out) > top {
		out = out[:top]
	}
	return out
}
