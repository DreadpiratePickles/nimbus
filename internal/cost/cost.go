// Package cost turns collector cost signals, the security graph and attack paths into
// zombie-resource, rightsizing, security+cost and ROI recommendations.
package cost

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// DefaultBreachCostUSD is the IBM Cost of a Data Breach 2024 global average.
const DefaultBreachCostUSD = 4_880_000

// DefaultHoursPerMonth is the billing-hours convention used by AWS/Azure/GCP.
const DefaultHoursPerMonth = 730

// defaultStoppedGB is the assumed root volume when a stopped instance reports no storage.
const defaultStoppedGB = 8

const (
	CategoryZombie      = "zombie"
	CategoryRightsizing = "rightsizing"
)

type Options struct {
	BreachCostUSD float64  `json:"breach_cost_usd"`
	HoursPerMonth float64  `json:"hours_per_month"`
	Pricing       *Pricing `json:"-"`
	// Findings maps attack-path finding IDs to canonical IDs and resources.
	Findings []model.Finding `json:"-"`
}

type Item struct {
	Provider       string  `json:"provider"`
	Account        string  `json:"account"`
	Region         string  `json:"region,omitempty"`
	ResourceID     string  `json:"resource_id"`
	ResourceType   string  `json:"resource_type,omitempty"`
	Kind           string  `json:"kind"`
	Category       string  `json:"category"`
	Description    string  `json:"description"`
	CurrentMonthly float64 `json:"current_monthly"`
	MonthlySavings float64 `json:"monthly_savings"`
	Recommendation string  `json:"recommendation"`
}

type Win struct {
	Title            string   `json:"title"`
	Theme            string   `json:"theme"`
	Resources        []string `json:"resources"`
	CanonicalIDs     []string `json:"canonical_ids,omitempty"`
	RiskReductionPct float64  `json:"risk_reduction_pct"`
	MonthlySavings   float64  `json:"monthly_savings"`
	Note             string   `json:"note"`
}

type Fix struct {
	CanonicalID               string   `json:"canonical_id"`
	FindingIDs                []string `json:"finding_ids"`
	PathsBroken               int      `json:"paths_broken"`
	RiskReductionPct          float64  `json:"risk_reduction_pct"`
	ExpectedAnnualLossAvoided float64  `json:"expected_annual_loss_avoided"`
	MonthlySavings            float64  `json:"monthly_savings"`
}

type ROI struct {
	BreachCostUSD      float64 `json:"breach_cost_usd"`
	TotalPathScore     float64 `json:"total_path_score"`
	BreachProbability  float64 `json:"breach_probability"`
	ExpectedAnnualLoss float64 `json:"expected_annual_loss"`
	Fixes              []Fix   `json:"fixes"`
}

// ServiceSpend is informational Cost Explorer spend (not counted as savings).
type ServiceSpend struct {
	Provider     string  `json:"provider"`
	Account      string  `json:"account"`
	Service      string  `json:"service"`
	MonthlySpend float64 `json:"monthly_spend"`
}

type Report struct {
	Zombies             []Item         `json:"zombies"`
	Rightsizing         []Item         `json:"rightsizing"`
	SecurityCostWins    []Win          `json:"security_cost_wins"`
	ROI                 ROI            `json:"roi"`
	Spend               []ServiceSpend `json:"spend,omitempty"`
	TotalMonthlySavings float64        `json:"total_monthly_savings"`
}

// JSON renders the report as indented JSON.
func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// BreachProbability is p = 1 - exp(-totalScore/50).
func BreachProbability(totalScore float64) float64 {
	if totalScore <= 0 {
		return 0
	}
	return 1 - math.Exp(-totalScore/50)
}

// Analyze prices signals, groups security wins from the graph and computes ROI per fix.
func Analyze(signals []core.CostSignal, g *graph.Graph, paths []model.AttackPath, opts Options) Report {
	if opts.BreachCostUSD <= 0 {
		opts.BreachCostUSD = DefaultBreachCostUSD
	}
	if opts.HoursPerMonth <= 0 {
		opts.HoursPerMonth = DefaultHoursPerMonth
	}
	if opts.Pricing == nil {
		opts.Pricing = DefaultPricing()
	}
	var r Report
	egress := map[string]float64{}
	for _, s := range signals {
		switch s.Kind {
		case core.KindPublicEgress:
			egress[s.ResourceID] += egressMonthly(s, opts.Pricing)
		case core.KindServiceSpend:
			r.Spend = append(r.Spend, ServiceSpend{Provider: s.Provider, Account: s.Account, Service: attrString(s.Attributes, "service", s.ResourceID), MonthlySpend: round2(s.MonthlySpend)})
		case core.KindOversizedInstance:
			r.Rightsizing = append(r.Rightsizing, rightsize(s, opts))
		case core.KindUnattachedVolume, core.KindUnassociatedIP, core.KindStoppedInstance, core.KindIdleInstance:
			r.Zombies = append(r.Zombies, zombie(s, opts))
		}
	}
	sortItems(r.Zombies)
	sortItems(r.Rightsizing)
	sort.Slice(r.Spend, func(i, j int) bool { return r.Spend[i].MonthlySpend > r.Spend[j].MonthlySpend })

	idx := newPathIndex(paths, opts.Findings)
	r.SecurityCostWins = wins(g, idx, egress, opts.Findings)
	r.ROI = roi(idx, egress, opts)

	for _, it := range r.Zombies {
		r.TotalMonthlySavings += it.MonthlySavings
	}
	for _, it := range r.Rightsizing {
		r.TotalMonthlySavings += it.MonthlySavings
	}
	for _, w := range r.SecurityCostWins {
		r.TotalMonthlySavings += w.MonthlySavings
	}
	r.TotalMonthlySavings = round2(r.TotalMonthlySavings)
	return r
}

func sortItems(items []Item) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].MonthlySavings != items[j].MonthlySavings {
			return items[i].MonthlySavings > items[j].MonthlySavings
		}
		return items[i].ResourceID < items[j].ResourceID
	})
}

func base(s core.CostSignal, category string) Item {
	return Item{Provider: s.Provider, Account: s.Account, Region: s.Region, ResourceID: s.ResourceID, ResourceType: s.ResourceType, Kind: s.Kind, Category: category}
}

func zombie(s core.CostSignal, o Options) Item {
	it := base(s, CategoryZombie)
	p := o.Pricing
	switch s.Kind {
	case core.KindUnattachedVolume:
		class := attrString(s.Attributes, "volume_type", attrString(s.Attributes, "sku", attrString(s.Attributes, "disk_type", "")))
		it.CurrentMonthly = s.SizeGB * p.StorageGB(s.Provider, class)
		it.Description = fmt.Sprintf("%.0f GB unattached volume", s.SizeGB)
		it.Recommendation = "Snapshot (if needed) and delete the unattached volume"
	case core.KindUnassociatedIP:
		it.CurrentMonthly = p.IP(s.Provider)
		it.Description = "Public IP not associated with any running resource"
		it.Recommendation = "Release the unused address"
	case core.KindStoppedInstance:
		gb := attrFloat(s.Attributes, "volume_gb")
		if gb <= 0 {
			gb = s.SizeGB
		}
		if gb <= 0 {
			gb = defaultStoppedGB
		}
		it.CurrentMonthly = gb * p.StorageGB(s.Provider, attrString(s.Attributes, "volume_type", ""))
		it.Description = fmt.Sprintf("Stopped %s still billing %.0f GB of attached storage", nonEmpty(s.InstanceType, "instance"), gb)
		it.Recommendation = "Snapshot / image and terminate the stopped instance"
	case core.KindIdleInstance:
		h, _ := p.InstanceHourly(s.Provider, s.InstanceType)
		it.CurrentMonthly = h * o.HoursPerMonth
		it.Description = fmt.Sprintf("%s averaging %.1f%% CPU", nonEmpty(s.InstanceType, "instance"), s.AvgCPU)
		it.Recommendation = "Stop or terminate the idle instance (or schedule it off-hours)"
	}
	if s.MonthlySpend > 0 {
		it.CurrentMonthly = s.MonthlySpend
	}
	it.CurrentMonthly = round2(it.CurrentMonthly)
	it.MonthlySavings = it.CurrentMonthly
	return it
}

func rightsize(s core.CostSignal, o Options) Item {
	it := base(s, CategoryRightsizing)
	p := o.Pricing
	cur, known := p.InstanceHourly(s.Provider, s.InstanceType)
	curMonthly := cur * o.HoursPerMonth
	if s.MonthlySpend > 0 {
		curMonthly = s.MonthlySpend
	}
	target, tPrice, ok := p.Downsize(s.Provider, s.InstanceType)
	switch {
	case ok && known && cur > 0:
		it.MonthlySavings = curMonthly * (1 - tPrice/cur)
		it.Recommendation = fmt.Sprintf("Downsize %s → %s", s.InstanceType, target)
	default:
		it.MonthlySavings = curMonthly / 2
		it.Recommendation = fmt.Sprintf("Downsize %s one size within its family", nonEmpty(s.InstanceType, "instance"))
	}
	it.Description = fmt.Sprintf("%s averaging %.1f%% CPU", nonEmpty(s.InstanceType, "instance"), s.AvgCPU)
	it.CurrentMonthly = round2(curMonthly)
	it.MonthlySavings = round2(it.MonthlySavings)
	return it
}

func egressMonthly(s core.CostSignal, p *Pricing) float64 {
	if s.MonthlySpend > 0 {
		return s.MonthlySpend
	}
	gb := attrFloat(s.Attributes, "egress_gb")
	if gb <= 0 {
		gb = s.SizeGB
	}
	return gb * p.Egress(s.Provider)
}

// ---------------------------------------------------------------- attack-path index

type pathIndex struct {
	paths      []model.AttackPath
	ids        []map[string]bool // finding IDs per path
	total      float64
	canonical  map[string]string // finding ID -> canonical / group key
	resourceOf map[string]string // finding ID -> resource ID
}

func newPathIndex(paths []model.AttackPath, findings []model.Finding) *pathIndex {
	ix := &pathIndex{paths: paths, canonical: map[string]string{}, resourceOf: map[string]string{}}
	for _, f := range findings {
		key := f.CanonicalID
		if key == "" {
			key = f.CheckID
		}
		ix.canonical[f.ID] = key
		ix.resourceOf[f.ID] = f.Resource.ID
	}
	for _, p := range paths {
		set := map[string]bool{}
		for _, id := range p.FindingIDs {
			set[id] = true
		}
		for _, st := range p.Steps {
			if st.FindingID == "" {
				continue
			}
			set[st.FindingID] = true
			if _, ok := ix.canonical[st.FindingID]; !ok && st.Weakness != "" {
				ix.canonical[st.FindingID] = st.Weakness
			}
			if _, ok := ix.resourceOf[st.FindingID]; !ok && st.Resource != "" {
				ix.resourceOf[st.FindingID] = st.Resource
			}
		}
		ix.ids = append(ix.ids, set)
		ix.total += p.Score
	}
	return ix
}

// removed returns paths broken and score removed when the given findings are fixed.
func (ix *pathIndex) removed(fixed map[string]bool) (int, float64) {
	n, score := 0, 0.0
	for i, set := range ix.ids {
		for id := range set {
			if fixed[id] {
				n++
				score += ix.paths[i].Score
				break
			}
		}
	}
	return n, score
}

func (ix *pathIndex) reductionPct(fixed map[string]bool) (int, float64) {
	n, s := ix.removed(fixed)
	if ix.total <= 0 {
		return n, 0
	}
	return n, round1(100 * s / ix.total)
}

// ---------------------------------------------------------------- security + cost wins

type theme struct {
	key, verb, noun string
}

func themeFor(n *graph.Node, exposed bool) (theme, bool) {
	switch n.Class {
	case graph.ClassDataStore:
		if !exposed && !n.HasWeakness("PUBLIC_DATA_STORE") {
			return theme{}, false
		}
		return theme{"public_data:" + n.Type, "Removing public access from", dataNoun(n.Type)}, true
	case graph.ClassNetwork:
		if !n.HasWeakness("PUBLIC_NETWORK_EXPOSURE") {
			return theme{}, false
		}
		return theme{"open_network:" + n.Type, "Closing internet-open ports on", networkNoun(n.Type)}, true
	case graph.ClassCompute:
		if !exposed {
			return theme{}, false
		}
		return theme{"exposed_compute:" + n.Type, "Removing direct internet exposure from", computeNoun(n.Provider, n.Type)}, true
	}
	return theme{}, false
}

func wins(g *graph.Graph, ix *pathIndex, egress map[string]float64, findings []model.Finding) []Win {
	if g == nil {
		return nil
	}
	findingsByRes := map[string][]model.Finding{}
	for _, f := range findings {
		if f.Status == model.Fail || f.Status == "" {
			findingsByRes[f.Resource.ID] = append(findingsByRes[f.Resource.ID], f)
		}
	}
	type group struct {
		th    theme
		nodes []*graph.Node
	}
	groups := map[string]*group{}
	for _, n := range g.Nodes() {
		exposed := false
		for _, e := range g.In(n.ID) {
			if e.Kind == graph.EdgeExposes && e.From == graph.InternetNodeID {
				exposed = true
				break
			}
		}
		th, ok := themeFor(n, exposed)
		if !ok {
			continue
		}
		gr := groups[th.key]
		if gr == nil {
			gr = &group{th: th}
			groups[th.key] = gr
		}
		gr.nodes = append(gr.nodes, n)
	}
	var out []Win
	for _, gr := range groups {
		fixed := map[string]bool{}
		canon := map[string]bool{}
		w := Win{Theme: strings.SplitN(gr.th.key, ":", 2)[0], Note: "data transfer costs"}
		for _, n := range gr.nodes {
			w.Resources = append(w.Resources, n.ID)
			for _, id := range n.FindingIDs {
				fixed[id] = true
				if c := ix.canonical[id]; c != "" {
					canon[c] = true
				}
			}
			for _, f := range findingsByRes[n.ID] {
				fixed[f.ID] = true
				if f.CanonicalID != "" {
					canon[f.CanonicalID] = true
				}
			}
			w.MonthlySavings += egress[n.ID]
		}
		sort.Strings(w.Resources)
		w.CanonicalIDs = sortedSet(canon)
		_, w.RiskReductionPct = ix.reductionPct(fixed)
		w.MonthlySavings = round2(w.MonthlySavings)
		noun := gr.th.noun
		if len(gr.nodes) == 1 {
			noun = singular(noun)
			w.Title = fmt.Sprintf("%s this %s", gr.th.verb, noun)
		} else {
			w.Title = fmt.Sprintf("%s these %d %s", gr.th.verb, len(gr.nodes), noun)
		}
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RiskReductionPct != out[j].RiskReductionPct {
			return out[i].RiskReductionPct > out[j].RiskReductionPct
		}
		if out[i].MonthlySavings != out[j].MonthlySavings {
			return out[i].MonthlySavings > out[j].MonthlySavings
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// ---------------------------------------------------------------- ROI

func roi(ix *pathIndex, egress map[string]float64, o Options) ROI {
	r := ROI{BreachCostUSD: o.BreachCostUSD, TotalPathScore: round2(ix.total), BreachProbability: BreachProbability(ix.total)}
	r.ExpectedAnnualLoss = round2(o.BreachCostUSD * r.BreachProbability)
	groups := map[string]map[string]bool{}
	for _, set := range ix.ids {
		for id := range set {
			key := ix.canonical[id]
			if key == "" {
				key = id
			}
			if groups[key] == nil {
				groups[key] = map[string]bool{}
			}
			groups[key][id] = true
		}
	}
	for key, ids := range groups {
		n, pct := ix.reductionPct(ids)
		fx := Fix{CanonicalID: key, FindingIDs: sortedSet(ids), PathsBroken: n, RiskReductionPct: pct}
		fx.ExpectedAnnualLossAvoided = round2(o.BreachCostUSD * r.BreachProbability * pct / 100)
		seen := map[string]bool{}
		for id := range ids {
			if res := ix.resourceOf[id]; res != "" && !seen[res] {
				seen[res] = true
				fx.MonthlySavings += egress[res]
			}
		}
		fx.MonthlySavings = round2(fx.MonthlySavings)
		r.Fixes = append(r.Fixes, fx)
	}
	sort.Slice(r.Fixes, func(i, j int) bool {
		if r.Fixes[i].ExpectedAnnualLossAvoided != r.Fixes[j].ExpectedAnnualLossAvoided {
			return r.Fixes[i].ExpectedAnnualLossAvoided > r.Fixes[j].ExpectedAnnualLossAvoided
		}
		return r.Fixes[i].CanonicalID < r.Fixes[j].CanonicalID
	})
	return r
}

// ---------------------------------------------------------------- helpers

func attrString(m map[string]any, key, def string) string {
	if v, ok := m[key]; ok && v != nil {
		if s := fmt.Sprint(v); s != "" {
			return s
		}
	}
	return def
}

func attrFloat(m map[string]any, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	}
	return 0
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
func round1(f float64) float64 { return math.Round(f*10) / 10 }
