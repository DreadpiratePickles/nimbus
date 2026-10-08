package cost

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

var kindOrder = []string{core.KindUnattachedVolume, core.KindOversizedInstance, core.KindUnassociatedIP, core.KindStoppedInstance, core.KindIdleInstance}

var providerOrder = map[string]int{"aws": 0, "azure": 1, "gcp": 2}

func nounFor(kind, provider string) string {
	p := strings.ToLower(provider)
	switch kind {
	case core.KindUnattachedVolume:
		return "orphaned " + map[string]string{"aws": "EBS volumes", "azure": "Azure managed disks", "gcp": "persistent disks"}[p] + defaultNoun(p, "volumes")
	case core.KindUnassociatedIP:
		return "unused " + map[string]string{"aws": "Elastic IPs", "azure": "public IPs", "gcp": "static IPs"}[p] + defaultNoun(p, "public IPs")
	case core.KindStoppedInstance:
		return "stopped " + computeNoun(p, "")
	case core.KindIdleInstance:
		return "idle " + computeNoun(p, "")
	case core.KindOversizedInstance:
		return "oversized " + computeNoun(p, "")
	}
	return kind
}

func defaultNoun(p, n string) string {
	if p == "aws" || p == "azure" || p == "gcp" {
		return ""
	}
	return n
}

func computeNoun(provider, typ string) string {
	switch strings.ToLower(provider) {
	case "aws":
		if strings.Contains(typ, "lambda") {
			return "Lambda functions"
		}
		return "EC2 instances"
	case "azure":
		return "Azure VMs"
	case "gcp":
		return "GCE instances"
	case "kubernetes":
		return "pods"
	}
	return "instances"
}

func dataNoun(typ string) string {
	switch typ {
	case "aws_s3_bucket":
		return "S3 buckets"
	case "gcp_storage_bucket":
		return "GCS buckets"
	case "azure_storage_account":
		return "Azure storage accounts"
	case "aws_db_instance":
		return "RDS instances"
	case "azure_sql_server":
		return "Azure SQL servers"
	case "gcp_sql_database_instance":
		return "Cloud SQL instances"
	}
	return "public data stores"
}

func networkNoun(typ string) string {
	switch typ {
	case "aws_security_group":
		return "security groups"
	case "azure_network_security_group":
		return "network security groups"
	case "gcp_compute_firewall":
		return "firewall rules"
	}
	return "network controls"
}

func singular(n string) string {
	words := strings.Fields(n)
	if len(words) == 0 {
		return n
	}
	last := words[len(words)-1]
	switch {
	case strings.HasSuffix(last, "IPs"), strings.HasSuffix(last, "VMs"):
		last = strings.TrimSuffix(last, "s")
	case strings.HasSuffix(last, "s"):
		last = strings.TrimSuffix(last, "s")
	}
	words[len(words)-1] = last
	return strings.Join(words, " ")
}

// Money renders whole dollars with comma grouping: 2340.4 -> "$2,340".
func Money(v float64) string {
	neg := v < 0
	n := int64(math.Round(math.Abs(v)))
	s := fmt.Sprint(n)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-$" + b.String()
	}
	return "$" + b.String()
}

func pct(v float64) string {
	if v == math.Trunc(v) {
		return fmt.Sprintf("%.0f%%", v)
	}
	return fmt.Sprintf("%.1f%%", v)
}

// Text renders the human summary.
func (r Report) Text() string {
	var b strings.Builder
	b.WriteString("💰 Cost Optimization Opportunities:\n")
	type agg struct {
		kind, provider string
		count          int
		savings        float64
	}
	groups := map[string]*agg{}
	for _, it := range append(append([]Item(nil), r.Zombies...), r.Rightsizing...) {
		k := it.Kind + "|" + strings.ToLower(it.Provider)
		if groups[k] == nil {
			groups[k] = &agg{kind: it.Kind, provider: strings.ToLower(it.Provider)}
		}
		groups[k].count++
		groups[k].savings += it.MonthlySavings
	}
	kindRank := map[string]int{}
	for i, k := range kindOrder {
		kindRank[k] = i
	}
	list := make([]*agg, 0, len(groups))
	for _, a := range groups {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].kind != list[j].kind {
			return kindRank[list[i].kind] < kindRank[list[j].kind]
		}
		pi, oki := providerOrder[list[i].provider]
		pj, okj := providerOrder[list[j].provider]
		if oki != okj {
			return oki
		}
		if pi != pj {
			return pi < pj
		}
		return list[i].provider < list[j].provider
	})
	if len(list) == 0 {
		b.WriteString("- No zombie or oversized resources detected\n")
	}
	for _, a := range list {
		noun := nounFor(a.kind, a.provider)
		if a.count == 1 {
			noun = singular(noun)
		}
		suffix := ""
		if a.kind == core.KindOversizedInstance {
			suffix = " (rightsizing)"
		}
		fmt.Fprintf(&b, "- %d %s → %s/month savings%s\n", a.count, noun, Money(a.savings), suffix)
	}

	b.WriteString("\n🔒 Security + Cost Wins:\n")
	if len(r.SecurityCostWins) == 0 {
		b.WriteString("- No public data stores or internet-exposed resources found\n")
	}
	for _, w := range r.SecurityCostWins {
		fmt.Fprintf(&b, "- %s:\n", w.Title)
		fmt.Fprintf(&b, "  - Reduces breach risk by %s\n", pct(w.RiskReductionPct))
		if w.MonthlySavings > 0 {
			fmt.Fprintf(&b, "  - Saves %s/month (%s)\n", Money(w.MonthlySavings), w.Note)
		}
	}

	b.WriteString("\n📈 ROI:\n")
	fmt.Fprintf(&b, "- Breach probability %s × breach cost %s = %s expected annual loss\n",
		pct(math.Round(r.ROI.BreachProbability*1000)/10), Money(r.ROI.BreachCostUSD), Money(r.ROI.ExpectedAnnualLoss))
	if len(r.ROI.Fixes) == 0 {
		b.WriteString("- No attack paths to break\n")
	}
	for _, f := range r.ROI.Fixes {
		paths := "paths"
		if f.PathsBroken == 1 {
			paths = "path"
		}
		fmt.Fprintf(&b, "- Fix %s: breaks %d attack %s, reduces risk by %s, avoids %s/year expected loss",
			f.CanonicalID, f.PathsBroken, paths, pct(f.RiskReductionPct), Money(f.ExpectedAnnualLossAvoided))
		if f.MonthlySavings > 0 {
			fmt.Fprintf(&b, ", saves %s/month", Money(f.MonthlySavings))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "\nTotal potential savings: %s/month\n", Money(r.TotalMonthlySavings))
	return b.String()
}
