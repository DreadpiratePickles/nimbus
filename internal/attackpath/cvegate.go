package attackpath

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/intel"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// CVE exploitability gate (council decision 5; competitive delta 2026-10-09 shortfall #9;
// Cortex CVRS bar: KEV / EPSS decide exploitability, a CVE count alone does not). A hop that
// exists because a workload runs vulnerable software is priced by the best evidence that the
// vulnerability is exploited in the wild:
//
//	a CVE in CISA KEV (or node attr kev=true)           0.9  known exploited
//	EPSS probability ≥ 0.5                               0.6  likely exploited within 30 days
//	EPSS probability ≥ 0.1                               0.3
//	EPSS probability < 0.1                               0.1  below MinLikelihood on its own
//	CVE ids with no KEV / EPSS row, or a CVE count /     0.3  confidence: hint (exploitability unknown,
//	UNPATCHED label with no ids                               not assumed high and not assumed safe)
//
// Thresholds are EPSS *probabilities* (FIRST EPSS v4 score), not percentiles. Where it applies:
// the credential hop "RCE, then credential theft" (credhop.go) takes the gate value; the internet
// hop into the workload is reachability (0.8) and only a KEV listing raises it (to 0.9); an
// internet → workload allows_traffic_to hop takes max(0.55, gate). Before round 2 every one of
// these was 0.95 / 0.6 for any UNPATCHED / CVECount > 0.
const (
	CVEGateKEV       = 0.9
	CVEGateEPSSHigh  = 0.6
	CVEGateEPSSMid   = 0.3
	CVEGateEPSSLow   = 0.1
	CVEGateUnknown   = 0.3
	EPSSHighCutoff   = 0.5
	EPSSMidCutoff    = 0.1
	exposedReachOnly = 0.8 // exposesEval "reachable from the internet"
)

// CVEIntel is the exploitability data the gate reads (internal/intel.Feed implements it; risk.Intel
// is the same interface).
type CVEIntel interface {
	KEV(cve string) bool
	EPSS(cve string) (score, percentile float64, ok bool)
}

var (
	gateSnapOnce sync.Once
	gateSnap     *intel.Feed
)

func defaultCVEIntel() CVEIntel {
	gateSnapOnce.Do(func() { gateSnap = intel.Snapshot() })
	return gateSnap
}

var cveIDRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

func cveIDs(s string) []string {
	var out []string
	for _, m := range cveIDRe.FindAllString(s, -1) {
		out = append(out, strings.ToUpper(m))
	}
	return out
}

// CVEIndex maps a resource id to the CVE ids its FAIL findings name (check id, canonical id and
// the cve / cves / vulnerability_id attributes). The graph keeps only a CVE count per node, so
// callers pass this as TraversalOptions.NodeCVEs to let the gate look the ids up in KEV / EPSS.
func CVEIndex(findings []model.Finding) map[string][]string {
	out := map[string][]string{}
	for _, f := range findings {
		if f.Status != model.Fail || f.Resource.ID == "" {
			continue
		}
		ids := append(cveIDs(f.CheckID), cveIDs(f.CanonicalID)...)
		for _, k := range []string{"cve", "cves", "vulnerability_id"} {
			for _, v := range toStrings(f.Resource.Attributes[k]) {
				ids = append(ids, cveIDs(v)...)
			}
		}
		if len(ids) > 0 {
			out[f.Resource.ID] = uniq(append(out[f.Resource.ID], ids...))
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// cveGate is the gate's verdict for one node.
type cveGate struct {
	applies bool    // the node runs vulnerable software (UNPATCHED, CVE count, ids or kev attr)
	p       float64 // gate likelihood
	kev     bool
	hint    bool
	label   string
}

// gateCVE evaluates node n. o may be nil (snapshot intel, no finding index).
func gateCVE(n *graph.Node, o *TraversalOptions) cveGate {
	if n == nil {
		return cveGate{}
	}
	var ids []string
	for _, k := range []string{"cve", "cves", "cve_ids", "vulnerability_id"} {
		for _, v := range toStrings(n.Attributes[k]) {
			ids = append(ids, cveIDs(v)...)
		}
	}
	var in CVEIntel
	if o != nil {
		ids = append(ids, o.NodeCVEs[n.ID]...)
		in = o.Intel
	}
	if in == nil {
		in = defaultCVEIntel()
	}
	ids = uniq(ids)
	sort.Strings(ids)
	kevAttr, _ := n.Attributes["kev"].(bool)
	if !kevAttr && len(ids) == 0 && n.CVECount == 0 && !n.HasWeakness("UNPATCHED") {
		return cveGate{}
	}
	g := cveGate{applies: true}
	for _, c := range ids {
		if in.KEV(c) {
			g.p, g.kev, g.label = CVEGateKEV, true, c+" is in CISA KEV (known exploited)"
			return g
		}
	}
	if kevAttr {
		g.p, g.kev, g.label = CVEGateKEV, true, "a CVE listed in CISA KEV (node attr kev=true)"
		return g
	}
	best, bestID, any := -1.0, "", false
	for _, c := range ids {
		if s, _, ok := in.EPSS(c); ok && s > best {
			best, bestID, any = s, c, true
		}
	}
	switch {
	case any && best >= EPSSHighCutoff:
		g.p, g.label = CVEGateEPSSHigh, fmt.Sprintf("%s EPSS %.3f ≥ %.1f (not in KEV)", bestID, best, EPSSHighCutoff)
	case any && best >= EPSSMidCutoff:
		g.p, g.label = CVEGateEPSSMid, fmt.Sprintf("%s EPSS %.3f ≥ %.1f (not in KEV)", bestID, best, EPSSMidCutoff)
	case any:
		g.p, g.label = CVEGateEPSSLow, fmt.Sprintf("%s EPSS %.3f < %.1f and not in KEV: exploitation unlikely", bestID, best, EPSSMidCutoff)
	case len(ids) > 0:
		g.p, g.hint, g.label = CVEGateUnknown, true, strings.Join(ids, ", ")+" not in KEV and no EPSS data: exploitability unknown (confidence hint)"
	default:
		g.p, g.hint, g.label = CVEGateUnknown, true, "vulnerable software reported without CVE ids to check against KEV / EPSS (confidence hint)"
	}
	return g
}
