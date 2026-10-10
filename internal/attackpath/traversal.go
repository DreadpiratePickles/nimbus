package attackpath

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/iam"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Graph traversal attack-path analysis.
//
// Scoring follows the most transparent model on the market (Google SCC attack exposure):
//   score = likelihood × priority, on a 0–10 scale
//   likelihood = Π step_exploitability × hop_decay^hops   (AND along a path: every hop must hold)
//   priority   = crown-jewel criticality: 4 → 10, 3 → 5, 2 → 2, 1 → 1
// Alternative paths to the same target are reported separately; there is no OR aggregation
// of likelihood across them (an earlier comment claimed one; it was never implemented).
// Each step records which weakness made it exploitable and the node carrying it
// (Step.WeaknessOn), so "break the path" credits the fix to the right resource. Break/reduce
// claims are verified by re-evaluating the path on a graph with the fix applied (see fix.go).

type JewelRule struct {
	Pattern     string `yaml:"pattern" json:"pattern"` // glob on node name, id or type
	Criticality int    `yaml:"criticality" json:"criticality"`
}

type TraversalOptions struct {
	MaxHops      int
	MaxPaths     int // overall cap, highest-scoring kept
	MinScore     float64
	CrownJewels  []JewelRule
	HopDecay     float64
	MaxBranching int
	// MinLikelihood is the reporting floor on path likelihood: a path that needs an unknown
	// code-execution step (credential hop 0.1) stays below it.
	MinLikelihood float64
	// TrustedCIDRs (config trusted_cidrs): internet exposure whose every source lies inside
	// them is "trusted" and is never an entry edge; it is listed in Analysis.Suppressed.
	TrustedCIDRs []string
	// Intel is the KEV / EPSS data of the CVE gate (cvegate.go); nil = the embedded snapshot.
	Intel CVEIntel
	// NodeCVEs maps a node id to the CVE ids of its findings (CVEIndex); the graph keeps only a
	// count. Without it the gate reads node attributes (cve / cves / kev) and treats a bare count
	// as "exploitability unknown" (0.3, confidence hint).
	NodeCVEs map[string][]string
	// PathRules overrides the path-rule library whose verified matches become rule-match path
	// Issues (nil: the embedded library); NoPathRules turns the wiring off.
	PathRules   []PathRule
	NoPathRules bool
}

// pathRules is the path-rule library traversal evaluates (rulematch.go): PathRules when set,
// none with NoPathRules, else the embedded library.
func (o *TraversalOptions) pathRules() []PathRule {
	if o.NoPathRules {
		return nil
	}
	if o.PathRules != nil {
		return o.PathRules
	}
	return productRules()
}

func (o *TraversalOptions) trusted() []string {
	if o == nil {
		return nil
	}
	return o.TrustedCIDRs
}

func DefaultTraversalOptions() TraversalOptions {
	return TraversalOptions{MaxHops: 6, MaxPaths: 500, MinScore: 0.5, MinLikelihood: 0.1, HopDecay: 0.95, MaxBranching: 25}
}

type ChokePoint struct {
	NodeID     string   `json:"node_id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Paths      int      `json:"paths"`
	ScoreSum   float64  `json:"score_sum"`
	Weaknesses []string `json:"weaknesses"`
	PathIDs    []string `json:"path_ids"` // complete paths through this node (drill-in)
	ClosesN    int      `json:"closes_n"` // complete paths gone when the node is removed and traversal re-run
}

// DeadEnds summarises finding-bearing nodes that sit on no complete path to a crown jewel.
type DeadEnds struct {
	Count int      `json:"count"`
	IDs   []string `json:"ids"`
}

// Fix is one remediation action and the paths it affects. A fix removes Weakness from
// NodeID (and the edges that weakness creates, see fixEffects) and/or deletes Edge.
type Fix struct {
	NodeID       string   `json:"node_id"`
	Name         string   `json:"name"`
	Weakness     string   `json:"weakness"`
	Edge         *EdgeRef `json:"edge,omitempty"`
	FindingIDs   []string `json:"finding_ids"`
	Breaks       []string `json:"breaks"`            // path IDs removed entirely (verified by re-evaluation)
	Reduces      []string `json:"reduces"`           // path IDs the node is on that survive the fix
	Enables      []string `json:"enables,omitempty"` // path IDs where this weakness enables a hop
	ScoreRemoved float64  `json:"score_removed"`
	Command      string   `json:"command"`
}

// EdgeRef names one edge for an edge-removal fix.
type EdgeRef struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type Analysis struct {
	Paths []model.AttackPath `json:"paths"` // complete entry → crown-jewel paths only
	// Incomplete holds paths that end at a crown jewel but are a strict prefix of a longer
	// path from the same entry. They are never counted in totals, choke points or fixes.
	Incomplete     []model.AttackPath `json:"incomplete,omitempty"`
	EntryPoints    []string           `json:"entry_points"`
	Targets        []string           `json:"targets"`
	ChokePoints    []ChokePoint       `json:"choke_points"`
	BreakFixes     []Fix              `json:"break_fixes"`      // "Recommendations": break ≥1 path
	ReduceFixes    []Fix              `json:"reduce_fixes"`     // "Additional": lower risk only
	MinFixSet      []Fix              `json:"min_fix_set"`      // smallest set of fixes cutting every cuttable path
	MinFixExact    bool               `json:"min_fix_exact"`    // true: provably minimal; false: greedy fallback
	MinFixVerified bool               `json:"min_fix_verified"` // re-traversal with MinFixSet applied removed every path it claims
	MinFixCoverage float64            `json:"min_fix_coverage"` // share of total score removed by MinFixSet (measured by re-traversal)
	TotalScore     float64            `json:"total_score"`
	// ReachesCrownJewel classifies every finding-bearing node: true when it lies on a
	// complete path to a crown jewel. DeadEnds lists the false ones.
	ReachesCrownJewel map[string]bool `json:"reaches_crown_jewel"`
	DeadEnds          DeadEnds        `json:"dead_ends"`
	// Suppressed lists internet exposure that is not an entry: every source is inside
	// trusted_cidrs (or private). The node keeps its findings; no path starts there.
	Suppressed []Suppressed `json:"suppressed"`
	// Exposures lists internet-reachable resources that are not an impact target (planning
	// decision 1): a public website bucket, a host open on 443, an EKS endpoint restricted to a
	// CIDR. They are exposures, never paths: not in Paths, totals, choke points, fixes or Issues.
	Exposures []Exposure `json:"exposures"`
	// RuleMatches lists every verified path-rule match (rulematch.go); PathID names the
	// rule-match path Issue it became (one is in Paths), empty when no entry reaches it.
	RuleMatches []PathRuleMatch `json:"rule_matches,omitempty"`

	opts     TraversalOptions
	allPaths []model.AttackPath // complete paths before the MaxPaths cap
}

// Criticality returns 0 (not an impact target) .. 4 (tier-0 crown jewel) for a node.
//
// Planning decision (P1-ENGINE noise round): an attack path must reach an impact target, and
// priority comes only from typed facts, never from names:
//
//	configured crown jewel   TraversalOptions.CrownJewels (config crown_jewels), its tier
//	sensitive data store     4 in production, else 3 (sensitiveData: explicit classification
//	                         tags win over the graph's name heuristics)
//	crown data store         3: the registry's jewel default (graph.TypeSpec.Crown: managed
//	                         databases, secrets, keys), unless explicitly classified public
//	admin-level identity     4 (adminLevel, toxic.go: OVERPRIVILEGED_IDENTITY, CLUSTER_ADMIN,
//	                         admin policies / role assignments, the cluster-admin ClusterRole)
//
// Everything else is 0, including clusters, accounts, workloads and plain buckets: reaching
// them is an exposure (Analysis.Exposures), not a path. The former built-in name catalog
// (*customer*, *prod*, *admin*, …) made an ECS service named customer-portal, every resource in
// a project called halyard-prod and an orphaned user called svc-prod-admin-legacy top-priority
// targets on the independent noise estate; it is gone.
func Criticality(n *graph.Node, rules []JewelRule) int {
	if best := configuredJewel(n, rules); best > 0 {
		return best
	}
	switch n.Class {
	case graph.ClassDataStore:
		switch c := dataClassification(n); {
		case nonSensitiveClass[c]:
			return 0
		case sensitiveData(n) && n.Criticality == "production":
			return 4
		case sensitiveData(n):
			return 3
		}
		if spec, ok := graph.Lookup(n.Type); ok && spec.Crown {
			return 3
		}
	case graph.ClassIdentity:
		if adminLevel(n) != "" {
			return 4
		}
	}
	return 0
}

// Classification values (lower case) that settle sensitivity either way.
var (
	nonSensitiveClass = map[string]bool{"public": true, "none": true, "synthetic": true, "non-sensitive": true, "nonsensitive": true,
		"non_sensitive": true, "test": true, "dummy": true, "open": true}
	sensitiveClassValues = map[string]bool{"pii": true, "phi": true, "pci": true, "confidential": true, "restricted": true, "secret": true,
		"sensitive": true, "high": true}
)

// dataClassification is the node's explicit data classification ("" when none): attributes
// data_classification / classification / sensitivity, or a tag / label whose key contains
// "classification" or "sensitivity".
func dataClassification(n *graph.Node) string {
	if n == nil || n.Attributes == nil {
		return ""
	}
	for _, k := range []string{"data_classification", "DataClassification", "classification", "sensitivity"} {
		if v, ok := n.Attributes[k].(string); ok && v != "" {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	for _, tk := range []string{"tags", "labels"} {
		m, _ := n.Attributes[tk].(map[string]any)
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "classification") || strings.Contains(lk, "sensitivity") {
				return strings.ToLower(strings.TrimSpace(fmt.Sprint(m[k])))
			}
		}
	}
	return ""
}

// sensitiveData reports a data store holding sensitive data. An explicit classification wins
// over the graph's name heuristics (a bucket named public-pii-redacted-reports classified
// public, or halyard-sandbox-public-fixtures classified none, is not sensitive); then the
// attribute contains_sensitive_data; then the graph's Sensitive flag.
func sensitiveData(n *graph.Node) bool {
	if n == nil {
		return false
	}
	c := dataClassification(n)
	switch {
	case nonSensitiveClass[c]:
		return false
	case sensitiveClassValues[c]:
		return true
	}
	if v, ok := n.Attributes["contains_sensitive_data"].(bool); ok {
		return v
	}
	return n.Sensitive
}

var priorityOf = map[int]float64{4: 10, 3: 5, 2: 2, 1: 1}

// step is an exploitability evaluation of entering `to` via edge `kind` from `from`.
type stepEval struct {
	exploitability float64
	weakness       string // weakness that made it possible ("" when structural, e.g. explicit grant)
	label          string
	weakOn         string   // ID of the node carrying weakness
	weaknesses     []string // entry steps: every credential weakness combined (noisy-OR)
	noDecay        bool     // plumbing hop (exposed network control): no hop decay
	chip           string   // compensating control on this hop, shown in because (decision 3)
	hint           bool     // the hop rests on a scanner label no attribute confirms (confidence: hint)
	reachUnknown   bool     // REACH could not decide internet reachability (confidence: inferred)
	inferredEntry  bool     // an entry whose restriction could not be judged (own organisation unknown): confidence inferred
}

func on(ev stepEval, n *graph.Node) stepEval {
	if ev.weakness != "" && n != nil {
		ev.weakOn = n.ID
	}
	return ev
}

// evaluate returns 0 when the edge is not an attack step. The weakness is credited to the
// node that carries it: the source for IMDSv1 / container escape / token theft / wildcard
// grants / a cluster-admin binding, the target for exposure and admin policies.
func evaluate(g *graph.Graph, o *TraversalOptions, from, to *graph.Node, e *graph.Edge) stepEval {
	trusted := o.trusted()
	has := to.HasWeakness
	switch e.Kind {
	case graph.EdgeExposes:
		width, _, _ := exposureAt(g, e, trusted)
		if suppressedWidth(width) {
			return stepEval{} // trusted / private / REACH-blocked, or authentication required: not an internet entry
		}
		ev := exposesEval(to, has, gateCVE(to, o))
		ev.reachUnknown = reachUnknown(e, to)
		ev.exploitability *= widthFactor(width)
		if width == "narrow" {
			ev.label += " (narrow: specific public sources only)"
		}
		if v, _ := anonymousReach(to.Type, to.Attributes); v == "" && authCheckable(to.Type) {
			ev.hint = true
			ev.label += " (confidence hint: no auth / policy attribute confirms anonymous access)"
		}
		return ev
	case graph.EdgeAllowsTrafficTo:
		exposed := from.Class == graph.ClassInternet || nodeExposure(g, from, trusted) != ""
		if from.Class == graph.ClassInternet {
			if w, _, _ := exposureAt(g, e, trusted); suppressedWidth(w) {
				exposed = false
			}
		}
		if exposed && reachBlockedEdge(e, to) != "" {
			return stepEval{} // REACH: the workload behind the open control is not internet-reachable
		}
		if exposed && from.Class == graph.ClassNetwork {
			// An exposed security group / NSG / firewall in front of the workload: the internet
			// hop already priced the exposure, so this is plumbing (1.0, no hop decay). An
			// authenticating load balancer / API gateway is a compensating control (decision 3).
			ev := stepEval{exploitability: 1.0, weakness: "PUBLIC_NETWORK_EXPOSURE", label: "exposed network control forwards internet traffic", noDecay: true,
				reachUnknown: reachUnknown(e, to)}
			if why := authFront(from); why != "" {
				ev.exploitability = AuthLBFactor
				ev.chip = fmt.Sprintf("auth-lb ×%.1f (%s)", AuthLBFactor, why)
				ev.label += "; " + ev.chip
			}
			return on(ev, from)
		}
		if exposed {
			ev := stepEval{exploitability: 0.55, weakness: "PUBLIC_NETWORK_EXPOSURE", label: "network path allows inbound traffic"}
			carrier := from
			if from.Class == graph.ClassInternet {
				carrier = to
				if !to.HasWeakness("PUBLIC_NETWORK_EXPOSURE") {
					ev.weakness = ""
				}
			}
			ev.reachUnknown = reachUnknown(e, to)
			// CVE gate (cvegate.go): vulnerable software raises the hop only as far as KEV / EPSS
			// say it is exploited; the network path itself is 0.55.
			if cg := gateCVE(to, o); cg.applies && cg.p > ev.exploitability {
				ev.exploitability, ev.label, ev.hint = cg.p, "network path to exploitable software: "+cg.label, cg.hint
				if has("UNPATCHED") {
					ev.weakness, carrier = "UNPATCHED", to
				}
			} else if has("WEAK_AUTH") {
				ev.exploitability, ev.weakness, carrier = 0.8, "WEAK_AUTH", to
			} else if cg.applies {
				ev.label += " (" + cg.label + ")"
			}
			return on(ev, carrier)
		}
		return stepEval{exploitability: 0.5, label: "lateral network movement"}
	case graph.EdgeRunsAs, graph.EdgeAttachedTo:
		if to.Class != graph.ClassIdentity {
			return stepEval{}
		}
		if agentType(from) {
			return agentHop(g, o, from)
		}
		if from.Class == graph.ClassCompute {
			return credentialHop(g, o, from)
		}
		if h, _ := e.Attr["hint"].(bool); h {
			return stepEval{exploitability: 0.5, label: "identity linked by a scanner hint (attachment not verified)"}
		}
		return stepEval{exploitability: 0.5, label: "identity usable from " + from.Name}
	case graph.EdgeHasPolicy:
		if has("OVERPRIVILEGED_IDENTITY") {
			return on(stepEval{exploitability: 1.0, weakness: "OVERPRIVILEGED_IDENTITY", label: "wildcard administrative policy"}, to)
		}
		return stepEval{exploitability: 0.9, weakness: "", label: "attached policy"}
	case graph.EdgeGrantsAccessTo, graph.EdgeStoresDataIn:
		if from.HasWeakness("OVERPRIVILEGED_IDENTITY") {
			return on(stepEval{exploitability: 1.0, weakness: "OVERPRIVILEGED_IDENTITY", label: "admin privileges reach the data"}, from)
		}
		return stepEval{exploitability: 0.85, weakness: "", label: "policy grants data access"}
	case graph.EdgeCanAssume:
		if from.Class == graph.ClassSaaS {
			// Federated (OIDC) trust from a repository / CI identity: any workflow run that
			// satisfies the trust's subject gets the role, deterministically.
			ev := stepEval{exploitability: 1.0, label: "pipeline assumes the role through its federated (OIDC) trust"}
			if has("OVERPRIVILEGED_IDENTITY") {
				ev.weakness, ev.label = "OVERPRIVILEGED_IDENTITY", ev.label+" (role is admin)"
				return on(ev, to)
			}
			return ev
		}
		if tech, _ := e.Attr[graph.AttrTechnique].(string); tech != "" {
			// Privilege-escalation edge from the IAM evaluator (graph/permissions.go): the
			// principal can obtain the role's credentials by a known technique.
			ev := stepEval{exploitability: EscalationLikelihood, label: "privilege escalation (" + tech + ")"}
			if has("OVERPRIVILEGED_IDENTITY") {
				ev.weakness, ev.label = "OVERPRIVILEGED_IDENTITY", ev.label+" into an admin role"
				return on(ev, to)
			}
			return ev
		}
		if has("CROSS_ACCOUNT_TRUST") {
			return on(stepEval{exploitability: 0.9, weakness: "CROSS_ACCOUNT_TRUST", label: "role assumable by external principals"}, to)
		}
		if from.HasWeakness("CROSS_ACCOUNT_TRUST") {
			return on(stepEval{exploitability: 0.9, weakness: "CROSS_ACCOUNT_TRUST", label: "role assumable by external principals"}, from)
		}
		if has("OVERPRIVILEGED_IDENTITY") {
			return on(stepEval{exploitability: 0.8, weakness: "OVERPRIVILEGED_IDENTITY", label: "assume into an admin role"}, to)
		}
		return stepEval{exploitability: 0.6, weakness: "", label: "sts:AssumeRole permitted"}
	case graph.EdgeBoundTo:
		if has("CLUSTER_ADMIN") {
			return on(stepEval{exploitability: 1.0, weakness: "CLUSTER_ADMIN", label: "bound to cluster-admin"}, to)
		}
		if has("OVERPRIVILEGED_IDENTITY") {
			return on(stepEval{exploitability: 1.0, weakness: "OVERPRIVILEGED_IDENTITY", label: "bound to cluster-admin"}, to)
		}
		if b := bindingCarrying(g, from, to, e, "CLUSTER_ADMIN"); b != nil {
			return on(stepEval{exploitability: 1.0, weakness: "CLUSTER_ADMIN", label: "bound to cluster-admin"}, b)
		}
		return stepEval{exploitability: 0.6, weakness: "", label: "RBAC binding"}
	case graph.EdgeMemberOf:
		if to.Class == graph.ClassIdentity {
			return stepEval{exploitability: 0.8, weakness: "", label: "group membership"}
		}
		return stepEval{}
	case graph.EdgeTrusts:
		return stepEval{}
	}
	return stepEval{}
}

// exposesEval is the internet → node step before exposure width is applied. Vulnerable software
// raises it above plain reachability (0.8) only when a CVE is in KEV (CVE gate, cvegate.go).
func exposesEval(to *graph.Node, has func(string) bool, cg cveGate) stepEval {
	switch {
	case has("PUBLIC_DATA_STORE"):
		return on(stepEval{exploitability: 1.0, weakness: "PUBLIC_DATA_STORE", label: "readable by anyone on the internet"}, to)
	case has("PUBLIC_NETWORK_EXPOSURE") && cg.applies && cg.p > exposedReachOnly:
		w := "PUBLIC_NETWORK_EXPOSURE"
		if has("UNPATCHED") {
			w = "UNPATCHED"
		}
		return on(stepEval{exploitability: cg.p, weakness: w, label: "reachable from the internet and runs known-exploited software: " + cg.label}, to)
	case has("PUBLIC_NETWORK_EXPOSURE") && has("WEAK_AUTH"):
		return on(stepEval{exploitability: 0.8, weakness: "WEAK_AUTH", label: "reachable from the internet with weak authentication"}, to)
	case has("PUBLIC_NETWORK_EXPOSURE") && cg.applies:
		return on(stepEval{exploitability: exposedReachOnly, weakness: "PUBLIC_NETWORK_EXPOSURE", label: "reachable from the internet (" + cg.label + ")"}, to)
	case has("PUBLIC_NETWORK_EXPOSURE"):
		return on(stepEval{exploitability: exposedReachOnly, weakness: "PUBLIC_NETWORK_EXPOSURE", label: "reachable from the internet"}, to)
	}
	return stepEval{exploitability: 0.4, weakness: "", label: "exposed to the internet"}
}

// bindingCarrying returns the RBAC binding behind a bound_to edge when that binding carries
// weakness w: the source itself (binding → role), or the binding named in the edge's
// "binding" attribute (subject → role edges the K8s collector adds per binding).
func bindingCarrying(g *graph.Graph, from, to *graph.Node, e *graph.Edge, w string) *graph.Node {
	if from.HasWeakness(w) {
		return from
	}
	name, _ := e.Attr["binding"].(string)
	if name == "" || g == nil {
		return nil
	}
	for _, in := range g.In(to.ID) {
		if in.Kind != graph.EdgeBoundTo || in.From == from.ID {
			continue
		}
		if b, ok := g.Node(in.From); ok && b.HasWeakness(w) && (b.Name == name || strings.HasSuffix(b.ID, "/"+name)) {
			return b
		}
	}
	return nil
}

// entryEval scores footholds that need no network path: phished or leaked credentials, an
// unprotected repository, and roles that principals outside the account may assume. Several
// independent credential weaknesses on one node combine as a noisy-OR
// (1 − Π(1 − p_i)): a user with no MFA (0.5) and a 400-day access key (0.4) is compromised
// with likelihood 0.7. The strongest weakness is the step's weakness; all are evidence.
func entryEval(g *graph.Graph, n *graph.Node) stepEval {
	type cand struct {
		w     string
		p     float64
		label string
	}
	var cs []cand
	ident := n.Class == graph.ClassIdentity
	// Decision 4: a user's credential weaknesses are an entry only when the user has a usable
	// credential. No console access and no active keys: no path. Unknown: confidence hint ×0.5.
	cred := credentialState(n)
	credOK := ident && cred != credNone
	if credOK && n.HasWeakness("NO_MFA") {
		l := "credential phishing succeeds without MFA"
		if why := idpUsable(n); why != "" {
			l += " (federated IdP user, credential usable: " + why + ")"
		}
		cs = append(cs, cand{"NO_MFA", 0.5, l})
	}
	if credOK && n.HasWeakness("STALE_CREDENTIALS") {
		cs = append(cs, cand{"STALE_CREDENTIALS", 0.4, "long-lived access key leaked or reused"})
	}
	if credOK && n.HasWeakness("WEAK_AUTH") {
		cs = append(cs, cand{"WEAK_AUTH", 0.45, "legacy or weak authentication"})
	}
	credOnly := len(cs) > 0
	inferredEntry := false
	if ident && n.HasWeakness("CROSS_ACCOUNT_TRUST") {
		if p, label, inf := crossAccountEntryEval(g, n); p > 0 {
			cs = append(cs, cand{"CROSS_ACCOUNT_TRUST", p, label})
			inferredEntry = inf
		}
	}
	if n.Class == graph.ClassSaaS && n.HasWeakness("BRANCH_UNPROTECTED") {
		cs = append(cs, cand{"BRANCH_UNPROTECTED", 0.4, "unreviewed code lands in the pipeline"})
	}
	if n.HasWeakness("SECRET_EXPOSURE") {
		cs = append(cs, cand{"SECRET_EXPOSURE", 0.6, "hard-coded secret reused"})
	}
	if len(cs) == 0 {
		return stepEval{}
	}
	for _, c := range cs {
		credOnly = credOnly && (c.w == "NO_MFA" || c.w == "STALE_CREDENTIALS" || c.w == "WEAK_AUTH")
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].p > cs[j].p })
	miss := 1.0
	var labels, ws []string
	for _, c := range cs {
		miss *= 1 - c.p
		labels = append(labels, c.w+": "+c.label)
		ws = append(ws, c.w)
	}
	ev := on(stepEval{exploitability: 1 - miss, weakness: cs[0].w, label: strings.Join(labels, "; ")}, n)
	ev.inferredEntry = inferredEntry && cs[0].w == "CROSS_ACCOUNT_TRUST"
	if len(ws) > 1 {
		ev.label += fmt.Sprintf(" (independent routes combined: 1 − Π(1 − p) = %.2f)", ev.exploitability)
	}
	ev.weaknesses = ws
	if credOnly && cred == credUnknown {
		ev.exploitability *= IdentityHintFactor
		ev.hint = true
		ev.label += fmt.Sprintf(" (confidence hint: no attribute shows a usable credential; ×%.1f)", IdentityHintFactor)
	}
	return ev
}

// IdentityHintFactor scales a user entry whose credential usability is unknown (decision 4).
const IdentityHintFactor = 0.5

const (
	credNotUser = iota // not a user account: the rule does not apply
	credUsable
	credNone
	credUnknown
)

// credentialState says whether user n can authenticate at all: console access or an active
// access key is usable; console_access=false with no active key is none (an orphaned user,
// whatever its MFA state); otherwise a STALE_CREDENTIALS finding or a key age proves a key
// exists; with none of those attributes the state is unknown.
func credentialState(n *graph.Node) int {
	if n == nil || !strings.Contains(strings.ToLower(n.Type), "user") {
		return credNotUser
	}
	if idpUser(n) {
		// Engine round 2 (#12): an IdP (Okta / Entra) user signs in with its IdP credential; its
		// lifecycle status says whether that credential works.
		switch idpStatus(n) {
		case credUsable:
			return credUsable
		case credNone:
			return credNone
		}
	}
	a := n.Attributes
	b := func(k string) (bool, bool) { v, ok := a[k].(bool); return v, ok }
	if v, ok := b("console_access"); ok && v {
		return credUsable
	}
	if v, ok := b("password_enabled"); ok && v {
		return credUsable
	}
	keysKnown, keysActive := false, false
	switch v := a["active_keys"].(type) {
	case int:
		keysKnown, keysActive = true, v > 0
	case float64:
		keysKnown, keysActive = true, v > 0
	}
	for _, k := range []string{"access_key_1_active", "access_key_2_active"} {
		if v, ok := b(k); ok {
			keysKnown = true
			keysActive = keysActive || v
		}
	}
	if keysActive {
		return credUsable
	}
	if console, ok := b("console_access"); ok && !console && keysKnown {
		return credNone
	}
	if n.HasWeakness("STALE_CREDENTIALS") {
		return credUsable
	}
	for _, k := range []string{"access_key_1_age_days", "access_key_2_age_days", "access_key_age_days"} {
		if _, ok := a[k]; ok {
			return credUsable
		}
	}
	return credUnknown
}

// crossAccountEntry rates a role that principals outside its account may assume: a wildcard
// principal is anyone (1.0); a foreign account's root (arn:aws:iam::<acct>:root or a bare
// account id: every principal that account's admins allow) without an ExternalId condition 0.8
// (ExternalRootEntry, engine round 2 #12b); another foreign principal without an ExternalId is
// open to the confused-deputy problem and to whoever controls it (0.7); with an ExternalId 0.4.
func crossAccountEntry(g *graph.Graph, n *graph.Node) (float64, string) {
	p, why, _ := crossAccountEntryEval(g, n)
	return p, why
}

// UnknownOrgTrustEntry is the entry likelihood of a cross-account trust limited by
// aws:PrincipalOrgID / PrincipalOrgPaths while the role's own organisation is unknown
// (organizations:DescribeOrganization not collected or denied): the condition may name the
// role's own organisation (no external entry) or a foreign one (an external entry), so the entry
// is kept, labelled inferred, at the protected-trust likelihood and never floored (W7-ENGINE r5
// #15, verification 6 C1: an unknown own organisation used to delete the path).
const UnknownOrgTrustEntry = ProtectedTrustEntry

// crossAccountEntryEval is crossAccountEntry plus whether the entry is inferred (the trust's
// organisation restriction could not be judged against an unknown own organisation).
func crossAccountEntryEval(g *graph.Graph, n *graph.Node) (float64, string, bool) {
	var principals []string
	if v, ok := n.Attributes["trust_principals"]; ok {
		principals = append(principals, toStrings(v)...)
	}
	if g != nil {
		for _, e := range g.In(n.ID) {
			if e.Kind == graph.EdgeCanAssume && e.From != n.ID {
				principals = append(principals, e.From)
			}
		}
		for _, e := range g.Out(n.ID) {
			if e.Kind == graph.EdgeTrusts {
				principals = append(principals, e.To)
			}
		}
	}
	principals = uniq(principals)
	who := "principals in another account"
	if len(principals) > 0 {
		who = strings.Join(principals, ", ")
	}
	// Trust conditions (defect 10a/b, verify-4 D1/D2): an organisation-limited trust is not an
	// external entry; an ExternalId / SourceIdentity condition is ProtectedTrustEntry.
	tc := trustConditionsOf(g, n)
	if tc.orgUnknown != "" {
		return UnknownOrgTrustEntry, "assumable by " + who + " only from organisation " + tc.orgUnknown +
			" (aws:PrincipalOrgID in the trust policy); the role's own organisation is unknown (organizations:DescribeOrganization not collected), so whether that is a foreign organisation is not decided (confidence inferred)", true
	}
	if tc.org != "" {
		if tc.ownOrg != "" && (tc.org == "aws:principalorgid" || tc.org == "aws:principalorgpaths") {
			return 0, "trust limited to callers in the role's own organisation " + tc.ownOrg + " (" + tc.org + ", same organisation): not an external entry", false
		}
		return 0, "trust limited to the caller's organisation (" + tc.org + "): not an external entry", false
	}
	if tc.bound != "" {
		return ProtectedTrustEntry, "assumable by " + who + " (" + tc.bound + " required)", false
	}
	foreign := ""
	if tc.ownOrg != "" && tc.foreignOrg != "" {
		foreign = " (trust names organisation " + tc.foreignOrg + ", not the role's own " + tc.ownOrg + ")"
	}
	for _, p := range principals {
		if p == "*" || p == graph.InternetNodeID || strings.HasSuffix(p, ":*") {
			return 1.0, "trust policy allows any principal (" + who + ")" + foreign, false
		}
	}
	for _, p := range principals {
		if acct := rootAccount(p); acct != "" && acct != accountOfNode(n) {
			return ExternalRootEntry, "assumable by every principal of external account " + acct + " (account root trust " + p + ") without an ExternalId condition" + foreign, false
		}
	}
	return 0.7, "assumable by " + who + " without an ExternalId condition (confused deputy)" + foreign, false
}

// ExternalRootEntry is the entry likelihood of a role trusting a foreign account's root.
const ExternalRootEntry = 0.8

// ProtectedTrustEntry is the entry likelihood of a cross-account trust that requires
// sts:ExternalId or binds sts:SourceIdentity: the external party must also hold the shared
// secret / a named identity (was 0.4 for ExternalId before verify-4 D2).
const ProtectedTrustEntry = 0.3

// trustConds is what a role's trust policy conditions say about who may assume it: org names
// the condition key that limits the role to the caller's organisation / own account; bound is
// "ExternalId" / "SourceIdentity" when the external party must also present a secret value.
//
// Verify-5 C1: conditions are judged by operator and value through internal/iam's condition
// evaluator, not by key. The trust policy is evaluated for an external attacker (a principal of
// each trusted foreign account, holding full permissions in its own account) under every request
// context the attacker controls: no organisation, a probe organisation, a foreign organisation
// named in the policy (when the role's own organisation is known), sts:ExternalId and
// sts:SourceIdentity absent or set to a guess. Only the organisation / account / ARN /
// ExternalId / SourceIdentity keys are evaluated; any other condition (MFA, source IP, …) is
// assumed satisfiable by the attacker (dropped from Allow statements; a Deny relying on one is
// assumed avoidable). If some context gets in, the conditions do not restrict. If none does but
// supplying the policy's own ExternalId / SourceIdentity value does, the trust is bound; else it
// is limited to the organisation / own account. Conditions that are not the reason the attacker
// is refused (the unconditioned policy refuses it too) say nothing.
type trustConds struct {
	org, bound string
	// ownOrg is the role's own organisation when known; foreignOrg a concrete organisation the
	// policy names that is not it; orgUnknown the organisation(s) an org-only restriction names
	// while ownOrg is unknown (W7-ENGINE r5 #15: inferred entry, path kept).
	ownOrg, foreignOrg, orgUnknown string
}

var trustOrgKeys = map[string]bool{"aws:principalorgid": true, "aws:principalorgpaths": true, "aws:principalaccount": true}

// trustCondKeys are the condition keys whose values an external attacker cannot choose freely
// (or whose secret it must know); every other key is assumed attacker-satisfiable.
var trustCondKeys = map[string]bool{"aws:principalorgid": true, "aws:principalorgpaths": true, "aws:principalaccount": true,
	"aws:principalarn": true, "sts:externalid": true, "sts:sourceidentity": true, "aws:sourceidentity": true}

var trustSecretKeys = map[string]string{"sts:externalid": "ExternalId", "sts:sourceidentity": "SourceIdentity", "aws:sourceidentity": "SourceIdentity"}

const (
	trustProbeAccount = "000000000001"   // the account of a "*" principal's attacker
	trustProbeOrg     = "o-nimbusprobe0" // an organisation that is not the role's
	trustProbeGuess   = "nimbus-probe-guess"
)

var trustAttackerIdentity = iam.Policy{ID: "attacker-identity", Version: "2012-10-17",
	Statement: []iam.Statement{{Effect: "Allow", Action: []string{"*"}, Resource: []string{"*"}}}}

func trustConditionsOf(g *graph.Graph, n *graph.Node) trustConds {
	var tc trustConds
	if n == nil || n.Attributes == nil {
		return tc
	}
	a := n.Attributes
	if req, ok := a["external_id_required"].(bool); ok && req {
		tc.bound = "ExternalId"
	}
	pol, ok := trustPolicyOf(n)
	if !ok {
		return tc
	}
	own := ownOrgOf(g, n)
	tc.ownOrg = own
	org, bound := evalTrustConditions(pol, n, own)
	named := trustNamedOrgs(pol)
	if own != "" {
		for _, o := range named {
			if !strings.EqualFold(o, own) {
				tc.foreignOrg = o
				break
			}
		}
	}
	if org != "" {
		if own == "" && (org == "aws:principalorgid" || org == "aws:principalorgpaths") {
			tc.orgUnknown = strings.Join(named, ", ")
			if tc.orgUnknown == "" {
				tc.orgUnknown = "(named by pattern)"
			}
			return tc
		}
		tc.org = org
		return tc
	}
	if bound != "" {
		tc.bound = bound
	}
	return tc
}

// trustPolicyOf is the role's trust policy document, else one synthesised from trust_principals
// and the flattened trust_conditions attribute.
func trustPolicyOf(n *graph.Node) (iam.Policy, bool) {
	a := n.Attributes
	for _, k := range []string{"trust_policy", "assume_role_policy", "assume_role_policy_document"} {
		if a[k] == nil {
			continue
		}
		if p, err := iam.ParseAny(a[k]); err == nil && len(p.Statement) > 0 {
			return p, true
		}
	}
	c, ok := a["trust_conditions"]
	if !ok {
		return iam.Policy{}, false
	}
	principals := toStrings(a["trust_principals"])
	if len(principals) == 0 {
		principals = []string{"*"}
	}
	p, err := iam.ParseAny(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
		"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]any{"AWS": principals}, "Condition": c}}})
	return p, err == nil && len(p.Statement) > 0
}

// trustNamedOrgs are the concrete organisation ids a trust policy's aws:PrincipalOrgID /
// PrincipalOrgPaths conditions name (patterns excluded).
func trustNamedOrgs(pol iam.Policy) []string {
	var out []string
	for _, v := range trustCondValues(trustRelevantPolicy(pol, true), func(k string) bool { return k == "aws:principalorgid" || k == "aws:principalorgpaths" }) {
		if o := strings.SplitN(v, "/", 2)[0]; o != "" && !strings.ContainsAny(o, "*?$") {
			out = append(out, o)
		}
	}
	out = uniq(out)
	sort.Strings(out)
	return out
}

// ownOrgOf is the role's own organisation id when the inventory records it ("" when unknown):
// the role's own attribute, else its account node's (the AWS collector writes organization_id
// from organizations:DescribeOrganization, falling back to the organisation in the SCP chain's
// policy ARNs; a denied read leaves organization_id_status "denied" and no id). Both the
// collector / ingest account node id (aws:account:<id>) and a bare account id are looked up.
func ownOrgOf(g *graph.Graph, n *graph.Node) string {
	keys := []string{"organization_id", "org_id", "aws_organization_id", "organisation_id"}
	for _, k := range keys {
		if s, _ := n.Attributes[k].(string); s != "" {
			return s
		}
	}
	if g == nil {
		return ""
	}
	acct := accountOfNode(n)
	if acct == "" {
		return ""
	}
	for _, id := range []string{core.AccountNodeID(model.ProviderAWS, acct), acct} {
		if an, ok := g.Node(id); ok && an.Attributes != nil {
			for _, k := range keys {
				if s, _ := an.Attributes[k].(string); s != "" {
					return s
				}
			}
			if st, _ := an.Attributes["organization_id_status"].(string); st == "not_in_org" {
				return noOrganization // every organisation a trust names is foreign
			}
		}
	}
	return ""
}

// noOrganization is the own "organisation" of an account in none: it equals no real id.
const noOrganization = "(no organization)"

// trustAttackers are the external callers of a trust policy: a role in every foreign account
// (or foreign principal) its Allow statements name; "*" is a role in a probe account.
func trustAttackers(pol iam.Policy, own string) []string {
	var out []string
	for _, st := range pol.Statement {
		if st.Effect != "Allow" || st.Principal == nil {
			continue
		}
		var vals []string
		if st.Principal.Any {
			vals = append(vals, "*")
		}
		for typ, vs := range st.Principal.Values {
			if strings.EqualFold(typ, "AWS") {
				vals = append(vals, vs...)
			}
		}
		for _, v := range vals {
			switch {
			case v == "*":
				out = append(out, "arn:aws:iam::"+trustProbeAccount+":role/nimbus-trust-probe")
			case rootAccount(v) != "":
				if acct := rootAccount(v); acct != own {
					out = append(out, "arn:aws:iam::"+acct+":role/nimbus-trust-probe")
				}
			case strings.HasPrefix(v, "arn:aws:iam::"):
				if parts := strings.SplitN(v, ":", 6); len(parts) == 6 && parts[4] != own {
					out = append(out, v)
				}
			}
		}
	}
	out = uniq(out)
	sort.Strings(out)
	return out
}

// trustRelevantPolicy normalises Effect and keeps only the conditions an attacker cannot
// satisfy at will (all conditions dropped when keepConds is false).
func trustRelevantPolicy(pol iam.Policy, keepConds bool) iam.Policy {
	out := iam.Policy{ID: pol.ID, Version: pol.Version}
	for _, st := range pol.Statement {
		switch {
		case st.Effect == "" || strings.EqualFold(st.Effect, "Allow"): // a missing Effect reads as Allow (as before)
			st.Effect = "Allow"
		case strings.EqualFold(st.Effect, "Deny"):
			st.Effect = "Deny"
		default:
			continue
		}
		cond := map[string]map[string][]string{}
		other := false
		for op, kv := range st.Condition {
			for k, v := range kv {
				if !trustCondKeys[strings.ToLower(k)] {
					other = true
					continue
				}
				if cond[op] == nil {
					cond[op] = map[string][]string{}
				}
				cond[op][k] = v
			}
		}
		if st.Effect == "Deny" && (other || !keepConds) && len(st.Condition) > 0 {
			continue // a Deny the attacker can avoid
		}
		if !keepConds {
			cond = nil
		}
		st.Condition = cond
		out.Statement = append(out.Statement, st)
	}
	return out
}

// trustCondValues lists the literal values the policy compares key against (lower-cased key).
func trustCondValues(pol iam.Policy, match func(key string) bool) []string {
	var out []string
	for _, st := range pol.Statement {
		for _, kv := range st.Condition {
			for k, vs := range kv {
				if match(strings.ToLower(k)) {
					out = append(out, vs...)
				}
			}
		}
	}
	return uniq(out)
}

func evalTrustConditions(raw iam.Policy, n *graph.Node, ownOrg string) (org, bound string) {
	own := accountOfNode(n)
	pol := trustRelevantPolicy(raw, true)
	attackers := trustAttackers(pol, own)
	if len(attackers) == 0 {
		return "", ""
	}
	roleARN := n.ID
	if !strings.HasPrefix(roleARN, "arn:") && own != "" {
		roleARN = "arn:aws:iam::" + own + ":role/" + n.Name
	}
	// The attacker's organisation: none, a probe organisation, and every concrete foreign
	// organisation the policy names (only when the role's own organisation is known: otherwise a
	// named organisation is taken to be the role's own).
	orgs := []string{trustProbeOrg}
	if ownOrg != "" {
		for _, v := range trustCondValues(pol, func(k string) bool { return k == "aws:principalorgid" || k == "aws:principalorgpaths" }) {
			if o := strings.SplitN(v, "/", 2)[0]; o != "" && !strings.ContainsAny(o, "*?$") && !strings.EqualFold(o, ownOrg) {
				orgs = append(orgs, o)
			}
		}
	}
	orgs = append([]string{""}, uniq(orgs)...) // "" = the caller is in no organisation
	extIDs := trustCondValues(pol, func(k string) bool { return k == "sts:externalid" })
	srcIDs := trustCondValues(pol, func(k string) bool { return k == "sts:sourceidentity" || k == "aws:sourceidentity" })
	admits := func(p iam.Policy, ext, src []string) bool {
		for _, who := range attackers {
			for _, o := range orgs {
				for _, x := range ext {
					for _, s := range src {
						ctx := map[string]iam.ConditionValue{}
						if o != "" {
							ctx["aws:PrincipalOrgID"] = iam.ConditionValue{o}
							ctx["aws:PrincipalOrgPaths"] = iam.ConditionValue{o + "/r-probe/ou-probe/"}
						}
						if x != "" {
							ctx["sts:ExternalId"] = iam.ConditionValue{x}
						}
						if s != "" {
							ctx["sts:SourceIdentity"] = iam.ConditionValue{s}
							ctx["aws:SourceIdentity"] = iam.ConditionValue{s}
						}
						d := iam.EvaluateSet(iam.Request{Principal: who, Action: "sts:AssumeRole", Resource: roleARN, ResourceAccount: own,
							Context: ctx, ContextComplete: true}, iam.PolicySet{Identity: []iam.Policy{trustAttackerIdentity}, Resource: &p})
						if d.Effect == iam.Allow || d.Effect == iam.Unknown {
							return true
						}
					}
				}
			}
		}
		return false
	}
	guess := []string{"", trustProbeGuess}
	if admits(pol, guess, guess) {
		return "", "" // some context the attacker controls gets in: no restriction
	}
	if !admits(trustRelevantPolicy(raw, false), []string{""}, []string{""}) {
		return "", "" // refused without any condition too: the conditions are not the reason
	}
	if len(extIDs) > 0 && admits(pol, extIDs, guess) {
		return "", "ExternalId"
	}
	if len(srcIDs) > 0 && admits(pol, guess, srcIDs) {
		return "", "SourceIdentity"
	}
	if len(extIDs) > 0 && len(srcIDs) > 0 && admits(pol, extIDs, srcIDs) {
		return "", "ExternalId"
	}
	for _, k := range []string{"aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn"} {
		if len(trustCondValues(pol, func(x string) bool { return x == k })) > 0 {
			return k, ""
		}
	}
	return "trust policy conditions", ""
}

var bareAccount = regexp.MustCompile(`^\d{12}$`)

// rootAccount returns the account id of an account-root principal ("" otherwise).
func rootAccount(p string) string {
	if bareAccount.MatchString(p) {
		return p
	}
	if strings.HasPrefix(p, "arn:aws:iam::") && strings.HasSuffix(p, ":root") {
		return strings.TrimSuffix(strings.TrimPrefix(p, "arn:aws:iam::"), ":root")
	}
	return ""
}

// accountOfNode is n.Account, else the account field of an AWS ARN id.
func accountOfNode(n *graph.Node) string {
	if n.Account != "" {
		return n.Account
	}
	if parts := strings.Split(n.ID, ":"); len(parts) > 4 && strings.HasPrefix(n.ID, "arn:") {
		return parts[4]
	}
	return ""
}

// idpUser reports a user of an external identity provider (Okta, Entra ID / Azure AD, Google
// Workspace) whose groups federate into cloud roles.
func idpUser(n *graph.Node) bool {
	t, p := strings.ToLower(n.Type), strings.ToLower(n.Provider)
	if !strings.Contains(t, "user") {
		return false
	}
	for _, x := range []string{"okta", "entra", "azuread", "azure_ad", "google_workspace", "onelogin", "jumpcloud", "ping"} {
		if strings.HasPrefix(t, x) || p == x || strings.HasPrefix(strings.ToLower(n.ID), x+":") {
			return true
		}
	}
	return false
}

// idpStatus reads an IdP user's lifecycle status: ACTIVE / PASSWORD_EXPIRED / RECOVERY (Okta) or
// account_enabled=true (Entra) is a usable credential; SUSPENDED / DEPROVISIONED / LOCKED_OUT /
// STAGED / PROVISIONED (not activated) or account_enabled=false is none; else unknown.
func idpStatus(n *graph.Node) int {
	if v, ok := n.Attributes["account_enabled"].(bool); ok {
		if v {
			return credUsable
		}
		return credNone
	}
	st, _ := n.Attributes["status"].(string)
	switch strings.ToUpper(strings.TrimSpace(st)) {
	case "ACTIVE", "PASSWORD_EXPIRED", "RECOVERY", "ENABLED":
		return credUsable
	case "SUSPENDED", "DEPROVISIONED", "LOCKED_OUT", "STAGED", "PROVISIONED", "DISABLED":
		return credNone
	}
	return credUnknown
}

// idpUsable says why an IdP user's credential is usable ("" when it is not an IdP user or unknown).
func idpUsable(n *graph.Node) string {
	if !idpUser(n) || idpStatus(n) != credUsable {
		return ""
	}
	if v, ok := n.Attributes["account_enabled"].(bool); ok && v {
		return "account_enabled"
	}
	st, _ := n.Attributes["status"].(string)
	return "status " + strings.ToUpper(strings.TrimSpace(st))
}

func toStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

type frame struct {
	node  *graph.Node
	steps []model.Step
	lik   float64
	seen  map[string]bool
	best  float64 // highest score at any crown jewel already passed on this path
	// entryWidth is the exposure width of the internet entry hop ("" for other entries);
	// it decides the toxic-combination floor (toxic.go).
	entryWidth string
	// carried is the toxic tag of the best crown jewel already passed: a path that inherits
	// that jewel's floored score keeps its explanation.
	carried, carriedWhy string
	// exposed: every step so far is the internet hop or exposed-network-control plumbing, so
	// the node is an internet exposure (recorded in Analysis.Exposures when not a target).
	exposed bool
	// compensated names a compensating control on the entry (an authenticating load balancer,
	// decision 3): the entry is no longer anonymous wide exposure, so no toxic floor.
	compensated string
}

// Traverse finds attack paths from entry points to crown jewels over the security graph,
// then computes choke points, verified break/reduce fixes, the minimal fix set and dead ends.
func Traverse(g *graph.Graph, opts TraversalOptions) *Analysis {
	an := traverse(g, opts)
	an.analyzeFixes(g)
	an.classifyDeadEnds(g)
	return an
}

// traverse is the path search only (no fix analysis), so what-if re-runs stay cheap.
func traverse(g *graph.Graph, opts TraversalOptions) *Analysis {
	if opts.MaxHops == 0 {
		opts = DefaultTraversalOptions()
	}
	an := &Analysis{opts: opts, Suppressed: suppressedExposures(g, opts.TrustedCIDRs)}
	crit := map[string]int{}
	for _, n := range g.Nodes() {
		crit[n.ID] = Criticality(n, opts.CrownJewels)
		if crit[n.ID] >= 2 && n.Class != graph.ClassAccount {
			an.Targets = append(an.Targets, n.ID)
		}
	}
	// Entry points: the internet node, plus identities/SaaS nodes with credential weaknesses.
	type entry struct {
		node *graph.Node
		eval stepEval
	}
	var entries []entry
	if inet, ok := g.Node(graph.InternetNodeID); ok {
		entries = append(entries, entry{inet, stepEval{exploitability: 1, weakness: "", label: "attacker on the internet"}})
		an.EntryPoints = append(an.EntryPoints, inet.ID)
	}
	for _, n := range g.Nodes() {
		if ev := entryEval(g, n); ev.exploitability > 0 {
			entries = append(entries, entry{n, ev})
			an.EntryPoints = append(an.EntryPoints, n.ID)
		}
	}
	var paths []model.AttackPath
	seenPath := map[string]bool{}
	exposures := map[string]*Exposure{}
	for _, en := range entries {
		start := frame{node: en.node, lik: en.eval.exploitability, seen: map[string]bool{en.node.ID: true}}
		if en.node.ID != graph.InternetNodeID {
			start.steps = []model.Step{entryStep(en.node, en.eval)}
		}
		stack := []frame{start}
		explored := 0
		for len(stack) > 0 && explored < 20000 {
			fr := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			explored++
			hops := len(fr.steps)
			if fr.exposed && hops >= 1 && crit[fr.node.ID] == 0 && fr.node.Class != graph.ClassNetwork {
				recordExposure(g, exposures, fr)
			}
			// Emit a path when we stand on a crown jewel reached through ≥1 attack step. An
			// identity entry that is itself a tier-0/1 jewel (an admin user with no MFA, an
			// admin role external accounts can assume) is a one-step path: the credential
			// compromise is the attack (item 4, P04/P05).
			if c := crit[fr.node.ID]; c >= 2 && hops >= 1 && (fr.node.ID != en.node.ID || hops > 1 || c >= 3) {
				p := buildPath(g, en.node, fr, priorityOf[c], opts.CrownJewels)
				fr.best = p.Score // children carry it: a path through this jewel never scores less
				if k := ToxicCombination(p); k != "" {
					fr.carried, fr.carriedWhy = k, p.Steps[len(p.Steps)-1].Evidence["toxic_reason"].(string)
				}
				if p.Score >= opts.MinScore && !seenPath[p.ID] {
					seenPath[p.ID] = true
					paths = append(paths, p)
				}
				if fr.node.Class == graph.ClassDataStore {
					continue // data is the end of the kill chain
				}
			}
			if hops >= opts.MaxHops {
				continue
			}
			branches := 0
			for _, e := range g.Out(fr.node.ID) {
				if fr.seen[e.To] {
					continue
				}
				to, ok := g.Node(e.To)
				if !ok {
					continue
				}
				ev := evaluate(g, &opts, fr.node, to, e)
				if ev.exploitability == 0 {
					continue
				}
				// The internet's out-edges are separate entries, not branches of one foothold:
				// capping them dropped every exposure past the 25th in store order (noise TP3).
				if fr.node.ID != graph.InternetNodeID && branches >= opts.MaxBranching {
					break
				}
				branches++
				lik := fr.lik * ev.exploitability * hopDecay(opts, fr.node, ev)
				if lik < minLik(opts) {
					continue
				}
				seen := make(map[string]bool, len(fr.seen)+1)
				for k := range fr.seen {
					seen[k] = true
				}
				seen[to.ID] = true
				steps := append(append([]model.Step{}, fr.steps...), edgeStep(g, fr.node, to, e, hops+1, ev))
				width := fr.entryWidth
				exposed := fr.exposed && ev.noDecay
				if fr.node.ID == graph.InternetNodeID {
					width = entryWidthOf(g, fr.node, e, opts.TrustedCIDRs)
					exposed = true
				}
				comp := fr.compensated
				if ev.chip != "" {
					comp = ev.chip
				}
				stack = append(stack, frame{node: to, steps: steps, lik: lik, seen: seen, best: fr.best, entryWidth: width, carried: fr.carried, carriedWhy: fr.carriedWhy,
					exposed: exposed, compensated: comp})
			}
		}
	}
	for _, x := range exposures {
		an.Exposures = append(an.Exposures, *x)
	}
	for _, x := range blockedExposures(g, opts.TrustedCIDRs) {
		if _, ok := exposures[x.NodeID]; !ok {
			an.Exposures = append(an.Exposures, x)
		}
	}
	sort.Slice(an.Exposures, func(i, j int) bool { return an.Exposures[i].NodeID < an.Exposures[j].NodeID })
	paths, rps, rms := rulePaths(g, opts.pathRules(), paths, crit, opts)
	complete, incomplete := splitPrefixes(paths)
	complete = append(complete, rps...)
	an.RuleMatches = rms
	sortPaths(complete)
	sortPaths(incomplete)
	an.allPaths = complete
	an.Paths = complete
	if opts.MaxPaths > 0 && len(complete) > opts.MaxPaths {
		an.Paths = complete[:opts.MaxPaths]
	}
	an.Incomplete = incomplete
	if opts.MaxPaths > 0 && len(incomplete) > opts.MaxPaths {
		an.Incomplete = incomplete[:opts.MaxPaths]
	}
	for _, p := range an.Paths {
		an.TotalScore += p.Score
	}
	an.TotalScore = math.Round(an.TotalScore*100) / 100
	return an
}

// hopDecay is the per-hop decay for a lateral hop. Initial access from the internet carries
// its own likelihood (exposure width) and plumbing hops through an exposed network control are
// not attacker footholds, so neither decays (item 6 calibration).
func hopDecay(opts TraversalOptions, from *graph.Node, ev stepEval) float64 {
	if from.ID == graph.InternetNodeID || ev.noDecay {
		return 1
	}
	return opts.HopDecay
}

// recordExposure keeps the internet exposure fr stands on (decision 1): the node, the widest
// entry width, the chain's because and every finding that opened it.
func recordExposure(g *graph.Graph, out map[string]*Exposure, fr frame) {
	n := fr.node
	var because []string
	var fids []string
	for _, s := range fr.steps {
		because = append(because, s.Because)
		if sn, ok := g.Node(s.Resource); ok {
			fids = append(fids, sn.FindingIDs...)
		}
		if ids, ok := s.Evidence["finding_ids"].([]string); ok {
			fids = append(fids, ids...)
		}
	}
	x := Exposure{NodeID: n.ID, Name: n.Name, Type: n.Type, Width: fr.entryWidth, Because: strings.Join(because, " → "), FindingIDs: uniq(fids)}
	if prev, ok := out[n.ID]; ok && !(prev.Width != core.ExposureWide && x.Width == core.ExposureWide) {
		return
	}
	out[n.ID] = &x
}

// minLik is the likelihood floor below which a path is neither extended nor reported.
func minLik(opts TraversalOptions) float64 {
	if opts.MinLikelihood > 0 {
		return opts.MinLikelihood
	}
	return 0.02
}

func sortPaths(paths []model.AttackPath) {
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Score != paths[j].Score {
			return paths[i].Score > paths[j].Score
		}
		return paths[i].ID < paths[j].ID
	})
}

// pathEntry is the entry node of a traversal path: the first step for identity entries,
// otherwise the internet.
func pathEntry(p model.AttackPath) string {
	if len(p.Steps) > 0 && p.Steps[0].Relation == "entry" {
		return p.Steps[0].Resource
	}
	return graph.InternetNodeID
}

func stepKey(entry string, steps []model.Step) string {
	var b strings.Builder
	b.WriteString(entry)
	b.WriteString("|")
	for i, s := range steps {
		if i > 0 {
			b.WriteString(">")
		}
		b.WriteString(s.Resource)
	}
	return b.String()
}

// splitPrefixes separates complete paths from those that are a strict prefix of a longer
// emitted path from the same entry (defect 18b: prefixes were counted as separate paths).
func splitPrefixes(paths []model.AttackPath) (complete, incomplete []model.AttackPath) {
	extended := map[string]bool{}
	for _, p := range paths {
		e := pathEntry(p)
		for k := 1; k < len(p.Steps); k++ {
			extended[stepKey(e, p.Steps[:k])] = true
		}
	}
	for _, p := range paths {
		if extended[stepKey(pathEntry(p), p.Steps)] {
			incomplete = append(incomplete, p)
		} else {
			complete = append(complete, p)
		}
	}
	return
}

// entryStep is the first step of an identity / SaaS entry (no edge: the credential itself).
func entryStep(n *graph.Node, ev stepEval) model.Step {
	s := stepFor(n, 1, "entry", ev)
	s.Because = fmt.Sprintf("%s on %s: %s", ev.weakness, n.Name, ev.label)
	s.Evidence = map[string]any{"entry": true, "weakness": ev.weakness, "node": n.ID, "likelihood": round2(ev.exploitability)}
	if len(ev.weaknesses) > 0 {
		s.Evidence["entry_weaknesses"] = ev.weaknesses
	}
	if ev.hint {
		s.Evidence["confidence"] = "hint"
	} else if ev.inferredEntry {
		s.Evidence["confidence"] = "inferred"
	}
	if len(n.FindingIDs) > 0 {
		s.Because += " (finding " + strings.Join(n.FindingIDs, ", ") + ")"
		s.Evidence["finding_ids"] = n.FindingIDs
	}
	return s
}

// edgeStep is a hop over edge e; Because/Evidence come from the edge (O4).
func edgeStep(g *graph.Graph, from, to *graph.Node, e *graph.Edge, stage int, ev stepEval) model.Step {
	s := stepFor(to, stage, e.Kind, ev)
	because, _ := e.Attr["because"].(string)
	if because == "" {
		because = graph.DescribeEdge(from, to, e.Kind, e.Attr)
	}
	ev2 := map[string]any{"edge": e.Kind, "from": e.From, "to": e.To, "likelihood": round2(ev.exploitability)}
	for k, v := range e.Attr {
		if k != "because" {
			ev2[k] = v
		}
	}
	if ev.weakness != "" {
		because += "; enabled by " + ev.weakness
		ev2["weakness"] = ev.weakness
		if c, ok := g.Node(ev.weakOn); ok {
			because += " on " + c.Name
			ev2["weakness_on"] = c.ID
			if len(c.FindingIDs) > 0 {
				because += " (finding " + strings.Join(c.FindingIDs, ", ") + ")"
				ev2["finding_ids"] = c.FindingIDs
			}
		}
	}
	if ev.chip != "" {
		because += "; " + ev.chip
		ev2["compensating_control"] = ev.chip
	}
	if ev.hint {
		because += "; confidence hint"
		ev2["confidence"] = "hint"
	} else if ev.reachUnknown {
		because += "; internet reachability not decided by network analysis (confidence inferred)"
		ev2["confidence"] = "inferred"
	}
	s.Because = because
	s.Evidence = ev2
	return s
}

func stepFor(n *graph.Node, stage int, relation string, ev stepEval) model.Step {
	fid := ""
	if len(n.FindingIDs) > 0 {
		fid = n.FindingIDs[0]
	}
	return model.Step{Stage: stage, FindingID: fid, Weakness: ev.weakness, WeaknessOn: ev.weakOn, Relation: relation, Resource: n.ID,
		Title: n.Name, Summary: fmt.Sprintf("%s (%s): %s [p=%.2f]", n.Name, n.Type, ev.label, ev.exploitability)}
}

// pathScore is likelihood × priority (0–10), but never below the score already reached at
// an earlier crown jewel on the same path (the attacker holds that jewel too).
func pathScore(lik, priority, best float64) float64 {
	score := math.Min(math.Round(lik*priority*100)/100, 10)
	return math.Max(score, best)
}

func buildPath(g *graph.Graph, entry *graph.Node, fr frame, priority float64, jewels []JewelRule) model.AttackPath {
	target := fr.node
	width := fr.entryWidth
	if fr.compensated != "" {
		width = "" // authenticated front door: not anonymous wide exposure (decision 3)
	}
	lik, toxic, toxicWhy := applyToxicFloor(fr.lik, width, target, jewels)
	if toxic == "" { // CI-entry floor (toxic.go, P1-PLANDIFF / P12 decision)
		lik, toxic, toxicWhy, fr.steps = applyCIEntryFloor(g, lik, entry, fr.steps, target, jewels)
	}
	if toxic == "" && fr.compensated == "" { // identity-entry floor (identity.go, engine round 2 #12)
		lik, toxic, toxicWhy = applyIdentityFloor(g, lik, entry, fr.steps, target, jewels)
	}
	if toxic == "" && fr.carried != "" && pathScore(lik, priority, 0) < fr.best {
		toxic, toxicWhy = fr.carried, "score held at an earlier crown jewel on this path: "+fr.carriedWhy
	}
	if toxic != "" && len(fr.steps) > 0 {
		// Tag the last step (copied: the frame's steps are shared with child frames).
		fr.steps = append([]model.Step(nil), fr.steps...)
		last := fr.steps[len(fr.steps)-1]
		ev := make(map[string]any, len(last.Evidence)+2)
		for k, v := range last.Evidence {
			ev[k] = v
		}
		ev["toxic_combination"], ev["toxic_reason"] = toxic, toxicWhy
		last.Evidence = ev
		last.Because += "; toxic combination " + toxic + ": " + toxicWhy
		fr.steps[len(fr.steps)-1] = last
	}
	score := pathScore(lik, priority, fr.best)
	var ids []string
	var ids2 []string
	for _, s := range fr.steps {
		ids = append(ids, s.Resource)
		if n, ok := g.Node(s.Resource); ok {
			ids2 = append(ids2, n.FindingIDs...)
		}
	}
	sum := sha256.Sum256([]byte(entry.ID + "|" + strings.Join(ids, ">")))
	sev := PathSeverity(score) // one scale everywhere (shortfall #1)
	var narr []string
	narr = append(narr, fmt.Sprintf("Entry: %s", entry.Name))
	for _, s := range fr.steps {
		narr = append(narr, fmt.Sprintf("%d. %s", s.Stage, s.Summary))
	}
	narr = append(narr, fmt.Sprintf("Target: %s (%s) — likelihood %.0f%% × priority %.0f", target.Name, target.Type, lik*100, priority))
	if toxic != "" {
		narr = append(narr, "Toxic combination ("+toxic+"): "+toxicWhy)
	}
	// Provider / account (defect 3, verify-4 D4): the anchor's, else the entry step's. Node
	// provider / account are order-independent (graph.pickOwner), so the path's are too.
	provider, account := target.Provider, target.Account
	if provider == "" || provider == "any" || account == "" {
		if len(fr.steps) > 0 {
			if n, ok := g.Node(fr.steps[0].Resource); ok && n.Provider != "" && n.Provider != "any" {
				if provider == "" || provider == "any" {
					provider, account = n.Provider, n.Account
				} else if account == "" && n.Provider == provider {
					account = n.Account
				}
			}
		}
	}
	return model.AttackPath{
		ID: hex.EncodeToString(sum[:8]), RuleID: "GRAPH_TRAVERSAL", Name: fmt.Sprintf("%s → %s", entry.Name, target.Name),
		Impact: impactFor(target), Mitre: mitreFor(fr.steps), Provider: provider, Account: account, Score: score, Severity: sev,
		Steps: fr.steps, Narrative: strings.Join(narr, "\n"), FindingIDs: uniq(ids2),
	}
}

func impactFor(n *graph.Node) string {
	switch n.Class {
	case graph.ClassDataStore:
		if sensitiveData(n) {
			return "Sensitive data exfiltration from " + n.Name
		}
		return "Data access on " + n.Name
	case graph.ClassIdentity:
		return "Privilege escalation to " + n.Name
	case graph.ClassCluster:
		return "Cluster takeover: " + n.Name
	case graph.ClassAccount:
		return "Account compromise: " + n.Name
	}
	return "Compromise of " + n.Name
}

func mitreFor(steps []model.Step) []string {
	set := map[string]bool{}
	for _, s := range steps {
		switch s.Weakness {
		case "PUBLIC_NETWORK_EXPOSURE", "UNPATCHED", "PUBLIC_DATA_STORE":
			set["T1190"] = true
		case "IMDSV1_ENABLED":
			set["T1552.005"] = true
		case "OVERPRIVILEGED_IDENTITY", "CLUSTER_ADMIN":
			set["T1078.004"] = true
		case "NO_MFA", "WEAK_AUTH":
			set["T1078"] = true
		case "STALE_CREDENTIALS", "SECRET_EXPOSURE":
			set["T1552.001"] = true
		case "CROSS_ACCOUNT_TRUST":
			set["T1098.003"] = true
		case "PRIVILEGED_CONTAINER":
			set["T1611"] = true
		case "SERVICE_ACCOUNT_TOKEN":
			set["T1528"] = true
		case "BRANCH_UNPROTECTED":
			set["T1195.002"] = true
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// analyzeFixes computes choke points (with drill-in and re-traversal "closes N"),
// break-the-path fixes verified on a fixed copy of the graph, and the minimal fix set.
func (an *Analysis) analyzeFixes(g *graph.Graph) {
	type key struct{ node, weak, to string } // to: the edge target of an edge fix (PassRole)
	scoreOf := map[string]float64{}
	choke := map[string]*ChokePoint{}
	cands := map[key]bool{}
	enables := map[key]map[string]bool{}
	touches := map[key]map[string]bool{} // paths the fix's node is on
	add := func(m map[key]map[string]bool, k key, id string) {
		if m[k] == nil {
			m[k] = map[string]bool{}
		}
		m[k][id] = true
	}
	for _, p := range an.Paths {
		scoreOf[p.ID] = p.Score
		last := len(p.Steps) - 1
		for i, s := range p.Steps {
			n, ok := g.Node(s.Resource)
			if !ok {
				continue
			}
			if i != last && n.Class != graph.ClassInternet {
				cp := choke[n.ID]
				if cp == nil {
					cp = &ChokePoint{NodeID: n.ID, Name: n.Name, Type: n.Type, Weaknesses: n.Weaknesses}
					choke[n.ID] = cp
				}
				cp.Paths++
				cp.ScoreSum += p.Score
				cp.PathIDs = append(cp.PathIDs, p.ID)
			}
			for _, w := range n.Weaknesses {
				k := key{n.ID, w, ""}
				cands[k] = true
				add(touches, k, p.ID)
			}
			if s.Weakness != "" && s.WeaknessOn != "" {
				k := key{s.WeaknessOn, s.Weakness, ""}
				cands[k] = true
				add(enables, k, p.ID)
				add(touches, k, p.ID)
			}
			// A privilege-escalation hop (can_assume with a technique) is cuttable by scoping the
			// permission that creates it (delta r2 #12): an edge fix on that one edge.
			if i > 0 && s.Relation == graph.EdgeCanAssume && escalationEdge(g, p.Steps[i-1].Resource, s.Resource) {
				k := key{p.Steps[i-1].Resource, WeaknessPassRoleEscalation, s.Resource}
				cands[k] = true
				add(enables, k, p.ID)
				add(touches, k, p.ID)
			}
		}
	}
	keys := make([]key, 0, len(cands))
	for k := range cands {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].node != keys[j].node {
			return keys[i].node < keys[j].node
		}
		if keys[i].weak != keys[j].weak {
			return keys[i].weak < keys[j].weak
		}
		return keys[i].to < keys[j].to
	})
	for _, k := range keys {
		fx := Fix{NodeID: k.node, Weakness: k.weak}
		if n, ok := g.Node(k.node); ok {
			fx.Name = n.Name
			fx.FindingIDs = n.FindingIDs
		}
		fx.Command = fixCommand(k.weak, nodeOrNil(g, k.node))
		if k.to != "" {
			fx.Edge = &EdgeRef{From: k.node, To: k.to, Kind: graph.EdgeCanAssume}
			fx.Command = passRoleCommand(g, k.node, k.to)
			if to, ok := g.Node(k.to); ok {
				fx.Name += " → " + to.Name
			}
		}
		v := newFixView(g, []Fix{fx})
		for _, p := range an.Paths {
			if !v.survives(p, an.opts) {
				fx.Breaks = append(fx.Breaks, p.ID)
				fx.ScoreRemoved += p.Score
			}
		}
		broken := map[string]bool{}
		for _, id := range fx.Breaks {
			broken[id] = true
		}
		for id := range touches[k] {
			if !broken[id] {
				fx.Reduces = append(fx.Reduces, id)
			}
		}
		for id := range enables[k] {
			fx.Enables = append(fx.Enables, id)
		}
		sort.Strings(fx.Breaks)
		sort.Strings(fx.Reduces)
		sort.Strings(fx.Enables)
		fx.ScoreRemoved = math.Round(fx.ScoreRemoved*100) / 100
		if len(fx.Breaks) > 0 {
			an.BreakFixes = append(an.BreakFixes, fx)
		} else {
			an.ReduceFixes = append(an.ReduceFixes, fx)
		}
	}
	sort.SliceStable(an.BreakFixes, func(i, j int) bool {
		if len(an.BreakFixes[i].Breaks) != len(an.BreakFixes[j].Breaks) {
			return len(an.BreakFixes[i].Breaks) > len(an.BreakFixes[j].Breaks)
		}
		return an.BreakFixes[i].ScoreRemoved > an.BreakFixes[j].ScoreRemoved
	})
	sort.SliceStable(an.ReduceFixes, func(i, j int) bool { return len(an.ReduceFixes[i].Reduces) > len(an.ReduceFixes[j].Reduces) })

	for _, cp := range choke {
		cp.ScoreSum = math.Round(cp.ScoreSum*100) / 100
		an.ChokePoints = append(an.ChokePoints, *cp)
	}
	sort.Slice(an.ChokePoints, func(i, j int) bool {
		if an.ChokePoints[i].Paths != an.ChokePoints[j].Paths {
			return an.ChokePoints[i].Paths > an.ChokePoints[j].Paths
		}
		if an.ChokePoints[i].ScoreSum != an.ChokePoints[j].ScoreSum {
			return an.ChokePoints[i].ScoreSum > an.ChokePoints[j].ScoreSum
		}
		return an.ChokePoints[i].NodeID < an.ChokePoints[j].NodeID
	})
	if len(an.ChokePoints) > 10 {
		an.ChokePoints = an.ChokePoints[:10]
	}
	// O9: "fixing this closes N" — measured by removing the node and re-running traversal.
	for i := range an.ChokePoints {
		c := g.Clone()
		c.RemoveNode(an.ChokePoints[i].NodeID)
		an.ChokePoints[i].ClosesN = removedCount(an.Paths, traverse(c, an.opts).allPaths)
	}

	an.minFixSet(g, scoreOf)
}

func nodeOrNil(g *graph.Graph, id string) *graph.Node {
	n, _ := g.Node(id)
	return n
}

// minFixSet picks the smallest set of break fixes that cuts every cuttable path: exact
// (brute force ≤ 20 candidates, branch and bound on graphs ≤ 2,000 edges) or greedy weighted
// set cover above that, then re-verifies the claim by re-traversing with the set applied.
func (an *Analysis) minFixSet(g *graph.Graph, scoreOf map[string]float64) {
	idx := map[string]int{}
	weights := make([]float64, len(an.Paths))
	for i, p := range an.Paths {
		idx[p.ID] = i
		weights[i] = p.Score
	}
	sets := make([][]int, len(an.BreakFixes))
	for i, fx := range an.BreakFixes {
		for _, id := range fx.Breaks {
			sets[i] = append(sets[i], idx[id])
		}
	}
	var chosen []int
	switch {
	case len(sets) == 0:
		an.MinFixExact = true
	case len(sets) <= exactBruteForceMax || len(g.Edges()) <= exactEdgeMax:
		budget := 2_000_000
		if sol, ok := exactCover(sets, len(an.Paths), budget); ok {
			chosen, an.MinFixExact = sol, true
			break
		}
		chosen = greedyCover(sets, weights)
	default:
		chosen = greedyCover(sets, weights)
	}
	claimed := map[string]bool{}
	for _, i := range chosen {
		an.MinFixSet = append(an.MinFixSet, an.BreakFixes[i])
		for _, id := range an.BreakFixes[i].Breaks {
			claimed[id] = true
		}
	}
	// Re-verify: apply the set in-graph and re-traverse.
	after := traverse(ApplyFixes(g, an.MinFixSet), an.opts)
	still := map[string]bool{}
	for _, p := range after.allPaths {
		still[p.ID] = true
	}
	an.MinFixVerified = true
	removed := 0.0
	for _, p := range an.Paths {
		if still[p.ID] {
			if claimed[p.ID] {
				an.MinFixVerified = false
			}
			continue
		}
		removed += scoreOf[p.ID]
	}
	if an.TotalScore > 0 {
		an.MinFixCoverage = math.Round(removed/an.TotalScore*1000) / 10
	}
}

// classifyDeadEnds marks every finding-bearing node by whether a complete path crosses it (O11).
func (an *Analysis) classifyDeadEnds(g *graph.Graph) {
	on := map[string]bool{}
	for _, p := range an.allPaths {
		for _, s := range p.Steps {
			on[s.Resource] = true
		}
	}
	an.ReachesCrownJewel = map[string]bool{}
	an.DeadEnds = DeadEnds{IDs: []string{}}
	for _, n := range g.Nodes() {
		if len(n.FindingIDs) == 0 {
			continue
		}
		an.ReachesCrownJewel[n.ID] = on[n.ID]
		if !on[n.ID] {
			an.DeadEnds.IDs = append(an.DeadEnds.IDs, n.ID)
		}
	}
	an.DeadEnds.Count = len(an.DeadEnds.IDs)
}

// FilterFindings keeps findings whose resource reaches a crown jewel (reaching=true) or the
// dead ends (reaching=false). Resources that are not in the graph count as dead ends.
func (an *Analysis) FilterFindings(fs []model.Finding, reaching bool) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if an.ReachesCrownJewel[f.Resource.ID] == reaching {
			out = append(out, f)
		}
	}
	return out
}

var weaknessToCanonical = map[string]string{
	"PUBLIC_DATA_STORE": "S3_PUBLIC_BUCKET", "PUBLIC_NETWORK_EXPOSURE": "EC2_SG_OPEN_SSH", "IMDSV1_ENABLED": "EC2_IMDSV1",
	"OVERPRIVILEGED_IDENTITY": "IAM_ADMIN_POLICY", "NO_MFA": "IAM_USER_NO_MFA", "STALE_CREDENTIALS": "IAM_STALE_KEYS",
	"CROSS_ACCOUNT_TRUST": "IAM_CROSS_ACCOUNT_TRUST", "UNENCRYPTED_AT_REST": "RDS_UNENCRYPTED", "NO_LOGGING": "CLOUDTRAIL_DISABLED",
	"PRIVILEGED_CONTAINER": "K8S_PRIVILEGED_CONTAINER", "CLUSTER_ADMIN": "K8S_CLUSTER_ADMIN_BINDING", "SERVICE_ACCOUNT_TOKEN": "K8S_DEFAULT_SA_TOKEN",
}

func fixCommand(weak string, n *graph.Node) string {
	if n != nil && len(n.FindingIDs) > 0 {
		return "cloud-posture fix --id " + n.FindingIDs[0] + " --generate-terraform"
	}
	if c, ok := weaknessToCanonical[weak]; ok {
		return "cloud-posture fix --finding " + c + " --generate-terraform"
	}
	return "cloud-posture fix --weakness " + weak
}

// BlastRadius lists everything reachable from a node within maxHops over attack edges,
// with the sensitive targets called out (the "what if this is compromised" view).
func BlastRadius(g *graph.Graph, nodeID string, maxHops int, jewels []JewelRule) (reachable []string, sensitive []string) {
	start, ok := g.Node(nodeID)
	if !ok {
		return nil, nil
	}
	type item struct {
		id   string
		hops int
	}
	seen := map[string]bool{nodeID: true}
	queue := []item{{nodeID, 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.hops >= maxHops {
			continue
		}
		from, _ := g.Node(cur.id)
		for _, e := range g.Out(cur.id) {
			if seen[e.To] {
				continue
			}
			to, ok := g.Node(e.To)
			if !ok || evaluate(g, nil, from, to, e).exploitability == 0 {
				continue
			}
			seen[e.To] = true
			reachable = append(reachable, e.To)
			if Criticality(to, jewels) >= 3 {
				sensitive = append(sensitive, e.To)
			}
			queue = append(queue, item{e.To, cur.hops + 1})
		}
	}
	_ = start
	sort.Strings(reachable)
	sort.Strings(sensitive)
	return
}

// Merge combines rule-based and traversal paths, de-duplicated by ID and sorted by score. A rule
// chain that a traversal path already covers is folded into it (FoldRuleChains, delta r2 #2).
func Merge(a, b []model.AttackPath) []model.AttackPath {
	// Same id twice (two producers): keep the higher score; equal scores → the lexicographically
	// smaller hop list, so the result never depends on input order (verification 6).
	hopList := func(p model.AttackPath) string {
		hs := make([]string, len(p.Steps))
		for i, s := range p.Steps {
			hs[i] = s.Resource
		}
		return strings.Join(hs, "\x00")
	}
	at := map[string]int{}
	var out []model.AttackPath
	for _, p := range append(append([]model.AttackPath{}, a...), b...) {
		if i, ok := at[p.ID]; ok {
			if q := out[i]; p.Score > q.Score || p.Score == q.Score && hopList(p) < hopList(q) {
				out[i] = p
			}
			continue
		}
		at[p.ID] = len(out)
		out = append(out, p)
	}
	out = FoldRuleChains(out)
	// Score first; equal scores by secondary key, then id, so the order never depends on the
	// input order (verify-5 fold probe: equal-score twins swapped with the input).
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if ki, kj := model.PathSecondaryKey(out[i]), model.PathSecondaryKey(out[j]); ki != kj {
			return ki < kj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// AttrAlsoMatchesRule is the evidence key, on the last step of a traversal path, listing the
// rule chains folded into it.
const AttrAlsoMatchesRule = "also_matches_rule"

// AttrFoldSources lists, on the last step of a traversal path with folded rule chains, every
// merged source with its own score ("GRAPH_TRAVERSAL 4.00", "<rule id> 9.50"); AttrFoldScoreFrom
// names the source whose (highest) score the folded path reports (verify-5 C6).
const (
	AttrFoldSources   = "fold_sources"
	AttrFoldScoreFrom = "score_from"
)

func isTraversal(p model.AttackPath) bool { return p.RuleID == "" || p.RuleID == "GRAPH_TRAVERSAL" }

// AlsoMatchesRules returns the rule ids folded into a traversal path (sorted; nil when none).
func AlsoMatchesRules(p model.AttackPath) []string {
	if len(p.Steps) == 0 {
		return nil
	}
	return toStrings(p.Steps[len(p.Steps)-1].Evidence[AttrAlsoMatchesRule])
}

// FoldRuleChains folds every rule chain that shares entry kind, entry and anchor with a traversal
// path (the same path Issue modulo rule; a rule chain's first step is the resource a traversal
// path enters at, so an internet traversal path is matched on its first exposed hop; an
// identity-entry chain only folds into an identity-entry path and an internet one into an internet
// one, verify-5 C14) into the best such traversal path: the rule id is added to its
// also_matches_rule tag, its findings to the path's FindingIDs, and the chain is dropped, so one
// risk is one Issue at one score. The folded path reports the HIGHEST score (and its band) of the
// merged sources and lists every source with its own score (fold_sources, score_from; verify-5
// C6: folding used to keep the traversal score even when the rule chain scored 9.5 against 4.0).
// Rule chains with no traversal counterpart are kept. Input paths are never mutated; the result
// does not depend on input order.
func FoldRuleChains(paths []model.AttackPath) []model.AttackPath {
	type key struct {
		first, anchor string
		identity      bool
	}
	keyOf := func(p model.AttackPath) key {
		return key{p.Steps[0].Resource, p.Steps[len(p.Steps)-1].Resource, foldIdentityEntry(p)}
	}
	best := map[key]int{}
	for i, p := range paths {
		if len(p.Steps) == 0 || !isTraversal(p) {
			continue
		}
		k := keyOf(p)
		j, ok := best[k]
		if !ok || p.Score > paths[j].Score || p.Score == paths[j].Score && model.PathSecondaryKey(p) < model.PathSecondaryKey(paths[j]) ||
			p.Score == paths[j].Score && model.PathSecondaryKey(p) == model.PathSecondaryKey(paths[j]) && p.ID < paths[j].ID {
			best[k] = i
		}
	}
	folded := map[int][]model.AttackPath{}
	drop := map[int]bool{}
	for i, p := range paths {
		if len(p.Steps) == 0 || isTraversal(p) || IsRuleMatch(p) {
			continue // a rule-match path is its own Issue (rulematch.go), never folded
		}
		if j, ok := best[keyOf(p)]; ok {
			folded[j] = append(folded[j], p)
			drop[i] = true
		}
	}
	if len(drop) == 0 {
		return paths
	}
	out := make([]model.AttackPath, 0, len(paths)-len(drop))
	for i, p := range paths {
		if drop[i] {
			continue
		}
		if rs := folded[i]; len(rs) > 0 {
			sort.SliceStable(rs, func(a, b int) bool {
				if rs[a].RuleID != rs[b].RuleID {
					return rs[a].RuleID < rs[b].RuleID
				}
				return rs[a].ID < rs[b].ID
			})
			rules := AlsoMatchesRules(p)
			fids := append([]string(nil), p.FindingIDs...)
			travRule := p.RuleID
			if travRule == "" {
				travRule = "GRAPH_TRAVERSAL"
			}
			sources := []string{fmt.Sprintf("%s %.2f", travRule, p.Score)}
			score, from := p.Score, travRule
			for _, r := range rs {
				rules = append(rules, r.RuleID)
				fids = append(fids, r.FindingIDs...)
				sources = append(sources, fmt.Sprintf("%s %.2f", r.RuleID, r.Score))
				if r.Score > score {
					score, from = r.Score, r.RuleID
				}
			}
			rules = uniq(rules)
			sort.Strings(rules)
			steps := append([]model.Step(nil), p.Steps...)
			last := &steps[len(steps)-1]
			ev := make(map[string]any, len(last.Evidence)+3)
			for k, v := range last.Evidence {
				ev[k] = v
			}
			ev[AttrAlsoMatchesRule] = rules
			ev[AttrFoldSources] = uniq(sources)
			ev[AttrFoldScoreFrom] = from
			last.Evidence = ev
			p.Steps, p.FindingIDs = steps, uniq(fids)
			if score > p.Score {
				p.Score, p.Severity = score, PathSeverity(score)
			}
		}
		out = append(out, p)
	}
	return out
}

// foldIdentityEntry is the entry kind FoldRuleChains matches on: a traversal path enters by an
// identity when its first step is an "entry" step (else from the internet). The rule engine
// marks every chain's first step "entry", so a rule chain's kind is read from its first stage's
// weakness: a PUBLIC_* exposure (PUBLIC_NETWORK_EXPOSURE, PUBLIC_DATA_STORE…) is an internet
// entry; any other weakness (CROSS_ACCOUNT_TRUST, STALE_CREDENTIALS…) or none an identity one.
func foldIdentityEntry(p model.AttackPath) bool {
	st := p.Steps[0]
	if st.Relation != "entry" {
		return false
	}
	if isTraversal(p) {
		return true
	}
	return !strings.HasPrefix(st.Weakness, "PUBLIC_")
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
