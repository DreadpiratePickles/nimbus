package attackpath

import (
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Exposure width on internet edges (O10, Track B2 item 3). Collectors label their exposes
// edges with core.Expose (exposure + exposure_cidrs); ingested findings carry the scanner's
// attributes.exposure_cidrs onto the edge (graph.AttachFindings). Width is decided here with
// the same helper (core.ExposureWidth) against TraversalOptions.TrustedCIDRs:
//
//	wide     any source is 0.0.0.0/0 or ::/0, or no source restriction is known
//	narrow   specific public sources, at least one outside trusted_cidrs
//	trusted  every source inside trusted_cidrs → not an entry; listed in Analysis.Suppressed
//	private  every source is private / non-routable → not an internet entry either
const exposurePrivate = "private"

// Suppressed is internet exposure that analysis refused to use as an entry, and why.
type Suppressed struct {
	NodeID     string   `json:"node_id"`
	Name       string   `json:"name"`
	Exposure   string   `json:"exposure"` // trusted | private
	CIDRs      []string `json:"exposure_cidrs,omitempty"`
	Reason     string   `json:"reason"`
	FindingIDs []string `json:"finding_ids,omitempty"`
}

// Exposure is an internet-reachable resource that is not an impact target (decision 1), or
// (Reachability "blocked") a resource whose internet exposure network analysis disproved: its
// findings stand, but it is no path entry, and Reason names the blocker (REACH reach_blocker).
type Exposure struct {
	NodeID       string   `json:"node_id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Width        string   `json:"width"` // wide | narrow | blocked
	Because      string   `json:"because"`
	FindingIDs   []string `json:"finding_ids,omitempty"`
	Reachability string   `json:"reachability,omitempty"` // REACH verdict: blocked (only blocked exposures set it)
	Reason       string   `json:"reason,omitempty"`       // reach_blocker for a blocked exposure
	ReachPath    string   `json:"reach_path,omitempty"`
}

// REACH consumption (P2-REACH attrs on internet edges / nodes: reachability, reach_path,
// reach_blocker, reach_confidence). blocked: the edge is dropped from traversal and the resource
// is listed in Analysis.Exposures with the blocker as its reason; unknown: the edge stays, its hop
// carries confidence inferred; anything else (reachable, or no attribute): unchanged.
const (
	AttrReachability = "reachability"
	AttrReachBlocker = "reach_blocker"
	AttrReachPath    = "reach_path"
	ReachBlocked     = "blocked"
	ReachUnknown     = "unknown"
	exposureBlocked  = "blocked"
)

func reachAttr(m map[string]any) (state, blocker, path string) {
	if m == nil {
		return "", "", ""
	}
	state, _ = m[AttrReachability].(string)
	blocker, _ = m[AttrReachBlocker].(string)
	path, _ = m[AttrReachPath].(string)
	return strings.ToLower(strings.TrimSpace(state)), blocker, path
}

// reachBlockedNode returns the blocker when the node itself is REACH-blocked ("" otherwise).
func reachBlockedNode(n *graph.Node) string {
	if n == nil {
		return ""
	}
	if st, b, _ := reachAttr(n.Attributes); st == ReachBlocked {
		if b == "" {
			b = "network analysis: not reachable from the internet"
		}
		return b
	}
	return ""
}

// reachBlockedEdge returns the blocker of an internet-facing edge into to: the edge's own
// verdict, else the target node's.
func reachBlockedEdge(e *graph.Edge, to *graph.Node) string {
	if e != nil {
		if st, b, _ := reachAttr(e.Attr); st == ReachBlocked {
			if b == "" {
				b = "network analysis: not reachable from the internet"
			}
			return b
		}
	}
	return reachBlockedNode(to)
}

// reachUnknown reports a REACH "unknown" verdict on the edge or its target.
func reachUnknown(e *graph.Edge, to *graph.Node) bool {
	if e != nil {
		if st, _, _ := reachAttr(e.Attr); st == ReachUnknown {
			return true
		}
	}
	if to != nil {
		if st, _, _ := reachAttr(to.Attributes); st == ReachUnknown {
			return true
		}
	}
	return false
}

// blockedExposures lists resources whose every internet route (direct, or through an exposed
// network control) REACH marked blocked.
func blockedExposures(g *graph.Graph, trusted []string) []Exposure {
	type acc struct {
		x      Exposure
		usable bool
	}
	by := map[string]*acc{}
	note := func(n *graph.Node, blocker, via string, blocked bool, path string) {
		a := by[n.ID]
		if a == nil {
			a = &acc{x: Exposure{NodeID: n.ID, Name: n.Name, Type: n.Type, Width: exposureBlocked, Reachability: ReachBlocked,
				FindingIDs: append([]string(nil), n.FindingIDs...)}}
			by[n.ID] = a
		}
		if !blocked {
			a.usable = true
			return
		}
		if a.x.Reason == "" {
			a.x.Reason, a.x.ReachPath = blocker, path
			a.x.Because = via + " is not reachable from the internet: " + blocker
		}
	}
	for _, e := range g.Out(graph.InternetNodeID) {
		if e.Kind != graph.EdgeExposes && e.Kind != graph.EdgeAllowsTrafficTo {
			continue
		}
		to, ok := g.Node(e.To)
		if !ok {
			continue
		}
		if w, _, _ := exposureOf(e, trusted); w == core.ExposureTrusted || w == exposurePrivate {
			continue // suppressed for another reason; listed there
		}
		_, _, path := reachAttr(e.Attr)
		b := reachBlockedEdge(e, to)
		note(to, b, "internet → "+to.Name, b != "", path)
		if to.Class != graph.ClassNetwork || b != "" {
			continue
		}
		for _, f := range g.Out(to.ID) {
			if f.Kind != graph.EdgeAllowsTrafficTo {
				continue
			}
			if behind, ok := g.Node(f.To); ok {
				bb := reachBlockedEdge(f, behind)
				_, _, p2 := reachAttr(f.Attr)
				note(behind, bb, "internet → "+to.Name+" → "+behind.Name, bb != "", p2)
			}
		}
	}
	var out []Exposure
	for _, a := range by {
		if !a.usable && a.x.Reason != "" {
			out = append(out, a.x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// exposureOf classifies one internet → node edge.
func exposureOf(e *graph.Edge, trusted []string) (width string, cidrs []string, reason string) {
	cidrs = toStrings(e.Attr[core.AttrExposureCIDRs])
	label, _ := e.Attr[core.AttrExposure].(string)
	if label == core.ExposureTrusted {
		r, _ := e.Attr[core.AttrExposureReason].(string)
		if r == "" {
			r = "the collector labelled this exposure trusted (every source inside trusted_cidrs)"
		}
		return core.ExposureTrusted, cidrs, r
	}
	if label == exposurePrivate {
		r, _ := e.Attr[core.AttrExposureReason].(string)
		if r == "" {
			r = "labelled private"
		}
		return exposurePrivate, cidrs, r
	}
	if len(cidrs) == 0 {
		if label == core.ExposureNarrow {
			return core.ExposureNarrow, nil, ""
		}
		return core.ExposureWide, nil, ""
	}
	pub := core.PublicSources(cidrs)
	if len(pub) == 0 {
		return exposurePrivate, cidrs, "every source (" + strings.Join(cidrs, ", ") + ") is a private or non-routable range"
	}
	switch w := core.ExposureWidth(pub, trusted); w {
	case core.ExposureTrusted:
		return w, cidrs, "every source (" + strings.Join(pub, ", ") + ") is inside trusted_cidrs (" + strings.Join(trusted, ", ") + ")"
	default:
		return w, cidrs, ""
	}
}

// exposureAt is exposureOf plus the target's own attributes (planning decision 2): exposure
// needs effective reachability by an anonymous attacker. A function URL that requires
// authentication, a Principal * resource policy conditioned on the caller's organisation /
// account / VPC, or storage with anonymous access disabled is "private" with the reason, so it is
// never an entry (listed in Analysis.Suppressed).
func exposureAt(g *graph.Graph, e *graph.Edge, trusted []string) (string, []string, string) {
	w, cidrs, reason := exposureOf(e, trusted)
	if suppressedWidth(w) || g == nil || e.From != graph.InternetNodeID {
		return w, cidrs, reason
	}
	n, _ := g.Node(e.To)
	if b := reachBlockedEdge(e, n); b != "" {
		return exposureBlocked, cidrs, b // REACH: route / NACL / IGW analysis disproves the exposure
	}
	if n != nil {
		if v, why := graph.AnonymousReachOf(n); v == exposurePrivate {
			return exposurePrivate, cidrs, why
		}
	}
	return w, cidrs, reason
}

// anonymousReach is graph.AnonymousReach (one implementation shared with who-can's anonymous
// principal, delta #5): "private" (with the reason), "anonymous", or "". Callers holding the node
// use graph.AnonymousReachOf, which evaluates the resource policy against the node's own ARN.
func anonymousReach(typ string, attrs map[string]any) (string, string) {
	return graph.AnonymousReach(typ, attrs)
}

// authCheckable: resource types whose anonymous reach the attributes can settle (serverless
// URLs, object storage). Exposure on them with no deciding attribute is confidence: hint.
func authCheckable(typ string) bool {
	t := strings.ToLower(typ)
	return serverlessType(t) || strings.Contains(t, "s3_bucket") || strings.Contains(t, "storage_account") || strings.Contains(t, "storage_bucket")
}

func serverlessType(t string) bool {
	return strings.Contains(t, "lambda") || strings.Contains(t, "cloud_function") || strings.Contains(t, "cloudfunction") ||
		strings.Contains(t, "function_app") || strings.Contains(t, "cloud_run")
}

// AuthLBFactor is the likelihood multiplier for the hop through an internet-facing load
// balancer / API gateway that authenticates callers (planning decision 3).
const AuthLBFactor = 0.3

// authFront says why n, a load balancer / API gateway / application gateway, authenticates or
// filters callers before forwarding ("" when it does not, or n is not a front door): an
// authentication / authorizer attribute (OIDC, Cognito, IAM authorizer) or a WAF web ACL.
func authFront(n *graph.Node) string {
	if n == nil || n.Attributes == nil {
		return ""
	}
	t := strings.ToLower(n.Type)
	front := strings.Contains(t, "_lb") || strings.Contains(t, "load_balancer") || strings.Contains(t, "loadbalancer") || strings.Contains(t, "elb") ||
		strings.Contains(t, "api_gateway") || strings.Contains(t, "apigateway") || strings.Contains(t, "application_gateway") || strings.Contains(t, "front_door")
	if !front {
		return ""
	}
	for _, k := range []string{"authentication", "auth", "authorizer", "authorizer_type", "listener_authentication", "oidc", "cognito"} {
		switch v := n.Attributes[k].(type) {
		case string:
			if lv := strings.ToLower(strings.TrimSpace(v)); lv != "" && lv != "none" && lv != "false" && lv != "disabled" {
				return k + ": " + v
			}
		case bool:
			if v {
				return k
			}
		}
	}
	for _, k := range []string{"waf_web_acl", "waf", "web_acl", "waf_enabled"} {
		switch v := n.Attributes[k].(type) {
		case string:
			if strings.TrimSpace(v) != "" && !strings.EqualFold(v, "none") {
				return "WAF " + v
			}
		case bool:
			if v {
				return "WAF"
			}
		}
	}
	return ""
}

func suppressedWidth(w string) bool {
	return w == core.ExposureTrusted || w == exposurePrivate || w == exposureBlocked
}

// widthFactor scales internet-entry likelihood by how many sources can reach the resource.
func widthFactor(w string) float64 {
	if w == core.ExposureNarrow {
		return 0.5
	}
	return 1
}

// nodeExposure is the widest usable internet exposure of n ("" when n is not reachable from
// the internet, directly or through an exposed network control in front of it).
func nodeExposure(g *graph.Graph, n *graph.Node, trusted []string) string {
	if g == nil || n == nil || reachBlockedNode(n) != "" {
		return ""
	}
	best := ""
	consider := func(w string) {
		if suppressedWidth(w) || w == "" {
			return
		}
		if best == "" || w == core.ExposureWide {
			best = w
		}
	}
	for _, e := range g.In(n.ID) {
		switch {
		case e.From == graph.InternetNodeID && (e.Kind == graph.EdgeExposes || e.Kind == graph.EdgeAllowsTrafficTo):
			w, _, _ := exposureAt(g, e, trusted)
			consider(w)
		case e.Kind == graph.EdgeAllowsTrafficTo:
			if reachBlockedEdge(e, n) != "" {
				continue
			}
			if src, ok := g.Node(e.From); ok && src.Class == graph.ClassNetwork {
				for _, in := range g.In(src.ID) {
					if in.From == graph.InternetNodeID && in.Kind == graph.EdgeExposes {
						w, _, _ := exposureAt(g, in, trusted)
						consider(w)
					}
				}
			}
		}
	}
	return best
}

// suppressedExposures lists the nodes whose every internet edge is trusted or private.
func suppressedExposures(g *graph.Graph, trusted []string) []Suppressed {
	byNode := map[string]*Suppressed{}
	usable := map[string]bool{}
	for _, e := range g.Out(graph.InternetNodeID) {
		if e.Kind != graph.EdgeExposes && e.Kind != graph.EdgeAllowsTrafficTo {
			continue
		}
		w, cidrs, reason := exposureAt(g, e, trusted)
		if w == exposureBlocked {
			usable[e.To] = true // listed in Analysis.Exposures with the REACH blocker instead
			continue
		}
		if !suppressedWidth(w) {
			usable[e.To] = true
			continue
		}
		s := byNode[e.To]
		if s == nil {
			s = &Suppressed{NodeID: e.To, Exposure: w, Reason: reason}
			if n, ok := g.Node(e.To); ok {
				s.Name = n.Name
				s.FindingIDs = append([]string(nil), n.FindingIDs...)
			}
			byNode[e.To] = s
		}
		s.CIDRs = uniq(append(s.CIDRs, cidrs...))
	}
	var out []Suppressed
	for id, s := range byNode {
		if !usable[id] {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// AnnotateExposure labels every internet edge that carries exposure_cidrs (and its node)
// with exposure / exposure_cidrs / exposure_reason against trusted, in place, so ingested
// graphs look like collector-built ones. It returns the suppressed exposures.
func AnnotateExposure(g *graph.Graph, trusted []string) []Suppressed {
	for _, e := range g.Out(graph.InternetNodeID) {
		if e.Kind != graph.EdgeExposes {
			continue
		}
		if n, ok := g.Node(e.To); ok {
			if v, why := graph.AnonymousReachOf(n); v == exposurePrivate {
				// Decision 2: not anonymously reachable. Label edge and node so risk scoring and
				// every later reader see exposure=private with the reason.
				e.Attr[core.AttrExposure], e.Attr[core.AttrExposureReason] = exposurePrivate, why
				g.AddNode(&graph.Node{ID: e.To, Attributes: map[string]any{core.AttrExposure: exposurePrivate, core.AttrExposureReason: why}})
				continue
			}
		}
		cidrs := toStrings(e.Attr[core.AttrExposureCIDRs])
		if len(cidrs) == 0 {
			continue
		}
		w, _, reason := exposureOf(e, trusted)
		core.ExposureAttrs(e.Attr, cidrs, trusted)
		if w == exposurePrivate {
			e.Attr[core.AttrExposure], e.Attr[core.AttrExposureReason] = exposurePrivate, reason
		}
		attrs := map[string]any{core.AttrExposure: e.Attr[core.AttrExposure], core.AttrExposureCIDRs: e.Attr[core.AttrExposureCIDRs]}
		if r, ok := e.Attr[core.AttrExposureReason]; ok {
			attrs[core.AttrExposureReason] = r
		}
		g.AddNode(&graph.Node{ID: e.To, Attributes: attrs})
	}
	return suppressedExposures(g, trusted)
}

// findingExposureSuppressed reports a finding whose own exposure evidence
// (attributes.exposure / exposure_cidrs) is trusted or private: the rule engine must not use
// it as an internet entry.
func findingExposureSuppressed(f *model.Finding, trusted []string) bool {
	attrs := f.Resource.Attributes
	if attrs == nil {
		return false
	}
	if v, _ := graph.AnonymousReachOf(&graph.Node{ID: f.Resource.ID, Type: f.Resource.Type, Attributes: attrs}); v == exposurePrivate {
		return true // authentication required / org-conditioned / anonymous access disabled
	}
	e := &graph.Edge{Attr: map[string]any{}}
	if v, ok := attrs[core.AttrExposure]; ok {
		e.Attr[core.AttrExposure] = v
	}
	if v, ok := attrs[core.AttrExposureCIDRs]; ok {
		e.Attr[core.AttrExposureCIDRs] = v
	}
	w, _, _ := exposureOf(e, trusted)
	return suppressedWidth(w)
}
