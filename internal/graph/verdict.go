package graph

import (
	"fmt"
	"strings"
)

// One verdict everywhere (competitive delta r2 #1). Verdict is the internet-reachability
// verdict of one node as every surface must read it: `paths --exposures` (attackpath), the risk
// exposure factor, Issue severity, the copilot / MCP. It folds the REACH attributes
// (reachability.go) over every internet route into the node:
//
//	reachable  at least one route is reachable
//	blocked    every route is blocked (Reason is the first blocker, e.g. "route table … has no
//	           route to an internet gateway")
//	unknown    no route is reachable and at least one is unknown (Reason says why); the exposure
//	           stands as "inferred"
//	private    every internet route is suppressed: the collector / analysis labelled it private
//	trusted    (or trusted); Reason is the exposure_reason, Label "private (suppressed: <reason>)"
//	""         the node has no internet route and no REACH verdict (not exposed)
//
// Width is the route's reach_width, else its internet edge's exposure label.
//
// A route with no REACH verdict anywhere (edge, node, the network control in front of it, its
// internet edge or its own node) is unknown ("reachability not evaluated"), never "": no
// exposure data is unknown, whether or not the reachability pass ran on the graph. Reason is short: the node is named instead
// of its full id and every clause appears once (at most two, "+N more"); the full text stays in
// reach_unknown / reach_blocker.
//
// A route is an internet edge (exposes / allows_traffic_to from the internet node) into the
// node, or an allows_traffic_to edge into it from an internet-exposed network control (security
// group / NSG / firewall); each route's verdict is the edge's own REACH verdict, else the node's,
// else the control's.
// Routes the collector labelled exposure trusted / private are not internet routes. A node with
// no route but a node-level verdict (a load-balancer target) takes the node verdict.
type Verdict struct {
	NodeID     string `json:"node_id"`
	Status     string `json:"status"` // reachable | blocked | unknown | private | trusted | ""
	Reason     string `json:"reason,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Width      string `json:"width,omitempty"` // REACH reach_width or the exposure label, when known
	Routes     int    `json:"routes"`
	// Label is the one-line wording every surface prints: "internet reachable",
	// "not exposed (blocked: <reason>)", "exposure inferred (reachability unknown: <reason>)".
	Label string `json:"label,omitempty"`
}

// Verdict statuses.
const (
	VerdictReachable = "reachable"
	VerdictBlocked   = "blocked"
	VerdictUnknown   = "unknown"
	// VerdictPrivate / VerdictTrusted: every internet route into the node is suppressed
	// (collector / analysis exposure label private or trusted); Reason is exposure_reason.
	VerdictPrivate = "private"
	VerdictTrusted = "trusted"
)

// Blocked reports a blocked verdict.
func (v Verdict) Blocked() bool { return v.Status == VerdictBlocked }

type routeVerdict struct {
	status, reason, conf, width string
}

func verdictOf(attrs map[string]any) routeVerdict {
	if attrs == nil {
		return routeVerdict{}
	}
	st, _ := attrs[AttrReachability].(string)
	rv := routeVerdict{status: strings.ToLower(strings.TrimSpace(st))}
	rv.conf, _ = attrs[AttrReachConfidence].(string)
	rv.width, _ = attrs[AttrReachWidth].(string)
	switch rv.status {
	case VerdictBlocked:
		rv.reason, _ = attrs[AttrReachBlocker].(string)
		if rv.reason == "" {
			rv.reason = "network analysis: not reachable from the internet"
		}
	case VerdictUnknown:
		rv.reason, _ = attrs[AttrReachUnknown].(string)
		if rv.reason == "" {
			rv.reason = "network data incomplete"
		}
	}
	return rv
}

func suppressedRoute(e *Edge) bool {
	l, _ := e.Attr["exposure"].(string)
	l = strings.ToLower(l)
	return l == "trusted" || l == "private"
}

// noVerdictReason: a route nothing evaluated (no REACH verdict on the edge, the node or the
// network control in front of it).
const noVerdictReason = "reachability not evaluated (no network verdict on this route)"

// suppressedOf is the exposure label (private | trusted) and reason of a suppressed route.
func suppressedOf(e *Edge, n *Node) (string, string) {
	l, _ := e.Attr["exposure"].(string)
	why, _ := e.Attr["exposure_reason"].(string)
	if why == "" && n != nil {
		why, _ = n.Attributes["exposure_reason"].(string)
	}
	if why == "" {
		why = "exposure labelled " + strings.ToLower(l)
	}
	return strings.ToLower(l), why
}

// shortReason is one short reason: the nodes named instead of their full ids, every clause once,
// at most two clauses (the full text stays in reach_unknown / reach_blocker).
func shortReason(reason string, named ...*Node) string {
	for _, n := range named {
		if n != nil && n.Name != "" && n.Name != n.ID && n.ID != "" {
			reason = strings.ReplaceAll(reason, n.ID, n.Name)
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range strings.Split(reason, "; ") {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	const keep = 2
	if len(out) > keep {
		more := len(out) - keep
		out = append(out[:keep:keep], fmt.Sprintf("+%d more", more))
	}
	return strings.Join(out, "; ")
}

// Verdict returns the node's one internet-reachability verdict (see the type).
func (g *Graph) Verdict(nodeID string) Verdict {
	v := Verdict{NodeID: nodeID}
	n, ok := g.Node(nodeID)
	if !ok {
		return v
	}
	g.mu.RLock()
	nodeV := verdictOf(n.Attributes)
	g.mu.RUnlock()
	var routes []routeVerdict
	// The first suppressed (private / trusted) route: the verdict when no other route exists.
	var supLabel, supReason string
	suppress := func(e *Edge) {
		if supLabel == "" {
			g.mu.RLock()
			supLabel, supReason = suppressedOf(e, n)
			g.mu.RUnlock()
		}
	}
	// A route's verdict is its edge's, else the node's, else the network control's (its
	// internet edge, then the control node itself) (C11). A route nothing evaluated is unknown
	// — "no exposure data" never reads as "" once an internet route exists (W5).
	add := func(width string, vs ...routeVerdict) {
		for _, rv := range vs {
			if rv.status != "" {
				if rv.width == "" {
					rv.width = width
				}
				routes = append(routes, rv)
				return
			}
		}
		routes = append(routes, routeVerdict{status: VerdictUnknown, reason: noVerdictReason, width: width})
	}
	edgeWidth := func(attrs map[string]any) string {
		if w, _ := attrs[AttrReachWidth].(string); w != "" {
			return w
		}
		w, _ := attrs["exposure"].(string)
		return strings.ToLower(w)
	}
	for _, e := range g.In(nodeID) {
		switch {
		case e.From == InternetNodeID && (e.Kind == EdgeExposes || e.Kind == EdgeAllowsTrafficTo):
			if suppressedRoute(e) {
				suppress(e)
				continue
			}
			g.mu.RLock()
			w, ev := edgeWidth(e.Attr), verdictOf(e.Attr)
			g.mu.RUnlock()
			// The resource's own settings (auth type, public access block, a resource policy only
			// an in-organisation caller passes) make the exposure private even before exposure
			// annotation labels the edge (attackpath.AnnotateExposure / exposureAt read the same
			// graph.AnonymousReachOf); a blocked route still reads blocked, as there.
			if e.Kind == EdgeExposes && ev.status != VerdictBlocked {
				g.mu.RLock()
				anon, why := AnonymousReachOf(n)
				g.mu.RUnlock()
				if anon == AnonPrivate {
					if supLabel == "" {
						supLabel, supReason = VerdictPrivate, why
					}
					continue
				}
			}
			add(w, ev, nodeV)
		case e.Kind == EdgeAllowsTrafficTo:
			ctl, ok := g.Node(e.From)
			if !ok || ctl.Class != ClassNetwork {
				continue
			}
			for _, ie := range g.In(ctl.ID) {
				if ie.From != InternetNodeID || (ie.Kind != EdgeExposes && ie.Kind != EdgeAllowsTrafficTo) {
					continue
				}
				if suppressedRoute(ie) {
					suppress(ie) // the control admits only private / trusted sources
					continue
				}
				g.mu.RLock()
				cv, ctlV, w := verdictOf(ie.Attr), verdictOf(ctl.Attributes), edgeWidth(ie.Attr)
				g.mu.RUnlock()
				if cv.status == VerdictBlocked {
					routes = append(routes, cv) // the control itself is cut off
					continue
				}
				add(w, verdictOf(e.Attr), nodeV, cv, ctlV)
				break
			}
		}
	}
	if len(routes) == 0 {
		if supLabel != "" {
			// Every internet route is suppressed: the exposure label decides, not the node's
			// own (label-blind) REACH verdict.
			v.Status, v.Width, v.Reason = supLabel, supLabel, shortReason(supReason, n)
			v.Label = supLabel + " (suppressed: " + v.Reason + ")"
			return v
		}
		if nodeV.status != "" {
			routes = append(routes, nodeV)
		}
	}
	v.Routes = len(routes)
	// A network control's verdict quotes the resources it admits traffic to: name them too.
	named := []*Node{n}
	if n.Class == ClassNetwork {
		for _, e := range g.Out(nodeID) {
			if e.Kind == EdgeAllowsTrafficTo {
				if t, ok := g.Node(e.To); ok {
					named = append(named, t)
				}
			}
		}
	}
	var unknown, blocked *routeVerdict
	none := 0
	for i := range routes {
		r := &routes[i]
		switch r.status {
		case VerdictReachable:
			v.Status, v.Confidence, v.Width = VerdictReachable, r.conf, r.width
			v.Label = "internet reachable"
			if r.width != "" {
				v.Label += " (" + r.width + ")"
			}
			return v
		case VerdictUnknown:
			if unknown == nil {
				unknown = r
			}
		case VerdictBlocked:
			if blocked == nil {
				blocked = r
			}
		default:
			none++
		}
	}
	switch {
	case unknown != nil || (none > 0 && blocked != nil):
		// An unannotated route next to a blocked one is not proof the node is cut off.
		r := unknown
		if r == nil {
			r = &routeVerdict{reason: "a route has no network verdict"}
		}
		v.Status, v.Reason, v.Confidence, v.Width = VerdictUnknown, shortReason(r.reason, named...), "inferred", r.width
		v.Label = "exposure inferred (reachability unknown: " + v.Reason + ")"
	case blocked != nil:
		v.Status, v.Reason, v.Confidence = VerdictBlocked, shortReason(blocked.reason, named...), blocked.conf
		v.Label = "not exposed (blocked: " + v.Reason + ")"
	}
	return v
}
