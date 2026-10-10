package remediation

// The Kubernetes LoadBalancer exposure fix (K8S_SERVICE_PUBLIC_LB) changes the Service that
// selects the exposed pod, never the pod (W7-ENGINE r5 #7: the W6 fix ran `kubectl patch … --
// pod report-worker-0` with a Service patch). The Service is resolved, in order, from:
//
//	graph      a k8s_service node joined to the pod by a bound_to / runs_on / exposes / selects /
//	           routes_to / attached_to edge (either direction)
//	via        the internet → pod exposes edge the live collector writes ("via": "<ns>/service/<name>")
//	attribute  the pod's exposed_by ("service/<ns>/<name> (type LoadBalancer, …)" or "<ns>/service/<name>")
//
// WithK8sService records the result on a copy of the finding (service_name, service_namespace,
// service_resolved_from); Generate also reads exposed_by itself, so callers without a graph get
// the attribute-resolved Service. Unresolved, the fix lists the LoadBalancer Services of the
// namespace and patches "$SERVICE".

import (
	"regexp"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// serviceTargetedCanonical: canonical ids whose Kubernetes fix patches the selecting Service.
var serviceTargetedCanonical = map[string]bool{"K8S_SERVICE_PUBLIC_LB": true}

var (
	svcPrefixRe = regexp.MustCompile(`(?:^|\s)service/([a-z0-9][a-z0-9.-]*)/([a-z0-9][a-z0-9.-]*)`)
	svcInfixRe  = regexp.MustCompile(`(?:^|\s)([a-z0-9][a-z0-9.-]*)/service/([a-z0-9][a-z0-9.-]*)`)
)

// parseServiceRef reads "service/<ns>/<name>" or "<ns>/service/<name>" (DNS-1123 names only).
func parseServiceRef(s string) (ns, name string, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if m := svcPrefixRe.FindStringSubmatch(s); m != nil {
		return m[1], m[2], true
	}
	if m := svcInfixRe.FindStringSubmatch(s); m != nil {
		return m[1], m[2], true
	}
	return "", "", false
}

var serviceEdgeKinds = map[string]bool{graph.EdgeBoundTo: true, graph.EdgeRunsOn: true, graph.EdgeExposes: true, "selects": true, "routes_to": true, graph.EdgeAttachedTo: true}

// resolveK8sService finds the Service exposing the finding's pod; from names the source.
func resolveK8sService(f model.Finding, g *graph.Graph) (ns, name, from string) {
	pod := f.Resource.ID
	if g != nil {
		var cands [][2]string
		consider := func(id string) {
			n, ok := g.Node(id)
			if !ok || n.Type != "k8s_service" {
				return
			}
			sns, _ := n.Attributes["namespace"].(string)
			sname := n.Name
			if pns, pname, ok := parseServiceRef(n.ID); ok {
				sns = firstNonEmptyStr(sns, pns)
				sname = firstNonEmptyStr(sname, pname)
			}
			if sname != "" {
				cands = append(cands, [2]string{sns, sname})
			}
		}
		for _, e := range g.Out(pod) {
			if serviceEdgeKinds[e.Kind] {
				consider(e.To)
			}
		}
		for _, e := range g.In(pod) {
			if serviceEdgeKinds[e.Kind] {
				consider(e.From)
			}
		}
		if len(cands) > 0 {
			best := cands[0]
			for _, c := range cands[1:] {
				if c[0]+"/"+c[1] < best[0]+"/"+best[1] {
					best = c
				}
			}
			return firstNonEmptyStr(best[0], podNamespace(f)), best[1], "graph"
		}
		for _, e := range g.In(pod) {
			if e.From != graph.InternetNodeID || e.Kind != graph.EdgeExposes {
				continue
			}
			if via, _ := e.Attr["via"].(string); via != "" {
				if sns, sname, ok := parseServiceRef(via); ok {
					return sns, sname, "via"
				}
			}
		}
	}
	if eb, _ := f.Resource.Attributes["exposed_by"].(string); eb != "" {
		if sns, sname, ok := parseServiceRef(eb); ok {
			return sns, sname, "attribute"
		}
	}
	return "", "", ""
}

func podNamespace(f model.Finding) string {
	if ns, _ := f.Resource.Attributes["namespace"].(string); ns != "" {
		return ns
	}
	if parts := strings.Split(f.Resource.ID, "/"); len(parts) == 3 {
		return parts[0]
	}
	return ""
}

// WithK8sService returns f with the Service that exposes its pod recorded (service_name,
// service_namespace, service_resolved_from) when the finding's fix targets that Service and the
// graph resolves it; otherwise f unchanged. f is not mutated.
func WithK8sService(f model.Finding, g *graph.Graph) model.Finding {
	if !serviceTargetedCanonical[f.CanonicalID] {
		return f
	}
	ns, name, from := resolveK8sService(f, g)
	if name == "" {
		return f
	}
	attrs := make(map[string]any, len(f.Resource.Attributes)+3)
	for k, v := range f.Resource.Attributes {
		attrs[k] = v
	}
	attrs["service_name"], attrs["service_namespace"], attrs["service_resolved_from"] = name, firstNonEmptyStr(ns, podNamespace(f)), from
	f.Resource.Attributes = attrs
	return f
}

// serviceOf is the Service a service-targeted fix patches ("" when unresolved).
func serviceOf(f model.Finding) (ns, name, from string) {
	if n, _ := f.Resource.Attributes["service_name"].(string); n != "" {
		sns, _ := f.Resource.Attributes["service_namespace"].(string)
		src, _ := f.Resource.Attributes["service_resolved_from"].(string)
		return firstNonEmptyStr(sns, podNamespace(f)), n, src
	}
	return resolveK8sService(f, nil)
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// TargetsK8sService reports a canonical id whose Kubernetes fix patches the Service selecting
// the finding's pod (callers resolve it on the graph with WithK8sService).
func TargetsK8sService(canonicalID string) bool { return serviceTargetedCanonical[canonicalID] }
