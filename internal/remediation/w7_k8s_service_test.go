package remediation

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W7-ENGINE item 5 (r5 #7): the LoadBalancer exposure fix patches the Service that selects the
// pod, never the pod. The Service is resolved from the graph (a k8s_service node joined to the pod
// by bound_to / runs_on / exposes / selects edges, or the internet edge's "via"), else from the
// pod's exposed_by attribute; unresolved, the fix lists the LoadBalancer Services to choose from
// and patches "$SERVICE", still never the pod.
func lbFinding(attrs map[string]any) model.Finding {
	f := model.Finding{ID: "lab-W49", Source: "nimbus-lab", CheckID: "service_type_loadbalancer_public", Provider: "kubernetes", Severity: model.High, Status: model.Fail,
		Account: "nimbus-lab-eks", Resource: model.Resource{ID: "analytics/pod/report-worker-0", Name: "report-worker-0", Type: "k8s_pod", Attributes: attrs}}
	catalog.Default().Enrich(&f)
	return f
}

func patchesPod(fix *Fix) bool {
	for _, s := range append([]string{fix.Apply}, fix.Steps...) {
		if strings.Contains(s, "-- pod ") {
			return true
		}
	}
	return false
}

func TestK8sLoadBalancerFixPatchesTheService(t *testing.T) {
	// 1. From the pod's exposed_by attribute (the lab, W49).
	f := lbFinding(map[string]any{"namespace": "analytics", "exposed_by": "service/analytics/report-worker (type LoadBalancer, 0.0.0.0/0)"})
	fix, err := Generate(f, Kubernetes)
	if err != nil || fix.Generic {
		t.Fatalf("generate: %v generic=%v", err, fix != nil && fix.Generic)
	}
	if patchesPod(fix) || !strings.Contains(fix.Apply, "--namespace=analytics") || !strings.HasSuffix(fix.Apply, "-- service report-worker") {
		t.Errorf("apply %q: want the Service report-worker in analytics, never the pod", fix.Apply)
	}
	if !strings.Contains(fix.Content, "Service report-worker") || !strings.Contains(fix.Metadata.Rollback, "service report-worker") {
		t.Errorf("content / rollback must name the Service:\n%s\nrollback: %s", fix.Content, fix.Metadata.Rollback)
	}
	if !strings.Contains(fix.FileName, "report_worker") || strings.Contains(fix.FileName, "report_worker_0") {
		t.Errorf("file name %q should be the Service's", fix.FileName)
	}

	// 2. From the graph: a k8s_service node bound to the pod wins over the attribute.
	g := graph.New()
	g.AddNode(&graph.Node{ID: "analytics/pod/report-worker-0", Type: "k8s_pod", Name: "report-worker-0", Provider: "kubernetes"})
	g.AddNode(&graph.Node{ID: "analytics/service/report-api", Type: "k8s_service", Name: "report-api", Provider: "kubernetes", Attributes: map[string]any{"namespace": "analytics", "type": "LoadBalancer"}})
	g.AddEdge("analytics/service/report-api", "analytics/pod/report-worker-0", graph.EdgeBoundTo, nil)
	gf := WithK8sService(f, g)
	fix, _ = Generate(gf, Kubernetes)
	if !strings.HasSuffix(fix.Apply, "-- service report-api") {
		t.Errorf("graph-resolved apply %q, want service report-api", fix.Apply)
	}
	if gf.Resource.Attributes["service_resolved_from"] != "graph" || f.Resource.Attributes["service_name"] != nil {
		t.Errorf("resolution source %v (input must not be mutated: %v)", gf.Resource.Attributes["service_resolved_from"], f.Resource.Attributes["service_name"])
	}

	// 3. From the live collector's internet edge (via <ns>/service/<name>).
	g2 := graph.New()
	g2.AddNode(&graph.Node{ID: "analytics/pod/report-worker-0", Type: "k8s_pod", Name: "report-worker-0"})
	g2.AddEdge(graph.InternetNodeID, "analytics/pod/report-worker-0", graph.EdgeExposes, map[string]any{"via": "analytics/service/report-lb", "service_type": "LoadBalancer"})
	fix, _ = Generate(WithK8sService(lbFinding(map[string]any{"namespace": "analytics"}), g2), Kubernetes)
	if !strings.HasSuffix(fix.Apply, "-- service report-lb") {
		t.Errorf("via-resolved apply %q, want service report-lb", fix.Apply)
	}

	// 4. Unresolved: list the Services, patch "$SERVICE"; never the pod.
	fix, _ = Generate(lbFinding(map[string]any{"namespace": "analytics"}), Kubernetes)
	if patchesPod(fix) || !strings.Contains(fix.Apply, "--dry-run=server") || !strings.Contains(fix.Apply, `-- service "$SERVICE"`) || !strings.Contains(fix.Apply, "kubectl get services") {
		t.Errorf("unresolved: apply %q steps %q", fix.Apply, fix.Steps)
	}
}
