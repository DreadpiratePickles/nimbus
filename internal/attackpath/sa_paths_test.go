package attackpath

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// k8sSAGraph: internet → exposed pod → runs_as SA → ClusterRoleBinding → cluster-admin.
// Classes are left empty so graph.ClassFor decides, as it does for collector output.
func k8sSAGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "k8s/pod/web/api-0", Type: "k8s_pod", Name: "api-0", Provider: "kubernetes", Account: "prod-eks",
		Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "SERVICE_ACCOUNT_TOKEN"}, FindingIDs: []string{"f-pod"}})
	g.AddNode(&graph.Node{ID: "k8s/serviceaccount/web/api", Type: "k8s_service_account", Name: "api", Provider: "kubernetes", Account: "prod-eks"})
	g.AddNode(&graph.Node{ID: "k8s/clusterrolebinding/api-admin", Type: "k8s_cluster_role_binding", Name: "api-admin", Provider: "kubernetes", Account: "prod-eks",
		Weaknesses: []string{"CLUSTER_ADMIN"}, FindingIDs: []string{"f-crb"}})
	g.AddNode(&graph.Node{ID: "k8s/clusterrole/cluster-admin", Type: "k8s_cluster_role", Name: "cluster-admin", Provider: "kubernetes", Account: "prod-eks",
		Attributes: map[string]any{"admin": true}})
	g.AddEdge(graph.InternetNodeID, "k8s/pod/web/api-0", graph.EdgeExposes, map[string]any{"via": "LoadBalancer service api", "ports": "443"})
	g.AddEdge("k8s/pod/web/api-0", "k8s/serviceaccount/web/api", graph.EdgeRunsAs, nil)
	g.AddEdge("k8s/serviceaccount/web/api", "k8s/clusterrole/cluster-admin", graph.EdgeBoundTo, map[string]any{"binding": "api-admin"})
	g.AddEdge("k8s/serviceaccount/web/api", "k8s/clusterrolebinding/api-admin", graph.EdgeMemberOf, map[string]any{"binding": "api-admin"})
	g.AddEdge("k8s/clusterrolebinding/api-admin", "k8s/clusterrole/cluster-admin", graph.EdgeBoundTo, map[string]any{"binding": "api-admin"})
	return g
}

// gcpSAGraph: internet → GCE instance → runs_as default compute SA → roles/editor on the project.
func gcpSAGraph() *graph.Graph {
	g := graph.New()
	inst := "//compute.googleapis.com/projects/acme/zones/us-central1-a/instances/web-1"
	sa := "//iam.googleapis.com/projects/acme/serviceAccounts/123-compute@developer.gserviceaccount.com"
	editor := "//cloudresourcemanager.googleapis.com/projects/acme/roles/editor"
	g.AddNode(&graph.Node{ID: inst, Type: "gcp_compute_instance", Name: "web-1", Provider: "gcp", Account: "acme",
		Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"}, FindingIDs: []string{"f-fw"}})
	g.AddNode(&graph.Node{ID: sa, Type: "gcp_service_account", Name: "123-compute@developer.gserviceaccount.com", Provider: "gcp", Account: "acme",
		Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}, FindingIDs: []string{"f-default-sa"}})
	g.AddNode(&graph.Node{ID: editor, Type: "gcp_iam_role", Name: "roles/editor", Provider: "gcp", Account: "acme",
		Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}})
	g.AddEdge(graph.InternetNodeID, inst, graph.EdgeExposes, map[string]any{"via": "default-allow-ssh", "ports": "tcp:22", "public_ip": "34.1.2.3"})
	g.AddEdge(inst, sa, graph.EdgeRunsAs, map[string]any{"scopes": []string{"https://www.googleapis.com/auth/cloud-platform"}})
	g.AddEdge(sa, editor, graph.EdgeHasPolicy, map[string]any{"role": "roles/editor", "member": "serviceAccount:123-compute@developer.gserviceaccount.com"})
	return g
}

func pathEndingAt(an *Analysis, target string) bool {
	for _, p := range an.Paths {
		if len(p.Steps) > 1 && p.Steps[len(p.Steps)-1].Resource == target {
			return true
		}
	}
	return false
}

func TestK8sServiceAccountToClusterAdminPath(t *testing.T) {
	g := k8sSAGraph()
	if n, _ := g.Node("k8s/serviceaccount/web/api"); n.Class != graph.ClassIdentity {
		t.Fatalf("k8s service account class = %q, want identity", n.Class)
	}
	an := Traverse(g, DefaultTraversalOptions())
	if !pathEndingAt(an, "k8s/clusterrole/cluster-admin") {
		t.Fatalf("no pod → SA → cluster-admin path: %+v", an.Paths)
	}
}

func TestGCPDefaultServiceAccountToEditorPath(t *testing.T) {
	g := gcpSAGraph()
	sa := "//iam.googleapis.com/projects/acme/serviceAccounts/123-compute@developer.gserviceaccount.com"
	if n, _ := g.Node(sa); n.Class != graph.ClassIdentity {
		t.Fatalf("gcp service account class = %q, want identity", n.Class)
	}
	an := Traverse(g, DefaultTraversalOptions())
	if !pathEndingAt(an, "//cloudresourcemanager.googleapis.com/projects/acme/roles/editor") {
		t.Fatalf("no GCE → default SA → roles/editor path: %+v", an.Paths)
	}
}
