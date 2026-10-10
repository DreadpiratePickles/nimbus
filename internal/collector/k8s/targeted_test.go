package k8s

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W7-VERIFY (r5 #6): Kubernetes Services, Pods, ClusterRoleBindings and ServiceAccounts are
// re-read through the same analyze() as a full scan (namespaced lists for the namespaces the
// Issue touches; cluster-scoped RBAC only when an RBAC object is targeted); a forbidden list is
// inconclusive, never a deletion.

var _ core.Targeted = (*Collector)(nil)

const (
	tPod = "prod/pod/web-7d9f-abc"
	tSvc = "prod/service/web-lb"
	tCRB = "cluster/clusterrolebinding/web-admin"
	tSA  = "prod/serviceaccount/web"
)

func k8sTarget(t *testing.T, cs kubernetes.Interface, ids ...string) *core.TargetResult {
	t.Helper()
	c := &Collector{NewClient: func(core.AccountSpec) (kubernetes.Interface, string, error) { return cs, "test-cluster", nil },
		Now: func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }}
	r, err := c.Target(context.Background(), core.AccountSpec{Name: "test-cluster", Provider: "kubernetes"}, ids)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	return r
}

func forbid(cs *fake.Clientset, verb, resource string) {
	cs.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: resource}, "", nil)
	})
}

func findingStatus(fs []model.Finding, check, id string) (model.Status, bool) {
	for _, f := range fs {
		if f.CheckID == check && f.Resource.ID == id {
			return f.Status, true
		}
	}
	return "", false
}

func TestK8sTargetServiceExposureThenFixed(t *testing.T) {
	cs := fake.NewSimpleClientset(fixtures()...)
	forbid(cs, "list", "clusterrolebindings") // a Service read never needs cluster RBAC
	r := k8sTarget(t, cs, tSvc)
	if r.Inconclusive() {
		t.Fatalf("service read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if len(r.Observed) != 1 || r.Observed[0] != tSvc {
		t.Fatalf("observed = %v", r.Observed)
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, tPod, graph.EdgeExposes) {
		t.Fatalf("the LoadBalancer's pod is not exposed in the fragment")
	}
	if _, ok := r.Graph.Node("dev/pod/batch"); ok {
		t.Errorf("a pod in another namespace is in the fragment")
	}
	// The owner makes the Service internal.
	svc, _ := cs.CoreV1().Services("prod").Get(context.Background(), "web-lb", metav1.GetOptions{})
	svc.Spec.Type = corev1.ServiceTypeClusterIP
	if _, err := cs.CoreV1().Services("prod").Update(context.Background(), svc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	r = k8sTarget(t, cs, tSvc)
	if hasEdge(r.Graph, graph.InternetNodeID, tPod, graph.EdgeExposes) {
		t.Errorf("pod still exposed after the Service became ClusterIP")
	}
	if _, ok := r.Graph.Node(tPod); !ok {
		t.Errorf("the selected pod must stay in the fragment so its stored exposure is replaced")
	}
	if r = k8sTarget(t, cs, "prod/service/deleted"); len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted service: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
	forbid(cs, "list", "services")
	if r = k8sTarget(t, cs, tSvc); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("forbidden service list must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestK8sTargetPodSeesEveryServiceInItsNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset(fixtures()...)
	r := k8sTarget(t, cs, tPod)
	if r.Inconclusive() {
		t.Fatalf("pod read inconclusive: %v", r.Errors)
	}
	if st, ok := findingStatus(r.Findings, "core_pod_privileged", tPod); !ok || st != model.Fail {
		t.Fatalf("privileged pod = %q (%v)", st, ok)
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, tPod, graph.EdgeExposes) || !hasEdge(r.Graph, tPod, tSA, graph.EdgeRunsAs) {
		t.Errorf("pod fragment lacks its exposure or its service account")
	}
	if _, ok := r.Graph.Node("namespace/prod"); !ok {
		t.Errorf("pod fragment lacks its namespace (one hop)")
	}
	if st, ok := findingStatus(r.Findings, "namespace_network_policy_defined", "namespace/prod"); !ok || st != model.Fail {
		t.Errorf("the namespace is re-read, not a placeholder: %q (%v)", st, ok)
	}
	if err := cs.CoreV1().Services("prod").Delete(context.Background(), "web-lb", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if r = k8sTarget(t, cs, tPod); hasEdge(r.Graph, graph.InternetNodeID, tPod, graph.EdgeExposes) {
		t.Errorf("pod still exposed after its LoadBalancer was deleted")
	}
	if r = k8sTarget(t, cs, "prod/pod/gone"); len(r.Missing) != 1 {
		t.Errorf("deleted pod: missing %v", r.Missing)
	}
}

func TestK8sTargetClusterRoleBindingThenRemoved(t *testing.T) {
	cs := fake.NewSimpleClientset(fixtures()...)
	forbid(cs, "list", "pods") // an RBAC read never lists pods
	r := k8sTarget(t, cs, tCRB)
	if r.Inconclusive() {
		t.Fatalf("CRB read inconclusive: %v", r.Errors)
	}
	if st, ok := findingStatus(r.Findings, "cluster_role_binding_cluster_admin_disabled", tCRB); !ok || st != model.Fail {
		t.Fatalf("cluster-admin binding = %q (%v)", st, ok)
	}
	if !hasEdge(r.Graph, tSA, ClusterRoleID("cluster-admin"), graph.EdgeBoundTo) {
		t.Errorf("fragment lacks the subject's binding to cluster-admin")
	}
	for _, f := range r.Findings {
		if f.Resource.ID == "cluster/clusterrolebinding/viewers" {
			t.Errorf("an unrelated binding is in the read")
		}
	}
	// The owner rebinds the subject to view.
	crb, _ := cs.RbacV1().ClusterRoleBindings().Get(context.Background(), "web-admin", metav1.GetOptions{})
	crb.RoleRef = rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"}
	if _, err := cs.RbacV1().ClusterRoleBindings().Update(context.Background(), crb, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	r = k8sTarget(t, cs, tCRB)
	if st, _ := findingStatus(r.Findings, "cluster_role_binding_cluster_admin_disabled", tCRB); st != model.Pass {
		t.Fatalf("rebound to view = %q, want PASS", st)
	}
	if err := cs.RbacV1().ClusterRoleBindings().Delete(context.Background(), "web-admin", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if r = k8sTarget(t, cs, tCRB); len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted binding: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
	forbid(cs, "list", "clusterrolebindings")
	if r = k8sTarget(t, cs, tCRB); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("forbidden CRB list must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestK8sTargetServiceAccountBindings(t *testing.T) {
	cs := fake.NewSimpleClientset(fixtures()...)
	r := k8sTarget(t, cs, tSA)
	if r.Inconclusive() {
		t.Fatalf("SA read inconclusive: %v", r.Errors)
	}
	if !hasEdge(r.Graph, tSA, ClusterRoleID("cluster-admin"), graph.EdgeBoundTo) {
		t.Errorf("SA fragment lacks its cluster-admin binding")
	}
	if !hasEdge(r.Graph, tPod, tSA, graph.EdgeRunsAs) {
		t.Errorf("SA fragment lacks the pod that runs as it (one hop)")
	}
	if err := cs.CoreV1().ServiceAccounts("prod").Delete(context.Background(), "web", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if r = k8sTarget(t, cs, tSA); len(r.Missing) != 1 {
		t.Errorf("deleted SA: missing %v", r.Missing)
	}
	forbid(cs, "list", "serviceaccounts")
	if r = k8sTarget(t, cs, tSA); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("forbidden SA list must be inconclusive: missing %v", r.Missing)
	}
}

func TestK8sTargetUnsupportedAndReader(t *testing.T) {
	cs := fake.NewSimpleClientset(fixtures()...)
	img := "image/nginx:1.25"
	r := k8sTarget(t, cs, img, tSA)
	if len(r.Unsupported) != 1 || r.Unsupported[0] != img || !r.Inconclusive() {
		t.Errorf("images are not targeted: unsupported %v", r.Unsupported)
	}
	for id, want := range map[string]string{tPod: "kubernetes:pod", tSvc: "kubernetes:service", tCRB: "kubernetes:clusterrolebinding", tSA: "kubernetes:serviceaccount",
		img: "", "namespace/prod": "", "prod/deployment/web": "", "a/b/pod/c": ""} {
		_, ok := parseK8sTarget(id)
		if got := core.TargetReader("kubernetes", id); got != want || (got != "") != ok {
			t.Errorf("%s: reader %q (parser %v), want %q", id, got, ok, want)
		}
	}
}
