package k8s

import (
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func ptr[T any](v T) *T { return &v }

func meta(ns, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name, CreationTimestamp: metav1.NewTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))}
}

func fixtures() []runtime.Object {
	privPod := &corev1.Pod{ObjectMeta: meta("prod", "web-7d9f-abc"), Spec: corev1.PodSpec{
		ServiceAccountName: "web", NodeName: "node-1", HostNetwork: true,
		Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25", SecurityContext: &corev1.SecurityContext{Privileged: ptr(true)}}},
		Volumes:    []corev1.Volume{{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}}}},
	}}
	privPod.Labels = map[string]string{"app": "web"}
	privPod.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-7d9f"}}
	safePod := &corev1.Pod{ObjectMeta: meta("dev", "batch"), Spec: corev1.PodSpec{
		AutomountServiceAccountToken: ptr(false),
		Containers:                   []corev1.Container{{Name: "job", Image: "busybox", SecurityContext: &corev1.SecurityContext{Privileged: ptr(false), AllowPrivilegeEscalation: ptr(false)}}},
	}}
	return []runtime.Object{
		&corev1.Namespace{ObjectMeta: meta("", "prod")},
		&corev1.Namespace{ObjectMeta: meta("", "dev")},
		&corev1.Namespace{ObjectMeta: meta("", "kube-system")},
		&networkingv1.NetworkPolicy{ObjectMeta: meta("dev", "deny-all")},
		privPod, safePod,
		&appsv1.Deployment{ObjectMeta: meta("prod", "web")},
		&corev1.ServiceAccount{ObjectMeta: meta("prod", "web")},
		&corev1.ServiceAccount{ObjectMeta: meta("dev", "default")},
		&corev1.Service{ObjectMeta: meta("prod", "web-lb"), Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{"app": "web"}, Ports: []corev1.ServicePort{{Port: 443}}}},
		&corev1.Node{ObjectMeta: meta("", "node-1")},
		&rbacv1.ClusterRole{ObjectMeta: meta("", "cluster-admin"), Rules: []rbacv1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}}}},
		&rbacv1.ClusterRole{ObjectMeta: meta("", "view"), Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: meta("", "web-admin"), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "web", Namespace: "prod"}}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: meta("", "viewers"), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "devs"}}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: meta("", "system:masters-binding"), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "system:masters"}}},
		&rbacv1.Role{ObjectMeta: meta("dev", "reader")},
		&rbacv1.RoleBinding{ObjectMeta: meta("dev", "reader-bind"), RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "reader"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "default"}}},
	}
}

func collect(t *testing.T, cs kubernetes.Interface) (core.Result, *graph.Graph) {
	t.Helper()
	c := &Collector{
		NewClient: func(core.AccountSpec) (kubernetes.Interface, string, error) { return cs, "test-cluster", nil },
		Now:       func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) },
	}
	g := graph.New()
	res, err := c.Collect(context.Background(), core.AccountSpec{Name: "test-cluster", Provider: "kubernetes"}, g)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return res, g
}

func status(res core.Result, check, resource string) model.Status {
	for _, f := range res.Findings {
		if f.CheckID == check && f.Resource.ID == resource {
			return f.Status
		}
	}
	return ""
}

func TestFindings(t *testing.T) {
	res, _ := collect(t, fake.NewSimpleClientset(fixtures()...))
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
	cases := []struct {
		check, resource string
		want            model.Status
		canonical       string
	}{
		{"core_pod_privileged", "prod/pod/web-7d9f-abc", model.Fail, "K8S_PRIVILEGED_CONTAINER"},
		{"core_pod_privileged", "dev/pod/batch", model.Pass, "K8S_PRIVILEGED_CONTAINER"},
		{"pod_host_network_access_disabled", "prod/pod/web-7d9f-abc", model.Fail, "K8S_HOST_NETWORK"},
		{"pod_host_network_access_disabled", "dev/pod/batch", model.Pass, "K8S_HOST_NETWORK"},
		{"pod_volume_host_path", "prod/pod/web-7d9f-abc", model.Fail, "K8S_HOST_PATH"},
		{"pod_container_privilege_escalation_disabled", "prod/pod/web-7d9f-abc", model.Fail, "K8S_PRIVILEGE_ESCALATION"},
		{"pod_container_privilege_escalation_disabled", "dev/pod/batch", model.Pass, "K8S_PRIVILEGE_ESCALATION"},
		{"pod_service_account_token_disabled", "prod/pod/web-7d9f-abc", model.Fail, "K8S_DEFAULT_SA_TOKEN"},
		{"pod_service_account_token_disabled", "dev/pod/batch", model.Pass, "K8S_DEFAULT_SA_TOKEN"},
		{"namespace_network_policy_defined", "namespace/prod", model.Fail, "K8S_NO_NETWORK_POLICY"},
		{"namespace_network_policy_defined", "namespace/dev", model.Pass, "K8S_NO_NETWORK_POLICY"},
		{"namespace_network_policy_defined", "namespace/kube-system", "", ""},
		{"cluster_role_binding_cluster_admin_disabled", "cluster/clusterrolebinding/web-admin", model.Fail, "K8S_CLUSTER_ADMIN_BINDING"},
		{"cluster_role_binding_cluster_admin_disabled", "cluster/clusterrolebinding/viewers", model.Pass, "K8S_CLUSTER_ADMIN_BINDING"},
		{"cluster_role_binding_cluster_admin_disabled", "cluster/clusterrolebinding/system:masters-binding", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.check+"/"+tc.resource, func(t *testing.T) {
			if got := status(res, tc.check, tc.resource); got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
			for _, f := range res.Findings {
				if f.CheckID == tc.check && f.Resource.ID == tc.resource {
					if f.CanonicalID != tc.canonical || f.Source != core.Source || f.Account != "test-cluster" || f.ID == "" {
						t.Fatalf("bad finding %+v", f)
					}
				}
			}
		})
	}
	if len(res.Runs) != 1 || res.Runs[0].Status != "ok" {
		t.Fatalf("runs = %+v", res.Runs)
	}
}

func hasEdge(g *graph.Graph, from, to, kind string) bool {
	for _, e := range g.Out(from) {
		if e.To == to && e.Kind == kind {
			return true
		}
	}
	return false
}

func TestGraph(t *testing.T) {
	_, g := collect(t, fake.NewSimpleClientset(fixtures()...))
	pod := "prod/pod/web-7d9f-abc"
	edges := []struct{ from, to, kind string }{
		{core.AccountNodeID("kubernetes", "test-cluster"), pod, graph.EdgeContains},
		{pod, "namespace/prod", graph.EdgeMemberOf},
		{pod, "prod/serviceaccount/web", graph.EdgeRunsAs},
		{pod, "image/nginx:1.25", graph.EdgeRunsOn},
		{pod, "cluster/node/node-1", graph.EdgeRunsOn},
		{"prod/serviceaccount/web", "cluster/clusterrole/cluster-admin", graph.EdgeBoundTo},
		{"cluster/clusterrolebinding/web-admin", "cluster/clusterrole/cluster-admin", graph.EdgeBoundTo},
		{"dev/serviceaccount/default", "dev/role/reader", graph.EdgeBoundTo},
		{"cluster/group/devs", "cluster/clusterrole/view", graph.EdgeBoundTo},
		{graph.InternetNodeID, pod, graph.EdgeExposes},
		{"prod/deployment/web", pod, graph.EdgeContains},
	}
	for _, e := range edges {
		if !hasEdge(g, e.from, e.to, e.kind) {
			t.Errorf("missing edge %s -[%s]-> %s", e.from, e.kind, e.to)
		}
	}
	if hasEdge(g, graph.InternetNodeID, "dev/pod/batch", graph.EdgeExposes) {
		t.Errorf("unexpected exposure of dev/pod/batch")
	}
	n, ok := g.Node(pod)
	if !ok {
		t.Fatal("pod node missing")
	}
	if n.Type != "k8s_pod" || n.Criticality != "production" || n.Account != "test-cluster" || n.ModifiedAt == "" {
		t.Errorf("pod node = %+v", n)
	}
	if !n.HasWeakness("PRIVILEGED_CONTAINER") || len(n.FindingIDs) == 0 {
		t.Errorf("pod node missing weaknesses: %v", n.Weaknesses)
	}
	if n.Attributes["container"] != "app" || n.Attributes["service_account"] != "web" || n.Attributes["privileged"] != true {
		t.Errorf("pod attributes = %v", n.Attributes)
	}
	if ns, _ := g.Node("namespace/prod"); ns == nil || ns.Type != "k8s_namespace" {
		t.Errorf("namespace node = %+v", ns)
	}
}

func TestPartialFailure(t *testing.T) {
	cs := fake.NewSimpleClientset(fixtures()...)
	cs.PrependReactor("list", "networkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})
	res, g := collect(t, cs)
	if len(res.Errors) != 1 {
		t.Fatalf("errors = %v", res.Errors)
	}
	if res.Runs[0].Status != "partial" {
		t.Fatalf("run status = %q", res.Runs[0].Status)
	}
	if status(res, "core_pod_privileged", "prod/pod/web-7d9f-abc") != model.Fail {
		t.Fatal("pod checks should still run")
	}
	if status(res, "namespace_network_policy_defined", "namespace/prod") != "" {
		t.Fatal("network policy check must be skipped when the list failed")
	}
	if _, ok := g.Node("namespace/prod"); !ok {
		t.Fatal("namespaces should still be in the graph")
	}
}

func TestClientError(t *testing.T) {
	c := &Collector{NewClient: func(core.AccountSpec) (kubernetes.Interface, string, error) {
		return nil, "", errors.New("no kubeconfig")
	}}
	res, err := c.Collect(context.Background(), core.AccountSpec{KubeContext: "x"}, graph.New())
	if err == nil || len(res.Runs) != 1 || res.Runs[0].Status != "failed" {
		t.Fatalf("err=%v runs=%+v", err, res.Runs)
	}
}

func TestPagination(t *testing.T) {
	calls := 0
	got, err := listAll(context.Background(), func(_ context.Context, o metav1.ListOptions) ([]int, string, error) {
		calls++
		if o.Limit != pageSize {
			t.Fatalf("limit = %d", o.Limit)
		}
		switch o.Continue {
		case "":
			return []int{1, 2}, "tok", nil
		case "tok":
			return []int{3}, "", nil
		}
		return nil, "", errors.New("bad token")
	})
	if err != nil || len(got) != 3 || calls != 2 {
		t.Fatalf("got=%v calls=%d err=%v", got, calls, err)
	}
}

func TestHelpers(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"sa subject default ns", subjectID(rbacv1.Subject{Kind: "ServiceAccount", Name: "a"}, "ns1"), "ns1/serviceaccount/a"},
		{"sa subject no ns", subjectID(rbacv1.Subject{Kind: "ServiceAccount", Name: "a"}, ""), ""},
		{"user subject", subjectID(rbacv1.Subject{Kind: "User", Name: "bob"}, ""), "cluster/user/bob"},
		{"role ref", roleRefID("ns", rbacv1.RoleRef{Kind: "Role", Name: "r"}), "ns/role/r"},
		{"cluster role ref", roleRefID("ns", rbacv1.RoleRef{Kind: "ClusterRole", Name: "r"}), "cluster/clusterrole/r"},
		{"sa default", saName(""), "default"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, tc.got, tc.want)
		}
	}
	if !hasWildcard([]rbacv1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"*"}}}) || hasWildcard([]rbacv1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"*"}}}) {
		t.Error("hasWildcard")
	}
	if GraphTypeCheck := graph.GuessType(PodID("a", "b")); GraphTypeCheck != "k8s_pod" {
		t.Errorf("GuessType(pod) = %q", GraphTypeCheck)
	}
}
