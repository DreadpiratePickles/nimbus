package k8s

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Targeted re-collection (plan v3 RM4, W7-VERIFY r5 #6): `cloud-posture verify` re-reads the
// Services, Pods, ClusterRoleBindings and ServiceAccounts of one Issue through the same analyze()
// as Collect and returns the findings and graph fragment of the anchors plus their one-hop
// neighbours.
//
// A Pod or Service needs its namespace (the Namespace object, its NetworkPolicies, and every Pod,
// Service, ServiceAccount, Deployment, Role and RoleBinding in it: a pod's exposure depends on
// every Service of the namespace) and the Nodes its pods run on; a Service's anchors are the pods
// its selector matches, so their stored exposure is replaced by the fresh verdict. A
// ClusterRoleBinding needs the cluster RBAC (bindings and cluster roles) and the ServiceAccounts
// of its subjects' namespaces; a ServiceAccount its namespace plus the cluster RBAC. Every list is
// namespaced except the RBAC ones. A forbidden or failed list is a partial error: the read is
// inconclusive, never a confirmation or a deletion.

// ServiceID is the id a targeted read accepts for a Service ("<ns>/service/<name>", the `via`
// of the exposure edges a Service creates). Services are not graph nodes: the pods they select
// carry the exposure.
func ServiceID(ns, name string) string { return ns + "/service/" + name }

type k8sRef struct{ id, kind, ns, name string } // kind: pod | service | serviceaccount | clusterrolebinding

// parseK8sTarget classifies a Kubernetes graph id; ok=false for a type this collector cannot
// target yet.
func parseK8sTarget(id string) (k8sRef, bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return k8sRef{}, false
	}
	switch {
	case parts[0] == "cluster" && parts[1] == "clusterrolebinding":
		return k8sRef{id: id, kind: "clusterrolebinding", name: parts[2]}, true
	case parts[0] == "cluster":
		return k8sRef{}, false
	case parts[1] == "pod", parts[1] == "service", parts[1] == "serviceaccount":
		return k8sRef{id: id, kind: parts[1], ns: parts[0], name: parts[2]}, true
	}
	return k8sRef{}, false
}

// Target implements core.Targeted. Only client construction failures are fatal.
func (c *Collector) Target(ctx context.Context, spec core.AccountSpec, ids []string) (*core.TargetResult, error) {
	out := &core.TargetResult{Graph: graph.New()}
	var refs []k8sRef
	for _, id := range ids {
		if r, ok := parseK8sTarget(id); ok {
			refs = append(refs, r)
		} else {
			out.Unsupported = append(out.Unsupported, id)
		}
	}
	if len(refs) == 0 {
		return out, nil
	}
	newClient := c.NewClient
	if newClient == nil {
		newClient = DefaultClient
	}
	cs, cluster, err := newClient(spec)
	if err != nil {
		return nil, fmt.Errorf("kubernetes %s: %w", spec.Label(), err)
	}
	if cluster == "" {
		cluster = spec.Label()
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	acc := &core.Acc{}
	t := &targetRead{cs: cs, acc: acc, inv: &inventory{failed: map[string]bool{}}, listed: map[string]bool{}}
	nsFull, saNS := map[string]bool{}, map[string]bool{}
	needRBAC := false
	for _, r := range refs {
		switch r.kind {
		case "pod", "service":
			nsFull[r.ns] = true
		case "serviceaccount":
			nsFull[r.ns], needRBAC = true, true
		case "clusterrolebinding":
			needRBAC = true
		}
	}
	if needRBAC {
		t.clusterRBAC(ctx)
		// The subjects of the requested bindings are one hop away: read their namespaces' SAs.
		for _, r := range refs {
			if r.kind != "clusterrolebinding" {
				continue
			}
			for _, crb := range t.inv.clusterRoleBindings {
				if crb.Name != r.name {
					continue
				}
				for _, s := range crb.Subjects {
					if s.Kind == rbacv1.ServiceAccountKind && s.Namespace != "" && !nsFull[s.Namespace] {
						saNS[s.Namespace] = true
					}
				}
			}
		}
	}
	for _, ns := range sortedKeys(nsFull) {
		t.namespace(ctx, ns)
	}
	for _, ns := range sortedKeys(saNS) {
		t.serviceAccounts(ctx, ns)
	}
	t.nodes(ctx)

	g := graph.New()
	analyze(t.inv, spec, cluster, now(), g, acc)

	var anchors []string
	for _, r := range refs {
		var listedOK, present bool
		switch r.kind {
		case "pod":
			listedOK = t.listed["pods/"+r.ns]
			present = t.hasPod(r.ns, r.name)
			if present {
				anchors = append(anchors, PodID(r.ns, r.name))
			}
		case "service":
			listedOK = t.listed["services/"+r.ns] && t.listed["pods/"+r.ns]
			for _, svc := range t.inv.services {
				if svc.Namespace != r.ns || svc.Name != r.name {
					continue
				}
				present = true
				if len(svc.Spec.Selector) == 0 {
					continue
				}
				sel := labels.SelectorFromSet(svc.Spec.Selector)
				for _, p := range t.inv.pods {
					if p.Namespace == r.ns && sel.Matches(labels.Set(p.Labels)) {
						anchors = append(anchors, PodID(p.Namespace, p.Name))
					}
				}
			}
		case "serviceaccount":
			listedOK = t.listed["serviceaccounts/"+r.ns]
			for _, sa := range t.inv.serviceAccounts {
				present = present || (sa.Namespace == r.ns && sa.Name == r.name)
			}
			if present {
				anchors = append(anchors, ServiceAccountID(r.ns, r.name))
			}
		case "clusterrolebinding":
			listedOK = t.listed["clusterrolebindings"]
			for _, crb := range t.inv.clusterRoleBindings {
				present = present || crb.Name == r.name
			}
			if present {
				anchors = append(anchors, ClusterRoleBindingID(r.name))
			}
		}
		switch {
		case !listedOK:
			// a failed list proves nothing either way (the error makes the read inconclusive)
		case present:
			out.Observed = append(out.Observed, r.id)
		default:
			out.Missing = append(out.Missing, r.id)
		}
	}
	keep := core.OneHop(g, anchors)
	res := acc.Result()
	for _, f := range res.Findings {
		if keep[f.Resource.ID] {
			out.Findings = append(out.Findings, f)
		}
	}
	out.Graph.Merge(core.Subgraph(g, keep))
	for _, e := range res.Errors {
		out.Errors = append(out.Errors, fmt.Errorf("kubernetes %s: %w", cluster, e))
	}
	out.Warnings = append(out.Warnings, res.Warnings...)
	return out, nil
}

type targetRead struct {
	cs     kubernetes.Interface
	acc    *core.Acc
	inv    *inventory
	listed map[string]bool // "<resource>/<ns>" or cluster-scoped "<resource>" -> list succeeded
}

func (t *targetRead) fail(name string, err error) bool {
	if err == nil {
		t.listed[name] = true
		return false
	}
	t.inv.failed[strings.SplitN(name, "/", 2)[0]] = true
	t.acc.Error(name, err)
	return true
}

func (t *targetRead) hasPod(ns, name string) bool {
	for _, p := range t.inv.pods {
		if p.Namespace == ns && p.Name == name {
			return true
		}
	}
	return false
}

func (t *targetRead) clusterRBAC(ctx context.Context) {
	crbs, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.ClusterRoleBinding, string, error) {
		l, err := t.cs.RbacV1().ClusterRoleBindings().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if !t.fail("clusterrolebindings", err) {
		t.inv.clusterRoleBindings = crbs
	}
	crs, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.ClusterRole, string, error) {
		l, err := t.cs.RbacV1().ClusterRoles().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if !t.fail("clusterroles", err) {
		t.inv.clusterRoles = crs
	}
}

func (t *targetRead) serviceAccounts(ctx context.Context, ns string) {
	sas, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.ServiceAccount, string, error) {
		l, err := t.cs.CoreV1().ServiceAccounts(ns).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if !t.fail("serviceaccounts/"+ns, err) {
		t.inv.serviceAccounts = append(t.inv.serviceAccounts, sas...)
	}
}

// namespace reads one namespace the Issue touches and everything in it a pod's verdict and
// one-hop neighbourhood depend on.
func (t *targetRead) namespace(ctx context.Context, ns string) {
	core1 := t.cs.CoreV1()
	if obj, err := core1.Namespaces().Get(ctx, ns, metav1.GetOptions{}); err == nil {
		t.inv.namespaces = append(t.inv.namespaces, *obj)
		t.listed["namespaces/"+ns] = true
	} else if !apierrors.IsNotFound(err) {
		t.fail("namespaces/"+ns, err)
	}
	pods, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Pod, string, error) {
		l, err := core1.Pods(ns).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if !t.fail("pods/"+ns, err) {
		t.inv.pods = append(t.inv.pods, pods...)
	}
	svcs, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Service, string, error) {
		l, err := core1.Services(ns).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if !t.fail("services/"+ns, err) {
		t.inv.services = append(t.inv.services, svcs...)
	}
	t.serviceAccounts(ctx, ns)
	deps, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]appsv1.Deployment, string, error) {
		l, err := t.cs.AppsV1().Deployments(ns).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if !t.fail("deployments/"+ns, err) {
		t.inv.deployments = append(t.inv.deployments, deps...)
	}
	rbs, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.RoleBinding, string, error) {
		l, err := t.cs.RbacV1().RoleBindings(ns).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if !t.fail("rolebindings/"+ns, err) {
		t.inv.roleBindings = append(t.inv.roleBindings, rbs...)
	}
	roles, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.Role, string, error) {
		l, err := t.cs.RbacV1().Roles(ns).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if !t.fail("roles/"+ns, err) {
		t.inv.roles = append(t.inv.roles, roles...)
	}
	nps, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]networkingv1.NetworkPolicy, string, error) {
		l, err := t.cs.NetworkingV1().NetworkPolicies(ns).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	})
	if !t.fail("networkpolicies/"+ns, err) {
		t.inv.networkPolicies = append(t.inv.networkPolicies, nps...)
	}
}

// nodes reads the Nodes the re-read pods run on (one hop from a pod).
func (t *targetRead) nodes(ctx context.Context) {
	want := map[string]bool{}
	for _, p := range t.inv.pods {
		if p.Spec.NodeName != "" {
			want[p.Spec.NodeName] = true
		}
	}
	for _, name := range sortedKeys(want) {
		n, err := t.cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if !t.fail("nodes/"+name, err) {
			t.inv.nodes = append(t.inv.nodes, *n)
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
