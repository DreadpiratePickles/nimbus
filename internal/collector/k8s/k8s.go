// Package k8s collects Kubernetes workloads, RBAC and network policy posture through
// client-go and models them in the security graph (pod → namespace / service account /
// image / node, service account → role bindings, internet → exposed pods).
package k8s

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const pageSize = 500

// Collector gathers posture for one cluster (kube context).
type Collector struct {
	// NewClient builds the clientset and returns the cluster name; tests inject a fake clientset.
	NewClient   func(spec core.AccountSpec) (kubernetes.Interface, string, error)
	Concurrency int
	Now         func() time.Time
}

// New returns a collector that uses kubeconfig (KUBECONFIG / ~/.kube/config) with
// spec.KubeContext, falling back to the in-cluster service account.
func New() *Collector { return &Collector{NewClient: DefaultClient} }

func (c *Collector) Name() string     { return "kubernetes" }
func (c *Collector) Provider() string { return model.ProviderKubernetes }

// DefaultClient loads a REST config for spec.KubeContext and returns the clientset plus cluster name.
func DefaultClient(spec core.AccountSpec) (kubernetes.Interface, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: spec.KubeContext})
	cfg, err := cc.ClientConfig()
	name := spec.KubeContext
	if err == nil && name == "" {
		if raw, rerr := cc.RawConfig(); rerr == nil {
			name = raw.CurrentContext
		}
	}
	if err != nil {
		inCfg, ierr := rest.InClusterConfig()
		if ierr != nil {
			return nil, "", fmt.Errorf("kubeconfig: %v; in-cluster: %v", err, ierr)
		}
		cfg, name = inCfg, "in-cluster"
	}
	cfg.QPS, cfg.Burst = 50, 100
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", err
	}
	if spec.Name != "" {
		name = spec.Name
	}
	return cs, name, nil
}

// inventory is the raw cluster state collected in parallel.
type inventory struct {
	mu                  sync.Mutex
	namespaces          []corev1.Namespace
	pods                []corev1.Pod
	deployments         []appsv1.Deployment
	serviceAccounts     []corev1.ServiceAccount
	services            []corev1.Service
	clusterRoleBindings []rbacv1.ClusterRoleBinding
	roleBindings        []rbacv1.RoleBinding
	clusterRoles        []rbacv1.ClusterRole
	roles               []rbacv1.Role
	networkPolicies     []networkingv1.NetworkPolicy
	nodes               []corev1.Node
	// failed records which inventories could not be listed (checks depending on them are skipped).
	failed map[string]bool
}

// listAll pages through a List call using Limit + Continue.
func listAll[T any](ctx context.Context, fn func(context.Context, metav1.ListOptions) ([]T, string, error)) ([]T, error) {
	var out []T
	opts := metav1.ListOptions{Limit: pageSize}
	for {
		items, cont, err := fn(ctx, opts)
		if err != nil {
			return out, err
		}
		out = append(out, items...)
		if cont == "" {
			return out, nil
		}
		opts.Continue = cont
	}
}

// Collect lists cluster objects in parallel, evaluates checks and builds the graph.
func (c *Collector) Collect(ctx context.Context, spec core.AccountSpec, g *graph.Graph) (core.Result, error) {
	newClient := c.NewClient
	if newClient == nil {
		newClient = DefaultClient
	}
	cs, cluster, err := newClient(spec)
	if err != nil {
		return core.Result{Runs: []model.ToolRun{{Tool: "nimbus-kubernetes", Account: spec.Label(), Status: "failed", Message: err.Error()}}, Errors: []error{err}}, err
	}
	if cluster == "" {
		cluster = spec.Label()
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	acc := &core.Acc{}
	inv := gather(ctx, cs, c.Concurrency, acc)
	analyze(inv, spec, cluster, now(), g, acc)
	res := acc.Result()
	status, msg := "ok", ""
	if len(res.Errors) > 0 {
		status, msg = "partial", res.Err().Error()
	}
	res.Runs = append(res.Runs, model.ToolRun{Tool: "nimbus-kubernetes", Account: cluster, Status: status, Message: msg, Findings: len(res.Findings)})
	return res, nil
}

func gather(ctx context.Context, cs kubernetes.Interface, limit int, acc *core.Acc) *inventory {
	inv := &inventory{failed: map[string]bool{}}
	fail := func(name string, err error) error {
		if err != nil {
			inv.mu.Lock()
			inv.failed[name] = true
			inv.mu.Unlock()
		}
		return err
	}
	tasks := []core.Task{
		{Name: "namespaces", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Namespace, string, error) {
				l, err := cs.CoreV1().Namespaces().List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.namespaces = v
			inv.mu.Unlock()
			return fail("namespaces", err)
		}},
		{Name: "pods", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Pod, string, error) {
				l, err := cs.CoreV1().Pods("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.pods = v
			inv.mu.Unlock()
			return fail("pods", err)
		}},
		{Name: "deployments", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]appsv1.Deployment, string, error) {
				l, err := cs.AppsV1().Deployments("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.deployments = v
			inv.mu.Unlock()
			return fail("deployments", err)
		}},
		{Name: "serviceaccounts", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.ServiceAccount, string, error) {
				l, err := cs.CoreV1().ServiceAccounts("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.serviceAccounts = v
			inv.mu.Unlock()
			return fail("serviceaccounts", err)
		}},
		{Name: "services", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Service, string, error) {
				l, err := cs.CoreV1().Services("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.services = v
			inv.mu.Unlock()
			return fail("services", err)
		}},
		{Name: "clusterrolebindings", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.ClusterRoleBinding, string, error) {
				l, err := cs.RbacV1().ClusterRoleBindings().List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.clusterRoleBindings = v
			inv.mu.Unlock()
			return fail("clusterrolebindings", err)
		}},
		{Name: "rolebindings", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.RoleBinding, string, error) {
				l, err := cs.RbacV1().RoleBindings("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.roleBindings = v
			inv.mu.Unlock()
			return fail("rolebindings", err)
		}},
		{Name: "clusterroles", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.ClusterRole, string, error) {
				l, err := cs.RbacV1().ClusterRoles().List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.clusterRoles = v
			inv.mu.Unlock()
			return fail("clusterroles", err)
		}},
		{Name: "roles", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.Role, string, error) {
				l, err := cs.RbacV1().Roles("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.roles = v
			inv.mu.Unlock()
			return fail("roles", err)
		}},
		{Name: "networkpolicies", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]networkingv1.NetworkPolicy, string, error) {
				l, err := cs.NetworkingV1().NetworkPolicies("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.networkPolicies = v
			inv.mu.Unlock()
			return fail("networkpolicies", err)
		}},
		{Name: "nodes", Fn: func(ctx context.Context) error {
			v, err := listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Node, string, error) {
				l, err := cs.CoreV1().Nodes().List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return l.Items, l.Continue, nil
			})
			inv.mu.Lock()
			inv.nodes = v
			inv.mu.Unlock()
			return fail("nodes", err)
		}},
	}
	wrapped := make([]core.Task, len(tasks))
	for i, t := range tasks {
		wrapped[i] = core.Task{Name: "kubernetes/" + t.Name, Fn: t.Fn}
	}
	core.RunTasks(ctx, limit, acc, wrapped)
	return inv
}

// ID helpers.
func NamespaceID(ns string) string            { return "namespace/" + ns }
func PodID(ns, name string) string            { return ns + "/pod/" + name }
func DeploymentID(ns, name string) string     { return ns + "/deployment/" + name }
func ServiceAccountID(ns, name string) string { return ns + "/serviceaccount/" + name }
func RoleID(ns, name string) string           { return ns + "/role/" + name }
func ClusterRoleID(name string) string        { return "cluster/clusterrole/" + name }
func ClusterRoleBindingID(name string) string { return "cluster/clusterrolebinding/" + name }
func NodeID(name string) string               { return "cluster/node/" + name }
func ImageID(ref string) string               { return "image/" + ref }

type ctxw struct {
	g       *graph.Graph
	acc     *core.Acc
	cluster string
	label   string
	now     time.Time
}

func (w *ctxw) add(r model.Resource, tags map[string]string, created time.Time, sensitive bool) string {
	return core.AddResource(w.g, core.Res{Provider: model.ProviderKubernetes, Account: w.cluster, Resource: r, Tags: tags, Created: created, ForceSensitive: sensitive})
}

func (w *ctxw) check(id string, res model.Resource, pass bool, detail string, steampipe bool) {
	ck := core.Check{CheckID: id, Provider: model.ProviderKubernetes, Account: w.cluster, AccountLabel: w.label, Resource: res, Pass: pass, Detail: detail}
	if steampipe {
		ck.AliasSource = "steampipe"
	}
	f := ck.Finding(w.now)
	w.acc.Finding(f)
	core.AttachFinding(w.g, f)
}

func analyze(inv *inventory, spec core.AccountSpec, cluster string, now time.Time, g *graph.Graph, acc *core.Acc) {
	w := &ctxw{g: g, acc: acc, cluster: cluster, label: spec.Name, now: now}
	core.EnsureAccount(g, model.ProviderKubernetes, cluster, spec.Name)

	// Namespaces and NetworkPolicy coverage.
	policiesByNS := map[string]int{}
	for _, np := range inv.networkPolicies {
		policiesByNS[np.Namespace]++
	}
	for _, ns := range inv.namespaces {
		res := model.Resource{ID: NamespaceID(ns.Name), Type: "k8s_namespace", Name: ns.Name,
			Attributes: map[string]any{"kind": "Namespace", "namespace": ns.Name, "phase": string(ns.Status.Phase)}}
		w.add(res, ns.Labels, ns.CreationTimestamp.Time, false)
		if isSystemNamespace(ns.Name) || inv.failed["networkpolicies"] {
			continue
		}
		n := policiesByNS[ns.Name]
		w.check("namespace_network_policy_defined", res, n > 0, fmt.Sprintf("namespace %s has %d NetworkPolicy object(s)", ns.Name, n), true)
	}

	// Service accounts.
	for _, sa := range inv.serviceAccounts {
		res := model.Resource{ID: ServiceAccountID(sa.Namespace, sa.Name), Type: "k8s_service_account", Name: sa.Name,
			Attributes: map[string]any{"kind": "ServiceAccount", "namespace": sa.Namespace, "automount_token": sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken}}
		id := w.add(res, sa.Labels, sa.CreationTimestamp.Time, false)
		g.AddEdge(id, NamespaceID(sa.Namespace), graph.EdgeMemberOf, nil)
	}
	saAutomount := map[string]*bool{}
	for _, sa := range inv.serviceAccounts {
		saAutomount[sa.Namespace+"/"+sa.Name] = sa.AutomountServiceAccountToken
	}

	// Roles / cluster roles (wildcard detection feeds attributes).
	for _, cr := range inv.clusterRoles {
		w.add(model.Resource{ID: ClusterRoleID(cr.Name), Type: "k8s_cluster_role", Name: cr.Name,
			Attributes: map[string]any{"kind": "ClusterRole", "wildcard": hasWildcard(cr.Rules), "admin": cr.Name == "cluster-admin" || hasWildcard(cr.Rules)}}, cr.Labels, cr.CreationTimestamp.Time, false)
	}
	for _, r := range inv.roles {
		w.add(model.Resource{ID: RoleID(r.Namespace, r.Name), Type: "k8s_role", Name: r.Name,
			Attributes: map[string]any{"kind": "Role", "namespace": r.Namespace, "wildcard": hasWildcard(r.Rules)}}, r.Labels, r.CreationTimestamp.Time, false)
	}
	wildcardCR := map[string]bool{}
	for _, cr := range inv.clusterRoles {
		if hasWildcard(cr.Rules) {
			wildcardCR[cr.Name] = true
		}
	}

	// Cluster role bindings.
	for _, crb := range inv.clusterRoleBindings {
		roleID := roleRefID("", crb.RoleRef)
		res := model.Resource{ID: ClusterRoleBindingID(crb.Name), Type: "k8s_cluster_role_binding", Name: crb.Name,
			Attributes: map[string]any{"kind": "ClusterRoleBinding", "role": crb.RoleRef.Name, "subjects": subjectNames(crb.Subjects, "")}, Related: []string{roleID}}
		id := w.add(res, crb.Labels, crb.CreationTimestamp.Time, false)
		g.AddEdge(id, roleID, graph.EdgeBoundTo, map[string]any{"binding": crb.Name})
		for _, s := range crb.Subjects {
			if sid := subjectID(s, ""); sid != "" {
				g.AddEdge(sid, roleID, graph.EdgeBoundTo, map[string]any{"binding": crb.Name})
				g.AddEdge(sid, id, graph.EdgeMemberOf, map[string]any{"binding": crb.Name})
			}
		}
		if strings.HasPrefix(crb.Name, "system:") {
			continue
		}
		if crb.RoleRef.Kind == "ClusterRole" && (crb.RoleRef.Name == "cluster-admin" || wildcardCR[crb.RoleRef.Name]) {
			w.check("cluster_role_binding_cluster_admin_disabled", res, false,
				fmt.Sprintf("ClusterRoleBinding %s grants %s to %s", crb.Name, crb.RoleRef.Name, strings.Join(subjectNames(crb.Subjects, ""), ", ")), true)
		} else if crb.RoleRef.Kind == "ClusterRole" {
			w.check("cluster_role_binding_cluster_admin_disabled", res, true, fmt.Sprintf("ClusterRoleBinding %s binds non-admin role %s", crb.Name, crb.RoleRef.Name), true)
		}
	}

	// Role bindings.
	for _, rb := range inv.roleBindings {
		roleID := roleRefID(rb.Namespace, rb.RoleRef)
		for _, s := range rb.Subjects {
			if sid := subjectID(s, rb.Namespace); sid != "" {
				g.AddEdge(sid, roleID, graph.EdgeBoundTo, map[string]any{"binding": rb.Namespace + "/" + rb.Name})
			}
		}
	}

	// Nodes.
	for _, n := range inv.nodes {
		attrs := map[string]any{"kind": "Node", "kubelet_version": n.Status.NodeInfo.KubeletVersion, "os_image": n.Status.NodeInfo.OSImage}
		if it := n.Labels["node.kubernetes.io/instance-type"]; it != "" {
			attrs["instance_type"] = it
		}
		if n.Spec.ProviderID != "" {
			attrs["provider_id"] = n.Spec.ProviderID
		}
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeExternalIP {
				attrs["public_ip"] = a.Address
			}
		}
		w.add(model.Resource{ID: NodeID(n.Name), Type: "k8s_node", Name: n.Name, Attributes: attrs}, n.Labels, n.CreationTimestamp.Time, false)
	}

	// Deployments.
	for _, d := range inv.deployments {
		id := w.add(model.Resource{ID: DeploymentID(d.Namespace, d.Name), Type: "k8s_deployment", Name: d.Name,
			Attributes: map[string]any{"kind": "Deployment", "namespace": d.Namespace, "replicas": replicas(d.Spec.Replicas), "service_account": saName(d.Spec.Template.Spec.ServiceAccountName)}}, d.Labels, d.CreationTimestamp.Time, false)
		g.AddEdge(id, NamespaceID(d.Namespace), graph.EdgeMemberOf, nil)
	}

	// Pods.
	for _, p := range inv.pods {
		analyzePod(w, p, saAutomount, inv.deployments)
	}

	// Services of type LoadBalancer / NodePort expose matching pods to the internet.
	podsByNS := map[string][]corev1.Pod{}
	for _, p := range inv.pods {
		podsByNS[p.Namespace] = append(podsByNS[p.Namespace], p)
	}
	for _, svc := range inv.services {
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer && svc.Spec.Type != corev1.ServiceTypeNodePort {
			continue
		}
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		if internalLoadBalancer(svc) {
			continue // cloud-internal load balancer: not reachable from the internet
		}
		sel := labels.SelectorFromSet(svc.Spec.Selector)
		var ports []string
		for _, sp := range svc.Spec.Ports {
			ports = append(ports, fmt.Sprint(sp.Port))
		}
		sources := lbSourceRanges(svc)
		public := core.PublicSources(sources)
		if len(sources) > 0 && len(public) == 0 {
			continue // restricted to private ranges only
		}
		for _, p := range podsByNS[svc.Namespace] {
			if sel.Matches(labels.Set(p.Labels)) {
				core.Expose(g, PodID(p.Namespace, p.Name),
					map[string]any{"via": svc.Namespace + "/service/" + svc.Name, "service_type": string(svc.Spec.Type), "ports": strings.Join(ports, ",")},
					public, spec.TrustedCIDRs)
			}
		}
	}
}

// lbSourceRanges returns spec.loadBalancerSourceRanges, falling back to the
// service.beta.kubernetes.io/load-balancer-source-ranges annotation.
func lbSourceRanges(svc corev1.Service) []string {
	if len(svc.Spec.LoadBalancerSourceRanges) > 0 {
		return svc.Spec.LoadBalancerSourceRanges
	}
	var out []string
	for _, r := range strings.Split(svc.Annotations["service.beta.kubernetes.io/load-balancer-source-ranges"], ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// internalLoadBalancer recognises the AWS, Azure, GCP and OCI internal-LB annotations.
func internalLoadBalancer(svc corev1.Service) bool {
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return false
	}
	a := svc.Annotations
	truthy := func(k string) bool {
		v := strings.ToLower(strings.TrimSpace(a[k]))
		return v == "true" || v == "0.0.0.0/0"
	}
	return truthy("service.beta.kubernetes.io/aws-load-balancer-internal") ||
		strings.EqualFold(a["service.beta.kubernetes.io/aws-load-balancer-scheme"], "internal") ||
		truthy("service.beta.kubernetes.io/azure-load-balancer-internal") ||
		strings.EqualFold(a["networking.gke.io/load-balancer-type"], "Internal") ||
		strings.EqualFold(a["cloud.google.com/load-balancer-type"], "Internal") ||
		truthy("service.beta.kubernetes.io/oci-load-balancer-internal")
}

func analyzePod(w *ctxw, p corev1.Pod, saAutomount map[string]*bool, deps []appsv1.Deployment) {
	spec := p.Spec
	var containers []corev1.Container
	containers = append(containers, spec.InitContainers...)
	containers = append(containers, spec.Containers...)
	privileged, escalation := false, false
	var privNames, escNames, names, images []string
	for _, c := range containers {
		names = append(names, c.Name)
		if c.Image != "" {
			images = append(images, c.Image)
		}
		sc := c.SecurityContext
		if sc != nil && sc.Privileged != nil && *sc.Privileged {
			privileged = true
			privNames = append(privNames, c.Name)
		}
		// allowPrivilegeEscalation defaults to true unless explicitly false (or privileged).
		if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			escalation = true
			escNames = append(escNames, c.Name)
		}
	}
	sa := saName(spec.ServiceAccountName)
	hostNS := spec.HostNetwork || spec.HostPID || spec.HostIPC
	var hostPaths []string
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			hostPaths = append(hostPaths, v.HostPath.Path)
		}
	}
	first := ""
	if len(spec.Containers) > 0 {
		first = spec.Containers[0].Name
	}
	attrs := map[string]any{
		"kind": "Pod", "namespace": p.Namespace, "container": first, "containers": names, "images": images,
		"service_account": sa, "node": spec.NodeName, "privileged": privileged, "host_network": spec.HostNetwork,
		"host_pid": spec.HostPID, "host_ipc": spec.HostIPC, "phase": string(p.Status.Phase),
	}
	if len(hostPaths) > 0 {
		attrs["host_paths"] = hostPaths
	}
	if p.Status.PodIP != "" {
		attrs["pod_ip"] = p.Status.PodIP
	}
	saID := ServiceAccountID(p.Namespace, sa)
	res := model.Resource{ID: PodID(p.Namespace, p.Name), Type: "k8s_pod", Name: p.Name, Attributes: attrs, Related: []string{saID}}
	tags := map[string]string{}
	for k, v := range p.Labels {
		tags[k] = v
	}
	if _, ok := tags["environment"]; !ok && core.Criticality(p.Namespace, nil) != "unknown" {
		tags["environment"] = p.Namespace
	}
	id := w.add(res, tags, p.CreationTimestamp.Time, false)
	g := w.g
	g.AddEdge(id, NamespaceID(p.Namespace), graph.EdgeMemberOf, nil)
	g.AddEdge(id, saID, graph.EdgeRunsAs, nil)
	for _, img := range images {
		g.AddNode(&graph.Node{ID: ImageID(img), Type: "container_image", Class: graph.ClassImage, Name: img, Provider: model.ProviderKubernetes, Account: w.cluster})
		g.AddEdge(id, ImageID(img), graph.EdgeRunsOn, nil)
	}
	if spec.NodeName != "" {
		g.AddEdge(id, NodeID(spec.NodeName), graph.EdgeRunsOn, nil)
	}
	if dep := owningDeployment(p, deps); dep != "" {
		g.AddEdge(DeploymentID(p.Namespace, dep), id, graph.EdgeContains, nil)
	}

	pr := model.Resource{ID: res.ID, Type: res.Type, Name: res.Name, Attributes: map[string]any{"kind": "Pod", "namespace": p.Namespace, "container": first}}
	if privileged {
		w.check("core_pod_privileged", pr, false, fmt.Sprintf("privileged container(s): %s", strings.Join(privNames, ", ")), false)
	} else {
		w.check("core_pod_privileged", pr, true, "no container runs privileged", false)
	}
	w.check("pod_host_network_access_disabled", pr, !hostNS,
		fmt.Sprintf("hostNetwork=%t hostPID=%t hostIPC=%t", spec.HostNetwork, spec.HostPID, spec.HostIPC), true)
	if len(hostPaths) > 0 {
		w.check("pod_volume_host_path", pr, false, "hostPath volumes: "+strings.Join(hostPaths, ", "), true)
	} else {
		w.check("pod_volume_host_path", pr, true, "no hostPath volumes", true)
	}
	if escalation {
		w.check("pod_container_privilege_escalation_disabled", pr, false, "allowPrivilegeEscalation not false for: "+strings.Join(escNames, ", "), true)
	} else {
		w.check("pod_container_privilege_escalation_disabled", pr, true, "all containers set allowPrivilegeEscalation=false", true)
	}
	automount := true
	if spec.AutomountServiceAccountToken != nil {
		automount = *spec.AutomountServiceAccountToken
	} else if v, ok := saAutomount[p.Namespace+"/"+sa]; ok && v != nil {
		automount = *v
	}
	w.check("pod_service_account_token_disabled", pr, !automount,
		fmt.Sprintf("service account %s token automount=%t", sa, automount), true)
}

func owningDeployment(p corev1.Pod, deps []appsv1.Deployment) string {
	for _, o := range p.OwnerReferences {
		if o.Kind != "ReplicaSet" {
			continue
		}
		best := ""
		for _, d := range deps {
			if d.Namespace == p.Namespace && strings.HasPrefix(o.Name, d.Name+"-") && len(d.Name) > len(best) {
				best = d.Name
			}
		}
		if best != "" {
			return best
		}
	}
	return ""
}

func roleRefID(ns string, ref rbacv1.RoleRef) string {
	if ref.Kind == "Role" && ns != "" {
		return RoleID(ns, ref.Name)
	}
	return ClusterRoleID(ref.Name)
}

// subjectID maps an RBAC subject to a graph node ID; users and groups get synthetic IDs.
func subjectID(s rbacv1.Subject, defaultNS string) string {
	switch s.Kind {
	case rbacv1.ServiceAccountKind:
		ns := s.Namespace
		if ns == "" {
			ns = defaultNS
		}
		if ns == "" {
			return ""
		}
		return ServiceAccountID(ns, s.Name)
	case rbacv1.UserKind:
		return "cluster/user/" + s.Name
	case rbacv1.GroupKind:
		return "cluster/group/" + s.Name
	}
	return ""
}

func subjectNames(ss []rbacv1.Subject, defaultNS string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		n := s.Kind + ":" + s.Name
		if s.Kind == rbacv1.ServiceAccountKind {
			ns := s.Namespace
			if ns == "" {
				ns = defaultNS
			}
			n = s.Kind + ":" + ns + "/" + s.Name
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func hasWildcard(rules []rbacv1.PolicyRule) bool {
	for _, r := range rules {
		if contains(r.Verbs, "*") && (contains(r.Resources, "*") || len(r.NonResourceURLs) > 0 && contains(r.NonResourceURLs, "*")) {
			return true
		}
	}
	return false
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func saName(n string) string {
	if n == "" {
		return "default"
	}
	return n
}

func replicas(r *int32) int32 {
	if r == nil {
		return 1
	}
	return *r
}

func isSystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}
