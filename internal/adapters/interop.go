package adapters

import (
	"strings"
	"unicode"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Versioned is implemented by adapters that declare which upstream output version they parse.
type Versioned interface {
	SupportedVersion() string
}

// Versions lists adapter name -> supported upstream version for every registered adapter that
// declares one (the CLI prints this). Adapters without a declaration are omitted.
func Versions() map[string]string {
	out := map[string]string{}
	for _, a := range registry {
		if v, ok := a.(Versioned); ok {
			out[a.Name()] = v.SupportedVersion()
		}
	}
	return out
}

// k8sResourceID mirrors the IDs the native Kubernetes collector builds (internal/collector/k8s:
// NamespaceID, PodID, DeploymentID, RoleID, ClusterRoleID, NodeID) so findings from imported
// tools join the same graph nodes: "namespace/<ns>", "<ns>/<kind>/<name>" for namespaced
// objects and "cluster/<kind>/<name>" for cluster-scoped ones, kind lower-cased.
func k8sResourceID(kind, namespace, name string) string {
	k := strings.ToLower(kind)
	switch {
	case k == "namespace":
		return "namespace/" + name
	case namespace == "":
		return "cluster/" + k + "/" + name
	}
	return namespace + "/" + k + "/" + name
}

// k8sResourceType is "k8s_" + snake_case(kind), matching the collector's k8s_pod,
// k8s_service_account, k8s_cluster_role, ...
func k8sResourceType(kind string) string {
	if kind == "" {
		return "k8s_resource"
	}
	var b strings.Builder
	for i, r := range kind {
		if unicode.IsUpper(r) && i > 0 {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return "k8s_" + b.String()
}

// k8sResource builds a Kubernetes resource; namespaced objects get a member_of relation to
// their namespace, the edge the collector draws for pods, deployments and service accounts.
func k8sResource(kind, namespace, name string) model.Resource {
	r := model.Resource{
		ID:         k8sResourceID(kind, namespace, name),
		Type:       k8sResourceType(kind),
		Name:       name,
		Attributes: map[string]any{"kind": kind},
	}
	if namespace != "" {
		r.Attributes["namespace"] = namespace
		if !strings.EqualFold(kind, "namespace") {
			addRelation(&r, "namespace/"+namespace, "member_of", nil)
		}
	}
	return r
}

// addRelation appends a typed relation (and its ID to Related), skipping duplicates.
func addRelation(r *model.Resource, id, kind string, attr map[string]any) {
	if id == "" || kind == "" {
		return
	}
	for _, x := range r.Relations {
		if x.ID == id && x.Kind == kind {
			return
		}
	}
	r.Relations = append(r.Relations, model.Relation{ID: id, Kind: kind, Attr: attr})
	for _, x := range r.Related {
		if x == id {
			return
		}
	}
	r.Related = append(r.Related, id)
}

// floatOf reads a JSON number (or numeric string) as float64.
func floatOf(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	}
	return 0, false
}
