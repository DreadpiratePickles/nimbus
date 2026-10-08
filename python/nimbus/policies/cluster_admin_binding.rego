# Deny ClusterRoleBindings / RoleBindings that grant cluster-admin to users, groups or service accounts
# outside the allow-list. Input: Kubernetes object or AdmissionReview.
package nimbus.k8s.cluster_admin_binding

import rego.v1

obj := input.request.object if input.request.object

obj := input if not input.request

allowed_subjects := {"system:masters"}

deny contains msg if {
	obj.kind in {"ClusterRoleBinding", "RoleBinding"}
	obj.roleRef.name == "cluster-admin"
	s := obj.subjects[_]
	not allowed_subjects[s.name]
	msg := sprintf("%s %q grants cluster-admin to %s %q (K8S_CLUSTER_ADMIN_BINDING)", [obj.kind, obj.metadata.name, s.kind, s.name])
}
