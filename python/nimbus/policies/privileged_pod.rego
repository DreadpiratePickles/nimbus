# Deny privileged containers, privilege escalation and host namespaces.
# Input: a Kubernetes object (Pod / Deployment / ...) or an AdmissionReview (input.request.object).
package nimbus.k8s.privileged_pod

import rego.v1

obj := input.request.object if input.request.object

obj := input if not input.request

pod_spec := obj.spec.template.spec if obj.spec.template

pod_spec := obj.spec if not obj.spec.template

containers contains c if c := pod_spec.containers[_]

containers contains c if c := pod_spec.initContainers[_]

deny contains msg if {
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf("%s/%s: container %q is privileged (K8S_PRIVILEGED_CONTAINER)", [obj.kind, obj.metadata.name, c.name])
}

deny contains msg if {
	some c in containers
	object.get(object.get(c, "securityContext", {}), "allowPrivilegeEscalation", true) != false
	msg := sprintf("%s/%s: container %q must set allowPrivilegeEscalation: false", [obj.kind, obj.metadata.name, c.name])
}

deny contains msg if {
	some field in ["hostNetwork", "hostPID", "hostIPC"]
	pod_spec[field] == true
	msg := sprintf("%s/%s: %s is enabled (K8S_HOST_NETWORK)", [obj.kind, obj.metadata.name, field])
}
