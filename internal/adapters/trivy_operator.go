package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// TrivyOperatorSupportedVersion: the CRD reports trivy-operator v0.2x writes under
// aquasecurity.github.io/v1alpha1 (VulnerabilityReport, ConfigAuditReport, RbacAssessmentReport,
// ClusterRbacAssessmentReport, ExposedSecretReport; the Cluster* variants of the config/vuln
// reports parse too). https://aquasecurity.github.io/trivy-operator/latest/docs/crds/
const TrivyOperatorSupportedVersion = "trivy-operator v0.2x CRDs aquasecurity.github.io/v1alpha1"

// TrivyOperator parses trivy-operator CRD reports as one object, a `kind: List` (what
// `kubectl get vulnerabilityreports -A -o json` returns) or a JSON array of reports.
//
// Mapping:
//   - the resource is the scanned workload / RBAC object named by the
//     trivy-operator.resource.{kind,name,namespace} labels, with IDs in the native k8s collector
//     format and a member_of relation to its namespace;
//   - vulnerabilities[] -> FAIL findings, CheckID = vulnerabilityID (CVE-* maps to
//     CVE_VULNERABILITY), keeping CVSS score and primary link as attributes "cvss" /
//     "primary_url" (also tags) and the image repository/tag/digest;
//   - checks[] (config audit and RBAC) -> FAIL when success=false, PASS when true;
//   - secrets[] -> FAIL findings; the `match` text (it can contain the secret) is never copied,
//     not even into Raw.
//
// Account stays empty unless Options.Account names the cluster.
type TrivyOperator struct{}

func (TrivyOperator) Name() string             { return "trivy-operator" }
func (TrivyOperator) SupportedVersion() string { return TrivyOperatorSupportedVersion }

var trivyOperatorKinds = []string{
	"VulnerabilityReport", "ConfigAuditReport", "RbacAssessmentReport", "ExposedSecretReport",
	"ClusterVulnerabilityReport", "ClusterConfigAuditReport", "ClusterRbacAssessmentReport", "InfraAssessmentReport", "ClusterInfraAssessmentReport",
}

func (TrivyOperator) Detect(filename string, data []byte) bool {
	if !bytes.Contains(data, []byte("aquasecurity.github.io/")) {
		return false
	}
	for _, k := range trivyOperatorKinds {
		if bytes.Contains(data, []byte(`"`+k+`"`)) {
			return true
		}
	}
	return false
}

func (t TrivyOperator) Parse(data []byte, opts Options) ([]model.Finding, error) {
	var doc any
	if err := json.Unmarshal(bytes.TrimSpace(data), &doc); err != nil {
		return nil, err
	}
	var objs []any
	switch v := doc.(type) {
	case []any:
		objs = v
	case map[string]any:
		if items, ok := v["items"].([]any); ok {
			objs = items
		} else {
			objs = []any{v}
		}
	default:
		return nil, fmt.Errorf("expected a report object, List or array")
	}
	var out []model.Finding
	for _, o := range objs {
		m, ok := o.(map[string]any)
		if !ok || !strings.HasPrefix(str(m, "apiVersion"), "aquasecurity.github.io/") {
			continue
		}
		out = append(out, t.report(m, opts)...)
	}
	return out, nil
}

type trivyOperatorTarget struct {
	kind, name, namespace, container, reportKind, reportName string
	image                                                    map[string]any
}

func (TrivyOperator) target(m map[string]any) trivyOperatorTarget {
	meta := sub(m, "metadata")
	labels := sub(meta, "labels")
	tg := trivyOperatorTarget{
		kind:       str(labels, "trivy-operator.resource.kind"),
		name:       str(labels, "trivy-operator.resource.name"),
		namespace:  str(labels, "trivy-operator.resource.namespace"),
		container:  str(labels, "trivy-operator.container.name"),
		reportKind: str(m, "kind"),
		reportName: str(meta, "name"),
	}
	if tg.kind == "" || tg.name == "" {
		// Older reports without labels: fall back to the owner reference.
		for _, o := range list(meta, "ownerReferences") {
			if ref, ok := o.(map[string]any); ok {
				tg.kind, tg.name = str(ref, "kind"), str(ref, "name")
				break
			}
		}
	}
	if tg.namespace == "" && !strings.HasPrefix(tg.reportKind, "Cluster") {
		tg.namespace = str(meta, "namespace")
	}
	if tg.name == "" {
		tg.kind, tg.name = tg.reportKind, tg.reportName
	}
	rep := sub(m, "report")
	art, reg := sub(rep, "artifact"), sub(rep, "registry")
	if repo := str(art, "repository"); repo != "" {
		tg.image = map[string]any{"image_repository": repo, "image_tag": str(art, "tag"), "image_digest": str(art, "digest"), "image_registry": str(reg, "server")}
		ref := repo
		if s := str(reg, "server"); s != "" {
			ref = s + "/" + repo
		}
		if tag := str(art, "tag"); tag != "" {
			ref += ":" + tag
		} else if d := str(art, "digest"); d != "" {
			ref += "@" + d
		}
		tg.image["image"] = ref
	}
	return tg
}

// resource returns a fresh resource per finding (attributes are per-finding).
func (tg trivyOperatorTarget) resource() model.Resource {
	r := k8sResource(tg.kind, tg.namespace, tg.name)
	r.Attributes["report"] = tg.reportName
	r.Attributes["report_kind"] = tg.reportKind
	if tg.container != "" {
		r.Attributes["container"] = tg.container
	}
	for k, v := range tg.image {
		if v != "" {
			r.Attributes[k] = v
		}
	}
	return r
}

func (t TrivyOperator) report(m map[string]any, opts Options) []model.Finding {
	tg := t.target(m)
	rep := sub(m, "report")
	var out []model.Finding
	for _, v := range list(rep, "vulnerabilities") {
		if vm, ok := v.(map[string]any); ok {
			out = append(out, t.vuln(vm, tg, opts))
		}
	}
	for _, c := range list(rep, "checks") {
		if cm, ok := c.(map[string]any); ok {
			out = append(out, t.check(cm, tg, opts))
		}
	}
	for _, s := range list(rep, "secrets") {
		if sm, ok := s.(map[string]any); ok {
			out = append(out, t.secret(sm, tg, opts))
		}
	}
	return out
}

func (TrivyOperator) base(tg trivyOperatorTarget, opts Options) model.Finding {
	tags := map[string]string{"report_kind": tg.reportKind}
	if tg.container != "" {
		tags["container"] = tg.container
	}
	return model.Finding{
		Source:   "trivy-operator",
		Provider: model.ProviderKubernetes,
		Account:  opts.Account, // set before fingerprinting so per-cluster findings stay distinct
		Resource: tg.resource(),
		Tags:     tags,
	}
}

func (t TrivyOperator) vuln(m map[string]any, tg trivyOperatorTarget, opts Options) model.Finding {
	id := str(m, "vulnerabilityID")
	pkg := firstNonEmpty(str(m, "resource"), str(m, "pkgName"))
	pkgPath := str(m, "pkgPath")
	installed, fixed := str(m, "installedVersion"), str(m, "fixedVersion")
	f := t.base(tg, opts)
	f.CheckID = id
	f.Title = fmt.Sprintf("%s in %s %s", id, pkg, installed)
	f.Description = str(m, "title")
	f.Severity = model.ParseSeverity(str(m, "severity"))
	f.Status = model.Fail
	if fixed != "" {
		f.Remediation = fmt.Sprintf("Upgrade %s to %s and rebuild the image.", pkg, fixed)
	} else {
		f.Remediation = fmt.Sprintf("No fixed version of %s is available yet; track the advisory or replace the package.", pkg)
	}
	a := f.Resource.Attributes
	a["package"], a["installed"], a["fixed"] = pkg, installed, fixed
	if pkgPath != "" {
		a["path"] = pkgPath
	}
	if score, ok := floatOf(m["score"]); ok {
		a["cvss"] = score
		f.Tags["cvss"] = strconv.FormatFloat(score, 'f', -1, 64)
	}
	if link := str(m, "primaryLink"); link != "" {
		a["primary_url"] = link
		f.Tags["primary_url"] = link
	}
	f.Tags["pkg"] = pkg
	f.Raw = rawOf(m)
	f.ID = f.FingerprintWith("container="+tg.container, "pkg="+pkg, "path="+pkgPath)
	return f
}

func (t TrivyOperator) check(m map[string]any, tg trivyOperatorTarget, opts Options) model.Finding {
	f := t.base(tg, opts)
	f.CheckID = firstNonEmpty(str(m, "checkID"), str(m, "id"))
	f.Title = str(m, "title")
	var msgs []string
	for _, x := range list(m, "messages") {
		if s, ok := x.(string); ok && s != "" {
			msgs = append(msgs, s)
		}
	}
	f.Description = str(m, "description")
	if len(msgs) > 0 {
		f.Description = strings.TrimSpace(strings.Join(msgs, "; ") + "\n\n" + f.Description)
		f.Resource.Attributes["messages"] = msgs
	}
	f.Severity = model.ParseSeverity(str(m, "severity"))
	f.Status = model.Fail
	if ok, _ := m["success"].(bool); ok {
		f.Status = model.Pass
	}
	f.Remediation = str(m, "remediation")
	if c := str(m, "category"); c != "" {
		f.Tags["category"] = c
	}
	f.Raw = rawOf(m)
	return f
}

// secret never copies `match` (the matched line, which can hold the secret) anywhere.
func (t TrivyOperator) secret(m map[string]any, tg trivyOperatorTarget, opts Options) model.Finding {
	rule := str(m, "ruleID")
	target := str(m, "target")
	f := t.base(tg, opts)
	f.CheckID = rule
	f.Title = firstNonEmpty(str(m, "title"), rule)
	where := fmt.Sprintf("%s %s", tg.kind, tg.name)
	if tg.container != "" {
		where = fmt.Sprintf("container %s of %s", tg.container, where)
	}
	f.Description = fmt.Sprintf("Secret matching rule %s found at %s in the image of %s; the matched text is redacted.", rule, firstNonEmpty(target, "an unknown path"), where)
	f.Severity = model.ParseSeverity(str(m, "severity"))
	f.Status = model.Fail
	f.File = target
	f.Remediation = "Remove the secret from the image, rotate it, and load it at runtime from a secrets manager or Kubernetes Secret."
	a := f.Resource.Attributes
	a["secret_target"], a["rule_id"], a["match_redacted"] = target, rule, true
	if c := str(m, "category"); c != "" {
		f.Tags["category"] = c
	}
	safe := map[string]any{}
	for k, v := range m {
		safe[k] = v
	}
	if _, ok := safe["match"]; ok {
		safe["match"] = "[REDACTED]"
	}
	f.Raw = rawOf(safe)
	f.ID = f.FingerprintWith("container=" + tg.container)
	return f
}
