package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Trivy parses `trivy <config|k8s|image|fs> -f json` output, including
// misconfigurations, vulnerabilities and secrets.
type Trivy struct{}

func (Trivy) Name() string { return "trivy" }

func (Trivy) Detect(filename string, data []byte) bool {
	if strings.Contains(filename, "trivy") {
		return true
	}
	head := data[:min(len(data), 2048)]
	return bytes.Contains(head, []byte(`"SchemaVersion"`)) || (bytes.Contains(head, []byte(`"Results"`)) && bytes.Contains(head, []byte(`"ArtifactName"`)))
}

func (t Trivy) Parse(data []byte, opts Options) ([]model.Finding, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	artifact := str(doc, "ArtifactName")
	var out []model.Finding
	var results []trivyResult
	for _, r := range list(doc, "Results") {
		results = append(results, trivyResult{res: r})
	}
	// `trivy k8s` wraps per-resource results under Resources[].Results, with the object's
	// Namespace / Kind / Name on the wrapper.
	if len(results) == 0 {
		for _, key := range []string{"Resources", "Misconfigurations", "Vulnerabilities"} {
			for _, r := range list(doc, key) {
				if m, ok := r.(map[string]any); ok {
					for _, x := range list(m, "Results") {
						results = append(results, trivyResult{res: x, namespace: str(m, "Namespace"), kind: str(m, "Kind"), name: str(m, "Name")})
					}
				}
			}
		}
	}
	for _, tr := range results {
		res, ok := tr.res.(map[string]any)
		if !ok {
			continue
		}
		target := str(res, "Target")
		class := str(res, "Class")
		for _, mc := range list(res, "Misconfigurations") {
			if m, ok := mc.(map[string]any); ok {
				f := t.misconfig(m, target, artifact)
				// Trivy gives no CauseMetadata.Resource for Kubernetes objects: use the
				// <ns>/<kind>/<name> id of the k8s collector, trivy-operator and kubescape.
				if f.Resource.ID == "" && tr.kind != "" && tr.name != "" {
					kr := k8sResource(tr.kind, tr.namespace, tr.name)
					for k, v := range f.Resource.Attributes {
						kr.Attributes[k] = v
					}
					f.Resource = kr
				}
				out = append(out, f)
			}
		}
		for _, v := range list(res, "Vulnerabilities") {
			if m, ok := v.(map[string]any); ok {
				out = append(out, t.vuln(m, target, artifact, class))
			}
		}
		for _, s := range list(res, "Secrets") {
			if m, ok := s.(map[string]any); ok {
				out = append(out, t.secret(m, target))
			}
		}
	}
	return out, nil
}

// trivyResult is one Results[] entry, with the Kubernetes object that wraps it in `trivy k8s` output.
type trivyResult struct {
	res                   any
	namespace, kind, name string
}

func (Trivy) misconfig(m map[string]any, target, artifact string) model.Finding {
	cause := sub(m, "CauseMetadata")
	provider := model.NormalizeProvider(str(cause, "Provider"))
	if provider == model.ProviderUnknown {
		provider = providerFromAVD(str(m, "ID"))
	}
	resource := str(cause, "Resource")
	f := model.Finding{
		Source:      "trivy",
		CheckID:     firstNonEmpty(str(m, "AVDID"), str(m, "ID")),
		Title:       str(m, "Title"),
		Description: firstNonEmpty(str(m, "Message"), str(m, "Description")),
		Severity:    model.ParseSeverity(str(m, "Severity")),
		Status:      model.ParseStatus(str(m, "Status")),
		Provider:    provider,
		Account:     "iac",
		File:        target,
		LineStart:   intOf(cause["StartLine"]),
		LineEnd:     intOf(cause["EndLine"]),
		Remediation: str(m, "Resolution"),
		Resource: model.Resource{
			ID:   resource,
			Name: resource,
			Type: resourceTypeFromCheckov(resource),
			Attributes: map[string]any{
				"service": str(cause, "Service"),
				"file":    target,
			},
		},
		Tags: map[string]string{"artifact": artifact, "trivy_type": str(m, "Type"), "avd_id": str(m, "AVDID"), "trivy_id": str(m, "ID")},
		Raw:  rawOf(m),
	}
	if f.Status == model.Error {
		f.Status = model.Fail
	}
	// Prefer the short policy ID (KSV017 / AVD-AWS-0086) for catalog matching; the catalog lists both.
	return f
}

func (Trivy) vuln(m map[string]any, target, artifact, class string) model.Finding {
	pkg := str(m, "PkgName")
	pkgPath := str(m, "PkgPath") // the jar / lockfile inside the target (empty for OS packages)
	id := str(m, "VulnerabilityID")
	provider := model.ProviderKubernetes
	if class == "lang-pkgs" {
		provider = model.ProviderIaC
	}
	f := model.Finding{
		Source:      "trivy",
		CheckID:     id,
		Title:       fmt.Sprintf("%s in %s %s", id, pkg, str(m, "InstalledVersion")),
		Description: str(m, "Title"),
		Severity:    model.ParseSeverity(str(m, "Severity")),
		Status:      model.Fail,
		Provider:    provider,
		Account:     "iac",
		File:        target,
		Remediation: fmt.Sprintf("Upgrade %s to %s", pkg, firstNonEmpty(str(m, "FixedVersion"), "a patched version")),
		Resource: model.Resource{
			ID:   firstNonEmpty(artifact, target),
			Name: firstNonEmpty(artifact, target),
			Type: "container_image",
			Attributes: map[string]any{
				"package": pkg, "installed": str(m, "InstalledVersion"), "fixed": str(m, "FixedVersion"), "image": artifact, "path": pkgPath,
			},
		},
		Tags: map[string]string{"class": class, "pkg": pkg, "pkg_path": pkgPath},
		Raw:  rawOf(m),
	}
	// One CVE in two packages, or in the same package at two paths (two jars), of one
	// image is two findings (defect 19b, V2 11a). The installed version is not part of
	// the identity: a bump that is still vulnerable is the same open finding, keeping its
	// first_seen, not "resolved + new" (V2 11b).
	f.ID = f.FingerprintWith("pkg="+pkg, "path="+pkgPath)
	return f
}

func (Trivy) secret(m map[string]any, target string) model.Finding {
	return model.Finding{
		Source:      "trivy",
		CheckID:     str(m, "RuleID"),
		Title:       str(m, "Title"),
		Description: str(m, "Match"),
		Severity:    model.ParseSeverity(str(m, "Severity")),
		Status:      model.Fail,
		Provider:    model.ProviderIaC,
		Account:     "iac",
		File:        target,
		LineStart:   intOf(m["StartLine"]),
		LineEnd:     intOf(m["EndLine"]),
		Remediation: "Remove the secret from source, rotate it, and load it from a secrets manager.",
		Resource:    model.Resource{ID: target + ":" + str(m, "RuleID"), Name: target, Type: "secret"},
		Tags:        map[string]string{"category": str(m, "Category")},
		Raw:         rawOf(m),
	}
}

func providerFromAVD(id string) string {
	// Trivy >= 0.6x drops the "AVD-" prefix ("AWS-0028", "KSV-0111").
	if !strings.HasPrefix(id, "AVD-") {
		id = "AVD-" + id
	}
	switch {
	case strings.HasPrefix(id, "AVD-AWS"):
		return model.ProviderAWS
	case strings.HasPrefix(id, "AVD-AZU"):
		return model.ProviderAzure
	case strings.HasPrefix(id, "AVD-GCP"):
		return model.ProviderGCP
	case strings.HasPrefix(id, "AVD-OCI"):
		return model.ProviderOCI
	case strings.HasPrefix(id, "KSV"), strings.HasPrefix(id, "AVD-KSV"):
		return model.ProviderKubernetes
	}
	return model.ProviderIaC
}

func intOf(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}
