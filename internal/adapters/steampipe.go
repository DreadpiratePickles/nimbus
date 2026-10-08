package adapters

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Steampipe parses `steampipe check ... --export json` (nested groups/controls)
// and `powerpipe benchmark run ... --export json`, which share the shape.
type Steampipe struct{}

func (Steampipe) Name() string { return "steampipe" }

func (Steampipe) Detect(filename string, data []byte) bool {
	if strings.Contains(filename, "steampipe") || strings.Contains(filename, "powerpipe") {
		return true
	}
	head := data[:min(len(data), 2048)]
	return bytes.Contains(head, []byte(`"group_id"`)) && bytes.Contains(head, []byte(`"summary"`))
}

func (s Steampipe) Parse(data []byte, opts Options) ([]model.Finding, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []model.Finding
	s.walk(doc, nil, &out, opts)
	return out, nil
}

func (s Steampipe) walk(group map[string]any, parents []string, out *[]model.Finding, opts Options) {
	title := str(group, "title")
	chain := append(append([]string{}, parents...), title)
	for _, c := range list(group, "controls") {
		if m, ok := c.(map[string]any); ok {
			s.control(m, chain, out, opts)
		}
	}
	for _, g := range list(group, "groups") {
		if m, ok := g.(map[string]any); ok {
			s.walk(m, chain, out, opts)
		}
	}
}

func (Steampipe) control(ctl map[string]any, chain []string, out *[]model.Finding, opts Options) {
	controlID := str(ctl, "control_id") // e.g. aws_compliance.control.s3_bucket_restrict_public_read_access
	short := controlID
	if i := strings.LastIndex(short, "."); i >= 0 {
		short = short[i+1:]
	}
	provider := model.ProviderUnknown
	switch {
	case strings.HasPrefix(controlID, "aws_"):
		provider = model.ProviderAWS
	case strings.HasPrefix(controlID, "azure_"):
		provider = model.ProviderAzure
	case strings.HasPrefix(controlID, "gcp_"):
		provider = model.ProviderGCP
	case strings.HasPrefix(controlID, "oci_"):
		provider = model.ProviderOCI
	case strings.HasPrefix(controlID, "kubernetes_"):
		provider = model.ProviderKubernetes
	case strings.HasPrefix(controlID, "github_"):
		provider = model.ProviderGitHub
	case strings.HasPrefix(controlID, "okta_"):
		provider = model.ProviderOkta
	case strings.HasPrefix(controlID, "microsoft365_"), strings.HasPrefix(controlID, "m365_"):
		provider = model.ProviderM365
	}
	tags := map[string]string{}
	if t, ok := ctl["tags"].(map[string]any); ok {
		for k, v := range t {
			tags[k] = toString(v)
		}
	}
	sev := model.ParseSeverity(str(ctl, "severity"))
	for _, r := range list(ctl, "results") {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		f := model.Finding{
			Source:      "steampipe",
			CheckID:     short,
			Title:       str(ctl, "title"),
			Description: firstNonEmpty(str(m, "reason"), str(ctl, "description")),
			Severity:    sev,
			Status:      model.ParseStatus(str(m, "status")),
			Provider:    provider,
			Resource:    model.Resource{ID: str(m, "resource"), Name: str(m, "resource"), Attributes: map[string]any{}},
			Tags:        map[string]string{"benchmark": strings.Join(chain, " > "), "control_id": controlID},
			Raw:         rawOf(m),
		}
		for _, d := range list(m, "dimensions") {
			dm, ok := d.(map[string]any)
			if !ok {
				continue
			}
			k, v := str(dm, "key"), str(dm, "value")
			switch k {
			case "account_id", "subscription_id", "project", "project_id", "tenant_id", "compartment_id", "organization", "domain":
				f.Account = v
			case "region", "location", "zone":
				f.Region = v
			case "namespace", "context_name", "cluster_name":
				f.Resource.Related = append(f.Resource.Related, v)
				f.Resource.Attributes[k] = v
			default:
				f.Resource.Attributes[k] = v
			}
		}
		for k, v := range tags {
			switch {
			case strings.HasPrefix(k, "cis_") && v == "true":
				f.AddCompliance("cis_"+providerShort(provider), tags["cis_item_id"])
			case strings.HasPrefix(k, "nist_800_53") && v == "true":
				f.AddCompliance("nist_800_53", tags["nist_800_53_rev_5_item_id"], tags["nist_800_53_rev_4_item_id"])
			case strings.HasPrefix(k, "pci_dss") && v == "true":
				f.AddCompliance("pci_dss", tags["pci_dss_v321_item_id"], tags["pci_dss_v40_item_id"])
			case strings.HasPrefix(k, "hipaa") && v == "true":
				f.AddCompliance("hipaa", tags["hipaa_final_omnibus_security_rule_2013_item_id"], tags["hipaa_security_rule_2003_item_id"])
			case strings.HasPrefix(k, "gdpr") && v == "true":
				f.AddCompliance("gdpr", tags["gdpr_item_id"])
			}
		}
		if f.Resource.ID == "" {
			f.Resource.ID = f.Account + "/" + short
		}
		*out = append(*out, f)
	}
}

func providerShort(p string) string {
	if p == model.ProviderKubernetes {
		return "k8s"
	}
	return p
}
