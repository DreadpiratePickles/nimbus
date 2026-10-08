package adapters

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Prowler supports the OCSF JSON output of Prowler v4/v5 (`-M json-ocsf`) and the
// flat JSON of Prowler v3 (`-M json`).
type Prowler struct{}

func (Prowler) Name() string { return "prowler" }

func (Prowler) Detect(filename string, data []byte) bool {
	if strings.Contains(filename, "prowler") || strings.HasSuffix(filename, ".ocsf.json") {
		return true
	}
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 || trim[0] != '[' {
		return false
	}
	var probe []map[string]json.RawMessage
	if err := json.Unmarshal(trim, &probe); err != nil || len(probe) == 0 {
		return false
	}
	_, ocsf := probe[0]["finding_info"]
	_, v3 := probe[0]["CheckID"]
	return ocsf || v3
}

func (p Prowler) Parse(data []byte, opts Options) ([]model.Finding, error) {
	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	out := make([]model.Finding, 0, len(rows))
	for _, r := range rows {
		if _, ok := r["finding_info"]; ok {
			out = append(out, p.parseOCSF(r))
		} else {
			out = append(out, p.parseV3(r))
		}
	}
	return out, nil
}

func (Prowler) parseOCSF(r map[string]any) model.Finding {
	info := sub(r, "finding_info")
	meta := sub(r, "metadata")
	cloud := sub(r, "cloud")
	acct := sub(cloud, "account")
	rem := sub(r, "remediation")
	unmapped := sub(r, "unmapped")
	f := model.Finding{
		Source:      "prowler",
		CheckID:     str(meta, "event_code"),
		Title:       str(info, "title"),
		Description: firstNonEmpty(str(r, "risk_details"), str(info, "desc"), str(r, "message")),
		Severity:    model.ParseSeverity(str(r, "severity")),
		Status:      model.ParseStatus(str(r, "status_code")),
		Provider:    model.NormalizeProvider(str(cloud, "provider")),
		Account:     firstNonEmpty(str(acct, "uid"), str(acct, "name")),
		Region:      str(cloud, "region"),
		Remediation: str(rem, "desc"),
		Raw:         rawOf(r),
	}
	if f.CheckID == "" {
		f.CheckID = str(unmapped, "check_id")
	}
	if res := list(r, "resources"); len(res) > 0 {
		if m, ok := res[0].(map[string]any); ok {
			f.Resource = model.Resource{
				ID:   str(m, "uid"),
				Name: str(m, "name"),
				Type: str(m, "type"),
			}
			if d, ok := m["data"].(map[string]any); ok {
				f.Resource.Attributes = d
				f.Resource.Related = relatedFromAttrs(d)
			}
			if g := sub(m, "group"); len(g) > 0 {
				if f.Tags == nil {
					f.Tags = map[string]string{}
				}
				f.Tags["service"] = str(g, "name")
			}
		}
	}
	if comp, ok := unmapped["compliance"].(map[string]any); ok {
		for fw, ctrls := range comp {
			key := normalizeFrameworkKey(fw)
			if key == "" {
				continue
			}
			if arr, ok := ctrls.([]any); ok {
				for _, c := range arr {
					f.AddCompliance(key, strings.TrimSpace(toString(c)))
				}
			}
		}
	}
	if cats := str(unmapped, "categories"); cats != "" {
		if f.Tags == nil {
			f.Tags = map[string]string{}
		}
		f.Tags["categories"] = cats
	}
	return f
}

func (Prowler) parseV3(r map[string]any) model.Finding {
	f := model.Finding{
		Source:      "prowler",
		CheckID:     str(r, "CheckID"),
		Title:       str(r, "CheckTitle"),
		Description: firstNonEmpty(str(r, "Risk"), str(r, "Description"), str(r, "StatusExtended")),
		Severity:    model.ParseSeverity(str(r, "Severity")),
		Status:      model.ParseStatus(str(r, "Status")),
		Provider:    model.NormalizeProvider(str(r, "Provider")),
		Account:     firstNonEmpty(str(r, "AccountId"), str(r, "SubscriptionId"), str(r, "ProjectId")),
		Region:      firstNonEmpty(str(r, "Region"), str(r, "Location")),
		Remediation: str(sub(sub(r, "Remediation"), "Recommendation"), "Text"),
		Resource: model.Resource{
			ID:   firstNonEmpty(str(r, "ResourceArn"), str(r, "ResourceId")),
			Name: firstNonEmpty(str(r, "ResourceName"), str(r, "ResourceId")),
			Type: str(r, "ResourceType"),
		},
		Raw: rawOf(r),
	}
	if comp, ok := r["Compliance"].(map[string]any); ok {
		for fw, ctrls := range comp {
			key := normalizeFrameworkKey(fw)
			if key == "" {
				continue
			}
			if arr, ok := ctrls.([]any); ok {
				for _, c := range arr {
					f.AddCompliance(key, toString(c))
				}
			}
		}
	}
	return f
}

// normalizeFrameworkKey folds Prowler's many framework labels onto catalog keys.
func normalizeFrameworkKey(fw string) string {
	l := strings.ToLower(fw)
	switch {
	case strings.HasPrefix(l, "cis_") || strings.HasPrefix(l, "cis-"):
		switch {
		case strings.Contains(l, "aws"):
			return "cis_aws"
		case strings.Contains(l, "azure"):
			return "cis_azure"
		case strings.Contains(l, "gcp"):
			return "cis_gcp"
		case strings.Contains(l, "kubernetes") || strings.Contains(l, "eks"):
			return "cis_k8s"
		case strings.Contains(l, "github"):
			return "cis_github"
		}
		return "cis"
	case strings.Contains(l, "nist") && strings.Contains(l, "800-53"):
		return "nist_800_53"
	case strings.Contains(l, "nist") && strings.Contains(l, "csf"):
		return "nist_csf"
	case strings.HasPrefix(l, "pci"):
		return "pci_dss"
	case strings.HasPrefix(l, "hipaa"):
		return "hipaa"
	case strings.HasPrefix(l, "gdpr"):
		return "gdpr"
	case strings.HasPrefix(l, "iso27001") || strings.HasPrefix(l, "iso_27001") || strings.HasPrefix(l, "iso-27001"):
		return "iso_27001"
	case strings.HasPrefix(l, "soc2"):
		return "soc2"
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// relatedFromAttrs pulls relationship hints that tools commonly include in resource details.
func relatedFromAttrs(d map[string]any) []string {
	var rel []string
	for _, k := range []string{"iam_role", "role_arn", "instance_profile", "IamInstanceProfile", "service_account", "serviceAccountName", "security_groups", "SecurityGroups", "vpc_id", "subnet_id", "cluster", "cluster_name", "namespace"} {
		switch v := d[k].(type) {
		case string:
			if v != "" {
				rel = append(rel, v)
			}
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					rel = append(rel, s)
				} else if m, ok := x.(map[string]any); ok {
					if id := str(m, "GroupId", "id", "arn"); id != "" {
						rel = append(rel, id)
					}
				}
			}
		case map[string]any:
			if id := str(v, "Arn", "arn", "id", "Id"); id != "" {
				rel = append(rel, id)
			}
		}
	}
	return rel
}
