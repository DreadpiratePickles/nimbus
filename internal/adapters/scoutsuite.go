package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// ScoutSuite parses scoutsuite_results_<provider>-<account>.js, a JS assignment
// wrapping one large JSON document. Pure JSON exports are accepted too.
type ScoutSuite struct{}

func (ScoutSuite) Name() string { return "scoutsuite" }

func (ScoutSuite) Detect(filename string, data []byte) bool {
	if strings.Contains(filename, "scoutsuite") || strings.Contains(filename, "scout_") {
		return true
	}
	head := data[:min(len(data), 512)]
	return bytes.HasPrefix(bytes.TrimSpace(head), []byte("scoutsuite_results"))
}

func (s ScoutSuite) Parse(data []byte, opts Options) ([]model.Finding, error) {
	trim := bytes.TrimSpace(data)
	if i := bytes.Index(trim, []byte("=")); bytes.HasPrefix(trim, []byte("scoutsuite_results")) && i > 0 {
		trim = bytes.TrimSpace(trim[i+1:])
	}
	trim = bytes.TrimSuffix(trim, []byte(";"))
	var doc map[string]any
	if err := json.Unmarshal(trim, &doc); err != nil {
		return nil, fmt.Errorf("scoutsuite results: %w", err)
	}
	provider := model.NormalizeProvider(str(doc, "provider_code"))
	account := firstNonEmpty(str(doc, "account_id"), str(doc, "subscription_id"), str(doc, "project_id"), str(doc, "organization_id"))
	services := sub(doc, "services")
	var out []model.Finding
	for svcName, svcAny := range services {
		svc, ok := svcAny.(map[string]any)
		if !ok {
			continue
		}
		findings := sub(svc, "findings")
		for fid, fAny := range findings {
			fm, ok := fAny.(map[string]any)
			if !ok {
				continue
			}
			base := model.Finding{
				Source:      "scoutsuite",
				CheckID:     fid,
				Title:       str(fm, "description"),
				Description: str(fm, "rationale"),
				Severity:    model.ParseSeverity(str(fm, "level")),
				Provider:    provider,
				Account:     account,
				Remediation: str(fm, "remediation"),
				Tags:        map[string]string{"service": svcName},
			}
			for _, c := range list(fm, "compliance") {
				if cm, ok := c.(map[string]any); ok {
					if key := normalizeFrameworkKey(strings.ReplaceAll(str(cm, "name"), " ", "_") + "_" + provider); key != "" {
						base.AddCompliance(key, str(cm, "reference"))
					}
				}
			}
			items := list(fm, "items")
			if len(items) == 0 {
				// Checked but nothing flagged: emit a single PASS so coverage shows up.
				f := base
				f.Status = model.Pass
				f.Resource = model.Resource{ID: account + "/" + svcName, Name: svcName, Type: svcName}
				f.Raw = rawOf(fm)
				out = append(out, f)
				continue
			}
			for _, it := range items {
				path, _ := it.(string)
				f := base
				f.Status = model.Fail
				f.Resource = s.resolveResource(svc, path)
				f.Region = regionFromPath(path)
				f.Raw = rawOf(map[string]any{"item": path, "finding": fid})
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// resolveResource walks the item path (e.g. "s3.buckets.my-bucket.acls") in the service tree
// to find the resource node and its display name.
func (ScoutSuite) resolveResource(svc map[string]any, path string) model.Resource {
	parts := strings.Split(path, ".")
	var node any = svc
	var resID, resType string
	var attrs map[string]any
	// parts[0] is the service name; walk from parts[1]
	for i := 1; i < len(parts); i++ {
		m, ok := node.(map[string]any)
		if !ok {
			break
		}
		next, ok := m[parts[i]]
		if !ok {
			break
		}
		if nm, ok := next.(map[string]any); ok {
			if _, hasName := nm["name"]; hasName || nm["id"] != nil || nm["arn"] != nil {
				resID = parts[i]
				resType = singular(parts[i-1])
				attrs = nm
			}
		}
		node = next
	}
	if resID == "" {
		resID = path
		resType = parts[0]
	}
	r := model.Resource{ID: resID, Name: resID, Type: resType}
	if attrs != nil {
		r.Name = firstNonEmpty(str(attrs, "name"), resID)
		if arn := firstNonEmpty(str(attrs, "arn"), str(attrs, "id")); arn != "" {
			r.ID = arn
		}
		r.Attributes = attrs
		r.Related = relatedFromAttrs(attrs)
	}
	return r
}

func regionFromPath(path string) string {
	parts := strings.Split(path, ".")
	for i, p := range parts {
		if p == "regions" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func singular(s string) string {
	if strings.HasSuffix(s, "ies") {
		return strings.TrimSuffix(s, "ies") + "y"
	}
	return strings.TrimSuffix(s, "s")
}
