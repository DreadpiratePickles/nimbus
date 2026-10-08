package adapters

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Checkov parses `checkov -o json` output: a single report object or a list of them.
type Checkov struct{}

func (Checkov) Name() string { return "checkov" }

func (Checkov) Detect(filename string, data []byte) bool {
	if strings.Contains(filename, "checkov") || strings.HasPrefix(filename, "results_json") {
		return true
	}
	return bytes.Contains(data[:min(len(data), 4096)], []byte(`"check_type"`)) && bytes.Contains(data[:min(len(data), 4096)], []byte(`"results"`))
}

func (c Checkov) Parse(data []byte, opts Options) ([]model.Finding, error) {
	trim := bytes.TrimSpace(data)
	var reports []map[string]any
	if len(trim) > 0 && trim[0] == '[' {
		if err := json.Unmarshal(trim, &reports); err != nil {
			return nil, err
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal(trim, &one); err != nil {
			return nil, err
		}
		reports = []map[string]any{one}
	}
	var out []model.Finding
	for _, rep := range reports {
		checkType := str(rep, "check_type")
		results := sub(rep, "results")
		for _, kind := range []struct {
			key    string
			status model.Status
		}{{"failed_checks", model.Fail}, {"passed_checks", model.Pass}, {"skipped_checks", model.Skip}} {
			for _, item := range list(results, kind.key) {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				out = append(out, c.one(m, checkType, kind.status))
			}
		}
	}
	return out, nil
}

func (Checkov) one(m map[string]any, checkType string, status model.Status) model.Finding {
	provider := providerFromCheckov(str(m, "check_id"), checkType)
	lineStart, lineEnd := 0, 0
	if lr := list(m, "file_line_range"); len(lr) == 2 {
		if a, ok := lr[0].(float64); ok {
			lineStart = int(a)
		}
		if b, ok := lr[1].(float64); ok {
			lineEnd = int(b)
		}
	}
	resource := str(m, "resource")
	f := model.Finding{
		Source:      "checkov",
		CheckID:     str(m, "check_id"),
		Title:       str(m, "check_name"),
		Description: str(m, "description"),
		Severity:    model.ParseSeverity(str(m, "severity")),
		Status:      status,
		Provider:    provider,
		Account:     "iac",
		File:        strings.TrimPrefix(str(m, "file_path"), "/"),
		LineStart:   lineStart,
		LineEnd:     lineEnd,
		Remediation: str(m, "guideline"),
		Resource: model.Resource{
			ID:   resource,
			Name: resourceNameFromCheckov(resource),
			Type: resourceTypeFromCheckov(resource),
		},
		Tags: map[string]string{"framework": checkType, "bc_check_id": str(m, "bc_check_id")},
		Raw:  rawOf(m),
	}
	if f.Resource.Attributes == nil {
		f.Resource.Attributes = map[string]any{}
	}
	f.Resource.Attributes["file"] = f.File
	if checkType == "secrets" {
		f.Severity = model.Critical
	}
	return f
}

func providerFromCheckov(checkID, checkType string) string {
	switch {
	case strings.HasPrefix(checkID, "CKV_AWS"), strings.HasPrefix(checkID, "CKV2_AWS"):
		return model.ProviderAWS
	case strings.HasPrefix(checkID, "CKV_AZURE"), strings.HasPrefix(checkID, "CKV2_AZURE"):
		return model.ProviderAzure
	case strings.HasPrefix(checkID, "CKV_GCP"), strings.HasPrefix(checkID, "CKV2_GCP"):
		return model.ProviderGCP
	case strings.HasPrefix(checkID, "CKV_OCI"):
		return model.ProviderOCI
	case strings.HasPrefix(checkID, "CKV_K8S"), strings.HasPrefix(checkID, "CKV2_K8S"), checkType == "kubernetes", checkType == "helm":
		return model.ProviderKubernetes
	case strings.HasPrefix(checkID, "CKV_GITHUB"), strings.HasPrefix(checkID, "CKV_GHA"):
		return model.ProviderGitHub
	}
	return model.ProviderIaC
}

func resourceTypeFromCheckov(resource string) string {
	if i := strings.Index(resource, "."); i > 0 {
		return resource[:i]
	}
	return resource
}

func resourceNameFromCheckov(resource string) string {
	if i := strings.LastIndex(resource, "."); i > 0 && i < len(resource)-1 {
		return resource[i+1:]
	}
	return resource
}
