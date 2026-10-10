package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// KubeBenchSupportedVersion: `kube-bench run --json` from kube-bench v0.x — the current
// {"Controls": [...], "Totals": {...}} object, the older bare array of Controls, and the
// oldest form (one Controls object per target, concatenated).
const KubeBenchSupportedVersion = "kube-bench v0.x JSON (--json; Controls/Totals and legacy []Controls)"

// KubeBench maps each tests[].results[] entry to a finding.
//
// Mapping decisions:
//   - CheckID = test_number ("1.2.16") and compliance cis_k8s: [test_number];
//   - PASS -> PASS, FAIL -> FAIL; WARN (kube-bench's "manual / could not determine" outcome)
//     and INFO -> SKIP, keeping the original in tag kube_bench_status;
//   - kube-bench has no severity: scored (Automated) tests are MEDIUM, unscored (Manual) LOW;
//   - the resource is the node type the benchmark section targets ("master", "node", "etcd",
//     "policies", ...): ID "cluster/nodetype/<type>", since kube-bench does not name the host.
type KubeBench struct{}

func (KubeBench) Name() string             { return "kube-bench" }
func (KubeBench) SupportedVersion() string { return KubeBenchSupportedVersion }

func (KubeBench) Detect(filename string, data []byte) bool {
	return bytes.Contains(data, []byte(`"test_number"`)) && bytes.Contains(data, []byte(`"node_type"`))
}

func (k KubeBench) Parse(data []byte, opts Options) ([]model.Finding, error) {
	var controls []map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var v any
		if err := dec.Decode(&v); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		switch t := v.(type) {
		case []any:
			controls = appendMaps(controls, t)
		case map[string]any:
			if cs, ok := t["Controls"].([]any); ok {
				controls = appendMaps(controls, cs)
			} else if _, ok := t["tests"]; ok {
				controls = append(controls, t)
			}
		}
	}
	if len(controls) == 0 {
		return nil, fmt.Errorf("no kube-bench Controls found")
	}
	var out []model.Finding
	for _, c := range controls {
		for _, tst := range list(c, "tests") {
			tm, ok := tst.(map[string]any)
			if !ok {
				continue
			}
			for _, r := range list(tm, "results") {
				if rm, ok := r.(map[string]any); ok {
					out = append(out, k.finding(c, tm, rm))
				}
			}
		}
	}
	return out, nil
}

func appendMaps(dst []map[string]any, src []any) []map[string]any {
	for _, x := range src {
		if m, ok := x.(map[string]any); ok {
			dst = append(dst, m)
		}
	}
	return dst
}

func (KubeBench) finding(control, test, r map[string]any) model.Finding {
	nodeType := firstNonEmpty(str(control, "node_type"), "unknown")
	num := str(r, "test_number")
	raw := strings.ToUpper(str(r, "status"))
	var status model.Status
	switch raw {
	case "PASS":
		status = model.Pass
	case "FAIL":
		status = model.Fail
	default: // WARN, INFO: manual or informational, not a verdict
		status = model.Skip
	}
	scored, _ := r["scored"].(bool)
	sev := model.Low
	if scored {
		sev = model.Medium
	}
	desc := str(r, "test_desc")
	var parts []string
	if e := str(r, "expected_result"); e != "" {
		parts = append(parts, "Expected: "+e)
	}
	if a := str(r, "actual_value"); a != "" {
		parts = append(parts, "Actual: "+a)
	}
	if rs := str(r, "reason"); rs != "" {
		parts = append(parts, "Reason: "+rs)
	}
	if len(parts) > 0 {
		desc += "\n\n" + strings.Join(parts, "\n")
	}
	attrs := map[string]any{
		"node_type":    nodeType,
		"benchmark":    str(control, "version"),
		"control_id":   str(control, "id"),
		"control_text": str(control, "text"),
		"section":      str(test, "section"),
		"section_desc": str(test, "desc"),
		"scored":       scored,
		"audit":        str(r, "audit"),
		"actual_value": str(r, "actual_value"),
		"expected":     str(r, "expected_result"),
		"kube_version": str(control, "detected_version"),
	}
	for k, v := range attrs {
		if v == "" {
			delete(attrs, k)
		}
	}
	f := model.Finding{
		Source:      "kube-bench",
		CheckID:     num,
		Title:       str(r, "test_desc"),
		Description: desc,
		Severity:    sev,
		Status:      status,
		Provider:    model.ProviderKubernetes,
		Remediation: str(r, "remediation"),
		Resource: model.Resource{
			ID:         "cluster/nodetype/" + nodeType,
			Type:       "k8s_node_type",
			Name:       nodeType,
			Attributes: attrs,
		},
		Tags: map[string]string{"kube_bench_status": raw, "benchmark": str(control, "version"), "node_type": nodeType},
		Raw:  rawOf(r),
	}
	f.AddCompliance("cis_k8s", num)
	return f
}
