package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// KubescapeSupportedVersion: `kubescape scan --format json` from kubescape v3.x (the
// reporthandling v2 PostureReport: summaryDetails, resources[], results[]). v2.x output has the
// same top-level shape and parses as well.
const KubescapeSupportedVersion = "kubescape v3.x JSON (--format json, PostureReport v2)"

// Kubescape maps each (resource, control) pair in results[] to a finding.
//
// Assumptions about the v3 format (documented because upstream has no stable schema doc):
//   - results[].resourceID matches resources[].resourceID; resources[].object is the
//     Kubernetes object (kind, metadata.name, metadata.namespace). When the object is missing
//     the ID is split as "<group>/<version>/<namespace>/<Kind>/<name>" (namespace empty for
//     cluster-scoped objects; file scans prefix "path=<n>/api=").
//   - results[].controls[].status is {"status": passed|failed|skipped|excluded|irrelevant}
//     (a bare string is accepted too). failed -> FAIL, passed -> PASS, anything else -> SKIP.
//   - results controls carry no severity; it comes from summaryDetails.controls[id].scoreFactor
//     (the control's base score, 1-10) using Kubescape's own bands: >=9 CRITICAL, >=7 HIGH,
//     >=4 MEDIUM, else LOW. An explicit "severity" string, where present, wins.
//   - clusterName (top level) becomes the finding account; Options.Account still adds the label.
type Kubescape struct{}

func (Kubescape) Name() string             { return "kubescape" }
func (Kubescape) SupportedVersion() string { return KubescapeSupportedVersion }

func (Kubescape) Detect(filename string, data []byte) bool {
	return bytes.Contains(data, []byte(`"summaryDetails"`)) && (bytes.Contains(data, []byte(`"results"`)) || bytes.Contains(data, []byte(`"resources"`)))
}

func kubescapeSeverity(scoreFactor float64) model.Severity {
	switch {
	case scoreFactor >= 9:
		return model.Critical
	case scoreFactor >= 7:
		return model.High
	case scoreFactor >= 4:
		return model.Medium
	}
	return model.Low
}

func (k Kubescape) Parse(data []byte, opts Options) ([]model.Finding, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if _, ok := doc["summaryDetails"]; !ok {
		return nil, fmt.Errorf("not a kubescape report: no summaryDetails")
	}
	ctrlMeta := sub(sub(doc, "summaryDetails"), "controls")
	resources := map[string]map[string]any{}
	for _, r := range list(doc, "resources") {
		if m, ok := r.(map[string]any); ok {
			resources[str(m, "resourceID")] = m
		}
	}
	cluster := str(doc, "clusterName")
	var out []model.Finding
	for _, r := range list(doc, "results") {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		rid := str(rm, "resourceID")
		res, file := k.resource(rid, resources[rid])
		for _, c := range list(rm, "controls") {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, k.finding(cm, ctrlMeta, rid, res, file, cluster))
		}
	}
	return out, nil
}

func (Kubescape) resource(rid string, entry map[string]any) (model.Resource, string) {
	obj := sub(entry, "object")
	meta := sub(obj, "metadata")
	kind, name, ns := str(obj, "kind"), str(meta, "name"), str(meta, "namespace")
	if kind == "" || name == "" {
		id := rid
		if i := strings.Index(id, "api="); i >= 0 {
			id = id[i+len("api="):]
		}
		parts := strings.Split(id, "/")
		n := len(parts)
		if n >= 2 {
			kind, name = parts[n-2], parts[n-1]
		}
		if n >= 3 {
			ns = parts[n-3]
		}
	}
	file := str(sub(entry, "source"), "relativePath")
	return k8sResource(kind, ns, name), file
}

func (Kubescape) finding(c, ctrlMeta map[string]any, rid string, res model.Resource, file, cluster string) model.Finding {
	id := str(c, "controlID")
	meta := sub(ctrlMeta, id)
	raw := str(sub(c, "status"), "status")
	if raw == "" {
		raw = str(c, "status")
	}
	status := model.Skip
	switch strings.ToLower(raw) {
	case "failed":
		status = model.Fail
	case "passed":
		status = model.Pass
	}
	sev := model.Info
	if s := firstNonEmpty(str(c, "severity"), str(meta, "severity")); s != "" {
		sev = model.ParseSeverity(s)
	} else if sf, ok := floatOf(meta["scoreFactor"]); ok {
		sev = kubescapeSeverity(sf)
	} else if sf, ok := floatOf(c["baseScore"]); ok {
		sev = kubescapeSeverity(sf)
	}
	// Fresh copy of the resource: attributes are per finding.
	r := res
	r.Attributes = map[string]any{}
	for k, v := range res.Attributes {
		r.Attributes[k] = v
	}
	r.Relations = append([]model.Relation(nil), res.Relations...)
	r.Related = append([]string(nil), res.Related...)
	r.Attributes["kubescape_resource_id"] = rid
	failed, fixes := kubescapePaths(c)
	if len(failed) > 0 {
		r.Attributes["failed_paths"] = failed
	}
	if len(fixes) > 0 {
		r.Attributes["fix_paths"] = fixes
	}
	if sf, ok := floatOf(meta["scoreFactor"]); ok {
		r.Attributes["score_factor"] = sf
	}
	rem := "See https://hub.armosec.io/docs/" + strings.ToLower(id)
	if len(fixes) > 0 {
		rem = "Set " + strings.Join(fixes, ", ") + ". " + rem
	}
	name := firstNonEmpty(str(c, "name"), str(meta, "name"))
	desc := name
	if len(failed) > 0 {
		desc = fmt.Sprintf("%s: failed at %s", name, strings.Join(failed, ", "))
	}
	return model.Finding{
		Source:      "kubescape",
		CheckID:     id,
		Title:       name,
		Description: desc,
		Severity:    sev,
		Status:      status,
		Provider:    model.ProviderKubernetes,
		Account:     cluster,
		File:        file,
		Remediation: rem,
		Resource:    r,
		Tags:        map[string]string{"kubescape_status": strings.ToLower(raw)},
		Raw:         rawOf(c),
	}
}

// kubescapePaths collects failed/review/delete paths and "path=value" fixes from the control's
// rules (rules[].paths[] in v3; failedPaths/fixPaths lists in older output).
func kubescapePaths(c map[string]any) (failed, fixes []string) {
	seen := map[string]bool{}
	add := func(dst *[]string, s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			*dst = append(*dst, s)
		}
	}
	fix := func(fp map[string]any) {
		if p := str(fp, "path"); p != "" {
			if v := str(fp, "value"); v != "" {
				add(&fixes, p+"="+v)
			} else {
				add(&fixes, p)
			}
		}
	}
	for _, ru := range list(c, "rules") {
		rm, ok := ru.(map[string]any)
		if !ok {
			continue
		}
		for _, p := range list(rm, "paths") {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			add(&failed, firstNonEmpty(str(pm, "failedPath"), str(pm, "reviewPath"), str(pm, "deletePath")))
			fix(sub(pm, "fixPath"))
		}
		for _, p := range list(rm, "failedPaths") {
			if s, ok := p.(string); ok {
				add(&failed, s)
			}
		}
		for _, p := range list(rm, "fixPaths") {
			if pm, ok := p.(map[string]any); ok {
				fix(pm)
			}
		}
	}
	return failed, fixes
}
