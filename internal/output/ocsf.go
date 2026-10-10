package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// ToolVersion is the producer version written into SARIF, OCSF, ASFF and GitLab reports.
var ToolVersion = "0.1.0"

// OCSF schema constants: Detection Finding (class 2004) in category Findings (2), OCSF 1.6.0.
const (
	OCSFVersion        = "1.6.0"
	OCSFClassUID       = 2004
	OCSFCategoryUID    = 2
	OCSFActivityCreate = 1
)

var ocsfSeverity = map[model.Severity]struct {
	id   int
	name string
}{
	model.Info: {1, "Informational"}, model.Low: {2, "Low"}, model.Medium: {3, "Medium"},
	model.High: {4, "High"}, model.Critical: {5, "Critical"},
}

// ocsfStatus maps nimbus status onto OCSF finding status_id: FAIL → New (1), PASS → Resolved
// (4), SKIP → Suppressed (3), ERROR → Other (99). status_code keeps the nimbus value, which is
// where Prowler's json-ocsf puts PASS/FAIL/MANUAL.
var ocsfStatus = map[model.Status]struct {
	id   int
	name string
}{
	model.Fail: {1, "New"}, model.Pass: {4, "Resolved"}, model.Skip: {3, "Suppressed"}, model.Error: {99, "Other"},
}

// OCSF renders findings as an array of OCSF 1.6 Detection Finding events (the same envelope
// as Prowler's `-M json-ocsf`). Standard attributes carry everything OCSF has a slot for; the
// nimbus-only fields (canonical id, weaknesses, compliance, tags, file location, typed
// relations) go under `unmapped`, so a nimbus → OCSF → nimbus round trip is lossless
// (Finding.Raw excepted).
func OCSF(findings []model.Finding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, ocsfFinding(f))
	}
	return out
}

func ocsfFinding(f model.Finding) map[string]any {
	sev, ok := ocsfSeverity[f.Severity]
	if !ok {
		sev = struct {
			id   int
			name string
		}{0, "Unknown"}
	}
	st, ok := ocsfStatus[f.Status]
	if !ok {
		st = ocsfStatus[model.Error]
	}
	last := f.LastSeen.UTC()
	first := f.FirstSeen.UTC()
	info := map[string]any{
		"uid":                f.ID,
		"title":              firstNonEmpty(f.Title, f.CanonicalID),
		"types":              []string{f.CanonicalID},
		"first_seen_time":    first.UnixMilli(),
		"first_seen_time_dt": first.Format(time.RFC3339Nano),
		"last_seen_time":     last.UnixMilli(),
		"last_seen_time_dt":  last.Format(time.RFC3339Nano),
		"created_time":       first.UnixMilli(),
		"created_time_dt":    first.Format(time.RFC3339Nano),
	}
	if f.Description != "" {
		info["desc"] = f.Description
	}
	if f.Source != "" {
		info["product"] = map[string]any{"name": f.Source}
	}
	if f.CheckID != "" {
		info["analytic"] = map[string]any{"uid": f.CheckID, "name": f.CheckID, "type_id": 1, "type": "Rule"}
	}
	meta := map[string]any{
		"version": OCSFVersion,
		"product": map[string]any{
			"name": "cloud-posture", "vendor_name": "nimbus", "uid": "nimbus", "version": ToolVersion,
			"url_string": "https://github.com/DreadpiratePickles/nimbus",
		},
		"uid":      f.ID,
		"profiles": []string{"cloud"},
	}
	if f.CheckID != "" {
		meta["event_code"] = f.CheckID
	}
	if f.ScanID != "" {
		meta["correlation_uid"] = f.ScanID
	}
	cloud := map[string]any{"provider": firstNonEmpty(f.Provider, model.ProviderUnknown)}
	if f.Region != "" {
		cloud["region"] = f.Region
	}
	if f.Account != "" {
		acct := map[string]any{"uid": f.Account}
		if l := f.Tags["account_label"]; l != "" {
			acct["name"] = l
		}
		cloud["account"] = acct
	}
	res := map[string]any{"uid": firstNonEmpty(f.Resource.ID, f.Resource.Name, f.File, f.ID)}
	if f.Resource.Name != "" {
		res["name"] = f.Resource.Name
	}
	if f.Resource.Type != "" {
		res["type"] = f.Resource.Type
	}
	if f.Region != "" {
		res["region"] = f.Region
	}
	if len(f.Resource.Attributes) > 0 {
		res["data"] = f.Resource.Attributes
	}
	ev := map[string]any{
		"activity_id": OCSFActivityCreate, "activity_name": "Create",
		"category_uid": OCSFCategoryUID, "category_name": "Findings",
		"class_uid": OCSFClassUID, "class_name": "Detection Finding",
		"type_uid": OCSFClassUID*100 + OCSFActivityCreate, "type_name": "Detection Finding: Create",
		"severity_id": sev.id, "severity": sev.name,
		"status_id": st.id, "status": st.name, "status_code": string(f.Status),
		"time": last.UnixMilli(), "time_dt": last.Format(time.RFC3339Nano),
		"message":      firstNonEmpty(f.Title, f.CanonicalID),
		"metadata":     meta,
		"cloud":        cloud,
		"finding_info": info,
		"resources":    []any{res},
		"osint":        []any{},
	}
	if f.Remediation != "" {
		ev["remediation"] = map[string]any{"desc": f.Remediation}
	}
	if strings.HasPrefix(strings.ToUpper(f.CheckID), "CVE-") {
		cve := map[string]any{"uid": f.CheckID}
		if score, err := parseFloat(f.Tags["cvss"]); err == nil {
			cve["cvss"] = []any{map[string]any{"base_score": score, "version": firstNonEmpty(f.Tags["cvss_version"], "3.1")}}
		}
		vuln := map[string]any{"cve": cve, "title": firstNonEmpty(f.Title, f.CheckID), "severity": sev.name}
		if u := f.Tags["primary_url"]; u != "" {
			vuln["references"] = []string{u}
		}
		ev["vulnerabilities"] = []any{vuln}
	}
	un := map[string]any{"canonical_id": f.CanonicalID}
	if f.Source != "" {
		un["source"] = f.Source
	}
	if f.CheckID != "" {
		un["check_id"] = f.CheckID
	}
	if len(f.Weaknesses) > 0 {
		un["weaknesses"] = f.Weaknesses
	}
	if len(f.Compliance) > 0 {
		un["compliance"] = f.Compliance // same place and shape as Prowler's json-ocsf
	}
	if len(f.Tags) > 0 {
		un["tags"] = f.Tags
	}
	if f.ScanID != "" {
		un["scan_id"] = f.ScanID
	}
	if f.File != "" {
		un["file"] = f.File
	}
	if f.LineStart > 0 {
		un["line_start"] = f.LineStart
	}
	if f.LineEnd > 0 {
		un["line_end"] = f.LineEnd
	}
	if len(f.Resource.Related) > 0 {
		un["related"] = f.Resource.Related
	}
	if len(f.Resource.Relations) > 0 {
		un["relations"] = f.Resource.Relations
	}
	ev["unmapped"] = un
	return ev
}

func parseFloat(s string) (float64, error) {
	var f float64
	if strings.TrimSpace(s) == "" {
		return 0, fmt.Errorf("empty")
	}
	_, err := fmt.Sscanf(s, "%g", &f)
	return f, err
}

// ParseOCSF reads OCSF Detection Finding events (a JSON array, one object, or JSON lines),
// whether written by nimbus or by another producer such as Prowler, into findings. It reads the
// standard attributes first and the nimbus `unmapped` extras when present.
func ParseOCSF(data []byte) ([]model.Finding, error) {
	events, err := jsonRecords(data)
	if err != nil {
		return nil, fmt.Errorf("ocsf: %w", err)
	}
	out := make([]model.Finding, 0, len(events))
	for i, raw := range events {
		var ev map[string]any
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("ocsf: event %d: %w", i, err)
		}
		if cls, _ := ev["class_uid"].(float64); int(cls) != OCSFClassUID {
			return nil, fmt.Errorf("ocsf: event %d: class_uid %v is not Detection Finding (2004)", i, ev["class_uid"])
		}
		f, err := ocsfToFinding(ev)
		if err != nil {
			return nil, fmt.Errorf("ocsf: event %d: %w", i, err)
		}
		out = append(out, f)
	}
	return out, nil
}

func ocsfToFinding(ev map[string]any) (model.Finding, error) {
	info := obj(ev, "finding_info")
	meta := obj(ev, "metadata")
	cloud := obj(ev, "cloud")
	un := obj(ev, "unmapped")
	f := model.Finding{
		ID:          firstNonEmpty(sval(info, "uid"), sval(meta, "uid")),
		Source:      firstNonEmpty(sval(un, "source"), sval(obj(info, "product"), "name"), strings.ToLower(sval(obj(meta, "product"), "name"))),
		CheckID:     firstNonEmpty(sval(un, "check_id"), sval(meta, "event_code"), sval(obj(info, "analytic"), "uid")),
		CanonicalID: sval(un, "canonical_id"),
		Title:       firstNonEmpty(sval(info, "title"), sval(ev, "message")),
		Description: sval(info, "desc"),
		Provider:    model.NormalizeProvider(sval(cloud, "provider")),
		Account:     firstNonEmpty(sval(obj(cloud, "account"), "uid"), sval(obj(cloud, "account"), "name")),
		Region:      sval(cloud, "region"),
		Remediation: sval(obj(ev, "remediation"), "desc"),
		ScanID:      firstNonEmpty(sval(un, "scan_id"), sval(meta, "correlation_uid")),
		File:        sval(un, "file"),
	}
	if p := sval(cloud, "provider"); f.Provider == model.ProviderUnknown && p != "" && p != model.ProviderUnknown {
		f.Provider = strings.ToLower(p)
	}
	f.Severity = ocsfSeverityFrom(ev)
	f.Status = ocsfStatusFrom(ev)
	if res, ok := ev["resources"].([]any); ok && len(res) > 0 {
		if r, ok := res[0].(map[string]any); ok {
			f.Resource = model.Resource{ID: sval(r, "uid"), Name: sval(r, "name"), Type: sval(r, "type")}
			if d, ok := r["data"].(map[string]any); ok {
				f.Resource.Attributes = d
			}
		}
	}
	if n, ok := un["line_start"].(float64); ok {
		f.LineStart = int(n)
	}
	if n, ok := un["line_end"].(float64); ok {
		f.LineEnd = int(n)
	}
	if err := remarshal(un["weaknesses"], &f.Weaknesses); err != nil {
		return f, fmt.Errorf("unmapped.weaknesses: %w", err)
	}
	if err := remarshal(un["compliance"], &f.Compliance); err != nil {
		// Prowler writes compliance values as arrays of strings too; anything else is skipped.
		f.Compliance = nil
	}
	if err := remarshal(un["tags"], &f.Tags); err != nil {
		return f, fmt.Errorf("unmapped.tags: %w", err)
	}
	if err := remarshal(un["related"], &f.Resource.Related); err != nil {
		return f, fmt.Errorf("unmapped.related: %w", err)
	}
	if err := remarshal(un["relations"], &f.Resource.Relations); err != nil {
		return f, fmt.Errorf("unmapped.relations: %w", err)
	}
	f.FirstSeen = ocsfTime(info, "first_seen_time")
	f.LastSeen = ocsfTime(info, "last_seen_time")
	if f.LastSeen.IsZero() {
		f.LastSeen = ocsfTime(ev, "time")
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = f.LastSeen
	}
	return f, nil
}

func ocsfSeverityFrom(ev map[string]any) model.Severity {
	if id, ok := ev["severity_id"].(float64); ok {
		for s, v := range ocsfSeverity {
			if v.id == int(id) {
				return s
			}
		}
		if int(id) == 6 { // Fatal
			return model.Critical
		}
	}
	return model.ParseSeverity(sval(ev, "severity"))
}

func ocsfStatusFrom(ev map[string]any) model.Status {
	if code := strings.ToUpper(sval(ev, "status_code")); code != "" {
		switch model.Status(code) {
		case model.Fail, model.Pass, model.Skip, model.Error:
			return model.Status(code)
		}
		if st := model.ParseStatus(code); st != model.Error {
			return st
		}
	}
	switch id, _ := ev["status_id"].(float64); int(id) {
	case 1, 2: // New, In Progress
		return model.Fail
	case 3: // Suppressed
		return model.Skip
	case 4: // Resolved
		return model.Pass
	}
	return model.Error
}

// ocsfTime prefers the RFC 3339 `<name>_dt` sibling (nanosecond precision) over the epoch
// milliseconds; an epoch below 1e11 is taken as seconds (some producers write seconds).
func ocsfTime(m map[string]any, name string) time.Time {
	if s := sval(m, name+"_dt"); s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC()
		}
	}
	if n, ok := m[name].(float64); ok && n > 0 {
		if n < 1e11 {
			return time.Unix(int64(n), 0).UTC()
		}
		return time.UnixMilli(int64(n)).UTC()
	}
	return time.Time{}
}

func obj(m map[string]any, k string) map[string]any {
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func sval(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprint(v)
	}
	return ""
}

func remarshal(v any, dst any) error {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

// jsonRecords splits a JSON array, a single object, or JSON lines into raw records.
func jsonRecords(data []byte) ([]json.RawMessage, error) {
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 {
		return nil, nil
	}
	switch trim[0] {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(trim, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	case '{':
		var one json.RawMessage
		dec := json.NewDecoder(bytes.NewReader(trim))
		var out []json.RawMessage
		for dec.More() {
			if err := dec.Decode(&one); err != nil {
				return nil, err
			}
			out = append(out, append(json.RawMessage(nil), one...))
		}
		return out, nil
	}
	return nil, fmt.Errorf("expected a JSON array, object or JSON lines")
}
