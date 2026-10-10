package output

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// GitLabSASTVersion is the GitLab security report schema version written (sast-report-format,
// schema v15; fields `category`, `message`, `cve` and per-vulnerability `scanner` were removed
// in v15 and are not emitted).
const GitLabSASTVersion = "15.0.7"

// GitLabSAST renders open findings and scan gaps as a GitLab SAST report (`artifacts:
// reports: sast`). Cloud findings have no source file, so their location is the same
// cloud://<provider>/<resource-id> URI SARIF uses.
func GitLabSAST(findings []model.Finding) map[string]any {
	vulns := []map[string]any{}
	var start, end time.Time
	for _, f := range findings {
		if !f.LastSeen.IsZero() {
			if start.IsZero() || f.LastSeen.Before(start) {
				start = f.LastSeen
			}
			if f.LastSeen.After(end) {
				end = f.LastSeen
			}
		}
		if f.Status != model.Fail && !IsScanGap(f) {
			continue
		}
		loc := map[string]any{"file": firstNonEmpty(f.File, "cloud://"+f.Provider+"/"+f.Resource.ID)}
		if f.LineStart > 0 {
			loc["start_line"] = f.LineStart
			loc["end_line"] = max(f.LineEnd, f.LineStart)
		}
		ids := []map[string]any{{"type": "nimbus_canonical_id", "name": "nimbus " + f.CanonicalID, "value": f.CanonicalID}}
		if f.CheckID != "" && f.CheckID != f.CanonicalID {
			id := map[string]any{"type": firstNonEmpty(f.Source, "check") + "_check_id", "name": firstNonEmpty(f.Source, "check") + " " + f.CheckID, "value": f.CheckID}
			if strings.HasPrefix(strings.ToUpper(f.CheckID), "CVE-") {
				id = map[string]any{"type": "cve", "name": f.CheckID, "value": f.CheckID, "url": "https://nvd.nist.gov/vuln/detail/" + f.CheckID}
			}
			ids = append(ids, id)
		}
		v := map[string]any{
			"id":          gitlabUUID(f.ID),
			"name":        firstNonEmpty(f.Title, f.CanonicalID),
			"description": firstNonEmpty(f.Description, f.Title, f.CanonicalID),
			"severity":    gitlabSeverity(f),
			"location":    loc,
			"identifiers": ids,
		}
		if f.Remediation != "" {
			v["solution"] = f.Remediation
		}
		vulns = append(vulns, v)
	}
	if start.IsZero() {
		start = time.Unix(0, 0)
		end = start
	}
	tool := func() map[string]any {
		return map[string]any{"id": "nimbus", "name": "nimbus cloud-posture", "version": ToolVersion, "vendor": map[string]any{"name": "nimbus"}, "url": "https://github.com/DreadpiratePickles/nimbus"}
	}
	return map[string]any{
		"version": GitLabSASTVersion,
		"scan": map[string]any{
			"analyzer": tool(), "scanner": tool(), "type": "sast", "status": "success",
			"start_time": start.UTC().Format("2006-01-02T15:04:05"),
			"end_time":   end.UTC().Format("2006-01-02T15:04:05"),
		},
		"vulnerabilities": vulns,
	}
}

func gitlabSeverity(f model.Finding) string {
	if IsScanGap(f) {
		return "High"
	}
	switch f.Severity {
	case model.Critical:
		return "Critical"
	case model.High:
		return "High"
	case model.Medium:
		return "Medium"
	case model.Low:
		return "Low"
	case model.Info:
		return "Info"
	}
	return "Unknown"
}

// gitlabUUID derives a stable RFC 4122-shaped id (version 5 bits) from the fingerprint, so a
// finding keeps its GitLab vulnerability id across pipelines.
func gitlabUUID(fp string) string {
	sum := sha256.Sum256([]byte("nimbus:" + fp))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}
