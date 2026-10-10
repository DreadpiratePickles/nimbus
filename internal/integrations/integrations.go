// Package integrations delivers findings and attack paths to Slack, GitHub Issues and SIEMs.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

type Result struct {
	Channel   string `json:"channel"`
	FindingID string `json:"finding_id"`
	IssueID   string `json:"issue_id,omitempty"` // set by DispatchIssues (one ticket per Issue)
	Ref       string `json:"ref,omitempty"`      // issue URL, event id...
	Err       string `json:"error,omitempty"`
	Skipped   bool   `json:"skipped,omitempty"`
}

// Sink is one delivery target. Deliver returns an external reference for de-duplication.
type Sink interface {
	Name() string
	Deliver(ctx context.Context, f model.Finding, paths []model.AttackPath) (ref string, err error)
}

var httpClient = &redactingClient{c: newSinkHTTPClient()}

func envOr(envName, literal string) string {
	if literal != "" {
		return literal
	}
	if envName != "" {
		return os.Getenv(envName)
	}
	return ""
}

func postJSON(ctx context.Context, url string, headers map[string]string, body any) ([]byte, int, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, err := newRequest(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cloud-posture/0.1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return data, resp.StatusCode, nil
}

// ---------------------------------------------------------------- Slack

type Slack struct {
	WebhookURL string
	Channel    string
}

func (s *Slack) Name() string { return "slack" }

func (s *Slack) Deliver(ctx context.Context, f model.Finding, paths []model.AttackPath) (string, error) {
	if s.WebhookURL == "" {
		return "", fmt.Errorf("slack webhook URL not configured (SLACK_WEBHOOK_URL)")
	}
	emoji := map[model.Severity]string{model.Critical: ":rotating_light:", model.High: ":red_circle:", model.Medium: ":large_orange_circle:", model.Low: ":large_yellow_circle:", model.Info: ":white_circle:"}[f.Severity]
	text := fmt.Sprintf("%s *%s* `%s`\n*%s* in `%s` / %s %s\nResource: `%s`", emoji, f.Severity, f.CanonicalID, f.Title, f.Provider, f.Account, f.Region, f.Resource.ID)
	blocks := []map[string]any{
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text}},
	}
	if len(paths) > 0 {
		var names []string
		for _, p := range paths {
			names = append(names, fmt.Sprintf("• %s → _%s_ (score %.1f)", p.Name, p.Impact, p.Score))
		}
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": ":crossed_swords: *Part of attack paths*\n" + strings.Join(names, "\n")}})
	}
	if f.Remediation != "" {
		rem := f.Remediation
		if len(rem) > 400 {
			rem = rem[:397] + "..."
		}
		blocks = append(blocks, map[string]any{"type": "context", "elements": []map[string]any{{"type": "mrkdwn", "text": ":wrench: " + rem}}})
	}
	blocks = append(blocks, map[string]any{"type": "context", "elements": []map[string]any{{"type": "mrkdwn", "text": fmt.Sprintf("source: %s · check: %s · fix: `cloud-posture fix --finding %s --generate-terraform`", f.Source, f.CheckID, f.CanonicalID)}}})
	payload := map[string]any{"text": fmt.Sprintf("[%s] %s on %s", f.Severity, f.Title, f.Resource.Name), "blocks": blocks}
	if s.Channel != "" {
		payload["channel"] = s.Channel
	}
	body, code, err := postJSON(ctx, s.WebhookURL, nil, payload)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("slack responded %d: %s", code, strings.TrimSpace(string(body)))
	}
	return "sent", nil
}

// ---------------------------------------------------------------- GitHub Issues

type GitHubIssues struct {
	Repo    string // owner/name
	Token   string
	Labels  []string
	APIBase string
}

func (g *GitHubIssues) Name() string { return "github" }

func (g *GitHubIssues) api() string {
	if g.APIBase != "" {
		return strings.TrimRight(g.APIBase, "/")
	}
	return "https://api.github.com"
}

func (g *GitHubIssues) headers() map[string]string {
	return map[string]string{
		"Authorization":        "Bearer " + g.Token,
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
}

// Deliver creates one issue per finding fingerprint; the fingerprint is embedded in the body
// so a search can find an existing issue even when the local alert table was lost.
func (g *GitHubIssues) Deliver(ctx context.Context, f model.Finding, paths []model.AttackPath) (string, error) {
	if g.Token == "" {
		return "", fmt.Errorf("GitHub token not configured (GITHUB_TOKEN)")
	}
	if g.Repo == "" || !strings.Contains(g.Repo, "/") {
		return "", fmt.Errorf("github repo must be owner/name")
	}
	marker := "cloud-posture-fingerprint: " + f.ID
	if url, found := g.findExisting(ctx, marker); found {
		return url, nil
	}
	title := fmt.Sprintf("[%s] %s: %s", f.Severity, f.CanonicalID, f.Resource.Name)
	if len(title) > 200 {
		title = title[:200]
	}
	body := IssueBody(f, paths) + "\n\n<!-- " + marker + " -->\n"
	labels := append([]string{"security", "cloud-posture", "severity:" + strings.ToLower(string(f.Severity)), "provider:" + f.Provider}, g.Labels...)
	resp, code, err := postJSON(ctx, fmt.Sprintf("%s/repos/%s/issues", g.api(), g.Repo), g.headers(), map[string]any{"title": title, "body": body, "labels": labels})
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("github responded %d: %s", code, truncate(string(resp), 300))
	}
	var created struct {
		HTMLURL string `json:"html_url"`
	}
	_ = json.Unmarshal(resp, &created)
	return created.HTMLURL, nil
}

// Close resolves the issue when the finding passes again (comment + close as completed).
func (g *GitHubIssues) Close(ctx context.Context, f model.Finding, ref string) error {
	// ref is the issue html_url: https://github.com/owner/repo/issues/123
	i := strings.LastIndex(ref, "/issues/")
	if i < 0 {
		return fmt.Errorf("not an issue url: %s", ref)
	}
	num := ref[i+len("/issues/"):]
	url := fmt.Sprintf("%s/repos/%s/issues/%s", g.api(), g.Repo, num)
	if _, _, err := postJSON(ctx, url+"/comments", g.headers(), map[string]any{"body": fmt.Sprintf("✅ cloud-posture: finding `%s` on `%s` now passes (last scan %s). Closing.", f.CanonicalID, f.Resource.Name, f.LastSeen.Format(time.RFC3339))}); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"state": "closed", "state_reason": "completed"})
	req, err := newRequest(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range g.headers() {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("close issue: %d", resp.StatusCode)
	}
	return nil
}

func (g *GitHubIssues) findExisting(ctx context.Context, marker string) (string, bool) {
	q := fmt.Sprintf("repo:%s in:body \"%s\"", g.Repo, marker)
	req, _ := newRequest(ctx, http.MethodGet, g.api()+"/search/issues?per_page=1&q="+urlEncode(q), nil)
	for k, v := range g.headers() {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	var out struct {
		Items []struct {
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.Items) == 0 {
		return "", false
	}
	return out.Items[0].HTMLURL, true
}

// Whoami validates a token; used by `cloud-posture alert --check`.
func (g *GitHubIssues) Whoami(ctx context.Context) (string, error) {
	req, _ := newRequest(ctx, http.MethodGet, g.api()+"/user", nil)
	for k, v := range g.headers() {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("github /user responded %d", resp.StatusCode)
	}
	var u struct {
		Login string `json:"login"`
	}
	return u.Login, json.NewDecoder(resp.Body).Decode(&u)
}

func IssueBody(f model.Finding, paths []model.AttackPath) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", f.Title)
	fmt.Fprintf(&b, "| | |\n|---|---|\n| Severity | **%s** |\n| Canonical ID | `%s` |\n| Source | %s (`%s`) |\n| Provider / Account | %s / %s |\n| Region | %s |\n| Resource | `%s` |\n",
		f.Severity, f.CanonicalID, f.Source, f.CheckID, f.Provider, f.Account, f.Region, f.Resource.ID)
	if f.File != "" {
		fmt.Fprintf(&b, "| File | `%s:%d` |\n", f.File, f.LineStart)
	}
	if f.Description != "" {
		fmt.Fprintf(&b, "\n### Risk\n%s\n", f.Description)
	}
	if f.Remediation != "" {
		fmt.Fprintf(&b, "\n### Remediation\n%s\n", f.Remediation)
	}
	fmt.Fprintf(&b, "\n```bash\ncloud-posture fix --finding %s --generate-terraform\n```\n", f.CanonicalID)
	if len(paths) > 0 {
		b.WriteString("\n### Attack paths this finding enables\n")
		for _, p := range paths {
			fmt.Fprintf(&b, "- **%s** → %s (score %.1f, MITRE %s)\n", p.Name, p.Impact, p.Score, strings.Join(p.Mitre, ", "))
		}
	}
	if len(f.Compliance) > 0 {
		b.WriteString("\n### Compliance\n")
		for fw, ctrls := range f.Compliance {
			fmt.Fprintf(&b, "- %s: %s\n", fw, strings.Join(ctrls, ", "))
		}
	}
	return b.String()
}

// ---------------------------------------------------------------- SIEM

// SIEM supports Splunk HEC, Elastic/OpenSearch document POST, a generic JSON webhook and CEF syslog.
type SIEM struct {
	Type    string // splunk_hec | elastic | webhook | syslog
	URL     string // HEC endpoint, index doc URL, webhook URL, or host:port for syslog
	Token   string
	Index   string
	Source  string
	Headers map[string]string
}

func (s *SIEM) Name() string { return "siem" }

func (s *SIEM) Deliver(ctx context.Context, f model.Finding, paths []model.AttackPath) (string, error) {
	event := Event(f, paths)
	switch strings.ToLower(s.Type) {
	case "splunk", "splunk_hec", "hec":
		payload := map[string]any{"time": f.LastSeen.Unix(), "sourcetype": "cloud-posture:finding", "source": firstNonEmpty(s.Source, "cloud-posture"), "event": event}
		if s.Index != "" {
			payload["index"] = s.Index
		}
		url := strings.TrimRight(s.URL, "/")
		if !strings.HasSuffix(url, "/services/collector/event") && !strings.HasSuffix(url, "/services/collector") {
			url += "/services/collector/event"
		}
		body, code, err := postJSON(ctx, url, map[string]string{"Authorization": "Splunk " + s.Token}, payload)
		if err != nil {
			return "", err
		}
		if code >= 300 {
			return "", fmt.Errorf("splunk HEC %d: %s", code, truncate(string(body), 200))
		}
		return "hec", nil
	case "elastic", "elasticsearch", "opensearch":
		url := strings.TrimRight(s.URL, "/") + "/" + firstNonEmpty(s.Index, "cloud-posture-findings") + "/_doc/" + f.ID
		headers := map[string]string{}
		if s.Token != "" {
			headers["Authorization"] = "ApiKey " + s.Token
		}
		req, err := newRequest(ctx, http.MethodPut, url, bytes.NewReader(mustJSON(event)))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		for k, v := range s.Headers {
			req.Header.Set(k, v)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return "", err
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			return "", fmt.Errorf("elastic responded %d", resp.StatusCode)
		}
		return f.ID, nil
	case "webhook", "http", "":
		headers := map[string]string{}
		if s.Token != "" {
			headers["Authorization"] = "Bearer " + s.Token
		}
		for k, v := range s.Headers {
			headers[k] = v
		}
		body, code, err := postJSON(ctx, s.URL, headers, event)
		if err != nil {
			return "", err
		}
		if code >= 300 {
			return "", fmt.Errorf("webhook responded %d: %s", code, truncate(string(body), 200))
		}
		return "posted", nil
	case "syslog", "cef":
		network := "udp"
		addr := s.URL
		if strings.HasPrefix(addr, "tcp://") {
			network, addr = "tcp", strings.TrimPrefix(addr, "tcp://")
		}
		addr = strings.TrimPrefix(addr, "udp://")
		conn, err := dialSyslog(ctx, network, addr)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		line := fmt.Sprintf("<%d>%s cloud-posture %s\n", 14, time.Now().UTC().Format(time.RFC3339), CEF(f))
		if _, err := conn.Write([]byte(line)); err != nil {
			return "", err
		}
		return "syslog", nil
	}
	return "", fmt.Errorf("unknown siem type %q", s.Type)
}

// Event is the flat JSON shape pushed to SIEMs (OCSF-flavoured field names).
func Event(f model.Finding, paths []model.AttackPath) map[string]any {
	ev := map[string]any{
		"event_type":    "cloud_posture.finding",
		"finding_id":    f.ID,
		"canonical_id":  f.CanonicalID,
		"source":        f.Source,
		"check_id":      f.CheckID,
		"title":         f.Title,
		"severity":      f.Severity,
		"status":        f.Status,
		"provider":      f.Provider,
		"account":       f.Account,
		"region":        f.Region,
		"resource_id":   f.Resource.ID,
		"resource_type": f.Resource.Type,
		"resource_name": f.Resource.Name,
		"weaknesses":    f.Weaknesses,
		"compliance":    f.Compliance,
		"first_seen":    f.FirstSeen,
		"last_seen":     f.LastSeen,
		"remediation":   f.Remediation,
	}
	if f.File != "" {
		ev["file"] = f.File
		ev["line"] = f.LineStart
	}
	if len(paths) > 0 {
		var ap []map[string]any
		for _, p := range paths {
			ap = append(ap, map[string]any{"id": p.ID, "name": p.Name, "impact": p.Impact, "score": p.Score, "mitre": p.Mitre})
		}
		ev["attack_paths"] = ap
	}
	return ev
}

// CEF renders ArcSight Common Event Format.
func CEF(f model.Finding) string {
	sev := map[model.Severity]int{model.Critical: 10, model.High: 8, model.Medium: 5, model.Low: 3, model.Info: 1}[f.Severity]
	esc := func(s string) string {
		return strings.NewReplacer("\\", "\\\\", "=", "\\=", "\n", " ", "\r", " ").Replace(s)
	}
	hdr := func(s string) string { return strings.NewReplacer("\\", "\\\\", "|", "\\|").Replace(s) }
	return fmt.Sprintf("CEF:0|nimbus|cloud-posture|0.1|%s|%s|%d|cs1Label=provider cs1=%s cs2Label=account cs2=%s cs3Label=resource cs3=%s cs4Label=source cs4=%s cs5Label=status cs5=%s msg=%s",
		hdr(f.CanonicalID), hdr(f.Title), sev, esc(f.Provider), esc(f.Account), esc(f.Resource.ID), esc(f.Source), esc(string(f.Status)), esc(truncate(f.Description, 500)))
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func urlEncode(s string) string {
	r := strings.NewReplacer(" ", "%20", "\"", "%22", ":", "%3A", "/", "%2F", "#", "%23", "&", "%26")
	return r.Replace(s)
}
