package integrations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Jira creates one Jira Cloud issue per finding, de-duplicated by the label cp-<fingerprint>.
type Jira struct {
	BaseURL    string
	Email      string
	APIToken   string
	ProjectKey string
	IssueType  string
	Labels     []string
}

func NewJira(baseURL, email, apiToken, projectKey, issueType string) *Jira {
	if issueType == "" {
		issueType = "Task"
	}
	return &Jira{BaseURL: strings.TrimRight(baseURL, "/"), Email: email, APIToken: apiToken, ProjectKey: projectKey, IssueType: issueType}
}

func (j *Jira) Name() string { return "jira" }

func (j *Jira) base() string { return strings.TrimRight(j.BaseURL, "/") }

func (j *Jira) headers() map[string]string {
	return map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(j.Email+":"+j.APIToken)),
		"Accept":        "application/json",
	}
}

// JiraLabel is the de-duplication label for a finding.
func JiraLabel(f model.Finding) string { return "cp-" + f.ID }

func (j *Jira) Deliver(ctx context.Context, f model.Finding, paths []model.AttackPath) (string, error) {
	if j.BaseURL == "" || j.Email == "" || j.APIToken == "" || j.ProjectKey == "" {
		return "", fmt.Errorf("jira requires base URL, email, API token and project key (JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT)")
	}
	key, err := j.findExisting(ctx, JiraLabel(f))
	if err != nil {
		return "", err
	}
	if key != "" {
		return j.base() + "/browse/" + key, nil
	}
	summary := fmt.Sprintf("[%s] %s: %s", f.Severity, f.CanonicalID, firstNonEmpty(f.Resource.Name, f.Resource.ID))
	if len(summary) > 255 {
		summary = summary[:255]
	}
	labels := []string{"cloud-posture", JiraLabel(f), "severity-" + strings.ToLower(string(f.Severity)), "provider-" + f.Provider}
	labels = append(labels, j.Labels...)
	payload := map[string]any{"fields": map[string]any{
		"project":     map[string]any{"key": j.ProjectKey},
		"issuetype":   map[string]any{"name": firstNonEmpty(j.IssueType, "Task")},
		"summary":     summary,
		"description": JiraADF(f, paths),
		"labels":      labels,
	}}
	body, code, err := postJSON(ctx, j.base()+"/rest/api/3/issue", j.headers(), payload)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("jira responded %d: %s", code, truncate(string(body), 300))
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.Key == "" {
		return "", fmt.Errorf("jira create: unexpected response %s", truncate(string(body), 200))
	}
	return j.base() + "/browse/" + created.Key, nil
}

func (j *Jira) findExisting(ctx context.Context, label string) (string, error) {
	jql := fmt.Sprintf(`project = "%s" AND labels = "%s"`, j.ProjectKey, label)
	q := "?jql=" + url.QueryEscape(jql) + "&maxResults=1&fields=key"
	for _, path := range []string{"/rest/api/3/search/jql", "/rest/api/3/search"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.base()+path+q, nil)
		if err != nil {
			return "", err
		}
		for k, v := range j.headers() {
			req.Header.Set(k, v)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return "", err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
			continue
		}
		if resp.StatusCode >= 300 {
			return "", fmt.Errorf("jira search responded %d: %s", resp.StatusCode, truncate(string(data), 200))
		}
		var out struct {
			Issues []struct {
				Key string `json:"key"`
			} `json:"issues"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return "", fmt.Errorf("jira search decode: %w", err)
		}
		if len(out.Issues) > 0 {
			return out.Issues[0].Key, nil
		}
		return "", nil
	}
	return "", fmt.Errorf("jira search endpoints unavailable")
}

func adfText(s string) map[string]any { return map[string]any{"type": "text", "text": s} }

func adfPara(parts ...map[string]any) map[string]any {
	return map[string]any{"type": "paragraph", "content": parts}
}

func adfBullets(items []string) map[string]any {
	var lis []map[string]any
	for _, it := range items {
		lis = append(lis, map[string]any{"type": "listItem", "content": []map[string]any{adfPara(adfText(it))}})
	}
	return map[string]any{"type": "bulletList", "content": lis}
}

// JiraADF renders the finding as an Atlassian Document Format description.
func JiraADF(f model.Finding, paths []model.AttackPath) map[string]any {
	content := []map[string]any{
		{"type": "heading", "attrs": map[string]any{"level": 2}, "content": []map[string]any{adfText(firstNonEmpty(f.Title, f.CanonicalID))}},
	}
	facts := []string{
		"Severity: " + string(f.Severity),
		"Canonical ID: " + f.CanonicalID,
		fmt.Sprintf("Source: %s (%s)", f.Source, f.CheckID),
		"Provider / Account: " + f.Provider + " / " + f.Account,
		"Region: " + firstNonEmpty(f.Region, "-"),
		"Resource: " + f.Resource.ID,
	}
	if f.File != "" {
		facts = append(facts, fmt.Sprintf("File: %s:%d", f.File, f.LineStart))
	}
	content = append(content, adfBullets(facts))
	if f.Description != "" {
		content = append(content, adfPara(map[string]any{"type": "text", "text": "Risk: ", "marks": []map[string]any{{"type": "strong"}}}, adfText(truncate(f.Description, 4000))))
	}
	if f.Remediation != "" {
		content = append(content, adfPara(map[string]any{"type": "text", "text": "Remediation: ", "marks": []map[string]any{{"type": "strong"}}}, adfText(truncate(f.Remediation, 4000))))
	}
	content = append(content, map[string]any{"type": "codeBlock", "attrs": map[string]any{"language": "bash"},
		"content": []map[string]any{adfText(fmt.Sprintf("cloud-posture fix --finding %s --generate-terraform", f.CanonicalID))}})
	if len(paths) > 0 {
		content = append(content, map[string]any{"type": "heading", "attrs": map[string]any{"level": 3}, "content": []map[string]any{adfText("Attack paths this finding enables")}})
		var items []string
		for _, p := range paths {
			items = append(items, fmt.Sprintf("%s → %s (score %.1f)", p.Name, p.Impact, p.Score))
		}
		content = append(content, adfBullets(items))
	}
	content = append(content, adfPara(adfText("cloud-posture-fingerprint: "+f.ID)))
	return map[string]any{"type": "doc", "version": 1, "content": content}
}

