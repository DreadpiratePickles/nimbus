package integrations

import (
	"context"
	"fmt"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Teams posts an Adaptive Card to a Microsoft Teams incoming webhook (or Workflows webhook).
type Teams struct {
	WebhookURL string
}

func NewTeams(webhookURL string) *Teams { return &Teams{WebhookURL: webhookURL} }

func (t *Teams) Name() string { return "teams" }

func teamsColor(s model.Severity) string {
	switch s {
	case model.Critical, model.High:
		return "attention"
	case model.Medium:
		return "warning"
	case model.Low:
		return "accent"
	}
	return "default"
}

// TeamsCard builds the Adaptive Card 1.4 content for a finding.
func TeamsCard(f model.Finding, paths []model.AttackPath) map[string]any {
	body := []map[string]any{
		{"type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": true, "color": teamsColor(f.Severity),
			"text": fmt.Sprintf("[%s] %s", f.Severity, f.Title)},
		{"type": "FactSet", "facts": []map[string]any{
			{"title": "Severity", "value": string(f.Severity)},
			{"title": "Canonical ID", "value": f.CanonicalID},
			{"title": "Provider / Account", "value": f.Provider + " / " + f.Account},
			{"title": "Region", "value": firstNonEmpty(f.Region, "-")},
			{"title": "Resource", "value": f.Resource.ID},
			{"title": "Source / Check", "value": f.Source + " / " + f.CheckID},
		}},
	}
	if f.Description != "" {
		body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "text": truncate(f.Description, 1000)})
	}
	if len(paths) > 0 {
		var lines []string
		for _, p := range paths {
			lines = append(lines, fmt.Sprintf("- %s → %s (score %.1f)", p.Name, p.Impact, p.Score))
		}
		body = append(body,
			map[string]any{"type": "TextBlock", "weight": "Bolder", "text": "Part of attack paths", "color": "attention"},
			map[string]any{"type": "TextBlock", "wrap": true, "text": strings.Join(lines, "\n")})
	}
	if f.Remediation != "" {
		body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "isSubtle": true, "text": "Remediation: " + truncate(f.Remediation, 600)})
	}
	body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "fontType": "Monospace", "isSubtle": true,
		"text": fmt.Sprintf("cloud-posture fix --finding %s --generate-terraform", f.CanonicalID)})
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
	}
	if url, ok := f.Resource.Attributes["console_url"].(string); ok && url != "" {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open in console", "url": url}}
	}
	return card
}

func (t *Teams) Deliver(ctx context.Context, f model.Finding, paths []model.AttackPath) (string, error) {
	if t.WebhookURL == "" {
		return "", fmt.Errorf("teams webhook URL not configured (TEAMS_WEBHOOK_URL)")
	}
	payload := map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     TeamsCard(f, paths),
		}},
	}
	body, code, err := postJSON(ctx, t.WebhookURL, nil, payload)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("teams responded %d: %s", code, truncate(strings.TrimSpace(string(body)), 200))
	}
	return "sent", nil
}
