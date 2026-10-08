package integrations

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDuty sends Events API v2 alerts; dedup_key is the finding ID so re-sends update one incident.
type PagerDuty struct {
	RoutingKey string
	EventsURL  string
	Source     string
}

func NewPagerDuty(routingKey string) *PagerDuty { return &PagerDuty{RoutingKey: routingKey} }

func (p *PagerDuty) Name() string { return "pagerduty" }

// PagerDutySeverity maps finding severity onto PD's critical|error|warning|info.
func PagerDutySeverity(s model.Severity) string {
	switch s {
	case model.Critical:
		return "critical"
	case model.High:
		return "error"
	case model.Medium:
		return "warning"
	}
	return "info"
}

func (p *PagerDuty) Deliver(ctx context.Context, f model.Finding, paths []model.AttackPath) (string, error) {
	if p.RoutingKey == "" {
		return "", fmt.Errorf("pagerduty routing key not configured (PAGERDUTY_ROUTING_KEY)")
	}
	action := "trigger"
	if f.Status == model.Pass {
		action = "resolve"
	}
	summary := fmt.Sprintf("[%s] %s on %s (%s/%s)", f.Severity, f.Title, firstNonEmpty(f.Resource.Name, f.Resource.ID), f.Provider, f.Account)
	if len(summary) > 1024 {
		summary = summary[:1021] + "..."
	}
	payload := map[string]any{
		"routing_key":  p.RoutingKey,
		"event_action": action,
		"dedup_key":    f.ID,
		"client":       "cloud-posture",
		"payload": map[string]any{
			"summary":        summary,
			"source":         firstNonEmpty(f.Resource.ID, p.Source, f.Source, "cloud-posture"),
			"severity":       PagerDutySeverity(f.Severity),
			"component":      f.Resource.Type,
			"group":          f.Provider + "/" + f.Account,
			"class":          f.CanonicalID,
			"custom_details": Event(f, paths),
		},
	}
	body, code, err := postJSON(ctx, firstNonEmpty(p.EventsURL, pagerDutyEventsURL), nil, payload)
	if err != nil {
		return "", err
	}
	if code != 202 && code != 200 {
		return "", fmt.Errorf("pagerduty responded %d: %s", code, truncate(string(body), 200))
	}
	var out struct {
		DedupKey string `json:"dedup_key"`
	}
	_ = json.Unmarshal(body, &out)
	return firstNonEmpty(out.DedupKey, f.ID), nil
}
