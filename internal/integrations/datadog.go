package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Datadog ships findings to the Logs intake (v2) and optionally the Events API.
type Datadog struct {
	APIKey    string
	Site      string // datadoghq.com, datadoghq.eu, us3.datadoghq.com ...
	Service   string
	Tags      []string
	SendEvent bool
	LogsURL   string // overrides (tests / proxies)
	EventsURL string
}

func NewDatadog(apiKey, site string) *Datadog {
	return &Datadog{APIKey: apiKey, Site: site}
}

func (d *Datadog) Name() string { return "datadog" }

func (d *Datadog) site() string { return firstNonEmpty(strings.TrimSpace(d.Site), "datadoghq.com") }

func (d *Datadog) logsURL() string {
	return firstNonEmpty(d.LogsURL, "https://http-intake.logs."+d.site()+"/api/v2/logs")
}

func (d *Datadog) eventsURL() string {
	return firstNonEmpty(d.EventsURL, "https://api."+d.site()+"/api/v1/events")
}

func datadogStatus(s model.Severity) string {
	switch s {
	case model.Critical:
		return "critical"
	case model.High:
		return "error"
	case model.Medium:
		return "warn"
	}
	return "info"
}

func (d *Datadog) tags(f model.Finding) []string {
	t := []string{
		"severity:" + strings.ToLower(string(f.Severity)),
		"provider:" + f.Provider,
		"account:" + f.Account,
		"canonical_id:" + f.CanonicalID,
		"source:" + f.Source,
	}
	if f.Region != "" {
		t = append(t, "region:"+f.Region)
	}
	return append(t, d.Tags...)
}

func (d *Datadog) Deliver(ctx context.Context, f model.Finding, paths []model.AttackPath) (string, error) {
	if d.APIKey == "" {
		return "", fmt.Errorf("datadog API key not configured (DD_API_KEY)")
	}
	headers := map[string]string{"DD-API-KEY": d.APIKey}
	tags := d.tags(f)
	msg := fmt.Sprintf("[%s] %s: %s on %s (%s/%s)", f.Severity, f.CanonicalID, f.Title, f.Resource.ID, f.Provider, f.Account)
	logs := []map[string]any{{
		"ddsource": "cloud-posture",
		"ddtags":   strings.Join(tags, ","),
		"hostname": firstNonEmpty(f.Account, "cloud-posture"),
		"service":  firstNonEmpty(d.Service, "cloud-posture"),
		"message":  msg,
		"status":   datadogStatus(f.Severity),
		"finding":  Event(f, paths),
	}}
	body, code, err := postJSON(ctx, d.logsURL(), headers, logs)
	if err != nil {
		return "", err
	}
	if code != 202 && code != 200 {
		return "", fmt.Errorf("datadog logs intake responded %d: %s", code, truncate(string(body), 200))
	}
	if !d.SendEvent {
		return "logs", nil
	}
	alert := map[model.Severity]string{model.Critical: "error", model.High: "error", model.Medium: "warning"}[f.Severity]
	event := map[string]any{
		"title":            truncate(fmt.Sprintf("[%s] %s", f.Severity, f.Title), 100),
		"text":             truncate(firstNonEmpty(f.Description, msg)+"\n\nResource: "+f.Resource.ID, 4000),
		"alert_type":       firstNonEmpty(alert, "info"),
		"tags":             tags,
		"aggregation_key":  f.ID,
		"source_type_name": "cloud-posture",
	}
	body, code, err = postJSON(ctx, d.eventsURL(), headers, event)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("datadog events responded %d: %s", code, truncate(string(body), 200))
	}
	var ev struct {
		Event struct {
			ID json.Number `json:"id"`
		} `json:"event"`
	}
	_ = json.Unmarshal(body, &ev)
	return "logs+event", nil
}
