package integrations

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Webhook URLs are bearer credentials (the path is the secret); delivery errors must not contain them.
func TestDeliveryErrorsRedactWebhookURLs(t *testing.T) {
	const secretPath = "/services/T0SECRET/B0SECRET/xoxSECRETxyz"
	f := model.Finding{ID: "f1", CanonicalID: "X", Severity: model.High, Status: model.Fail, Title: "t", LastSeen: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sinks := []Sink{
		&Slack{WebhookURL: "http://127.0.0.1:1" + secretPath},          // connection refused
		NewTeams("http://127.0.0.1:1" + secretPath),                    // connection refused
		&SIEM{Type: "webhook", URL: "http://127.0.0.1:1" + secretPath}, // connection refused
		&Slack{WebhookURL: "http://[::1" + secretPath},                 // URL parse error
	}
	for _, s := range sinks {
		_, err := s.Deliver(ctx, f, nil)
		if err == nil {
			t.Fatalf("%s: expected a delivery error", s.Name())
		}
		if msg := err.Error(); strings.Contains(msg, "SECRET") || strings.Contains(msg, "/services/") {
			t.Errorf("%s error leaks the webhook path: %s", s.Name(), msg)
		}
	}
	if got := redactURL("https://hooks.slack.com/services/T/B/x?token=1"); got != "https://hooks.slack.com" {
		t.Errorf("redactURL = %q", got)
	}
}
