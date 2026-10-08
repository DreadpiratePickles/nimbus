package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestDatadogDeliver(t *testing.T) {
	tests := []struct {
		name       string
		sev        model.Severity
		sendEvent  bool
		logsCode   int
		wantStatus string
		wantRef    string
		wantReqs   int
		wantErr    bool
	}{
		{"logs only high", model.High, false, 202, "error", "logs", 1, false},
		{"logs and event critical", model.Critical, true, 202, "critical", "logs+event", 2, false},
		{"medium warn", model.Medium, false, 200, "warn", "logs", 1, false},
		{"forbidden", model.Low, true, 403, "info", "", 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v2/logs" {
					w.WriteHeader(tc.logsCode)
					return
				}
				w.WriteHeader(202)
				_, _ = w.Write([]byte(`{"status":"ok","event":{"id":1}}`))
			})
			d := NewDatadog("DDKEY", "")
			d.LogsURL, d.EventsURL = srv.URL+"/api/v2/logs", srv.URL+"/api/v1/events"
			d.Tags, d.SendEvent = []string{"env:prod"}, tc.sendEvent
			ref, err := d.Deliver(context.Background(), sampleFinding(tc.sev), samplePaths())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if ref != tc.wantRef {
				t.Fatalf("ref %q", ref)
			}
			reqs := rec.all()
			if len(reqs) != tc.wantReqs {
				t.Fatalf("%d requests", len(reqs))
			}
			for _, r := range reqs {
				if r.Header.Get("DD-API-KEY") != "DDKEY" {
					t.Fatal("missing DD-API-KEY")
				}
			}
			var logs []map[string]any
			if err := json.Unmarshal(reqs[0].Body, &logs); err != nil || len(logs) != 1 {
				t.Fatalf("logs body %s", reqs[0].Body)
			}
			l := logs[0]
			if l["ddsource"] != "cloud-posture" || l["service"] != "cloud-posture" || l["status"] != tc.wantStatus || l["hostname"] != "123456789012" {
				t.Fatalf("bad log %+v", l)
			}
			tags := l["ddtags"].(string)
			for _, w := range []string{"severity:" + strings.ToLower(string(tc.sev)), "provider:aws", "account:123456789012", "canonical_id:S3_PUBLIC_BUCKET", "env:prod"} {
				if !strings.Contains(tags, w) {
					t.Errorf("ddtags missing %s: %s", w, tags)
				}
			}
			if l["finding"].(map[string]any)["canonical_id"] != "S3_PUBLIC_BUCKET" {
				t.Fatal("finding attributes missing")
			}
			if tc.wantReqs == 2 {
				var ev map[string]any
				_ = json.Unmarshal(reqs[1].Body, &ev)
				if reqs[1].Path != "/api/v1/events" || ev["alert_type"] != "error" || ev["source_type_name"] != "cloud-posture" || ev["aggregation_key"] == "" {
					t.Fatalf("bad event %+v", ev)
				}
			}
		})
	}
}

func TestDatadogDefaultURLs(t *testing.T) {
	d := NewDatadog("k", "datadoghq.eu")
	if d.logsURL() != "https://http-intake.logs.datadoghq.eu/api/v2/logs" || d.eventsURL() != "https://api.datadoghq.eu/api/v1/events" {
		t.Fatalf("urls %s %s", d.logsURL(), d.eventsURL())
	}
	if NewDatadog("k", "").logsURL() != "https://http-intake.logs.datadoghq.com/api/v2/logs" {
		t.Fatal("default site")
	}
}
