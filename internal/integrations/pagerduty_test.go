package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestPagerDutySeverityMap(t *testing.T) {
	for sev, want := range map[model.Severity]string{model.Critical: "critical", model.High: "error", model.Medium: "warning", model.Low: "info", model.Info: "info"} {
		if got := PagerDutySeverity(sev); got != want {
			t.Errorf("%s -> %s, want %s", sev, got, want)
		}
	}
}

func TestPagerDutyDeliver(t *testing.T) {
	tests := []struct {
		name       string
		sev        model.Severity
		status     model.Status
		code       int
		wantAction string
		wantSev    string
		wantErr    bool
	}{
		{"trigger critical", model.Critical, model.Fail, 202, "trigger", "critical", false},
		{"trigger medium", model.Medium, model.Fail, 202, "trigger", "warning", false},
		{"resolve on pass", model.High, model.Pass, 202, "resolve", "error", false},
		{"bad request", model.High, model.Fail, 400, "trigger", "error", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := sampleFinding(tc.sev)
			f.Status = tc.status
			srv, rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(`{"status":"success","dedup_key":"` + f.ID + `"}`))
			})
			pd := NewPagerDuty("RKEY123")
			pd.EventsURL = srv.URL + "/v2/enqueue"
			ref, err := pd.Deliver(context.Background(), f, samplePaths())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if !tc.wantErr && ref != f.ID {
				t.Fatalf("ref %q want %q", ref, f.ID)
			}
			req := rec.all()[0]
			if req.Path != "/v2/enqueue" {
				t.Fatalf("path %s", req.Path)
			}
			var body struct {
				RoutingKey  string         `json:"routing_key"`
				EventAction string         `json:"event_action"`
				DedupKey    string         `json:"dedup_key"`
				Client      string         `json:"client"`
				Payload     map[string]any `json:"payload"`
			}
			if err := json.Unmarshal(req.Body, &body); err != nil {
				t.Fatal(err)
			}
			if body.RoutingKey != "RKEY123" || body.DedupKey != f.ID || body.EventAction != tc.wantAction || body.Client != "cloud-posture" {
				t.Fatalf("bad envelope %+v", body)
			}
			if body.Payload["severity"] != tc.wantSev || body.Payload["source"] != f.Resource.ID || body.Payload["class"] != "S3_PUBLIC_BUCKET" ||
				body.Payload["component"] != "aws_s3_bucket" || body.Payload["group"] != "aws/123456789012" {
				t.Fatalf("bad payload %+v", body.Payload)
			}
			cd := body.Payload["custom_details"].(map[string]any)
			if cd["finding_id"] != f.ID || cd["attack_paths"] == nil {
				t.Fatalf("custom_details %+v", cd)
			}
		})
	}
}

func TestPagerDutyRequiresKey(t *testing.T) {
	if _, err := NewPagerDuty("").Deliver(context.Background(), sampleFinding(model.High), nil); err == nil {
		t.Fatal("expected error")
	}
}
