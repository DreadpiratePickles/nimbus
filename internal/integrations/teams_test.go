package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestTeamsDeliver(t *testing.T) {
	tests := []struct {
		name    string
		sev     model.Severity
		status  int
		color   string
		wantErr bool
	}{
		{"critical", model.Critical, 200, "attention", false},
		{"high", model.High, 202, "attention", false},
		{"medium", model.Medium, 200, "warning", false},
		{"server error", model.Low, 500, "accent", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status) })
			ref, err := NewTeams(srv.URL+"/hook").Deliver(context.Background(), sampleFinding(tc.sev), samplePaths())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && ref != "sent" {
				t.Fatalf("ref = %q", ref)
			}
			reqs := rec.all()
			if len(reqs) != 1 || reqs[0].Method != http.MethodPost || reqs[0].Path != "/hook" {
				t.Fatalf("unexpected requests %+v", reqs)
			}
			var msg struct {
				Type        string `json:"type"`
				Attachments []struct {
					ContentType string         `json:"contentType"`
					Content     map[string]any `json:"content"`
				} `json:"attachments"`
			}
			if err := json.Unmarshal(reqs[0].Body, &msg); err != nil {
				t.Fatal(err)
			}
			if msg.Type != "message" || len(msg.Attachments) != 1 || msg.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" {
				t.Fatalf("bad envelope: %s", reqs[0].Body)
			}
			card := msg.Attachments[0].Content
			if card["type"] != "AdaptiveCard" || card["version"] != "1.4" || card["$schema"] == nil {
				t.Fatalf("bad card header: %v", card)
			}
			body := card["body"].([]any)
			title := body[0].(map[string]any)
			if title["color"] != tc.color {
				t.Fatalf("color = %v want %s", title["color"], tc.color)
			}
			s := string(reqs[0].Body)
			for _, want := range []string{"FactSet", "S3_PUBLIC_BUCKET", "arn:aws:s3:::customer-pii", "Public bucket data theft", "Enable S3 Block Public Access"} {
				if !strings.Contains(s, want) {
					t.Errorf("payload missing %q", want)
				}
			}
		})
	}
}

func TestTeamsRequiresURL(t *testing.T) {
	if _, err := NewTeams("").Deliver(context.Background(), sampleFinding(model.High), nil); err == nil {
		t.Fatal("expected error")
	}
}
