package integrations

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestSentinelSignature(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("super-secret-key"))
	date := "Mon, 02 Jan 2026 03:04:05 GMT"
	tests := []struct {
		name    string
		key     string
		length  int
		wantErr bool
	}{
		{"valid", key, 123, false},
		{"zero length", key, 0, false},
		{"bad base64", "!!not-base64!!", 10, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SentinelSignature("ws-1", tc.key, date, tc.length)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if tc.wantErr {
				return
			}
			mac := hmac.New(sha256.New, []byte("super-secret-key"))
			mac.Write([]byte("POST\n" + itoa(tc.length) + "\napplication/json\nx-ms-date:" + date + "\n/api/logs"))
			want := "SharedKey ws-1:" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
			if got != want {
				t.Fatalf("got %s want %s", got, want)
			}
		})
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestSentinelDeliver(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("k3y"))
	fixed := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		code    int
		wantErr bool
	}{{"ok", 200, false}, {"forbidden", 403, true}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.code) })
			s := NewSentinel("ws-1", key)
			s.Endpoint, s.now = srv.URL, func() time.Time { return fixed }
			ref, err := s.Deliver(context.Background(), sampleFinding(model.High), samplePaths())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if !tc.wantErr && ref != "sentinel" {
				t.Fatalf("ref %q", ref)
			}
			r := rec.all()[0]
			if r.Method != http.MethodPost || r.Path != "/api/logs" || r.Query != "api-version=2016-04-01" {
				t.Fatalf("bad request %s %s?%s", r.Method, r.Path, r.Query)
			}
			date := "Wed, 04 Mar 2026 05:06:07 GMT"
			if r.Header.Get("x-ms-date") != date || r.Header.Get("Log-Type") != "CloudPosture" ||
				r.Header.Get("time-generated-field") != "TimeGenerated" || r.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("headers %v", r.Header)
			}
			mac := hmac.New(sha256.New, []byte("k3y"))
			mac.Write([]byte("POST\n" + itoa(len(r.Body)) + "\napplication/json\nx-ms-date:" + date + "\n/api/logs"))
			if want := "SharedKey ws-1:" + base64.StdEncoding.EncodeToString(mac.Sum(nil)); r.Header.Get("Authorization") != want {
				t.Fatalf("auth %s want %s", r.Header.Get("Authorization"), want)
			}
			var recs []map[string]any
			if err := json.Unmarshal(r.Body, &recs); err != nil || len(recs) != 1 {
				t.Fatalf("body %s", r.Body)
			}
			if recs[0]["TimeGenerated"] != "2026-03-04T05:06:07Z" || recs[0]["canonical_id"] != "S3_PUBLIC_BUCKET" {
				t.Fatalf("record %+v", recs[0])
			}
		})
	}
}

func TestSentinelInvalidKey(t *testing.T) {
	if _, err := NewSentinel("ws", "%%%").Deliver(context.Background(), sampleFinding(model.Low), nil); err == nil {
		t.Fatal("expected error for invalid key")
	}
}
