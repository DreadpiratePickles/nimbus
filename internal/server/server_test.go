package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/gorilla/websocket"
)

func TestAPI(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "s.db"))
	defer st.Close()
	f := model.Finding{Source: "prowler", CheckID: "x", CanonicalID: "S3_PUBLIC_BUCKET", Title: "public", Severity: model.High, Status: model.Fail, Provider: "aws", Account: "1",
		Resource: model.Resource{ID: "arn:aws:s3:::pii", Type: "aws_s3_bucket", Name: "pii"}, Weaknesses: []string{"PUBLIC_DATA_STORE"}, Compliance: map[string][]string{"cis_aws": {"2.1.4"}}}
	f.Finalize(time.Now())
	st.UpsertFindings([]model.Finding{f})
	st.ReplaceAttackPaths("s", []model.AttackPath{{ID: "p", Score: 6, Severity: model.High, FindingIDs: []string{f.ID}, Steps: []model.Step{{Resource: "arn:aws:s3:::pii"}}}})
	s := New(st, func() ([]byte, error) { return []byte("<html>dash</html>"), nil })
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	get := func(p string, v any) int {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if v != nil {
			json.NewDecoder(resp.Body).Decode(v)
		}
		return resp.StatusCode
	}
	var sum map[string]any
	if get("/api/summary", &sum) != 200 || sum["open"].(float64) != 1 || sum["attack_paths"].(float64) != 1 {
		t.Errorf("summary: %v", sum)
	}
	var fs []model.Finding
	if get("/api/findings?status=FAIL&min_severity=high", &fs) != 200 || len(fs) != 1 {
		t.Errorf("findings: %v", fs)
	}
	var one map[string]any
	if get("/api/findings/"+f.ID, &one) != 200 || len(one["attack_paths"].([]any)) != 1 {
		t.Errorf("finding: %v", one)
	}
	var ranked []map[string]any
	if get("/api/risk/top?n=5", &ranked) != 200 || len(ranked) != 1 || ranked[0]["risk_score"].(float64) < 4 {
		t.Errorf("risk: %v", ranked)
	}
	var rep map[string]any
	if get("/api/compliance/cis?provider=aws", &rep) != 200 || rep["failing"].(float64) != 1 {
		t.Errorf("compliance: %v", rep)
	}
	resp, _ := http.Post(ts.URL+"/api/query", "application/json", strings.NewReader(`{"sql":"SELECT name FROM aws_s3_buckets"}`))
	var qr map[string]any
	json.NewDecoder(resp.Body).Decode(&qr)
	if resp.StatusCode != 200 || len(qr["rows"].([]any)) != 1 {
		t.Errorf("query: %d %v", resp.StatusCode, qr)
	}
	resp, _ = http.Post(ts.URL+"/api/query", "application/json", strings.NewReader(`{"sql":"DELETE FROM findings"}`))
	if resp.StatusCode != 400 {
		t.Errorf("write query should be rejected")
	}
	if get("/", nil) != 200 || get("/api/graph", nil) != 200 || get("/api/schema", nil) != 200 {
		t.Errorf("static endpoints")
	}
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http")+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	var hello Event
	ws.ReadJSON(&hello)
	s.Broadcast(Event{Type: "findings_updated"})
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	var ev Event
	if err := ws.ReadJSON(&ev); err != nil || ev.Type != "findings_updated" {
		t.Errorf("ws broadcast: %v %+v", err, ev)
	}
}
