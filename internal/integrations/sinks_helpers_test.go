package integrations

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

type captured struct {
	Method, Path, Query string
	Header              http.Header
	Body                []byte
}

type recorder struct {
	mu   sync.Mutex
	reqs []captured
}

func (r *recorder) all() []captured {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]captured(nil), r.reqs...)
}

// newRecorder starts a server that records requests and answers via respond.
func newRecorder(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.reqs = append(rec.reqs, captured{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone(), Body: b})
		rec.mu.Unlock()
		respond(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func sampleFinding(sev model.Severity) model.Finding {
	f := model.Finding{
		Source: "nimbus", CheckID: "s3_bucket_public_access", CanonicalID: "S3_PUBLIC_BUCKET",
		Title: "S3 bucket allows public access", Description: "Bucket is world readable", Severity: sev, Status: model.Fail,
		Provider: "aws", Account: "123456789012", Region: "us-east-1",
		Resource:    model.Resource{ID: "arn:aws:s3:::customer-pii", Type: "aws_s3_bucket", Name: "customer-pii"},
		Remediation: "Enable S3 Block Public Access",
	}
	f.Finalize(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	return f
}

func samplePaths() []model.AttackPath {
	return []model.AttackPath{{ID: "ap1", Name: "Public bucket data theft", Impact: "PII exfiltration", Score: 9.1}}
}
