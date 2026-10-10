package intel

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const kevBody = `{"catalogVersion":"2099.01.01","vulnerabilities":[{"cveID":"CVE-2099-0001","vendorProject":"Acme","product":"Widget","dateAdded":"2099-01-01"}]}`
const epssCSV = "#model_version:v2099,score_date:2099-01-01T00:00:00Z\ncve,epss,percentile\nCVE-2099-0001,0.97,0.999\nCVE-2099-0002,0.001,0.12\n"

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func feedServer(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()
	epss := gz(t, epssCSV)
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		switch r.URL.Path {
		case "/kev.json":
			w.Write([]byte(kevBody))
		case "/epss.csv.gz":
			w.Write(epss)
		case "/huge":
			w.Write(bytes.Repeat([]byte("x"), 2048))
		default:
			http.Error(w, "nope", 500)
		}
	}))
}

func TestSnapshotOffline(t *testing.T) {
	f := Snapshot()
	k, e := f.Counts()
	if k < 200 || e < 3 || len(f.Warnings) > 0 {
		t.Fatalf("snapshot kev=%d epss=%d warnings=%v", k, e, f.Warnings)
	}
	if !f.KEV("cve-2021-44228") || f.KEV("CVE-2024-6387") {
		t.Errorf("KEV lookups wrong: log4shell=%v regresshion=%v", f.KEV("CVE-2021-44228"), f.KEV("CVE-2024-6387"))
	}
	if _, p, ok := f.EPSS("CVE-2024-6387"); !ok || p < 0.99 {
		t.Errorf("EPSS for testdata CVE-2024-6387: %v %v", p, ok)
	}
	if _, _, ok := f.EPSS("CVE-1900-0001"); ok {
		t.Error("unknown CVE must report ok=false (not scored), not zero")
	}
	if f.KEVVersion != "2026.10.08" || !strings.HasPrefix(f.EPSSDate, SnapshotDate) {
		t.Errorf("snapshot dates: kev=%s epss=%s (SnapshotDate %s)", f.KEVVersion, f.EPSSDate, SnapshotDate)
	}
}

func TestLoadFetchesCachesAndHonoursTTL(t *testing.T) {
	var hits int32
	srv := feedServer(t, &hits)
	defer srv.Close()
	dir := t.TempDir()
	now := time.Now()
	e := NewEnricher(Options{CacheDir: dir, Client: srv.Client(), KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz", Now: func() time.Time { return now }})
	f := e.Load(context.Background())
	if f.Origin != "kev:network+epss:network" || !f.KEV("CVE-2099-0001") || f.KEVVersion != "2099.01.01" {
		t.Fatalf("network load: origin=%s warnings=%v", f.Origin, f.Warnings)
	}
	if s, p, ok := f.EPSS("CVE-2099-0002"); !ok || s != 0.001 || p != 0.12 {
		t.Errorf("epss: %v %v %v", s, p, ok)
	}
	for _, n := range []string{"kev.json", "epss.csv.gz"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("cache file %s not written: %v", n, err)
		}
	}
	// within TTL: served from cache, no new requests
	before := atomic.LoadInt32(&hits)
	f = e.Load(context.Background())
	if f.Origin != "kev:cache+epss:cache" || atomic.LoadInt32(&hits) != before {
		t.Errorf("expected cache hit, origin=%s hits %d->%d", f.Origin, before, hits)
	}
	// past TTL with network down: stale cache, warning recorded
	later := now.Add(25 * time.Hour)
	srv.Close()
	e2 := NewEnricher(Options{CacheDir: dir, Client: srv.Client(), KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz", Now: func() time.Time { return later }})
	f = e2.Load(context.Background())
	if f.Origin != "kev:stale-cache+epss:stale-cache" || len(f.Warnings) == 0 {
		t.Errorf("stale fallback: origin=%s warnings=%v", f.Origin, f.Warnings)
	}
}

func TestNoNetworkUsesSnapshot(t *testing.T) {
	var hits int32
	srv := feedServer(t, &hits)
	defer srv.Close()
	e := NewEnricher(Options{CacheDir: t.TempDir(), NoNetwork: true, Client: srv.Client(), KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz"})
	f := e.Load(context.Background())
	if hits != 0 {
		t.Fatalf("--no-network made %d requests", hits)
	}
	if f.Origin != "kev:snapshot+epss:snapshot" || !f.KEV("CVE-2021-44228") {
		t.Errorf("origin=%s", f.Origin)
	}
}

func TestFetchRefusesPlainHTTPAndOversize(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(kevBody)) }))
	defer plain.Close()
	e := NewEnricher(Options{CacheDir: t.TempDir()})
	if _, err := e.fetch(context.Background(), plain.URL, MaxKEVBytes); err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("plain http accepted: %v", err)
	}
	var hits int32
	srv := feedServer(t, &hits)
	defer srv.Close()
	e = NewEnricher(Options{CacheDir: t.TempDir(), Client: srv.Client()})
	if _, err := e.fetch(context.Background(), srv.URL+"/huge", 1024); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Errorf("oversize body accepted: %v", err)
	}
	// TLS verification stays on: the default client does not trust the test CA.
	e = NewEnricher(Options{CacheDir: t.TempDir(), Client: &http.Client{Timeout: 5 * time.Second}})
	if _, err := e.fetch(context.Background(), srv.URL+"/kev.json", MaxKEVBytes); err == nil {
		t.Error("untrusted certificate accepted; TLS verification must be on")
	}
}

func TestCorruptDownloadFallsBackToSnapshot(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not json / not gzip")) }))
	defer srv.Close()
	e := NewEnricher(Options{CacheDir: t.TempDir(), Client: srv.Client(), KEVURL: srv.URL + "/k", EPSSURL: srv.URL + "/e"})
	f := e.Load(context.Background())
	if f.Origin != "kev:snapshot+epss:snapshot" || len(f.Warnings) < 2 || !f.KEV("CVE-2021-44228") {
		t.Errorf("origin=%s warnings=%v", f.Origin, f.Warnings)
	}
}

func TestStaticSource(t *testing.T) {
	var s Source = Static{KEVs: map[string]bool{"CVE-1-1": true}, Score: map[string][2]float64{"CVE-1-1": {0.5, 0.9}}}
	if !s.KEV("cve-1-1") {
		t.Error("static KEV")
	}
	if _, p, ok := s.EPSS("CVE-1-1"); !ok || p != 0.9 {
		t.Error("static EPSS")
	}
}

func TestInvalidDownloadNeverReplacesCache(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("garbage")) }))
	defer srv.Close()
	dir := t.TempDir()
	e := NewEnricher(Options{CacheDir: dir, Client: srv.Client(), KEVURL: srv.URL + "/k", EPSSURL: srv.URL + "/e"})
	e.Load(context.Background())
	if _, err := os.Stat(filepath.Join(dir, "kev.json")); err == nil {
		t.Error("invalid KEV download was cached")
	}
}
