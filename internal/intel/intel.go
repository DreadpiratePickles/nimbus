// Package intel loads vulnerability-exploitation intelligence — the CISA Known Exploited
// Vulnerabilities (KEV) catalog and FIRST EPSS scores — for the risk score's exploitability factor.
//
// Resolution order in Enricher.Load:
//  1. a fresh cache file in CacheDir (default .cloud-posture/intel/, TTL 24h);
//  2. unless NoNetwork, an HTTPS download (timeouts, TLS verification, size caps) written to the cache;
//  3. a stale cache file (download failed);
//  4. the embedded snapshot in snapshot/ (see SnapshotDate) — always available offline.
//
// The risk package consumes only the Source interface (KEV, EPSS) so tests inject fakes and
// never touch the network.
package intel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	KEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	EPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

	DefaultCacheDir = ".cloud-posture/intel"
	DefaultTTL      = 24 * time.Hour
	// Size caps: the KEV JSON is ~2 MB and the EPSS gzip ~3 MB (~13 MB inflated) as of 2026-10.
	MaxKEVBytes      = 32 << 20
	MaxEPSSGzipBytes = 64 << 20
	MaxEPSSCSVBytes  = 256 << 20

	// SnapshotDate is when snapshot/ was cut: KEV catalogVersion 2026.10.08 (200 most recent entries
	// plus calibration CVEs), EPSS score_date 2026-10-09 (rows for the snapshot KEV CVEs, testdata
	// and calibration CVEs only). Refresh procedure: docs/scoring.md "Exploitability data".
	SnapshotDate = "2026-10-09"
)

//go:embed snapshot/kev.json snapshot/epss.csv
var snapshotFS embed.FS

// Source is what the risk score needs. ok=false from EPSS means "no data" (not scored), never 0.
type Source interface {
	KEV(cve string) bool
	EPSS(cve string) (score, percentile float64, ok bool)
}

// KEVEntry is the subset of a CISA KEV record we keep.
type KEVEntry struct {
	CVE        string `json:"cveID"`
	Vendor     string `json:"vendorProject"`
	Product    string `json:"product"`
	Name       string `json:"vulnerabilityName"`
	DateAdded  string `json:"dateAdded"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

type EPSSEntry struct {
	Score      float64
	Percentile float64
}

// Feed is a loaded KEV + EPSS data set. It implements Source.
type Feed struct {
	kev        map[string]KEVEntry
	epss       map[string]EPSSEntry
	KEVVersion string // catalogVersion
	EPSSDate   string // score_date from the CSV header comment
	Origin     string // "cache", "network", "stale-cache", "snapshot" (per feed, joined with "+")
	Warnings   []string
}

func (f *Feed) KEV(cve string) bool {
	if f == nil {
		return false
	}
	_, ok := f.kev[normalize(cve)]
	return ok
}

func (f *Feed) KEVEntry(cve string) (KEVEntry, bool) {
	if f == nil {
		return KEVEntry{}, false
	}
	e, ok := f.kev[normalize(cve)]
	return e, ok
}

func (f *Feed) EPSS(cve string) (float64, float64, bool) {
	if f == nil {
		return 0, 0, false
	}
	e, ok := f.epss[normalize(cve)]
	return e.Score, e.Percentile, ok
}

// Counts reports how many KEV and EPSS records are loaded.
func (f *Feed) Counts() (kev, epss int) { return len(f.kev), len(f.epss) }

func normalize(cve string) string { return strings.ToUpper(strings.TrimSpace(cve)) }

// Options configures an Enricher. Zero values mean the documented defaults.
type Options struct {
	CacheDir  string
	TTL       time.Duration
	NoNetwork bool // --no-network: cache or embedded snapshot only
	Client    *http.Client
	KEVURL    string
	EPSSURL   string
	Now       func() time.Time
}

// Enricher resolves KEV/EPSS data from cache, network or the embedded snapshot.
type Enricher struct{ opts Options }

func NewEnricher(o Options) *Enricher {
	if o.CacheDir == "" {
		o.CacheDir = DefaultCacheDir
	}
	if o.TTL <= 0 {
		o.TTL = DefaultTTL
	}
	if o.KEVURL == "" {
		o.KEVURL = KEVURL
	}
	if o.EPSSURL == "" {
		o.EPSSURL = EPSSURL
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 60 * time.Second}
	}
	return &Enricher{opts: o}
}

// Load always returns a usable Feed (falling back to the embedded snapshot); problems are in Warnings.
func (e *Enricher) Load(ctx context.Context) *Feed {
	f := &Feed{kev: map[string]KEVEntry{}, epss: map[string]EPSSEntry{}}
	var origins []string
	kevData, kevOrigin, warn := e.resolve(ctx, "kev.json", e.opts.KEVURL, MaxKEVBytes, func(b []byte) error {
		return (&Feed{kev: map[string]KEVEntry{}}).parseKEV(b)
	})
	f.Warnings = append(f.Warnings, warn...)
	if kevData != nil {
		_ = f.parseKEV(kevData) // validated in resolve
	} else {
		f.kev = map[string]KEVEntry{}
		data, _ := snapshotFS.ReadFile("snapshot/kev.json")
		_ = f.parseKEV(data)
		kevOrigin = "snapshot"
	}
	origins = append(origins, "kev:"+kevOrigin)

	gz, epssOrigin, warn := e.resolve(ctx, "epss.csv.gz", e.opts.EPSSURL, MaxEPSSGzipBytes, func(b []byte) error {
		return (&Feed{epss: map[string]EPSSEntry{}}).parseEPSSGzip(b)
	})
	f.Warnings = append(f.Warnings, warn...)
	if gz != nil {
		_ = f.parseEPSSGzip(gz) // validated in resolve
	} else {
		f.epss = map[string]EPSSEntry{}
		data, _ := snapshotFS.ReadFile("snapshot/epss.csv")
		_ = f.parseEPSS(bytes.NewReader(data))
		epssOrigin = "snapshot"
	}
	origins = append(origins, "epss:"+epssOrigin)
	f.Origin = strings.Join(origins, "+")
	return f
}

// Snapshot returns the embedded offline data set (no I/O beyond the binary itself).
func Snapshot() *Feed {
	f := &Feed{kev: map[string]KEVEntry{}, epss: map[string]EPSSEntry{}, Origin: "kev:snapshot+epss:snapshot"}
	data, _ := snapshotFS.ReadFile("snapshot/kev.json")
	if err := f.parseKEV(data); err != nil {
		f.Warnings = append(f.Warnings, "snapshot kev: "+err.Error())
	}
	data, _ = snapshotFS.ReadFile("snapshot/epss.csv")
	if err := f.parseEPSS(bytes.NewReader(data)); err != nil {
		f.Warnings = append(f.Warnings, "snapshot epss: "+err.Error())
	}
	return f
}

// resolve returns validated raw bytes for one feed and where they came from; nil means "use the
// embedded snapshot". Downloads are validated before they replace the cache.
func (e *Enricher) resolve(ctx context.Context, name, url string, max int64, validate func([]byte) error) ([]byte, string, []string) {
	var warns []string
	path := filepath.Join(e.opts.CacheDir, name)
	st, statErr := os.Stat(path)
	cached := func() ([]byte, error) {
		data, err := readCapped(path, max)
		if err == nil {
			err = validate(data)
		}
		return data, err
	}
	if statErr == nil && e.opts.Now().Sub(st.ModTime()) < e.opts.TTL {
		if data, err := cached(); err == nil {
			return data, "cache", nil
		} else {
			warns = append(warns, name+": cache unusable: "+err.Error())
		}
	}
	if !e.opts.NoNetwork {
		data, err := e.fetch(ctx, url, max)
		if err == nil {
			err = validate(data)
		}
		if err == nil {
			if err := writeAtomic(path, data); err != nil {
				warns = append(warns, name+": cache write failed: "+err.Error())
			}
			return data, "network", warns
		}
		warns = append(warns, name+": download failed: "+err.Error())
	}
	if statErr == nil {
		if data, err := cached(); err == nil {
			return data, "stale-cache", append(warns, name+": using stale cache from "+st.ModTime().UTC().Format(time.RFC3339))
		}
	}
	return nil, "snapshot", append(warns, name+": using embedded snapshot ("+SnapshotDate+")")
}

func (e *Enricher) fetch(ctx context.Context, url string, max int64) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("refusing non-HTTPS feed URL %q", url)
	}
	client := *e.opts.Client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-HTTPS %s", req.URL.Redacted())
		}
		return nil
	}
	if client.Timeout == 0 {
		client.Timeout = 60 * time.Second
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nimbus-cloud-posture/intel")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	if resp.ContentLength > max {
		return nil, fmt.Errorf("GET %s: body %d bytes exceeds cap %d", url, resp.ContentLength, max)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("GET %s: body exceeds cap %d bytes", url, max)
	}
	return data, nil
}

func readCapped(path string, max int64) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s exceeds cap %d bytes", path, max)
	}
	return data, nil
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (f *Feed) parseKEV(data []byte) error {
	var doc struct {
		CatalogVersion  string     `json:"catalogVersion"`
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	if len(doc.Vulnerabilities) == 0 {
		return errors.New("catalog has no vulnerabilities")
	}
	for _, v := range doc.Vulnerabilities {
		if id := normalize(v.CVE); strings.HasPrefix(id, "CVE-") {
			v.CVE = id
			f.kev[id] = v
		}
	}
	f.KEVVersion = doc.CatalogVersion
	return nil
}

func (f *Feed) parseEPSSGzip(data []byte) error {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer zr.Close()
	lr := &io.LimitedReader{R: zr, N: MaxEPSSCSVBytes + 1}
	if err := f.parseEPSS(lr); err != nil {
		return err
	}
	if lr.N <= 0 {
		return fmt.Errorf("inflated EPSS CSV exceeds cap %d bytes", MaxEPSSCSVBytes)
	}
	return nil
}

// parseEPSS reads "#model_version:...,score_date:..." then "cve,epss,percentile" rows.
func (f *Feed) parseEPSS(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	rows := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			for _, kv := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
				if k, v, ok := strings.Cut(kv, ":"); ok && strings.TrimSpace(k) == "score_date" {
					f.EPSSDate = strings.TrimSpace(v)
				}
			}
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 3 || !strings.HasPrefix(strings.ToUpper(parts[0]), "CVE-") {
			continue // header or junk
		}
		s, err1 := strconv.ParseFloat(parts[1], 64)
		p, err2 := strconv.ParseFloat(parts[2], 64)
		if err1 != nil || err2 != nil || s < 0 || s > 1 || p < 0 || p > 1 {
			continue
		}
		f.epss[normalize(parts[0])] = EPSSEntry{Score: s, Percentile: p}
		rows++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no EPSS rows")
	}
	return nil
}

// Static is an in-memory Source for tests and fixtures.
type Static struct {
	KEVs  map[string]bool
	Score map[string][2]float64 // cve -> {epss, percentile}
}

func (s Static) KEV(cve string) bool { return s.KEVs[normalize(cve)] }
func (s Static) EPSS(cve string) (float64, float64, bool) {
	v, ok := s.Score[normalize(cve)]
	return v[0], v[1], ok
}
