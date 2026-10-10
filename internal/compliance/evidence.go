package compliance

// Evidence package v2 (W7-VERIFY r5 #9; bar: Drata Audit Hub audit-period packages, Vanta
// continuous tests, AWS Audit Manager assessment reports with integrity digests).
//
// The zip holds the report (report.md, report.json), one evidence.json per control, the scan
// metadata, the legacy MANIFEST.sha256.json and manifest.json, format "nimbus-evidence/v2":
//
//   - files: the SHA-256 of every other entry (manifest.json and its signature bundle excepted);
//   - period: the audit period (default the last 90 days), the scans inside it;
//   - controls: per control its kind (native | prowler_ingest | manual), the evidence status, and
//     "effective X of Y days": a day counts as effective when the last scan that day evaluated the
//     control PASS (a mapped finding observed, none failing at that moment), failing when one was
//     failing, untested when no scan ran that day or nothing mapped was observed yet;
//   - manual controls are never passed automatically: an automated PASS on a control no nimbus
//     check covers becomes MANUAL in the zip's report and manifest (evidence must be collected by
//     people), and a manual control has no effective days.
//
// manifest.json is signed with `cosign sign-blob` (NIMBUS_EVIDENCE_KEY: a key file or a KMS URI;
// COSIGN_PASSWORD as cosign reads it) into manifest.json.sigstore.json (a Sigstore bundle). As the
// manifest carries every other file's digest, the signature covers the whole package.
// `cloud-posture verify --evidence <zip> --key cosign.pub` (VerifyEvidence) re-computes every
// digest, reports changed, missing and unlisted entries, and verifies the signature.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const (
	EvidenceFormat    = "nimbus-evidence/v2"
	ManifestName      = "manifest.json"
	BundleName        = "manifest.json.sigstore.json"
	LegacyManifest    = "MANIFEST.sha256.json"
	DefaultPeriodDays = 90
	maxEvidenceEntry  = 256 << 20 // a single zip entry read by VerifyEvidence
)

// Interval is one span a finding was failing; To is zero while it still is.
type Interval struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// PeriodHistory is the scan history the period coverage is computed from.
type PeriodHistory interface {
	ScanTimes(from, to time.Time) ([]time.Time, error)
	FailIntervals(findingIDs []string) (map[string][]Interval, error)
}

// OpenHistory opens the scan history of a database path for EvidenceZip (meta["db"]); the CLI
// registers it (compliance cannot import the store: the store's tests import the adapters,
// which import compliance). nil, or an error: no period coverage.
var OpenHistory func(dbPath string) (PeriodHistory, func(), error)

// SigningInfo describes how manifest.json was signed (recorded in the manifest itself).
type SigningInfo struct {
	Method string `json:"method"`                      // "cosign sign-blob"
	KeyRef string `json:"key_ref"`                     // key file name or KMS URI (never key material)
	PubSHA string `json:"public_key_sha256,omitempty"` // of the .pub next to a key file, when present
	Bundle string `json:"bundle"`                      // the zip entry holding the Sigstore bundle
	Verify string `json:"verify"`                      // the command that verifies it
}

// Signer signs a file and returns the signature bundle.
type Signer interface {
	Info() SigningInfo
	SignBlob(ctx context.Context, path string) ([]byte, error)
}

// CosignSigner runs `cosign sign-blob` with a key (file path or KMS URI). Offline: no
// transparency log upload (a private key needs none; the bundle carries the signature).
type CosignSigner struct {
	Bin string // default "cosign" on PATH
	Key string
}

func (c *CosignSigner) bin() string {
	if c.Bin != "" {
		return c.Bin
	}
	return "cosign"
}

func (c *CosignSigner) Info() SigningInfo {
	ref := c.Key
	in := SigningInfo{Method: "cosign sign-blob", Bundle: BundleName,
		Verify: "cloud-posture verify --evidence <zip> --key <cosign.pub>  (or: cosign verify-blob --key <cosign.pub> --bundle " + BundleName + " --insecure-ignore-tlog=true " + ManifestName + ")"}
	if !strings.Contains(ref, "://") {
		ref = filepath.Base(ref)
		if b, err := os.ReadFile(strings.TrimSuffix(c.Key, ".key") + ".pub"); err == nil {
			s := sha256.Sum256(b)
			in.PubSHA = hex.EncodeToString(s[:])
		}
	}
	in.KeyRef = ref
	return in
}

func (c *CosignSigner) SignBlob(ctx context.Context, path string) ([]byte, error) {
	out := path + ".bundle"
	defer os.Remove(out)
	run := func(extra ...string) ([]byte, error) {
		args := append([]string{"sign-blob", "--key", c.Key, "--bundle", out}, extra...)
		args = append(args, "--yes", path)
		cmd := exec.CommandContext(ctx, c.bin(), args...)
		cmd.Env = os.Environ() // COSIGN_PASSWORD, KMS credentials
		return cmd.CombinedOutput()
	}
	// cosign v3 (no signing config, no tlog), then the cosign v2 flags.
	msg, err := run("--use-signing-config=false", "--tlog-upload=false")
	if err != nil && strings.Contains(string(msg), "unknown flag") {
		msg, err = run("--tlog-upload=false")
	}
	if err != nil {
		return nil, fmt.Errorf("cosign sign-blob: %v: %s", err, lastLine(string(msg)))
	}
	return os.ReadFile(out)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// EvidenceOptions configures EvidenceZipV2.
type EvidenceOptions struct {
	Now        time.Time
	PeriodDays int           // default DefaultPeriodDays
	History    PeriodHistory // nil: no period coverage (every day untested)
	Signer     Signer        // nil: unsigned (the manifest says so)
}

// PeriodInfo is the audit period of a package.
type PeriodInfo struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Days   int       `json:"days"`
	Scans  int       `json:"scans"`
	Source string    `json:"source"` // "scan history" | "none"
}

// ControlEvidence is one control in manifest.json.
type ControlEvidence struct {
	ID            string     `json:"id"`
	Title         string     `json:"title,omitempty"`
	Kind          string     `json:"kind"`
	Status        string     `json:"status"` // PASS | FAIL | NOT_ASSESSED | MANUAL
	EffectiveDays int        `json:"effective_days"`
	FailingDays   int        `json:"failing_days"`
	UntestedDays  int        `json:"untested_days"`
	PeriodDays    int        `json:"period_days"`
	LastTested    *time.Time `json:"last_tested,omitempty"`
	Statement     string     `json:"statement"`
}

// EvidenceManifest is manifest.json.
type EvidenceManifest struct {
	Format        string            `json:"format"`
	Framework     string            `json:"framework"`
	FrameworkName string            `json:"framework_name"`
	Version       string            `json:"version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Period        PeriodInfo        `json:"period"`
	Files         map[string]string `json:"files"`
	Controls      []ControlEvidence `json:"controls"`
	Signed        bool              `json:"signed"`
	Signing       *SigningInfo      `json:"signing,omitempty"`
	Note          string            `json:"note"`
}

// EvidenceOptionsFromEnv reads NIMBUS_EVIDENCE_KEY (key file or KMS URI; empty: unsigned),
// NIMBUS_COSIGN (cosign binary) and NIMBUS_EVIDENCE_PERIOD_DAYS.
func EvidenceOptionsFromEnv() (EvidenceOptions, error) {
	o := EvidenceOptions{}
	if v := strings.TrimSpace(os.Getenv("NIMBUS_EVIDENCE_PERIOD_DAYS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 3660 {
			return o, fmt.Errorf("NIMBUS_EVIDENCE_PERIOD_DAYS=%q: want 1..3660", v)
		}
		o.PeriodDays = n
	}
	if k := strings.TrimSpace(os.Getenv("NIMBUS_EVIDENCE_KEY")); k != "" {
		o.Signer = &CosignSigner{Bin: os.Getenv("NIMBUS_COSIGN"), Key: k}
	}
	return o, nil
}

// EvidenceZip writes the v2 package with options from the environment and, when meta["db"]
// names the database, its scan history (the `report --evidence-zip` entry point).
func EvidenceZip(path string, rep *Report, findings []model.Finding, meta map[string]any) error {
	o, err := EvidenceOptionsFromEnv()
	if err != nil {
		return err
	}
	if db, ok := meta["db"].(string); ok && db != "" && OpenHistory != nil {
		if h, closeFn, err := OpenHistory(db); err == nil {
			defer closeFn()
			o.History = h
		}
	}
	_, err = EvidenceZipV2(context.Background(), path, rep, findings, meta, o)
	return err
}

// EvidenceZipV2 writes the package and returns its manifest.
func EvidenceZipV2(ctx context.Context, path string, rep *Report, findings []model.Finding, meta map[string]any, o EvidenceOptions) (*EvidenceManifest, error) {
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	if o.PeriodDays <= 0 {
		o.PeriodDays = DefaultPeriodDays
	}
	fwKey := rep.Framework.Key
	evRep, controls, period, err := periodCoverage(rep, findings, o)
	if err != nil {
		return nil, err
	}
	m := &EvidenceManifest{Format: EvidenceFormat, Framework: fwKey, FrameworkName: rep.Framework.Name, Version: rep.Framework.Version,
		GeneratedAt: o.Now.UTC(), Period: period, Files: map[string]string{}, Controls: controls,
		Note: "A day is effective when the day's last scan evaluated the control PASS; manual controls are never passed automatically."}
	if o.Signer != nil {
		in := o.Signer.Info()
		m.Signed, m.Signing = true, &in
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		s := sha256.Sum256(data)
		m.Files[name] = hex.EncodeToString(s[:])
		return nil
	}
	byID := map[string]model.Finding{}
	for _, fd := range findings {
		byID[fd.ID] = fd
	}
	if err := write("report.md", []byte(evRep.Markdown()+periodMarkdown(m))); err != nil {
		return nil, err
	}
	repJSON, _ := json.MarshalIndent(evRep, "", "  ")
	if err := write("report.json", repJSON); err != nil {
		return nil, err
	}
	for _, c := range evRep.Controls {
		dir := "controls/" + strings.NewReplacer("/", "_", "(", "_", ")", "").Replace(c.ID) + "/"
		var evidence []model.Finding
		for _, id := range c.Findings {
			if fd, ok := byID[id]; ok {
				evidence = append(evidence, fd)
			}
		}
		for _, fd := range findings {
			if fd.Status == model.Pass {
				for _, ctl := range controlsFor(fwKey, &fd) {
					if ctl == c.ID {
						evidence = append(evidence, fd)
					}
				}
			}
		}
		if len(evidence) == 0 {
			continue
		}
		data, _ := json.MarshalIndent(map[string]any{"control": c, "evidence": evidence, "collected_at": o.Now.UTC()}, "", "  ")
		if err := write(dir+"evidence.json", data); err != nil {
			return nil, err
		}
	}
	if meta == nil {
		meta = map[string]any{}
	}
	meta["framework"] = evRep.Framework
	meta["generated_at"] = o.Now.UTC()
	metaJSON, _ := json.MarshalIndent(meta, "", "  ")
	if err := write("metadata.json", metaJSON); err != nil {
		return nil, err
	}
	legacy := map[string]string{}
	for k, v := range m.Files {
		legacy[k] = v
	}
	lj, _ := json.MarshalIndent(legacy, "", "  ")
	if err := write(LegacyManifest, lj); err != nil {
		return nil, err
	}
	mj, _ := json.MarshalIndent(m, "", "  ")
	w, err := zw.Create(ManifestName)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(mj); err != nil {
		return nil, err
	}
	if o.Signer != nil {
		tmp, err := os.CreateTemp("", "nimbus-manifest-*.json")
		if err != nil {
			return nil, err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(mj); err != nil {
			tmp.Close()
			return nil, err
		}
		tmp.Close()
		bundle, err := o.Signer.SignBlob(ctx, tmp.Name())
		if err != nil {
			return nil, err
		}
		w, err := zw.Create(BundleName)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(bundle); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return nil, err
	}
	return m, nil
}

// periodCoverage returns the zip's copy of the report (manual PASS → MANUAL), the per-control
// period evidence and the period.
func periodCoverage(rep *Report, findings []model.Finding, o EvidenceOptions) (*Report, []ControlEvidence, PeriodInfo, error) {
	to := o.Now.UTC()
	from := time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -(o.PeriodDays - 1))
	period := PeriodInfo{From: from, To: to, Days: o.PeriodDays, Source: "none"}
	var scans []time.Time
	fail := map[string][]Interval{}
	mapped := map[string][]model.Finding{} // control -> findings mapped to it
	var ids []string
	for i := range findings {
		f := findings[i]
		for _, c := range controlsFor(rep.Framework.Key, &f) {
			mapped[c] = append(mapped[c], f)
		}
		ids = append(ids, f.ID)
	}
	if o.History != nil {
		var err error
		if scans, err = o.History.ScanTimes(from, to); err != nil {
			return nil, nil, period, err
		}
		if fail, err = o.History.FailIntervals(ids); err != nil {
			return nil, nil, period, err
		}
		period.Source = "scan history"
	}
	period.Scans = len(scans)
	// The last scan of each day.
	lastOfDay := make([]time.Time, o.PeriodDays)
	for _, t := range scans {
		d := int(t.Sub(from).Hours() / 24)
		if d >= 0 && d < o.PeriodDays && t.After(lastOfDay[d]) {
			lastOfDay[d] = t
		}
	}
	statusAt := func(ctrl string, t time.Time) string {
		observed := false
		for _, f := range mapped[ctrl] {
			ivs, ok := fail[f.ID]
			if !ok && f.Status == model.Fail && !f.FirstSeen.IsZero() {
				ivs = []Interval{{From: f.FirstSeen}}
			}
			for _, iv := range ivs {
				if !t.Before(iv.From) && (iv.To.IsZero() || t.Before(iv.To)) {
					return "FAIL"
				}
			}
			if f.FirstSeen.IsZero() || !f.FirstSeen.After(t) {
				observed = true
			}
		}
		if observed {
			return "PASS"
		}
		return "NOT_ASSESSED"
	}
	ev := *rep
	ev.Controls = append([]ControlStatus(nil), rep.Controls...)
	var out []ControlEvidence
	for i := range ev.Controls {
		c := &ev.Controls[i]
		kind := ControlKind(rep.Framework.Key, c.ID)
		if kind == "" {
			kind = KindNative // a custom framework's control maps to checks by definition
		}
		ce := ControlEvidence{ID: c.ID, Title: c.Title, Kind: kind, Status: c.Status, PeriodDays: o.PeriodDays}
		if kind == KindManual {
			if c.Status == "PASS" {
				c.Status = "MANUAL"
			}
			if c.Status != "FAIL" {
				c.Status = "MANUAL"
			}
			ce.Status = c.Status
			ce.UntestedDays = o.PeriodDays
			ce.Statement = "manual control: no nimbus check covers it; evidence must be collected and reviewed by people (never passed automatically)"
			out = append(out, ce)
			continue
		}
		for d := 0; d < o.PeriodDays; d++ {
			t := lastOfDay[d]
			if t.IsZero() {
				ce.UntestedDays++
				continue
			}
			switch statusAt(c.ID, t) {
			case "PASS":
				ce.EffectiveDays++
				tt := t
				ce.LastTested = &tt
			case "FAIL":
				ce.FailingDays++
				tt := t
				ce.LastTested = &tt
			default:
				ce.UntestedDays++
			}
		}
		ce.Statement = fmt.Sprintf("effective %d of %d days", ce.EffectiveDays, o.PeriodDays)
		if ce.FailingDays > 0 || ce.UntestedDays > 0 {
			ce.Statement += fmt.Sprintf(" (%d failing, %d untested)", ce.FailingDays, ce.UntestedDays)
		}
		out = append(out, ce)
	}
	ev.Passing, ev.Failing, ev.NotAssessed = 0, 0, 0
	for _, c := range ev.Controls {
		switch c.Status {
		case "PASS":
			ev.Passing++
		case "FAIL":
			ev.Failing++
		default:
			ev.NotAssessed++
		}
	}
	ev.Assessed = ev.Passing + ev.Failing
	ev.ScorePercent = scorePercent(ev.Passing, ev.Failing)
	sort.SliceStable(out, func(i, j int) bool { return controlLess(out[i].ID, out[j].ID) })
	return &ev, out, period, nil
}

func periodMarkdown(m *EvidenceManifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n## Audit period\n\n%s to %s (%d days), %d scan(s) from %s. A day is effective when that day's last scan evaluated the control PASS; manual controls are never passed automatically.\n\n",
		m.Period.From.Format("2006-01-02"), m.Period.To.Format("2006-01-02"), m.Period.Days, m.Period.Scans, m.Period.Source)
	b.WriteString("| Control | Kind | Evidence over the period |\n|---|---|---|\n")
	for _, c := range m.Controls {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", c.ID, c.Kind, c.Statement)
	}
	if m.Signed && m.Signing != nil {
		fmt.Fprintf(&b, "\nmanifest.json is signed (%s, key %s); verify: %s\n", m.Signing.Method, m.Signing.KeyRef, m.Signing.Verify)
	} else {
		b.WriteString("\nmanifest.json is not signed (set NIMBUS_EVIDENCE_KEY to sign with cosign).\n")
	}
	return b.String()
}

// VerifyOptions configures VerifyEvidence.
type VerifyOptions struct {
	PublicKey string // cosign public key (file or KMS URI); empty: the signature is not checked
	CosignBin string
}

// EvidenceCheck is the outcome of VerifyEvidence.
type EvidenceCheck struct {
	Format       string            `json:"format"`
	Files        int               `json:"files"`
	Mismatched   []string          `json:"mismatched,omitempty"`
	Missing      []string          `json:"missing,omitempty"`
	Unlisted     []string          `json:"unlisted,omitempty"`
	Duplicates   []string          `json:"duplicates,omitempty"`
	Signed       bool              `json:"signed"`
	SignatureOK  bool              `json:"signature_ok"`
	SignatureErr string            `json:"signature_error,omitempty"`
	Manifest     *EvidenceManifest `json:"manifest,omitempty"`
}

// OK: every digest matches, nothing is missing, unlisted or duplicated, and the signature verified.
func (c *EvidenceCheck) OK() bool {
	return c != nil && len(c.Mismatched)+len(c.Missing)+len(c.Unlisted)+len(c.Duplicates) == 0 && c.SignatureOK
}

// VerifyEvidence re-computes every digest of an evidence zip and verifies the manifest signature.
func VerifyEvidence(ctx context.Context, path string, o VerifyOptions) (*EvidenceCheck, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	entries := map[string][]byte{}
	chk := &EvidenceCheck{}
	for _, f := range zr.File {
		if _, dup := entries[f.Name]; dup {
			chk.Duplicates = append(chk.Duplicates, f.Name)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxEvidenceEntry+1))
		rc.Close()
		if err != nil {
			return nil, err
		}
		if len(b) > maxEvidenceEntry {
			return nil, fmt.Errorf("%s: entry over %d bytes", f.Name, maxEvidenceEntry)
		}
		entries[f.Name] = b
	}
	mj, ok := entries[ManifestName]
	if !ok {
		return nil, fmt.Errorf("%s has no %s (not a nimbus-evidence/v2 package; v1 zips carry only %s)", filepath.Base(path), ManifestName, LegacyManifest)
	}
	var m EvidenceManifest
	if err := json.Unmarshal(mj, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestName, err)
	}
	if m.Format != EvidenceFormat {
		return nil, fmt.Errorf("%s: format %q, want %q", ManifestName, m.Format, EvidenceFormat)
	}
	chk.Format, chk.Manifest, chk.Signed = m.Format, &m, m.Signed
	for name, want := range m.Files {
		b, ok := entries[name]
		if !ok {
			chk.Missing = append(chk.Missing, name)
			continue
		}
		chk.Files++
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != want {
			chk.Mismatched = append(chk.Mismatched, name)
		}
	}
	for name := range entries {
		if _, ok := m.Files[name]; !ok && name != ManifestName && name != BundleName {
			chk.Unlisted = append(chk.Unlisted, name)
		}
	}
	sort.Strings(chk.Mismatched)
	sort.Strings(chk.Missing)
	sort.Strings(chk.Unlisted)
	bundle, hasBundle := entries[BundleName]
	switch {
	case !hasBundle:
		chk.SignatureErr = "the package is not signed (no " + BundleName + ")"
	case o.PublicKey == "":
		chk.SignatureErr = "signature not checked: pass the signer's public key (--key cosign.pub)"
	default:
		if err := cosignVerify(ctx, o, mj, bundle); err != nil {
			chk.SignatureErr = err.Error()
		} else {
			chk.SignatureOK = true
		}
	}
	return chk, nil
}

func cosignVerify(ctx context.Context, o VerifyOptions, manifest, bundle []byte) error {
	dir, err := os.MkdirTemp("", "nimbus-evidence-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	mp, bp := filepath.Join(dir, ManifestName), filepath.Join(dir, BundleName)
	if err := os.WriteFile(mp, manifest, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(bp, bundle, 0o600); err != nil {
		return err
	}
	bin := o.CosignBin
	if bin == "" {
		bin = "cosign"
	}
	cmd := exec.CommandContext(ctx, bin, "verify-blob", "--key", o.PublicKey, "--bundle", bp, "--insecure-ignore-tlog=true", mp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.Error
		if errors.As(err, &ee) {
			return fmt.Errorf("cosign not found (%s): install cosign to verify the signature", bin)
		}
		return fmt.Errorf("signature invalid: %s", lastLine(string(out)))
	}
	return nil
}
