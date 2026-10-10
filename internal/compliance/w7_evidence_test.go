package compliance

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W7-VERIFY r5 #9 (bar: Drata audit-period evidence packages, Vanta continuous tests, AWS Audit
// Manager assessment reports): the evidence zip carries manifest.json (format nimbus-evidence/v2)
// with the SHA-256 of every file, the audit period and, per control, how many days of the period
// it was evidenced effective from scan history; manual controls are never passed automatically;
// the manifest is signed with cosign sign-blob (a configurable key) and `verify --evidence`
// checks digests and signature.

type fakeHistory struct {
	scans []time.Time
	fail  map[string][]Interval
}

func (h fakeHistory) ScanTimes(from, to time.Time) ([]time.Time, error) {
	var out []time.Time
	for _, t := range h.scans {
		if !t.Before(from) && !t.After(to) {
			out = append(out, t)
		}
	}
	return out, nil
}
func (h fakeHistory) FailIntervals(ids []string) (map[string][]Interval, error) { return h.fail, nil }

func controlsOfKind(t *testing.T, fw, kind string) []string {
	t.Helper()
	var out []string
	for id := range Frameworks()[fw].Controls {
		if ControlKind(fw, id) == kind {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatalf("%s has no %s control", fw, kind)
	}
	return out
}

func readZip(t *testing.T, path string) map[string][]byte {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = b
	}
	return out
}

func evidenceFixture(t *testing.T) (*Report, []model.Finding, fakeHistory, time.Time, string, string) {
	t.Helper()
	native := controlsOfKind(t, "cis_7.0_aws", KindNative)[0]
	manual := controlsOfKind(t, "cis_7.0_aws", KindManual)[0]
	day0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	mk := func(id string, st model.Status, ctrl string) model.Finding {
		f := model.Finding{ID: id, Source: "native", CheckID: id, CanonicalID: strings.ToUpper(id), Status: st, Severity: model.High,
			Provider: "aws", Account: "111111111111", Resource: model.Resource{ID: "r-" + id, Name: "r-" + id}, FirstSeen: day0.Add(time.Hour)}
		f.AddCompliance("cis_7.0_aws", ctrl)
		return f
	}
	fs := []model.Finding{mk(strings.Repeat("a", 32), model.Pass, native), mk(strings.Repeat("b", 32), model.Pass, manual)}
	rep, err := Build("cis_7.0_aws", fs, "")
	if err != nil {
		t.Fatal(err)
	}
	// Ten days; a scan at noon every day but day 4 (index 3); the native control's finding failed
	// from day 6 to day 8 (resolved on day 8 before noon): days 6 and 7 are failing.
	var scans []time.Time
	for d := 0; d < 10; d++ {
		if d != 3 {
			scans = append(scans, day0.AddDate(0, 0, d).Add(12*time.Hour))
		}
	}
	h := fakeHistory{scans: scans, fail: map[string][]Interval{
		strings.Repeat("a", 32): {{From: day0.AddDate(0, 0, 5).Add(time.Hour), To: day0.AddDate(0, 0, 7).Add(time.Hour)}},
	}}
	return rep, fs, h, day0.AddDate(0, 0, 9).Add(23 * time.Hour), native, manual
}

func TestEvidenceV2PeriodCoverageAndManualControls(t *testing.T) {
	rep, fs, h, now, native, manual := evidenceFixture(t)
	if st := statusOf(rep, manual); st != "PASS" {
		t.Fatalf("fixture: the report itself passes the manual control (%s), which the evidence must not", st)
	}
	p := filepath.Join(t.TempDir(), "ev.zip")
	m, err := EvidenceZipV2(context.Background(), p, rep, fs, map[string]any{"db": "x"}, EvidenceOptions{Now: now, PeriodDays: 10, History: h})
	if err != nil {
		t.Fatal(err)
	}
	files := readZip(t, p)
	var doc EvidenceManifest
	if err := json.Unmarshal(files[ManifestName], &doc); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	if doc.Format != EvidenceFormat || doc.Period.Days != 10 || doc.Period.Scans != 9 || doc.Signed || m.Format != EvidenceFormat {
		t.Fatalf("manifest header = %+v", doc)
	}
	for name, sum := range doc.Files {
		if b, ok := files[name]; !ok || sha(b) != sum {
			t.Errorf("manifest digest of %s does not match the zip", name)
		}
	}
	for name := range files {
		if _, ok := doc.Files[name]; !ok && name != ManifestName {
			t.Errorf("zip entry %s is not in the manifest", name)
		}
	}
	byID := map[string]ControlEvidence{}
	for _, c := range doc.Controls {
		byID[c.ID] = c
	}
	n := byID[native]
	if n.Kind != KindNative || n.EffectiveDays != 7 || n.FailingDays != 2 || n.UntestedDays != 1 || n.Statement != "effective 7 of 10 days (2 failing, 1 untested)" {
		t.Errorf("native control period = %+v", n)
	}
	mc := byID[manual]
	if mc.Kind != KindManual || mc.Status != "MANUAL" || mc.EffectiveDays != 0 || !strings.Contains(mc.Statement, "manual") {
		t.Errorf("manual control = %+v (a manual control is never passed automatically)", mc)
	}
	var evRep Report
	json.Unmarshal(files["report.json"], &evRep)
	if st := statusOf(&evRep, manual); st != "MANUAL" {
		t.Errorf("report.json in the zip still passes the manual control: %s", st)
	}
	if !strings.Contains(string(files["report.md"]), "effective 7 of 10 days") {
		t.Errorf("report.md lacks the period statement")
	}
}

func statusOf(r *Report, id string) string {
	for _, c := range r.Controls {
		if c.ID == id {
			return c.Status
		}
	}
	return ""
}

func cosignOrSkip(t *testing.T) (bin, key, pub string) {
	t.Helper()
	bin, err := exec.LookPath("cosign")
	if err != nil {
		t.Skip("cosign not installed")
	}
	dir := t.TempDir()
	cmd := exec.Command(bin, "generate-key-pair")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("test key: %v %s", err, out)
	}
	t.Setenv("COSIGN_PASSWORD", "")
	return bin, filepath.Join(dir, "cosign.key"), filepath.Join(dir, "cosign.pub")
}

func TestEvidenceV2SignedWithCosignAndVerified(t *testing.T) {
	bin, key, pub := cosignOrSkip(t)
	rep, fs, h, now, _, _ := evidenceFixture(t)
	p := filepath.Join(t.TempDir(), "ev.zip")
	m, err := EvidenceZipV2(context.Background(), p, rep, fs, nil, EvidenceOptions{Now: now, PeriodDays: 10, History: h, Signer: &CosignSigner{Bin: bin, Key: key}})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Signed || m.Signing.Method != "cosign sign-blob" {
		t.Fatalf("manifest signing = %+v", m.Signing)
	}
	files := readZip(t, p)
	if len(files[BundleName]) == 0 {
		t.Fatalf("no %s in the zip", BundleName)
	}
	ctx := context.Background()
	chk, err := VerifyEvidence(ctx, p, VerifyOptions{PublicKey: pub, CosignBin: bin})
	if err != nil || !chk.OK() || !chk.SignatureOK || chk.Files == 0 {
		t.Fatalf("verify of an untouched zip: %+v %v", chk, err)
	}
	// A different key fails the signature.
	_, _, otherPub := cosignOrSkip(t)
	if chk, _ := VerifyEvidence(ctx, p, VerifyOptions{PublicKey: otherPub, CosignBin: bin}); chk.OK() || chk.SignatureOK {
		t.Errorf("another key verified the zip: %+v", chk)
	}
	// Tamper with one evidence file: the digest check names it.
	tampered := rewriteZip(t, p, func(name string, b []byte) []byte {
		if name == "report.md" {
			return append(b, []byte("\nall controls pass\n")...)
		}
		return b
	})
	if chk, _ := VerifyEvidence(ctx, tampered, VerifyOptions{PublicKey: pub, CosignBin: bin}); chk.OK() || len(chk.Mismatched) != 1 || chk.Mismatched[0] != "report.md" {
		t.Errorf("tampered report.md: %+v", chk)
	}
	// Tamper with the manifest (and fix up nothing else): the signature fails.
	forged := rewriteZip(t, p, func(name string, b []byte) []byte {
		if name == ManifestName {
			return bytes.Replace(b, []byte(`"effective_days": 7`), []byte(`"effective_days": 10`), 1)
		}
		return b
	})
	if chk, _ := VerifyEvidence(ctx, forged, VerifyOptions{PublicKey: pub, CosignBin: bin}); chk.OK() || chk.SignatureOK {
		t.Errorf("a forged manifest verified: %+v", chk)
	}
	// An extra file not in the manifest is reported.
	extra := rewriteZip(t, p, nil, "controls/x/evidence.json")
	if chk, _ := VerifyEvidence(ctx, extra, VerifyOptions{PublicKey: pub, CosignBin: bin}); chk.OK() || len(chk.Unlisted) != 1 {
		t.Errorf("an unlisted file: %+v", chk)
	}
	// Without a key the digests are checked but the zip is not called verified.
	if chk, _ := VerifyEvidence(ctx, p, VerifyOptions{CosignBin: bin}); chk.OK() || len(chk.Mismatched) != 0 {
		t.Errorf("no key: %+v", chk)
	}
}

func rewriteZip(t *testing.T, src string, edit func(string, []byte) []byte, add ...string) string {
	t.Helper()
	files := readZip(t, src)
	out := filepath.Join(t.TempDir(), "x.zip")
	f, _ := os.Create(out)
	zw := zip.NewWriter(f)
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b := files[n]
		if edit != nil {
			b = edit(n, b)
		}
		w, _ := zw.Create(n)
		w.Write(b)
	}
	for _, n := range add {
		w, _ := zw.Create(n)
		w.Write([]byte(`{}`))
	}
	zw.Close()
	f.Close()
	return out
}

// The legacy entry point (cloud-posture report --evidence-zip) writes the v2 manifest too, and
// signs when NIMBUS_EVIDENCE_KEY names a key.
func TestEvidenceZipLegacyWritesV2AndSignsFromEnv(t *testing.T) {
	rep, fs, _, _, _, _ := evidenceFixture(t)
	t.Setenv("NIMBUS_EVIDENCE_KEY", "")
	p := filepath.Join(t.TempDir(), "a.zip")
	if err := EvidenceZip(p, rep, fs, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	files := readZip(t, p)
	if len(files[ManifestName]) == 0 || len(files["MANIFEST.sha256.json"]) == 0 {
		t.Fatalf("legacy zip lacks manifest.json or MANIFEST.sha256.json: %v", keys(files))
	}
	if _, ok := files[BundleName]; ok {
		t.Errorf("unsigned zip carries a bundle")
	}
	bin, key, pub := cosignOrSkip(t)
	t.Setenv("NIMBUS_EVIDENCE_KEY", key)
	t.Setenv("NIMBUS_COSIGN", bin)
	if err := EvidenceZip(p, rep, fs, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if chk, err := VerifyEvidence(context.Background(), p, VerifyOptions{PublicKey: pub, CosignBin: bin}); err != nil || !chk.OK() {
		t.Fatalf("env-signed zip: %+v %v", chk, err)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
