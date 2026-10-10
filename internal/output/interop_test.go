package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files under testdata/golden/output")

const goldenDir = "../../testdata/golden/output"

func loadInput(t *testing.T) []model.Finding {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(goldenDir, "input.findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := ParseNative(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 6 {
		t.Fatalf("fixture has %d findings, want 6", len(fs))
	}
	return fs
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join(goldenDir, name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run `go test ./internal/output -run %s -update` to create it)", err, t.Name())
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from golden (rerun with -update after reviewing):\n%s", name, firstDiff(string(want), string(got)))
	}
}

func firstDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return fmt.Sprintf("line %d:\n- %s\n+ %s", i+1, x, y)
		}
	}
	return ""
}

func ocsfSchema(t *testing.T) *Schema {
	t.Helper()
	data, err := os.ReadFile("../../testdata/ocsf/detection_finding-1.6.0.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := CompileSchema(data)
	if err != nil {
		t.Fatalf("official OCSF schema does not compile with the vendored validator: %v", err)
	}
	return s
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := JSON(&buf, v); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Every finding — the golden input and every adapter fixture in testdata — validates against
// the official OCSF 1.6.0 Detection Finding schema (testdata/ocsf, fetched from schema.ocsf.io).
func TestOCSFValidatesAgainstOfficialSchema(t *testing.T) {
	s := ocsfSchema(t)
	fs := loadInput(t)
	for _, fx := range []string{"prowler.ocsf.json", "checkov.json", "trivy.json", "steampipe.json", "scoutsuite_results_azure.js", "native.findings.json"} {
		got, _, err := adapters.ParseFile(filepath.Join("..", "..", "testdata", fx), "", adapters.Options{Now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)})
		if err != nil {
			t.Fatalf("%s: %v", fx, err)
		}
		fs = append(fs, got...)
	}
	evs := OCSF(fs)
	if len(evs) != len(fs) {
		t.Fatalf("%d events for %d findings", len(evs), len(fs))
	}
	doc := mustJSON(t, evs)
	var decoded []any
	if err := json.Unmarshal(doc, &decoded); err != nil {
		t.Fatal(err)
	}
	for i, ev := range decoded {
		if errs := s.Validate(ev); len(errs) > 0 {
			t.Errorf("finding %d (%s): %v", i, fs[i].CanonicalID, errs)
		}
	}
	e := evs[0]
	if e["class_uid"] != 2004 || e["type_uid"] != 200401 || e["category_uid"] != 2 || e["severity_id"] != 4 || e["status_id"] != 1 {
		t.Errorf("core ids: class %v type %v cat %v sev %v status %v", e["class_uid"], e["type_uid"], e["category_uid"], e["severity_id"], e["status_id"])
	}
	golden(t, "ocsf.json", mustJSON(t, OCSF(loadInput(t))))
}

// A schema-invalid event must be caught (guards against a validator that accepts anything).
func TestOCSFSchemaRejectsBrokenEvent(t *testing.T) {
	s := ocsfSchema(t)
	ev := OCSF(loadInput(t))[0]
	b, _ := json.Marshal(ev)
	var m map[string]any
	json.Unmarshal(b, &m)
	delete(m, "finding_info")
	m["severity_id"] = 7
	m["bogus"] = true
	errs := s.Validate(m)
	joined := fmt.Sprint(errs)
	for _, want := range []string{"finding_info", "severity_id", "bogus"} {
		if !strings.Contains(joined, want) {
			t.Errorf("schema did not flag %s: %v", want, errs)
		}
	}
}

// Re-ingesting nimbus's own OCSF reproduces identical findings and fingerprints — through the
// OCSF reader in this package, not the Prowler adapter (plan v3 IW4: no circular test).
func TestOCSFRoundTripIsLossless(t *testing.T) {
	in := loadInput(t)
	back, err := ParseOCSF(mustJSON(t, OCSF(in)))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(mustJSON(t, back)), string(mustJSON(t, in)); got != want {
		t.Errorf("round trip changed findings:\n%s", firstDiff(want, got))
	}
	// Without the nimbus `unmapped` extras a cloud finding keeps its fingerprint inputs from
	// standard OCSF attributes alone.
	evs := OCSF(in)
	delete(evs[0], "unmapped")
	stripped, err := ParseOCSF(mustJSON(t, evs[:1]))
	if err != nil {
		t.Fatal(err)
	}
	if stripped[0].Fingerprint() != in[0].Fingerprint() {
		t.Errorf("fingerprint from standard attributes: %+v", stripped[0])
	}
}

var (
	asffRequired = []string{"SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "Types", "CreatedAt", "UpdatedAt", "Severity", "Title", "Description", "Resources"}
	asffTimeRE   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
	asffArn      = regexp.MustCompile(`^arn:aws:securityhub:[a-z0-9-]+:\d{12}:product/\d{12}/default$`)
)

func TestASFFShapeAndProductArn(t *testing.T) {
	fs := ASFF(loadInput(t), ASFFOptions{})
	if len(fs) != 6 {
		t.Fatalf("got %d ASFF findings", len(fs))
	}
	for i, f := range fs {
		for _, k := range asffRequired {
			if _, ok := f[k]; !ok {
				t.Errorf("finding %d missing %s", i, k)
			}
		}
		if f["SchemaVersion"] != "2018-10-08" {
			t.Errorf("schema version %v", f["SchemaVersion"])
		}
		if !asffArn.MatchString(f["ProductArn"].(string)) {
			t.Errorf("ProductArn %v", f["ProductArn"])
		}
		if !regexp.MustCompile(`^\d{12}$`).MatchString(f["AwsAccountId"].(string)) {
			t.Errorf("AwsAccountId %v", f["AwsAccountId"])
		}
		for _, k := range []string{"CreatedAt", "UpdatedAt"} {
			if !asffTimeRE.MatchString(f[k].(string)) {
				t.Errorf("%s = %v", k, f[k])
			}
		}
		sev := f["Severity"].(map[string]any)["Label"]
		if !strings.Contains(" INFORMATIONAL LOW MEDIUM HIGH CRITICAL ", " "+sev.(string)+" ") {
			t.Errorf("severity label %v", sev)
		}
		for _, ty := range f["Types"].([]string) {
			if len(strings.Split(ty, "/")) < 2 {
				t.Errorf("type %q is not namespace/category[/classifier]", ty)
			}
		}
	}
	if fs[0]["AwsAccountId"] != "123456789012" || fs[0]["ProductArn"] != "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default" {
		t.Errorf("first finding account/arn: %v %v", fs[0]["AwsAccountId"], fs[0]["ProductArn"])
	}
	opt := ASFF(loadInput(t)[:1], ASFFOptions{ProductArn: "arn:aws:securityhub:us-east-1:999999999999:product/999999999999/default", AccountID: "999999999999"})
	if opt[0]["ProductArn"] != "arn:aws:securityhub:us-east-1:999999999999:product/999999999999/default" || opt[0]["AwsAccountId"] != "123456789012" {
		t.Errorf("explicit ProductArn: %v / %v", opt[0]["ProductArn"], opt[0]["AwsAccountId"])
	}
	golden(t, "asff.json", mustJSON(t, fs))
}

// Security Hub BatchImportFindings limits: 100 findings per call, 240 KB per finding, and the
// documented field limits (Title 256, Description 1024, Recommendation.Text 512, Resources 32,
// Types 50, ProductFields 50 pairs, Id/GeneratorId 512).
func TestASFFSizeLimits(t *testing.T) {
	f := loadInput(t)[0]
	f.Title = strings.Repeat("T", 400)
	f.Description = strings.Repeat("D", 5000)
	f.Remediation = strings.Repeat("R", 900)
	f.Resource.Attributes = map[string]any{"blob": strings.Repeat("x", 400_000)}
	f.Compliance = map[string][]string{}
	for i := 0; i < 80; i++ {
		f.Compliance[fmt.Sprintf("fw%02d", i)] = []string{"1"}
	}
	f.Tags = map[string]string{}
	for i := 0; i < 80; i++ {
		f.Tags[fmt.Sprintf("k%02d", i)] = strings.Repeat("v", 3000)
	}
	out := ASFF([]model.Finding{f}, ASFFOptions{})[0]
	if n := len([]rune(out["Title"].(string))); n > 256 {
		t.Errorf("Title %d chars", n)
	}
	if n := len([]rune(out["Description"].(string))); n > 1024 {
		t.Errorf("Description %d chars", n)
	}
	rec := out["Remediation"].(map[string]any)["Recommendation"].(map[string]any)
	if n := len([]rune(rec["Text"].(string))); n > 512 {
		t.Errorf("Recommendation.Text %d chars", n)
	}
	if n := len(out["ProductFields"].(map[string]string)); n > 50 {
		t.Errorf("ProductFields %d pairs", n)
	}
	for k, v := range out["ProductFields"].(map[string]string) {
		if len(k) > 128 || len([]rune(v)) > 2048 {
			t.Errorf("ProductFields %q (%d) too long", k, len(v))
		}
	}
	if comp, ok := out["Compliance"].(map[string]any); ok {
		if n := len(comp["RelatedRequirements"].([]string)); n > 32 {
			t.Errorf("RelatedRequirements %d", n)
		}
	}
	b, _ := json.Marshal(out)
	if len(b) > ASFFMaxFindingBytes {
		t.Errorf("finding is %d bytes, limit %d", len(b), ASFFMaxFindingBytes)
	}
	many := make([]model.Finding, 250)
	for i := range many {
		many[i] = loadInput(t)[0]
		many[i].ID = fmt.Sprintf("id-%03d", i)
	}
	batches := ASFFBatches(ASFF(many, ASFFOptions{}))
	if len(batches) != 3 || len(batches[0]) != 100 || len(batches[2]) != 50 {
		t.Errorf("batches: %d", len(batches))
	}
}

var gitlabTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$`)

// GitLab SAST report schema v15 (security-report-schemas sast-report-format.json): required
// top-level version + vulnerabilities + scan; scan.{analyzer,scanner}.{id,name,vendor.name,
// version}, scan.type "sast", scan.status, start/end time without zone; each vulnerability has
// id, identifiers (≥1, each type/name/value), location.file, and a severity from the enum.
func TestGitLabSASTv15(t *testing.T) {
	rep := GitLabSAST(loadInput(t))
	b := mustJSON(t, rep)
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if v, _ := doc["version"].(string); !strings.HasPrefix(v, "15.") {
		t.Errorf("version %v", doc["version"])
	}
	scan := doc["scan"].(map[string]any)
	for _, k := range []string{"analyzer", "scanner"} {
		c := scan[k].(map[string]any)
		for _, f := range []string{"id", "name", "version"} {
			if s, _ := c[f].(string); s == "" {
				t.Errorf("scan.%s.%s empty", k, f)
			}
		}
		if c["vendor"].(map[string]any)["name"] == "" {
			t.Errorf("scan.%s.vendor.name empty", k)
		}
	}
	if scan["type"] != "sast" || scan["status"] != "success" || !gitlabTime.MatchString(scan["start_time"].(string)) || !gitlabTime.MatchString(scan["end_time"].(string)) {
		t.Errorf("scan: %v", scan)
	}
	vulns := doc["vulnerabilities"].([]any)
	if len(vulns) != 4 { // 3 FAIL + 1 scan gap; PASS and SKIP are not vulnerabilities
		t.Errorf("%d vulnerabilities, want 4", len(vulns))
	}
	sevs := map[string]bool{"Critical": true, "High": true, "Medium": true, "Low": true, "Info": true, "Unknown": true}
	ids := map[string]bool{}
	for i, v := range vulns {
		m := v.(map[string]any)
		id, _ := m["id"].(string)
		if id == "" || ids[id] {
			t.Errorf("vuln %d id %q empty or duplicate", i, id)
		}
		ids[id] = true
		if !sevs[m["severity"].(string)] {
			t.Errorf("vuln %d severity %v", i, m["severity"])
		}
		idents := m["identifiers"].([]any)
		if len(idents) == 0 {
			t.Errorf("vuln %d no identifiers", i)
		}
		for _, x := range idents {
			im := x.(map[string]any)
			if im["type"] == "" || im["name"] == "" || im["value"] == "" {
				t.Errorf("vuln %d identifier %v", i, im)
			}
		}
		if loc := m["location"].(map[string]any); loc["file"] == "" {
			t.Errorf("vuln %d location %v", i, loc)
		}
		for _, banned := range []string{"category", "message", "cve", "scanner"} { // removed in v15
			if _, ok := m[banned]; ok {
				t.Errorf("vuln %d has field %q removed in schema v15", i, banned)
			}
		}
	}
	golden(t, "gitlab-sast.json", b)
}

func TestJUnit(t *testing.T) {
	out, err := JUnit(loadInput(t))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		XMLName  xml.Name `xml:"testsuites"`
		Tests    int      `xml:"tests,attr"`
		Failures int      `xml:"failures,attr"`
		Errors   int      `xml:"errors,attr"`
		Skipped  int      `xml:"skipped,attr"`
		Suites   []struct {
			Name  string `xml:"name,attr"`
			Tests int    `xml:"tests,attr"`
			Cases []struct {
				Name    string    `xml:"name,attr"`
				Failure *struct{} `xml:"failure"`
				Error   *struct{} `xml:"error"`
				Skipped *struct{} `xml:"skipped"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("invalid XML: %v\n%s", err, out)
	}
	if doc.Tests != 6 || doc.Failures != 3 || doc.Errors != 1 || doc.Skipped != 1 {
		t.Errorf("totals tests=%d failures=%d errors=%d skipped=%d", doc.Tests, doc.Failures, doc.Errors, doc.Skipped)
	}
	n := 0
	for _, s := range doc.Suites {
		n += len(s.Cases)
		if s.Tests != len(s.Cases) {
			t.Errorf("suite %s tests=%d cases=%d", s.Name, s.Tests, len(s.Cases))
		}
	}
	if n != 6 {
		t.Errorf("%d testcases", n)
	}
	if !bytes.Contains(out, []byte("&lt;admin&gt;")) {
		t.Errorf("markup in descriptions must be escaped")
	}
	golden(t, "junit.xml", out)
}

func TestCSVEscapesFormulas(t *testing.T) {
	fs := loadInput(t)
	fs[0].Title = "=HYPERLINK(\"http://evil\")"
	out, err := CSV(fs)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 7 || rows[0][0] != "id" {
		t.Fatalf("rows %d header %v", len(rows), rows[0])
	}
	found := false
	for _, c := range rows[1] {
		if strings.HasPrefix(c, "'=HYPERLINK") {
			found = true
		}
		if strings.HasPrefix(c, "=") {
			t.Errorf("formula cell not neutralised: %q", c)
		}
	}
	if !found {
		t.Errorf("title cell missing: %v", rows[1])
	}
	good, _ := CSV(loadInput(t))
	golden(t, "findings.csv", good)
}

// GitHub code scanning accepts at most 25,000 results per run; beyond that nimbus keeps the
// most severe results and says so in a tool execution notification.
func TestSARIFTruncatesAtGitHubLimit(t *testing.T) {
	var fs []model.Finding
	for i := 0; i < MaxSARIFResults+10; i++ {
		sev := model.Low
		if i >= MaxSARIFResults { // the last ten are critical: they must survive truncation
			sev = model.Critical
		}
		fs = append(fs, model.Finding{ID: fmt.Sprintf("f%d", i), CanonicalID: "X", Status: model.Fail, Severity: sev, Provider: "aws", Resource: model.Resource{ID: fmt.Sprint(i)}})
	}
	doc := SARIF(fs)
	run := doc["runs"].([]map[string]any)[0]
	res := run["results"].([]map[string]any)
	if len(res) != MaxSARIFResults {
		t.Fatalf("%d results, want %d", len(res), MaxSARIFResults)
	}
	crit := 0
	for _, r := range res {
		if r["level"] == "error" {
			crit++
		}
	}
	if crit != 10 {
		t.Errorf("critical results kept: %d, want 10", crit)
	}
	inv, ok := run["invocations"].([]map[string]any)
	if !ok || len(inv) != 1 {
		t.Fatalf("no invocation notice: %v", run["invocations"])
	}
	notes := inv[0]["toolExecutionNotifications"].([]map[string]any)
	if len(notes) == 0 || !strings.Contains(notes[0]["message"].(map[string]any)["text"].(string), "10 of 25010") {
		t.Errorf("truncation notice: %v", notes)
	}
	if run["properties"].(map[string]any)["truncated"] != true {
		t.Errorf("truncated property missing")
	}
	// Under the limit nothing changes: no invocations block.
	small := SARIF(loadInput(t))["runs"].([]map[string]any)[0]
	if _, ok := small["invocations"]; ok {
		t.Errorf("untruncated run must not carry invocations")
	}
	golden(t, "sarif.json", mustJSON(t, SARIF(loadInput(t))))
}

func readGoldenInput(t *testing.T) []byte {
	b, err := os.ReadFile(filepath.Join(goldenDir, "input.findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Convert from nimbus JSON to every format equals the direct renderer, and auto-detects input.
func TestConvertMatrix(t *testing.T) {
	in := readGoldenInput(t)
	fs := loadInput(t)
	direct := map[string][]byte{
		"sarif": mustJSON(t, SARIF(fs)), "ocsf": mustJSON(t, OCSF(fs)), "asff": mustJSON(t, ASFF(fs, ASFFOptions{})),
		"gitlab": mustJSON(t, GitLabSAST(fs)), "json": mustJSON(t, NativeDocument(fs)),
	}
	direct["junit"], _ = JUnit(fs)
	direct["csv"], _ = CSV(fs)
	for _, to := range ConvertFormats() {
		if to == "html" {
			continue
		}
		got, err := Convert(in, "json", to)
		if err != nil {
			t.Errorf("json → %s: %v", to, err)
			continue
		}
		if want, ok := direct[to]; ok && !bytes.Equal(got, want) {
			t.Errorf("json → %s differs from the renderer:\n%s", to, firstDiff(string(want), string(got)))
		}
		if auto, err := Convert(in, "", to); err != nil || !bytes.Equal(auto, got) {
			t.Errorf("auto-detect → %s: %v", to, err)
		}
	}
	// The scan document (`scan --format json`) and JSON lines are accepted as nimbus JSON.
	scanDoc, _ := json.Marshal(map[string]any{"scan": map[string]any{"scan_id": "x"}, "findings": json.RawMessage(in)})
	var lines bytes.Buffer
	for _, f := range fs {
		b, _ := json.Marshal(f)
		lines.Write(b)
		lines.WriteByte('\n')
	}
	for name, src := range map[string][]byte{"scan document": scanDoc, "jsonl": lines.Bytes()} {
		got, err := Convert(src, "", "ocsf")
		if err != nil || !bytes.Equal(got, direct["ocsf"]) {
			t.Errorf("%s → ocsf: %v", name, err)
		}
	}
	if _, err := Convert(in, "json", "pdf"); err == nil {
		t.Error("unknown target format must fail")
	}
	if _, err := Convert([]byte("not json"), "", "sarif"); err == nil {
		t.Error("undetectable input must fail")
	}
	golden(t, "native.json", direct["json"])
}

// Round trips: OCSF is lossless; SARIF and ASFF keep every finding's id, fingerprint inputs
// and status for the results they carry (both drop PASS-only details they have no slot for).
func TestConvertRoundTrips(t *testing.T) {
	in := readGoldenInput(t)
	orig := loadInput(t)
	for _, via := range []string{"ocsf", "sarif", "asff"} {
		mid, err := Convert(in, "json", via)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Convert(mid, "", "json")
		if err != nil {
			t.Fatalf("%s → json: %v", via, err)
		}
		got, err := ParseNative(back)
		if err != nil {
			t.Fatal(err)
		}
		if via == "ocsf" {
			if !bytes.Equal(back, mustJSON(t, NativeDocument(orig))) {
				t.Errorf("ocsf round trip is not lossless:\n%s", firstDiff(string(mustJSON(t, NativeDocument(orig))), string(back)))
			}
			continue
		}
		byID := map[string]model.Finding{}
		for _, f := range orig {
			byID[f.ID] = f
		}
		for _, g := range got {
			o, ok := byID[g.ID]
			if !ok {
				t.Errorf("%s: unknown id %s", via, g.ID)
				continue
			}
			if g.Fingerprint() != o.Fingerprint() || g.Status != o.Status || g.Severity != o.Severity || g.CanonicalID != o.CanonicalID || g.File != o.File || g.LineStart != o.LineStart {
				t.Errorf("%s round trip of %s:\n got  %+v\n want %+v", via, o.ID, g, o)
			}
		}
		if want := map[string]int{"sarif": 4, "asff": 6}[via]; len(got) != want {
			t.Errorf("%s carried %d findings, want %d", via, len(got), want)
		}
	}
}

func TestConvertHTMLUsesEscapedDashboard(t *testing.T) {
	out, err := Convert(readGoldenInput(t), "json", "html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(strings.ToLower(s[:200]), "<!doctype html>") {
		t.Errorf("not an HTML document: %.200s", s)
	}
	if strings.Contains(s, "<admin>") {
		t.Error("finding text was inserted unescaped")
	}
	if !strings.Contains(s, "S3_PUBLIC_BUCKET") {
		t.Error("findings missing from the page")
	}
}
