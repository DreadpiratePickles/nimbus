package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/compliance"
	"github.com/DreadpiratePickles/nimbus/internal/dashboard"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// FindingSpecVersion is the version of the native finding contract (docs/spec/finding-v1.md).
const FindingSpecVersion = "1.0.0"

// ConvertFormats lists the target formats Convert writes.
func ConvertFormats() []string {
	return []string{"json", "sarif", "ocsf", "asff", "gitlab", "junit", "csv", "html"}
}

// ConvertInputs lists the source formats Convert reads ("" or "auto" sniffs the content).
func ConvertInputs() []string { return []string{"json", "ocsf", "sarif", "asff"} }

// MaxConvertInput caps one convert input: parsing expands a document several-fold in memory
// (verify-4: a 200 MB file cost 1.4 GB RSS), so larger inputs are refused with a clear error.
const MaxConvertInput = 64 << 20

// ErrConvertTooLarge is matched (errors.Is) when an input exceeds MaxConvertInput.
var ErrConvertTooLarge = errors.New("convert: input too large")

func convertTooLarge() error {
	return fmt.Errorf("%w: over the %d MiB limit; split the findings file (e.g. by account) and convert each part", ErrConvertTooLarge, MaxConvertInput>>20)
}

// ReadConvertInput reads one convert input, refusing more than MaxConvertInput bytes without
// buffering the rest.
func ReadConvertInput(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxConvertInput+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxConvertInput {
		return nil, convertTooLarge()
	}
	return b, nil
}

// Convert re-renders findings from one format into another. It is pure: no files, no
// network, no clock (report timestamps come from the findings). Inputs: nimbus JSON (a
// findings array, JSON lines, the {"spec_version","findings"} envelope or a `scan --format
// json` document), OCSF Detection Finding JSON (nimbus's or Prowler's), and the SARIF and ASFF
// that nimbus writes. OCSF ↔ JSON is lossless; SARIF carries open findings only and ASFF keeps
// identity but not attributes or relations (docs/spec/finding-v1.md, "Format mappings").
//
// Inputs larger than MaxConvertInput are refused before parsing (ErrConvertTooLarge).
func Convert(in []byte, from, to string) ([]byte, error) {
	if len(in) > MaxConvertInput {
		return nil, convertTooLarge()
	}
	from = normFormat(from)
	to = normFormat(to)
	if from == "" || from == "auto" {
		var err error
		if from, err = DetectFormat(in); err != nil {
			return nil, err
		}
	}
	var fs []model.Finding
	var err error
	switch from {
	case "json":
		fs, err = ParseNative(in)
	case "ocsf":
		fs, err = ParseOCSF(in)
	case "sarif":
		fs, err = ParseSARIF(in)
	case "asff":
		fs, err = ParseASFF(in)
	default:
		return nil, fmt.Errorf("convert: unsupported input format %q (want one of %s)", from, strings.Join(ConvertInputs(), ", "))
	}
	if err != nil {
		return nil, err
	}
	return Render(fs, to)
}

// Render writes findings in one of ConvertFormats.
func Render(fs []model.Finding, to string) ([]byte, error) {
	enc := func(v any) ([]byte, error) {
		var buf bytes.Buffer
		err := JSON(&buf, v)
		return buf.Bytes(), err
	}
	switch normFormat(to) {
	case "json":
		return enc(NativeDocument(fs))
	case "sarif":
		return enc(SARIF(fs))
	case "ocsf":
		return enc(OCSF(fs))
	case "asff":
		return enc(ASFF(fs, ASFFOptions{}))
	case "gitlab":
		return enc(GitLabSAST(fs))
	case "junit":
		return JUnit(fs)
	case "csv":
		return CSV(fs)
	case "html":
		return HTML(fs)
	}
	return nil, fmt.Errorf("convert: unsupported output format %q (want one of %s)", to, strings.Join(ConvertFormats(), ", "))
}

func normFormat(f string) string {
	f = strings.ToLower(strings.TrimSpace(f))
	switch f {
	case "native", "nimbus", "findings":
		return "json"
	case "json-ocsf", "ocsf-json":
		return "ocsf"
	case "gitlab-sast", "sast":
		return "gitlab"
	case "junit-xml", "xml":
		return "junit"
	case "dashboard":
		return "html"
	case "securityhub", "security-hub":
		return "asff"
	}
	return f
}

// NativeDocument is the versioned envelope of the native contract.
func NativeDocument(fs []model.Finding) map[string]any {
	if fs == nil {
		fs = []model.Finding{}
	}
	return map[string]any{"spec_version": FindingSpecVersion, "findings": fs}
}

// ParseNative reads the native finding contract: a JSON array of findings, JSON lines, or an
// object with a `findings` array (the versioned envelope or a `scan --format json` document).
func ParseNative(data []byte) ([]model.Finding, error) {
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 {
		return nil, nil
	}
	if trim[0] == '{' {
		var env struct {
			SpecVersion string          `json:"spec_version"`
			Findings    json.RawMessage `json:"findings"`
		}
		if err := json.Unmarshal(trim, &env); err == nil && len(env.Findings) > 0 {
			if env.SpecVersion != "" && !strings.HasPrefix(env.SpecVersion, "1.") {
				return nil, fmt.Errorf("native: spec_version %q is not supported (this build reads 1.x)", env.SpecVersion)
			}
			var fs []model.Finding
			if err := json.Unmarshal(env.Findings, &fs); err != nil {
				return nil, fmt.Errorf("native: %w", err)
			}
			return fs, nil
		}
	}
	recs, err := jsonRecords(trim)
	if err != nil {
		return nil, fmt.Errorf("native: %w", err)
	}
	fs := make([]model.Finding, 0, len(recs))
	for i, r := range recs {
		var f model.Finding
		if err := json.Unmarshal(r, &f); err != nil {
			return nil, fmt.Errorf("native: finding %d: %w", i, err)
		}
		fs = append(fs, f)
	}
	return fs, nil
}

// DetectFormat sniffs which of ConvertInputs a document is.
func DetectFormat(data []byte) (string, error) {
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 {
		return "", fmt.Errorf("convert: empty input")
	}
	var probe map[string]json.RawMessage
	switch trim[0] {
	case '{':
		dec := json.NewDecoder(bytes.NewReader(trim))
		if err := dec.Decode(&probe); err != nil {
			return "", fmt.Errorf("convert: input is not JSON: %w", err)
		}
		if _, ok := probe["runs"]; ok {
			return "sarif", nil
		}
		if _, ok := probe["Findings"]; ok {
			return "asff", nil
		}
		if _, ok := probe["findings"]; ok {
			return "json", nil
		}
	case '[':
		var arr []map[string]json.RawMessage
		if err := json.Unmarshal(trim, &arr); err != nil {
			return "", fmt.Errorf("convert: input is not a JSON array of objects: %w", err)
		}
		if len(arr) == 0 {
			return "json", nil
		}
		probe = arr[0]
	default:
		return "", fmt.Errorf("convert: input is not JSON")
	}
	switch {
	case probe["class_uid"] != nil:
		return "ocsf", nil
	case probe["SchemaVersion"] != nil:
		return "asff", nil
	case probe["canonical_id"] != nil || (probe["check_id"] != nil && probe["source"] != nil):
		return "json", nil
	}
	return "", fmt.Errorf("convert: could not detect the input format; pass --from (%s)", strings.Join(ConvertInputs(), ", "))
}

// ParseSARIF reads SARIF written by SARIF() back into findings (results only; rules supply
// title, description and remediation).
func ParseSARIF(data []byte) ([]model.Finding, error) {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID               string                `json:"id"`
						ShortDescription struct{ Text string } `json:"shortDescription"`
						FullDescription  struct{ Text string } `json:"fullDescription"`
						Help             struct{ Text string } `json:"help"`
						Properties       struct {
							Tags []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
						Region           struct {
							StartLine int `json:"startLine"`
							EndLine   int `json:"endLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Properties          map[string]any    `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("sarif: %w", err)
	}
	var out []model.Finding
	for _, run := range doc.Runs {
		type ruleInfo struct {
			title, desc, help string
			tags              []string
		}
		rules := map[string]ruleInfo{}
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = ruleInfo{r.ShortDescription.Text, r.FullDescription.Text, r.Help.Text, r.Properties.Tags}
		}
		for _, r := range run.Results {
			p := r.Properties
			ri := rules[r.RuleID]
			f := model.Finding{
				ID:          r.PartialFingerprints["cloudPostureFingerprint"],
				CanonicalID: r.RuleID,
				Title:       ri.title,
				Severity:    model.Severity(sval(p, "severity")),
				Status:      model.Status(sval(p, "status")),
				Provider:    sval(p, "provider"),
				Account:     sval(p, "account"),
				Region:      sval(p, "region"),
				Source:      sval(p, "source"),
				CheckID:     sval(p, "check_id"),
				Resource:    model.Resource{ID: sval(p, "resource_id"), Type: sval(p, "resource_type")},
			}
			if ri.desc != ri.title {
				f.Description = ri.desc
			}
			if !strings.HasPrefix(ri.help, "See cloud-posture fix") {
				f.Remediation = ri.help
			}
			if len(ri.tags) > 2 {
				f.Weaknesses = append([]string(nil), ri.tags[2:]...)
			}
			if len(r.Locations) > 0 {
				pl := r.Locations[0].PhysicalLocation
				if uri := pl.ArtifactLocation.URI; !strings.HasPrefix(uri, "cloud://") {
					f.File = uri
				} else if f.Resource.ID == "" {
					f.Resource.ID = strings.TrimPrefix(uri, "cloud://"+f.Provider+"/")
				}
				// SARIF() writes endLine = startLine when the finding had no end line, so a
				// missing end line comes back equal to the start line.
				f.LineStart, f.LineEnd = pl.Region.StartLine, pl.Region.EndLine
			}
			// Resource name is in the message "<title> (<name>) — <source>".
			if i := strings.LastIndex(r.Message.Text, " — "); i > 0 {
				head := r.Message.Text[:i]
				if j := strings.LastIndex(head, " ("); j >= 0 && strings.HasSuffix(head, ")") {
					f.Resource.Name = head[j+2 : len(head)-1]
				}
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// HTML renders the single-file dashboard (the same escaped renderer as `scan --format html`)
// for findings alone. The generation time is the newest LastSeen, so output is deterministic.
func HTML(fs []model.Finding) ([]byte, error) {
	cp := make([]model.Finding, len(fs))
	copy(cp, fs)
	var newest time.Time
	accts := map[string]bool{}
	fws := map[string]bool{}
	for _, f := range cp {
		if f.LastSeen.After(newest) {
			newest = f.LastSeen
		}
		if f.Account != "" {
			accts[f.Account] = true
		}
		for fw := range f.Compliance {
			fws[fw] = true
		}
	}
	accounts := make([]string, 0, len(accts))
	for a := range accts {
		accounts = append(accounts, a)
	}
	sort.Strings(accounts)
	var names []string
	for fw := range fws {
		names = append(names, fw)
	}
	sort.Strings(names)
	reports := []*compliance.Report{}
	for _, fw := range names {
		if rep, err := compliance.Build(fw, cp, ""); err == nil && rep.Passing+rep.Failing > 0 {
			reports = append(reports, rep)
		}
	}
	d := dashboard.Data{Mode: "static", Accounts: accounts, Findings: cp, Paths: []model.AttackPath{}, Compliance: reports,
		Issues: []model.Issue{}, Scans: []model.ScanSummary{}}
	if !newest.IsZero() {
		d.GeneratedAt = newest.UTC().Format("2006-01-02 15:04 UTC")
	} else {
		d.GeneratedAt = "1970-01-01 00:00 UTC"
	}
	return dashboard.Render(d)
}
