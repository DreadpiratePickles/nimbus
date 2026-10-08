// Package compliance turns findings into per-framework control status reports.
package compliance

import (
	"archive/zip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"gopkg.in/yaml.v3"
)

//go:embed frameworks.yaml
var frameworksYAML []byte

//go:embed extra.yaml
var extraYAML []byte

// ISO 27001:2022 Annex A controls referenced by weakness mappings.
var iso27001Controls = map[string]string{
	"A.5.15": "Access control", "A.5.17": "Authentication information", "A.8.2": "Privileged access rights",
	"A.8.3": "Information access restriction", "A.8.5": "Secure authentication", "A.8.6": "Capacity management",
	"A.8.8": "Management of technical vulnerabilities", "A.8.9": "Configuration management", "A.8.12": "Data leakage prevention",
	"A.8.13": "Information backup", "A.8.15": "Logging", "A.8.16": "Monitoring activities", "A.8.20": "Networks security",
	"A.8.22": "Segregation of networks", "A.8.24": "Use of cryptography", "A.8.28": "Secure coding", "A.8.32": "Change management",
}

type Framework struct {
	Key      string            `yaml:"-" json:"key"`
	Name     string            `yaml:"name" json:"name"`
	Version  string            `yaml:"version" json:"version"`
	Controls map[string]string `yaml:"controls" json:"controls"`
}

type file struct {
	Frameworks       map[string]*Framework          `yaml:"frameworks"`
	WeaknessMappings map[string]map[string][]string `yaml:"weakness_mappings"`
}

var weaknessMappings map[string]map[string][]string

func Frameworks() map[string]*Framework {
	var f file
	if err := yaml.Unmarshal(frameworksYAML, &f); err != nil {
		panic(err)
	}
	var extra file
	if err := yaml.Unmarshal(extraYAML, &extra); err != nil {
		panic(err)
	}
	for k, fw := range extra.Frameworks {
		f.Frameworks[k] = fw
	}
	for k, fw := range f.Frameworks {
		fw.Key = k
	}
	if iso, ok := f.Frameworks["iso_27001"]; ok {
		if iso.Controls == nil {
			iso.Controls = map[string]string{}
		}
		for id, title := range iso27001Controls {
			iso.Controls[id] = title
		}
		iso.Version = "2022"
	}
	weaknessMappings = extra.WeaknessMappings
	return f.Frameworks
}

// WeaknessMappings returns framework controls implied by each weakness (SOC 2, ISO 27001).
func WeaknessMappings() map[string]map[string][]string {
	if weaknessMappings == nil {
		Frameworks()
	}
	return weaknessMappings
}

// DeriveCompliance adds SOC 2 / ISO 27001 controls to a finding from its weaknesses.
func DeriveCompliance(f *model.Finding) {
	for _, w := range f.Weaknesses {
		for fw, ctrls := range WeaknessMappings()[w] {
			f.AddCompliance(fw, ctrls...)
		}
	}
}

// CustomFramework is a user-defined pack: controls map to canonical IDs and/or weaknesses.
type CustomFramework struct {
	Key      string `yaml:"key"`
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Controls map[string]struct {
		Title        string   `yaml:"title"`
		CanonicalIDs []string `yaml:"canonical_ids"`
		Weaknesses   []string `yaml:"weaknesses"`
	} `yaml:"controls"`
}

// LoadCustom parses a custom framework YAML and tags findings with its controls.
func LoadCustom(data []byte, findings []model.Finding) (*Framework, error) {
	var cf CustomFramework
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, err
	}
	if cf.Key == "" {
		cf.Key = strings.ToLower(strings.ReplaceAll(cf.Name, " ", "_"))
	}
	fw := &Framework{Key: cf.Key, Name: cf.Name, Version: cf.Version, Controls: map[string]string{}}
	for id, c := range cf.Controls {
		fw.Controls[id] = c.Title
		for i := range findings {
			f := &findings[i]
			match := false
			for _, cid := range c.CanonicalIDs {
				if strings.EqualFold(cid, f.CanonicalID) {
					match = true
				}
			}
			for _, w := range c.Weaknesses {
				if f.HasWeakness(w) {
					match = true
				}
			}
			if match {
				f.AddCompliance(cf.Key, id)
			}
		}
	}
	return fw, nil
}

// Aliases let users type cis, nist, pci, hipaa, gdpr, iso.
func ResolveKey(name, provider string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "cis":
		switch provider {
		case "", "aws":
			return "cis_aws"
		case "kubernetes":
			return "cis_k8s"
		}
		return "cis_" + provider
	case "nist", "nist-800-53", "nist800-53":
		return "nist_800_53"
	case "pci", "pci-dss", "pcidss":
		return "pci_dss"
	case "iso", "iso27001", "iso-27001":
		return "iso_27001"
	}
	return strings.ReplaceAll(n, "-", "_")
}

type ControlStatus struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Status    string   `json:"status"` // PASS | FAIL | NOT_ASSESSED
	Failed    int      `json:"failed"`
	Passed    int      `json:"passed"`
	Findings  []string `json:"finding_ids,omitempty"`
	Resources []string `json:"resources,omitempty"`
	MaxSev    string   `json:"max_severity,omitempty"`
}

type Report struct {
	Framework    Framework       `json:"framework"`
	Scope        string          `json:"scope"`
	Controls     []ControlStatus `json:"controls"`
	Total        int             `json:"total_controls"`
	Passing      int             `json:"passing"`
	Failing      int             `json:"failing"`
	NotAssessed  int             `json:"not_assessed"`
	ScorePercent float64         `json:"score_percent"`
}

// Build evaluates findings against a framework. A control FAILs if any FAIL finding maps
// to it, PASSes if only PASS findings map to it, else NOT_ASSESSED.
func Build(frameworkKey string, findings []model.Finding, scope string) (*Report, error) {
	fws := Frameworks()
	fw, ok := fws[frameworkKey]
	if !ok {
		fw = &Framework{Key: frameworkKey, Name: frameworkKey, Controls: map[string]string{}}
	}
	for i := range findings {
		DeriveCompliance(&findings[i])
	}
	status := map[string]*ControlStatus{}
	for id, title := range fw.Controls {
		status[id] = &ControlStatus{ID: id, Title: title, Status: "NOT_ASSESSED"}
	}
	for _, f := range findings {
		for _, ctrl := range f.Compliance[frameworkKey] {
			cs, ok := status[ctrl]
			if !ok {
				cs = &ControlStatus{ID: ctrl, Status: "NOT_ASSESSED"}
				status[ctrl] = cs
			}
			switch f.Status {
			case model.Fail:
				cs.Failed++
				cs.Status = "FAIL"
				cs.Findings = append(cs.Findings, f.ID)
				cs.Resources = appendUnique(cs.Resources, f.Resource.Name)
				if model.Severity(cs.MaxSev).Rank() < f.Severity.Rank() {
					cs.MaxSev = string(f.Severity)
				}
			case model.Pass:
				cs.Passed++
				if cs.Status == "NOT_ASSESSED" {
					cs.Status = "PASS"
				}
			}
		}
	}
	rep := &Report{Framework: *fw, Scope: scope}
	for _, cs := range status {
		rep.Controls = append(rep.Controls, *cs)
		switch cs.Status {
		case "PASS":
			rep.Passing++
		case "FAIL":
			rep.Failing++
		default:
			rep.NotAssessed++
		}
	}
	sort.Slice(rep.Controls, func(i, j int) bool { return controlLess(rep.Controls[i].ID, rep.Controls[j].ID) })
	rep.Total = len(rep.Controls)
	if assessed := rep.Passing + rep.Failing; assessed > 0 {
		rep.ScorePercent = float64(int(float64(rep.Passing)/float64(assessed)*1000)) / 10
	}
	return rep, nil
}

func (r *Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s %s compliance report\n\n", r.Framework.Name, r.Framework.Version)
	if r.Scope != "" {
		fmt.Fprintf(&b, "Scope: %s\n\n", r.Scope)
	}
	fmt.Fprintf(&b, "| Score | Passing | Failing | Not assessed |\n|---|---|---|---|\n| %.1f%% | %d | %d | %d |\n\n", r.ScorePercent, r.Passing, r.Failing, r.NotAssessed)
	b.WriteString("| Control | Title | Status | Failing resources | Max severity |\n|---|---|---|---|---|\n")
	for _, c := range r.Controls {
		res := strings.Join(c.Resources, ", ")
		if len(res) > 80 {
			res = res[:77] + "..."
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", c.ID, c.Title, c.Status, res, c.MaxSev)
	}
	return b.String()
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// controlLess sorts "1.10" after "1.5" and "AC-6(1)" after "AC-6".
func controlLess(a, b string) bool {
	as, bs := splitControl(a), splitControl(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		var ai, bi int
		_, errA := fmt.Sscanf(as[i], "%d", &ai)
		_, errB := fmt.Sscanf(bs[i], "%d", &bi)
		if errA == nil && errB == nil && ai != bi {
			return ai < bi
		}
		return as[i] < bs[i]
	}
	return len(as) < len(bs)
}

func splitControl(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '(' || r == ')' })
}

// EvidenceZip writes an auditor-ready evidence package: one folder per control with the
// failing/passing findings as JSON, a manifest with SHA-256 digests (AWS Audit Manager style),
// the markdown report and the scan metadata.
func EvidenceZip(path string, rep *Report, findings []model.Finding, meta map[string]any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()
	byID := map[string]model.Finding{}
	for _, fd := range findings {
		byID[fd.ID] = fd
	}
	manifest := map[string]string{}
	write := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		manifest[name] = hex.EncodeToString(sum[:])
		return nil
	}
	if err := write("report.md", []byte(rep.Markdown())); err != nil {
		return err
	}
	repJSON, _ := json.MarshalIndent(rep, "", "  ")
	if err := write("report.json", repJSON); err != nil {
		return err
	}
	for _, c := range rep.Controls {
		dir := "controls/" + strings.NewReplacer("/", "_", "(", "_", ")", "").Replace(c.ID) + "/"
		var evidence []model.Finding
		for _, id := range c.Findings {
			if fd, ok := byID[id]; ok {
				evidence = append(evidence, fd)
			}
		}
		for _, fd := range findings {
			if fd.Status == model.Pass {
				for _, ctl := range fd.Compliance[rep.Framework.Key] {
					if ctl == c.ID {
						evidence = append(evidence, fd)
					}
				}
			}
		}
		if len(evidence) == 0 {
			continue
		}
		data, _ := json.MarshalIndent(map[string]any{"control": c, "evidence": evidence, "collected_at": time.Now().UTC()}, "", "  ")
		if err := write(dir+"evidence.json", data); err != nil {
			return err
		}
	}
	if meta == nil {
		meta = map[string]any{}
	}
	meta["framework"] = rep.Framework
	meta["generated_at"] = time.Now().UTC()
	metaJSON, _ := json.MarshalIndent(meta, "", "  ")
	if err := write("metadata.json", metaJSON); err != nil {
		return err
	}
	digest, _ := json.MarshalIndent(manifest, "", "  ")
	w, err := zw.Create("MANIFEST.sha256.json")
	if err != nil {
		return err
	}
	_, err = w.Write(digest)
	return err
}
