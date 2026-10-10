// Package compliance turns findings into per-framework control status reports.
package compliance

import (
	"archive/zip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"gopkg.in/yaml.v3"
)

//go:generate go run ./gen

//go:embed frameworks.yaml
var frameworksYAML []byte

//go:embed extra.yaml
var extraYAML []byte

// importedFS holds frameworks converted from Prowler's compliance JSON by
// tools/import-prowler-frameworks (one file per framework, plus index.yaml).
//
//go:embed frameworks/*.yaml
var importedFS embed.FS

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
	// Checks lists, per control, the canonical finding ids that assess it (imported frameworks).
	// A finding whose CanonicalID is listed maps to the control in addition to f.Compliance.
	Checks map[string][]string `yaml:"-" json:"-"`
	// Provenance is set for frameworks imported from upstream (licence, attribution, source).
	Provenance *Provenance `yaml:"-" json:"provenance,omitempty"`
}

// Provenance records where an imported framework came from.
type Provenance struct {
	Source       string `yaml:"source" json:"source"`
	Framework    string `yaml:"framework" json:"framework,omitempty"`
	Provider     string `yaml:"provider" json:"provider,omitempty"`
	UpstreamPath string `yaml:"upstream_path" json:"upstream_path"`
	UpstreamURL  string `yaml:"upstream_url" json:"upstream_url"`
	License      string `yaml:"license" json:"license"`
	Attribution  string `yaml:"attribution" json:"attribution"`
	TextPolicy   string `yaml:"text_policy" json:"text_policy"`
	ReferenceURL string `yaml:"reference_url" json:"reference_url,omitempty"`
}

// ControlCoverage is the honest denominator of a framework: how many of its controls nimbus can
// assess with its own checks, how many only through ingested Prowler results, and how many are
// manual (no automated check at all).
type ControlCoverage struct {
	Native        int `json:"native"`
	ProwlerIngest int `json:"prowler_ingest"`
	Manual        int `json:"manual"`
}

type file struct {
	Frameworks       map[string]*Framework          `yaml:"frameworks"`
	WeaknessMappings map[string]map[string][]string `yaml:"weakness_mappings"`
}

type importedFile struct {
	Key          string `yaml:"key"`
	Name         string `yaml:"name"`
	Version      string `yaml:"version"`
	Provenance   `yaml:",inline"`
	Requirements []struct {
		ID     string   `yaml:"id"`
		Title  string   `yaml:"title"`
		Checks []string `yaml:"checks"`
	} `yaml:"requirements"`
}

var (
	loadOnce         sync.Once
	loaded           map[string]*Framework
	weaknessMappings map[string]map[string][]string
	checkIndex       map[string]map[string][]string // framework -> upper(canonical id) -> controls
	coverage         map[string]ControlCoverage
)

func load() {
	loadOnce.Do(func() {
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
		handWritten := map[string]bool{}
		for k := range f.Frameworks {
			handWritten[k] = true
		}
		names, err := fs.Glob(importedFS, "frameworks/*.yaml")
		if err != nil {
			panic(err)
		}
		for _, name := range names {
			if path.Base(name) == "index.yaml" {
				continue
			}
			data, err := importedFS.ReadFile(name)
			if err != nil {
				panic(err)
			}
			var imp importedFile
			if err := yaml.Unmarshal(data, &imp); err != nil {
				panic(fmt.Sprintf("%s: %v", name, err))
			}
			if imp.Key == "" || imp.License == "" || imp.Attribution == "" || imp.Source == "" {
				panic(fmt.Sprintf("%s: imported framework must declare key, license, attribution and source", name))
			}
			if _, clash := f.Frameworks[imp.Key]; clash {
				panic(fmt.Sprintf("%s: key %q already defined", name, imp.Key))
			}
			prov := imp.Provenance
			fw := &Framework{Key: imp.Key, Name: imp.Name, Version: imp.Version, Controls: map[string]string{}, Checks: map[string][]string{}, Provenance: &prov}
			for _, r := range imp.Requirements {
				fw.Controls[r.ID] = r.Title
				if len(r.Checks) > 0 {
					fw.Checks[r.ID] = append([]string(nil), r.Checks...)
				}
			}
			f.Frameworks[imp.Key] = fw
		}
		loaded = f.Frameworks
		checkIndex = map[string]map[string][]string{}
		for k, fw := range loaded {
			if len(fw.Checks) == 0 {
				continue
			}
			idx := map[string][]string{}
			for ctrl, ids := range fw.Checks {
				for _, id := range ids {
					u := strings.ToUpper(id)
					idx[u] = append(idx[u], ctrl)
				}
			}
			for _, ctrls := range idx {
				sort.Slice(ctrls, func(i, j int) bool { return controlLess(ctrls[i], ctrls[j]) })
			}
			checkIndex[k] = idx
		}
		coverage = computeCoverage(loaded, handWritten, weaknessMappings)
	})
}

// computeCoverage classifies each control. Imported frameworks: native when a listed check is a
// catalog canonical id, prowler_ingest when only PROWLER:<check> ids are listed, manual when none.
// Hand-written frameworks: native when any catalog entry maps to the control, through its
// compliance list or through a weakness mapping, else manual.
func computeCoverage(fws map[string]*Framework, handWritten map[string]bool, wm map[string]map[string][]string) map[string]ControlCoverage {
	mapped := map[string]map[string]bool{}
	mark := func(fw string, ctrls []string) {
		if mapped[fw] == nil {
			mapped[fw] = map[string]bool{}
		}
		for _, c := range ctrls {
			mapped[fw][c] = true
		}
	}
	for _, e := range catalog.Default().Entries {
		for fw, ctrls := range e.Compliance {
			mark(fw, ctrls)
		}
		for _, w := range e.Weaknesses {
			for fw, ctrls := range wm[w] {
				mark(fw, ctrls)
			}
		}
	}
	out := map[string]ControlCoverage{}
	for k, fw := range fws {
		var c ControlCoverage
		for ctrl := range fw.Controls {
			if handWritten[k] {
				if mapped[k][ctrl] {
					c.Native++
				} else {
					c.Manual++
				}
				continue
			}
			native, ingest := false, false
			for _, id := range fw.Checks[ctrl] {
				if strings.HasPrefix(id, "PROWLER:") {
					ingest = true
				} else {
					native = true
				}
			}
			switch {
			case native:
				c.Native++
			case ingest:
				c.ProwlerIngest++
			default:
				c.Manual++
			}
		}
		out[k] = c
	}
	return out
}

func copyFramework(fw *Framework) *Framework {
	c := *fw
	c.Controls = make(map[string]string, len(fw.Controls))
	for k, v := range fw.Controls {
		c.Controls[k] = v
	}
	if fw.Checks != nil {
		c.Checks = make(map[string][]string, len(fw.Checks))
		for k, v := range fw.Checks {
			c.Checks[k] = append([]string(nil), v...)
		}
	}
	if fw.Provenance != nil {
		p := *fw.Provenance
		c.Provenance = &p
	}
	return &c
}

// Frameworks returns a fresh copy of every built-in framework (hand-written and imported).
func Frameworks() map[string]*Framework {
	load()
	out := make(map[string]*Framework, len(loaded))
	for k, fw := range loaded {
		out[k] = copyFramework(fw)
	}
	return out
}

func lookupFramework(key string) (*Framework, bool) {
	load()
	fw, ok := loaded[key]
	if !ok {
		return nil, false
	}
	return copyFramework(fw), true
}

// Coverage returns the control coverage classes of a built-in framework.
func Coverage(key string) (ControlCoverage, bool) {
	load()
	c, ok := coverage[key]
	return c, ok
}

// controlsFor lists the controls of a framework a finding maps to: its explicit compliance
// mappings plus every control whose check list contains its canonical id.
func controlsFor(key string, f *model.Finding) []string {
	load()
	ctrls := f.Compliance[key]
	idx := checkIndex[key]
	if idx == nil || f.CanonicalID == "" {
		return ctrls
	}
	extra := idx[strings.ToUpper(f.CanonicalID)]
	if len(extra) == 0 {
		return ctrls
	}
	out := append([]string(nil), ctrls...)
	for _, c := range extra {
		out = appendUnique(out, c)
	}
	return out
}

// WeaknessMappings returns framework controls implied by each weakness (SOC 2, ISO 27001).
func WeaknessMappings() map[string]map[string][]string {
	load()
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
	// Assessed = Passing + Failing; Total is the denominator ("N of M controls assessed").
	Assessed int              `json:"assessed"`
	Coverage *ControlCoverage `json:"coverage,omitempty"`
}

// Build evaluates findings against a framework. A control FAILs if any FAIL finding maps
// to it, PASSes if only PASS findings map to it, else NOT_ASSESSED.
func Build(frameworkKey string, findings []model.Finding, scope string) (*Report, error) {
	fw, ok := lookupFramework(frameworkKey)
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
	load()
	for i := range findings {
		f := &findings[i]
		for _, ctrl := range controlsFor(frameworkKey, f) {
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
	if c, ok := coverage[frameworkKey]; ok {
		rep.Coverage = &c
	}
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
	rep.Assessed = rep.Passing + rep.Failing
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
	fmt.Fprintf(&b, "%d of %d controls assessed.\n", r.Assessed, r.Total)
	if c := r.Coverage; c != nil {
		fmt.Fprintf(&b, "Coverage: %d assessable natively, %d via Prowler ingest, %d manual.\n", c.Native, c.ProwlerIngest, c.Manual)
	}
	if p := r.Framework.Provenance; p != nil {
		fmt.Fprintf(&b, "Source: %s, %s (%s).\n", p.Source, p.License, p.UpstreamURL)
		if p.ReferenceURL != "" {
			fmt.Fprintf(&b, "Control text: %s\n", p.ReferenceURL)
		}
	}
	b.WriteString("\n")
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
				for _, ctl := range controlsFor(rep.Framework.Key, &fd) {
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
