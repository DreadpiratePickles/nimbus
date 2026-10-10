// Package catalog maps tool-native check IDs onto canonical finding IDs and
// enriches findings with weaknesses, compliance controls and remediation templates.
package catalog

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"gopkg.in/yaml.v3"
)

//go:embed catalog.yaml
var catalogYAML []byte

type Entry struct {
	ID           string              `yaml:"-" json:"id"`
	Title        string              `yaml:"title" json:"title"`
	Provider     string              `yaml:"provider" json:"provider"`
	Severity     model.Severity      `yaml:"severity" json:"severity"`
	ResourceType string              `yaml:"resource_type" json:"resource_type"`
	Weaknesses   []string            `yaml:"weaknesses" json:"weaknesses"`
	Aliases      map[string][]string `yaml:"aliases" json:"aliases"`
	Compliance   map[string][]string `yaml:"compliance" json:"compliance"`
	Remediation  []string            `yaml:"remediation" json:"remediation"`
}

type Catalog struct {
	Entries map[string]*Entry
	// alias index: source -> lower(checkID) -> entry
	index map[string]map[string]*Entry
}

var (
	once           sync.Once
	defaultCatalog *Catalog
	loadErr        error
)

// Default returns the embedded catalog.
func Default() *Catalog {
	once.Do(func() { defaultCatalog, loadErr = Parse(catalogYAML) })
	if loadErr != nil {
		panic(fmt.Sprintf("embedded catalog invalid: %v", loadErr))
	}
	return defaultCatalog
}

func Parse(data []byte) (*Catalog, error) {
	raw := map[string]*Entry{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	c := &Catalog{Entries: raw, index: map[string]map[string]*Entry{}}
	for id, e := range raw {
		e.ID = id
		for source, aliases := range e.Aliases {
			src := strings.ToLower(source)
			if c.index[src] == nil {
				c.index[src] = map[string]*Entry{}
			}
			for _, a := range aliases {
				key := strings.ToLower(strings.TrimSpace(a))
				c.index[src][key] = e
				if trivySpelled(src) {
					c.index[src][strings.ToLower(NormalizeTrivyID(key))] = e
				}
			}
		}
	}
	return c, nil
}

// Lookup resolves a native check ID for a tool. Prefix matches cover IDs such as "CVE-2024-1234".
// Trivy / trivy-operator ids match in every spelling Trivy has emitted (NormalizeTrivyID).
// kube-bench aliases are "<benchmark>:<test_number>" (cis-1.8:5.1.1): kube-bench numbers checks per
// benchmark, so Enrich builds the key from the finding's benchmark tag and a bare number never maps.
func (c *Catalog) Lookup(source, checkID string) (*Entry, bool) {
	src := strings.ToLower(source)
	key := strings.ToLower(strings.TrimSpace(checkID))
	if e, ok := c.lookupIn(src, key); ok {
		return e, true
	}
	if m := c.index[src]; m != nil {
		for alias, e := range m {
			if strings.HasSuffix(alias, "*") && strings.HasPrefix(key, strings.TrimSuffix(alias, "*")) {
				return e, true
			}
		}
	}
	// Native collectors, Python checks, the change monitor and plugins reuse Prowler / Steampipe check names.
	if src != "prowler" && src != "steampipe" && src != "checkov" && src != "trivy" && src != "scoutsuite" && src != "kube-bench" && src != "kubescape" {
		for _, alt := range []string{"prowler", "steampipe", "checkov", "trivy"} {
			if e, ok := c.lookupIn(alt, key); ok {
				return e, true
			}
		}
	}
	if strings.HasPrefix(key, "cve-") || strings.HasPrefix(key, "ghsa-") {
		if e, ok := c.Entries["CVE_VULNERABILITY"]; ok {
			return e, true
		}
	}
	return nil, false
}

// lookupIn is an exact alias match in one source's index (Trivy ids also in canonical spelling).
func (c *Catalog) lookupIn(src, key string) (*Entry, bool) {
	m := c.index[src]
	if m == nil {
		return nil, false
	}
	if e, ok := m[key]; ok {
		return e, true
	}
	if trivySpelled(src) {
		if e, ok := m[strings.ToLower(NormalizeTrivyID(key))]; ok {
			return e, true
		}
	}
	return nil, false
}

// trivySpelled: sources whose check ids are Trivy policy ids.
func trivySpelled(src string) bool { return src == "trivy" || src == "trivy-operator" }

// trivyIDRe matches a Trivy misconfiguration policy id in any spelling Trivy has emitted:
// AVDID "AVD-AWS-0028" / ID "KSV017" (Trivy up to ~0.5x), ID "AWS-0028" / "KSV-0111" (0.6x+),
// and the "KSV0111" / "KSV111" forms seen in trivy-operator CRDs and rego package names.
var trivyIDRe = regexp.MustCompile(`(?i)^(?:avd-)?(aws|azu|gcp|oci|dig|nif|cldstk|opnstk|git|ksv|kcv|ds)-?([0-9]+)$`)

// NormalizeTrivyID returns the canonical alias spelling "AVD-<PREFIX>-<4 digits>" of a Trivy
// policy id ("KSV111" → "AVD-KSV-0111", "AWS-0028" → "AVD-AWS-0028"); any other id (CVE-*,
// secret rule ids such as "aws-access-key-id") is returned unchanged.
func NormalizeTrivyID(id string) string {
	m := trivyIDRe.FindStringSubmatch(strings.TrimSpace(id))
	if m == nil {
		return id
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return id
	}
	return fmt.Sprintf("AVD-%s-%04d", strings.ToUpper(m[1]), n)
}

func (c *Catalog) Get(id string) (*Entry, bool) {
	e, ok := c.Entries[strings.ToUpper(id)]
	return e, ok
}

func (c *Catalog) IDs() []string {
	ids := make([]string, 0, len(c.Entries))
	for id := range c.Entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Enrich applies canonical ID, weaknesses, compliance mappings, default severity and title.
func (c *Catalog) Enrich(f *model.Finding) {
	checkID := f.CheckID
	kubeBench := strings.EqualFold(f.Source, "kube-bench")
	if kubeBench {
		checkID = f.Tags["benchmark"] + ":" + f.CheckID
	}
	e, ok := c.Lookup(f.Source, checkID)
	if !ok {
		return
	}
	f.CanonicalID = e.ID
	if f.Title == "" {
		f.Title = e.Title
	}
	if f.Severity == "" || f.Severity == model.Info {
		f.Severity = e.Severity
	}
	if f.Resource.Type == "" {
		f.Resource.Type = e.ResourceType
	}
	if f.Provider == model.ProviderUnknown || f.Provider == "" {
		f.Provider = e.Provider
	}
	for _, w := range e.Weaknesses {
		if !f.HasWeakness(w) {
			f.Weaknesses = append(f.Weaknesses, w)
		}
	}
	for fw, controls := range e.Compliance {
		if kubeBench && fw == "cis_k8s" {
			continue // kube-bench names the exact control of its own benchmark revision
		}
		f.AddCompliance(fw, controls...)
	}
}

// Remapped returns copies of fs with canonical ids re-resolved against this catalog (the input
// is not modified): stored findings keep the mapping of the catalog they were ingested with, so
// coverage of a stored DB (`catalog unmapped` without --from) must re-resolve them for aliases
// added since. A finding no alias maps keeps its stored canonical id ("<TOOL>:<check>").
// Callers: adapters.CoverageOf(tool, catalog.Default().Remapped(storedFindingsOfTool)).
func (c *Catalog) Remapped(fs []model.Finding) []model.Finding {
	out := make([]model.Finding, len(fs))
	for i, f := range fs {
		f.Weaknesses = append([]string(nil), f.Weaknesses...)
		if f.Compliance != nil {
			cp := make(map[string][]string, len(f.Compliance))
			for k, v := range f.Compliance {
				cp[k] = append([]string(nil), v...)
			}
			f.Compliance = cp
		}
		c.Enrich(&f)
		out[i] = f
	}
	return out
}
