// Package catalog maps tool-native check IDs onto canonical finding IDs and
// enriches findings with weaknesses, compliance controls and remediation templates.
package catalog

import (
	_ "embed"
	"fmt"
	"sort"
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
	once    sync.Once
	defaultCatalog *Catalog
	loadErr error
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
				c.index[src][strings.ToLower(strings.TrimSpace(a))] = e
			}
		}
	}
	return c, nil
}

// Lookup resolves a native check ID for a tool. Prefix matches cover IDs such as "CVE-2024-1234".
func (c *Catalog) Lookup(source, checkID string) (*Entry, bool) {
	src := strings.ToLower(source)
	key := strings.ToLower(strings.TrimSpace(checkID))
	if m := c.index[src]; m != nil {
		if e, ok := m[key]; ok {
			return e, true
		}
		for alias, e := range m {
			if strings.HasSuffix(alias, "*") && strings.HasPrefix(key, strings.TrimSuffix(alias, "*")) {
				return e, true
			}
		}
	}
	// Native collectors, Python checks, the change monitor and plugins reuse Prowler / Steampipe check names.
	if src != "prowler" && src != "steampipe" && src != "checkov" && src != "trivy" && src != "scoutsuite" {
		for _, alt := range []string{"prowler", "steampipe", "checkov", "trivy"} {
			if e, ok := c.index[alt][key]; ok {
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
	e, ok := c.Lookup(f.Source, f.CheckID)
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
		f.AddCompliance(fw, controls...)
	}
}
