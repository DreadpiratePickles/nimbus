// Package estate turns lab/local/estate.yaml (the seeded, deliberately vulnerable
// multi-cloud estate) into the native findings JSON that `cloud-posture ingest
// --source native` accepts. It writes the JSON contract directly instead of importing
// internal/model so the ground-truth harness stays black-box.
package estate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Account struct {
	Provider string `yaml:"provider"`
	ID       string `yaml:"id"`
	Label    string `yaml:"label"`
	Note     string `yaml:"note"`
}

type Relationship struct {
	Kind string `yaml:"kind" json:"kind"`
	To   string `yaml:"to" json:"to"`
	Via  string `yaml:"via,omitempty" json:"via,omitempty"`
}

type Resource struct {
	ID            string         `yaml:"id"`
	Scenario      string         `yaml:"scenario"`
	Provider      string         `yaml:"provider"`
	Account       string         `yaml:"account"`
	Region        string         `yaml:"region"`
	Type          string         `yaml:"type"`
	Name          string         `yaml:"name"`
	Attributes    map[string]any `yaml:"attributes"`
	Relationships []Relationship `yaml:"relationships"`
	// PassCheck / PassTitle: on a weakness-free resource, the check its inventory PASS record
	// evidences (a control the resource passes, e.g. s3_bucket_default_encryption), so compliance
	// reports have PASS rows. The record keeps its id (lab-inv-NN) and lab_inventory tag.
	PassCheck string `yaml:"pass_check"`
	PassTitle string `yaml:"pass_title"`
}

type Weakness struct {
	ID         string         `yaml:"id"`
	Resource   string         `yaml:"resource"`
	CheckID    string         `yaml:"check_id"`
	Severity   string         `yaml:"severity"`
	Weaknesses []string       `yaml:"weaknesses"`
	Title      string         `yaml:"title"`
	Attributes map[string]any `yaml:"attributes"`
}

type Estate struct {
	Version    int        `yaml:"version"`
	Name       string     `yaml:"name"`
	Source     string     `yaml:"source"`
	Accounts   []Account  `yaml:"accounts"`
	Resources  []Resource `yaml:"resources"`
	Weaknesses []Weakness `yaml:"weaknesses"`
}

// FindingResource and Finding mirror the native finding JSON contract
// (internal/model.Finding); only the fields the lab needs are emitted.
type FindingResource struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Attributes map[string]any `json:"attributes,omitempty"`
	// Related holds one typed relationship object per estate relationship (see Relation).
	Related []any `json:"related,omitempty"`
}

// Relation is the typed native relationship (internal/model/relation.go, docs/benchmark.md
// "Native relationship contract"): {"id", "kind", "attr": {"via"}}; attr is left out when the
// estate gives no via.
type Relation struct {
	ID   string            `json:"id"`
	Kind string            `json:"kind"`
	Attr map[string]string `json:"attr,omitempty"`
}

type Finding struct {
	ID          string            `json:"id"`
	Source      string            `json:"source"`
	CheckID     string            `json:"check_id"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Severity    string            `json:"severity"`
	Status      string            `json:"status"`
	Provider    string            `json:"provider"`
	Account     string            `json:"account"`
	Region      string            `json:"region,omitempty"`
	Resource    FindingResource   `json:"resource"`
	Weaknesses  []string          `json:"weaknesses,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// InventoryCheckID marks PASS records that only carry a resource and its relationships.
const InventoryCheckID = "lab_inventory"

// FindingID is the stable finding id of a seeded weakness.
func FindingID(weaknessID string) string { return "lab-" + weaknessID }

func Load(path string) (*Estate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(data []byte) (*Estate, error) {
	var e Estate
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("estate: %w", err)
	}
	return &e, e.Validate()
}

// Validate checks referential integrity: unique ids, weaknesses on known resources,
// relationships that point somewhere the estate (or an external principal) defines.
func (e *Estate) Validate() error {
	var errs []string
	res := map[string]bool{}
	for _, r := range e.Resources {
		if r.ID == "" || r.Type == "" || r.Provider == "" || r.Account == "" || r.Scenario == "" {
			errs = append(errs, fmt.Sprintf("resource %q: id, type, provider, account and scenario are required", r.ID))
		}
		if res[r.ID] {
			errs = append(errs, fmt.Sprintf("duplicate resource id %q", r.ID))
		}
		res[r.ID] = true
	}
	for _, r := range e.Resources {
		for _, rel := range r.Relationships {
			if rel.Kind == "" || rel.To == "" {
				errs = append(errs, fmt.Sprintf("resource %q: relationship needs kind and to", r.ID))
			}
			if !res[rel.To] && rel.Kind != "trusts" {
				errs = append(errs, fmt.Sprintf("resource %q: relationship %s -> %q targets no resource", r.ID, rel.Kind, rel.To))
			}
		}
	}
	wid := map[string]bool{}
	for _, w := range e.Weaknesses {
		if wid[w.ID] {
			errs = append(errs, fmt.Sprintf("duplicate weakness id %q", w.ID))
		}
		wid[w.ID] = true
		if !res[w.Resource] {
			errs = append(errs, fmt.Sprintf("weakness %s: unknown resource %q", w.ID, w.Resource))
		}
		if r := e.resource(w.Resource); r != nil && r.PassCheck != "" {
			errs = append(errs, fmt.Sprintf("resource %q: pass_check needs a weakness-free resource (it rides on the inventory record), but %s is seeded on it", r.ID, w.ID))
		}
		if len(w.Weaknesses) == 0 || w.CheckID == "" || w.Severity == "" {
			errs = append(errs, fmt.Sprintf("weakness %s: check_id, severity and weaknesses are required", w.ID))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("estate invalid:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

func (e *Estate) resource(id string) *Resource {
	for i := range e.Resources {
		if e.Resources[i].ID == id {
			return &e.Resources[i]
		}
	}
	return nil
}

func findingResource(r *Resource, extra map[string]any) FindingResource {
	attrs := map[string]any{}
	for k, v := range r.Attributes {
		attrs[k] = v
	}
	for k, v := range extra {
		attrs[k] = v
	}
	attrs["lab_scenario"] = r.Scenario
	var related []any
	for _, rel := range r.Relationships {
		tr := Relation{ID: rel.To, Kind: rel.Kind}
		if rel.Via != "" {
			tr.Attr = map[string]string{"via": rel.Via}
		}
		related = append(related, tr)
	}
	return FindingResource{ID: r.ID, Type: r.Type, Name: r.Name, Attributes: attrs, Related: related}
}

// Findings returns one FAIL finding per weakness (stable id lab-<Wxx>) followed by one PASS
// inventory record (stable id lab-inv-<resource index>) per resource without weaknesses.
func (e *Estate) Findings() []Finding {
	source := e.Source
	if source == "" {
		source = "nimbus-lab"
	}
	out := []Finding{}
	weak := map[string]bool{}
	for _, w := range e.Weaknesses {
		r := e.resource(w.Resource)
		weak[r.ID] = true
		out = append(out, Finding{
			ID: FindingID(w.ID), Source: source, CheckID: w.CheckID, Title: w.Title,
			Description: fmt.Sprintf("nimbus lab seeded weakness %s (scenario %s)", w.ID, r.Scenario),
			Severity:    strings.ToUpper(w.Severity), Status: "FAIL", Provider: r.Provider, Account: r.Account, Region: r.Region,
			Resource: findingResource(r, w.Attributes), Weaknesses: append([]string{}, w.Weaknesses...),
			Tags: map[string]string{"lab_weakness": w.ID, "lab_scenario": r.Scenario},
		})
	}
	for i := range e.Resources {
		r := &e.Resources[i]
		if weak[r.ID] {
			continue
		}
		check, title := InventoryCheckID, "Inventory record: "+r.Name
		if r.PassCheck != "" {
			check, title = r.PassCheck, r.PassTitle
			if title == "" {
				title = r.PassCheck + ": " + r.Name
			}
		}
		out = append(out, Finding{
			ID: fmt.Sprintf("lab-inv-%02d", i+1), Source: source, CheckID: check,
			Title: title, Severity: "INFO", Status: "PASS",
			Provider: r.Provider, Account: r.Account, Region: r.Region, Resource: findingResource(r, nil),
			Tags: map[string]string{"lab_scenario": r.Scenario, "lab_inventory": "true"},
		})
	}
	return out
}

// SeverityCounts counts FAIL findings per severity.
func (e *Estate) SeverityCounts() map[string]int {
	out := map[string]int{}
	for _, w := range e.Weaknesses {
		out[strings.ToUpper(w.Severity)]++
	}
	return out
}

// JSON renders the findings deterministically (stable order, sorted map keys, indented).
func (e *Estate) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(e.Findings(), "", "  ") // authoring order; map keys sorted by encoding/json
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Write generates the findings JSON at path.
func (e *Estate) Write(path string) error {
	b, err := e.JSON()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
