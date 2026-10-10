package remediation

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// Metadata is the structured remediation plan content carried by every template (gap O26,
// modelled on CrowdStrike's remediation plans: permissions, validation, compensating control,
// effort, confidence). It lives in a sidecar next to the template: <template>.meta.yaml.
type Metadata struct {
	// ActionsRequired are the cloud API permissions (IAM actions, Azure operations, GCP
	// permissions, Kubernetes verbs) needed to apply the fix.
	ActionsRequired []string   `yaml:"actions_required" json:"actions_required"`
	Validation      Validation `yaml:"validation" json:"validation"`
	// Mitigation is a temporary workaround for when the real fix needs downtime or approval.
	Mitigation string `yaml:"mitigation" json:"mitigation"`
	Effort     string `yaml:"effort" json:"effort"`         // S | M | L
	Confidence string `yaml:"confidence" json:"confidence"` // high | medium | low
	Rollback   string `yaml:"rollback" json:"rollback"`
	// BreaksFunction says whether applying the fix can break a working workload.
	BreaksFunction BreaksFunction `yaml:"breaks_function" json:"breaks_function"`
}

// Validation proves the fix worked. SQL runs over the nimbus store (read-only path) after a
// re-scan; Expect says what a passing result looks like.
type Validation struct {
	SQL    string `yaml:"sql" json:"sql"`                       // rendered with the finding's IDs
	Expect string `yaml:"expect" json:"expect"`                 // "no_rows"
	Note   string `yaml:"note,omitempty" json:"note,omitempty"` // caveats (e.g. needs a re-scan)
}

type BreaksFunction struct {
	Value *bool  `yaml:"value" json:"value"`
	Note  string `yaml:"note" json:"note"`
}

const metaSuffix = ".meta.yaml"

var (
	efforts     = map[string]bool{"S": true, "M": true, "L": true}
	confidences = map[string]bool{"high": true, "medium": true, "low": true}
	expects     = map[string]bool{"no_rows": true}
)

// Validate reports every missing or malformed field.
func (m *Metadata) Validate() error {
	var errs []string
	if len(m.ActionsRequired) == 0 {
		errs = append(errs, "actions_required is empty")
	}
	for _, a := range m.ActionsRequired {
		if strings.TrimSpace(a) == "" || a == "*" || a == "*:*" {
			errs = append(errs, fmt.Sprintf("actions_required entry %q is not a specific action", a))
		}
	}
	if strings.TrimSpace(m.Validation.SQL) == "" {
		errs = append(errs, "validation.sql is empty")
	}
	if !expects[m.Validation.Expect] {
		errs = append(errs, fmt.Sprintf("validation.expect %q not in [no_rows]", m.Validation.Expect))
	}
	if strings.TrimSpace(m.Mitigation) == "" {
		errs = append(errs, "mitigation is empty")
	}
	if !efforts[m.Effort] {
		errs = append(errs, fmt.Sprintf("effort %q not in [S M L]", m.Effort))
	}
	if !confidences[m.Confidence] {
		errs = append(errs, fmt.Sprintf("confidence %q not in [high medium low]", m.Confidence))
	}
	if strings.TrimSpace(m.Rollback) == "" {
		errs = append(errs, "rollback is empty")
	}
	if m.BreaksFunction.Value == nil {
		errs = append(errs, "breaks_function.value is missing")
	}
	if strings.TrimSpace(m.BreaksFunction.Note) == "" {
		errs = append(errs, "breaks_function.note is empty")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// TemplateMetadata loads and validates the raw (unrendered) sidecar for a template file name.
func TemplateMetadata(tplName string) (*Metadata, error) {
	raw, err := fs.ReadFile(templateFS, path.Join("templates", tplName+metaSuffix))
	if err != nil {
		return nil, fmt.Errorf("metadata for %s: %w", tplName, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var m Metadata
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("metadata for %s: %w", tplName, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("metadata for %s: %w", tplName, err)
	}
	return &m, nil
}

// renderMetadata loads the sidecar and renders its validation SQL for this finding. Values reach
// the SQL only through the sqlstr func (single-quoted, quotes doubled).
func renderMetadata(tplName string, c ctx) (*Metadata, error) {
	m, err := TemplateMetadata(tplName)
	if err != nil {
		return nil, err
	}
	t, err := template.New(tplName + metaSuffix).Funcs(funcs).Option("missingkey=error").Parse(m.Validation.SQL)
	if err != nil {
		return nil, fmt.Errorf("metadata for %s: validation.sql: %w", tplName, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, c); err != nil {
		return nil, fmt.Errorf("metadata for %s: validation.sql: %w", tplName, err)
	}
	m.Validation.SQL = strings.TrimSpace(buf.String())
	// The rollback may name the object it restores (W7: the Service a K8s fix patches).
	if strings.Contains(m.Rollback, "{{") {
		rt, err := template.New(tplName + metaSuffix + ".rollback").Funcs(funcs).Option("missingkey=error").Parse(m.Rollback)
		if err != nil {
			return nil, fmt.Errorf("metadata for %s: rollback: %w", tplName, err)
		}
		var rb bytes.Buffer
		if err := rt.Execute(&rb, c); err != nil {
			return nil, fmt.Errorf("metadata for %s: rollback: %w", tplName, err)
		}
		m.Rollback = strings.TrimSpace(rb.String())
	}
	return m, nil
}

// Templates lists every template file (sidecars excluded).
func Templates() []string {
	ents, _ := fs.ReadDir(templateFS, "templates")
	var out []string
	for _, e := range ents {
		if !e.IsDir() && !strings.HasSuffix(e.Name(), metaSuffix) {
			out = append(out, e.Name())
		}
	}
	return out
}
