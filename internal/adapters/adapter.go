// Package adapters parses native scanner output into unified findings.
package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/compliance"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Adapter converts one tool's output bytes into findings.
type Adapter interface {
	Name() string
	// Detect reports whether the payload looks like this tool's output.
	Detect(filename string, data []byte) bool
	Parse(data []byte, opts Options) ([]model.Finding, error)
}

type Options struct {
	Account  string // override account label (e.g. "aws-prod")
	Provider string // override provider when the tool does not say
	Now      time.Time
}

var registry = []Adapter{
	&Prowler{}, &Checkov{}, &Trivy{}, &Steampipe{}, &ScoutSuite{}, &Native{},
}

func All() []Adapter { return registry }

func ByName(name string) (Adapter, bool) {
	for _, a := range registry {
		if strings.EqualFold(a.Name(), name) {
			return a, true
		}
	}
	return nil, false
}

// Detect picks the adapter for a file, by content sniffing then by filename hints.
func Detect(filename string, data []byte) (Adapter, bool) {
	for _, a := range registry {
		if a.Detect(filename, data) {
			return a, true
		}
	}
	return nil, false
}

// ParseFile reads, detects (unless source is given), parses and enriches.
func ParseFile(path, source string, opts Options) ([]model.Finding, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var a Adapter
	if source != "" {
		var ok bool
		if a, ok = ByName(source); !ok {
			return nil, "", fmt.Errorf("unknown source %q", source)
		}
	} else {
		var ok bool
		if a, ok = Detect(filepath.Base(path), data); !ok {
			return nil, "", fmt.Errorf("could not detect scanner format for %s", path)
		}
	}
	findings, err := a.Parse(data, opts)
	if err != nil {
		return nil, a.Name(), fmt.Errorf("%s: %w", a.Name(), err)
	}
	Finalize(findings, opts)
	return findings, a.Name(), nil
}

// Finalize enriches from the catalog and fills defaults; call after any Parse.
func Finalize(findings []model.Finding, opts Options) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cat := catalog.Default()
	for i := range findings {
		f := &findings[i]
		if opts.Account != "" {
			if f.Tags == nil {
				f.Tags = map[string]string{}
			}
			f.Tags["account_label"] = opts.Account
			if f.Account == "" {
				f.Account = opts.Account
			}
		}
		if opts.Provider != "" && (f.Provider == "" || f.Provider == model.ProviderUnknown) {
			f.Provider = model.NormalizeProvider(opts.Provider)
		}
		cat.Enrich(f)
		compliance.DeriveCompliance(f)
		f.Finalize(now)
	}
}

// Native parses the unified JSON contract itself (array of findings or JSON lines).
// Plugins written with the Python SDK emit this format.
type Native struct{}

func (Native) Name() string { return "native" }
func (Native) Detect(filename string, data []byte) bool {
	trim := bytes.TrimSpace(data)
	if strings.HasSuffix(filename, ".findings.json") || strings.HasSuffix(filename, ".jsonl") {
		return true
	}
	if len(trim) == 0 || trim[0] != '[' {
		return false
	}
	var probe []map[string]json.RawMessage
	if err := json.Unmarshal(trim, &probe); err != nil || len(probe) == 0 {
		return false
	}
	_, a := probe[0]["canonical_id"]
	_, b := probe[0]["check_id"]
	_, c := probe[0]["source"]
	return a || (b && c)
}

func (Native) Parse(data []byte, opts Options) ([]model.Finding, error) {
	trim := bytes.TrimSpace(data)
	var out []model.Finding
	if len(trim) > 0 && trim[0] == '[' {
		if err := json.Unmarshal(trim, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	for _, line := range bytes.Split(trim, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var f model.Finding
		if err := json.Unmarshal(line, &f); err != nil {
			return nil, fmt.Errorf("bad finding line: %w", err)
		}
		out = append(out, f)
	}
	return out, nil
}

// helpers shared by adapters

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			switch t := v.(type) {
			case string:
				return t
			case float64:
				return fmt.Sprintf("%v", t)
			case bool:
				return fmt.Sprintf("%v", t)
			}
		}
	}
	return ""
}

func sub(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func list(m map[string]any, key string) []any {
	if v, ok := m[key].([]any); ok {
		return v
	}
	return nil
}

func rawOf(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
