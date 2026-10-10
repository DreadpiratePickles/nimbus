package iam

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// corpusFile is one testdata/corpus/*.yaml file. Every case declares the AWS
// documentation section (or lab fixture) it derives from in `source`.
type corpusFile struct {
	Category string       `yaml:"category"`
	Cases    []corpusCase `yaml:"cases"`
}

type corpusPolicy struct {
	ID       string `yaml:"id"`
	Document any    `yaml:"document"`
}

type corpusRequest struct {
	Principal       string         `yaml:"principal"`
	Action          string         `yaml:"action"`
	Resource        string         `yaml:"resource"`
	ResourceAccount string         `yaml:"resource_account"`
	Context         map[string]any `yaml:"context"`
	ContextComplete bool           `yaml:"context_complete"`
}

type corpusExpect struct {
	Decision    string    `yaml:"decision"`
	Matched     *[]string `yaml:"matched"`
	UnknownKeys []string  `yaml:"unknown_keys"`
}

type corpusCase struct {
	Name     string           `yaml:"name"`
	Source   string           `yaml:"source"`
	Request  corpusRequest    `yaml:"request"`
	Identity []corpusPolicy   `yaml:"identity"`
	Resource *corpusPolicy    `yaml:"resource_policy"`
	Boundary *corpusPolicy    `yaml:"boundary"`
	Session  *corpusPolicy    `yaml:"session"`
	SCPs     [][]corpusPolicy `yaml:"scps"`
	RCPs     [][]corpusPolicy `yaml:"rcps"`
	Expect   corpusExpect     `yaml:"expect"`
}

func toPolicy(t *testing.T, cp corpusPolicy) Policy {
	t.Helper()
	b, err := json.Marshal(cp.Document)
	if err != nil {
		t.Fatalf("policy %s: marshal: %v", cp.ID, err)
	}
	p, err := ParsePolicy(b)
	if err != nil {
		t.Fatalf("policy %s: parse: %v", cp.ID, err)
	}
	p.ID = cp.ID
	return p
}

func toPtr(t *testing.T, cp *corpusPolicy) *Policy {
	if cp == nil {
		return nil
	}
	p := toPolicy(t, *cp)
	return &p
}

func toLevels(t *testing.T, in [][]corpusPolicy) [][]Policy {
	var out [][]Policy
	for _, lvl := range in {
		var ps []Policy
		for _, cp := range lvl {
			ps = append(ps, toPolicy(t, cp))
		}
		out = append(out, ps)
	}
	return out
}

func toContext(in map[string]any) map[string]ConditionValue {
	if in == nil {
		return nil
	}
	out := map[string]ConditionValue{}
	for k, v := range in {
		switch x := v.(type) {
		case []any:
			var vals []string
			for _, e := range x {
				vals = append(vals, fmt.Sprint(e))
			}
			out[k] = vals
		default:
			out[k] = ConditionValue{fmt.Sprint(x)}
		}
	}
	return out
}

func loadCorpus(t *testing.T) map[string]corpusFile {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "corpus", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]corpusFile{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var cf corpusFile
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&cf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[filepath.Base(f)] = cf
	}
	return out
}

func TestCorpus(t *testing.T) {
	corpus := loadCorpus(t)
	total := 0
	byCategory := map[string]int{}
	names := map[string]bool{}
	var fileNames []string
	for f := range corpus {
		fileNames = append(fileNames, f)
	}
	sort.Strings(fileNames)
	for _, f := range fileNames {
		cf := corpus[f]
		if cf.Category == "" {
			t.Errorf("%s: missing category", f)
		}
		for _, c := range cf.Cases {
			total++
			byCategory[cf.Category]++
			id := f + "/" + c.Name
			if names[id] {
				t.Errorf("duplicate case %s", id)
			}
			names[id] = true
			t.Run(strings.TrimSuffix(f, ".yaml")+"/"+c.Name, func(t *testing.T) {
				if !strings.HasPrefix(c.Source, "https://docs.aws.amazon.com/") && !strings.HasPrefix(c.Source, "lab/") {
					t.Fatalf("source must be an AWS docs URL or a lab fixture path, got %q", c.Source)
				}
				if c.Expect.Matched == nil {
					t.Fatalf("expect.matched must be declared (use [] for none)")
				}
				var ids []Policy
				for _, cp := range c.Identity {
					ids = append(ids, toPolicy(t, cp))
				}
				req := Request{
					Principal: c.Request.Principal, Action: c.Request.Action, Resource: c.Request.Resource,
					ResourceAccount: c.Request.ResourceAccount, Context: toContext(c.Request.Context),
					ContextComplete: c.Request.ContextComplete,
				}
				d := EvaluateSet(req, PolicySet{
					Identity: ids, Resource: toPtr(t, c.Resource), Boundary: toPtr(t, c.Boundary),
					Session: toPtr(t, c.Session), SCPs: toLevels(t, c.SCPs), RCPs: toLevels(t, c.RCPs),
				})
				if string(d.Effect) != c.Expect.Decision {
					t.Errorf("decision = %s, want %s\nreasons: %v\nmatched: %v\nunknown: %v", d.Effect, c.Expect.Decision, d.Reasons, d.MatchedStatements, d.UnknownConditionKeys)
				}
				got := []string{}
				for _, r := range d.MatchedStatements {
					got = append(got, r.String())
				}
				want := append([]string{}, (*c.Expect.Matched)...)
				sort.Strings(got)
				sort.Strings(want)
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Errorf("matched = %v, want %v", got, want)
				}
				if c.Expect.UnknownKeys != nil {
					uk := append([]string{}, c.Expect.UnknownKeys...)
					sort.Strings(uk)
					if strings.Join(d.UnknownConditionKeys, ",") != strings.Join(uk, ",") {
						t.Errorf("unknown keys = %v, want %v", d.UnknownConditionKeys, uk)
					}
				}
				if d.Effect == Unknown && len(d.UnknownConditionKeys) == 0 && len(d.Reasons) == 0 {
					t.Errorf("Unknown decision carries no reason")
				}
			})
		}
	}
	if total < 60 {
		t.Errorf("corpus has %d cases, want >= 60", total)
	}
	t.Logf("corpus: %d cases %v", total, byCategory)
}
