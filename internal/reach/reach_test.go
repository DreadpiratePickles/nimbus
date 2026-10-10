package reach

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// corpusFile is one testdata/*.yaml file: a list of topologies with the expected verdict.
type corpusFile struct {
	Cases []corpusCase `yaml:"cases"`
}

type corpusCase struct {
	Name    string   `yaml:"name"`
	Source  string   `yaml:"source"` // the AWS (or provider) documentation the expectation follows
	Port    Port     `yaml:"port"`
	Trusted []string `yaml:"trusted"`
	Target  Target   `yaml:"target"`
	Expect  struct {
		Status     Status   `yaml:"status"`
		Width      string   `yaml:"width"`
		Port       *Port    `yaml:"port"`
		Blocker    string   `yaml:"blocker"`    // substring of some Blockers[].Because
		Unknown    string   `yaml:"unknown"`    // substring of some Unknown[].Because
		PathKinds  []string `yaml:"path_kinds"` // Path[].Kind, in order, when given
		PathHas    string   `yaml:"path_has"`   // substring of some Path[].Because
		Sources    []string `yaml:"sources"`    // exact Result.Sources when given
		Confidence string   `yaml:"confidence"` // verified | inferred | hint
		NoBlocker  string   `yaml:"no_blocker"` // substring that must NOT appear in Blockers
	} `yaml:"expect"`
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files in testdata: %v", err)
	}
	sort.Strings(files)
	var all []corpusCase
	seen := map[string]bool{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var cf corpusFile
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&cf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, c := range cf.Cases {
			if c.Name == "" || c.Source == "" {
				t.Fatalf("%s: every case needs a name and a documentation source (case %q)", f, c.Name)
			}
			if seen[c.Name] {
				t.Fatalf("%s: duplicate case name %q", f, c.Name)
			}
			seen[c.Name] = true
			all = append(all, c)
		}
	}
	return all
}

// TestCorpus runs every topology in testdata through Reachable (plan v3 §3.2.2 corpus).
func TestCorpus(t *testing.T) {
	cases := loadCorpus(t)
	if len(cases) < 40 {
		t.Fatalf("corpus has %d cases, want >= 40", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			r := Reachable(c.Target, Internet(c.Trusted...), c.Port)
			dump := func() string { return r.String() }
			if r.Status != c.Expect.Status {
				t.Fatalf("status = %s, want %s\n%s", r.Status, c.Expect.Status, dump())
			}
			if r.Reachable != (c.Expect.Status == StatusReachable) {
				t.Fatalf("Reachable=%v disagrees with status %s", r.Reachable, r.Status)
			}
			if c.Expect.Width != "" && r.Width != c.Expect.Width {
				t.Errorf("width = %q, want %q\n%s", r.Width, c.Expect.Width, dump())
			}
			if c.Expect.Port != nil && r.Port != *c.Expect.Port {
				t.Errorf("port = %v, want %v\n%s", r.Port, *c.Expect.Port, dump())
			}
			if c.Expect.Blocker != "" && !hopsContain(r.Blockers, c.Expect.Blocker) {
				t.Errorf("no blocker contains %q\n%s", c.Expect.Blocker, dump())
			}
			if c.Expect.NoBlocker != "" && hopsContain(r.Blockers, c.Expect.NoBlocker) {
				t.Errorf("a blocker contains %q, want none\n%s", c.Expect.NoBlocker, dump())
			}
			if c.Expect.Unknown != "" && !hopsContain(r.Unknown, c.Expect.Unknown) {
				t.Errorf("no unknown hop contains %q\n%s", c.Expect.Unknown, dump())
			}
			if c.Expect.PathHas != "" && !hopsContain(r.Path, c.Expect.PathHas) {
				t.Errorf("no path hop contains %q\n%s", c.Expect.PathHas, dump())
			}
			if len(c.Expect.PathKinds) > 0 {
				var kinds []string
				for _, h := range r.Path {
					kinds = append(kinds, h.Kind)
				}
				if strings.Join(kinds, ",") != strings.Join(c.Expect.PathKinds, ",") {
					t.Errorf("path kinds = %v, want %v\n%s", kinds, c.Expect.PathKinds, dump())
				}
			}
			if c.Expect.Sources != nil && strings.Join(r.Sources, ",") != strings.Join(c.Expect.Sources, ",") {
				t.Errorf("sources = %v, want %v", r.Sources, c.Expect.Sources)
			}
			if c.Expect.Confidence != "" && r.Confidence != c.Expect.Confidence {
				t.Errorf("confidence = %q, want %q\n%s", r.Confidence, c.Expect.Confidence, dump())
			}
			// Evidence contract: a reachable verdict has a path, a blocked one a blocker, an
			// unknown one a reason. Every hop says why.
			switch r.Status {
			case StatusReachable:
				if len(r.Path) == 0 {
					t.Errorf("reachable without path hops")
				}
			case StatusBlocked:
				if len(r.Blockers) == 0 {
					t.Errorf("blocked without a blocker")
				}
			case StatusUnknown:
				if len(r.Unknown) == 0 {
					t.Errorf("unknown without a reason")
				}
			}
			for _, h := range append(append(append([]Hop{}, r.Path...), r.Blockers...), r.Unknown...) {
				if h.Kind == "" || h.Because == "" {
					t.Errorf("hop without kind/because: %+v", h)
				}
			}
		})
	}
}

func hopsContain(hs []Hop, sub string) bool {
	for _, h := range hs {
		if strings.Contains(h.Because, sub) {
			return true
		}
	}
	return false
}

// TestDeterministic: the same input gives byte-identical evidence (published, deterministic model).
func TestDeterministic(t *testing.T) {
	for _, c := range loadCorpus(t) {
		a := Reachable(c.Target, Internet(c.Trusted...), c.Port).String()
		for i := 0; i < 3; i++ {
			if b := Reachable(c.Target, Internet(c.Trusted...), c.Port).String(); a != b {
				t.Fatalf("%s: non-deterministic result:\n%s\n---\n%s", c.Name, a, b)
			}
		}
	}
}

func TestIPSet(t *testing.T) {
	all := setOf("0.0.0.0/0")
	minus := all.subtract(setOf("10.0.0.0/8"))
	if got := strings.Join(minus.cidrs(), ","); !strings.Contains(got, "0.0.0.0/5") || strings.Contains(got, "10.0.0.0/8") {
		t.Fatalf("subtract: %s", got)
	}
	if !setOf("203.0.113.0/24").intersect(setOf("203.0.113.128/25")).equal(setOf("203.0.113.128/25")) {
		t.Fatal("intersect")
	}
	if u := setOf("10.0.0.0/9").union(setOf("10.128.0.0/9")); strings.Join(u.cidrs(), ",") != "10.0.0.0/8" {
		t.Fatalf("union merge: %v", u.cidrs())
	}
	if got := publicSpace().intersect(setOf("192.168.0.0/16")); !got.empty() {
		t.Fatalf("private range is public: %v", got.cidrs())
	}
	if v6 := setOf("::/0").intersect(setOf("2001:db8::/32")); strings.Join(v6.cidrs(), ",") != "2001:db8::/32" {
		t.Fatalf("v6: %v", v6.cidrs())
	}
}
