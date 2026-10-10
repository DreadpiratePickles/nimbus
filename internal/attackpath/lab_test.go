package attackpath

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"gopkg.in/yaml.v3"
)

// Lab-derived fixtures for Track B2. testdata/lab_typed.findings.json is the lab estate
// (lab/local/out/estate.findings.json) with every relationship in the typed native form
// {id, kind, attr} the generator is asked to emit; the plain lab file has strings only.

const labTrustedCIDR = "203.0.113.0/24" // lab/local/cloud-posture.lab.yaml trusted_cidrs

type gtLabel struct {
	ID           string   `yaml:"id"`
	Status       string   `yaml:"status"`
	Entry        string   `yaml:"entry"`
	Target       string   `yaml:"target"`
	Hops         []string `yaml:"hops"`
	OptionalHops []string `yaml:"optional_hops"`
	MinScore     float64  `yaml:"min_score"`
}

func groundTruth(t *testing.T) map[string]gtLabel {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "lab", "ground_truth.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var gt struct {
		Paths []gtLabel `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &gt); err != nil {
		t.Fatal(err)
	}
	out := map[string]gtLabel{}
	for _, p := range gt.Paths {
		out[p.ID] = p
	}
	return out
}

func labFindings(t *testing.T, typed bool) []model.Finding {
	t.Helper()
	p := filepath.Join("..", "..", "lab", "local", "out", "estate.findings.json")
	if typed {
		p = filepath.Join("testdata", "lab_typed.findings.json")
	}
	fs, _, err := adapters.ParseFile(p, "native", adapters.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func labGraph(t *testing.T, typed bool) (*graph.Graph, []model.Finding) {
	fs := labFindings(t, typed)
	g := graph.New()
	g.AttachFindings(fs)
	return g, fs
}

func labOptions() TraversalOptions {
	o := DefaultTraversalOptions()
	o.TrustedCIDRs = []string{labTrustedCIDR}
	return o
}

// gtEntry mirrors tests/groundtruth: no entry step → internet; an entry step whose weakness is
// public exposure → internet; otherwise the first resource is the foothold.
func gtEntry(p model.AttackPath) string {
	if len(p.Steps) == 0 {
		return ""
	}
	f := p.Steps[0]
	if f.Relation != "entry" || f.Weakness == "PUBLIC_NETWORK_EXPOSURE" || f.Weakness == "PUBLIC_DATA_STORE" {
		return "internet"
	}
	return f.Resource
}

// gtMatch is the ground-truth matcher: same entry, every hop present, nothing outside
// hops ∪ optional_hops, and the path ends on the target or on optional hops after it.
func gtMatch(l gtLabel, p model.AttackPath) bool {
	if len(p.Steps) == 0 || gtEntry(p) != l.Entry {
		return false
	}
	allowed, opt, hops := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range p.Steps {
		if s.Resource != graph.InternetNodeID {
			hops[s.Resource] = true
		}
	}
	for _, h := range l.Hops {
		if !hops[h] {
			return false
		}
		allowed[h] = true
	}
	for _, h := range l.OptionalHops {
		allowed[h], opt[h] = true, true
	}
	for h := range hops {
		if !allowed[h] {
			return false
		}
	}
	for i := len(p.Steps) - 1; i >= 0; i-- {
		r := p.Steps[i].Resource
		if r == l.Target {
			return true
		}
		if !opt[r] {
			return false
		}
	}
	return false
}

func bestMatch(l gtLabel, paths []model.AttackPath) (found bool, best float64) {
	for _, p := range paths {
		if gtMatch(l, p) {
			found = true
			if p.Score > best {
				best = p.Score
			}
		}
	}
	return
}

// Item 1: with typed relations the lab's role→bucket (grants_access_to), NSG→VM
// (allows_traffic_to), OIDC trust (can_assume) and external-account trust (trusts) produce P06,
// P11, P12 and P04.
func TestTypedLabRelationsProducePaths(t *testing.T) {
	g, _ := labGraph(t, true)
	an := Traverse(g, labOptions())
	gt := groundTruth(t)
	for _, id := range []string{"P04", "P06", "P11", "P12"} {
		if ok, _ := bestMatch(gt[id], an.Paths); !ok {
			t.Errorf("%s not produced from typed relations", id)
		}
	}
	if t.Failed() {
		for _, p := range an.Paths {
			t.Logf("%.2f %s", p.Score, stepKey(pathEntry(p), p.Steps))
		}
	}
}

// Item 4: an identity that is both the entry (phishable: NO_MFA; leaked: 400-day key) and the
// crown jewel (AdministratorAccess) is itself a path; independent credential weaknesses combine
// as a noisy-OR. The externally trusted admin role (P04) is the same shape.
func TestIdentityIsEntryAndCrownJewel(t *testing.T) {
	gt := groundTruth(t)
	for _, typed := range []bool{false, true} {
		g, _ := labGraph(t, typed)
		an := Traverse(g, labOptions())
		for _, id := range []string{"P05", "P04"} {
			ok, best := bestMatch(gt[id], an.Paths)
			if !ok || best < 7 {
				t.Errorf("typed=%v %s: found=%v best=%.2f, want >= 7", typed, id, ok, best)
			}
		}
		for _, p := range an.Paths {
			if gtMatch(gt["P05"], p) {
				s := p.Steps[0]
				if s.Relation != "entry" || s.Because == "" || len(p.Steps) != 1 {
					t.Errorf("P05 step: %+v", s)
				}
				ws, _ := s.Evidence["entry_weaknesses"].([]string)
				if len(ws) != 2 {
					t.Errorf("P05 evidence should list both credential weaknesses: %v", s.Evidence)
				}
			}
		}
	}
}
