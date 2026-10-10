package iam

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Simulator parity hook (plan v3 P1-IAM I6, risk 1(d)): the evaluator is cross-checked against
// iam:SimulatePrincipalPolicy / SimulateCustomPolicy results replayed offline. No network: a
// FixtureSource only reads recorded results. The NIMBUS_E2E recorder that captures live results
// lands with O1; until then every fixture is authored from an AWS documentation example and
// carries Provenance "authored, not recorded live".

const (
	ProvenanceAuthored = "authored, not recorded live"
	ProvenanceRecorded = "recorded"
)

// SimulatorFixture is one simulation request and the decisions the simulator returned, in the
// API's own field names (PolicyInputList, CallerArn, ResourceOwner, ContextEntries, ...).
type SimulatorFixture struct {
	ID         string `json:"id"`
	Source     string `json:"source"`     // AWS documentation URL (authored) or recording run id
	Provenance string `json:"provenance"` // ProvenanceAuthored | ProvenanceRecorded
	CallerArn  string `json:"CallerArn"`
	// Policy documents as JSON text (fixture files may write them as JSON objects).
	PolicyInputList                    []string          `json:"PolicyInputList"`
	PermissionsBoundaryPolicyInputList []string          `json:"PermissionsBoundaryPolicyInputList,omitempty"`
	ResourcePolicy                     string            `json:"ResourcePolicy,omitempty"`
	ResourceOwner                      string            `json:"ResourceOwner,omitempty"` // account id or arn:aws:iam::<id>:root
	OrganizationsPolicies              [][]string        `json:"OrganizationsPolicies,omitempty"`
	ContextEntries                     []ContextEntry    `json:"ContextEntries,omitempty"`
	Results                            []SimulatorResult `json:"EvaluationResults"`
}

// ContextEntry is one SimulatePrincipalPolicy context entry.
type ContextEntry struct {
	ContextKeyName   string   `json:"ContextKeyName"`
	ContextKeyValues []string `json:"ContextKeyValues"`
	ContextKeyType   string   `json:"ContextKeyType,omitempty"`
}

// SimulatorResult is one EvaluationResult: EvalDecision is allowed | explicitDeny | implicitDeny.
type SimulatorResult struct {
	EvalActionName   string `json:"EvalActionName"`
	EvalResourceName string `json:"EvalResourceName"`
	EvalDecision     string `json:"EvalDecision"`
}

// FixtureSource yields recorded simulator fixtures (a directory today; the e2e recorder later).
type FixtureSource interface {
	Fixtures() ([]SimulatorFixture, error)
}

// DirFixtures reads every *.json file in a directory; each holds a list of fixtures.
type DirFixtures string

func (d DirFixtures) Fixtures() ([]SimulatorFixture, error) {
	files, err := filepath.Glob(filepath.Join(string(d), "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []SimulatorFixture
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var raw []map[string]json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, r := range raw {
			// Policy documents may be JSON objects in the file: turn them into JSON text.
			for _, k := range []string{"PolicyInputList", "PermissionsBoundaryPolicyInputList"} {
				if v, ok := r[k]; ok {
					r[k] = docsAsText(v)
				}
			}
			if v, ok := r["ResourcePolicy"]; ok && len(v) > 0 && v[0] == '{' {
				s, _ := json.Marshal(string(v))
				r["ResourcePolicy"] = s
			}
			if v, ok := r["OrganizationsPolicies"]; ok {
				var levels []json.RawMessage
				_ = json.Unmarshal(v, &levels)
				var conv []json.RawMessage
				for _, l := range levels {
					conv = append(conv, docsAsText(l))
				}
				r["OrganizationsPolicies"], _ = json.Marshal(conv)
			}
			nb, _ := json.Marshal(r)
			var fx SimulatorFixture
			if err := json.Unmarshal(nb, &fx); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			out = append(out, fx)
		}
	}
	return out, nil
}

func docsAsText(v json.RawMessage) json.RawMessage {
	var items []json.RawMessage
	if json.Unmarshal(v, &items) != nil {
		return v
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		var s string
		if json.Unmarshal(it, &s) == nil {
			out = append(out, s)
			continue
		}
		out = append(out, string(it))
	}
	b, _ := json.Marshal(out)
	return b
}

// Disagreement is one result where the evaluator and the simulator differ.
type Disagreement struct {
	Fixture, Action, Resource string
	Simulator                 string
	Evaluator                 Effect
	Reasons                   []string
}

func (d Disagreement) String() string {
	return fmt.Sprintf("%s: %s on %s: simulator %s, evaluator %s (%s)", d.Fixture, d.Action, d.Resource, d.Simulator, d.Evaluator, strings.Join(d.Reasons, "; "))
}

// simulatorEffect maps an EvalDecision to the evaluator's vocabulary.
func simulatorEffect(s string) Effect {
	switch s {
	case "allowed":
		return Allow
	case "explicitDeny":
		return ExplicitDeny
	}
	return ImplicitDeny
}

// Replay evaluates every result of the fixture and returns the disagreements. The simulator
// treats context keys it was not given as absent, so requests are ContextComplete.
func Replay(f SimulatorFixture) []Disagreement {
	parse := func(id, doc string) (Policy, error) {
		p, err := ParsePolicy([]byte(doc))
		p.ID = id
		return p, err
	}
	var out []Disagreement
	fail := func(r SimulatorResult, why string) {
		out = append(out, Disagreement{Fixture: f.ID, Action: r.EvalActionName, Resource: r.EvalResourceName, Simulator: r.EvalDecision, Reasons: []string{why}})
	}
	var ps PolicySet
	for i, d := range f.PolicyInputList {
		p, err := parse(fmt.Sprintf("policy-%d", i), d)
		if err != nil {
			for _, r := range f.Results {
				fail(r, err.Error())
			}
			return out
		}
		ps.Identity = append(ps.Identity, p)
	}
	for i, d := range f.PermissionsBoundaryPolicyInputList {
		p, err := parse(fmt.Sprintf("boundary-%d", i), d)
		if err == nil {
			ps.Boundary = &p
		}
	}
	if f.ResourcePolicy != "" {
		if p, err := parse("resource-policy", f.ResourcePolicy); err == nil {
			ps.Resource = &p
		}
	}
	for lvl, docs := range f.OrganizationsPolicies {
		var level []Policy
		for i, d := range docs {
			if p, err := parse(fmt.Sprintf("scp-%d-%d", lvl, i), d); err == nil {
				level = append(level, p)
			}
		}
		ps.SCPs = append(ps.SCPs, level)
	}
	ctx := map[string]ConditionValue{}
	for _, c := range f.ContextEntries {
		ctx[c.ContextKeyName] = ConditionValue(c.ContextKeyValues)
	}
	owner := f.ResourceOwner
	if a := arnAccount(owner); a != "" {
		owner = a
	}
	for _, r := range f.Results {
		d := EvaluateSet(Request{Principal: f.CallerArn, Action: r.EvalActionName, Resource: r.EvalResourceName, ResourceAccount: owner, Context: ctx, ContextComplete: true}, ps)
		if d.Effect != simulatorEffect(r.EvalDecision) {
			out = append(out, Disagreement{Fixture: f.ID, Action: r.EvalActionName, Resource: r.EvalResourceName, Simulator: r.EvalDecision, Evaluator: d.Effect, Reasons: d.Reasons})
		}
	}
	return out
}
