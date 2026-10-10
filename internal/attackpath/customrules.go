package attackpath

// Customer path rules in the product (W7-ENGINE item 2, competitive delta r5 #4; bar: Sysdig
// custom risk definitions become Issues with New badges).
//
// Rules load from directories (config path_rules.dirs, `--rules-dir` on scan / ingest / paths).
// Every file is validated with `risk test` semantics before traversal sees it: the schema (unknown
// keys are errors), ValidatePathRules, and the rule's own tests block against its fixture
// (RunPathRuleTests). A rule whose id repeats a library rule or an earlier customer rule is
// refused. A refused rule is never used; the refusal names the file and the reason, and the other
// rules still load. Accepted rules feed TraversalOptions.PathRules next to the library, so a
// verified match folds into the traversal Issue carrying it or, for a chain traversal did not
// find, becomes a rule-match path Issue tagged rule_match + custom (rulematch.go).

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// RejectedPathRule is a customer rule file that was not loaded, with the reason.
type RejectedPathRule struct {
	File   string `json:"file"`
	ID     string `json:"id,omitempty"`
	Reason string `json:"reason"`
}

func (r RejectedPathRule) String() string {
	if r.ID != "" {
		return fmt.Sprintf("path rule %s (%s) rejected: %s", r.ID, r.File, r.Reason)
	}
	return fmt.Sprintf("path rule file %s rejected: %s", r.File, r.Reason)
}

// LoadCustomPathRules loads every *.yaml / *.yml under each directory (recursively, in path
// order), validating each rule on its own with `risk test` semantics. existing are the rules
// already in use (the library): a customer rule may not reuse one of their ids.
func LoadCustomPathRules(dirs []string, existing []PathRule) ([]PathRule, []RejectedPathRule) {
	ids := map[string]string{}
	for _, r := range existing {
		ids[r.ID] = r.Source
	}
	var accepted []PathRule
	var rejected []RejectedPathRule
	for _, dir := range dirs {
		var files []string
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				if ext := filepath.Ext(p); ext == ".yaml" || ext == ".yml" {
					files = append(files, p)
				}
			}
			return nil
		})
		if err != nil {
			rejected = append(rejected, RejectedPathRule{File: dir, Reason: "cannot read the rules directory: " + err.Error()})
			continue
		}
		sort.Strings(files)
		for _, f := range files {
			b, err := os.ReadFile(f) // #nosec G304 -- a rules directory the operator configured
			if err != nil {
				rejected = append(rejected, RejectedPathRule{File: f, Reason: err.Error()})
				continue
			}
			r, err := ParsePathRule(b)
			if err != nil {
				rejected = append(rejected, RejectedPathRule{File: f, Reason: "schema: " + err.Error()})
				continue
			}
			r.Source = f
			if prev, dup := ids[r.ID]; dup {
				rejected = append(rejected, RejectedPathRule{File: f, ID: r.ID, Reason: "duplicate id (also " + prev + ")"})
				continue
			}
			if err := ValidatePathRules([]PathRule{r}); err != nil {
				rejected = append(rejected, RejectedPathRule{File: f, ID: r.ID, Reason: "schema: " + err.Error()})
				continue
			}
			if err := RunPathRuleTests(r); err != nil {
				rejected = append(rejected, RejectedPathRule{File: f, ID: r.ID, Reason: "own tests fail: " + err.Error()})
				continue
			}
			ids[r.ID] = f
			accepted = append(accepted, r)
		}
	}
	return accepted, rejected
}

// ProductPathRules is the embedded library (what traversal uses by default).
func ProductPathRules() []PathRule {
	return append([]PathRule(nil), productRules()...)
}

// PotentialEscalations is every INFERRED path-rule match on g, keyed by the anchor principal's
// node id (W7-ENGINE r5 #10): the permissions allow an escalation the graph cannot prove (an SSM
// session onto an instance whose role is admin, a role that may rewrite its own policy). They are
// "potential escalation" annotations on the principal's finding Issue, never path Issues
// (verified matches are: rulematch.go). rules nil = the embedded library. Store-free; matches per
// anchor are sorted by rule id, then target.
func PotentialEscalations(g *graph.Graph, rules []PathRule) map[string][]PathRuleMatch {
	if rules == nil {
		rules = productRules()
	}
	out := map[string][]PathRuleMatch{}
	if g == nil {
		return out
	}
	for _, r := range rules {
		custom := IsCustomRule(r)
		for _, m := range MatchPathRule(g, r) {
			if m.Confidence != string(model.ConfidenceInferred) {
				continue
			}
			m.Custom = custom
			out[m.Anchor] = append(out[m.Anchor], m)
		}
	}
	for a, ms := range out {
		sort.SliceStable(ms, func(i, j int) bool {
			if ms[i].RuleID != ms[j].RuleID {
				return ms[i].RuleID < ms[j].RuleID
			}
			return ms[i].Target < ms[j].Target
		})
		out[a] = ms
	}
	return out
}
