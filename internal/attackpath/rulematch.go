package attackpath

// Rule matches in the product (W6-ENGINE item 1, competitive delta r4 #7; W7-ENGINE r5 #3 / #4;
// bars: Prowler's AWS attack-path queries feed its findings, Sysdig custom risk definitions
// produce Issues with New badges).
//
// The path-rule library (pathrules.go: the embedded Prowler ports plus validated customer rules,
// TraversalOptions.PathRules) is evaluated inside traversal. For every VERIFIED match:
//
//   - the escalation (anchor → target over the rule's verifying edge kind; the anchor anywhere
//     before the target otherwise) lies on an emitted traversal path, as its whole hop list or a
//     sub-path of it: the match FOLDS into every such path. The rule id joins the path's
//     also_matches_rule tag, path_rule_matches records the rule, confidence, because and credit,
//     and the last step's because names the rule and its credit. The match never becomes a second
//     Issue (r5 #3: W6 emitted the dev-sam PassRole match as its own Issue, duplicating the
//     traversal Issue with the same two hops);
//   - the escalation lies on no emitted path, but an entry reaches the anchor and the target is
//     an impact target: a chain traversal did not find. It becomes a rule-match path Issue (the
//     emitted prefix to the anchor plus one rule hop), rule id = the path's rule (Issue id
//     component), last step tagged rule_match (+ custom for a customer rule). Being a new path
//     Issue, the lifecycle gives it the first-seen "new" state.
//
// Inferred matches never become paths; they are "potential escalation" annotations on the
// principal (PotentialEscalations). A verified match no entry reaches stays dry-run (`risk test`):
// precision first (lab/ground_truth.yaml, noise estate).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// AttrRuleMatch is the evidence key, on the last step of a rule-match path, holding the rule id.
// RuleMatchTag is the tag rule-match paths carry (evidence "tags"); CustomRuleTag is added for a
// customer rule. AttrPathRuleMatches, on the last step of a traversal path, lists the verified
// rule matches folded into it ([]PathRuleMatch; PathRuleMatchesOf reads it back).
const (
	AttrRuleMatch       = "rule_match"
	RuleMatchTag        = "rule_match"
	CustomRuleTag       = "custom"
	AttrPathRuleMatches = "path_rule_matches"
)

// IsRuleMatch reports a path the path-rule library produced (a rule-match path Issue).
func IsRuleMatch(p model.AttackPath) bool {
	if len(p.Steps) == 0 {
		return false
	}
	v, _ := p.Steps[len(p.Steps)-1].Evidence[AttrRuleMatch].(string)
	return v != ""
}

// PathRuleMatchesOf returns the verified rule matches folded into p (nil when none). It reads
// both the in-memory form and the JSON-decoded form a stored path carries.
func PathRuleMatchesOf(p model.AttackPath) []PathRuleMatch {
	if len(p.Steps) == 0 {
		return nil
	}
	switch v := p.Steps[len(p.Steps)-1].Evidence[AttrPathRuleMatches].(type) {
	case nil:
		return nil
	case []PathRuleMatch:
		return append([]PathRuleMatch(nil), v...)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		var out []PathRuleMatch
		if json.Unmarshal(b, &out) != nil {
			return nil
		}
		return out
	}
}

var (
	libOnce  sync.Once
	libRules []PathRule
)

// productRules is the embedded library parsed once (traversal runs it on every what-if re-run).
func productRules() []PathRule {
	libOnce.Do(func() {
		rs, err := LibraryPathRules()
		if err == nil {
			libRules = rs
		}
	})
	return libRules
}

// canBeVerified: only a rule with verified_by_edge, or one declaring itself verified, can produce
// a verified match.
func canBeVerified(r PathRule) bool {
	return r.VerifiedByEdge != nil || r.Confidence == string(model.ConfidenceVerified)
}

// IsCustomRule reports a customer rule (loaded from a rules directory, not the embedded library).
func IsCustomRule(r PathRule) bool {
	return !strings.HasPrefix(r.Source, "builtin:")
}

// rulePaths applies the verified rule matches to the emitted traversal paths (complete and
// prefix): it returns the paths with folded matches annotated (inputs are never mutated), the
// rule-match paths for chains traversal did not find, and every verified match (PathID: the
// path it folded into or became; Folded for a fold).
func rulePaths(g *graph.Graph, rules []PathRule, emitted []model.AttackPath, crit map[string]int, opts TraversalOptions) ([]model.AttackPath, []model.AttackPath, []PathRuleMatch) {
	anchors := map[string]bool{}
	for _, p := range emitted {
		for _, s := range p.Steps {
			anchors[s.Resource] = true
		}
	}
	if len(anchors) == 0 {
		return emitted, nil, nil
	}
	paths := emitted
	var extra []model.AttackPath
	var matches []PathRuleMatch
	seen := map[string]bool{}
	for _, r := range rules {
		if !canBeVerified(r) {
			continue
		}
		custom := IsCustomRule(r)
		for _, m := range matchPathRule(g, r, matchOptions{anchors: anchors, verifiedOnly: true}) {
			if m.Confidence != string(model.ConfidenceVerified) {
				continue
			}
			m.Custom = custom
			if out, id, ok := foldRuleMatch(r, m, paths, custom); ok {
				paths, m.PathID, m.Folded = out, id, true
			} else if p, ok := newRuleChain(g, r, m, paths, crit, opts); ok {
				if !seen[p.ID] {
					seen[p.ID] = true
					extra = append(extra, p)
				}
				m.PathID = p.ID
			}
			matches = append(matches, m)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].RuleID != matches[j].RuleID {
			return matches[i].RuleID < matches[j].RuleID
		}
		if matches[i].Anchor != matches[j].Anchor {
			return matches[i].Anchor < matches[j].Anchor
		}
		return matches[i].Target < matches[j].Target
	})
	return paths, extra, matches
}

// carriesEscalation reports a path whose hops contain the match's escalation: the target with
// the anchor right before it over the rule's verifying edge kind (a verified_by_edge rule), the
// anchor itself for a self rule, or the anchor anywhere before the target otherwise.
func carriesEscalation(r PathRule, m PathRuleMatch, p model.AttackPath) bool {
	for k, s := range p.Steps {
		if s.Resource != m.Target {
			continue
		}
		switch {
		case m.Anchor == m.Target:
			return true
		case r.VerifiedByEdge != nil:
			if k >= 1 && p.Steps[k-1].Resource == m.Anchor && s.Relation == r.VerifiedByEdge.Kind {
				return true
			}
		default:
			for _, x := range p.Steps[:k] {
				if x.Resource == m.Anchor {
					return true
				}
			}
		}
	}
	return false
}

// foldRuleMatch tags every path carrying the match's escalation (copies; the input slice is not
// mutated) and returns the id of the path Issue it folded into: the best-scoring carrier that is
// not a strict prefix of another emitted path (that one is the complete path), else the best.
func foldRuleMatch(r PathRule, m PathRuleMatch, paths []model.AttackPath, custom bool) ([]model.AttackPath, string, bool) {
	var carriers []int
	for i, p := range paths {
		if carriesEscalation(r, m, p) {
			carriers = append(carriers, i)
		}
	}
	if len(carriers) == 0 {
		return paths, "", false
	}
	extended := map[string]bool{}
	for _, p := range paths {
		e := pathEntry(p)
		for k := 1; k < len(p.Steps); k++ {
			extended[stepKey(e, p.Steps[:k])] = true
		}
	}
	better := func(a, b model.AttackPath) bool {
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if ka, kb := model.PathSecondaryKey(a), model.PathSecondaryKey(b); ka != kb {
			return ka < kb
		}
		return a.ID < b.ID
	}
	best, bestComplete := -1, -1
	for _, i := range carriers {
		if best < 0 || better(paths[i], paths[best]) {
			best = i
		}
		if !extended[stepKey(pathEntry(paths[i]), paths[i].Steps)] && (bestComplete < 0 || better(paths[i], paths[bestComplete])) {
			bestComplete = i
		}
	}
	if bestComplete >= 0 {
		best = bestComplete
	}
	out := append([]model.AttackPath(nil), paths...)
	for _, i := range carriers {
		out[i] = withFoldedMatch(out[i], r, m)
	}
	return out, out[best].ID, true
}

func ruleCredit(r PathRule) string {
	if r.Credit == nil {
		return ""
	}
	credit := fmt.Sprintf("%s (%s) %s", r.Credit.Source, r.Credit.Licence, r.Credit.UpstreamID)
	if r.Credit.Upstream != "" {
		credit += "; upstream " + r.Credit.Upstream
	}
	return credit
}

// withFoldedMatch returns p with the match recorded on its last step (also_matches_rule,
// path_rule_matches, because).
func withFoldedMatch(p model.AttackPath, r PathRule, m PathRuleMatch) model.AttackPath {
	steps := append([]model.Step(nil), p.Steps...)
	last := steps[len(steps)-1]
	ev := make(map[string]any, len(last.Evidence)+2)
	for k, v := range last.Evidence {
		ev[k] = v
	}
	rules := append(toStrings(ev[AttrAlsoMatchesRule]), r.ID)
	rules = uniq(rules)
	sort.Strings(rules)
	ev[AttrAlsoMatchesRule] = rules
	pm := PathRuleMatchesOf(p)
	dup := false
	for _, x := range pm {
		dup = dup || x.RuleID == m.RuleID && x.Anchor == m.Anchor && x.Target == m.Target
	}
	if !dup {
		pm = append(pm, m)
		sort.Slice(pm, func(i, j int) bool {
			if pm[i].RuleID != pm[j].RuleID {
				return pm[i].RuleID < pm[j].RuleID
			}
			return pm[i].Anchor+">"+pm[i].Target < pm[j].Anchor+">"+pm[j].Target
		})
		kind := "path rule"
		if m.Custom {
			kind = "custom path rule"
		}
		last.Because += fmt.Sprintf("; also matches %s %s (%s) [%s]", kind, r.ID, r.Title, m.Confidence)
		if c := ruleCredit(r); c != "" {
			last.Because += "; credit " + c
		}
	}
	ev[AttrPathRuleMatches] = pm
	last.Evidence = ev
	steps[len(steps)-1] = last
	p.Steps = steps
	return p
}

// newRuleChain is the rule-match path for a verified match traversal did not find: the best
// emitted path through the anchor, cut at the anchor, plus one rule hop to the target. The
// target must be an impact target. The rule hop has the likelihood of a verified escalation
// (0.9, decayed like any lateral hop) and the path is scored by buildPath like a traversal path
// (likelihood × the target's priority, the toxic / identity floors, and never below the score
// already held at the anchor when the anchor itself is a crown jewel).
func newRuleChain(g *graph.Graph, r PathRule, m PathRuleMatch, emitted []model.AttackPath, crit map[string]int, opts TraversalOptions) (model.AttackPath, bool) {
	c := crit[m.Target]
	if c < 2 || m.Anchor == m.Target {
		return model.AttackPath{}, false
	}
	tn, ok := g.Node(m.Target)
	if !ok {
		return model.AttackPath{}, false
	}
	var base model.AttackPath
	cut, found := 0, false
	for _, p := range emitted {
		for k, s := range p.Steps {
			if s.Resource == m.Target {
				break // a path that already passes the target before the anchor is no base
			}
			if s.Resource != m.Anchor {
				continue
			}
			if !found || p.Score > base.Score || p.Score == base.Score && model.PathSecondaryKey(p) < model.PathSecondaryKey(base) {
				base, cut, found = p, k+1, true
			}
			break
		}
	}
	if !found {
		return model.AttackPath{}, false
	}
	prefix := base.Steps[:cut]
	entry, ok := g.Node(graph.InternetNodeID)
	if pathEntry(base) != "internet" {
		entry, ok = g.Node(prefix[0].Resource)
	}
	if !ok {
		return model.AttackPath{}, false
	}
	steps := append([]model.Step(nil), prefix...)
	lik, best := 1.0, 0.0
	for i, s := range steps {
		if v, ok := s.Evidence["likelihood"].(float64); ok && v > 0 {
			lik *= v
		}
		if i > 0 && s.Relation != "entry" {
			lik *= hopDecayOf(opts)
		}
	}
	// The score already held at the anchor (an emitted path ending exactly there).
	key := stepKey(pathEntry(base), prefix)
	for _, p := range emitted {
		if p.Score > best && stepKey(pathEntry(p), p.Steps) == key {
			best = p.Score
		}
	}
	const ruleHop = 0.9
	lik *= ruleHop * hopDecayOf(opts)
	if lik < minLik(opts) {
		return model.AttackPath{}, false
	}
	width := ""
	if entry.ID == graph.InternetNodeID {
		for _, e := range g.Out(entry.ID) {
			if e.To == prefix[0].Resource {
				if w := entryWidthOf(g, entry, e, opts.TrustedCIDRs); w != "" {
					width = w
				}
			}
		}
	}
	rel := "path_rule"
	if r.VerifiedByEdge != nil {
		rel = r.VerifiedByEdge.Kind
	}
	credit := ruleCredit(r)
	tags := []string{RuleMatchTag}
	if m.Custom {
		tags = append(tags, CustomRuleTag)
	}
	because := fmt.Sprintf("path rule %s (%s) matches [%s]: %s", r.ID, r.Title, m.Confidence, strings.Join(m.Because, "; "))
	if credit != "" {
		because += "; credit " + credit
	}
	steps = append(steps, model.Step{Stage: len(steps) + 1, Relation: rel, Resource: tn.ID, Title: tn.Name,
		Summary: fmt.Sprintf("%s (%s): %s [p=%.2f]", tn.Name, tn.Type, r.Title, ruleHop), Because: because,
		Evidence: map[string]any{"edge": rel, "from": m.Anchor, "to": m.Target, "likelihood": ruleHop, model.AttrConfidence: m.Confidence,
			AttrRuleMatch: r.ID, "rule_confidence": m.Confidence, "rule_because": append([]string(nil), m.Because...),
			"rule_credit": credit, "rule_custom": m.Custom, "tags": tags}})
	p := buildPath(g, entry, frame{node: tn, steps: steps, lik: lik, best: best, entryWidth: width}, priorityOf[c], opts.CrownJewels)
	if p.Score < opts.MinScore {
		return model.AttackPath{}, false
	}
	name := func(id string) string {
		if n, ok := g.Node(id); ok {
			return nodeLabel(n)
		}
		return id
	}
	var hops []string
	for _, s := range p.Steps {
		hops = append(hops, s.Resource)
	}
	sum := sha256.Sum256([]byte("rule_match|" + r.ID + "|" + pathEntry(base) + "|" + strings.Join(hops, ">")))
	p.ID, p.RuleID = hex.EncodeToString(sum[:8]), r.ID
	p.Name = fmt.Sprintf("%s: %s → %s", r.Title, name(m.Anchor), name(m.Target))
	p.Narrative += "\nPath rule " + r.ID + " (" + r.Title + "), " + m.Confidence
	if credit != "" {
		p.Narrative += "; credit " + credit
	}
	return p, true
}

func hopDecayOf(opts TraversalOptions) float64 {
	if opts.HopDecay > 0 {
		return opts.HopDecay
	}
	return 1
}

// PathRuleCount is one rule's match count on a graph (`risk list` against the stored snapshot).
type PathRuleCount struct {
	Total    int `json:"total"`
	Verified int `json:"verified"`
}

// PathRuleMatchCounts runs every rule over g (dry run, no writes) and counts its matches; every
// rule has an entry (zero included).
func PathRuleMatchCounts(g *graph.Graph, rules []PathRule) map[string]PathRuleCount {
	out := make(map[string]PathRuleCount, len(rules))
	for _, r := range rules {
		c := PathRuleCount{}
		if g != nil {
			for _, m := range MatchPathRule(g, r) {
				c.Total++
				if m.Confidence == string(model.ConfidenceVerified) {
					c.Verified++
				}
			}
		}
		out[r.ID] = c
	}
	return out
}
