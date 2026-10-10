package attackpath

// Path rules (competitive delta r3 #9; matrix rows AP4 rule authoring, ID2 privesc library).
//
// One YAML rule per file. A rule names an anchor (an AWS principal type), how a target is
// joined to it, what the IAM evaluator must allow the anchor to do, and its own tests: a mini
// graph fixture plus expected match / no-match pairs. The validator refuses a rule with an
// unknown edge kind, a missing credit on a ported rule, a co-tenancy join without
// allow_same_account + justification, or a duplicate id. The embedded library
// (rules/aws/privesc/*.yaml) ports Prowler's AWS privilege-escalation queries by id, with credit;
// user rules load from a directory (`cloud-posture risk test`, `--rules-dir`).
//
// join modes:
//   self         the target is the anchor itself (self-escalation: put/attach own policy)
//   permission   the target is any node passing the target constraints on which every
//                `resource: target` permission evaluates to allow/unknown (a permission link)
//   path         the target is reached from the anchor by the typed `path` hops (graph edges);
//                `resource: target` permissions are then evaluated on that node
//   same_account no edge or permission scopes the target: co-tenancy, needs allow_same_account
//                and a justification (mirrors ValidateRules for finding-chain rules)
//
// confidence: a rule declares inferred (or verified). A match is verified only when the rule's
// verified_by_edge names a graph edge from anchor to target that the evaluator marked verified,
// or every permission decision is an exact Allow and the rule itself declares verified.

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/iam"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"gopkg.in/yaml.v3"
)

//go:embed rules/aws/privesc/*.yaml
var pathRuleFS embed.FS

// PathRuleCredit records where a ported rule came from (Apache-2.0 requires attribution).
type PathRuleCredit struct {
	Source     string `yaml:"source" json:"source"`
	Licence    string `yaml:"licence" json:"licence"`
	URL        string `yaml:"url" json:"url"`
	UpstreamID string `yaml:"upstream_id" json:"upstream_id,omitempty"`
	// Upstream: the credit the source itself gives (Prowler credits pathfinding.cloud).
	Upstream    string `yaml:"upstream" json:"upstream,omitempty"`
	UpstreamURL string `yaml:"upstream_url" json:"upstream_url,omitempty"`
	Modified    string `yaml:"modified" json:"modified,omitempty"`
}

type PathRuleAnchor struct {
	Types []string `yaml:"types" json:"types"`
	// IncludeAdmin keeps principals iam.IsAdmin calls admin — which includes any principal
	// holding one escalation action on "*" (the self-escalation rules need exactly those).
	// Principals allowed "*" on "*" are never anchors.
	IncludeAdmin bool `yaml:"include_admin" json:"include_admin,omitempty"`
}

type PathRulePermission struct {
	Action string `yaml:"action" json:"action"`
	// Resource: "target", "anchor", or an ARN template with {account} / {region} / {anchor} / {target}.
	Resource string `yaml:"resource" json:"resource"`
}

type PathRuleHop struct {
	Edge      string   `yaml:"edge" json:"edge"`
	Direction string   `yaml:"direction" json:"direction,omitempty"` // out (default) | in
	ToTypes   []string `yaml:"to_types" json:"to_types,omitempty"`
	// ToAdmin: the node reached must be a principal the IAM evaluator rates admin (holds an
	// escalation action or more), e.g. the role an instance runs as for the SSM / EC2 Instance
	// Connect rules: taking over an instance whose role lifts nothing is not an escalation.
	ToAdmin bool `yaml:"to_admin" json:"to_admin,omitempty"`
}

type PathRuleTarget struct {
	Types         []string     `yaml:"types" json:"types,omitempty"`
	TrustsService string       `yaml:"trusts_service" json:"trusts_service,omitempty"`
	HasAttribute  []string     `yaml:"has_attribute" json:"has_attribute,omitempty"` // any of
	HasEdge       *PathRuleHop `yaml:"has_edge" json:"has_edge,omitempty"`
	ExcludeSelf   bool         `yaml:"exclude_self" json:"exclude_self,omitempty"`
	// IDLike: the target id must match one of these globs (`*` any run, `?` one char), e.g.
	// arn:aws:iam::*:policy/* for customer-managed policies (not inline or AWS-managed).
	IDLike []string `yaml:"id_like" json:"id_like,omitempty"`
}

type PathRuleMatchSpec struct {
	Join                string               `yaml:"join" json:"join"`
	RequiresPermissions []PathRulePermission `yaml:"requires_permissions" json:"requires_permissions,omitempty"`
	Path                []PathRuleHop        `yaml:"path" json:"path,omitempty"`
	Target              PathRuleTarget       `yaml:"target" json:"target"`
}

type PathRuleEdgeProof struct {
	Kind      string `yaml:"kind" json:"kind"`
	Technique string `yaml:"technique" json:"technique,omitempty"`
}

type PathRuleFixtureNode struct {
	ID         string         `yaml:"id"`
	Type       string         `yaml:"type"`
	Account    string         `yaml:"account"`
	Region     string         `yaml:"region"`
	Attributes map[string]any `yaml:"attributes"`
	Weaknesses []string       `yaml:"weaknesses"`
}

type PathRuleFixtureEdge struct {
	From string         `yaml:"from"`
	To   string         `yaml:"to"`
	Kind string         `yaml:"kind"`
	Attr map[string]any `yaml:"attr"`
}

type PathRuleExpect struct {
	Anchor     string `yaml:"anchor"`
	Target     string `yaml:"target"`
	Match      bool   `yaml:"match"`
	Confidence string `yaml:"confidence"`
}

type PathRuleTests struct {
	Fixture struct {
		Nodes []PathRuleFixtureNode `yaml:"nodes"`
		Edges []PathRuleFixtureEdge `yaml:"edges"`
	} `yaml:"fixture"`
	Expect []PathRuleExpect `yaml:"expect"`
}

// PathRule is one path rule file.
type PathRule struct {
	ID               string             `yaml:"id" json:"id"`
	Title            string             `yaml:"title" json:"title"`
	Description      string             `yaml:"description" json:"description"`
	Severity         string             `yaml:"severity" json:"severity"`
	Confidence       string             `yaml:"confidence" json:"confidence"`
	Credit           *PathRuleCredit    `yaml:"credit" json:"credit,omitempty"`
	Anchor           PathRuleAnchor     `yaml:"anchor" json:"anchor"`
	Match            PathRuleMatchSpec  `yaml:"match" json:"match"`
	Requires         []string           `yaml:"requires" json:"requires,omitempty"` // anchor weaknesses (all of)
	AllowSameAccount bool               `yaml:"allow_same_account" json:"allow_same_account,omitempty"`
	Justification    string             `yaml:"justification" json:"justification,omitempty"`
	VerifiedByEdge   *PathRuleEdgeProof `yaml:"verified_by_edge" json:"verified_by_edge,omitempty"`
	Tests            PathRuleTests      `yaml:"tests" json:"-"`
	// Ported: set for library rules (credit then mandatory); Source records the file.
	Ported bool   `yaml:"ported" json:"ported,omitempty"`
	Source string `yaml:"-" json:"source_file,omitempty"`
}

// PathRuleMatch is one anchor -> target match with a per-hop explanation.
type PathRuleMatch struct {
	RuleID     string          `json:"rule_id"`
	Title      string          `json:"title"`
	Anchor     string          `json:"anchor"`
	Target     string          `json:"target"`
	Confidence string          `json:"confidence"`
	Because    []string        `json:"because"`
	Credit     *PathRuleCredit `json:"credit,omitempty"`
	// PathID is the path Issue a verified match folded into (Folded) or became, if any.
	PathID string `json:"path_id,omitempty"`
	Folded bool   `json:"folded,omitempty"`
	// Custom: the match comes from a customer rule (a rules directory), not the library.
	Custom bool `json:"custom,omitempty"`
}

// ParsePathRule decodes one rule (unknown keys are errors: typos must not silently disable a rule).
func ParsePathRule(data []byte) (PathRule, error) {
	var r PathRule
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return PathRule{}, fmt.Errorf("path rule: %w", err)
	}
	if r.Credit != nil && r.Credit.Source != "" {
		r.Ported = r.Ported || r.Credit.UpstreamID != ""
	}
	return r, nil
}

func knownEdgeKind(k string) bool {
	for _, s := range graph.EdgeKinds {
		if s.Kind == k {
			return true
		}
	}
	return false
}

func validateHop(id string, h PathRuleHop, where string) error {
	if !knownEdgeKind(h.Edge) {
		return fmt.Errorf("path rule %s: %s: unknown edge kind %q (see graph.EdgeKinds)", id, where, h.Edge)
	}
	if h.Direction != "" && h.Direction != "out" && h.Direction != "in" {
		return fmt.Errorf("path rule %s: %s: direction must be out or in, got %q", id, where, h.Direction)
	}
	return nil
}

// ValidatePathRules checks every rule and rejects duplicate ids, with errors naming the rule.
func ValidatePathRules(rules []PathRule) error {
	seen := map[string]string{}
	for _, r := range rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("path rule %s: missing id", r.Source)
		}
		if prev, dup := seen[r.ID]; dup {
			return fmt.Errorf("path rule %s: duplicate id (also in %s)", r.ID, prev)
		}
		seen[r.ID] = r.Source
		if r.Title == "" {
			return fmt.Errorf("path rule %s: missing title", r.ID)
		}
		switch r.Confidence {
		case string(model.ConfidenceInferred), string(model.ConfidenceVerified):
		default:
			return fmt.Errorf("path rule %s: confidence must be inferred or verified, got %q", r.ID, r.Confidence)
		}
		if r.Ported || r.Credit != nil {
			c := r.Credit
			if c == nil || c.Source == "" || c.Licence == "" || c.URL == "" {
				return fmt.Errorf("path rule %s: ported rule needs credit (source, licence, url)", r.ID)
			}
		}
		if len(r.Anchor.Types) == 0 {
			return fmt.Errorf("path rule %s: anchor.types is empty", r.ID)
		}
		m := r.Match
		for i, h := range m.Path {
			if err := validateHop(r.ID, h, fmt.Sprintf("match.path[%d]", i)); err != nil {
				return err
			}
		}
		if m.Target.HasEdge != nil {
			if err := validateHop(r.ID, *m.Target.HasEdge, "match.target.has_edge"); err != nil {
				return err
			}
		}
		if r.VerifiedByEdge != nil && !knownEdgeKind(r.VerifiedByEdge.Kind) {
			return fmt.Errorf("path rule %s: verified_by_edge: unknown edge kind %q", r.ID, r.VerifiedByEdge.Kind)
		}
		for i, p := range m.RequiresPermissions {
			if !strings.Contains(p.Action, ":") || p.Resource == "" {
				return fmt.Errorf("path rule %s: requires_permissions[%d] needs service:Action and a resource", r.ID, i)
			}
		}
		targetScoped := false
		for _, p := range m.RequiresPermissions {
			if p.Resource == "target" || strings.Contains(p.Resource, "{target}") {
				targetScoped = true
			}
		}
		switch m.Join {
		case "self":
		case "permission":
			if !targetScoped {
				return fmt.Errorf("path rule %s: join permission needs a requires_permissions entry on resource: target", r.ID)
			}
			if len(m.Target.Types) == 0 {
				return fmt.Errorf("path rule %s: join permission needs match.target.types", r.ID)
			}
		case "path":
			if len(m.Path) == 0 {
				return fmt.Errorf("path rule %s: join path needs match.path hops", r.ID)
			}
		case "same_account":
			if !r.AllowSameAccount {
				return fmt.Errorf("path rule %s: join same_account joins by co-tenancy; set allow_same_account with a justification, or use permission/path", r.ID)
			}
		default:
			return fmt.Errorf("path rule %s: match.join must be self, permission, path or same_account, got %q", r.ID, m.Join)
		}
		if r.AllowSameAccount && strings.TrimSpace(r.Justification) == "" {
			return fmt.Errorf("path rule %s: allow_same_account needs a justification", r.ID)
		}
		if len(r.Tests.Expect) == 0 {
			return fmt.Errorf("path rule %s: tests.expect is empty (a rule ships with a fixture match and a near-miss)", r.ID)
		}
		hasMatch, hasMiss := false, false
		for _, e := range r.Tests.Expect {
			hasMatch = hasMatch || e.Match
			hasMiss = hasMiss || !e.Match
		}
		if !hasMatch || !hasMiss {
			return fmt.Errorf("path rule %s: tests need at least one match and one near-miss (match: false)", r.ID)
		}
	}
	return nil
}

func loadRuleFS(fsys fs.FS, pattern string) ([]PathRule, error) {
	names, err := fs.Glob(fsys, pattern)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var out []PathRule
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, err
		}
		r, err := ParsePathRule(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		r.Source = n
		out = append(out, r)
	}
	return out, nil
}

// LibraryPathRules returns the embedded library, validated. The rules are compiled into the
// binary (embed.FS), so a release archive carries them without the source tree; Source reads
// "builtin:<path in the library>".
func LibraryPathRules() ([]PathRule, error) {
	rules, err := loadRuleFS(pathRuleFS, "rules/aws/privesc/*.yaml")
	if err != nil {
		return nil, err
	}
	for i := range rules {
		rules[i].Ported = true
		rules[i].Source = "builtin:" + rules[i].Source
	}
	return rules, ValidatePathRules(rules)
}

// LibraryPathRule returns the embedded rule with this id.
func LibraryPathRule(id string) (PathRule, bool) {
	rules, err := LibraryPathRules()
	if err != nil {
		return PathRule{}, false
	}
	for _, r := range rules {
		if r.ID == id {
			return r, true
		}
	}
	return PathRule{}, false
}

// LoadPathRulesDir loads every *.yaml / *.yml under dir (recursively), validated.
func LoadPathRulesDir(dir string) ([]PathRule, error) {
	var out []PathRule
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		r, err := ParsePathRule(b)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		r.Source = p
		out = append(out, r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, ValidatePathRules(out)
}

// LoadPathRuleFile loads and validates one rule file, or, when no such file exists, the embedded
// library rule with that id (`risk test <id|file>`: the id `risk list` prints works as is).
func LoadPathRuleFile(path string) (PathRule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if r, ok := LibraryPathRule(strings.TrimSpace(path)); ok {
				return r, nil
			}
			return PathRule{}, fmt.Errorf("%s: no such file or library rule (cloud-posture risk list prints the library ids)", path)
		}
		return PathRule{}, err
	}
	r, err := ParsePathRule(b)
	if err != nil {
		return PathRule{}, fmt.Errorf("%s: %w", path, err)
	}
	r.Source = path
	return r, ValidatePathRules([]PathRule{r})
}

func typeIn(t string, types []string) bool {
	if len(types) == 0 {
		return true
	}
	for _, x := range types {
		if x == t {
			return true
		}
	}
	return false
}

func nodeLabel(n *graph.Node) string {
	if n.Name != "" && n.Name != n.ID {
		return n.Name
	}
	return n.ID
}

func expandResource(tmpl string, anchor, target *graph.Node, account string) string {
	switch tmpl {
	case "target":
		return target.ID
	case "anchor":
		return anchor.ID
	}
	region := target.Region
	if region == "" {
		region = anchor.Region
	}
	if region == "" {
		region = "us-east-1"
	}
	tid := ""
	if target != nil {
		tid = target.ID
	}
	return strings.NewReplacer("{account}", account, "{region}", region, "{anchor}", anchor.ID, "{target}", tid).Replace(tmpl)
}

func hopNeighbours(g *graph.Graph, from string, h PathRuleHop) []string {
	var out []string
	edges := g.Out(from)
	if h.Direction == "in" {
		edges = g.In(from)
	}
	for _, e := range edges {
		if e.Kind != h.Edge {
			continue
		}
		next := e.To
		if h.Direction == "in" {
			next = e.From
		}
		if h.ToAdmin && !g.PrincipalIsAdmin(next) {
			continue
		}
		if n, ok := g.Node(next); ok && typeIn(n.Type, h.ToTypes) {
			out = append(out, next)
		}
	}
	return out
}

func (r PathRule) targetOK(g *graph.Graph, anchor, t *graph.Node, account string) (string, bool) {
	tc := r.Match.Target
	if !typeIn(t.Type, tc.Types) {
		return "", false
	}
	if tc.ExcludeSelf && t.ID == anchor.ID {
		return "", false
	}
	if len(tc.IDLike) > 0 {
		hit := false
		for _, pat := range tc.IDLike {
			if globMatch(pat, t.ID) {
				hit = true
				break
			}
		}
		if !hit {
			return "", false
		}
	}
	if g.AccountOf(t.ID) != "" && g.AccountOf(t.ID) != account {
		return "", false // v1: same-account escalations only (as Prowler's queries are per account)
	}
	var why []string
	if tc.TrustsService != "" {
		if !g.TrustsService(t.ID, tc.TrustsService) {
			return "", false
		}
		why = append(why, fmt.Sprintf("%s trusts %s", nodeLabel(t), tc.TrustsService))
	}
	if len(tc.HasAttribute) > 0 {
		hit := ""
		for _, a := range tc.HasAttribute {
			if v, ok := t.Attributes[a]; ok && v != nil && v != "" {
				hit = a
				break
			}
		}
		if hit == "" {
			return "", false
		}
		why = append(why, fmt.Sprintf("%s has %s", nodeLabel(t), hit))
	}
	if tc.HasEdge != nil {
		ns := hopNeighbours(g, t.ID, *tc.HasEdge)
		if len(ns) == 0 {
			return "", false
		}
		why = append(why, fmt.Sprintf("%s -[%s]-> %s", nodeLabel(t), tc.HasEdge.Edge, ns[0]))
	}
	return strings.Join(why, "; "), true
}

// globMatch matches s against a pattern where `*` is any run and `?` one character.
func globMatch(pat, s string) bool {
	if pat == "" {
		return s == ""
	}
	switch pat[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if globMatch(pat[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		return s != "" && globMatch(pat[1:], s[1:])
	}
	return s != "" && s[0] == pat[0] && globMatch(pat[1:], s[1:])
}

// MatchPathRule evaluates r over g and returns matches sorted by anchor, target.
func MatchPathRule(g *graph.Graph, r PathRule) []PathRuleMatch {
	return matchPathRule(g, r, matchOptions{})
}

// matchOptions narrow a rule evaluation (traversal wiring): anchors limits the anchor set (nil:
// every principal); verifiedOnly limits a verified_by_edge rule's targets to the anchor's verified
// out-neighbours over that edge kind (the only targets a verified match can have).
type matchOptions struct {
	anchors      map[string]bool
	verifiedOnly bool
}

func matchPathRule(g *graph.Graph, r PathRule, mo matchOptions) []PathRuleMatch {
	out := []PathRuleMatch{}
	nodes := g.Nodes()
	for _, a := range nodes {
		if mo.anchors != nil && !mo.anchors[a.ID] {
			continue
		}
		if !typeIn(a.Type, r.Anchor.Types) || !g.IsAWSPrincipal(a.ID) {
			continue
		}
		missing := false
		for _, w := range r.Requires {
			if !a.HasWeakness(w) {
				missing = true
			}
		}
		if missing {
			continue
		}
		// A principal already allowed every action on every resource gains nothing from an
		// escalation: never an anchor (Prowler's queries list them; nimbus does not). "Admin" is
		// the evaluator's Allow on a spread of unrelated services (fullAdmin), never a
		// wildcard-looking action set: iam:PassRole on * is the escalation grant itself, and an
		// Allow NotAction iam:* evaluates `*` as allowed although it cannot touch IAM
		// (verification 6 false negatives). include_admin is accepted for compatibility.
		if fullAdmin(g, a.ID) {
			continue
		}
		account := g.AccountOf(a.ID)
		var targets []*graph.Node
		var pathWhy map[string]string
		switch r.Match.Join {
		case "self":
			targets = []*graph.Node{a}
		case "path":
			pathWhy = map[string]string{}
			frontier := map[string]string{a.ID: ""}
			for _, h := range r.Match.Path {
				next := map[string]string{}
				for id, why := range frontier {
					for _, n := range hopNeighbours(g, id, h) {
						if _, ok := next[n]; !ok {
							next[n] = strings.TrimPrefix(why+fmt.Sprintf(" -> %s -[%s]-> %s", id, h.Edge, n), " -> ")
						}
					}
				}
				frontier = next
			}
			for id, why := range frontier {
				if n, ok := g.Node(id); ok {
					targets = append(targets, n)
					pathWhy[id] = why
				}
			}
		default: // permission, same_account
			targets = nodes
		}
		if mo.verifiedOnly && r.VerifiedByEdge != nil {
			// Targets the verifying edge reaches (any confidence: the rule's own exact
			// evaluation may prove an edge the graph left inferred, see below).
			proven := map[string]bool{}
			for _, e := range g.Out(a.ID) {
				if e.Kind == r.VerifiedByEdge.Kind {
					proven[e.To] = true
				}
			}
			var keep []*graph.Node
			for _, t := range targets {
				if proven[t.ID] {
					keep = append(keep, t)
				}
			}
			targets = keep
		}
		for _, t := range targets {
			tWhy, ok := r.targetOK(g, a, t, account)
			if !ok {
				continue
			}
			because := []string{}
			if w := pathWhy[t.ID]; w != "" {
				because = append(because, "graph: "+w)
			}
			allExact := true
			denied := false
			for _, p := range r.Match.RequiresPermissions {
				res := expandResource(p.Resource, a, t, account)
				d := g.EvaluatePrincipalActionWith(a.ID, p.Action, res, r.requestContext(p))
				mfaNote := ""
				if d.Effect == iam.ExplicitDeny && d.Statement != "" {
					// A Deny that applies only to sessions without MFA (the "deny unless MFA"
					// guardrail) does not stop an MFA session: the grant stands, inferred.
					if why, ok := mfaOnlyDeny(g, d.DeniedBy); ok {
						d.Effect, mfaNote = iam.Unknown, "; only from an MFA session: "+why
					}
				}
				switch d.Effect {
				case iam.Allow:
					allExact = allExact && d.Exact
				case iam.Unknown:
					allExact = false
				default:
					denied = true
				}
				if denied {
					break
				}
				src := d.Statement
				if src == "" {
					src = "the principal's policies"
				}
				because = append(because, fmt.Sprintf("%s may %s on %s (%s by %s)%s", nodeLabel(a), p.Action, res, d.Effect, src, mfaNote))
			}
			if denied {
				continue
			}
			if tWhy != "" {
				because = append(because, tWhy)
			}
			if r.Match.Join == "same_account" {
				because = append(because, "same account (co-tenancy join): "+r.Justification)
			}
			conf := string(model.ConfidenceInferred)
			if r.VerifiedByEdge != nil {
				for _, e := range g.Out(a.ID) {
					if e.To != t.ID || e.Kind != r.VerifiedByEdge.Kind || conf == string(model.ConfidenceVerified) {
						continue
					}
					tech, _ := e.Attr[graph.AttrTechnique].(string)
					if r.VerifiedByEdge.Technique != "" && tech != r.VerifiedByEdge.Technique {
						continue
					}
					switch {
					case e.Confidence() == model.ConfidenceVerified:
						conf = string(model.ConfidenceVerified)
						because = append(because, fmt.Sprintf("graph edge %s (%s) proves it: %s", e.Kind, tech, e.Because()))
					case allExact && len(r.Match.RequiresPermissions) > 0:
						// The graph left the edge inferred on a condition the rule's own request
						// context settles (iam:PassedToService = the exploited service): every
						// permission is an exact Allow in that context.
						conf = string(model.ConfidenceVerified)
						because = append(because, fmt.Sprintf("graph edge %s (%s), confidence %s, proven by the rule's exact evaluation with %s", e.Kind, tech, e.Confidence(), r.contextText()))
					}
				}
			} else if r.Confidence == string(model.ConfidenceVerified) && allExact && len(r.Match.RequiresPermissions) > 0 {
				conf = string(model.ConfidenceVerified)
			}
			out = append(out, PathRuleMatch{RuleID: r.ID, Title: r.Title, Anchor: a.ID, Target: t.ID, Confidence: conf, Because: because, Credit: r.Credit})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Anchor != out[j].Anchor {
			return out[i].Anchor < out[j].Anchor
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// FixtureGraph builds the rule's test fixture and runs the permission pass over it, as the
// stored graph has had it run.
func (r PathRule) FixtureGraph() *graph.Graph {
	g := graph.New()
	for _, n := range r.Tests.Fixture.Nodes {
		g.AddNode(&graph.Node{ID: n.ID, Type: n.Type, Provider: "aws", Account: n.Account, Region: n.Region,
			Attributes: normaliseYAML(n.Attributes).(map[string]any), Weaknesses: n.Weaknesses})
	}
	for _, e := range r.Tests.Fixture.Edges {
		var attr map[string]any
		if e.Attr != nil {
			attr = normaliseYAML(e.Attr).(map[string]any)
		}
		g.AddEdge(e.From, e.To, e.Kind, attr)
	}
	g.EvaluatePermissions()
	return g
}

// normaliseYAML turns yaml.v3 values into the JSON-shaped values graph attributes carry.
func normaliseYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[k] = normaliseYAML(val)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = normaliseYAML(val)
		}
		return out
	case nil:
		return map[string]any{}
	}
	return v
}

// RunPathRuleTests runs the rule's own tests block against its fixture.
func RunPathRuleTests(r PathRule) error {
	if err := ValidatePathRules([]PathRule{r}); err != nil {
		return err
	}
	g := r.FixtureGraph()
	got := map[[2]string]PathRuleMatch{}
	for _, m := range MatchPathRule(g, r) {
		got[[2]string{m.Anchor, m.Target}] = m
	}
	var errs []string
	for _, e := range r.Tests.Expect {
		m, ok := got[[2]string{e.Anchor, e.Target}]
		switch {
		case e.Match && !ok:
			errs = append(errs, fmt.Sprintf("expected match %s -> %s, got none", e.Anchor, e.Target))
		case !e.Match && ok:
			errs = append(errs, fmt.Sprintf("expected no match %s -> %s, got one: %s", e.Anchor, e.Target, strings.Join(m.Because, "; ")))
		case ok && e.Confidence != "" && m.Confidence != e.Confidence:
			errs = append(errs, fmt.Sprintf("%s -> %s: confidence %s, want %s", e.Anchor, e.Target, m.Confidence, e.Confidence))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("path rule %s tests: %s", r.ID, strings.Join(errs, "; "))
	}
	return nil
}

// requestContext is the request context a rule knows for one permission check: iam:PassRole is
// evaluated with iam:PassedToService = the service the target role must trust (the service the
// rule exploits), so a PassRole conditioned on another service is refused (verification 7
// defect 5). nil when the rule names no service.
func (r PathRule) requestContext(p PathRulePermission) map[string]iam.ConditionValue {
	if svc := r.Match.Target.TrustsService; svc != "" && strings.EqualFold(p.Action, "iam:PassRole") {
		return map[string]iam.ConditionValue{"iam:PassedToService": {svc}}
	}
	return nil
}

func (r PathRule) contextText() string {
	if svc := r.Match.Target.TrustsService; svc != "" {
		return "iam:PassedToService=" + svc
	}
	return "the rule's context"
}
