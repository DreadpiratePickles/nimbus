package model

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"time"
)

// Issue kinds.
const (
	IssueSingle      = "single"      // one canonical check on one resource
	IssueCombination = "combination" // a declared toxic combination of weaknesses on one resource
	IssuePath        = "path"        // an entry → anchor attack path (hop lists are evidence)
	IssueChokepoint  = "chokepoint"  // reserved (migration 6): a node many path Issues cross
	IssueCorrelated  = "correlated"  // reserved (migration 6): runtime/threat signal on a path
)

// IssueKinds is the vocabulary the issues.kind CHECK constraint accepts (migration 6).
var IssueKinds = []string{IssueSingle, IssueCombination, IssuePath, IssueChokepoint, IssueCorrelated}

// StateSuppressed is an accepted risk: it needs a reason and an expiry, and the Issue is
// reopened automatically once the expiry passes and the problem is still observed.
const StateSuppressed = "suppressed"

// Closure states (W5-ISSUES, r3 #3). verified_fixed is terminal: a confirmed fix
// (`cloud-posture verify`) that later rebuilds keep while the problem stays absent and turn
// into reopened (flagged regressed_after_verify) when the same finding / path is observed again.
// pending_verification is "a fix was merged or applied; not yet confirmed": the next scan or
// `verify` settles it (absent ⇒ resolved, present ⇒ open, verify ⇒ verified_fixed). Neither is
// active (IsActive), so neither is overdue or in the open queue.
const (
	StateVerifiedFixed       = "verified_fixed"
	StatePendingVerification = "pending_verification"
)

// IssueStates is the Issue state vocabulary, in lifecycle order.
var IssueStates = []string{StateOpen, StateReopened, StatePendingVerification, StateVerifiedFixed, StateResolved, StateSuppressed}

// Path Issue identity (plan v3 AP3 / council decision 2): id = sha256(kind|entry|anchor|rule).
const (
	// PathRuleTraversal is the rule of every path the graph traversal emits (RuleID
	// GRAPH_TRAVERSAL or empty); rule-chain paths keep their own rule id.
	PathRuleTraversal = "traversal"
	// PathEntryInternet is the entry of a path that starts on the internet (graph.InternetNodeID).
	PathEntryInternet = "internet"
)

// ConditionSensitive is the pseudo-weakness a toxic combination uses for "the resource
// holds sensitive data" (graph crown-jewel flag, or a finding carrying this weakness).
const ConditionSensitive = "SENSITIVE_DATA"

// Issue is the unit dashboards, alerts and counts should use: one per
// (canonical_id, resource), with every tool's findings attached as evidence.
type Issue struct {
	ID          string     `json:"id"`
	CanonicalID string     `json:"canonical_id"`
	ResourceID  string     `json:"resource_id"`
	Provider    string     `json:"provider"`
	Account     string     `json:"account"`
	Severity    Severity   `json:"severity"`
	State       string     `json:"state"`
	Kind        string     `json:"kind"`
	Title       string     `json:"title,omitempty"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
	FindingIDs  []string   `json:"finding_ids"`
	Sources     []string   `json:"sources"`
	Confidence  float64    `json:"confidence"`

	// Path Issue fields (kind path; zero for single/combination). EntryID, AnchorID and RuleID
	// are the identity; SecondaryKey is PathSecondaryKey of the highest-scoring path (the full
	// hop list), SecondaryKeys all of them; Score is the max over the Issue's paths.
	EntryID          string            `json:"entry_id,omitempty"`
	AnchorID         string            `json:"anchor_id,omitempty"`
	RuleID           string            `json:"rule_id,omitempty"`
	SecondaryKey     string            `json:"secondary_key,omitempty"`
	SecondaryKeys    []string          `json:"secondary_keys,omitempty"`
	PathIDs          []string          `json:"path_ids,omitempty"` // traversal path ids (attack_paths.id)
	Score            float64           `json:"score,omitempty"`
	Band             string            `json:"band,omitempty"`
	ConfidenceLabel  Confidence        `json:"confidence_label,omitempty"` // weakest-edge confidence of the best path
	Validation       *ValidationResult `json:"validation,omitempty"`
	WeakLink         bool              `json:"weak_link,omitempty"`
	ToxicCombination string            `json:"toxic_combination,omitempty"`

	// Suppression (state suppressed) and verification; any kind.
	Reason     string     `json:"reason,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ApprovedBy string     `json:"approved_by,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	VerifiedBy string     `json:"verified_by,omitempty"`
	// PendingAt / PendingBy: when and by what (a fix PR, `issues mark-pending`) the Issue was
	// moved to pending_verification. RegressedAfterVerify: the Issue was verified_fixed and the
	// same problem was observed again (sticky until it is verified again).
	PendingAt            *time.Time `json:"pending_at,omitempty"`
	PendingBy            string     `json:"pending_by,omitempty"`
	RegressedAfterVerify bool       `json:"regressed_after_verify,omitempty"`

	// Governance (store migration 7; docs/governance.md): who must act and by when, resolved
	// on every scan/ingest/prioritize from the governance rules, tags, CODEOWNERS, account
	// owner and defaults. DueAt is the one due date every output shows (nil = no SLA).
	Owner       string     `json:"owner,omitempty"`
	OwnerSource string     `json:"owner_source,omitempty"` // rule | tag | codeowners | account | default | unassigned
	OwnerRule   string     `json:"owner_rule,omitempty"`   // matching governance rule id
	OwnerWhy    string     `json:"owner_why,omitempty"`    // the resolution trail
	SLADays     int        `json:"sla_days,omitempty"`
	DueAt       *time.Time `json:"due_at,omitempty"`
	GraceUntil  *time.Time `json:"grace_until,omitempty"`
	// Overdue is computed when the Issue is read: open/reopened and strictly past DueAt.
	// Suppressed and resolved Issues are never overdue.
	Overdue bool `json:"overdue"`

	// Ticket: the one external ticket opened for this Issue (Jira / GitHub Issues).
	TicketSink  string `json:"ticket_sink,omitempty"`
	TicketKey   string `json:"ticket_key,omitempty"`
	TicketURL   string `json:"ticket_url,omitempty"`
	TicketState string `json:"ticket_state,omitempty"` // open | closed (as nimbus last set it)
}

// IsOverdue reports an active Issue strictly past its due date at now.
func (is Issue) IsOverdue(now time.Time) bool {
	return is.DueAt != nil && IsActive(is.State) && now.After(*is.DueAt)
}

// PathIssueID is the stable id of a path-level Issue: hex(sha256(kind|entry|anchor|rule)[:16]).
// The anchor is the impact node (the path's last hop); middle hops are evidence and change
// only the secondary key, so a re-routed path keeps its Issue.
func PathIssueID(kind, entry, anchor, rule string) string {
	sum := sha256.Sum256([]byte(kind + "|" + entry + "|" + anchor + "|" + rule))
	return hex.EncodeToString(sum[:16])
}

// PathIssueKey derives (entry, anchor, rule) from a path: the entry is the identity of an
// identity/SaaS entry step (relation "entry"), otherwise the internet; the anchor is the
// last hop's resource; the rule is the path's rule id, with traversal paths mapped to
// PathRuleTraversal.
func PathIssueKey(p AttackPath) (entry, anchor, rule string) {
	entry = PathEntryInternet
	if len(p.Steps) > 0 {
		if p.Steps[0].Relation == "entry" {
			entry = p.Steps[0].Resource
		}
		anchor = p.Steps[len(p.Steps)-1].Resource
	}
	rule = p.RuleID
	if rule == "" || rule == "GRAPH_TRAVERSAL" {
		rule = PathRuleTraversal
	}
	return entry, anchor, rule
}

// PathSecondaryKey hashes the full hop list (entry, rule and every hop's resource in order):
// it changes when any hop changes, which the Issue id deliberately does not.
func PathSecondaryKey(p AttackPath) string {
	entry, _, rule := PathIssueKey(p)
	hops := make([]string, len(p.Steps))
	for i, s := range p.Steps {
		hops[i] = s.Resource
	}
	sum := sha256.Sum256([]byte(entry + "|" + rule + "|" + strings.Join(hops, ">")))
	return hex.EncodeToString(sum[:16])
}

// PathConfidence is the weakest edge confidence on the path (steps carrying an "edge" in
// their evidence; an entry step is the credential itself and has no edge). An edge without a
// confidence label is not proven, so it counts as inferred; a path with no edges is inferred.
func PathConfidence(p AttackPath) Confidence {
	rank := map[Confidence]int{ConfidenceVerified: 0, ConfidenceInferred: 1, ConfidenceHint: 2}
	worst, seen := ConfidenceVerified, false
	for _, s := range p.Steps {
		if _, ok := s.Evidence["edge"]; !ok {
			continue
		}
		seen = true
		c := ConfidenceInferred
		if v, ok := s.Evidence[AttrConfidence].(string); ok && Confidence(v).Valid() {
			c = Confidence(v)
		}
		if rank[c] > rank[worst] {
			worst = c
		}
	}
	if !seen {
		return ConfidenceInferred
	}
	return worst
}

// ScoreBand maps a 0–10 score to its band; same thresholds as risk.BandFor (docs/scoring.md):
// Critical ≥ 9, High ≥ 7, Medium ≥ 5, Low < 5.
func ScoreBand(score float64) string {
	switch {
	case score >= 9:
		return "Critical"
	case score >= 7:
		return "High"
	case score >= 5:
		return "Medium"
	default:
		return "Low"
	}
}

// ToxicCombination is a declared set of weaknesses that is far worse together on one
// resource than any one alone (Wiz-style "toxic combination").
type ToxicCombination struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	AllOf    []string `json:"all_of"`
}

// ToxicCombinations is the declared list evaluated per resource.
var ToxicCombinations = []ToxicCombination{
	{ID: "TOXIC_PUBLIC_UNENCRYPTED_SENSITIVE", Title: "Public, unencrypted data store holding sensitive data", Severity: Critical,
		AllOf: []string{"PUBLIC_DATA_STORE", "UNENCRYPTED_AT_REST", ConditionSensitive}},
	{ID: "TOXIC_PUBLIC_ADMIN", Title: "Internet-exposed workload with an administrative identity", Severity: Critical,
		AllOf: []string{"PUBLIC_NETWORK_EXPOSURE", "OVERPRIVILEGED_IDENTITY"}},
	{ID: "TOXIC_NO_MFA_ADMIN", Title: "Administrative identity without MFA", Severity: Critical,
		AllOf: []string{"NO_MFA", "OVERPRIVILEGED_IDENTITY"}},
}

// IssueConfidence rises with the number of independent sources that agree:
// 1 source 0.70, 2 sources 0.91, 3 sources 0.97 (1 - 0.3^n), rounded to 2 places.
func IssueConfidence(sources int) float64 {
	if sources <= 0 {
		return 0
	}
	return math.Round((1-math.Pow(0.3, float64(sources)))*100) / 100
}

// PathNode is what PathIssueTitle needs to know about a hop's resource.
type PathNode struct {
	Name  string
	Attrs map[string]any
}

// entryVerb names how an identity / SaaS entry is taken over, from the entry hop's weakness.
func entryVerb(weakness string) string {
	switch weakness {
	case "CROSS_ACCOUNT_TRUST":
		return "external trust abuse of"
	case "BRANCH_UNPROTECTED", "CI_SECRET_EXPOSED", "WORKFLOW_INJECTION":
		return "pipeline compromise of"
	}
	return "credential compromise of"
}

// privilegeLabel is the most privileged attached policy / role of a node ("AdministratorAccess"),
// or "" when the node carries none.
func privilegeLabel(attrs map[string]any) string {
	var names []string
	for _, k := range []string{"attached_policies", "managed_policies", "roles", "role"} {
		switch v := attrs[k].(type) {
		case string:
			names = append(names, v)
		case []string:
			names = append(names, v...)
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					names = append(names, s)
				}
			}
		}
	}
	rank := func(n string) int {
		l := strings.ToLower(n)
		switch {
		case l == "administratoraccess" || l == "owner" || strings.HasSuffix(l, "cluster-admin"):
			return 4
		case strings.HasSuffix(l, "fullaccess") || l == "poweruseraccess" || l == "editor" || l == "contributor":
			return 3
		case strings.Contains(l, "write") || strings.Contains(l, "admin"):
			return 2
		}
		return 1
	}
	best, bestRank := "", 0
	for _, n := range names {
		base := n
		if i := strings.LastIndexAny(base, "/:"); i >= 0 {
			base = base[i+1:]
		}
		if base == "" {
			continue
		}
		if r := rank(base); r > bestRank {
			best, bestRank = base, r
		}
	}
	return best
}

// PathIssueTitle is the title of a path Issue (W5-ISSUES item 2, r3 E7). A traversal path that
// starts at an identity / SaaS entry (relation "entry") reads "<how> <entry> → <what it reaches>":
// "credential compromise of ops-jane → AdministratorAccess" when the entry is itself the impact
// (its own privileges), "credential compromise of dev-sam → ec2-admin (AdministratorAccess)" when
// it reaches another identity. Internet paths and rule chains keep the engine's name. lookup
// may be nil (names fall back to the last segment of the id).
func PathIssueTitle(p AttackPath, lookup func(id string) (PathNode, bool)) string {
	if len(p.Steps) == 0 || p.Steps[0].Relation != "entry" || (p.RuleID != "" && p.RuleID != "GRAPH_TRAVERSAL") {
		return p.Name
	}
	node := func(id string) PathNode {
		if lookup != nil {
			if n, ok := lookup(id); ok {
				if n.Name == "" {
					n.Name = shortID(id)
				}
				return n
			}
		}
		return PathNode{Name: shortID(id)}
	}
	first, last := p.Steps[0], p.Steps[len(p.Steps)-1]
	en := node(first.Resource)
	verb := entryVerb(first.Weakness)
	if last.Resource == first.Resource {
		target := privilegeLabel(en.Attrs)
		if target == "" {
			target = "its own permissions"
		}
		return verb + " " + en.Name + " → " + target
	}
	an := node(last.Resource)
	target := an.Name
	if pl := privilegeLabel(an.Attrs); pl != "" && pl != an.Name {
		target += " (" + pl + ")"
	}
	return verb + " " + en.Name + " → " + target
}

func shortID(id string) string {
	if i := strings.LastIndexAny(id, "/:"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}
