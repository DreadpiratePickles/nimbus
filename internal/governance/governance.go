// Package governance assigns an owner and an SLA due date to every Issue
// (first-match YAML rules, owner from a tag, CODEOWNERS for IaC files, account
// owner, default) and computes MTTR / on-time / overdue metrics from the store's
// lifecycle history. It is pure: no I/O except LoadCodeowners, deterministic, and
// safe for concurrent use once the config has been validated. See docs/governance.md.
package governance

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Owner sources (store column owner_source).
const (
	SourceRule       = "rule"       // a rule's literal owner
	SourceTag        = "tag"        // a resource tag (a rule's tag:Key, or defaults.owner_tags)
	SourceCodeowners = "codeowners" // CODEOWNERS owner of the IaC file
	SourceAccount    = "account"    // accounts.<name>.owner in the config
	// SourceDefault: governance.defaults.owner, defaults.account_owners or defaults.provider_owners
	// — an owner by default, not from the resource (doctor and `issues metrics` count these as
	// "assigned by default", W6-POLISH r4 #5).
	SourceDefault    = "default"
	SourceUnassigned = "unassigned" // nobody: the Issue shows in the unassigned bucket
)

// Unassigned is the owner key used for Issues with no owner in grouped metrics/digests.
const Unassigned = "(unassigned)"

// Subject is what owner resolution looks at: one Issue (or finding).
type Subject struct {
	Provider     string
	Account      string
	ResourceID   string
	Name         string // resource name (name_regex); falls back to ResourceID
	Severity     model.Severity
	Tags         map[string]string // resource tags
	IaCPath      string            // repo-relative IaC file for IaC-origin findings ("" otherwise)
	OpenedAt     time.Time         // start of the current open episode (first_seen, or the last reopen)
	AccountOwner string            // accounts.<name>.owner, if any
}

// Assignment is the resolved owner and due date of one Issue.
type Assignment struct {
	Owner      string    `json:"owner"`
	Owners     []string  `json:"owners,omitempty"` // every CODEOWNERS owner; Owner is the first
	Source     string    `json:"owner_source"`
	RuleID     string    `json:"rule_id,omitempty"` // the matching governance rule ("" = none)
	SLADays    int       `json:"sla_days"`          // 0 = no SLA (INFO)
	GraceDays  int       `json:"grace_days"`
	DueAt      time.Time `json:"due_at"`      // zero when no SLA or no OpenedAt
	GraceUntil time.Time `json:"grace_until"` // DueAt + grace days
	Why        string    `json:"why"`         // human explanation of the chain that was followed
}

// Overdue reports an Issue past its due date (strictly after DueAt).
func (a Assignment) Overdue(now time.Time) bool { return !a.DueAt.IsZero() && now.After(a.DueAt) }

// PastGrace reports an Issue past its grace period (strictly after GraceUntil): the
// point at which it is escalated and counted as breached.
func (a Assignment) PastGrace(now time.Time) bool {
	return !a.GraceUntil.IsZero() && now.After(a.GraceUntil)
}

// OwnerKey is Owner, or Unassigned when empty (grouping key).
func (a Assignment) OwnerKey() string { return OwnerKey(a.Owner) }

// OwnerKey maps "" to Unassigned.
func OwnerKey(owner string) string {
	if strings.TrimSpace(owner) == "" {
		return Unassigned
	}
	return owner
}

// Resolver resolves Assignments from a governance config and an optional CODEOWNERS.
type Resolver struct {
	g  config.Governance
	co *Codeowners
}

// NewResolver builds a resolver. g should come from a validated config (rules are
// pre-compiled and carry ids); co may be nil.
func NewResolver(g config.Governance, co *Codeowners) *Resolver {
	rules := make([]config.GovernanceRule, len(g.Rules))
	copy(rules, g.Rules)
	for i := range rules {
		if rules[i].ID == "" {
			rules[i].ID = fmt.Sprintf("rule-%d", i+1)
		}
	}
	g.Rules = rules
	return &Resolver{g: g, co: co}
}

// Resolve is NewResolver(g, co).Resolve(s).
func Resolve(g config.Governance, co *Codeowners, s Subject) Assignment {
	return NewResolver(g, co).Resolve(s)
}

// Resolve assigns an owner and due date. Rules are evaluated in order and the first
// match wins; its owner is a literal (source rule), "tag:Key" (source tag) or
// "codeowners" (source codeowners). When the rule's owner cannot be resolved, or no
// rule matches, the fallback chain is: defaults.owner_tags (owner, team) → CODEOWNERS
// for the IaC file → account owner → defaults.owner → unassigned. SLA days come from
// the matched rule, then defaults.sla_days, then 7/14/30/90; grace from the rule, then
// defaults.grace_days. DueAt = OpenedAt + SLA days, GraceUntil = DueAt + grace days.
func (r *Resolver) Resolve(s Subject) Assignment {
	var a Assignment
	var why []string
	subj := config.GovernanceSubject{Provider: s.Provider, Account: s.Account, Name: s.name(), IaCPath: s.IaCPath, Tags: s.Tags}
	sla := r.g.SLA()
	grace := r.g.Defaults.GraceDays
	var rule *config.GovernanceRule
	for i := range r.g.Rules {
		if r.g.Rules[i].Match.Matches(subj) {
			rule = &r.g.Rules[i]
			break
		}
	}
	resolved := false
	if rule != nil {
		a.RuleID = rule.ID
		sla = rule.SLADays.WithFallback(sla)
		if rule.GraceDays != nil {
			grace = *rule.GraceDays
		}
		switch rule.OwnerKind() {
		case config.OwnerTag:
			key := rule.OwnerTag()
			if v, ok := tagValue(s.Tags, key); ok {
				a.Owner, a.Source, resolved = v, SourceTag, true
				why = append(why, fmt.Sprintf("rule %s: owner from tag %s", rule.ID, key))
			} else {
				why = append(why, fmt.Sprintf("rule %s: tag %s missing", rule.ID, key))
			}
		case config.OwnerCodeowners:
			if owners, line, ok := r.codeowners(s.IaCPath); ok {
				a.Owner, a.Owners, a.Source, resolved = owners[0], owners, SourceCodeowners, true
				why = append(why, fmt.Sprintf("rule %s: CODEOWNERS line %d for %s", rule.ID, line, config.CleanRepoPath(s.IaCPath)))
			} else {
				why = append(why, fmt.Sprintf("rule %s: no CODEOWNERS owner for %q", rule.ID, config.CleanRepoPath(s.IaCPath)))
			}
		default:
			a.Owner, a.Source, resolved = rule.Owner, SourceRule, true
			why = append(why, fmt.Sprintf("rule %s", rule.ID))
		}
	} else {
		why = append(why, "no rule matched")
	}
	if !resolved {
		r.fallback(s, &a, &why)
	}

	a.SLADays = sla.For(string(s.Severity))
	a.GraceDays = grace
	if a.SLADays > 0 && !s.OpenedAt.IsZero() {
		a.DueAt = s.OpenedAt.Add(days(a.SLADays))
		a.GraceUntil = a.DueAt.Add(days(grace))
		why = append(why, fmt.Sprintf("%s SLA %dd (+%dd grace)", strings.ToUpper(string(s.Severity)), a.SLADays, grace))
	} else if a.SLADays == 0 {
		why = append(why, "no SLA for severity "+string(s.Severity))
	}
	a.Why = strings.Join(why, "; ")
	return a
}

func (r *Resolver) fallback(s Subject, a *Assignment, why *[]string) {
	for _, k := range r.g.Defaults.OwnerTagsOrDefault() {
		if v, ok := tagValue(s.Tags, k); ok {
			a.Owner, a.Source = v, SourceTag
			*why = append(*why, "owner from tag "+k)
			return
		}
	}
	if owners, line, ok := r.codeowners(s.IaCPath); ok {
		a.Owner, a.Owners, a.Source = owners[0], owners, SourceCodeowners
		*why = append(*why, fmt.Sprintf("CODEOWNERS line %d for %s", line, config.CleanRepoPath(s.IaCPath)))
		return
	}
	if o := strings.TrimSpace(s.AccountOwner); o != "" {
		a.Owner, a.Source = o, SourceAccount
		*why = append(*why, "account owner")
		return
	}
	if o, key := r.g.Defaults.AccountOwner(s.Provider, s.Account); o != "" {
		a.Owner, a.Source = o, SourceDefault
		*why = append(*why, "default account owner (defaults."+key+")")
		return
	}
	if o := strings.TrimSpace(r.g.Defaults.Owner); o != "" {
		a.Owner, a.Source = o, SourceDefault
		*why = append(*why, "default owner")
		return
	}
	a.Source = SourceUnassigned
	*why = append(*why, "unassigned")
}

func (r *Resolver) codeowners(iacPath string) ([]string, int, bool) {
	if r.co == nil || strings.TrimSpace(iacPath) == "" {
		return nil, 0, false
	}
	m, ok := r.co.Match(iacPath)
	if !ok || len(m.Owners) == 0 {
		return nil, 0, false
	}
	return append([]string(nil), m.Owners...), m.Line, true
}

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func (s Subject) name() string {
	if s.Name != "" {
		return s.Name
	}
	return s.ResourceID
}

// tagValue looks a tag up exactly, then case-insensitively (lowest key first, so the
// result is deterministic); blank values count as missing.
func tagValue(tags map[string]string, key string) (string, bool) {
	if v, ok := tags[key]; ok {
		if v = strings.TrimSpace(v); v != "" {
			return v, true
		}
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, key) {
			if v := strings.TrimSpace(tags[k]); v != "" {
				return v, true
			}
		}
	}
	return "", false
}

// SubjectFromFinding builds a subject from one finding: resource tags
// (attributes.tags) win over finding tags; the IaC path is the finding's file.
func SubjectFromFinding(f model.Finding) Subject {
	s := Subject{Provider: f.Provider, Account: f.Account, ResourceID: f.Resource.ID, Name: f.Resource.Name,
		Severity: f.Severity, OpenedAt: f.FirstSeen, IaCPath: config.CleanRepoPath(f.File)}
	s.Tags = mergeTags(nil, f)
	return s
}

// mergeTags adds f's resource tags, then its finding tags, never overwriting a key
// already present (so the first source wins).
func mergeTags(dst map[string]string, f model.Finding) map[string]string {
	if dst == nil {
		dst = map[string]string{}
	}
	put := func(k, v string) {
		if _, ok := dst[k]; !ok {
			dst[k] = v
		}
	}
	switch t := f.Resource.Attributes["tags"].(type) {
	case map[string]any:
		for k, v := range t {
			put(k, fmt.Sprint(v))
		}
	case map[string]string:
		for k, v := range t {
			put(k, v)
		}
	}
	for k, v := range f.Tags {
		put(k, v)
	}
	return dst
}

// SubjectFromIssue builds a subject from an Issue and its evidence findings
// (store.Findings for is.FindingIDs). Identity, severity and opened-at come from the
// Issue; name, tags and IaC path from the evidence, lowest finding id first. Path
// Issues have no evidence findings: set Tags/Name from the anchor node yourself.
func SubjectFromIssue(is model.Issue, evidence []model.Finding) Subject {
	s := Subject{Provider: is.Provider, Account: is.Account, ResourceID: is.ResourceID, Severity: is.Severity, OpenedAt: is.FirstSeen}
	ev := append([]model.Finding(nil), evidence...)
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].ID < ev[j].ID })
	for _, f := range ev {
		if s.Name == "" && f.Resource.Name != "" {
			s.Name = f.Resource.Name
		}
		if s.IaCPath == "" && f.File != "" {
			s.IaCPath = config.CleanRepoPath(f.File)
		}
		s.Tags = mergeTags(s.Tags, f)
	}
	if s.Name == "" {
		s.Name = is.ResourceID
	}
	if len(s.Tags) == 0 {
		s.Tags = nil
	}
	return s
}
