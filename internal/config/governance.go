package config

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Governance sentinels (match with errors.Is).
var (
	ErrInvalidOwner    = errors.New("invalid governance owner")
	ErrInvalidSLA      = errors.New("invalid SLA days")
	ErrInvalidGlob     = errors.New("invalid glob pattern")
	ErrInvalidDigest   = errors.New("invalid digest setting")
	ErrDuplicateRuleID = errors.New("duplicate governance rule id")
)

// MaxGovernanceRules caps governance.rules; extra rules are dropped with a warning.
const MaxGovernanceRules = 500

// MaxSLADays bounds any sla_days / grace_days value (ten years).
const MaxSLADays = 3650

// Owner kinds of a governance rule's owner field.
const (
	OwnerLiteral    = "literal"    // team@example.com, @org/team, payments-oncall
	OwnerTag        = "tag"        // "tag:<Key>": the resource's tag value
	OwnerCodeowners = "codeowners" // CODEOWNERS owner of the finding's IaC file
)

// SLADays is a remediation window in days per severity; 0 means "inherit".
type SLADays struct {
	Critical int `yaml:"critical,omitempty" json:"critical,omitempty"`
	High     int `yaml:"high,omitempty" json:"high,omitempty"`
	Medium   int `yaml:"medium,omitempty" json:"medium,omitempty"`
	Low      int `yaml:"low,omitempty" json:"low,omitempty"`
}

// DefaultSLADays are the built-in windows (Microsoft Defender CSPM governance
// presets): critical 7, high 14, medium 30, low 90 days.
var DefaultSLADays = SLADays{Critical: 7, High: 14, Medium: 30, Low: 90}

// WithFallback fills every zero field from fb.
func (s SLADays) WithFallback(fb SLADays) SLADays {
	if s.Critical == 0 {
		s.Critical = fb.Critical
	}
	if s.High == 0 {
		s.High = fb.High
	}
	if s.Medium == 0 {
		s.Medium = fb.Medium
	}
	if s.Low == 0 {
		s.Low = fb.Low
	}
	return s
}

// For returns the window for a severity (CRITICAL/HIGH/MEDIUM/LOW, any case); INFO
// and unknown severities have no SLA (0).
func (s SLADays) For(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return s.Critical
	case "HIGH":
		return s.High
	case "MEDIUM":
		return s.Medium
	case "LOW":
		return s.Low
	}
	return 0
}

// GovernanceMatch selects Issues/findings. Every selector that is set must match
// (AND). provider and account are case-insensitive globs; tag values match
// case-insensitively and "*" means "tag present"; name_regex matches the resource
// name; iac_path_glob matches the repo-relative IaC file (** crosses directories).
type GovernanceMatch struct {
	Provider    string            `yaml:"provider,omitempty"`
	Account     string            `yaml:"account,omitempty"`
	Tag         map[string]string `yaml:"tag,omitempty"`
	NameRegex   string            `yaml:"name_regex,omitempty"`
	IaCPathGlob string            `yaml:"iac_path_glob,omitempty"`

	providerRe, accountRe, nameRe, iacRe *regexp.Regexp
}

// Empty reports a match with no selector.
func (m GovernanceMatch) Empty() bool {
	return m.Provider == "" && m.Account == "" && len(m.Tag) == 0 && m.NameRegex == "" && m.IaCPathGlob == ""
}

// GovernanceRule assigns an owner and SLA to what it matches; rules are evaluated
// in order and the first match wins.
type GovernanceRule struct {
	ID        string          `yaml:"id,omitempty"`
	Match     GovernanceMatch `yaml:"match"`
	Owner     string          `yaml:"owner"`
	SLADays   SLADays         `yaml:"sla_days,omitempty"`
	GraceDays *int            `yaml:"grace_days,omitempty"`
}

// OwnerKind classifies Owner: OwnerTag ("tag:Key"), OwnerCodeowners ("codeowners")
// or OwnerLiteral.
func (r GovernanceRule) OwnerKind() string {
	o := strings.TrimSpace(r.Owner)
	switch {
	case strings.EqualFold(o, "codeowners"):
		return OwnerCodeowners
	case len(o) >= 4 && strings.EqualFold(o[:4], "tag:"):
		return OwnerTag
	}
	return OwnerLiteral
}

// OwnerTag is the tag key of a "tag:Key" owner ("" otherwise).
func (r GovernanceRule) OwnerTag() string {
	if r.OwnerKind() != OwnerTag {
		return ""
	}
	return strings.TrimSpace(strings.TrimSpace(r.Owner)[4:])
}

// GovernanceDefaults apply when no rule matches, and fill what a matching rule leaves unset.
type GovernanceDefaults struct {
	Owner     string   `yaml:"owner,omitempty"`
	OwnerTags []string `yaml:"owner_tags,omitempty"` // tag keys tried when no rule matches; default [owner, team]
	SLADays   SLADays  `yaml:"sla_days,omitempty"`
	GraceDays int      `yaml:"grace_days,omitempty"`
	// AccountOwners / ProviderOwners route an Issue nothing else assigns (no rule, tag or
	// CODEOWNERS owner, no accounts.<name>.owner) to its account's owner — keyed
	// "provider/account" or "account" — then to its provider's, before Owner (W5-ISSUES).
	AccountOwners  map[string]string `yaml:"account_owners,omitempty"`
	ProviderOwners map[string]string `yaml:"provider_owners,omitempty"`
	// MinOwnerShare is the share of the tagged resources (in (0, 1], default 0.5) an owner tag
	// value needs before `governance init` proposes it as defaults.owner, an account owner or a
	// provider owner; a tie never proposes one (W6-POLISH, r4 #5).
	MinOwnerShare *float64 `yaml:"min_owner_share,omitempty"`
}

// DefaultMinOwnerShare is governance.defaults.min_owner_share when unset.
const DefaultMinOwnerShare = 0.5

// MinOwnerShareOrDefault is MinOwnerShare, or DefaultMinOwnerShare when unset.
func (d GovernanceDefaults) MinOwnerShareOrDefault() float64 {
	if d.MinOwnerShare == nil {
		return DefaultMinOwnerShare
	}
	return *d.MinOwnerShare
}

// AccountOwner is the defaults.account_owners / provider_owners owner of provider/account and
// the key that matched ("" when none). Keys match case-insensitively.
func (d GovernanceDefaults) AccountOwner(provider, account string) (owner, key string) {
	look := func(m map[string]string, k string) (string, string) {
		if k == "" || k == "/" {
			return "", ""
		}
		if v, ok := m[k]; ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v), k
		}
		keys := make([]string, 0, len(m))
		for x := range m {
			keys = append(keys, x)
		}
		sort.Strings(keys)
		for _, x := range keys {
			if strings.EqualFold(x, k) && strings.TrimSpace(m[x]) != "" {
				return strings.TrimSpace(m[x]), x
			}
		}
		return "", ""
	}
	if account != "" {
		if o, k := look(d.AccountOwners, provider+"/"+account); o != "" {
			return o, "account_owners " + k
		}
		if o, k := look(d.AccountOwners, account); o != "" {
			return o, "account_owners " + k
		}
	}
	if o, k := look(d.ProviderOwners, provider); o != "" {
		return o, "provider_owners " + k
	}
	return "", ""
}

// DefaultOwnerTags are the tag keys consulted when no rule matches.
var DefaultOwnerTags = []string{"owner", "team"}

// OwnerTagsOrDefault returns OwnerTags, or DefaultOwnerTags when unset.
func (d GovernanceDefaults) OwnerTagsOrDefault() []string {
	if len(d.OwnerTags) == 0 {
		return DefaultOwnerTags
	}
	return d.OwnerTags
}

// DigestConfig controls the per-owner digest (`alert --digest`).
type DigestConfig struct {
	Schedule string `yaml:"schedule,omitempty"` // weekly (default) | daily
	Sink     string `yaml:"sink,omitempty"`     // slack | teams | email | webhook | stdout
	GroupBy  string `yaml:"group_by,omitempty"` // owner (default) | account
	Window   string `yaml:"dedup_window,omitempty"`
	// UnassignedSink receives the "(unassigned)" digest instead of Sink (a security triage
	// channel), so Issues nobody owns still reach a person.
	UnassignedSink string `yaml:"unassigned_sink,omitempty"`
}

// DigestSinks are the accepted digest.sink values.
var DigestSinks = []string{"slack", "teams", "email", "webhook", "stdout"}

// ScheduleOrDefault is the schedule, weekly when unset.
func (d DigestConfig) ScheduleOrDefault() string {
	if s := strings.ToLower(strings.TrimSpace(d.Schedule)); s != "" {
		return s
	}
	return "weekly"
}

// GroupByOrDefault is group_by, owner when unset.
func (d DigestConfig) GroupByOrDefault() string {
	if s := strings.ToLower(strings.TrimSpace(d.GroupBy)); s != "" {
		return s
	}
	return "owner"
}

// Period is the schedule period (7 days weekly, 24h daily).
func (d DigestConfig) Period() time.Duration {
	if d.ScheduleOrDefault() == "daily" {
		return 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}

// DedupWindow is how long an unchanged digest is not re-sent (default: the period).
func (d DigestConfig) DedupWindow() time.Duration {
	if v := strings.TrimSpace(d.Window); v != "" {
		if w, err := time.ParseDuration(v); err == nil && w > 0 {
			return w
		}
	}
	return d.Period()
}

// Governance is the governance: block — owners, SLAs and digests for Issues.
type Governance struct {
	Rules          []GovernanceRule   `yaml:"rules,omitempty"`
	Defaults       GovernanceDefaults `yaml:"defaults,omitempty"`
	Digest         DigestConfig       `yaml:"digest,omitempty"`
	CodeownersFile string             `yaml:"codeowners_file,omitempty"` // default: .github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS
}

// Enabled reports whether the block configures anything.
func (g Governance) Enabled() bool {
	return len(g.Rules) > 0 || g.Defaults.Owner != "" || len(g.Defaults.OwnerTags) > 0 || len(g.Defaults.AccountOwners) > 0 || len(g.Defaults.ProviderOwners) > 0 ||
		g.Defaults.SLADays != (SLADays{}) || g.Defaults.GraceDays != 0 || g.Digest != (DigestConfig{}) || g.CodeownersFile != ""
}

// SLA is the effective SLA table of the defaults (built-ins fill unset severities).
func (g Governance) SLA() SLADays { return g.Defaults.SLADays.WithFallback(DefaultSLADays) }

// GovernanceSubject is what a governance match looks at.
type GovernanceSubject struct {
	Provider, Account, Name, IaCPath string
	Tags                             map[string]string
}

// Matches reports whether every configured selector matches s. Rules from a
// validated config are pre-compiled; others compile lazily (a bad pattern never matches).
func (m *GovernanceMatch) Matches(s GovernanceSubject) bool {
	if m.Empty() {
		return false
	}
	if m.Provider != "" && !globFold(&m.providerRe, m.Provider, s.Provider) {
		return false
	}
	if m.Account != "" && !globFold(&m.accountRe, m.Account, s.Account) {
		return false
	}
	for _, k := range sortedKeys(m.Tag) {
		want := m.Tag[k]
		got, ok := lookupFold(s.Tags, k)
		if !ok || (strings.TrimSpace(want) != "*" && !strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(want))) {
			return false
		}
	}
	if m.NameRegex != "" {
		if m.nameRe == nil {
			re, err := regexp.Compile(m.NameRegex)
			if err != nil {
				return false
			}
			m.nameRe = re
		}
		if !m.nameRe.MatchString(s.Name) {
			return false
		}
	}
	if m.IaCPathGlob != "" {
		p := CleanRepoPath(s.IaCPath)
		if p == "" {
			return false
		}
		if m.iacRe == nil {
			re, err := CompileGlob(CleanRepoPath(m.IaCPathGlob))
			if err != nil {
				return false
			}
			m.iacRe = re
		}
		if !m.iacRe.MatchString(p) {
			return false
		}
	}
	return true
}

func globFold(cache **regexp.Regexp, pattern, v string) bool {
	if *cache == nil {
		re, err := CompileGlob(strings.ToLower(pattern))
		if err != nil {
			return false
		}
		*cache = re
	}
	return (*cache).MatchString(strings.ToLower(v))
}

// CleanRepoPath normalises a repo-relative path: forward slashes, no leading "./" or "/".
func CleanRepoPath(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return strings.TrimLeft(p, "/")
}

// CompileGlob compiles a path glob to an anchored regexp: "**" matches across
// directories ("**/" also matches zero directories), "*" and "?" stay within one
// path segment, "[...]" is a character class (a leading "!" negates).
func CompileGlob(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				i++
				if i+1 < len(glob) && glob[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			j := strings.IndexByte(glob[i+1:], ']')
			if j < 0 {
				return nil, fmt.Errorf("%q: unclosed character class", glob)
			}
			class := glob[i+1 : i+1+j]
			if class == "" {
				return nil, fmt.Errorf("%q: empty character class", glob)
			}
			neg := false
			if class[0] == '!' || class[0] == '^' {
				neg, class = true, class[1:]
			}
			b.WriteString("[")
			if neg {
				b.WriteString("^")
			}
			b.WriteString(strings.ReplaceAll(strings.ReplaceAll(class, `\`, `\\`), "[", `\[`))
			b.WriteString("]")
			i += j + 1
		case '\\':
			if i+1 < len(glob) {
				i++
				b.WriteString(regexp.QuoteMeta(string(glob[i])))
			} else {
				b.WriteString(`\\`)
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// validateGovernance checks and normalises the governance block (assigns positional
// rule ids "rule-N", compiles patterns, caps the rule count).
func (c *Config) validateGovernance(add func(field string, sentinel error, format string, args ...any)) {
	g := &c.Governance
	if len(g.Rules) > MaxGovernanceRules {
		c.warnings = append(c.warnings, fmt.Sprintf("governance.rules has %d rules; only the first %d are used", len(g.Rules), MaxGovernanceRules))
		g.Rules = g.Rules[:MaxGovernanceRules]
	}
	checkSLA := func(field string, s SLADays) {
		for _, kv := range []struct {
			k string
			v int
		}{{"critical", s.Critical}, {"high", s.High}, {"medium", s.Medium}, {"low", s.Low}} {
			if kv.v < 0 || kv.v > MaxSLADays {
				add(field+"."+kv.k, ErrInvalidSLA, "%d must be between 0 (inherit) and %d days", kv.v, MaxSLADays)
			}
		}
	}
	ids := map[string]int{}
	for i := range g.Rules {
		r := &g.Rules[i]
		field := fmt.Sprintf("governance.rules[%d]", i)
		r.ID = strings.TrimSpace(r.ID)
		if r.ID == "" {
			r.ID = fmt.Sprintf("rule-%d", i+1)
		}
		if j, dup := ids[r.ID]; dup {
			add(field+".id", ErrDuplicateRuleID, "%q is already used by governance.rules[%d]", r.ID, j)
		} else {
			ids[r.ID] = i
		}
		r.Owner = strings.TrimSpace(r.Owner)
		switch {
		case r.Owner == "":
			add(field+".owner", ErrInvalidOwner, "set an owner: an address or team, \"tag:<Key>\" or \"codeowners\"")
		case r.OwnerKind() == OwnerTag && r.OwnerTag() == "":
			add(field+".owner", ErrInvalidOwner, "%q needs a tag key, e.g. tag:Owner", r.Owner)
		case strings.ContainsAny(r.Owner, "\n\t"):
			add(field+".owner", ErrInvalidOwner, "owner must be a single line")
		}
		m := &r.Match
		if m.Empty() {
			add(field+".match", ErrEmptySelector, "set at least one of provider, account, tag, name_regex, iac_path_glob")
		}
		if m.Provider != "" {
			if re, err := CompileGlob(strings.ToLower(m.Provider)); err != nil {
				add(field+".match.provider", ErrInvalidGlob, "%v", err)
			} else {
				m.providerRe = re
			}
		}
		if m.Account != "" {
			if re, err := CompileGlob(strings.ToLower(m.Account)); err != nil {
				add(field+".match.account", ErrInvalidGlob, "%v", err)
			} else {
				m.accountRe = re
			}
		}
		if m.NameRegex != "" {
			if re, err := regexp.Compile(m.NameRegex); err != nil {
				add(field+".match.name_regex", ErrInvalidRegex, "%v", err)
			} else {
				m.nameRe = re
			}
		}
		if m.IaCPathGlob != "" {
			if re, err := CompileGlob(CleanRepoPath(m.IaCPathGlob)); err != nil {
				add(field+".match.iac_path_glob", ErrInvalidGlob, "%v", err)
			} else {
				m.iacRe = re
			}
		}
		checkSLA(field+".sla_days", r.SLADays)
		if r.GraceDays != nil && (*r.GraceDays < 0 || *r.GraceDays > MaxSLADays) {
			add(field+".grace_days", ErrInvalidSLA, "%d must be between 0 and %d days", *r.GraceDays, MaxSLADays)
		}
	}
	checkSLA("governance.defaults.sla_days", g.Defaults.SLADays)
	if g.Defaults.GraceDays < 0 || g.Defaults.GraceDays > MaxSLADays {
		add("governance.defaults.grace_days", ErrInvalidSLA, "%d must be between 0 and %d days", g.Defaults.GraceDays, MaxSLADays)
	}

	d := &g.Digest
	switch d.ScheduleOrDefault() {
	case "weekly", "daily":
	default:
		add("governance.digest.schedule", ErrInvalidDigest, "%q must be weekly or daily", d.Schedule)
	}
	switch d.GroupByOrDefault() {
	case "owner", "account":
	default:
		add("governance.digest.group_by", ErrInvalidDigest, "%q must be owner or account", d.GroupBy)
	}
	if s := strings.ToLower(strings.TrimSpace(d.Sink)); s != "" {
		known := false
		for _, k := range DigestSinks {
			known = known || s == k
		}
		if !known {
			add("governance.digest.sink", ErrInvalidDigest, "%q must be one of %s", d.Sink, strings.Join(DigestSinks, ", "))
		} else if s != "stdout" {
			if _, ok := c.Integrations[s]; !ok {
				c.warnings = append(c.warnings, fmt.Sprintf("governance.digest.sink: %q has no integrations.%s entry; the digest will fall back to environment defaults or stdout", s, s))
			}
		}
	}
	if s := strings.ToLower(strings.TrimSpace(d.UnassignedSink)); s != "" {
		known := false
		for _, k := range DigestSinks {
			known = known || s == k
		}
		if !known {
			add("governance.digest.unassigned_sink", ErrInvalidDigest, "%q must be one of %s", d.UnassignedSink, strings.Join(DigestSinks, ", "))
		}
	}
	for _, m := range []struct {
		field string
		v     map[string]string
	}{{"governance.defaults.account_owners", g.Defaults.AccountOwners}, {"governance.defaults.provider_owners", g.Defaults.ProviderOwners}} {
		for k, v := range m.v {
			if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
				add(m.field, ErrInvalidOwner, "%q: key and owner must be non-empty", k)
			}
		}
	}
	if v := g.Defaults.MinOwnerShare; v != nil && (*v <= 0 || *v > 1) {
		add("governance.defaults.min_owner_share", ErrInvalidOwner, "%v must be a share in (0, 1], e.g. 0.5", *v)
	}
	if v := strings.TrimSpace(d.Window); v != "" {
		if w, err := time.ParseDuration(v); err != nil || w <= 0 {
			add("governance.digest.dedup_window", ErrInvalidDuration, "%q is not a positive Go duration (e.g. 72h)", d.Window)
		}
	}
}
