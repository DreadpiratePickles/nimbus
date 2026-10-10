package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Sentinel kinds for ValidationError (match with errors.Is).
var (
	ErrInvalidCIDR         = errors.New("invalid CIDR")
	ErrTrustedCIDRTooBroad = errors.New("trusted CIDR too broad")
	ErrInvalidLevel        = errors.New("invalid crown-jewel level")
	ErrInvalidRegex        = errors.New("invalid regular expression")
	ErrEmptySelector       = errors.New("crown-jewel rule has no selector")
	ErrPlaintextSecret     = errors.New("plain-text secret in config")
	ErrInvalidDuration     = errors.New("invalid duration")
)

// ValidationError is one problem in the config, located by its YAML path.
type ValidationError struct {
	Field string // YAML path, e.g. "crown_jewels[2].name_regex"
	Msg   string
	Err   error // one of the Err* sentinels
}

func (e *ValidationError) Error() string { return "config: " + e.Field + ": " + e.Msg }
func (e *ValidationError) Unwrap() error { return e.Err }

// ValidationErrors is every problem found by Validate.
type ValidationErrors []*ValidationError

func (v ValidationErrors) Error() string {
	parts := make([]string, len(v))
	for i, e := range v {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "; ")
}

// Unwrap lets errors.Is / errors.As see every contained error.
func (v ValidationErrors) Unwrap() []error {
	out := make([]error, len(v))
	for i, e := range v {
		out[i] = e
	}
	return out
}

// Crown-jewel levels, highest first.
const (
	LevelVeryHigh = "very_high"
	LevelHigh     = "high"
	LevelMedium   = "medium"
	LevelLow      = "low"
)

// MaxCrownJewelRules caps crown_jewels; extra rules are dropped with a warning.
const MaxCrownJewelRules = 200

// DefaultAccountTimeout is the per-account native collection limit when
// scan.account_timeout is unset.
const DefaultAccountTimeout = 10 * time.Minute

var levelRank = map[string]int{LevelVeryHigh: 4, LevelHigh: 3, LevelMedium: 2, LevelLow: 1}

// LevelRank orders crown-jewel levels (very_high=4 … low=1, unknown=0).
func LevelRank(level string) int { return levelRank[strings.ToLower(level)] }

// CrownJewelRule marks resources as business-critical (O62). Every selector that is
// set must match (AND); list selectors match when any entry matches. Types accept
// globs (aws_s3_*); a tag value of "*" means "tag present".
type CrownJewelRule struct {
	Name      string            `yaml:"name,omitempty"`
	Level     string            `yaml:"level"`
	Types     []string          `yaml:"types,omitempty"`
	Tags      map[string]string `yaml:"tags,omitempty"`
	Accounts  []string          `yaml:"accounts,omitempty"`
	NameRegex string            `yaml:"name_regex,omitempty"`

	re *regexp.Regexp
}

// JewelSubject is the slice of a graph node a crown-jewel rule looks at.
type JewelSubject struct {
	Type, Name, Account string
	Tags                map[string]string
}

// JewelSubjectFromAttrs builds a subject from graph-node fields; tags are read from
// attrs["tags"] (map[string]any or map[string]string).
func JewelSubjectFromAttrs(typ, name, account string, attrs map[string]any) JewelSubject {
	s := JewelSubject{Type: typ, Name: name, Account: account, Tags: map[string]string{}}
	switch t := attrs["tags"].(type) {
	case map[string]any:
		for k, v := range t {
			s.Tags[k] = fmt.Sprint(v)
		}
	case map[string]string:
		for k, v := range t {
			s.Tags[k] = v
		}
	}
	return s
}

func (r *CrownJewelRule) regex() *regexp.Regexp {
	if r.NameRegex == "" {
		return nil
	}
	if r.re == nil {
		re, err := regexp.Compile(r.NameRegex)
		if err != nil {
			return nil
		}
		r.re = re
	}
	return r.re
}

func (r CrownJewelRule) empty() bool {
	return len(r.Types) == 0 && len(r.Tags) == 0 && len(r.Accounts) == 0 && r.NameRegex == ""
}

// Matches reports whether every configured selector matches the subject.
func (r *CrownJewelRule) Matches(s JewelSubject) bool {
	if r.empty() {
		return false
	}
	if len(r.Types) > 0 {
		ok := false
		for _, t := range r.Types {
			if m, _ := path.Match(strings.ToLower(t), strings.ToLower(s.Type)); m {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.Accounts) > 0 {
		ok := false
		for _, a := range r.Accounts {
			if strings.EqualFold(a, s.Account) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for k, want := range r.Tags {
		got, ok := lookupFold(s.Tags, k)
		if !ok || (want != "*" && !strings.EqualFold(got, want)) {
			return false
		}
	}
	if r.NameRegex != "" {
		re := r.regex()
		if re == nil || !re.MatchString(s.Name) {
			return false
		}
	}
	return true
}

func lookupFold(m map[string]string, k string) (string, bool) {
	if v, ok := m[k]; ok {
		return v, true
	}
	for mk, v := range m {
		if strings.EqualFold(mk, k) {
			return v, true
		}
	}
	return "", false
}

// MatchCrownJewel returns the highest level among matching rules (very_high >
// high > medium > low). It is pure: no I/O, safe for concurrent use once the rules
// are validated (unvalidated rules compile their regex lazily).
func MatchCrownJewel(rules []CrownJewelRule, s JewelSubject) (level string, matched bool) {
	best := 0
	for i := range rules {
		r := &rules[i]
		rank := LevelRank(r.Level)
		if rank <= best || !r.Matches(s) {
			continue
		}
		best, level, matched = rank, strings.ToLower(r.Level), true
	}
	return level, matched
}

// AccountTimeout is scan.account_timeout (default 10m; "none"/"0" disables → -1).
func (c *Config) AccountTimeout() time.Duration {
	v := strings.TrimSpace(strings.ToLower(c.Scan.AccountTimeout))
	switch v {
	case "":
		return DefaultAccountTimeout
	case "none", "off", "0", "unlimited":
		return -1
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return DefaultAccountTimeout
	}
	return d
}

// Warnings are non-fatal findings of the last Validate (e.g. crown-jewel cap).
func (c *Config) Warnings() []string { return append([]string(nil), c.warnings...) }

// Validate checks the whole config and returns every problem as ValidationErrors
// (nil when valid). It compiles crown-jewel regexes, normalises levels and enforces
// the crown-jewel cap (dropping extra rules with a warning).
func (c *Config) Validate() error {
	var errs ValidationErrors
	add := func(field string, sentinel error, format string, args ...any) {
		errs = append(errs, &ValidationError{Field: field, Msg: fmt.Sprintf(format, args...), Err: sentinel})
	}
	c.warnings = nil

	for i, s := range c.TrustedCIDRs {
		field := fmt.Sprintf("trusted_cidrs[%d]", i)
		s = strings.TrimSpace(s)
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				add(field, ErrInvalidCIDR, "%q is not a CIDR or IP address", s)
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Bits() == 0 {
			add(field, ErrTrustedCIDRTooBroad, "%s would trust the whole internet; list your egress / VPN ranges instead", s)
		}
	}

	if len(c.CrownJewels) > MaxCrownJewelRules {
		c.warnings = append(c.warnings, fmt.Sprintf("crown_jewels has %d rules; only the first %d are used", len(c.CrownJewels), MaxCrownJewelRules))
		c.CrownJewels = c.CrownJewels[:MaxCrownJewelRules]
	}
	for i := range c.CrownJewels {
		r := &c.CrownJewels[i]
		field := fmt.Sprintf("crown_jewels[%d]", i)
		r.Level = strings.ToLower(strings.TrimSpace(r.Level))
		if LevelRank(r.Level) == 0 {
			add(field+".level", ErrInvalidLevel, "%q must be one of very_high, high, medium, low", r.Level)
		}
		if r.empty() {
			add(field, ErrEmptySelector, "set at least one of types, tags, accounts, name_regex")
		}
		if r.NameRegex != "" {
			re, err := regexp.Compile(r.NameRegex)
			if err != nil {
				add(field+".name_regex", ErrInvalidRegex, "%v", err)
			} else {
				r.re = re
			}
		}
	}

	c.validateGovernance(add)

	if v := strings.TrimSpace(strings.ToLower(c.Scan.AccountTimeout)); v != "" {
		switch v {
		case "none", "off", "0", "unlimited":
		default:
			if d, err := time.ParseDuration(v); err != nil || d <= 0 {
				add("scan.account_timeout", ErrInvalidDuration, "%q is not a positive Go duration (e.g. 10m, 1h) or \"none\"", c.Scan.AccountTimeout)
			}
		}
	}

	// Plain-text secrets: struct fields first, then any secret-named key seen in the raw YAML.
	seen := map[string]bool{}
	secret := func(field, envKey string) {
		if seen[field] {
			return
		}
		seen[field] = true
		add(field, ErrPlaintextSecret, "literal secret values are not allowed; set %s to the name of an environment variable instead (values are never logged)", envKey)
	}
	for _, name := range sortedKeys(c.Integrations) {
		if sc := c.Integrations[name]; sc != nil && sc.Token != "" {
			secret("integrations."+name+".token", "token_env")
		}
	}
	if c.Neo4j.Password != "" {
		secret("neo4j.password", "password_env")
	}
	for _, f := range c.rawSecrets {
		if k := f[strings.LastIndexAny(f, ".]")+1:]; strings.HasSuffix(strings.ToLower(k), "_env") {
			if !seen[f] {
				seen[f] = true
				add(f, ErrPlaintextSecret, "must be the name of an environment variable (letters, digits, _), not a value (values are never logged)")
			}
			continue
		}
		secret(f, envKeyFor(f))
	}

	if len(errs) == 0 {
		return nil
	}
	return errs
}

// secretKeys are YAML keys whose literal values are refused; keys ending in one of
// secretSuffixes (bot_token, access_token, signing_secret, ...) are refused too.
var secretKeys = map[string]bool{"key": true, "token": true, "password": true, "secret": true, "client_secret": true, "api_key": true, "apikey": true, "secret_access_key": true, "private_key": true}

var secretSuffixes = []string{"_token", "_secret", "_password", "_key", "_apikey"}

func isSecretKey(k string) bool {
	k = strings.ToLower(k)
	if secretKeys[k] {
		return true
	}
	for _, suf := range secretSuffixes {
		if strings.HasSuffix(k, suf) {
			return true
		}
	}
	return false
}

// credentialHeader reports an HTTP header that carries a credential.
func credentialHeader(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "authorization", "proxy-authorization", "cookie":
		return true
	}
	for _, w := range []string{"token", "secret", "key", "auth", "password", "signature"} {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// secretQueryParams are URL query parameters that carry credentials.
var secretQueryParams = []string{"token", "key", "secret", "sig", "signature", "password", "passwd", "pwd", "auth", "code", "credential"}

// webhookHosts are hosts whose webhook URL path is itself the credential.
var webhookHosts = []string{"hooks.slack.com", "webhook.office.com", "outlook.office.com", "discord.com", "discordapp.com", "chat.googleapis.com", "hooks.zapier.com"}

// secretURL reports a URL value that embeds a credential: a password in the
// userinfo, a credential-named query parameter, or a webhook whose path is the secret.
func secretURL(v string) bool {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Host == "" {
		return false
	}
	if _, ok := u.User.Password(); ok {
		return true
	}
	for name := range u.Query() {
		n := strings.ToLower(name)
		for _, p := range secretQueryParams {
			if strings.Contains(n, p) {
				return true
			}
		}
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range webhookHosts {
		if (host == h || strings.HasSuffix(host, "."+h)) && strings.Trim(u.Path, "/") != "" {
			return true
		}
	}
	return false
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func envKeyFor(field string) string {
	k := field
	if i := strings.LastIndexAny(field, ".]"); i >= 0 {
		k = field[i+1:]
	}
	if strings.Contains(field, ".headers.") {
		return "token_env (the sink sends it as the credential header)"
	}
	return k + "_env"
}

// scanSecrets walks the raw YAML and records paths of fields holding a literal
// credential (the value itself is never stored): secret-named keys, URLs that embed
// a credential, credential HTTP headers, and *_env keys whose value is not an
// environment variable name. Aliases are followed.
func scanSecrets(n *yaml.Node, prefix string, out *[]string) {
	if n == nil {
		return
	}
	if n.Kind == yaml.AliasNode {
		scanSecrets(n.Alias, prefix, out)
		return
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			scanSecrets(c, prefix, out)
		}
	case yaml.MappingNode:
		inHeaders := strings.EqualFold(prefix[strings.LastIndex(prefix, ".")+1:], "headers")
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if v.Kind == yaml.AliasNode && v.Alias != nil {
				v = v.Alias
			}
			p := k.Value
			if prefix != "" {
				p = prefix + "." + k.Value
			}
			scalar := v.Kind == yaml.ScalarNode && strings.TrimSpace(v.Value) != "" && v.Tag != "!!null"
			lk := strings.ToLower(k.Value)
			switch {
			case !scalar:
			case strings.HasSuffix(lk, "_env"):
				if !envNameRe.MatchString(strings.TrimSpace(v.Value)) {
					*out = append(*out, p)
				}
				continue
			case isSecretKey(k.Value), inHeaders && credentialHeader(k.Value):
				*out = append(*out, p)
				continue
			case (lk == "url" || lk == "uri" || strings.HasSuffix(lk, "_url") || strings.HasSuffix(lk, "_uri")) && secretURL(v.Value):
				*out = append(*out, p)
				continue
			}
			scanSecrets(v, p, out)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			scanSecrets(c, fmt.Sprintf("%s[%d]", prefix, i), out)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
