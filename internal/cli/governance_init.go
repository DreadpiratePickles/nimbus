package cli

// Ownership out of the box (delta review 2 #9). `governance init` and `onboard` write a
// starter `governance:` block from what the estate already says about ownership: resource
// tags whose key names an owner (owner, team, owner_email, contact, ...; cost center and
// department last) and the repository's CODEOWNERS for IaC files. The rules are ordinary
// first-match governance rules (docs/governance.md), so users edit them like any other.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	awscol "github.com/DreadpiratePickles/nimbus/internal/collector/aws"
	azcol "github.com/DreadpiratePickles/nimbus/internal/collector/azure"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/governance"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// unassignedWarnPct is the share of open Issues without an owner above which doctor warns.
const unassignedWarnPct = 30.0

var (
	strongOwnerKey = regexp.MustCompile(`(?i)^(owner|owners|team|teams|owning[-_ ]?team|owner[-_ ]?(email|team|name|group)|team[-_ ]?(name|email)|contact|contact[-_ ]?email|maintainer|maintainers|squad|tribe|service[-_ ]?owner|tech(nical)?[-_ ]?owner|business[-_ ]?owner|app(lication)?[-_ ]?owner|product[-_ ]?owner|responsible|support[-_ ]?team|on[-_ ]?call)$`)
	weakOwnerKey   = regexp.MustCompile(`(?i)^(cost[-_ ]?cent(er|re)|department|business[-_ ]?unit|bu)$`)
)

// ownerTagStat is one ownership tag key and the number of distinct resources carrying it.
type ownerTagStat struct {
	Key       string
	Resources int
	Weak      bool // cost center / department: an owner only by convention
}

// discoverOwnerTags counts ownership-like tag keys over the resources of fs (resource tags
// and finding tags) and of g's nodes. total is the number of distinct resources seen.
// Strong keys rank first, then by count, then by key.
func discoverOwnerTags(fs []model.Finding, g *graph.Graph) ([]ownerTagStat, int) {
	seen := map[string]map[string]bool{} // key -> resource ids
	resources := map[string]bool{}
	note := func(rid string, tags map[string]string) {
		if rid == "" {
			return
		}
		resources[rid] = true
		for k, v := range tags {
			if strings.TrimSpace(v) == "" || !(strongOwnerKey.MatchString(k) || weakOwnerKey.MatchString(k)) {
				continue
			}
			if seen[k] == nil {
				seen[k] = map[string]bool{}
			}
			seen[k][rid] = true
		}
	}
	for _, f := range fs {
		note(f.Resource.ID, governance.SubjectFromFinding(f).Tags)
	}
	if g != nil {
		for _, n := range g.Nodes() {
			if n.Type == "internet" {
				continue
			}
			tags := map[string]string{}
			if t, ok := n.Attributes["tags"].(map[string]any); ok {
				for k, v := range t {
					tags[k] = fmt.Sprint(v)
				}
			}
			note(n.ID, tags)
		}
	}
	out := make([]ownerTagStat, 0, len(seen))
	for k, ids := range seen {
		out = append(out, ownerTagStat{Key: k, Resources: len(ids), Weak: !strongOwnerKey.MatchString(k)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Weak != out[j].Weak {
			return !out[i].Weak
		}
		if out[i].Resources != out[j].Resources {
			return out[i].Resources > out[j].Resources
		}
		return out[i].Key < out[j].Key
	})
	return out, len(resources)
}

var ruleIDUnsafe = regexp.MustCompile(`[^a-z0-9]+`)

// starterGovernance builds the starter block: one `tag:<Key>` rule per strong ownership key
// (most common first), then a CODEOWNERS rule for IaC files when the repository has one; the
// defaults keep owner/team plus every discovered key (weak keys last) as fallback tags.
// codeownersFile is set only when the CODEOWNERS is outside the default locations of the
// working directory.
func starterGovernance(stats []ownerTagStat, hasCodeowners bool, codeownersFile string) config.Governance {
	var g config.Governance
	ids := map[string]bool{}
	for _, s := range stats {
		if s.Weak {
			continue
		}
		id := "owner-tag-" + strings.Trim(ruleIDUnsafe.ReplaceAllString(strings.ToLower(s.Key), "-"), "-")
		if ids[id] {
			continue
		}
		ids[id] = true
		g.Rules = append(g.Rules, config.GovernanceRule{ID: id, Match: config.GovernanceMatch{Tag: map[string]string{s.Key: "*"}}, Owner: "tag:" + s.Key})
	}
	if len(g.Rules) == 0 {
		// Nothing tagged yet: the conventional keys, so tagging later just works.
		for _, k := range config.DefaultOwnerTags {
			g.Rules = append(g.Rules, config.GovernanceRule{ID: "owner-tag-" + k, Match: config.GovernanceMatch{Tag: map[string]string{k: "*"}}, Owner: "tag:" + k})
		}
	}
	if hasCodeowners {
		g.Rules = append(g.Rules, config.GovernanceRule{ID: "iac-codeowners", Match: config.GovernanceMatch{IaCPathGlob: "**"}, Owner: "codeowners"})
		g.CodeownersFile = codeownersFile
	}
	tags := append([]string(nil), config.DefaultOwnerTags...)
	have := map[string]bool{}
	for _, k := range tags {
		have[strings.ToLower(k)] = true
	}
	for _, s := range stats {
		if !have[strings.ToLower(s.Key)] {
			have[strings.ToLower(s.Key)] = true
			tags = append(tags, s.Key)
		}
	}
	g.Defaults.OwnerTags = tags
	return g
}

// ownerProposal is what `governance init` proposes for Issues nothing else assigns (W5-ISSUES
// item 3, r3 #5): a default owner, per-account and per-provider owners, from the owner/team tags
// already in the estate. W6-POLISH (r4 #5): a value is proposed only with a strict plurality AND
// at least governance.defaults.min_owner_share (default 50%) of the tagged resources in scope —
// never on a tie, never "finance" from 2 of 14 — and a provider owner only where that provider's
// resources carry owner tags.
type ownerProposal struct {
	Default     string
	DefaultWhy  string
	Accounts    map[string]string // "provider/account" -> owner
	AccountWhy  map[string]string
	Providers   map[string]string // provider -> owner
	ProviderWhy map[string]string
}

// resourceOwnerTag is a resource's ownership value: the first non-empty strong owner key
// (owner, team, then the other strong keys alphabetically).
func resourceOwnerTag(tags map[string]string) string {
	for _, k := range config.DefaultOwnerTags {
		for tk, v := range tags {
			if strings.EqualFold(tk, k) && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strongOwnerKey.MatchString(k) && strings.TrimSpace(tags[k]) != "" {
			return strings.TrimSpace(tags[k])
		}
	}
	return ""
}

// plurality is the value with the strictly highest count ("" on a tie or no values) and its count.
func plurality(c map[string]int) (string, int, int) {
	best, n, total, tie := "", 0, 0, false
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		total += c[k]
		switch {
		case c[k] > n:
			best, n, tie = k, c[k], false
		case c[k] == n:
			tie = true
		}
	}
	if tie {
		return "", n, total
	}
	return best, n, total
}

// proposeFrom picks the owner of one scope (the estate, an account, a provider) from its tag
// counts: a strict plurality holding at least share of the tagged resources. why explains the
// choice or the refusal.
func proposeFrom(c map[string]int, share float64) (owner, why string) {
	if len(c) == 0 {
		return "", "no owner/team tags"
	}
	o, n, total := plurality(c)
	if o == "" {
		keys := make([]string, 0, len(c))
		for k := range c {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "", fmt.Sprintf("the owner tags tie (%s, %d of %d tagged resources each)", strings.Join(keys, ", "), n, total)
	}
	// Integer basis points (verification 7 #13): 56 of 100 meets 0.56, which the float product
	// 0.56*100 = 56.000000000000007 refused.
	if bp := int64(math.Round(share * 10000)); int64(n)*10000 < bp*int64(total) {
		return "", fmt.Sprintf("the most common owner tag %q is on %d of %d tagged resources (%.0f%%), below the %.0f%% min_owner_share", o, n, total, pct(n, total), 100*share)
	}
	return o, fmt.Sprintf("owner tag %q on %d of %d tagged resources (%.0f%%)", o, n, total, pct(n, total))
}

// proposeOwners counts ownership tag values per account and provider over fs and g and proposes
// the account owners (accounts already owned in the config are skipped), the provider owners
// (providers whose tagged accounts all got an account owner are skipped) and the default owner.
func proposeOwners(cfg *config.Config, fs []model.Finding, g *graph.Graph) ownerProposal {
	p := ownerProposal{Accounts: map[string]string{}, AccountWhy: map[string]string{}, Providers: map[string]string{}, ProviderWhy: map[string]string{}}
	share := config.DefaultMinOwnerShare
	if cfg != nil {
		share = cfg.Governance.Defaults.MinOwnerShareOrDefault()
	}
	perAcct := map[string]map[string]map[string]bool{} // acct -> owner -> resources
	perProv := map[string]map[string]map[string]bool{} // provider -> owner -> resources
	all := map[string]map[string]bool{}
	add := func(m map[string]map[string]map[string]bool, k, o, rid string) {
		if m[k] == nil {
			m[k] = map[string]map[string]bool{}
		}
		if m[k][o] == nil {
			m[k][o] = map[string]bool{}
		}
		m[k][o][rid] = true
	}
	note := func(provider, account, rid string, tags map[string]string) {
		o := resourceOwnerTag(tags)
		if o == "" || rid == "" {
			return
		}
		if account != "" {
			add(perAcct, provider+"/"+account, o, rid)
		}
		if provider != "" {
			add(perProv, provider, o, rid)
		}
		if all[o] == nil {
			all[o] = map[string]bool{}
		}
		all[o][rid] = true
	}
	for _, f := range fs {
		note(f.Provider, f.Account, f.Resource.ID, governance.SubjectFromFinding(f).Tags)
	}
	if g != nil {
		for _, n := range g.Nodes() {
			tags := map[string]string{}
			if t, ok := n.Attributes["tags"].(map[string]any); ok {
				for k, v := range t {
					tags[k] = fmt.Sprint(v)
				}
			}
			note(n.Provider, n.Account, n.ID, tags)
		}
	}
	counts := func(owners map[string]map[string]bool) map[string]int {
		c := map[string]int{}
		for o, rs := range owners {
			c[o] = len(rs)
		}
		return c
	}
	covered := map[string]bool{} // provider -> every tagged account has an owner
	for prov := range perProv {
		covered[prov] = true
	}
	for acct, owners := range perAcct {
		parts := strings.SplitN(acct, "/", 2)
		if accountOwner(cfg, parts[0], parts[1]) != "" {
			continue // accounts.<name>.owner already routes this account
		}
		o, why := proposeFrom(counts(owners), share)
		if o != "" {
			p.Accounts[acct] = o
		} else {
			covered[parts[0]] = false
		}
		p.AccountWhy[acct] = acct + ": " + why
	}
	for prov, owners := range perProv {
		if covered[prov] {
			continue
		}
		o, why := proposeFrom(counts(owners), share)
		if o != "" {
			p.Providers[prov] = o
		}
		p.ProviderWhy[prov] = prov + ": " + why
	}
	if cfg != nil && strings.TrimSpace(cfg.Governance.Defaults.Owner) != "" {
		p.Default = strings.TrimSpace(cfg.Governance.Defaults.Owner)
		p.DefaultWhy = "kept the configured defaults.owner"
	} else if o, why := proposeFrom(counts(all), share); o != "" {
		p.Default = o
		p.DefaultWhy = fmt.Sprintf("proposed defaults.owner %q: %s; replace it with your triage owner if that is not right", o, why)
	} else {
		p.DefaultWhy = "no proposed defaults.owner: " + why + "; set one by hand (or route the rest with governance.digest.unassigned_sink)"
	}
	return p
}

// repoCodeowners loads the CODEOWNERS of repo (nil when there is none) and the value a
// starter block needs in codeowners_file ("" when the default lookup from the working
// directory already finds it).
func repoCodeowners(repo string) (*governance.Codeowners, string) {
	co, err := governance.LoadCodeowners(repo, "")
	if err != nil || co == nil {
		return nil, ""
	}
	absRepo, _ := filepath.Abs(repo)
	cwd, _ := os.Getwd()
	if absRepo == cwd {
		return co, ""
	}
	abs, _ := filepath.Abs(co.Path)
	return co, abs
}

// onboardGovernance gives cfg a starter governance block when it has none (tags from st when
// a database exists, CODEOWNERS from repo). It reports whether it added one.
func onboardGovernance(cfg *config.Config, repo string, st *store.Store) bool {
	if cfg.Governance.Enabled() {
		return false
	}
	var stats []ownerTagStat
	if st != nil {
		fs, _ := st.Findings(store.Filter{})
		g, _ := loadGraph(st)
		stats, _ = discoverOwnerTags(fs, g)
	}
	co, coFile := repoCodeowners(repo)
	cfg.Governance = starterGovernance(stats, co != nil, coFile)
	return true
}

// governanceCoverage resolves every open Issue with cfg's governance and counts the ones that
// get an owner.
func governanceCoverage(cfg *config.Config, st *store.Store) (assigned, open int, err error) {
	issues, err := st.Issues(store.IssueFilter{OpenOnly: true})
	if err != nil || len(issues) == 0 {
		return 0, 0, err
	}
	events, err := governance.CollectEvents(st, nil)
	if err != nil {
		return 0, 0, err
	}
	g, _ := loadGraph(st)
	gr := newGovResolver(cfg)
	for _, is := range issues {
		open++
		if a := gr.Resolve(issueSubject(cfg, st, g, events, is)); a.Source != governance.SourceUnassigned && a.Owner != "" {
			assigned++
		}
	}
	return assigned, open, nil
}

// storedUnassigned counts open Issues whose persisted owner is empty or unassigned.
func storedUnassigned(st *store.Store) (unassigned, open int, err error) {
	c, err := storedOwnership(st)
	return c.Unassigned, c.Open, err
}

// ownershipCounts splits the open Issues by where their owner came from (W6-POLISH, r4 #5): an
// owner from the resource (rule, tag, CODEOWNERS, accounts.<name>.owner), an owner by default
// (defaults.owner / account_owners / provider_owners), or none. "100% owned" by a default is
// not ownership, so doctor and `issues metrics` print the default share apart.
type ownershipCounts struct {
	Open       int `json:"open"`
	Owned      int `json:"owned"`               // owner from the resource or the account config
	ByDefault  int `json:"assigned_by_default"` // owner from governance.defaults.*
	Unassigned int `json:"unassigned"`
}

func (c ownershipCounts) Text() string {
	return fmt.Sprintf("ownership: %d of %d open Issues owned from tags, rules, CODEOWNERS or accounts.<name>.owner · assigned by default: %d (defaults.owner / account_owners / provider_owners) · unassigned: %d",
		c.Owned, c.Open, c.ByDefault, c.Unassigned)
}

func storedOwnership(st *store.Store) (ownershipCounts, error) {
	var c ownershipCounts
	issues, err := st.Issues(store.IssueFilter{OpenOnly: true})
	if err != nil {
		return c, err
	}
	for _, is := range issues {
		c.Open++
		switch {
		case is.Owner == "" || is.OwnerSource == governance.SourceUnassigned:
			c.Unassigned++
		case is.OwnerSource == governance.SourceDefault:
			c.ByDefault++
		default:
			c.Owned++
		}
	}
	return c, nil
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}

// renderGovernanceBlock is the YAML of `governance:` preceded by comment lines.
func renderGovernanceBlock(g config.Governance, comments []string) (string, error) {
	var sb strings.Builder
	for _, c := range comments {
		sb.WriteString("# " + c + "\n")
	}
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(map[string]config.Governance{"governance": g}); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return sb.String(), nil
}

var govInitFlags struct {
	repo         string
	write, force bool
	owner        string
	accountTags  string
}

var governanceCmd = &cobra.Command{
	Use:   "governance",
	Short: "Owner and SLA governance (docs/governance.md)",
}

var governanceInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Print (or --write) a starter governance block from resource owner/team tags and CODEOWNERS",
	Long: `governance init reads the resource tags in the posture database and the repository's CODEOWNERS
and prints a starter governance: block: one rule per ownership tag key found (owner, team, owner_email,
contact, ...), then CODEOWNERS for IaC files, with owner/team plus the discovered keys as fallback tags.
It also prints how many open Issues the block would assign. --write appends it to the config file.

Account owners: for the configured AWS accounts and Azure subscriptions it reads the owner/team
tags of the AWS Organizations accounts (organizations:ListAccounts + ListTagsForResource; the
management account or a delegated administrator) and of the subscriptions (Resource Graph), or
takes them from --account-tags <file>, and writes one owner-account-* rule per tagged account
(after the resource-tag rules, so a resource's own owner tag still wins). A Kubernetes cluster
that is an EKS / AKS / GKE cluster of a tagged account inherits that account's owner.
--owner <team> sets defaults.owner; on a terminal, init asks for it when nothing proposes one.`,
	Example: `  cloud-posture governance init
  cloud-posture governance init --owner secops --write
  cloud-posture governance init --account-tags account-tags.json --repo ../infra --write`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		var (
			st    *store.Store
			stats []ownerTagStat
			total int
		)
		if _, err := os.Stat(firstNonEmpty(flagDB, store.DefaultPath())); err == nil {
			if st, err = openStore(); err != nil {
				return err
			}
			defer st.Close()
			fs, _ := st.Findings(store.Filter{})
			g, _ := loadGraph(st)
			stats, total = discoverOwnerTags(fs, g)
		}
		co, coFile := repoCodeowners(govInitFlags.repo)
		gov := starterGovernance(stats, co != nil, coFile)
		var prop ownerProposal
		if st != nil {
			fs, _ := st.Findings(store.Filter{})
			g, _ := loadGraph(st)
			prop = proposeOwners(cfg, fs, g)
		}
		// Account / subscription owner tags (r5 #5): rules after the resource-tag rules.
		acctTags, acctNotes := loadAccountTags(cmd.Context(), cfg, govInitFlags.accountTags)
		var acctRules []config.GovernanceRule
		var acctWhy []string
		if len(acctTags) > 0 {
			var fs []model.Finding
			var g *graph.Graph
			if st != nil {
				fs, _ = st.Findings(store.Filter{})
				g, _ = loadGraph(st)
			}
			acctRules, acctWhy = accountTagRules(cfg, acctTags, fs, g, st != nil)
			gov.Rules = insertAccountRules(gov.Rules, acctRules)
			for _, r := range acctRules {
				key := strings.ToLower(r.Match.Provider) + "/" + r.Match.Account
				for k := range prop.Accounts {
					if strings.EqualFold(k, key) {
						delete(prop.Accounts, k)
						prop.AccountWhy[k] = k + ": owned by rule " + r.ID + " (account tag)"
					}
				}
			}
		}
		if o := strings.TrimSpace(govInitFlags.owner); o != "" {
			prop.Default = o
			prop.DefaultWhy = fmt.Sprintf("defaults.owner %q from --owner (Issues nothing else assigns)", o)
		} else if prop.Default == "" && stdinIsTTY() {
			fmt.Fprint(cmd.ErrOrStderr(), "Default owner for Issues no rule, tag or account owner assigns (a team, email or @org/team; Enter to skip): ")
			if line, err := bufio.NewReader(promptInput).ReadString('\n'); err == nil || line != "" {
				if o := strings.TrimSpace(line); o != "" {
					prop.Default = o
					prop.DefaultWhy = fmt.Sprintf("defaults.owner %q entered at the prompt", o)
				}
			}
		}
		gov.Defaults.Owner = prop.Default
		if len(prop.Accounts) > 0 {
			gov.Defaults.AccountOwners = prop.Accounts
		}
		if len(prop.Providers) > 0 {
			gov.Defaults.ProviderOwners = prop.Providers
		}
		comments := []string{"starter block written by `cloud-posture governance init` on " + time.Now().UTC().Format("2006-01-02") + " (edit freely; first matching rule wins)"}
		if st == nil {
			comments = append(comments, "no posture database yet: run a scan, then re-run governance init to see tag coverage")
		}
		for _, s := range stats {
			kind := "owner tag"
			if s.Weak {
				kind = "fallback tag (cost center / department)"
			}
			comments = append(comments, fmt.Sprintf("%s %q on %d of %d resources", kind, s.Key, s.Resources, total))
		}
		comments = append(comments, acctWhy...)
		comments = append(comments, acctNotes...)
		if prop.DefaultWhy != "" {
			comments = append(comments, prop.DefaultWhy)
		}
		accts := make([]string, 0, len(prop.AccountWhy))
		for a := range prop.AccountWhy {
			accts = append(accts, a)
		}
		sort.Strings(accts)
		for _, a := range accts {
			comments = append(comments, "account owner "+prop.AccountWhy[a])
		}
		provs := make([]string, 0, len(prop.ProviderWhy))
		for pv := range prop.ProviderWhy {
			provs = append(provs, pv)
		}
		sort.Strings(provs)
		for _, pv := range provs {
			comments = append(comments, "provider owner "+prop.ProviderWhy[pv])
		}
		if len(prop.Accounts) > 0 || len(prop.Providers) > 0 || prop.Default != "" {
			comments = append(comments, "Issues no rule, tag or CODEOWNERS assigns go to the account owner, then defaults.owner (set governance.digest.unassigned_sink for what is left)")
		}
		if co != nil {
			comments = append(comments, "CODEOWNERS: "+co.Path)
		} else {
			comments = append(comments, "no CODEOWNERS under "+govInitFlags.repo+" (.github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS)")
		}
		if st != nil {
			trial := *cfg
			trial.Governance = gov
			if a, n, err := governanceCoverage(&trial, st); err == nil && n > 0 {
				if a < n {
					comments = append(comments, fmt.Sprintf("would assign %d of %d open Issues (%.0f%%); set defaults.owner for the other %d", a, n, pct(a, n), n-a))
				} else {
					comments = append(comments, fmt.Sprintf("would assign %d of %d open Issues (%.0f%%)", a, n, pct(a, n)))
				}
			}
		}
		block, err := renderGovernanceBlock(gov, comments)
		if err != nil {
			return err
		}
		if !govInitFlags.write {
			fmt.Print(block)
			return nil
		}
		path := firstNonEmpty(cfg.Path(), flagConfig, config.DefaultFile)
		if err := writeGovernanceBlock(path, gov, comments, block, govInitFlags.force); err != nil {
			return err
		}
		written, err := config.Load(path)
		if err != nil {
			return fmt.Errorf("wrote %s but it no longer validates: %w", path, err)
		}
		fmt.Printf("✓ wrote a starter governance block to %s (%d rule(s))\n", path, len(gov.Rules))
		if st != nil {
			// Apply it now, so `issues`, doctor and the digest see the owners without a rescan.
			if err := applyGovernance(written, st, nil); err != nil {
				return fmt.Errorf("wrote %s; applying it to the stored Issues failed: %w", path, err)
			}
			if un, n, err := storedUnassigned(st); err == nil && n > 0 {
				fmt.Printf("  applied to %d open Issues: %d unassigned (%.0f%%)\n", n, un, pct(un, n))
				markGovernanceInit(st, govInitMarker{At: time.Now().UTC().Format(time.RFC3339), Config: path, Open: n, Unassigned: un, DefaultOwner: gov.Defaults.Owner != ""})
			}
		}
		return nil
	},
}

func init() {
	governanceInitCmd.Flags().StringVar(&govInitFlags.repo, "repo", ".", "repository root searched for CODEOWNERS")
	governanceInitCmd.Flags().BoolVar(&govInitFlags.write, "write", false, "append the block to the config file instead of printing it")
	governanceInitCmd.Flags().BoolVar(&govInitFlags.force, "force", false, "with --write: replace an existing governance block")
	governanceInitCmd.Flags().StringVar(&govInitFlags.owner, "owner", "", "defaults.owner: the team that gets every Issue nothing else assigns (prompted for on a terminal when nothing proposes one)")
	governanceInitCmd.Flags().StringVar(&govInitFlags.accountTags, "account-tags", "", `JSON file of account / subscription tags, {"aws/<account id>": {"owner": "…"}, "azure/<subscription id>": {…}} (instead of, or on top of, reading them from AWS Organizations / Azure Resource Graph for the configured accounts)`)
	governanceCmd.AddCommand(governanceInitCmd)
	root.AddCommand(governanceCmd)
}

// writeGovernanceBlock puts gov into the config file at path (Verification 6 G1/G2):
//   - no governance: key → the rendered block is appended (the file is kept byte for byte);
//   - an empty governance: key ({} or null, comments allowed) → the block becomes its value;
//   - a non-empty block → refused without --force; with --force the generated parts (owner-tag-*
//     and iac-codeowners rules, defaults.owner / owner_tags / account_owners / provider_owners,
//     codeowners_file) are replaced in place and everything else — user rules (kept first, so
//     they still win), digest, SLA settings and every comment — is kept (yaml.v3 node round trip).
//
// The result is written atomically, and only when it re-loads and validates; a symlinked config
// is refused (the write could be redirected), and the file keeps its mode (0600 when new).
func writeGovernanceBlock(path string, gov config.Governance, comments []string, block string, force bool) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; pass the real file with -c so the write cannot be redirected", path)
		}
		mode = fi.Mode().Perm()
		// A read-only config is the user's "do not change this": the atomic rename would replace
		// it regardless of its mode (verification 7 #14), so refuse instead of writing (or chmod).
		if mode&0o200 == 0 {
			return fmt.Errorf("%s is read-only (mode %v); make it writable to let governance init --write change it, or paste the printed block yourself", path, mode)
		}
	}
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var doc yaml.Node
	if len(strings.TrimSpace(string(old))) > 0 {
		if err := yaml.Unmarshal(old, &doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	key, val := topLevelKey(&doc, "governance")
	var out []byte
	switch {
	case key == nil:
		sep := ""
		if len(old) > 0 && !strings.HasSuffix(string(old), "\n") {
			sep = "\n"
		}
		out = append(append([]byte{}, old...), []byte(sep+"\n"+block)...)
	case emptyNode(val) || force:
		if emptyNode(val) {
			*val = *encodeNode(gov)
		} else {
			mergeGovernanceNode(val, gov)
		}
		var hc []string
		for _, c := range comments {
			hc = append(hc, "# "+c)
		}
		// Keep the user's own comment above the key; drop the previous run's generated lines
		// (they start at "starter block written by"), so reruns do not stack them.
		if prev := key.HeadComment; prev != "" {
			if i := strings.Index(prev, "# starter block written by"); i >= 0 {
				prev = strings.TrimRight(prev[:i], "\n")
			}
			if prev != "" {
				hc = append([]string{prev}, hc...)
			}
		}
		key.HeadComment = strings.Join(hc, "\n")
		var sb strings.Builder
		enc := yaml.NewEncoder(&sb)
		enc.SetIndent(2)
		if err := enc.Encode(&doc); err != nil {
			return err
		}
		enc.Close()
		out = []byte(sb.String())
	default:
		return fmt.Errorf("%s already has a governance: block; edit it, or pass --force to replace its generated rules and defaults (your rules and comments are kept)", path)
	}
	return writeConfigValidated(path, out, mode)
}

// writeConfigValidated writes data to path through a temporary file in the same directory and
// renames it into place only after it loads and validates as a config; otherwise path is left
// as it was and the temporary file is removed.
func writeConfigValidated(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cloud-posture-*.yaml")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := config.Load(name); err != nil {
		return fmt.Errorf("the updated config would not load, so %s was left unchanged: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// topLevelKey returns the key and value nodes of a top-level mapping key (nil, nil when absent).
func topLevelKey(doc *yaml.Node, k string) (*yaml.Node, *yaml.Node) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	return mapKey(doc.Content[0], k)
}

func mapKey(m *yaml.Node, k string) (*yaml.Node, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

func emptyNode(n *yaml.Node) bool {
	return n == nil || (n.Kind == yaml.ScalarNode && (n.Tag == "!!null" || n.Value == "")) || (n.Kind == yaml.MappingNode && len(n.Content) == 0)
}

func encodeNode(v any) *yaml.Node {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"}
	}
	return &n
}

// setMapKey replaces k's value in m (keeping the key's comments) or appends k: v.
func setMapKey(m *yaml.Node, k string, v *yaml.Node) {
	if _, old := mapKey(m, k); old != nil {
		hc, lc := old.HeadComment, old.LineComment
		*old = *v
		if old.LineComment == "" {
			old.LineComment = lc
		}
		if old.HeadComment == "" {
			old.HeadComment = hc
		}
		return
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, v)
}

// generatedRuleID reports a rule id governance init writes (replaced by --force).
func generatedRuleID(id string) bool {
	return strings.HasPrefix(id, "owner-tag-") || strings.HasPrefix(id, "owner-account-") || id == "iac-codeowners"
}

// mergeGovernanceNode replaces the generated parts of an existing governance mapping with gov's
// and keeps everything else (see writeGovernanceBlock).
func mergeGovernanceNode(val *yaml.Node, gov config.Governance) {
	if val.Kind != yaml.MappingNode {
		*val = *encodeNode(gov)
		return
	}
	newRules := encodeNode(gov.Rules)
	if _, rules := mapKey(val, "rules"); rules != nil && rules.Kind == yaml.SequenceNode {
		var keep []*yaml.Node
		for _, r := range rules.Content {
			if _, id := mapKey(r, "id"); id != nil && generatedRuleID(id.Value) {
				continue
			}
			keep = append(keep, r)
		}
		if newRules.Kind == yaml.SequenceNode {
			keep = append(keep, newRules.Content...)
		}
		rules.Content = keep
		rules.Style = 0
	} else if len(gov.Rules) > 0 {
		setMapKey(val, "rules", newRules)
	}
	_, defs := mapKey(val, "defaults")
	if defs == nil || defs.Kind != yaml.MappingNode {
		setMapKey(val, "defaults", encodeNode(gov.Defaults))
	} else {
		d := gov.Defaults
		if d.Owner != "" {
			setMapKey(defs, "owner", encodeNode(d.Owner))
		}
		if len(d.OwnerTags) > 0 {
			setMapKey(defs, "owner_tags", encodeNode(d.OwnerTags))
		}
		if len(d.AccountOwners) > 0 {
			setMapKey(defs, "account_owners", encodeNode(d.AccountOwners))
		}
		if len(d.ProviderOwners) > 0 {
			setMapKey(defs, "provider_owners", encodeNode(d.ProviderOwners))
		}
	}
	if gov.CodeownersFile != "" {
		setMapKey(val, "codeowners_file", encodeNode(gov.CodeownersFile))
	}
}

// ---------------------------------------------------------------- account tags (W7-POLISH, r5 #5)

// stdinIsTTY reports whether stdin is a terminal (governance init prompts only then); tests
// replace it, and promptInput, to drive the prompt.
var stdinIsTTY = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

var promptInput io.Reader = os.Stdin

// accountTagsLookup reads the account-level tags one configured account can see: for AWS every
// ACTIVE account of its organization ("aws/<id>"), for Azure every subscription the credential
// reads ("azure/<id>"). Other providers have none here (nil). Tests replace it.
var accountTagsLookup = func(ctx context.Context, a *config.Account) (map[string]map[string]string, []string, error) {
	switch strings.ToLower(a.Provider) {
	case "aws":
		c, err := awscol.NewAccountTagsClient(ctx, specFor(a))
		if err != nil {
			return nil, nil, err
		}
		tags, notes, err := awscol.AccountTags(ctx, c)
		out := map[string]map[string]string{}
		for id, t := range tags {
			out["aws/"+id] = t
		}
		return out, notes, err
	case "azure":
		rg, err := azcol.NewSubscriptionTagsClient(specFor(a))
		if err != nil {
			return nil, nil, err
		}
		tags, err := azcol.SubscriptionTags(ctx, rg, nil)
		out := map[string]map[string]string{}
		for id, t := range tags {
			out["azure/"+id] = t
		}
		return out, nil, err
	}
	return nil, nil, nil
}

// loadAccountTags merges --account-tags (a JSON file, "provider/account" -> tags) with the tags
// read live for each configured AWS / Azure account (skipped under --no-network). Lookups that
// fail are notes in the generated block, never errors: ownership from resource tags still works.
func loadAccountTags(ctx context.Context, cfg *config.Config, file string) (map[string]map[string]string, []string) {
	if ctx == nil {
		ctx = context.Background()
	}
	out := map[string]map[string]string{}
	var notes []string
	put := func(k string, t map[string]string) {
		parts := strings.SplitN(k, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || len(t) == 0 {
			return
		}
		out[strings.ToLower(parts[0])+"/"+parts[1]] = t
	}
	if file != "" {
		var m map[string]map[string]string
		b, err := os.ReadFile(file)
		if err == nil {
			err = json.Unmarshal(b, &m)
		}
		if err != nil {
			notes = append(notes, fmt.Sprintf("account tags: %s not read: %v", file, err))
		}
		for k, t := range m {
			put(k, t)
		}
	}
	if cfg == nil {
		return out, notes
	}
	names := make([]string, 0, len(cfg.Accounts))
	for n, a := range cfg.Accounts {
		if a != nil && (strings.EqualFold(a.Provider, "aws") || strings.EqualFold(a.Provider, "azure")) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) > 0 && noNetwork() {
		return out, append(notes, "account tags: skipped (no-network); pass --account-tags <file> to use them offline")
	}
	seen := map[string]bool{} // one organization / tenant read per credential
	for _, n := range names {
		a := cfg.Accounts[n]
		a.Name = n
		key := strings.ToLower(a.Provider) + "|" + a.Profile + "|" + a.RoleARN + "|" + a.TenantID
		if seen[key] {
			continue
		}
		seen[key] = true
		tags, ns, err := accountTagsLookup(ctx, a)
		for _, x := range ns {
			notes = append(notes, "account tags ("+n+"): "+oneLine(x))
		}
		if err != nil {
			notes = append(notes, "account tags ("+n+"): "+oneLine(err.Error())+"; resource tags still apply (or pass --account-tags <file>)")
			continue
		}
		for k, t := range tags {
			if _, ok := out[strings.ToLower(k)]; !ok { // --account-tags wins
				put(k, t)
			}
		}
	}
	return out, notes
}

// clusterHostTypes are the managed Kubernetes cluster node types whose name is the cluster's.
var clusterHostTypes = map[string]string{"aws_eks_cluster": "EKS", "azure_kubernetes_cluster": "AKS", "gcp_container_cluster": "GKE"}

// accountTagRules turns account owner tags into first-match rules, one per tagged account
// (`owner-account-<provider>-<account>`, match provider + account): the account's own owner,
// like accounts.<name>.owner, so it counts as owned, not "assigned by default". With a database
// (inEstate) only accounts the estate has are written. A Kubernetes cluster that is the EKS /
// AKS / GKE cluster of a tagged account (one cluster node of that name) gets that owner too.
// Accounts that already have accounts.<name>.owner are left to it.
func accountTagRules(cfg *config.Config, tags map[string]map[string]string, fs []model.Finding, g *graph.Graph, inEstate bool) ([]config.GovernanceRule, []string) {
	estate := map[string]bool{}
	clusters := map[string][]string{} // cluster name -> hosting "provider/account" (+ kind)
	kinds := map[string]string{}
	for _, f := range fs {
		if f.Account != "" {
			estate[strings.ToLower(f.Provider)+"/"+f.Account] = true
		}
	}
	if g != nil {
		for _, n := range g.Nodes() {
			if n.Account != "" && n.Provider != "" && n.Provider != "any" {
				estate[strings.ToLower(n.Provider)+"/"+n.Account] = true
			}
			if k, ok := clusterHostTypes[n.Type]; ok && n.Name != "" && n.Account != "" {
				host := strings.ToLower(n.Provider) + "/" + n.Account
				clusters[n.Name] = append(clusters[n.Name], host)
				kinds[n.Name+"|"+host] = k
			}
		}
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	owners := map[string]string{}
	var rules []config.GovernanceRule
	var why []string
	add := func(prov, acct, owner, reason string) {
		id := "owner-account-" + strings.Trim(ruleIDUnsafe.ReplaceAllString(strings.ToLower(prov+"-"+acct), "-"), "-")
		rules = append(rules, config.GovernanceRule{ID: id, Match: config.GovernanceMatch{Provider: prov, Account: acct}, Owner: owner})
		why = append(why, reason+" → rule "+id)
	}
	for _, k := range keys {
		parts := strings.SplitN(k, "/", 2)
		prov, acct := parts[0], parts[1]
		if inEstate && !estate[k] {
			continue
		}
		o := resourceOwnerTag(tags[k])
		if o == "" {
			why = append(why, fmt.Sprintf("account %s has tags but no owner/team tag", k))
			continue
		}
		owners[k] = o
		if accountOwner(cfg, prov, acct) != "" {
			why = append(why, fmt.Sprintf("account tag owner=%q on %s: accounts.<name>.owner already routes it", o, k))
			continue
		}
		add(prov, acct, o, fmt.Sprintf("account tag owner=%q on %s", o, k))
	}
	// Kubernetes clusters hosted in a tagged account.
	var kube []string
	for k := range estate {
		if strings.HasPrefix(k, "kubernetes/") {
			kube = append(kube, k)
		}
	}
	sort.Strings(kube)
	for _, k := range kube {
		name := strings.TrimPrefix(k, "kubernetes/")
		hosts := clusters[name]
		if len(hosts) != 1 || owners[hosts[0]] == "" || accountOwner(cfg, "kubernetes", name) != "" {
			continue
		}
		if _, tagged := tags[k]; tagged {
			continue
		}
		add("kubernetes", name, owners[hosts[0]], fmt.Sprintf("%s cluster %s runs in %s (account tag owner=%q)", kinds[name+"|"+hosts[0]], name, hosts[0], owners[hosts[0]]))
	}
	return rules, why
}

// insertAccountRules places the account rules after the resource-tag rules (a resource's own
// owner tag wins) and before the CODEOWNERS rule.
func insertAccountRules(rules, acct []config.GovernanceRule) []config.GovernanceRule {
	if len(acct) == 0 {
		return rules
	}
	i := len(rules)
	for j, r := range rules {
		if r.ID == "iac-codeowners" {
			i = j
			break
		}
	}
	out := append([]config.GovernanceRule{}, rules[:i]...)
	out = append(out, acct...)
	return append(out, rules[i:]...)
}

// govInitMarker is what `governance init --write` leaves in store_meta (key governance_init) so
// doctor knows it ran and stops advising it (r5 R9).
type govInitMarker struct {
	At           string `json:"at"`
	Config       string `json:"config"`
	Open         int    `json:"open"`
	Unassigned   int    `json:"unassigned"`
	DefaultOwner bool   `json:"default_owner"`
}

const govInitMetaKey = "governance_init"

func markGovernanceInit(st *store.Store, m govInitMarker) {
	b, err := json.Marshal(m)
	if err != nil || st == nil || st.DB() == nil {
		return
	}
	_, _ = st.DB().Exec("INSERT INTO store_meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", govInitMetaKey, b)
}

func governanceInitMarker(st *store.Store) (govInitMarker, bool) {
	var m govInitMarker
	var b []byte
	if st == nil || st.DB() == nil || st.DB().QueryRow("SELECT v FROM store_meta WHERE k = ?", govInitMetaKey).Scan(&b) != nil {
		return m, false
	}
	return m, json.Unmarshal(b, &m) == nil
}
