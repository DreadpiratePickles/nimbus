// Package config loads cloud-posture.yaml and .env style files.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Account struct {
	Name           string   `yaml:"-"`
	Provider       string   `yaml:"provider"`
	Profile        string   `yaml:"profile,omitempty"`  // AWS profile
	RoleARN        string   `yaml:"role_arn,omitempty"` // AWS role to assume
	Regions        []string `yaml:"regions,omitempty"`
	SubscriptionID string   `yaml:"subscription_id,omitempty"` // Azure
	TenantID       string   `yaml:"tenant_id,omitempty"`       // Azure / M365
	ProjectID      string   `yaml:"project_id,omitempty"`      // GCP
	KubeContext    string   `yaml:"kube_context,omitempty"`    // Kubernetes
	Org            string   `yaml:"org,omitempty"`             // GitHub org
	Domain         string   `yaml:"domain,omitempty"`          // Okta org URL / M365 domain
	TokenEnv       string   `yaml:"token_env,omitempty"`
	Tools          []string `yaml:"tools,omitempty"`       // native, prowler, scoutsuite, checkov, trivy, steampipe, python-checks
	Criticality    string   `yaml:"criticality,omitempty"` // production | staging | dev
	Owner          string   `yaml:"owner,omitempty"`
}

type SinkConfig struct {
	Enabled     *bool             `yaml:"enabled,omitempty"`
	MinSeverity string            `yaml:"min_severity,omitempty"`
	URL         string            `yaml:"url,omitempty"`
	URLEnv      string            `yaml:"url_env,omitempty"`
	Token       string            `yaml:"token,omitempty"`
	TokenEnv    string            `yaml:"token_env,omitempty"`
	Type        string            `yaml:"type,omitempty"` // siem: splunk_hec | elastic | webhook | syslog
	Index       string            `yaml:"index,omitempty"`
	Repo        string            `yaml:"repo,omitempty"` // github owner/name
	Labels      []string          `yaml:"labels,omitempty"`
	Channel     string            `yaml:"channel,omitempty"`
	Project     string            `yaml:"project,omitempty"` // jira project key
	IssueType   string            `yaml:"issue_type,omitempty"`
	Email       string            `yaml:"email,omitempty"`
	EmailEnv    string            `yaml:"email_env,omitempty"`
	WorkspaceID string            `yaml:"workspace_id,omitempty"` // sentinel
	KeyEnv      string            `yaml:"key_env,omitempty"`
	Site        string            `yaml:"site,omitempty"` // datadog site
	Headers     map[string]string `yaml:"headers,omitempty"`
}

type Plugin struct {
	Name    string   `yaml:"name"`
	Command []string `yaml:"command"`
	Account string   `yaml:"account,omitempty"`
}

type Config struct {
	Accounts     map[string]*Account    `yaml:"accounts"`
	Integrations map[string]*SinkConfig `yaml:"integrations,omitempty"`
	Plugins      []Plugin               `yaml:"plugins,omitempty"`
	Python       struct {
		Enabled    *bool  `yaml:"enabled,omitempty"`
		Executable string `yaml:"executable,omitempty"`
	} `yaml:"python,omitempty"`
	Neo4j struct {
		URI         string `yaml:"uri,omitempty"`
		URIEnv      string `yaml:"uri_env,omitempty"`
		User        string `yaml:"user,omitempty"`
		UserEnv     string `yaml:"user_env,omitempty"`
		Password    string `yaml:"password,omitempty"` // rejected by Validate: use password_env
		PasswordEnv string `yaml:"password_env,omitempty"`
		Database    string `yaml:"database,omitempty"`
	} `yaml:"neo4j,omitempty"`
	Scan struct {
		IaCPaths        []string `yaml:"iac_paths,omitempty"`
		AttackRulesFile string   `yaml:"attack_rules_file,omitempty"`
		WorkDir         string   `yaml:"work_dir,omitempty"`
		Parallel        int      `yaml:"parallel,omitempty"`
		MinSeverity     string   `yaml:"min_severity,omitempty"`
		// AccountTimeout caps one account's native collection (Go duration; default
		// 10m; "none" disables). Read it through Config.AccountTimeout().
		AccountTimeout string `yaml:"account_timeout,omitempty"`
	} `yaml:"scan,omitempty"`
	// TrustedCIDRs are corporate egress / VPN ranges: internet exposure whose every
	// source is inside them is labelled exposure "trusted" (O10).
	TrustedCIDRs []string `yaml:"trusted_cidrs,omitempty"`
	// PathRules are customer path-rule directories (W7-ENGINE r5 #4; docs/attack-paths): every
	// *.yaml under them is validated with `risk test` semantics and, when accepted, evaluated by
	// traversal next to the embedded library. Relative dirs resolve against the config file.
	PathRules struct {
		Dirs []string `yaml:"dirs,omitempty"`
	} `yaml:"path_rules,omitempty"`
	// CrownJewels are business-priority rules (O62); see MatchCrownJewel.
	CrownJewels []CrownJewelRule `yaml:"crown_jewels,omitempty"`
	// Governance assigns owners and SLA due dates to Issues and drives digests
	// (docs/governance.md).
	Governance Governance `yaml:"governance,omitempty"`
	DB         string     `yaml:"db,omitempty"`
	path       string
	warnings   []string
	rawSecrets []string // YAML paths of secret-named keys with literal values
}

const DefaultFile = "cloud-posture.yaml"

// ErrConfigNotFound: an explicitly named config file (--config / -c) does not exist. Only the
// implicit default (./cloud-posture.yaml, ~/.cloud-posture/cloud-posture.yaml) may be absent;
// a mistyped path used to load the defaults silently (verification 7 defect 6).
var ErrConfigNotFound = errors.New("config file not found")

// Load reads the config file (or returns an empty config when absent), applies env
// files and runs Validate: any ValidationErrors fail the load (errors.Is works with
// the Err* sentinels). Non-fatal issues are in cfg.Warnings().
func Load(path string) (*Config, error) {
	LoadEnvFiles()
	cfg := &Config{Accounts: map[string]*Account{}, Integrations: map[string]*SinkConfig{}}
	explicit := path != ""
	if path == "" {
		path = DefaultFile
		if _, err := os.Stat(path); err != nil {
			if home, err := os.UserHomeDir(); err == nil {
				alt := filepath.Join(home, ".cloud-posture", DefaultFile)
				if _, err := os.Stat(alt); err == nil {
					path = alt
				}
			}
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if explicit {
				return nil, fmt.Errorf("%w: %s (check the --config path; without --config the default %s may be absent)", ErrConfigNotFound, path, DefaultFile)
			}
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var raw yaml.Node
	if err := yaml.Unmarshal(data, &raw); err == nil {
		scanSecrets(&raw, "", &cfg.rawSecrets)
	}
	cfg.path = path
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for name, a := range cfg.Accounts {
		if a == nil {
			a = &Account{}
			cfg.Accounts[name] = a
		}
		a.Name = name
		if a.Provider == "" {
			a.Provider = guessProvider(name)
		}
	}
	return cfg, nil
}

func (c *Config) Path() string { return c.path }

// PathRuleDirs is path_rules.dirs with relative entries resolved against the config file's
// directory (as written when the config has no file).
func (c *Config) PathRuleDirs() []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, d := range c.PathRules.Dirs {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if !filepath.IsAbs(d) && c.path != "" {
			d = filepath.Join(filepath.Dir(c.path), d)
		}
		out = append(out, d)
	}
	return out
}

func (c *Config) Save(path string) error {
	if path == "" {
		path = DefaultFile
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// SelectAccounts returns the named accounts (all when names is empty).
func (c *Config) SelectAccounts(names []string) ([]*Account, error) {
	if len(names) == 0 {
		var out []*Account
		for _, a := range c.Accounts {
			out = append(out, a)
		}
		return out, nil
	}
	var out []*Account
	for _, n := range names {
		n = strings.TrimSpace(n)
		a, ok := c.Accounts[n]
		if !ok {
			// allow ad-hoc "provider:identifier" specs: aws:prod-profile, gcp:my-project, k8s:ctx
			if i := strings.Index(n, ":"); i > 0 {
				a = &Account{Name: n, Provider: n[:i]}
				id := n[i+1:]
				switch a.Provider {
				case "aws":
					a.Profile = id
				case "azure":
					a.SubscriptionID = id
				case "gcp":
					a.ProjectID = id
				case "kubernetes", "k8s":
					a.Provider, a.KubeContext = "kubernetes", id
				case "github":
					a.Org = id
				default:
					a.Domain = id
				}
				out = append(out, a)
				continue
			}
			return nil, fmt.Errorf("account %q not found in %s (known: %s)", n, c.pathOrDefault(), strings.Join(c.AccountNames(), ", "))
		}
		out = append(out, a)
	}
	return out, nil
}

func (c *Config) pathOrDefault() string {
	if c.path == "" {
		return DefaultFile
	}
	return c.path
}

func (c *Config) AccountNames() []string {
	var names []string
	for n := range c.Accounts {
		names = append(names, n)
	}
	return names
}

func guessProvider(name string) string {
	l := strings.ToLower(name)
	for _, p := range []string{"aws", "azure", "gcp", "oci", "k8s", "kubernetes", "github", "okta", "m365"} {
		if strings.HasPrefix(l, p) {
			if p == "k8s" {
				return "kubernetes"
			}
			return p
		}
	}
	return ""
}

// Resolve returns a literal value or the named env var.
func Resolve(literal, envName string) string {
	if literal != "" {
		return literal
	}
	if envName != "" {
		return os.Getenv(envName)
	}
	return ""
}

// LoadEnvFiles reads KEY=VALUE lines from nimbus.env and .env in the working directory
// into the process environment without overriding variables already set.
func LoadEnvFiles(paths ...string) {
	if len(paths) == 0 {
		paths = []string{".env", "nimbus.env", filepath.Join(".cloud-posture", ".env")}
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimPrefix(line, "export ")
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			if os.Getenv(k) == "" {
				os.Setenv(k, v)
			}
		}
		f.Close()
	}
}
