package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	awscol "github.com/DreadpiratePickles/nimbus/internal/collector/aws"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
	crm "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/governance"
	"github.com/DreadpiratePickles/nimbus/internal/intel"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// doctorEnv holds every side effect doctor performs, so tests use fakes.
type doctorEnv struct {
	identity func(ctx context.Context, a *config.Account) (string, error)
	lookPath func(name string) (string, error)
	version  func(ctx context.Context, path string) (string, error)
	python   func(cfg *config.Config) string
	httpHead func(ctx context.Context, url string) error
	feeds    []string
	// discoverAWS looks at the AWS SDK default chain when no account is configured (nil: skip).
	discoverAWS func(ctx context.Context) []awscol.DiscoveredIdentity
}

type doctorCheck struct{ status, name, detail string }

const (
	docOK   = "ok"
	docWarn = "warn"
	docFail = "fail"
	docSkip = "skip"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check credentials, scanners, the Python layer, the database schema, config and intel-feed reachability",
	Long: `doctor runs read-only checks and prints ok / warn / fail per item:
  credentials per configured account (AWS STS GetCallerIdentity, an Azure ARM token, GCP projects.get, ...),
  the Python intelligence layer, prowler/checkov/trivy/steampipe on PATH with versions,
  the posture database schema version, config validation, and network access to the KEV/EPSS feeds.
It exits non-zero when any check fails (warnings do not fail).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDoctor(cmd.Context(), defaultDoctorEnv(), os.Stdout)
	},
}

func init() { root.AddCommand(doctorCmd) }

func defaultDoctorEnv() doctorEnv {
	return doctorEnv{
		identity: cloudIdentity,
		lookPath: exec.LookPath,
		version:  toolVersion,
		python:   python,
		httpHead: headURL,
		feeds:    []string{intel.KEVURL, intel.EPSSURL},
		discoverAWS: func(ctx context.Context) []awscol.DiscoveredIdentity {
			if noNetwork() { // discovery makes one STS call per credential source
				return nil
			}
			return discoverAWS(ctx)
		},
	}
}

func runDoctor(ctx context.Context, env doctorEnv, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var checks []doctorCheck
	add := func(status, name, detail string) { checks = append(checks, doctorCheck{status, name, detail}) }

	// config
	cfg, err := loadConfig()
	if err != nil {
		add(docFail, "config", err.Error())
		cfg = &config.Config{Accounts: map[string]*config.Account{}}
	} else {
		where := firstNonEmpty(cfg.Path(), "(none: no config file found)")
		if v, ok := any(cfg).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				add(docFail, "config", err.Error())
			} else {
				add(docOK, "config", fmt.Sprintf("%s valid, %d account(s)", where, len(cfg.Accounts)))
			}
		} else {
			add(docSkip, "config", "config.Validate not available in this build")
		}
		if wv, ok := any(cfg).(interface{ Warnings() []string }); ok {
			for _, msg := range wv.Warnings() {
				add(docWarn, "config", msg)
			}
		}
	}

	// credentials per configured account
	if len(cfg.Accounts) == 0 {
		add(docWarn, "credentials", "no accounts configured (run cloud-posture onboard)")
		if env.discoverAWS != nil {
			// The SDK default chain (env, shared profiles, SSO cache, web identity, container and
			// instance metadata) — the same chain the collectors use; no `aws` CLI needed.
			dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			for _, id := range env.discoverAWS(dctx) {
				switch {
				case id.Account != "":
					via := id.Source
					if id.Profile != "" {
						via += " (profile " + id.Profile + ")"
					}
					add(docWarn, "credentials aws", fmt.Sprintf("AWS credentials found via %s: account %s (%s) is not configured; run cloud-posture onboard --aws", via, id.Account, id.Arn))
				case id.Err != "":
					add(docWarn, "credentials aws", id.Err)
				default:
					// A reply that decodes to no identity (a garbage 200 body) is not "no credentials".
					add(docFail, "credentials aws", fmt.Sprintf("AWS credentials found via %s, but there is no account in the STS reply (unreadable GetCallerIdentity response; check proxies / AWS_ENDPOINT_URL*)", firstNonEmpty(id.Source, "the SDK chain")))
				}
			}
			cancel()
		}
	}
	for _, name := range cfg.AccountNames() {
		a := cfg.Accounts[name]
		if a == nil {
			continue
		}
		label := "credentials " + a.Provider + "/" + name
		if noNetwork() { // an identity call is a network call (r4 #14 / N7)
			add(docSkip, label, "skipped (no-network): the read-only identity call was not made")
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		id, err := env.identity(cctx, a)
		cancel()
		switch {
		case err == errNoIdentityCheck:
			add(docSkip, label, "no read-only identity check for this provider")
		case err != nil:
			add(docFail, label, err.Error())
		default:
			add(docOK, label, id)
		}
	}

	// Python layer
	if exe := env.python(cfg); exe != "" {
		add(docOK, "python layer", exe+" can import nimbus"+pyDirNote())
	} else {
		if by := pythonDisabledBy(cfg); by != "" {
			add(docSkip, "python layer", "off ("+by+"); optional: only ask, fix --ai, saved queries and html/pdf reports need it")
		} else {
			add(docWarn, "python layer", "not found (optional: only ask, fix --ai, html/pdf reports): "+copilotInstallCmd("python3"))
		}
	}

	// external scanners
	for _, t := range []string{"prowler", "checkov", "trivy", "steampipe"} {
		p, err := env.lookPath(t)
		if err != nil {
			add(docWarn, "tool "+t, "not on PATH (optional)")
			continue
		}
		vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		v, err := env.version(vctx, p)
		cancel()
		if err != nil {
			add(docWarn, "tool "+t, p+": version check failed: "+err.Error())
			continue
		}
		add(docOK, "tool "+t, v)
	}

	// database schema (never create one)
	dbPath := firstNonEmpty(flagDB, store.DefaultPath())
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		add(docWarn, "database", "no database yet at "+dbPath+" (run a scan)")
	} else if st, err := store.Open(dbPath); err != nil {
		add(docFail, "database", err.Error())
	} else {
		v, err := st.SchemaVersion()
		st.Close()
		switch {
		case err != nil:
			add(docFail, "database", err.Error())
		case v != store.LatestSchemaVersion():
			add(docFail, "database", fmt.Sprintf("schema v%d, expected v%d", v, store.LatestSchemaVersion()))
		default:
			add(docOK, "database", fmt.Sprintf("%s schema v%d (latest)", dbPath, v))
			doctorOwnership(cfg, dbPath, add)
		}
	}

	// intel snapshot embedded in this binary (used offline and when a feed download fails)
	add(docOK, "intel snapshot", "embedded KEV/EPSS snapshot "+intel.SnapshotDate+" (refreshed from the feeds unless --no-network)")

	// intel feeds (never probed under --no-network / CLOUD_POSTURE_NO_NETWORK)
	for _, u := range env.feeds {
		if noNetwork() {
			add(docSkip, "intel feed", u+": skipped (no-network)")
			continue
		}
		hctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		err := env.httpHead(hctx, u)
		cancel()
		if err != nil {
			add(docWarn, "intel feed", u+": "+err.Error()+" (offline: cached feeds are used)")
		} else {
			add(docOK, "intel feed", u)
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCHECK\tDETAIL")
	fails := 0
	for _, c := range checks {
		if c.status == docFail {
			fails++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.status, c.name, oneLine(c.detail))
	}
	tw.Flush()
	if fails > 0 {
		return fmt.Errorf("doctor: %d check(s) failed", fails)
	}
	return nil
}

// doctorOwnership warns when more than unassignedWarnPct of the open Issues have no owner
// (delta review 2 #9): digests and tickets would go to "(unassigned)". It always names the
// unassigned share and the next concrete step; once `governance init --write` has run (its
// store_meta marker) it no longer advises that command (r5 R9: it cannot fix what tags do not
// say) and points at the account holding most unassigned Issues and at defaults.owner instead.
func doctorOwnership(cfg *config.Config, dbPath string, add func(status, name, detail string)) {
	st, err := store.Open(dbPath)
	if err != nil {
		return
	}
	defer st.Close()
	c, err := storedOwnership(st)
	if err != nil || c.Open == 0 {
		return
	}
	un, open := c.Unassigned, c.Open
	byDefault := fmt.Sprintf("assigned by default: %d", c.ByDefault)
	where := topUnassignedAccount(st)
	defaultSet := cfg != nil && strings.TrimSpace(cfg.Governance.Defaults.Owner) != ""
	// next adds the concrete next steps as their own rows (doctor cuts a detail at 160 bytes).
	next := func(status string) {
		if where != "" {
			add(status, "ownership next", "most unassigned are in "+where+": tag that account's owner (account / subscription tags) or set accounts.<name>.owner")
		}
		if !defaultSet {
			add(status, "ownership next", "or set defaults.owner: `cloud-posture governance init --write --force --owner <team>` (or governance.digest.unassigned_sink)")
		}
	}
	switch p := pct(un, open); {
	case p > unassignedWarnPct:
		if m, ran := governanceInitMarker(st); ran {
			when := m.At
			if t, err := time.Parse(time.RFC3339, m.At); err == nil {
				when = t.Format("2006-01-02")
			}
			add(docWarn, "ownership", fmt.Sprintf("%d of %d open Issues (%.0f%%) are unassigned after governance init ran (%s); %s", un, open, p, when, byDefault))
			next(docWarn)
			return
		}
		add(docWarn, "ownership", fmt.Sprintf("%d of %d open Issues (%.0f%%) are unassigned, %s; run `cloud-posture governance init --write` (--owner <team> for the rest)", un, open, p, byDefault))
	case pct(c.ByDefault, open) > 50:
		// "100% owned" by a fallback is not ownership (r4 #5): say so.
		add(docWarn, "ownership", fmt.Sprintf("%d of %d open Issues have an owner, but %s (governance.defaults.*); tag owners or add rules", open-un, open, byDefault))
	case un > 0:
		add(docOK, "ownership", fmt.Sprintf("%d of %d open Issues have an owner; %s; unassigned: %d (%.0f%%)", open-un, open, byDefault, un, p))
		next(docOK)
	default:
		add(docOK, "ownership", fmt.Sprintf("%d of %d open Issues have an owner; %s", open-un, open, byDefault))
	}
}

// topUnassignedAccount is "provider/account (n)" for the account with the most unassigned open
// Issues ("" when there are none).
func topUnassignedAccount(st *store.Store) string {
	issues, err := st.Issues(store.IssueFilter{OpenOnly: true})
	if err != nil {
		return ""
	}
	n := map[string]int{}
	for _, is := range issues {
		if is.Owner == "" || is.OwnerSource == governance.SourceUnassigned {
			n[is.Provider+"/"+is.Account]++
		}
	}
	best, bn := "", 0
	for k, v := range n {
		if v > bn || (v == bn && k < best) {
			best, bn = k, v
		}
	}
	if best == "" {
		return ""
	}
	return fmt.Sprintf("%s (%d)", best, bn)
}

func pyDirNote() string {
	if d := pythonDir(); d != "" {
		return " (trusted source " + d + ")"
	}
	return ""
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

var errNoIdentityCheck = fmt.Errorf("no identity check")

func specFor(a *config.Account) core.AccountSpec {
	return core.AccountSpec{Name: a.Name, Provider: a.Provider, Profile: a.Profile, RoleARN: a.RoleARN, Regions: a.Regions, SubscriptionID: a.SubscriptionID,
		TenantID: a.TenantID, ProjectID: a.ProjectID, KubeContext: a.KubeContext, Org: a.Org, Domain: a.Domain, TokenEnv: a.TokenEnv}
}

// cloudIdentity performs one read-only identity call per provider with the same
// credential helpers the collectors use.
func cloudIdentity(ctx context.Context, a *config.Account) (string, error) {
	spec := specFor(a)
	switch a.Provider {
	case "aws":
		cfg, err := core.AWSConfig(ctx, spec, core.DefaultAWSRegion)
		if err != nil {
			return "", err
		}
		out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return "", err
		}
		return stsIdentity(out)
	case "azure":
		cred, err := core.AzureCredential(spec)
		if err != nil {
			return "", err
		}
		if _, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://management.azure.com/.default"}}); err != nil {
			return "", err
		}
		return "ARM token acquired for subscription " + firstNonEmpty(a.SubscriptionID, "(default)"), nil
	case "gcp":
		if a.ProjectID == "" {
			return "", fmt.Errorf("project_id not set")
		}
		svc, err := crm.NewService(ctx, core.GCPOptions(spec)...)
		if err != nil {
			return "", err
		}
		p, err := svc.Projects.Get(a.ProjectID).Context(ctx).Do()
		if err != nil {
			return "", err
		}
		return "project " + p.ProjectId + " readable", nil
	case "kubernetes":
		args := []string{"config", "current-context"}
		if a.KubeContext != "" {
			args = []string{"config", "get-contexts", a.KubeContext, "-o", "name"}
		}
		out, err := exec.CommandContext(ctx, "kubectl", args...).Output()
		if err != nil {
			return "", fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
		}
		return "context " + strings.TrimSpace(string(out)), nil
	case "github", "okta", "m365":
		env := firstNonEmpty(a.TokenEnv, map[string]string{"github": "GITHUB_TOKEN", "okta": "OKTA_API_TOKEN", "m365": "M365_CLIENT_SECRET"}[a.Provider])
		if os.Getenv(env) == "" {
			return "", fmt.Errorf("$%s is not set", env)
		}
		return "$" + env + " is set (value not shown)", nil
	}
	return "", errNoIdentityCheck
}

func toolVersion(ctx context.Context, path string) (string, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			return l, nil
		}
	}
	return "(no version output)", nil
}

func headURL(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// stsIdentity is the caller ARN of a GetCallerIdentity reply; a reply without one (a garbage
// 200 body decodes to an empty output) is an error, never a nil dereference (Verification 6).
func stsIdentity(out *sts.GetCallerIdentityOutput) (string, error) {
	if out == nil || out.Arn == nil || *out.Arn == "" || out.Account == nil || *out.Account == "" {
		return "", fmt.Errorf("sts:GetCallerIdentity returned no account / ARN (unreadable reply)")
	}
	return *out.Arn, nil
}
