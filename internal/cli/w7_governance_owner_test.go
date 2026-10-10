package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/config"
)

// W7-POLISH r5 #5: ownership out of the box. `governance init` reads owners from AWS
// Organizations account tags and Azure subscription tags (live for configured accounts, or
// --account-tags <file>), proposes per-account owners from them (an EKS/AKS/GKE cluster inherits
// the owner of the account it runs in), takes --owner <team> for defaults.owner and prompts for
// it on a TTY; doctor stops advising `governance init --write` once it ran (store_meta marker)
// and names the unassigned share with the next concrete step.

// labAccountTags is the test fixture: the tags the lab's AWS accounts and Azure subscription
// would carry in an organization (the lab estate itself has no account-level tags).
var labAccountTags = map[string]map[string]string{
	"aws/111111111111":                           {"owner": "platform-team", "cost-center": "cc-100"},
	"aws/222222222222":                           {"team": "payments"},
	"azure/00000000-0000-4000-8000-000000000001": {"owner": "azure-ops"},
}

func writeAccountTags(t *testing.T, dir string) string {
	t.Helper()
	b, _ := json.Marshal(labAccountTags)
	p := filepath.Join(dir, "account-tags.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var appliedRe = regexp.MustCompile(`applied to (\d+) open Issues: (\d+) unassigned \((\d+)%\)`)

func appliedShare(t *testing.T, out string) (un, open int) {
	t.Helper()
	m := appliedRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no applied line:\n%s", out)
	}
	open, _ = strconv.Atoi(m[1])
	un, _ = strconv.Atoi(m[2])
	return un, open
}

func govCfg(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "c.yaml")
	os.WriteFile(p, []byte("python:\n  enabled: false\n"), 0o600)
	return p
}

func TestGovernanceInitOwnersFromAccountTags(t *testing.T) {
	dir := labDB(t)
	cfgPath := govCfg(t, dir)
	out, err := runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--account-tags", writeAccountTags(t, dir), "--write")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	un, open := appliedShare(t, out)
	if pct(un, open) > 25 {
		t.Errorf("lab with account tags: %d of %d open Issues unassigned (%.0f%%), want ≤ 25%%:\n%s", un, open, pct(un, open), out)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"owner-account-aws-111111111111": "platform-team", "owner-account-aws-222222222222": "payments",
		"owner-account-azure-00000000-0000-4000-8000-000000000001": "azure-ops", "owner-account-kubernetes-nimbus-lab-eks": "platform-team"}
	got := map[string]string{}
	firstAcct, lastTag := -1, -1
	for i, r := range cfg.Governance.Rules {
		if strings.HasPrefix(r.ID, "owner-account-") {
			got[r.ID] = r.Owner
			if firstAcct < 0 {
				firstAcct = i
			}
		}
		if strings.HasPrefix(r.ID, "owner-tag-") {
			lastTag = i
		}
	}
	for id, o := range want {
		if got[id] != o {
			t.Errorf("rule %s owner %q, want %q (rules %v)", id, got[id], o, got)
		}
	}
	if firstAcct < lastTag {
		t.Errorf("resource owner tags must win over the account's owner: account rules start at %d, tag rules end at %d", firstAcct, lastTag)
	}
	b, _ := os.ReadFile(cfgPath)
	for _, why := range []string{`account tag owner="platform-team"`, "nimbus-lab-eks runs in aws/111111111111"} {
		if !strings.Contains(string(b), why) {
			t.Errorf("the block does not explain %q:\n%s", why, b)
		}
	}
	// A rerun with --force replaces the generated account rules instead of stacking them.
	if out, err := runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--account-tags", filepath.Join(dir, "account-tags.json"), "--write", "--force"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cfg, _ = config.Load(cfgPath)
	n := 0
	for _, r := range cfg.Governance.Rules {
		if r.ID == "owner-account-aws-111111111111" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("--force rerun: %d owner-account-aws-111111111111 rules", n)
	}
}

// Live lookup for configured accounts goes through accountTagsLookup (fakes here); under
// --no-network it is skipped and says so.
func TestGovernanceInitLiveAccountTagsAndNoNetwork(t *testing.T) {
	dir := labDB(t)
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("python:\n  enabled: false\naccounts:\n  prod:\n    provider: aws\n    profile: prod\n"), 0o600)
	prev := accountTagsLookup
	t.Cleanup(func() { accountTagsLookup = prev })
	calls := 0
	accountTagsLookup = func(_ context.Context, a *config.Account) (map[string]map[string]string, []string, error) {
		calls++
		return map[string]map[string]string{"aws/111111111111": {"owner": "platform-team"}}, nil, nil
	}
	t.Setenv("CLOUD_POSTURE_NO_NETWORK", "")
	out, err := runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir)
	if err != nil || calls != 1 || !strings.Contains(out, "owner-account-aws-111111111111") {
		t.Fatalf("live account tags: calls %d, err %v\n%s", calls, err, out)
	}
	t.Setenv("CLOUD_POSTURE_NO_NETWORK", "1")
	out, _ = runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir)
	if calls != 1 || !strings.Contains(out, "account tags: skipped (no-network)") {
		t.Errorf("no-network must skip the lookup and say so (calls %d):\n%s", calls, out)
	}
}

func TestGovernanceInitOwnerFlagAndPrompt(t *testing.T) {
	dir := labDB(t)
	cfgPath := govCfg(t, dir)
	out, err := runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--owner", "sec-triage", "--write")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cfg, _ := config.Load(cfgPath)
	if cfg.Governance.Defaults.Owner != "sec-triage" {
		t.Errorf("--owner: defaults.owner %q", cfg.Governance.Defaults.Owner)
	}
	if un, _ := appliedShare(t, out); un != 0 {
		t.Errorf("--owner leaves %d unassigned", un)
	}

	// TTY: prompts for the default owner when nothing proposes one; a non-TTY never prompts.
	prevTTY, prevIn := stdinIsTTY, promptInput
	t.Cleanup(func() { stdinIsTTY, promptInput = prevTTY, prevIn })
	stdinIsTTY = func() bool { return true }
	promptInput = strings.NewReader("triage-team\n")
	cfgPath2 := filepath.Join(dir, "c2.yaml")
	os.WriteFile(cfgPath2, []byte("python:\n  enabled: false\n"), 0o600)
	out, err = runErr(t, "-c", cfgPath2, "governance", "init", "--repo", dir, "--write")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cfg, _ = config.Load(cfgPath2)
	if cfg.Governance.Defaults.Owner != "triage-team" || !strings.Contains(out, "Default owner") {
		t.Errorf("TTY prompt: defaults.owner %q\n%s", cfg.Governance.Defaults.Owner, out)
	}
	stdinIsTTY = func() bool { return false }
	promptInput = strings.NewReader("should-not-be-read\n")
	cfgPath3 := filepath.Join(dir, "c3.yaml")
	os.WriteFile(cfgPath3, []byte("python:\n  enabled: false\n"), 0o600)
	out, _ = runErr(t, "-c", cfgPath3, "governance", "init", "--repo", dir, "--write")
	cfg, _ = config.Load(cfgPath3)
	if cfg.Governance.Defaults.Owner != "" || strings.Contains(out, "Default owner") {
		t.Errorf("non-TTY must not prompt: %q\n%s", cfg.Governance.Defaults.Owner, out)
	}
}

func TestDoctorOwnershipAfterGovernanceInit(t *testing.T) {
	dir := labDB(t)
	cfgPath := govCfg(t, dir)
	doctorOwnershipLine := func() string {
		flagConfig = cfgPath
		t.Cleanup(func() { flagConfig = "" })
		env := fakeDoctorEnv(nil, nil, nil)
		var lines []string
		cfg, _ := config.Load(cfgPath)
		doctorOwnership(cfg, flagDB, func(status, name, detail string) {
			if strings.HasPrefix(name, "ownership") {
				lines = append(lines, status+" "+detail)
			}
		})
		_ = env
		return strings.Join(lines, "\n")
	}
	before := doctorOwnershipLine()
	if !strings.Contains(before, "governance init --write") {
		t.Errorf("before init doctor should advise governance init --write: %s", before)
	}
	if out, err := runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--write"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	after := doctorOwnershipLine()
	if strings.Contains(after, "run `cloud-posture governance init --write`") {
		t.Errorf("doctor still advises the command that just ran: %s", after)
	}
	for _, want := range []string{"after governance init ran", "unassigned", "%", "defaults.owner", "--owner <team>"} {
		if !strings.Contains(after, want) {
			t.Errorf("doctor after init lacks %q: %s", want, after)
		}
	}
	// The next step names where the unassigned Issues are (the biggest account).
	if !strings.Contains(after, "most unassigned are in aws/111111111111") {
		t.Errorf("doctor does not name the account holding most unassigned Issues: %s", after)
	}
}
