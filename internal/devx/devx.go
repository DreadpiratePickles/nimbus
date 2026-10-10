// Package devx holds the developer-experience surfaces: one-command onboarding (credential
// detection + org-wide AWS role StackSet), pre-commit hooks, GitHub Action, and the
// interactive tutorial that teaches cloud security on the user's own findings.
package devx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Detected is one credential source found on the machine.
type Detected struct {
	Provider string `json:"provider"`
	Account  config.Account
	Identity string `json:"identity"`
	Detail   string `json:"detail"`
	Err      string `json:"error,omitempty"`
}

func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", fmt.Errorf("%s not installed", name)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %s", name, strings.TrimSpace(firstLine(errb.String())))
	}
	return strings.TrimSpace(out.String()), nil
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i > 0 {
		return s[:i]
	}
	return s
}

// Detect probes aws/az/gcloud/kubectl/gh/okta/m365 credentials present locally (agentless, read-only).
func Detect(ctx context.Context, want map[string]bool) []Detected {
	var out []Detected
	has := func(p string) bool { return len(want) == 0 || want[p] }
	if has("aws") {
		profiles := []string{""}
		if lst, err := run(ctx, 10*time.Second, "aws", "configure", "list-profiles"); err == nil && lst != "" {
			profiles = strings.Split(lst, "\n")
		}
		for _, p := range profiles {
			args := []string{"sts", "get-caller-identity", "--output", "json"}
			if p != "" {
				args = append(args, "--profile", p)
			}
			d := Detected{Provider: "aws", Account: config.Account{Provider: "aws", Profile: p, Tools: []string{"native", "python-checks", "prowler", "steampipe"}}}
			o, err := run(ctx, 20*time.Second, "aws", args...)
			if err != nil {
				d.Err = err.Error()
			} else {
				var id struct{ Account, Arn string }
				json.Unmarshal([]byte(o), &id)
				d.Identity = id.Arn
				d.Detail = "account " + id.Account
				d.Account.Name = "aws-" + strings.TrimPrefix(firstNonEmpty(p, id.Account), "default")
				if d.Account.Name == "aws-" {
					d.Account.Name = "aws-" + id.Account
				}
			}
			out = append(out, d)
		}
	}
	if has("azure") {
		d := Detected{Provider: "azure", Account: config.Account{Provider: "azure", Tools: []string{"native", "prowler", "steampipe"}}}
		if o, err := run(ctx, 20*time.Second, "az", "account", "list", "--output", "json", "--only-show-errors"); err != nil {
			d.Err = err.Error()
			out = append(out, d)
		} else {
			var subs []struct {
				ID, Name, TenantID string
				User               struct{ Name string }
			}
			json.Unmarshal([]byte(o), &subs)
			for _, sdesc := range subs {
				dd := d
				dd.Account.SubscriptionID, dd.Account.TenantID = sdesc.ID, sdesc.TenantID
				dd.Account.Name = "azure-" + slug(sdesc.Name)
				dd.Identity = sdesc.User.Name
				dd.Detail = "subscription " + sdesc.Name
				out = append(out, dd)
			}
			if len(subs) == 0 {
				d.Err = "no subscriptions (run az login)"
				out = append(out, d)
			}
		}
	}
	if has("gcp") {
		d := Detected{Provider: "gcp", Account: config.Account{Provider: "gcp", Tools: []string{"native", "prowler", "steampipe"}}}
		if o, err := run(ctx, 20*time.Second, "gcloud", "projects", "list", "--format", "json"); err != nil {
			d.Err = err.Error()
			out = append(out, d)
		} else {
			var projs []struct {
				ProjectID string `json:"projectId"`
				Name      string `json:"name"`
			}
			json.Unmarshal([]byte(o), &projs)
			acct, _ := run(ctx, 10*time.Second, "gcloud", "config", "get-value", "account")
			for _, p := range projs {
				dd := d
				dd.Account.ProjectID = p.ProjectID
				dd.Account.Name = "gcp-" + slug(p.ProjectID)
				dd.Identity = acct
				dd.Detail = "project " + p.Name
				out = append(out, dd)
			}
		}
	}
	if has("kubernetes") {
		if o, err := run(ctx, 10*time.Second, "kubectl", "config", "get-contexts", "-o", "name"); err == nil {
			for _, c := range strings.Split(o, "\n") {
				if c = strings.TrimSpace(c); c != "" {
					out = append(out, Detected{Provider: "kubernetes", Account: config.Account{Provider: "kubernetes", KubeContext: c, Name: "k8s-" + slug(c), Tools: []string{"native", "trivy", "checkov", "steampipe"}}, Detail: "context " + c})
				}
			}
		}
	}
	if has("github") {
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
			d := Detected{Provider: "github", Account: config.Account{Provider: "github", TokenEnv: "GITHUB_TOKEN", Tools: []string{"native", "prowler", "steampipe"}}}
			if o, err := run(ctx, 10*time.Second, "gh", "api", "user", "--jq", ".login"); err == nil {
				d.Identity = o
				d.Account.Name, d.Account.Org = "github-"+slug(o), o
			} else {
				d.Account.Name = "github"
				d.Detail = "GITHUB_TOKEN present (set org: in config)"
			}
			out = append(out, d)
		}
	}
	if has("okta") && os.Getenv("OKTA_ORG_URL") != "" {
		out = append(out, Detected{Provider: "okta", Account: config.Account{Provider: "okta", Name: "okta", Domain: os.Getenv("OKTA_ORG_URL"), TokenEnv: "OKTA_API_TOKEN", Tools: []string{"native", "steampipe"}}, Detail: os.Getenv("OKTA_ORG_URL")})
	}
	if has("m365") && os.Getenv("M365_TENANT_ID") != "" {
		out = append(out, Detected{Provider: "m365", Account: config.Account{Provider: "m365", Name: "m365", TenantID: os.Getenv("M365_TENANT_ID"), Tools: []string{"native", "prowler"}}, Detail: "tenant " + os.Getenv("M365_TENANT_ID")})
	}
	return out
}

func slug(s string) string {
	return strings.Trim(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return '-'
	}, s), "-")
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// AWSOrgStackSet returns a CloudFormation template that creates a read-only cross-account
// role (with External ID) in every member account — the Prowler/Wiz-style org-wide onboarding.
func AWSOrgStackSet(trustedAccount, externalID string) string {
	return fmt.Sprintf(`AWSTemplateFormatVersion: '2010-09-09'
Description: cloud-posture read-only scanning role (deploy as a StackSet to the organization)
Parameters:
  TrustedAccountId:
    Type: String
    Default: "%s"
  ExternalId:
    Type: String
    Default: "%s"
Resources:
  CloudPostureRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: CloudPostureScanRole
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: {AWS: !Sub "arn:aws:iam::${TrustedAccountId}:root"}
            Action: sts:AssumeRole
            Condition:
              StringEquals: {"sts:ExternalId": !Ref ExternalId}
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecurityAudit
        - arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
      Policies:
        - PolicyName: CloudPostureExtraRead
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - ce:GetCostAndUsage
                  - cloudwatch:GetMetricStatistics
                  - cloudtrail:LookupEvents
                  - account:Get*
                  - access-analyzer:List*
                  - securityhub:Get*
                  - guardduty:Get*
                  - guardduty:List*
                  - eks:Describe*
                  - eks:List*
                  - lambda:GetFunctionUrlConfig
                  - s3:GetAccountPublicAccessBlock
                Resource: "*"
Outputs:
  RoleArn:
    Value: !GetAtt CloudPostureRole.Arn
`, trustedAccount, externalID)
}

// PreCommitHook returns .pre-commit-hooks.yaml content and the local hook script.
const PreCommitHooksYAML = `# Use from another repo's .pre-commit-config.yaml:
#   - repo: https://github.com/DreadpiratePickles/nimbus
#     rev: v0.1.0
#     hooks: [{id: cloud-posture-iac}]
- id: cloud-posture-iac
  name: cloud-posture IaC scan
  description: Block commits that introduce cloud misconfigurations (Terraform, CloudFormation, Bicep, Kubernetes, Helm).
  entry: cloud-posture scan --iac . --output table --fail-on HIGH --changed-only --no-store
  language: system
  pass_filenames: false
  files: '\.(tf|tfvars|ya?ml|json|bicep)$'
`

const GitHookScript = `#!/bin/sh
# Installed by: cloud-posture hook install
# Blocks commits that introduce HIGH/CRITICAL IaC misconfigurations in staged files.
if ! command -v cloud-posture >/dev/null 2>&1; then exit 0; fi
exec cloud-posture scan --iac . --output table --fail-on HIGH --changed-only --no-store
`

// InstallGitHook writes .git/hooks/pre-commit in the repo.
func InstallGitHook(repo string) (string, error) {
	gitDir, err := run(context.Background(), 5*time.Second, "git", "-C", repo, "rev-parse", "--git-dir")
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(repo, gitDir)
	}
	path := filepath.Join(gitDir, "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	return path, os.WriteFile(path, []byte(GitHookScript), 0o755)
}

// GitHubWorkflow is the reusable workflow users drop into .github/workflows/.
const GitHubWorkflow = `name: cloud-posture
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'   # continuous compliance: daily scan
permissions:
  contents: read
  pull-requests: write
  security-events: write
  id-token: write          # OIDC to the cloud, no long-lived keys
jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DreadpiratePickles/nimbus@v0.1.0
        with:
          iac-path: .
          fail-on: HIGH
          sarif: true
          pr-comment: true
          # cloud scans (optional): configure OIDC first
          # accounts: aws-prod
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`

// ActionYAML is the composite GitHub Action definition for this repo.
const ActionYAML = `name: cloud-posture
description: Scan IaC and cloud accounts, post results as a PR comment and SARIF code scanning alerts, fail on severity.
branding: {icon: shield, color: blue}
inputs:
  iac-path: {description: Directory of IaC to scan, default: "."}
  accounts: {description: Comma-separated accounts from cloud-posture.yaml (cloud scans), default: ""}
  fail-on: {description: Minimum severity that fails the job, default: HIGH}
  sarif: {description: Upload SARIF to GitHub code scanning, default: "true"}
  pr-comment: {description: Post a sticky PR comment with results, default: "true"}
  version: {description: cloud-posture release to install, default: latest}
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        set -euo pipefail
        curl -fsSL https://raw.githubusercontent.com/DreadpiratePickles/nimbus/main/install.sh | bash -s -- "${{ inputs.version }}"
    - shell: bash
      run: |
        set -euo pipefail
        ARGS="--iac ${{ inputs.iac-path }} --output json --out-file cloud-posture.json --sarif cloud-posture.sarif --fail-on ${{ inputs.fail-on }}"
        if [ -n "${{ inputs.accounts }}" ]; then ARGS="$ARGS --accounts ${{ inputs.accounts }}"; fi
        cloud-posture scan $ARGS || echo "CP_FAILED=1" >> "$GITHUB_ENV"
    - if: inputs.sarif == 'true' && hashFiles('cloud-posture.sarif') != ''
      uses: github/codeql-action/upload-sarif@v3
      with: {sarif_file: cloud-posture.sarif}
    - if: inputs.pr-comment == 'true' && github.event_name == 'pull_request'
      shell: bash
      run: cloud-posture pr-comment --results cloud-posture.json --repo "${{ github.repository }}" --pr "${{ github.event.pull_request.number }}"
      env: {GITHUB_TOKEN: "${{ github.token }}"}
    - shell: bash
      run: if [ "${CP_FAILED:-0}" = "1" ]; then echo "::error::findings at or above ${{ inputs.fail-on }}"; exit 1; fi
`

// ---------------------------------------------------------------- interactive tutorial

type Lesson struct {
	ID        string
	Title     string
	Canonical []string // findings that make this lesson "live"
	Explain   string
	Exploit   string // how an attacker abuses it (defensive framing)
	Fix       string
	Verify    string
	Mitre     string
}

var Lessons = []Lesson{
	{ID: "public-bucket", Title: "Public storage buckets", Canonical: []string{"S3_PUBLIC_BUCKET", "AZ_STORAGE_PUBLIC_BLOB", "GCP_BUCKET_PUBLIC"},
		Explain: "A bucket with a public ACL or policy is readable by anyone with the URL. Most large data breaches of the last decade started here (Capital One, Accenture, Twilio).",
		Exploit: "Attackers scan bucket names (company-backups, prod-exports) and list objects with `aws s3 ls s3://<name> --no-sign-request`. Logging is often off, so the read is silent.",
		Fix:     "Block public access at the account and bucket level, enforce BucketOwnerEnforced ownership, then audit policies for Principal \"*\". `cloud-posture fix --finding S3_PUBLIC_BUCKET --generate-terraform`",
		Verify:  "Re-run `cloud-posture scan` and confirm the finding flips to PASS; query `SELECT name FROM aws_s3_buckets WHERE public_access = 1` returns nothing.", Mitre: "T1530 Data from Cloud Storage"},
	{ID: "open-ssh", Title: "Security groups open to the world", Canonical: []string{"EC2_SG_OPEN_SSH", "EC2_SG_OPEN_RDP", "EC2_SG_OPEN_ALL", "AZ_NSG_OPEN_SSH", "GCP_FIREWALL_OPEN_SSH"},
		Explain: "0.0.0.0/0 on port 22/3389 exposes management ports to every internet scanner. Combined with a weak password or an unpatched service this is remote code execution.",
		Exploit: "Shodan/Censys index the host within hours; credential stuffing and CVE scanners follow. cloud-posture draws this as the first hop of an attack path.",
		Fix:     "Replace the CIDR with an allow-list or remove the rule and use SSM Session Manager / Azure Bastion / IAP. `cloud-posture fix --finding EC2_SG_OPEN_SSH --generate-terraform`",
		Verify:  "`cloud-posture paths` should no longer list the instance as an entry point.", Mitre: "T1190 Exploit Public-Facing Application"},
	{ID: "imdsv1", Title: "IMDSv1 and credential theft", Canonical: []string{"EC2_IMDSV1"},
		Explain: "IMDSv1 answers any GET to 169.254.169.254, so an SSRF or a compromised container on the box can read the instance role's temporary credentials.",
		Exploit: "This is exactly the Capital One path: SSRF → metadata → role credentials → S3. IMDSv2 requires a PUT with a hop-limit token first.",
		Fix:     "Set http_tokens = required and hop limit 1. `cloud-posture fix --finding EC2_IMDSV1 --generate-terraform`", Verify: "The attack path 'Internet → instance → role' disappears from `cloud-posture paths`.", Mitre: "T1552.005 Cloud Instance Metadata API"},
	{ID: "admin-policy", Title: "Wildcard administrative policies", Canonical: []string{"IAM_ADMIN_POLICY", "GCP_IAM_PRIMITIVE_ROLE", "K8S_CLUSTER_ADMIN_BINDING", "AZ_AKS_RBAC_DISABLED"},
		Explain: "*:* turns any compromised principal into a full account compromise. It is the most common choke point: fixing it breaks the most attack paths.",
		Exploit: "Any stolen key or role session attached to the policy can create users, disable logging and exfiltrate data.",
		Fix:     "Generate a least-privilege policy from CloudTrail activity (IAM Access Analyzer policy generation), then swap it in. `cloud-posture fix --finding IAM_ADMIN_POLICY --generate-terraform`",
		Verify:  "`cloud-posture paths --fixes` should show the policy no longer in the min-fix set.", Mitre: "T1078.004 Cloud Accounts"},
	{ID: "mfa", Title: "Identities without MFA", Canonical: []string{"IAM_ROOT_NO_MFA", "IAM_USER_NO_MFA", "AZ_MFA_DISABLED", "GH_ORG_NO_2FA", "OKTA_ADMIN_NO_MFA", "M365_NO_MFA_ADMIN"},
		Explain: "Password-only identities fall to phishing and credential stuffing. Root/global-admin without MFA is the single worst finding in any account.",
		Exploit: "Phished credentials → console login → persistence (new access keys) → privilege escalation. No network exposure needed, so it is an entry point in the graph.",
		Fix:     "Enforce hardware MFA for root/admins and MFA policies for everyone; block legacy auth.", Verify: "Rescan: `SELECT * FROM aws_iam_users WHERE mfa_enabled = 0` is empty.", Mitre: "T1078 Valid Accounts"},
	{ID: "logging", Title: "Audit logging gaps", Canonical: []string{"CLOUDTRAIL_DISABLED", "CLOUDTRAIL_NO_LOG_VALIDATION", "S3_NO_LOGGING"},
		Explain: "Without CloudTrail / activity logs you cannot investigate or detect; attackers disable it first (StopLogging). cloud-posture treats missing logs as a risk multiplier on every path.",
		Exploit: "The median breach takes 241 days to identify (IBM 2025); logging gaps are why.",
		Fix:     "Multi-region organization trail with log validation to a locked bucket. `cloud-posture fix --finding CLOUDTRAIL_DISABLED --generate-terraform`", Verify: "`cloud-posture monitor` starts receiving CloudTrail events.", Mitre: "T1562.008 Disable Cloud Logs"},
	{ID: "privileged-pods", Title: "Privileged containers", Canonical: []string{"K8S_PRIVILEGED_CONTAINER", "K8S_HOST_NETWORK", "K8S_HOST_PATH", "K8S_PRIVILEGE_ESCALATION"},
		Explain: "privileged: true or host namespaces let a container escape to the node, read every pod's secrets and the kubelet credentials.",
		Exploit: "Exploit in the app → container escape → node → cluster-admin via mounted tokens.",
		Fix:     "Pod Security Standards 'restricted', drop capabilities, no hostPath. `cloud-posture fix --finding K8S_PRIVILEGED_CONTAINER --format kubernetes`", Verify: "`trivy k8s` / cloud-posture show no privileged pods in the namespace.", Mitre: "T1611 Escape to Host"},
}

// Pick returns the lessons that apply to the user's own findings, most severe first.
func Pick(findings []model.Finding) []struct {
	Lesson   Lesson
	Examples []model.Finding
} {
	type item = struct {
		Lesson   Lesson
		Examples []model.Finding
	}
	var out []item
	for _, l := range Lessons {
		var ex []model.Finding
		for _, f := range findings {
			if f.Status != model.Fail {
				continue
			}
			for _, c := range l.Canonical {
				if f.CanonicalID == c {
					ex = append(ex, f)
					break
				}
			}
		}
		if len(ex) > 0 {
			out = append(out, item{l, ex})
		}
	}
	return out
}
