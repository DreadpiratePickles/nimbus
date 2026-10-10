package cli

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/spf13/cobra"

	"github.com/DreadpiratePickles/nimbus/internal/devx"
)

// readOnlyPolicyAWS is the least-privilege policy generated from the collectors' API
// calls (docs/iam/readonly-policy-aws.json; kept identical by TestReadOnlyPolicies).
//
//go:embed iam/readonly-policy-aws.json
var readOnlyPolicyAWS string

const (
	onboardRoleName      = "CloudPostureScanRole"
	onboardPolicyName    = "CloudPostureReadOnly"
	onboardStackSetName  = "cloud-posture"
	onboardTagKey        = "managed-by"
	onboardTagValue      = "cloud-posture"
	securityAuditARN     = "arn:aws:iam::aws:policy/SecurityAudit"
	manifestVersion      = 1
	kindIAMPolicy        = "aws_iam_policy"
	kindIAMRole          = "aws_iam_role"
	kindIAMAttachment    = "aws_iam_role_policy_attachment"
	kindStackSet         = "aws_cloudformation_stack_set"
	kindStackSetInstance = "aws_cloudformation_stack_instances"
)

// errNotFound marks "already gone" during rollback.
var errNotFound = errors.New("not found")

// errRollbackRefused is matched (errors.Is) by every rollbackRefusedError.
var errRollbackRefused = errors.New("rollback refused")

const (
	refuseAccountMismatch = "account-mismatch"
	refuseNotAllowlisted  = "not-allowlisted"
	refuseNotTagged       = "not-tagged"
	refuseBadManifest     = "bad-manifest"
)

// rollbackRefusedError is returned before any delete when the manifest does not
// describe resources onboard created in the account the credentials belong to.
type rollbackRefusedError struct {
	Reason   string // one of the refuse* constants
	Resource string
	Detail   string
}

func (e *rollbackRefusedError) Error() string {
	s := "rollback refused (" + e.Reason + ")"
	if e.Resource != "" {
		s += ": " + e.Resource
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s + "; nothing was deleted"
}

func (e *rollbackRefusedError) Is(target error) bool { return target == errRollbackRefused }

// awsOnboardAPI is the IAM/STS surface onboard and offboard use (fakes in tests).
type awsOnboardAPI interface {
	AccountID(ctx context.Context) (string, error)
	CreatePolicy(ctx context.Context, name, document string) (arn string, err error)
	DeletePolicy(ctx context.Context, arn string) error
	CreateRole(ctx context.Context, name, trustDocument string) (arn string, err error)
	DeleteRole(ctx context.Context, name string) error
	AttachRolePolicy(ctx context.Context, role, policyARN string) error
	DetachRolePolicy(ctx context.Context, role, policyARN string) error
	RoleExists(ctx context.Context, name string) (bool, error)
	PolicyExists(ctx context.Context, arn string) (bool, error)
	AttachmentExists(ctx context.Context, role, policyARN string) (bool, error)
	// RoleTags / PolicyTags return the resource's tags (errNotFound when it is gone).
	RoleTags(ctx context.Context, name string) (map[string]string, error)
	PolicyTags(ctx context.Context, arn string) (map[string]string, error)
}

// stackSetAPI is the CloudFormation StackSet surface (the AWS CLI; there is no
// CloudFormation SDK module in go.mod).
type stackSetAPI interface {
	CreateStackSet(ctx context.Context, name, template string, params map[string]string) (id string, err error)
	CreateStackInstances(ctx context.Context, name string, ous, regions []string) (operationID string, err error)
	DeleteStackInstances(ctx context.Context, name string, ous, regions []string) error
	DeleteStackSet(ctx context.Context, name string) error
	StackSetExists(ctx context.Context, name string) (bool, error)
}

var (
	newAWSOnboard = func(ctx context.Context, profile string) (awsOnboardAPI, error) {
		return newAWSOnboardSDK(ctx, profile)
	}
	newStackSets = func(profile string) stackSetAPI { return &stackSetCLI{profile: profile} }
)

// onboardManifest lists every cloud resource onboard created, in creation order.
type onboardManifest struct {
	Version  int    `json:"version"`
	Provider string `json:"provider"`
	Account  string `json:"account"`
	// ManagementAccount is the account (STS caller identity) the StackSet was created
	// in; rollback refuses to touch a StackSet unless the credentials match it.
	ManagementAccount string             `json:"management_account,omitempty"`
	Tags              map[string]string  `json:"tags,omitempty"` // tags onboard put on every IAM resource
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
	Resources         []manifestResource `json:"resources"`
}

type manifestResource struct {
	Kind      string    `json:"kind"`
	ID        string    `json:"id"` // name, StackSet id or operation id
	ARN       string    `json:"arn,omitempty"`
	Role      string    `json:"role,omitempty"` // attachments
	PolicyARN string    `json:"policy_arn,omitempty"`
	StackSet  string    `json:"stack_set,omitempty"`
	OUs       []string  `json:"ous,omitempty"`
	Regions   []string  `json:"regions,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func manifestPath(dir, account string) string {
	return filepath.Join(firstNonEmpty(dir, ".cloud-posture"), "onboard-"+sanitizeName(account)+".json")
}

func sanitizeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func loadManifest(path string) (*onboardManifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m onboardManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// manifestWriter appends one resource at a time and rewrites the file immediately, so
// a failure halfway through onboarding still leaves a complete record for rollback.
type manifestWriter struct {
	path string
	m    *onboardManifest
}

func openManifest(dir, provider, account string) (*manifestWriter, error) {
	path := manifestPath(dir, account)
	m, err := loadManifest(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		m = &onboardManifest{Version: manifestVersion, Provider: provider, Account: account, Tags: map[string]string{onboardTagKey: onboardTagValue}, CreatedAt: time.Now().UTC()}
	}
	return &manifestWriter{path: path, m: m}, nil
}

func (w *manifestWriter) add(r manifestResource) error {
	r.CreatedAt = time.Now().UTC()
	w.m.Resources = append(w.m.Resources, r)
	w.m.UpdatedAt = r.CreatedAt
	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(w.m, "", "  ")
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.path)
}

func trustPolicy(trustedAccount, externalID string) string {
	doc := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
		"Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::" + trustedAccount + ":root"}, "Action": "sts:AssumeRole",
		"Condition": map[string]any{"StringEquals": map[string]any{"sts:ExternalId": externalID}},
	}}}
	b, _ := json.Marshal(doc)
	return string(b)
}

// deployAWSRole creates the read-only scanning role in the current account: the
// generated customer-managed policy, the role, and two attachments (the generated
// policy and AWS SecurityAudit). Every step is recorded before the next one starts.
func deployAWSRole(ctx context.Context, api awsOnboardAPI, dir, trusted, externalID string) (*manifestWriter, error) {
	acct, err := api.AccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws identity: %w", err)
	}
	w, err := openManifest(dir, "aws", acct)
	if err != nil {
		return nil, err
	}
	trusted = firstNonEmpty(trusted, acct)
	policyARN, err := api.CreatePolicy(ctx, onboardPolicyName, readOnlyPolicyAWS)
	if err != nil {
		return w, fmt.Errorf("create policy %s: %w", onboardPolicyName, err)
	}
	if err := w.add(manifestResource{Kind: kindIAMPolicy, ID: onboardPolicyName, ARN: policyARN}); err != nil {
		return w, err
	}
	roleARN, err := api.CreateRole(ctx, onboardRoleName, trustPolicy(trusted, externalID))
	if err != nil {
		return w, fmt.Errorf("create role %s: %w", onboardRoleName, err)
	}
	if err := w.add(manifestResource{Kind: kindIAMRole, ID: onboardRoleName, ARN: roleARN}); err != nil {
		return w, err
	}
	for _, p := range []string{policyARN, securityAuditARN} {
		if err := api.AttachRolePolicy(ctx, onboardRoleName, p); err != nil {
			return w, fmt.Errorf("attach %s: %w", p, err)
		}
		if err := w.add(manifestResource{Kind: kindIAMAttachment, ID: onboardRoleName + "|" + p, Role: onboardRoleName, PolicyARN: p}); err != nil {
			return w, err
		}
	}
	return w, nil
}

// deployStackSet creates the org-wide StackSet and its instances, recording both and
// the management account (caller identity) the StackSet lives in, so rollback can
// refuse to delete another management account's StackSet.
func deployStackSet(ctx context.Context, api stackSetAPI, ident awsOnboardAPI, dir, trusted, externalID string, ous, regions []string) (*manifestWriter, error) {
	if len(ous) == 0 || len(regions) == 0 {
		return nil, fmt.Errorf("--deploy needs --org-ous and --regions")
	}
	mgmt, err := ident.AccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws identity (the StackSet's management account is recorded for rollback): %w", err)
	}
	w, err := openManifest(dir, "aws", trusted)
	if err != nil {
		return nil, err
	}
	if w.m.ManagementAccount != "" && w.m.ManagementAccount != mgmt {
		return nil, fmt.Errorf("manifest %s already records StackSets in management account %s; the credentials are for %s", w.path, w.m.ManagementAccount, mgmt)
	}
	w.m.ManagementAccount = mgmt
	id, err := api.CreateStackSet(ctx, onboardStackSetName, devx.AWSOrgStackSet(trusted, externalID), map[string]string{"TrustedAccountId": trusted, "ExternalId": externalID})
	if err != nil {
		return w, fmt.Errorf("create stack set: %w", err)
	}
	if err := w.add(manifestResource{Kind: kindStackSet, ID: id, StackSet: onboardStackSetName}); err != nil {
		return w, err
	}
	op, err := api.CreateStackInstances(ctx, onboardStackSetName, ous, regions)
	if err != nil {
		return w, fmt.Errorf("create stack instances: %w", err)
	}
	return w, w.add(manifestResource{Kind: kindStackSetInstance, ID: op, StackSet: onboardStackSetName, OUs: ous, Regions: regions})
}

func runOnboardDeploy(ctx context.Context) error {
	f := &onboardFlags
	externalID := firstNonEmpty(f.externalID, "cloud-posture")
	var w *manifestWriter
	var err error
	if f.awsOrg != "" {
		var ident awsOnboardAPI
		if ident, err = newAWSOnboard(ctx, f.profile); err != nil {
			return err
		}
		w, err = deployStackSet(ctx, newStackSets(f.profile), ident, f.manifestDir, f.awsOrg, externalID, f.orgOUs, f.regions)
	} else {
		var api awsOnboardAPI
		if api, err = newAWSOnboard(ctx, f.profile); err != nil {
			return err
		}
		w, err = deployAWSRole(ctx, api, f.manifestDir, f.trusted, externalID)
	}
	if w != nil && len(w.m.Resources) > 0 {
		fmt.Printf("manifest: %s (%d resource(s))\n", w.path, len(w.m.Resources))
		for _, r := range w.m.Resources {
			fmt.Printf("  + %-34s %s\n", r.Kind, firstNonEmpty(r.ARN, r.ID))
		}
	}
	if err != nil {
		if w != nil && len(w.m.Resources) > 0 {
			return fmt.Errorf("%w (partial deploy recorded; undo with: cloud-posture offboard --rollback --account %s)", err, w.m.Account)
		}
		return err
	}
	fmt.Printf("\n✓ onboarded; undo with: cloud-posture offboard --rollback --account %s\n", w.m.Account)
	return nil
}

// ---------------------------------------------------------------- offboard

var offboardFlags struct {
	rollback    bool
	account     string
	manifestDir string
	profile     string
}

var offboardCmd = &cobra.Command{
	Use:   "offboard",
	Short: "Remove exactly what `onboard` created (from its manifest); dry run unless --rollback",
	Example: `  cloud-posture offboard --account 123456789012            # show what would be removed
  cloud-posture offboard --rollback --account 123456789012 # delete it and verify nothing remains`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := pickManifest(offboardFlags.manifestDir, offboardFlags.account)
		if err != nil {
			return err
		}
		m, err := loadManifest(path)
		if err != nil {
			return err
		}
		fmt.Printf("manifest %s: %d resource(s) in %s account %s\n", path, len(m.Resources), m.Provider, m.Account)
		if !offboardFlags.rollback {
			for i := len(m.Resources) - 1; i >= 0; i-- {
				r := m.Resources[i]
				fmt.Printf("  would delete %-34s %s\n", r.Kind, firstNonEmpty(r.ARN, r.ID))
			}
			fmt.Println("dry run: pass --rollback to delete these")
			return nil
		}
		return rollback(cmd.Context(), path, m, offboardFlags.profile)
	},
}

func init() {
	offboardCmd.Flags().BoolVar(&offboardFlags.rollback, "rollback", false, "delete every resource in the onboarding manifest, then verify none remain")
	offboardCmd.Flags().StringVar(&offboardFlags.account, "account", "", "account whose manifest to use (onboard-<account>.json)")
	offboardCmd.Flags().StringVar(&offboardFlags.manifestDir, "manifest-dir", ".cloud-posture", "directory holding onboard manifests")
	offboardCmd.Flags().StringVar(&offboardFlags.profile, "profile", "", "AWS profile for the deletions")
	root.AddCommand(offboardCmd)
}

func pickManifest(dir, account string) (string, error) {
	if account != "" {
		return manifestPath(dir, account), nil
	}
	matches, _ := filepath.Glob(filepath.Join(firstNonEmpty(dir, ".cloud-posture"), "onboard-*.json"))
	var active []string
	for _, m := range matches {
		if !strings.Contains(filepath.Base(m), ".rolledback-") {
			active = append(active, m)
		}
	}
	if len(active) != 1 {
		return "", fmt.Errorf("found %d onboarding manifest(s) in %s; pass --account", len(active), firstNonEmpty(dir, ".cloud-posture"))
	}
	return active[0], nil
}

// rollback deletes the manifest's resources in reverse creation order (an already
// missing resource is fine), then re-checks each one and fails if anything remains.
func rollback(ctx context.Context, path string, m *onboardManifest, profile string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var iamAPI awsOnboardAPI
	needIAM, needStackSet := false, false
	for _, r := range m.Resources {
		if strings.HasPrefix(r.Kind, "aws_iam_") {
			needIAM = true
		}
		if r.Kind == kindStackSet || r.Kind == kindStackSetInstance {
			needStackSet = true
		}
	}
	if err := checkManifestAllowlist(m); err != nil {
		return err
	}
	if needIAM || needStackSet {
		var err error
		if iamAPI, err = newAWSOnboard(ctx, profile); err != nil {
			return err
		}
	}
	if needStackSet {
		if err := preflightStackSet(ctx, iamAPI, m); err != nil {
			return err
		}
	}
	if needIAM {
		if err := preflightIAM(ctx, iamAPI, m); err != nil {
			return err
		}
	}
	ss := newStackSets(profile)
	var errs []error
	for i := len(m.Resources) - 1; i >= 0; i-- {
		r := m.Resources[i]
		var err error
		switch r.Kind {
		case kindIAMAttachment:
			err = iamAPI.DetachRolePolicy(ctx, r.Role, r.PolicyARN)
		case kindIAMRole:
			err = iamAPI.DeleteRole(ctx, r.ID)
		case kindIAMPolicy:
			err = iamAPI.DeletePolicy(ctx, r.ARN)
		case kindStackSetInstance:
			err = ss.DeleteStackInstances(ctx, r.StackSet, r.OUs, r.Regions)
		case kindStackSet:
			err = ss.DeleteStackSet(ctx, r.StackSet)
		default:
			err = fmt.Errorf("unknown resource kind %q", r.Kind)
		}
		if err != nil && !errors.Is(err, errNotFound) {
			errs = append(errs, fmt.Errorf("%s %s: %w", r.Kind, firstNonEmpty(r.ARN, r.ID), err))
			continue
		}
		fmt.Printf("  - deleted %-34s %s\n", r.Kind, firstNonEmpty(r.ARN, r.ID))
	}
	// Verify: nothing the manifest lists may still exist.
	var remain []string
	for _, r := range m.Resources {
		var exists bool
		var err error
		switch r.Kind {
		case kindIAMAttachment:
			exists, err = iamAPI.AttachmentExists(ctx, r.Role, r.PolicyARN)
		case kindIAMRole:
			exists, err = iamAPI.RoleExists(ctx, r.ID)
		case kindIAMPolicy:
			exists, err = iamAPI.PolicyExists(ctx, r.ARN)
		case kindStackSet:
			exists, err = ss.StackSetExists(ctx, r.StackSet)
		}
		if err != nil {
			remain = append(remain, fmt.Sprintf("%s %s (check failed: %v)", r.Kind, firstNonEmpty(r.ARN, r.ID), err))
		} else if exists {
			remain = append(remain, r.Kind+" "+firstNonEmpty(r.ARN, r.ID))
		}
	}
	if len(remain) > 0 || len(errs) > 0 {
		return fmt.Errorf("rollback incomplete; still present: %s %w", strings.Join(remain, ", "), errors.Join(errs...))
	}
	retired := strings.TrimSuffix(path, ".json") + ".rolledback-" + time.Now().UTC().Format("20060102T150405Z") + ".json"
	if err := os.Rename(path, retired); err != nil {
		return err
	}
	fmt.Printf("✓ rollback verified: nothing remains of %d resource(s); manifest retired to %s\n", len(m.Resources), retired)
	return nil
}

// checkManifestAllowlist refuses (before any API call) a manifest that names anything
// onboard does not create: only the scan role, the generated read-only policy in the
// manifest's account, their two attachments and the cloud-posture StackSet qualify.
// An edited manifest naming OrganizationAccountAccessRole, an AWS-managed policy or a
// role in another account is refused as a whole.
func checkManifestAllowlist(m *onboardManifest) error {
	if m.Provider != "" && m.Provider != "aws" {
		return &rollbackRefusedError{Reason: refuseBadManifest, Detail: "provider " + m.Provider}
	}
	if !isAWSAccountID(m.Account) {
		return &rollbackRefusedError{Reason: refuseBadManifest, Detail: fmt.Sprintf("account %q is not a 12-digit AWS account id", m.Account)}
	}
	if len(m.Tags) > 0 && m.Tags[onboardTagKey] != onboardTagValue {
		return &rollbackRefusedError{Reason: refuseBadManifest, Detail: fmt.Sprintf("manifest tag %s=%q is not the onboard tag", onboardTagKey, m.Tags[onboardTagKey])}
	}
	roleARN := "arn:aws:iam::" + m.Account + ":role/" + onboardRoleName
	policyARN := "arn:aws:iam::" + m.Account + ":policy/" + onboardPolicyName
	for _, r := range m.Resources {
		label := r.Kind + " " + firstNonEmpty(r.ARN, r.ID, r.Role+"|"+r.PolicyARN, r.StackSet)
		ok := false
		switch r.Kind {
		case kindIAMRole:
			ok = r.ID == onboardRoleName && (r.ARN == "" || r.ARN == roleARN)
		case kindIAMPolicy:
			ok = r.ID == onboardPolicyName && r.ARN == policyARN
		case kindIAMAttachment:
			ok = r.Role == onboardRoleName && (r.PolicyARN == policyARN || r.PolicyARN == securityAuditARN)
		case kindStackSet, kindStackSetInstance:
			ok = r.StackSet == onboardStackSetName
		}
		if !ok {
			return &rollbackRefusedError{Reason: refuseNotAllowlisted, Resource: label,
				Detail: "offboard only removes " + onboardRoleName + ", " + onboardPolicyName + ", their attachments and the " + onboardStackSetName + " StackSet"}
		}
	}
	return nil
}

func isAWSAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// preflightStackSet refuses (read-only STS call, before any delete) to touch a
// StackSet unless the manifest records the management account it was created in and
// the credentials belong to that account. Manifests written before the management
// account was recorded are refused: delete such a StackSet by hand.
func preflightStackSet(ctx context.Context, api awsOnboardAPI, m *onboardManifest) error {
	if !isAWSAccountID(m.ManagementAccount) {
		return &rollbackRefusedError{Reason: refuseBadManifest, Resource: kindStackSet + " " + onboardStackSetName,
			Detail: "the manifest does not record the management account the StackSet was created in"}
	}
	acct, err := api.AccountID(ctx)
	if err != nil {
		return fmt.Errorf("aws identity (needed to check the StackSet's management account before deleting): %w", err)
	}
	if acct != m.ManagementAccount {
		return &rollbackRefusedError{Reason: refuseAccountMismatch, Resource: kindStackSet + " " + onboardStackSetName,
			Detail: fmt.Sprintf("the StackSet was created in management account %s but the credentials are for account %s", m.ManagementAccount, acct)}
	}
	return nil
}

// preflightIAM runs read-only calls only: the credentials must belong to the
// manifest's account, and every role/policy still present must carry the onboard
// tag (one with the onboard name but without the tag was not created by onboard).
func preflightIAM(ctx context.Context, api awsOnboardAPI, m *onboardManifest) error {
	acct, err := api.AccountID(ctx)
	if err != nil {
		return fmt.Errorf("aws identity (needed to check the manifest account before deleting): %w", err)
	}
	if acct != m.Account {
		return &rollbackRefusedError{Reason: refuseAccountMismatch,
			Detail: fmt.Sprintf("manifest is for account %s but the credentials are for account %s", m.Account, acct)}
	}
	for _, r := range m.Resources {
		var tags map[string]string
		switch r.Kind {
		case kindIAMRole:
			tags, err = api.RoleTags(ctx, r.ID)
		case kindIAMPolicy:
			tags, err = api.PolicyTags(ctx, r.ARN)
		default:
			continue // attachments are covered by their role; StackSets by name
		}
		if errors.Is(err, errNotFound) {
			continue // already gone
		}
		if err != nil {
			return fmt.Errorf("read tags of %s %s: %w", r.Kind, firstNonEmpty(r.ARN, r.ID), err)
		}
		if tags[onboardTagKey] != onboardTagValue {
			return &rollbackRefusedError{Reason: refuseNotTagged, Resource: r.Kind + " " + firstNonEmpty(r.ARN, r.ID),
				Detail: fmt.Sprintf("missing tag %s=%s, so onboard did not create it", onboardTagKey, onboardTagValue)}
		}
	}
	return nil
}

// ---------------------------------------------------------------- real clients

type awsOnboardSDK struct {
	iam *iam.Client
	sts *sts.Client
}

func newAWSOnboardSDK(ctx context.Context, profile string) (*awsOnboardSDK, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &awsOnboardSDK{iam: iam.NewFromConfig(cfg), sts: sts.NewFromConfig(cfg)}, nil
}

var onboardTags = []iamtypes.Tag{{Key: awssdk.String(onboardTagKey), Value: awssdk.String(onboardTagValue)}}

func notFound(err error) error {
	var ae smithy.APIError
	if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchEntity" {
		return errNotFound
	}
	return err
}

func (a *awsOnboardSDK) AccountID(ctx context.Context) (string, error) {
	out, err := a.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return awssdk.ToString(out.Account), nil
}

func (a *awsOnboardSDK) CreatePolicy(ctx context.Context, name, doc string) (string, error) {
	out, err := a.iam.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: &name, PolicyDocument: &doc,
		Description: awssdk.String("cloud-posture read-only scanning (generated from collector API calls)"), Tags: onboardTags})
	if err != nil {
		return "", err
	}
	return awssdk.ToString(out.Policy.Arn), nil
}

func (a *awsOnboardSDK) DeletePolicy(ctx context.Context, arn string) error {
	_, err := a.iam.DeletePolicy(ctx, &iam.DeletePolicyInput{PolicyArn: &arn})
	return notFound(err)
}

func (a *awsOnboardSDK) CreateRole(ctx context.Context, name, trust string) (string, error) {
	out, err := a.iam.CreateRole(ctx, &iam.CreateRoleInput{RoleName: &name, AssumeRolePolicyDocument: &trust,
		Description: awssdk.String("cloud-posture read-only scanning role"), Tags: onboardTags})
	if err != nil {
		return "", err
	}
	return awssdk.ToString(out.Role.Arn), nil
}

func (a *awsOnboardSDK) DeleteRole(ctx context.Context, name string) error {
	_, err := a.iam.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: &name})
	return notFound(err)
}

func (a *awsOnboardSDK) AttachRolePolicy(ctx context.Context, role, arn string) error {
	_, err := a.iam.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{RoleName: &role, PolicyArn: &arn})
	return err
}

func (a *awsOnboardSDK) DetachRolePolicy(ctx context.Context, role, arn string) error {
	_, err := a.iam.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{RoleName: &role, PolicyArn: &arn})
	return notFound(err)
}

func (a *awsOnboardSDK) RoleExists(ctx context.Context, name string) (bool, error) {
	_, err := a.iam.GetRole(ctx, &iam.GetRoleInput{RoleName: &name})
	return existsResult(err)
}

func (a *awsOnboardSDK) PolicyExists(ctx context.Context, arn string) (bool, error) {
	_, err := a.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &arn})
	return existsResult(err)
}

func (a *awsOnboardSDK) AttachmentExists(ctx context.Context, role, arn string) (bool, error) {
	p := iam.NewListAttachedRolePoliciesPaginator(a.iam, &iam.ListAttachedRolePoliciesInput{RoleName: &role})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			if errors.Is(notFound(err), errNotFound) {
				return false, nil
			}
			return false, err
		}
		for _, ap := range page.AttachedPolicies {
			if awssdk.ToString(ap.PolicyArn) == arn {
				return true, nil
			}
		}
	}
	return false, nil
}

func (a *awsOnboardSDK) RoleTags(ctx context.Context, name string) (map[string]string, error) {
	tags := map[string]string{}
	p := iam.NewListRoleTagsPaginator(a.iam, &iam.ListRoleTagsInput{RoleName: &name})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, notFound(err)
		}
		for _, t := range page.Tags {
			tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
		}
	}
	return tags, nil
}

func (a *awsOnboardSDK) PolicyTags(ctx context.Context, arn string) (map[string]string, error) {
	tags := map[string]string{}
	p := iam.NewListPolicyTagsPaginator(a.iam, &iam.ListPolicyTagsInput{PolicyArn: &arn})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, notFound(err)
		}
		for _, t := range page.Tags {
			tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
		}
	}
	return tags, nil
}

func existsResult(err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	if errors.Is(notFound(err), errNotFound) {
		return false, nil
	}
	return false, err
}

// stackSetCLI drives `aws cloudformation` (service-managed StackSets).
type stackSetCLI struct{ profile string }

func (c *stackSetCLI) aws(ctx context.Context, args ...string) ([]byte, error) {
	if c.profile != "" {
		args = append(args, "--profile", c.profile)
	}
	cmd := exec.CommandContext(ctx, "aws", append([]string{"cloudformation"}, append(args, "--output", "json")...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if strings.Contains(msg, "StackSetNotFoundException") {
			return nil, errNotFound
		}
		return nil, fmt.Errorf("aws cloudformation %s: %v: %s", args[0], err, msg)
	}
	return out, nil
}

func (c *stackSetCLI) CreateStackSet(ctx context.Context, name, template string, params map[string]string) (string, error) {
	f, err := os.CreateTemp("", "cloud-posture-stackset-*.yaml")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	f.WriteString(template)
	f.Close()
	args := []string{"create-stack-set", "--stack-set-name", name, "--template-body", "file://" + f.Name(), "--capabilities", "CAPABILITY_NAMED_IAM",
		"--permission-model", "SERVICE_MANAGED", "--auto-deployment", "Enabled=false"}
	if len(params) > 0 {
		args = append(args, "--parameters")
		for k, v := range params {
			args = append(args, "ParameterKey="+k+",ParameterValue="+v)
		}
	}
	out, err := c.aws(ctx, args...)
	if err != nil {
		return "", err
	}
	var r struct{ StackSetId string }
	json.Unmarshal(out, &r)
	return r.StackSetId, nil
}

func (c *stackSetCLI) CreateStackInstances(ctx context.Context, name string, ous, regions []string) (string, error) {
	out, err := c.aws(ctx, append([]string{"create-stack-instances", "--stack-set-name", name, "--deployment-targets", "OrganizationalUnitIds=" + strings.Join(ous, ","), "--regions"}, regions...)...)
	if err != nil {
		return "", err
	}
	var r struct{ OperationId string }
	json.Unmarshal(out, &r)
	return r.OperationId, c.wait(ctx, name, r.OperationId)
}

func (c *stackSetCLI) DeleteStackInstances(ctx context.Context, name string, ous, regions []string) error {
	out, err := c.aws(ctx, append([]string{"delete-stack-instances", "--stack-set-name", name, "--deployment-targets", "OrganizationalUnitIds=" + strings.Join(ous, ","), "--no-retain-stacks", "--regions"}, regions...)...)
	if err != nil {
		return err
	}
	var r struct{ OperationId string }
	json.Unmarshal(out, &r)
	return c.wait(ctx, name, r.OperationId)
}

// wait polls a StackSet operation until it finishes (StackSet deletes need the
// instance deletion to complete first).
func (c *stackSetCLI) wait(ctx context.Context, name, op string) error {
	if op == "" {
		return nil
	}
	deadline := time.Now().Add(30 * time.Minute)
	for time.Now().Before(deadline) {
		out, err := c.aws(ctx, "describe-stack-set-operation", "--stack-set-name", name, "--operation-id", op)
		if err != nil {
			return err
		}
		var r struct{ StackSetOperation struct{ Status string } }
		json.Unmarshal(out, &r)
		switch r.StackSetOperation.Status {
		case "SUCCEEDED":
			return nil
		case "FAILED", "STOPPED":
			return fmt.Errorf("stack set operation %s %s", op, r.StackSetOperation.Status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(15 * time.Second):
		}
	}
	return fmt.Errorf("stack set operation %s: timeout", op)
}

func (c *stackSetCLI) DeleteStackSet(ctx context.Context, name string) error {
	_, err := c.aws(ctx, "delete-stack-set", "--stack-set-name", name)
	return err
}

func (c *stackSetCLI) StackSetExists(ctx context.Context, name string) (bool, error) {
	_, err := c.aws(ctx, "describe-stack-set", "--stack-set-name", name)
	return existsResult(err)
}
