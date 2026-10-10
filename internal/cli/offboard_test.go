package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeAWSOnboard is an in-memory IAM: roles, customer policies, attachments.
type fakeAWSOnboard struct {
	mu          sync.Mutex
	account     string
	roles       map[string]string // name -> trust doc
	policies    map[string]string // arn -> doc
	attachments map[string]bool   // role|policyArn
	failRole    bool
	tags        map[string]map[string]string // role name or policy arn -> tags
	mutations   int                          // create/delete/attach/detach calls
}

func newFakeAWSOnboard(account string) *fakeAWSOnboard {
	return &fakeAWSOnboard{account: account, roles: map[string]string{}, policies: map[string]string{}, attachments: map[string]bool{}, tags: map[string]map[string]string{}}
}

func (f *fakeAWSOnboard) AccountID(context.Context) (string, error) { return f.account, nil }
func (f *fakeAWSOnboard) CreatePolicy(_ context.Context, name, doc string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mutations++
	arn := "arn:aws:iam::" + f.account + ":policy/" + name
	if _, ok := f.policies[arn]; ok {
		return "", errors.New("EntityAlreadyExists")
	}
	if !json.Valid([]byte(doc)) {
		return "", errors.New("MalformedPolicyDocument")
	}
	f.policies[arn] = doc
	f.tags[arn] = map[string]string{"managed-by": "cloud-posture"}
	return arn, nil
}
func (f *fakeAWSOnboard) DeletePolicy(_ context.Context, arn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mutations++
	for k := range f.attachments {
		if strings.HasSuffix(k, "|"+arn) {
			return errors.New("DeleteConflict: policy still attached")
		}
	}
	if _, ok := f.policies[arn]; !ok {
		return errNotFound
	}
	delete(f.policies, arn)
	return nil
}
func (f *fakeAWSOnboard) CreateRole(_ context.Context, name, trust string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mutations++
	if f.failRole {
		return "", errors.New("AccessDenied: iam:CreateRole")
	}
	if _, ok := f.roles[name]; ok {
		return "", errors.New("EntityAlreadyExists")
	}
	f.roles[name] = trust
	f.tags[name] = map[string]string{"managed-by": "cloud-posture"}
	return "arn:aws:iam::" + f.account + ":role/" + name, nil
}
func (f *fakeAWSOnboard) DeleteRole(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mutations++
	for k := range f.attachments {
		if strings.HasPrefix(k, name+"|") {
			return errors.New("DeleteConflict: role has attached policies")
		}
	}
	if _, ok := f.roles[name]; !ok {
		return errNotFound
	}
	delete(f.roles, name)
	return nil
}
func (f *fakeAWSOnboard) AttachRolePolicy(_ context.Context, role, arn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mutations++
	f.attachments[role+"|"+arn] = true
	return nil
}
func (f *fakeAWSOnboard) DetachRolePolicy(_ context.Context, role, arn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mutations++
	if !f.attachments[role+"|"+arn] {
		return errNotFound
	}
	delete(f.attachments, role+"|"+arn)
	return nil
}
func (f *fakeAWSOnboard) RoleExists(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.roles[name]
	return ok, nil
}
func (f *fakeAWSOnboard) PolicyExists(_ context.Context, arn string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.policies[arn]
	return ok, nil
}
func (f *fakeAWSOnboard) AttachmentExists(_ context.Context, role, arn string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attachments[role+"|"+arn], nil
}

func (f *fakeAWSOnboard) RoleTags(_ context.Context, name string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.roles[name]; !ok {
		return nil, errNotFound
	}
	return f.tags[name], nil
}
func (f *fakeAWSOnboard) PolicyTags(_ context.Context, arn string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.policies[arn]; !ok {
		return nil, errNotFound
	}
	return f.tags[arn], nil
}

type fakeStackSets struct {
	mu        sync.Mutex
	sets      map[string]string   // name -> id
	instances map[string][]string // name -> ous
}

func (f *fakeStackSets) CreateStackSet(_ context.Context, name, template string, params map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(template, "AWS::IAM::Role") || params["TrustedAccountId"] == "" {
		return "", errors.New("bad template/params")
	}
	id := name + ":11111111-2222-3333-4444-555555555555"
	f.sets[name] = id
	return id, nil
}
func (f *fakeStackSets) CreateStackInstances(_ context.Context, name string, ous, regions []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sets[name]; !ok {
		return "", errNotFound
	}
	f.instances[name] = append(f.instances[name], ous...)
	return "op-1", nil
}
func (f *fakeStackSets) DeleteStackInstances(_ context.Context, name string, ous, regions []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.instances, name)
	return nil
}
func (f *fakeStackSets) DeleteStackSet(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.instances[name]) > 0 {
		return errors.New("OperationInProgress: stack set still has instances")
	}
	if _, ok := f.sets[name]; !ok {
		return errNotFound
	}
	delete(f.sets, name)
	return nil
}
func (f *fakeStackSets) StackSetExists(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.sets[name]
	return ok, nil
}

func useFakes(t *testing.T, aws *fakeAWSOnboard, ss *fakeStackSets) {
	t.Helper()
	oldA, oldS := newAWSOnboard, newStackSets
	newAWSOnboard = func(context.Context, string) (awsOnboardAPI, error) { return aws, nil }
	newStackSets = func(string) stackSetAPI { return ss }
	t.Cleanup(func() { newAWSOnboard, newStackSets = oldA, oldS })
	resetOnboardFlags()
	t.Cleanup(resetOnboardFlags)
}

func resetOnboardFlags() {
	onboardFlags = struct {
		providers   []string
		yes         bool
		scan        bool
		awsOrg      string
		externalID  string
		out         string
		deployRole  bool
		deploy      bool
		trusted     string
		orgOUs      []string
		regions     []string
		profile     string
		manifestDir string
	}{}
	offboardFlags.rollback, offboardFlags.account, offboardFlags.manifestDir, offboardFlags.profile = false, "", "", ""
}

// O46: onboard records every resource it creates; offboard --rollback deletes exactly those.
func TestOnboardManifestAndOffboardRollback(t *testing.T) {
	fake := newFakeAWSOnboard("123456789012")
	fake.roles["unrelated-role"] = "{}" // must survive the rollback
	ss := &fakeStackSets{sets: map[string]string{"someone-elses": "x"}, instances: map[string][]string{}}
	useFakes(t, fake, ss)
	dir := t.TempDir()

	out := run(t, "onboard", "--deploy-role", "--external-id", "ext-1", "--manifest-dir", dir)
	manifestPath := filepath.Join(dir, "onboard-123456789012.json")
	m := readManifest(t, manifestPath)
	kinds := manifestKinds(m)
	if strings.Join(kinds, ",") != "aws_iam_policy,aws_iam_role,aws_iam_role_policy_attachment,aws_iam_role_policy_attachment" {
		t.Fatalf("manifest kinds %v\n%s", kinds, out)
	}
	if m.Resources[1].ARN != "arn:aws:iam::123456789012:role/"+onboardRoleName || !strings.HasPrefix(m.Resources[0].ARN, "arn:aws:iam::123456789012:policy/") {
		t.Errorf("manifest ARNs: %+v", m.Resources)
	}
	trust := fake.roles[onboardRoleName]
	if !strings.Contains(trust, "ext-1") || !strings.Contains(trust, "123456789012") {
		t.Errorf("trust policy must pin the external id and trusted account: %s", trust)
	}
	if doc := fake.policies[m.Resources[0].ARN]; !strings.Contains(doc, "s3:GetBucketPolicyStatus") || strings.Contains(doc, "s3:Put") {
		t.Errorf("customer policy must be the generated read-only policy: %.200s", doc)
	}

	resetOnboardFlags()
	run(t, "onboard", "--aws-org", "123456789012", "--external-id", "ext-1", "--deploy", "--org-ous", "ou-root-1", "--regions", "us-east-1", "--manifest-dir", dir)
	m = readManifest(t, manifestPath)
	if k := manifestKinds(m); len(k) != 6 || k[4] != "aws_cloudformation_stack_set" || k[5] != "aws_cloudformation_stack_instances" || m.Resources[4].ID == "" {
		t.Fatalf("stack set not recorded: %+v", m.Resources)
	}

	// without --rollback offboard is a dry run
	resetOnboardFlags()
	out = run(t, "offboard", "--account", "123456789012", "--manifest-dir", dir)
	if !strings.Contains(out, "dry run") || len(fake.roles) != 2 {
		t.Fatalf("offboard without --rollback must not delete:\n%s", out)
	}

	resetOnboardFlags()
	out = run(t, "offboard", "--rollback", "--account", "123456789012", "--manifest-dir", dir)
	if _, ok := fake.roles[onboardRoleName]; ok || len(fake.policies) != 0 || len(fake.attachments) != 0 {
		t.Fatalf("rollback left resources: roles=%v policies=%v attachments=%v\n%s", fake.roles, fake.policies, fake.attachments, out)
	}
	if _, ok := fake.roles["unrelated-role"]; !ok {
		t.Fatalf("rollback deleted a role it did not create")
	}
	if _, ok := ss.sets[onboardStackSetName]; ok || ss.sets["someone-elses"] == "" {
		t.Fatalf("stack sets after rollback: %v", ss.sets)
	}
	if !strings.Contains(out, "nothing remains") {
		t.Errorf("rollback must verify and report: %s", out)
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Errorf("the active manifest must be retired after a verified rollback")
	}
}

// A failure mid-onboard still leaves an accurate manifest, so rollback cleans up the partial deploy.
func TestOnboardPartialFailureIsRollbackable(t *testing.T) {
	fake := newFakeAWSOnboard("210987654321")
	fake.failRole = true
	ss := &fakeStackSets{sets: map[string]string{}, instances: map[string][]string{}}
	useFakes(t, fake, ss)
	dir := t.TempDir()
	root.SetArgs([]string{"onboard", "--deploy-role", "--manifest-dir", dir})
	if err := root.Execute(); err == nil {
		t.Fatal("onboard must fail when CreateRole is denied")
	}
	m := readManifest(t, filepath.Join(dir, "onboard-210987654321.json"))
	if k := manifestKinds(m); len(k) != 1 || k[0] != "aws_iam_policy" {
		t.Fatalf("partial manifest: %v", k)
	}
	resetOnboardFlags()
	run(t, "offboard", "--rollback", "--account", "210987654321", "--manifest-dir", dir)
	if len(fake.policies) != 0 {
		t.Fatalf("partial deploy not rolled back: %v", fake.policies)
	}
}

func readManifest(t *testing.T, path string) onboardManifest {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var m onboardManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func manifestKinds(m onboardManifest) []string {
	var out []string
	for _, r := range m.Resources {
		out = append(out, r.Kind)
	}
	return out
}

var _ = sort.Strings
var _ = fmt.Sprint
