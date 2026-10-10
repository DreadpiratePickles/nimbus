package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// V2 defect 4: offboard --rollback must only delete what onboard created in the
// account the current credentials belong to.

func onboardInto(t *testing.T, f *fakeAWSOnboard, dir string) (string, *onboardManifest) {
	t.Helper()
	if _, err := deployAWSRole(context.Background(), f, dir, "", "ext"); err != nil {
		t.Fatal(err)
	}
	p := manifestPath(dir, f.account)
	m, err := loadManifest(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, m
}

func withAWS(t *testing.T, f *fakeAWSOnboard) {
	t.Helper()
	old := newAWSOnboard
	newAWSOnboard = func(context.Context, string) (awsOnboardAPI, error) { return f, nil }
	t.Cleanup(func() { newAWSOnboard = old })
}

func TestRollbackNormalLeavesUnrelated(t *testing.T) {
	dir := t.TempDir()
	f := newFakeAWSOnboard("111111111111")
	p, m := onboardInto(t, f, dir)
	f.roles["Unrelated"] = "{}"
	f.policies["arn:aws:iam::111111111111:policy/Other"] = "{}"
	withAWS(t, f)
	if err := rollback(context.Background(), p, m, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.roles["Unrelated"]; !ok || len(f.policies) != 1 || len(f.attachments) != 0 {
		t.Fatalf("roles=%v policies=%v attachments=%v", f.roles, f.policies, f.attachments)
	}
}

func TestRollbackRefusesOtherAccountsManifest(t *testing.T) {
	dir := t.TempDir()
	f111 := newFakeAWSOnboard("111111111111")
	p, m := onboardInto(t, f111, filepath.Join(dir, "a"))
	f222 := newFakeAWSOnboard("222222222222")
	onboardInto(t, f222, filepath.Join(dir, "b")) // 222's own scan role
	f222.mutations = 0
	withAWS(t, f222)
	err := rollback(context.Background(), p, m, "")
	var re *rollbackRefusedError
	if !errors.As(err, &re) || re.Reason != refuseAccountMismatch {
		t.Fatalf("want account-mismatch refusal, got %v", err)
	}
	if f222.mutations != 0 || len(f222.attachments) != 2 {
		t.Fatalf("replaying another account's manifest mutated: %d calls, attachments=%v", f222.mutations, f222.attachments)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("manifest must not be retired on refusal: %v", err)
	}
}

func TestRollbackRefusesNonAllowlistedResources(t *testing.T) {
	cases := map[string]string{
		"org access role": `{"kind":"aws_iam_role","id":"OrganizationAccountAccessRole"}`,
		"role arn swap":   `{"kind":"aws_iam_role","id":"CloudPostureScanRole","arn":"arn:aws:iam::333333333333:role/Admin"}`,
		"foreign policy":  `{"kind":"aws_iam_policy","id":"CloudPostureReadOnly","arn":"arn:aws:iam::333333333333:policy/ProdAdmin"}`,
		"aws managed":     `{"kind":"aws_iam_policy","id":"AdministratorAccess","arn":"arn:aws:iam::aws:policy/AdministratorAccess"}`,
		"detach admin":    `{"kind":"aws_iam_role_policy_attachment","id":"x","role":"OrganizationAccountAccessRole","policy_arn":"arn:aws:iam::aws:policy/AdministratorAccess"}`,
		"detach other":    `{"kind":"aws_iam_role_policy_attachment","id":"x","role":"CloudPostureScanRole","policy_arn":"arn:aws:iam::aws:policy/AdministratorAccess"}`,
		"stack set":       `{"kind":"aws_cloudformation_stack_set","id":"x","stack_set":"prod-baseline"}`,
		"unknown kind":    `{"kind":"aws_s3_bucket","id":"logs"}`,
	}
	for name, res := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			f := newFakeAWSOnboard("333333333333")
			onboardInto(t, f, dir)
			f.roles["OrganizationAccountAccessRole"] = "{}"
			f.attachments["OrganizationAccountAccessRole|arn:aws:iam::aws:policy/AdministratorAccess"] = true
			f.mutations = 0
			withAWS(t, f)
			ss := &fakeStackSets{sets: map[string]string{"prod-baseline": "x"}, instances: map[string][]string{}}
			oldS := newStackSets
			newStackSets = func(string) stackSetAPI { return ss }
			t.Cleanup(func() { newStackSets = oldS })
			tp := filepath.Join(dir, "onboard-333333333333.json")
			os.WriteFile(tp, []byte(`{"version":1,"provider":"aws","account":"333333333333","resources":[`+res+`]}`), 0o600)
			m, err := loadManifest(tp)
			if err != nil {
				t.Fatal(err)
			}
			err = rollback(context.Background(), tp, m, "")
			var re *rollbackRefusedError
			if !errors.As(err, &re) || !errors.Is(err, errRollbackRefused) {
				t.Fatalf("want typed refusal, got %v", err)
			}
			if f.mutations != 0 || ss.sets["prod-baseline"] == "" {
				t.Fatalf("refused manifest still mutated (%d calls)", f.mutations)
			}
		})
	}
}

// A role/policy with the onboard name that does not carry the managed-by tag was
// not created by onboard (e.g. the operator's own), so it is not deleted.
func TestRollbackRefusesUntaggedResources(t *testing.T) {
	dir := t.TempDir()
	f := newFakeAWSOnboard("444444444444")
	p, m := onboardInto(t, f, dir)
	f.tags[onboardRoleName] = map[string]string{"owner": "platform-team"}
	f.mutations = 0
	withAWS(t, f)
	err := rollback(context.Background(), p, m, "")
	var re *rollbackRefusedError
	if !errors.As(err, &re) || re.Reason != refuseNotTagged {
		t.Fatalf("want not-tagged refusal, got %v", err)
	}
	if f.mutations != 0 {
		t.Fatalf("mutated %d times", f.mutations)
	}
}

// A manifest whose recorded tag was edited to something else is refused.
func TestRollbackRefusesEditedManifestTag(t *testing.T) {
	dir := t.TempDir()
	f := newFakeAWSOnboard("555555555555")
	p, m := onboardInto(t, f, dir)
	if m.Tags["managed-by"] != "cloud-posture" {
		t.Fatalf("manifest must record the onboard tag: %v", m.Tags)
	}
	m.Tags = map[string]string{"owner": "platform-team"}
	f.mutations = 0
	withAWS(t, f)
	err := rollback(context.Background(), p, m, "")
	if !errors.Is(err, errRollbackRefused) || f.mutations != 0 {
		t.Fatalf("got %v, %d mutations", err, f.mutations)
	}
}
