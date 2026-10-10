package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verify-3 defect 7: a StackSet-only manifest carried no account check, so a manifest
// for any org deleted the current management account's cloud-posture StackSet. Onboard
// now records the management account (STS) and rollback refuses on a mismatch.

func TestStackSetManifestRecordsManagementAccount(t *testing.T) {
	fake := newFakeAWSOnboard("111111111111")
	ss := &fakeStackSets{sets: map[string]string{}, instances: map[string][]string{}}
	useFakes(t, fake, ss)
	dir := t.TempDir()
	run(t, "onboard", "--aws-org", "999999999999", "--deploy", "--org-ous", "ou-1", "--regions", "us-east-1", "--manifest-dir", dir)
	m := readManifest(t, filepath.Join(dir, "onboard-999999999999.json"))
	if m.ManagementAccount != "111111111111" {
		t.Fatalf("manifest management_account = %q, want the STS account 111111111111", m.ManagementAccount)
	}
}

func TestStackSetOnlyRollbackRefusesOtherManagementAccount(t *testing.T) {
	fake := newFakeAWSOnboard("111111111111")
	ss := &fakeStackSets{sets: map[string]string{}, instances: map[string][]string{}}
	useFakes(t, fake, ss)
	dir := t.TempDir()
	run(t, "onboard", "--aws-org", "999999999999", "--deploy", "--org-ous", "ou-1", "--regions", "us-east-1", "--manifest-dir", dir)
	path := filepath.Join(dir, "onboard-999999999999.json")
	m, err := loadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	// Credentials now belong to another management account that has its own StackSet.
	fake.account = "222222222222"
	err = rollback(context.Background(), path, m, "")
	var re *rollbackRefusedError
	if !errors.As(err, &re) || re.Reason != refuseAccountMismatch {
		t.Fatalf("rollback with another management account's credentials: err=%v, want account-mismatch refusal", err)
	}
	if _, ok := ss.sets[onboardStackSetName]; !ok || len(ss.instances[onboardStackSetName]) == 0 {
		t.Fatalf("the StackSet was mutated despite the refusal: sets=%v instances=%v", ss.sets, ss.instances)
	}
	// A manifest from before management_account was recorded is refused too.
	m.ManagementAccount = ""
	if err := rollback(context.Background(), path, m, ""); !errors.Is(err, errRollbackRefused) {
		t.Fatalf("StackSet manifest without management_account: err=%v, want refusal", err)
	}
	if _, ok := ss.sets[onboardStackSetName]; !ok {
		t.Fatal("StackSet deleted from a manifest with no management account")
	}
	// The right management account rolls back.
	fake.account = "111111111111"
	m.ManagementAccount = "111111111111"
	if err := rollback(context.Background(), path, m, ""); err != nil {
		t.Fatalf("rollback with the recorded management account: %v", err)
	}
	if _, ok := ss.sets[onboardStackSetName]; ok {
		t.Fatal("StackSet not deleted by a matching rollback")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) && !strings.Contains(path, "rolledback") {
		t.Errorf("manifest not retired after a verified rollback")
	}
}
