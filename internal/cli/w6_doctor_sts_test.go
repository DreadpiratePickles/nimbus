package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"

	awscol "github.com/DreadpiratePickles/nimbus/internal/collector/aws"
)

// Verification 6 (routed item 10): an STS reply that carries no identity (a 200 with a garbage
// body decodes to an empty output) is a failure doctor prints, not silence — and never a panic.
func TestDoctorReportsAnEmptySTSReply(t *testing.T) {
	t.Setenv("CLOUD_POSTURE_NO_NETWORK", "")
	flagDB = filepath.Join(t.TempDir(), "none.db")
	flagConfig = filepath.Join(t.TempDir(), "none.yaml")
	t.Cleanup(func() { flagConfig = "" })
	env := fakeDoctorEnv(nil, nil, nil)
	env.feeds = nil
	env.discoverAWS = func(context.Context) []awscol.DiscoveredIdentity {
		return []awscol.DiscoveredIdentity{{Source: "environment"}}
	}
	var buf bytes.Buffer
	err := runDoctor(context.Background(), env, &buf)
	out := buf.String()
	if err == nil || !strings.Contains(out, "fail") || !strings.Contains(out, "no account in the STS reply") {
		t.Fatalf("doctor must fail on an STS reply without an account (err %v):\n%s", err, out)
	}
}

func TestSTSIdentityRejectsEmptyReply(t *testing.T) {
	if _, err := stsIdentity(&sts.GetCallerIdentityOutput{}); err == nil {
		t.Error("an empty GetCallerIdentity reply must be an error (it was a nil dereference)")
	}
	if _, err := stsIdentity(nil); err == nil {
		t.Error("a nil reply must be an error")
	}
	arn, acct := "arn:aws:iam::1:user/x", "1"
	if got, err := stsIdentity(&sts.GetCallerIdentityOutput{Arn: &arn, Account: &acct}); err != nil || got != arn {
		t.Errorf("got %q %v", got, err)
	}
}
