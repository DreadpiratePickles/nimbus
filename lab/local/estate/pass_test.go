package estate

import (
	"strings"
	"testing"
)

// W6-ENGINE item 5 (competitive delta r4 #13): a weakness-free resource may name the control its
// inventory PASS record evidences (pass_check), so compliance has PASS rows; the record count, ids
// and the lab_inventory tag do not change (ground truth counts and labels stay as they are).
func TestPassCheckRidesOnTheInventoryRecord(t *testing.T) {
	e, err := Parse([]byte(`
version: 1
name: t
source: nimbus-lab
accounts: [{provider: aws, id: "111111111111"}]
resources:
  - {id: "arn:aws:s3:::b", scenario: S1, provider: aws, account: "111111111111", type: aws_s3_bucket, name: b, pass_check: s3_bucket_default_encryption, pass_title: "Bucket b encrypts by default"}
  - {id: "arn:aws:s3:::c", scenario: S1, provider: aws, account: "111111111111", type: aws_s3_bucket, name: c}
weaknesses: []
`))
	if err != nil {
		t.Fatal(err)
	}
	fs := e.Findings()
	if len(fs) != 2 || fs[0].ID != "lab-inv-01" || fs[0].CheckID != "s3_bucket_default_encryption" || fs[0].Status != "PASS" ||
		fs[0].Tags["lab_inventory"] != "true" || fs[0].Title != "Bucket b encrypts by default" {
		t.Fatalf("pass_check record: %+v", fs[0])
	}
	if fs[1].CheckID != InventoryCheckID {
		t.Fatalf("plain inventory record changed: %+v", fs[1])
	}
	_, err = Parse([]byte(`
version: 1
name: t
accounts: [{provider: aws, id: "111111111111"}]
resources:
  - {id: "arn:aws:s3:::b", scenario: S1, provider: aws, account: "111111111111", type: aws_s3_bucket, name: b, pass_check: s3_bucket_default_encryption}
weaknesses:
  - {id: W1, resource: "arn:aws:s3:::b", check_id: s3_bucket_public_access, severity: HIGH, weaknesses: [PUBLIC_DATA_STORE], title: x}
`))
	if err == nil || !strings.Contains(err.Error(), "pass_check") {
		t.Fatalf("pass_check on a resource with weaknesses must be refused (it has no inventory record): %v", err)
	}
}
