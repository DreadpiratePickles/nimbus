package iac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Defect 17 (verified probe): `endpoint_public_access = !var.x` evaluated to an unknown bool and
// v.True() panicked. Unknown values must be reported as SKIP ("not statically known"), never as a
// pass/fail guess and never as a panic.
func TestScannerHandlesUnaryTernaryForAndNulls(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "iac", "expressions")
	var fs []model.Finding
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("scanner panicked: %v", r)
			}
		}()
		var err error
		fs, err = ScanTerraform(dir, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}()
	got := map[string]model.Finding{}
	for _, f := range fs {
		if f.Status == model.Error {
			t.Errorf("%s %s: error status: %s", f.CheckID, f.Resource.ID, f.Description)
		}
		got[f.CheckID+"/"+f.Resource.ID] = f
	}
	want := map[string]model.Status{
		"NIMBUS_TF_EKS_PUBLIC/aws_eks_cluster.negated":                      model.Skip, // !var.public is unknown
		"NIMBUS_TF_EKS_PUBLIC/aws_eks_cluster.literal_negation":             model.Fail, // !false is known true
		"NIMBUS_TF_GCP_SQL_PUBLIC/google_sql_database_instance.negated":     model.Skip,
		"NIMBUS_TF_SG_OPEN/aws_security_group.exprs":                        model.Skip, // ternary may open 0.0.0.0/0
		"NIMBUS_TF_SG_RULE_OPEN/aws_security_group_rule.nulls":              model.Pass,
		"NIMBUS_TF_GCP_FW_OPEN/google_compute_firewall.nulls":               model.Pass,
		"NIMBUS_TF_GCS_PUBLIC/google_storage_bucket_iam_binding.nulls":      model.Pass,
		"NIMBUS_TF_GCS_PUBLIC/google_storage_bucket_iam_member.null_member": model.Pass,
		"NIMBUS_TF_S3_PAB/aws_s3_bucket_public_access_block.unknowns":       model.Skip,
		"NIMBUS_TF_PUBLIC_IP/aws_instance.ternary":                          model.Skip,
		"NIMBUS_TF_IMDSV1/aws_instance.ternary":                             model.Skip,
		"NIMBUS_TF_EBS_ENC/aws_ebs_volume.negated":                          model.Skip,
		"NIMBUS_TF_IAM_STAR/aws_iam_policy.jsonencoded":                     model.Skip,
		"NIMBUS_TF_AZ_BLOB_PUBLIC/azurerm_storage_account.unknowns":         model.Skip,
		"NIMBUS_TF_AZ_HTTPS/azurerm_storage_account.unknowns":               model.Fail, // -1 > 0 is known false
		"NIMBUS_TF_AZ_NSG_OPEN/azurerm_network_security_rule.ternary":       model.Skip,
		"NIMBUS_TF_TRAIL_VALIDATION/aws_cloudtrail.neg":                     model.Skip,
		"NIMBUS_TF_TRAIL_REGION/aws_cloudtrail.neg":                         model.Pass, // !!true
		"NIMBUS_TF_KMS_ROTATION/aws_kms_key.neg":                            model.Skip,
		"NIMBUS_TF_RDS_PUBLIC/aws_db_instance.neg":                          model.Skip,
		"NIMBUS_TF_RDS_ENC/aws_db_instance.neg":                             model.Skip,
	}
	for k, st := range want {
		f, ok := got[k]
		if !ok {
			t.Errorf("%s: no finding", k)
			continue
		}
		if f.Status != st {
			t.Errorf("%s: status %s (%s), want %s", k, f.Status, f.Description, st)
		}
		if st == model.Skip && !strings.Contains(f.Description, "not statically known") {
			t.Errorf("%s: skip without reason: %q", k, f.Description)
		}
	}
}

// fuzzSeeds returns every .tf fixture under testdata/iac plus the inline package fixture.
func fuzzSeeds(f *testing.F) {
	root := filepath.Join("..", "..", "testdata", "iac")
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(p) == ".tf" {
			if b, err := os.ReadFile(p); err == nil {
				f.Add(b)
			}
		}
		return nil
	})
	f.Add([]byte(tf))
	addPathologicalSeeds(f)
	f.Add([]byte("resource \"aws_eks_cluster\" \"x\" {\n vpc_config { endpoint_public_access = !var.x }\n}\n"))
	f.Add([]byte("resource \"aws_security_group\" \"x\" {\n ingress { cidr_blocks = [null, -1, !true, [for x in [] : x]] }\n}\n"))
}

// FuzzScanHCL: the scanner and patcher must never panic on any input, and on input that parses
// cleanly no rule may hit its panic guard (reported as Status ERROR).
func FuzzScanHCL(f *testing.F) {
	fuzzSeeds(f)
	now := time.Unix(0, 0)
	f.Fuzz(func(t *testing.T, src []byte) {
		// Verification 3 defect 1: whatever the guard accepts, the real syntax tree stays within a
		// small multiple of its measure, so an uncounted recursive construct fails here at a depth
		// of a few dozen instead of overflowing the stack at a few hundred thousand.
		if checkParseLimits(src, "fuzz.tf") == nil {
			if ok, ast, m := guardBoundHolds(src); !ok {
				t.Fatalf("guard under-counts: syntax tree depth %d, guard depth %d chain %d", ast, m.depth, m.chain)
			}
		}
		fs, parseErr := ScanHCL(src, "fuzz.tf", now)
		for _, x := range fs {
			if x.Status == model.Error && parseErr == nil {
				t.Fatalf("rule guard tripped on valid HCL: %s", x.Description)
			}
			if x.Status != model.Fail {
				continue
			}
			p, err := patchSource(x, "fuzz.tf", src, nil)
			if err != nil || p == nil {
				continue
			}
			if _, err := ScanHCL([]byte(p.After), "fuzz.tf", now); err != nil && parseErr == nil {
				t.Fatalf("patch of valid HCL produced unparseable HCL: %v\n%s", err, p.After)
			}
		}
	})
}
