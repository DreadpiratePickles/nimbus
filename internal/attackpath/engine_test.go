package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func f(id, canon, res string, weak ...string) model.Finding {
	return model.Finding{ID: id, CanonicalID: canon, Title: canon, Status: model.Fail, Severity: model.High, Provider: "aws", Account: "1",
		Resource: model.Resource{ID: res, Name: res}, Weaknesses: weak}
}

func TestRuleChains(t *testing.T) {
	rules, err := LoadRules(nil)
	if err != nil || len(rules) < 10 {
		t.Fatalf("rules: %v %d", err, len(rules))
	}
	sg := f("f1", "EC2_SG_OPEN_SSH", "sg-1", "PUBLIC_NETWORK_EXPOSURE")
	inst := f("f2", "EC2_IMDSV1", "i-1", "IMDSV1_ENABLED")
	inst.Resource.Related = []string{"sg-1", "arn:aws:iam::1:role/admin"}
	role := f("f3", "IAM_ADMIN_POLICY", "arn:aws:iam::1:role/admin", "OVERPRIVILEGED_IDENTITY")
	bucket := f("f4", "S3_PUBLIC_BUCKET", "arn:aws:s3:::pii", "PUBLIC_DATA_STORE")
	enc := f("f5", "S3_UNENCRYPTED", "arn:aws:s3:::pii", "UNENCRYPTED_AT_REST")
	logs := f("f6", "S3_NO_LOGGING", "arn:aws:s3:::pii", "NO_LOGGING")
	passed := f("f7", "S3_PUBLIC_BUCKET", "arn:aws:s3:::other", "PUBLIC_DATA_STORE")
	passed.Status = model.Pass
	paths := Evaluate([]model.Finding{sg, inst, role, bucket, enc, logs, passed}, rules)
	var admin, exfil *model.AttackPath
	for i := range paths {
		switch paths[i].RuleID {
		case "INTERNET_TO_ACCOUNT_ADMIN":
			admin = &paths[i]
		case "PUBLIC_BUCKET_SILENT_EXFIL":
			exfil = &paths[i]
		}
	}
	if admin == nil || len(admin.Steps) != 3 || admin.Steps[1].Relation != "related" {
		t.Fatalf("admin path: %+v", admin)
	}
	if exfil == nil || exfil.Steps[1].Relation != "same_resource" || exfil.Steps[2].Relation != "same_resource" {
		t.Fatalf("exfil path: %+v", exfil)
	}
	for _, p := range paths {
		for _, id := range p.FindingIDs {
			if id == "f7" {
				t.Errorf("PASS finding used in path")
			}
		}
	}
	if paths[0].Score < paths[len(paths)-1].Score {
		t.Errorf("not sorted by score")
	}
	m := Mermaid(paths)
	if !strings.Contains(m, "flowchart LR") || !strings.Contains(m, "Internet") {
		t.Errorf("mermaid: %s", m)
	}
	if !strings.Contains(DOT(paths), "digraph") {
		t.Errorf("dot")
	}
}
