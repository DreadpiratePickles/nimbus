package query

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func TestViewsAndSafety(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "q.db"))
	defer st.Close()
	f := model.Finding{Source: "prowler", CheckID: "x", CanonicalID: "RDS_PUBLIC", Title: "RDS public", Severity: model.Critical, Status: model.Fail, Provider: "aws", Account: "1",
		Resource: model.Resource{ID: "arn:aws:rds:::db:pay", Type: "aws_db_instance", Name: "pay"}, Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "DATABASE"},
		Compliance: map[string][]string{"cis_aws": {"2.3.3"}, "soc2": {"CC6.6"}}}
	f.Finalize(time.Now())
	st.UpsertFindings([]model.Finding{f})
	st.ReplaceAttackPaths("s", []model.AttackPath{{ID: "p", RuleID: "PUBLIC_DATABASE_BREACH", Name: "db", Score: 5, Severity: model.Critical, Provider: "aws", Account: "1", Impact: "theft",
		Steps: []model.Step{{Resource: "internet-sg", Weakness: "PUBLIC_NETWORK_EXPOSURE"}, {Resource: "arn:aws:rds:::db:pay", Weakness: "UNENCRYPTED_AT_REST"}}}})
	for _, bad := range []string{"DELETE FROM findings", "select 1; drop table findings", "PRAGMA x", "insert into findings values(1)"} {
		if IsReadOnly(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
	res, err := Run(context.Background(), st, "SELECT control_id, status FROM cis_aws_benchmark WHERE control_id = '2.3.3'", "local")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0][1] != "FAIL" {
		t.Errorf("cis view: %+v", res.Rows)
	}
	res, err = Run(context.Background(), st, "SELECT entry_point, target, path_length, target_type FROM attack_path_summary", "local")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0][0] != "internet-sg" || res.Rows[0][1] != "arn:aws:rds:::db:pay" || res.Rows[0][2] != int64(2) {
		t.Errorf("attack path view: %+v", res.Rows)
	}
	res, err = Run(context.Background(), st, "SELECT name, internet_exposed FROM aws_db_instances WHERE internet_exposed = 1", "local")
	if err != nil || len(res.Rows) != 1 {
		t.Errorf("inventory view: %v %+v", err, res)
	}
	res, _ = Run(context.Background(), st, "SELECT status FROM soc2 WHERE control_id='CC6.6'", "local")
	if len(res.Rows) != 1 {
		t.Errorf("soc2 view: %+v", res)
	}
	schema, _ := Schema(st)
	if len(schema["attack_path_summary"]) == 0 {
		t.Errorf("schema missing")
	}
	if got := Tables("select * from aws_s3_bucket join aws_iam_role r on 1"); len(got) != 2 {
		t.Errorf("tables: %v", got)
	}
}
