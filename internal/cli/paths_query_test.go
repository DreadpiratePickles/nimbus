package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// `paths --from/--to/--through/--max-hops` on the stored lab graph (delta r3 #8, IG6).
func TestPathsQueryFromToThrough(t *testing.T) {
	labDB(t)
	out := run(t, "paths", "--from", "internet", "--to", "type:aws_s3_bucket", "--through", "type:aws_iam_role")
	for _, want := range []string{"path(s) from internet to type:aws_s3_bucket through type:aws_iam_role", "nimbus-lab-customer-pii", "because:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	js := run(t, "paths", "--from", "internet", "--to", "type:aws_s3_bucket", "--through", "type:aws_iam_role", "--max-hops", "4", "--format", "json")
	var res struct {
		Query struct {
			From, To, Through string
			MaxHops           int `json:"max_hops"`
		}
		Paths []struct {
			RuleID string `json:"rule_id"`
			Steps  []struct {
				Because  string `json:"because"`
				Resource string `json:"resource"`
			} `json:"steps"`
		} `json:"paths"`
	}
	if err := json.Unmarshal([]byte(js), &res); err != nil {
		t.Fatalf("%v\n%s", err, js)
	}
	if res.Query.MaxHops != 4 || res.Query.Through != "type:aws_iam_role" || len(res.Paths) == 0 {
		t.Fatalf("json: %+v", res)
	}
	for _, p := range res.Paths {
		if len(p.Steps) > 4 {
			t.Fatalf("max-hops 4 exceeded: %d", len(p.Steps))
		}
		for _, s := range p.Steps {
			if s.Because == "" {
				t.Fatalf("hop without because: %+v", s)
			}
		}
	}
	bare := run(t, "paths", "--from", "internet", "--to", "aws_s3_bucket", "--through", "aws_iam_role")
	if !strings.Contains(bare, "nimbus-lab-customer-pii") {
		t.Fatalf("bare node type selector:\n%s", bare)
	}
	none := run(t, "paths", "--from", "internet", "--to", "type:aws_s3_bucket", "--through", "type:aws_iam_role", "--max-hops", "1")
	if !strings.Contains(none, "0 path(s)") {
		t.Fatalf("max-hops 1 through a role:\n%s", none)
	}
}

func TestPathsQueryNeedsBothEnds(t *testing.T) {
	labDB(t)
	if _, err := runErr(t, "paths", "--to", "type:aws_s3_bucket"); err == nil || !strings.Contains(err.Error(), "--from") {
		t.Fatalf("--to without --from: %v", err)
	}
	if _, err := runErr(t, "paths", "--from", "internet", "--to", "nope-not-a-node"); err == nil || !strings.Contains(err.Error(), "nope-not-a-node") {
		t.Fatalf("unknown node: %v", err)
	}
}
