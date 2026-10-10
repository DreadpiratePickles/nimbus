package attackpath

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W7-ENGINE item 3 (r5 #10): inferred rule matches are "potential escalation" annotations on the
// principal, never path Issues. PotentialEscalations is store-free (the Issue page builder renders
// it on the principal's finding Issue).
func TestPotentialEscalationsOnTheLab(t *testing.T) {
	g, _ := labGraph(t, false)
	pe := PotentialEscalations(g, nil) // nil: the embedded library
	const agent = "arn:aws:iam::111111111111:role/nimbus-lab-support-agent-role"
	hit := false
	for _, m := range pe[agent] {
		hit = hit || m.RuleID == "aws-iam-privesc-put-role-policy"
	}
	if !hit {
		t.Errorf("support-agent-role lacks the inferred put-role-policy escalation: %+v", pe[agent])
	}
	total := 0
	for anchor, ms := range pe {
		for _, m := range ms {
			total++
			if m.Confidence != string(model.ConfidenceInferred) || m.Anchor != anchor {
				t.Errorf("%s: %+v is not an inferred match on its anchor", anchor, m)
			}
			if m.RuleID == ec2RuleID {
				t.Errorf("the verified dev-sam match is a path, not a potential escalation")
			}
		}
	}
	if total < 3 {
		t.Errorf("only %d potential escalations on the lab (W6 dry run: 7 inferred)", total)
	}
	an := Traverse(g, labOptions())
	for _, p := range an.Paths {
		for _, ms := range pe {
			for _, m := range ms {
				if p.RuleID == m.RuleID {
					t.Errorf("inferred match %s became path %s", m.RuleID, p.ID)
				}
			}
		}
	}
}
