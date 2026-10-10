package reach

import (
	"strings"
	"testing"
)

// An SG that admits nothing must not make an open NACL / IGW route appear as a blocker.
func TestV4BlockerEvidenceNoOpenLayers(t *testing.T) {
	tg := v4Inst(v4PubSubnet(v4OpenACL), []SecurityGroup{{ID: "sg-g", Ingress: []SGRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, Groups: []string{"sg-other"}}}}})
	r := Reachable(tg, Internet(), v4Tcp22)
	t.Logf("blockers: %q", r.Blocker())
	if strings.Contains(r.Blocker(), "acl-open") || strings.Contains(r.Blocker(), "no route") {
		t.Errorf("open NACL / IGW route reported as blocker: %q", r.Blocker())
	}
	db := Target{ID: "db", Kind: KindDBInstance, PubliclyAccessible: v4Bool(false), Subnets: []Subnet{v4PubSubnet(v4OpenACL)}, SecurityGroups: v4SGssh}
	r = Reachable(db, Internet(), v4Tcp22)
	t.Logf("rds blockers: %q", r.Blocker())
	if strings.Contains(r.Blocker(), "acl-open") || strings.Contains(r.Blocker(), "no route") {
		t.Errorf("rds: open layers reported as blockers: %q", r.Blocker())
	}
}
