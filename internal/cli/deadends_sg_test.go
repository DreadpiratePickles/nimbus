package cli

import (
	"encoding/json"
	"testing"
)

// V2 integration (b): an open-SSH security group whose instance (web-1) is on a complete
// path is not a dead end. The instance links to the SG by its bare id (sg-0abc123) while
// the SG node is the full ARN.
func TestDeadEndsLinkSecurityGroupToItsInstance(t *testing.T) {
	ingestTestdata(t)
	out := run(t, "paths", "--dead-ends", "--format", "json")
	var de struct {
		DeadEnds struct {
			IDs []string `json:"ids"`
		} `json:"dead_ends"`
	}
	if err := json.Unmarshal([]byte(out), &de); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, id := range de.DeadEnds.IDs {
		if id == "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123" {
			t.Fatalf("the open-SSH SG of web-1 (on a path) is listed as a dead end: %v", de.DeadEnds.IDs)
		}
	}
}
