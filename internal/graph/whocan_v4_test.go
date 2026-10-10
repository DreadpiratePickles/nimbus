package graph_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Delta r2 #5: who-can names the anonymous principal first when the resource is anonymously
// readable. The lab PII bucket has a Principal * bucket policy and no public access block.
func TestV4WhoCanAnonymousFirst(t *testing.T) {
	fs, _, err := adapters.ParseFile(filepath.Join("..", "..", "lab", "local", "out", "estate.findings.json"), "native", adapters.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	g.AttachFindings(fs)
	res := graph.WhoCan(g, "s3:GetObject", "arn:aws:s3:::nimbus-lab-customer-pii/*", 4)
	if len(res) < 2 {
		t.Fatalf("who-can returned %d principals", len(res))
	}
	if res[0].Principal != graph.AnonymousPrincipal || !strings.Contains(res[0].Because, "Principal *") || res[0].Decision != "allow" {
		t.Errorf("first result %+v, want %q with the because", res[0], graph.AnonymousPrincipal)
	}
	for _, r := range res[1:] {
		if r.Principal == graph.AnonymousPrincipal {
			t.Errorf("anonymous listed twice")
		}
	}
	// A private bucket and a write action do not get the anonymous principal.
	for _, q := range [][2]string{{"s3:PutBucketPolicy", "arn:aws:s3:::nimbus-lab-customer-pii"}} {
		for _, r := range graph.WhoCan(g, q[0], q[1], 4) {
			if r.Principal == graph.AnonymousPrincipal {
				t.Errorf("%s on %s: anonymous listed", q[0], q[1])
			}
		}
	}
	// Org-conditioned Principal * policy: demoted to org-wide, never anonymous.
	g2 := graph.New()
	g2.AddNode(&graph.Node{ID: "arn:aws:s3:::shared", Type: "aws_s3_bucket", Provider: "aws", Account: "111111111111", Attributes: map[string]any{
		"bucket_policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]}`}})
	rs := graph.WhoCan(g2, "s3:GetObject", "arn:aws:s3:::shared/x", 4)
	if len(rs) == 0 || rs[0].Principal != graph.OrgWidePrincipal {
		t.Errorf("org-conditioned: %+v", rs)
	}
}

func TestV4WhoCanAnonymousACL(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "arn:aws:s3:::acl-pub", Type: "aws_s3_bucket", Provider: "aws", Account: "111111111111", Attributes: map[string]any{"acl": "public-read"}})
	rs := graph.WhoCan(g, "s3:GetObject", "arn:aws:s3:::acl-pub/k", 4)
	if len(rs) == 0 || rs[0].Principal != graph.AnonymousPrincipal || !strings.Contains(rs[0].Because, "ACL public-read") {
		t.Errorf("public-read ACL: %+v", rs)
	}
	g.AddNode(&graph.Node{ID: "arn:aws:s3:::acl-pub", Attributes: map[string]any{"public_access_block": true}})
	for _, r := range graph.WhoCan(g, "s3:GetObject", "arn:aws:s3:::acl-pub/k", 4) {
		if r.Principal == graph.AnonymousPrincipal {
			t.Errorf("public access block on: anonymous still listed")
		}
	}
}
