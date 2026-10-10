package attackpath

import (
	"strings"
	"testing"
)

// Verify-5 C3/C4: the attack-path entry check reads the same anonymous-reach code as who-can,
// evaluated against the exposed node's own ARN: the public access block (full or partial) is
// read before the policy, and a Deny for Principal * on the bucket's objects closes the entry.
func TestV5ExposureAnonymousReach(t *testing.T) {
	const b = "arn:aws:s3:::v5-bucket"
	allowAll := `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}`
	pol := func(st ...string) string {
		return `{"Version":"2012-10-17","Statement":[` + strings.Join(st, ",") + `]}`
	}
	cases := []struct {
		name   string
		attrs  map[string]any
		entry  bool
		reason string
	}{
		{"public policy (control)", map[string]any{"bucket_policy": pol(allowAll)}, true, ""},
		{"public policy + PAB true", map[string]any{"bucket_policy": pol(allowAll), "public_access_block": true}, false, "public access block"},
		{"public policy + partial PAB RestrictPublicBuckets", map[string]any{"bucket_policy": pol(allowAll), "public_access_block": map[string]any{"RestrictPublicBuckets": true}}, false, "RestrictPublicBuckets"},
		{"Allow Resource * + Deny * on the bucket's objects", map[string]any{"bucket_policy": pol(allowAll,
			`{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"`+b+`/*"}`)}, false, "deny"},
		{"SourceIp-limited Allow", map[string]any{"bucket_policy": pol(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}`)}, false, "aws:sourceip"},
		{"StringNotEquals PrincipalOrgID stays public", map[string]any{"bucket_policy": pol(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"o-x"}}}`)}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			attrs := map[string]any{"tags": map[string]any{"data_classification": "confidential"}}
			for k, v := range c.attrs {
				attrs[k] = v
			}
			g := newNB().node(b, "aws_s3_bucket", "v5-bucket", attrs, "PUBLIC_DATA_STORE").sensitive(b).expose(b, nil).g
			an := Traverse(g, DefaultTraversalOptions())
			got := false
			for _, p := range an.Paths {
				if touches(p, b) {
					got = true
				}
			}
			if got != c.entry {
				t.Errorf("path through %s: %v, want %v", b, got, c.entry)
			}
			if !c.entry {
				s := suppressedOf(an, b)
				if s == nil || s.Exposure != exposurePrivate || !strings.Contains(strings.ToLower(s.Reason), strings.ToLower(c.reason)) {
					t.Errorf("suppressed %+v, want private / %q", s, c.reason)
				}
			}
		})
	}
}
