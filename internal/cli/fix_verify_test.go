package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// IaC-track addendum (a): a tfstate-mapped finding carries the full module address
// (module.a.aws_instance.web[0]) while the re-scan of the patched file reports the short
// address (aws_instance.web). verifyPatch must compare like with like, so a patch that
// did not remove the finding fails verification.
func TestVerifyPatchComparesNormalisedAddresses(t *testing.T) {
	vulnerable := "resource \"aws_instance\" \"web\" {\n  ami = \"ami-1\"\n  instance_type = \"t3.micro\"\n}\n"
	f := model.Finding{CanonicalID: "EC2_IMDSV1", File: "modules/a/main.tf", Resource: model.Resource{ID: "module.a.aws_instance.web[0]"}}
	// sanity: the re-scan does report the vulnerable instance under the short address
	if verifyPatch(model.Finding{CanonicalID: "EC2_IMDSV1", Resource: model.Resource{ID: "aws_instance.web"}}, iac.Patch{After: vulnerable}) {
		t.Fatal("setup: unpatched short-address finding must fail verification")
	}
	if verifyPatch(f, iac.Patch{After: vulnerable}) {
		t.Fatal("a patch that left the mapped finding in place was reported as verified")
	}
	for _, id := range []string{`module.a["x"].module.b.aws_instance.web["k"]`, "module.a[0].aws_instance.web"} {
		if verifyPatch(model.Finding{CanonicalID: "EC2_IMDSV1", Resource: model.Resource{ID: id}}, iac.Patch{After: vulnerable}) {
			t.Errorf("%s: unpatched finding verified", id)
		}
	}
	fixed := "resource \"aws_instance\" \"web\" {\n  ami = \"ami-1\"\n  instance_type = \"t3.micro\"\n  metadata_options {\n    http_tokens = \"required\"\n  }\n}\n"
	if !verifyPatch(f, iac.Patch{After: fixed}) {
		t.Fatal("a patch that removed the finding must verify")
	}
}

// IaC-track addendum (b): when LocateStrict refuses a mapping (ambiguous target) the
// reason and the candidate blocks are logged instead of the finding being skipped silently.
func TestCodeMappingLogsRefusals(t *testing.T) {
	mapping := map[string]iac.CodeLocation{
		"i-amb": {Address: "module.x.aws_instance.web", Unresolved: "module source not found", Candidates: []string{"modules/a/main.tf:1", "modules/b/main.tf:1"}},
		"i-ok":  {Address: "aws_instance.ok", File: "main.tf", Line: 3},
	}
	targets := []model.Finding{
		{CanonicalID: "EC2_IMDSV1", Resource: model.Resource{ID: "i-amb", Name: "amb"}},
		{CanonicalID: "EC2_IMDSV1", Resource: model.Resource{ID: "i-ok", Name: "ok"}},
	}
	var logs []string
	applyCodeMapping(targets, mapping, func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) })
	if targets[1].File != "main.tf" || targets[1].Resource.ID != "aws_instance.ok" {
		t.Fatalf("mapped target not updated: %+v", targets[1])
	}
	if targets[0].File != "" {
		t.Fatalf("refused target must stay unmapped: %+v", targets[0])
	}
	joined := strings.Join(logs, "\n")
	for _, want := range []string{"amb", "module source not found", "modules/a/main.tf:1", "modules/b/main.tf:1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("refusal log missing %q:\n%s", want, joined)
		}
	}
}
