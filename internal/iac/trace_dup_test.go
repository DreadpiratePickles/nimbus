package iac

import (
	"errors"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 2 defect 5 (D2): a duplicate yor_trace hidden inside merge() was not seen, so the
// other block was patched instead of refusing. Derived from probe zz_verify_target_test.go (b2).
func TestYorTraceDuplicateInsideMergeIsAmbiguous(t *testing.T) {
	src := []byte(`resource "aws_instance" "x" {
  ami  = "a"
  tags = merge(local.t, { yor_trace = "dup" })
}
resource "aws_instance" "y" {
  ami  = "b"
  tags = { yor_trace = "dup" }
}
`)
	f := model.Finding{CanonicalID: "EC2_IMDSV1", Tags: map[string]string{"yor_trace": "dup"}, Resource: model.Resource{ID: "i-1"}}
	p, err := patchSource(f, "m.tf", src, nil)
	if !errors.Is(err, ErrAmbiguousTarget) {
		addr := ""
		if p != nil {
			addr = p.Address
		}
		t.Fatalf("want ErrAmbiguousTarget, got patch of %q err=%v", addr, err)
	}
}

func TestYorTraceNestedExpressionsStillResolve(t *testing.T) {
	src := []byte(`resource "aws_instance" "x" {
  ami  = "a"
  tags = merge(local.t, { Name = "x" }, { yor_trace = "only-x" })
}
resource "aws_instance" "y" {
  ami  = "b"
  tags = { yor_trace = "other" }
}
resource "aws_instance" "z" {
  ami  = "c"
  tags = merge({ yor_trace = "conflict-1" }, { yor_trace = "conflict-2" })
}
`)
	f := model.Finding{CanonicalID: "EC2_IMDSV1", Tags: map[string]string{"yor_trace": "only-x"}, Resource: model.Resource{ID: "i-1"}}
	p, err := patchSource(f, "m.tf", src, nil)
	if err != nil || p == nil || p.Address != "aws_instance.x" {
		t.Fatalf("unique trace in merge(): %v %v", p, err)
	}
	// A block carrying two different yor_trace literals cannot be trusted either way.
	f.Tags["yor_trace"] = "conflict-1"
	if _, err := patchSource(f, "m.tf", src, nil); !errors.Is(err, ErrAmbiguousTarget) {
		t.Fatalf("conflicting traces in one block: want ErrAmbiguousTarget, got %v", err)
	}
}
