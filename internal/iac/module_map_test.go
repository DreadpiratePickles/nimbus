package iac

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 2 defect 1 (D1): a tfstate-mapped finding for one module patched another module's
// file because MapCloudToCode keyed blocks by bare type.name. Derived from the verifier probe
// zz_verify_target_test.go (case a4).

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func twoModuleTree(t *testing.T) string {
	d := t.TempDir()
	writeTree(t, d, map[string]string{
		"main.tf": `module "a" {
  source = "./modules/a"
}
module "b" {
  source = "./modules/b"
}
resource "aws_instance" "web" {
  ami = "root"
}
`,
		"modules/a/main.tf": "resource \"aws_instance\" \"web\" {\n  ami = \"A\"\n}\n",
		// extra lines so module b's block does not start on the same line as module a's
		"modules/b/main.tf": "# module b\n\nresource \"aws_instance\" \"web\" {\n  ami = \"B\"\n}\n",
		"terraform.tfstate": `{"version":4,"resources":[
 {"module":"module.a","mode":"managed","type":"aws_instance","name":"web","instances":[{"attributes":{"id":"i-aaa","arn":"arn:aws:ec2:us-east-1:1:instance/i-aaa"}}]},
 {"module":"module.b","mode":"managed","type":"aws_instance","name":"web","instances":[{"index_key":0,"attributes":{"id":"i-bbb","arn":"arn:aws:ec2:us-east-1:1:instance/i-bbb"}}]},
 {"mode":"managed","type":"aws_instance","name":"web","instances":[{"attributes":{"id":"i-root","arn":"arn:aws:ec2:us-east-1:1:instance/i-root"}}]},
 {"mode":"data","type":"aws_instance","name":"web","instances":[{"attributes":{"id":"i-data"}}]}]}`,
	})
	return d
}

func TestMapCloudToCodeResolvesModuleAddress(t *testing.T) {
	d := twoModuleTree(t)
	m, err := MapCloudToCode(filepath.Join(d, "terraform.tfstate"), d)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{ file, addr, ami string }{
		"i-aaa":  {"modules/a/main.tf", "module.a.aws_instance.web", `"A"`},
		"i-bbb":  {"modules/b/main.tf", "module.b.aws_instance.web[0]", `"B"`},
		"i-root": {"main.tf", "aws_instance.web", `"root"`},
	}
	for id, w := range want {
		f := model.Finding{CanonicalID: "EC2_IMDSV1", Resource: model.Resource{ID: "arn:aws:ec2:us-east-1:1:instance/" + id, Name: id, Type: "aws_instance"}}
		loc, ok := Locate(f, m)
		if !ok || loc.File != w.file || loc.Address != w.addr {
			t.Errorf("%s: located=%v file=%q addr=%q; want %s %s", id, ok, loc.File, loc.Address, w.file, w.addr)
			continue
		}
		// The CLI copies the location onto the finding and patches (cli/fix.go).
		f.File, f.LineStart, f.Resource.ID = loc.File, loc.Line, loc.Address
		p, err := PatchTerraform(f, d)
		if err != nil || p == nil {
			t.Errorf("%s: patch: %v %v", id, p, err)
			continue
		}
		if p.File != w.file || !strings.Contains(p.Before, "ami = "+w.ami) {
			t.Errorf("%s: patched %s (before contains ami %s? %v)", id, p.File, w.ami, strings.Contains(p.Before, w.ami))
		}
	}
	// Data sources are never mapped onto resource blocks.
	if _, ok := Locate(model.Finding{Resource: model.Resource{ID: "i-data"}}, m); ok {
		t.Errorf("data source i-data was mapped onto a resource block")
	}
}

func TestPatchRefusesModuleAddressInOtherModuleFile(t *testing.T) {
	d := twoModuleTree(t)
	for _, file := range []string{"modules/a/main.tf", "main.tf"} {
		f := model.Finding{CanonicalID: "EC2_IMDSV1", File: file, Resource: model.Resource{ID: "module.b.aws_instance.web"}}
		p, err := PatchTerraform(f, d)
		if !errors.Is(err, ErrAmbiguousTarget) {
			t.Errorf("module.b address with file %s: want ErrAmbiguousTarget, got patch=%v err=%v", file, p != nil, err)
		}
	}
	f := model.Finding{CanonicalID: "EC2_IMDSV1", File: "modules/b/main.tf", Resource: model.Resource{ID: "module.b.aws_instance.web"}}
	if p, err := PatchTerraform(f, d); err != nil || p == nil {
		t.Errorf("matching module file refused: %v", err)
	}
}

func TestMapCloudToCodeRefusesNonUniqueAddress(t *testing.T) {
	d := t.TempDir()
	writeTree(t, d, map[string]string{
		"main.tf":           "module \"a\" {\n  source = \"./modules/a\"\n}\n",
		"modules/a/one.tf":  "resource \"aws_instance\" \"web\" {\n  ami = \"1\"\n}\n",
		"modules/a/two.tf":  "resource \"aws_instance\" \"web\" {\n  ami = \"2\"\n}\n",
		"terraform.tfstate": `{"version":4,"resources":[{"module":"module.a","mode":"managed","type":"aws_instance","name":"web","instances":[{"attributes":{"id":"i-aaa"}}]}]}`,
	})
	m, err := MapCloudToCode(filepath.Join(d, "terraform.tfstate"), d)
	if err != nil {
		t.Fatal(err)
	}
	f := model.Finding{Resource: model.Resource{ID: "i-aaa"}}
	if loc, ok := Locate(f, m); ok {
		t.Errorf("duplicate address located at %s:%d", loc.File, loc.Line)
	}
	if _, err := LocateStrict(f, m); !errors.Is(err, ErrAmbiguousTarget) {
		t.Errorf("LocateStrict: want ErrAmbiguousTarget, got %v", err)
	}
}

func TestMapCloudToCodeShowJSONChildModules(t *testing.T) {
	d := twoModuleTree(t)
	writeTree(t, d, map[string]string{"show.json": `{"values":{"root_module":{
  "resources":[{"address":"aws_instance.web","mode":"managed","type":"aws_instance","name":"web","values":{"id":"i-root"}}],
  "child_modules":[
    {"address":"module.a","resources":[{"address":"module.a.aws_instance.web","mode":"managed","type":"aws_instance","name":"web","values":{"id":"i-aaa"}}]},
    {"address":"module.b","resources":[{"address":"module.b.aws_instance.web","mode":"managed","type":"aws_instance","name":"web","values":{"id":"i-bbb"}}]}]}}}`})
	m, err := MapCloudToCode(filepath.Join(d, "show.json"), d)
	if err != nil {
		t.Fatal(err)
	}
	for id, file := range map[string]string{"i-aaa": "modules/a/main.tf", "i-bbb": "modules/b/main.tf", "i-root": "main.tf"} {
		loc, ok := Locate(model.Finding{Resource: model.Resource{ID: id}}, m)
		if !ok || loc.File != file {
			t.Errorf("%s: ok=%v file=%q want %s", id, ok, loc.File, file)
		}
	}
}
