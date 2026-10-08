package iac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const tf = `resource "aws_s3_bucket" "exports" {
  bucket = "customer-exports"
  acl    = "public-read" # TODO
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "t3.micro"
  tags = { yor_trace = "abc-123" }
}

resource "aws_db_instance" "pay" {
  identifier          = "payments"
  publicly_accessible = true
  storage_encrypted   = true
}
`

func TestScanAndPatch(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o644)
	fs, err := ScanTerraform(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fails := map[string]model.Finding{}
	for _, f := range fs {
		if f.Status == model.Fail {
			fails[f.CanonicalID+"/"+f.Resource.ID] = f
		}
	}
	for _, want := range []string{"S3_PUBLIC_BUCKET/aws_s3_bucket.exports", "EC2_SG_OPEN_SSH/aws_security_group.web", "EC2_IMDSV1/aws_instance.web", "RDS_PUBLIC/aws_db_instance.pay"} {
		if _, ok := fails[want]; !ok {
			t.Errorf("missing %s; got %v", want, keys(fails))
		}
	}
	if _, ok := fails["RDS_UNENCRYPTED/aws_db_instance.pay"]; ok {
		t.Errorf("encrypted db flagged")
	}
	f := fails["S3_PUBLIC_BUCKET/aws_s3_bucket.exports"]
	if f.File != "main.tf" || f.LineStart != 1 {
		t.Errorf("location: %s:%d", f.File, f.LineStart)
	}
	p, err := PatchTerraform(f, dir)
	if err != nil || p == nil {
		t.Fatalf("patch: %v %v", err, p)
	}
	if !strings.Contains(p.After, `acl    = "private"`) && !strings.Contains(p.After, `acl = "private"`) || !strings.Contains(p.After, "# TODO") || p.WidensAccess || !strings.Contains(p.Diff, "-  acl") {
		t.Errorf("patch content:\n%s\n%s", p.After, p.Diff)
	}
	p2, _ := PatchTerraform(fails["EC2_IMDSV1/aws_instance.web"], dir)
	if p2 == nil || !strings.Contains(p2.After, `http_tokens`) || !strings.Contains(p2.After, "required") {
		t.Errorf("imds patch: %+v", p2)
	}
	p3, _ := PatchTerraform(fails["EC2_SG_OPEN_SSH/aws_security_group.web"], dir)
	if p3 == nil || strings.Contains(p3.After, "0.0.0.0/0") || !strings.Contains(p3.After, "var.allowed_cidrs") {
		t.Errorf("sg patch: %+v", p3)
	}
	if widens("x", "cidr_blocks = [\"0.0.0.0/0\"]") == false {
		t.Errorf("guardrail")
	}
	state := `{"resources":[{"module":"","type":"aws_instance","name":"web","instances":[{"attributes":{"id":"i-0abc","arn":"arn:aws:ec2:us-east-1:1:instance/i-0abc","tags":{"yor_trace":"abc-123"}}}]}]}`
	os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte(state), 0o644)
	m, err := MapCloudToCode(filepath.Join(dir, "terraform.tfstate"), dir)
	if err != nil {
		t.Fatal(err)
	}
	loc, ok := Locate(model.Finding{Resource: model.Resource{ID: "arn:aws:ec2:us-east-1:1:instance/i-0abc"}}, m)
	if !ok || loc.File != "main.tf" || loc.Line == 0 || loc.Address != "aws_instance.web" {
		t.Errorf("cloud-to-code: %+v %v", loc, ok)
	}
	if _, ok := Locate(model.Finding{Resource: model.Resource{ID: "zzz", Attributes: map[string]any{"tags": map[string]any{"yor_trace": "abc-123"}}}}, m); !ok {
		t.Errorf("yor trace lookup")
	}
	if DetectKind("x.bicep", nil) != Bicep || DetectKind("deploy.yaml", []byte("apiVersion: v1\nkind: Pod")) != Kubernetes || DetectKind("t.yaml", []byte("AWSTemplateFormatVersion: x")) != CloudFormation || DetectKind("app.ts", []byte("import * as cdk from 'aws-cdk-lib'")) != CDK {
		t.Errorf("detect kinds")
	}
	inv, _ := Inventory(dir)
	if len(inv[Terraform]) != 1 {
		t.Errorf("inventory: %v", inv)
	}
}

func keys(m map[string]model.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
