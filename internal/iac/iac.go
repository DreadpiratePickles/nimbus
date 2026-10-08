// Package iac provides native Infrastructure-as-Code scanning and patching:
//   - file-type detection (Terraform, CloudFormation, Bicep, Kubernetes, Helm, Pulumi, CDK, Ansible)
//   - a built-in Terraform (HCL) scanner for the highest-impact checks (no Python needed)
//   - an HCL patcher that rewrites the offending block in place (hclwrite, comments preserved)
//   - cloud-to-code mapping: Terraform state (and Yor `yor_trace` tags) link a live resource to file:line
package iac

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type Kind string

const (
	Terraform      Kind = "terraform"
	CloudFormation Kind = "cloudformation"
	Bicep          Kind = "bicep"
	Kubernetes     Kind = "kubernetes"
	Helm           Kind = "helm"
	Pulumi         Kind = "pulumi"
	CDK            Kind = "cdk"
	Ansible        Kind = "ansible"
	Dockerfile     Kind = "dockerfile"
	Unknown        Kind = ""
)

// DetectKind classifies a file by extension and content sniffing.
func DetectKind(path string, head []byte) Kind {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	h := string(head)
	switch {
	case ext == ".tf" || ext == ".tfvars" || ext == ".hcl":
		return Terraform
	case ext == ".bicep":
		return Bicep
	case base == "dockerfile" || strings.HasSuffix(base, ".dockerfile"):
		return Dockerfile
	case base == "chart.yaml" || base == "values.yaml" || strings.Contains(path, "/templates/") && (ext == ".yaml" || ext == ".yml" || ext == ".tpl"):
		return Helm
	case base == "pulumi.yaml" || strings.Contains(h, "pulumi."):
		return Pulumi
	case base == "cdk.json" || strings.Contains(h, "aws-cdk-lib") || strings.Contains(h, "@aws-cdk/"):
		return CDK
	case ext == ".yaml" || ext == ".yml" || ext == ".json":
		switch {
		case strings.Contains(h, "AWSTemplateFormatVersion") || strings.Contains(h, "\"Resources\"") && strings.Contains(h, "\"Type\": \"AWS::") || strings.Contains(h, "Type: AWS::"):
			return CloudFormation
		case strings.Contains(h, "apiVersion:") && strings.Contains(h, "kind:"):
			return Kubernetes
		case strings.Contains(h, "hosts:") && (strings.Contains(h, "tasks:") || strings.Contains(h, "roles:")):
			return Ansible
		case base == "playbook.yml" || base == "playbook.yaml" || base == "site.yml":
			return Ansible
		}
	case ext == ".ts" || ext == ".py" || ext == ".go" || ext == ".cs" || ext == ".java":
		if strings.Contains(h, "aws-cdk") || strings.Contains(h, "aws_cdk") {
			return CDK
		}
		if strings.Contains(h, "@pulumi/") || strings.Contains(h, "import pulumi") {
			return Pulumi
		}
	}
	return Unknown
}

// Inventory walks a directory and groups files by IaC kind (used to decide which external scanners to run).
func Inventory(root string) (map[Kind][]string, error) {
	out := map[Kind][]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == ".terraform" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		head := make([]byte, 4096)
		n, _ := f.Read(head)
		f.Close()
		if k := DetectKind(p, head[:n]); k != Unknown {
			out[k] = append(out[k], p)
		}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------- native Terraform scanner

type Block struct {
	File    string
	Type    string // resource type e.g. aws_s3_bucket
	Name    string
	Address string // aws_s3_bucket.exports
	Range   hcl.Range
	Attrs   map[string]cty.Value
	Body    *hclsyntax.Body
}

// ParseTerraform parses every .tf file under root (non-recursive into .terraform).
func ParseTerraform(root string) ([]Block, hcl.Diagnostics) {
	var blocks []Block
	var diags hcl.Diagnostics
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && (d.Name() == ".terraform" || d.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(p) != ".tf" {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		f, dg := hclsyntax.ParseConfig(src, p, hcl.Pos{Line: 1, Column: 1})
		diags = append(diags, dg...)
		if f == nil {
			return nil
		}
		body, ok := f.Body.(*hclsyntax.Body)
		if !ok {
			return nil
		}
		for _, b := range body.Blocks {
			if b.Type != "resource" || len(b.Labels) != 2 {
				continue
			}
			blk := Block{File: p, Type: b.Labels[0], Name: b.Labels[1], Address: b.Labels[0] + "." + b.Labels[1], Range: b.Range(), Attrs: map[string]cty.Value{}, Body: b.Body}
			for name, attr := range b.Body.Attributes {
				v, d := attr.Expr.Value(nil)
				if !d.HasErrors() {
					blk.Attrs[name] = v
				}
			}
			blocks = append(blocks, blk)
		}
		return nil
	})
	return blocks, diags
}

func attrString(b Block, name string) (string, bool) {
	v, ok := b.Attrs[name]
	if !ok || v.IsNull() || !v.IsKnown() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

func attrBool(b Block, name string) (bool, bool) {
	v, ok := b.Attrs[name]
	if !ok || v.IsNull() || !v.IsKnown() || v.Type() != cty.Bool {
		return false, false
	}
	return v.True(), true
}

func nestedBlocks(b Block, typ string) []*hclsyntax.Block {
	var out []*hclsyntax.Block
	for _, nb := range b.Body.Blocks {
		if nb.Type == typ {
			out = append(out, nb)
		}
	}
	return out
}

func blockAttrString(nb *hclsyntax.Block, name string) (string, bool) {
	a, ok := nb.Body.Attributes[name]
	if !ok {
		return "", false
	}
	v, d := a.Expr.Value(nil)
	if d.HasErrors() || v.IsNull() || !v.IsKnown() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

func blockAttrList(nb *hclsyntax.Block, name string) []string {
	a, ok := nb.Body.Attributes[name]
	if !ok {
		return nil
	}
	v, d := a.Expr.Value(nil)
	if d.HasErrors() || v.IsNull() || !v.IsKnown() || !v.CanIterateElements() {
		return nil
	}
	var out []string
	for it := v.ElementIterator(); it.Next(); {
		_, ev := it.Element()
		if ev.Type() == cty.String && ev.IsKnown() && !ev.IsNull() {
			out = append(out, ev.AsString())
		}
	}
	return out
}

func blockAttrNumber(nb *hclsyntax.Block, name string) (int64, bool) {
	a, ok := nb.Body.Attributes[name]
	if !ok {
		return 0, false
	}
	v, d := a.Expr.Value(nil)
	if d.HasErrors() || v.IsNull() || !v.IsKnown() || v.Type() != cty.Number {
		return 0, false
	}
	n, _ := v.AsBigFloat().Int64()
	return n, true
}

type rule struct {
	ID       string // canonical ID
	CheckID  string
	Title    string
	Severity model.Severity
	Types    []string
	Eval     func(b Block, all []Block) (fail bool, detail string)
}

var rules = []rule{
	{ID: "S3_PUBLIC_BUCKET", CheckID: "NIMBUS_TF_S3_PUBLIC", Title: "S3 bucket ACL grants public access", Severity: model.High, Types: []string{"aws_s3_bucket", "aws_s3_bucket_acl"}, Eval: func(b Block, _ []Block) (bool, string) {
		if acl, ok := attrString(b, "acl"); ok && (acl == "public-read" || acl == "public-read-write" || acl == "authenticated-read") {
			return true, "acl = " + acl
		}
		return false, ""
	}},
	{ID: "S3_PUBLIC_BUCKET", CheckID: "NIMBUS_TF_S3_PAB", Title: "S3 public access block does not block all public access", Severity: model.High, Types: []string{"aws_s3_bucket_public_access_block"}, Eval: func(b Block, _ []Block) (bool, string) {
		for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
			if v, ok := attrBool(b, k); !ok || !v {
				return true, k + " is not true"
			}
		}
		return false, ""
	}},
	{ID: "EC2_SG_OPEN_SSH", CheckID: "NIMBUS_TF_SG_OPEN", Title: "Security group ingress open to the world", Severity: model.High, Types: []string{"aws_security_group"}, Eval: func(b Block, _ []Block) (bool, string) {
		for _, ing := range nestedBlocks(b, "ingress") {
			for _, c := range blockAttrList(ing, "cidr_blocks") {
				if c == "0.0.0.0/0" {
					from, _ := blockAttrNumber(ing, "from_port")
					to, _ := blockAttrNumber(ing, "to_port")
					return true, fmt.Sprintf("ingress %d-%d from 0.0.0.0/0", from, to)
				}
			}
			for _, c := range blockAttrList(ing, "ipv6_cidr_blocks") {
				if c == "::/0" {
					return true, "ingress from ::/0"
				}
			}
		}
		return false, ""
	}},
	{ID: "EC2_SG_OPEN_SSH", CheckID: "NIMBUS_TF_SG_RULE_OPEN", Title: "Security group rule open to the world", Severity: model.High, Types: []string{"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}, Eval: func(b Block, _ []Block) (bool, string) {
		if t, ok := attrString(b, "type"); ok && t != "ingress" {
			return false, ""
		}
		if c, ok := attrString(b, "cidr_ipv4"); ok && c == "0.0.0.0/0" {
			return true, "cidr_ipv4 = 0.0.0.0/0"
		}
		if v, ok := b.Attrs["cidr_blocks"]; ok && v.IsKnown() && !v.IsNull() && v.CanIterateElements() {
			for it := v.ElementIterator(); it.Next(); {
				_, ev := it.Element()
				if ev.Type() == cty.String && ev.AsString() == "0.0.0.0/0" {
					return true, "cidr_blocks contains 0.0.0.0/0"
				}
			}
		}
		return false, ""
	}},
	{ID: "EC2_IMDSV1", CheckID: "NIMBUS_TF_IMDSV1", Title: "EC2 instance allows IMDSv1", Severity: model.High, Types: []string{"aws_instance", "aws_launch_template"}, Eval: func(b Block, _ []Block) (bool, string) {
		mo := nestedBlocks(b, "metadata_options")
		if len(mo) == 0 {
			return true, "metadata_options block missing (http_tokens defaults to optional)"
		}
		if t, ok := blockAttrString(mo[0], "http_tokens"); !ok || t != "required" {
			return true, "http_tokens is not \"required\""
		}
		return false, ""
	}},
	{ID: "EC2_PUBLIC_IP", CheckID: "NIMBUS_TF_PUBLIC_IP", Title: "EC2 instance associates a public IP", Severity: model.Medium, Types: []string{"aws_instance"}, Eval: func(b Block, _ []Block) (bool, string) {
		if v, ok := attrBool(b, "associate_public_ip_address"); ok && v {
			return true, "associate_public_ip_address = true"
		}
		return false, ""
	}},
	{ID: "EBS_UNENCRYPTED", CheckID: "NIMBUS_TF_EBS_ENC", Title: "EBS volume not encrypted", Severity: model.Medium, Types: []string{"aws_ebs_volume"}, Eval: func(b Block, _ []Block) (bool, string) {
		if v, ok := attrBool(b, "encrypted"); !ok || !v {
			return true, "encrypted is not true"
		}
		return false, ""
	}},
	{ID: "RDS_PUBLIC", CheckID: "NIMBUS_TF_RDS_PUBLIC", Title: "RDS instance publicly accessible", Severity: model.Critical, Types: []string{"aws_db_instance", "aws_rds_cluster_instance"}, Eval: func(b Block, _ []Block) (bool, string) {
		if v, ok := attrBool(b, "publicly_accessible"); ok && v {
			return true, "publicly_accessible = true"
		}
		return false, ""
	}},
	{ID: "RDS_UNENCRYPTED", CheckID: "NIMBUS_TF_RDS_ENC", Title: "RDS storage not encrypted", Severity: model.High, Types: []string{"aws_db_instance"}, Eval: func(b Block, _ []Block) (bool, string) {
		if v, ok := attrBool(b, "storage_encrypted"); !ok || !v {
			return true, "storage_encrypted is not true"
		}
		return false, ""
	}},
	{ID: "IAM_ADMIN_POLICY", CheckID: "NIMBUS_TF_IAM_STAR", Title: "IAM policy allows *:*", Severity: model.High, Types: []string{"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}, Eval: func(b Block, _ []Block) (bool, string) {
		if p, ok := attrString(b, "policy"); ok {
			var doc struct {
				Statement []map[string]any `json:"Statement"`
			}
			if json.Unmarshal([]byte(p), &doc) == nil {
				for _, st := range doc.Statement {
					if st["Effect"] == "Allow" && hasStar(st["Action"]) && hasStar(st["Resource"]) {
						return true, "statement allows Action \"*\" on Resource \"*\""
					}
				}
			}
		}
		return false, ""
	}},
	{ID: "CLOUDTRAIL_NO_LOG_VALIDATION", CheckID: "NIMBUS_TF_TRAIL_VALIDATION", Title: "CloudTrail log validation disabled", Severity: model.Low, Types: []string{"aws_cloudtrail"}, Eval: func(b Block, _ []Block) (bool, string) {
		if v, ok := attrBool(b, "enable_log_file_validation"); !ok || !v {
			return true, "enable_log_file_validation is not true"
		}
		return false, ""
	}},
	{ID: "CLOUDTRAIL_DISABLED", CheckID: "NIMBUS_TF_TRAIL_REGION", Title: "CloudTrail is not multi-region", Severity: model.High, Types: []string{"aws_cloudtrail"}, Eval: func(b Block, _ []Block) (bool, string) {
		if v, ok := attrBool(b, "is_multi_region_trail"); !ok || !v {
			return true, "is_multi_region_trail is not true"
		}
		return false, ""
	}},
	{ID: "KMS_ROTATION_DISABLED", CheckID: "NIMBUS_TF_KMS_ROTATION", Title: "KMS key rotation disabled", Severity: model.Low, Types: []string{"aws_kms_key"}, Eval: func(b Block, _ []Block) (bool, string) {
		if v, ok := attrBool(b, "enable_key_rotation"); !ok || !v {
			return true, "enable_key_rotation is not true"
		}
		return false, ""
	}},
	{ID: "EKS_PUBLIC_ENDPOINT", CheckID: "NIMBUS_TF_EKS_PUBLIC", Title: "EKS endpoint public", Severity: model.High, Types: []string{"aws_eks_cluster"}, Eval: func(b Block, _ []Block) (bool, string) {
		for _, vc := range nestedBlocks(b, "vpc_config") {
			a, ok := vc.Body.Attributes["endpoint_public_access"]
			if !ok {
				return true, "endpoint_public_access defaults to true"
			}
			v, _ := a.Expr.Value(nil)
			if v.Type() == cty.Bool && v.True() {
				return true, "endpoint_public_access = true"
			}
		}
		return false, ""
	}},
	{ID: "AZ_STORAGE_PUBLIC_BLOB", CheckID: "NIMBUS_TF_AZ_BLOB_PUBLIC", Title: "Storage account allows public blob access", Severity: model.High, Types: []string{"azurerm_storage_account"}, Eval: func(b Block, _ []Block) (bool, string) {
		if v, ok := attrBool(b, "allow_nested_items_to_be_public"); !ok || v {
			return true, "allow_nested_items_to_be_public is not false"
		}
		return false, ""
	}},
	{ID: "AZ_STORAGE_HTTP_ALLOWED", CheckID: "NIMBUS_TF_AZ_HTTPS", Title: "Storage account does not enforce HTTPS", Severity: model.Medium, Types: []string{"azurerm_storage_account"}, Eval: func(b Block, _ []Block) (bool, string) {
		for _, k := range []string{"https_traffic_only_enabled", "enable_https_traffic_only"} {
			if v, ok := attrBool(b, k); ok {
				return !v, k + " = false"
			}
		}
		return false, ""
	}},
	{ID: "AZ_NSG_OPEN_SSH", CheckID: "NIMBUS_TF_AZ_NSG_OPEN", Title: "NSG rule allows inbound from Internet", Severity: model.High, Types: []string{"azurerm_network_security_rule"}, Eval: func(b Block, _ []Block) (bool, string) {
		dir, _ := attrString(b, "direction")
		acc, _ := attrString(b, "access")
		src, _ := attrString(b, "source_address_prefix")
		if strings.EqualFold(dir, "Inbound") && strings.EqualFold(acc, "Allow") && (src == "*" || src == "0.0.0.0/0" || strings.EqualFold(src, "Internet") || strings.EqualFold(src, "Any")) {
			return true, "source_address_prefix = " + src
		}
		return false, ""
	}},
	{ID: "GCP_BUCKET_PUBLIC", CheckID: "NIMBUS_TF_GCS_PUBLIC", Title: "GCS bucket IAM grants allUsers", Severity: model.High, Types: []string{"google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"}, Eval: func(b Block, _ []Block) (bool, string) {
		if m, ok := attrString(b, "member"); ok && (m == "allUsers" || m == "allAuthenticatedUsers") {
			return true, "member = " + m
		}
		if v, ok := b.Attrs["members"]; ok && v.IsKnown() && v.CanIterateElements() {
			for it := v.ElementIterator(); it.Next(); {
				_, ev := it.Element()
				if ev.Type() == cty.String && (ev.AsString() == "allUsers" || ev.AsString() == "allAuthenticatedUsers") {
					return true, "members contains " + ev.AsString()
				}
			}
		}
		return false, ""
	}},
	{ID: "GCP_FIREWALL_OPEN_SSH", CheckID: "NIMBUS_TF_GCP_FW_OPEN", Title: "GCP firewall allows ingress from 0.0.0.0/0", Severity: model.High, Types: []string{"google_compute_firewall"}, Eval: func(b Block, _ []Block) (bool, string) {
		if v, ok := b.Attrs["source_ranges"]; ok && v.IsKnown() && !v.IsNull() && v.CanIterateElements() {
			for it := v.ElementIterator(); it.Next(); {
				_, ev := it.Element()
				if ev.Type() == cty.String && ev.AsString() == "0.0.0.0/0" && len(nestedBlocks(b, "allow")) > 0 {
					return true, "source_ranges contains 0.0.0.0/0"
				}
			}
		}
		return false, ""
	}},
	{ID: "GCP_SQL_PUBLIC", CheckID: "NIMBUS_TF_GCP_SQL_PUBLIC", Title: "Cloud SQL has a public IPv4 address", Severity: model.Critical, Types: []string{"google_sql_database_instance"}, Eval: func(b Block, _ []Block) (bool, string) {
		for _, s := range nestedBlocks(b, "settings") {
			for _, ip := range s.Body.Blocks {
				if ip.Type == "ip_configuration" {
					if a, ok := ip.Body.Attributes["ipv4_enabled"]; ok {
						v, _ := a.Expr.Value(nil)
						if v.Type() == cty.Bool && v.True() {
							return true, "ipv4_enabled = true"
						}
					}
				}
			}
		}
		return false, ""
	}},
}

func hasStar(v any) bool {
	switch t := v.(type) {
	case string:
		return t == "*"
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}

// ScanTerraform runs the native rules over a directory and returns findings.
func ScanTerraform(root string, now time.Time) ([]model.Finding, error) {
	blocks, diags := ParseTerraform(root)
	if diags.HasErrors() && len(blocks) == 0 {
		return nil, fmt.Errorf("parse: %s", diags.Error())
	}
	var out []model.Finding
	for _, b := range blocks {
		for _, r := range rules {
			if !containsStr(r.Types, b.Type) {
				continue
			}
			fail, detail := r.Eval(b, blocks)
			status := model.Pass
			if fail {
				status = model.Fail
			}
			rel, _ := filepath.Rel(root, b.File)
			if rel == "" || strings.HasPrefix(rel, "..") {
				rel = b.File
			}
			f := model.Finding{
				Source: "nimbus-iac", CheckID: r.CheckID, CanonicalID: r.ID, Title: r.Title, Description: detail, Severity: r.Severity, Status: status,
				Provider: providerOfType(b.Type), Account: "iac", File: filepath.ToSlash(rel), LineStart: b.Range.Start.Line, LineEnd: b.Range.End.Line,
				Resource: model.Resource{ID: b.Address, Type: b.Type, Name: b.Name, Attributes: map[string]any{"file": rel, "address": b.Address}},
				Tags:     map[string]string{"framework": "terraform"},
			}
			f.Finalize(now)
			out = append(out, f)
		}
	}
	return out, nil
}

func providerOfType(t string) string {
	switch {
	case strings.HasPrefix(t, "aws_"):
		return model.ProviderAWS
	case strings.HasPrefix(t, "azurerm_"), strings.HasPrefix(t, "azuread_"):
		return model.ProviderAzure
	case strings.HasPrefix(t, "google_"):
		return model.ProviderGCP
	case strings.HasPrefix(t, "oci_"):
		return model.ProviderOCI
	case strings.HasPrefix(t, "kubernetes_"), strings.HasPrefix(t, "helm_"):
		return model.ProviderKubernetes
	case strings.HasPrefix(t, "github_"):
		return model.ProviderGitHub
	case strings.HasPrefix(t, "okta_"):
		return model.ProviderOkta
	}
	return model.ProviderIaC
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- patcher

// Patch is a proposed in-place change to an IaC file.
type Patch struct {
	File        string `json:"file"`
	Address     string `json:"address"`
	CanonicalID string `json:"canonical_id"`
	Before      string `json:"before"`
	After       string `json:"after"`
	Diff        string `json:"diff"`
	Explanation string `json:"explanation"`
	Confidence  float64 `json:"confidence"` // 1.0 deterministic rewrite; <1 when assumptions were made
	WidensAccess bool  `json:"widens_access"` // guardrail: must be false before auto-commit
}

// PatchTerraform rewrites the block that a finding points at. It returns nil when no
// deterministic fix exists for the canonical ID (callers then fall back to the generated template).
func PatchTerraform(f model.Finding, root string) (*Patch, error) {
	file := f.File
	if !filepath.IsAbs(file) {
		file = filepath.Join(root, file)
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	wf, diags := hclwrite.ParseConfig(src, file, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse %s: %s", file, diags.Error())
	}
	var target *hclwrite.Block
	addr := f.Resource.ID
	for _, b := range wf.Body().Blocks() {
		if b.Type() == "resource" && len(b.Labels()) == 2 && b.Labels()[0]+"."+b.Labels()[1] == addr {
			target = b
			break
		}
	}
	if target == nil {
		// fall back to line match
		for _, b := range wf.Body().Blocks() {
			if b.Type() == "resource" && len(b.Labels()) == 2 && strings.HasSuffix(addr, b.Labels()[1]) {
				target = b
			}
		}
	}
	if target == nil {
		return nil, fmt.Errorf("resource %s not found in %s", addr, file)
	}
	explanation, conf, applied := applyFix(target, f.CanonicalID)
	if !applied {
		return nil, nil
	}
	after := hclwrite.Format(wf.Bytes())
	p := &Patch{File: f.File, Address: addr, CanonicalID: f.CanonicalID, Before: string(src), After: string(after), Explanation: explanation, Confidence: conf}
	p.Diff = UnifiedDiff(f.File, string(src), string(after))
	p.WidensAccess = widens(string(src), string(after))
	return p, nil
}

func applyFix(b *hclwrite.Block, canonical string) (string, float64, bool) {
	body := b.Body()
	typ := b.Labels()[0]
	switch canonical {
	case "S3_PUBLIC_BUCKET":
		if typ == "aws_s3_bucket" || typ == "aws_s3_bucket_acl" {
			body.SetAttributeValue("acl", cty.StringVal("private"))
			return "Set acl = \"private\"; add an aws_s3_bucket_public_access_block with all four flags true to block policy-based exposure.", 1, true
		}
		if typ == "aws_s3_bucket_public_access_block" {
			for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				body.SetAttributeValue(k, cty.True)
			}
			return "Enabled all four public access block settings.", 1, true
		}
	case "EC2_SG_OPEN_SSH", "EC2_SG_OPEN_RDP", "EC2_SG_OPEN_ALL":
		changed := false
		for _, nb := range body.Blocks() {
			if nb.Type() != "ingress" {
				continue
			}
			if a := nb.Body().GetAttribute("cidr_blocks"); a != nil && strings.Contains(string(a.Expr().BuildTokens(nil).Bytes()), "0.0.0.0/0") {
				nb.Body().SetAttributeRaw("cidr_blocks", hclwrite.TokensForTraversal(hcl.Traversal{hcl.TraverseRoot{Name: "var"}, hcl.TraverseAttr{Name: "allowed_cidrs"}}))
				changed = true
			}
			if a := nb.Body().GetAttribute("ipv6_cidr_blocks"); a != nil && strings.Contains(string(a.Expr().BuildTokens(nil).Bytes()), "::/0") {
				nb.Body().RemoveAttribute("ipv6_cidr_blocks")
				changed = true
			}
		}
		if typ == "aws_security_group_rule" || typ == "aws_vpc_security_group_ingress_rule" {
			if a := body.GetAttribute("cidr_blocks"); a != nil {
				body.SetAttributeRaw("cidr_blocks", hclwrite.TokensForTraversal(hcl.Traversal{hcl.TraverseRoot{Name: "var"}, hcl.TraverseAttr{Name: "allowed_cidrs"}}))
				changed = true
			}
			if a := body.GetAttribute("cidr_ipv4"); a != nil {
				body.SetAttributeRaw("cidr_ipv4", hclwrite.TokensForTraversal(hcl.Traversal{hcl.TraverseRoot{Name: "var"}, hcl.TraverseAttr{Name: "allowed_cidr"}}))
				changed = true
			}
		}
		if changed {
			return "Replaced 0.0.0.0/0 with var.allowed_cidrs (declare: variable \"allowed_cidrs\" { type = list(string) }) so ingress is an explicit allow-list.", 0.9, true
		}
	case "EC2_IMDSV1":
		var mo *hclwrite.Block
		for _, nb := range body.Blocks() {
			if nb.Type() == "metadata_options" {
				mo = nb
			}
		}
		if mo == nil {
			mo = body.AppendNewBlock("metadata_options", nil)
		}
		mo.Body().SetAttributeValue("http_endpoint", cty.StringVal("enabled"))
		mo.Body().SetAttributeValue("http_tokens", cty.StringVal("required"))
		mo.Body().SetAttributeValue("http_put_response_hop_limit", cty.NumberIntVal(1))
		return "Require IMDSv2 (http_tokens = \"required\") and limit the hop count so containers cannot reach the metadata service.", 1, true
	case "EC2_PUBLIC_IP":
		body.SetAttributeValue("associate_public_ip_address", cty.False)
		return "Disabled public IP association; front the instance with a load balancer or NAT.", 0.8, true
	case "EBS_UNENCRYPTED":
		body.SetAttributeValue("encrypted", cty.True)
		return "Enabled EBS encryption with the account default KMS key.", 1, true
	case "RDS_PUBLIC":
		body.SetAttributeValue("publicly_accessible", cty.False)
		return "Made the RDS instance private.", 1, true
	case "RDS_UNENCRYPTED":
		body.SetAttributeValue("storage_encrypted", cty.True)
		return "Enabled storage encryption (note: forces replacement for an existing instance; snapshot first).", 0.7, true
	case "CLOUDTRAIL_NO_LOG_VALIDATION":
		body.SetAttributeValue("enable_log_file_validation", cty.True)
		return "Enabled log file validation.", 1, true
	case "CLOUDTRAIL_DISABLED":
		body.SetAttributeValue("is_multi_region_trail", cty.True)
		body.SetAttributeValue("include_global_service_events", cty.True)
		return "Made the trail multi-region including global service events.", 1, true
	case "KMS_ROTATION_DISABLED":
		body.SetAttributeValue("enable_key_rotation", cty.True)
		return "Enabled annual key rotation.", 1, true
	case "EKS_PUBLIC_ENDPOINT":
		for _, nb := range body.Blocks() {
			if nb.Type() == "vpc_config" {
				nb.Body().SetAttributeValue("endpoint_public_access", cty.False)
				nb.Body().SetAttributeValue("endpoint_private_access", cty.True)
				return "Disabled the public API endpoint and enabled private access.", 0.9, true
			}
		}
	case "AZ_STORAGE_PUBLIC_BLOB":
		body.SetAttributeValue("allow_nested_items_to_be_public", cty.False)
		return "Disabled anonymous blob access.", 1, true
	case "AZ_STORAGE_HTTP_ALLOWED":
		body.SetAttributeValue("https_traffic_only_enabled", cty.True)
		body.SetAttributeValue("min_tls_version", cty.StringVal("TLS1_2"))
		return "Enforced HTTPS and TLS 1.2.", 1, true
	case "AZ_NSG_OPEN_SSH", "AZ_NSG_OPEN_RDP":
		body.SetAttributeRaw("source_address_prefix", hclwrite.TokensForTraversal(hcl.Traversal{hcl.TraverseRoot{Name: "var"}, hcl.TraverseAttr{Name: "allowed_source"}}))
		return "Replaced the Internet/Any source with var.allowed_source.", 0.9, true
	case "GCP_BUCKET_PUBLIC":
		if a := body.GetAttribute("member"); a != nil {
			body.SetAttributeRaw("member", hclwrite.TokensForTraversal(hcl.Traversal{hcl.TraverseRoot{Name: "var"}, hcl.TraverseAttr{Name: "bucket_reader"}}))
			return "Replaced allUsers with var.bucket_reader (a specific principal).", 0.9, true
		}
	case "GCP_FIREWALL_OPEN_SSH", "GCP_FIREWALL_OPEN_RDP":
		body.SetAttributeRaw("source_ranges", hclwrite.TokensForTraversal(hcl.Traversal{hcl.TraverseRoot{Name: "var"}, hcl.TraverseAttr{Name: "allowed_ranges"}}))
		return "Replaced 0.0.0.0/0 with var.allowed_ranges.", 0.9, true
	case "GCP_SQL_PUBLIC":
		for _, s := range body.Blocks() {
			if s.Type() == "settings" {
				for _, ip := range s.Body().Blocks() {
					if ip.Type() == "ip_configuration" {
						ip.Body().SetAttributeValue("ipv4_enabled", cty.False)
						return "Disabled the public IPv4 address; use private IP / Cloud SQL Auth Proxy.", 0.9, true
					}
				}
			}
		}
	}
	return "", 0, false
}

// widens is the "never widen access" guardrail: the patch must not introduce new world-open CIDRs,
// public ACLs, wildcard policies or publicly_accessible = true.
func widens(before, after string) bool {
	count := func(s, sub string) int { return strings.Count(s, sub) }
	for _, bad := range []string{"0.0.0.0/0", "::/0", "public-read", "allUsers", "publicly_accessible = true", "\"Action\": \"*\""} {
		if count(after, bad) > count(before, bad) {
			return true
		}
	}
	return false
}

// UnifiedDiff produces a minimal line-based unified diff (LCS) for PR bodies.
func UnifiedDiff(name, a, b string) string {
	al := strings.Split(a, "\n")
	bl := strings.Split(b, "\n")
	n, m := len(al), len(bl)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var out []string
	out = append(out, "--- a/"+name, "+++ b/"+name)
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && al[i] == bl[j]:
			out = append(out, " "+al[i])
			i++
			j++
		case i < n && (j >= m || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, "-"+al[i])
			i++
		default:
			out = append(out, "+"+bl[j])
			j++
		}
	}
	// collapse long unchanged runs
	var compact []string
	run := 0
	for _, l := range out {
		if strings.HasPrefix(l, " ") {
			run++
			if run > 3 {
				continue
			}
		} else {
			if run > 3 {
				compact = append(compact, "@@ ... @@")
			}
			run = 0
		}
		compact = append(compact, l)
	}
	return strings.Join(compact, "\n")
}

// ---------------------------------------------------------------- cloud-to-code mapping

// CodeLocation links a live cloud resource to its IaC definition.
type CodeLocation struct {
	Address string `json:"address"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Module  string `json:"module,omitempty"`
	Trace   string `json:"yor_trace,omitempty"`
}

// MapCloudToCode reads terraform.tfstate (or a `terraform show -json` dump) and the HCL
// sources to map cloud IDs/ARNs and yor_trace tags onto file:line.
func MapCloudToCode(statePath, root string) (map[string]CodeLocation, error) {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil, err
	}
	blocks, _ := ParseTerraform(root)
	byAddr := map[string]Block{}
	for _, b := range blocks {
		byAddr[b.Address] = b
	}
	out := map[string]CodeLocation{}
	var state struct {
		Resources []struct {
			Module    string `json:"module"`
			Type      string `json:"type"`
			Name      string `json:"name"`
			Instances []struct {
				Attributes map[string]any `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
		Values struct {
			RootModule struct {
				Resources []struct {
					Address string         `json:"address"`
					Type    string         `json:"type"`
					Name    string         `json:"name"`
					Values  map[string]any `json:"values"`
				} `json:"resources"`
			} `json:"root_module"`
		} `json:"values"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	add := func(addr, module string, attrs map[string]any) {
		loc := CodeLocation{Address: addr, Module: module}
		if b, ok := byAddr[addr]; ok {
			rel, _ := filepath.Rel(root, b.File)
			loc.File, loc.Line = filepath.ToSlash(rel), b.Range.Start.Line
		}
		if tags, ok := attrs["tags"].(map[string]any); ok {
			if t, ok := tags["yor_trace"].(string); ok {
				loc.Trace = t
				out["yor_trace:"+t] = loc
			}
		}
		for _, k := range []string{"arn", "id", "self_link", "name", "bucket"} {
			if v, ok := attrs[k].(string); ok && v != "" {
				if _, exists := out[v]; !exists {
					out[v] = loc
				}
			}
		}
	}
	for _, r := range state.Resources {
		addr := r.Type + "." + r.Name
		for _, inst := range r.Instances {
			add(addr, r.Module, inst.Attributes)
		}
	}
	for _, r := range state.Values.RootModule.Resources {
		add(r.Address, "", r.Values)
	}
	return out, nil
}

// Locate finds the code location for a cloud finding using the mapping.
func Locate(f model.Finding, mapping map[string]CodeLocation) (CodeLocation, bool) {
	for _, k := range []string{f.Resource.ID, f.Resource.Name} {
		if loc, ok := mapping[k]; ok {
			return loc, true
		}
	}
	if attrs := f.Resource.Attributes; attrs != nil {
		if tags, ok := attrs["tags"].(map[string]any); ok {
			if t, ok := tags["yor_trace"].(string); ok {
				if loc, ok := mapping["yor_trace:"+t]; ok {
					return loc, true
				}
			}
		}
	}
	return CodeLocation{}, false
}

// Rules exposes the native rule catalog (for docs / --list).
func Rules() []string {
	var out []string
	for _, r := range rules {
		out = append(out, r.CheckID+" -> "+r.ID+" ("+strings.Join(r.Types, ", ")+")")
	}
	sort.Strings(out)
	return out
}
