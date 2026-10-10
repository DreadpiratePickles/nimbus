package iac

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// ParseTerraform parses every .tf file under root (skipping .terraform and .git).
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
		if info, err := d.Info(); err == nil && info.Size() > int64(currentLimits().MaxFileBytes) {
			// Do not even read it: checkParseLimits would reject it after a large allocation.
			diags = append(diags, limitDiag(&LimitError{File: p, Reason: fmt.Sprintf("file size %d bytes exceeds the %d-byte limit (%s)", info.Size(), currentLimits().MaxFileBytes, EnvMaxFileBytes)}, p)...)
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: unreadableSummary, Detail: err.Error(), Subject: &hcl.Range{Filename: p, Start: hcl.Pos{Line: 1, Column: 1}, End: hcl.Pos{Line: 1, Column: 1}}})
			return nil
		}
		bs, dg := parseHCL(src, p)
		diags = append(diags, dg...)
		blocks = append(blocks, bs...)
		return nil
	})
	return blocks, diags
}

// parseHCL extracts the resource blocks of one file. Attrs holds only values that are statically
// known (no references, function calls or unknowns); rules use the attr* helpers, which tell
// "absent" apart from "present but not statically known".
func parseHCL(src []byte, path string) ([]Block, hcl.Diagnostics) {
	f, dg := parseConfig(src, path)
	if f == nil {
		return nil, dg
	}
	body, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		return nil, dg
	}
	var blocks []Block
	for _, b := range body.Blocks {
		if b.Type != "resource" || len(b.Labels) != 2 || b.Body == nil {
			continue
		}
		blk := Block{File: path, Type: b.Labels[0], Name: b.Labels[1], Address: b.Labels[0] + "." + b.Labels[1], Range: b.Range(), Attrs: map[string]cty.Value{}, Body: b.Body}
		for name := range b.Body.Attributes {
			if v, st := attrValue(b.Body, name); st == stKnown {
				blk.Attrs[name] = v
			}
		}
		blocks = append(blocks, blk)
	}
	return blocks, dg
}

// ---------------------------------------------------------------- static value helpers

type attrState int

const (
	stAbsent  attrState = iota // not set, or set to null (Terraform treats both as unset)
	stKnown                    // statically known, non-null
	stUnknown                  // depends on var./local./resources/functions, or failed to evaluate
)

// unknownMarker prefixes the detail of a rule that could not decide; the finding becomes SKIP.
const unknownMarker = "not statically known: "

func unknown(what string) (bool, string) { return false, unknownMarker + what }

// safeValue evaluates an expression without a variable context and never panics.
func safeValue(e hclsyntax.Expression) (v cty.Value, ok bool) {
	defer func() {
		if recover() != nil {
			v, ok = cty.NilVal, false
		}
	}()
	if e == nil {
		return cty.NilVal, false
	}
	v, d := e.Value(nil)
	if d.HasErrors() || v == cty.NilVal || !v.IsWhollyKnown() {
		return cty.NilVal, false
	}
	return v, true
}

func attrValue(body *hclsyntax.Body, name string) (cty.Value, attrState) {
	if body == nil {
		return cty.NilVal, stAbsent
	}
	a, ok := body.Attributes[name]
	if !ok {
		return cty.NilVal, stAbsent
	}
	v, ok := safeValue(a.Expr)
	if !ok {
		return cty.NilVal, stUnknown
	}
	if v.IsNull() {
		return cty.NilVal, stAbsent
	}
	return v, stKnown
}

func attrBoolBody(body *hclsyntax.Body, name string) (bool, attrState) {
	v, st := attrValue(body, name)
	if st != stKnown {
		return false, st
	}
	c, err := convert.Convert(v, cty.Bool)
	if err != nil || c.IsNull() || !c.IsKnown() {
		return false, stUnknown
	}
	return c.True(), stKnown
}

func attrStringBody(body *hclsyntax.Body, name string) (string, attrState) {
	v, st := attrValue(body, name)
	if st != stKnown {
		return "", st
	}
	c, err := convert.Convert(v, cty.String)
	if err != nil || c.IsNull() || !c.IsKnown() {
		return "", stUnknown
	}
	return c.AsString(), stKnown
}

func attrNumberBody(body *hclsyntax.Body, name string) (int64, attrState) {
	v, st := attrValue(body, name)
	if st != stKnown {
		return 0, st
	}
	c, err := convert.Convert(v, cty.Number)
	if err != nil || c.IsNull() || !c.IsKnown() {
		return 0, stUnknown
	}
	n, _ := c.AsBigFloat().Int64()
	return n, stKnown
}

// attrStringsBody returns the string elements of a list/set/tuple attribute (null elements are
// ignored; a single string is treated as a one-element list).
func attrStringsBody(body *hclsyntax.Body, name string) ([]string, attrState) {
	v, st := attrValue(body, name)
	if st != stKnown {
		return nil, st
	}
	return stringElems(v), stKnown
}

func stringElems(v cty.Value) []string {
	if v == cty.NilVal || v.IsNull() || !v.IsWhollyKnown() {
		return nil
	}
	if v.Type() == cty.String {
		return []string{v.AsString()}
	}
	if !v.CanIterateElements() || !(v.Type().IsListType() || v.Type().IsSetType() || v.Type().IsTupleType()) {
		return nil
	}
	var out []string
	for it := v.ElementIterator(); it.Next(); {
		_, ev := it.Element()
		if ev.IsNull() || !ev.IsKnown() {
			continue
		}
		if c, err := convert.Convert(ev, cty.String); err == nil && !c.IsNull() && c.IsKnown() {
			out = append(out, c.AsString())
		}
	}
	return out
}

func nestedBlocks(b Block, typ string) []*hclsyntax.Block {
	if b.Body == nil {
		return nil
	}
	var out []*hclsyntax.Block
	for _, nb := range b.Body.Blocks {
		if nb.Type == typ && nb.Body != nil {
			out = append(out, nb)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- rules

type rule struct {
	ID       string // canonical ID
	CheckID  string
	Title    string
	Severity model.Severity
	Types    []string
	// Eval returns fail=true with a detail, or fail=false with an optional detail. A detail that
	// starts with unknownMarker means the rule could not decide statically (finding becomes SKIP).
	Eval func(b Block, all []Block) (fail bool, detail string)
}

// requireTrue: fail when absent (provider default false) or false; unknown → skip.
func requireTrue(body *hclsyntax.Body, name string) (bool, string) {
	v, st := attrBoolBody(body, name)
	switch {
	case st == stUnknown:
		return unknown(name)
	case st == stAbsent || !v:
		return true, name + " is not true"
	}
	return false, ""
}

// forbidTrue: fail only when explicitly true; unknown → skip.
func forbidTrue(body *hclsyntax.Body, name string) (bool, string) {
	v, st := attrBoolBody(body, name)
	switch {
	case st == stUnknown:
		return unknown(name)
	case st == stKnown && v:
		return true, name + " = true"
	}
	return false, ""
}

var rules = []rule{
	{ID: "S3_PUBLIC_BUCKET", CheckID: "NIMBUS_TF_S3_PUBLIC", Title: "S3 bucket ACL grants public access", Severity: model.High, Types: []string{"aws_s3_bucket", "aws_s3_bucket_acl"}, Eval: func(b Block, _ []Block) (bool, string) {
		acl, st := attrStringBody(b.Body, "acl")
		if st == stUnknown {
			return unknown("acl")
		}
		if acl == "public-read" || acl == "public-read-write" || acl == "authenticated-read" {
			return true, "acl = " + acl
		}
		return false, ""
	}},
	{ID: "S3_PUBLIC_BUCKET", CheckID: "NIMBUS_TF_S3_PAB", Title: "S3 public access block does not block all public access", Severity: model.High, Types: []string{"aws_s3_bucket_public_access_block"}, Eval: func(b Block, _ []Block) (bool, string) {
		var unk []string
		for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
			fail, d := requireTrue(b.Body, k)
			if fail {
				return true, d
			}
			if d != "" {
				unk = append(unk, k)
			}
		}
		if len(unk) > 0 {
			return unknown(strings.Join(unk, ", "))
		}
		return false, ""
	}},
	{ID: "EC2_SG_OPEN_SSH", CheckID: "NIMBUS_TF_SG_OPEN", Title: "Security group ingress open to the world", Severity: model.High, Types: []string{"aws_security_group"}, Eval: func(b Block, _ []Block) (bool, string) {
		var unk []string
		for _, ing := range nestedBlocks(b, "ingress") {
			cidrs, st := attrStringsBody(ing.Body, "cidr_blocks")
			if st == stUnknown {
				unk = append(unk, "ingress.cidr_blocks")
			}
			if contains(cidrs, "0.0.0.0/0") {
				return true, "ingress " + portRange(ing.Body) + " from 0.0.0.0/0"
			}
			v6, st := attrStringsBody(ing.Body, "ipv6_cidr_blocks")
			if st == stUnknown {
				unk = append(unk, "ingress.ipv6_cidr_blocks")
			}
			if contains(v6, "::/0") {
				return true, "ingress " + portRange(ing.Body) + " from ::/0"
			}
		}
		// D6: dynamic "ingress" blocks with a statically known for_each are expanded.
		insts, dynUnk := expandDynamic(b.Body, "ingress")
		unk = append(unk, dynUnk...)
		for _, in := range insts {
			for _, attr := range []struct{ name, world string }{{"cidr_blocks", "0.0.0.0/0"}, {"ipv6_cidr_blocks", "::/0"}} {
				cidrs, st := attrStringsIn(in.content, attr.name, in.ectx)
				if st == stUnknown {
					unk = append(unk, "dynamic ingress content."+attr.name)
				}
				if contains(cidrs, attr.world) {
					return true, "dynamic ingress " + portRangeIn(in.content, in.ectx) + " from " + attr.world
				}
			}
		}
		if len(unk) > 0 {
			return unknown(strings.Join(unk, ", "))
		}
		return false, ""
	}},
	{ID: "EC2_SG_OPEN_SSH", CheckID: "NIMBUS_TF_SG_RULE_OPEN", Title: "Security group rule open to the world", Severity: model.High, Types: []string{"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}, Eval: func(b Block, _ []Block) (bool, string) {
		t, st := attrStringBody(b.Body, "type")
		if st == stKnown && t != "ingress" {
			return false, ""
		}
		c, cst := attrStringBody(b.Body, "cidr_ipv4")
		if cst == stKnown && c == "0.0.0.0/0" {
			return true, "cidr_ipv4 = 0.0.0.0/0"
		}
		cidrs, lst := attrStringsBody(b.Body, "cidr_blocks")
		if contains(cidrs, "0.0.0.0/0") {
			return true, "cidr_blocks contains 0.0.0.0/0"
		}
		if st == stUnknown || cst == stUnknown || lst == stUnknown {
			return unknown("type/cidr_ipv4/cidr_blocks")
		}
		return false, ""
	}},
	{ID: "EC2_IMDSV1", CheckID: "NIMBUS_TF_IMDSV1", Title: "EC2 instance allows IMDSv1", Severity: model.High, Types: []string{"aws_instance", "aws_launch_template"}, Eval: func(b Block, _ []Block) (bool, string) {
		mo := nestedBlocks(b, "metadata_options")
		if len(mo) == 0 {
			return true, "metadata_options block missing (http_tokens defaults to optional)"
		}
		t, st := attrStringBody(mo[0].Body, "http_tokens")
		if st == stUnknown {
			return unknown("metadata_options.http_tokens")
		}
		if t != "required" {
			return true, "http_tokens is not \"required\""
		}
		return false, ""
	}},
	{ID: "EC2_PUBLIC_IP", CheckID: "NIMBUS_TF_PUBLIC_IP", Title: "EC2 instance associates a public IP", Severity: model.Medium, Types: []string{"aws_instance"}, Eval: func(b Block, _ []Block) (bool, string) {
		return forbidTrue(b.Body, "associate_public_ip_address")
	}},
	{ID: "EBS_UNENCRYPTED", CheckID: "NIMBUS_TF_EBS_ENC", Title: "EBS volume not encrypted", Severity: model.Medium, Types: []string{"aws_ebs_volume"}, Eval: func(b Block, _ []Block) (bool, string) {
		return requireTrue(b.Body, "encrypted")
	}},
	{ID: "RDS_PUBLIC", CheckID: "NIMBUS_TF_RDS_PUBLIC", Title: "RDS instance publicly accessible", Severity: model.Critical, Types: []string{"aws_db_instance", "aws_rds_cluster_instance"}, Eval: func(b Block, _ []Block) (bool, string) {
		return forbidTrue(b.Body, "publicly_accessible")
	}},
	{ID: "RDS_UNENCRYPTED", CheckID: "NIMBUS_TF_RDS_ENC", Title: "RDS storage not encrypted", Severity: model.High, Types: []string{"aws_db_instance"}, Eval: func(b Block, _ []Block) (bool, string) {
		return requireTrue(b.Body, "storage_encrypted")
	}},
	{ID: "IAM_ADMIN_POLICY", CheckID: "NIMBUS_TF_IAM_STAR", Title: "IAM policy allows *:*", Severity: model.High, Types: []string{"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}, Eval: func(b Block, _ []Block) (bool, string) {
		p, st := attrStringBody(b.Body, "policy")
		if st == stUnknown {
			return unknown("policy (jsonencode/data source/reference)")
		}
		if st != stKnown {
			return false, ""
		}
		var doc struct {
			Statement json.RawMessage `json:"Statement"`
		}
		if json.Unmarshal([]byte(p), &doc) != nil {
			return false, ""
		}
		var stmts []map[string]any
		if json.Unmarshal(doc.Statement, &stmts) != nil {
			var one map[string]any
			if json.Unmarshal(doc.Statement, &one) == nil {
				stmts = []map[string]any{one}
			}
		}
		for _, s := range stmts {
			if s["Effect"] == "Allow" && hasStar(s["Action"]) && hasStar(s["Resource"]) {
				return true, "statement allows Action \"*\" on Resource \"*\""
			}
		}
		return false, ""
	}},
	{ID: "CLOUDTRAIL_NO_LOG_VALIDATION", CheckID: "NIMBUS_TF_TRAIL_VALIDATION", Title: "CloudTrail log validation disabled", Severity: model.Low, Types: []string{"aws_cloudtrail"}, Eval: func(b Block, _ []Block) (bool, string) {
		return requireTrue(b.Body, "enable_log_file_validation")
	}},
	{ID: "CLOUDTRAIL_DISABLED", CheckID: "NIMBUS_TF_TRAIL_REGION", Title: "CloudTrail is not multi-region", Severity: model.High, Types: []string{"aws_cloudtrail"}, Eval: func(b Block, _ []Block) (bool, string) {
		return requireTrue(b.Body, "is_multi_region_trail")
	}},
	{ID: "KMS_ROTATION_DISABLED", CheckID: "NIMBUS_TF_KMS_ROTATION", Title: "KMS key rotation disabled", Severity: model.Low, Types: []string{"aws_kms_key"}, Eval: func(b Block, _ []Block) (bool, string) {
		return requireTrue(b.Body, "enable_key_rotation")
	}},
	{ID: "EKS_PUBLIC_ENDPOINT", CheckID: "NIMBUS_TF_EKS_PUBLIC", Title: "EKS endpoint public", Severity: model.High, Types: []string{"aws_eks_cluster"}, Eval: func(b Block, _ []Block) (bool, string) {
		for _, vc := range nestedBlocks(b, "vpc_config") {
			v, st := attrBoolBody(vc.Body, "endpoint_public_access")
			switch {
			case st == stUnknown:
				return unknown("vpc_config.endpoint_public_access")
			case st == stAbsent:
				return true, "endpoint_public_access defaults to true"
			case v:
				return true, "endpoint_public_access = true"
			}
		}
		return false, ""
	}},
	{ID: "AZ_STORAGE_PUBLIC_BLOB", CheckID: "NIMBUS_TF_AZ_BLOB_PUBLIC", Title: "Storage account allows public blob access", Severity: model.High, Types: []string{"azurerm_storage_account"}, Eval: func(b Block, _ []Block) (bool, string) {
		v, st := attrBoolBody(b.Body, "allow_nested_items_to_be_public")
		switch {
		case st == stUnknown:
			return unknown("allow_nested_items_to_be_public")
		case st == stAbsent || v:
			return true, "allow_nested_items_to_be_public is not false"
		}
		return false, ""
	}},
	{ID: "AZ_STORAGE_HTTP_ALLOWED", CheckID: "NIMBUS_TF_AZ_HTTPS", Title: "Storage account does not enforce HTTPS", Severity: model.Medium, Types: []string{"azurerm_storage_account"}, Eval: func(b Block, _ []Block) (bool, string) {
		for _, k := range []string{"https_traffic_only_enabled", "enable_https_traffic_only"} {
			v, st := attrBoolBody(b.Body, k)
			switch {
			case st == stUnknown:
				return unknown(k)
			case st == stKnown:
				if !v {
					return true, k + " = false"
				}
				return false, ""
			}
		}
		return false, ""
	}},
	{ID: "AZ_NSG_OPEN_SSH", CheckID: "NIMBUS_TF_AZ_NSG_OPEN", Title: "NSG rule allows inbound from Internet", Severity: model.High, Types: []string{"azurerm_network_security_rule"}, Eval: func(b Block, _ []Block) (bool, string) {
		dir, dst := attrStringBody(b.Body, "direction")
		acc, ast := attrStringBody(b.Body, "access")
		src, sst := attrStringBody(b.Body, "source_address_prefix")
		if dst == stKnown && !strings.EqualFold(dir, "Inbound") || ast == stKnown && !strings.EqualFold(acc, "Allow") {
			return false, ""
		}
		if dst == stUnknown || ast == stUnknown || sst == stUnknown {
			return unknown("direction/access/source_address_prefix")
		}
		if strings.EqualFold(dir, "Inbound") && strings.EqualFold(acc, "Allow") && isAzureWorld(src) {
			return true, "source_address_prefix = " + src
		}
		return false, ""
	}},
	{ID: "GCP_BUCKET_PUBLIC", CheckID: "NIMBUS_TF_GCS_PUBLIC", Title: "GCS bucket IAM grants allUsers", Severity: model.High, Types: []string{"google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"}, Eval: func(b Block, _ []Block) (bool, string) {
		m, mst := attrStringBody(b.Body, "member")
		if mst == stKnown && isGCPPublic(m) {
			return true, "member = " + m
		}
		ms, lst := attrStringsBody(b.Body, "members")
		for _, x := range ms {
			if isGCPPublic(x) {
				return true, "members contains " + x
			}
		}
		if mst == stUnknown || lst == stUnknown {
			return unknown("member/members")
		}
		return false, ""
	}},
	{ID: "GCP_FIREWALL_OPEN_SSH", CheckID: "NIMBUS_TF_GCP_FW_OPEN", Title: "GCP firewall allows ingress from 0.0.0.0/0", Severity: model.High, Types: []string{"google_compute_firewall"}, Eval: func(b Block, _ []Block) (bool, string) {
		rs, st := attrStringsBody(b.Body, "source_ranges")
		if contains(rs, "0.0.0.0/0") && len(nestedBlocks(b, "allow")) > 0 {
			return true, "source_ranges contains 0.0.0.0/0"
		}
		if st == stUnknown {
			return unknown("source_ranges")
		}
		return false, ""
	}},
	{ID: "GCP_SQL_PUBLIC", CheckID: "NIMBUS_TF_GCP_SQL_PUBLIC", Title: "Cloud SQL has a public IPv4 address", Severity: model.Critical, Types: []string{"google_sql_database_instance"}, Eval: func(b Block, _ []Block) (bool, string) {
		for _, s := range nestedBlocks(b, "settings") {
			for _, ip := range s.Body.Blocks {
				if ip.Type != "ip_configuration" || ip.Body == nil {
					continue
				}
				if fail, d := forbidTrue(ip.Body, "ipv4_enabled"); fail || d != "" {
					if fail {
						return true, "ipv4_enabled = true"
					}
					return unknown("settings.ip_configuration.ipv4_enabled")
				}
			}
		}
		return false, ""
	}},
}

func portRange(body *hclsyntax.Body) string {
	p := func(name string) string {
		n, st := attrNumberBody(body, name)
		if st != stKnown {
			return "?"
		}
		return fmt.Sprint(n)
	}
	return p("from_port") + "-" + p("to_port")
}

func isAzureWorld(src string) bool {
	return src == "*" || src == "0.0.0.0/0" || strings.EqualFold(src, "Internet") || strings.EqualFold(src, "Any")
}

func isGCPPublic(m string) bool { return m == "allUsers" || m == "allAuthenticatedUsers" }

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

// evalRule runs one rule behind a panic guard: a rule bug on odd input is reported as an ERROR
// finding for that block instead of crashing a CI run (FuzzScanHCL asserts this never trips on
// HCL that parses cleanly).
func evalRule(r rule, b Block, all []Block) (fail bool, detail string, err error) {
	defer func() {
		if p := recover(); p != nil {
			fail, detail, err = false, "", fmt.Errorf("rule %s panicked on %s: %v", r.CheckID, b.Address, p)
		}
	}()
	fail, detail = r.Eval(b, all)
	return fail, detail, nil
}

// ScanTerraform runs the native rules over a directory and returns findings. When a file could not
// be scanned it still returns every finding (including the file's IAC_PARSE_LIMIT ERROR finding)
// together with an *UnscannedError naming the files; see ScanTerraformResult.
func ScanTerraform(root string, now time.Time) ([]model.Finding, error) {
	res, err := ScanTerraformResult(root, now)
	return res.Findings, err
}

// ScanHCL runs the native rules over one in-memory Terraform file. Findings are returned for
// every block that parsed; the error reports syntax problems (findings may still be partial).
func ScanHCL(src []byte, filename string, now time.Time) ([]model.Finding, error) {
	blocks, diags := parseHCL(src, filename)
	gaps, _ := gapFindings(diags, "", "", now)
	fs := append(evaluate(blocks, "", "", now), gaps...)
	if diags.HasErrors() {
		return fs, fmt.Errorf("parse: %s", diags.Error())
	}
	return fs, nil
}

// evaluate runs the rules over blocks. rootID (see rootIdentity) is folded into every finding id,
// so identical files under different IaC roots keep distinct ids.
func evaluate(blocks []Block, root, rootID string, now time.Time) []model.Finding {
	var out []model.Finding
	for _, b := range blocks {
		for _, r := range rules {
			if !containsStr(r.Types, b.Type) {
				continue
			}
			fail, detail, err := evalRule(r, b, blocks)
			status := model.Pass
			switch {
			case err != nil:
				status, detail = model.Error, err.Error()
			case fail:
				status = model.Fail
			case strings.HasPrefix(detail, unknownMarker):
				status = model.Skip
			}
			rel := b.File
			if root != "" {
				if r, err := filepath.Rel(root, b.File); err == nil && r != "" && !strings.HasPrefix(r, "..") {
					rel = r
				}
			}
			f := model.Finding{
				Source: "nimbus-iac", CheckID: r.CheckID, CanonicalID: r.ID, Title: r.Title, Description: detail, Severity: r.Severity, Status: status,
				Provider: providerOfType(b.Type), Account: "iac", File: filepath.ToSlash(rel), LineStart: b.Range.Start.Line, LineEnd: b.Range.End.Line,
				Resource: model.Resource{ID: b.Address, Type: b.Type, Name: b.Name, Attributes: map[string]any{"file": rel, "address": b.Address}},
				Tags:     map[string]string{"framework": "terraform"},
			}
			f.ID = rootedID(f, rootID)
			f.Finalize(now)
			if status == model.Skip || status == model.Error {
				// Finalize may default the status; keep the scanner's verdict.
				f.Status = status
			}
			out = append(out, f)
		}
	}
	return out
}
