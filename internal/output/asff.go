package output

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// AWS Security Finding Format (ASFF), the shape Security Hub's BatchImportFindings accepts.
// Limits from the ASFF syntax reference and the BatchImportFindings API reference.
const (
	ASFFSchemaVersion   = "2018-10-08"
	ASFFMaxBatch        = 100     // findings per BatchImportFindings call
	ASFFMaxFindingBytes = 240_000 // per finding
	asffMaxTitle        = 256
	asffMaxDescription  = 1024
	asffMaxRecText      = 512
	asffMaxID           = 512
	asffMaxResources    = 32
	asffMaxTypes        = 50
	asffMaxProductField = 50 // key/value pairs; key ≤128, value ≤2048
	asffMaxRelatedReqs  = 32
	asffMaxResourceID   = 512
	// asffProductArnTemplate is the ARN of the default product for a custom integration
	// importing into its own account; replace it via ASFFOptions.ProductArn for a registered
	// partner product.
	asffProductArnTemplate = "arn:aws:securityhub:%s:%s:product/%s/default"
	asffPlaceholderAccount = "000000000000"
	asffDefaultRegion      = "us-east-1"
)

// ASFFOptions controls account placement. AccountID is used for findings whose own account is
// not a 12-digit AWS account id (IaC, Kubernetes, other clouds); ProductArn overrides the
// per-finding default `arn:aws:securityhub:<region>:<account>:product/<account>/default`.
type ASFFOptions struct {
	ProductArn string
	AccountID  string
	Region     string
}

var awsAccountRE = regexp.MustCompile(`^\d{12}$`)

// ASFF renders findings in AWS Security Finding Format. Status maps to Compliance.Status
// (FAIL → FAILED, PASS → PASSED, else NOT_AVAILABLE), Workflow.Status and RecordState
// (PASS → RESOLVED/ARCHIVED). nimbus identity fields travel in ProductFields under "nimbus/".
func ASFF(findings []model.Finding, opts ASFFOptions) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, asffFinding(f, opts))
	}
	return out
}

// ASFFBatches splits findings into BatchImportFindings-sized chunks.
func ASFFBatches(fs []map[string]any) [][]map[string]any {
	var out [][]map[string]any
	for len(fs) > ASFFMaxBatch {
		out = append(out, fs[:ASFFMaxBatch])
		fs = fs[ASFFMaxBatch:]
	}
	if len(fs) > 0 {
		out = append(out, fs)
	}
	return out
}

func asffFinding(f model.Finding, opts ASFFOptions) map[string]any {
	account := f.Account
	if !awsAccountRE.MatchString(account) {
		account = firstNonEmpty(opts.AccountID, asffPlaceholderAccount)
	}
	region := f.Region
	if f.Provider != model.ProviderAWS || region == "" {
		region = firstNonEmpty(opts.Region, asffDefaultRegion)
	}
	productArn := opts.ProductArn
	if productArn == "" {
		productAcct := firstNonEmpty(opts.AccountID, account)
		productArn = fmt.Sprintf(asffProductArnTemplate, region, productAcct, productAcct)
	}
	label := map[model.Severity]string{model.Critical: "CRITICAL", model.High: "HIGH", model.Medium: "MEDIUM", model.Low: "LOW", model.Info: "INFORMATIONAL"}[f.Severity]
	if label == "" {
		label = "INFORMATIONAL"
	}
	comp, workflow, record := "NOT_AVAILABLE", "NEW", "ACTIVE"
	switch f.Status {
	case model.Fail:
		comp = "FAILED"
	case model.Pass:
		comp, workflow, record = "PASSED", "RESOLVED", "ARCHIVED"
	case model.Skip:
		workflow = "SUPPRESSED"
	case model.Error:
		comp = "WARNING"
	}
	types := []string{asffType(f)}
	title := truncRunes(firstNonEmpty(f.Title, f.CanonicalID), asffMaxTitle)
	desc := truncRunes(firstNonEmpty(f.Description, f.Title, f.CanonicalID), asffMaxDescription)
	res := map[string]any{
		"Type": asffResourceType(f),
		"Id":   truncRunes(firstNonEmpty(f.Resource.ID, f.File, f.Resource.Name, f.ID), asffMaxResourceID),
	}
	if f.Provider == model.ProviderAWS {
		res["Partition"] = "aws"
		res["Region"] = region
	}
	other := map[string]string{}
	if f.Resource.Name != "" {
		other["name"] = truncRunes(f.Resource.Name, 1024)
	}
	if f.File != "" {
		loc := f.File
		if f.LineStart > 0 {
			loc = fmt.Sprintf("%s:%d-%d", f.File, f.LineStart, max(f.LineEnd, f.LineStart))
		}
		other["file"] = truncRunes(loc, 1024)
	}
	if f.Provider != model.ProviderAWS {
		other["provider"] = f.Provider
		if f.Account != "" {
			other["account"] = truncRunes(f.Account, 1024)
		}
		if f.Region != "" {
			other["region"] = f.Region
		}
	}
	if len(other) > 0 {
		res["Details"] = map[string]any{"Other": other}
	}
	pf := map[string]string{
		"ProviderName":        "nimbus",
		"ProviderVersion":     ToolVersion,
		"nimbus/fingerprint":  f.ID,
		"nimbus/canonical_id": f.CanonicalID,
		"nimbus/source":       f.Source,
		"nimbus/check_id":     f.CheckID,
		"nimbus/status":       string(f.Status),
		"nimbus/provider":     f.Provider,
	}
	if f.Account != "" {
		pf["nimbus/account"] = f.Account
	}
	if f.Region != "" {
		pf["nimbus/region"] = f.Region
	}
	if f.File != "" {
		pf["nimbus/file"] = f.File
	}
	if f.LineStart > 0 {
		pf["nimbus/line_start"] = fmt.Sprint(f.LineStart)
	}
	if f.LineEnd > 0 {
		pf["nimbus/line_end"] = fmt.Sprint(f.LineEnd)
	}
	if f.Resource.Name != "" {
		pf["nimbus/resource_name"] = f.Resource.Name
	}
	if f.Resource.Type != "" {
		pf["nimbus/resource_type"] = f.Resource.Type
	}
	if len(f.Weaknesses) > 0 {
		pf["nimbus/weaknesses"] = strings.Join(f.Weaknesses, ",")
	}
	if f.ScanID != "" {
		pf["nimbus/scan_id"] = f.ScanID
	}
	tagKeys := make([]string, 0, len(f.Tags))
	for k := range f.Tags {
		tagKeys = append(tagKeys, k)
	}
	sort.Strings(tagKeys)
	for _, k := range tagKeys {
		if len(pf) >= asffMaxProductField {
			break
		}
		pf[truncBytes("nimbus/tag/"+k, 128)] = f.Tags[k]
	}
	for k, v := range pf {
		pf[k] = truncRunes(v, 2048)
	}
	out := map[string]any{
		"SchemaVersion": ASFFSchemaVersion,
		"Id":            truncRunes(firstNonEmpty(f.ID, f.Fingerprint()), asffMaxID),
		"ProductArn":    productArn,
		"ProductName":   "cloud-posture",
		"CompanyName":   "nimbus",
		"GeneratorId":   truncRunes(f.Source+"/"+f.CheckID, asffMaxID),
		"AwsAccountId":  account,
		"Types":         types,
		"CreatedAt":     asffTime(f.FirstSeen),
		"UpdatedAt":     asffTime(f.LastSeen),
		"Severity":      map[string]any{"Label": label, "Original": string(f.Severity)},
		"Title":         title,
		"Description":   desc,
		"Resources":     []any{res},
		"Compliance":    map[string]any{"Status": comp},
		"Workflow":      map[string]any{"Status": workflow},
		"RecordState":   record,
		"ProductFields": pf,
		"FindingProviderFields": map[string]any{
			"Severity": map[string]any{"Label": label, "Original": string(f.Severity)},
			"Types":    types,
		},
	}
	if reqs := asffRelatedRequirements(f.Compliance); len(reqs) > 0 {
		out["Compliance"].(map[string]any)["RelatedRequirements"] = reqs
	}
	if f.Remediation != "" {
		out["Remediation"] = map[string]any{"Recommendation": map[string]any{"Text": truncRunes(f.Remediation, asffMaxRecText)}}
	}
	if u := f.Tags["primary_url"]; u != "" && strings.HasPrefix(u, "https://") {
		out["SourceUrl"] = truncRunes(u, 1024)
	}
	if strings.HasPrefix(strings.ToUpper(f.CheckID), "CVE-") {
		v := map[string]any{"Id": f.CheckID}
		if score, err := parseFloat(f.Tags["cvss"]); err == nil {
			v["Cvss"] = []any{map[string]any{"BaseScore": score, "Version": firstNonEmpty(f.Tags["cvss_version"], "3.1")}}
		}
		if u := f.Tags["primary_url"]; u != "" {
			v["ReferenceUrls"] = []string{u}
		}
		out["Vulnerabilities"] = []any{v}
	}
	// Last resort for the 240 KB per-finding limit: drop the bulky optional parts.
	if b, _ := json.Marshal(out); len(b) > ASFFMaxFindingBytes {
		delete(res, "Details")
		for k := range pf {
			if strings.HasPrefix(k, "nimbus/tag/") {
				delete(pf, k)
			}
		}
	}
	return out
}

func asffTime(t time.Time) string {
	if t.IsZero() {
		t = time.Unix(0, 0)
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func asffType(f model.Finding) string {
	switch {
	case f.CanonicalID == "CVE_VULNERABILITY" || strings.HasPrefix(strings.ToUpper(f.CheckID), "CVE-"):
		return "Software and Configuration Checks/Vulnerabilities/CVE"
	case f.HasWeakness("SECRET_EXPOSURE"):
		return "Sensitive Data Identifications/Passwords/" + f.CanonicalID
	case f.Provider == model.ProviderAWS:
		return "Software and Configuration Checks/AWS Security Best Practices/" + f.CanonicalID
	}
	return "Software and Configuration Checks/Industry and Regulatory Standards/" + f.CanonicalID
}

// asffResourceTypes maps Terraform-style resource types onto ASFF resource types; anything
// else is "Other" (with the original type in Details.Other).
var asffResourceTypes = map[string]string{
	"aws_s3_bucket": "AwsS3Bucket", "aws_iam_role": "AwsIamRole", "aws_iam_user": "AwsIamUser",
	"aws_iam_policy": "AwsIamPolicy", "aws_iam_access_key": "AwsIamAccessKey", "aws_instance": "AwsEc2Instance",
	"aws_security_group": "AwsEc2SecurityGroup", "aws_vpc": "AwsEc2Vpc", "aws_subnet": "AwsEc2Subnet",
	"aws_ebs_volume": "AwsEc2Volume", "aws_network_acl": "AwsEc2NetworkAcl", "aws_db_instance": "AwsRdsDbInstance",
	"aws_rds_cluster": "AwsRdsDbCluster", "aws_lambda_function": "AwsLambdaFunction", "aws_kms_key": "AwsKmsKey",
	"aws_cloudtrail": "AwsCloudTrailTrail", "aws_eks_cluster": "AwsEksCluster", "aws_ecr_repository": "AwsEcrRepository",
	"aws_secretsmanager_secret": "AwsSecretsManagerSecret", "aws_sns_topic": "AwsSnsTopic", "aws_sqs_queue": "AwsSqsQueue",
	"aws_dynamodb_table": "AwsDynamoDbTable", "aws_elb": "AwsElbLoadBalancer", "aws_lb": "AwsElbv2LoadBalancer",
	"aws_account": "AwsAccount", "aws_efs_file_system": "AwsEfsAccessPoint",
}

func asffResourceType(f model.Finding) string {
	if t, ok := asffResourceTypes[strings.ToLower(f.Resource.Type)]; ok {
		return t
	}
	if f.CanonicalID == "CVE_VULNERABILITY" && f.Provider == model.ProviderKubernetes {
		return "Container"
	}
	return "Other"
}

func asffRelatedRequirements(c map[string][]string) []string {
	var keys []string
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		for _, ctl := range c[k] {
			if len(out) == asffMaxRelatedReqs {
				return out
			}
			out = append(out, k+" "+ctl)
		}
	}
	return out
}

// ParseASFF reads ASFF findings (an array, {"Findings": [...]}, or JSON lines) back into
// findings. Identity comes from the nimbus/ ProductFields when nimbus wrote the file.
func ParseASFF(data []byte) ([]model.Finding, error) {
	trim := strings.TrimSpace(string(data))
	if strings.HasPrefix(trim, "{") {
		var env struct {
			Findings []json.RawMessage `json:"Findings"`
		}
		if json.Unmarshal([]byte(trim), &env) == nil && env.Findings != nil {
			b, _ := json.Marshal(env.Findings)
			data = b
		}
	}
	recs, err := jsonRecords(data)
	if err != nil {
		return nil, fmt.Errorf("asff: %w", err)
	}
	out := make([]model.Finding, 0, len(recs))
	for i, raw := range recs {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("asff: finding %d: %w", i, err)
		}
		if sval(m, "SchemaVersion") == "" {
			return nil, fmt.Errorf("asff: finding %d has no SchemaVersion", i)
		}
		pf := map[string]string{}
		if p, ok := m["ProductFields"].(map[string]any); ok {
			for k, v := range p {
				if s, ok := v.(string); ok {
					pf[k] = s
				}
			}
		}
		res := map[string]any{}
		if rs, ok := m["Resources"].([]any); ok && len(rs) > 0 {
			res, _ = rs[0].(map[string]any)
		}
		gen := sval(m, "GeneratorId")
		src, chk, _ := strings.Cut(gen, "/")
		f := model.Finding{
			ID:          firstNonEmpty(pf["nimbus/fingerprint"], sval(m, "Id")),
			Source:      firstNonEmpty(pf["nimbus/source"], src),
			CheckID:     firstNonEmpty(pf["nimbus/check_id"], chk),
			CanonicalID: pf["nimbus/canonical_id"],
			Title:       sval(m, "Title"),
			Description: sval(m, "Description"),
			Severity:    model.ParseSeverity(firstNonEmpty(sval(obj(m, "Severity"), "Original"), sval(obj(m, "Severity"), "Label"))),
			Provider:    firstNonEmpty(pf["nimbus/provider"], model.ProviderAWS),
			Account:     sval(m, "AwsAccountId"),
			Region:      sval(res, "Region"),
			File:        pf["nimbus/file"],
			ScanID:      pf["nimbus/scan_id"],
			Remediation: sval(obj(obj(m, "Remediation"), "Recommendation"), "Text"),
			Resource: model.Resource{
				ID:   sval(res, "Id"),
				Name: pf["nimbus/resource_name"],
				Type: pf["nimbus/resource_type"],
			},
		}
		if pf["nimbus/fingerprint"] != "" { // written by nimbus: placement fields are exact
			f.Account, f.Region = pf["nimbus/account"], pf["nimbus/region"]
		}
		if sval(obj(m, "Severity"), "Original") == "" && sval(obj(m, "Severity"), "Label") == "INFORMATIONAL" {
			f.Severity = model.Info
		}
		fmt.Sscan(pf["nimbus/line_start"], &f.LineStart)
		fmt.Sscan(pf["nimbus/line_end"], &f.LineEnd)
		if w := pf["nimbus/weaknesses"]; w != "" {
			f.Weaknesses = strings.Split(w, ",")
		}
		if st := pf["nimbus/status"]; st != "" {
			f.Status = model.Status(st)
		} else {
			switch sval(obj(m, "Compliance"), "Status") {
			case "FAILED":
				f.Status = model.Fail
			case "PASSED":
				f.Status = model.Pass
			default:
				f.Status = model.ParseStatus(sval(obj(m, "Workflow"), "Status"))
			}
		}
		for k, v := range pf {
			if tag, ok := strings.CutPrefix(k, "nimbus/tag/"); ok {
				if f.Tags == nil {
					f.Tags = map[string]string{}
				}
				f.Tags[tag] = v
			}
		}
		if t, err := time.Parse(time.RFC3339Nano, sval(m, "CreatedAt")); err == nil {
			f.FirstSeen = t.UTC()
		}
		if t, err := time.Parse(time.RFC3339Nano, sval(m, "UpdatedAt")); err == nil {
			f.LastSeen = t.UTC()
		}
		out = append(out, f)
	}
	return out, nil
}

// truncRunes cuts s to at most n characters, ending with "…" when cut.
func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// truncBytes cuts s to at most n bytes on a rune boundary.
func truncBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
