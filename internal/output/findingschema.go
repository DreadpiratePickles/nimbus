package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

//go:generate go run ./gen/findingschema ../../docs/spec/finding-v1.schema.json

// FindingSchemaID is the canonical location of the published schema.
const FindingSchemaID = "https://github.com/DreadpiratePickles/nimbus/blob/main/docs/spec/finding-v1.schema.json"

// RelationKinds are the typed relationship kinds the graph understands (edge kinds first, then
// aliases). An unknown kind is accepted on ingest but becomes an unverified attached_to hint.
var RelationKinds = []string{
	"attached_to", "runs_as", "bound_to", "member_of", "trusts", "has_policy", "grants_access_to",
	"runs_on", "allows_traffic_to", "can_assume", "exposes", "contains", "stores_data_in",
	"policy", "resource", "sts_assume_role_allows", "exposed_to_internet",
}

// fieldDocs documents every JSON field of the contract. The generator refuses a model field
// without an entry, so adding a field to internal/model fails `go generate` and the drift
// test until the spec says what it means.
var fieldDocs = map[string]string{
	"Finding.id":           "Stable fingerprint. Optional on ingest: when empty nimbus computes it as hex(sha256(source|check_id|provider|account|region|resource.id|file))[:32].",
	"Finding.source":       "Producing tool in lower case (prowler, checkov, trivy, steampipe, scoutsuite, cloud-posture, or a plugin name). Part of the fingerprint.",
	"Finding.check_id":     "The tool's native check id (s3_bucket_public_access, CKV_AWS_20, CVE-2024-3094). Part of the fingerprint.",
	"Finding.canonical_id": "nimbus catalog id (S3_PUBLIC_BUCKET). Optional on ingest: the catalog maps source+check_id onto it, else it becomes UPPER(source):check_id.",
	"Finding.title":        "One-line human title. Filled from the catalog when empty.",
	"Finding.description":  "Longer explanation or the tool's status detail.",
	"Finding.severity":     "Upper-case severity. Native ingest does not normalise other spellings (adapters do); empty means INFO, and an INFO finding takes the catalog severity.",
	"Finding.status":       "FAIL = open misconfiguration, PASS = checked and fine, SKIP = muted/manual/not applicable, ERROR = could not be evaluated (scan gaps carry tags.scan_gap and fail closed).",
	"Finding.provider":     "aws | azure | gcp | oci | kubernetes | github | m365 | okta | iac | unknown (aliases such as k8s, azurerm, terraform are normalised).",
	"Finding.account":      "Account, subscription, project, cluster or org id the resource lives in. Part of the fingerprint.",
	"Finding.region":       "Cloud region or location, when the resource is regional. Part of the fingerprint.",
	"Finding.resource":     "The affected resource (for IaC: the Terraform address).",
	"Finding.file":         "IaC file path relative to the scanned root (IaC findings only). Part of the fingerprint.",
	"Finding.line_start":   "First line of the offending block (1-based).",
	"Finding.line_end":     "Last line of the offending block.",
	"Finding.remediation":  "Fix guidance text.",
	"Finding.weaknesses":   "Weakness vocabulary consumed by the attack-path engine (PUBLIC_DATA_STORE, IMDSV1_ENABLED, ...). Filled from the catalog.",
	"Finding.compliance":   "Framework key → control ids (cis_aws: [\"2.1.4\"]). Merged with the catalog's mappings.",
	"Finding.tags":         "Free-form string labels. Reserved: account_label, scan_gap, service, cvss, primary_url.",
	"Finding.scan_id":      "Id of the scan that produced the finding (set by nimbus).",
	"Finding.first_seen":   "RFC 3339 time the finding was first observed (set by nimbus when absent).",
	"Finding.last_seen":    "RFC 3339 time of the latest observation (set by nimbus on ingest).",
	"Finding.raw":          "The tool's original record, kept verbatim for evidence. Never rendered as HTML.",
	"Resource.id":          "Provider-native resource id (ARN, Azure resource id, GCP self link, Kubernetes <namespace>/<kind>/<name>, Terraform address). Part of the fingerprint and the graph node id.",
	"Resource.type":        "Resource type in Terraform naming where one exists (aws_s3_bucket, kubernetes_pod).",
	"Resource.name":        "Display name (defaults to id).",
	"Resource.attributes":  "Collector or tool attributes used by rules and the graph (public, versioning, ...).",
	"Resource.related":     "Related resource ids. On ingest an entry is either a string (an untyped hint, becomes an attached_to edge) or a typed relation object {id, kind, attr}. nimbus writes strings here and the typed entries again under relations.",
	"Resource.relations":   "Typed relationships from this resource (the form nimbus writes). Each id is also listed in related.",
	"Relation.id":          "Target resource id.",
	"Relation.kind":        "Edge kind: attached_to, runs_as, bound_to, member_of, trusts, has_policy, grants_access_to, runs_on, allows_traffic_to, can_assume, exposes, contains, stores_data_in, or an alias (policy → has_policy, resource → grants_access_to, sts_assume_role_allows → can_assume reversed, exposed_to_internet → exposes from the internet). Unknown kinds are kept as unverified attached_to hints.",
	"Relation.attr":        "Edge attributes copied onto the graph edge; attr.because (string) becomes the hop's explanation.",
}

// FindingSchema builds the JSON Schema of the native finding contract from internal/model by
// reflection, so the published schema cannot drift from the Go types (see the drift test).
func FindingSchema() (map[string]any, error) {
	defs := map[string]any{}
	finding, err := structSchema(reflect.TypeOf(model.Finding{}), "Finding")
	if err != nil {
		return nil, err
	}
	finding["anyOf"] = []any{
		map[string]any{"required": []string{"canonical_id"}},
		map[string]any{"required": []string{"source", "check_id"}},
	}
	resource, err := structSchema(reflect.TypeOf(model.Resource{}), "Resource")
	if err != nil {
		return nil, err
	}
	relation, err := structSchema(reflect.TypeOf(model.Relation{}), "Relation")
	if err != nil {
		return nil, err
	}
	relation["required"] = []string{"id", "kind"}
	defs["finding"], defs["resource"], defs["relation"] = finding, resource, relation
	return map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"$id":                  FindingSchemaID,
		"title":                "nimbus finding contract v1",
		"description":          "Native ingest and output format of nimbus (cloud-posture), spec version " + FindingSpecVersion + ". A document is either this envelope, a JSON array of findings, or JSON lines of findings. Generated from internal/model by `go generate ./internal/output`; do not edit by hand. Human-readable spec: docs/spec/finding-v1.md.",
		"type":                 "object",
		"required":             []string{"findings"},
		"additionalProperties": false,
		"properties": map[string]any{
			"spec_version": map[string]any{"type": "string", "pattern": `^1\.\d+\.\d+$`, "description": "Contract version (semver). Readers accept any 1.x."},
			"findings":     map[string]any{"type": "array", "items": map[string]any{"$ref": "#/$defs/finding"}},
		},
		"$defs": defs,
	}, nil
}

// FindingSchemaJSON is the canonical serialisation written to docs/spec.
func FindingSchemaJSON() ([]byte, error) {
	s, err := FindingSchema()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var (
	timeType = reflect.TypeOf(time.Time{})
	rawType  = reflect.TypeOf(json.RawMessage{})
)

func structSchema(t reflect.Type, name string) (map[string]any, error) {
	props := map[string]any{}
	var missing []string
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		tag := sf.Tag.Get("json")
		if tag == "-" {
			continue
		}
		jname, _, _ := strings.Cut(tag, ",")
		if jname == "" {
			jname = sf.Name
		}
		doc, ok := fieldDocs[name+"."+jname]
		if !ok {
			missing = append(missing, name+"."+jname)
			continue
		}
		ps, err := typeSchema(sf.Type, name+"."+jname)
		if err != nil {
			return nil, err
		}
		ps["description"] = doc
		props[jname] = ps
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("finding schema: no documentation for %s (add it to fieldDocs in internal/output/findingschema.go and to docs/spec/finding-v1.md)", strings.Join(missing, ", "))
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": props}, nil
}

func typeSchema(t reflect.Type, path string) (map[string]any, error) {
	switch path {
	case "Finding.severity":
		return map[string]any{"type": "string", "enum": []string{string(model.Critical), string(model.High), string(model.Medium), string(model.Low), string(model.Info)}}, nil
	case "Finding.status":
		return map[string]any{"type": "string", "enum": []string{string(model.Fail), string(model.Pass), string(model.Skip), string(model.Error)}}, nil
	case "Finding.provider":
		return map[string]any{"type": "string", "minLength": 1}, nil
	case "Resource.related":
		return map[string]any{"type": "array", "items": map[string]any{"anyOf": []any{
			map[string]any{"type": "string", "minLength": 1}, map[string]any{"$ref": "#/$defs/relation"},
		}}}, nil
	case "Relation.id", "Relation.kind":
		return map[string]any{"type": "string", "minLength": 1}, nil
	}
	switch {
	case t == timeType:
		return map[string]any{"type": "string", "format": "date-time"}, nil
	case t == rawType:
		return map[string]any{}, nil
	case t == reflect.TypeOf(model.Resource{}):
		return map[string]any{"$ref": "#/$defs/resource"}, nil
	case t == reflect.TypeOf(model.Relation{}):
		return map[string]any{"$ref": "#/$defs/relation"}, nil
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}, nil
	case reflect.Int, reflect.Int64, reflect.Int32:
		return map[string]any{"type": "integer", "minimum": 0}, nil
	case reflect.Float64, reflect.Float32:
		return map[string]any{"type": "number"}, nil
	case reflect.Bool:
		return map[string]any{"type": "boolean"}, nil
	case reflect.Slice:
		items, err := typeSchema(t.Elem(), path+"[]")
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "array", "items": items}, nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return nil, fmt.Errorf("finding schema: %s: map key must be string", path)
		}
		if t.Elem().Kind() == reflect.Interface {
			return map[string]any{"type": "object"}, nil
		}
		v, err := typeSchema(t.Elem(), path+"{}")
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "object", "additionalProperties": v}, nil
	case reflect.Interface:
		return map[string]any{}, nil
	}
	return nil, fmt.Errorf("finding schema: %s: unsupported Go type %s", path, t)
}
