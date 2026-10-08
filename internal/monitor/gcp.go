package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/logging"
	"cloud.google.com/go/logging/logadmin"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	// Registers the AuditLog proto so audit payloads decode.
	_ "google.golang.org/genproto/googleapis/cloud/audit"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// GCPMethods are the audit-log method names the GCP source watches (substring match,
// so "SetIamPolicy" covers every service's SetIamPolicy).
var GCPMethods = []string{"storage.setIamPermissions", "v1.compute.firewalls.insert", "v1.compute.firewalls.patch", "SetIamPolicy", "cloudsql.instances.update"}

// AuditLogAPI lists log entries matching an advanced logs filter.
type AuditLogAPI interface {
	Entries(ctx context.Context, filter string) ([]*logging.Entry, error)
}

// AuditLogSource polls Cloud Audit Logs of one project.
type AuditLogSource struct {
	API     AuditLogAPI
	Project string
}

func (s *AuditLogSource) Name() string { return "auditlog:" + s.Project }

// AuditFilter builds the Logging filter for the window.
func AuditFilter(since time.Time) string {
	q := make([]string, len(GCPMethods))
	for i, m := range GCPMethods {
		q[i] = fmt.Sprintf("%q", m)
	}
	return fmt.Sprintf(`logName:"cloudaudit.googleapis.com" AND timestamp>=%q AND protoPayload.methodName:(%s)`, since.UTC().Format(time.RFC3339Nano), strings.Join(q, " OR "))
}

func (s *AuditLogSource) Poll(ctx context.Context, since time.Time) ([]Event, error) {
	entries, err := s.API.Entries(ctx, AuditFilter(since))
	var out []Event
	for _, en := range entries {
		if e, ok := MapAuditEntry(en, s.Project); ok {
			out = append(out, e)
		}
	}
	return out, err
}

func (s *AuditLogSource) Close() error {
	if c, ok := s.API.(closer); ok {
		return c.Close()
	}
	return nil
}

type logadminAPI struct{ c *logadmin.Client }

func (l logadminAPI) Entries(ctx context.Context, filter string) ([]*logging.Entry, error) {
	it := l.c.Entries(ctx, logadmin.Filter(filter))
	var out []*logging.Entry
	for {
		e, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, e)
	}
}

func (l logadminAPI) Close() error { return l.c.Close() }

func newAuditLogSource(ctx context.Context, spec core.AccountSpec) (Source, error) {
	if spec.ProjectID == "" {
		return nil, fmt.Errorf("gcp monitor requires project id")
	}
	c, err := logadmin.NewClient(ctx, "projects/"+spec.ProjectID, core.GCPOptions(spec)...)
	if err != nil {
		return nil, err
	}
	return &AuditLogSource{API: logadminAPI{c}, Project: spec.ProjectID}, nil
}

// payloadMap converts an entry payload (AuditLog proto, Struct or map) into JSON-shaped data.
func payloadMap(p any) map[string]any {
	switch x := p.(type) {
	case map[string]any:
		return x
	case *structpb.Struct:
		return x.AsMap()
	case proto.Message:
		b, err := protojson.Marshal(x)
		if err != nil {
			return nil
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return nil
		}
		return m
	case string:
		if m, ok := jsonish(x).(map[string]any); ok {
			return m
		}
	}
	return nil
}

// MapAuditEntry maps one audit log entry onto an Event.
func MapAuditEntry(en *logging.Entry, project string) (Event, bool) {
	if en == nil {
		return Event{}, false
	}
	return MapAuditLog(payloadMap(en.Payload), en.Timestamp, en.InsertID, project)
}

// MapAuditLog maps an AuditLog payload (protoPayload in JSON form) onto an Event.
func MapAuditLog(p map[string]any, ts time.Time, insertID, project string) (Event, bool) {
	if p == nil {
		return Event{}, false
	}
	method := gets(p, "methodName")
	matched := ""
	for _, m := range GCPMethods {
		if strings.Contains(method, m) {
			matched = m
			break
		}
	}
	if matched == "" {
		return Event{}, false
	}
	if code, ok := num(get(p, "status", "code")); ok && code != 0 {
		return Event{}, false
	}
	resName := gets(p, "resourceName")
	raw := map[string]any{"event_id": insertID, "payload": p}
	e := Event{
		Time: ts, Provider: model.ProviderGCP, Account: project, Source: "cloudaudit:" + gets(p, "serviceName"),
		EventName: method, Actor: gets(p, "authenticationInfo", "principalEmail"), Raw: raw,
	}
	if e.Source == "cloudaudit:" {
		e.Source = "cloudaudit"
	}
	req := get(p, "request")
	set := func(canon string, sev model.Severity, id, typ, title string) {
		e.CanonicalID, e.Severity, e.ResourceID, e.ResourceType, e.Title = canon, sev, id, typ, title
	}
	switch matched {
	case "storage.setIamPermissions":
		id := "//storage.googleapis.com/" + resName
		if gcpAddsMember(p, "allUsers", "allAuthenticatedUsers") {
			set("GCP_BUCKET_PUBLIC", model.High, id, "gcp_storage_bucket", "Bucket IAM grants allUsers / allAuthenticatedUsers")
		} else {
			set("", model.Low, id, "gcp_storage_bucket", "Bucket IAM policy changed")
		}
	case "v1.compute.firewalls.insert", "v1.compute.firewalls.patch":
		id := "https://www.googleapis.com/compute/v1/" + resName
		switch gcpFirewallExposure(req) {
		case "all":
			set("GCP_FIREWALL_OPEN_SSH", model.Critical, id, "gcp_compute_firewall", "Firewall allows all ports from the internet")
		case "ssh":
			set("GCP_FIREWALL_OPEN_SSH", model.High, id, "gcp_compute_firewall", "Firewall allows SSH from the internet")
		case "rdp":
			set("GCP_FIREWALL_OPEN_RDP", model.High, id, "gcp_compute_firewall", "Firewall allows RDP from the internet")
		case "other":
			set("", model.Medium, id, "gcp_compute_firewall", "Firewall opens a port to the internet")
		default:
			set("", model.Low, id, "gcp_compute_firewall", "Firewall rule changed")
		}
	case "SetIamPolicy":
		if gcpGrantsRole(p, "roles/owner", "roles/editor") {
			set("GCP_IAM_PRIMITIVE_ROLE", model.High, resName, "gcp_iam_binding", "Primitive Owner/Editor role granted")
		} else {
			set("", model.Low, resName, "gcp_iam_binding", "IAM policy changed")
		}
	case "cloudsql.instances.update":
		id := "//cloudsql.googleapis.com/" + resName
		open := false
		walk(req, func(k string, v any) {
			if strings.EqualFold(k, "authorizedNetworks") {
				for _, n := range list(v) {
					if openSource(gets(n, "value")) {
						open = true
					}
				}
			}
		})
		if open {
			set("GCP_SQL_PUBLIC", model.Critical, id, "gcp_sql_database_instance", "Cloud SQL authorized networks opened to 0.0.0.0/0")
		} else {
			set("", model.Low, id, "gcp_sql_database_instance", "Cloud SQL instance updated")
		}
	}
	return e, true
}

// gcpAddsMember checks bindingDeltas (ADD) in serviceData/metadata, or request policy bindings.
func gcpAddsMember(p map[string]any, members ...string) bool {
	hit := func(m string) bool {
		for _, x := range members {
			if m == x || strings.HasSuffix(m, ":"+x) {
				return true
			}
		}
		return false
	}
	found := false
	walk(p, func(k string, v any) {
		switch k {
		case "bindingDeltas":
			for _, d := range list(v) {
				if strings.EqualFold(gets(d, "action"), "ADD") && hit(gets(d, "member")) {
					found = true
				}
			}
		case "bindings":
			for _, b := range list(v) {
				for _, m := range strs(get(b, "members")) {
					if hit(m) {
						found = true
					}
				}
			}
		}
	})
	return found
}

func gcpGrantsRole(p map[string]any, roles ...string) bool {
	isRole := func(r string) bool {
		for _, x := range roles {
			if r == x {
				return true
			}
		}
		return false
	}
	found := false
	walk(p, func(k string, v any) {
		switch k {
		case "bindingDeltas":
			for _, d := range list(v) {
				if strings.EqualFold(gets(d, "action"), "ADD") && isRole(gets(d, "role")) {
					found = true
				}
			}
		case "bindings":
			for _, b := range list(v) {
				if isRole(gets(b, "role")) && len(strs(get(b, "members"))) > 0 {
					found = true
				}
			}
		}
	})
	return found
}

// gcpFirewallExposure classifies a firewall insert/patch request.
func gcpFirewallExposure(req any) string {
	if d := gets(req, "direction"); d != "" && !strings.EqualFold(d, "INGRESS") {
		return ""
	}
	open := false
	for _, r := range strs(get(req, "sourceRanges")) {
		if openSource(r) {
			open = true
		}
	}
	if !open {
		return ""
	}
	rules := list(get(req, "alloweds"))
	rules = append(rules, list(get(req, "allowed"))...)
	cls := ""
	for _, a := range rules {
		proto := strings.ToLower(gets(a, "IPProtocol"))
		if proto == "" {
			proto = strings.ToLower(gets(a, "ipProtocol"))
		}
		ports := strs(get(a, "ports"))
		if proto == "all" || ((proto == "tcp" || proto == "6") && len(ports) == 0) {
			return "all"
		}
		if proto != "tcp" && proto != "6" {
			if cls == "" {
				cls = "other"
			}
			continue
		}
		for _, pr := range ports {
			switch {
			case allPorts(pr):
				return "all"
			case portSpanCovers(pr, 22):
				cls = "ssh"
			case portSpanCovers(pr, 3389) && cls != "ssh":
				cls = "rdp"
			case cls == "":
				cls = "other"
			}
		}
	}
	return cls
}
