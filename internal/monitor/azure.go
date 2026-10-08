package monitor

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// AzureOperations are the Activity Log operations the Azure source watches.
var AzureOperations = []string{
	"Microsoft.Network/networkSecurityGroups/securityRules/write",
	"Microsoft.Storage/storageAccounts/write",
	"Microsoft.Authorization/roleAssignments/write",
	"Microsoft.KeyVault/vaults/write",
	"Microsoft.Sql/servers/firewallRules/write",
}

// OwnerRoleID is the built-in Owner role definition GUID.
const OwnerRoleID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

// ActivityLogAPI is the subset of *armmonitor.ActivityLogsClient the monitor uses.
type ActivityLogAPI interface {
	NewListPager(filter string, options *armmonitor.ActivityLogsClientListOptions) *runtime.Pager[armmonitor.ActivityLogsClientListResponse]
}

// ActivityLogSource polls the Azure Activity Log of one subscription.
type ActivityLogSource struct {
	API          ActivityLogAPI
	Subscription string
	Now          func() time.Time
}

func (s *ActivityLogSource) Name() string { return "activitylog:" + s.Subscription }

const activitySelect = "eventTimestamp,eventDataId,operationName,caller,resourceId,status,properties,subscriptionId,resourceType,correlationId,level"

// ActivityFilter builds the OData filter for the window.
func ActivityFilter(since, until time.Time) string {
	return fmt.Sprintf("eventTimestamp ge '%s' and eventTimestamp le '%s'", since.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339))
}

func (s *ActivityLogSource) Poll(ctx context.Context, since time.Time) ([]Event, error) {
	until := time.Now()
	if s.Now != nil {
		until = s.Now()
	}
	pager := s.API.NewListPager(ActivityFilter(since, until), &armmonitor.ActivityLogsClientListOptions{Select: strPtr(activitySelect)})
	var out []Event
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		for _, ev := range page.Value {
			if e, ok := MapActivityLog(ev, s.Subscription); ok {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func strPtr(s string) *string { return &s }

func newActivityLogSource(spec core.AccountSpec) (Source, error) {
	if spec.SubscriptionID == "" {
		return nil, fmt.Errorf("azure monitor requires subscription id")
	}
	cred, err := core.AzureCredential(spec)
	if err != nil {
		return nil, err
	}
	c, err := armmonitor.NewActivityLogsClient(spec.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return &ActivityLogSource{API: c, Subscription: spec.SubscriptionID}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func locValue(l *armmonitor.LocalizableString) string {
	if l == nil {
		return ""
	}
	return deref(l.Value)
}

var childSegment = regexp.MustCompile(`(?i)/(securityRules|firewallRules)/[^/]+$`)

// MapActivityLog maps a watched Activity Log record onto an Event. Started and
// Failed records are skipped (each write logs Started + Succeeded).
func MapActivityLog(ev *armmonitor.EventData, subscription string) (Event, bool) {
	if ev == nil {
		return Event{}, false
	}
	op := locValue(ev.OperationName)
	watched := false
	for _, w := range AzureOperations {
		if strings.EqualFold(op, w) {
			op, watched = w, true
		}
	}
	if !watched {
		return Event{}, false
	}
	switch strings.ToLower(locValue(ev.Status)) {
	case "started", "failed":
		return Event{}, false
	}
	if s := deref(ev.SubscriptionID); s != "" {
		subscription = s
	}
	raw := map[string]any{"event_id": deref(ev.EventDataID), "operation": op, "status": locValue(ev.Status), "correlation_id": deref(ev.CorrelationID)}
	var body any
	for k, v := range ev.Properties {
		if v == nil {
			continue
		}
		raw[k] = *v
		lk := strings.ToLower(k)
		if lk == "responsebody" || (lk == "requestbody" && body == nil) {
			if b := jsonish(*v); b != nil {
				if _, ok := b.(map[string]any); ok {
					body = b
				}
			}
		}
	}
	props := get(body, "properties")
	resID := deref(ev.ResourceID)
	e := Event{
		Provider: model.ProviderAzure, Account: subscription, Source: "activitylog", EventName: op,
		Actor: deref(ev.Caller), ResourceID: resID, Raw: raw,
	}
	if ev.EventTimestamp != nil {
		e.Time = *ev.EventTimestamp
	}
	parent := childSegment.ReplaceAllString(resID, "")
	set := func(canon string, sev model.Severity, id, typ, title string) {
		e.CanonicalID, e.Severity, e.ResourceID, e.ResourceType, e.Title = canon, sev, id, typ, title
	}
	switch op {
	case "Microsoft.Network/networkSecurityGroups/securityRules/write":
		if props == nil {
			set("", model.Medium, parent, "azure_network_security_group", "NSG security rule changed")
			break
		}
		switch nsgExposure(props) {
		case "all":
			set("AZ_NSG_OPEN_SSH", model.Critical, parent, "azure_network_security_group", "NSG rule allows all ports from the internet")
		case "ssh":
			set("AZ_NSG_OPEN_SSH", model.High, parent, "azure_network_security_group", "NSG rule allows SSH from the internet")
		case "rdp":
			set("AZ_NSG_OPEN_RDP", model.High, parent, "azure_network_security_group", "NSG rule allows RDP from the internet")
		case "other":
			set("", model.Medium, parent, "azure_network_security_group", "NSG rule opens a port to the internet")
		default:
			set("", model.Low, parent, "azure_network_security_group", "NSG security rule changed")
		}
	case "Microsoft.Storage/storageAccounts/write":
		switch {
		case isTrue(get(props, "allowBlobPublicAccess")):
			set("AZ_STORAGE_PUBLIC_BLOB", model.High, resID, "azure_storage_account", "Storage account allows anonymous blob access")
		case isFalse(get(props, "supportsHttpsTrafficOnly")):
			set("AZ_STORAGE_HTTP_ALLOWED", model.Medium, resID, "azure_storage_account", "Storage account allows HTTP")
		default:
			set("", model.Medium, resID, "azure_storage_account", "Storage account configuration changed")
		}
	case "Microsoft.Authorization/roleAssignments/write":
		if strings.Contains(strings.ToLower(gets(props, "roleDefinitionId")), OwnerRoleID) {
			set("", model.Critical, resID, "azure_role_assignment", "Owner role assigned")
		} else {
			set("", model.High, resID, "azure_role_assignment", "Role assignment created")
		}
	case "Microsoft.KeyVault/vaults/write":
		if isFalse(get(props, "enableSoftDelete")) {
			set("AZ_KEYVAULT_NO_SOFTDELETE", model.Medium, resID, "azure_key_vault", "Key Vault soft delete disabled")
		} else {
			set("", model.Medium, resID, "azure_key_vault", "Key Vault configuration changed")
		}
	case "Microsoft.Sql/servers/firewallRules/write":
		start, end := gets(props, "startIpAddress"), gets(props, "endIpAddress")
		if start == "0.0.0.0" && end == "255.255.255.255" {
			set("AZ_SQL_PUBLIC", model.Critical, parent, "azure_sql_server", "SQL server firewall opened to the entire internet")
		} else {
			set("", model.Medium, parent, "azure_sql_server", "SQL server firewall rule changed")
		}
	}
	return e, true
}

// nsgExposure classifies an inbound Allow rule from an internet source: all | ssh | rdp | other | "".
func nsgExposure(props any) string {
	if !strings.EqualFold(gets(props, "access"), "Allow") || (gets(props, "direction") != "" && !strings.EqualFold(gets(props, "direction"), "Inbound")) {
		return ""
	}
	sources := append(strs(get(props, "sourceAddressPrefix")), strs(get(props, "sourceAddressPrefixes"))...)
	open := false
	for _, s := range sources {
		if openSource(s) {
			open = true
		}
	}
	if !open {
		return ""
	}
	ports := append(strs(get(props, "destinationPortRange")), strs(get(props, "destinationPortRanges"))...)
	cls := "other"
	for _, p := range ports {
		switch {
		case allPorts(p):
			return "all"
		case portSpanCovers(p, 22):
			cls = "ssh"
		case portSpanCovers(p, 3389) && cls != "ssh":
			cls = "rdp"
		}
	}
	return cls
}
