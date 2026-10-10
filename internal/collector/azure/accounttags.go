package azure

// Subscription tags for ownership (W7-POLISH, r5 #5): `governance init` proposes a
// per-subscription owner from the subscription's own tags (owner, team, ...), read with one
// Resource Graph query over resourcecontainers (read-only; Reader on the subscription suffices).

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

const subscriptionTagsQuery = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, tags"

// SubscriptionTags returns subscription id -> tags for the subscriptions the credential can read
// (subs narrows the query when set). Untagged subscriptions are left out.
func SubscriptionTags(ctx context.Context, rg ResourceGraph, subs []string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	req := armresourcegraph.QueryRequest{Query: to.Ptr(subscriptionTagsQuery)}
	for _, s := range subs {
		req.Subscriptions = append(req.Subscriptions, to.Ptr(s))
	}
	var skip *string
	for page := 0; page < 1000; page++ {
		req.Options = &armresourcegraph.QueryRequestOptions{ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray), SkipToken: skip}
		resp, err := rg.Resources(ctx, req, nil)
		if err != nil {
			return nil, fmt.Errorf("resource graph (subscription tags): %w", err)
		}
		rows, _ := resp.Data.([]any)
		for _, r := range rows {
			m, _ := r.(map[string]any)
			id, _ := m["subscriptionId"].(string)
			tags, _ := m["tags"].(map[string]any)
			if id == "" || len(tags) == 0 {
				continue
			}
			t := map[string]string{}
			for k, v := range tags {
				if s, ok := v.(string); ok {
					t[k] = s
				}
			}
			if len(t) > 0 {
				out[id] = t
			}
		}
		if resp.SkipToken == nil || *resp.SkipToken == "" {
			return out, nil
		}
		skip = resp.SkipToken
	}
	return out, fmt.Errorf("resource graph (subscription tags): pagination stopped after 1000 pages")
}

// NewSubscriptionTagsClient is a Resource Graph client for spec's credential.
func NewSubscriptionTagsClient(spec core.AccountSpec) (ResourceGraph, error) {
	cred, err := core.AzureCredential(spec)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	return armresourcegraph.NewClient(cred, nil)
}
