package azure

import (
	"context"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
)

// W7-POLISH r5 #5: subscription tags (owner, team, ...) for `governance init` come from one
// Resource Graph query over resourcecontainers (read-only, paged).
type fakeSubTagGraph struct {
	queries []string
}

func (f *fakeSubTagGraph) Resources(_ context.Context, q armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	f.queries = append(f.queries, *q.Query)
	var resp armresourcegraph.ClientResourcesResponse
	if q.Options == nil || q.Options.SkipToken == nil {
		resp.Data = []any{map[string]any{"subscriptionId": "00000000-0000-4000-8000-000000000001", "tags": map[string]any{"owner": "azure-ops", "env": "prod"}}}
		resp.SkipToken = to.Ptr("p2")
		return resp, nil
	}
	resp.Data = []any{
		map[string]any{"subscriptionId": "00000000-0000-4000-8000-000000000002", "tags": map[string]any{"team": "data"}},
		map[string]any{"subscriptionId": "00000000-0000-4000-8000-000000000003", "tags": nil},
	}
	return resp, nil
}

func TestSubscriptionTagsFromResourceGraph(t *testing.T) {
	f := &fakeSubTagGraph{}
	got, err := SubscriptionTags(context.Background(), f, []string{"00000000-0000-4000-8000-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	if got["00000000-0000-4000-8000-000000000001"]["owner"] != "azure-ops" || got["00000000-0000-4000-8000-000000000002"]["team"] != "data" {
		t.Errorf("tags %v", got)
	}
	if _, ok := got["00000000-0000-4000-8000-000000000003"]; ok {
		t.Errorf("an untagged subscription is not listed: %v", got)
	}
	if len(f.queries) != 2 || !strings.Contains(f.queries[0], "resourcecontainers") || !strings.Contains(f.queries[0], "microsoft.resources/subscriptions") {
		t.Errorf("queries %v", f.queries)
	}
}
