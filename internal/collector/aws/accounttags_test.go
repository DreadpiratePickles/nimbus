package aws

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/smithy-go"
)

// W7-POLISH r5 #5: `governance init` proposes per-account owners from AWS Organizations account
// tags (organizations:ListAccounts + ListTagsForResource on each account; read-only).

type fakeAccountTags struct {
	accounts []OrgAccount
	tags     map[string]map[string]string
	listErr  error
	tagErr   map[string]error
}

func (f *fakeAccountTags) ListOrgAccounts(context.Context) ([]OrgAccount, error) {
	return f.accounts, f.listErr
}

func (f *fakeAccountTags) ListAccountTags(_ context.Context, id string) (map[string]string, error) {
	if err := f.tagErr[id]; err != nil {
		return nil, err
	}
	return f.tags[id], nil
}

func TestAccountTagsReadsActiveAccounts(t *testing.T) {
	f := &fakeAccountTags{
		accounts: []OrgAccount{{ID: "111111111111", Name: "prod", Status: "ACTIVE"}, {ID: "222222222222", Name: "pay", Status: "ACTIVE"},
			{ID: "333333333333", Name: "gone", Status: "SUSPENDED"}, {ID: "444444444444", Name: "denied", Status: "ACTIVE"}},
		tags: map[string]map[string]string{
			"111111111111": {"owner": "platform-team", "env": "prod"},
			"222222222222": {"team": "payments"},
			"333333333333": {"owner": "nobody"},
		},
		tagErr: map[string]error{"444444444444": &smithy.GenericAPIError{Code: "AccessDeniedException"}},
	}
	got, notes, err := AccountTags(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if got["111111111111"]["owner"] != "platform-team" || got["222222222222"]["team"] != "payments" {
		t.Errorf("tags %v", got)
	}
	if _, ok := got["333333333333"]; ok {
		t.Errorf("a suspended account's tags must not be proposed: %v", got)
	}
	if _, ok := got["444444444444"]; ok || len(notes) != 1 || !strings.Contains(notes[0], "444444444444") {
		t.Errorf("a denied tag read is skipped with a note: %v %v", got, notes)
	}

	// A member account cannot list the organization: one error naming the call.
	_, _, err = AccountTags(context.Background(), &fakeAccountTags{listErr: &smithy.GenericAPIError{Code: "AccessDeniedException"}})
	if err == nil || !strings.Contains(err.Error(), "organizations:ListAccounts") {
		t.Errorf("denied ListAccounts: %v", err)
	}
	_, _, err = AccountTags(context.Background(), &fakeAccountTags{listErr: &smithy.GenericAPIError{Code: "AWSOrganizationsNotInUseException"}})
	if !errors.Is(err, ErrNotInOrganization) {
		t.Errorf("not in an organization: %v", err)
	}
}

// The hand-signed Organizations client speaks the JSON 1.1 API for both calls and pages.
func TestSDKOrganizationsAccountTagsWire(t *testing.T) {
	var mu sync.Mutex
	var targets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var in map[string]string
		json.Unmarshal(b, &in)
		tgt := r.Header.Get("X-Amz-Target")
		mu.Lock()
		targets = append(targets, tgt)
		mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			w.WriteHeader(403)
			return
		}
		switch tgt {
		case "AWSOrganizationsV20161128.ListAccounts":
			if in["NextToken"] == "" {
				w.Write([]byte(`{"Accounts":[{"Id":"111111111111","Name":"prod","Status":"ACTIVE"}],"NextToken":"p2"}`))
				return
			}
			w.Write([]byte(`{"Accounts":[{"Id":"222222222222","Name":"pay","Status":"ACTIVE"}]}`))
		case "AWSOrganizationsV20161128.ListTagsForResource":
			if in["ResourceId"] == "111111111111" {
				w.Write([]byte(`{"Tags":[{"Key":"owner","Value":"platform-team"}]}`))
				return
			}
			w.Write([]byte(`{"Tags":[{"Key":"team","Value":"payments"}]}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	o := &sdkOrganizations{cfg: v4cfg(nil), endpoint: srv.URL}
	got, notes, err := AccountTags(context.Background(), o)
	if err != nil || len(notes) != 0 {
		t.Fatalf("%v %v", err, notes)
	}
	if got["111111111111"]["owner"] != "platform-team" || got["222222222222"]["team"] != "payments" {
		t.Errorf("tags %v", got)
	}
	if len(targets) != 4 {
		t.Errorf("calls %v", targets)
	}
}
