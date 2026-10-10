package aws

// Account tags for ownership (W7-POLISH, r5 #5): `governance init` proposes a per-account owner
// from the tags on the AWS Organizations account (owner, team, ...). Two read-only calls:
// organizations:ListAccounts and organizations:ListTagsForResource on each account. Only the
// management account or a delegated administrator may make them; a member account gets an
// AccessDenied error, which governance init reports and moves on from.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

// OrgAccount is one account of the organization (organizations:ListAccounts).
type OrgAccount struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Status string `json:"Status"` // ACTIVE | SUSPENDED | PENDING_CLOSURE
}

// AccountTagsAPI is the read-only subset of AWS Organizations account tags need.
type AccountTagsAPI interface {
	ListOrgAccounts(ctx context.Context) ([]OrgAccount, error)
	ListAccountTags(ctx context.Context, accountID string) (map[string]string, error)
}

// ErrNotInOrganization: the credential's account is not in an AWS organization.
var ErrNotInOrganization = errors.New("the account is not in an AWS organization")

// AccountTags reads the tags of every ACTIVE account in the organization: account id -> tags.
// A failed ListAccounts is an error naming the call (ErrNotInOrganization when there is no
// organization); a failed tag read on one account skips that account with a note.
func AccountTags(ctx context.Context, c AccountTagsAPI) (map[string]map[string]string, []string, error) {
	accts, err := c.ListOrgAccounts(ctx)
	if err != nil {
		if strings.Contains(apiCode(err), "AWSOrganizationsNotInUse") {
			return nil, nil, fmt.Errorf("organizations:ListAccounts: %w", ErrNotInOrganization)
		}
		return nil, nil, fmt.Errorf("organizations:ListAccounts: %w", err)
	}
	sort.Slice(accts, func(i, j int) bool { return accts[i].ID < accts[j].ID })
	out := map[string]map[string]string{}
	var notes []string
	for _, a := range accts {
		if a.ID == "" || (a.Status != "" && !strings.EqualFold(a.Status, "ACTIVE")) {
			continue
		}
		tags, err := c.ListAccountTags(ctx, a.ID)
		if err != nil {
			notes = append(notes, fmt.Sprintf("organizations:ListTagsForResource %s: %v", a.ID, err))
			continue
		}
		if len(tags) > 0 {
			out[a.ID] = tags
		}
	}
	return out, notes, nil
}

// NewAccountTagsClient is the hand-signed Organizations client for spec's credentials.
func NewAccountTagsClient(ctx context.Context, spec core.AccountSpec) (AccountTagsAPI, error) {
	cfg, err := core.AWSConfig(ctx, spec, core.DefaultAWSRegion)
	if err != nil {
		return nil, err
	}
	return &sdkOrganizations{cfg: cfg}, nil
}

// ListOrgAccounts is organizations:ListAccounts (all pages).
func (o *sdkOrganizations) ListOrgAccounts(ctx context.Context) ([]OrgAccount, error) {
	var all []OrgAccount
	token := ""
	var pages pageTokens
	for {
		in := map[string]any{}
		if token != "" {
			in["NextToken"] = token
		}
		var out struct {
			Accounts  []OrgAccount
			NextToken string
		}
		if err := o.call(ctx, "ListAccounts", in, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Accounts...)
		if token = out.NextToken; token == "" {
			return all, nil
		}
		if err := pages.next("organizations:ListAccounts", token); err != nil {
			return nil, err
		}
	}
}

// ListAccountTags is organizations:ListTagsForResource on an account id (all pages).
func (o *sdkOrganizations) ListAccountTags(ctx context.Context, accountID string) (map[string]string, error) {
	tags := map[string]string{}
	token := ""
	var pages pageTokens
	for {
		in := map[string]any{"ResourceId": accountID}
		if token != "" {
			in["NextToken"] = token
		}
		var out struct {
			Tags      []struct{ Key, Value string }
			NextToken string
		}
		if err := o.call(ctx, "ListTagsForResource", in, &out); err != nil {
			return nil, err
		}
		for _, t := range out.Tags {
			tags[t.Key] = t.Value
		}
		if token = out.NextToken; token == "" {
			return tags, nil
		}
		if err := pages.next("organizations:ListTagsForResource", token); err != nil {
			return nil, err
		}
	}
}
