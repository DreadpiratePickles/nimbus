package aws

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

// OrgParent is one parent of an account or OU (organizations:ListParents).
type OrgParent struct {
	ID   string `json:"Id"`
	Type string `json:"Type"` // ROOT | ORGANIZATIONAL_UNIT
}

// OrgPolicy is one policy summary (organizations:ListPoliciesForTarget).
type OrgPolicy struct {
	ID         string `json:"Id"`
	ARN        string `json:"Arn"`
	Name       string `json:"Name"`
	AWSManaged bool   `json:"AwsManaged"`
}

// OrganizationsAPI is the read-only subset of AWS Organizations the SCP chain needs. Member
// accounts are usually denied these calls (only the management account or a delegated
// administrator may call them); the denial is recorded as a coverage row.
type OrganizationsAPI interface {
	// DescribeOrganization may be called from any member account (organisation id, W7).
	DescribeOrganization(ctx context.Context) (OrgInfo, error)
	ListParents(ctx context.Context, childID string) ([]OrgParent, error)
	ListPoliciesForTarget(ctx context.Context, targetID, filter string) ([]OrgPolicy, error)
	DescribePolicy(ctx context.Context, policyID string) (string, error)
}

// OrgInfo is the account's organisation (organizations:DescribeOrganization).
type OrgInfo struct {
	ID              string `json:"Id"`
	ARN             string `json:"Arn"`
	MasterAccountID string `json:"MasterAccountId"`
}

// orgIdentity is what the collector knows about the account's organisation id.
type orgIdentity struct {
	id, status, source string // status collected | not_in_org | denied | error
}

// fetchOrgID records the account's organisation id; every failed call is a coverage row.
func fetchOrgID(ctx context.Context, c OrganizationsAPI, inv *inventory, acc *core.Acc) {
	oi := orgIdentity{status: "not_collected"}
	defer func() { inv.lock(func() { inv.orgID = &oi }) }()
	// Unlike the SCP chain reads, DescribeOrganization may be called from any member account
	// (W7-ENGINE r5 #15: aws:PrincipalOrgID trust evaluation needs the own organisation id).
	info, err := c.DescribeOrganization(ctx)
	switch {
	case err == nil && info.ID != "":
		oi = orgIdentity{id: info.ID, status: "collected", source: "organizations:DescribeOrganization"}
	case err == nil:
		oi.status = "error"
	case strings.Contains(apiCode(err), "AWSOrganizationsNotInUse"):
		oi.status = "not_in_org"
	case isAccessDenied(err):
		oi.status = "denied"
		acc.Error("organizations:DescribeOrganization", err)
	default:
		oi.status = "error"
		acc.Error("organizations:DescribeOrganization", err)
	}
}

// orgIDFromPolicyARN is the organisation id in an Organizations policy ARN
// (arn:aws:organizations::<mgmt>:policy/o-xxxx/service_control_policy/p-xxxx); "" otherwise
// (AWS-managed policies carry no organisation).
func orgIDFromPolicyARN(arn string) string {
	i := strings.Index(arn, ":policy/o-")
	if i < 0 {
		return ""
	}
	rest := arn[i+len(":policy/"):]
	if j := strings.IndexByte(rest, '/'); j > 0 {
		return rest[:j]
	}
	return ""
}

const (
	filterSCP = "SERVICE_CONTROL_POLICY"
	filterRCP = "RESOURCE_CONTROL_POLICY"
)

// scpPolicy is one SCP / RCP with its content.
type scpPolicy struct {
	ID, Name, ARN string
	Document      string
}

// orgPolicies is the account's policy chain, root first, then each OU, then the account.
type orgPolicies struct {
	status string // collected | not_in_org | denied | error
	levels [][]scpPolicy
	rcps   [][]scpPolicy
	path   []string // target ids, root first
}

// fetchSCPs walks the account's OU path to the root and reads the SCPs (and RCPs) attached at
// every level. Every failed call is recorded on acc with its API name (coverage).
func fetchSCPs(ctx context.Context, c OrganizationsAPI, inv *inventory, acc *core.Acc) error {
	op := orgPolicies{status: "collected"}
	defer func() { inv.lock(func() { inv.org = &op }) }()
	fail := func(api string, err error) error {
		switch {
		case strings.Contains(apiCode(err), "AWSOrganizationsNotInUse"):
			op.status = "not_in_org"
			return nil
		case isAccessDenied(err):
			op.status = "denied"
		default:
			op.status = "error"
		}
		acc.Error("organizations:"+api, err)
		return nil
	}
	path := []string{inv.account}
	for child, depth := inv.account, 0; depth < 8; depth++ {
		parents, err := c.ListParents(ctx, child)
		if err != nil {
			return fail("ListParents "+child, err)
		}
		if len(parents) == 0 {
			break
		}
		path = append([]string{parents[0].ID}, path...)
		if parents[0].Type == "ROOT" {
			break
		}
		child = parents[0].ID
	}
	op.path = path
	content := map[string]string{}
	read := func(filter string) ([][]scpPolicy, error) {
		var levels [][]scpPolicy
		for _, target := range path {
			pols, err := c.ListPoliciesForTarget(ctx, target, filter)
			if err != nil {
				return nil, fail("ListPoliciesForTarget "+target+" "+filter, err)
			}
			var level []scpPolicy
			for _, p := range pols {
				doc, ok := content[p.ID]
				if !ok {
					d, err := c.DescribePolicy(ctx, p.ID)
					if err != nil {
						return nil, fail("DescribePolicy "+p.ID, err)
					}
					doc, content[p.ID] = d, d
				}
				level = append(level, scpPolicy{ID: p.ID, Name: p.Name, ARN: p.ARN, Document: doc})
			}
			levels = append(levels, level)
		}
		return levels, nil
	}
	levels, err := read(filterSCP)
	if err != nil || op.status != "collected" {
		return err
	}
	op.levels = levels
	// RCPs are newer; an account that has none enabled answers with an error we tolerate.
	if rcps, _ := read(filterRCP); op.status == "collected" {
		op.rcps = rcps
	} else {
		op.status = "collected" // SCPs are complete; RCP failure is already a coverage row
	}
	return nil
}

// sdkOrganizations calls the Organizations JSON 1.1 API with SigV4 (the organizations SDK module
// is not a dependency; these are three read-only calls).
type sdkOrganizations struct {
	cfg      awssdk.Config
	endpoint string // tests
}

func (o *sdkOrganizations) call(ctx context.Context, op string, in, out any) error {
	body, _ := json.Marshal(in)
	base := o.endpoint
	if base == "" {
		base = "https://organizations.us-east-1.amazonaws.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AWSOrganizationsV20161128."+op)
	if o.cfg.Credentials == nil {
		return fmt.Errorf("organizations: no credentials")
	}
	creds, err := o.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "organizations", "us-east-1", time.Now().UTC()); err != nil {
		return err
	}
	resp, err := signedDoer(o.cfg.HTTPClient).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Type    string `json:"__type"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		code := e.Type
		if i := strings.LastIndex(code, "#"); i >= 0 {
			code = code[i+1:]
		}
		if code == "" {
			code = http.StatusText(resp.StatusCode)
		}
		return &smithy.GenericAPIError{Code: code, Message: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, e.Message)}
	}
	return json.Unmarshal(data, out)
}

func (o *sdkOrganizations) ListParents(ctx context.Context, child string) ([]OrgParent, error) {
	var all []OrgParent
	token := ""
	var pages pageTokens
	for {
		in := map[string]any{"ChildId": child}
		if token != "" {
			in["NextToken"] = token
		}
		var out struct {
			Parents   []OrgParent
			NextToken string
		}
		if err := o.call(ctx, "ListParents", in, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Parents...)
		if token = out.NextToken; token == "" {
			return all, nil
		}
		if err := pages.next("organizations:ListParents", token); err != nil {
			return nil, err
		}
	}
}

func (o *sdkOrganizations) ListPoliciesForTarget(ctx context.Context, target, filter string) ([]OrgPolicy, error) {
	var all []OrgPolicy
	token := ""
	var pages pageTokens
	for {
		in := map[string]any{"TargetId": target, "Filter": filter}
		if token != "" {
			in["NextToken"] = token
		}
		var out struct {
			Policies  []OrgPolicy
			NextToken string
		}
		if err := o.call(ctx, "ListPoliciesForTarget", in, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Policies...)
		if token = out.NextToken; token == "" {
			return all, nil
		}
		if err := pages.next("organizations:ListPoliciesForTarget", token); err != nil {
			return nil, err
		}
	}
}

func (o *sdkOrganizations) DescribeOrganization(ctx context.Context) (OrgInfo, error) {
	var out struct {
		Organization OrgInfo
	}
	if err := o.call(ctx, "DescribeOrganization", map[string]any{}, &out); err != nil {
		return OrgInfo{}, err
	}
	return out.Organization, nil
}

func (o *sdkOrganizations) DescribePolicy(ctx context.Context, id string) (string, error) {
	var out struct {
		Policy struct {
			Content string
		}
	}
	if err := o.call(ctx, "DescribePolicy", map[string]any{"PolicyId": id}, &out); err != nil {
		return "", err
	}
	return out.Policy.Content, nil
}
