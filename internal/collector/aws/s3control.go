package aws

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go"
)

// AccountPublicAccessBlock is the account-wide S3 Block Public Access configuration
// (s3control:GetPublicAccessBlock). Configured is false when none is set.
type AccountPublicAccessBlock struct {
	Configured            bool
	BlockPublicAcls       bool
	IgnorePublicAcls      bool
	BlockPublicPolicy     bool
	RestrictPublicBuckets bool
}

// All reports all four settings on.
func (p *AccountPublicAccessBlock) All() bool {
	return p != nil && p.BlockPublicAcls && p.IgnorePublicAcls && p.BlockPublicPolicy && p.RestrictPublicBuckets
}

// S3ControlAPI reads the account-level Block Public Access configuration.
type S3ControlAPI interface {
	GetAccountPublicAccessBlock(ctx context.Context, accountID string) (*AccountPublicAccessBlock, error)
}

// emptyPayloadSHA256 is the SHA-256 of an empty request body.
const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// sdkS3Control calls the S3 Control REST API directly with SigV4 (the s3control SDK
// module is not a dependency; this is one read-only GET).
type sdkS3Control struct {
	cfg awssdk.Config
	// endpoint overrides https://{account}.s3-control.{region}.amazonaws.com (tests).
	endpoint string
}

func (c *sdkS3Control) GetAccountPublicAccessBlock(ctx context.Context, accountID string) (*AccountPublicAccessBlock, error) {
	region := c.cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	base := c.endpoint
	if base == "" {
		base = fmt.Sprintf("https://%s.s3-control.%s.amazonaws.com", accountID, region)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/v20180820/configuration/publicAccessBlock", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-amz-account-id", accountID)
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
	if c.cfg.Credentials == nil {
		return nil, fmt.Errorf("s3control: no credentials")
	}
	creds, err := c.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, emptyPayloadSHA256, "s3", region, time.Now().UTC()); err != nil {
		return nil, err
	}
	var client interface {
		Do(*http.Request) (*http.Response, error)
	} = &http.Client{Timeout: 30 * time.Second}
	if c.cfg.HTTPClient != nil {
		client = c.cfg.HTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return parseAccountPAB(resp.StatusCode, body)
}

func parseAccountPAB(status int, body []byte) (*AccountPublicAccessBlock, error) {
	if status != http.StatusOK {
		var e struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		}
		_ = xml.Unmarshal(body, &e)
		if e.Code == "" {
			// S3 Control wraps errors in <ErrorResponse><Error>…</Error></ErrorResponse>.
			var wrapped struct {
				Error struct {
					Code    string `xml:"Code"`
					Message string `xml:"Message"`
				} `xml:"Error"`
			}
			_ = xml.Unmarshal(body, &wrapped)
			e.Code, e.Message = wrapped.Error.Code, wrapped.Error.Message
		}
		if e.Code == "NoSuchPublicAccessBlockConfiguration" {
			return &AccountPublicAccessBlock{}, nil
		}
		if e.Code == "" {
			e.Code = http.StatusText(status)
		}
		return nil, &smithy.GenericAPIError{Code: e.Code, Message: fmt.Sprintf("HTTP %d: %s", status, e.Message)}
	}
	var cfg struct {
		BlockPublicAcls       bool `xml:"BlockPublicAcls"`
		IgnorePublicAcls      bool `xml:"IgnorePublicAcls"`
		BlockPublicPolicy     bool `xml:"BlockPublicPolicy"`
		RestrictPublicBuckets bool `xml:"RestrictPublicBuckets"`
	}
	if err := xml.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("s3control: decode publicAccessBlock: %w", err)
	}
	return &AccountPublicAccessBlock{Configured: true, BlockPublicAcls: cfg.BlockPublicAcls, IgnorePublicAcls: cfg.IgnorePublicAcls,
		BlockPublicPolicy: cfg.BlockPublicPolicy, RestrictPublicBuckets: cfg.RestrictPublicBuckets}, nil
}
