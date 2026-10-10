package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestSDKS3ControlAccountPAB(t *testing.T) {
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v20180820/configuration/publicAccessBlock" || r.Header.Get("x-amz-account-id") != "111111111111" {
			t.Errorf("bad request %s %v", r.URL.Path, r.Header)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || !strings.Contains(r.Header.Get("Authorization"), "/s3/aws4_request") {
			t.Errorf("request not SigV4-signed for s3: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	cfg := awssdk.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")}
	c := &sdkS3Control{cfg: cfg, endpoint: srv.URL}

	status, body = 200, `<PublicAccessBlockConfiguration xmlns="http://awss3control.amazonaws.com/doc/2018-08-20/"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
	p, err := c.GetAccountPublicAccessBlock(context.Background(), "111111111111")
	if err != nil || !p.All() || !p.Configured {
		t.Fatalf("all-on: %+v %v", p, err)
	}
	status, body = 404, `<ErrorResponse><Error><Code>NoSuchPublicAccessBlockConfiguration</Code><Message>none</Message></Error></ErrorResponse>`
	p, err = c.GetAccountPublicAccessBlock(context.Background(), "111111111111")
	if err != nil || p.Configured || p.All() {
		t.Fatalf("not configured: %+v %v", p, err)
	}
	status, body = 403, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>denied</Message></Error></ErrorResponse>`
	if _, err = c.GetAccountPublicAccessBlock(context.Background(), "111111111111"); err == nil || !isAccessDenied(err) {
		t.Fatalf("denied: %v", err)
	}
}
