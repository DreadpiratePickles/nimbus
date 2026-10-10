package aws

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// Verify-4 LOW (scratchpad/verify-4/tree-sec/internal/collector/aws/zz_verify4_signed_test.go):
// the hand-signed ELBv2 / Organizations clients must not carry the session token (or the
// signature) to another host on a redirect, and must stop on a repeated page token.

func v4cfg(hc awssdk.HTTPClient) awssdk.Config {
	return awssdk.Config{Region: "us-east-1", HTTPClient: hc,
		Credentials: credentials.NewStaticCredentialsProvider("AKIDV4PROBE", "SECRETV4PROBE", "SESSIONTOKENV4PROBE")}
}

func TestSignedClientsDoNotFollowRedirects(t *testing.T) {
	for _, hc := range []awssdk.HTTPClient{nil, awshttp.NewBuildableClient(), &http.Client{}} {
		var mu sync.Mutex
		var got []string
		evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got = append(got, "tok="+r.Header.Get("X-Amz-Security-Token")+" auth="+r.Header.Get("Authorization"))
			mu.Unlock()
			w.WriteHeader(500)
		}))
		other := strings.Replace(evil.URL, "127.0.0.1", "localhost", 1)
		rd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other+"/", http.StatusTemporaryRedirect)
		}))
		_, err1 := (&sdkELBv2{cfg: v4cfg(hc), endpoint: rd.URL}).DescribeLoadBalancers(context.Background())
		_, err2 := (&sdkOrganizations{cfg: v4cfg(hc), endpoint: rd.URL}).ListParents(context.Background(), "111111111111")
		rd.Close()
		evil.Close()
		if len(got) > 0 {
			t.Errorf("client %T: redirect followed to another host: %v", hc, got)
		}
		if err1 == nil || err2 == nil {
			t.Errorf("client %T: redirect not reported as an error: elbv2=%v orgs=%v", hc, err1, err2)
		}
	}
}

func TestSignedClientsStopOnRepeatedPageToken(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&n, 1)
		b, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(r.Header.Get("X-Amz-Target"), "ListParents"):
			io.WriteString(w, `{"Parents":[{"Id":"r-1","Type":"ROOT"}],"NextToken":"same"}`)
		case strings.Contains(r.Header.Get("X-Amz-Target"), "ListPoliciesForTarget"):
			io.WriteString(w, `{"Policies":[],"NextToken":"same"}`)
		case strings.Contains(string(b), "DescribeListeners"):
			io.WriteString(w, `<DescribeListenersResponse><DescribeListenersResult><Listeners></Listeners><NextMarker>same</NextMarker></DescribeListenersResult></DescribeListenersResponse>`)
		case strings.Contains(string(b), "DescribeTargetGroups"):
			io.WriteString(w, `<DescribeTargetGroupsResponse><DescribeTargetGroupsResult><TargetGroups></TargetGroups><NextMarker>same</NextMarker></DescribeTargetGroupsResult></DescribeTargetGroupsResponse>`)
		default:
			io.WriteString(w, `<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers></LoadBalancers><NextMarker>same</NextMarker></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`)
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e := &sdkELBv2{cfg: v4cfg(nil), endpoint: srv.URL}
	o := &sdkOrganizations{cfg: v4cfg(nil), endpoint: srv.URL}
	calls := map[string]func() error{
		"DescribeLoadBalancers": func() error { _, err := e.DescribeLoadBalancers(ctx); return err },
		"DescribeListeners":     func() error { _, err := e.DescribeListeners(ctx, "lb"); return err },
		"DescribeTargetGroups":  func() error { _, err := e.DescribeTargetGroups(ctx, "lb"); return err },
		"ListParents":           func() error { _, err := o.ListParents(ctx, "111111111111"); return err },
		"ListPoliciesForTarget": func() error { _, err := o.ListPoliciesForTarget(ctx, "t", "SERVICE_CONTROL_POLICY"); return err },
	}
	for name, call := range calls {
		atomic.StoreInt64(&n, 0)
		err := call()
		if got := atomic.LoadInt64(&n); got > 3 || err == nil || !strings.Contains(err.Error(), "repeated") {
			t.Errorf("%s: %d requests, err=%v; want a stop after the token repeats", name, got, err)
		}
	}
}
