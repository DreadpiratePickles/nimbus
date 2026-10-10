package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAccErrorIsTypedCollectError(t *testing.T) {
	var acc Acc
	acc.Error("s3:GetBucketAcl", &HTTPError{Status: 403, URL: "u", Body: "AccessDenied"})
	acc.Error("ec2", context.DeadlineExceeded)
	r := acc.Result()
	if len(r.Errors) != 2 {
		t.Fatalf("errors = %v", r.Errors)
	}
	if !errors.Is(r.Errors[1], context.DeadlineExceeded) {
		t.Error("CollectError must unwrap to its cause")
	}
	if !strings.HasPrefix(r.Errors[0].Error(), "s3:GetBucketAcl: ") {
		t.Errorf("message = %q", r.Errors[0].Error())
	}
	r.Errors = AttributeErrors(r.Errors, "aws", "111")
	ces := r.CollectErrors()
	if len(ces) != 2 {
		t.Fatalf("collect errors = %+v", ces)
	}
	want := []CollectError{
		{Provider: "aws", Account: "111", API: "s3:GetBucketAcl", Reason: ReasonAccessDenied},
		{Provider: "aws", Account: "111", API: "ec2", Reason: ReasonTimeout},
	}
	for i, w := range want {
		g := ces[i]
		if g.Provider != w.Provider || g.Account != w.Account || g.API != w.API || g.Reason != w.Reason || g.Message == "" {
			t.Errorf("collect error %d = %+v, want %+v", i, g, w)
		}
	}
}

func TestCollectErrorsWrapsPlainErrors(t *testing.T) {
	r := Result{Errors: AttributeErrors([]error{errors.New("boom"), fmt.Errorf("aws 1: %w", &CollectError{API: "rds", Reason: ReasonError, Err: errors.New("x")})}, "aws", "1")}
	ces := r.CollectErrors()
	if len(ces) != 2 || ces[0].Reason != ReasonError || ces[0].Provider != "aws" || ces[0].Message != "boom" {
		t.Fatalf("plain = %+v", ces)
	}
	if ces[1].API != "rds" || ces[1].Account != "1" {
		t.Fatalf("wrapped = %+v", ces[1])
	}
}

func TestRESTSurfacesGitHubRateLimit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(time.Hour).Unix()))
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"API rate limit exceeded for installation"}`)
	}))
	defer srv.Close()
	rc := &REST{BaseURL: srv.URL, Backoff: time.Millisecond}
	_, err := rc.Get(context.Background(), "/x", nil)
	if err == nil || !IsRateLimited(err) {
		t.Fatalf("err = %v, want rate-limited", err)
	}
	if ClassifyReason(err) != ReasonRateLimited {
		t.Errorf("reason = %q", ClassifyReason(err))
	}
	if calls != 1 {
		t.Errorf("a reset an hour away must not be retried in a loop: calls = %d", calls)
	}
}

func TestRESTRetriesShortSecondaryRateLimit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"You have exceeded a secondary rate limit"}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()
	rc := &REST{BaseURL: srv.URL, Backoff: time.Millisecond}
	var out map[string]bool
	if _, err := rc.Get(context.Background(), "/x", &out); err != nil || !out["ok"] {
		t.Fatalf("err = %v out = %v calls = %d", err, out, calls)
	}
}

func TestPlain403IsNotRateLimited(t *testing.T) {
	err := &HTTPError{Status: 403, Body: "Resource not accessible by integration"}
	if IsRateLimited(err) || ClassifyReason(err) != ReasonAccessDenied {
		t.Fatalf("plain 403 misclassified: %v %q", IsRateLimited(err), ClassifyReason(err))
	}
}
