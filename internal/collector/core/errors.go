package core

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Collection-error reasons (CollectError.Reason). The coverage table groups denied /
// skipped API calls by these values.
const (
	ReasonRateLimited  = "rate_limited"
	ReasonAccessDenied = "access_denied"
	ReasonTimeout      = "timeout"
	ReasonCanceled     = "canceled"
	ReasonNotFound     = "not_found"
	ReasonError        = "error"
)

// CollectError is one failed (denied, throttled, timed-out or broken) API call or
// collection scope. Every entry of Result.Errors produced by a native collector is,
// or wraps, a *CollectError; Result.CollectErrors() returns the typed list for the
// coverage table. Provider/Account are filled by RunAll (AttributeErrors).
type CollectError struct {
	Provider string `json:"provider"`
	Account  string `json:"account"`
	// API is the scope or call that failed ("s3:prod-bucket", "github: repo org/x", "account").
	API string `json:"api"`
	// Reason is one of the Reason* constants.
	Reason string `json:"reason"`
	// Message is the underlying error text.
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *CollectError) Error() string {
	msg := e.Message
	if e.Err != nil {
		msg = e.Err.Error()
	}
	if e.API == "" {
		return msg
	}
	return e.API + ": " + msg
}

func (e *CollectError) Unwrap() error { return e.Err }

// NewCollectError wraps err for scope with a classified reason (nil when err is nil).
func NewCollectError(scope string, err error) error {
	if err == nil {
		return nil
	}
	return &CollectError{API: scope, Reason: ClassifyReason(err), Message: err.Error(), Err: err}
}

// ClassifyReason maps an error to a Reason* constant.
func ClassifyReason(err error) string {
	if err == nil {
		return ""
	}
	var ce *CollectError
	if errors.As(err, &ce) && ce.Reason != "" && ce.Reason != ReasonError {
		return ce.Reason
	}
	switch {
	case IsRateLimited(err):
		return ReasonRateLimited
	case errors.Is(err, context.DeadlineExceeded):
		return ReasonTimeout
	case errors.Is(err, context.Canceled):
		return ReasonCanceled
	}
	switch StatusOf(err) {
	case http.StatusUnauthorized, http.StatusForbidden:
		return ReasonAccessDenied
	case http.StatusNotFound:
		return ReasonNotFound
	case http.StatusTooManyRequests:
		return ReasonRateLimited
	}
	l := strings.ToLower(err.Error())
	for _, s := range []string{"accessdenied", "access denied", "unauthorized", "authorizationfailed", "permission_denied", "permission denied", "forbidden", "optinrequired"} {
		if strings.Contains(l, s) {
			return ReasonAccessDenied
		}
	}
	for _, s := range []string{"throttl", "rate limit", "ratelimit", "toomanyrequests", "rate exceeded", "quota exceeded"} {
		if strings.Contains(l, s) {
			return ReasonRateLimited
		}
	}
	return ReasonError
}

// AttributeErrors stamps provider/account onto every CollectError in errs (wrapping
// plain errors in a CollectError) without changing their messages.
func AttributeErrors(errs []error, provider, account string) []error {
	out := make([]error, 0, len(errs))
	for _, e := range errs {
		if e == nil {
			continue
		}
		var ce *CollectError
		if errors.As(e, &ce) {
			if ce.Provider == "" {
				ce.Provider = provider
			}
			if ce.Account == "" {
				ce.Account = account
			}
			out = append(out, e)
			continue
		}
		out = append(out, &CollectError{Provider: provider, Account: account, Reason: ClassifyReason(e), Message: e.Error(), Err: e})
	}
	return out
}

// CollectErrors returns Result.Errors as typed CollectError values (plain errors are
// wrapped with Reason "error"). Message always carries the full error text.
func (r Result) CollectErrors() []CollectError {
	out := make([]CollectError, 0, len(r.Errors))
	for _, e := range r.Errors {
		if e == nil {
			continue
		}
		var ce *CollectError
		if errors.As(e, &ce) {
			c := *ce
			c.Message = e.Error()
			if c.API != "" {
				c.Message = strings.TrimPrefix(c.Message, c.API+": ")
			}
			if c.Reason == "" {
				c.Reason = ClassifyReason(e)
			}
			out = append(out, c)
			continue
		}
		out = append(out, CollectError{Reason: ClassifyReason(e), Message: e.Error(), Err: e})
	}
	return out
}
