// Package iam is a pure, deterministic evaluator of AWS IAM authorization.
//
// It takes parsed policy documents (identity, resource, permission boundary,
// session, SCPs and RCPs per OU level) and a Request, and returns a Decision
// following the AWS policy evaluation logic. It performs no I/O and imports no
// SDK. Anything it cannot decide from its inputs (a condition key missing from
// the request context, an unsupported operator, an unresolvable policy
// variable) makes the outcome Unknown, never Allow. See docs/iam/evaluator.md.
package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
)

// Policy is one parsed IAM policy document. ID is set by the caller (policy
// ARN, name or fixture id) and is used in statement references.
type Policy struct {
	ID        string
	Version   string
	Statement []Statement
}

// Statement is one IAM statement; string-or-list fields are normalized to slices.
type Statement struct {
	Sid          string
	Effect       string // "Allow" | "Deny" (case-sensitive, as in IAM)
	Principal    *PrincipalSet
	NotPrincipal *PrincipalSet
	Action       []string
	NotAction    []string
	Resource     []string
	NotResource  []string
	// Condition maps operator -> condition key -> values. Non-string JSON
	// values (bool, number) are kept in their JSON text form.
	Condition map[string]map[string][]string
}

// PrincipalSet is a Principal / NotPrincipal element. Any is set for the bare
// "*" form; Values maps the principal type (AWS, Service, Federated,
// CanonicalUser) to its values.
type PrincipalSet struct {
	Any    bool
	Values map[string][]string
}

type rawStatement struct {
	Sid          string          `json:"Sid"`
	Effect       string          `json:"Effect"`
	Principal    json.RawMessage `json:"Principal"`
	NotPrincipal json.RawMessage `json:"NotPrincipal"`
	Action       json.RawMessage `json:"Action"`
	NotAction    json.RawMessage `json:"NotAction"`
	Resource     json.RawMessage `json:"Resource"`
	NotResource  json.RawMessage `json:"NotResource"`
	Condition    json.RawMessage `json:"Condition"`
}

// ParsePolicy decodes an IAM policy JSON document. IAM APIs return documents
// URL-encoded, so a percent-encoded input is unescaped first. The returned
// Policy has an empty ID; callers set it.
func ParsePolicy(doc []byte) (Policy, error) {
	doc = bytes.TrimSpace(doc)
	if bytes.HasPrefix(doc, []byte("%7B")) || bytes.HasPrefix(doc, []byte("%7b")) {
		if d, err := url.QueryUnescape(string(doc)); err == nil {
			doc = []byte(d)
		}
	}
	var raw struct {
		Version   string          `json:"Version"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(doc, &raw); err != nil {
		return Policy{}, fmt.Errorf("iam: policy: %w", err)
	}
	var stmts []rawStatement
	trimmed := bytes.TrimSpace(raw.Statement)
	switch {
	case len(trimmed) == 0 || string(trimmed) == "null":
	case trimmed[0] == '{':
		var one rawStatement
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return Policy{}, fmt.Errorf("iam: statement: %w", err)
		}
		stmts = []rawStatement{one}
	default:
		if err := json.Unmarshal(trimmed, &stmts); err != nil {
			return Policy{}, fmt.Errorf("iam: statements: %w", err)
		}
	}
	p := Policy{Version: raw.Version}
	for i, r := range stmts {
		s := Statement{Sid: r.Sid, Effect: r.Effect}
		var err error
		if s.Action, err = strList(r.Action); err != nil {
			return Policy{}, fmt.Errorf("iam: statement %d Action: %w", i, err)
		}
		if s.NotAction, err = strList(r.NotAction); err != nil {
			return Policy{}, fmt.Errorf("iam: statement %d NotAction: %w", i, err)
		}
		if s.Resource, err = strList(r.Resource); err != nil {
			return Policy{}, fmt.Errorf("iam: statement %d Resource: %w", i, err)
		}
		if s.NotResource, err = strList(r.NotResource); err != nil {
			return Policy{}, fmt.Errorf("iam: statement %d NotResource: %w", i, err)
		}
		if s.Principal, err = principalSet(r.Principal); err != nil {
			return Policy{}, fmt.Errorf("iam: statement %d Principal: %w", i, err)
		}
		if s.NotPrincipal, err = principalSet(r.NotPrincipal); err != nil {
			return Policy{}, fmt.Errorf("iam: statement %d NotPrincipal: %w", i, err)
		}
		if s.Condition, err = conditionBlock(r.Condition); err != nil {
			return Policy{}, fmt.Errorf("iam: statement %d Condition: %w", i, err)
		}
		p.Statement = append(p.Statement, s)
	}
	return p, nil
}

func isNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

// strList decodes a string or list of strings.
func strList(raw json.RawMessage) ([]string, error) {
	if isNull(raw) {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, err
	}
	return many, nil
}

// scalarList decodes a scalar (string, bool, number) or a list of scalars into
// their string forms, as condition values may be written either way.
func scalarList(raw json.RawMessage) ([]string, error) {
	var anyv any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&anyv); err != nil {
		return nil, err
	}
	conv := func(v any) (string, error) {
		switch x := v.(type) {
		case string:
			return x, nil
		case bool:
			return strconv.FormatBool(x), nil
		case json.Number:
			return x.String(), nil
		default:
			return "", fmt.Errorf("unsupported condition value %v", v)
		}
	}
	if list, ok := anyv.([]any); ok {
		out := make([]string, 0, len(list))
		for _, v := range list {
			s, err := conv(v)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	}
	s, err := conv(anyv)
	if err != nil {
		return nil, err
	}
	return []string{s}, nil
}

func principalSet(raw json.RawMessage) (*PrincipalSet, error) {
	if isNull(raw) {
		return nil, nil
	}
	var star string
	if err := json.Unmarshal(raw, &star); err == nil {
		if star == "*" {
			return &PrincipalSet{Any: true}, nil
		}
		return &PrincipalSet{Values: map[string][]string{"AWS": {star}}}, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	ps := &PrincipalSet{Values: map[string][]string{}}
	for k, v := range m {
		vals, err := strList(v)
		if err != nil {
			return nil, err
		}
		ps.Values[k] = vals
	}
	return ps, nil
}

func conditionBlock(raw json.RawMessage) (map[string]map[string][]string, error) {
	if isNull(raw) {
		return nil, nil
	}
	var ops map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ops); err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		return nil, nil
	}
	out := map[string]map[string][]string{}
	for op, keys := range ops {
		out[op] = map[string][]string{}
		for k, v := range keys {
			vals, err := scalarList(v)
			if err != nil {
				return nil, err
			}
			out[op][k] = vals
		}
	}
	return out, nil
}

// sortedKeys returns the keys of m in sorted order (deterministic evaluation).
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Ref identifies one statement that matched a request.
type Ref struct {
	Layer    Layer
	PolicyID string
	Sid      string
	Index    int
	Effect   string
	// Conditional is true when the statement's applicability could not be
	// decided (unknown condition key, unresolvable variable).
	Conditional bool
}

// String renders "<policy>#<sid|index>", with a trailing "?" when Conditional.
func (r Ref) String() string {
	id := r.Sid
	if id == "" {
		id = strconv.Itoa(r.Index)
	}
	s := r.PolicyID + "#" + id
	if r.Conditional {
		s += "?"
	}
	return s
}

// Layer names the policy type a statement came from.
type Layer string

const (
	LayerSCP      Layer = "scp"
	LayerRCP      Layer = "rcp"
	LayerResource Layer = "resource"
	LayerIdentity Layer = "identity"
	LayerBoundary Layer = "boundary"
	LayerSession  Layer = "session"
)
