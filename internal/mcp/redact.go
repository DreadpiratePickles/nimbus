package mcp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// redactor replaces identifying values with stable per-session placeholders on the way out and
// restores them on the way in. The HMAC key is random per session, so a placeholder cannot be
// brute-forced back to a 12-digit account id offline, and it means nothing outside the session.
//
// What is redacted (docs/data-flow.md, plan §5.2):
//   - any value under a key named account/accounts, and any bare 12-digit number (AWS account)
//   - the account segment of an ARN
//   - the subscription id in an Azure /subscriptions/<guid> path
//   - IPv4 addresses (0.0.0.0 is kept: it means "anywhere")
//   - every value (not key) of a tags map, including a JSON-text tags column from the sql tool
type redactor struct {
	mu     sync.Mutex
	key    []byte
	toPH   map[string]string // kind|value -> placeholder
	fromPH map[string]string // placeholder -> value

	known    *strings.Replacer // raw numeric ACCT/SUB/IP value -> placeholder (substring), rebuilt lazily
	knownTok [][2]string       // other raw values -> placeholder (whole token only), longest first
	knownN   int               // len(toPH) when known was built

	// ids keys finding / attack-path ids (store/extid.go) in every value and SQL cell, so the
	// sql tool's columns hold the keyed id too and no comparison can run on the raw digest.
	ids *store.IDMapper
}

// idPolicy says how a redaction pass treats digest ids (Verification 7 defect 1). key=false: the
// pass never keys (the sql tool's output: its stored columns were keyed inside SQLite, per column
// provenance, and anything else is text the client wrote or computed — keying it would confirm
// that the text is a stored fingerprint). sent: tokens the client sent in this call, never keyed.
type idPolicy struct {
	key  bool
	sent map[string]bool
}

var keyStored = idPolicy{key: true} // values that come only from stored data

func (r *redactor) mapIDs(s string, p idPolicy) string {
	if !p.key {
		return s
	}
	return r.ids.MapStringExcept(s, p.sent)
}

func newRedactor() *redactor {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return &redactor{key: k, toPH: map[string]string{}, fromPH: map[string]string{}}
}

var (
	reARNAcct = regexp.MustCompile(`(arn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:)(\d{12})(:)`)
	reAcct    = regexp.MustCompile(`\b\d{12}\b`)
	reSub     = regexp.MustCompile(`(?i)(/subscriptions/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)
	reIPv4    = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	rePH      = regexp.MustCompile(`\b(?:ACCT|IP|SUB|TAG|RES)_[0-9a-f]{8}\b`)
	// reAWSRes is an AWS resource id (route table, NACL, security group, subnet, VPC, gateway,
	// interface, instance, ...): the ids verdict reasons and hop "because" text name
	// (delta r3 #7). Names (roles, buckets, hosts) are not ids and stay readable.
	reAWSRes = regexp.MustCompile(`\b(?:rtb|acl|sg|subnet|vpc|igw|eigw|nat|eni|i|vpce|pcx|tgw|tgw-attach|eipalloc|lt|vol|snap|ami|pl)-[0-9a-f]{8,17}\b`)
	// reGCPProject is a GCP project id inside a resource path (projects/<id>/...): the account
	// of a GCP resource (verify-5 MCP-2).
	reGCPProject = regexp.MustCompile(`(projects/)([a-z][a-z0-9-]{4,28}[a-z0-9])(/|$|[^A-Za-z0-9_.-])`)
	accountKey   = map[string]bool{"account": true, "accounts": true, "account_id": true, "subscription": true, "project": true}
)

func (r *redactor) placeholder(kind, v string) string {
	if v == "" || r.fromPH[v] != "" {
		return v
	}
	k := kind + "|" + v
	if ph, ok := r.toPH[k]; ok {
		return ph
	}
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(k))
	ph := kind + "_" + hex.EncodeToString(m.Sum(nil))[:8]
	r.toPH[k], r.fromPH[ph] = ph, v
	return ph
}

// str redacts identifiers inside free text.
func (r *redactor) str(s string) string {
	if s == "" {
		return s
	}
	s = reARNAcct.ReplaceAllStringFunc(s, func(m string) string {
		p := reARNAcct.FindStringSubmatch(m)
		return p[1] + r.placeholder("ACCT", p[2]) + p[3]
	})
	s = reSub.ReplaceAllStringFunc(s, func(m string) string {
		p := reSub.FindStringSubmatch(m)
		return p[1] + r.placeholder("SUB", strings.ToLower(p[2]))
	})
	s = reGCPProject.ReplaceAllStringFunc(s, func(m string) string {
		p := reGCPProject.FindStringSubmatch(m)
		return p[1] + r.placeholder("ACCT", p[2]) + p[3]
	})
	s = reAWSRes.ReplaceAllStringFunc(s, func(m string) string { return r.placeholder("RES", m) })
	s = reAcct.ReplaceAllStringFunc(s, func(m string) string { return r.placeholder("ACCT", m) })
	s = reIPv4.ReplaceAllStringFunc(s, func(m string) string {
		if m == "0.0.0.0" {
			return m
		}
		return r.placeholder("IP", m)
	})
	return s
}

// value redacts a decoded JSON value; key is the field name it sits under ("" for none).
func (r *redactor) value(key string, v any, p idPolicy) any {
	lk := strings.ToLower(key)
	switch x := v.(type) {
	case string:
		x = r.mapIDs(x, p)
		if accountKey[lk] {
			return r.placeholder("ACCT", x)
		}
		if lk == "tags" {
			return r.tagsText(x)
		}
		return r.str(x)
	case []any:
		for i := range x {
			if accountKey[lk] {
				if s, ok := x[i].(string); ok {
					x[i] = r.placeholder("ACCT", s)
					continue
				}
			}
			x[i] = r.value("", x[i], p)
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			nk := r.str(k)
			if lk == "tags" {
				out[nk] = r.tagValue(vv)
				continue
			}
			out[nk] = r.value(k, vv, p)
		}
		return out
	}
	return v
}

func (r *redactor) tagValue(v any) any {
	if s, ok := v.(string); ok {
		return r.placeholder("TAG", s)
	}
	if v == nil {
		return v
	}
	b, _ := json.Marshal(v)
	return r.placeholder("TAG", string(b))
}

// cell redacts one SQL value read from column key (the per-column redaction applied inside
// SQLite by the nimbus_redact function, see sqlview.go). Strings that hold a JSON object or
// array are decoded and redacted structurally (so nested account/tags keys are covered); a
// 12-digit integer, or any integer under an account key, becomes an ACCT placeholder.
// cell is called inside SQLite on stored columns only (the redacting CTE): it keys ids.
func (r *redactor) cell(key string, v any) any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cellLocked(key, v, keyStored)
}

func (r *redactor) cellLocked(key string, v any, p idPolicy) any {
	lk := strings.ToLower(key)
	switch x := v.(type) {
	case []byte:
		return r.cellLocked(key, string(x), p)
	case int64:
		d := strconv.FormatInt(x, 10)
		if accountKey[lk] || x >= 1e11 && x < 1e12 {
			return r.placeholder("ACCT", d)
		}
		return x
	case string:
		x = r.mapIDs(x, p)
		if lk == "tags" {
			return r.tagsText(x)
		}
		if t := strings.TrimSpace(x); len(t) > 1 && (t[0] == '{' || t[0] == '[') {
			var d any
			if json.Unmarshal([]byte(t), &d) == nil {
				if b, err := json.Marshal(r.value(key, d, p)); err == nil {
					return string(b)
				}
			}
		}
		return r.value(key, x, p)
	}
	return v
}

// knownValues replaces every raw ACCT/SUB/IP/RES value this session has seen with its
// placeholder, wherever it occurs in s (defence in depth behind the per-column redaction). Tag
// values are not substring-replaced: they are free text (often short words) and are only
// redacted under a tags key. Numeric values (account ids, IPs, subscription GUIDs) are replaced
// as substrings; other values (a GCP project id, a name-like account) only as a whole token, so
// "nimbus-lab" never turns the name "nimbus-lab-ledger" into "ACCT_…-ledger" (verify-5 MCP-4).
func (r *redactor) knownValues(s string) string {
	if r.known == nil || r.knownN != len(r.toPH) {
		var pairs []string
		r.knownTok = r.knownTok[:0]
		for k, ph := range r.toPH {
			kind, v, _ := strings.Cut(k, "|")
			if kind == "TAG" || len(v) < 7 {
				continue
			}
			if numericLike(v) {
				pairs = append(pairs, v, ph)
			} else {
				r.knownTok = append(r.knownTok, [2]string{v, ph})
			}
		}
		sort.Slice(r.knownTok, func(i, j int) bool { return len(r.knownTok[i][0]) > len(r.knownTok[j][0]) })
		r.known, r.knownN = strings.NewReplacer(pairs...), len(r.toPH)
	}
	s = r.known.Replace(s)
	for _, kv := range r.knownTok {
		s = replaceToken(s, kv[0], kv[1])
	}
	return s
}

// numericLike: digits, IPv4 dots, or a GUID (hex and dashes): replaced as a substring.
func numericLike(v string) bool {
	hasDigit := false
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '.' || c == ':' || c == '-' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
		default:
			return false
		}
	}
	return hasDigit && (strings.Count(v, "-") == 4 || !strings.ContainsAny(v, "abcdefABCDEF-"))
}

func tokenChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-' || b == '.'
}

// replaceToken replaces v with ph where v is a whole token (not inside a longer name).
func replaceToken(s, v, ph string) string {
	if !strings.Contains(s, v) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, v)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := i + len(v)
		if (i == 0 || !tokenChar(s[i-1])) && (j == len(s) || !tokenChar(s[j])) {
			b.WriteString(s[:i] + ph)
		} else {
			b.WriteString(s[:j])
		}
		s = s[j:]
	}
}

// text redacts free text the client will see that is not a structured result: error messages.
// Besides the identifier patterns and known values, every value restored from a placeholder in
// this call's arguments (restored) is put back to its placeholder, so an error that echoes an
// argument can never resolve a placeholder.
func (r *redactor) text(s string, restored map[string]string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(restored) > 0 {
		var pairs []string
		for v, ph := range restored {
			if v != "" {
				pairs = append(pairs, v, ph)
			}
		}
		s = strings.NewReplacer(pairs...).Replace(s)
	}
	return r.knownValues(r.str(s))
}

// hasRawIdentifier reports whether any string in a tool's JSON arguments holds an identifier
// redaction would replace (an account id, ARN account, subscription id or IP). In a redacted
// session such a value would be compared with real data, a yes/no oracle on raw ids, so the
// caller refuses it and the client must pass placeholders.
func (r *redactor) hasRawIdentifier(raw json.RawMessage) bool {
	var d any
	if json.Unmarshal(raw, &d) != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	found := false
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if reAcct.MatchString(x) || reSub.MatchString(x) || reARNAcct.MatchString(x) || reAWSRes.MatchString(x) || reGCPProject.MatchString(x) {
				found = true
			}
			for _, ip := range reIPv4.FindAllString(x, -1) {
				if ip != "0.0.0.0" {
					found = true
				}
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for k, e := range x {
				// any non-placeholder value under an account key is a raw account (a GCP project or
				// Azure name is no 12-digit number, verify-5 MCP-3)
				if str, ok := e.(string); ok && accountKey[strings.ToLower(k)] && str != "" && !rePH.MatchString(str) {
					found = true
				}
				walk(e)
			}
		}
	}
	walk(d)
	return found
}

// tagsText redacts a tags value stored as JSON text (the findings.tags column).
func (r *redactor) tagsText(s string) string {
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return r.str(s)
	}
	out := map[string]any{}
	for k, v := range m {
		out[k] = r.tagValue(v)
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// table redacts sql-tool rows using the column names as keys.
// table is the value pass over a sql result: it never keys ids (see idPolicy).
func (r *redactor) table(cols []string, rows [][]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range rows {
		for i := range row {
			k := ""
			if i < len(cols) {
				k = cols[i]
			}
			row[i] = r.cellLocked(k, row[i], idPolicy{})
			if str, ok := row[i].(string); ok {
				row[i] = r.knownValues(str)
			}
		}
	}
}

// any redacts an arbitrary Go value by round-tripping it through JSON.
func (r *redactor) any(v any, p idPolicy) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var d any
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.knownWalk(r.value("", d, p)), nil
}

// knownWalk applies knownValues to every string in a decoded JSON value, and turns a number that
// is a 12-digit account id into its placeholder (defence in depth behind value()).
func (r *redactor) knownWalk(v any) any {
	switch x := v.(type) {
	case string:
		return r.knownValues(x)
	case float64:
		if x >= 1e11 && x < 1e12 && x == float64(int64(x)) {
			return r.placeholder("ACCT", strconv.FormatInt(int64(x), 10))
		}
	case []any:
		for i := range x {
			x[i] = r.knownWalk(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = r.knownWalk(x[k])
		}
	}
	return v
}

// restore replaces known placeholders in s with their values.
func (r *redactor) restore(s string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return rePH.ReplaceAllStringFunc(s, func(ph string) string {
		if v, ok := r.fromPH[ph]; ok {
			return v
		}
		return ph
	})
}

// restoreJSON re-hydrates every string in a JSON document (tool arguments). restored, when not
// nil, receives value -> placeholder for every substitution made (used to re-redact error text).
func (r *redactor) restoreJSON(raw json.RawMessage, restored map[string]string) (json.RawMessage, error) {
	if len(raw) == 0 || !rePH.Match(raw) {
		return raw, nil
	}
	var d any
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	var walk func(v any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			if restored != nil {
				r.mu.Lock()
				for _, ph := range rePH.FindAllString(x, -1) {
					if v, ok := r.fromPH[ph]; ok {
						restored[v] = ph
					}
				}
				r.mu.Unlock()
			}
			return r.restore(x)
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case map[string]any:
			for k := range x {
				x[k] = walk(x[k])
			}
		}
		return v
	}
	return json.Marshal(walk(d))
}
