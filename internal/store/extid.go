package store

// Keyed external ids for findings and attack paths (W6-VERIFY r4 #15, Verification 6).
//
// A finding id is model.Finding.Fingerprint(): hex(sha256(source|check|provider|account|region|
// resource|file)[:16]); an attack path id is hex(sha256(entry|hops)[:8]). Shown next to a
// redacted account (MCP), either is an offline oracle: Verification 6 recovered the account of
// an S3 finding in 0.7 s by hashing a million candidate accounts. Stored ids stay as they are
// (stable across scans, shared with the Python layer and every adapter); what leaves through
// MCP and the HTTP API is
//
//	ExternalID(raw) = hex(HMAC-SHA256(key, domain || raw)[:len(raw)/2])
//
// with the per-database key of the Issue ids (idkey.go) and a domain per kind, so it has the
// raw id's length, is stable within a database and cannot be reproduced without the key. Only
// digest-shaped ids (32 or 16 lower-case hex characters) are keyed; a native id such as
// "lab-W01" is no hash and is shown as is. ResolveFindingID accepts the external id and — with
// the semantics of ResolveIssueID — an old raw fingerprint (a ticket body, a runbook).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sync"
	"time"
)

const (
	findingIDDomain = "nimbus/finding-id/v1\x00"
	pathIDDomain    = "nimbus/path-id/v1\x00"
)

var reDigestToken = regexp.MustCompile(`\b[0-9a-f]{16}(?:[0-9a-f]{16})?\b`)

// IsDigestID reports an id shaped like a fingerprint (32 hex) or a path id (16 hex).
func IsDigestID(id string) bool {
	if len(id) != 32 && len(id) != 16 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func extID(key []byte, domain, raw string) string {
	if len(key) == 0 || !IsDigestID(raw) {
		return raw
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(domain))
	m.Write([]byte(raw))
	return hex.EncodeToString(m.Sum(nil))[:len(raw)]
}

// ExternalFindingID is the id a finding is shown under outside the store (MCP, API).
func (s *Store) ExternalFindingID(raw string) string {
	if s == nil {
		return raw
	}
	return extID(s.idKey, findingIDDomain, raw)
}

// ExternalPathID is the id an attack path is shown under outside the store.
func (s *Store) ExternalPathID(raw string) string {
	if s == nil {
		return raw
	}
	return extID(s.idKey, pathIDDomain, raw)
}

// ResolveFindingID maps an inbound finding id to the stored one: an external (keyed) id, or a
// stored id itself (an old raw fingerprint keeps resolving, like ResolveIssueID). ok=false for
// an unknown id.
func (s *Store) ResolveFindingID(id string) (string, bool) {
	var n int
	if s.db.QueryRow("SELECT COUNT(*) FROM findings WHERE id = ?", id).Scan(&n) == nil && n > 0 {
		return id, true
	}
	m, err := s.IDMapper()
	if err != nil {
		return id, false
	}
	if raw, ok := m.Raw(id); ok && m.kind[raw] == kindFinding {
		return raw, true
	}
	return id, false
}

const (
	kindFinding = 1
	kindPath    = 2
)

// IDMapper translates between stored digest ids (findings, attack paths) and their external
// keyed form. It reloads the id set when it meets an unknown digest and the stored id set has
// changed since the last load (no time window: Verification 7 defect 3), so a long MCP session
// also keys the findings of a later scan, even one committed a millisecond ago.
type IDMapper struct {
	st     *Store
	mu     sync.Mutex
	toExt  map[string]string // raw -> external
	toRaw  map[string]string // external -> raw
	kind   map[string]int    // raw -> kind
	loaded time.Time
}

// IDMapper returns a mapper over the current findings and attack paths.
func (s *Store) IDMapper() (*IDMapper, error) {
	m := &IDMapper{st: s}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m, m.reloadLocked()
}

// idSources are every stored place an exposed digest id comes from. Issue rows are a source of
// their own (Verification 7 defect 2): a resolved path Issue keeps path ids whose attack_paths
// row is gone, and they must be keyed all the same.
var idSources = []struct {
	sql  string
	kind int
}{
	{"SELECT id FROM findings", kindFinding},
	{"SELECT id FROM attack_paths", kindPath},
	{"SELECT DISTINCT j.value FROM issues, json_each(issues.path_ids) j WHERE json_valid(issues.path_ids)", kindPath},
	{"SELECT DISTINCT j.value FROM issues, json_each(issues.finding_ids) j WHERE json_valid(issues.finding_ids)", kindFinding},
}

// reloadLocked builds the new maps completely and only then swaps them in, so no reader ever
// sees a partial set (the mapper's mutex is held by the caller).
func (m *IDMapper) reloadLocked() error {
	toExt, toRaw, kind := map[string]string{}, map[string]string{}, map[string]int{}
	for _, q := range idSources {
		rows, err := m.st.db.Query(q.sql)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil || !IsDigestID(id) {
				continue
			}
			if _, seen := kind[id]; seen {
				continue
			}
			var ext string
			if q.kind == kindFinding {
				ext = m.st.ExternalFindingID(id)
			} else {
				ext = m.st.ExternalPathID(id)
			}
			toExt[id], toRaw[ext], kind[id] = ext, id, q.kind
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	m.toExt, m.toRaw, m.kind, m.loaded = toExt, toRaw, kind, time.Now()
	return nil
}

// lookupLocked classifies a digest the maps do not hold by asking the store directly (indexed
// lookups on findings / attack_paths, then the Issue id lists), and adds it when stored: no time
// window, so an id committed a millisecond ago is keyed too (Verification 7 defect 3).
// ok=false: the store could not be read; the caller fails closed.
func (m *IDMapper) lookupLocked(tok string) (kind int, ok bool) {
	var n int
	for _, q := range []struct {
		sql  string
		kind int
		args []any
	}{
		{"SELECT COUNT(*) FROM findings WHERE id = ?", kindFinding, []any{tok}},
		{"SELECT COUNT(*) FROM attack_paths WHERE id = ?", kindPath, []any{tok}},
		{"SELECT COUNT(*) FROM issues, json_each(issues.path_ids) j WHERE json_valid(issues.path_ids) AND instr(issues.path_ids, ?) > 0 AND j.value = ?", kindPath, []any{tok, tok}},
		{"SELECT COUNT(*) FROM issues, json_each(issues.finding_ids) j WHERE json_valid(issues.finding_ids) AND instr(issues.finding_ids, ?) > 0 AND j.value = ?", kindFinding, []any{tok, tok}},
	} {
		if err := m.st.db.QueryRow(q.sql, q.args...).Scan(&n); err != nil {
			return 0, false
		}
		if n > 0 {
			var ext string
			if q.kind == kindFinding {
				ext = m.st.ExternalFindingID(tok)
			} else {
				ext = m.st.ExternalPathID(tok)
			}
			m.toExt[tok], m.toRaw[ext], m.kind[tok] = ext, tok, q.kind
			return q.kind, true
		}
	}
	return 0, true
}

// idUnavailable replaces a digest the mapper cannot classify because the store could not be
// read: never the raw value (fail closed).
const idUnavailable = "[id-unavailable]"

// Ext is the external form of a stored id (unchanged when it is not a stored digest).
func (m *IDMapper) Ext(raw string) string {
	if m == nil {
		return raw
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.extLocked(raw)
}

func (m *IDMapper) extLocked(tok string) string {
	if e, ok := m.toExt[tok]; ok {
		return e
	}
	if _, isExt := m.toRaw[tok]; isExt {
		return tok
	}
	if !IsDigestID(tok) {
		return tok
	}
	if _, ok := m.lookupLocked(tok); !ok {
		return idUnavailable
	}
	if e, ok := m.toExt[tok]; ok {
		return e
	}
	return tok // not a stored id
}

// Raw maps an external id back to the stored id.
func (m *IDMapper) Raw(ext string) (string, bool) {
	if m == nil {
		return ext, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.toRaw[ext]; ok {
		return r, true
	}
	// An external id of an id stored after the last load: reload (the keyed form cannot be looked
	// up directly) — at most once a second, which can only delay a resolution, never leak.
	if time.Since(m.loaded) > time.Second && m.reloadLocked() == nil {
		if r, ok := m.toRaw[ext]; ok {
			return r, true
		}
	}
	return ext, false
}

// KeyPath keys an attack-path id whether or not it is stored (an ad-hoc graph query's paths).
func (m *IDMapper) KeyPath(raw string) string {
	if m == nil {
		return raw
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, isExt := m.toRaw[raw]; isExt {
		return raw
	}
	if e, ok := m.toExt[raw]; ok {
		return e
	}
	return m.st.ExternalPathID(raw)
}

// IsRaw reports a stored digest id (an inbound raw id in a session that must not accept one).
func (m *IDMapper) IsRaw(id string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.toExt[id]; ok {
		return true
	}
	if _, isExt := m.toRaw[id]; isExt || !IsDigestID(id) {
		return false
	}
	kind, ok := m.lookupLocked(id)
	return kind != 0 || !ok // unreadable store: treat as raw (refuse), fail closed
}

// MapString replaces every stored digest id inside s (also inside JSON text) by its external id.
func (m *IDMapper) MapString(s string) string {
	if m == nil || len(s) < 16 || !reDigestToken.MatchString(s) {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return reDigestToken.ReplaceAllStringFunc(s, m.extLocked)
}

// MapStringExcept is MapString that leaves the tokens in skip unchanged: text a client sent must
// never come back keyed, or the keyed echo confirms that the text is a stored id (an oracle).
func (m *IDMapper) MapStringExcept(s string, skip map[string]bool) string {
	if len(skip) == 0 {
		return m.MapString(s)
	}
	if m == nil || len(s) < 16 || !reDigestToken.MatchString(s) {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return reDigestToken.ReplaceAllStringFunc(s, func(tok string) string {
		if skip[tok] {
			return tok
		}
		return m.extLocked(tok)
	})
}

// MapValue maps every string (and map key) of a decoded JSON value in place and returns it.
func (m *IDMapper) MapValue(v any) any { return m.MapValueExcept(v, nil) }

// MapValueExcept is MapValue with MapStringExcept.
func (m *IDMapper) MapValueExcept(v any, skip map[string]bool) any {
	if m == nil {
		return v
	}
	switch x := v.(type) {
	case string:
		return m.MapStringExcept(x, skip)
	case []any:
		for i := range x {
			x[i] = m.MapValueExcept(x[i], skip)
		}
	case map[string]any:
		for k, vv := range x {
			nk := m.MapStringExcept(k, skip)
			if nk != k {
				delete(x, k)
			}
			x[nk] = m.MapValueExcept(vv, skip)
		}
	}
	return v
}

// MapJSON round-trips any Go value through JSON and maps it (API responses).
func (m *IDMapper) MapJSON(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var d any
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return m.MapValue(d), nil
}
