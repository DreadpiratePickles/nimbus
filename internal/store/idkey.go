package store

// Keyed Issue ids (W5-ISSUES / Verification 5 MCP-1).
//
// An Issue id used to be hex(sha256(kind|canonical|resource)[:16]) (path Issues:
// sha256(kind|entry|anchor|rule), secondary keys sha256(entry|rule|hops)). Shown next to a
// redacted ARN (MCP, copilot), that is an offline oracle: hashing candidate ARNs over an account
// range gives the account back. Stored ids are now
//
//	KeyID(digest) = hex(HMAC-SHA256(key, "nimbus/issue-id/v1\x00" || digest)[:16])
//
// where digest is the old unkeyed value (model.PathIssueID, model.PathSecondaryKey,
// legacyIssueDigest) and key is 32 random bytes created once per database by migration 10 and
// kept in store_meta. Ids are stable within a database (same key), differ across databases, and
// cannot be reproduced without the key. The digest stays an in-process grouping key (attackpath
// grouping, pathdiff, tie-breaks) and is never stored or surfaced by a store-backed output.
//
// Migration 10 maps every stored id and secondary key old → KeyID(old) in place (issues,
// path_issue_history, issue_verifications, issue_score_history) and records old → new in
// issue_id_map so an id quoted before the upgrade (a ticket body, a runbook) still resolves
// (ResolveIssueID). store_meta and issue_id_map are excluded from untrusted SQL (readonly.go):
// the map holds the old unkeyed ids, which are the oracle.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const (
	idKeyName   = "issue_id_key"
	idKeyDomain = "nimbus/issue-id/v1\x00"
)

// internalTables are never queryable by untrusted SQL (and never listed by /api/schema).
var internalTables = map[string]bool{"store_meta": true, "issue_id_map": true}

func legacyIssueDigest(kind, canonical, resource string) string {
	sum := sha256.Sum256([]byte(kind + "|" + canonical + "|" + resource))
	return hex.EncodeToString(sum[:16])
}

func keyID(key []byte, digest string) string {
	if len(key) == 0 || digest == "" {
		return digest
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(idKeyDomain))
	m.Write([]byte(digest))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// KeyID maps an unkeyed identity digest (model.PathIssueID, model.PathSecondaryKey) to this
// database's keyed id. Callers that match in-memory paths against stored Issues use it (or
// PathIssueIDOf); the result is what Issues() returns.
func (s *Store) KeyID(digest string) string {
	if s == nil {
		return digest
	}
	return keyID(s.idKey, digest)
}

// PathIssueIDOf is the stored id of p's path Issue in this database.
func (s *Store) PathIssueIDOf(p model.AttackPath) string {
	e, a, r := model.PathIssueKey(p)
	return s.KeyID(model.PathIssueID(model.IssuePath, e, a, r))
}

// PathSecondaryKeyOf is the stored secondary key of p in this database.
func (s *Store) PathSecondaryKeyOf(p model.AttackPath) string {
	return s.KeyID(model.PathSecondaryKey(p))
}

// ResolveIssueID returns the current id of id: id itself, or the keyed id an id from before
// migration 10 was mapped to. Unknown ids are returned unchanged.
func (s *Store) ResolveIssueID(id string) string {
	if s == nil {
		return id
	}
	var n int
	if s.db.QueryRow("SELECT COUNT(*) FROM issues WHERE id = ?", id).Scan(&n) == nil && n > 0 {
		return id
	}
	var nid string
	if s.db.QueryRow("SELECT new_id FROM issue_id_map WHERE old_id = ?", id).Scan(&nid) == nil {
		return nid
	}
	return id
}

func loadIDKey(db *sql.DB) ([]byte, error) {
	var k []byte
	if err := db.QueryRow("SELECT v FROM store_meta WHERE k = ?", idKeyName).Scan(&k); err != nil {
		return nil, fmt.Errorf("issue id key: %w", err)
	}
	if len(k) != 32 {
		return nil, errors.New("issue id key: corrupt (want 32 bytes)")
	}
	return k, nil
}

// migrateKeyedIssueIDs is migration 10: create the key, re-key every stored id in place.
func migrateKeyedIssueIDs(tx *sql.Tx) error {
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS store_meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS issue_id_map (old_id TEXT PRIMARY KEY, new_id TEXT NOT NULL);`); err != nil {
		return err
	}
	var key []byte
	if err := tx.QueryRow("SELECT v FROM store_meta WHERE k = ?", idKeyName).Scan(&key); errors.Is(err, sql.ErrNoRows) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO store_meta (k, v) VALUES (?, ?)", idKeyName, key); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	k := func(d string) string { return keyID(key, d) }

	type row struct{ id, skey, skeys string }
	rows, err := tx.Query("SELECT id, COALESCE(secondary_key,''), COALESCE(secondary_keys,'') FROM issues")
	if err != nil {
		return err
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.skey, &r.skeys); err != nil {
			rows.Close()
			return err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range all {
		nid := k(r.id)
		var keys []string
		skeys := r.skeys
		if r.skeys != "" && json.Unmarshal([]byte(r.skeys), &keys) == nil {
			for i := range keys {
				keys[i] = k(keys[i])
			}
			b, _ := json.Marshal(keys)
			skeys = string(b)
		}
		if _, err := tx.Exec("UPDATE issues SET id = ?, secondary_key = NULLIF(?,''), secondary_keys = NULLIF(?,'') WHERE id = ?", nid, k(r.skey), skeys, r.id); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT OR REPLACE INTO issue_id_map (old_id, new_id) VALUES (?, ?)", r.id, nid); err != nil {
			return err
		}
	}
	// Child tables: every distinct id (also history of Issues no longer stored) and secondary key.
	for _, c := range []struct{ table, col string }{
		{"path_issue_history", "issue_id"}, {"path_issue_history", "secondary_key"},
		{"issue_verifications", "issue_id"}, {"issue_score_history", "issue_id"},
	} {
		var exists int
		if err := tx.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?", c.table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		vrows, err := tx.Query(fmt.Sprintf("SELECT DISTINCT %s FROM %s WHERE %s IS NOT NULL AND %s != ''", c.col, c.table, c.col, c.col))
		if err != nil {
			return err
		}
		var vals []string
		for vrows.Next() {
			var v string
			if err := vrows.Scan(&v); err != nil {
				vrows.Close()
				return err
			}
			vals = append(vals, v)
		}
		vrows.Close()
		for _, v := range vals {
			if _, err := tx.Exec(fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?", c.table, c.col, c.col), k(v), v); err != nil {
				return err
			}
			if c.col == "issue_id" {
				if _, err := tx.Exec("INSERT OR IGNORE INTO issue_id_map (old_id, new_id) VALUES (?, ?)", v, k(v)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
