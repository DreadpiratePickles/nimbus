package output

// Ids in outputs written without a posture database (W6-VERIFY r4 #15).
//
// Store-backed surfaces (MCP, the HTTP API) show keyed ids (store/extid.go). An output written
// without a database has no per-database key, so it does one of two things:
//
//   - IDSchemeUnkeyed: the ids are the raw digests (finding fingerprints, path Issue ids) and the
//     output says so (SARIF run properties.nimbus_id_scheme). This is only acceptable where the
//     file already shows every identifier the digest is computed from (account, resource ARN),
//     so the digest reveals nothing more.
//   - IDSchemeRunKeyed: a redacted output (a PR comment on a public repository, a pathdiff with
//     topology redaction) must not carry a raw digest next to redacted names — the digest is an
//     offline oracle for them. RunKeyer keys ids with a random per-run secret, or with a
//     configured secret (NIMBUS_ID_KEY in CI) when ids must stay stable across runs for
//     alert continuity; ids carry a "run-" prefix so nobody mistakes them for store ids.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	IDSchemeUnkeyed  = "unkeyed"
	IDSchemeRunKeyed = "run-keyed"
)

// RunKeyer keys digest ids for one DB-less run.
type RunKeyer struct{ key []byte }

// NewRunKeyer uses key when given (≥ 16 bytes, e.g. from a CI secret), else 32 random bytes.
func NewRunKeyer(key []byte) *RunKeyer {
	if len(key) < 16 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}
	return &RunKeyer{key: append([]byte(nil), key...)}
}

// MinIDKeyBytes is the shortest configured id key accepted (NIMBUS_ID_KEY).
const MinIDKeyBytes = 16

// RunKeyerFromKey is the keyer for a configured key (NIMBUS_ID_KEY): empty means 32 random bytes
// (ids differ per run); a key shorter than MinIDKeyBytes is an error, never a silent random
// fallback (Verification 7 defect 10).
func RunKeyerFromKey(key string) (*RunKeyer, error) {
	if key == "" {
		return NewRunKeyer(nil), nil
	}
	if len(key) < MinIDKeyBytes {
		return nil, fmt.Errorf("NIMBUS_ID_KEY is %d bytes; it must be at least %d (or unset for per-run random ids)", len(key), MinIDKeyBytes)
	}
	return NewRunKeyer([]byte(key)), nil
}

// ID is "run-" + hex(HMAC-SHA256(key, "nimbus/run-id/v1\0" || id))[:32].
func (k *RunKeyer) ID(id string) string {
	if id == "" {
		return id
	}
	m := hmac.New(sha256.New, k.key)
	m.Write([]byte("nimbus/run-id/v1\x00"))
	m.Write([]byte(id))
	return "run-" + hex.EncodeToString(m.Sum(nil))[:32]
}

// Scheme names the id scheme for the output's metadata.
func (k *RunKeyer) Scheme() string { return IDSchemeRunKeyed }
