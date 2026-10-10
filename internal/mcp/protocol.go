package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// JSON-RPC 2.0 error codes (codeNotInitialized is in the implementation-defined server range).
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	codeNotInitialized = -32002
)

// LatestProtocolVersion is offered when the client asks for a version this server does not know.
const LatestProtocolVersion = "2025-11-25"

var supportedVersions = map[string]bool{"2025-11-25": true, "2025-06-18": true, "2025-03-26": true, "2024-11-05": true}

// maxLineBytes bounds one inbound message.
const maxLineBytes = 4 << 20

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (r *request) isNotification() bool { return len(r.ID) == 0 }

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

var errLineTooLong = errors.New("message exceeds the 4 MiB limit")

// readLine returns one newline-terminated message without the newline. An overlong line is
// consumed and reported as errLineTooLong so the stream stays in sync.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > maxLineBytes {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err == io.EOF && (len(buf) > 0 || tooLong) {
				break
			}
			return nil, err
		}
		break
	}
	if tooLong {
		return nil, errLineTooLong
	}
	return bytes.TrimRight(buf, "\r\n"), nil
}

// encodeFrame marshals v as one line. encoding/json already escapes <, >, &, U+2028 and
// U+2029; escapeFormatRunes additionally escapes every Unicode format (Cf) rune, which can
// only occur inside JSON strings, so the frame decodes to the same value.
func encodeFrame(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(escapeFormatRunes(b), '\n'), nil
}

func escapeFormatRunes(b []byte) []byte {
	clean := true
	for i := 0; i < len(b); {
		r, n := utf8.DecodeRune(b[i:])
		if r >= 0x80 && unicode.Is(unicode.Cf, r) {
			clean = false
			break
		}
		i += n
	}
	if clean {
		return b
	}
	out := make([]byte, 0, len(b)+32)
	for i := 0; i < len(b); {
		r, n := utf8.DecodeRune(b[i:])
		if r >= 0x80 && unicode.Is(unicode.Cf, r) {
			if r > 0xFFFF {
				r1, r2 := utf16.EncodeRune(r)
				out = appendU(appendU(out, r1), r2)
			} else {
				out = appendU(out, r)
			}
		} else {
			out = append(out, b[i:i+n]...)
		}
		i += n
	}
	return out
}

func appendU(out []byte, r rune) []byte {
	h := strconv.FormatInt(int64(r), 16)
	for len(h) < 4 {
		h = "0" + h
	}
	return append(append(out, '\\', 'u'), h...)
}
