package iac

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Parser limits (Verification 2 defect 2). hclsyntax and hclwrite parse recursively: 70,000 nested
// brackets (140 KB) exhaust the 1 GB goroutine stack, which is a fatal error that recover() cannot
// catch. Every parse of untrusted Terraform therefore runs checkParseLimits first; a file over a
// limit becomes an ERROR finding instead of crashing the scan.
const (
	DefaultMaxFileBytes = 2 << 20 // 2 MiB
	DefaultMaxDepth     = 256
)

// Limits bounds what the HCL parsers are given. Zero fields mean the default.
type Limits struct {
	MaxFileBytes int
	MaxDepth     int
}

// EnvMaxFileBytes overrides the file-size limit (bytes) for a process.
const EnvMaxFileBytes = "CLOUD_POSTURE_IAC_MAX_FILE_BYTES"

var (
	limitsMu sync.RWMutex
	limits   = defaultLimits()
)

func defaultLimits() Limits {
	l := Limits{MaxFileBytes: DefaultMaxFileBytes, MaxDepth: DefaultMaxDepth}
	if v, err := strconv.Atoi(os.Getenv(EnvMaxFileBytes)); err == nil && v > 0 {
		l.MaxFileBytes = v
	}
	return l
}

// SetLimits replaces the parser limits and returns the previous ones (zero fields → defaults).
func SetLimits(l Limits) Limits {
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = DefaultMaxFileBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}
	limitsMu.Lock()
	defer limitsMu.Unlock()
	old := limits
	limits = l
	return old
}

func currentLimits() Limits {
	limitsMu.RLock()
	defer limitsMu.RUnlock()
	return limits
}

// parseLimitSummary marks the diagnostic produced by checkParseLimits.
const parseLimitSummary = "input exceeds parser limits"

// LimitError reports a file the parsers were not given.
type LimitError struct {
	File   string
	Reason string
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("%s: %s; not parsed", e.File, e.Reason)
}

// checkParseLimits rejects input the recursive HCL parsers cannot safely handle: files over the
// size limit, files whose parser recursion depth exceeds MaxDepth, and expressions whose operator
// or traversal chain exceeds MaxDepth (the parser builds those iteratively, but every walk and
// evaluation of the resulting left-nested tree recurses once per link).
func checkParseLimits(src []byte, file string) error {
	l := currentLimits()
	if len(src) > l.MaxFileBytes {
		return &LimitError{File: file, Reason: fmt.Sprintf("file size %d bytes exceeds the %d-byte limit (%s)", len(src), l.MaxFileBytes, EnvMaxFileBytes)}
	}
	m := measureNesting(src, l.MaxDepth)
	if m.depth > l.MaxDepth {
		return &LimitError{File: file, Reason: fmt.Sprintf("nesting depth exceeds the limit of %d", l.MaxDepth)}
	}
	if m.chain > l.MaxDepth {
		return &LimitError{File: file, Reason: fmt.Sprintf("nesting of an operator/index/attribute chain exceeds the limit of %d", l.MaxDepth)}
	}
	return nil
}

func limitDiag(err error, file string) hcl.Diagnostics {
	return hcl.Diagnostics{{Severity: hcl.DiagError, Summary: parseLimitSummary, Detail: err.Error(), Subject: &hcl.Range{Filename: file, Start: hcl.Pos{Line: 1, Column: 1}, End: hcl.Pos{Line: 1, Column: 1}}}}
}

// nestingDepth returns the parser recursion depth measureNesting computes.
func nestingDepth(src []byte, stop int) int { return measureNesting(src, stop).depth }

// guardMeasure is what the pre-parse guard measured: depth bounds the recursion of the hclsyntax
// parser, chain the longest operator/traversal chain of one expression.
type guardMeasure struct{ depth, chain int }

// guardLevel is one open bracket of the token stream (index 0 is the file body).
type guardLevel struct {
	open         hclsyntax.TokenType
	newlineEnds  bool // a newline ends the expression here (bodies and object constructors)
	seen         bool // a significant token was seen at this level
	cond         int  // `?` of the current expression: each nests the rest of the expression
	held         int  // unary operators and [*] splats the current term holds on the stack
	chain        int  // binary operators and traversal steps of the current expression
	afterOperand bool // the current term has an operand (so `-` is binary, `[` an index)
	afterDot     bool // the previous token was a traversal `.`
	index        bool // this level is an index `[ ]` that follows an operand
	onlyStar     int  // for an index: 1 while its only token is `*`, -1 once anything else is seen
}

var guardClosers = map[hclsyntax.TokenType]hclsyntax.TokenType{
	hclsyntax.TokenOBrace: hclsyntax.TokenCBrace, hclsyntax.TokenOBrack: hclsyntax.TokenCBrack,
	hclsyntax.TokenOParen: hclsyntax.TokenCParen, hclsyntax.TokenOQuote: hclsyntax.TokenCQuote,
	hclsyntax.TokenOHeredoc: hclsyntax.TokenCHeredoc, hclsyntax.TokenTemplateInterp: hclsyntax.TokenTemplateSeqEnd,
	hclsyntax.TokenTemplateControl: hclsyntax.TokenTemplateSeqEnd,
}

var guardBinaryOps = map[hclsyntax.TokenType]bool{
	hclsyntax.TokenPlus: true, hclsyntax.TokenStar: true, hclsyntax.TokenSlash: true, hclsyntax.TokenPercent: true,
	hclsyntax.TokenEqualOp: true, hclsyntax.TokenNotEqual: true, hclsyntax.TokenLessThan: true, hclsyntax.TokenLessThanEq: true,
	hclsyntax.TokenGreaterThan: true, hclsyntax.TokenGreaterThanEq: true, hclsyntax.TokenAnd: true, hclsyntax.TokenOr: true,
}

// measureNesting bounds, on the token stream (the lexer is a non-recursive state machine), the
// recursion the hclsyntax parser would need for src, stopping early once either measure exceeds
// stop. It models every construct the parser recurses on (Verification 3 defect 1):
//   - brackets, braces, parentheses, quoted and heredoc templates, ${ } and %{ } sequences
//     (one level each; %{ if }/%{ for } directives also nest the template parser);
//   - unary ! and - (parseExpressionTerm recurses once per operator, and its operand includes the
//     whole traversal chain), however they are separated: newlines and comments are skipped
//     inside brackets, so they never end a run;
//   - full splats [*] (parseExpressionTraversals recurses once per splat for the rest of the
//     chain, across nested index brackets);
//   - ?: conditionals (each `?` nests the rest of the expression until a comma or a newline that
//     ends the expression; `for` expressions in braces are newline-insensitive).
//
// A term's held unary/splat frames stay counted while any bracket opened inside it is open, so
// the measure is the sum over all open levels. Binary operators and index/attribute steps are
// parsed iteratively but produce a left-nested tree, so their run length is measured as chain.
func measureNesting(src []byte, stop int) guardMeasure {
	g := newGuardState(stop)
	pos, w := 0, guardWindow
	for {
		end := pos + w
		final := end >= len(src)
		if final {
			end = len(src)
		}
		toks, _ := hclsyntax.LexConfig(src[pos:end], "", hcl.Pos{Line: 1, Column: 1})
		limit := end - pos
		if !final {
			limit -= guardMargin
		}
		// Pass 1 on a copy: exceedance (exact: every token before limit is what the full lex
		// produces) and the last token boundary where a fresh lexer may restart.
		probe := g.clone()
		restart := -1
		for i, t := range toks {
			if t.Type == hclsyntax.TokenEOF {
				break
			}
			if !final && (t.Range.End.Byte > limit || unterminatedBlockComment(toks, i)) {
				break
			}
			if probe.feed(t) {
				return probe.m
			}
			if probe.templateFree() {
				restart = i
			}
		}
		if final {
			return probe.m
		}
		if restart < 0 || toks[restart].Range.End.Byte == 0 {
			w *= 2 // inside one template the whole window (or no progress): widen it
			continue
		}
		// Pass 2: commit up to the restart point; the next window lexes from there.
		for _, t := range toks[:restart+1] {
			g.feed(t)
		}
		pos += toks[restart].Range.End.Byte
		w = guardWindow
	}
}

// The guard lexes the file in windows (verify-4: lexing a whole 2 MiB file of one-byte tokens
// allocated over 1 GB at once). A window is lexed as if it were the file; its tokens that end
// at least guardMargin bytes before the cut are exactly the full lex's (the lexer's look-ahead
// past a finished token is a few bytes, except an unterminated /* comment, which shows as an
// adjacent / * pair and stops the trusted region). The next window restarts the lexer at the
// last trusted token boundary where it is in plain configuration mode (no quoted / heredoc
// template or ${ } / %{ } sequence open): there the lexer's state is its initial state (its
// brace counter only matters relative to an open template), so the token stream, and hence the
// measure, is identical to a single full lex. A window entirely inside a template is widened.
var (
	guardWindow = 32 << 10
	guardMargin = 4 << 10
)

// unterminatedBlockComment: toks[i] is the `/` of a `/*` that the window lexed as code because
// its `*/` lies beyond the cut.
func unterminatedBlockComment(toks hclsyntax.Tokens, i int) bool {
	return toks[i].Type == hclsyntax.TokenSlash && i+1 < len(toks) && toks[i+1].Type == hclsyntax.TokenStar &&
		toks[i+1].Range.Start.Byte == toks[i].Range.End.Byte
}

// guardState is measureNesting's state between tokens.
type guardState struct {
	stop         int
	stack        []guardLevel
	sum          int // Σ over the stack of (1 + cond + held), excluding the body level's own 1
	directives   int // open %{ if }/%{ for } template directives
	afterControl bool
	m            guardMeasure
}

func newGuardState(stop int) *guardState {
	return &guardState{stop: stop, stack: []guardLevel{{newlineEnds: true}}}
}

func (g *guardState) clone() *guardState {
	c := *g
	c.stack = append([]guardLevel(nil), g.stack...)
	return &c
}

// templateFree: no quoted/heredoc template or template sequence is open, so the lexer is in
// configuration mode with an empty mode stack.
func (g *guardState) templateFree() bool {
	for _, l := range g.stack {
		switch l.open {
		case hclsyntax.TokenOQuote, hclsyntax.TokenOHeredoc, hclsyntax.TokenTemplateInterp, hclsyntax.TokenTemplateControl:
			return false
		}
	}
	return !g.afterControl
}

func (g *guardState) termEnd(l *guardLevel) {
	g.sum -= l.held
	l.held = 0
	l.afterOperand, l.afterDot = false, false
}

// feed advances the measure by one token and reports whether a limit is exceeded.
func (g *guardState) feed(t hclsyntax.Token) bool {
	if t.Type == hclsyntax.TokenComment {
		return false
	}
	top := &g.stack[len(g.stack)-1]
	if t.Type == hclsyntax.TokenNewline {
		if top.newlineEnds && top.seen {
			g.termEnd(top)
			g.sum -= top.cond
			top.cond, top.chain = 0, 0
		}
		return false
	}
	if g.afterControl && t.Type == hclsyntax.TokenIdent {
		switch string(t.Bytes) {
		case "if", "for":
			g.directives++
		case "endif", "endfor":
			if g.directives > 0 {
				g.directives--
			}
		}
	}
	g.afterControl = t.Type == hclsyntax.TokenTemplateControl
	if top.index {
		if t.Type == hclsyntax.TokenStar && top.onlyStar == 0 {
			top.onlyStar = 1
		} else if t.Type != guardClosers[top.open] {
			top.onlyStar = -1
		}
	}
	if !top.seen && top.open == hclsyntax.TokenOBrace && t.Type == hclsyntax.TokenIdent && string(t.Bytes) == "for" {
		top.newlineEnds = false // for expressions are newline-insensitive
	}
	top.seen = true

	if _, isOpener := guardClosers[t.Type]; isOpener {
		child := guardLevel{open: t.Type, newlineEnds: t.Type == hclsyntax.TokenOBrace}
		if top.afterOperand && t.Type == hclsyntax.TokenOBrack {
			child.index = true
			top.chain++
		}
		top.afterDot = false
		g.stack = append(g.stack, child)
		g.sum++
	} else if len(g.stack) > 1 && t.Type == guardClosers[top.open] {
		child := *top
		g.stack = g.stack[:len(g.stack)-1]
		g.sum -= 1 + child.cond + child.held
		parent := &g.stack[len(g.stack)-1]
		if child.index && child.onlyStar == 1 {
			parent.held++ // a full splat: the rest of the traversal chain recurses
			g.sum++
		}
		parent.afterOperand, parent.afterDot = true, false
	} else {
		switch t.Type {
		case hclsyntax.TokenBang:
			if top.afterOperand {
				g.termEnd(top)
			}
			top.held++
			g.sum++
		case hclsyntax.TokenMinus:
			if top.afterOperand { // binary minus
				g.termEnd(top)
				top.chain++
			} else { // unary minus
				top.held++
				g.sum++
			}
		case hclsyntax.TokenDot:
			if top.afterOperand {
				top.chain++
				top.afterDot = true
			} else {
				g.termEnd(top)
			}
		case hclsyntax.TokenIdent, hclsyntax.TokenNumberLit, hclsyntax.TokenStar:
			switch {
			case top.afterDot:
				top.afterDot = false // attribute, legacy index or attribute-only splat
			case t.Type == hclsyntax.TokenStar:
				g.termEnd(top) // multiplication
				top.chain++
			case top.afterOperand:
				g.termEnd(top) // a keyword (in, if, for) or a syntax error: a new term starts
				top.afterOperand = true
			default:
				top.afterOperand = true
			}
		case hclsyntax.TokenQuestion:
			g.termEnd(top)
			top.cond++
			top.chain = 0
			g.sum++
		case hclsyntax.TokenComma:
			g.termEnd(top)
			g.sum -= top.cond
			top.cond, top.chain = 0, 0
		case hclsyntax.TokenColon, hclsyntax.TokenEqual, hclsyntax.TokenFatArrow, hclsyntax.TokenEllipsis:
			g.termEnd(top)
			top.chain = 0
		default:
			if guardBinaryOps[t.Type] {
				g.termEnd(top)
				top.chain++
			} else if t.Type != hclsyntax.TokenQuotedLit && t.Type != hclsyntax.TokenStringLit {
				g.termEnd(top) // anything else ends the term (closers that do not match, invalid tokens)
			}
		}
	}
	top = &g.stack[len(g.stack)-1]
	if top.chain > g.m.chain {
		g.m.chain = top.chain
	}
	if d := g.sum + g.directives; d > g.m.depth {
		g.m.depth = d
	}
	return g.m.depth > g.stop || g.m.chain > g.stop
}

// parseConfig is hclsyntax.ParseConfig behind checkParseLimits. Every parse of a Terraform file in
// this package goes through it.
func parseConfig(src []byte, file string) (*hcl.File, hcl.Diagnostics) {
	if err := checkParseLimits(src, file); err != nil {
		return nil, limitDiag(err, file)
	}
	return hclsyntax.ParseConfig(src, file, hcl.Pos{Line: 1, Column: 1})
}
