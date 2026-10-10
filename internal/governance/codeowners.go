package governance

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/config"
)

// CodeownersLocations are searched in GitHub's order; the first file found is used.
var CodeownersLocations = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

// Codeowners is a parsed GitHub CODEOWNERS file.
type Codeowners struct {
	Path   string            // file it was loaded from ("" when parsed from a reader)
	Errors []CodeownersError // lines GitHub would skip (they are skipped here too)
	rules  []coRule
}

// CodeownersError is one skipped line.
type CodeownersError struct {
	Line int    `json:"line"`
	Msg  string `json:"msg"`
}

func (e CodeownersError) Error() string { return fmt.Sprintf("CODEOWNERS line %d: %s", e.Line, e.Msg) }

// CodeownersMatch is the line that owns a path.
type CodeownersMatch struct {
	Line    int
	Pattern string
	Owners  []string // empty: the path is explicitly unowned
}

type coRule struct {
	line    int
	pattern string
	owners  []string
	re      *regexp.Regexp
}

var (
	coUserRe  = regexp.MustCompile(`^@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)
	coTeamRe  = regexp.MustCompile(`^@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9._-]+$`)
	coEmailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

func validCodeowner(o string) bool {
	return coUserRe.MatchString(o) || coTeamRe.MatchString(o) || coEmailRe.MatchString(o)
}

// ParseCodeowners parses GitHub CODEOWNERS syntax: "pattern owner..." per line, "#"
// comments (also after the owners), patterns with gitignore semantics (leading "/"
// or an inner "/" anchors to the repo root, otherwise the pattern matches at any
// depth; a trailing "/" matches directory contents; "*" stays in one segment, "**"
// crosses segments; "dir/*" does not match nested files). A pattern with no owners
// marks the path unowned. Lines GitHub rejects ("!" negation, "[ ]" ranges, "\#"
// escapes, invalid owners) are skipped and reported in Errors. Read errors are fatal.
func ParseCodeowners(r io.Reader) (*Codeowners, error) {
	co := &Codeowners{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		pattern := fields[0]
		var owners []string
		bad := ""
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "#") {
				break
			}
			if !validCodeowner(f) {
				bad = f
				break
			}
			owners = append(owners, f)
		}
		skip := func(msg string) { co.Errors = append(co.Errors, CodeownersError{Line: n, Msg: msg}) }
		switch {
		case bad != "":
			skip(fmt.Sprintf("invalid owner %q (want @user, @org/team or an email)", bad))
			continue
		case strings.HasPrefix(pattern, "!"):
			skip("negation (!) is not supported in CODEOWNERS")
			continue
		case strings.ContainsAny(pattern, "[]"):
			skip("character ranges ([ ]) are not supported in CODEOWNERS")
			continue
		case strings.HasPrefix(pattern, `\#`):
			skip(`escaping "#" with "\" is not supported in CODEOWNERS`)
			continue
		}
		re, err := compileCodeownersPattern(pattern)
		if err != nil {
			skip(err.Error())
			continue
		}
		co.rules = append(co.rules, coRule{line: n, pattern: pattern, owners: owners, re: re})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return co, nil
}

func compileCodeownersPattern(p string) (*regexp.Regexp, error) {
	dirOnly := strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")
	anchored := strings.HasPrefix(p, "/") || strings.Contains(p, "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	body, err := config.CompileGlob(p)
	if err != nil {
		return nil, err
	}
	expr := strings.TrimSuffix(strings.TrimPrefix(body.String(), "^"), "$")
	prefix := "^"
	if !anchored {
		prefix = "^(?:.*/)?"
	}
	var suffix string
	switch {
	case dirOnly:
		suffix = "/.*$"
	case strings.HasSuffix(p, "/*") || p == "*" && anchored:
		suffix = "$" // GitHub: "docs/*" matches docs/x but not docs/a/x
	default:
		suffix = "(?:/.*)?$"
	}
	return regexp.Compile(prefix + expr + suffix)
}

// Match returns the last line whose pattern matches path (repo-relative, any
// separator, leading "./" or "/" ignored). ok is false when nothing matches.
func (c *Codeowners) Match(path string) (CodeownersMatch, bool) {
	if c == nil {
		return CodeownersMatch{}, false
	}
	p := config.CleanRepoPath(path)
	if p == "" {
		return CodeownersMatch{}, false
	}
	for i := len(c.rules) - 1; i >= 0; i-- {
		r := c.rules[i]
		if r.re.MatchString(p) {
			return CodeownersMatch{Line: r.line, Pattern: r.pattern, Owners: append([]string(nil), r.owners...)}, true
		}
	}
	return CodeownersMatch{}, false
}

// LoadCodeowners reads explicit (relative to repoRoot unless absolute) or, when
// explicit is "", the first of CodeownersLocations under repoRoot. It returns
// (nil, nil) when no file exists and explicit is "".
func LoadCodeowners(repoRoot, explicit string) (*Codeowners, error) {
	try := CodeownersLocations
	if explicit != "" {
		try = []string{explicit}
	}
	for _, rel := range try {
		p := rel
		if !filepath.IsAbs(p) {
			p = filepath.Join(repoRoot, filepath.FromSlash(rel))
		}
		f, err := os.Open(p)
		if err != nil {
			if os.IsNotExist(err) && explicit == "" {
				continue
			}
			return nil, err
		}
		co, err := ParseCodeowners(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		co.Path = p
		return co, nil
	}
	return nil, nil
}
