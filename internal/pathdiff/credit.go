package pathdiff

import (
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Lowers reports a de-escalation (competitive delta 2026-10-09 r2, shortfall #14): a path Issue
// present before and after whose band drops (High → Low, Critical → High, Medium → Low, …).
// A move inside one band is a score change only. A lowered path is credit, never a gate trip.
func Lowers(before, after float64) bool {
	return bandRank[model.ScoreBand(after)] < bandRank[model.ScoreBand(before)]
}

// Lowered are the ChangedScore entries whose band drops (Lowers): the paths a fixing PR makes
// less exploitable without closing them. They belong in the headline ("lowers L") and the
// `nimbus-lowers-paths` footer; GateCount never counts them.
func (r Result) Lowered() []ScoreChange {
	var out []ScoreChange
	for _, c := range r.ChangedScore {
		if Lowers(c.Before, c.After) {
			out = append(out, c)
		}
	}
	return out
}

// Hunk is one contiguous line range of a file (1-based, inclusive, in the original) and the
// lines that replace it: the shape of a GitHub ```suggestion on start_line..line.
type Hunk struct {
	Start int      `json:"start"`
	End   int      `json:"end"`
	Lines []string `json:"lines"`
}

// hunkGap is the run of unchanged lines that separates two hunks (a unified diff with 3 lines
// of context merges hunks closer than 2×3; a suggestion should not carry long unchanged runs).
const hunkGap = 3

// SingleHunk reports whether after differs from before in exactly one contiguous region of at
// most maxLines lines on either side, and returns it. A pure insertion is anchored to the line
// before it (or after it, at the top of the file), since a suggestion replaces at least one line.
func SingleHunk(before, after string, maxLines int) (Hunk, bool) {
	b, a := strings.Split(before, "\n"), strings.Split(after, "\n")
	p := 0
	for p < len(b) && p < len(a) && b[p] == a[p] {
		p++
	}
	if p == len(b) && p == len(a) {
		return Hunk{}, false
	}
	s := 0
	for s < len(b)-p && s < len(a)-p && b[len(b)-1-s] == a[len(a)-1-s] {
		s++
	}
	if len(b)-s == p { // pure insertion: anchor to a neighbouring line
		switch {
		case p > 0:
			p--
		case s > 0:
			s--
		default:
			return Hunk{}, false
		}
	}
	bm, am := b[p:len(b)-s], a[p:len(a)-s]
	if len(bm) > maxLines || len(am) > maxLines {
		return Hunk{}, false
	}
	if longestCommonRun(bm, am) > hunkGap {
		return Hunk{}, false
	}
	// A trailing "" from a final newline is not a line of the file.
	if p+len(bm) > lineCount(before) {
		return Hunk{}, false
	}
	return Hunk{Start: p + 1, End: p + len(bm), Lines: append([]string(nil), am...)}, true
}

func lineCount(s string) int {
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

// longestCommonRun is the longest run of consecutive unchanged lines inside the region, by an
// LCS alignment (regions are capped, so the table is small).
func longestCommonRun(b, a []string) int {
	n, m := len(b), len(a)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case b[i] == a[j]:
				dp[i][j] = dp[i+1][j+1] + 1
			case dp[i+1][j] >= dp[i][j+1]:
				dp[i][j] = dp[i+1][j]
			default:
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	best, run := 0, 0
	for i, j := 0, 0; i < n && j < m; {
		switch {
		case b[i] == a[j] && dp[i][j] == dp[i+1][j+1]+1:
			run++
			if run > best {
				best = run
			}
			i, j = i+1, j+1
		case dp[i+1][j] >= dp[i][j+1]:
			run = 0
			i++
		default:
			run = 0
			j++
		}
	}
	return best
}

// Fence is the backtick fence for a Markdown code block holding content verbatim: one backtick
// longer than the longest backtick run in content (at least three), so no line of content can
// close it. Tilde runs cannot close a backtick fence.
func Fence(content string) string {
	longest, run := 0, 0
	for _, r := range content {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	n := longest + 1
	if n < 3 {
		n = 3
	}
	return strings.Repeat("`", n)
}

// hunksMaxCells bounds the LCS table of the changed middle region (after the common prefix and
// suffix are trimmed): a patch is a few lines, so a larger region is refused, not diffed.
const hunksMaxCells = 4 << 20

// Hunks splits the change from before to after into the hunks a GitHub review would show: runs
// of changed lines separated by more than hunkGap unchanged lines are separate hunks; closer
// runs merge (carrying the unchanged lines between them). Each hunk is a suggestion on
// Start..End of before (1-based, inclusive). A pure insertion is anchored to the line before it
// (or after it, at the top of the file). It refuses (false) when nothing changed, when any hunk
// exceeds maxLines on either side, or when the change touches the end of a file without a final
// newline: a partial fix is never offered.
func Hunks(before, after string, maxLines int) ([]Hunk, bool) {
	total := lineCount(before)
	if strings.HasSuffix(before, "\n") && strings.HasSuffix(after, "\n") {
		// both end with a newline: it is not a line of either file
		before, after = before[:len(before)-1], after[:len(after)-1]
	}
	b, a := strings.Split(before, "\n"), strings.Split(after, "\n")
	p := 0
	for p < len(b) && p < len(a) && b[p] == a[p] {
		p++
	}
	if p == len(b) && p == len(a) {
		return nil, false
	}
	s := 0
	for s < len(b)-p && s < len(a)-p && b[len(b)-1-s] == a[len(a)-1-s] {
		s++
	}
	bm, am := b[p:len(b)-s], a[p:len(a)-s]
	if (len(bm)+1)*(len(am)+1) > hunksMaxCells {
		return nil, false
	}
	// LCS alignment of the middle region: eq[i] is the index in am that bm[i] keeps (-1: deleted).
	n, m := len(bm), len(am)
	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case bm[i] == am[j]:
				dp[i][j] = dp[i+1][j+1] + 1
			case dp[i+1][j] >= dp[i][j+1]:
				dp[i][j] = dp[i+1][j]
			default:
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	// regions: [bi, bj) of b replaced by [ai, aj) of a (absolute indexes)
	type region struct{ bi, bj, ai, aj int }
	var regs []region
	i, j := 0, 0
	for i < n || j < m {
		if i < n && j < m && bm[i] == am[j] && dp[i][j] == dp[i+1][j+1]+1 {
			i, j = i+1, j+1
			continue
		}
		r := region{bi: p + i, ai: p + j}
		for i < n || j < m {
			if i < n && j < m && bm[i] == am[j] && dp[i][j] == dp[i+1][j+1]+1 {
				break
			}
			if j >= m || (i < n && dp[i+1][j] >= dp[i][j+1]) {
				i++
			} else {
				j++
			}
		}
		r.bj, r.aj = p+i, p+j
		regs = append(regs, r)
	}
	// slide pure insertions down past equal lines (as git's diff does), so an appended block
	// lands after the file's last line instead of splitting its closing braces
	for k := range regs {
		r := &regs[k]
		for r.bi == r.bj && r.aj < len(a) && r.bj < total && a[r.ai] == a[r.aj] && (k == len(regs)-1 || regs[k+1].bi > r.bj) {
			r.bi, r.bj, r.ai, r.aj = r.bi+1, r.bj+1, r.ai+1, r.aj+1
		}
	}
	// merge regions whose gap is at most hunkGap unchanged lines
	var merged []region
	for _, r := range regs {
		if k := len(merged) - 1; k >= 0 && r.bi-merged[k].bj <= hunkGap {
			merged[k].bj, merged[k].aj = r.bj, r.aj
			continue
		}
		merged = append(merged, r)
	}
	var out []Hunk
	for k, r := range merged {
		lines := append([]string(nil), a[r.ai:r.aj]...)
		start, end := r.bi, r.bj // [start, end) of b
		if start == end {        // pure insertion: anchor to a neighbouring unchanged line
			switch {
			case start > 0 && (k == 0 || merged[k-1].bj < start):
				start--
				lines = append([]string{b[start]}, lines...)
			case start < len(b) && (k == len(merged)-1 || merged[k+1].bi > start):
				lines = append(lines, b[start])
				end++
			default:
				return nil, false
			}
		}
		if end > total || end-start > maxLines || len(lines) > maxLines {
			return nil, false
		}
		out = append(out, Hunk{Start: start + 1, End: end, Lines: lines})
	}
	return out, len(out) > 0
}

// ApplyHunks applies hunks (from Hunks on before) to before: what committing every suggestion
// of a batch produces.
func ApplyHunks(before string, hs []Hunk) string {
	b := strings.Split(before, "\n")
	for k := len(hs) - 1; k >= 0; k-- {
		h := hs[k]
		if h.Start < 1 || h.End < h.Start-1 || h.End > len(b) {
			continue
		}
		nb := append([]string{}, b[:h.Start-1]...)
		nb = append(nb, h.Lines...)
		b = append(nb, b[h.End:]...)
	}
	return strings.Join(b, "\n")
}
