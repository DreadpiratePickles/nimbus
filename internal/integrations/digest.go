package integrations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/DreadpiratePickles/nimbus/internal/governance"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// DigestItem is one Issue as the governance digest sees it.
type DigestItem struct {
	IssueID    string         `json:"issue_id"`
	Title      string         `json:"title"`
	Severity   model.Severity `json:"severity"`
	State      string         `json:"state"`
	Provider   string         `json:"provider,omitempty"`
	Account    string         `json:"account,omitempty"`
	ResourceID string         `json:"resource_id,omitempty"`
	Owner      string         `json:"owner,omitempty"`
	DueAt      time.Time      `json:"due_at,omitempty"`
	ResolvedAt *time.Time     `json:"resolved_at,omitempty"`
	FixCommand string         `json:"fix_command,omitempty"`
}

// DigestItemFromIssue builds an item from an Issue, its governance assignment and
// an optional fix command.
func DigestItemFromIssue(is model.Issue, a governance.Assignment, fix string) DigestItem {
	title := is.Title
	if title == "" {
		title = is.CanonicalID
	}
	return DigestItem{IssueID: is.ID, Title: title, Severity: is.Severity, State: is.State, Provider: is.Provider,
		Account: is.Account, ResourceID: is.ResourceID, Owner: a.Owner, DueAt: a.DueAt, ResolvedAt: is.ResolvedAt, FixCommand: fix}
}

func (it DigestItem) overdue(now time.Time) bool {
	return model.IsActive(it.State) && !it.DueAt.IsZero() && now.After(it.DueAt)
}

// DigestOptions controls BuildDigests.
type DigestOptions struct {
	Now           time.Time
	Since         time.Time // start of the period ("newly resolved" means resolved in (Since, Now])
	GroupBy       string    // owner (default) | account
	MaxPerSection int       // items rendered per section (default 15); counts stay exact
}

// DigestCounts are the exact section sizes before truncation.
type DigestCounts struct {
	Overdue      int `json:"overdue"`
	OpenCritical int `json:"open_critical"`
	OpenHigh     int `json:"open_high"`
	Resolved     int `json:"resolved"`
}

// Digest is the periodic summary for one owner (or account).
type Digest struct {
	Key          string       `json:"key"`
	GroupBy      string       `json:"group_by"`
	Since        time.Time    `json:"since"`
	Until        time.Time    `json:"until"`
	Overdue      []DigestItem `json:"overdue"`       // active and past due, any severity, oldest due first
	OpenCritical []DigestItem `json:"open_critical"` // active CRITICAL not yet overdue
	OpenHigh     []DigestItem `json:"open_high"`     // active HIGH not yet overdue
	Resolved     []DigestItem `json:"resolved"`      // resolved during the period
	OpenTotal    int          `json:"open_total"`    // all active Issues of this key
	Counts       DigestCounts `json:"counts"`
	fp           string
}

// Empty reports a digest with nothing to say (no section has items).
func (d Digest) Empty() bool { return d.Counts == (DigestCounts{}) }

// BuildDigests groups items by owner (Unassigned for none) or account and fills the
// sections. Suppressed Issues are left out. Output is sorted by key; sections are
// sorted by due date (then severity, then id), resolved by resolution time.
func BuildDigests(items []DigestItem, opt DigestOptions) []Digest {
	groupBy := strings.ToLower(strings.TrimSpace(opt.GroupBy))
	if groupBy == "" {
		groupBy = "owner"
	}
	max := opt.MaxPerSection
	if max <= 0 {
		max = 15
	}
	by := map[string]*Digest{}
	get := func(it DigestItem) *Digest {
		k := governance.OwnerKey(it.Owner)
		if groupBy == "account" {
			k = it.Account
			if k == "" {
				k = "(no account)"
			}
		}
		d := by[k]
		if d == nil {
			d = &Digest{Key: k, GroupBy: groupBy, Since: opt.Since, Until: opt.Now}
			by[k] = d
		}
		return d
	}
	for _, it := range items {
		switch {
		case model.IsActive(it.State):
			d := get(it)
			d.OpenTotal++
			switch {
			case it.overdue(opt.Now):
				d.Overdue = append(d.Overdue, it)
			case it.Severity == model.Critical:
				d.OpenCritical = append(d.OpenCritical, it)
			case it.Severity == model.High:
				d.OpenHigh = append(d.OpenHigh, it)
			}
		case it.State == model.StateResolved && it.ResolvedAt != nil && it.ResolvedAt.After(opt.Since) && !it.ResolvedAt.After(opt.Now):
			d := get(it)
			d.Resolved = append(d.Resolved, it)
		}
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Digest, 0, len(keys))
	for _, k := range keys {
		d := by[k]
		for _, s := range [][]DigestItem{d.Overdue, d.OpenCritical, d.OpenHigh} {
			sortByDue(s)
		}
		sort.SliceStable(d.Resolved, func(i, j int) bool {
			a, b := d.Resolved[i], d.Resolved[j]
			if !a.ResolvedAt.Equal(*b.ResolvedAt) {
				return a.ResolvedAt.Before(*b.ResolvedAt)
			}
			return a.IssueID < b.IssueID
		})
		d.Counts = DigestCounts{Overdue: len(d.Overdue), OpenCritical: len(d.OpenCritical), OpenHigh: len(d.OpenHigh), Resolved: len(d.Resolved)}
		d.fp = digestFingerprint(d)
		d.Overdue, d.OpenCritical, d.OpenHigh, d.Resolved = head(d.Overdue, max), head(d.OpenCritical, max), head(d.OpenHigh, max), head(d.Resolved, max)
		out = append(out, *d)
	}
	return out
}

func sortByDue(s []DigestItem) {
	sort.SliceStable(s, func(i, j int) bool {
		a, b := s[i], s[j]
		if a.DueAt.IsZero() != b.DueAt.IsZero() {
			return !a.DueAt.IsZero()
		}
		if !a.DueAt.Equal(b.DueAt) {
			return a.DueAt.Before(b.DueAt)
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.IssueID < b.IssueID
	})
}

func head(s []DigestItem, n int) []DigestItem {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// digestFingerprint hashes the key and which Issue is in which section (before
// truncation) — not dates or day counters — so a digest whose membership has not
// changed is recognised as a duplicate.
func digestFingerprint(d *Digest) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s\n", d.GroupBy, d.Key)
	for _, sec := range []struct {
		name  string
		items []DigestItem
	}{{"overdue", d.Overdue}, {"critical", d.OpenCritical}, {"high", d.OpenHigh}, {"resolved", d.Resolved}} {
		ids := make([]string, len(sec.items))
		for i, it := range sec.items {
			ids[i] = it.IssueID
		}
		sort.Strings(ids)
		fmt.Fprintf(h, "%s:%s\n", sec.name, strings.Join(ids, ","))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// Fingerprint identifies the digest's content for de-duplication.
func (d Digest) Fingerprint() string {
	if d.fp == "" {
		d.fp = digestFingerprint(&d)
	}
	return d.fp
}

const dateFmt = "2006-01-02"

// daysBetween counts calendar days (UTC) from a to b.
func daysBetween(a, b time.Time) int {
	da := time.Date(a.UTC().Year(), a.UTC().Month(), a.UTC().Day(), 0, 0, 0, 0, time.UTC)
	db := time.Date(b.UTC().Year(), b.UTC().Month(), b.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return int(db.Sub(da).Hours() / 24)
}

func (d Digest) summary() string {
	return fmt.Sprintf("%d overdue · %d open critical · %d open high · %d resolved this period · %d open in total",
		d.Counts.Overdue, d.Counts.OpenCritical, d.Counts.OpenHigh, d.Counts.Resolved, d.OpenTotal)
}

func (d Digest) itemLine(it DigestItem, section string) string {
	where := strings.Trim(it.Provider+"/"+it.Account, "/")
	s := fmt.Sprintf("[%s] %s %s", it.Severity, it.IssueID, it.Title)
	if where != "" {
		s += " (" + where + ")"
	}
	switch section {
	case "overdue":
		s += fmt.Sprintf(" - due %s, %dd overdue", it.DueAt.Format(dateFmt), daysBetween(it.DueAt, d.Until))
	case "resolved":
		s += " - resolved " + it.ResolvedAt.Format(dateFmt)
	default:
		if it.DueAt.IsZero() {
			s += " - no due date"
		} else {
			s += fmt.Sprintf(" - due %s (in %dd)", it.DueAt.Format(dateFmt), daysBetween(d.Until, it.DueAt))
		}
	}
	return s
}

type digestSection struct {
	key, title string
	items      []DigestItem
	total      int
}

func (d Digest) sections() []digestSection {
	return []digestSection{
		{"overdue", "Overdue", d.Overdue, d.Counts.Overdue},
		{"critical", "Open critical", d.OpenCritical, d.Counts.OpenCritical},
		{"high", "Open high", d.OpenHigh, d.Counts.OpenHigh},
		{"resolved", "Resolved this period", d.Resolved, d.Counts.Resolved},
	}
}

// Text renders the digest as plain text (email body / stdout).
func (d Digest) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Governance digest for %s (by %s)\n", d.Key, d.GroupBy)
	fmt.Fprintf(&b, "Period %s to %s\n", d.Since.Format(dateFmt), d.Until.Format(dateFmt))
	fmt.Fprintf(&b, "%s\n", d.summary())
	for _, sec := range d.sections() {
		if sec.total == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s (%d)\n", strings.ToUpper(sec.title), sec.total)
		for _, it := range sec.items {
			fmt.Fprintf(&b, "  %s\n", d.itemLine(it, sec.key))
			if it.FixCommand != "" && sec.key != "resolved" {
				fmt.Fprintf(&b, "      fix: %s\n", it.FixCommand)
			}
		}
		if more := sec.total - len(sec.items); more > 0 {
			fmt.Fprintf(&b, "  ... and %d more (cloud-posture issues --owner %q)\n", more, d.Key)
		}
	}
	return b.String()
}

func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// clip limits s to n characters (Slack counts characters), cutting on a rune boundary so the
// result never carries a broken multi-byte sequence (verify-4/5: U+FFFD at the cut).
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	if n <= 3 {
		return strings.Repeat(".", max(n, 0))
	}
	r := []rune(s)
	return string(r[:n-3]) + "..."
}

// SlackPayload is the digest as a Slack Block Kit message (≤ 50 blocks, section
// text ≤ 3000 characters, mrkdwn escaped).
func (d Digest) SlackPayload() map[string]any {
	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": clip("Governance digest: "+d.Key, 150)}},
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": slackEscape(d.summary())}},
	}
	for _, sec := range d.sections() {
		if sec.total == 0 {
			continue
		}
		var lines []string
		for _, it := range sec.items {
			l := "• " + slackEscape(d.itemLine(it, sec.key))
			if it.FixCommand != "" && sec.key != "resolved" {
				l += "\n    fix: `" + strings.ReplaceAll(it.FixCommand, "`", "'") + "`"
			}
			lines = append(lines, l)
		}
		if more := sec.total - len(sec.items); more > 0 {
			lines = append(lines, fmt.Sprintf("_... and %d more_", more))
		}
		blocks = append(blocks,
			map[string]any{"type": "divider"},
			map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn",
				"text": clip(fmt.Sprintf("*%s (%d)*\n%s", sec.title, sec.total, strings.Join(lines, "\n")), 3000)}})
	}
	blocks = append(blocks, map[string]any{"type": "context", "elements": []map[string]any{{"type": "mrkdwn",
		"text": fmt.Sprintf("Period %s to %s · `cloud-posture issues --overdue` for the full list", d.Since.Format(dateFmt), d.Until.Format(dateFmt))}}})
	if len(blocks) > 50 {
		blocks = blocks[:50]
	}
	return map[string]any{"text": slackEscape(fmt.Sprintf("Governance digest for %s: %s", d.Key, d.summary())), "blocks": blocks}
}

// SlackJSON is SlackPayload as indented JSON (stable key order).
func (d Digest) SlackJSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d.SlackPayload()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DigestLedger remembers what was last sent per digest key.
type DigestLedger interface {
	Last(key string) (fingerprint string, at time.Time, ok bool)
	Record(key, fingerprint string, at time.Time) error
}

type ledgerEntry struct {
	Fingerprint string    `json:"fingerprint"`
	At          time.Time `json:"at"`
}

// MemoryLedger is an in-process DigestLedger.
type MemoryLedger struct {
	mu sync.Mutex
	m  map[string]ledgerEntry
}

// NewMemoryLedger returns an empty in-memory ledger.
func NewMemoryLedger() *MemoryLedger { return &MemoryLedger{m: map[string]ledgerEntry{}} }

func (l *MemoryLedger) Last(key string) (string, time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[key]
	return e.Fingerprint, e.At, ok
}

func (l *MemoryLedger) Record(key, fp string, at time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m[key] = ledgerEntry{fp, at}
	return nil
}

// FileLedger is a DigestLedger persisted as JSON (e.g. <work_dir>/digest-ledger.json).
type FileLedger struct {
	mu   sync.Mutex
	path string
}

// NewFileLedger returns a ledger stored at path (created on first Record).
func NewFileLedger(path string) *FileLedger { return &FileLedger{path: path} }

func (l *FileLedger) load() map[string]ledgerEntry {
	m := map[string]ledgerEntry{}
	if b, err := os.ReadFile(l.path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (l *FileLedger) Last(key string) (string, time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.load()[key]
	return e.Fingerprint, e.At, ok
}

func (l *FileLedger) Record(key, fp string, at time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := l.load()
	m[key] = ledgerEntry{fp, at}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// ShouldSend reports whether d should go out at now: never when empty; otherwise
// unless the ledger holds the same fingerprint for d.Key recorded within window.
func ShouldSend(d Digest, l DigestLedger, window time.Duration, now time.Time) bool {
	if d.Empty() {
		return false
	}
	if l == nil {
		return true
	}
	fp, at, ok := l.Last(d.Key)
	return !ok || fp != d.Fingerprint() || now.Sub(at) >= window-dedupJitter(window)
}

// dedupJitter is the scheduler tolerance at the dedup-window edge (verify-4/5 D7): the window
// defaults to the schedule period, so a cron that fires slightly earlier than last time must not
// skip an unchanged digest for a whole extra period. 10% of the window, at most one hour.
func dedupJitter(window time.Duration) time.Duration {
	return min(window/10, time.Hour)
}

// DigestRun is the outcome of SendDigests (keys in input order).
type DigestRun struct {
	Sent    []string `json:"sent"`
	Skipped []string `json:"skipped"` // empty or unchanged within the window
	Failed  []string `json:"failed"`
}

// SendDigests sends every digest ShouldSend allows and records successful sends in
// the ledger. Failures are retried on the next run; their errors are joined.
func SendDigests(ctx context.Context, ds []Digest, l DigestLedger, window time.Duration, now time.Time, send func(context.Context, Digest) error) (DigestRun, error) {
	var run DigestRun
	var errs []error
	for _, d := range ds {
		if !ShouldSend(d, l, window, now) {
			run.Skipped = append(run.Skipped, d.Key)
			continue
		}
		if err := send(ctx, d); err != nil {
			run.Failed = append(run.Failed, d.Key)
			errs = append(errs, fmt.Errorf("digest %s: %w", d.Key, err))
			continue
		}
		run.Sent = append(run.Sent, d.Key)
		if l != nil {
			if err := l.Record(d.Key, d.Fingerprint(), now); err != nil {
				errs = append(errs, fmt.Errorf("digest ledger %s: %w", d.Key, err))
			}
		}
	}
	return run, errors.Join(errs...)
}

// SlackDigestSender posts digests to a Slack incoming webhook (channel optional).
func SlackDigestSender(webhookURL, channel string) func(context.Context, Digest) error {
	return func(ctx context.Context, d Digest) error {
		if webhookURL == "" {
			return fmt.Errorf("slack webhook URL not configured (SLACK_WEBHOOK_URL)")
		}
		p := d.SlackPayload()
		if channel != "" {
			p["channel"] = channel
		}
		_, code, err := postJSON(ctx, webhookURL, nil, p)
		if err != nil {
			return err
		}
		if code/100 != 2 {
			return fmt.Errorf("slack webhook returned HTTP %d", code)
		}
		return nil
	}
}
