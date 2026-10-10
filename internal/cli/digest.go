package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/governance"
	"github.com/DreadpiratePickles/nimbus/internal/integrations"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// runDigest is `alert --digest`: one digest per owner (or account) built from the stored
// Issues and their governance due dates, de-duplicated through <db dir>/digest-ledger.json, sent
// to governance.digest.sink (or --digest-sink): slack → Block Kit to integrations.slack, stdout →
// the text body. --dry-run prints every digest and whether it would be sent, sending nothing.
func runDigest(ctx context.Context, cfg *config.Config, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	g := cfg.Governance
	sink := strings.ToLower(strings.TrimSpace(firstNonEmpty(alertFlags.digestSink, g.Digest.Sink, "stdout")))
	send, err := digestSender(cfg, sink, w)
	if err != nil {
		return err
	}
	// The "(unassigned)" digest goes to governance.digest.unassigned_sink when set (W5-ISSUES
	// item 3): Issues nobody owns still reach a person.
	uSink := strings.ToLower(strings.TrimSpace(g.Digest.UnassignedSink))
	var uSend func(context.Context, integrations.Digest) error
	if uSink != "" && uSink != sink {
		if uSend, err = digestSender(cfg, uSink, w); err != nil {
			return fmt.Errorf("governance.digest.unassigned_sink: %w", err)
		}
	}
	now := time.Now().UTC()
	since := now.Add(-g.Digest.Period())
	if alertFlags.since != "" {
		t, err := parseSince(alertFlags.since, now)
		if err != nil {
			return err
		}
		since = t
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	issues, err := st.Issues(store.IssueFilter{Now: now})
	if err != nil {
		return err
	}
	var items []integrations.DigestItem
	for _, is := range issues {
		items = append(items, integrations.DigestItemFromIssue(is, server.AssignmentOf(is), issueFixCommand(is)))
	}
	all := integrations.BuildDigests(items, integrations.DigestOptions{Now: now, Since: since, GroupBy: g.Digest.GroupByOrDefault()})
	ds, unassigned := all, []integrations.Digest(nil)
	if uSend != nil {
		ds = nil
		for _, d := range all {
			if d.Key == governance.Unassigned {
				unassigned = append(unassigned, d)
			} else {
				ds = append(ds, d)
			}
		}
	}
	// One ledger file, keyed per sink: a digest printed to stdout does not count as sent to Slack.
	ledger := sinkLedger{l: integrations.NewFileLedger(digestLedgerPath(st)), sink: sink}
	window := g.Digest.DedupWindow()
	if alertFlags.dryRun {
		for _, d := range ds {
			verdict := "would send"
			if !integrations.ShouldSend(d, ledger, window, now) {
				verdict = "would skip (empty or unchanged within the dedup window)"
			}
			fmt.Fprintf(w, "── digest %s (%s): %s via %s\n%s\n", d.Key, d.GroupBy, verdict, sink, d.Text())
		}
		for _, d := range unassigned {
			fmt.Fprintf(w, "── digest %s (%s): unassigned → %s\n%s\n", d.Key, d.GroupBy, uSink, d.Text())
		}
		fmt.Fprintf(w, "dry run: %d digest(s), nothing sent, ledger %s untouched\n", len(ds)+len(unassigned), digestLedgerPath(st))
		return nil
	}
	if len(unassigned) > 0 {
		uLedger := sinkLedger{l: integrations.NewFileLedger(digestLedgerPath(st)), sink: uSink}
		urun, err := integrations.SendDigests(ctx, unassigned, uLedger, window, now, uSend)
		fmt.Fprintf(w, "unassigned digest via %s: sent %d · skipped %d · failed %d\n", uSink, len(urun.Sent), len(urun.Skipped), len(urun.Failed))
		if err != nil {
			return fmt.Errorf("digest (unassigned): %w", err)
		}
	}
	run, err := integrations.SendDigests(ctx, ds, ledger, window, now, send)
	fmt.Fprintf(w, "digest via %s: sent %d · skipped %d (empty or unchanged) · failed %d\n", sink, len(run.Sent), len(run.Skipped), len(run.Failed))
	for _, k := range run.Sent {
		fmt.Fprintf(w, "  ✓ %s\n", k)
	}
	for _, k := range run.Failed {
		fmt.Fprintf(w, "  ✗ %s\n", k)
	}
	if err != nil {
		return fmt.Errorf("digest: %w", err)
	}
	return nil
}

// sinkLedger prefixes ledger keys with the sink ("slack/<owner>").
type sinkLedger struct {
	l    integrations.DigestLedger
	sink string
}

func (s sinkLedger) Last(key string) (string, time.Time, bool) { return s.l.Last(s.sink + "/" + key) }
func (s sinkLedger) Record(key, fp string, at time.Time) error {
	return s.l.Record(s.sink+"/"+key, fp, at)
}

// digestSender is the send function of one digest sink (slack | stdout).
func digestSender(cfg *config.Config, sink string, w io.Writer) (func(context.Context, integrations.Digest) error, error) {
	switch sink {
	case "slack":
		sc := cfg.Integrations["slack"]
		if sc == nil {
			sc = &config.SinkConfig{}
		}
		return integrations.SlackDigestSender(config.Resolve(sc.URL, firstNonEmpty(sc.URLEnv, "SLACK_WEBHOOK_URL")), sc.Channel), nil
	case "stdout":
		return func(_ context.Context, d integrations.Digest) error {
			_, err := fmt.Fprintln(w, d.Text())
			return err
		}, nil
	case "teams", "email", "webhook":
		return nil, fmt.Errorf("digest sink %q is not implemented yet (slack and stdout are); use --digest-sink slack|stdout", sink)
	}
	return nil, fmt.Errorf("unknown digest sink %q (slack | stdout)", sink)
}
