// Package monitor detects risky configuration changes in near real time by polling
// AWS CloudTrail, the Azure Activity Log and GCP Cloud Audit Logs, mapping each
// security-relevant API call onto a canonical finding ID from the catalog.
package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Event is one security-relevant change observed in a cloud audit log.
type Event struct {
	Time         time.Time
	Provider     string
	Account      string
	Region       string
	Source       string
	EventName    string
	Actor        string
	ResourceID   string
	ResourceType string
	Title        string
	Severity     model.Severity
	CanonicalID  string
	Raw          map[string]any
}

// ID is the provider event identifier (CloudTrail eventID, Activity Log eventDataId,
// audit log insertId) when known, else a composite key.
func (e Event) ID() string {
	if e.Raw != nil {
		if id, ok := e.Raw["event_id"].(string); ok && id != "" {
			return id
		}
	}
	return strings.Join([]string{e.Provider, e.Account, e.EventName, e.ResourceID, e.Time.UTC().Format(time.RFC3339Nano)}, "|")
}

// ToFinding converts the change into a FAIL finding with Source "monitor".
func (e Event) ToFinding() model.Finding {
	f := model.Finding{
		Source:      "monitor",
		CheckID:     e.EventName,
		CanonicalID: e.CanonicalID,
		Title:       e.Title,
		Severity:    e.Severity,
		Status:      model.Fail,
		Provider:    e.Provider,
		Account:     e.Account,
		Region:      e.Region,
		Resource:    model.Resource{ID: e.ResourceID, Type: e.ResourceType, Name: lastSeg(e.ResourceID)},
		Tags:        map[string]string{"actor": e.Actor, "event_source": e.Source},
	}
	actor := e.Actor
	if actor == "" {
		actor = "unknown actor"
	}
	f.Description = fmt.Sprintf("%s called %s (%s) on %s at %s.", actor, e.EventName, e.Source, e.ResourceID, e.Time.UTC().Format(time.RFC3339))
	if f.CanonicalID == "" {
		f.CanonicalID = "MONITOR:" + e.EventName
	} else if entry, ok := catalog.Default().Get(e.CanonicalID); ok {
		f.Weaknesses = append(f.Weaknesses, entry.Weaknesses...)
		for fw, ctrls := range entry.Compliance {
			f.AddCompliance(fw, ctrls...)
		}
		if f.Title == "" {
			f.Title = entry.Title
		}
		if f.Severity == "" {
			f.Severity = entry.Severity
		}
	}
	if f.Title == "" {
		f.Title = e.EventName
	}
	if e.Raw != nil {
		if b, err := json.Marshal(e.Raw); err == nil {
			f.Raw = b
		}
	}
	t := e.Time
	if t.IsZero() {
		t = time.Now()
	}
	f.Finalize(t)
	f.FirstSeen = t
	return f
}

// Source polls one audit-log stream (one account / region / log scope).
type Source interface {
	Name() string
	Poll(ctx context.Context, since time.Time) ([]Event, error)
}

// Closer is implemented by sources holding network clients.
type closer interface{ Close() error }

// Monitor polls every configured source and checkpoints the last-seen event time
// per account+source in a JSON file so restarts neither miss nor repeat changes.
type Monitor struct {
	specs          []core.AccountSpec
	checkpointPath string

	// Concurrency bounds parallel source polls (default 8).
	Concurrency int
	// InitialLookback is how far back the first poll of a source reaches (default 1h).
	InitialLookback time.Duration
	// Now is the clock (tests override).
	Now func() time.Time

	mu          sync.Mutex
	sources     map[string][]Source // account key -> sources
	built       bool
	checkpoints map[string]time.Time
	loaded      bool
}

// New creates a monitor for specs; sources are built lazily on the first Poll.
func New(specs []core.AccountSpec, checkpointPath string) *Monitor {
	return &Monitor{specs: specs, checkpointPath: checkpointPath, sources: map[string][]Source{}, checkpoints: map[string]time.Time{}}
}

// AddSource registers an additional (or fake) source under account.
func (m *Monitor) AddSource(account string, s Source) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sources[account] = append(m.sources[account], s)
}

func (m *Monitor) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Monitor) build(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.built {
		return nil
	}
	m.built = true
	var errs []error
	for _, spec := range m.specs {
		srcs, err := sourcesFor(ctx, spec)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", spec.Provider, spec.Label(), err))
		}
		m.sources[spec.Label()] = append(m.sources[spec.Label()], srcs...)
	}
	return errors.Join(errs...)
}

func sourcesFor(ctx context.Context, spec core.AccountSpec) ([]Source, error) {
	switch model.NormalizeProvider(spec.Provider) {
	case model.ProviderAWS:
		return newCloudTrailSources(ctx, spec)
	case model.ProviderAzure:
		s, err := newActivityLogSource(spec)
		if err != nil {
			return nil, err
		}
		return []Source{s}, nil
	case model.ProviderGCP:
		s, err := newAuditLogSource(ctx, spec)
		if err != nil {
			return nil, err
		}
		return []Source{s}, nil
	}
	return nil, nil
}

// Close releases source clients.
func (m *Monitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, srcs := range m.sources {
		for _, s := range srcs {
			if c, ok := s.(closer); ok {
				errs = append(errs, c.Close())
			}
		}
	}
	return errors.Join(errs...)
}

func checkpointKey(account string, s Source) string { return account + "|" + s.Name() }

func (m *Monitor) loadCheckpoints() error {
	if m.loaded {
		return nil
	}
	m.loaded = true
	if m.checkpointPath == "" {
		return nil
	}
	data, err := os.ReadFile(m.checkpointPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	raw := map[string]string{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("checkpoint %s: %w", m.checkpointPath, err)
	}
	for k, v := range raw {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			m.checkpoints[k] = t
		}
	}
	return nil
}

func (m *Monitor) saveCheckpoints() error {
	if m.checkpointPath == "" {
		return nil
	}
	raw := map[string]string{}
	for k, t := range m.checkpoints {
		raw[k] = t.UTC().Format(time.RFC3339Nano)
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.checkpointPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".monitor-checkpoint-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), m.checkpointPath)
}

// Checkpoint returns the stored last-seen time for account+source name.
func (m *Monitor) Checkpoint(account, sourceName string) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.checkpoints[account+"|"+sourceName]
	return t, ok
}

// Poll queries every source since its checkpoint, in parallel. Events from sources
// that succeeded are returned even when others fail; the error joins the failures.
func (m *Monitor) Poll(ctx context.Context) ([]Event, error) {
	var errs []error
	if err := m.build(ctx); err != nil {
		errs = append(errs, err)
	}
	m.mu.Lock()
	if err := m.loadCheckpoints(); err != nil {
		errs = append(errs, err)
	}
	type job struct {
		account string
		src     Source
		since   time.Time
	}
	lookback := m.InitialLookback
	if lookback <= 0 {
		lookback = time.Hour
	}
	now := m.now()
	var jobs []job
	for _, acct := range core.SortedKeys(m.sources) {
		for _, s := range m.sources[acct] {
			since, ok := m.checkpoints[checkpointKey(acct, s)]
			if !ok {
				since = now.Add(-lookback)
			}
			jobs = append(jobs, job{acct, s, since})
		}
	}
	m.mu.Unlock()

	limit := m.Concurrency
	if limit <= 0 {
		limit = 8
	}
	results := make([][]Event, len(jobs))
	jobErrs := make([]error, len(jobs))
	var eg errgroup.Group
	eg.SetLimit(limit)
	for i, j := range jobs {
		eg.Go(func() error {
			evs, err := j.src.Poll(ctx, j.since)
			results[i], jobErrs[i] = evs, err
			return nil
		})
	}
	_ = eg.Wait()

	seen := map[string]bool{}
	var out []Event
	m.mu.Lock()
	for i, j := range jobs {
		if jobErrs[i] != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", j.account, j.src.Name(), jobErrs[i]))
		}
		maxT := time.Time{}
		for _, e := range results[i] {
			if e.Time.After(maxT) {
				maxT = e.Time
			}
			id := e.ID()
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, e)
		}
		if jobErrs[i] == nil {
			key := checkpointKey(j.account, j.src)
			next := j.since
			if !maxT.IsZero() && !maxT.Before(next) {
				next = maxT.Add(time.Nanosecond)
			}
			if _, ok := m.checkpoints[key]; !ok || next.After(m.checkpoints[key]) {
				m.checkpoints[key] = next
			}
		}
	}
	if err := m.saveCheckpoints(); err != nil {
		errs = append(errs, fmt.Errorf("save checkpoint: %w", err))
	}
	m.mu.Unlock()
	sort.SliceStable(out, func(a, b int) bool { return out[a].Time.Before(out[b].Time) })
	return out, errors.Join(errs...)
}

// ErrorHandler, when set, receives partial poll errors during Run.
type ErrorHandler func(error)

// Run polls immediately and then every interval, sending events to out until ctx is
// cancelled (returns ctx.Err()). Poll errors are non-fatal.
func (m *Monitor) Run(ctx context.Context, interval time.Duration, out chan<- Event) error {
	return m.RunWithErrors(ctx, interval, out, nil)
}

// RunWithErrors is Run with a callback for partial poll failures.
func (m *Monitor) RunWithErrors(ctx context.Context, interval time.Duration, out chan<- Event, onErr ErrorHandler) error {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		evs, err := m.Poll(ctx)
		if err != nil && onErr != nil && ctx.Err() == nil {
			onErr(err)
		}
		for _, e := range evs {
			select {
			case out <- e:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func lastSeg(s string) string {
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndexAny(s, "/:"); i >= 0 && i < len(s)-1 {
		return s[i+1:]
	}
	return s
}
