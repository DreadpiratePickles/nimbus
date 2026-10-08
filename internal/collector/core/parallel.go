package core

import (
	"context"
	"fmt"
	"sort"

	"golang.org/x/sync/errgroup"
)

// Task is one named unit of collection work.
type Task struct {
	Name string
	Fn   func(ctx context.Context) error
}

// RunTasks executes tasks with at most limit in flight. A failing task never cancels
// its siblings: errors (and panics) are recorded on acc under the task name.
func RunTasks(ctx context.Context, limit int, acc *Acc, tasks []Task) {
	if limit <= 0 {
		limit = 8
	}
	var eg errgroup.Group
	eg.SetLimit(limit)
	for _, t := range tasks {
		eg.Go(func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					acc.Error(t.Name, fmt.Errorf("panic: %v", r))
				}
			}()
			if ctx.Err() != nil {
				acc.Error(t.Name, ctx.Err())
				return nil
			}
			acc.Error(t.Name, t.Fn(ctx))
			return nil
		})
	}
	_ = eg.Wait()
}

// SortedKeys returns map keys in order (deterministic graph / finding output).
func SortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
