//go:build !unix

package iac

import "time"

// processCPU is unavailable here; callers fall back to wall-clock time with generous bounds.
func processCPU() (time.Duration, bool) { return 0, false }
