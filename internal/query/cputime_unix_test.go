//go:build unix

package query

import (
	"syscall"
	"time"
)

// processCPU is the CPU time (user + system) this test process has used. Timing assertions use
// it instead of wall-clock time: CPU time does not grow when other processes (a parallel
// `go test ./...`, CI neighbours) compete for the machine, which is what made the wall-clock
// bounds flake (W7-POLISH flake hunt).
func processCPU() (time.Duration, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()), true
}
