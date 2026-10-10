//go:build race

package cli

// raceEnabled: the race detector instruments every memory access (5-20x slower, more
// allocation), so absolute time and allocation bounds are skipped under -race; ratio and
// behaviour assertions still run (W7-POLISH flake hunt, verification 7).
const raceEnabled = true
