package output

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// CSVColumns is the column order of CSV output.
var CSVColumns = []string{"id", "severity", "status", "provider", "account", "region", "canonical_id", "check_id", "source", "title", "resource_id", "resource_name", "resource_type", "file", "line_start", "line_end", "weaknesses", "first_seen", "last_seen"}

// CSV renders one row per finding. Cells that a spreadsheet would evaluate as a formula
// (leading = + - @ tab or CR) are prefixed with a single quote (OWASP CSV injection guidance).
func CSV(findings []model.Finding) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(CSVColumns); err != nil {
		return nil, err
	}
	for _, f := range findings {
		line := func(n int) string {
			if n == 0 {
				return ""
			}
			return fmt.Sprint(n)
		}
		row := []string{f.ID, string(f.Severity), string(f.Status), f.Provider, f.Account, f.Region, f.CanonicalID, f.CheckID, f.Source, f.Title,
			f.Resource.ID, f.Resource.Name, f.Resource.Type, f.File, line(f.LineStart), line(f.LineEnd), strings.Join(f.Weaknesses, ";"),
			csvTime(f.FirstSeen), csvTime(f.LastSeen)}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func csvTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
