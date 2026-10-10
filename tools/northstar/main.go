// Command northstar sums the north-star footers (plan v3 §8) that nimbus writes into pull
// requests and plan-diff comments:
//
//	nimbus-closes-paths: N   attack paths the change closes (fix PRs, plan-diff comments)
//	nimbus-opens-paths: N    attack paths the change opens (plan-diff comments)
//	nimbus-escalates-paths: N  surviving paths the change raises into High/Critical (plan-diff)
//	nimbus-lowers-paths: N   surviving paths whose band the change lowers (plan-diff credit)
//
// Input: one or more GitHub search API responses (GET /search/issues?q="nimbus-closes-paths"),
// as files or stdin. It never calls GitHub itself. A footer counts only on its own line; the
// last one in a body wins; items are de-duplicated by id (pages may overlap); a value above
// -max-per-item is rejected (counted in "rejected"). See tools/northstar/README.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	closesRe = regexp.MustCompile(`(?m)^nimbus-closes-paths:[ \t]*([0-9]{1,12})[ \t]*\r?$`)
	opensRe  = regexp.MustCompile(`(?m)^nimbus-opens-paths:[ \t]*([0-9]{1,12})[ \t]*\r?$`)
	escRe    = regexp.MustCompile(`(?m)^nimbus-escalates-paths:[ \t]*([0-9]{1,12})[ \t]*\r?$`)
	lowersRe = regexp.MustCompile(`(?m)^nimbus-lowers-paths:[ \t]*([0-9]{1,12})[ \t]*\r?$`)
)

// MaxPerItem caps a single footer value (a PR closing more is implausible, or hostile).
var MaxPerItem = 10000

// Summary accumulates search responses.
type Summary struct {
	Items      int            `json:"items"`       // distinct PRs / issues read
	WithFooter int            `json:"with_footer"` // items carrying a closes footer
	Closes     int            `json:"closes"`
	Opens      int            `json:"opens"`
	Escalates  int            `json:"escalates"`
	Lowers     int            `json:"lowers"`
	Rejected   int            `json:"rejected"`
	Repos      map[string]int `json:"repos"` // owner/repo → closes
	seen       map[string]bool
}

type searchResponse struct {
	Items []struct {
		ID            json.Number `json:"id"`
		HTMLURL       string      `json:"html_url"`
		RepositoryURL string      `json:"repository_url"`
		Body          string      `json:"body"`
	} `json:"items"`
}

// Add reads one search response (at most 64 MiB).
func (s *Summary) Add(r io.Reader) error {
	if s.seen == nil {
		s.seen, s.Repos = map[string]bool{}, map[string]int{}
	}
	var resp searchResponse
	if err := json.NewDecoder(io.LimitReader(r, 64<<20)).Decode(&resp); err != nil {
		return fmt.Errorf("search response: %w", err)
	}
	for _, it := range resp.Items {
		key := it.ID.String()
		if key == "" {
			key = it.HTMLURL
		}
		if s.seen[key] {
			continue
		}
		s.seen[key] = true
		s.Items++
		if n, ok := last(closesRe, it.Body, &s.Rejected); ok {
			s.WithFooter++
			s.Closes += n
			s.Repos[repoOf(it.RepositoryURL)] += n
		}
		if n, ok := last(opensRe, it.Body, &s.Rejected); ok {
			s.Opens += n
		}
		if n, ok := last(escRe, it.Body, &s.Rejected); ok {
			s.Escalates += n
		}
		if n, ok := last(lowersRe, it.Body, &s.Rejected); ok {
			s.Lowers += n
		}
	}
	return nil
}

func last(re *regexp.Regexp, body string, rejected *int) (int, bool) {
	m := re.FindAllStringSubmatch(body, -1)
	if len(m) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(m[len(m)-1][1])
	if err != nil || n > MaxPerItem {
		*rejected++
		return 0, false
	}
	return n, true
}

func repoOf(u string) string {
	if i := strings.Index(u, "/repos/"); i >= 0 {
		return u[i+len("/repos/"):]
	}
	return u
}

// Print writes a human summary.
func (s *Summary) Print(w io.Writer) {
	fmt.Fprintf(w, "nimbus-closes-paths total: %d\nnimbus-opens-paths total: %d\nnimbus-escalates-paths total: %d\nnimbus-lowers-paths total: %d\nitems: %d (with a closes footer: %d, rejected footers: %d)\n",
		s.Closes, s.Opens, s.Escalates, s.Lowers, s.Items, s.WithFooter, s.Rejected)
	repos := make([]string, 0, len(s.Repos))
	for r := range s.Repos {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	for _, r := range repos {
		fmt.Fprintf(w, "  %-40s %d\n", r, s.Repos[r])
	}
}

func main() {
	asJSON := flag.Bool("json", false, "print the summary as JSON")
	flag.IntVar(&MaxPerItem, "max-per-item", MaxPerItem, "reject a footer value above this")
	flag.Parse()
	var s Summary
	files := flag.Args()
	if len(files) == 0 {
		files = []string{"-"}
	}
	for _, f := range files {
		var r io.Reader = os.Stdin
		if f != "-" {
			fh, err := os.Open(f)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			defer fh.Close()
			r = fh
		}
		if err := s.Add(r); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", f, err)
			os.Exit(1)
		}
	}
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(s)
		return
	}
	s.Print(os.Stdout)
}
