package remediation

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 3 defect 6 (MEDIUM): the copy-paste command lines inside templates interpolated
// {{ .Name }}, .ShortID, .ID and .Region unquoted, e.g. gcp_bucket_public.tf
// `gcloud storage buckets update gs://{{ .Name }}`: a bucket named `b1 $(touch PWNED_gcloud)` ran
// the command substitution, and `db1 --endpoint-url=https://evil.example` became an aws option
// (scratchpad verify-3/iac/cmdinj, iac/shell_out.txt).
//
// Every template is rendered with hostile values in every field; every command line must be a
// `# CLI:` / `// CLI:` line, pass `bash -n`, keep each hostile value inside one single-quoted
// span, never start an argument with it (option injection), and run against stub CLIs without
// executing anything embedded in it.

type hostileValue struct {
	raw, marker string // marker: a distinctive part of raw that must stay single-quoted
	option      bool   // raw starts with '-'
}

func hostileValues() []hostileValue {
	return []hostileValue{
		{"$(touch PWNED_subst)", "touch PWNED_subst", false},
		{"`touch PWNED_tick`", "touch PWNED_tick", false},
		{"x;touch PWNED_semi", "touch PWNED_semi", false},
		{"a\ntouch PWNED_nl", "touch PWNED_nl", false},
		{"'$(touch PWNED_q)'", "touch PWNED_q", false},
		{"\" $(touch PWNED_dq) \"", "touch PWNED_dq", false},
		{"--endpoint-url=https://evil.example", "--endpoint-url=https://evil.example", true},
		{"-x", "-x", true},
	}
}

var cliLine = regexp.MustCompile(`^\s*(?:#|//)\s*CLI:\s*(.+)$`)
var cliWord = regexp.MustCompile(`(^|[\s(:])(aws|az|gcloud|kubectl)\s`)

func hostileFinding(id string, h hostileValue) model.Finding {
	return model.Finding{CanonicalID: id, Severity: model.High, Source: "x", Account: h.raw, Region: h.raw,
		Resource: model.Resource{ID: "arn:aws:x:us-east-1:111122223333:thing/" + h.raw, Name: h.raw, Type: "x",
			Attributes: map[string]any{"namespace": h.raw, "kind": h.raw, "resource_group": h.raw}}}
}

// quoteMap marks, for each byte of a POSIX shell line, whether it is inside single quotes.
func quoteMap(line string) []bool {
	in := make([]bool, len(line))
	single, double := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case single:
			if c == '\'' {
				single = false
			} else {
				in[i] = true
			}
		case c == '\\':
			i++
		case double:
			if c == '"' {
				double = false
			}
		case c == '\'':
			single = true
		case c == '"':
			double = true
		}
	}
	return in
}

// shellWords splits a line into words the way the shell would (quotes removed, no expansion),
// reporting for each word whether it starts with an unquoted or quoted character of marker.
func shellWords(line string) []string {
	var words []string
	var cur strings.Builder
	has, single, double := false, false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case single:
			if c == '\'' {
				single = false
			} else {
				cur.WriteByte(c)
			}
		case double:
			if c == '"' {
				double = false
			} else if c == '\\' && i+1 < len(line) {
				i++
				cur.WriteByte(line[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '\'':
			single, has = true, true
		case c == '"':
			double, has = true, true
		case c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
			has = true
		case c == ' ' || c == '\t':
			if has {
				words = append(words, cur.String())
				cur.Reset()
				has = false
			}
		case c == '#' && !has:
			i = len(line) // a trailing shell comment
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	if has {
		words = append(words, cur.String())
	}
	return words
}

func TestTemplateCLILinesQuoteHostileNames(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	stub := `aws(){ printf '%s\n' "$@"; }; az(){ printf '%s\n' "$@"; }; gcloud(){ printf '%s\n' "$@"; }; kubectl(){ printf '%s\n' "$@"; }; `
	work := t.TempDir()
	cat := catalog.Default()
	rendered, lines := 0, 0
	for _, id := range cat.IDs() {
		for _, fm := range Formats(id) {
			for _, h := range hostileValues() {
				fx, err := Generate(hostileFinding(id, h), fm)
				if err != nil {
					t.Errorf("%s %s %q: %v", id, fm, h.raw, err)
					continue
				}
				rendered++
				for _, l := range strings.Split(fx.Content, "\n") {
					m := cliLine.FindStringSubmatch(l)
					if m == nil {
						if cliWord.MatchString(l) && strings.Contains(l, strings.Split(h.marker, " ")[0]) && strings.Contains(l, h.marker) {
							t.Errorf("%s %s (%s): command with a hostile value outside a CLI: line:\n  %s", id, fm, fx.Template, l)
						}
						continue
					}
					cmd := m[1]
					lines++
					if out, err := exec.Command("bash", "-n", "-c", cmd).CombinedOutput(); err != nil {
						t.Errorf("%s %s (%s): bash -n rejects %q: %s", id, fm, fx.Template, cmd, out)
						continue
					}
					q := quoteMap(cmd)
					for off := 0; ; {
						i := strings.Index(cmd[off:], h.marker)
						if i < 0 {
							break
						}
						i += off
						for j := i; j < i+len(h.marker); j++ {
							if !q[j] {
								t.Errorf("%s %s (%s): %q is not single-quoted in:\n  %s", id, fm, fx.Template, h.raw, cmd)
								break
							}
						}
						off = i + len(h.marker)
					}
					endOpts := false
					for _, w := range shellWords(cmd) {
						if w == "--" {
							endOpts = true
						}
						if h.option && !endOpts && strings.HasPrefix(w, h.raw) {
							t.Errorf("%s %s (%s): hostile %q becomes an option argument %q in:\n  %s", id, fm, fx.Template, h.raw, w, cmd)
						}
					}
					run := exec.Command("bash", "-c", stub+cmd)
					run.Dir = work
					run.Env = append(os.Environ(), "RESOURCE_GROUP=rg", "NAMESPACE=ns", "KIND=deployment", "PATCH={}", "SNAPSHOT_ID=snap-1", "PREVIOUS_VERSION=v1", "OPEN_RULE=r", "SERVICE_ACCOUNT=sa")
					if out, err := run.CombinedOutput(); err != nil {
						t.Errorf("%s %s (%s): command fails against stubs: %v\n  %s\n%s", id, fm, fx.Template, err, cmd, out)
					}
				}
			}
		}
	}
	if pwned, _ := filepath.Glob(filepath.Join(work, "PWNED*")); len(pwned) > 0 {
		t.Errorf("a template command executed an embedded payload: %v", pwned)
	}
	if rendered == 0 || lines == 0 {
		t.Fatalf("rendered %d fixes, checked %d CLI lines: the test exercised nothing", rendered, lines)
	}
	t.Logf("rendered %d fixes, checked %d CLI lines", rendered, lines)
}
