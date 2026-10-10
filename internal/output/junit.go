package output

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Errors   int          `xml:"errors,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	File      string        `xml:"file,attr,omitempty"`
	Line      int           `xml:"line,attr,omitempty"`
	Failure   *junitProblem `xml:"failure,omitempty"`
	Error     *junitProblem `xml:"error,omitempty"`
	Skipped   *junitProblem `xml:"skipped,omitempty"`
}

type junitProblem struct {
	Message string `xml:"message,attr,omitempty"`
	Type    string `xml:"type,attr,omitempty"`
	Body    string `xml:",chardata"`
}

// JUnit renders every finding as a test case, one test suite per provider: FAIL → <failure>,
// ERROR (scan gaps, collector errors) → <error>, SKIP → <skipped>, PASS → a passing case. CI
// systems (GitLab, Jenkins, Azure DevOps, CircleCI) show these as test results.
func JUnit(findings []model.Finding) ([]byte, error) {
	byProv := map[string]*junitSuite{}
	var names []string
	doc := junitSuites{Name: "cloud-posture"}
	for _, f := range findings {
		prov := firstNonEmpty(f.Provider, model.ProviderUnknown)
		s, ok := byProv[prov]
		if !ok {
			s = &junitSuite{Name: prov}
			byProv[prov] = s
			names = append(names, prov)
		}
		c := junitCase{
			Name:      strings.TrimSpace(f.CanonicalID + " " + firstNonEmpty(f.Resource.Name, f.Resource.ID, f.File)),
			Classname: prov + "." + f.CanonicalID,
			File:      f.File,
			Line:      f.LineStart,
		}
		body := junitBody(f)
		switch {
		case f.Status == model.Error || IsScanGap(f):
			c.Error = &junitProblem{Message: firstNonEmpty(f.Title, f.CanonicalID), Type: string(f.Severity), Body: body}
			s.Errors++
		case f.Status == model.Fail:
			c.Failure = &junitProblem{Message: firstNonEmpty(f.Title, f.CanonicalID), Type: string(f.Severity), Body: body}
			s.Failures++
		case f.Status == model.Skip:
			c.Skipped = &junitProblem{Message: firstNonEmpty(f.Title, "skipped")}
			s.Skipped++
		}
		s.Tests++
		s.Cases = append(s.Cases, c)
	}
	sort.Strings(names)
	for _, n := range names {
		s := byProv[n]
		doc.Tests += s.Tests
		doc.Failures += s.Failures
		doc.Errors += s.Errors
		doc.Skipped += s.Skipped
		doc.Suites = append(doc.Suites, *s)
	}
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

func junitBody(f model.Finding) string {
	var b strings.Builder
	if f.Description != "" {
		b.WriteString(f.Description + "\n")
	}
	fmt.Fprintf(&b, "resource: %s\n", firstNonEmpty(f.Resource.ID, f.Resource.Name))
	if f.Account != "" {
		fmt.Fprintf(&b, "account: %s\n", f.Account)
	}
	if f.Region != "" {
		fmt.Fprintf(&b, "region: %s\n", f.Region)
	}
	fmt.Fprintf(&b, "source: %s %s\n", f.Source, f.CheckID)
	if f.Remediation != "" {
		fmt.Fprintf(&b, "remediation: %s\n", f.Remediation)
	}
	fmt.Fprintf(&b, "fingerprint: %s", f.ID)
	return b.String()
}
