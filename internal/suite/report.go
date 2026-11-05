package suite

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// Text prints a human summary.
func Text(w io.Writer, r Report) {
	counts := map[string]int{}
	for _, res := range r.Results {
		counts[res.Status]++
		fmt.Fprintf(w, "\n%s  %s  (%s, %.1fs)\n", badge(res.Status), res.Scenario, res.Kind, float64(res.DurationMs)/1000)
		if res.Description != "" {
			fmt.Fprintf(w, "   %s\n", res.Description)
		}
		if res.Error != "" {
			fmt.Fprintf(w, "   error: %s\n", res.Error)
		}
		for _, c := range res.Checks {
			mark := "✓"
			if !c.Pass {
				mark = "✗"
			}
			line := fmt.Sprintf("   %s %s", mark, c.Name)
			if c.Detail != "" && (!c.Pass || strings.Contains(c.Detail, "contained")) {
				line += ": " + c.Detail
			}
			fmt.Fprintln(w, line)
		}
		s := res.Summary
		fmt.Fprintf(w, "   %d tool calls, %d blocked, %d faults", s.Calls, s.Blocked, s.Faults)
		if s.LLMCalls > 0 {
			fmt.Fprintf(w, ", %d model calls ($%.4f)", s.LLMCalls, s.CostUSD)
		}
		fmt.Fprintf(w, " · evidence in %s\n", res.Dir)
	}
	fmt.Fprintf(w, "\n%d scenarios: %d passed, %d failed, %d inconclusive, %d errors\n",
		len(r.Results), counts[Pass], counts[Fail], counts[Inconclusive], counts[Error])
}

func badge(status string) string {
	switch status {
	case Pass:
		return "PASS        "
	case Fail:
		return "FAIL        "
	case Inconclusive:
		return "INCONCLUSIVE"
	}
	return "ERROR       "
}

// JSON writes the report.
func JSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// JUnit writes JUnit XML, which most CI systems display natively.
func JUnit(w io.Writer, r Report) error {
	type failure struct {
		Message string `xml:"message,attr"`
		Text    string `xml:",chardata"`
	}
	type skipped struct {
		Message string `xml:"message,attr"`
	}
	type testcase struct {
		Name      string   `xml:"name,attr"`
		Classname string   `xml:"classname,attr"`
		Time      string   `xml:"time,attr"`
		Failure   *failure `xml:"failure,omitempty"`
		Error     *failure `xml:"error,omitempty"`
		Skipped   *skipped `xml:"skipped,omitempty"`
	}
	type suite struct {
		XMLName  xml.Name   `xml:"testsuite"`
		Name     string     `xml:"name,attr"`
		Tests    int        `xml:"tests,attr"`
		Failures int        `xml:"failures,attr"`
		Errors   int        `xml:"errors,attr"`
		Skipped  int        `xml:"skipped,attr"`
		Cases    []testcase `xml:"testcase"`
	}
	s := suite{Name: "groot: " + r.Agent, Tests: len(r.Results)}
	for _, res := range r.Results {
		tc := testcase{Name: res.Scenario, Classname: "groot." + res.Kind, Time: fmt.Sprintf("%.3f", float64(res.DurationMs)/1000)}
		var lines []string
		for _, c := range res.Checks {
			if !c.Pass {
				lines = append(lines, c.Name+": "+c.Detail)
			}
		}
		switch res.Status {
		case Fail:
			s.Failures++
			tc.Failure = &failure{Message: lines[0], Text: strings.Join(lines, "\n")}
		case Error:
			s.Errors++
			tc.Error = &failure{Message: res.Error, Text: res.Error}
		case Inconclusive:
			s.Skipped++
			tc.Skipped = &skipped{Message: "attack was not delivered"}
		}
		s.Cases = append(s.Cases, tc)
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(s); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
