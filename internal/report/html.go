package report

import (
	_ "embed"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/mohitkumar/groot/internal/risk"
	"github.com/mohitkumar/groot/internal/suite"
)

//go:embed report.html.tmpl
var htmlTemplate string

// HTMLData is everything one HTML report shows. Either part may be nil.
type HTMLData struct {
	Title     string
	Generated time.Time
	Test      *suite.Report
	Scan      *risk.Result
}

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
	"join":  strings.Join,
	"sev":   func(s risk.Severity) string { return s.String() },
	"svg": func(r *risk.Result, a risk.AgentResult) template.HTML {
		return ReachSVG(r, a)
	},
	"secs": func(ms int64) string {
		return time.Duration(ms * int64(time.Millisecond)).Round(100 * time.Millisecond).String()
	},
	"findings": func(r *risk.Result, agent string) []risk.Finding {
		var out []risk.Finding
		for _, f := range r.Findings {
			if f.Agent == agent {
				out = append(out, f)
			}
		}
		return out
	},
	"yesCount": func(as []risk.Answer) int {
		n := 0
		for _, a := range as {
			if a.Yes {
				n++
			}
		}
		return n
	},
	"testCounts": func(r *suite.Report) map[string]int {
		c := map[string]int{}
		for _, res := range r.Results {
			c[res.Status]++
		}
		return c
	},
	"sevCounts": func(r *risk.Result) map[string]int {
		c := map[string]int{}
		for _, f := range r.Findings {
			c[f.Severity.String()]++
		}
		return c
	},
}).Parse(htmlTemplate))

// HTML writes a self-contained HTML report: test results, what each agent
// can reach (with a graph), and scan findings. No scripts or external assets.
func HTML(w io.Writer, d HTMLData) error {
	if d.Title == "" {
		d.Title = "Groot report"
	}
	if d.Generated.IsZero() {
		d.Generated = time.Now().UTC()
	}
	return tmpl.Execute(w, d)
}
