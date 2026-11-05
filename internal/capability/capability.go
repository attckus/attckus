// Package capability is the shared vocabulary of what an action or tool can
// do. The scanner uses it to rank grants; the gateway and analyzer use it to
// classify tool calls. Keeping one model means a tool the scanner calls
// "destroy" is the same tool the default policy denies.
package capability

import (
	"regexp"
	"sort"
	"strings"
)

// Class is one kind of power.
type Class string

const (
	Admin     Class = "admin"     // change permissions or become someone else
	Exec      Class = "exec"      // run arbitrary code or commands
	Destroy   Class = "destroy"   // delete or terminate data or infrastructure
	Secrets   Class = "secrets"   // read credentials
	Write     Class = "write"     // create or modify data
	External  Class = "external"  // send data outside the company (messages, email, web requests)
	Untrusted Class = "untrusted" // read content an attacker can control (web, email, issues)
	Read      Class = "read"      // read private data
)

// rank orders classes from most to least dangerous.
var rank = map[Class]int{Admin: 0, Exec: 1, Destroy: 2, Secrets: 3, Write: 4, External: 5, Untrusted: 6, Read: 7}

// Rank returns a sort key; lower is more dangerous.
func (c Class) Rank() int {
	if r, ok := rank[c]; ok {
		return r
	}
	return 99
}

// Set is a small set of classes.
type Set map[Class]bool

func NewSet(cs ...Class) Set {
	s := Set{}
	for _, c := range cs {
		s[c] = true
	}
	return s
}

func (s Set) Add(other Set) {
	for c := range other {
		s[c] = true
	}
}

func (s Set) Has(c Class) bool { return s[c] }

// Sorted returns classes most dangerous first.
func (s Set) Sorted() []Class {
	out := make([]Class, 0, len(s))
	for c := range s {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rank() < out[j].Rank() })
	return out
}

// Strongest returns the most dangerous class in s, or "" if empty.
func (s Set) Strongest() Class {
	sorted := s.Sorted()
	if len(sorted) == 0 {
		return ""
	}
	return sorted[0]
}

// Trifecta reports whether a set of capabilities lets prompt injection
// exfiltrate data: private data + untrusted input + an external channel.
// See https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
func Trifecta(s Set) bool {
	private := s[Read] || s[Secrets] || s[Write] || s[Destroy] || s[Admin] || s[Exec]
	return private && s[Untrusted] && s[External]
}

// ---------------------------------------------------------------------------
// Tool classification by name and description.

var toolPatterns = []struct {
	class Class
	re    *regexp.Regexp
}{
	{Exec, regexp.MustCompile(`(?i)(^|_|-)(exec|execute|run|shell|bash|command|cmd|eval|spawn|terminal)($|_|-)`)},
	{Admin, regexp.MustCompile(`(?i)(^|_|-)(grant|permission|role|policy|impersonate|assume)($|_|-)`)},
	{Destroy, regexp.MustCompile(`(?i)(^|_|-)(delete|remove|rm|drop|truncate|destroy|purge|terminate|wipe|kill)($|_|-)`)},
	{Secrets, regexp.MustCompile(`(?i)(^|_|-)(secret|secrets|credential|credentials|password|token|apikey|api_key)($|_|-)`)},
	{External, regexp.MustCompile(`(?i)(^|_|-)(send|email|mail|post|message|notify|publish|tweet|comment|reply|webhook|sms)($|_|-)`)},
	{Untrusted, regexp.MustCompile(`(?i)(^|_|-)(fetch|browse|scrape|crawl|navigate|search_web|web|url|inbox|read_email)($|_|-)`)},
	{Write, regexp.MustCompile(`(?i)(^|_|-)(create|update|write|edit|put|set|insert|upsert|patch|move|rename|push|merge|refund|pay|transfer|charge|deploy|apply)($|_|-)`)},
	{Read, regexp.MustCompile(`(?i)(^|_|-)(get|read|list|query|search|describe|show|find|lookup|select|download)($|_|-)`)},
}

// ClassifyTool returns the classes a tool name suggests. Names are split on
// camelCase as well, so "deleteOrder" and "delete_order" agree.
func ClassifyTool(name string) Set {
	norm := splitCamel(name)
	s := Set{}
	for _, p := range toolPatterns {
		if p.re.MatchString(norm) {
			s[p.class] = true
		}
	}
	return s
}

var camel = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func splitCamel(s string) string {
	return strings.ToLower(camel.ReplaceAllString(s, "${1}_${2}"))
}
