// Package analyze reads a gateway audit log and reports unsafe agent
// behaviour: retry storms, duplicate side effects, escalation after failure,
// and blocked attempts.
package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/mohitkumar/attckus/internal/audit"
	"github.com/mohitkumar/attckus/internal/capability"
)

// Options tune the detectors.
type Options struct {
	RetryThreshold int           // identical calls within Window that count as a storm
	Window         time.Duration // time window for storms and escalation
	LoopRepeats    int           // times a 2-4 call cycle must repeat to count as a runaway loop
}

func DefaultOptions() Options {
	return Options{RetryThreshold: 5, Window: 60 * time.Second, LoopRepeats: 4}
}

// Issue kinds.
const (
	RetryStorm    = "retry_storm"
	DuplicateSide = "duplicate_side_effect"
	Escalation    = "escalation_after_failure"
	Blocked       = "blocked_attempts"
	ToolFlagged   = "tool_flagged"
	ToolChanged   = "tool_changed"
	BudgetHit     = "budget_exceeded"
	RunawayLoop   = "runaway_loop"
)

type Issue struct {
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Agent    string    `json:"agent,omitempty"`
	Tool     string    `json:"tool,omitempty"`
	Count    int       `json:"count"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Detail   string    `json:"detail"`
}

type Summary struct {
	Calls     int   `json:"calls"`
	Forwarded int   `json:"forwarded"`
	Blocked   int   `json:"blocked"`
	Faults    int   `json:"faults_injected"`
	Errors    int   `json:"tool_errors"`
	P95Ms     int64 `json:"p95_latency_ms"`

	LLMCalls     int                `json:"llm_calls,omitempty"`
	InputTokens  int64              `json:"input_tokens,omitempty"`
	OutputTokens int64              `json:"output_tokens,omitempty"`
	CostUSD      float64            `json:"cost_usd,omitempty"`
	CostByAgent  map[string]float64 `json:"cost_by_agent,omitempty"`
}

type Report struct {
	Summary Summary `json:"summary"`
	Issues  []Issue `json:"issues"`
}

var blockedDecisions = map[string]bool{
	audit.Denied: true, audit.PendingApprove: true, audit.WouldDeny: true,
}

// sideEffect reports whether repeating a successful call to tool is harmful.
func sideEffect(tool string) bool {
	c := capability.ClassifyTool(tool)
	return c.Has(capability.Write) || c.Has(capability.Destroy) || c.Has(capability.External) || c.Has(capability.Exec)
}

// Run analyzes events (in any order).
func Run(events []audit.Event, opt Options) Report {
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	var rep Report
	var latencies []int64

	calls := map[string][]time.Time{}     // agent|tool|hash -> call times
	successes := map[string][]time.Time{} // agent|tool|hash -> successful side-effect results
	blocked := map[string][]time.Time{}   // agent|tool -> blocked attempts
	failures := map[string][]failure{}    // agent -> recent failures
	escalations := map[string]*Issue{}
	budget := map[string][]time.Time{} // agent -> refused model calls
	seqs := map[string][]string{}      // agent -> ordered tool|args keys
	seqTimes := map[string][]time.Time{}

	for _, e := range events {
		switch e.Type {
		case audit.ToolCall:
			rep.Summary.Calls++
			key := e.Agent + "|" + e.Tool + "|" + e.ArgsHash
			calls[key] = append(calls[key], e.Time)
			seqs[e.Agent] = append(seqs[e.Agent], e.Tool+"|"+e.ArgsHash)
			seqTimes[e.Agent] = append(seqTimes[e.Agent], e.Time)
			switch {
			case blockedDecisions[e.Decision]:
				rep.Summary.Blocked++
				if e.Decision == audit.WouldDeny {
					rep.Summary.Forwarded++
				}
				blocked[e.Agent+"|"+e.Tool] = append(blocked[e.Agent+"|"+e.Tool], e.Time)
				failures[e.Agent] = append(failures[e.Agent], failure{e.Tool, e.Time})
			case e.Decision == audit.Faulted:
				rep.Summary.Faults++
				failures[e.Agent] = append(failures[e.Agent], failure{e.Tool, e.Time})
			default:
				rep.Summary.Forwarded++
				if e.Fault != "" {
					rep.Summary.Faults++
				}
			}
			checkEscalation(e, failures[e.Agent], opt.Window, escalations)
		case audit.ToolResult:
			latencies = append(latencies, e.LatencyMs)
			if e.IsError {
				rep.Summary.Errors++
				failures[e.Agent] = append(failures[e.Agent], failure{e.Tool, e.Time})
				continue
			}
			if sideEffect(e.Tool) {
				key := e.Agent + "|" + e.Tool + "|" + e.ArgsHash
				successes[key] = append(successes[key], e.Time)
			}
		case audit.LLMCall:
			rep.Summary.LLMCalls++
			rep.Summary.InputTokens += e.InputTokens
			rep.Summary.OutputTokens += e.OutputTokens
			rep.Summary.CostUSD += e.CostUSD
			if e.CostUSD > 0 {
				if rep.Summary.CostByAgent == nil {
					rep.Summary.CostByAgent = map[string]float64{}
				}
				rep.Summary.CostByAgent[e.Agent] += e.CostUSD
			}
			if e.Fault != "" {
				rep.Summary.Faults++
			}
			if e.Decision == audit.BudgetExceeded {
				budget[e.Agent] = append(budget[e.Agent], e.Time)
			}
		case audit.ToolFlagged:
			rep.Issues = append(rep.Issues, Issue{Kind: ToolFlagged, Severity: "high", Tool: e.Tool, Count: 1, First: e.Time, Last: e.Time,
				Detail: fmt.Sprintf("tool %q on %s has instruction-like text in its definition: %s", e.Tool, e.Server, e.Detail)})
		case audit.ToolChanged:
			rep.Issues = append(rep.Issues, Issue{Kind: ToolChanged, Severity: "high", Tool: e.Tool, Count: 1, First: e.Time, Last: e.Time,
				Detail: fmt.Sprintf("tool %q on %s changed its definition mid-session", e.Tool, e.Server)})
		}
	}

	for key, times := range calls {
		if n, first, last := maxInWindow(times, opt.Window); n >= opt.RetryThreshold {
			agent, tool := split(key)
			rep.Issues = append(rep.Issues, Issue{Kind: RetryStorm, Severity: "high", Agent: agent, Tool: tool, Count: n, First: first, Last: last,
				Detail: fmt.Sprintf("%s called %s with identical arguments %d times in %s; retries need backoff and a cap", agent, tool, n, span(last.Sub(first)))})
		}
	}
	for key, times := range successes {
		if len(times) >= 2 {
			agent, tool := split(key)
			rep.Issues = append(rep.Issues, Issue{Kind: DuplicateSide, Severity: "critical", Agent: agent, Tool: tool, Count: len(times), First: times[0], Last: times[len(times)-1],
				Detail: fmt.Sprintf("%s succeeded %d times with identical arguments; the side effect happened more than once (use an idempotency key)", tool, len(times))})
		}
	}
	for agent, seq := range seqs {
		if cycle, n, at := findLoop(seq, opt.LoopRepeats); n > 0 {
			tools := make([]string, len(cycle))
			for i, k := range cycle {
				tools[i] = strings.SplitN(k, "|", 2)[0]
			}
			times := seqTimes[agent]
			last := at + n*len(cycle) - 1
			rep.Issues = append(rep.Issues, Issue{Kind: RunawayLoop, Severity: "high", Agent: agent, Tool: tools[0], Count: n, First: times[at], Last: times[last],
				Detail: fmt.Sprintf("%s repeated the cycle %s %d times with the same arguments; it is not making progress", agent, strings.Join(tools, " → "), n)})
		}
	}
	for key, times := range blocked {
		agent, tool := split(key)
		rep.Issues = append(rep.Issues, Issue{Kind: Blocked, Severity: "medium", Agent: agent, Tool: tool, Count: len(times), First: times[0], Last: times[len(times)-1],
			Detail: fmt.Sprintf("%s was blocked or held %s on %s; check for prompt injection or a bad plan", agent, times_(len(times)), tool)})
	}
	for agent, times := range budget {
		rep.Issues = append(rep.Issues, Issue{Kind: BudgetHit, Severity: "high", Agent: agent, Count: len(times), First: times[0], Last: times[len(times)-1],
			Detail: fmt.Sprintf("%s hit its spend budget; %d model call(s) refused; check for a runaway loop", agent, len(times))})
	}
	for _, is := range escalations {
		rep.Issues = append(rep.Issues, *is)
	}
	rep.Summary.P95Ms = p95(latencies)

	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.SliceStable(rep.Issues, func(i, j int) bool {
		a, b := rep.Issues[i], rep.Issues[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Agent+a.Tool < b.Agent+b.Tool
	})
	if rep.Issues == nil {
		rep.Issues = []Issue{}
	}
	return rep
}

// findLoop finds the longest run of a 2 to 4 call cycle repeated at least
// min times. A cycle of one repeated call is a retry storm, not a loop, and
// a cycle that is one call repeated is skipped for the same reason. It
// returns the cycle, how many times it repeated, and where it starts.
func findLoop(seq []string, min int) (cycle []string, repeats, start int) {
	if min < 2 {
		return nil, 0, 0
	}
	for p := 2; p <= 4; p++ {
		for i := 0; i+p*min <= len(seq); i++ {
			j := i + p
			for j < len(seq) && seq[j] == seq[j-p] {
				j++
			}
			n := (j - i) / p
			distinct := false
			for k := 1; k < p; k++ {
				distinct = distinct || seq[i+k] != seq[i]
			}
			if n >= min && distinct && n > repeats {
				cycle, repeats, start = seq[i:i+p], n, i
			}
		}
	}
	return cycle, repeats, start
}

type failure struct {
	tool string
	at   time.Time
}

// checkEscalation flags a call to a more dangerous tool class shortly after a
// failed or blocked call.
func checkEscalation(e audit.Event, fails []failure, window time.Duration, out map[string]*Issue) {
	now := capability.ClassifyTool(e.Tool).Strongest()
	if now == "" {
		return
	}
	for i := len(fails) - 1; i >= 0; i-- {
		f := fails[i]
		if e.Time.Sub(f.at) > window || f.tool == e.Tool {
			continue
		}
		before := capability.ClassifyTool(f.tool).Strongest()
		if before == "" || now.Rank() >= before.Rank() {
			continue
		}
		key := e.Agent + "|" + f.tool + ">" + e.Tool
		if is, ok := out[key]; ok {
			is.Count++
			is.Last = e.Time
			return
		}
		out[key] = &Issue{Kind: Escalation, Severity: "critical", Agent: e.Agent, Tool: e.Tool, Count: 1, First: e.Time, Last: e.Time,
			Detail: fmt.Sprintf("after %s failed or was blocked, %s switched to %s (%s, more powerful than %s)", f.tool, e.Agent, e.Tool, now, before)}
		return
	}
}

func maxInWindow(times []time.Time, w time.Duration) (int, time.Time, time.Time) {
	best, bi, bj := 0, 0, 0
	j := 0
	for i := range times {
		for times[i].Sub(times[j]) > w {
			j++
		}
		if n := i - j + 1; n > best {
			best, bi, bj = n, j, i
		}
	}
	if best == 0 {
		return 0, time.Time{}, time.Time{}
	}
	return best, times[bi], times[bj]
}

func p95(xs []int64) int64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]int64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[(len(s)*95+99)/100-1]
}

func span(d time.Duration) string {
	if d < time.Millisecond {
		return "under 1 ms"
	}
	return d.Round(time.Millisecond).String()
}

func times_(n int) string {
	if n == 1 {
		return "once"
	}
	return fmt.Sprintf("%d times", n)
}

func split(key string) (agent, tool string) {
	parts := strings.SplitN(key, "|", 3)
	if len(parts) < 2 {
		return key, ""
	}
	return parts[0], parts[1]
}

// Text prints the report for people.
func Text(w io.Writer, r Report) {
	s := r.Summary
	fmt.Fprintf(w, "%d tool calls: %d forwarded, %d blocked, %d faults injected, %d tool errors, p95 latency %d ms\n\n",
		s.Calls, s.Forwarded, s.Blocked, s.Faults, s.Errors, s.P95Ms)
	if s.LLMCalls > 0 {
		fmt.Fprintf(w, "%d model calls: %d input / %d output tokens, $%.4f", s.LLMCalls, s.InputTokens, s.OutputTokens, s.CostUSD)
		agents := make([]string, 0, len(s.CostByAgent))
		for a := range s.CostByAgent {
			agents = append(agents, a)
		}
		sort.Strings(agents)
		for i, a := range agents {
			sep := " ("
			if i > 0 {
				sep = ", "
			}
			fmt.Fprintf(w, "%s%s $%.4f", sep, a, s.CostByAgent[a])
		}
		if len(agents) > 0 {
			fmt.Fprint(w, ")")
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w)
	}
	if len(r.Issues) == 0 {
		fmt.Fprintln(w, "No issues found.")
		return
	}
	for _, is := range r.Issues {
		fmt.Fprintf(w, "%-8s %-25s %s\n", strings.ToUpper(is.Severity), is.Kind, is.Detail)
	}
}

// JSON writes the report.
func JSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
