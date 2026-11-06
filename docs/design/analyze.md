# groot analyze

```
groot analyze [--format text|json] [--retry-threshold 5] [--window 60s] audit.jsonl
```

## Use case

Every `groot test` scenario leaves an `audit.jsonl` of what the agent did: each tool call, its decision, the faults injected, results and model calls. The test runner analyzes it automatically to decide pass or fail. `groot analyze` runs the same detectors on any audit log by hand, for example to re-check a kept evidence directory with a different threshold.

The questions it answers: did the agent hammer a failing tool, repeat a side effect, loop without progress, reach for a more powerful tool after one failed, or run out of budget? It exits 1 on any critical or high issue.

## Design

```mermaid
flowchart LR
  log[(audit.jsonl)] --> read[audit.Read]
  read --> sort[Sort by time]
  sort --> pass["Single pass: counters, per-key call times, per-agent call sequence, successes, blocked, failures"]
  pass --> esc[Escalation check per tool_call]
  pass --> post["Post-pass detectors: retry storm, runaway loop, duplicate side effect, blocked, budget"]
  esc --> issues
  post --> issues[Issues sorted by severity]
  issues --> out[text or JSON]
```

Detectors:

| Detector | Rule | Severity |
| --- | --- | --- |
| Retry storm | same agent, tool and argument hash at least `--retry-threshold` times within `--window` | high |
| Runaway loop | a cycle of 2 to 4 distinct (tool, argument hash) calls repeated at least 4 times in a row (`Options.LoopRepeats`); changing arguments, such as paging, is progress and is not flagged | high |
| Duplicate side effect | a write, destroy, external or exec tool succeeds twice with identical arguments | critical |
| Escalation after failure | within `--window` of a failed or blocked call, a call to a strictly more powerful tool class | critical |
| Budget exceeded | model calls refused by the model API proxy's budget | high |
| Flagged or changed tools | from the proxy's `tools/list` checks | high |
| Blocked attempts | denials and approval holds per agent and tool | medium |

Design choices:

- **Argument hashes, not arguments.** The audit log redacts sensitive values, but the hash is computed on the raw arguments, so identical calls are still detected.
- **Tool classes come from names.** `capability.ClassifyTool` splits snake_case and camelCase names and matches verbs, so the analyzer needs no server metadata. Side effects are write, destroy, external or exec; escalation compares `Strongest()` ranks.
- **Order-independent input.** Events are sorted by time first, so logs appended by several proxies can be analyzed together.
- **Dry-run counts.** `would_deny` calls count as blocked (for escalation and blocked attempts) and as forwarded, since they really reached the server.

Per-scenario limits that need the suite (`at_most_once`, call and cost caps) are checked by the test runner, not here; see [test.md](test.md).

## Data flow

| Event type | Effect |
| --- | --- |
| `tool_call` | call counted; time added under `agent|tool|hash`; appended to the agent's call sequence; blocked decisions also go to `blocked` and `failures`; `fault_injected` counts as a fault and a failure; escalation is checked |
| `tool_result` | latency recorded; errors are counted and become failures; successful side-effect results go to `successes` |
| `llm_call` | model call count, tokens, cost (total and per agent), faults; `budget_exceeded` recorded |
| `tool_flagged`, `tool_changed` | one high issue each |

Output is a `Report{Summary, Issues}`. `Summary` holds calls, forwarded, blocked, faults, tool errors, p95 latency, and the model totals.

## Where the code lives

| Step | Code |
| --- | --- |
| Flags, output, exit code | `analyzeCmd` in `cmd/groot/main.go` |
| Reading the log | `audit.Read` in `internal/audit/audit.go` |
| Main pass and post-pass detectors | `Run` in `internal/analyze/analyze.go` |
| Escalation | `checkEscalation` |
| Retry storm window | `maxInWindow` |
| Runaway loop | `findLoop` |
| Rendering | `Text`, `JSON` |

## Failure modes

| Situation | Behaviour |
| --- | --- |
| Wrong argument count, unreadable file | exit 2 |
| Malformed line | skipped |
| Line longer than 8 MiB | scanner error, exit 2 |
| Empty log | empty report, exit 0 |
