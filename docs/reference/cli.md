---
title: Command line
parent: Reference
nav_order: 1
---

# Command line
{: .no_toc }

1. TOC
{:toc}

---

## attckus test

Runs every scenario in a suite against your agent and reports the results.

```
attckus test [--suite attckus-suite.json] [--format text|json|junit] [--html file] [--scan folder]
           [--scenario name]... [--out folder] [--strict]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--suite` | `attckus-suite.json` | The suite file to run. |
| `--format` | `text` | How to print results on stdout: `text`, `json` or `junit`. |
| `--html` | (none) | Also write the HTML report to this file. |
| `--scan` | the suite's `scan` | A folder to scan, so obeyed injections report what the agent can reach. |
| `--scenario` | all | Run only the scenario with this name. Repeat the flag to run several. |
| `--out` | `.attckus/runs/<date-time>` | Where to keep each scenario's evidence. |
| `--strict` | off | Treat inconclusive scenarios as failures. |

Progress lines are printed on stderr as each scenario finishes.

**Exit code:** `0` if every scenario passed (or was inconclusive, without `--strict`); `1` if any failed or errored; `2` if the suite is invalid, the scan folder can't be read, no scenario matched `--scenario`, or the output couldn't be written.

## attckus scan

Reads a folder and reports what each agent can reach.

```
attckus scan [--format text|json|sarif|mermaid|html] [--fail-on critical|high|medium|low|none] [folder]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--format` | `text` | `text`, `json`, `sarif` (2.1.0), `mermaid` or `html`. |
| `--fail-on` | `critical` | Exit with code `1` if any finding is at this severity or above. `none` never fails. |
| `folder` | `.` | The folder to scan. |

Warnings about files that couldn't be read are printed on stderr; the scan continues.

**Exit code:** `0` if no finding reaches `--fail-on`; `1` if one does; `2` for a bad flag or an unreadable folder.

## attckus graph

```
attckus graph [folder]
```

The same as `attckus scan --format html --fail-on none`: writes the HTML reach report to stdout and always exits `0` when the scan ran.

## attckus analyze

Re-checks an audit log by hand. `attckus test` already does this for every scenario.

```
attckus analyze [--format text|json] [--retry-threshold 5] [--window 60s] audit.jsonl
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--format` | `text` | `text` or `json`. |
| `--retry-threshold` | `5` | How many identical calls within the window count as a retry storm. |
| `--window` | `60s` | The time window for retry storms and for escalation after failure. Any Go duration, such as `30s` or `2m`. |

**Exit code:** `1` if any critical or high issue is found; `0` otherwise; `2` for a bad flag or an unreadable file.

## attckus policy init

Writes a starting policy.

```
attckus policy init [--out policy.json]
```

Without `--out`, the policy is printed on stdout. With `--out`, it is written to that file. Attckus refuses to overwrite an existing file (exit code `1`).

## attckus policy check

Validates a policy file with the same checks `attckus test` uses.

```
attckus policy check policy.json
```

Prints `ok: <n> rules, mode <mode>, default <action>, <failures note>` and exits `0`, or prints the problem and exits `1`.

## attckus version

```
attckus version
```

Prints the version.

## attckus gateway stdio (internal)

```
attckus gateway stdio --policy p.json [flags] -- <server command...>
```

This is the go-between `attckus test` puts in front of local MCP servers, by writing it into the MCP config it gives your agent. You don't need to run it yourself.
