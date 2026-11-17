---
title: Reports
parent: User guide
nav_order: 6
---

# Reports
{: .no_toc }

Attckus can show its results in several forms: a visual HTML report for people, and machine-readable formats for CI and other tools.

1. TOC
{:toc}

---

## The HTML report

### Making one

| Command | What the report contains |
| --- | --- |
| `attckus test --html report.html` | Test results. If the suite has a `scan` folder (or you pass `--scan <folder>`), also what the agent can reach. |
| `attckus scan --format html my-repo/ > report.html` | What every agent can reach, with findings. |
| `attckus graph my-repo/ > report.html` | The same as `scan --format html`, but it never fails the build. Use it when you just want the picture. |

The report is a single file. It has no scripts and loads nothing from the internet, so you can open it offline, attach it to a CI run, add it to a ticket or email it. Light and dark mode follow your system setting.

### What's in it

**Summary tiles** at the top show, at a glance, how many scenarios passed and failed, how many agents were scanned, and how many findings there are of each severity.

**One card per test scenario** shows:

- the result (pass, fail, inconclusive or error), the kind of scenario, how long it took, and how many tool calls, blocks and failures it had;
- every check, with the reason for any failure;
- the control-run result, if the scenario had one;
- the **impact**: if the agent obeyed a planted instruction, what that agent's real permissions allow, with the path for each;
- where the evidence files are.

**One card per agent** shows:

- the eight yes/no answers ("Can it delete a database?" and so on), with the permission behind every "yes" and a note when production is affected;
- the **reach diagram**;
- every permission the agent can reach, in a table you can expand.

**Findings** list every problem per agent, with severity, rule number, path, evidence and a suggested fix.

### Reading the reach diagram

The diagram reads from left to right:

1. **The agent** is on the far left.
2. **Each column to the right is one more step away:** the service accounts it runs as, the AWS roles those get, the roles those can take on, and the MCP servers it uses. Box colours show the kind: agent, Kubernetes service account, AWS role or MCP server. The label also says which (`sa …`, `role …`, `mcp …`).
3. **On the far right are the powers.** Each identity or server links with dashed lines to up to four boxes, one per kind of power it grants, most dangerous first. Each box shows an example permission and how many more there are. The box's outline colour is its severity: red for critical, orange for high, yellow for medium, grey for low.

Hover over any box or line for the full text.

## Other formats

### Test results

| Format | Command | Use it for |
| --- | --- | --- |
| Text | `attckus test` | Reading in a terminal or CI log |
| JSON | `attckus test --format json` | Your own tooling and dashboards. Includes every check, the summary counts, the control-run comparison and the impact. |
| JUnit XML | `attckus test --format junit` | CI systems that show test results (GitHub, GitLab, Jenkins, CircleCI and others). Each scenario is a test case; inconclusive scenarios are shown as skipped. |

Progress lines go to stderr, and the results go to stdout, so you can redirect the results to a file safely.

### Scan results

| Format | Command | Use it for |
| --- | --- | --- |
| Text | `attckus scan` | Reading in a terminal |
| JSON | `attckus scan --format json` | Your own tooling. Includes every agent's permissions, yes/no answers and findings. |
| SARIF | `attckus scan --format sarif` | GitHub code scanning, and other tools that read SARIF 2.1.0. Findings appear in pull requests, linked to the agent's file. |
| Mermaid | `attckus scan --format mermaid` | Pasting a diagram into Markdown, a wiki, or a design doc. GitHub and GitLab render it. |
| HTML | `attckus scan --format html` | People (see above) |

### Audit logs

Every test scenario keeps an `audit.jsonl` in its evidence folder: one JSON line per event (each tool call, result, planted instruction and model call). To re-check one by hand:

```bash
attckus analyze .attckus/runs/20261106-101500/payments-outage/audit.jsonl
attckus analyze --format json --retry-threshold 3 audit.jsonl
```

This reports retry storms, runaway loops, duplicate actions, escalation, blocked attempts, budget problems and cost per agent.

## Secrets in reports

Attckus hides passwords and tokens wherever it reports them. A token found in an MCP config appears as, for example, `xoxb…REDACTED`. Tool call arguments with names that look like passwords, tokens or keys are hidden in the audit log. Even so, reports describe your permissions in detail; share them as you would share an architecture diagram, not publicly.
