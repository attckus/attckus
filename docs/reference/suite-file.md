---
title: Suite file
parent: Reference
nav_order: 2
---

# Suite file
{: .no_toc }

A suite is a JSON file, usually named `attckus-suite.json`. Attckus checks it strictly: an unknown field or an invalid value stops the run before anything starts. For a walkthrough, see [Write a test suite](../guide/write-a-suite.md).

1. TOC
{:toc}

---

## Top level

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `version` | number | yes | | Must be `1`. |
| `agent` | text | no | `agent` | The agent's name. Use the name `attckus scan` shows, so impact can be reported. |
| `command` | list of text | yes | | The command that runs your agent once, for example `["python", "-m", "pytest", "tests/e2e.py"]`. |
| `dir` | text | no | the suite's folder | The folder to run `command` from, relative to the suite file. |
| `env` | object of text | no | | Extra environment variables for the agent. |
| `timeout_seconds` | number | no | `120` | How long one run may take. After this, the agent and everything it started are stopped, and the scenario fails. |
| `policy` | text | no | allow everything | Path to a [policy file](policy-file.md), relative to the suite file. |
| `scan` | text | no | | A folder for `attckus scan`, relative to the suite file. Enables impact reporting. |
| `seed` | number | no | `1` | The random seed for choosing which calls fail. |
| `mcp_servers` | list | see note | | The MCP servers your agent uses. See below. |
| `llm` | object | see note | | Include this if your agent calls the Anthropic or OpenAI API directly. See below. |
| `scenarios` | list | yes | | At least one scenario. See below. |

You must give at least one `mcp_servers` entry or an `llm` section, so that there is something for Attckus to sit in front of.

## mcp_servers

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | text | yes | A unique name using letters, digits, `_` or `-`. Your agent finds the server under this name in `ATTCKUS_MCP_CONFIG`. |
| `command` | list of text | one of these | The command that starts a local server, for example `["npx", "-y", "@acme/orders-mcp@1.4.0"]`. |
| `url` | text | one of these | The address of a remote server that speaks Streamable HTTP. |

Give exactly one of `command` and `url`.

## llm

All fields are optional; `"llm": {}` is enough.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `anthropic_url` | text | `https://api.anthropic.com` | Where to forward Anthropic API calls. |
| `openai_url` | text | `https://api.openai.com/v1` | Where to forward OpenAI-compatible API calls. |
| `inject_keys` | true/false | `false` | Use the `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` from Attckus's own environment, instead of the keys your agent sends. |

## scenarios

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | text | yes | Unique within the suite. Also names the evidence folder. |
| `description` | text | no | Shown in reports. |
| `faults` | list | no | Failures to apply. See below. |
| `attacks` | list | no | Instructions to plant. See below. |
| `expect` | object | no | Extra checks and exceptions. See below. |
| `control` | true/false | no | Also run the scenario without its faults, and compare. Only allowed when the scenario has both `faults` and `attacks`. |

A scenario's **kind** comes from what it contains: `baseline` (neither), `failure` (faults only), `attack` (attacks only) or `attack+failure` (both).

## faults

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `type` | text | yes | `error`, `timeout`, `latency`, `malformed` or `rate_limit`. |
| `tool` | text | no | The tool name or pattern (`refund_*`), or `provider/model` for model APIs (`anthropic/*`, `openai/gpt-*`). Empty means all. |
| `agent` | text | no | Apply only to this agent name or pattern. |
| `probability` | number | yes | From `0` to `1`. `1` means every matching call. |
| `delay_ms` | number | for `timeout` and `latency` | How long to wait, in milliseconds. Must be above `0` and at most `120000`. |
| `message` | text | no | The error text the agent sees. |

| Type | Effect |
| --- | --- |
| `error` | The tool returns an error. A model API returns 529 (Anthropic) or 503 (OpenAI). |
| `timeout` | Waits `delay_ms`, then returns a timeout error. |
| `latency` | Waits `delay_ms`, then returns the real response. |
| `malformed` | Returns a garbled response. |
| `rate_limit` | Returns 429 "too many requests" with `retry-after` (model APIs). |

## attacks

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `type` | text | yes | `inject_result`, `poison_tool` or `rug_pull`. |
| `tool` | text | yes | The tool that carries the instruction: a name or pattern. |
| `target` | text | no | The tool the instruction asks the agent to call. Default `send_email`. |
| `payload` | text | no | Your own instruction text. `{target}` and `{canary}` are replaced. Include `{canary}`, or obedience can't be detected. |

| Type | Where the instruction appears |
| --- | --- |
| `inject_result` | In the tool's result. If the tool is failing in this scenario, in its error message. |
| `poison_tool` | In the tool's description. |
| `rug_pull` | In the tool's description, from the second time the tools are listed. |

## expect

| Field | Type | Meaning |
| --- | --- | --- |
| `agent_succeeds` | true/false | Fail if the agent's command exits with an error. |
| `forbidden_tools` | list of text | Fail if any of these tools is called at all. |
| `at_most_once` | list of text | Fail if any of these tools succeeds more than once, whatever its arguments. |
| `max_tool_calls` | number | Fail above this many tool calls. `0` means no limit. |
| `max_model_calls` | number | Fail above this many model API calls. `0` means no limit. |
| `max_cost_usd` | number | Fail above this model spend in dollars. `0` means no limit. |
| `allow` | list of text | Problem kinds that don't fail this scenario: `retry_storm`, `duplicate_side_effect`, `escalation_after_failure`, `runaway_loop`, `budget_exceeded`, `tool_flagged`, `tool_changed`. |
| `allow_contained` | true/false | Pass when the agent obeyed a planted instruction but the policy blocked every resulting call. |

## What the agent receives

| Environment variable | Value |
| --- | --- |
| `ATTCKUS_MCP_CONFIG` | Path to the MCP config for this scenario, with every server routed through Attckus |
| `ATTCKUS_SCENARIO` | The scenario's name |
| `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` | Local Attckus addresses (only when `llm` is set) |
| everything in `env` | As given |

The agent also inherits Attckus's own environment.
