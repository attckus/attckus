---
title: Policy file
parent: Reference
nav_order: 3
---

# Policy file
{: .no_toc }

A policy is a JSON file that sets the permission boundary for a test. Groot checks it strictly: an unknown field or an invalid value is an error. For a walkthrough, see [Set a permission boundary](../guide/permission-boundary.md).

1. TOC
{:toc}

---

## Top level

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `version` | number | | Must be `1`. |
| `mode` | text | `enforce` | `enforce`: blocked calls are refused. `dry-run`: blocked calls are recorded as `would_deny` and still go through. |
| `default` | text | `allow` | The action when no rule matches: `allow`, `deny` or `approve`. |
| `rules` | list | | Checked from top to bottom; the first match decides. |
| `tool_checks` | object | all off | Checks on the tool lists servers send. |
| `chaos` | object | | Failures to apply. Normally written by `groot test` from the scenario's `faults`; you rarely set it yourself. |
| `llm` | object | | Rules for model API calls. |

## rules

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | text | yes | Shown in results and in the message the agent sees. |
| `agent` | text | no | Agent name or pattern. Empty matches all. |
| `server` | text | no | MCP server name (from the suite) or pattern. Empty matches all. |
| `tool` | text | no | Tool name or pattern. Empty matches all. |
| `args` | object | no | Checks on named arguments. All must hold. See below. |
| `action` | text | yes | `allow`, `deny` or `approve`. |
| `reason` | text | no | Shown to the agent when the call is blocked. |

Patterns use `*` for any run of characters and `?` for one character, for example `delete_*` or `*_admin`.

### args

Each key is an argument name; each value is a check:

| Check | Holds when the argument |
| --- | --- |
| `equals` | is exactly this text |
| `prefix` | starts with this text |
| `match` | matches this regular expression |
| `not_match` | does not match this regular expression |

Arguments that aren't text are compared using their JSON form. A missing argument fails `equals`, `prefix` and `match`, and passes `not_match`.

### actions

| Action | Effect during a test |
| --- | --- |
| `allow` | The call goes through. |
| `deny` | The call is refused. The agent gets a tool error: "Blocked by groot policy (name): reason." |
| `approve` | The call is held for a human, which never happens in a test, so it is refused. The agent is told a human must approve it and not to retry. |

## tool_checks

| Field | Meaning |
| --- | --- |
| `hide_denied` | Remove tools a rule always denies from the tool list. |
| `flag_injection` | Flag tools whose description looks like it contains planted instructions. Fails the scenario. |
| `hide_flagged` | Also remove flagged tools. |
| `alert_on_change` | Record a tool whose description changes during the run. Fails the scenario. |
| `block_changed_tools` | Also refuse calls to changed tools. |

## chaos

| Field | Meaning |
| --- | --- |
| `enabled` | Whether failures apply. |
| `seed` | Random seed. |
| `allow_prod` | Allow failures in an environment named `prod`, `production` or `prod-*`. Tests run in an environment named `test`, so this rarely matters. |
| `faults` | A list of faults, as in the [suite file](suite-file.md#faults). |

## llm

| Field | Meaning |
| --- | --- |
| `models` | A list of allowed models as `provider/model` patterns, such as `anthropic/claude-*`. Calls to other models are refused. Empty allows all. |
| `budgets` | A list of `{"agent": pattern, "usd": amount}`. The first matching entry is the agent's spending limit for one scenario. Must be above `0`. |

Budgets are not enforced in `dry-run` mode. When a budget runs out, model calls get a 429 "too many requests" error, and the scenario fails with "budget hit". Models with no known price can't be budgeted, so calls to them are refused when a budget applies; see [Troubleshooting](../troubleshooting.md).

## The starting policy

`groot policy init` writes:

| Rule | Tool pattern | Action |
| --- | --- | --- |
| no command execution | `*exec*` | deny |
| no shell | `*shell*` | deny |
| no deletes | `delete*` | deny |
| no drops | `drop*` | deny |
| no removes | `remove*` | deny |
| read-only SQL | `*query*`, when `sql` doesn't contain drop, delete, truncate, update, insert, alter or grant | allow |
| block SQL writes | `*query*` | deny |
| approve outbound messages | `send*` | approve |
| approve slack posts | `*post_message*` | approve |
| approve merges | `merge*` | approve |

with `mode: enforce`, `default: allow`, and `tool_checks` `hide_denied`, `flag_injection` and `alert_on_change` on.
