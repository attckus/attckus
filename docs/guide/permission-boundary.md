---
title: Set a permission boundary
parent: User guide
nav_order: 4
---

# Set a permission boundary
{: .no_toc }

A policy is the set of rules for what your agent may call during a test. This guide shows how to write one and what it tells you. Every field is listed in the [policy file reference](../reference/policy-file.md).

1. TOC
{:toc}

---

## Why test with a boundary

A test without a policy tells you whether your agent can be fooled. A test with a policy also tells you **whether being fooled would matter**. These are different risks:

| Agent | Boundary | Risk |
| --- | --- | --- |
| Easily fooled | Lets it do anything | High: one planted instruction can cause real damage |
| Easily fooled | Blocks dangerous calls | Lower: the agent is fooled, but the harm is contained |
| Hard to fool | Lets it do anything | Depends on how hard; one new attack could change this |
| Hard to fool | Blocks dangerous calls | Lowest |

When the agent obeys a planted instruction and the policy blocks everything it tries, Groot calls the result **contained**. That still fails by default, because the agent was fooled. You can accept it with `"allow_contained": true` when you only want to check the boundary.

## Start from the default

```bash
groot policy init --out groot-policy.json
```

This writes:

```json
{
  "version": 1,
  "mode": "enforce",
  "default": "allow",
  "rules": [
    {"name": "no command execution", "tool": "*exec*", "action": "deny", "reason": "agents may not run arbitrary commands"},
    {"name": "no shell", "tool": "*shell*", "action": "deny", "reason": "agents may not run arbitrary commands"},
    {"name": "no deletes", "tool": "delete*", "action": "deny", "reason": "destructive tools are denied by default"},
    {"name": "no drops", "tool": "drop*", "action": "deny", "reason": "destructive tools are denied by default"},
    {"name": "no removes", "tool": "remove*", "action": "deny", "reason": "destructive tools are denied by default"},
    {"name": "read-only SQL", "tool": "*query*",
     "args": {"sql": {"not_match": "(?i)\\b(drop|delete|truncate|update|insert|alter|grant)\\b"}}, "action": "allow"},
    {"name": "block SQL writes", "tool": "*query*", "action": "deny", "reason": "only read-only SQL is allowed"},
    {"name": "approve outbound messages", "tool": "send*", "action": "approve", "reason": "outbound messages need a human"},
    {"name": "approve slack posts", "tool": "*post_message*", "action": "approve", "reason": "outbound messages need a human"},
    {"name": "approve merges", "tool": "merge*", "action": "approve", "reason": "merges need a human"}
  ],
  "tool_checks": {"hide_denied": true, "flag_injection": true, "alert_on_change": true}
}
```

Then point the suite at it with `"policy": "groot-policy.json"`.

## How rules work

Rules are checked from top to bottom, and **the first rule that matches decides**. If no rule matches, `default` decides.

Each rule can match on:

- **`tool`**: the tool name, or a pattern such as `delete*` or `*_admin`;
- **`server`**: the MCP server name from your suite;
- **`agent`**: the agent name;
- **`args`**: the call's arguments (see below).

And it has an **`action`**:

| Action | What happens | How the agent sees it |
| --- | --- | --- |
| `allow` | The call goes through. | Normally |
| `deny` | The call is refused. | A tool error: "Blocked by groot policy (rule name): reason" |
| `approve` | The call is held for a human. In a test, it is never approved, so it counts as blocked. | A tool error saying a human must approve it and not to retry |

The `reason` is shown to the agent, so the model can understand why it was blocked.

## Checking arguments

Rules can look inside a call. Each argument can be checked with:

| Check | Matches when the argument |
| --- | --- |
| `equals` | is exactly this value |
| `prefix` | starts with this value |
| `match` | matches this regular expression |
| `not_match` | does **not** match this regular expression |

For example, allow refunds only for your own orders, and only small ones by ID prefix:

```json
{"name": "only ACME refunds", "tool": "refund_order",
 "args": {"order_id": {"prefix": "ACME-"}}, "action": "allow"},
{"name": "no other refunds", "tool": "refund_order", "action": "deny", "reason": "refunds outside ACME orders are not allowed"}
```

The first rule allows matching refunds. Any other refund falls through to the second rule and is denied.

Arguments that aren't text (numbers, lists, objects) are checked using their JSON form.

## Tool list checks

`tool_checks` controls what Groot does with the list of tools each server offers:

| Setting | What it does |
| --- | --- |
| `hide_denied` | Remove tools that a rule always denies, so the model doesn't plan around them. |
| `flag_injection` | Flag tool descriptions that look like they contain planted instructions. A flagged tool from one of **your** servers fails the scenario. |
| `hide_flagged` | Also remove flagged tools. |
| `alert_on_change` | Record a tool whose description changes during the run. This also fails the scenario. |
| `block_changed_tools` | Also refuse calls to a tool whose description changed. |

Groot's own planted instructions are added after these checks, so they are never reported as a problem with your server.

## Dry-run mode

Set `"mode": "dry-run"` to see what a policy *would* block without changing the run. Calls the policy would block are recorded as `would_deny` in the audit log but still go through. This is useful when you're writing a policy for an existing agent and want to see which rules fire before enforcing them.

## Model API rules

If your agent calls the model API directly (the suite has an `llm` section), the same tool rules apply to tool calls the model asks for. A blocked request is replaced with a short note before it reaches your agent.

The `llm` section of the policy adds two more controls:

```json
"llm": {
  "models": ["anthropic/claude-*", "openai/gpt-*"],
  "budgets": [{"agent": "support-bot", "usd": 5}, {"agent": "*", "usd": 20}]
}
```

- **`models`** lists the models the agent may use. Calls to any other model are refused.
- **`budgets`** sets a spending limit per agent for one scenario, in dollars. The first matching entry wins. When the money runs out, model calls get a "too many requests" error, and the scenario fails with "budget hit".

## Check your policy

```bash
groot policy check groot-policy.json
```

```
ok: 10 rules, mode enforce, default allow, no chaos
```

Groot checks policies strictly. An unknown field, a typo in an action, a bad pattern or a bad regular expression is an error, so a mistake can't silently weaken the boundary. Run `groot policy check` in CI to catch mistakes early.
