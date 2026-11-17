---
title: Troubleshooting
nav_order: 6
---

# Troubleshooting and FAQ
{: .no_toc }

1. TOC
{:toc}

---

## Testing

### The audit log is empty, or has no `tool_call` lines

Your agent didn't use Attckus's MCP config. Check that:

- your agent reads `ATTCKUS_MCP_CONFIG` when it is set (see [Connect your agent](guide/connect-your-agent.md));
- the server names in your code match the `name` values in the suite's `mcp_servers`;
- your test command actually starts the agent: look at `agent.log` in the scenario's evidence folder.

### My tool server fails to start under Attckus, but works normally

The server probably needs environment variables (a token, a database address) that it isn't getting. Some MCP clients start servers with only a minimal environment. Pass the full environment when your client starts the command (for example `"env": dict(os.environ)` in Python), and set the values in the suite's `env` or in your CI environment.

### An attack scenario is always inconclusive

The attack never reached the agent: it never called (for `inject_result`) or listed (for `poison_tool` and `rug_pull`) the tool where the instruction was planted. Plant it on a tool your test is sure to use. For `rug_pull`, the agent must list the tools more than once.

### A scenario passes sometimes and fails other times

AI agents don't behave identically every run, especially under attack. Attckus's failures repeat exactly (the `seed` is fixed), but the model's choices don't. Run important scenarios several times, for example nightly as well as on pull requests, and treat any failure as real.

### A scenario fails with "finishes in time"

The agent ran longer than `timeout_seconds` (default 120) and Attckus stopped it. Either your agent hangs when a tool fails (worth fixing), or the test simply needs longer: raise `timeout_seconds`.

### "no price configured for …" when using a budget

When a budget applies, Attckus must know the model's price to keep spending under it. Prices for Anthropic models are built in. For others, create a JSON file of prices in dollars per million tokens and point `ATTCKUS_PRICES_FILE` at it:

```json
{"openai/gpt-5": {"input": 1.25, "output": 10}}
```

### Does Attckus change my agent's behaviour when it isn't under attack?

In a baseline scenario with no faults, attacks or blocking rules, Attckus passes calls through unchanged. It adds a little latency, and it may hide tools your policy always denies (`hide_denied`).

### Do tool calls really happen?

Yes. Calls the policy allows are passed to your real tool servers. Always point tests at a test environment.

## Scanning

### My agent isn't found

Attckus finds agents from code that imports a model provider SDK or an agent framework, from MCP config files, and from Kubernetes workloads with an LLM API key in their environment. If yours isn't found, annotate its Kubernetes workload with `attckus.dev/agent: "true"` and export again. See [Scan your environment](guide/scan-your-environment.md#if-an-agent-is-missing-or-not-linked).

### The code and the Kubernetes workload show up as two agents

They are joined by name: the code's folder name and the workload's name. If they differ, add `attckus.dev/agent-name: "<folder name>"` to the workload.

### "Agents use AWS roles but no IAM snapshot was found"

An agent's service account (through IRSA) or tool server uses an AWS role, but there is no IAM export in the folder. Export one with `aws iam get-account-authorization-details --output json > iam.json`.

### "Role … is referenced but not in the IAM snapshot"

The role is in a different AWS account from the export, or the export is out of date. Scan each account separately for now.

### The scan reports access that we've blocked with an SCP or permission boundary

Attckus doesn't model SCPs, permission boundaries or session policies yet, so it can overstate reach where those apply. Every report notes this. It also doesn't read resource policies (such as S3 bucket policies), so it can miss access those grant.

### Impact says "agent … was not found in the scan"

The suite's `agent` name doesn't match any agent name the scan prints. Run `attckus scan <folder>` and copy the name exactly.

## Reports

### Is the HTML report safe to share?

It contains no scripts and loads nothing from the internet, and secrets are hidden. But it describes your permissions in detail. Share it as you would an internal architecture diagram, not publicly.

### Can I get a diagram for Markdown?

Yes: `attckus scan --format mermaid <folder>` prints a Mermaid diagram that GitHub, GitLab and many wikis render.

## Still stuck?

[Open an issue on GitHub](https://github.com/attckus/attckus/issues) with the command you ran, the output, and (if you can share it) the scenario's `audit.jsonl` and `agent.log`.
