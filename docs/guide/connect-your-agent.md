---
title: Connect your agent
parent: User guide
nav_order: 1
---

# Connect your agent
{: .no_toc }

Before Attckus can test your agent, the agent must let Attckus sit between it and its tools. For most agents this is a few lines of code, and it changes nothing when Attckus isn't running.

1. TOC
{:toc}

---

## What Attckus needs from your agent

For each scenario, Attckus starts your agent with a few environment variables set:

| Variable | Set when | What your agent should do with it |
| --- | --- | --- |
| `ATTCKUS_MCP_CONFIG` | always | Load its MCP tool servers from this file instead of its usual config. |
| `ANTHROPIC_BASE_URL` | the suite has an `llm` section | Send Anthropic API calls here. The official Anthropic SDKs already read this variable. |
| `OPENAI_BASE_URL` | the suite has an `llm` section | Send OpenAI API calls here. The official OpenAI SDKs already read this variable. |
| `ATTCKUS_SCENARIO` | always | The name of the scenario being run. Useful for logging; you don't have to use it. |

Any variables listed under `env` in the suite are also set.

So the only real change is this: **if `ATTCKUS_MCP_CONFIG` is set, load MCP servers from that file.**

## What the file looks like

`ATTCKUS_MCP_CONFIG` points at a standard MCP config, in the same format Claude Desktop, Cursor and most MCP clients use. Each of your servers appears under its own name:

```json
{
  "mcpServers": {
    "orders": {
      "command": "/usr/local/bin/attckus",
      "args": ["gateway", "stdio", "--policy", "…", "--", "npx", "-y", "@acme/orders-mcp@1.4.0"]
    },
    "crm": {
      "type": "http",
      "url": "http://127.0.0.1:53817/mcp"
    }
  }
}
```

- **Local servers** (ones you start with a command) become a `command` and `args` entry. The command starts Attckus, and Attckus starts your real server. Your agent doesn't need to know this; it starts the command as usual.
- **Remote servers** (ones you reach by URL) become an `http` entry pointing at a local Attckus address. Attckus forwards to your real server.

The server names are the ones you give in the suite's `mcp_servers`, so your code can find each server by name.

## Examples

These are short sketches for common setups. Function names change between library versions, so check your framework's documentation for the exact API. The idea is always the same: read the file, then hand each server to your MCP client.

### Any Python agent: a small loader

```python
import json
import os

def load_mcp_servers(default_path="mcp.json"):
    """Return {name: server} from ATTCKUS_MCP_CONFIG when Attckus runs us, else our usual config."""
    path = os.environ.get("ATTCKUS_MCP_CONFIG", default_path)
    with open(path) as f:
        return json.load(f)["mcpServers"]
```

Use whatever you get back exactly as you use your normal config today.

### LangGraph / LangChain (langchain-mcp-adapters)

```python
import os
from langchain_mcp_adapters.client import MultiServerMCPClient

def connections():
    servers = load_mcp_servers()          # from the loader above
    out = {}
    for name, s in servers.items():
        if s.get("type") == "http":
            out[name] = {"transport": "streamable_http", "url": s["url"]}
        else:
            out[name] = {"transport": "stdio", "command": s["command"], "args": s.get("args", []),
                         "env": dict(os.environ)}
    return out

client = MultiServerMCPClient(connections())
tools = await client.get_tools()
```

### OpenAI Agents SDK

```python
import os
from agents.mcp import MCPServerStdio, MCPServerStreamableHttp

def mcp_servers():
    out = []
    for name, s in load_mcp_servers().items():
        if s.get("type") == "http":
            out.append(MCPServerStreamableHttp(name=name, params={"url": s["url"]}))
        else:
            out.append(MCPServerStdio(name=name, params={"command": s["command"], "args": s.get("args", []),
                                                         "env": dict(os.environ)}))
    return out
```

The OpenAI SDK reads `OPENAI_BASE_URL` on its own, so model calls go through Attckus when the suite has an `llm` section.

### Claude Agent SDK

The Claude Agent SDK can load MCP servers straight from a config file path:

```python
import os
from claude_agent_sdk import ClaudeAgentOptions

options = ClaudeAgentOptions(
    mcp_servers=os.environ.get("ATTCKUS_MCP_CONFIG", "mcp.json"),
)
```

### TypeScript

```ts
import { readFileSync } from "node:fs";

const path = process.env.ATTCKUS_MCP_CONFIG ?? "mcp.json";
const servers = JSON.parse(readFileSync(path, "utf8")).mcpServers;
// For each entry: if type === "http", connect to entry.url;
// otherwise start entry.command with entry.args, as you do today.
```

## Pass environment variables to your tool servers

Some MCP clients start tool servers with only a minimal set of environment variables, for safety. When Attckus is in the middle, it is Attckus that starts your real server, and Attckus passes on the environment it was given. If your server needs a token or a database address, make sure your client passes the full environment when it starts the command. The `"env": dict(os.environ)` lines in the examples above do this. Then set the values themselves in the suite's `env` section or in your CI environment.

## Agents that call the model API directly

If your agent calls the Anthropic or OpenAI API itself (function calling, without MCP), add an `llm` section to the suite:

```json
"llm": {}
```

Attckus then starts a local stand-in for the APIs and sets `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL`. The official SDKs pick these up with no code change. Attckus passes your agent's own API key through to the real API, so the agent still needs its usual `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.

Through this stand-in, Attckus can:

- plant instructions in the tool descriptions and tool results your agent sends to the model;
- make the API return "overloaded", "too many requests", slow or garbled responses;
- block tool calls the model asks for if the policy forbids them;
- count tokens and cost, and enforce a budget.

If your agent uses a different API address (a proxy, a compatible server, or Azure), set `anthropic_url` or `openai_url` in the `llm` section to the real address Attckus should forward to.

## Check the connection

Write a suite with just a baseline scenario (see [Write a test suite](write-a-suite.md)) and run it:

```bash
attckus test --suite attckus-suite.json
```

Then open the scenario's `audit.jsonl` in the evidence folder. If you see `tool_call` lines for your tools, Attckus is in the middle and you're ready to add attacks and faults. If the file is empty, your agent didn't load `ATTCKUS_MCP_CONFIG`; see [Troubleshooting](../troubleshooting.md).
