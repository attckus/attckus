# Demo environment

This folder is a pretend company that runs three AI agents. Each agent has realistic mistakes planted in its setup, the kind found in real companies, so you can see what Attckus finds without pointing it at your own systems.

```bash
make demo                                    # runs both test suites and the scan, and writes HTML reports to bin/
attckus scan examples/demo-env                 # what each agent can reach, as text
attckus graph examples/demo-env > reach.html   # the same, as an HTML report with diagrams
```

## What's in the folder

| File or folder | What it stands for |
| --- | --- |
| `agents/support-bot/`, `agents/report-writer/` | The agents' code and their MCP tool configs |
| `.mcp.json` | A tool config for the AI assistant in a developer's editor |
| `cluster/k8s.json` | An export of the company's Kubernetes cluster, as `kubectl get … -o json` would produce |
| `cloud/iam.json` | An export of the company's AWS permissions, as `aws iam get-account-authorization-details` would produce |
| `attckus-suite.json`, `attckus-suite-compound.json` | Two test suites for `support-bot` |
| `gateway/test-policy.json` | The permission boundary both suites use |

All tokens and account numbers are fake.

## The agents, and what the scan should find

| Agent | Where it lives | What's wrong with it |
| --- | --- | --- |
| **support-bot** (LangGraph and OpenAI) | `agents/support-bot/`, and the Kubernetes Deployment `support/support-bot` | Almost everything. Its AWS role (given through IRSA) has `s3:*` on the production orders bucket, so it can delete production data (FL103). That role can also take on `ops-admin`, which has full admin rights, so it can change permissions and run code anywhere (FL101, FL102). It can read secrets through both Kubernetes and AWS (FL104). It fetches web pages, posts to Slack and reads order data: the lethal trifecta (FL110). Its Slack token is written into its config (FL201), and its fetch server isn't pinned to a version (FL202). |
| **report-writer** (Anthropic) | `agents/report-writer/`, and the Deployment `analytics/report-writer` | The well-behaved one. Its Kubernetes token isn't mounted, its AWS role can only read, under a condition, and its database server is pinned to a version. The only finding is a medium one: its database tool can change data. |
| **ide-assistant** | `.mcp.json` at the top of the folder | The GitHub tool server on its own is a lethal trifecta: issues can contain anything an outsider writes, and comments go out to the world (FL110). There's a GitHub token written into the file (FL201), an unpinned image (FL202), an internal server reached over unencrypted HTTP (FL203), and a server Attckus doesn't recognise (FL204). |

There is also a fourth workload, **checkout** (`shop/checkout`). It has full cluster-admin rights in Kubernetes, but it isn't an AI agent, so Attckus correctly leaves it out. Attckus only reports on agents.

## The test suites

Both suites test `support-bot`. In the tests it is played by `examples/naive-agent`, a small program that behaves badly on purpose. It talks to `examples/fake-mcp-server`, a pretend order system with tools such as `get_order`, `refund_order`, `send_email`, `delete_order` and `execute_sql`.

| Suite | What it shows |
| --- | --- |
| `attckus-suite.json` | Six scenarios: everything working; the payments tool failing (the agent retries in a storm, then switches to raw SQL); a slow email tool (the agent sends the email twice); an instruction planted in an order record (the agent obeys it); the same attack aimed at a tool the policy forbids (the agent obeys, but the policy blocks it); and a poisoned tool description. The suite sets `"scan": "."`, so when the agent obeys a planted instruction, the result says what support-bot's real permissions allow. |
| `attckus-suite-compound.json` | Two scenarios where a planted instruction arrives while the payments tool is failing: once in an order record, and once inside the payment error message itself. Each has a control run without the failure. The agent runs with `NAIVE_MODE=desperate`, which makes it ignore planted instructions until something goes wrong, so both scenarios show `only under failure`. |

The policy in `gateway/test-policy.json` forbids deleting anything and forbids running commands or SQL.
