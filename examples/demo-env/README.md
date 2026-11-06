# Demo environment

A small company's agents, with realistic mistakes planted.

```bash
make demo                                    # both suites and the scan, with HTML reports in bin/
groot scan examples/demo-env                 # what each agent can reach
groot graph examples/demo-env > reach.html   # the same, as an HTML report with reach graphs
```

| What | Where | What scan should find |
| --- | --- | --- |
| support-bot (LangGraph + OpenAI) | `agents/support-bot/`, Deployment `support/support-bot` | IRSA role with `s3:*` on `orders-prod` (FL103), can assume `ops-admin` with AdministratorAccess (FL101, FL102), reads secrets via RBAC and IAM (FL104), fetch + Slack + order data = lethal trifecta (FL110), Slack token in config (FL201), unpinned fetch server (FL202) |
| report-writer (Anthropic) | `agents/report-writer/`, Deployment `analytics/report-writer` | Contained: token not mounted, IAM read-only with a condition, pinned database server. Only a medium write finding from the database server profile |
| IDE assistant | `.mcp.json` | GitHub server alone is a trifecta (issues are untrusted, comments go out) (FL110), hardcoded GitHub token (FL201), unpinned image (FL202), plain-HTTP internal server (FL203), unknown server (FL204) |
| checkout | Deployment `shop/checkout` | Has cluster-admin but is not an agent, so it is not reported |

`cluster/k8s.json` and `cloud/iam.json` stand in for real `kubectl` and `aws iam` exports. All tokens are fake.

Two suites test `support-bot` (played by `examples/naive-agent` against `examples/fake-mcp-server`):

| Suite | What it shows |
| --- | --- |
| `groot-suite.json` | Baseline, tool outages, slow email, prompt injection, an injection contained by policy, a poisoned tool. Sets `"scan": "."`, so obeyed injections report what support-bot can reach |
| `groot-suite-compound.json` | Injections that arrive while payments is failing (in an order record, and in the error message itself), each with a control run. The agent runs with `NAIVE_MODE=desperate`, so it obeys only after a failure |

`gateway/test-policy.json` is the permission boundary both suites use: no deletes, no command or SQL execution.
