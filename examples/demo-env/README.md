# Demo environment

A small company's agents, with realistic mistakes planted. Scan it with:

```bash
groot scan examples/demo-env
```

| What | Where | What scan should find |
| --- | --- | --- |
| support-bot (LangGraph + OpenAI) | `agents/support-bot/`, Deployment `support/support-bot` | IRSA role with `s3:*` on `orders-prod` (FL103), can assume `ops-admin` with AdministratorAccess (FL101, FL102), reads secrets via RBAC and IAM (FL104), fetch + Slack + order data = lethal trifecta (FL110), Slack token in config (FL201), unpinned fetch server (FL202) |
| report-writer (Anthropic) | `agents/report-writer/`, Deployment `analytics/report-writer` | Contained: token not mounted, IAM read-only with a condition, pinned database server. Only a medium write finding from the database server profile |
| IDE assistant | `.mcp.json` | GitHub server alone is a trifecta (issues are untrusted, comments go out) (FL110), hardcoded GitHub token (FL201), unpinned image (FL202), plain-HTTP internal server (FL203), unknown server (FL204) |
| checkout | Deployment `shop/checkout` | Has cluster-admin but is not an agent, so it is not reported |

`cluster/k8s.json` and `cloud/iam.json` stand in for real `kubectl` and `aws iam` exports. All tokens are fake.

`gateway/policy.json` is an enforcing policy for the fake order server; `gateway/chaos-policy.json` drives `make demo-chaos`.
