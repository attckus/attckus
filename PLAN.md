# Groot plan

Last updated: 2026-11-05 · Owner: Mohit Kumar

## Goal

**Security and resilience tests for AI agents, in CI.** Groot runs an agent's own tests under attack (prompt injection in tool results, poisoned tools, rug pulls) and under failure (tool errors, timeouts, provider rate limits), and fails the build when the agent behaves unsafely. `groot scan` adds the static view: what each agent can reach.

The product is lean on purpose: one CLI, one GitHub Action, one verdict per pull request, run against test environments. The always-on production proxy is parked (see "Parked" below) and comes back as a paid tier only if test users ask for it ([ADR 0006](docs/adr/0006-verification-first.md)). Target outcomes, most likely first: a Staff/Principal role in AI security or AI infrastructure; an acqui-hire; a seed round. All three need adoption, visible expertise, and a gap filled that big vendors have not covered.

**Not competing on:** prompt-injection classifiers, jailbreak testing, content moderation (crowded, consolidating through acquisitions).

## Phases and gates

| Phase | Window | Outcome | Gate to move on |
| --- | --- | --- | --- |
| 0. Build and validate | Nov–Dec 2026 | `groot test` with attack and failure scenarios; scan; demo suite; run on 3 real agents | 3 teams run `groot test` on a real agent and keep it in CI |
| 1. Launch | Jan–Feb 2027 | Research post: popular open-source agents tested with Groot; scenario library; framework quickstarts; GitHub Action; talk proposals; 1–2 responsible disclosures | 500 stars and 3 named users |
| 2. Depth | Mar–May 2027 | Larger attack library; multi-turn attack scenarios; hosted history of runs (paid); opt-in live collectors for scan | 2,000 stars, 10 companies, 1 paying design partner |
| 3. Outcome | Jun–Aug 2027 | Conversations with buyers' corporate development; senior interviews; or a seed round | — |

Dates assume 15–20 hours a week alongside a full-time role.

## Phase 0 (now)

### Done in this repo
- [x] `groot test`: suite format; per-scenario policy, attacks file and generated MCP config (`GROOT_MCP_CONFIG`); stdio servers wrapped by the gateway, URL servers and model APIs behind in-process gateways; agent run with timeout and process-group kill; verdicts from the audit log; evidence per scenario; text, JSON and JUnit output; `--scenario`, `--strict`
- [x] Attacks with canary tokens: `inject_result`, `poison_tool`, `rug_pull`, for MCP tools and for tools sent to the Anthropic and OpenAI APIs; groot's own payloads never reported as poisoned servers
- [x] Verdict rules: retry storm, duplicate side effect, escalation after failure, budget hit, poisoned or changed real tools, obeyed injection (with "contained by policy"), forbidden tools, timeout, exit code; inconclusive when an attack was never delivered
- [x] Demo suite with 6 scenarios and a deliberately unsafe agent; CI checks every verdict
- [x] Capability model shared by scanner, gateway and analyzer
- [x] MCP config parsing (Claude, Cursor, VS Code formats); hardcoded secrets with redaction; unpinned packages; plain-HTTP remotes; known-server profiles
- [x] Agent code detection (Python, TS/JS, Go) and linking code, configs and workloads into agents
- [x] Kubernetes: workloads, service accounts, RBAC with wildcards and group subjects, IRSA, automount
- [x] AWS IAM: inline and managed policies, default versions, URL-encoded documents, wildcards, NotAction, explicit deny, conditions, assume-role chains via trust policies
- [x] Graph with shortest paths; one finding per agent and risk class with the worst path; lethal trifecta
- [x] Text, JSON, SARIF, Mermaid output; CI exit codes
- [x] Gateway: policy (globs, argument matchers), dry-run, approvals (held), kill switch, token-bucket rate limits, batch rejection, audit log with redaction
- [x] tools/list filtering: hide always-denied tools, flag injected instructions and hidden Unicode, detect mid-session definition changes
- [x] Stdio and Streamable HTTP transports (JSON and SSE)
- [x] Chaos: error, timeout, latency, malformed; seeded; refuses prod by default
- [x] Analyzer: retry storms, duplicate side effects, escalation after failure, blocked attempts, flagged and changed tools
- [x] Demo environment, fake MCP server, naive agent; CI asserts every planted risk is found
- [x] GitHub Action with SARIF upload
- [x] LLM gateway (`groot gateway llm`): Anthropic and OpenAI passthrough ported from zoko; tool-call policy on JSON and streaming responses; per-agent budgets; model allowlist; provider chaos (429, 529/503, timeout, latency, malformed); token and cost audit; analyzer cost summary and budget issues

### Remaining
- [ ] Quickstarts that load `GROOT_MCP_CONFIG` in LangGraph, the OpenAI Agents SDK, the Claude Agent SDK and Vercel AI SDK
- [ ] Run `groot test` on 3 real open-source agents; fix whatever breaks
- [ ] Review employment contract IP and side-project clauses
- [ ] Run scan on 3 real environments; fix false positives and missed edges
- [ ] Put the gateway in front of one real MCP server in dry-run for two weeks; tune the default policy
- [ ] Record a 3-minute demo of `make demo-chaos`
- [ ] Interview 10 platform/security engineers running agents in production
- [ ] Final name, domain, LICENSE file; publish

## Phase 1 backlog

### Scan
- [ ] Baseline mode: report only new findings in a PR (`--baseline scan.json`)
- [ ] Per-repo config: suppressions with reasons, severity overrides, ignored paths
- [ ] Kubernetes: Pods created via `create pods` as an escalation path (mount any SA in the namespace)
- [ ] AWS: users and groups; instance profiles; Lambda execution roles as agent identities
- [ ] Bedrock AgentCore and OpenAI Agents SDK tool definitions as agent sources
- [ ] More server profiles from real configs; let users add profiles in config
- [ ] Probe mode: start a stdio MCP server in a sandbox and list its real tools

### Gateway
- [ ] LLM gateway: OpenAI Responses API and Bedrock/Vertex routes; per-model fallbacks (zoko's fallback chain) as an opt-in
- [ ] LLM gateway: run injection checks on tool results and retrieved documents sent back to the model
- [ ] LLM gateway: persist spend across restarts (budgets are in memory today)
- [ ] Approval workflow: pending queue file and `groot approve <id>`; Slack webhook in phase 2
- [ ] Policy generation from scan results (`groot policy suggest`)
- [ ] OpenTelemetry spans for each tool call
- [ ] Benchmarks in CI (target: under 1 ms added latency per call)

### Launch
- [ ] Scan 50 public repos with MCP configs; publish aggregate results (no names before disclosure)
- [ ] Docs site with the demo, the threat model and the rule catalogue
- [ ] Submit talks: KubeCon, BSides, fwd:cloudsec, local AI security meetups

## Parked: production enforcement

The gateways work as an always-on proxy today (`groot gateway stdio|http|llm`), but this mode is a preview and gets no new features until test users ask: approval workflows, a central policy server, persistent budgets, HA deployment, Kubernetes sidecar. It is the natural paid tier ("enforce in production what you tested in CI").

## Phase 2 backlog
- [ ] Opt-in live collectors (AWS SDK, Kubernetes API) behind read-only roles
- [ ] SCPs, permission boundaries, session policies, resource-based policies (S3 bucket policies, KMS key policies)
- [ ] GCP IAM and Workload Identity
- [ ] Central policy server and fleet view of gateways (paid)
- [ ] Chaos scenarios library and reports (paid)

## Decisions
- Offline snapshots, not live API access ([ADR 0001](docs/adr/0001-offline-snapshots.md))
- Gateway as a transparent MCP proxy, not an SDK ([ADR 0002](docs/adr/0002-gateway-as-proxy.md))
- Standard library only ([ADR 0003](docs/adr/0003-stdlib-only.md))
- One shared capability model for scan, gateway and analyzer ([ADR 0004](docs/adr/0004-shared-capability-model.md))
- Reuse zoko's model passthrough for the LLM gateway, rewritten without dependencies ([ADR 0005](docs/adr/0005-reuse-zoko-passthrough.md))
- Verification first: `groot test` is the product, the production proxy is parked ([ADR 0006](docs/adr/0006-verification-first.md))
- LLMs never decide pass or fail; detection is deterministic

## Open questions
- Which framework integrations matter most to early users (LangGraph, OpenAI Agents SDK, Bedrock)?
- Should the gateway ship as a sidecar container for Kubernetes in phase 1?
- Pricing unit for the paid tier: per gateway, per agent, or per environment?

## Previous direction
The resilience-testing MVP (static resilience checks, chaos agent, control plane) is preserved at git tag `v0-resilience`.
