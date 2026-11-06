# Groot plan

Last updated: 2026-11-06 · Owner: Mohit Kumar

## Goal

A security and governance tool for teams building AI agents:

1. **Break the agent on purpose.** Run the agent under injected attacks and faults, and fail the build when it does something disastrous: obeys an injection, crosses its permission boundary, repeats a side effect, loops, or runs up cost.
2. **Show what it can reach.** For each agent: can it delete a database, run unbounded compute (Lambda, EC2, ECS, pods), delete AWS or Kubernetes resources, read secrets, or give itself more access? Each answer comes with the path that makes it true.
3. **Report it visually.** One HTML report: test results, a reach graph per agent, and findings with fixes.

Scope for now: AWS and Kubernetes, MCP tools, and the Anthropic and OpenAI APIs.

**Not building:** a production proxy or enforcement layer, prompt-injection classifiers, jailbreak testing, content moderation, model-quality evals. Pass and fail are decided by deterministic rules, never by an LLM.

## Phase 1: Core (done, November 2026)

**Test**
- [x] Suite format; one run per scenario through Groot's proxies (stdio wrapper, HTTP proxy, model API proxy); evidence directory per scenario; text, JSON, JUnit
- [x] Attacks with canary tokens: `inject_result`, `poison_tool`, `rug_pull`, for MCP tools and for tools sent to model APIs
- [x] Faults: error, timeout, latency, malformed, provider 429; seeded
- [x] Permission boundary: policy rules (deny, allow, approve by tool and arguments); contained injections
- [x] Verdicts: retry storm, duplicate side effect, escalation after failure, budget hit, poisoned or changed tools, obeyed injection, forbidden tools, timeout, exit code; inconclusive when the attack was never delivered
- [x] Attacks under failure: `attack+failure` scenarios, injection carried in a failing tool's error message, control run with a differential
- [x] Correctness under failure: runaway-loop detector, `at_most_once`, `max_tool_calls`, `max_model_calls`, `max_cost_usd`
- [x] Impact: an obeyed injection reports what the agent's identity can reach (`scan` in the suite)

**Reach**
- [x] MCP configs (Claude, Cursor, VS Code); agent code detection (Python, TS/JS, Go); linking code, configs and workloads into agents
- [x] Kubernetes: workloads, service accounts, RBAC with wildcards and groups, IRSA, automount
- [x] AWS IAM: inline and managed policies, wildcards, NotAction, explicit deny, conditions, assume-role chains
- [x] Graph with shortest paths; one finding per agent and risk class; lethal trifecta; config hygiene
- [x] "Can it ...?" answers per agent (delete a database, delete AWS or Kubernetes resources, unbounded compute, exec, secrets, privilege escalation, data out)

**Report**
- [x] HTML report (self-contained, light and dark): summary, scenarios with impact and control outcome, per-agent answers, reach graph, permission table, findings
- [x] Text, JSON, SARIF and Mermaid for scan; GitHub Action with SARIF upload

## Phase 2: Prove it on real agents (November to December 2026)

Gate: 3 teams run `groot test` on a real agent and keep it in CI.

- [ ] Quickstarts that load `GROOT_MCP_CONFIG` in LangGraph, the OpenAI Agents SDK, the Claude Agent SDK and the Vercel AI SDK
- [ ] Run `groot test` on 3 real open-source agents; fix whatever breaks
- [ ] Run `groot scan` on 3 real environments; fix false positives and missed edges
- [ ] Repeat runs per scenario (`runs: N`) with a pass rate, since LLM agents vary between runs
- [ ] Record a 3-minute demo: test, impact, HTML report
- [ ] Interview 10 platform and security engineers running agents
- [ ] Final name, domain, LICENSE file; publish

## Phase 3: Deeper testing (January to February 2027)

Gate: 500 stars and 3 named users.

- [ ] **Guardrail testing:** run the same attack suite with and without the policy (or a third-party guardrail) and report what each control caught; builds on the control run
- [ ] **Incident replay:** turn an audit log, then an OpenTelemetry trace, into a scenario that replays the recorded tool responses, then adds an attack or a fault
- [ ] Deliver an attack only after the first fault fires, not for the whole run
- [ ] Idempotency-key awareness: a retry that reuses the key is not a duplicate
- [ ] Cost baselines per scenario: fail on a jump against the last passing run
- [ ] Multi-turn attacks; a scenario library for common agent types (support, coding, data)
- [ ] Tool-result injection checks for documents retrieved and sent back to the model

## Phase 4: Deeper reach (March to April 2027)

Gate: 10 companies using scan or test.

- [ ] Name the resource, not only the action: "can delete the `orders-prod` table", with resource ARNs carried through the graph
- [ ] Kubernetes: `create pods` as an escalation path (mount any service account in the namespace); Jobs and CronJobs as unbounded compute
- [ ] AWS: users and groups; instance profiles; Lambda execution roles as agent identities; Bedrock AgentCore agents
- [ ] AWS: SCPs, permission boundaries, session policies, resource-based policies (S3 bucket policies, KMS key policies)
- [ ] Baseline mode: report only new findings in a pull request (`--baseline scan.json`)
- [ ] Per-repo config: suppressions with reasons, severity overrides, ignored paths, custom MCP server profiles
- [ ] Probe mode: start a stdio MCP server in a sandbox and list its real tools

## Phase 5: Reporting and launch (May to June 2027)

Gate: 2,000 stars and 1 paying design partner.

- [ ] Report history: trend of failures and findings across runs; diff against the last run
- [ ] Policy suggestions from scan results: the narrowest policy that keeps the tests passing
- [ ] Research post: popular open-source agents tested with Groot; 1 or 2 responsible disclosures
- [ ] Docs site with the demo, the threat model and the rule catalogue
- [ ] Talks: KubeCon, BSides, fwd:cloudsec, local AI security meetups

## Later

- GCP IAM and Workload Identity
- Opt-in live collectors (AWS SDK, Kubernetes API) behind read-only roles
- Hosted run history (paid)

## Decisions

- **Test, not enforce.** Groot proxies only exist inside a test run. No production proxy.
- **Offline snapshots** for scan, not live API access: no credentials and no security review needed to try it.
- **Proxies, not SDK hooks** for tests: the agent is unmodified and any MCP client works.
- **One capability model** shared by scan, tests and analysis: a tool the scanner calls "destroy" is the tool the analyzer treats as a side effect.
- **Standard library only:** the supply chain is the Go toolchain.
- **Deterministic verdicts:** LLMs never decide pass or fail.

## Open questions

- Which framework integrations matter most to early users (LangGraph, OpenAI Agents SDK, Bedrock)?
- How far to go on IAM fidelity before relying on AWS's policy simulator through opt-in collectors?
- Pricing unit for a paid tier: per agent or per environment?
