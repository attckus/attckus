# Attckus plan

Last updated: 2026-11-06 · Owner: Mohit Kumar

## The goal in one paragraph

Teams are putting AI agents into production faster than they can check them. Attckus gives those teams a way to **break their agent on purpose before release**, to **see exactly what the agent could damage**, and to **show both in a report** their security team can read. It runs in CI against a test environment, needs no cloud credentials, and never uses an AI to decide whether a test passed.

## What Attckus does

1. **Break the agent on purpose.** Run the agent while Attckus plants hidden instructions in what its tools return and makes tools fail. Fail the build when the agent does something dangerous: follows a planted instruction, steps outside the permissions it was given, repeats an action that should happen once (like a refund), loops, or runs up cost.
2. **Show what it can reach.** For each agent, answer plain questions. Can it delete a database? Can it start unlimited Lambda functions or servers? Can it delete AWS or Kubernetes resources? Can it read secrets? Can it give itself more access? Each answer comes with the chain of permissions that makes it true.
3. **Report it clearly.** One HTML file with the test results, a diagram of what each agent can reach, and every problem with a suggested fix.

**Scope for now:** AWS and Kubernetes for permissions; MCP tool servers and the Anthropic and OpenAI APIs for tests.

**What we are deliberately not building:**

- A production proxy or filter that sits in front of agents in live traffic. Attckus tests before release; it does not guard at runtime.
- Prompt-injection detectors, jailbreak testing or content moderation. Many tools do these already.
- Quality evals ("is the answer good?"). That is what eval tools are for.
- AI-based judging. Every pass or fail comes from a fixed rule anyone can check.

## How the plan is organised

The work is split into five phases. Each phase has a goal, a list of tasks, and a **gate**: something that must be true before moving to the next phase. Gates keep the project honest. There is no point building deeper features if nobody is using the basics.

Dates assume 15 to 20 hours a week alongside a full-time job.

| Phase | When | Goal | Gate to move on |
| --- | --- | --- | --- |
| 1. Core | done, November 2026 | All three jobs work end to end on a demo | Done |
| 2. Prove it on real agents | November to December 2026 | Real teams use it on real agents | 3 teams run `attckus test` on a real agent and keep it in CI |
| 3. Deeper testing | January to February 2027 | Test guardrails, replay real incidents | 500 GitHub stars and 3 named users |
| 4. Deeper reach | March to April 2027 | Name the exact resource at risk; cover more AWS and Kubernetes paths | 10 companies using scan or test |
| 5. Reporting and launch | May to June 2027 | Trends across runs; public launch | 2,000 stars and 1 paying design partner |

## Phase 1: Core (done, November 2026)

The goal was to have all three jobs working end to end, so the idea can be shown and tried.

**Breaking the agent (`attckus test`)**

- [x] A suite file describing how to run the agent and which scenarios to try; one run per scenario, with all evidence kept; results as text, JSON or JUnit.
- [x] Planted instructions (attacks) with a random marker to prove the agent obeyed: in tool results, in tool descriptions, and in descriptions that change mid-run. Works for MCP tools and for tools passed to model APIs.
- [x] Faults: errors, timeouts, slow responses, garbled responses, and "too many requests" from model APIs, chosen with a fixed seed so runs repeat.
- [x] A permission boundary (policy) the agent must stay inside, with "contained" results when the boundary stopped a fooled agent.
- [x] Checks for retry storms, duplicate actions, switching to more powerful tools after a failure, budget overruns, suspicious tool servers, obeyed instructions, forbidden tools, timeouts and exit codes. "Inconclusive" when an attack never got delivered.
- [x] Attacks while tools are failing, including instructions hidden in error messages, with an optional control run that shows whether the failure made the difference.
- [x] Correctness limits: a runaway-loop check, "this tool may succeed only once", and caps on tool calls, model calls and cost.
- [x] Impact: when the agent obeys a planted instruction, the result says what its real permissions allow.

**Mapping reach (`attckus scan`)**

- [x] Finding agents from their code, their MCP configs and their Kubernetes workloads, and linking these together.
- [x] Kubernetes: workloads, service accounts, role bindings (including wildcards and groups), and IRSA (how pods get AWS roles).
- [x] AWS: inline and managed policies, wildcards, explicit denies, conditions, and chains of roles that can take on other roles.
- [x] A map of every path from each agent; one finding per agent and kind of risk; the "lethal trifecta"; config hygiene (passwords in files, unpinned versions, unencrypted connections).
- [x] Eight yes/no questions per agent, each with its evidence.

**Reporting**

- [x] A self-contained HTML report with summary, test results, per-agent answers, a reach diagram, a permission table and findings. Works in light and dark mode.
- [x] Text, JSON, SARIF (for GitHub code scanning) and Mermaid output for the scan; a GitHub Action.

## Phase 2: Prove it on real agents (November to December 2026)

**Goal:** find out whether Attckus works on agents it wasn't written for, and whether teams keep using it.

**Gate:** 3 teams run `attckus test` on a real agent and keep it in their CI.

- [ ] **Quickstarts** for LangGraph, the OpenAI Agents SDK, the Claude Agent SDK and the Vercel AI SDK, showing how to load tool servers from `ATTCKUS_MCP_CONFIG`. This is the main thing standing between a new user and a first run.
- [ ] **Test 3 real open-source agents** with `attckus test`, and fix whatever breaks.
- [ ] **Scan 3 real environments** with `attckus scan`, and fix wrong results and missed paths.
- [ ] **Repeat runs** (`runs: N` per scenario) with a pass rate. Real AI agents don't behave the same way every time, so one run can mislead.
- [ ] **Record a 3-minute demo:** a test failing, its impact, and the HTML report.
- [ ] **Interview 10 platform and security engineers** who run agents, to learn which failures and permissions worry them most.
- [ ] **Publish:** final name, domain, LICENSE file.

## Phase 3: Deeper testing (January to February 2027)

**Goal:** answer the next two questions teams ask: "do my guardrails actually work?" and "could yesterday's incident happen again?"

**Gate:** 500 GitHub stars and 3 named users.

- [ ] **Guardrail testing.** Run the same attacks with and without a policy (or a third-party guardrail product), and report what each control caught and missed. Security teams buying guardrails need neutral proof that they work. This builds on the control run from phase 1.
- [ ] **Incident replay.** Turn a real session (first a Attckus audit log, later an OpenTelemetry trace) into a test that plays back the same tool responses, then adds an attack or a failure. "Yesterday's incident becomes today's CI test."
- [ ] **Attack timing.** Deliver an attack only after the first failure happens, instead of for the whole run, to model "the injection arrives while payments is down" more precisely.
- [ ] **Idempotency keys.** Recognise a retry that reuses its idempotency key as safe, so it isn't reported as a duplicate.
- [ ] **Cost baselines.** Fail a scenario when its cost jumps compared with its last passing run.
- [ ] **Multi-turn attacks** that build up over several steps, and a **library of ready-made scenarios** for common agent types (support, coding, data).
- [ ] **Injections in retrieved documents** that are sent back to the model, not only in tool results.

## Phase 4: Deeper reach (March to April 2027)

**Goal:** make the scan precise enough that people act on it without double-checking.

**Gate:** 10 companies using scan or test.

- [ ] **Name the resource, not just the action.** Today the scan can say "can delete DynamoDB tables". It should say "can delete the `orders-prod` table".
- [ ] **More Kubernetes paths:** creating pods as a way to borrow another service account's permissions; Jobs and CronJobs as a way to run unlimited compute.
- [ ] **More AWS identities:** IAM users and groups, EC2 instance profiles, Lambda execution roles, and Bedrock AgentCore agents.
- [ ] **More AWS rules:** organisation-wide restrictions (SCPs), permission boundaries, session policies, and resource policies such as S3 bucket policies. Today these are not modelled, so the scan can overstate reach.
- [ ] **Baseline mode:** in a pull request, show only findings that are new (`--baseline scan.json`).
- [ ] **Per-repository settings:** suppress a finding with a reason, change a severity, ignore paths, describe custom tool servers.
- [ ] **Probe mode:** start a local tool server in a sandbox and read its real list of tools, instead of relying on known profiles.

## Phase 5: Reporting and launch (May to June 2027)

**Goal:** make Attckus easy to adopt and keep using, and tell people about it.

**Gate:** 2,000 GitHub stars and 1 paying design partner.

- [ ] **Report history:** how failures and findings change across runs, and what changed since the last run.
- [ ] **Policy suggestions:** propose the narrowest policy that keeps all tests passing, based on what the agent actually needed.
- [ ] **Research post:** test popular open-source agents with Attckus and publish the results, with responsible disclosure first.
- [ ] **Docs site** with the demo, the threat model and the list of rules.
- [ ] **Talks:** KubeCon, BSides, fwd:cloudsec, and local AI security meetups.

## Later (not scheduled)

- Google Cloud permissions (GCP IAM and Workload Identity).
- Optional live collection from AWS and Kubernetes using read-only roles, for teams that don't want to export files.
- Hosted history of runs, as a paid service.

## Decisions already made

| Decision | Why |
| --- | --- |
| **Test, don't enforce.** Attckus's go-betweens exist only inside a test run. | A production proxy is a different product with much higher reliability demands. Testing before release is where Attckus adds value nobody else does. |
| **Scan exported files, not live APIs.** | No credentials and no security review are needed to try it. It works in locked-down CI. |
| **Sit between the agent and its tools, rather than plugging into each framework.** | The agent doesn't change, and one approach works for every framework and language. |
| **One shared list of "kinds of power"** for scanning, testing and analysis. | A tool the scan calls "delete" is the same tool the tests treat as dangerous, so results agree. |
| **Go standard library only.** | Nothing third-party in the supply chain of a security tool. |
| **Fixed rules decide pass or fail, never an AI.** | Security gates must give the same answer every time and be explainable. |

## Open questions

- Which agent frameworks matter most to early users: LangGraph, the OpenAI Agents SDK, or Bedrock?
- How accurate does the AWS evaluation need to be before it's worth using AWS's own policy simulator through optional live collection?
- If there is a paid tier, should it be priced per agent or per environment?
