---
title: Scan your environment
parent: User guide
nav_order: 5
---

# Scan your environment
{: .no_toc }

How to find out what each of your agents can reach in Kubernetes and AWS, without giving Attckus any credentials.

1. TOC
{:toc}

---

## How it works, in one paragraph

`attckus scan` reads files from a folder: your agents' code, their MCP configs, and exports of your Kubernetes and AWS permissions. It works out which agents exist, which identities they run as, and what those identities are allowed to do, following chains such as "pod → service account → AWS role → another role". It never calls a cloud API, so it needs no credentials and no network. The cost of that choice is that you export the permissions yourself, which takes two commands.

## Step 1: gather the inputs in one folder

The simplest setup is to run the scan on your repository, with the exports added to it (or to a copy of it):

```
my-repo/
  agents/support-bot/agent.py       ← agent code
  agents/support-bot/mcp.json       ← its tool servers
  .mcp.json                         ← your editor's AI assistant config, if any
  scan/k8s.json                     ← Kubernetes export
  scan/iam.json                     ← AWS export
```

The file names of the exports don't matter: Attckus recognises them by their content.

### Kubernetes

With `kubectl` pointed at the cluster where your agents run:

```bash
kubectl get deploy,sts,ds,cronjob,job,sa,role,clusterrole,rolebinding,clusterrolebinding -A -o json > scan/k8s.json
```

This exports workloads, service accounts and every role and binding. It needs read access to those objects across all namespaces. It does **not** export secrets or their values.

You can export several clusters into separate files; Attckus merges them.

### AWS

With AWS credentials for the account your agents use:

```bash
aws iam get-account-authorization-details --output json > scan/iam.json
```

This exports every IAM role, user, group and policy in the account. It needs the `iam:GetAccountAuthorizationDetails` permission (included in the AWS managed `SecurityAudit` and `ReadOnlyAccess` policies). It does not export any data or secret values.

Only one IAM export is used per scan. If your agents use roles in several accounts, scan each account separately for now.

{: .note }
The exports describe your permissions in detail. Treat them as sensitive: don't commit them to a public repository, and delete them from CI artifacts after the scan if needed.

### Agent code and MCP configs

These are usually already in your repository. Attckus recognises:

- **MCP configs** named `.mcp.json`, `mcp.json`, `mcp_config.json` or `claude_desktop_config.json`, including those in `.cursor/` and `.vscode/`;
- **agent code** in Python, TypeScript/JavaScript and Go that imports a model provider SDK or an agent framework (LangGraph, LangChain, CrewAI, AutoGen, LlamaIndex, Pydantic AI, the OpenAI Agents SDK, the Vercel AI SDK, Mastra, and the Anthropic and OpenAI SDKs).

## Step 2: run the scan

```bash
attckus scan my-repo/
```

## Step 3: check that Attckus found your agents

The first line of each section is an agent, followed by where Attckus found it:

```
■ support-bot
  code agents/support-bot (LangGraph, OpenAI)
  k8s Deployment support/support-bot
  mcp config agents/support-bot/mcp.json
```

Attckus links the pieces of one agent together like this:

1. A folder containing agent code is an agent, named after the folder (`agents/support-bot/` → `support-bot`).
2. An MCP config in that folder belongs to that agent. A config at the top of the repository, or in `.cursor/` or `.vscode/`, belongs to an agent called `ide-assistant`, your editor's AI assistant.
3. A Kubernetes workload is treated as an agent if it has an LLM API key in its environment (such as `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`), or if you mark it (see below). It is joined to the code agent with the same name.

### If an agent is missing or not linked

Mark the workload in Kubernetes with annotations:

```yaml
metadata:
  annotations:
    attckus.dev/agent: "true"              # this workload is an agent
    attckus.dev/agent-name: "support-bot"  # and this is its name (to join it with the code)
```

Then export again. Workloads that aren't agents, even very powerful ones, are deliberately left out of the report.

## Step 4: read the answers and findings

For each agent you get:

- **`can:`**, a list of every [kind of power](../concepts.md#kinds-of-power) the agent has;
- **findings**, each with a severity, a rule number, a sentence, the **path** that causes it, evidence, and a suggested fix.

```
  CRITICAL FL103  support-bot can delete data or infrastructure via role ops-admin, including production resources; also via role support-agent-role
           path: support-bot → sa support/support-bot → role support-agent-role → role ops-admin
           - dynamodb:DeleteItem on * (AdministratorAccess)
           - dynamodb:DeleteTable on * (AdministratorAccess)
           fix: Scope access to read or write only, add an explicit deny for delete actions, and require approval for destructive tools in the gateway.
```

How to read this one:

- **The path** is the chain from the agent to the identity that holds the permission. Read the arrows as "runs as", "gets the role", "can take on".
- **"also via"** means another identity gives the same power. Fixing only the worst path won't be enough.
- **The evidence** lines are the actual permissions, with the policy they come from in brackets.
- **"including production resources"** means at least one permission covers production: a resource with `prod` or `production` in its name, a role tagged as production, or `*` (everything).

The yes/no questions ("Can it delete a database?", "Can it run compute without a cap?" and so on) are in the HTML and JSON output. See [Reports](reports.md).

See the full [list of findings](../reference/findings.md) with what each one means and how to fix it.

## Step 5: see it as a picture

```bash
attckus graph my-repo/ > reach.html
```

Open `reach.html` in a browser. Each agent gets a card with its yes/no answers and a diagram, read left to right: the agent, then the identities and tool servers it reaches, then on the far right the powers each one grants, coloured by severity.

## What the scan understands

| Area | Understood |
| --- | --- |
| Kubernetes | Deployments, StatefulSets, DaemonSets, Jobs, CronJobs; service accounts and whether their token is mounted; Roles, ClusterRoles and their bindings, including wildcards and bindings to groups (all service accounts, all signed-in users); IRSA |
| AWS IAM | Inline and attached managed policies; wildcards such as `s3:*` or `*`; `NotAction`; explicit denies; conditional permissions (kept, but marked "conditional" and rated one level lower); roles that can take on other roles, checked against the other role's trust policy |
| MCP servers | Profiles for common servers (shell, Kubernetes, AWS, filesystem, GitHub, GitLab, Slack, email, web fetch, browser, database, payments); version pinning; passwords written into the config; unencrypted remote servers |

## What it doesn't understand yet

- **AWS organisation rules (SCPs), permission boundaries and session policies.** These can only take access away, so the scan may report access that they would block.
- **Resource policies,** such as S3 bucket policies or KMS key policies. These can also grant access, so the scan can miss some reach.
- **IAM users and groups, EC2 instance profiles, and Lambda execution roles** as agent identities.
- **Google Cloud and Azure.**

Every report includes a note about the AWS limits. These are on the [plan](https://github.com/attckus/attckus/blob/main/PLAN.md).

## Use the scan in tests

Add the scan folder to your test suite:

```json
"scan": "my-repo/"
```

Then, when a test shows your agent obeying a planted instruction, the result includes what that agent could reach. Make sure the suite's `agent` matches the agent name the scan prints.
