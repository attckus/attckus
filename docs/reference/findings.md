---
title: Scan findings
parent: Reference
nav_order: 5
---

# Scan findings
{: .no_toc }

Every finding `groot scan` can report: what it means, how its severity is decided, and how to fix it.

1. TOC
{:toc}

---

## How severity works

| Severity | Meaning |
| --- | --- |
| **critical** | One fooled or faulty run could cause serious, hard-to-undo damage. Fix before release. |
| **high** | Serious exposure. Fix soon. |
| **medium** | Worth fixing; limited damage on its own. |
| **low** | Informational, or a gap in what Groot could check. |

Two rules adjust severity:

- **Production is rated higher.** A permission counts as production when its resource name contains `prod` or `production`, when it applies to `*` (everything), when the role is tagged as production, or when a Kubernetes permission is cluster-wide or in a namespace named like production.
- **Conditional permissions are rated one level lower.** If every matching AWS permission only applies under a condition (for example "only from this network"), the finding is still reported, marked "conditional", one level lower.

`groot scan --fail-on <severity>` fails the build at that severity or above (default `critical`).

## Reach findings

These come from following the agent's identities. Each finding shows the worst path, and lists other paths to the same power as "also via".

### FL101: Agent can change permissions or assume other roles

**Severity:** critical

**What it means:** the agent can give itself, or something else, more access: attach policies, create users or access keys, pass roles, take on other roles, or (in Kubernetes) bind, escalate or impersonate. A fooled agent with this power can turn a small foothold into full control.

**Fix:** remove permission-management and role-assumption rights. An agent should never be able to grant itself more access.

### FL102: Agent can execute arbitrary commands or code

**Severity:** critical

**What it means:** the agent can run commands or code, or start compute: a shell tool, `ssm:SendCommand`, creating or updating Lambda functions, starting EC2 instances or ECS tasks, or creating or entering pods. A fooled agent can do anything that code can do, and run up a large bill.

**Fix:** remove command execution, or run it in a sandbox and limit it to an allowlist.

### FL103: Agent can delete data or infrastructure

**Severity:** critical if production is affected, otherwise high

**What it means:** the agent can delete buckets, objects, tables, items, databases, instances, volumes, snapshots, keys, logs or Kubernetes resources.

**Fix:** scope access to read or write only, add an explicit deny for delete actions, and require approval for destructive tools.

### FL104: Agent can read secrets

**Severity:** high

**What it means:** the agent can read Secrets Manager values, SSM parameters, decrypt with KMS, or read Kubernetes secrets. A fooled agent could hand them to an attacker.

**Fix:** grant only the specific secrets the agent needs (exact ARNs or resource names), never wildcards.

### FL105: Agent can modify data

**Severity:** high if production is affected, otherwise medium

**What it means:** the agent can create or change data: write objects, put items, change database settings, or create and update Kubernetes resources.

**Fix:** narrow write access to the resources this agent owns.

### FL110: Lethal trifecta

**Severity:** critical

**What it means:** the agent has all three of: access to private data; exposure to content an attacker can control (web pages, email, public issues); and a way to send data out (email, Slack, web requests, comments). With all three, one planted instruction is enough to make it read your data and send it away. The finding names which tool or identity supplies each of the three. [Background](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/).

**Fix:** remove one of the three: drop the outbound channel, move the untrusted input to a separate agent with no data access, or require approval for outbound tools.

## Config findings

These come from reading MCP config files.

### FL201: Credential written into an MCP config

**Severity:** high

**What it means:** a password, token or key is written directly into a config file, where anyone with access to the repository can read it. Groot shows only the start of the value and hides the rest.

**Fix:** reference an environment variable or a secret manager instead, and rotate the exposed credential.

### FL202: MCP server package is not pinned to a version

**Severity:** medium

**What it means:** the server is started with a package name but no fixed version (for example `npx some-server` instead of `npx some-server@1.2.3`). The next start may pull a different release, including a compromised one.

**Fix:** pin an exact version (`pkg@1.2.3`, `pkg==1.2.3`, or `image@sha256:…`).

### FL203: Remote MCP server reached over plain HTTP

**Severity:** medium

**What it means:** tool calls, and any credentials sent with them, travel unencrypted.

**Fix:** use `https`, or keep the server on `localhost`.

### FL204: MCP server with unknown capabilities

**Severity:** low

**What it means:** Groot doesn't recognise this server, so it can't tell what the server lets the agent do. The agent's reach may be larger than reported.

**Fix:** review the server's tools yourself.

## Servers Groot recognises

Groot knows what these kinds of MCP server allow, and counts their powers in the agent's reach:

| Server kind | Powers |
| --- | --- |
| shell | exec, write, destroy, read |
| kubernetes | exec, write, destroy, secrets, read |
| aws | write, destroy, read |
| filesystem | read, write |
| github, gitlab | read, write, external, untrusted |
| slack | read, external |
| email | read, external, untrusted |
| fetch, browser | untrusted, external |
| database | read, write |
| payments | read, write, destroy |
