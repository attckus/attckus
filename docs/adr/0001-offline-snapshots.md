# ADR 0001: Scan offline snapshots, not live APIs

Status: accepted · 2026-11-02

## Context
Resolving what an agent can reach needs Kubernetes RBAC and AWS IAM. Calling those APIs directly means asking for credentials and passing a security review before anyone can try the tool.

## Decision
Scan reads files the customer exports with standard commands (`kubectl get ... -o json`, `aws iam get-account-authorization-details`). Snapshots are detected by content, so they can sit anywhere in the scanned directory.

## Consequences
- Zero-trust first run: no credentials, works air-gapped and in CI.
- Snapshots go stale; reports show what was exported, not what is live.
- Opt-in live collectors with read-only roles come in phase 2 for teams that want continuous scanning.
