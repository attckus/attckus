# ADR 0004: One capability model for scan, gateway and analyzer

Status: accepted · 2026-11-02

## Context
The scanner ranks IAM actions, RBAC verbs and MCP servers; the gateway's default policy denies dangerous tools; the analyzer decides which repeated calls are side effects and which switches are escalations.

## Decision
`internal/capability` defines eight classes (admin, exec, destroy, secrets, write, external, untrusted, read), their ranking, the AWS action catalogue, RBAC classification, MCP server profiles and the tool-name classifier. Every component uses it.

## Consequences
- Consistent language across reports, policies and analysis.
- Classification by name is heuristic; misclassifications show up in one place and are fixed once.
