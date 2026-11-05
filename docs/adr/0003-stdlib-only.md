# ADR 0003: Go standard library only

Status: accepted · 2026-11-02

## Context
Groot sits in the path of every tool call and inside customers' CI. Each dependency is supply-chain surface and a security-review question.

## Decision
Use only the Go standard library. Kubernetes and IAM inputs are JSON, which the standard library parses; MCP is JSON-RPC.

## Consequences
- One small static binary; trivial SBOM.
- YAML manifests are not read directly; users export JSON with kubectl.
- A dependency is added only when it clearly pays for itself (for example an HCL parser for Terraform-defined IAM).
