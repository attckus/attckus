# ADR 0006: Verification first; production proxy parked

Status: accepted · 2026-11-05

## Context
Groot had three parts: scan, an always-on production gateway, and chaos plus analysis. Selling a production proxy from an early-stage project needs trust that takes years (HA, latency guarantees, security review of something in every request path). Teams adopt CI tools much faster. Security budgets are larger than reliability budgets, and pre-deployment security testing of agents is a proven buying category.

## Decision
The product is `groot test`: security and resilience scenarios for AI agents, run in CI against test environments. The gateways stay as the test harness. Their production use remains available as a preview, with no new production-only features (approval workflows, central policy server, persistent budgets, HA) until test users ask.

Attack scenarios are part of the core, so the pitch is security testing, not chaos tooling.

## Consequences
- Much smaller surface for one maintainer; one clear output (a verdict per pull request).
- Lower trust barrier: nothing sits in front of production traffic.
- The production proxy becomes the natural paid tier later.
- Groot must make agents easy to point at its MCP config; framework quickstarts move up the backlog.
