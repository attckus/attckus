# ADR 0005: Reuse zoko's model passthrough for the LLM gateway

Status: accepted · 2026-11-03

## Context
Many agents call model APIs directly with provider function calling, so the MCP gateway never sees their tools. Zoko (the agent platform) already has a drop-in passthrough for the Anthropic and OpenAI APIs with streaming, usage metering, a price table and budget clamping, tested in production-like use.

## Decision
Port from zoko's `internal/gateway`: `passthrough.go` (forwarding, header handling, budget clamp, OpenAI `include_usage`, usage parsing) and `pricing.go` (price table, defaults, `fitOutputTokens`). Rewrite `gjson`/`sjson` usage on `encoding/json` and drop OpenTelemetry, keeping Groot dependency-free (ADR 0003). Do not port zoko's provider-neutral request model, SDK-based adapters, fallback chains or orchestration: Groot is a transparent proxy, not a client.

Add on top: tool-call policy for JSON and streaming responses, per-agent budgets from the policy file, model allowlist, kill switch, provider fault injection, and Groot's audit log.

## Consequences
- One implementation of usage parsing and pricing to maintain across both projects; changes should be mirrored (or extracted into a shared module later).
- Default behaviour differs from zoko: Groot forwards the caller's credentials unless `--inject-keys` is set, because a security tool should not need to hold provider keys.
- OpenTelemetry spans are a phase 1 item for both gateways.
