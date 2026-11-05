# ADR 0002: Enforce at an MCP proxy, not inside agent frameworks

Status: accepted · 2026-11-02

## Context
Agents are written in many frameworks and languages. Tool access increasingly goes through MCP.

## Decision
The gateway is a transparent MCP proxy (stdio wrapper and Streamable HTTP reverse proxy). Agents change one line of config, not code. Blocked calls return MCP `isError` results so the model sees the reason.

## Consequences
- Works with any MCP client regardless of framework.
- Tools called outside MCP (direct SDK calls with the pod's IAM role) are not enforced by the gateway; scan still reports them. Identity-level fixes (narrower roles) remain the primary control.
- The gateway sees tool names and arguments, not the model's reasoning; detectors work on behaviour.
