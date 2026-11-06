---
title: User guide
nav_order: 4
has_children: true
permalink: /guide/
---

# User guide

Step-by-step guides for using Groot on your own agents and your own infrastructure.

If you haven't yet, run the demo first ([Getting started](../getting-started.md)) and skim [Concepts](../concepts.md). The guides assume you know what a scenario, an attack, a fault and a policy are.

## Testing an agent

Follow these in order the first time.

1. **[Connect your agent](connect-your-agent.md):** the one small change that lets Groot sit between your agent and its tools.
2. **[Write a test suite](write-a-suite.md):** describe how to run your agent and which scenarios to try.
3. **[Attacks and failures](attacks-and-failures.md):** choose what to plant and what to break, including attacks during an outage.
4. **[Set a permission boundary](permission-boundary.md):** write the policy the agent must stay inside.

## Mapping reach

5. **[Scan your environment](scan-your-environment.md):** export your Kubernetes and AWS permissions and find out what each agent can touch.

## Sharing results

6. **[Reports](reports.md):** the HTML report and the other output formats.
7. **[Run in CI](ci.md):** fail builds on unsafe behaviour or dangerous reach, in GitHub Actions or any other CI.
