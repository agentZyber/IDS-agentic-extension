# Integration Patterns

This skill now supports three agent-facing entry points.

See [architecture.md](./architecture.md) for the component architecture and data flows behind these entry points.

## 1. Direct CLI translation

Use the CLI when a human or script already has the IDS object:

- `scripts/ids_policy_to_tools.py`

Best for:

- local review
- CI checks
- generating a JSON permission envelope for another tool
- evaluating ACP message/run envelopes carrying IDS policy
- evaluating A2A AgentCard or `message/send` envelopes carrying IDS policy

## 2. Repo extraction

Use the extractor when you want to mine real examples from this repo's docs and collections:

- `scripts/extract_ids_examples.py`

Best for:

- building eval fixtures from the current repo
- pulling fresh policy samples after Postman collection changes
- regression testing the mapper against real IDS-testbed flows

## 3. MCP-style server

Use the stdio server when another agent or tool runner wants a tool-shaped interface:

- `scripts/policy_mcp_server.py`

Exposed tools:

- `evaluate_ids_policy`
- `extract_repo_ids_examples`

This is a lightweight MCP-style integration surface intended for local experimentation and adapter layers.

## 4. Harness

Use the harness to validate that all three entry points still work together:

- `scripts/run_harness.py`
