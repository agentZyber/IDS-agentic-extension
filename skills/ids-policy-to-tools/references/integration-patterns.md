# Integration Patterns

This skill now supports four agent-facing entry points.

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
- classifying ACP/A2A transport envelopes around embedded IDS payloads
- regression testing the mapper against real IDS-testbed flows

## 3. End-to-end project integration

Use the project integration script when you want the policy tooling connected to the real IDS-testbed assets:

- `scripts/testbed_agentic_integration.py`

Best for:

- reading the compose topology as agent context
- comparing connector configs with testsuite environment files
- evaluating extracted IDS examples against the configured applicant connector
- generating one report for the repo's current end-to-end agentic state

## 4. MCP-style server

Use the stdio server when another agent or tool runner wants a tool-shaped interface:

- `scripts/policy_mcp_server.py`

Exposed tools:

- `evaluate_ids_policy`
- `extract_repo_ids_examples`
- `inspect_testbed_project`

This is a lightweight MCP-style integration surface intended for local experimentation and adapter layers.

## 5. Harness

Use the harness to validate that all three entry points still work together:

- `scripts/run_harness.py`
