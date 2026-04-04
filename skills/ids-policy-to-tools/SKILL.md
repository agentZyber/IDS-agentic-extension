---
name: ids-policy-to-tools
description: Translate IDS Permission, ContractAgreement, and rule-wrapper JSON into conservative agent tool recommendations. Use this skill when a user wants to decide what an agent may read, fetch, download, or refuse based on IDS contracts, security profiles, assignee/assigner identity, or contract dates.
metadata:
  short-description: Translate IDS policy into agent permissions
---

# IDS Policy To Tools

## Overview

Use this skill when the input is an IDS policy artifact, not freeform governance text. It is designed for JSON or JSON-LD shaped like `ids:Permission`, `ids:ContractAgreement`, a connector rule wrapper whose `value` field contains embedded IDS JSON, or ACP/A2A communication envelopes carrying those IDS objects.

The skill does two things:

1. Normalize the IDS object into a small set of trust signals:
   `action`, `target`, `assigner`, `assignee`, `contractStart`, `contractEnd`, `securityProfile`, and whether duties or constraints are present.
2. Convert those trust signals into conservative agent-tool guidance such as:
   allow metadata fetches, allow target-scoped artifact reads, or deny arbitrary shell execution and broad filesystem writes.

## When To Use It

Use this skill when the user asks for any of the following:

- Translate an IDS contract into agent permissions
- Decide whether an agent may fetch or download an IDS artifact
- Turn a Dataspace Connector agreement into a tool allowlist
- Explain why an IDS policy should keep shell or write access disabled
- Review a contract agreement for agent-safe execution boundaries

Do not use this skill when the input is only human prose with no concrete IDS object to inspect. In that case, ask for the JSON policy, agreement, or rule payload first.

## Supported Inputs

The first version supports these shapes:

- A top-level `ids:Permission`
- A top-level `ids:ContractAgreement`
- A top-level list of permissions
- A wrapper object with a `value` field that contains serialized IDS JSON
- ACP `Run` / `Message` style envelopes with IDS JSON in message parts
- A2A `AgentCard`, JSON-RPC `message/send`, `Message`, and `Task` style envelopes with IDS JSON in message parts

The script can also pull nested `ids:permission` entries out of larger objects. It is intentionally conservative around unsupported IDS features such as rich duties and constraints.

## Entry Points

This skill now exposes three practical integration surfaces:

- `scripts/ids_policy_to_tools.py`
  Direct CLI translation of a concrete IDS object into agent-tool recommendations.
- `scripts/extract_ids_examples.py`
  Automatic extraction of real IDS policy and agreement payloads from the repo's markdown guides and Postman collections.
- `scripts/policy_mcp_server.py`
  A lightweight MCP-style stdio server exposing `evaluate_ids_policy` and `extract_repo_ids_examples`.

Use `scripts/run_harness.py` to smoke-test all of them together.

Read [references/architecture.md](./references/architecture.md) for the component and flow architecture of the tool.

## Workflow

### 1. Translate The IDS Object

Run the helper script first:

```bash
python3 skills/ids-policy-to-tools/scripts/ids_policy_to_tools.py \
  --input skills/ids-policy-to-tools/references/example-rule-wrapper.json \
  --format markdown
```

If you need principal-aware output, pass the expected consumer or assignee:

```bash
python3 skills/ids-policy-to-tools/scripts/ids_policy_to_tools.py \
  --input skills/ids-policy-to-tools/references/example-contract-agreement.json \
  --assignee https://connector_B \
  --format markdown
```

Use `--format json` when the output will feed another script or evaluation pipeline.

ACP example:

```bash
python3 skills/ids-policy-to-tools/scripts/ids_policy_to_tools.py \
  --input skills/ids-policy-to-tools/references/example-acp-run.json \
  --format markdown
```

A2A example:

```bash
python3 skills/ids-policy-to-tools/scripts/ids_policy_to_tools.py \
  --input skills/ids-policy-to-tools/references/example-a2a-message-send.json \
  --assignee https://connector_B \
  --format markdown
```

If you need repo-derived fixtures instead of hand-crafted examples, extract them first:

```bash
python3 skills/ids-policy-to-tools/scripts/extract_ids_examples.py \
  --format markdown \
  --limit 10
```

### 2. Apply The Recommendations Conservatively

Treat the script output as a recommended policy envelope, not automatic truth. In this version:

- `USE` plus an active agreement and matching assignee can unlock target-scoped artifact reads
- Metadata discovery is usually safer than artifact download and is allowed earlier
- Arbitrary shell execution, Docker mutation, and broad filesystem writes stay denied by default
- Any duties, constraints, or unsupported actions should trigger manual review

### 3. Escalate When The IDS Semantics Are Richer Than The Mapper

Read [references/policy-mapping.md](./references/policy-mapping.md) when you need the mapping rationale.

Read [references/repo-shapes.md](./references/repo-shapes.md) when you need to align the judgment with the IDS-testbed’s actual contract and negotiation examples.

If the input includes `ids:constraint`, `ids:preDuty`, `ids:postDuty`, `ids:prohibition`, or actions other than `USE`, do not widen permissions casually. Keep the result narrow and say manual interpretation is still required.

## MCP-Style API

Start the local stdio server with:

```bash
python3 skills/ids-policy-to-tools/scripts/policy_mcp_server.py
```

The server exposes two tools:

- `evaluate_ids_policy`
- `extract_repo_ids_examples`

See [references/integration-patterns.md](./references/integration-patterns.md) for the integration overview.
See [references/architecture.md](./references/architecture.md) for the full architecture.

## Tests

Run the smoke harness:

```bash
python3 skills/ids-policy-to-tools/scripts/run_harness.py
```

Run the protocol-focused unit tests:

```bash
python3 -m unittest discover -s skills/ids-policy-to-tools/tests -p 'test_*.py'
```

## Output Expectations

For normal interactive use, summarize the result in this order:

1. What the IDS object grants
2. What an agent may do
3. What stays denied
4. What requires human review

For automation use, prefer the script's JSON output and keep any extra narrative short.
