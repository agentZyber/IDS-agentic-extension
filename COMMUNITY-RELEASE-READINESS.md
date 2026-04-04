# Community Release Readiness

This document summarizes what is now ready for public use in this repository and what was tightened to make the setup easier for the community to adopt.

## Scope

This publish-readiness pass covers two connected surfaces:

1. The IDS reference testbed and MVDS deployment flow
2. The repo-local `ids-policy-to-tools` agentic extension

The goal is that a public user can:

- understand what the repository is for
- deploy the local IDS stack
- validate broker, connector, agreement, and artifact flows
- evaluate IDS policy artifacts with the agentic tooling
- reuse the scripts and docs without thread-specific context

## What Is Ready

### 1. Reference MVDS deployment

The repository contains a working local IDS stack built from:

- DAPS / Omejdn
- two Dataspace Connectors
- Metadata Broker
- PostgreSQL backends for both connectors

The deployment can be started with `docker compose up -d`.

For environments where host port `8080` is already occupied, the repository now also provides a repeatable fallback path through:

- `Testsuite/run_live_connector_suite.sh`

That helper can start the main stack, reuse or start a fallback `connectora` container on a different host port, register both connectors with the broker, and execute the connector suite.

### 2. Automated interoperability validation

The connector testsuite is now ready for public use with the current repo topology.

The following gaps were fixed:

- the broker inquiry test now uses the broker catalog identifier exposed by this repo: `https://broker-reverseproxy/connectors/`
- the agreement-artifact retrieval flow no longer assumes the provider agreement lives on `https://localhost:8080`
- the shell runner creates the `Testsuite/results` directory automatically
- a live deployment helper is available for users who want one command for deployment plus validation

### 3. Agentic IDS policy tooling

The `skills/ids-policy-to-tools` extension is ready as a repo-local public artifact with:

- direct CLI evaluation
- repo example extraction
- end-to-end project integration reporting
- MCP-style stdio exposure
- protocol coverage for IDS, ACP, and A2A envelopes

The public entry points are:

- `skills/ids-policy-to-tools/scripts/ids_policy_to_tools.py`
- `skills/ids-policy-to-tools/scripts/extract_ids_examples.py`
- `skills/ids-policy-to-tools/scripts/testbed_agentic_integration.py`
- `skills/ids-policy-to-tools/scripts/policy_mcp_server.py`
- `skills/ids-policy-to-tools/scripts/run_harness.py`

## Public Entry Points

### Repo quick start

- `README.md`
- `InstallationGuide.md`
- `PreparingPreconfiguredSetup.md`
- `TestbedUserGuide.md`
- `minimum-viable-data-space/MVDS.md`

### Testsuite quick start

- `Testsuite/README.md`
- `Testsuite/execute.sh`
- `Testsuite/run_live_connector_suite.sh`

### Agentic quick start

- `skills/ids-policy-to-tools/SKILL.md`
- `skills/ids-policy-to-tools/references/architecture.md`
- `skills/ids-policy-to-tools/references/integration-patterns.md`

## Validated Workflows

The repository now has a documented and validated path for:

1. deploying the IDS testbed locally
2. registering both connectors with the broker
3. querying the broker catalog through IDS message exchange
4. negotiating an IDS agreement between the connectors
5. fetching governed artifacts from the negotiated agreement
6. translating real IDS agreements into conservative agent-tool recommendations
7. exposing those recommendations through a tool-shaped MCP-style interface

## Documentation Improvements Included In This Pass

- Root README updated to explain the agentic extension and public entry points
- Testsuite README updated with host-port override guidance and the live deployment helper
- Skill docs aligned with the repo-wide project integration flow
- Changelog updated to describe the new release-ready surfaces
- This readiness document added for maintainers and community adopters

## Integration Improvements Included In This Pass

- broker lookup test aligned with the actual broker catalog identifier
- agreement-artifact retrieval aligned with the live agreement URL returned by the provider connector
- repeatable live deployment helper added for local community use
- generated cache and report paths excluded from git noise

## Operational Assumptions

Community users should expect the following local requirements:

- Docker and Docker Compose
- Python 3
- Node.js
- Newman for the testsuite
- optional `newman-reporter-html` and `htmldoc` if PDF reports are desired

The local default ports used by the stack include:

- `80`, `443`
- `81`, `444`
- `5432`, `5433`
- `8080`, `8081`

If `8080` is already in use, the live helper handles the common fallback case automatically.

## Known Limitations

- The policy tooling is intentionally conservative around rich IDS duties, constraints, prohibitions, and non-`USE` actions.
- ACP and A2A support is scoped to communication context and envelope detection; they are not treated as standalone authorization sources.
- The live helper assumes the default connector basic-auth credentials unless the caller overrides `ADMIN_USERNAME` and `ADMIN_PASSWORD`.
- The MCP-style server is intentionally lightweight and intended for local integration and experimentation rather than production-grade remote hosting.

## Publish Recommendation

The repository is ready to be published and used publicly as:

- a local IDS reference testbed / MVDS
- an interoperability validation environment
- a reference implementation for agent-aware IDS policy translation
- a starting point for community experiments around IDS plus ACP/A2A-aware agent runtimes

Before a public announcement, the remaining recommended maintainer step is only to review and commit the current documentation and testsuite changes together so the public branch matches the validated workflow described here.
