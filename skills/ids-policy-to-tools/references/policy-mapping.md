# Policy Mapping

This skill maps IDS trust and contract signals into conservative agent-tool guidance.

## Design Rule

The mapper should only widen agent permissions when the IDS object is explicit enough to justify it.

That means:

- Metadata inspection is safer than data download
- Active agreements are stronger than standalone permissions
- Matching assignee identity is stronger than an unbound permission
- Duties, constraints, and prohibitions should narrow or pause automation

## Current Mapping Surface

### Core IDS signals

- `ids:action`
- `ids:target`
- `ids:assigner`
- `ids:assignee`
- `ids:contractStart`
- `ids:contractEnd`
- `ids:securityProfile`
- `ids:constraint`
- `ids:preDuty`
- `ids:postDuty`
- `ids:prohibition`

### Current action support

- `USE`
  Supported. This is interpreted as a candidate grant for reading or fetching the target artifact, subject to contract window and assignee checks.

### Unsupported or partial semantics

- Non-`USE` actions
  Flag for manual review.
- Constraints, duties, prohibitions
  Parsed and surfaced, but not fully evaluated. Keep permissions narrow.

## Agent Capability Recommendations

### Usually allowed

- `filesystem.read`
  The agent may inspect local contract or policy files.
- `web.fetch.metadata`
  The agent may query broker metadata, connector self-descriptions, and agreement metadata.

### Allowed only when contract signals are strong

- `web.fetch.artifact`
  Allow only if there is a `USE` permission, the contract is active, the assignee matches when specified, and the target artifact is known.

### Usually denied

- `exec_command`
  IDS contracts do not imply arbitrary local code execution.
- `docker.compose`
  IDS contracts do not imply permission to mutate local infrastructure.
- `filesystem.write`
  Persisting governed data locally needs a separate retention or processing policy.
- `web.fetch.unscoped`
  Keep network access limited to the broker, connector metadata, and the target artifacts covered by the agreement.

## Security Profile Notes

### `idsc:BASE_SECURITY_PROFILE`

Interpret this as a reason to keep permissions narrow:

- scoped network reads over broad access
- no arbitrary shell execution
- no broad write permissions by default

This skill does not currently assign different concrete tool bundles for stronger IDS security profiles. That is a good next increment.
