#!/usr/bin/env python3
"""
Translate IDS policy artifacts into conservative agent-tool recommendations.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Translate IDS Permission or ContractAgreement JSON into "
            "recommended agent tool permissions."
        )
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a JSON file or '-' to read from stdin.",
    )
    parser.add_argument(
        "--assignee",
        help="Expected assignee/consumer identifier used to validate principal match.",
    )
    parser.add_argument(
        "--security-profile",
        help="Override the detected IDS security profile.",
    )
    parser.add_argument(
        "--now",
        help="Evaluation time in ISO 8601 form. Defaults to the current UTC time.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output format.",
    )
    return parser.parse_args()


def load_input(path: str) -> Any:
    if path == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(path).read_text()
    return decode_jsonish(raw)


def decode_jsonish(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return value
        if looks_like_json(stripped):
            try:
                return decode_jsonish(json.loads(stripped))
            except json.JSONDecodeError:
                return value
        return value
    if isinstance(value, list):
        return [decode_jsonish(item) for item in value]
    if isinstance(value, dict):
        return {key: decode_jsonish(item) for key, item in value.items()}
    return value


def looks_like_json(text: str) -> bool:
    return (
        (text.startswith("{") and text.endswith("}"))
        or (text.startswith("[") and text.endswith("]"))
        or (text.startswith('"') and text.endswith('"'))
    )


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def type_values(obj: dict[str, Any]) -> list[str]:
    return [str(item) for item in as_list(obj.get("@type"))]


def is_type(obj: Any, expected: str) -> bool:
    return isinstance(obj, dict) and expected in type_values(obj)


def ids_to_strings(value: Any) -> list[str]:
    results: list[str] = []
    for item in as_list(value):
        if isinstance(item, dict):
            if "@id" in item:
                results.append(str(item["@id"]))
            elif "@value" in item:
                results.append(str(item["@value"]))
        elif item is not None:
            results.append(str(item))
    return results


def extract_permissions(node: Any) -> list[dict[str, Any]]:
    permissions: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if is_type(value, "ids:Permission"):
                permissions.append(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(node)
    return permissions


def find_ids_recursively(node: Any, target_key: str) -> list[str]:
    values: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == target_key:
                    values.extend(ids_to_strings(child))
                visit(child)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(node)
    return unique(values)


def find_type_recursively(node: Any, expected: str) -> bool:
    found = False

    def visit(value: Any) -> None:
        nonlocal found
        if found:
            return
        if isinstance(value, dict):
            if is_type(value, expected):
                found = True
                return
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(node)
    return found


def has_nonempty_field(node: dict[str, Any], key: str) -> bool:
    value = node.get(key)
    if value is None:
        return False
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, dict):
        return bool(value)
    return True


def unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def parse_datetimeish(value: Any) -> datetime | None:
    if isinstance(value, dict):
        value = value.get("@value")
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    for pattern in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(text, pattern)
        except ValueError:
            continue
    return None


def determine_now(raw_now: str | None) -> datetime:
    if raw_now:
        parsed = parse_datetimeish(raw_now)
        if parsed is None:
            raise SystemExit(f"Could not parse --now value: {raw_now}")
        return ensure_tz(parsed)
    return datetime.now(timezone.utc)


def ensure_tz(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def compact_action(action_id: str) -> str:
    if "/" in action_id:
        return action_id.rsplit("/", 1)[-1]
    return action_id


def summarize(source: Any, assignee: str | None, security_profile: str | None, now: datetime) -> dict[str, Any]:
    permissions = extract_permissions(source)
    actions = unique(
        compact_action(action)
        for permission in permissions
        for action in ids_to_strings(permission.get("ids:action"))
    )
    actions = [action for action in actions if action]

    permission_assignees = unique(
        assignee_id
        for permission in permissions
        for assignee_id in ids_to_strings(permission.get("ids:assignee"))
    )
    permission_assigners = unique(
        assigner_id
        for permission in permissions
        for assigner_id in ids_to_strings(permission.get("ids:assigner"))
    )
    permission_targets = unique(
        target_id
        for permission in permissions
        for target_id in ids_to_strings(permission.get("ids:target"))
    )

    contract_start = parse_datetimeish(
        source.get("ids:contractStart") if isinstance(source, dict) else None
    )
    contract_end = parse_datetimeish(
        source.get("ids:contractEnd") if isinstance(source, dict) else None
    )
    contract_active: bool | None = None
    if contract_start or contract_end:
        lower_ok = contract_start is None or now >= ensure_tz(contract_start)
        upper_ok = contract_end is None or now <= ensure_tz(contract_end)
        contract_active = lower_ok and upper_ok

    providers = []
    consumers = []
    if isinstance(source, dict):
        providers = ids_to_strings(source.get("ids:provider"))
        consumers = ids_to_strings(source.get("ids:consumer"))

    detected_security_profiles = find_ids_recursively(source, "ids:securityProfile")
    security_profile = security_profile or (detected_security_profiles[0] if detected_security_profiles else None)

    has_constraints = any(
        has_nonempty_field(permission, "ids:constraint") for permission in permissions
    )
    has_pre_duties = any(
        has_nonempty_field(permission, "ids:preDuty") for permission in permissions
    )
    has_post_duties = any(
        has_nonempty_field(permission, "ids:postDuty") for permission in permissions
    )
    has_prohibitions = find_type_recursively(source, "ids:Prohibition")
    has_contract_agreement_context = find_type_recursively(source, "ids:ContractAgreement")

    principal_match: bool | None = None
    if assignee and permission_assignees:
        principal_match = assignee in permission_assignees
    elif assignee and consumers:
        principal_match = assignee in consumers

    if isinstance(source, dict):
        source_types = type_values(source)
        if not source_types and "value" in source:
            source_types = ["rule-wrapper"]
        elif not source_types and permissions:
            source_types = ["untyped-ids-envelope"]
    elif isinstance(source, list):
        source_types = ["list"]
    else:
        source_types = [type(source).__name__]

    return {
        "source_types": source_types,
        "permissions_found": len(permissions),
        "actions": actions,
        "targets": permission_targets,
        "permission_assignees": permission_assignees,
        "permission_assigners": permission_assigners,
        "providers": providers,
        "consumers": consumers,
        "contract_start": contract_start.isoformat() if contract_start else None,
        "contract_end": contract_end.isoformat() if contract_end else None,
        "contract_active": contract_active,
        "security_profile": security_profile,
        "principal_under_test": assignee,
        "principal_match": principal_match,
        "has_constraints": has_constraints,
        "has_pre_duties": has_pre_duties,
        "has_post_duties": has_post_duties,
        "has_prohibitions": has_prohibitions,
        "evaluation_time": now.isoformat(),
        "has_contract_agreement_context": has_contract_agreement_context,
    }


def recommendation(tool: str, decision: str, reason: str, scope: str) -> dict[str, str]:
    return {
        "tool": tool,
        "decision": decision,
        "reason": reason,
        "scope": scope,
    }


def build_recommendations(summary: dict[str, Any]) -> dict[str, Any]:
    allow: list[dict[str, str]] = []
    conditional: list[dict[str, str]] = []
    deny: list[dict[str, str]] = []
    findings: list[str] = []

    allow.append(
        recommendation(
            "filesystem.read",
            "allow",
            "The agent may inspect local IDS policy and agreement files.",
            "Local policy artifacts only.",
        )
    )
    allow.append(
        recommendation(
            "web.fetch.metadata",
            "allow",
            "Metadata inspection is lower risk than artifact download and is needed to inspect broker, connector, and agreement state.",
            "Broker metadata, connector self-descriptions, and agreement endpoints.",
        )
    )

    deny.append(
        recommendation(
            "exec_command",
            "deny",
            "This IDS mapper does not treat contracts as permission for arbitrary local execution.",
            "Keep shell execution out of the data-use path by default.",
        )
    )
    deny.append(
        recommendation(
            "docker.compose",
            "deny",
            "An IDS contract does not authorize local infrastructure mutation.",
            "Do not start, stop, or reconfigure containers based only on a data-use agreement.",
        )
    )
    deny.append(
        recommendation(
            "filesystem.write",
            "deny",
            "Persisting governed data locally needs a separate retention or processing decision.",
            "No unrestricted local writes of downloaded artifacts.",
        )
    )
    deny.append(
        recommendation(
            "web.fetch.unscoped",
            "deny",
            "Network access should stay limited to IDS endpoints related to the agreement.",
            "No arbitrary internet fetches.",
        )
    )

    actions = set(summary["actions"])
    has_use = "USE" in actions
    contract_active = summary["contract_active"]
    principal_match = summary["principal_match"]
    principal_under_test = summary["principal_under_test"]
    permission_assignees = summary["permission_assignees"]
    targets = summary["targets"]
    has_contract_agreement_context = summary["has_contract_agreement_context"]
    complex_controls = any(
        [
            summary["has_constraints"],
            summary["has_pre_duties"],
            summary["has_post_duties"],
            summary["has_prohibitions"],
        ]
    )

    unsupported_actions = sorted(action for action in actions if action != "USE")
    if unsupported_actions:
        findings.append(
            "Unsupported IDS actions detected: "
            + ", ".join(unsupported_actions)
            + ". Keep permissions narrow and review manually."
        )

    if complex_controls:
        findings.append(
            "Constraints, duties, or prohibitions are present. The mapper surfaces them but does not fully evaluate their semantics."
        )

    if has_use:
        if not has_contract_agreement_context:
            allow.append(
                recommendation(
                    "web.post.contract",
                    "allow",
                    "A USE permission can justify contract negotiation against the provider connector.",
                    "Only IDS contract-negotiation endpoints for the relevant provider and resource.",
                )
            )
            conditional.append(
                recommendation(
                    "web.fetch.artifact",
                    "conditional",
                    "A standalone permission is not enough for data download. Negotiate and validate a contract agreement first.",
                    "Only after an agreement binds the target and consumer.",
                )
            )
        elif contract_active is False:
            conditional.append(
                recommendation(
                    "web.fetch.artifact",
                    "conditional",
                    "A USE permission exists but the agreement is outside its active time window.",
                    "Only proceed after renewing or revalidating the agreement.",
                )
            )
        elif contract_active is None:
            conditional.append(
                recommendation(
                    "web.fetch.artifact",
                    "conditional",
                    "The object looks like a contract agreement but its active window could not be verified.",
                    "Validate agreement lifecycle before downloading data.",
                )
            )
        elif principal_match is False:
            deny.append(
                recommendation(
                    "web.fetch.artifact",
                    "deny",
                    "The tested assignee does not match the agreement assignee.",
                    "Do not fetch target artifacts for a different principal.",
                )
            )
        elif permission_assignees and principal_under_test is None:
            conditional.append(
                recommendation(
                    "web.fetch.artifact",
                    "conditional",
                    "The agreement binds a specific assignee, but no assignee was supplied for validation.",
                    "Pass --assignee before widening artifact access.",
                )
            )
        elif not targets:
            conditional.append(
                recommendation(
                    "web.fetch.artifact",
                    "conditional",
                    "A USE permission exists but no concrete target artifact was resolved.",
                    "Resolve the target artifact through the agreement before downloading data.",
                )
            )
        elif complex_controls or unsupported_actions:
            conditional.append(
                recommendation(
                    "web.fetch.artifact",
                    "conditional",
                    "Target-scoped fetch is plausible, but richer IDS controls require manual interpretation first.",
                    "Only the listed target artifacts after human review.",
                )
            )
        else:
            allow.append(
                recommendation(
                    "web.fetch.artifact",
                    "allow",
                    "The contract expresses USE for concrete targets and no unsupported controls were detected.",
                    "Only these targets: " + ", ".join(targets),
                )
            )
    else:
        findings.append(
            "No USE action was found, so artifact fetch should not be widened automatically."
        )

    security_profile = summary["security_profile"]
    if security_profile and security_profile.endswith("BASE_SECURITY_PROFILE"):
        findings.append(
            "BASE_SECURITY_PROFILE detected. Keep permissions narrow and prefer scoped read-only access."
        )

    return {
        "findings": findings,
        "allow": allow,
        "conditional": conditional,
        "deny": deny,
    }


def render_markdown(summary: dict[str, Any], recommendations: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# IDS Policy Translation")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Source types: {', '.join(summary['source_types'])}")
    lines.append(f"- Permissions found: {summary['permissions_found']}")
    lines.append(f"- Actions: {', '.join(summary['actions']) if summary['actions'] else 'none'}")
    lines.append(f"- Targets: {', '.join(summary['targets']) if summary['targets'] else 'none'}")
    lines.append(
        f"- Contract active: {summary['contract_active'] if summary['contract_active'] is not None else 'unknown'}"
    )
    lines.append(
        f"- Principal match: {summary['principal_match'] if summary['principal_match'] is not None else 'not tested'}"
    )
    lines.append(
        f"- Security profile: {summary['security_profile'] or 'not detected'}"
    )
    lines.append("")

    if recommendations["findings"]:
        lines.append("## Findings")
        for finding in recommendations["findings"]:
            lines.append(f"- {finding}")
        lines.append("")

    for title, bucket in (
        ("Allow", recommendations["allow"]),
        ("Conditional", recommendations["conditional"]),
        ("Deny", recommendations["deny"]),
    ):
        lines.append(f"## {title}")
        for item in bucket:
            lines.append(
                f"- `{item['tool']}`: {item['reason']} Scope: {item['scope']}"
            )
        if not bucket:
            lines.append("- none")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    args = parse_args()
    source = load_input(args.input)
    now = determine_now(args.now)
    summary = summarize(
        source=source,
        assignee=args.assignee,
        security_profile=args.security_profile,
        now=now,
    )
    recommendations = build_recommendations(summary)
    payload = {
        "summary": summary,
        "recommendations": recommendations,
        "note": (
            "These are conservative recommendations for agent tool scope, not automatic IDS enforcement."
        ),
    }

    if args.format == "json":
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_markdown(summary, recommendations))


if __name__ == "__main__":
    main()
