#!/usr/bin/env python3
"""
Build an end-to-end agentic integration report for the IDS testbed repository.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from extract_ids_examples import default_paths, extract_from_paths
from ids_policy_to_tools import build_recommendations, determine_now, summarize


REPO_ROOT = Path(__file__).resolve().parents[3]
CONNECTOR_CONFIG_PATHS = (
    ("connectora", REPO_ROOT / "DataspaceConnectorA" / "conf" / "config.json"),
    ("connectorb", REPO_ROOT / "DataspaceConnectorB" / "conf" / "config.json"),
)
TESTSUITE_ENV_PATHS = (
    (
        "connector",
        REPO_ROOT
        / "Testsuite"
        / "env"
        / "Applicant_IDS_Connector_Test_Configuration.postman_environment.json",
    ),
    (
        "broker",
        REPO_ROOT
        / "Testsuite"
        / "env"
        / "Applicant_IDS_Broker_Test_Configuration.postman_environment.json",
    ),
)
TESTSUITE_COLLECTION_PATHS = (
    REPO_ROOT / "TestbedPreconfiguration.postman_collection.json",
    REPO_ROOT / "Testsuite" / "Testsuite.postman_collection.json",
)
REQUIRED_SERVICES = ("omejdn", "connectora", "connectorb", "broker-reverseproxy")
TEMPLATE_PATTERN = re.compile(r"{{\s*([^{}]+?)\s*}}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect the IDS testbed repo and build an end-to-end integration report "
            "covering topology, connector configs, testsuite alignment, and policy evaluation."
        )
    )
    parser.add_argument(
        "--assignee",
        help="Override the principal under test. Defaults to the applicant connector ID.",
    )
    parser.add_argument(
        "--security-profile",
        help="Override the security profile used during policy evaluation.",
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
    parser.add_argument(
        "--include-examples",
        action="store_true",
        help="Include per-example evaluation snapshots in the output.",
    )
    parser.add_argument(
        "--example-limit",
        type=int,
        help="Maximum number of example snapshots to include when --include-examples is set.",
    )
    return parser.parse_args()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def first_literal(value: Any) -> str | None:
    for item in as_list(value):
        if isinstance(item, dict):
            if "@id" in item and item["@id"] is not None:
                return str(item["@id"])
            if "@value" in item and item["@value"] is not None:
                return str(item["@value"])
        elif item is not None:
            return str(item)
    return None


def normalize_port_mapping(raw: str) -> str:
    cleaned = raw.split("#", 1)[0].strip()
    return cleaned.strip("'\"")


def normalize_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "/" in text:
        return text.rsplit("/", 1)[-1]
    if ":" in text:
        return text.rsplit(":", 1)[-1]
    return text


def parse_port_mapping(raw: str) -> dict[str, str | None]:
    mapping = normalize_port_mapping(raw)
    parts = mapping.split(":")
    host_port: str | None = None
    container_port: str | None = None
    if len(parts) == 1:
        container_port = parts[0].strip() or None
    elif len(parts) >= 2:
        host_port = parts[-2].strip() or None
        container_port = parts[-1].strip() or None
    return {
        "mapping": mapping,
        "host_port": host_port,
        "container_port": container_port,
    }


def parse_compose_services(path: Path) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    in_services = False
    current: dict[str, Any] | None = None
    active_block: str | None = None

    for raw_line in path.read_text().splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            in_services = stripped == "services:"
            current = None
            active_block = None
            continue
        if not in_services:
            continue

        if indent == 2 and stripped.endswith(":"):
            current = {
                "name": stripped[:-1],
                "container_name": None,
                "published_ports": [],
                "depends_on": [],
            }
            services.append(current)
            active_block = None
            continue

        if current is None:
            continue

        if indent == 4 and stripped.startswith("container_name:"):
            current["container_name"] = stripped.partition(":")[2].strip().strip("'\"")
            active_block = None
            continue
        if indent == 4 and stripped == "ports:":
            active_block = "ports"
            continue
        if indent == 4 and stripped == "depends_on:":
            active_block = "depends_on"
            continue
        if indent == 4 and stripped.endswith(":"):
            active_block = None
            continue
        if indent >= 6 and stripped.startswith("-") and active_block == "ports":
            current["published_ports"].append(parse_port_mapping(stripped[1:].strip()))
            continue
        if indent >= 6 and stripped.startswith("-") and active_block == "depends_on":
            current["depends_on"].append(stripped[1:].strip())

    return services


def parse_connector_config(name: str, path: Path) -> dict[str, Any]:
    payload = load_json(path)
    description = payload.get("ids:connectorDescription", {})
    endpoint = description.get("ids:hasDefaultEndpoint", {})
    return {
        "name": name,
        "source_file": str(path.relative_to(REPO_ROOT)),
        "connector_id": description.get("@id"),
        "title": first_literal(description.get("ids:title")),
        "description": first_literal(description.get("ids:description")),
        "default_endpoint": first_literal(endpoint.get("ids:accessURL")),
        "security_profile": first_literal(description.get("ids:securityProfile")),
        "deploy_mode": first_literal(payload.get("ids:connectorDeployMode")),
        "status": first_literal(payload.get("ids:connectorStatus")),
        "curator": first_literal(description.get("ids:curator")),
        "maintainer": first_literal(description.get("ids:maintainer")),
        "outbound_model_version": description.get("ids:outboundModelVersion"),
        "inbound_model_versions": [str(item) for item in as_list(description.get("ids:inboundModelVersion"))],
    }


def parse_testsuite_environment(name: str, path: Path) -> dict[str, Any]:
    payload = load_json(path)
    values = {
        str(item.get("key")): item.get("value")
        for item in payload.get("values", [])
        if item.get("key") is not None
    }
    return {
        "name": name,
        "source_file": str(path.relative_to(REPO_ROOT)),
        "values": values,
    }


def resolve_templates(value: str | None, variables: dict[str, Any]) -> str | None:
    if value is None:
        return None
    resolved = str(value)
    for _ in range(10):
        updated = TEMPLATE_PATTERN.sub(
            lambda match: str(variables.get(match.group(1), match.group(0))),
            resolved,
        )
        if updated == resolved:
            return updated
        resolved = updated
    return resolved


def parse_collection_summary(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    return {
        "source_file": str(path.relative_to(REPO_ROOT)),
        "name": payload.get("info", {}).get("name", path.name),
        "top_level_folders": [
            item.get("name")
            for item in payload.get("item", [])
            if item.get("name")
        ],
    }


def sort_counter(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def make_alignment_check(
    name: str,
    ok: bool,
    expected: str | None,
    observed: str | None,
    message: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "ok": ok,
        "expected": expected,
        "observed": observed,
        "message": message,
    }


def service_port_lookup(services: list[dict[str, Any]], service_name: str, container_port: str) -> str | None:
    for service in services:
        if service["name"] != service_name:
            continue
        for mapping in service["published_ports"]:
            if mapping.get("container_port") == container_port:
                return mapping.get("host_port")
    return None


def alignment_checks(
    connectors: list[dict[str, Any]],
    services: list[dict[str, Any]],
    testsuite_envs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    connector_by_name = {item["name"]: item for item in connectors}
    env_by_name = {item["name"]: item for item in testsuite_envs}

    connector_b = connector_by_name.get("connectorb")
    connector_env = env_by_name.get("connector")
    if connector_b and connector_env:
        env_values = connector_env["values"]
        endpoint = urlparse(connector_b["default_endpoint"] or "")
        resolved_access_url = resolve_templates(
            env_values.get("APPLICANT_CONNECTOR_ACCESS_URL"),
            env_values,
        )
        checks.extend(
            [
                make_alignment_check(
                    "connector_env.connector_id",
                    connector_b["connector_id"] == env_values.get("APPLICANT_CONNECTOR_ID"),
                    connector_b["connector_id"],
                    env_values.get("APPLICANT_CONNECTOR_ID"),
                    "Testsuite applicant connector ID should match the live connector B configuration.",
                ),
                make_alignment_check(
                    "connector_env.security_profile",
                    normalize_identifier(connector_b["security_profile"])
                    == normalize_identifier(env_values.get("APPLICANT_SECURITY_PROFILE")),
                    connector_b["security_profile"],
                    env_values.get("APPLICANT_SECURITY_PROFILE"),
                    "Testsuite security profile should match connector B.",
                ),
                make_alignment_check(
                    "connector_env.endpoint_host",
                    endpoint.hostname == env_values.get("APPLICANT_CONNECTOR_IP_DNS"),
                    endpoint.hostname,
                    env_values.get("APPLICANT_CONNECTOR_IP_DNS"),
                    "Testsuite applicant host should match the configured connector endpoint host.",
                ),
                make_alignment_check(
                    "connector_env.endpoint_port",
                    str(endpoint.port) == str(env_values.get("APPLICANT_CONNECTOR_PORT")),
                    str(endpoint.port) if endpoint.port is not None else None,
                    str(env_values.get("APPLICANT_CONNECTOR_PORT")),
                    "Testsuite applicant port should match the configured connector endpoint port.",
                ),
                make_alignment_check(
                    "connector_env.access_path",
                    endpoint.path == resolved_access_url,
                    endpoint.path,
                    resolved_access_url,
                    "Testsuite applicant access path should resolve to the connector endpoint path.",
                ),
            ]
        )

    required_present = {
        name for name in REQUIRED_SERVICES if any(service["name"] == name for service in services)
    }
    checks.append(
        make_alignment_check(
            "compose.required_services",
            len(required_present) == len(REQUIRED_SERVICES),
            ", ".join(REQUIRED_SERVICES),
            ", ".join(sorted(required_present)),
            "The compose topology should expose the expected IDS testbed services.",
        )
    )

    broker_env = env_by_name.get("broker")
    if broker_env:
        expected_port = service_port_lookup(services, "broker-reverseproxy", "443")
        observed_port = broker_env["values"].get("APPLICANT_BROKER_PORT")
        checks.append(
            make_alignment_check(
                "broker_env.reverseproxy_https_port",
                str(expected_port) == str(observed_port),
                str(expected_port) if expected_port is not None else None,
                str(observed_port) if observed_port is not None else None,
                "The broker testsuite environment should target the reverse proxy HTTPS port exposed by compose.",
            )
        )

    return checks


def artifact_fetch_decision(recommendations: dict[str, Any]) -> str:
    for bucket in ("allow", "conditional", "deny"):
        if any(item["tool"] == "web.fetch.artifact" for item in recommendations[bucket]):
            return bucket
    return "not-mentioned"


def build_project_report(
    *,
    assignee: str | None,
    security_profile: str | None,
    now: datetime,
    include_examples: bool,
    example_limit: int | None,
) -> dict[str, Any]:
    services = parse_compose_services(REPO_ROOT / "docker-compose.yml")
    connectors = [parse_connector_config(name, path) for name, path in CONNECTOR_CONFIG_PATHS]
    testsuite_envs = [parse_testsuite_environment(name, path) for name, path in TESTSUITE_ENV_PATHS]
    collections = [parse_collection_summary(path) for path in TESTSUITE_COLLECTION_PATHS]

    connector_b = next((item for item in connectors if item["name"] == "connectorb"), None)
    connector_env = next((item for item in testsuite_envs if item["name"] == "connector"), None)
    effective_assignee = (
        assignee
        or (connector_env["values"].get("APPLICANT_CONNECTOR_ID") if connector_env else None)
        or (connector_b["connector_id"] if connector_b else None)
    )
    effective_security_profile = (
        security_profile
        or (connector_env["values"].get("APPLICANT_SECURITY_PROFILE") if connector_env else None)
        or (connector_b["security_profile"] if connector_b else None)
    )

    checks = alignment_checks(connectors, services, testsuite_envs)
    failing_checks = [check for check in checks if not check["ok"]]

    records = extract_from_paths(default_paths())
    kind_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    source_file_counts: Counter[str] = Counter()
    decision_counts = {
        "allow": Counter(),
        "conditional": Counter(),
        "deny": Counter(),
    }
    evaluation_finding_counts: Counter[str] = Counter()
    fetch_decision_counts: Counter[str] = Counter()
    example_snapshots: list[dict[str, Any]] = []

    for record in records:
        kind_counts[record["kind"]] += 1
        source_file_counts[record["source_file"]] += 1
        for protocol in record.get("communication_protocols", []):
            protocol_counts[protocol] += 1

        summary = summarize(
            source=record["object"],
            assignee=effective_assignee,
            security_profile=effective_security_profile,
            now=now,
        )
        recommendations = build_recommendations(summary)

        for bucket in ("allow", "conditional", "deny"):
            for item in recommendations[bucket]:
                decision_counts[bucket][item["tool"]] += 1
        for finding in recommendations["findings"]:
            evaluation_finding_counts[finding] += 1
        fetch_decision_counts[artifact_fetch_decision(recommendations)] += 1

        if include_examples and (
            example_limit is None or len(example_snapshots) < example_limit
        ):
            example_snapshots.append(
                {
                    "source_file": record["source_file"],
                    "source_path": record["source_path"],
                    "kind": record["kind"],
                    "embedded_ids_types": record.get("embedded_ids_types", []),
                    "communication_protocols": summary["communication_protocols"],
                    "communication_envelopes": summary["communication_envelopes"],
                    "permissions_found": summary["permissions_found"],
                    "actions": summary["actions"],
                    "targets": summary["targets"],
                    "artifact_fetch_decision": artifact_fetch_decision(recommendations),
                    "allow_tools": [item["tool"] for item in recommendations["allow"]],
                    "conditional_tools": [item["tool"] for item in recommendations["conditional"]],
                    "deny_tools": [item["tool"] for item in recommendations["deny"]],
                }
            )

    report: dict[str, Any] = {
        "project": {
            "repo_root": str(REPO_ROOT),
            "compose": {
                "source_file": "docker-compose.yml",
                "service_count": len(services),
                "services": services,
            },
            "connectors": connectors,
            "testsuite": {
                "collections": collections,
                "environments": [
                    {
                        "name": item["name"],
                        "source_file": item["source_file"],
                        "keys": sorted(item["values"]),
                    }
                    for item in testsuite_envs
                ],
            },
        },
        "integration": {
            "assignee_under_test": effective_assignee,
            "security_profile_under_test": effective_security_profile,
            "evaluation_time": now.isoformat(),
            "testsuite_alignment": {
                "check_count": len(checks),
                "failing_count": len(failing_checks),
                "checks": checks,
            },
            "extraction": {
                "source_files": [str(path.relative_to(REPO_ROOT)) for path in default_paths()],
                "count": len(records),
                "kind_counts": sort_counter(kind_counts),
                "protocol_counts": sort_counter(protocol_counts),
                "source_file_counts": sort_counter(source_file_counts),
            },
            "tool_decision_counts": {
                bucket: sort_counter(counter)
                for bucket, counter in decision_counts.items()
            },
            "artifact_fetch_decision_counts": sort_counter(fetch_decision_counts),
            "evaluation_findings": sort_counter(evaluation_finding_counts),
            "entrypoints": {
                "project_report": (
                    "python3 skills/ids-policy-to-tools/scripts/testbed_agentic_integration.py "
                    "--format markdown"
                ),
                "policy_cli": (
                    "python3 skills/ids-policy-to-tools/scripts/ids_policy_to_tools.py "
                    "--input skills/ids-policy-to-tools/references/example-contract-agreement.json "
                    "--assignee https://connector_B --format markdown"
                ),
                "mcp_server": "python3 skills/ids-policy-to-tools/scripts/policy_mcp_server.py",
                "mcp_project_tool": "inspect_testbed_project",
            },
            "findings": [
                check["message"]
                + f" Expected `{check['expected']}` but observed `{check['observed']}`."
                for check in failing_checks
            ],
        },
    }
    if include_examples:
        report["integration"]["example_snapshots"] = example_snapshots
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    project = report["project"]
    integration = report["integration"]

    lines.append("# Testbed Agentic Integration")
    lines.append("")
    lines.append("## Project")
    lines.append(
        "- Services: "
        + ", ".join(service["name"] for service in project["compose"]["services"])
    )
    for connector in project["connectors"]:
        lines.append(
            "- Connector `"
            + connector["name"]
            + "`: "
            + (connector["connector_id"] or "unknown id")
            + " | endpoint "
            + (connector["default_endpoint"] or "unknown")
            + " | profile "
            + (connector["security_profile"] or "unknown")
        )
    lines.append("")

    lines.append("## Alignment")
    lines.append(
        f"- Checks: {integration['testsuite_alignment']['check_count']}"
    )
    lines.append(
        f"- Failing checks: {integration['testsuite_alignment']['failing_count']}"
    )
    for check in integration["testsuite_alignment"]["checks"]:
        status = "OK" if check["ok"] else "REVIEW"
        lines.append(
            f"- [{status}] `{check['name']}`: {check['message']} "
            f"Expected `{check['expected']}` observed `{check['observed']}`."
        )
    lines.append("")

    extraction = integration["extraction"]
    lines.append("## Extracted Examples")
    lines.append(f"- Count: {extraction['count']}")
    lines.append(
        "- Kinds: "
        + (
            ", ".join(f"{key}={value}" for key, value in extraction["kind_counts"].items())
            if extraction["kind_counts"]
            else "none"
        )
    )
    lines.append(
        "- Protocols: "
        + (
            ", ".join(f"{key}={value}" for key, value in extraction["protocol_counts"].items())
            if extraction["protocol_counts"]
            else "none"
        )
    )
    lines.append("")

    lines.append("## Policy Decisions")
    lines.append(
        f"- Assignee under test: {integration['assignee_under_test'] or 'not set'}"
    )
    lines.append(
        f"- Security profile under test: {integration['security_profile_under_test'] or 'not set'}"
    )
    lines.append(
        "- Artifact fetch outcomes: "
        + ", ".join(
            f"{key}={value}"
            for key, value in integration["artifact_fetch_decision_counts"].items()
        )
    )
    for bucket in ("allow", "conditional", "deny"):
        counts = integration["tool_decision_counts"][bucket]
        lines.append(
            f"- {bucket.title()} tools: "
            + (
                ", ".join(f"{key}={value}" for key, value in counts.items())
                if counts
                else "none"
            )
        )
    lines.append("")

    if integration["findings"]:
        lines.append("## Findings")
        for finding in integration["findings"]:
            lines.append(f"- {finding}")
        lines.append("")

    if integration.get("example_snapshots"):
        lines.append("## Example Snapshots")
        for example in integration["example_snapshots"]:
            lines.append(
                f"- `{example['kind']}` from `{example['source_file']}` -> "
                f"artifact fetch `{example['artifact_fetch_decision']}`"
            )
        lines.append("")

    lines.append("## Entry Points")
    for name, command in integration["entrypoints"].items():
        lines.append(f"- `{name}`: `{command}`")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    args = parse_args()
    report = build_project_report(
        assignee=args.assignee,
        security_profile=args.security_profile,
        now=determine_now(args.now),
        include_examples=args.include_examples,
        example_limit=args.example_limit,
    )
    if args.format == "json":
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_markdown(report))


if __name__ == "__main__":
    main()
