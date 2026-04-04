#!/usr/bin/env python3
"""
Extract IDS policy and protocol-envelope examples from repo docs and collections.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from ids_policy_to_tools import (
    collect_communication_context,
    decode_jsonish,
    is_acp_message_like,
    is_acp_run_like,
    is_a2a_agent_card_like,
    is_a2a_jsonrpc_like,
    is_a2a_message_like,
    is_a2a_task_like,
    type_values,
)


IDS_TYPES = ("ids:Permission", "ids:ContractAgreement")
PROTOCOL_KINDS = (
    ("acp-run", is_acp_run_like),
    ("acp-message", is_acp_message_like),
    ("a2a-agent-card", is_a2a_agent_card_like),
    ("a2a-jsonrpc", is_a2a_jsonrpc_like),
    ("a2a-message", is_a2a_message_like),
    ("a2a-task", is_a2a_task_like),
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def default_paths() -> list[Path]:
    root = repo_root()
    return [
        root / "PreparingPreconfiguredSetup.md",
        root / "TestbedPreconfiguration.postman_collection.json",
        root / "Testsuite" / "Testsuite.postman_collection.json",
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract IDS and ACP/A2A protocol examples from markdown and JSON files."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files to scan. Defaults to the repo's docs and Postman collections.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output format.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum number of extracted examples to return.",
    )
    parser.add_argument(
        "--write-dir",
        help="Optional output directory to write each extracted example as JSON.",
    )
    return parser.parse_args()


def compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def protocol_kind(node: Any) -> str | None:
    if not isinstance(node, dict):
        return None
    for kind, detector in PROTOCOL_KINDS:
        if detector(node):
            return kind
    return None


def embedded_ids_types(node: Any) -> list[str]:
    found: list[str] = []

    def visit(value: Any) -> None:
        decoded = decode_jsonish(value)
        if isinstance(decoded, dict):
            node_types = type_values(decoded)
            for ids_type in IDS_TYPES:
                if ids_type in node_types and ids_type not in found:
                    found.append(ids_type)
            for child in decoded.values():
                visit(child)
        elif isinstance(decoded, list):
            for item in decoded:
                visit(item)

    visit(node)
    return found


def source_label(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo_root()))
    except ValueError:
        return str(path)


def classify_node(node: Any) -> str | None:
    if not isinstance(node, dict):
        return None
    node_types = type_values(node)
    for ids_type in IDS_TYPES:
        if ids_type in node_types:
            return ids_type
    if "value" in node:
        decoded = decode_jsonish(node["value"])
        if isinstance(decoded, dict):
            decoded_types = type_values(decoded)
            if any(ids_type in decoded_types for ids_type in IDS_TYPES):
                return "rule-wrapper"
    return protocol_kind(node)


def extract_from_json_node(
    node: Any,
    source_file: Path,
    source_path: str,
    records: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
) -> None:
    decoded_node = decode_jsonish(node)
    kind = classify_node(decoded_node)
    if kind is not None:
        canonical_source = str(source_file.resolve())
        key = (canonical_source, kind, compact_json(decoded_node))
        if key not in seen:
            seen.add(key)
            communication = collect_communication_context(decoded_node)
            embedded_types = embedded_ids_types(decoded_node)
            record: dict[str, Any] = {
                "source_file": source_label(source_file),
                "source_path": source_path,
                "kind": kind,
                "object": decoded_node,
            }
            if communication["protocols"]:
                record["communication_protocols"] = communication["protocols"]
            if communication["envelopes"]:
                record["communication_envelopes"] = communication["envelopes"]
            if communication["methods"]:
                record["communication_methods"] = communication["methods"]
            if kind not in IDS_TYPES and embedded_types:
                record["embedded_ids_types"] = embedded_types
            records.append(
                record
            )

    if isinstance(decoded_node, dict):
        for key, value in decoded_node.items():
            extract_from_json_node(
                value,
                source_file,
                f"{source_path}.{key}",
                records,
                seen,
            )
    elif isinstance(decoded_node, list):
        for idx, item in enumerate(decoded_node):
            extract_from_json_node(
                item,
                source_file,
                f"{source_path}[{idx}]",
                records,
                seen,
            )


def extract_from_markdown(path: Path) -> list[dict[str, Any]]:
    text = path.read_text()
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    fence_pattern = re.compile(r"```(?:json|jsonld)?\n(.*?)```", re.DOTALL)

    for idx, match in enumerate(fence_pattern.finditer(text)):
        block = match.group(1).strip()
        if not block:
            continue
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError:
            continue
        extract_from_json_node(
            parsed,
            path,
            f"markdown_code_block[{idx}]",
            records,
            seen,
        )

    return records


def extract_from_json_file(path: Path) -> list[dict[str, Any]]:
    parsed = json.loads(path.read_text())
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    extract_from_json_node(parsed, path, "$", records, seen)
    return records


def extract_from_path(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".md":
        return extract_from_markdown(path)
    return extract_from_json_file(path)


def extract_from_paths(paths: list[Path]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for path in paths:
        results.extend(extract_from_path(path))
    return results


def write_records(records: list[dict[str, Any]], write_dir: Path) -> None:
    write_dir.mkdir(parents=True, exist_ok=True)
    for idx, record in enumerate(records, start=1):
        slug = record["kind"].replace(":", "-").lower()
        out_path = write_dir / f"{idx:02d}-{slug}.json"
        out_path.write_text(json.dumps(record["object"], indent=2) + "\n")


def render_markdown(records: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append("# Extracted IDS And Protocol Examples")
    lines.append("")
    lines.append(f"- Count: {len(records)}")
    lines.append("")
    for idx, record in enumerate(records, start=1):
        lines.append(f"## {idx}. {record['kind']}")
        lines.append(f"- Source file: `{record['source_file']}`")
        lines.append(f"- Source path: `{record['source_path']}`")
        object_types = type_values(record["object"]) if isinstance(record["object"], dict) else []
        if object_types:
            lines.append(f"- Object types: {', '.join(object_types)}")
        if record.get("embedded_ids_types"):
            lines.append(f"- Embedded IDS types: {', '.join(record['embedded_ids_types'])}")
        if record.get("communication_protocols"):
            lines.append(
                "- Communication protocols: "
                + ", ".join(record["communication_protocols"])
            )
        if record.get("communication_envelopes"):
            lines.append(
                "- Communication envelopes: "
                + ", ".join(record["communication_envelopes"])
            )
        if record.get("communication_methods"):
            lines.append(
                "- Communication methods: "
                + ", ".join(record["communication_methods"])
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    args = parse_args()
    paths = [Path(path) for path in args.paths] if args.paths else default_paths()
    records = extract_from_paths(paths)
    if args.limit is not None:
        records = records[: args.limit]

    if args.write_dir:
        write_records(records, Path(args.write_dir))

    payload = {
        "count": len(records),
        "examples": records,
    }
    if args.format == "json":
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(render_markdown(records), end="")


if __name__ == "__main__":
    main()
