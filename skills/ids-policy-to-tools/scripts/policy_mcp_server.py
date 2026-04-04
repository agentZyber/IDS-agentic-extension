#!/usr/bin/env python3
"""
Minimal MCP-style stdio server for IDS policy evaluation.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from extract_ids_examples import default_paths, extract_from_paths
from ids_policy_to_tools import build_recommendations, decode_jsonish, determine_now, summarize


SERVER_INFO = {
    "name": "ids-policy-to-tools",
    "version": "0.1.0",
}


def tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "evaluate_ids_policy",
            "description": (
                "Translate an IDS Permission, ContractAgreement, rule-wrapper, ACP envelope, "
                "or A2A envelope into conservative agent tool recommendations."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "policy": {
                        "description": "IDS object, ACP envelope, A2A envelope, or JSON string to evaluate.",
                    },
                    "assignee": {
                        "type": "string",
                        "description": "Expected assignee or consumer identifier.",
                    },
                    "security_profile": {
                        "type": "string",
                        "description": "Optional IDS security profile override.",
                    },
                    "now": {
                        "type": "string",
                        "description": "ISO 8601 evaluation time override.",
                    },
                },
                "required": ["policy"],
            },
        },
        {
            "name": "extract_repo_ids_examples",
            "description": (
                "Extract IDS Permission and ContractAgreement examples from the repo's docs "
                "and Postman collections."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional explicit files to scan.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of examples to return.",
                    },
                    "include_objects": {
                        "type": "boolean",
                        "description": "Include full extracted objects in the result.",
                    },
                },
            },
        },
    ]


def evaluate_policy(arguments: dict[str, Any]) -> dict[str, Any]:
    if "policy" not in arguments:
        raise ValueError("Missing required argument: policy")
    source = decode_jsonish(arguments["policy"])
    now = determine_now(arguments.get("now"))
    summary = summarize(
        source=source,
        assignee=arguments.get("assignee"),
        security_profile=arguments.get("security_profile"),
        now=now,
    )
    recommendations = build_recommendations(summary)
    return {
        "summary": summary,
        "recommendations": recommendations,
        "note": "Conservative recommendations only; not automatic IDS enforcement. ACP and A2A envelopes are treated as communication context around the IDS policy, not as standalone authority.",
    }


def extract_repo_examples(arguments: dict[str, Any]) -> dict[str, Any]:
    raw_paths = arguments.get("paths")
    if raw_paths:
        paths = [Path(path) for path in raw_paths]
    else:
        paths = default_paths()
    records = extract_from_paths(paths)
    limit = arguments.get("limit")
    if isinstance(limit, int):
        records = records[:limit]
    include_objects = bool(arguments.get("include_objects"))

    examples = []
    for record in records:
        item = {
            "source_file": record["source_file"],
            "source_path": record["source_path"],
            "kind": record["kind"],
        }
        if include_objects:
            item["object"] = record["object"]
        examples.append(item)

    return {
        "count": len(records),
        "examples": examples,
    }


def tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "evaluate_ids_policy":
        return evaluate_policy(arguments)
    if name == "extract_repo_ids_examples":
        return extract_repo_examples(arguments)
    raise ValueError(f"Unknown tool: {name}")


def ok_response(message_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "result": result,
    }


def error_response(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


def read_message() -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        name, _, value = line.decode("utf-8").partition(":")
        headers[name.strip().lower()] = value.strip()

    if "content-length" not in headers:
        return None

    content_length = int(headers["content-length"])
    body = sys.stdin.buffer.read(content_length)
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def write_message(message: dict[str, Any]) -> None:
    body = json.dumps(message).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    sys.stdout.buffer.write(header)
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def format_tool_result(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, indent=2),
            }
        ],
        "structuredContent": payload,
        "isError": False,
    }


def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method")
    message_id = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        return ok_response(
            message_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    }
                },
                "serverInfo": SERVER_INFO,
            },
        )

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return ok_response(message_id, {"tools": tool_specs()})

    if method == "tools/call":
        try:
            name = params["name"]
            arguments = params.get("arguments", {})
            payload = tool_call(name, arguments)
            return ok_response(message_id, format_tool_result(payload))
        except Exception as exc:  # noqa: BLE001
            return error_response(message_id, -32000, str(exc))

    return error_response(message_id, -32601, f"Method not found: {method}")


def main() -> None:
    while True:
        request = read_message()
        if request is None:
            break
        response = handle_request(request)
        if response is not None:
            write_message(response)


if __name__ == "__main__":
    main()
