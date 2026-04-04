#!/usr/bin/env python3
"""
Smoke-test the IDS policy skill, extractor, and MCP-style server.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
SKILL_DIR = REPO_ROOT / "skills" / "ids-policy-to-tools"
SCRIPT_DIR = SKILL_DIR / "scripts"


def run_json_command(args: list[str]) -> Any:
    result = subprocess.run(
        args,
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_skill_validator() -> None:
    validator = (
        Path("/Users/akiskourtis/.codex/skills/.system/skill-creator/scripts/quick_validate.py")
    )
    result = subprocess.run(
        ["python3", str(validator), str(SKILL_DIR)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert_true("Skill is valid!" in result.stdout, "Skill validator did not pass.")


def decisions(payload: dict[str, Any], tool: str, bucket: str) -> list[dict[str, Any]]:
    return [
        item
        for item in payload["recommendations"][bucket]
        if item["tool"] == tool
    ]


def test_cli_rule_wrapper() -> None:
    payload = run_json_command(
        [
            "python3",
            str(SCRIPT_DIR / "ids_policy_to_tools.py"),
            "--input",
            str(SKILL_DIR / "references" / "example-rule-wrapper.json"),
            "--format",
            "json",
        ]
    )
    assert_true(
        bool(decisions(payload, "web.post.contract", "allow")),
        "Standalone permission should allow contract negotiation.",
    )
    assert_true(
        bool(decisions(payload, "web.fetch.artifact", "conditional")),
        "Standalone permission should keep artifact fetch conditional.",
    )


def test_cli_agreement() -> None:
    payload = run_json_command(
        [
            "python3",
            str(SCRIPT_DIR / "ids_policy_to_tools.py"),
            "--input",
            str(SKILL_DIR / "references" / "example-contract-agreement.json"),
            "--assignee",
            "https://connector_B",
            "--format",
            "json",
        ]
    )
    assert_true(
        bool(decisions(payload, "web.fetch.artifact", "allow")),
        "Matching assignee on an active agreement should allow target-scoped artifact fetch.",
    )


def test_cli_wrong_assignee() -> None:
    payload = run_json_command(
        [
            "python3",
            str(SCRIPT_DIR / "ids_policy_to_tools.py"),
            "--input",
            str(SKILL_DIR / "references" / "example-contract-agreement.json"),
            "--assignee",
            "https://connector_X",
            "--format",
            "json",
        ]
    )
    assert_true(
        bool(decisions(payload, "web.fetch.artifact", "deny")),
        "Wrong assignee should deny artifact fetch.",
    )


def test_cli_acp_envelope() -> None:
    payload = run_json_command(
        [
            "python3",
            str(SCRIPT_DIR / "ids_policy_to_tools.py"),
            "--input",
            str(SKILL_DIR / "references" / "example-acp-run.json"),
            "--format",
            "json",
        ]
    )
    summary = payload["summary"]
    assert_true("ACP" in summary["communication_protocols"], "ACP protocol should be detected.")
    assert_true(
        "acp.send_message" in {item["tool"] for item in payload["recommendations"]["allow"]},
        "ACP envelopes should allow scoped ACP messaging.",
    )


def test_cli_a2a_message_envelope() -> None:
    payload = run_json_command(
        [
            "python3",
            str(SCRIPT_DIR / "ids_policy_to_tools.py"),
            "--input",
            str(SKILL_DIR / "references" / "example-a2a-message-send.json"),
            "--assignee",
            "https://connector_B",
            "--format",
            "json",
        ]
    )
    summary = payload["summary"]
    assert_true("A2A" in summary["communication_protocols"], "A2A protocol should be detected.")
    assert_true(
        "a2a.send_message" in {item["tool"] for item in payload["recommendations"]["allow"]},
        "A2A envelopes should allow scoped A2A messaging.",
    )


def test_cli_a2a_agent_card() -> None:
    payload = run_json_command(
        [
            "python3",
            str(SCRIPT_DIR / "ids_policy_to_tools.py"),
            "--input",
            str(SKILL_DIR / "references" / "example-a2a-agent-card.json"),
            "--format",
            "json",
        ]
    )
    assert_true(
        "a2a.read_agent_card" in {item["tool"] for item in payload["recommendations"]["allow"]},
        "A2A Agent Cards should allow discovery reads.",
    )
    assert_true(
        "a2a.send_message" in {item["tool"] for item in payload["recommendations"]["conditional"]},
        "A2A Agent Cards should make A2A messaging conditional until policy is present.",
    )


def test_repo_extraction() -> None:
    payload = run_json_command(
        [
            "python3",
            str(SCRIPT_DIR / "extract_ids_examples.py"),
            "--format",
            "json",
        ]
    )
    kinds = {item["kind"] for item in payload["examples"]}
    assert_true(payload["count"] >= 2, "Expected at least two IDS examples from repo sources.")
    assert_true("ids:Permission" in kinds, "Expected to extract at least one IDS Permission.")
    assert_true(
        "ids:ContractAgreement" in kinds,
        "Expected to extract at least one IDS ContractAgreement.",
    )


def test_unittest_suite() -> None:
    result = subprocess.run(
        [
            "python3",
            "-m",
            "unittest",
            "discover",
            "-s",
            str(SKILL_DIR / "tests"),
            "-p",
            "test_*.py",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert_true("OK" in result.stdout or "OK" in result.stderr, "Unit test suite did not pass.")


def write_mcp_message(process: subprocess.Popen[str], message: dict[str, Any]) -> None:
    assert process.stdin is not None
    body = json.dumps(message).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    process.stdin.buffer.write(header)
    process.stdin.buffer.write(body)
    process.stdin.flush()


def read_mcp_message(process: subprocess.Popen[str]) -> dict[str, Any]:
    assert process.stdout is not None
    headers: dict[str, str] = {}
    while True:
        line = process.stdout.buffer.readline()
        if not line:
            raise RuntimeError("MCP server closed unexpectedly.")
        if line in (b"\r\n", b"\n"):
            break
        name, _, value = line.decode("utf-8").partition(":")
        headers[name.strip().lower()] = value.strip()
    body = process.stdout.buffer.read(int(headers["content-length"]))
    return json.loads(body.decode("utf-8"))


def test_mcp_server() -> None:
    process = subprocess.Popen(
        ["python3", str(SCRIPT_DIR / "policy_mcp_server.py")],
        cwd=REPO_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        write_mcp_message(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {},
            },
        )
        init_response = read_mcp_message(process)
        assert_true(
            init_response["result"]["serverInfo"]["name"] == "ids-policy-to-tools",
            "MCP initialize failed.",
        )

        write_mcp_message(
            process,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            },
        )
        tools_response = read_mcp_message(process)
        tool_names = {tool["name"] for tool in tools_response["result"]["tools"]}
        assert_true(
            "evaluate_ids_policy" in tool_names and "extract_repo_ids_examples" in tool_names,
            "MCP server did not expose the expected tools.",
        )

        agreement = json.loads(
            (SKILL_DIR / "references" / "example-contract-agreement.json").read_text()
        )
        write_mcp_message(
            process,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "evaluate_ids_policy",
                    "arguments": {
                        "policy": agreement,
                        "assignee": "https://connector_B",
                    },
                },
            },
        )
        eval_response = read_mcp_message(process)
        structured = eval_response["result"]["structuredContent"]
        assert_true(
            any(
                item["tool"] == "web.fetch.artifact"
                for item in structured["recommendations"]["allow"]
            ),
            "MCP evaluation should allow target-scoped artifact fetch for the matching assignee.",
        )

        write_mcp_message(
            process,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "extract_repo_ids_examples",
                    "arguments": {
                        "limit": 5,
                    },
                },
            },
        )
        extract_response = read_mcp_message(process)
        assert_true(
            extract_response["result"]["structuredContent"]["count"] >= 1,
            "MCP extractor should return repo examples.",
        )
    finally:
        process.terminate()
        process.wait(timeout=5)


def main() -> None:
    tests = [
        ("skill validator", test_skill_validator),
        ("rule-wrapper CLI", test_cli_rule_wrapper),
        ("agreement CLI", test_cli_agreement),
        ("wrong-assignee CLI", test_cli_wrong_assignee),
        ("ACP CLI", test_cli_acp_envelope),
        ("A2A message CLI", test_cli_a2a_message_envelope),
        ("A2A agent card CLI", test_cli_a2a_agent_card),
        ("repo extraction", test_repo_extraction),
        ("unit test suite", test_unittest_suite),
        ("MCP server", test_mcp_server),
    ]

    failures: list[str] = []
    for label, test in tests:
        try:
            test()
            print(f"[PASS] {label}")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{label}: {exc}")
            print(f"[FAIL] {label}: {exc}")

    if failures:
        print("\nHarness failed:")
        for failure in failures:
            print(f"- {failure}")
        sys.exit(1)

    print("\nHarness passed.")


if __name__ == "__main__":
    main()
