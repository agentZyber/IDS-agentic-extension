#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SKILL_DIR = REPO_ROOT / "skills" / "ids-policy-to-tools"
SCRIPT_DIR = SKILL_DIR / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from extract_ids_examples import extract_from_paths  # noqa: E402


def record_by_kind(records: list[dict], kind: str) -> dict:
    for record in records:
        if record["kind"] == kind:
            return record
    raise AssertionError(f"Missing record kind: {kind}")


class ExampleExtractionTests(unittest.TestCase):
    def test_acp_fixture_is_classified(self) -> None:
        records = extract_from_paths([SKILL_DIR / "references" / "example-acp-run.json"])
        kinds = {record["kind"] for record in records}

        self.assertIn("acp-run", kinds)
        self.assertIn("acp-message", kinds)
        self.assertIn("ids:Permission", kinds)

        acp_run = record_by_kind(records, "acp-run")
        self.assertEqual(acp_run["communication_protocols"], ["ACP"])
        self.assertIn("acp-run", acp_run["communication_envelopes"])
        self.assertIn("ids:Permission", acp_run["embedded_ids_types"])

    def test_a2a_fixtures_are_classified(self) -> None:
        records = extract_from_paths(
            [
                SKILL_DIR / "references" / "example-a2a-message-send.json",
                SKILL_DIR / "references" / "example-a2a-agent-card.json",
            ]
        )
        kinds = {record["kind"] for record in records}

        self.assertIn("a2a-jsonrpc", kinds)
        self.assertIn("a2a-message", kinds)
        self.assertIn("a2a-agent-card", kinds)
        self.assertIn("ids:ContractAgreement", kinds)

        jsonrpc_record = record_by_kind(records, "a2a-jsonrpc")
        self.assertEqual(jsonrpc_record["communication_protocols"], ["A2A"])
        self.assertIn("message/send", jsonrpc_record["communication_methods"])
        self.assertIn("ids:ContractAgreement", jsonrpc_record["embedded_ids_types"])

        agent_card = record_by_kind(records, "a2a-agent-card")
        self.assertEqual(agent_card["communication_protocols"], ["A2A"])
        self.assertIn("a2a-agent-card", agent_card["communication_envelopes"])
        self.assertNotIn("embedded_ids_types", agent_card)

    def test_cli_supports_relative_protocol_fixture_paths(self) -> None:
        relative_path = (SKILL_DIR / "references" / "example-a2a-message-send.json").relative_to(
            REPO_ROOT
        )
        result = subprocess.run(
            [
                "python3",
                str(SCRIPT_DIR / "extract_ids_examples.py"),
                str(relative_path),
                "--format",
                "json",
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

        payload = json.loads(result.stdout)
        kinds = {record["kind"] for record in payload["examples"]}
        self.assertIn("a2a-jsonrpc", kinds)
        self.assertIn("ids:ContractAgreement", kinds)


if __name__ == "__main__":
    unittest.main()
