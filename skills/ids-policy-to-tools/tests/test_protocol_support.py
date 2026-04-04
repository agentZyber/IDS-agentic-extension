#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SKILL_DIR = REPO_ROOT / "skills" / "ids-policy-to-tools"
SCRIPT_DIR = SKILL_DIR / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from ids_policy_to_tools import build_recommendations, determine_now, summarize  # noqa: E402


NOW = determine_now("2026-04-02T00:00:00Z")


def load_reference(name: str) -> dict:
    return json.loads((SKILL_DIR / "references" / name).read_text())


def tools(payload: dict, bucket: str) -> set[str]:
    return {item["tool"] for item in payload[bucket]}


class ProtocolSupportTests(unittest.TestCase):
    def test_acp_run_support(self) -> None:
        source = load_reference("example-acp-run.json")
        summary = summarize(source, None, None, NOW)
        recommendations = build_recommendations(summary)

        self.assertIn("ACP", summary["communication_protocols"])
        self.assertIn("acp-run", summary["communication_envelopes"])
        self.assertIn("acp-message", summary["communication_envelopes"])
        self.assertIn("acp.send_message", tools(recommendations, "allow"))
        self.assertIn("acp.read_run", tools(recommendations, "allow"))
        self.assertIn("web.post.contract", tools(recommendations, "allow"))
        self.assertIn("web.fetch.artifact", tools(recommendations, "conditional"))

    def test_a2a_message_send_support(self) -> None:
        source = load_reference("example-a2a-message-send.json")
        summary = summarize(source, "https://connector_B", None, NOW)
        recommendations = build_recommendations(summary)

        self.assertIn("A2A", summary["communication_protocols"])
        self.assertIn("a2a-jsonrpc", summary["communication_envelopes"])
        self.assertIn("a2a-message", summary["communication_envelopes"])
        self.assertIn("message/send", summary["communication_methods"])
        self.assertIn("a2a.send_message", tools(recommendations, "allow"))
        self.assertIn("web.fetch.artifact", tools(recommendations, "allow"))

    def test_a2a_agent_card_support(self) -> None:
        source = load_reference("example-a2a-agent-card.json")
        summary = summarize(source, None, None, NOW)
        recommendations = build_recommendations(summary)

        self.assertIn("A2A", summary["communication_protocols"])
        self.assertIn("a2a-agent-card", summary["communication_envelopes"])
        self.assertEqual(summary["permissions_found"], 0)
        self.assertIn("a2a.read_agent_card", tools(recommendations, "allow"))
        self.assertIn("a2a.send_message", tools(recommendations, "conditional"))
        self.assertNotIn("web.fetch.artifact", tools(recommendations, "allow"))


if __name__ == "__main__":
    unittest.main()
