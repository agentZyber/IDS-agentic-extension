#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SKILL_DIR = REPO_ROOT / "skills" / "ids-policy-to-tools"
SCRIPT_DIR = SKILL_DIR / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from ids_policy_to_tools import determine_now  # noqa: E402
from testbed_agentic_integration import build_project_report  # noqa: E402


NOW = determine_now("2026-04-02T00:00:00Z")


class TestbedIntegrationTests(unittest.TestCase):
    def test_project_report_covers_repo_topology(self) -> None:
        report = build_project_report(
            assignee=None,
            security_profile=None,
            now=NOW,
            include_examples=False,
            example_limit=None,
        )

        connector_ids = {item["connector_id"] for item in report["project"]["connectors"]}
        service_names = {item["name"] for item in report["project"]["compose"]["services"]}

        self.assertIn("https://connector_A", connector_ids)
        self.assertIn("https://connector_B", connector_ids)
        self.assertIn("connectora", service_names)
        self.assertIn("connectorb", service_names)
        self.assertIn("broker-reverseproxy", service_names)

    def test_project_report_uses_repo_context_for_evaluation(self) -> None:
        report = build_project_report(
            assignee=None,
            security_profile=None,
            now=NOW,
            include_examples=True,
            example_limit=2,
        )

        integration = report["integration"]
        self.assertEqual(integration["assignee_under_test"], "https://connector_B")
        self.assertEqual(
            integration["security_profile_under_test"],
            "https://w3id.org/idsa/code/BASE_SECURITY_PROFILE",
        )
        self.assertGreaterEqual(integration["extraction"]["count"], 2)
        self.assertIn("ids:Permission", integration["extraction"]["kind_counts"])
        self.assertIn("ids:ContractAgreement", integration["extraction"]["kind_counts"])
        self.assertGreater(
            integration["tool_decision_counts"]["allow"]["web.fetch.metadata"],
            0,
        )
        self.assertGreater(
            integration["artifact_fetch_decision_counts"]["conditional"],
            0,
        )
        self.assertEqual(len(integration["example_snapshots"]), 2)

    def test_alignment_checks_cover_broker_port_alignment(self) -> None:
        report = build_project_report(
            assignee=None,
            security_profile=None,
            now=NOW,
            include_examples=False,
            example_limit=None,
        )
        checks = {
            item["name"]: item
            for item in report["integration"]["testsuite_alignment"]["checks"]
        }

        self.assertEqual(report["integration"]["testsuite_alignment"]["failing_count"], 0)
        self.assertTrue(checks["connector_env.connector_id"]["ok"])
        self.assertTrue(checks["connector_env.security_profile"]["ok"])
        self.assertIn("broker_env.reverseproxy_https_port", checks)
        self.assertTrue(checks["broker_env.reverseproxy_https_port"]["ok"])


if __name__ == "__main__":
    unittest.main()
