import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import orchestrator


class DetectionCorrelationTests(unittest.TestCase):
    def test_query_excludes_baseline_alert_ids(self):
        with patch.object(orchestrator, "_os_search", return_value=[]) as search:
            orchestrator.query_technique_alerts("T1071.001", time.time(), {"old-1", "old-2"})

        query = search.call_args.args[0]
        self.assertEqual(
            query["query"]["bool"]["must_not"],
            [{"terms": {"_id": ["old-1", "old-2"]}}],
        )

    def test_opensearch_http_errors_are_not_silenced(self):
        response = Mock()
        response.raise_for_status.side_effect = RuntimeError("index unavailable")
        with patch.object(orchestrator.requests, "post", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "index unavailable"):
                orchestrator._os_search({"query": {"match_all": {}}})


class RuleDeploymentTests(unittest.TestCase):
    def test_rule_verification_requires_every_mapped_id(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"data": {"affected_items": [{"id": 100113}]}}
        with patch.object(orchestrator, "get_wazuh_token", return_value="token"), patch.object(
            orchestrator.requests, "get", return_value=response
        ):
            with self.assertRaisesRegex(RuntimeError, "100125"):
                orchestrator._verify_rules_loaded([100113, 100125])

    def test_reset_preserves_deployed_rule_state(self):
        original = set(orchestrator.deployed_sigma_rules)
        orchestrator.deployed_sigma_rules = {"T1048"}
        orchestrator.run_status = "idle"
        orchestrator.run_results = [{"detected": True}]
        with tempfile.TemporaryDirectory() as directory:
            old_output = orchestrator.OUTPUT_DIR
            orchestrator.OUTPUT_DIR = directory
            try:
                with orchestrator.app.test_request_context("/reset", method="POST"):
                    response = orchestrator.reset()
                self.assertEqual(response.json["status"], "reset")
                self.assertEqual(orchestrator.deployed_sigma_rules, {"T1048"})
                self.assertEqual(json.loads(Path(directory, "sigma_rules.json").read_text()), [])
            finally:
                orchestrator.OUTPUT_DIR = old_output
                orchestrator.deployed_sigma_rules = original


if __name__ == "__main__":
    unittest.main()
