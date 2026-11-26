import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import audit_agent  # noqa: E402

CONFIGS = str(ROOT / "configs")
FEDERATION_ENV = {
    "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_test",
    "ANTHROPIC_ORGANIZATION_ID": "org_test",
}
REVIEW = {
    "risk_level": "low",
    "summary": "Mock review.",
    "additional_findings": [],
    "false_positives": [],
    "priorities": [],
}


def reply_with(text, stop_reason="end_turn"):
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)], stop_reason=stop_reason)


def mock_client(side_effect=None):
    client = mock.MagicMock()
    reply = reply_with(json.dumps(REVIEW))
    if side_effect is None:
        client.messages.create.return_value = reply
    else:
        client.messages.create.side_effect = side_effect
    return client


class AgentRun(unittest.TestCase):
    def run_agent(self, env, client=None, extra_args=(), factory_error=None, with_report=False):
        """Run main() against configs/ and return (exit code, stdout, make_client mock, findings)."""
        clean_env = {
            key: value for key, value in os.environ.items()
            if not key.startswith("ANTHROPIC_") and key != "GITHUB_STEP_SUMMARY"
        }
        clean_env.update(env)
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "findings.json"
            report_path = Path(tmp) / "report.md"
            argv = [CONFIGS, "--out", str(report_path), "--json", str(json_path), *extra_args]
            stdout = io.StringIO()
            with mock.patch.dict(os.environ, clean_env, clear=True), \
                    mock.patch.object(audit_agent, "make_client", return_value=client, side_effect=factory_error) as make_client, \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = audit_agent.main(argv)
            findings = json.loads(json_path.read_text())
            report = report_path.read_text()
        if with_report:
            return code, stdout.getvalue(), make_client, findings, report
        return code, stdout.getvalue(), make_client, findings

    def test_one_client_is_shared_across_files(self):
        client = mock_client()
        code, out, make_client, findings = self.run_agent(FEDERATION_ENV, client)
        self.assertEqual(code, 0)
        self.assertEqual(len(findings), 2)
        make_client.assert_called_once_with()
        self.assertEqual(client.messages.create.call_count, 2)
        self.assertTrue(all(f["ai_error"] is None and f["risk_level"] == "low" for f in findings))
        self.assertTrue(all(f["stop_reason"] == "end_turn" for f in findings))
        self.assertEqual(client.messages.create.call_args.kwargs["max_tokens"], 8000)
        self.assertIn("mode: rules + AI review", out)
        self.assertNotIn("::error", out)

    def test_ai_review_failure_exits_1_with_annotation(self):
        client = mock_client(side_effect=[reply_with(json.dumps(REVIEW)), RuntimeError("Token exchange failed (HTTP 401)\nsecond line")])
        code, out, _, findings = self.run_agent(FEDERATION_ENV, client)
        self.assertEqual(code, 1)
        # Reports are still written, with the rule findings and the error recorded.
        self.assertIsNone(findings[0]["ai_error"])
        self.assertIn("HTTP 401", findings[1]["ai_error"])
        annotations = [line for line in out.splitlines() if line.startswith("::error")]
        self.assertEqual(len(annotations), 1)
        self.assertIn("lab-r2-hardened.cfg", annotations[0])
        self.assertIn("RuntimeError: Token exchange failed (HTTP 401)%0Asecond line", annotations[0])

    def assert_unusable_response_fails(self, bad_reply, expected_error, stop_reason, leaked_text):
        client = mock_client(side_effect=[reply_with(json.dumps(REVIEW)), bad_reply])
        code, out, _, findings, report = self.run_agent(FEDERATION_ENV, client, with_report=True)
        self.assertEqual(code, 1)
        self.assertIsNone(findings[0]["ai_error"])
        self.assertIn(expected_error, findings[1]["ai_error"])
        self.assertEqual(findings[1]["stop_reason"], stop_reason)
        self.assertIsNone(findings[1]["risk_level"])
        annotations = [line for line in out.splitlines() if line.startswith("::error")]
        self.assertEqual(len(annotations), 1)
        self.assertIn("lab-r2-hardened.cfg", annotations[0])
        self.assertIn(expected_error, annotations[0])
        # The raw model text must not be dumped anywhere.
        self.assertIn("AI review failed", report)
        for output in (report, out, json.dumps(findings)):
            self.assertNotIn(leaked_text, output)

    def test_truncated_response_is_a_failed_review(self):
        truncated = '{"risk_level": "low", "summary": "TRUNCATED-MARKER looks fine", "additional_findings": [{"sev'
        self.assert_unusable_response_fails(
            reply_with(truncated, stop_reason="max_tokens"), "truncated at max_tokens", "max_tokens", "TRUNCATED-MARKER"
        )

    def test_truncated_response_fails_even_if_json_parses(self):
        complete_looking = json.dumps({**REVIEW, "summary": "TRUNCATED-MARKER"})
        self.assert_unusable_response_fails(
            reply_with(complete_looking, stop_reason="max_tokens"), "truncated at max_tokens", "max_tokens", "TRUNCATED-MARKER"
        )

    def test_non_json_response_is_a_failed_review(self):
        self.assert_unusable_response_fails(
            reply_with("PLAIN-TEXT-MARKER: the configuration looks fine."), "not valid JSON", "end_turn", "PLAIN-TEXT-MARKER"
        )

    def test_client_creation_failure_exits_1(self):
        code, out, _, findings = self.run_agent(FEDERATION_ENV, factory_error=ImportError("no anthropic"))
        self.assertEqual(code, 1)
        self.assertTrue(all("no anthropic" in f["ai_error"] for f in findings))
        self.assertEqual(sum(line.startswith("::error") for line in out.splitlines()), 2)

    def test_rules_only_without_credentials_exits_0(self):
        code, out, make_client, findings = self.run_agent({})
        self.assertEqual(code, 0)
        make_client.assert_not_called()
        self.assertIn("mode: rules only", out)
        self.assertNotIn("::error", out)
        self.assertTrue(all(f["ai_error"] is None for f in findings))

    def test_no_llm_flag_with_credentials_exits_0(self):
        code, out, make_client, _ = self.run_agent(FEDERATION_ENV, mock_client(), extra_args=["--no-llm"])
        self.assertEqual(code, 0)
        make_client.assert_not_called()
        self.assertIn("mode: rules only", out)


if __name__ == "__main__":
    unittest.main()
