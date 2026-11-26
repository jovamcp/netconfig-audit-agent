import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from audit_agent import extract_json, redact  # noqa: E402
from rules import SEVERITY_ORDER, run_rules  # noqa: E402


def rule_ids(text: str) -> set[str]:
    return {f.rule_id for f in run_rules(text)}


class VulnerableConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / "configs" / "lab-r1-vulnerable.cfg").read_text()
        cls.ids = rule_ids(cls.text)

    def test_detects_expected_rules(self):
        expected = {
            "IOS-001", "IOS-003", "IOS-004", "IOS-005", "IOS-006", "IOS-007",
            "IOS-008", "IOS-010", "IOS-011", "IOS-012", "IOS-014", "IOS-015",
            "IOS-016", "IOS-017", "IOS-018", "IOS-019", "IOS-020",
        }
        self.assertEqual(expected - self.ids, set())

    def test_findings_are_sorted_by_severity(self):
        severities = [SEVERITY_ORDER[f.severity] for f in run_rules(self.text)]
        self.assertEqual(severities, sorted(severities, reverse=True))


class HardenedConfig(unittest.TestCase):
    def test_no_findings(self):
        text = (ROOT / "configs" / "lab-r2-hardened.cfg").read_text()
        self.assertEqual(run_rules(text), [])


class IndividualRules(unittest.TestCase):
    def test_console_without_local_fallback(self):
        text = (
            "aaa new-model\n"
            "aaa authentication login default group radius\n"
            "line con 0\n"
            " exec-timeout 10 0\n"
        )
        self.assertIn("IOS-009", rule_ids(text))

    def test_console_with_local_list_is_clean(self):
        text = (
            "aaa new-model\n"
            "aaa authentication login default group radius\n"
            "aaa authentication login CONSOLE local\n"
            "line con 0\n"
            " login authentication CONSOLE\n"
        )
        self.assertNotIn("IOS-009", rule_ids(text))

    def test_vty_missing_transport(self):
        self.assertIn("IOS-006", rule_ids("line vty 0 4\n login local\n"))

    def test_snmp_with_acl_and_custom_string_is_clean(self):
        self.assertNotIn("IOS-015", rule_ids("snmp-server community Lab9xTz RO 10\n"))

    def test_permit_any_inside_named_acl(self):
        text = "ip access-list extended TEST\n permit ip any any\n"
        self.assertIn("IOS-020", rule_ids(text))


class Redaction(unittest.TestCase):
    def test_secrets_are_removed(self):
        text = (ROOT / "configs" / "lab-r1-vulnerable.cfg").read_text()
        redacted = redact(text)
        for secret in ("cisco123", "admin123", "0822455D0A16", "public RO", "private RW"):
            self.assertNotIn(secret, redacted)
        self.assertIn("enable password <redacted>", redacted)
        self.assertIn("snmp-server community <redacted> RW", redacted)

    def test_line_password_is_removed(self):
        self.assertEqual(redact(" password cisco"), " password <redacted>")


class JsonExtraction(unittest.TestCase):
    def test_extracts_object_with_surrounding_text(self):
        self.assertEqual(extract_json('Here you go:\n{"risk_level": "high"}\n'), {"risk_level": "high"})

    def test_returns_none_for_plain_text(self):
        self.assertIsNone(extract_json("no json here"))


if __name__ == "__main__":
    unittest.main()
