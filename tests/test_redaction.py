import unittest

from utils.redaction import redact_value, sanitize_finding, value_fingerprint


class RedactionTests(unittest.TestCase):
    def test_sanitize_masks_value_and_adds_hash(self):
        finding = {"matched_value": "sk-live-secret-value", "pattern_name": "example"}

        sanitized = sanitize_finding(finding)

        self.assertNotEqual(sanitized["matched_value"], finding["matched_value"])
        self.assertEqual(sanitized["matched_value_hash"], value_fingerprint(finding["matched_value"]))

    def test_sanitize_preserves_value_when_revealed(self):
        finding = {"matched_value": "sk-live-secret-value"}

        sanitized = sanitize_finding(finding, reveal=True)

        self.assertEqual(sanitized["matched_value"], finding["matched_value"])
        self.assertNotIn("matched_value_hash", sanitized)

    def test_redact_value_keeps_context_without_full_secret(self):
        redacted = redact_value("abcdef1234567890")

        self.assertEqual(redacted, "abcd...7890 (16 chars)")


if __name__ == "__main__":
    unittest.main()
