
import unittest

from cti_engine import analyze_threat


class TestCyberScope(unittest.TestCase):

    def test_extracts_cve(self):
        result = analyze_threat("Report mentions CVE-2024-12345")
        self.assertIn("CVE-2024-12345", result["cves"])

    def test_extracts_valid_ip(self):
        result = analyze_threat("Suspicious IP: 8.8.8.8")
        self.assertIn("8.8.8.8", result["ips"])

    def test_rejects_invalid_ip(self):
        result = analyze_threat("Suspicious IP: 999.999.999.999")
        self.assertNotIn("999.999.999.999", result["ips"])

    def test_extracts_url_and_domain(self):
        result = analyze_threat(
            "Visit https://example.com/login"
        )
        self.assertIn(
            "https://example.com/login", result["urls"]
        )
        self.assertIn("example.com", result["domains"])

    def test_detects_malware_mention(self):
        result = analyze_threat("The report mentions Emotet")
        self.assertIn("emotet", result["malware"])

    def test_empty_input_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_threat("   ")


if __name__ == "__main__":
    unittest.main()
