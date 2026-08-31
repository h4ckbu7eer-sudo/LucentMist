"""Offline scanner regression tests; synthetic strings, never usable credentials."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("check_secrets", Path(__file__).with_name("check-secrets.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class SecretScannerTests(unittest.TestCase):
    def test_provider_key_is_detected(self):
        self.assertIn((1, "provider-key"), scanner.findings("sk-" + "X" * 32))

    def test_github_aws_and_private_key_are_detected(self):
        value = "ghp_" + "X" * 36 + "\n" + "AKIA" + "X" * 16
        value += "\n-----BEGIN " + "PRIVATE KEY-----"
        self.assertEqual(["github-token", "aws-access-id", "private-key"],
                         [rule for _, rule in scanner.findings(value)])

    def test_literal_secret_and_line_number(self):
        self.assertIn((2, "literal-secret"), scanner.findings("comment\nLMIST_API_TOKEN=" + "X" * 32))

    def test_placeholder_and_environment_reference_are_not_credentials(self):
        self.assertEqual([], scanner.findings('LMIST_LLM_APIKEY=<你的key>\n"ApiKey": "${LMIST_LLM_APIKEY}"'))

    def test_utf16_secret_and_binary_detection(self):
        value = "sk-" + "X" * 32
        self.assertTrue(scanner.findings(scanner.decode_text(value.encode("utf-16"))))
        self.assertIsNone(scanner.decode_text(b"binary\0data"))

    def test_default_ignores_env_explicit_scan_checks_it_without_echo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            value = "sk-" + "X" * 32
            (root / ".env").write_text(value, encoding="utf-8")
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture):
                self.assertEqual(0, scanner.scan(root))
                self.assertEqual(1, scanner.scan(root, include_ignored=True))
            self.assertNotIn(value, capture.getvalue())
            self.assertIn(".env:1", capture.getvalue())

    def test_non_repository_is_not_reported_clean(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(2, scanner.scan(Path(directory)))

    def test_oversized_file_is_incomplete_not_clean(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            root = Path(directory)
            with (root / "oversized.txt").open("wb") as stream:
                stream.truncate(scanner.MAX_BYTES + 1)
            self.assertEqual(2, scanner.scan(root, include_ignored=True))


if __name__ == "__main__":
    unittest.main()
