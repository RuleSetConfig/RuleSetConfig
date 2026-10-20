"""Keep v5 output valid, payload-preserving and atomic on compiler failures."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ruleset_format


class RuleSetFormatTests(unittest.TestCase):
    def test_source_format_is_required_before_invoking_the_compiler(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "source.json", Path(directory) / "output.srs"
            for version in (1, 2, 3, 4, "5", None):
                source.write_text(json.dumps({"version": version, "rules": []}))
                with self.subTest(version=version), patch.object(ruleset_format.subprocess, "run") as run:
                    with self.assertRaisesRegex(ValueError, "source format version 5"):
                        ruleset_format.compile_ruleset(source, output)
                    run.assert_not_called()
                    self.assertFalse(output.exists())

    def test_pinning_preserves_the_compiled_payload_and_validates_before_replacing(self):
        payload = b"compressed-rule-payload"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "source.json", root / "output.srs"
            source.write_text(json.dumps({"version": 5, "rules": []}))
            for version in (2, 3, 4, 5):
                output.write_bytes(b"previous-output")
                def run(command, check):
                    self.assertTrue(check)
                    target = Path(command[command.index("-o") + 1])
                    if command[2] == "compile":
                        target.write_bytes(b"SRS" + bytes([version]) + payload)
                    else:
                        self.assertEqual(output.read_bytes(), b"previous-output")
                        self.assertEqual(Path(command[-1]).read_bytes(), b"SRS\x05" + payload)
                        target.write_text(json.dumps({"version": 5, "rules": []}))
                with self.subTest(version=version), patch.object(ruleset_format.subprocess, "run", side_effect=run):
                    ruleset_format.compile_ruleset(source, output)
                    self.assertEqual(output.read_bytes(), b"SRS\x05" + payload)

    def test_bad_or_legacy_compiler_output_does_not_replace_the_existing_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "source.json", root / "output.srs"
            source.write_text(json.dumps({"version": 5, "rules": []}))
            output.write_bytes(b"previous-output")
            for data in (b"", b"SRS", b"BAD\x05payload", b"SRS\x01payload", b"SRS\x06payload"):
                def run(command, check):
                    Path(command[command.index("-o") + 1]).write_bytes(data)
                with self.subTest(data=data), patch.object(ruleset_format.subprocess, "run", side_effect=run):
                    with self.assertRaisesRegex(ValueError, "unsupported rule-set binary format"):
                        ruleset_format.compile_ruleset(source, output)
                    self.assertEqual(output.read_bytes(), b"previous-output")

    def test_native_decoder_failure_keeps_the_existing_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "source.json", root / "output.srs"
            source.write_text(json.dumps({"version": 5, "rules": []}))
            output.write_bytes(b"previous-output")
            def run(command, check):
                if command[2] == "compile":
                    Path(command[command.index("-o") + 1]).write_bytes(b"SRS\x02payload")
                else:
                    raise subprocess.CalledProcessError(1, command)
            with patch.object(ruleset_format.subprocess, "run", side_effect=run):
                with self.assertRaises(subprocess.CalledProcessError):
                    ruleset_format.compile_ruleset(source, output)
            self.assertEqual(output.read_bytes(), b"previous-output")

    def test_source_cannot_be_replaced_by_its_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            source.write_text(json.dumps({"version": 5, "rules": []}))
            with self.assertRaisesRegex(ValueError, "must be different"):
                ruleset_format.compile_ruleset(source, source)
            self.assertEqual(json.loads(source.read_text())["version"], 5)


if __name__ == "__main__":
    unittest.main()
