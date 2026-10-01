"""Exercise the publisher with fake Git/verification commands; no network writes."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PUBLISHER = Path(__file__).resolve().parents[1] / "scripts" / "publish-rulesets.sh"


class PublishPipelineTests(unittest.TestCase):
    def run_publisher(self, *, changed=True, verification=0):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            git = root / "git"
            git.write_text(
                '#!/bin/sh\n'
                'printf "%s\\n" "$*" >> "$PUBLISH_LOG"\n'
                'case "$1" in\n'
                '  diff) exit "$DIFF_EXIT" ;;\n'
                '  pull|push)\n'
                '    test "$GIT_CONFIG_KEY_0" = http.https://github.com/.extraheader || exit 9\n'
                '    test -n "$GIT_CONFIG_VALUE_0" || exit 9 ;;\n'
                'esac\nexit 0\n', encoding="utf-8")
            verifier = root / "python3"
            verifier.write_text(
                '#!/bin/sh\nprintf "verify\\n" >> "$PUBLISH_LOG"\n'
                'exit "$VERIFY_EXIT"\n', encoding="utf-8")
            git.chmod(0o755)
            verifier.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                   "GITHUB_TOKEN": "dummy-test-token", "PUBLISH_LOG": str(root / "log"),
                   "DIFF_EXIT": "1" if changed else "0", "VERIFY_EXIT": str(verification)}
            result = subprocess.run(
                ["bash", str(PUBLISHER), "test publication", "filter.list", "filter.srs"],
                cwd=root, env=env, capture_output=True, text=True)
            return result, (root / "log").read_text().splitlines()

    def test_rebased_tree_is_verified_before_push(self):
        result, calls = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(calls.index("pull --rebase --autostash origin main"), calls.index("verify"))
        self.assertLess(calls.index("verify"), calls.index("push origin HEAD:main"))
        self.assertIn("add -- filter.list filter.srs", calls)
        self.assertNotIn("dummy-test-token", "\n".join(calls) + result.stdout + result.stderr)
        self.assertFalse(any("set-url" in call for call in calls))

    def test_failed_verification_stops_without_push(self):
        result, calls = self.run_publisher(verification=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call.startswith("push ") for call in calls))
        self.assertEqual(calls.count("verify"), 1)

    def test_unchanged_outputs_do_not_create_a_commit(self):
        result, calls = self.run_publisher(changed=False)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(any(call.startswith(("commit ", "pull ", "push ")) for call in calls))


if __name__ == "__main__":
    unittest.main()
