"""Exercise the publisher with fake Git/verification commands; no network writes."""

import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest


PUBLISHER = Path(__file__).resolve().parents[1] / "scripts" / "publish-rulesets.sh"
OUTPUTS = ["REJECT-DOMAIN-SET.list", "REJECT-DOMAIN-SET.srs",
           "REJECT-IP-SET.list", "REJECT-IP-SET.srs",
           "REJECT-RULE-SET.list", "REJECT-RULE-SET.srs", "metadata/filter.json"]


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
                ["bash", str(PUBLISHER), "test publication", *OUTPUTS],
                cwd=root, env=env, capture_output=True, text=True)
            return result, (root / "log").read_text().splitlines()

    def test_rebased_tree_is_verified_before_push(self):
        result, calls = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(calls.index("pull --rebase --autostash origin main"), calls.index("verify"))
        self.assertLess(calls.index("verify"), calls.index("push origin HEAD:main"))
        self.assertIn("add -- " + " ".join(OUTPUTS), calls)
        self.assertNotIn("dummy-test-token", "\n".join(calls) + result.stdout + result.stderr)
        self.assertFalse(any("set-url" in call for call in calls))

    def test_failed_verification_stops_without_push(self):
        result, calls = self.run_publisher(verification=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call.startswith("push ") for call in calls))
        self.assertEqual(calls.count("verify"), 1)

    def test_release_targets_checked_out_revision_instead_of_older_event(self):
        workflow = PUBLISHER.parents[1] / ".github/workflows/publish-release.yml"
        text = workflow.read_text()
        record = re.search(r"id: snapshot\s+run: ([^\n]+)", text).group(1)
        section = text.split("      - name: Publish immutable daily release", 1)[1]
        section = section.split("      - name:", 1)[0]
        publish = section.split("        run: |\n", 1)[1]
        publish = "\n".join(line[10:] if line.startswith("          ") else line
                            for line in publish.splitlines())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, capture = root / "output", root / "captured"
            fake_gh = root / "gh"
            fake_gh.write_text('#!/bin/sh\n'
                               'if [ "$1 $2" = "release view" ]; then exit 1; fi\n'
                               'printf "%s\\n" "$@" > "$RELEASE_CAPTURE"\n')
            fake_gh.chmod(0o755)
            assets = root / "release-assets"
            assets.mkdir()
            (assets / "test.list").write_text("example.com\n")
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                   "GITHUB_OUTPUT": str(output), "GITHUB_SHA": "0" * 40,
                   "GH_TOKEN": "dummy-test-token", "RELEASE_CAPTURE": str(capture)}
            subprocess.run(["bash", "-euc", record], cwd=PUBLISHER.parents[1],
                           env=env, capture_output=True, text=True, check=True)
            revision = dict(line.split("=", 1) for line in output.read_text().splitlines())["sha"]
            actual = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PUBLISHER.parents[1],
                                    capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(revision, actual)
            self.assertNotEqual(revision, env["GITHUB_SHA"])
            env["SNAPSHOT_SHA"] = revision
            subprocess.run(["bash", "-euc", publish], cwd=root, env=env,
                           capture_output=True, text=True, check=True)
            arguments = capture.read_text().splitlines()
            self.assertEqual(arguments[arguments.index("--target") + 1], revision)
            self.assertIn(revision, arguments[arguments.index("--notes") + 1])

    def test_unchanged_outputs_do_not_create_a_commit(self):
        result, calls = self.run_publisher(changed=False)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(any(call.startswith(("commit ", "pull ", "push ")) for call in calls))


if __name__ == "__main__":
    unittest.main()
