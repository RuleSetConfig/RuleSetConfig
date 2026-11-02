"""Keep exact process-name scope consistent through routing generation and verification."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from domain_keywords import KEYWORD_SOURCE, read_companion_processes
from rust_core import binary, generate

SPEC = importlib.util.spec_from_file_location("process_verify", ROOT / "scripts/verify-all.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ProcessRuleTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "source").mkdir()
        policy = {
            "schema": 4, "proxy": ["python"], "direct": ["weixin"],
            "proxy_domain_suffixes": [], "direct_domain_suffixes": [],
            "proxy_domains": [], "direct_domains": [],
            "proxy_process_names": ["netbiosd", "trustd"],
            "direct_process_names": ["Finder"],
            "rule_counts": {"proxy": 3, "direct": 2},
        }
        return root, policy

    def write(self, root, policy):
        (root / KEYWORD_SOURCE).write_text(json.dumps(policy))

    def verify_pair(self, listed, compiled):
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            return VERIFY.verify(listed, compiled)

    def test_process_names_keep_exact_case_sensitive_scope_in_both_outputs(self):
        root, policy = self.fixture()
        self.write(root, policy)
        output = root / "output"
        summary = generate(root, output)
        processes = read_companion_processes(root)
        self.assertEqual(summary["process_names"], {p: list(v) for p, v in processes.items()})
        for name in ("proxy", "direct"):
            listed, compiled = (output / (name.upper() + "-RULE-SET" + ext) for ext in (".list", ".json"))
            text = listed.read_text()
            document = json.loads(compiled.read_text())
            self.assertIn({"process_name": list(processes[name])}, document["rules"])
            self.assertNotIn({"domain_keyword": policy[name], "process_name": list(processes[name])},
                             document["rules"])
            for process in processes[name]:
                self.assertIn("PROCESS-NAME," + process + "\n", text)
            self.assertEqual(self.verify_pair(listed, compiled), 0)

    def test_missing_extra_and_case_changed_compiled_processes_are_rejected(self):
        root, policy = self.fixture()
        self.write(root, policy)
        output = root / "output"
        generate(root, output)
        listed = output / "DIRECT-RULE-SET.list"
        compiled = output / "DIRECT-RULE-SET.json"
        baseline = json.loads(compiled.read_text())
        for names in ([], ["finder"], ["Finder", "other"]):
            document = copy.deepcopy(baseline)
            document["rules"][-1]["process_name"] = names
            compiled.write_text(json.dumps(document))
            with self.subTest(names=names):
                self.assertEqual(self.verify_pair(listed, compiled), 1)

    def test_invalid_process_policy_fails_in_python_and_rust_before_lists_are_written(self):
        mutations = [
            lambda d, name=name: d.update(proxy_process_names=[name])
            for name in ("", "/usr/libexec/trustd", "trust*", "trustd,PROXY", "trust d", "trustd\n", 1, ["trustd"])
        ]
        mutations += [
            lambda d: d.update(proxy_process_names=["trustd", "trustd"]),
            lambda d: d.update(direct_process_names=["trustd"]),
            lambda d: d.update(schema=3),
            lambda d: d.update(schema=4.0),
        ]
        for mutation in mutations:
            root, policy = self.fixture()
            mutation(policy)
            policy["rule_counts"] = {
                p: len(policy[p]) + len(policy[p + "_process_names"]) for p in ("proxy", "direct")}
            self.write(root, policy)
            with self.subTest(policy=policy):
                with self.assertRaises(ValueError):
                    read_companion_processes(root)
                result = subprocess.run(
                    [str(binary()), "--root", str(root), "--output-dir", str(root / "output")],
                    capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(list((root / "output").glob("*.list")))

    def test_process_rules_are_included_in_declared_count_validation(self):
        root, policy = self.fixture()
        policy["rule_counts"]["proxy"] = 1
        self.write(root, policy)
        with self.assertRaisesRegex(ValueError, "counts"):
            read_companion_processes(root)
        result = subprocess.run(
            [str(binary()), "--root", str(root), "--output-dir", str(root / "output")],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list((root / "output").glob("*.list")))


if __name__ == "__main__":
    unittest.main()
