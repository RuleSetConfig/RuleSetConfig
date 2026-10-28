"""Protect blocking-only novel inputs, immutable revisions and failed-fetch behavior."""

import argparse
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import novel_rules as novel

SPEC = importlib.util.spec_from_file_location("novel_merge", ROOT / "scripts/merge-filter.py")
MERGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGE)


class ModuleProjectionTests(unittest.TestCase):
    def test_preserves_portable_match_scopes_and_does_not_promote_url_hosts(self):
        text = """#!name=fixture
[Rule]
#DOMAIN,disabled.example,REJECT
DOMAIN,exact.example,REJECT,extended-matching,pre-matching
DOMAIN-SUFFIX,suffix.example,REJECT
DOMAIN-KEYWORD,-applog.example,REJECT-DROP
DOMAIN-WILDCARD,ads*.pattern.example,REJECT
IP-CIDR,192.0.2.0/24,REJECT,no-resolve
IP-CIDR6,2001:db8::/32,REJECT
DOMAIN,allowed.example,DIRECT
[URL Rewrite]
^https://shared.example/ads - reject
[Map Local]
^https://api.example/ads data-type=text data="{}"
[MITM]
hostname = %APPEND% shared.example
"""
        suffix, exact, patterns, audit = novel.parse_module(text)
        self.assertEqual(suffix, {"suffix.example"})
        self.assertEqual(exact, {"exact.example"})
        self.assertEqual(patterns, {("domain_keyword", "-applog.example"),
                                    ("domain_wildcard", "ads*.pattern.example"),
                                    ("ip_cidr", "192.0.2.0/24"),
                                    ("ip_cidr", "2001:db8::/32")})
        self.assertEqual(len(audit["ignored_nonblocking"]), 1)
        self.assertEqual(audit["counts"]["surge-only:url rewrite"], 1)

    def test_unsupported_reject_matchers_and_scoping_options_fail_closed(self):
        for line in ("URL-REGEX,^https://shared.example/ads,REJECT",
                     "DOMAIN,exact.example,REJECT,src-ip=192.0.2.1",
                     "DOMAIN,*.example,REJECT", "DOMAIN,192.0.2.1,REJECT",
                     "DOMAIN-WILDCARD,,REJECT", "IP-CIDR6,192.0.2.0/24,REJECT",
                     "FINAL,REJECT"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                novel.parse_module("[Rule]\n" + line)

    def test_duplicate_rules_cannot_mask_a_truncated_upstream(self):
        with self.assertRaisesRegex(ValueError, "floor"):
            novel.parse_module("[Rule]\n" + "DOMAIN,ads.example,REJECT\n" * 10, minimum=2)

    def test_html_or_module_without_a_rule_section_is_rejected(self):
        for text in ("<html>upstream error</html>", "[MITM]\nhostname=ads.example"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                novel.parse_module(text)

    def test_modules_feed_all_three_existing_reject_partitions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adblock, module, exclusions = [root / name for name in ("small.txt", "novel.sgmodule", "exclusions.txt")]
            adblock.write_text("||baseline.example^\n")
            module.write_text("[Rule]\nDOMAIN,exact.novel.example,REJECT\n"
                              "DOMAIN-SUFFIX,ads.novel.example,REJECT\n"
                              "DOMAIN-KEYWORD,novel-ads,REJECT\n"
                              "IP-CIDR,192.0.2.0/24,REJECT\n"
                              "[URL Rewrite]\n^https://shared.example/ad - reject\n")
            exclusions.write_text("# none\n")
            args = argparse.Namespace(adblock=[adblock], surge_module=[module],
                                      output_dir=root / "candidate", domain_exclusions=exclusions)
            with patch.object(MERGE, "MIN_ADBLOCK", 1), patch.object(MERGE, "MIN_SUFFIX", 1), \
                    patch.object(MERGE, "MIN_EXACT", 0), redirect_stdout(io.StringIO()):
                self.assertEqual(MERGE.build(args), 0)
            domain_text = (args.output_dir / "REJECT-DOMAIN-SET.list").read_text()
            self.assertIn("exact.novel.example\n", domain_text)
            self.assertIn(".ads.novel.example\n", domain_text)
            self.assertNotIn("shared.example", domain_text)
            self.assertIn("DOMAIN-KEYWORD,novel-ads", (args.output_dir / "REJECT-RULE-SET.list").read_text())
            self.assertIn("IP-CIDR,192.0.2.0/24", (args.output_dir / "REJECT-IP-SET.list").read_text())



class NovelSourceTests(unittest.TestCase):
    def fixture(self):
        specs = {name: {**spec, "minimum": 1} for name, spec in novel.SOURCES.items()}
        revisions = {"qimao": "a" * 40, "fanqie": "b" * 40}
        responses = {}
        for name, spec in specs.items():
            sha = revisions[name]
            responses["https://api.github.com/repos/" + spec["repository"] + "/commits/main"] = json.dumps({"sha": sha}).encode()
            responses[novel.source_url(spec, sha, spec["path"])] = (
                f"#!name=fixture\n[Rule]\nDOMAIN,ads.{name}.example,REJECT\n"
                "[Script]\nhttp-response ^https://api.example script-path=https://ignored.example/code.js\n"
                "[URL Rewrite]\n^https://shared.example/ads - reject\n"
            ).encode()
        return specs, responses

    def test_fetch_is_deterministic_and_only_downloads_rule_inputs(self):
        specs, responses = self.fixture()
        with tempfile.TemporaryDirectory() as temporary, patch.object(novel, "SOURCES", specs), \
                patch.object(novel, "download", side_effect=responses.__getitem__) as download, redirect_stdout(io.StringIO()):
            root = Path(temporary)
            novel.fetch_rules(root)
            first = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            novel.fetch_rules(root)
            self.assertEqual(first, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()})
            self.assertEqual(set(first), {"qimao.sgmodule", "fanqie.sgmodule", "novel-sources.json"})
            self.assertFalse(any("ignored.example" in call.args[0] for call in download.call_args_list))
            records = json.loads((root / "novel-sources.json").read_text())
            self.assertIn("/" + "a" * 40 + "/", records["qimao_module"]["url"])
            projection = novel.manifest_rules({"sources": records})
            self.assertEqual(projection["qimao"], (set(), {"ads.qimao.example"}, set()))
            self.assertNotIn("shared.example", json.dumps(records))

    def test_failed_peer_download_preserves_previous_inputs(self):
        specs, responses = self.fixture()
        bad = novel.source_url(specs["fanqie"], "b" * 40, specs["fanqie"]["path"])
        responses[bad] = b"<html>not a module</html>"
        with tempfile.TemporaryDirectory() as temporary, patch.object(novel, "SOURCES", specs), \
                patch.object(novel, "download", side_effect=responses.__getitem__), redirect_stdout(io.StringIO()):
            root = Path(temporary)
            (root / "qimao.sgmodule").write_bytes(b"existing input")
            with self.assertRaises(ValueError):
                novel.fetch_rules(root)
            self.assertEqual(list(root.iterdir()), [root / "qimao.sgmodule"])
            self.assertEqual((root / "qimao.sgmodule").read_bytes(), b"existing input")

    def test_missing_or_unsupported_projection_is_rejected(self):
        specs, responses = self.fixture()
        with tempfile.TemporaryDirectory() as temporary, patch.object(novel, "SOURCES", specs), \
                patch.object(novel, "download", side_effect=responses.__getitem__), redirect_stdout(io.StringIO()):
            root = Path(temporary)
            novel.fetch_rules(root)
            records = json.loads((root / "novel-sources.json").read_text())
            for projection in (None, [], [["url_regex", "https://shared.example/ads"]], [[[], "invalid"]]):
                with self.subTest(projection=projection):
                    records["qimao_module"]["portable_rules"] = projection
                    with self.assertRaises(ValueError):
                        novel.manifest_rules({"sources": records})

    def test_mutable_source_revision_is_rejected(self):
        specs, responses = self.fixture()
        with tempfile.TemporaryDirectory() as temporary, patch.object(novel, "SOURCES", specs), \
                patch.object(novel, "download", side_effect=responses.__getitem__), redirect_stdout(io.StringIO()):
            root = Path(temporary)
            novel.fetch_rules(root)
            records = json.loads((root / "novel-sources.json").read_text())
            records["qimao_module"]["url"] = records["qimao_module"]["url"].replace("a" * 40, "main")
            with self.assertRaisesRegex(ValueError, "pinned upstream"):
                novel.manifest_rules({"sources": records})


if __name__ == "__main__":
    unittest.main()
