"""Validate fixed companion counts, short-name suffixes and explicit rule priority."""
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from domain_keywords import (KEYWORD_SOURCE, read_inline_keywords, read_proxy_suffixes, read_companion_suffixes,
                             covering_keyword)


class CompanionPolicyTests(unittest.TestCase):
    def document(self):
        return {"schema": 2, "proxy": ["python"], "direct": ["tencent"],
                "proxy_domain_suffixes": ["7-zip.org"], "direct_domain_suffixes": [], "rule_counts": {"proxy": 2, "direct": 1}}

    def check_document(self, document, tlds=".io\n.sh\n"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "source").mkdir()
        (root / KEYWORD_SOURCE).write_text(json.dumps(document))
        (root / "PROXY-DOMAIN-SET.list").write_text(tlds)
        return root

    def test_published_companions_match_the_reviewed_100_and_10_rule_targets(self):
        words = read_inline_keywords(ROOT)
        self.assertEqual(len(words["proxy"]) + len(read_proxy_suffixes(ROOT)), 100)
        self.assertEqual(len(words["direct"]) + len(read_companion_suffixes(ROOT)["direct"]), 10)
        self.assertTrue(all(len(re.findall("[a-z]", word)) >= 5 for values in words.values() for word in values))
        self.assertTrue({"adguard", "adtidy", "python", "snapgene", "crowdcafe", "barebones"} <= set(words["proxy"]))
        self.assertEqual(set(words["direct"]), {"alipay", "alicdn", "autonavi", "baidu", "deepseek",
                                              "qznovelvod", "fqnovel", "wechat", "weixin"})
        self.assertEqual(read_companion_suffixes(ROOT)["direct"], ("qq.com",))
        self.assertNotIn("homebrew", words["proxy"])

    def test_rule_count_mismatch_and_substring_filler_are_rejected(self):
        for change in (lambda d: d["rule_counts"].update(proxy=100),
                       lambda d: d["proxy"].append("ipython"),
                       lambda d: d["proxy"].append("7-zip")):
            doc = self.document()
            change(doc)
            with self.subTest(document=doc), self.assertRaises(ValueError):
                read_inline_keywords(self.check_document(doc))

    def test_short_names_keep_bounded_domain_suffix_scope(self):
        root = self.check_document(self.document())
        self.assertEqual(read_proxy_suffixes(root), ("7-zip.org",))
        self.assertEqual(read_inline_keywords(root)["proxy"], ("python",))
        for suffix in ("brew.sh", "python.org", "*.7-zip.org", ".7-zip.org", "192.0.2.1"):
            doc = self.document()
            doc["proxy_domain_suffixes"] = [suffix]
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                read_proxy_suffixes(self.check_document(doc))

    def test_requested_core_services_remain_covered(self):
        words = read_inline_keywords(ROOT)["direct"]
        suffixes = read_companion_suffixes(ROOT)["direct"]
        for host in ("api.deepseek.com", "restapi.autonavi.com", "www.baidu.com", "api.alipay.com",
                     "cdn.alicdn.com", "v3.qznovelvod.com", "api.fqnovel.com", "wechat.com",
                     "api.weixin.qq.com", "start.qq.com"):
            self.assertTrue(covering_keyword(host, words) or any(host == suffix or host.endswith("." + suffix)
                                                              for suffix in suffixes), host)
        for host in ("restapi.amap.com", "www.hongguoduanju.com", "meeting.tencent.com",
                     "www.douyin.com", "notqq.com", "qq.com.invalid"):
            self.assertFalse(covering_keyword(host, words) or any(host == suffix or host.endswith("." + suffix)
                                                               for suffix in suffixes), host)
        self.assertEqual(suffixes, ("qq.com",))

    def test_readme_preserves_proxy_before_direct_companion_priority(self):
        text = (ROOT / "README.md").read_text()
        ini = text.split("```ini\n", 1)[1].split("```", 1)[0]
        expected = ["PROXY-RULE-SET", "PROXY-DOMAIN-SET", "DIRECT-RULE-SET", "DIRECT-DOMAIN-SET"]
        self.assertEqual(sorted(expected, key=ini.index), expected)
        for block in re.findall(r"```json\n(.*?)\n```", text, re.DOTALL):
            document = json.loads(block)
            if "route" not in document:
                continue
            references = [rule["rule_set"][0] for rule in document["route"]["rules"] if "rule_set" in rule]
            self.assertEqual(sorted(expected, key=references.index), expected)


if __name__ == "__main__":
    unittest.main()
