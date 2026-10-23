import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from filter_optimizer import PatternCoverage, optimize_filter
from filter_domains import read_domain_rules
from filter_patterns import read_pattern_rules


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MERGE = load('optimizer_merge', 'merge-filter.py')
VERIFY = load('optimizer_verify', 'verify-all.py')
SYNC = load('optimizer_domain', 'sync-domain-sets.py')


class EquivalentOptimizationTests(unittest.TestCase):
    def test_suffix_requires_apex_and_every_child(self):
        coverage = PatternCoverage({('domain_wildcard', '*.aan.amazon.*')})
        self.assertIsNone(coverage.domain_proof('.aan.amazon.com'))
        self.assertIsNotNone(coverage.domain_proof('child.aan.amazon.com'))
        coverage = PatternCoverage({('domain_wildcard', '*.aan.amazon.*'),
                                    ('domain_wildcard', 'aan.amazon.*')})
        proof = coverage.domain_proof('.aan.amazon.com')
        self.assertEqual(proof['kind'], 'glob-apex-plus-children-union')
        self.assertIsNone(coverage.domain_proof('.notaan.amazon.com'))

    def test_keywords_inside_character_classes_are_not_guaranteed(self):
        patterns = {('domain_keyword', 'ab'), ('domain_wildcard', '[ab].example'),
                    ('domain_wildcard', '*ab*.example')}
        _, _, retained, audit = optimize_filter(set(), set(), patterns)
        self.assertIn(('domain_wildcard', '[ab].example'), retained)
        self.assertNotIn(('domain_wildcard', '*ab*.example'), retained)
        self.assertEqual(audit['summary']['wildcard_rules_net_removed'], 1)

    def test_fixed_point_preserves_ip_and_explicit_and_and_protocol(self):
        patterns = {('domain_keyword', 'log'), ('domain_keyword', 'applog'),
                    ('domain_wildcard', 'trace-*.example.com'),
                    ('domain_wildcard', 'track-*.example.com'),
                    ('domain_wildcard', 'piwik.*.vn'), ('domain_wildcard', 'piwik.*'),
                    ('logical_and', ('fqnovel', 'misc')), ('protocol', 'stun'),
                    ('ip_cidr', '192.0.2.0/24')}
        first = optimize_filter({'applog.example', 'keep.example'}, {'piwik.a.vn'}, patterns)
        second = optimize_filter(*first[:3])
        self.assertEqual(first[:3], second[:3])
        self.assertEqual(first[0], {'keep.example'})
        self.assertEqual(first[1], set())
        self.assertTrue({('ip_cidr', '192.0.2.0/24'), ('protocol', 'stun'),
                         ('logical_and', ('fqnovel', 'misc'))} <= first[2])
        self.assertIn(('domain_wildcard', 'trac[ek]-*.example.com'), first[2])

    def test_source_coverage_verifier_accepts_equivalent_cross_set_rules(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);(root / 'source').mkdir()
            (root / 'source/reject-domain-extra.list').write_text('.analytics.example.com\n')
            (root / 'source/reject-rule-extra.list').write_text('DOMAIN-WILDCARD,piwik.*.vn\n')
            (root / 'REJECT-DOMAIN-SET.list').write_text('.keep.example\n')
            rules = root / 'REJECT-RULE-SET.list'
            rules.write_text('DOMAIN-KEYWORD,analytics\nDOMAIN-WILDCARD,piwik.*\n')
            self.assertEqual(VERIFY.verify_supplemental_domains(root), 0)
            self.assertEqual(VERIFY.verify_supplemental_patterns(root), 0)
            rules.write_text('DOMAIN-KEYWORD,unrelated\n')
            with self.assertRaises(SystemExit):VERIFY.verify_supplemental_domains(root)
            with self.assertRaises(SystemExit):VERIFY.verify_supplemental_patterns(root)

    def test_fixed_point_verifier_detects_reintroduced_domain_and_pattern(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            domain = root / 'REJECT-DOMAIN-SET.list';rules = root / 'REJECT-RULE-SET.list'
            domain.write_text('.applog.example.com\n')
            rules.write_text('DOMAIN-KEYWORD,applog\n')
            with self.assertRaises(SystemExit):VERIFY.verify_filter_optimization(root)
            domain.write_text('.keep.example\n')
            rules.write_text('DOMAIN-WILDCARD,piwik.*\nDOMAIN-WILDCARD,piwik.*.vn\n')
            with self.assertRaises(SystemExit):VERIFY.verify_filter_optimization(root)
            rules.write_text('DOMAIN-WILDCARD,piwik.*\n')
            self.assertEqual(VERIFY.verify_filter_optimization(root), 0)

    def test_full_builder_generates_optimized_pairs_and_keeps_exception_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);source = root / 'upstream.txt'
            source.write_text('||applog.example.com^\n@@||applog.example.com^\n'
                              '||keep.example^\n0.0.0.0 exact.example.net\n'
                              '||aan.amazon.com^\n||aan.amazon.*^\n')
            pattern = root / 'patterns.list'
            pattern.write_text('DOMAIN-KEYWORD,applog\nDOMAIN-WILDCARD,*.aan.amazon.*\n')
            output = root / 'out'
            with patch.object(MERGE, 'MIN_ADBLOCK', 1), patch.object(MERGE, 'MIN_SUFFIX', 1), patch.object(MERGE, 'MIN_EXACT', 1):
                MERGE.build(argparse.Namespace(adblock=[source], pattern_rules=[pattern], output_dir=output))
            s, e = read_domain_rules(output / 'REJECT-DOMAIN-SET.list')
            self.assertEqual(s, {'keep.example'})
            self.assertEqual(e, {'exact.example.net'})
            report = json.loads((output / 'filter-audit.json').read_text())
            self.assertEqual(report['result']['equivalent_optimization']['domain_records_removed'], 2)
            self.assertEqual(report['result']['overlapping_exception_domains'], 1)
            self.assertEqual(VERIFY.verify_filter_optimization(output), 0)

    def test_proxy_keywords_prune_whole_direct_scopes_without_changing_substring_policy(self):
        direct = {'.google.example.cn', 'prefix-google.example.net', '.alicloud.com',
                  '.cn', '.goog.example.cn', 'proxy.example.invalid'}
        retained, audit = SYNC.prune_direct_entries(direct, set(), ('google', 'icloud'))
        self.assertEqual(retained, {'.cn', '.goog.example.cn', 'proxy.example.invalid'})
        self.assertEqual(len(audit), 3)
        with self.assertRaises(SystemExit):
            VERIFY.verify_domain_set_proxy_pruning([], ['.alicloud.com'], ('icloud',))
        self.assertEqual(VERIFY.verify_domain_set_proxy_pruning([], sorted(retained), ('google', 'icloud')), 0)
        # Withdrawing the earlier keyword restores the source entry next build.
        self.assertEqual(SYNC.prune_direct_entries(direct, set(), ())[0], direct)


if __name__ == '__main__':unittest.main()
