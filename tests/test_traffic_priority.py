"""Traffic observations may rank rules but cannot create new block scopes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from filter_scope import AppScope
from filter_selection import RuleSelection


class TrafficPriorityTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / 'source').mkdir()
        scope = {'schema': 1, 'preserve_manual_supplements': True,
                 'min_selected_domains': 1, 'max_selected_domains': 100,
                 'families': [{'id': 'existing', 'roots': ['existing.example']}],
                 'traffic_priority_source': 'source/traffic-brand-priority.json'}
        profile = {'schema': 1, 'functional_exact_hosts': ['brand.example'], 'families': [
            {'id': 'observed', 'suffix_roots': ['brand.example'], 'exact_hosts': []},
            {'id': 'shared-cloud', 'suffix_roots': [], 'exact_hosts': ['pages.example']}]}
        (root / 'source/reject-app-scope.json').write_text(json.dumps(scope))
        path = root / 'source/traffic-brand-priority.json'
        path.write_text(json.dumps(profile))
        return root, path, profile

    def test_observed_priority_does_not_create_base_blocks_or_expand_shared_clouds(self):
        root, _, _ = self.fixture()
        scope = AppScope(root / 'source/reject-app-scope.json')
        self.assertEqual(scope.family('ad.brand.example'), 'observed')
        self.assertIsNone(scope.family('notbrand.example'))
        self.assertIsNone(scope.family('brand.example.invalid'))
        self.assertEqual(scope.family('pages.example'), 'shared-cloud')
        self.assertIsNone(scope.family('tenant.pages.example'))
        self.assertEqual(scope.category('observed'), 'traffic-observed')
        suffix, exact, patterns, _ = scope.select(
            {'ads.brand.example', 'ads.existing.example'}, {'brand.example'}, set())
        self.assertEqual(suffix, {'ads.existing.example'})
        self.assertEqual(exact, set())
        self.assertEqual(patterns, set())

    def test_unsafe_duplicate_or_conflicting_brand_namespaces_fail(self):
        root, path, original = self.fixture()
        for mutate in [lambda d: d['families'].append(d['families'][0]),
                       lambda d: d['families'][0]['suffix_roots'].append('com'),
                       lambda d: d['families'][0]['suffix_roots'].append('existing.example')]:
            profile = json.loads(json.dumps(original)); mutate(profile)
            path.write_text(json.dumps(profile))
            with self.assertRaises(ValueError):
                AppScope(root / 'source/reject-app-scope.json')

    def select(self, root, sources):
        policy = root / 'source/selection.json'
        policy.write_text(json.dumps({'schema': 1, 'target_rules': 1, 'minimum_support': 2,
            'source_preference': ['a', 'b', 'c'], 'category_preference': [
                'installed', 'traffic-observed', 'mainstream'], 'respect_upstream_exceptions': True}))
        scope = AppScope(root / 'source/reject-app-scope.json')
        return RuleSelection(policy).select(sources, set(), set(), set(), scope=scope)[0]

    def test_functional_exact_host_protection_keeps_advertising_children_eligible(self):
        root, _, _ = self.fixture()
        source = ({'brand.example', 'ads.brand.example'}, set(), set(), set())
        selected = self.select(root, {'a': source, 'b': source, 'c': (set(), set(), set(), set())})
        self.assertEqual(selected, {('domain_suffix', 'ads.brand.example')})

    def test_uncapped_reject_keeps_all_eligible_brands_and_omits_generic_padding(self):
        root, _, _ = self.fixture()
        path = root / "source/selection.json"
        path.write_text(json.dumps({"schema": 1, "target_rules": None,
            "selection_scope": "reviewed-brands", "minimum_support": 2,
            "source_preference": ["a", "b"], "category_preference": ["traffic-observed"],
            "respect_upstream_exceptions": True}))
        source = ({"ads.brand.example", "stats.brand.example", "generic.example"}, set(), set(), set())
        scope = AppScope(root / "source/reject-app-scope.json")
        selected, audit, _ = RuleSelection(path).select({"a": source, "b": source}, set(), set(), set(), scope=scope)
        self.assertEqual(selected, {("domain_suffix", "ads.brand.example"),
                                    ("domain_suffix", "stats.brand.example")})
        self.assertIsNone(audit["target_rules"])
        self.assertEqual(audit["rejected"]["outside-reviewed-brand-scope"], 1)

    def test_observed_brand_precedes_a_generic_with_more_supporters(self):
        root, _, _ = self.fixture()
        source = ({'ads.brand.example', 'generic.example'}, set(), set(), set())
        selected = self.select(root, {'a': source, 'b': source,
                                     'c': ({'generic.example'}, set(), set(), set())})
        self.assertEqual(selected, {('domain_suffix', 'ads.brand.example')})


if __name__ == '__main__':
    unittest.main()
