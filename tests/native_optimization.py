#!/usr/bin/env python3
"""Check equivalent pruning and proxy-keyword priority in the native engine."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from filter_optimizer import optimize_filter
from ruleset_format import compile_ruleset, RULE_SET_VERSION


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MERGE = load('native_optimization_merge', 'merge-filter.py')
SYNC = load('native_optimization_domain', 'sync-domain-sets.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sing-box', default='sing-box')
    args = parser.parse_args()
    matches = 0
    case_count = 0

    def native(path, host):
        nonlocal matches
        result = subprocess.run([args.sing_box, 'rule-set', 'match', '-f', 'binary', str(path), '--', host],
                                check=True, capture_output=True, text=True)
        matches += 1
        return 'match rules.' in result.stdout + result.stderr

    def compile_parts(path):
        for name in MERGE.PARTITIONS:
            compile_ruleset(path / (name + '.json'), path / (name + '.srs'), args.sing_box)

    with tempfile.TemporaryDirectory(prefix='native-equivalent-pruning-') as temporary:
        root = Path(temporary)
        suffixes = {'aan.amazon.com', 'applog.example', 'keep.example'}
        exact = {'piwik.a.vn', 'safe.example'}
        patterns = {('domain_keyword', 'applog'), ('domain_wildcard', 'aan.amazon.*'),
                    ('domain_wildcard', '*.aan.amazon.*'), ('domain_wildcard', 'piwik.*'),
                    ('domain_wildcard', 'piwik.*.vn'), ('domain_wildcard', 'trace-*.example.net'),
                    ('domain_wildcard', 'track-*.example.net'), ('domain_wildcard', 'psma01.com*'),
                    ('domain_wildcard', 'psma02.com*'), ('domain_wildcard', 'psma03.com*'),
                    ('domain_wildcard', '[ab].example.org'), ('logical_and', ('fqnovel', 'misc')),
                    ('protocol', 'stun'), ('ip_cidr', '192.0.2.0/24'), ('ip_cidr', '2001:db8::/32')}
        optimized_s, optimized_e, optimized_p, audit = optimize_filter(suffixes, exact, patterns)
        assert audit['summary']['domain_records_removed'] == 3
        for label, data in [('before', (suffixes, exact, patterns)),
                            ('after', (optimized_s, optimized_e, optimized_p))]:
            MERGE.write_filter_partitions(*data, root / label)
            compile_parts(root / label)
        cases = {'aan.amazon.com': True, 'audit.aan.amazon.com': True,
                 'a.b.aan.amazon.com': True, 'notaan.amazon.com': False,
                 'applog.example': True, 'deep.applog.example': True,
                 'keep.example': True, 'child.keep.example': True,
                 'safe.example': True, 'child.safe.example': False,
                 'piwik.a.vn': True, 'piwik.x.com': True, 'notpiwik.x.com': False,
                 'trace-x.example.net': True, 'track-.example.net': True,
                 'tracf-x.example.net': False, 'trace-x.example.net.invalid': False,
                 'psma01.com': True, 'psma02.com.evil': True, 'psma03.com': True,
                 'psma00.com': False, 'psma04.com': False,
                 'a.example.org': True, 'b.example.org': True, 'c.example.org': False,
                 'fqnovel.misc.example': True, 'fqnovel.safe.example': False,
                 '192.0.2.1': True, '192.0.3.1': False,
                 '2001:db8::1': True, '2001:db9::1': False,
                 'stun.example': False, 'unrelated.example': False}
        case_count += len(cases)
        for host, expected in cases.items():
            results = [any(native(root / label / (name + '.srs'), host) for name in MERGE.PARTITIONS)
                       for label in ('before', 'after')]
            if results != [expected, expected]:
                raise AssertionError(('REJECT equivalent union', host, expected, results))
        # Match first-policy wins against original and pruned DIRECT domains.
        proxy = {'.proxy.example'}
        direct = {'.google.example.cn', '.alicloud.com', '.cn', 'exact.example.net'}
        pruned, removed = SYNC.prune_direct_entries(direct, proxy, ('google', 'icloud'))
        assert len(removed) == 2 and '.cn' in pruned
        for label, entries in [('direct-before', direct), ('direct-after', pruned), ('proxy', proxy)]:
            rule = {'domain_suffix': sorted(e[1:] for e in entries if e.startswith('.')),
                    'domain': sorted(e for e in entries if not e.startswith('.'))}
            path = root / (label + '.json');path.write_text(json.dumps({'version': RULE_SET_VERSION, 'rules': [rule]}))
            compile_ruleset(path, root / (label + '.srs'), args.sing_box)
        path = root / 'proxy-keywords.json'
        path.write_text(json.dumps({'version': RULE_SET_VERSION, 'rules': [{'domain_keyword': ['google', 'icloud']}]}))
        compile_ruleset(path, root / 'proxy-keywords.srs', args.sing_box)
        cases = {'google.example.cn': 'proxy', 'deep.google.example.cn': 'proxy',
                 'alicloud.com': 'proxy', 'deep.alicloud.com': 'proxy',
                 'prefix-google-name.net': 'proxy', 'safe.cn': 'direct',
                 'exact.example.net': 'direct', 'child.exact.example.net': 'final',
                 'proxy.example': 'proxy', 'safe.invalid': 'final'}
        case_count += len(cases)
        for host, expected in cases.items():
            values = []
            for label in ('direct-before', 'direct-after'):
                proxy_match = native(root / 'proxy-keywords.srs', host) or native(root / 'proxy.srs', host)
                direct_match = native(root / (label + '.srs'), host)
                values.append('proxy' if proxy_match else 'direct' if direct_match else 'final')
            if values != [expected, expected]:
                raise AssertionError(('proxy-before-direct', host, expected, values))
    print(f'{case_count} native optimisation cases passed; {matches} native match invocations')


if __name__ == '__main__':main()
