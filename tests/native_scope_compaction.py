#!/usr/bin/env python3
"""Compare raw compacted wildcard rows with indexed domains in sing-box."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from filter_patterns import wildcard_regex
from ruleset_format import compile_ruleset, RULE_SET_VERSION
from scope_compaction import compact_text, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sing-box', default='sing-box')
    args = parser.parse_args()
    tested = 0
    # The missing corner must stay missing: grouping may not fill a sparse grid.
    universe = {f'very-long-service-node-{a}{b}.tenant.example.com'
                for a in range(4) for b in range(4)}
    names = universe - {'very-long-service-node-33.tenant.example.com'}
    with tempfile.TemporaryDirectory(prefix='native-finite-scope-') as directory:
        root = Path(directory)
        for kind, field in [('DOMAIN', 'domain'), ('DOMAIN-SUFFIX', 'domain_suffix')]:
            source = ''.join(kind + ',' + name + '\n' for name in sorted(names))
            compacted, audit = compact_text(source)
            assert audit['rules_removed'] > 0
            raw = {}
            for line in records(compacted):
                # Deliberately bypass certificate expansion to test the rules a
                # client actually receives, rather than the inverse reader.
                rule_type, value = line.split(',', 1)
                if rule_type == 'DOMAIN-WILDCARD':
                    raw.setdefault('domain_regex', []).append(wildcard_regex(value))
                elif rule_type in {'DOMAIN', 'DOMAIN-SUFFIX'}:
                    raw.setdefault('domain' if rule_type == 'DOMAIN' else 'domain_suffix', []).append(value)
                else:
                    raise AssertionError(line)
            binaries = []
            for label, rule in [('indexed', {field: sorted(names)}), ('raw-wildcards', raw)]:
                path = root / f'{kind}-{label}.json'
                path.write_text(json.dumps({'version': RULE_SET_VERSION, 'rules': [rule]}))
                binary = path.with_suffix('.srs')
                compile_ruleset(path, binary, args.sing_box)
                binaries.append(binary)
            cases = {host for name in universe
                     for host in [name, 'child.' + name, 'one.two.' + name,
                                  'not' + name, name + '.invalid']}
            for host in sorted(cases):
                expected = host in names or (kind == 'DOMAIN-SUFFIX' and
                                            any(host.endswith('.' + name) for name in names))
                for binary in binaries:
                    result = subprocess.run([args.sing_box, 'rule-set', 'match', '-f', 'binary',
                                             str(binary), '--', host], check=True,
                                            capture_output=True, text=True)
                    actual = 'match rules.' in result.stdout + result.stderr
                    if actual != expected:
                        raise AssertionError((kind, binary.name, host, expected, actual))
                tested += 1
    print(f'{tested} native finite-compaction cases passed; {tested * 2} native match invocations')


if __name__ == '__main__':
    main()
