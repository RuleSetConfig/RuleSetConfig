#!/usr/bin/env python3
"""Verify reviewed functional portals and representative brand routes natively."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from filter_scope import AppScope


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sing-box', default='sing-box')
    args = parser.parse_args()
    probes = 0

    def match(policy, host):
        nonlocal probes
        for kind in ['DOMAIN-SET', 'RULE-SET']:
            result = subprocess.run([args.sing_box, 'rule-set', 'match', '-f', 'binary',
                                     str(ROOT / f'{policy}-{kind}.srs'), '--', host],
                                    check=True, capture_output=True, text=True)
            probes += 1
            if 'match rules.' in result.stdout + result.stderr:
                return True
        return False

    scope = AppScope(ROOT / 'source/reject-app-scope.json')
    for host in sorted(scope.functional_exact_hosts):
        if match('REJECT', host):
            raise AssertionError(('functional service is blocked', host))
    cases = {host: 'DIRECT' for host in [
        'qq.com', 'work.weixin.qq.com', 'spdb.com.cn', '12306.cn', 'italent.cn',
        'www.ctrip.com', 'img.tripcdn.com', 'restapi.amap.com']}
    cases.update({host: None for host in ['gtimg.com', 'myqcloud.com', 'bankcomm.com',
                                        'beisen.com', 'bdcgslb.com', 'vegslb.com']})
    cases.update({host: 'PROXY' for host in ['googlevideo.com', 'icloud-content.com', 'github.com']})
    cases.update({'notbankcomm.com': None, 'bankcomm.com.invalid': None})
    for host, expected in cases.items():
        actual = {policy for policy in ['REJECT', 'PROXY', 'DIRECT'] if match(policy, host)}
        wanted = {expected} if expected else set()
        if actual != wanted:
            raise AssertionError((host, wanted, actual))
    print(f'{len(cases) + len(scope.functional_exact_hosts)} native brand/service cases passed; '
          f'{probes} native match invocations')


if __name__ == '__main__':
    main()
