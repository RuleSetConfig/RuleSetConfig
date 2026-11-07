#!/usr/bin/env python3
"""Project literal brand/service namespaces from the pinned community archive."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import tarfile
from direct_refinement import public_suffix_rules

ALIASES = {'youtube':'google','google-trust-services':'google','amp':'google','icloud':'apple',
           'azure':'microsoft','qcloud':'tencent','tencent-dev':'tencent',
           'bytedance':'bytedance-reading-drama','volcengine':'bytedance-reading-drama',
           'douyin':'bytedance-reading-drama','ctrip':'travel','aliyun':'alibaba',
           'hikvision':'ezviz-hikvision','zaobao':'sph-zaobao','qihoo360':'qihoo-sogou',
           'facebook':'amazon-meta','aws':'amazon-meta'}
SKIP = {'cn','private','ads','tracker','speedtest','gfw','greatfire','geosite','cdn',
        'win-spy','win-update','test','test-security'}


def build(root, archive):
    root, archive = Path(root), Path(archive)
    record = json.loads((root/'source/companion-import.json').read_text())['sources']['community']
    raw = archive.read_bytes()
    if len(raw) != record['bytes'] or hashlib.sha256(raw).hexdigest() != record['sha256']:
        raise ValueError('community archive fingerprint differs')
    suffix_data = (root/'source/public-suffix-list.dat').read_bytes()
    suffix_record = json.loads((root/'source/companion-import.json').read_text())['direct_refinement']['public_suffix_list']
    if len(suffix_data) != suffix_record['bytes'] or hashlib.sha256(suffix_data).hexdigest() != suffix_record['sha256']:
        raise ValueError('public suffix fingerprint differs')
    public, wildcard, exceptions = public_suffix_rules(root/'source/public-suffix-list.dat')
    shared = {'cloudfront.net','amazonaws.com','azurewebsites.net','run.app','appspot.com','pages.dev','workers.dev','github.io','gitlab.io','fastly.net','fastly-edge.com','akamaized.net','akamai.net','akamaiedge.net','edgekey.net','edgesuite.net','aliyuncs.com','myqcloud.com'}
    groups = defaultdict(lambda: {'suffixes':set(), 'exact':set(), 'source_groups':set()})
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            parts = member.name.split('/')
            if not member.isfile() or len(parts)!=3 or parts[1]!='data':
                continue
            name = parts[2]
            if name in SKIP or name.startswith(('category-','geolocation-','tld-')):
                continue
            family = ALIASES.get(name, name)
            for base in ('google','apple','microsoft','tencent','adobe','amazon','baidu','netease'):
                if name.startswith(base+'-'):
                    family = base
            for line in tar.extractfile(member).read().decode('utf-8').splitlines():
                fields = line.split('#',1)[0].split()
                if not fields or fields[0].startswith(('include:','regexp:','keyword:')):
                    continue
                item = fields[0]; host=item.removeprefix('full:').removeprefix('domain:').lower()
                if ('.' not in host or len(host)>253 or not all(
                        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', s) for s in host.split('.'))):
                    continue
                is_shared = host in shared or (host not in exceptions and (host in public or host.split('.',1)[-1] in wildcard))
                key = 'exact' if item.startswith('full:') or is_shared else 'suffixes'
                groups[family][key].add(host); groups[family]['source_groups'].add(name)
    data={'schema':1,'description':'Literal namespaces classified by pinned community brand/service groups. This is source classification, not a legal ownership claim, keyword inference or routing/blocking authority.',
          'source':record,'public_suffixes':suffix_record,'shared_namespace_policy':'Public suffixes and shared infrastructure roots classify only their exact names; unrelated tenants are not inferred.','omitted':'aggregate groups, includes, keywords, regex and single-label namespaces',
          'groups':{g:{k:sorted(v) for k,v in values.items()} for g,values in sorted(groups.items())}}
    destination=root/'source/brand-catalog.json'
    destination.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'groups':len(groups),'literal_namespaces':sum(len(x['suffixes'])+len(x['exact']) for x in groups.values())}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',default='.');parser.add_argument('--archive',required=True)
    args=parser.parse_args();build(args.root,args.archive)
