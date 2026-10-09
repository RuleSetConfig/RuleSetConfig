# Surge & sing-box Rule Sets

This repository builds and publishes three paired reject rule sets for
[Surge](https://nssurge.com/) and [sing-box](https://github.com/SagerNet/sing-box),
and maintains two paired Surge/sing-box domain sets.

## Filter artifacts

The five upstream lists are merged and deduplicated before being split into three
partitions. Each partition has a Surge text file and a semantically equivalent
sing-box binary file:

| Surge file | Contents | Surge reference | sing-box file |
| --- | --- | --- | --- |
| [REJECT-DOMAIN-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list) | Exact domains and domain suffixes | DOMAIN-SET | [REJECT-DOMAIN-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.srs) |
| [REJECT-IP-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list) | Destination IPv4/IPv6 CIDRs | RULE-SET | [REJECT-IP-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.srs) |
| [REJECT-RULE-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list) | Domain keywords and wildcard patterns | RULE-SET | [REJECT-RULE-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.srs) |

The domain partition uses plain hostnames for exact matches and a leading dot
for suffix matches. The IP partition contains IP-CIDR/IP-CIDR6 declarations
without policies. IP-SET is its filename convention; Surge loads it using RULE-SET.
The pattern partition contains DOMAIN-KEYWORD and DOMAIN-WILDCARD declarations.
Supported hostname regexes become equivalent wildcard masks in Surge and
domain_regex expressions in sing-box. The three files contain separate rule
types; their union is the merged filter.

## Manual domain sets

| Surge file | Domain suffixes | Surge reference | sing-box file |
| --- | --- | --- | --- |
| [PROXY_SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY_SET.list) | 51 manually selected TLDs, in the supplied order | DOMAIN-SET | [PROXY_SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY_SET.srs) |
| [DIRECT_SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT_SET.list) | `.cn`, `.amap.com`, `.qq.com` | DOMAIN-SET | [DIRECT_SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT_SET.srs) |

Both files contain one leading-dot suffix per line, such as `.ai` and `.amap.com`.
The lists are maintained manually. Their same-name SRS files use `domain_suffix`
with the leading dot removed, preserving the suffix itself and its subdomains.
All five text/binary pairs are checked for identical matching coverage and are
included in snapshot releases. The daily filter builder generates the three
reject pairs; the manual-set sync workflow rebuilds the two domain binaries when their
source lists or build tooling change on main, and also supports manual dispatch.

```ini
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY_SET.list,PROXY
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT_SET.list,DIRECT
```

Replace `PROXY` with your proxy policy or group name.

For sing-box, reference `PROXY_SET.srs` and `DIRECT_SET.srs` as remote binary
rule sets and route their tags to your proxy and direct outbounds respectively.
They use rule-set format version 2, requiring sing-box 1.10.0 or newer.
To regenerate both binaries locally with the pinned sing-box compiler:

```bash
python3 scripts/verify-all.py --compile-tld
python3 scripts/write-manifest.py --name tld --sing-box-version 1.14.2 \
  --source 'PROXY_SET|PROXY_SET.list|repository:PROXY_SET.list' \
  --source 'DIRECT_SET|DIRECT_SET.list|repository:DIRECT_SET.list' \
  --output PROXY_SET.list --output PROXY_SET.srs \
  --output DIRECT_SET.list --output DIRECT_SET.srs --manifest metadata/tld.json
python3 scripts/verify-all.py
```

## Sources & Credits

The build merges the five lists below, including the complete OISD Small list.

| Registry source | Upstream |
| --- | --- |
| [filter_1.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt) | AdGuard DNS filter |
| [filter_2.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt) | AdAway Default Blocklist |
| [filter_5.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt) | OISD Blocklist Small |
| [filter_53.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt) | AWAvenue Ads Rule |
| [filter_59.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt) | AdGuard DNS Popup Hosts filter |

All credit for the data belongs to the upstream projects. Upstream data retains
its respective licenses; see the [AdGuard Hostlists Registry](https://github.com/AdguardTeam/HostlistsRegistry)
and upstream repositories for attribution and license details.

## Consumption

For Surge:

```ini
[Rule]
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list,REJECT
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list,REJECT
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list,REJECT
```

The order above checks domains and patterns before destination IPs. Do not add
no-resolve to the IP reference when domains should be resolved for IP matching.
See the official [DOMAIN-SET format](https://manual.nssurge.com/rules/domain.html)
and [RULE-SET format](https://manual.nssurge.com/rules/ruleset.html).

For sing-box, declare all three remote binary rule sets and reference their tags
in a reject route rule. The files use rule-set format version 2 and require
sing-box 1.10.0 or newer.

```json
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "REJECT-DOMAIN-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.srs"
      },
      {
        "type": "remote",
        "tag": "REJECT-IP-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.srs"
      },
      {
        "type": "remote",
        "tag": "REJECT-RULE-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.srs"
      }
    ],
    "rules": [
      {
        "rule_set": ["REJECT-DOMAIN-SET", "REJECT-RULE-SET", "REJECT-IP-SET"],
        "action": "reject"
      }
    ]
  }
}
```

This is a route configuration fragment. IP matching requires a known destination
IP. For domain destinations, check the domain/pattern sets first, arrange a
resolve action when needed, then check the IP set before any terminal allow
route. Earlier terminal rules take precedence. These routing block sets do not
reproduce CNAME-chain inspection, multi-answer DNS filtering or DNS response codes.

Migration: replace the old `filter.list`/`filter.srs` references with the three new
references above. The legacy generated pair is retired. The main branch is mutable;
pin a commit SHA or consume a daily rulesets-YYYY-MM-DD release for immutable inputs.
Snapshots built from this revision contain all ten rule files, `SHA256SUMS`,
`filter-manifest.json` and `tld-manifest.json`. Historical snapshots keep the
files from their pinned commit.

## Repository layout

| Path | Purpose |
| --- | --- |
| `REJECT-*.list`, `REJECT-*.srs` | The three published Surge/sing-box pairs |
| `PROXY_SET.list` / `PROXY_SET.srs`, `DIRECT_SET.list` / `DIRECT_SET.srs` | Two manually maintained domain lists and their generated binaries |
| [metadata/filter.json](metadata/filter.json) | Five source hashes, six output hashes, counts and compiler version |
| [metadata/tld.json](metadata/tld.json) | Two local source hashes, four output hashes and compiler version |
| [.github/workflows/build-filter.yml](.github/workflows/build-filter.yml) | Fetch, merge, partition, verify and publish the rules |
| [.github/workflows/verify-rulesets.yml](.github/workflows/verify-rulesets.yml) | Verify pushes, pull requests and manual runs |
| [.github/workflows/sync-tld.yml](.github/workflows/sync-tld.yml) | Rebuild and publish the two domain binaries when the local lists change |
| [.github/workflows/publish-release.yml](.github/workflows/publish-release.yml) | Create immutable daily snapshots |
| [.github/actions/setup-sing-box/action.yml](.github/actions/setup-sing-box/action.yml) | Install the pinned, checksum-verified compiler |
| [scripts/merge-filter.py](scripts/merge-filter.py), [scripts/filter_patterns.py](scripts/filter_patterns.py) | Parse and convert the five sources into the three pairs |
| [scripts/guard-ruleset.py](scripts/guard-ruleset.py) | Guard generated rule counts |
| [scripts/verify-all.py](scripts/verify-all.py) | Compile the manual domain sets; check every text/binary pair and manifest hash |
| [scripts/write-manifest.py](scripts/write-manifest.py) | Record source and output provenance |
| [scripts/publish-rulesets.sh](scripts/publish-rulesets.sh) | Stage selected files, rebase, verify and push |
| [tests/](tests/) | Rule conversion, partition and publication regression tests |
| [LICENSE](LICENSE) | Repository license |

## Automatic updates and verification

The build workflow runs daily at 05:13 UTC+8; the release workflow runs at 16:30
UTC+8. Both can be dispatched manually. GitHub may start scheduled jobs later.
The builder:

- Checks source-specific minimum counts, merges identical rules and prunes child
  domains covered by parent suffixes.
- Collapses equivalent IPv4/IPv6 CIDR coverage and splits domains, IPs and patterns.
- Guards the size of each partition. Empty IP/pattern partitions are represented
  by zero JSON rules, which match nothing; disappearing nonempty partitions still
  fail the change guard unless accept_large_change is enabled after review.
- Compiles each JSON source with pinned, checksum-verified sing-box 1.14.2.
- Decompiles all three binaries and checks their semantics against the Surge files.
- Verifies SHA-256 hashes in metadata/filter.json before publication, including
  after rebasing on the latest main.

Adblock @@ exceptions remain audit-only under the existing block-wins policy.
They are never published as DIRECT/PROXY rules and do not remove positive blocks.
Same-source badfilter directives disable only their matching rule. Unsupported
URL paths and scoped modifiers are audited without expanding them to entire
domains. Unknown hostname regex constructs stop the build for review.
Blocking hosts sink addresses remain exact-domain entries; the sink addresses
themselves do not become destination IP blocks.

Each run saves filter-audit.json as an Actions artifact for 14 days and prints
partition counts, per-source conversion counts and exception overlaps in the
Actions summary. metadata/filter.json records input/output hashes, rule counts
and compiler version. The build and release workflows share a publishing
concurrency group. Only the six generated files and manifest are staged by the
filter publisher.

With sing-box in PATH:

```bash
python3 -m unittest discover -s tests -v
python3 tests/native_filter.py
python3 scripts/verify-all.py
actionlint
```

The tests cover exact/suffix distinctions, partition union, CIDR coverage,
wildcard boundaries, empty partitions, source truncation and publication failure
handling. Native matching tests compile the split fixtures and check positive
and negative cases against the actual binaries.

## License

Copyright (C) 2026 RuleSetConfig

This repository is distributed under the [GNU General Public License v3.0](LICENSE),
except for upstream data, which remains under its respective project's license.
