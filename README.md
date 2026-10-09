# Personal sing-box & Surge Configurations

This repository contains my personal configurations for [sing-box](https://github.com/SagerNet/sing-box) and [Surge](https://nssurge.com/).

## Filter artifacts

The five upstream lists are merged and deduplicated before being split into three
partitions. Each partition has a Surge text file and a semantically equivalent
sing-box binary file:

| Surge file | Contents | Surge reference | sing-box file |
| --- | --- | --- | --- |
| REJECT-DOMAIN-SET.list | Exact domains and domain suffixes | DOMAIN-SET | REJECT-DOMAIN-SET.srs |
| REJECT-IP-SET.list | Destination IPv4/IPv6 CIDRs | RULE-SET | REJECT-IP-SET.srs |
| REJECT-RULE-SET.list | Domain keywords and wildcard patterns | RULE-SET | REJECT-RULE-SET.srs |

The domain partition uses plain hostnames for exact matches and a leading dot
for suffix matches. The IP partition contains IP-CIDR/IP-CIDR6 declarations
without policies. IP-SET is its filename convention; Surge loads it using RULE-SET.
The pattern partition contains DOMAIN-KEYWORD and DOMAIN-WILDCARD declarations.
Supported hostname regexes become equivalent wildcard masks in Surge and
domain_regex expressions in sing-box. The three files contain separate rule
types; their union is the merged filter.

## Sources & Credits

Only these five lists are merged. OISD Small is used in full; no Chinese-use
selection or additional reference lists are part of the build.

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

Migration: replace the old filter.list/filter.srs references with the three new
references above. The legacy generated pair is retired. The main branch is mutable;
pin a commit SHA or consume a daily rulesets-YYYY-MM-DD release for immutable inputs.
Releases contain all six files, SHA256SUMS and filter-manifest.json.

## Automatic updates and verification

.github/workflows/build-filter.yml runs daily at 05:13 UTC+8 and can be dispatched
manually. GitHub may start scheduled jobs later. The builder:

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
