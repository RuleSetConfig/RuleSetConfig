# Surge & sing-box Rule Sets

[![Build filters](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/build-filter.yml/badge.svg)](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/build-filter.yml)
[![Verify rule sets](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/verify-rulesets.yml/badge.svg)](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/verify-rulesets.yml)

Paired rule sets for [Surge](https://nssurge.com/) and
[sing-box](https://github.com/SagerNet/sing-box): three generated reject sets and
two manually maintained proxy/direct domain sets. Each Surge text file has a
sing-box binary with the same matching coverage.

- [Rule sets](#rule-sets)
- [Quick start](#quick-start)
- [Sources and rule semantics](#sources-and-rule-semantics)
- [Workflows and snapshots](#workflows-and-snapshots)
- [Maintenance and validation](#maintenance-and-validation)
- [Repository layout](#repository-layout)

## Rule sets

| Purpose | Surge text | Surge reference | sing-box binary |
| --- | --- | --- | --- |
| Reject exact domains and domain suffixes | [REJECT-DOMAIN-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list) | `DOMAIN-SET` | [REJECT-DOMAIN-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.srs) |
| Reject domain keywords and wildcard patterns | [REJECT-RULE-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list) | `RULE-SET` | [REJECT-RULE-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.srs) |
| Reject destination IPv4/IPv6 CIDRs | [REJECT-IP-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list) | `RULE-SET` | [REJECT-IP-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.srs) |
| Proxy TLDs and service domains | [PROXY_SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY_SET.list) | `DOMAIN-SET` | [PROXY_SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY_SET.srs) |
| Direct China and service domains | [DIRECT_SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT_SET.list) | `DOMAIN-SET` | [DIRECT_SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT_SET.srs) |

Use all three reject partitions together. `IP-SET` is a filename convention;
Surge loads that file with `RULE-SET`. The proxy/direct sets require the companion
keyword rules shown below because keyword-covered domains were removed from the
lists during refinement.

Current reject counts, source hashes and output hashes are recorded in
[metadata/filter.json](metadata/filter.json). The manual domain pairs and their
compiler version are recorded in [metadata/tld.json](metadata/tld.json).

## Quick start

### Surge

Add the following entries to your existing `[Rule]` section. Reject rules precede
the proxy/direct rules so broad TLDs and parent suffixes cannot bypass blocking.
Replace `PROXY` with your proxy policy or group name.

```ini
[Rule]
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list,REJECT
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list,REJECT
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list,REJECT

DOMAIN-KEYWORD,apple,PROXY
DOMAIN-KEYWORD,chatgpt,PROXY
DOMAIN-KEYWORD,github,PROXY
DOMAIN-KEYWORD,google,PROXY
DOMAIN-KEYWORD,icloud,PROXY
DOMAIN-KEYWORD,openai,PROXY
DOMAIN-KEYWORD,sagernet,PROXY
DOMAIN-KEYWORD,surge,PROXY
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY_SET.list,PROXY

DOMAIN-KEYWORD,alipay,DIRECT
DOMAIN-KEYWORD,autonavi,DIRECT
DOMAIN-KEYWORD,baidu,DIRECT
DOMAIN-KEYWORD,deepseek,DIRECT
DOMAIN-KEYWORD,gtimg,DIRECT
DOMAIN-KEYWORD,tencent,DIRECT
DOMAIN-KEYWORD,wechat,DIRECT
DOMAIN-KEYWORD,weixin,DIRECT
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT_SET.list,DIRECT
```

Domain and pattern checks run before destination IP checks. Leave `no-resolve`
off the IP reference when domain destinations should be resolved for IP matching.
See the official [DOMAIN-SET](https://manual.nssurge.com/rules/domain.html) and
[RULE-SET](https://manual.nssurge.com/rules/ruleset.html) documentation.

### sing-box

The `.srs` files use [rule-set format version 2](https://sing-box.sagernet.org/configuration/rule-set/source-format/),
which requires sing-box **1.10.0 or newer**. The `route`, `reject` and `resolve`
actions in this example require **1.11.0 or newer**. Repository builds and
verification use a pinned, checksum-verified **1.14.2** compiler.

Merge this route fragment into your existing configuration. Replace `proxy` and
`direct` with your outbound tags, and `dns-real` with an existing DNS server tag
that returns real destination addresses. Configure remote-set downloads using
the [remote rule-set fields](https://sing-box.sagernet.org/configuration/rule-set/)
for your client version.

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
        "tag": "REJECT-RULE-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.srs"
      },
      {
        "type": "remote",
        "tag": "REJECT-IP-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.srs"
      },
      {
        "type": "remote",
        "tag": "PROXY_SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY_SET.srs"
      },
      {
        "type": "remote",
        "tag": "DIRECT_SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT_SET.srs"
      }
    ],
    "rules": [
      {
        "rule_set": ["REJECT-DOMAIN-SET", "REJECT-RULE-SET"],
        "action": "reject"
      },
      {
        "action": "resolve",
        "server": "dns-real"
      },
      {
        "rule_set": ["REJECT-IP-SET"],
        "action": "reject"
      },
      {
        "domain_keyword": ["apple", "chatgpt", "github", "google", "icloud", "openai", "sagernet", "surge"],
        "action": "route",
        "outbound": "proxy"
      },
      {
        "rule_set": ["PROXY_SET"],
        "action": "route",
        "outbound": "proxy"
      },
      {
        "domain_keyword": ["alipay", "autonavi", "baidu", "deepseek", "gtimg", "tencent", "wechat", "weixin"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": ["DIRECT_SET"],
        "action": "route",
        "outbound": "direct"
      }
    ]
  }
}
```

The order is domain/pattern rejection, destination resolution, IP rejection, then
proxy/direct routing. IP matching needs a known destination IP; resolving only in
a terminal outbound would occur too late for these route checks. Adapt the
[`resolve` action](https://sing-box.sagernet.org/configuration/route/rule_action/#resolve)
to your existing DNS and FakeIP setup. Earlier terminal rules still take precedence.
These routing sets do not reproduce CNAME-chain inspection, multi-answer DNS
filtering or DNS response codes.

The old `filter.list` / `filter.srs` pair is retired. Replace legacy references
with all three reject partitions above.

## Sources and rule semantics

### Generated reject sets

The daily builder downloads and merges the five AdGuard Hostlists Registry
sources below, including the complete OISD Small list.

| Source | Upstream project |
| --- | --- |
| [filter_1.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt) | AdGuard DNS filter |
| [filter_2.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt) | AdAway Default Blocklist |
| [filter_5.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt) | OISD Blocklist Small |
| [filter_53.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt) | AWAvenue Ads Rule |
| [filter_59.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt) | AdGuard DNS Popup Hosts filter |

It also merges [source/reject-ip-extra.list](source/reject-ip-extra.list), a local
snapshot of the IPv4/IPv6 HTTPDNS entries from
[Sukka's reject rules](https://ruleset.skk.moe/List/non_ip/reject.conf).
The source file retains upstream attribution and the AGPL-3.0 license notice.
Imported entries omit `no-resolve` and use destination IP matching. Update this
source file to maintain the supplement; the generated IP pair is rebuilt from it.

Conversion preserves the supported hostname and destination IP matching scopes:

- Bare domain entries match exactly; leading-dot entries match the domain and its
  subdomains. Parent suffixes remove covered child suffixes and exact hosts.
- The pattern partition contains `DOMAIN-KEYWORD` and `DOMAIN-WILDCARD` rules.
  Supported hostname regexes become equivalent Surge masks and sing-box
  `domain_regex` expressions. A wildcard is removed only when its entire match
  language is covered by a retained reject suffix. Keywords and open-ended
  wildcard suffixes remain.
- Equivalent IPv4/IPv6 CIDR coverage is collapsed. Blocking hosts sink addresses
  produce exact-domain entries; sink addresses themselves do not become IP blocks.
- Adblock `@@` exceptions are audit-only under the existing **block-wins** policy.
  They do not remove positive blocks or become `DIRECT` / `PROXY` rules.
  Same-source `$badfilter` directives disable only their matching rule.
- Unsupported URL paths and scoped modifiers are audited without expanding them
  to entire domains. Unknown hostname regex constructs stop the build for review.

Each build saves `filter-audit.json` as an Actions artifact for 14 days. Its summary
reports partition counts, conversion counts, parent pruning and exception overlaps.

### Manual proxy/direct sets

`PROXY_SET.list` contains proxy TLDs and service domains. `DIRECT_SET.list`
contains `.cn` and direct service domains, including Tencent and Amap. Both support leading-dot
suffixes and bare exact hosts. Their binaries use `domain_suffix` without the
leading dot and `domain` for exact hosts. The companion keywords in the quick
start are maintained in the client configuration and are not embedded in either
manual binary.

On 2026-10-15, the existing lists were merged with domain-only snapshots from:

| Target | SagerNet sing-geosite | Loyalsoldier surge-rules |
| --- | --- | --- |
| `PROXY_SET` | [geosite-geolocation-!cn.srs](https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs) | [proxy.txt](https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/proxy.txt) |
| `DIRECT_SET` | [geosite-geolocation-cn.srs](https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-cn.srs) | [direct.txt](https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt) |

This one-time import preserves exact-host and suffix matching, removes duplicate
and same-set parent-covered entries, and keeps the original lists' domain
coverage. It produces 21,841 proxy entries and 110,703 direct entries. The
[import audit](source/domain-import-2026-10-15.json) records source hashes,
snapshot counts and the 151 proxy / 8 direct regex rules that were not imported:
arbitrary regex cannot be expressed in a Surge `DOMAIN-SET`. Consequently these
pairs cover the sources' domain entries, rather than every SRS regex match.
Children-only sing-box suffixes are merged only where another input already
covers their apex, so conversion does not expand the input union.

Cross-set overlaps are retained from the sources, including direct domains below
proxy TLDs. Their routing depends on client rule order; the quick-start example
places proxy checks before direct checks. The sync workflow rebuilds local lists
and does not fetch either of these upstream projects automatically.

The lists include a reviewed import from [Aegis](https://github.com/Thoseyearsbrian/Aegis)
at commit [`5c20699a2f5538510afd7c806e6e961095bfab15`](https://github.com/Thoseyearsbrian/Aegis/tree/5c20699a2f5538510afd7c806e6e961095bfab15):
[OpenAI](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/5c20699a2f5538510afd7c806e6e961095bfab15/rules/OpenAI.list),
[Apple](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/5c20699a2f5538510afd7c806e6e961095bfab15/rules/Apple.list),
[GitHub](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/5c20699a2f5538510afd7c806e6e961095bfab15/rules/GitHub.list),
[Microsoft](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/5c20699a2f5538510afd7c806e6e961095bfab15/rules/Microsoft.list),
[Google](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/5c20699a2f5538510afd7c806e6e961095bfab15/rules/Google.list),
[WeChat](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/5c20699a2f5538510afd7c806e6e961095bfab15/rules/WeChat.list)
and selected common platforms and required resources from
[Proxy](https://raw.githubusercontent.com/Thoseyearsbrian/Aegis/5c20699a2f5538510afd7c806e6e961095bfab15/rules/Proxy.list).
Sync rebuilds binaries from the local lists; it does **not** fetch Aegis automatically.

The Proxy selection covers common social, media, development, office, cloud,
commerce, payment and travel services, including required login, API, download,
CDN and media resources. Personal blogs, obscure sites, individual test nodes,
dedicated marketing/analytics services and non-domain rules are excluded.
Additional reviewed app-service entries cover BBEdit, Magnet, Elmedia Player,
the Omni suite, PDF Expert, Parallels Desktop, SnapGene, Termius and Telegram.
Tencent mail, media and cloud-game resources use the direct set.

The earlier manual refinement removed same-set TLD/keyword coverage, duplicate entries and
parent-covered domains. Reviewed service/resource hosts may use their parent
suffix, deliberately including siblings. The [Public Suffix List](https://publicsuffix.org/list/)
guides registrable-domain boundaries; shared tenant/CDN namespaces and limited
project/resolver hosts retain their required scope. For example, Datatables uses
`.datatables.net`, CUHK uses `.cuhk.edu.hk`, while `app.link` tenants remain specific.
Tencent static resources use `.qcloudimg.com`, CloudBase storage uses `.qcloud.la`,
and mail documents use `.qmail.com`; `.qqmail.com` is a separate suffix.

Reviewed brand TLDs `.aws`, `.java`, `.microsoft` and `.youtube` use their TLD
suffixes. See the [AWS registry agreement](https://www.icann.org/en/registry-agreements/details/aws),
[Java registry agreement](https://www.icann.org/en/registry-agreements/details/java),
[Microsoft registry policy](https://nic.microsoft/) and [Google Registry FAQ](https://www.registry.google/faqs/).
Other TLDs are not inferred automatically from individual service domains.
Manual entries whose hostnames match current reject domain/pattern rules were
removed during refinement. A rejected child does not remove its parent suffix;
keep reject rules ahead of these sets.

All data credit belongs to the upstream projects. See the
[AdGuard Hostlists Registry](https://github.com/AdguardTeam/HostlistsRegistry) and
upstream repositories for attribution and their respective licenses.

## Workflows and snapshots

| Workflow | Trigger | Result |
| --- | --- | --- |
| [Build Merged AdGuard Filters](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/build-filter.yml) | Daily at 05:13 UTC+8; manual | Fetch sources, merge and verify all three reject pairs, then push changed outputs and `metadata/filter.json` |
| [Sync TLD Rule Sets](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/sync-tld.yml) | Relevant list/tooling changes on `main`; manual | Rebuild both manual binaries and update `metadata/tld.json` |
| [Verify Rule Sets](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/verify-rulesets.yml) | Push to `main`, pull request; manual | Run unit/native tests; check all five text/binary pairs, parent coverage, IP supplement, ordering and manifests |
| [Publish Immutable Rule-Set Snapshot](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/publish-release.yml) | Daily at 16:30 UTC+8; manual | Verify the checked-out commit and publish an immutable daily release |

Scheduled jobs may start later than their configured time. Build, manual-set sync
and snapshot publication share the `ruleset-publisher` concurrency group.

To run manually, open the workflow under **Actions**, choose **Run workflow** and
select `main`. For a complete refresh, finish **Build** and **Sync**, then run
**Verify** and **Publish** against the updated branch. Keep `accept_large_change`
unchecked unless an unusual rule-count change has been reviewed.

The builder checks per-source minimum counts, rejects parent-covered filter rules
and guards each partition against a change below 80% or above 125% of its baseline,
with a 300,000-rule maximum per partition. Empty IP/pattern partitions match
nothing; disappearance of a nonempty partition still fails the change guard.
All candidate pairs must pass compilation, round-trip comparison and manifest
checks before publication. The publisher stages only the requested outputs,
rebases onto current `main` and verifies again before pushing.

The `main` branch is mutable. For a fixed version, pin a commit SHA in the raw URLs
or download a [release snapshot](https://github.com/RuleSetConfig/RuleSetConfig/releases).
Tags use **`rulesets-YYYY-MM-DD` with the UTC date**. Each current snapshot contains
all ten `.list` / `.srs` files, `SHA256SUMS`, `filter-manifest.json` and
`tld-manifest.json`. An existing daily release is left unchanged; rerunning its
workflow does not replace that snapshot. Historical releases retain the files
from their pinned commits.

## Maintenance and validation

Lists use deterministic ascending order. Domain sets put TLD suffixes first,
then sort other entries by domain name while preserving the leading-dot meaning.
Pattern rules sort by rule type/value. IP lists use separate IPv4 and IPv6 sections,
IPv4 first, sorted by numeric network address and prefix length. Generators and
verification enforce the same order.

With sing-box **1.14.2** and `actionlint` in `PATH`, run the existing checks:

```bash
python3 -m unittest discover -s tests -v
python3 tests/native_filter.py
python3 scripts/verify-all.py
python3 scripts/sort-rulesets.py --check
actionlint
```

The tests cover exact/suffix scopes, wildcard boundaries, partition coverage,
CIDR coverage, empty partitions, truncated sources and publication failures.
Native tests check positive and negative matches against compiled binaries.

After editing the manual domain lists, sort them with
`python3 scripts/sort-rulesets.py --write`, then regenerate both binaries and
their manifest before committing:

```bash
python3 scripts/verify-all.py --compile-tld
python3 scripts/write-manifest.py --name tld --sing-box-version 1.14.2 \
  --source 'PROXY_SET|PROXY_SET.list|repository:PROXY_SET.list' \
  --source 'DIRECT_SET|DIRECT_SET.list|repository:DIRECT_SET.list' \
  --output PROXY_SET.list --output PROXY_SET.srs \
  --output DIRECT_SET.list --output DIRECT_SET.srs --manifest metadata/tld.json
python3 scripts/verify-all.py
```

For reject updates, maintain the generator or supplementary source and dispatch
the build workflow. The three reject pairs and their manifest are generated
outputs; a future build replaces direct edits to those files.

## Repository layout

| Path | Purpose |
| --- | --- |
| `REJECT-*.list`, `REJECT-*.srs` | Three generated reject pairs |
| `PROXY_SET.list` / `.srs`, `DIRECT_SET.list` / `.srs` | Manual domain sources and their generated binaries |
| [source/reject-ip-extra.list](source/reject-ip-extra.list) | Supplementary HTTPDNS IP snapshot |
| [metadata/](metadata/) | Source/output hashes, reject counts and compiler version |
| [.github/workflows/](.github/workflows/) | Build, sync, verification and snapshot publication |
| [.github/actions/setup-sing-box/](.github/actions/setup-sing-box/) | Pinned, checksum-verified compiler installation |
| [scripts/merge-filter.py](scripts/merge-filter.py), [filter_patterns.py](scripts/filter_patterns.py), [filter_ips.py](scripts/filter_ips.py) | Source parsing, scope-preserving conversion, parent pruning and IP coverage |
| [scripts/rule_sorting.py](scripts/rule_sorting.py), [sort-rulesets.py](scripts/sort-rulesets.py) | Shared ordering, sorting and checks |
| [scripts/guard-ruleset.py](scripts/guard-ruleset.py) | Generated rule-count guards |
| [scripts/verify-all.py](scripts/verify-all.py) | Manual compilation, pair/manifest validation and coverage checks |
| [scripts/write-manifest.py](scripts/write-manifest.py) | Deterministic provenance manifests |
| [scripts/publish-rulesets.sh](scripts/publish-rulesets.sh) | Stage selected outputs, rebase, verify and push |
| [tests/](tests/) | Conversion, partition, ordering and publication tests |

## License

Copyright (C) 2026 RuleSetConfig

Repository code is distributed under the [GNU General Public License v3.0](LICENSE).
Upstream data retains its respective project's license.
