# Surge & sing-box Rule Sets

[![Build filters](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/build-filter.yml/badge.svg)](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/build-filter.yml)
[![Sync proxy/direct](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/sync-tld.yml/badge.svg)](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/sync-tld.yml)
[![Sync direct/proxy IP](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/sync-ip.yml/badge.svg)](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/sync-ip.yml)
[![Verify rule sets](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/verify-rulesets.yml/badge.svg)](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/verify-rulesets.yml)

Nine maintained rule-set pairs for [Surge](https://nssurge.com/) and
[sing-box](https://github.com/SagerNet/sing-box), organized by policy
(`PROXY`, `DIRECT`, `REJECT`) and match type (`DOMAIN-SET`, `RULE-SET`, `IP-SET`).
Each name provides a Surge `.list` and a sing-box `.srs` in format version 5.

The portable hostname and destination-IP rules have the same matching scope in
both formats. `PROTOCOL,STUN` is the explicit exception: it appears in the Surge
reject text, while sing-box needs a separate sniff/reject route rule as shown below.

- [Rule sets](#rule-sets)
- [Quick start](#quick-start)
- [Sources and rule semantics](#sources-and-rule-semantics)
- [Workflows and snapshots](#workflows-and-snapshots)
- [Maintenance and validation](#maintenance-and-validation)
- [Repository layout](#repository-layout)

## Rule sets

| Purpose | Surge text | Surge reference | sing-box binary |
| --- | --- | --- | --- |
| Proxy exact domains and domain suffixes | [PROXY-DOMAIN-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.list) | `DOMAIN-SET` | [PROXY-DOMAIN-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.srs) |
| Proxy domain keywords | [PROXY-RULE-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.list) | `RULE-SET` | [PROXY-RULE-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.srs) |
| Proxy service and curated destination CIDRs | [PROXY-IP-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.list) | `RULE-SET` | [PROXY-IP-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.srs) |
| Direct `.cn`, `.中国` and `.中國` TLDs | [DIRECT-DOMAIN-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.list) | `DOMAIN-SET` | [DIRECT-DOMAIN-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.srs) |
| Direct domain keywords | [DIRECT-RULE-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.list) | `RULE-SET` | [DIRECT-RULE-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.srs) |
| Direct APNIC CN IPv4/IPv6 allocations | [DIRECT-IP-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.list) | `RULE-SET` | [DIRECT-IP-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.srs) |
| Reject exact domains and domain suffixes | [REJECT-DOMAIN-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list) | `DOMAIN-SET` | [REJECT-DOMAIN-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.srs) |
| Reject keywords, wildcards, AND and STUN matches | [REJECT-RULE-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list) | `RULE-SET` | [REJECT-RULE-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.srs) |
| Reject destination IPv4/IPv6 CIDRs | [REJECT-IP-SET.list](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list) | `RULE-SET` | [REJECT-IP-SET.srs](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.srs) |

Use all three reject partitions together. `IP-SET` is a filename convention;
Surge loads that file with `RULE-SET`. Add `PROXY-RULE-SET` and `DIRECT-RULE-SET`
alongside their same-policy domain sets: keywords cannot be represented in a
`DOMAIN-SET`. All keyword sources are shared through
[source/domain-keywords.json](source/domain-keywords.json).
The proxy IP pair includes the curated Telegram/Apple ranges, public DNS hosts
and exact Parallels Desktop service-address snapshot in
[source/proxy-ip-extra.list](source/proxy-ip-extra.list).

Current reject counts, source hashes and output hashes are recorded in
[metadata/filter.json](metadata/filter.json). The proxy/direct sources, domain
counts, regex exclusions and compiler version are recorded in
[metadata/tld.json](metadata/tld.json). APNIC serial/date, IPv4/IPv6 counts and
source/output hashes are recorded in [metadata/direct-ip.json](metadata/direct-ip.json).
Companion keyword coverage and hashes are recorded in
[metadata/keywords.json](metadata/keywords.json). Proxy IP selection, source
hashes and any APNIC overlap are recorded in
[metadata/proxy-ip.json](metadata/proxy-ip.json).

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

RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.list,PROXY
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.list,PROXY

RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.list,DIRECT
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.list,DIRECT

RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.list,PROXY
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.list,DIRECT
```

Reject rules precede routing policies, and explicit domain policies precede the
proxy/direct IP fallbacks. Leave `no-resolve` off the IP reference when domain
destinations should be resolved for IP matching.
See the official [DOMAIN-SET](https://manual.nssurge.com/rules/domain.html) and
[RULE-SET](https://manual.nssurge.com/rules/ruleset.html) documentation.

### Reviewed 96-rule supplement

The 96 reviewed Surge reject rules are maintained locally in
[source/reject-domain-extra.list](source/reject-domain-extra.list) (72 exact/suffix entries)
and [source/reject-rule-extra.list](source/reject-rule-extra.list) (24 pattern/Surge-only entries).
They replace automatic imports of the Qimao/Fanqie remote modules.
The generated pattern list puts both AND rules first, followed by keywords,
suffix/exact/wildcard rules and the explicitly enabled STUN/User-Agent rules.

The whole-domain block for zijieapi.com is removed and guarded by a reviewed
exclusion; individual ad, telemetry, AB-test and mssdk blocks remain.
The snssdk.com keyword block remains enabled. The rules retain the reviewed
blocking scope across apps; CI does not test current-app ad removal or normal
application behavior.

### sing-box

The `.srs` files use [rule-set format version 5](https://sing-box.sagernet.org/configuration/rule-set/source-format/),
which requires sing-box **1.14.0 or newer**. Repository builds and verification
use a pinned, checksum-verified **1.14.2** compiler. Publication checks require
format version 5 for every generated rule set.

Generation uses `scripts/ruleset_format.py` because the upstream compiler
automatically lowers the binary version when newer match fields are unused.
The wrapper keeps the compressed rule payload intact, pins the binary header
to v5, and validates it with the native decoder before replacing any output.

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
        "tag": "PROXY-RULE-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.srs"
      },
      {
        "type": "remote",
        "tag": "PROXY-DOMAIN-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.srs"
      },
      {
        "type": "remote",
        "tag": "DIRECT-RULE-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.srs"
      },
      {
        "type": "remote",
        "tag": "DIRECT-DOMAIN-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.srs"
      },
      {
        "type": "remote",
        "tag": "PROXY-IP-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.srs"
      },
      {
        "type": "remote",
        "tag": "DIRECT-IP-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.srs"
      }
    ],
    "rules": [
      {
        "action": "sniff",
        "sniffer": ["stun"]
      },
      {
        "protocol": "stun",
        "action": "reject"
      },
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
        "rule_set": ["PROXY-RULE-SET"],
        "action": "route",
        "outbound": "proxy"
      },
      {
        "rule_set": ["PROXY-DOMAIN-SET"],
        "action": "route",
        "outbound": "proxy"
      },
      {
        "rule_set": ["DIRECT-RULE-SET"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": ["DIRECT-DOMAIN-SET"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": ["PROXY-IP-SET"],
        "action": "route",
        "outbound": "proxy"
      },
      {
        "rule_set": ["DIRECT-IP-SET"],
        "action": "route",
        "outbound": "direct"
      }
    ]
  }
}
```

The order is domain/pattern rejection, destination resolution, IP rejection,
proxy/direct domain routing, proxy IP fallback, then APNIC CN IP direct fallback.
The proxy IP pair includes the Telegram/Apple ranges previously kept inline.
IP matching needs a known destination IP; resolving only in a terminal outbound
would occur too late for these route checks. Adapt the
[`resolve` action](https://sing-box.sagernet.org/configuration/route/rule_action/#resolve)
to your existing DNS and FakeIP setup. Earlier terminal rules still take precedence.
These routing sets do not reproduce CNAME-chain inspection, multi-answer DNS
filtering or DNS response codes.

The old `filter.list` / `filter.srs` pair is retired. Replace legacy references
with all three reject partitions above.

## Sources and rule semantics

### Generated reject sets

The daily builder downloads only these three AdGuard Hostlists Registry sources:

| Source | Upstream project | Imported scope |
| --- | --- | --- |
| [filter_1.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt) | AdGuard DNS filter | Domains, patterns and destination IPs |
| [filter_2.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt) | AdAway Default Blocklist | Domains and domain patterns only |
| [filter_59.txt](https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt) | AdGuard DNS Popup Hosts filter | Domains and domain patterns only |

Only filter_1 contributes upstream IP blocks. The domain-only inputs cannot
contribute IP entries even if future upstream versions add them. Source roles
are recorded in the conversion audit and the committed provenance manifest.
Filters 5 and 53 are no longer downloaded or imported.

It also merges [source/reject-ip-extra.list](source/reject-ip-extra.list), a local
snapshot of the IPv4/IPv6 HTTPDNS entries from
[Sukka's reject rules](https://ruleset.skk.moe/List/non_ip/reject.conf), plus
maintainer-selected destination IP rules.
The source file retains upstream attribution and the AGPL-3.0 license notice.
Imported entries omit `no-resolve` and use destination IP matching. Update this
source file to maintain the supplement; the generated IP pair is rebuilt from it.

Maintainer-selected domain blocks live in
[source/reject-domain-extra.list](source/reject-domain-extra.list). The daily
builder merges this DOMAIN-SET source before parent pruning: bare hostnames
remain exact matches and leading-dot entries include subdomains. Verification
checks that the generated domain pair still covers every supplementary entry.

Maintainer-selected keyword and wildcard blocks live in
[source/reject-rule-extra.list](source/reject-rule-extra.list), using
`DOMAIN-KEYWORD,value`, `DOMAIN-WILDCARD,value`, keyword-only AND rules, PROTOCOL,STUN or USER-AGENT,ttplayer*,
without policies or options. `AND` compiles to separate
single-keyword conditions joined by logical `and`; keyword order does not
change the match. PROTOCOL,STUN and USER-AGENT,ttplayer* are enabled in the
Surge list and explicitly recorded in the manifest's surge_only fields.
Headless SRS supports neither protocol nor User-Agent matching; both entries
are omitted from SRS with an exact audited allowlist. STUN needs the explicit
sniff/reject route rules in the sing-box example. No equivalent User-Agent
rule is available in SRS. No match-all, port-based or UDP-wide replacement is emitted.
A Surge RULE-SET containing these two entries must not use pre-matching.
Surge User-Agent matching depends on the HTTP engine seeing the request header,
including the documented HTTPS/MITM limitations.

The daily builder merges this source into the pattern partition. Verification
checks that the generated outputs retain each entry's matching scope.

Conversion preserves the supported hostname and destination IP matching scopes:

- Bare domain entries match exactly; leading-dot entries match the domain and its
  subdomains. Parent suffixes remove covered child suffixes and exact hosts.
- The pattern partition contains keywords, wildcards, logical AND and the two audited Surge-only rules.
  Supported hostname regexes become equivalent Surge masks and sing-box
  `domain_regex` expressions. Parent suffixes first remove fully covered masks.
  A second, equivalent pass removes domain entries covered by retained keywords,
  keyword ANDs or a complete apex/descendant wildcard union. It also proves
  wildcard containment and combines masks differing in one character into an
  exact character class. Unproven or over-budget comparisons retain their rules.
- Equivalent IPv4/IPv6 CIDR coverage is collapsed. Blocking hosts sink addresses
  produce exact-domain entries; sink addresses themselves do not become IP blocks.
- Adblock `@@` exceptions are audit-only under the existing **block-wins** policy.
  They do not remove positive blocks or become `DIRECT` / `PROXY` rules.
  Same-source `$badfilter` directives disable only their matching rule.
- Reviewed false positives are maintained separately in
  [`source/reject-domain-exclusions.list`](source/reject-domain-exclusions.list).
  Builds remove same-host exact/suffix entries and verification rejects any
  remaining parent, keyword or wildcard coverage. This currently permits the
  `beacon.cdn.qq.com` bootstrap SDK required by START activity pages; reporting
  domains such as `otheve.beacon.qq.com` remain blocked.
- Unsupported URL paths and scoped modifiers are audited without expanding them
  to entire domains. Unknown hostname regex constructs stop the build for review.

Load both reject domain and pattern companions with the same REJECT policy and
matching-stage parameters, at adjacent priority positions. Their combined coverage
is preserved; the domain file alone no longer carries entries fully covered by its
pattern companion. IP and explicit AND/STUN rules retain their existing scope.

Each build saves `filter-audit.json` as an Actions artifact for 14 days. It includes
per-deletion certificates, automaton inclusion proofs, exact character-class
merges, partition/conversion counts and exception overlaps. The public manifest
records optimization totals, and verification checks that the generated companions
are at an equivalent-optimization fixed point. Exception overlap analysis uses the
domain projection before equivalent pruning, whose coverage remains in the union.
See [the optimization audit](docs/equivalent-optimization.md) for a fixed snapshot.

### Synchronized proxy/direct sets

`PROXY-DOMAIN-SET.list` contains only top-level suffixes selected from
[IANA's Root Zone Database](https://www.iana.org/domains/root/db), using its official
[machine-readable registry](https://data.iana.org/TLD/v1/tlds.json). The old proxy
service-domain list, third-party proxy imports and `source/proxy-custom.list`
have been removed. Daily updates rebuild the proxy pair from scratch.

The explicit policy lives in [source/proxy-tld-policy.json](source/proxy-tld-policy.json).
It includes all active, delegated country-code TLDs except `.cn`, `.中国`
(`.xn--fiqs8s`) and `.中國` (`.xn--fiqz9s`). This includes `.hk`, `.tw`, `.mo`,
their internationalized equivalents, and repurposed suffixes such as `.cc`, `.tv`,
`.io`, `.ai`, `.me` and `.co`. IDN suffixes use ASCII Punycode in both output formats.
Country-code selection follows IANA's TLD classification, not the manager's address.

The policy also retains `.gov`, `.mil` and 43 explicitly reviewed overseas brand
namespaces. These dedicated generic TLDs must remain active and delegated and
match the reviewed manager organization and country exactly. Retirement or owner/
country changes exclude an explicit selection; missing policy records, malformed
data and source-count failures stop the build. Other generic TLDs are never added
merely because their manager is overseas. `.edu` and shared generic suffixes such
as `.com`, `.net`, `.org`, `.app` and `.dev` remain excluded.
IANA describes delegations rather than network reachability. Including a complete
country-code suffix also routes domestic services under that suffix to the proxy
when these proxy checks precede direct checks. This is an explicit routing policy,
not an IANA determination that a website requires a proxy.

The proxy `.list` contains leading-dot suffixes only, and `.srs` uses the same
suffixes without the leading dots. The list remains independently complete,
including brand TLDs also matched by the separate proxy keyword companion.
`PROXY-RULE-SET` keywords and `PROXY-IP-SET` destinations are maintained separately;
this TLD replacement does not clear those companion policies.

`DIRECT-DOMAIN-SET.list` is rebuilt exclusively from the same official IANA
registry. It contains exactly these three active, delegated country-code TLDs:

```text
.cn
.xn--fiqs8s
.xn--fiqz9s
```

The two Punycode suffixes represent `.中国` and `.中國`. These are independent
TLDs, so `.cn` alone does not cover them. The direct selector requires all three
records to remain active, delegated country-code TLDs managed in country `CN`;
a missing or invalid record stops the build. Third-party direct imports and
`source/direct-custom.list` have been retired. Other Chinese-language or
China-managed generic TLDs are outside this fixed selection.

| Target | Sources |
| --- | --- |
| `PROXY-DOMAIN-SET` | Official IANA JSON: all active non-mainland ccTLDs plus reviewed dedicated TLDs |
| `DIRECT-DOMAIN-SET` | Official IANA JSON: `.cn`, `.中国` and `.中國` only |

Both domain lists remain independently complete, including suffixes also matched
by a keyword companion. Both proxy companions precede both direct companions in
the client examples. `PROXY-RULE-SET`, `DIRECT-RULE-SET` and the IP pairs remain
separate policies. The keyword policy in
[source/domain-keywords.json](source/domain-keywords.json) requires at least five
lowercase ASCII letters and can route service domains independently of TLD rules.

Fresh IANA data rebuilds both domain pairs and their provenance together.
`metadata/tld.json` records the IANA source hash, selection-policy and selector
hashes, selected IANA records and rejected proxy selections. The Actions
`domain-sync-audit` artifact preserves the audit and complete IANA JSON for 14 days.
Verification requires each list to agree exactly with its recorded IANA selection
and checks text/binary equivalence. Failed downloads, malformed sources or failed
compilation leave committed pairs intact.

TLD data credit belongs to IANA. Historical service-domain reviews in `docs/`
describe earlier snapshots and do not supply either current TLD output.

### APNIC China IP set

`DIRECT-IP-SET.list` and `.srs` are rebuilt daily from APNIC's official
[delegated-apnic-latest](https://ftp.apnic.net/stats/apnic/delegated-apnic-latest)
and its [MD5 file](https://ftp.apnic.net/stats/apnic/delegated-apnic-latest.md5).
The builder selects country code `CN`, types `ipv4` / `ipv6`, and statuses
`allocated` / `assigned`. ASN records, other country codes, available addresses
and reserved addresses are excluded.

According to APNIC's [statistics format](https://www.apnic.net/about-apnic/corporate-documents/documents/resource-guidelines/rir-statistics-exchange-format/),
IPv4 `value` is an address count, while IPv6 `value` is a prefix length. IPv4
ranges are converted to exact CIDRs, including non-aligned ranges; overlapping
and adjacent CIDRs are collapsed without changing address coverage. The output
uses `IP-CIDR` / `IP-CIDR6` rows, with IPv4 first and numeric ascending order.
Use Surge `RULE-SET` for this file; `IP-SET` is part of its filename.

APNIC country codes describe the organization receiving an allocation or
assignment. The addresses may be used elsewhere, so the data does not guarantee
their current physical location. Place this direct IP fallback after explicit
proxy/direct domain policies and reject rules, as in the examples above.

The builder verifies the official MD5, complete record/type-summary counts,
minimum CN counts in both families, and text/SRS address-space equality before
publication. It records APNIC serial/date and per-family counts in
`metadata/direct-ip.json`. The output guard accepts 80%–125% of the baseline
rule count, with a 30,000-rule maximum. Failed downloads, incomplete input or
failed validation preserve the committed pair. `accept_large_change` only
bypasses the relative change guard after review.

### Common service proxy IP set

`PROXY-IP-SET.list` and `.srs` include curated Telegram/Apple ranges and service IPs.
The daily builder uses these sources:

| Source | Selection |
| --- | --- |
| Google [goog.json](https://www.gstatic.com/ipranges/goog.json) and [cloud.json](https://www.gstatic.com/ipranges/cloud.json) | Google-owned ranges minus customer Google Cloud ranges, following Google's [official method](https://docs.cloud.google.com/vpc/docs/configure-private-google-access#ip-addr-defaults) |
| [Microsoft 365 Worldwide API](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service) | Explicit IP ranges from required `Optimize` / `Allow` endpoint groups; optional, `Default` and URL-only groups are excluded |
| Meta/Facebook [AS32934](https://stat.ripe.net/data/as-overview/data.json?resource=AS32934) via [RIPEstat announced prefixes](https://data.stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes) | Prefixes visible at the returned query end time; previously withdrawn prefixes in the historical window are excluded |
| [Cloudflare DNS](https://developers.cloudflare.com/1.1.1.1/ip-addresses/), [Google Public DNS](https://developers.google.com/speed/public-dns/docs/using), [Quad9](https://quad9.net/service/service-addresses-and-features/) | Primary public resolver destination hosts from official documentation, retained in [source/proxy-ip-extra.list](source/proxy-ip-extra.list) |
| [Parallels Desktop](https://kb.parallels.com/en/128971) | `parallels` domain keyword plus eight exact DNS-observed shared CDN destinations; see the [scope and snapshot](docs/parallels-desktop-proxy.md) |
| [OmniGroup](https://support.omnigroup.com/oss-syncing-on-restricted-networks/) | `omnigroup` domain keyword plus vendor-published `198.151.161.0/24` and `204.128.250.0/24`, with current ARIN and DNS checks; see the [scope and snapshot](docs/omnigroup-proxy.md) |

This is a selected service IP list, not the complement of the CN database.
RIPEstat supplies BGP observations for Meta's ASN rather than a vendor-maintained
product endpoint list. IP rules apply to all destination ports; Microsoft 365's
endpoint-specific port fields are not represented. Shared service addresses can
cover several products, so explicit domain policies precede the IP fallback.

Telegram and Apple ranges are retained in
[source/proxy-ip-extra.list](source/proxy-ip-extra.list), together with the
curated public DNS hosts, the documented Parallels Desktop snapshot and OmniGroup networks. The builder merges equivalent coverage and sorts
IPv4/IPv6 numerically. Adjacent prefixes may collapse without changing their
covered addresses. Maintain custom ranges in
[source/proxy-ip-extra.list](source/proxy-ip-extra.list) rather than editing
generated output. Every curated range must remain covered in both formats.

Both IP pairs are built and published together. Every remote source must provide
minimum IPv4 and IPv6 counts. Invalid schemas, non-public service prefixes,
download failures and failed text/binary comparisons stop publication. Both
outputs use the 80%–125% change guard and a 30,000-rule maximum. Verification
rejects noncanonical IP ranges and missing curated coverage. Cross-set APNIC
overlap is recorded in `metadata/proxy-ip.json` and retained; the example places
the proxy IP fallback before the direct IP fallback.
RIPEstat fingerprints use canonical resource/query/prefix data, excluding request
IDs, server names and processing timings that would otherwise cause empty updates.

## Workflows and snapshots

| Workflow | Trigger | Result |
| --- | --- | --- |
| [Build Merged AdGuard Filters](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/build-filter.yml) | Daily at 05:13 UTC+8; manual | Fetch five AdGuard sources plus portable Qimao/Fanqie reject rules, merge and verify all three reject pairs, then push changed outputs and `metadata/filter.json` |
| [Sync Proxy and Direct Rule Sets](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/sync-tld.yml) | Daily at 05:43 UTC+8; relevant source/tooling changes on `main`; manual | Fetch official IANA JSON, select proxy TLDs and the three mainland direct ccTLDs, rebuild both domain pairs and both companion keyword pairs; update `metadata/tld.json` and `metadata/keywords.json` |
| [Sync Direct and Proxy IP Rule Sets](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/sync-ip.yml) | Daily at 06:13 UTC+8; relevant source/tooling changes on `main`; manual | Validate APNIC and common service IP sources, rebuild both IP pairs and update their manifests |
| [Verify Rule Sets](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/verify-rulesets.yml) | Push to `main`, pull request; manual | Run unit/native tests; check all nine text/binary pairs, parent coverage, canonical IP ranges, curated coverage, ordering and manifests |
| [Publish Immutable Rule-Set Snapshot](https://github.com/RuleSetConfig/RuleSetConfig/actions/workflows/publish-release.yml) | Daily at 16:30 UTC+8; manual | Verify the checked-out commit and publish an immutable daily release |

Scheduled jobs may start later than their configured time. Build, domain/IP sync
and snapshot publication share the `ruleset-publisher` concurrency group.
Each uses `queue: max` to retain up to 100 pending runs while keeping one publisher
active. This prevents a newly queued task from replacing an older pending task;
see [GitHub concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

To run manually, open the workflow under **Actions**, choose **Run workflow** and
select `main`. For a complete refresh, finish **Build** and both **Sync** jobs, then run
**Verify** and **Publish** against the updated branch. Keep `accept_large_change`
unchecked unless an unusual rule-count change has been reviewed.

The builder checks per-source minimum counts, rejects parent-covered and provably redundant companion rules
and guards each partition against a change below 80% or above 125% of its baseline,
with a 300,000-rule maximum per partition. Empty IP/pattern partitions match
nothing; disappearance of a nonempty partition still fails the change guard.
All candidate pairs must pass compilation, round-trip comparison and manifest
checks before publication. The publisher stages only the requested outputs,
rebases onto current `main` and verifies again before pushing.

The domain sync also enforces a minimum count for each upstream, the same
80%–125% output change guard, and a 300,000-entry limit for each generated domain
set. Verification requires exact agreement between the proxy TLD output, explicit
policy and recorded IANA evidence, and exact agreement between the direct output
and the three mainland ccTLD records. The `accept_large_change` manual input bypasses the relative change guard
after review; source floors, the absolute limit and semantic checks still apply.
Unchanged inputs produce identical outputs and no new commit. Repository-source
hashes are checked again after rebasing, so a concurrent selector or keyword-policy change
cannot be published with stale generated coverage.

Actions are pinned to full commit SHAs, and sing-box is pinned and checksum
verified. Each sync uses the repository's `GITHUB_TOKEN` with `contents: write`,
checks out current `main` without persisting credentials, and stages only its
generated pairs and manifests. It runs unit, native and complete pair/manifest
checks before publication: pushes made with `GITHUB_TOKEN` do not trigger another
`push` workflow. See GitHub's [secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
and [workflow trigger documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow#triggering-a-workflow-from-a-workflow).

The `main` branch is mutable. For a fixed version, pin a commit SHA in the raw URLs
or download a [release snapshot](https://github.com/RuleSetConfig/RuleSetConfig/releases).
Tags use **`rulesets-YYYY-MM-DD` with the UTC date**. New snapshots contain
all eighteen `.list` / `.srs` files, the five provenance manifests
(`filter-manifest.json`, `tld-manifest.json`, `keywords-manifest.json`,
`direct-ip-manifest.json`, `proxy-ip-manifest.json`) and `SHA256SUMS`: 24 assets
in total.
An existing daily release is left unchanged; rerunning its
workflow does not replace that snapshot. Historical releases retain the files
from their pinned commits. The release job checks out current `main`
after waiting for the publisher group and binds assets and notes to that actual
checkout revision, even when the workflow event originated from an older commit.

## Maintenance and validation

Lists use deterministic ascending order. Domain sets put TLD suffixes first,
then sort other entries by domain name while preserving the leading-dot meaning.
Pattern rules sort by rule type/value. IP lists use separate IPv4 and IPv6 sections,
IPv4 first, sorted by numeric network address and prefix length. Generators and
verification enforce the same order.

The full verifier requires all nine named pairs and all five named manifests,
including their output inventories, required source fingerprints and compiler
identity. A missing manifest or provenance record is a verification failure.
See the [2026-10-25 deep review](docs/rules-deep-review-2026-10-25.md) for the fixed
baseline, priority relationships and validation evidence.

With sing-box **1.14.2** and `actionlint` in `PATH`, run the existing checks:

```bash
python3 -m unittest discover -s tests -v
python3 tests/native_filter.py
python3 tests/native_optimization.py
python3 scripts/verify-all.py
python3 scripts/sort-rulesets.py --check
actionlint -ignore 'unexpected key "queue" for "concurrency" section'
```

Actionlint 1.7.12 does not yet recognize the documented `concurrency.queue`
field ([upstream report](https://github.com/rhysd/actionlint/issues/746)). The command
above ignores only that diagnostic; the other workflow checks remain active.
Remove the narrow ignore once the installed linter supports the field.

The tests cover upstream source roles, domain-only IP isolation, the 96 reviewed
supplements, audited Surge-only omissions, AND priority, exact/suffix scopes, wildcard boundaries, partition coverage,
CIDR coverage, empty partitions, truncated sources and publication failures.
They also check same-policy keyword pruning, automaton containment, exact character-class
unions, apex-plus-descendant coverage and proxy-over-direct companion pruning
and both README companion-set examples. Native tests verify that the domain list plus
companion keywords has the same matching behavior before and after pruning, including embedded substrings and
cross-policy entries. Cross-set native tests preserve proxy-first routing after
removing fully covered direct entries under proxy domain/keyword priority, while retaining direct parent suffixes
and descendants of exact-only proxy hosts. APNIC tests cover country/status
filtering, record totals, MD5 validation, non-CIDR IPv4 ranges, IPv6 prefix lengths and IP match boundaries.
Proxy IP tests cover Google Cloud subtraction, Microsoft endpoint selection,
active BGP timelines, curated DNS/Telegram/Apple coverage and
partial-prefix boundaries in the compiled binary.

After editing `source/proxy-tld-policy.json`, either IANA selector or
`source/domain-keywords.json`, rebuild both domain pairs, both companion keyword
pairs and their two manifests together. The TLD selections remain complete while
keyword routing is maintained in the companion pairs. With the pinned
compiler in `PATH`:

```bash
set -euo pipefail
python3 scripts/sort-rulesets.py --write
domain_build_dir="$(mktemp -d)"
python3 scripts/sync-domain-sets.py --fetch \
  --source-dir "$domain_build_dir/upstream" \
  --output-dir "$domain_build_dir/candidate"
python3 scripts/build-keyword-sets.py --output-dir "$domain_build_dir/candidate"
for name in PROXY-DOMAIN-SET DIRECT-DOMAIN-SET; do
  python3 scripts/guard-ruleset.py \
    --baseline "$name.list" --candidate "$domain_build_dir/candidate/$name.list" \
    --min-ratio 0.80 --max-ratio 1.25 --max-rules 300000
done
for name in PROXY-DOMAIN-SET DIRECT-DOMAIN-SET PROXY-RULE-SET DIRECT-RULE-SET; do
  cp "$domain_build_dir/candidate/$name.list" "$name.list"
  cp "$domain_build_dir/candidate/$name.srs" "$name.srs"
done
cp "$domain_build_dir/candidate/metadata/tld.json" metadata/tld.json
cp "$domain_build_dir/candidate/metadata/keywords.json" metadata/keywords.json
python3 scripts/verify-all.py
```

To refresh both IP pairs locally with the pinned compiler in `PATH`:

```bash
set -euo pipefail
ip_build_dir="$(mktemp -d)"
python3 scripts/sync-apnic-cn.py --fetch \
  --source-dir "$ip_build_dir/apnic-upstream" \
  --output-dir "$ip_build_dir/candidate"
python3 scripts/sync-proxy-ips.py --fetch \
  --source-dir "$ip_build_dir/proxy-upstream" \
  --output-dir "$ip_build_dir/candidate" \
  --direct-list "$ip_build_dir/candidate/DIRECT-IP-SET.list"
for name in DIRECT-IP-SET PROXY-IP-SET; do
  python3 scripts/guard-ruleset.py --baseline "$name.list" \
    --candidate "$ip_build_dir/candidate/$name.list" \
    --min-ratio 0.80 --max-ratio 1.25 --max-rules 30000
done
for name in DIRECT-IP-SET PROXY-IP-SET; do
  cp "$ip_build_dir/candidate/$name.list" "$name.list"
  cp "$ip_build_dir/candidate/$name.srs" "$name.srs"
done
for name in direct-ip proxy-ip; do
  cp "$ip_build_dir/candidate/metadata/$name.json" "metadata/$name.json"
done
python3 scripts/verify-all.py
```

For reject updates, maintain the generator or supplementary source and dispatch
the build workflow. The three reject pairs and their manifest are generated
outputs; a future build replaces direct edits to those files.

## Repository layout

| Path | Purpose |
| --- | --- |
| `REJECT-*.list`, `REJECT-*.srs` | Three generated reject pairs from the selected upstream roles and local reviewed rules |
| `PROXY-DOMAIN-SET.list` / `.srs`, `DIRECT-DOMAIN-SET.list` / `.srs` | Daily generated proxy/direct domain pairs |
| `DIRECT-IP-SET.list` / `.srs` | Daily generated APNIC CN IPv4/IPv6 direct pair |
| `PROXY-IP-SET.list` / `.srs` | Daily generated common service proxy IPv4/IPv6 pair |
| [source/proxy-tld-policy.json](source/proxy-tld-policy.json), [scripts/iana_direct.py](scripts/iana_direct.py) | IANA proxy TLD policy and the fixed three mainland direct ccTLDs |
| [source/domain-keywords.json](source/domain-keywords.json) | Shared keyword source for companion RULE-SET pairs and domain pruning |
| [source/reject-domain-extra.list](source/reject-domain-extra.list) | Persistent supplementary exact hosts and domain suffixes |
| [source/reject-rule-extra.list](source/reject-rule-extra.list) | Persistent supplementary keywords, wildcards, logical AND and Surge-only STUN blocks |
| [source/reject-ip-extra.list](source/reject-ip-extra.list) | Supplementary HTTPDNS and selected destination IP snapshot |
| [source/proxy-ip-extra.list](source/proxy-ip-extra.list) | Curated DNS, Telegram, Apple, Parallels Desktop and OmniGroup destinations retained in the proxy IP pair |
| `PROXY-RULE-SET.list` / `.srs`, `DIRECT-RULE-SET.list` / `.srs` | Generated companion keyword pairs |
| [scripts/build-keyword-sets.py](scripts/build-keyword-sets.py) | Keyword pair compilation and provenance |
| [metadata/](metadata/) | Five current provenance manifests: source/output hashes, coverage counts and compiler version |
| [.github/workflows/](.github/workflows/) | Build, sync, verification and snapshot publication |
| [.github/actions/setup-sing-box/](.github/actions/setup-sing-box/) | Pinned, checksum-verified compiler installation |
| [scripts/merge-filter.py](scripts/merge-filter.py), [filter_patterns.py](scripts/filter_patterns.py), [filter_domains.py](scripts/filter_domains.py), [filter_ips.py](scripts/filter_ips.py) | Source parsing, scope-preserving conversion, parent pruning and IP coverage |
| [scripts/filter_optimizer.py](scripts/filter_optimizer.py), [glob_optimizer.py](scripts/glob_optimizer.py) | Certified companion-set pruning, bounded glob inclusion and exact character-class union |
| [scripts/sync-domain-sets.py](scripts/sync-domain-sets.py) | Daily official IANA download, both TLD selections, compilation and provenance |
| [scripts/domain_keywords.py](scripts/domain_keywords.py) | Shared keyword validation and coverage matching |
| [scripts/sync-apnic-cn.py](scripts/sync-apnic-cn.py) | APNIC checksum/record validation, CN selection, exact IP conversion and compilation |
| [scripts/sync-proxy-ips.py](scripts/sync-proxy-ips.py), [ip_rulesets.py](scripts/ip_rulesets.py) | Service source selection, Google Cloud subtraction, compilation and provenance |
| [scripts/rule_sorting.py](scripts/rule_sorting.py), [sort-rulesets.py](scripts/sort-rulesets.py) | Shared ordering, sorting and checks |
| [scripts/guard-ruleset.py](scripts/guard-ruleset.py) | Generated rule-count guards |
| [scripts/verify-all.py](scripts/verify-all.py) | Domain compilation, pair/manifest validation, repository-source hash checks and coverage checks |
| [scripts/write-manifest.py](scripts/write-manifest.py) | Deterministic provenance manifests |
| [scripts/publish-rulesets.sh](scripts/publish-rulesets.sh) | Stage selected outputs, rebase, verify and push |
| [tests/](tests/) | Conversion, partition, ordering and publication tests |

## License

Copyright (C) 2026 RuleSetConfig

Repository code is distributed under the [GNU General Public License v3.0](LICENSE).
Upstream data retains its respective project's license.
