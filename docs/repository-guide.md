# Repository structure and publication

## Published and maintained files

| Location | Purpose |
| --- | --- |
| Root-level .list and .srs files | Nine generated text/binary pairs |
| [source/](../source/) | Maintained selection policies, supplementary rules and exclusions |
| [scripts/](../scripts/) | Import, selection, conversion, optimisation and verification |
| [metadata/](../metadata/) | Five source/output provenance manifests |
| [tests/](../tests/) | Unit tests, native matching and optimisation checks |
| [.github/workflows/](../.github/workflows/) | Scheduled generation, verification and Release publication |
| [.github/actions/](../.github/actions/) | Installation of the pinned, checksum-verified compiler |
| [docs/](.) | Current client configuration and this maintenance guide |

Published pairs, maintained inputs, build scripts, tests and provenance
manifests are maintained together. Legacy rejection selection inputs remain
available for the generic builder and its regression fixtures. Historical reviews and raw DNS/network snapshots remain
available in Git history. Current policy is defined by the maintained sources;
current counts and hashes are recorded in the manifests.

## Source ownership

| Input | Responsibility |
| --- | --- |
| [domain-keywords.json](../source/domain-keywords.json) | Maintained keywords and generated hostname selection with declared counts |
| [companion-import.json](../source/companion-import.json) | Pinned community sources, application priorities and ranking policy |
| [ranked-domain-candidates.csv](../source/ranked-domain-candidates.csv) | Reproducible exact-host candidate projection; [attribution](../source/ranked-domain-NOTICE.md) |
| [proxy-tld-policy.json](../source/proxy-tld-policy.json) | Reviewed dedicated and explicitly requested generic proxy TLDs |
| [reject-app-scope.json](../source/reject-app-scope.json) | Application and advertising-platform selection namespaces |
| [reject-domain-set.list](../source/reject-domain-set.list) | Complete published rejection DOMAIN-SET, currently `.data` only |
| [reject-domain-extra.list](../source/reject-domain-extra.list) | Reviewed hostname candidates retained as rule-selection exclusions |
| [reject-rule-set.list](../source/reject-rule-set.list) | Complete published rejection keywords and AND conditions |
| [reject-rule-selection.json](../source/reject-rule-selection.json) | Legacy automatic selection policy for generic builder fixtures |
| [reject-rule-extra.list](../source/reject-rule-extra.list) | Legacy reviewed patterns for generic builder fixtures |
| [reject-domain-exclusions.list](../source/reject-domain-exclusions.list) | Reviewed rejection exclusions |
| [reject-ip-extra.list](../source/reject-ip-extra.list) | Maintained supplementary rejection ranges; [source review](../source/reject-ip-NOTICE.md) |
| [proxy-ip-extra.list](../source/proxy-ip-extra.list) | Maintained supplementary proxy ranges |

Reviewed foreign brand IDNs use explicit Punycode names and must retain matching
IANA owner, country and active delegation evidence. Open-registration IDNs are
not admitted through the brand exception. TLD selection has no numeric target.

Official IANA data supplies both TLD pairs. AdGuard filters 1, 2, 5, 53 and 59 supply
the hostname rejection inputs; only filter 1 contributes upstream IP blocks.
The application selector retains existing rules within explicit namespace roots
and preserves manual supplements. It does not create blocks for catalogue roots.
Upstream Adblock exceptions are audited under the block-wins policy; reviewed
local exclusions are enforced separately. APNIC and the documented service
sources supply the IP routing pairs.

## Source-only rejection domain set

REJECT-DOMAIN-SET publishes exactly the maintained entries in
[reject-domain-set.list](../source/reject-domain-set.list), currently `.data` only.
Its SRS preserves the same apex-and-descendants suffix scope. The published text
contains no generated header. Verification rejects any additional hostname.

The application-selected upstream hostname inventory and reviewed hostname
supplements remain selection exclusions: they are omitted from publication and
are not migrated into REJECT-RULE-SET. Integrity floors still validate those
upstream inputs. Maintained rule publication and IP selection continue separately; pruning uses only
the domain scopes that will actually be published. The audit records the explicit
source-only policy and omitted base counts.

The order of conditions inside each maintained AND is preserved exactly as
written. The first rule uses `ads`, then `zijieapi`; the second uses `misc`, then
`fqnovel`. Semantic comparison remains order-independent.

## Proxy keyword review

The maintained `proxy_keyword_review` in [brand-scope.json](../source/brand-scope.json)
records previous proxy-keyword, pinned proxy-domain or explicitly reviewed official
application-update evidence for every published keyword. Selection follows the supplied brand table and the existing
proxy sources; the explicit direct inventory takes precedence. Unrelated former
keywords are removed. Unsupported aliases and wholly substring-covered keywords
are recorded as omissions, without numeric padding. Each keyword contains at least
five ASCII letters; dotted literals such as `pypi.org`, `bing.com` and `dmit.io`
retain substring semantics. Codex, BBEdit and the Omni applications use their
reviewed provider keywords rather than invented hostname aliases.

## Keyword-only routing companions

PROXY-RULE-SET contains 121 keywords and DIRECT-RULE-SET contains 14 keywords maintained in
[domain-keywords.json](../source/domain-keywords.json). Duplicate `weixin` input
is removed. All former suffix, exact-host and process entries are cleared.
[The import policy](../source/companion-import.json) sets `keyword_only_policies` to both routing policies
so scheduled rejection and TLD builds cannot restore those entries. Literal dots
are supported in keywords: `qq.com` keeps substring semantics, including names
such as `notqq.com` and `qq.com.invalid`.

## Maintained rejection companion

[The complete rejection rule source](../source/reject-rule-set.list) contains
18 distinct DOMAIN-KEYWORD entries and two AND conditions. It includes `douyin`,
uses `ads` with `zijieapi` in the first conjunction, and uses `misc` with `fqnovel`
in the second. Conjunction order does not change matching scope. Duplicate
`dig.bdurl` input and trailing whitespace are removed.

The builder publishes only this source for REJECT-RULE-SET. Previous hostname,
wildcard, keyword and logical rules are replaced; upstream additions and the
legacy source-agreement selector are disabled for this companion. Its SRS uses
the same substring and conjunction semantics. The verifier compares the complete
published inventory with the maintained source and its provenance fingerprint.

## Matching and optimisation

- A bare DOMAIN-SET entry matches one hostname; a leading dot also covers its
  descendants. Keywords match literal substrings, including within DNS labels.
- Routing companion keywords require at least five ASCII letters. Bounded suffixes and exact hosts supply the remaining
  rules in both uncapped routing companions. Declared actual
  counts and current selections are checked against domain-keywords.json.
- Logical AND rules retain conjunction semantics and appear before other
  patterns. The maintained rejection rule source contains only keywords and
  conjunctions; it contains no protocol or User-Agent rules.
- REJECT domain and pattern companions must be loaded together at the same
  policy and matching stage. The optimiser removes a domain or wildcard only
  when retained rules prove its whole matching scope remains covered. Wildcard
  descendants alone do not cover their apex; unsupported syntax fails the build.
- Load both PROXY companions before both DIRECT companions. Explicit domain
  policies precede the IP fallbacks; PROXY IP rules precede DIRECT IP rules.

The builder records optimisation evidence in its Actions artefact. Verification
checks the equivalent-optimisation fixed point and coverage of manual rules.
Keep source selection, equivalent pruning and changes in live behaviour distinct.
Native tests establish matching behaviour, not client connectivity or performance.

## Reviewed rejection IPs

The [reviewed rejection IP supplements](../source/reject-ip-NOTICE.md) include
HTTPDNS destination hosts supported by Sukka and blackmatrix7, plus the retained
maintainer snapshot. The 2026-10-30 review adds four exact public IPv4 hosts.
These supplements are separate from the designated AdGuard base IP source.

## Curated proxy IPs

The proxy supplement preserves reviewed DNS, Telegram, Apple, Claude, Parallels
Desktop and OmniGroup destinations across rebuilds. Its comments retain official
service references; it is not expanded automatically from live DNS.

| Service | Maintained basis |
| --- | --- |
| Claude API and Console | Vendor-published inbound networks 160.79.104.0/23 and 2607:6bc0::/48, verified on 2026-10-30. Outbound MCP ranges and phased-out cloud addresses are excluded. [Official IP reference](https://platform.claude.com/docs/en/api/ip-addresses). |
| Parallels Desktop | Four IPv4 /32 and four IPv6 /128 addresses observed on 2026-10-24 for core .com/.cn service hosts. These are shared Cloudflare edges, not product-exclusive networks. Review changed service answers before replacing the curated addresses. [Official host reference](https://kb.parallels.com/en/128971). |
| OmniGroup | The vendor-published 198.151.161.0/24 and 204.128.250.0/24 networks, recorded on 2026-10-24. Rotating shared CDN download addresses are not pinned. [Official restricted-network guide](https://support.omnigroup.com/oss-syncing-on-restricted-networks/). |

The corresponding domain keywords remain in domain-keywords.json. Keep domain
policies ahead of IP fallbacks, and review vendor guidance when changing these
manual ranges. The original observation date is separate from build timestamps.

## Workflow responsibilities

| Workflow | Function |
| --- | --- |
| build-filter.yml | Generate the three rejection pairs, then reselect and rebuild both routing companions |
| sync-tld.yml | Generate both IANA TLD pairs, then reselect and rebuild both routing companions |
| sync-ip.yml | Generate direct and proxy IP pairs |
| verify-rulesets.yml | Verify committed pairs and source provenance |
| publish-release.yml | Publish and verify the latest snapshot, then remove older Releases |

Publishing workflows share the serial ruleset-publisher queue. Each job records
the current checkout revision and publishes only its designated artefacts.
The rejection and TLD jobs publish the selected companion source, both routing
companion pairs and their manifests in the same commit. No downstream workflow
trigger is required to complete that update. Failed generation, source-integrity
checks or verification prevent publication.

## Provenance and verification

The filter, TLD, keyword, direct-IP and proxy-IP manifests record source identities
and output hashes. The companion manifest also fingerprints both routing
DOMAIN-SET lists and both hostname rejection lists used during selection; stale
coverage inputs fail verification. Verification requires all nine pairs and five
manifests.
Generated sources and their consumers must be updated together. Regenerate
affected artefacts after changing maintained rules or generator output. Editorial
changes to fingerprinted sources also require refreshed source digests.

Use Python 3.11 or later and Rust 1.85 or later. Run the existing checks with
the pinned sing-box compiler on PATH:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/verify-all.py
python3 tests/native_filter.py
python3 tests/native_optimization.py
```

Local Python caches and macOS .DS_Store files are ignored. Use Git history to
retrieve retired documents rather than maintaining duplicate snapshot files.

## Single-Release retention

Release tags include the UTC date and the first 12 characters of the recorded
checkout revision. Repeating the same snapshot reuses its existing Release.

Before historical Releases are removed, the workflow:

1. verifies all committed pairs and manifests;
2. uploads the 24 required assets;
3. downloads them and compares SHA256SUMS with the local snapshot;
4. checks every downloaded asset and its remote inventory;
5. retains the newest verified published Release and removes older published Releases.

Drafts are excluded from automatic removal. The retention step does not delete
Git tags or rewrite commit history. Publication or verification failures leave
the previous Releases available.

## Routing companion selection

Both routing companions publish only their complete maintained keyword lists:
121 proxy keywords and 14 direct keywords. Hostname and process selections are
empty. The importer enforces keyword-only publication on every scheduled rebuild.
The 73-group / 35-app catalogue retains the 135 current routing keywords; it cannot
create additional published rules. Keywords retain substring semantics, including
literal dots. The rejection companion follows its separate complete keyword/AND
source.

[companion-import.json](../source/companion-import.json) pins the Loyalsoldier
proxy/direct lists and the v2fly archive by commit, byte count and SHA-256.
Application families include OpenAI, Anthropic/Claude, Mozilla/Firefox,
Telegram, Google, Microsoft, Apple and Tencent. Seeds and reviewed vendor suffixes
take precedence over application families; application families precede the remaining community pool. Equal
priority cross-policy conflicts are omitted. Coverage supplied by either
DOMAIN-SET, same-policy keywords or retained parents cannot consume extra slots.
Wholly blocked scopes are excluded; blocked descendants retain REJECT priority.

A checked-in [rank/hostname projection](../source/ranked-domain-candidates.csv)
can supply existing exact hostnames within the reviewed brand namespaces. It
does not supply unrelated rules to reach a target count.
It retains the first 250,000 rows of the Majestic Million, with the full download
fingerprint and date recorded in the import policy. These ranks measure
referring subnets, not visits, local application use, geographic ownership or
blocking efficacy. All known direct scopes and current rejection coverage are
excluded before selecting proxy exact supplements.
Ranked proxy hostnames are never promoted to suffixes. Direct suffixes are
refined to second-level domains where that does not swallow a public suffix or
known proxy scope; otherwise their original scope remains. The pinned
[source Public Suffix List](../source/public-suffix-list.dat), distributed under
MPL-2.0, protects public registration boundaries such as cn.com and co.uk.
Mainland TLD coverage remains in DIRECT-DOMAIN-SET and is not duplicated.
The direct list orders exact hosts first, suffixes by descending label count
and ascending name next, and keywords last. Priority does not depend on source
input order.

The checked-in candidate projection makes selection reproducible after the daily
upstream ranking changes. The installed application snapshot and reviewed traffic-brand profile supply
brand priority at whole DNS-label boundaries. Installed brands rank before
observed services; other reviewed application families follow, then available referring-subnet rank and SHA-256 ordering for unranked
suffixes. Exact proxy supplements apply the same installed-brand priority before
source-host and ranking order. The importer never adds a namespace root merely
because an application from that brand is installed.

Both the rejection and TLD jobs rebuild the maintained selection. To check the
committed selection against its pinned sources and current coverage, run:

```sh
python3 scripts/import-companion-domains.py --fetch \
  --source-dir /tmp/companion-inputs --check --audit /tmp/companion-audit.json
```

For an isolated refresh, place any newly generated TLD pairs and their manifest,
or new rejection hostname lists, in the candidate directory first. Unchanged
coverage files come from the current repository. Then run:

```sh
python3 scripts/refresh-companions.py --fetch \
  --source-dir /tmp/companion-inputs --output-dir /tmp/companion-candidate
```

The refresh command verifies the candidate TLD pair, reselects against candidate
coverage, validates the projection with Rust and compiles both pairs. It writes
the selected source, both pairs, refreshed keyword/TLD manifests and a complete
selection-change audit only after construction succeeds. The repository remains
unchanged until the workflow stages the successful candidate. Publish those files
together with the coverage update and run full repository verification.

Direct candidates are refined before applying the reviewed brand scope. Exact
proxy supplements preserve their upstream scope. Actual source and published
counts are audited alongside complete inventory/SRS parity; neither list is
truncated or padded to satisfy a numeric target. Proxy exact scopes are never widened. Pinned source
revisions and ranking rows remain unchanged unless their import policy is reviewed.

Loyalsoldier/surge-rules uses GPL-3.0. The v2fly MIT notice is retained in
[companion-upstream-LICENSE.txt](../source/companion-upstream-LICENSE.txt).
Majestic's rank/hostname data retains CC BY 3.0 attribution in
[ranked-domain-NOTICE.md](../source/ranked-domain-NOTICE.md), with attribution
also included in the generated lists. Repository code remains under GPL-3.0.

## Rust routing construction

[ruleset-core](../rust/ruleset-core/src/main.rs) parses the maintained routing
policy, validates keywords, DNS-label boundaries, DOMAIN-SET and parent coverage,
cross-policy overlaps and exact counts, then writes both Surge lists and sing-box
JSON projections. Exact hosts retain exact scope. Input schemas 1 through 4 remain
supported with integer schema identifiers. Schema 4 adds explicit process-name
inventories to both routing policies. Keywords identical to or containing an
opposite-policy keyword are rejected. All validation completes before output
lists are written.

[scripts/rust_core.py](../scripts/rust_core.py) builds the release binary with
Cargo.lock and invokes it from the existing build-keyword-sets.py entry point.
Python retains source acquisition/selection, the pinned sing-box compiler and
provenance publication. REJECT selection has not been migrated to Rust.
Rust 1.85 or later and Cargo are required; compiled target files are ignored.

Rust unit tests exercise hostname boundaries and invalid inputs. Independent
Python policy checks and native sing-box matching remain in CI. A golden check
requires the committed lists to match the Rust projection byte for byte. The
initial migration also verified byte-identical SRS outputs, preserving the
already-tested routing behaviour. Manifests fingerprint the Rust source, package
manifest, dependency lockfile, Python bridge, builder and refresh orchestration.

## Lossless scope compaction

The original source inventory remains authoritative. Published mixed domain
lists may use finite character classes to combine existing exact or suffix
rules. No parent, keyword or arbitrary wildcard is inferred. Both entry count
and byte count must decrease; otherwise the original rules remain.

Each generated group has a comment of the form
`#@scope-v1 exact MASK` or `#@scope-v1 suffix MASK`. The exact form requires one
`DOMAIN-WILDCARD` row. The suffix form requires both `MASK` and `*.MASK` rows, so the
apex and every descendant retain the original scope. Every cell of a class
product must already exist in the source inventory. A sparse product is never
completed by inference.

The reader validates each complete certificate and reconstructs all original
rules before source checks, policy checks and list/SRS comparison. Missing
rows, added class members and mismatched comments fail verification. The
builder compares the full reconstructed inventory, not just samples.
Certificates are comments to Surge; its [documented wildcard classes](https://manual.nssurge.com/rules/domain.html)
implement the finite union. SRS JSON keeps the original domain and suffix arrays, so
existing trie-based matching and SRS bytes remain unchanged for an unchanged
source selection.

Routing selections remain uncapped; the rejection companion retains its complete
maintained source. Finite compaction never adds missing hostnames or matching scope. Manifest
`scope_compaction` records show source and published counts, bytes and identical
before/after inventory digests. Existing exclusions, process rules, logical
conjunctions and Surge-only entries remain in effect.

## Traffic-observed brand priorities

[The reviewed traffic profile](../source/traffic-brand-priority.json) records
44 brand/service groups from the supplied export. Namespace associations cite
the pinned v2fly brand files or official service pages. The raw CSV, per-host
policies, request counts and volumes are not committed. Unknown domains are
not assigned invented ownership. Shared CDN/cloud references stay exact.

These observations rank already eligible source rules. They do not add base
advertising blocks, infer a new keyword or widen an exact host to a suffix.
Twelve reviewed service portals receive exact-host protection during reject
selection; their advertising children remain subject to the ordinary support
and exception checks. Verification also rejects a release that blocks one of
those exact functional hosts through another reject companion or pattern.
