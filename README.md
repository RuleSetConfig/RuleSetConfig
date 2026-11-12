# Surge and sing-box Rule Sets

Nine maintained rule-set pairs for rejection, proxy routing and direct routing.
Each pair contains a Surge text list and a sing-box binary with equivalent
portable matching scope. The files supply matching rules; the client profile
assigns the rejection action or outbound policy.

## Downloads

| Rule set | Scope | Surge text | sing-box |
| --- | --- | --- | --- |
| REJECT-DOMAIN-SET | Maintained `.data` suffix only | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.srs) |
| REJECT-RULE-SET | Maintained exact hosts, suffixes, keywords and AND rules | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.srs) |
| REJECT-IP-SET | Selected destination IPv4 and IPv6 ranges | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.srs) |
| PROXY-DOMAIN-SET | IANA country-code and reviewed TLDs | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.srs) |
| PROXY-RULE-SET | Maintained source-supported proxy keywords | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.srs) |
| PROXY-IP-SET | Maintained service and destination ranges | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.srs) |
| DIRECT-DOMAIN-SET | Mainland country-code TLDs | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.srs) |
| DIRECT-RULE-SET | Maintained direct keywords | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.srs) |
| DIRECT-IP-SET | APNIC mainland China IPv4 and IPv6 allocations | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.srs) |

These URLs track `main`. For a verified snapshot with checksums, use the
[latest Release](https://github.com/RuleSetConfig/RuleSetConfig/releases/latest).
The [provenance manifests](metadata/) record the generated counts, source
fingerprints and output hashes.

### Formats and compatibility

- Load `*-DOMAIN-SET.list` through Surge `DOMAIN-SET`. A bare hostname matches
  exactly; a leading dot matches the apex and its descendants.
- Load `*-RULE-SET.list` and `*-IP-SET.list` through Surge `RULE-SET`. `IP-SET`
  is the repository's file naming convention.
- Subscribe to `.srs` files as remote binary rule sets in sing-box. They use
  [format version 5](https://sing-box.sagernet.org/configuration/rule-set/source-format/),
  which requires sing-box 1.14.0 or later. Builds and native checks pin 1.14.2.
- `DOMAIN-KEYWORD` matches a substring. Dots remain literal characters:
  `qq.com` can also match `notqq.com` and `qq.com.invalid`. A dotted keyword
  retains keyword semantics rather than becoming a suffix rule.

## Configuration

The Surge fragment below references all nine resources through six named groups,
with a 12-hour resource update interval. Nested rule-set references require
[Surge Mac 6.9.0 or iOS 5.22.0 or later](https://manual.nssurge.com/rules/ruleset.html).

`SYSTEM` and `LAN` are built-in sets. `SYSTEM_SET` and `SYSTEM_IP` refer to
existing local exception sets; keep their definitions in the profile.
`PROXY` refers to an existing proxy policy. This fragment preserves the
local exception and matching order; it forms part of a complete profile.

```ini
[Rule]
RULE-SET,SYSTEM,PROXY,extended-matching
RULE-SET,SYSTEM_SET,DIRECT,extended-matching
RULE-SET,REJECT_SET,REJECT,extended-matching
RULE-SET,PROXY_SET,PROXY,extended-matching
RULE-SET,DIRECT_SET,DIRECT,extended-matching
RULE-SET,SYSTEM_IP,DIRECT,no-resolve
RULE-SET,REJECT_IP,REJECT,pre-matching,no-resolve
RULE-SET,PROXY_IP,PROXY,no-resolve
RULE-SET,DIRECT_IP,DIRECT,no-resolve
OR,((RULE-SET,LAN),(IP-CIDR6,::/64)),DIRECT
FINAL,PROXY

[Ruleset REJECT_SET]
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list,update-interval=43200
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list,update-interval=43200

[Ruleset PROXY_SET]
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.list,update-interval=43200
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.list,update-interval=43200

[Ruleset DIRECT_SET]
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.list,update-interval=43200
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.list,update-interval=43200

[Ruleset REJECT_IP]
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list,update-interval=43200

[Ruleset PROXY_IP]
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.list,update-interval=43200

[Ruleset DIRECT_IP]
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.list,update-interval=43200
```

Keep the PROXY domain companions before the DIRECT domain companions, and
PROXY IP matching before DIRECT IP matching. Rejection IP ranges can overlap
mainland allocations, so their rejection priority must also be retained.

[Client configuration](docs/client-configuration.md) provides a direct-URL Surge
alternative and the sing-box route fragment with all nine subscriptions. The
sing-box example uses existing `proxy`, `direct` and `dns-real` tags. Resolve
destination domains to real addresses before destination-IP routing, as shown
there. Its explicit STUN rejection is a client policy separate from these lists.

## Published scope

### Rejection

[reject-domain-set.list](source/reject-domain-set.list) is the complete source for
REJECT-DOMAIN-SET and currently contains only `.data`. The generated list retains
that content without a header.

[reject-rule-set.list](source/reject-rule-set.list) is the complete source for
REJECT-RULE-SET: maintained exact hostnames, domain suffixes, keywords and
logical AND conditions. Exact hostnames use literal DOMAIN-WILDCARD entries and
do not cover their descendants. Suffixes preserve hostname boundaries; for example, e.qq.com does
not match qzone.qq.com or live.qq.com. Each AND requires both keyword
conditions to match. The source's condition order is
preserved in the generated text, while semantic verification treats equivalent
AND orderings alike.

The AdGuard import continues to validate seven upstream lists and audit candidate
rules. The maintained sources above determine the published domain and rule
companions; upstream hostname inventories are omitted from those outputs.
Only HostlistsRegistry filter 1 supplies upstream rejection IPs. Reviewed
[IP supplements](source/reject-ip-extra.list) are merged into REJECT-IP-SET;
[the review notice](source/reject-ip-NOTICE.md) records their scope and attribution.
Upstream Adblock exceptions are audited under the block-wins policy, with
[reviewed local exclusions](source/reject-domain-exclusions.list) enforced
separately. The lists contain portable rules; no MITM, rewrite or script setup
is required by these subscriptions.

### Domain routing

The two routing DOMAIN-SETs are generated from official IANA root-zone data.
DIRECT selects `.cn`, `.xn--fiqs8s` and `.xn--fiqz9s`. PROXY selects active
country-code TLDs outside that direct set, together with the dedicated and
generic exceptions in [proxy-tld-policy.json](source/proxy-tld-policy.json).
Selection checks registry and delegation evidence and has no numeric target.
These are maintained namespace policies; TLD registration does not establish
the location of an individual service or server.

PROXY-RULE-SET and DIRECT-RULE-SET publish the complete keyword inventories in
[domain-keywords.json](source/domain-keywords.json). Both policies are locked to
keywords by [companion-import.json](source/companion-import.json), so scheduled
imports cannot restore hostname or process rules. Routing keywords must be
lowercase, unique and contain at least five ASCII letters; dotted forms are
allowed. Validation checks redundant coverage and cross-policy conflicts.

[brand-scope.json](source/brand-scope.json) records the reviewed brand catalogue
and per-keyword proxy evidence: previous maintained keywords, pinned proxy-domain
records or explicitly reviewed official update information. The installed-app
and traffic profiles document source review and selection context. CI reuses
these maintained records rather than inspecting the runner's installed apps.
The generic hostname selectors and compaction code retain regression coverage.
Legacy pattern samples belong in [tests/fixtures/](tests/fixtures/); the current
routing companions use the maintained keyword inventories without ranking data,
public-suffix refinement or count padding.

### Destination-IP routing

DIRECT-IP-SET uses APNIC records for country `CN` with `allocated` or `assigned`
status, covering IPv4 and IPv6. Downloads are checked against APNIC's accompanying
checksum before parsing and canonical network merging.

PROXY-IP-SET combines Google service ranges (`goog.json` minus `cloud.json`),
required Microsoft 365 `Optimize`/`Allow` endpoint ranges, active Meta AS32934
announcements from RIPEstat, and
[reviewed supplementary ranges](source/proxy-ip-extra.list). Its source selection
and overlap with the current DIRECT IP candidate are recorded in
[proxy-ip.json](metadata/proxy-ip.json). This is a selected service inventory;
it does not enumerate every address outside mainland China. Allocation and
announcement records describe source membership rather than measured reachability.

## Repository map and provenance

| Location | Responsibility |
| --- | --- |
| Root `.list` and `.srs` files | Nine generated text/binary pairs for client subscriptions |
| [source/](source/) | Maintained rules, selection policies, review evidence, pinned input records and data notices |
| [scripts/](scripts/) | Fetching, selection, generation, format conversion, ordering, validation and publication |
| [rust/ruleset-core/](rust/ruleset-core/) | Locked Rust routing projection invoked by the Python orchestration |
| [metadata/](metadata/) | Five deterministic source/output provenance manifests |
| [tests/](tests/) | Unit tests, native sing-box matching and isolated legacy fixtures |
| [.github/workflows/](.github/workflows/) | Scheduled generation, PR verification and Release publication |
| [.github/actions/setup-sing-box/](.github/actions/setup-sing-box/) | Installation of the pinned, checksum-verified compiler |
| [docs/](docs/) | Client configuration and detailed implementation notes |

Each manifest follows the inputs and outputs of one generation family:

| Manifest | Maintained inputs and upstream data | Published pairs |
| --- | --- | --- |
| [filter.json](metadata/filter.json) | Fixed rejection sources, local exclusions and supplements, AdGuard HostlistsRegistry filters 1, 2, 5, 27, 34, 53 and 59 | Three REJECT pairs |
| [tld.json](metadata/tld.json) | Official IANA registry and delegation data, reviewed proxy TLD policy | PROXY and DIRECT DOMAIN-SETs |
| [keywords.json](metadata/keywords.json) | Maintained keywords, brand review and pinned companion-source policy | PROXY and DIRECT RULE-SETs |
| [direct-ip.json](metadata/direct-ip.json) | APNIC delegated statistics and official checksum | DIRECT-IP-SET |
| [proxy-ip.json](metadata/proxy-ip.json) | Google, Microsoft 365, RIPEstat, proxy supplements and the DIRECT IP candidate | PROXY-IP-SET |

The pinned community inputs in the companion policy retain revision, size and
SHA-256 records. Retired candidate datasets and their notices remain available
in Git history. Application snapshots and source membership document review
context; they do not establish local usage, endpoint ownership or a blocking rate.
[The repository guide](docs/repository-guide.md) describes the
selection machinery, scope certificates and historical selection policies in
greater detail; the published scope above identifies the active policies.

## Automated updates

All times below are configured daily schedules. Actual start times depend on
GitHub Actions scheduling.

| Workflow | UTC | UTC+8 | Responsibility |
| --- | --- | --- | --- |
| [Build Merged AdGuard Filters](.github/workflows/build-filter.yml) | 21:13 | 05:13 next day | Build the three REJECT pairs and refresh both routing keyword companions |
| [Sync Proxy and Direct Rule Sets](.github/workflows/sync-tld.yml) | 21:43 | 05:43 next day | Refresh IANA TLD pairs and both routing keyword companions |
| [Sync Direct and Proxy IP Rule Sets](.github/workflows/sync-ip.yml) | 22:13 | 06:13 next day | Build DIRECT IPs, then audit and build PROXY IPs against that candidate |
| [Publish Latest Verified Rule-Set Snapshot](.github/workflows/publish-release.yml) | 08:30 | 16:30 | Verify a `main` snapshot, publish and verify Release assets, then prune older Releases |

[Verify Rule Sets](.github/workflows/verify-rulesets.yml) runs on pull requests,
`main` pushes and manual dispatch. TLD and IP generation also run on the
relevant source/code pushes listed in their workflows; the AdGuard build and
Release publication run on schedule or manual dispatch.

The publishing workflows share a serial queue. Generators build isolated
candidates, check unusual count changes, compile and validate associated pairs,
and publish their maintained selection and manifests together. The shared
[publisher](scripts/publish-rulesets.sh) rebases onto current `main` and verifies
the resulting tree again before pushing. Manual acceptance of a large count
change bypasses only that size guard; semantic validation still applies.

## Maintenance and validation

Edit the authoritative inputs in `source/`, then regenerate every affected
`.list`, `.srs` and manifest together. Keyword changes also need the matching
brand scope and review evidence. Use the relevant workflow's commands to build
isolated candidates and review the resulting diff before publication.

Local checks require Python 3.11 or later, Rust 1.85 or later with Cargo, and the
pinned sing-box 1.14.2 executable on `PATH`. Dependency versions are locked in
[Cargo.lock](rust/ruleset-core/Cargo.lock). The core checks are:

```sh
cargo test --release --locked --manifest-path rust/ruleset-core/Cargo.toml
python3 -m unittest discover -s tests -v
python3 scripts/sort-rulesets.py --check
python3 scripts/verify-all.py
```

Verification checks all nine text/binary pairs, SRS version 5, source and output
hashes, ordering, maintained scope, exclusions and equivalent pruning. Run
`python3 scripts/sort-rulesets.py --write` to apply the canonical list ordering;
refresh affected provenance after any source or generated-file changes. Ordering
is deterministic: TLDs precede other domain entries, rule rows are
grouped by type and name, and IPv4 precedes IPv6 in numeric network order.
Condition order inside maintained AND rules is preserved. The README's effective
Surge references and PROXY-before-DIRECT companion priority are also tested.

CI additionally runs Rust formatting and Clippy checks and these native tests
with the pinned sing-box core:

```sh
python3 tests/native_filter.py
python3 tests/native_optimization.py
python3 tests/native_scope_compaction.py
python3 tests/native_brand_scope.py
python3 tests/native_brand_boundary.py
```

Native matching checks establish rule behaviour in the tested core; they do not
measure live service availability or network performance. The generic parser
and optimisation fixtures cover rule types beyond those currently published.

## Verified Releases

[The latest Release](https://github.com/RuleSetConfig/RuleSetConfig/releases/latest)
contains 18 rule files, five provenance manifests and `SHA256SUMS` (24 assets).
Each Release records the checked-out commit in a
`rulesets-YYYY-MM-DD-<12-character-commit>` tag. It is a fixed snapshot; `main`
subscription URLs can advance before the next Release is published.

Assets are downloaded and checked after upload. Only after successful
verification are older published Releases and their assets removed. The newest
published Release is retained; draft Releases, Git commits and tags are preserved.
For a fixed subscription reference, replace `main` in a raw URL with the full
commit SHA recorded by the Release.

## Documentation and licences

- [Client configuration](docs/client-configuration.md)
- [Repository structure, selection and publication](docs/repository-guide.md)
- [Repository code licence: GNU GPL v3](LICENSE)
- [Companion-source licence notice](source/companion-upstream-LICENSE.txt)
- [Rejection IP source attribution](source/reject-ip-NOTICE.md)

Third-party data and test fixtures retain their upstream licences and attribution.
Repository-maintained prose, comments and publication messages use formal British
English. Technical identifiers, source records and original licence text retain
their required spelling.
