# Surge and sing-box Rule Sets

Nine maintained rule-set pairs for Surge and sing-box. Each pair provides
equivalent portable matching rules in Surge text and sing-box format version 5.

## Downloads

| Rule set | Scope | Surge text | sing-box |
| --- | --- | --- | --- |
| REJECT-DOMAIN-SET | Maintained `.data` suffix only | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.srs) |
| REJECT-RULE-SET | Maintained keyword and AND rules | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.srs) |
| REJECT-IP-SET | Selected destination IPv4 and IPv6 ranges | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.srs) |
| PROXY-DOMAIN-SET | IANA country-code and reviewed TLDs | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.srs) |
| PROXY-RULE-SET | 121 source-supported proxy keywords only | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.srs) |
| PROXY-IP-SET | Maintained service and destination ranges | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.srs) |
| DIRECT-DOMAIN-SET | Mainland country-code TLDs | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.srs) |
| DIRECT-RULE-SET | Fourteen maintained direct keywords only | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.srs) |
| DIRECT-IP-SET | APNIC mainland China IPv4 and IPv6 allocations | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.srs) |

## Configuration

The Surge fragment below uses named rule sets and a 12-hour resource update
interval. The rejection group contains domain matching rules and the preserved
logical AND conditions.
`SYSTEM` and `LAN` are built-in sets; `SYSTEM_SET` and `SYSTEM_IP` are existing
local exception sets. `PROXY` denotes the existing proxy policy. Keep those
local definitions when adding this fragment to a profile.

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

The six named groups reference all nine published resources.
sing-box requires version 1.14.0 or later. [Client configuration](docs/client-configuration.md)
provides an alternative direct-URL Surge fragment, the complete sing-box route
fragment and DNS requirements.

## Maintained scope

- **Rejection:** the domain partition publishes only `.data`, maintained in
  [source/reject-domain-set.list](source/reject-domain-set.list). The rule
  companion publishes exactly the 18 keywords and two AND conditions in
  [source/reject-rule-set.list](source/reject-rule-set.list), including `douyin`.
  Previous hostname and pattern rules are removed; automatic upstream additions
  are disabled for these two companions. Filter 1 and the reviewed supplementary
  ranges continue to supply the separate IP partition.
- **Domain routing:** IANA country-code TLDs and reviewed dedicated TLDs, with
  mainland country-code domains assigned to direct routing. The maintained
  policy records the reviewed generic exceptions and delegation requirements.
  TLD selection has no numeric target.
- **Routing companions:** PROXY publishes exactly 121 keywords and DIRECT
  exactly 14 keywords from [domain-keywords.json](source/domain-keywords.json).
  Both are keyword-only: previous hostname and process rules are removed, and
  scheduled imports cannot add them back. Dots in keywords remain literal
  substring characters, including `qq.com` and `amap.com`.
- **IP routing:** APNIC mainland China allocations and maintained proxy service
  ranges, represented as canonical IPv4 and IPv6 networks.

[Selection and provenance](docs/repository-guide.md) describe the maintained
sources, brand scope, source licences, exclusions and overlap checks.
Keywords use substring matching. Bare DOMAIN-SET entries are exact matches;
a leading dot includes the apex and descendants.

## Reviewed companion boundary

The PROXY and DIRECT companions publish the complete maintained keyword
inventories, with no automatic hostname additions. The REJECT companion follows
its complete maintained keyword/AND source. The source and generated text retain
the requested order inside AND conditions. The catalogues in
source/brand-scope.json still describe 73 reviewed groups and 35 observed apps,
with the 135 current routing keywords.

## Installed application brands

The [reviewed namespace policy](source/reject-app-scope.json) records a macOS
snapshot of 35 application bundles in 14 brand families, observed on
7 November 2026. Apple, Microsoft, Tencent, OpenAI, Mozilla and the other
installed vendors supply the primary selection scope.
Google is prioritised as a traffic-observed service.

The [traffic brand profile](source/traffic-brand-priority.json) adds 44 reviewed
brand/service groups from the supplied export. Installed brands rank first,
observed services next, followed by the other reviewed application namespaces. The raw
export, per-host policies and traffic volumes remain outside the repository.
Shared cloud/CDN references keep exact-host boundaries. Twelve reviewed
functional service hosts are protected as exact names; advertising children
remain eligible when their existing upstream scopes meet the support policy.
Traffic observations cannot create base advertising blocks or new matching rules.

Brand priority matches DNS-label boundaries. It never creates a brand-wide
block, a new keyword or a broader suffix in the routing companions. The rejection
companion instead follows its explicit keyword/AND source.
Unrelated generic candidates are omitted. There is no minimum or target rule
count and no padding. Installation does not establish usage, geographical
ownership or a blocking rate. This brand-focused selection reduces general
coverage compared with the previous larger inventories.
The recorded snapshot is reused in CI and must be reviewed when applications
change; CI does not scan a developer's or runner's installed applications.

## Lossless text compaction

The generator combines only complete, finite hostname combinations. A character class is emitted only when expanding it reconstructs
the exact original inventory. Suffix groups retain both the apex and every
descendant; exact groups retain apex-only scope. Keywords and logical rules retain their original scope.

Compaction must reduce both rule entries and bytes while reconstructing the
complete selected inventory. Checked comment certificates
make the transformation reversible and fail closed if a class or required row
is changed. SRS compilation retains the original indexed domain inventories,
so text compaction does not introduce additional regex matching into sing-box.
[Compaction and verification](docs/repository-guide.md#lossless-scope-compaction)
describe the representation and safety checks.

## Ordering

All published lists and local rule-list sources use deterministic ordering:

- DOMAIN-SET lists place TLD suffixes first, then order hostnames by name.
- DIRECT-RULE-SET prioritises exact hosts, then suffixes from more to fewer DNS
  labels, then finite wildcard groups and keywords. Names ascend within the same type and specificity.
- Other mixed RULE-SET lists group logical AND, keyword, suffix, exact-host,
  wildcard, protocol and User-Agent rules; entries ascend within each type.
- IP lists place IPv4 before IPv6, then sort by numeric network address and prefix length.

Comments and rule scopes are retained. This ordering applies inside each list;
the client references above retain their policy priority. Generators emit this
order, and repository verification rejects an unordered list.

## Maintenance

Edit the maintained inputs in [source/](source/). Scheduled workflows regenerate
the published lists, binaries and five provenance manifests in [metadata/](metadata/).
Do not edit generated artefacts directly.

Builds require Python 3.11 or later, Rust 1.85 or later and Cargo. Routing
companion projection uses Rust with locked dependencies. Python orchestrates source imports, SRS compilation and
provenance. Rejection selection remains in the existing Python pipeline. TLD
and rejection builds reselect both routing companions against candidate coverage
before publishing their rules, maintained selection and manifests together.

```sh
cargo test --release --locked --manifest-path rust/ruleset-core/Cargo.toml
python3 -m unittest discover -s tests -v
python3 scripts/sort-rulesets.py --check
python3 scripts/verify-all.py
```

Validation covers all nine list/SRS pairs, source and output hashes, deterministic
ordering, exclusions and equivalent optimisation. CI additionally checks native
sing-box matching with the pinned 1.14.2 compiler.

## Releases

[The latest Release](https://github.com/RuleSetConfig/RuleSetConfig/releases/latest)
contains 18 rule files, five provenance manifests and SHA256SUMS.
Only the latest published Release is retained. Uploaded assets are downloaded
and verified before older Releases and their assets are removed. Existing Git
commits and tags remain available; commit-specific raw URLs provide fixed references.

## Repository guide

- [Client configuration](docs/client-configuration.md)
- [Repository structure and publication](docs/repository-guide.md)
- [GNU GPL v3 licence](LICENSE)

Repository-maintained prose, comments and publication messages use formal British
English. Technical identifiers, source records and the original licence text
retain their required spelling.
