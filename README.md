# Surge and sing-box Rule Sets

Nine maintained rule-set pairs for Surge and sing-box. Each pair provides
equivalent portable matching rules in Surge text and sing-box format version 5.

## Downloads

| Rule set | Scope | Surge text | sing-box |
| --- | --- | --- | --- |
| REJECT-DOMAIN-SET | Selected advertising and telemetry domains | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.srs) |
| REJECT-RULE-SET | 100,000 selected hostname, pattern and Surge-only rules | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.srs) |
| REJECT-IP-SET | Selected destination IPv4 and IPv6 ranges | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.srs) |
| PROXY-DOMAIN-SET | IANA country-code and reviewed TLDs | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.srs) |
| PROXY-RULE-SET | 100,000 maintained proxy domain rules | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.srs) |
| PROXY-IP-SET | Maintained service and destination ranges | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.srs) |
| DIRECT-DOMAIN-SET | Mainland country-code TLDs | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.srs) |
| DIRECT-RULE-SET | 100,000 maintained direct domain rules | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.srs) |
| DIRECT-IP-SET | APNIC mainland China IPv4 and IPv6 allocations | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.srs) |

## Configuration

The Surge fragment below follows the local profile's named-rule-set layout,
including its rule order, matching options and 12-hour resource update interval.
`SYSTEM` and `LAN` are built-in sets; `SYSTEM_SET` and `SYSTEM_IP` are existing
local exception sets. `PROXY` denotes the existing proxy policy. Keep those
local definitions when adding this fragment to a profile.

```ini
[Rule]
RULE-SET,SYSTEM,PROXY,extended-matching
RULE-SET,SYSTEM_SET,DIRECT,extended-matching
RULE-SET,REJECT_SET,REJECT,pre-matching,extended-matching
RULE-SET,PROXY_SET,PROXY,extended-matching
RULE-SET,DIRECT_SET,DIRECT,extended-matching
RULE-SET,SYSTEM_IP,DIRECT,no-resolve
RULE-SET,REJECT_IP,REJECT,pre-matching,no-resolve
RULE-SET,PROXY_IP,PROXY,no-resolve
RULE-SET,DIRECT_IP,DIRECT,no-resolve
OR,((RULE-SET,LAN),(IP-CIDR6,::/64)),DIRECT
FINAL,PROXY

[Ruleset REJECT_SET]
PROTOCOL,STUN
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

The six named groups reference all nine published resources. The explicit
STUN entry and matching options are reproduced from the local deployment.
sing-box requires version 1.14.0 or later. [Client configuration](docs/client-configuration.md)
provides an alternative direct-URL Surge fragment, the complete sing-box route
fragment, DNS requirements and Surge-only matching limitations.

## Maintained scope

- **Rejection:** advertising and telemetry rules selected from maintained registry
  filters and reviewed local sources. The rule companion contains exactly
  100,000 non-comment entries. New hostname additions require matching-scope
  support from at least two lists. Application rules and shared advertising
  platforms are reviewed separately; list agreement is not a measured usage or
  blocking rate. IP imports use the designated IP-capable source only.
- **Domain routing:** IANA country-code TLDs and reviewed dedicated TLDs, with
  mainland country-code domains assigned to direct routing. The maintained
  policy records the reviewed generic exceptions and delegation requirements.
- **Routing companions:** exactly 100,000 proxy rules and 100,000 direct rules,
  retaining reviewed keywords and precise hostname scopes. Pinned community
  sources supply suffix rules, with application and vendor domains prioritised.
  Ranked hostnames supply exact proxy matches after known direct and rejection
  scopes are excluded. Referring-subnet ranks measure neither local usage nor
  geographic ownership.
- **IP routing:** APNIC mainland China allocations and maintained proxy service
  ranges, represented as canonical IPv4 and IPv6 networks.

[Selection and provenance](docs/repository-guide.md) describe the maintained
sources, fixed budgets, source licences, exclusions and overlap checks.
Keywords use substring matching. Bare DOMAIN-SET entries are exact matches;
a leading dot includes the apex and descendants.

## Ordering

All published lists and local rule-list sources use deterministic ascending order:

- DOMAIN-SET lists place TLD suffixes first, then order hostnames by name.
- Mixed RULE-SET lists group logical AND, keyword, suffix, exact-host, wildcard,
  protocol and User-Agent rules; entries ascend within each type.
- IP lists place IPv4 before IPv6, then sort by numeric network address and prefix length.

Comments and rule scopes are retained. This ordering applies inside each list;
the client references above retain their policy priority. Generators emit this
order, and repository verification rejects an unordered list.

## Maintenance

Edit the maintained inputs in [source/](source/). Scheduled workflows regenerate
the published lists, binaries and five provenance manifests in [metadata/](metadata/).
Do not edit generated artefacts directly.

Routing companion projection uses Rust and Cargo (Rust 1.85 or later), with
locked dependencies. Python orchestrates source imports, SRS compilation and
provenance. Rejection selection remains in the existing Python pipeline.

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
