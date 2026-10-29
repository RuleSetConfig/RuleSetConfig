# Surge and sing-box Rule Sets

Nine maintained rule-set pairs for Surge and sing-box. Each pair provides
equivalent portable matching rules in Surge text and sing-box format version 5.

## Downloads

| Rule set | Scope | Surge text | sing-box |
| --- | --- | --- | --- |
| REJECT-DOMAIN-SET | Selected advertising and telemetry domains | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.srs) |
| REJECT-RULE-SET | 60,000 selected hostname, pattern and Surge-only rules | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.srs) |
| REJECT-IP-SET | Selected destination IPv4 and IPv6 ranges | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.srs) |
| PROXY-DOMAIN-SET | IANA country-code and reviewed TLDs | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.srs) |
| PROXY-RULE-SET | 60,000 maintained proxy domain rules | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.srs) |
| PROXY-IP-SET | Maintained service and destination ranges | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.srs) |
| DIRECT-DOMAIN-SET | Mainland country-code TLDs | [DOMAIN-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.srs) |
| DIRECT-RULE-SET | 60,000 maintained direct domain rules | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.srs) |
| DIRECT-IP-SET | APNIC mainland China IPv4 and IPv6 allocations | [RULE-SET](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.list) | [SRS](https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.srs) |

## Configuration

Use all three reject sets together. Routing priority is: rejection, proxy
companions, direct companions, then IP fallbacks.

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

`PROXY` denotes an existing Surge policy. The reject pattern companion
contains STUN and User-Agent rules and must not use pre-matching.

sing-box requires version 1.14.0 or later. [Client configuration](docs/client-configuration.md)
provides the complete route fragment, DNS requirements and Surge-only exceptions.

## Maintained scope

- **Rejection:** application and shared advertising-platform rules selected from
  AdGuard Hostlists Registry filters 1, 2, 5, 53 and 59, plus the 97 reviewed local rules.
  HaGeZi Normal (34) provides additional hostname support for the bounded rule
  companion, without contributing base domains, patterns or IP rules.
  The rule companion contains exactly 60,000 non-comment entries. New hostname
  additions require matching-scope support from at least two lists. Installed Mac
  applications, Hongguo Short Drama and Fanqie Novel remain in the application scope.
  List agreement is not measured usage or blocking rate. Upstream IP imports come
  from filter 1 only. Both logical AND rules remain first;
  the zijieapi.com keyword rejects matching hostnames and snssdk.com remains blocked.
- **Proxy domains:** active IANA country-code TLDs except the three mainland
  country-code TLDs, together with reviewed dedicated TLDs and the explicitly
  requested `.app`, `.dev` and `.moe` generic TLDs. `.tv` is already included
  as a country-code TLD. The generic exceptions must remain active and
  delegated with the reviewed IANA manager and country.
- **Direct domains:** `.cn`, `.xn--fiqs8s` and `.xn--fiqz9s`.
- **Routing companions:** 60,000 rules each. The proxy set retains 98 keywords;
  the direct set retains the nine alipay, alicdn, autonavi, baidu, deepseek,
  qznovelvod, fqnovel, wechat and weixin keywords. Pinned Loyalsoldier and v2fly
  sources supply suffix rules, with application and vendor domains prioritised.
  Ranked Majestic hostnames supply exact proxy matches after known direct and
  rejection scopes are excluded. Referring-subnet ranks measure neither local
  usage nor geographic ownership. The direct set includes the explicitly
  requested skhb.com and medtl.com suffixes; qq.com, 7-zip.org and pypi.org remain.
  [Selection and provenance](docs/repository-guide.md#routing-companion-selection)
  describe the fixed budgets, source licences and overlap checks.
- **IP routing:** APNIC mainland China allocations and the maintained proxy service ranges.

Keywords use substring matching. Bare DOMAIN-SET entries are exact matches;
a leading dot includes the apex and descendants.

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
