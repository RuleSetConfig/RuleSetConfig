# Personal sing-box & Surge Configurations

This repository contains my personal configurations for [sing-box](https://github.com/SagerNet/sing-box) and [Surge](https://nssurge.com/).

## About

These files are maintained for personal use across multiple devices. The publishing
pipeline nevertheless uses production-style safety controls: pinned build tools,
checksum verification, source-specific size floors, change guards, provenance
metadata, unit tests, and byte/semantic verification of every committed rule-set
pair. The selection policy is still personal and is not a general-purpose promise
of correct routing for every network.

## Disclaimer

This repository is provided for personal learning and use only. The configurations may change at any time without notice, and their availability, functionality, and security are not guaranteed. The rule sets are generated automatically from the upstream projects listed below and may contain errors or omissions. Please comply with all applicable local laws and the terms of service of any related providers. Use at your own risk.

## Sources & Credits

All credit for the underlying data belongs to the upstream projects below. See
[LICENSE](LICENSE) for the license of this repository.

| File | Upstream | License |
| --- | --- | --- |
| `filter.list`, `filter.srs` | [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter), [AdGuard DNS Popup Hosts filter](https://github.com/AdguardTeam/AdGuardSDNSFilter), [AdAway default blocklist](https://github.com/AdAway/adaway.github.io), [Peter Lowe's Blocklist](https://pgl.yoyo.org/adservers/), [AWAvenue Ads Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) and [OISD Blocklist Big](https://oisd.nl/) published through the [AdGuard Hostlists Registry](https://github.com/AdguardTeam/HostlistsRegistry); OISD is selected using Chinese-use reference coverage plus Chinese domain suffixes and `source/china-brands.txt`. Plus the [anti-AD](https://github.com/privacy-protection-tools/anti-AD) auto number verification list | GPL-3.0, GPL-3.0, CC BY 3.0, McRae GPL, GPL-3.0, GPL-3.0, MIT |
| `source/china-brands.txt` | maintained here | — |

## Consumption

`filter.list` is a Surge **RULE-SET**. It contains `DOMAIN`, `DOMAIN-SUFFIX`,
`DOMAIN-KEYWORD`, `DOMAIN-WILDCARD` and destination `IP-CIDR` rules.
**Migration:** change existing `DOMAIN-SET` references to `RULE-SET`; keeping
`DOMAIN-SET` with this URL will not load the new format correctly.

```ini
[Rule]
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/filter.list,REJECT
```

For sing-box, match `filter.srs` in a reject route rule. The binary files use
rule-set format version 2 and require sing-box 1.10.0 or newer.
Wildcard masks and the supported domain-regex subset become `domain_regex`;
IP targets become `ip_cidr`. IP matches require a known destination IP: with
sing-box domain destinations, arrange a `resolve` action and another filter
check before any terminal allow route when IP filtering is required. Do not
add `no-resolve` to the Surge reference if it should resolve domains for IP
matching. As with any routing rule, earlier terminal rules take precedence.
These are routing block sets, not a complete DNS-response filter: CNAME-chain
inspection, multi-answer DNS rejection, and DNS response codes are not reproduced.

The `main` branch is mutable. Pin a commit SHA when a deployment needs immutable
inputs, or consume the daily `rulesets-YYYY-MM-DD` GitHub Release snapshot. Each
release contains `filter.list`, `filter.srs`, `SHA256SUMS`, and the provenance
manifest under the name `filter-manifest.json`. The manifest records the SHA-256
and byte size of every filter input
and output, together with the pinned sing-box compiler version.

## Automatic updates

The rule sets are regenerated every day by GitHub Actions. Times below are planned
trigger times in UTC+8; GitHub may start scheduled jobs later:

| File | Workflow | Upstream and local input | Time |
| --- | --- | --- | --- |
| `filter.list` / `filter.srs` | `.github/workflows/build-filter.yml` | AdGuard DNS filter, AdGuard DNS Popup Hosts filter, AdAway default blocklist, Peter Lowe's Blocklist, AWAvenue Ads Rule, selected Chinese-use entries of OISD Blocklist Big, anti-AD auto number verification list | 05:13 |

Maintained by hand and never regenerated: the input files under `source/`.

Rules applied while generating: merge every source, deduplicate, drop entries already
covered by a wider prefix or a parent domain. Adblock `@@` entries are upstream allow
exceptions, not routing policy: the generator reports their count for audit but
does not publish them or let them remove positive blocking rules.
This is an aggressive blocking policy: an upstream exception for a login,
redirect, or other functional hostname can remain blocked by an explicit rule
or a parent suffix. `@@` never selects DIRECT or PROXY. Each filter run saves
`filter-audit.json` as an Actions artifact for 14 days, with the original
exception, source line, parse result, covering suffix, and whether descendant
block rules overlap. The Actions summary includes per-source counts and conflict totals.

The converter retains exact domains, domain suffixes, substrings, prefix/suffix
anchors and `*` masks. For example, `-applog*.fqnovel.com^` becomes
`DOMAIN-WILDCARD,*-applog*.fqnovel.com` and an equivalent anchored RE2 expression.
A `||` anchor respects label boundaries; absence of an end anchor is preserved.
Supported hostname regexes (alternation, character classes and bounded repeats)
are expanded into equivalent Surge wildcard masks; sing-box receives the same
matching language. Expansion is bounded, and an unknown regex construct fails
the build for review instead of silently dropping it.

AdGuard Home checks DNS answer IP strings as well as hostnames. Explicit IP
rules become `/32` or `/128` destination rules, and bounded numeric IPv4 regexes
are enumerated against valid decimal octets then collapsed into exact CIDR
coverage. Domain matches from those regexes are also retained. URL schemes,
paths, port-bearing regexes and scoped modifiers such as `$client`, `$dnstype`
and `$denyallow` are recorded in the audit, not widened into domain/IP blocks.
`$badfilter` disables the matching same-source rule; an independent block in
another source still wins. `$important` retains its positive block, and the
known AdGuard popup rewrite to `ad-block.dns.adguard.com` is intentionally
projected to rejection. Other DNS rewrites are audited and skipped. Blocking
hosts entries (`0.0.0.0`, `127.0.0.1`, `::`, `::1`) remain exact-domain matches.
Pattern/IP exception overlap is not fully computed; the audit marks those
entries as unevaluated. The policy still ignores all `@@` exceptions.

OISD `filter_27` has no Chinese section. Its selected subset is the union of:

- OISD domains covered by suffix rules in [anti-AD](https://github.com/privacy-protection-tools/anti-AD),
  [AdRules DNS](https://github.com/Cats-Team/AdRules), or AWAvenue (already a full input).
- Chinese domain suffixes (`.cn`, `.xn--fiqs8s`, `.xn--fiqz9s`).
- Domestic brand tokens matched on the registrable-domain approximation in
  `source/china-brands.txt`, never arbitrary subdomain labels.

The two additional references are **selection-only**, not merged wholesale.
They include international services used by Chinese users, so this is a
Chinese-use subset, not a geographic classification. The selector does not
claim to use the full Public Suffix List. `china-selection.json` records every
selected host and its reasons; the Actions artifact stores it alongside the
conversion audit. Reference hashes and count summaries are in `metadata/filter.json`.
Reference rules retain their upstream licenses; see the respective anti-AD and
AdRules repositories and AdRules' source attribution list.

Before publication, the filter build rejects empty, oversized, or unusually changed
outputs and verifies the `filter.list`/`filter.srs` pair. The filter publisher and
release workflow share one concurrency group. A manually reviewed exceptional change can be
run with the `accept_large_change` workflow input. The sing-box release and
`actions/checkout` revision are pinned, and checkout credentials are only introduced
for the final push step.
The filter build uses `scripts/publish-rulesets.sh`, which supplies
Git authentication only to the network commands, stages the filter outputs,
and verifies the rule-set pair and manifest after rebasing onto the latest `main`.
A verification failure stops the push immediately.

## Local verification

The repository keeps one published pair, `filter.list`/`filter.srs`, at its root.
`source/china-brands.txt` is the manually maintained input; `metadata/filter.json`
records filter provenance. Under `scripts/`, the filter builder generates
the pair, `verify-all.py` handles both candidate and repository verification,
and `publish-rulesets.sh` handles the final push. Chinese-use OISD
selection lives in its only consumer, `filter-china.py`.
The old `sync-filter.yml` workflow has been removed and replaced by
`build-filter.yml`; there is only one scheduled filter writer.
The three workflows cover filter generation, verification, and release snapshots;
the shared setup action installs the pinned compiler. `tests/` protects filter
semantics and publication behavior.

With a compatible `sing-box` in `PATH`:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/verify-all.py
```

## License

Copyright (C) 2026 RuleSetConfig

This repository is distributed under the terms of the
[GNU General Public License v3.0](LICENSE), except for the upstream data listed
above, which stays under the license of its respective project.
