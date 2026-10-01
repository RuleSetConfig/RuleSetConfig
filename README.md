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
| `filter.list`, `filter.srs` | [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter), [AdGuard DNS Popup Hosts filter](https://github.com/AdguardTeam/AdGuardSDNSFilter), [AdAway default blocklist](https://github.com/AdAway/adaway.github.io), [Peter Lowe's Blocklist](https://pgl.yoyo.org/adservers/), [AWAvenue Ads Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) and [OISD Blocklist Big](https://oisd.nl/) published through the [AdGuard Hostlists Registry](https://github.com/AdguardTeam/HostlistsRegistry); only the domestic entries of the OISD list are kept, see `source/china-brands.txt`. Plus the [anti-AD](https://github.com/privacy-protection-tools/anti-AD) auto number verification list | GPL-3.0, GPL-3.0, CC BY 3.0, McRae GPL, GPL-3.0, GPL-3.0, MIT |
| `direct-ip.list`, `direct-ip.srs` | [mayaxcn/china-ip-list](https://github.com/mayaxcn/china-ip-list), plus AS132203 prefixes from [RouteViews](https://www.routeviews.org/) | GPL-3.0 / CC BY 4.0 |
| `proxy-ip.list`, `proxy-ip.srs` | [Cloudflare IP ranges](https://www.cloudflare.com/ips-v4), [Telegram CIDR](https://core.telegram.org/resources/cidr.txt), [Google `goog.json`](https://www.gstatic.com/ipranges/goog.json), [GitHub `meta`](https://api.github.com/meta), plus ASN prefixes from [RouteViews](https://www.routeviews.org/) | Upstream terms / CC BY 4.0 |
| `source/china-brands.txt`, `source/proxy-ip.asn`, `source/proxy-ip.local.list` | maintained here | — |

## Consumption

`filter.list` is a Surge `DOMAIN-SET`, not a general `RULE-SET`. A leading dot is
a suffix match and a line without one is an exact domain:

```ini
[Rule]
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/filter.list,REJECT
```

For sing-box, match `filter.srs` in a reject route rule. The binary files use
rule-set format version 2 and require sing-box 1.10.0 or newer.
`direct-ip.list` and `proxy-ip.list` are Surge `RULE-SET`
files containing `IP-CIDR` / `IP-CIDR6` entries.

The `main` branch is mutable. Pin a commit SHA when a deployment needs immutable
inputs, or consume the daily `rulesets-YYYY-MM-DD` GitHub Release snapshot. Each
release contains all `.list`/`.srs` files, `SHA256SUMS`, and the provenance
manifest under the name `filter-manifest.json`. The manifest records the SHA-256
and byte size of every filter input
and output, together with the pinned sing-box compiler version.

## Automatic updates

The rule sets are regenerated every day by GitHub Actions. Times below are planned
trigger times in UTC+8; GitHub may start scheduled jobs later:

| File | Workflow | Upstream and local input | Time |
| --- | --- | --- | --- |
| `filter.list` / `filter.srs` | `.github/workflows/sync-filter.yml` | AdGuard DNS filter, AdGuard DNS Popup Hosts filter, AdAway default blocklist, Peter Lowe's Blocklist, AWAvenue Ads Rule, the domestic entries of OISD Blocklist Big, anti-AD auto number verification list | 05:13 |
| `direct-ip.list` / `direct-ip.srs` | `.github/workflows/sync-direct-ip.yml` | chnroute / chnroute_v6 from mayaxcn/china-ip-list plus AS132203 from RouteViews | 06:23 |
| `proxy-ip.list` / `proxy-ip.srs` | `.github/workflows/sync-proxy-ip.yml` | Official Cloudflare / Telegram / Google / GitHub lists plus the ASNs in `source/proxy-ip.asn` expanded via RouteViews; `source/proxy-ip.local.list` only steers the priority and the pruning | 06:53 |

Maintained by hand and never regenerated: the input files under `source/`.

Rules applied while generating: merge every source, deduplicate, drop entries already
covered by a wider prefix or a parent domain, and let a proxy match win over a direct one
when the same rule appears in both. Adblock `@@` entries are upstream allow
exceptions, not routing policy: the generator reports their count for audit but
does not publish them or let them remove positive blocking rules.
This is an aggressive blocking policy: an upstream exception for a login,
redirect, or other functional hostname can remain blocked by an explicit rule
or a parent suffix. `@@` never selects DIRECT or PROXY. Each filter run saves
`filter-audit.json` as an Actions artifact for 14 days, with the original
exception, source line, parse result, covering suffix, and whether descendant
block rules overlap. The Actions summary includes per-source counts and conflict totals.

The domain-only converter skips URL paths, regexes, wildcard masks and scoped
modifiers such as `$client`, `$dnstype` and `$denyallow`, rather than silently
turning them into whole-domain blocks. `$badfilter` disables its matching rule
within the same source; an independent block from another source still wins.
`$important` is retained as a block match, and the known AdGuard popup rewrite
to `ad-block.dns.adguard.com` is intentionally converted to rejection. Other
DNS rewrites are skipped. Hosts entries are accepted only for blocking addresses
(`0.0.0.0`, `127.0.0.1`, `::`, `::1`), including multiple hosts on one line.
This projection does not reproduce the complete AdGuard filtering language.
The local rules under `source/` are the highest
priority layer and decide IP pruning, but they are not copied into the generated files:
`proxy-ip` contains upstream entries only and never repeats an entry the local layer
already carries.

Before publication, each workflow rejects empty, oversized, or unusually changed
outputs; verifies every `.list`/`.srs` pair in the repository; and serializes all
writers through one concurrency group. A manually reviewed exceptional change can be
run with the `accept_large_change` workflow input. The sing-box release and
`actions/checkout` revision are pinned, and checkout credentials are only introduced
for the final push step.
The three sync workflows share `scripts/publish-rulesets.sh`, which supplies
Git authentication only to the network commands, stages their named outputs,
and verifies all pairs and manifests after rebasing onto the latest `main`.
A verification failure stops the push immediately.

## Local verification

With a compatible `sing-box` in `PATH`:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/verify-all.py
```

AS132203 prefix data is provided by the [RouteViews](https://www.routeviews.org/)
project under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## License

Copyright (C) 2026 RuleSetConfig

This repository is distributed under the terms of the
[GNU General Public License v3.0](LICENSE), except for the upstream data listed
above, which stays under the license of its respective project.
