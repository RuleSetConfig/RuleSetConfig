# Personal sing-box & Surge Configurations

This repository contains my personal configurations for [sing-box](https://github.com/SagerNet/sing-box) and [Surge](https://nssurge.com/).

## About

These files are maintained for my own use across multiple devices. They may include custom proxy setups, routing rules, and other settings tailored to my personal needs, and are not intended as a general-purpose or production-ready solution.

## Disclaimer

This repository is provided for personal learning and use only. The configurations may change at any time without notice, and their availability, functionality, and security are not guaranteed. The rule sets are generated automatically from the upstream projects listed below and may contain errors or omissions. Please comply with all applicable local laws and the terms of service of any related providers. Use at your own risk.

## Sources & Credits

All credit for the underlying data belongs to the upstream projects below. See
[LICENSE](LICENSE) for the license of this repository.

| File | Upstream | License |
| --- | --- | --- |
| `filter.list`, `filter.srs` | [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter), [AdAway default blocklist](https://github.com/AdAway/adaway.github.io) published through the [AdGuard Hostlists Registry](https://github.com/AdguardTeam/HostlistsRegistry), [oisd](https://github.com/sjhgvr/oisd), [anti-AD](https://github.com/privacy-protection-tools/anti-AD) | GPL-3.0, CC BY 3.0, GPL-3.0, MIT |
| `proxy-set.list`, `proxy-set.srs`, `direct-set.list`, `direct-set.srs` | [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules) | GPL-3.0 |
| `direct-ip.list`, `direct-ip.srs` | [mayaxcn/china-ip-list](https://github.com/mayaxcn/china-ip-list), plus AS132203 prefixes from [RouteViews](https://www.routeviews.org/) | GPL-3.0 / CC BY 4.0 |
| `proxy-ip.list`, `proxy-ip.srs` | [Cloudflare IP ranges](https://www.cloudflare.com/ips-v4), [Telegram CIDR](https://core.telegram.org/resources/cidr.txt), [Google `goog.json`](https://www.gstatic.com/ipranges/goog.json), [GitHub `meta`](https://api.github.com/meta), plus ASN prefixes from [RouteViews](https://www.routeviews.org/) | Upstream terms / CC BY 4.0 |
| `filter-set.list`, `filter-set.srs`, `filter-ip.list`, `filter-ip.srs`, `source/*.local.list`, `source/proxy-ip.asn` | maintained here | — |

## Automatic updates

The rule sets are regenerated every day by GitHub Actions (times are UTC+8):

| File | Workflow | Upstream and local input | Time |
| --- | --- | --- | --- |
| `filter.list` / `filter.srs` | `.github/workflows/sync-filter.yml` | AdGuard DNS filter, AdAway default blocklist, oisd, anti-AD | 05:13 |
| `proxy-set.list` / `.srs`, `direct-set.list` / `.srs` | `.github/workflows/sync-proxy-direct.yml` | Loyalsoldier/surge-rules; `source/proxy.local.list` and `source/direct.local.list` only steer the priority and the pruning | 05:47 |
| `direct-ip.list` / `direct-ip.srs` | `.github/workflows/sync-direct-ip.yml` | chnroute / chnroute_v6 from mayaxcn/china-ip-list plus AS132203 from RouteViews | 06:23 |
| `proxy-ip.list` / `proxy-ip.srs` | `.github/workflows/sync-proxy-ip.yml` | Official Cloudflare / Telegram / Google / GitHub lists plus the ASNs in `source/proxy-ip.asn` expanded via RouteViews; `source/proxy-ip.local.list` only steers the priority and the pruning | 06:53 |

Maintained by hand and never regenerated: `filter-set.list` / `filter-set.srs`,
`filter-ip.list` / `filter-ip.srs`, and the input files under `source/`.

Rules applied while generating: merge every source, deduplicate, drop entries already
covered by a wider prefix or a parent domain, keep every `.cn` domain direct, and let
proxy win over direct when the same rule appears in both. The local rules under `source/`
are the highest priority layer and decide that pruning, but they are not copied into the
generated files: `proxy-set` / `direct-set` and `proxy-ip` contain upstream entries only
and never repeat an entry the local layer already carries.
`.list` files use Surge rule syntax, `.srs` files are the equivalent sing-box rule sets.

AS132203 prefix data is provided by the [RouteViews](https://www.routeviews.org/)
project under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## License

Copyright (C) 2026 RuleSetConfig

This repository is distributed under the terms of the
[GNU General Public License v3.0](LICENSE), except for the upstream data listed
above, which stays under the license of its respective project.
