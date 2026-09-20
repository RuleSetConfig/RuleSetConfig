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
| `filter.list`, `filter.srs` | [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter), [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists), [oisd](https://github.com/sjhgvr/oisd), [anti-AD](https://github.com/privacy-protection-tools/anti-AD) | GPL-3.0, GPL-3.0, GPL-3.0, MIT |
| `proxy-set.list`, `proxy-set.srs`, `direct-set.list`, `direct-set.srs` | [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules) | GPL-3.0 |
| `direct-ip.list`, `direct-ip.srs` | [mayaxcn/china-ip-list](https://github.com/mayaxcn/china-ip-list), plus AS132203 prefixes from [RouteViews](https://www.routeviews.org/) | GPL-3.0 / CC BY 4.0 |
| `proxy-ip.list`, `proxy-ip.srs` | [Cloudflare IP ranges](https://www.cloudflare.com/ips-v4), [Telegram CIDR](https://core.telegram.org/resources/cidr.txt), [Google `goog.json`](https://www.gstatic.com/ipranges/goog.json), [GitHub `meta`](https://api.github.com/meta), plus ASN prefixes from [RouteViews](https://www.routeviews.org/) | 各上游条款 / CC BY 4.0 |
| `filter-set.list`, `filter-set.srs`, `filter-ip.list`, `filter-ip.srs`, `source/*.local.list`, `source/proxy-ip.asn` | maintained here | — |

## 自动更新

规则集由 GitHub Actions 每天自动生成（时间为北京时间）：

| 文件 | 工作流 | 上游与本地输入 | 时间 |
| --- | --- | --- | --- |
| `filter.list` / `filter.srs` | `.github/workflows/sync-filter.yml` | AdGuard DNS filter、hagezi、oisd、anti-AD | 05:00 |
| `proxy-set.list` / `.srs`、`direct-set.list` / `.srs` | `.github/workflows/sync-proxy-direct.yml` | Loyalsoldier/surge-rules + `source/proxy.local.list`、`source/direct.local.list` | 05:00 |
| `direct-ip.list` / `direct-ip.srs` | `.github/workflows/sync-direct-ip.yml` | mayaxcn/china-ip-list 的 chnroute / chnroute_v6 + AS132203（RouteViews） | 05:45 |
| `proxy-ip.list` / `proxy-ip.srs` | `.github/workflows/sync-proxy-ip.yml` | Cloudflare / Telegram / Google / GitHub 官方清单 + `source/proxy-ip.asn` 的 ASN 展开（RouteViews）+ `source/proxy-ip.local.list` | 06:00 |

手工维护、不自动更新：`filter-set.list` / `filter-set.srs`、`filter-ip.list` / `filter-ip.srs`，
以及 `source/` 下作为输入的本地规则文件。

生成规则：合并所有来源后去重复、删除被更大前缀或父域覆盖的冗余条目，`.cn` 一律直连，
proxy 与 direct 同名时以 proxy 为准。`.list` 是 Surge 规则语法，`.srs` 是同内容的
sing-box 规则集。

AS132203 prefix data is provided by the [RouteViews](https://www.routeviews.org/)
project under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## License

Copyright (C) 2026 samsaraRAID

This repository is distributed under the terms of the
[GNU General Public License v3.0](LICENSE), except for the upstream data listed
above, which stays under the license of its respective project.
