# Personal sing-box & Surge Configurations

This repository contains my personal configurations for [sing-box](https://github.com/SagerNet/sing-box) and [Surge](https://nssurge.com/).

## About

These files are maintained for my own use across multiple devices. They may include custom proxy setups, routing rules, and other settings tailored to my personal needs, and are not intended as a general-purpose or production-ready solution.

## Disclaimer

This repository is provided for personal learning and use only. The configurations may change at any time without notice, and their availability, functionality, and security are not guaranteed. Please comply with all applicable local laws and the terms of service of any related providers. Use at your own risk.

## Sources & Credits

All credit for the underlying data belongs to the upstream projects below. See
[LICENSE](LICENSE) for the license of this repository.

| File | Upstream | License |
| --- | --- | --- |
| `filter.list`, `filter.srs` | [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter), [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists), [oisd](https://github.com/sjhgvr/oisd), [anti-AD](https://github.com/privacy-protection-tools/anti-AD) | GPL-3.0, GPL-3.0, GPL-3.0, MIT |
| `geoip-cn.srs` | [SagerNet/sing-geoip](https://github.com/SagerNet/sing-geoip), plus AS132203 prefixes from [RouteViews](https://www.routeviews.org/) | GPL-3.0 / CC BY-SA 4.0 / CC BY 4.0 |
| `geosite-geolocation-cn.srs` | [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite), built from [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | GPL-3.0 / MIT |
| `proxy.list`, `proxy.srs`, `direct.list`, `direct.srs` | [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules) | GPL-3.0 |
| `filter-set.list`, `filter-ip.list`, `source/proxy.local.list`, `source/direct.local.list` | maintained here | — |

`proxy.list` / `direct.list` 由 `.github/workflows/sync-proxy-direct.yml` 每天自动生成：
以本地的 `source/proxy.local.list`、`source/direct.local.list` 为主，叠加 Loyalsoldier 的远程列表，
去重复、去掉已被父域覆盖的子规则，`.cn` 一律直连，proxy 与 direct 同名时以 proxy 为准；
`proxy.srs` / `direct.srs` 是同内容的 sing-box 规则集。

This product includes GeoLite Data created by MaxMind, available from <https://www.maxmind.com>.

AS132203 prefix data is provided by the [RouteViews](https://www.routeviews.org/)
project under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
