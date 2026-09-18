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
| `geoip-cn.srs` | [SagerNet/sing-geoip](https://github.com/SagerNet/sing-geoip), plus AS132203 prefixes from [RIPE Stat](https://stat.ripe.net/) | GPL-3.0 / CC BY-SA 4.0 |
| `geosite-geolocation-cn.srs` | [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite), built from [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | GPL-3.0 / MIT |
| `filter-set.list`, `filter-ip.list`, `proxy-set.json` | maintained here | — |

This product includes GeoLite Data created by MaxMind, available from <https://www.maxmind.com>.
