# OmniGroup proxy coverage

`PROXY-RULE-SET` contains `DOMAIN-KEYWORD,omnigroup`; the SRS companion uses
`domain_keyword`. This matches the literal substring anywhere in a hostname,
including `omnigroup.com` and its service subdomains. The original suffix remains
in the custom source; the generator removes keyword-covered domain entries.
Both PROXY companions precede the DIRECT companions.

## Vendor-published IPv4 networks

The [official restricted-network guide](https://support.omnigroup.com/oss-syncing-on-restricted-networks/)
publishes two IPv4 /24 networks. Its June 2020 text writes them with host bits
(`198.151.161.1/24` and `204.128.250.1/24`); the rules use canonical network bases:

| PROXY-IP-SET entry | Current ARIN registration |
| --- | --- |
| `IP-CIDR,198.151.161.0/24` | [OMNIGROUP-NET](https://rdap.arin.net/registry/ip/198.151.161.0), Omni Group |
| `IP-CIDR,204.128.250.0/24` | [OMNIGROUP-R1](https://rdap.arin.net/registry/ip/204.128.250.0), Omni Development, Inc. |

Both registrations were checked on 2026-10-24. These are vendor-published
networks rather than CIDRs inferred by expanding individual DNS answers.
The IP rules apply to all ports, consistent with the repository's IP-set format.

## Current DNS check

At `2026-10-24T07:59:01+08:00`, Google and Cloudflare public DNS agreed on the A
records of ten sampled service hosts. The apex, website, support, account, store,
update and sampled sync hosts returned addresses within `204.128.250.0/24`.
All twenty AAAA queries completed without an IPv6 address, so this change adds
no IPv6 range. This sample does not prove that every OmniGroup service lacks IPv6.

`downloads.omnigroup.com` uses a shared CloudFront distribution. Its rotating
edge addresses are recorded for audit and are not pinned as OmniGroup networks.
The domain keyword covers download requests when their hostname is available.
An IP-only request to an edge outside the published networks does not gain
coverage from these two additions.

The [public snapshot](omnigroup-network-snapshot.json) records all forty DNS
queries, TTLs, aliases, resolver endpoints and the two ARIN network checks.

Maintain the keyword in [source/domain-keywords.json](../source/domain-keywords.json)
and the networks in [source/proxy-ip-extra.list](../source/proxy-ip-extra.list).
Rebuild both domain/keyword companions and their manifests together, then the
proxy IP pair and its manifest. Scheduled builds retain these curated networks;
review vendor changes before replacing them. Existing Parallels snapshot IPs
remain in the same source.
