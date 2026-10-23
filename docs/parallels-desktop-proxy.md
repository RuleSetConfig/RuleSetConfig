# Parallels Desktop proxy coverage

`PROXY-DOMAIN-SET` covers both `parallels.com` and `parallels.cn`, including their
apex names and descendants. The `.com` suffix was already retained in the custom
source; this update adds the `.cn` suffix. The PROXY companions precede the
DIRECT companions, so `.parallels.cn` is selected before the broader direct `.cn`
policy.

The [official communication-host reference](https://kb.parallels.com/en/128971)
identifies the Desktop licensing, activation and account hosts and their China
counterparts. The suffixes also cover download, update, support, documentation
and enterprise-management hostnames under these domains.

## Exact destination IP snapshot

At `2026-10-24T07:42:22+08:00`, Cloudflare and Google public DNS agreed on these
addresses for `desktop`, `license` and `account` under the two domain suffixes.
The complete A/AAAA answers, TTLs, queried hostnames and resolver endpoints are
preserved in [the public DNS snapshot](parallels-desktop-dns-snapshot.json).

| Host family | Exact IPv4 destinations | Exact IPv6 destinations |
| --- | --- | --- |
| Core `*.parallels.com` service hosts | `104.18.170.3/32`, `104.18.171.3/32` | `2606:4700::6812:aa03/128`, `2606:4700::6812:ab03/128` |
| Core `*.parallels.cn` service hosts | `104.18.8.96/32`, `104.18.9.96/32` | `2606:4700::6812:860/128`, `2606:4700::6812:960/128` |

These are DNS-observed [shared Cloudflare edge addresses](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/).
They are not Parallels-owned, product-exclusive or vendor-guaranteed fixed IPs.
When the IP fallback applies, another site using one of these exact addresses
can also be sent through PROXY. Explicit domain policies stay ahead of the IP
fallback. The snapshot adds only eight individual destination addresses; no
Cloudflare/AWS network, private VM subnet, port restriction or ASN-wide rule is
inferred.

Support also uses a dynamic AWS load balancer. Its current load-balancer IPs are not
pinned; the existing `parallels.com` suffix covers that hostname. Negative DNS
responses do not become IP rules. If these service answers change, review and
replace the curated snapshot; scheduled builds preserve it rather than silently
performing live DNS expansion.

Maintain domains in [source/proxy-custom.list](../source/proxy-custom.list) and IPs
in [source/proxy-ip-extra.list](../source/proxy-ip-extra.list). Regenerate the
PROXY/DIRECT domain companions and manifests, then rebuild the proxy IP pair
against the current DIRECT-IP-SET. Each text/SRS pair is verified before staging;
repository-source fingerprints prevent a later rebase from publishing stale
curated coverage. The DNS observation time is separate from build/publish times.
