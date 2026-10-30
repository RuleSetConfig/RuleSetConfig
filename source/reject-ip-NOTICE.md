# Reviewed supplementary rejection IP sources

The supplement retains the original HTTPDNS and maintainer-selected Fanqie
snapshot. The 2026-10-30 review adds four exact public IPv4 hosts present in both
Sukka's current non-IP rejection list and blackmatrix7's dedicated BlockHttpDNS
list:

- 101.91.140.124/32
- 101.91.140.224/32
- 122.9.13.79/32
- 122.9.15.129/32

The complete reviewed HTTPDNS scope is covered after these additions. The
reviewed additions overlap neither the maintained PROXY-IP-SET nor the explicit
proxy service supplements. Mainland allocation overlap is expected: rejection
precedes direct routing. Host scope is retained, with no parent subnet expansion.
Source agreement records maintained list membership, not independent traffic or
blocking-rate evidence. Other advertising, botnet and shared hosting candidates
require a separate scope review. Current DNS answers were also sampled: they
differ from these maintained HTTPDNS snapshots and were not used to infer
exclusive ownership or to pin shared CDN networks.

## Source attribution and snapshots

SukkaW/Surge, Reject Non-IP:

- Source: https://ruleset.skk.moe/List/non_ip/reject.conf
- SHA-256: a20731d45036217728e6324ac46acc34cf1b0ab077b63424c24fc500aa7a7d12
- Bytes: 13667

blackmatrix7/ios_rule_script, BlockHttpDNS:

- Source: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/BlockHttpDNS/BlockHttpDNS.list
- SHA-256: 52753614063eff40364dcbdbbcea14f974409e197c0fe71fa716baa6fb518051
- Bytes: 2403

Sukka's source data retains its upstream AGPL-3.0 terms and attribution:
https://github.com/SukkaW/Surge and https://www.gnu.org/licenses/agpl-3.0.html.
blackmatrix7's source attribution and download URL are retained above. The
repository's original code licence remains recorded in the root LICENSE file.

The automated base IP import remains AdGuard Registry filter 1. These reviewed
manual supplements are maintained separately and are preserved by every build.
