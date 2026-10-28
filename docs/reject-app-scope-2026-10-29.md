# Application-scoped reject rules — 2026-10-29

The previous builder imported the entire hostname projection of three global
blocklists. This review selects existing upstream advertising and telemetry entries for the
maintainer's installed application brand families, explicitly requested reading
and short-drama applications, mainstream domestic applications, and shared advertising/analytics
services. Unrelated publishers and long-tail pop-up domains are omitted.

The selection catalogue contains **40 families and 420 explicit namespace roots**.
It is maintained in [source/reject-app-scope.json](../source/reject-app-scope.json).
The approved 96 local rules are merged after selection and verified against the
combined domain/pattern companions, so their matching scope remains covered.
The installed-application inventory stays local and is not part of this repository.

## Result for the reviewed source snapshot

| Partition | Before | After |
| --- | ---: | ---: |
| REJECT-DOMAIN-SET | 186,239 | 1,104 |
| REJECT-RULE-SET (Surge list) | 1,206 | 137 |
| REJECT-RULE-SET (portable SRS entries) | 1,204 | 135 |
| REJECT-IP-SET | 140 | 140 |

Two logical AND rules remain first in the pattern list, followed by keywords.
Whole-domain zijieapi.com stays excluded; explicit advertising and telemetry children remain
eligible. The reviewed snssdk.com keyword remains enabled.
PROTOCOL,STUN and USER-AGENT,ttplayer* remain enabled in Surge and are omitted
from SRS with the existing exact audit allowlist.

| Artefact | Before (bytes) | After (bytes) | Reduction |
| --- | ---: | ---: | ---: |
| REJECT-DOMAIN-SET.list | 4,119,528 | 24,774 | 99.40% |
| REJECT-DOMAIN-SET.srs | 1,651,873 | 9,422 | 99.43% |
| REJECT-RULE-SET.list | 51,036 | 5,328 | 89.56% |
| REJECT-RULE-SET.srs | 9,975 | 1,159 | 88.38% |

The two list files together shrink from **4,170,564 to 30,102 bytes (99.28%)**;
the paired SRS files shrink from **1,661,848 to 10,581 bytes (99.36%)**.
These are measured artefact sizes. Client process memory and live hit frequency
were not measured.

## Selection and maintenance

- Fully parse filter_1, filter_2 and filter_59 and enforce their original
  completeness floors before application selection.
- Match a whole namespace root or its DNS-label descendants. ads.qq.com
  qualifies for qq.com; evilqq.com and qq.com.example do not.
- Keep the original rule type and value. A scope root never synthesises a block
  for the brand, its login/API hosts, or its content/media hosts.
- Patterns with a fixed namespace suffix may qualify. The one reviewed
  cross-TLD pattern *.adservice.google.* is retained only if present upstream.
  Other global/long-tail patterns are omitted.
- Merge the 72 local exact/suffix entries and 24 local patterns/Surge-only
  entries after selecting upstream rules. Apply reviewed exclusions and
  equivalent pruning, then compile and round-trip both representations.
- Keep all upstream IP blocks from filter_1 plus the existing local IP source.
  Domain-only filter_2/filter_59 inputs cannot supply IPs, and the application
  selector does not change IP entries.
- Require 300–15,000 selected domain entries before and after equivalent
  optimisation. Normal daily publication retains the existing 0.80–1.25
  baseline ratio guards.
- Include the scope, selector and manifest writer hashes in provenance.
  metadata/filter.json records each source's before/selected/removed counts
  and family hits. The full conversion audit is also saved as an Actions artefact.

The namespace list is a reviewed relevance filter, not a measured popularity
ranking. Update the scope source when another application family is needed;
the next daily build refreshes its existing upstream rules. A family with no
upstream ad match contributes no blocking rule.

## Catalogue and selected input records

Counts below are before cross-source deduplication and equivalent pruning.
The same input record can occur in multiple sources. Manual supplements and IP
entries are excluded from these family counts.

| Family | Reason for inclusion | Namespace roots | Selected input records |
| --- | --- | ---: | ---: |
| apple | installed | 9 | 29 |
| microsoft | installed | 20 | 50 |
| google | installed | 14 | 29 |
| tencent | installed | 15 | 82 |
| openai | installed | 4 | 2 |
| omnigroup | installed | 2 | 0 |
| parallels | installed | 2 | 0 |
| telegram | installed | 4 | 0 |
| termius | installed | 1 | 0 |
| readdle | installed | 2 | 0 |
| elmedia | installed | 3 | 0 |
| barebones | installed | 1 | 0 |
| snapgene | installed | 2 | 0 |
| mac-utilities | installed | 7 | 0 |
| bytedance-reading-drama | requested | 38 | 107 |
| qimao | requested | 3 | 1 |
| alibaba | mainstream | 22 | 128 |
| baidu | mainstream | 16 | 60 |
| netease | mainstream | 10 | 20 |
| bilibili | mainstream | 8 | 7 |
| kuaishou | mainstream | 6 | 41 |
| xiaohongshu | mainstream | 3 | 9 |
| weibo | mainstream | 7 | 23 |
| zhihu | mainstream | 2 | 3 |
| jd | mainstream | 6 | 4 |
| meituan | mainstream | 5 | 4 |
| pinduoduo | mainstream | 3 | 3 |
| didi | mainstream | 4 | 1 |
| travel | mainstream | 5 | 4 |
| xiaomi | mainstream | 6 | 50 |
| huawei | mainstream | 8 | 26 |
| oppo-vivo | mainstream | 9 | 54 |
| samsung | mainstream | 4 | 35 |
| kingsoft | mainstream | 6 | 2 |
| qihoo-sogou | mainstream | 12 | 27 |
| media-games | mainstream | 14 | 19 |
| amazon-meta | shared-platform | 11 | 43 |
| google-ads | shared-platform | 13 | 64 |
| mobile-ad-sdk | shared-platform | 45 | 401 |
| web-ad-analytics | shared-platform | 68 | 957 |

The installed category denotes the installed Mac brand family catalogue;
requested covers Hongguo Short Dramas / Fanqie Novel / Qimao Novel and their reviewed related namespaces;
mainstream covers the confirmed common-application scope; shared-platform covers
common advertising, attribution and analytics services.

## Validation

- 197 unit tests passed, including preservation of all 96 supplements,
  primary-only IP imports, label boundaries, selection size floors and scope integrity.
- 683 native sing-box matching cases and 43 native optimisation cases passed.
- 29 checks against the actual curated SRS passed, including 20 sampled normal
  login/content/bootstrap endpoints remaining outside the reject sets.
- All nine repository list/SRS pairs and every committed provenance hash passed.
- Surge offline syntax validation passed; no client configuration was loaded or reloaded.
- Workflow lint and patch whitespace checks passed.
- Both IP artefacts and all 12 unrelated proxy/direct artefacts stayed byte-identical.
