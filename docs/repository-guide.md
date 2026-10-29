# Repository structure and publication

## Published and maintained files

| Location | Purpose |
| --- | --- |
| Root-level .list and .srs files | Nine generated text/binary pairs |
| [source/](../source/) | Maintained selection policies, supplementary rules and exclusions |
| [scripts/](../scripts/) | Import, selection, conversion, optimisation and verification |
| [metadata/](../metadata/) | Five source/output provenance manifests |
| [tests/](../tests/) | Unit tests, native matching and optimisation checks |
| [.github/workflows/](../.github/workflows/) | Scheduled generation, verification and Release publication |
| [.github/actions/](../.github/actions/) | Installation of the pinned, checksum-verified compiler |
| [docs/](.) | Current client configuration and this maintenance guide |

All published pairs, maintained inputs, build scripts, tests and provenance
manifests are active. Historical reviews and raw DNS/network snapshots remain
available in Git history. Current policy is defined by the maintained sources;
current counts and hashes are recorded in the manifests.

## Source ownership

| Input | Responsibility |
| --- | --- |
| [domain-keywords.json](../source/domain-keywords.json) | Proxy/direct companion keywords, suffixes and declared counts |
| [proxy-tld-policy.json](../source/proxy-tld-policy.json) | Reviewed dedicated and explicitly requested generic proxy TLDs |
| [reject-app-scope.json](../source/reject-app-scope.json) | Application and advertising-platform selection namespaces |
| [reject-domain-extra.list](../source/reject-domain-extra.list) | Reviewed exact and suffix rejection rules |
| [reject-rule-selection.json](../source/reject-rule-selection.json) | Exact rule-companion size and source-agreement selection |
| [reject-rule-extra.list](../source/reject-rule-extra.list) | Reviewed patterns, logical AND and Surge-only rules |
| [reject-domain-exclusions.list](../source/reject-domain-exclusions.list) | Reviewed rejection exclusions |
| [reject-ip-extra.list](../source/reject-ip-extra.list) | Maintained supplementary rejection ranges |
| [proxy-ip-extra.list](../source/proxy-ip-extra.list) | Maintained supplementary proxy ranges |

Official IANA data supplies both TLD pairs. AdGuard filters 1, 2, 5, 53 and 59 supply
the hostname rejection inputs; only filter 1 contributes upstream IP blocks.
The application selector retains existing rules within explicit namespace roots
and preserves manual supplements. It does not create blocks for catalogue roots.
Upstream Adblock exceptions are audited under the block-wins policy; reviewed
local exclusions are enforced separately. APNIC and the documented service
sources supply the IP routing pairs.

## Bounded rejection companion

[The selection policy](../source/reject-rule-selection.json) fixes REJECT-RULE-SET
at 60,000 non-comment rules, including the two Surge-only entries. Application
selection and the 97 reviewed supplements run first; their retained coverage is
preserved. Installed Mac families include Apple, Microsoft, Google, Tencent,
OpenAI, OmniGroup and Parallels. The requested reading/drama family explicitly
includes Hongguo Short Drama and Fanqie Novel.

The remaining slots use positive hostname rules from six maintained sources:
AdGuard DNS (1), AdAway (2), OISD Small (5), AWAvenue (53), AdGuard DNS Popup
Hosts (59) and HaGeZi Normal (34). HaGeZi is a selection-support-only source;
it contributes no base domain, pattern or destination IP coverage. Every addition needs at least two lists supporting its complete match
scope. An exact hosts entry cannot support all descendants of a suffix rule.
Candidates conflicting with a parsed upstream hostname exception or reviewed
local exclusion are rejected, including parents that would subsume an exception.
The existing application projection retains its audited block-wins policy.

Candidates already covered by a companion, candidates that would subsume
preserved domains or wildcards, and parent-covered children cannot consume slots.
Ranking uses application category, descending support count, the explicit source
preference (53, 2, 34, 5, 1, 59), then hostname order as a deterministic tie-break.
OISD Small [focuses on web and mobile-app advertisements](https://oisd.nl/faq).
The lists overlap in their own upstream inputs; agreement is not independent
evidence, user counts, traffic frequency or measured blocking efficacy.

The build fails if the remaining eligible pool cannot fill the budget. It never
pads the file with generated hostnames, duplicated scopes or broader keywords.
Scheduled builds enforce the same budget. The Actions audit records each new
rule and its supporters; metadata/filter.json records the selection digest,
support histogram, policy/source fingerprints and resulting output hashes.

## Matching and optimisation

- A bare DOMAIN-SET entry matches one hostname; a leading dot also covers its
  descendants. Keywords match literal substrings, including within DNS labels.
- Routing companion keywords require at least five ASCII letters. Bounded suffixes and exact hosts supply the remaining
  rules in each 60,000-entry companion. Declared companion counts and current
  selections are checked against domain-keywords.json.
- Logical AND rules retain conjunction semantics and appear before other
  patterns. STUN and the reviewed ttplayer User-Agent rule are Surge-only;
  [client configuration](client-configuration.md) describes the sing-box handling.
- REJECT domain and pattern companions must be loaded together at the same
  policy and matching stage. The optimiser removes a domain or wildcard only
  when retained rules prove its whole matching scope remains covered. Wildcard
  descendants alone do not cover their apex; unsupported syntax fails the build.
- Load both PROXY companions before both DIRECT companions. Explicit domain
  policies precede the IP fallbacks; PROXY IP rules precede DIRECT IP rules.

The builder records optimisation evidence in its Actions artefact. Verification
checks the equivalent-optimisation fixed point and coverage of manual rules.
Keep source selection, equivalent pruning and changes in live behaviour distinct.
Native tests establish matching behaviour, not client connectivity or performance.

## Curated proxy IPs

The proxy supplement preserves reviewed DNS, Telegram, Apple, Parallels Desktop
and OmniGroup destinations across rebuilds. Its comments retain official service
references; it is not expanded automatically from live DNS.

| Service | Maintained basis |
| --- | --- |
| Parallels Desktop | Four IPv4 /32 and four IPv6 /128 addresses observed on 2026-10-24 for core .com/.cn service hosts. These are shared Cloudflare edges, not product-exclusive networks. Review changed service answers before replacing the curated addresses. [Official host reference](https://kb.parallels.com/en/128971). |
| OmniGroup | The vendor-published 198.151.161.0/24 and 204.128.250.0/24 networks, recorded on 2026-10-24. Rotating shared CDN download addresses are not pinned. [Official restricted-network guide](https://support.omnigroup.com/oss-syncing-on-restricted-networks/). |

The corresponding domain keywords remain in domain-keywords.json. Keep domain
policies ahead of IP fallbacks, and review vendor guidance when changing these
manual ranges. The original observation date is separate from build timestamps.

## Workflow responsibilities

| Workflow | Function |
| --- | --- |
| build-filter.yml | Generate the three rejection pairs |
| sync-tld.yml | Generate both IANA TLD pairs and both companion pairs |
| sync-ip.yml | Generate direct and proxy IP pairs |
| verify-rulesets.yml | Verify committed pairs and source provenance |
| publish-release.yml | Publish and verify the latest snapshot, then remove older Releases |

Publishing workflows share the serial ruleset-publisher queue. Each job records
the current checkout revision and publishes only its designated artefacts.
Failed generation or verification prevents publication.

## Provenance and verification

The filter, TLD, keyword, direct-IP and proxy-IP manifests record source identities
and output hashes. Verification requires all nine pairs and five manifests.
Generated sources and their consumers must be updated together. Regenerate
affected artefacts after changing maintained rules or generator output. Editorial
changes to fingerprinted sources also require refreshed source digests.

Run the existing checks with the pinned sing-box compiler on PATH:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/verify-all.py
python3 tests/native_filter.py
python3 tests/native_optimization.py
```

Local Python caches and macOS .DS_Store files are ignored. Use Git history to
retrieve retired documents rather than maintaining duplicate snapshot files.

## Single-Release retention

Release tags include the UTC date and the first 12 characters of the recorded
checkout revision. Repeating the same snapshot reuses its existing Release.

Before historical Releases are removed, the workflow:

1. verifies all committed pairs and manifests;
2. uploads the 24 required assets;
3. downloads them and compares SHA256SUMS with the local snapshot;
4. checks every downloaded asset and its remote inventory;
5. retains the newest verified published Release and removes older published Releases.

Drafts are excluded from automatic removal. The retention step does not delete
Git tags or rewrite commit history. Publication or verification failures leave
the previous Releases available.

## Routing companion selection

Each companion contains exactly 60,000 rules, excluding comments and blank lines.
The existing 98 proxy keywords and nine direct keywords remain unchanged.
The current proxy projection contains 17,425 suffixes and 42,477 exact hosts;
the direct projection contains 59,991 suffixes, including the requested skhb.com
and medtl.com domains. Keyword, suffix and exact-host scopes follow the
[Surge Domain Rules semantics](https://manual.nssurge.com/rules/domain.html).

[companion-import.json](../source/companion-import.json) pins the Loyalsoldier
proxy/direct lists and the v2fly archive by commit, byte count and SHA-256.
Application families include OpenAI, Telegram, Google, Microsoft, Apple and
Tencent. Seeds and reviewed vendor suffixes take precedence over application
families; application families precede the remaining community pool. Equal
priority cross-policy conflicts are omitted. Coverage supplied by either
DOMAIN-SET, same-policy keywords or retained parents cannot consume extra slots.
Wholly blocked scopes are excluded; blocked descendants retain REJECT priority.

The community proxy pool alone contains fewer than 60,000 independent scopes.
A checked-in [rank/hostname projection](../source/ranked-domain-candidates.csv)
therefore supplements the existing default proxy policy with exact host rules.
It retains the first 250,000 rows of the Majestic Million, with the full download
fingerprint and date recorded in the import policy. These ranks measure
referring subnets, not visits, local application use, geographic ownership or
blocking efficacy. Known direct scopes, including those outside the selected
direct budget, and current rejection coverage are excluded before selection.
Ranked hostnames are never promoted to suffixes. Rank influences selection of
already-supported direct suffixes without broadening their matching scope.

The checked-in candidate projection makes selection reproducible after the daily
upstream ranking changes. Application priority comes first, followed by available
referring-subnet rank, then SHA-256 ordering for unranked suffixes. Exact proxy
supplements retain known source hosts before the remaining ranked candidates.

Scheduled jobs rebuild the maintained selection. To reproduce or refresh it
against the current routing and rejection snapshot, run:

```sh
python3 scripts/import-companion-domains.py --fetch \
  --source-dir /tmp/companion-inputs --check --audit /tmp/companion-audit.json
```

Omit `--check` to update the selected rules after reviewing inputs. Rebuild both
pairs with scripts/build-keyword-sets.py and refresh the TLD manifest's keyword
source fingerprint. The build fails if the independent pool cannot fill either
60,000-entry budget; it never fabricates hostnames or widens exact scopes.

Loyalsoldier/surge-rules uses GPL-3.0. The v2fly MIT notice is retained in
[companion-upstream-LICENSE.txt](../source/companion-upstream-LICENSE.txt).
Majestic's rank/hostname data retains CC BY 3.0 attribution in
[ranked-domain-NOTICE.md](../source/ranked-domain-NOTICE.md), with attribution
also included in the generated lists. Repository code remains under GPL-3.0.
