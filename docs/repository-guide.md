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
| [proxy-tld-policy.json](../source/proxy-tld-policy.json) | Reviewed dedicated proxy TLDs |
| [reject-app-scope.json](../source/reject-app-scope.json) | Application and advertising-platform selection namespaces |
| [reject-domain-extra.list](../source/reject-domain-extra.list) | Reviewed exact and suffix rejection rules |
| [reject-rule-extra.list](../source/reject-rule-extra.list) | Reviewed patterns, logical AND and Surge-only rules |
| [reject-domain-exclusions.list](../source/reject-domain-exclusions.list) | Reviewed rejection exclusions |
| [reject-ip-extra.list](../source/reject-ip-extra.list) | Maintained supplementary rejection ranges |
| [proxy-ip-extra.list](../source/proxy-ip-extra.list) | Maintained supplementary proxy ranges |

Official IANA data supplies both TLD pairs. AdGuard filters 1, 2 and 59 supply
the hostname rejection inputs; only filter 1 contributes upstream IP blocks.
The application selector retains existing rules within explicit namespace roots
and preserves manual supplements. It does not create blocks for catalogue roots.
Upstream Adblock exceptions are audited under the block-wins policy; reviewed
local exclusions are enforced separately. APNIC and the documented service
sources supply the IP routing pairs.

## Matching and optimisation

- A bare DOMAIN-SET entry matches one hostname; a leading dot also covers its
  descendants. Keywords match literal substrings, including within DNS labels.
- Routing companion keywords require at least five ASCII letters. Short service
  names use explicit domain suffixes. Declared companion counts and current
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
