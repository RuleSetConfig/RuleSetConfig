# Deep rule-set review — 2026-10-25

This review uses `main` at `da0433fbe30b95dbf1db3c52cc55ad55463c19cf`. Counts describe that fixed revision;
scheduled builds may subsequently change them. All nine rule pairs and all five
provenance manifests were reviewed. The corrections below do not edit any of
the eighteen published `.list` / `.srs` payloads or the routing keyword source.

## Findings and corrections

| Priority | Finding | Correction |
| --- | --- | --- |
| P2 | Missing provenance could pass full verification. An isolated copy with `metadata/keywords.json` removed still exited 0 and reported all nine pairs verified. Deleting an output fingerprint or the keyword-policy fingerprint was also accepted by the previous manifest helper. | The full CLI now requires the nine named pairs, five named manifests, exact output inventories, required source fingerprints and repository source identities, well-formed SHA256/byte records and compiler identity. Missing declarations stop before native execution. Single-candidate and compile modes retain their separate scope. |
| P2 | Four publishers shared the default concurrency queue. A newly pending run could cancel an older pending run even with `cancel-in-progress: false`. Two IP synchronization runs previously needed a second attempt after this occurred. | Keep the shared serialized publisher group and add `queue: max` to all four workflows. GitHub can retain up to 100 pending runs instead of replacing the sole pending slot. |
| P2 | The release job could wait behind a publisher but still check out the older event revision. Its comment promised a snapshot of `main` after waiting. | Check out `main` after acquiring the group, record that checkout's SHA and use it for both the release target and provenance note. A regression test supplies an older event SHA and verifies the captured release arguments use the checkout revision. Existing daily releases remain immutable. |

The concurrency behavior and queue limit follow [GitHub's official documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

## Inventory and consistency

| Pair | Text rules | SRS bytes |
| --- | ---: | ---: |
| `REJECT-DOMAIN-SET` | 196,855 | 1,726,671 |
| `REJECT-RULE-SET` | 1,176 | 9,785 |
| `REJECT-IP-SET` | 140 | 667 |
| `PROXY-DOMAIN-SET` | 20,647 | 123,746 |
| `PROXY-RULE-SET` | 11 | 92 |
| `PROXY-IP-SET` | 546 | 2,462 |
| `DIRECT-DOMAIN-SET` | 107,753 | 425,801 |
| `DIRECT-RULE-SET` | 11 | 92 |
| `DIRECT-IP-SET` | 7,517 | 33,614 |

There are 334,656 text rules in total. All binary headers use SRS v5. The portable
hostname/IP scopes match their text companions; `PROTOCOL,STUN` is the documented
Surge-only text rule and still needs a separate sniff/reject route in sing-box.
The binaries total 2,322,930 bytes (2.22 MiB), versus 6,353,982 bytes (6.06 MiB)
for text. These are storage sizes, not runtime-memory or latency measurements.

The review found no duplicate rows, parent-covered domain entries, same-policy
keyword-covered domain entries or full DIRECT scopes shadowed by earlier PROXY
companions. REJECT domain/pattern optimization is already at its verified fixed
point. The 22 routing keywords contain at least five letters, with no same-policy
substring redundancy or completely shadowed DIRECT keyword.

## Priority relationships retained

- At least 125 PROXY and 310 DIRECT domain scopes are provably covered by earlier
  REJECT domain/pattern rules. Examples include `.addthis.com`, `.2o7.net` and
  `.360ads.com`. These records remain useful when a routing set is consumed
  independently; removing them would couple its coverage to the reject feed.
- REJECT and DIRECT IP space intersects in 55 canonical CIDRs: 307 IPv4 addresses
  and four IPv6 addresses. Examples include `39.97.128.148/32` and
  `49.71.37.101/32`. REJECT must retain its earlier priority after resolution.
- Current PROXY/DIRECT IP intersection is empty. REJECT/PROXY IP intersection is
  also empty. Each IP set uses canonical ranges and contains no non-global range.
- Domain sets include 131 PROXY, 48 DIRECT and one REJECT single-label suffixes.
  All 180 appear in the [IANA root-zone TLD list](https://data.iana.org/TLD/tlds-alpha-by-domain.txt),
  version `2026102400`, checked on 2026-10-25. These are whole-namespace policies:
  `.app`, `.hk` and `.io` remain PROXY, `.cn` remains DIRECT, and the explicitly
  configured `.data` remains REJECT.

These relations assume the documented order: rejection, PROXY domain/keyword
companions, DIRECT domain/keyword companions, then applicable IP fallbacks at the
correct resolution stage. Matching a source's category is not an exception to
an earlier terminal rule. No LAN, SYSTEM or live client profile was changed.

## Broad matching and source limits

A minimum length is not an ownership boundary. `icloud` also occurs inside
`hicloud.com` and `alicloud.com`; `surge` occurs inside `surgeon.example`. The
user-selected literal substring policy is retained. Narrowing those keywords
would be a routing change, not equivalent cleanup. Surge's [domain-rule reference](https://manual.nssurge.com/rules/domain.html)
and sing-box's [headless-rule reference](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/)
explain the available match types.

The current domain import records 151 PROXY and eight DIRECT upstream regular
expressions as not imported. The published domain/keyword companions therefore
are not a complete mirror of every upstream matcher. Some regex languages may
already be covered by other retained rules; the exclusion count alone does not
measure uncovered traffic. Unsupported regexes should not be widened into parent
suffixes without a scope proof.

The reject feed deliberately uses `audit-only-block-wins` for AdGuard exceptions.
Its current result records 100 exception-domain overlaps. This is a repository
policy choice, not full AdGuard exception semantics, and exceptions are not
converted into DIRECT/PROXY routes. STUN detection and DNS CNAME-chain behavior
also remain client-side integration concerns.

## Curated IP maintenance

The existing eight Parallels address rules remain a shared Cloudflare edge
snapshot rather than product-exclusive IP ownership. Twenty-four fresh DNS
queries (six hosts, A/AAAA, Google and Cloudflare) all succeeded and the two
resolvers agreed. Their eight unique addresses matched the curated snapshot at
`2026-10-25T08:37:57.286529+08:00`. No CDN network was expanded during this review. The vendor-published
OmniGroup networks and all other curated ranges remain covered by the IP pair.

## Validation and limits

- 160 unit tests passed, including 12 repository-contract tests and the release
  revision regression test.
- Both sing-box 1.14.2 and 1.15.0-alpha.12 passed all nine pair checks, 297 native
  matching cases, and 43 native optimization cases (220 match invocations per
  core for that optimization suite).
- Surge's native checker accepted the profile referencing all nine local sets.
- Actionlint 1.7.12 passed with only its known unknown-`queue` diagnostic narrowly
  ignored. The field is documented by GitHub; the [upstream compatibility report](https://github.com/rhysd/actionlint/issues/746)
  reproduces this version's limitation. Other syntax, expression and shell checks
  remain enabled. GitHub workflow execution is the final backend check.
- Every published payload's SHA256 is unchanged from the review baseline.

Static coverage and isolated/native tests do not establish live application
reachability. This review does not infer application ownership from substring
matches or expand IP ownership from DNS answers.
