# Companion rule-set optimization audit

This audit describes the 2026-10-24 publication candidate against repository
baseline `fa9c8472ad08501da9fe614f5d5482ade75798dd`. Counts exclude comments and
blank lines. Scheduled source updates can change subsequent counts; consult the
current provenance manifests for the active snapshot.

| Pair | Published baseline | Updated candidate |
| --- | ---: | ---: |
| REJECT-DOMAIN-SET | 196,483 | 196,487 |
| REJECT-RULE-SET | 1,212 | 1,176 |
| REJECT-IP-SET | 140 | 140 |
| PROXY-DOMAIN-SET | 20,712 | 20,712 |
| PROXY-RULE-SET | 8 | 8 |
| PROXY-IP-SET | 532 | 539 |
| DIRECT-DOMAIN-SET | 108,410 | 107,792 |
| DIRECT-RULE-SET | 8 | 8 |
| DIRECT-IP-SET | 7,517 | 7,517 |

All nine text/SRS pairs use the existing canonical names and SRS format v5.

## Equivalent changes

The REJECT optimizer removes 350 domain records: 252 suffix scopes and 98 exact
hosts. Retained keywords cover 65 records, an explicit keyword AND covers one,
prefix-closed wildcards cover 23 suffixes, wildcard apex/descendant unions cover
176 suffixes, and retained wildcards cover 85 exact hosts.

For example, `aan.amazon.*` covers `aan.amazon.com` while `*.aan.amazon.*`
covers every descendant. Both are required before removing `.aan.amazon.com`.
A child-only wildcard alone does not cover its apex.

The pattern partition loses 36 records in total: seven masks covered by literal
keywords, 23 masks proven to be contained in retained masks, and six records
saved by four exact character-class unions. For example, the pair
`trace-*.hungrypanda.co` / `track-*.hungrypanda.co` becomes
`trac[ek]-*.hungrypanda.co`. Combining one character position at a time preserves
missing combinations at other positions. The 41 keywords, two explicit ANDs,
Surge-only STUN rule and 140 IP scopes remain.

The bounded product-automaton checker models normalized ASCII hostname
characters plus an OTHER class. It deletes only proven inclusions; a state-budget
limit retains the input. Deletions are made against currently retained masks and
resolved directly to final retained targets, avoiding dependency cycles. Unsupported
syntax fails the build. The scope claim concerns normalized hostnames, not
arbitrary Unicode strings, URL paths or DNS response/CNAME processing.

DIRECT pruning now includes the earlier PROXY keyword companion. On the fresh
domain snapshot, 336 additional direct records are fully covered by proxy
keywords. For example, `alicloud.com` already matches the literal `icloud`
keyword. The existing keyword policy is preserved. A direct parent suffix remains
when only some of its descendants match proxy domains or keywords. Withdrawing
a covering proxy keyword/source restores eligible direct source records during
the next full rebuild.

## Source changes kept separate

The five REJECT inputs were downloaded at `2026-10-24T06:50:35+08:00`. Their raw
merged domain projection has 196,837 records: 359 additions and five removals
against the baseline, a net increase of 354. Equivalent pruning then removes
350, resulting in 196,487. The baseline-equivalent version would have 196,133
records; that fixed-input comparison saved 2,977 SRS bytes. Source updates and
algorithmic savings must not be conflated, and no runtime speedup is claimed.

The refreshed four-source PROXY/DIRECT domain import has 108,128 direct records
under the previous pruning policy, 282 fewer than the published baseline.
The additional 336 keyword-covered deletions produce 107,792. The published
PROXY domain artifact and both eight-keyword pairs are byte-identical to baseline.

Both IP generators were run against fresh APNIC and service inputs. DIRECT
remains 7,517 canonical CIDRs; PROXY becomes 539. These changes follow existing
selection rules: exact Google Cloud subtraction, required Optimize/Allow
Microsoft 365 endpoints, active Meta announcements and curated Telegram/Apple
ranges. No destination-policy expansion was introduced by the optimizer.

All five reject feeds are retained: each had a concrete hostname witness absent
from the union of the other feeds and manual rules. Upstream `@@` exceptions
remain audit-only under the existing block-wins policy; the 100 overlapping
exception-domain records remain visible. Same-source `$badfilter` and scoped/path
conversion safeguards are preserved. No rule was removed because it was absent
from query logs. The existing `beacon.cdn.qq.com` exclusion remains.

## Required loading order

Load REJECT-DOMAIN-SET and REJECT-RULE-SET together, with the same policy and
matching-stage parameters, at adjacent priority positions. The coverage proof is
for their union. Keep the explicit sing-box STUN sniff/reject route because
headless SRS has no protocol field.

Load both PROXY companions before both DIRECT companions, as in the README.
Standalone direct coverage changes when an earlier proxy rule now covers the
removed scope. Keep explicit domain policies before the existing IP fallback
rules. Preserve the original IP resolution stage and PROXY-IP-before-DIRECT-IP
order.

## Persistent verification

`merge-filter.py` runs the optimizer before emitting partitions. The conversion
Actions artifact stores each deletion certificate, inclusion proof and exact
class merge. `metadata/filter.json` records optimization totals, original/output
hashes and optimizer fingerprints. The complete verifier independently checks
that committed companion sets are at the optimization fixed point, retains source
coverage checks across domain/pattern companions, and verifies all text/SRS pairs.

The domain builder and verifier both include earlier proxy keyword coverage.
The domain Actions artifact records the original direct entry and covering proxy
rule; `metadata/tld.json` records domain/keyword removal totals. Existing size
floors, 80%–125% change guards, canonical CIDR checks, source hashes, pinned core
checksums, staged-candidate publication and rebase-time verification still apply.

The 146-unit-test suite covers symbolic/finite exhaustive glob checks,
apex/descendant boundaries, class unions, unknown-proof retention, source
restoration and policy priority. Native optimization fixtures replay 43 cases
against original/optimized REJECT unions and proxy-before-direct routing.
The reviewed REJECT artifacts also passed 4,320 sample checks across sing-box
1.14.2 and 1.15.0-alpha.12; the integrated generator reproduces all six reviewed
REJECT artifact hashes. Native samples complement the general symbolic proof;
they do not establish live application behavior, TUN connectivity or performance.

The 336 direct deletions comprise 123 suffixes and 213 exact hosts. Their 582
apex/child inputs passed 1,164 native proxy-keyword matches across both cores.
All nine final pairs were checked on both cores, and the full local Surge
reference template passed its native syntax check. Existing native conversion
fixtures passed 285/285 cases on the pinned compiler.
