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
| [docs/](.) | Client guidance, dated reviews and supporting evidence |

The 2026-10-29 DIRECT companion replaces the earlier 100-rule catalogue with
nine keywords and the qq.com suffix. Dated reviews describe their recorded
snapshots and do not override the current maintained inputs.

## Source ownership

| Input | Responsibility |
| --- | --- |
| domain-keywords.json | Proxy and direct companion keywords, suffixes and declared counts |
| proxy-tld-policy.json | Reviewed dedicated proxy TLDs |
| reject-app-scope.json | Application and advertising-platform selection namespaces |
| reject-domain-extra.list | Reviewed exact and suffix rejection rules |
| reject-rule-extra.list | Reviewed patterns, logical AND and Surge-only rules |
| reject-domain-exclusions.list | Reviewed rejection exclusions |
| reject-ip-extra.list | Maintained supplementary rejection ranges |
| proxy-ip-extra.list | Maintained supplementary proxy ranges |

Official IANA data supplies both TLD pairs. AdGuard filters 1, 2 and 59 supply
the selected hostname rejection inputs; only filter 1 contributes upstream IP
blocks. APNIC and the documented service sources supply the IP routing pairs.

## Workflow responsibilities

| Workflow | Function |
| --- | --- |
| build-filter.yml | Generate the three rejection pairs |
| sync-tld.yml | Generate both IANA TLD pairs and both companion pairs |
| sync-ip.yml | Generate direct and proxy IP pairs |
| verify-rulesets.yml | Verify committed pairs and source provenance |
| publish-release.yml | Publish and verify the latest snapshot, then remove older Releases |

Publishing workflows share the serial `ruleset-publisher` queue. Each job
records the current checkout revision and publishes only its designated
artefacts. Failed generation or verification prevents publication.

## Provenance and verification

The filter, TLD, keyword, direct-IP and proxy-IP manifests record the source
identities and output hashes. Verification requires nine complete pairs and all
five manifests. Native checks verify matching behaviour; isolated tests do not
establish live application behaviour, connectivity or process memory usage.

Generated sources and their consumers must be updated together. Regenerate
affected artefacts after changing maintained rules or generator output. Editorial
changes to fingerprinted sources also require refreshed source digests.

## Single-Release retention

Release tags include the UTC date and the first 12 characters of the recorded
checkout revision. Repeating the same snapshot reuses its existing Release.

Before historical Releases are removed, the workflow:

1. verifies all committed pairs and manifests;
2. uploads the 24 required assets;
3. downloads them and compares SHA256SUMS with the local snapshot;
4. checks every downloaded asset and its remote inventory;
5. retains the newest verified published Release and removes older published Releases.

Drafts are not historical publications and are excluded from automatic removal.
The retention step does not delete Git tags or rewrite commit history.
Publication or verification failures leave the previous Releases available.
