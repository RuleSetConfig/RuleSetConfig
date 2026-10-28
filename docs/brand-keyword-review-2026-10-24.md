# Brand keyword review — 2026-10-24

Routing keywords require at least five lowercase ASCII letters. Digits and
hyphens do not contribute to the minimum. Brand spelling, multiple service
families and policy consistency matter more than the number of keywords.

| Change | Policy | Reason |
| --- | --- | --- |
| Add `microsoft` | PROXY | Consolidate Microsoft application, account and service domain families; [official application reference](https://www.microsoft.com/en-us/microsoft-365/products-apps-services). |
| Add `douyin` | DIRECT | Consolidate the Douyin service and media families; [official product reference](https://www.douyin.com/downloadpage/app). |
| Add `fqnovel` | DIRECT | Consolidate the existing Fanqie API, image, static and media domain families; [product reference](https://fanqienovel.com/). |
| Add `meituan` | DIRECT | Consolidate Meituan service and asset families; [official site](https://www.meituan.com/). |
| Retain `gtimg` | DIRECT | Five letters; the existing keyword satisfies the minimum and retains its previous coverage. |

Cloudflare keeps its existing proxy/direct domain distinction. Generic terms
such as `start`, `magnet`, `office`, `live` and `windows` are not promoted just
to increase keyword counts. Single-family services already covered by precise
rules, including Termius, Bare Bones, Readdle and SnapGene, retain those rules.
The installed Telegram application does not by itself justify a broader keyword.

Keywords use literal substring matching. They do not prove brand ownership:
`microsoft` can also match another organisation's hostname containing that text.
Earlier PROXY domains continue to precede DIRECT keywords, including existing
proxy names containing `douyin`. The new Microsoft keyword takes priority over
the previously direct `surface-microsoftstore.com` scope. Reject rules keep their
earlier position; this update does not make blocked service requests allowable.

Both domain companions, both keyword companions and their two manifests are
rebuilt together. Original custom domain sources remain available for restoration
when a covering keyword is withdrawn. The minimum is enforced by the shared
policy reader and its boundary tests. Detailed application inventory and DNS observations
are retained locally; this public review contains policy decisions only.
