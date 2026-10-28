# Proxy and direct companion review — 2026-10-28

The proxy companion contains exactly **100 rules: 98 keywords and two precise domain suffixes**. The direct companion contains exactly **100 rules: 98 keywords and two precise domain suffixes**. Keyword values contain at least five ASCII letters; digits and hyphens do not count. Both counts are declared in source policy schema 2 and checked on every build.

Selection prioritizes the maintained application/toolchain policy, common software and services, then recent Homebrew installation activity. Domestic selections prioritize common applications and their established resource namespaces, with the current China App Store free chart used as a popularity reference. These sources measure different populations and do not form a single global ranking.

- [Homebrew cask installation activity, 90 days](https://formulae.brew.sh/api/analytics/cask-install/90d.json), 2026-07-30 to 2026-10-28.
- [Homebrew formula installation activity, 90 days](https://formulae.brew.sh/api/analytics/install/90d.json), 2026-07-30 to 2026-10-28.
- [Homebrew application metadata](https://formulae.brew.sh/api/cask.json) and the formula metadata linked below.
- [Apple China App Store top-free chart](https://rss.marketingtools.apple.com/api/v2/cn/apps/top-free/100/apps.json), snapshot retrieved 2026-10-28.

The chart snapshot includes Hongguo short dramas, Hongguo animated dramas, Qianwen, Doubao, Qishui Music, WorkBuddy, Jianying, enterprise WeChat, QQ Mail, Tencent Meeting, AMap, DeepSeek, Xiaohongshu, Taobao, Kuaishou, Meituan, Bilibili and Alipay. Existing short service identifiers remain covered by retained precise domains or their vendor rules.

## Coverage and priority

Each proxy keyword below has a real primary hostname outside the current proxy TLD set. Homebrew (`brew.sh`), Keka (`keka.io`), Cyberduck (`cyberduck.io`), Obsidian (`obsidian.md`), HandBrake (`handbrake.fr`), Typora (`typora.io`) and curl (`curl.se`) already match country-code TLD rules and do not need companion keyword entries for those hostnames. GitHub-hosted releases and raw files remain covered by the existing `github` keyword or `.io` TLD rule.

`7-zip` has only three letters and `pypi` has four. Use `DOMAIN-SUFFIX,7-zip.org` and `DOMAIN-SUFFIX,pypi.org` to include these requested toolchains without weak short substring rules. Neither suffix is covered by a proxy TLD or another proxy keyword. Python package-file hosts containing `python` are covered by the retained `python` keyword.

Both DOMAIN-SET files remain exclusively generated from IANA. The direct domain set contains only `.cn`, `.中国` and `.中國`; service domains belong in the companions. Two bounded direct suffixes, `amap.com` and `qq.com`, preserve map-service and Tencent/QQ/START base coverage without four-letter `amap` or two-letter `qq` keywords.

AMap remains limited to map-service namespaces: the precise `amap.com` companion suffix and `autonavi` keyword. `deepseek.com`, `baidu.com` and `alipay.com` remain covered by their explicit brand keywords. Tencent selections include `tencent`, `wechat`, `weixin`, `gtimg`, `qcloud`, `qqmail`, `wegame`, `weiyun`, `foxmail`, `qqbrowser`, `qqlive`, `qqmusic`, `codebuddy` and `workbuddy`; the precise `qq.com` companion suffix continues to cover QQ and START subdomains. Hongguo and related domestic services use `hongguo`, `changdunovel`, `fanqienovel`, `fqnovel`, `douyin`, `qishui` and other reviewed ByteDance service namespaces below.

The existing client order is retained: reject rules, both proxy companions, both direct companions, then IP fallbacks. No dedicated `qcloud.la` exception is introduced; individual country-code conflicts can be reviewed when an actual service issue occurs. The `hicloud` keyword is excluded because it contains the existing proxy keyword `icloud`.

## Proxy keyword evidence

| Keyword | Primary hostname | Reference |
| --- | --- | --- |
| `1password` | `1password.com` | [Source](https://formulae.brew.sh/api/cask/1password.json) |
| `adguard` | `adguard.com` | [Source](https://github.com/AdguardTeam/AdGuardHome) |
| `adoptium` | `adoptium.net` | [Source](https://formulae.brew.sh/api/cask/temurin@17.json) |
| `adtidy` | `static.adtidy.org` | [Source](https://github.com/AdguardTeam/AdGuardHome/blob/master/scripts/install.sh) |
| `alfredapp` | `www.alfredapp.com` | [Source](https://formulae.brew.sh/api/cask/alfred.json) |
| `amazon` | `www.amazon.com` | [Source](https://www.amazon.com/) |
| `android` | `developer.android.com` | [Source](https://formulae.brew.sh/api/cask/android-platform-tools.json) |
| `ansible` | `www.ansible.com` | [Source](https://formulae.brew.sh/api/formula/ansible.json) |
| `anthropic` | `www.anthropic.com` | [Source](https://www.anthropic.com/) |
| `apple` | `www.apple.com` | [Source](https://www.apple.com/) |
| `audacityteam` | `www.audacityteam.org` | [Source](https://formulae.brew.sh/api/cask/audacity.json) |
| `barebones` | `www.barebones.com` | [Source](https://formulae.brew.sh/api/cask/bbedit.json) |
| `bitwarden` | `bitwarden.com` | [Source](https://formulae.brew.sh/api/cask/bitwarden.json) |
| `blender` | `www.blender.org` | [Source](https://formulae.brew.sh/api/cask/blender.json) |
| `calibre-ebook` | `calibre-ebook.com` | [Source](https://formulae.brew.sh/api/cask/calibre.json) |
| `chatgpt` | `chatgpt.com` | [Source](https://chatgpt.com/) |
| `claude` | `claude.com` | [Source](https://formulae.brew.sh/api/cask/claude-code.json) |
| `cmake` | `www.cmake.org` | [Source](https://formulae.brew.sh/api/formula/cmake.json) |
| `crowdcafe` | `magnet.crowdcafe.com` | [Source](https://magnet.crowdcafe.com/) |
| `cursor` | `www.cursor.com` | [Source](https://formulae.brew.sh/api/cask/cursor.json) |
| `diagrams` | `www.diagrams.net` | [Source](https://formulae.brew.sh/api/cask/drawio.json) |
| `discord` | `discord.com` | [Source](https://formulae.brew.sh/api/cask/discord.json) |
| `docker` | `www.docker.com` | [Source](https://formulae.brew.sh/api/cask/docker-desktop.json) |
| `elmedia` | `www.elmedia-video-player.com` | [Source](https://www.elmedia-video-player.com/) |
| `exiftool` | `exiftool.org` | [Source](https://formulae.brew.sh/api/formula/exiftool.json) |
| `facebook` | `www.facebook.com` | [Source](https://www.facebook.com/) |
| `ffmpeg` | `ffmpeg.org` | [Source](https://formulae.brew.sh/api/formula/ffmpeg.json) |
| `flutter` | `flutter.dev` | [Source](https://formulae.brew.sh/api/cask/flutter.json) |
| `freemacsoft` | `freemacsoft.net` | [Source](https://formulae.brew.sh/api/cask/appcleaner.json) |
| `getutm` | `mac.getutm.app` | [Source](https://formulae.brew.sh/api/cask/utm.json) |
| `ghostty` | `ghostty.org` | [Source](https://formulae.brew.sh/api/cask/ghostty.json) |
| `github` | `github.com` | [Source](https://github.com/) |
| `gnupg` | `gnupg.org` | [Source](https://formulae.brew.sh/api/formula/gnupg.json) |
| `gnutls` | `gnutls.org` | [Source](https://formulae.brew.sh/api/formula/gnutls.json) |
| `google` | `www.google.com` | [Source](https://www.google.com/) |
| `graphviz` | `graphviz.org` | [Source](https://formulae.brew.sh/api/formula/graphviz.json) |
| `icloud` | `www.icloud.com` | [Source](https://www.icloud.com/) |
| `imagemagick` | `imagemagick.org` | [Source](https://formulae.brew.sh/api/formula/imagemagick.json) |
| `inkscape` | `inkscape.org` | [Source](https://formulae.brew.sh/api/cask/inkscape.json) |
| `instagram` | `www.instagram.com` | [Source](https://www.instagram.com/) |
| `iterm2` | `iterm2.com` | [Source](https://formulae.brew.sh/api/cask/iterm2.json) |
| `jetbrains` | `www.jetbrains.com` | [Source](https://formulae.brew.sh/api/cask/jetbrains-toolbox.json) |
| `jupyter` | `jupyter.org` | [Source](https://formulae.brew.sh/api/formula/jupyterlab.json) |
| `keepassxc` | `keepassxc.org` | [Source](https://formulae.brew.sh/api/cask/keepassxc.json) |
| `libreoffice` | `www.libreoffice.org` | [Source](https://formulae.brew.sh/api/cask/libreoffice.json) |
| `maccy` | `maccy.app` | [Source](https://formulae.brew.sh/api/cask/maccy.json) |
| `mariadb` | `mariadb.org` | [Source](https://formulae.brew.sh/api/formula/mariadb.json) |
| `microsoft` | `www.microsoft.com` | [Source](https://www.microsoft.com/) |
| `mongodb` | `www.mongodb.com` | [Source](https://formulae.brew.sh/api/cask/mongodb-compass.json) |
| `motrix` | `motrix.app` | [Source](https://formulae.brew.sh/api/cask/motrix.json) |
| `mozilla` | `www.mozilla.org` | [Source](https://formulae.brew.sh/api/cask/firefox.json) |
| `netflix` | `www.netflix.com` | [Source](https://www.netflix.com/) |
| `ngrok` | `ngrok.com` | [Source](https://formulae.brew.sh/api/cask/ngrok.json) |
| `nodejs` | `nodejs.org` | [Source](https://formulae.brew.sh/api/formula/node.json) |
| `notion` | `www.notion.com` | [Source](https://formulae.brew.sh/api/cask/notion.json) |
| `numpy` | `www.numpy.org` | [Source](https://formulae.brew.sh/api/formula/numpy.json) |
| `objective-see` | `objective-see.org` | [Source](https://formulae.brew.sh/api/cask/lulu.json) |
| `obsproject` | `obsproject.com` | [Source](https://formulae.brew.sh/api/cask/obs.json) |
| `omnigroup` | `www.omnigroup.com` | [Source](https://www.omnigroup.com/) |
| `openai` | `openai.com` | [Source](https://openai.com/) |
| `openssl` | `openssl-library.org` | [Source](https://formulae.brew.sh/api/formula/openssl@4.json) |
| `orbstack` | `orbstack.dev` | [Source](https://formulae.brew.sh/api/cask/orbstack.json) |
| `pandoc` | `pandoc.org` | [Source](https://formulae.brew.sh/api/formula/pandoc.json) |
| `parallels` | `www.parallels.com` | [Source](https://www.parallels.com/) |
| `pdfexpert` | `pdfexpert.com` | [Source](https://formulae.brew.sh/api/cask/pdf-expert.json) |
| `postman` | `www.postman.com` | [Source](https://formulae.brew.sh/api/cask/postman.json) |
| `primevideo` | `www.primevideo.com` | [Source](https://www.primevideo.com/) |
| `python` | `www.python.org` | [Source](https://formulae.brew.sh/api/formula/python@3.15.json) |
| `raycast` | `raycast.com` | [Source](https://formulae.brew.sh/api/cask/raycast.json) |
| `rclone` | `rclone.org` | [Source](https://formulae.brew.sh/api/formula/rclone.json) |
| `rectangleapp` | `rectangleapp.com` | [Source](https://formulae.brew.sh/api/cask/rectangle.json) |
| `reddit` | `www.reddit.com` | [Source](https://www.reddit.com/) |
| `rsync` | `rsync.samba.org` | [Source](https://formulae.brew.sh/api/formula/rsync.json) |
| `ruby-lang` | `www.ruby-lang.org` | [Source](https://formulae.brew.sh/api/formula/ruby.json) |
| `rust-lang` | `www.rust-lang.org` | [Source](https://formulae.brew.sh/api/formula/rust.json) |
| `sagernet` | `sagernet.org` | [Source](https://sagernet.org/) |
| `shellcheck` | `www.shellcheck.net` | [Source](https://formulae.brew.sh/api/formula/shellcheck.json) |
| `snapgene` | `www.snapgene.com` | [Source](https://www.snapgene.com/) |
| `spotify` | `www.spotify.com` | [Source](https://formulae.brew.sh/api/cask/spotify.json) |
| `sqlite` | `sqlite.org` | [Source](https://formulae.brew.sh/api/formula/sqlite.json) |
| `steampowered` | `store.steampowered.com` | [Source](https://formulae.brew.sh/api/cask/steam.json) |
| `sublimetext` | `www.sublimetext.com` | [Source](https://formulae.brew.sh/api/cask/sublime-text.json) |
| `surge` | `nssurge.com` | [Source](https://nssurge.com/) |
| `tableplus` | `tableplus.com` | [Source](https://formulae.brew.sh/api/cask/tableplus.json) |
| `tailscale` | `tailscale.com` | [Source](https://formulae.brew.sh/api/cask/tailscale-app.json) |
| `telegram` | `macos.telegram.org` | [Source](https://formulae.brew.sh/api/cask/telegram.json) |
| `termius` | `www.termius.com` | [Source](https://formulae.brew.sh/api/cask/termius.json) |
| `thunderbird` | `www.thunderbird.net` | [Source](https://formulae.brew.sh/api/cask/thunderbird.json) |
| `torproject` | `www.torproject.org` | [Source](https://formulae.brew.sh/api/cask/tor-browser.json) |
| `transmissionbt` | `transmissionbt.com` | [Source](https://formulae.brew.sh/api/cask/transmission.json) |
| `tukaani` | `tukaani.org` | [Source](https://formulae.brew.sh/api/formula/xz.json) |
| `videolan` | `www.videolan.org` | [Source](https://formulae.brew.sh/api/cask/vlc.json) |
| `visualstudio` | `code.visualstudio.com` | [Source](https://formulae.brew.sh/api/cask/visual-studio-code.json) |
| `wezterm` | `wezterm.org` | [Source](https://formulae.brew.sh/api/cask/wezterm.json) |
| `whatsapp` | `www.whatsapp.com` | [Source](https://www.whatsapp.com/) |
| `wireshark` | `www.wireshark.org` | [Source](https://formulae.brew.sh/api/cask/wireshark-app.json) |
| `youtube` | `www.youtube.com` | [Source](https://www.youtube.com/) |
| `zotero` | `www.zotero.org` | [Source](https://formulae.brew.sh/api/cask/zotero.json) |

## Precise proxy domains

| Rule | Reference |
| --- | --- |
| `DOMAIN-SUFFIX,7-zip.org` | [7-Zip](https://www.7-zip.org/), [Homebrew formula](https://formulae.brew.sh/api/formula/sevenzip.json) |
| `DOMAIN-SUFFIX,pypi.org` | [Python Package Index](https://pypi.org/) |

AdGuard Home attribution: its [official repository](https://github.com/AdguardTeam/AdGuardHome) identifies the `adguard.com` product site, and its [installation script](https://github.com/AdguardTeam/AdGuardHome/blob/master/scripts/install.sh) downloads packages from `static.adtidy.org`. The two keywords therefore cover the vendor site and installation/update distribution namespace.

## Precise direct domains

| Rule | Reference |
| --- | --- |
| `DOMAIN-SUFFIX,amap.com` | [AMap](https://www.amap.com/) |
| `DOMAIN-SUFFIX,qq.com` | [Tencent / QQ](https://www.qq.com/) |

## Direct service namespaces

These are established domestic application, platform and resource namespaces. The generated companion applies substring matching; it does not depend on the hostname being a subdomain of the illustrative primary domain.

| Keyword | Service namespace |
| --- | --- |
| `360buyimg` | [360buyimg.com](https://360buyimg.com/) |
| `abchina` | [abchina.com](https://abchina.com/) |
| `alibaba` | [alibaba.com](https://alibaba.com/) |
| `alicdn` | [alicdn.com](https://alicdn.com/) |
| `alipan` | [alipan.com](https://alipan.com/) |
| `alipay` | [alipay.com](https://alipay.com/) |
| `aliyun` | [aliyun.com](https://aliyun.com/) |
| `antfin` | [antfin.com](https://antfin.com/) |
| `antgroup` | [antgroup.com](https://antgroup.com/) |
| `autonavi` | [autonavi.com](https://autonavi.com/) |
| `baidu` | [baidu.com](https://baidu.com/) |
| `biliapi` | [biliapi.net](https://biliapi.net/) |
| `bilibili` | [bilibili.com](https://bilibili.com/) |
| `bilivideo` | [bilivideo.com](https://bilivideo.com/) |
| `bytedance` | [bytedance.com](https://bytedance.com/) |
| `bytegecko` | [bytegecko.com](https://bytegecko.com/) |
| `byteimg` | [byteimg.com](https://byteimg.com/) |
| `camscanner` | [camscanner.com](https://camscanner.com/) |
| `changdunovel` | [changdunovel.com](https://changdunovel.com/) |
| `chinamobile` | [chinamobile.com](https://chinamobile.com/) |
| `chinaunicom` | [chinaunicom.com](https://chinaunicom.com/) |
| `cmbchina` | [cmbchina.com](https://cmbchina.com/) |
| `cnblogs` | [cnblogs.com](https://cnblogs.com/) |
| `codebuddy` | [codebuddy.ai](https://codebuddy.ai/) |
| `damai` | [damai.cn](https://damai.cn/) |
| `deepseek` | [deepseek.com](https://deepseek.com/) |
| `dianping` | [dianping.com](https://dianping.com/) |
| `dingtalk` | [dingtalk.com](https://dingtalk.com/) |
| `dongchedi` | [dongchedi.com](https://dongchedi.com/) |
| `doubao` | [doubao.com](https://doubao.com/) |
| `douyin` | [douyin.com](https://douyin.com/) |
| `douyu` | [douyu.com](https://douyu.com/) |
| `dpfile` | [dpfile.com](https://dpfile.com/) |
| `fanqienovel` | [fanqienovel.com](https://fanqienovel.com/) |
| `feishu` | [feishu.net](https://feishu.net/) |
| `foxmail` | [foxmail.com](https://foxmail.com/) |
| `fqnovel` | [fqnovel.com](https://fqnovel.com/) |
| `gitee` | [gitee.com](https://gitee.com/) |
| `goofish` | [goofish.com](https://goofish.com/) |
| `gtimg` | [gtimg.com](https://gtimg.com/) |
| `hongguo` | [hongguoduanju.com](https://hongguoduanju.com/) |
| `huawei` | [huawei.com](https://huawei.com/) |
| `iqiyi` | [iqiyi.com](https://iqiyi.com/) |
| `ixigua` | [ixigua.com](https://ixigua.com/) |
| `jdcloud` | [jdcloud.com](https://jdcloud.com/) |
| `jdpay` | [jdpay.com](https://jdpay.com/) |
| `jianying` | [jianying.com](https://jianying.com/) |
| `kingsoft` | [kingsoft.com](https://kingsoft.com/) |
| `kuaishou` | [kuaishou.com](https://kuaishou.com/) |
| `liepin` | [liepin.com](https://liepin.com/) |
| `meituan` | [meituan.com](https://meituan.com/) |
| `miwifi` | [miwifi.com](https://miwifi.com/) |
| `netease` | [netease.com](https://netease.com/) |
| `oceanengine` | [oceanengine.com](https://oceanengine.com/) |
| `oppomobile` | [oppomobile.com](https://oppomobile.com/) |
| `oschina` | [oschina.net](https://oschina.net/) |
| `pddpic` | [pddpic.com](https://pddpic.com/) |
| `pinduoduo` | [pinduoduo.com](https://pinduoduo.com/) |
| `pipix` | [pipix.com](https://pipix.com/) |
| `qcloud` | [qcloud.com](https://qcloud.com/) |
| `qianwen` | [qianwen.com](https://qianwen.com/) |
| `qiniu` | [qiniu.com](https://qiniu.com/) |
| `qishui` | [qishui.com](https://qishui.com/) |
| `qqbrowser` | [qqbrowser.com](https://qqbrowser.com/) |
| `qqlive` | [qqlive.com](https://qqlive.com/) |
| `qqmail` | [qqmail.com](https://qqmail.com/) |
| `qqmusic` | [qqmusic.com](https://qqmusic.com/) |
| `realme` | [realme.com](https://realme.com/) |
| `rednote` | [rednote.com](https://rednote.com/) |
| `sankuai` | [sankuai.com](https://sankuai.com/) |
| `sogou` | [sogou.com](https://sogou.com/) |
| `taobao` | [taobao.com](https://taobao.com/) |
| `tencent` | [tencent.com](https://tencent.com/) |
| `tmall` | [tmall.com](https://tmall.com/) |
| `tongyi` | [tongyi.com](https://tongyi.com/) |
| `toutiao` | [toutiao.com](https://toutiao.com/) |
| `unionpay` | [unionpay.com](https://unionpay.com/) |
| `volcengine` | [volcengine.com](https://volcengine.com/) |
| `volces` | [volces.com](https://volces.com/) |
| `wechat` | [wechat.com](https://wechat.com/) |
| `wegame` | [wegame.com](https://wegame.com/) |
| `weibo` | [weibo.com](https://weibo.com/) |
| `weixin` | [weixin.qq.com](https://weixin.qq.com/) |
| `weiyun` | [weiyun.com](https://weiyun.com/) |
| `workbuddy` | [workbuddy.qq.com](https://workbuddy.qq.com/) |
| `xhscdn` | [xhscdn.com](https://xhscdn.com/) |
| `xiaohongshu` | [xiaohongshu.com](https://xiaohongshu.com/) |
| `xiaomi` | [xiaomi.com](https://xiaomi.com/) |
| `ximalaya` | [ximalaya.com](https://ximalaya.com/) |
| `xunlei` | [xunlei.com](https://xunlei.com/) |
| `yangkeduo` | [yangkeduo.com](https://yangkeduo.com/) |
| `ykimg` | [ykimg.com](https://ykimg.com/) |
| `youdao` | [youdao.com](https://youdao.com/) |
| `youku` | [youku.com](https://youku.com/) |
| `yuque` | [yuque.com](https://yuque.com/) |
| `zhaopin` | [zhaopin.com](https://zhaopin.com/) |
| `zhipin` | [zhipin.com](https://zhipin.com/) |
| `zhuanzhuan` | [zhuanzhuan.com](https://zhuanzhuan.com/) |

## Validation

Policy checks enforce declared counts, five-letter keyword minimums, uniqueness, same-policy substring pruning and bounded short-name suffixes. Native checks exercise both companions, short-name label boundaries and the existing proxy-before-direct priority. The standard build also compares all text/binary pairs, verifies manifests and checks deterministic ordering.
