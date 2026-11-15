# Client configuration

The examples use existing policy and outbound names. Substitute the configured
proxy policy, outbound tags and real-address DNS server where appropriate.

## Surge

Merge these `[Rule]` and `[Ruleset]` sections into the existing profile, using
its configured `PROXY` policy. They include the local direct exceptions,
pre-matching rejection, STUN rule, IP stages and the later `RESOLVE` group.

```ini
[Rule]
RULE-SET,SYSTEM_SET,DIRECT,extended-matching
RULE-SET,REJECT_SET,REJECT,pre-matching,extended-matching
RULE-SET,PROXY_SET,PROXY,extended-matching
RULE-SET,DIRECT_SET,DIRECT,extended-matching
RULE-SET,SYSTEM_IP,DIRECT,no-resolve
RULE-SET,REJECT_IP,REJECT,pre-matching,no-resolve
RULE-SET,PROXY_IP,PROXY,no-resolve
RULE-SET,DIRECT_IP,DIRECT,no-resolve
RULE-SET,RESOLVE,DIRECT
FINAL,PROXY

[Ruleset SYSTEM_SET]
DOMAIN-SUFFIX,swiftestonline.org,extended-matching
DOMAIN-SUFFIX,api.termius.com,extended-matching
DOMAIN-SUFFIX,dmit.io,extended-matching

[Ruleset SYSTEM_IP]
IP-CIDR6,2605:52c0:2:3b09::/64,no-resolve
IP-CIDR,64.186.239.96/32,no-resolve

[Ruleset REJECT_SET]
PROTOCOL,STUN
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list,extended-matching,"update-interval=43200"
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list,extended-matching,"update-interval=43200"

[Ruleset REJECT_IP]
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list,"update-interval=43200",no-resolve

[Ruleset PROXY_SET]
RULE-SET,SYSTEM,extended-matching
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.list,extended-matching,"update-interval=43200"
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.list,extended-matching,"update-interval=43200"

[Ruleset PROXY_IP]
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.list,"update-interval=43200",no-resolve

[Ruleset DIRECT_SET]
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.list,extended-matching,"update-interval=43200"
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.list,extended-matching,"update-interval=43200"

[Ruleset DIRECT_IP]
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.list,"update-interval=43200",no-resolve

[Ruleset RESOLVE]
RULE-SET,LAN
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.list,"update-interval=43200"
```

Keywords require `RULE-SET`; they cannot be represented by `DOMAIN-SET`.
`IP-SET` is an artefact naming convention and is loaded with `RULE-SET`.
The reject companion contains maintained suffixes, substring keywords and the
two preserved AND conditions. A suffix covers its apex and descendants.
STUN is configured locally in `REJECT_SET`. The `RESOLVE` group references
`LAN` and `DIRECT-IP-SET` after the earlier `no-resolve` IP stage.

## sing-box

The published binaries use rule-set format version 5 and require sing-box 1.14.0
or later. Builds use a checksum-verified 1.14.4 compiler.
The route fragment requires existing `proxy`, `direct` and `dns-real` tags.

```json
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "REJECT-DOMAIN-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.srs"
      },
      {
        "type": "remote",
        "tag": "REJECT-RULE-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.srs"
      },
      {
        "type": "remote",
        "tag": "REJECT-IP-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.srs"
      },
      {
        "type": "remote",
        "tag": "PROXY-RULE-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.srs"
      },
      {
        "type": "remote",
        "tag": "PROXY-DOMAIN-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.srs"
      },
      {
        "type": "remote",
        "tag": "DIRECT-RULE-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.srs"
      },
      {
        "type": "remote",
        "tag": "DIRECT-DOMAIN-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.srs"
      },
      {
        "type": "remote",
        "tag": "PROXY-IP-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.srs"
      },
      {
        "type": "remote",
        "tag": "DIRECT-IP-SET",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.srs"
      }
    ],
    "rules": [
      {
        "action": "sniff",
        "sniffer": ["stun"]
      },
      {
        "protocol": "stun",
        "action": "reject"
      },
      {
        "rule_set": ["REJECT-DOMAIN-SET", "REJECT-RULE-SET"],
        "action": "reject"
      },
      {
        "action": "resolve",
        "server": "dns-real"
      },
      {
        "rule_set": ["REJECT-IP-SET"],
        "action": "reject"
      },
      {
        "rule_set": ["PROXY-RULE-SET"],
        "action": "route",
        "outbound": "proxy"
      },
      {
        "rule_set": ["PROXY-DOMAIN-SET"],
        "action": "route",
        "outbound": "proxy"
      },
      {
        "rule_set": ["DIRECT-RULE-SET"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": ["DIRECT-DOMAIN-SET"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": ["PROXY-IP-SET"],
        "action": "route",
        "outbound": "proxy"
      },
      {
        "rule_set": ["DIRECT-IP-SET"],
        "action": "route",
        "outbound": "direct"
      }
    ]
  }
}
```

Destination resolution precedes IP rejection and IP fallback routing. The DNS
server must return real destination addresses; terminal outbound resolution
would occur too late for these IP checks.

The example independently configures STUN sniffing and rejection; STUN is not
part of the three domain-only RULE-SET companions.
Routing sets do not reproduce CNAME-chain inspection, multi-answer DNS filtering
or DNS response codes.

## References

- [Surge domain rules](https://manual.nssurge.com/rules/domain.html)
- [Surge rule sets](https://manual.nssurge.com/rules/ruleset.html)
- [sing-box remote rule sets](https://sing-box.sagernet.org/configuration/rule-set/)
- [sing-box headless rule schema](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/)
