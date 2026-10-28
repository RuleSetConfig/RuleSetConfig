# Client configuration

The examples use existing policy and outbound names. Substitute the configured
proxy policy, outbound tags and real-address DNS server where appropriate.

## Surge

Insert these entries in the existing `[Rule]` section. Rejection precedes
routing; both proxy companions precede both direct companions, followed by IP fallbacks.

```ini
[Rule]
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-DOMAIN-SET.list,REJECT
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-RULE-SET.list,REJECT
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/REJECT-IP-SET.list,REJECT

RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-RULE-SET.list,PROXY
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-DOMAIN-SET.list,PROXY

RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-RULE-SET.list,DIRECT
DOMAIN-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-DOMAIN-SET.list,DIRECT

RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/PROXY-IP-SET.list,PROXY
RULE-SET,https://raw.githubusercontent.com/RuleSetConfig/RuleSetConfig/main/DIRECT-IP-SET.list,DIRECT
```

Keywords require `RULE-SET`; they cannot be represented by `DOMAIN-SET`.
`IP-SET` is an artefact naming convention and is loaded with `RULE-SET`.
The reject pattern list contains STUN and User-Agent rules, so its reference
must not enable pre-matching. User-Agent matching requires visibility of HTTP
headers and is subject to Surge's HTTPS inspection limitations.

## sing-box

The published binaries use rule-set format version 5 and require sing-box 1.14.0
or later. Builds use a checksum-verified 1.14.2 compiler.
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

SRS cannot represent Surge protocol or User-Agent rules. The example provides
separate STUN sniffing and rejection; the User-Agent rule remains Surge-only.
Routing sets do not reproduce CNAME-chain inspection, multi-answer DNS filtering
or DNS response codes.

## References

- [Surge domain rules](https://manual.nssurge.com/rules/domain.html)
- [Surge rule sets](https://manual.nssurge.com/rules/ruleset.html)
- [sing-box remote rule sets](https://sing-box.sagernet.org/configuration/rule-set/)
- [sing-box headless rule schema](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/)
