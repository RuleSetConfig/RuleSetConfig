"""Shared hostname-pattern representation for Surge and sing-box.

Hostname masks and bounded IP targets are projected. URL schemes/paths and scoped DNS
modifiers are audited, never stripped to produce broader domain blocks.
Surge has no arbitrary domain-regex rule: a bounded regex subset is expanded
into equivalent wildcard masks. Unknown regex constructs stop publication.
"""
import itertools
import re
try:
    from re import _parser as regex_parser
except ImportError:  # Python 3.9
    import sre_parse as regex_parser

KINDS = {"domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX",
         "domain_keyword": "DOMAIN-KEYWORD", "domain_wildcard": "DOMAIN-WILDCARD", "ip_cidr": "IP-CIDR"}
LIMIT = 512


def split_options(line):
    # '$' inside /...$/ is a regex anchor, not an Adblock modifier separator.
    if line.startswith("/"):
        end = line.rfind("/")
        if end > 0:
            tail = line[end + 1:]
            if not tail or tail.startswith("$"):
                return line[:end + 1], tail[1:] if tail else ""
    return tuple(line.split("$", 1)) if "$" in line else (line, "")


def wildcard_regex(mask):
    """Translate our restricted Surge glob alphabet to portable RE2."""
    out, i = [], 0
    while i < len(mask):
        c = mask[i]
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        elif c == "[":
            end = mask.find("]", i + 1)
            if end < 0 or not re.fullmatch(r"[a-zA-Z0-9_\-]+", mask[i+1:end]):
                raise ValueError(f"unsupported wildcard class: {mask}")
            out.append(mask[i:end+1])
            i = end
        elif re.fullmatch(r"[a-zA-Z0-9_.\-]", c):
            out.append(re.escape(c))
        else:
            raise ValueError(f"unsupported wildcard character: {mask}")
        i += 1
    return "(?i)^" + "".join(out) + "$"


def product(parts):
    result = [""]
    for choices in parts:
        if len(result) * len(choices) > LIMIT:
            raise ValueError("regex expansion exceeds 512 masks")
        result = [a + b for a in result for b in choices]
    return result


def regex_globs(expression):
    """Exact expansion on ASCII/IDNA hostnames; no URL or IP-route projection."""
    parsed = regex_parser.parse(expression, flags=re.ASCII)
    nodes = list(parsed)
    start = bool(nodes and str(nodes[0][0]) == "AT" and
                 str(nodes[0][1]) in {"AT_BEGINNING", "AT_BEGINNING_STRING"})
    end = bool(nodes and str(nodes[-1][0]) == "AT" and
               str(nodes[-1][1]) in {"AT_END", "AT_END_STRING"})
    if end:
        nodes.pop()
    if start:
        nodes.pop(0)

    def expand(tokens):
        parts = []
        for op, arg in tokens:
            op = str(op)
            if op == "LITERAL":
                c = chr(arg)
                if not re.fullmatch(r"[a-zA-Z0-9_.\-]", c):
                    raise ValueError("non-host regex literal")
                choices = [c.lower()]
            elif op == "ANY":
                choices = ["?"]
            elif op == "IN":
                value = ""
                for kind, val in arg:
                    kind = str(kind)
                    if kind == "LITERAL" and re.fullmatch(r"[a-zA-Z0-9_]", chr(val)):
                        value += chr(val).lower()
                    elif kind == "RANGE" and all(re.fullmatch(r"[a-zA-Z0-9]", chr(v)) for v in val):
                        value += chr(val[0]).lower() + "-" + chr(val[1]).lower()
                    elif kind == "CATEGORY" and str(val) == "CATEGORY_DIGIT":
                        value += "0-9"
                    elif kind == "CATEGORY" and str(val) == "CATEGORY_WORD":
                        value += "a-z0-9_"
                    else:
                        raise ValueError("unsupported regex character class")
                choices = ["[" + value + "]"]
            elif op == "SUBPATTERN":
                if arg[1] or arg[2]:
                    raise ValueError("unsupported regex flags")
                choices = expand(arg[3])
            elif op == "BRANCH":
                choices = [v for branch in arg[1] for v in expand(branch)]
            elif op in {"MAX_REPEAT", "MIN_REPEAT"}:
                lo, hi, child = arg
                if lo == 0 and str(hi) == "MAXREPEAT" and len(child) == 1 and str(child[0][0]) == "ANY":
                    choices = ["*"]
                elif hi <= 64:
                    unit = expand(child)
                    choices = [v for n in range(lo, hi+1) for v in product([unit] * n)]
                else:
                    raise ValueError("unbounded or oversized regex repetition")
            else:
                raise ValueError(f"unsupported regex opcode {op}")
            parts.append(choices)
        return product(parts)

    return sorted({("" if start else "*") + p + ("" if end else "*") for p in expand(nodes)})


def mask_rules(pattern):
    """AdGuard DNS hostname mask -> canonical exact/suffix/keyword/glob rules."""
    suffix = pattern.startswith("||")
    anchored = pattern.startswith("|") and not suffix
    body = pattern[2:] if suffix else pattern[1:] if anchored else pattern
    right = body.endswith(("^", "|"))
    if body.endswith("^|"):
        body = body[:-2]
    elif right:
        body = body[:-1]
    if not body or not re.fullmatch(r"[a-zA-Z0-9_.\-*]+", body):
        return None, "non-host-pattern"
    body = body.lower()
    # A plain domain line is AdGuard's exact-domain list syntax.
    plain_domain = (not suffix and not anchored and not right and "*" not in body
                    and "." in body and not body.startswith((".", "-")) and not body.endswith((".", "-")))
    if plain_domain:
        return [("domain", body)], "accepted"
    if suffix and right and "*" not in body:
        return [("domain_suffix", body)], "accepted"
    if anchored and right and "*" not in body:
        return [("domain", body)], "accepted"
    if not suffix and not anchored and not right and "*" not in body:
        return [("domain_keyword", body)], "accepted"
    tail = "" if right else "*"
    if suffix:
        masks = [body + tail]
        if not body.startswith("*"):
            masks.append("*." + body + tail)
    else:
        masks = [("" if anchored else "*") + body + tail]
    return [("domain_wildcard", re.sub(r"\*+", "*", m)) for m in masks], "accepted"


def ipv4_regex_networks(expression, masks):
    """Project bounded numeric IPv4 regexes to exact destination IP coverage.

    An unescaped dot is safe here only if consuming a digit instead of a dot
    would make the adjacent octet contain more than three digits.
    """
    import ipaddress
    if not re.match(r"\^?[0-9]", expression):
        return []
    addresses = set()
    original = re.compile(expression, re.ASCII)
    for mask in masks:
        if not re.fullmatch(r"[0-9.\[\]*?\-]+", mask):
            raise ValueError("numeric IP regex requires manual review")
        octets = re.split(r"[.?]", mask)
        if len(octets) != 4:
            raise ValueError("IP regex must have four octets")
        separators = re.findall(r"[.?]", mask)
        lengths = [len(re.sub(r"\[[^]]+\]", "0", x).replace("*", "")) for x in octets]
        for i, sep in enumerate(separators):
            if sep == "?" and lengths[i] + lengths[i+1] + 1 <= 3:
                raise ValueError("ambiguous unescaped dot in IP regex")
        options = []
        for octet in octets:
            regex = re.compile(wildcard_regex(octet))
            options.append([str(i) for i in range(256) if regex.fullmatch(str(i))])
        count = 1
        for values in options:
            count *= len(values)
        if count > 65536:
            raise ValueError("IP regex expands beyond 65536 addresses")
        for values in itertools.product(*options):
            address = ".".join(values)
            if original.search(address):
                addresses.add(ipaddress.ip_address(address))
    return [str(n) for n in ipaddress.collapse_addresses(sorted(addresses))]
