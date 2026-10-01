"""Shared domestic-domain classification helpers."""

import re


MULTI_SUFFIXES = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "xn--fiqs8s", "xn--fiqz9s",
}

CN_SUFFIXES = tuple("." + suffix for suffix in MULTI_SUFFIXES) + (".cn",)


def registrable(host):
    labels = host.strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def load_brands(path):
    brands = set()
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip().lower()
            if line:
                brands.add(line)
    return brands


def brand_hit(host, brands):
    """Brand tokens carried by the registrable domain, if any."""
    hits = set()
    for label in registrable(host).split("."):
        for token in re.split(r"[-_]", label):
            if not token:
                continue
            if token in brands:
                hits.add(token)
                continue
            stripped = re.sub(r"\d+$", "", token)
            if stripped and stripped in brands:
                hits.add(stripped)
    return hits


def is_domestic(host, brands):
    return registrable(host).endswith(CN_SUFFIXES) or bool(brand_hit(host, brands))
