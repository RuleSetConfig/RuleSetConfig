#!/usr/bin/env python3
"""Retain the newest verified published Release and remove older publications."""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


PAIRS = {policy + "-" + kind for policy in ("PROXY", "DIRECT", "REJECT")
         for kind in ("DOMAIN-SET", "RULE-SET", "IP-SET")}
MANIFESTS = {name + "-manifest.json"
             for name in ("filter", "tld", "keywords", "direct-ip", "proxy-ip")}
ASSETS = {name + ext for name in PAIRS for ext in (".list", ".srs")} | MANIFESTS | {"SHA256SUMS"}


def list_releases(api, repository):
    releases = []
    page = 1
    while True:
        batch = api("GET", f"repos/{repository}/releases?per_page=100&page={page}")
        if not isinstance(batch, list):
            raise ValueError("The Release inventory is not an array.")
        releases.extend(batch)
        ids = [release["id"] for release in releases]
        if len(ids) != len(set(ids)):
            raise ValueError("The Release inventory contains duplicate identifiers.")
        if len(batch) < 100:
            return releases
        page += 1


def deletion_plan(releases, keep_tag):
    matches = [release for release in releases if release.get("tag_name") == keep_tag]
    if len(matches) != 1 or matches[0].get("draft") or not matches[0].get("published_at"):
        raise ValueError("The retained Release must be a unique published snapshot.")
    keep = matches[0]
    published = [release for release in releases if not release.get("draft")]
    def chronology(release):
        return datetime.fromisoformat(release["published_at"]), release["id"]
    if max(published, key=chronology)["id"] != keep["id"]:
        raise ValueError("A newer Release exists; historical removal has been stopped.")
    targets = sorted((release for release in published if release["id"] != keep["id"]),
                     key=chronology)
    return keep, targets


def verify_assets(release, directory):
    directory = Path(directory)
    if {path.name for path in directory.iterdir()} != ASSETS:
        raise ValueError("The downloaded asset inventory is incomplete or unexpected.")
    checksums = {}
    for line in (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if not match or match[2] not in ASSETS - {"SHA256SUMS"} or match[2] in checksums:
            raise ValueError("The checksum inventory is invalid.")
        checksums[match[2]] = match[1]
    if set(checksums) != ASSETS - {"SHA256SUMS"}:
        raise ValueError("The checksum inventory is incomplete.")
    assets = release.get("assets", [])
    remote = {asset["name"]: asset for asset in assets}
    if set(remote) != ASSETS or len(remote) != len(assets):
        raise ValueError("The uploaded asset inventory is incomplete or duplicated.")
    for name in sorted(ASSETS):
        path = directory / name
        if not path.is_file():
            raise ValueError("A downloaded asset is not a regular file.")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if name in checksums and checksums[name] != digest:
            raise ValueError("A downloaded asset does not match SHA256SUMS: " + name)
        asset = remote[name]
        if (asset.get("state") != "uploaded" or asset.get("size") != len(data)
                or asset.get("digest") not in (None, "sha256:" + digest)):
            raise ValueError("An uploaded asset does not match the verified download: " + name)


def prune(api, repository, keep_tag, directory):
    releases = list_releases(api, repository)
    keep, targets = deletion_plan(releases, keep_tag)
    verify_assets(keep, directory)
    for release in targets:
        api("DELETE", f"repos/{repository}/releases/{release['id']}")
        print("Removed historical Release: " + release["tag_name"])
    remaining = [release for release in list_releases(api, repository) if not release.get("draft")]
    if len(remaining) != 1 or remaining[0]["id"] != keep["id"]:
        raise ValueError("The final Release inventory differs from the retention policy.")
    print("Retained verified Release: " + keep_tag)
    return len(targets)


def github_api(method, path):
    response = subprocess.run(["gh", "api", "--method", method, path],
                              check=True, capture_output=True, text=True)
    return json.loads(response.stdout) if response.stdout.strip() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--keep-tag", required=True)
    parser.add_argument("--verified-directory", required=True)
    args = parser.parse_args()
    if not args.repository or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("A valid owner/repository identifier is required.")
    prune(github_api, args.repository, args.keep_tag, args.verified_directory)


if __name__ == "__main__":
    main()
