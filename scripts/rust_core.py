"""Build and invoke the locked Rust routing companion projection."""
from functools import lru_cache
import json
import os
from pathlib import Path
import shutil
import subprocess
from scope_compaction import compact_file

CODE_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = CODE_ROOT / "rust/ruleset-core/Cargo.toml"
RUST_SOURCES = {
    "rust_core": "rust/ruleset-core/src/main.rs",
    "rust_manifest": "rust/ruleset-core/Cargo.toml",
    "rust_lock": "rust/ruleset-core/Cargo.lock",
    "rust_bridge": "scripts/rust_core.py",
    "scope_compactor": "scripts/scope_compaction.py",
    "glob_optimizer": "scripts/glob_optimizer.py",
    "rule_sorting": "scripts/rule_sorting.py",
}


@lru_cache(maxsize=1)
def binary():
    cargo = shutil.which("cargo")
    if not cargo:
        raise RuntimeError("Rust and Cargo are required to build routing companions")
    subprocess.run([cargo, "build", "--release", "--locked", "--manifest-path", str(MANIFEST)], check=True)
    filename = "ruleset-core.exe" if os.name == "nt" else "ruleset-core"
    target = Path(os.environ.get("CARGO_TARGET_DIR", MANIFEST.parent / "target"))
    return target.resolve() / "release" / filename


def generate(root, output):
    output = Path(output)
    subprocess.run([str(binary()), "--root", str(Path(root).resolve()),
                    "--output-dir", str(output.resolve())], check=True)
    summary = json.loads((output / "companion-summary.json").read_text())
    plan_path = Path(root) / "source/companion-import.json"
    plan = json.loads(plan_path.read_text()) if plan_path.is_file() else {}
    counts = plan.get("rule_counts", {}) if plan.get("published_count_policy") == "exact" else {}
    summary["scope_compaction"] = {
        policy: compact_file(output / (policy.upper() + "-RULE-SET.list"), minimum_rules=counts.get(policy) or 0)
        for policy in ("proxy", "direct")}
    return summary
