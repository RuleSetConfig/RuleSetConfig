"""Protect finite compaction against missing cells, suffix leaks and tampering."""
from collections import Counter
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_compaction import compact_text, expand_text, records, PREFIX
from filter_patterns import wildcard_regex


class ScopeCompactionTests(unittest.TestCase):
    def source(self, kind, ids=range(10)):
        names = [f"very-long-service-node-{i}.tenant.example.com" for i in ids]
        return "# fixture\n" + "".join(kind + "," + n + "\n" for n in names), names

    def masks(self, text):
        return [re.compile(wildcard_regex(line.split(",", 1)[1]))
                for line in records(text) if line.startswith("DOMAIN-WILDCARD,")]

    def test_exact_compaction_keeps_apex_only_and_no_neighbour(self):
        source, names = self.source("DOMAIN")
        text, audit = compact_text(source)
        self.assertLess(audit["published_rules"], audit["source_rules"])
        self.assertLess(len(text.encode()), len(source.encode()))
        self.assertEqual(Counter(records(expand_text(text))), Counter(records(source)))
        masks = self.masks(text)
        for name in names:
            self.assertTrue(any(p.fullmatch(name.upper()) for p in masks))
            self.assertFalse(any(p.fullmatch("child." + name) for p in masks))
        self.assertFalse(any(p.fullmatch(names[0].replace("node-0", "node-x")) for p in masks))

    def test_suffix_compaction_keeps_apex_and_all_descendant_depths(self):
        source, names = self.source("DOMAIN-SUFFIX")
        text, audit = compact_text(source, direct=True)
        self.assertEqual(audit["published_rules"], 2)
        self.assertEqual(Counter(records(expand_text(text))), Counter(records(source)))
        masks = self.masks(text)
        for name in names:
            for host in [name, "child." + name, "one.two." + name]:
                self.assertTrue(any(p.fullmatch(host) for p in masks))
            for host in ["not" + name, name + ".invalid"]:
                self.assertFalse(any(p.fullmatch(host) for p in masks))

    def test_sparse_cartesian_product_does_not_add_the_missing_cell(self):
        names = [f"very-long-service-node-{a}{b}.tenant.example.com"
                 for a in range(4) for b in range(4) if (a, b) != (3, 3)]
        source = "".join("DOMAIN," + n + "\n" for n in names)
        text, _ = compact_text(source)
        self.assertEqual(Counter(records(expand_text(text))), Counter(records(source)))
        missing = "very-long-service-node-33.tenant.example.com"
        self.assertFalse(any(p.fullmatch(missing) for p in self.masks(text)))

    def test_suffix_certificate_rejects_a_missing_child_row_or_dot(self):
        source, _ = self.source("DOMAIN-SUFFIX")
        text, _ = compact_text(source)
        child = next(s for s in records(text) if s.startswith("DOMAIN-WILDCARD,*."))
        for changed in [text.replace(child + "\n", ""), text.replace(child, child.replace("*.", "*", 1))]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                expand_text(changed)

    def test_nonbeneficial_pair_is_retained_and_opaque_rules_are_unchanged(self):
        source, _ = self.source("DOMAIN", range(2))
        opaque = "PROCESS-NAME,trustd\nAND,((DOMAIN-KEYWORD,alpha),(DOMAIN-KEYWORD,bravo))\n"
        text, audit = compact_text(source + opaque)
        self.assertEqual(audit["rules_removed"], 0)
        self.assertEqual(Counter(records(text)), Counter(records(source + opaque)))

    def test_compaction_is_deterministic_and_idempotent(self):
        source, _ = self.source("DOMAIN-SUFFIX")
        first, _ = compact_text(source, direct=True)
        shuffled = "# fixture\n" + "\n".join(reversed(records(source))) + "\n"
        self.assertEqual(compact_text(shuffled, direct=True)[0], first)
        self.assertEqual(compact_text(first, direct=True)[0], first)

    def test_certificate_alone_cannot_override_the_srs_scope(self):
        source, names = self.source("DOMAIN")
        text, _ = compact_text(source)
        text = text.replace("[0-9]", "[0-9a]")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "PROXY-RULE-SET.list"; path.write_text(text)
            document = root / "original.json"
            document.write_text(json.dumps({"version": 5, "rules": [{"domain": names}]}))
            spec = importlib.util.spec_from_file_location("scope_verify", ROOT / "scripts/verify-all.py")
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertEqual(module.verify(path, document), 1)


if __name__ == "__main__":
    unittest.main()
