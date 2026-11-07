"""Brand balance must retain scope and cannot disguise padding as coverage."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from coverage_priority import BrandCatalog, diverse_select
from scope_compaction import compact_text, records, expand_text


class CoveragePriorityTests(unittest.TestCase):
    def test_large_family_cannot_crowd_out_other_families(self):
        rows=[('large',i) for i in range(100)]+[('small-a',0),('small-b',0)]
        selected=diverse_select(rows,3,lambda r:r[0],lambda r:r)
        self.assertEqual({r[0] for r in selected},{'large','small-a','small-b'})
        self.assertEqual(selected,diverse_select(list(reversed(rows)),3,lambda r:r[0],lambda r:r))

    def test_preserved_scopes_are_kept_before_balancing_representatives(self):
        rows=[('a',i) for i in range(6)]+[('b',0),('c',0)]
        selected=diverse_select(rows,5,lambda r:r[0],lambda r:r,mandatory=[('a',0),('a',1),('a',2)])
        self.assertEqual(set(selected),{('a',0),('a',1),('a',2),('b',0),('c',0)})
        with self.assertRaisesRegex(ValueError,'refusing padding'):
            diverse_select(rows,20,lambda r:r[0],lambda r:r)

    def test_catalogue_exact_namespace_does_not_classify_cloud_tenants(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'catalog.json'
            data={'schema':1,'source':{'sha256':'pinned'},'groups':{
                'brand':{'suffixes':['brand.example'],'exact':[]},
                'cloud':{'suffixes':[],'exact':['shared.example']}}}
            p.write_text(json.dumps(data));catalog=BrandCatalog(p,expected_source={'sha256':'pinned'})
            self.assertEqual(catalog.family('x.brand.example'),'brand')
            self.assertIsNone(catalog.family('notbrand.example'))
            self.assertIsNone(catalog.family('brand.example.invalid'))
            self.assertEqual(catalog.family('shared.example'),'cloud')
            self.assertIsNone(catalog.family('tenant.shared.example'))
            with self.assertRaisesRegex(ValueError,'fingerprint'):
                BrandCatalog(p,expected_source={'sha256':'different'})

    def test_count_floor_preserves_selected_inventory_and_requested_order(self):
        source='\n'.join('DOMAIN,very-long-service-'+str(i)+'.example.com' for i in range(10))+'\n'
        text,audit=compact_text(source,minimum_rules=10)
        self.assertEqual(len(records(text)),10)
        self.assertEqual(set(records(expand_text(text))),set(records(source)))
        self.assertEqual(audit['rules_removed'],0)
        with self.assertRaises(ValueError):compact_text(source,minimum_rules=11)


if __name__=='__main__':unittest.main()
