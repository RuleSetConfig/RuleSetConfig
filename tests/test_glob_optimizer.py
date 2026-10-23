import fnmatch, itertools, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from glob_optimizer import Glob, Inclusion, parse, render, factor_classes, prune_subsumed

class OptimizerTests(unittest.TestCase):

    def test_known_inclusions_and_counterexamples(self):
        engine = Inclusion()
        for small, big in [('ab*', 'a*'), ('a?b', 'a*b'), ('*.example.com', '*example.com'), ('a[12].test', 'a[0-9].test'), ('x*.a', '*a'), ('ab', '?*')]:
            self.assertIsNotNone(engine.prove(small, big), (small, big))
        for small, big in [('a*', 'ab*'), ('*example.com', '*.example.com'), ('a*b', 'a?b'), ('*a', 'a*'), ('[ab]x', 'ax'), ('a*b*', 'a*b')]:
            self.assertIsNone(engine.prove(small, big), (small, big))

    def test_automaton_matches_independent_glob_implementation(self):
        patterns = ['*', '?', 'a*', '*a', 'a?', '[ab]a', 'a*a', '*a*', 'a', 'b', '*.*', 'a.b', '*.b', 'a?b', 'a*b', 'a*b*']
        strings = [''.join(t) for length in range(6) for t in itertools.product('ab.', repeat=length)]
        for pattern in patterns:
            automaton = Glob(pattern)
            for value in strings:
                self.assertEqual(automaton.match(value), fnmatch.fnmatchcase(value, pattern), (pattern, value))

    def test_inclusion_proofs_have_no_finite_counterexamples(self):
        patterns = ['*', '?', 'a*', '*a', 'a?', '[ab]a', 'a*a', '*a*', 'a', 'b', '*.*', 'a.b', '*.b', 'a?b', 'a*b', 'a*b*']
        strings = [''.join(t) for length in range(6) for t in itertools.product('ab.', repeat=length)]
        engine = Inclusion()
        for a, b in itertools.product(patterns, repeat=2):
            if engine.prove(a, b) is not None:
                self.assertFalse(any((fnmatch.fnmatchcase(v, a) and (not fnmatch.fnmatchcase(v, b)) for v in strings)), (a, b))

    def test_factorization_preserves_missing_cartesian_combinations(self):
        original = {'aa.example', 'ab.example', 'ba.example'}
        optimized, steps = factor_classes(original)
        self.assertTrue(steps)
        for prefix in [''.join(t) for t in itertools.product('ab', repeat=2)]:
            value = prefix + '.example'
            self.assertEqual(any((fnmatch.fnmatchcase(value, m) for m in original)), any((fnmatch.fnmatchcase(value, m) for m in optimized)))
        self.assertFalse(any((fnmatch.fnmatchcase('bb.example', m) for m in optimized)))

    def test_factorization_of_digit_classes(self):
        original = {'pc[1-3].test', 'pc[2-4].test'}
        optimized, steps = factor_classes(original)
        self.assertEqual(optimized, {'pc[1-4].test'})
        for n in range(10):
            self.assertEqual(any((fnmatch.fnmatchcase('pc' + str(n) + '.test', m) for m in original)), any((fnmatch.fnmatchcase('pc' + str(n) + '.test', m) for m in optimized)))

    def test_unproven_inclusion_retains_rules(self):
        engine = Inclusion(max_states=1)
        retained, removed = prune_subsumed({'a*b', 'a*'}, engine)
        self.assertEqual(retained, {'a*b', 'a*'})
        self.assertEqual(removed, [])

    def test_roundtrip_and_other_character(self):
        for mask in ['a**b', '[ab]*.[0-9]x', '[-ab]??.test', '[a-z0-9_]', '??*']:
            self.assertEqual(parse(mask), parse(render(parse(mask))))
        self.assertTrue(Glob('*').match('aé'))
        self.assertFalse(Glob('[ab]').match('é'))
if __name__ == '__main__':
    unittest.main(verbosity=2)
