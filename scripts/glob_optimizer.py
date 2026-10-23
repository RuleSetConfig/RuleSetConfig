"""Conservative, auditable optimization of DNS hostname glob languages.

Proof alphabet partitions normalized hostname characters and one OTHER class.
Unproven/over-budget inclusion checks retain their inputs.
"""
from collections import defaultdict, deque
ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789_.-' + '\x00'
INDEX = {c: i for i, c in enumerate(ALPHABET)}
ALL = (1 << len(ALPHABET)) - 1
STAR = -1

def parse(mask):
    result = []
    i = 0
    while i < len(mask):
        c = mask[i].lower()
        if c == '*':
            if not result or result[-1] != STAR:
                result.append(STAR)
        elif c == '?':
            result.append(ALL)
        elif c == '[':
            end = mask.index(']', i + 1)
            body = mask[i + 1:end].lower()
            chars = set()
            j = 0
            while j < len(body):
                if j + 2 < len(body) and body[j + 1] == '-' and (body[j] != '-') and (body[j + 2] != '-'):
                    if ord(body[j]) > ord(body[j + 2]):
                        raise ValueError('invalid class range')
                    chars.update((chr(k) for k in range(ord(body[j]), ord(body[j + 2]) + 1)))
                    j += 3
                else:
                    chars.add(body[j])
                    j += 1
            value = 0
            for char in chars:
                value |= 1 << INDEX[char]
            if not value:
                raise ValueError('empty class')
            result.append(value)
            i = end
        else:
            result.append(1 << INDEX[c])
        i += 1
    return tuple(result)

def class_text(value):
    if value == ALL:
        return '?'
    chars = {c for c, index in INDEX.items() if value & 1 << index}
    if len(chars) == 1:
        return next(iter(chars))
    if '.' in chars or '\x00' in chars:
        return None
    parts = '-' if '-' in chars else ''
    for alphabet in ('0123456789', 'abcdefghijklmnopqrstuvwxyz'):
        group = [c for c in alphabet if c in chars]
        i = 0
        while i < len(group):
            j = i + 1
            while j < len(group) and ord(group[j]) == ord(group[j - 1]) + 1:
                j += 1
            parts += group[i] + '-' + group[j - 1] if j - i >= 3 else ''.join(group[i:j])
            i = j
    if '_' in chars:
        parts += '_'
    return '[' + parts + ']'

def render(tokens):
    parts = []
    for token in tokens:
        part = '*' if token == STAR else class_text(token)
        if part is None:
            return None
        parts.append(part)
    return ''.join(parts)

class Glob:

    def __init__(self, mask):
        self.mask = mask
        self.tokens = parse(mask)
        self.length = len(self.tokens)
        self.minimum = sum((t != STAR for t in self.tokens))
        self.star_mask = sum((1 << i for i, t in enumerate(self.tokens) if t == STAR))
        self.char_masks = [sum((1 << i for i, t in enumerate(self.tokens) if t != STAR and t & 1 << c)) for c in range(len(ALPHABET))]
        self.accept = 1 << self.length
        self.start = self.closure(1)
        self.cache = {}
        self.witnesses = tuple((self.witness(fill) for fill in ('', 'x', 'a.b')))

    def closure(self, state):
        # Adjacent stars are normalized, so one epsilon step is sufficient.
        return state | (state & self.star_mask) << 1

    def step(self, state, column):
        key = (state, column)
        if key not in self.cache:
            self.cache[key] = self.closure(state & self.star_mask | (state & self.char_masks[column]) << 1)
        return self.cache[key]

    def witness(self, fill):
        return ''.join((fill if t == STAR else ALPHABET[(t & -t).bit_length() - 1] for t in self.tokens))

    def match(self, text):
        state = self.start
        for char in text.lower():
            state = self.step(state, INDEX.get(char, len(ALPHABET) - 1))
        return bool(state & self.accept)

class Inclusion:

    def __init__(self, max_states=20000):
        self.max_states = max_states
        self.globs = {}
        self.cache = {}
        self.stats = defaultdict(int)

    def glob(self, mask):
        if mask not in self.globs:
            self.globs[mask] = Glob(mask)
        return self.globs[mask]

    def prove(self, smaller, larger):
        if smaller == larger:
            return {'states': 0, 'proof': 'identical'}
        key = (smaller, larger)
        if key in self.cache:
            return self.cache[key]
        a = self.glob(smaller)
        b = self.glob(larger)
        self.stats['candidate_pairs'] += 1
        if b.minimum > a.minimum or any((not b.match(w) for w in a.witnesses)):
            self.stats['rejected_by_witness'] += 1
            return None
        queue = deque([(a.start, b.start)])
        visited = {(a.start, b.start)}
        while queue:
            left, right = queue.popleft()
            if left & a.accept and (not right & b.accept):
                self.stats['formal_counterexamples'] += 1
                self.cache[key] = None
                return None
            successors = set()
            for column in range(len(ALPHABET)):
                next_left = a.step(left, column)
                if next_left:
                    successors.add((next_left, b.step(right, column)))
            for pair in successors:
                if pair in visited:
                    continue
                visited.add(pair)
                if len(visited) > self.max_states:
                    self.stats['unproven_budget_limit'] += 1
                    self.cache[key] = None
                    return None
                queue.append(pair)
        result = {'states': len(visited), 'proof': 'product-automaton-language-inclusion'}
        self.stats['proven_inclusions'] += 1
        self.cache[key] = result
        return result

def prune_subsumed(masks, engine):
    """Delete only against a currently retained rule; resolve proof chains."""
    ordered = sorted(masks, key=lambda mask: (len(mask), mask))
    retained = set(ordered)
    targets = {}
    for smaller in reversed(ordered):
        for larger in ordered:
            if smaller == larger or larger not in retained:
                continue
            if engine.prove(smaller, larger) is not None:
                retained.remove(smaller)
                targets[smaller] = larger
                break
    removed = []
    for smaller in ordered:
        if smaller not in targets:
            continue
        target = targets[smaller]
        while target in targets:
            target = targets[target]
        proof = engine.prove(smaller, target)
        if proof is None:
            retained.add(smaller)
            continue
        removed.append({'mask': smaller, 'covered_by': target, **proof})
    return (retained, removed)

def factor_classes(masks):
    current = {parse(m) for m in masks}
    steps = []
    while True:
        changed = False
        for position in range(max((len(m) for m in current), default=0)):
            groups = defaultdict(list)
            for tokens in current:
                if position < len(tokens) and tokens[position] != STAR:
                    groups[tokens[:position], tokens[position + 1:]].append(tokens)
            for (prefix, suffix), group in sorted(groups.items(), key=lambda x: str(x[0])):
                if len(group) < 2:
                    continue
                union = 0
                for tokens in group:
                    union |= tokens[position]
                combined = prefix + (union,) + suffix
                mask = render(combined)
                if mask is None:
                    continue
                before = sorted((render(t) for t in group))
                current.difference_update(group)
                current.add(combined)
                steps.append({'inputs': before, 'output': mask, 'position': position, 'proof': 'distribute-one-character-class-union'})
                changed = True
        if not changed:
            break
    return ({render(t) for t in current}, steps)

def optimize_masks(masks, max_rounds=4):
    engine = Inclusion()
    normalized = {render(parse(m)) for m in masks}
    normalizations = [{'input': m, 'output': render(parse(m)), 'proof': 'same-normalized-glob-tokens'} for m in sorted(masks) if m != render(parse(m))]
    current = normalized
    phases = []
    for round_index in range(max_rounds):
        start = len(current)
        pruned, removed = prune_subsumed(current, engine)
        factored, steps = factor_classes(pruned)
        phases.append({'round': round_index + 1, 'before': start, 'after_subsumption': len(pruned), 'after_factorization': len(factored), 'removed': removed, 'factorizations': steps})
        current = factored
        if not removed and (not steps):
            break
    return (current, {'normalizations': normalizations, 'phases': phases, 'automaton_statistics': dict(engine.stats), 'alphabet': 'normalized ASCII hostname characters plus OTHER; inclusion proven over all strings in this partition, not only sample domains', 'max_states_per_inclusion': engine.max_states, 'unproven_rules': 'retained'})
