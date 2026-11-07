"""Source-classified brand diversity, without inferring new matching scope."""
from collections import Counter, defaultdict, deque
import hashlib
import json
from pathlib import Path


class BrandCatalog:
    def __init__(self, path, expected_source=None):
        raw=Path(path).read_bytes(); data=json.loads(raw)
        if not isinstance(data,dict) or data.get('schema')!=1 or not isinstance(data.get('groups'),dict):
            raise ValueError('invalid brand catalogue')
        if expected_source is not None and data.get('source') != expected_source:
            raise ValueError('brand catalogue source fingerprint differs from import policy')
        self.suffixes,self.exact={},{}
        self.groups=set(data['groups'])
        for name,group in data['groups'].items():
            if not isinstance(name,str) or not name:
                raise ValueError('invalid catalogue group')
            for key,index in [('suffixes',self.suffixes),('exact',self.exact)]:
                values=group.get(key)
                if not isinstance(values,list) or len(values)!=len(set(values)):
                    raise ValueError('invalid catalogue namespaces')
                for host in values:
                    if not isinstance(host,str) or '.' not in host or host!=host.lower() or any(c in host for c in '*?[,] '):
                        raise ValueError('invalid literal catalogue namespace')
                    # An ambiguous shared namespace gets one deterministic source
                    # classification. It never becomes a new match condition.
                    index.setdefault(host,[]).append(name)
        for index in [self.suffixes,self.exact]:
            for host,names in index.items():index[host]=min(names)
        self.identity={'sha256':hashlib.sha256(raw).hexdigest(),'groups':len(self.groups),
                       'suffix_namespaces':len(self.suffixes),'exact_namespaces':len(self.exact)}

    def family(self, host):
        if host in self.exact:return self.exact[host]
        parts=host.split('.')
        for i in range(len(parts)-1):
            if (name:=self.suffixes.get('.'.join(parts[i:]))) is not None:return name
        return None


def diverse_select(rows, limit, family, priority, mandatory=()):
    """Keep protected rows, then visit each source family once per round."""
    rows=set(rows); mandatory=set(mandatory)
    if not mandatory<=rows:raise ValueError('mandatory scope missing from candidate pool')
    if limit is None:limit=len(rows)
    if type(limit) is not int or limit<len(mandatory) or limit>len(rows):
        raise ValueError('insufficient independent candidates for the target; refusing padding')
    selected=sorted(mandatory,key=priority); seen=Counter(family(row) for row in selected)
    groups=defaultdict(list)
    for row in rows-mandatory:groups[family(row)].append(row)
    for key in groups:groups[key]=deque(sorted(groups[key],key=priority))
    while len(selected)<limit:
        active=[g for g,q in groups.items() if q]
        if not active:raise ValueError('candidate pool exhausted')
        # Families already represented by protected scopes wait for less
        # represented families; ties follow the requested type/source ranking.
        active.sort(key=lambda g:(seen[g],priority(groups[g][0]),str(g)))
        level=seen[active[0]]
        for group in active:
            if len(selected)==limit:break
            if seen[group]!=level:continue
            selected.append(groups[group].popleft());seen[group]+=1
    return selected
