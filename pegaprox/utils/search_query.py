# -*- coding: utf-8 -*-
"""
PegaProx search expressions - the query language of the global search and of the
text filter of the All Guests table.

MK Oct 2026 - the search took one prefix per query and a comma between tags. This
reads a query into a small tree and lets the caller say what a single term matches:

    web                              free text, as the search always did
    tag:prod node:pve1               both: terms side by side are ANDed
    tag:web OR tag:api               either
    -status:running                  not running, the same as NOT status:running
    (tag:db OR tag:cache) AND NOT node:pve3
    name:"web 01"                    a value with a space in it
    id:100-199                       a VMID, or a range of them
    type:ct  cluster:lab  pool:dev   guest type (vm, ct, node), cluster, pool

AND, OR and NOT are operators in capitals only; "and" is a word like any other. NOT
binds before AND, AND before OR.

A query without AND/OR/NOT, parentheses or quotes is first read as before (read_plain):
one of the old prefixes at the very start and all the rest its value, spaces and all.
The routes try that first and the expression only when it finds nothing, so every
query that found something before finds the same now.

Read in one pass without backtracking, and no pattern is built from the query. A query
longer than MAX_LENGTH, with more than MAX_TERMS terms or nested deeper than MAX_DEPTH
(parentheses and NOTs) is refused with SearchSyntaxError, which says where reading
stopped.
"""

import re

from pegaprox.background import guest_index

MAX_LENGTH = 256
MAX_TERMS = 20
MAX_DEPTH = 8

# the prefixes of the old search, in the order it tried them
PLAIN_PREFIXES = ('tag', 'node', 'ip', 'status', 'mac', 'notes')
FIELDS = PLAIN_PREFIXES + ('name', 'id', 'type', 'cluster', 'pool')
_LONGEST_FIELD = max(len(f) for f in FIELDS)
KEYWORDS = ('AND', 'OR', 'NOT')
TYPES = {'vm': 'qemu', 'qemu': 'qemu', 'ct': 'lxc', 'lxc': 'lxc', 'container': 'lxc', 'node': 'node'}
# a term on one of these can be about a node; a query without one leaves the nodes out,
# as the old search did for tag:, ip:, status:, mac: and notes:
NODE_SUBJECTS = (None, 'node', 'name', 'type', 'cluster')
_INDEX_FIELDS = ('ip', 'mac', 'notes')
# a hit on these only narrows the list; another hit says more about why a row is there
_FILTER_FIELDS = ('type', 'status', 'cluster', 'pool')
_ID = re.compile(r'([0-9]{1,9})(?:-([0-9]{1,9}))?')

_MESSAGES = {
    'empty': 'Nothing to search for',
    'too_long': 'The query is longer than {limit} characters',
    'too_many_terms': 'At most {limit} terms, the one at character {at} is one too many',
    'too_deep': 'Nested deeper than {limit} levels at character {at}',
    'unclosed_quote': 'The quote at character {at} is not closed',
    'unclosed_paren': "The '(' at character {at} is not closed",
    'unexpected_paren': "The ')' at character {at} closes nothing",
    'empty_group': "Nothing between the parentheses at character {at}",
    'term_before': '{token} at character {at} needs a term before it',
    'term_after': '{token} at character {at} needs a term after it',
    'empty_value': '{token} at character {at} needs a value',
    'bad_id': 'id: takes a VMID or a range like 100-199 (character {at})',
    'bad_type': 'type: is vm, ct or node (character {at})',
}


class SearchSyntaxError(ValueError):
    """A query that cannot be read. position counts from 0; the message from 1."""

    def __init__(self, reason, position, token=None, limit=None):
        self.reason = reason
        self.position = position
        self.token = token
        self.limit = limit
        super().__init__(_MESSAGES[reason].format(at=position + 1, token=token or '', limit=limit))

    def to_json(self):
        out = {'error': str(self), 'code': 'SEARCH_SYNTAX', 'reason': self.reason, 'position': self.position}
        if self.token is not None:
            out['token'] = self.token
        if self.limit is not None:
            out['limit'] = self.limit
        return out


# -- the tree ---------------------------------------------------------------------------------

class Term:
    """One field and value. start/end span the term in the query, a '-' in front aside;
    value is lower case. tag: has its comma parts, id: its range, type: its kind."""
    __slots__ = ('field', 'value', 'start', 'end', 'value_start', 'quoted', 'parts', 'low', 'high', 'kind')

    def __init__(self, field, raw, start, end, value_start, quoted=False):
        self.field = field
        self.value = raw.lower()
        self.start, self.end, self.value_start = start, end, value_start
        self.quoted = quoted
        self.parts = [p.strip() for p in self.value.split(',')] if field == 'tag' else None
        self.low = self.high = self.kind = None

    def match(self, hit, facts):
        got = hit(self, facts)
        return [got] if got else None


class Not:
    __slots__ = ('child',)

    def __init__(self, child):
        self.child = child

    def match(self, hit, facts):
        return [] if self.child.match(hit, facts) is None else None


class And:
    __slots__ = ('children',)

    def __init__(self, children):
        self.children = children

    def match(self, hit, facts):
        hits = []
        for child in self.children:
            got = child.match(hit, facts)
            if got is None:
                return None
            hits.extend(got)
        return hits


class Or:
    __slots__ = ('children',)

    def __init__(self, children):
        self.children = children

    def match(self, hit, facts):
        for child in self.children:
            got = child.match(hit, facts)
            if got is not None:
                return got
        return None


class Query:
    """A read query. match(hit, facts) gives the hits of a row that fits (a list, empty
    when only NOTs held), None for one that does not; hit(term, facts) is the caller's
    test of one term against one row, a (field, value, net) tuple or None."""

    def __init__(self, text, root, terms, plain, positive):
        self.text = text
        self.root = root
        self.terms = terms
        self.plain = plain
        self.positive = positive

    def match(self, hit, facts):
        return self.root.match(hit, facts)

    def about_nodes(self):
        return any(t.field in NODE_SUBJECTS for t in self.positive)

    def rank_text(self):
        """What a name is compared with to put the closest names first: the free text or
        name: of the query, else its first other value."""
        for t in self.positive:
            if t.field in (None, 'name'):
                return t.value
        for t in self.positive:
            if t.field not in ('type', 'id'):
                return t.value
        return None

    def highlight(self):
        """The values a tag of a hit is marked for."""
        out = []
        for t in self.positive:
            if t.field is None:
                out.append(t.value)
            elif t.field == 'tag':
                out.extend(p for p in t.parts if p)
        return out

    def tag_completion(self):
        """(needle, start, end, prefix) of the term at the end of the query when it can
        be a tag: free text, or the last comma part of a tag: value. A picked tag goes
        in place of text[start:end], prefix in front."""
        t = self.terms[-1] if self.terms else None
        if t is None or t.quoted or t.end != len(self.text) or t.field not in (None, 'tag'):
            return None
        if t.field is None:
            return t.value, t.start, t.end, 'tag:'
        raw = self.text[t.value_start:t.end]
        cut = raw.rfind(',') + 1
        part = raw[cut:]
        lead = len(part) - len(part.lstrip())
        return part.strip().lower(), t.value_start + cut + lead, t.end, ''

    def same_as(self, other):
        """True when both readings come down to the one same term."""
        a, b = self.root, other.root
        return isinstance(a, Term) and isinstance(b, Term) and (a.field, a.value) == (b.field, b.value)

    def whole_text(self):
        """True when the expression is nothing but the query as one free text term."""
        r = self.root
        return isinstance(r, Term) and r.field is None and r.value == self.text.lower()


def explicit(text):
    """Whether a query uses what only the expression reading knows: AND, OR, NOT,
    parentheses or quotes."""
    if '(' in text or ')' in text or '"' in text:
        return True
    return any(word in KEYWORDS for word in text.split())


def read_plain(text):
    """The query the way the search always read it: an old prefix at the very start, the
    rest its value. A prefix with nothing after it is refused as before."""
    _check_length(text)
    low = text.lower()
    for prefix in PLAIN_PREFIXES:
        if low.startswith(prefix + ':'):
            rest = text[len(prefix) + 1:]
            value = rest.strip()
            if not value:
                raise SearchSyntaxError('empty_value', 0, prefix + ':')
            start = len(prefix) + 1 + (len(rest) - len(rest.lstrip()))
            term = Term(prefix, value, 0, start + len(value), start)
            break
    else:
        term = Term(None, text, 0, len(text), 0)
    return Query(text, term, [term], True, [term])


def parse(text):
    """The query as an expression. Raises SearchSyntaxError."""
    _check_length(text)
    tokens = _tokens(text)
    if not tokens:
        raise SearchSyntaxError('empty', 0)
    parser = _Parser(text, tokens)
    root = parser.expression()
    positive = []
    _collect_positive(root, True, positive)
    positive.sort(key=lambda t: t.start)
    return Query(text, root, parser.terms, False, positive)


def _check_length(text):
    if len(text) > MAX_LENGTH:
        raise SearchSyntaxError('too_long', MAX_LENGTH, limit=MAX_LENGTH)


def _collect_positive(node, positive, out):
    if isinstance(node, Term):
        if positive:
            out.append(node)
    elif isinstance(node, Not):
        _collect_positive(node.child, not positive, out)
    else:
        for child in node.children:
            _collect_positive(child, positive, out)


# -- reading ----------------------------------------------------------------------------------

class _Tok:
    __slots__ = ('kind', 'start', 'end', 'text', 'field', 'raw', 'value_start', 'quoted')

    def __init__(self, kind, start, end, text, field=None, raw=None, value_start=None, quoted=False):
        self.kind, self.start, self.end, self.text = kind, start, end, text
        self.field, self.raw, self.value_start, self.quoted = field, raw, value_start, quoted


def _tokens(text):
    out = []
    words = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c in '()':
            out.append(_Tok(c, i, i + 1, c))
            i += 1
            continue
        if c == '-':
            # a '-' right in front of a term or a '(' leaves it out
            if i + 1 >= n or text[i + 1].isspace() or text[i + 1] == ')':
                raise SearchSyntaxError('term_after', i, '-')
            out.append(_Tok('NOT', i, i + 1, '-'))
            i += 1
            continue
        start = i
        field = None
        j = i
        while j < n and j - i <= _LONGEST_FIELD and text[j].isalpha():
            j += 1
        if j < n and text[j] == ':' and text[i:j].lower() in FIELDS:
            field = text[i:j].lower()
            i = j + 1
        value_start = i
        quoted = False
        if i < n and text[i] == '"':
            close = text.find('"', i + 1)
            if close < 0:
                raise SearchSyntaxError('unclosed_quote', i)
            raw, value_start, i, quoted = text[i + 1:close], i + 1, close + 1, True
        else:
            while i < n and not text[i].isspace() and text[i] not in '()"':
                i += 1
            raw = text[value_start:i]
        if field is None and not quoted and raw in KEYWORDS:
            out.append(_Tok(raw, start, i, raw))
            continue
        if not raw.strip() and (field or quoted):
            raise SearchSyntaxError('empty_value', start, (field + ':') if field else '""')
        words += 1
        if words > MAX_TERMS:
            raise SearchSyntaxError('too_many_terms', start, limit=MAX_TERMS)
        out.append(_Tok('WORD', start, i, text[start:i], field, raw, value_start, quoted))
    return _join_tag_lists(text, out)


def _join_tag_lists(text, tokens):
    """tag:web, prod and tag:web ,prod are one list, as they were before."""
    out = []
    for tok in tokens:
        prev = out[-1] if out else None
        if (prev is not None and prev.kind == 'WORD' and prev.field == 'tag' and not prev.quoted
                and tok.kind == 'WORD' and tok.field is None and not tok.quoted
                and (prev.raw.endswith(',') or tok.raw.startswith(','))):
            prev.raw = text[prev.value_start:tok.end]
            prev.end = tok.end
            prev.text = text[prev.start:tok.end]
            continue
        out.append(tok)
    return out


class _Parser:
    """or := and (OR and)*; and := unary ([AND] unary)*; unary := NOT unary | '(' or ')' | term"""

    def __init__(self, text, tokens):
        self.text = text
        self.tokens = tokens
        self.at = 0
        self.terms = []

    def _peek(self):
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def expression(self):
        node = self._or(0)
        left = self._peek()
        if left is not None:
            # the one token the loops leave behind is a ')' without its '('
            raise SearchSyntaxError('unexpected_paren', left.start)
        return node

    def _or(self, depth, after=None):
        parts = [self._and(depth, after)]
        while True:
            tok = self._peek()
            if tok is None or tok.kind != 'OR':
                break
            self.at += 1
            parts.append(self._and(depth, tok))
        return parts[0] if len(parts) == 1 else Or(parts)

    def _and(self, depth, after):
        parts = [self._unary(depth, after)]
        while True:
            tok = self._peek()
            if tok is None or tok.kind in ('OR', ')'):
                break
            if tok.kind == 'AND':
                self.at += 1
                parts.append(self._unary(depth, tok))
            else:
                parts.append(self._unary(depth, None))
        return parts[0] if len(parts) == 1 else And(parts)

    def _unary(self, depth, after):
        tok = self._peek()
        if tok is None or tok.kind in ('AND', 'OR', ')'):
            if after is not None:
                raise SearchSyntaxError('term_after', after.start, after.text)
            if tok is None:
                raise SearchSyntaxError('empty', len(self.text))
            if tok.kind == ')':
                raise SearchSyntaxError('unexpected_paren', tok.start)
            raise SearchSyntaxError('term_before', tok.start, tok.text)
        if tok.kind == 'NOT':
            if depth >= MAX_DEPTH:
                raise SearchSyntaxError('too_deep', tok.start, limit=MAX_DEPTH)
            self.at += 1
            return Not(self._unary(depth + 1, tok))
        if tok.kind == '(':
            if depth >= MAX_DEPTH:
                raise SearchSyntaxError('too_deep', tok.start, limit=MAX_DEPTH)
            self.at += 1
            nxt = self._peek()
            if nxt is not None and nxt.kind == ')':
                raise SearchSyntaxError('empty_group', tok.start)
            node = self._or(depth + 1, tok)
            close = self._peek()
            if close is None or close.kind != ')':
                raise SearchSyntaxError('unclosed_paren', tok.start)
            self.at += 1
            return node
        self.at += 1
        term = Term(tok.field, tok.raw, tok.start, tok.end, tok.value_start, tok.quoted)
        if term.field == 'id':
            m = _ID.fullmatch(term.value.strip())
            if not m:
                raise SearchSyntaxError('bad_id', tok.value_start)
            term.low = int(m.group(1))
            term.high = int(m.group(2)) if m.group(2) else term.low
            if term.high < term.low:
                raise SearchSyntaxError('bad_id', tok.value_start)
        elif term.field == 'type':
            term.kind = TYPES.get(term.value.strip())
            if term.kind is None:
                raise SearchSyntaxError('bad_type', tok.value_start)
        self.terms.append(term)
        return term


# -- what a term matches ----------------------------------------------------------------------

def guest_hit(term, g):
    """One term against one guest, (field, value, net) or None. g holds lower case
    name, vmid (str), node, ip (the one the row shows) with ip_raw as written, tags (list),
    status, type (qemu/lxc), cluster_id, cluster (its name), pool, the guest index entry
    and live_ips. With text set, free text looks there instead (the guest table's own).
    Free text and the old prefixes match exactly as the search always did."""
    field, value = term.field, term.value
    if field is None:
        if g.get('text') is not None:
            return ('text', None, None) if value in g['text'] else None
        if value in g['name']:
            return 'name', None, None
        if value == g['vmid'] or value in g['vmid']:
            return 'vmid', None, None
        if value in g['node']:
            return 'node', None, None
        if value in g['ip']:
            return 'ip', g['ip_raw'], None
        if any(value in tag for tag in g['tags']):
            return 'tag', None, None
        return guest_index.find(g['entry'], g['live_ips'], value)
    if field == 'tag':
        # every part of the list on one of the tags
        parts = [p for p in term.parts if p]
        if parts and all(any(p in tag for tag in g['tags']) for p in parts):
            return 'tag', None, None
        return None
    if field == 'node':
        return ('node', None, None) if value in g['node'] else None
    if field in _INDEX_FIELDS:
        return guest_index.find(g['entry'], g['live_ips'], value, fields=(field,), prefixed=True)
    if field == 'status':
        return ('status', None, None) if g['status'].startswith(value) else None
    if field == 'name':
        return ('name', None, None) if value in g['name'] else None
    if field == 'id':
        vmid = g['vmid']
        return ('vmid', None, None) if vmid.isdigit() and term.low <= int(vmid) <= term.high else None
    if field == 'type':
        return ('type', None, None) if g['type'] == term.kind else None
    if field == 'cluster':
        return ('cluster', None, None) if value in g['cluster'] or value == g['cluster_id'].lower() else None
    if field == 'pool':
        return ('pool', None, None) if g['pool'] and value in g['pool'] else None
    return None


def node_hit(term, n):
    """One term against a node: lower case name, status, cluster_id and cluster. The
    free text, node: and name: look at the name, as the search always did for nodes."""
    field, value = term.field, term.value
    if field in (None, 'node', 'name'):
        return ('name', None, None) if value in n['name'] else None
    if field == 'type':
        return ('type', None, None) if term.kind == 'node' else None
    if field == 'cluster':
        return ('cluster', None, None) if value in n['cluster'] or value == n['cluster_id'].lower() else None
    if field == 'status':
        return ('status', None, None) if n['status'].startswith(value) else None
    return None


def best_hit(hits):
    """The hit a row reports: one with a value to show (IP, MAC, notes) first, then the
    first that is more than a filter."""
    if not hits:
        return None
    for h in hits:
        if h[0] in _INDEX_FIELDS:
            return h
    for h in hits:
        if h[0] not in _FILTER_FIELDS:
            return h
    return hits[0]
