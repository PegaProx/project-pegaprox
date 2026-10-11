"""The query language of the global search: AND, OR, NOT, parentheses, quotes, several
prefixes in one query (pegaprox/utils/search_query.py), behind /api/global/search and
the text filter of the All Guests table.

What a query found before it has to find now, row for row: the route is held against a
copy of the old matching code for every prefix, the tag comma list, the MAC spellings,
notes and addresses with what matched. The rest drives real requests through the real
app with the managers faked, as the other search tests do, and the per-guest scope of a
pool, ACL, tenant and confined admin stays what it was whatever the expression says.
MK Oct 2026
"""
import ast
import inspect
import json
import time

import pytest

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac
from pegaprox.utils import search_query as sq

from test_ha_api import ha_env, _standby_of_active  # noqa: F401

MAC_WEB = 'BC:24:11:AA:BB:01'
MAC_DB = 'BC:24:11:AA:BB:02'
MAC_CT = 'BC:24:11:CC:DD:03'

C1_VMS = [
    {'vmid': 100, 'name': 'web01', 'node': 'pve1', 'type': 'qemu', 'status': 'running', 'ip': '10.1.0.10',
     'ip_addresses': ['10.1.0.10', '172.16.5.10'], 'tags': 'web;prod', 'pool': 'shop', 'cpu': 0.1, 'mem': 1, 'maxmem': 4},
    {'vmid': 101, 'name': 'db01', 'node': 'pve1', 'type': 'qemu', 'status': 'stopped', 'tags': 'db;prod'},
    {'vmid': 150, 'name': 'web02', 'node': 'pve2', 'type': 'qemu', 'status': 'running', 'ip': '10.1.0.12',
     'tags': 'web;staging', 'pool': 'shop'},
    {'vmid': 900, 'name': 'cache', 'node': 'pve2', 'type': 'lxc', 'status': 'running', 'tags': 'cache'},
    {'vmid': 1001, 'name': 'app-01', 'node': 'pve2', 'type': 'qemu', 'status': 'paused', 'tags': ''},
]
C1_NODES = {'pve1': {'status': 'online', 'cpu': 0.1, 'mem': 1, 'maxmem': 2}, 'pve2': {'status': 'offline'}}
C2_VMS = [
    {'vmid': 200, 'name': 'lab-web', 'node': 'lab1', 'type': 'qemu', 'status': 'running', 'tags': 'web'},
    {'vmid': 201, 'name': 'lab-db', 'node': 'lab1', 'type': 'lxc', 'status': 'stopped', 'tags': 'db;lab'},
]
C2_NODES = {'lab1': {'status': 'online'}}
CONFIGS = {
    ('c1', 'qemu', 100): {'net0': f'virtio={MAC_WEB},bridge=vmbr0',
                          'description': 'Frontend for the shop.\nBackup window 02:00 - 03:00, ask ops first.'},
    ('c1', 'qemu', 101): {'net0': f'virtio={MAC_DB},bridge=vmbr0', 'net1': 'e1000=BC:24:11:AA:BB:12,bridge=vmbr1',
                          'ipconfig0': 'ip=10.2.0.20/24,gw=10.2.0.1', 'description': 'Primary database'},
    ('c1', 'lxc', 900): {'net0': f'name=eth0,bridge=vmbr0,hwaddr={MAC_CT},ip=192.168.9.30/24',
                         'description': 'redis cache'},
    ('c2', 'qemu', 200): {'net0': 'virtio=BC:24:11:EE:00:01,bridge=vmbr0', 'description': 'lab web for the shop'},
}


@pytest.fixture
def estate(api, seed):
    from pegaprox.background import guest_index
    for cid, name, vms, nodes in (('c1', 'Testi', C1_VMS, C1_NODES), ('c2', 'Lab', C2_VMS, C2_NODES)):
        m = api.make_fake_manager(cluster_id=cid, get_vm_resources=[dict(v) for v in vms])
        m.is_connected = True
        m.config.name = name
        m.nodes = {k: dict(v) for k, v in nodes.items()}
        api.set_manager(cid, m)
    for (cid, vm_type, vmid), cfg in CONFIGS.items():
        guest_index.ingest(cid, vm_type, vmid, cfg)
    return api


def _admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _get(client, q, type_=None):
    args = {'q': q}
    if type_:
        args['type'] = type_
    r = client.get('/api/global/search', query_string=args)
    return r.status_code, r.get_json()


def _found(client, q, type_=None):
    code, body = _get(client, q, type_)
    assert code == 200, (q, body)
    rows = body['results']
    return (sorted((x['cluster_id'], x['vmid']) for x in rows if x['type'] != 'node')
            + sorted((x['cluster_id'], x['name']) for x in rows if x['type'] == 'node'))


# -- the old search, verbatim but for access checks (an admin sees all) ------------------------

def _old_search(raw_query, search_type='all'):
    from pegaprox.background import guest_index
    raw_query = raw_query.strip()
    prefix_filter = None
    query = raw_query.lower()
    for prefix in ['tag:', 'node:', 'ip:', 'status:', 'mac:', 'notes:']:
        if query.startswith(prefix):
            prefix_filter = prefix[:-1]
            query = query[len(prefix):].strip()
            break
    tag_queries = [t.strip() for t in query.split(',')] if prefix_filter == 'tag' else [query]
    results = []
    all_tags = set()
    for cluster_id, mgr in list(ppglobals.cluster_managers.items()):
        if not mgr.is_connected:
            continue
        cluster_name = mgr.config.name or cluster_id
        if search_type in ['all', 'vm', 'ct']:
            resources = mgr.get_vm_resources(max_age=6)
            indexed = guest_index.snapshot(cluster_id)
            for r in resources:
                name = (r.get('name') or '').lower()
                vmid = str(r.get('vmid', ''))
                node = (r.get('node') or '').lower()
                ip = (r.get('ip') or '').lower()
                tags_str = (r.get('tags') or '').lower()
                tags_list = [t.strip() for t in tags_str.split(';') if t.strip()] if tags_str else []
                status = (r.get('status') or '').lower()
                for t in tags_list:
                    all_tags.add(t)
                matched = False
                match_field = None
                hit = None
                entry = indexed.get((r.get('type'), int(vmid))) if vmid.isdigit() else None
                live_ips = r.get('ip_addresses') or ([r['ip']] if r.get('ip') else [])
                if prefix_filter == 'tag':
                    matched = all(any(tq in tag for tag in tags_list) for tq in tag_queries)
                    if matched:
                        match_field = 'tag'
                elif prefix_filter == 'node':
                    matched = query in node
                    if matched:
                        match_field = 'node'
                elif prefix_filter in ('ip', 'mac', 'notes'):
                    hit = guest_index.find(entry, live_ips, query, fields=(prefix_filter,), prefixed=True)
                elif prefix_filter == 'status':
                    matched = status.startswith(query)
                    if matched:
                        match_field = 'status'
                else:
                    if query in name:
                        matched, match_field = True, 'name'
                    elif query == vmid or query in vmid:
                        matched, match_field = True, 'vmid'
                    elif query in node:
                        matched, match_field = True, 'node'
                    elif query in ip:
                        matched, match_field = True, 'ip'
                    elif any(query in tag for tag in tags_list):
                        matched, match_field = True, 'tag'
                    else:
                        hit = guest_index.find(entry, live_ips, query)
                if hit:
                    matched, match_field = True, hit[0]
                if not matched:
                    continue
                vm_type = r.get('type', 'qemu')
                if search_type == 'vm' and vm_type != 'qemu':
                    continue
                if search_type == 'ct' and vm_type != 'lxc':
                    continue
                row = {'type': 'vm' if vm_type == 'qemu' else 'ct', 'cluster_id': cluster_id,
                       'cluster_name': cluster_name, 'vmid': r.get('vmid'), 'name': r.get('name'),
                       'node': r.get('node'), 'status': r.get('status'), 'ip': r.get('ip'),
                       'tags': r.get('tags', ''), 'cpu': r.get('cpu'), 'mem': r.get('mem'),
                       'maxmem': r.get('maxmem'), 'match_field': match_field}
                if hit:
                    row['match_value'] = hit[1]
                    if hit[2]:
                        row['match_net'] = hit[2]
                elif match_field == 'ip':
                    row['match_value'] = r.get('ip')
                results.append(row)
        if search_type in ['all', 'node'] and prefix_filter in [None, 'node']:
            for node_name, node_data in (mgr.nodes or {}).items():
                if query in node_name.lower():
                    results.append({'type': 'node', 'cluster_id': cluster_id, 'cluster_name': cluster_name,
                                    'name': node_name, 'status': node_data.get('status', 'unknown'),
                                    'cpu': node_data.get('cpu'), 'mem': node_data.get('mem'),
                                    'maxmem': node_data.get('maxmem'), 'match_field': 'name'})

    def sort_key(r):
        name = (r.get('name') or str(r.get('vmid', ''))).lower()
        mf = r.get('match_field', '')
        if name == query:
            return (0, name)
        elif name.startswith(query):
            return (1, name)
        elif mf == 'tag':
            return (2, name)
        elif mf == 'vmid':
            return (3, name)
        return (4, name)
    results.sort(key=sort_key)
    tag_suggestions = sorted([t for t in all_tags if query in t])[:10] if not prefix_filter or prefix_filter == 'tag' else []
    return json.loads(json.dumps({'count': len(results), 'results': results[:100], 'tag_suggestions': tag_suggestions}))


OLD_QUERIES = [
    'web', 'WEB01', 'web01', 'db', '10', '100', '1001', 'pve1', 'pve', 'lab', '10.1.0', '172.16', '10.2.0.20',
    'prod', 'stag', 'tag:web', 'tag:web,prod', 'tag:web, prod', 'tag:web ,prod', 'tag:prod,db', 'tag:web,',
    'Tag:PROD', 'tag: web', 'node:pve2', 'node:lab', 'NODE:PVE1', 'ip:10.1', 'ip:192.168.9', 'ip:10.2.0',
    'status:run', 'status:stopped', 'status:p', 'mac:bc:24:11', 'mac:bc 24 11 aa', 'mac:cc', 'bc-24-11-aa-bb-02',
    'BC2411AABB12', 'aa:bb:02', 'bc 24 11 ee 00 01', 'notes:backup', 'notes:REDIS', 'notes:for the shop',
    'backup window', 'Backup Window 02:00', 'for the shop', 'primary database', '-01', 'app-01', 'redis cache',
    'shop', 'cache', 'online', '02:00 - 03:00',
]


@pytest.mark.parametrize('type_', ['all', 'vm', 'ct', 'node'])
def test_every_query_that_found_something_finds_the_same(estate, seed, type_):
    admin = _admin(estate, seed)
    compared = 0
    for q in OLD_QUERIES:
        old = _old_search(q, type_)
        if not old['count']:
            continue
        code, new = _get(admin, q, type_)
        assert code == 200, (q, new)
        assert new['results'] == old['results'], q
        assert new['count'] == old['count'], q
        assert new['syntax'] == 'plain', q
        # a tag: list now suggests for its last part; everything else as before
        if not (q.lower().startswith('tag:') and ',' in q):
            assert new['tag_suggestions'] == old['tag_suggestions'], q
        compared += 1
    assert compared >= {'all': 40, 'vm': 30, 'ct': 8, 'node': 4}[type_], compared


def test_what_matched_is_said_as_before(estate, seed):
    admin = _admin(estate, seed)
    _, body = _get(admin, 'bc-24-11-aa-bb-12')
    assert [(x['vmid'], x['match_field'], x['match_value'], x['match_net']) for x in body['results']] == [
        (101, 'mac', 'BC:24:11:AA:BB:12', 'net1')]
    _, body = _get(admin, '172.16.5')
    assert [(x['vmid'], x['match_field'], x['match_value']) for x in body['results']] == [(100, 'ip', '172.16.5.10')]
    _, body = _get(admin, '10.1.0.10')
    assert [(x['vmid'], x['match_field'], x['match_value']) for x in body['results']] == [(100, 'ip', '10.1.0.10')]
    _, body = _get(admin, 'cache')
    hit = next(x for x in body['results'] if x['vmid'] == 900)
    assert hit['match_field'] == 'name' and 'match_value' not in hit
    # the old error for a prefix with nothing after it is still a 400
    code, body = _get(admin, 'tag:')
    assert code == 400 and body['code'] == 'SEARCH_SYNTAX' and body['reason'] == 'empty_value'


# -- the new terms -------------------------------------------------------------------------------

def test_and_or_not_and_the_minus(estate, seed):
    admin = _admin(estate, seed)
    assert _found(admin, 'tag:web AND tag:staging') == [('c1', 150)]
    assert _found(admin, 'tag:web tag:prod') == [('c1', 100)]
    assert _found(admin, 'tag:cache OR tag:lab') == [('c1', 900), ('c2', 201)]
    assert _found(admin, 'tag:web -tag:prod') == [('c1', 150), ('c2', 200)]
    assert _found(admin, 'tag:web AND NOT tag:prod') == [('c1', 150), ('c2', 200)]
    assert _found(admin, '(tag:db OR tag:cache) AND -cluster:lab') == [('c1', 101), ('c1', 900)]
    # NOT before AND before OR
    assert _found(admin, 'tag:cache OR tag:web tag:staging') == [('c1', 150), ('c1', 900)]
    # "and" in lower case is a word: web AND and AND db, which nothing holds
    assert _found(admin, 'web and db') == []


def test_the_new_prefixes(estate, seed):
    admin = _admin(estate, seed)
    assert _found(admin, 'id:150') == [('c1', 150)]
    assert _found(admin, 'id:100-199') == [('c1', 100), ('c1', 101), ('c1', 150)]
    assert _found(admin, 'type:ct') == [('c1', 900), ('c2', 201)]
    assert _found(admin, 'type:vm tag:db') == [('c1', 101)]
    assert _found(admin, 'cluster:lab type:vm') == [('c2', 200)]
    assert _found(admin, 'cluster:c2 tag:db') == [('c2', 201)]
    assert _found(admin, 'pool:shop') == [('c1', 100), ('c1', 150)]
    assert _found(admin, 'name:web -name:lab') == [('c1', 100), ('c1', 150)]
    assert _found(admin, 'name:"web0" OR id:900') == [('c1', 100), ('c1', 150), ('c1', 900)]
    # nodes: by type:, and their status once the query is about them
    assert _found(admin, 'type:node') == [('c1', 'pve1'), ('c1', 'pve2'), ('c2', 'lab1')]
    assert _found(admin, 'type:node status:offline') == [('c1', 'pve2')]
    assert _found(admin, 'node:pve status:run') == [('c1', 100), ('c1', 150), ('c1', 900)]


def test_words_are_terms_when_the_phrase_finds_nothing(estate, seed):
    admin = _admin(estate, seed)
    # "backup window" is in a note: found as before, as one phrase
    code, body = _get(admin, 'backup window')
    assert body['syntax'] == 'plain' and [x['vmid'] for x in body['results']] == [100]
    # "web prod" is in no name or note: both words, each anywhere
    code, body = _get(admin, 'web prod')
    assert code == 200 and body['syntax'] == 'expression'
    assert sorted(x['vmid'] for x in body['results']) == [100]
    # several prefixes without operators
    assert _found(admin, 'node:pve2 web') == [('c1', 150)]
    assert _found(admin, 'tag:web node:lab') == [('c2', 200)]
    # a name with a dash in it is found the old way, the dash is no NOT then
    assert _found(admin, '-01') == [('c1', 1001)]
    assert _found(admin, '-zz9 tag:lab') == [('c2', 201)]


def test_index_fields_in_an_expression_say_what_matched(estate, seed):
    admin = _admin(estate, seed)
    _, body = _get(admin, 'tag:prod AND mac:bc:24:11:aa:bb:1')
    assert [(x['vmid'], x['match_field'], x['match_value'], x.get('match_net')) for x in body['results']] == [
        (101, 'mac', 'BC:24:11:AA:BB:12', 'net1')]
    _, body = _get(admin, 'notes:shop -cluster:lab')
    assert [(x['vmid'], x['match_field']) for x in body['results']] == [(100, 'notes')]
    assert body['results'][0]['match_value'].startswith('Frontend for the shop.')
    _, body = _get(admin, 'ip:10.2.0.20 OR ip:192.168.9')
    assert sorted((x['vmid'], x['match_value'], x['match_net']) for x in body['results']) == [
        (101, '10.2.0.20', 'net0'), (900, '192.168.9.30', 'net0')]
    # only NOTs: in the list, without a field to show
    _, body = _get(admin, '-tag:web -tag:db type:vm')
    assert [(x['vmid'], x['match_field']) for x in body['results']] == [(1001, 'type')]


def test_tag_suggestions_follow_the_last_term(estate, seed):
    admin = _admin(estate, seed)
    _, body = _get(admin, 'node:pve1 AND tag:pro')
    assert body['tag_suggestions'] == ['prod']
    assert body['tag_complete'] == {'start': 18, 'end': 21, 'prefix': ''}
    _, body = _get(admin, 'tag:cache OR sta')
    assert body['tag_suggestions'] == ['staging']
    assert body['tag_complete'] == {'start': 13, 'end': 16, 'prefix': 'tag:'}
    _, body = _get(admin, 'tag:web,sta')
    assert body['tag_suggestions'] == ['staging'] and body['tag_complete']['start'] == 8
    # nothing to complete after a closing parenthesis or on another prefix
    assert _get(admin, '(tag:web OR tag:db)')[1]['tag_suggestions'] == []
    assert _get(admin, 'tag:web node:pv')[1]['tag_suggestions'] == []
    # which tags of a hit the UI marks
    assert _get(admin, 'tag:web,prod OR db -tag:x')[1]['highlight'] == ['web', 'prod', 'db']


@pytest.mark.parametrize('q,reason,position', [
    ('(tag:web OR db', 'unclosed_paren', 0),
    ('tag:web)', 'unexpected_paren', 7),
    ('web AND', 'term_after', 4),
    ('OR web', 'term_before', 0),
    ('web OR OR db', 'term_after', 4),
    ('()', 'empty_group', 0),
    ('name:"web 01', 'unclosed_quote', 5),
    ('id:abc', 'bad_id', 3),
    ('id:300-100', 'bad_id', 3),
    ('type:disk', 'bad_type', 5),
    ('web tag: db', 'empty_value', 4),
    ('web - db', 'term_after', 4),
    ('x' + ' OR x' * 20, 'too_many_terms', 100),
    ('a ' + 'NOT ' * 9 + 'b', 'too_deep', 34),
    ('(' * 9 + 'a' + ')' * 9, 'too_deep', 8),
    ('w' * 257, 'too_long', 256),
])
def test_a_query_that_cannot_be_read_is_a_400_that_says_where(estate, seed, q, reason, position):
    code, body = _get(_admin(estate, seed), q)
    assert code == 400, body
    assert (body['code'], body['reason'], body['position']) == ('SEARCH_SYNTAX', reason, position), body
    assert body['error'] and '\u2014' not in body['error']


# -- who sees what ---------------------------------------------------------------------------------

def _pool_user(seed):
    seed.tenant('tenant_x', clusters=['c1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('c1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['c1'] = {'data': {'100:qemu': 'pool_1'}, 'timestamp': time.time(),
                                             'refreshing': False}
    return u


def test_a_pool_user_finds_their_own_guest_whatever_the_expression(estate, seed):
    mallory = estate.as_user(_pool_user(seed))
    for q in ('-tag:zzz', 'NOT tag:zzz', 'tag:web OR tag:db OR tag:cache', 'type:vm OR type:ct',
              'id:1-99999', 'cluster:testi', 'mac:bc:24:11 OR notes:database', '(web OR db) -tag:nothing'):
        got = _found(mallory, q)
        # their guest, and the nodes of the cluster as the search always listed them
        assert [x for x in got if isinstance(x[1], int)] == [('c1', 100)], (q, got)
        assert all(x[0] == 'c1' for x in got), (q, got)
    # the tags of the guests out of reach are not suggested either
    assert _get(mallory, 'tag:web AND st')[1]['tag_suggestions'] == []
    assert _get(mallory, 'tag:web AND pro')[1]['tag_suggestions'] == ['prod']


def test_an_acl_user_finds_the_one_guest_they_were_given(estate, seed):
    seed.tenant('tenant_x', clusters=['c1'])
    alice = estate.as_user(seed.user('alice', role='viewer', tenant_id='tenant_x'))
    seed.vm_acl('c1', 900, ['alice'], inherit_role=False, permissions=['vm.view'])
    for q in ('-tag:zzz type:ct OR type:vm', 'id:1-99999', 'tag:prod OR tag:cache', 'notes:redis OR notes:database'):
        assert [x for x in _found(alice, q) if isinstance(x[1], int)] == [('c1', 900)], q
    assert _found(alice, 'tag:prod OR notes:database') == []


def test_another_tenant_and_a_confined_admin_find_nothing_of_the_cluster(estate, seed):
    seed.tenant('tenant_x', clusters=['c1'])
    seed.tenant('globex', clusters=['c2'])
    callers = {
        'other tenant': seed.user('milton', role='user', tenant_id='globex'),
        'confined admin': seed.user('gx', role='admin', tenant_id='globex',
                                    tenant_permissions={'globex': {'role': 'user'}}),
    }
    for who, user in callers.items():
        client = estate.as_user(user)
        for q in ('-tag:zzz', 'cluster:testi', 'cluster:c1 OR id:100', 'type:node', 'mac:bc:24:11 OR notes:redis'):
            got = _found(client, q)
            assert all(x[0] == 'c2' for x in got), (who, q, got)
        assert _found(client, 'id:1-99999') == [('c2', 200), ('c2', 201)], who


def test_a_standby_answers_searches_too(ha_env, seed, db):  # noqa: F811
    api = ha_env.api
    m = api.make_fake_manager(cluster_id='c1', get_vm_resources=[dict(v) for v in C1_VMS])
    m.is_connected = True
    m.config.name = 'Testi'
    m.nodes = {}
    api.set_manager('c1', m)
    client = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    before = db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    assert _found(client, 'tag:web -tag:prod') == [('c1', 150)]
    assert db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0] == before


# -- the module ------------------------------------------------------------------------------------

def _shape(node):
    if isinstance(node, sq.Term):
        return f'{node.field or "*"}:{node.value}'
    if isinstance(node, sq.Not):
        return ['NOT', _shape(node.child)]
    return [type(node).__name__.upper()] + [_shape(c) for c in node.children]


@pytest.mark.parametrize('q,shape', [
    ('web', '*:web'),
    ('tag:prod node:pve1', ['AND', 'tag:prod', 'node:pve1']),
    ('a OR b c OR d', ['OR', '*:a', ['AND', '*:b', '*:c'], '*:d']),
    ('NOT a b', ['AND', ['NOT', '*:a'], '*:b']),
    ('-(a OR b) c', ['AND', ['NOT', ['OR', '*:a', '*:b']], '*:c']),
    ('Name:"Web 01" ID:7', ['AND', 'name:web 01', 'id:7']),
    ('bc:24:11:aa:bb:cc', '*:bc:24:11:aa:bb:cc'),
    ('ip:fd00:2::21', 'ip:fd00:2::21'),
    ('tag:web, prod x', ['AND', 'tag:web, prod', '*:x']),
    ('web-01 -lab', ['AND', '*:web-01', ['NOT', '*:lab']]),
    ('foo:bar', '*:foo:bar'),
])
def test_the_tree(q, shape):
    assert _shape(sq.parse(q).root) == shape


def test_read_plain_is_the_old_split():
    for q, field, value in (('tag:web,prod', 'tag', 'web,prod'), ('notes:Backup server', 'notes', 'backup server'),
                            ('mac: bc 24', 'mac', 'bc 24'), ('backup window', None, 'backup window'),
                            ('name:web', None, 'name:web'), ('web OR db', None, 'web or db')):
        t = sq.read_plain(q).root
        assert (t.field, t.value) == (field, value), q
    assert sq.explicit('a OR b') and sq.explicit('(a)') and sq.explicit('"a b"') and sq.explicit('NOT x')
    assert not sq.explicit('a or b') and not sq.explicit('-a tag:b') and not sq.explicit('Notes')


def test_reading_takes_one_pass():
    """Every worst case at the length limit reads in well under a millisecond each."""
    cases = ['(' * 8 + 'a' + ')' * 8 + ' b' * 10, '"' + 'x' * 250 + '"', 'tag:' + 'a,' * 120,
             ' '.join(['a OR b'] * 10)[:256], 'x' * 256]
    t0 = time.perf_counter()
    for _ in range(200):
        for q in cases:
            try:
                sq.parse(q)
            except sq.SearchSyntaxError:
                pass
    assert time.perf_counter() - t0 < 2.0


def test_no_pattern_is_built_from_the_query():
    tree = ast.parse(inspect.getsource(sq))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 're':
            assert node.args and isinstance(node.args[0], ast.Constant), ast.dump(node)


# -- the All Guests table ------------------------------------------------------------------------

PAGE = '/api/inventory/guests/page'


def _page_ids(client, q):
    r = client.get(PAGE, query_string={'q': q})
    assert r.status_code == 200, r.get_json()
    return [(g['cluster_id'], g['vmid']) for g in r.get_json()['guests']]


def test_the_guest_table_takes_the_same_expressions(estate, seed):
    admin = _admin(estate, seed)
    # plain text as before: in the row's text
    assert _page_ids(admin, 'WEB') == [('c2', 200), ('c1', 100), ('c1', 150)]
    assert _page_ids(admin, 'testi lab') == []
    # expressions
    assert _page_ids(admin, 'tag:web -tag:prod') == [('c2', 200), ('c1', 150)]
    assert _page_ids(admin, 'type:ct OR id:1001') == [('c1', 1001), ('c1', 900), ('c2', 201)]
    assert _page_ids(admin, '(cluster:lab OR pool:shop) status:run') == [('c2', 200), ('c1', 100), ('c1', 150)]
    assert _page_ids(admin, 'mac:bc:24:11:aa OR notes:redis') == [('c1', 900), ('c1', 101), ('c1', 100)]
    # free text of an expression is the row's text, the cluster's name included
    assert _page_ids(admin, 'web AND lab') == [('c2', 200)]
    r = admin.get(PAGE, query_string={'q': 'tag:web OR'})
    assert r.status_code == 400 and r.get_json()['reason'] == 'term_after'


def test_the_guest_table_keeps_a_pool_user_to_their_guests(estate, seed):
    mallory = estate.as_user(_pool_user(seed))
    assert _page_ids(mallory, '-tag:zzz') == [('c1', 100)]
    assert _page_ids(mallory, 'tag:db OR tag:cache') == []


# -- scale -----------------------------------------------------------------------------------------

def test_ten_thousand_guests_one_expression(api, seed):
    fleet = [{'vmid': 1000 + i, 'name': f'g-{i:05d}', 'node': f'n{i % 100:02d}', 'type': 'qemu' if i % 4 else 'lxc',
              'status': 'running' if i % 3 else 'stopped', 'tags': 'fleet;web' if i % 10 == 0 else 'fleet'}
             for i in range(10000)]
    m = api.make_fake_manager(cluster_id='big', get_vm_resources=fleet)
    m.is_connected = True
    m.config.name = 'Big'
    m.nodes = {f'n{i:02d}': {'status': 'online'} for i in range(100)}
    api.set_manager('big', m)
    client = api.as_user(seed.user('root', role='admin'))
    t0 = time.monotonic()
    code, body = _get(client, '(tag:web OR name:g-0999) -status:stopped type:ct node:n0')
    spent = time.monotonic() - t0
    assert code == 200 and body['count'] > 0 and len(body['results']) <= 100
    assert spent < 5, spent
    # one read of the guest list for both readings of a plain query that finds nothing
    m.get_vm_resources.reset_mock()
    assert _get(client, 'nothing here')[1]['count'] == 0
    assert m.get_vm_resources.call_count == 1


def test_a_tag_list_of_empty_parts_finds_nothing(estate, seed):
    """tag:, has only empty parts; each of them is in every tag, so it found every tagged guest"""
    admin = _admin(estate, seed)
    assert _found(admin, 'tag:,') == []
    assert _found(admin, 'tag:web,') == _found(admin, 'tag:web')
