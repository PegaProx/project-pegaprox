"""rbac.user_vm_access is user_can_access_vm for every guest of a cluster at once: the account
is read once, then a guest is a few dict lookups. The stream's 'resources' filter asked
user_can_access_vm guest by guest, four or five SQL statements each, so one non-admin stream
on a 10k-guest cluster held the hub 2.7 s (an operator) to 5 s (pool-scoped) per frame, and
two to four of them kept it busy for good.

The two must agree on every guest, or the stream shows what the REST routes refuse. Random
estates hold one against the other on each account, cluster, guest and permission, and a
line tracer checks that every way out of user_can_access_vm was taken while they did; the
fixed cases below name one estate per branch.
"""
import ast
import collections
import inspect
import json
import queue
import random
import sys
import time

import gevent
import pytest

import pegaprox.utils.rbac as rbac
import pegaprox.utils.realtime as rt

CLUSTERS = ('c1', 'c2', 'c3')
PERMS = ('vm.view', 'vm.start', 'vm.delete', 'pool.view')
POOL_PERMS = ('pool.view', 'vm.start', 'vm.console', 'pool.admin', 'vm.view')
ACL_PERMS = ('vm.view', 'vm.start', 'vm.console', 'vm.delete')
ROLES = ('admin', 'user', 'viewer', 'ops_g', 'ops_t', 'blind', 'twice', 'gone')
TENANTS = ('default', 't_a', 't_b', 't_none')
GROUPS = ('g_ops', 'g_dev')
POOLS = ('p1', 'p2', 'p3')


def _members(cluster_id, data):
    """The pool membership cache, fresh: {'vmid:type': pool}."""
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {'data': data, 'timestamp': time.time(),
                                                   'refreshing': False}


def _forget_caches():
    rbac.invalidate_vm_acls_cache()
    rbac.invalidate_roles_cache()
    rbac.invalidate_tenants_cache()


# --- random estates ---------------------------------------------------------------------------

def _random_estate(seed, rng, n_users=20, n_guests=20):
    """Tenants (one reaching a cluster through a cluster group), custom roles (global, per
    tenant, one name two tenants define), accounts of every kind (admins, lowered admins,
    portal_only, denies, extra grants, directory groups, API tokens), VM-ACL rows (wildcards,
    custom lists, keys no vmid spells), pool grants to users and groups (empty ones too) and
    pool members of both kinds. Returns (accounts, {cluster: [(vmid, type)]})."""
    db = seed.db
    seed.tenant('default', rng.choice([[], ['c1']]))
    seed.tenant('t_a', ['c1'])
    seed.tenant('t_b', ['c2'])
    seed.tenant('t_none', [])
    db.execute("INSERT INTO cluster_groups (id, name, tenant_id) VALUES ('grp_b', 'grp_b', 't_b')")
    db.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted, group_id) "
               "VALUES ('c3', 'c3', '10.0.0.3', 'root@pam', 'x', 'grp_b')")
    rbac.save_custom_roles({
        'global': {'ops_g': {'name': 'ops_g', 'permissions': ['vm.view', 'vm.start', 'cluster.view']}},
        'tenants': {
            't_a': {'ops_t': {'name': 'ops_t', 'permissions': ['vm.view', 'vm.console']},
                    'twice': {'name': 'twice', 'permissions': ['vm.view']}},
            't_b': {'twice': {'name': 'twice', 'permissions': ['vm.view', 'vm.delete']},
                    'blind': {'name': 'blind', 'permissions': ['cluster.view']}},
        }})

    names = [f'u{k:02d}' for k in range(n_users)]
    accounts = []
    for name in names:
        tenant = rng.choice(TENANTS)
        override = {}
        if rng.random() < 0.25:
            override = {rng.choice((tenant, 't_a')):
                        {'role': rng.choice(('viewer', 'user', 'admin', 'ops_g', 'ops_t'))}}
        u = seed.user(name, role=rng.choice(ROLES), tenant_id=tenant,
                      portal_only=rng.random() < 0.2,
                      permissions=rng.sample(('vm.view', 'vm.start', 'vm.delete'), rng.randint(0, 1)),
                      denied=(rng.sample(('vm.view', 'vm.start', 'pool.view'), 1)
                              if rng.random() < 0.3 else []),
                      tenant_permissions=override)
        u['groups'] = rng.sample(GROUPS, rng.randint(0, 2))
        if rng.random() < 0.3:
            # an API token: its own role, of what its owner holds
            u['effective_role'] = rng.choice(('viewer', 'user', 'admin', 'ops_g', 'ops_t'))
            if rng.random() < 0.7:
                u['_token_owner_capped'] = True
        accounts.append(u)

    guests = {}
    for cid in CLUSTERS:
        rows = [(100 + i, rng.choice(('qemu', 'lxc'))) for i in range(n_guests)]
        vmid, kind = rows[3]
        rows.append((vmid, 'lxc' if kind == 'qemu' else 'qemu'))     # one vmid as both kinds
        rows += [(str(rows[5][0]), rows[5][1]), (None, 'qemu'), ('x1', 'qemu')]
        guests[cid] = rows

        keys = [str(v) for v, _ in rng.sample(rows[:n_guests], 8)]
        keys += ['0' + str(rows[7][0]), '-7', 'x1']
        for key in keys:
            seed.vm_acl(cid, key, users=rng.sample(names + ['*'], rng.randint(0, 3)),
                        inherit_role=rng.random() < 0.5,
                        permissions=rng.sample(ACL_PERMS, rng.randint(0, 2)))
        for pool in POOLS:
            for subject in rng.sample(names, 3):
                seed.pool(cid, pool, subject, rng.sample(POOL_PERMS, rng.randint(0, 2)))
            if rng.random() < 0.5:
                seed.pool(cid, pool, rng.choice(GROUPS), rng.sample(POOL_PERMS, rng.randint(0, 2)),
                          subject_type='group')
        _members(cid, {f'{v}:{t}': rng.choice(POOLS + ('p_orphan',))
                       for v, t in rows[:n_guests + 1] if rng.random() < 0.5})
    _forget_caches()
    return accounts, guests


def _exits(*fns):
    """The first line of every way out of these functions: each return and each except."""
    out = set()
    for fn in fns:
        code = fn.__code__
        for node in ast.walk(ast.parse(inspect.getsource(fn))):
            if isinstance(node, ast.Return):
                out.add((code, node.lineno + code.co_firstlineno - 1))
            elif isinstance(node, ast.ExceptHandler):
                out.add((code, node.body[0].lineno + code.co_firstlineno - 1))
    return out


class _LinesRun:
    """The lines run in the given functions while the block is open."""

    def __init__(self, *fns):
        self.codes = {fn.__code__ for fn in fns}
        self.lines = set()

    def _call(self, frame, event, arg):
        return self._line if frame.f_code in self.codes else None

    def _line(self, frame, event, arg):
        if event == 'line':
            self.lines.add((frame.f_code, frame.f_lineno))
        return self._line

    def __enter__(self):
        self._was = sys.gettrace()
        sys.settrace(self._call)
        return self

    def __exit__(self, *exc):
        sys.settrace(self._was)


def _disagreements(accounts, guests, clusters, seen):
    wrong = []
    for u in accounts:
        for cid in clusters:
            rows = guests.get(cid, guests['c1'])
            for perm in PERMS:
                allowed = rbac.user_vm_access(u, cid, perm)
                # a frame keeps every row on this without asking: it has to be yes for each
                everything = getattr(allowed, 'everything', False)
                seen['everything'] += everything
                for vmid, kind in rows:
                    for t in (kind, None):
                        want = rbac.user_can_access_vm(u, cid, vmid, perm, t)
                        seen[want] += 1
                        if allowed(vmid, t) != want or (everything and not want):
                            wrong.append((u['username'], u.get('effective_role'), cid, vmid, t,
                                          perm, want))
    return wrong


@pytest.mark.parametrize('rng_seed', [1, 2, 3])
def test_user_vm_access_agrees_with_user_can_access_vm(seed, monkeypatch, rng_seed):
    accounts, guests = _random_estate(seed, random.Random(rng_seed))
    seen = collections.Counter()
    checked = (rbac._user_can_access_vm_uncapped, rbac.user_can_access_vm)
    with _LinesRun(*checked) as run:
        wrong = _disagreements(accounts, guests, CLUSTERS + ('c_nowhere',), seen)

        # the pool grants cannot be read: no pool step, and every non-admin is confined
        def unreadable(*a, **k):
            raise RuntimeError('pool_permissions unreadable')
        with monkeypatch.context() as m:
            m.setattr(rbac, '_pool_perms_for', unreadable)
            wrong += _disagreements(accounts, guests, ('c1', 'c3'), seen)

        # the ACL store cannot be read: nobody but an admin gets a guest
        with monkeypatch.context() as m:
            m.setattr(rbac, 'load_vm_acls', lambda: rbac._Snapshot(unavailable=True))
            rbac.invalidate_vm_acls_cache()
            wrong += _disagreements(accounts, guests, ('c1',), seen)
        rbac.invalidate_vm_acls_cache()

    assert not wrong, f'{len(wrong)} of {seen[True] + seen[False]} answers differ, e.g. {wrong[:5]}'
    assert seen[True] > 1000 and seen[False] > 1000 and seen['everything'], seen
    missed = sorted(line for code, line in _exits(*checked) - run.lines)
    assert not missed, f'no estate took the exits on lines {missed} of user_can_access_vm'


# --- one estate per branch ----------------------------------------------------------------------

@pytest.fixture
def estate(seed):
    """c1 belongs to acme, c2 to globex. 100: alice's row; 101: carol's row with vm.console
    only; 102: a '*' row; '0105': zed's row under a key no vmid spells. Pool p1 holds 200
    (qemu) and 201 (lxc). 300 is nobody's."""
    seed.tenant('acme', ['c1'])
    seed.tenant('globex', ['c2'])
    seed.vm_acl('c1', 100, users=['alice'])
    seed.vm_acl('c1', 101, users=['carol'], inherit_role=False, permissions=['vm.console'])
    seed.vm_acl('c1', 102, users=['*'])
    seed.vm_acl('c1', '0105', users=['zed'])
    seed.pool('c1', 'p1', 'pam', ['pool.admin'])
    seed.pool('c1', 'p1', 'pete', ['vm.start'])
    seed.pool('c1', 'p1', 'quinn', ['vm.start'])
    seed.pool('c1', 'p1', 'quinn2', ['vm.start'])
    seed.pool('c1', 'p1', 'erin', [])
    seed.pool('c1', 'p1', 'gina', [])
    _members('c1', {'200:qemu': 'p1', '201:lxc': 'p1'})
    who = {name: seed.user(name, role='user', tenant_id='acme')
           for name in ('ops', 'ops2', 'alice', 'carol', 'pam', 'quinn', 'quinn2', 'erin', 'zed')}
    who['root'] = seed.user('root', role='admin')
    who['dave'] = seed.user('dave', role='user', tenant_id='globex')
    who['pete'] = seed.user('pete', role='user', tenant_id='globex')
    who['gina'] = seed.user('gina', role='user', tenant_id='globex')
    who['polly'] = seed.user('polly', role='user', tenant_id='acme', portal_only=True)
    who['blind'] = seed.user('blind', role='user', tenant_id='acme', denied=['vm.view'])
    who['pam_token'] = dict(who['pam'], effective_role='viewer', _token_owner_capped=True)
    _forget_caches()
    return who


BRANCHES = [
    ('root', 300, 'qemu', 'vm.delete', True),        # admin
    ('pam', 201, 'lxc', 'vm.delete', True),          # pool.admin hands it out...
    ('pam_token', 201, 'lxc', 'vm.delete', False),   # ...her viewer token does not carry it
    ('pam_token', 201, 'lxc', 'vm.view', True),
    ('alice', 100, 'qemu', 'vm.view', True),         # a row naming the account decides alone
    ('alice', 100, 'qemu', 'vm.delete', False),      # inherit_role hands a fixed set
    ('carol', 101, 'qemu', 'vm.console', True),
    ('carol', 101, 'qemu', 'vm.view', False),        # the row's list, not her role
    ('dave', 102, 'qemu', 'vm.view', True),          # '*', from another tenant
    ('pam', 200, 'qemu', 'vm.delete', True),         # pool.admin
    ('pete', 200, 'qemu', 'vm.start', True),         # the granted permission
    ('pete', 200, 'qemu', 'vm.view', True),          # any grant shows the members
    ('pete', 200, 'qemu', 'vm.console', False),      # not granted, not his tenant's cluster
    ('erin', 300, 'qemu', 'vm.view', True),          # an empty grant confines nobody...
    ('gina', 200, 'qemu', 'vm.view', False),         # ...and shows no member
    ('pete', 201, 'qemu', 'vm.view', False),         # a member as lxc is none as qemu
    ('polly', 300, 'qemu', 'vm.view', False),        # portal_only: no role-wide grant
    ('ops', 300, 'qemu', 'vm.view', True),           # the role, on the tenant's cluster
    ('dave', 300, 'qemu', 'vm.view', False),         # not his tenant's cluster
    ('alice', 300, 'qemu', 'vm.view', False),        # ACL-scoped in her own cluster
    ('quinn', 300, 'qemu', 'vm.view', False),        # pool-scoped in his own cluster
    ('quinn', 201, 'qemu', 'vm.console', True),      # no member as qemu, but in his scope
    ('blind', 300, 'qemu', 'vm.view', False),        # the role withholds it
    ('zed', 105, 'qemu', 'vm.view', True),           # '0105' is no row of 105, but scopes it
    ('zed', 300, 'qemu', 'vm.view', False),
    ('ops', None, 'qemu', 'vm.view', True),
    ('quinn', 'x', 'qemu', 'vm.view', False),        # no vmid is in no scope
    ('ops', 300, None, 'vm.view', True),
    ('pete', 201, None, 'vm.view', True),            # no kind given: either kind's member
]


@pytest.mark.parametrize('name,vmid,kind,perm,expected', BRANCHES)
def test_each_branch(estate, name, vmid, kind, perm, expected):
    u = estate[name]
    assert rbac.user_can_access_vm(u, 'c1', vmid, perm, kind) is expected
    assert rbac.user_vm_access(u, 'c1', perm)(vmid, kind) is expected


def test_every_guest_is_said_only_where_each_one_is_yes(estate, seed):
    guests = (100, 101, 102, 103, 105, 200, 201, 300, None, 'x')

    def unconfined():
        out = set()
        for name, u in estate.items():
            if getattr(rbac.user_vm_access(u, 'c1', 'vm.view'), 'everything', False):
                out.add(name)
                assert all(rbac.user_can_access_vm(u, 'c1', vmid, 'vm.view', 'qemu')
                           for vmid in guests), name
        return out
    # not the ACL- or pool-scoped, not portal_only, not another tenant's or a withheld vm.view
    assert unconfined() == {'ops', 'ops2', 'erin'}
    # a '*' row whose list leaves vm.view out takes its guest from everyone
    seed.vm_acl('c1', 103, users=['*'], inherit_role=False, permissions=['vm.console'])
    rbac.invalidate_vm_acls_cache()
    assert rbac.user_can_access_vm(estate['ops'], 'c1', 103, 'vm.view', 'qemu') is False
    assert unconfined() == set()


@pytest.mark.parametrize('name,vmid,expected', [
    ('root', 300, True), ('alice', 100, False), ('ops', 300, False), ('dave', 102, False)])
def test_an_unread_acl_store_gives_no_guest(estate, monkeypatch, name, vmid, expected):
    monkeypatch.setattr(rbac, 'load_vm_acls', lambda: rbac._Snapshot(unavailable=True))
    rbac.invalidate_vm_acls_cache()
    u = estate[name]
    assert rbac.user_can_access_vm(u, 'c1', vmid, 'vm.view', 'qemu') is expected
    assert rbac.user_vm_access(u, 'c1', 'vm.view')(vmid, 'qemu') is expected


@pytest.mark.parametrize('name,vmid,expected', [
    ('alice', 100, True),     # her row decides before the pool step
    ('alice', 300, False),
    ('quinn', 200, False),    # no pool step, and confined to no row
    ('ops', 300, False),      # an unknown grant confines an operator too
])
def test_unread_pool_grants_confine(estate, monkeypatch, name, vmid, expected):
    def unreadable(*a, **k):
        raise RuntimeError('pool_permissions unreadable')
    monkeypatch.setattr(rbac, '_pool_perms_for', unreadable)
    u = estate[name]
    assert rbac.user_can_access_vm(u, 'c1', vmid, 'vm.view', 'qemu') is expected
    assert rbac.user_vm_access(u, 'c1', 'vm.view')(vmid, 'qemu') is expected


@pytest.mark.parametrize('row', [['pete', 'quinn'], 'pam'])
def test_a_row_that_is_no_mapping_hands_out_no_guest(estate, monkeypatch, row):
    """Only the legacy JSON fallback of load_vm_acls hands one over. user_can_access_vm raises
    on that guest for everyone but an admin, so no pool grant may hand it out here either."""
    acls = rbac._Snapshot({cid: dict(rows) for cid, rows in rbac.load_vm_acls().items()})
    acls['c1']['200'] = row
    monkeypatch.setattr(rbac, 'load_vm_acls', lambda: acls)
    rbac.invalidate_vm_acls_cache()
    raised, wider = [], []
    try:
        for name, u in estate.items():
            try:
                allowed = rbac.user_vm_access(u, 'c1', 'vm.view')
            except AttributeError:
                allowed = lambda vmid, vm_type=None: False     # no frame at all, as it raised
            for vmid in (100, 101, 102, 105, 200, 201, 300):
                try:
                    was = rbac.user_can_access_vm(u, 'c1', vmid, 'vm.view', 'qemu')
                except AttributeError:
                    was = None
                    raised.append((name, vmid))
                if allowed(vmid, 'qemu') and was is not True:
                    wider.append((name, vmid, was))
    finally:
        rbac.invalidate_vm_acls_cache()
    # pete reaches 200 through his pool grant alone, the other raised on it
    assert ('pete', 200) in raised and ('root', 200) not in raised, raised
    assert not wider, wider


# --- the stream -------------------------------------------------------------------------------

def _rows(n):
    return [{'vmid': 100 + i, 'type': 'qemu', 'node': f'n{i % 3}', 'name': f'g{i}'}
            for i in range(n)]


def _statements(db, fn):
    seen = []
    db.conn.set_trace_callback(seen.append)
    try:
        fn()
    finally:
        db.conn.set_trace_callback(None)
    return len(seen)


def test_a_resources_frame_reads_an_account_once_whatever_the_guest_count(estate, seed):
    for name in ('ops', 'alice', 'quinn', 'pete'):
        frame = rt._filtered_resources_frame(_rows(30), 'c1', name, 'ts')   # caches warm
        u = rt._sse_stored_user(name)
        assert [r['vmid'] for r in json.loads(frame)['data']] == [
            r['vmid'] for r in _rows(30)
            if rbac.user_can_access_vm(u, 'c1', r['vmid'], 'vm.view', r['type'])], name
        few = _statements(seed.db, lambda: rt._filtered_resources_frame(_rows(20), 'c1', name, 'ts'))
        many = _statements(seed.db, lambda: rt._filtered_resources_frame(_rows(3000), 'c1', name, 'ts'))
        assert many == few, (name, few, many)


def test_a_tasks_frame_reads_an_account_once_whatever_the_row_count(estate, seed):
    def tasks(n):
        return [{'vmid': 100 + i, 'type': 'qmstart', 'status': 'OK'} for i in range(n)]
    for name in ('alice', 'quinn'):
        frame = rt._filtered_tasks_frame(tasks(210), 'c1', name, 'ts')
        assert [t['vmid'] for t in json.loads(frame)['data']] == (
            [100, 102] if name == 'alice' else [102, 200, 201]), name
        few = _statements(seed.db, lambda: rt._filtered_tasks_frame(tasks(5), 'c1', name, 'ts'))
        many = _statements(seed.db, lambda: rt._filtered_tasks_frame(tasks(500), 'c1', name, 'ts'))
        assert many == few, (name, few, many)


@pytest.fixture
def stream():
    """add(name, clusters, is_admin): a stream of that account, as /api/sse/updates keeps it."""
    saved = dict(rt.sse_clients)
    rt.sse_clients.clear()
    queues = {}

    def add(name, clusters=('c1',), is_admin=False):
        queues[name] = queue.Queue()
        rt.sse_clients[name] = {'queue': queues[name], 'user': name, 'is_admin': is_admin,
                                'clusters': list(clusters) if clusters else None,
                                'effective_role': None}
    try:
        yield add, queues
    finally:
        rt.sse_clients.clear()
        rt.sse_clients.update(saved)
        getattr(rt, '_sse_node_scope', {}).clear()


def _vmids(q):
    return [r['vmid'] for r in json.loads(q.get_nowait())['data']]


def test_accounts_that_keep_the_same_guests_share_one_frame(estate, stream, monkeypatch):
    add, queues = stream
    add('root', None, True)
    for name in ('ops', 'ops2', 'erin', 'quinn', 'quinn2', 'alice', 'zed'):
        add(name)
    made = []
    real = rt._serialize_sse_message
    monkeypatch.setattr(rt, '_serialize_sse_message',
                        lambda *a, **k: made.append(a[0]) or real(*a, **k))
    rows = _rows(400)
    rt.broadcast_sse('resources', rows, 'c1')

    everything = [r['vmid'] for r in rows]
    for name in ('root', 'ops', 'ops2', 'erin'):
        assert _vmids(queues[name]) == everything, name
    assert _vmids(queues['quinn']) == _vmids(queues['quinn2']) == [102, 200, 201]
    # as many guests as alice, other ones: a frame is shared by the rows, never by their count
    assert _vmids(queues['alice']) == [100, 102]
    assert _vmids(queues['zed']) == [102, 105]
    # one frame for all guests, one per other set of them
    assert made == ['resources'] * 4, made


def test_a_pass_over_many_accounts_lets_the_hub_in(estate, stream, monkeypatch):
    """Each account's decision is cheap now, but fifty of them still add up: between two the
    hub gets its turn, so the other requests and streams are not held for the whole pass."""
    add, queues = stream
    names = ('ops', 'alice', 'quinn', 'pete', 'zed')
    for name in names:
        add(name)
    real = rbac.user_vm_access

    def slow(*a, **k):
        until = time.perf_counter() + 0.03
        while time.perf_counter() < until:
            pass
        return real(*a, **k)
    monkeypatch.setattr(rbac, 'user_vm_access', slow)
    ticks = [0]

    def ticker():
        while True:
            gevent.sleep(0.0005)
            ticks[0] += 1
    t = gevent.spawn(ticker)
    gevent.sleep(0.005)
    try:
        before = ticks[0]
        rt.broadcast_sse('resources', _rows(50), 'c1')
        during = ticks[0] - before
    finally:
        t.kill()
    assert all(not queues[n].empty() for n in names)
    assert during >= len(names) - 1, during


def test_an_account_that_keeps_every_guest_is_not_asked_guest_by_guest(estate, stream):
    """Most non-admins are operators nothing confines. Their frame is the shared one, and
    walking 10k rows to find that out cost the hub 3 ms per account and frame."""
    add, queues = stream
    reads = collections.Counter()

    class Row(dict):
        def get(self, key, default=None):
            reads[key] += 1
            return dict.get(self, key, default)

        def __getitem__(self, key):
            reads[key] += 1
            return dict.__getitem__(self, key)
    rows = [Row(r) for r in _rows(3000)]
    for name in ('ops', 'ops2', 'erin'):
        add(name)
    rt.broadcast_sse('resources', rows, 'c1')
    for name in ('ops', 'ops2', 'erin'):
        assert _vmids(queues[name]) == [r['vmid'] for r in _rows(3000)], name
    assert reads['vmid'] == 0, reads

    add('alice')        # confined: her rows are looked at, each once
    rt.broadcast_sse('resources', rows, 'c1')
    assert _vmids(queues['alice']) == [100, 102]
    assert reads['vmid'] == len(rows), reads


def test_a_stream_that_ends_while_the_pass_lets_the_hub_in_gets_nothing(estate, stream, monkeypatch):
    """The pass takes turns between accounts. A stream signed out during one of them is still
    in the pass's snapshot, and its generator sends what it finds queued before it checks."""
    add, queues = stream
    for name in ('ops', 'alice', 'quinn', 'zed'):
        add(name)
    real = rbac.user_vm_access
    asked = []

    def slow(user, *a, **k):
        asked.append(user['username'])
        until = time.perf_counter() + 0.03
        while time.perf_counter() < until:
            pass
        return real(user, *a, **k)
    monkeypatch.setattr(rbac, 'user_vm_access', slow)
    ended = []
    signing_out = gevent.spawn(lambda: ended.append((list(asked), rt.end_session_channels('zed'))))
    rt.broadcast_sse('resources', _rows(50), 'c1')
    signing_out.join()

    # signed out in the middle of the pass, before zed's own turn came
    (asked_before, gone), = ended
    assert asked_before and 'zed' not in asked_before and gone == 1, ended
    assert 'zed' in asked
    # the one thing on zed's queue is what wakes the generator of a dropped stream, no frame
    left = []
    while not queues['zed'].empty():
        left.append(queues['zed'].get_nowait())
    assert left == [rt.STREAM_DROPPED], left
    assert all(not queues[n].empty() for n in ('ops', 'alice', 'quinn'))
