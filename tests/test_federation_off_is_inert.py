"""With the federation switched off, nothing of it runs.

The federation is experimental and off by default: the server setting
federation_enabled is false (an admin switches it on in the settings), and
PEGAPROX_FEDERATION is not set ('1' forces it on, '0' off). Its hooks sit in paths
every install takes - the exits to the clusters, the LDAP and OIDC provisioning, the
login, the cluster reads of the database, the balancers, the HA promotion, the users
and roles routes. Off, each of them has to behave as it did before the federation
existed.

Every test here arms tripwires on the core functions the hooks would call
(instance_id, identity, cluster_owner, foreign_home, takes_writes_for, guard_exit and
the rest): each records the call and raises. The off path must touch none of them, and
its result must be what the plain path gives. Where it helps, a counterproof turns the
switch on and shows the same action does reach a tripwire, so the test cannot pass
because the tripwire sits somewhere the code never looks.

No federation lease file and no federation identity may appear either, and every
/api/federation/ route answers 404 FED_DISABLED - except the switch and its status,
which the settings page needs to offer the switch.

One call runs with the switch off on purpose, and the inventory below names it as the
only one: an HA standby that leaves its group drops the federation identity the HA sync
carried whenever the row is there (federation.forget_inherited). Switched on later, the
host would otherwise act as that member next to its old active.

MK Nov 2026
"""
import json
import os
import re
import subprocess
import sys
import textwrap
import threading

import pyotp
import pytest
from unittest.mock import MagicMock

from pegaprox.core import federation

FOREIGN = 'f' * 32      # an instance id this one is not
OLD_ACTIVE = 'a' * 32   # the HA active a standby takes over from
STANDBY = 'b' * 32
PASSWORD = 'C0rrect!horse9'

TRIPWIRES = ('instance_id', 'identity', '_mutate_identity', 'cluster_owner', 'foreign_home',
             'takes_writes_for', 'worker_takes_writes_for', 'guard_exit', 'cast_votes',
             'lease_round', 'release', 'peer_verdict',
             'sync_identities', 'start_workers', '_lease_state', '_save_leases',
             '_mutate_leases')


def _identity_row():
    from pegaprox.core.db import get_db
    try:
        return get_db().conn.execute(
            "SELECT 1 FROM pegaprox_kv WHERE k = 'federation_identity'").fetchone()
    except Exception:
        return None


@pytest.fixture
def calls(monkeypatch):
    """The switch off (no environment, no setting), the caches of the federation
    forgotten, and every tripwire armed. Yields the list of tripwires that went off; no
    lease file and no identity may exist when the test is done."""
    monkeypatch.delenv(federation.ENV_SWITCH, raising=False)
    lease_file = federation._runtime['lease_file']
    federation.reset_for_tests(lease_file)
    hit = []

    def arm(name):
        def tripwire(*a, **kw):
            hit.append(name)
            raise AssertionError(f'federation.{name} was called with the switch off')
        monkeypatch.setattr(federation, name, tripwire)
    for name in TRIPWIRES:
        arm(name)
    yield hit
    assert not os.path.exists(lease_file), 'a federation lease file was written with the switch off'
    assert _identity_row() is None, 'a federation identity was made with the switch off'


def _switch_on(monkeypatch):
    monkeypatch.setenv(federation.ENV_SWITCH, '1')


def test_the_switch_reads_env_then_setting(db, monkeypatch):
    """'0' is off whatever the setting says, '1' is on, anything else (or nothing) leaves
    it to the setting. The setting is read through a short cache, which set_enabled
    drops at once."""
    started = []
    monkeypatch.setattr(federation, 'start_workers', lambda: started.append(1))
    monkeypatch.delenv(federation.ENV_SWITCH, raising=False)
    assert federation.enabled() is False and federation.forced() is None
    db.save_server_setting(federation.SETTING_KEY, True)
    # the cache still answers what it read a moment ago
    assert federation.enabled() is False
    federation._runtime['switch'] = None
    assert federation.enabled() is True
    # the change the cache saw started the workers, once
    assert started == [1]
    for word in ('true', 'yes', '', '2'):
        monkeypatch.setenv(federation.ENV_SWITCH, word)
        assert federation.enabled() is True, word
        assert federation.forced() is None, word
    monkeypatch.setenv(federation.ENV_SWITCH, '0')
    assert federation.enabled() is False and federation.forced() == 'off'
    db.save_server_setting(federation.SETTING_KEY, False)
    federation._runtime['switch'] = None
    monkeypatch.setenv(federation.ENV_SWITCH, '1')
    assert federation.enabled() is True and federation.forced() == 'on'
    # unset again: the setting (false) decides, no wait for the cache
    monkeypatch.delenv(federation.ENV_SWITCH)
    assert federation.enabled() is False
    federation.set_enabled(True)
    assert federation.enabled() is True
    federation.set_enabled(False)
    assert federation.enabled() is False


# --- the exits to the clusters ---------------------------------------------------------------

def _rows(db):
    for cid, owner in (('c-local', ''), ('c-foreign', FOREIGN)):
        db.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted, fed_owner) "
                   "VALUES (?, ?, '10.0.0.8', 'root@pam', ?, ?)",
                   (cid, cid, db._encrypt('pw'), owner))


def _stub_session(sent):
    import requests

    class Stub(requests.adapters.BaseAdapter):
        def send(self, request, **kwargs):
            sent.append((request.method, request.url))
            resp = requests.Response()
            resp.status_code, resp._content, resp.request = 200, b'{}', request
            return resp

        def close(self):
            pass
    s = requests.Session()
    s.mount('https://', Stub())
    return s


def test_a_cluster_write_at_the_exit_asks_nothing(db, calls, monkeypatch):
    """A guarded session of a cluster another member once led: off, a write goes out
    as it always did, and the exit asks the federation nothing."""
    from pegaprox.core import ha_transport
    _rows(db)
    sent = []
    s = ha_transport.guard_session(_stub_session(sent), cluster_id='c-foreign')
    s.post('https://10.0.0.8:8006/api2/json/nodes/n1/qemu/100/status/start')
    s.get('https://10.0.0.8:8006/api2/json/nodes')
    assert [m for m, _u in sent] == ['POST', 'GET']
    assert calls == []

    # counterproof: switched on, the same write asks the exit guard first
    _switch_on(monkeypatch)
    with pytest.raises(AssertionError):
        s.post('https://10.0.0.8:8006/api2/json/nodes/n1/qemu/100/status/start')
    assert calls == ['guard_exit'] and len(sent) == 2


def test_every_exit_with_a_cluster_asks_nothing(db, calls, monkeypatch):
    """The SSH exits and node_cmd name their Proxmox VE cluster too. Off, none of them asks
    the federation, and none builds the text of its action: no URL is parsed and no peer
    address asked for a write that nobody checks."""
    import subprocess
    from pegaprox.core import ha_transport
    _rows(db)
    built = []
    real_action = ha_transport.http_action
    monkeypatch.setattr(ha_transport, 'http_action',
                        lambda m, u: built.append('http_action') or real_action(m, u))
    monkeypatch.setattr(ha_transport, '_peer', lambda client: built.append('_peer') or '10.0.0.8')
    ran = []
    monkeypatch.setattr(ha_transport.subprocess, 'run',
                        lambda argv, **kw: ran.append(argv) or
                        subprocess.CompletedProcess(argv, 0, b'', b''))

    class Client:
        def exec_command(self, cmd, **kw):
            ran.append(cmd)
            return None, None, None

    def every_exit():
        ha_transport.guard_ssh('10.0.0.8', 'qm start 100', cluster_id='c-foreign')
        ha_transport.guard_client(Client(), cluster_id='c-foreign').exec_command('qm start 100')
        ha_transport.node_cmd(['ssh', 'root@10.0.0.8', 'qm', 'start', '100'], timeout=5,
                              host='10.0.0.8', cluster_id='c-foreign')
        sent = []
        ha_transport.guard_session(_stub_session(sent), cluster_id='c-foreign').post(
            'https://10.0.0.8:8006/api2/json/nodes/n1/qemu/100/status/start')
    every_exit()
    assert calls == [] and built == []
    assert len(ran) == 2

    # counterproof: switched on, each exit asks the guard and builds its action first
    _switch_on(monkeypatch)
    for one in (lambda: ha_transport.guard_ssh('10.0.0.8', 'qm start 100', cluster_id='c-foreign'),
                lambda: ha_transport.guard_client(Client(), cluster_id='c-foreign').exec_command('x'),
                lambda: ha_transport.node_cmd(['ssh', 'x'], timeout=5, host='10.0.0.8',
                                              cluster_id='c-foreign'),
                lambda: ha_transport.guard_session(_stub_session([]), cluster_id='c-foreign').post(
                    'https://10.0.0.8:8006/api2/json/nodes/n1/qemu/100/status/start')):
        with pytest.raises(AssertionError):
            one()
    assert calls == ['guard_exit'] * 4
    assert built == ['_peer', 'http_action']


def test_a_fan_out_is_carried_as_before(calls, monkeypatch):
    """ha.carry hands a fan-out its request's refusal list; off, and with no HA lease in
    force, it gives the function back untouched and asks the federation nothing."""
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'guard_on', lambda: False)

    def work():
        return 'done'
    assert ha.carry(work) is work
    assert calls == []
    # counterproof: switched on, inside a request, the fan-out is wrapped
    _switch_on(monkeypatch)
    monkeypatch.setattr(federation, '_refusal_list', lambda: [])
    assert ha.carry(work) is not work


def test_joining_an_ha_active_asks_nothing(api, seed, calls, monkeypatch):
    """POST /api/ha/join refuses a federation member; off, the check asks nothing and the
    route goes on to read the code."""
    admin = api.as_user(seed.user('root', role='admin'))
    body = {'confirm': True, 'code': 'not-a-code', 'own_url': 'https://standby.example:5000'}
    r = admin.post('/api/ha/join', json=body)
    assert r.status_code == 400, r.data
    assert calls == []
    _switch_on(monkeypatch)
    try:
        admin.post('/api/ha/join', json=body)
    except AssertionError:
        pass
    assert 'identity' in calls


def test_the_users_list_asks_nothing(api, seed, calls, monkeypatch):
    """The users list names the site of a mirrored account while the federation runs; off,
    it shows the row with its home and no site, and asks nothing."""
    admin = api.as_user(seed.user('root', role='admin'))
    seed.user('mirrored', role='viewer')
    seed.db.conn.execute("UPDATE users SET fed_home = ? WHERE username = 'mirrored'",
                         (FOREIGN,))
    seed.db.conn.commit()
    r = admin.get('/api/users')
    assert r.status_code == 200, r.data
    rows = r.get_json()
    rows = rows if isinstance(rows, list) else rows.get('users', rows)
    row = [u for u in rows if u.get('username') == 'mirrored'][0]
    assert row['fed_home'] == FOREIGN and row['fed_site'] == ''
    assert calls == []
    _switch_on(monkeypatch)
    admin.get('/api/users')
    assert 'identity' in calls


def test_saving_users_asks_no_extra_query(db, calls, monkeypatch):
    """Off, a whole-table save (what an LDAP or OIDC sign-in writes) runs one INSERT OR
    REPLACE per user and nothing else of the federation: no home looked up per row, the
    switch read once at most. Signed-in requests read the switch from its cache."""
    for i in range(20):
        db.save_user(f'u{i}', {'password_salt': 's', 'password_hash': 'h', 'role': 'viewer',
                               'enabled': True, 'auth_source': 'ldap'})
    loaded = db.get_all_users()
    seen = []
    db.conn.set_trace_callback(seen.append)
    try:
        db.save_all_users(loaded)
    finally:
        db.conn.set_trace_callback(None)
    assert not [s for s in seen if s.strip().startswith('SELECT fed_home')]
    assert sum(1 for s in seen if 'INSERT OR REPLACE INTO users' in s) == len(loaded)
    assert sum(1 for s in seen if federation.SETTING_KEY in s) <= 1
    assert calls == []
    # counterproof: switched on, every row's home is looked up before it is written
    _switch_on(monkeypatch)
    seen.clear()
    db.conn.set_trace_callback(seen.append)
    try:
        db.save_all_users(loaded)
    finally:
        db.conn.set_trace_callback(None)
    assert len([s for s in seen if s.strip().startswith('SELECT fed_home')]) == len(loaded)


def test_requests_read_the_switch_from_its_cache(api, seed, calls):
    """A handful of signed-in requests with the switch off read the federation setting
    once at most and look up no account's home."""
    admin = api.as_user(seed.user('root', role='admin'))
    from pegaprox.core.db import get_db
    conn = get_db().conn
    seen = []
    conn.set_trace_callback(seen.append)
    try:
        for _ in range(5):
            assert admin.get('/api/auth/check').status_code == 200
    finally:
        conn.set_trace_callback(None)
    assert sum(1 for s in seen if federation.SETTING_KEY in s) <= 1
    assert not [s for s in seen if s.strip().startswith('SELECT fed_home')]
    assert calls == []


# the calls into the federation that may run with the switch off: the switch itself, and
# names that read no state of it
_OFF_SAFE = {'enabled', 'forced'}
# a call guarded where it is set up rather than where it runs, with the reason
_GUARDED_ELSEWHERE = {
    # ha.carry binds the list _federation_refusals handed it, which is None while off
    ('pegaprox/core/ha.py', 'bind_refusals'),
    # the exit watch runs only for what a write kept with the switch on; switched off since,
    # it still tells an enrolled cluster (stopped) from one unenrolled meanwhile (left alone)
    ('pegaprox/core/ha_transport.py', 'is_enrolled'),
}
# the one call that runs while the switch is off, on purpose: a standby that leaves its HA
# group drops the inherited identity whenever its row is there (forget_inherited)
_RUNS_WHILE_OFF = {('pegaprox/core/ha.py', 'forget_inherited')}
_FEDERATION_MODULES = {'pegaprox/core/federation.py', 'pegaprox/core/federation_lease.py',
                       'pegaprox/api/federation.py'}
# names taken from the core by name that read no state of it: an exception and two constants
_TAKEN_BY_NAME = {'SETTING_KEY', 'FED_REFUSED_ENVIRON', 'LeaseRefused'}


_CORE = ('federation', 'federation_lease')


def _federation_aliases(tree):
    """The names a module binds the federation core to, the names it binds the lease
    module to (its calls are hooks too, but it has no switch to ask), and the imports of
    either the inventory cannot follow, as (line, what): a name other than _TAKEN_BY_NAME
    taken from one of them, a relative import, `import pegaprox.core.<module>` without a
    name of its own."""
    import ast
    aliases, lease, odd = set(), set(), []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names = [a.name for a in node.names]
            if node.level:
                if set(_CORE) & set(names + (node.module or '').split('.')):
                    odd.append((node.lineno, f"from {'.' * node.level}{node.module or ''}"))
            elif node.module == 'pegaprox.core':
                aliases |= {a.asname or a.name for a in node.names if a.name == 'federation'}
                lease |= {a.asname or a.name for a in node.names if a.name == 'federation_lease'}
            elif node.module in [f'pegaprox.core.{m}' for m in _CORE]:
                odd += [(node.lineno, n) for n in names if n not in _TAKEN_BY_NAME]
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name not in [f'pegaprox.core.{m}' for m in _CORE]:
                    continue
                if not a.asname:
                    odd.append((node.lineno, a.name))
                elif a.name.endswith('_lease'):
                    lease.add(a.asname)
                else:
                    aliases.add(a.asname)
    return aliases, lease, odd


def _asks_switch(node, aliases, flags):
    """Whether `node`, when true, says the switch is on: `<federation>.enabled()`, a flag
    set from such a test, and the `and`/`or`/`not` around them read the right way round.
    `not <federation>.enabled() and x` says nothing of the kind."""
    import ast
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'enabled' and isinstance(node.func.value, ast.Name)
            and node.func.value.id in aliases):
        return True
    if isinstance(node, ast.Name):
        return node.id in flags
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        # not X true says on <=> X false says on <=> X is true whenever off
        return _off_covered(node.operand, aliases, flags)
    if isinstance(node, ast.BoolOp):
        parts = [_asks_switch(v, aliases, flags) for v in node.values]
        return any(parts) if isinstance(node.op, ast.And) else all(parts)
    return False


def _off_covered(node, aliases, flags):
    """Whether `node` is true whenever the switch is off, so its false branch only runs
    with the switch on."""
    import ast
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _asks_switch(node.operand, aliases, flags)
    if isinstance(node, ast.BoolOp):
        parts = [_off_covered(v, aliases, flags) for v in node.values]
        return any(parts) if isinstance(node.op, ast.Or) else all(parts)
    return False


def _is_off_exit(stmt, aliases, flags):
    """`if not <federation>.enabled(): return/raise/continue` - the off path leaves."""
    import ast
    return (isinstance(stmt, ast.If) and _off_covered(stmt.test, aliases, flags)
            and stmt.body and isinstance(stmt.body[-1], (ast.Return, ast.Raise, ast.Continue)))


def _guarded(call, parents, aliases, flags):
    import ast
    child = call
    node = parents.get(call)
    while node is not None:
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            before = node.values[:node.values.index(child)] if child in node.values else []
            if any(_asks_switch(v, aliases, flags) for v in before):
                return True
        if isinstance(node, (ast.If, ast.While, ast.IfExp)) and child is not node.test:
            in_body = child in (node.body if isinstance(node.body, list) else [node.body])
            if in_body and _asks_switch(node.test, aliases, flags):
                # the body of `if <switch>`
                return True
            if not in_body and _off_covered(node.test, aliases, flags):
                # the else of `if not <switch>`
                return True
        for field in ('body', 'orelse', 'finalbody'):
            seq = getattr(node, field, None)
            if isinstance(seq, list) and child in seq:
                if any(_is_off_exit(s, aliases, flags) for s in seq[:seq.index(child)]):
                    return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return False
        child, node = node, parents.get(node)
    return False


def _hooks_of(rel, src):
    """The hooks of one module: (how many, the bare ones, the _RUNS_WHILE_OFF calls met,
    the imports the walk cannot follow)."""
    import ast
    tree = ast.parse(src)
    aliases, lease, odd = _federation_aliases(tree)
    found, bare, allowed = 0, [], set()
    flags = set()
    parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
    for node in ast.walk(tree):
        # a flag that, when true, says the switch is on - `off = not ...` is none
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and _asks_switch(node.value, aliases, set())):
            flags.add(node.targets[0].id)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in aliases | lease):
            continue
        what = node.func.attr
        if what in _OFF_SAFE or (rel, what) in _GUARDED_ELSEWHERE:
            continue
        if (rel, what) in _RUNS_WHILE_OFF:
            allowed.add((rel, what))
            continue
        found += 1
        if not _guarded(node, parents, aliases, flags):
            bare.append(f'{rel}:{node.lineno} {what}()')
    return found, bare, allowed, [f'{rel}:{line} {what}' for line, what in odd]


def test_every_hook_outside_the_federation_asks_the_switch_first():
    """An inventory, as test_ha_exits keeps one for the HA guard: every call into the
    federation core from a module outside it - the manager, the background jobs, the
    routes, the HA module, the exits - sits behind federation.enabled(): in the same
    condition, in an enclosing if, behind an early return of the off path, or behind a
    flag set from the switch. A new hook that forgets it turns this red. _RUNS_WHILE_OFF is
    the one call allowed past it, and it has to be there."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found, bare, allowed, unread = 0, [], set(), []
    for folder, _dirs, files in os.walk(os.path.join(root, 'pegaprox')):
        for name in files:
            if not name.endswith('.py'):
                continue
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, root).replace(os.sep, '/')
            if rel in _FEDERATION_MODULES:
                continue
            with open(path, encoding='utf-8') as fh:
                src = fh.read()
            # every form of the import names the module
            if 'federation' not in src:
                continue
            n, b, a, u = _hooks_of(rel, src)
            found, bare, allowed, unread = found + n, bare + b, allowed | a, unread + u
    # counterproof that the walk sees the hooks: the manager, the jobs, the routes, the exits
    assert found >= 15, found
    assert not bare, bare
    assert allowed == _RUNS_WHILE_OFF, allowed
    # a hook behind an import the walk does not follow would pass unseen: the core is
    # imported as `from pegaprox.core import federation [as x]`, the lease module alike
    assert not unread, unread


def test_the_inventory_reads_every_import_of_the_core():
    """Counterproof for the import half of the inventory: each way of importing the core
    either names an alias the walk follows or is flagged."""
    import ast
    src = textwrap.dedent("""
        from pegaprox.core import ha, federation as _a
        from pegaprox.core import (federation as _b)
        import pegaprox.core.federation as _c
        from pegaprox.core.federation import worker_takes_writes_for
        from pegaprox.core.federation import LeaseRefused
        import pegaprox.core.federation
        from . import federation
        from .federation import guard_exit
        from pegaprox.core import federation_lease
        from pegaprox.core import federation_lease as _fl
        import pegaprox.core.federation_lease as _fl2
        from pegaprox.core.federation_lease import lease_round
        import pegaprox.core.federation_lease
        from .federation_lease import note_epoch_kept
        from . import federation_lease
    """)
    aliases, lease, odd = _federation_aliases(ast.parse(src))
    assert aliases == {'_a', '_b', '_c'}
    assert lease == {'federation_lease', '_fl', '_fl2'}
    assert odd == [(5, 'worker_takes_writes_for'), (7, 'pegaprox.core.federation'),
                   (8, 'from .'), (9, 'from .federation'), (13, 'lease_round'),
                   (14, 'pegaprox.core.federation_lease'), (15, 'from .federation_lease'),
                   (16, 'from .')]


def test_the_inventory_flags_a_bare_call_of_the_lease_module():
    """Counterproof: the lease module has no switch of its own, and a call of it outside
    the federation needs the core's switch first like any other hook."""
    src = textwrap.dedent("""
        from pegaprox.core import federation, federation_lease as fl
        def bare():
            fl.lease_round()
        def guarded():
            if not federation.enabled():
                return
            fl.lease_round()
    """)
    found, bare, _allowed, unread = _hooks_of('pegaprox/x.py', src)
    assert (found, bare, unread) == (2, ['pegaprox/x.py:4 lease_round()'], [])


def test_the_inventory_flags_a_bare_hook():
    """Counterproof: the checks of the inventory above flag a hook without the switch and
    pass one behind it."""
    import ast
    src = textwrap.dedent("""
        from pegaprox.core import federation as _fed
        def bare(cid):
            return _fed.worker_takes_writes_for(cid)
        def guarded(cid):
            if not _fed.enabled():
                return True
            return _fed.worker_takes_writes_for(cid)
        def inline(cid):
            return _fed.enabled() and _fed.worker_takes_writes_for(cid)
        def wrong_branch(cid):
            if not _fed.enabled():
                return _fed.worker_takes_writes_for(cid)
            return True
        def other_branch(cid):
            if not _fed.enabled():
                return True
            else:
                return _fed.worker_takes_writes_for(cid)
        def inverted_inline(cid):
            return not _fed.enabled() and _fed.worker_takes_writes_for(cid)
        def inverted_or(cid, x):
            if not _fed.enabled() or x:
                return _fed.worker_takes_writes_for(cid)
        def inverted_flag(cid):
            off = not _fed.enabled()
            if off:
                return _fed.worker_takes_writes_for(cid)
        def exit_with_and(cid, x):
            if not _fed.enabled() and x:
                return True
            return _fed.worker_takes_writes_for(cid)
        def exit_with_or(cid, x):
            if not _fed.enabled() or x:
                return True
            return _fed.worker_takes_writes_for(cid)
        def both_and(cid, x):
            if x and _fed.enabled():
                return _fed.worker_takes_writes_for(cid)
    """)
    tree = ast.parse(src)
    parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
    flags = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                and _asks_switch(node.value, {'_fed'}, set())):
            flags.add(node.targets[0].id)
    verdict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'worker_takes_writes_for':
            fn = node
            while not isinstance(fn, ast.FunctionDef):
                fn = parents[fn]
            verdict[fn.name] = _guarded(node, parents, {'_fed'}, flags)
    assert flags == set()
    assert verdict == {'bare': False, 'guarded': True, 'inline': True,
                       'wrong_branch': False, 'other_branch': True,
                       # the switch asked the wrong way round guards nothing
                       'inverted_inline': False, 'inverted_or': False, 'inverted_flag': False,
                       'exit_with_and': False, 'exit_with_or': True, 'both_and': True}


# --- a leftover mirror is a disabled account everywhere --------------------------------

def _mirror_admin(seed):
    seed.user('mira', role='admin')
    seed.db.conn.execute('UPDATE users SET fed_home = ? WHERE username = ?', (FOREIGN, 'mira'))
    seed.db.conn.commit()


def test_a_leftover_mirror_scrapes_no_metrics(api, seed, calls):
    """Off, a mirrored admin's API token is refused by /api/metrics as it is by every
    require_auth route; the same token of a local admin scrapes."""
    from pegaprox.utils.auth import create_api_token
    _mirror_admin(seed)
    with api.app.test_request_context('/'):
        tok = create_api_token('mira', 'scrape', role='admin')['token']
    head = {'Authorization': f'Bearer {tok}'}
    assert api.anon().get('/api/federation/status', headers=head).status_code == 401
    assert api.anon().get('/api/metrics', headers=head).status_code in (401, 403)
    assert calls == []
    seed.db.conn.execute("UPDATE users SET fed_home = '' WHERE username = 'mira'")
    seed.db.conn.commit()
    assert api.anon().get('/api/metrics', headers=head).status_code == 200


def test_a_leftover_mirror_opens_no_console_and_no_stream(api, seed, calls):
    """Off, the console gate and the live streams refuse a mirror like a disabled account;
    the same row homed here passes."""
    from pegaprox.api.vms import _console_authz
    from pegaprox.api.realtime import _stream_identity
    from pegaprox.utils.auth import resolve_authz_user
    _mirror_admin(seed)
    assert resolve_authz_user({'user': 'mira', 'role': 'admin'}) is None
    row = dict(seed.db.get_user('mira'), username='mira')
    assert _console_authz(row, 'c1', 100, 'qemu', by_session=True) == (False, 'account disabled')
    with api.app.test_request_context('/'):
        assert _stream_identity('mira') is None
    from pegaprox.utils.realtime import create_sse_token, validate_sse_token
    assert validate_sse_token(create_sse_token('mira', None, 'admin')) is None
    assert calls == []
    seed.db.conn.execute("UPDATE users SET fed_home = '' WHERE username = 'mira'")
    seed.db.conn.commit()
    user = resolve_authz_user({'user': 'mira', 'role': 'admin'})
    assert _console_authz(user, 'c1', 100, 'qemu', by_session=True) == (True, None)
    with api.app.test_request_context('/'):
        assert _stream_identity('mira') is not None
    assert validate_sse_token(create_sse_token('mira', None, 'admin')) is not None


# --- LDAP, OIDC and the login ----------------------------------------------------------

def _mirrored(db, username):
    db.conn.execute('UPDATE users SET fed_home = ? WHERE username = ?', (FOREIGN, username))
    db.conn.commit()


def test_ldap_provisioning_asks_nothing(db, calls, monkeypatch):
    import pegaprox.utils.ldap as ldapmod
    for name in ('carol', 'mirka'):
        db.save_user(name, {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                            'auth_source': 'ldap', 'enabled': True})
    _mirrored(db, 'mirka')

    user = ldapmod.ldap_provision_user({'username': 'carol', 'role': 'user'})

    assert user is not None and user['role'] == 'user'
    assert db.get_user('carol')['role'] == 'user'
    # a mirror is never the directory's, in either state of the switch, and the rule reads
    # the row - it asks the federation nothing
    for switched_on in (False, True):
        if switched_on:
            _switch_on(monkeypatch)
        assert ldapmod.ldap_provision_user({'username': 'mirka', 'role': 'admin'}) is None
        assert db.get_user('mirka')['role'] == 'viewer'
        assert ldapmod.ldap_provision_user({'username': 'carol', 'role': 'viewer'}) is not None
    assert calls == []


def test_oidc_provisioning_asks_nothing(db, calls, monkeypatch):
    from pegaprox.utils.oidc import oidc_provision_user
    info = {'sub': 'sub-kim', 'preferred_username': 'kim'}
    assert oidc_provision_user(info, {'role': 'viewer', '_authoritative': True})

    # the second sign-in refreshes the row the first one made
    user = oidc_provision_user(info, {'role': 'user', '_authoritative': True})

    assert user is not None and db.get_user('kim')['role'] == 'user'
    db.save_user('ops', {'password_salt': '', 'password_hash': '', 'role': 'admin',
                         'auth_source': 'oidc', 'enabled': True})
    _mirrored(db, 'ops')
    ops = {'sub': 'sub-ops', 'preferred_username': 'ops'}
    for switched_on in (False, True):
        if switched_on:
            _switch_on(monkeypatch)
        assert oidc_provision_user(ops, {'role': 'admin', '_authoritative': True}) is None
        assert db.get_user('ops')['oidc_sub'] == ''
        assert oidc_provision_user(info, {'role': 'viewer', '_authoritative': True})
    assert calls == []


def _totp_account(db, username='ops'):
    from pegaprox.utils.auth import hash_password
    salt, pw_hash = hash_password(PASSWORD)
    secret = pyotp.random_base32()
    db.save_user(username, {'password_salt': salt, 'password_hash': pw_hash, 'role': 'user',
                            'enabled': True, 'auth_source': 'local',
                            'totp_enabled': True, 'totp_secret': secret})
    return secret


def _mirrored_totp(db, username):
    """A mirror as the sync stores it: totp_enabled travels, the secret does not."""
    from pegaprox.utils.auth import hash_password
    salt, pw_hash = hash_password(PASSWORD)
    db.save_user(username, {'password_salt': salt, 'password_hash': pw_hash, 'role': 'user',
                            'enabled': True, 'auth_source': 'local'})
    db.conn.execute("UPDATE users SET totp_enabled = 1, totp_secret_encrypted = '', "
                    "fed_home = ? WHERE username = ?", (FOREIGN, username))
    db.conn.commit()


def test_a_totp_user_signs_in_as_before(api, db, calls, monkeypatch):
    secret = _totp_account(db)
    _mirrored_totp(db, 'mira')

    # without the code the login asks for it, with the code it signs in
    r = api.anon().post('/api/auth/login', json={'username': 'ops', 'password': PASSWORD})
    body = r.get_json() or {}
    assert r.status_code == 200 and body.get('requires_2fa'), (r.status_code, body)
    r = api.anon().post('/api/auth/login', json={'username': 'ops', 'password': PASSWORD,
                                                 'totp_code': pyotp.TOTP(secret).now()})
    body = r.get_json() or {}
    assert r.status_code == 200 and body.get('session_id'), (r.status_code, body)
    # a leftover mirror is a dead account while off - never a sign-in on the password alone
    r = api.anon().post('/api/auth/login', json={'username': 'mira', 'password': PASSWORD})
    assert r.status_code == 401 and not (r.get_json() or {}).get('session_id'), r.data
    assert calls == []

    # counterproof: switched on, the mirror branch is live and sends the account home,
    # and the local account still signs in - neither asks the federation anything
    _switch_on(monkeypatch)
    r = api.anon().post('/api/auth/login', json={'username': 'mira', 'password': PASSWORD})
    assert r.status_code == 409 and r.get_json()['code'] == 'FED_2FA_HOME', r.data
    assert r.get_json()['home'] == FOREIGN
    secret = _totp_account(db, 'ops2')
    r = api.anon().post('/api/auth/login', json={'username': 'ops2', 'password': PASSWORD,
                                                 'totp_code': pyotp.TOTP(secret).now()})
    assert r.status_code == 200 and r.get_json().get('session_id'), r.data
    assert calls == []


def test_the_second_factor_is_read_as_before(db, calls, monkeypatch):
    """The user reads open the TOTP secret with the plain _decrypt, raise and all, as they
    did before the federation - in both states of the switch. No row the sync writes holds
    a secret this host cannot open."""
    db.save_user('ops', {'password_salt': 'x', 'password_hash': 'x', 'role': 'user'})
    db.conn.execute("UPDATE users SET totp_secret_encrypted = 'aes256:AAAA', "
                    "totp_enabled = 1 WHERE username = 'ops'")
    db.conn.commit()

    for switched_on in (False, True):
        if switched_on:
            _switch_on(monkeypatch)
        with pytest.raises(RuntimeError):
            db.get_user('ops')
        with pytest.raises(RuntimeError):
            db.get_all_users()
    assert not hasattr(db, '_decrypt_safe') and not hasattr(db, '_totp_decrypt')
    assert calls == []


def test_a_leftover_mirror_does_not_sign_in_while_off(api, db, calls):
    """A row a federation once mirrored, with the federation off here (a restored database,
    or PEGAPROX_FEDERATION=0): nothing syncs it, so it is a disabled account - no sign-in,
    and a session it still holds is refused."""
    from pegaprox.utils.auth import hash_password
    salt, pw_hash = hash_password(PASSWORD)
    db.save_user('left', {'password_salt': salt, 'password_hash': pw_hash, 'role': 'admin',
                          'enabled': True, 'auth_source': 'local'})
    held = api.as_user({'username': 'left', 'role': 'admin'})
    _mirrored(db, 'left')

    r = api.anon().post('/api/auth/login', json={'username': 'left', 'password': PASSWORD})
    assert r.status_code == 401 and not (r.get_json() or {}).get('session_id'), r.data
    r = held.get('/api/users')
    assert r.status_code == 401 and r.get_json()['code'] == 'ACCOUNT_DISABLED', r.data
    assert calls == []

    # counterproof: the same row homed here signs in
    db.conn.execute("UPDATE users SET fed_home = '' WHERE username = 'left'")
    db.conn.commit()
    r = api.anon().post('/api/auth/login', json={'username': 'left', 'password': PASSWORD})
    assert r.status_code == 200 and r.get_json().get('session_id'), r.data
    assert held.get('/api/users').status_code == 200
    assert calls == []


# --- the cluster reads -------------------------------------------------------------------

def test_every_cluster_row_is_read_as_before(db, calls, monkeypatch):
    """Off, every row of an install that never joined a federation is read as before, and
    the reads ask the federation nothing. A row a federation owns (a leftover of a site
    that was a member, or one that is still a member with PEGAPROX_FEDERATION=0) stays
    out: nothing fences its writes while the federation is off."""
    _rows(db)
    plain = {r['id'] for r in db.conn.execute("SELECT id FROM clusters WHERE fed_owner = ''")}

    clusters = db.get_all_clusters()

    assert set(clusters) == plain == {'c-local'}
    assert clusters['c-local']['pass'] == 'pw'
    assert db.get_cluster('c-local')['pass'] == 'pw'
    assert db.get_cluster('c-foreign') is None
    assert calls == []

    # counterproof: switched on, the reads ask who this instance is
    _switch_on(monkeypatch)
    assert set(db.get_all_clusters()) == {'c-local'}
    assert 'instance_id' in calls


# --- the balancers and the scheduler ------------------------------------------------------

def test_the_balance_check_asks_nothing(db, calls, monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    fake = MagicMock()
    fake.get_node_status.return_value = {}

    PegaProxManager.run_balance_check(fake)

    fake.get_node_status.assert_called_once_with()
    assert calls == []

    _switch_on(monkeypatch)
    with pytest.raises(AssertionError):
        PegaProxManager.run_balance_check(MagicMock())
    assert calls == ['worker_takes_writes_for']


def test_the_cross_cluster_balance_asks_nothing(calls, monkeypatch):
    import pegaprox.background.cross_cluster_lb as xclb
    fake_db = MagicMock()
    fake_db.query.return_value = [{'id': 'c1'}, {'id': 'c2'}]
    monkeypatch.setattr(xclb, 'get_db', lambda: fake_db)
    monkeypatch.setattr(xclb, 'cluster_managers', {'c1': 'mgr1', 'c2': 'mgr2'})
    monkeypatch.setattr(xclb, 'compute_cluster_score', {'mgr1': 85.0, 'mgr2': 20.0}.get)
    audits = []
    monkeypatch.setattr(xclb, 'log_audit', lambda *a, **k: audits.append(a[1]))
    group = {'id': 'g1', 'name': 'grp', 'cross_cluster_threshold': 10,
             'cross_cluster_dry_run': 1}

    xclb.run_cross_cluster_balance_check(group)

    assert audits == ['xclb.dry_run'] and calls == []


def test_a_scheduled_task_asks_nothing(calls):
    from pegaprox.background import scheduler
    said = scheduler.task_refusal('c1', 'no-such-action')
    assert said.startswith('Unknown action') and calls == []


# --- the HA promotion ---------------------------------------------------------------------

def _standby_state(ha):
    import json
    peer = {'instance_id': OLD_ACTIVE, 'url': 'https://active.example:5000',
            'fingerprint': '', 'secret_out': 'y' * 43,
            'secret_in_hash': ha._hash_secret('z' * 48),
            'paired_at': '2026-09-29T10:00:00+00:00', 'role_seen': 'active',
            'epoch_seen': 1}
    st = {'role': 'standby', 'epoch': 2, 'instance_id': STANDBY, 'interval': 30,
          'peer': peer, 'pairing': None, 'sync': {}, 'forward_writes': False}
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        json.dump(st, fh)
    ha.reset_for_tests()


def test_a_standby_that_leaves_its_group_drops_the_identity_while_off(db, calls):
    """The one call that runs with the switch off (_RUNS_WHILE_OFF). Without an identity
    row the unpairing of a standby changes nothing of the federation, the setting
    included; with the row the HA sync carried, the row goes, so the host is no member when
    the switch goes on later. Neither asks any state of the federation."""
    from pegaprox.core import ha
    _standby_state(ha)
    assert ha.unpair() == 'standby'
    assert db.get_server_setting(federation.SETTING_KEY, 'unset') == 'unset'
    db.conn.execute('CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)')
    db.conn.execute("INSERT INTO pegaprox_kv (k, v) VALUES ('federation_identity', '{}')")
    db.conn.commit()
    _standby_state(ha)
    assert _identity_row() is not None
    assert ha.unpair() == 'standby'
    assert _identity_row() is None
    assert federation.enabled() is False and calls == []


def test_a_promotion_asks_the_federation_nothing(db, calls, monkeypatch):
    """An HA group is one member of the federation: its identity rides the HA sync, so
    a promotion moves nothing, in either state of the switch."""
    from pegaprox.core import ha
    db.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted, fed_owner) "
               "VALUES ('c-ha', 'c-ha', '10.0.0.8', 'root@pam', 'x', ?)", (OLD_ACTIVE,))
    for switched_on in (False, True):
        if switched_on:
            _switch_on(monkeypatch)
        _standby_state(ha)
        epoch, _gap = ha._promote()
        assert epoch == 3 and ha.role() == 'active'
        owner = db.conn.execute("SELECT fed_owner FROM clusters WHERE id = 'c-ha'").fetchone()[0]
        assert owner == OLD_ACTIVE
        assert calls == [], switched_on


# --- the users and roles routes -----------------------------------------------------------

def test_the_users_and_roles_routes_ask_nothing(api, seed, calls):
    admin = api.as_user(seed.user('root', role='admin'))
    # a row a federation once mirrored: off, nobody reads its home
    seed.user('mirrored', role='viewer')
    seed.db.conn.execute("UPDATE users SET fed_home = ? WHERE username = 'mirrored'",
                         (FOREIGN,))
    seed.db.conn.commit()

    r = admin.put('/api/users/mirrored', json={'role': 'user'})
    assert r.status_code == 200, r.data
    r = admin.post('/api/roles', json={'id': 'ops', 'name': 'Ops',
                                       'permissions': ['vm.view']})
    assert r.status_code in (200, 201), r.data
    assert admin.delete('/api/roles/ops').status_code == 200
    assert admin.delete('/api/users/mirrored').status_code == 200
    assert seed.db.get_user('mirrored') is None
    assert calls == []


# --- the federation routes and its workers ------------------------------------------------

def _federation_routes(app):
    out = []
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith('/api/federation/'):
            continue
        path = re.sub(r'<[^>]+>', lambda m: FOREIGN if 'instance' in m.group(0) else 'c1',
                      rule.rule)
        for method in sorted(rule.methods - {'HEAD', 'OPTIONS'}):
            out.append((method, path))
    return out


OFF_STATUS = {'enabled': False, 'forced': False, 'can_disable': False, 'disable_blockers': [],
              'manage': True, 'local_account': True, 'reauth': 'password'}


def test_every_federation_route_answers_404(api, seed, calls):
    routes = _federation_routes(api.app)
    # counterproof that the walk sees them: the admin half and the peer half
    assert len(routes) >= 20 and ('POST', '/api/federation/peer/join') in routes
    assert ('POST', '/api/federation/switch') in routes
    admin = api.as_user(seed.user('root', role='admin'))
    for method, path in routes:
        for who, client in (('admin', admin), ('anonymous', api.anon())):
            r = getattr(client, method.lower())(path, json={})
            if (method, path) == ('GET', '/api/federation/status'):
                if who == 'admin':
                    assert r.status_code == 200 and r.get_json() == OFF_STATUS, r.data
                else:
                    assert r.status_code == 401
                continue
            if (method, path) == ('POST', '/api/federation/switch'):
                # the switch answers either way: a body that says neither on nor off is
                # refused, nobody without a login gets near it
                if who == 'admin':
                    assert r.status_code == 400 and r.get_json()['code'] == 'FED_BAD_VALUE'
                else:
                    assert r.status_code == 401
                continue
            body = r.get_json(silent=True) or {}
            assert r.status_code == 404 and body.get('code') == 'FED_DISABLED', \
                (who, method, path, r.status_code, body)
    assert calls == []


def test_a_peer_call_is_not_checked(api, calls):
    """The rate limiter of validate_request takes a member's signed call out of the
    count. Off, it checks no signature, and the route answers 404."""
    r = api.anon().get('/api/federation/peer/status',
                       headers={'X-PegaProx-Peer': FOREIGN, 'X-PegaProx-Peer-Ts': '1',
                                'X-PegaProx-Peer-Nonce': 'n', 'X-PegaProx-Peer-Sig': 's'})
    assert r.status_code == 404 and r.get_json()['code'] == 'FED_DISABLED'
    assert calls == []


def test_no_federation_worker_runs(api, calls):
    """The app of this test run was built with the switch off: register_blueprints
    started no worker, and asking whether one runs asks the federation nothing."""
    if os.environ.get(federation.ENV_SWITCH) == '1':
        pytest.skip('this test run has the federation switched on')

    assert federation.enabled() is False
    assert federation.workers_running() is False
    assert not [t.name for t in threading.enumerate() if t.name.startswith('federation-')]
    assert calls == []


# --- the start of the app ----------------------------------------------------------------

_BOOT = textwrap.dedent("""
    import json, os, sys, threading
    from pegaprox.core import federation
    if sys.argv[2] == 'setting':
        from pegaprox.core.db import get_db
        get_db().save_server_setting(federation.SETTING_KEY, True)
    hit = []
    def wire(name, orig):
        def recorded(*a, **kw):
            hit.append(name)
            return orig(*a, **kw)
        return recorded
    for name in sys.argv[1].split(','):
        setattr(federation, name, wire(name, getattr(federation, name)))
    from pegaprox.app import create_app
    create_app()
    from pegaprox.core.db import get_db
    try:
        ident = get_db().conn.execute(
            "SELECT 1 FROM pegaprox_kv WHERE k = 'federation_identity'").fetchone() is not None
    except Exception:
        ident = False
    print(json.dumps({
        'calls': hit,
        'running': federation.workers_running(),
        'threads': [t.name for t in threading.enumerate() if t.name.startswith('federation-')],
        'lease_file': federation._runtime['lease_file'],
        'identity': ident,
    }))
    sys.stdout.flush()
    os._exit(0)
""")


def _boot(tmp_path, switch):
    """switch: None (off), 'env' (PEGAPROX_FEDERATION=1) or 'setting' (the server
    setting written before the start)."""
    env = dict(os.environ, PEGAPROX_CONFIG_DIR=str(tmp_path))
    env.pop(federation.ENV_SWITCH, None)
    if switch == 'env':
        env[federation.ENV_SWITCH] = '1'
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run([sys.executable, '-c', _BOOT, ','.join(TRIPWIRES), switch or 'off'],
                       cwd=root, env=env, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr[-3000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_the_app_starts_without_the_federation(tmp_path):
    """create_app() in a process of its own, the way an install starts: nothing of
    the federation is asked, no worker runs, no lease file is written and no identity
    made. The session app of the other tests was built before any tripwire could be
    armed, so this one starts its own."""
    out = _boot(tmp_path, switch=None)
    assert out['calls'] == [] and out['running'] is False and out['threads'] == []
    assert out['lease_file'].startswith(str(tmp_path))
    assert not os.path.exists(out['lease_file'])
    assert out['identity'] is False


@pytest.mark.parametrize('switch', ('env', 'setting'))
def test_the_app_starts_the_federation_when_switched_on(tmp_path, switch):
    """Counterproof: the same start with the switch on - by the environment, or by the
    setting an admin saved - starts the workers."""
    out = _boot(tmp_path, switch=switch)
    assert out['running'] is True and 'start_workers' in out['calls']
    assert sorted(out['threads']) == ['federation-lease', 'federation-sync']
