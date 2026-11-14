"""A disabled ESXi server can be switched back on and removed after a restart.

load_vmware_servers loads the rows with enabled = 1 only, and check_vmware_access asked the
in-memory registry alone: a server that was disabled was a 404 at the gate after the next
start. GET /api/vmware still listed it from the table, but PUT and DELETE never got past the
gate, so the row could be fixed or removed in the database only.

Update and delete fall back to the row now (the other routes under /api/vmware/<id> do not,
they need a loaded server anyway). The row is held to the rule of the gate: a global admin,
an unlinked server, an unconfined caller or a linked cluster the caller owns - a pool grant
does not count. linked_clusters that do not parse leave the row to a global admin, as in the
list, and an update of such a row has to name the clusters, or the server would come up
linked to nobody, which is open to everybody. Switched back on without the password typed
again, the server connects with the stored one.

The list entry of such a row is what the edit dialog is filled from, and the dialog saves
all of it. It had no account, TLS setting or notes, so the dialog put in 'root', TLS off and
no notes, and a rename wrote those over the row. And an edit that keeps the server disabled
leaves it out of the registry, as a start does: registered, the keepalive of the broadcast
loop connected it to the stored host with the stored password. MK
"""
import inspect
import re

import pytest

import pegaprox.api.vmware as vmwareapi
import pegaprox.globals as ppglobals
from pegaprox.core.vmware import VMwareManager, load_vmware_servers, save_vmware_server

PARKED, BROKEN = 'esx-off-b', 'esx-off-broken'


def _perms_of(*handlers):
    """What these routes ask for, so that a refusal below is the object gate."""
    src = inspect.getsource(vmwareapi)
    return sorted({re.findall(r"require_auth\(perms=\['([a-z.]+)'\]\)", src[:src.index(f'\ndef {h}(')])[-1]
                   for h in handlers})


PERMS = _perms_of('list_vmware_servers', 'update_vmware_server', 'delete_vmware_server')


@pytest.fixture
def dials(monkeypatch):
    seen = []

    def connect(self):
        seen.append((self.id, self.host, self.password))
        self.connected = True
        return True
    monkeypatch.setattr(VMwareManager, 'connect', connect)
    return seen


@pytest.fixture
def offline(monkeypatch):
    """Nothing here may dial a host."""
    import requests

    def _refuse(*a, **k):
        raise AssertionError('an ESXi request left the process')
    for name in ('get', 'post', 'put', 'delete', 'request'):
        monkeypatch.setattr(requests, name, _refuse)
    monkeypatch.setattr(requests.Session, 'request', _refuse)


@pytest.fixture
def people(api, seed):
    seed.tenant('acme', clusters=['cluster_a'])
    seed.tenant('other', clusters=['cluster_b'])
    # a pool on the other tenant's cluster: a claim on guests there, not on its ESXi server
    seed.pool('cluster_b', 'pool_b', 'pooly', ['pool.view', 'vm.view'])
    return {
        'admin': seed.user('root', role='admin'),
        'acme': seed.user('alice', role='viewer', tenant_id='acme', permissions=PERMS),
        'other': seed.user('bob', role='viewer', tenant_id='other', permissions=PERMS),
        'pool': seed.user('pooly', role='viewer', tenant_id='acme', permissions=PERMS),
        'unconfined': seed.user('plain', role='viewer', permissions=PERMS),
    }


def _park(sid, linked, **kw):
    save_vmware_server(sid, dict({'name': sid, 'host': f'{sid}.lab', 'username': 'root',
                                  'password': 'stored-pw', 'server_type': 'esxi',
                                  'enabled': False, 'linked_clusters': linked}, **kw))


@pytest.fixture
def restarted(people, dials):
    """Two disabled servers of the other tenant, one with linked_clusters that do not parse,
    after a start: in the table, not in the registry."""
    from pegaprox.core.db import get_db
    _park(PARKED, ['cluster_b'])
    _park(BROKEN, ['cluster_b'])
    get_db().conn.execute("UPDATE vmware_servers SET linked_clusters = '[broken' WHERE id = ?", (BROKEN,))
    get_db().conn.commit()
    load_vmware_servers()
    assert PARKED not in ppglobals.vmware_managers and BROKEN not in ppglobals.vmware_managers
    return people


def _row(sid):
    from pegaprox.core.db import get_db
    r = get_db().conn.cursor().execute('SELECT * FROM vmware_servers WHERE id = ?', (sid,)).fetchone()
    return dict(r) if r else None


def _as(api, people, who):
    return api.as_user(people[who])


# --- the owner and an admin get to it ----------------------------------------------------------

def test_an_admin_can_remove_it(api, restarted):
    admin = _as(api, restarted, 'admin')
    assert any(s['id'] == PARKED for s in admin.get('/api/vmware').get_json())
    r = admin.delete(f'/api/vmware/{PARKED}')
    assert r.status_code == 200, (r.status_code, r.get_json())
    assert _row(PARKED) is None
    assert not any(s['id'] == PARKED for s in admin.get('/api/vmware').get_json())


def test_switched_back_on_it_connects_with_the_stored_password(api, restarted, dials):
    r = _as(api, restarted, 'admin').put(f'/api/vmware/{PARKED}', json={'enabled': True})
    assert r.status_code == 200, (r.status_code, r.get_json())
    assert _row(PARKED)['enabled'] == 1
    mgr = ppglobals.vmware_managers[PARKED]
    assert mgr.password == 'stored-pw', 'the live manager came up without the stored credential'
    assert (mgr.server_type, mgr.linked_clusters, mgr.enabled) == ('esxi', ['cluster_b'], True)
    assert dials == [(PARKED, f'{PARKED}.lab', 'stored-pw')]


def test_the_owning_tenant_may_change_and_remove_it_another_may_not(api, restarted, dials):
    owner = _as(api, restarted, 'other')
    r = owner.put(f'/api/vmware/{PARKED}', json={'notes': 'rack 9'})
    assert r.status_code == 200, (r.status_code, r.get_json())
    assert _row(PARKED)['notes'] == 'rack 9' and _row(PARKED)['enabled'] == 0
    # still disabled: still only a row, and not connected
    assert PARKED not in ppglobals.vmware_managers and not dials

    before = _row(PARKED)
    for verb in ('put', 'delete'):
        for who in ('acme', 'pool'):
            kw = {'json': {'notes': 'probe'}} if verb == 'put' else {}
            r = getattr(_as(api, restarted, who), verb)(f'/api/vmware/{PARKED}', **kw)
            assert r.status_code == 403, (who, verb, r.status_code)
            assert _row(PARKED) == before, (who, verb)
    assert PARKED not in ppglobals.vmware_managers and not dials

    r = owner.delete(f'/api/vmware/{PARKED}')
    assert r.status_code == 200, (r.status_code, r.get_json())
    assert _row(PARKED) is None


def _edit_form(entry):
    """What the edit dialog PUTs for a list entry (openVmwareEdit / handleUpdateVMware)."""
    return {'name': entry.get('name') or '', 'host': entry['host'], 'port': entry.get('port') or 443,
            'username': entry.get('username') or 'root', 'password': '',
            'ssl_verify': entry.get('ssl_verify') or False, 'notes': entry.get('notes') or ''}


@pytest.mark.parametrize('who', ['admin', 'other'])
def test_a_rename_in_the_edit_dialog_keeps_the_account_tls_and_notes(api, restarted, dials, who):
    sid = 'esx-off-svc'
    _park(sid, ['cluster_b'], username='svc-esx', ssl_verify=True, notes='rack 7')
    load_vmware_servers()
    assert sid not in ppglobals.vmware_managers
    client = _as(api, restarted, who)
    entry = next(s for s in client.get('/api/vmware').get_json() if s['id'] == sid)

    r = client.put(f'/api/vmware/{sid}', json=dict(_edit_form(entry), name='parked svc'))
    assert r.status_code == 200, (r.status_code, r.get_json())
    row = _row(sid)
    assert (row['username'], row['ssl_verify'], row['notes']) == ('svc-esx', 1, 'rack 7'), \
        (row['username'], row['ssl_verify'], row['notes'])
    assert (row['name'], row['enabled'], row['server_type']) == ('parked svc', 0, 'esxi')
    assert not dials
    # the entry has them as to_dict has them for a loaded server
    assert (entry['username'], entry['ssl_verify'], entry['notes']) == ('svc-esx', True, 'rack 7')


def test_an_edit_that_keeps_it_disabled_leaves_it_unregistered(api, restarted, dials):
    r = _as(api, restarted, 'other').put(f'/api/vmware/{PARKED}', json={'notes': 'rack 9'})
    assert r.status_code == 200, (r.status_code, r.get_json())
    assert PARKED not in ppglobals.vmware_managers, 'a disabled server was registered'
    # the keepalive of the broadcast loop: ensure_connected on every registered server
    for mgr in list(ppglobals.vmware_managers.values()):
        mgr.ensure_connected()
    assert not dials, dials
    # switched back on, it is registered and connected
    r = _as(api, restarted, 'other').put(f'/api/vmware/{PARKED}', json={'enabled': True})
    assert r.status_code == 200, (r.status_code, r.get_json())
    assert ppglobals.vmware_managers[PARKED].connected
    assert dials == [(PARKED, f'{PARKED}.lab', 'stored-pw')]


# --- linked_clusters that do not parse ----------------------------------------------------------

def test_an_unreadable_linkage_leaves_the_row_to_an_admin(api, restarted, dials):
    from pegaprox.core.db import get_db
    admin = _as(api, restarted, 'admin')
    # the admin fixes it by naming the clusters
    r = admin.put(f'/api/vmware/{BROKEN}', json={'enabled': True, 'linked_clusters': ['cluster_b']})
    assert r.status_code == 200, (r.status_code, r.get_json())
    assert _row(BROKEN)['linked_clusters'] == '["cluster_b"]'
    assert ppglobals.vmware_managers[BROKEN].linked_clusters == ['cluster_b']

    # broken again, and out of the registry, as after a start
    ppglobals.vmware_managers.pop(BROKEN, None)
    get_db().conn.execute("UPDATE vmware_servers SET linked_clusters = '[broken', enabled = 0 WHERE id = ?",
                          (BROKEN,))
    get_db().conn.commit()
    before, n = _row(BROKEN), len(dials)
    for who in ('acme', 'other', 'pool', 'unconfined'):
        for verb in ('put', 'delete'):
            kw = {'json': {'notes': 'probe'}} if verb == 'put' else {}
            r = getattr(_as(api, restarted, who), verb)(f'/api/vmware/{BROKEN}', **kw)
            assert r.status_code == 403, (who, verb, r.status_code)
    assert _row(BROKEN) == before

    # without the clusters it would come up linked to nobody: open to everybody
    r = admin.put(f'/api/vmware/{BROKEN}', json={'enabled': True})
    assert r.status_code == 400, (r.status_code, r.get_json())
    assert 'linked_clusters' in r.get_json()['error']
    assert _row(BROKEN) == before and BROKEN not in ppglobals.vmware_managers and len(dials) == n


# --- one rule for a loaded server and a row ------------------------------------------------------

LINKS = {'open': [], 'mine': ['cluster_a'], 'theirs': ['cluster_b']}


@pytest.mark.parametrize('who', ['admin', 'acme', 'other', 'pool', 'unconfined'])
def test_the_row_is_held_to_the_rule_of_the_gate(api, people, dials, who):
    """Per linkage the same answer for a server in the registry and one that is only a row."""
    client = _as(api, people, who)
    answers = {}
    for name, linked in LINKS.items():
        loaded, parked = f'up-{name}', f'off-{name}'
        _park(loaded, linked, enabled=True)
        ppglobals.vmware_managers[loaded] = VMwareManager(loaded, {
            'name': loaded, 'host': f'{loaded}.lab', 'username': 'root', 'password': 'stored-pw',
            'server_type': 'esxi', 'linked_clusters': linked})
        _park(parked, linked)
        for sid in (loaded, parked):
            r = client.put(f'/api/vmware/{sid}', json={'notes': 'probe'})
            assert r.status_code in (200, 403), (who, sid, r.status_code, r.get_json())
            answers[sid] = r.status_code
        assert answers[loaded] == answers[parked], (who, name, answers)
    # and the rule itself, so that a gate refusing everybody cannot pass
    want = {'admin': {'open', 'mine', 'theirs'}, 'unconfined': {'open', 'mine', 'theirs'},
            'acme': {'open', 'mine'}, 'pool': {'open', 'mine'}, 'other': {'open', 'theirs'}}[who]
    assert {n for n in LINKS if answers[f'off-{n}'] == 200} == want, (who, answers)


# --- the other routes still want a loaded server ------------------------------------------------

_PLACEHOLDERS = {'vm_id': 'vm-1', 'action': 'start', 'snapshot_id': 'snap-1', 'ds_id': 'ds-1',
                 'cluster_id': 'domain-c1'}


def test_only_update_and_delete_reach_a_server_that_is_only_a_row(api, restarted, offline):
    admin = _as(api, restarted, 'admin')
    others = []
    for rule in api.app.url_map.iter_rules():
        if not rule.rule.startswith('/api/vmware/<vmware_id>') or rule.rule == '/api/vmware/<vmware_id>':
            continue
        path = re.sub(r'<(?:[^:>]+:)?([^>]+)>',
                      lambda m: PARKED if m.group(1) == 'vmware_id' else _PLACEHOLDERS.get(m.group(1), 'x'),
                      rule.rule)
        others += [(verb, path) for verb in sorted(rule.methods - {'HEAD', 'OPTIONS'})]
    assert len(others) >= 25, others
    wrong = []
    for verb, path in others:
        kw = {} if verb in ('GET', 'DELETE') else {'json': {'name': 'probe'}}
        r = getattr(admin, verb.lower())(path, **kw)
        if r.status_code != 404:
            wrong.append((verb, path, r.status_code))
    assert not wrong, wrong
    assert admin.put(f'/api/vmware/{PARKED}', json={'notes': 'x'}).status_code == 200
    ppglobals.vmware_managers.pop(PARKED, None)
    assert admin.delete(f'/api/vmware/{PARKED}').status_code == 200
    # gone means gone: no row, no fallback
    assert admin.delete(f'/api/vmware/{PARKED}').status_code == 404
    assert admin.put(f'/api/vmware/{PARKED}', json={'notes': 'x'}).status_code == 404
