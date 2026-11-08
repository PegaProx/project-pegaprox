"""The ESXi server list answers check_vmware_access's question for every row.

Every route that names one ESXi server has asked check_vmware_access since the Jul and
Aug rounds. The two places that LIST servers never did: GET /api/vmware returned each
server's to_dict (host, account name, notes, last error, server info, linkage) to anyone
holding vmware.view, and the 'vmware_servers' stream frame carried name and host of every
server to every non-admin client with that permission. vmware.view is in the builtin
viewer and user roles, so each tenant read every other tenant's ESXi estate. A pool grant
on another tenant's cluster made no difference either way, and must not start to: the
gate resolves the caller's clusters without pool reach.

Here: two tenants, one ESXi server each, one unlinked server everybody may see, and a
disabled server of the second tenant that lives only in the table. The callers who must
not see the second tenant's servers: a plain tenant user, one with a pool on the other
tenant's cluster, one with VM ACLs there (a Proxmox guest and an ESXi guest), an admin a
tenant override lowers to viewer, and an admin's API token with the narrower user role.
The bottom half walks every other way a server's details leave the process: each route
under /api/vmware/<vmware_id>, the V2P migration records and the other ESXi stream
frames. NS Oct 2026
"""
import json
import queue
import re

import pytest

import pegaprox.globals as ppglobals
from pegaprox.core.vmware import VMwareManager, save_vmware_server
from pegaprox.models.permissions import PERMISSIONS, ROLE_PERMISSIONS
from pegaprox.utils.realtime import broadcast_sse


MINE, THEIRS, OPEN, PARKED = 'esx-a', 'esx-b', 'esx-open', 'esx-off-b'
THEIR_HOST = 'esx-b.other.internal'
PARKED_HOST = 'esx-off-b.other.internal'
THEIR_NOTES = 'other tenant rack 4'
THEIR_VM = 'vm-7'

# every vmware.* permission, so a refusal below is the object gate and not a missing perm
ALL_VMW = sorted(p for p in PERMISSIONS if p.startswith('vmware.'))
# the builtin role the admin's API token is cut down to
TOKEN_ROLE = 'user'
DENIED = ['acme', 'pool', 'vmacl', 'capped', 'token']


def _server(sid, host, linked, notes=''):
    return VMwareManager(sid, {'name': sid, 'host': host, 'username': f'svc-{sid}',
                               'server_type': 'esxi', 'linked_clusters': linked,
                               'notes': notes})


@pytest.fixture
def estate(db, seed):
    seed.tenant('acme', clusters=['cluster_a'])
    seed.tenant('other', clusters=['cluster_b'])
    users = {
        'acme': seed.user('alice', role='viewer', tenant_id='acme', permissions=ALL_VMW),
        'other': seed.user('bob', role='viewer', tenant_id='other', permissions=ALL_VMW),
        'pool': seed.user('pooly', role='viewer', tenant_id='acme', permissions=ALL_VMW),
        'vmacl': seed.user('vic', role='viewer', tenant_id='acme', permissions=ALL_VMW),
        'capped': seed.user('gx', role='admin', tenant_id='acme', tenant_permissions={
            'acme': {'role': 'viewer', 'extra': ALL_VMW}}),
        'unconfined': seed.user('plain', role='viewer', permissions=ALL_VMW),
        'admin': seed.user('root', role='admin'),
    }
    # a resource pool on the other tenant's cluster - a claim on guests, not on the server
    seed.pool('cluster_b', 'pool_b', 'pooly', ['pool.view', 'vm.view'])
    # VM ACLs into the other tenant: a Proxmox guest and a guest on its ESXi server
    seed.vm_acl('cluster_b', 100, ['vic'])
    seed.vm_acl(f'vmware:{THEIRS}', THEIR_VM, ['vic'])

    ppglobals.vmware_managers.clear()
    ppglobals.vmware_managers.update({
        MINE: _server(MINE, 'esx-a.acme.internal', ['cluster_a']),
        THEIRS: _server(THEIRS, THEIR_HOST, ['cluster_b'], notes=THEIR_NOTES),
        OPEN: _server(OPEN, 'esx-open.lab', []),
    })
    save_vmware_server(PARKED, {'name': PARKED, 'host': PARKED_HOST, 'username': 'root',
                                'enabled': False, 'linked_clusters': ['cluster_b']})
    try:
        yield users
    finally:
        ppglobals.vmware_managers.clear()


@pytest.fixture
def token(estate, seed):
    """An acme admin and an API token of theirs cut down to the user role."""
    from pegaprox.utils.auth import create_api_token
    owner = seed.user('tokadm', role='admin', tenant_id='acme')
    res = create_api_token('tokadm', 'ci', role=TOKEN_ROLE)
    assert res.get('token'), res
    return owner, res['token']


class _Bearer:
    """The harness client, authenticated by an API token instead of a session."""

    def __init__(self, api, secret):
        self._c, self._auth = api.anon(), {'Authorization': f'Bearer {secret}'}

    def __getattr__(self, verb):
        return lambda path, **kw: getattr(self._c, verb)(path, headers=self._auth, **kw)


def _as(api, estate, token, who):
    return _Bearer(api, token[1]) if who == 'token' else api.as_user(estate[who])


def _held(who):
    """The ESXi perms a caller holds: a refusal naming one of them was not the perm gate."""
    return set(ROLE_PERMISSIONS[TOKEN_ROLE]) if who == 'token' else set(ALL_VMW)


def _leaks(body):
    return [s for s in (THEIR_HOST, PARKED_HOST, THEIR_NOTES) if s in body]


# --- GET /api/vmware -----------------------------------------------------------

def _listed(client):
    r = client.get('/api/vmware')
    assert r.status_code == 200, r.get_data(as_text=True)
    return {s['id'] for s in r.get_json()}, r.get_data(as_text=True)


@pytest.mark.parametrize('who', DENIED)
def test_the_list_hides_another_tenants_servers(api, estate, token, who):
    ids, body = _listed(_as(api, estate, token, who))
    assert ids == {MINE, OPEN}, (who, ids)
    assert not _leaks(body), (who, _leaks(body))


def test_the_owning_tenant_still_lists_its_servers(api, estate):
    ids, body = _listed(api.as_user(estate['other']))
    assert ids == {THEIRS, OPEN, PARKED}, ids
    assert THEIR_HOST in body


@pytest.mark.parametrize('who', ['admin', 'unconfined'])
def test_an_admin_and_an_unconfined_user_list_everything(api, estate, who):
    ids, _ = _listed(api.as_user(estate[who]))
    assert ids == {MINE, THEIRS, OPEN, PARKED}, (who, ids)


def test_the_tokens_owner_lists_everything_so_the_token_is_what_narrows(api, token):
    ids, _ = _listed(api.as_user(token[0]))
    assert ids == {MINE, THEIRS, OPEN, PARKED}, ids


def test_an_unreadable_linkage_lists_the_row_to_an_admin_only(api, estate, db):
    db.conn.execute("UPDATE vmware_servers SET linked_clusters = '[broken' WHERE id = ?", (PARKED,))
    db.conn.commit()
    assert PARKED not in _listed(api.as_user(estate['acme']))[0]
    assert PARKED in _listed(api.as_user(estate['admin']))[0]


def test_the_list_rule_is_the_gate_rule(api, estate, token):
    """vmware_server_reach must answer what check_vmware_access answers, server by
    server, for every caller here - one rule, two shapes."""
    from flask import g, request
    from pegaprox.api.helpers import acting_user, check_vmware_access, vmware_server_reach

    callers = [(who, user, {'user': user['username'], 'role': user['role']})
               for who, user in estate.items()]
    callers.append(('token', token[0], {'user': 'tokadm', 'role': TOKEN_ROLE, 'api_token': True}))
    for who, user, session in callers:
        with api.app.test_request_context('/'):
            request.session = session
            g.current_user = user
            reaches = vmware_server_reach(acting_user())
            for sid, mgr in ppglobals.vmware_managers.items():
                ok, _ = check_vmware_access(sid)
                assert reaches(mgr.linked_clusters) is ok, (who, sid, ok)


# --- every route that names one server -------------------------------------------

_PLACEHOLDERS = {'vmware_id': THEIRS, 'vm_id': THEIR_VM, 'action': 'start',
                 'snapshot_id': 'snap-1', 'ds_id': 'ds-1', 'cluster_id': 'domain-c1'}


def _routes_naming_a_server(app):
    out = []
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith('/api/vmware/<vmware_id>'):
            continue
        path = re.sub(r'<(?:[^:>]+:)?([^>]+)>',
                      lambda m: _PLACEHOLDERS.get(m.group(1), 'x'), rule.rule)
        out += [(verb, path) for verb in sorted(rule.methods - {'HEAD', 'OPTIONS'})]
    return out


@pytest.fixture
def offline(monkeypatch):
    """A route that wrongly let the caller through must fail here, not dial the host."""
    import requests

    def _refuse(*a, **k):
        raise AssertionError('an ESXi request left the process for a refused caller')
    for name in ('get', 'post', 'put', 'delete', 'request'):
        monkeypatch.setattr(requests, name, _refuse)
    monkeypatch.setattr(requests.Session, 'request', _refuse)


@pytest.mark.parametrize('who', DENIED)
def test_no_route_naming_a_foreign_server_answers_with_it(api, estate, token, offline, who):
    client = _as(api, estate, token, who)
    routes = _routes_naming_a_server(api.app)
    assert len(routes) >= 30, routes
    wrong = []
    for verb, path in routes:
        # snapshot, clone and rename check for a name before they ask the gate
        kw = {} if verb in ('GET', 'DELETE') else {'json': {'name': 'probe'}}
        r = getattr(client, verb.lower())(path, **kw)
        body = r.get_data(as_text=True)
        required = (r.get_json(silent=True) or {}).get('required')
        if r.status_code not in (403, 404) or _leaks(body) or required in _held(who):
            wrong.append((verb, path, r.status_code, body[:120]))
    assert not wrong, (who, wrong)


# --- V2P migration records ---------------------------------------------------------

@pytest.fixture
def their_migration(estate):
    from pegaprox.api.vmware import _vmware_migrations
    from pegaprox.core.v2p import V2PMigrationTask
    task = V2PMigrationTask('mig-b1', THEIRS, THEIR_VM, 'cluster_b', 'pve-b1', 'local-lvm',
                            'their-db', {'esxi_host': THEIR_HOST})
    _vmware_migrations[task.id] = task
    try:
        yield task
    finally:
        _vmware_migrations.pop(task.id, None)


@pytest.mark.parametrize('who', DENIED)
def test_a_foreign_v2p_migration_is_neither_listed_nor_shown(api, estate, token,
                                                             their_migration, who):
    client = _as(api, estate, token, who)
    listed = client.get('/api/vmware/migrations')
    assert listed.status_code == 200, listed.get_data(as_text=True)
    assert their_migration.id not in {t['id'] for t in listed.get_json()}, who
    one = client.get(f'/api/vmware/migrations/{their_migration.id}')
    assert one.status_code == 404 and not _leaks(one.get_data(as_text=True)), who


def test_the_owning_tenant_still_sees_its_v2p_migration(api, estate, their_migration):
    client = api.as_user(estate['other'])
    assert their_migration.id in {t['id'] for t in client.get('/api/vmware/migrations').get_json()}
    assert client.get(f'/api/vmware/migrations/{their_migration.id}').status_code == 200


# --- the stream ----------------------------------------------------------------

def _frame():
    """Built the way background/broadcast.py builds it."""
    return [{'id': sid, 'name': m.name, 'host': m.host, 'connected': m.connected,
             'type': m.server_type} for sid, m in ppglobals.vmware_managers.items()]


@pytest.fixture
def stream(estate):
    made = []

    def _open(user, is_admin=False, clusters=None, effective_role=None):
        q, cid = queue.Queue(), f'test-sse-esxlist-{user["username"]}'
        with ppglobals.sse_clients_lock:
            ppglobals.sse_clients[cid] = {
                'queue': q, 'user': user['username'], 'clusters': clusters,
                'is_admin': is_admin, 'effective_role': effective_role,
                'connected_at': 'x', 'auth_method': 'test',
            }
        made.append(cid)
        return q

    try:
        yield _open
    finally:
        with ppglobals.sse_clients_lock:
            for cid in made:
                ppglobals.sse_clients.pop(cid, None)


def _drain(q):
    frames = []
    try:
        while True:
            frames.append(json.loads(q.get_nowait()))
    except queue.Empty:
        pass
    return frames


def _servers_seen(q):
    frames = [f for f in _drain(q) if f.get('type') == 'vmware_servers']
    assert len(frames) == 1, frames
    return frames[0]


def _client_of(stream, estate, token, who, clusters):
    """A stream as the connect path registers it: a token's stream carries the token role."""
    if who == 'token':
        return stream(token[0], clusters=clusters, effective_role=TOKEN_ROLE)
    return stream(estate[who], clusters=clusters)


# every stream is subscribed to the other tenant's cluster as well, so the subscription
# cannot be what keeps those servers out (the pool user's really is: it counts pool reach)
@pytest.mark.parametrize('who', DENIED)
def test_the_frame_hides_another_tenants_servers(estate, token, stream, who):
    q = _client_of(stream, estate, token, who, ['cluster_a', 'cluster_b'])
    broadcast_sse('vmware_servers', _frame())

    frame = _servers_seen(q)
    assert {s['id'] for s in frame['data']} == {MINE, OPEN}, (who, frame['data'])
    assert THEIR_HOST not in json.dumps(frame), who


def test_the_owning_tenant_still_gets_its_servers_in_the_frame(estate, stream):
    q = stream(estate['other'], clusters=['cluster_b'])
    broadcast_sse('vmware_servers', _frame())
    assert {s['id'] for s in _servers_seen(q)['data']} == {THEIRS, OPEN}


def test_an_admin_and_an_unconfined_client_get_the_whole_frame(estate, stream):
    root = stream(estate['admin'], is_admin=True)
    plain = stream(estate['unconfined'])
    broadcast_sse('vmware_servers', _frame())
    assert {s['id'] for s in _servers_seen(root)['data']} == {MINE, THEIRS, OPEN}
    assert {s['id'] for s in _servers_seen(plain)['data']} == {MINE, THEIRS, OPEN}


def test_the_frame_still_needs_vmware_view(estate, stream, seed):
    seed.user('novmw', role='viewer', tenant_id='other', denied=['vmware.view'])
    q = stream({'username': 'novmw'}, clusters=['cluster_b'])
    broadcast_sse('vmware_servers', _frame())
    assert q.empty(), 'a role without vmware.view received the ESXi server list'


def _their_other_frames(migration_id):
    """The rest of what the stream says about one server, as broadcast.py and v2p.py send it."""
    broadcast_sse('vmware_vms', {'vmware_id': THEIRS,
                                 'vms': [{'vm': THEIR_VM, 'name': 'their-db'}]},
                  target_clusters=['cluster_b'])
    broadcast_sse('vmware_vm_detail', {'vmware_id': THEIRS, 'vm_id': THEIR_VM,
                                       'data': {'name': 'their-db'}}, target_clusters=['cluster_b'])
    broadcast_sse('vmware_migration', {'id': migration_id, 'phase': 'pre_sync',
                                       'vm_name': 'their-db'})
    broadcast_sse('vmware_migration_log', {'id': migration_id, 'line': f'mount {THEIR_HOST}'})


@pytest.mark.parametrize('who', DENIED)
def test_no_other_frame_about_a_foreign_server_reaches_them(estate, token, stream,
                                                            their_migration, who):
    q = _client_of(stream, estate, token, who, ['cluster_a', 'cluster_b'])
    _their_other_frames(their_migration.id)
    seen = [f for f in _drain(q) if THEIRS in json.dumps(f) or 'their-db' in json.dumps(f)]
    assert not seen, (who, seen)


def test_the_owning_tenant_still_gets_the_other_frames(estate, stream, their_migration):
    q = stream(estate['other'], clusters=['cluster_b'])
    _their_other_frames(their_migration.id)
    got = {f['type'] for f in _drain(q)}
    assert got == {'vmware_vms', 'vmware_vm_detail', 'vmware_migration',
                   'vmware_migration_log'}, got
