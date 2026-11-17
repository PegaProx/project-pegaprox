"""Linked mode: a guest moved between the clusters of two sites.

The site that leads the target cluster makes the API token of the migration after its own
checks, with privilege separation and the ACLs of that one migration; the site the user
works at hands it to the source's remote-migrate route and has it dropped once the task
has ended. The token never reaches the browser, a refused start drops it at once, and only
the user and site that asked for it can drop it.

MK Nov 2026
"""
import json
from unittest.mock import MagicMock

import pytest

from pegaprox.core import federation_migrate as fmig
from pegaprox.core import federation_relay as relay
from tests.test_federation import (  # noqa: F401 - fixtures by name
    _add_local_user, _db_of, _defaults_out_of_the_config_dir, _fresh_budgets, at, iid)
from tests.test_federation_relay import (  # noqa: F401 - fixtures by name
    CID, MIGRATE_ANSWER, MIGRATIONS, _fresh_relay, _post, _session, linked)

SRC = 'src0'
SECRET = 'f0e1d2c3-b4a5-9687-7869-5a4b3c2d1e0f'


class _Resp:
    def __init__(self, status=200, data=None, text=''):
        self.status_code, self._data, self.text = status, data, text

    def json(self):
        return {'data': self._data}


@pytest.fixture
def pve(monkeypatch):
    """pve1, the target cluster b leads, as its PVE API sees the calls; src0 at a."""
    from pegaprox import globals as g
    from pegaprox.core import transfer_net
    calls = {'post': [], 'put': [], 'deleted': [], 'refuse': set(), 'taken': set()}
    fmig.reset_for_tests()
    tgt = MagicMock(id=CID, cluster_type='proxmox', is_connected=True, host='10.0.0.5',
                    api_port=8006)
    tgt.config.user, tgt.config.name = 'root@pam', 'target-cluster'

    def post(url, data=None, **kw):
        calls['post'].append((url.split('/api2/json', 1)[1], dict(data or {})))
        if '/token/' in url:
            name = url.rsplit('/', 1)[1]
            return _Resp(200, {'full-tokenid': f'root@pam!{name}', 'value': SECRET})
        return _Resp(200)

    def put(url, data=None, **kw):
        path = url.split('/api2/json', 1)[1]
        calls['put'].append((path, dict(data or {})))
        if (data or {}).get('path') in calls['refuse']:
            return _Resp(403, text='permission check failed')
        return _Resp(200)

    def delete(name):
        calls['deleted'].append(name)
        return {'success': True}

    def get(url, **kw):
        path = url.split('/api2/json', 1)[1]
        if path.startswith('/cluster/nextid'):
            vmid = int(path.split('vmid=', 1)[1])
            return _Resp(400, text=f'VM {vmid} already exists') if vmid in calls['taken'] \
                else _Resp(200, vmid)
        if path == '/cluster/sdn/vnets':
            return _Resp(200, [{'vnet': 'tenant1', 'zone': 'evpn1'}])
        return _Resp(404)
    tgt._api_post.side_effect, tgt._api_put.side_effect = post, put
    tgt._api_get.side_effect = get
    tgt.delete_api_token.side_effect = delete
    tgt.get_cluster_fingerprint.return_value = {'success': True, 'host': '10.0.0.5',
                                                'fingerprint': 'AA:BB'}
    g.cluster_managers[CID] = tgt
    g.cluster_managers[SRC] = MagicMock(id=SRC, cluster_type='proxmox')
    monkeypatch.setattr(transfer_net, 'migration_route', lambda mgr, node=None: None)
    from pegaprox.api import helpers
    monkeypatch.setattr(helpers, 'guest_size',
                        lambda m, n, t, v: {'cores': 2, 'memory_gb': 4, 'disk_gb': 32})
    followed = []
    monkeypatch.setattr(fmig, 'follow', lambda *a: followed.append(a))
    calls['followed'] = followed
    yield calls
    g.cluster_managers.pop(SRC, None)
    fmig.reset_for_tests()


def _migrate(a, b, sid, **over):
    body = {'source_cluster': SRC, 'target_cluster': f'{CID}~{iid(b)}', 'vmid': 101,
            'vm_type': 'qemu', 'source_node': 'n1', 'target_node': 'pve-b1',
            'target_storage': 'ceph-b', 'target_bridge': 'vmbr1'}
    body.update(over)
    return _post(a, '/api/federation/migrate', sid, body)


def test_a_migration_to_another_site_runs_on_a_token_made_there_for_it(linked, pve):
    a, b = linked
    sid = _session(a, 'alice')
    r = _migrate(a, b, sid)
    assert r.status_code == 200, r.data
    assert SECRET not in r.get_data(as_text=True)
    # the token: separated from the account's rights, with an end of its own
    (path, data), = [c for c in pve['post'] if '/token/' in c[0]]
    name = path.rsplit('/', 1)[1]
    assert name.startswith(fmig.TOKEN_PREFIX) and data['privsep'] == 1 and data['expire'] > 0
    # and only the rights of this migration
    acls = {(d['path'], d['roles'], d['propagate']) for p, d in pve['put'] if p == '/access/acl'}
    assert acls == {('/', 'PegaProxFedIncoming', 0), ('/vms/101', 'PegaProxFedGuest', 1),
                    ('/sdn/zones/localnetwork/vmbr1', 'PegaProxFedNet', 1),
                    ('/storage/ceph-b', 'PegaProxFedStorage', 1)}
    assert {d['tokens'] for p, d in pve['put'] if p == '/access/acl'} == {f'root@pam!{name}'}
    # the source's route got it, as the caller, on this site's own cluster
    (cid, user, node, vm_type, vmid, body), = MIGRATIONS
    assert (cid, user, node, vmid) == (SRC, 'alice', 'n1', 101)
    assert body['target_endpoint'] == (f'apitoken=PVEAPIToken=root@pam!{name}={SECRET},'
                                       'host=10.0.0.5,fingerprint=AA:BB')
    assert (body['target_storage'], body['target_bridge']) == ('ceph-b', 'vmbr1')
    # followed to its end, then dropped at the site that made it
    (target, source, followed_name, upid, _what), = pve['followed']
    assert isinstance(target, fmig._RemoteTarget) and followed_name == name
    assert upid.startswith('UPID:n1:')
    with at(a):
        assert target.delete_api_token(name) == {'success': True}
    assert pve['deleted'] == [name]
    # the audit of the target site names the token, never its secret
    rows = _db_of(b).conn.execute("SELECT details FROM audit_log WHERE action = "
                                  "'federation.migration_target'").fetchall()
    assert len(rows) == 1 and name in rows[0][0] and SECRET not in rows[0][0]


def test_a_migration_the_source_does_not_start_drops_its_token(linked, pve, monkeypatch):
    a, b = linked
    from pegaprox.utils import rbac
    released = []
    real = rbac.quota_release_key
    monkeypatch.setattr(rbac, 'quota_release_key', lambda key: (released.append(key), real(key)))
    MIGRATE_ANSWER[:] = [(500, {'error': 'remote migration failed'})]
    sid = _session(a, 'alice')
    r = _migrate(a, b, sid)
    assert r.status_code == 500 and r.get_json()['error'] == 'remote migration failed'
    made = [c[0].rsplit('/', 1)[1] for c in pve['post'] if '/token/' in c[0]]
    assert len(made) == 1 and pve['deleted'] == made and pve['followed'] == []
    # and the quota hold that came with the token goes with it
    assert released == [f'fedmig:{made[0]}']


def test_what_proxmox_echoes_of_the_token_never_reaches_the_browser(linked, pve):
    a, b = linked
    MIGRATE_ANSWER[:] = [(500, {'error': f'bad target-endpoint apitoken=PVEAPIToken=x={SECRET}'})]
    r = _migrate(a, b, _session(a, 'alice'))
    assert r.status_code == 500 and SECRET not in r.get_data(as_text=True)


def test_no_token_lands_on_a_guest_that_is_there(linked, pve):
    a, b = linked
    pve['taken'].add(205)
    r = _migrate(a, b, _session(a, 'alice'), target_vmid=205)
    assert r.status_code == 409 and r.get_json()['code'] == 'FED_MIGRATE_VMID'
    assert pve['post'] == [] and MIGRATIONS == []
    # counterproof: a free one
    assert _migrate(a, b, _session(a, 'alice'), target_vmid=206).status_code == 200


def test_a_vnet_gets_its_zone(linked, pve):
    a, b = linked
    assert _migrate(a, b, _session(a, 'alice'), target_bridge='tenant1').status_code == 200
    nets = {d['path'] for p, d in pve['put'] if p == '/access/acl' and d['roles'] == 'PegaProxFedNet'}
    assert nets == {'/sdn/zones/evpn1/tenant1'}


def test_no_token_for_a_guest_the_caller_may_not_move_here(linked, pve):
    """The source's gates run before the target site is asked for anything."""
    a, b = linked
    _db_of(a).conn.execute("UPDATE users SET role = 'viewer' WHERE username = 'alice'")
    _db_of(a).conn.commit()
    r = _migrate(a, b, _session(a, 'alice'))
    assert r.status_code == 403
    assert pve['post'] == [] and MIGRATIONS == []


def test_a_token_the_target_cannot_restrict_is_dropped(linked, pve):
    """No token with the full rights of the account as a fallback: refused, and gone."""
    a, b = linked
    pve['refuse'].add('/storage/ceph-b')
    sid = _session(a, 'alice')
    r = _migrate(a, b, sid)
    assert r.status_code == 502 and 'PegaProxFedStorage' in r.get_json()['error']
    made = [c[0].rsplit('/', 1)[1] for c in pve['post'] if '/token/' in c[0]]
    assert pve['deleted'] == made and MIGRATIONS == []


def test_the_target_site_checks_the_user_itself(linked, pve, monkeypatch):
    a, b = linked
    from pegaprox.api import helpers
    monkeypatch.setattr(helpers, 'caller_is_scoped', lambda user, cid: True)
    sid = _session(a, 'alice')
    r = _migrate(a, b, sid)
    assert r.status_code == 403 and 'target cluster' in r.get_json()['error']
    assert pve['post'] == [] and MIGRATIONS == []
    # a viewer there gets no token either: the route asks vm.migrate
    monkeypatch.setattr(helpers, 'caller_is_scoped', lambda user, cid: False)
    r = _migrate(a, b, _session(a, 'vic'))
    assert r.status_code == 403 and pve['post'] == [] and MIGRATIONS == []


def test_a_token_is_dropped_only_for_the_site_that_asked_for_it(linked, pve):
    """By that site's signed call, whoever's session it was: a drop only takes rights away,
    and it has to work after the user's sign-in has run out. Kept over a restart."""
    a, b = linked
    sid = _session(a, 'alice')
    assert _migrate(a, b, sid).status_code == 200
    (target, _s, name, _u, _w), = pve['followed']
    with at(b):
        assert fmig.drop_target(CID, name, 'e' * 32) is False
        assert fmig.drop_target(CID, name, '') is False
    assert pve['deleted'] == []
    fmig.reset_for_tests()          # the site restarts: the table comes back from its file
    with at(a):
        assert target.delete_api_token(name) == {'success': True}
        # once
        assert target.delete_api_token(name)['success'] is False
    assert pve['deleted'] == [name]


def test_no_browser_reaches_the_target_routes(linked, pve):
    a, b = linked
    sid = _session(a, 'alice')
    r = _post(a, f'/api/clusters/{CID}~{iid(b)}/migration-target', sid,
              {'target_node': 'pve-b1', 'vm_type': 'qemu', 'vmid': 101, 'storages': ['x'],
               'bridges': ['vmbr0'], 'footprint': {}})
    assert r.status_code == 404 and r.get_json()['code'] == 'FED_RELAY_RULE'
    r = _post(b, f'/api/clusters/{CID}/migration-target', _session(b, 'alice'), {})
    assert r.status_code == 404 and r.get_json()['code'] == 'FED_RELAY_ONLY'
    assert pve['post'] == []


def test_a_migration_from_another_site_takes_the_token_of_this_one(linked, pve, monkeypatch):
    """The source at the other site, the target here: the token is made here, and the
    remote-migrate route runs there as the caller."""
    a, b = linked
    from pegaprox import globals as g
    # one process holds both sites: b still leads pve1, and tgt0 is a's
    g.cluster_managers['tgt0'] = g.cluster_managers[CID]
    config = {'raw': {'cores': 2, 'memory': 4096, 'scsi0': 'local:vm-101-disk-0,size=32G'}}
    monkeypatch.setattr(relay, 'relay_call', _answer_config(relay.relay_call, config))
    try:
        sid = _session(a, 'alice')
        r = _migrate(a, b, sid, source_cluster=f'{CID}~{iid(b)}', target_cluster='tgt0')
        assert r.status_code == 200, r.data
        (cid, user, *_rest, body), = MIGRATIONS
        assert (cid, user) == (CID, 'alice') and SECRET in body['target_endpoint']
        (target, source, *_x), = pve['followed']
        assert isinstance(target, fmig._LocalTarget) and isinstance(source, fmig._RemoteSource)
    finally:
        g.cluster_managers.pop('tgt0', None)


def _answer_config(real, config):
    def call(iid_, method, path, *args, **kw):
        if method == 'GET' and path.endswith('/config'):
            return 'answer', 200, {}, json.dumps(config).encode()
        return real(iid_, method, path, *args, **kw)
    return call


def test_both_clusters_of_this_site_are_not_a_federation_migration(linked, pve):
    a, b = linked
    sid = _session(a, 'alice')
    from pegaprox import globals as g
    g.cluster_managers['other'] = MagicMock(id='other')
    try:
        r = _migrate(a, b, sid, target_cluster='other')
    finally:
        g.cluster_managers.pop('other', None)
    assert r.status_code == 400 and pve['post'] == []
