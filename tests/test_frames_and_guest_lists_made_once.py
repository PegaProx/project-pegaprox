"""A frame of the broadcast and the whole guest list are made once, not once per client.

At 10k guests the 'resources' frame is 4-5 MB. Every SSE stream built its own `data: ...`
string of it and Werkzeug encoded that again: two copies per stream and frame, held while a
slow client read them. The frame now carries its bytes (utils/realtime.py SSEFrame), made by
the first stream that sends it, and every stream it went to writes that one object. A frame
cut for a confined account is its own frame with its own bytes, as before.

GET /api/clusters/<id>/resources encoded and compressed the same rows for every caller who
gets all of them (75 ms of jsonify on the hub, 20-110 ms of compression at 10k guests). That
body is made once per snapshot of the manager's read-cache, each coding once, every variant
with a strong ETag, and a caller who sends the tag back gets a 304. A caller the route
filters for never gets it, whatever tag they send.

MK Nov 2026
"""
import gzip
import json
import time

import pytest
from werkzeug.test import EnvironBuilder

import pegaprox.api.clusters as clusters_api
import pegaprox.api.realtime as rt_api
import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac
import pegaprox.utils.realtime as rtu


def _guests(n, start=100):
    return [{'vmid': start + i, 'name': f'guest-{start + i}', 'type': 'qemu' if i % 3 else 'lxc',
             'node': f'pve{i % 4}', 'status': 'running', 'cpu_percent': 1.5, 'mem_percent': 20.0}
            for i in range(n)]


@pytest.fixture
def registry():
    ppglobals.sse_clients.clear()
    rtu._sse_node_scope.clear()
    try:
        yield ppglobals.sse_clients
    finally:
        ppglobals.sse_clients.clear()
        rtu._sse_node_scope.clear()


@pytest.fixture
def whole_lists():
    clusters_api._whole_lists.clear()
    try:
        yield clusters_api._whole_lists
    finally:
        clusters_api._whole_lists.clear()


# --- the SSE stream --------------------------------------------------------------------------

def _open(app, user, clusters=None):
    """The body of a real /api/sse/updates answer, past its 'connected' frame."""
    token = rt_api.create_sse_token(user, clusters)
    environ = EnvironBuilder(path='/api/sse/updates', base_url='http://localhost',
                             query_string={'token': token}).get_environ()
    status = []
    body = app(environ, lambda st, headers, exc_info=None: status.append(st))
    assert status and status[0].startswith('200'), status
    it = iter(body)
    assert b'connected' in next(it)
    return body, it


def _rows_of(chunk):
    assert chunk.startswith(b'data: ') and chunk.endswith(b'\n\n'), chunk[:40]
    frame = json.loads(chunk[len(b'data: '):-2])
    assert frame['type'] == 'resources'
    return [r['vmid'] for r in frame['data']]


def test_every_stream_of_the_whole_list_writes_one_bytes_object(api, seed, registry):
    for name in ('root1', 'root2', 'root3'):
        seed.user(name, role='admin')
    opened = [_open(api.app, name) for name in ('root1', 'root2', 'root3')]
    try:
        rows = _guests(300)
        rtu.broadcast_sse('resources', rows, 'c1')
        written = [next(it) for _, it in opened]

        assert _rows_of(written[0]) == [r['vmid'] for r in rows]
        assert written[0] == written[1] == written[2]
        assert written[0] is written[1] is written[2], 'each stream wrote its own copy of the frame'
        # the frame as json.dumps wrote it before, one event per frame
        assert written[0].startswith(b'data: {"type": "resources", "data": [{"vmid": 100, ')
        assert written[0].count(b'\n\n') == 1
    finally:
        for body, _ in opened:
            body.close()


def test_a_confined_stream_gets_its_own_frame_never_the_whole_one(api, seed, registry):
    seed.user('root', role='admin')
    carol = seed.user('carol', role='user')
    seed.vm_acl('c1', 101, users=['carol'])
    seed.vm_acl('c1', 104, users=['somebody-else'])
    rbac.invalidate_vm_acls_cache()
    admin, admin_it = _open(api.app, 'root')
    confined, confined_it = _open(api.app, 'carol', ['c1'])
    try:
        rows = _guests(12)
        rtu.broadcast_sse('resources', rows, 'c1')
        whole, cut = next(admin_it), next(confined_it)

        assert _rows_of(whole) == [r['vmid'] for r in rows]
        allowed = [r['vmid'] for r in rows
                   if rbac.user_can_access_vm(carol, 'c1', r['vmid'], 'vm.view', r['type'])]
        assert allowed and len(allowed) < len(rows)
        assert _rows_of(cut) == allowed, 'the confined stream got guests it may not see'
        assert cut is not whole
    finally:
        admin.close()
        confined.close()


# --- GET /api/clusters/<id>/resources --------------------------------------------------------

RES = '/api/clusters/c1/resources'


def _manager(api, rows):
    mgr = api.make_fake_manager(cluster_id='c1', get_vm_resources=rows)
    mgr.is_connected = True
    mgr._vm_resources_cache = (time.time(), rows)
    return api.set_manager('c1', mgr)


def _renew(mgr, rows):
    """What the broadcast loop's read does: a new list, a new stamp."""
    mgr.get_vm_resources.return_value = rows
    mgr._vm_resources_cache = (mgr._vm_resources_cache[0] + 1, rows)


def _json_of(resp):
    data = resp.get_data()
    if resp.headers.get('Content-Encoding') == 'gzip':
        data = gzip.decompress(data)
    return json.loads(data)


def _encodes_of(api, monkeypatch):
    """How often jsonify encoded a list the manager handed out."""
    made = []
    real = api.app.json.dumps

    def dumps(obj, **kw):
        if isinstance(obj, list):
            made.append(len(obj))
        return real(obj, **kw)
    monkeypatch.setattr(api.app.json, 'dumps', dumps)
    return made


def test_callers_who_get_the_whole_list_share_one_body_per_snapshot(api, seed, whole_lists,
                                                                    monkeypatch):
    root = seed.user('root', role='admin')
    ops = seed.user('ops', role='user')          # the tenant's operator, no VM-ACL on c1
    rows = _guests(40)
    mgr = _manager(api, rows)
    # the bytes jsonify makes of the rows, as the route always sent them
    with api.app.app_context():
        sent_before = api.app.json.response(rows).get_data()
    made = _encodes_of(api, monkeypatch)

    bodies = [api.as_user(u).get(RES) for u in (root, ops, root, ops)]
    assert [b.status_code for b in bodies] == [200] * 4
    assert [b.get_data() for b in bodies] == [sent_before] * 4
    assert bodies[0].mimetype == 'application/json'
    assert made == [40], f'the same snapshot was encoded {len(made)} times for four callers'

    _renew(mgr, _guests(41))
    again = api.as_user(ops).get(RES)
    assert [r['vmid'] for r in again.get_json()] == [r['vmid'] for r in _guests(41)]
    assert made == [40, 41]


def test_a_filtered_caller_never_gets_the_whole_list(api, seed, whole_lists):
    root = seed.user('root', role='admin')
    carol = seed.user('carol', role='user')      # confined by a VM-ACL
    dave = seed.user('dave', role='user')        # the tenant's operator, ACL'd guests hidden
    seed.vm_acl('c1', 101, users=['carol'])
    rbac.invalidate_vm_acls_cache()
    rows = _guests(30)
    _manager(api, rows)

    whole = api.as_user(root).get(RES, headers={'Accept-Encoding': 'gzip'})
    assert len(_json_of(whole)) == 30 and whole.headers.get('ETag')
    tags = ', '.join([whole.headers['ETag'], f'"{whole_lists["c1"].tag}"', '*'])

    for user, expected in (
            (carol, [r['vmid'] for r in rows
                     if rbac.user_can_access_vm(carol, 'c1', r['vmid'], 'vm.view', r['type'])]),
            (dave, [r['vmid'] for r in rows if r['vmid'] != 101])):
        for headers in ({}, {'If-None-Match': tags},
                        {'If-None-Match': tags, 'Accept-Encoding': 'gzip'}):
            got = api.as_user(user).get(RES, headers=headers)
            assert got.status_code == 200, (user['username'], headers, got.status_code)
            assert [r['vmid'] for r in _json_of(got)] == expected, user['username']
            assert len(expected) < len(rows)
            assert got.headers.get('ETag') is None, user['username']


def test_the_tag_answers_304_until_the_bytes_change(api, seed, whole_lists):
    root = seed.user('root', role='admin')
    rows = _guests(40)
    mgr = _manager(api, rows)
    client = api.as_user(root)

    first = client.get(RES)
    assert first.status_code == 200
    tag, weak = first.get_etag()
    assert tag and not weak
    assert client.get(RES, headers={'If-None-Match': first.headers['ETag']}).status_code == 304

    packed = client.get(RES, headers={'Accept-Encoding': 'gzip'})
    assert packed.status_code == 200 and packed.headers['Content-Encoding'] == 'gzip'
    assert gzip.decompress(packed.get_data()) == first.get_data()
    assert packed.headers['ETag'] != first.headers['ETag'], 'two codings share one strong tag'
    assert 'Accept-Encoding' in packed.headers.get('Vary', '')
    not_again = client.get(RES, headers={'Accept-Encoding': 'gzip',
                                         'If-None-Match': packed.headers['ETag']})
    assert not_again.status_code == 304 and not not_again.get_data()

    # a new snapshot with the same rows is the same body: still 304
    _renew(mgr, [dict(r) for r in rows])
    assert client.get(RES, headers={'If-None-Match': first.headers['ETag']}).status_code == 304

    # one guest stopped: a new body, a new tag
    changed = [dict(r) for r in rows]
    changed[3]['status'] = 'stopped'
    _renew(mgr, changed)
    after = client.get(RES, headers={'If-None-Match': first.headers['ETag']})
    assert after.status_code == 200
    assert after.get_json()[3]['status'] == 'stopped'
    assert after.headers['ETag'] != first.headers['ETag']
    assert client.get(RES, headers={'If-None-Match': after.headers['ETag']}).status_code == 304


def test_rows_that_are_not_the_snapshot_go_out_as_they_are(api, seed, whole_lists):
    """A failed read answers an empty list the read-cache never holds, a manager of another
    kind builds its list fresh: neither is the body of the snapshot asked for before."""
    from pegaprox.core.manager import UnreadList
    root = seed.user('root', role='admin')
    rows = _guests(40)
    mgr = _manager(api, rows)
    client = api.as_user(root)
    assert client.get(RES).get_json() == rows

    mgr.get_vm_resources.return_value = UnreadList()
    failed = client.get(RES)
    assert failed.status_code == 200 and failed.get_json() == []
    fresh = _guests(5, start=900)
    mgr.get_vm_resources.return_value = fresh
    assert client.get(RES).get_json() == fresh
