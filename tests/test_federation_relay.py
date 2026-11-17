"""Linked mode: a cluster of another site, worked on from this instance through the relay.

Two sites live in one process as in tests/test_federation.py: each with its own database,
runtime slot and a Flask app with the federation blueprints and a few stand-in cluster
routes. a is the site the browser talks to (the entry), b leads the cluster pve1. The
relay signs, sends and checks every call as it does on the wire; the stand-in transport
routes it into b's app.

What is held here: the leading site decides (its rights, its audit, its refusal of the
rules that never cross), a site speaks only for the accounts it homes, the relayed session
lives for one request, a replayed, altered or foreign-signed call is nobody's, an answer
carries no HTML, no sign-in loss and no unsigned word, and with the switch off a '~' id is
an unknown cluster like any other.

MK Nov 2026
"""
import base64
import json
from unittest.mock import MagicMock

import pytest
from flask import Blueprint, Response, jsonify, request

from pegaprox.core import federation, ha_wire
from pegaprox.core import federation_relay as relay
from tests.test_federation import (  # noqa: F401 - fixtures by name
    Side, URL, _add_local_user, _code, _db_of, _defaults_out_of_the_config_dir, _fresh_budgets,
    _join, _map, _settled, _wire, at, iid)

CID = 'pve1'
# what the stand-in upload route of the leading site took
UPLOADED = []
# what the stand-in remote-migrate route took, and what it answers
MIGRATIONS = []
MIGRATE_ANSWER = [(200, {'task': 'UPID:n1:0001:0002:0003:qmigrate:101:root@pam:'})]


def _cluster_routes():
    """Stand-ins of the leading site's cluster routes, with the guards the real ones use."""
    from pegaprox.api.helpers import check_cluster_access
    from pegaprox.utils.audit import log_audit
    from pegaprox.utils.auth import require_auth
    bp = Blueprint('relaytest', __name__)

    @bp.route('/api/clusters/<cluster_id>/status')
    @require_auth(perms=['cluster.view'])
    def status(cluster_id):
        ok, err = check_cluster_access(cluster_id)
        if not ok:
            return err
        return jsonify({'cluster': cluster_id, 'user': request.session['user'],
                        'client': request.remote_addr, 'q': request.args.get('q')})

    @bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/start',
              methods=['POST'])
    @require_auth(perms=['vm.start'])
    def start(cluster_id, node, vm_type, vmid):
        log_audit(request.session['user'], 'vm.start', f'started {vmid}')
        return jsonify({'started': vmid, 'body': request.get_json(silent=True)})

    @bp.route('/api/clusters/<cluster_id>', methods=['PUT'])
    @require_auth(perms=['cluster.config'])
    def put_cluster(cluster_id):
        return jsonify({'changed': True})

    @bp.route('/api/clusters/<cluster_id>/scripts')
    @require_auth(perms=['admin.scripts'])
    def scripts(cluster_id):
        return jsonify([])

    @bp.route('/api/clusters/<cluster_id>/page')
    @require_auth(perms=['cluster.view'])
    def page(cluster_id):
        return Response('<script>alert(1)</script>', mimetype='text/html')

    @bp.route('/api/clusters/<cluster_id>/log.txt')
    @require_auth(perms=['cluster.view'])
    def log_file(cluster_id):
        return Response('line 1\n', mimetype='application/octet-stream',
                        headers={'Content-Disposition': 'inline; filename="../task.log"',
                                 'Set-Cookie': 'session_id=evil'})

    @bp.route('/api/clusters/<cluster_id>/datastores/<storage_name>/upload', methods=['POST'])
    @require_auth(perms=['storage.upload'])
    def upload(cluster_id, storage_name):
        f = request.files['file']
        data = f.read()
        UPLOADED.append((request.session['user'], storage_name, request.form.get('node'),
                         f.filename, data))
        return jsonify({'success': True, 'size': len(data)})

    @bp.route('/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/remote-migrate',
              methods=['POST'])
    @require_auth(perms=['vm.migrate'])
    def remote_migrate(cluster_id, node, vm_type, vmid):
        MIGRATIONS.append((cluster_id, request.session['user'], node, vm_type, vmid,
                           request.get_json()))
        status, body = MIGRATE_ANSWER[0]
        return jsonify(body), status

    @bp.route('/api/clusters/<cluster_id>/session-gone')
    @require_auth(perms=['cluster.view'])
    def session_gone(cluster_id):
        return jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401

    return bp


def _relay_side(tmp, name):
    s = Side(tmp, name)
    from pegaprox.api import federation_relay as api_relay
    s.app.register_blueprint(api_relay.bp)
    s.app.register_blueprint(_cluster_routes())
    s.app.wsgi_app = relay.RemotePaths(s.app.wsgi_app)
    s.client = s.app.test_client()
    return s


@pytest.fixture(autouse=True)
def _fresh_relay():
    UPLOADED.clear()
    MIGRATIONS.clear()
    MIGRATE_ANSWER[:] = [(200, {'task': 'UPID:n1:0001:0002:0003:qmigrate:101:root@pam:'})]
    relay.reset_for_tests()
    from pegaprox import globals as g
    g.cluster_managers[CID] = MagicMock(id=CID)
    yield
    g.cluster_managers.pop(CID, None)
    relay.reset_for_tests()
    import pegaprox.utils.auth as authmod
    with authmod.sessions_lock:
        for sid in [k for k, v in authmod.active_sessions.items() if v.get('fed_relay')]:
            authmod.active_sessions.pop(sid, None)


@pytest.fixture
def linked(tmp_path):
    """a and b paired, alice (admin) and vic (viewer) homed at a and mapped at b."""
    a, b = _relay_side(tmp_path, 'a'), _relay_side(tmp_path, 'b')
    calls = []
    wire = _wire([a, b], calls)
    _add_local_user(a, 'alice', role='admin')
    _add_local_user(a, 'vic', role='viewer')
    _join(b, _code(a))
    for s in (a, b):
        _settled(s)
    out = _map(b, a, 'tenant', 'default', 'default')
    assert out['pulled'], out
    a.calls, a.wire_fn = calls, wire
    return a, b


def _session(side, username):
    from pegaprox.utils.auth import create_session
    with at(side):
        with side.app.test_request_context('/'):
            return create_session(username, 'admin')


def _get(side, path, sid, **kw):
    with at(side):
        return side.client.get(path, headers={'X-Session-ID': sid,
                                              'X-Requested-With': 'XMLHttpRequest'}, **kw)


def _post(side, path, sid, body=None):
    with at(side):
        return side.client.post(path, json=body, headers={'X-Session-ID': sid,
                                                          'X-Requested-With': 'XMLHttpRequest'})


def _relay_path(b, tail=''):
    return f'/api/federation/relay/{iid(b)}/clusters/{CID}{tail}'


def _relayed_calls(a):
    return [c for c in a.calls if c[2] == relay.RELAY_PATH]


# --- the path in -----------------------------------------------------------------------------

def test_a_read_runs_at_the_leading_site_as_the_caller(linked):
    a, b = linked
    sid = _session(a, 'alice')
    r = _get(a, _relay_path(b, '/status?q=x'), sid)
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['cluster'] == CID and body['user'] == 'alice' and body['q'] == 'x'
    assert r.headers[relay.SITE_HEADER] == iid(b)


def test_a_remote_id_in_a_cluster_path_goes_to_the_relay(linked):
    a, b = linked
    sid = _session(a, 'alice')
    r = _get(a, f'/api/clusters/{CID}~{iid(b)}/status', sid)
    assert r.status_code == 200, r.data
    assert r.get_json()['user'] == 'alice' and len(_relayed_calls(a)) == 1


def test_with_the_switch_off_a_remote_id_is_an_unknown_cluster(linked, monkeypatch):
    a, b = linked
    sid = _session(a, 'alice')
    monkeypatch.setattr(federation, 'enabled', lambda: False)
    r = _get(a, f'/api/clusters/{CID}~{iid(b)}/status', sid)
    # the path stays as it came: the local route answers for an id it does not know
    assert r.status_code != 200 or r.get_json().get('cluster') == f'{CID}~{iid(b)}'
    assert _relayed_calls(a) == []
    r = _get(a, _relay_path(b, '/status'), sid)
    assert r.status_code == 404 and r.get_json()['code'] == 'FED_DISABLED'


def test_a_local_cluster_with_a_tilde_stays_local(linked):
    a, b = linked
    from pegaprox import globals as g
    odd = f'{CID}~{iid(b)}'
    g.cluster_managers[odd] = MagicMock(id=odd)
    try:
        sid = _session(a, 'alice')
        r = _get(a, f'/api/clusters/{odd}/status', sid)
        assert r.get_json()['cluster'] == odd and _relayed_calls(a) == []
    finally:
        g.cluster_managers.pop(odd, None)


def test_a_write_carries_its_body_and_is_audited_at_both_sites(linked):
    a, b = linked
    sid = _session(a, 'alice')
    r = _post(a, _relay_path(b, '/vms/n1/qemu/101/start'), sid, {'timeout': 5})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'started': 101, 'body': {'timeout': 5}}
    at_b = _db_of(b).conn.execute("SELECT user, details FROM audit_log WHERE action = 'vm.start'"
                                  ).fetchall()
    assert len(at_b) == 1 and at_b[0]['user'] == 'alice'
    assert '(via site site-a, request ' in at_b[0]['details']
    at_a = _db_of(a).conn.execute("SELECT user, details FROM audit_log WHERE action = "
                                  "'federation.relayed'").fetchall()
    assert len(at_a) == 1 and 'site-b' in at_a[0]['details'] and ': 200' in at_a[0]['details']


def test_the_leading_site_decides_the_rights(linked):
    a, b = linked
    sid = _session(a, 'vic')
    r = _post(a, _relay_path(b, '/vms/n1/qemu/101/start'), sid, {})
    assert r.status_code == 403, r.data
    assert _db_of(b).conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'vm.start'"
                                  ).fetchone()[0] == 0
    # counterproof: the same viewer reads
    assert _get(a, _relay_path(b, '/status'), sid).status_code == 200


def test_the_relayed_session_holds_for_its_request_only(linked):
    a, b = linked
    import pegaprox.utils.auth as authmod
    seen = []
    real = authmod.open_relay_session

    def spy(*args, **kw):
        sid = real(*args, **kw)
        seen.append(sid)
        return sid
    authmod.open_relay_session = spy
    try:
        sid = _session(a, 'alice')
        assert _get(a, _relay_path(b, '/status'), sid).status_code == 200
    finally:
        authmod.open_relay_session = real
    assert len(seen) == 1
    assert seen[0] not in authmod.active_sessions
    # even put back, it is no session outside its request
    authmod.active_sessions[seen[0]] = {'user': 'alice', 'role': 'admin', 'created_at': 9e9,
                                        'last_activity': 9e9, 'fed_relay': 'site-a'}
    try:
        with b.app.test_request_context('/'):
            assert authmod.validate_session(seen[0]) is None
    finally:
        authmod.active_sessions.pop(seen[0], None)


# --- what never crosses -------------------------------------------------------------------------

@pytest.mark.parametrize('method, tail, reason', [
    ('put', '', 'record'),
    ('get', '/scripts', 'admin'),
])
def test_a_rule_that_never_crosses_is_refused_before_any_dial(linked, method, tail, reason):
    a, b = linked
    sid = _session(a, 'alice')
    with at(a):
        r = getattr(a.client, method)(_relay_path(b, tail), json={},
                                      headers={'X-Session-ID': sid,
                                               'X-Requested-With': 'XMLHttpRequest'})
    assert r.status_code == 404 and r.get_json()['code'] == 'FED_RELAY_RULE', r.data
    assert r.get_json()['reason'] == reason and r.get_json()['site'] == 'site-b'
    assert _relayed_calls(a) == []


def test_the_leading_site_refuses_such_a_rule_on_its_own(linked):
    """A member that skips its own check still meets the leading site's."""
    a, b = linked
    principal = {'user': 'alice', 'home': iid(a), 'sh': '', 'ip': '10.0.0.9'}
    with at(a):
        kind, status, _h, body = relay.relay_call(iid(b), 'PUT', f'/api/clusters/{CID}',
                                                  body=b'{}', ctype='application/json',
                                                  principal=principal)
    assert (kind, status) == ('answer', 404) and json.loads(body)['code'] == 'FED_RELAY_RULE'


def test_only_cluster_routes_cross(linked):
    a, b = linked
    principal = {'user': 'alice', 'home': iid(a), 'sh': '', 'ip': ''}
    with at(a):
        kind, status, _h, body = relay.relay_call(iid(b), 'GET', '/api/federation/status',
                                                  principal=principal)
    assert (kind, status) == ('answer', 404) and json.loads(body)['code'] == 'FED_RELAY_RULE'


# --- who a site speaks for --------------------------------------------------------------------------

def _as(a, b, **principal):
    p = {'user': 'alice', 'home': iid(a), 'sh': '', 'ip': ''}
    p.update(principal)
    with at(a):
        kind, status, _h, body = relay.relay_call(iid(b), 'GET', f'/api/clusters/{CID}/status',
                                                  principal=p)
    return status, json.loads(body or b'{}')


def test_a_site_speaks_only_for_the_accounts_it_homes(linked):
    a, b = linked
    status, body = _as(a, b, home=iid(b))
    assert (status, body['code']) == (403, 'FED_RELAY_WRONG_HOME')


def test_a_local_account_of_the_leading_site_is_never_borrowed(linked):
    a, b = linked
    _add_local_user(b, 'root', role='admin')
    status, body = _as(a, b, user='root')
    assert (status, body['code']) == (403, 'FED_RELAY_WRONG_HOME')


def test_an_account_that_has_not_arrived_waits(linked, monkeypatch):
    a, b = linked
    pulled = []
    monkeypatch.setattr(federation, 'pull_identities', lambda home: pulled.append(home))
    status, body = _as(a, b, user='newcomer')
    assert (status, body['code']) == (503, 'FED_RELAY_SYNCING')


def test_an_unmapped_mirror_is_refused(linked):
    a, b = linked
    _db_of(b).conn.execute("UPDATE users SET tenant = ?, role = ? WHERE username = 'alice'",
                           (federation.QUARANTINE, federation.QUARANTINE))
    _db_of(b).conn.commit()
    status, body = _as(a, b)
    assert (status, body['code']) == (403, 'FED_RELAY_UNMAPPED')


def test_a_disabled_mirror_is_refused(linked):
    a, b = linked
    _db_of(b).conn.execute("UPDATE users SET enabled = 0 WHERE username = 'alice'")
    _db_of(b).conn.commit()
    status, body = _as(a, b)
    assert (status, body['code']) == (403, 'FED_RELAY_DISABLED')


def _with_token(monkeypatch, role, user='alice'):
    from pegaprox.utils import auth as authmod
    monkeypatch.setattr(authmod, 'validate_api_token',
                        lambda token: {'user': user, 'role': role, 'api_token': True,
                                       'token_id': 7, 'token_name': 'ci'})


def _token_call(a, path, method='GET', body=None):
    with at(a):
        return a.client.open(path, method=method, json=body,
                             headers={'Authorization': 'Bearer pgx_x'})


def test_an_api_token_crosses_with_its_role_and_no_more(linked, monkeypatch):
    """A viewer token of an admin reads at the leading site and starts nothing there, where
    the admin's session would. The leading site holds it to the role as one of its own
    tokens: the relayed session is a token's."""
    a, b = linked
    import pegaprox.utils.auth as authmod
    opened = []
    real = authmod.open_relay_session

    def spy(*args, **kw):
        opened.append((args[1], kw.get('api_token', False)))
        return real(*args, **kw)
    monkeypatch.setattr(authmod, 'open_relay_session', spy)
    _with_token(monkeypatch, 'viewer')
    r = _token_call(a, _relay_path(b, '/status'))
    assert r.status_code == 200 and r.get_json()['user'] == 'alice', r.data
    r = _token_call(a, _relay_path(b, '/vms/n1/qemu/101/start'), 'POST', {})
    assert r.status_code == 403 and r.get_json()['code'] == 'MISSING_PERMISSION'
    assert opened == [('viewer', True), ('viewer', True)]
    # counterproof: an admin token of the same account starts it
    _with_token(monkeypatch, 'admin')
    r = _token_call(a, _relay_path(b, '/vms/n1/qemu/101/start'), 'POST', {})
    assert r.status_code == 200, r.data


def test_a_token_is_floored_at_both_sites(linked, monkeypatch):
    """An admin token of a viewer crosses as a viewer's; an admin token of an account the
    leading site maps lower acts there with that lower role."""
    a, b = linked
    _with_token(monkeypatch, 'admin', user='vic')
    r = _token_call(a, _relay_path(b, '/vms/n1/qemu/101/start'), 'POST', {})
    assert r.status_code == 403 and r.get_json()['code'] == 'MISSING_PERMISSION'
    _with_token(monkeypatch, 'admin')
    _db_of(b).conn.execute("UPDATE users SET role = 'viewer' WHERE username = 'alice'")
    _db_of(b).conn.commit()
    r = _token_call(a, _relay_path(b, '/vms/n1/qemu/101/start'), 'POST', {})
    assert r.status_code == 403 and r.get_json()['code'] == 'MISSING_PERMISSION'


def test_a_token_with_a_custom_role_stays_at_its_site(linked, monkeypatch):
    a, b = linked
    _with_token(monkeypatch, 'ci-operators')
    r = _token_call(a, _relay_path(b, '/status'))
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_RELAY_TOKEN'
    with at(a):
        r = a.client.get('/api/federation/linked', headers={'Authorization': 'Bearer pgx_x'})
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_RELAY_TOKEN'
    assert _relayed_calls(a) == []


def test_a_token_lists_the_other_sites_with_its_own_permissions(linked, monkeypatch):
    a, b = linked
    _with_token(monkeypatch, 'viewer')
    with at(a):
        r = a.client.get('/api/federation/linked', headers={'Authorization': 'Bearer pgx_x'})
    site = r.get_json()['sites'][0]
    assert site['state'] == 'ok', site
    assert 'vm.start' not in site['perms'] and 'cluster.view' in site['perms']


def test_a_token_and_the_session_of_one_account_have_lists_of_their_own(linked, monkeypatch):
    """The list is kept for half a minute per site and account: a viewer token's never
    stands in for the session's, nor the session's for the token's."""
    a, b = linked
    _with_token(monkeypatch, 'viewer')
    with at(a):
        site = a.client.get('/api/federation/linked',
                            headers={'Authorization': 'Bearer pgx_x'}).get_json()['sites'][0]
    assert 'vm.start' not in site['perms'] and site['admin'] is False
    sid = _session(a, 'alice')
    site = _get(a, '/api/federation/linked', sid).get_json()['sites'][0]
    assert 'vm.start' in site['perms'] and site['admin'] is True
    with at(a):
        site = a.client.get('/api/federation/linked',
                            headers={'Authorization': 'Bearer pgx_x'}).get_json()['sites'][0]
    assert 'vm.start' not in site['perms']


def test_a_principal_this_site_cannot_read_whole_is_refused():
    """An unknown key of the principal may be a restriction a newer site added: dropped,
    the call would run wider than it was sent, so it does not run."""
    good = {'v': relay.RELAY_VERSION, 'rid': 'a' * 32, 'method': 'GET',
            'path': '/api/clusters/x/status', 'query': '', 'ctype': '',
            'principal': {'user': 'u', 'home': 'b' * 32, 'sh': '', 'ip': ''}}
    assert relay.valid_envelope(good)['tok'] is None
    with_tok = dict(good, principal=dict(good['principal'], tok='viewer'))
    assert relay.valid_envelope(with_tok)['tok'] == 'viewer'
    assert relay.valid_envelope(dict(good, principal=dict(good['principal'], tok='ops'))) is None
    assert relay.valid_envelope(dict(good, principal=dict(good['principal'], scope='x'))) is None


def test_an_account_of_another_site_works_from_its_home(linked):
    a, b = linked
    _add_local_user(a, 'mira', role='admin', fed_home='f' * 32)
    sid = _session(a, 'mira')
    r = _get(a, _relay_path(b, '/status'), sid)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_HOME_ELSEWHERE'
    assert _relayed_calls(a) == []


# --- the wire ---------------------------------------------------------------------------------------

def _capture(a):
    """The next relayed request a sends, as (headers, body)."""
    got = {}
    inner = a.runtime['transport']

    def spy(url, method, path, body, headers):
        if path == relay.RELAY_PATH:
            got['req'] = (dict(headers), body)
        return inner(url, method, path, body, headers)
    a.runtime['transport'] = spy
    return got


def _send_raw(b, headers, body):
    with at(b):
        return b.client.post(relay.RELAY_PATH, data=body, headers=headers)


def test_a_replayed_request_is_nobodys(linked):
    a, b = linked
    got = _capture(a)
    sid = _session(a, 'alice')
    assert _post(a, _relay_path(b, '/vms/n1/qemu/101/start'), sid, {}).status_code == 200
    headers, body = got['req']
    r = _send_raw(b, headers, body)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_NOT_MEMBER'
    assert _db_of(b).conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'vm.start'"
                                  ).fetchone()[0] == 1


def _held(a, b, n):
    """n relayed writes a signs for b, kept back: none reaches b, so every nonce is unspent."""
    held = []

    def keep(url, method, path, body, headers):
        if path != relay.RELAY_PATH:
            raise AssertionError(path)
        held.append((dict(headers), body))
        raise OSError('kept back')
    a.runtime['transport'] = keep
    sid = _session(a, 'alice')
    for i in range(n):
        relay.reset_for_tests()
        _post(a, _relay_path(b, '/vms/n1/qemu/101/start'), sid, {'n': i})
    assert len(held) == n
    return held


def _inner_status(r):
    """The status a signed answer carries: the peer route itself answers 200."""
    return json.loads(relay._unb64(r.headers[relay.ANSWER_HEADER]))['status']


def test_an_altered_body_or_envelope_is_nobodys(linked):
    a, b = linked
    (h1, body1), (h2, body2), (h3, body3) = _held(a, b, 3)
    started = "SELECT COUNT(*) FROM audit_log WHERE action = 'vm.start'"
    # counterproof: delivered as signed, the request runs
    r = _send_raw(b, h1, body1)
    assert r.status_code == 200 and _inner_status(r) == 200
    assert _db_of(b).conn.execute(started).fetchone()[0] == 1
    # another body under the signed digest: refused in a signed answer the sender can check
    r = _send_raw(b, h2, b'{"n": 99}')
    assert _inner_status(r) == 400 and r.get_json(force=True)['code'] == 'FED_RELAY_BODY'
    assert relay.SIG_HEADER in r.headers
    # another envelope: the signature no longer covers it
    env = json.loads(relay._unb64(h3[relay.ENVELOPE_HEADER]))
    env['principal']['user'] = 'vic'
    h = dict(h3, **{relay.ENVELOPE_HEADER: relay._b64(json.dumps(env).encode())})
    assert _send_raw(b, h, body3).status_code == 403
    assert _db_of(b).conn.execute(started).fetchone()[0] == 1


# --- uploads ---------------------------------------------------------------------------------------------

_ISO = bytes(range(256)) * (3 * 4096 + 7)    # three MiB and a bit: more than one spool chunk


def _upload(a, b, sid, data=_ISO, name='debian.iso'):
    import io
    with at(a):
        return a.client.post(f'/api/clusters/{CID}~{iid(b)}/datastores/local/upload',
                             data={'file': (io.BytesIO(data), name), 'node': 'n1',
                                   'content': 'iso'},
                             content_type='multipart/form-data',
                             headers={'X-Session-ID': sid, 'X-Requested-With': 'XMLHttpRequest'})


def _spool_files():
    import os
    return sorted(os.listdir(relay.upload_dir()))


def test_an_upload_reaches_the_leading_site_whole(linked):
    a, b = linked
    before = _spool_files()
    sid = _session(a, 'alice')
    r = _upload(a, b, sid)
    assert r.status_code == 200 and r.get_json()['size'] == len(_ISO), r.data
    assert UPLOADED == [('alice', 'local', 'n1', 'debian.iso', _ISO)]
    assert [c[2] for c in _relayed_upload_calls(a)] == [relay.RELAY_UPLOAD_PATH]
    # the copies spooled at both sites are gone again
    assert _spool_files() == before
    assert _db_of(a).conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = "
                                  "'federation.relayed'").fetchone()[0] == 1


def _relayed_upload_calls(a):
    return [c for c in a.calls if c[2] == relay.RELAY_UPLOAD_PATH]


def test_an_upload_the_leading_site_did_not_get_as_signed_is_refused(linked):
    """Another body under the signed digest never reaches the upload route."""
    a, b = linked
    inner = a.runtime['transport']

    def bend(url, method, path, body, headers):
        if path == relay.RELAY_UPLOAD_PATH:
            body = body.replace(b'debian.iso', b'debian.isx')
        return inner(url, method, path, body, headers)
    a.runtime['transport'] = bend
    sid = _session(a, 'alice')
    r = _upload(a, b, sid)
    assert r.status_code == 400 and r.get_json()['code'] == 'FED_RELAY_BODY'
    assert UPLOADED == []
    # counterproof: delivered as sent, it lands
    a.runtime['transport'] = inner
    assert _upload(a, b, sid).status_code == 200 and len(UPLOADED) == 1


def test_an_upload_comes_only_over_its_own_path(linked):
    """The plain relay refuses the upload rule (its body limit is not an upload's), and a
    signature made for one of the two paths does not hold on the other."""
    a, b = linked
    p = {'user': 'alice', 'home': iid(a), 'sh': '', 'ip': ''}
    with at(a):
        kind, status, _h, body = relay.relay_call(
            iid(b), 'POST', f'/api/clusters/{CID}/datastores/local/upload', body=b'x',
            ctype='multipart/form-data; boundary=x', principal=p)
    assert (kind, status, json.loads(body)['code']) == ('answer', 404, 'FED_RELAY_RULE')
    got = _capture(a)
    sid = _session(a, 'alice')
    _get(a, _relay_path(b, '/status'), sid)
    headers, raw = got['req']
    with at(b):
        r = b.client.post(relay.RELAY_UPLOAD_PATH, data=raw, headers=headers)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_NOT_MEMBER'
    assert UPLOADED == []


def test_an_upload_without_room_goes_nowhere(linked, monkeypatch):
    a, b = linked
    import shutil
    from collections import namedtuple
    usage = namedtuple('usage', 'total used free')
    monkeypatch.setattr(shutil, 'disk_usage', lambda path: usage(10 ** 9, 10 ** 9, 1024))
    sid = _session(a, 'alice')
    r = _upload(a, b, sid)
    assert r.status_code == 507 and r.get_json()['code'] == 'FED_RELAY_NO_SPACE'
    assert _relayed_upload_calls(a) == [] and UPLOADED == []


def test_an_account_that_may_not_upload_there_writes_nothing_to_either_disk(linked, monkeypatch):
    """A viewer: refused here from the site's permission list, before the body is read.
    Should this site's list be wrong, the leading site refuses before its disk too."""
    a, b = linked
    spooled = []
    real = relay.spool

    def spy(stream, size):
        spooled.append(size)
        return real(stream, size)
    monkeypatch.setattr(relay, 'spool', spy)
    r = _upload(a, b, _session(a, 'vic'))
    assert r.status_code == 403 and r.get_json()['code'] == 'MISSING_PERMISSION'
    assert spooled == [] and UPLOADED == []
    real_list = relay.site_list
    monkeypatch.setattr(relay, 'site_list', lambda *x, **kw: dict(real_list(*x, **kw), admin=True))
    relay.reset_for_tests()
    r = _upload(a, b, _session(a, 'vic'))
    assert r.status_code == 403 and r.get_json()['code'] == 'MISSING_PERMISSION'
    # written here once, not there
    assert len(spooled) == 1 and UPLOADED == []


def test_one_upload_at_a_time_per_account(linked):
    a, b = linked
    assert relay.take_upload('alice') is True
    try:
        r = _upload(a, b, _session(a, 'alice'))
        assert r.status_code == 429 and r.get_json()['code'] == 'FED_RELAY_BUSY'
    finally:
        relay.give_upload('alice')
    assert _upload(a, b, _session(a, 'alice')).status_code == 200


def test_an_account_the_leading_site_refuses_sends_no_upload_to_its_disk(linked, monkeypatch):
    """The account is checked from the headers, before the body is read there."""
    a, b = linked
    spooled = []
    real = relay.spool

    def spy(stream, size):
        spooled.append(size)
        return real(stream, size)
    monkeypatch.setattr(relay, 'spool', spy)
    _db_of(b).conn.execute("UPDATE users SET enabled = 0 WHERE username = 'alice'")
    _db_of(b).conn.commit()
    sid = _session(a, 'alice')
    r = _upload(a, b, sid)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_RELAY_DISABLED'
    # spooled once, at this site; none at the leading one
    assert len(spooled) == 1 and UPLOADED == []


def test_a_control_signature_is_no_relay_signature(linked):
    from tests.test_federation import _signed_headers_of
    a, b = linked
    h = _signed_headers_of(a, iid(b), 'POST', relay.RELAY_PATH)
    h[relay.ENVELOPE_HEADER] = relay._b64(b'{}')
    h[relay.BODY_HEADER] = relay._sha(b'')
    assert _send_raw(b, h, b'').status_code == 403


def test_a_relay_signature_opens_no_control_route(linked):
    a, b = linked
    got = _capture(a)
    sid = _session(a, 'alice')
    _get(a, _relay_path(b, '/status'), sid)
    headers, _body = got['req']
    with at(b):
        r = b.client.get(federation.STATUS_PATH, headers=headers)
    assert r.status_code == 403


def test_an_unsigned_answer_is_no_answer(linked):
    a, b = linked
    inner = a.runtime['transport']

    def strip(url, method, path, body, headers):
        status, raw, rh = inner(url, method, path, body, headers)
        if path == relay.RELAY_PATH:
            rh = {k: v for k, v in rh.items() if k != relay.SIG_HEADER}
        return status, raw, rh
    a.runtime['transport'] = strip
    sid = _session(a, 'alice')
    r = _get(a, _relay_path(b, '/status'), sid)
    assert r.status_code == 503 and r.get_json()['code'] == 'FED_SITE_UNREACHABLE'
    r = _post(a, _relay_path(b, '/vms/n1/qemu/101/start'), sid, {})
    assert r.status_code == 504 and r.get_json()['code'] == 'FED_RELAY_NO_ANSWER'


def test_a_site_that_does_not_answer_is_not_dialled_for_a_while(linked):
    a, b = linked
    a.runtime['transport'] = lambda *args: (0, b'', {})
    sid = _session(a, 'alice')
    for _ in range(relay._BREAK_AFTER):
        assert _get(a, _relay_path(b, '/status'), sid).status_code == 503
    a.calls.clear()
    seen = []
    a.runtime['transport'] = lambda *args: seen.append(args) or (0, b'', {})
    r = _get(a, _relay_path(b, '/status'), sid)
    assert r.status_code == 503 and r.get_json()['code'] == 'FED_SITE_UNREACHABLE'
    assert seen == []


def test_over_its_budget_a_site_is_told_to_wait(linked, monkeypatch):
    a, b = linked
    monkeypatch.setattr(relay, 'SLOT_WAIT', 0.3)
    monkeypatch.setattr(relay._out, 'take', lambda key: False)
    sid = _session(a, 'alice')
    r = _get(a, _relay_path(b, '/status'), sid)
    assert r.status_code == 429 and r.get_json()['code'] == 'FED_RELAY_BUSY'


def test_a_call_waits_a_moment_for_a_slot_of_its_site(linked, monkeypatch):
    """The reads of one view come in a burst: a call that finds the site's slots taken waits
    for one to come free rather than leaving its panel empty."""
    import threading
    a, b = linked
    monkeypatch.setattr(relay._out, 'each', 1)
    with at(a):
        assert relay.take_slot(iid(b), 'vic', wait=0)
    threading.Timer(0.4, relay.give_slot, args=(iid(b), 'vic')).start()
    sid = _session(a, 'alice')
    r = _get(a, _relay_path(b, '/status'), sid)
    assert r.status_code == 200, r.data


def test_one_account_holds_half_a_sites_share_at_most():
    relay.reset_for_tests()
    site = 'd' * 32
    each = relay._out_users.each
    assert each == max(2, relay._out.each // 2) and each < relay._out.each
    held = [relay.take_slot(site, 'alice', wait=0) for _ in range(each)]
    assert all(held) and relay.take_slot(site, 'alice', wait=0) is False
    # another account still gets one
    assert relay.take_slot(site, 'vic', wait=0) is True
    relay.reset_for_tests()


def test_a_write_that_never_left_says_nothing_was_sent(linked):
    """No connection to the site: the write did not happen there, and the answer says so.
    Counterproof: a connection that broke off after the send may have delivered it."""
    a, b = linked
    sid = _session(a, 'alice')

    def refused(*args, **kw):
        raise ConnectionRefusedError('refused')
    a.runtime['transport'] = refused
    r = _post(a, _relay_path(b, '/vms/n1/qemu/101/start'), sid, {})
    assert r.status_code == 503 and r.get_json()['code'] == 'FED_SITE_UNREACHABLE'
    assert 'nothing was sent' in r.get_json()['error']
    relay.reset_for_tests()

    def broke(*args, **kw):
        raise OSError('connection reset')
    a.runtime['transport'] = broke
    r = _post(a, _relay_path(b, '/vms/n1/qemu/101/start'), sid, {})
    assert r.status_code == 504 and r.get_json()['code'] == 'FED_RELAY_NO_ANSWER'


def test_only_a_connection_that_never_stood_counts_as_unsent():
    import requests
    from urllib3.exceptions import MaxRetryError, NewConnectionError, ProtocolError
    refused = requests.exceptions.ConnectionError(
        MaxRetryError(None, '/x', reason=NewConnectionError(None, 'refused')))
    broke = requests.exceptions.ConnectionError(
        MaxRetryError(None, '/x', reason=ProtocolError('reset')))
    assert federation._never_connected(refused) is True
    assert federation._never_connected(requests.exceptions.ConnectTimeout()) is True
    assert federation._never_connected(broke) is False
    assert federation._never_connected(requests.exceptions.ReadTimeout()) is False


def test_only_a_tls_failure_before_the_send_counts_as_unsent():
    """A pin or certificate failure stops the connection before the request goes out; a TLS
    error while the answer is read does not, and the request may have been delivered."""
    import requests
    pin = requests.exceptions.SSLError('Fingerprints did not match. Expected "ab", got "cd"')
    cert = requests.exceptions.SSLError('[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed')
    late = requests.exceptions.SSLError('[SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC] bad record mac')
    assert federation._tls_before_send(pin) and federation._tls_before_send(cert)
    assert not federation._tls_before_send(late)


def test_a_tls_error_on_the_answer_is_no_unsent_call(monkeypatch):
    import requests

    class _Sess:
        def __init__(self, exc):
            self.exc = exc

        def request(self, *args, **kw):
            raise self.exc
    monkeypatch.setattr(federation, '_url_ok', lambda url: True)
    for text, never in (('bad record mac', False), ('Fingerprints did not match', True)):
        exc = requests.exceptions.SSLError(text)
        monkeypatch.setattr(federation, '_session_for', lambda url, fp, e=exc: _Sess(e))
        sent = {}
        federation._wire_call('https://b.example:5000', ['ab'], 'POST', relay.RELAY_PATH, b'',
                              {}, 5, 1024, sent=sent)
        assert bool(sent.get('never')) is never, text


def test_a_site_over_its_rate_is_told_to_wait(linked, monkeypatch):
    """The leading site counts a member's relayed calls on their own, whatever address
    they come from."""
    from pegaprox.api import federation_relay as api_relay
    from pegaprox.utils.ratelimit import SlidingWindow
    a, b = linked
    monkeypatch.setattr(api_relay, '_relay_rate', SlidingWindow(limit=1, window=60, max_keys=8))
    sid = _session(a, 'alice')
    assert _get(a, _relay_path(b, '/status'), sid).status_code == 200
    r = _get(a, _relay_path(b, '/status'), sid)
    assert r.status_code == 429 and r.get_json()['code'] == 'FED_RELAY_BUSY'


# --- the answer -----------------------------------------------------------------------------------------

def test_no_html_reaches_this_origin(linked):
    a, b = linked
    sid = _session(a, 'alice')
    r = _get(a, _relay_path(b, '/page'), sid)
    assert r.status_code == 502 and r.get_json()['code'] == 'FED_RELAY_TYPE'
    assert b'<script>' not in r.data


def test_a_file_is_a_download_without_cookie_or_path(linked):
    a, b = linked
    sid = _session(a, 'alice')
    r = _get(a, _relay_path(b, '/log.txt'), sid)
    assert r.status_code == 200 and r.data == b'line 1\n'
    assert r.headers['Content-Disposition'] == 'attachment; filename=".._task.log"'
    assert 'Set-Cookie' not in r.headers


def test_a_sign_in_refusal_there_is_no_lost_session_here(linked):
    a, b = linked
    sid = _session(a, 'alice')
    r = _get(a, _relay_path(b, '/session-gone'), sid)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_RELAY_AUTH'


# --- the list ----------------------------------------------------------------------------------------------

def test_the_list_names_the_clusters_the_caller_may_see_there(linked):
    a, b = linked
    _db_of(b).conn.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted, "
                           "fed_owner, cluster_type) VALUES (?, 'Prod', 'h', 'u', '', '', "
                           "'proxmox')", (CID,))
    _db_of(b).conn.commit()
    with at(b):
        federation._runtime['clusters_body'] = None
    sid = _session(a, 'alice')
    r = _get(a, '/api/federation/linked', sid)
    assert r.status_code == 200, r.data
    sites = r.get_json()['sites']
    assert len(sites) == 1 and sites[0]['iid'] == iid(b) and sites[0]['state'] == 'ok'
    assert [c['id'] for c in sites[0]['clusters']] == [f'{CID}~{iid(b)}']
    assert sites[0]['clusters'][0]['name'] == 'Prod'
    assert 'vm.start' in sites[0]['perms']


def test_the_list_says_why_a_site_shows_nothing(linked):
    a, b = linked
    _db_of(b).conn.execute("UPDATE users SET tenant = ?, role = ? WHERE username = 'vic'",
                           (federation.QUARANTINE, federation.QUARANTINE))
    _db_of(b).conn.commit()
    sid = _session(a, 'vic')
    sites = _get(a, '/api/federation/linked', sid).get_json()['sites']
    assert sites[0]['state'] == 'unmapped' and sites[0]['clusters'] == []


def test_a_site_in_trouble_says_so_and_a_busy_one_keeps_its_last_list(linked, monkeypatch):
    """A site that does not answer shows that, never its last list as if it ran; the
    trouble is not kept, so the next poll asks again. While only this instance is short
    of slots for the site, its last good list stays."""
    a, b = linked
    monkeypatch.setattr(relay, 'LIST_SECONDS', 0)
    sid = _session(a, 'alice')
    assert _get(a, '/api/federation/linked', sid).get_json()['sites'][0]['state'] == 'ok'
    inner = a.runtime['transport']

    def down(*args, **kw):
        raise OSError('unreachable')
    a.runtime['transport'] = down
    site = _get(a, '/api/federation/linked', sid).get_json()['sites'][0]
    assert site['state'] == 'unreachable' and site['clusters'] == []
    # the good list is still the one held: the trouble did not replace it
    assert [e['state'] for e, _t in relay._list_cache.values()] == ['ok']
    relay.reset_for_tests()
    a.runtime['transport'] = inner
    good = _get(a, '/api/federation/linked', sid).get_json()['sites'][0]
    assert good['state'] == 'ok'
    monkeypatch.setattr(relay._out, 'take', lambda key: False)
    site = _get(a, '/api/federation/linked', sid).get_json()['sites'][0]
    assert site == dict(good, stale=True)


def test_a_list_waits_behind_the_relays_of_its_site(linked, monkeypatch):
    a, b = linked
    monkeypatch.setattr(relay._out, 'take', lambda key: False)
    sid = _session(a, 'alice')
    site = _get(a, '/api/federation/linked', sid).get_json()['sites'][0]
    assert site['state'] == 'loading' and relay._list_cache == {}


def test_the_list_cache_stays_bounded():
    relay.reset_for_tests()
    rec = {'site': 's', 'url': 'https://s.example'}
    try:
        orig = relay.relay_call
        relay.relay_call = lambda *a, **k: ('refused', 403, {}, b'{"code": "FED_RELAY_UNMAPPED"}')
        for i in range(relay.MAX_LISTS + 50):
            relay.site_list('c' * 32, rec, {'user': f'u{i}'}, now=1000.0)
        assert len(relay._list_cache) == relay.MAX_LISTS
        # the expired go first: one more, later, leaves only the fresh one
        relay.site_list('c' * 32, rec, {'user': 'late'}, now=1000.0 + relay.LIST_SECONDS + 1)
        assert list(relay._list_cache) == [('c' * 32, 'late', '', '')]
    finally:
        relay.relay_call = orig
        relay.reset_for_tests()


def test_the_list_answers_relayed_requests_only(linked):
    a, b = linked
    _add_local_user(b, 'root', role='admin')
    sid = _session(b, 'root')
    r = _get(b, relay.LIST_RULE, sid)
    assert r.status_code == 404 and r.get_json()['code'] == 'FED_RELAY_ONLY'


def test_an_account_of_another_site_gets_its_home_named(linked):
    a, b = linked
    _add_local_user(a, 'mira', role='admin', fed_home=iid(b))
    sid = _session(a, 'mira')
    body = _get(a, '/api/federation/linked', sid).get_json()
    assert body['sites'] == [] and body['home']['iid'] == iid(b)


# --- the rule table -------------------------------------------------------------------------------------

def test_every_cluster_route_is_decided(api):
    """The full list of the cluster rules that cross is pinned: a cluster route added later
    fails here until someone decides whether another site may run it as one of this site's
    accounts (add it below) or not (relay._EXCLUDED)."""
    import os
    app = api.app
    crossing = set()
    for rule in app.url_map.iter_rules():
        if not (rule.rule == relay.CLUSTER_RULE or rule.rule.startswith(relay.CLUSTER_RULE + '/')):
            continue
        for method in sorted((rule.methods or set()) - {'HEAD', 'OPTIONS'}):
            if relay.rule_verdict(app, method, rule) is None:
                crossing.add(f'{method} {rule.rule[len(relay.CLUSTER_RULE):] or "/"}')
    pinned_file = os.path.join(os.path.dirname(__file__), 'data', 'federation_relayed_rules.txt')
    pinned = {line.strip() for line in open(pinned_file) if line.strip() and not line.startswith('#')}
    assert crossing - pinned == set(), 'decide on these new cluster routes'
    assert pinned - crossing == set(), 'these are pinned but gone or excluded now'


# --- consoles ---------------------------------------------------------------------------------------------

class _FakeWS:
    """The browser's side of the console socket."""

    def __init__(self, incoming=()):
        self.incoming, self.sent, self.connected = list(incoming), [], True
        self.closed, self._waited = None, False

    def receive(self, timeout=None):
        if self.incoming:
            got = self.incoming.pop(0)
            if isinstance(got, Exception):
                raise got
            return got
        if not self._waited:
            import gevent
            gevent.sleep(0.1)
            self._waited = True
            return None
        self.connected = False
        return None

    def send(self, data):
        self.sent.append(data)

    def close(self, reason=None, message=None):
        self.closed, self.connected = (reason, message), False


class _FakeUpstream:
    """The leading site's console server."""

    def __init__(self, frames=()):
        self.frames, self.sent, self.closed = list(frames), [], False

    def settimeout(self, t):
        pass

    def recv_data(self):
        import websocket
        if self.frames:
            return self.frames.pop(0)
        return websocket.ABNF.OPCODE_CLOSE, b''

    def send(self, data, opcode=None):
        self.sent.append((opcode, data))

    def close(self):
        self.closed = True


def _console(a, b, monkeypatch, user='alice', query=None, upstream=None, api_token=False,
             incoming=('hello', b'\x01')):
    """Open a console of b's guest at a; returns (browser socket, what open_console got)."""
    from pegaprox.api import federation_relay as api_relay
    from pegaprox.utils.realtime import create_ws_token
    opened = []

    def fake_open(rec, kind, path, q, reverse_proxy, timeout=10):
        opened.append({'url': rec['url'], 'kind': kind, 'path': path, 'query': q,
                       'reverse_proxy': reverse_proxy})
        return upstream or _FakeUpstream()
    monkeypatch.setattr(relay, 'open_console', fake_open)
    sid = _session(a, user)
    token = create_ws_token(user, 'admin', api_token=api_token, sid=sid)
    q = {'token': token, 'cluster': f'{CID}~{iid(b)}', 'kind': 'vnc', 'node': 'n1',
         'type': 'qemu', 'vmid': '101', 'pve_ticket': 'PVEVNC:T', 'pve_port': '5900'}
    q.update(query or {})
    from urllib.parse import urlencode
    ws = _FakeWS(list(incoming))
    with at(a):
        with a.app.test_request_context(f'/api/federation/console?{urlencode(q)}'):
            api_relay.federation_console(ws)
    return ws, opened


def _error_of(ws):
    return json.loads(ws.sent[0])['message'] if ws.sent and isinstance(ws.sent[0], str) else None


def test_a_console_opens_at_the_leading_site_with_its_own_token(linked, monkeypatch):
    import websocket
    a, b = linked
    upstream = _FakeUpstream([(websocket.ABNF.OPCODE_BINARY, b'RFB 003.008\n')])
    ws, opened = _console(a, b, monkeypatch, upstream=upstream)
    assert len(opened) == 1, ws.sent
    o = opened[0]
    assert o['url'] == URL['b'] and o['kind'] == 'vnc' and o['reverse_proxy'] is False
    assert o['path'] == f'/api/clusters/{CID}/vms/n1/qemu/101/vncwebsocket'
    from urllib.parse import parse_qs
    q = parse_qs(o['query'])
    assert q['pve_ticket'] == ['PVEVNC:T'] and q['pve_port'] == ['5900']
    # the token is the leading site's own, for the caller, under this site's session handle
    from pegaprox.utils.realtime import validate_ws_token
    granted = validate_ws_token(q['token'][0])
    assert granted['user'] == 'alice' and granted['sid'].startswith(f'fed:{iid(a)}:')
    # bytes both ways, text stays text
    assert upstream.sent == [(websocket.ABNF.OPCODE_TEXT, 'hello'),
                             (websocket.ABNF.OPCODE_BINARY, b'\x01')]
    assert b'RFB 003.008\n' in ws.sent and upstream.closed
    rows = _db_of(a).conn.execute("SELECT details FROM audit_log WHERE action = "
                                  "'federation.console'").fetchall()
    assert len(rows) == 1 and 'vnc console' in rows[0]['details']


def test_only_the_ticket_of_its_kind_rides_along(linked, monkeypatch):
    a, b = linked
    ws, opened = _console(a, b, monkeypatch, query={'kind': 'shell', 'host': '10.0.0.1',
                                                    'ticket': 'x'})
    assert opened[0]['path'] == f'/api/clusters/{CID}/nodes/n1/shellws'
    from urllib.parse import parse_qs
    assert set(parse_qs(opened[0]['query'])) == {'token'}


@pytest.mark.parametrize('query, why', [
    ({'kind': 'spice'}, 'Not a console'),
    ({'node': '../x'}, 'Not a console'),
    ({'cluster': 'pve1'}, 'No such site'),
    ({'token': 'forged'}, 'Authentication required'),
])
def test_a_console_that_is_not_one_is_refused(linked, monkeypatch, query, why):
    a, b = linked
    ws, opened = _console(a, b, monkeypatch, query=query)
    assert opened == [] and why in (_error_of(ws) or '')


def test_a_console_token_is_good_for_one_console(linked, monkeypatch):
    """The very token that opened a console opens no second one."""
    from pegaprox.utils.realtime import create_ws_token
    a, b = linked
    with at(a):
        token = create_ws_token('alice', 'admin', sid=_session(a, 'alice'))
    ws, opened = _console(a, b, monkeypatch, query={'token': token})
    assert len(opened) == 1
    ws2, opened2 = _console(a, b, monkeypatch, query={'token': token})
    assert opened2 == [] and 'Authentication required' in (_error_of(ws2) or '')


def test_a_read_that_timed_out_keeps_the_console_open(linked, monkeypatch):
    """Some versions of the socket library raise on a read that timed out: the console goes on."""
    import websocket
    a, b = linked
    upstream = _FakeUpstream()
    ws, opened = _console(a, b, monkeypatch, upstream=upstream,
                          incoming=(TimeoutError('timed out'), 'hello',
                                    RuntimeError('socket timed out'), b'\x01'))
    assert len(opened) == 1
    assert upstream.sent == [(websocket.ABNF.OPCODE_TEXT, 'hello'),
                             (websocket.ABNF.OPCODE_BINARY, b'\x01')]


def test_no_console_crosses_with_the_switch_off(linked, monkeypatch):
    a, b = linked
    monkeypatch.setattr(federation, 'enabled', lambda: False)
    ws, opened = _console(a, b, monkeypatch)
    assert opened == [] and _error_of(ws) == federation.FED_DISABLED_ERROR


def test_an_api_token_opens_no_console_of_another_site(linked, monkeypatch):
    a, b = linked
    ws, opened = _console(a, b, monkeypatch, api_token=True)
    assert opened == [] and 'API token' in _error_of(ws)


def test_an_account_of_another_site_opens_no_console_from_here(linked, monkeypatch):
    a, b = linked
    _add_local_user(a, 'mira', role='admin', fed_home='f' * 32)
    ws, opened = _console(a, b, monkeypatch, user='mira')
    assert opened == [] and 'belongs to another site' in _error_of(ws)


def test_the_leading_site_can_refuse_the_console(linked, monkeypatch):
    a, b = linked
    _db_of(b).conn.execute("UPDATE users SET enabled = 0 WHERE username = 'alice'")
    _db_of(b).conn.commit()
    ws, opened = _console(a, b, monkeypatch)
    assert opened == [] and 'disabled' in _error_of(ws)


def test_the_console_token_route_answers_relayed_requests_only(linked):
    a, b = linked
    _add_local_user(b, 'root', role='admin')
    sid = _session(b, 'root')
    r = _post(b, f'/api/clusters/{CID}/console-token', sid, {})
    assert r.status_code == 404 and r.get_json()['code'] == 'FED_RELAY_ONLY'


def test_a_console_server_without_a_matching_pin_is_not_spoken_to(monkeypatch):
    """open_console checks the certificate against the pins before the upgrade."""
    import socket
    import ssl
    sent = []

    class Tls:
        def getpeercert(self, binary_form=False):
            return b'not-the-pinned-cert'

        def close(self):
            sent.append('closed')

        def sendall(self, data):
            sent.append(data)

    class Raw:
        def close(self):
            pass
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: Raw())
    monkeypatch.setattr(ssl.SSLContext, 'wrap_socket', lambda self, s, server_hostname=None: Tls())
    monkeypatch.setattr(federation, '_url_ok', lambda url: True)
    rec = {'url': 'https://b.example:5000', 'fingerprints': [':'.join(['AB'] * 32)]}
    with pytest.raises(ssl.SSLError):
        relay.open_console(rec, 'vnc', f'/api/clusters/{CID}/vms/n1/qemu/101/vncwebsocket',
                           'token=t', False)
    assert sent == ['closed']


# --- what an adversarial review found -------------------------------------------------------------

def test_the_body_is_read_before_a_slot_of_the_site_is_taken(linked, monkeypatch):
    """A client that sends its body slowly holds its own request, not one of the few
    slots of the site: the body is in before the slot is taken."""
    a, b = linked
    seen = []
    real = relay._out.take

    def take(key):
        from flask import request
        seen.append(request.environ['wsgi.input'].read())
        return real(key)
    monkeypatch.setattr(relay._out, 'take', take)
    sid = _session(a, 'alice')
    assert _post(a, _relay_path(b, '/vms/n1/qemu/101/start'), sid, {'n': 1}).status_code == 200
    assert seen == [b'']


def test_a_browser_gets_no_console_token_of_another_site(linked):
    a, b = linked
    sid = _session(a, 'alice')
    r = _post(a, _relay_path(b, '/console-token'), sid, {})
    assert r.status_code == 404 and r.get_json()['code'] == 'FED_RELAY_RULE'
    assert _relayed_calls(a) == []


def test_a_head_is_judged_as_the_get_it_runs(api):
    for path, reason in (('/api/clusters/c1/config/export', 'record'),
                         ('/api/clusters/c1/node-credentials', 'record')):
        rule, _args = relay.match_rule(api.app, 'HEAD', path)
        assert rule is not None
        assert relay.rule_verdict(api.app, 'HEAD', rule) == reason
        assert relay.rule_verdict(api.app, 'GET', rule) == reason


def test_one_user_does_not_take_every_console_of_a_site():
    for _ in range(relay.TUNNELS_PER_USER):
        assert relay.take_tunnel('one', 'f' * 32)
    assert not relay.take_tunnel('one', 'f' * 32)
    assert relay.take_tunnel('two', 'f' * 32)


def test_a_slow_request_does_not_close_the_site_for_everybody():
    import time
    for _ in range(relay._BREAK_AFTER + 1):
        relay.note_answer('e' * 32, 'silent', time.monotonic() - 60)
    assert not relay._broken('e' * 32)
    # counterproof: answers that never came, fast, do
    for _ in range(relay._BREAK_AFTER):
        relay.note_answer('e' * 32, 'silent', time.monotonic())
    assert relay._broken('e' * 32)
