"""The pool session of an ISO upload, a chart read and a move to another pool stays out
of their errors.

import_raw_vdi and rrd_updates take the XAPI session in the query string, and requests
names the url of a call that fails in its exception text. upload_to_storage logged that
text and returned it, and the upload route sends the error to the browser as it is;
_rrd_fetch wrote it to the cluster log on every chart read the pool did not answer.
remote_migrate_vm hands VM.migrate_send the session of the other pool in its dest map
and returned the error text of the call as it was. All three now print session_id=***
and keep the rest of the message.

The upload read its session as api.xenapi._session, and on the xenapi proxy that is the
name of one more method, so the PUT never carried the session at all. It takes the ref
of the logged-in session now, as _rrd_fetch does, answers 'Not connected' when there is
none, and a PUT that fails takes the VDI made for it along.
MK Nov 2026
"""
import io
import logging
import threading
import types

import pytest
import requests

import pegaprox.core.xcpng as xcpng_mod
from pegaprox.core.xcpng import XcpngManager

CL = 'cluster_1'
SESSION = 'OpaqueRef:5b1d0c77-9e1a-4c1d-pool-login'
ENCODED = SESSION.replace(':', '%3A')     # how urlencode and requests put it in the query


def _refused(method, url, params=None):
    """The ConnectionError requests raises when the pool does not answer, url and all."""
    path = requests.Request(method, url, params=params).prepare().path_url
    return requests.exceptions.ConnectionError(
        f"HTTPSConnectionPool(host='xcp.example', port=443): Max retries exceeded with url: {path} "
        "(Caused by NewConnectionError(\"HTTPSConnection(host='xcp.example', port=443): "
        "Failed to establish a new connection: [Errno 111] Connection refused\"))")


@pytest.fixture(autouse=True)
def _plain_records():
    # the log record sanitizer app.py installs blanks the session as well, and another
    # test may have installed it in this process: these lines must be clean without it
    before = logging.getLogRecordFactory()
    logging.setLogRecordFactory(logging.LogRecord)
    yield
    logging.setLogRecordFactory(before)


@pytest.fixture
def xapi_calls():
    return []


@pytest.fixture
def pool(caplog, xapi_calls):
    XenAPI = pytest.importorskip('XenAPI')
    answers = {
        'SR.get_by_name_label': lambda name: ['OpaqueRef:sr-iso'],
        'SR.get_type': lambda ref: 'iso',
        'VDI.create': lambda rec: 'OpaqueRef:vdi-new',
        'VDI.get_uuid': lambda ref: 'u1',
        'VDI.destroy': lambda ref: None,
    }

    def _answer(method, params):
        xapi_calls.append((method,) + tuple(params))
        return answers[method](*params)

    # a session of the XenAPI library as connect() leaves it, logged in; its calls are
    # answered here instead of on the wire, the same hook ha_transport.guard_xapi takes
    session = XenAPI.Session('https://xcp.example', ignore_ssl=True)
    session._session = SESSION
    session.xenapi_request = _answer
    x = XcpngManager.__new__(XcpngManager)
    x.id, x.cluster_type = CL, 'xcpng'
    x.config = types.SimpleNamespace(name='pool', host='xcp.example', ssl_verification=False)
    x.current_host = 'xcp.example'
    x.is_connected = True
    x.connection_error = None
    x._session_lock = threading.Lock()
    x._session = session
    x._api = lambda: session.xenapi
    # the per-cluster logger as __init__ builds it: its own handlers, nothing propagates
    x.logger = logging.getLogger('XCPng_pool_session_test')
    x.logger.setLevel(logging.DEBUG)
    x.logger.propagate = False
    x.logger.handlers = [caplog.handler]
    yield x
    x.logger.handlers = []


def test_an_upload_puts_the_file_with_the_pool_session(pool, monkeypatch, xapi_calls):
    sent = []

    def _put(method, url, **kw):
        sent.append((method, url))
        return types.SimpleNamespace(status_code=200)

    monkeypatch.setattr(xcpng_mod.ha_transport, 'http', _put)
    r = pool.upload_to_storage('', 'iso-sr', 'debian.iso', io.BytesIO(b'\0' * 16))

    assert r == {'success': True, 'message': 'debian.iso uploaded'}, r
    # the ref the pool gave at login, not the name of one more proxy method
    # (<XenAPI._Dispatcher for xenapi._session>)
    assert sent == [('PUT', f'https://xcp.example/import_raw_vdi?session_id={ENCODED}&vdi=u1&format=raw')], sent
    assert not [c for c in xapi_calls if c[0] == 'VDI.destroy'], xapi_calls


def test_an_upload_after_the_pool_logged_out_makes_no_vdi(pool, monkeypatch, xapi_calls):
    sent = []

    def _put(method, url, **kw):
        sent.append(url)
        raise requests.exceptions.ConnectionError('no PUT expected here')

    monkeypatch.setattr(xcpng_mod.ha_transport, 'http', _put)
    api = pool._session.xenapi
    # _api() handed out the proxy, then disconnect() ran
    pool._api = lambda: api
    pool._session = None

    r = pool.upload_to_storage('', 'iso-sr', 'debian.iso', io.BytesIO(b'\0' * 16))

    assert r == {'success': False, 'error': 'Not connected'}, r
    assert not sent and not xapi_calls, (sent, xapi_calls)


def test_a_failed_upload_answers_without_the_session(api, seed, pool, monkeypatch, caplog, xapi_calls):
    sent = []

    def _put(method, url, **kw):
        sent.append(url)
        raise _refused(method, url)

    monkeypatch.setattr(xcpng_mod.ha_transport, 'http', _put)
    api.set_manager(CL, pool)
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(f'/api/clusters/{CL}/datastores/iso-sr/upload',
                   data={'content': 'iso', 'file': (io.BytesIO(b'\0' * 16), 'debian.iso')},
                   content_type='multipart/form-data')

    # the url did carry the session, so the error text of requests carried it too
    assert sent and ENCODED in sent[0], sent
    assert r.status_code == 500, r.data[:300]
    error = r.get_json()['error']
    # the operator still learns which call failed, and how
    assert 'import_raw_vdi?session_id=***&vdi=u1&format=raw' in error, error
    assert 'Connection refused' in error
    assert SESSION not in error and ENCODED not in error, error
    assert 'upload_to_storage' in caplog.text
    assert SESSION not in caplog.text and ENCODED not in caplog.text, caplog.text
    # the VDI made for the upload goes again, as it does on an answer that is no 2xx
    assert ('VDI.destroy', 'OpaqueRef:vdi-new') in xapi_calls, xapi_calls


def test_a_chart_read_the_pool_does_not_answer_logs_without_the_session(pool, monkeypatch, caplog):
    asked = []

    def _get(url, params=None, **kw):
        asked.append(params)
        raise _refused('GET', url, params)

    monkeypatch.setattr(requests, 'get', _get)
    legends, rows = pool._rrd_fetch('rrd_updates', {'start': 1762848000, 'cf': 'AVERAGE', 'host': 'false'})

    assert (legends, rows) == (None, None)
    assert asked and asked[0]['session_id'] == SESSION
    line = caplog.text
    assert '_rrd_fetch rrd_updates' in line, line
    assert '/rrd_updates?session_id=***&start=1762848000&cf=AVERAGE&host=false' in line, line
    assert SESSION not in line and ENCODED not in line, line


def test_a_failed_move_to_another_pool_answers_without_its_session(pool, monkeypatch, caplog):
    remote = 'OpaqueRef:9c3e41aa-7d0b-target-pool-login'
    sent = {}

    class _TargetSession:
        def __init__(self, url, ignore_ssl=None):
            self._session = remote
            self.xenapi = types.SimpleNamespace(
                login_with_password=lambda *a: None,
                host=types.SimpleNamespace(get_all=lambda: ['OpaqueRef:host-b']),
                session=types.SimpleNamespace(logout=lambda: None))

    def _migrate_send(vm_ref, dest, live, vdi_map, vif_map, options):
        sent.update(dest)
        # an error text that quotes the map it was given
        raise RuntimeError(f'VM.migrate_send refused {dest!r}')

    monkeypatch.setattr(xcpng_mod, 'XenAPI', types.SimpleNamespace(Session=_TargetSession))
    pool._api = lambda: types.SimpleNamespace(
        VM=types.SimpleNamespace(get_power_state=lambda ref: 'Running'),
        Async=types.SimpleNamespace(VM=types.SimpleNamespace(migrate_send=_migrate_send)))
    pool._resolve_vm = lambda vmid: 'OpaqueRef:vm-101'
    target = XcpngManager.__new__(XcpngManager)
    target.config = types.SimpleNamespace(name='pool-b', host='xcp-b.example', user='root',
                                          pass_='pw', ssl_verification=False)

    r = pool.remote_migrate_vm('xcp1', 101, target_pool=target)

    # the map did carry the session of the other pool
    assert sent.get('session_id') == remote, sent
    assert r['success'] is False
    assert "VM.migrate_send refused {'force': 'true', 'session_id': '***', 'host': 'OpaqueRef:host-b'}" \
        == r['error'], r
    assert 'remote_migrate_vm 101' in caplog.text
    assert remote not in caplog.text, caplog.text
