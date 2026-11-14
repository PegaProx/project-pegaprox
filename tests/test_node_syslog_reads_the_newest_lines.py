"""The node system log shows the newest journal lines, and a slow read is no offline cluster.

GET /api/clusters/<id>/nodes/<node>/syslog read PVE's /nodes/{node}/syslog with only
`limit`. That endpoint runs journalctl over the whole journal and hands back the first
`limit` lines from `start` (PVE::Tools::dump_journal), so the page showed the boot messages
of months ago, after 13 s, and at the default of 500 the read ran into the 15 s timeout and
the route answered 503 "Cluster temporarily unreachable" with offline: true for a cluster
that was fine.

It reads /nodes/{node}/journal with lastentries now, which seeks to the end of the journal
(the PVE web UI reads it the same way). Its first and last entries are the cursors of the
range and are not log lines. A read timeout is a 504 PVE_TIMEOUT. The fake PVE below answers
both endpoints the way PVE does, from one journal of 2000 lines.
"""
import logging
from unittest.mock import MagicMock

import pytest
import requests

import pegaprox.globals as ppglobals

CLUSTER = 'cluster_1'
NODE = 'pve1'
JOURNAL = [f'Nov 12 10:{i // 60:02d}:{i % 60:02d} pve1 systemd[1]: line {i}' for i in range(2000)]


def _cursor(i):
    return f's=6f2a91;i={i:x};b=77c1;m={i:x};t=63f1{i:x};x=9e{i:x}'


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = str(body)

    def json(self):
        return self._body


class _Pve:
    def __init__(self):
        self.calls = []
        self.answer = None      # an exception, or a body for /journal instead of the journal

    def get(self, url, params=None, **kw):
        path = url.split('/api2/json', 1)[1]
        self.calls.append((path, dict(params or {})))
        if isinstance(self.answer, Exception):
            raise self.answer
        if path == f'/nodes/{NODE}/syslog':
            # dump_journal: from the head of the journal, `start` on, `limit` lines (50 without)
            start, limit = int(params.get('start') or 0), int(params.get('limit') or 50)
            return _Resp(200, {'data': [{'n': i + 1, 't': JOURNAL[i]} for i in range(start, min(start + limit, 2000))],
                               'total': 2000})
        if path == f'/nodes/{NODE}/journal':
            if self.answer is not None:
                return _Resp(200, self.answer)
            if params.get('lastentries'):
                first = 2000 - int(params['lastentries'])
            else:
                first = max(0, int(params.get('since') or 0) - 1)    # a line per second, from 1
            return _Resp(200, {'data': [_cursor(first)] + JOURNAL[first:] + [_cursor(1999)], 'success': 1})
        return _Resp(404, {'data': None})


@pytest.fixture
def pve(api):
    from pegaprox.core.manager import PegaProxManager
    fake = _Pve()
    m = api.make_fake_manager(CLUSTER)
    m.is_connected = True
    m.host, m.api_port = 'pve.test', 8006
    m.logger = logging.getLogger('test.syslog')
    session = MagicMock()
    session.get = fake.get
    m._create_session = lambda: session
    m.get_node_syslog = PegaProxManager.get_node_syslog.__get__(m, PegaProxManager)
    api.set_manager(CLUSTER, m)
    return fake


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


def _syslog(admin, query=''):
    return admin.get(f'/api/clusters/{CLUSTER}/nodes/{NODE}/syslog{query}')


def test_the_ui_read_gets_the_newest_hundred_lines_newest_first(admin, pve):
    r = _syslog(admin, '?limit=100')
    assert r.status_code == 200, r.get_data(as_text=True)
    lines = r.get_json()
    assert lines == list(reversed(JOURNAL[-100:]))
    assert lines[0].endswith('line 1999')
    assert pve.calls == [(f'/nodes/{NODE}/journal', {'lastentries': 100})]


def test_the_default_read_asks_for_the_last_500(admin, pve):
    lines = _syslog(admin).get_json()
    assert len(lines) == 500 and lines[0].endswith('line 1999') and lines[-1].endswith('line 1500')
    assert pve.calls[-1] == (f'/nodes/{NODE}/journal', {'lastentries': 500})


def test_the_cursors_are_no_log_lines(admin, pve):
    lines = _syslog(admin, '?limit=3').get_json()
    assert not any(line.startswith('s=') for line in lines)
    # a body without cursors keeps every line it has
    pve.answer = {'data': ['one', '-- Reboot --', 'two'], 'success': 1}
    assert _syslog(admin, '?limit=3').get_json() == ['two', '-- Reboot --', 'one']


def test_since_reads_from_that_time_and_keeps_the_newest(pve):
    # since and lastentries exclude each other in PVE: since alone, then the newest `limit`
    lines = ppglobals.cluster_managers[CLUSTER].get_node_syslog(NODE, limit=10, since=1990)
    assert pve.calls == [(f'/nodes/{NODE}/journal', {'since': 1990})]
    assert lines == list(reversed(JOURNAL[-10:]))


def test_a_read_timeout_is_a_504_not_offline(admin, pve):
    pve.answer = requests.exceptions.ReadTimeout('Read timed out. (read timeout=15)')
    r = _syslog(admin)
    assert r.status_code == 504, r.get_data(as_text=True)
    body = r.get_json()
    assert body['code'] == 'PVE_TIMEOUT' and body['timeout'] is True
    assert 'offline' not in body
    assert 'took too long' in body['error'] and f'node {NODE}' in body['error']


def test_no_connection_at_all_is_still_offline(admin, pve):
    pve.answer = requests.exceptions.ConnectTimeout('timed out')
    r = _syslog(admin)
    assert r.status_code == 503
    assert (r.get_json()['code'], r.get_json()['offline']) == ('PVE_UNREACHABLE', True)


def test_a_reader_that_stopped_part_way_is_a_failed_read(admin, pve):
    pve.answer = {'data': [_cursor(1)], 'error': 'Failed to seek to end/cursor: Bad message', 'success': 0}
    r = _syslog(admin)
    assert r.status_code == 502, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'PVE_READ_FAILED'
    assert 'Failed to seek' in r.get_json()['error']
