"""The PBS Jobs tab lists sync jobs that push as well as the ones that pull (#801).

Since PBS 3.3 a sync job has a direction. GET /admin/sync lists only pull jobs unless
sync-direction (all, push or pull, default pull) asks for more, and it leaves the field out
of a job for that default. A PBS before 3.3 knows no direction: its parameter schema has
only `store`, so anything else is refused with a 400 ("schema does not allow additional
properties"), and every job it has pulls. POST /admin/sync/<id>/run looks the job up by id
and runs it in its own direction.

The fake below answers the way both kinds of PBS do, at the HTTP session, so the real
PBSManager request code runs.
"""
import json
import logging
import re
from unittest.mock import MagicMock

import pytest

import pegaprox.core.pbs as corepbs
import pegaprox.globals as ppglobals
from pegaprox.core.pbs import PBSManager

PBS = 'p801'
PULL = {'id': 'pull-offsite', 'store': 'local1', 'remote': 'offsite', 'remote-store': 'archive',
        'schedule': 'daily', 'last-run-state': 'OK', 'next-run': 1780100000}
LOCAL = {'id': 'pull-local', 'store': 'local2', 'remote-store': 'local1'}
PUSH = {'id': 'push-dr', 'store': 'local1', 'remote': 'dr-site', 'remote-store': 'replica',
        'sync-direction': 'push', 'schedule': 'hourly'}
UPID = 'UPID:pbs:000012AB:0000CDEF:00000001:65000000:syncjob:push-dr:root@pam:'


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self):
        if isinstance(self._body, str):
            raise ValueError('no json body')
        return self._body


class _FakePBS:
    """The session PBSManager talks through. Records (path, params) of every GET."""

    def __init__(self, jobs, new=True, status=None):
        self.jobs, self.new, self.status = list(jobs), new, status
        self.headers = {}
        self.cookies = MagicMock()
        self.gets, self.posts = [], []

    @staticmethod
    def _path(url):
        return url.split('/api2/json', 1)[1]

    def get(self, url, params=None, timeout=None, **kw):
        params = dict(params or {})
        path = self._path(url)
        self.gets.append((path, params))
        if self.status:
            return _Resp(self.status, f'HTTP {self.status}')
        if path != '/admin/sync':
            return _Resp(404, 'Path not found.')
        known = {'store', 'sync-direction'} if self.new else {'store'}
        unknown = sorted(set(params) - known)
        if unknown:
            return _Resp(400, f"parameter verification failed - '{unknown[0]}': "
                              "schema does not allow additional properties.")
        want = params.get('sync-direction', 'pull')
        if want not in ('all', 'push', 'pull'):
            return _Resp(400, "parameter verification failed - 'sync-direction': value not in enum")
        rows = [dict(j) for j in self.jobs if want == 'all' or j.get('sync-direction', 'pull') == want]
        return _Resp(200, {'data': rows})

    def post(self, url, json=None, timeout=None, **kw):
        path = self._path(url)
        self.posts.append(path)
        m = re.fullmatch(r'/admin/sync/([^/]+)/run', path)
        if m and any(j['id'] == m.group(1) for j in self.jobs):
            return _Resp(200, {'data': UPID.replace('push-dr', m.group(1))})
        return _Resp(400, {'message': f"no such sync job '{path}'"})


def _mgr(jobs, new=True, status=None):
    m = PBSManager(PBS, {'name': 'pbs801', 'host': '10.0.0.80', 'linked_clusters': ['cluster_1']})
    m._session = _FakePBS(jobs, new=new, status=status)
    return m


def _directions(result):
    return {job['id']: job['sync-direction'] for job in result['data']}


# -- the manager -------------------------------------------------------------------------

def test_a_current_pbs_lists_its_push_jobs_beside_the_pull_jobs():
    m = _mgr([PULL, LOCAL, PUSH])

    result = m.get_sync_jobs()

    assert sorted(j['id'] for j in result['data']) == ['pull-local', 'pull-offsite', 'push-dr']
    assert _directions(result) == {'pull-offsite': 'pull', 'pull-local': 'pull', 'push-dr': 'push'}
    # one read, the schedule and last-run fields stay as PBS sent them
    assert m._session.gets == [('/admin/sync', {'sync-direction': 'all'})]
    assert result['data'][0]['next-run'] == PULL['next-run']


def test_an_older_pbs_that_refuses_the_parameter_still_lists_its_jobs_as_pull():
    m = _mgr([PULL, LOCAL], new=False)

    result = m.get_sync_jobs()

    assert 'error' not in result
    assert _directions(result) == {'pull-offsite': 'pull', 'pull-local': 'pull'}
    assert m._session.gets == [('/admin/sync', {'sync-direction': 'all'}), ('/admin/sync', {})]


def test_the_older_pbs_is_asked_again_after_an_hour_not_on_every_poll(monkeypatch):
    now = [5000.0]
    monkeypatch.setattr(corepbs.time, 'monotonic', lambda: now[0])
    m = _mgr([PULL], new=False)
    m.get_sync_jobs()
    assert len(m._session.gets) == 2

    m._session.gets.clear()
    now[0] += 30
    assert _directions(m.get_sync_jobs()) == {'pull-offsite': 'pull'}
    assert m._session.gets == [('/admin/sync', {})]

    # upgraded to 3.3 in the meantime: within the hour the push job shows up
    m._session.gets.clear()
    m._session.new = True
    m._session.jobs.append(PUSH)
    now[0] += 3600
    assert _directions(m.get_sync_jobs()) == {'pull-offsite': 'pull', 'push-dr': 'push'}
    assert m._session.gets == [('/admin/sync', {'sync-direction': 'all'})]


@pytest.mark.parametrize('status', [403, 500])
def test_a_refusal_that_is_no_parameter_error_is_passed_on(status):
    m = _mgr([PULL, PUSH], status=status)

    result = m.get_sync_jobs()

    assert result.get('status_code') == status
    assert m._session.gets == [('/admin/sync', {'sync-direction': 'all'})]


def test_a_400_on_the_plain_read_too_is_passed_on_and_not_kept():
    m = _mgr([PULL], status=400)

    assert m.get_sync_jobs().get('status_code') == 400
    assert m._session.gets == [('/admin/sync', {'sync-direction': 'all'}), ('/admin/sync', {})]
    m._session.gets.clear()
    m.get_sync_jobs()
    assert m._session.gets[0] == ('/admin/sync', {'sync-direction': 'all'})


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and '/admin/sync' in r.getMessage()]


def test_the_refusal_of_an_older_pbs_is_no_warning_in_the_log(caplog):
    caplog.set_level(logging.DEBUG)
    m = _mgr([PULL], new=False)

    assert _directions(m.get_sync_jobs()) == {'pull-offsite': 'pull'}

    # the probe was sent and refused, it only shows at debug
    assert m._session.gets[0] == ('/admin/sync', {'sync-direction': 'all'})
    assert _warnings(caplog) == []
    assert any('/admin/sync' in r.getMessage() and '400' in r.getMessage()
               for r in caplog.records if r.levelno == logging.DEBUG)


@pytest.mark.parametrize('status', [400, 403, 500])
def test_a_failing_read_of_the_jobs_still_warns(caplog, status):
    caplog.set_level(logging.DEBUG)
    m = _mgr([PULL], status=status)

    m.get_sync_jobs()

    # a 400 on the probe is expected, the plain read after it is not
    assert len(_warnings(caplog)) == 1
    assert str(status) in _warnings(caplog)[0]


# -- the route the Jobs tab reads --------------------------------------------------------

@pytest.fixture
def admin(api, seed):
    yield api.as_user(seed.user('sync801_admin', role='admin'))
    ppglobals.pbs_managers.pop(PBS, None)


def _register(jobs, new=True):
    m = _mgr(jobs, new=new)
    # verify and prune are not what this is about
    m.get_verify_jobs = lambda: {'data': []}
    m.get_prune_jobs = lambda: {'data': []}
    ppglobals.pbs_managers[PBS] = m
    return m


def test_the_jobs_tab_gets_every_sync_job_with_its_direction(admin):
    _register([PULL, LOCAL, PUSH])

    r = admin.get(f'/api/pbs/{PBS}/jobs')

    assert r.status_code == 200
    body = r.get_json()
    assert 'errors' not in body
    assert sorted(j['id'] for j in body['sync']) == ['pull-local', 'pull-offsite', 'push-dr']
    assert _directions({'data': body['sync']}) == {
        'pull-offsite': 'pull', 'pull-local': 'pull', 'push-dr': 'push'}
    push = next(j for j in body['sync'] if j['id'] == 'push-dr')
    assert (push['store'], push['remote'], push['remote-store']) == ('local1', 'dr-site', 'replica')


def test_the_jobs_tab_of_an_older_pbs_shows_no_read_error(admin):
    _register([PULL, LOCAL], new=False)

    body = admin.get(f'/api/pbs/{PBS}/jobs').get_json()

    assert 'errors' not in body
    assert _directions({'data': body['sync']}) == {'pull-offsite': 'pull', 'pull-local': 'pull'}


def test_a_push_job_listed_in_the_tab_can_be_run(admin):
    m = _register([PULL, PUSH])
    listed = admin.get(f'/api/pbs/{PBS}/jobs').get_json()['sync']
    push = [j['id'] for j in listed if j.get('sync-direction') == 'push']
    assert push == ['push-dr']

    r = admin.post(f'/api/pbs/{PBS}/jobs/sync/{push[0]}/run')

    assert r.status_code == 200
    assert r.get_json() == {'data': UPID}
    assert m._session.posts == ['/admin/sync/push-dr/run']
