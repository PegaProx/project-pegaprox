"""The runs of a backup job, with the guests of each run and their logs.

GET /api/clusters/<cid>/datacenter/backup/<job>/runs reads the vzdump tasks of the nodes and
keeps those whose first log line selects what the job selects and writes where it writes.
.../runs/guests reads the logs of one run, .../runs/log the lines of one guest. Proxmox is
faked at the HTTP level: the job, the task list of each node and the task logs.

MK Oct 2026
"""
import re
import time

import pytest

from test_ha_api import ha_env, _standby_of_active  # noqa: F401 (ha_env is a fixture)

from pegaprox.core import backup_runs as runs

CID = 'cluster_1'
T0 = int(time.time()) - 3 * 3600
DAY = 86400

JOB_ALL = {'id': 'backup-all', 'type': 'vzdump', 'all': 1, 'storage': 'pbs', 'mode': 'snapshot',
           'schedule': '21:00', 'enabled': 1}
JOB_VMS = {'id': 'backup-vms', 'type': 'vzdump', 'vmid': '100,101', 'storage': 'local', 'mode': 'snapshot',
           'schedule': 'sat 02:00', 'enabled': 1}
JOB_POOL = {'id': 'backup-pool', 'type': 'vzdump', 'pool': 'web', 'storage': 'pbs', 'schedule': '03:00'}


def _upid(node, start, vmid='', user='root@pam', pid=1):
    return f'UPID:{node}:{pid:08X}:00000001:{start:08X}:vzdump:{vmid}:{user}:'


def _guest_lines(vmid, kind='qemu', ok=True, size='1.20GB'):
    out = [f'INFO: Starting Backup of VM {vmid} ({kind})',
           'INFO: Backup started at 2026-10-06 21:00:01',
           'INFO: status = running',
           f"INFO: creating vzdump archive '/mnt/pve/local/dump/vzdump-{kind}-{vmid}-2026_10_06-21_00_01.vma.zst'"]
    if ok:
        out += [f'INFO: archive file size: {size}', f'INFO: Finished Backup of VM {vmid} (00:01:23)',
                'INFO: Backup finished at 2026-10-06 21:01:24']
    else:
        out += [f'ERROR: Backup of VM {vmid} failed - unable to open file - No space left on device',
                'INFO: Failed at 2026-10-06 21:00:09']
    return out


class _Resp:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data
        self.text = ''

    def json(self):
        return {'data': self._data}


class _Pve:
    """Proxmox as the history reads it: /cluster/backup/<id>, /nodes/<n>/tasks, the task logs"""

    def __init__(self, api, jobs=(JOB_ALL, JOB_VMS, JOB_POOL), nodes=None, cluster_id=CID):
        self.jobs = {j['id']: dict(j) for j in jobs}
        self.tasks = {}       # node -> [task]
        self.logs = {}        # upid -> [lines]
        self.reads = []
        self.down = set()     # nodes whose answers fail
        m = api.make_fake_manager(cluster_id)
        m.is_connected = True
        m.host, m.api_port = '192.0.2.10', 8006
        m.config.name = cluster_id
        m.get_node_status.return_value = nodes or {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'},
                                                   'pve3': {'status': 'offline', 'offline': True}}
        m._api_get.side_effect = self.get
        self.mgr = api.set_manager(cluster_id, m)

    def task(self, node, start, header, guests=(), status='OK', end=True, vmid='', user='root@pam', extra=()):
        upid = _upid(node, start, vmid, user, pid=len(self.logs) + 1)
        lines = ['INFO: starting new backup job: ' + header] if header else ['TASK ERROR: lock wait timeout']
        for g in guests:
            lines += g
        lines += list(extra)
        if end and header:
            lines += ['INFO: Backup job finished ' + ('successfully' if status == 'OK' else 'with errors'),
                      'TASK OK' if status == 'OK' else f'TASK ERROR: {status}']
        self.logs[upid] = lines
        t = {'upid': upid, 'node': node, 'starttime': start, 'type': 'vzdump', 'id': vmid, 'user': user}
        if end:
            t.update(endtime=start + 90, status=status)
        self.tasks.setdefault(node, []).append(t)
        return upid

    def log_reads(self):
        return [p for p, _ in self.reads if p.endswith('/log')]

    def get(self, url, params=None, timeout=None, **kw):
        path = url.split('/api2/json', 1)[1]
        params = dict(params or {})
        self.reads.append((path, params))
        if path == '/cluster/backup':
            return _Resp(200, [dict(j) for j in self.jobs.values()])
        m = re.fullmatch(r'/cluster/backup/([^/]+)', path)
        if m:
            job = self.jobs.get(m.group(1))
            return _Resp(200, dict(job)) if job else _Resp(500, None)
        m = re.fullmatch(r'/nodes/([^/]+)/tasks', path)
        if m:
            if m.group(1) in self.down:
                return _Resp(595, None)
            assert params['typefilter'] == 'vzdump' and params['source'] == 'all'
            got = [t for t in self.tasks.get(m.group(1), []) if t['starttime'] >= params['since']]
            return _Resp(200, sorted(got, key=lambda t: -t['starttime'])[:params['limit']])
        m = re.fullmatch(r'/nodes/([^/]+)/tasks/(.+)/log', path)
        if m:
            if m.group(1) in self.down or m.group(2) not in self.logs:
                return _Resp(500, None)
            lines = self.logs[m.group(2)]
            start, limit = int(params['start']), int(params['limit'])
            return _Resp(200, [{'n': i + 1, 't': lines[i]} for i in range(start, min(len(lines), start + limit))])
        return _Resp(404, None)


@pytest.fixture(autouse=True)
def fresh():
    runs.reset_for_tests()
    yield
    runs.reset_for_tests()


ALL_HEAD = "vzdump --all 1 --storage pbs --mode snapshot --quiet 1 --notes-template '{{guestname}}'"
VMS_HEAD = 'vzdump 100 101 --storage local --mode snapshot --quiet 1'


def _cluster(api):
    """Two runs of the all-guests job on two nodes, one that failed a day before, a run of
    the vmid job, a manual one-guest backup, and a task that never got to a command line"""
    pve = _Pve(api)
    pve.task('pve1', T0, ALL_HEAD, [_guest_lines(100), _guest_lines(101, ok=False)], status='job errors')
    pve.task('pve2', T0 + 4, ALL_HEAD, [_guest_lines(200, 'lxc')])
    pve.task('pve1', T0 - DAY, ALL_HEAD, [_guest_lines(100)])
    pve.task('pve2', T0 - DAY + 2, ALL_HEAD, [_guest_lines(200, 'lxc')])
    pve.task('pve1', T0 - 2 * 3600, VMS_HEAD, [_guest_lines(100), _guest_lines(101)])
    pve.task('pve1', T0 - 3600, 'vzdump 100 --storage local --mode snapshot', [_guest_lines(100)],
             vmid='100', user='ops@pve')
    pve.task('pve2', T0 - 1800, None)
    return pve


def _admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _runs(client, job='backup-all', **q):
    qs = '&'.join(f'{k}={v}' for k, v in q.items())
    return client.get(f'/api/clusters/{CID}/datacenter/backup/{job}/runs' + (f'?{qs}' if qs else ''))


# --- the runs --------------------------------------------------------------------------------

def test_the_runs_of_a_cluster_wide_job_are_its_tasks_on_every_node(api, seed):
    pve = _cluster(api)
    r = _runs(_admin(api, seed))
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['partial'] is False and body['unread_nodes'] == ['pve3'] and body['days'] == 14
    got = [(x['start'], x['state'], sorted(t['node'] for t in x['tasks'])) for x in body['runs']]
    assert got == [(T0, 'failed', ['pve1', 'pve2']), (T0 - DAY, 'ok', ['pve1', 'pve2'])]
    newest = body['runs'][0]
    assert newest['end'] == T0 + 4 + 90 and newest['duration'] == 94 and newest['failed_tasks'] == 1
    assert newest['scheduled'] is True and newest['started_by'] == ''
    # the offline node is not asked at all
    assert not [p for p, _ in pve.reads if '/nodes/pve3/' in p]


def test_a_job_with_guests_named_keeps_only_its_own_runs(api, seed):
    pve = _cluster(api)
    body = _runs(_admin(api, seed), job='backup-vms').get_json()
    assert [(x['start'], x['state'], len(x['tasks'])) for x in body['runs']] == [(T0 - 2 * 3600, 'ok', 1)]
    # the one-guest task names guest 100 in the list: a candidate, read and left out (other
    # options); the all-guests tasks are read as well, nothing here tells them apart
    assert body['runs'][0]['tasks'][0]['node'] == 'pve1'
    # the pve2 task that never got to a command line is read as well, once
    assert len(pve.log_reads()) == 7


def test_a_task_that_backs_up_a_guest_outside_the_job_is_not_even_read(api, seed):
    pve = _Pve(api)
    pve.task('pve1', T0, 'vzdump 300 --storage local', [_guest_lines(300)], vmid='300')
    body = _runs(_admin(api, seed), job='backup-vms').get_json()
    assert body['runs'] == [] and pve.log_reads() == []


def test_a_manual_run_says_who_started_it(api, seed):
    from pegaprox.api.helpers import register_task_user
    pve = _Pve(api)
    upid = pve.task('pve1', T0, 'vzdump 100 101 --storage local --mode snapshot', [_guest_lines(100)],
                    user='pegaprox@pve')
    register_task_user(upid, 'alice', CID)
    run = _runs(_admin(api, seed), job='backup-vms').get_json()['runs'][0]
    assert run['scheduled'] is False and run['started_by'] == 'alice'


def test_a_run_still_going_is_running(api, seed):
    pve = _Pve(api)
    pve.task('pve1', T0, ALL_HEAD, [_guest_lines(100)])
    pve.task('pve2', T0 + 1, ALL_HEAD, [['INFO: Starting Backup of VM 200 (lxc)']], end=False)
    run = _runs(_admin(api, seed)).get_json()['runs'][0]
    assert run['state'] == 'running' and run['end'] is None and run['duration'] is None


def test_the_first_lines_are_read_once(api, seed):
    pve = _cluster(api)
    c = _admin(api, seed)
    first = _runs(c).get_json()
    reads = len(pve.log_reads())
    runs._lists.clear()
    assert _runs(c).get_json()['runs'] == first['runs']
    assert len(pve.log_reads()) == reads


def test_a_budget_spent_says_partial_and_the_next_call_goes_on(api, seed, monkeypatch):
    monkeypatch.setattr(runs, 'HEADER_BUDGET', 3)
    pve = _cluster(api)
    c = _admin(api, seed)
    first = _runs(c).get_json()
    assert first['partial'] is True and len(pve.log_reads()) == 3
    for _ in range(3):
        body = _runs(c).get_json()
    assert body['partial'] is False and [x['start'] for x in body['runs']] == [T0, T0 - DAY]


def test_limit_and_days_bound_what_is_read(api, seed):
    pve = _cluster(api)
    c = _admin(api, seed)
    body = _runs(c, limit=1).get_json()
    assert [x['start'] for x in body['runs']] == [T0] and body['limit'] == 1
    body = _runs(c, days=99999, limit=-5).get_json()
    assert body['days'] == runs.DAYS_MAX and body['limit'] == runs.RUNS_DEFAULT
    since = [p['since'] for path, p in pve.reads if path.endswith('/tasks')]
    assert since and all(s >= int(time.time()) - runs.DAYS_MAX * DAY - 5 for s in since)


def test_a_node_that_does_not_answer_is_named(api, seed):
    pve = _cluster(api)
    pve.down.add('pve2')
    body = _runs(_admin(api, seed)).get_json()
    assert body['unread_nodes'] == ['pve2', 'pve3']
    assert [len(x['tasks']) for x in body['runs']] == [1, 1]


def test_a_job_on_one_node_asks_that_node_only(api, seed):
    pve = _Pve(api, jobs=[dict(JOB_VMS, node='pve2')])
    pve.task('pve2', T0, VMS_HEAD + ' --node pve2', [_guest_lines(100)])
    body = _runs(_admin(api, seed), job='backup-vms').get_json()
    assert len(body['runs']) == 1
    assert {p.split('/')[2] for p, _ in pve.reads if p.startswith('/nodes/')} == {'pve2'}


def test_an_unknown_job_and_a_job_id_out_of_shape(api, seed):
    _cluster(api)
    c = _admin(api, seed)
    assert _runs(c, job='backup-nope').status_code == 404
    assert c.get(f'/api/clusters/{CID}/datacenter/backup/..%2F..%2Fnodes/runs').status_code == 404


def test_a_run_that_failed_before_its_command_line_is_the_jobs_failed_run(api, seed):
    """The storage could not be activated: the task logs only that, and the run was nobody's."""
    pve = _Pve(api)
    early = ["ERROR: could not activate storage 'local', local: error fetching datastores - "
             "500 Can't connect to 192.0.2.20:8007 (No route to host)"]
    pve.task('pve1', T0, None, extra=early, status="could not activate storage 'local'", vmid='100')
    body = _runs(_admin(api, seed), job='backup-vms').get_json()
    assert [(x['start'], x['state']) for x in body['runs']] == [(T0, 'failed')]
    assert _last(_admin(api, seed)).get_json()['jobs']['backup-vms']['state'] == 'failed'
    # read once: a second look takes it from what was kept
    reads = len(pve.log_reads())
    runs._lists.clear()
    _runs(_admin(api, seed), job='backup-vms')
    assert len(pve.log_reads()) == reads


def test_an_early_failure_on_another_storage_or_guest_is_not_the_jobs(api, seed):
    pve = _Pve(api)
    pve.task('pve1', T0, None, extra=["ERROR: could not activate storage 'nas2', nas2: timeout"],
             status="could not activate storage 'nas2'", vmid='100')
    pve.task('pve1', T0 + 300, None, extra=["ERROR: could not activate storage 'local', local: gone"],
             status="could not activate storage 'local'", vmid='300')
    assert _runs(_admin(api, seed), job='backup-vms').get_json()['runs'] == []
    # an all-guests job on that storage takes the one that names no guest outside it
    pve.task('pve2', T0 + 600, None, extra=["ERROR: could not activate storage 'pbs', pbs: gone"],
             status="could not activate storage 'pbs'")
    runs._lists.clear()
    got = _runs(_admin(api, seed)).get_json()['runs']
    assert [(x['start'], x['state']) for x in got] == [(T0 + 600, 'failed')]


# --- who sees them ---------------------------------------------------------------------------

def _scoped(api, seed, vmids):
    seed.tenant('acme', clusters=['cluster_9'])
    u = seed.user('bob', role='user', tenant_id='acme')
    for v in vmids:
        seed.vm_acl(CID, v, ['bob'])
    return api.as_user(u)


def test_a_caller_without_backup_view_reads_nothing(api, seed):
    pve = _cluster(api)
    c = api.as_user(seed.user('ops', role='user', denied=['backup.view']))
    for path in ('runs', 'runs/guests?upid=x', 'runs/log?upid=x'):
        assert c.get(f'/api/clusters/{CID}/datacenter/backup/backup-all/{path}').status_code == 403
    assert pve.reads == []


def test_a_confined_admin_and_another_tenant_reach_nothing(api, seed):
    seed.tenant('globex', clusters=['cluster_2'])
    pve = _cluster(api)
    confined = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                     tenant_permissions={'globex': {'role': 'user'}}))
    other = api.as_user(seed.user('milton', role='user', tenant_id='globex'))
    for c in (confined, other):
        assert _runs(c).status_code == 403
        assert _runs(c, job='backup-vms').status_code == 403
    assert pve.reads == []


def test_a_scoped_caller_sees_the_runs_of_the_jobs_the_job_list_shows_them(api, seed):
    _cluster(api)
    c = _scoped(api, seed, [100, 101])
    assert _runs(c).status_code == 404               # every guest: not theirs to see
    assert _runs(c, job='backup-pool').status_code == 404
    r = _runs(c, job='backup-vms')
    assert r.status_code == 200 and len(r.get_json()['runs']) == 1


def test_a_scoped_caller_does_not_see_a_job_that_names_a_guest_beyond_them(api, seed):
    _cluster(api)
    c = _scoped(api, seed, [100])
    assert _runs(c, job='backup-vms').status_code == 404


def test_a_standby_still_reads_them(ha_env, seed):  # noqa: F811
    api = ha_env.api
    _cluster(api)
    _standby_of_active(ha_env)
    c = api.as_user(seed.user('root', role='admin'))
    assert _runs(c).status_code == 200


# --- the guests of a run ---------------------------------------------------------------------

def _guests(client, upids, job='backup-all'):
    qs = '&'.join(f'upid={u}' for u in upids)
    return client.get(f'/api/clusters/{CID}/datacenter/backup/{job}/runs/guests?{qs}')


def test_the_guests_of_a_run_come_from_its_logs(api, seed):
    _cluster(api)
    c = _admin(api, seed)
    run = _runs(c).get_json()['runs'][0]
    r = _guests(c, [t['upid'] for t in run['tasks']])
    assert r.status_code == 200, r.data
    body = r.get_json()
    by = {g['vmid']: g for g in body['guests']}
    assert sorted(by) == [100, 101, 200]
    assert (by[100]['state'], by[100]['took'], by[100]['size'], by[100]['node']) == ('ok', '00:01:23', '1.20GB', 'pve1')
    assert by[100]['archive'] == 'vzdump-qemu-100-2026_10_06-21_00_01.vma.zst'
    assert by[100]['started'] == '2026-10-06 21:00:01' and by[100]['ended'] == '2026-10-06 21:01:24'
    assert by[101]['state'] == 'failed' and 'No space left on device' in by[101]['error']
    assert by[101]['ended'] == '2026-10-06 21:00:09'
    assert (by[200]['type'], by[200]['node']) == ('lxc', 'pve2')
    assert sorted((t['node'], t['status']) for t in body['tasks']) == [('pve1', 'job errors'), ('pve2', 'OK')]
    assert body['missing'] == []


def test_a_guest_the_job_names_and_no_task_backed_up_is_missing(api, seed):
    pve = _Pve(api)
    upid = pve.task('pve1', T0, VMS_HEAD, [_guest_lines(100)])
    body = _guests(_admin(api, seed), [upid], job='backup-vms').get_json()
    assert [g['vmid'] for g in body['guests']] == [100] and body['missing'] == [101]


def test_a_task_of_another_job_or_out_of_shape_is_refused(api, seed):
    pve = _cluster(api)
    c = _admin(api, seed)
    vms_task = next(t['upid'] for t in pve.tasks['pve1'] if pve.logs[t['upid']][0].endswith(VMS_HEAD))
    assert _guests(c, [vms_task]).status_code == 404
    for bad in ('UPID:pve1:1:1:1:qmigrate:100:root@pam:', 'UPID:../x:1:1:1:vzdump::root@pam:', 'nope'):
        assert _guests(c, [bad]).status_code == 404, bad
    assert _guests(c, []).status_code == 400
    assert _guests(c, [_upid('pve1', T0 + i) for i in range(runs_max() + 1)]).status_code == 400


def runs_max():
    from pegaprox.api.storage import RUN_TASKS_MAX
    return RUN_TASKS_MAX


def test_a_log_that_cannot_be_read_says_so(api, seed):
    pve = _cluster(api)
    c = _admin(api, seed)
    run = _runs(c).get_json()['runs'][0]
    pve.down.add('pve2')
    body = _guests(c, [t['upid'] for t in run['tasks']]).get_json()
    assert {t['node']: t['readable'] for t in body['tasks']} == {'pve1': True, 'pve2': False}
    assert sorted(g['vmid'] for g in body['guests']) == [100, 101]


def test_a_finished_task_is_parsed_once(api, seed):
    pve = _cluster(api)
    c = _admin(api, seed)
    upids = [t['upid'] for t in _runs(c).get_json()['runs'][0]['tasks']]
    _guests(c, upids)
    before = len(pve.log_reads())
    _guests(c, upids)
    assert len(pve.log_reads()) == before


def test_a_guest_beyond_the_caller_in_a_log_stays_hidden(api, seed):
    """A task of their job names their guests only - unless its log says otherwise; then what
    it says about another guest is not handed out, neither the row nor its lines"""
    pve = _Pve(api)
    upid = pve.task('pve1', T0, VMS_HEAD, [_guest_lines(100), _guest_lines(300)])
    c = _scoped(api, seed, [100, 101])
    assert [g['vmid'] for g in _guests(c, [upid], job='backup-vms').get_json()['guests']] == [100]
    assert _log(c, upid, job='backup-vms', vmid=300).status_code == 404
    admin = _admin(api, seed)
    assert [g['vmid'] for g in _guests(admin, [upid], job='backup-vms').get_json()['guests']] == [100, 300]
    assert _log(admin, upid, job='backup-vms', vmid=300).status_code == 200


def test_a_scoped_caller_gets_the_guests_of_their_job(api, seed):
    pve = _cluster(api)
    c = _scoped(api, seed, [100, 101])
    upid = next(t['upid'] for t in pve.tasks['pve1'] if pve.logs[t['upid']][0].endswith(VMS_HEAD))
    body = _guests(c, [upid], job='backup-vms').get_json()
    assert [g['vmid'] for g in body['guests']] == [100, 101]
    # the job they cannot see answers as unknown, whatever task they name
    assert _guests(c, [upid]).status_code == 404


# --- the log of a guest ----------------------------------------------------------------------

def _log(client, upid, job='backup-all', **q):
    qs = '&'.join(f'{k}={v}' for k, v in q.items())
    return client.get(f'/api/clusters/{CID}/datacenter/backup/{job}/runs/log?upid={upid}' + (f'&{qs}' if qs else ''))


def test_the_log_of_one_guest_is_its_lines(api, seed):
    pve = _cluster(api)
    c = _admin(api, seed)
    upid = next(t['upid'] for t in _runs(c).get_json()['runs'][0]['tasks'] if t['node'] == 'pve1')
    body = _log(c, upid, vmid=101).get_json()
    assert body['lines'][0] == 'INFO: Starting Backup of VM 101 (qemu)'
    assert body['lines'][-1] == 'INFO: Failed at 2026-10-06 21:00:09'
    assert not any('VM 100' in x for x in body['lines'])
    whole = _log(c, upid).get_json()
    assert whole['lines'] == pve.logs[upid] and whole['more'] is False
    page = _log(c, upid, start=2, limit=3).get_json()
    assert page['lines'] == pve.logs[upid][2:5] and page['start'] == 2 and page['more'] is True
    assert _log(c, upid, vmid=999).status_code == 404
    assert _log(c, upid, vmid='abc').status_code == 400
    assert _log(c, upid, start='x').status_code == 400
    assert c.get(f'/api/clusters/{CID}/datacenter/backup/backup-all/runs/log').status_code == 400


def test_a_scoped_caller_names_the_guest(api, seed):
    pve = _cluster(api)
    c = _scoped(api, seed, [100, 101])
    upid = next(t['upid'] for t in pve.tasks['pve1'] if pve.logs[t['upid']][0].endswith(VMS_HEAD))
    assert _log(c, upid, job='backup-vms').status_code == 403
    body = _log(c, upid, job='backup-vms', vmid=100).get_json()
    assert body['lines'][0] == 'INFO: Starting Backup of VM 100 (qemu)'


# --- the pieces ------------------------------------------------------------------------------

def test_the_command_line_as_vzdump_logs_it():
    opts = runs.parse_command("INFO: starting new backup job: vzdump 100 101 --mode snapshot "
                              "--notes-template '{{guestname}} - nightly' --storage local --quiet 1 "
                              "--prune-backups 'keep-daily=7,keep-weekly=4'")
    assert opts == {'vmid': '100,101', 'mode': 'snapshot', 'notes-template': '{{guestname}} - nightly',
                    'storage': 'local', 'quiet': '1', 'prune-backups': 'keep-daily=7,keep-weekly=4'}
    assert runs.parse_command('INFO: Starting Backup of VM 100 (qemu)') is None
    assert runs.parse_command("INFO: starting new backup job: vzdump --pool 'unclosed") is None
    assert runs.parse_command('INFO: starting new backup job: rm -rf /') is None


@pytest.mark.parametrize('job,opts,same', [
    ({'all': 1, 'storage': 'pbs'}, {'all': '1', 'storage': 'pbs', 'vmid': ''}, True),
    ({'all': 1, 'storage': 'pbs'}, {'all': '1', 'storage': 'local', 'vmid': ''}, False),
    ({'all': 1, 'exclude': '100,101', 'storage': 'pbs'}, {'all': '1', 'exclude': '101,100', 'storage': 'pbs'}, True),
    ({'all': 1, 'exclude': '100', 'storage': 'pbs'}, {'all': '1', 'storage': 'pbs'}, False),
    ({'vmid': '100,101', 'storage': 'l'}, {'vmid': '101,100', 'storage': 'l'}, True),
    ({'vmid': '100,101', 'storage': 'l'}, {'vmid': '100', 'storage': 'l'}, False),
    ({'pool': 'web', 'storage': 'l'}, {'pool': 'web', 'storage': 'l', 'vmid': ''}, True),
    ({'pool': 'web', 'storage': 'l'}, {'pool': 'db', 'storage': 'l'}, False),
    ({'storage': 'l'}, {'storage': 'l', 'vmid': ''}, False),          # selects nothing
    ({'all': 1, 'storage': 'pbs'}, None, False),
])
def test_what_belongs_to_a_job(job, opts, same):
    assert runs.belongs(job, opts) is same


def test_tasks_of_one_run_and_of_the_next():
    def t(node, start, status='OK', end=True):
        return {'upid': f'U{node}{start}', 'node': node, 'start': start, 'end': start + 10 if end else None,
                'status': status if end else '', 'user': 'root@pam', 'scheduled': True}
    # a node twice starts the next run; a task too long after the first one does as well
    got = runs.group([t('a', 1000), t('b', 1030, 'WARNINGS: 1'), t('a', 1060), t('c', 5000, end=False),
                      t('b', 1100, 'job errors'), t('c', 1060 + runs.GROUP_SECONDS + 1)])
    assert [(r['start'], r['state'], [x['node'] for x in r['tasks']]) for r in got] == [
        (5000, 'running', ['c']), (1181, 'ok', ['c']), (1060, 'failed', ['a', 'b']),
        (1000, 'warning', ['a', 'b'])]
    assert got[2]['failed_tasks'] == 1 and got[3]['end'] == 1040 and got[3]['duration'] == 40


# --- the newest run of every job, for the job list -------------------------------------------

def _last(client):
    return client.get(f'/api/clusters/{CID}/datacenter/backup/last-runs')


def test_the_last_run_of_every_job(api, seed):
    pve = _cluster(api)
    r = _last(_admin(api, seed))
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['jobs'] == {'backup-all': {'state': 'failed', 'start': T0, 'end': T0 + 4 + 90},
                            'backup-vms': {'state': 'ok', 'start': T0 - 2 * 3600, 'end': T0 - 2 * 3600 + 90},
                            'backup-pool': None}
    assert body['partial'] is False and body['unread_nodes'] == ['pve3']
    # the jobs share the reads: every first line once
    assert len(pve.log_reads()) == len(set(pve.log_reads()))


def test_the_last_runs_show_a_scoped_caller_their_jobs_only(api, seed):
    _cluster(api)
    assert _last(_scoped(api, seed, [100, 101])).get_json()['jobs'] == {
        'backup-vms': {'state': 'ok', 'start': T0 - 2 * 3600, 'end': T0 - 2 * 3600 + 90}}


def test_the_last_runs_are_no_ones_without_backup_view_or_the_cluster(api, seed):
    seed.tenant('globex', clusters=['cluster_2'])
    pve = _cluster(api)
    for c in (api.as_user(seed.user('ops', role='user', denied=['backup.view'])),
              api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                    tenant_permissions={'globex': {'role': 'user'}})),
              api.as_user(seed.user('milton', role='user', tenant_id='globex'))):
        assert _last(c).status_code == 403
    assert pve.reads == []
