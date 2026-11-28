"""The whole log of an ESXi migration, kept past a restart, and a registry that stays small (#1278).

The UI got the last 20 lines of a run, a restart lost the run with its log, and the registry
in api/vmware.py kept every run of the process and handed all of them out on each poll of the
list. Here:

* the log keeps every line up to 20000; past that the head and the newest lines stay with one
  line in between, counted so a read from line n means the same in memory and in the table
* GET /api/vmware/migrations/<mid>/log reads it from an offset, or as a file to download
* a run is written when its job starts, in batches while it runs, and when it returns; a run
  a stop of PegaProx cut off reads as interrupted afterwards
* a finished run leaves the registry a while after it was written, and the list answers the
  runs of the process plus a page of the stored ones
* a stored run and its log are shown to whoever saw the live one, and to nobody else

MK Nov 2026
"""
import datetime
import json
import threading
import time
import types

import pytest

import pegaprox.globals as ppglobals
from pegaprox.core import v2p_history as hist
from pegaprox.core.v2p import V2PMigrationTask
from pegaprox.core.vmware import VMwareManager

PW = 'Sup3r$ecret/pw'


def _task(mid='m1', vmware_id='esx-a', vm_id='vm-1', cluster='cluster_a', name='web01', **cfg):
    return V2PMigrationTask(mid, vmware_id, vm_id, cluster, 'pve1', 'local-lvm', name,
                            {'esxi_host': '10.0.0.5', **cfg})


def _fill(task, n, start=0):
    """n numbered lines the quick way: what log() does, without its clock and its stream"""
    for i in range(start, start + n):
        task.log_lines.append(f'line {i}')
        hist.note_line(task)


def _rows(db, table):
    return [dict(r) for r in db.conn.execute(f'SELECT * FROM {table}').fetchall()]


@pytest.fixture
def quiet(monkeypatch):
    """log() without the SSE stream"""
    import pegaprox.core.v2p as v2p
    monkeypatch.setattr(v2p, 'broadcast_sse', lambda *a, **k: None)


# -- the cap ----------------------------------------------------------------------------------

def test_a_long_log_keeps_its_head_and_its_newest_lines_with_a_line_between(db, quiet):
    t = _task()
    for i in range(25000):
        t.log(f'step {i}')
    assert hist.total_lines(t) == 25000
    kept = len(t.log_lines) - 1
    assert hist.LOG_MAX_LINES - hist.LOG_CHUNK < kept <= hist.LOG_MAX_LINES
    assert t.log_lines[0].endswith('step 0') and t.log_lines[1999].endswith('step 1999')
    assert t.log_lines[2000] == hist.left_out_line(t.log_dropped)
    assert t.log_lines[-1].endswith('step 24999')
    # the kept tail starts on a chunk of the table, right after what was left out
    assert t.log_dropped % hist.LOG_CHUNK == 0
    assert t.log_lines[2001].endswith(f'step {2000 + t.log_dropped}')
    # the last 20 lines of to_dict are the newest ones, the marker is not among them
    assert t.to_dict()['log'][-1].endswith('step 24999')


def test_a_log_under_the_cap_is_left_alone(db):
    t = _task()
    _fill(t, hist.LOG_MAX_LINES)
    assert len(t.log_lines) == hist.LOG_MAX_LINES and not getattr(t, 'log_dropped', 0)


def test_a_line_of_a_whole_page_is_cut(db, quiet):
    t = _task()
    t.log('x' * 10000)
    assert len(t.log_lines[-1]) < hist.LINE_MAX_CHARS + 60
    assert t.log_lines[-1].endswith('more characters)')


# -- reading from an offset -------------------------------------------------------------------

def test_reads_from_an_offset_hand_out_each_line_once(db):
    t = _task()
    _fill(t, 30)
    got, offset = [], 0
    while True:
        r = hist.read_live(t, offset, 7)
        got += r['lines']
        if r['next'] == offset:
            break
        offset = r['next']
    assert got == [f'line {i}' for i in range(30)]
    assert hist.read_live(t, 30)['lines'] == [] and hist.read_live(t, 99)['next'] == 99


def test_a_read_across_what_was_left_out_says_so_once(db):
    t = _task()
    _fill(t, 25000)
    tail_start = hist.LOG_HEAD_LINES + t.log_dropped
    r = hist.read_live(t, 1990, 20)
    assert r['lines'][:10] == [f'line {i}' for i in range(1990, 2000)]
    assert r['lines'][10] == hist.left_out_line(t.log_dropped)
    assert r['lines'][11:] == [f'line {i}' for i in range(tail_start, tail_start + 9)]
    assert r['next'] == tail_start + 9 and r['total'] == 25000
    # from inside the gap: what is missing from there, then the tail
    inside = hist.read_live(t, tail_start - 10, 3)
    assert inside['lines'] == [hist.left_out_line(10), f'line {tail_start}', f'line {tail_start + 1}']
    whole = hist.whole_live(t)
    assert len(whole) == len(t.log_lines) and whole[-1] == 'line 24999'


# -- the table --------------------------------------------------------------------------------

def test_a_run_is_written_at_its_start_in_batches_and_at_its_end(db, monkeypatch):
    t = _task()
    saves = []
    real = hist._save
    monkeypatch.setattr(hist, '_save', lambda task: (saves.append(hist.total_lines(task)), real(task)))
    hist.track(t)
    assert saves == [0]
    row = hist.load('m1')
    assert row['status'] == 'running' and row['vm_name'] == 'web01' and row['target_cluster'] == 'cluster_a'
    _fill(t, 450)
    # by count, never per line
    assert saves == [0, 200, 400]
    # and by time: a line after FLUSH_SECONDS writes what waited
    t._hist['at'] -= hist.FLUSH_SECONDS + 1
    _fill(t, 1, start=450)
    assert saves[-1] == 451
    t.status, t.phase = 'completed', 'completed'
    hist.finish(t)
    assert saves[-1] == 451 and t._hist['done']
    assert hist.load('m1')['status'] == 'completed'


def test_a_write_that_failed_is_not_tried_again_on_every_line(db, monkeypatch):
    # against a locked database each try waits out the busy timeout inside log()
    t = _task()
    hist.track(t)
    tries = []
    real = hist._save

    def _locked(task):
        tries.append(hist.total_lines(task))
        raise RuntimeError('database is locked')
    monkeypatch.setattr(hist, '_save', _locked)
    _fill(t, 600)
    assert tries == [200]
    t._hist['retry'] -= hist.RETRY_SECONDS + 1
    monkeypatch.setattr(hist, '_save', real)
    _fill(t, 1, start=600)
    assert hist.load('m1')['log_total'] == 601


def test_a_line_from_another_thread_leaves_a_write_under_way_alone(db, monkeypatch):
    # the disk monitor logs from a thread of its own while the job logs too
    t = _task()
    hist.track(t)
    saves = []
    real = hist._save
    monkeypatch.setattr(hist, '_save', lambda task: (saves.append(hist.total_lines(task)), real(task)))
    lk = t._hist['lock']
    lk.acquire()
    try:
        _fill(t, 300)
        assert saves == []
    finally:
        lk.release()
    _fill(t, 1, start=300)
    assert saves == [301]


def test_the_stored_log_reads_like_the_live_one(db):
    t = _task()
    hist.track(t)
    _fill(t, 25000)
    t.status = 'failed'
    hist.finish(t)
    row = hist.load('m1')
    assert row['log_total'] == 25000 and row['log_dropped'] == t.log_dropped
    assert hist.whole_stored(row) == hist.whole_live(t)
    for offset, limit in ((0, 5000), (1990, 20), (hist.LOG_HEAD_LINES + 3, 50), (24990, 100), (25000, 10)):
        live, stored = hist.read_live(t, offset, limit), hist.read_stored(row, offset, limit)
        assert (live['lines'], live['next']) == (stored['lines'], stored['next']), offset
    # the chunks of what was left out are gone from the table, the head and tail are there
    chunks = sorted(r['chunk'] for r in _rows(db, 'v2p_migration_log'))
    first_tail = (hist.LOG_HEAD_LINES + t.log_dropped) // hist.LOG_CHUNK
    assert chunks == list(range(hist.LOG_HEAD_LINES // hist.LOG_CHUNK)) + \
        list(range(first_tail, (25000 - 1) // hist.LOG_CHUNK + 1))


def test_the_stored_log_holds_no_password(db, quiet):
    import urllib.parse
    t = _task(esxi_password=PW)
    hist.track(t)
    t.log(f'ssh root@10.0.0.5 said: bad password {PW}')
    t.log(f'curl https://root:{urllib.parse.quote(PW, safe="")}@10.0.0.5/folder')
    t.log('> Authorization: Basic cm9vdDpTdXAzciRlY3JldA==')
    t.set_phase('failed', f'login with {PW} refused')
    hist.finish(t)
    stored = json.dumps(_rows(db, 'v2p_migration_log')) + json.dumps(_rows(db, 'v2p_migration_runs'))
    for form in (PW, urllib.parse.quote(PW, safe=''), 'cm9vdDpTdXAzciRlY3JldA=='):
        assert form not in stored
    assert '********' in stored
    assert all(PW not in line for line in hist.whole_stored(hist.load('m1')))


def test_a_run_a_stop_cut_off_reads_as_interrupted(db):
    cut, live = _task('cut1'), _task('live1')
    for t in (cut, live):
        hist.track(t)
        _fill(t, 3)
        hist._save(t)
    # the process ended: only live1 is held by the new one
    assert hist.mark_interrupted({'live1'}) == 1
    row = hist.load('cut1')
    assert row['status'] == hist.INTERRUPTED and row['log_total'] == 4
    assert hist.as_dict(row)['status'] == hist.INTERRUPTED
    assert 'stopped' in hist.as_dict(row)['error']
    last = hist.whole_stored(row)[-1]
    assert 'INTERRUPTED' in last and 'planning' in last
    assert hist.as_dict(row)['log'][-1] == last
    assert hist.load('live1')['status'] == 'running'
    # once per database
    db._v2p_swept = False
    hist.sweep_once({'live1'})
    assert db._v2p_swept and hist.mark_interrupted({'live1'}) == 0


@pytest.mark.parametrize('guest_prep,said', [
    # the in-guest preparation had released the guest: how it comes back on ESXi
    ({'on': True, 'state': 'shut_down'}, 'mount the installer of its ESXi guest tools within 15 min'),
    ({'on': True, 'state': 'shutting_down'}, 'its first boot task reinstalls them and puts the address back'),
    # Live Mirror had run the guest from the source's disks: it stays off on ESXi
    ({'on': True, 'state': 'shut_down', 'source_disks_used': True}, 'keep the source off on ESXi'),
    ({'on': True, 'state': 'prepared'}, 'Check the source guest on ESXi'),
    (None, 'Check the source guest on ESXi'),
])
def test_a_cut_off_run_says_what_to_do_with_its_source(db, guest_prep, said):
    t = _task('cut2')
    hist.track(t)
    _fill(t, 2)
    hist._save(t)
    if guest_prep is not None:
        row = db.conn.execute("SELECT summary FROM v2p_migration_runs WHERE id = 'cut2'").fetchone()
        summary = json.loads(row['summary'])
        summary['guest_prep'] = guest_prep
        db.conn.execute("UPDATE v2p_migration_runs SET summary = ? WHERE id = 'cut2'", (json.dumps(summary),))
        db.conn.commit()
    assert hist.mark_interrupted(set()) == 1
    last = hist.whole_stored(hist.load('cut2'))[-1]
    assert 'INTERRUPTED' in last and said in last, last


def test_the_newest_runs_of_the_last_days_are_kept(db, monkeypatch):
    monkeypatch.setattr(hist, 'KEEP_RUNS', 3)
    tasks = []
    for i in range(5):
        t = _task(f'r{i}')
        t.started_at = t.started_at.replace(microsecond=0) - datetime.timedelta(minutes=10 - i)
        hist.track(t)
        _fill(t, 2)
        t.status = 'completed'
        tasks.append(t)
    old = _task('old')
    old.started_at -= datetime.timedelta(days=hist.KEEP_DAYS + 1)
    old.status = 'failed'
    hist.track(old)
    running = _task('busy')
    running.started_at -= datetime.timedelta(days=200)
    hist.track(running)
    for t in tasks:
        hist._save(t)
    hist._save(old)
    assert hist.prune() == 3
    ids = {r['id'] for r in _rows(db, 'v2p_migration_runs')}
    assert ids == {'r2', 'r3', 'r4', 'busy'}
    assert {r['run_id'] for r in _rows(db, 'v2p_migration_log')} <= ids


def test_a_finished_run_leaves_the_registry_a_while_after_its_last_write():
    lock = threading.Lock()
    done = types.SimpleNamespace(status='completed', _hist={'done': time.time() - hist.EVICT_AFTER - 1})
    fresh = types.SimpleNamespace(status='failed', _hist={'done': time.time()})
    unsaved = types.SimpleNamespace(status='failed', _hist={'done': None})
    busy = types.SimpleNamespace(status='running', _hist={'done': time.time() - 10 ** 6})
    plain = types.SimpleNamespace(status='completed')
    reg = {'a': done, 'b': fresh, 'c': unsaved, 'd': busy, 'e': plain}
    assert hist.evict(reg, lock) == ['a']
    assert set(reg) == {'b', 'c', 'd', 'e'}


# -- the routes -------------------------------------------------------------------------------

ALL_VMW = ['cluster.view', 'vmware.vm.migrate', 'vmware.vm.view']


def _server(sid, linked):
    return VMwareManager(sid, {'name': sid, 'host': f'{sid}.lab', 'username': 'root',
                               'server_type': 'esxi', 'linked_clusters': linked})


@pytest.fixture
def estate(api, seed):
    seed.tenant('acme', clusters=['cluster_a'])
    seed.tenant('other', clusters=['cluster_b'])
    users = {
        'admin': seed.user('root', role='admin'),
        'alice': seed.user('alice', role='viewer', tenant_id='acme', permissions=ALL_VMW),
        'bob': seed.user('bob', role='viewer', tenant_id='other', permissions=ALL_VMW),
        # reaches the target cluster, but the ESXi server belongs to the other tenant
        'mallory': seed.user('mallory', role='viewer', tenant_id='acme', permissions=ALL_VMW),
        'viewer': seed.user('vera', role='viewer', tenant_id='acme'),
    }
    ppglobals.vmware_managers.update({'esx-a': _server('esx-a', ['cluster_a']),
                                      'esx-b': _server('esx-b', ['cluster_b'])})
    from pegaprox.api import vmware as vmw
    try:
        yield types.SimpleNamespace(users=users, reg=vmw._vmware_migrations, api=api, db=seed.db)
    finally:
        ppglobals.vmware_managers.clear()


def _stored(mid, vmware_id='esx-a', vm_id='vm-1', cluster='cluster_a', lines=5, status='completed',
            ago=0):
    t = _task(mid, vmware_id, vm_id, cluster, name=f'vm-{mid}')
    t.started_at -= datetime.timedelta(seconds=ago)
    hist.track(t)
    _fill(t, lines)
    t.status = t.phase = status
    hist.finish(t)
    return t


def _ids(resp):
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return [m['id'] for m in resp.get_json()]


def test_the_list_answers_live_runs_then_a_page_of_stored_ones(estate):
    admin = estate.api.as_user(estate.users['admin'])
    for i in range(7):
        _stored(f's{i}', ago=100 - i)
    live = _task('live1')
    estate.reg['live1'] = live
    hist.track(live)
    r = admin.get('/api/vmware/migrations?limit=3')
    assert _ids(r) == ['live1', 's6', 's5', 's4'] and r.headers['X-History-More'] == '1'
    r = admin.get('/api/vmware/migrations?limit=3&offset=3')
    assert _ids(r) == ['live1', 's3', 's2', 's1'] and r.headers['X-History-More'] == '1'
    r = admin.get('/api/vmware/migrations?limit=3&offset=6')
    assert _ids(r) == ['live1', 's0'] and r.headers['X-History-More'] == '0'
    assert _ids(admin.get('/api/vmware/migrations?limit=0')) == ['live1']
    # the default page, the live run once
    assert _ids(admin.get('/api/vmware/migrations')) == ['live1'] + [f's{i}' for i in range(6, -1, -1)]
    stored = admin.get('/api/vmware/migrations').get_json()[1]
    assert stored['status'] == 'completed' and stored['log'] == [] and stored['log_total'] == 5
    assert stored['vm_name'] == 'vm-s6' and stored['target_node'] == 'pve1'
    for bad in ('limit=x', 'limit=-1', f'limit={hist.PAGE_MAX + 1}', 'offset=-2'):
        assert admin.get(f'/api/vmware/migrations?{bad}').status_code == 400, bad


def test_an_ended_run_moves_from_the_registry_to_the_table_unchanged(estate):
    admin = estate.api.as_user(estate.users['admin'])
    t = _task('done1')
    estate.reg['done1'] = t
    hist.track(t)
    _fill(t, 12)
    t.status, t.phase = 'completed', 'completed'
    hist.finish(t)
    before = admin.get('/api/vmware/migrations/done1').get_json()
    t._hist['done'] -= hist.EVICT_AFTER + 1
    assert _ids(admin.get('/api/vmware/migrations')) == ['done1']
    assert 'done1' not in estate.reg
    after = admin.get('/api/vmware/migrations/done1').get_json()
    assert after['status'] == 'completed' and after['log'] == before['log']
    assert after['vm_name'] == before['vm_name'] and after['config'] == before['config']


def test_after_a_restart_the_runs_and_their_logs_are_there(estate):
    admin = estate.api.as_user(estate.users['admin'])
    _stored('old1', lines=30)
    cut = _task('cut1')
    hist.track(cut)
    _fill(cut, 4)
    hist._save(cut)
    # a new process: an empty registry, the table as it was
    estate.reg.clear()
    estate.db._v2p_swept = False
    listed = {m['id']: m for m in admin.get('/api/vmware/migrations').get_json()}
    assert listed['old1']['status'] == 'completed' and listed['cut1']['status'] == 'interrupted'
    log = admin.get('/api/vmware/migrations/old1/log').get_json()
    assert log['lines'] == [f'line {i}' for i in range(30)] and log['running'] is False
    assert 'INTERRUPTED' in admin.get('/api/vmware/migrations/cut1/log').get_json()['lines'][-1]


def test_the_log_route_reads_a_live_run_from_an_offset(estate):
    admin = estate.api.as_user(estate.users['admin'])
    t = _task('live2')
    estate.reg['live2'] = t
    hist.track(t)
    _fill(t, 12)
    r = admin.get('/api/vmware/migrations/live2/log?offset=0&limit=5').get_json()
    assert r['lines'] == [f'line {i}' for i in range(5)] and r['next'] == 5 and r['total'] == 12
    assert r['running'] is True and r['status'] == 'running' and r['id'] == 'live2'
    _fill(t, 3, start=12)
    r = admin.get('/api/vmware/migrations/live2/log?offset=5').get_json()
    assert r['lines'] == [f'line {i}' for i in range(5, 15)] and r['next'] == 15
    # the status turned, but the job still writes its clean up: running until it returned
    t.status = 'failed'
    assert admin.get('/api/vmware/migrations/live2/log?offset=15').get_json()['running'] is True
    hist.finish(t)
    assert admin.get('/api/vmware/migrations/live2/log?offset=15').get_json()['running'] is False


def test_a_job_whose_last_write_failed_reads_as_over_and_stays_in_the_registry(estate, monkeypatch):
    admin = estate.api.as_user(estate.users['admin'])
    t = _task('lost1')
    estate.reg['lost1'] = t
    hist.track(t)
    _fill(t, 3)
    t.status = 'failed'

    def _broken(task):
        raise RuntimeError('database is locked')
    monkeypatch.setattr(hist, '_save', _broken)
    hist.finish(t)
    assert t._hist['ended'] and not t._hist['done']
    r = admin.get('/api/vmware/migrations/lost1/log').get_json()
    assert r['running'] is False and r['lines'] == ['line 0', 'line 1', 'line 2']
    # its log is nowhere else, so it is not evicted
    assert hist.evict(estate.reg, threading.Lock(), now=time.time() + 10 ** 6) == []
    for bad in ('offset=-1', 'offset=a', 'limit=0', f'limit={hist.READ_MAX_LINES + 1}'):
        assert admin.get(f'/api/vmware/migrations/live2/log?{bad}').status_code == 400, bad
    assert admin.get('/api/vmware/migrations/nope/log').status_code == 404


def test_a_run_whose_job_never_started_is_saved_and_leaves_the_registry(estate):
    """A task registered for a thread that did not start never reaches _run_held, the only
    other place its row is written and it is marked for eviction."""
    from pegaprox.api import vmware as vmw
    admin = estate.api.as_user(estate.users['admin'])
    t = _task('nostart1')
    estate.reg['nostart1'] = t
    vmw._never_ran('nostart1')
    assert t.status == 'failed' and t.completed_at is not None and t._hist['done']
    row = hist.load('nostart1')
    assert row['status'] == 'failed' and row['summary']['error'] == 'The migration could not be started'
    t._hist['done'] -= hist.EVICT_AFTER + 1
    assert _ids(admin.get('/api/vmware/migrations')) == ['nostart1']
    assert 'nostart1' not in estate.reg
    got = admin.get('/api/vmware/migrations/nostart1').get_json()
    assert got['status'] == 'failed' and got['error'] == 'The migration could not be started'
    # a task that got as far as its job is not touched
    ran = _task('ran1')
    ran.status = 'completed'
    estate.reg['ran1'] = ran
    vmw._never_ran('ran1')
    assert ran.status == 'completed' and not hasattr(ran, '_hist') and hist.load('ran1') is None


def test_a_run_that_never_started_and_could_not_be_saved_stays_and_raises_nothing(estate, monkeypatch):
    from pegaprox.api import vmware as vmw
    t = _task('nostart2')
    estate.reg['nostart2'] = t

    def _broken(task):
        raise RuntimeError('database is locked')
    monkeypatch.setattr(hist, '_save', _broken)
    vmw._never_ran('nostart2')
    assert t.status == 'failed' and not t._hist['done']
    assert hist.evict(estate.reg, threading.Lock(), now=time.time() + 10 ** 6) == []
    assert 'nostart2' in estate.reg


def test_the_log_downloads_as_a_plain_text_file(estate, quiet):
    admin = estate.api.as_user(estate.users['admin'])
    t = _task('dl1', name='web 01/"x"\nforged', esxi_password=PW)
    estate.reg['dl1'] = t
    hist.track(t)
    _fill(t, 25000)
    t.log(f'password was {PW}')
    r = admin.get('/api/vmware/migrations/dl1/log?download=1')
    assert r.status_code == 200 and r.mimetype == 'text/plain'
    disp = r.headers['Content-Disposition']
    assert disp == 'attachment; filename="esxi-migration-web_01_x_forged-dl1.log"', disp
    text = r.get_data(as_text=True)
    lines = text.splitlines()
    assert lines[0].startswith('# ESXi migration dl1: web 01/"x" forged (esx-a/vm-1) -> cluster_a/pve1/local-lvm')
    assert lines[1].startswith('# status running, phase planning')
    assert lines[2] == 'line 0' and hist.left_out_line(t.log_dropped) in lines
    assert lines[-1].endswith('password was ********') and PW not in text
    # the same file once the run is only in the table
    t.status = 'completed'
    hist.finish(t)
    estate.reg.clear()
    stored = admin.get('/api/vmware/migrations/dl1/log?download=1').get_data(as_text=True)
    assert stored.splitlines()[2:] == lines[2:]


def test_a_stored_run_is_shown_to_its_tenant_and_to_nobody_else(estate):
    _stored('run-a', 'esx-a', 'vm-1', 'cluster_a')
    _stored('run-b', 'esx-b', 'vm-7', 'cluster_b')
    who = {k: estate.api.as_user(u) for k, u in estate.users.items()}
    assert set(_ids(who['admin'].get('/api/vmware/migrations'))) == {'run-a', 'run-b'}
    assert _ids(who['alice'].get('/api/vmware/migrations')) == ['run-a']
    assert _ids(who['bob'].get('/api/vmware/migrations')) == ['run-b']
    for name, mine, theirs in (('alice', 'run-a', 'run-b'), ('bob', 'run-b', 'run-a')):
        c = who[name]
        assert c.get(f'/api/vmware/migrations/{mine}').status_code == 200
        assert c.get(f'/api/vmware/migrations/{mine}/log').status_code == 200
        for path in (f'/api/vmware/migrations/{theirs}', f'/api/vmware/migrations/{theirs}/log',
                     f'/api/vmware/migrations/{theirs}/log?download=1'):
            r = c.get(path)
            assert r.status_code == 404 and 'vm-' + theirs not in r.get_data(as_text=True), (name, path)
    # no vmware.vm.migrate, no migrations at all
    for path in ('/api/vmware/migrations', '/api/vmware/migrations/run-a',
                 '/api/vmware/migrations/run-a/log'):
        assert who['viewer'].get(path).status_code == 403, path


def test_a_stored_run_on_a_foreign_esxi_server_stays_hidden(estate):
    # mallory reaches cluster_a, the run's target, but esx-b is the other tenant's server
    _stored('run-x', 'esx-b', 'vm-7', 'cluster_a')
    c = estate.api.as_user(estate.users['mallory'])
    assert _ids(c.get('/api/vmware/migrations')) == []
    assert c.get('/api/vmware/migrations/run-x').status_code == 404
    assert c.get('/api/vmware/migrations/run-x/log').status_code == 404


def test_a_stored_run_without_its_guest_is_left_to_an_admin(estate):
    t = _stored('bare1')
    estate.db.conn.execute("UPDATE v2p_migration_runs SET vmware_id = '', vm_id = '' WHERE id = 'bare1'")
    estate.db.conn.commit()
    assert t
    assert _ids(estate.api.as_user(estate.users['alice']).get('/api/vmware/migrations')) == []
    assert estate.api.as_user(estate.users['alice']).get('/api/vmware/migrations/bare1/log').status_code == 404
    assert _ids(estate.api.as_user(estate.users['admin']).get('/api/vmware/migrations')) == ['bare1']


def test_the_stored_runs_get_the_answer_the_live_ones_get(estate):
    """The memoised check of the stored runs and _migration_reachable agree for every caller."""
    runs = [('esx-a', 'vm-1', 'cluster_a'), ('esx-b', 'vm-7', 'cluster_b'), ('esx-b', 'vm-7', 'cluster_a'),
            ('esx-a', 'vm-2', 'cluster_b')]
    for name in ('admin', 'alice', 'bob', 'mallory'):
        client = estate.api.as_user(estate.users[name])
        for i, (vmw_id, vm, cl) in enumerate(runs):
            live = _task(f'L{name}{i}', vmw_id, vm, cl)
            estate.reg[live.id] = live
            _stored(f'S{name}{i}', vmw_id, vm, cl)
        listed = set(_ids(client.get('/api/vmware/migrations')))
        for i in range(len(runs)):
            assert (f'L{name}{i}' in listed) == (f'S{name}{i}' in listed), (name, runs[i])
        estate.reg.clear()


def test_a_job_writes_its_row_and_its_whole_log(estate, monkeypatch, quiet):
    from pegaprox.api import vmware as vmw
    t = _task('job1')
    estate.reg['job1'] = t

    def run(task):
        for i in range(250):
            task.log(f'copy {i}')
        task.set_phase('completed')
        task.log('COMPLETED')
    monkeypatch.setattr(vmw, '_run_v2p_migration', run)
    vmw._run_held(t, 'task:job1')
    row = hist.load('job1')
    assert row['status'] == 'completed' and row['log_total'] == 252
    assert hist.whole_stored(row)[-1].endswith('COMPLETED')
    assert hist.job_running(t) is False


def test_both_tables_stay_on_their_instance_and_a_standby_forwards_the_log():
    from pegaprox.core import ha
    for table in ('v2p_migration_runs', 'v2p_migration_log'):
        assert table in ha.LOCAL_TABLES and table not in ha.SYNC_TABLES
    assert '/api/vmware/migrations/<mid>/log' in ha.FORWARDED_READS
    assert '/api/vmware/migrations/<mid>/log' not in ha.LEADER_ONLY_READS
