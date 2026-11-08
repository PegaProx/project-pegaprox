"""Boot screenshots as the evidence of a DR test failover.

A test failover clones the replicas on the target and starts the clones. After that,
one console frame per started guest is taken with the grab the console tile uses
(api/vms.py grab_vm_frame) and kept with the test's event: a summary in its details
(what was taken, what failed and why, how long each took) and the pictures in
site_recovery_screenshots, served by one route that asks what the screenshot route asks.

What these hold shut:
  * the end to end path: POST /test -> worker -> pictures in the event -> GET the PNG
  * a grab that fails is listed and never changes the outcome of the test
  * the bounds: a cap per test, a timeout per guest that the RFB fallback cannot
    outlive, a few in parallel, a size limit, the pictures of the last tests only
  * the event is complete before the pictures, so a cleanup meanwhile finds the clones
  * permissions: only of guests the starter may open the console of; reading one asks
    the plan's gates and vm.console, so another tenant, a confined admin and a pool user
    outside the plan get nothing
MK Oct 2026
"""
import io
import json
import os
import time
from unittest.mock import MagicMock

import gevent
import gevent.event
import pytest
from PIL import Image

import pegaprox.api.vms as vms_api
import pegaprox.background.site_recovery as srw
import pegaprox.utils.rbac as rbac
from pegaprox.utils import vnc_grab

try:
    import pegaprox.background.sr_boot_shots as shots
except ImportError:
    # the counterproof runs the end to end tests against the code before the change
    shots = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOT_RULE = '/api/site-recovery/plans/<plan_id>/events/<event_id>/screenshots/<int:vmid>'


def _png(size=(64, 48), color=(30, 120, 200)):
    out = io.BytesIO()
    Image.new('RGB', size, color).save(out, format='PNG')
    return out.getvalue()


PNG = _png()


def _noise_png(size=(640, 480)):
    out = io.BytesIO()
    Image.frombytes('RGB', size, os.urandom(size[0] * size[1] * 3)).save(out, format='PNG')
    return out.getvalue()


@pytest.fixture
def fast(monkeypatch):
    if shots is not None:
        monkeypatch.setattr(shots, 'BOOT_SETTLE', 0)
    return monkeypatch


def _grab_with(monkeypatch, grab):
    # raising=False: before the change there was no grab_vm_frame to replace
    monkeypatch.setattr(vms_api, 'grab_vm_frame', grab, raising=False)


def _grabber(frames, delay=0):
    """grab_vm_frame as the worker sees it: {test_vmid: png or an exception}."""
    calls = []

    def grab(mgr, node, vm_type, vmid, max_width=480):
        calls.append((node, vm_type, vmid, max_width))
        if delay:
            gevent.sleep(delay)
        got = frames.get(vmid, PNG)
        if isinstance(got, BaseException):
            raise got
        return got
    grab.calls = calls
    return grab


def _plan(db, plan_id='p1', vms=((100, 'qemu', 'web01'), (101, 'qemu', 'db01'), (102, 'lxc', 'ct01')),
          src='cluster_1', tgt='cluster_2'):
    db.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster, status) "
               "VALUES (?, 'g1', ?, ?, ?, 'ready')", (plan_id, f'Plan {plan_id}', src, tgt))
    for vmid, vtype, name in vms:
        db.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name, vm_type, boot_group) "
                   "VALUES (?, ?, ?, ?, ?, 0)", (f'{plan_id}-{vmid}', plan_id, vmid, name, vtype))


def _target(vmids, cluster_type='proxmox'):
    m = MagicMock(name='target')
    m.cluster_type = cluster_type
    m.is_connected = True
    m.get_node_status.return_value = {'n1': {'status': 'online'}}
    m.get_vms.return_value = [{'vmid': v} for v in vmids]
    m.clone_vm.return_value = {'success': True}
    m.vm_action.return_value = {'success': True}
    m.create_snapshot.return_value = {'success': True}
    return m


def _test_event(db, plan_id='p1', settled=True, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = db.query_one("SELECT * FROM site_recovery_events WHERE plan_id = ? AND event_type = 'test' "
                           "ORDER BY started_at DESC LIMIT 1", (plan_id,))
        if row and row['status'] != 'running':
            ev = dict(row)
            ev['details'] = json.loads(ev['details'] or '{}')
            state = (ev['details'].get('screenshots') or {}).get('state')
            if not settled or state != 'capturing':
                return ev
        gevent.sleep(0.05)
    raise AssertionError('the test failover did not finish')


def _guests(n, vm_type='qemu', first=100):
    return [{'vmid': first + i, 'test_vmid': 90000 + first + i, 'vm_type': vm_type,
             'vm_name': f'g{first + i}', 'node': 'n1', 'started': time.monotonic()} for i in range(n)]


def _event(db, event_id, plan_id='p1', started='2026-10-01T10:00:00', details=None, kind='test'):
    db.execute("INSERT INTO site_recovery_events (id, plan_id, event_type, status, started_at, details) "
               "VALUES (?, ?, ?, 'completed', ?, ?)", (event_id, plan_id, kind, started, json.dumps(details or {})))


# --- end to end ----------------------------------------------------------------------------

def test_a_test_failover_keeps_a_boot_screenshot_of_each_guest_it_started(api, seed, fast):
    """The core: through the route, into the event, out of the image route."""
    _plan(seed.db)
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    api.set_manager('cluster_2', _target([100, 101, 102]))
    grab = _grabber({90100: PNG, 90101: IOError('blank framebuffer (display likely off)')})
    _grab_with(fast, grab)
    admin = seed.user('root', role='admin')
    client = api.as_user(admin)

    r = client.post('/api/site-recovery/plans/p1/test', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    ev = _test_event(seed.db)

    summary = ev['details'].get('screenshots')
    assert summary, f"the test event carries no boot screenshots: {sorted(ev['details'])}"
    assert summary['state'] == 'done'
    assert (summary['taken'], summary['failed'], summary['skipped']) == (1, 1, 1)
    rows = {g['vmid']: g for g in summary['guests']}
    assert rows[100]['status'] == 'ok' and rows[100]['test_vmid'] == 90100
    assert rows[100]['bytes'] == len(PNG) and rows[100]['ms'] >= 0 and rows[100]['after_boot_s'] >= 0
    assert rows[100]['captured_at']
    assert rows[101]['status'] == 'failed' and 'blank framebuffer' in rows[101]['reason']
    assert rows[102]['status'] == 'skipped' and 'container' in rows[102]['reason']
    # the clone on its node, at the evidence width; the container was never tried
    assert sorted(c[2] for c in grab.calls) == [90100, 90101]
    assert {(c[0], c[1], c[3]) for c in grab.calls} == {('n1', 'qemu', shots.SHOT_MAX_WIDTH)}
    # a guest that could not be grabbed does not fail the test
    assert ev['status'] == 'completed'
    assert sorted(ev['details']['test_vmids'], key=lambda e: e['vmid']) == [
        {'vmid': 90100, 'vm_type': 'qemu'}, {'vmid': 90101, 'vm_type': 'qemu'}, {'vmid': 90102, 'vm_type': 'lxc'}]

    img = client.get(f"/api/site-recovery/plans/p1/events/{ev['id']}/screenshots/100")
    assert img.status_code == 200, img.get_data(as_text=True)
    assert img.mimetype == 'image/png' and img.data == PNG
    assert 'private' in img.headers.get('Cache-Control', '')
    assert client.get(f"/api/site-recovery/plans/p1/events/{ev['id']}/screenshots/101").status_code == 404

    audit = [r['details'] for r in seed.db.query(
        "SELECT details FROM audit_log WHERE action = 'site_recovery.test_complete'")]
    assert audit and 'boot screenshots: 1 taken, 1 failed, 1 skipped' in audit[-1], audit


def test_every_grab_failing_still_leaves_a_completed_test(api, seed, fast):
    _plan(seed.db, vms=((100, 'qemu', 'a'), (101, 'qemu', 'b')))
    api.set_manager('cluster_2', _target([100, 101]))
    _grab_with(fast, _grabber({90100: IOError('no SSH'), 90101: RuntimeError('x')}))
    r = api.as_user(seed.user('root', role='admin')).post('/api/site-recovery/plans/p1/test', json={})
    assert r.status_code == 200
    ev = _test_event(seed.db)
    assert ev['status'] == 'completed'
    assert ev['details']['counts'] == {'ok': 2, 'failed': 0, 'total': 2}
    assert ev['details']['screenshots']['failed'] == 2
    assert seed.db.query_one('SELECT COUNT(*) AS n FROM site_recovery_screenshots')['n'] == 0


def test_no_picture_of_a_guest_whose_console_the_starter_may_not_open(api, seed, fast):
    """The screenshot route asks vm.console; the job has no caller, so the route that starts
    the test asks it and hands the answer over."""
    _plan(seed.db, vms=((100, 'qemu', 'a'),))
    api.set_manager('cluster_2', _target([100]))
    grab = _grabber({})
    _grab_with(fast, grab)
    operator = seed.user('dr_op', role='user', permissions=['site_recovery.failover'], denied=['vm.console'])
    r = api.as_user(operator).post('/api/site-recovery/plans/p1/test', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    ev = _test_event(seed.db)
    row = ev['details']['screenshots']['guests'][0]
    assert row['status'] == 'skipped' and 'console permission' in row['reason']
    assert grab.calls == []


def test_the_worker_takes_none_when_nobody_said_which(db, fast):
    """None is no answer from a caller, not 'all of them'."""
    grab = _grabber({})
    _grab_with(fast, grab)
    out = shots.capture(_target([]), 'p1', 'e1', _guests(2), None)
    assert [g['status'] for g in out['guests']] == ['skipped', 'skipped']
    assert grab.calls == []


def test_the_event_is_complete_before_the_pictures_are_taken(api, seed, fast):
    """A cleanup reads test_vmids from the newest test event. Were the event still open
    while the pictures are taken, a cleanup then would find no clones and leave them."""
    _plan(seed.db, vms=((100, 'qemu', 'a'),))
    api.set_manager('cluster_2', _target([100]))
    gate = gevent.event.Event()

    def held(mgr, node, vm_type, vmid, max_width=480):
        gate.wait(5)
        return PNG
    _grab_with(fast, held)
    api.as_user(seed.user('root', role='admin')).post('/api/site-recovery/plans/p1/test', json={})
    ev = _test_event(seed.db, settled=False)
    assert ev['status'] == 'completed'
    assert ev['details']['screenshots']['state'] == 'capturing'
    assert ev['details']['test_vmids'] == [{'vmid': 90100, 'vm_type': 'qemu'}]
    gate.set()
    assert _test_event(seed.db)['details']['screenshots']['taken'] == 1


# --- bounds --------------------------------------------------------------------------------

def test_no_more_than_the_cap_per_test(db, fast):
    fast.setattr(shots, 'SHOT_CAP', 2)
    grab = _grabber({})
    _grab_with(fast, grab)
    guests = _guests(4)
    out = shots.capture(_target([]), 'p1', 'e1', guests, [g['vmid'] for g in guests])
    assert [g['status'] for g in out['guests']] == ['ok', 'ok', 'skipped', 'skipped']
    assert 'limit of 2' in out['guests'][3]['reason']
    assert len(grab.calls) == 2


def test_only_a_few_at_a_time(db, fast):
    fast.setattr(shots, 'SHOT_PARALLEL', 2)
    live = {'now': 0, 'max': 0}

    def grab(mgr, node, vm_type, vmid, max_width=480):
        live['now'] += 1
        live['max'] = max(live['max'], live['now'])
        gevent.sleep(0.05)
        live['now'] -= 1
        return PNG
    _grab_with(fast, grab)
    guests = _guests(6)
    out = shots.capture(_target([]), 'p1', 'e1', guests, [g['vmid'] for g in guests])
    assert out['taken'] == 6
    assert live['max'] == 2, live


def test_a_guest_that_never_answers_costs_its_timeout_and_no_more(db, fast):
    fast.setattr(shots, 'SHOT_TIMEOUT', 0.3)
    _grab_with(fast, _grabber({}, delay=30))
    t0 = time.monotonic()
    out = shots.capture(_target([]), 'p1', 'e1', _guests(2), [100, 101])
    assert time.monotonic() - t0 < 3
    assert [g['status'] for g in out['guests']] == ['failed', 'failed']
    assert out['guests'][0]['reason'] == 'no picture within 0.3s'


def test_the_fallback_cannot_outlive_the_timeout(db, fast):
    """grab_vm_frame catches Exception around the screendump and tries RFB next. A
    timeout that is an Exception would be caught there and start the RFB leg on time
    that is already up."""
    fast.setattr(shots, 'SHOT_TIMEOUT', 0.3)
    rfb = []

    def stuck(*a, **k):
        gevent.sleep(30)
    fast.setattr(vnc_grab, 'screendump_to_png', stuck)
    fast.setattr(vms_api, '_screenshot_via_rfb', lambda *a, **k: rfb.append(a) or PNG)
    out = shots.capture(_target([]), 'p1', 'e1', _guests(1), [100])
    assert out['guests'][0]['status'] == 'failed'
    assert rfb == [], 'the RFB fallback ran after the timeout fired'


def test_the_real_grab_falls_back_to_rfb_when_screendump_gives_nothing(db, fast):
    fast.setattr(vnc_grab, 'screendump_to_png', lambda *a, **k: (_ for _ in ()).throw(IOError('blank')))
    fast.setattr(vms_api, '_screenshot_via_rfb', lambda *a, **k: PNG)
    out = shots.capture(_target([]), 'p1', 'e1', _guests(1), [100])
    assert out['guests'][0]['status'] == 'ok'
    assert shots.load('e1', 100) == (90100, PNG)


def test_a_picture_is_kept_small(db, fast):
    big = _noise_png()
    assert len(big) > shots.SHOT_MAX_BYTES
    _grab_with(fast, _grabber({90100: big}))
    out = shots.capture(_target([]), 'p1', 'e1', _guests(1), [100])
    assert out['guests'][0]['status'] == 'ok'
    _tv, kept = shots.load('e1', 100)
    assert len(kept) <= shots.SHOT_MAX_BYTES and out['guests'][0]['bytes'] == len(kept)
    assert Image.open(io.BytesIO(kept)).width < 640


def test_a_picture_that_cannot_be_made_small_enough_is_listed(db, fast):
    fast.setattr(shots, 'SHOT_MAX_BYTES', 64)
    _grab_with(fast, _grabber({90100: _noise_png((320, 240))}))
    out = shots.capture(_target([]), 'p1', 'e1', _guests(1), [100])
    assert out['guests'][0]['status'] == 'failed' and 'larger than' in out['guests'][0]['reason']
    assert shots.load('e1', 100) == (None, None)


def test_only_a_proxmox_target_is_asked(db, fast):
    grab = _grabber({})
    _grab_with(fast, grab)
    out = shots.capture(_target([], cluster_type='xcpng'), 'p1', 'e1', _guests(1), [100])
    assert out['guests'][0]['status'] == 'skipped' and grab.calls == []


def test_only_the_last_tests_of_a_plan_keep_their_pictures(db):
    for i in range(7):
        _event(db, f'e{i}', started=f'2026-10-0{i + 1}T10:00:00')
        shots._store('p1', f'e{i}', {'vmid': 100, 'test_vmid': 90100}, {}, PNG)
    _event(db, 'other', plan_id='p2')
    shots._store('p2', 'other', {'vmid': 100, 'test_vmid': 90100}, {}, PNG)
    shots._prune('p1')
    kept = sorted(r['event_id'] for r in db.query('SELECT event_id FROM site_recovery_screenshots'))
    assert kept == sorted([f'e{i}' for i in range(2, 7)] + ['other'])
    assert shots.KEEP_TESTS == 5


def test_a_failing_capture_does_not_escape(db, fast):
    _event(db, 'e1', details={'results': {}, 'screenshots': {'state': 'capturing'}})
    fast.setattr(shots, 'capture', lambda *a: 1 / 0)
    out = shots.run(_target([]), 'p1', 'e1', _guests(2), [100, 101])
    assert out['state'] == 'done' and out['failed'] == 2 and 'division' in out['error']
    details = json.loads(db.query_one("SELECT details FROM site_recovery_events WHERE id = 'e1'")['details'])
    assert details['screenshots']['state'] == 'done' and 'results' in details


def test_a_restart_during_the_pictures_says_so(db):
    _event(db, 'e1', details={'results': {'100': {'success': True}},
                              'screenshots': {'state': 'capturing', 'guests': []}})
    _event(db, 'e2', details={'screenshots': {'state': 'done', 'guests': []}})
    srw.recover_orphan_runs()
    states = {r['id']: json.loads(r['details'])['screenshots']['state']
              for r in db.query('SELECT id, details FROM site_recovery_events')}
    assert states == {'e1': 'interrupted', 'e2': 'done'}


# --- who may read one ----------------------------------------------------------------------

def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {'data': data, 'timestamp': time.time(),
                                                   'refreshing': False}


@pytest.fixture
def stored(seed):
    """Plan p1 (guests 100 and 101) and p2 (guest 100 only), each with a test event and a
    picture of guest 100, on clusters of tenant_a."""
    seed.tenant('tenant_a', clusters=['cluster_1', 'cluster_2'])
    seed.tenant('tenant_b', clusters=['cluster_9'])
    _plan(seed.db, 'p1', vms=((100, 'qemu', 'web01'), (101, 'qemu', 'db01')))
    _plan(seed.db, 'p2', vms=((100, 'qemu', 'web01'),))
    for plan_id in ('p1', 'p2'):
        _event(seed.db, f'ev-{plan_id}', plan_id=plan_id)
        shots._store(plan_id, f'ev-{plan_id}', {'vmid': 100, 'test_vmid': 90100}, {}, PNG)
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    _seed_pool_membership('cluster_2', {})
    return seed


def _get(api, user, plan_id='p1', vmid=100):
    return api.as_user(user).get(f'/api/site-recovery/plans/{plan_id}/events/ev-{plan_id}/screenshots/{vmid}')


def test_an_admin_reads_the_picture(api, stored):
    r = _get(api, stored.user('root', role='admin'))
    assert r.status_code == 200 and r.data == PNG


def test_another_tenant_reads_nothing(api, stored):
    bob = stored.user('bob', role='user', tenant_id='tenant_b', permissions=['site_recovery.view'])
    r = _get(api, bob)
    assert r.status_code == 403, r.get_data(as_text=True)
    assert r.data != PNG


def test_a_confined_admin_reads_nothing_of_another_tenant(api, stored):
    capped = stored.user('tadmin', role='admin', tenant_id='tenant_b',
                         tenant_permissions={'tenant_b': {'role': 'viewer'}})
    r = _get(api, capped)
    assert r.status_code == 403, r.get_data(as_text=True)


def test_without_vm_console_the_picture_stays_closed(api, stored):
    """The plan and its events are readable to them; the console picture is not."""
    alice = stored.user('alice', role='user', tenant_id='tenant_a', denied=['vm.console'])
    assert api.as_user(alice).get('/api/site-recovery/plans/p1/events').status_code == 200
    r = _get(api, alice)
    assert r.status_code == 403 and 'vm.console' in r.get_json()['error']


def test_a_pool_user_reads_nothing_of_a_plan_that_reaches_past_their_pool(api, stored):
    mallory = stored.user('mallory', role='viewer', tenant_id='tenant_a')
    stored.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    assert _get(api, mallory, 'p1').status_code == 403
    # positive control: the plan of only their own guest opens
    r = _get(api, mallory, 'p2')
    assert r.status_code == 200 and r.data == PNG


def test_an_event_of_another_plan_is_not_reached_through_this_one(api, stored):
    root = stored.user('root', role='admin')
    r = api.as_user(root).get('/api/site-recovery/plans/p1/events/ev-p2/screenshots/100')
    assert r.status_code == 404


def test_deleting_the_plan_takes_its_pictures(api, stored):
    root = stored.user('root', role='admin')
    assert api.as_user(root).delete('/api/site-recovery/plans/p2').status_code == 200
    left = {r['plan_id'] for r in stored.db.query('SELECT plan_id FROM site_recovery_screenshots')}
    assert left == {'p1'}


# --- where it is wired ---------------------------------------------------------------------

def test_a_forwarding_standby_reads_the_picture_from_the_active():
    """The pictures live in the active's own tables, like the event they belong to."""
    from pegaprox.core import ha
    assert '/api/site-recovery/plans/<plan_id>/events' in ha.FORWARDED_READS
    assert SHOT_RULE in ha.FORWARDED_READS and SHOT_RULE not in ha.LEADER_ONLY_READS
    assert 'site_recovery_screenshots' in ha.LOCAL_TABLES


def test_the_route_is_registered(api):
    rules = {r.rule: r for r in api.app.url_map.iter_rules()}
    assert SHOT_RULE in rules and rules[SHOT_RULE].methods >= {'GET'}


def test_the_new_module_ships_with_an_update():
    with open(os.path.join(ROOT, 'version.json'), encoding='utf-8') as fh:
        assert 'pegaprox/background/sr_boot_shots.py' in json.load(fh)['update_files']
