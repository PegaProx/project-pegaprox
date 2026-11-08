"""The review round on the live view of a warm standby (#625, stage two).

  * "apply now" and the automatic reload read the waiting reload once (they were a
    restart then, with a stamp against a clock set back; a reload needs none);
  * the HA page of a standby follows the synced row: a PVE manager copies ha_enabled
    and ha_settings when it is built, so a sync hands those copies over as well;
  * a sync whose rows are committed notes a new connection setting even when a later
    step fails, and a host key file that cannot be written leaves the sync applied,
    with the problem in its status;
  * PegaProx node maintenance on a standby follows node_maintenance after each sync;
  * the recovery worker asks again right before the poison pill and right before each
    VM start, both of which come after reads that can take seconds;
  * the Prometheus exporter runs the SSH-backed Ceph probe only where this instance acts;
  * the ESXi VM detail watch is open on a standby (it only keeps a dict in memory);
  * GET /api/clusters with an ESXi host registered for XHM, which was a 500; now that
    its config has a name, save_config has to leave it out of the clusters table.

Every one of them has its counterproof on an active instance, or the case that was
right before.

MK Sep 2026
"""
import json
import os
import types

import pytest

from pegaprox.core import ha
import pegaprox.globals as g

from test_ha_v2_managers import (  # noqa: F401  (env and registries are fixtures)
    env, registries, _be, _switch_role, _sync, _poll, _update, _seed_all, _started,
    _standby_with_managers, _active_meta, _recovery_fake,
)
from test_ha_api import (  # noqa: F401  (ha_env is a fixture)
    ha_env, _admin, _standby_of_active, _active_with_standby,
)


# --- the waiting reload is read once ----------------------------------------------------
# (the config restart and its stamp against a clock set back are gone: a change to how
# the managers connect reloads them in place, tests/test_ha_reload.py)

class _Vanishing(dict):
    """_run whose waiting reload is gone after the first read: a sync that brought the
    old settings back landed between two reads (threads with gevent off)."""

    def __getitem__(self, key):
        value = super().__getitem__(key)
        if key == 'reload' and value:
            super().__setitem__('reload', None)
        return value


def test_apply_now_reads_the_waiting_reload_once(env, monkeypatch):
    _standby_with_managers(env)
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    monkeypatch.setattr(ha, '_run', _Vanishing(ha._run))
    assert ha.apply_config_now() == 'reload'
    assert env.reloads == [([], [], ['cluster:pve1'])]


def test_the_due_reload_reads_the_waiting_reload_once(env, monkeypatch):
    _standby_with_managers(env)
    env.clock.advance(300)
    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE)
    # the old settings are back by the time it looks: nothing to reload, and no TypeError
    _update(env.db, 'clusters', 'pve1', host='10.0.0.1')
    monkeypatch.setattr(ha, '_run', _Vanishing(ha._run))
    assert ha._reload_if_due() is False
    assert env.reloads == [] and env.restarts == []


# --- the HA page of a standby -----------------------------------------------------------

def _pve_manager(env, tmp_path, monkeypatch, cid='pve1'):
    """A real PegaProxManager, built from the row and not started (no network)."""
    import pegaprox.core.manager as mgrmod
    from pegaprox.models.tasks import PegaProxConfig
    monkeypatch.setattr(mgrmod, 'LOG_DIR', str(tmp_path))
    return mgrmod.PegaProxManager(cid, PegaProxConfig(env.db.get_all_clusters()[cid]))


def _close(mgr):
    for h in list(mgr.logger.handlers):
        h.close()
        mgr.logger.removeHandler(h)


@pytest.fixture
def pve(env, tmp_path, monkeypatch):
    made = []

    def build(cid='pve1'):
        mgr = _pve_manager(env, tmp_path, monkeypatch, cid)
        made.append(mgr)
        return mgr
    yield build
    for mgr in made:
        _close(mgr)


def _ha_row(env, enabled, **settings):
    _update(env.db, 'clusters', 'pve1', ha_enabled=1 if enabled else 0,
            ha_settings=env.db._encrypt(json.dumps(settings)))


def _view(mgr):
    st = mgr.get_ha_status()
    sbp = st['split_brain_prevention']
    return (st['enabled'], st['failure_threshold'], sbp['recovery_delay'], sbp['quorum_enabled'],
            sbp['quorum_hosts'], sbp['two_node_mode'])


def test_the_ha_page_of_a_standby_follows_the_synced_row(env, pve):
    _be('standby')
    _seed_all(env.db)
    _ha_row(env, True, recovery_delay=45, quorum_hosts=['10.9.9.9'])
    assert _sync(env) == 'applied'
    mgr = pve()
    mgr.start_ha_monitor()                  # what start() does: refused on a standby
    assert mgr.ha_thread is None
    # what the process sets on its own, and the synced settings do not carry
    mgr.ha_config['fence_strategy'] = {'strategy': 'wait', 'reason': 'two nodes'}
    mgr.ha_config['scsi_keys'] = {'pve2': '0xabc'}
    mgr.ha_config['node_ips'] = {'pve2': '10.0.0.2'}
    g.cluster_managers['pve1'] = mgr
    _started(env)
    env.clock.advance(300)
    assert _view(mgr) == (True, 3, 45, True, ['10.9.9.9'], False)

    assert _sync(env, lambda: _ha_row(env, False, recovery_delay=120, quorum_enabled=False,
                                      quorum_hosts=['10.1.1.1', '10.1.1.2'], two_node_mode=True,
                                      failure_threshold=5)) == 'applied'

    assert _view(mgr) == (False, 5, 120, False, ['10.1.1.1', '10.1.1.2'], True)
    assert mgr.get_ha_status()['split_brain_prevention']['fence_strategy']['strategy'] == 'wait'
    assert mgr.ha_config['scsi_keys'] == {'pve2': '0xabc'}
    assert mgr.ha_config['node_ips'] == {'pve2': '10.0.0.2'}
    # the cluster list and the HA page say the same now
    assert mgr.config.ha_enabled is False

    # switched on again on the active: shown, and still no monitor here
    assert _sync(env, lambda: _ha_row(env, True, recovery_delay=90)) == 'applied'
    assert _view(mgr)[:3] == (True, 3, 90) and mgr.ha_thread is None
    # a view, not a new connection: nothing to reload for
    assert ha.public_status()['sync']['reload_pending'] is None
    env.clock.advance(3600)
    assert _poll(env) == 'unchanged' and env.reloads == [] and ha.apply_config_now() is False


def test_the_ha_view_is_left_alone_where_this_instance_acts(env, pve):
    """Counterproof: on an active the monitor owns these copies (and _refresh_managers
    never runs there anyway); a monitor thread keeps them on a standby as well."""
    _be('standby')
    _seed_all(env.db)
    _ha_row(env, True, recovery_delay=45)
    assert _sync(env) == 'applied'
    mgr = pve()
    g.cluster_managers['pve1'] = mgr
    _started(env)

    _switch_role('active')
    _ha_row(env, False, recovery_delay=120)
    ha._refresh_managers()
    assert _view(mgr)[:3] == (True, 3, 45)

    _switch_role('standby')
    mgr.ha_thread = object()
    ha._refresh_managers()
    assert _view(mgr)[:3] == (True, 3, 45)


def test_a_manager_is_built_with_the_ha_settings_as_before(env, pve):
    """_apply_ha_settings is the builder __init__ had: the same keys and defaults."""
    _seed_all(env.db)
    _ha_row(env, True, recovery_delay=45, verify_network=False, node_ips={'pve1': '10.0.0.1'},
            self_fence_installed=True)
    mgr = pve()
    assert mgr.ha_enabled is True and mgr.ha_failure_threshold == 3
    assert mgr.ha_config['recovery_delay'] == 45
    assert mgr.ha_config['verify_network_before_recovery'] is False
    assert mgr.ha_config['node_ips'] == {'pve1': '10.0.0.1'}
    assert mgr.ha_config['self_fence_installed'] is True
    assert mgr.ha_config['quorum_enabled'] is True and mgr.ha_config['node_timeout'] == 60
    assert 'fence_strategy' not in mgr.ha_config
    # read back from the stored settings since S6 (it was saved and never loaded)
    assert mgr.ha_config['pegaprox_vmid'] == ''


# --- a sync that commits and then fails -------------------------------------------------

def _serve_host_change(env):
    """The active moved pve1 to 10.0.0.9 and has a known_hosts file; this standby still
    holds 10.0.0.1 (the same database plays both)."""
    with open(ha.KNOWN_HOSTS_FILE, 'w') as fh:
        fh.write('10.0.0.1 ssh-ed25519 AAAA\n')
    _update(env.db, 'clusters', 'pve1', host='10.0.0.9')
    env.serving[0] = json.loads(json.dumps(ha.build_snapshot(meta=_active_meta(), stuck=[]),
                                           default=str))
    assert 'ssh_known_hosts' in env.serving[0]['files']
    _update(env.db, 'clusters', 'pve1', host='10.0.0.1')
    assert ha.manager_signature() == ha._run['signature']


@pytest.mark.parametrize('blocker', ['read-only leftover', 'directory'])
def test_a_host_key_file_that_cannot_be_written_leaves_the_sync_applied(env, blocker):
    _standby_with_managers(env)
    env.clock.advance(300)
    _serve_host_change(env)
    tmp = ha.KNOWN_HOSTS_FILE + '.ha-tmp'
    if blocker == 'directory':
        os.mkdir(tmp)
    else:
        with open(tmp, 'w') as fh:
            fh.write('x')
        os.chmod(tmp, 0o400)
    if blocker != 'directory' and os.access(tmp, os.W_OK):
        pytest.skip('running as root: a read-only file is still writable')
    try:
        assert ha.pull_once() == 'applied'
        assert env.db.get_all_clusters()['pve1']['host'] == '10.0.0.9'
        sync = ha.public_status()['sync']
        assert sync['reload_pending']['reason'] == '1 cluster changed'
        assert sync['last_error'].startswith('The configuration was applied, but the SSH host key pins')
        assert sync['last_ok_at']
        # held less than the whole snapshot: the next poll fetches it all again
        assert ha._load()['sync'].get('etag') is None
        env.clock.advance(ha.RELOAD_SETTLE)
        assert ha.pull_once() == 'applied'
        assert env.reloads == [([], [], ['cluster:pve1'])]
    finally:
        if os.path.isdir(tmp):
            os.rmdir(tmp)
        else:
            os.chmod(tmp, 0o600)
            os.remove(tmp)

    # the file can be written again: written, the note gone, the etag kept
    assert ha.pull_once() == 'applied'
    with open(ha.KNOWN_HOSTS_FILE, encoding='utf-8') as fh:
        assert fh.read() == env.serving[0]['files']['ssh_known_hosts']
    assert ha._load()['sync']['last_error'] == ''
    assert ha._load()['sync']['etag'] == env.serving[0]['etag']


def test_a_failure_after_the_commit_still_notes_the_new_connection(env, monkeypatch):
    """Whatever fails once the rows are in, the managers are compared against them."""
    _standby_with_managers(env)
    env.clock.advance(300)
    real = ha._finish_pull

    def no_note(sid, sync, member=None):
        # the note of a pull that got its rows in; the one of a failure goes through
        if 'last_ok_at' in sync:
            raise OSError('No space left on device')
        return real(sid, sync, member)
    monkeypatch.setattr(ha, '_finish_pull', no_note)

    assert _sync(env, lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'failed'
    assert ha._run['reload']['reason'] == '1 cluster changed'
    env.clock.advance(ha.RELOAD_SETTLE)
    assert ha.pull_once() == 'failed'
    assert env.reloads == [([], [], ['cluster:pve1'])]


def test_a_sync_that_fails_before_the_commit_notes_nothing(env, monkeypatch):
    """Counterproof: rolled back, nothing changed, nothing to compare."""
    _standby_with_managers(env)
    env.clock.advance(300)
    seen = []
    monkeypatch.setattr(ha, '_after_sync_applied', lambda: seen.append(1))
    _update(env.db, 'clusters', 'pve1', host='10.0.0.9')
    snap = json.loads(json.dumps(ha.build_snapshot(meta=_active_meta(), stuck=[]), default=str))
    snap['key_fp'] = 'another key'          # refused before a single row is written
    env.serving[0] = snap
    assert ha.pull_once() == 'failed' and seen == []


# --- PegaProx node maintenance on a standby -----------------------------------------------

def _maintenance_standby(env, pve):
    from pegaprox.models.tasks import MaintenanceTask
    _be('standby')
    _seed_all(env.db)
    env.db.save_node_maintenance('pve1', 'pve1')
    assert _sync(env) == 'applied'
    mgr = pve()
    mgr._restore_persisted_maintenance()     # what start() does
    # one the manager's own poll found in PVE's HA maintenance, not in the table
    found = MaintenanceTask('pve3')
    found.native_ha, found.status, found._discovered_by_refresh = True, 'completed', True
    mgr.nodes_in_maintenance['pve3'] = found
    g.cluster_managers['pve1'] = mgr
    _started(env)
    env.clock.advance(300)
    return mgr, found


def test_node_maintenance_on_a_standby_follows_the_sync(env, pve):
    mgr, found = _maintenance_standby(env, pve)
    assert set(mgr.nodes_in_maintenance) == {'pve1', 'pve3'}

    def change():
        # on the active: pve1 out of maintenance, pve2 into it
        env.db.remove_node_maintenance('pve1', 'pve1')
        env.db.save_node_maintenance('pve1', 'pve2')
    assert _sync(env, change) == 'applied'

    assert set(mgr.nodes_in_maintenance) == {'pve2', 'pve3'}
    entered = mgr.nodes_in_maintenance['pve2']
    assert (entered.status, entered.native_ha, entered._restored) == ('completed', False, True)
    assert not getattr(entered, '_discovered_by_refresh', False)
    assert mgr.nodes_in_maintenance['pve3'] is found

    # native HA maintenance on the same node: the same entry, now marked so
    assert _sync(env, lambda: env.db.save_node_maintenance('pve1', 'pve2', native_ha=True)) == 'applied'
    assert mgr.nodes_in_maintenance['pve2'] is entered and entered.native_ha is True

    # a view, not a new connection
    assert ha.public_status()['sync']['reload_pending'] is None
    env.clock.advance(3600)
    assert _poll(env) == 'unchanged' and env.reloads == [] and env.restarts == []


def test_node_maintenance_is_left_alone_where_this_instance_acts(env, pve):
    """Counterproof: an active's own routes write the table and its set."""
    mgr, _found = _maintenance_standby(env, pve)
    _switch_role('active')
    env.db.remove_node_maintenance('pve1', 'pve1')
    env.db.save_node_maintenance('pve1', 'pve2')
    assert mgr._follow_persisted_maintenance() == 0
    ha._refresh_managers()
    assert set(mgr.nodes_in_maintenance) == {'pve1', 'pve3'}


# --- the recovery worker right before the poison pill and each VM start -------------------

def _recovery(env, monkeypatch):
    import pegaprox.core.manager as mgrmod
    naps = []
    monkeypatch.setattr(mgrmod, 'time', types.SimpleNamespace(sleep=naps.append))
    return mgrmod, naps


def _step_down(result):
    def side(*a, **kw):
        _switch_role('standby')
        return result
    return side


@pytest.mark.parametrize('step_down', [False, True], ids=['active-throughout', 'during-the-ssh-stop'])
def test_no_poison_pill_after_a_step_down_during_the_ssh_stop(step_down, env, monkeypatch):
    """The node answers SSH with VMs running, the SSH stop fails and the storage
    heartbeat is on: the pill is next. A step-down while the stop ran leaves it out."""
    mgrmod, naps = _recovery(env, monkeypatch)
    _be('active')
    fake = _recovery_fake()
    fake._ha_ssh_stop_vms_on_node.side_effect = _step_down(False) if step_down else None
    fake._ha_ssh_stop_vms_on_node.return_value = False
    fake._ha_write_poison_pill.return_value = True

    mgrmod.PegaProxManager._ha_recovery_worker(fake, 'pve2')

    assert fake._ha_ssh_stop_vms_on_node.call_count == 1
    if step_down:
        assert fake._ha_write_poison_pill.call_count == 0
        assert naps.count(30) == 1          # the recovery delay, not the pill's wait
        assert fake._ha_fence_node.call_count == 0 and fake._ha_start_vm_on_node.call_count == 0
    else:
        assert fake._ha_write_poison_pill.call_count == 1
        assert naps.count(30) == 2
        assert fake._ha_start_vm_on_node.call_count == 2


@pytest.mark.parametrize('where', ['storage-check', 'target-choice'])
def test_no_vm_start_after_a_step_down_during_the_reads_before_it(where, env, monkeypatch):
    mgrmod, _naps = _recovery(env, monkeypatch)
    _be('active')
    fake = _recovery_fake()
    fake._ha_check_node_via_ssh.return_value = {'reachable': False}
    if where == 'storage-check':
        fake._ha_check_vm_storage.side_effect = _step_down('shared')
    else:
        fake._ha_select_target_node.side_effect = _step_down('pve1')

    mgrmod.PegaProxManager._ha_recovery_worker(fake, 'pve2')

    assert ha.role() == 'standby'
    assert fake._ha_start_vm_on_node.call_count == 0
    assert fake._ha_check_vm_storage.call_count == 1


def test_every_vm_starts_while_this_instance_stays_active(env, monkeypatch):
    mgrmod, _naps = _recovery(env, monkeypatch)
    _be('active')
    fake = _recovery_fake()
    fake._ha_check_node_via_ssh.return_value = {'reachable': False}
    mgrmod.PegaProxManager._ha_recovery_worker(fake, 'pve2')
    assert [c.args[0] for c in fake._ha_start_vm_on_node.call_args_list] == [100, 101]


# --- the Prometheus exporter ----------------------------------------------------------------

def _scraped_cluster(api):
    m = api.make_fake_manager(
        'pve1',
        get_node_status={'pve1': {'status': 'online', 'cpu': 0.1, 'mem_percent': 5, 'uptime': 10}},
        get_vm_resources=[], get_node_apt_updates=[],
        get_ceph_health_summary={'status': 'HEALTH_OK', 'osd_up': 3, 'osd_in': 3})
    m.is_connected = True
    m.config.name = 'Lab'
    return api.set_manager('pve1', m)


@pytest.mark.parametrize('which', ['standby', 'active'])
def test_a_scrape_runs_the_ceph_probe_only_where_this_instance_acts(which, ha_env, monkeypatch):
    import pegaprox.api.metrics_exporter as mx
    (_standby_of_active if which == 'standby' else _active_with_standby)(ha_env)
    real = mx.load_server_settings
    monkeypatch.setattr(mx, 'load_server_settings', lambda: dict(real(), metrics_public=True))
    mgr = _scraped_cluster(ha_env.api)

    for _ in range(2):
        r = ha_env.api.anon().get('/api/metrics')
        assert r.status_code == 200, r.data[:200]
    body = r.get_data(as_text=True)

    # the API side is there in both roles
    assert 'pegaprox_node_online{cluster_id="pve1",cluster="Lab",node="pve1"} 1' in body
    if which == 'standby':
        assert mgr.get_ceph_health_summary.call_count == 0
        assert 'pegaprox_ceph_health_status{' not in body
    else:
        assert mgr.get_ceph_health_summary.call_count == 2
        assert 'pegaprox_ceph_health_status{cluster_id="pve1",cluster="Lab"} 0' in body


# --- the ESXi VM detail watch ---------------------------------------------------------------

@pytest.mark.parametrize('which', ['standby', 'active'])
def test_the_esxi_vm_watch_is_open_on_a_standby(which, ha_env, seed, monkeypatch):
    from pegaprox.background.broadcast import broadcast_resources_loop
    admin = _admin(ha_env.api, seed)
    powered = []
    g.vmware_managers['v1'] = types.SimpleNamespace(
        name='Farm', host='10.0.3.1', linked_clusters=[], connected=True,
        vm_power_action=lambda vm_id, action: powered.append((vm_id, action)) or {'success': True})
    watched = {}
    monkeypatch.setattr(broadcast_resources_loop, '_vmw_watched', watched, raising=False)
    (_standby_of_active if which == 'standby' else _active_with_standby)(ha_env)

    r = admin.post('/api/vmware/v1/vms/vm-1/watch', json={})
    assert r.status_code == 200 and r.get_json()['watching'] == 'vm-1', r.data
    assert list(watched) == [('v1', 'vm-1')]
    r = admin.delete('/api/vmware/v1/vms/vm-1/watch')
    assert r.status_code == 200 and watched == {}, r.data

    # counterproof: acting on the same VM is still the active's
    r = admin.post('/api/vmware/v1/vms/vm-1/power/start', json={})
    if which == 'standby':
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
        assert powered == []
    else:
        assert r.status_code == 200 and powered == [('vm-1', 'start')], r.data


# --- the cluster list with an ESXi host registered for XHM -----------------------------------

def _esxi_host(**kw):
    from pegaprox.core.esxi_cluster import ESXiClusterManager
    vmw = types.SimpleNamespace(host='10.0.3.1', username='root', password='pw', ssl_verify=False,
                                connected=True, name='Old farm', api_version='8.0', enabled=True,
                                last_error=None)
    vars(vmw).update(kw)
    return vmw, ESXiClusterManager('esx1', vmw)


@pytest.mark.parametrize('which', ['standby', 'active'])
def test_the_cluster_list_shows_an_esxi_host(which, ha_env, seed):
    (_standby_of_active if which == 'standby' else _active_with_standby)(ha_env)
    vmw, esxi = _esxi_host()
    g.cluster_managers['esx1'] = esxi
    admin = _admin(ha_env.api, seed)

    r = admin.get('/api/clusters')

    assert r.status_code == 200, r.data[:300]
    row = next(c for c in r.get_json() if c['id'] == 'esx1')
    assert (row['name'], row['cluster_type'], row['connected'], row['host']) == \
        ('Old farm', 'esxi', True, '10.0.3.1')
    assert (row['ha_enabled'], row['auto_migrate'], row['fallback_hosts']) == (False, False, [])
    # renamed in place (an HA sync does that to the VMware manager): the list follows
    vmw.name, vmw.connected, vmw.last_error = 'New farm', False, 'Connection refused'
    row = next(c for c in admin.get('/api/clusters').get_json() if c['id'] == 'esx1')
    assert (row['name'], row['connected'], row['connection_error']) == \
        ('New farm', False, 'Connection refused')


def test_save_config_leaves_an_esxi_host_out_of_the_clusters_table(env):
    """It lives in vmware_servers. A clusters row for it would come back at the next start
    as a Proxmox manager aimed at the ESXi host."""
    from pegaprox.core.config import save_config
    from pegaprox.models.tasks import PegaProxConfig
    _be('active')
    _seed_all(env.db)
    pve_cfg = PegaProxConfig(env.db.get_all_clusters()['pve1'])
    pve_cfg.name = 'Lab renamed'
    g.cluster_managers.update(pve1=types.SimpleNamespace(config=pve_cfg, cluster_type='proxmox'),
                              esx1=_esxi_host()[1])

    assert save_config() is True

    rows = env.db.get_all_clusters()
    assert 'esx1' not in rows and rows['pve1']['name'] == 'Lab renamed'


def test_two_pulls_never_apply_side_by_side(monkeypatch):
    """(#625 v2 CodeAnt) "Sync now" and the loop both call pull_once. Side by side
    they applied the same snapshot twice at once, and the file writes share their
    temporary names."""
    import threading
    import time
    from pegaprox.core import ha
    inside, overlap = [], []

    def slow_pull(timeout):
        if inside:
            overlap.append(True)
        inside.append(1)
        time.sleep(0.2)
        inside.pop()
        return 'unchanged'
    monkeypatch.setattr(ha, '_pull', slow_pull)
    monkeypatch.setattr(ha, '_reload_if_due', lambda: False)

    results = []
    threads = [threading.Thread(target=lambda: results.append(ha.pull_once(timeout=5))) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ['unchanged'] * 3
    assert overlap == []
