"""IO Thread and the cache mode of the migration dialog reach the migrated disks (#1270).

Both were read into the task and never used again, so every disk came out without
iothread=1 and with PVE's default cache, whatever the Advanced tab said. PVE runs a disk in
its own IO thread only on VirtIO Block or on SCSI behind virtio-scsi-single, so the flag
goes on there only. The cache mode is one of PVE's literal tokens or nothing, since it lands
in a root `qm set`, and native AIO with a cache mode that drops O_DIRECT is refused at the
start: the guest would not boot with it.

The migrations run against the ESXi host and Proxmox node of test_v2p_tpm_and_folder_copy.
"""
import inspect
import re

import pytest

import pegaprox.core.v2p as v2p
from test_v2p_tpm_and_folder_copy import Run, VMID
from test_sec_migrations_paths import V2P, _v2p_body, v2p_route  # noqa: F401


def _run(monkeypatch, extra, **kw):
    """One migration whose dialog sent `extra` on top of the harness config."""
    orig = v2p.V2PMigrationTask

    def task(*a, config=None, **k):
        return orig(*a, config={**config, **extra}, **k)
    monkeypatch.setattr(v2p, 'V2PMigrationTask', task)
    if kw.get('mode') == 'snapshot_zero':
        monkeypatch.setattr(v2p, '_snapshot_zero_v2p_delta_loop', lambda *a, **k: (True, 1, []))
    r = Run(monkeypatch, **kw).go()
    assert r.task.status == 'completed', r.task.error
    return r


def _attach_opts(r, bus='scsi'):
    """{disk: [options]} of the final attaches of the run"""
    out = {}
    for c in r.nodecmds():
        m = re.match(rf'qm set {VMID} --({bus}\d+) \S+?((?:,[^ ,]+)*) 2>&1$', c)
        if m:
            out[m.group(1)] = [o for o in m.group(2).split(',') if o]
    assert out, r.nodecmds()
    return out


@pytest.mark.parametrize('kw', [dict(mode='offline'), dict(mode='vmkfstools_clone'),
                                dict(mode='auto', clone_snap_fails=True),
                                dict(mode='snapshot_zero'),
                                dict(mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed')],
                         ids=lambda kw: kw['mode'])
def test_every_transfer_mode_attaches_with_the_io_thread_and_the_cache_mode(monkeypatch, kw):
    r = _run(monkeypatch, {'scsihw': 'virtio-scsi-single', 'disk_iothread': True,
                           'disk_cache': 'writeback'}, **kw)
    assert _attach_opts(r) == {'scsi0': ['iothread=1', 'cache=writeback'],
                               'scsi1': ['iothread=1', 'cache=writeback']}


@pytest.mark.parametrize('extra,bus', [
    ({'scsihw': 'virtio-scsi-single'}, 'scsi'),
    ({'disk_bus': 'virtio'}, 'virtio'),
], ids=['scsi-on-virtio-scsi-single', 'virtio-block'])
def test_the_io_thread_goes_on_where_pve_runs_one(monkeypatch, extra, bus):
    r = _run(monkeypatch, {'disk_iothread': True, 'disk_cache': 'none', **extra})
    assert _attach_opts(r, bus) == {f'{bus}0': ['iothread=1'], f'{bus}1': ['iothread=1']}


@pytest.mark.parametrize('extra,bus', [
    ({'scsihw': 'virtio-scsi-pci'}, 'scsi'),
    ({}, 'scsi'),                                   # the source's controller, pvscsi here
    ({'disk_bus': 'sata', 'scsihw': 'virtio-scsi-single'}, 'sata'),
    ({'scsihw': 'virtio-scsi-single', 'disk_iothread': False}, 'scsi'),
    ({'scsihw': 'virtio-scsi-single', 'disk_iothread': 'false'}, 'scsi'),
], ids=['virtio-scsi-pci', 'pvscsi', 'sata', 'switched-off', 'switched-off-as-text'])
def test_no_io_thread_elsewhere(monkeypatch, extra, bus):
    r = _run(monkeypatch, {'disk_iothread': True, 'disk_cache': 'none', **extra})
    assert _attach_opts(r, bus) == {f'{bus}0': [], f'{bus}1': []}


def _opts(**cfg):
    return v2p.V2PMigrationTask('t1', 'vw1', 'vm-42', 'pve-cl', 'pve1', 'local-lvm',
                                config={'disk_iothread': False, **cfg})._disk_attach_opts()


@pytest.mark.parametrize('cache,want', [
    ('none', ''), ('', ''), (None, ''),
    ('WriteThrough', ',cache=writethrough'), ('directsync', ',cache=directsync'),
    ('unsafe', ',cache=unsafe'),
    ('writeback;reboot', ''), ('writeback,discard=on', ''), ('writeback ', ',cache=writeback'),
    (['writeback'], ''),
], ids=repr)
def test_the_cache_mode_is_a_pve_token_or_nothing(cache, want):
    assert _opts(disk_cache=cache) == want


def test_cache_and_aio_go_on_together():
    assert _opts(disk_cache='directsync', aio_mode='native') == ',cache=directsync,aio=native'


def test_every_attach_of_a_final_disk_carries_the_drive_options():
    # the rescue of an unused volume attaches a final disk too, and a bare attach drops them
    attaches = re.findall(r'qm set \{task\.proxmox_vmid\} --\{disk_bus\}\{\w+\} \{\w*vol\w*\}(\S*)',
                          inspect.getsource(v2p))
    assert len(attaches) >= 11, attaches
    assert [a for a in attaches if not a.startswith('{task._disk_attach_opts()}')] == []


# -- the start of the migration --------------------------------------------------------------

@pytest.mark.parametrize('body', [
    {'disk_cache': 'writeback;reboot'}, {'disk_cache': 'fast'}, {'disk_cache': ['none']},
    {'aio_mode': 'native', 'disk_cache': 'writeback'},
    {'aio_mode': 'native', 'disk_cache': 'writethrough'},
    {'aio_mode': 'native', 'disk_cache': 'unsafe'},
], ids=repr)
def test_a_cache_mode_the_disk_cannot_run_with_starts_nothing(api, seed, v2p_route, body):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(V2P, json=_v2p_body(**body))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'disk_cache' in r.get_json()['error'] or 'native' in r.get_json()['error']
    assert v2p_route == []


@pytest.mark.parametrize('body,cache', [
    ({}, ''), ({'disk_cache': 'none'}, 'none'),
    ({'aio_mode': 'native', 'disk_cache': 'none'}, 'none'),
    ({'aio_mode': 'native', 'disk_cache': 'directsync'}, 'directsync'),
    ({'aio_mode': 'native'}, ''),
    ({'aio_mode': 'threads', 'disk_cache': 'writeback'}, 'writeback'),
    ({'disk_cache': 'WriteBack'}, 'writeback'),
], ids=repr)
def test_a_cache_mode_the_disk_runs_with_reaches_the_task(api, seed, v2p_route, body, cache):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(V2P, json=_v2p_body(**body))
    assert r.status_code == 202, r.get_data(as_text=True)
    # nothing chosen and none are the same disk
    assert (v2p_route[0].disk_cache or 'none') == (cache or 'none')
