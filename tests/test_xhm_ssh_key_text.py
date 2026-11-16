"""A cross-hypervisor migration logs in to the Proxmox node with the cluster's stored key.

The three transfers (XCP-ng to PVE, PVE to XCP-ng, ESXi to PVE) hand _connect_ssh the
cluster's config.ssh_key as key_path. That is the key's text, decrypted from the
database, not a file: os.path.exists() said no, and the key was never offered. A cluster
with SSH by key only failed with "no SSH password to offer", one with a password fell
back to it without a word. A key given as text is now loaded and offered as it is; a
key file still goes by its path. With SSH switched off for the cluster no transfer logs
in at all, key or no key.

MK Nov 2026
"""
import io

import paramiko
import pytest

from pegaprox.core import xhm


@pytest.fixture
def tried(monkeypatch):
    from pegaprox.utils import ssh_security
    got = []
    monkeypatch.setattr(paramiko.SSHClient, 'connect', lambda self, *a, **kw: got.append(kw))
    monkeypatch.setattr(ssh_security, 'apply_host_key_policy', lambda client, _p: client)
    monkeypatch.setattr(ssh_security, 'persist_host_keys', lambda client: None)
    return got


def _key_text():
    buf = io.StringIO()
    paramiko.RSAKey.generate(1024).write_private_key(buf)
    return buf.getvalue()


def test_the_stored_key_text_is_offered(tried):
    xhm._connect_ssh('10.0.0.8', 'root', '', key_path=_key_text())
    assert len(tried) == 1
    assert isinstance(tried[0]['pkey'], paramiko.RSAKey)
    assert tried[0]['allow_agent'] is False and tried[0]['look_for_keys'] is False


def test_a_key_file_still_goes_by_its_path(tried, tmp_path):
    path = tmp_path / 'id_rsa'
    path.write_text(_key_text())
    xhm._connect_ssh('10.0.0.8', 'root', '', key_path=str(path))
    assert len(tried) == 1 and tried[0]['key_filename'] == str(path) and 'pkey' not in tried[0]


def test_text_that_is_no_key_offers_nothing(tried):
    with pytest.raises(Exception, match='no SSH password'):
        xhm._connect_ssh('10.0.0.8', 'root', '', key_path='-----BEGIN NOTHING-----\n')
    assert tried == []


class _Cluster:
    """A connected cluster with a key stored, SSH switched off or on."""
    is_connected = True
    host = '10.0.0.9'

    def __init__(self, off):
        self.config = type('cfg', (), {'ssh_disabled': off, 'ssh_key': _key_text(),
                                       'pass_': 'pw', 'user': 'root@pam'})()

    def _api(self):
        return None

    def get_vm_config(self, node, vmid, kind):
        return {'success': False, 'error': 'stopped by the test'}

    def get_vm_disks_for_export(self, vmid):
        return {'data': {'name': 'web01', 'disks': [
            {'vmdk_file': '[datastore1] web01/web01.vmdk', 'capacity_bytes': 1 << 30}]}}


def _run(monkeypatch, direction, src_off=False, tgt_off=False):
    tried = []

    def connect(*a, **kw):
        tried.append(kw)
        raise RuntimeError('stopped by the test')
    monkeypatch.setattr(xhm, '_connect_ssh', connect)
    monkeypatch.setattr(xhm, '_resolve_pve_node_ip', lambda mgr, n: '10.0.0.9')
    monkeypatch.setattr(xhm, '_next_pve_vmid', lambda mgr: 900)
    monkeypatch.setitem(xhm.cluster_managers, 'src', _Cluster(src_off))
    monkeypatch.setitem(xhm.cluster_managers, 'tgt', _Cluster(tgt_off))
    task = xhm.XHMigrationTask(mid='deadbeef', direction=direction, source_cluster='src',
                               source_node='n1', source_vmid=100, target_cluster='tgt',
                               target_node='n2', target_storage='local-lvm')
    getattr(xhm, f'_run_{direction}')(task)
    return task, tried


@pytest.mark.parametrize('direction,pve', [('xcpng_to_pve', 'target'), ('pve_to_xcpng', 'source'),
                                           ('esxi_to_pve', 'target')])
def test_a_transfer_with_ssh_switched_off_stops_before_it_starts(monkeypatch, direction, pve):
    task, tried = _run(monkeypatch, direction, src_off=pve == 'source', tgt_off=pve == 'target')
    assert task.phase == 'failed' and tried == []
    assert f'SSH is switched off for the {pve} Proxmox cluster' in task.error, task.error
    # counterproof: with SSH on the run goes on (to its planning, stopped there)
    task, _tried = _run(monkeypatch, direction)
    assert task.phase == 'failed' and 'SSH is switched off' not in task.error


def test_the_stored_key_does_not_log_in_with_ssh_switched_off(monkeypatch):
    """An ESXi import driven up to the login on the node: the key is offered with SSH on,
    and nothing is with SSH off."""
    task, tried = _run(monkeypatch, 'esxi_to_pve')
    assert len(tried) == 1 and tried[0]['key_path'].startswith('-----BEGIN')
    task, tried = _run(monkeypatch, 'esxi_to_pve', tgt_off=True)
    assert tried == [] and task.phase == 'failed'
