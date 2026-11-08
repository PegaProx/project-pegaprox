# -*- coding: utf-8 -*-
"""V2P migration hardening (#1106, #1097, #1098). NS Oct 2026.

These exercise the core/v2p transfer code directly - no PVE node, no ESXi host - by
feeding the descriptor validator a fake node-exec and reading the migration task's own
redaction and the module source for the removed netcat path.
"""
import inspect
import types

import pegaprox.core.v2p as v2p


# --------------------------------------------------------------------------- #1106
# A VMDK descriptor is read as root by qemu-img/qm. Only a descriptor whose extents are
# plain files in its own directory may be used as the copy source.

_GOOD = (
    '# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n'
    'createType="vmfs"\n\n'
    '# Extent description\n'
    'RW 20971520 VMFS "MyVM-flat.vmdk"\n\n'
    'ddb.virtualHWVersion = "11"\n'
)


def test_a_normal_descriptor_with_a_local_extent_is_accepted(monkeypatch):
    monkeypatch.setattr(v2p, '_pve_node_exec',
                        lambda *a, **k: (0, _GOOD, '') if a[2].startswith('cat ') else (0, '', ''))
    assert v2p._descriptor_extents_are_local(object(), 'node', '/mnt/x/MyVM.vmdk') is True


def test_an_absolute_extent_path_is_refused(monkeypatch):
    bad = _GOOD.replace('"MyVM-flat.vmdk"', '"/etc/pve/priv/authkey.key"')
    monkeypatch.setattr(v2p, '_pve_node_exec',
                        lambda *a, **k: (0, bad, '') if a[2].startswith('cat ') else (0, '', ''))
    assert v2p._descriptor_extents_are_local(object(), 'node', '/mnt/x/MyVM.vmdk') is False


def test_a_parent_directory_escape_is_refused(monkeypatch):
    bad = _GOOD.replace('"MyVM-flat.vmdk"', '"../../other-guest/vm-100-disk-0-flat.vmdk"')
    monkeypatch.setattr(v2p, '_pve_node_exec',
                        lambda *a, **k: (0, bad, '') if a[2].startswith('cat ') else (0, '', ''))
    assert v2p._descriptor_extents_are_local(object(), 'node', '/mnt/x/MyVM.vmdk') is False


def test_a_protocol_prefixed_extent_is_refused(monkeypatch):
    for mal in ('"nbd://attacker/exp"', '"file:///dev/sda"', '"ssh://h/etc/hostname"'):
        bad = _GOOD.replace('"MyVM-flat.vmdk"', mal)
        monkeypatch.setattr(v2p, '_pve_node_exec',
                            lambda *a, **k: (0, bad, '') if a[2].startswith('cat ') else (0, '', ''))
        assert v2p._descriptor_extents_are_local(object(), 'node', '/mnt/x/MyVM.vmdk') is False, mal


def test_a_descriptor_with_no_extent_line_is_refused(monkeypatch):
    monkeypatch.setattr(v2p, '_pve_node_exec',
                        lambda *a, **k: (0, 'version=1\nCID=1\n', '') if a[2].startswith('cat ') else (0, '', ''))
    assert v2p._descriptor_extents_are_local(object(), 'node', '/mnt/x/MyVM.vmdk') is False


# --------------------------------------------------------------------------- #1097
# The unauthenticated-netcat transfer must be gone from both copy paths.

def test_no_netcat_listener_in_the_transfer_code():
    src = inspect.getsource(v2p)
    assert 'nc -l' not in src, 'an unauthenticated netcat listener is still in the transfer path'
    assert "which nc " not in src, 'ESXi nc capability is still probed - the nc path lingers'


def test_the_ssh_stream_is_still_present():
    """The data still moves - the SSH+compress pipe that followed nc is the method now."""
    src = inspect.getsource(v2p)
    assert 'SSH+' in src and 'ssh_fast' in src


# --------------------------------------------------------------------------- #1098
# ESXi credentials never reach the task log or the stored error.

def _bare_task():
    t = object.__new__(v2p.V2PMigrationTask)
    t.id = 'testmig'
    t.log_lines = []
    t.esxi_password = 'S3cr3t!pw'
    t.phase = 'transfer'
    t.progress = 0
    return t


def test_the_log_redacts_the_esxi_password():
    t = _bare_task()
    t.log("qemu-img: https://root:S3cr3t!pw@esxi/folder failed")
    assert 'S3cr3t!pw' not in t.log_lines[-1]
    assert '********' in t.log_lines[-1]


def test_the_log_redacts_the_url_encoded_form():
    import urllib.parse
    t = _bare_task()
    enc = urllib.parse.quote('S3cr3t!pw', safe='')
    t.log(f"url=https://root:{enc}@esxi/x")
    assert enc not in t.log_lines[-1]


def test_an_empty_password_leaves_the_line_intact():
    t = _bare_task()
    t.esxi_password = ''
    t.log('ordinary line, nothing to hide')
    assert t.log_lines[-1].endswith('ordinary line, nothing to hide')


def test_the_https_boot_url_carries_no_basic_auth():
    """The credential moved out of the args: line into a root-only secret file."""
    src = inspect.getsource(v2p._do_sshfs_boot_migration)
    assert 'password-secret' in src, 'HTTPS boot no longer uses a QEMU secret object'
    assert '{url_user}:{url_pass}@' not in src, 'the password is still inlined in the URL'
    assert 'password-secret' in src and 'file.username' in src
