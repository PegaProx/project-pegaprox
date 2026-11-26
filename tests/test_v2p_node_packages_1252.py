"""#1252 - an ESXi migration asks before it installs packages on the target node.

It used to run apt-get at nine places of core/v2p.py, each with its own list, and said so
in the log once it was running. Every install now goes through one helper with one map of
what each feature needs (core/v2p_packages.py), and allow_package_install false makes the
run install nothing: a package it needs is missing, it stops before ESXi or Proxmox
changed, with the node, the packages and the apt command. The review (a dry run) and a
bulk check ask the target node once which of them it has.

The scripts run in a real bash here, with apt-get, dpkg-query and the tools as stand-ins
on a PATH of their own. The runs use the hosts of tests/test_v2p_tpm_and_folder_copy.py,
the routes those of tests/test_esxi_mapping_verify.py and tests/test_esxi_bulk.py.
MK Nov 2026
"""
import ast
import os
import pathlib
import re
import shutil
import subprocess
import time
import types

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import v2p_packages as pk

import test_v2p_tpm_and_folder_copy as farm
from test_esxi_mapping_verify import route  # noqa: F401 (fixture)
from test_esxi_bulk import env  # noqa: F401 (fixture)

_V2P_SRC = (pathlib.Path(__file__).resolve().parent.parent / 'pegaprox' / 'core' / 'v2p.py').read_text()
EVERY = [p for f in pk.NODE_PACKAGES for p in pk.packages_of(f)]


# --------------------------------------------------------------------------- the map

def test_every_package_has_a_check_and_every_feature_says_what_it_is_for():
    for feature, ent in pk.NODE_PACKAGES.items():
        assert ent['packages'] and ent['purpose'], feature
        for p in ent['packages']:
            assert pk.PACKAGE_CHECKS.get(p), p
    assert len(EVERY) == len(set(EVERY)), 'a package belongs to one feature'


def test_the_map_never_asks_for_qemu_utils():
    """qemu-utils conflicts with pve-qemu-kvm, apt would offer to take proxmox-ve with it (#520)"""
    assert 'qemu-utils' not in EVERY


def test_no_node_command_of_the_migration_installs_anything_itself():
    """Every apt-get goes through _ensure_node_packages: no string a node call gets in
    v2p.py holds one, the VirtIO node script neither."""
    tree = ast.parse(_V2P_SRC)
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '_pve_node_exec':
            for sub in ast.walk(node):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and 'apt-get' in sub.value:
                    bad.append(sub.value[:120])
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', '') == 'script' for t in node.targets):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and 'apt-get' in sub.value:
                    bad.append(sub.value[:120])
    assert not bad, bad
    assert 'mbuffer' not in ' '.join(pk.ensure_script(f) for f in pk.NODE_PACKAGES)


def _features(plan):
    return {f: needed for f, needed in plan}


@pytest.mark.parametrize('mode,needs_sshfs', [('offline', True), ('auto', True), ('sshfs_boot', True),
                                              ('vmkfstools_clone', False), ('snapshot_zero', False)])
def test_sshfs_is_needed_where_the_mode_mounts_and_optional_where_it_is_the_last_way_out(mode, needs_sshfs):
    f = _features(pk.package_plan(mode))
    assert f['sshfs'] is needs_sshfs
    assert f['sshpass'] is False, 'every copy has a key on ESXi as its other way'
    assert ('lz4' in f) is (mode in ('sshfs_boot', 'auto'))
    assert 'virtio' not in f and 'rbd' not in f


def test_the_driver_tools_come_with_prepare_virtio_and_ceph_common_with_an_rbd_boot_disk():
    f = _features(pk.package_plan('offline', install_virtio_drivers=True, boot_storage_type='lvmthin'))
    assert f['virtio'] is True and f['virtio_build'] is False and 'rbd' not in f
    f = _features(pk.package_plan('vmkfstools_clone', install_virtio_drivers=True, boot_storage_type='rbd'))
    assert f['rbd'] is True
    # the Live Mirror runs the guest on the target while it copies: no injection, no tools
    f = _features(pk.package_plan('sshfs_boot', install_virtio_drivers=True, boot_storage_type='rbd'))
    assert 'virtio' not in f and 'rbd' not in f


# --------------------------------------------------------------------------- the scripts, in bash

_FAKE_APT = r'''#!/bin/sh
echo "apt-get $*" >> "$APT_LOG"
cmd=""; pkgs=""; skip=0
for a; do
  if [ $skip = 1 ]; then skip=0; continue; fi
  case "$a" in -o) skip=1 ;; -*) ;; *) if [ -z "$cmd" ]; then cmd=$a; else pkgs="$pkgs $a"; fi ;; esac
done
[ "$cmd" = install ] || exit 0
echo "Reading package lists..."
[ "$APT_MODE" = fail ] && { echo "E: Unable to locate package$pkgs"; exit 100; }
[ "$APT_MODE" = noop ] && exit 0
for p in $pkgs; do
  b=$p; [ "$p" = libhivex-bin ] && b=hivexsh; [ "$p" = ceph-common ] && b=rbd
  printf '#!/bin/sh\nexit 0\n' > "$BIN/$b"; chmod +x "$BIN/$b"
done
echo "Setting up$pkgs ..."
'''

_FAKE_DPKG = r'''#!/bin/sh
# dpkg-query -W -f='${Status}' <pkg>, from FAKE_DPKG ("pkg=status;pkg=status")
p=$3
printf '%s\n' "$FAKE_DPKG" | tr ';' '\n' | while IFS='=' read -r n s; do
  [ "$n" = "$p" ] && printf '%s' "$s"
done
'''


class Box:
    """A node of its own: a PATH with tail, the stand-ins, and the tools in `have`."""

    def __init__(self, tmp, have=(), apt='ok', dpkg=''):
        self.bin = tmp / 'bin'
        self.bin.mkdir()
        self.apt_log = tmp / 'apt.log'
        # chmod for the stand-in apt-get: bash's command -v also finds a file that is not
        # executable, so without it an install that left no tool behind still read as done
        for tool in ('tail', 'tr', 'chmod'):
            os.symlink(shutil.which(tool), self.bin / tool)
        self._tool('apt-get', _FAKE_APT)
        self._tool('dpkg-query', _FAKE_DPKG)
        for b in have:
            self._tool(b, '#!/bin/sh\nexit 0\n')
        self.env = {'PATH': str(self.bin), 'BIN': str(self.bin), 'APT_LOG': str(self.apt_log),
                    'APT_MODE': apt, 'FAKE_DPKG': dpkg, 'LC_ALL': 'C'}

    def _tool(self, name, body):
        (self.bin / name).write_text(body)
        (self.bin / name).chmod(0o755)

    def sh(self, cmd, shell='/bin/bash'):
        p = subprocess.run([shell, '-c', cmd], env=self.env, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout, p.stderr

    def apt(self):
        return self.apt_log.read_text().splitlines() if self.apt_log.exists() else []


def test_a_present_package_is_neither_installed_nor_asked_for(tmp_path):
    box = Box(tmp_path, have=('sshfs',))
    rc, out, _ = box.sh(pk.ensure_script('sshfs'))
    assert pk.parse_ensure(rc, out, ('sshfs',))[:2] == ('PRESENT', [])
    assert box.apt() == []


def test_a_missing_package_is_installed_and_checked_again(tmp_path):
    box = Box(tmp_path, have=('python3',))
    rc, out, _ = box.sh(pk.ensure_script('lz4'))
    verdict, installed, said = pk.parse_ensure(rc, out, ('lz4',))
    assert (verdict, installed) == ('INSTALLED', ['lz4']), out
    assert box.apt() == ['apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=60 lz4']
    assert 'Setting up lz4' in said


def test_a_failed_install_keeps_the_reason_and_tries_once_more_after_an_update(tmp_path):
    box = Box(tmp_path, apt='fail')
    rc, out, _ = box.sh(pk.ensure_script('sshfs'))
    verdict, missing, said = pk.parse_ensure(rc, out, ('sshfs',))
    assert (verdict, missing) == ('FAILED', ['sshfs'])
    assert 'Unable to locate package sshfs' in said
    assert [a.split()[1] for a in box.apt()] == ['install', 'update', 'install']


def test_an_apt_run_that_went_through_without_the_tool_is_unverified(tmp_path):
    box = Box(tmp_path, apt='noop')
    rc, out, _ = box.sh(pk.ensure_script('sshpass'))
    assert pk.parse_ensure(rc, out, ('sshpass',))[:2] == ('UNVERIFIED', ['sshpass'])


def test_without_installs_the_script_only_names_what_is_missing(tmp_path):
    box = Box(tmp_path, have=('ntfs-3g', 'ntfsfix'))
    script = pk.ensure_script('virtio', install=False)
    assert 'apt-get' not in script
    rc, out, _ = box.sh(script)
    assert pk.parse_ensure(rc, out, pk.packages_of('virtio'))[:2] == ('MISSING', ['python3-hivex'])
    assert box.apt() == []


def test_only_the_missing_packages_of_a_feature_are_installed(tmp_path):
    box = Box(tmp_path, have=('ntfs-3g', 'ntfsfix'))
    rc, out, _ = box.sh(pk.ensure_script('virtio'))
    # python3 is no tool of this PATH, so the check still fails after the stand-in apt-get
    assert pk.parse_ensure(rc, out, pk.packages_of('virtio'))[0] == 'UNVERIFIED'
    assert box.apt() == ['apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=60 python3-hivex']


def test_an_answer_without_a_verdict_is_read_by_its_exit_code():
    assert pk.parse_ensure(0, '', ('sshpass',))[0] == 'PRESENT'
    assert pk.parse_ensure(1, '', ('sshpass',))[:2] == ('UNKNOWN', ['sshpass'])
    assert pk.parse_ensure(255, 'Permission denied', ('sshfs',))[2] == 'Permission denied'


# --------------------------------------------------------------------------- the probe of the review

def test_the_probe_reads_dpkg_and_counts_a_tool_from_elsewhere(tmp_path):
    box = Box(tmp_path, have=('lz4',),
              dpkg='sshfs=install ok installed;sshpass=deinstall ok config-files;ntfs-3g=install ok installed')
    rc, out, _ = box.sh(pk.probe_script(EVERY))
    found = pk.parse_probe(out, EVERY)
    assert found == {'sshfs': True, 'sshpass': False, 'python3-hivex': False, 'ntfs-3g': True,
                     'libhivex-bin': False, 'ceph-common': False, 'lz4': True}


@pytest.mark.parametrize('out', [
    '',
    'UPID:pve1:1:2:create',
    'V2P_PKG sshfs installed\n',                                 # cut off before its end
    'V2P_PKG sshfs installed\nV2P_PKG_PROBE_END\n',              # a package without a line
])
def test_a_probe_that_did_not_run_to_its_end_is_unknown_and_never_nothing_missing(out):
    assert pk.parse_probe(out, ['sshfs', 'sshpass']) is None


def _answer(have):
    """A node exec that answers the probe as a node with the packages `have` would."""
    def node(mgr, n, cmd, timeout=600, **kw):
        names = re.search(r'for p in (.*?); do', cmd).group(1).split()
        lines = [f"V2P_PKG {p} {'installed' if p in have else ''}" for p in names]
        return 0, '\n'.join(lines + ['V2P_PKG_PROBE_END']) + '\n', ''
    return node


def test_the_report_lists_needed_and_optional_and_what_to_run():
    rep = pk.package_report(_answer({'sshpass'}), None, 'pve1', pk.package_plan('offline', True, 'lvmthin'),
                            allow_install=False)
    assert rep['checked'] is True and rep['node'] == 'pve1'
    assert rep['missing'] == ['sshfs', 'python3-hivex', 'ntfs-3g', 'libhivex-bin']
    assert rep['missing_needed'] == ['sshfs', 'python3-hivex', 'ntfs-3g']
    assert rep['apt_command'] == 'apt-get install --no-install-recommends sshfs python3-hivex ntfs-3g libhivex-bin'
    err, warn = pk.report_problem(rep)
    assert warn is None
    assert 'pve1' in err and 'sshfs' in err and 'python3-hivex' in err
    assert 'apt-get install --no-install-recommends sshfs python3-hivex ntfs-3g' in err
    # allowed: the same report, nothing that stops
    rep['allow_install'] = True
    assert pk.report_problem(rep) == (None, None)


@pytest.mark.parametrize('broken', ['raises', 'junk', 'refused'])
def test_a_report_the_node_did_not_answer_says_could_not_check(broken):
    def node(mgr, n, cmd, timeout=600, **kw):
        if broken == 'raises':
            raise OSError('no route to host')
        if broken == 'junk':
            return 0, 'UPID:pve1:1:2:create', ''
        return 255, '', 'root@pve1: Permission denied (publickey).'
    rep = pk.package_report(node, None, 'pve1', pk.package_plan('offline'), allow_install=False)
    assert rep['checked'] is False and rep['missing'] is None and rep['missing_needed'] is None
    assert all(it['installed'] is None for it in rep['items'])
    assert rep['error']
    err, warn = pk.report_problem(rep)
    assert err is None and 'could not be checked' in warn


# --------------------------------------------------------------------------- a migration

def _run(monkeypatch, allow=False, have=None, mode='offline', probe='answer', **config):
    """A run of the hosts of test_v2p_tpm_and_folder_copy.py; the node's package probe
    answers as a node with `have` would (None: every package)."""
    r = farm.Run(monkeypatch, mode=mode, ndisks=1, tpm=False)
    r.task.config['allow_package_install'] = allow
    for k, v in config.items():
        r.task.config[k] = v
        setattr(r.task, k, v)
    real = r.node
    have = set(EVERY) if have is None else set(have)

    def node(mgr, n, cmd, timeout=600, **kw):
        if 'dpkg-query' in cmd:
            real.log.append(('node', n, cmd))
            if probe != 'answer':
                return 1, '', "cannot run node commands on 'pve1': not a node of this cluster"
            names = re.search(r'for p in (.*?); do', cmd).group(1).split()
            return 0, ''.join(f"V2P_PKG {p} {'installed' if p in have else ''}\n" for p in names) \
                + 'V2P_PKG_PROBE_END\n', ''
        return real(mgr, n, cmd, timeout, **kw)
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    return r


def _nothing_changed(r):
    assert r.posts() == [], 'the Proxmox API was asked to change something'
    assert not [e for e in r.log if e[0] == 'esxi_api' and e[1] in ('power', 'snapshot', 'tracking', 'delete_vm')]
    assert not [c for c in r.nodecmds() if 'apt-get install' in c]
    assert r.task.proxmox_vmid is None


def test_a_run_that_may_not_install_stops_before_any_change_when_a_needed_package_is_missing(monkeypatch):
    r = _run(monkeypatch, allow=False, have={'sshpass'}).go()
    assert r.task.status == 'failed'
    err = r.task.error
    assert 'pve1' in err and 'sshfs (mounting the ESXi datastore' in err
    assert 'apt-get install --no-install-recommends sshfs' in err
    assert 'Nothing was changed on ESXi or Proxmox' in err
    _nothing_changed(r)
    assert len([c for c in r.nodecmds() if 'dpkg-query' in c]) == 1


def test_a_probe_without_an_answer_stops_a_run_that_may_not_install(monkeypatch):
    r = _run(monkeypatch, allow=False, probe='refused').go()
    assert r.task.status == 'failed'
    assert r.task.error.startswith('Cannot check the packages on target node pve1'), r.task.error
    _nothing_changed(r)


def test_a_run_that_may_not_install_goes_on_when_everything_is_there_and_never_runs_apt(monkeypatch):
    r = _run(monkeypatch, allow=False).go()
    assert r.task.status == 'completed', r.task.error
    assert not [c for c in r.nodecmds() if 'apt-get' in c]
    assert any('everything this migration uses is installed' in ln for ln in r.task.log_lines)


def test_an_optional_package_does_not_stop_a_run_that_may_not_install(monkeypatch):
    """sshpass is missing: the copies log in with a key put on ESXi instead."""
    r = _run(monkeypatch, allow=False, have=set(EVERY) - {'sshpass'}).go()
    assert r.task.status == 'completed', r.task.error
    assert any('Not installed on pve1, and this migration installs nothing: sshpass' in ln
               for ln in r.task.log_lines)
    assert not [c for c in r.nodecmds() if 'apt-get' in c]


def test_ceph_common_for_an_rbd_boot_disk_goes_through_the_flag_too(monkeypatch):
    monkeypatch.setattr(v2p, '_pve_storage_type', lambda mgr, node, storage: 'rbd')
    r = _run(monkeypatch, allow=False, have=set(EVERY) - {'ceph-common'}, install_virtio_drivers=True).go()
    assert r.task.status == 'failed'
    assert 'ceph-common (Prepare VirtIO drivers on a Ceph RBD boot disk' in r.task.error
    _nothing_changed(r)


def test_a_run_that_may_install_asks_nothing_first_and_installs_as_before(monkeypatch):
    r = farm.Run(monkeypatch, mode='offline', ndisks=1, tpm=False)
    real = r.node

    def node(mgr, n, cmd, timeout=600, **kw):
        if cmd.startswith('command -v sshfs >/dev/null 2>&1 && echo PRESENT'):
            real.log.append(('node', n, cmd))
            # the node had no sshfs: the apt-get of the script put it there
            return (0, 'Setting up sshfs ...\nINSTALLED\n', '') if 'apt-get install' in cmd else (0, 'MISSING\n', '')
        return real(mgr, n, cmd, timeout, **kw)
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    r.go()
    assert r.task.status == 'completed', r.task.error
    cmds = r.nodecmds()
    assert not [c for c in cmds if 'dpkg-query' in c], 'a run that may install has nothing to ask first'
    sshfs = [c for c in cmds if c.startswith('command -v sshfs >/dev/null 2>&1 && echo PRESENT')]
    assert len(sshfs) == 1 and 'apt-get install -y --no-install-recommends' in sshfs[0]
    assert any('Installed sshfs on pve1 (one-time)' in ln for ln in r.task.log_lines)


@pytest.mark.parametrize('value,allowed', [(None, True), (True, True), (False, False), ('false', False),
                                           ('0', False), ('yes', True)])
def test_the_flag_of_a_task(value, allowed):
    cfg = {} if value is None else {'allow_package_install': value}
    task = v2p.V2PMigrationTask('t', 'vw1', 'vm-1', 'pve-cl', 'pve1', 'local-lvm', config=cfg)
    assert v2p._package_installs_allowed(task) is allowed
    # a task built without a config at all (the VirtIO tests do that) installs as before
    assert v2p._package_installs_allowed(types.SimpleNamespace()) is True


# --------------------------------------------------------------------------- the VirtIO step

def _virtio(monkeypatch, allow, answer):
    sent = []

    def node(mgr, n, cmd, timeout=600, **kw):
        sent.append(cmd)
        if "import hivex" in cmd:
            return answer(cmd)
        return 0, '', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    task = v2p.V2PMigrationTask('tv', 'vw1', 'vm-1', 'pve-cl', 'pve1', 'local-lvm',
                                config={'install_virtio_drivers': True, 'allow_package_install': allow})
    task.proxmox_vmid = 120
    mgr = types.SimpleNamespace(host='pve1', api_port=8006,
                                _api_get=lambda *a, **k: types.SimpleNamespace(status_code=500))
    ok = v2p._inject_virtio_drivers(mgr, task)
    return ok, task, sent


def test_prepare_virtio_without_installs_says_why_and_runs_no_apt(monkeypatch):
    ok, task, sent = _virtio(monkeypatch, False, lambda cmd: (0, 'MISSING python3-hivex ntfs-3g\n', ''))
    assert ok is False
    assert not [c for c in sent if 'apt-get' in c]
    assert any('python3-hivex / ntfs-3g are not installed on the node, and this migration may not '
               'install packages' in w for w in task.warnings), task.warnings


def test_prepare_virtio_with_installs_asks_apt_for_the_tools(monkeypatch):
    ok, task, sent = _virtio(monkeypatch, True,
                             lambda cmd: (0, 'INSTALLED\n', '') if 'apt-get install' in cmd else (0, 'MISSING\n', ''))
    tools = [c for c in sent if 'import hivex' in c]
    assert len(tools) == 1 and 'apt-get install -y --no-install-recommends' in tools[0]
    assert 'python3-hivex' in tools[0] and 'ntfs-3g' in tools[0]
    assert any('Installed python3-hivex ntfs-3g on pve1' in ln for ln in task.log_lines)


def test_the_rbd_branch_asks_the_helper_and_the_node_script_installs_nothing():
    tree = ast.parse(_V2P_SRC)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_inject_virtio_drivers')
    asked = sorted((c.lineno, c.args[2].value) for c in ast.walk(fn) if isinstance(c, ast.Call)
                   and getattr(c.func, 'id', '') == '_ensure_node_packages')
    assert [f for _n, f in asked] == ['virtio', 'virtio_build', 'rbd']


# --------------------------------------------------------------------------- the SSH copy fallback

@pytest.mark.parametrize('allow,expect', [(False, 'gzip-1'), (True, 'lz4')])
def test_lz4_is_only_used_when_the_node_has_it_or_may_get_it(monkeypatch, allow, expect):
    sent = []

    def node(mgr, n, cmd, timeout=600, **kw):
        sent.append(cmd)
        if cmd.startswith('command -v lz4'):
            return (0, 'INSTALLED\n', '') if 'apt-get install' in cmd else (0, 'MISSING lz4\n', '')
        return 0, '', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    monkeypatch.setattr(v2p, '_ssh_exec', lambda h, u, p, cmd, timeout=30: (
        0, 'LZ4=/bin/lz4\nGZIP=/bin/gzip\nPIGZ=NO\nXXHASH=NO\n', '') if 'LZ4=' in cmd else (0, '', ''))
    monkeypatch.setattr(v2p, '_setup_copy_isolation', lambda *a, **k: {})
    monkeypatch.setattr(v2p, '_cleanup_copy_isolation', lambda *a, **k: None)
    monkeypatch.setattr(v2p, 'broadcast_sse', lambda *a, **k: None)
    task = v2p.V2PMigrationTask('tl', 'vw1', 'vm-1', 'pve-cl', 'pve1', 'local-lvm',
                                config={'esxi_password': 'pw', 'allow_package_install': allow})
    assert v2p._qemu_img_ssh_copy(None, task, 'esx1.lab', 'root', '/tmp/key', 'ds1', 'vm1', [], 'scsi') is True
    assert any(f'Compression: {expect}' in ln for ln in task.log_lines), task.log_lines
    assert not [c for c in sent if 'mbuffer' in c]
    assert bool([c for c in sent if 'apt-get install' in c]) is allow


# --------------------------------------------------------------------------- the review of one migration

@pytest.fixture
def probe(monkeypatch):
    """The node's answer to the package probe of a dry run: `have` is what it has."""
    state = types.SimpleNamespace(have=set(EVERY), calls=0, broken=False)

    def node(mgr, n, cmd, timeout=600, **kw):
        assert 'dpkg-query' in cmd, cmd
        state.calls += 1
        if state.broken:
            raise OSError('no route to host')
        names = re.search(r'for p in (.*?); do', cmd).group(1).split()
        return 0, ''.join(f"V2P_PKG {p} {'installed' if p in state.have else ''}\n" for p in names) \
            + 'V2P_PKG_PROBE_END\n', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    return state


def test_the_review_lists_the_packages_of_the_chosen_options(route, probe):
    r = route.post(dry_run=True, esxi_password=None)
    assert r.status_code == 200, r.get_data(as_text=True)
    p = r.get_json()
    np = p['node_packages']
    assert np['checked'] is True and np['node'] == 'pve1' and np['allow_install'] is True
    assert [(it['package'], it['needed'], it['installed']) for it in np['items']] == [
        ('sshfs', True, True), ('sshpass', False, True)]
    assert np['missing'] == [] and p['ok'] is True
    assert probe.calls == 1


def test_the_review_stops_a_run_that_may_not_install_a_missing_package(route, probe):
    probe.have = {'sshpass'}
    p = route.post(dry_run=True, esxi_password=None, allow_package_install=False).get_json()
    assert p['ok'] is False
    assert any('apt-get install --no-install-recommends sshfs' in e and 'pve1' in e for e in p['errors']), p['errors']
    # the same missing package with installs allowed: listed, nothing that stops
    p = route.post(dry_run=True, esxi_password=None).get_json()
    assert p['ok'] is True, p['errors']
    assert p['node_packages']['missing'] == ['sshfs']
    assert p['node_packages']['apt_command'] == 'apt-get install --no-install-recommends sshfs'


def test_the_review_says_could_not_check_and_never_nothing_missing(route, probe):
    probe.broken = True
    p = route.post(dry_run=True, esxi_password=None, allow_package_install=False).get_json()
    np = p['node_packages']
    assert np['checked'] is False and np['missing'] is None
    assert all(it['installed'] is None for it in np['items'])
    assert any('the packages on node pve1 could not be checked' in w for w in p['warnings']), p['warnings']


def test_the_review_lists_the_driver_tools_with_prepare_virtio(route, probe):
    p = route.post(dry_run=True, esxi_password=None, install_virtio_drivers=True).get_json()
    assert [it['package'] for it in p['node_packages']['items'] if it['needed']] == [
        'sshfs', 'python3-hivex', 'ntfs-3g']


def test_the_flag_must_be_true_or_false(route, probe):
    r = route.post(dry_run=True, esxi_password=None, allow_package_install='no')
    assert r.status_code == 400 and 'allow_package_install' in r.get_json()['error']
    assert probe.calls == 0


def test_a_start_asks_nothing_and_hands_the_flag_to_the_task(route, probe):
    r = route.post(allow_package_install=False)
    assert r.status_code == 202, r.get_data(as_text=True)
    task = route.wait_started()[0]
    assert task.config['allow_package_install'] is False
    assert v2p._package_installs_allowed(task) is False
    assert probe.calls == 0, 'the run asks for itself, the start route does not'


# --------------------------------------------------------------------------- a bulk run

def test_a_bulk_check_asks_the_node_once_for_all_its_guests(env, probe):
    r = env.post(vms=['vm-1', 'vm-2', 'vm-3'], dry_run=True, esxi_password=None)
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert probe.calls == 1
    assert d['node_packages']['checked'] is True and d['ok'] is True
    assert [it['package'] for it in d['node_packages']['items']] == ['sshfs', 'sshpass']


def test_a_bulk_run_that_may_not_install_is_refused_as_a_whole_when_a_package_is_missing(env, probe):
    probe.have = {'sshpass'}
    d = env.post(dry_run=True, esxi_password=None, allow_package_install=False).get_json()
    assert d['ok'] is False
    assert any('apt-get install --no-install-recommends sshfs' in e for e in d['errors']), d['errors']
    r = env.post(allow_package_install=False)
    assert r.status_code == 400
    time.sleep(0.05)
    assert env.runner.names() == []
    # allowed, the same node: the run starts and each guest carries the flag
    r = env.post(allow_package_install=True)
    assert r.status_code == 202, r.get_data(as_text=True)


def test_a_bulk_run_hands_the_flag_to_every_guest(env, probe):
    r = env.post(allow_package_install=False)
    assert r.status_code == 202, r.get_data(as_text=True)
    deadline = time.time() + 5
    while time.time() < deadline and len(env.runner.names()) < 1:
        time.sleep(0.02)
    task = env.runner.task(env.runner.names()[0])
    assert task.config['allow_package_install'] is False


def test_a_bulk_flag_must_be_true_or_false(env, probe):
    r = env.post(dry_run=True, esxi_password=None, allow_package_install='off')
    assert r.status_code == 400
    assert probe.calls == 0


def test_one_rbd_boot_disk_among_the_guests_of_a_bulk_check_brings_ceph_common(probe):
    """Every guest's boot disk counts: the plan of a bulk check carries the disks of all of them."""
    import pegaprox.api.vmware as vw
    data = {'target_cluster': 'pve-cl', 'target_node': 'pve1', 'target_storage': 'local-lvm',
            'transfer_mode': 'offline', 'install_virtio_drivers': True}
    plan = {'disks': [{'boot': True, 'storage': 'local-lvm'}, {'boot': False, 'storage': 'ceph'},
                      {'boot': True, 'storage': 'ceph'}],
            'available': {'storages': [{'storage': 'local-lvm', 'type': 'lvmthin'}, {'storage': 'ceph', 'type': 'rbd'}]}}
    rep, _err, _warn = vw._v2p_node_packages(data, plan)
    assert [it['package'] for it in rep['items'] if it['feature'] == 'rbd'] == ['ceph-common']
    # a data disk on rbd is no reason: only the boot disk is mapped for the drivers
    plan['disks'][2]['storage'] = 'local-lvm'
    rep, _err, _warn = vw._v2p_node_packages(data, plan)
    assert 'ceph-common' not in [it['package'] for it in rep['items']]


def test_a_bulk_check_hands_the_boot_disks_of_all_its_guests_to_the_package_check(env, probe, monkeypatch):
    import pegaprox.api.vmware as vw
    seen, real = [], vw._v2p_node_packages
    monkeypatch.setattr(vw, '_v2p_node_packages', lambda data, plan=None: (seen.append(plan), real(data, plan))[1])
    r = env.post(vms=['vm-1', 'vm-2'], dry_run=True, esxi_password=None)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert len(seen) == 1 and probe.calls == 1
    assert [d['storage'] for d in seen[0]['disks'] if d['boot']] == ['local-lvm', 'local-lvm']
    assert 'local-lvm' in [s['storage'] for s in seen[0]['available']['storages']]


def test_the_inventory_read_of_the_wizard_leaves_the_package_check_out(route, probe):
    """The wizard reads the node's bridges and storages on every target change; the package
    check is the review's, one SSH call each time would be spent for nothing."""
    r = route.post(dry_run=True, esxi_password=None, check_packages=False)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['node_packages'] is None and probe.calls == 0
    # anything but false still checks
    route.post(dry_run=True, esxi_password=None, check_packages='no')
    assert probe.calls == 1


def test_no_hint_of_the_migration_tells_the_admin_to_install_qemu_utils():
    """qemu-img comes with pve-qemu-kvm, and qemu-utils conflicts with it (#520). Two hints
    of the Live Mirror said to install it all the same."""
    said = [ln.strip() for ln in _V2P_SRC.splitlines()
            if 'qemu-utils' in ln and not ln.strip().startswith('#') and 'Do NOT' not in ln]
    assert not said, said


# --------------------------------------------------------------------------- the helpers against a shell

SHELLS = [s for s in ('/bin/bash', '/bin/sh') if os.path.exists(s)]


def _shell_node(monkeypatch, box, shell='/bin/bash'):
    """_pve_node_exec runs each command in the Box, as the node's login shell would."""
    sent = []

    def node(mgr, n, cmd, timeout=600, **kw):
        sent.append(cmd)
        return box.sh(cmd, shell)
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    return sent


def _task(allow, **config):
    return v2p.V2PMigrationTask('tb', 'vw1', 'vm-1', 'pve-cl', 'pve1', 'local-lvm',
                                config=dict(config, allow_package_install=allow))


@pytest.mark.parametrize('shell', SHELLS)
def test_the_helper_installs_in_a_shell_and_finds_it_the_next_time(tmp_path, monkeypatch, shell):
    box = Box(tmp_path)
    _shell_node(monkeypatch, box, shell)
    task = _task(True)
    assert v2p._ensure_node_packages(None, task, 'sshfs') == (True, [])
    assert box.apt() == ['apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=60 sshfs']
    assert any('Installed sshfs on pve1 (one-time)' in ln for ln in task.log_lines)
    assert v2p._ensure_node_packages(None, task, 'sshfs') == (True, [])
    assert len(box.apt()) == 1, 'the second ask found it and ran no apt-get'


@pytest.mark.parametrize('shell', SHELLS)
def test_the_helper_without_installs_names_what_is_missing_and_runs_no_apt(tmp_path, monkeypatch, shell):
    box = Box(tmp_path, have=('ntfs-3g', 'ntfsfix'))
    sent = _shell_node(monkeypatch, box, shell)
    task = _task(False)
    assert v2p._ensure_node_packages(None, task, 'virtio', trust_apt=True) == (False, ['python3-hivex'])
    assert box.apt() == [] and not [c for c in sent if 'apt-get' in c]
    assert any('python3-hivex is not installed on pve1 and installing packages is turned off' in ln
               for ln in task.log_lines), task.log_lines


def test_the_helper_takes_an_apt_run_without_the_tool_only_where_the_caller_trusts_apt(tmp_path, monkeypatch):
    box = Box(tmp_path, apt='noop')
    _shell_node(monkeypatch, box)
    task = _task(True)
    assert v2p._ensure_node_packages(None, task, 'virtio', trust_apt=True) == (True, [])
    assert v2p._ensure_node_packages(None, task, 'sshpass') == (False, ['sshpass'])
    assert any('apt-get could not install sshpass on pve1' in ln for ln in task.log_lines)


@pytest.mark.parametrize('shell', SHELLS)
def test_the_refusal_of_a_run_reads_the_probe_of_a_shell(tmp_path, monkeypatch, shell):
    box = Box(tmp_path, have=('sshpass',), dpkg='sshpass=install ok installed;sshfs=deinstall ok config-files')
    sent = _shell_node(monkeypatch, box, shell)
    task = _task(False, transfer_mode='offline')
    why = v2p._node_packages_refusal(None, task)
    assert why and 'pve1' in why and 'sshfs (mounting the ESXi datastore' in why, why
    assert 'apt-get install --no-install-recommends sshfs)' in why and 'sshpass' not in why
    assert len(sent) == 1 and box.apt() == []
    # sshfs from elsewhere (dpkg still says config-files): the run goes on
    box._tool('sshfs', '#!/bin/sh\nexit 0\n')
    assert v2p._node_packages_refusal(None, task) is None
    assert any('everything this migration uses is installed' in ln for ln in task.log_lines)
