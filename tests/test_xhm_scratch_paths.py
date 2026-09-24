"""The cross-hypervisor migration engine writes as root into a directory nobody can name.

The four scratch paths (`/tmp/xhm-<id>/mnt-N`, `.../diskN.vmdk`, `.../N-flat.vmdk`,
`.../N.raw`) were all built from `task.id`, which is `str(uuid.uuid4())[:8]` and is handed
out by GET /api/xhm/migrations. /tmp is world-writable on the PegaProx host and on the
target PVE node alike, and the sticky bit does not stop anyone creating a name that is
still free. So a local account that could read the migration id - or simply sit on the
32-bit space - could pre-create any of the four as a symlink and have a root qemu-img or
scp write the guest's disk image somewhere else entirely.

The tests drive the real engine with recording fakes and look at what actually reaches the
node, because that is the thing the attacker sees. Aikido ai_pentest 700489697. MK
"""
import os
import re

import pytest

import pegaprox.core.xhm as xhm


# --- the path itself -------------------------------------------------------------

def _task(mid='deadbeef'):
    return xhm.XHMigrationTask(
        mid=mid, direction='esxi_to_pve', source_cluster='esxi1', source_node='esx-a',
        source_vmid=42, target_cluster='pve1', target_node='pve-a', target_storage='local')


def test_the_migration_id_does_not_name_the_scratch_directory():
    """The whole point: the id the API hands out must not tell you the path.

    The paths this replaced were `/tmp/xhm-esxi-<id>` and `/tmp/xhm-<id>-disk<n>.vmdk`,
    so the test asks the general question - is the id enough to write the name down -
    rather than listing shapes somebody could sidestep with a new one.
    """
    mid = 'deadbeef'

    scratch = _task(mid).scratch

    assert scratch.startswith('/tmp/')
    leftover = scratch[len('/tmp/'):].replace(mid, '')
    # strip the fixed prefix/separators the name is allowed to have and what remains
    # must still be unguessable
    assert len(re.sub(r'[^0-9a-f]', '', leftover)) >= 32, scratch


def test_two_migrations_with_the_same_id_get_different_directories():
    """Proof the randomness is real and not just the id in a different shape."""
    paths = {_task().scratch for _ in range(200)}

    assert len(paths) == 200


def test_the_scratch_name_carries_a_full_random_component():
    scratch = _task().scratch

    tail = scratch.rsplit('-', 1)[-1]
    assert re.fullmatch(r'[0-9a-f]{32}', tail), scratch


def test_the_module_builds_no_other_tmp_path():
    """One construction site. A second one is how the next one of these gets reintroduced."""
    src = open(xhm.__file__, encoding='utf-8').read()
    code = '\n'.join(l for l in src.splitlines() if not l.lstrip().startswith('#'))

    literals = re.findall(r'["\']/tmp/[^"\']*', code)

    assert literals == ['"/tmp/xhm-{mid}-{uuid.uuid4().hex}'], literals


# --- what actually reaches the PVE node ------------------------------------------

class _Chan:
    def __init__(self, rc=0):
        self._rc = rc

    def recv_exit_status(self):
        return self._rc


class _Stream:
    def __init__(self, payload=b''):
        self._payload = payload
        self.channel = _Chan()

    def read(self):
        return self._payload


class _RecordingSSH:
    """Records every command. `listing` is what an `ls` of the mount returns - empty
    drives the scp fallback, non-empty the sshfs-direct path."""

    def __init__(self, listing=b'vm.vmdk\n'):
        self.commands = []
        self._listing = listing

    def exec_command(self, cmd, timeout=None, **kw):
        self.commands.append(cmd)
        if cmd.lstrip().startswith('ls '):
            return _Stream(), _Stream(self._listing), _Stream()
        return _Stream(), _Stream(), _Stream()

    def close(self):
        pass


class _Config:
    ssh_user = 'root'
    pass_ = 'pw'
    ssh_key = ''
    ssh_port = 22


class _Mgr:
    is_connected = True
    host = '10.0.0.9'
    config = _Config()

    def get_vm_disks_for_export(self, vmid):
        return {'data': {'name': 'web01', 'guest_os': 'ubuntu64Guest', 'memory_mb': 2048,
                         'cpu_count': 2,
                         'disks': [{'vmdk_file': '[datastore1] web01/web01.vmdk',
                                    'capacity_bytes': 8 * 1024 ** 3, 'capacity_gb': 8,
                                    'label': 'Hard disk 1'}]}}


@pytest.fixture
def driven(monkeypatch):
    """Runs _run_esxi_to_pve against fakes and hands back the recorded commands."""

    def _run(listing=b'vm.vmdk\n'):
        ssh = _RecordingSSH(listing)
        monkeypatch.setitem(xhm.cluster_managers, 'esxi1', _Mgr())
        monkeypatch.setitem(xhm.cluster_managers, 'pve1', _Mgr())
        monkeypatch.setattr(xhm, '_resolve_pve_node_ip', lambda mgr, node: '10.0.0.9')
        monkeypatch.setattr(xhm, '_next_pve_vmid', lambda mgr: 900, raising=False)
        monkeypatch.setattr(xhm, '_connect_ssh',
                            lambda *a, **kw: ssh)
        task = _task()
        xhm._run_esxi_to_pve(task)
        return task, ssh.commands

    return _run


def _scratch_writes(commands, scratch):
    return [c for c in commands if scratch in c]


def test_the_node_is_told_to_create_the_scratch_root_before_anything_writes_into_it(driven):
    task, commands = driven()

    touching = _scratch_writes(commands, task.scratch)
    assert touching, 'the engine never used the scratch directory at all'
    first = touching[0]
    assert first.startswith('mkdir -m 700 -p '), first


def test_the_scratch_root_is_created_0700_not_with_the_default_mode(driven):
    task, commands = driven()

    mkdirs = [c for c in commands if c.startswith('mkdir') and task.scratch in c]
    assert mkdirs
    for cmd in mkdirs:
        # -m has to come before -p: `mkdir -p a/b` creates `a` with the umask mode, and
        # `a` is the directory whose contents matter here
        assert '-m 700' in cmd, cmd


def test_the_scp_fallback_also_creates_its_directory_first(driven):
    """The fallback runs after the failed mount has been torn down, so it cannot assume
    the directory is still there."""
    task, commands = driven(listing=b'')

    disk = f"{task.scratch}/disk0.vmdk"
    writes = [i for i, c in enumerate(commands) if disk in c]
    assert writes, 'scp fallback never ran'
    mkdirs = [i for i, c in enumerate(commands)
              if c.startswith('mkdir -m 700 -p ') and task.scratch in c]
    assert any(m < writes[0] for m in mkdirs), commands


def test_no_command_the_node_runs_names_a_tmp_path_built_from_the_migration_id(driven):
    """Catches any /tmp path that carries the id without the random part - which is
    exactly what the old `/tmp/xhm-esxi-<id>` and `/tmp/xhm-<id>-disk<n>` were."""
    task, commands = driven()

    offenders = []
    for cmd in commands:
        for path in re.findall(r"/tmp/[^\s'\"]*", cmd):
            if task.id in path and not path.startswith(task.scratch):
                offenders.append(path)

    assert offenders == []


def test_the_teardown_removes_the_scratch_directory(driven):
    """A 0700 directory per migration is cheap, but leaving one behind per run on every
    node in the estate is not."""
    task, commands = driven(listing=b'')

    assert any(f"rmdir {_shq(task.scratch)}" in c or f"rmdir {task.scratch}" in c
               for c in commands), commands


def _shq(s):
    import shlex
    return shlex.quote(s)


# --- the local side --------------------------------------------------------------

def test_the_local_conversion_directory_is_created_private(monkeypatch):
    """The ESXi->XCP-ng leg converts on the PegaProx host itself, into the same scratch."""
    import inspect
    body = inspect.getsource(xhm._run_esxi_to_xcpng)

    assert 'os.makedirs(task.scratch, mode=0o700, exist_ok=True)' in body
    for var in ('tmp_vmdk', 'tmp_raw'):
        m = re.search(rf'{var} = f"([^"]+)"', body)
        assert m, var
        assert m.group(1).startswith('{task.scratch}/'), (var, m.group(1))


# --- the host-key policy the operator configured -----------------------------------

def _hostkey_values(commands):
    return re.findall(r'StrictHostKeyChecking=([A-Za-z-]+)', ' '.join(commands))


def test_strict_mode_reaches_the_node_as_a_refusal(driven, monkeypatch):
    """These two commands run on the PVE node and reach the ESXi host from there, so the
    setting has to travel with them. They were hardcoded to accept-new, which is
    trust-on-first-use - the one thing strict mode exists to switch off.

    (CodeAnt, 18.09.: the first version of this test monkeypatched the helper and then
    asserted a ternary it had written itself, so it exercised nothing.)
    """
    # the env var, not the helper: xhm imports the function inside the handler today,
    # so patching the module happens to work - but that is an implementation detail of
    # where the import sits, and this is the switch an operator actually flips
    monkeypatch.setenv('PEGAPROX_SSH_STRICT_HOST_KEYS', '1')

    _task, commands = driven(listing=b'')

    values = _hostkey_values(commands)
    assert values, 'no ssh command carried a host-key option at all'
    assert set(values) == {'yes'}, values


def test_the_mount_path_carries_it_too_not_just_the_fallback(driven, monkeypatch):
    """The other branch: when the SSHFS mount succeeds the scp fallback never runs, so
    the mount command has to carry the setting on its own."""
    monkeypatch.setenv('PEGAPROX_SSH_STRICT_HOST_KEYS', '1')

    _task, commands = driven(listing=b'vm.vmdk\n')      # mount succeeds, no fallback

    assert not [c for c in commands if ' scp ' in c or c.startswith('scp ')]
    assert _hostkey_values(commands) == ['yes']


def test_without_strict_mode_the_node_still_learns_the_host(driven, monkeypatch):
    """The counterweight: turning strict mode off must keep first-use working, or every
    ESXi migration on a default install stops."""
    monkeypatch.delenv('PEGAPROX_SSH_STRICT_HOST_KEYS', raising=False)

    _task, commands = driven(listing=b'')

    assert set(_hostkey_values(commands)) == {'accept-new'}


def test_both_of_the_nested_commands_carry_it(driven, monkeypatch):
    """The sshfs mount and the scp fallback - missing either leaves a way round."""
    # the env var, not the helper: xhm imports the function inside the handler today,
    # so patching the module happens to work - but that is an implementation detail of
    # where the import sits, and this is the switch an operator actually flips
    monkeypatch.setenv('PEGAPROX_SSH_STRICT_HOST_KEYS', '1')

    _task, commands = driven(listing=b'')

    assert len([c for c in commands if 'sshfs' in c]) == 1
    assert len([c for c in commands if ' scp ' in c or c.startswith('scp ')]) >= 1
    assert len(_hostkey_values(commands)) == 2
