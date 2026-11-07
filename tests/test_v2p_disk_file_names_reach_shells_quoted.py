# ESXi -> Proxmox migration: the disk file names ESXi lists end up in root commands on the
# target node and on the ESXi host, and the Live Mirror writes them into the QEMU -drive
# specs of the VM config.
#
# A name is checked once, right after the listing: a control character (a Unicode line
# separator or invisible format character included), a quote, a backtick, a dollar sign or
# a backslash stops the run before anything is touched, and so does a comma where the name
# can go into a -drive spec: in every mode but Offline, Snapshot Zero and Live Clone, a mode
# name the code does not know included. Spaces, umlauts, parentheses, '#', '&' and '+' are
# taken, and every command quotes the name for the shell that reads it.
#
# The runs use the ESXi host, API and Proxmox node of tests/test_v2p_tpm_and_folder_copy.py.
# Where a command matters as such it runs in a real shell on this machine.

import json
import re
import shlex
import subprocess
import urllib.parse

import pytest

import pegaprox.core.v2p as v2p
import test_v2p_tpm_and_folder_copy as farm

GiB = 1024 ** 3
# allowed on ESXi and by the check, and each of them means something to a shell
TAKEN = ['App Server (Ä) #1 & co+.vmdk', 'data disk+2.vmdk']


def _flat(name):
    return name[:-len('.vmdk')] + '-flat.vmdk'


def _run(monkeypatch, names, mode='offline', **kw):
    for n in names:
        monkeypatch.setitem(farm.FLATS, _flat(n), GiB)
    r = farm.Run(monkeypatch, mode=mode, ndisks=1, tpm=False, **kw)
    r.esxi.disks = [{'key': str(2000 + i), 'label': f'Hard disk {i + 1}', 'capacity_bytes': GiB,
                     'capacity_gb': 1.0, 'thin': False, 'vmdk_file': f'[ds1] app01/{n}'}
                    for i, n in enumerate(names)]
    return r


def _nothing_touched(r):
    assert r.posts() == [], 'a VM was created on Proxmox'
    assert not any('sshfs' in c and 'password_stdin' in c for c in r.nodecmds()), 'the datastore was mounted'
    assert not any(c.startswith('pvesm alloc') for c in r.nodecmds())
    assert not [e for e in r.log if e[:2] in (('esxi_api', 'power'), ('esxi_api', 'snapshot'))]


# --------------------------------------------------------------------------- the check

@pytest.mark.parametrize('name', ['web$(id).vmdk', 'web`id`.vmdk', "web'1.vmdk", 'web"1.vmdk',
                                  'web\\1.vmdk', 'web\n1.vmdk', 'web\r1.vmdk', 'web\x00.vmdk',
                                  'web\x1b[2J.vmdk', 'web\x85.vmdk', 'a/b.vmdk', '', '   '])
def test_a_name_a_shell_or_qemu_would_read_into_is_refused(name):
    assert v2p.disk_name_problem(name)
    assert v2p.disk_name_problem(name, drive_spec=True)


@pytest.mark.parametrize('name', TAKEN + ['Würfel_ß.vmdk', 'db-2024.01.vmdk', 'x=y%2f.vmdk'])
def test_spaces_umlauts_parentheses_hash_ampersand_and_plus_are_taken(name):
    assert v2p.disk_name_problem(name) is None
    assert v2p.disk_name_problem(name, drive_spec=True) is None


def test_a_comma_is_refused_only_where_the_name_becomes_part_of_a_drive_spec():
    assert v2p.disk_name_problem('web,1.vmdk') is None
    assert 'comma' in v2p.disk_name_problem('web,1.vmdk', drive_spec=True)


@pytest.mark.parametrize('ch', [' ', ' ', '‮', '​', '﻿'])
def test_line_separators_and_invisible_format_characters_are_refused_other_spaces_are_not(ch):
    # they break or reorder the line the name is shown on, in the task log and the refusal
    for drive_spec in (False, True):
        assert v2p.disk_name_problem(f'web{ch}1.vmdk', drive_spec) == 'a control character or line break'
        # a no-break or an ideographic space is a space like any other
        assert v2p.disk_name_problem('web 1　2.vmdk', drive_spec) is None


@pytest.mark.parametrize('bad', ['web$(touch x).vmdk', 'web`id`.vmdk', "web'1.vmdk", 'web"1.vmdk',
                                 'web\\1.vmdk', 'web\x01.vmdk'])
@pytest.mark.parametrize('mode', ['offline', 'snapshot_zero', 'sshfs_boot', 'auto', 'vmkfstools_clone'])
def test_a_listed_name_with_such_a_character_stops_the_run_before_anything(monkeypatch, mode, bad):
    r = _run(monkeypatch, [TAKEN[0], bad], mode=mode).go()
    assert r.task.status == 'failed'
    assert 'Rename the disk on ESXi' in r.task.error and repr(bad) in r.task.error, r.task.error
    # one line, whatever the name held
    assert '\n' not in r.task.error and '\x01' not in r.task.error
    _nothing_touched(r)


def test_a_comma_stops_only_the_modes_that_can_end_in_the_live_mirror(monkeypatch):
    for mode in ('sshfs_boot', 'auto'):
        r = _run(monkeypatch, ['web,1.vmdk'], mode=mode, ssh_key='/tmp/v2p-key-fixed').go()
        assert r.task.status == 'failed', mode
        assert 'comma' in r.task.error and 'Rename the disk on ESXi' in r.task.error, r.task.error
        _nothing_touched(r)
    # where the name reaches no drive spec it is taken, with the other signs, and each disk
    # is copied from its very file
    monkeypatch.setattr(v2p, '_snapshot_zero_v2p_delta_loop', lambda *a, **k: (True, 1, []))
    names = TAKEN + ['web,3.vmdk']
    for mode in ('offline', 'snapshot_zero'):
        r = _run(monkeypatch, names, mode=mode).go()
        assert r.task.status == 'completed', (mode, r.task.error)
        att = r.attached()
        src = {k: r.node.copied_from.get(f'/dev/{v.replace(":", "/", 1)}') for k, v in att.items()}
        assert src == {f'scsi{i}': _flat(n) for i, n in enumerate(names)}, (mode, src)


@pytest.mark.parametrize('mode', [None, '', 'Auto', 'live_mirror'])
def test_a_comma_stops_a_run_in_a_mode_this_code_does_not_know(monkeypatch, mode):
    # such a mode runs the pre-sync flow, which switches to the Live Mirror when the copy
    # fails while the source runs
    monkeypatch.setattr(v2p, '_ssh_pipe_transfer', lambda *a, **k: (None, None))
    r = _run(monkeypatch, ['web,1.vmdk'], mode=mode, ssh_key='/tmp/v2p-key-fixed').go()
    assert r.task.status == 'failed', (mode, r.task.error)
    assert 'comma' in r.task.error and 'Rename the disk on ESXi' in r.task.error, r.task.error
    _nothing_touched(r)


@pytest.mark.parametrize('ch', [' ', '‮'])
def test_a_listed_name_with_a_line_separator_or_bidi_override_stops_the_run(monkeypatch, ch):
    bad = f'web{ch}1.vmdk'
    r = _run(monkeypatch, [TAKEN[0], bad], mode='offline').go()
    assert r.task.status == 'failed'
    assert 'Rename the disk on ESXi' in r.task.error and repr(bad) in r.task.error, r.task.error
    # the refusal shows the character escaped, never as such
    assert ch not in r.task.error
    _nothing_touched(r)


# --------------------------------------------------------------------------- the Live Mirror

def _conf_after(cmd, tmp_path):
    """The args: line the node's config gets from an `echo ... >> conf` command, run in bash."""
    conf = tmp_path / 'vm.conf'
    conf.write_text('')
    real = re.sub(r'/etc/pve/qemu-server/\d+\.conf', str(conf), cmd)
    subprocess.run(['bash', '-c', real], check=True, cwd=tmp_path)
    (line,) = conf.read_text().splitlines()
    assert line.startswith('args: ')
    return line[len('args: '):]


def _drive_options(args_value):
    """{option: value} of every -drive, split the way qemu-server splits the args: line
    (Text::ParseWords shellwords, which shlex.split follows) and QEMU splits an option list."""
    words = shlex.split(args_value)
    drives = [words[i + 1] for i, w in enumerate(words) if w == '-drive']
    return [dict(o.split('=', 1) for o in d.split(',')) for d in drives]


def _esxi_path(name):
    return f'/vmfs/volumes/ds1/app01/{_flat(name)}'


def test_the_live_mirror_over_libssh_hands_qemu_the_exact_file(monkeypatch, tmp_path):
    r = _run(monkeypatch, TAKEN, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed').go()
    assert r.task.status == 'completed', r.task.error
    writes = [c for c in r.nodecmds() if c.startswith("echo 'args: ")]
    assert writes
    drives = _drive_options(_conf_after(writes[-1], tmp_path))
    assert [d.get('file.path') for d in drives] == [_esxi_path(n) for n in TAKEN], drives
    assert all(d['file.driver'] == 'ssh' and d['format'] == 'raw' for d in drives)
    # the connection test before it names the same file
    probe = next(c for c in r.nodecmds() if 'qemu-img info' in c and 'json:' in c)
    spec = next(w for w in shlex.split(probe) if w.startswith('json:'))
    assert json.loads(spec[len('json:'):])['file.path'] == _esxi_path(TAKEN[0])


class _NoLibssh(farm.Node):
    """The node's QEMU reaches ESXi neither over libssh nor over HTTPS, and the SSHFS
    mount holds the flat files."""

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        if 'qemu-img info' in cmd and ('json:' in cmd or 'ssh://' in cmd):
            self.log.append(('node', node, cmd))
            return 1, 'Could not open: authentication failed', ''
        if cmd.startswith('for i in 1 2 3'):
            self.log.append(('node', node, cmd))
            return 0, f'{GiB}', ''
        return super().__call__(mgr, node, cmd, timeout, **kw)


def _script_bodies(r, tag):
    """The scripts the run wrote on the node through _write_node_script, by their tag."""
    out = []
    for c in r.nodecmds():
        if c.startswith('umask 077; f=$(mktemp /tmp/v2p-' + tag):
            out.append(c.split('\n', 1)[1].rsplit('V2P_NODE_SCRIPT', 1)[0])
    return out


def _esxi_reads(line, host='esx1.lab'):
    """The if= of the dd ESXi runs for a node line `... ssh ... <host> '<remote>' | ...`:
    the node's shell takes the line apart, ESXi's shell the remote command."""
    words = shlex.split(line)
    remote = words[next(i for i, w in enumerate(words) if w.endswith('@' + host)) + 1]
    return [w[len('if='):] for w in shlex.split(remote) if w.startswith('if=')]


def test_the_live_mirror_over_sshfs_hands_qemu_nbd_and_the_copy_the_exact_file(monkeypatch, tmp_path):
    r = _run(monkeypatch, TAKEN, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed')
    node = _NoLibssh(r.log, r.vols)
    r.node = node
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    # the VM never comes up on the remote disks, so the run copies them with dd over ssh
    r.pve._api_post = lambda url, data=None, **kw: farm._Resp('UPID:pve1:1:2:x')
    r.go()
    fuse = [f'/tmp/v2p-t1/app01/{_flat(n)}' for n in TAKEN]
    cmds = r.nodecmds()

    # the URL form of the libssh test: one word, the path in it percent-encoded
    url = next(w for c in cmds if 'ssh://' in c for w in shlex.split(c) if w.startswith('ssh://'))
    assert urllib.parse.unquote(urllib.parse.urlsplit(url).path) == _esxi_path(TAKEN[0]), url

    # the SSHFS-backed boot: QEMU and qemu-nbd get each flat file as one word
    drives = [d for c in cmds if c.startswith("echo 'args: ")
              for d in _drive_options(_conf_after(c, tmp_path)) if 'file' in d]
    assert [d['file'] for d in drives] == fuse, drives
    loops = [c for c in cmds if c.startswith('for i in 1 2 3')]
    assert [fuse[i] in shlex.split(c) for i, c in enumerate(loops)] == [True, True], loops
    nbd = [c for c in cmds if c.startswith('qemu-nbd ')]
    assert nbd and [shlex.split(c)[-2] for c in nbd] == fuse, nbd

    # the dd over ssh: ESXi's shell reads the exact file in every stream
    bodies = _script_bodies(r, 'bgssh-')
    assert len(bodies) == len(TAKEN), r.task.log_lines[-20:]
    for name, body in zip(TAKEN, bodies):
        streams = [ln for ln in body.splitlines() if ' ssh ' in ln]
        assert streams and all(_esxi_reads(ln) == [_esxi_path(name)] for ln in streams), streams


# --------------------------------------------------------------------------- the ESXi listing

def test_the_delta_listing_keeps_the_name_one_word_for_the_esxi_shell(monkeypatch, tmp_path):
    folder = tmp_path / 'vmfs' / 'ds1' / 'app01'
    folder.mkdir(parents=True)
    taken = 'App (1) #2 & co+ä'
    for n in (1, 2):
        (folder / f'{taken}-00000{n}-delta.vmdk').write_text('')
    ran = []

    def esxi(host, user, pw, cmd, timeout=30):
        ran.append(cmd)
        p = subprocess.run(['sh', '-c', cmd.replace('/vmfs/volumes/', f'{tmp_path}/vmfs/')],
                           capture_output=True, text=True, cwd=tmp_path, timeout=30)
        return p.returncode, p.stdout.replace(f'{tmp_path}/vmfs/', '/vmfs/volumes/'), p.stderr
    monkeypatch.setattr(v2p, '_ssh_esxi_exec', esxi)

    breaking = "x'$(touch canary)'y"
    got = v2p._list_delta_files_on_esxi('esx1', 'root', 'pw', 'ds1', 'app01',
                                        [f'{breaking}.vmdk', f'{taken}.vmdk'])
    assert not (tmp_path / 'canary').exists(), f'the ESXi shell ran what the name held: {ran[0]}'
    assert got[0] == []
    assert got[1] == [f'/vmfs/volumes/ds1/app01/{taken}-00000{n}-delta.vmdk' for n in (1, 2)], got
