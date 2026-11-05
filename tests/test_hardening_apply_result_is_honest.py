"""What an apply or a rollback of a hardening control reports, and what decides it.

An apply counted as done when its output held DONE. Every control ends in `echo DONE`, so a
package install that failed into /dev/null, a script that ran half way or a control whose
apply changes nothing at all read as applied, and the tab said "N/N controls applied".
Now the apply runs in a subshell of its own, the control's own check runs right after it
in the same SSH call, and success needs both: the script reached its end and the check
passes. Seven controls change nothing on apply (net_protocols is covered by fs_modules, the
six VS-NfD ones are audit only); they answer noop and go out to no node.

A rollback said success as soon as one file of a control came back, and it now reports
every file it restored and every one it had no snapshot for.

The mechanism tests run the commands the manager builds through a local bash the way the
SSH helpers answer (stdout when the command exits 0, None otherwise), with stand-in
controls that touch only a temporary directory. The real controls are never executed:
their commands are only parsed with `bash -n`. NS Nov 2026
"""
import inspect
import os
import re
import stat
import subprocess
import types
from unittest.mock import create_autospec

import pytest

from pegaprox.core.manager import PegaProxManager
from pegaprox.core.xcpng import XcpngManager

PROBE = 'pp_probe'
NOOP = {'net_protocols', 'vsnfd_disk_encryption', 'vsnfd_audit_retention', 'vsnfd_journald_size',
        'vsnfd_secure_boot', 'vsnfd_kernel_lockdown', 'vsnfd_password_min_12'}


def _bash(cmd, cwd):
    r = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=30, cwd=cwd,
                       env={'PATH': f'{cwd}/bin:/usr/bin:/bin', 'HOME': str(cwd), 'LC_ALL': 'C'})
    return r.stdout if r.returncode == 0 else None


@pytest.fixture
def node(tmp_path):
    """A manager whose node is a local bash in tmp_path; .sent holds every command."""
    (tmp_path / 'bin').mkdir()
    m = PegaProxManager.__new__(PegaProxManager)
    m.sent = []

    def run(node_name, cmd, timeout=60):
        m.sent.append(cmd)
        return _bash(cmd, tmp_path)
    m._ssh_node_output = run
    m.dir = tmp_path
    return m


def _stub(tmp_path, name, body):
    p = tmp_path / 'bin' / name
    p.write_text('#!/bin/sh\n' + body + '\n')
    p.chmod(p.stat().st_mode | stat.S_IXUSR)


def _probe(monkeypatch, apply, check, **extra):
    monkeypatch.setitem(PegaProxManager.CIS_CHECKS, PROBE, dict(apply=apply, check=check, **extra))


def _apply(m, controls=(PROBE,), params=None):
    return m.apply_node_hardening('pve1', list(controls), params=params)


# -- apply: what decides success ------------------------------------------------------------------

def test_a_failed_install_is_not_reported_as_applied(node, monkeypatch):
    # the shape of debsums, sysstat, pam_tmpdir: the install goes to /dev/null, then DONE
    _stub(node.dir, 'pp_install', 'echo "E: Unable to locate package" >&2; exit 100')
    _probe(monkeypatch, apply='pp_install -y pp-tool >/dev/null 2>&1\necho DONE',
           check='command -v pp_tool >/dev/null 2>&1 && echo OK || echo FAIL')
    r = _apply(node)[PROBE]
    assert r['success'] is False
    assert r['verified'] is False
    assert 'still fails' in r['error']


def test_an_install_that_worked_is_applied_and_verified(node, monkeypatch):
    _stub(node.dir, 'pp_install', f'printf "#!/bin/sh\\n" > {node.dir}/bin/pp_tool; chmod +x {node.dir}/bin/pp_tool')
    _probe(monkeypatch, apply='pp_install -y pp-tool >/dev/null 2>&1\necho DONE',
           check='command -v pp_tool >/dev/null 2>&1 && echo OK || echo FAIL')
    r = _apply(node)[PROBE]
    assert r == {'success': True, 'verified': True, 'exit_code': 0}
    assert len(node.sent) == 1        # the check rides along, no second SSH call


@pytest.mark.parametrize('apply', [
    # pve_fail2ban: set -e, a failing step ends the script before DONE
    "set -e\necho '[probe] installing...'\nfalse\necho DONE",
    # pve_fail2ban, pam_password_repair: an explicit exit 1 with a reason
    "echo 'SSHD JAIL MISSING:'\nexit 1\necho DONE",
])
def test_a_script_that_stops_is_not_applied_even_when_the_check_passes(node, monkeypatch, apply):
    _probe(monkeypatch, apply=apply, check='echo OK')
    r = _apply(node)[PROBE]
    assert r['success'] is False and r['exit_code'] == 1
    assert 'exit status 1' in r['error']
    # what the script said on the way is kept for the operator
    assert ('[probe] installing...' in r['error']) or ('SSHD JAIL MISSING' in r['error'])


def test_a_stopped_script_runs_once_not_once_per_credential(monkeypatch, tmp_path):
    """The SSH ladder tries the next credential when a command exits non-zero, so a control
    that stopped with exit 1 used to run again with the process keys and the password."""
    _probe(monkeypatch, apply=f'echo ran >> {tmp_path}/runs\nexit 1\necho DONE', check='echo OK')
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(user='root@pam', ssh_key='KEY', name='c1')
    m._get_node_ip = lambda n: '192.0.2.10'
    m._last_ssh_stderr = lambda ip: ''
    m.ssh_password_to_offer = lambda ip: 'secret'
    m._ssh_run_command_with_key_output = lambda host, user, cmd, key, timeout=30: _bash(cmd, tmp_path)
    m._ssh_run_command_output = lambda host, user, cmd, timeout=30: _bash(cmd, tmp_path)
    m._ssh_run_command_with_password_output = lambda host, user, cmd, pw, timeout=30: _bash(cmd, tmp_path)
    r = _apply(m)[PROBE]
    assert r['success'] is False
    assert (tmp_path / 'runs').read_text().count('ran') == 1


def test_an_intended_tolerance_is_not_turned_into_a_failure(node, monkeypatch):
    # usb_storage, restrict_compilers, file_perms, remove_legacy_svcs: the last command before
    # DONE fails on a healthy node on purpose (no such module, no such file); the check decides
    _probe(monkeypatch, apply='pp_rmmod() { return 1; }\npp_rmmod 2>/dev/null; false 2>/dev/null\necho DONE',
           check='echo OK')
    r = _apply(node)[PROBE]
    assert r == {'success': True, 'verified': True, 'exit_code': 0}


def test_an_early_exit_0_is_still_verified(node, monkeypatch):
    # pam_password_repair leaves with `echo DONE; exit 0` when there is nothing to repair
    _probe(monkeypatch, apply='echo "(nothing to repair)"\necho DONE; exit 0\necho never',
           check='echo OK')
    r = _apply(node)[PROBE]
    assert r['success'] is True and r['verified'] is True


def test_set_e_of_one_control_does_not_reach_its_check(node, monkeypatch):
    _probe(monkeypatch, apply='set -e\necho DONE', check='grep -q nothing /dev/null\necho OK')
    assert _apply(node)[PROBE]['verified'] is True


def test_a_check_without_a_verdict_is_not_a_success(node, monkeypatch):
    _probe(monkeypatch, apply='echo DONE', check='echo maybe')
    r = _apply(node)[PROBE]
    assert r['success'] is False and r['verified'] is None
    assert 'no verdict' in r['error']


def test_no_answer_from_the_node_is_not_a_success(monkeypatch):
    _probe(monkeypatch, apply='echo DONE', check='echo OK')
    m = PegaProxManager.__new__(PegaProxManager)
    m._ssh_node_output = lambda node_name, cmd, timeout=60: None
    r = _apply(m)[PROBE]
    assert r['success'] is False and r['verified'] is None and r['exit_code'] is None
    assert r['error'].startswith('SSH command failed')


def test_an_apply_without_a_trailing_newline_still_names_its_exit_status(node, monkeypatch):
    # pve_fail2ban's exit 1 path: `cat /tmp/f2b.err` with no newline at the end, then exit 1.
    # The exit marker used to land in the middle of that line and was not found
    _probe(monkeypatch, apply="echo '[probe] restarting'\nprintf 'jail failed'; exit 1", check='echo OK')
    r = _apply(node)[PROBE]
    assert r['success'] is False and r['exit_code'] == 1
    assert 'exit status 1' in r['error'] and r['error'].endswith('jail failed')


def test_a_done_without_a_trailing_newline_is_applied(node, monkeypatch):
    _probe(monkeypatch, apply="printf 'DONE'", check='echo OK')
    assert _apply(node)[PROBE] == {'success': True, 'verified': True, 'exit_code': 0}


def test_the_snapshot_is_still_taken_before_the_apply(node, monkeypatch):
    f = node.dir / 'probe.conf'
    f.write_text('original\n')
    _probe(monkeypatch, apply=f'echo hardened > {f}\necho DONE', check=f'grep -q hardened {f} && echo OK || echo FAIL',
           backup_files=[str(f)])
    assert _apply(node)[PROBE]['success'] is True
    assert (node.dir / f'probe.conf.pegaprox-bak.{PROBE}').read_text() == 'original\n'


# -- the seven that change nothing ----------------------------------------------------------------

def test_controls_that_change_nothing_are_not_reported_as_applied(node):
    res = _apply(node, sorted(NOOP))
    for cid in NOOP:
        assert res[cid]['success'] is False and res[cid]['noop'] is True, cid
        assert res[cid]['error'], cid
    assert 'fs_modules' in res['net_protocols']['error']
    assert node.sent == []            # nothing to run, so nothing goes to the node


def test_the_noop_controls_are_the_ones_whose_apply_only_prints():
    """Derived from the apply text: a control whose apply is nothing but comments and echo
    lines must be marked, and no control that does something may be."""
    def only_prints(text):
        lines = [l.strip() for l in re.split(r'[\n;]', text) if l.strip()]
        return all(l.startswith('#') or (l.startswith('echo ') and '>' not in l) for l in lines)
    controls = PegaProxManager._all_hardening_controls()
    assert {cid for cid, c in controls.items() if only_prints(c['apply'])} == NOOP
    assert {cid for cid, c in controls.items() if c.get('noop')} == NOOP


def test_the_profiles_catalog_marks_the_noop_controls(api, seed):
    """The classic tab reads the noop ids from here instead of keeping a list of its own."""
    r = api.as_user(seed.user('root', role='admin')).get('/api/hardening/profiles')
    assert r.status_code == 200, r.data
    entries = {e['id']: e for e in r.get_json()['catalog']}
    assert set(entries) == set(PegaProxManager._all_hardening_controls())
    assert all(isinstance(e.get('noop'), bool) for e in entries.values())
    assert {cid for cid, e in entries.items() if e['noop']} == NOOP


def test_a_mixed_selection_counts_only_the_real_ones(api, seed, monkeypatch):
    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True
    fake.config = types.SimpleNamespace(name='cluster_1', ssh_key='k')
    m = PegaProxManager.__new__(PegaProxManager)
    m._ssh_node_output = lambda node_name, cmd, timeout=60: (
        'DONE\n---PEGAPROX-APPLY-EXIT:0---\nOK\n---PEGAPROX-END---\n')
    fake.apply_node_hardening = m.apply_node_hardening
    api.set_manager('cluster_1', fake)
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post('/api/clusters/cluster_1/nodes/pve1/hardening',
                   json={'controls': ['journald', 'vsnfd_secure_boot', 'net_protocols']})
    assert r.status_code == 200, r.data
    j = r.get_json()
    assert j['applied'] == 1 and j['total'] == 3
    assert j['results']['journald']['success'] is True
    assert j['results']['vsnfd_secure_boot']['noop'] is True


# -- every real control: the command still parses and checks itself -------------------------------

def _sent_for(cid):
    sent = []
    m = PegaProxManager.__new__(PegaProxManager)
    m._ssh_node_output = lambda node_name, cmd, timeout=60: (sent.append(cmd), None)[1]
    m.apply_node_hardening('pve1', [cid])
    return sent


# inactive_accounts never formats: its awk '{print $1}' is taken for a placeholder, so its
# apply has not reached a node since the control took parameters. The fix is one escaped
# brace in the control's text, left for a decision because the control then starts to change
# nodes. Until then the apply answers the error instead of a 500 (test below).
_UNFORMATTABLE = {'inactive_accounts'}


@pytest.mark.parametrize('cid', [
    pytest.param(c, marks=pytest.mark.xfail(strict=True, reason='template does not format'))
    if c in _UNFORMATTABLE else c
    for c in sorted(set(PegaProxManager._all_hardening_controls()) - NOOP)])
def test_every_control_is_sent_with_its_own_check_after_it(cid):
    ctrl = PegaProxManager._all_hardening_controls()[cid]
    sent = _sent_for(cid)
    assert len(sent) == 1
    cmd = sent[0]
    apply = ctrl['apply'].format(**ctrl['defaults']) if ctrl.get('apply_template') else ctrl['apply']
    assert apply in cmd and ctrl['check'] in cmd
    assert cmd.index(apply) < cmd.rindex(ctrl['check'])
    parsed = subprocess.run(['bash', '-n', '-c', cmd], capture_output=True, text=True, timeout=30)
    assert parsed.returncode == 0, parsed.stderr


def test_a_template_that_does_not_format_is_an_error_not_a_500(node, monkeypatch):
    _probe(monkeypatch, apply="awk '{print $1}' /etc/passwd\necho DONE", check='echo OK',
           apply_template=True, defaults={})
    r = _apply(node)[PROBE]
    assert r['success'] is False and 'could not be built' in r['error']
    assert node.sent == []


# -- rollback ----------------------------------------------------------------------------------

def _two_files(node, monkeypatch):
    a, b = node.dir / 'a.conf', node.dir / 'b.conf'
    a.write_text('a original\n')
    b.write_text('b original\n')
    _probe(monkeypatch, apply=f'echo hardened > {a}\necho hardened > {b}\necho DONE',
           check=f'grep -q hardened {a} && echo OK || echo FAIL', backup_files=[str(a), str(b)])
    assert _apply(node)[PROBE]['success'] is True
    return a, b


def test_a_full_rollback_names_every_file(node, monkeypatch):
    a, b = _two_files(node, monkeypatch)
    r = node.rollback_node_hardening('pve1', [PROBE])[PROBE]
    assert r['success'] is True
    assert r['files'] == {str(a): 'restored', str(b): 'restored'}
    assert a.read_text() == 'a original\n' and b.read_text() == 'b original\n'


def test_a_partial_rollback_is_not_a_full_one(node, monkeypatch):
    a, b = _two_files(node, monkeypatch)
    os.remove(f'{b}.pegaprox-bak.{PROBE}')
    r = node.rollback_node_hardening('pve1', [PROBE])[PROBE]
    assert r['success'] is False and r['partial'] is True
    assert r['files'] == {str(a): 'restored', str(b): 'no_snapshot'}
    assert str(b) in r['error']
    assert a.read_text() == 'a original\n' and b.read_text() == 'hardened\n'


def test_a_restored_file_counts_as_restored_when_its_snapshot_cannot_be_removed(node, monkeypatch):
    a, b = _two_files(node, monkeypatch)
    _stub(node.dir, 'rm', 'exit 1')         # the copy back works, removing the snapshot does not
    r = node.rollback_node_hardening('pve1', [PROBE])[PROBE]
    assert r['success'] is True
    assert r['files'] == {str(a): 'restored', str(b): 'restored'}
    assert a.read_text() == 'a original\n' and b.read_text() == 'b original\n'
    assert os.path.exists(f'{a}.pegaprox-bak.{PROBE}')     # the stub really refused


def test_a_copy_back_that_fails_is_a_failed_file(node, monkeypatch):
    a, b = _two_files(node, monkeypatch)
    _stub(node.dir, 'cp', 'exit 1')
    r = node.rollback_node_hardening('pve1', [PROBE])[PROBE]
    assert r['success'] is False
    assert r['files'] == {str(a): 'failed', str(b): 'failed'}
    assert a.read_text() == 'hardened\n'
    assert os.path.exists(f'{a}.pegaprox-bak.{PROBE}')     # the snapshot is kept for a retry


def test_a_rollback_without_any_snapshot_says_so(node, monkeypatch):
    a, b = _two_files(node, monkeypatch)
    for f in (a, b):
        os.remove(f'{f}.pegaprox-bak.{PROBE}')
    r = node.rollback_node_hardening('pve1', [PROBE])[PROBE]
    assert r['success'] is False and not r.get('partial')
    assert 'no snapshot found' in r['error']
    assert r['files'] == {str(a): 'no_snapshot', str(b): 'no_snapshot'}


def test_the_rollback_route_counts_only_full_ones(api, seed, node, monkeypatch):
    a, b = _two_files(node, monkeypatch)
    os.remove(f'{b}.pegaprox-bak.{PROBE}')
    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True
    fake.rollback_node_hardening = node.rollback_node_hardening
    api.set_manager('cluster_1', fake)
    r = api.as_user(seed.user('root', role='admin')).post(
        '/api/clusters/cluster_1/nodes/pve1/hardening/rollback', json={'controls': [PROBE]})
    assert r.status_code == 200, r.data
    j = r.get_json()
    assert j['restored'] == 0 and j['results'][PROBE]['partial'] is True


# -- XCP-ng ------------------------------------------------------------------------------------

def _xcpng(api):
    """A fake XCP-ng manager whose hardening methods have the real class's signatures."""
    fake = api.make_fake_manager('cluster_1', cluster_type='xcpng')
    fake.is_connected = True
    fake.config = types.SimpleNamespace(name='cluster_1', ssh_key='')
    real = XcpngManager.__new__(XcpngManager)
    fake.apply_node_hardening = create_autospec(real.apply_node_hardening)
    if hasattr(XcpngManager, 'rollback_node_hardening'):
        fake.rollback_node_hardening = create_autospec(real.rollback_node_hardening)
    else:
        del fake.rollback_node_hardening
    return api.set_manager('cluster_1', fake)


@pytest.mark.parametrize('path', ['hardening', 'hardening/rollback'])
def test_an_xcpng_pool_refuses_apply_and_rollback(api, seed, path):
    fake = _xcpng(api)
    r = api.as_user(seed.user('root', role='admin')).post(
        f'/api/clusters/cluster_1/nodes/xen1/{path}', json={'controls': ['fs_modules']})
    assert r.status_code == 400, r.data
    j = r.get_json()
    assert j['code'] == 'PVE_ONLY' and 'Proxmox VE' in j['error']
    assert fake.apply_node_hardening.call_count == 0
    assert fake.rollback_node_hardening.call_count == 0


def test_the_xcpng_refusal_says_that_the_check_runs(api, seed):
    _xcpng(api)
    r = api.as_user(seed.user('root', role='admin')).post(
        '/api/clusters/cluster_1/nodes/xen1/hardening', json={'controls': ['fs_modules']})
    assert r.status_code == 400 and 'the check runs' in r.get_json()['error']


@pytest.mark.parametrize('path', ['hardening', 'hardening/rollback'])
def test_an_esxi_cluster_is_refused_without_the_claim_that_a_check_runs(api, seed, path):
    # an ESXi manager sits in cluster_managers too and has no hardening check at all
    fake = api.make_fake_manager('cluster_1', cluster_type='esxi')
    fake.is_connected = True
    api.set_manager('cluster_1', fake)
    r = api.as_user(seed.user('root', role='admin')).post(
        f'/api/clusters/cluster_1/nodes/esx1/{path}', json={'controls': ['fs_modules']})
    assert r.status_code == 400, r.data
    j = r.get_json()
    assert j['code'] == 'PVE_ONLY' and 'Proxmox VE nodes only' in j['error']
    assert 'check' not in j['error']
    assert fake.apply_node_hardening.call_count == 0 and fake.rollback_node_hardening.call_count == 0


def test_the_xcpng_methods_take_what_the_route_would_pass():
    real = XcpngManager.__new__(XcpngManager)
    inspect.signature(real.apply_node_hardening).bind('xen1', ['fs_modules'], params={})
    real._ssh_exec = lambda *a, **k: pytest.fail('a rollback on XCP-ng must not reach the host')
    res = real.rollback_node_hardening('xen1', ['fs_modules', 'firewall'])
    assert all(v['success'] is False and v['error'] for v in res.values())
