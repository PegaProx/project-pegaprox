"""The update, the rollback and the restart button hand the restart to systemctl only
when this process runs in pegaprox.service.

They asked `systemctl is-active pegaprox` and restarted that unit whenever it was up. On
a host with a second PegaProx (a test instance started by hand, one in a unit of another
name) that restarted the other one, and this process went on as it was. Which unit a
process runs in is what the kernel lists in /proc/self/cgroup; anywhere else the
process restarts in place (ha.leave_process). No test here runs systemctl.

MK Oct 2026
"""
import ast
import os
import types

import pytest

import pegaprox.api.settings as settings_mod
from pegaprox.core import ha
from test_ha_api import _admin

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _Left(BaseException):
    pass


def _press_restart(api, seed, monkeypatch, tmp_path, cgroup, euid=0):
    """Press the restart button and run what it starts: (commands run, left in place).
    The unit 'pegaprox' is active and every systemctl call would go through."""
    if cgroup is None:
        monkeypatch.setattr(settings_mod, '_CGROUP_FILE', str(tmp_path / 'no-such-file'), raising=False)
    else:
        path = tmp_path / 'cgroup'
        path.write_text(cgroup)
        monkeypatch.setattr(settings_mod, '_CGROUP_FILE', str(path), raising=False)
    admin = _admin(api, seed)
    started = []
    monkeypatch.setattr(settings_mod, 'threading', types.SimpleNamespace(
        Thread=lambda target=None, **kw: types.SimpleNamespace(start=lambda: started.append(target), daemon=True)))
    assert admin.post('/api/settings/server/restart', json={}).status_code == 200
    monkeypatch.setattr(settings_mod, 'time', types.SimpleNamespace(sleep=lambda s: None))
    monkeypatch.setattr(ha, 'planned_restart', lambda why: True)
    left = []

    def leave():
        left.append(1)
        raise _Left()
    monkeypatch.setattr(ha, 'leave_process', leave)
    monkeypatch.setattr(os, 'geteuid', lambda: euid)
    monkeypatch.setattr(settings_mod.shutil, 'which', lambda name: '/usr/bin/sudo')
    ran = []
    monkeypatch.setattr(settings_mod.subprocess, 'run', lambda cmd, **kw: ran.append(list(cmd)) or types.SimpleNamespace(
        returncode=0, stdout='active\n', stderr=''))
    try:
        started[0]()
    except _Left:
        pass
    return ran, left


@pytest.mark.parametrize('cgroup', [
    '0::/user.slice/user-1000.slice/session-3.scope\n',
    '0::/system.slice/pegaprox-b.service\n',
    '0::/system.slice/old-pegaprox.service\n',
    '0::/\n',
    '12:pids:/system.slice/pegaprox.service\n1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n',
    '',
    None,
], ids=['a session', 'another unit', 'a unit named like it', 'a container', 'v1 in a session',
        'empty', 'not readable'])
def test_outside_its_unit_the_restart_leaves_the_unit_alone(api, seed, monkeypatch, tmp_path, cgroup):
    ran, left = _press_restart(api, seed, monkeypatch, tmp_path, cgroup)
    assert [c for c in ran if 'systemctl' in c] == [], ran
    assert left == [1]


@pytest.mark.parametrize('cgroup', [
    '0::/system.slice/pegaprox.service\n',
    '12:pids:/system.slice/pegaprox.service\n1:name=systemd:/system.slice/pegaprox.service\n'
    '0::/system.slice/pegaprox.service\n',
    '1:name=systemd:/system.slice/pegaprox.service\n',
], ids=['cgroup v2', 'hybrid', 'cgroup v1'])
def test_in_its_own_unit_the_restart_goes_to_systemctl(api, seed, monkeypatch, tmp_path, cgroup):
    ran, left = _press_restart(api, seed, monkeypatch, tmp_path, cgroup)
    assert ran == [['systemctl', 'is-active', 'pegaprox'], ['systemctl', 'restart', 'pegaprox']]
    assert left == []


def test_in_its_own_unit_without_root_it_asks_sudo(api, seed, monkeypatch, tmp_path):
    ran, left = _press_restart(api, seed, monkeypatch, tmp_path, '0::/system.slice/pegaprox.service\n',
                               euid=1000)
    assert ran[-1] == ['sudo', '-n', 'systemctl', 'restart', 'pegaprox'] and left == []


def _restart_functions():
    tree = ast.parse(open(os.path.join(ROOT, 'pegaprox', 'api', 'settings.py'), encoding='utf-8').read())
    out = {}
    for outer in tree.body:
        if not isinstance(outer, ast.FunctionDef):
            continue
        for fn in ast.walk(outer):
            if isinstance(fn, ast.FunctionDef) and fn is not outer and fn.name in ('restart_server', 'do_restart'):
                out[f'{outer.name}.{fn.name}'] = fn
    return out


def test_the_update_and_the_rollback_ask_the_same_way():
    """The three ways a restart is asked for from the UI: each goes through the one check
    and none runs systemctl itself."""
    found = _restart_functions()
    assert set(found) == {'perform_pegaprox_update.restart_server',
                          'rollback_pegaprox_update.restart_server', 'restart_server.do_restart'}
    for name, fn in found.items():
        calls = [ast.unparse(c.func) for c in ast.walk(fn) if isinstance(c, ast.Call)]
        assert '_restart_through_systemd' in calls, name
        assert 'subprocess.run' not in calls, name


def test_nothing_else_restarts_the_unit():
    hits = []
    for base, _dirs, files in os.walk(os.path.join(ROOT, 'pegaprox')):
        for name in files:
            if not name.endswith('.py'):
                continue
            path = os.path.join(base, name)
            with open(path, encoding='utf-8') as fh:
                for lineno, line in enumerate(fh, 1):
                    if "'restart', 'pegaprox'" in line:
                        hits.append((os.path.relpath(path, ROOT), lineno))
    assert len(hits) == 2 and {h[0] for h in hits} == {'pegaprox/api/settings.py'}, hits
    src = open(os.path.join(ROOT, 'pegaprox', 'api', 'settings.py'), encoding='utf-8').read()
    helper = src[src.index('def _restart_through_systemd'):]
    helper = helper[:helper.index('\n\n\n')]
    assert helper.count("'restart', 'pegaprox'") == 2
