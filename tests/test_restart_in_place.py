"""A restart the server cannot hand to systemctl (no root, no sudo: the unit of the .deb
runs as pegaprox with NoNewPrivileges) restarts the process in place. A plain exit 0 left
it stopped under that unit's Restart=on-failure.

MK Oct 2026
"""
import os
import types

import pytest

import pegaprox.api.settings as settings_mod
from pegaprox.core import ha
from test_ha_api import _admin


class _Left(BaseException):
    pass


def test_the_restart_button_restarts_in_place_where_systemctl_cannot(api, seed, monkeypatch, tmp_path):
    admin = _admin(api, seed)
    # this process runs in pegaprox.service
    cgroup = tmp_path / 'cgroup'
    cgroup.write_text('0::/system.slice/pegaprox.service\n')
    monkeypatch.setattr(settings_mod, '_CGROUP_FILE', str(cgroup), raising=False)
    started = []
    monkeypatch.setattr(settings_mod, 'threading', types.SimpleNamespace(
        Thread=lambda target=None, **kw: types.SimpleNamespace(start=lambda: started.append(target), daemon=True)))
    assert admin.post('/api/settings/server/restart', json={}).status_code == 200
    left, exits = [], []
    monkeypatch.setattr(settings_mod, 'time', types.SimpleNamespace(sleep=lambda s: None))
    monkeypatch.setattr(ha, 'planned_restart', lambda why: True)

    def leave():
        left.append(1)
        raise _Left()
    monkeypatch.setattr(ha, 'leave_process', leave)
    monkeypatch.setattr(os, '_exit', lambda code: exits.append(code))
    # the unit is active, but neither root nor a password-less sudo can restart it
    monkeypatch.setattr(os, 'geteuid', lambda: 1000)
    monkeypatch.setattr(settings_mod.shutil, 'which', lambda name: '/usr/bin/sudo')
    ran = []
    monkeypatch.setattr(settings_mod.subprocess, 'run', lambda cmd, **kw: ran.append(cmd) or types.SimpleNamespace(
        returncode=0 if cmd[:2] == ['systemctl', 'is-active'] else 1, stdout='', stderr=''))

    with pytest.raises(_Left):
        started[0]()

    assert left == [1] and exits == []
    assert ['sudo', '-n', 'systemctl', 'restart', 'pegaprox'] in ran


def test_no_restart_path_ends_in_a_plain_exit_0():
    src = open(settings_mod.__file__, encoding='utf-8').read()
    assert 'os._exit(0)' not in src
    assert src.count('ha.leave_process()') >= 3
