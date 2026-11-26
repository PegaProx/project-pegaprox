"""An upgrade of the Debian package restarts PegaProx once.

The postinst restarted the unit itself, and the part dh_installsystemd puts after it at
#DEBHELPER# restarts it again (deb-systemd-invoke restart, where there is a version before).
The unit is Type=simple, so systemctl returns at once and the second restart came a few
seconds into the first start of the new version: the start that encrypts the database. Only
a first install starts the unit in our part now; debhelper's start after it finds it running.

The debhelper part below is the one in the published pegaprox_1.5.0-1_all.deb, written by
dh_installsystemd 13.11.4 for this debian/ directory (compat 13, no override). MK Nov 2026
"""
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEBHELPER = """\
# Automatically added by dh_installsystemd/13.11.4
if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ] ; then
\t# The following line should be removed in trixie or trixie+1
\tdeb-systemd-helper unmask 'pegaprox.service' >/dev/null || true

\t# was-enabled defaults to true, so new installations run enable.
\tif deb-systemd-helper --quiet was-enabled 'pegaprox.service'; then
\t\t# Enables the unit on first installation, creates new
\t\t# symlinks on upgrades if the unit file has changed.
\t\tdeb-systemd-helper enable 'pegaprox.service' >/dev/null || true
\telse
\t\t# Update the statefile to add new symlinks (if any), which need to be
\t\t# cleaned up on purge. Also remove old symlinks.
\t\tdeb-systemd-helper update-state 'pegaprox.service' >/dev/null || true
\tfi
fi
# End automatically added section
# Automatically added by dh_installsystemd/13.11.4
if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ] ; then
\tif [ -d /run/systemd/system ]; then
\t\tsystemctl --system daemon-reload >/dev/null || true
\t\tif [ -n "$2" ]; then
\t\t\t_dh_action=restart
\t\telse
\t\t\t_dh_action=start
\t\tfi
\t\tdeb-systemd-invoke $_dh_action 'pegaprox.service' >/dev/null || true
\tfi
fi
# End automatically added section
"""

STARTS = re.compile(r"^(systemctl (re)?start pegaprox\.service|deb-systemd-invoke (re)?start pegaprox\.service)$")


def _read(*rel):
    return ROOT.joinpath(*rel).read_text(encoding='utf-8')


def _built_postinst(text, tmp_path):
    """The postinst as the package carries it: the debhelper part at #DEBHELPER#, systemd
    running, its paths under a temp root and every command it calls a stub that writes down
    how it was called. The key step and the plugin sync are other tests'."""
    root = tmp_path / 'root'
    run_dir = tmp_path / 'run-systemd-system'
    run_dir.mkdir(parents=True)
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    calls = tmp_path / 'calls.log'
    for cmd in ('id', 'useradd', 'chown', 'systemctl', 'deb-systemd-helper', 'deb-systemd-invoke'):
        (stubs / cmd).write_text(f'#!/bin/sh\necho "{cmd} $*" >> "{calls}"\nexit 0\n')
        (stubs / cmd).chmod(0o755)
    assert text.count('#DEBHELPER#') == 1
    text = text.replace('#DEBHELPER#', DEBHELPER)
    text = text.replace('/usr/bin/python3', 'true')
    for path in ('/var/lib/pegaprox', '/usr/share/pegaprox', '/usr/lib/pegaprox', '/etc/pegaprox'):
        text = text.replace(path, str(root) + path)
    text = text.replace('/run/systemd/system', str(run_dir))
    script = tmp_path / 'postinst'
    script.write_text(text)
    env = dict(os.environ, PATH=f'{stubs}:{os.environ.get("PATH", "")}')

    def run(*args):
        if calls.exists():
            calls.unlink()
        r = subprocess.run(['bash', str(script), *args], env=env, capture_output=True, text=True,
                           timeout=60)
        assert r.returncode == 0, r.stdout + r.stderr
        return [ln.replace("'", '') for ln in calls.read_text().splitlines() if STARTS.match(ln.replace("'", ''))]
    return run


def test_an_upgrade_restarts_the_unit_once(tmp_path):
    run = _built_postinst(_read('debian', 'pegaprox.postinst'), tmp_path)
    assert run('configure', '1.5.0-1') == ['deb-systemd-invoke restart pegaprox.service']


def test_a_first_install_still_starts_it(tmp_path):
    run = _built_postinst(_read('debian', 'pegaprox.postinst'), tmp_path)
    # ours starts it, debhelper's start then finds it running: no second restart
    assert run('configure') == ['systemctl restart pegaprox.service', 'deb-systemd-invoke start pegaprox.service']


def test_counterproof_the_postinst_of_1_5_0_restarted_an_upgrade_twice(tmp_path):
    ours = _read('debian', 'pegaprox.postinst')
    block = '    if [ -z "$2" ]; then\n        systemctl restart pegaprox.service || true\n    fi\n'
    assert ours.count(block) == 1
    before = ours.replace(block, '    systemctl restart pegaprox.service || true\n')
    run = _built_postinst(before, tmp_path)
    assert run('configure', '1.5.0-1') == ['systemctl restart pegaprox.service',
                                           'deb-systemd-invoke restart pegaprox.service']


def test_debhelper_restarts_on_upgrade_because_nothing_tells_it_otherwise():
    """The upgrade restart is debhelper's alone now. An override of dh_installsystemd
    (--no-restart-after-upgrade, --no-start, a compat level below 10) would leave an upgrade
    running the old code until the next reboot."""
    rules = _read('debian', 'rules')
    assert 'dh_installsystemd' not in rules and 'override_' not in rules
    assert re.search(r'^\s*dh \$@\s*$', rules, re.M)
    assert 'debhelper-compat (= 13)' in _read('debian', 'control')
    postinst = _read('debian', 'pegaprox.postinst')
    assert postinst.rstrip().splitlines()[-1] == '#DEBHELPER#'
