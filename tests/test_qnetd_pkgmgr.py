"""init of packaging/qnetd/pegaprox-qnetd-helper with dnf, yum and zypper (helper protocol
2), the environment file of RHEL and SUSE, and the NSS database there.

The stand-ins of test_qnetd_helper, without apt-get: a dnf, yum or zypper stand-in logs
its argv and the variables the helper hands it, and on install copies corosync-qnetd and
certutil into place from a stash (and runs what the test gives it as the package's own
files, the environment file of the rpm for one).

MK Oct 2026
"""
import os
import shutil

import pytest

from test_qnetd_helper import HELPER, FakeBins, load_helper, slurp

H = load_helper()

FAKE_PM = r'''#!/bin/sh
HERE=$(dirname "$0")
n=$(basename "$0")
echo "$n $* | ZYPP_LOCK_TIMEOUT=${ZYPP_LOCK_TIMEOUT:-} DEBIAN_FRONTEND=${DEBIAN_FRONTEND:-} umask=$(umask)" >> "$HERE/calls.txt"
[ -f "$HERE/pm-stderr" ] && cat "$HERE/pm-stderr" >&2
[ -f "$HERE/pm-rc" ] && exit "$(cat "$HERE/pm-rc")"
case " $* " in
    *" install "*)
        cp -p "$HERE"/pm-stash/* "$HERE"/
        [ -f "$HERE/pm-post" ] && sh "$HERE/pm-post"
        ;;
esac
exit 0
'''

# what the rpm ships as /etc/sysconfig/corosync-qnetd (Fedora's spec sets RUNAS)
RPM_SYSCONFIG = ('# Corosync Qdevice Network daemon init script configuration file\n\n'
                 '# COROSYNC_QNETD_OPTIONS specifies options passed to corosync-qnetd command\n'
                 '# (default is no options).\n'
                 'COROSYNC_QNETD_OPTIONS=""\n\n'
                 'COROSYNC_QNETD_RUNAS="coroqnetd"\n')


class RpmHost(FakeBins):
    """A QNetd host without apt-get and without corosync-qnetd."""

    def __init__(self, base, pm='dnf'):
        FakeBins.__init__(self, base)
        os.unlink(os.path.join(self.bin, 'apt-get'))
        stash = os.path.join(self.bin, 'pm-stash')
        os.makedirs(stash)
        for name in ('certutil', 'corosync-qnetd'):
            shutil.move(os.path.join(self.bin, name), os.path.join(stash, name))
        if pm:
            self.write(pm, FAKE_PM)
        self.sysconfig = os.path.join(self.base, 'etc', 'sysconfig', 'corosync-qnetd')
        self.default = os.path.join(self.base, 'etc', 'default', 'corosync-qnetd')

    def ships_sysconfig(self, text=RPM_SYSCONFIG):
        """The package puts its environment file into /etc/sysconfig on install."""
        src = os.path.join(self.bin, 'pm-sysconfig')
        with open(src, 'w') as fh:
            fh.write(text)
        with open(os.path.join(self.bin, 'pm-post'), 'w') as fh:
            fh.write('mkdir -p "%s"\ncp "%s" "%s"\n' % (os.path.dirname(self.sysconfig), src, self.sysconfig))

    def says(self, text, rc):
        with open(os.path.join(self.bin, 'pm-stderr'), 'w') as fh:
            fh.write(text)
        with open(os.path.join(self.bin, 'pm-rc'), 'w') as fh:
            fh.write(str(rc))

    def pm_calls(self):
        return [c for c in self.calls() if c.startswith(('dnf ', 'yum ', 'zypper ', 'apt-get '))]


@pytest.fixture
def dnf(tmp_path):
    return RpmHost(tmp_path, 'dnf')


def test_dnf_installs_corosync_qnetd_and_nss_tools_and_tls_is_required(dnf):
    dnf.ships_sysconfig()
    rc, ans = dnf.helper('version')
    assert rc == 0 and ans['package_manager'] == 'dnf' and ans['packages'] == ['corosync-qnetd', 'nss-tools']
    rc, ans = dnf.helper('init')
    assert rc == 0 and ans['installed'] is True and ans['tls_set'] is True and ans['created'] is True, ans
    assert dnf.pm_calls() == [
        'dnf -y --setopt=timeout=15 --setopt=retries=2 --setopt=install_weak_deps=False install corosync-qnetd '
        'nss-tools | ZYPP_LOCK_TIMEOUT= DEBIAN_FRONTEND= umask=0022']
    # the file of the rpm, its other lines kept; nothing written to /etc/default
    text = slurp(dnf.sysconfig).decode()
    assert 'COROSYNC_QNETD_OPTIONS="-s req"\n' in text and 'COROSYNC_QNETD_RUNAS="coroqnetd"\n' in text
    assert text.startswith('# Corosync Qdevice') and not os.path.exists(dnf.default)
    calls = dnf.calls()
    assert calls.index('systemctl enable --now corosync-qnetd.service') < \
        calls.index('systemctl restart corosync-qnetd.service')
    # again: installed, nothing to do
    rc, ans = dnf.helper('init')
    assert rc == 0 and ans['installed'] is False and len(dnf.pm_calls()) == 1


def test_yum_where_there_is_no_dnf(tmp_path):
    host = RpmHost(tmp_path, 'yum')
    assert host.helper('version')[1]['package_manager'] == 'yum'
    rc, ans = host.helper('init')
    assert rc == 0 and ans['installed'] is True, ans
    # yum 3 knows no install_weak_deps
    assert host.pm_calls() == ['yum -y --setopt=timeout=15 --setopt=retries=2 install corosync-qnetd nss-tools'
                               ' | ZYPP_LOCK_TIMEOUT= DEBIAN_FRONTEND= umask=0022']


def test_zypper_installs_mozilla_nss_tools_and_never_trusts_a_key_on_its_own(tmp_path):
    host = RpmHost(tmp_path, 'zypper')
    host.ships_sysconfig()
    assert host.helper('version')[1]['packages'] == ['corosync-qnetd', 'mozilla-nss-tools']
    rc, ans = host.helper('init')
    assert rc == 0 and ans['installed'] is True and ans['tls_set'] is True, ans
    assert host.pm_calls() == ['zypper --non-interactive install --no-recommends corosync-qnetd mozilla-nss-tools'
                               ' | ZYPP_LOCK_TIMEOUT=120 DEBIAN_FRONTEND= umask=0022']
    assert 'COROSYNC_QNETD_OPTIONS="-s req"\n' in slurp(host.sysconfig).decode()
    with open(HELPER) as fh:
        text = fh.read()
    for word in ('--gpg-auto-import-keys', '--no-gpg-checks', '--nogpgcheck', 'gpgcheck=0', '--allow-unsigned'):
        assert word not in text.replace("never runs with\n    --gpg-auto-import-keys", ''), word


def test_apt_get_comes_first_where_there_are_several(tmp_path):
    host = FakeBins(tmp_path)
    host.write('dnf', FAKE_PM)
    assert host.helper('version')[1]['package_manager'] == 'apt'


def test_without_any_package_manager_it_says_what_to_install(tmp_path):
    host = RpmHost(tmp_path, None)
    rc, ans = host.helper('version')
    assert ans['package_manager'] is None and ans['packages'] == []
    rc, ans = host.helper('init')
    assert rc == 1 and ans['code'] == 'not_installed'
    assert 'no apt-get, dnf, yum or zypper' in ans['error'] and 'nss-tools' in ans['error']


@pytest.mark.parametrize('pm,text,rc', [
    ('dnf', 'No match for argument: corosync-qnetd\nError: Unable to find a match: corosync-qnetd\n', 1),
    ('yum', 'No package corosync-qnetd available.\nError: Nothing to do\n', 1),
    ('zypper', "'corosync-qnetd' not found in package names. Trying capabilities.\n"
               "No provider of 'corosync-qnetd' found.\n", 104),
    ('zypper', 'Nothing here\n', 104),
])
def test_a_repository_without_the_package_says_where_it_is(tmp_path, pm, text, rc):
    host = RpmHost(tmp_path, pm)
    host.says(text, rc)
    rc, ans = host.helper('init')
    assert rc == 1 and ans['code'] == 'not_installed', ans
    assert 'High Availability' in ans['error'] and pm in ans['error']
    assert not os.path.exists(host.db)


@pytest.mark.parametrize('pm,text', [
    ('dnf', "Curl error (6): Couldn't resolve host name for https://mirrors.rockylinux.org/x "
            "[Could not resolve host: mirrors.rockylinux.org]\n"
            "Error: Failed to download metadata for repo 'baseos': Cannot download repomd.xml\n"),
    ('dnf', 'Curl error (28): Timeout was reached for https://mirror.example/repomd.xml\n'),
    ('yum', 'Could not retrieve mirrorlist http://mirrorlist.centos.org/ error was\n'
            '14: curl#6 - "Could not resolve host: mirrorlist.centos.org; Unknown error"\n'),
    ('zypper', "Download (curl) error for 'http://download.opensuse.org/x':\n"
               'Error code: Connection failed\nError message: Could not resolve host: download.opensuse.org\n'),
])
def test_no_route_to_the_package_sources_is_said_as_such(tmp_path, pm, text):
    host = RpmHost(tmp_path, pm)
    host.says(text, 1)
    rc, ans = host.helper('init')
    assert rc == 1 and ans['code'] == 'no_package_sources', ans
    assert 'cannot reach the package sources' in ans['error']


def test_another_failure_names_the_last_line(dnf):
    dnf.says('Error:\n Problem: conflicting requests\n  - nothing provides libfoo.so needed by corosync-qnetd\n', 1)
    rc, ans = dnf.helper('init')
    assert rc == 1 and ans['code'] == 'not_installed' and 'nothing provides libfoo.so' in ans['error']


# --- where the environment file is -------------------------------------------------------------

def test_the_environment_file_is_the_one_that_is_there(tmp_path):
    host = RpmHost(tmp_path, 'dnf')
    h = H.Host('systemd', host.env())
    assert h.defaults_files == (host.default, host.sysconfig)
    # nothing there, no apt-get, no /etc/sysconfig: /etc/default
    assert h.defaults_file == host.default
    os.makedirs(os.path.dirname(host.sysconfig))
    assert h.defaults_file == host.sysconfig
    os.makedirs(os.path.dirname(host.default))
    with open(host.default, 'w') as fh:
        fh.write('COROSYNC_QNETD_OPTIONS=""\n')
    assert h.defaults_file == host.default


def test_the_environment_file_the_unit_names(tmp_path):
    host = RpmHost(tmp_path, 'dnf')
    host.write('systemctl', '#!/bin/sh\necho "systemctl $*" >> "$(dirname "$0")/calls.txt"\n'
                            'case "$*" in "show -p EnvironmentFiles corosync-qnetd.service") '
                            'echo "EnvironmentFiles=/etc/sysconfig/corosync-qnetd (ignore_errors=yes)" ;; esac\n')
    h = H.Host('systemd', host.env())
    # neither file there yet, no /etc/sysconfig directory: the unit decides
    assert h.defaults_file == host.sysconfig
    assert H._unit_environment_file(H.Host('sidecar', host.env())) is None


def test_a_fresh_rpm_install_without_the_file_gets_one_in_sysconfig(tmp_path):
    host = RpmHost(tmp_path, 'dnf')
    os.makedirs(os.path.dirname(host.sysconfig))
    rc, ans = host.helper('init')
    assert rc == 0 and ans['tls_set'] is True, ans
    assert slurp(host.sysconfig) == b'COROSYNC_QNETD_OPTIONS="-s req"\n'


# --- the NSS database of an rpm install ---------------------------------------------------------

def test_the_database_follows_the_owner_of_the_config_directory(tmp_path, monkeypatch):
    """corosync-qnetd-certutil gives what it makes the owner and group of
    /etc/corosync/qnetd (chown --reference): coroqnetd on RHEL, where the rpm gives the
    daemon that directory. The helper does the same, as root, and gives the group
    coroqnetd read access only where the directory is root's (Debian)."""
    host = FakeBins(tmp_path)
    h = H.Host('systemd', host.env())
    st = os.stat(host.conf)
    owned, regrouped = [], []
    real_fchown = os.fchown
    monkeypatch.setattr(H.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(H.os, 'fchown', lambda fd, uid, gid: (owned.append((uid, gid)), real_fchown(fd, -1, -1)))
    monkeypatch.setattr(H.os, 'chown', lambda *a, **k: regrouped.append(a))
    assert H.ensure_db(h) is True
    assert owned and set(owned) == {(st.st_uid, st.st_gid)}
    if st.st_gid != 0:
        assert regrouped == []


def test_a_symlinked_database_is_never_followed(tmp_path):
    host = FakeBins(tmp_path)
    elsewhere = os.path.join(host.base, 'elsewhere')
    os.makedirs(elsewhere)
    os.chmod(elsewhere, 0o755)
    os.symlink(elsewhere, host.db)
    rc, ans = host.helper('init')
    assert rc == 1 and ans['code'] == 'not_initialised' and 'symlink' in ans['error'], ans
    assert os.listdir(elsewhere) == [] and oct(os.stat(elsewhere).st_mode & 0o777) == '0o755'


def test_fix_never_follows_a_symlink(tmp_path):
    host = FakeBins(tmp_path)
    h = H.Host('systemd', host.env())
    target = os.path.join(host.base, 'target')
    with open(target, 'w') as fh:
        fh.write('x')
    os.chmod(target, 0o600)
    link = os.path.join(host.base, 'link')
    os.symlink(target, link)
    with pytest.raises(H.Refused):
        H._fix(h, link, 0o644)
    assert oct(os.stat(target).st_mode & 0o777) == '0o600'
