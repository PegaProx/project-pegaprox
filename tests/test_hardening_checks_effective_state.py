"""Three hardening controls tested a marker we write ourselves, not the node's state.

Found while reviewing the compliance section Sep 2026. `ssh_crypto` grepped sshd_config for
the comment banner our own apply step leaves behind, `sysctl_hardening` for one line in our
own drop-in, `journald` for a key in our own drop-in. Two ways that goes wrong:

  * an admin who hardened the node by hand reads FAIL, and the tool looks broken
  * the marker survives while the settings underneath change, and we report PASS on a node
    that is not hardened - which in a report someone hands an auditor is the bad direction

The banner case is the sharp one: it is a COMMENT. Any config-management run that rewrites
directives and keeps comments leaves it in place. All three now ask for the effective state
(`sshd -T`, `sysctl -n`, the merged journald config) instead.

The checks run as a single shell string built from a static dict and parsed line by line -
the parser takes the FIRST line after the marker, so each one has to print exactly OK or
FAIL and nothing else. That is pinned here too, because a stray line breaks every control
after it in the same batch.
MK
"""
import shutil
import subprocess
import textwrap

import pytest

from pegaprox.core.manager import PegaProxManager as _M

_CHECKS = dict(_M.CIS_CHECKS)
_CHECKS.update(_M._VSNFD_EXTRA_CHECKS)
_REWRITTEN = ('ssh_crypto', 'sysctl_hardening', 'journald')

pytestmark = pytest.mark.skipif(not shutil.which('bash'), reason='no bash')


def _run(cid, path_prepend=None, env=None):
    """Run a control's check command, return its single-line verdict."""
    import os
    e = dict(os.environ, **(env or {}))
    if path_prepend:
        e['PATH'] = f"{path_prepend}:{e['PATH']}"
    p = subprocess.run(['bash', '-c', _CHECKS[cid]['check']],
                       capture_output=True, text=True, timeout=30, env=e)
    return p.stdout, p.stderr


def _stub(d, name, body):
    f = d / name
    f.write_text(textwrap.dedent(body))
    f.chmod(0o755)
    return f


# What each rewritten control has to interrogate. Naming the tool is the property that
# matters - "does not contain these three strings" would let the next marker-based check
# through under a different filename, which is how this got here in the first place.
_QUERIES_LIVE_STATE = {
    'ssh_crypto': ('sshd -T',),
    'sysctl_hardening': ('sysctl -n',),
    'journald': ('systemd-analyze cat-config', '/etc/systemd/journald.conf'),
}


@pytest.mark.parametrize('cid', _REWRITTEN)
def test_the_check_asks_the_system_not_a_file_we_wrote(cid):
    cmd = _CHECKS[cid]['check']
    for marker in ('CIS SSH Cryptographic Hardening', '99-pegaprox-hardening.conf',
                   '99-cis-hardening.conf'):
        assert marker not in cmd, (
            f"{cid} still keys on {marker!r} - a file we write. An admin who hardened by "
            f"hand reads FAIL, and a stale marker over changed settings reads PASS.")
    wanted = _QUERIES_LIVE_STATE.get(cid)
    assert wanted, (f"{cid} is in _REWRITTEN but nothing says what it should query - add it "
                    f"to _QUERIES_LIVE_STATE, otherwise this test passes on absence alone")
    assert any(w in cmd for w in wanted), (
        f"{cid} no longer queries the effective state - expected one of {wanted}. "
        f"Absence of the old markers is not the property; asking the system is.")


@pytest.mark.parametrize('cid', _REWRITTEN)
def test_the_check_does_not_key_on_any_path_our_apply_step_writes(cid):
    """Generalises the above: whatever files the matching apply step creates must not be
    what the check looks for, whatever they end up being called."""
    import re
    apply_cmd = str(_CHECKS[cid].get('apply', ''))
    written = set(re.findall(r'/etc/[\w./-]+', apply_cmd))
    check_cmd = _CHECKS[cid]['check']
    # Reading the system's own view is fine even where our apply step also writes:
    # the main config file, and the whole drop-in DIRECTORY (every admin's drop-in, not
    # just ours). What must not appear is a specific filename we create - the first
    # assertion above covers those by name.
    written -= {'/etc/systemd/journald.conf', '/etc/ssh/sshd_config',
                '/etc/systemd/journald.conf.d'}
    leaked = sorted(w for w in written if w in check_cmd)
    assert not leaked, f"{cid} checks for files its own apply step creates: {leaked}"


@pytest.mark.parametrize('cid', _REWRITTEN)
def test_the_check_prints_exactly_one_verdict(cid, tmp_path):
    """The batch parser takes the first line after the marker. Anything extra on stdout
    shifts every following control in the same SSH round."""
    out, _ = _run(cid)
    lines = [l for l in out.splitlines() if l.strip()]
    assert len(lines) == 1, f"{cid} printed {len(lines)} lines: {out!r}"
    assert lines[0].strip() in ('OK', 'FAIL'), f"{cid} printed {lines[0]!r}"


@pytest.mark.parametrize('cid', _REWRITTEN)
def test_the_check_is_valid_shell(cid):
    p = subprocess.run(['bash', '-n'], input=_CHECKS[cid]['check'], text=True,
                       capture_output=True)
    assert p.returncode == 0, p.stderr


# ── ssh_crypto: both directions, against a stubbed `sshd -T` ─────────────────

_SSHD = """\
    #!/bin/bash
    [ "$1" = "-T" ] || exit 1
    cat <<'CFG'
    ciphers {ciphers}
    macs {macs}
    gssapiauthentication {gssapi}
    hostbasedauthentication no
    ignorerhosts yes
    permituserenvironment no
    CFG
    """


def _sshd_stub(tmp_path, ciphers, macs, gssapi='no'):
    d = tmp_path / 'bin'
    d.mkdir(exist_ok=True)
    _stub(d, 'sshd', _SSHD.format(ciphers=ciphers, macs=macs, gssapi=gssapi))
    return d


def test_ssh_crypto_passes_on_a_hardened_daemon(tmp_path):
    d = _sshd_stub(tmp_path,
                   'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr',
                   'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com')
    out, _ = _run('ssh_crypto', path_prepend=str(d))
    assert out.strip() == 'OK'


@pytest.mark.parametrize('ciphers,macs,why', [
    ('aes256-ctr,aes128-cbc', 'hmac-sha2-256-etm@openssh.com', 'CBC cipher'),
    ('aes256-ctr', 'hmac-sha2-256,hmac-md5', 'MD5 MAC'),
    ('aes256-ctr,arcfour', 'hmac-sha2-256-etm@openssh.com', 'arcfour'),
    ('aes256-ctr,3des-cbc', 'hmac-sha2-256-etm@openssh.com', '3DES'),
    ('aes256-ctr', 'hmac-sha1-96', 'truncated MAC'),
])
def test_ssh_crypto_fails_on_weak_algorithms(tmp_path, ciphers, macs, why):
    """The old check would have said OK for every one of these as long as the banner
    comment was still in sshd_config."""
    d = _sshd_stub(tmp_path, ciphers, macs)
    out, _ = _run('ssh_crypto', path_prepend=str(d))
    assert out.strip() == 'FAIL', f"{why} accepted"


def test_ssh_crypto_fails_when_gssapi_is_on(tmp_path):
    d = _sshd_stub(tmp_path, 'aes256-ctr', 'hmac-sha2-512-etm@openssh.com', gssapi='yes')
    assert _run('ssh_crypto', path_prepend=str(d))[0].strip() == 'FAIL'


def test_ssh_crypto_fails_when_sshd_cannot_be_asked(tmp_path):
    """No sshd, no answer - that must not read as compliant."""
    d = tmp_path / 'bin'
    d.mkdir(exist_ok=True)
    _stub(d, 'sshd', '#!/bin/bash\nexit 1\n')
    out, _ = _run('ssh_crypto', path_prepend=str(d))
    assert out.strip() == 'FAIL'


# ── sysctl_hardening: the running kernel, not the file ──────────────────────

_SYSCTL = """\
    #!/bin/bash
    [ "$1" = "-n" ] || exit 1
    case "$2" in
      fs.suid_dumpable) echo "$SUID_VAL" ;;
      net.ipv4.conf.all.rp_filter|net.ipv4.tcp_syncookies|kernel.dmesg_restrict) echo 1 ;;
      fs.protected_hardlinks|fs.protected_symlinks) echo 1 ;;
      kernel.randomize_va_space|kernel.kptr_restrict) echo 2 ;;
      net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.send_redirects) echo 0 ;;
      net.ipv4.conf.all.accept_source_route) echo 0 ;;
      *) exit 1 ;;
    esac
    """


def test_sysctl_passes_when_the_running_kernel_matches(tmp_path):
    d = tmp_path / 'bin'; d.mkdir(exist_ok=True)
    _stub(d, 'sysctl', _SYSCTL)
    out, _ = _run('sysctl_hardening', path_prepend=str(d), env={'SUID_VAL': '0'})
    assert out.strip() == 'OK'


def test_sysctl_fails_when_a_single_value_drifted(tmp_path):
    """The file can still say the right thing while the kernel does not - a later drop-in
    or a runtime override wins. That is the case the old file-grep could not see."""
    d = tmp_path / 'bin'; d.mkdir(exist_ok=True)
    _stub(d, 'sysctl', _SYSCTL)
    out, _ = _run('sysctl_hardening', path_prepend=str(d), env={'SUID_VAL': '1'})
    assert out.strip() == 'FAIL'


# ── journald: the merged config, wherever the operator put it ───────────────

def test_journald_accepts_the_setting_in_the_main_file(tmp_path):
    """Previously only our own drop-in counted, so a hand-configured node read FAIL."""
    d = tmp_path / 'bin'; d.mkdir(exist_ok=True)
    cfg = tmp_path / 'journald.conf'
    cfg.write_text('[Journal]\nStorage=persistent\nSystemMaxUse=500M\n')
    _stub(d, 'systemd-analyze', '#!/bin/bash\ncat "$FAKE_JOURNALD"\n')
    out, _ = _run('journald', path_prepend=str(d), env={'FAKE_JOURNALD': str(cfg)})
    assert out.strip() == 'OK'


def test_journald_fails_when_nothing_caps_the_journal(tmp_path):
    d = tmp_path / 'bin'; d.mkdir(exist_ok=True)
    cfg = tmp_path / 'journald.conf'
    cfg.write_text('[Journal]\nStorage=persistent\n')
    _stub(d, 'systemd-analyze', '#!/bin/bash\ncat "$FAKE_JOURNALD"\n')
    out, _ = _run('journald', path_prepend=str(d), env={'FAKE_JOURNALD': str(cfg)})
    assert out.strip() == 'FAIL'


# ── the profile a report is allowed to name ─────────────────────────────────

def test_cis_l2_resolves_to_the_profile_that_actually_ran():
    """cis-l2 mapped to the same 44 controls as cis-l1 while the UI offered it and the PDF
    printed the chosen name in a labelled field. A report naming a level nobody checked is
    the one failure mode a compliance feature cannot have."""
    assert _M._effective_profile('cis-l2') == 'cis-l1'
    assert _M._effective_profile('cis-l1') == 'cis-l1'
    assert _M._effective_profile(None) == 'cis-l1'
    for p in ('vs-nfd', 'bsi', 'iso', 'stig'):
        assert _M._effective_profile(p) == p, f"{p} must not be rewritten"


def test_cis_l2_is_still_accepted_so_saved_links_do_not_break():
    """Dropping it from the dropdown is a UI change; the API keeps answering."""
    assert 'cis-l2' in _M._HARDENING_PROFILES


def test_the_two_cis_profiles_have_not_silently_diverged():
    """If someone gives cis-l2 a real control set later, _effective_profile has to stop
    collapsing it - this test is the reminder."""
    if _M._HARDENING_PROFILES.get('cis-l2') is not None:
        pytest.fail("cis-l2 now has its own control set - drop the alias in "
                    "_effective_profile and put the option back in the dropdown")


# ── the XCP-ng call site ────────────────────────────────────────────────────

def test_both_managers_take_the_same_hardening_arguments():
    """api/reports.py calls check_node_hardening(node, verbose=, profile=) for whatever is
    in cluster_managers, and XCP-ng clusters live in the same dict. Its method took only
    (self, node_name), so opening the hardening panel on an XCP-ng host raised TypeError
    and the route answered 500. Surfaced by the daily scan as an api mismatch at the call
    site, then reproduced directly."""
    import inspect
    from pegaprox.core.xcpng import XcpngManager

    pve = inspect.signature(_M.check_node_hardening).parameters
    xcp = inspect.signature(XcpngManager.check_node_hardening).parameters
    for kw in ('verbose', 'profile'):
        assert kw in xcp, f"XcpngManager.check_node_hardening cannot take {kw}= - the shared route passes it"
        assert kw in pve


def test_the_xcpng_manager_does_not_raise_on_the_shared_call_shape():
    from pegaprox.core.xcpng import XcpngManager
    m = XcpngManager.__new__(XcpngManager)
    # Deliberately not pytest.raises(Exception): the stub has no SSH, so today something
    # does blow up further in - but the test must still be right on the day it doesn't.
    # The only failure this pins is the signature.
    try:
        XcpngManager.check_node_hardening(m, 'host1', verbose=True, profile='cis-l1')
    except TypeError as e:
        pytest.fail(f"still a signature mismatch: {e}")
    except Exception:
        pass


def test_an_xcpng_result_is_not_labelled_with_a_pve_profile():
    """XCP-ng runs its own ten checks and ignores the profile argument. Echoing back
    'cis-l1' would put a PVE profile name on an XCP-ng result - the same mislabel as
    cis-l2, one hypervisor over."""
    from pegaprox.core.xcpng import XcpngManager
    for asked in ('cis-l1', 'bsi', None):
        eff = XcpngManager._effective_profile(asked)
        assert eff != asked or asked is None and eff != 'cis-l1'
        assert eff not in _M._HARDENING_PROFILES, \
            f"an XCP-ng run must not be labelled with the PVE profile {eff!r}"
        # and it must stay a string: the field was never nullable and callers indexed on it
        assert isinstance(eff, str) and eff
