"""The CVE scan told two lies, reported a few hours apart by the same person.

#825 — a node command that fails for a non-SSH reason came back as
"SSH connection failed". For a non-root cluster user every node command runs through
`sudo -n bash`, so on a node without passwordless sudo the login succeeds, sudo refuses,
and the operator reads a connection error next to their own sshd log showing an accepted
password and a clean session. The raw stderr only went out at DEBUG and the #717 hint
classifier had no sudo branch, so there was nothing in the logs either.

#827 — on a trixie node with no fixable CVEs the block fell back to
`debsecan --suite bookworm --only-fixed`, i.e. it evaluated the installed packages
against a different distribution. PVE 9 is trixie, so a fully patched Proxmox 9 node was
shown CVEs from a release it isn't running, some marked obsolete. Separately, `head -500`
cut a 1000-entry list in alphabetical order with nothing saying so.
MK
"""
import ast
import os
import pathlib
import shutil
import subprocess
import types

import pytest

from pegaprox.core.manager import _ssh_auth_hint, PegaProxManager

_SRC = (pathlib.Path(__file__).resolve().parent.parent
        / 'pegaprox' / 'core' / 'manager.py').read_text(encoding='utf-8')


def _scan_cmd():
    """The shell block scan_node_packages runs on the node."""
    tree = ast.parse(_SRC)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == 'scan_node_packages')

    def flat(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            return n.value
        if isinstance(n, ast.BinOp):
            return flat(n.left) + flat(n.right)
        return ''

    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', '') == 'scan_cmd'
                                                for t in node.targets):
            return flat(node.value)
    raise AssertionError('scan_cmd not found')


class _NullLog:
    def __getattr__(self, _):
        return lambda *a, **k: None


def _mgr(out, reason=None):
    """A manager stub that answers one canned node-command result.

    Only what the parse path touches: the CVE-history write goes to the real DB
    otherwise, which this test has no business doing.
    """
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = 'c-test'
    m.logger = _NullLog()
    m._ssh_node_output_ex = lambda node, cmd, timeout=60: (out, reason)
    return m


# ── #825: say what actually refused ──────────────────────────────────────────

@pytest.mark.parametrize('stderr,expect', [
    ('sudo: a password is required', 'sudo'),
    ('sudo: no tty present and no askpass program specified', 'sudo'),
    ('pegaprox is not in the sudoers file.  This incident will be reported.', 'sudoers'),
    ('sudo: command not found', 'sudo is not installed'),
])
def test_a_sudo_refusal_is_named_as_one(stderr, expect):
    hint = _ssh_auth_hint(stderr)
    assert hint, f"no hint for {stderr!r} — the operator gets silence again"
    assert expect in hint.lower()
    assert 'ssh works' in hint.lower() or 'sudoers' in hint.lower(), \
        "the hint must not read like a connection problem"


def test_the_717_hints_still_classify():
    """Regression guard: the sudo branch sits after these and must not shadow them."""
    assert 'key auth only' in _ssh_auth_hint('Permission denied (publickey).')
    assert 'password rejected' in _ssh_auth_hint('Permission denied (publickey,password).')
    assert 'host key' in _ssh_auth_hint('Host key verification failed.')
    assert 'invalid format' in _ssh_auth_hint('Load key "/tmp/k": invalid format')


def test_a_commands_own_permission_denied_is_not_read_as_sudo():
    """`cat: /etc/shadow: Permission denied` from the command itself is not an auth
    failure and must not produce an sshd-flavoured hint."""
    assert _ssh_auth_hint('cat: /etc/pve/priv/x: Permission denied') is not None  # generic branch
    assert 'sudo' not in (_ssh_auth_hint('cat: /x: Permission denied') or '').lower()


def test_the_scan_reports_the_real_reason_not_the_connection():
    mgr = _mgr(None, "SSH works, sudo does not: 'pegaprox' needs passwordless sudo")
    res = mgr.scan_node_packages('n1')
    assert 'sudo' in res['error'].lower()
    assert 'ssh connection failed' != res['error'].lower()


def test_an_actual_connection_failure_still_says_so():
    mgr = _mgr(None, None)
    assert mgr.scan_node_packages('n1')['error'] == 'SSH connection failed'


def test_ssh_node_output_still_returns_a_plain_string():
    """Eight callers rely on the old signature; only the scan uses the _ex variant."""
    tree = ast.parse(_SRC)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == '_ssh_node_output')
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    assert returns and all(not isinstance(r.value, ast.Tuple) for r in returns), \
        "_ssh_node_output must keep returning str|None — its other callers unpack nothing"


# ── #827: the right suite, and say when the list is cut ──────────────────────

def test_the_scan_never_queries_a_different_suite():
    cmd = _scan_cmd()
    assert '--suite bookworm' not in cmd, (
        "falling back to bookworm evaluates installed packages against another "
        "distribution; on PVE 9 (trixie) that is every node")
    assert cmd.count('--suite $SUITE') >= 2, "the detected suite is no longer what's queried"


def test_the_block_announces_suite_mode_and_total():
    cmd = _scan_cmd()
    for marker in ('SUITE=$SUITE', 'MODE=$MODE', 'TOTAL=$TOTAL', 'TRUNCATED='):
        assert marker in cmd, f"{marker} missing — the consumer can't tell what it got"


@pytest.mark.parametrize('blob,expect', [
    ("---DEBSECAN---\nSUITE=trixie\nMODE=all\nTOTAL=1043\nTRUNCATED=500\nCVE-2026-1 pkg1 low (open)\n---END---",
     {'suite': 'trixie', 'cve_mode': 'all', 'cve_total': 1043, 'cve_truncated': True}),
    ("---DEBSECAN---\nSUITE=trixie\nMODE=fixed\nTOTAL=2\nCVE-2026-1111 curl low (fixed)\n---END---",
     {'suite': 'trixie', 'cve_mode': 'fixed', 'cve_total': 2, 'cve_truncated': False}),
    ("---DEBSECAN---\nNOT_INSTALLED\n---END---",
     {'cve_mode': '', 'cve_total': 0, 'cve_truncated': False}),
])
def test_the_markers_reach_the_result(blob, expect):
    res = _mgr(blob).scan_node_packages('n1')
    for k, v in expect.items():
        assert res[k] == v, f"{k}: {res[k]!r} != {v!r}"


def test_a_truncated_run_is_flagged_rather_than_silently_short():
    res = _mgr("---DEBSECAN---\nSUITE=trixie\nMODE=all\nTOTAL=1043\nTRUNCATED=500\n"
               + '\n'.join(f"CVE-2026-{i} pkg{i} low (open)" for i in range(500))
               + "\n---END---").scan_node_packages('n1')
    assert res['cve_truncated'] is True
    assert res['cve_total'] == 1043
    assert res['cve_count'] < res['cve_total'], "count and total must be allowed to differ"


# ── the block, actually executed ─────────────────────────────────────────────

_FAKE_DEBSECAN = r'''#!/bin/bash
suite=""; only_fixed=0
while [ $# -gt 0 ]; do
  case "$1" in
    --suite) suite="$2"; shift 2;;
    --only-fixed) only_fixed=1; shift;;
    *) shift;;
  esac
done
echo "$suite $only_fixed" >> "$SCEN_LOG"
if [ "$SCENARIO" = patched ]; then
  [ "$only_fixed" = 1 ] && exit 0
  for i in $(seq 1 1043); do echo "CVE-2026-$i pkg$i"; done
else
  if [ "$only_fixed" = 1 ]; then echo "CVE-2026-1111 curl (fixed)"; fi
fi
'''


def _run_block(tmp_path, scenario):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    (bin_dir / 'debsecan').write_text(_FAKE_DEBSECAN)
    (bin_dir / 'lsb_release').write_text('#!/bin/bash\n[ "$1" = "-cs" ] && echo trixie\n')
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    log = tmp_path / 'calls'
    log.write_text('')
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}",
               SCENARIO=scenario, SCEN_LOG=str(log))
    p = subprocess.run(['bash', '-c', _scan_cmd()], capture_output=True, text=True, env=env)
    return p.stdout, log.read_text().split('\n')


@pytest.mark.skipif(not shutil.which('bash'), reason='no bash')
def test_a_patched_trixie_node_is_never_measured_against_bookworm(tmp_path):
    """The #827 case end to end: no fixable CVEs, so the old code went to bookworm."""
    out, calls = _run_block(tmp_path, 'patched')
    suites = {c.split()[0] for c in calls if c.strip()}
    assert suites == {'trixie'}, f"debsecan was asked about {suites}"
    assert 'MODE=all' in out and 'TOTAL=1043' in out and 'TRUNCATED=500' in out


@pytest.mark.skipif(not shutil.which('bash'), reason='no bash')
def test_the_fixed_list_is_preferred_and_not_capped_at_500(tmp_path):
    out, calls = _run_block(tmp_path, 'normal')
    assert 'MODE=fixed' in out
    assert len([c for c in calls if c.strip()]) == 1, \
        "a usable --only-fixed answer must not trigger a second, broader run"


@pytest.mark.skipif(not shutil.which('bash'), reason='no bash')
def test_the_block_is_valid_shell():
    p = subprocess.run(['bash', '-n'], input=_scan_cmd(), text=True, capture_output=True)
    assert p.returncode == 0, p.stderr
