"""#1269 - the log said the QEMU HTTPS test failed, but not why.

qemu-img repeats the whole json spec before the reason, and the log kept the first 200 characters of
that, so "Server does not support 'range'" never reached it.
"""
import pytest

import pegaprox.core.v2p as v2p
from test_v2p_tpm_and_folder_copy import Run

SPEC = ('json:{"file.driver":"https","file.url":"https://10.0.0.20/folder/web01/web01-flat.vmdk?dcPath=ha-datacenter'
        '&dsName=ds1","file.username":"root","file.password-secret":"sec0","file.sslverify":"off"}')
REASON = "CURL: Error opening file: Server does not support 'range' (byte ranges)."


def test_the_reason_comes_without_the_spec_in_front():
    assert v2p._qemu_open_reason(f"qemu-img: Could not open '{SPEC}': {REASON}") == REASON


def test_output_of_another_shape_is_kept_from_its_end():
    other = 'x' * 500 + ' timed out'
    assert v2p._qemu_open_reason(other) == other[-300:]
    assert v2p._qemu_open_reason('') == ''


def test_output_that_stops_after_the_spec_does_not_log_nothing():
    cut = f"qemu-img: Could not open '{SPEC}': "
    assert v2p._qemu_open_reason(cut) == cut[-300:]


def test_a_very_long_reason_stays_a_log_line():
    assert len(v2p._qemu_open_reason(f"Could not open '{SPEC}': " + 'y' * 900)) == 300


PW = 'Passw0rd!Secret'


def _log_of_failing_qemu_tests(monkeypatch, output):
    """The log of an sshfs_boot run in which every qemu-img info answers with `output`: the SSH
    test, the HTTPS test and the fallback after them are the real code."""
    r = Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed')
    r.task.esxi_password = PW
    node = r.node

    def failing(mgr, n, cmd, *a, **k):
        if 'qemu-img info' in cmd:
            return 1, output, ''
        return node(mgr, n, cmd, *a, **k)
    monkeypatch.setattr(v2p, '_pve_node_exec', failing)
    return r.go().task.log_lines


TESTS = ['QEMU HTTPS test failed', 'QEMU SSH driver test failed']


@pytest.mark.parametrize('text', TESTS)
def test_the_failed_test_logs_that_reason(monkeypatch, text):
    log = _log_of_failing_qemu_tests(monkeypatch, f"qemu-img: Could not open '{SPEC}': {REASON}")
    lines = [line for line in log if text in line]
    assert len(lines) == 1 and lines[0].endswith(f'failed: {REASON}'), lines


@pytest.mark.parametrize('text', TESTS)
def test_a_password_at_the_cut_leaves_no_piece_of_itself(monkeypatch, text):
    # the 300 characters end inside the password: cut before the redaction, it is no longer found
    log = _log_of_failing_qemu_tests(monkeypatch, f"Could not open '{SPEC}': " + 'x' * 290 + PW + ' tail')
    lines = [line for line in log if text in line]
    assert len(lines) == 1 and PW[:4] not in lines[0], lines
