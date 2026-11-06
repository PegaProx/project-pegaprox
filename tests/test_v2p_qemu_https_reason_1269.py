"""#1269 - the log said the QEMU HTTPS test failed, but not why.

qemu-img repeats the whole json spec before the reason, and the log kept the first 200 characters of
that, so "Server does not support 'range'" never reached it.
"""
import ast
import inspect

import pegaprox.core.v2p as v2p

SPEC = ('json:{"file.driver":"https","file.url":"https://10.0.0.20/folder/web01/web01-flat.vmdk?dcPath=ha-datacenter'
        '&dsName=ds1","file.username":"root","file.password-secret":"sec0","file.sslverify":"off"}')
REASON = "CURL: Error opening file: Server does not support 'range' (byte ranges)."


def test_the_reason_comes_without_the_spec_in_front():
    assert v2p._qemu_open_reason(f"qemu-img: Could not open '{SPEC}': {REASON}") == REASON


def test_output_of_another_shape_is_kept_from_its_end():
    other = 'x' * 500 + ' timed out'
    assert v2p._qemu_open_reason(other).endswith(' timed out')
    assert len(v2p._qemu_open_reason(other)) == 300
    assert v2p._qemu_open_reason('') == ''


def test_a_very_long_reason_stays_a_log_line():
    assert len(v2p._qemu_open_reason(f"Could not open '{SPEC}': " + 'y' * 900)) == 300


def test_the_failed_test_logs_that_reason():
    tree = ast.parse(inspect.getsource(v2p._do_sshfs_boot_migration))
    lines = [n for n in ast.walk(tree) if isinstance(n, ast.JoinedStr)
             and any(isinstance(v, ast.Constant) and 'QEMU HTTPS test failed' in str(v.value) for v in n.values)]
    assert len(lines) == 1
    calls = [n for n in ast.walk(lines[0]) if isinstance(n, ast.Call)]
    assert [getattr(c.func, 'id', '') for c in calls] == ['_qemu_open_reason'], ast.dump(lines[0])
