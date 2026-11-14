"""The XAPI session of a disk upload stays out of the task, the stream and the logs.

import_raw_vdi and export_raw_vdi take the session in the query string, and a request
that fails names its url in the exception text. That text became the task error, a line
of the SSE log every migration viewer gets, an audit entry and a server log line, and
the support bundle copied the log as it was. The session is the pool login until XCP-ng
drops it. The task, the module logger and the bundle now print session_id=*** instead.
MK Nov 2026
"""
import io
import logging
import subprocess
import types
import zipfile

import requests

import pegaprox.core.xhm as xhm_core
import pegaprox.globals as ppglobals
from pegaprox.api import settings as settings_mod
from test_xhm_esxi_to_xcpng_attaches_disks import DISKS, ESXI, TGT, _Xapi

SESSION = 'OpaqueRef:5b1d0c77-pool-login'


def _run_with_a_failing_upload(monkeypatch, tmp_path):
    def _proc(argv, **kw):
        with open(argv[-1], 'wb') as fh:
            fh.write(b'\0' * 16)
        return types.SimpleNamespace(returncode=0, stderr=b'', stdout=b'')

    def _put(method, url, **kw):
        # what requests says when the pool does not answer
        path = url.split('://', 1)[1].split('/', 1)[1]
        raise requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='xcp', port=443): Max retries exceeded with url: /{path} "
            "(Caused by NewConnectionError('Failed to establish a new connection: [Errno 111]'))")

    sse, audit = [], []
    monkeypatch.setattr(subprocess, 'run', _proc)
    monkeypatch.setattr(xhm_core.ha_transport, 'http', _put)
    monkeypatch.setattr(xhm_core, 'broadcast_sse', lambda kind, data: sse.append((kind, data)))
    monkeypatch.setattr(xhm_core, 'log_audit', lambda *a, **k: audit.append((a, k)))
    monkeypatch.setitem(ppglobals.cluster_managers, ESXI, types.SimpleNamespace(
        is_connected=True, host='10.0.0.5', config=types.SimpleNamespace(ssh_user='root', pass_='pw'),
        get_vm_disks_for_export=lambda vmid: DISKS))
    xapi = _Xapi()
    monkeypatch.setitem(ppglobals.cluster_managers, TGT, types.SimpleNamespace(
        is_connected=True, host='xcp', _api=lambda: xapi, _session=types.SimpleNamespace(_session=SESSION),
        config=types.SimpleNamespace(ssl_verification=False)))
    task = xhm_core.XHMigrationTask('t-sess', 'esxi_to_xcpng', ESXI, '', '5', TGT, '', 'sr1')
    task.scratch = str(tmp_path / 'scratch')
    task._last_sse_log = -1e9     # every line goes out, as the first one of a second does
    xhm_core._run_esxi_to_xcpng(task)
    return task, sse, audit


def test_a_failed_upload_names_the_url_without_the_session(db, monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger=xhm_core.logger.name)
    task, sse, audit = _run_with_a_failing_upload(monkeypatch, tmp_path)

    assert task.phase == 'failed', task.log_lines[-4:]
    # the operator still learns which call failed, and how
    assert 'import_raw_vdi?session_id=***&vdi=' in task.error, task.error
    assert 'Max retries exceeded' in task.error
    assert SESSION not in task.error
    assert not [line for line in task.log_lines if SESSION in line]
    assert SESSION not in repr(task.to_dict())
    assert sse and not [d for _, d in sse if SESSION in repr(d)]
    assert audit and SESSION not in repr(audit)
    assert 'Transfer error' in caplog.text and SESSION not in caplog.text


def test_a_traceback_of_the_module_logger_keeps_its_lines_but_not_the_session(caplog):
    caplog.set_level(logging.INFO, logger=xhm_core.logger.name)
    try:
        raise RuntimeError(f'PUT https://xcp/import_raw_vdi?session_id={SESSION}&vdi=u1 refused')
    except RuntimeError:
        xhm_core.logger.exception('[XHM:t1] unhandled error')
    xhm_core.logger.info('upload to %s', f'https://xcp/export_raw_vdi?vdi=u1&session_id={SESSION}')

    assert 'Traceback (most recent call last)' in caplog.text
    assert 'import_raw_vdi?session_id=***&vdi=u1 refused' in caplog.text
    assert 'export_raw_vdi?vdi=u1&session_id=***' in caplog.text
    assert SESSION not in caplog.text


def test_the_support_bundle_blanks_a_session_in_the_log(api, seed, tmp_path, monkeypatch):
    (tmp_path / 'pegaprox.log').write_text(
        f"2026-11-11 08:00:01 ERROR [XHM:t1] Transfer error: url: /import_raw_vdi?session_id={SESSION}&vdi=u1\n"
        # a line written before the log record sanitizer was there, the map of a pool move
        f"2026-11-11 08:00:02 ERROR remote_migrate_vm 101: {{'force': 'true', 'session_id': '{SESSION}'}}\n"
        "2026-11-11 08:00:03 INFO [XHM:t1] Phase: failed\n")
    monkeypatch.setattr(settings_mod, 'LOG_DIR', str(tmp_path))
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.get('/api/support-bundle')
    assert r.status_code == 200, r.data[:300]
    with zipfile.ZipFile(io.BytesIO(r.data)) as zf:
        name = next(n for n in zf.namelist() if n.endswith('/pegaprox.log'))
        log = zf.read(name).decode()
    assert SESSION not in log
    # the same helper as the log lines, so the same mark
    assert 'import_raw_vdi?session_id=***&vdi=u1' in log
    assert "remote_migrate_vm 101: {'force': 'true', 'session_id': '***'}" in log
    assert 'Phase: failed' in log
