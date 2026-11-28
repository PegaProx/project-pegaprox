"""A target VM Proxmox refuses to start is a warning of the run, in every path.

The offline copy, the pre-sync flow and the restarts of Live Mirror sent the start and logged
"VM <id> started" right after it: the API call raises only when no answer comes, so a refusal
(HTTP 500 "start failed: ...") was not seen at all, and a failure that was seen was a log line
under COMPLETED. They start through the checking helper of the clone path now: a VM that does
not run after it is a warning with the reason, and no downtime is counted for it.
"""
import pytest

import test_v2p_tpm_and_folder_copy as farm


def _refusing(r):
    real = r.pve._api_post

    def post(url, data=None, **kw):
        if url.endswith('/status/start'):
            r.pve.log.append(('pve_api', url.split('/api2/json', 1)[-1], []))
            return farm._Resp(None, status=500)
        return real(url, data, **kw)
    r.pve._api_post = post
    return r


# auto: the live clone's snapshot fails, so it falls back to the pre-sync flow
MODES = [('offline', {}), ('auto', {'clone_snap_fails': True}), ('sshfs_boot', {})]


@pytest.mark.parametrize('mode,kw', MODES, ids=[m for m, _ in MODES])
def test_a_refused_start_is_a_warning_and_never_called_started(monkeypatch, mode, kw):
    r = _refusing(farm.Run(monkeypatch, mode=mode, ssh_key='/tmp/v2p-key-fixed', **kw))
    r.go()
    t = r.task
    assert t.status == 'completed', t.error
    assert not r.pve.running
    assert any(w.startswith('The target VM 120 did not start: Proxmox refused the start: HTTP 500')
               and 'start it there' in w for w in t.warnings), t.warnings
    assert not any(('VM 120 started' in ln or 'VM 120 STARTED on' in ln or 'RESTARTED' in ln) for ln in t.log_lines), \
        [ln for ln in t.log_lines if 'VM 120' in ln]
    assert t.total_downtime_seconds is None


@pytest.mark.parametrize('mode,kw', MODES[:2], ids=[m for m, _ in MODES[:2]])
def test_a_start_that_runs_is_logged_as_before(monkeypatch, mode, kw):
    r = farm.Run(monkeypatch, mode=mode, ssh_key='/tmp/v2p-key-fixed', **kw).go()
    assert r.task.status == 'completed', r.task.error
    assert r.pve.running and not any('did not start' in w for w in r.task.warnings), r.task.warnings
    assert any('VM 120 started' in ln for ln in r.task.log_lines)
