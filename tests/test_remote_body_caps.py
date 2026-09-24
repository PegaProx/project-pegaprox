"""Three places pulled a whole remote response into memory before looking at it.

  * The PBS file-level restore download. api_get_raw already asks PBS for a streamed
    response and its docstring says the point is to stream it on to the client - and
    then the handler called `resp.content`, which pulls the entire file into the hub
    first. Downloading anything large out of a backup was a self-inflicted outage.
  * The site-recovery webhook. Nothing reads the response, but without stream=True
    requests downloads the body anyway. The URL is operator-configured; the SSRF guard
    decides where it may point, not what comes back.
  * The update check. version.json is a few hundred bytes, and a hostile mirror - or
    anyone on the path - got to choose how many we buffer before .json() ever runs.

Aikido ai_pentest 700489378 / 700487653 / 700488091. MK
"""
import json
import types

import pytest


# --- PBS download ------------------------------------------------------------------

class _Resp:
    status_code = 200

    def __init__(self, blocks, length=None):
        self._blocks = blocks
        self.headers = {'content-type': 'application/octet-stream'}
        if length is not None:
            self.headers['content-length'] = str(length)
        self.content_touched = False
        self.streamed = False

    @property
    def content(self):
        self.content_touched = True
        return b''.join(self._blocks)

    def iter_content(self, chunk_size=None):
        self.streamed = True
        for b in self._blocks:
            yield b


def _download(api, pbs_mgr, monkeypatch):
    import pegaprox.api.pbs as pbs
    import pegaprox.globals as ppglobals
    from flask import request as _rq

    ppglobals.pbs_managers.clear()
    ppglobals.pbs_managers['pbs_a'] = pbs_mgr
    fn = pbs.download_pbs_file
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    monkeypatch.setattr(pbs, 'check_pbs_access', lambda pid: (True, None))
    monkeypatch.setattr(pbs, '_authz_pbs_backup', lambda *a, **kw: (True, None))
    qs = '?backup-type=vm&backup-id=100&backup-time=1&filepath=/etc/hosts'
    with api.app.test_request_context('/' + qs, base_url='http://localhost'):
        _rq.session = {'user': 'root', 'role': 'admin'}
        return fn('pbs_a', 'store1')


@pytest.fixture
def pbs_mgr():
    from unittest.mock import MagicMock
    m = MagicMock()
    m.linked_clusters = ['cluster_1']
    return m


def test_the_pbs_download_is_streamed_not_buffered(api, pbs_mgr, monkeypatch):
    blocks = [b'a' * 4096, b'b' * 4096]
    resp = _Resp(blocks, length=8192)
    pbs_mgr.download_file_from_snapshot.return_value = resp

    out = _download(api, pbs_mgr, monkeypatch)
    body = b''.join(out.response)          # consume it: Flask holds the iterator lazily

    assert not resp.content_touched, 'the whole file was pulled into memory'
    assert resp.streamed
    assert body == b''.join(blocks)


def test_the_length_is_passed_through_when_pbs_gives_one(api, pbs_mgr, monkeypatch):
    resp = _Resp([b'x' * 10], length=10)
    pbs_mgr.download_file_from_snapshot.return_value = resp

    out = _download(api, pbs_mgr, monkeypatch)

    assert out.headers['Content-Length'] == '10'


def test_no_length_is_invented_when_pbs_gives_none(api, pbs_mgr, monkeypatch):
    """We no longer know it without buffering, and a wrong one truncates the download."""
    resp = _Resp([b'x' * 10])
    pbs_mgr.download_file_from_snapshot.return_value = resp

    out = _download(api, pbs_mgr, monkeypatch)

    assert 'Content-Length' not in out.headers or out.headers['Content-Length'] != '10'


def test_the_filename_is_still_sanitised(api, pbs_mgr, monkeypatch):
    """The header-injection guard predates this and has to survive it."""
    import inspect
    import pegaprox.api.pbs as pbs
    fn = pbs.download_pbs_file
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__

    assert 'Content-Disposition' in inspect.getsource(fn)
    assert '\\r\\n' in inspect.getsource(fn) or 'x00-\\x1f' in inspect.getsource(fn)


# --- the two background callers ----------------------------------------------------

def test_the_webhook_never_downloads_its_response():
    import inspect
    import pegaprox.background.site_recovery as sr

    src = inspect.getsource(sr)
    i = src.index("'event': 'site_recovery'")
    window = src[max(0, i - 600):i + 600]
    assert 'stream=True' in window, window[-400:]


def test_the_update_check_reads_a_bounded_body():
    import inspect
    import pegaprox.background.alerts as al

    # anchor on the USE, not the import (src.index finds the import first), and stop
    # at the `break` - the same function parses other, unrelated JSON further down
    src = inspect.getsource(al)
    i = src.index('for url in (GITHUB_VERSION_URL')
    window = src[i:src.index('break', i)]
    # drop comment lines: the comment explaining this fix mentions .json() and would
    # trip the assertion below, which is the trap test_node_tmp_path_hardening warns about
    window = '\n'.join(l for l in window.splitlines() if not l.strip().startswith('#'))

    assert 'stream=True' in window
    assert '.json()' not in window, 'still parsing whatever arrived'
    assert 'raw.read(' in window
