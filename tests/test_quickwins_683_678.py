# Quick-win regression tests:
#   #683 — a Proxmox account with 2FA enabled returns HTTP 200 + NeedTFA:1 and a partial ticket on
#          password login; PegaProxManager.connect_to_proxmox() must reject it with a clear error
#          instead of marking the cluster "connected" (then silently offline).
#   #678 — create_vm must append ,format=<fmt> to efidisk0/tpmstate0 when efi_format/tpm_format are
#          set, and must NOT emit a format= segment when they are absent (preserving the old default).

from unittest.mock import MagicMock

import pegaprox.core.manager as mgrmod
from pegaprox.models.tasks import PegaProxConfig


def _mk_manager(**overrides):
    cfg = {'name': 't', 'host': '127.0.0.1', 'user': 'root@pam', 'pass': 'secret'}
    cfg.update(overrides)
    return mgrmod.PegaProxManager('c1', PegaProxConfig(cfg))


# ---------------------------------------------------------------------------
# #683 — 2FA / NeedTFA detection
# ---------------------------------------------------------------------------

def test_683_connect_rejects_2fa_account_with_actionable_error(monkeypatch):
    class _Resp:
        status_code = 200
        text = ''
        # PVE's /access/ticket response for a TFA-enabled account: 200 + NeedTFA + partial ticket
        def json(self):
            return {'data': {'NeedTFA': 1, 'ticket': 'PVE:root@pam:PARTIAL::', 'CSRFPreventionToken': 'x'}}

    class _Session:
        def __init__(self):
            self.cookies = MagicMock()
            self.headers = {}
            self.verify = False
        def mount(self, *a, **k):
            pass
        def post(self, *a, **k):
            return _Resp()
        def get(self, *a, **k):
            return _Resp()
        def close(self):
            pass

    monkeypatch.setattr(mgrmod.requests, 'Session', _Session)
    m = _mk_manager()  # password auth (no api_token) → hits the /access/ticket path

    assert m.connect_to_proxmox() is False          # must NOT report success
    assert m.is_connected is False
    err = (m.connection_error or '').lower()
    assert 'two-factor' in err or '2fa' in err or 'api token' in err, m.connection_error
    # the message must also offer the temporarily-disable-2FA option, and expose the machine code
    # the UI maps to a localized hint (all 8 languages)
    assert 'disable' in err or 'temporarily' in err, m.connection_error
    assert getattr(m, 'connection_error_code', None) == 'NEEDS_2FA'


def test_683_normal_password_login_still_connects(monkeypatch):
    # a non-2FA account: 200 WITHOUT NeedTFA must still connect (no over-block)
    class _Resp:
        status_code = 200
        text = ''
        def json(self):
            return {'data': {'ticket': 'PVE:root@pam:GOODTICKET::', 'CSRFPreventionToken': 'x'}}

    class _Session:
        def __init__(self):
            self.cookies = MagicMock()
            self.headers = {}
            self.verify = False
        def mount(self, *a, **k): pass
        def post(self, *a, **k): return _Resp()
        def get(self, *a, **k): return _Resp()
        def close(self): pass

    monkeypatch.setattr(mgrmod.requests, 'Session', _Session)
    # avoid the auto token-create follow-up call path touching the network
    monkeypatch.setattr(mgrmod.PegaProxManager, '_try_create_api_token', lambda self, *a, **k: None)
    monkeypatch.setattr(mgrmod.PegaProxManager, '_auto_discover_fallback_hosts', lambda self, *a, **k: None)
    m = _mk_manager()

    assert m.connect_to_proxmox() is True
    assert m.is_connected is True
    assert m._ticket == 'PVE:root@pam:GOODTICKET::'


# ---------------------------------------------------------------------------
# #678 — EFI/TPM disk format
# ---------------------------------------------------------------------------

def _capture_create_vm_data(monkeypatch, vm_config):
    """Run the real create_vm but capture the dict it POSTs to PVE."""
    captured = {}

    def fake_api_post(self, url, data=None, **k):
        captured['url'] = url
        captured['data'] = data
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {'data': 'UPID:test'}
        return resp

    def fake_api_get(self, *a, **k):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {'data': []}
        return resp

    monkeypatch.setattr(mgrmod.PegaProxManager, '_api_post', fake_api_post)
    monkeypatch.setattr(mgrmod.PegaProxManager, '_api_get', fake_api_get)
    # pretend we're already connected so create_vm goes straight to building + POSTing the config
    monkeypatch.setattr(mgrmod.PegaProxManager, 'connect_to_proxmox', lambda self, *a, **k: True)
    m = _mk_manager()
    m.is_connected = True
    m.session = True
    m.create_vm('node1', vm_config)
    return captured.get('data', {})


BASE_VM = {'vmid': 999, 'name': 'testvm', 'storage': 'local', 'cores': 1, 'memory': 512,
           'disk_size': '8', 'ostype': 'l26', 'bios': 'ovmf'}


def test_678_efi_and_tpm_format_appended_when_set(monkeypatch):
    cfg = dict(BASE_VM, efi_storage='local', efi_format='qcow2',
               tpm_storage='local', tpm_format='qcow2')
    data = _capture_create_vm_data(monkeypatch, cfg)
    assert 'efidisk0' in data and 'format=qcow2' in data['efidisk0'], data.get('efidisk0')
    assert 'tpmstate0' in data and 'format=qcow2' in data['tpmstate0'], data.get('tpmstate0')


def test_678_no_format_segment_when_unset(monkeypatch):
    # default (no efi_format/tpm_format) must NOT add a format= segment — preserves the old behaviour
    cfg = dict(BASE_VM, efi_storage='local', tpm_storage='local')
    data = _capture_create_vm_data(monkeypatch, cfg)
    assert 'efidisk0' in data and 'format=' not in data['efidisk0'], data.get('efidisk0')
    assert 'tpmstate0' in data and 'format=' not in data['tpmstate0'], data.get('tpmstate0')
