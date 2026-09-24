"""Two more findings from the autofix bot's open pile that held up under checking.

  #869  the re-auth gate for sensitive operations (/api/auth/verify-password) probes
        webauthn_credentials to decide which rung of the OIDC ladder applies. The probe
        swallowed its own error into "no key enrolled", and the bottom rung accepts on
        session validity alone - so a database hiccup turned re-auth into a no-op for
        precisely the admins who had secured themselves with a security key. The login
        path had the same bug and was fixed earlier this month; this is its twin.

  #854  the XCP-ng remote migration built its session to the target pool with
        ignore_ssl pinned to True. Every other XenAPI session in that file already
        derives it from the cluster's ssl_verification setting, so an operator who
        turned verification on got it everywhere except the one leg that carries the
        disks.

MK
"""
import logging

import pytest


# --------------------------------------------------------------------------- #869
def _oidc_admin(db, name='sso-admin'):
    db.save_user(name, {'role': 'admin', 'enabled': True, 'auth_source': 'oidc'})
    return {'username': name, 'role': 'admin'}


def test_the_bottom_rung_still_accepts_when_nothing_is_enrolled(api, db):
    """Positive control: this is the documented behaviour and must not change."""
    u = _oidc_admin(db)
    r = api.as_user(u).post('/api/auth/verify-password', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['success'] is True


def test_an_unreadable_enrolment_table_does_not_become_an_open_door(api, db, monkeypatch):
    import pegaprox.api.auth as apiauth

    u = _oidc_admin(db, 'key-admin')

    class _ProbeFails:
        def query(self, *a, **k):
            raise RuntimeError('database is locked')
        def __getattr__(self, name):
            return getattr(db, name)
    monkeypatch.setattr(apiauth, 'get_db', lambda: _ProbeFails())

    r = api.as_user(u).post('/api/auth/verify-password', json={})

    assert r.status_code != 200, "session validity alone passed the re-auth gate"
    assert r.status_code == 503
    assert r.get_json()['code'] == 'MFA_STATE_UNAVAILABLE'


def test_a_working_probe_still_demands_the_proof(api, db, monkeypatch):
    """The refusal above must not be the only thing standing between a key-holder and
    the gate - with a readable table the WebAuthn rung still applies."""
    import pegaprox.api.auth as apiauth

    u = _oidc_admin(db, 'has-key')

    class _OneKey:
        def query(self, *a, **k):
            return [{'n': 1}]
        def __getattr__(self, name):
            return getattr(db, name)
    monkeypatch.setattr(apiauth, 'get_db', lambda: _OneKey())

    r = api.as_user(u).post('/api/auth/verify-password', json={})
    assert r.status_code == 401
    assert r.get_json().get('requires_webauthn') is True


# --------------------------------------------------------------------------- #854
class _RecordingSession:
    calls = []

    def __init__(self, url, ignore_ssl=None):
        _RecordingSession.calls.append({'url': url, 'ignore_ssl': ignore_ssl})
        self._session = 'OpaqueRef:session'
        self.xenapi = self

    def login_with_password(self, *a, **k):
        return None


def _migrate_with(ssl_verification, monkeypatch):
    """Drive remote_migrate_vm far enough to build the target session, and hand back
    the kwargs it used."""
    import types
    from pegaprox.core import xcpng

    _RecordingSession.calls = []
    monkeypatch.setattr(xcpng, 'XenAPI',
                        types.SimpleNamespace(Session=_RecordingSession))

    mgr = object.__new__(xcpng.XcpngManager)
    mgr.config = types.SimpleNamespace(ssl_verification=ssl_verification,
                                       user='root', pass_='secret')
    fake_api = types.SimpleNamespace(
        VM=types.SimpleNamespace(get_power_state=lambda ref: 'Halted'))
    mgr._api = lambda: fake_api
    mgr._resolve_vm = lambda vmid: 'OpaqueRef:vm'
    mgr.logger = logging.getLogger('test.xcpng')

    # everything past the session build may fail; the call we care about already
    # happened by then and the method funnels errors into a result dict.
    mgr.remote_migrate_vm('node1', 101, target_endpoint='https://target.example')
    assert _RecordingSession.calls, "the target session was never built"
    return _RecordingSession.calls[0]


def test_verification_on_means_the_migration_leg_verifies(monkeypatch):
    assert _migrate_with(True, monkeypatch)['ignore_ssl'] is False


def test_verification_off_is_still_honoured(monkeypatch):
    assert _migrate_with(False, monkeypatch)['ignore_ssl'] is True


def test_the_flag_is_not_pinned(monkeypatch):
    """The counter-proof: before the fix both settings produced ignore_ssl=True."""
    on = _migrate_with(True, monkeypatch)['ignore_ssl']
    off = _migrate_with(False, monkeypatch)['ignore_ssl']
    assert on != off, "the setting makes no difference - the flag is still hardcoded"
