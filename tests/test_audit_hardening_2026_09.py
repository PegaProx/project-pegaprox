# E2E for the 2026-09 audit hardening fixes:
#   - a password change / admin reset now revokes the user's API tokens (were left valid → an
#     exfiltrated token survived the standard "lock the intruder out" action)
#   - the web-push endpoint validator now delegates to the central SSRF guard: fail-CLOSED on an
#     unresolvable host (was fail-open) and IPv6/transition-address aware
from pegaprox.utils.auth import create_api_token, validate_api_token, revoke_user_api_tokens


def test_admin_password_reset_revokes_tokens(api, seed):
    bob = seed.user('bob', role='viewer')
    admin = seed.user('root', role='admin')
    tok = create_api_token('bob', 'tok')['token']
    assert validate_api_token(tok) is not None, "token should be valid before the reset"
    resp = api.as_user(admin).put('/api/users/bob/password', json={'password': 'NewPassw0rd!23'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert validate_api_token(tok) is None, "token must be revoked after an admin password reset"


def test_revoke_helper(db, seed):
    seed.user('carl', role='viewer')
    tok = create_api_token('carl', 'tok')['token']
    assert validate_api_token(tok) is not None
    assert revoke_user_api_tokens('carl') == 1
    assert validate_api_token(tok) is None


def test_push_validator_blocks_and_fails_closed():
    from pegaprox.api.push import _is_internal_or_metadata_host as f
    assert f('169.254.169.254') is True, "cloud metadata must be blocked"
    assert f('127.0.0.1') is True, "loopback must be blocked"
    assert f('10.0.0.1') is True, "RFC1918 must be blocked"
    assert f('') is True
    # the key regression: an unresolvable host now fails CLOSED (was 'let it through')
    assert f('no-such-host-zzz.invalid') is True, "unresolvable host must fail closed"
