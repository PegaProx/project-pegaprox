"""Controls of the security self-check that still pass without the property they name."""


def _ctl(api, user):
    r = api.as_user(user).get('/api/security/compliance')
    assert r.status_code == 200, r.get_data(as_text=True)
    return {c['id']: c for c in r.get_json()['controls']}


def test_session_timeout_does_not_pass_while_remember_me_sessions_idle_for_30_days(api, seed):
    """The control reads session_timeout only. Every login may ask for remember=true, and
    such a session idles for 30 days (7 days absolute) whatever session_timeout says;
    nothing can switch that off."""
    from pegaprox.utils import auth
    admin = seed.user('root', role='admin')
    seed.db.save_server_setting('session_timeout', 3600)
    with api.app.test_request_context('/'):
        sid = auth.create_session('root', 'admin', remember=True)
    with auth.sessions_lock:
        auth.active_sessions[sid]['last_activity'] -= 10 * 86400     # idle for ten days
    assert auth.validate_session(sid) is not None                   # still a live session
    assert _ctl(api, admin)['session_timeout_compliant']['status'] != 'passed'


def test_two_factor_does_not_pass_when_the_admins_are_exempt(api, seed):
    """force_2fa with force_2fa_exclude_admins: every admin signs in with a password alone,
    and the control reads passed."""
    admin = seed.user('root', role='admin')
    seed.db.save_server_setting('force_2fa', True)
    seed.db.save_server_setting('force_2fa_exclude_admins', True)
    assert _ctl(api, admin)['two_factor_enforced']['status'] != 'passed'
