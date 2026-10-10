"""The security self-check scores only what it checked.

Two of its eight controls were the constant True (audit logging, brute-force protection),
and the score divided by all eight, so every install started with a quarter of the points.
Each control now reads the configuration the instance runs with, or answers 'not_checked'
with the reason, and the score is taken over the checked ones only.

The per-node hardening checks had the same blind spot: a control whose output did not come
back read as FAIL. It is None now, and the route counts it apart. MK Oct 2026
"""
import pytest

from pegaprox.core.manager import PegaProxManager as _M


def _get(api, user, **kw):
    r = api.as_user(user).get('/api/security/compliance', **kw)
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def _by_id(body):
    return {c['id']: c for c in body['controls']}


def test_score_is_taken_over_checked_controls_only(api, seed):
    admin = seed.user('root', role='admin')
    seed.db.save_server_setting('reverse_proxy_enabled', True)
    body = _get(api, admin)
    ctl = _by_id(body)
    # the test client talks plain HTTP from behind no proxy that says what the client used
    assert ctl['https_enabled']['status'] == 'not_checked' and ctl['https_enabled']['reason']
    checked = [c for c in body['controls'] if c['status'] != 'not_checked']
    passed = [c for c in checked if c['status'] == 'passed']
    assert body['total'] == len(body['controls']) == 8
    assert body['checked'] == len(checked) and body['not_checked'] == 8 - len(checked)
    assert body['compliance_score'] == round(len(passed) / len(checked) * 100, 1)
    # the old shape stays readable: True, False, None
    assert body['checks']['https_enabled'] is None
    assert set(body['checks'].values()) <= {True, False, None}


def test_no_control_is_a_constant(api, seed):
    """audit logging and brute-force protection used to be True whatever the config said."""
    admin = seed.user('root', role='admin')
    seed.db.save_server_setting('login_max_attempts', 50)
    ctl = _by_id(_get(api, admin))
    assert ctl['brute_force_protection']['status'] == 'failed'
    seed.db.save_server_setting('login_max_attempts', 5)
    seed.db.save_server_setting('login_lockout_time', 300)
    assert _by_id(_get(api, admin))['brute_force_protection']['status'] == 'passed'


def test_audit_logging_looks_at_the_newest_entry(api, seed):
    admin = seed.user('root', role='admin')
    seed.db.conn.execute('DELETE FROM audit_log')
    seed.db.conn.commit()
    assert _by_id(_get(api, admin))['audit_logging_enabled']['status'] == 'not_checked'
    seed.db.add_audit_entry('root', 'test.signed', 'x')
    assert _by_id(_get(api, admin))['audit_logging_enabled']['status'] == 'passed'
    seed.db.conn.execute("INSERT INTO audit_log (timestamp, user, action, details, ip_address, hmac_signature) "
                         "VALUES ('2026-10-10T00:00:00', 'x', 'unsigned.row', '', '', '')")
    seed.db.conn.commit()
    assert _by_id(_get(api, admin))['audit_logging_enabled']['status'] == 'failed'


def test_two_factor_counts_when_it_is_required(api, seed):
    admin = seed.user('root', role='admin')
    seed.db.save_server_setting('force_2fa', False)
    assert _by_id(_get(api, admin))['two_factor_enforced']['status'] == 'failed'
    seed.db.save_server_setting('force_2fa', True)
    # the admin asking has no second factor, the exclusion keeps the route reachable - and
    # leaves the accounts 2FA matters most for on a password alone, so it is no pass
    seed.db.save_server_setting('force_2fa_exclude_admins', True)
    body = _get(api, admin)
    ctl = _by_id(body)['two_factor_enforced']
    assert ctl['status'] == 'failed' and 'except the admins' in ctl['detail']
    assert any('admins too' in r for r in body['recommendations'])


def test_two_factor_passes_when_it_covers_the_admins(api, seed):
    admin = seed.user('root', role='admin')
    # an enrolled admin, so force_2fa lets the request through
    rec = seed.db.get_user('root')
    rec.update(totp_enabled=True, totp_secret='JBSWY3DPEHPK3PXP')
    seed.db.save_user('root', rec)
    seed.db.save_server_setting('force_2fa', True)
    seed.db.save_server_setting('force_2fa_exclude_admins', False)
    assert _by_id(_get(api, admin))['two_factor_enforced']['status'] == 'passed'


def test_session_control_names_remember_me(api, seed):
    admin = seed.user('root', role='admin')
    seed.db.save_server_setting('session_timeout', 3600)
    body = _get(api, admin)
    ctl = _by_id(body)['session_timeout_compliant']
    assert ctl['status'] == 'failed' and 'Remember me' in ctl['detail']
    # the timeout itself is fine, so the advice is not to lower it
    assert not any('Reduce session timeout' in r for r in body['recommendations'])
    seed.db.save_server_setting('session_timeout', 86400)
    body = _get(api, admin)
    assert any('Reduce session timeout' in r for r in body['recommendations'])


@pytest.mark.parametrize('proto,want', [('https', 'passed'), ('http', 'failed')])
def test_https_believes_a_trusted_proxy(api, seed, proto, want):
    admin = seed.user('root', role='admin')
    body = _get(api, admin, headers={'X-Forwarded-Proto': proto})
    assert _by_id(body)['https_enabled']['status'] == want


def test_plain_http_without_a_proxy_fails(api, seed):
    admin = seed.user('root', role='admin')
    seed.db.save_server_setting('reverse_proxy_enabled', False)
    assert _by_id(_get(api, admin))['https_enabled']['status'] == 'failed'


def test_unreadable_settings_are_not_judged_on_defaults(api, seed, monkeypatch):
    admin = seed.user('root', role='admin')
    db = seed.db

    def boom():
        raise RuntimeError('table gone')
    monkeypatch.setattr(db, 'get_server_settings', boom)
    ctl = _by_id(_get(api, admin))
    for cid in ('password_policy_enabled', 'session_timeout_compliant', 'brute_force_protection'):
        assert ctl[cid]['status'] == 'not_checked', cid
        assert 'could not be read' in ctl[cid]['reason']


def test_compliance_needs_the_security_permission(api, seed):
    u = seed.user('pat', role='user')
    assert api.as_user(u).get('/api/security/compliance').status_code == 403


# ---- per-node hardening ----------------------------------------------------------------

def _pve(raw):
    m = _M.__new__(_M)
    m._ssh_node_output = lambda node, cmd, timeout=90: raw
    return m


def test_a_control_without_output_is_not_checked_not_failed():
    ids = list(_M.CIS_CHECKS)[:4]
    raw = '\n'.join([
        f'---{ids[0]}---', 'OK',
        f'---{ids[1]}---', 'FAIL',
        f'---{ids[2]}---', 'bash: line 1: sshd: command not found',
        # ids[3] and everything after it never came back: the output was cut off
    ])
    res = _M.check_node_hardening(_pve(raw), 'pve1')
    assert res[ids[0]] is True and res[ids[1]] is False
    assert res[ids[2]] is None and res[ids[3]] is None
    assert set(res) == set(_M.CIS_CHECKS)        # every control answers


def test_a_stray_line_before_the_verdict_does_not_turn_ok_into_fail():
    cid = list(_M.CIS_CHECKS)[0]
    res = _M.check_node_hardening(_pve(f'---{cid}---\nwarning: something\nOK\n---END---'), 'pve1')
    assert res[cid] is True


def test_verbose_marks_the_unread_control():
    ids = list(_M.CIS_CHECKS)[:2]
    raw = f'---{ids[0]}---\nOK\n---{ids[0]}:EVIDENCE---\nfine\n---{ids[1]}---\n---END---'
    res = _M.check_node_hardening(_pve(raw), 'pve1', verbose=True)
    assert res[ids[0]]['status'] is True and 'fine' in res[ids[0]]['evidence']
    assert res[ids[1]]['status'] is None and res[ids[1]]['not_checked']


def test_xcpng_fills_unread_controls_with_none():
    from pegaprox.core.xcpng import XcpngManager
    m = XcpngManager.__new__(XcpngManager)
    first = list(XcpngManager._CIS_CHECKS)[0]
    m._ssh_exec = lambda node, cmd, timeout=60: (0, f'---{first}---\nOK\n', '')
    res = XcpngManager.check_node_hardening(m, 'h1')
    assert res[first] is True
    assert all(v is None for k, v in res.items() if k != first)


def test_the_route_counts_not_checked_apart(api, seed):
    seed.db.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted) "
                    "VALUES ('cluster_1', 'cluster_1', '10.0.0.1', 'root@pam', 'x')")
    m = api.make_fake_manager('cluster_1', check_node_hardening={'a': True, 'b': False, 'c': None})
    m.is_connected = True
    m._effective_profile = lambda p: p or 'cis-l1'
    api.set_manager('cluster_1', m)
    admin = seed.user('root', role='admin')
    body = api.as_user(admin).get('/api/clusters/cluster_1/nodes/pve1/hardening').get_json()
    assert body['summary'] == {'total': 3, 'passed': 1, 'failed': 1, 'not_checked': 1, 'checked': 2}
    assert body['controls']['c'] is None
