"""/api/pegaprox/security/status reported 0 active sessions, always.

`active_sessions` is defined in pegaprox/globals.py. At boot, app.py calls
utils/auth.load_sessions(), which does

    global active_sessions
    active_sessions = db.get_all_sessions()

That rebinds utils.auth's OWN name to a new dict. Every module that imported the
name earlier — settings.py among them — keeps pointing at the original, which is
empty at that moment and stays empty forever: logins write into the live dict.

So the security panel told an operator "0 active sessions" on a box with everyone
logged in, and the support bundle shipped an empty sessions_info.json — precisely
the artifact you reach for when working out who was on the system during an
incident.

WHY THE FIXTURE BELOW EXISTS. The first version of this test asserted the count
over a real minted session and passed against the BROKEN code, because the test
process never calls load_sessions(): the bindings never diverge in-process, so
settings.py and utils.auth were still the same object and the bug could not
appear. The fixture reproduces the post-boot state instead — stale original left
empty, live dict elsewhere — which is the only state in which this defect exists.
A test that cannot fail is not evidence. MK
"""
import pytest

import pegaprox.utils.auth as authmod

STATUS = '/api/pegaprox/security/status'


@pytest.fixture
def after_boot(api):
    """Put the process in the state load_sessions() leaves it in: utils.auth
    holds a fresh dict, and the object every other module imported is the empty
    pre-boot original."""
    original = authmod.active_sessions
    live = dict(original)
    original.clear()
    authmod.active_sessions = live
    try:
        yield live
    finally:
        authmod.active_sessions = original


@pytest.fixture
def admin(api, seed, after_boot):
    return api.as_user(seed.user('statusadmin', role='admin'))


def test_the_panel_counts_the_session_it_is_being_asked_over(admin, after_boot):
    # premise: the caller's session went into the LIVE store, and the stale
    # binding other modules hold is the empty one. Without both, no defect.
    assert len(after_boot) >= 1
    import pegaprox.api.settings as settingsmod
    assert settingsmod.active_sessions is not after_boot, \
        'bindings did not diverge — this test cannot detect the bug'

    r = admin.get(STATUS)
    assert r.status_code == 200, r.data

    reported = r.get_json()['session_management']['active_sessions']
    assert reported == len(after_boot), (
        f'panel reports {reported} sessions, the live store holds {len(after_boot)}')
    assert reported >= 1


def test_a_second_session_moves_the_number(api, seed, admin, after_boot):
    first = admin.get(STATUS).get_json()['session_management']['active_sessions']

    api.as_user(seed.user('statusother', role='user'))

    second = admin.get(STATUS).get_json()['session_management']['active_sessions']
    assert second == first + 1, f'a new login did not move the counter: {first} -> {second}'
