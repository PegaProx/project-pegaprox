"""Two places where "we could not work it out" resolved in the caller's favour.

Both are the same shape as the pattern this codebase already has a name for: a
read that fails, an empty answer, and empty happening to mean "allowed".

1. user_has_any_pool_access caught its own exception and returned False. False
   there does not mean "holds no pool grant" — helpers.caller_is_scoped asks the
   question to decide whether the caller is a plain cluster-wide operator, and it
   wraps the call in its own try/except precisely so a failure falls closed.
   Swallowing the error inside meant that except never fired, so an unreadable
   pool_permissions table silently promoted every pool-scoped caller to
   unconfined — on exactly the endpoints that use confinement to decide how much
   of a cluster to show.

2. get_role_permissions_for_user fell back to the ROLE_VIEWER set for a role it
   could not resolve. A custom role exists because somebody wanted something
   NARROWER than viewer, so that fallback handed its holders more than the role
   ever granted: a role allowing only vm.view, once deleted, left its accounts
   with viewer's thirty-one permissions including the whole PBS read surface.
   Deleting a role means revoke, never promote.

Aikido ai_pentest 700487716 700487983. NS
"""
import pytest

from pegaprox.utils.rbac import get_role_permissions_for_user, user_has_any_pool_access


# --------------------------------------------------------------- the role side

def test_an_unresolvable_role_grants_nothing():
    perms = get_role_permissions_for_user({'username': 'x', 'role': 'role_that_is_gone'},
                                          'sometenant')
    assert perms == [], f'an unknown role handed out {len(perms)} permissions'


def test_it_is_specifically_not_the_viewer_set():
    """The shape of the old bug: viewer is 31 permissions, and a custom role is
    almost always narrower than that."""
    from pegaprox.models.permissions import ROLE_PERMISSIONS, ROLE_VIEWER
    perms = set(get_role_permissions_for_user({'username': 'x', 'role': 'gone'}, None))
    assert not (perms & set(ROLE_PERMISSIONS[ROLE_VIEWER])), 'still inheriting viewer'


def test_builtin_roles_are_untouched():
    """The mirror. Only non-builtin names reach the fallback."""
    from pegaprox.models.permissions import ROLE_PERMISSIONS, ROLE_VIEWER, ROLE_USER
    assert get_role_permissions_for_user({'role': 'viewer'}) == ROLE_PERMISSIONS[ROLE_VIEWER]
    assert get_role_permissions_for_user({'role': 'user'}) == ROLE_PERMISSIONS[ROLE_USER]
    assert get_role_permissions_for_user({}) == ROLE_PERMISSIONS[ROLE_VIEWER]


def test_a_real_custom_role_still_resolves(db):
    import pegaprox.utils.rbac as rbac
    assert rbac.save_custom_roles({'global': {'narrow': {'name': 'N',
                                                         'permissions': ['vm.view']}},
                                   'tenants': {}})
    rbac.invalidate_roles_cache()
    assert get_role_permissions_for_user({'role': 'narrow'}, None) == ['vm.view']


# --------------------------------------------------------------- the pool side

def test_a_failed_pool_read_is_not_reported_as_no_grant(monkeypatch):
    """It must raise, so the caller that knows what a failure means can fail closed."""
    import pegaprox.utils.rbac as rbac

    def _boom(*a, **kw):
        raise RuntimeError('pool_permissions unreadable')

    monkeypatch.setattr(rbac, '_pool_perms_for', _boom)
    with pytest.raises(RuntimeError):
        user_has_any_pool_access({'username': 'alice', 'role': 'user'}, 'cluster_1')


def test_the_caller_turns_that_into_confined(monkeypatch):
    """The property that matters: caller_is_scoped must answer 'confined' when the
    pool table cannot be read, not 'plain cluster-wide operator'."""
    import pegaprox.utils.rbac as rbac
    from pegaprox.api.helpers import caller_is_scoped

    def _boom(*a, **kw):
        raise RuntimeError('pool_permissions unreadable')

    monkeypatch.setattr(rbac, '_pool_perms_for', _boom)
    monkeypatch.setattr(rbac, 'get_user_clusters', lambda *a, **kw: None)

    assert caller_is_scoped({'username': 'alice', 'role': 'user'}, 'cluster_1') is True


def test_an_admin_is_still_unconfined(monkeypatch):
    """The mirror — admins short-circuit before any of this."""
    from pegaprox.api.helpers import caller_is_scoped
    assert caller_is_scoped({'username': 'boss', 'role': 'admin'}, 'cluster_1') is False
