"""Three findings the Aikido autofix bot raised that we had genuinely not covered.

The bot's own patches were not usable - one checked the raw session role (the exact bug
fixed in groups.py the day before), one would have blocked emergency failover entirely,
one swapped a permission check for a hardcoded role. The findings behind them were real,
so they are rebuilt here.

  #888  a pool grant to a GROUP escaped the tenant boundary. Group names come from LDAP
        or OIDC and carry no tenant association; the grant matches by name, so a
        tenant-scoped delegate could hand pool permissions to a group whose members sit
        somewhere else. _authz_object_write was already checking user subjects against
        the caller's tenant - with subject_type='group' it was handed an empty list and
        checked nothing.

  #879  emergency failover starts the replica while the source is presumed gone. If the
        source is actually still up, both guests run on the same replicated disks. The
        bot refused whenever the source could not be verified, which is the network
        partition - the one case the feature exists for. Only a source we can SEE and
        that is still running gets refused.

  #889  the auto-balance worker moves disks. The interactive route that does the same
        thing requires vm.config on that VM; the worker runs userless and moved anything,
        including guests somebody had deliberately fenced off with an ACL or pool grant.

MK
"""
import contextlib
import inspect

import pytest


# --- #888: group grants are not a tenant-scoped decision -----------------------------

@contextlib.contextmanager
def _as(api, session):
    from flask import request as _rq
    with api.app.test_request_context('/', base_url='http://localhost', json={}):
        _rq.session = session
        yield


def _authz_write(**kw):
    import pegaprox.api.users as users
    return users._authz_object_write('cluster_1', **kw)


@pytest.fixture
def delegate(api, seed):
    from tests.conftest import make_fake_manager
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.user('dana', role='user', tenant_id='tenant_a', permissions=['admin.users'])
    seed.user('root8', role='admin')
    api.set_manager('cluster_1', make_fake_manager('cluster_1'))
    return {'user': 'dana', 'role': 'user'}


def test_a_delegate_cannot_grant_a_pool_to_a_group(api, delegate):
    with _as(api, delegate):
        err = _authz_write(groups=['ldap-admins'], permissions=[])

    assert err is not None and err[1] == 403
    assert 'global admin' in err[0].get_json()['error']


def test_a_global_admin_still_can(api, delegate, seed):
    with _as(api, {'user': 'root8', 'role': 'admin'}):
        assert _authz_write(groups=['ldap-admins'], permissions=[]) is None


def test_a_user_subject_in_the_same_tenant_is_unaffected(api, delegate, seed):
    """The counterweight: user grants are what a tenant delegate is for."""
    seed.user('mate', role='user', tenant_id='tenant_a')
    with _as(api, delegate):
        assert _authz_write(subjects=['mate'], permissions=[]) is None


def test_both_pool_routes_pass_the_group_through():
    """A guard in the helper does nothing if the route never tells it there is a group."""
    import pegaprox.api.users as users

    for name in ('add_pool_permission_api', 'delete_pool_permission_api'):
        fn = getattr(users, name)
        while hasattr(fn, '__wrapped__'):
            fn = fn.__wrapped__
        assert "groups=[subject_id] if subject_type == 'group'" in inspect.getsource(fn), name


# --- #879: split brain, without blocking the emergency -------------------------------

class _Src:
    def __init__(self, connected=True, status='running', boom=False, host='10.0.0.1'):
        self.is_connected = connected
        self.host = host
        self.api_port = 8006
        self._status = status
        self._boom = boom

    def _api_get(self, url, params=None, **kw):
        if self._boom:
            raise OSError('unreachable')
        class R:
            status_code = 200
            def json(_s):
                return {'data': [{'vmid': 100, 'status': self._status}]}
        return R()


def _running(src):
    import pegaprox.background.site_recovery as sr
    return sr._source_vm_is_running(src, 100)


def test_a_source_we_can_see_running_is_reported():
    assert _running(_Src(status='running')) == (True, True)


def test_a_source_we_can_see_stopped_is_reported():
    assert _running(_Src(status='stopped')) == (False, True)


def test_an_unreachable_source_is_not_reported_as_running():
    """This is the partition, which is the case emergency failover is FOR. Reporting it
    as running would block the one scenario the feature exists to handle."""
    assert _running(_Src(connected=False)) == (False, False)


def test_an_api_error_is_not_reported_as_running():
    assert _running(_Src(boom=True)) == (False, False)


def test_a_guest_missing_from_the_source_collides_with_nothing():
    src = _Src(status='running')
    src._status = 'running'

    class _Empty(_Src):
        def _api_get(self, url, params=None, **kw):
            class R:
                status_code = 200
                def json(_s): return {'data': []}
            return R()

    assert _running(_Empty()) == (False, True)


def test_the_emergency_branch_refuses_only_a_verified_running_source():
    import pegaprox.background.site_recovery as sr

    body = inspect.getsource(sr.execute_failover)
    assert '_source_vm_is_running(src_mgr, vmid)' in body
    # refuses on _running, not on "could not check"
    assert 'if _running:' in body
    assert 'if not _checked:' in body, 'the unverifiable case must warn, not refuse'


# --- #889: the userless worker leaves fenced guests alone ----------------------------

def test_the_balance_worker_builds_a_restricted_set():
    import pegaprox.api.storage as st

    body = inspect.getsource(st.run_auto_storage_balance)
    assert 'restricted_vmids' in body
    assert 'get_vm_acls()' in body and 'get_pool_membership_cache' in body


def test_it_skips_those_guests():
    import pegaprox.api.storage as st

    body = inspect.getsource(st.run_auto_storage_balance)
    assert 'if vmid in restricted_vmids:' in body


def test_a_set_it_cannot_build_stops_the_cycle():
    """Failing to work out what is protected must not mean moving more, not less."""
    import pegaprox.api.storage as st

    body = inspect.getsource(st.run_auto_storage_balance)
    i = body.index('cannot determine protected VMs')
    assert 'continue' in body[i:i + 260]
