"""Three OIDC findings, fixed together Sep 2026.

1. Group removal in the IdP revoked nothing. `permissions` was unioned with what was
   already stored, `tenant_permissions` was dict-updated, and `role` fell back to the
   stored value - all three behind `if role_mapping.get(...)`, so an empty mapping never
   even entered them. A leaver kept every permission until an admin noticed by hand.

2. An LDAP account could be taken over by an OIDC login of the same name. The guard
   checked `auth_source == 'local'` only, while the comment on OIDC_AUTH_SOURCES says
   local AND ldap must never be adopted.

3. Discovery validated the authority URL carefully and then let requests follow a 302
   anywhere, including to link-local metadata addresses.

The interesting half of (1) is what it must NOT do: the group fetch used to answer []
for "no groups", "Graph call failed" and "generic provider, look in the token" alike.
Revoking on that would strip every Entra user whenever Graph hiccuped, and Entra pages
at 100 groups so a mid-pagination failure yields a PARTIAL list - worse to decide on
than none. Hence the completeness signal, and hence the tests below covering the
not-authoritative paths at least as carefully as the revoking one.
NS
"""
import pytest

from pegaprox.utils import oidc as O
from pegaprox.models.permissions import ROLE_ADMIN, ROLE_VIEWER


# ── the completeness signal ─────────────────────────────────────────────────

def test_a_generic_provider_is_never_authoritative_by_itself(monkeypatch):
    """Groups come from the ID token there, so the fetch has nothing to say."""
    groups, complete = O.oidc_get_user_groups_ex({'provider': 'keycloak'}, 'tok')
    assert groups == [] and complete is False


def test_a_clean_entra_fetch_is_authoritative(monkeypatch):
    pages = [{'value': [{'@odata.type': '#microsoft.graph.group', 'id': 'g1',
                         'displayName': 'Admins'}]}]

    class _R:
        status_code = 200
        def json(self): return pages[0]

    monkeypatch.setattr(O, 'get_oidc_endpoints', lambda c: {'graph_groups': 'https://g/x'})
    monkeypatch.setattr(O.requests, 'get', lambda *a, **k: _R())
    groups, complete = O.oidc_get_user_groups_ex({'provider': 'entra'}, 'tok')
    assert complete is True
    assert groups and groups[0]['id'] == 'g1'


def test_a_failed_entra_fetch_is_not_authoritative(monkeypatch):
    class _R:
        status_code = 503
        def json(self): return {}

    monkeypatch.setattr(O, 'get_oidc_endpoints', lambda c: {'graph_groups': 'https://g/x'})
    monkeypatch.setattr(O.requests, 'get', lambda *a, **k: _R())
    groups, complete = O.oidc_get_user_groups_ex({'provider': 'entra'}, 'tok')
    assert complete is False, "a 503 must not look like 'this user has no groups'"


def test_a_partial_page_walk_is_not_authoritative(monkeypatch):
    """Entra pages at 100. The old loop broke out on a non-200 and kept what it had."""
    calls = {'n': 0}

    class _R:
        def __init__(self, ok, nxt=None): self.status_code = 200 if ok else 500; self._n = nxt
        def json(self): return {'value': [{'@odata.type': '#microsoft.graph.group',
                                           'id': 'g1', 'displayName': 'A'}],
                                '@odata.nextLink': self._n}

    def _get(*a, **k):
        calls['n'] += 1
        return _R(True, 'https://g/page2') if calls['n'] == 1 else _R(False)

    monkeypatch.setattr(O, 'get_oidc_endpoints', lambda c: {'graph_groups': 'https://g/x'})
    monkeypatch.setattr(O.requests, 'get', _get)
    groups, complete = O.oidc_get_user_groups_ex({'provider': 'entra'}, 'tok')
    assert groups, 'the first page did arrive'
    assert complete is False, "half a group list must not be treated as the whole set"


def test_an_exception_is_not_authoritative(monkeypatch):
    monkeypatch.setattr(O, 'get_oidc_endpoints', lambda c: {'graph_groups': 'https://g/x'})
    def _boom(*a, **k): raise RuntimeError('network')
    monkeypatch.setattr(O.requests, 'get', _boom)
    assert O.oidc_get_user_groups_ex({'provider': 'entra'}, 'tok')[1] is False


# ── what the mapping declares ───────────────────────────────────────────────

def test_the_mapping_marks_a_complete_fetch_authoritative():
    m = O.oidc_map_groups_to_role({}, [], None, groups_complete=True)
    assert m['_authoritative'] is True


def test_a_groups_claim_in_the_id_token_counts_even_when_empty():
    """The token is signature-checked, so an explicit empty groups claim means the user
    really is in no groups - that has to be able to revoke."""
    m = O.oidc_map_groups_to_role({}, [], {'groups': []}, groups_complete=False)
    assert m['_authoritative'] is True


def test_no_groups_claim_at_all_is_not_authoritative():
    """A provider that never sends groups is indistinguishable from one whose user lost
    them all."""
    m = O.oidc_map_groups_to_role({}, [], {'sub': 'x'}, groups_complete=False)
    assert m['_authoritative'] is False


# ── provisioning: revoke when allowed, never when not ───────────────────────

def _provision(monkeypatch, existing, mapping):
    """Run oidc_provision_user against a canned user store; return the stored row."""
    store = {'bob': dict(existing)} if existing else {}
    # *a/**k rather than a bare lambda: both are imported inside the functions under
    # test, and a signature change there should not make this stub the thing that fails.
    monkeypatch.setattr('pegaprox.utils.auth.load_users', lambda *a, **k: store)
    monkeypatch.setattr('pegaprox.utils.auth.save_users', lambda u, *a, **k: store.update(u))
    # preferred_username without an '@' so the derived key is exactly 'bob' and we hit
    # the update path. With 'bob@corp.com' the derived name keeps the domain and a
    # separate row is created instead - which is itself correct, and is why the takeover
    # case has to be set up deliberately rather than by accident.
    out = O.oidc_provision_user({'sub': 's-1', 'email': 'bob@corp.com',
                                 'preferred_username': 'bob'}, mapping)
    return out, store


_HAD = {'auth_source': 'oidc', 'oidc_sub': 's-1', 'role': ROLE_ADMIN,
        'permissions': ['vm.delete', 'node.maintenance'],
        'tenant_permissions': {'acme': ['vm.view']}}


def test_losing_every_group_takes_the_permissions_with_it(monkeypatch):
    """The reported bug: this used to leave vm.delete and node.maintenance in place."""
    mapping = {'role': ROLE_VIEWER, 'tenant': '', 'permissions': [],
               'tenant_permissions': {}, '_authoritative': True}
    user, _ = _provision(monkeypatch, _HAD, mapping)
    assert user is not None
    assert user['permissions'] == [], f"stale grants survived: {user['permissions']}"
    assert user['tenant_permissions'] == {}
    assert user['role'] == ROLE_VIEWER, 'an IdP demotion has to arrive here too'


def test_a_reduced_group_set_removes_only_what_was_removed(monkeypatch):
    mapping = {'role': ROLE_VIEWER, 'tenant': '', 'permissions': ['vm.delete'],
               'tenant_permissions': {}, '_authoritative': True}
    user, _ = _provision(monkeypatch, _HAD, mapping)
    assert user['permissions'] == ['vm.delete']


def test_a_failed_group_fetch_revokes_nothing(monkeypatch):
    """The trade this fix must not make: one Graph hiccup stripping everybody."""
    mapping = {'role': ROLE_VIEWER, 'tenant': '', 'permissions': [],
               'tenant_permissions': {}, '_authoritative': False}
    user, _ = _provision(monkeypatch, _HAD, mapping)
    assert set(user['permissions']) == {'vm.delete', 'node.maintenance'}
    assert user['tenant_permissions'] == {'acme': ['vm.view']}
    assert user['role'] == ROLE_ADMIN, 'must not demote on an unreliable answer either'


def test_a_non_authoritative_mapping_can_still_grant(monkeypatch):
    """A fetch problem should not break the grant path that does work."""
    mapping = {'role': ROLE_ADMIN, 'tenant': '', 'permissions': ['storage.manage'],
               'tenant_permissions': {}, '_authoritative': False}
    user, _ = _provision(monkeypatch, _HAD, mapping)
    assert 'storage.manage' in user['permissions']
    assert 'vm.delete' in user['permissions'], 'grant-only means keep the old ones'


def test_tenant_is_not_cleared_when_unmapped(monkeypatch):
    """Deliberate: admins set tenant_id by hand too, and dropping someone out of their
    tenant is a different decision from taking a permission away."""
    had = dict(_HAD, tenant_id='acme')
    mapping = {'role': ROLE_VIEWER, 'tenant': '', 'permissions': [],
               'tenant_permissions': {}, '_authoritative': True}
    user, _ = _provision(monkeypatch, had, mapping)
    assert user['tenant_id'] == 'acme'


# ── account takeover ────────────────────────────────────────────────────────

@pytest.mark.parametrize('source', ['local', 'ldap'])
def test_an_account_this_login_does_not_own_is_never_adopted(monkeypatch, source):
    """'local' was already refused; 'ldap' fell through to the update path and had its
    role and auth_source rewritten."""
    had = {'auth_source': source, 'role': ROLE_ADMIN, 'permissions': ['vm.delete']}
    mapping = {'role': ROLE_VIEWER, 'tenant': '', 'permissions': [],
               'tenant_permissions': {}, '_authoritative': True}
    user, store = _provision(monkeypatch, had, mapping)
    assert user is None, f"an OIDC login took over a {source} account"
    assert store['bob']['auth_source'] == source, 'and it was rewritten on disk'
    assert store['bob']['role'] == ROLE_ADMIN


def test_the_guard_uses_the_shared_constant():
    """So a future auth_source ('saml', ...) is refused by default rather than adopted."""
    import inspect
    src = inspect.getsource(O.oidc_provision_user)
    assert 'not in OIDC_AUTH_SOURCES' in src
    assert "== 'local'" not in src


# ── discovery must not follow redirects ─────────────────────────────────────

def test_discovery_refuses_a_redirect(monkeypatch, caplog):
    """The authority URL is validated hard before the request; requests would then have
    followed a 302 to anywhere - link-local metadata included - with none of that
    validation applied to the second hop."""
    seen = {}

    class _Redirect:
        status_code = 302
        is_redirect = True
        headers = {'Location': 'http://169.254.169.254/latest/meta-data/'}
        def json(self): return {}

    def _get(url, **kw):
        seen.update(kw)
        return _Redirect()

    monkeypatch.setattr(O.requests, 'get', _get)
    monkeypatch.setattr(O, 'load_server_settings', lambda: {}, raising=False)
    # The SSRF guard rejects the example host before any request is made (it cannot be
    # resolved from a test box), which is correct and has its own tests. Step past it so
    # this one can reach the redirect behaviour it is about.
    # MK Sep 2026 - the discovery path pins the vetted address now instead of only
    # checking it, so this is the seam to step past, not sanitize_outbound_url. Same
    # intent as before: the guard's own behaviour has its own tests, this one is about
    # what happens to a 302.
    monkeypatch.setattr(O, 'resolve_and_pin_url', lambda u, **k: u)
    O._oidc_discovery_cache.clear()
    ep = O.get_oidc_endpoints({'provider': 'keycloak',
                               'authority': 'https://idp.example.com/realms/x'})

    assert seen.get('allow_redirects') is False, \
        'the discovery GET still follows redirects'
    # falls back to issuer-relative endpoints rather than blowing up
    assert ep['authorization'].startswith('https://idp.example.com/realms/x')


def test_no_outgoing_oidc_call_follows_redirects_silently():
    """Guard for the other four calls in this module - if one of them is ever pointed at
    an attacker-influenced URL, the same hole opens again."""
    import inspect, re
    src = inspect.getsource(O)
    disco = [l for l in src.splitlines() if 'discovery_url' in l and 'requests.get' in l]
    assert disco, 'the discovery call moved - re-point this test'
    assert any('allow_redirects=False' in l for l in
               src[src.index('discovery_url, timeout'):][:400].splitlines())


def test_the_redirect_target_is_sanitised_before_it_is_logged(monkeypatch, caplog):
    """CWE-117. The Location header is whatever answered the request, so it can carry
    newlines and forge log lines. Same treatment the login path gives usernames."""
    class _Redirect:
        status_code = 302
        is_redirect = True
        headers = {'Location': 'http://evil/\n2026-01-01 ERROR [OIDC] admin login ok'}
        def json(self): return {}

    monkeypatch.setattr(O.requests, 'get', lambda url, **kw: _Redirect())
    # MK Sep 2026 - the discovery path pins the vetted address now instead of only
    # checking it, so this is the seam to step past, not sanitize_outbound_url. Same
    # intent as before: the guard's own behaviour has its own tests, this one is about
    # what happens to a 302.
    monkeypatch.setattr(O, 'resolve_and_pin_url', lambda u, **k: u)
    monkeypatch.setattr(O, 'load_server_settings', lambda: {}, raising=False)
    O._oidc_discovery_cache.clear()
    with caplog.at_level('WARNING'):
        O.get_oidc_endpoints({'provider': 'keycloak',
                              'authority': 'https://idp.example.com/realms/x'})
    redirect_lines = [r.getMessage() for r in caplog.records if 'redirected to' in r.getMessage()]
    assert redirect_lines, 'the refusal is no longer logged at all'
    assert '\n2026-01-01 ERROR' not in redirect_lines[0], \
        'a forged log line came through the Location header'


# ── the near-miss: an empty Graph endpoint must not read as "no groups" ─────

def test_a_missing_graph_endpoint_is_not_authoritative(monkeypatch):
    """get_oidc_endpoints sets graph_groups to '' on five different discovery/config
    fallback paths. With an empty URL the page loop never runs, so an optimistic
    `complete = True` would have returned ([], True) - authoritative, zero groups - and
    revoked every Entra user's permissions whenever discovery failed. Caught by the daily
    scan on the initialisation, not by the tests above, because those all stub
    get_oidc_endpoints with a working URL."""
    monkeypatch.setattr(O, 'get_oidc_endpoints', lambda c: {'graph_groups': ''})
    called = {'n': 0}
    monkeypatch.setattr(O.requests, 'get',
                        lambda *a, **k: called.update(n=called['n'] + 1))
    groups, complete = O.oidc_get_user_groups_ex({'provider': 'entra'}, 'tok')
    assert groups == []
    assert complete is False, 'an unresolved Graph endpoint must never permit revocation'
    assert called['n'] == 0, 'and nothing should have been fetched'


@pytest.mark.parametrize('endpoints', [
    {},                       # key absent entirely
    {'graph_groups': None},   # present but null
    {'graph_groups': ''},     # present but empty
])
def test_every_shape_of_missing_endpoint_fails_closed(monkeypatch, endpoints):
    monkeypatch.setattr(O, 'get_oidc_endpoints', lambda c: endpoints)
    assert O.oidc_get_user_groups_ex({'provider': 'entra'}, 'tok')[1] is False


def test_only_a_completed_walk_is_authoritative():
    """Pins the invariant rather than one path: the flag is set in exactly one place,
    the while/else that runs when the loop ended on its own."""
    import inspect
    src = inspect.getsource(O.oidc_get_user_groups_ex)
    assert src.count('complete = True') == 1, \
        'more than one way to become authoritative - each is a chance to be wrong'
    assert 'complete = False' in src.split('try:')[0], \
        'the pessimistic default must be set before the fetch, not after'


def test_a_truncated_groups_claim_cannot_revoke():
    """Entra emits _claim_names/_claim_sources instead of the full list once a user is in
    too many groups. The claim is present but partial - authoritative on it would revoke
    against half the memberships. Flagged by the daily scan on the elif that trusted any
    groups claim."""
    claims = {'groups': ['g1', 'g2'],
              '_claim_names': {'groups': 'src1'},
              '_claim_sources': {'src1': {'endpoint': 'https://graph/...'}}}
    m = O.oidc_map_groups_to_role({}, [], claims, groups_complete=False)
    assert m['_authoritative'] is False


def test_an_untruncated_groups_claim_still_counts():
    m = O.oidc_map_groups_to_role({}, [], {'groups': ['g1']}, groups_complete=False)
    assert m['_authoritative'] is True


def test_a_complete_graph_fetch_beats_an_overage_marker():
    """If Graph answered in full, the token's truncation is irrelevant."""
    claims = {'groups': ['g1'], '_claim_names': {'groups': 'src1'}}
    m = O.oidc_map_groups_to_role({}, [], claims, groups_complete=True)
    assert m['_authoritative'] is True
