"""Pool permissions granted to an LDAP group never matched.

An LDAP/AD login stores group memberships as full DNs — utils/ldap.py puts
`member_of` straight into the user's `groups`, and those look like
"CN=PVE-Admins,OU=Groups,DC=corp,DC=local". The pool-permission dialog labels its
field "Group Name" (and "Gruppenname"; it appears in datacenter.js,
settings_modal.js and dashboard.js) so the operator types `PVE-Admins`. The
lookup compared the whole string, the two never met, and the pool simply stayed
empty. Nothing raised anywhere, which is the reason this went unnoticed for so
long — a grant that silently does nothing looks exactly like a grant that has not
been made yet.

Both lookups had it: get_user_pool_permissions decides what the user may do, and
get_user_pool_clusters decides whether the cluster is visible at all, so missing
the second would have left the user without even the cluster the grant was on.

The role/tenant mapping side of LDAP is deliberately untouched: its field is
called `group_dn` and it compares whole strings, which matches what it asks for.
#940. MK
"""
import pytest

DN = 'CN=PVE-Admins,OU=Groups,DC=corp,DC=local'
CLUSTER = 'cluster_1'


def _group_grant_spellings(value):
    """Imported at call time on purpose. A module-level import of a helper that does
    not exist yet makes THIS FILE unimportable against the unfixed tree, and an
    ImportError is not a counter-proof — it would hide whether the behavioural tests
    below actually detect the bug. This way they run and fail on the property."""
    from pegaprox.core.db import _group_grant_spellings as _f
    return _f(value)


# ------------------------------------------------------------- the spellings

def test_a_dn_offers_its_bare_group_name_too():
    assert _group_grant_spellings(DN) == [DN, 'PVE-Admins']


def test_a_bare_name_stays_a_bare_name():
    assert _group_grant_spellings('PVE-Admins') == ['PVE-Admins']


def test_an_escaped_comma_does_not_split_the_rdn():
    """RFC 4514 lets a name contain a comma as \\, — splitting naively would hand
    back half a group name and match nothing."""
    out = _group_grant_spellings(r'CN=Acme\, Inc Admins,OU=G,DC=x')
    assert out[1] == 'Acme, Inc Admins'


def test_nothing_in_nothing_out():
    assert _group_grant_spellings('') == []
    assert _group_grant_spellings(None) == []


# ------------------------------------------------------- what the user gets

def test_a_grant_typed_as_a_group_name_matches_a_dn_membership(db, seed):
    """The reported case, end to end through the lookup the gate uses."""
    seed.pool(CLUSTER, 'pool_a', 'PVE-Admins', ['pool.view', 'vm.start'],
              subject_type='group')

    perms = db.get_user_pool_permissions(CLUSTER, 'someone', [DN])

    assert 'pool_a' in perms, 'the grant the operator made still does nothing'
    assert set(perms['pool_a']) == {'pool.view', 'vm.start'}


def test_the_cluster_itself_becomes_visible(db, seed):
    """get_user_pool_clusters is the other half — it decides whether the cluster is
    listed at all, so a fix to only the permission lookup would leave the user
    staring at nothing."""
    seed.pool(CLUSTER, 'pool_a', 'PVE-Admins', ['pool.view'], subject_type='group')

    assert CLUSTER in db.get_user_pool_clusters('someone', [DN])


def test_a_grant_typed_as_a_full_dn_still_works(db, seed):
    """The regression guard: installations that worked around this by entering the
    DN must not break."""
    seed.pool(CLUSTER, 'pool_a', DN, ['pool.view'], subject_type='group')

    perms = db.get_user_pool_permissions(CLUSTER, 'someone', [DN])
    assert 'pool_a' in perms
    assert CLUSTER in db.get_user_pool_clusters('someone', [DN])


def test_a_different_group_does_not_match(db, seed):
    """The mirror that matters for a widening change: the bare-name fallback must
    not start matching groups the user is not in."""
    seed.pool(CLUSTER, 'pool_a', 'PVE-Admins', ['pool.view'], subject_type='group')

    perms = db.get_user_pool_permissions(
        CLUSTER, 'someone', ['CN=Helpdesk,OU=Groups,DC=corp,DC=local'])

    assert perms == {}
    assert db.get_user_pool_clusters('someone', ['CN=Helpdesk,OU=G,DC=corp']) == []


def test_a_dn_grant_is_not_matched_by_a_bare_name_membership(db, seed):
    """Asymmetric on purpose. An operator who entered the full DN asked for that
    exact group; a login that reports a bare name must not satisfy it."""
    seed.pool(CLUSTER, 'pool_a', DN, ['pool.view'], subject_type='group')

    assert db.get_user_pool_permissions(CLUSTER, 'someone', ['PVE-Admins']) == {}


def test_case_still_does_not_matter(db, seed):
    """AD is case-insensitive and the existing behaviour (#555) relied on that."""
    seed.pool(CLUSTER, 'pool_a', 'pve-admins', ['pool.view'], subject_type='group')

    assert 'pool_a' in db.get_user_pool_permissions(CLUSTER, 'someone', [DN])


def test_user_grants_are_untouched(db, seed):
    """Usernames stay exact — only group subjects gained the second spelling."""
    seed.pool(CLUSTER, 'pool_a', 'alice', ['pool.view'], subject_type='user')

    assert 'pool_a' in db.get_user_pool_permissions(CLUSTER, 'alice', [])
    assert db.get_user_pool_permissions(CLUSTER, 'ALICE', []) == {}


# ------------------------------------------- an empty grant grants nothing

def test_an_empty_grant_does_not_buy_cluster_reach(db, seed):
    """#700487672 — a pool_permissions row with no permissions in it grants nothing
    inside the pool, but get_user_pool_clusters returned its cluster regardless, and
    check_cluster_access's #555 fallback turns "holds a pool grant here" into reach
    over the whole cluster. So emptying a grant left the door open while the UI
    showed no permissions at all. rbac.user_has_any_pool_access already ignored
    empty grants, which is what makes this a bug rather than a decision."""
    seed.pool(CLUSTER, 'pool_a', 'alice', [], subject_type='user')

    assert db.get_user_pool_clusters('alice', []) == []
    assert db.get_user_pool_permissions(CLUSTER, 'alice', []) in ({}, {'pool_a': []})


def test_a_real_grant_still_buys_cluster_reach(db, seed):
    """The mirror — the #555 fallback exists for a reason."""
    seed.pool(CLUSTER, 'pool_a', 'alice', ['pool.view'], subject_type='user')

    assert CLUSTER in db.get_user_pool_clusters('alice', [])


def test_an_empty_group_grant_does_not_buy_reach_either(db, seed):
    seed.pool(CLUSTER, 'pool_a', 'PVE-Admins', [], subject_type='group')

    assert db.get_user_pool_clusters('someone', [DN]) == []
