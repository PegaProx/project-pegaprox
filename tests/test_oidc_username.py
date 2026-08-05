# Username derivation from OIDC claims — oidc_derive_username().
#
# The username is the users-table primary key, so how it is derived from the
# IdP's claims decides which account an OIDC login lands on. This used to
# truncate at '@', which collapsed bob@corp.com and bob@partner.com onto a
# single 'bob' account — the second one to log in inherited the first one's
# role and tenant. The full name is now kept, with a back-compat lookup so
# installs that already provisioned the truncated form aren't orphaned.
#
# Harness note: the `db` fixture is required for every case, not just the
# legacy one — oidc_derive_username() calls load_users() whenever the derived
# name contains '@', and without the fixture that would hit the real CONFIG_DIR.

import pytest

from tests.conftest import _seed_user

from pegaprox.utils.auth import load_users
from pegaprox.utils.oidc import oidc_derive_username


def _seed_oidc_user(db, username, sub, auth_source='oidc'):
    """A pre-change row: truncated key, plus the IdP binding a real login left."""
    _seed_user(db, username)
    u = db.get_user(username)
    u['auth_source'] = auth_source
    u['oidc_sub'] = sub
    db.save_user(username, u)


def test_preferred_username_keeps_the_domain(db):
    assert oidc_derive_username(
        {'preferred_username': 'bob@example.com', 'sub': 's1'}
    ) == 'bob@example.com'


def test_two_domains_stay_distinct(db):
    """The actual bug: these must not collapse onto one account."""
    corp = oidc_derive_username({'preferred_username': 'bob@corp.com'})
    partner = oidc_derive_username({'preferred_username': 'bob@partner.com'})
    assert corp != partner


def test_plus_addressing_is_preserved(db):
    """'+' is in sanitize_username()'s allowlist; stripping it merges identities."""
    assert oidc_derive_username(
        {'preferred_username': 'a+b@example.com', 'sub': 's4'}
    ) == 'a+b@example.com'


def test_plus_identity_does_not_collide_with_the_bare_one(db):
    plus = oidc_derive_username({'preferred_username': 'a+b@example.com'})
    bare = oidc_derive_username({'preferred_username': 'ab@example.com'})
    assert plus != bare


def test_preloaded_users_are_used_instead_of_a_second_read(db):
    """Callers in the login path pass the table they already loaded."""
    _seed_oidc_user(db, 'bob', sub='sub-bob')
    users = load_users()
    assert oidc_derive_username(
        {'preferred_username': 'bob@example.com', 'sub': 'sub-bob'}, users
    ) == 'bob'


def test_plain_preferred_username_is_unchanged(db):
    assert oidc_derive_username(
        {'preferred_username': 'John.Doe', 'sub': 's2'}
    ) == 'john.doe'


def test_falls_back_to_email(db):
    assert oidc_derive_username(
        {'email': 'carol@example.com', 'sub': 's3'}
    ) == 'carol@example.com'


def test_falls_back_to_sub_when_claims_are_empty(db):
    assert oidc_derive_username({'sub': 'abcdef0123456789'}) == 'oidc_abcdef012345'


def test_existing_truncated_account_keeps_its_key(db):
    """Pre-change installs stored 'bob'; that login must not fork a new account."""
    _seed_oidc_user(db, 'bob', sub='sub-bob')
    assert oidc_derive_username(
        {'preferred_username': 'bob@example.com', 'sub': 'sub-bob'}
    ) == 'bob'


def test_entra_account_also_keeps_its_key(db):
    _seed_oidc_user(db, 'bob', sub='sub-bob', auth_source='entra')
    assert oidc_derive_username(
        {'preferred_username': 'bob@example.com', 'sub': 'sub-bob'}
    ) == 'bob'


def test_unrelated_existing_account_does_not_capture_the_login(db):
    _seed_user(db, 'alice')
    assert oidc_derive_username(
        {'preferred_username': 'bob@example.com'}
    ) == 'bob@example.com'


# ---------------------------------------------------------------------------
# The back-compat lookup must not become a second route to the original bug.
# Adopting a legacy row on a bare local-part match would let any subject whose
# name happens to be 'bob@<anything>' take over the 'bob' account, which is the
# collision this whole change exists to close.

def test_different_subject_does_not_inherit_the_legacy_account(db):
    """bob@corp.com owns legacy 'bob'; bob@partner.com must not land on it."""
    _seed_oidc_user(db, 'bob', sub='sub-corp-bob')
    assert oidc_derive_username(
        {'preferred_username': 'bob@partner.com', 'sub': 'sub-partner-bob'}
    ) == 'bob@partner.com'


def test_login_without_a_sub_claim_does_not_adopt_the_legacy_account(db):
    _seed_oidc_user(db, 'bob', sub='sub-bob')
    assert oidc_derive_username(
        {'preferred_username': 'bob@example.com'}
    ) == 'bob@example.com'


def test_local_account_is_not_adopted(db):
    """A local 'bob' stays local; oidc_provision_user rejects the overwrite."""
    _seed_user(db, 'bob')  # no auth_source -> 'local'
    assert oidc_derive_username(
        {'preferred_username': 'bob@example.com', 'sub': 'sub-bob'}
    ) == 'bob@example.com'


def test_ldap_account_is_not_adopted(db):
    _seed_oidc_user(db, 'bob', sub='sub-bob', auth_source='ldap')
    assert oidc_derive_username(
        {'preferred_username': 'bob@example.com', 'sub': 'sub-bob'}
    ) == 'bob@example.com'
