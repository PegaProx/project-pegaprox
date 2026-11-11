"""A directory login may only refresh rows the directory owns.

Three things in the LDAP provisioning path, and the third was not on anyone's list.

  * The adoption guard read `existing_source == 'local' and password_hash`. An OIDC or
    Entra row therefore fell straight through to the update branch: whoever controls the
    directory could take over an account belonging to a different identity provider just
    by creating a matching name in it. The rule is written down on the other side already
    - the comment above OIDC_AUTH_SOURCES says 'local' and 'ldap' rows must never be
    adopted by an OIDC login - and it holds mirrored.
  * `and password_hash` meant a local account WITHOUT a stored password was adopted. An
    account whose only credential is a security key has no password_hash, and neither
    does one created but never given a password.
  * The tenant was only ever assigned, never withdrawn: drop a user from the mapped group
    and they keep the tenant, and with it access to that tenant's clusters.

And underneath all of it: ldap_permissions, the field the August revocation fix relies on
to know what it granted last time, had no column. Every restart wiped it, so the
revocation quietly stopped working. ldap_tenant would have had the same fate.

Aikido ai_pentest 700488637 / 700486998, plus the persistence gap found while fixing them.
MK
"""
import pytest

import pegaprox.utils.ldap as ldapmod


def _seed(db, name, source, **extra):
    row = {'password_salt': '', 'password_hash': '', 'role': 'viewer',
           'auth_source': source, 'enabled': True}
    row.update(extra)
    db.save_user(name, row)
    return row


def _provision(name, **kw):
    payload = {'username': name, 'role': 'user'}
    payload.update(kw)
    return ldapmod.ldap_provision_user(payload)


# --- only rows this login owns ------------------------------------------------

@pytest.mark.parametrize('source', ['oidc', 'entra'])
def test_an_idp_account_is_not_adopted(db, source):
    _seed(db, 'victim', source)

    assert _provision('victim') is None
    assert db.get_user('victim')['auth_source'] == source


def test_a_local_account_with_a_password_is_not_adopted(db):
    _seed(db, 'victim', 'local', password_hash='realhash')

    assert _provision('victim') is None


def test_a_local_account_WITHOUT_a_password_is_not_adopted_either(db):
    """A security-key-only account has no password_hash. It used to be takeable."""
    _seed(db, 'keyonly', 'local')

    assert _provision('keyonly') is None
    assert db.get_user('keyonly')['auth_source'] == 'local'


def test_an_ldap_account_is_still_refreshed(db):
    """The invariant: this is what the function is for."""
    _seed(db, 'carol', 'ldap')

    assert _provision('carol', role='user') is not None
    assert db.get_user('carol')['role'] == 'user'


# --- the tenant is revocable, but only ours -----------------------------------

def test_a_tenant_the_directory_assigned_is_withdrawn_when_the_mapping_goes(db):
    _seed(db, 'carol', 'ldap', tenant_id='acme', ldap_tenant='acme')

    _provision('carol')          # no tenant in the result: mapping gone

    assert db.get_user('carol')['tenant_id'] != 'acme'


def test_a_tenant_an_admin_set_by_hand_is_left_alone(db):
    """LDAP did not put them there, so it is not LDAP's to take away."""
    _seed(db, 'dave', 'ldap', tenant_id='manual')

    _provision('dave')

    assert db.get_user('dave')['tenant_id'] == 'manual'


def test_a_mapped_tenant_is_still_applied(db):
    _seed(db, 'erin', 'ldap')

    _provision('erin', tenant='acme')

    u = db.get_user('erin')
    assert u['tenant_id'] == 'acme'
    assert u['ldap_tenant'] == 'acme'


def _reopen():
    import pegaprox.core.db as dbmod
    dbmod._db = None
    dbmod.PegaProxDB._instance = None
    return dbmod.get_db()


def test_a_tenant_assigned_at_the_first_sign_in_is_withdrawn_as_well(db):
    """The first sign-in creates the row. It set tenant_id from the mapping but not
    ldap_tenant, so that tenant never counted as the directory's and stayed for good."""
    from pegaprox.utils.rbac import DEFAULT_TENANT_ID
    assert db.get_user('newbie') is None

    _provision('newbie', tenant='acme')
    assert _reopen().get_user('newbie')['ldap_tenant'] == 'acme'

    _provision('newbie', tenant=None)        # the mapping names no tenant any more

    u = _reopen().get_user('newbie')
    assert u['tenant_id'] == DEFAULT_TENANT_ID
    assert u['ldap_tenant'] == ''


# --- the bookkeeping has to survive a restart ---------------------------------

def test_the_directorys_own_grants_are_persisted(db):
    """Without a column these live only in memory: every restart wipes them, and the
    revocation logic that reads them then has nothing to take back."""
    db.save_user('x', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                       'ldap_permissions': ['vm.view', 'vm.start'], 'ldap_tenant': 'acme'})

    u = db.get_user('x')

    assert u['ldap_permissions'] == ['vm.view', 'vm.start']
    assert u['ldap_tenant'] == 'acme'


def test_they_survive_a_reopen(db, tmp_path):
    """The real shape of the bug - not a round trip through one connection."""
    import pegaprox.core.db as dbmod
    db.save_user('y', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                       'ldap_permissions': ['vm.view'], 'ldap_tenant': 'acme'})
    dbmod._db = None
    dbmod.PegaProxDB._instance = None

    reopened = dbmod.get_db()

    assert reopened.get_user('y')['ldap_permissions'] == ['vm.view']


TENANT_ADMIN = {'acme': {'role': 'admin', 'extra': []}}


def test_the_directorys_tenant_roles_survive_a_reopen(db):
    db.save_user('z', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                       'auth_source': 'ldap', 'ldap_tenant_permissions': TENANT_ADMIN})

    assert _reopen().get_user('z')['ldap_tenant_permissions'] == TENANT_ADMIN
    assert _reopen().get_all_users()['z']['ldap_tenant_permissions'] == TENANT_ADMIN


def test_an_older_database_gets_the_tenant_roles_column(db):
    cols = [r[1] for r in db.conn.execute('PRAGMA table_info(users)').fetchall()]
    if 'ldap_tenant_permissions' in cols:
        db.conn.execute('ALTER TABLE users DROP COLUMN ldap_tenant_permissions')
        db.conn.commit()

    reopened = _reopen()

    cols = [r[1] for r in reopened.conn.execute('PRAGMA table_info(users)').fetchall()]
    assert 'ldap_tenant_permissions' in cols


def test_a_tenant_role_the_directory_withdrew_goes_with_the_next_sign_in(db):
    """Still mapped to the tenant, only the group that gave the tenant role is gone.
    The sign-in has to know which tenant roles were its own, and that has to come from
    the database: a restart sits between any two sign-ins."""
    from pegaprox.utils.rbac import get_user_permissions, get_role_permissions_for_user
    _seed(db, 'omar', 'ldap', tenant_permissions={'beta': {'role': 'user'}})   # by hand

    _provision('omar', role='viewer', tenant='acme', tenant_permissions=TENANT_ADMIN)
    assert _reopen().get_user('omar')['tenant_permissions']['acme'] == TENANT_ADMIN['acme']

    _provision('omar', role='viewer', tenant='acme', tenant_permissions={})

    u = _reopen().get_user('omar')
    assert u['tenant_id'] == 'acme'
    assert u['tenant_permissions'] == {'beta': {'role': 'user'}}
    assert u['ldap_tenant_permissions'] == {}
    assert set(get_user_permissions(u)) == set(get_role_permissions_for_user({'role': 'viewer'}))
