"""Two lifecycle invariants the SPEC-010 junction tables have to hold.

Both came out of the bot review on the tenant-roles PR and both are the same
family we keep tripping over: a grant that outlives the thing it was attached
to, and a read failure that resolves in the destructive direction.

MK Sep 2026
"""
import pegaprox.core.db as dbmod
import pegaprox.utils.rbac as rbac


def _memberships(db, username):
    cur = db.conn.cursor()
    cur.execute('SELECT tenant_id FROM user_tenants WHERE username = ?', (username,))
    return sorted(r[0] for r in cur.fetchall())


def test_a_recreated_username_does_not_inherit_the_old_tenants(db, seed):
    """The membership must die with the account, not with the name.

    Measured as the thing that actually hurts: create, grant, delete, create
    again with the SAME username, and ask what the new account is a member of.
    """
    seed.user('carol', role='viewer')
    cur = db.conn.cursor()
    cur.execute("INSERT OR REPLACE INTO user_tenants (username, tenant_id, granted_at, granted_by) "
                "VALUES ('carol', 'tenant_finance', '2026-09-28', 'test')")
    db.conn.commit()
    assert _memberships(db, 'carol') == ['tenant_finance']

    db.delete_user('carol')
    seed.user('carol', role='viewer')

    assert _memberships(db, 'carol') == [], \
        'the new carol inherited the deleted carol\'s tenant membership'


def test_an_unreadable_grant_table_does_not_let_the_role_rewrite_through(db, monkeypatch):
    """save_custom_roles() rewrites custom_roles with DELETE+reinsert. The only
    thing protecting a still-granted role is a read of user_roles. If that read
    fails we cannot know whether a grant exists, so the rewrite must not run.

    The property measured here is the TABLE CONTENT afterwards, not the return
    value and not the presence of the guard.
    """
    rbac.save_custom_roles({'global': {'auditor': {'permissions': ['vm.view']}}, 'tenants': {}})
    before = rbac.load_custom_roles()
    assert 'auditor' in before.get('global', {}), 'precondition: the role is stored'

    class _Boom(Exception):
        pass

    real_query = db.query

    def _query(sql, *a, **kw):
        if 'user_roles' in sql:
            raise _Boom('user_roles unreadable')
        return real_query(sql, *a, **kw)

    monkeypatch.setattr(db, 'query', _query)
    monkeypatch.setattr(dbmod, 'get_db', lambda: db)
    monkeypatch.setattr(rbac, 'get_db', lambda: db)

    rbac.save_custom_roles({'global': {}, 'tenants': {}})

    rbac._custom_roles_cache = None
    after = rbac.load_custom_roles()
    assert 'auditor' in after.get('global', {}), \
        'the rewrite deleted the role while the grant table could not be read'
