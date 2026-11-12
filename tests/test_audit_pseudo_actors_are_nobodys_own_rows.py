"""The names the background jobs write audit entries under are nobody's own rows.

A caller confined to some clusters reads the audit rows of those clusters and their own,
and their own are matched by name. The scheduler, the HA and storage loops, the auto
installer and the session fallbacks of the routes write under 'system', 'scheduler',
'installer' and 'unknown'. An account of one of those names, which a tenant admin holding
admin.users and admin.audit could create, read every such row of every tenant: in the
search, its facets, /api/audit and its CSV.

Those names have no own rows in the audit scope now. An account that holds one reads the
rows of its clusters like anyone else; an admin and an ordinary confined auditor read what
they read before.

MK Nov 2026
"""
import time
import types

import pytest

from pegaprox.utils.audit import AUDIT_PSEUDO_ACTORS, is_audit_pseudo_actor, log_audit

OWN, FOREIGN = 'cluster_a', 'cluster_b'
FOREIGN_ROWS = ('Scheduled stop executed on VM 200 in Beta', 'HA recovery moved VM 201',
                'Installer wrote node pve9', 'Login refused for an unknown name')


def _mgr(api, cid, name):
    m = api.make_fake_manager(cluster_id=cid, get_tasks=[])
    m.config = types.SimpleNamespace(name=name)
    m.is_connected = True
    m._vm_resources_cache = (time.time(), [])
    m._node_status_cache = (time.monotonic(), {})
    return api.set_manager(cid, m)


@pytest.fixture
def estate(api, seed):
    """Tenant A owns cluster_a "Alpha", tenant B owns cluster_b "Beta". The pseudo actors
    wrote rows on Beta and rows that belong to no cluster; one row on Alpha."""
    seed.tenant('tenant_a', clusters=[OWN])
    seed.tenant('tenant_b', clusters=[FOREIGN])
    _mgr(api, OWN, 'Alpha')
    _mgr(api, FOREIGN, 'Beta')
    log_audit('alice', 'vm.start', 'Started VM 100', cluster='Alpha')
    log_audit('scheduler', 'scheduled_task.executed', FOREIGN_ROWS[0], cluster='Beta')
    log_audit('system', 'ha.recovery', FOREIGN_ROWS[1], cluster='Beta')
    log_audit('installer', 'auto_install.node', FOREIGN_ROWS[2])
    log_audit('unknown', 'auth.login_failed', FOREIGN_ROWS[3])
    log_audit('scheduler', 'scheduled_task.executed', 'Scheduled snapshot of VM 100 in Alpha',
              cluster='Alpha')
    return api


def _text(rows):
    return ' | '.join(str(e.get('details') or '') for e in rows)


def _reads(client):
    """What each audit reader hands the caller, as text and the facet users."""
    s = client.get('/api/audit/search?limit=500')
    f = client.get('/api/audit/facets')
    a = client.get('/api/audit?limit=500')
    c = client.get('/api/audit?format=csv&limit=500')
    for r in (s, f, a, c):
        assert r.status_code == 200, (r.status_code, r.get_data(as_text=True))
    return {'search': _text(s.get_json()['entries']), 'audit': _text(a.get_json()),
            'csv': c.get_data(as_text=True)}, {u['user'] for u in f.get_json()['users']}


# --- the names --------------------------------------------------------------------------

@pytest.mark.parametrize('name', ['system', 'Scheduler', ' INSTALLER ', 'unknown'])
def test_the_names_the_background_writes_under_are_known(name):
    assert is_audit_pseudo_actor(name)


@pytest.mark.parametrize('name', ['', None, 'alice', 'systems', 'system.admin', 'root', 'admin'])
def test_an_ordinary_name_is_none_of_them(name):
    assert not is_audit_pseudo_actor(name)


def test_every_literal_actor_of_the_code_is_in_the_set():
    """log_audit('<name>', ...) and the session fallbacks written into it, as they stand."""
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[1]
    found = set()
    for path in list((root / 'pegaprox').rglob('*.py')) + list((root / 'plugins').rglob('*.py')):
        text = path.read_text(encoding='utf-8', errors='replace')
        found |= set(re.findall(r"log_audit\(\s*(?:user=)?'([a-z]+)'", text))
        found |= set(re.findall(r"log_audit\(\s*(?:getattr\(request, 'session', \{\}\)|request\.session)"
                                r"\.get\('user', '([a-z]+)'\)", text))
        found |= set(re.findall(r"log_audit\(\s*[\w\[\]'.()]+ or '([a-z]+)'", text))
    # 'admin' is a session fallback too, and a name real accounts carry: under require_auth
    # every session has a user, so those rows are written under the caller's own name
    found.discard('admin')
    assert found and found <= AUDIT_PSEUDO_ACTORS, found - AUDIT_PSEUDO_ACTORS


# --- the readers, for an account that exists under such a name ---------------------------

@pytest.mark.parametrize('name', sorted(AUDIT_PSEUDO_ACTORS))
def test_an_account_of_that_name_reads_no_foreign_rows(estate, seed, name):
    who = seed.user(name, role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])
    texts, users = _reads(estate.as_user(who))
    for reader, text in texts.items():
        for row in FOREIGN_ROWS:
            assert row not in text, (reader, row)
        # the rows of its own cluster stay, whoever wrote them
        assert 'Started VM 100' in text and 'Scheduled snapshot of VM 100' in text, reader
    assert users == {'alice', 'scheduler'}, users


def test_an_account_named_scheduler_finds_nothing_foreign_by_searching(estate, seed):
    who = seed.user('scheduler', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])
    c = estate.as_user(who)
    for q in ('?user=scheduler', '?user=system', '?q=Beta', '?q=Installer', '?cluster=Beta'):
        body = c.get('/api/audit/search' + q).get_json()
        assert not any(row in _text(body['entries']) for row in FOREIGN_ROWS), (q, body)
    mine = c.get('/api/audit/search?user=scheduler').get_json()
    assert mine['total'] == 1 and 'Alpha' in _text(mine['entries']), mine


def test_an_account_named_scheduler_sees_only_its_clusters_timeline(estate, seed):
    who = seed.user('scheduler', role='viewer', tenant_id='tenant_a',
                    permissions=['admin.audit', 'cluster.view'])
    c = estate.as_user(who)
    r = c.get(f'/api/timeline?cluster={OWN}&kinds=audit')
    assert r.status_code == 200, r.get_data(as_text=True)
    shown = ' | '.join(str(e.get('details') or '') for e in r.get_json()['events'])
    assert 'Scheduled snapshot of VM 100' in shown
    assert not any(row in shown for row in FOREIGN_ROWS), shown
    assert c.get(f'/api/timeline?cluster={FOREIGN}&kinds=audit').status_code == 403
    r = c.get('/api/timeline/evidence?kinds=audit')
    assert r.status_code == 200, r.get_data(as_text=True)
    dump = r.get_data(as_text=True)
    assert not any(row in dump for row in FOREIGN_ROWS)


def test_an_ordinary_confined_auditor_still_reads_its_own_rows(estate, seed):
    who = seed.user('aud_a', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])
    log_audit('aud_a', 'user.login', 'Login of the auditor')
    texts, users = _reads(estate.as_user(who))
    for reader, text in texts.items():
        assert 'Login of the auditor' in text, reader
        assert not any(row in text for row in FOREIGN_ROWS), reader
    assert 'aud_a' in users


def test_an_admin_keeps_every_row(estate, seed):
    texts, users = _reads(estate.as_user(seed.user('root', role='admin')))
    for reader, text in texts.items():
        for row in FOREIGN_ROWS:
            assert row in text, (reader, row)
    assert {'alice', 'scheduler', 'system', 'installer', 'unknown'} <= users
