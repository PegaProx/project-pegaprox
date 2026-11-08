"""The evidence bundle of the flight recorder: GET /api/timeline/evidence and its verify route.

A signed JSON attachment with the events of a window the caller may see, the audit rows of it
for a holder of admin.audit, and where the audit chain stood. The signature has a domain of
its own, apart from the recovery evidence.

NS Oct 2026
"""
import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from pegaprox.core import flight_recorder as fr
from test_timeline import env, _fresh, _admin_client, _local, _audit, CID, NOW  # noqa: F401
from test_ha_api import ha_env, _standby_of_active  # noqa: F401

ROUTE = '/api/timeline/evidence'
VERIFY = '/api/timeline/evidence/verify'


def _bundle(client, query=''):
    r = client.get(ROUTE + query)
    assert r.status_code == 200, r.get_data(as_text=True)
    return r, json.loads(r.get_data(as_text=True))


def _check(client, doc):
    r = client.post(VERIFY, json=doc)
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def test_an_admin_gets_an_attachment_with_everything_in_the_window(env):
    r, doc = _bundle(_admin_client(env), f'?clusters={CID}')
    assert r.headers['Content-Disposition'].startswith('attachment; filename="flight-recorder-')
    assert r.headers['Content-Disposition'].endswith('.json"')
    assert doc['format'] == 'pegaprox-flight-recorder' and doc['version'] == 1
    assert doc['generated_by'] == 'root'
    assert doc['instance']['name'] and doc['instance']['version']
    assert [c['id'] for c in doc['clusters']] == [CID]
    kinds = {e['kind'] for e in doc['events']}
    assert {'audit', 'alert', 'migration', 'task', 'drift', 'node'} <= kinds
    assert doc['event_count'] == len(doc['events']) and doc['truncated'] is False
    assert all(e['cluster'] == CID for e in doc['events'])
    # newest first
    times = [e['time'] for e in doc['events']]
    assert times == sorted(times, reverse=True)
    assert doc['window']['since'] < doc['window']['until']
    assert doc['signature']['value']


def test_the_events_are_those_of_the_timeline(env):
    c = _admin_client(env)
    # the timeline first: the export of one cluster is an audit row of that cluster after it
    got = c.get(f'/api/timeline?cluster={CID}&limit=500&correlate=0').get_json()
    _, doc = _bundle(c, f'?clusters={CID}')
    assert [e['id'] for e in doc['events']] == [e['id'] for e in got['events']]


def test_without_a_cluster_list_it_takes_every_cluster_the_caller_reaches(env):
    _, doc = _bundle(_admin_client(env))
    assert {c['id'] for c in doc['clusters']} == {CID, 'other'}
    assert doc['filters']['clusters'] == sorted([CID, 'other'])


def test_the_filters_apply_and_are_stated(env):
    _, doc = _bundle(_admin_client(env), f'?clusters={CID}&kinds=alert&severity=critical')
    assert doc['events'] and {e['kind'] for e in doc['events']} == {'alert'}
    assert {e['severity'] for e in doc['events']} == {'critical'}
    assert doc['filters']['kinds'] == ['alert'] and doc['filters']['severities'] == ['critical']


def test_a_window_is_honoured_and_a_long_one_is_cut(env):
    c = _admin_client(env)
    since = int((NOW - timedelta(minutes=10)).timestamp())
    _, doc = _bundle(c, f'?clusters={CID}&from={since}')
    assert doc['events'] and all(e['time'] >= doc['window']['since'] for e in doc['events'])
    assert not any(e['id'].startswith('task:') and e['kind'] == 'backup' for e in doc['events'])
    long_ago = int((NOW - timedelta(days=90)).timestamp())
    _, doc = _bundle(c, f'?clusters={CID}&from={long_ago}')
    assert doc['window']['clipped'] is True
    lo = datetime.fromisoformat(doc['window']['since'])
    hi = datetime.fromisoformat(doc['window']['until'])
    assert hi - lo <= timedelta(days=30)


@pytest.mark.parametrize('query', ['&from=yesterday', '&from=2026-01-02&to=2026-01-01', '&kinds=nope',
                                   '&severity=loud'])
def test_a_malformed_query_is_a_400(env, query):
    assert _admin_client(env).get(f'{ROUTE}?clusters={CID}{query}').status_code == 400


def test_an_unknown_cluster_is_a_404_and_the_route_wants_a_session(env):
    assert _admin_client(env).get(ROUTE + '?clusters=nope').status_code == 404
    assert env.api.anon().get(ROUTE).status_code == 401
    assert env.api.anon().post(VERIFY, json={}).status_code == 401


def test_a_user_without_cluster_view_gets_none(env):
    c = env.api.as_user(env.seed.user('nora', role='viewer', denied=['cluster.view']))
    assert c.get(ROUTE).status_code == 403
    assert c.post(VERIFY, json={}).status_code == 403


# --- who sees what ---------------------------------------------------------------------------------

def test_a_tenant_confined_user_gets_its_clusters_events_and_no_audit_section(env):
    env.seed.tenant('acme', clusters=['other'])
    env.db.add_migration_event('other', 300, 'x', 'a', 'b', 'success', reason='r', timestamp=_local(3))
    c = env.api.as_user(env.seed.user('milton', role='user', tenant_id='acme'))
    _, doc = _bundle(c)
    assert [x['id'] for x in doc['clusters']] == ['other']
    assert doc['events'] and all(e['cluster'] == 'other' for e in doc['events'])
    assert doc['audit']['included'] is False and 'rows' not in doc['audit']
    assert doc['audit_chain']['included'] is False
    text = json.dumps(doc)
    assert 'web01' not in text and 'Updated config of VM 100' not in text
    # naming a cluster of another tenant is refused as the timeline refuses it
    assert c.get(f'{ROUTE}?clusters={CID}').status_code == 403
    assert c.get(f'{ROUTE}?clusters=other,{CID}').status_code == 403


def test_a_pool_confined_caller_gets_its_guests_only(env):
    from test_proxlb_pins import _seed_pool_membership
    env.seed.tenant('acme', clusters=[CID])
    env.seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view', 'vm.backup'])
    _seed_pool_membership(CID, {100: ('qemu', 'pool_1'), 200: ('qemu', 'pool_2')})
    c = env.api.as_user(env.seed.user('mallory', role='viewer', tenant_id='acme'))
    _, doc = _bundle(c, f'?clusters={CID}')
    assert doc['events'] and all(e['guest'] == 100 for e in doc['events'])
    text = json.dumps(doc)
    assert 'db01' not in text and 'did not boot' not in text
    assert doc['audit']['included'] is False


def test_an_audit_holder_gets_the_audit_rows_of_the_window_only(env):
    # one row far outside the window, one of another cluster
    _audit(env.db, 60 * 24 * 3, 'vm.config', 'Updated config of VM 100 [lab] long ago')
    c = _admin_client(env)
    since = int((NOW - timedelta(minutes=45)).timestamp())
    _, doc = _bundle(c, f'?clusters={CID}&from={since}')
    audit = doc['audit']
    assert audit['included'] is True and audit['clusters'] == [CID]
    assert audit['row_count'] == len(audit['rows']) == 3
    assert {r['cluster_id'] for r in audit['rows']} == {CID}
    assert not any('long ago' in r['details'] for r in audit['rows'])
    assert all(r['timestamp'] for r in audit['rows'])
    assert 'hmac_signature' not in audit['rows'][0]
    assert doc['audit_chain']['included'] is True
    # the fixture moved the times of its rows after they were signed, so these do not verify
    assert doc['audit_chain']['rows_verified'] + doc['audit_chain']['rows_failed'] == 3
    assert doc['audit_chain']['head']['chain_seq'] >= 3


def test_an_audit_holder_of_a_tenant_gets_the_rows_of_its_clusters_whole_only(env):
    env.seed.tenant('acme', clusters=['other'])
    env.db.add_audit_entry('milton', 'vm.config', 'Updated config of VM 300 [other]', '10.0.0.9',
                           cluster='other', severity='info', cluster_id='other')
    u = env.seed.user('amy', role='user', tenant_id='acme')
    c = env.api.as_user(u)
    from pegaprox.utils import rbac
    # the template that carries admin.audit for a tenant's auditor (as GET /api/audit sees it)
    orig = rbac.has_permission

    def granted(user, perm, *a, **kw):
        return perm == 'admin.audit' or orig(user, perm, *a, **kw)
    import pegaprox.api.timeline  # noqa: F401
    import pegaprox.utils.rbac as r
    r.has_permission = granted
    try:
        _, doc = _bundle(c)
    finally:
        r.has_permission = orig
    assert doc['audit']['included'] is True
    assert {x['cluster_id'] for x in doc['audit']['rows']} == {'other'}
    assert not any(CID in json.dumps(x) for x in doc['audit']['rows'])


def test_a_token_below_its_owners_role_gets_no_audit_rows(env):
    """An admin's viewer token: what the token's role holds counts, not the owner's."""
    from pegaprox.utils.auth import create_api_token
    env.seed.user('root', role='admin')
    token = create_api_token('root', 'evidence', role='viewer')['token']
    r = env.api.anon().get(f'{ROUTE}?clusters={CID}', headers={'Authorization': f'Bearer {token}'})
    assert r.status_code == 200, r.get_data(as_text=True)
    doc = json.loads(r.get_data(as_text=True))
    assert doc['audit'] == {'included': False, 'why': doc['audit']['why']}
    assert doc['audit_chain']['included'] is False
    kinds = {e['kind'] for e in doc['events']}
    # drift and syslog want admin.audit, the incidents an admin
    assert kinds and not kinds & {'drift', 'syslog', 'incident'}
    assert doc['generated_by'] == 'root'


def test_a_tenant_admin_gets_its_tenants_clusters_and_their_audit_rows_only(env):
    """Administrator inside a tenant (the override), not of the instance."""
    env.seed.tenant('acme', clusters=['other'])
    u = env.seed.user('tara', role='user', tenant_id='acme', tenant_permissions={'acme': {'role': 'admin'}})
    c = env.api.as_user(u)
    _, doc = _bundle(c)
    assert doc['filters']['clusters'] == ['other'] and doc['audit']['clusters'] == ['other']
    assert doc['audit']['rows'] and {r['cluster_id'] for r in doc['audit']['rows']} == {'other'}
    assert doc['events'] and {e['cluster'] for e in doc['events']} == {'other'}
    # the plan to CID and the incidents (instance admins only) stay out
    assert not {e['kind'] for e in doc['events']} & {'site_recovery', 'incident'}
    assert c.get(f'{ROUTE}?clusters={CID}').status_code == 403


def test_an_auditor_confined_to_a_pool_gets_no_audit_rows_of_that_cluster(env):
    """admin.audit through a custom role in the default tenant, and a pool grant on CID:
    CID is a cluster this caller sees some guests of, so none of its audit rows."""
    from pegaprox.utils import rbac
    from test_proxlb_pins import _seed_pool_membership
    env.db.conn.execute("INSERT INTO custom_roles (name, permissions, description, tenant_id, created_at) "
                        "VALUES ('pool_auditor', ?, '', '', '2026-01-01')",
                        (json.dumps(['cluster.view', 'admin.audit']),))
    env.db.conn.commit()
    rbac.invalidate_roles_cache()
    env.seed.pool(CID, 'pool_1', 'paula', ['pool.view', 'vm.view'])
    _seed_pool_membership(CID, {100: ('qemu', 'pool_1'), 200: ('qemu', 'pool_2')})
    c = env.api.as_user(env.seed.user('paula', role='pool_auditor'))
    _, doc = _bundle(c)
    assert doc['audit']['included'] is True
    assert CID in doc['filters']['clusters'] and CID not in doc['audit']['clusters']
    assert doc['audit']['rows'] and {r['cluster_id'] for r in doc['audit']['rows']} == {'other'}
    mine = [e for e in doc['events'] if e['cluster'] == CID]
    assert mine and all(e['guest'] == 100 for e in mine)


def test_the_chain_section_checks_the_rows_exported(env):
    db = env.db
    for i in range(3):
        db.add_audit_entry('root', 'vm.config', f'Updated config of VM 10{i} [lab]', '10.0.0.9',
                           cluster='lab', severity='info', cluster_id='fresh')
    env.api.set_manager('fresh', env.api.make_fake_manager('fresh', get_tasks=[]))
    c = _admin_client(env)
    _, doc = _bundle(c, '?clusters=fresh')
    chain = doc['audit_chain']
    assert (chain['rows'], chain['rows_verified'], chain['rows_failed']) == (3, 3, 0)
    assert chain['links_checked'] == 2 and chain['links_broken'] == 0
    assert chain['first_seq'] and chain['last_seq'] == chain['first_seq'] + 2
    assert chain['head']['chain_seq'] >= chain['last_seq'] and chain['head']['hash']
    assert chain['walk']['scanned_rows'] >= 3
    # one row edited in the log after the fact shows in the next bundle
    db.conn.execute("UPDATE audit_log SET details = 'edited' WHERE chain_seq = ?", (chain['first_seq'] + 1,))
    db.conn.commit()
    _, doc = _bundle(c, '?clusters=fresh')
    chain = doc['audit_chain']
    assert chain['rows_failed'] == 1 and chain['walk']['intact'] is False and chain['walk']['edited'] >= 1


# --- the signature --------------------------------------------------------------------------------

def test_the_bundle_verifies(env):
    c = _admin_client(env)
    _, doc = _bundle(c, f'?clusters={CID}')
    assert _check(c, doc) == {'valid': True, 'reason': 'signed by this instance and unchanged'}
    # also after a round trip through a file
    assert _check(c, json.loads(json.dumps(doc, indent=1)))['valid'] is True


def _tampered(doc, how):
    d = copy.deepcopy(doc)
    how(d)
    return d


@pytest.mark.parametrize('name,how', [
    ('event title', lambda d: d['events'][0].update(title='changed')),
    ('event dropped', lambda d: d['events'].pop()),
    ('event added', lambda d: d['events'].append(dict(d['events'][0], id='audit:999'))),
    ('window', lambda d: d['window'].update(since='2020-01-01T00:00:00+00:00')),
    ('generated_by', lambda d: d.update(generated_by='someone')),
    ('generated_at', lambda d: d.update(generated_at='2020-01-01T00:00:00+00:00')),
    ('instance', lambda d: d['instance'].update(name='other-host')),
    ('filters', lambda d: d['filters'].update(kinds=['audit'])),
    ('clusters', lambda d: d['clusters'].append({'id': 'x', 'name': 'x'})),
    ('truncated', lambda d: d.update(truncated=True)),
    ('audit row', lambda d: d['audit']['rows'][0].update(details='nothing happened')),
    ('audit row dropped', lambda d: d['audit']['rows'].pop()),
    ('audit chain', lambda d: d['audit_chain'].update(rows_failed=7)),
    ('signature value', lambda d: d['signature'].update(value='0' * 64)),
    ('signature removed', lambda d: d.pop('signature')),
])
def test_a_changed_bundle_is_invalid(env, name, how):
    c = _admin_client(env)
    _, doc = _bundle(c, f'?clusters={CID}')
    res = _check(c, _tampered(doc, how))
    assert res['valid'] is False and res['reason'], name


def test_a_bundle_without_a_signing_key_is_unsigned_and_invalid(env, monkeypatch):
    c = _admin_client(env)
    monkeypatch.setattr(env.db, 'aes_key', None)
    _, doc = _bundle(c, f'?clusters={CID}')
    assert doc['signature']['value'] is None
    res = _check(c, doc)
    assert res['valid'] is False and 'signature' in res['reason']


def test_a_body_that_is_no_bundle_is_refused_or_invalid(env):
    c = _admin_client(env)
    assert c.post(VERIFY, json=[1, 2]).status_code == 400
    assert c.post(VERIFY, data='not json', content_type='application/json').status_code == 400
    assert _check(c, {'format': 'something else'})['valid'] is False


@pytest.mark.parametrize('where', ['top', 'event', 'audit row'])
def test_a_key_written_twice_makes_the_bundle_invalid(env, where):
    """The parser keeps the last of two equal keys, so the signed value goes last and a
    forged one before it: valid here, while a reader that keeps the first (or a person
    reading the file) sees the forged one."""
    c = _admin_client(env)
    r, doc = _bundle(c, f'?clusters={CID}')
    raw = r.get_data(as_text=True)
    signed = {'top': '"generated_by": "root"',
              'event': json.dumps({'title': doc['events'][0]['title']}, ensure_ascii=False)[1:-1],
              'audit row': json.dumps({'details': doc['audit']['rows'][0]['details']}, ensure_ascii=False)[1:-1]}[where]
    assert signed in raw
    key = signed.split(':', 1)[0]
    forged = raw.replace(signed, f'{key}: "nothing happened here", {signed}', 1)
    assert json.loads(forged) == json.loads(raw)
    res = c.post(VERIFY, data=forged, content_type='application/json')
    assert res.status_code == 200, res.get_data(as_text=True)
    assert res.get_json()['valid'] is False and 'twice' in res.get_json()['reason']
    # the file as it came is still fine
    assert c.post(VERIFY, data=raw, content_type='application/json').get_json()['valid'] is True


def test_a_body_nested_too_deep_is_a_400_not_a_crash(env):
    c = _admin_client(env)
    deep = '[' * 100000 + ']' * 100000
    assert c.post(VERIFY, data=deep, content_type='application/json').status_code == 400
    deep = '{"format": "pegaprox-flight-recorder", "x": ' + '{"a": ' * 100000 + '1' + '}' * 100001
    assert c.post(VERIFY, data=deep, content_type='application/json').status_code == 400


@pytest.mark.parametrize('name,how', [
    ('a note beside the value', lambda s: s.update(note='checked by the auditor, nothing found')),
    ('another algorithm named', lambda s: s.update(alg='none')),
    ('no algorithm named', lambda s: s.pop('alg')),
])
def test_the_signature_block_holds_the_signature_and_nothing_else(env, name, how):
    """Only the rest of the bundle is signed: whatever sits in the signature block next to the
    value is covered by nothing."""
    c = _admin_client(env)
    _, doc = _bundle(c, f'?clusters={CID}')
    how(doc['signature'])
    res = _check(c, doc)
    assert res['valid'] is False and 'signature' in res['reason'], name


def test_the_verify_post_is_behind_the_csrf_check(env):
    c = _admin_client(env)
    _, doc = _bundle(c, f'?clusters={CID}')
    bare = c._c.post(VERIFY, json=doc, headers={'X-Session-ID': c.session_id}, base_url='http://localhost')
    assert bare.status_code == 403 and 'CSRF' in bare.get_json()['error']
    assert c.post(VERIFY, json=doc, headers={'Origin': 'https://elsewhere.example'}).status_code == 403
    assert c.post(VERIFY, json=doc).get_json()['valid'] is True


def test_a_bundle_at_the_event_cap_still_verifies(env):
    """A bundle comes back whole to be checked. At the event cap, with titles and details as
    long as an event carries them, it is larger than the 10 MB an API call may be."""
    c = _admin_client(env)
    _, doc = _bundle(c, f'?clusters={CID}')
    one = dict(doc['events'][0], title='t' * 300, details='d' * 500)
    doc['events'] = [dict(one, id=f'audit:{i}') for i in range(fr.EVENTS_MAX)]
    doc['event_count'] = len(doc['events'])
    doc.pop('signature')
    fr.sign(doc)
    raw = json.dumps(doc, ensure_ascii=False, indent=1).encode('utf-8')     # as the route writes it
    assert len(raw) > 10 * 1024 * 1024
    r = c.post(VERIFY, data=raw, content_type='application/json')
    assert r.status_code == 200, (r.status_code, r.get_data(as_text=True)[:200])
    assert r.get_json()['valid'] is True


def test_a_recovery_evidence_document_does_not_verify_here(env):
    from pegaprox.core import assurance
    c = _admin_client(env)
    doc = assurance.build_evidence('cluster', CID, 30, [], [], [], [], assurance.coverage([]))
    assert assurance.verify(doc)['signature_valid'] is True
    assert _check(c, doc)['valid'] is False
    # relabelled: the format says bundle, the signature was made in the other domain
    relabelled = dict(doc, format=fr.FORMAT)
    res = _check(c, relabelled)
    assert res['valid'] is False and 'signature' in res['reason']
    resigned = fr.sign(dict(doc, format=fr.FORMAT))
    assert _check(c, resigned)['valid'] is True      # only by signing it here, which needs the key


def test_a_bundle_does_not_verify_as_recovery_evidence(env):
    from pegaprox.core import assurance
    c = _admin_client(env)
    _, doc = _bundle(c, f'?clusters={CID}')
    assert c.post('/api/recovery-evidence/verify', json=doc).status_code == 400
    relabelled = dict(doc, format=assurance.EVIDENCE_FORMAT)
    r = c.post('/api/recovery-evidence/verify', json=relabelled)
    assert r.status_code == 200 and r.get_json()['signature_valid'] is False


def test_a_signature_made_in_the_other_domain_does_not_count_either_way(env):
    """Same key, same body: only the domain tells the two signatures apart (a document
    relabelled changes its body, so that alone proves nothing)."""
    import hashlib
    import hmac
    from pegaprox.core import assurance
    c = _admin_client(env)
    key = env.db.aes_key
    assert key
    body = {'format': fr.FORMAT, 'version': 1, 'events': []}
    wrong = dict(body, signature={'alg': 'HMAC-SHA256', 'value': hmac.new(
        key, assurance._SIG_DOMAIN + assurance._canonical(body), hashlib.sha256).hexdigest()})
    assert _check(c, wrong)['valid'] is False
    right = dict(body, signature={'alg': 'HMAC-SHA256', 'value': hmac.new(
        key, b'pegaprox-flight-recorder\x00' + assurance._canonical(body), hashlib.sha256).hexdigest()})
    assert _check(c, right)['valid'] is True
    # and a recovery document signed in the bundle's domain is no evidence of that kind
    doc = assurance.build_evidence('cluster', CID, 30, [], [], [], [], assurance.coverage([]))
    doc['signature'] = {'alg': 'HMAC-SHA256', 'value': hmac.new(
        key, b'pegaprox-flight-recorder\x00' + assurance._canonical(doc), hashlib.sha256).hexdigest()}
    assert assurance.verify(doc)['signature_valid'] is False


def test_the_two_domains_differ():
    from pegaprox.core import assurance
    assert fr._SIG_DOMAIN != assurance._SIG_DOMAIN
    assert not fr._SIG_DOMAIN.startswith(assurance._SIG_DOMAIN[:-1] + b'x')


# --- caps, audit, standby -------------------------------------------------------------------------

def test_the_event_cap_sets_truncated_and_the_count(env, monkeypatch):
    monkeypatch.setattr(fr, 'EVENTS_MAX', 5)
    full = _admin_client(env).get(f'/api/timeline?cluster={CID}&limit=500&correlate=0').get_json()['events']
    _, doc = _bundle(_admin_client(env), f'?clusters={CID}')
    assert doc['truncated'] is True and doc['event_count'] == 5 == len(doc['events'])
    assert doc['event_cap'] == 5
    # the newest ones are what stays
    assert [e['id'] for e in doc['events']] == [e['id'] for e in full][:5]
    assert _check(_admin_client(env), doc)['valid'] is True


def test_the_audit_cap_sets_truncated(env, monkeypatch):
    monkeypatch.setattr(fr, 'AUDIT_MAX', 2)
    _, doc = _bundle(_admin_client(env), f'?clusters={CID}')
    assert doc['audit']['truncated'] is True and len(doc['audit']['rows']) == 2


def test_more_pages_than_one_are_walked(env, monkeypatch):
    import pegaprox.api.timeline as tapi
    monkeypatch.setattr(tl_limit(), 'LIMIT_MAX', 3)
    c = _admin_client(env)
    _, doc = _bundle(c, f'?clusters={CID}')
    monkeypatch.setattr(tl_limit(), 'LIMIT_MAX', 500)
    _, whole = _bundle(c, f'?clusters={CID}')
    assert len(doc['events']) > 3
    # the second bundle has the export of the first among its events
    later = [e['id'] for e in whole['events'] if e['title'] != 'timeline.evidence_export']
    assert [e['id'] for e in doc['events']] == later
    assert tapi  # the route module is the one under test


def tl_limit():
    from pegaprox.core import timeline
    return timeline


def test_the_event_cap_is_the_bundles_not_each_clusters(env, monkeypatch):
    """Every cluster was walked to the cap of its own and all of it held at once: 50 busy
    clusters made a million events in memory for a bundle that keeps 20000. Once the bundle
    is full, a cluster whose next page is older than everything kept is read no further."""
    import pegaprox.api.timeline as tapi
    for name in ('zz1', 'zz2'):
        env.api.set_manager(name, env.api.make_fake_manager(name, get_tasks=[]))
        for i in range(8):
            env.db.add_migration_event(name, 500 + i, f'old{i}', 'a', 'b', 'success', reason='r',
                                       timestamp=_local(300 + i))
    c = _admin_client(env)
    _, whole = _bundle(c)
    assert {e['cluster'] for e in whole['events']} >= {CID, 'zz1', 'zz2'}

    monkeypatch.setattr(fr, 'EVENTS_MAX', 5)
    monkeypatch.setattr(tl_limit(), 'LIMIT_MAX', 2)
    walked = {}
    real = tapi._walk_cluster

    def spy(cid, *a, **kw):
        got = real(cid, *a, **kw)
        walked[cid] = len(got[0])
        return got
    monkeypatch.setattr(tapi, '_walk_cluster', spy)
    _, doc = _bundle(c)
    assert [e['id'] for e in doc['events']] == [e['id'] for e in whole['events']][:5]
    assert doc['truncated'] is True and doc['event_count'] == 5
    # the two old clusters: one page each (2 events), not walked to the cap (6)
    assert walked['zz1'] <= 2 and walked['zz2'] <= 2, walked


def test_the_export_is_written_to_the_audit_log(env):
    c = _admin_client(env)
    _, doc = _bundle(c, f'?clusters={CID}')
    rows = env.db.query("SELECT * FROM audit_log WHERE action = 'timeline.evidence_export'")
    assert len(rows) == 1
    row = rows[0]
    assert row['user'] == 'root'
    assert doc['window']['since'] in row['details'] and f"{doc['event_count']} events" in row['details']
    assert f"{doc['audit']['row_count']} audit rows" in row['details']
    # the export is not in its own bundle, but in the next one
    assert not any(r['action'] == 'timeline.evidence_export' for r in doc['audit']['rows'])
    _, later = _bundle(c, f'?clusters={CID}')
    assert later['event_count'] >= 0


def test_the_export_row_says_which_clusters_and_belongs_to_a_single_one(env):
    """'2 clusters' tells an auditor nothing. And the export of one cluster is that cluster's
    row, so its own trail shows who took the bundle, as the recovery evidence does."""
    c = _admin_client(env)
    _bundle(c, f'?clusters={CID},other')
    row = env.db.query("SELECT * FROM audit_log WHERE action = 'timeline.evidence_export'")[0]
    assert CID in row['details'] and 'other' in row['details']
    assert not row['cluster_id']
    _bundle(c, f'?clusters={CID}')
    row = env.db.query("SELECT * FROM audit_log WHERE action = 'timeline.evidence_export' ORDER BY id DESC")[0]
    assert row['cluster_id'] == CID and CID in row['details']
    _, later = _bundle(c, f'?clusters={CID}')
    assert any(r['action'] == 'timeline.evidence_export' for r in later['audit']['rows'])
    assert any(e['title'] == 'timeline.evidence_export' for e in later['events'])


def test_a_refused_request_writes_nothing(env):
    c = _admin_client(env)
    c.get(ROUTE + '?clusters=nope')
    c.get(f'{ROUTE}?clusters={CID}&from=bad')
    assert env.db.query("SELECT * FROM audit_log WHERE action = 'timeline.evidence_export'") == []


def test_a_standby_reads_the_evidence_from_its_active():
    from pegaprox.core import ha
    assert '/api/timeline/evidence' in ha.LEADER_ONLY_READS
    assert '/api/timeline/evidence' in ha.FORWARDED_READS
