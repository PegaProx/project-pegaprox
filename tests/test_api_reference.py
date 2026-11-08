"""The API reference: GET /api/pegaprox/openapi.json hands the description of this
instance to anyone signed in, and the user menu renders it (test_api_reference_ui.py).

The document is built from the route table of the running app, so it is the one
docs/openapi.json holds for this version and it names the permission every route
enforces. It holds no cluster, guest or storage of anybody, so a confined admin, a
pool-confined user and another tenant all read the same document.

MK Oct 2026
"""
import json
import os

import pytest

from pegaprox.cli.gen_openapi import build
from pegaprox.constants import PEGAPROX_VERSION

ROUTE = '/api/pegaprox/openapi.json'
SPEC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'docs', 'openapi.json')


def _ops(paths):
    """{(path, method): (perms, roles, auth kind, summary)}"""
    return {(path, method): (tuple(sorted(op.get('x-pegaprox-permissions', []))),
                             tuple(sorted(op.get('x-pegaprox-roles', []))),
                             op.get('x-pegaprox-auth'), op.get('summary'))
            for path, methods in paths.items() for method, op in methods.items()}


@pytest.fixture
def fresh():
    """Forget the document an earlier test had built."""
    import pegaprox.api.settings as st
    cache = getattr(st, '_openapi_doc', {})
    cache.clear()
    yield
    cache.clear()


def test_signed_out_gets_nothing(api, fresh):
    r = api.anon().get(ROUTE)
    assert r.status_code == 401
    assert b'"paths"' not in r.data


def test_a_viewer_reads_the_description_of_this_instance(api, seed, fresh):
    r = api.as_user(seed.user('vic', role='viewer')).get(ROUTE)
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert r.mimetype == 'application/json'
    doc = r.get_json()
    assert doc['openapi'].startswith('3.1')
    assert doc['info']['version'] == PEGAPROX_VERSION
    assert {'apiToken', 'sessionId'} <= set(doc['components']['securitySchemes'])
    assert _ops(doc['paths']) == _ops(build(api.app))
    assert len(doc['paths']) > 500
    # it describes itself: signed in, no permission
    own = doc['paths'][ROUTE]['get']
    assert own['x-pegaprox-auth'] == 'decorator'
    assert 'x-pegaprox-permissions' not in own and 'x-pegaprox-roles' not in own
    # and a route that does demand one says which
    assert doc['paths']['/api/clusters/{cluster_id}/updates/rolling']['post']['x-pegaprox-permissions'] == ['node.update']


def test_it_is_the_document_the_repository_ships(api, seed, fresh):
    with open(SPEC, encoding='utf-8') as fh:
        committed = json.load(fh)
    doc = api.as_user(seed.user('vic', role='viewer')).get(ROUTE).get_json()
    assert _ops(doc['paths']) == _ops(committed['paths'])
    assert doc['components'] == committed['components']


def test_an_api_token_reads_it_too(api, seed, fresh):
    from pegaprox.utils.auth import create_api_token
    seed.user('ci', role='viewer')
    res = create_api_token('ci', 'docs', role='viewer')
    assert 'token' in res, res
    r = api.anon().get(ROUTE, headers={'Authorization': f"Bearer {res['token']}"})
    assert r.status_code == 200
    assert ROUTE in r.get_json()['paths']


def test_nobody_confined_or_elsewhere_finds_a_cluster_in_it(api, seed, fresh):
    import time
    from pegaprox.utils import rbac
    seed.tenant('acme', clusters=['acme-prod-7f3'])
    seed.tenant('globex', clusters=['globex-dc-9q2'])
    for cid, name in (('acme-prod-7f3', 'Acme Production'), ('globex-dc-9q2', 'Globex Datacenter')):
        m = api.make_fake_manager(cluster_id=cid)
        m.name = name
        api.set_manager(cid, m)
    seed.pool('acme-prod-7f3', 'acme-pool-4k', 'mallory', ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['acme-prod-7f3'] = {
            'data': {'4711:qemu': 'acme-pool-4k'}, 'timestamp': time.time(), 'refreshing': False}
    callers = {
        'confined admin': seed.user('gx', role='admin', tenant_id='globex',
                                    tenant_permissions={'globex': {'role': 'user'}}),
        'other tenant': seed.user('milton', role='user', tenant_id='globex'),
        'pool-confined': seed.user('mallory', role='viewer', tenant_id='acme'),
    }
    bodies = set()
    for who, user in callers.items():
        r = api.as_user(user).get(ROUTE)
        assert r.status_code == 200, (who, r.status_code)
        text = r.get_data(as_text=True)
        for foreign in ('acme-prod-7f3', 'globex-dc-9q2', 'Acme Production', 'Globex Datacenter',
                        'acme-pool-4k', '4711'):
            assert foreign not in text, (who, foreign)
        bodies.add(text)
    # one document for everyone: nothing in it depends on who asks
    assert len(bodies) == 1


def test_it_is_built_once_and_not_per_request(api, seed, fresh, monkeypatch):
    """The generator walks every route (900-odd); doing that per open would block the
    worker for each user who opens the reference."""
    import pegaprox.cli.gen_openapi as gen
    real, built = gen.spec, []
    monkeypatch.setattr(gen, 'spec', lambda app, version: built.append(version) or real(app, version))
    client = api.as_user(seed.user('vic', role='viewer'))
    first = client.get(ROUTE)
    assert first.status_code == 200
    for _ in range(3):
        assert client.get(ROUTE).data == first.data
    assert built == [PEGAPROX_VERSION]


def test_a_standby_answers_it_itself(api, seed, fresh, monkeypatch):
    """A read of the code this instance runs: nothing to forward and nothing to refuse."""
    from pegaprox.core import ha
    import pegaprox.api.ha as ha_api
    forwarded = []
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha_api, 'forward_to_active', lambda read=False: forwarded.append(read))
    r = api.as_user(seed.user('vic', role='viewer')).get(ROUTE)
    assert r.status_code == 200
    assert forwarded == []


def test_it_only_reads(api):
    methods = {m for r in api.app.url_map.iter_rules() if r.rule == ROUTE for m in r.methods}
    assert methods - {'HEAD', 'OPTIONS'} == {'GET'}
