"""The published API description has to match the API.

docs/openapi.json is what external tooling reads (#104 Terraform, #693 Ansible).
A spec that drifts from the code is worse than no spec, because it looks
authoritative. So this rebuilds the description from the live route table and
compares it against the committed file: a new route, a removed one, or a changed
permission turns this red until someone re-runs

    venv/bin/python -m pegaprox.cli.gen_openapi -o docs/openapi.json

Body schemas are deliberately NOT compared - they are hand-written per resource
group and the generator does not produce them, so comparing them would fight the
people filling them in.

MK Sep 2026
"""
import json
import os

import pytest

from pegaprox.cli.gen_openapi import build

SPEC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'docs', 'openapi.json')


def _ops(paths):
    """{(path, method): (sorted perms, sorted roles, auth kind)}"""
    out = {}
    for path, methods in paths.items():
        for method, op in methods.items():
            out[(path, method)] = (
                tuple(sorted(op.get('x-pegaprox-permissions', []))),
                tuple(sorted(op.get('x-pegaprox-roles', []))),
                op.get('x-pegaprox-auth'),
            )
    return out


@pytest.fixture(scope='module')
def committed():
    with open(SPEC, encoding='utf-8') as fh:
        return json.load(fh)


def test_the_spec_is_structurally_sound(committed):
    assert committed['openapi'].startswith('3.1')
    ids = [o['operationId'] for m in committed['paths'].values() for o in m.values()]
    assert len(ids) == len(set(ids)), 'operationId must be unique across the document'
    for path in committed['paths']:
        assert path.startswith('/'), path
        assert '<' not in path, f'werkzeug syntax leaked into the spec: {path}'


def test_every_live_route_is_described(api, committed):
    live, doc = _ops(build(api.app)), _ops(committed['paths'])

    missing = sorted(live.keys() - doc.keys())
    stale = sorted(doc.keys() - live.keys())
    assert not missing, (
        f'{len(missing)} route(s) exist but are not in docs/openapi.json, '
        f'e.g. {missing[:5]} - re-run python -m pegaprox.cli.gen_openapi -o docs/openapi.json')
    assert not stale, (
        f'{len(stale)} route(s) in docs/openapi.json no longer exist, '
        f'e.g. {stale[:5]} - re-run the generator')


def test_the_documented_permissions_are_the_enforced_ones(api, committed):
    """The interesting half. If a route's permission changes and the spec keeps
    the old one, we are publishing a false claim about who can call it."""
    live, doc = _ops(build(api.app)), _ops(committed['paths'])
    drift = {k: (doc[k], live[k]) for k in live.keys() & doc.keys() if doc[k] != live[k]}
    assert not drift, (
        f'{len(drift)} route(s) document different auth than they enforce: '
        + '; '.join(f'{m.upper()} {p}: spec={d} code={l}'
                    for (p, m), (d, l) in list(drift.items())[:4]))


# --- found by the 2026-09-29 scan -------------------------------------------
#
# Seven URLs carry TWO registrations (same path, same method, two blueprints).
# werkzeug answers with one of them; the generator was writing whichever
# iter_rules() happened to yield last into the document. For two of the seven
# that is a different handler with a different permission, so the spec named a
# permission the app does not enforce - on /ha it advertised cluster.view while
# the served handler demands ha.view, which is a 403 for anyone who provisions
# from the document.

def _collisions(app):
    import collections
    from pegaprox.cli.gen_openapi import _split_rule, _SKIP_ENDPOINT, _SKIP_RULE
    pairs = collections.defaultdict(list)
    for rule in app.url_map.iter_rules():
        if _SKIP_ENDPOINT.match(rule.endpoint) or _SKIP_RULE.search(str(rule)):
            continue
        if app.view_functions.get(rule.endpoint) is None:
            continue
        path, _ = _split_rule(rule)
        for m in sorted(rule.methods - {'HEAD', 'OPTIONS'}):
            pairs[(path, m.lower())].append(rule.endpoint)
    return {k: v for k, v in pairs.items() if len(v) > 1}


def test_a_doubly_registered_path_is_described_as_the_app_serves_it(api):
    """Not 'as one of them' - as the one that answers.

    The existing drift test compares the committed file against build(), so both
    sides come from the same generator and agree with each other while both are
    wrong. werkzeug's own matcher is the independent oracle here.
    """
    app = api.app
    doc = {'paths': build(app)}
    adapter = app.url_map.bind('localhost')

    wrong = []
    for (path, method), endpoints in _collisions(app).items():
        probe = path
        for ph in ('{cluster_id}', '{rule_id}', '{node}', '{vmid}', '{plugin_id}'):
            probe = probe.replace(ph, 'x1')
        try:
            served = adapter.match(probe, method=method.upper())[0]
        except Exception:
            continue
        op = doc['paths'].get(path, {}).get(method)
        assert op is not None, f'{method} {path} vanished from the spec'
        described = op['operationId'].split('_' + method)[0]
        if not op['operationId'].startswith(served):
            wrong.append((path, method, served, op['operationId']))
    assert not wrong, (
        'the spec describes a handler the app does not serve: '
        + '; '.join(f'{m.upper()} {p}: serves {s}, spec says {o}' for p, m, s, o in wrong))


def test_the_shadowed_registration_is_not_silently_dropped(api):
    """A reader has to be able to see that a second handler is registered there,
    otherwise the document quietly hides dead code."""
    app = api.app
    doc = {'paths': build(app)}
    coll = _collisions(app)
    if not coll:
        import pytest
        pytest.skip('no duplicate registrations in this tree')
    for (path, method), endpoints in coll.items():
        op = doc['paths'].get(path, {}).get(method) or {}
        shadowed = op.get('x-pegaprox-shadowed-by') or []
        assert shadowed, f'{method.upper()} {path} hides {len(endpoints) - 1} other registration(s)'
