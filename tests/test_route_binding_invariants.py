"""Every rule in the url_map must point at the handler that was meant to serve it.

Inserting a helper between a route's decorators and its handler binds the URL to
the helper and silently unregisters the handler — Flask reports nothing, and a
test that greps the source for the guard it expects still passes. That is exactly
how /api/clusters/<cluster_id>/backup-verify/<task_id> ended up served by
_verification_rows_visible: the route answered with whatever that helper returned
for a task-id string, and the real status handler became dead code.

Cheap to check against the assembled app, so check it for all ~850 rules. MK
"""
import pytest


@pytest.fixture(scope='module')
def rules(_integration_app):
    return list(_integration_app.url_map.iter_rules())


def test_no_route_is_served_by_a_private_helper(rules):
    bound_to_helper = sorted(
        f'{rule} -> {rule.endpoint}' for rule in rules
        if rule.endpoint.rsplit('.', 1)[-1].startswith('_')
    )

    assert not bound_to_helper, (
        'a helper is registered as a view function — its decorators almost certainly '
        'belong to the handler below it:\n  ' + '\n  '.join(bound_to_helper))


def test_the_app_registered_the_routes_we_expect(rules):
    """Guards the guard: a fixture that built an empty app would make this file green."""
    assert len(rules) > 700, len(rules)


@pytest.mark.parametrize('rule,endpoint', [
    ('/api/clusters/<cluster_id>/backup-verify', 'pbs.start_backup_verification'),
    ('/api/clusters/<cluster_id>/backup-verify/<task_id>', 'pbs.get_backup_verification_status'),
    ('/api/clusters/<cluster_id>/backup-verify/history', 'pbs.get_backup_verification_history'),
    ('/api/clusters/<cluster_id>/backup-verify/active', 'pbs.get_active_verifications'),
])
def test_backup_verify_routes_reach_their_handlers(rules, rule, endpoint):
    match = [r for r in rules if str(r) == rule]

    assert match, f'{rule} is not registered at all'
    assert match[0].endpoint == endpoint, f'{rule} is served by {match[0].endpoint}'
