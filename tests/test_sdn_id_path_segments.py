"""An SDN id is a URL path segment that ends up inside a PVE API path.

Found by sweeping the medium tier for sinks rather than reading 72 finding titles: every
f-string that builds an `api2/json` path was checked for placeholders that come from the
caller. The subnet route was already right - it percent-encodes, because a CIDR contains a
slash, and says so. The six object ids next to it were not.

The exploit is smaller than the snapshot one it resembles, because Werkzeug will not pass
a slash into a <string> converter, so it is one level per request rather than a walk. It
is still a PUT or DELETE landing somewhere the caller did not ask for, spoken with the
cluster's stored root credential.

MK
"""
import pytest

from pegaprox.utils.sanitization import validate_sdn_id


# --- the mechanism, so the next reader does not have to take it on trust ------------

def test_requests_really_does_resolve_dot_segments():
    """This is why a bare '..' matters at all. If this ever stops being true the guard is
    belt and braces rather than the belt."""
    from requests.models import PreparedRequest

    r = PreparedRequest()
    r.prepare_url('https://pve.example:8006/api2/json/cluster/sdn/vnets/../subnets/x', None)
    assert r.url.endswith('/api2/json/cluster/sdn/subnets/x')


def test_werkzeug_hands_a_dot_segment_straight_to_the_handler():
    from werkzeug.routing import Map, Rule

    m = Map([Rule('/api/clusters/<cluster_id>/datacenter/sdn/zones/<zone_id>', endpoint='z')])
    _, args = m.bind('localhost').match('/api/clusters/c1/datacenter/sdn/zones/..')
    assert args['zone_id'] == '..'


# --- the guard ----------------------------------------------------------------------

@pytest.mark.parametrize('bad', ['..', '.', '../..', '', 'x/y', '%2e%2e', '..%2F..', '-lead'])
def test_unusable_ids_are_refused(bad):
    assert not validate_sdn_id(bad)


@pytest.mark.parametrize('ok', ['zone1', 'myVnet', 'a-b_c', 'evpn', 'Z9'])
def test_real_ids_still_pass(ok):
    """Proxmox publishes the grammar as [a-zA-Z][a-zA-Z0-9]*[a-zA-Z0-9]; dash and
    underscore are tolerated here so an id somebody already created keeps working."""
    assert validate_sdn_id(ok)


def test_the_guard_sits_on_the_blueprint_not_on_one_handler():
    """Eighteen routes take one of these ids today. The point of putting it on the
    blueprint is the nineteenth."""
    import inspect
    import pegaprox.api.datacenter as D

    src = inspect.getsource(D)
    assert '@bp.before_request' in src
    assert '_SDN_ID_PARAMS' in src
    # subnet_id must NOT be in the list - it is a CIDR and contains a slash on purpose
    body = src.split('_SDN_ID_PARAMS')[1].split(')')[0]
    assert 'subnet_id' not in body


def test_the_subnet_route_still_encodes_instead_of_refusing():
    """The counter-case. Adding subnet_id to the guard would break DHCP range edits."""
    import inspect
    import pegaprox.api.datacenter as D

    body = inspect.getsource(D.update_sdn_subnet)
    assert "quote(subnet_id, safe='')" in body


def test_a_dot_segment_is_refused_before_it_reaches_a_handler(api, db, seed):
    """The behavioural one. The two tests at the top prove the mechanism (requests
    resolves the segment, werkzeug hands it over); this proves we stop it.

    Written to survive being run against code that has no validate_sdn_id at all - the
    import-by-name version above goes red with an ImportError, which says nothing about
    traversal. This one just drives the request."""
    seed.tenant('acme', clusters=['cluster_1'])
    user = seed.user('sdnadmin', role='admin', tenant_id='acme')
    c = api.as_user(user)

    r = c.put('/api/clusters/cluster_1/datacenter/sdn/zones/..', json={'type': 'evpn'})
    assert r.status_code == 400, \
        f"'..' reached the handler and would have moved the PUT up a level (got {r.status_code})"
    assert 'zone_id' in (r.get_json() or {}).get('error', '')


def test_a_real_zone_id_is_not_refused_by_the_guard(api, db, seed):
    """The mirror. A guard that also blocks legitimate ids is worse than the traversal."""
    seed.tenant('acme', clusters=['cluster_1'])
    user = seed.user('sdnadmin2', role='admin', tenant_id='acme')
    c = api.as_user(user)

    r = c.put('/api/clusters/cluster_1/datacenter/sdn/zones/evpn1', json={'type': 'evpn'})
    # whatever happens next is the handler's business - it must simply not be our 400
    assert not (r.status_code == 400 and 'zone_id' in (r.get_json() or {}).get('error', ''))
