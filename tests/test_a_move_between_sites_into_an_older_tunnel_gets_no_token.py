"""A move between two sites into a target older than its Proxmox VE 9.3 source gets no token.

The source of a move between two sites is read at one site and the node the guest lands on
at the other. A 9.3 source (qemu-server 9.2.21, pve-container 6.1.25) aborts against an
older target in the task, after the target reserved the VMID and after the target's site
made the token and its ACLs. Now the site that leads the source sends its node's tunnel
version along with the token request, and the target's site refuses it with 409
PVE_TUNNEL_TOO_OLD before it makes anything. Its answer carries its own node's version,
which the asking site hands the source's remote-migrate route, for a source it does not
lead (tests/test_a_move_into_an_older_migration_tunnel_is_refused_up_front.py holds that
route to it). An older source, and a site that sends no version, move as before.

MK Nov 2026
"""
import pytest

from pegaprox import globals as g

from tests.test_federation import (  # noqa: F401 - fixtures by name
    _defaults_out_of_the_config_dir, _fresh_budgets)
from tests.test_federation_relay import (  # noqa: F401 - fixtures by name
    MIGRATIONS, _fresh_relay, _session, linked)
from tests.test_federation_migrate import SRC, _migrate, pve  # noqa: F401
from tests.test_a_move_into_an_older_migration_tunnel_is_refused_up_front import NEW, OLD, _reads
from tests.test_federation_relay import CID


@pytest.fixture
def versions(pve):
    """The source node n1 at a and the target node pve-b1 at b, each with its packages."""
    seen = {'n1': None, 'pve-b1': None}
    tgt, inner = g.cluster_managers[CID], g.cluster_managers[CID]._api_get.side_effect
    # the host its endpoint names, as get_cluster_fingerprint() answers there
    tgt.config.host = tgt.host

    def target(url, **kw):
        got = _reads({'pve-b1': seen['pve-b1']}, 'pve-b1')(url)
        return got if got.status_code != 404 else inner(url, **kw)
    tgt._api_get.side_effect = target
    g.cluster_managers[SRC]._api_get.side_effect = lambda url, **kw: _reads({'n1': seen['n1']}, 'n1')(url)
    return seen


def test_the_target_site_refuses_an_older_target_before_it_makes_anything(linked, pve, versions):
    a, b = linked
    versions.update({'n1': NEW, 'pve-b1': OLD})
    r = _migrate(a, b, _session(a, 'alice'))
    assert r.status_code == 409 and r.get_json()['code'] == 'PVE_TUNNEL_TOO_OLD', r.data
    assert 'Upgrade the target cluster first' in r.get_json()['error']
    # no role, no token, no ACL there, and the source was not asked
    assert pve['post'] == [] and pve['put'] == [] and MIGRATIONS == []


@pytest.mark.parametrize('source, target', [(OLD, OLD), (NEW, NEW), (None, OLD)],
                         ids=['9.2', '9.3', 'source unread'])
def test_other_versions_move_and_the_source_route_learns_the_target(linked, pve, versions, source, target):
    a, b = linked
    versions.update({'n1': source, 'pve-b1': target})
    r = _migrate(a, b, _session(a, 'alice'))
    assert r.status_code == 200, r.data
    (_cid, _user, _node, _type, _vmid, body), = MIGRATIONS
    assert body['target_tunnel'] == (3 if target is NEW else 2)


def test_a_target_whose_version_cannot_be_read_moves_as_before(linked, pve, versions):
    a, b = linked
    versions.update({'n1': NEW, 'pve-b1': None})
    r = _migrate(a, b, _session(a, 'alice'))
    assert r.status_code == 200, r.data
    (*_rest, body), = MIGRATIONS
    assert 'target_tunnel' not in body
