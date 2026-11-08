"""A snapshot name must not be able to walk out of its guest.

The snapshot routes interpolate the name straight into the PVE API path
(.../{vmid}/snapshot/{snapname}) while the authz gate in front of them validates
only the vmid. So a caller who legitimately owns ONE guest could poison the name
and reach a different guest — or a different endpoint entirely — as the cluster's
stored root ticket, with DELETE as the verb:

    ../../800                             -> /nodes/pve/qemu/800        (destroy a VM)
    ../../../../../storage/ceph           -> /storage/ceph              (drop a storage)
    ../../../../../access/users/victim    -> /access/users/victim       (delete a PVE user)

Reachable by the stock builtin ROLE_USER: vm.view and vm.snapshot are both on its
first line, and all four shipped ROLE_TEMPLATES carry them too — including
vm_operator, the deliberately minimal one.

The portal grew a private copy of this check when the same bug was found there.
The dashboard twins never got it, so the rule lives in utils.sanitization now and
the manager sinks enforce it for every caller. MK
"""
from unittest.mock import MagicMock

import pytest

from pegaprox.utils.sanitization import validate_snapshot_name


TRAVERSALS = [
    '../../800',
    '../../../../../storage/ceph',
    '../../../../../access/users/victim%40pve',
    '..',
    '../current',
    'ok/../../../evil',
    'a\x00b',
    '',
    None,
]


@pytest.mark.parametrize('name', TRAVERSALS)
def test_the_validator_rejects_traversal(name):
    assert validate_snapshot_name(name) is False


@pytest.mark.parametrize('name', ['daily', 'pre-upgrade', 'xcrepl-20260906T020000', 'A', 'a_b-c9'])
def test_the_validator_accepts_real_pve_names(name):
    assert validate_snapshot_name(name) is True


def test_a_63_char_name_is_fine_and_64_is_not():
    assert validate_snapshot_name('a' * 63) is True
    assert validate_snapshot_name('a' * 64) is False


@pytest.fixture
def mgr():
    """A real PegaProxManager bound only enough to reach the URL build."""
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.is_connected = True
    m.logger = MagicMock()
    # host/api_port are properties over these two
    m.current_host = 'pve.example'
    m.config = MagicMock(host='pve.example', api_port=8006)
    m._api_delete = MagicMock(side_effect=AssertionError('the request was sent'))
    m._create_session = MagicMock(side_effect=AssertionError('the request was sent'))
    return m


@pytest.mark.parametrize('name', ['../../800', '../../../../../access/users/victim'])
def test_delete_snapshot_refuses_before_it_builds_a_url(mgr, name):
    """The sink is the right place: every route reaches the same three methods."""
    res = mgr.delete_snapshot('pve1', 100, 'qemu', name)

    assert res == {'success': False, 'error': 'Invalid snapshot name'}
    mgr._api_delete.assert_not_called()


@pytest.mark.parametrize('method', ['delete_snapshot', 'rollback_snapshot', 'create_snapshot'])
def test_all_three_sinks_are_guarded(mgr, method):
    res = getattr(mgr, method)('pve1', 100, 'qemu', '../../800')

    assert res.get('error') == 'Invalid snapshot name', f'{method} is unguarded'


def test_a_poisoned_node_is_refused_too(mgr):
    """node is interpolated one segment earlier and is an independent pivot."""
    res = mgr.delete_snapshot('../../../access/users', 100, 'qemu', 'daily')

    assert res == {'success': False, 'error': 'Invalid node name'}


def test_a_legitimate_delete_still_reaches_the_api(mgr):
    """The guard must not refuse the names PVE actually produces."""
    resp = MagicMock(status_code=200)
    resp.json.return_value = {'data': 'UPID:...'}
    mgr._api_delete = MagicMock(return_value=resp)

    res = mgr.delete_snapshot('pve1', 100, 'qemu', 'pre-upgrade')

    assert res['success'] is True
    url = mgr._api_delete.call_args[0][0]
    assert url.endswith('/qemu/100/snapshot/pre-upgrade')


def test_the_portal_and_the_dashboard_share_one_rule():
    """The portal's private copy was the reason the dashboard twin stayed open."""
    from plugins.client_portal import _valid_snapshot_name

    assert _valid_snapshot_name('../../800') is False
    assert _valid_snapshot_name('daily') is True
