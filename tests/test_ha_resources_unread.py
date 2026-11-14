"""GET .../proxmox-ha/resources answered 200 [] when PVE could not be asked, so the VM
cards said "not in HA" and offered the add. The route now reads the list strictly and
answers 502 for a failed read; the balancer keeps its [] (it only skips guests).

The route tests run the real manager method on a stand-in manager, so a fake that
returns None cannot pass for the wrong reason. The UI side is test_vm_detail_reads_ui.py.
"""
import types
from unittest.mock import MagicMock

import pytest

from pegaprox.core.manager import PegaProxManager

ROUTE = '/api/clusters/cluster_1/proxmox-ha/resources'
REAL = PegaProxManager.get_proxmox_ha_resources


def _resp(status, data=None, body=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body if body is not None else {'data': data}
    return r


def _mgr(connected=True, connects=False, answer=None, raises=None):
    m = MagicMock(name='ha-manager')
    m.is_connected = connected
    m.connect_to_proxmox.return_value = connects
    m.host, m.api_port = '10.0.0.1', 8006
    if raises:
        m._api_get.side_effect = raises
    else:
        m._api_get.return_value = answer
    return m


FAILED = [
    pytest.param(dict(connected=False, connects=False), id='no-connection'),
    pytest.param(dict(answer=_resp(500)), id='http-500'),
    pytest.param(dict(answer=_resp(403)), id='http-403'),
    pytest.param(dict(raises=ConnectionError('reset')), id='exception'),
]


# -- the manager method ---------------------------------------------------------------------

@pytest.mark.parametrize('how', FAILED)
def test_strict_says_none_for_a_failed_read(how):
    assert REAL(_mgr(**how), strict=True) is None


@pytest.mark.parametrize('how', FAILED)
def test_the_default_keeps_the_empty_list_for_the_balancer(how):
    # the CRS filter in the balancer iterates it and only skips guests
    assert REAL(_mgr(**how)) == []


def test_strict_does_not_take_a_200_without_a_list_for_an_empty_one():
    assert REAL(_mgr(answer=_resp(200, body={'data': None})), strict=True) is None


@pytest.mark.parametrize('kw', [{'strict': True}, {}], ids=['strict', 'default'])
def test_a_list_that_was_read_comes_back_either_way(kw):
    rows = [{'sid': 'vm:100', 'state': 'started', 'max_restart': 0}]
    assert REAL(_mgr(answer=_resp(200, rows)), **kw) == rows
    assert REAL(_mgr(answer=_resp(200, [])), **kw) == []


# -- the route ------------------------------------------------------------------------------

@pytest.fixture
def admin(seed):
    return seed.user('root', role='admin', tenant_id='default')


def _route(api, admin, mgr):
    mgr.get_proxmox_ha_resources = types.MethodType(REAL, mgr)
    mgr.cluster_type = 'proxmox'
    api.set_manager('cluster_1', mgr)
    return api.as_user(admin).get(ROUTE)


@pytest.mark.parametrize('how', FAILED)
def test_the_route_answers_502_when_the_list_was_not_read(api, admin, how):
    resp = _route(api, admin, _mgr(**how))
    assert resp.status_code == 502, resp.get_data(as_text=True)
    assert resp.get_json().get('error')


def test_the_route_still_answers_an_empty_list_that_was_read(api, admin):
    resp = _route(api, admin, _mgr(answer=_resp(200, [])))
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_the_route_still_answers_the_list(api, admin):
    rows = [{'sid': 'vm:100', 'state': 'started', 'max_restart': 0, 'max_relocate': 2}]
    resp = _route(api, admin, _mgr(answer=_resp(200, rows)))
    assert resp.status_code == 200
    assert resp.get_json() == rows
