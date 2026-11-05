"""The CPU models and machine types the VM dialogs offer come from the cluster of the VM.

/api/hardware-options took the first registered cluster for every dialog: an XCP-ng pool
answered with its two CPU types, an ESXi host had no list at all (a 500, the dialog fell back
to three types), and a PVE cluster answered for another one with other custom models.
?cluster_id= now answers from that cluster, under the same access as the cluster itself.
Without it the first Proxmox VE cluster the caller may see answers.

MK Nov 2026
"""
import re

import pytest

from pegaprox.core.manager import PegaProxManager

URL = '/api/hardware-options'


def _pve(api, cid, cpu_types):
    return api.set_manager(cid, api.make_fake_manager(
        cid, get_cpu_types=cpu_types, get_scsi_controllers=[], get_network_models=[],
        get_disk_bus_types=[], get_cache_modes=[], get_machine_types=[{'value': '', 'label': cid}]))


class _NoOptions:
    """A manager without the option methods, like the ESXi one."""
    cluster_type = 'esxi'


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def test_the_named_cluster_answers(api, admin):
    _pve(api, 'pve_a', ['host', 'Haswell'])
    _pve(api, 'pve_b', ['host', 'EPYC-Genoa', 'custom-fleet'])
    r = admin.get(f'{URL}?cluster_id=pve_b')
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['cpu_types'] == ['host', 'EPYC-Genoa', 'custom-fleet']
    assert body['machine_types'] == [{'value': '', 'label': 'pve_b'}]


def test_without_a_cluster_the_first_proxmox_cluster_answers(api, admin):
    api.set_manager('xcp', api.make_fake_manager('xcp', cluster_type='xcpng', get_cpu_types=['host', 'max']))
    api.set_manager('esxi', _NoOptions())
    _pve(api, 'pve_a', ['host', 'Haswell'])
    r = admin.get(URL)
    assert r.status_code == 200, r.data
    assert r.get_json()['cpu_types'] == ['host', 'Haswell']


def test_a_cluster_without_options_gets_the_defaults_not_a_500(api, admin):
    api.set_manager('esxi', _NoOptions())
    r = admin.get(f'{URL}?cluster_id=esxi')
    assert r.status_code == 200, r.data
    assert 'host' in r.get_json()['cpu_types']


def test_a_cluster_the_caller_cannot_see_is_refused(api, seed):
    hidden = _pve(api, 'pve_hidden', ['host', 'custom-secret'])
    _pve(api, 'pve_own', ['host', 'Haswell'])
    seed.tenant('own', ['pve_own'])
    user = api.as_user(seed.user('op', role='user', tenant_id='own', permissions=['node.view']))
    r = user.get(f'{URL}?cluster_id=pve_hidden')
    assert r.status_code == 403, r.data
    assert not hidden.get_cpu_types.called
    # and without a cluster: the first one this caller may see, not the first one registered
    r = user.get(URL)
    assert r.status_code == 200, r.data
    assert r.get_json()['cpu_types'] == ['host', 'Haswell']
    assert not hidden.get_cpu_types.called


def test_the_fallback_list_is_the_one_qemu_server_accepts():
    types = PegaProxManager._STATIC_CPU_TYPES
    assert len(types) == len(set(types))
    for name in ('EPYC-Genoa', 'EPYC-Genoa-v2', 'EPYC-Turin', 'EPYC-Milan-v3', 'GraniteRapids-v3',
                 'SierraForest-v3', 'ClearwaterForest', 'SapphireRapids-v4', 'Icelake-Server-v7',
                 'Skylake-Server-v5', 'Cascadelake-Server-v5', 'KnightsMill', '486',
                 'x86-64-v2-AES', 'x86-64-v4', 'host', 'max'):
        assert name in types, name
    # QEMU knows n270, the PVE model list does not: a config with it is refused
    assert 'n270' not in types
    assert all(re.fullmatch(r'[A-Za-z0-9_.-]+', t) for t in types)


def test_an_unreachable_cluster_offers_the_fallback_sorted():
    m = PegaProxManager.__new__(PegaProxManager)
    m._fetch_pve_cpu_types = lambda: []
    out = m.get_cpu_types()
    assert out[:2] == ['host', 'max']
    assert sorted(out[2:], key=str.casefold) == out[2:]
    assert set(out) == set(PegaProxManager._STATIC_CPU_TYPES)
