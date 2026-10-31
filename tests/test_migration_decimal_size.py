"""The server and browser agree on fractional cross-cluster migration disk sizes."""

from unittest.mock import MagicMock

import pytest

from pegaprox.core import preflight
from test_migration_preflight import (CFG, XPF, _fresh, _two, _xbody, _xrun, _rows,
                                     _codes, _store, _guest, no_cleanup_thread)  # noqa: F401


@pytest.mark.parametrize('size, gb', [('0.5T', 512), ('100.1G', 100.1), ('100.5G', 100.5)])
@pytest.mark.parametrize('forced', [False, True])
def test_fractional_large_disks_change_mode_unless_forced(size, gb, forced):
    """Both automatic offline selection and explicit online override use the full size."""
    online, total, warning = preflight.cross_online({'scsi0': f'local:disk,size={size}'}, True, forced)
    assert online is forced
    assert total == pytest.approx(gb)
    assert warning
    if size == '100.1G':
        assert '101GB' in warning


def test_the_preflight_warns_and_blocks_a_running_fractional_large_vm(api, seed):
    """The Check step explains that a large running VM needs shutdown or a forced live move."""
    _two(api, src_cfg={100: dict(CFG, scsi0='local-lvm:disk,size=0.5T')},
         storages=[_store('far1', 'fast', free_gb=2000)])
    client = api.as_user(seed.user('root', role='admin'))
    response = client.post(XPF, json=_xbody(vms=[100], online=True))
    assert response.status_code == 200
    row = _rows(response.get_json())[100]
    assert 'large_disk' in _codes(row, 'warning')
    assert 'running_offline' in _codes(row, 'blocked')


@pytest.mark.parametrize('forced', [False, True])
def test_the_start_route_uses_the_same_fractional_disk_mode(api, seed, no_cleanup_thread, forced):
    """The actual remote-migrate call agrees with the preflight's disk-size decision."""
    source, _ = _two(api, src_guests=[_guest(100, status='stopped')],
                     src_cfg={100: dict(CFG, scsi0='local-lvm:disk,size=0.5T')},
                     storages=[_store('far1', 'fast', free_gb=2000)])
    source.remote_migrate_vm = MagicMock(return_value={'success': True, 'task': 'UPID:pve1:1:qmigrate'})
    client = api.as_user(seed.user('root', role='admin'))
    response = _xrun(client, online=True, force_online=forced)
    assert response.status_code == 200, response.get_data(as_text=True)
    assert source.remote_migrate_vm.call_args.args[7] is forced
