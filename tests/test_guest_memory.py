import threading
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from pegaprox.core.manager import PegaProxManager
from pegaprox.api.vms import _get_guest_linux_memory, _parse_linux_meminfo


def _response(status_code, data):
    response = Mock(status_code=status_code)
    response.json.return_value = {'data': data}
    return response


def test_parse_linux_meminfo_uses_available_not_free():
    result = _parse_linux_meminfo(
        "MemTotal:        8192000 kB\n"
        "MemFree:          400000 kB\n"
        "MemAvailable:    6400000 kB\n"
        "Cached:          5800000 kB\n"
    )

    assert result == {
        'total_bytes': 8192000 * 1024,
        'used_bytes': (8192000 - 6400000) * 1024,
        'available_bytes': 6400000 * 1024,
        'used_pct': 21.9,
        'source': 'qemu-guest-agent:/proc/meminfo:MemAvailable',
    }


def test_parse_linux_meminfo_requires_total_and_available():
    assert _parse_linux_meminfo("MemTotal: 1024 kB\nMemFree: 512 kB\n") is None


def test_parse_linux_meminfo_clamps_inconsistent_available_value():
    result = _parse_linux_meminfo("MemTotal: 1024 kB\nMemAvailable: 2048 kB\n")
    assert result['available_bytes'] == result['total_bytes']
    assert result['used_bytes'] == 0
    assert result['used_pct'] == 0.0


def test_get_guest_linux_memory_uses_bounded_exec_and_polls_to_exit():
    manager = Mock()
    manager._api_post.return_value = _response(200, {'pid': 42})
    manager._api_get.side_effect = [
        _response(200, {'exited': 0}),
        _response(200, {
            'exited': 1,
            'exitcode': 0,
            'out-data': 'MemTotal: 4096 kB\nMemAvailable: 3072 kB\n',
        }),
    ]

    with patch('pegaprox.utils.guest_memory.time.sleep') as sleep:
        result = _get_guest_linux_memory(manager, 'https://pve/api/agent')

    assert result['used_pct'] == 25.0
    manager._api_post.assert_called_once_with(
        'https://pve/api/agent/exec',
        data=[('command', '/usr/bin/cat'), ('command', '/proc/meminfo')],
        timeout=8,
    )
    assert manager._api_get.call_args_list == [
        call('https://pve/api/agent/exec-status', params={'pid': 42}, timeout=8),
        call('https://pve/api/agent/exec-status', params={'pid': 42}, timeout=8),
    ]
    sleep.assert_called_once_with(0.05)


def test_get_guest_linux_memory_returns_none_on_agent_failure():
    manager = Mock()
    manager._api_post.return_value = _response(500, None)
    assert _get_guest_linux_memory(manager, 'https://pve/api/agent') is None
    manager._api_get.assert_not_called()


def _manager_with_memory_cache(cache):
    manager = object.__new__(PegaProxManager)
    manager._memory_cache = cache
    manager._memory_cache_lock = threading.Lock()
    return manager


def test_inventory_uses_cached_guest_pressure_and_preserves_host_accounting():
    manager = _manager_with_memory_cache({
        ('pve', 179): {
            'total_bytes': 64 * 1024**3,
            'used_bytes': 10 * 1024**3,
            'available_bytes': 54 * 1024**3,
            'used_pct': 15.6,
            'source': 'qemu-guest-agent:/proc/meminfo:MemAvailable',
        }
    })
    resources = [{
        'type': 'qemu', 'node': 'pve', 'vmid': 179, 'status': 'running',
        'mem': 65 * 1024**3, 'maxmem': 64 * 1024**3, 'mem_percent': 101.6,
    }]

    manager._inject_guest_memory(resources)

    assert resources[0]['guest_mem_percent'] == 15.6
    assert resources[0]['guest_memory_status'] == 'available'
    assert resources[0]['host_mem_percent'] == 101.6
    assert resources[0]['host_mem'] == 65 * 1024**3


def test_inventory_does_not_substitute_host_ram_when_guest_data_unavailable():
    manager = _manager_with_memory_cache({})
    resources = [{
        'type': 'qemu', 'node': 'pve', 'vmid': 150, 'status': 'running',
        'mem': 7 * 1024**3, 'maxmem': 8 * 1024**3, 'mem_percent': 87.5,
    }]

    manager._inject_guest_memory(resources)

    assert resources[0]['guest_mem_percent'] is None
    assert resources[0]['guest_memory_status'] == 'unavailable'
    assert resources[0]['host_mem_percent'] == 87.5


def test_lxc_cgroup_memory_is_valid_guest_pressure_and_is_bounded():
    manager = _manager_with_memory_cache({})
    resources = [{
        'type': 'lxc', 'node': 'pve', 'vmid': 9000, 'status': 'running',
        'mem': 1100, 'maxmem': 1000, 'mem_percent': 110.0,
    }]

    manager._inject_guest_memory(resources)

    assert resources[0]['guest_mem_percent'] == 100.0
    assert resources[0]['guest_memory_status'] == 'available'
    assert resources[0]['guest_memory_source'] == 'proxmox-lxc-cgroup'


def test_freshly_booted_vm_forces_memory_probe_past_no_agent_cache():
    manager = _manager_with_memory_cache({})
    manager._no_agent_vms = {200}
    manager.current_host = None
    manager.config = SimpleNamespace(host='pve', api_port=8006)
    manager._api_post = Mock(return_value=_response(200, {'pid': 7}))
    manager._api_get = Mock(return_value=_response(200, {
        'exited': 1,
        'exitcode': 0,
        'out-data': 'MemTotal: 1000 kB\nMemAvailable: 900 kB\n',
    }))

    result = manager._fetch_qemu_memory('pve', 200, force=True)

    assert result['used_pct'] == 10.0
    assert 200 not in manager._no_agent_vms
