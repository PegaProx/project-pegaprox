from unittest.mock import Mock, call, patch

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

    with patch('pegaprox.api.vms.time.sleep') as sleep:
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
