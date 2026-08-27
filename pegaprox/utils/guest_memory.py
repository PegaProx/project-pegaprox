"""Guest-memory helpers shared by inventory and VM detail APIs."""

import time


def parse_linux_meminfo(content):
    """Return Linux guest pressure using the kernel's MemAvailable estimate."""
    values = {}
    for line in (content or '').splitlines():
        if ':' not in line:
            continue
        key, raw = line.split(':', 1)
        parts = raw.strip().split()
        if not parts or not parts[0].isdigit():
            continue
        multiplier = 1024 if len(parts) > 1 and parts[1].lower() == 'kb' else 1
        values[key] = int(parts[0]) * multiplier

    total = values.get('MemTotal')
    available = values.get('MemAvailable')
    if not total or available is None:
        return None
    available = max(0, min(available, total))
    used = total - available
    return {
        'total_bytes': total,
        'used_bytes': used,
        'available_bytes': available,
        'used_pct': round((used / total) * 100, 1),
        'source': 'qemu-guest-agent:/proc/meminfo:MemAvailable',
    }


def get_guest_linux_memory(manager, base):
    """Read /proc/meminfo through PVE's bounded guest-exec API."""
    started = manager._api_post(
        f"{base}/exec",
        data=[('command', '/usr/bin/cat'), ('command', '/proc/meminfo')],
        timeout=8,
    )
    if started.status_code != 200:
        return None
    pid = (started.json().get('data') or {}).get('pid')
    if pid is None:
        return None

    for _ in range(10):
        status = manager._api_get(f"{base}/exec-status", params={'pid': pid}, timeout=8)
        if status.status_code != 200:
            return None
        payload = status.json().get('data') or {}
        if payload.get('exited'):
            if payload.get('exitcode') != 0:
                return None
            return parse_linux_meminfo(payload.get('out-data') or '')
        time.sleep(0.05)
    return None
