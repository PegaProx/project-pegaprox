"""A check_interval stored before the routes checked it does not end or spin the loop of an XCP-ng pool.

The wait took min(check_interval, 15) outside the loop's try: text or None raised there and the loop ended for
good, 0 or less made it spin. The balance timer compared against the same value and failed every round.
"""
import types
from unittest.mock import MagicMock, patch

import pytest

from pegaprox.core.xcpng import XcpngManager


def _loop(stored):
    waits, balanced = [], []
    m = XcpngManager.__new__(XcpngManager)
    m.logger = MagicMock()
    m._session, m.is_connected = object(), True
    m._refresh_cache = m._poll_tasks = lambda: None
    m._last_balance_check = 0
    m.run_balance_check = lambda: balanced.append(True)
    m.config = types.SimpleNamespace(name='p1', enabled=True, auto_migrate=True, check_interval=stored)
    m.stop_event = types.SimpleNamespace(is_set=lambda: bool(waits), wait=lambda seconds=None: waits.append(seconds))
    with patch('pegaprox.core.xcpng.ha') as ha:
        ha.is_active.return_value = True
        XcpngManager._run_loop(m)
    return waits, balanced


@pytest.mark.parametrize('stored', ['300', 'abc', None, 0, -5, True])
def test_one_stored_before_the_check_is_read_as_300(stored):
    waits, balanced = _loop(stored)
    assert waits == [15] and balanced == [True], (waits, balanced)
