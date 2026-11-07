"""On XCP-ng a package check that failed is not an empty list.

SSH down or a repo error returned [], which a rolling update read as already up to date and skipped the node, so a scheduled run could end with 0 updated, N skipped and nothing checked.
"""
from unittest.mock import MagicMock

import pytest

from pegaprox.core.xcpng import XcpngManager


def _xcp(rc, out=''):
    x = XcpngManager.__new__(XcpngManager)
    x.logger = MagicMock()
    x._ssh_exec = lambda node, cmd, timeout=60: (rc, out, 'boom')
    return x


@pytest.mark.parametrize('rc', [1, -1, 255])
def test_a_failed_check_raises(rc):
    with pytest.raises(Exception, match='check-update'):
        _xcp(rc).get_node_apt_updates('n1')


def test_nothing_pending_is_still_an_empty_list():
    assert _xcp(0).get_node_apt_updates('n1') == []


def test_pending_updates_are_still_listed():
    got = _xcp(100, 'Loaded plugins\n\nkernel.x86_64  4.19  updates\n').get_node_apt_updates('n1')
    assert any('kernel' in str(p) for p in got), got


@pytest.mark.parametrize('err,says', [('SSH connection failed', 'SSH connection failed'), ('', 'no SSH answer'),
                                      ('Timeout opening channel.\n', 'Timeout opening channel.')])
def test_a_check_that_got_no_answer_says_why(err, says):
    x = XcpngManager.__new__(XcpngManager)
    x._ssh_exec = lambda node, cmd, timeout=60: (-1, '', err)
    with pytest.raises(Exception) as got:
        x.get_node_apt_updates('n1')
    assert str(got.value) == f'yum check-update on n1 failed ({says})'
