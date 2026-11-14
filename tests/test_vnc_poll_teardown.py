"""A poll console that PVE ends first still gives back its SSH forward and its PVE socket.

The pump marks the session closed when the PVE side goes away (guest shutdown, reboot, a
reset connection). stop() used that same flag to tell whether it had already run, so the
browser's action=close and the reaper both found the session "stopped" and returned before
closing pve_ws or the tunnel endpoint. With vnc_tunnel on, every such console kept a bound
local port, its listener and the accept loop waiting on it, for the life of the process.
"""
import socket

import gevent

from pegaprox.utils import vnc_polling as poll
from pegaprox.utils import vnc_tunnel


class _PveGone:
    """pve_ws whose PVE side has ended: recv raises, the way a reset connection does."""

    def __init__(self):
        self.closed = 0

    def settimeout(self, _t):
        pass

    def recv(self):
        raise ConnectionResetError(104, 'Connection reset by peer')

    def close(self):
        self.closed += 1


def _endpoint():
    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.bind(('127.0.0.1', 0))
    lst.listen(8)
    ep = vnc_tunnel.TunnelEndpoint(lst, transport=object(), target_host='127.0.0.1',
                                   target_port=8006, cluster_id='c1', pve_host='pve1')
    return ep, lst


def _wait(cond, seconds=2.0):
    for _ in range(int(seconds / 0.01)):
        if cond():
            return True
        gevent.sleep(0.01)
    return cond()


def _torn_down(ep, lst, ws):
    _wait(lambda: not ep._accept_thread.is_alive())
    return {'pve_ws_closed': ws.closed, 'endpoint_stopped': ep._stopped,
            'listener_fd': lst.fileno(), 'accept_loop_alive': ep._accept_thread.is_alive()}


TORN_DOWN = {'pve_ws_closed': 1, 'endpoint_stopped': True, 'listener_fd': -1,
             'accept_loop_alive': False}


def test_close_after_pve_ended_releases_the_forward_and_the_pve_socket():
    ep, lst = _endpoint()
    ws = _PveGone()
    s = poll.VncPollSession(poll.new_poll_id(), ws, ep, None, 'c1', 'qemu', 100, 'pve1')
    poll._pool[s.poll_id] = s        # what register() does, without starting the reaper
    try:
        assert _wait(lambda: s.closed), 'the pump did not notice the PVE side going away'
        poll.drop(s.poll_id)         # the browser's action=close
        assert _torn_down(ep, lst, ws) == TORN_DOWN
        s.stop()                     # and the reaper after it: nothing runs twice
        assert ws.closed == 1
    finally:
        poll._pool.pop(s.poll_id, None)
        ep.stop()


def test_the_reaper_releases_a_session_that_pve_ended():
    """The browser may never send action=close (tab gone). The reaper calls the same stop()."""
    ep, lst = _endpoint()
    ws = _PveGone()
    s = poll.VncPollSession(poll.new_poll_id(), ws, ep, None, 'c1', 'qemu', 100, 'pve1')
    try:
        assert _wait(lambda: s.closed)
        s.stop()
        assert _torn_down(ep, lst, ws) == TORN_DOWN
    finally:
        ep.stop()
