"""A second process on the syslog UDP port fails to bind instead of silently taking the
datagrams (no SO_REUSEADDR on the UDP socket).

MK Oct 2026
"""
import socket
import threading

import pegaprox.background.syslog_server as S


def test_a_second_listener_on_the_udp_port_does_not_bind(monkeypatch):
    first = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    first.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    first.bind(('127.0.0.1', 0))
    port = first.getsockname()[1]
    monkeypatch.setattr(S, '_udp_sock', None)
    t = threading.Thread(target=S._udp_listener, args=('127.0.0.1', port), daemon=True)
    try:
        t.start()
        t.join(timeout=2)
        bound = S._udp_sock
        assert bound is None and not t.is_alive()
    finally:
        first.close()
        if S._udp_sock is not None:
            S._udp_sock.close()
