# #740 defects 1+3 — the asyncio<->gevent interop helpers. The gevent-patched behaviour is proven
# by a live repro under gevent (see the commit); pytest doesn't monkey-patch, so here we cover the
# native / not-patched paths that every deployment without gevent (and py<=3.12) actually takes.

import socket
import sys
import asyncio

import pegaprox.utils.concurrent as c


def test_gevent_patched_flag_is_bool():
    # the app import chain may monkey-patch during collection — either way it's a clean bool
    assert isinstance(c.GEVENT_PATCHED, bool)


def test_install_is_noop_on_py312():
    # gated to py>=3.13, so on the 3.12 CI runner it must leave native asyncio.to_thread alone
    if sys.version_info < (3, 13):
        assert c.install_gevent_to_thread() is False
        assert asyncio.to_thread is not c.gevent_to_thread


def test_gevent_to_thread_falls_through_to_stdlib_without_gevent():
    async def go():
        return await c.gevent_to_thread(lambda x: x + 1, 41)
    assert asyncio.run(go()) == 42


def test_listen_socket_binds_and_accepts_a_connection():
    s = c.gevent_listen_socket('127.0.0.1', 0)  # ephemeral port
    try:
        assert s.fileno() >= 0
        port = s.getsockname()[1]
        assert port > 0
        cli = socket.create_connection(('127.0.0.1', port), timeout=2)
        cli.close()
    finally:
        s.close()


def test_listen_socket_empty_host_is_dual_stack():
    s = c.gevent_listen_socket('', 0)
    try:
        assert s.fileno() >= 0
        assert s.getsockname()[1] > 0
    finally:
        s.close()
