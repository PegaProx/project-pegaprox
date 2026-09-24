"""Every phase before the application sees the request has to be bounded.

A pool slot is taken the moment a connection is accepted and returned when the handler
finishes. Anything a client can make take forever in between is a way to hold slots, and
`workers` of them is the whole server - no login, no valid certificate, just open a socket
and stop.

read_requestline was the only bounded phase. The two either side of it were not:

  * the TLS handshake. `wrap_socket_and_handle` already runs inside the spawned greenlet,
    so a connection that opens and never finishes its handshake sits there. Verified
    end-to-end against a real instance: 60 half-open handshakes against 16 slots and an
    ordinary request times out; with the timeout in place the same request is answered.
  * the headers after the request line. `GET / HTTP/1.1` arrives promptly, and everything
    after it was unbounded, so dribbling headers one every 500ms held a slot indefinitely.

The handshake bound is a SOCKET timeout rather than a gevent.Timeout around the call,
because with an stdlib SSLContext the handshake can be deferred to the first read - which
happens in the handler, outside any timer started here. handle() clears it immediately
afterwards so keep-alive and hour-long console sockets are unaffected.

Aikido ai_pentest 700489641 / 700489304. MK
"""
import inspect

import pytest

import pegaprox.app as app


def test_the_three_phases_all_have_a_bound():
    assert app._KEEPALIVE_IDLE_TIMEOUT > 0      # request line on an idle connection
    assert app._HANDSHAKE_TIMEOUT > 0           # TLS
    assert app._HEADER_TIMEOUT > 0              # headers after the request line


@pytest.mark.parametrize('var,attr', [
    ('PEGAPROX_HANDSHAKE_TIMEOUT', '_HANDSHAKE_TIMEOUT'),
    ('PEGAPROX_HEADER_TIMEOUT', '_HEADER_TIMEOUT'),
])
def test_each_bound_is_operator_overridable(var, attr):
    """An operator on a genuinely awful link has to be able to raise these."""
    src = inspect.getsource(app)
    i = src.index(f'{attr} = ')
    assert var in src[i:i + 200]


def test_the_header_phase_is_bounded_in_the_mixin():
    assert hasattr(app._IdleTimeoutMixin, 'read_request')
    src = inspect.getsource(app._IdleTimeoutMixin.read_request)
    assert 'Timeout' in src
    assert '_header_timeout' in src


def test_a_disabled_header_bound_falls_through_to_the_old_behaviour():
    """Setting it to 0 has to restore exactly what was there before."""
    src = inspect.getsource(app._IdleTimeoutMixin.read_request)
    assert 'if not to or to <= 0:' in src
    assert 'return super().read_request(raw_requestline)' in src


def test_the_header_timeout_answers_rather_than_raising():
    """pywsgi turns a falsy return into a clean 400 and closes; an exception escaping
    here would surface as a traceback in the log for every slow client."""
    src = inspect.getsource(app._IdleTimeoutMixin.read_request)
    assert 'return False' in src


def test_the_request_line_bound_is_untouched():
    """The pre-existing #777 behaviour must survive this."""
    src = inspect.getsource(app._IdleTimeoutMixin.read_requestline)
    assert "return b''" in src
    assert '_idle_timeout' in src
