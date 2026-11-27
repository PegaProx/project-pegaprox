# #740 defects 1+3 - the asyncio<->gevent interop helpers. gevent_to_thread,
# install_gevent_to_thread and gevent_listen_socket served the asyncio console server on
# port+1 and went with it (the consoles are flask-sock routes of the main port now), so
# their tests went too. What is left of the module's gevent detection is covered here.

import pegaprox.utils.concurrent as c


def test_gevent_patched_flag_is_bool():
    # the app import chain may monkey-patch during collection - either way it's a clean bool
    assert isinstance(c.GEVENT_PATCHED, bool)
