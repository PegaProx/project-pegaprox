"""Self-service creation is the one route a customer can call in a loop.

The quota was checked and the container was created as two separate steps. Usage is
computed from what exists, so two requests arriving together both measured the world
before either had created anything, both passed, and both went on to create.

Which of these is the counter-proof: only the third. The first two exercise the new lock
helper by name, so against the old code they die with an AttributeError, which says
nothing about the race. The third reads the handler and shows the check and the create
sitting outside any lock - that is the defect stated.

MK
"""
import threading

import pytest


def test_creation_is_serialised_per_tenant():
    """The lock has to be the SAME object for the same tenant and a DIFFERENT one for
    another - that is the whole mechanism."""
    import plugins.client_portal as P

    a1 = P._tenant_create_lock('acme')
    a2 = P._tenant_create_lock('acme')
    b1 = P._tenant_create_lock('other')

    assert a1 is a2, 'two requests from one tenant would not wait on each other'
    assert a1 is not b1, 'one tenant creating would block every other tenant'


def test_the_lock_actually_excludes():
    import plugins.client_portal as P

    lk = P._tenant_create_lock('acme2')
    order = []

    def _second():
        with lk:
            order.append('second')

    with lk:
        t = threading.Thread(target=_second)
        t.start()
        t.join(timeout=0.3)
        order.append('first')
    t.join(timeout=1)

    assert order == ['first', 'second'], f'the lock did not exclude: {order}'


def test_the_check_and_the_create_are_inside_it():
    """Source-level, because driving two concurrent LXC creations needs a cluster. The
    point is that no work happens between the measurement and the allocation."""
    import inspect
    import plugins.client_portal as P

    body = inspect.getsource(P._create_ct)
    stripped = '\n'.join(l for l in body.split('\n') if not l.strip().startswith('#'))

    assert '_tenant_create_lock(' in stripped, 'creation is not serialised at all'
    i_lock = stripped.index('_tenant_create_lock(')
    i_check = stripped.index('check_tenant_quota(')
    i_create = stripped.index('create_container(')
    assert i_lock < i_check < i_create, \
        'the quota check or the create sits outside the lock that is meant to cover both'
