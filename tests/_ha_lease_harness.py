"""The group harness of tests/test_ha_members.py, for automatic failover (#625 stage 2).

The same five instances in one process, each a state file of its own, and on top:
  * a lease clock per member (ha.ha_clock reads the clock of whichever instance is
    answering), turned by hand, with a freeze switch per member
  * a wall clock offset per member, for the skew the watch measures
  * directed cuts: `cuts` holds (from, to); a call the cut stops does not get there, an
    answer it stops is lost after the call ran
  * pause(n): calls to n get no answer and its loop does not run; its clock is frozen
    or runs on, as the test says
  * restart(n): the lease runtime of n is gone, and the boot check runs again
  * a driver instead of timers: step(n) is one pass of n's lease loop and delivers what
    its node queued; run(seconds) turns the clocks and steps every member

Nothing runs in the background: tests/conftest.py leaves every queued call in the queue,
and deliver() sends them one at a time through the real routes.

MK Oct 2026 (#625)
"""
import time

import pytest

from pegaprox.core import ha as _ha
from pegaprox.core import ha_vote as hv
from test_ha_api import ADMIN_PW
from test_ha_members import IDS, NAMES, _built, _fresh_windows, _sync, _watch

# taken before a test replaces it (tests/conftest.py)
_REAL_LEASE_START = _ha.lease_start

NAME_OF = {v: k for k, v in IDS.items()}
T = hv.Timings()
ZONE = 'Europe/Vienna'


class Auto:
    """A group under automatic failover, driven by hand."""

    def __init__(self, g, monkeypatch):
        self.g, self.ha = g, g.ha
        self.clock = {n: 5000.0 + 100 * i for i, n in enumerate(NAMES)}
        self.frozen, self.paused, self.cuts = set(), set(), set()
        self.skew = {}
        self.members = ''
        self.admin = None
        self.boots, self.pulls, self.killed = [], [], []
        self.auto_restart = True
        self._restarts_seen = 0
        ha = g.ha
        monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
        monkeypatch.setattr(ha, 'ha_clock', lambda: self.clock[g.name()])
        monkeypatch.setattr(ha, '_wall', lambda: time.time() + self.skew.get(g.name(), 0.0))
        monkeypatch.setattr(ha, '_peer_call', self._call)
        monkeypatch.setattr(ha, '_lease_sleep', self.advance)
        monkeypatch.setattr(ha, '_lease_wait', self._wait)
        monkeypatch.setattr(ha, '_watchdog_start', lambda rt: None)
        # the real one: it marks the loop as started and spawns nothing (conftest)
        monkeypatch.setattr(ha, 'lease_start', _REAL_LEASE_START)
        monkeypatch.setattr(ha, 'pull_soon', lambda: self.pulls.append(g.name()) or True)
        # the real one kills every child of this process, the test runner's included
        monkeypatch.setattr(ha, 'kill_children', lambda: self.killed.append(g.name()))
        # every instance here runs in one zone that can be told, so a group formed in a
        # test has a zone (one without is refused the switch; tests/conftest.py leaves
        # the zone of the machine out)
        monkeypatch.setattr(ha, '_local_zone', {'name': ZONE})

    # --- the network ---

    def _call(self, method, base_url, fingerprint, path, json_body=None, auth=None,
              headers=None, timeout=15, keep_alive=False):
        g, ha = self.g, self.ha
        me, to = g.name(), g.by_url[base_url.rstrip('/')]
        if to in self.paused:
            g.calls.append((me, to, method, path))
            raise ha.PeerNoAnswer('The peer took the call but sent no answer: ReadTimeout')
        if (me, to) in self.cuts:
            g.calls.append((me, to, method, path))
            raise ha.PeerUnreachable('Cannot reach the peer: ConnectTimeout')
        resp = g.call(method, base_url, fingerprint, path, json_body=json_body, auth=auth,
                      headers=headers, timeout=timeout)
        if (to, me) in self.cuts:
            raise ha.PeerNoAnswer('The peer took the call but sent no answer: ReadTimeout')
        return resp

    def cut(self, a, b, both=True):
        self.cuts.add((a, b))
        if both:
            self.cuts.add((b, a))

    def isolate(self, n):
        for other in self.members:
            if other != n:
                self.cut(n, other)

    def heal(self):
        self.cuts.clear()

    # --- clocks ---

    def advance(self, dt):
        for n in NAMES:
            if n not in self.frozen:
                self.clock[n] += dt

    def pause(self, n, freeze=False):
        self.paused.add(n)
        if freeze:
            self.frozen.add(n)

    def resume(self, n):
        self.paused.discard(n)
        self.frozen.discard(n)

    # --- the driver ---

    def rt(self, n):
        return self.ha._rts.get(IDS[n])

    def node(self, n):
        rt = self.rt(n)
        return rt.node if rt is not None else None

    def deliver(self, n, limit=400):
        """Send what n's node queued, one call at a time, and what the answers make it
        queue. Returns how many calls went out."""
        sent = 0
        with self.g.at(n) as ha:
            rt = ha._rts.get(IDS[n])
            while rt is not None and rt.outbox and sent < limit:
                ha._lease_deliver(rt, rt.outbox.popleft())
                sent += 1
        self._restart_what_left()
        return sent

    def drop(self, n):
        """Lose what n's node queued, as a network that takes the calls does."""
        rt = self.rt(n)
        lost = len(rt.outbox) if rt is not None else 0
        if rt is not None:
            rt.outbox.clear()
        return lost

    def _wait(self, done, seconds):
        # confirm_lease waits for its round: the lease loop sends it (rounds are at
        # least 100 ms apart) and the answers come back
        n, waited = self.g.name(), 0.0
        self.deliver(n)
        while not done.is_set() and waited < seconds:
            self.advance(0.1)
            waited += 0.1
            self.step(n)

    def step(self, n):
        """One pass of n's lease loop, and its calls delivered."""
        if n in self.paused or n in self.g.down:
            return None
        with self.g.at(n) as ha:
            wait = ha.lease_step()
        self.deliver(n)
        return wait

    def run(self, seconds, dt=0.5, members=None, until=None):
        """Turn the clocks by `seconds` in steps of `dt` and step every member after each.
        Stops early once until() holds; returns the time that passed."""
        passed = 0.0
        while passed < seconds:
            self.advance(dt)
            passed += dt
            for n in members or self.members:
                self.step(n)
            if until is not None and until():
                break
        return passed

    def _restart_what_left(self):
        g = self.g
        while self._restarts_seen < len(g.restarts):
            name, why = g.restarts[self._restarts_seen]
            self._restarts_seen += 1
            if self.auto_restart and str(why).startswith('automatic failover'):
                self.restart(name)

    def restart(self, n):
        """The process of n starts over: its lease runtime is gone, the boot check runs
        and the lease loop counts as started."""
        with self.g.at(n) as ha:
            ha._rts.pop(IDS[n], None)
            said = ha.check_peer_at_boot()
            self.boots.append((n, said))
            ha.lease_start()
        self._restart_what_left()
        return said

    def crash(self, n):
        """n is gone: no answers, no loop. back(n) starts it again."""
        self.g.down.add(n)

    def back(self, n):
        self.g.down.discard(n)
        return self.restart(n)

    # --- what the tests ask ---

    def at(self, n):
        return self.g.at(n)

    def mode(self, n):
        with self.g.at(n) as ha:
            return ha.mode()

    def active(self):
        """The names that may act right now."""
        out = []
        for n in self.members:
            with self.g.at(n) as ha:
                if ha.is_active():
                    out.append(n)
        return out

    def holders(self):
        out = []
        for n in self.members:
            with self.g.at(n) as ha:
                if ha.lease_in_force() and ha.holds_lease():
                    out.append(n)
        return out

    def leader(self):
        act = self.active()
        return act[0] if len(act) == 1 else None

    def state(self, n):
        return self.g.state(n)

    def file(self, n):
        return self.g.file(n)

    def put(self, n, path, body):
        import pegaprox.api.ha as ha_api
        _fresh_windows(ha_api)
        with self.g.at(n):
            return self.admin.put(path, json=body)

    def post(self, n, path, body=None):
        import pegaprox.api.ha as ha_api
        _fresh_windows(ha_api)
        with self.g.at(n):
            return self.admin.post(path, json=body)

    def watch(self, *names):
        for n in names or self.members:
            _watch(self.g, n)

    # --- forming the group ---

    def pair(self, seed, standbys='bc', sites=True):
        """a active with `standbys`, synced, and the watch of a has heard every member.
        With `sites` each instance runs at a site of its own (dc-a, dc-b, ...): a group
        that names none wants NO_SITE_LABELS ticked at the switch."""
        self.admin = _built(self.g, seed, standbys, sync=False)
        self.members = 'a' + standbys
        if sites:
            with self.g.at('a') as ha:
                for n in self.members:
                    ha.set_member_site(IDS[n], f'dc-{n}')
        for n in standbys:
            assert _sync(self.g, self.admin, n) == 'applied'
        self.watch('a')
        return self.admin

    def switch_on(self, lease_s=20, accept=None, settle=True):
        body = {'mode': 'auto', 'lease_s': lease_s, 'user_password': ADMIN_PW}
        if accept is not None:
            body['accept'] = accept
        r = self.put('a', '/api/ha/mode', body)
        if r.status_code == 200 and settle:
            for _ in range(8):
                self.step('a')
                if all(self.mode(n) == 'auto' for n in self.members):
                    break
            # one renewal round, so the lease of the new leader stands
            self.step('a')
        return r

    def form(self, seed, standbys='bc', lease_s=20, accept=None):
        """An automatic group: a leads with a lease, `standbys` follow."""
        self.pair(seed, standbys)
        r = self.switch_on(lease_s, accept)
        assert r.status_code == 200, r.data
        assert all(self.mode(n) == 'auto' for n in self.members), \
            {n: self.mode(n) for n in self.members}
        assert self.leader() == 'a'
        return self.admin

    def past_the_hold(self):
        """Let the hold after a start pass on every member (rule 5)."""
        self.run(T.hold_after_start + 1, dt=2.0)


@pytest.fixture
def auto(group, monkeypatch):
    return Auto(group, monkeypatch)
