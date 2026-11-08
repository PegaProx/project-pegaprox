# -*- coding: utf-8 -*-
"""A sliding-window counter that cannot be grown without bound by the thing it limits.

Seven of these existed in the tree, written out longhand each time, and they shared two
problems.

The first is the obvious one: the map is keyed by something the caller chooses - a
remote IP, a username, an (ip, cluster) pair - and entries were only ever added. An
IPv6 /64 costs nothing, so a rotating source grows the map until the process dies. The
limiter meant to protect the service was the way to take it down.

The second is subtler and is what makes a naive fix useless. app.py grew a sweep that
ran whenever the map passed a threshold, and it removed only EXPIRED windows. An
attacker who keeps the map just above the threshold with LIVE windows gets a full scan
on every single request and nothing freed - O(n) per request, with n still climbing.
So the sweep here is on a clock, not on a size trigger, and when the ceiling is still
breached afterwards the oldest entries go regardless of whether they have expired.

MK Sep 2026
"""

import threading
import time


class SlidingWindow:
    """`limit` events per `window` seconds per key, with a hard ceiling on keys.

    allow(key) -> True when the event is within budget, False when it is not.
    """

    def __init__(self, limit, window, max_keys=4096, name=''):
        self.limit = int(limit)
        self.window = float(window)
        self.max_keys = int(max_keys)
        self.name = name
        self._hits = {}                 # key -> [timestamps]
        self._lock = threading.Lock()
        self._last_sweep = 0.0

    # -- internals ------------------------------------------------------------
    def _sweep(self, now):
        """Drop expired keys, then the oldest ones if we are still over the ceiling."""
        cutoff = now - self.window
        for key in [k for k, ts in self._hits.items() if not ts or ts[-1] < cutoff]:
            self._hits.pop(key, None)
        if len(self._hits) > self.max_keys:
            # over the ceiling with live windows: somebody is rotating keys at us. Drop
            # the least recently seen - they are the ones least likely to be a real user
            # mid-burst, and an evicted key simply starts its window again.
            victims = sorted(self._hits.items(), key=lambda kv: kv[1][-1])
            for key, _ in victims[:len(self._hits) - self.max_keys]:
                self._hits.pop(key, None)
        self._last_sweep = now

    # -- api ------------------------------------------------------------------
    def allow(self, key):
        now = time.time()
        cutoff = now - self.window
        with self._lock:
            # on a clock, not on a size trigger: a size trigger with nothing expired is
            # a full scan per request and frees nothing
            if now - self._last_sweep >= self.window:
                self._sweep(now)
            ts = [t for t in self._hits.get(key, ()) if t > cutoff]
            if len(ts) >= self.limit:
                self._hits[key] = ts
                return False
            ts.append(now)
            self._hits[key] = ts
            # a brand-new key while we are already at the ceiling must not extend it;
            # the clock sweep may be up to `window` away
            if len(self._hits) > self.max_keys:
                self._sweep(now)
            return True

    def reset(self, key=None):
        """Forget one key, or all of them. Used by the unlock endpoints and by tests."""
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)

    def __len__(self):
        with self._lock:
            return len(self._hits)
