"""Linked mode: the live updates of another site's clusters.

A browser's SSE stream here may ask for remote ids (<raw>~<iid>) next to its own clusters.
For each site among them this instance keeps one feed per stream: a signed request to the
site's RELAY_STREAM_PATH, answered with a stream of that site's own SSE frames for the
user. The site registers it as an SSE client of its own for the mirror of the account, so
its broadcast filters every frame per guest, node and role exactly as for a browser there,
and re-checks the account every half minute. Each frame comes signed over the request's
nonce and a running number; this instance checks both, keeps the frame types a cluster view
reads, writes the remote id into it and puts it into the browser's stream.

A feed that breaks is opened again after a pause; the browser's polls keep the view going
in between. It ends with the browser's stream, with the federation switch and with the
site's membership.

MK Nov 2026
"""
import base64
import hashlib
import json
import logging
import queue as queue_module
import threading
import time
import uuid

from pegaprox.core import federation as fed
from pegaprox.core import federation_relay as relay
from pegaprox.core import ha_wire

STREAM_DOMAIN = 'pegaprox-fed-stream-1'
# what the envelope of a stream names: not a route, the stream has its own path
STREAM_RULE = '/api/federation/linked/stream'
# the frame types of a cluster view; anything else (another site's global events) stays there
FORWARD_TYPES = frozenset({'tasks', 'metrics', 'resources', 'vm_config', 'action', 'node_status',
                           'ha_status', 'vm_update', 'task_update', 'migration', 'maintenance',
                           'ha_event', 'alert'})
MAX_CLUSTERS = 64
MAX_LINE = 8 * 1024 * 1024
KEEPALIVE = 15
READ_TIMEOUT = 45
RECHECK = 30
RETRY_FIRST, RETRY_MAX = 5, 120
FEEDS_PER_USER = 8
# of which to one site: the browser streams of one account beyond that poll
FEEDS_PER_USER_AND_SITE = 2

_P = relay._P
_streams_out = relay._Budget(max(4, _P // 4), max(4, _P // 8))
_streams_in = relay._Budget(max(4, _P // 4), max(4, _P // 8))
_feeds = {}           # browser stream id -> {site iid: Feed}
_feeds_lock = threading.Lock()


def _frame_message(nonce, rid, seq, frame):
    return '\n'.join((STREAM_DOMAIN, nonce, rid, str(seq),
                      hashlib.sha256(frame.encode()).hexdigest())).encode()


def signed_line(nonce, rid, seq, frame):
    sig = fed.signing_key().sign(_frame_message(nonce, rid, seq, frame))
    return f'{seq} {base64.b64encode(sig).decode()} {frame}\n'


def bounded_lines(chunks, limit=None):
    """The lines of a byte stream, none longer than `limit` (MAX_LINE): a line that grows past
    it ends the stream with ValueError rather than being held whole in memory."""
    limit = MAX_LINE if limit is None else limit
    buf = bytearray()
    for chunk in chunks:
        if not chunk:
            continue
        start = len(buf)
        buf += chunk
        # only the new bytes are searched, and a line is cut out once
        cut = buf.find(b'\n', start)
        while cut >= 0:
            line = bytes(buf[:cut])
            del buf[:cut + 1]
            if len(line) > limit:
                raise ValueError('a frame over the size limit')
            yield line
            cut = buf.find(b'\n')
        if len(buf) > limit:
            raise ValueError('a frame over the size limit')
    if buf:
        yield bytes(buf)


def reset_for_tests():
    with _feeds_lock:
        feeds = [f for by_site in _feeds.values() for f in by_site.values()]
        _feeds.clear()
    for f in feeds:
        f.stop()
    for b in (_streams_out, _streams_in):
        with b._lock:
            b._used, b._per = 0, {}


# --- the site the browser works at ---------------------------------------------------------------

def split_wanted(ids):
    """(this instance's ids, the remote ids) of what a browser's stream asks for. With the
    federation off every id stays where it was, and a '~' id is an unknown cluster."""
    if not ids or not fed.enabled():
        return ids, []
    local, me, remote = relay._local_ids(), fed.instance_id(), []
    for c in ids:
        got = relay.split_remote(c) if c not in local else None
        if got and got[1] != me:
            remote.append(c)
    return [c for c in ids if c not in remote], remote


def watch(client_id, remote_ids, principal):
    """Keep feeds for the remote ids the browser's stream `client_id` asks for: one per
    site, opened again when its set of clusters changes, closed for a site it no longer
    asks for. `principal` as the relay takes it."""
    wanted = {}
    for c in remote_ids or ():
        got = relay.split_remote(c)
        if got and fed.member_record(got[1]) is not None:
            raws = wanted.setdefault(got[1], set())
            if len(raws) < MAX_CLUSTERS:
                raws.add(got[0])
    stop, start = [], []
    with _feeds_lock:
        mine = _feeds.setdefault(client_id, {})
        for iid in list(mine):
            if wanted.get(iid) != mine[iid].raws:
                stop.append(mine.pop(iid))
        theirs = [f for k, v in _feeds.items() if k != client_id for f in v.values()
                  if f.principal.get('user') == principal.get('user')]
        held = len(theirs)
        for iid, raws in sorted(wanted.items()):
            if iid in mine:
                continue
            if held + len(mine) >= FEEDS_PER_USER or \
                    sum(1 for f in theirs if f.iid == iid) >= FEEDS_PER_USER_AND_SITE:
                logging.info(f"[FED] no live feed of site {iid[:8]} for "
                             f"{principal.get('user')!r}: {FEEDS_PER_USER} open already")
                continue
            mine[iid] = Feed(client_id, iid, raws, principal)
            start.append(mine[iid])
        if not mine:
            _feeds.pop(client_id, None)
    for f in stop:
        f.stop()
    for f in start:
        f.start()


def principal_for(user, sid, token_id, token_role, ip):
    """The relay principal of a browser's stream, or None for one that gets no feeds: an
    account another site homes, an API token with a custom role."""
    from pegaprox.core.db import get_db
    try:
        row = get_db().conn.execute('SELECT fed_home FROM users WHERE username = ?',
                                    (user,)).fetchone()
    except Exception:
        return None
    if row is None:
        return None
    if row['fed_home'] or '':
        # signed in here through its home, or no feed
        if token_id is not None or not sid:
            return None
        from pegaprox.core import federation_signin
        got = federation_signin.principal(sid, user, ip)
        return dict(got, _sid=sid) if got else None
    principal = {'user': user, 'home': fed.instance_id(), 'ip': ip or ''}
    if token_id is not None:
        if token_role not in relay.TOKEN_ROLES:
            return None
        principal.update(sh=relay.session_handle(f'token:{token_id}'), tok=token_role)
    else:
        principal['sh'] = relay.session_handle(sid or '')
    return principal


def unwatch(client_id):
    with _feeds_lock:
        mine = _feeds.pop(client_id, {})
    for f in mine.values():
        f.stop()


def _client_queue(client_id):
    from pegaprox.utils.realtime import sse_clients, sse_clients_lock
    with sse_clients_lock:
        client = sse_clients.get(client_id)
    return client.get('queue') if client else None


class Feed:
    """One site's frames for one browser stream."""

    def __init__(self, client_id, iid, raws, principal):
        self.client_id, self.iid, self.raws = client_id, iid, frozenset(raws)
        principal = dict(principal)
        # the session behind an assertion, never sent anywhere
        self.sid = principal.pop('_sid', None)
        self.principal = principal
        self.stopped = False
        self.dropped = 0
        # the close of the connection under way: a feed stopped gives its slot back now, not
        # when the site's next line comes (a selection switched to and fro held them all)
        self._close = None

    def stop(self):
        self.stopped = True
        close = self._close
        if close is not None:
            try:
                close()
            except Exception:
                pass

    def start(self):
        threading.Thread(target=self.run, daemon=True, name='federation-feed').start()

    def alive(self):
        return (not self.stopped and fed.enabled() and fed.member_record(self.iid) is not None
                and _client_queue(self.client_id) is not None)

    def run(self):
        pause = RETRY_FIRST
        while self.alive():
            got = self.once()
            if not self.alive():
                break
            pause = RETRY_FIRST if got else min(RETRY_MAX, pause * 2)
            time.sleep(pause)
        with _feeds_lock:
            mine = _feeds.get(self.client_id) or {}
            if mine.get(self.iid) is self:
                mine.pop(self.iid, None)
                if not mine:
                    _feeds.pop(self.client_id, None)

    def once(self):
        """One connection to the site: True when frames came through it."""
        rec = fed.member_record(self.iid)
        if not rec or not rec.get('url') or relay._broken(self.iid):
            return False
        if not _streams_out.take(self.iid):
            return False
        lines, close = None, None
        try:
            if self.principal.get('asr'):
                # an assertion runs out every few minutes: renewed for each connection
                from pegaprox.core import federation_signin
                fresh = federation_signin.principal(self.sid, self.principal['user'],
                                                    self.principal.get('ip'))
                if fresh is None:
                    self.stopped = True
                    return False
                self.principal = fresh
            query = 'clusters=' + ','.join(sorted(self.raws))
            signed = relay.signed_request(self.iid, 'GET', STREAM_RULE, query, relay._sha(b''),
                                          '', self.principal, relay.RELAY_STREAM_PATH)
            if signed is None:
                return False
            headers, nonce, rid = signed
            hook = fed._runtime.get('stream')
            if hook is not None:
                status, lines, close = hook(rec['url'], relay.RELAY_STREAM_PATH, headers)
            else:
                status, resp = fed._wire_stream(rec['url'], rec.get('fingerprints') or [],
                                                relay.RELAY_STREAM_PATH, headers, READ_TIMEOUT)
                if resp is not None:
                    lines, close = bounded_lines(resp.iter_content(chunk_size=65536)), resp.close
            if status != 200 or lines is None:
                return False
            self._close = close
            if self.stopped:
                return False
            return self.read(lines, nonce, rid, ha_wire.public_key(rec.get('public_key') or ''))
        except Exception as e:
            logging.info(f'[FED] live feed of site {self.iid[:8]} broke off: {type(e).__name__}')
            return False
        finally:
            self._close = None
            if close is not None:
                try:
                    close()
                except Exception:
                    pass
            _streams_out.give(self.iid)

    def read(self, lines, nonce, rid, key):
        """Check and pass on the frames of one connection, in order, until it ends or this
        feed is no longer wanted. True when at least the opening frame was good."""
        from cryptography.exceptions import InvalidSignature
        if key is None:
            return False
        expect, good = 0, False
        for line in lines:
            if not self.alive():
                break
            if isinstance(line, bytes):
                line = line.decode('utf-8', 'replace')
            line = line.rstrip('\r\n')
            if not line or len(line) > MAX_LINE:
                if line:
                    return good
                continue
            try:
                seq_text, sig, frame = line.split(' ', 2)
                if int(seq_text) != expect:
                    raise ValueError('out of order')
                key.verify(base64.b64decode(sig), _frame_message(nonce, rid, expect, frame))
                obj = json.loads(frame)
            except (ValueError, InvalidSignature, TypeError):
                logging.warning(f'[FED] live feed of site {self.iid[:8]}: a frame without a good '
                                'signature or out of order - closed')
                return good
            expect += 1
            if expect == 1:
                good = isinstance(obj, dict) and obj.get('type') == 'fed_stream'
                if not good:
                    return False
                continue
            self.deliver(obj)
        return good

    def deliver(self, obj):
        if not isinstance(obj, dict) or obj.get('type') not in FORWARD_TYPES:
            return
        raw = obj.get('cluster_id')
        if raw not in self.raws:
            return
        obj['cluster_id'] = relay.remote_id(raw, self.iid)
        frame = json.dumps(obj, default=str)
        from pegaprox.utils.realtime import _MAX_BROADCAST_BYTES
        if len(frame) > _MAX_BROADCAST_BYTES:
            # what a stream of this site would not carry either
            return
        q = _client_queue(self.client_id)
        if q is None:
            self.stopped = True
            return
        try:
            q.put_nowait(frame)
        except queue_module.Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                logging.warning(f'[FED] live feed of site {self.iid[:8]}: the browser stream is '
                                f'full - {self.dropped} frames dropped')


# --- the site that leads the clusters --------------------------------------------------------------

class StreamRefused(Exception):
    def __init__(self, status, code, error):
        super().__init__(error)
        self.status, self.code, self.error = status, code, error


def wanted_clusters(query):
    from urllib.parse import parse_qs
    got = (parse_qs(query or '').get('clusters') or [''])[0]
    raws = [c for c in got.split(',') if c]
    if not raws or len(raws) > MAX_CLUSTERS or not all(fed.CLUSTER_ID_RE.fullmatch(c) for c in raws):
        raise StreamRefused(400, 'FED_STREAM_CLUSTERS', 'A stream names 1 to 64 clusters')
    return list(dict.fromkeys(raws))


def _scope(username, tok, raws):
    """(identity, effective role, admin, the clusters of `raws` that stream to the account),
    as the SSE route of this instance decides it for a browser."""
    from pegaprox.api.realtime import _floor_by_token_role, _stream_identity
    from pegaprox.utils.rbac import acts_as_admin, get_user_clusters
    ident = _stream_identity(username)
    if ident is None:
        return None, None, False, []
    floored = _floor_by_token_role(dict(ident), tok) if tok else ident
    eff = floored.get('effective_role') or floored.get('role')
    try:
        allowed = get_user_clusters(floored)
    except Exception as e:
        logging.error(f'[FED] the cluster scope of {username!r} could not be read: {e}')
        allowed = []
    local = relay._local_ids()
    scope = [r for r in raws if r in local and (allowed is None or r in allowed)]
    admin = acts_as_admin(floored) and tok in (None, 'admin')
    return ident, eff, admin, scope


def leading_stream(sender, call, row, nonce, rid):
    """The answer body of a member's stream request for the mirror `row`: a generator of
    signed lines. Raises StreamRefused before anything is registered."""
    from pegaprox.api.realtime import _supersede_oldest_streams
    from pegaprox.utils.realtime import sse_clients, sse_clients_lock
    raws = wanted_clusters(call['query'])
    username, tok = row['username'], call.get('tok')
    ident, eff, admin, scope = _scope(username, tok, raws)
    if ident is None or not scope:
        raise StreamRefused(403, 'FED_STREAM_SCOPE', 'None of these clusters streams to you here')
    if not _streams_in.take(sender):
        raise StreamRefused(429, 'FED_RELAY_BUSY', 'Too many live feeds from your site at once')
    client_id = f'fed-{uuid.uuid4()}'
    q = queue_module.Queue(maxsize=200)
    # the session at home it streams for: only that one's feeds are superseded for it
    sid = f"fed:{call.get('home') or ''}:{call.get('sh') or ''}"
    with sse_clients_lock:
        _supersede_oldest_streams(username, sid)
        sse_clients[client_id] = {
            'queue': q, 'user': username, 'clusters': list(scope), 'is_admin': admin,
            'effective_role': eff, 'connected_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'auth_method': 'federation', 'sid': sid, 'fed_stream': sender,
        }
    logging.info(f'[FED] live feed of {len(scope)} cluster(s) for {username!r} from site '
                 f'{sender[:8]} opened')
    ended = []

    def end():
        # once, whether the answer ran or was closed before its first frame
        if ended:
            return
        ended.append(True)
        with sse_clients_lock:
            sse_clients.pop(client_id, None)
        _streams_in.give(sender)
        logging.info(f'[FED] live feed for {username!r} from site {sender[:8]} closed')

    def lines():
        seq = 0
        now_scope = list(scope)
        # out of the request pool like a browser's stream (api/realtime.py); _streams_in
        # bounds how many of these there are
        from pegaprox.utils.realtime import _leave_request_pool
        _leave_request_pool()
        try:
            yield signed_line(nonce, rid, seq, json.dumps({'type': 'fed_stream',
                                                           'clusters': now_scope}))
            next_keep = time.monotonic() + KEEPALIVE
            next_check = time.monotonic() + RECHECK
            while True:
                try:
                    message = q.get(timeout=5)
                except queue_module.Empty:
                    message = None
                with sse_clients_lock:
                    if client_id not in sse_clients:
                        return
                if message:
                    try:
                        obj = json.loads(message)
                    except Exception:
                        obj = None
                    if isinstance(obj, dict) and obj.get('type') in FORWARD_TYPES \
                            and obj.get('cluster_id') in now_scope:
                        seq += 1
                        yield signed_line(nonce, rid, seq, message)
                now = time.monotonic()
                if now >= next_keep:
                    seq += 1
                    next_keep = now + KEEPALIVE
                    yield signed_line(nonce, rid, seq, '{"type":"keepalive"}')
                if now >= next_check:
                    next_check = now + RECHECK
                    now_scope, eff_now, admin_now = _recheck(sender, call, raws, now_scope)
                    if not now_scope:
                        return
                    with sse_clients_lock:
                        entry = sse_clients.get(client_id)
                        if entry is None:
                            return
                        entry['clusters'] = list(now_scope)
                        # the role and the admin flag are what the per-guest filters of
                        # the broadcast decide with: as the account stands now, as the
                        # browser's own stream takes them (api/realtime.py)
                        entry['effective_role'] = eff_now
                        entry['is_admin'] = admin_now
        except GeneratorExit:
            pass
        finally:
            end()
    return _Answer(lines(), end)


class _Answer:
    """The body of a stream answer: its frames, and its end when the server closes it, also
    when that happens before the first frame (a generator that never started runs no
    finally)."""

    def __init__(self, frames, end):
        self.frames, self.end = frames, end

    def __iter__(self):
        return self

    def __next__(self):
        return next(self.frames)

    def close(self):
        try:
            self.frames.close()
        finally:
            self.end()


def _recheck(sender, call, raws, now_scope):
    """(clusters, effective role, admin): what the stream may still carry and as whom.
    No clusters once the switch is off, the site is no member, the mirror is refused
    (disabled, unmapped, gone) or none of its clusters is left."""
    try:
        if not fed.enabled() or fed.member_record(sender) is None:
            return [], None, False
        row, why = relay.resolve_principal(sender, call)
        if why:
            return [], None, False
        _i, eff, admin, scope = _scope(row['username'], call.get('tok'), raws)
    except Exception as e:
        logging.warning(f'[FED] a live feed of site {sender[:8]} could not be re-checked: {e}')
        return [], None, False
    return [r for r in now_scope if r in scope], eff, admin
