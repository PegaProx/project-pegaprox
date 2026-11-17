"""Linked mode: the clusters of the other sites, worked on from this instance.

A remote cluster has the id <raw>~<iid>: its id at the site that leads it, a tilde, and
that site's instance id. The UI builds its cluster URLs with that id like with any other;
RemotePaths, a WSGI wrapper in front of the Flask app, moves such a path onto the relay
route (api/federation_relay.py), and the relay sends the request on to the leading site
over the federation's pinned channel. There it runs through that site's own app under a
session that holds for that one request: its sign-in, permissions, quotas and audit
decide, exactly as for a request made there.

Who may: a site speaks only for the accounts it homes. The leading site takes a request
only for a mirror of an account the sending site homes, mapped there (resolve_principal),
and only for a cluster route that crosses (rule_verdict): the cluster's own record, the
site's access rules, admin settings, scripts and installs on its nodes, routes that name
a second cluster, uploads, sockets and PegaProx's own HA of a cluster stay where they are.

The wire: a POST to RELAY_PATH with the inner body raw and an envelope of at most 4 KiB
in a header, signed with the member key under a domain of its own; the answer is signed
back over the request's nonce. A control call never verifies as a relay call, nor the
other way round. The receiving side refuses a call signed before its process started.

Off (the federation switch), RemotePaths changes no path and the routes answer 404, so a
'~' id gets the answer of any unknown cluster.

MK Nov 2026
"""
import base64
import contextvars
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sys
import threading
import time

from pegaprox.core import federation as fed
from pegaprox.core import ha_wire

RELAY_PATH = '/api/federation/peer/relay'
RELAY_DOMAIN = 'pegaprox-fed-relay-1'
ANSWER_DOMAIN = 'pegaprox-fed-relay-answer-1'
ENVELOPE_HEADER = 'X-PegaProx-Relay'
BODY_HEADER = 'X-PegaProx-Relay-Body'
ANSWER_HEADER = 'X-PegaProx-Relay-Answer'
SIG_HEADER = 'X-PegaProx-Relay-Sig'
SITE_HEADER = 'X-PegaProx-Site'
# the path a request came in with before RemotePaths moved it, and the mark of an answer
# that came from another site (add_security_headers sandboxes those)
ENTRY_ENVIRON = 'pegaprox.fed_entry'
RELAYED_ENVIRON = 'pegaprox.fed_relayed'
_VERDICT_ENVIRON = 'pegaprox.fed_relay_verdict'

RELAY_VERSION = 1
MAX_ENVELOPE = 4096
MAX_BODY = 10 * 1024 * 1024
MAX_ANSWER = 16 * 1024 * 1024
READ_TIMEOUT = 30
WRITE_TIMEOUT = 180
LIST_TIMEOUT = 5

CLUSTER_RULE = '/api/clusters/<cluster_id>'
LIST_RULE = '/api/federation/linked/self'
_SAFE_METHODS = ('GET', 'HEAD')
_METHODS = ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE')
_HEX64 = re.compile(r'[0-9a-f]{64}')
_RID_RE = re.compile(r'[0-9a-f]{32}')

# what an answer from another site may be: no HTML and no SVG reach this origin
ANSWER_TYPES = ('application/json', 'text/plain', 'text/csv', 'application/octet-stream',
                'application/x-virt-viewer')
_INLINE_TYPES = ('application/json', 'text/plain')
_PASS_HEADERS = ('Content-Type', 'Content-Disposition', 'Retry-After', 'ETag')

# --- what crosses ------------------------------------------------------------------------
#
# Every route under CLUSTER_RULE crosses unless it is named here or its view asks for an
# admin, the site's access rules, scripts or settings (rule_verdict). The tail is the rule
# after CLUSTER_RULE. tests/test_federation_relay.py pins the full list of the rules that
# cross, so a cluster route added later is decided on before it is relayed.
_EXCLUDED = {
    # the cluster's own record and credentials at the site that leads it
    'record': frozenset({
        ('PUT', ''), ('DELETE', ''), ('PATCH', '/config'), ('GET', '/config/export'),
        ('POST', '/reconfigure'), ('POST', '/api-token/rotate'),
        ('GET', '/node-credentials'), ('POST', '/node-credentials/check'),
        ('PUT', '/node-credentials/<node>'), ('DELETE', '/node-credentials/<node>'),
        ('POST', '/ssh/repin-host-keys'), ('PUT', '/rename'), ('PUT', '/group'),
        ('PUT', '/sort-order'), ('PUT', '/location'), ('POST', '/ha/claim'),
        ('GET', '/esxi-hosts'), ('POST', '/esxi-hosts'), ('POST', '/connection-check')}),
    # installs of software on the site's nodes
    'install': frozenset({
        ('POST', '/reports/install-debsecan'), ('POST', '/ha/install-self-fence'),
        ('POST', '/ha/uninstall-self-fence')}),
    # a second cluster: this site's pickers hold this site's ids
    'second_cluster': frozenset({
        ('POST', '/vms/<node>/<vm_type>/<int:vmid>/remote-migrate'),
        ('POST', '/transfer-network/check')}),
    # uploads and sockets, which have their own way
    'transport': frozenset({
        ('POST', '/datastores/<storage_name>/upload'),
        ('POST', '/vms/<node>/<vm_type>/<int:vmid>/vnc-poll'),
        ('GET', '/vms/<node>/<vm_type>/<int:vmid>/vncwebsocket'),
        ('GET', '/nodes/<node>/shellws')}),
    # PegaProx's own HA of the cluster, set and acted on at the site that leads it
    'ha': frozenset({
        ('PUT', '/ha'), ('PUT', '/ha/config'), ('POST', '/ha/enable'),
        ('POST', '/ha/disable'), ('POST', '/ha/agent-check'),
        ('POST', '/ha/interrupted-recoveries/dismiss'),
        ('POST', '/ha/interrupted-recoveries/start')}),
}
_ADMIN_PERMS = frozenset({'admin.scripts', 'admin.settings'})

REASONS = {
    'record': 'The settings and credentials of this cluster are kept at the site that leads it',
    'access': 'Who may act on this cluster is set at the site that leads it',
    'admin': 'This is set by an admin of the site that leads the cluster',
    'install': 'Software on the nodes of this cluster is installed from the site that leads it',
    'second_cluster': 'This names a second cluster, which is picked at the site that leads it',
    'transport': 'Uploads and sockets go to the site that leads the cluster directly',
    'ha': "PegaProx's HA of this cluster is set at the site that leads it",
    'scope': 'Only the cluster routes of another site are relayed',
}


def rule_verdict(app, method, rule):
    """None when `method` on the url rule `rule` (a werkzeug Rule) crosses to another site,
    else the key of REASONS that says why not. A HEAD is judged as the GET it runs."""
    if method == 'HEAD':
        method = 'GET'
    path = rule.rule
    if path == LIST_RULE:
        return None if method == 'GET' else 'scope'
    if not (path == CLUSTER_RULE or path.startswith(CLUSTER_RULE + '/')):
        return 'scope'
    if getattr(rule, 'websocket', False):
        return 'transport'
    tail = path[len(CLUSTER_RULE):]
    for reason, pairs in _EXCLUDED.items():
        if (method, tail) in pairs:
            return reason
    if tail.startswith('/storage-clusters'):
        return 'second_cluster'
    auth = getattr(app.view_functions.get(rule.endpoint), '_pp_auth', None) or {}
    perms = set(auth.get('perms') or ())
    if 'admin' in (auth.get('roles') or ()) or perms & _ADMIN_PERMS:
        return 'admin'
    if 'admin.users' in perms:
        return 'access'
    return None


def match_rule(app, method, path):
    """(werkzeug Rule, view args) that serves `method` on `path` here, or (None, None)."""
    try:
        return app.url_map.bind('localhost').match(path, method=method, return_rule=True)
    except Exception:
        return None, None


# --- remote ids ------------------------------------------------------------------------------

def split_remote(cluster_id):
    """(raw id, instance id) of a remote cluster id, None for anything else."""
    if not isinstance(cluster_id, str) or '~' not in cluster_id:
        return None
    raw, _, iid = cluster_id.rpartition('~')
    if not fed.CLUSTER_ID_RE.fullmatch(raw) or not ha_wire.ID_RE.fullmatch(iid):
        return None
    return raw, iid


def remote_id(raw, iid):
    return f'{raw}~{iid}'


def _local_ids():
    from pegaprox import globals as g
    return getattr(g, 'cluster_managers', None) or {}


class RemotePaths:
    """The WSGI app in front of Flask: a path under /api/clusters/ whose cluster id is a
    remote one goes to the relay route, every other path as it came. With the federation
    off it changes nothing, so a '~' id gets the answer of any unknown cluster. A cluster
    of this instance whose id happens to carry a '~' stays local."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO') or ''
        if path.startswith('/api/clusters/') and '~' in path and not environ.get('HTTP_UPGRADE'):
            cid, sep, rest = path[len('/api/clusters/'):].partition('/')
            ids = split_remote(cid)
            if ids and fed.enabled() and cid not in _local_ids():
                environ[ENTRY_ENVIRON] = path
                environ['PATH_INFO'] = f'/api/federation/relay/{ids[1]}/clusters/{ids[0]}{sep}{rest}'
        return self.wsgi_app(environ, start_response)


# --- budgets -------------------------------------------------------------------------------
#
# Sized from the request pool of this process (app.py), so relays never hold every slot:
# half the pool for all sites together, an eighth (at least four) per site. Over a budget
# the answer is 429 FED_RELAY_BUSY at once, never a wait.

def _pool_size():
    try:
        return max(8, int(os.environ.get('PEGAPROX_WORKERS') or max(32, (os.cpu_count() or 2) * 16)))
    except ValueError:
        return 32


class _Budget:
    def __init__(self, total, each):
        self.total, self.each = total, each
        self._lock = threading.Lock()
        self._used, self._per = 0, {}

    def take(self, key):
        with self._lock:
            if self._used >= self.total or self._per.get(key, 0) >= self.each:
                return False
            self._used += 1
            self._per[key] = self._per.get(key, 0) + 1
            return True

    def give(self, key):
        with self._lock:
            self._used = max(0, self._used - 1)
            n = self._per.get(key, 0) - 1
            if n > 0:
                self._per[key] = n
            else:
                self._per.pop(key, None)


_P = _pool_size()
# the relayed calls one member may make per minute, whatever they carry
SENDER_RATE = 3000
# relay_call's kinds for no answer: sent with none back, or never sent
_NO_ANSWER = ('silent', 'unsent')
# what this instance sends out (per receiving site) and runs for others (per sender)
_out = _Budget(max(4, _P // 2), max(4, _P // 8))
_in = _Budget(max(4, _P // 2), max(4, _P // 8))

# a site that does not answer is not dialled for a while: 3 failed connects within 30 s
# keep it closed for 15 s
_BREAK_AFTER, _BREAK_WINDOW, _BREAK_FOR = 3, 30, 15
_breaker = {}
_breaker_lock = threading.Lock()


def _broken(iid):
    with _breaker_lock:
        st = _breaker.get(iid)
        return bool(st and st.get('until', 0) > time.monotonic())


def note_answer(iid, kind, started):
    """What a relayed call says about the site, for the breaker: a signed or unsigned answer
    is a site that runs; no answer counts only when it came fast (a refused or unreachable
    address), so a slow request of one user does not close the site for everybody."""
    if kind not in _NO_ANSWER:
        _note_dial(iid, True)
    elif time.monotonic() - started < fed.CONNECT_TIMEOUT + 2:
        _note_dial(iid, False)


def _note_dial(iid, ok):
    now = time.monotonic()
    with _breaker_lock:
        st = _breaker.setdefault(iid, {'fails': [], 'until': 0})
        if ok:
            st['fails'] = []
            st['until'] = 0
            return
        st['fails'] = [t for t in st['fails'] if now - t < _BREAK_WINDOW] + [now]
        if len(st['fails']) >= _BREAK_AFTER:
            st['until'] = now + _BREAK_FOR
            st['fails'] = []


def reset_for_tests():
    with _breaker_lock:
        _breaker.clear()
    for b in (_out, _in, _tunnels):
        with b._lock:
            b._used, b._per = 0, {}
    with _user_tunnels_lock:
        _user_tunnels.clear()
    with _list_lock:
        _list_cache.clear()
    with _nonces_lock:
        _nonces.clear()
    _pulls.clear()


# --- the wire ------------------------------------------------------------------------------

def _sha(data):
    return hashlib.sha256(data or b'').hexdigest()


def _b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def _unb64(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _request_message(body_sha, env_sha, ts, nonce, receiver, sender):
    return '\n'.join((RELAY_DOMAIN, 'POST', RELAY_PATH, body_sha, env_sha, ts, nonce,
                      receiver, sender)).encode()


def _answer_message(nonce, rid, answer_sha, body_sha, responder, requester):
    return '\n'.join((ANSWER_DOMAIN, nonce, rid, answer_sha, body_sha, responder,
                      requester)).encode()


def session_handle(session_id):
    """What the other sites know of a session of this instance: an HMAC of its id, which
    never leaves this instance itself."""
    key = hashlib.sha256(b'pegaprox-fed-session-1' + fed._own_field_key()[0]).digest()
    return hmac.new(key, (session_id or '').encode(), hashlib.sha256).hexdigest()[:32]


def relay_call(iid, method, path, query='', body=b'', ctype='', principal=None,
               read_timeout=READ_TIMEOUT):
    """Send one request to member `iid` to run there as `principal`.

    Returns (kind, status, headers, body): kind 'answer' for a signed answer of the site
    (status, headers and body are the inner request's, or the site's signed refusal),
    'refused' for an unsigned refusal before any check of ours went through there (its
    JSON in body), 'silent' when no answer came at all, 'unsent' when the request did not
    leave this instance (no connection to the site)."""
    rec = fed.member_record(iid)
    if not rec or not rec.get('url'):
        return 'silent', 0, {}, b''
    rid = secrets.token_hex(16)
    envelope = {'v': RELAY_VERSION, 'rid': rid, 'method': method, 'path': path,
                'query': query or '', 'ctype': ctype or '', 'principal': principal or {}}
    env_text = _b64(json.dumps(envelope, separators=(',', ':'), sort_keys=True).encode())
    if len(env_text) > MAX_ENVELOPE:
        return 'refused', 414, {}, json.dumps({'code': 'FED_RELAY_TOO_LARGE', 'error':
                                              'The request is too long to relay'}).encode()
    sender = fed.instance_id()
    ts, nonce = str(int(time.time())), secrets.token_urlsafe(18)
    body_sha = _sha(body)
    sig = fed.signing_key().sign(_request_message(body_sha, _sha(env_text.encode()), ts, nonce,
                                                  iid, sender))
    headers = {ha_wire.PEER_HEADER: sender, ha_wire.PEER_TS_HEADER: ts,
               ha_wire.PEER_NONCE_HEADER: nonce,
               ha_wire.PEER_SIG_HEADER: base64.b64encode(sig).decode(),
               ENVELOPE_HEADER: env_text, BODY_HEADER: body_sha,
               'X-Requested-With': fed.PEER_XHR, 'Accept': '*/*',
               'Content-Type': ctype if ctype and body else 'application/json'}
    transport = fed._runtime.get('transport')
    sent = {}
    if transport is not None:
        try:
            status, raw, rh = transport(rec['url'], 'POST', RELAY_PATH, body or b'', headers)
        except Exception as e:
            logging.warning(f'[FED] relay to {iid} failed: {e}')
            status, raw, rh = 0, None, {}
            if isinstance(e, ConnectionRefusedError):
                sent['never'] = True
    else:
        status, raw, rh = fed._wire_call(rec['url'], rec.get('fingerprints') or [], 'POST',
                                         RELAY_PATH, body or b'', headers, read_timeout,
                                         MAX_ANSWER, sent=sent)
    if not status:
        return ('unsent' if sent.get('never') else 'silent'), 0, {}, b''
    raw = raw or b''
    rh = {k.lower(): v for k, v in (rh or {}).items() if isinstance(k, str)}
    answer_text, answer_sig = rh.get(ANSWER_HEADER.lower()), rh.get(SIG_HEADER.lower())
    key = ha_wire.public_key(rec.get('public_key') or '')
    signed = False
    if (status == 200 and isinstance(answer_text, str) and isinstance(answer_sig, str)
            and key is not None and len(answer_text) <= 4 * MAX_ENVELOPE):
        from cryptography.exceptions import InvalidSignature
        try:
            key.verify(base64.b64decode(answer_sig),
                       _answer_message(nonce, rid, _sha(answer_text.encode()), _sha(raw), iid,
                                       sender))
            signed = True
        except (InvalidSignature, ValueError):
            signed = False
    if not signed:
        if status == 200:
            logging.warning(f'[FED] the answer of {iid} to a relayed request carries no good '
                            'signature - taken as no answer')
            return 'silent', 0, {}, b''
        return 'refused', status, {}, raw[:4096]
    try:
        answer = json.loads(_unb64(answer_text))
    except Exception:
        return 'silent', 0, {}, b''
    if not isinstance(answer, dict) or answer.get('rid') != rid:
        return 'silent', 0, {}, b''
    inner = answer.get('status')
    if not isinstance(inner, int) or isinstance(inner, bool) or not 100 <= inner < 600:
        return 'silent', 0, {}, b''
    out_headers = {}
    for k, v in (answer.get('headers') or {}).items():
        if k in _PASS_HEADERS and isinstance(v, str) and '\n' not in v and '\r' not in v:
            out_headers[k] = v[:512]
    return 'answer', inner, out_headers, raw


# --- the leading side ------------------------------------------------------------------------

_nonces = {}
_nonces_lock = threading.Lock()


def header_verdict(request):
    """Who sent this relayed request, from its headers alone (no byte of the body is read):
    ('member', record, envelope), ('removed', tombstone, None), ('skewed', record, None) or
    (None, None, None). Worked out once per request; the nonce is spent with the 'member'
    verdict, so the request counts once."""
    env = request.environ
    if _VERDICT_ENVIRON in env:
        return env[_VERDICT_ENVIRON]
    verdict = (None, None, None)
    try:
        verdict = _header_verdict(request.headers)
    except Exception as e:
        logging.warning(f'[FED] could not check a relayed request: {e}')
    env[_VERDICT_ENVIRON] = verdict
    return verdict


def _header_verdict(headers):
    claimed = headers.get(ha_wire.PEER_HEADER) or ''
    ts, nonce, sig = (headers.get(ha_wire.PEER_TS_HEADER), headers.get(ha_wire.PEER_NONCE_HEADER),
                      headers.get(ha_wire.PEER_SIG_HEADER))
    env_text, body_sha = headers.get(ENVELOPE_HEADER), headers.get(BODY_HEADER)
    if not (ha_wire.ID_RE.fullmatch(claimed) and isinstance(env_text, str)
            and 0 < len(env_text) <= MAX_ENVELOPE and isinstance(body_sha, str)
            and _HEX64.fullmatch(body_sha) and all(isinstance(v, str) for v in (ts, nonce, sig))
            and ha_wire.TS_RE.fullmatch(ts) and ha_wire.NONCE_RE.fullmatch(nonce)
            and ha_wire.SIGNATURE_RE.fullmatch(sig)):
        return None, None, None
    ident = fed.identity() or {}
    me = ident.get('instance_id') or ''
    if not me:
        return None, None, None
    view = (ident.get('view') or {}).get('members') or {}
    rec = view.get(claimed)
    kind = 'member'
    if rec is None:
        rec = (ident.get('tombstones') or {}).get(claimed)
        kind = 'removed'
    key = ha_wire.public_key((rec or {}).get('public_key') or '')
    if key is None:
        return None, None, None
    from cryptography.exceptions import InvalidSignature
    try:
        key.verify(base64.b64decode(sig),
                   _request_message(body_sha, _sha(env_text.encode()), ts, nonce, me, claimed))
    except (InvalidSignature, ValueError):
        return None, None, None
    rec = dict(rec, instance_id=claimed)
    if kind == 'removed':
        return 'removed', rec, None
    now = time.time()
    if abs(now - int(ts)) > ha_wire.SIGNATURE_WINDOW or int(ts) < fed._started():
        return 'skewed', dict(rec, skew='early' if int(ts) < fed._started() else 'window'), None
    with _nonces_lock:
        if ha_wire.take_nonce(_nonces.setdefault(claimed, {}), nonce, int(ts), now) != 'ok':
            return None, None, None
    try:
        envelope = json.loads(_unb64(env_text))
    except Exception:
        envelope = None
    return 'member', rec, envelope if isinstance(envelope, dict) else {}


def valid_envelope(envelope):
    """The envelope's fields when they are well formed, else None."""
    if not isinstance(envelope, dict) or envelope.get('v') != RELAY_VERSION:
        return None
    method, path, query = envelope.get('method'), envelope.get('path'), envelope.get('query')
    ctype, rid, principal = envelope.get('ctype'), envelope.get('rid'), envelope.get('principal')
    if method not in _METHODS or not isinstance(path, str) or not path.startswith('/api/'):
        return None
    if '~' in path or '..' in path or '\\' in path or len(path) > 2048:
        return None
    if not isinstance(query, str) or '~' in query or len(query) > 2048:
        return None
    if not isinstance(ctype, str) or len(ctype) > 200 or '\n' in ctype or '\r' in ctype:
        return None
    if not isinstance(rid, str) or not _RID_RE.fullmatch(rid) or not isinstance(principal, dict):
        return None
    user, home = principal.get('user'), principal.get('home')
    sh, ip = principal.get('sh', ''), principal.get('ip', '')
    if not (isinstance(user, str) and 0 < len(user) <= 128 and isinstance(home, str)
            and ha_wire.ID_RE.fullmatch(home) and isinstance(sh, str) and len(sh) <= 64
            and isinstance(ip, str) and len(ip) <= 64):
        return None
    try:
        import ipaddress
        ip = str(ipaddress.ip_address(ip)) if ip else ''
    except ValueError:
        return None
    return {'method': method, 'path': path, 'query': query, 'ctype': ctype, 'rid': rid,
            'user': user, 'home': home, 'sh': sh, 'ip': ip}


# a mirror that has not arrived yet is pulled from its home once per half minute
_pulls = {}
_PULL_EVERY = 30


def _pull_soon(home):
    now = time.monotonic()
    if now - _pulls.get(home, -1e9) < _PULL_EVERY:
        return
    _pulls[home] = now

    def go():
        try:
            fed.pull_identities(home)
        except Exception as e:
            logging.warning(f'[FED] the accounts of {home} could not be pulled: {e}')
    threading.Thread(target=go, daemon=True, name='federation-relay-pull').start()


def resolve_principal(sender, call):
    """(user row, None) when this instance runs the call as a mirror of an account the
    sender homes, else (None, (status, code, sentence))."""
    from pegaprox.core.db import get_db
    if call['home'] != sender:
        return None, (403, 'FED_RELAY_WRONG_HOME', 'A site acts only for the accounts it homes')
    try:
        row = get_db().conn.execute('SELECT * FROM users WHERE username = ?',
                                    (call['user'],)).fetchone()
    except Exception as e:
        logging.warning(f'[FED] could not read the account of a relayed request: {e}')
        return None, (503, 'FED_UNAVAILABLE', 'The accounts of this site cannot be read')
    if row is None:
        _pull_soon(sender)
        return None, (503, 'FED_RELAY_SYNCING', 'Your account has not reached this site yet - '
                                                'try again in a moment')
    row = dict(row)
    if (row.get('fed_home') or '') != sender:
        return None, (403, 'FED_RELAY_WRONG_HOME', 'This site has an account of its own with '
                                                   'that name')
    if row.get('tenant') == fed.QUARANTINE or row.get('role') == fed.QUARANTINE:
        return None, (403, 'FED_RELAY_UNMAPPED', 'An admin of this site has not mapped your '
                                                 'tenant and role yet')
    if not row.get('enabled', 1):
        return None, (403, 'FED_RELAY_DISABLED', 'Your account is disabled at this site')
    if row.get('portal_only'):
        return None, (403, 'PORTAL_ONLY', 'This account can only use the Client Portal')
    try:
        from pegaprox.utils.auth import mfa_enrolment_state, MFA_DUE
        from pegaprox.api.helpers import load_server_settings
        user = get_db().get_user(call['user']) or {}
        if mfa_enrolment_state(user, load_server_settings(), call['user']) == MFA_DUE:
            return None, (403, 'FED_RELAY_MFA', 'This site asks every account for a second '
                                                'factor: set one up at your home site')
    except Exception as e:
        logging.warning(f'[FED] could not tell whether force_2fa holds a relayed request: {e}')
        return None, (503, 'FED_UNAVAILABLE', 'The second-factor rule of this site cannot be read')
    return row, None


def run_relayed(app, outer, call, row, site):
    """Run the call through this app as the mirror `row`: (status, headers, body)."""
    from pegaprox.utils.auth import open_relay_session, end_relay_session, RELAY_ENVIRON
    body = call['body']
    sid = open_relay_session(row['username'], row.get('role') or 'viewer', call['ip'], site)
    environ = {
        'REQUEST_METHOD': call['method'],
        'SCRIPT_NAME': '',
        'PATH_INFO': call['path'].encode('utf-8').decode('latin-1'),
        'QUERY_STRING': call['query'],
        'SERVER_NAME': outer.get('SERVER_NAME') or 'localhost',
        'SERVER_PORT': outer.get('SERVER_PORT') or '443',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'REMOTE_ADDR': call['ip'] or outer.get('REMOTE_ADDR') or '',
        'HTTP_HOST': outer.get('HTTP_HOST') or 'localhost',
        # the marker of the UI's own calls and no Origin: the CSRF gate takes it as a
        # same-origin call
        'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest',
        'HTTP_X_SESSION_ID': sid,
        'HTTP_USER_AGENT': f'PegaProx site {site}'[:200],
        'CONTENT_LENGTH': str(len(body)),
        'wsgi.version': (1, 0),
        'wsgi.url_scheme': outer.get('wsgi.url_scheme') or 'https',
        'wsgi.input': io.BytesIO(body),
        'wsgi.errors': outer.get('wsgi.errors') or sys.stderr,
        'wsgi.multithread': bool(outer.get('wsgi.multithread')),
        'wsgi.multiprocess': False,
        'wsgi.run_once': False,
        RELAY_ENVIRON: {'session': sid, 'site': site, 'home': call['home'], 'rid': call['rid'],
                        'ip': call['ip'], 'sh': call['sh']},
    }
    if call['ctype']:
        environ['CONTENT_TYPE'] = call['ctype']
    try:
        return contextvars.Context().run(_dispatch, app, environ)
    finally:
        end_relay_session(sid)


def _dispatch(app, environ):
    started, chunks = {}, []

    def start_response(status, headers, exc_info=None):
        started['status'], started['headers'] = status, headers
        return chunks.append

    result = app(environ, start_response)
    size, too_large = 0, False
    try:
        for chunk in result:
            size += len(chunk)
            if size > MAX_ANSWER:
                too_large = True
                break
            chunks.append(chunk)
    finally:
        close = getattr(result, 'close', None)
        if close:
            close()
    if too_large:
        return 502, {'Content-Type': 'application/json'}, json.dumps({
            'code': 'FED_RELAY_TOO_LARGE',
            'error': 'Done at the site that leads the cluster, but its answer is too large to '
                     'carry - look there'}).encode()
    status = int(str(started.get('status') or '500').split(' ', 1)[0])
    wanted = {name.lower(): name for name in _PASS_HEADERS}
    headers = {wanted[k.lower()]: v for k, v in started.get('headers') or ()
               if k.lower() in wanted}
    return status, headers, b''.join(chunks)


def sign_answer(nonce, rid, requester, status, headers, body):
    """The answer headers of a relayed request: the inner status and headers in an envelope,
    signed over the request's nonce, the rid and the body."""
    answer_text = _b64(json.dumps({'status': int(status), 'headers': headers, 'rid': rid},
                                  separators=(',', ':'), sort_keys=True).encode())
    sig = fed.signing_key().sign(_answer_message(nonce, rid, _sha(answer_text.encode()),
                                                 _sha(body), fed.instance_id(), requester))
    return {ANSWER_HEADER: answer_text, SIG_HEADER: base64.b64encode(sig).decode()}


# --- the entry side: what the browser gets back ----------------------------------------------

def browser_answer(kind, status, headers, body, write):
    """(status, headers, body) for the browser from relay_call's result. An answer from
    another site never carries HTML or SVG, a cookie or a redirect; a file other than JSON
    or text is a download. A sign-in refusal there is no lost session here."""
    if kind == 'unsent':
        return _json(503, 'FED_SITE_UNREACHABLE', 'The site that leads this cluster cannot be '
                                                  'reached - nothing was sent to it')
    if kind == 'silent':
        if write:
            return _json(504, 'FED_RELAY_NO_ANSWER', 'The site that leads this cluster did not '
                                                     'answer. The change may have happened '
                                                     'there - check its tasks')
        return _json(503, 'FED_SITE_UNREACHABLE', 'The site that leads this cluster does not '
                                                  'answer')
    if kind == 'refused':
        code = ''
        try:
            code = (json.loads(body or b'{}') or {}).get('code') or ''
        except Exception:
            pass
        if code == 'FED_DISABLED':
            return _json(503, 'FED_SITE_OFF', 'The federation is switched off at the site that '
                                              'leads this cluster')
        if code in ('FED_STANDBY',) or str(code).startswith('HA_'):
            return _json(503, 'FED_SITE_SWITCHING', 'The site that leads this cluster is '
                                                    'switching over - try again in a moment')
        if code == 'FED_CLOCK':
            return _json(503, 'FED_CLOCK', 'The clocks of this site and the site that leads '
                                           'this cluster are more than two minutes apart')
        if code == 'FED_REMOVED':
            return _json(410, 'FED_REMOVED', 'This site is no longer a member there')
        return _json(502, 'FED_RELAY_REFUSED', 'The site that leads this cluster refused the '
                                               'request')
    out = dict(headers)
    if 300 <= status < 400 and status != 304:
        return _json(502, 'FED_RELAY_REDIRECT', 'The site that leads this cluster answered with '
                                                'a redirect')
    if status == 401:
        try:
            inner = json.loads(body or b'{}')
        except Exception:
            inner = {}
        return _json(403, 'FED_RELAY_AUTH', (inner or {}).get('error')
                     or 'The site that leads this cluster did not take your sign-in')
    try:
        code = (json.loads(body) or {}).get('code') if body and \
            out.get('Content-Type', '').startswith('application/json') else ''
    except Exception:
        code = ''
    if isinstance(code, str) and code.startswith('HA_'):
        return _json(503, 'FED_SITE_SWITCHING', 'The site that leads this cluster is switching '
                                                'over - try again in a moment')
    ctype = (out.get('Content-Type') or '').split(';', 1)[0].strip().lower()
    if body and ctype not in ANSWER_TYPES:
        return _json(502, 'FED_RELAY_TYPE', 'The site that leads this cluster answered with '
                                            'content this site does not pass on')
    if body and ctype not in _INLINE_TYPES:
        disp = out.get('Content-Disposition') or ''
        name = re.search(r'filename="?([^";]{1,120})', disp)
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', name.group(1)) if name else 'download'
        out['Content-Disposition'] = f'attachment; filename="{safe}"'
    elif 'Content-Disposition' in out:
        out.pop('Content-Disposition')
    return status, out, body


def _json(status, code, error):
    return status, {'Content-Type': 'application/json'}, json.dumps(
        {'code': code, 'error': error}).encode()


# --- the cluster list ------------------------------------------------------------------------
#
# Each site answers LIST_RULE through the relay for the user asking: the clusters that user
# may see there, with that user's permissions there. Kept here for half a minute per
# (site, user); a site that does not answer never fails the list.

LIST_SECONDS = 30
MAX_LIST_ROWS = 1000
# (site, user) lists kept: the expired go first, then the oldest
MAX_LISTS = 2048
# what is asked again at the next poll rather than kept
_PASSING_STATES = ('unreachable', 'busy', 'switching', 'loading')
# of these, the ones where the site itself runs
_BUSY_STATES = ('busy', 'loading')


def _good(held):
    return held is not None and held[0].get('state') == 'ok'
_list_cache = {}
_list_lock = threading.Lock()


def _list_row(r, iid):
    if not isinstance(r, dict):
        return None
    raw = r.get('id')
    if not isinstance(raw, str) or not fed.CLUSTER_ID_RE.fullmatch(raw):
        return None
    out = {'id': remote_id(raw, iid), 'name': str(r.get('name') or raw)[:80],
           'cluster_type': r.get('type') if r.get('type') in fed.CLUSTER_TYPES else 'other',
           'connected': r.get('connected') is True}
    for field in ('nodes', 'vms'):
        n = fed._count(r.get(field))
        if n is not None:
            out[field] = n
    return out


def site_list(iid, rec, principal, now=None):
    """The entry of one site in /api/federation/linked for one user."""
    now = time.monotonic() if now is None else now
    key = (iid, principal['user'])
    with _list_lock:
        held = _list_cache.get(key)
    if held is not None and 0 <= now - held[1] < LIST_SECONDS:
        return held[0]
    entry = {'iid': iid, 'site': rec.get('site') or iid[:8], 'url': rec.get('url') or '',
             'state': 'ok', 'clusters': [], 'perms': []}
    if _broken(iid):
        entry['state'] = 'unreachable'
    elif not _out.take(iid):
        # the relays of the site come first; the last list is shown as it was
        return dict(held[0], stale=True) if _good(held) else dict(entry, state='loading')
    else:
        try:
            started = time.monotonic()
            kind, status, _h, body = relay_call(iid, 'GET', LIST_RULE, principal=principal,
                                                read_timeout=LIST_TIMEOUT)
            note_answer(iid, kind, started)
        finally:
            _out.give(iid)
        entry.update(_list_state(kind, status, body, iid))
    if entry['state'] in _PASSING_STATES:
        # asked again at the next poll, not kept. A site that is busy runs, and its last good
        # list stays; one that does not answer or switches over says so
        if entry['state'] in _BUSY_STATES and _good(held):
            return dict(held[0], stale=True)
        return entry
    with _list_lock:
        if len(_list_cache) >= MAX_LISTS:
            for k in [k for k, v in _list_cache.items() if not 0 <= now - v[1] < LIST_SECONDS]:
                _list_cache.pop(k, None)
            while len(_list_cache) >= MAX_LISTS:
                _list_cache.pop(next(iter(_list_cache)))
        _list_cache[key] = (entry, now)
    return entry


_LIST_STATES = {'FED_RELAY_UNMAPPED': 'unmapped', 'FED_RELAY_SYNCING': 'syncing',
                'FED_RELAY_WRONG_HOME': 'name_taken', 'FED_RELAY_DISABLED': 'disabled_account',
                'FED_RELAY_MFA': 'mfa', 'PORTAL_ONLY': 'portal_only'}


def _list_state(kind, status, body, iid):
    if kind in _NO_ANSWER:
        return {'state': 'unreachable'}
    try:
        data = json.loads(body or b'{}')
    except Exception:
        data = {}
    data = data if isinstance(data, dict) else {}
    if kind == 'refused':
        code = data.get('code') or ''
        if code == 'FED_DISABLED':
            return {'state': 'off'}
        if code == 'FED_CLOCK':
            return {'state': 'clock'}
        if code == 'FED_STANDBY' or str(code).startswith('HA_'):
            return {'state': 'switching'}
        if status in (404, 405):
            return {'state': 'old_release'}
        return {'state': 'refused'}
    if status == 429:
        return {'state': 'busy'}
    if status != 200:
        return {'state': _LIST_STATES.get(data.get('code'), 'refused')}
    rows = [x for x in (_list_row(r, iid) for r in (data.get('clusters') or [])[:MAX_LIST_ROWS])
            if x]
    perms = [p for p in (data.get('perms') or []) if isinstance(p, str) and len(p) <= 64][:256]
    return {'state': 'ok', 'clusters': rows, 'perms': perms,
            'release': str(data.get('release') or '')[:32]}


def forget_lists(iid=None):
    with _list_lock:
        for key in [k for k in _list_cache if iid is None or k[0] == iid]:
            _list_cache.pop(key, None)


# --- consoles --------------------------------------------------------------------------------
#
# A console of another site's guest or node opens through this instance: the browser opens
# CONSOLE_PATH on this instance's main port, which asks the leading site for a console token
# as the user (CONSOLE_TOKEN_RULE, through the relay) and opens that site's own console
# server with it, over TLS checked against the site's pins before a byte of the upgrade
# leaves. The leading site's console server checks the token, the cluster and the guest or
# node exactly as for a browser of its own. Only that site's console ports, or its main port
# behind a reverse proxy, have to be reachable from here.

CONSOLE_PATH = '/api/federation/console'
CONSOLE_TOKEN_RULE = CLUSTER_RULE + '/console-token'
CONSOLE_KINDS = ('vnc', 'shell', 'term')
# what the browser may hand on to the leading site's console server, per kind: the PVE
# ticket the relayed ticket call gave it, nothing else
CONSOLE_PARAMS = {'vnc': ('pve_ticket', 'pve_port'), 'shell': (),
                  'term': ('ticket', 'port', 'host', 'user')}
_NODE_RE = re.compile(r'[a-zA-Z][a-zA-Z0-9.\-]{0,62}')
# open tunnels per user, per site and in all
TUNNELS_PER_USER = 4
_tunnels = _Budget(max(4 * TUNNELS_PER_USER, _P // 2), max(3 * TUNNELS_PER_USER, _P // 4))
_user_tunnels = {}
_user_tunnels_lock = threading.Lock()


def take_tunnel(username, iid):
    with _user_tunnels_lock:
        if _user_tunnels.get(username, 0) >= TUNNELS_PER_USER:
            return False
        if not _tunnels.take(iid):
            return False
        _user_tunnels[username] = _user_tunnels.get(username, 0) + 1
        return True


def give_tunnel(username, iid):
    with _user_tunnels_lock:
        n = _user_tunnels.get(username, 0) - 1
        if n > 0:
            _user_tunnels[username] = n
        else:
            _user_tunnels.pop(username, None)
    _tunnels.give(iid)


def console_target(kind, raw, node, vm_type, vmid, params):
    """The path of the leading site's console server for one console, the token left out:
    None for anything malformed."""
    from urllib.parse import urlencode
    if kind not in CONSOLE_KINDS or not _NODE_RE.fullmatch(node or ''):
        return None
    extra = {}
    for name in CONSOLE_PARAMS[kind]:
        value = params.get(name)
        if value is None:
            continue
        if not isinstance(value, str) or len(value) > 1024 or '\n' in value:
            return None
        extra[name] = value
    if kind == 'shell':
        return f'/api/clusters/{raw}/nodes/{node}/shellws', extra
    if vm_type not in ('qemu', 'lxc') or not isinstance(vmid, int) or not 0 < vmid < 10 ** 9:
        return None
    leaf = 'vncwebsocket' if kind == 'vnc' else 'termwebsocket'
    return f'/api/clusters/{raw}/vms/{node}/{vm_type}/{vmid}/{leaf}', extra


def _pins_match(der, pins):
    got = hashlib.sha256(der or b'').hexdigest()
    return any(isinstance(p, str) and p.replace(':', '').lower() == got for p in pins)


def open_console(rec, kind, path, query, reverse_proxy, timeout=10):
    """A websocket-client connection to the leading site's console server for `path`?`query`.
    Its certificate must match the site's pins (or, without pins, a CA and its host name)
    before the upgrade goes out. Raises on anything else."""
    import socket
    import ssl
    from urllib.parse import urlsplit
    import websocket
    url = urlsplit(rec.get('url') or '')
    host = url.hostname
    if url.scheme != 'https' or not host or not fed._url_ok(rec['url'] + path):
        raise ValueError('the site has no https address this instance may dial')
    base = url.port or 443
    port = base if reverse_proxy else base + (1 if kind == 'vnc' else 2)
    pins = list(rec.get('fingerprints') or [])
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if pins:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(raw_sock, server_hostname=host)
        if pins and not _pins_match(tls.getpeercert(binary_form=True), pins):
            tls.close()
            raise ssl.SSLError('the console server of the site shows a certificate none of its '
                               'pins match')
    except Exception:
        raw_sock.close()
        raise
    netloc = f'[{host}]' if ':' in host else host
    return websocket.create_connection(f'wss://{netloc}:{port}{path}?{query}', socket=tls,
                                       timeout=timeout, redirect_limit=0,
                                       header={'User-Agent': 'PegaProx-Federation/2'})
