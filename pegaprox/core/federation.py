"""The federation of PegaProx instances: three leaders, each over its own clusters,
connected (Phase 1).

Phase 1 is the read federation only: a registry of member instances that paired by a
one-time code, and signed peer calls between them. A member answers /peer/status with
who it is and who it knows, and nothing else: no credentials, no configuration, no
cluster secrets travel. Writes stay local; there is no leader of the federation and no
consensus yet (that is Phase 2 and 3 of the design, on top of ha_vote.py).

The wire reuses the pieces of ha_wire.py that carry no state of their own: the key
parsing (with its small-order refusal), the replay rule, the sealed pairing answer and
the shape of an address and a pairing code. The signature domain is its own
('pegaprox-fed-peer-1', SIGN_DOMAIN below): a call signed for the HA group of an
instance is worthless as a federation call and the other way round, beyond the path a
signature already covers.

Trust model: a member is whoever holds the Ed25519 key that a pairing handed over. The
code an admin reads on one instance is typed on the other; the answer that carries the
member list is sealed under that code's secret, so nobody between the two can read it
or forge it. Every member of a federation is a trusted administrator of it: any member
may announce another to the rest (member-added), as the active of an HA group hands its
member list around. What a compromised member can reach is the registry and the
summaries - the credentials of the clusters stay out of the federation in this phase.

State lives in config/federation_state.json, next to ha_state.json and just as
private: 0600, written atomically, the signing key inside it. Nothing here reads the
database or imports Flask; the routes are in pegaprox/api/federation.py, as they are
for the HA group.
"""
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time

from pegaprox.constants import CONFIG_DIR
from pegaprox.core import ha_wire

# the wire this release speaks; a member refuses a federation call of another mark
FED_MARK = 1
# a code that pairs a federation member, never an HA standby or a witness: the three
# prefixes must not be taken for each other
CODE_PREFIX = 'pgxfd1_'
# the first line of everything a federation peer signs: its own domain, so a signature
# for the HA group ('pegaprox-ha-peer-1' in ha_wire.to_sign) is refused here
SIGN_DOMAIN = 'pegaprox-fed-peer-1'
# one code, fifteen minutes, one member: as the HA pairing does it
PAIRING_TTL = 15 * 60
# a federation is a handful of sites; a bound keeps a runaway pairing loop from
# filling the state with members no admin ever read about
MAX_MEMBERS = 8
# what a peer call may carry; the notices are a few bytes, the status is a GET
MAX_PEER_BODY = 64 * 1024
# what an answer of a member may weigh before it is read: a member list is a few
# hundred bytes, and nobody a federation talks to has a megabyte to say
MAX_ANSWER = 256 * 1024
SITE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
# the CSRF gate in app.py takes exactly this word from an /api call that carries no
# Origin, as it does an HA peer call; every federation call on the wire says it
PEER_XHR = 'XMLHttpRequest'

_STATE_FILE = os.path.join(CONFIG_DIR, 'federation_state.json')

_lock = threading.RLock()
# what belongs to the process that serves the state file _runtime['file'] and does not
# survive a restart: the start time (a call signed before it is refused, its nonces
# are gone) and the nonces each sender has spent here. 'transport' is the stand-in the
# tests hand over; nothing in production sets it.
_runtime = {'file': _STATE_FILE, 'started': time.time(), 'nonces': {}, 'transport': None}


class FederationError(Exception):
    """What the admin reads, with the sentence for it."""


# --- the state file ------------------------------------------------------------------

def _default_state():
    return {'instance_id': '', 'signing_key': '', 'site': '', 'members': {},
            'tombstones': {}, 'pairing': None, 'created_at': int(time.time()),
            # Phase 3: the leases held here and the promises given - state like the
            # rest, persisted and read back (a key not named here is dropped on
            # load, as _load takes only what the default knows)
            'my_leases': {}, 'lease_promises': {},
            # Phase 4: the field keys the members handed over, sealed at the
            # pairing - what an adoption opens the mirrored credentials with
            'field_keys': {}}


def _read(path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as e:
        raise FederationError(f'The federation state file cannot be read - restore '
                              f'config/federation_state.json, or leave the federation '
                              f'and pair again: {e}')
    if not isinstance(raw, dict):
        raise FederationError('The federation state file holds no federation state - '
                              'restore config/federation_state.json, or leave the '
                              'federation and pair again')
    return raw


def _load():
    """The state as it is on disk, the defaults for what an old file misses.

    The caller holds _lock around every read-and-write pair; _load is the read half
    of it (as ha._load is for the HA group)."""
    raw = _read(_runtime['file'])
    if raw is None:
        return _default_state()
    state = _default_state()
    state.update({k: raw[k] for k in state if k in raw})
    for key in ('members', 'tombstones'):
        if not isinstance(state[key], dict):
            state[key] = {}
    return state


def _save(state):
    path = _runtime['file']
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    tmp = f'{path}.tmp.{os.getpid()}.{threading.get_ident()}'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(state, fh, separators=(',', ':'), sort_keys=True)
            fh.write('\n')
            # the answer of a join says the code is spent; a state that rolls back on
            # a crash would hand the one-time code to a second joiner
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)


def _mutate(fn):
    """`fn(state)` under the lock; saved when it returned True. Returns the state."""
    with _lock:
        state = _load()
        if fn(state) is True:
            _save(state)
        return state


# --- who we are ----------------------------------------------------------------------

def instance_id():
    """This instance's id in the federation, drawn once and kept in the state file."""
    def go(state):
        if isinstance(state.get('instance_id'), str) and state['instance_id']:
            return False
        state['instance_id'] = secrets.token_hex(16)
        return True
    return _mutate(go)['instance_id']


def _private():
    def go(state):
        key = state.get('signing_key')
        if isinstance(key, str) and key:
            return False
        state['signing_key'] = ha_wire.new_signing_key()
        return True
    key = _mutate(go)['signing_key']
    try:
        return ha_wire.private_key(key)
    except Exception as e:
        raise FederationError(f'The federation signing key cannot be read - restore '
                              f'config/federation_state.json, or leave the federation '
                              f'and pair again: {e}')


def public_key():
    """This instance's Ed25519 public key, base64 of the raw 32 bytes."""
    return ha_wire.public_of(_private())


def own_site():
    return _load().get('site') or ''


def set_own_site(site):
    """The label of this instance in the federation; taken at the pairing code and at
    the join, so the others know a name for the site this instance stands for. An
    empty or unusable label never wipes what is set - a re-join without one keeps
    the name this site already has, as a member's record keeps its pin."""
    site = _clean_site(site)
    if not site:
        return own_site()

    def go(state):
        if state.get('site') == site:
            return False
        state['site'] = site
        return True
    _mutate(go)
    return site


def _started():
    return _runtime['started']


# --- a signed federation peer call -----------------------------------------------------

def _to_sign(method, path, body, ts, nonce, receiver, sender, digest=None):
    return '\n'.join((SIGN_DOMAIN, method.upper(), path,
                      digest if digest is not None else ha_wire.body_digest(body),
                      ts, nonce, receiver, sender)).encode()


def signed_headers(receiver, method, path, body=None, now=None):
    """The peer headers of one federation call we make to `receiver` (its instance
    id), signed with our key over this federation's own domain."""
    body = ha_wire.wire_body(body) if body is not None else b''
    now = time.time() if now is None else now
    sender = instance_id()
    ts, digest = str(int(now)), ha_wire.body_digest(body)
    nonce = secrets.token_urlsafe(18)
    sig = _private().sign(_to_sign(method, path, body, ts, nonce, receiver, sender, digest))
    return {ha_wire.PEER_HEADER: sender, ha_wire.PEER_TS_HEADER: ts,
            ha_wire.PEER_NONCE_HEADER: nonce,
            ha_wire.PEER_SIG_HEADER: base64.b64encode(sig).decode(),
            ha_wire.PEER_BODY_HEADER: digest,
            'Content-Type': 'application/json',
            'X-Requested-With': PEER_XHR}


def signature_verdict(headers, method, path, body, sender, public_b64, receiver, now,
                      started):
    """What the signature headers of one federation call say, before any nonce is
    spent: 'ok', '' for no good signature at all, 'window' for a good one from outside
    ha_wire.SIGNATURE_WINDOW, 'early' for one signed before this process started.
    Mirrors ha_wire.signature_verdict over the federation's own domain."""
    ts, nonce, sig = (headers.get(ha_wire.PEER_TS_HEADER),
                      headers.get(ha_wire.PEER_NONCE_HEADER),
                      headers.get(ha_wire.PEER_SIG_HEADER))
    if not all(isinstance(v, str) for v in (ts, nonce, sig)):
        return ''
    if not (ha_wire.TS_RE.fullmatch(ts) and ha_wire.NONCE_RE.fullmatch(nonce)
            and ha_wire.SIGNATURE_RE.fullmatch(sig)):
        return ''
    key = ha_wire.public_key(public_b64)
    if key is None:
        return ''
    from cryptography.exceptions import InvalidSignature
    try:
        key.verify(base64.b64decode(sig),
                   _to_sign(method, path, body, ts, nonce, receiver, sender))
    except (InvalidSignature, ValueError):
        return ''
    if abs(now - int(ts)) > ha_wire.SIGNATURE_WINDOW:
        return 'window'
    if int(ts) < started:
        return 'early'
    return 'ok'


def clock_refusal(verdict, now, started, ts):
    """The 401 body for a good signature whose time is not, in this federation's
    name. `ts` is the header's, digits when this is called - kept defensive anyway."""
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        ts = 0
    if verdict == 'early':
        return {'code': 'FED_CLOCK', 'clock': 'early',
                'error': f'The receiving instance started {max(0, int(now - started))} s '
                         f'ago, and the call was signed before that by the clock of the '
                         f'sender, which is {max(0, int(now) - ts)} s behind it (or the '
                         'call is an old one). Set both clocks by NTP'}
    return {'code': 'FED_CLOCK', 'clock': 'window',
            'error': f'The clocks of the two instances are more than '
                     f'{ha_wire.SIGNATURE_WINDOW} seconds apart - set both by NTP'}


def peer_verdict(headers, method, path, body):
    """Who sent a federation peer call: ('member', record), ('removed', tombstone),
    ('skewed', record) or (None, None).

    A member signs every call with the key the pairing handed over; there is no
    pre-key legacy in the federation, a member without a key on record is nobody. The
    nonce is spent under the lock, on the 'ok' verdict alone, once: a replayed call
    is nobody's, however good its signature."""
    raw = headers.get(ha_wire.PEER_HEADER) if headers is not None else None
    if not isinstance(raw, str) or not raw:
        return None, None
    claimed = raw.partition(':')[0]
    if not ha_wire.ID_RE.fullmatch(claimed):
        return None, None
    with _lock:
        state = _load()
        me = state['instance_id']
        now = time.time()
        rec = (state.get('members') or {}).get(claimed)
        if rec is not None and isinstance(rec.get('public_key'), str):
            check = signature_verdict(headers, method, path, body, claimed,
                                      rec['public_key'], me, now, _started())
            if check == 'ok':
                nonces = _runtime['nonces'].setdefault(claimed, {})
                if ha_wire.take_nonce(nonces, headers.get(ha_wire.PEER_NONCE_HEADER),
                                      int(headers.get(ha_wire.PEER_TS_HEADER) or 0),
                                      now) != 'ok':
                    return None, None
                return 'member', dict(rec, instance_id=claimed)
            if check in ('window', 'early'):
                # the record carries which of the two it is: the answer says so
                return 'skewed', dict(rec, instance_id=claimed, skew=check)
            return None, None
        tomb = (state.get('tombstones') or {}).get(claimed)
        if tomb is not None and isinstance(tomb.get('public_key'), str):
            # an old call of a removed member hears the same, whatever its time
            check = signature_verdict(headers, method, path, body, claimed,
                                      tomb['public_key'], me, now, _started())
            if check in ('ok', 'window', 'early'):
                return 'removed', dict(tomb, instance_id=claimed)
        return None, None


def touch(sender):
    """Note that member `sender` was just seen; never fails."""
    def go(state):
        rec = (state.get('members') or {}).get(sender)
        if rec is None:
            return False
        rec['last_seen'] = int(time.time())
        return True
    try:
        _mutate(go)
    except Exception as e:
        logging.debug(f"[FED] could not note the visit of {sender}: {e}")


# --- pairing --------------------------------------------------------------------------

def create_pairing_code(url, fingerprint=''):
    """A one-time code for the instance that is to join this one. One code is open at
    a time; a new one replaces it. Returns (code, expires_at)."""
    url = ha_wire.valid_https_url(url)
    if not url:
        raise FederationError('Enter the https:// address the joining instance will '
                              'use to reach this one')
    if fingerprint and not ha_wire.FP_RE.fullmatch(fingerprint.strip().upper()):
        raise FederationError('The certificate fingerprint is malformed')
    fingerprint = fingerprint.strip().upper()
    secret = secrets.token_hex(32)

    def go(state):
        state['pairing'] = {'secret': secret, 'url': url, 'fingerprint': fingerprint,
                            'expires': int(time.time()) + PAIRING_TTL}
        return True
    _mutate(go)
    code = ha_wire.encode_code(CODE_PREFIX, url, fingerprint, secret, instance_id())
    return code, int(time.time()) + PAIRING_TTL


PAIRING_CODE_ERROR = ('The pairing code is not one this instance made, or it has '
                      'expired - make a new one on the federation page')


def accept_join(code, url, joiner_id, joiner_key, site):
    """The issuer's half of the join: spend the code, add the member, answer with the
    member list sealed under the code's secret. Raises FederationError with what the
    joining instance reads. The push tells the members that paired before; one that
    misses it learns the new member at the next reconcile."""
    if not isinstance(code, str):
        raise FederationError(PAIRING_CODE_ERROR)
    try:
        parts = ha_wire.decode_code(CODE_PREFIX, code, 'a federation pairing code')
    except ha_wire.WireError as e:
        raise FederationError(str(e))
    url = ha_wire.valid_https_url(url)
    if not url:
        raise FederationError('The joining instance did not send a usable https:// '
                              'address')
    if not ha_wire.ID_RE.fullmatch(joiner_id or ''):
        raise FederationError('The joining instance did not send a usable instance id')
    if ha_wire.public_key(joiner_key) is None:
        raise FederationError('The joining instance did not send a usable public key')
    if joiner_id == instance_id():
        raise FederationError('This instance cannot pair with itself')
    site = _clean_site(site)
    out = {}

    def go(state):
        pairing = state.get('pairing') or {}
        held = pairing.get('secret') or ''
        if (not held or pairing.get('expires', 0) < time.time()
                or not secrets.compare_digest(held, parts['secret'])):
            out['refused'] = PAIRING_CODE_ERROR
            return False
        # the code is spent whether the join works or the federation is full: a
        # second join with it, however soon, is nobody's
        state['pairing'] = None
        members_ = state.setdefault('members', {})
        if joiner_id not in members_ and len(members_) >= MAX_MEMBERS:
            out['refused'] = f'The federation holds {MAX_MEMBERS} members already'
            return True
        # a fresh pairing is the one way a tombstone goes: an admin read the code
        # on this instance and typed it on the other
        replaced = state.get('tombstones', {}).pop(joiner_id, None) is not None \
            or members_.get(joiner_id) is not None
        rec = {'url': url, 'public_key': joiner_key, 'site': site,
               'fingerprint': '', 'paired_at': int(time.time()), 'last_seen': 0}
        old = members_.get(joiner_id)
        if old is not None:
            # a re-pair keeps what an admin pinned on this member here
            rec['fingerprint'] = old.get('fingerprint') or ''
            rec['site'] = site or old.get('site') or ''
        members_[joiner_id] = rec
        out['replaced'] = replaced
        return True
    _mutate(go)
    if out.get('refused'):
        raise FederationError(out['refused'])

    state = _load()
    rec = (state.get('members') or {}).get(joiner_id)
    if rec is None:
        # an admin took the member out between the pairing and the answer
        raise FederationError('The member was taken out while pairing - pair again')
    others = {iid: dict(r) for iid, r in (state.get('members') or {}).items()
              if iid != joiner_id}
    own = {'url': parts['url'], 'public_key': public_key(), 'site': state.get('site') or '',
           'fingerprint': parts['fingerprint'], 'paired_at': 0, 'last_seen': 0}
    body = {'members': {instance_id(): own, **others}}
    # Phase 4: the field keys travel sealed with the member list - the issuer
    # introduces every key it holds, its own first. What a member holds, an
    # adoption can open; the state file keeps them beside the signing key.
    held_keys = peer_field_keys()
    body['field_keys'] = {instance_id(): field_key_b64(),
                          **{iid: k for iid, k in held_keys.items() if iid != joiner_id}}
    sealed = ha_wire.seal(parts['secret'], body,
                          f'federation-join:{instance_id()}:{joiner_id}')
    notice = {'member': {'instance_id': joiner_id, **rec}}
    for iid, r in others.items():
        push(iid, 'member-added', notice)
    return {'sealed': sealed, 'replaced': out.get('replaced', False),
            'members': sorted({instance_id(), joiner_id, *others.keys()})}


def join(code, own_url, site=''):
    """The joining half: hand the code to the instance that made it, take the member
    list it answers under the code's seal, keep it. The call itself carries no
    signature - the issuer does not know this instance's key yet - so the code in the
    body is what lets it through, and the seal on the answer is what tells the issuer
    apart from anybody else on the way."""
    try:
        parts = ha_wire.decode_code(CODE_PREFIX, code, 'a federation pairing code')
    except ha_wire.WireError as e:
        raise FederationError(str(e))
    own_url = ha_wire.valid_https_url(own_url)
    if not own_url:
        raise FederationError('Enter the https:// address the other instances will '
                              'use to reach this one')
    site = _clean_site(site)
    set_own_site(site)
    me = instance_id()
    body = {'code': code, 'url': own_url, 'instance_id': me,
            'public_key': public_key(), 'site': site}
    status, answer = _post(parts['url'], '/api/federation/peer/join', body,
                           fingerprint=parts['fingerprint'])
    if status == 403:
        raise FederationError((answer or {}).get('error')
                              or 'The other instance refused the pairing code')
    if status != 200 or not isinstance(answer, dict) or not answer.get('sealed'):
        raise FederationError('The conversation with the other instance failed - '
                              'unreachable, or it did not answer a member list')
    if len(answer.get('sealed') or '') > 256 * 1024:
        raise FederationError('The answer of the other instance is no member list - '
                              'far too large for a federation')
    try:
        opened = ha_wire.unseal(parts['secret'], answer['sealed'],
                                f'federation-join:{parts["instance_id"]}:{me}')
    except Exception:
        raise FederationError('The answer of the other instance did not open under '
                              'the pairing code - a wrong instance answered, or the '
                              'code was spent')
    listed = opened.get('members') if isinstance(opened, dict) else None
    if not isinstance(listed, dict) or parts['instance_id'] not in listed:
        raise FederationError('The answer of the other instance carries no member list')
    # Phase 4: the field keys came sealed with the member list
    _remember_field_keys(opened.get('field_keys'))

    def go(state):
        # a member the issuer lists that this instance had removed is back: the
        # issuer vouches for it by listing it under the seal
        state['tombstones'] = {iid: t for iid, t in state.get('tombstones', {}).items()
                               if iid not in listed}
        merged = dict(state.get('members') or {})
        for iid, rec in listed.items():
            if iid == me or not isinstance(rec, dict):
                continue
            # the same bound a pairing goes by: a list nobody reads could fill the
            # state with members no admin ever saw
            if iid not in merged and len(merged) >= MAX_MEMBERS:
                out['capped'] = True
                break
            kept = _member_record(iid, rec)
            if kept is None or not kept['url'] or not kept['public_key']:
                continue
            old = merged.get(iid)
            if old is not None:
                kept['fingerprint'] = old.get('fingerprint') or kept['fingerprint']
            merged[iid] = kept
        if parts['instance_id'] in merged and parts['fingerprint']:
            merged[parts['instance_id']]['fingerprint'] = parts['fingerprint']
        state['members'] = merged
        return True
    out = {}
    _mutate(go)
    if out.get('capped'):
        logging.warning(f"[FED] the member list of {parts['instance_id']} was cut at "
                        f"{MAX_MEMBERS} members")
    # the joiner says itself hello to the members the answer listed, its field key
    # with it: what a later adoption of ITS clusters opens, at theirs (signed on
    # the wire, sealed only where TLS seals it - the trust every member-added has)
    hello = {'member': {'instance_id': me, 'url': own_url, 'public_key': public_key(),
                        'site': site, 'fingerprint': parts['fingerprint'],
                        'paired_at': int(time.time()), 'last_seen': 0},
             'field_key': field_key_b64()}
    for iid in listed:
        if iid != me:
            push(iid, 'member-added', hello)
    # the identities of the issuer come along at once, so a joined member can serve
    # the users of the federation from the first minute - best effort, the admin
    # sync route and the reconcile cover what this misses
    pull_identities(parts['instance_id'])
    return {'joined': parts['instance_id'], 'members': sorted(listed.keys())}


# --- the registry ---------------------------------------------------------------------

def _clean_site(site):
    if not isinstance(site, str):
        return ''
    site = site.strip()
    return site if SITE_RE.fullmatch(site) else ''


def _member_record(iid, rec):
    """A member record as this code keeps it, or None: a 32-hex id, an https address
    and a usable Ed25519 key at the least. What walks in from a peer is checked here
    before it is kept, as a pairing's answer is."""
    if not isinstance(rec, dict) or not ha_wire.ID_RE.fullmatch(iid or ''):
        return None
    url = ha_wire.valid_https_url(rec.get('url') if isinstance(rec.get('url'), str) else '')
    key = rec.get('public_key') if isinstance(rec.get('public_key'), str) else ''
    if ha_wire.public_key(key) is None:
        return None
    fp = rec.get('fingerprint') if isinstance(rec.get('fingerprint'), str) else ''
    if fp and not ha_wire.FP_RE.fullmatch(fp):
        fp = ''
    stamps = {}
    for field in ('paired_at', 'last_seen'):
        value = rec.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            stamps[field] = value
    return {'url': url, 'public_key': key, 'site': _clean_site(rec.get('site')),
            'fingerprint': fp, 'paired_at': stamps.get('paired_at', 0),
            'last_seen': stamps.get('last_seen', 0)}


def members():
    """{instance_id: record} of the federation as this instance holds it."""
    state = _load()
    return {iid: dict(rec, instance_id=iid)
            for iid, rec in (state.get('members') or {}).items()}


def tombstones():
    return dict(_load().get('tombstones') or {})


def member_record(sender):
    with _lock:
        state = _load()
        rec = (state.get('members') or {}).get(sender)
        return dict(rec, instance_id=sender) if rec else None


def add_member(rec, origin):
    """Take a member a peer call announced (member-added, or a reconcile). Any member
    may vouch, the record is checked as a pairing's is - but no notice brings a
    member back that was taken out: a tombstone only a fresh pairing clears, or the
    removal would not survive the member it was meant for. Returns the record kept,
    or None when the notice was no member, the federation was full, or the member is
    out."""
    if not isinstance(rec, dict):
        return None
    iid = rec.get('instance_id') or ''
    if iid == instance_id():
        return None
    kept = _member_record(iid, rec)
    if kept is None or not kept['url']:
        return None
    out = {}

    def go(state):
        if iid in (state.get('tombstones') or {}):
            out['tombstoned'] = True
            return False
        members_ = state.setdefault('members', {})
        if iid not in members_ and len(members_) >= MAX_MEMBERS:
            out['full'] = True
            return False
        old = members_.get(iid)
        if old is not None:
            # what an admin pinned on this member here stays; the notice only tells
            # the address and the key
            kept['fingerprint'] = old.get('fingerprint') or kept['fingerprint']
            kept['site'] = kept['site'] or old.get('site') or ''
            out['updated'] = True
        members_[iid] = kept
        return True
    _mutate(go)
    if out.get('tombstoned'):
        logging.warning(f"[FED] a member-added for {iid} was refused: that member is "
                        f"out - only a fresh pairing brings it back (told by {origin})")
        return None
    if out.get('full'):
        return None
    logging.info(f"[FED] member {iid} "
                 f"{'updated' if out.get('updated') else 'added'} (told by {origin})")
    return dict(kept, instance_id=iid)


# tombstones older ones drop off first: an entry without a member is only the refusal
# of a re-add, and a federation that cycles members fast cannot grow the state without
# end - a compromised member could announce and remove members all day
MAX_TOMBSTONES = 64


def remove_member(sender, by):
    """Take a member out locally, with a tombstone its later calls will hear (410),
    and tell the others. The admin route audits it; this only acts. A member that is
    not held is gone either way - but no push goes out for it, or two members
    forwarding a removal would ping-pong it between them forever."""
    out = {}

    def go(state):
        members_ = state.get('members') or {}
        rec = members_.pop(sender, None)
        if rec is not None:
            tombstones = state.setdefault('tombstones', {})
            tombstones[sender] = dict(rec, removed_at=int(time.time()), removed_by=by)
            while len(tombstones) > MAX_TOMBSTONES:
                tombstones.pop(next(iter(tombstones)))
        out['gone'] = rec is not None
        return out['gone']
    _mutate(go)
    if out.get('gone'):
        # what this instance mirrored of the member goes with it - its accounts
        # must not stay half-alive here (H1)
        drop_mirror_rows(sender)
        push_all('member-removed', {'instance_id': sender})
    return bool(out.get('gone'))


def drop_mirror_rows(home):
    """Everything this instance mirrored of `home` goes when the member goes:
    rows, grants, favorites and the sessions their users opened here - a member
    taken out of the federation must not stay signed in on this side, and its
    accounts must not stay locked mirrors no admin here can change."""
    try:
        conn = _identities_conn()
        names = [r['username'] for r in conn.execute(
            'SELECT username FROM users WHERE fed_home = ?', (home,)).fetchall()]
        for table in IDENTITY_TABLES:
            conn.execute(f'DELETE FROM "{table}" WHERE fed_home = ?', (home,))
        conn.execute('DELETE FROM federation_sync_state WHERE peer = ?', (home,))
        conn.execute('DELETE FROM federation_identity_tombstones WHERE home = ?', (home,))
        conn.commit()
        try:
            from pegaprox.core.db import get_db
            for name in names:
                get_db().purge_user_grants(name)
                conn.execute('DELETE FROM user_favorites WHERE username = ?', (name,))
            conn.commit()
        except Exception as e:
            logging.warning(f"[FED] could not purge the grants of {home}'s users: {e}")
        for name in names:
            _end_sessions_of(name)
        try:
            from pegaprox.utils import rbac
            rbac.invalidate_roles_cache()
        except Exception:
            pass
    except Exception as e:
        logging.warning(f"[FED] could not drop the mirrors of {home}: {e}")


def leave():
    """Leave the federation: forget the others and everything mirrored of them,
    then tell them on the way out. The members are held before the registry is
    emptied - a push after it would find nobody in it, and a call_peer would not
    know where to go."""
    before = members()
    for iid in before:
        drop_mirror_rows(iid)
    # what this instance led it leads no more: the leases go, the rows unenroll
    try:
        conn = _identities_conn()
        owned = [r['id'] for r in conn.execute(
            'SELECT id FROM clusters WHERE fed_owner = ?',
            (instance_id(),)).fetchall()]
        for cid in owned:
            unenroll_cluster(cid)
    except Exception as e:
        logging.warning(f"[FED] could not unenroll the clusters on leave: {e}")

    def go(state):
        state['members'] = {}
        state['tombstones'] = {}
        state['pairing'] = None
        state['my_leases'] = {}
        state['lease_promises'] = {}
        return bool(before)
    _mutate(go)
    for iid, rec in before.items():
        status, _ = _deliver(rec.get('url') or '', iid, 'POST',
                             '/api/federation/peer/left', {},
                             rec.get('fingerprint') or '')
        if status != 200:
            logging.warning(f"[FED] left to {iid} answered {status or 'nothing'}")
    return bool(before)


def reconcile():
    """Ask every member for its status and take the members it lists that this
    instance lacks. A member of the federation vouches for the others, as the sealed
    join answer does; each record is checked before it is kept."""
    learned = []
    me = instance_id()
    known, gone = members(), tombstones()
    for iid in list(known.keys()):
        status, body = call_peer(iid, 'GET', '/api/federation/peer/status')
        if status != 200 or not isinstance(body, dict):
            continue
        for other in body.get('members') or []:
            if not isinstance(other, dict):
                continue
            other_id = other.get('instance_id') or ''
            if other_id in (me, '') or other_id in known or other_id in gone:
                continue
            kept = add_member({**other, 'instance_id': other_id},
                              origin=f'reconcile:{iid}')
            if kept is not None:
                # two members may list the same missing one: it is learned once
                known[other_id] = kept
                learned.append(other_id)
    return learned


# --- the calls the members make ---------------------------------------------------------

STATUS_PATH = '/api/federation/peer/status'
JOIN_PATH = '/api/federation/peer/join'


def peer_status_body():
    """What /peer/status answers: who we are, who we know, and a summary of what this
    instance manages. Counts only - no names, no addresses of clusters, no
    credentials."""
    state = _load()
    body = {'instance_id': state['instance_id'], 'fed': FED_MARK,
            'site': state.get('site') or '', 'members': [], 'summary': {}}
    for iid, rec in sorted((state.get('members') or {}).items()):
        body['members'].append({'instance_id': iid, 'url': rec.get('url') or '',
                                'site': rec.get('site') or '',
                                'public_key': rec.get('public_key') or ''})
    try:
        from pegaprox import globals as g
        body['summary'] = {'clusters': len(getattr(g, 'cluster_managers', None) or {})}
    except Exception:
        pass
    return body


def _pinned_session(fingerprint):
    """A requests session that pins the peer's certificate when a fingerprint is on
    record. The pin is the verification: the certificate of the peer itself, as the
    pairing code carried it or an admin set it. Without one the call still goes out -
    the signature tells the member, TLS only carries the bytes - and a warning says
    so, once per process."""
    import requests
    from requests.adapters import HTTPAdapter
    s = requests.Session()
    s.headers.update({'User-Agent': 'PegaProx-Federation/1'})
    if not fingerprint:
        if not _warned['tls']:
            logging.warning('[FED] federation call without a pinned certificate: the '
                            'signature tells the member, TLS only carries the bytes. '
                            'Pin the fingerprint on the member to close that gap')
            _warned['tls'] = True
        # the members' certificates are usually self-signed and the pin is the
        # verification: without one the signature carries the authentication, and
        # verification stays off instead of failing every call
        s.verify = False
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        return s

    class _Pinned(HTTPAdapter):
        def init_poolmanager(self, *args, **kw):
            kw['assert_fingerprint'] = fingerprint.lower()
            kw['assert_hostname'] = False
            kw['cert_reqs'] = 'CERT_NONE'
            return super().init_poolmanager(*args, **kw)

    s.mount('https://', _Pinned())
    return s


_warned = {'tls': False}


def _post(url, path, body, fingerprint='', timeout=10):
    """One unsigned call a join makes: the code in the body is its authorization.
    Returns (status, json or None); raises nothing."""
    transport = _runtime.get('transport')
    if transport is not None:
        return transport(url, 'POST', path, body, fingerprint, timeout)
    try:
        s = _pinned_session(fingerprint)
        r = s.post(url + path, data=ha_wire.wire_body(body), timeout=timeout,
                   headers={'Content-Type': 'application/json',
                            'X-Requested-With': PEER_XHR})
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None
    except Exception as e:
        logging.warning(f"[FED] call to {url}{path} failed: {e}")
        return 0, None


def _deliver(url, receiver, method, path, body, fingerprint='', timeout=10,
             extra_headers=None, max_answer=None):
    """One signed call to `receiver` at `url`, whatever the registry holds: the
    leaving member's push goes out after its own registry is empty. Returns (status,
    json or None); raises nothing."""
    if not url:
        return 0, None
    transport = _runtime.get('transport')
    if transport is not None:
        return transport(url, method, path, body, fingerprint, timeout)
    try:
        s = _pinned_session(fingerprint)
        headers = signed_headers(receiver, method, path, body)
        cap = max_answer if max_answer is not None else MAX_ANSWER
        if extra_headers:
            # a plain HTTP header a proxy may touch (If-None-Match): not signed, and
            # the worst a wrong one does is fetch a body that was due anyway
            headers.update({k: v for k, v in extra_headers.items()
                            if isinstance(k, str) and isinstance(v, str)})
        r = s.request(method, url + path,
                      data=ha_wire.wire_body(body) if body is not None else None,
                      headers=headers, timeout=timeout)
        if len(r.content or b'') > cap:
            logging.warning(f"[FED] answer of {url}{path} over {cap} bytes - refused")
            return r.status_code, None
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None
    except Exception as e:
        logging.warning(f"[FED] call to {url}{path} failed: {e}")
        return 0, None


def call_peer(sender, method, path, body=None, timeout=10, extra_headers=None,
              max_answer=None):
    """One signed call to a member of the federation by its instance id. Returns
    (status, json or None); raises nothing."""
    rec = member_record(sender)
    if rec is None or not rec.get('url'):
        return 0, None
    return _deliver(rec['url'], sender, method, path, body,
                    rec.get('fingerprint') or '', timeout, extra_headers, max_answer)


def push(sender, path, body):
    """One best-effort notice to one member; a failure is a line in the log, the
    reconcile covers it later."""
    status, _ = call_peer(sender, 'POST', f'/api/federation/peer/{path}', body)
    if status not in (200, 409):
        logging.warning(f"[FED] {path} to {sender} answered {status or 'nothing'}")


def push_all(path, body):
    for iid in list(members().keys()):
        push(iid, path, body)


# --- identity federation (Phase 2) -------------------------------------------------------
#
# What travels between the members of a federation: the users, their custom roles
# and their API tokens, each row saying which instance it is homed at. A row homed
# at A is a mirror on B and C: the login stack reads it like a local row (the
# password hash travels, the token hashes travel - a token drawn at A works against
# B and C), but only the home writes it. B and C refuse the write with a sentence
# that names the home, and a delete travels as a tombstone in the snapshot, so a
# pull cannot bring back what the home took out.
#
# The columns are an allowlist: what a user is and may do travels, the workbench
# (theme, layout, avatar, last_login, the pending TOTP enrolment) stays where it is
# set - a user that signs in on another site keeps their own desk there.

IDENTITY_TABLES = ('users', 'custom_roles', 'api_tokens', 'webauthn_credentials')
IDENTITY_KIND = {'users': 'user', 'custom_roles': 'role', 'api_tokens': 'token',
                 'webauthn_credentials': 'webauthn'}
# a security key is identity too: without it a key-only account signs in at a mirror
# on the password alone. The credentials travel as base64 (the columns are BLOBs);
# the key of a credential is its credential_id, hex-encoded on the wire.
BLOB_COLUMNS = {'webauthn_credentials': ('credential_id', 'public_key', 'user_handle')}
JSON_COLUMNS = {'permissions', 'ldap_permissions', 'tenant_permissions',
                'denied_permissions', 'directory_groups'}
IDENTITY_COLUMNS = {
    'users': ('username', 'password_salt', 'password_hash', 'role', 'permissions',
              'tenant', 'created_at', 'password_expiry',
              'totp_enabled', 'enabled', 'auth_source', 'display_name', 'email',
              'ldap_dn', 'ldap_permissions', 'ldap_tenant', 'tenant_permissions',
              'denied_permissions', 'oidc_sub', 'directory_groups'),
    'custom_roles': ('name', 'permissions', 'description', 'tenant_id', 'created_at'),
    'api_tokens': ('token_hash', 'token_prefix', 'username', 'name', 'role',
                   'permissions', 'expires_at', 'created_at', 'revoked'),
    'webauthn_credentials': ('username', 'credential_id', 'public_key', 'sign_count',
                             'transports', 'aaguid', 'name', 'user_handle',
                             'created_at'),
}
IDENTITY_KEYS = {'users': ('username',), 'custom_roles': ('name', 'tenant_id'),
                 'api_tokens': ('token_hash',),
                 'webauthn_credentials': ('credential_id',)}
# Columns a mirror writes empty however the row comes: a TOTP secret travels as
# ciphertext under the HOME's field key, and no other instance can open it - left
# in place it would break every reader of the table (db._decrypt raises on foreign
# ciphertext). totp_enabled still travels: the mirror then refuses the sign-in of
# such a user outright (its second factor lives at the home), it never falls back
# to the password alone.
PER_TABLE_CLEAR = {'users': ('totp_secret_encrypted',)}
IDENTITIES_PATH = '/api/federation/peer/identities'


def _identities_conn():
    from pegaprox.core.db import get_db
    return get_db().conn


def identity_rows(table, home=None):
    """The rows of `table` homed at `home` (this instance when left out), as dicts of
    the columns that travel. Nothing else reads the table here - the login stack
    reads the rows where they lie, mirrored or not."""
    if table not in IDENTITY_TABLES:
        return []
    import base64 as _b64
    cols = ', '.join(f'"{c}"' for c in IDENTITY_COLUMNS[table])
    keys = IDENTITY_KEYS[table]
    order = ', '.join(f'COALESCE("{k}", \'\')' for k in keys)
    sql = f'SELECT {cols} FROM "{table}" WHERE fed_home = ? ORDER BY {order}'
    try:
        cur = _identities_conn().execute(sql, (home if home is not None else '',))
    except Exception as e:
        logging.warning(f"[FED] could not read {table} for the snapshot: {e}")
        return []
    blobs = BLOB_COLUMNS.get(table) or ()
    out = []
    for r in cur.fetchall():
        row = dict(r)
        for c in blobs + (keys[0],) if table in BLOB_COLUMNS else blobs:
            if isinstance(row.get(c), (bytes, bytearray)):
                row[c] = _b64.b64encode(bytes(row[c])).decode()
        out.append(row)
    return out


def identity_tombstones(home=None):
    """The deletions this instance (or `home`) has noted, as the snapshot carries
    them: a home that deleted a row says so, and a pull applies that before the
    rows, so a mirror of the deleted row goes even if the puller never held the
    row's latest state. The default is this instance - note_identity_delete writes
    under its own id, not under the empty string."""
    try:
        cur = _identities_conn().execute(
            'SELECT kind, key, at FROM federation_identity_tombstones WHERE home = ?',
            (home if home is not None else instance_id(),))
        return [{'kind': r['kind'], 'key': r['key'], 'at': r['at']} for r in cur.fetchall()]
    except Exception as e:
        logging.warning(f"[FED] could not read the identity tombstones: {e}")
        return []


# the note table is bounded: the diff delete (a mirror row the snapshot no longer
# lists) covers whatever an old tombstone would have said, so the oldest notes go
# when the table grows past this
MAX_IDENTITY_TOMBSTONES = 256


def note_identity_delete(kind, key):
    """The home's half of a delete: note it, so the next snapshot tells the others.
    Called where the row is deleted - the guards live in the routes."""
    me = instance_id()
    try:
        conn = _identities_conn()
        conn.execute(
            'INSERT INTO federation_identity_tombstones (kind, key, home, at) '
            'VALUES (?, ?, ?, ?) ON CONFLICT(kind, key) DO UPDATE SET at = excluded.at',
            (kind, key, me, int(time.time())))
        # bounded by mine alone, and only mine: a peer's notes are not ours to drop
        cur = conn.execute('SELECT COUNT(*) AS n FROM federation_identity_tombstones '
                           'WHERE home = ?', (me,))
        if cur.fetchone()['n'] > MAX_IDENTITY_TOMBSTONES:
            conn.execute(
                'DELETE FROM federation_identity_tombstones WHERE rowid IN ('
                '  SELECT rowid FROM federation_identity_tombstones WHERE home = ? '
                '  ORDER BY at ASC LIMIT ?)', (me, MAX_IDENTITY_TOMBSTONES // 2))
        conn.commit()
    except Exception as e:
        logging.warning(f"[FED] could not note the delete of {kind} {key}: {e}")


def identity_snapshot_body():
    """What /peer/identities answers: the rows homed here and the deletes noted
    here, with the etag over all of it. Nothing homed at a peer is served - a
    member answers for itself alone."""
    body = {'home': instance_id(), 'fed': FED_MARK, 'etag': '', 'tombstones': [],
            'rows': {}}
    canon = ''
    present = set()
    for table in IDENTITY_TABLES:
        rows = identity_rows(table)
        body['rows'][table] = rows
        canon += json.dumps(rows, separators=(',', ':'), sort_keys=True)
        for row in rows:
            key_vals = _key_of(row, IDENTITY_KEYS[table])
            if key_vals is not None:
                present.add((IDENTITY_KIND[table], '\x1f'.join(key_vals)))
    # a delete the home has taken back by re-creating the row is no delete: the
    # puller would apply the tombstone of a row that is due again
    body['tombstones'] = [t for t in identity_tombstones()
                          if (t.get('kind'), t.get('key')) not in present]
    canon = json.dumps(body['tombstones'], separators=(',', ':'), sort_keys=True) + canon
    # Phase 4: the clusters this instance leads travel with the same answer
    c_rows, c_canon = _cluster_mirror_body()
    body['clusters'] = c_rows
    body['etag'] = hashlib.sha256((canon + c_canon).encode()).hexdigest()
    return body


def _key_where(keys):
    """The WHERE of a table's key columns. tenant_id may be NULL in a table whose
    key it is, and NULL is not '=' to anything in SQL, not even to NULL: COALESCE
    makes an empty key match a NULL column, and the sync treats both as the same
    'no tenant'."""
    return ' AND '.join(f'COALESCE("{k}", \'\') = COALESCE(?, \'\')' for k in keys)


def _key_of(row, keys):
    """The key values of an incoming row, None as '' - or None when the row is no
    identity (a missing or non-string key). Only the first key part has to say
    something: a custom role of no tenant carries '' as its second, and that is a
    global role, not a broken row."""
    vals = tuple('' if row.get(k) is None else row.get(k) for k in keys)
    if not all(isinstance(v, str) for v in vals) or not vals[0]:
        return None
    return vals


def apply_identity_snapshot(body, sender=None):
    """Take a snapshot another member signed for us: mirrors of its rows up to
    date, its deletes applied, our own rows never touched. Returns the report the
    admin route shows; raises FederationError for a body that is no snapshot.

    `sender` is the member the pull verified (peer_verdict) - the home a body may
    claim is that member and no other, so no member can write rows under a third
    one's name. A direct call without a sender (a repair tool reading a saved
    snapshot) still gets the format checks, but no membership claim."""
    if not isinstance(body, dict) or body.get('fed') != FED_MARK \
            or not isinstance(body.get('rows'), dict):
        raise FederationError('That answer is no identity snapshot')
    home = body.get('home') or ''
    if not ha_wire.ID_RE.fullmatch(home) or home == instance_id():
        raise FederationError('That snapshot names no member of this federation')
    if sender is not None and sender != home:
        raise FederationError('That snapshot claims a home its sender is not')
    if sender is not None and member_record(sender) is None:
        raise FederationError('That snapshot\'s sender is no member of this federation')
    import base64 as _b64
    rows_in, tombs_in = body['rows'], body.get('tombstones') or []
    report = {'applied': 0, 'updated': 0, 'deleted': 0, 'tombstoned': 0,
              'conflicts': []}
    changed_users = set()
    dropped_users = set()
    conn = _identities_conn()
    try:
        conn.execute('BEGIN IMMEDIATE')
    except Exception:
        pass
    try:
        # the deletes go first: a row the home re-created after a delete is a fresh
        # identity, and it survives the tombstone of its old self
        for tomb in tombs_in:
            if not isinstance(tomb, dict):
                continue
            kind, key = tomb.get('kind'), tomb.get('key')
            if kind not in IDENTITY_KIND.values() or not isinstance(key, str) or not key:
                continue
            table = next(t for t, k in IDENTITY_KIND.items() if k == kind)
            keys = IDENTITY_KEYS[table]
            key_vals = tuple(key.split('\x1f')) if len(keys) > 1 else (key,)
            if len(key_vals) != len(keys):
                continue
            if table in BLOB_COLUMNS:
                key_vals = tuple(_b64.b64decode(v) for v in key_vals)
            _drop_row(conn, table, keys, key_vals, home, dropped_users)
            report['tombstoned'] += 1
        for table in IDENTITY_TABLES:
            kind = IDENTITY_KIND[table]
            keys, cols = IDENTITY_KEYS[table], IDENTITY_COLUMNS[table]
            kwhere = _key_where(keys)
            incoming = rows_in.get(table) or []
            if not isinstance(incoming, list):
                continue
            blobs = BLOB_COLUMNS.get(table) or ()
            keep = set()
            for row in incoming:
                if not isinstance(row, dict):
                    continue
                key_vals = _key_of(row, keys)
                if key_vals is None:
                    continue
                # a column that is JSON in the table must arrive as JSON, or the
                # mirror breaks for every reader the way a foreign ciphertext did
                bad = [c for c in cols if c in JSON_COLUMNS
                       and not _plain_json(row.get(c))]
                if bad:
                    report['conflicts'].append(
                        f'{kind} "{key_vals[0]}" carries no readable {bad[0]}')
                    continue
                sql_keys = tuple(_b64.b64decode(v) for v in key_vals) if blobs \
                    else key_vals
                keep.add(key_vals)
                # password_hash and enabled exist on users alone; the change watch
                # (sessions of a re-passworded or disabled account) reads them there
                watch = ', password_hash, enabled' if table == 'users' else ''
                held = conn.execute(
                    f'SELECT fed_home{watch} FROM "{table}" '
                    f'WHERE {kwhere}', sql_keys).fetchone()
                if held is not None and held['fed_home'] != home:
                    # a local row, or another home's mirror: never overwritten by a
                    # snapshot - the collision goes to the report instead
                    report['conflicts'].append(f'{kind} "{key_vals[0]}" homed here')
                    continue
                if kind == 'role' and _clashes_locally(conn, keys, key_vals):
                    # a tenant role of another home must not shadow a local role of
                    # the same name: rbac resolves the name across namespaces
                    report['conflicts'].append(
                        f'role "{key_vals[0]}" would shadow a local role of that name')
                    continue
                values = dict((c, row.get(c)) for c in cols if c not in keys)
                for c in blobs:
                    v = values.get(c)
                    values[c] = _b64.b64decode(v) if isinstance(v, str) else v
                clear = PER_TABLE_CLEAR.get(table) or ()
                if held is None:
                    fields = ', '.join(f'"{c}"' for c in cols) + ''.join(
                        f', "{c}"' for c in clear) + ', fed_home'
                    marks = ', '.join('?' * (len(cols) + len(clear) + 1))
                    ins_vals = [values.get(c) if c not in keys
                                else dict(zip(keys, sql_keys))[c] for c in cols]
                    conn.execute(f'INSERT INTO "{table}" ({fields}) VALUES ({marks})',
                                 ins_vals + [''] * len(clear) + [home])
                    report['applied'] += 1
                else:
                    sets = ', '.join(f'"{c}" = ?' for c in cols if c not in keys)
                    sets += ''.join(f", \"{c}\" = ''" for c in clear)
                    vals = [values.get(c) for c in cols if c not in keys]
                    conn.execute(f'UPDATE "{table}" SET {sets}, fed_home = ? '
                                 f'WHERE {kwhere}',
                                 vals + [home, *sql_keys])
                    report['updated'] += 1
                if kind == 'user':
                    if held is None or (held['password_hash'] or '') != (row.get('password_hash') or '') \
                            or (1 if row.get('enabled') else 0) != (1 if held['enabled'] else 0):
                        changed_users.add(key_vals[0])
            # a mirror of this home that the snapshot no longer lists is gone at the
            # home: gone here too. Local rows are not in the WHERE and stay.
            for held_row in conn.execute(
                    f'SELECT {", ".join(keys)} FROM "{table}" WHERE fed_home = ?',
                    (home,)).fetchall():
                raw = tuple('' if held_row[k] is None else held_row[k] for k in keys)
                # the wire form of a blob key is base64, as the snapshot carries it
                key_vals = tuple(_b64.b64encode(v).decode() if isinstance(v, bytes)
                                 else v for v in raw)
                if key_vals not in keep:
                    _drop_row(conn, table, keys, raw, home, dropped_users, key_vals)
                    report['deleted'] += 1
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    # Phase 4: the clusters the home leads become mirrors here - credentials as
    # ciphertext under the home's field key, opened only at an adoption
    try:
        _apply_cluster_mirrors(home, body.get('clusters'), report)
        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logging.warning(f"[FED] cluster mirrors of {home} not applied: {e}")
    # what a mirror lost or had changed on it ends the sessions it opened here: a
    # disabled or re-passworded account does not keep a sign-in at this site
    for name in sorted(changed_users | dropped_users):
        _end_sessions_of(name)
    # a role that arrived or left changes what the permission checks resolve against
    try:
        from pegaprox.utils import rbac
        rbac.invalidate_roles_cache()
    except Exception:
        pass
    _note_pull(home, body.get('etag') or '', report)
    return report


def _plain_json(value):
    """Whether `value` is the string of a JSON array/object, or empty - what the
    JSON columns of the identity tables hold."""
    if not isinstance(value, str) or not value:
        return True
    try:
        json.loads(value)
        return True
    except Exception:
        return False


def _clashes_locally(conn, keys, key_vals):
    """Whether an incoming role would shadow a local role: a local row of the same
    name under a different tenant key. RBAC resolves roles by name across
    namespaces, so a mirrored tenant role must not sit on a local name."""
    if keys != IDENTITY_KEYS['custom_roles'] or len(key_vals) < 2:
        return False
    row = conn.execute("SELECT 1 FROM custom_roles WHERE COALESCE(name, '') = "
                       "COALESCE(?, '') AND COALESCE(tenant_id, '') != COALESCE(?, '') "
                       "AND fed_home = ''", (key_vals[0], key_vals[1])).fetchone()
    return row is not None


def _drop_row(conn, table, keys, sql_keys, home, dropped_users, logical_keys=None):
    """Delete one mirrored row (and what hangs on it, for a user: grants, favorites,
    open sessions), under the home the snapshot names."""
    kwhere = _key_where(keys)
    if table == 'users':
        name = (logical_keys or sql_keys)[0]
        try:
            from pegaprox.core.db import get_db
            get_db().purge_user_grants(name)
            conn.execute('DELETE FROM user_favorites WHERE username = ?', (name,))
        except Exception as e:
            logging.warning(f"[FED] could not purge the grants of {name}: {e}")
        dropped_users.add(name)
    conn.execute(f'DELETE FROM "{table}" WHERE {kwhere} AND fed_home = ?',
                 (*sql_keys, home))


def _end_sessions_of(username):
    try:
        from pegaprox.utils.auth import invalidate_all_user_sessions
        invalidate_all_user_sessions(username)
    except Exception as e:
        logging.warning(f"[FED] could not end the sessions of {username}: {e}")


def _note_pull(home, etag, report):
    try:
        conn = _identities_conn()
        conn.execute(
            'INSERT INTO federation_sync_state (peer, etag, pulled_at, rows) '
            'VALUES (?, ?, ?, ?) ON CONFLICT(peer) DO UPDATE SET etag = excluded.etag, '
            'pulled_at = excluded.pulled_at, rows = excluded.rows',
            (home, etag, int(time.time()),
             report.get('applied', 0) + report.get('updated', 0)))
        conn.commit()
    except Exception as e:
        logging.warning(f"[FED] could not note the pull of {home}: {e}")


def foreign_home(table, key_vals):
    """The instance a row of an identity table is homed at: '' when it is ours or
    nobody's. The guards in the routes ask this before a write goes through - the
    home decides, everything else refuses with the instance it names."""
    if table not in IDENTITY_TABLES:
        return ''
    try:
        row = _identities_conn().execute(
            f'SELECT fed_home FROM "{table}" WHERE {_key_where(IDENTITY_KEYS[table])}',
            tuple(key_vals)).fetchone()
    except Exception as e:
        # fail closed for the guards: a table that cannot be read is no reason to
        # treat a row as anybody's to write
        raise FederationError(f'The {table} table cannot be read: {e}')
    home = (row['fed_home'] if row is not None else '') or ''
    return home if home and home != instance_id() else ''


def sync_state():
    """What the status shows: the last pull of every member."""
    try:
        cur = _identities_conn().execute(
            'SELECT peer, etag, pulled_at, rows FROM federation_sync_state')
        return {r['peer']: {'etag': r['etag'], 'pulled_at': r['pulled_at'],
                            'rows': r['rows']} for r in cur.fetchall()}
    except Exception:
        return {}


def pull_identities(sender, extra_headers=None):
    """Pull the identities of member `sender`: 304 when nothing changed since the
    last pull, else the snapshot applied. Returns a report or None for nothing to
    do; raises nothing."""
    rec = member_record(sender)
    if rec is None or not rec.get('url'):
        return None
    headers = dict(extra_headers or {})
    state = sync_state().get(sender) or {}
    if state.get('etag'):
        headers['If-None-Match'] = state['etag']
    # an identity table holds rows, not a member list: the cap sits higher than the
    # general one, and what exceeds it fails loudly in the report, never silently
    status, body = call_peer(sender, 'GET', IDENTITIES_PATH, None,
                             extra_headers=headers, max_answer=16 * 1024 * 1024)
    if status == 304 and state.get('etag'):
        _note_pull(sender, state['etag'], {'applied': 0, 'updated': 0})
        return {'unchanged': True}
    if status == 304:
        # nothing was held that this could confirm - a wrong answer, not a shortcut
        logging.warning(f"[FED] identity pull from {sender} answered 304 unsolicited")
        return {'failed': True}
    if status != 200 or not isinstance(body, dict):
        logging.warning(f"[FED] identity pull from {sender} answered {status or 'nothing'}")
        return {'failed': True}
    if body.get('etag') and state.get('etag') == body.get('etag'):
        _note_pull(sender, state['etag'], {'applied': 0, 'updated': 0})
        return {'unchanged': True}
    try:
        return apply_identity_snapshot(body, sender=sender)
    except Exception as e:
        logging.warning(f"[FED] identity pull from {sender} refused: {e}")
        return {'failed': True}


def sync_identities():
    """Pull every member; the report the admin route shows. The joins of the
    federation are independent: one member's failure to answer never stops the
    others."""
    out = {}
    for iid in members():
        out[iid] = pull_identities(iid) or {'failed': True}
    return out


# --- partition leases (Phase 3) ----------------------------------------------------------
#
# A cluster of this instance that is enrolled in the federation is written to only
# while a majority of the members backs this instance's lease on it - the
# three-leader rule: each site leads its own clusters, and no network split lets
# two sites lead the same one.
#
# The safety rules are ha_vote's, carried over the federation's signed peer calls:
# a promise is ON DISK before the vote goes out (a voter that crashes and comes
# back keeps its word), a term is monotonic per cluster, and a new candidate is
# granted only once the old promise has run out (plus a skew allowance, so clocks
# a few seconds apart cannot let two writers in). The owner stops writing before
# its lease runs out (the write margin), and renews on a third of the lease.

LEASE_SECONDS = 30
LEASE_RENEW_AFTER = 10
LEASE_WRITE_MARGIN = 2.0
# how long a voter holds a promise beyond its end before another candidate may
# have it: the clocks of the members may be this far apart (ha_vote's SKEW_LIMIT)
LEASE_SKEW = 5
CLUSTER_ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
LEASE_PATH = '/api/federation/peer/lease-vote'
# how many promises a voter keeps note of at most (expired ones go first)
MAX_PROMISES = 256


def _lease_now():
    """The lease clock: CLOCK_BOOTTIME where there is one, the monotonic clock
    otherwise. A wall clock that jumps - NTP stepping back, a VM restore - must
    not lengthen a lease past its end or wake a promise early; ha_vote keeps its
    lease on the same clock for the same reason."""
    try:
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        return time.monotonic()


def _lease_check_vote(candidate, cluster_id, term, lease_s, now=None):
    """The voter's half, one request: (verdict-dict, granted-promise-or-None).
    Rules above; the caller persists the promise before it answers."""
    now = _lease_now() if now is None else now
    if not ha_wire.ID_RE.fullmatch(candidate or ''):
        return {'granted': False, 'reason': 'candidate'}, None
    if not CLUSTER_ID_RE.fullmatch(cluster_id or ''):
        return {'granted': False, 'reason': 'cluster'}, None
    if not isinstance(term, int) or isinstance(term, bool) or not 0 < term < 1 << 30:
        return {'granted': False, 'reason': 'term'}, None
    lease_s = lease_s if isinstance(lease_s, int) and 5 <= lease_s <= 300 \
        else LEASE_SECONDS
    if candidate not in members() and candidate != instance_id():
        return {'granted': False, 'reason': 'member'}, None
    with _lock:
        state = _load()
        promised = (state.get('lease_promises') or {}).get(cluster_id) or {}
        held_term, held_by, held_until = (promised.get('term') or 0,
                                          promised.get('candidate') or '',
                                          promised.get('until') or 0)
        if term == held_term and candidate == held_by:
            until = now + lease_s
            return {'granted': True, 'term': term, 'until': until}, \
                {'term': term, 'candidate': candidate, 'until': until}
        # a new word on the cluster steps the term by exactly one - no jumps, or a
        # member could sit on a huge term and starve the cluster's writers forever
        if term == held_term + 1 and (candidate == held_by or held_until == 0
                                      or now > held_until + LEASE_SKEW):
            until = now + lease_s
            return {'granted': True, 'term': term, 'until': until}, \
                {'term': term, 'candidate': candidate, 'until': until}
        return {'granted': False, 'reason': 'held', 'term_held': held_term,
                'until': held_until}, None


def lease_vote(sender, body):
    """The peer route's work: check the call, persist the promise on disk BEFORE
    the grant leaves (a crash between the two keeps the word), answer."""
    if not isinstance(body, dict):
        return {'granted': False, 'reason': 'body'}
    release = body.get('release') is True
    candidate = body.get('candidate') or ''
    cluster_id = body.get('cluster_id') or ''
    # a member asks for its own lease - nobody vouches for another's
    if candidate != sender:
        return {'granted': False, 'reason': 'candidate'}
    if release:
        return _lease_release(sender, cluster_id)
    verdict, promise = _lease_check_vote(candidate, cluster_id, body.get('term'),
                                         body.get('lease_s'))
    if promise is not None:

        def go(state):
            promises = state.setdefault('lease_promises', {})
            promises[cluster_id] = promise
            # bounded: only promises that are over go, never a live one, and a
            # member flooding terms cannot grow the state without end
            if len(promises) > MAX_PROMISES:
                for cid in [c for c, r in promises.items()
                            if (r.get('until') or 0) < _lease_now()]:
                    del promises[cid]
            return True
        _mutate(go)
    return verdict


def _lease_release(sender, cluster_id):
    """The old owner's word that it is done: the promise goes (its term stays, so
    an old vote of it cannot come back and win)."""
    if not CLUSTER_ID_RE.fullmatch(cluster_id or ''):
        return {'released': False, 'reason': 'cluster'}

    out = {}

    def go(state):
        promised = (state.get('lease_promises') or {}).get(cluster_id)
        if not promised or promised.get('candidate') != sender:
            out['no'] = True
            return False
        promised['until'] = 0
        return True
    _mutate(go)
    return {'released': not out.get('no')}


def my_leases():
    return dict(_load().get('my_leases') or {})


def lease_status(cluster_id=None):
    """What the status shows: the leases held here and the promises given."""
    state = _load()
    leases = dict(state.get('my_leases') or {})
    if cluster_id is not None:
        leases = {cluster_id: leases.get(cluster_id)} if cluster_id in leases else {}
    now = _lease_now()
    out = {'leases': {}, 'promises': {}}
    for cid, rec in leases.items():
        out['leases'][cid] = dict(rec, valid=now < (rec.get('expires') or 0))
    for cid, rec in (state.get('lease_promises') or {}).items():
        out['promises'][cid] = dict(rec)
    return out


def _vote_round(cluster_id, candidate, term, lease_s):
    """One round of asks: the peers over the wire, this instance through the same
    rules on its own state. Returns (granted-count, highest-term-anyone-holds)."""
    me = instance_id()
    granted, held_high = 0, 0
    verdict, promise = _lease_check_vote(candidate, cluster_id, term, lease_s)
    if promise is not None:
        # self-vote: on disk first, like every other vote
        def go(state):
            state.setdefault('lease_promises', {})[cluster_id] = promise
            return True
        _mutate(go)
        granted += 1
    elif verdict.get('reason') == 'held':
        held_high = max(held_high, verdict.get('term_held') or 0)
    body = {'cluster_id': cluster_id, 'candidate': candidate, 'term': term,
            'lease_s': lease_s}
    for iid in members():
        status, answer = call_peer(iid, 'POST', LEASE_PATH, body)
        if status == 200 and isinstance(answer, dict) and answer.get('granted'):
            granted += 1
        elif isinstance(answer, dict):
            held_high = max(held_high, answer.get('term_held') or 0)
    return granted, held_high


def _needed_votes():
    """Majority of the members including this one (majority as ha_vote counts it:
    n // 2 + 1).
    """
    return (len(members()) + 1) // 2 + 1


def acquire_lease(cluster_id, lease_s=None):
    """Become the writer of `cluster_id`, with a majority behind it. Returns the
    lease, or why it did not work (a lease still held elsewhere says when its
    holder's time is up, so a claim can wait)."""
    lease_s = lease_s if isinstance(lease_s, int) and 5 <= lease_s <= 300 \
        else LEASE_SECONDS
    me = instance_id()
    held = my_leases().get(cluster_id) or {}
    term = int(held.get('term') or 0) + 1
    granted, held_high = _vote_round(cluster_id, me, term, lease_s)
    if granted < _needed_votes() and held_high >= term:
        # somebody holds a newer word on this cluster: ask again past its end
        term = int(held_high) + 1
        granted, held_high = _vote_round(cluster_id, me, term, lease_s)
    if granted < _needed_votes():
        return {'failed': True, 'term': term, 'votes': granted,
                'needed': _needed_votes()}
    lease = {'term': term, 'expires': _lease_now() + lease_s - LEASE_WRITE_MARGIN,
             'votes': granted}

    def go(state):
        state.setdefault('my_leases', {})[cluster_id] = lease
        return True
    _mutate(go)
    return dict(lease, cluster_id=cluster_id)


def renew_leases():
    """Every lease held here gets its round; one that no majority backs simply
    runs out where its clock says, and the gates close on their own."""
    now = _lease_now()
    out = {}
    for cid, rec in list(my_leases().items()):
        if now > rec.get('expires', 0) + LEASE_SECONDS * 2:
            def drop(state, _cid=cid):
                state.get('my_leases', {}).pop(_cid, None)
                return True
            _mutate(drop)
            out[cid] = {'dropped': True}
            continue
        granted, held_high = _vote_round(cid, instance_id(), int(rec.get('term') or 0),
                                         LEASE_SECONDS)
        if granted >= _needed_votes():
            fresh = {'term': rec.get('term'),
                     'expires': now + LEASE_SECONDS - LEASE_WRITE_MARGIN,
                     'votes': granted}

            def go(state, _cid=cid, _fresh=fresh):
                state.setdefault('my_leases', {})[_cid] = _fresh
                return True
            _mutate(go)
            out[cid] = {'renewed': True}
        else:
            out[cid] = {'renewed': False, 'votes': granted}
    return out


def release_lease(cluster_id):
    """Give the cluster up: the voters hear it, the lease here goes, the row is
    this instance's alone again (no owner, no gate)."""
    me = instance_id()
    held = my_leases().get(cluster_id)
    body = {'cluster_id': cluster_id, 'candidate': me, 'release': True}
    for iid in members():
        call_peer(iid, 'POST', LEASE_PATH, body)

    def go(state):
        state.get('my_leases', {}).pop(cluster_id, None)
        # our own promise goes too - we just said we are done
        promised = (state.get('lease_promises') or {}).get(cluster_id)
        if promised and promised.get('candidate') == me:
            promised['until'] = 0
        return True
    _mutate(go)
    # the row stays enrolled with this instance as its owner: the gate stays shut
    # (an owner without a lease writes nothing) while the next one takes over. A
    # full unenroll is its own step, said with the word below.
    return True


def unenroll_cluster(cluster_id):
    """Take a cluster out of the federation's rule altogether: the lease goes and
    the row is this instance's alone again. Only the owner (or a row with no
    owner) unenrolls - nobody lifts another member's enrollment."""
    owner = cluster_owner(cluster_id)
    if owner and owner != instance_id():
        raise FederationError('That cluster belongs to another member')
    release_lease(cluster_id)
    _set_cluster_owner(cluster_id, '')
    return True


def _set_cluster_owner(cluster_id, owner):
    try:
        conn = _identities_conn()
        conn.execute('UPDATE clusters SET fed_owner = ? WHERE id = ?',
                     (owner, cluster_id))
        conn.commit()
    except Exception as e:
        logging.warning(f"[FED] could not set the owner of cluster {cluster_id}: {e}")


def cluster_owner(cluster_id):
    """The member a cluster row says its writes belong to: '' for one this
    instance holds alone, None for a row that is not there. A table that cannot
    be read says '' (the gate's own fail-closed answer covers it)."""
    try:
        row = _identities_conn().execute(
            'SELECT fed_owner FROM clusters WHERE id = ?', (cluster_id,)).fetchone()
        if row is None:
            return None
        return (row['fed_owner'] or '') or ''
    except Exception:
        return ''


def takes_writes_for(cluster_id):
    """The gate every write on a cluster goes through. A cluster not enrolled in
    the federation ('') is this instance's own, no lease asked; an enrolled one is
    written to only while THIS instance holds a live lease on it - the row names
    the owner, the clock names the moment, and the margin keeps the two apart."""
    owner = cluster_owner(cluster_id)
    if not owner:
        # no row (None) or an unenrolled row (''): nothing the federation rules
        return True
    if owner != instance_id():
        return False
    lease = my_leases().get(cluster_id)
    return bool(lease and _lease_now() < (lease.get('expires') or 0))


def enroll_cluster(cluster_id):
    """Put a local cluster under the federation's rule: this instance becomes the
    writer, with a majority behind it. Without a majority the row stays as it was."""
    if not members():
        raise FederationError('No federation to enroll a cluster in - pair first')
    if not CLUSTER_ID_RE.fullmatch(cluster_id or ''):
        raise FederationError('That cluster id cannot be enrolled')
    owner = cluster_owner(cluster_id)
    if owner is None:
        raise FederationError('No such cluster here')
    if owner and owner != instance_id():
        raise FederationError('That cluster belongs to another member')
    # the owner first: a crash after this and before the lease leaves the gate
    # shut on an unleased cluster (fail closed), and the next attempt heals it
    _set_cluster_owner(cluster_id, instance_id())
    lease = acquire_lease(cluster_id)
    if lease.get('failed'):
        _set_cluster_owner(cluster_id, owner)
        raise FederationError(f'The federation did not back the lease '
                              f'({lease.get("votes")}/{lease.get("needed")} votes)')
    if cluster_owner(cluster_id) != instance_id():
        # the row did not take the owner (the audit's D10): no gate, no lease
        def drop(state):
            state.get('my_leases', {}).pop(cluster_id, None)
            return True
        _mutate(drop)
        raise FederationError('The cluster row did not hold its owner - try again')
    return lease


# --- cluster replication (Phase 4) -------------------------------------------------------
#
# What a federation member leads, the others shadow: an enrolled cluster's row -
# credentials included, as ciphertext under the owner's field key - mirrors to every
# member with the identity sync. A mirror is not managed here (no manager, no
# listing, no writes: the Phase 3 gate answers FED_FOREIGN for it), it is the
# disaster-recovery copy. When the owner is gone for good, a member adopts the
# cluster: the voters hand it the lease (their promises enforce the old owner's
# lease having run out - the protocol fence), and the mirrored credentials open
# under the owner's field key, exchanged sealed at the pairing, and re-encrypt
# under this instance's own key.

# what travels of a cluster row: everything but the home marker itself
CLUSTER_SYNC_COLUMNS = ('id', 'name', 'host', 'user', 'pass_encrypted',
                        'ssl_verification', 'migration_threshold',
                        'migration_tolerance', 'check_interval', 'auto_migrate',
                        'balance_containers', 'balance_local_disks', 'dry_run',
                        'enabled', 'ha_enabled', 'fallback_hosts', 'ssh_user',
                        'ssh_key_encrypted', 'ssh_port', 'api_port', 'ha_settings',
                        'created_at', 'updated_at', 'cluster_type',
                        'transfer_network')


def enrolled_cluster_rows():
    """The cluster rows this instance leads (enrolled: fed_owner names this
    instance) - what the snapshot carries to the other members."""
    try:
        cur = _identities_conn().execute(
            'SELECT %s FROM clusters WHERE fed_owner = ? ORDER BY id'
            % ', '.join(f'"{c}"' for c in CLUSTER_SYNC_COLUMNS), (instance_id(),))
        return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logging.warning(f"[FED] could not read the enrolled clusters: {e}")
        return []


def _apply_cluster_mirrors(home, rows_in, report):
    """The mirror half of the cluster sync: rows the home leads become mirrors
    here. A local cluster (unenrolled, '') or one this instance leads is never
    touched - an id that collides goes to the report, not over the local row."""
    if not isinstance(rows_in, list):
        return
    conn = _identities_conn()
    cols = CLUSTER_SYNC_COLUMNS
    keep = set()
    for row in rows_in:
        if not isinstance(row, dict):
            continue
        cid = row.get('id')
        if not isinstance(cid, str) or not CLUSTER_ID_RE.fullmatch(cid):
            continue
        keep.add(cid)
        held = conn.execute('SELECT fed_owner FROM clusters WHERE id = ?',
                            (cid,)).fetchone()
        if held is not None and held['fed_owner'] != home:
            report['conflicts'].append(f'cluster "{cid}" homed here')
            continue
        values = [row.get(c) for c in cols if c != 'id']
        if held is None:
            fields = ', '.join(f'"{c}"' for c in cols) + ', fed_owner'
            marks = ', '.join('?' * (len(cols) + 1))
            conn.execute(f'INSERT INTO clusters ({fields}) VALUES ({marks})',
                         [cid] + values + [home])
            report['applied'] += 1
        else:
            sets = ', '.join(f'"{c}" = ?' for c in cols if c != 'id')
            conn.execute(f'UPDATE clusters SET {sets} WHERE id = ?',
                         values + [cid])
            report['updated'] += 1
    # a mirror of the home that the snapshot no longer lists is gone at the home:
    # gone here too. Local rows and this instance's own are not in the WHERE.
    for held_row in conn.execute('SELECT id FROM clusters WHERE fed_owner = ?',
                                 (home,)).fetchall():
        if held_row['id'] not in keep:
            conn.execute('DELETE FROM clusters WHERE id = ? AND fed_owner = ?',
                         (held_row['id'], home))
            report['deleted'] += 1


def _cluster_mirror_body():
    """The clusters section of the snapshot, with the etag over it."""
    rows = enrolled_cluster_rows()
    canon = json.dumps(rows, separators=(',', ':'), sort_keys=True)
    return rows, canon


# --- the adoption (Phase 4) ---------------------------------------------------------------
#
# A member that is gone for good has its clusters taken over by another: the
# voters hand out the lease only past the old promise (the protocol fence - a
# live owner's lease blocks the adoption at every voter), the mirrored row is
# already here, and its credentials open under the owner's field key, exchanged
# sealed at the pairing, and seal again under this instance's own key.

CLUSTER_ENCRYPTED_COLUMNS = ('pass_encrypted', 'ssh_key_encrypted', 'ha_settings')


def _field_key_file():
    return os.path.join(CONFIG_DIR, '.pegaprox_aes256.key')


def field_key_b64():
    """This instance's field key (the AES-256 key the credential columns are
    sealed under), as base64 - what the sealed join answer carries. The living
    database holds its raw bytes; the file is the fallback."""
    try:
        from pegaprox.core.db import get_db
        raw = getattr(get_db(), 'aes_key', None)
        if isinstance(raw, (bytes, bytearray)) and len(raw) == 32:
            return base64.b64encode(bytes(raw)).decode()
    except Exception:
        pass
    try:
        with open(_field_key_file(), 'rb') as fh:
            raw = fh.read()
        if len(raw) == 32:
            return base64.b64encode(raw).decode()
    except Exception:
        pass
    return ''


def peer_field_keys():
    """The field keys the members handed over, {instance_id: base64 key}. Sealed
    at the pairing, kept in the state file beside the signing key."""
    keys = _load().get('field_keys') or {}
    return dict(keys) if isinstance(keys, dict) else {}


def _remember_field_keys(keys):
    """Take {instance_id: base64} into the state; only members we know keep
    theirs, and an empty key never overwrites one already held."""
    if not isinstance(keys, dict):
        return

    def go(state):
        held = state.setdefault('field_keys', {})
        for iid, key in keys.items():
            if not ha_wire.ID_RE.fullmatch(iid or '') or not isinstance(key, str):
                continue
            try:
                if base64.b64decode(key, validate=True).__len__() == 32:
                    held[iid] = key
            except Exception:
                continue
        return True
    _mutate(go)


def adopt_cluster(cluster_id, force=False):
    """Take over the cluster of a member that is gone for good. The lease is the
    fence: the voters grant it only past the old owner's promise, so a live
    owner (or a partitioned one, until its lease runs out) blocks the adoption.
    The mirrored credentials open under the owner's field key and seal under
    this instance's own. Raises FederationError with what stands in the way."""
    if not CLUSTER_ID_RE.fullmatch(cluster_id or ''):
        raise FederationError('That cluster id cannot be adopted')
    owner = cluster_owner(cluster_id)
    if owner is None:
        raise FederationError('No such cluster here - sync first, the mirror '
                              'must exist')
    if not owner:
        raise FederationError('That cluster is this instance\'s own already')
    if owner == instance_id():
        raise FederationError('That cluster is already led here')
    # the belt before the fence: an owner that answers is not gone
    status, _ = call_peer(owner, 'GET', STATUS_PATH, timeout=5)
    if status == 200:
        raise FederationError('The owner answered - it is not gone. Take the '
                              'cluster over there, or remove the member first')
    keys = peer_field_keys()
    key = keys.get(owner)
    if not key and not force:
        raise FederationError(f'The field key of the owner is not held here - '
                              f'without it the credentials cannot cross over')
    lease = acquire_lease(cluster_id)
    if lease.get('failed'):
        raise FederationError(f'The federation did not back the takeover '
                              f'({lease.get("votes")}/{lease.get("needed")} votes) '
                              f'- the owner\'s lease may still stand')
    _reseat_credentials(cluster_id, owner, key, force)
    _set_cluster_owner(cluster_id, instance_id())
    return lease


def _reseat_credentials(cluster_id, owner, key_b64, force):
    """Open the mirrored credential columns under the owner's field key and seal
    them under this instance's own. Without the key (force), the columns carry
    what they carried - the admin re-enters them at the cluster."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    conn = _identities_conn()
    cols = ', '.join(f'"{c}"' for c in CLUSTER_ENCRYPTED_COLUMNS)
    row = conn.execute(f'SELECT {cols} FROM clusters WHERE id = ?',
                       (cluster_id,)).fetchone()
    if row is None:
        return
    updates, params = [], []
    aesgcm_own = None
    try:
        from pegaprox.core.db import get_db
        aesgcm_own = get_db().aesgcm
    except Exception:
        pass
    if key_b64:
        try:
            aesgcm_old = AESGCM(base64.b64decode(key_b64))
            from pegaprox.core.db import get_db
            db = get_db()
            for col in CLUSTER_ENCRYPTED_COLUMNS:
                value = row[col]
                if not value:
                    continue
                plain = db._decrypt_with_key(value, aesgcm_old)
                updates.append(f'"{col}" = ?')
                params.append(db._encrypt_with_key(plain, aesgcm_own)
                              if aesgcm_own is not None else db._encrypt(plain))
        except Exception as e:
            if not force:
                raise FederationError(f'The credentials did not open under the '
                                      f'owner\'s key: {e}')
            logging.warning(f"[FED] adoption of {cluster_id} keeps the mirrored "
                            f"ciphertext ({e})")
    if updates:
        params.append(cluster_id)
        conn.execute(f'UPDATE clusters SET {", ".join(updates)} WHERE id = ?',
                     params)
        conn.commit()
