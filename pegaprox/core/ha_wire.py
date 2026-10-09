"""How the members of a group (#625) talk to each other, without any state of its own.

The signature over a peer call, the replay rule, the sealed pairing answer, the shape of
an address and of a pairing code. ha.py signs and checks every peer call with these, and
so does the witness (pegaprox/witness.py), which holds no database and must not import
ha.py: one implementation for both sides, so the two cannot drift apart.

Nothing here reads a clock, a file or the network on its own. The caller hands in the
time, the process start and the nonces it has seen.

MK Oct 2026 (#625)
"""
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import urllib.parse

# the sender's instance id; '<id>:<secret>' from a member paired before the keys
PEER_HEADER = 'X-PegaProx-Peer'
PEER_TS_HEADER = 'X-PegaProx-Peer-Ts'
PEER_NONCE_HEADER = 'X-PegaProx-Peer-Nonce'
PEER_SIG_HEADER = 'X-PegaProx-Peer-Sig'
PEER_BODY_HEADER = 'X-PegaProx-Peer-Body'
# how far a signed call's time may be off, either way
SIGNATURE_WINDOW = 120
NONCES_PER_SENDER = 4096
# what /peer/status says it speaks: the groups of members with keys, and the lease
# protocol of automatic failover (a mark of its own: a release before it compares
# GROUP_MARK for equality)
GROUP_MARK = 1
LEASE_MARK = 2

CODE_PREFIX = 'pgxha1_'
# a code that pairs a witness, never a member: the two must not be taken for each other
WITNESS_CODE_PREFIX = 'pgxwt1_'
# the witness keeps its state here, in a directory of its own (pegaprox/witness.py)
WITNESS_STATE_NAME = 'ha_witness.json'
# The calls between the members and the witness, by version. 1: the witness as first
# shipped, random nonces only and no updates. 2: stream nonces on votes and renewals,
# and the witness updates itself from the leader (witness-update, the code bundle).
# A member talks to a witness one version behind its own; the witness says its version
# in its status, and a witness that says none is a 1.
WITNESS_WIRE = 2
BUNDLE_MARK = b'pegaprox-witness-bundle-1\n'

MAX_URL_LEN = 512
DNS_LABEL_RE = re.compile(r'(?!-)[a-z0-9-]{1,63}(?<!-)')
URL_CHARS_RE = re.compile(r'[A-Za-z0-9.\-_~:/\[\]]+')
URL_PATH_RE = re.compile(r'/[A-Za-z0-9._~\-/]*')
URL_PORT_RE = re.compile(r':[0-9]{1,5}')
ID_RE = re.compile(r'[0-9a-f]{32}')
FP_RE = re.compile(r'[0-9A-F]{2}(:[0-9A-F]{2}){31}')
# an Ed25519 public key or signature, base64 of the raw bytes
PUBLIC_KEY_RE = re.compile(r'[A-Za-z0-9+/]{43}=')
SIGNATURE_RE = re.compile(r'[A-Za-z0-9+/]{86}==')
NONCE_RE = re.compile(r'[A-Za-z0-9_-]{16,64}')
TS_RE = re.compile(r'[0-9]{1,12}')
DIGEST_RE = re.compile(r'[0-9a-f]{64}')


class WireError(ValueError):
    """A code or an address that cannot be used, with the sentence the admin reads."""


# --- keys ------------------------------------------------------------------------

def new_signing_key():
    """A fresh Ed25519 private key, as a state file keeps it (base64 of the raw bytes)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    raw = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return base64.b64encode(raw).decode()


def private_key(value):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(value))


def public_of(private):
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


# The y coordinates of the eight Ed25519 points of small order (libsodium keeps the
# same list). OpenSSL takes them as public keys, and under the identity point one
# fixed signature holds for every message: such a key would be an identity anybody
# can sign as.
_ED25519_P = 2 ** 255 - 19
_ORDER_8_Y = 2707385501144840649318225287225658788936804267575313519463743609750303402022
_SMALL_ORDER_Y = frozenset((0, 1, _ED25519_P - 1, _ORDER_8_Y, _ED25519_P - _ORDER_8_Y))


def public_key(value):
    """The Ed25519 public key in `value` (base64 of the raw 32 bytes), None for anything
    else, a point of small order included."""
    if not isinstance(value, str):
        return None
    # every signed call is checked against a key of a member: each one is read once
    held = _keys_read.get(value)
    if held is not None:
        return held
    if not PUBLIC_KEY_RE.fullmatch(value):
        return None
    raw = base64.b64decode(value)
    # the sign bit of x left out, and y taken mod p: the encodings above p are the
    # same points
    if (int.from_bytes(raw, 'little') & ((1 << 255) - 1)) % _ED25519_P in _SMALL_ORDER_Y:
        return None
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        key = Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None
    if len(_keys_read) >= 64:
        _keys_read.clear()
    _keys_read[value] = key
    return key


_keys_read = {}


def cfg_signed(public_b64, message, sig):
    """Whether `sig` is the signature of `message` under `public_b64`: how a voter config
    is checked (ha_vote.Node verify)."""
    key = public_key(public_b64)
    if key is None or not isinstance(sig, str) or not SIGNATURE_RE.fullmatch(sig):
        return False
    try:
        key.verify(base64.b64decode(sig), message)
        return True
    except Exception:
        return False


# --- a signed peer call ------------------------------------------------------------

def wire_body(json_body):
    """The bytes a peer call carries, the same ones its signature covers."""
    if json_body is None:
        return b''
    return json.dumps(json_body, separators=(',', ':'), sort_keys=True).encode()


def body_digest(body):
    return hashlib.sha256(body or b'').hexdigest()


def to_sign(method, path, body, ts, nonce, receiver, sender, digest=None):
    return '\n'.join(('pegaprox-ha-peer-1', method.upper(), path,
                      digest if digest is not None else body_digest(body), ts, nonce,
                      receiver, sender)).encode()


def signed_headers(private, sender, receiver, method, path, body, now, nonce=None):
    """The peer headers of one call. `nonce` is a stream nonce (stream_nonce) for the
    calls of automatic failover, a random one when left out."""
    ts, digest = str(int(now)), body_digest(body)
    nonce = nonce or secrets.token_urlsafe(18)
    sig = private.sign(to_sign(method, path, body, ts, nonce, receiver, sender, digest))
    return {PEER_HEADER: sender, PEER_TS_HEADER: ts, PEER_NONCE_HEADER: nonce,
            PEER_SIG_HEADER: base64.b64encode(sig).decode(), PEER_BODY_HEADER: digest}


def signature_verdict(headers, method, path, body, sender, public_b64, receiver, now, started,
                      digest=None):
    """What the signature headers of one call say, before any nonce is spent: 'ok', '' for
    no good signature at all, 'window' for a good one from outside SIGNATURE_WINDOW (a
    clock that is off, or an old call), 'early' for one signed before the receiving
    process `started` (the nonces it saw until then are gone). With `digest` the
    signature is checked over that body digest instead of `body`: who sent a call, told
    before its body is read; the body still has to match it afterwards."""
    ts, nonce, sig = (headers.get(PEER_TS_HEADER), headers.get(PEER_NONCE_HEADER),
                      headers.get(PEER_SIG_HEADER))
    if not all(isinstance(v, str) for v in (ts, nonce, sig)):
        return ''
    if not (TS_RE.fullmatch(ts) and NONCE_RE.fullmatch(nonce) and SIGNATURE_RE.fullmatch(sig)):
        return ''
    key = public_key(public_b64)
    if key is None:
        return ''
    from cryptography.exceptions import InvalidSignature
    try:
        key.verify(base64.b64decode(sig), to_sign(method, path, body, ts, nonce, receiver, sender, digest))
    except (InvalidSignature, ValueError):
        return ''
    if abs(now - int(ts)) > SIGNATURE_WINDOW:
        return 'window'
    if int(ts) < started:
        return 'early'
    return 'ok'


def clock_refusal(verdict, now, started, ts):
    """The 401 answer to a call with a good signature that signature_verdict found
    'window' or 'early': {code, clock, error}. An early call says nothing of clocks a
    window apart - right after a restart every sender whose clock is behind the
    receiver's hears it, for as long as it is behind - so it gets a text of its own."""
    if verdict == 'early':
        return {'code': 'HA_CLOCK', 'clock': 'early',
                'error': f'The receiving instance started {max(0, int(now - started))} s ago, and '
                         f'the call was signed before that by the clock of the sender, which is '
                         f'{max(0, int(now - ts))} s behind it (or the call is an old one). Calls '
                         'signed after the start are taken - set both clocks by NTP'}
    return {'code': 'HA_CLOCK', 'clock': 'window',
            'error': f'The clocks of the two instances are more than {SIGNATURE_WINDOW} seconds '
                     'apart - set both by NTP'}


def take_nonce(seen, nonce, ts, now, cap=NONCES_PER_SENDER):
    """Spend `nonce` in `seen` ({nonce: kept until}, one per sender and bucket): 'ok' the
    first time within the window, 'seen' for a replay, 'full' while the bucket holds
    `cap` live ones. The caller holds its lock around it."""
    for n in [n for n, until in seen.items() if until < now]:
        del seen[n]
    if nonce in seen:
        return 'seen'
    if len(seen) >= cap:
        return 'full'
    seen[nonce] = ts + SIGNATURE_WINDOW + 1
    return 'ok'


# --- stream nonces: the votes and renewals of automatic failover ---------------------------
#
# MK Oct 2026 (#625) - a leader sends a confirm round before each write, many a second. A
# replay cache of random nonces that has to hold every one of them for the signature
# window would need 121 entries per round a second and sender. Instead each process
# that sends lease calls draws a random stream id once and numbers its calls to each
# receiver 1, 2, 3, ... The receiver keeps per sender and stream the highest number it
# took and which of the STREAM_WINDOW below it it took (a bitmap), for as long as the
# newest call it took from that stream is inside the signature window. A number is taken
# once: above the highest it moves the window, inside it needs its bit clear, below it is
# refused. A sender that restarts draws a new stream; a receiver that restarts refuses
# whatever was signed before its start (signature_verdict 'early'), as it does for random
# nonces; calls that overtake each other on the way are taken as long as they are less
# than STREAM_WINDOW apart. A stream left alone ages out once its newest call is outside
# the signature window, and so is every call of it ever taken.

STREAM_NONCE_RE = re.compile(r'ls1-([0-9a-f]{32})-([1-9][0-9]{0,17})')
STREAM_WINDOW = 4096
# streams one sender may have live at a receiver: one per start of its process within the
# signature window. A sender that restarts this often is refused until the oldest ages out
STREAMS_PER_SENDER = 64


def new_stream():
    return secrets.token_hex(16)


def stream_nonce(stream, seq):
    return f'ls1-{stream}-{seq}'


def is_stream_nonce(nonce):
    return isinstance(nonce, str) and STREAM_NONCE_RE.fullmatch(nonce) is not None


def take_stream(streams, nonce, ts, now, spend=True):
    """Spend the stream nonce `nonce` in `streams` ({stream: [highest, bitmap, newest ts]},
    one per sender): 'ok' the first time, 'seen' for a number taken before or one too far
    below the highest, 'full' when the sender holds STREAMS_PER_SENDER live streams
    already. With spend=False only says what spending would say. The caller holds its
    lock around it and checked the signature and its window first."""
    m = STREAM_NONCE_RE.fullmatch(nonce)
    stream, seq = m.group(1), int(m.group(2))
    rec = streams.get(stream)
    if rec is None:
        for s in [s for s, r in streams.items() if r[2] + SIGNATURE_WINDOW + 1 < now]:
            del streams[s]
        if len(streams) >= STREAMS_PER_SENDER:
            return 'full'
        if spend:
            streams[stream] = [seq, 1, ts]
        return 'ok'
    high, bits, newest = rec
    if seq > high:
        if spend:
            shift = seq - high
            bits = ((bits << shift) | 1) if shift < STREAM_WINDOW else 1
            rec[0], rec[1] = seq, bits & ((1 << STREAM_WINDOW) - 1)
    else:
        back = high - seq
        if back >= STREAM_WINDOW or (bits >> back) & 1:
            return 'seen'
        if spend:
            rec[1] = bits | (1 << back)
    if spend and ts > newest:
        rec[2] = ts
    return 'ok'


def bundle_message(manifest):
    """What a data voter signs over the witness code bundle it serves: the manifest,
    which carries the archive's SHA-256 (ha.witness_bundle, witness.Witness.verify)."""
    return BUNDLE_MARK + json.dumps(manifest, separators=(',', ':'), sort_keys=True).encode()


# --- the sealed pairing answer -------------------------------------------------------

def seal_key(code_secret, salt):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b'pegaprox-ha-pairing').derive(code_secret.encode())


def seal(code_secret, payload, aad):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(seal_key(code_secret, salt)).encrypt(nonce, json.dumps(payload).encode(), aad.encode())
    return base64.b64encode(salt + nonce + ct).decode()


def unseal(code_secret, blob, aad):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.b64decode(blob)
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    return json.loads(AESGCM(seal_key(code_secret, salt)).decrypt(nonce, ct, aad.encode()))


# --- addresses and codes -------------------------------------------------------------

def valid_host(host):
    if len(host) > 253:
        return False
    labels = host.split('.')
    if not all(DNS_LABEL_RE.fullmatch(label) for label in labels):
        return False
    if all(label.isdigit() for label in labels):
        # all digits is an IPv4 address or nothing
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return False
    return True


def valid_https_url(url):
    """`url` as https://host[:port][/path] with the trailing slash gone, or ''.

    One shape for every address that travels: the admin routes, the address a
    pairing code carries and the one a standby or a witness sends. The host is a DNS
    name, an IPv4 address or a bracketed IPv6 address. No user info, query, fragment,
    percent escapes, whitespace or control characters. Too long is refused, not cut.
    """
    if not isinstance(url, str):
        return ''
    url = url.strip()
    if not url or len(url) > MAX_URL_LEN or not url.startswith('https://'):
        return ''
    url = url.rstrip('/')
    if not URL_CHARS_RE.fullmatch(url):
        return ''
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return ''
    if parts.scheme != 'https' or parts.query or parts.fragment or '@' in parts.netloc:
        return ''
    netloc = parts.netloc
    if netloc.startswith('['):
        host, bracket, port = netloc[1:].partition(']')
        if not bracket:
            return ''
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return ''
        host = f'[{host.lower()}]'
    else:
        host, colon, port = netloc.partition(':')
        port = colon + port
        host = host.lower()
        if not valid_host(host):
            return ''
    if port:
        if not URL_PORT_RE.fullmatch(port) or not 0 < int(port[1:]) < 65536:
            return ''
        port = f':{int(port[1:])}'
    if parts.path and not URL_PATH_RE.fullmatch(parts.path):
        return ''
    return f'https://{host}{port}{parts.path}'


def encode_code(prefix, url, fingerprint, secret, active_id):
    body = json.dumps({'u': url, 'f': fingerprint or '', 'c': secret, 'i': active_id},
                      separators=(',', ':')).encode()
    return prefix + base64.urlsafe_b64encode(body).decode().rstrip('=')


def decode_code(prefix, code, what='a PegaProx pairing code'):
    """{url, fingerprint, secret, instance_id} from a code made with `prefix`. Raises
    WireError with what the admin is told."""
    code = (code or '').strip()
    if not code.startswith(prefix):
        raise WireError(f'This is not {what}')
    raw = code[len(prefix):]
    try:
        body = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))
    except Exception:
        raise WireError('The pairing code is damaged - copy it again')
    if not isinstance(body, dict) or not all(isinstance(body.get(k) or '', str) for k in 'ufci'):
        raise WireError('The pairing code is damaged - copy it again')
    url = valid_https_url(body.get('u') or '')
    if not url:
        raise WireError('The pairing code does not carry a usable https:// address')
    fp = (body.get('f') or '').strip().upper()
    if fp and not re.match(r'^[0-9A-F]{2}(:[0-9A-F]{2}){31}$', fp):
        raise WireError('The pairing code carries a malformed certificate fingerprint')
    secret, active_id = body.get('c') or '', body.get('i') or ''
    if len(secret) < 32 or not re.match(r'^[0-9a-f]{32}$', active_id):
        raise WireError('The pairing code is incomplete')
    return {'url': url, 'fingerprint': fp, 'secret': secret, 'instance_id': active_id}


def cert_fingerprint(pem):
    """SHA-256 fingerprint of a PEM certificate in the colon-separated upper-hex form the
    pins use, '' for anything that is no certificate."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        cert = x509.load_pem_x509_certificate(pem)
        return ':'.join(f'{b:02X}' for b in cert.fingerprint(hashes.SHA256()))
    except Exception:
        return ''
