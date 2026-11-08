# -*- coding: utf-8 -*-
"""SHA-512 crypt ($6$) in plain Python - MK Sep 2026.

The auto-installer hands root-password-hashed straight to `chpasswd --encrypted`,
so the value has to be something the new node's libxcrypt can verify. The crypt
module is gone in Python 3.13 (the trixie package and the appliance run that),
libxcrypt refuses argon2 output, and bcrypt only reaches us through paramiko.
This is Drepper's SHA-crypt the way glibc and libxcrypt implement it, stdlib only.
"""
import hashlib
import secrets

_ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
DEFAULT_ROUNDS = 5000
MIN_ROUNDS, MAX_ROUNDS = 1000, 999_999_999
_SALT_MAX = 16

# byte order of the final 64-byte digest, three bytes per 4 output characters
_ORDER = ((0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26),
          (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32),
          (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38),
          (18, 39, 60), (40, 61, 19), (62, 20, 41))


def _b64(b2, b1, b0, n):
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(_ITOA64[w & 0x3f])
        w >>= 6
    return ''.join(out)


def _repeat(block, length):
    return (block * (length // len(block) + 1))[:length]


def sha512_crypt(password, salt=None, rounds=None):
    """`$6$[rounds=N$]<salt>$<86 chars>`, byte-identical to crypt(3).

    rounds=None leaves the rounds= field out, which means 5000. Anything outside
    1000..999999999 raises: glibc would clamp it, but libxcrypt answers '*0', and a
    hash that only one of them accepts is a root account nobody can log in to.

    The salt is at most 16 characters from ./0-9A-Za-z. crypt(3) would cut a longer
    one, but a '$' or ':' in it would break the hash or the chpasswd line.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    if not isinstance(password, bytes):
        raise TypeError('password must be str or bytes')
    if b'\x00' in password:
        # crypt(3) stops at the first NUL, so this hash could never match at login
        raise ValueError('password must not contain NUL')

    if salt is None:
        salt = ''.join(secrets.choice(_ITOA64) for _ in range(_SALT_MAX))
    if not isinstance(salt, str) or len(salt) > _SALT_MAX or any(ch not in _ITOA64 for ch in salt):
        raise ValueError('salt must be at most 16 characters from ./0-9A-Za-z')

    if rounds is None:
        r = DEFAULT_ROUNDS
    else:
        if not isinstance(rounds, int) or isinstance(rounds, bool):
            raise ValueError('rounds must be an integer')
        if not MIN_ROUNDS <= rounds <= MAX_ROUNDS:
            raise ValueError(f'rounds must be between {MIN_ROUNDS} and {MAX_ROUNDS}')
        r = rounds

    p = password
    s = salt.encode('ascii')
    sha = hashlib.sha512

    b = sha(p + s + p).digest()
    a = sha(p + s)
    a.update(_repeat(b, len(p)))
    n = len(p)
    while n:
        a.update(b if n & 1 else p)
        n >>= 1
    a = a.digest()

    # the password once per password byte. Streamed rather than built, because it
    # is quadratic in the length - the callers cap that at 64 characters
    dp = sha()
    for _ in range(len(p)):
        dp.update(p)
    dp = dp.digest()
    pseq = _repeat(dp, len(p)) if p else b''
    ds = sha(s * (16 + a[0])).digest()
    sseq = _repeat(ds, len(s)) if s else b''

    c = a
    for i in range(r):
        h = sha(pseq if i & 1 else c)
        if i % 3:
            h.update(sseq)
        if i % 7:
            h.update(pseq)
        h.update(c if i & 1 else pseq)
        c = h.digest()

    enc = ''.join(_b64(c[x], c[y], c[z], 4) for x, y, z in _ORDER) + _b64(0, 0, c[63], 2)
    head = '$6$' if rounds is None else f'$6$rounds={r}$'
    return f'{head}{salt}${enc}'
