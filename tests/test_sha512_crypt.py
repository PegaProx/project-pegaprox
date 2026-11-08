"""SHA-512 crypt ($6$) for root-password-hashed.

The installer pipes the value into `chpasswd --encrypted` and never looks at it,
so the only real proof is a root login on an installed node. What can be pinned
here: Drepper's published vectors, byte equality with crypt(3) and openssl where
they exist, and the two places the original draft was lenient - it clamped the
rounds (libxcrypt answers '*0' below 1000) and it took any salt. MK
"""
import random
import re
import shutil
import string
import subprocess
import time
import warnings

import pytest

from pegaprox.utils.sha512_crypt import sha512_crypt, _ITOA64


# sha-crypt.txt, the $6$ vectors with rounds >= 1000 (the rounds=10 one only holds
# for glibc's clamping, which is exactly what we refuse). The salts are passed the
# way crypt(3) would cut them from the setting string: 16 characters at most.
DREPPER = [
    ('saltstring', None, 'Hello world!',
     '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1'),
    ('saltstringsaltst', 10000, 'Hello world!',
     '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/'
     'YTBmSK6H9qs/y3RnOaw5v.'),
    ('toolongsaltstrin', 5000, 'This is just a test',
     '$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/'
     'e1JSbq3y6JMxxl8audkUEm0'),
    ('anotherlongsalts', 1400,
     'a very much longer text to encrypt.  This one even stretches over morethan one line.',
     '$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o'
     '7UmJEiDwGqd8p4ur1'),
    ('short', 77777, 'we have a short salt string but not a short password',
     '$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelF'
     'l5CxtgfiAc0'),
    ('asaltof16chars..', 123456, 'a short string',
     '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xX'
     'gMNrCzIMVcgEJAstJeonj1'),
]

SIX = re.compile(r'\$6\$rounds=100000\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{86}')


@pytest.mark.parametrize('salt,rounds,password,expected', DREPPER, ids=[v[0] for v in DREPPER])
def test_drepper_vectors(salt, rounds, password, expected):
    assert sha512_crypt(password, salt, rounds) == expected


@pytest.mark.parametrize('rounds', [10, 999, 1_000_000_000, -1, 0])
def test_rounds_out_of_range_are_refused_not_clamped(rounds):
    """glibc clamps, libxcrypt returns '*0'. A clamped hash here would install a
    root account that PAM on the node then refuses."""
    with pytest.raises(ValueError):
        sha512_crypt('some-root-password', 'abcdefgh', rounds)


def test_the_rounds_bounds_themselves_are_fine():
    assert sha512_crypt('pw-pw-pw-pw', 'abc', 1000).startswith('$6$rounds=1000$abc$')
    assert sha512_crypt('pw-pw-pw-pw', 'abc', 5000).startswith('$6$rounds=5000$abc$')


@pytest.mark.parametrize('salt', ['with$dollar', 'with:colon', 'x' * 17, 'new\nline', 'sp ace', 'ümlaut'])
def test_a_salt_outside_the_alphabet_is_refused(salt):
    with pytest.raises(ValueError):
        sha512_crypt('some-root-password', salt, 5000)


def test_a_nul_in_the_password_is_refused():
    """crypt(3) stops at the NUL, so the node would compare against a prefix."""
    with pytest.raises(ValueError):
        sha512_crypt('abc\x00defgh', 'abcdefgh')


def test_what_the_endpoint_produces_has_the_expected_shape():
    from pegaprox.api.auto_install import _CRYPT_RE
    a = sha512_crypt('correct horse battery', rounds=100000)
    b = sha512_crypt('correct horse battery', rounds=100000)
    for h in (a, b):
        assert SIX.fullmatch(h), h
        assert _CRYPT_RE.fullmatch(h), h
        salt = h.split('$')[3]
        assert len(salt) == 16 and all(ch in _ITOA64 for ch in salt)
    assert a != b, 'the salt has to be random'
    # and the hash verifies against itself with the salt read back out of it
    salt = a.split('$')[3]
    assert sha512_crypt('correct horse battery', salt, 100000) == a


def test_sixty_four_characters_hash_in_bounded_time():
    """The per-byte step is quadratic in the length; the endpoint caps at 64."""
    start = time.perf_counter()
    sha512_crypt('ä' * 64, rounds=100000)      # 128 bytes
    assert time.perf_counter() - start < 2.0


def _random_cases(n, seed):
    rng = random.Random(seed)
    alpha = string.ascii_letters + string.digits + string.punctuation + ' äöüß€'
    for _ in range(n):
        pw = ''.join(rng.choice(alpha) for _ in range(rng.choice([1, 7, 8, 16, 31, 63, 64, 65, 100])))
        salt = ''.join(rng.choice(_ITOA64) for _ in range(rng.randint(0, 16)))
        rounds = rng.choice([None, 1000, 5000, rng.randint(1000, 12000)])
        yield pw, salt, rounds


def test_byte_identical_to_crypt3():
    """The crypt module is gone in 3.13 (trixie), still there on CI's 3.12."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        crypt = pytest.importorskip('crypt')
    for pw, salt, rounds in _random_cases(50, 7):
        setting = '$6$' + (f'rounds={rounds}$' if rounds else '') + salt
        assert sha512_crypt(pw, salt, rounds) == crypt.crypt(pw, setting), (pw, setting)


@pytest.mark.skipif(not shutil.which('openssl'), reason='openssl not installed')
def test_byte_identical_to_openssl_passwd():
    for pw in ('Admin123', 'correct horse battery staple', 'ÄÖÜ-pässwörd', 'x' * 64):
        out = subprocess.run(['openssl', 'passwd', '-6', '-salt', 'Qy7fN2mZpL0aB9cD', '-stdin'],
                             input=pw.encode(), capture_output=True, check=True).stdout.decode().strip()
        assert out == sha512_crypt(pw, 'Qy7fN2mZpL0aB9cD')
