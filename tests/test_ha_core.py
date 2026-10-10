"""The warm standby core (#625), without routes: codes, sealing, the state file,
pairing, epochs, and the snapshot a standby replaces its configuration with.

Everything runs against a state file in tmp_path and the throwaway test database.
Both "instances" are this one process: a test builds a snapshot in the active role,
rewrites the state file to make the same process the standby, and applies it.

MK Sep 2026
"""
import base64
import gzip
import json
import os
import re
import shutil
import stat
import time
import types

import pytest
from cryptography.exceptions import InvalidTag

from pegaprox.core import ha

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

A = 'a' * 32   # the active
B = 'b' * 32   # the standby
C = 'c' * 32   # somebody else
FP = ':'.join(['AB'] * 32)
# what a standby from before the keys presented, and the hash it handed over
Z = 'z' * 43
ZH = ha._hash_secret(Z)
# the key pair a standby pairs with now: it keeps the private half, the public half
# (ZK) goes to the active (#625 groups)
ZKEY = ha._private_key(base64.b64encode(bytes(range(1, 33))).decode())
ZK = ha._public_of(ZKEY)
# the active behind _fake_active signs with this one
TKEY = ha._private_key(base64.b64encode(bytes(range(33, 65))).decode())
TK = ha._public_of(TKEY)


def _signed_by(private, sender, receiver, method='GET', path='/api/ha/peer/status', body=b''):
    """The peer headers of a call `sender` signs with `private` for `receiver`."""
    return ha._auth_for(ha._Signer(sender, private), receiver)(method, path, body)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(ha, 'STATE_FILE', str(tmp_path / 'ha_state.json'))
    monkeypatch.setattr(ha, 'AES_KEY_FILE', str(tmp_path / 'aes256.key'))
    monkeypatch.setattr(ha, 'KNOWN_HOSTS_FILE', str(tmp_path / 'known_hosts'))
    monkeypatch.setattr(ha, 'BRANDING_DIR', str(tmp_path / 'branding'))
    monkeypatch.setattr(ha, 'PLUGINS_DIR', str(tmp_path / 'plugins'))
    # every test starts like a fresh process
    monkeypatch.setattr(ha, '_etag_checked', False)
    restarts = []
    monkeypatch.setattr(ha, 'restart_process', restarts.append)
    ha.reset_for_tests()
    yield types.SimpleNamespace(tmp=tmp_path, restarts=restarts, mp=monkeypatch)
    ha.reset_for_tests()


def _write_state(**st):
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        json.dump(st, fh)
    ha.reset_for_tests()


def _peer(pid, **kw):
    """A peer record in the pair format of v1/v2; _load reads it as a group of two."""
    p = {'instance_id': pid, 'url': 'https://peer.example:5000', 'fingerprint': '',
         'secret_out': 'o' * 43, 'secret_in_hash': ha._hash_secret('i' * 43),
         'paired_at': '2026-09-29T10:00:00+00:00', 'role_seen': None, 'epoch_seen': 0}
    p.update(kw)
    return p


def _be_active(epoch=3):
    _write_state(role='active', instance_id=A, epoch=epoch, peer=_peer(B, role_seen='standby'))


def _be_standby(epoch=3, **kw):
    st = dict(role='standby', instance_id=B, epoch=epoch,
              peer=_peer(A, role_seen='active', epoch_seen=epoch))
    st.update(kw)
    _write_state(**st)


def _file_bytes(path):
    with open(path, 'rb') as fh:
        return fh.read()


# --- pairing codes -------------------------------------------------------------

def _raw_code(body):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return ha.CODE_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip('=')


def _body(**over):
    b = {'u': 'https://pp1.lab.example:5000', 'f': FP, 'c': 's' * 43, 'i': A}
    b.update(over)
    return b


def test_a_pairing_code_carries_address_pin_secret_and_id():
    code = ha.encode_code('https://pp1.lab.example:5000/', FP.lower(), 's' * 43, A)

    assert code.startswith(ha.CODE_PREFIX) and '=' not in code
    assert ha.decode_code('  ' + code + '\n') == {
        'url': 'https://pp1.lab.example:5000', 'fingerprint': FP,
        'secret': 's' * 43, 'instance_id': A}


def test_a_code_without_a_pin_is_fine():
    code = ha.encode_code('https://[fd00::10]:5000', '', 's' * 43, A)
    assert ha.decode_code(code)['fingerprint'] == ''
    assert ha.decode_code(code)['url'] == 'https://[fd00::10]:5000'


@pytest.mark.parametrize('code,message', [
    pytest.param('', 'not a PegaProx pairing code', id='empty'),
    pytest.param(None, 'not a PegaProx pairing code', id='none'),
    pytest.param('pgxha2_' + 'x' * 40, 'not a PegaProx pairing code', id='other-prefix'),
    pytest.param(ha.CODE_PREFIX + '%%%%', 'damaged', id='not-base64'),
    pytest.param(_raw_code(b'not json at all'), 'damaged', id='not-json'),
    pytest.param(_raw_code(b'\xff\xfe'), 'damaged', id='not-utf8'),
    pytest.param(_raw_code([1, 2, 3]), 'damaged', id='json-list'),
    pytest.param(_raw_code('https://x'), 'damaged', id='json-string'),
    pytest.param(_raw_code(_body(u=5)), 'damaged', id='url-not-a-string'),
    pytest.param(_raw_code(_body(c=['s' * 43])), 'damaged', id='secret-not-a-string'),
    pytest.param(_raw_code(_body(u='http://pp1.lab.example:5000')), 'https://', id='plain-http'),
    pytest.param(_raw_code(_body(u='')), 'https://', id='no-url'),
    pytest.param(_raw_code(_body(u='https://pp1.example/?next=evil')), 'https://', id='url-query'),
    pytest.param(_raw_code(_body(u='https://user@pp1.example')), 'https://', id='url-userinfo'),
    pytest.param(_raw_code(_body(u='https://pp1.example/#x')), 'https://', id='url-fragment'),
    pytest.param(_raw_code(_body(u='https://pp1.example/a b')), 'https://', id='url-space'),
    pytest.param(_raw_code(_body(f='AB:CD')), 'fingerprint', id='fp-short'),
    pytest.param(_raw_code(_body(f=':'.join(['ZZ'] * 32))), 'fingerprint', id='fp-not-hex'),
    pytest.param(_raw_code(_body(c='s' * 31)), 'incomplete', id='secret-short'),
    pytest.param(_raw_code(_body(c='')), 'incomplete', id='secret-missing'),
    pytest.param(_raw_code(_body(i='A' * 32)), 'incomplete', id='id-uppercase'),
    pytest.param(_raw_code(_body(i='a' * 31)), 'incomplete', id='id-short'),
    pytest.param(_raw_code(_body(i='')), 'incomplete', id='id-missing'),
])
def test_a_bad_pairing_code_is_refused_with_a_reason(code, message):
    with pytest.raises(ha.HaError, match=re.escape(message)):
        ha.decode_code(code)


@pytest.mark.parametrize('url', [
    pytest.param('https://.', id='dot'),
    pytest.param('https://[', id='open-bracket'),
    pytest.param('https://:::', id='colons'),
    pytest.param('https://a:99999', id='port-too-big'),
    pytest.param('https://' + 'a' * 600, id='too-long'),
])
def test_a_code_with_a_meaningless_host_is_refused_here_not_at_connect_time(url):
    with pytest.raises(ha.HaError, match='usable https://'):
        ha.decode_code(_raw_code(_body(u=url)))


# --- the address check ---------------------------------------------------------

@pytest.mark.parametrize('url,expected', [
    ('https://pp1.lab.example:5000', 'https://pp1.lab.example:5000'),
    ('  https://PP1.Lab.Example:5000//\n', 'https://pp1.lab.example:5000'),
    ('https://pp1.example/pegaprox/', 'https://pp1.example/pegaprox'),
    ('https://pp1.example:05000', 'https://pp1.example:5000'),
    ('https://pp1.example:65535', 'https://pp1.example:65535'),
    ('https://10.0.0.5', 'https://10.0.0.5'),
    ('https://localhost:5000', 'https://localhost:5000'),
    ('https://[fd00::10]:5000', 'https://[fd00::10]:5000'),
    ('https://[FD00::10]', 'https://[fd00::10]'),
    ('https://' + 'a' * 63 + '.example', 'https://' + 'a' * 63 + '.example'),
])
def test_valid_https_url_takes_a_plain_https_address(url, expected):
    assert ha.valid_https_url(url) == expected


@pytest.mark.parametrize('url', [
    pytest.param('http://pp1.example', id='plain-http'),
    pytest.param('HTTPS://pp1.example', id='scheme-uppercase'),
    pytest.param('https://', id='no-host'),
    pytest.param('https://.', id='dot'),
    pytest.param('https://[', id='open-bracket'),
    pytest.param('https://:::', id='colons'),
    pytest.param('https://:5000', id='port-only'),
    pytest.param('https://a:99999', id='port-too-big'),
    pytest.param('https://a:0', id='port-zero'),
    pytest.param('https://a:', id='port-empty'),
    pytest.param('https://a:5000:6000', id='two-ports'),
    pytest.param('https://-a.example', id='label-starts-with-dash'),
    pytest.param('https://a..example', id='empty-label'),
    pytest.param('https://a_b.example', id='underscore'),
    pytest.param('https://' + 'a' * 64 + '.example', id='label-too-long'),
    pytest.param('https://999.1.1.1', id='not-an-ipv4'),
    pytest.param('https://[fd00::zz]', id='not-an-ipv6'),
    pytest.param('https://[fd00::1%eth0]', id='ipv6-zone'),
    pytest.param('https://[fd00::1]x', id='junk-after-ipv6'),
    pytest.param('https://x.example\r\n2026-09-29 10:00:00 root ha.unpaired forged', id='crlf'),
    pytest.param('https://trusted.example@evil.example', id='userinfo'),
    pytest.param('https://h.example/p?q=1', id='query'),
    pytest.param('https://h.example/p#frag', id='fragment'),
    pytest.param('https://h.example/a b', id='space'),
    pytest.param('https://h.example/<b>x</b>', id='markup'),
    pytest.param('https://h.example/%2e%2e', id='percent'),
    pytest.param('https://hä.example', id='non-ascii'),
    pytest.param('https://h.example/\x00', id='nul'),
    pytest.param('https://' + 'a' * 600, id='too-long'),
    pytest.param('https://x.example/' + 'p' * 600, id='too-long-path'),
    pytest.param(None, id='none'),
    pytest.param(['https://x.example'], id='list'),
])
def test_valid_https_url_refuses_anything_else(url):
    """(#625 review) One check for every address that travels; the looser ones let
    CR/LF, user info and meaningless hosts into the peer record, and cut long input
    to a different address instead of refusing it."""
    assert ha.valid_https_url(url) == ''


# --- sealing -------------------------------------------------------------------

def test_seal_and_unseal_round_trip():
    payload = {'field_key': base64.b64encode(os.urandom(32)).decode(), 'secret': 'x' * 43}
    blob = ha._seal('code-secret', payload, aad=B)

    assert ha._unseal('code-secret', blob, aad=B) == payload
    # fresh salt and nonce every time
    assert ha._seal('code-secret', payload, aad=B) != blob


def test_unseal_needs_the_right_secret_and_the_right_standby():
    blob = ha._seal('code-secret', {'k': 1}, aad=B)

    with pytest.raises(InvalidTag):
        ha._unseal('another-secret', blob, aad=B)
    with pytest.raises(InvalidTag):
        ha._unseal('code-secret', blob, aad=C)

    raw = bytearray(base64.b64decode(blob))
    raw[-1] ^= 1
    with pytest.raises(InvalidTag):
        ha._unseal('code-secret', base64.b64encode(bytes(raw)).decode(), aad=B)


# --- the state file ------------------------------------------------------------

def test_nothing_is_written_until_something_changes(env):
    assert ha.role() == 'standalone' and ha.is_active() and not ha.is_standby()
    ha.instance_id(), ha.epoch(), ha.peer(), ha.public_status(), ha.banner()
    assert ha.pull_once() == 'not a standby'
    assert ha.watch_once() == 'idle'
    assert ha.verify_peer({ha.PEER_HEADER: f'{A}:secret'}) is None
    assert not os.path.exists(ha.STATE_FILE)

    ha.create_pairing_code('https://pp1.example:5000', '')
    assert os.path.exists(ha.STATE_FILE)


def test_the_state_file_is_private_whatever_was_there_before(env):
    _write_state(role='standalone', instance_id=A)
    os.chmod(ha.STATE_FILE, 0o644)
    # a leftover temp file from a crash, world readable
    with open(ha.STATE_FILE + '.tmp', 'w') as fh:
        fh.write('{}')
    os.chmod(ha.STATE_FILE + '.tmp', 0o666)

    old = os.umask(0)
    try:
        ha.create_pairing_code('https://pp1.example:5000', '')
    finally:
        os.umask(old)

    assert stat.S_IMODE(os.stat(ha.STATE_FILE).st_mode) == 0o600
    assert not os.path.exists(ha.STATE_FILE + '.tmp')


def test_a_new_state_file_is_private_from_the_start(env):
    old = os.umask(0)
    try:
        ha.create_pairing_code('https://pp1.example:5000', '')
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(ha.STATE_FILE).st_mode) == 0o600


@pytest.mark.parametrize('content', [
    pytest.param('{"role": "act', id='truncated'),
    pytest.param('', id='empty'),
    pytest.param('[]', id='json-list'),
    pytest.param('null', id='json-null'),
    pytest.param('"standalone"', id='json-string'),
])
def test_an_unreadable_state_file_makes_a_standby_and_stays_as_it_is(env, content):
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        fh.write(content)
    before = _file_bytes(ha.STATE_FILE)

    assert ha.role() == 'standby' and not ha.is_active()
    assert ha.public_status()['broken']
    assert ha.banner()['role'] == 'standby'
    # what the loop would do: nothing to pull from, nothing to watch
    assert ha.pull_once() == 'not paired'
    assert ha.watch_once() == 'idle'
    assert ha.verify_peer({ha.PEER_HEADER: f'{A}:secret'}) is None
    assert ha.step_down(99, A) is False
    assert ha.forget_peer(A) == ''
    with pytest.raises(ha.HaError):
        ha.create_pairing_code('https://pp1.example:5000', '')

    assert _file_bytes(ha.STATE_FILE) == before


def test_a_state_file_that_is_a_directory_makes_a_standby(env):
    os.mkdir(ha.STATE_FILE)
    assert ha.role() == 'standby' and ha.public_status()['broken']
    assert ha.pull_once() == 'not paired'
    assert os.path.isdir(ha.STATE_FILE)


def test_an_unknown_role_is_read_as_standby(env):
    _write_state(role='primary', instance_id=A)
    assert ha.role() == 'standby' and not ha.is_active()


@pytest.mark.parametrize('content', [
    pytest.param('{"role": "act', id='truncated'),
    pytest.param('[]', id='json-list'),
])
def test_nothing_writes_over_a_state_file_that_cannot_be_read(env, content):
    """(#625 review) Changing the interval on a broken standby saved the stand-in:
    a fresh identity, no peer, epoch 0. The peer record and both secrets were gone,
    even when the read error would have healed on its own."""
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        fh.write(content)
    before = _file_bytes(ha.STATE_FILE)
    interval = ha.public_status()['interval']

    with pytest.raises(ha.HaError, match='cannot be read'):
        ha._update(interval=60)
    with pytest.raises(ha.HaError, match='cannot be read'):
        ha._update_sync(last_error='x')
    with pytest.raises(ha.HaError, match='cannot be read'):
        ha.promote()

    assert _file_bytes(ha.STATE_FILE) == before
    assert ha.public_status()['interval'] == interval
    assert ha.role() == 'standby' and ha.public_status()['broken']
    assert env.restarts == []


def test_unpair_is_the_way_out_of_a_broken_state_file_and_takes_the_note_along(env):
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        fh.write('{"role": "act')
    assert ha.public_status()['broken']

    assert ha.unpair() == 'standby'

    on_disk = json.loads(_file_bytes(ha.STATE_FILE))
    assert on_disk['role'] == 'standalone' and 'broken' not in on_disk
    assert ha.public_status()['broken'] == '' and ha.is_active()
    ha.reset_for_tests()
    assert ha.role() == 'standalone' and ha.public_status()['broken'] == ''
    ha._update(interval=60)
    assert ha.public_status()['interval'] == 60


def test_a_broken_note_in_a_file_that_reads_fine_is_dropped(env):
    """An earlier build saved the note into the file, so a standalone kept showing
    'stays passive until it is fixed' while it acted."""
    _write_state(role='standalone', instance_id=A, broken='Unterminated string starting at: line 1')
    assert ha.role() == 'standalone' and ha.public_status()['broken'] == ''

    ha.create_pairing_code('https://pp1.example:5000', '')
    assert 'broken' not in json.loads(_file_bytes(ha.STATE_FILE))


def _key_backup(env, name='aes256.key.pre-ha.20260929-101500'):
    with open(os.path.join(env.tmp, name), 'wb') as fh:
        fh.write(os.urandom(32))


def test_a_missing_state_file_after_a_join_keeps_the_instance_passive(env):
    """A restore from before the pairing or a hand-made 'reset' removed the file,
    and the standby came up as an acting standalone on the active's key."""
    _key_backup(env)

    assert ha.role() == 'standby' and not ha.is_active()
    assert 'missing' in ha.public_status()['broken']
    assert ha.pull_once() == 'not paired' and ha.watch_once() == 'idle'
    with pytest.raises(ha.HaError):
        ha.promote()
    with pytest.raises(ha.HaError):
        ha._update(interval=60)
    assert not os.path.exists(ha.STATE_FILE)

    assert ha.unpair() == 'standby'
    ha.reset_for_tests()
    assert ha.role() == 'standalone' and ha.public_status()['broken'] == ''


def test_a_missing_state_file_without_a_join_is_an_ordinary_standalone(env):
    # a key rotation backup is not a sign of a pairing
    _key_backup(env, 'aes256.key.backup.20260929_101500')
    assert ha.role() == 'standalone' and ha.public_status()['broken'] == ''


# --- pairing -------------------------------------------------------------------

def _open_code(url='https://pp1.example:5000'):
    code, expires = ha.create_pairing_code(url, '')
    return ha.decode_code(code), expires


def test_pairing_turns_a_standalone_into_the_active_and_hands_over_the_key(env, db):
    assert ha.role() == 'standalone'
    info, expires = _open_code()
    assert info['instance_id'] == ha.instance_id()
    assert ha.public_status()['pairing_open_until'] == expires

    answer = ha.accept_pairing(info['secret'], B, 'https://pp2.example:5000/', FP.lower(), ZK)

    assert ha.role() == 'active' and ha.epoch() == 1
    assert answer['instance_id'] == ha.instance_id() and answer['epoch'] == 1
    assert answer['key_fp'] == ha.key_fingerprint()
    p = ha.peer()
    assert (p['instance_id'], p['url'], p['fingerprint'], p['public_key']) == \
        (B, 'https://pp2.example:5000', FP, ZK)
    assert ha.public_status()['pairing_open_until'] is None

    opened = ha._unseal(info['secret'], answer['sealed'], aad=B)
    assert base64.b64decode(opened['field_key']) == db.aes_key
    # the standby signs with its own key, whose private half never left it
    me = ha.instance_id()
    assert ha.verify_peer(_signed_by(ZKEY, B, me), 'GET', '/api/ha/peer/status')['instance_id'] == B
    # and gets our public key, to check what we sign for it
    assert opened['public_key'] == ha.own_public_key()
    assert ha._load()['signing_key'] not in json.dumps(opened)
    assert 'secret_hash' not in opened and ha._load()['member_secret'] is None

    # the state file keeps the standby's public key, never the field key or the code
    text = _file_bytes(ha.STATE_FILE).decode()
    assert opened['field_key'] not in text and info['secret'] not in text


def test_a_pairing_code_works_once(env, db):
    info, _ = _open_code()
    ha.accept_pairing(info['secret'], B, 'https://pp2.example', '', ZK)

    with pytest.raises(ha.HaError, match='wrong or has expired'):
        ha.accept_pairing(info['secret'], C, 'https://pp3.example', '', ZK)
    assert ha.peer()['instance_id'] == B


def test_a_pairing_code_expires(env, db, monkeypatch):
    info, expires = _open_code()
    monkeypatch.setattr(ha, 'time', types.SimpleNamespace(time=lambda: expires + 1))

    with pytest.raises(ha.HaError, match='wrong or has expired'):
        ha.accept_pairing(info['secret'], B, 'https://pp2.example', '', ZK)
    assert ha.role() == 'standalone' and ha.peer() is None


def test_a_wrong_code_is_refused(env, db):
    _open_code()
    with pytest.raises(ha.HaError, match='wrong or has expired'):
        ha.accept_pairing('s' * 43, B, 'https://pp2.example', '', ZK)
    assert ha.role() == 'standalone'


def _members(*ids):
    return {mid: {'url': f'https://{mid[:4]}.example', 'fingerprint': '',
                  'secret_hash': ha._hash_secret(mid), 'joined_at': '2026-09-30T10:00:00+00:00'}
            for mid in ids}


@pytest.mark.parametrize('change,message', [
    pytest.param({'members': _members('1' * 32, '2' * 32, '3' * 32)}, 'already has 3 standbys',
                 id='group-full'),
    pytest.param({'role': 'standby'}, 'cannot take a standby', id='standby'),
])
def test_accept_pairing_refuses_a_full_group_or_a_standby(env, db, change, message):
    info, _ = _open_code()
    with open(ha.STATE_FILE, encoding='utf-8') as fh:
        st = json.load(fh)
    st.update(change)
    _write_state(**st)

    with pytest.raises(ha.HaError, match=message):
        ha.accept_pairing(info['secret'], B, 'https://pp2.example', '', ZK)
    assert ha.role() == st['role'] and B not in ha._load()['members']


@pytest.mark.parametrize('standby_id,url,fp,secret,message', [
    pytest.param('own', 'https://pp2.example', '', ZK, 'identify', id='own-id'),
    pytest.param('B' * 32, 'https://pp2.example', '', ZK, 'identify', id='id-uppercase'),
    pytest.param(None, 'https://pp2.example', '', ZK, 'identify', id='id-missing'),
    pytest.param(B, 'https://pp2.example', '', ZK[:40] + '=', 'usable public key', id='key-short'),
    pytest.param(B, 'https://pp2.example', '', ZK.replace('=', '!'), 'usable public key',
                 id='key-not-base64'),
    # the hash of a secret, as a standby from before the keys sends it
    pytest.param(B, 'https://pp2.example', '', ZH, 'usable public key', id='secret-hash'),
    # the secret itself, as a standby from before the groups sends it
    pytest.param(B, 'https://pp2.example', '', Z, 'usable public key', id='secret-in-clear'),
    pytest.param(B, 'https://pp2.example', '', [ZK], 'usable public key', id='key-list'),
    pytest.param(B, 'https://pp2.example', '', None, 'usable public key', id='key-missing'),
    pytest.param(B, 'http://pp2.example', '', ZK, 'https://', id='plain-http'),
    pytest.param(B, 'https://pp2.example', 'AB:CD', ZK, 'fingerprint', id='fp-short'),
])
def test_accept_pairing_refuses_a_standby_that_does_not_identify_itself(
        env, db, standby_id, url, fp, secret, message):
    info, _ = _open_code()
    if standby_id == 'own':
        standby_id = ha.instance_id()

    with pytest.raises(ha.HaError, match=re.escape(message)):
        ha.accept_pairing(info['secret'], standby_id, url, fp, secret)
    assert ha.role() == 'standalone' and ha.peer() is None

    # a refused attempt does not use the code up
    ha.accept_pairing(info['secret'], B, 'https://pp2.example', '', ZK)
    assert ha.role() == 'active'


def test_verify_peer_takes_only_the_members_signature(env, db):
    info, _ = _open_code()
    ha.accept_pairing(info['secret'], B, 'https://pp2.example', '', ZK)
    me = ha.instance_id()

    assert ha.verify_peer(_signed_by(ZKEY, B, me), 'GET', '/api/ha/peer/status')['instance_id'] == B
    good = _signed_by(ZKEY, B, me)
    for headers in (
            {ha.PEER_HEADER: f'{B}:{Z}'},                      # a secret, from a member with a key
            dict(good, **{ha.PEER_HEADER: C}),                 # somebody else's id
            _signed_by(ZKEY, C, me),                           # signed as nobody we know
            _signed_by(TKEY, B, me),                           # the right id, another key
            _signed_by(ZKEY, B, C),                            # made for another receiver
            {k: v for k, v in good.items() if k != ha.PEER_SIG_HEADER},
            {}, None, {ha.PEER_HEADER: 42}):
        assert ha.verify_peer(headers, 'GET', '/api/ha/peer/status') is None, headers
    # and a good one counts once
    assert ha.verify_peer(good, 'GET', '/api/ha/peer/status')['instance_id'] == B
    assert ha.verify_peer(good, 'GET', '/api/ha/peer/status') is None


def _key_next_to_the_db(env):
    """Adopting the key is a rotation of the database's own key file, as in
    production, where ha.AES_KEY_FILE and the database's key are one file."""
    import pegaprox.core.db as dbmod
    path = os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key')
    env.mp.setattr(ha, 'AES_KEY_FILE', path)
    return os.path.dirname(path)


def _pre_ha_backups(folder):
    return sorted(f for f in os.listdir(folder) if f.startswith('.pegaprox_aes256.key.pre-ha.'))


def test_join_adopts_the_key_only_after_the_answer_opens(env, db, monkeypatch):
    keydir = _key_next_to_the_db(env)
    old_key, new_key = db.aes_key, os.urandom(32)
    with open(ha.AES_KEY_FILE, 'wb') as fh:
        fh.write(old_key)
    seen = _fake_active(monkeypatch, 's' * 43, new_key)
    me = ha.instance_id()

    p = ha.join(ha.encode_code('https://pp1.example:5000', '', 's' * 43, A),
                'https://pp2.example:5000/', '')

    method, url, path, auth, body = seen[0]
    assert (method, url, path, auth) == ('POST', 'https://pp1.example:5000', '/api/ha/peer/pair', None)
    assert body['code'] == 's' * 43 and body['instance_id'] == me
    assert body['url'] == 'https://pp2.example:5000'
    # only the public half of our new key leaves; we sign with the private one from now on
    assert 'secret' not in body and 'secret_hash' not in body
    assert body['public_key'] == ha.own_public_key()
    assert ha._load()['signing_key'] not in json.dumps(body) and ha._load()['member_secret'] is None
    assert ha.role() == 'standby' and ha.epoch() == 4
    assert (p['instance_id'], p['public_key']) == (A, TK)
    assert ha.verify_peer(_signed_by(TKEY, A, me), 'GET', '/api/ha/peer/status')['instance_id'] == A
    assert ha.source_id() == A

    assert _file_bytes(ha.AES_KEY_FILE) == new_key and db.aes_key == new_key
    backups = _pre_ha_backups(keydir)
    assert len(backups) == 1
    backup = os.path.join(keydir, backups[0])
    assert _file_bytes(backup) == old_key
    assert stat.S_IMODE(os.stat(backup).st_mode) == 0o600


def _fake_active(monkeypatch, code_secret, key, answer_id=A, aad=None, key_fp=None, status=200,
                 epoch=4, public_key=TK, members=(), tombstones=()):
    """The active behind the pair call: it signs with TKEY, so it hands over TK, and
    `members` as its member list."""
    seen = []

    def fake_call(method, base_url, fingerprint, path, json_body=None, auth=None, **kw):
        seen.append((method, base_url, path, auth, dict(json_body)))
        sealed = ha._seal(code_secret, {'field_key': base64.b64encode(key).decode(),
                                        'public_key': public_key,
                                        'members': list(members) if isinstance(members, tuple) else members,
                                        'tombstones': list(tombstones) if isinstance(tombstones, tuple)
                                        else tombstones},
                          aad=aad or json_body['instance_id'])
        data = {'instance_id': answer_id, 'epoch': epoch, 'sealed': sealed,
                'key_fp': key_fp or ha.key_fingerprint(key), 'error': 'no'}
        return types.SimpleNamespace(status_code=status, json=lambda: data)
    monkeypatch.setattr(ha, '_peer_call', fake_call)
    return seen


@pytest.mark.parametrize('answer,message', [
    pytest.param({'answer_id': C}, 'not the one that made the code', id='other-instance'),
    pytest.param({'aad': C}, 'could not be opened', id='sealed-for-someone-else'),
    pytest.param({'key_fp': '0' * 16}, 'not intact', id='key-fingerprint'),
    pytest.param({'status': 403}, 'no', id='refused'),
])
def test_join_writes_nothing_when_the_answer_is_wrong(env, db, monkeypatch, answer, message):
    old_key = db.aes_key
    with open(ha.AES_KEY_FILE, 'wb') as fh:
        fh.write(old_key)
    _fake_active(monkeypatch, 's' * 43, os.urandom(32), **answer)

    with pytest.raises(ha.HaError, match=message):
        ha.join(ha.encode_code('https://pp1.example:5000', '', 's' * 43, A), 'https://pp2.example', '')

    assert not os.path.exists(ha.STATE_FILE)
    assert _file_bytes(ha.AES_KEY_FILE) == old_key and db.aes_key == old_key
    assert [f for f in os.listdir(env.tmp) if f != 'ha'] == ['aes256.key']   # 'ha' is conftest's


def test_a_key_that_cannot_be_written_leaves_a_passive_standby(env, db, monkeypatch):
    """Standby first, key second. The other order left a standalone that acts while
    holding rows it can no longer read, and nothing said so."""
    _fake_active(monkeypatch, 's' * 43, os.urandom(32))

    def broken(_key):
        raise OSError('read-only file system')
    monkeypatch.setattr(ha, '_install_field_key', broken)

    with pytest.raises(ha.HaError, match='could not be written'):
        ha.join(ha.encode_code('https://pp1.example:5000', '', 's' * 43, A), 'https://pp2.example', '')

    ha.reset_for_tests()
    assert ha.role() == 'standby' and not ha.is_active()
    assert 'could not be written' in ha.public_status()['sync']['last_error']


def test_join_only_from_a_standalone_and_not_with_its_own_code(env, db, monkeypatch):
    _fake_active(monkeypatch, 's' * 43, os.urandom(32))
    _write_state(role='standalone', instance_id=A)
    with pytest.raises(ha.HaError, match='made on this instance'):
        ha.join(ha.encode_code('https://pp1.example', '', 's' * 43, A), 'https://pp2.example', '')

    _be_active()
    with pytest.raises(ha.HaError, match='standalone'):
        ha.join(ha.encode_code('https://pp1.example', '', 's' * 43, C), 'https://pp2.example', '')


def _join_code():
    return ha.encode_code('https://pp1.example:5000', '', 's' * 43, A)


@pytest.mark.parametrize('answer', [
    pytest.param({'epoch': 'not-a-number'}, id='epoch-text'),
    pytest.param({'epoch': None}, id='epoch-missing'),
    pytest.param({'epoch': True}, id='epoch-bool'),
    pytest.param({'epoch': 0}, id='epoch-zero'),
    pytest.param({'epoch': -3}, id='epoch-negative'),
    pytest.param({'epoch': 1.5}, id='epoch-float'),
    pytest.param({'epoch': 2 ** 31}, id='epoch-huge'),
    pytest.param({'public_key': TK[:40] + '='}, id='key-short'),
    # an active from before the keys hands over the hash of its secret
    pytest.param({'public_key': ha._hash_secret('t' * 43)}, id='hash-instead-of-key'),
    pytest.param({'public_key': 12345}, id='key-number'),
    pytest.param({'public_key': None}, id='key-missing'),
    pytest.param({'members': {'b' * 32: 'x'}}, id='members-not-a-list'),
    pytest.param({'tombstones': {'b' * 32: 'x'}}, id='tombstones-not-a-list'),
])
def test_join_checks_every_field_of_the_answer_before_it_writes(env, db, monkeypatch, answer):
    """(#625 review) An epoch that was not a number surfaced only after the key file
    had been replaced, and the code was spent on the active by then."""
    old_key = db.aes_key
    with open(ha.AES_KEY_FILE, 'wb') as fh:
        fh.write(old_key)
    installed = []
    monkeypatch.setattr(ha, '_install_field_key', installed.append)
    _fake_active(monkeypatch, 's' * 43, os.urandom(32), **answer)

    with pytest.raises(ha.HaError, match='incomplete'):
        ha.join(_join_code(), 'https://pp2.example', '')

    assert installed == [] and not os.path.exists(ha.STATE_FILE)
    assert ha.role() == 'standalone' and ha.peer() is None
    assert _file_bytes(ha.AES_KEY_FILE) == old_key and db.aes_key == old_key


def test_join_leaves_memory_and_key_alone_when_the_state_cannot_be_written(env, db, monkeypatch):
    installed = []
    monkeypatch.setattr(ha, '_install_field_key', installed.append)
    _fake_active(monkeypatch, 's' * 43, os.urandom(32))
    real = ha._write_locked

    def full_disk(st):
        if st.get('role') == 'standby':
            raise OSError(28, 'No space left on device')
        return real(st)
    monkeypatch.setattr(ha, '_write_locked', full_disk)

    with pytest.raises(OSError):
        ha.join(_join_code(), 'https://pp2.example', '')

    # the running process does not play standby on a file that says standalone
    assert ha.role() == 'standalone' and ha.peer() is None
    assert installed == []


def test_join_refuses_an_own_address_that_is_not_plain_https(env, db, monkeypatch):
    seen = _fake_active(monkeypatch, 's' * 43, os.urandom(32))
    with pytest.raises(ha.HaError, match='https://host'):
        ha.join(_join_code(), 'https://trusted.example@evil.example', '')
    assert seen == [] and not os.path.exists(ha.STATE_FILE)


def test_join_withdraws_the_pairing_code_this_instance_handed_out(env, db, monkeypatch):
    """(#625 review) Our own open code, redeemed while the join waited on the other
    active, made us that standby's active; the join then wrote over it, and the
    standby held our key and a secret nobody accepted any more."""
    installed = []
    monkeypatch.setattr(ha, '_install_field_key', installed.append)
    own = ha.decode_code(ha.create_pairing_code('https://pp2.example:5000', '')[0])
    _fake_active(monkeypatch, 's' * 43, os.urandom(32))
    answer = ha._peer_call
    redeemed = []

    def racing(method, base_url, fingerprint, path, **kw):
        # what a second greenlet can do while the pair call is out
        try:
            redeemed.append(ha.accept_pairing(own['secret'], 'd' * 32, 'https://s.example', '', ZK))
        except ha.HaError as e:
            redeemed.append(str(e))
        return answer(method, base_url, fingerprint, path, **kw)
    monkeypatch.setattr(ha, '_peer_call', racing)

    ha.join(_join_code(), 'https://pp2.example:5000', '')

    assert redeemed == ['The pairing code is wrong or has expired']
    assert ha.role() == 'standby' and ha.peer()['instance_id'] == A
    assert ha.public_status()['pairing_open_until'] is None
    assert len(installed) == 1


def test_join_refuses_when_something_paired_with_this_instance_meanwhile(env, db, monkeypatch):
    installed = []
    monkeypatch.setattr(ha, '_install_field_key', installed.append)
    _fake_active(monkeypatch, 's' * 43, os.urandom(32))
    answer = ha._peer_call
    calls, sent = [], []
    me = ha.instance_id()

    def racing(method, base_url, fingerprint, path, json_body=None, auth=None, headers=None, **kw):
        calls.append((method, base_url, path, auth, dict(headers or {})))
        if path == '/api/ha/peer/pair':
            sent.append(json_body['public_key'])
            # a fresh code, handed out and redeemed while the answer is on its way
            info = ha.decode_code(ha.create_pairing_code('https://pp2.example:5000', '')[0])
            ha.accept_pairing(info['secret'], 'd' * 32, 'https://s.example', '', ZK)
            return answer(method, base_url, fingerprint, path, json_body=json_body, auth=auth, **kw)
        return types.SimpleNamespace(status_code=200, json=lambda: {})
    monkeypatch.setattr(ha, '_peer_call', racing)

    with pytest.raises(ha.HaError, match='changed its pairing while joining'):
        ha.join(_join_code(), 'https://pp2.example:5000', '')

    assert ha.role() == 'active' and ha.peer()['instance_id'] == 'd' * 32
    assert installed == []
    # and the active that took us is told to let go
    method, url, path, auth, _headers = calls[-1]
    assert (method, url, path) == ('POST', 'https://pp1.example:5000', '/api/ha/peer/unpaired')
    # signed with the key whose public half the pair call handed over, which is what
    # the active checks, and for that active
    headers = auth(method, path, b'')
    assert headers[ha.PEER_HEADER] == me
    assert ha._signature_ok(headers, method, path, b'', me, sent[0], A)


@pytest.mark.parametrize('url', [
    pytest.param('https://x.example\r\n2026-09-29 10:00:00 root ha.unpaired forged', id='crlf'),
    pytest.param('https://trusted.example@evil.example', id='userinfo'),
    pytest.param('https://h.example/p?q=1#frag', id='query-fragment'),
    pytest.param('https://h.example/<b>x</b>', id='markup'),
    pytest.param('https://x.example/a b?c#ä', id='space-non-ascii'),
    pytest.param('https://' + 'a' * 600, id='too-long'),
    pytest.param(['https://x.example'], id='list'),
])
def test_accept_pairing_takes_only_a_plain_https_standby_address(env, db, url):
    """(#625 review) The active stored anything that started with https:// as the
    standby address: in its state file, on its status page, in the audit row."""
    info, _ = _open_code()

    with pytest.raises(ha.HaError, match=re.escape('https://host[:port][/path]')):
        ha.accept_pairing(info['secret'], B, url, '', ZK)
    assert ha.role() == 'standalone' and ha.peer() is None

    # a refused address does not use the code up
    ha.accept_pairing(info['secret'], B, 'https://PP2.example:5000/', '', ZK)
    assert ha.peer()['url'] == 'https://pp2.example:5000'


def test_the_key_file_and_its_backup_are_private_whatever_the_umask(env, db):
    """The backup used to be created with umask permissions first."""
    keydir = _key_next_to_the_db(env)
    old_key, new_key = db.aes_key, os.urandom(32)

    old = os.umask(0)
    try:
        ha._install_field_key(new_key)
        assert _file_bytes(ha.AES_KEY_FILE) == new_key and db.aes_key == new_key
        assert stat.S_IMODE(os.stat(ha.AES_KEY_FILE).st_mode) == 0o600
        ha._install_field_key(os.urandom(32))   # again within the same second
    finally:
        os.umask(old)

    backups = _pre_ha_backups(keydir)
    assert len(backups) == 2                    # the first backup is not overwritten
    assert _file_bytes(os.path.join(keydir, backups[0])) == old_key
    for b in backups:
        assert stat.S_IMODE(os.stat(os.path.join(keydir, b)).st_mode) == 0o600


def test_adopting_the_key_reseals_what_stays_local(env, db):
    """(#625 review) A join used to swap the key and nothing else: the acme_* DNS
    secrets, which never sync, and every audit signature stayed sealed under a key
    the instance no longer had."""
    _key_next_to_the_db(env)
    db.save_server_setting('acme_dns_cloudflare_token', db._encrypt('cf-token-local'))
    db.add_audit_entry('root', 'test.before_join', 'signed with the old key')
    new_key = os.urandom(32)

    ha._install_field_key(new_key)

    assert db.aes_key == new_key
    stored = db.get_server_settings()['acme_dns_cloudflare_token']
    assert db._decrypt(stored) == 'cf-token-local'
    row = db.conn.execute("SELECT * FROM audit_log WHERE action = 'test.before_join'").fetchone()
    assert db._verify_audit_hmac(dict(row))


def _tls_failure(monkeypatch):
    import requests

    def refuse(self, *a, **kw):
        raise requests.exceptions.SSLError('certificate verify failed: self-signed certificate')
    monkeypatch.setattr(requests.Session, 'request', refuse)


def test_a_tls_error_without_a_pin_does_not_blame_a_pin(env, monkeypatch):
    _tls_failure(monkeypatch)
    with pytest.raises(ha.HaError) as e:
        ha._peer_call('GET', 'https://10.0.0.5:5000', '', '/api/ha/peer/status', auth=None)
    assert 'not trusted by a CA' in str(e.value) and 'no fingerprint is pinned' in str(e.value)
    assert 'does not match' not in str(e.value)

    with pytest.raises(ha.HaError, match='does not match the pinned fingerprint'):
        ha._peer_call('GET', 'https://10.0.0.5:5000', FP, '/api/ha/peer/status', auth=None)


# --- epochs --------------------------------------------------------------------

def test_step_down_needs_a_newer_epoch_from_the_peer(env):
    # B is active and A its member: A never wins a tie against B
    _write_state(role='active', instance_id=B, epoch=5, peer=_peer(A, role_seen='standby'),
                 sync={'etag': 'x'})
    before = _file_bytes(ha.STATE_FILE)

    assert ha.step_down(5, A) is False
    assert ha.step_down(4, A) is False
    assert ha.step_down(9, C) is False
    assert ha.step_down(9, None) is False
    assert ha.role() == 'active' and ha.epoch() == 5
    assert _file_bytes(ha.STATE_FILE) == before

    assert ha.step_down(6, A) is True
    assert ha.role() == 'standby' and ha.epoch() == 6
    assert (ha.peer()['role_seen'], ha.peer()['epoch_seen']) == ('active', 6)
    assert ha.source_id() == A
    assert ha.public_status()['sync'] == {'etag': None, 'restart_pending': None,
                                          'reload_pending': None, 'last_reload': None}
    # already a standby: nothing left to step down from
    assert ha.step_down(7, A) is False and ha.epoch() == 6
    assert env.restarts == []  # step_down leaves the restart to its caller


@pytest.mark.parametrize('own,seen,expected', [(2, 7, 8), (9, 3, 10), (4, 4, 5), (0, 0, 1)])
def test_promote_takes_the_next_epoch_above_both(env, own, seen, expected):
    _write_state(role='standby', instance_id=B, epoch=own,
                 peer=_peer(A, role_seen='active', epoch_seen=seen))

    assert ha.promote() == expected
    assert ha.role() == 'active' and ha.epoch() == expected
    assert ha.peer()['role_seen'] is None


@pytest.mark.parametrize('role', ['active', 'standalone'])
def test_only_a_standby_can_be_promoted(env, role):
    _write_state(role=role, instance_id=A, epoch=3)
    with pytest.raises(ha.HaError, match='Only a standby'):
        ha.promote()
    assert ha.epoch() == 3


def test_a_standby_whose_state_file_cannot_be_read_is_not_promoted(env):
    """(#625 review) The stand-in has no peer, epoch 0 and a fresh identity. An
    active made from it answered the real active with 401 for good, so the real one
    never learned the newer epoch and both acted."""
    _be_standby(epoch=4)
    whole = _file_bytes(ha.STATE_FILE)
    with open(ha.STATE_FILE, 'wb') as fh:
        fh.write(whole[:len(whole) // 2])
    ha.reset_for_tests()
    half = _file_bytes(ha.STATE_FILE)
    assert ha.is_standby() and ha.public_status()['broken']

    with pytest.raises(ha.HaError, match='before promoting'):
        ha.promote()

    assert ha.role() == 'standby' and not ha.is_active()
    assert _file_bytes(ha.STATE_FILE) == half

    # the file is restored: the pairing is all still there
    with open(ha.STATE_FILE, 'wb') as fh:
        fh.write(whole)
    ha.reset_for_tests()
    assert ha.promote() == 5 and ha.peer()['instance_id'] == A


def _peer_answers(monkeypatch, answer):
    """ha._peer_call answered by `answer(path, json_body)`; records every call."""
    calls = []

    def call(method, base_url, fingerprint, path, json_body=None, auth='peer', headers=None,
             timeout=15):
        calls.append((method, path, json_body, timeout))
        result = answer(path, json_body)
        if isinstance(result, Exception):
            raise result
        return result
    monkeypatch.setattr(ha, '_peer_call', call)
    return calls


def _status(role, epoch, status=200):
    return types.SimpleNamespace(status_code=status, json=lambda: {'role': role, 'epoch': epoch})


def _not_json():
    raise ValueError('Expecting value: line 1 column 1 (char 0)')


def test_an_old_active_asks_its_peer_before_it_acts_and_steps_down(env):
    """(#625 review) A crashed active booted as active and ran managers and loops on
    its stale database until the watch loop's first call, 5 s or more later."""
    _be_active(epoch=1)
    calls = _peer_answers(env.mp, lambda path, body: _status('active', 2))

    assert ha.check_peer_at_boot() == 'stepped down'

    assert calls == [('GET', '/api/ha/peer/status', None, 5)]
    assert ha.role() == 'standby' and ha.epoch() == 2 and not ha.is_active()
    assert (ha.peer()['role_seen'], ha.peer()['epoch_seen']) == ('active', 2)
    # the caller simply comes up as a standby; nothing restarts
    assert env.restarts == []


@pytest.mark.parametrize('answer,result', [
    pytest.param(_status('active', 1), 'ok', id='older-epoch'),
    # a standby under our own epoch is where it belongs
    pytest.param(_status('standby', 3), 'ok', id='peer-is-standby'),
    pytest.param(_status('active', 9, status=429), 'unreachable', id='over-budget'),
    pytest.param(ha.HaError('Cannot reach the peer: ConnectTimeout'), 'unreachable', id='down'),
    pytest.param(types.SimpleNamespace(status_code=200, json=lambda: ['x']), 'unreachable', id='not-a-dict'),
    pytest.param(types.SimpleNamespace(status_code=200, json=lambda: {'epoch': 'x'}), 'unreachable',
                 id='epoch-garbage'),
    pytest.param(types.SimpleNamespace(status_code=200, json=_not_json), 'unreachable', id='not-json'),
])
def test_the_boot_check_keeps_acting_unless_a_newer_active_answers(env, answer, result):
    _be_active(epoch=3)
    _peer_answers(env.mp, lambda path, body: answer)

    assert ha.check_peer_at_boot(timeout=2) == result

    assert ha.role() == 'active' and ha.epoch() == 3
    assert env.restarts == []


@pytest.mark.parametrize('answer,epoch', [
    # the group moved on under epoch 9 and nobody active under it answers: a standby
    # that follows somebody else says so (#625 review)
    pytest.param(_status('standby', 9), 9, id='member-reports-a-newer-epoch'),
    # every member refuses us: we were taken out while we were down
    pytest.param(_status('active', 9, status=401), 3, id='every-member-refuses'),
])
def test_the_boot_check_steps_aside_when_the_group_has_moved_on(env, answer, epoch):
    """Before this, both came up as an acting active next to the group (#625 review):
    the boot check only looked at actives, and a refusal counted as unreachable."""
    _be_active(epoch=3)
    _peer_answers(env.mp, lambda path, body: answer)

    assert ha.check_peer_at_boot(timeout=2) == 'stepped aside'

    assert ha.role() == 'standby' and not ha.is_active() and ha.epoch() == epoch
    assert ha.source_id() is None and ha.peer() is None
    assert 'Stepped aside' in ha.public_status()['sync']['last_error']
    # the boot check comes up passive; nothing restarts
    assert env.restarts == []


@pytest.mark.parametrize('me,them,result', [
    pytest.param(A, B, 'stepped down', id='the-member-wins'),
    pytest.param(B, A, 'ok', id='we-win'),
])
def test_the_boot_check_settles_the_same_epoch_by_instance_id(env, me, them, result):
    """Two actives under one epoch (two admins promoting at once): the higher id stays."""
    _write_state(role='active', instance_id=me, epoch=3, peer=_peer(them, role_seen='standby'))
    _peer_answers(env.mp, lambda path, body: _status('active', 3))

    assert ha.check_peer_at_boot() == result

    assert ha.role() == ('standby' if result == 'stepped down' else 'active') and ha.epoch() == 3
    assert env.restarts == []


@pytest.mark.parametrize('state', ['standalone', 'standby', 'active-without-peer'])
def test_the_boot_check_only_asks_when_active_and_paired(env, state):
    if state == 'standalone':
        _write_state(role='standalone', instance_id=A)
    elif state == 'standby':
        _be_standby()
    else:
        _write_state(role='active', instance_id=A, epoch=3)
    calls = _peer_answers(env.mp, lambda path, body: _status('active', 99))

    assert ha.check_peer_at_boot() == 'idle'
    assert calls == []


def test_the_boot_check_never_raises(env):
    _be_active()

    def broken():
        raise RuntimeError('disk on fire')
    env.mp.setattr(ha, 'role', broken)
    assert ha.check_peer_at_boot() == 'error'


def test_watch_once_reads_its_own_epoch_before_the_call(env):
    """The peer's own watch loop stepped us down while our status call was out; our
    epoch read afterwards equalled theirs and a false 'same epoch' conflict landed
    on the page."""
    _be_active(epoch=3)

    def answer(path, body):
        ha.step_down(4, B)
        return _status('active', 4)
    _peer_answers(env.mp, answer)

    assert ha.watch_once() == 'idle'
    assert ha.role() == 'standby'
    assert 'same epoch' not in ha.public_status()['peer']['last_error']


def test_equal_epochs_are_settled_by_the_instance_id(env):
    """Both instances active under one epoch used to be a conflict an admin had to
    untangle by unpairing. The higher instance id stays active now, on both sides."""
    _be_active(epoch=3)                       # we are A, the member B is the higher id
    calls = _peer_answers(env.mp, lambda path, body: _status('active', 3))

    assert ha.watch_once() == 'stepped down'
    assert ha.role() == 'standby' and ha.source_id() == B and ha.epoch() == 3
    assert env.restarts == ['stepped down to standby']
    assert [c[1] for c in calls] == ['/api/ha/peer/status']

    # the other side: we are the higher id and tell the lower one to step down
    _write_state(role='active', instance_id=B, epoch=3, peer=_peer(A, role_seen='standby'))
    calls = _peer_answers(env.mp, lambda path, body: _status('active', 3))
    assert ha.watch_once() == 'told peer to step down'
    assert ha.role() == 'active'
    assert calls[-1][:3] == ('POST', '/api/ha/peer/step-down', {'epoch': 3})


# --- snapshot and apply --------------------------------------------------------

def _set(db, key, value):
    db.conn.execute('INSERT OR REPLACE INTO server_settings (key, value) VALUES (?, ?)', (key, value))
    db.conn.commit()


def _settings(db):
    return {r['key']: r['value'] for r in db.conn.execute('SELECT key, value FROM server_settings')}


def _users(db):
    return {r['username'] for r in db.conn.execute('SELECT username FROM users')}


def _wire(snap):
    """What the standby gets: gzip'd JSON over HTTP."""
    return json.loads(gzip.decompress(ha.snapshot_bytes(snap)))


def _add_passkey(db, username, cred):
    db.conn.execute(
        'INSERT INTO webauthn_credentials (username, credential_id, public_key, name, user_handle, '
        'created_at) VALUES (?, ?, ?, ?, ?, ?)',
        (username, cred, b'\x04' + bytes(range(64)), 'yubikey', b'\x00\xffhandle', '2026-09-29'))
    db.conn.commit()


def _snapshot_from_the_active(env, db, seed):
    _be_active()
    seed.user('alice', role='admin')
    seed.user('bob')
    _set(db, 'smtp_host', 'mail.corp.example')
    _add_passkey(db, 'alice', b'\x00\x01\x02\xff\xfecred')
    with open(ha.KNOWN_HOSTS_FILE, 'w') as fh:
        fh.write('10.0.0.11 ssh-ed25519 AAAAC3Nza\n')
    os.makedirs(ha.BRANDING_DIR)
    with open(os.path.join(ha.BRANDING_DIR, 'login-bg.png'), 'wb') as fh:
        fh.write(b'\x89PNG\r\n\x1a\n' + os.urandom(64))
    return _wire(ha.build_snapshot())


def test_snapshot_and_apply_round_trip(env, db, seed):
    snap = _snapshot_from_the_active(env, db, seed)
    branding = _file_bytes(os.path.join(ha.BRANDING_DIR, 'login-bg.png'))
    assert (snap['format'], snap['instance_id'], snap['role'], snap['epoch']) == (1, A, 'active', 3)
    assert set(snap['tables']) <= set(ha.SYNC_TABLES)
    assert not set(snap['tables']) & set(ha.LOCAL_TABLES)

    # the standby's copy drifted: a user deleted, one added, a setting changed,
    # the passkey gone, host keys and branding different
    audit_rows = db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    db.conn.execute("DELETE FROM users WHERE username = 'bob'")
    db.conn.execute('DELETE FROM webauthn_credentials')
    db.conn.commit()
    seed.user('carol')
    _set(db, 'smtp_host', 'mail.standby.example')
    _set(db, 'smtp_port', '2525')
    with open(ha.KNOWN_HOSTS_FILE, 'w') as fh:
        fh.write('')
    with open(os.path.join(ha.BRANDING_DIR, 'login-bg.png'), 'wb') as fh:
        fh.write(b'other')
    _be_standby()

    summary = ha.apply_snapshot(snap)

    assert _users(db) == {'alice', 'bob'}
    settings = _settings(db)
    assert settings['smtp_host'] == 'mail.corp.example' and 'smtp_port' not in settings
    row = db.conn.execute('SELECT credential_id, public_key, user_handle FROM webauthn_credentials').fetchone()
    assert (row[0], row[1], row[2]) == (b'\x00\x01\x02\xff\xfecred', b'\x04' + bytes(range(64)),
                                        b'\x00\xffhandle')
    assert isinstance(row[0], bytes)
    assert _file_bytes(ha.KNOWN_HOSTS_FILE) == b'10.0.0.11 ssh-ed25519 AAAAC3Nza\n'
    assert stat.S_IMODE(os.stat(ha.KNOWN_HOSTS_FILE).st_mode) == 0o600
    assert _file_bytes(os.path.join(ha.BRANDING_DIR, 'login-bg.png')) == branding
    # instance-local tables are not touched
    assert db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0] >= audit_rows
    assert summary['tables'] == len(snap['tables']) and summary['rows'] > 0
    assert summary['created'] == [] and summary['skipped_columns'] == {}


def test_instance_local_settings_never_travel_and_survive_an_apply(env, db, seed):
    local = sorted(ha.LOCAL_SETTING_KEYS) + ['acme_email', 'acme_account_key', 'acme_last_renewal']
    _be_active()
    for key in local:
        _set(db, key, f'active {key}')
    _set(db, 'smtp_host', 'mail.corp.example')
    snap = _wire(ha.build_snapshot())

    sent = {r[0] for r in snap['tables']['server_settings']['rows']}
    assert 'smtp_host' in sent
    assert not sent & set(local)

    for key in local:
        _set(db, key, f'standby {key}')
    _set(db, 'acme_only_here', 'x')
    _be_standby()
    # even when a snapshot does carry one, the standby keeps its own
    snap['tables']['server_settings']['rows'].append(['domain', 'pp1.corp.example'])
    snap['tables']['server_settings']['rows'].append(['acme_email', 'ops@corp.example'])

    ha.apply_snapshot(snap)

    settings = _settings(db)
    assert settings['smtp_host'] == 'mail.corp.example'
    for key in local:
        assert settings[key] == f'standby {key}', key
    assert settings['acme_only_here'] == 'x'


@pytest.mark.parametrize('change,message', [
    pytest.param({'instance_id': C}, 'not from the paired instance', id='other-instance'),
    pytest.param({'role': 'standby'}, 'not active', id='source-not-active'),
    pytest.param({'role': 'standalone'}, 'not active', id='source-standalone'),
    pytest.param({'epoch': 2}, 'older epoch', id='older-epoch'),
    pytest.param({'key_fp': '0' * 16}, 'field key changed', id='other-key'),
    pytest.param({'format': 2}, 'snapshot format', id='other-format'),
])
def test_apply_refuses_a_snapshot_it_should_not_trust(env, db, seed, change, message):
    snap = _snapshot_from_the_active(env, db, seed)
    db.conn.execute("DELETE FROM users WHERE username = 'bob'")
    db.conn.commit()
    seed.user('carol')
    _be_standby()
    snap.update(change)

    with pytest.raises(ha.HaError, match=message):
        ha.apply_snapshot(snap)
    assert _users(db) == {'alice', 'carol'}


def test_apply_takes_a_newer_epoch(env, db, seed):
    snap = _snapshot_from_the_active(env, db, seed)
    _be_standby(epoch=3)
    snap['epoch'] = 7
    ha.apply_snapshot(snap)
    assert _users(db) == {'alice', 'bob'}


def test_apply_needs_a_peer(env, db, seed):
    snap = _snapshot_from_the_active(env, db, seed)
    _write_state(role='standby', instance_id=B, epoch=3)
    with pytest.raises(ha.HaError, match='Not paired'):
        ha.apply_snapshot(snap)


def _tables(db):
    return {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_a_missing_table_is_created_from_the_sent_statement(env, db, seed):
    _be_active()
    db.conn.execute("INSERT INTO power_rates (cluster_id, kwh_price) VALUES ('c1', 0.42)")
    db.conn.commit()
    snap = _wire(ha.build_snapshot())
    assert snap['tables']['power_rates']['sql'].startswith('CREATE TABLE power_rates')

    db.conn.execute('DROP TABLE power_rates')
    db.conn.commit()
    _be_standby()

    summary = ha.apply_snapshot(snap)

    assert summary['created'] == ['power_rates']
    row = db.conn.execute('SELECT kwh_price FROM power_rates WHERE cluster_id = ?', ('c1',)).fetchone()
    assert row[0] == 0.42


@pytest.mark.parametrize('sql', [
    pytest.param('CREATE TABLE other_table (id TEXT PRIMARY KEY)', id='other-name'),
    pytest.param('CREATE TABLE auto_install_profiles_x (id TEXT)', id='prefixed-name'),
    pytest.param('DROP TABLE users', id='drop'),
    pytest.param('CREATE VIEW auto_install_profiles AS SELECT * FROM users', id='view'),
    pytest.param('CREATE TABLE auto_install_profiles AS SELECT * FROM users', id='create-as-select'),
    pytest.param('CREATE TEMP TABLE auto_install_profiles (id TEXT)', id='temp'),
    pytest.param('CREATE TABLE main.auto_install_profiles (id TEXT)', id='schema-qualified'),
    pytest.param('', id='empty'),
])
def test_a_statement_that_is_not_that_tables_create_is_refused(env, db, seed, sql):
    _refused_and_rolled_back(env, db, seed, sql, ha.HaError)


def test_a_create_with_a_second_statement_behind_it_is_refused(env, db, seed):
    # the name check passes; sqlite3 itself refuses to run two statements in one execute
    _refused_and_rolled_back(
        env, db, seed, 'CREATE TABLE auto_install_profiles (id TEXT); DROP TABLE users', Exception)


def _refused_and_rolled_back(env, db, seed, sql, exc):
    snap = _snapshot_from_the_active(env, db, seed)
    assert ha.SYNC_TABLES.index('power_rates') < ha.SYNC_TABLES.index('auto_install_profiles')
    # power_rates is recreated first, users rewritten even earlier; all of it has to go
    db.conn.execute('DROP TABLE power_rates')
    db.conn.execute('DROP TABLE auto_install_profiles')
    db.conn.execute("DELETE FROM users WHERE username = 'bob'")
    db.conn.commit()
    seed.user('carol')
    _set(db, 'smtp_host', 'mail.standby.example')
    _be_standby()
    snap['tables']['auto_install_profiles']['sql'] = sql
    before_tables = _tables(db)

    with pytest.raises(exc):
        ha.apply_snapshot(snap)

    assert _tables(db) == before_tables
    assert 'power_rates' not in before_tables and 'other_table' not in before_tables
    assert _users(db) == {'alice', 'carol'}
    assert _settings(db)['smtp_host'] == 'mail.standby.example'
    assert not db.conn.in_transaction


# --- the etag ------------------------------------------------------------------

def _add_token(db, username, prefix):
    db.conn.execute('INSERT INTO api_tokens (token_hash, token_prefix, username, name, created_at) '
                    'VALUES (?, ?, ?, ?, ?)', (prefix * 16, prefix, username, 'ci', '2026-09-29'))
    db.conn.commit()


def _row(snap, table, key_col, key):
    t = snap['tables'][table]
    row = [r for r in t['rows'] if r[t['columns'].index(key_col)] == key][0]
    return dict(zip(t['columns'], row))


def test_the_etag_leaves_out_what_every_login_and_token_use_writes(env, db, seed):
    """(#625 review) Every login wrote users.last_login and every token use
    api_tokens.last_used_at, so on a busy active nearly every poll was a full
    transfer of the whole configuration."""
    _be_active()
    seed.user('alice', role='admin')
    seed.user('bob')
    _add_token(db, 'alice', 'pgx1')
    first = ha.build_snapshot()
    assert ha.snapshot_etag() == first['etag']

    db.conn.execute("UPDATE users SET last_login = '2026-09-29T11:00:00' WHERE username = 'alice'")
    db.conn.execute("UPDATE api_tokens SET last_used_at = '2026-09-29T11:00:01', last_used_ip = '10.0.0.9'")
    # a save goes through INSERT OR REPLACE, which moves the row to the end
    db.conn.execute("INSERT OR REPLACE INTO users SELECT * FROM users WHERE username = 'alice'")
    db.conn.commit()
    assert [r['username'] for r in db.conn.execute('SELECT * FROM users')][-1] == 'alice'

    assert ha.snapshot_etag() == first['etag']
    second = ha.build_snapshot()
    assert second['etag'] == first['etag']
    # the values still travel with the next body
    assert _row(second, 'users', 'username', 'alice')['last_login'] == '2026-09-29T11:00:00'
    assert _row(second, 'api_tokens', 'username', 'alice')['last_used_ip'] == '10.0.0.9'

    db.conn.execute("UPDATE users SET role = 'viewer' WHERE username = 'bob'")
    db.conn.commit()
    assert ha.snapshot_etag() != first['etag']


def test_the_etag_alone_builds_no_body(env, db, seed, monkeypatch):
    _be_active()
    seed.user('alice')
    os.makedirs(ha.BRANDING_DIR)
    with open(os.path.join(ha.BRANDING_DIR, 'login-bg.png'), 'wb') as fh:
        fh.write(b'\x89PNG' + os.urandom(64))
    etag = ha.build_snapshot()['etag']

    def no_body(*a, **kw):
        raise AssertionError('the etag path built a body')
    monkeypatch.setattr(ha, '_enc', no_body)
    monkeypatch.setattr(ha, '_row_converter', no_body)
    monkeypatch.setattr(ha, 'base64', types.SimpleNamespace(b64encode=no_body, b64decode=base64.b64decode))

    assert ha.snapshot_etag() == etag
    with open(os.path.join(ha.BRANDING_DIR, 'login-bg.png'), 'wb') as fh:
        fh.write(b'another picture')
    assert ha.snapshot_etag() != etag


def test_a_legacy_fernet_value_travels_resealed_under_the_field_key(env, db, seed, monkeypatch):
    """(#625 review) Pairing hands over the field key, not the Fernet key. A value
    still in the old Fernet format reached the standby as it was, and the standby's
    _decrypt handed the token out as the secret: 2FA failed, LDAP bound with it."""
    from cryptography.fernet import Fernet
    _be_active()
    seed.user('olduser')
    totp = db.fernet.encrypt(b'JBSWY3DPEHPK3PXP').decode()
    lookalike = 'gAAAAAnot-a-token-at-all'
    db.conn.execute("UPDATE users SET totp_secret_encrypted = ?, totp_pending_secret_encrypted = ? "
                    "WHERE username = 'olduser'", (totp, lookalike))
    db.conn.execute("INSERT INTO pbs_servers (id, name, host, user, pass_encrypted) VALUES (?, ?, ?, ?, ?)",
                    ('p1', 'pbs', '10.0.0.7', 'root@pam', db.fernet.encrypt(b'pbs-pass').decode()))
    _set(db, 'smtp_password', json.dumps(db.fernet.encrypt(b'mail-pass').decode()))
    stored = _settings(db)['smtp_password']

    snap = _wire(ha.build_snapshot())

    # nothing is written back on the active
    assert db.conn.execute("SELECT totp_secret_encrypted FROM users WHERE username = 'olduser'"
                           ).fetchone()[0] == totp
    assert _settings(db)['smtp_password'] == stored
    # the etag comes from what is stored, so the random reseal does not move it
    assert snap['etag'] == ha.snapshot_etag() == ha.build_snapshot()['etag']
    sent = _row(snap, 'users', 'username', 'olduser')
    assert sent['totp_secret_encrypted'].startswith('aes256:')
    assert sent['totp_pending_secret_encrypted'] == lookalike    # not a token: as it is

    # the standby holds our field key and a Fernet key of its own
    monkeypatch.setattr(db, 'fernet', Fernet(Fernet.generate_key()))
    _be_standby()
    ha.apply_snapshot(snap)

    assert db.get_user('olduser')['totp_secret'] == 'JBSWY3DPEHPK3PXP'
    assert db._decrypt(json.loads(_settings(db)['smtp_password'])) == 'mail-pass'
    pbs = db.conn.execute("SELECT pass_encrypted FROM pbs_servers WHERE id = 'p1'").fetchone()[0]
    assert db._decrypt(pbs) == 'pbs-pass'


def test_a_node_password_travels_like_the_cluster_password(env, db, seed, monkeypatch):
    """(#1136) The root password of a single node is configuration the active acts on: it
    goes to the standby sealed as it is stored, as clusters.pass_encrypted does, a legacy
    Fernet value resealed under the field key, and opens there. MK Oct 2026"""
    from cryptography.fernet import Fernet
    _be_active()
    db.save_cluster('c1', {'name': 'c1', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'cluster-pw'})
    db.save_node_credential('c1', 'pve2', 'pve2-own-root', 'alice')
    db.conn.execute("INSERT INTO cluster_node_credentials (cluster_id, node, password_encrypted) "
                    "VALUES ('c1', 'pve3', ?)", (db.fernet.encrypt(b'pve3-legacy').decode(),))
    db.conn.commit()
    stored = db.conn.execute("SELECT password_encrypted FROM cluster_node_credentials "
                             "WHERE node = 'pve2'").fetchone()[0]

    snap = _wire(ha.build_snapshot())

    assert 'cluster_node_credentials' in snap['tables']
    sent2 = _row(snap, 'cluster_node_credentials', 'node', 'pve2')
    sent3 = _row(snap, 'cluster_node_credentials', 'node', 'pve3')
    assert sent2['password_encrypted'] == stored and stored.startswith('aes256:')
    assert sent3['password_encrypted'].startswith('aes256:')
    assert 'pve2-own-root' not in json.dumps(snap) and 'pve3-legacy' not in json.dumps(snap)

    monkeypatch.setattr(db, 'fernet', Fernet(Fernet.generate_key()))
    db.conn.execute('DELETE FROM cluster_node_credentials')
    db.conn.commit()
    _be_standby()
    ha.apply_snapshot(snap)

    assert db.node_credential_secrets('c1') == {'pve2': 'pve2-own-root', 'pve3': 'pve3-legacy'}


# --- plugin configuration --------------------------------------------------------

def _plugin(name, text=None, mode=None):
    folder = os.path.join(ha.PLUGINS_DIR, name)
    os.makedirs(folder, exist_ok=True)
    if text is not None:
        path = os.path.join(folder, 'config.json')
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(path, mode)
    return folder


def test_plugin_configuration_travels_into_the_plugins_this_instance_has(env, db, seed):
    """(#625 review) status_page, client_portal and notifications keep their settings
    in plugins/<id>/config.json. A promoted standby served its own status key,
    portal policy and alert targets."""
    _be_active()
    _plugin('status_page', '{"auth_key": "active-key"}')
    _plugin('client_portal', '{"allowed_actions": ["vm.view"]}')
    _plugin('notifications', '{"ntfy_topic": "active-ops"}')
    _plugin('Bad.Id', '{"x": 1}')
    _plugin('broken', '{not json')
    _plugin('huge', json.dumps({'x': 'y' * (300 * 1024)}))
    _plugin('noconfig')
    os.symlink(os.path.join(ha.PLUGINS_DIR, 'status_page', 'config.json'),
               os.path.join(_plugin('linked'), 'config.json'))
    etag = ha.snapshot_etag()
    snap = _wire(ha.build_snapshot())

    assert snap['etag'] == etag
    assert set(snap['files']['plugin_config']) == {'status_page', 'client_portal', 'notifications'}

    # the standby: an older status page config with a mode of its own, no client
    # portal config yet, and no notifications plugin at all
    _plugin('status_page', '{"auth_key": ""}', mode=0o640)
    os.unlink(os.path.join(ha.PLUGINS_DIR, 'client_portal', 'config.json'))
    shutil.rmtree(os.path.join(ha.PLUGINS_DIR, 'notifications'))
    _be_standby()
    ha.apply_snapshot(snap)

    sp = os.path.join(ha.PLUGINS_DIR, 'status_page', 'config.json')
    assert json.loads(_file_bytes(sp)) == {'auth_key': 'active-key'}
    assert stat.S_IMODE(os.stat(sp).st_mode) == 0o640
    cp = os.path.join(ha.PLUGINS_DIR, 'client_portal', 'config.json')
    assert json.loads(_file_bytes(cp)) == {'allowed_actions': ['vm.view']}
    assert stat.S_IMODE(os.stat(cp).st_mode) == 0o600
    assert not os.path.exists(os.path.join(ha.PLUGINS_DIR, 'notifications'))
    assert not [f for f in os.listdir(os.path.join(ha.PLUGINS_DIR, 'status_page')) if f.endswith('-tmp')]

    # and a change of a plugin config is a change of the snapshot
    _plugin('client_portal', '{"allowed_actions": []}')
    assert ha.snapshot_etag() != etag


def test_a_snapshot_writes_nothing_but_a_plugins_own_config(env, db, seed):
    _be_active()
    snap = _wire(ha.build_snapshot())
    outside = os.path.join(env.tmp, 'outside.json')
    with open(outside, 'w', encoding='utf-8') as fh:
        fh.write('{"keep": true}')
    os.symlink(outside, os.path.join(_plugin('linked'), 'config.json'))
    _plugin('portal', '{"a": 1}')
    snap['files']['plugin_config'] = {
        '../outside': '{"x": 1}', 'linked': '{"x": 1}', 'portal': '{not json',
        'Portal': '{"x": 1}', 'missing': '{"x": 1}', 'numbers': 5,
    }
    _be_standby()

    ha.apply_snapshot(snap)

    assert json.loads(_file_bytes(outside)) == {'keep': True}
    assert os.path.islink(os.path.join(ha.PLUGINS_DIR, 'linked', 'config.json'))
    assert json.loads(_file_bytes(os.path.join(ha.PLUGINS_DIR, 'portal', 'config.json'))) == {'a': 1}
    assert sorted(os.listdir(ha.PLUGINS_DIR)) == ['linked', 'portal']


# --- sessions after an apply -----------------------------------------------------

def test_an_apply_ends_the_sessions_of_users_whose_sign_in_changed(env, db, seed, monkeypatch):
    """(#625 review) A password reset on the active ended the user's sessions there
    only. The standby took the new hash and kept every session it held, so one
    opened there with a leaked password outlived the reset."""
    from pegaprox.utils import auth, realtime
    monkeypatch.setattr(auth, 'active_sessions', {})
    monkeypatch.setattr(realtime, 'ws_tokens', {})
    monkeypatch.setattr(realtime, 'sse_tokens', {})
    names = ('alice', 'bob', 'carol', 'dave')
    _be_active()
    for name in names:
        seed.user(name)
    db.conn.execute("UPDATE users SET password_hash = 'reset-on-the-active' WHERE username = 'alice'")
    db.conn.execute("UPDATE users SET enabled = 0 WHERE username = 'bob'")
    db.conn.execute("UPDATE users SET last_login = '2026-09-29T11:00:00' WHERE username = 'dave'")
    db.conn.commit()
    snap = _wire(ha.build_snapshot())
    users = snap['tables']['users']
    users['rows'] = [r for r in users['rows'] if r[users['columns'].index('username')] != 'carol']

    # the standby's copy from before, with a session and tokens for everyone
    db.conn.execute("UPDATE users SET password_hash = 'x', enabled = 1, last_login = NULL")
    db.conn.commit()
    for name in names:
        auth.create_session(name, 'user')
        realtime.create_ws_token(name, 'user')
        realtime.create_sse_token(name, [])
    _be_standby()

    ha.apply_snapshot(snap)

    # dave only logged in: a changed last_login is no reason to end anything
    assert {s['user'] for s in auth.active_sessions.values()} == {'dave'}
    assert {d['user'] for d in realtime.ws_tokens.values()} == {'dave'}
    assert {d['user'] for d in realtime.sse_tokens.values()} == {'dave'}


def test_a_failing_session_step_does_not_undo_the_sync(env, db, seed, monkeypatch):
    from pegaprox.utils import auth

    def broken(username):
        raise RuntimeError('session store gone')
    monkeypatch.setattr(auth, 'invalidate_all_user_sessions', broken)
    _be_active()
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    db.conn.execute("UPDATE users SET password_hash = 'old' WHERE username = 'alice'")
    db.conn.commit()
    _be_standby()

    ha.apply_snapshot(snap)

    assert db.conn.execute("SELECT password_hash FROM users WHERE username = 'alice'").fetchone()[0] == 'x'


# --- the etag a standby keeps -------------------------------------------------------

def _snapshot_to_pull(db, seed, extra_column=False):
    _be_active()
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    if extra_column:
        # from a newer release: a column this instance does not have yet
        name = extra_column if isinstance(extra_column, str) else 'added_in_a_later_release'
        users = snap['tables']['users']
        users['columns'].append(name)
        for row in users['rows']:
            row.append('x')
    _be_standby()
    return snap


def _serve(env, snap):
    """The active behind the pull: 304 for the snapshot's etag, else the snapshot.
    Returns the If-None-Match of every call."""
    sent = []

    def call(method, base_url, fingerprint, path, json_body=None, auth='peer', headers=None,
             timeout=15):
        inm = (headers or {}).get('If-None-Match')
        sent.append(inm)
        if inm == snap['etag']:
            return types.SimpleNamespace(status_code=304, json=lambda: {})
        return types.SimpleNamespace(status_code=200, json=lambda: snap)
    env.mp.setattr(ha, '_peer_call', call)
    return sent


def test_a_column_the_active_has_and_we_lack_is_added_not_dropped(env, db, seed):
    """(#625 live test) custom_scripts gets deleted_at and three more columns only on
    first use. A standby that had never used it dropped them, so a script deleted on
    the active came back as live on the standby."""
    snap = _snapshot_to_pull(db, seed, extra_column=True)
    _serve(env, snap)

    assert ha.pull_once() == 'applied'
    sync = ha._load()['sync']
    assert sync['skipped_columns'] == {}
    cols = [r[1] for r in db.conn.execute('PRAGMA table_info("users")').fetchall()]
    assert 'added_in_a_later_release' in cols
    assert db.conn.execute("SELECT added_in_a_later_release FROM users WHERE username = 'alice'"
                           ).fetchone()[0] == 'x'
    assert sync.get('etag') == snap['etag']


def test_an_etag_is_kept_only_when_no_column_was_left_out(env, db, seed):
    """(#625 review) A left-out column used to keep the etag, and the next pull was a
    304 that never brought it. Only a name that is not an identifier is left out now."""
    snap = _snapshot_to_pull(db, seed, extra_column='not a column; DROP TABLE users')
    sent = _serve(env, snap)

    assert ha.pull_once() == 'applied'
    sync = ha._load()['sync']
    assert sync['skipped_columns'] == {'users': ['not a column; DROP TABLE users']}
    assert sync.get('etag') is None
    assert ha.pull_once() == 'applied'
    assert sent == [None, None]
    assert db.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] >= 1


def test_the_first_pull_after_a_start_is_a_full_one(env, db, seed):
    snap = _snapshot_to_pull(db, seed)
    ha._update_sync(etag=snap['etag'])          # kept from the run before
    sent = _serve(env, snap)

    assert ha.pull_once() == 'applied'
    assert ha._load()['sync']['etag'] == snap['etag']
    assert ha.pull_once() == 'unchanged'
    assert sent == [None, snap['etag']]

    env.mp.setattr(ha, '_etag_checked', False)  # a restart
    assert ha.pull_once() == 'applied'
    assert sent[-1] is None


# --- every table has a place ---------------------------------------------------

_CREATE = re.compile(
    r'\bCREATE\s+(?:VIRTUAL\s+|TEMP\s+|TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?'
    r'["`\[]?([A-Za-z_][A-Za-z0-9_]*)["`\]]?\s*(?:\(|USING\b|AS\b)', re.I)
_DYNAMIC = re.compile(
    r'\bCREATE\s+(?:VIRTUAL\s+|TEMP\s+|TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`\[]?\{', re.I)


def _created_tables():
    found, dynamic = {}, []
    for top in ('pegaprox', 'plugins'):
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, top)):
            dirnames[:] = [d for d in dirnames if d != '__pycache__']
            for fn in filenames:
                if not fn.endswith(('.py', '.sql')):
                    continue
                path = os.path.join(dirpath, fn)
                with open(path, encoding='utf-8', errors='replace') as fh:
                    src = fh.read()
                rel = os.path.relpath(path, ROOT)
                for m in _CREATE.finditer(src):
                    found.setdefault(m.group(1), rel)
                dynamic += [rel for _ in _DYNAMIC.finditer(src)]
    return found, dynamic


def test_every_table_is_either_synced_or_instance_local():
    found, dynamic = _created_tables()
    # the scan has to see what it is meant to see, or the rest passes on nothing
    assert len(found) >= 50 and {'users', 'logs_fts', 'pegaprox_kv'} <= set(found)
    assert not dynamic, f'CREATE TABLE with a computed name in {dynamic} - place it by hand'

    sync, local = set(ha.SYNC_TABLES), set(ha.LOCAL_TABLES)
    assert len(sync) == len(ha.SYNC_TABLES) and len(local) == len(ha.LOCAL_TABLES)
    assert not sync & local, f'in both lists: {sorted(sync & local)}'
    unplaced = {name: where for name, where in found.items() if name not in sync | local}
    assert not unplaced, ('new tables need a place in ha.SYNC_TABLES (shared configuration) '
                          f'or ha.LOCAL_TABLES (per host): {unplaced}')
    # a typo in SYNC_TABLES would quietly leave the real table out of every snapshot
    assert not sync - set(found), f'synced but never created: {sorted(sync - set(found))}'


# --- second review of the fix round -----------------------------------------------------

def test_an_added_column_takes_the_actives_type_and_default(env, db, seed):
    """A later migration finds the column there and skips its ALTER, so the column
    has to arrive with what that ALTER would have set."""
    snap = _snapshot_to_pull(db, seed)
    users = snap['tables']['users']
    users['columns'].append('prefs_json')
    users['coldefs']['prefs_json'] = ['TEXT', "'{}'"]
    for row in users['rows']:
        row.append('{"a": 1}')
    _serve(env, snap)

    assert ha.pull_once() == 'applied'
    info = {r[1]: (r[2], r[4]) for r in db.conn.execute('PRAGMA table_info("users")').fetchall()}
    assert info['prefs_json'] == ('TEXT', "'{}'")
    db.conn.execute("INSERT INTO users (username, password_salt, password_hash) VALUES ('zed', 'x', 'x')")
    assert db.conn.execute("SELECT prefs_json FROM users WHERE username = 'zed'").fetchone()[0] == '{}'


@pytest.mark.parametrize('ctype,dflt', [
    ('TEXT; DROP TABLE users', None), ('TEXT', "1); DROP TABLE users; --"), ('TEXT', 'CURRENT_TIMESTAMP'),
])
def test_a_column_definition_that_is_not_plain_falls_back_to_no_type(env, db, seed, ctype, dflt):
    snap = _snapshot_to_pull(db, seed, extra_column=True)
    snap['tables']['users']['coldefs']['added_in_a_later_release'] = [ctype, dflt]
    _serve(env, snap)

    assert ha.pull_once() == 'applied'
    info = {r[1]: (r[2], r[4]) for r in db.conn.execute('PRAGMA table_info("users")').fetchall()}
    assert info['added_in_a_later_release'][1] is None
    assert db.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] >= 1


def test_a_column_that_differs_only_in_case_is_the_same_column(env, db, seed):
    """SQLite ignores case in column names; ADD COLUMN "Username" next to username
    failed and rolled the whole sync back, every time."""
    snap = _snapshot_to_pull(db, seed)
    users = snap['tables']['users']
    users['columns'] = [c.upper() if c == 'username' else c for c in users['columns']]
    _serve(env, snap)

    assert ha.pull_once() == 'applied'
    assert ha._load()['sync']['skipped_columns'] == {}
    assert db.conn.execute("SELECT COUNT(*) FROM users WHERE username = 'alice'").fetchone()[0] == 1


def test_a_failed_key_write_is_reported_even_when_the_note_cannot_be_saved(env, db, monkeypatch):
    _fake_active(monkeypatch, 's' * 43, os.urandom(32))
    monkeypatch.setattr(ha, '_install_field_key', lambda k: (_ for _ in ()).throw(OSError('disk full')))
    real = ha._update_sync

    def failing_note(**kw):
        if 'last_error' in kw:
            raise OSError('disk full')
        return real(**kw)
    monkeypatch.setattr(ha, '_update_sync', failing_note)

    with pytest.raises(ha.HaError, match='could not be written'):
        ha.join(_join_code(), 'https://pp2.example', '')
    assert ha.role() == 'standby'


def test_one_unreadable_secret_does_not_strand_the_ones_after_it(env, db):
    """The rotation re-sealed the secret settings in one try: a synced value that
    did not open aborted it before the acme_* secrets that never sync."""
    _key_next_to_the_db(env)
    db.save_server_setting('smtp_password', 'aes256:' + base64.b64encode(os.urandom(40)).decode())
    db.save_server_setting('acme_dns_cloudflare_token', db._encrypt('cf-token-local'))
    new_key = os.urandom(32)

    ha._install_field_key(new_key)

    assert db.aes_key == new_key
    assert db._decrypt(db.get_server_settings()['acme_dns_cloudflare_token']) == 'cf-token-local'


def test_the_snapshot_worker_needs_no_state_lock_and_logs_nothing(env, db, seed, monkeypatch):
    """build_snapshot runs in gevent's threadpool. The state lock and the logging
    handlers are gevent locks; a native thread holding one cannot wake a greenlet
    waiting for it. Metadata comes in from the hub, warnings go back out."""
    _be_active()
    meta = ha.snapshot_meta()

    def no_lock():
        raise AssertionError('the worker touched the state')
    monkeypatch.setattr(ha, '_load', no_lock)
    logged = []
    monkeypatch.setattr(ha.logging, 'warning', lambda *a, **k: logged.append(a))
    stuck = []

    snap = ha.build_snapshot(meta, stuck=stuck)
    assert snap['instance_id'] == meta['instance_id'] and snap['role'] == 'active'
    # the etag too: the member list in it comes from meta, not from the state
    assert ha.snapshot_etag(meta) == snap['etag']
    assert [e['instance_id'] for e in snap['members']] == [A, B]
    assert logged == []
