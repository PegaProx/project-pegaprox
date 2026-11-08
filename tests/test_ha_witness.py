"""The witness of an automatic group (#625 stage 2), driven in-process: pegaprox/witness.py
takes each peer call through Witness.handle, as its server does, with a clock the test
turns and a state directory of its own. The rules are ha_vote.Node's; what is checked
here is what the witness adds around them: who may call, what goes to disk and when,
the pairing answer, the state directory and the TLS pair.

tests/test_ha_witness_group.py runs it next to a group of data members.

MK Oct 2026 (#625)
"""
import base64
import errno
import json
import os
import subprocess
import sys
import time

import pytest

from pegaprox import witness as wm
from pegaprox.core import ha_vote as hv
from pegaprox.core import ha_wire

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A, B, C, D, W = 'a' * 32, 'b' * 32, 'c' * 32, 'd' * 32, 'f' * 32
KEYS = {i: ha_wire.new_signing_key() for i in (A, B, C, D, W)}
T = hv.Timings()
PATHS = {'vote': wm.VOTE_PATH, 'renew': wm.RENEW_PATH, 'status': wm.STATUS_PATH,
         'unpaired': wm.UNPAIRED_PATH}


def pub(i):
    return ha_wire.public_of(ha_wire.private_key(KEYS[i]))


def sign_as(i):
    key = ha_wire.private_key(KEYS[i])
    return lambda message: base64.b64encode(key.sign(message)).decode()


def body(data=(A, B), witness=W, mode=hv.MODE_AUTO, lease_s=20):
    voters = [{'id': i, 'public_key': pub(i), 'voter': True, 'may_lead': True, 'site': ''}
              for i in data]
    w = {'id': witness, 'public_key': pub(witness), 'site': 'dc3'} if witness else None
    return {'mode': mode, 'lease_s': lease_s, 'voters': voters, 'witness': w, 'quarantined': []}


def genesis(by=A, epoch=1, **kw):
    return hv.make_cfg(None, epoch, by, body(**kw), sign_as(by))


class Box:
    """A paired witness in a temp directory: a lease clock the test turns, the wall
    clock of the host (signatures are checked against it) with an offset."""

    def __init__(self, path, cfg, chain=(), epoch=1, started=0):
        self.path = wm.check_dir(str(path))
        self.now = 1000.0
        self.wall_off = 0.0
        self.started = started
        self.w = self.make()
        self.w.write({'role': hv.ROLE_WITNESS, 'instance_id': W, 'signing_key': KEYS[W],
                      'own_url': 'https://witness.example:5005',
                      'paired': {'instance_id': A, 'url': 'https://active.example:5000',
                                 'fingerprint': '', 'at': 'x'},
                      'epoch': epoch, 'voted_for': None, 'gen': 0, 'cfg': cfg,
                      'cfg_chain': list(chain), 'floor_cv': [0, 0], 'led': None, 'released': None,
                      'campaign_after': None, 'promised': None})
        self.w.start()

    def make(self):
        return wm.Witness(self.path, clock=lambda: self.now, wall=lambda: time.time() + self.wall_off,
                          started=self.started, boot_id='boot-1')

    def restart(self):
        self.w = self.make()
        self.w.start()

    def settle(self):
        self.now += T.hold_after_start + 1
        return self

    def file(self):
        with open(os.path.join(self.path, wm.STATE_NAME), encoding='utf-8') as fh:
            return json.load(fh)

    def signed(self, sender, kind, payload=None, ts_off=0, key=None, receiver=W):
        method = 'GET' if kind == 'status' else 'POST'
        raw = ha_wire.wire_body(payload) if method == 'POST' else b''
        h = ha_wire.signed_headers(ha_wire.private_key(KEYS[key or sender]), sender, receiver,
                                   method, PATHS[kind], raw, time.time() + ts_off)
        return method, PATHS[kind], h, raw

    def call(self, sender, kind, payload=None, **kw):
        method, path, h, raw = self.signed(sender, kind, payload, **kw)
        return self.w.handle(method, path, h, raw, remote='192.0.2.10')

    def vote(self, cand, epoch, pre=False, cv=(1, 5), cfg_id=None, chain=None, **kw):
        req = {'epoch': epoch, 'candidate': cand, 'pre': pre, 'why': 'timer', 'cv': list(cv),
               'cfg_id': list(cfg_id or self.w.node.view.id), 'lease_s': 20}
        if chain is not None:
            req['chain'] = chain
        return self.call(cand, 'vote', req, **kw)

    def renew(self, leader, epoch, **extra):
        req = {'epoch': epoch, 'leader': leader, 'lease_s': 20, 'cv': [epoch, 9],
               'floor_cv': [1, 0], 'wall': time.time() + self.wall_off}
        req.update(extra)
        return self.call(leader, 'renew', req)


@pytest.fixture
def box(tmp_path):
    return Box(tmp_path / 'w', genesis())


# --- votes, renewals and the disk -------------------------------------------------------

def test_a_vote_is_on_disk_file_and_directory_before_it_is_answered(box, monkeypatch):
    synced = []
    real = wm._fsync_dir
    monkeypatch.setattr(wm, '_fsync_dir', lambda path: synced.append(path) or real(path))
    box.settle()
    status, ans = box.vote(B, 2)
    assert status == 200 and ans['granted'] and ans['epoch'] == 2
    st = box.file()
    assert (st['epoch'], st['voted_for'], st['role']) == (2, B, 'witness') and st['gen'] == 1
    assert synced == [os.path.join(box.path, wm.STATE_NAME)]
    # a pre-vote writes nothing
    status, ans = box.vote(B, 3, pre=True)
    assert ans['granted'] and box.file()['gen'] == 1


def test_a_vote_that_cannot_be_written_is_not_given(box, monkeypatch):
    box.settle()

    def full(path, data):
        raise OSError(28, 'No space left on device')
    monkeypatch.setattr(wm, '_write_json', full)
    status, ans = box.vote(B, 2)
    assert status == 200 and not ans['granted'] and ans['reason'] == 'WRITE_FAILED'
    monkeypatch.undo()
    assert box.file()['epoch'] == 1 and box.file()['voted_for'] is None
    # a directory that cannot be synced is no vote either
    box2 = Box(os.path.join(box.path, '..', 'w2'), genesis()).settle()

    def no_dir(path):
        raise OSError(5, 'Input/output error')
    monkeypatch.setattr(wm, '_fsync_dir', no_dir)
    assert box2.vote(B, 2)[1]['reason'] == 'WRITE_FAILED'


def test_a_directory_that_cannot_be_synced_is_no_vote(box, monkeypatch):
    """The rename is on disk only once the directory is: an I/O error there is no vote. A
    file system that does not sync directories at all is let through, and says so."""
    import errno
    import stat
    real = os.fsync
    failing = {'errno': errno.EIO}

    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(failing['errno'], os.strerror(failing['errno']))
        return real(fd)
    monkeypatch.setattr(os, 'fsync', fsync)
    box.settle()
    assert box.vote(B, 2)[1]['reason'] == 'WRITE_FAILED'
    failing['errno'] = errno.EINVAL
    assert box.vote(B, 2)[1]['granted']
    assert box.call(A, 'status')[1]['dir_sync'] is False


def test_the_rules_are_the_nodes_rules(box):
    """Nothing of the vote rules is the witness's own: a term, a promise, the floor, a
    candidate that is no data voter - each answered by ha_vote.Node."""
    box.settle()
    assert box.vote(B, 2)[1]['granted']
    assert box.vote(A, 2)[1]['reason'] == 'TERM'
    # the floor a renewal carries: a candidate below it is refused by the witness
    assert box.renew(B, 2, floor_cv=[2, 7])[1]['ok']
    box.now += T.P + 1
    assert box.vote(A, 3, cv=(2, 6))[1]['reason'] == 'BELOW_FLOOR'
    assert box.vote(A, 3, cv=(2, 7))[1]['granted']
    # the witness itself is no candidate, and never campaigns
    for _ in range(20):
        box.now += T.L
        box.w.node.tick()
    assert box.w.node.next_wake() is None and box.file()['voted_for'] == A


def test_a_restart_keeps_the_promise(box):
    """The promise to the leader is memory only; what a restart keeps is the vote on disk
    and the hold after the start: nobody but the persisted holder gets a vote for P + D."""
    box.settle()
    assert box.renew(A, 1)[1]['ok']
    assert box.w.node.promise_to == A
    assert box.vote(B, 2)[1]['reason'] == 'PROMISED'
    box.now += 1
    box.restart()
    assert box.w.node.promise_to is None and box.file()['voted_for'] == A
    assert box.vote(B, 2)[1]['reason'] == 'HOLD_AFTER_START'
    box.now += T.hold_after_start - 2
    assert box.vote(B, 2)[1]['reason'] == 'HOLD_AFTER_START'
    box.now += 3
    assert box.vote(B, 2)[1]['granted']
    # and the vote of a term survives a restart as well
    box.restart()
    box.now += T.hold_after_start + 1
    assert box.vote(A, 2)[1]['reason'] == 'TERM'


def test_a_renewal_at_a_higher_epoch_is_on_disk_before_the_answer(box):
    box.settle()
    status, ans = box.renew(B, 5)
    assert ans['ok'] and box.file()['epoch'] == 5 and box.file()['voted_for'] == B
    assert box.renew(A, 4)[1]['reason'] == 'OLD_EPOCH'


@pytest.mark.parametrize('how', ['enospc', 'readonly_dir'])
def test_a_witness_that_cannot_write_says_so_with_every_answer(box, monkeypatch, capsys, how):
    """A renewal at the term held writes nothing, so a witness on a full disk would ack
    them all and look healthy until the vote of the next failover. It writes its state
    again every WRITE_CHECK seconds and says what it finds in every answer and in its
    status; what it acks and refuses stays ha_vote's: a renewal that needs no write is
    acked, one that needs one is not, and no vote is given."""
    box.settle()
    status, ans = box.renew(A, 1)
    assert ans['ok'] and ans['write_failed'] is False
    held = box.file()
    if how == 'enospc':
        def full(path, data, strict=True):
            raise OSError(errno.ENOSPC, 'No space left on device')
        monkeypatch.setattr(wm, '_write_json', full)
    else:
        if os.geteuid() == 0:
            pytest.skip('root writes into a 0500 directory')
        os.chmod(box.path, 0o500)
    try:
        box.now += wm.WRITE_CHECK
        status, ans = box.renew(A, 1)
        assert ans['ok'] is True and ans['write_failed'] is True
        said = box.call(A, 'status')[1]
        assert said['write_failed'] is True
        # what needs a write is refused, as the node's rules say
        assert box.renew(A, 1, floor_cv=[1, 5])[1]['reason'] == 'WRITE_FAILED'
        assert box.renew(A, 2)[1]['reason'] == 'WRITE_FAILED'
        box.now += T.P + 1
        vote = box.vote(B, 2)[1]
        assert vote['reason'] == 'WRITE_FAILED' and vote['write_failed'] is True
        if how == 'enospc':
            # the command says so as well, next to the running witness (it would make a
            # 0500 directory 0700 again, as it does with any state directory)
            assert wm.main(['--dir', box.path, 'status']) == 0
            out = json.loads(capsys.readouterr().out)
            assert out['writable'] is False and 'No space left' in out['write_error']
        assert box.file() == held
    finally:
        os.chmod(box.path, 0o700)
        monkeypatch.undo()
    # the disk is back: the next check clears it
    box.now += wm.WRITE_CHECK
    status, ans = box.renew(A, 1)
    assert ans['ok'] and ans['write_failed'] is False
    assert 'write_failed' not in box.call(A, 'status')[1]
    assert box.renew(A, 1, floor_cv=[1, 5])[1]['ok'] and box.file()['floor_cv'] == [1, 5]


def test_the_state_is_written_again_at_most_every_write_check(box, monkeypatch):
    writes = []
    real = wm._write_json
    monkeypatch.setattr(wm, '_write_json', lambda path, data, strict=True: writes.append(path)
                        or real(path, data, strict))
    box.settle()
    assert box.renew(A, 1)[1]['ok']
    first = len(writes)
    for _ in range(4):
        box.now += 2
        assert box.renew(A, 1)[1]['ok']
    assert len(writes) == first
    box.now += 2
    assert box.renew(A, 1)[1]['ok']
    assert len(writes) == first + 1 and set(writes) == {box.w.path}


def test_a_vote_refused_at_the_directory_sync_is_not_on_disk(box, monkeypatch):
    """The rename was in place when the directory sync failed: the file goes back to what
    the witness holds, so a vote it answered as not given is not there after a restart."""
    box.settle()

    def no_dir(path):
        raise OSError(errno.EIO, 'Input/output error')
    monkeypatch.setattr(wm, '_fsync_dir', no_dir)
    assert box.vote(B, 2)[1]['reason'] == 'WRITE_FAILED'
    monkeypatch.undo()
    st = box.file()
    assert (st['epoch'], st['voted_for'], st['gen']) == (1, None, 0)


def test_a_switch_taken_back_reaches_only_a_witness_that_holds_it_pending(tmp_path):
    """The manual config that took a pending switch back is handed out by whoever took it
    back, a leader or not: the witness takes it only while it holds a pending config, by
    the rule a data member goes by (ha_vote.takes_switch_back)."""
    pending = genesis(mode=hv.MODE_PENDING)
    back = hv.make_cfg(pending, 1, A, body(mode=hv.MODE_MANUAL), sign_as(A))
    box = Box(tmp_path / 'p', pending).settle()
    call = {'epoch': 1, 'leader': A, 'switch': True, 'taken_back': True, 'lease_s': 20,
            'chain': [pending, back]}
    status, ans = box.call(A, 'renew', call)
    assert status == 200 and ans['cfg_digest'] == hv.cfg_digest(back) and box.file()['cfg'] == back
    # a witness in automatic mode takes nothing from such a round
    auto_cfg = genesis()
    stray = hv.make_cfg(auto_cfg, 1, A, body(mode=hv.MODE_MANUAL), sign_as(A))
    box = Box(tmp_path / 'a', auto_cfg).settle()
    status, ans = box.call(A, 'renew', dict(call, chain=[auto_cfg, stray]))
    assert status == 200 and ans['reason'] == 'NOT_PENDING' and box.file()['cfg'] == auto_cfg
    assert box.w.node.view.mode == hv.MODE_AUTO


# --- who may call ------------------------------------------------------------------------

def test_forged_replayed_skewed_and_unsigned_calls_are_refused(box):
    box.settle()
    good = box.vote(B, 2, pre=True)
    assert good[0] == 200 and good[1]['granted']
    # signed with another key
    assert box.vote(B, 2, key=C)[0] == 401
    # a member the voter config does not name
    assert box.vote(C, 2)[0] == 401
    # the same call twice
    method, path, h, raw = box.signed(B, 'vote', {'epoch': 2, 'candidate': B, 'pre': True,
                                                  'cv': [1, 5], 'cfg_id': [1, 1]})
    assert box.w.handle(method, path, h, raw)[0] == 200
    assert box.w.handle(method, path, h, raw)[0] == 401
    # a body other than the one signed
    method, path, h, raw = box.signed(B, 'vote', {'epoch': 2, 'candidate': B, 'pre': True})
    assert box.w.handle(method, path, h, raw.replace(b'true', b'false'))[0] == 401
    # signed for another receiver
    assert box.call(B, 'status', receiver=A)[0] == 401
    # outside the window: the member is told it is its clock
    status, ans = box.vote(B, 2, ts_off=ha_wire.SIGNATURE_WINDOW + 30)
    assert status == 401 and ans['code'] == 'HA_CLOCK'
    # no signature at all, and the secret of a member paired before the keys
    assert box.w.handle('GET', wm.STATUS_PATH, {}, b'')[0] == 401
    legacy = {ha_wire.PEER_HEADER: f'{B}:a-secret-from-before-the-keys'}
    assert box.w.handle('GET', wm.STATUS_PATH, legacy, b'')[0] == 401
    # nothing of it reached the disk
    assert box.file()['epoch'] == 1 and box.file()['gen'] == 0


def test_a_call_signed_before_the_process_started_is_refused(tmp_path):
    box = Box(tmp_path / 'w', genesis(), started=int(time.time()) + 60)
    status, ans = box.call(B, 'status')
    assert status == 401 and ans['code'] == 'HA_CLOCK'


def test_a_witness_started_with_its_clock_ahead_answers_once_ntp_sets_it_back(tmp_path):
    """Its wall clock was an hour ahead when the process started (a stale RTC, a restored
    VM), and NTP stepped it back since: the start follows the clock, so the members are
    answered again, and a call signed before the start is still refused."""
    box = Box(tmp_path / 'w', genesis(), started=None)
    box.wall_off = 3600.0
    box.restart()
    box.wall_off = 0.0
    box.now += 30
    status, ans = box.call(B, 'status')
    assert status == 200 and ans['instance_id'] == W, ans
    assert abs(box.w.skews[B][0]) < 5
    assert box.call(B, 'status', ts_off=-10)[0] == 200
    status, ans = box.call(B, 'status', ts_off=-60)
    assert status == 401 and ans['code'] == 'HA_CLOCK'


def test_failed_calls_run_into_a_budget(box):
    for _ in range(10):
        assert box.vote(C, 2)[0] == 401
    assert box.vote(C, 2)[0] == 429


def test_the_witness_answers_four_routes_and_nothing_else(box):
    for method, path in (('GET', '/api/ha/peer/snapshot'), ('POST', '/api/ha/peer/forward'),
                         ('POST', '/api/ha/peer/pair'), ('POST', '/api/ha/peer/changed'),
                         ('GET', '/api/ha/status'), ('GET', '/'), ('POST', '/api/auth/login')):
        assert box.w.handle(method, path, {}, b'')[0] == 404, path
    assert box.w.handle('POST', wm.STATUS_PATH, {}, b'')[0] == 405
    assert box.w.handle('GET', wm.VOTE_PATH, {}, b'')[0] == 405
    assert box.w.handle('POST', wm.VOTE_PATH, {}, b'x' * (wm.MAX_BODY + 1))[0] == 413


def test_the_status_is_its_own_and_small(box):
    box.wall_off = 0
    status, ans = box.call(A, 'status')
    assert status == 200
    assert set(ans) == {'instance_id', 'role', 'kind', 'epoch', 'group', 'lease_mark', 'wall',
                        'release', 'zone', 'mode', 'cfg_id', 'gen', 'voted_for', 'reach', 'lease',
                        'floor_cv', 'skew', 'cfg_digest', 'wire', 'auto_update', 'install', 'code'}
    # what the leader keeps it up to date by (tests/test_ha_witness_delivery.py)
    assert ans['wire'] == ha_wire.WITNESS_WIRE and ans['auto_update'] is False and ans['code'] == ''
    assert (ans['instance_id'], ans['role'], ans['kind'], ans['mode']) == (W, 'witness', 'witness', 'auto')
    # the config it holds by digest, as a data member names it
    assert ans['cfg_digest'] == hv.cfg_digest(box.file()['cfg'])
    assert ans['lease']['holds'] is False and ans['lease_mark'] == ha_wire.LEASE_MARK
    from pegaprox.constants import PEGAPROX_VERSION
    assert ans['release'] == PEGAPROX_VERSION
    assert KEYS[W] not in json.dumps(ans)


def test_the_witness_counts_its_skew_against_the_caller(box, caplog):
    box.settle()
    box.wall_off = -7.0           # this host is 7 s behind the leader
    assert box.renew(A, 1, wall=time.time())[1]['ok']
    status, ans = box.call(A, 'status')
    assert status == 200 and 6 <= ans['skew'] <= 8
    assert sum('is 7.0 s off' in r.getMessage() for r in caplog.records) == 1
    box.renew(A, 1, wall=time.time())
    assert sum('s off this one' in r.getMessage() for r in caplog.records) == 1


def test_the_head_of_a_call(box):
    """The server reads a head strictly: one request line, no folded lines, no header
    twice. tests/test_ha_witness_server.py runs it over TLS."""
    head = b'POST /api/ha/peer/vote HTTP/1.1\r\nHost: w\r\nContent-Length: 12\r\nX-PegaProx-Peer: ' + A.encode()
    assert wm._parse_head(head) == ('POST', '/api/ha/peer/vote', 'HTTP/1.1',
                                    {'host': 'w', 'content-length': '12', 'x-pegaprox-peer': A})
    for bad in (b'GET /api/ha/peer/status', b'GET api HTTP/1.1', b'GET / HTTP/2.0', b'get / HTTP/1.1',
                b'GET / HTTP/1.1\r\n folded: x', b'GET / HTTP/1.1\r\nA: 1\r\na: 2',
                b'GET / HTTP/1.1\r\nno colon', b'GET / HTTP/1.1\r\nA: 1\nB: 2'):
        assert wm._parse_head(bad) is None, bad


def test_a_signed_call_is_told_before_its_body(box):
    """precheck: who sent a call, from its headers and the body digest they name, before
    the body is read. Nothing is spent: the call itself still runs through handle()."""
    box.settle()
    for kind, payload in (('status', None), ('vote', {'epoch': 2, 'candidate': B, 'pre': True})):
        method, path, h, raw = box.signed(B, kind, payload)
        assert box.w.precheck(method, path, h) == 'member'
        # the nonce is not spent by it, and a call seen before is no member's
        assert box.w.handle(method, path, h, raw)[0] == 200
        assert box.w.precheck(method, path, h) == ''
    method, path, h, raw = box.signed(B, 'vote', {'epoch': 2, 'candidate': B, 'pre': True})
    # a body other than the one named: the headers are a member's, handle() refuses the call
    assert box.w.precheck(method, path, h) == 'member'
    assert box.w.handle(method, path, h, raw.replace(b'true', b'false'))[0] == 401
    # signed with another key, without a signature, for an unknown route
    assert box.w.precheck(*box.signed(B, 'status', key=C)[:3]) == ''
    assert box.w.precheck('GET', wm.STATUS_PATH, {}) == ''
    assert box.w.precheck('GET', '/api/ha/peer/snapshot', box.signed(B, 'status')[2]) == ''
    # a voter only the chain in its body names, and a clock that is off: the body tells
    assert box.w.precheck(*box.signed(C, 'vote', {'epoch': 2})[:3]) == 'open'
    assert box.w.precheck(*box.signed(C, 'status')[:3]) == ''
    skewed = box.signed(B, 'vote', {'epoch': 2}, ts_off=ha_wire.SIGNATURE_WINDOW + 30)
    assert box.w.precheck(*skewed[:3]) == 'open'
    assert box.w.handle(*skewed)[1]['code'] == 'HA_CLOCK'


class _Greenlet:
    def __init__(self):
        self.killed = False

    def kill(self, block=True):
        self.killed = True


def test_the_gate_drops_the_oldest_unsigned_connection_of_a_source():
    gate = wm._Gate(per_source=3, anon_max=5, member_max=2)

    def conn(src):
        c = wm._Conn(src, _Greenlet())
        gate.admit(c)
        return c
    first = [conn('192.0.2.1') for _ in range(3)]
    other = conn('198.51.100.7')
    # the fourth from one source pushes out the oldest of that source, never another's
    fourth = conn('192.0.2.1')
    assert first[0].greenlet.killed and not other.greenlet.killed
    assert list(gate.anon) == first[1:] + [other, fourth]
    # past anon_max the oldest of all goes; one inside a call never does
    first[1].busy = True
    conn('203.0.113.9')
    assert not first[1].greenlet.killed and first[2].greenlet.killed is False
    conn('203.0.113.10')
    assert first[2].greenlet.killed and len(gate.anon) == 5
    # a connection whose call carried a good signature leaves the count of its source
    gate.promote(fourth)
    assert fourth not in gate.anon and list(gate.members) == [fourth]
    # the reserve of signed connections gives up the one idle the longest
    m2, m3 = conn('192.0.2.1'), conn('192.0.2.1')
    gate.promote(m2)
    gate.promote(fourth)                  # active again: the newest now
    gate.promote(m3)
    assert m2.greenlet.killed and not fourth.greenlet.killed and list(gate.members) == [fourth, m3]
    gate.release(fourth)
    assert list(gate.members) == [m3]


def test_the_source_of_a_connection():
    assert wm._source(('192.0.2.1', 4000)) == '192.0.2.1'
    assert wm._source(('::ffff:192.0.2.1', 4000, 0, 0)) == '192.0.2.1'
    # a whole /64 is one source
    assert wm._source(('2001:db8::1', 4000, 0, 0)) == wm._source(('2001:db8::ffff:2', 1, 0, 0)) == '2001:db8::/64'
    assert wm._source(('2001:db8:0:1::1', 4000, 0, 0)) != wm._source(('2001:db8::1', 4000, 0, 0))


# --- the voter config chain ---------------------------------------------------------------

def test_a_config_that_does_not_chain_is_refused(box):
    box.settle()
    held = box.file()['cfg']
    # a chain of its own, founded elsewhere
    other = genesis(by=B, epoch=3)
    nxt = hv.make_cfg(other, 3, B, body(data=(A, B, C)), sign_as(B))
    assert box.renew(B, 3, chain=[other, nxt])[1]['reason'] == 'CFG_GAP'
    # the next config, signed by an instance that is no data voter of the one before
    forged = hv.make_cfg(held, 1, C, body(data=(A, B, C)), sign_as(C))
    assert box.renew(A, 1, chain=[forged])[1]['reason'] == 'BAD_CFG'
    # signed by a voter, but with the witness's own key in the place of the signer
    forged = hv.make_cfg(held, 1, A, body(data=(A, B, C)), sign_as(W))
    assert box.renew(A, 1, chain=[forged])[1]['reason'] == 'BAD_CFG'
    assert box.file()['cfg'] == held
    # the real next one is taken, on disk before the answer
    good = hv.make_cfg(held, 1, A, body(data=(A, B, C)), sign_as(A))
    assert box.renew(A, 1, chain=[good])[1]['ok']
    assert box.file()['cfg'] == good and box.file()['cfg_chain'] == [held]


def test_a_new_data_voter_is_known_by_the_chain_it_carries(box):
    """D2: the witness missed the change that made C a voter. C's vote request carries
    the chain, signed by the leader before, and C's key comes from there."""
    held = box.file()['cfg']
    c2 = hv.make_cfg(held, 1, A, body(data=(A, B, C)), sign_as(A))
    box.settle()
    assert box.vote(C, 2, cfg_id=(1, 2))[0] == 401
    status, ans = box.vote(C, 2, cfg_id=(1, 2), chain=[c2])
    assert status == 200 and ans['granted'] and box.file()['cfg'] == c2
    # a chain that does not hang off what is held names nobody
    stray = hv.make_cfg(genesis(by=D), 1, D, body(data=(A, D)), sign_as(D))
    assert box.vote(D, 3, cfg_id=(1, 2), chain=[stray])[0] == 401


# --- leaving ----------------------------------------------------------------------------------

def test_the_leader_takes_the_witness_out(tmp_path):
    b = body(data=(A, B, C))
    b['voters'][2]['voter'] = False
    box = Box(tmp_path / 'w', hv.make_cfg(None, 1, A, b, sign_as(A)))
    # from a member that holds no vote, or without removed, nothing happens
    assert box.call(C, 'unpaired', {'removed': True})[1]['left_group'] is False
    assert box.call(B, 'unpaired', {})[1]['left_group'] is False
    assert box.w.paired()
    assert box.call(A, 'unpaired', {'removed': True})[1]['left_group'] is True
    st = box.file()
    assert not box.w.paired() and st['instance_id'] == W
    assert 'cfg' not in st and 'signing_key' not in st and st['left']['by'] == A
    assert box.call(A, 'status')[0] == 401


def test_leave_asks_the_leader_and_follows_a_hint(box):
    calls = []
    answers = [(409, {'error': 'not the leader',
                      'follow': {'instance_id': B, 'url': 'https://standby.example:5000',
                                 'fingerprint': '', 'public_key': pub(B), 'epoch': 1}}),
               (200, {'success': True})]

    def call(method, url, fp, path, raw, headers, timeout=15):
        calls.append((url, path, headers[ha_wire.PEER_HEADER]))
        # signed with the witness's key, for the member it goes to
        verdict = ha_wire.signature_verdict(headers, method, path, raw, W, pub(W),
                                            A if 'active' in url else B, time.time(), 0)
        assert verdict == 'ok'
        return answers.pop(0)
    box.w.call = call
    assert box.w.leave() is True
    assert [c[0] for c in calls] == ['https://active.example:5000', 'https://standby.example:5000']
    assert not box.w.paired()


def test_leave_without_the_leader_needs_force(box):
    def refuse(*a, **kw):
        return 409, {'code': 'HA_AUTO_MODE', 'error': 'too few votes without the witness'}
    box.w.call = refuse
    with pytest.raises(wm.WitnessError, match='too few votes'):
        box.w.leave()
    assert box.w.paired()
    # a hint to a member the config does not name as a voter is not followed
    box.w.call = lambda *a, **kw: (409, {'follow': {'instance_id': C, 'url': 'https://c.example',
                                                    'public_key': pub(C)}})
    with pytest.raises(wm.WitnessError):
        box.w.leave()
    assert box.w.leave(force=True) is False and not box.w.paired()


# --- pairing, the witness's half -----------------------------------------------------------

class Leader:
    """What the leader's pair route answers, made by hand."""

    def __init__(self, chain, epoch=1, me=A):
        self.chain, self.epoch, self.me = chain, epoch, me
        self.secret = 's' * 43
        self.sent = []
        self.public = pub(me)

    def code(self, prefix=ha_wire.WITNESS_CODE_PREFIX):
        return ha_wire.encode_code(prefix, 'https://active.example:5000', '', self.secret, self.me)

    def __call__(self, method, url, fp, path, raw, headers, timeout=15):
        req = json.loads(raw)
        self.sent.append((path, req, headers))
        payload = {'public_key': self.public, 'chain': self.chain, 'epoch': self.epoch,
                   'mode': 'manual', 'floor_cv': [1, 3]}
        return 200, {'instance_id': self.me, 'epoch': self.epoch,
                     'sealed': ha_wire.seal(self.secret, payload, aad=req['instance_id'])}


def _fresh(tmp_path, leader):
    return wm.Witness(str(tmp_path / 'fresh'), started=0, boot_id='boot-1', call=leader)


def test_join_takes_the_chain_and_holds_no_field_key(tmp_path):
    g = genesis(mode=hv.MODE_MANUAL)
    leader = Leader([g], epoch=4)
    w = _fresh(tmp_path, leader)
    wm.check_dir(w.dir)
    assert w.join(leader.code(), 'https://witness.example:5005') == A
    path, req, headers = leader.sent[0]
    assert path == wm.PAIR_PATH and headers == {}
    assert set(req) == {'code', 'instance_id', 'url', 'fingerprint', 'public_key'}
    assert req['fingerprint'] == wm.tls_pair(w.dir)[2] and req['url'] == 'https://witness.example:5005'
    st = w.read()
    assert st['cfg'] == g and st['epoch'] == 4 and st['floor_cv'] == [1, 3]
    assert st['paired']['instance_id'] == A and st['instance_id'] == req['instance_id']
    assert ha_wire.public_of(ha_wire.private_key(st['signing_key'])) == req['public_key']
    assert set(st) == {'role', 'instance_id', 'signing_key', 'own_url', 'paired', 'epoch', 'voted_for',
                       'gen', 'cfg', 'cfg_chain', 'floor_cv', 'led', 'released', 'campaign_after',
                       'promised'}
    assert oct(os.stat(w.path).st_mode & 0o777) == '0o600'
    assert oct(os.stat(w.dir).st_mode & 0o777) == '0o700'
    with pytest.raises(wm.WitnessError, match='paired already'):
        w.join(leader.code(), 'https://witness.example:5005')


@pytest.mark.parametrize('case', ['member_code', 'no_url', 'own_code', 'not_opened', 'not_signed',
                                  'leader_no_voter', 'broken_link', 'other_answer', 'refused'])
def test_join_refusals(tmp_path, case):
    g = genesis(mode=hv.MODE_MANUAL)
    leader = Leader([g])
    w = _fresh(tmp_path, leader)
    os.makedirs(w.dir)
    code, url = leader.code(), 'https://witness.example:5005'
    if case == 'member_code':
        code = leader.code(prefix=ha_wire.CODE_PREFIX)
    elif case == 'no_url':
        url = 'http://witness.example:5005'
    elif case == 'own_code':
        w.write({'role': 'witness', 'instance_id': A})
    elif case == 'not_opened':
        leader.secret = 't' * 43
        code = ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, 'https://active.example:5000', '',
                                   's' * 43, A)
    elif case == 'not_signed':
        leader.chain = [dict(g, sig=sign_as(C)(b'x'))]
    elif case == 'leader_no_voter':
        leader.chain = [genesis(by=B, data=(B, C), mode=hv.MODE_MANUAL)]
    elif case == 'broken_link':
        g2 = hv.make_cfg(g, 1, C, body(data=(A, B, C), mode=hv.MODE_MANUAL), sign_as(C))
        leader.chain = [g, g2]
    elif case == 'other_answer':
        leader.me = B
        leader.public = pub(B)
        code = ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, 'https://active.example:5000', '',
                                   leader.secret, A)
    elif case == 'refused':
        w.call = lambda *a, **kw: (403, {'error': 'The pairing code is wrong or has expired'})
    with pytest.raises(wm.WitnessError) as e:
        w.join(code, url)
    assert not w.paired() and not w.read().get('cfg')
    if case == 'member_code':
        assert 'not a PegaProx witness code' in str(e.value)
    if case == 'refused':
        assert 'wrong or has expired' in str(e.value)


# --- the state directory and TLS ----------------------------------------------------------

@pytest.mark.parametrize('name', ['pegaprox.db', '.ha-member', 'ha_state.json', '.pegaprox_aes256.key'])
def test_the_witness_refuses_a_pegaprox_data_directory(tmp_path, name):
    (tmp_path / name).write_text('x')
    with pytest.raises(wm.WitnessError, match='data of a PegaProx instance'):
        wm.check_dir(str(tmp_path))
    assert wm.main(['--dir', str(tmp_path), 'run']) == wm.EXIT_CONFIG
    assert not (tmp_path / wm.STATE_NAME).exists() and not (tmp_path / 'ssl').exists()


def test_pegaprox_refuses_a_witness_directory(tmp_path):
    from pegaprox.core import ha
    ha.check_not_a_witness_dir(str(tmp_path))
    (tmp_path / wm.STATE_NAME).write_text('{}')
    with pytest.raises(ha.HaError, match='state directory of a PegaProx witness'):
        ha.check_not_a_witness_dir(str(tmp_path))
    # main() asks before it takes the lock of the config directory, before anything is written
    import inspect
    from pegaprox import app
    src = inspect.getsource(app.main)
    assert 0 < src.index('ha.check_not_a_witness_dir()') < src.index('ha.lock_config_dir()')


def test_one_process_per_state_directory(tmp_path):
    fd = wm.lock_dir(str(tmp_path))
    try:
        with pytest.raises(wm.WitnessError, match='Another witness process'):
            wm.lock_dir(str(tmp_path))
    finally:
        wm.unlock_dir(fd)
    wm.unlock_dir(wm.lock_dir(str(tmp_path)))


def test_the_certificate_is_made_once_and_pinned(tmp_path):
    cert, key, pin = wm.tls_pair(str(tmp_path))
    assert ha_wire.FP_RE.fullmatch(pin)
    assert oct(os.stat(key).st_mode & 0o777) == '0o600'
    assert wm.tls_pair(str(tmp_path))[2] == pin
    with open(cert, 'rb') as fh:
        assert ha_wire.cert_fingerprint(fh.read()) == pin
    os.unlink(key)
    with pytest.raises(wm.WitnessError, match='missing next to its counterpart'):
        wm.tls_pair(str(tmp_path))
    with open(key, 'w') as fh:
        fh.write('not a key')
    with pytest.raises(wm.WitnessError, match='do not load as a pair'):
        wm.tls_pair(str(tmp_path))


def test_the_commands(tmp_path, capsys):
    d = str(tmp_path / 'w')
    assert wm.main(['--dir', d, 'fingerprint']) == 0
    pin = capsys.readouterr().out.strip()
    assert ha_wire.FP_RE.fullmatch(pin)
    assert wm.main(['--dir', d, 'status']) == 0
    assert json.loads(capsys.readouterr().out)['paired'] is False
    # unpaired, nothing answers on the port: not healthy
    assert wm.main(['--dir', d, 'health']) == 1
    assert wm.main(['--dir', d, 'join', 'pgxha1_abc', '--url', 'https://w.example:5005']) == wm.EXIT_CONFIG
    assert 'not a PegaProx witness code' in capsys.readouterr().err
    assert wm.main(['--dir', d, 'leave']) == wm.EXIT_CONFIG


def test_the_launcher_runs_the_witness_and_never_the_app(tmp_path):
    """pegaprox_multi_cluster.py witness ... is the witness and nothing of the app: it
    makes none of the directories pegaprox.constants makes when it is imported."""
    cwd = tmp_path / 'cwd'
    cwd.mkdir()
    env = dict(os.environ, PYTHONPATH=ROOT, PEGAPROX_WITNESS_DIR=str(tmp_path / 'state'))
    out = subprocess.run([sys.executable, os.path.join(ROOT, 'pegaprox_multi_cluster.py'), 'witness',
                          'fingerprint'], cwd=str(cwd), env=env, capture_output=True, text=True,
                         timeout=60)
    assert out.returncode == 0, out.stderr
    assert ha_wire.FP_RE.fullmatch(out.stdout.strip().splitlines()[-1])
    assert sorted(os.listdir(cwd)) == []
    assert sorted(os.listdir(tmp_path / 'state')) == ['ssl']
    out = subprocess.run([sys.executable, '-m', 'pegaprox.witness', '--help'], cwd=str(cwd), env=env,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and 'pegaprox-witness' in out.stdout
    # what the witness loads: the protocol, the wire and a rate limiter, and nothing of the
    # app, its database or its constants
    probe = ('import sys, pegaprox.witness as w; w.Witness(sys.argv[1]); '
             'print(sorted(m for m in sys.modules if m.split(".")[0] in ("pegaprox", "flask")))')
    out = subprocess.run([sys.executable, '-c', probe, str(tmp_path / 'probe')], cwd=str(cwd), env=env,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert eval(out.stdout) == ['pegaprox', 'pegaprox.core', 'pegaprox.core.ha_vote',
                                'pegaprox.core.ha_wire', 'pegaprox.utils', 'pegaprox.utils.ratelimit',
                                'pegaprox.witness', 'pegaprox.witness_boot']


def test_the_unit_and_the_image(tmp_path, monkeypatch):
    with open(os.path.join(ROOT, 'systemd', 'pegaprox-witness.service'), encoding='utf-8') as fh:
        unit = fh.read()
    # the command and the user are the ones packaging/witness/install.sh makes
    for line in ('User=pegaprox-witness', 'NoNewPrivileges=true', 'StateDirectory=pegaprox-witness',
                 'ExecStart=/usr/local/bin/pegaprox-witness run', 'Restart=on-failure',
                 'ProtectSystem=strict', 'RestartForceExitStatus=75'):
        assert line in unit.splitlines(), line
    with open(os.path.join(ROOT, 'Dockerfile'), encoding='utf-8') as fh:
        docker = fh.read()
    assert '/app/witness' in docker and 'EXPOSE 5005' in docker
    # the image's working directory is /app: the witness keeps its state next to config/
    assert os.environ.get('PEGAPROX_WITNESS_DIR') is None
    monkeypatch.delenv('STATE_DIRECTORY', raising=False)
    monkeypatch.chdir(tmp_path)
    assert wm.default_dir() == os.path.join(str(tmp_path), 'witness') or \
        wm.default_dir() == '/var/lib/pegaprox-witness'


def test_one_implementation_of_the_wire():
    """ha.py signs, checks and seals with ha_wire, the witness too."""
    from pegaprox.core import ha
    assert ha.PEER_HEADER == ha_wire.PEER_HEADER and ha.SIGNATURE_WINDOW == ha_wire.SIGNATURE_WINDOW
    assert ha.LEASE_MARK == ha_wire.LEASE_MARK and ha.GROUP_MARK == ha_wire.GROUP_MARK
    key = ha_wire.private_key(KEYS[A])
    h = ha._signed_headers(key, A, W, 'GET', wm.STATUS_PATH, b'')
    assert ha_wire.signature_verdict(h, 'GET', wm.STATUS_PATH, b'', A, pub(A), W, time.time(), 0) == 'ok'
    assert ha._unseal('s' * 43, ha_wire.seal('s' * 43, {'x': 1}, 'aad'), 'aad') == {'x': 1}
    assert ha.decode_code(ha.encode_code('https://a.example', '', 's' * 43, A))['instance_id'] == A
    with pytest.raises(ha.HaError, match='not a PegaProx pairing code'):
        ha.decode_code(ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, 'https://a.example', '',
                                           's' * 43, A))
