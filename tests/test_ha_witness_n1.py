"""A witness one wire version behind its members (#625 stage 2).

The witness as it first shipped (commit S5 below: wire 1, random nonces only, no
updates) next to members of this release, which number their votes and renewals
(stream nonces) and keep their witness up to date. The members talk to it as it is:
random nonces to a witness that does not say it takes stream nonces, no update it
could not take, and WITNESS_OUTDATED for the admin. The group keeps its third vote:
the leader renews with it while the other member is gone, and it votes the other
member in when the leader is gone.

Its three modules are read from git and run in this process next to the current ones,
under names of their own. Without the history (a shallow clone, a release tarball) the
test is skipped.

MK Oct 2026 (#625)
"""
import os
import subprocess
import time
import types

import pytest

from pegaprox.core import ha_vote as hv
from pegaprox.core import ha_wire
from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_members import IDS, _sync, group  # noqa: F401  (the fixture)
from test_ha_witness_group import WURL, Host, _code

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# the witness as S5 shipped it, before the stream nonces and the updates
S5 = '827fff7'


def _show(path):
    try:
        out = subprocess.run(['git', 'show', f'{S5}:{path}'], cwd=ROOT, capture_output=True, text=True,
                             timeout=30)
    except (OSError, subprocess.SubprocessError):
        out = None
    if out is None or out.returncode != 0:
        pytest.skip(f'the witness of {S5} is not in this checkout ({path})')
    return out.stdout


def _module(name, source, filename, **ns):
    mod = types.ModuleType(name)
    mod.__file__ = filename
    mod.__dict__.update(ns)
    exec(compile(source, filename, 'exec'), mod.__dict__)
    return mod


@pytest.fixture(scope='module')
def s5(tmp_path_factory):
    folder = tmp_path_factory.mktemp('s5')
    from pegaprox.constants import PEGAPROX_VERSION
    # its release as it reads it, next to its file: this one, on the older wire
    (folder / 'constants.py').write_text(f'PEGAPROX_VERSION = "{PEGAPROX_VERSION}"\n')
    vote = _module('s5_ha_vote', _show('pegaprox/core/ha_vote.py'), str(folder / 'ha_vote.py'))
    wire = _module('s5_ha_wire', _show('pegaprox/core/ha_wire.py'), str(folder / 'ha_wire.py'))
    assert not hasattr(wire, 'WITNESS_WIRE') and not hasattr(wire, 'take_stream'), 'not the first wire'
    source = _show('pegaprox/witness.py')
    line = 'from pegaprox.core import ha_vote, ha_wire'
    assert source.count(line) == 1
    source = source.replace(line, 'ha_vote, ha_wire = _S5_VOTE, _S5_WIRE')
    return _module('s5_witness', source, str(folder / 'witness.py'), _S5_VOTE=vote, _S5_WIRE=wire)


class S5Host(Host):
    """The witness next to the group, as S5 shipped it."""

    module = None

    def make(self):
        return self.module.Witness(self.dir, clock=lambda: self.auto.clock['e'], wall=time.time, started=0,
                                   boot_id='boot-w', call=self._to_member)


@pytest.fixture
def host(auto, tmp_path, monkeypatch, s5):
    S5Host.module = s5
    return S5Host(auto, tmp_path, monkeypatch)


def _lease_nonces(calls, paths=('/api/ha/peer/renew', '/api/ha/peer/vote')):
    return [h[ha_wire.PEER_NONCE_HEADER] for h in calls if h.get('_path') in paths]


def _form_with_s5(auto, host, seed):
    auto.pair(seed, 'b')
    r = _code(auto)
    assert r.status_code == 200, r.data
    assert host.w.join(r.get_json()['code'], WURL) == IDS['a']
    host.w.start()
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    wid = host.w.instance_id()
    with auto.at('a') as ha:
        ha._ask_witness()
        seen = ha._rt().seen[wid]
        # it says nothing of a wire: the first one
        assert seen['mark'] == ha_wire.LEASE_MARK and seen['wire'] is None and seen['auto_update'] is False
        findings = {f['code']: f for f in ha.auto_findings()}
    f = findings['WITNESS_OUTDATED']
    assert f['level'] == 'warn' and 'wire 1' in f['text'] and 'cannot update itself' in f['text']
    assert not [x for x in findings.values() if x['level'] == 'block']
    r = auto.switch_on(accept=['WITNESS_OUTDATED'])
    assert r.status_code == 200, r.data
    assert all(auto.mode(n) == 'auto' for n in auto.members) and auto.leader() == 'a'
    assert host.node.view.mode == hv.MODE_AUTO
    return wid


def test_a_witness_of_the_first_wire_keeps_the_third_vote_of_a_group_on_this_release(auto, host, seed):
    wid = _form_with_s5(auto, host, seed)
    for _ in range(10):
        auto.run(1.0)
        if host.node.view.witness == wid:
            break
    assert host.node.view.witness == wid
    auto.run(20)
    assert host.node.promise_to == IDS['a']
    # the members number their lease calls to each other, and send the old witness the
    # random nonces it always took
    to_w = [dict(h, _path=p) for me, _m, p, h, _r in host.calls if me == 'a']
    to_b = [dict(h, _path=p) for me, to, _m, p, _b, h in auto.g.sent if me == 'a' and to == 'b']
    assert _lease_nonces(to_w) and not any(ha_wire.is_stream_nonce(n) for n in _lease_nonces(to_w))
    assert _lease_nonces(to_b) and all(ha_wire.is_stream_nonce(n) for n in _lease_nonces(to_b))
    # and its other calls (the status, the word about updates) random too: the stream of
    # the other calls is no more its wire than the lease stream
    others = [h[ha_wire.PEER_NONCE_HEADER] for h in to_w
              if h.get('_path') not in ('/api/ha/peer/renew', '/api/ha/peer/vote') and ha_wire.PEER_NONCE_HEADER in h]
    assert others and not any(ha_wire.is_stream_nonce(n) for n in others)
    # the other member gone: the leader goes on with the witness's renewals
    auto.crash('b')
    with auto.at('a') as ha:
        before = ha._rts[IDS['a']].node.lease_until
    auto.run(90, members='a')
    assert auto.leader() == 'a'
    with auto.at('a') as ha:
        rt = ha._rts[IDS['a']]
        assert rt.node.lease_until > before + 60 and ha.ha_clock() - rt.acked[wid] < 5
    # and with the leader gone, its vote makes the other member the leader
    auto.back('b')
    auto.run(30)
    assert auto.leader() == 'a'
    auto.crash('a')
    auto.run(150, members='b', until=lambda: auto.leader() == 'b')
    assert auto.leader() == 'b'
    assert host.file()['voted_for'] == IDS['b'] and host.node.promise_to == IDS['b']


def test_the_leader_asks_the_old_witness_for_no_update_it_cannot_take(auto, host, seed):
    """It has no update route: the word goes out and comes back 404, nothing breaks, and
    the admin is told to put it in anew."""
    wid = _form_with_s5(auto, host, seed)
    auto.run(10)
    with auto.at('a') as ha:
        said = ha._witness_update_check()
        assert said is not None and said['status'] == 404 and said['answer'] == {}
        view = ha.witness_view()
    assert view['outdated'] is True and view['wire'] == 1 and view['update_command'] is None
    paths = [p for _me, _m, p, _h, _r in host.calls]
    assert '/api/ha/peer/witness-update' in paths
    auto.run(10)
    assert auto.leader() == 'a' and host.node.promise_to == IDS['a']
    with auto.at('a') as ha:
        assert ha.ha_clock() - ha._rts[IDS['a']].acked[wid] < 5
