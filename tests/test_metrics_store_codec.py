"""The parts a metrics snapshot is stored in have to read back as the JSON blob did.

pegaprox/background/metrics_store.py keeps a snapshot per cluster: a head, the nodes, the
storage and the guests (columnar, on a roster shared between snapshots). Whatever goes in,
what comes out is json.loads(json.dumps(snapshot)): the same keys in the same order, the same
types, the same float bits. Guest entries the columns cannot hold that exactly stay JSON;
these tests go through both, and through the bytes on disk, which are little-endian on any host.
MK Oct 2026
"""
import json
import random
import struct
import zlib
from array import array

import pytest

from pegaprox.background import metrics_store as ms

GIB = 1024 ** 3


def _json(x):
    return json.loads(json.dumps(x))


def _guest(t='qemu', r=True, cpu=12.3, mem=45.6, maxmem=4 * GIB, maxcpu=4, n='pve1'):
    g = {'t': t, 'r': r, 'cpu': cpu, 'mem': mem, 'maxmem': maxmem, 'maxcpu': maxcpu}
    if n is not None:
        g['n'] = n
    return g


def _roundtrip(vms, nodes=None):
    enc = ms.encode_guests(vms, nodes if nodes is not None else {'pve1': {}})
    assert enc is not None, 'should have fitted the columns'
    roster, dyn = enc
    back = ms.guest_map(ms.decode_roster(roster), dyn)
    want = _json(vms)
    assert ms._same(back, want), (back, want)
    assert list(back) == list(want)
    return roster, dyn


def _random_guests(rng, count):
    names = ['pve1', 'pve2', 'Rechenzentrum-Süd', 'n\ud800ode', '', 'edge']
    vms = {}
    for vid in rng.sample(range(0, 1 << 32), count):
        run = rng.random() > 0.2
        g = _guest(t=rng.choice(('qemu', 'lxc')), r=run,
                   cpu=rng.choice((round(rng.random() * 120, 1), 0.0, 100.0, 105.3, 0)) if run else None,
                   mem=round(rng.random() * 99, 1) if run and rng.random() > 0.1 else None,
                   maxmem=rng.choice((0, GIB, 3 * GIB, 1 << 62)), maxcpu=rng.choice((0, 1, 2, 64)),
                   n=rng.choice(names + [None]) if rng.random() > 0.5 else rng.choice(names))
        vms[str(vid)] = g
    return vms


# --- what fits the columns comes back as it went in -------------------------------------------

@pytest.mark.parametrize('seed', range(25))
def test_random_guest_maps_read_back_exactly(seed):
    rng = random.Random(seed)
    vms = _random_guests(rng, rng.choice((0, 1, 7, 300)))
    _roundtrip(vms, {'pve1': {}, 'edge': {}})


def test_the_edges_the_collector_writes_read_back_exactly():
    vms = {
        '100': _guest(n=None),                         # before #965 there is no host
        '101': _guest(n=''),                           # a resource row without a node
        '102': _guest(t='lxc'),
        '103': _guest(cpu=None),                       # running, no cpu figure
        '104': _guest(r=False, cpu=None, mem=None),
        '105': _guest(maxmem=0, mem=None),
        '106': _guest(maxmem=2 ** 62),
        '107': _guest(cpu=0.0), '108': _guest(cpu=100.0), '109': _guest(cpu=105.3),
        '110': _guest(cpu=0),                          # round(0 * 100, 1) of an idle guest stays an int
        '4294967295': _guest(),                        # the top of the vmid range
        '0': _guest(),
        '111': _guest(n='Rechenzentrum Süd'), '112': _guest(n='half \udc80 a pair'),
        '113': _guest(cpu=3276.7, mem=0.1),
    }
    roster, dyn = _roundtrip(vms)
    back = ms.guest_map(ms.decode_roster(roster), dyn)
    assert type(back['110']['cpu']) is int and back['110']['cpu'] == 0
    assert type(back['107']['cpu']) is float
    assert 'n' not in back['100'] and back['101']['n'] == ''


def test_the_dict_order_survives_when_it_is_not_the_vmid_order():
    vms = {str(v): _guest() for v in (300, 100, 200, 150, 999, 101)}
    roster, _dyn = _roundtrip(vms)
    assert ms.decode_roster(roster).perm is not None
    # sorted input needs no order column
    roster2, _ = _roundtrip({str(v): _guest() for v in (100, 101, 150)})
    assert ms.decode_roster(roster2).perm is None


@pytest.mark.parametrize('bend', [
    pytest.param(lambda g: g.update(note='x'), id='a key the collector never wrote'),
    pytest.param(lambda g: g.update({'n': g.pop('n'), 'cpu': g.pop('cpu')}), id='keys out of order'),
    pytest.param(lambda g: g.update(cpu=12), id='an int where a float was'),
    pytest.param(lambda g: g.update(cpu=12.34), id='two decimals'),
    pytest.param(lambda g: g.update(cpu=float('nan')), id='nan'),
    pytest.param(lambda g: g.update(mem=float('inf')), id='inf'),
    pytest.param(lambda g: g.update(cpu=-0.0), id='minus zero'),
    pytest.param(lambda g: g.update(cpu=-1.0), id='negative'),
    pytest.param(lambda g: g.update(cpu=3276.8), id='past an int16 of tenths'),
    pytest.param(lambda g: g.update(maxcpu=True), id='bool maxcpu'),
    pytest.param(lambda g: g.update(maxmem=4.0), id='float maxmem'),
    pytest.param(lambda g: g.update(maxmem=-1), id='negative maxmem'),
    pytest.param(lambda g: g.update(maxmem=1 << 63), id='maxmem past i64'),
    pytest.param(lambda g: g.update(maxcpu=1 << 32), id='maxcpu past u32'),
    pytest.param(lambda g: g.update(t='vm'), id='unknown type'),
    pytest.param(lambda g: g.update(r=1), id='int running'),
    pytest.param(lambda g: g.update(n=5), id='int host'),
    pytest.param(lambda g: g.update(cpu='12.3'), id='text cpu'),
])
def test_an_entry_off_the_shape_keeps_the_guests_as_json(bend):
    vms = {'100': _guest(), '101': _guest()}
    bend(vms['101'])
    assert ms.encode_guests(vms, {'pve1': {}}) is None
    parts = ms.encode_cluster({'name': 'c', 'vms': vms}, check=True)
    guests = [b for p, raw, b in parts if p == ms.P_GUESTS]
    assert guests[0][:1] in (b'{', b'['), 'the guests should have been kept as JSON'
    assert ms._same(ms._rebuild(parts), _json({'name': 'c', 'vms': vms}))


@pytest.mark.parametrize('key', ['abc', '0100', '+100', ' 100', '100 ', '-1', '4294967296', '1_000', '١٠٠'])
def test_a_key_that_is_no_plain_vmid_keeps_the_guests_as_json(key):
    assert ms.encode_guests({key: _guest(), '100': _guest()}, {}) is None


def test_a_guest_that_is_no_dict_keeps_the_guests_as_json():
    assert ms.encode_guests({'100': [1, 2]}, {}) is None
    assert ms.encode_guests({'100': None}, {}) is None


def test_a_cluster_that_is_no_dict_is_kept_whole():
    for value in (['a'], 'text', 5, None, 1.5):
        parts = ms.encode_cluster(value, check=True)
        assert [p for p, _r, _b in parts] == [ms.P_WHOLE]
        assert ms._same(ms._rebuild(parts), _json(value))


def test_a_guest_map_that_is_no_dict_is_kept_as_json():
    cd = {'name': 'c', 'vms': ['100'], 'nodes': {}}
    parts = ms.encode_cluster(cd, check=True)
    assert ms._same(ms._rebuild(parts), _json(cd))
    assert not [p for p, _r, _b in parts if p == ms.P_HOSTS]


def test_the_head_keeps_the_key_order_and_what_was_null():
    cd = {'vms': {'100': _guest()}, 'name': 'c', 'storage': None, 'totals': {'b': 1, 'a': 2},
          'nodes': {}, 'extra': [1, {'x': None}]}
    parts = ms.encode_cluster(cd, check=True)
    kinds = [p for p, _r, _b in parts]
    assert ms.P_STORAGE not in kinds, 'a null map gets no part'
    assert ms.P_NODES in kinds, 'an empty map does'
    back = ms._rebuild(parts)
    assert list(back) == list(cd) and ms._same(back, _json(cd))
    head = json.loads(parts[0][2])
    assert head['vms'] is None and head['nodes'] is None and head['storage'] is None


def test_falsy_maps_that_are_not_null_go_to_their_part():
    for value in (0, '', [], False):
        cd = {'name': 'c', 'nodes': value, 'vms': value, 'storage': value}
        assert ms._same(ms._rebuild(ms.encode_cluster(cd, check=True)), _json(cd))


def test_what_json_would_change_is_changed_the_same_way():
    """The parts are JSON too: tuples come back as lists, int keys as strings."""
    cd = {'name': ('a', 'b'), 'nodes': {1: {'cpu': 1.5}}, 'totals': {'x': (1, 2.5)}, 'vms': {}}
    assert ms._same(ms._rebuild(ms.encode_cluster(cd, check=True)), _json(cd))


def test_a_snapshot_with_more_than_clusters_stays_json():
    assert ms.plan_snapshot({'clusters': {}, 'other': 1}) is None
    assert ms.plan_snapshot({'clusters': []}) is None
    assert ms.plan_snapshot({}) is None
    assert ms.plan_snapshot({'clusters': {1: {}}}) is None
    assert ms.plan_snapshot({'clusters': {}}) == []
    plan = ms.plan_snapshot({'clusters': {'b': {'name': 'B'}, 'a': {'name': 'A'}}})
    assert [(cid, ord_) for cid, ord_, part, _r, _b in plan if part == ms.P_HEAD] == [('b', 0), ('a', 1)]


# --- the strict comparison the checks rely on ----------------------------------------------

def test_the_comparison_sees_types_order_and_float_bits():
    assert ms._same({'a': 1, 'b': 2.0}, {'a': 1, 'b': 2.0})
    assert not ms._same({'a': 1, 'b': 2}, {'b': 2, 'a': 1})
    assert not ms._same(0, 0.0) and not ms._same(True, 1)
    assert not ms._same(0.0, -0.0)
    assert ms._same(float('nan'), float('nan'))
    assert not ms._same([1, 2], [1, 2, 3])


# --- the power model's pass 1, written with the snapshot -------------------------------------

def _pass1(vms, nodes):
    """power._compute_power's pass 1, as plain as it reads there."""
    per_host = {}
    for v in vms.values():
        if not v.get('r'):
            continue
        n = v.get('n')
        if not n:
            return None
        if n not in nodes:
            continue
        vcpus = (v.get('maxcpu') or 0) or 1
        cores = (v.get('cpu') or 0) * vcpus / 100.0
        gb = (v.get('mem') or 0) * (v.get('maxmem') or 0) / (100.0 * GIB)
        if n in per_host:
            s = per_host[n]
            per_host[n] = [s[0] + vcpus, s[1] + cores, s[2] + gb]
        else:
            per_host[n] = [vcpus, cores, gb]
    return per_host


def test_the_host_sums_are_pass_one_of_the_power_model():
    rng = random.Random(7)
    vms = _random_guests(rng, 400)
    for v in vms.values():
        if not v.get('n'):
            v['n'] = 'pve1'
    nodes = {'pve1': {}, 'edge': {}}
    got = ms.host_sums(vms, nodes)
    want = _pass1(vms, nodes)
    assert ms._same(_json(got), want) and list(got) == list(want)
    # and the JSON part gives the same floats back
    assert ms._same(json.loads(ms._dumps(got)), want)


def test_no_host_sums_where_a_running_guest_has_no_host():
    assert ms.host_sums({'1': _guest(n=None)}, {'pve1': {}}) is None
    assert ms.host_sums({'1': _guest(n='')}, {'pve1': {}}) is None
    assert ms.host_sums({'1': _guest(n=None, r=False)}, {'pve1': {}}) == {}


def test_no_host_sums_where_the_host_names_are_no_plain_strings():
    """JSON turns a key 1 into '1': what the power model asks of the read-back nodes would
    not be what the writer saw, so the writer leaves the power parts out."""
    cd = {'name': 'c', 'nodes': {1: {'cpu': 1.0}, 'pve1': {}}, 'vms': {'100': _guest(n='1')}}
    parts = ms.encode_cluster(cd, check=True)
    assert [p for p, _r, _b in parts] == [ms.P_HEAD, ms.P_NODES, ms.P_GUESTS]
    dyn = [b for p, _r, b in parts if p == ms.P_GUESTS][0]
    assert not dyn[ms._DYN.size] & ms.D_ELIG
    assert ms._same(ms._rebuild(parts), _json(cd))


def test_the_eligible_bit_is_running_with_an_online_host():
    vms = {'1': _guest(n='pve1'), '2': _guest(n='gone'), '3': _guest(r=False, cpu=None, mem=None),
           '4': _guest(n=None), '5': _guest(n='')}
    _roster, dyn = ms.encode_guests(vms, {'pve1': {}})
    flags = dyn[ms._DYN.size:ms._DYN.size + 5]
    assert [bool(f & ms.D_ELIG) for f in flags] == [True, False, False, False, False]


# --- one guest at a time ----------------------------------------------------------------------

def test_a_guest_map_read_one_guest_at_a_time_is_the_map():
    rng = random.Random(3)
    vms = _random_guests(rng, 200)
    roster, dyn = ms.encode_guests(vms, {})
    r = ms.decode_roster(roster)
    lazy = ms.GuestMap(r, dyn)
    full = ms.guest_map(r, dyn)
    assert list(lazy) == list(full) and len(lazy) == len(full)
    for key in list(full)[:50]:
        assert key in lazy and ms._same(lazy[key], full[key])
    for key in ('nope', '0100', ' 1', '-1', 5, None, str(1 << 40)):
        assert lazy.get(key) is None and key not in lazy


# --- the bytes on disk ------------------------------------------------------------------------

def test_the_bodies_are_little_endian_as_written_down():
    vms = {'513': _guest(cpu=12.3, mem=None, maxmem=GIB, maxcpu=258, n='pve1'),
           '7': _guest(t='lxc', r=False, cpu=None, mem=None, maxmem=0, maxcpu=1, n=None)}
    roster, dyn = ms.encode_guests(vms, {'pve1': {}})
    names = b'["pve1"]'
    want_roster = (struct.pack('<4sBII', b'PGR1', 1, 2, len(names)) + names
                   + struct.pack('<II', 7, 513)                       # vmids, ascending
                   + bytes((ms.S_HERE | ms.S_LXC, ms.S_HERE | ms.S_HAS_N))
                   + struct.pack('<II', 1, 258) + struct.pack('<qq', 0, GIB)
                   + struct.pack('<HH', 0, 0)
                   + struct.pack('<II', 1, 0))                         # 513 came first
    assert roster == want_roster
    want_dyn = (struct.pack('<4sBI', b'PGD1', 0, 2)
                + bytes((ms.D_HERE, ms.D_HERE | ms.D_RUN | ms.D_CPU | ms.D_ELIG))
                + struct.pack('<hh', 0, 123) + struct.pack('<hh', 0, 0))
    assert dyn == want_dyn


def test_a_big_endian_host_swaps_on_the_way_in_and_out(monkeypatch):
    """What a big-endian host does, played on this one: the arrays are swapped before they
    are written and after they are read, so the body differs from what a host of the other
    order writes for its native arrays, and reads back the same."""
    vms = {str(v): _guest(cpu=float(v % 50), maxcpu=v, maxmem=v * GIB) for v in (300, 100, 70000)}
    native = ms.encode_guests(vms, {'pve1': {}})
    monkeypatch.setattr(ms, '_LE', False)
    swapped = ms.encode_guests(vms, {'pve1': {}})
    assert swapped != native
    # every column swapped: the vmids of the roster, here
    off = ms._ROSTER.size + len(b'["pve1"]')
    a = array(ms._U32)
    a.frombytes(native[0][off:off + 12])
    a.byteswap()
    assert swapped[0][off:off + 12] == a.tobytes()
    back = ms.guest_map(ms.decode_roster(swapped[0]), swapped[1])
    assert ms._same(back, _json(vms))


def test_a_body_that_does_not_fit_its_roster_is_refused():
    roster, dyn = ms.encode_guests({'1': _guest(), '2': _guest()}, {})
    other, other_dyn = ms.encode_guests({'1': _guest()}, {})
    with pytest.raises(ValueError):
        ms.guest_map(ms.decode_roster(roster), other_dyn)
    with pytest.raises(ValueError):
        ms.decode_roster(roster + b'x')
    with pytest.raises(ValueError):
        ms.decode_roster(dyn)


def test_a_roster_is_stored_compressed_and_dedupes_by_content():
    vms = {str(v): _guest() for v in range(100, 400)}
    a, _ = ms.encode_guests(vms, {})
    b, _ = ms.encode_guests(dict(vms), {})
    assert a == b
    vms['150'] = _guest(maxcpu=8)        # resized
    c, _ = ms.encode_guests(vms, {})
    assert c != a
    assert len(zlib.compress(a, 6)) < len(a) / 3
    assert len(a) == ms._ROSTER.size + len(b'["pve1"]') + 300 * (4 + 1 + 4 + 8 + 2)
