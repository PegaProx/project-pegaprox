"""The history reports read guests from columns and have to say exactly what the dicts said.

Costs, right-sizing and power walk guests x snapshots. Where every snapshot of a window has its
guests in columns (pegaprox/background/metrics_store.py), _cost_stats, _sizing_stats and
_compute_power hand the window to a twin (_cost_stats_cols, _sizing_stats_cols,
_compute_power_cols) that reads one guest's samples as a slice of a column instead of a dict
per guest and sample. The twins replay the originals' arithmetic in the same order on the same
numbers, so the answer must be the same to the bit: the same dicts, the same key order, the
same floats, the same row order and host order.

Every test here writes a generated history through the real writer, reads it back as the
routes do (a ClusterWindow), and holds the twin against the original engine run on the JSON
of the very same snapshots, which is what an older PegaProx read. The histories have what
real ones have: guests created and deleted (a vmid coming back), migrations, a host that went
offline with its guests still listed as running, one that joined, the list in another order
now and then, stopped and toggling guests, resized ones, the int 0 an idle guest's cpu reads
as, memory without a figure, and rows from before #965 without a host.
MK Oct 2026
"""
import json
import random
from datetime import datetime, timedelta

import pytest

from pegaprox import constants
from pegaprox.api import costs, insights, power
from pegaprox.background import metrics_store as ms
from pegaprox.core import dbcrypto

import metrics_history_fixture as mhf

GIB = 1024 ** 3
CID = 'c1'
RATES = {'node_idle_w': 80.0, 'node_max_w': 300.0, 'mem_w_per_gb': 0.3, 'pue': 1.5,
         'kwh_price': 0.3, 'kg_co2_per_kwh': 0.4, 'currency': 'EUR'}
PROFILES = {'pve2': {'idle_w': 95.0, 'max_w': 260.0, 'notes': '', 'updated_at': None, 'updated_by': ''}}


class _Guest:
    def __init__(self, rng, vid, host):
        self.vid = vid
        self.t = 'lxc' if rng.random() < 0.2 else 'qemu'
        self.maxcpu = rng.choice((0, 1, 2, 4, 8, 32))
        self.maxmem = rng.choice((0, GIB, 2 * GIB, 3 * GIB, 6 * GIB, 1 << 40))
        self.host = host
        self.on = rng.random() < 0.8
        self.idle = rng.random() < 0.15        # reads cpu 0: the int the collector writes


def _history(rng, guests, snaps, pre965=0, running_hosts_only=True):
    """[(timestamp, snapshot)] of cluster c1, about 5 minutes apart and ending now, with
    the churn described above. pre965: that many oldest rows without a host per guest.
    running_hosts_only: no running guest without a host after those (else the power model
    has to guess the host for that row, and the host sums are not written)."""
    hosts = ['pve1', 'pve2', 'pve3', 'Rechenzentrum-Süd']
    alive = {}
    next_vid = [100]

    def create():
        vid = next_vid[0]
        next_vid[0] += rng.choice((1, 1, 1, 7))
        alive[vid] = _Guest(rng, vid, rng.choice(hosts[:3]))

    for _ in range(guests):
        create()
    dead = []
    # a stopped guest whose resource row had no node
    if guests > 3:
        orphan = _Guest(rng, 99, '')
        orphan.on = False
        alive[99] = orphan
    offline = (snaps // 3, snaps // 3 + max(2, snaps // 10))      # pve3 away for a while
    joins = snaps // 2                                            # the 4th host joins
    start = datetime.now() - timedelta(minutes=5 * snaps + 2)
    out = []
    for s in range(snaps):
        if s in (snaps // 4, snaps // 4 + 1) and snaps > 20:
            continue                                              # the collector was not running
        # what changed since the last cycle
        for g in list(alive.values()):
            if getattr(g, 'until', None):
                continue
            x = rng.random()
            if x < 0.004 and len(alive) > 1 and g.vid != 99:
                dead.append(alive.pop(g.vid))
            elif x < 0.010:
                g.host = rng.choice(hosts if s >= joins else hosts[:3])
            elif x < 0.014:
                g.maxcpu = rng.choice((1, 2, 4, 16))
            elif x < 0.018:
                g.maxmem = rng.choice((GIB, 4 * GIB, 12 * GIB))
            elif x < 0.030 and g.vid != 99:
                g.on = not g.on
        if rng.random() < 0.02:
            create()
        if dead and rng.random() < 0.02:
            back = dead.pop(0)                                    # PVE hands the vmid out again
            alive[back.vid] = _Guest(rng, back.vid, rng.choice(hosts[:3]))
        if s == offline[0] and guests > 3:
            # guests that only ever ran on pve3 while it was away, and went with it
            for _ in range(3):
                create()
                g = alive[max(alive)]
                g.host, g.on, g.until = 'pve3', True, offline[1]
        for g in [g for g in alive.values() if getattr(g, 'until', None) == s]:
            dead.append(alive.pop(g.vid))
        nodes = {}
        for h in hosts:
            if h == 'pve3' and offline[0] <= s < offline[1]:
                continue
            if h == hosts[3] and s < joins:
                continue
            nodes[h] = {'status': 'online', 'cpu': round(rng.random() * 90, 1),
                        'mem_percent': round(rng.random() * 95, 1), 'maxcpu': 64, 'maxmem': 256 * GIB}
        # PVE lists the guests host by host, and now and then in another order still
        order = sorted(alive, key=lambda vid: (alive[vid].host, vid))
        if rng.random() < 0.1:
            rng.shuffle(order)
        vms = {}
        for vid in order:
            g = alive[vid]
            run = g.on
            if run:
                cpu = 0 if g.idle else rng.choice((round(rng.random() * 100, 1), 0.0, 105.3, 3.1))
                if rng.random() < 0.01:
                    cpu = None
                mem = round(rng.random() * 99, 1) if g.maxmem else None
            else:
                cpu = mem = None
            v = {'t': g.t, 'r': run, 'cpu': cpu, 'mem': mem, 'maxmem': g.maxmem, 'maxcpu': g.maxcpu}
            if s >= pre965:
                v['n'] = g.host if (g.host or not run or not running_hosts_only) else 'pve1'
            vms[str(vid)] = v
        ts = (start + timedelta(minutes=5 * s, seconds=rng.randrange(-40, 40))).isoformat()
        cd = {'name': 'Testi', 'nodes': nodes,
              'totals': {'vms_running': sum(1 for v in vms.values() if v['r'])},
              'vms': vms, 'storage': {'local': {'used': 1, 'total': 2, 'pct': 50.0}}}
        out.append((ts, {'clusters': {CID: cd}}))
    return out


def _write(rows, legacy=()):
    """Through the real writer; the rows whose index is in `legacy` as an older PegaProx
    wrote them (one JSON blob)."""
    h, run = mhf.History(), []
    for i, row in enumerate(rows):
        if i in legacy:
            if run:
                h.write(run)
                run = []
            h.write([row], legacy=True)
        else:
            run.append(row)
    if run:
        h.write(run)


def _window():
    return ms.cluster_window(CID, 'WHERE timestamp >= ?', ('2000-01-01',))


def _as_json(rows):
    """What the old reader handed the engines: (ts_unix, cluster dict parsed from JSON)."""
    return [(int(datetime.fromisoformat(ts).timestamp()), json.loads(json.dumps(snap['clusters'][CID])))
            for ts, snap in sorted(rows, key=lambda r: r[0])]


def _live(rows):
    """The live guest list: today's guests, a few without a name, the deleted ones gone."""
    last = rows[-1][1]['clusters'][CID]['vms']
    return [{'vmid': int(v), 'name': f'vm-{v}' if int(v) % 5 else '', 'node': e.get('n', '')}
            for v, e in last.items()]


def _equal(got, want):
    assert got == want
    # == leaves out key order, the type of a number and the sign of a zero
    assert ms._same(got, want), 'equal, but not the same to the bit or not in the same order'


def _no_guest_dicts(monkeypatch):
    def made(*a, **k):
        raise AssertionError('a guest dict was built on the column path')
    monkeypatch.setattr(ms, '_entry', made)


SIZES = [(1, 3, 1), (6, 40, 2), (40, 290, 3), (250, 620, 4)]


# --- the twins against the originals -----------------------------------------------------------

@pytest.mark.parametrize('guests,snaps,seed', SIZES)
def test_costs_from_the_columns_are_the_costs_from_the_dicts(db, monkeypatch, guests, snaps, seed):
    rows = _history(random.Random(seed), guests, snaps, pre965=snaps // 5)
    _write(rows)
    want = costs._cost_stats(_as_json(rows))
    _no_guest_dicts(monkeypatch)
    cols = ms.guest_columns(_window())
    assert cols is not None and cols.S == len(rows)
    _equal(costs._cost_stats_cols(cols), want)
    _equal(costs._cost_stats(_window()), want)


@pytest.mark.parametrize('guests,snaps,seed', SIZES)
def test_right_sizing_from_the_columns_is_right_sizing_from_the_dicts(db, monkeypatch, guests, snaps, seed):
    rows = _history(random.Random(seed + 10), guests, snaps, pre965=snaps // 5)
    _write(rows)
    want = insights._sizing_stats(_as_json(rows))
    _no_guest_dicts(monkeypatch)
    cols = ms.guest_columns(_window())
    assert cols is not None
    _equal(insights._sizing_stats_cols(cols), want)
    _equal(insights._sizing_stats(_window()), want)


@pytest.mark.parametrize('guests,snaps,seed', SIZES)
@pytest.mark.parametrize('profiles', [{}, PROFILES], ids=['cluster rates', 'host profile'])
def test_power_from_the_columns_is_power_from_the_dicts(db, monkeypatch, guests, snaps, seed, profiles):
    rows = _history(random.Random(seed + 20), guests, snaps)
    _write(rows)
    live = _live(rows)
    want = power._compute_power(_as_json(rows), live, RATES, profiles, 300)
    _no_guest_dicts(monkeypatch)
    cols = ms.guest_columns(_window(), hosts=True)
    assert cols is not None and len(cols.host_sums) == len(rows)
    got = power._compute_power_cols(cols, live, RATES, profiles, 300)
    _equal(got, want)
    # the row order (sorted by kWh, ties in the order the guests showed up) and the hosts'
    assert [r['vmid'] for r in got['rows']] == [r['vmid'] for r in want['rows']]
    assert list(got['hosts']) == list(want['hosts'])
    _equal(power._compute_power(_window(), live, RATES, profiles, 300), want)


def test_the_power_history_holds_what_the_twin_has_to_get_right(db):
    """The generated history is only worth something with the cases in it: a migrated
    guest charged to two hosts, guests running on the host that was offline, a resized one,
    and a vmid that came back."""
    rows = _history(random.Random(24), 250, 620)
    want = power._compute_power(_as_json(rows), _live(rows), RATES, {}, 300)
    assert sum(1 for r in want['rows'] if len(r['by_node']) > 1) >= 5
    assert list(want['hosts']) == ['pve1', 'pve2', 'pve3', 'Rechenzentrum-Süd']
    snaps = _as_json(rows)
    assert any(v['r'] and v.get('n') == 'pve3' and 'pve3' not in cd['nodes']
               for _ts, cd in snaps for v in cd['vms'].values())
    assert sum(1 for r in want['rows'] if r['by_node'] == {} and r['running_h'] > 0) >= 3
    sizes, hosts_of = {}, {}
    for _ts, cd in snaps:
        for k, v in cd['vms'].items():
            sizes.setdefault(k, set()).add((v['maxcpu'], v['maxmem']))
            hosts_of.setdefault(k, set()).add(v['n'])
    assert sum(1 for x in sizes.values() if len(x) > 1) >= 5
    assert sum(1 for x in hosts_of.values() if len(x) > 1) >= 5
    assert any(list(cd['vms']) != sorted(cd['vms'], key=int) for _ts, cd in snaps)
    assert any(v['cpu'] == 0 and type(v['cpu']) is int for _ts, cd in snaps for v in cd['vms'].values())
    # a vmid that went and came back
    present = [set(cd['vms']) for _ts, cd in snaps]
    assert any(k in present[0] and any(k not in p for p in present) and k in present[-1] for k in present[0])


def test_the_columns_read_back_on_a_big_endian_host_too(db, monkeypatch):
    """The bodies are little-endian on any host: written and read as a big-endian host
    does (array.byteswap both ways), the twins still say what the dicts said."""
    monkeypatch.setattr(ms, '_LE', False)
    rows = _history(random.Random(5), 30, 80)
    _write(rows)
    live = _live(rows)
    window = _window()
    _equal(costs._cost_stats(window), costs._cost_stats(_as_json(rows)))
    _equal(insights._sizing_stats(_window()), insights._sizing_stats(_as_json(rows)))
    _equal(power._compute_power(_window(), live, RATES, PROFILES, 300),
           power._compute_power(_as_json(rows), live, RATES, PROFILES, 300))


# --- which way a window goes ------------------------------------------------------------------

def _spy(monkeypatch, module, name):
    calls = []
    real = getattr(module, name)
    monkeypatch.setattr(module, name, lambda *a, **k: calls.append(1) or real(*a, **k))
    return calls


def test_a_window_all_in_columns_goes_to_the_twins(db, monkeypatch):
    rows = _history(random.Random(1), 20, 50)
    _write(rows)
    spies = [_spy(monkeypatch, costs, '_cost_stats_cols'), _spy(monkeypatch, insights, '_sizing_stats_cols'),
             _spy(monkeypatch, power, '_compute_power_cols')]
    costs._cost_stats(_window())
    insights._sizing_stats(_window())
    power._compute_power(_window(), [], RATES, {}, 300)
    assert spies == [[1], [1], [1]]


@pytest.mark.parametrize('case', ['legacy row', 'guests kept as JSON', 'no host before #965',
                                  'running guest without a host'])
def test_a_window_not_all_in_columns_goes_the_dict_way_and_says_the_same(db, monkeypatch, case):
    rng = random.Random(3)
    if case == 'no host before #965':
        rows = _history(rng, 20, 60, pre965=10)
    elif case == 'running guest without a host':
        rows = _history(rng, 20, 60, running_hosts_only=False)
        rows[30][1]['clusters'][CID]['vms']['100'].update(r=True, cpu=1.0, n='')
    else:
        rows = _history(rng, 20, 60)
    if case == 'guests kept as JSON':
        rows[20][1]['clusters'][CID]['vms']['101']['note'] = 'off the shape'
    _write(rows, legacy={17} if case == 'legacy row' else ())
    live = _live(rows)
    spies = [_spy(monkeypatch, costs, '_cost_stats_cols'), _spy(monkeypatch, insights, '_sizing_stats_cols'),
             _spy(monkeypatch, power, '_compute_power_cols')]
    _equal(costs._cost_stats(_window()), costs._cost_stats(_as_json(rows)))
    _equal(insights._sizing_stats(_window()), insights._sizing_stats(_as_json(rows)))
    _equal(power._compute_power(_window(), live, RATES, PROFILES, 300),
           power._compute_power(_as_json(rows), live, RATES, PROFILES, 300))
    by_dicts = [] if case in ('no host before #965', 'running guest without a host') else [1]
    # costs and right-sizing need no host: rows before #965 still have their columns
    assert spies == [[1] if not by_dicts else [], [1] if not by_dicts else [], []], case


def test_what_is_no_window_goes_the_dict_way(db):
    assert ms.guest_columns([(0, {'vms': {}})]) is None
    assert ms.guest_columns(_window()) is None                    # nothing stored yet
    assert costs._cost_stats([]) == {} and insights._sizing_stats([]) == {}
    assert power._compute_power([], [], RATES, {}, 300) == {'rows': [], 'hosts': {}, 'covered_h': 0}


def test_a_window_whose_guests_were_read_already_stays_with_them(db, monkeypatch):
    """A caller that read the guest dicts already (need('vms')) gets the dict engine on
    them: there is nothing left to save."""
    rows = _history(random.Random(8), 10, 30)
    _write(rows)
    window = ms.need(_window(), 'vms')
    calls = _spy(monkeypatch, costs, '_cost_stats_cols')
    _equal(costs._cost_stats(window), costs._cost_stats(_as_json(rows)))
    assert calls == []


def test_an_empty_guest_list_in_a_snapshot_is_a_snapshot_without_guests(db):
    """A cycle whose guest list read failed stores an empty map: in the columns a roster
    of none, which the window splices in as all holes."""
    rows = _history(random.Random(9), 12, 40)
    rows[10][1]['clusters'][CID]['vms'] = {}
    _write(rows)
    live = _live(rows)
    cols = ms.guest_columns(_window(), hosts=True)
    assert cols is not None
    _equal(costs._cost_stats_cols(cols), costs._cost_stats(_as_json(rows)))
    _equal(insights._sizing_stats_cols(cols), insights._sizing_stats(_as_json(rows)))
    _equal(power._compute_power_cols(cols, live, RATES, {}, 300),
           power._compute_power(_as_json(rows), live, RATES, {}, 300))


def test_a_snapshot_pruned_between_the_reads_leaves_the_window_as_on_the_dict_way(db, monkeypatch):
    """The window's index and its parts are two reads. A row pruned in between leaves the
    window on the dict way (need); the column way falls back to it rather than leave a hole."""
    rows = _history(random.Random(11), 10, 30)
    _write(rows)
    window = _window()
    first = window[0][1].sid
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    conn.execute('DELETE FROM metrics_part WHERE snap_id = ?', (first,))
    conn.execute('DELETE FROM metrics_history WHERE id = ?', (first,))
    conn.commit()
    conn.close()
    calls = _spy(monkeypatch, costs, '_cost_stats_cols')
    _equal(costs._cost_stats(window), costs._cost_stats(_as_json(rows)[1:]))
    assert calls == [] and len(window) == len(rows) - 1


def _db(sql, args=()):
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    try:
        out = [tuple(r) for r in conn.execute(sql, args).fetchall()]
        conn.commit()
        return out
    finally:
        conn.close()


@pytest.mark.parametrize('damage', ['roster gone', 'roster cut short', 'guest part cut short',
                                    'guest part of no kind', 'nodes no JSON', 'storage no JSON'])
def test_a_part_that_does_not_read_leaves_its_snapshot_out_as_a_row_that_did_not_parse(db, caplog, damage):
    """One damaged part or roster raised through need() and took every report of every
    window holding that snapshot down, with a 500; a roster is shared by many snapshots. A
    row an older PegaProx could not parse was left out of the window. A snapshot whose part
    (or roster) does not read is left out the same way, by what reads that part, and the
    figures are those of the snapshots that are left."""
    rows = _history(random.Random(13), 12, 60)
    _write(rows)
    ids = [r[0] for r in _db('SELECT id FROM metrics_history ORDER BY id')]
    sid = ids[30]
    (rid,) = _db('SELECT roster FROM metrics_part WHERE snap_id = ? AND part = 3', (sid,))[0]
    bad = {'vms': set(), 'nodes': set(), 'storage': set()}
    if damage.startswith('roster'):
        bad['vms'] = {s for (s,) in _db('SELECT snap_id FROM metrics_part WHERE roster = ?', (rid,))}
        assert 0 < len(bad['vms']) < len(ids)
        if damage == 'roster gone':
            _db('DELETE FROM metrics_roster WHERE id = ?', (rid,))
        else:
            _db('UPDATE metrics_roster SET body = substr(body, 1, 20) WHERE id = ?', (rid,))
    elif damage.startswith('guest part'):
        bad['vms'] = {sid}
        body = b'{"100": ' if damage == 'guest part cut short' else b'XXXX'
        _db('UPDATE metrics_part SET body = ? WHERE snap_id = ? AND part = 3', (body, sid))
    else:
        key = damage.split()[0]
        bad[key] = {sid}
        _db('UPDATE metrics_part SET body = ? WHERE snap_id = ? AND part = ?',
            (b'{"pve1": {"cpu": ', sid, ms._PART_OF[key]))

    def kept(*keys):
        gone = set().union(*(bad[k] for k in keys))
        return [row for row, i in zip(rows, ids) if i not in gone]
    live = _live(rows)
    _equal(costs._cost_stats(_window()), costs._cost_stats(_as_json(kept('vms'))))
    _equal(insights._sizing_stats(_window()), insights._sizing_stats(_as_json(kept('vms'))))
    _equal(power._compute_power(_window(), live, RATES, {}, 300),
           power._compute_power(_as_json(kept('vms', 'nodes')), live, RATES, {}, 300))
    for key in ('nodes', 'storage'):
        window = ms.need(_window(), key)
        assert [cd.sid for _ts, cd in window] == [i for i in ids if i not in bad[key]], key
        assert all(cd[key] == snap['clusters'][CID][key] for (_ts, cd), (_t, snap) in zip(window, kept(key)))
    assert 'does not read' in caplog.text


@pytest.mark.parametrize('change', ['host', 'cores', 'memory'])
def test_a_guest_eligible_all_along_that_moved_or_was_resized_is_charged_as_it_ran(db, change):
    """A guest that ran on an online host in every snapshot is in every roster, and the
    power twin tells from its K static values whether it kept host, cores and memory (then
    a column at a time) or not (then sample by sample). One that changed only one of the
    three at half time must not be charged as if it had kept the first."""
    start = datetime.now() - timedelta(minutes=5 * 41)
    rows = []
    for s in range(40):
        late = s >= 20
        nodes = {h: {'status': 'online', 'cpu': 10.0 + s % 7, 'mem_percent': 30.0 + s % 5, 'maxcpu': 64,
                     'maxmem': 256 * GIB} for h in ('pve1', 'pve2')}
        vms = {'100': {'t': 'qemu', 'r': True, 'cpu': round(5.0 + s % 9, 1), 'mem': round(40.0 + s % 11, 1),
                       'maxmem': (8 if late and change == 'memory' else 4) * GIB,
                       'maxcpu': 8 if late and change == 'cores' else 2,
                       'n': 'pve2' if late and change == 'host' else 'pve1'},
               '101': {'t': 'lxc', 'r': True, 'cpu': 1.5, 'mem': 12.0, 'maxmem': 2 * GIB, 'maxcpu': 1, 'n': 'pve2'}}
        cd = {'name': 'Testi', 'nodes': nodes, 'totals': {}, 'vms': vms, 'storage': {}}
        rows.append(((start + timedelta(minutes=5 * s)).isoformat(), {'clusters': {CID: cd}}))
    _write(rows)
    live = _live(rows)
    cols = ms.guest_columns(_window(), hosts=True)
    assert cols is not None and cols.K == 2
    got = power._compute_power_cols(cols, live, RATES, {}, 300)
    _equal(got, power._compute_power(_as_json(rows), live, RATES, {}, 300))
    if change == 'host':
        assert list(next(r for r in got['rows'] if r['vmid'] == '100')['by_node']) == ['pve1', 'pve2']
