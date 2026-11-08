# -*- coding: utf-8 -*-
"""
PegaProx Metrics Store - Layer 7
How the 5-minute metrics snapshots are kept: per cluster, in parts.

MK Oct 2026 - a snapshot was one JSON blob of the whole fleet in metrics_history.data,
0.3 MB at 3000 guests and 1.1 MB at 10k. Every reader decrypted and parsed all of it, for
one node's temperature as much as for one cluster's totals, and the parsed windows stayed
in memory for a minute: gigabytes at that size. A snapshot is still one row of
metrics_history (same id, same naive local timestamp, so the same selection SQL), but
what it holds now sits in metrics_part, per cluster:

    part 0  head: the cluster dict as compact JSON, nodes/vms/storage set to null where
            they have a part of their own (so the key order survives)
    part 1  nodes, JSON
    part 2  storage, JSON
    part 3  guests: columnar (encode_guests), or JSON where an entry is off the shape
    part 4  pass 1 of the power model per host (power._compute_power), JSON
    part 9  the whole cluster as JSON, where it is no dict

The static half of the guest columns (vmid, type, cores, memory, host, the order PVE
listed them in) only changes when a guest is created, deleted, moved or resized, so it is
kept once in metrics_roster and shared by every snapshot that has it.

metrics_history.fmt says where a row's payload is: 0 JSON in data (every row an older
PegaProx wrote, not converted yet), 1 JSON in data on purpose (it does not fit the parts),
2 in metrics_part with data ''. The readers take all three in the same query and order,
and the backfill below converts 0 to 1 or 2 in the background, newest first. An older
PegaProx reads data '' as a row it cannot parse and skips it.

Every body is little-endian, whatever the host is (array.byteswap on a big-endian one).
"""

import hashlib
import json
import logging
import math
import struct
import sys
import threading
import time
import zlib
from array import array
from bisect import bisect_left
from collections.abc import Mapping
from datetime import datetime
from itertools import compress, groupby
from operator import sub

from pegaprox import constants
from pegaprox.core import dbcrypto


FMT_LEGACY, FMT_JSON, FMT_PARTS = 0, 1, 2
P_HEAD, P_NODES, P_STORAGE, P_GUESTS, P_HOSTS, P_WHOLE = 0, 1, 2, 3, 4, 9
# the keys of a cluster dict that get a part of their own
_PART_OF = {'nodes': P_NODES, 'vms': P_GUESTS, 'storage': P_STORAGE}
_KEY_OF = {v: k for k, v in _PART_OF.items()}


def ensure_schema(cursor):
    """The fmt column and the two part tables, next to metrics_history (db.py calls this
    right after creating it). The ALTER only rewrites the schema: no data is touched, and
    the rows already there read fmt 0 from the default."""
    cursor.execute("PRAGMA table_info(metrics_history)")
    if 'fmt' not in {r[1] for r in cursor.fetchall()}:
        cursor.execute("ALTER TABLE metrics_history ADD COLUMN fmt INTEGER NOT NULL DEFAULT 0")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics_part (
            snap_id INTEGER NOT NULL,
            cluster_id TEXT NOT NULL,
            part INTEGER NOT NULL,
            ord INTEGER NOT NULL,
            roster INTEGER,
            body BLOB NOT NULL,
            PRIMARY KEY (snap_id, cluster_id, part)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics_roster (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cluster_id TEXT NOT NULL,
            digest BLOB NOT NULL,
            last_snap INTEGER NOT NULL,
            body BLOB NOT NULL
        )
    ''')
    cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_metrics_roster_digest '
                   'ON metrics_roster(cluster_id, digest)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_roster_last ON metrics_roster(last_snap)')


# --- the guest codec ------------------------------------------------------------------------

def _typecode(codes, size):
    for c in codes:
        if array(c).itemsize == size:
            return c
    raise ImportError(f'no array type of {size} bytes')


_U16, _I16 = _typecode('H', 2), _typecode('h', 2)
_U32, _I64 = _typecode('IL', 4), _typecode('qlL', 8)
_LE = sys.byteorder == 'little'


def _pack(a):
    """The bytes of an array, little-endian on any host."""
    if not _LE:
        a = array(a.typecode, a)
        a.byteswap()
    return a.tobytes()


def _unpack(code, buf):
    a = array(code)
    a.frombytes(buf)
    if not _LE:
        a.byteswap()
    return a


_KEYS7 = ('t', 'r', 'cpu', 'mem', 'maxmem', 'maxcpu', 'n')
_KEYS6 = _KEYS7[:-1]          # before #965 the collector wrote no host
# the per-snapshot flags of a guest
D_RUN, D_CPU, D_MEM, D_ELIG, D_HERE = 0x01, 0x02, 0x04, 0x08, 0x80
# the roster's
S_LXC, S_HAS_N, S_HERE = 0x01, 0x02, 0x80
_ROSTER = struct.Struct('<4sBII')     # magic, flags (1: order column), guests, bytes of the host names
_DYN = struct.Struct('<4sBI')         # magic, mode (0: tenths), guests
_ROSTER_MAGIC, _DYN_MAGIC = b'PGR1', b'PGD1'
# a stored tenth -> the float round(x, 1) gave; -1 is the int 0 the collector writes for a
# running guest whose cpu read 0 (round(0 * 100, 1) stays an int)
_FT = [t / 10 for t in range(32768)] + [0]


class _OffShape(Exception):
    pass


def _tenths(x):
    """(stored value, set) of a cpu or mem figure, or _OffShape where t/10 would not give
    back the very same number (the type and the sign of a zero included)."""
    if x is None:
        return 0, False
    if type(x) is float:
        t = round(x * 10)
        if 0 <= t <= 32767 and t / 10 == x and (t or math.copysign(1.0, x) > 0):
            return t, True
    elif type(x) is int and x == 0:
        return -1, True
    raise _OffShape


def encode_guests(vms, nodes):
    """(roster, dyn) bodies of one cluster's guest map, or None where an entry is not what
    the collector writes (then the guests stay JSON, which reads back as before).

    roster: '<4sBII' (b'PGR1', flags, n, len of names), the host names as a JSON list,
            vmid u32[n] ascending, flags u8[n] (lxc, has 'n', here), maxcpu u32[n],
            maxmem i64[n], host u16[n], and the position of each entry in the dict's own
            order u32[n] where that is not the vmid order
    dyn:    '<4sBI' (b'PGD1', 0, n), flags u8[n] (running, cpu set, mem set, eligible for
            the power model, here), cpu i16[n] and mem i16[n] in tenths
    nodes: the snapshot's online hosts, for the eligible bit (running, a host recorded,
    and that host online, as power._compute_power counts a sample)."""
    try:
        items = []
        for k, v in vms.items():
            if type(k) is not str or not isinstance(v, dict):
                return None
            vid = int(k)
            if not 0 <= vid < 1 << 32 or str(vid) != k:
                return None
            items.append((vid, v))
        # host codes in the order the hosts first show up, so the table only changes with them
        names, codes = [], {}
        for _vid, v in items:
            nn = v.get('n')
            if type(nn) is str and nn not in codes:
                codes[nn] = len(names)
                names.append(nn)
        if len(names) > 0xFFFF:
            return None
        online = nodes if isinstance(nodes, dict) else {}
        order = sorted(range(len(items)), key=lambda i: items[i][0])
        vids, sfl, maxcpu, maxmem, ncode = array(_U32), bytearray(), array(_U32), array(_I64), array(_U16)
        dfl, cpu, mem = bytearray(), array(_I16), array(_I16)
        for i in order:
            vid, v = items[i]
            keys = tuple(v)
            if keys != _KEYS7 and keys != _KEYS6:
                return None
            t, r, mm, mc = v['t'], v['r'], v['maxmem'], v['maxcpu']
            if type(t) is not str or t not in ('qemu', 'lxc') or type(r) is not bool:
                return None
            if type(mm) is not int or type(mc) is not int or not 0 <= mm < 1 << 63 or not 0 <= mc < 1 << 32:
                return None
            c, has_c = _tenths(v['cpu'])
            m, has_m = _tenths(v['mem'])
            sf = S_HERE | (S_LXC if t == 'lxc' else 0)
            df = D_HERE | (D_RUN if r else 0) | (D_CPU if has_c else 0) | (D_MEM if has_m else 0)
            if len(keys) == 7:
                nn = v['n']
                if type(nn) is not str:
                    return None
                sf |= S_HAS_N
                ncode.append(codes[nn])
                if r and nn and nn in online:
                    df |= D_ELIG
            else:
                ncode.append(0)
            vids.append(vid)
            sfl.append(sf)
            maxcpu.append(mc)
            maxmem.append(mm)
            dfl.append(df)
            cpu.append(c)
            mem.append(m)
        n = len(items)
        nb = json.dumps(names).encode('ascii')
        ident = order == list(range(n))
        roster = [_ROSTER.pack(_ROSTER_MAGIC, 0 if ident else 1, n, len(nb)), nb, _pack(vids), bytes(sfl),
                  _pack(maxcpu), _pack(maxmem), _pack(ncode)]
        if not ident:
            perm = array(_U32, bytes(4 * n))
            for pos, i in enumerate(order):
                perm[i] = pos
            roster.append(_pack(perm))
        dyn = [_DYN.pack(_DYN_MAGIC, 0, n), bytes(dfl), _pack(cpu), _pack(mem)]
        return b''.join(roster), b''.join(dyn)
    except (_OffShape, ValueError, TypeError, KeyError, OverflowError):
        return None


class Roster:
    """The static guest columns of a roster body, decoded."""
    __slots__ = ('n', 'names', 'vids', 'sfl', 'maxcpu', 'maxmem', 'ncode', 'perm')


def decode_roster(raw):
    """Roster of an uncompressed roster body."""
    magic, flags, n, nl = _ROSTER.unpack_from(raw, 0)
    if magic != _ROSTER_MAGIC:
        raise ValueError('not a roster body')
    r = Roster()
    r.n = n
    off = _ROSTER.size
    r.names = json.loads(raw[off:off + nl])
    off += nl
    r.vids = _unpack(_U32, raw[off:off + 4 * n])
    off += 4 * n
    r.sfl = raw[off:off + n]
    off += n
    r.maxcpu = _unpack(_U32, raw[off:off + 4 * n])
    off += 4 * n
    r.maxmem = _unpack(_I64, raw[off:off + 8 * n])
    off += 8 * n
    r.ncode = _unpack(_U16, raw[off:off + 2 * n])
    off += 2 * n
    r.perm = None
    if flags & 1:
        r.perm = _unpack(_U32, raw[off:off + 4 * n])
        off += 4 * n
    if off != len(raw):
        raise ValueError('roster body has the wrong length')
    return r


def _dyn(body, n):
    """(flags, cpu, mem) of a dyn body that belongs to a roster of n guests."""
    magic, mode, count = _DYN.unpack_from(body, 0)
    if magic != _DYN_MAGIC or mode != 0 or count != n or len(body) != _DYN.size + 5 * n:
        raise ValueError('dyn body does not fit its roster')
    o = _DYN.size
    return body[o:o + n], _unpack(_I16, body[o + n:o + 3 * n]), _unpack(_I16, body[o + 3 * n:o + 5 * n])


def _entry(roster, dfl, cpu, mem, pos):
    sf, df = roster.sfl[pos], dfl[pos]
    g = {'t': 'lxc' if sf & S_LXC else 'qemu', 'r': bool(df & D_RUN),
         'cpu': _FT[cpu[pos]] if df & D_CPU else None, 'mem': _FT[mem[pos]] if df & D_MEM else None,
         'maxmem': roster.maxmem[pos], 'maxcpu': roster.maxcpu[pos]}
    if sf & S_HAS_N:
        g['n'] = roster.names[roster.ncode[pos]]
    return g


def guest_map(roster, body):
    """The guest map exactly as json.loads handed it out: keys, their order, types."""
    dfl, cpu, mem = _dyn(body, roster.n)
    vids = roster.vids
    return {str(vids[pos]): _entry(roster, dfl, cpu, mem, pos)
            for pos in (range(roster.n) if roster.perm is None else roster.perm)}


class GuestMap(Mapping):
    """The guest map of one snapshot, read one guest at a time: a chart of one guest finds
    it in the roster and builds that entry only."""

    def __init__(self, roster, body):
        self._r = roster
        self._dfl, self._cpu, self._mem = _dyn(body, roster.n)

    def _pos(self, key):
        if type(key) is not str:
            return None
        try:
            vid = int(key)
        except ValueError:
            return None
        if str(vid) != key:
            return None
        vids = self._r.vids
        i = bisect_left(vids, vid)
        return i if i < len(vids) and vids[i] == vid else None

    def __getitem__(self, key):
        pos = self._pos(key)
        if pos is None:
            raise KeyError(key)
        return _entry(self._r, self._dfl, self._cpu, self._mem, pos)

    def __contains__(self, key):
        return self._pos(key) is not None

    def __iter__(self):
        r = self._r
        for pos in (range(r.n) if r.perm is None else r.perm):
            yield str(r.vids[pos])

    def __len__(self):
        return self._r.n


_GIB = 1024 ** 3
_PCT_GIB = 100.0 * _GIB


def host_sums(vms, nodes):
    """Pass 1 of power._compute_power for one snapshot, over the guests in their own order:
    {host: [vcpus, cores used, GB used]}. None where a running guest has no host recorded
    (before #965): there only a read knows today's placement. Same operations in the same
    order as there, so the floats are the same."""
    per_host = {}
    for vmid, v in vms.items():
        if not v.get('r'):
            continue
        n = v.get('n')
        if not n:
            return None
        if n not in nodes:
            continue
        maxcpu = v.get('maxcpu') or 0
        maxmem = v.get('maxmem') or 0
        cpu_pct = v.get('cpu') or 0
        mem_pct = v.get('mem') or 0
        vcpus = maxcpu or 1
        cores_used = cpu_pct * vcpus / 100.0
        mem_gb = mem_pct * maxmem / _PCT_GIB
        s = per_host.get(n)
        if s is None:
            per_host[n] = [vcpus, cores_used, mem_gb]
        else:
            s[0] += vcpus
            s[1] += cores_used
            s[2] += mem_gb
    return per_host


# --- a snapshot into parts and back -----------------------------------------------------------

def _dumps(value):
    # json.dumps' own number and string forms (allow_nan, ensure_ascii), only without the spaces
    return json.dumps(value, separators=(',', ':')).encode('ascii')


def _same(a, b):
    """a and b as json.loads hands them out, equal down to the type, the key order and the
    bits of a float (0.0 and -0.0 differ, a NaN equals itself)."""
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return list(a) == list(b) and all(_same(a[k], b[k]) for k in a)
    if type(a) is list:
        return len(a) == len(b) and all(map(_same, a, b))
    if type(a) is float:
        return struct.pack('<d', a) == struct.pack('<d', b)
    return a == b


def _decode_part(part, body, roster):
    if part == P_GUESTS and body[:4] == _DYN_MAGIC:
        return guest_map(roster, body)
    return json.loads(body)


def _rebuild(parts):
    """The cluster value of [(part, roster raw, body)] as encode_cluster made them."""
    by = {p: (raw, body) for p, raw, body in parts}
    if P_WHOLE in by:
        return json.loads(by[P_WHOLE][1])
    cd = json.loads(by[P_HEAD][1])
    for part, key in _KEY_OF.items():
        if part in by:
            raw, body = by[part]
            cd[key] = _decode_part(part, body, decode_roster(raw) if raw is not None else None)
    return cd


def encode_cluster(cd, check=False, ref=None, cid=''):
    """[(part, roster raw or None, body)] of one cluster of a snapshot.

    check: decode what was made and hold it against `ref` (what json.loads of the old blob
    would give; worked out here when not handed in). On a difference that is logged and the
    guests are kept as JSON, or the whole cluster where that does not do it either."""
    if not isinstance(cd, dict):
        return [(P_WHOLE, None, _dumps(cd))]
    head = dict(cd)
    parts, guests = [], None
    for key, part in _PART_OF.items():
        if key in head and head[key] is not None:
            val, head[key] = head[key], None
            if part == P_GUESTS:
                guests = val
            else:
                parts.append((part, None, _dumps(val)))
    if guests is not None:
        nodes = cd.get('nodes') or {}
        # the power model asks `host in nodes` of what JSON gave back: with a host name that
        # is no str (JSON makes one of it) the eligible bits and the host sums are left out
        plain = isinstance(nodes, dict) and all(type(k) is str for k in nodes)
        enc = encode_guests(guests, nodes if plain else {}) if isinstance(guests, dict) else None
        if enc is not None:
            parts.append((P_GUESTS, enc[0], enc[1]))
            if plain:
                try:
                    parts.append((P_HOSTS, None, _dumps(host_sums(guests, nodes))))
                except Exception:
                    pass
        else:
            parts.append((P_GUESTS, None, _dumps(guests)))
    parts.insert(0, (P_HEAD, None, _dumps(head)))
    if not check:
        return parts
    if ref is None:
        ref = json.loads(json.dumps(cd))
    try:
        ok = _same(_rebuild(parts), ref)
    except Exception:
        ok = False
    if ok:
        return parts
    _mismatches[:] = _mismatches[-99:] + [cid]
    if guests is not None and any(p == P_GUESTS and raw is not None for p, raw, _b in parts):
        logging.error(f"[metrics] {cid}: the guest columns did not read back as written - "
                      f"kept as JSON")
        parts = [p for p in parts if p[0] not in (P_GUESTS, P_HOSTS)] + [(P_GUESTS, None, _dumps(guests))]
        try:
            ok = _same(_rebuild(parts), ref)
        except Exception:
            ok = False
        if ok:
            return parts
    logging.error(f"[metrics] {cid}: the snapshot parts did not read back as written - "
                  f"the cluster is kept as JSON")
    return [(P_WHOLE, None, _dumps(ref))]


def _text_id(cid):
    # a str the cluster_id column can take: a lone surrogate (JSON escapes it) does not encode
    if type(cid) is not str:
        return False
    try:
        cid.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def plan_snapshot(stored, check=False, ref=None):
    """[(cluster_id, ord, part, roster raw, body)] of what a metrics_history row held
    ({'clusters': {...}}), or None where it does not fit the parts: anything next to
    'clusters', clusters that is no dict, a cluster id that is no str (or none UTF-8 can
    hold). ref: the parsed row itself (the backfill), held against what the parts read
    back as."""
    clusters = stored.get('clusters') if isinstance(stored, dict) else None
    if list(stored) != ['clusters'] or not isinstance(clusters, dict) \
            or not all(map(_text_id, clusters)):
        return None
    out = []
    for i, (cid, cd) in enumerate(clusters.items()):
        cref = ref['clusters'][cid] if ref is not None else None
        for part, raw, body in encode_cluster(cd, check, cref, cid):
            out.append((cid, i, part, raw, body))
    return out


# --- writing ----------------------------------------------------------------------------------

# One write at a time per process: the collector's save, a force-snapshot, the backfill's
# conversion of a row and the sweeps. Taken on the hub, before the work goes to the pool.
_lock = []
_rosters = {}                 # (db path, cluster id) -> (digest, roster id) of the newest roster
_last_sweep = [0.0]
_last_check = [0.0]
_SWEEP_EVERY = 3600
_CHECK_EVERY = 86400
# every save decodes what it wrote and holds it against the snapshot (the tests set it;
# in production it is one snapshot a day)
_check_every_save = False
# the clusters whose parts did not read back as written, newest last (the tests fail on one)
_mismatches = []


def _write_lock():
    if not _lock:
        try:
            from gevent.lock import Semaphore
            _lock.append(Semaphore(1))
        except Exception:
            import threading
            _lock.append(threading.Lock())
    return _lock[0]


def forget():
    """What the writer keeps in memory, for the tests: the next test has another database."""
    _rosters.clear()
    _last_sweep[0] = 0.0
    _last_check[0] = 0.0


def _due(last, every):
    now = time.monotonic()
    if not last[0] or now - last[0] >= every:
        last[0] = now
        return True
    return False


def _roster_id(cur, db_path, cid, raw, sid, learned):
    """Id of the roster with this body for the cluster, made where there is none yet; its
    last_snap moves up to sid."""
    digest = hashlib.blake2b(raw, digest_size=16).digest()
    hit = learned.get(cid) or _rosters.get((db_path, cid))
    if hit is not None and hit[0] == digest:
        cur.execute('UPDATE metrics_roster SET last_snap = MAX(last_snap, ?) WHERE id = ?', (sid, hit[1]))
        if cur.rowcount == 1:
            learned[cid] = hit
            return hit[1]
    row = cur.execute('SELECT id FROM metrics_roster WHERE cluster_id = ? AND digest = ?',
                      (cid, digest)).fetchone()
    if row is not None:
        rid = row[0]
        cur.execute('UPDATE metrics_roster SET last_snap = MAX(last_snap, ?) WHERE id = ?', (sid, rid))
    else:
        cur.execute('INSERT INTO metrics_roster (cluster_id, digest, last_snap, body) VALUES (?, ?, ?, ?)',
                    (cid, digest, sid, zlib.compress(raw, 6)))
        rid = cur.lastrowid
    learned[cid] = (digest, rid)
    return rid


def _insert_parts(cur, db_path, sid, plan, learned, replace=False):
    rows = []
    for cid, ord_, part, raw, body in plan:
        rid = _roster_id(cur, db_path, cid, raw, sid, learned) if raw is not None else None
        rows.append((sid, cid, part, ord_, rid, body))
    verb = 'INSERT OR REPLACE' if replace else 'INSERT'
    cur.executemany(f'{verb} INTO metrics_part (snap_id, cluster_id, part, ord, roster, body) '
                    'VALUES (?, ?, ?, ?, ?, ?)', rows)


def _sweep(cur):
    """Rosters no snapshot uses any more, and parts whose snapshot is gone: pruned by an
    older PegaProx after a downgrade, which knows nothing of the parts."""
    cur.execute('DELETE FROM metrics_roster WHERE last_snap < (SELECT MIN(id) FROM metrics_history)')
    cur.execute('DELETE FROM metrics_part WHERE snap_id < COALESCE((SELECT MIN(id) FROM metrics_history), ?)',
                (1 << 62,))


def _write_one(cur, db_path, timestamp, stored, plan, learned):
    if plan is None:
        # kept as the old writer wrote it, and read as it was read
        cur.execute('INSERT INTO metrics_history (timestamp, data, fmt) VALUES (?, ?, ?)',
                    (timestamp, json.dumps(stored), FMT_JSON))
        return cur.lastrowid
    cur.execute("INSERT INTO metrics_history (timestamp, data, fmt) VALUES (?, '', ?)", (timestamp, FMT_PARTS))
    sid = cur.lastrowid
    _insert_parts(cur, db_path, sid, plan, learned)
    return sid


def _prune(cur, cutoff):
    # the parts go with their rows; both deletes walk an index
    cur.execute('DELETE FROM metrics_part WHERE snap_id IN '
                '(SELECT id FROM metrics_history WHERE timestamp < ?)', (cutoff,))
    cur.execute('DELETE FROM metrics_history WHERE timestamp < ?', (cutoff,))


def save_many(snapshots, cutoff=None):
    """Write [(timestamp, snapshot)] in one transaction off the hub, each row as save()
    writes it, then prune what is older than `cutoff` (None: nothing). The ids written."""
    db_path = constants.DATABASE_FILE
    check = _check_every_save or _due(_last_check, _CHECK_EVERY)
    sweep = _due(_last_sweep, _SWEEP_EVERY)

    def work(conn):
        learned, ids = {}, []
        planned = []
        for timestamp, snapshot in snapshots:
            stored = {k: v for k, v in snapshot.items() if k != 'timestamp'}
            # the encoding happens here, in the worker thread
            planned.append((timestamp, stored, plan_snapshot(stored, check)))
        cur = conn.cursor()
        for timestamp, stored, plan in planned:
            ids.append(_write_one(cur, db_path, timestamp, stored, plan, learned))
        if cutoff is not None:
            _prune(cur, cutoff)
        if sweep:
            _sweep(cur)
        return ids, learned

    with _write_lock():
        ids, learned = dbcrypto.run_off_hub(work, db_path, commit=True)
    # only once it is committed: a rolled back roster must not be taken for one
    for cid, hit in learned.items():
        _rosters[(db_path, cid)] = hit
    return ids


def save(snapshot, timestamp, cutoff):
    """Write one snapshot as collect_metrics_snapshot builds it, and prune the rows (and
    their parts) older than `cutoff`, in one transaction off the hub. The row's id."""
    ids = save_many([(timestamp, snapshot)], cutoff)
    # an idle process lets go of expired heavy reads every 5 minutes too
    dbcrypto._heavy_cache_sweep()
    return ids[0]


# --- reading ----------------------------------------------------------------------------------

def _in_worker():
    """True in a thread without a gevent hub of its own (a thread of gevent's pool, where
    the report arithmetic runs): a read there runs right where it is."""
    try:
        from gevent._hub_local import get_hub_if_exists
    except Exception:
        return True
    return get_hub_if_exists() is None


def _read(statements, transform, slot=True):
    """transform(rows of each statement) of statements read in one transaction, off the hub;
    on a heavy-read slot unless slot=False."""
    if _in_worker():
        return dbcrypto._heavy_read_now(statements, (), transform)
    from contextlib import nullcontext
    sem = dbcrypto._heavy_sem() if slot else None
    with (sem or nullcontext()):
        return dbcrypto.run_heavy_read(statements, transform=transform)


def part_statements(ids_sql, params, parts, cluster_id=None):
    """The statements for run_heavy_read's list form that read the parts (and the rosters
    they use) of the snapshots whose ids `ids_sql` selects: in the one transaction with the
    statement that selected the rows, so they match."""
    nums = ', '.join(str(p) for p in sorted(parts))
    only = ' AND p.cluster_id = ?' if cluster_id is not None else ''
    args = tuple(params) + ((cluster_id,) if cluster_id is not None else ())
    out = [(f'SELECT p.snap_id, p.cluster_id, p.part, p.ord, p.roster, p.body FROM metrics_part p '
            f'WHERE p.snap_id IN ({ids_sql}) AND p.part IN ({nums}){only}', args)]
    if P_GUESTS in parts:
        out.append((f'SELECT r.id, r.body FROM metrics_roster r WHERE r.id IN (SELECT p.roster '
                    f'FROM metrics_part p WHERE p.snap_id IN ({ids_sql}) AND p.part = 3{only})', args))
    return out


class SnapParts:
    """The parts one read fetched, by snapshot, and the rosters they use (each decoded once)."""

    def __init__(self, part_rows, roster_rows=()):
        self._by_snap = {}
        for r in part_rows:
            self._by_snap.setdefault(r['snap_id'], []).append(
                (r['ord'], r['part'], r['cluster_id'], r['roster'], r['body']))
        for v in self._by_snap.values():
            v.sort(key=lambda x: (x[0], x[1]))
        self._raw = {r['id']: r['body'] for r in roster_rows}
        self._rosters = {}

    def roster(self, rid):
        r = self._rosters.get(rid)
        if r is None:
            r = self._rosters[rid] = decode_roster(zlib.decompress(self._raw[rid]))
        return r

    def guests(self, rid, body, lazy=False):
        if body[:4] != _DYN_MAGIC:
            return json.loads(body)
        r = self.roster(rid)
        return GuestMap(r, body) if lazy else guest_map(r, body)

    def clusters(self, sid, lazy_guests=False):
        """{cluster_id: cluster} of one snapshot, in its own order, from the parts read: the
        whole dict where the head and every part were read, a dict of just the parts read
        otherwise (a chart reads the nodes of one cluster and nothing else)."""
        out = {}
        for _ord, part, cid, rid, body in self._by_snap.get(sid, ()):
            if part == P_WHOLE:
                out[cid] = json.loads(body)
            elif part == P_HEAD:
                out[cid] = json.loads(body)
            elif part in _KEY_OF:
                cd = out.setdefault(cid, {})
                if not isinstance(cd, dict):
                    continue
                key = _KEY_OF[part]
                cd[key] = self.guests(rid, body, lazy_guests) if part == P_GUESTS else json.loads(body)
        return out


def snapshot_clusters(row, parts, lazy_guests=False):
    """The clusters map of one metrics_history row (id, data, fmt) whatever its format; it
    raises where today's json.loads did, and the callers skip the row as they did."""
    fmt = row['fmt']
    if fmt == FMT_PARTS:
        return parts.clusters(row['id'], lazy_guests)
    if fmt in (FMT_LEGACY, FMT_JSON):
        return json.loads(row['data']).get('clusters') or {}
    raise ValueError(f'metrics row format {fmt}')


def snapshot_data(row, parts):
    """What json.loads(data) of the row gave before: {'clusters': ...} of a converted row."""
    fmt = row['fmt']
    if fmt == FMT_PARTS:
        return {'clusters': parts.clusters(row['id'])}
    if fmt in (FMT_LEGACY, FMT_JSON):
        return json.loads(row['data'])
    raise ValueError(f'metrics row format {fmt}')


class LazyCluster(Mapping):
    """A cluster of a converted snapshot in a ClusterWindow: the head is read with the
    window, nodes, guests and storage when first asked for (for every snapshot of the
    window at once). Reads like the dict it was written as."""
    __slots__ = ('sid', '_head', '_waiting', '_window')

    def __init__(self, window, sid, head, waiting):
        self._window, self.sid, self._head, self._waiting = window, sid, head, waiting

    def __getitem__(self, key):
        if key in self._waiting:
            self._window.need(key)
        return self._head[key]

    def __contains__(self, key):
        return key in self._head

    def __iter__(self):
        return iter(self._head)

    def __len__(self):
        return len(self._head)

    def __repr__(self):
        return f'LazyCluster({self.sid}, {list(self._head)})'


class ClusterWindow:
    """One cluster's snapshots of a time window, oldest first: the sequence of (ts_unix,
    cluster) that helpers.load_metrics_window handed out before, for the same rows. A row
    an older PegaProx wrote comes as the dict parsed from it, a converted one as a
    LazyCluster. need() reads parts for all snapshots of the window in one go."""

    def __init__(self, cluster_id, rows):
        self.cluster_id = cluster_id
        self._rows = rows
        self._have = set()

    def __len__(self):
        return len(self._rows)

    def __bool__(self):
        return bool(self._rows)

    def __getitem__(self, i):
        return self._rows[i]

    def __iter__(self):
        return iter(self._rows)

    def need(self, *keys):
        """Read the parts of `keys` ('nodes', 'vms', 'storage') for every converted snapshot
        of the window; the guests are made into the dicts they were written as. A snapshot
        whose part went meanwhile (pruned at the end of the retention) leaves the window."""
        todo = [k for k in keys if k in _PART_OF and k not in self._have]
        if not todo:
            return self
        lazies = [cd for _ts, cd in self._rows if isinstance(cd, LazyCluster)
                  and any(k in cd._waiting for k in todo)]
        if lazies:
            ids = sorted({cd.sid for cd in lazies})
            got, bad = _read(part_statements('SELECT value FROM json_each(?)', (json.dumps(ids),),
                                             [_PART_OF[k] for k in todo], self.cluster_id),
                             lambda res: _decoded_parts(res, ids))
            if bad:
                logging.warning(f"[metrics] {self.cluster_id}: {len(bad)} snapshot(s) left out of the "
                                f"window, a part of theirs does not read (snapshot {bad[0]} first)")
            gone = set()
            for cd in lazies:
                have = got.get(cd.sid, {})
                for k in todo:
                    if k not in cd._waiting:
                        continue
                    part = _PART_OF[k]
                    if part in have:
                        cd._head[k] = have[part]
                    else:
                        gone.add(cd.sid)
                    cd._waiting.discard(k)
            if gone:
                logging.debug(f"[metrics] {self.cluster_id}: {len(gone)} snapshot(s) pruned while read")
                self._rows = [(ts, cd) for ts, cd in self._rows
                              if not (isinstance(cd, LazyCluster) and cd.sid in gone)]
        self._have.update(todo)
        return self

    def dicts(self):
        """[(ts_unix, plain dict)] with every part read: the window as it was handed out."""
        self.need(*_PART_OF)
        return [(ts, dict(cd.items()) if isinstance(cd, LazyCluster) else cd) for ts, cd in self._rows]


def _decoded_parts(results, ids):
    """({sid: {part: value}}, [sid of a snapshot left out]): a snapshot with a part (or its
    roster) that does not read is left out whole, as a row that did not parse always was,
    so the window drops it as one pruned meanwhile."""
    parts = SnapParts(results[0], results[1] if len(results) > 1 else ())
    out, bad = {}, []
    for sid in ids:
        got = {}
        try:
            for _ord, part, _cid, rid, body in parts._by_snap.get(sid, ()):
                if part in _KEY_OF:
                    got[part] = parts.guests(rid, body) if part == P_GUESTS else json.loads(body)
        except Exception:
            bad.append(sid)
            continue
        if got:
            out[sid] = got
    return out, bad


def need(history, *keys):
    """history with the parts of `keys` read where it is a ClusterWindow; anything else (a
    list a test hands in) as it is."""
    if isinstance(history, ClusterWindow):
        history.need(*keys)
    return history


# --- one cluster's guests over a window, as columns -------------------------------------------
#
# The history reports (costs, right-sizing, power) walk guests x snapshots: 2M guest dicts for
# a month of 3000 guests, built from the parts and then thrown away again. Where every
# snapshot of a window has its guests in columns, they read the columns instead (the *_cols
# twins next to _cost_stats, _sizing_stats and _compute_power): one guest's samples are a
# strided slice, and the twins hand the very same numbers in the very same order to the
# same operations, so the result is the same to the bit.

def _bit(mask):
    return bytes(1 if b & mask else 0 for b in range(256))


# bytes.translate tables: a flag byte to 1 where the bit is set, else 0
HERE, RUN, CPU_SET, MEM_SET, ELIGIBLE = _bit(D_HERE), _bit(D_RUN), _bit(D_CPU), _bit(D_MEM), _bit(D_ELIG)
_IN_ROSTER = _bit(S_HERE)
# a stored tenth -> the number the dict had (FT[-1] is the int 0)
FT = _FT


class GuestColumns:
    """The guests of one cluster over the S snapshots of a ClusterWindow.

    flags, cpu and mem: S rows of U, one entry per guest of the whole window (ascending
    vmid), so guest g's samples are col[g::U] in snapshot order; a guest not in a snapshot
    has flags 0 there. sfl, maxcpu, maxmem and host: the static columns, one row of U per
    roster the window uses (K), snap_k[s] being the row of snapshot s. host is a code into
    names. order: (vmid key, g) in the order the guests first show up, which is the order
    a dict of them filled in. rows: the window's (ts, cluster) rows. nodes and host_sums
    per snapshot when they were asked for (the power model)."""
    __slots__ = ('rows', 'S', 'U', 'K', 'order', 'flags', 'cpu', 'mem', 'snap_k',
                 'sfl', 'maxcpu', 'maxmem', 'host', 'names', 'nodes', 'host_sums')

    def flags_of(self, g):
        return self.flags[g::self.U]

    def cpu_of(self, g):
        return self.cpu[g::self.U]

    def mem_of(self, g):
        return self.mem[g::self.U]

    def at(self, col, g, s):
        """Guest g's value of a static column in snapshot s."""
        return col[self.snap_k[s] * self.U + g]

    def values(self, col, g):
        """Guest g's values of a static column, one per roster that has it."""
        here = self.sfl[g::self.U]
        if 0 not in here:
            # in every roster of the window (most guests are)
            return col[g::self.U]
        return list(compress(col[g::self.U], here.translate(_IN_ROSTER)))

    def kind(self, g, s):
        return 'lxc' if self.at(self.sfl, g, s) & S_LXC else 'qemu'


def _plan(vids, upos, width):
    """Where a roster's guests (ascending vmids) sit among the window's `width` guests: None
    where it has them all, else (from, to, 0) runs of its own entries and (0, 0, n) holes."""
    if len(vids) == width:
        return None
    idx = list(map(upos.__getitem__, vids))
    plan, at, i = [], 0, 0
    # both are ascending, so idx[j] - j stays the same along a run of neighbours
    for _step, run in groupby(map(sub, idx, range(len(idx)))):
        j = i + len(list(run))
        if idx[i] > at:
            plan.append((0, 0, idx[i] - at))
        plan.append((i, j, 0))
        at = idx[j - 1] + 1
        i = j
    if at < width:
        plan.append((0, 0, width - at))
    return plan


def _splice(plan, src, size, out):
    if plan is None:
        out.append(src)
        return
    for a, b, gap in plan:
        out.append(bytes(gap * size) if gap else src[a * size:b * size])


def _columns(results, rows, hosts):
    """GuestColumns of the window rows from the parts read, or None where a snapshot has no
    columns to read (its guests stayed JSON, the part is gone, no host sums for power)."""
    parts, raw = {}, {}
    for r in results[0]:
        parts.setdefault(r['snap_id'], {})[r['part']] = (r['roster'], r['body'])
    for r in results[1]:
        raw[r['id']] = r['body']
    snaps, host_sums, dec = [], [], {}
    for _ts, cd in rows:
        have = parts.get(cd.sid) or {}
        rid, body = have.get(P_GUESTS) or (None, b'')
        if rid is None or rid not in raw or body[:4] != _DYN_MAGIC:
            return None
        r = dec.get(rid)
        if r is None:
            r = dec[rid] = decode_roster(zlib.decompress(raw[rid]))
        magic, mode, count = _DYN.unpack_from(body, 0)
        if mode != 0 or count != r.n or len(body) != _DYN.size + 5 * r.n:
            raise ValueError('dyn body does not fit its roster')
        if hosts:
            sums = json.loads(have[P_HOSTS][1]) if P_HOSTS in have else None
            if not isinstance(sums, dict):
                return None
            host_sums.append(sums)
        snaps.append((rid, body))

    keys = {rid: r.vids.tobytes() for rid, r in dec.items()}
    sets = {}
    for rid, r in dec.items():
        sets.setdefault(keys[rid], r.vids)
    if len(sets) == 1:
        union = list(next(iter(sets.values())))
    else:
        u = set()
        for v in sets.values():
            u.update(v)
        union = sorted(u)
    width = len(union)
    upos = dict(zip(union, range(width)))
    plans = {k: _plan(v, upos, width) for k, v in sets.items()}

    # the rosters in the order the window first uses them, and one host table for all
    kof, used, snap_k = {}, [], []
    for rid, _body in snaps:
        k = kof.get(rid)
        if k is None:
            k = kof[rid] = len(used)
            used.append(rid)
        snap_k.append(k)
    names, code = [], {}
    sfl, mc, mm, hc = [], [], [], []
    for rid in used:
        r = dec[rid]
        remap = []
        for nm in r.names:
            c = code.get(nm)
            if c is None:
                c = code[nm] = len(names)
                names.append(nm)
            remap.append(c)
        ncode = r.ncode
        if remap != list(range(len(remap))):
            # a guest without a host (before #965) keeps code 0; nothing reads it there
            ncode = array(_U16, [remap[c] if c < len(remap) else 0 for c in ncode])
        p = plans[keys[rid]]
        _splice(p, r.sfl, 1, sfl)
        _splice(p, r.maxcpu.tobytes(), 4, mc)
        _splice(p, r.maxmem.tobytes(), 8, mm)
        _splice(p, ncode.tobytes(), 2, hc)

    fl, cp, me = [], [], []
    o = _DYN.size
    for rid, body in snaps:
        n = dec[rid].n
        p = plans[keys[rid]]
        view = memoryview(body)
        _splice(p, view[o:o + n], 1, fl)
        _splice(p, view[o + n:o + 3 * n], 2, cp)
        _splice(p, view[o + 3 * n:o + 5 * n], 2, me)

    # the guests in the order they first show up: a snapshot's own order is its dict order
    order, seen, prev, done = [], set(), None, set()
    for k in snap_k:
        if k == prev or len(seen) == width:
            continue
        prev = k
        if keys[used[k]] in done:
            # the guests of a roster like one before it (resized, moved) are all seen
            continue
        done.add(keys[used[k]])
        r = dec[used[k]]
        new = set(r.vids).difference(seen)
        if new:
            vids = r.vids
            for pos in (range(r.n) if r.perm is None else r.perm):
                v = vids[pos]
                if v in new:
                    order.append((str(v), upos[v]))
            seen.update(new)

    c = GuestColumns()
    c.rows, c.S, c.U, c.K = rows, len(snaps), width, len(used)
    c.order, c.snap_k, c.names = order, snap_k, names
    c.flags = b''.join(fl)
    c.cpu, c.mem = _unpack(_I16, b''.join(cp)), _unpack(_I16, b''.join(me))
    c.sfl = b''.join(sfl)
    c.maxcpu, c.maxmem, c.host = array(_U32), array(_I64), array(_U16)
    c.maxcpu.frombytes(b''.join(mc))
    c.maxmem.frombytes(b''.join(mm))
    c.host.frombytes(b''.join(hc))
    c.nodes = None
    c.host_sums = host_sums if hosts else None
    return c


def guest_columns(history, hosts=False):
    """GuestColumns of a ClusterWindow whose every snapshot has its guests in columns (and,
    with hosts, the power model's host sums), else None: a list a test hands in, a row an
    older PegaProx wrote that the backfill has not reached yet, guests kept as JSON, rows
    before #965. Then the dict engines run as before. hosts also reads the nodes. Runs
    where it is called (the report's worker thread)."""
    if not isinstance(history, ClusterWindow) or not history._rows:
        return None
    if not all(isinstance(cd, LazyCluster) and 'vms' in cd._waiting for _ts, cd in history._rows):
        return None
    try:
        if hosts:
            # the nodes as the dict engine reads them, `or {}` and all; a row pruned
            # meanwhile leaves the window here as it does there
            history.need('nodes')
        rows = list(history._rows)
        if not rows:
            return None
        ids = [cd.sid for _ts, cd in rows]
        wanted = [P_GUESTS, P_HOSTS] if hosts else [P_GUESTS]
        cols = _read(part_statements('SELECT value FROM json_each(?)', (json.dumps(ids),), wanted,
                                     history.cluster_id),
                     lambda res: _columns(res, rows, hosts))
    except Exception as e:
        logging.warning(f"[metrics] {history.cluster_id}: guest columns not read ({e}), "
                        f"reading the guests one by one")
        return None
    if cols is not None and hosts:
        cols.nodes = [cd.get('nodes') or {} for _ts, cd in rows]
    return cols


def _window_rows(results, cluster_id, window):
    rows, parts = results[0], results[1]
    present = {}
    for r in parts:
        present.setdefault(r['snap_id'], {})[r['part']] = r['body']
    out = []
    for row in rows:
        fmt = row['fmt']
        try:
            if fmt in (FMT_LEGACY, FMT_JSON):
                d = json.loads(row['data'])
                ts_unix = int(datetime.fromisoformat(row['timestamp']).timestamp())
                clusters = d.get('clusters') or {}
            elif fmt == FMT_PARTS:
                ts_unix = int(datetime.fromisoformat(row['timestamp']).timestamp())
                have = present.get(row['id'])
                if not have:
                    continue
                if P_WHOLE in have:
                    cd = json.loads(have[P_WHOLE])
                elif P_HEAD in have:
                    head = json.loads(have[P_HEAD])
                    waiting = {k for k, p in _PART_OF.items() if p in have and k in head and head[k] is None}
                    cd = LazyCluster(window, row['id'], head, waiting)
                else:
                    continue
                if cd:
                    out.append((ts_unix, cd))
                continue
            else:
                continue
        except Exception:
            continue
        try:
            cd = clusters.get(cluster_id)
        except Exception:
            # the per-cluster filter had its try around the whole loop: a row like this
            # ended the window there
            logging.warning(f"[metrics] history load stopped for {cluster_id} at a row it cannot read")
            break
        if cd:
            out.append((ts_unix, cd))
    return out


def cluster_window(cluster_id, where, params):
    """ClusterWindow of the snapshots `where` selects (helpers.load_metrics_window's
    predicate), oldest first, for one cluster. One read: the rows, the heads of the
    converted ones and which parts they have; rows an older PegaProx wrote are parsed in
    the worker as before, and only this cluster is kept of them."""
    window = ClusterWindow(cluster_id, [])
    sql = f'SELECT id, timestamp, data, fmt FROM metrics_history {where} ORDER BY timestamp ASC'
    heads = (f'SELECT p.snap_id, p.part, CASE WHEN p.part IN (0, 9) THEN p.body END AS body '
             f'FROM metrics_part p WHERE p.snap_id IN (SELECT id FROM metrics_history {where}) '
             f'AND p.cluster_id = ?')
    window._rows = _read([(sql, tuple(params)), (heads, tuple(params) + (cluster_id,))],
                         lambda res: _window_rows(res, cluster_id, window))
    return window


# --- the backfill -----------------------------------------------------------------------------

class _Gone(Exception):
    """The row went (pruned) while it was converted: the conversion is rolled back."""


def _convert(conn, db_path, sid, learned):
    """Row sid from fmt 0 to its parts (fmt 2), or to fmt 1 where it does not fit them;
    'parts', 'json' or 'gone'. Runs in a transaction of its own (run_off_hub)."""
    row = conn.execute('SELECT data FROM metrics_history WHERE id = ? AND fmt = ?', (sid, FMT_LEGACY)).fetchone()
    if row is None:
        return 'gone'
    try:
        root = json.loads(row[0])
    except Exception:
        root = None
    plan = plan_snapshot(root, check=True, ref=root) if isinstance(root, dict) else None
    cur = conn.cursor()
    if plan is None:
        cur.execute('UPDATE metrics_history SET fmt = ? WHERE id = ? AND fmt = ?', (FMT_JSON, sid, FMT_LEGACY))
        if cur.rowcount != 1:
            raise _Gone
        return 'json'
    _insert_parts(cur, db_path, sid, plan, learned, replace=True)
    cur.execute("UPDATE metrics_history SET data = '', fmt = ? WHERE id = ? AND fmt = ?",
                (FMT_PARTS, sid, FMT_LEGACY))
    if cur.rowcount != 1:
        raise _Gone
    return 'parts'


def convert_row(sid):
    """Convert one row (under the write lock, off the hub); what came of it."""
    db_path = constants.DATABASE_FILE
    learned = {}
    with _write_lock():
        try:
            done = dbcrypto.run_off_hub(lambda conn: _convert(conn, db_path, sid, learned), db_path, commit=True)
        except _Gone:
            return 'gone'
    for cid, hit in learned.items():
        _rosters[(db_path, cid)] = hit
    return done


_BATCH = 8
_backfill = {'started': False}


def run_backfill(pace=True, limit=None):
    """Convert every fmt 0 row, newest first (the windows the pages read are done first),
    one row per transaction. Resumable by its nature: what is converted says so in fmt, a
    restart walks from the top again and passes over it. pace: sleep twice the work time
    of a row after it (at least 50 ms), so this takes a third of a core at most. limit:
    stop after that many rows (the tests). {'parts', 'json', 'gone', 'failed'} counts."""
    counts = {'parts': 0, 'json': 0, 'gone': 0, 'failed': 0}
    below = 1 << 62
    done = 0
    while True:
        ids = _read([('SELECT id FROM metrics_history WHERE fmt = 0 AND id < ? ORDER BY id DESC LIMIT ?',
                      (below, _BATCH))], lambda res: [r[0] for r in res[0]], slot=False)
        if not ids:
            break
        for sid in ids:
            if limit is not None and done >= limit:
                return counts
            start = time.monotonic()
            try:
                counts[convert_row(sid)] += 1
            except Exception as e:
                counts['failed'] += 1
                logging.warning(f"[metrics] snapshot {sid} not converted: {e}")
            done += 1
            if pace:
                # gevent's sleep where it patched time, else this thread's own
                time.sleep(max(0.05, 2 * (time.monotonic() - start)))
        below = min(ids)
    return counts


def _backfill_job(delay=0):
    try:
        time.sleep(delay)
        counts = run_backfill()
        if any(counts.values()):
            logging.info(f"[metrics] stored snapshots converted to parts: {counts['parts']}, "
                         f"kept as JSON: {counts['json']}, failed: {counts['failed']}")
    except Exception as e:
        logging.warning(f"[metrics] snapshot conversion stopped: {e}")


def start_backfill(delay=60):
    """The background conversion of the rows an older PegaProx wrote, `delay` seconds from
    now; once per process. Every HA instance converts its own (the tables are local).
    A thread: a greenlet where gevent patched threading, a thread of its own under the
    threaded server (PEGAPROX_NO_GEVENT), where a greenlet would wait for a hub that never
    runs."""
    if _backfill['started']:
        return None
    _backfill['started'] = True
    job = threading.Thread(target=_backfill_job, args=(delay,), name='metrics-backfill', daemon=True)
    job.start()
    return job
