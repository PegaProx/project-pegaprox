"""ZFS pools: the pool detail route and the zfs_health alert source.

Proxmox answers GET /nodes/{node}/disks/zfs with the pools of a node (name, size, alloc,
free, frag, dedup, health from `zpool list`) and GET /nodes/{node}/disks/zfs/{name} with
`zpool status -P <name>` as pve-storage parses it (PVE/API2/Disks/ZFS.pm): the header
fields and the config section as a tree of vdevs with state, read, write and cksum. The
pool answers below are made the way Proxmox makes them: _pve_parse is a port of that
parser, run over zpool status output.

The alert is driven tick by tick against the fake cluster of test_alert_events.py; the
route through the real app with a faked manager.
MK Oct 2026
"""
import json
import os
import re
import types

import pytest

from pegaprox.background import alert_events as E
from pegaprox.background import alerts as A
from pegaprox.utils import zpool

from test_alert_events import NOW, _closed, _mute, _open, _rule, _rules, cluster, sent  # noqa: F401
from test_ha_api import ha_env, _standby_of_active  # noqa: F401
from test_ha_loop_gates import _drive, role  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --- what Proxmox answers --------------------------------------------------------------

def _num(text):
    m = re.match(r'[\d.]+', text or '')
    if not m:
        return 0
    n = float(m.group(0))
    return int(n) if n.is_integer() else n


def _pve_parse(text):
    """PVE::API2::Disks::ZFS detail, line by line: the header fields, the config lines
    into a tree by their indent (two spaces a level), lvl dropped and leaf set."""
    pool = {'lvl': 0}
    curfield, config = None, False
    stack, curlvl = [pool], 0
    for line in text.split('\n'):
        m = re.match(r'^\s*(\S+): (\S+.*)$', line)
        if m:
            curfield = m.group(1)
            pool[curfield] = m.group(2)
            if curfield == 'errors':
                config = False
            continue
        m = re.match(r'^\s+(\S+.*)$', line)
        if not config and m:
            pool[curfield] += ' ' + m.group(1)
            continue
        if not config and re.match(r'^\s*config:', line):
            config = True
            continue
        m = re.match(r'^(\s+)(\S+)\s*(\S+)?(?:\s+(\S+)\s+(\S+)\s+(\S+))?\s*(.*)$', line) if config else None
        if not m or m.group(2) == 'NAME':
            continue
        space, name, state, read, write, cksum, msg = m.groups()
        lvl = len(space) // 2 + 1
        vdev = {'name': name, 'msg': msg, 'lvl': lvl}
        if state is not None:
            vdev['state'] = state
        for k, v in (('read', read), ('write', write), ('cksum', cksum)):
            if v is not None:
                vdev[k] = _num(v)
        cur = stack.pop()
        if lvl > curlvl:
            cur['children'] = [vdev]
        elif lvl == curlvl:
            cur = stack.pop()
            cur['children'].append(vdev)
        else:
            while lvl <= cur['lvl'] and cur['lvl'] != 0:
                cur = stack.pop()
            cur['children'].append(vdev)
        stack.append(cur)
        stack.append(vdev)
        curlvl = lvl
    pool['name'] = pool.pop('pool')

    def prep(el):
        el.pop('lvl', None)
        if el.get('children'):
            el['leaf'] = 0
            for c in el['children']:
                prep(c)
        else:
            el['leaf'] = 1
    prep(pool)
    return pool


SCRUBBED = 'scrub repaired 0B in 00:00:02 with 0 errors on Sun Oct  5 00:24:03 2026'

ONLINE = f"""  pool: tank
 state: ONLINE
  scan: {SCRUBBED}
config:

\tNAME           STATE     READ WRITE CKSUM
\ttank           ONLINE       0     0     0
\t  mirror-0     ONLINE       0     0     0
\t    /dev/sdb1  ONLINE       0     0     0
\t    /dev/sdc1  ONLINE       0     0     0
\tlogs
\t  /dev/nvme0n1p1  ONLINE       0     0     0
\tspares
\t  /dev/sdd1    AVAIL

errors: No known data errors
"""

DEGRADED = f"""  pool: tank
 state: DEGRADED
status: One or more devices could not be opened.  Sufficient replicas exist for
\tthe pool to continue functioning in a degraded state.
action: Attach the missing device and online it using 'zpool online'.
   see: https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-2Q
  scan: {SCRUBBED}
config:

\tNAME                      STATE     READ WRITE CKSUM
\ttank                      DEGRADED     0     0     0
\t  mirror-0                DEGRADED     0     0     0
\t    /dev/sdb1             ONLINE       0     0     0
\t    10485834897452934531  UNAVAIL      0     0     0  was /dev/sdc1

errors: No known data errors
"""

CKSUM = """  pool: tank
 state: ONLINE
status: One or more devices has experienced an unrecoverable error.  An
\tattempt was made to correct the error.  Applications are unaffected.
action: Determine if the device needs to be replaced, and clear the errors
\tusing 'zpool clear' or replace the device with 'zpool replace'.
  scan: scrub in progress since Sun Oct  5 00:24:01 2026
\t1.23T scanned at 1.2G/s, 456G issued at 456M/s, 2.00T total
\t0B repaired, 22.80% done, 00:55:00 to go
config:

\tNAME           STATE     READ WRITE CKSUM
\ttank           ONLINE       0     0     0
\t  mirror-0     ONLINE       0     0     0
\t    /dev/sdb1  ONLINE       0     0    12
\t    /dev/sdc1  ONLINE       0     0     0

errors: No known data errors
"""

FAULTED_DATA = f"""  pool: tank
 state: FAULTED
status: One or more devices are faulted in response to IO failures.
action: Make sure the affected devices are connected, then run 'zpool clear'.
  scan: {SCRUBBED}
config:

\tNAME           STATE     READ WRITE CKSUM
\ttank           FAULTED      0     0     0
\t  /dev/sdb1    FAULTED    1.2K     3     0  too many errors

errors: 3 data errors, use '-v' for a list
"""


def _status(text):
    return _pve_parse(text)


def _listed(*pools):
    """The pool list of a node: (name, health) pairs."""
    return [{'name': n, 'size': 1000204886016, 'alloc': 1000, 'free': 1000204885016, 'frag': 1,
             'dedup': 1.0, 'health': h} for n, h in pools]


def _lpath(node):
    return f'/nodes/{node}/disks/zfs'


def _dpath(node, pool):
    return f'/nodes/{node}/disks/zfs/{pool}'


# --- the shape -------------------------------------------------------------------------

def test_the_port_reads_like_proxmox():
    """A check of the fixture itself: what pve-storage builds from zpool status."""
    s = _status(DEGRADED)
    assert (s['name'], s['state'], s['leaf']) == ('tank', 'DEGRADED', 0)
    assert s['status'].startswith('One or more devices could not be opened.  Sufficient replicas exist for the pool')
    top, = s['children']
    assert (top['name'], top['state'], top['cksum']) == ('tank', 'DEGRADED', 0)
    gone = top['children'][0]['children'][1]
    assert gone == {'name': '10485834897452934531', 'state': 'UNAVAIL', 'read': 0, 'write': 0, 'cksum': 0,
                    'msg': 'was /dev/sdc1', 'leaf': 1}
    o = _status(ONLINE)
    assert [c['name'] for c in o['children']] == ['tank', 'logs', 'spares']
    assert o['children'][2]['children'][0] == {'name': '/dev/sdd1', 'state': 'AVAIL', 'msg': '', 'leaf': 1}
    assert 'state' not in o['children'][1]


def test_the_pool_detail_names_what_is_wrong():
    d = zpool.pool_detail(_status(DEGRADED))
    assert (d['name'], d['state'], d['has_errors'], d['data_errors']) == ('tank', 'DEGRADED', False, '')
    assert d['action'] == "Attach the missing device and online it using 'zpool online'."
    assert d['see'] == 'https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-2Q'
    assert [(x['name'], x['state']) for x in d['devices']] == [('mirror-0', 'DEGRADED'),
                                                               ('10485834897452934531', 'UNAVAIL')]
    tank, = d['vdevs']
    mirror, = tank['children']
    assert [(c['name'], c['state'], c['read'], c['cksum'], c['children']) for c in mirror['children']] == [
        ('/dev/sdb1', 'ONLINE', 0, 0, []), ('10485834897452934531', 'UNAVAIL', 0, 0, [])]
    assert d['scan'] == {'kind': 'scrub', 'state': 'finished', 'when': 'Sun Oct 5 00:24:03 2026',
                         'repaired': '0B', 'duration': '00:00:02', 'errors': 0, 'progress': None,
                         'text': 'scrub repaired 0B in 00:00:02 with 0 errors on Sun Oct 5 00:24:03 2026'}
    assert [zpool.device_note(x) for x in d['devices']] == [
        'mirror-0 DEGRADED', '10485834897452934531 UNAVAIL (was /dev/sdc1)']


def test_sections_and_spares_are_no_problem():
    d = zpool.pool_detail(_status(ONLINE))
    assert d['devices'] == [] and d['has_errors'] is False
    logs, spares = d['vdevs'][1:]
    assert (logs['state'], logs['read'], logs['cksum']) == ('', None, None)
    assert spares['children'][0]['state'] == 'AVAIL' and spares['children'][0]['read'] is None


def test_counts_and_data_errors_are_errors():
    d = zpool.pool_detail(_status(CKSUM))
    assert d['state'] == 'ONLINE' and d['has_errors'] is True
    assert d['devices'] == [{'name': '/dev/sdb1', 'state': 'ONLINE', 'read': 0, 'write': 0, 'cksum': 12, 'msg': ''}]
    assert zpool.device_note(d['devices'][0]) == '/dev/sdb1, 0 read, 0 write, 12 checksum errors'
    assert (d['scan']['state'], d['scan']['progress'], d['scan']['when']) == ('running', 22.8, 'Sun Oct 5 00:24:01 2026')
    f = zpool.pool_detail(_status(FAULTED_DATA))
    assert f['data_errors'] == "3 data errors, use '-v' for a list" and f['has_errors'] is True
    # zpool prints 1.2K, Perl keeps the 1.2
    assert f['devices'][0]['read'] == 1.2
    assert zpool.device_note(f['devices'][0]) == '/dev/sdb1 FAULTED (too many errors), 1.2 read, 3 write, 0 checksum errors'


@pytest.mark.parametrize('text,want', [
    ('none requested', ('', 'none', '')),
    ('', ('', 'none', '')),
    ('resilvered 1.2G in 1 days 02:03:04 with 0 errors on Mon Oct  6 10:00:00 2026',
     ('resilver', 'finished', 'Mon Oct 6 10:00:00 2026')),
    ('resilvered (draid1:3d:5c:1s-0) 4.1G in 00:01:02 with 0 errors on Mon Oct  6 10:00:00 2026',
     ('resilver', 'finished', 'Mon Oct 6 10:00:00 2026')),
    ('scrub canceled on Tue Oct  7 01:00:00 2026', ('scrub', 'canceled', 'Tue Oct 7 01:00:00 2026')),
    ('scrub paused since Tue Oct  7 01:00:00 2026 scrub started on Tue Oct  7 00:00:00 2026 1.0T scanned',
     ('scrub', 'paused', 'Tue Oct 7 01:00:00 2026')),
    ('resilver in progress since Tue Oct  7 01:00:00 2026 4.1G scanned, 1.0G resilvered, 5.00% done',
     ('resilver', 'running', 'Tue Oct 7 01:00:00 2026')),
    ('something zpool says one day', ('', 'unknown', '')),
])
def test_the_scan_line(text, want):
    s = zpool.parse_scan(text)
    assert (s['kind'], s['state'], s['when']) == want


def test_a_huge_pool_is_cut_and_says_so():
    leaves = [{'name': f'/dev/disk{i}', 'state': 'ONLINE', 'read': 0, 'write': 0, 'cksum': 0, 'msg': '', 'leaf': 1}
              for i in range(zpool.MAX_ROWS + 50)]
    d = zpool.pool_detail({'name': 'big', 'state': 'ONLINE', 'errors': zpool.NO_DATA_ERRORS,
                           'children': [{'name': 'big', 'state': 'ONLINE', 'children': leaves}]})
    assert d['truncated'] is True and len(d['vdevs'][0]['children']) == zpool.MAX_ROWS - 1


@pytest.mark.parametrize('name,ok', [('tank', True), ('rpool', True), ('data_2.x-1', True),
                                     ('a', False), ('1tank', False), ('tank/vm', False), ('../x', False),
                                     ('tank-', False), ('x' * 256, False), (None, False)])
def test_pool_names_proxmox_takes(name, ok):
    assert zpool.valid_pool_name(name) is ok


# --- the alert -------------------------------------------------------------------------

@pytest.fixture
def zc(cluster, monkeypatch):  # noqa: F811
    # raising=False: on a tree without the source the tests below fail at what they check
    monkeypatch.setattr(E, '_zfs', {}, raising=False)
    cluster.answer(_lpath('pve1'), _listed(('tank', 'ONLINE'), ('rpool', 'ONLINE')))
    cluster.answer(_lpath('pve2'), _listed(('rpool', 'ONLINE')))
    cluster.answer(_dpath('pve1', 'tank'), _status(ONLINE))
    cluster.answer(_dpath('pve1', 'rpool'), _status(ONLINE.replace('tank', 'rpool')))
    cluster.answer(_dpath('pve2', 'rpool'), _status(ONLINE.replace('tank', 'rpool')))
    return cluster


def _zfs(**kw):
    r = _rule('task_failed', **kw)
    for k in ('task_type', 'task_status', 'task_warnings'):
        r.pop(k, None)
    r['metric'] = 'zfs_health'
    r['name'] = kw.get('name', 'zfs rule')
    r['threshold'] = kw.get('threshold', 0)
    return r


def _detail_reads(c):
    return [p for p in c.calls if p.count('/') == 5 and '/disks/zfs/' in p]


def test_a_degraded_pool_alerts_once_on_every_path(zc, sent, monkeypatch, db):  # noqa: F811
    _rules(monkeypatch, _zfs())
    zc.answer(_lpath('pve1'), _listed(('tank', 'DEGRADED'), ('rpool', 'ONLINE')))
    zc.answer(_dpath('pve1', 'tank'), _status(DEGRADED))

    E.check_event_alerts(NOW)

    assert sent.names() == ['ZFS pool tank on pve1 is DEGRADED']
    assert [s for _, s, _, _ in sent.mail] == ['[PegaProx Alert] ZFS pool tank on pve1 is DEGRADED']
    (hook, ids), = sent.hooks
    assert ids == ['hook1'] and hook['event'] == 'firing' and hook['metric'] == 'zfs_health'
    assert hook['message'] == ('ZFS pool tank on node pve1 is DEGRADED: mirror-0 DEGRADED; '
                               '10485834897452934531 UNAVAIL (was /dev/sdc1)')
    assert hook['severity'] == 'warning' and hook['current_value'] == 'DEGRADED'
    body = sent.mail[0][2]
    assert 'Pool: tank' in body and 'Last scan: scrub repaired 0B' in body
    row, = _open(db, 'r1')
    assert (row['target_type'], row['target_id'], row['target_name'], row['object_key']) == (
        'node', 'pve1', 'pve1', 'zfs:pve1:tank')
    assert row['operator'] == 'event'

    # the polls after it: nothing more, and each list is read every ZFS_EVERY only
    for i in range(1, 6):
        E.check_event_alerts(NOW + 60 * i)
    assert len(sent.push) == len(sent.hooks) == len(sent.mail) == 1
    assert zc.count(_lpath('pve1')) == 2 and zc.count(_lpath('pve2')) == 2
    assert len(_open(db, 'r1')) == 1


def test_back_online_says_so(zc, sent, monkeypatch, db):  # noqa: F811
    _rules(monkeypatch, _zfs())
    zc.answer(_lpath('pve1'), _listed(('tank', 'DEGRADED')))
    zc.answer(_dpath('pve1', 'tank'), _status(DEGRADED))
    E.check_event_alerts(NOW)
    zc.answer(_lpath('pve1'), _listed(('tank', 'ONLINE')))
    zc.answer(_dpath('pve1', 'tank'), _status(ONLINE))

    E.check_event_alerts(NOW + E.ZFS_EVERY)

    assert sent.names() == ['ZFS pool tank on pve1 is DEGRADED', 'Resolved: ZFS pool tank on pve1']
    assert sent.hooks[-1][0]['event'] == 'resolved' and sent.hooks[-1][0]['severity'] == 'info'
    assert sent.hooks[-1][0]['message'] == 'ZFS pool tank on node pve1 is ONLINE with no errors again.'
    assert sent.mail[-1][1] == '[PegaProx] Resolved: ZFS pool tank on pve1'
    assert _open(db) == [] and [(r['object_key'], r['resolved_by']) for r in _closed(db)] == [
        ('zfs:pve1:tank', 'clear')]


def test_checksum_errors_on_an_online_pool(zc, sent, monkeypatch, db):  # noqa: F811
    _rules(monkeypatch, _zfs(), _zfs(rid='r2', threshold=1, name='state only'))
    zc.answer(_dpath('pve1', 'tank'), _status(CKSUM))

    E.check_event_alerts(NOW)

    # the rule on errors too says it, the one on the state only does not
    assert sent.names() == ['ZFS pool tank on pve1 has errors']
    assert sent.hooks[0][0]['message'] == ('ZFS pool tank on node pve1 is ONLINE with errors: '
                                           '/dev/sdb1, 0 read, 0 write, 12 checksum errors')
    assert [r['alert_id'] for r in _open(db)] == ['r1']
    # zpool clear: the next pass reads the pool again at once, not after ZFS_DETAIL_EVERY
    zc.answer(_dpath('pve1', 'tank'), _status(ONLINE))
    E.check_event_alerts(NOW + E.ZFS_EVERY)
    assert sent.names()[-1] == 'Resolved: ZFS pool tank on pve1' and _open(db) == []


def test_data_errors_are_critical_and_a_worse_state_is_said(zc, sent, monkeypatch, db):  # noqa: F811
    _rules(monkeypatch, _zfs(threshold=1))
    zc.answer(_lpath('pve1'), _listed(('tank', 'DEGRADED')))
    zc.answer(_dpath('pve1', 'tank'), _status(DEGRADED))
    E.check_event_alerts(NOW)
    zc.answer(_lpath('pve1'), _listed(('tank', 'FAULTED')))
    zc.answer(_dpath('pve1', 'tank'), _status(FAULTED_DATA))

    E.check_event_alerts(NOW + E.ZFS_EVERY)

    assert sent.names() == ['ZFS pool tank on pve1 is DEGRADED', 'ZFS pool tank on pve1 is now FAULTED']
    last = sent.hooks[-1][0]
    assert last['event'] == 'changed' and last['severity'] == 'critical'
    assert last['message'] == ('ZFS pool tank on node pve1 is FAULTED: /dev/sdb1 FAULTED (too many errors), '
                               "1.2 read, 3 write, 0 checksum errors; 3 data errors, use '-v' for a list")
    row, = _open(db)
    assert (row['severity'], row['current_value']) == ('critical', 4.0)


def test_a_node_that_does_not_answer_changes_nothing(zc, sent, monkeypatch, db):  # noqa: F811
    _rules(monkeypatch, _zfs())
    zc.answer(_lpath('pve1'), _listed(('tank', 'DEGRADED')))
    zc.answer(_dpath('pve1', 'tank'), _status(DEGRADED))
    E.check_event_alerts(NOW)
    zc.answer(_lpath('pve1'), None, code=500)
    E.check_event_alerts(NOW + E.ZFS_EVERY)
    assert len(_open(db)) == 1 and len(sent.push) == 1
    note = E.source_status()['c1']['zfs']
    assert note['ok'] is False and "unread: ['pve1']" in note['note']
    # an offline node is not asked, and what is open there stays open
    zc.nodes['pve1'] = {'status': 'offline'}
    E.check_event_alerts(NOW + 2 * E.ZFS_EVERY)
    assert zc.count(_lpath('pve1')) == 2 and len(_open(db)) == 1


def test_a_pool_or_a_node_that_is_gone_closes_quietly(zc, sent, monkeypatch, db):  # noqa: F811
    _rules(monkeypatch, _zfs())
    zc.answer(_lpath('pve1'), _listed(('tank', 'DEGRADED')))
    zc.answer(_dpath('pve1', 'tank'), _status(DEGRADED))
    zc.answer(_lpath('pve2'), _listed(('rpool', 'FAULTED')))
    zc.answer(_dpath('pve2', 'rpool'), _status(FAULTED_DATA.replace('tank', 'rpool')))
    E.check_event_alerts(NOW)
    assert len(_open(db)) == 2
    # tank was exported, pve2 left the cluster
    zc.answer(_lpath('pve1'), [])
    del zc.nodes['pve2']
    E.check_event_alerts(NOW + E.ZFS_EVERY)
    assert len(sent.push) == 2
    assert sorted((r['object_key'], r['resolved_by']) for r in _closed(db)) == [
        ('zfs:pve1:tank', 'gone'), ('zfs:pve2:rpool', 'gone')]


def test_the_target_and_the_mutes(zc, sent, monkeypatch, db):  # noqa: F811
    zc.answer(_lpath('pve1'), _listed(('tank', 'DEGRADED')))
    zc.answer(_dpath('pve1', 'tank'), _status(DEGRADED))
    zc.answer(_lpath('pve2'), _listed(('rpool', 'DEGRADED')))
    zc.answer(_dpath('pve2', 'rpool'), _status(DEGRADED.replace('tank', 'rpool')))
    _rules(monkeypatch, _zfs(target_type='node', target_id='pve2'))
    E.check_event_alerts(NOW)
    assert sent.names() == ['ZFS pool rpool on pve2 is DEGRADED']
    # muting the node holds back every rule about it, the pool's alert included
    _mute(db, object_key='node:pve1', now=NOW)
    _rules(monkeypatch, _zfs(rid='r2'))
    E.rule_changed('c1', 'r2')
    E.check_event_alerts(NOW + 60)
    assert [r['object_key'] for r in _open(db, 'r2')] == ['zfs:pve2:rpool']
    assert sent.names()[-1] == 'ZFS pool rpool on pve2 is DEGRADED' and len(sent.push) == 2


def test_one_list_per_node_and_the_detail_reads_are_bounded(cluster, sent, monkeypatch, db):  # noqa: F811
    """100 nodes with two pools each: one list read per node and pass, no guest asked,
    the healthy pools' status spread over passes, the troubled ones first."""
    monkeypatch.setattr(E, '_zfs', {}, raising=False)
    nodes = [f'n{i:03d}' for i in range(100)]
    cluster.nodes = {n: {'status': 'online'} for n in nodes}
    cluster.guests = [{'vmid': 100 + i, 'type': 'qemu', 'node': nodes[i % 100], 'name': f'g{i}'} for i in range(500)]
    for n in nodes:
        cluster.answer(_lpath(n), _listed(('rpool', 'ONLINE'), ('data', 'ONLINE')))
        for p in ('rpool', 'data'):
            cluster.answer(_dpath(n, p), _status(ONLINE.replace('tank', p)))
    cluster.answer(_lpath('n042'), _listed(('rpool', 'ONLINE'), ('data', 'DEGRADED')))
    cluster.answer(_dpath('n042', 'data'), _status(DEGRADED.replace('tank', 'data')))
    _rules(monkeypatch, _zfs())

    E.check_event_alerts(NOW)

    lists = [p for p in cluster.calls if p.endswith('/disks/zfs')]
    assert sorted(lists) == sorted(_lpath(n) for n in nodes)
    details = _detail_reads(cluster)
    assert len(details) == E.ZFS_DETAILS_PER_PASS and details.count(_dpath('n042', 'data')) == 1
    assert not [p for p in cluster.calls if '/qemu/' in p or '/lxc/' in p or p == '/cluster/resources']
    assert sent.names() == ['ZFS pool data on n042 is DEGRADED']
    # the rest of the healthy pools on the passes after, never one twice within ZFS_DETAIL_EVERY
    t = NOW
    while len(set(_detail_reads(cluster))) < 200:
        t += E.ZFS_EVERY
        E.check_event_alerts(t)
        assert len(_detail_reads(cluster)) - len(details) <= E.ZFS_DETAILS_PER_PASS * ((t - NOW) // E.ZFS_EVERY)
    assert t - NOW <= E.ZFS_DETAIL_EVERY
    healthy = [p for p in _detail_reads(cluster) if p != _dpath('n042', 'data')]
    assert len(healthy) == len(set(healthy)) == 199


def test_a_rule_on_the_state_only_reads_no_healthy_pool(zc, sent, monkeypatch, db):  # noqa: F811
    _rules(monkeypatch, _zfs(threshold=1))
    zc.answer(_dpath('pve1', 'tank'), _status(CKSUM))
    for i in range(4):
        E.check_event_alerts(NOW + i * E.ZFS_EVERY)
    assert _detail_reads(zc) == [] and sent.push == []


def test_a_restart_does_not_say_it_again(zc, sent, monkeypatch, db):  # noqa: F811
    _rules(monkeypatch, _zfs())
    zc.answer(_lpath('pve1'), _listed(('tank', 'DEGRADED')))
    zc.answer(_dpath('pve1', 'tank'), _status(DEGRADED))
    E.check_event_alerts(NOW)
    monkeypatch.setattr(E, '_zfs', {})
    E.check_event_alerts(NOW + 120)
    E.check_event_alerts(NOW + 120 + E.ZFS_EVERY)
    assert len(sent.push) == 1 and len(_open(db)) == 1


def test_a_changed_rule_reads_again_at_once(zc, sent, monkeypatch, db):  # noqa: F811
    _rules(monkeypatch, _zfs())
    zc.answer(_lpath('pve1'), _listed(('tank', 'DEGRADED')))
    zc.answer(_dpath('pve1', 'tank'), _status(DEGRADED))
    E.check_event_alerts(NOW)
    E.rule_changed('c1', 'r1')
    assert _open(db) == []
    E.check_event_alerts(NOW + 60)
    assert zc.count(_lpath('pve1')) == 2 and len(_open(db)) == 1 and len(sent.push) == 2


@pytest.mark.parametrize('which', ['standby', 'active'])
def test_only_the_active_instance_reads_and_sends(which, role, zc, sent, monkeypatch, db):  # noqa: F811
    role(which)
    _rules(monkeypatch, _zfs())
    zc.answer(_lpath('pve1'), _listed(('tank', 'DEGRADED')))
    zc.answer(_dpath('pve1', 'tank'), _status(DEGRADED))
    for name in ('check_and_send_alerts', 'process_alert_lifecycle', 'check_node_status_transitions',
                 'check_update_available_alert', '_periodic_session_cleanup', '_periodic_audit_cleanup'):
        monkeypatch.setattr(A, name, lambda *a, **k: None)
    monkeypatch.setattr(A, '_alert_running', False)
    _drive(monkeypatch, A, A.alert_check_loop)
    if which == 'standby':
        assert zc.calls == [] and sent.push == sent.hooks == sent.mail == []
    else:
        assert zc.count(_lpath('pve1')) == 1 and sent.names() == ['ZFS pool tank on pve1 is DEGRADED']
        assert len(sent.hooks) == len(sent.mail) == 1


# --- the rule fields -------------------------------------------------------------------

def _store(monkeypatch, rules=None):
    from pegaprox.api import alerts as am
    store = {'c1': [dict(r) for r in (rules or [])]}
    monkeypatch.setattr(am, 'load_cluster_alerts', lambda: store)
    monkeypatch.setattr(am, 'save_cluster_alerts', lambda a: store.update(a))
    return store


@pytest.fixture
def routes(api, seed):
    api.set_manager('c1', api.make_fake_manager('c1'))
    return types.SimpleNamespace(api=api, seed=seed, admin=api.as_user(seed.user('root', role='admin')))


def test_a_zfs_rule_takes_its_defaults(routes, monkeypatch):
    store = _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'Pools', 'metric': 'zfs_health'})
    assert r.status_code == 200, r.data
    rule = r.get_json()['alert']
    assert (rule['operator'], rule['threshold'], rule['notify_resolved'], rule['target_type']) == (
        'event', 0, True, 'cluster')
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'p', 'metric': 'zfs_health', 'threshold': 1,
                                                           'target_type': 'node', 'target_id': 'pve1'})
    assert r.get_json()['alert']['threshold'] == 1 and len(store['c1']) == 2


@pytest.mark.parametrize('body,needle', [
    ({'threshold': 2}, 'threshold'),
    ({'threshold': -1}, 'threshold'),
    ({'target_type': 'vm', 'target_id': '101'}, 'ZFS rule'),
])
def test_a_bad_zfs_rule_is_refused(routes, monkeypatch, body, needle):
    store = _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json=dict(body, name='x', metric='zfs_health'))
    assert r.status_code == 400 and needle in r.get_json()['error'], r.data
    assert store['c1'] == []


def test_a_standby_takes_no_zfs_rule(ha_env, seed, monkeypatch):  # noqa: F811
    api = ha_env.api
    store = _store(monkeypatch)
    api.set_manager('c1', api.make_fake_manager('c1'))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = c.post('/api/clusters/c1/alerts', json={'name': 'z', 'metric': 'zfs_health'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert store['c1'] == []


def _incident(db, metric='zfs_health', object_key='zfs:pve1:tank', target_type='node', target_id='pve1'):
    db.conn.execute(
        "INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, target_type, target_id, "
        "target_name, message, object_key, triggered_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (f'i{len(object_key)}{metric[:3]}', f'r1:c1:{object_key}', 'r1', 'c1', metric, target_type, target_id,
         target_id, 'x', object_key, '2026-10-05T00:00:00'))
    db.conn.commit()


def test_a_confined_caller_sees_no_pool_incident(routes, db):
    from test_audit_bola_high_2026_09 import _seed_pool_membership
    _incident(db)
    _incident(db, metric='ceph_health', object_key='ceph', target_type='cluster', target_id='')
    _mute(db, object_key='zfs:pve1:tank')
    routes.seed.tenant('t_confined', [])
    routes.seed.pool('c1', 'pool1', 'pooled', ['vm.view'])
    _seed_pool_membership('c1', {101: ('qemu', 'pool1')})
    pooled = routes.api.as_user(routes.seed.user('pooled', role='user', tenant_id='t_confined'))
    r = pooled.get('/api/clusters/c1/active-alerts')
    assert r.status_code == 200 and [i['metric'] for i in r.get_json()['active_alerts']] == ['ceph_health']
    assert pooled.get('/api/clusters/c1/alert-mutes').get_json()['mutes'] == []
    # counterproof: the admin sees both, and the mute
    r = routes.admin.get('/api/clusters/c1/active-alerts')
    assert sorted(i['metric'] for i in r.get_json()['active_alerts']) == ['ceph_health', 'zfs_health']
    assert [m['object_key'] for m in routes.admin.get('/api/clusters/c1/alert-mutes').get_json()['mutes']] == [
        'zfs:pve1:tank']


# --- the pool detail route -------------------------------------------------------------

PATH = '/api/clusters/c1/nodes/pve1/disks/zfs/tank'


@pytest.fixture
def pool_api(api, seed):
    mgr = api.set_manager('c1', api.make_fake_manager('c1', get_node_zfs_detail=(200, _status(DEGRADED))))
    api.set_manager('c2', api.make_fake_manager('c2', get_node_zfs_detail=(200, _status(ONLINE))))
    return types.SimpleNamespace(api=api, seed=seed, mgr=mgr)


def test_the_admin_reads_a_pool(pool_api):
    c = pool_api.api.as_user(pool_api.seed.user('root', role='admin'))
    r = c.get(PATH)
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert (body['name'], body['node'], body['state']) == ('tank', 'pve1', 'DEGRADED')
    assert body['devices'][1]['name'] == '10485834897452934531'
    assert body['scan']['state'] == 'finished' and body['scan']['when'] == 'Sun Oct 5 00:24:03 2026'
    assert body['vdevs'][0]['children'][0]['name'] == 'mirror-0'
    pool_api.mgr.get_node_zfs_detail.assert_called_once_with('pve1', 'tank')


def test_a_viewer_of_the_owning_tenant_reads_it(pool_api):
    pool_api.seed.tenant('acme', ['c1'])
    c = pool_api.api.as_user(pool_api.seed.user('v', role='viewer', tenant_id='acme'))
    assert c.get(PATH).status_code == 200


def test_without_node_view_nothing_is_read(pool_api):
    c = pool_api.api.as_user(pool_api.seed.user('plain', role='user', denied=['node.view']))
    r = c.get(PATH)
    assert r.status_code == 403
    assert pool_api.api.anon().get(PATH).status_code == 401
    assert not pool_api.mgr.get_node_zfs_detail.called


def test_a_pool_confined_user_is_refused(pool_api):
    from test_audit_bola_high_2026_09 import _seed_pool_membership
    pool_api.seed.tenant('t_confined', [])
    pool_api.seed.pool('c1', 'pool1', 'pooled', ['vm.view'])
    _seed_pool_membership('c1', {101: ('qemu', 'pool1')})
    c = pool_api.api.as_user(pool_api.seed.user('pooled', role='user', tenant_id='t_confined'))
    r = c.get(PATH)
    assert r.status_code == 403 and 'whole cluster' in r.get_json()['error']
    assert not pool_api.mgr.get_node_zfs_detail.called


def test_a_portal_user_of_the_owning_tenant_is_refused(pool_api):
    pool_api.seed.tenant('acme', ['c1'])
    pool_api.seed.vm_acl('c1', 101, users=['portal'])
    c = pool_api.api.as_user(pool_api.seed.user('portal', role='user', tenant_id='acme'))
    assert c.get(PATH).status_code == 403
    assert not pool_api.mgr.get_node_zfs_detail.called


def test_a_confined_admin_reads_their_tenant_only(pool_api):
    pool_api.seed.tenant('globex', ['c2'])
    c = pool_api.api.as_user(pool_api.seed.user('gx', role='admin', tenant_id='globex',
                                                tenant_permissions={'globex': {'role': 'user'}}))
    assert c.get(PATH).status_code == 403
    assert c.get('/api/clusters/c2/nodes/pve1/disks/zfs/tank').status_code == 200
    assert not pool_api.mgr.get_node_zfs_detail.called


def test_another_tenant_is_refused(pool_api):
    pool_api.seed.tenant('acme', ['c1'])
    pool_api.seed.tenant('initech', ['c2'])
    c = pool_api.api.as_user(pool_api.seed.user('milton', role='user', tenant_id='initech'))
    assert c.get(PATH).status_code == 403
    assert not pool_api.mgr.get_node_zfs_detail.called


@pytest.mark.parametrize('path,code', [
    ('/api/clusters/c1/nodes/pve1/disks/zfs/a', 400),
    ('/api/clusters/c1/nodes/pve1/disks/zfs/tank%2Fvm', 404),
    ('/api/clusters/c1/nodes/pve1/disks/zfs/1tank', 400),
    ('/api/clusters/c1/nodes/pve_1/disks/zfs/tank', 400),
    ('/api/clusters/c1/nodes/-pve/disks/zfs/tank', 400),
    ('/api/clusters/nope/nodes/pve1/disks/zfs/tank', 404),
])
def test_names_proxmox_would_not_take_are_refused(pool_api, path, code):
    c = pool_api.api.as_user(pool_api.seed.user('root', role='admin'))
    assert c.get(path).status_code == code
    assert not pool_api.mgr.get_node_zfs_detail.called


@pytest.mark.parametrize('answer,code,needle', [
    ((500, None), 502, 'HTTP 500'),
    ((403, None), 502, 'Sys.Audit'),
    ((0, None), 503, 'did not answer'),
    ((200, ['x']), 502, 'could not be read'),
])
def test_a_pool_that_cannot_be_read_says_why(pool_api, answer, code, needle):
    pool_api.mgr.get_node_zfs_detail.return_value = answer
    c = pool_api.api.as_user(pool_api.seed.user('root', role='admin'))
    r = c.get(PATH)
    assert r.status_code == code and needle in r.get_json()['error'], r.data


def test_an_xcpng_pool_is_not_asked(pool_api):
    x = pool_api.api.set_manager('x1', pool_api.api.make_fake_manager('x1', cluster_type='xcpng'))
    c = pool_api.api.as_user(pool_api.seed.user('root', role='admin'))
    assert c.get('/api/clusters/x1/nodes/pve1/disks/zfs/tank').status_code == 400
    assert not x.get_node_zfs_detail.called


def test_a_standby_serves_it_and_writes_nothing(ha_env, seed, db):  # noqa: F811
    api = ha_env.api
    mgr = api.set_manager('c1', api.make_fake_manager('c1', get_node_zfs_detail=(200, _status(ONLINE))))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    before = db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    r = c.get(PATH)
    assert r.status_code == 200 and r.get_json()['state'] == 'ONLINE' and mgr.get_node_zfs_detail.called
    assert db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0] == before


def test_the_route_is_served_once(api):
    rules = [r for r in api.app.url_map.iter_rules()
             if r.rule == '/api/clusters/<cluster_id>/nodes/<node>/disks/zfs/<name>']
    assert [sorted(r.methods - {'HEAD', 'OPTIONS'}) for r in rules] == [['GET']]


def test_the_manager_quotes_what_it_sends():
    from pegaprox.core.manager import PegaProxManager
    seen = []

    class _R:
        status_code = 200

        def json(self):
            return {'data': {'name': 'tank'}}
    class _M(PegaProxManager):
        host, api_port, is_connected = 'pve.example', 8006, True

        def __init__(self):
            pass

        def _api_get(self, url, **kw):
            seen.append((url, kw))
            return _R()
    m = _M()
    assert m.get_node_zfs_detail('pve1', 'tank') == (200, {'name': 'tank'})
    assert seen == [('https://pve.example:8006/api2/json/nodes/pve1/disks/zfs/tank', {'timeout': 15})]
    m.get_node_zfs_detail('pve1', 'a/../b')
    assert seen[-1][0].endswith('/nodes/pve1/disks/zfs/a%2F..%2Fb')


def test_the_new_module_ships_with_updates():
    with open(os.path.join(ROOT, 'version.json'), encoding='utf-8') as fh:
        assert 'pegaprox/utils/zpool.py' in json.load(fh)['update_files']
    with open(os.path.join(ROOT, 'docs', 'openapi.json'), encoding='utf-8') as fh:
        spec = json.load(fh)
    assert 'get' in spec['paths']['/api/clusters/{cluster_id}/nodes/{node}/disks/zfs/{name}']
