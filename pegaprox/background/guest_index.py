# -*- coding: utf-8 -*-
"""
PegaProx guest search index - the MAC addresses, notes and configured IPs of every
guest, for the global search and the command palette.

MK Oct 2026 - /cluster/resources carries names, ids and the agent's IPs, but no MAC
and no description; those are in each guest's own config, which PVE only hands out
one guest at a time. So the index is fed from config reads that happen anyway (the
drift scanner's sweep, a config opened in the UI) and topped up by a slow refresher
with a fixed budget per pass: guests it has never seen first, then the oldest. A
large estate fills in over a while instead of costing one request per guest at once.

In memory only. A description can hold anything; it stays where the config came
from, and the search hands it out under the same per-guest check as the config.

An entry is keyed by the guest id, and PVE gives a freed id to the next new guest. So
an entry keeps the name its config had, and an entry whose guest now goes by another
name is not handed out and is read again first. PegaProx drops the entry itself where
it deletes a guest or puts a new one on an id.
"""

import re
import time
import logging
import functools
import threading

from pegaprox.globals import cluster_managers
from pegaprox.core import ha

# a pass every PASS_SECONDS reads at most PASS_BUDGET configs over all clusters and
# stops after PASS_DEADLINE seconds whatever it got through
PASS_SECONDS = 30
PASS_BUDGET = 50
PASS_DEADLINE = 20
READ_TIMEOUT = 8
# an entry older than this is read again when a pass has budget left
STALE_AFTER = 3600
# the guest list a pass works from may be this old
LIST_MAX_AGE = 300
NOTES_MAX = 2048

_NET_KEY = re.compile(r'net\d+')
_IPCONFIG_KEY = re.compile(r'ipconfig(\d+)')
_MAC = re.compile(r'(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f])')
_MAC_SEP = re.compile(r'[\s:.\-]')
_HEX = re.compile(r'[0-9a-f]+')
_DIGITS_AND_DOTS = re.compile(r'[\d.]+')
_NOT_AN_ADDRESS = ('dhcp', 'auto', 'manual')

_lock = threading.Lock()
_index = {}    # cluster_id -> {(vm_type, vmid): entry}
_thread = None


def normalize_mac(text):
    """The hex digits of a MAC address, lower case: separators and case do not count."""
    return _MAC_SEP.sub('', str(text or '')).lower()


@functools.lru_cache(maxsize=256)
def mac_needle(query, prefixed=False):
    """What a query looks for among the MAC addresses, or None when it cannot be a part of one.

    With mac: in front anything of two hex digits on. Without, the query has to look the
    part: four hex digits at least, and not an IP address or a guest id (digits and dots
    only, or an IPv6 address with ::), which would otherwise find a MAC that happens to
    contain the same digits."""
    q = str(query or '').strip().lower()
    hexed = normalize_mac(q)
    if not hexed or not _HEX.fullmatch(hexed):
        return None
    if prefixed:
        return hexed if len(hexed) >= 2 else None
    if '::' in q or _DIGITS_AND_DOTS.fullmatch(q):
        return None
    return hexed if len(hexed) >= 4 else None


def _addresses(value, keys):
    out = []
    for part in str(value or '').split(','):
        key, _, val = part.strip().partition('=')
        if key in keys and val and val.lower() not in _NOT_AN_ADDRESS:
            out.append(val.split('/')[0])
    return out


def _in_order(key):
    # net2 before net10
    m = re.match(r'(\D*)(\d+)$', key)
    return (m.group(1), int(m.group(2))) if m else (key, -1)


def parse_config(vm_type, cfg):
    """{'macs': [(net, MAC as configured, normalized)], 'ips': [(net, ip)], 'notes': str} of a
    guest config as /config returns it. Container NICs carry hwaddr= and ip=/ip6= on the netN
    line, a VM the MAC after its model and its static addresses in the cloud-init ipconfigN."""
    macs, ips = [], []
    if not isinstance(cfg, dict):
        cfg = {}
    for key in sorted((k for k in cfg if isinstance(k, str)), key=_in_order):
        value = cfg.get(key)
        if not isinstance(value, str):
            continue
        if _NET_KEY.fullmatch(key):
            for mac in _MAC.findall(value):
                macs.append((key, mac.upper(), normalize_mac(mac)))
            if vm_type == 'lxc':
                ips.extend((key, ip) for ip in _addresses(value, ('ip', 'ip6')))
            continue
        m = _IPCONFIG_KEY.fullmatch(key)
        if m and vm_type == 'qemu':
            ips.extend((f'net{m.group(1)}', ip) for ip in _addresses(value, ('ip', 'ip6')))
    notes = cfg.get('description')
    notes = notes[:NOTES_MAX] if isinstance(notes, str) else ''
    return {'macs': macs, 'ips': ips, 'notes': notes, 'notes_lc': notes.lower()}


def _config_name(vm_type, cfg):
    # what /cluster/resources shows as the name; '' when the config sets none
    name = cfg.get('hostname' if vm_type == 'lxc' else 'name')
    return name.strip().lower() if isinstance(name, str) else ''


def same_guest(entry, name):
    """False when the entry was read from a guest of another name, which is how a VMID
    that went to a new guest shows. An entry or a row without a name says nothing."""
    known = (entry or {}).get('name')
    name = str(name or '').strip().lower()
    return not known or not name or known == name


def ingest(cluster_id, vm_type, vmid, cfg):
    """Take a guest config that was read anyway. Never raises: a caller reads configs for
    something else and must not fail over the index."""
    try:
        if vm_type not in ('qemu', 'lxc') or not isinstance(cfg, dict):
            return
        entry = parse_config(vm_type, cfg)
        entry['name'] = _config_name(vm_type, cfg)
        entry['at'] = time.monotonic()
        with _lock:
            _index.setdefault(cluster_id, {})[(vm_type, int(vmid))] = entry
    except Exception as e:
        logging.debug(f"[guest-index] {cluster_id}/{vm_type}/{vmid} not taken: {e}")


def _mark_tried(cluster_id, key):
    """A read that failed: what the entry had stays, and the guest waits for its turn again."""
    with _lock:
        entries = _index.setdefault(cluster_id, {})
        old = entries.get(key)
        entries[key] = dict(old or {'macs': [], 'ips': [], 'notes': '', 'notes_lc': ''},
                            at=time.monotonic())


def snapshot(cluster_id):
    """The entries of one cluster, {(vm_type, vmid): entry}. An entry is replaced as a whole
    and never changed in place, so the copy can be read without the lock."""
    with _lock:
        return dict(_index.get(cluster_id) or {})


def forget(cluster_id, keep=None):
    """Drop a cluster, or with keep the entries of guests it no longer has."""
    with _lock:
        if keep is None:
            _index.pop(cluster_id, None)
            return
        entries = _index.get(cluster_id)
        if entries:
            for key in [k for k in entries if k not in keep]:
                del entries[key]


def drop(cluster_id, vm_type, vmid):
    """Forget one guest: it was deleted, or its id now belongs to a new one."""
    try:
        key = (vm_type, int(vmid))
    except (TypeError, ValueError):
        return
    with _lock:
        entries = _index.get(cluster_id)
        if entries:
            entries.pop(key, None)


def clear():
    with _lock:
        _index.clear()


def find(entry, live_ips, query, fields=('ip', 'mac', 'notes'), prefixed=False):
    """(field, value, net) of the first known IP, MAC or note of a guest that holds the query
    (lower case), else None. live_ips are what the guest agent reports right now."""
    for field in fields:
        if field == 'ip':
            for ip in live_ips or ():
                if isinstance(ip, str) and query in ip.lower():
                    return 'ip', ip, None
            for net, ip in (entry or {}).get('ips') or ():
                if query in ip.lower():
                    return 'ip', ip, net
        elif field == 'mac':
            needle = mac_needle(query, prefixed=prefixed)
            if needle:
                for net, mac, flat in (entry or {}).get('macs') or ():
                    if needle in flat:
                        return 'mac', mac, net
        elif field == 'notes':
            at = ((entry or {}).get('notes_lc') or '').find(query)
            if at >= 0:
                return 'notes', notes_excerpt(entry['notes'], at, len(query)), None
    return None


def notes_excerpt(notes, at, length, around=40):
    """The part of a note around a hit, on one line."""
    start, end = max(0, at - around), min(len(notes), at + length + around)
    text = ' '.join(notes[start:end].split())
    return ('...' if start > 0 else '') + text + ('...' if end < len(notes) else '')


# -- the refresher ---------------------------------------------------------------------------

def _due(cluster_id, rows, entries, now):
    """The guests of one cluster to read, those never read first, then the oldest."""
    never, stale = [], []
    for r in rows:
        vm_type, vmid, node = r.get('type'), r.get('vmid'), r.get('node')
        # unknown: PVE says so for every guest of a node that is down
        if vm_type not in ('qemu', 'lxc') or not node or r.get('status') == 'unknown':
            continue
        try:
            key = (vm_type, int(vmid))
        except (TypeError, ValueError):
            continue
        entry = entries.get(key)
        if entry is None:
            never.append((key, node))
        elif now - entry.get('at', 0) >= STALE_AFTER:
            stale.append((entry.get('at', 0), key, node))
    stale.sort(key=lambda s: s[0])
    return never + [(key, node) for _, key, node in stale]


def _read_config(mgr, cluster_id, key, node):
    """Read one guest config into the index. False when the request got no answer at all."""
    vm_type, vmid = key
    url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vm_type}/{vmid}/config"
    answered = False
    try:
        resp = mgr._api_get(url, timeout=READ_TIMEOUT)
        answered = True
        if resp is not None and getattr(resp, 'status_code', 0) == 200:
            ingest(cluster_id, vm_type, vmid, resp.json().get('data') or {})
            return True
    except Exception as e:
        logging.debug(f"[guest-index] {cluster_id}/{vm_type}/{vmid}: {e}")
    _mark_tried(cluster_id, key)
    return answered


def refresh_pass(budget=PASS_BUDGET, deadline=PASS_DEADLINE):
    """One pass over every connected Proxmox cluster. Returns how many configs it read."""
    with _lock:
        for cid in [c for c in _index if c not in cluster_managers]:
            del _index[cid]
    queues = []
    now = time.monotonic()
    for cid, mgr in list(cluster_managers.items()):
        if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox' or not getattr(mgr, 'is_connected', False):
            continue
        try:
            rows = [r for r in (mgr.get_vm_resources(max_age=LIST_MAX_AGE) or []) if isinstance(r, dict)]
        except Exception as e:
            logging.debug(f"[guest-index] guest list of {cid}: {e}")
            continue
        if rows:
            # an empty answer is as likely a failed read as a cluster without guests.
            # An entry whose guest goes by another name now was read from the guest
            # that had the id before: it goes too, so the new one is read first
            entries = snapshot(cid)
            keep = set()
            for r in rows:
                if str(r.get('vmid', '')).isdigit():
                    key = (r.get('type'), int(r['vmid']))
                    if same_guest(entries.get(key), r.get('name')):
                        keep.add(key)
            forget(cid, keep)
        due = _due(cid, rows, snapshot(cid), now)
        if due:
            queues.append((cid, mgr, due))
    # round robin, so one large cluster does not take every pass
    read, stop_at = 0, time.monotonic() + deadline
    while queues and read < budget and time.monotonic() < stop_at:
        for item in list(queues):
            cid, mgr, due = item
            if read >= budget or time.monotonic() >= stop_at:
                break
            key, node = due.pop(0)
            if not _read_config(mgr, cid, key, node):
                # a node that let one read run into the timeout gets no second one this pass
                due[:] = [d for d in due if d[1] != node]
            read += 1
            if not due:
                queues.remove(item)
    return read


def _loop():
    time.sleep(PASS_SECONDS)
    while True:
        try:
            # where users are served: an active instance, or a standby the leader made one
            if ha.is_active() or ha.serve_assigned():
                refresh_pass()
        except Exception as e:
            logging.warning(f"[guest-index] pass failed: {e}")
        time.sleep(PASS_SECONDS)


def start_guest_index_thread():
    global _thread
    if _thread is None or not _thread.is_alive():
        _thread = threading.Thread(target=_loop, daemon=True, name='guest-index')
        _thread.start()
        logging.info(f"Guest search index started ({PASS_BUDGET} configs per {PASS_SECONDS}s)")
