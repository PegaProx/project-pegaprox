# -*- coding: utf-8 -*-
"""The node's half of the offline Windows preparation of an ESXi migration.

MK Nov 2026 - runs as root on the target Proxmox node (python3 with python3-hivex) against the
NTFS volume of the copied boot disk, mounted by the driver injection of core/v2p.py, while the
VM is stopped. Nothing in the guest has to run for it and no Windows account is needed:

  * the static IPv4 configuration of every adapter is read from the SYSTEM hive
    (Tcpip\\Parameters\\Interfaces\\{GUID}, the adapter of each interface from
    Control\\Network\\...\\Connection and Control\\Class\\...\\NNNN) and written to
    <ProgramData>\\KVMMigration\\netconfig.json
  * the uninstall entry of the ESXi guest tools is looked up through the folder of the
    program the VMTools service runs, never by product name
  * firstboot.cmd (v2p_firstboot.cmd), firstboot-data.cmd and the packages of the ISO go next
    to it, and the one-shot SYSTEM service PegaProxFirstBoot starts that script at the first
    boot on KVM
  * the folder and every file written into it get a security descriptor that leaves them to
    SYSTEM and the Administrators; the service is registered only once all of them have it

ProgramData lets every user of the guest create a folder in it. A KVMMigration that is a
link or a junction, or that someone other than SYSTEM and the Administrators can change, is
moved aside and never written into or read from: the files of the first boot run as SYSTEM.

PegaProx imports this module as well, for data_cmd() of the in-guest preparation. Standard
library only, Python 3.7 and later, hivex is imported where a hive is opened: the node has
nothing of PegaProx. Every value that reaches firstboot-data.cmd is checked here, the cmd
script only ever reads plain addresses, MACs, GUIDs and device ids from it.
"""

import base64
import json
import os
import re
import struct
import sys

WORK_DIR = 'KVMMigration'
SERVICE = 'PegaProxFirstBoot'
TASK = 'PegaProxKvmFirstBoot'
NET_CLASS = '{4D36E972-E325-11CE-BFC1-08002BE10318}'
# Windows 10 2004 / Server 2022: the first builds whose pnputil has /remove-device
REMOVE_DEVICE_BUILD = 19041
MAX_NICS = 32
MAX_ADDRS = 16

# REG_* types as hivex numbers them
REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_MULTI_SZ = 1, 2, 4, 7

_IPV4 = re.compile(r'^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$')
_GUID = re.compile(r'^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$')
_MAC = re.compile(r'^[0-9a-f]{12}$')
# a PCI device instance id as the Enum tree names it; no character cmd would act on
_DEV = re.compile(r'^PCI\\[A-Za-z0-9_&]{1,120}\\[A-Za-z0-9_&.]{1,80}$')
_RUN = re.compile(r'^[A-Za-z0-9-]{1,64}$')
_FILE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
# vmxnet3 has the PCI device serial number capability, the instance id is that EUI-64 (the MAC
# with FF-FE in the middle, both double words reversed) and the function: FF565000B5D2BAFE00
# is 00:50:56:BA:D2:B5
_DSN_MAC = re.compile(r'^FF([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})FE[0-9A-F]{2}$')

SID_SYSTEM = (5, (18,))
SID_ADMINS = (5, (32, 544))
FILE_ALL_ACCESS = 0x001F01FF
_PRIVILEGED = ('S-1-5-18', 'S-1-5-32-544')
# the access bits that change a file or folder, its content, its descriptor or its owner (write
# and append data / add file and subfolder, write EA, delete child, write attributes, delete,
# WRITE_DAC, WRITE_OWNER, MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE)
WRITE_BITS = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x2000000 | 0x10000000 | 0x40000000
# what an earlier first boot left; never part of this copy's first boot
STALE_STATE = ('boots.txt', 'firstboot.json', 'firstboot.nics', 'drivers.done', 'agent.done', 'net.done',
               'devices.done', 'tools.done')
# DEVPKEY_Device_LastArrivalDate (0066) and LastRemovalDate (0067), Windows 8 and later
_DEV_DATES = '{83da6326-97a6-4088-9453-a1923f573b29}'


# --------------------------------------------------------------------------- values

def norm_mac(mac):
    """'005056bad2b5' of any spelling of a MAC, '' for anything that is no unicast MAC"""
    s = re.sub(r'[^0-9a-fA-F]', '', str(mac or '')).lower()
    if not _MAC.match(s) or int(s[:2], 16) & 1 or s == '000000000000':
        return ''
    return s


def mac_from_instance(instance_id):
    """The MAC in the instance id of an ESXi vmxnet3 adapter, '' when there is none"""
    tail = str(instance_id or '').rsplit('\\', 1)[-1].upper()
    m = _DSN_MAC.match(tail)
    if not m:
        return ''
    o2, o1, o0, b5, b4, b3 = m.groups()
    return norm_mac(o0 + o1 + o2 + b3 + b4 + b5)


def prefix_of(mask):
    """Prefix length of a dotted mask, None for a mask with holes"""
    if not _IPV4.match(str(mask or '')):
        return None
    bits = ''.join(f'{int(o):08b}' for o in mask.split('.'))
    if '01' in bits:
        return None
    return bits.count('1')


def mask_of(prefix):
    p = max(0, min(32, int(prefix)))
    n = (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF if p else 0
    return '.'.join(str((n >> s) & 0xFF) for s in (24, 16, 8, 0))


def host_ip(ip):
    """An address a Windows adapter can hold or reach: no 0.x, no loopback, no multicast or
    reserved range (Windows refuses them, and the first boot would retry at every boot)"""
    ip = str(ip or '')
    return bool(_IPV4.match(ip)) and int(ip.split('.')[0]) not in (0, 127) and int(ip.split('.')[0]) < 224


def _ips(values):
    out = []
    for v in values or []:
        for part in re.split(r'[\s,]+', str(v or '')):
            if host_ip(part) and part not in out:
                out.append(part)
    return out


# --------------------------------------------------------------------------- the hives

class Hive:
    """The few reads and writes needed of a hivex.Hivex, with names matched without case"""

    def __init__(self, h):
        self.h = h

    @classmethod
    def open(cls, path, write=False):
        import hivex
        return cls(hivex.Hivex(path, write=write))

    def root(self):
        return self.h.root()

    def child(self, node, *names):
        for name in names:
            if node is None:
                return None
            found = None
            for c in self.h.node_children(node) or []:
                if self.h.node_name(c).lower() == name.lower():
                    found = c
                    break
            node = found
        return node

    def children(self, node):
        return [(self.h.node_name(c), c) for c in (self.h.node_children(node) or [])] if node is not None else []

    def value(self, node, key):
        """str, int or [str] of a value, None when it is not there"""
        if node is None:
            return None
        for v in self.h.node_values(node) or []:
            if self.h.value_key(v).lower() != key.lower():
                continue
            t, raw = self.h.value_value(v)
            if t == REG_DWORD and len(raw) >= 4:
                return struct.unpack('<I', raw[:4])[0]
            if t in (REG_SZ, REG_EXPAND_SZ):
                return raw.decode('utf-16-le', 'replace').split('\x00', 1)[0]
            if t == REG_MULTI_SZ:
                return [s for s in raw.decode('utf-16-le', 'replace').split('\x00') if s]
            return None
        return None

    def raw(self, node, key):
        """(type, bytes) of a value of any type, None when it is not there"""
        if node is None:
            return None
        for v in self.h.node_values(node) or []:
            if self.h.value_key(v).lower() == key.lower():
                return self.h.value_value(v)
        return None

    def ensure(self, node, *names):
        for name in names:
            c = self.child(node, name)
            node = c if c is not None else self.h.node_add_child(node, name)
        return node

    def set(self, node, key, kind, value):
        if kind == REG_DWORD:
            raw = struct.pack('<I', int(value))
        else:
            raw = (str(value) + '\x00').encode('utf-16-le')
        self.h.node_set_value(node, {'key': key, 't': kind, 'value': raw})

    def commit(self):
        self.h.commit(None)


def control_sets(hv):
    """The control sets Select names (Default first), as the driver injection writes them (#823)"""
    root = hv.root()
    sel = hv.child(root, 'Select')
    names = []
    for key in ('Default', 'Current'):
        n = hv.value(sel, key)
        if isinstance(n, int) and 0 < n < 1000:
            name = f'ControlSet{n:03d}'
            if name not in names and hv.child(root, name) is not None:
                names.append(name)
    if not names and hv.child(root, 'ControlSet001') is not None:
        names = ['ControlSet001']
    return names


def device_dates(sys_hv, cs, instance):
    """(last arrival, last removal) of a device as FILETIME numbers, from the properties
    Windows 8 and later keep under its Enum key; 0 where there is none"""
    parts = str(instance or '').split('\\')
    node = sys_hv.child(cs, 'Enum', *parts) if len(parts) == 3 else None
    props = sys_hv.child(node, 'Properties', _DEV_DATES)
    out = []
    for pid in ('0066', '0067'):
        got = sys_hv.raw(sys_hv.child(props, pid), '')
        ok = got and (int(got[0]) & 0xFFFF) == 0x10 and len(got[1]) == 8
        out.append(struct.unpack('<Q', got[1])[0] if ok else 0)
    return out[0], out[1]


def read_adapters(sys_hv):
    """[{guid, name, desc, instance, mac, index, arrived, removed, ipv4, gateway, dns}] of every
    interface with a static IPv4 address on a PCI adapter, from the control set the next boot
    loads"""
    names = control_sets(sys_hv)
    if not names:
        return []
    cs = sys_hv.child(sys_hv.root(), names[0])
    ifaces = sys_hv.child(cs, 'Services', 'Tcpip', 'Parameters', 'Interfaces')
    net = sys_hv.child(cs, 'Control', 'Network', NET_CLASS)
    cls = sys_hv.child(cs, 'Control', 'Class', NET_CLASS)
    by_guid = {}
    for key, node in sys_hv.children(cls):
        if not key.isdigit():
            continue
        guid = str(sys_hv.value(node, 'NetCfgInstanceId') or '')
        if _GUID.match(guid):
            by_guid[guid.upper()] = (int(key), node)
    out = []
    for guid, node in sys_hv.children(ifaces):
        if not _GUID.match(guid):
            continue
        if sys_hv.value(node, 'EnableDHCP') == 1:
            continue
        addrs = sys_hv.value(node, 'IPAddress') or []
        masks = sys_hv.value(node, 'SubnetMask') or []
        addrs = [addrs] if isinstance(addrs, str) else addrs
        masks = [masks] if isinstance(masks, str) else masks
        ipv4 = []
        for i, ip in enumerate(addrs):
            mask = masks[i] if i < len(masks) else ''
            pre = prefix_of(mask)
            if host_ip(ip) and pre:
                ipv4.append({'ip': ip, 'prefix': pre, 'mask': mask_of(pre)})
        if not ipv4:
            continue
        conn = sys_hv.child(net, guid, 'Connection')
        instance = str(sys_hv.value(conn, 'PnPInstanceId') or '')
        if not instance.upper().startswith('PCI\\'):
            continue
        idx, cnode = by_guid.get(guid.upper(), (9999, None))
        mac = norm_mac(sys_hv.value(cnode, 'NetworkAddress')) or mac_from_instance(instance)
        gws = sys_hv.value(node, 'DefaultGateway') or []
        gws = [gws] if isinstance(gws, str) else gws
        metrics = sys_hv.value(node, 'DefaultGatewayMetric') or []
        metrics = [metrics] if isinstance(metrics, str) else metrics
        gateway = []
        for i, gw in enumerate(_ips(gws)):
            m = str(metrics[i]).strip() if i < len(metrics) else '0'
            gateway.append({'ip': gw, 'metric': int(m) if m.isdigit() and int(m) < 10000 else 0})
        dns = _ips([sys_hv.value(node, 'NameServer') or ''])
        arrived, removed = device_dates(sys_hv, cs, instance)
        out.append({'guid': guid.upper(), 'name': str(sys_hv.value(conn, 'Name') or '')[:120],
                    'desc': str(sys_hv.value(cnode, 'DriverDesc') or '')[:120], 'instance': instance,
                    'mac': mac, 'index': idx, 'arrived': arrived, 'removed': removed, 'ipv4': ipv4[:MAX_ADDRS],
                    'gateway': gateway[:MAX_ADDRS], 'dns': dns[:MAX_ADDRS]})
    out.sort(key=lambda a: (a['index'], a['guid']))
    return out[:MAX_NICS]


def is_esxi_nic(instance):
    """An ESXi network adapter: PCI vendor 15AD, or an emulated e1000 with that subsystem vendor"""
    up = str(instance or '').upper()
    return bool(_DEV.match(str(instance or ''))) and ('\\VEN_15AD&' in up or
                                                    re.search(r'&SUBSYS_[0-9A-F]{4}15AD&', up) is not None)


def old_devices(sys_hv):
    """Instance ids of the ESXi network adapters the guest had (vendor 15AD, or an emulated
    e1000 with that subsystem vendor): hidden devices once it runs on KVM"""
    names = control_sets(sys_hv)
    if not names:
        return []
    net = sys_hv.child(sys_hv.root(), names[0], 'Control', 'Network', NET_CLASS)
    out = []
    for guid, node in sys_hv.children(net):
        if not _GUID.match(guid):
            continue
        inst = str(sys_hv.value(sys_hv.child(node, 'Connection'), 'PnPInstanceId') or '')
        if is_esxi_nic(inst) and inst not in out:
            out.append(inst)
    return sorted(out)[:MAX_NICS]


def _program_folder(image_path):
    p = str(image_path or '').strip()
    if p.startswith('"'):
        end = p.find('"', 1)
        p = p[1:end] if end > 1 else ''
    else:
        i = p.lower().find('.exe')
        p = p[:i + 4] if i > 0 else p
    p = re.sub(r'^\\\?\?\\', '', p)
    return p.rsplit('\\', 1)[0].rstrip('\\') if '\\' in p else ''


def tools_uninstall_code(sys_hv, soft_hv):
    """The product code of the ESXi guest tools' uninstall entry, '' when there is none: the
    entry whose InstallLocation is the folder of the program the VMTools service runs"""
    names = control_sets(sys_hv)
    if not names:
        return ''
    svc = sys_hv.child(sys_hv.root(), names[0], 'Services', 'VMTools')
    folder = _program_folder(sys_hv.value(svc, 'ImagePath')).lower()
    if not folder:
        return ''
    for path in (('Microsoft', 'Windows', 'CurrentVersion', 'Uninstall'),
                 ('WOW6432Node', 'Microsoft', 'Windows', 'CurrentVersion', 'Uninstall')):
        for code, node in soft_hv.children(soft_hv.child(soft_hv.root(), *path)):
            loc = str(soft_hv.value(node, 'InstallLocation') or '').rstrip('\\').lower()
            if loc == folder and soft_hv.value(node, 'WindowsInstaller') == 1 and _GUID.match(code):
                return code.upper()
    return ''


def windows_version(soft_hv):
    cv = soft_hv.child(soft_hv.root(), 'Microsoft', 'Windows NT', 'CurrentVersion')
    build = str(soft_hv.value(cv, 'CurrentBuildNumber') or '')
    return {'build': int(build) if build.isdigit() else 0,
            'product': ' '.join(str(soft_hv.value(cv, 'ProductName') or '').split())[:120],
            'server': 'server' in str(soft_hv.value(cv, 'InstallationType') or '').lower()}


# --------------------------------------------------------------------------- the NICs

def parse_pairs(text):
    """[(source mac, target mac)] of '005056aabbcc=bc2411aabbcc,...', in the order of the
    target's netN; a side that is not known is ''"""
    out = []
    for part in str(text or '').split(','):
        if '=' not in part:
            continue
        src, tgt = part.split('=', 1)
        out.append((norm_mac(src), norm_mac(tgt)))
    return out[:MAX_NICS]


def match_nics(adapters, pairs):
    """The adapters that move, each with the MAC of its NIC on Proxmox (target_mac, '' when
    the first boot has to go by order), and the stale ones.

    An adapter whose MAC is one of the source's NICs is that NIC. When the source's MACs are
    known, a static adapter with another MAC belongs to hardware the guest no longer has
    (it is a hidden device on ESXi already) and stays as it is. Adapters without a MAC take
    the NICs left over, in the order Windows installed them.

    MK Nov 2026 - an emulated e1000 has no MAC in the registry, and the registry keeps the
    adapters of an earlier NIC swap. A device Windows saw go after it last came is gone; when
    more adapters without a MAC are left than NICs, those Windows saw arrive last (else
    installed last) are the ones the guest still has."""
    src = [s for s, _t in pairs if s]
    moved, stale, used, unknown = [], [], set(), []
    for a in adapters:
        a = dict(a)
        if a.get('mac') and src:
            if a['mac'] in src and a['mac'] not in used:
                a['target_mac'] = next((t for s, t in pairs if s == a['mac']), '')
                used.add(a['mac'])
                moved.append(a)
            else:
                stale.append(a)
            continue
        if int(a.get('removed') or 0) > int(a.get('arrived') or 0):
            stale.append(a)
            continue
        unknown.append(a)
    left = [t for s, t in pairs if not (s and s in used)]
    if pairs and len(unknown) > len(left):
        newest = sorted(unknown, key=lambda a: (-int(a.get('arrived') or 0), -int(a.get('index') or 0)))
        keep = {a['guid'] for a in newest[:len(left)]}
        stale += [a for a in unknown if a['guid'] not in keep]
        unknown = [a for a in unknown if a['guid'] in keep]
    for a in unknown:
        if left:
            a['target_mac'] = left.pop(0)
            moved.append(a)
        elif not pairs:
            a['target_mac'] = ''
            moved.append(a)
        else:
            stale.append(a)
    moved.sort(key=lambda a: (a['index'], a['guid']))
    return moved, stale


# --------------------------------------------------------------------------- the cmd data

def _check(cond, what):
    if not cond:
        raise ValueError(what)


def data_cmd(run, build, adapters, driver_msi='', agent_msi='', tools_code='', uninstall_tools=False,
             old_devs=()):
    """firstboot-data.cmd: set lines firstboot.cmd reads with `call`. Every value is checked,
    nothing here can carry a character cmd acts on (% ! " ^ & < > | outside the device ids,
    whose & is quoted). CRLF, as cmd wants it."""
    _check(_RUN.match(str(run)), 'the run id holds characters cmd would act on')
    _check(isinstance(build, int) and 0 <= build < 1000000, 'the build is no number')
    for f in (driver_msi, agent_msi):
        _check(not f or _FILE.match(f), 'a package name holds characters cmd would act on')
    _check(not tools_code or _GUID.match(tools_code), 'the product code is no GUID')
    lines = [f'rem PegaProx: data of the first boot on Proxmox VE (run {run})',
             f'set "KM_RUN={run}"', f'set "KM_BUILD={build}"',
             f'set "KM_DRIVER_MSI={driver_msi or ""}"', f'set "KM_AGENT_MSI={agent_msi or ""}"',
             f'set "KM_TOOLS_CODE={tools_code or ""}"',
             f'set "KM_TOOLS_UNINSTALL={1 if uninstall_tools and tools_code else 0}"',
             f'set "KM_REMOVE_DEVICES={1 if build >= REMOVE_DEVICE_BUILD else 0}"']
    devs = [d for d in (old_devs or []) if _DEV.match(str(d))][:MAX_NICS]
    lines.append(f'set "KM_OLDDEVS={len(devs)}"')
    lines += [f'set "KM_OLDDEV{k}={d}"' for k, d in enumerate(devs, 1)]
    nics = list(adapters or [])[:MAX_NICS]
    lines.append(f'set "KM_NICS={len(nics)}"')
    for n, a in enumerate(nics, 1):
        guid = str(a.get('guid') or '')
        _check(_GUID.match(guid), f'adapter {n}: no interface GUID')
        tgt, srcm = norm_mac(a.get('target_mac')), norm_mac(a.get('mac'))
        dev = str(a.get('instance') or '')
        if not _DEV.match(dev):
            dev = ''
        ips = [x for x in (a.get('ipv4') or []) if host_ip(x.get('ip')) and prefix_of(mask_of(x.get('prefix', 0)))]
        _check(ips, f'adapter {n}: no IPv4 address')
        gws = [g for g in (a.get('gateway') or []) if host_ip(g.get('ip'))]
        dns = [d for d in (a.get('dns') or []) if host_ip(d)]
        p = f'KM_NIC{n}_'
        lines += [f'set "{p}GUID={guid}"', f'set "{p}MAC={tgt}"', f'set "{p}SRCMAC={srcm}"',
                  f'set "{p}DEV={dev}"', f'set "{p}IPS={len(ips[:MAX_ADDRS])}"']
        for k, x in enumerate(ips[:MAX_ADDRS], 1):
            lines += [f'set "{p}IP{k}={x["ip"]}"', f'set "{p}MASK{k}={mask_of(x["prefix"])}"']
        lines.append(f'set "{p}GWS={len(gws[:MAX_ADDRS])}"')
        for k, g in enumerate(gws[:MAX_ADDRS], 1):
            metric = int(g.get('metric') or 0)
            lines += [f'set "{p}GW{k}={g["ip"]}"', f'set "{p}GWM{k}={metric if 0 < metric < 10000 else 0}"']
        lines.append(f'set "{p}DNS={" ".join(dns[:MAX_ADDRS])}"')
    text = '\r\n'.join(lines) + '\r\n'
    for ch in '%!^<>|':
        _check(ch not in text, f'the data holds {ch!r}')
    return text.encode('ascii')


# --------------------------------------------------------------------------- the folder

def _sid(auth, subs):
    return struct.pack('<BB', 1, len(subs)) + struct.pack('>Q', auth)[2:] + b''.join(struct.pack('<I', s) for s in subs)


def security_descriptor(folder=True):
    """A self-relative security descriptor: owner Administrators, DACL protected with full
    access for SYSTEM and Administrators only (inherited by what is created inside)"""
    owner, group = _sid(*SID_ADMINS), _sid(*SID_SYSTEM)
    flags = 0x03 if folder else 0x00     # OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    aces = b''
    for sid in (_sid(*SID_SYSTEM), _sid(*SID_ADMINS)):
        aces += struct.pack('<BBHI', 0, flags, 8 + len(sid), FILE_ALL_ACCESS) + sid
    acl = struct.pack('<BBHHH', 2, 0, 8 + len(aces), 2, 0) + aces
    # SE_SELF_RELATIVE | SE_DACL_PROTECTED | SE_DACL_PRESENT
    off_owner = 20
    off_group = off_owner + len(owner)
    off_dacl = off_group + len(group)
    head = struct.pack('<BBHIIII', 1, 0, 0x9004, off_owner, off_group, 0, off_dacl)
    return head + owner + group + acl


def lock(path, folder):
    """The descriptor on a file of the ntfs-3g mount (its system.ntfs_acl attribute), on the
    entry itself, never on what a link points to"""
    os.setxattr(path, 'system.ntfs_acl', security_descriptor(folder), follow_symlinks=False)


def _sid_at(sd, off):
    if off < 20 or off + 8 > len(sd):
        raise ValueError('no SID there')
    rev, count = sd[off], sd[off + 1]
    if off + 8 + 4 * count > len(sd):
        raise ValueError('the SID runs past the descriptor')
    auth = int.from_bytes(sd[off + 2:off + 8], 'big')
    subs = struct.unpack_from('<%dI' % count, sd, off + 8)
    return 'S-%d-%d' % (rev, auth) + ''.join('-%d' % s for s in subs)


def trusted_descriptor(sd):
    """True when only SYSTEM and the Administrators can change what carries this self-relative
    descriptor: one of them owns it, it has a DACL, and no other trustee is allowed more than
    reading. Deny entries only take rights away; any other kind of entry is not trusted."""
    try:
        sd = bytes(sd or b'')
        rev, _sbz, control, o_owner, _o_group, _o_sacl, o_dacl = struct.unpack_from('<BBHIIII', sd, 0)
        if rev != 1 or not control & 0x8000 or _sid_at(sd, o_owner) not in _PRIVILEGED:
            return False
        if not control & 0x0004 or not o_dacl:
            return False        # no DACL: everybody may do anything
        _rev, _z, _size, count, _z2 = struct.unpack_from('<BBHHH', sd, o_dacl)
        at = o_dacl + 8
        for _ in range(count):
            typ, _flags, size = struct.unpack_from('<BBH', sd, at)
            if size < 8:
                return False
            if typ == 0:
                mask = struct.unpack_from('<I', sd, at + 4)[0]
                if mask & WRITE_BITS and _sid_at(sd, at + 8) not in _PRIVILEGED:
                    return False
            elif typ not in (1, 6, 10, 12):
                return False
            at += size
        return True
    except (struct.error, ValueError, IndexError):
        return False


def _is_reparse(path):
    try:
        return bool(os.getxattr(path, 'system.ntfs_reparse_data', follow_symlinks=False))
    except OSError:
        return False


def plain_and_trusted(path, folder):
    """A plain folder or file of the mount (no link, no junction, no other reparse point) that
    only SYSTEM and the Administrators can change"""
    if os.path.islink(path) or _is_reparse(path):
        return False
    if not (os.path.isdir(path) if folder else os.path.isfile(path)):
        return False
    try:
        sd = os.getxattr(path, 'system.ntfs_acl', follow_symlinks=False)
    except OSError:
        return False
    return trusted_descriptor(sd)


def _ci_dir(parent, name):
    try:
        for e in os.listdir(parent):
            if e.lower() == name.lower() and os.path.isdir(os.path.join(parent, e)):
                return os.path.join(parent, e)
    except OSError:
        pass
    return os.path.join(parent, name)


def prepare_work_dir(root, run):
    """(path, kept, [names moved aside]) of <ProgramData>\\KVMMigration for this run. A plain
    folder only SYSTEM and the Administrators can change (the in-guest preparation makes it so)
    is kept. Anything else of that name, in any case (ntfs-3g tells them apart, Windows does
    not), is renamed, a link as the link, and a new folder is made and locked before anything
    goes into it."""
    pd = _ci_dir(root, 'ProgramData')
    if os.path.islink(pd) or _is_reparse(pd) or not os.path.isdir(pd):
        raise ValueError('ProgramData of the guest is no plain folder')
    found = [os.path.join(pd, e) for e in sorted(os.listdir(pd)) if e.lower() == WORK_DIR.lower()]
    if len(found) == 1 and plain_and_trusted(found[0], True):
        lock(found[0], True)
        return found[0], True, []
    aside = []
    for path in found:
        for n in range(100):
            dst = os.path.join(pd, '%s.untrusted-%s%s' % (WORK_DIR, run, '-%d' % n if n else ''))
            if not os.path.lexists(dst):
                break
        else:
            raise ValueError('no free name to move %s aside' % os.path.basename(path))
        os.rename(path, dst)
        aside.append(os.path.basename(dst))
    work = os.path.join(pd, WORK_DIR)
    os.mkdir(work, 0o700)
    lock(work, True)
    return work, False, aside


def put_file(work, name, body=None, src=None):
    """A new file in the work folder, never through a link, locked once written. An entry of
    that name goes first; a folder of that name stops the staging."""
    _check(_FILE.match(name), 'a file name holds characters cmd would act on')
    path = os.path.join(work, name)
    if os.path.lexists(path):
        if os.path.isdir(path) and not os.path.islink(path):
            raise ValueError('%s is a folder' % name)
        os.unlink(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as fh:
            if src is None:
                fh.write(body)
            else:
                with open(src, 'rb') as inp:
                    while True:
                        chunk = inp.read(1 << 20)
                        if not chunk:
                            break
                        fh.write(chunk)
        lock(path, False)
    except Exception:
        os.unlink(path)
        raise
    return path


# --------------------------------------------------------------------------- the service

def service_command():
    """ImagePath of PegaProxFirstBoot. The service process is a cmd that starts the script in
    a cmd of its own and ends: the service manager ends a service process that does not talk
    to it within 30 seconds, and the script runs much longer (installers, the network)."""
    return ('%SystemRoot%\\System32\\cmd.exe /d /c start "PegaProxFirstBoot" /b '
            '%SystemRoot%\\System32\\cmd.exe /d /c '
            f'%SystemDrive%\\ProgramData\\{WORK_DIR}\\firstboot.cmd kvm')


def register_service(sys_hv):
    """The one-shot SYSTEM service in each control set Select names; firstboot.cmd deletes it"""
    names = control_sets(sys_hv)
    for name in names:
        svc = sys_hv.ensure(sys_hv.child(sys_hv.root(), name), 'Services', SERVICE)
        sys_hv.set(svc, 'DisplayName', REG_SZ, 'PegaProx first boot on Proxmox VE')
        sys_hv.set(svc, 'Type', REG_DWORD, 0x10)
        sys_hv.set(svc, 'Start', REG_DWORD, 2)
        sys_hv.set(svc, 'ErrorControl', REG_DWORD, 0)
        sys_hv.set(svc, 'ImagePath', REG_EXPAND_SZ, service_command())
        sys_hv.set(svc, 'ObjectName', REG_SZ, 'LocalSystem')
    return names


# Windows Server keeps a disk it sees for the first time offline and read-only (SAN policy
# OfflineShared, the default of the server editions); on Proxmox VE every data disk sits on a
# new controller. 1 = OnlineAll, the default of the client editions
SAN_ONLINE_ALL = 1
SAN_POLICIES = {1: 'OnlineAll', 2: 'OfflineShared', 3: 'OfflineAll', 4: 'OfflineInternal'}


def san_online(sys_hv):
    """SanPolicy OnlineAll in each control set Select names. Returns the value it had in the
    first one, None where none was set (then the edition's default applied).

    MK Nov 2026 - seen on Server 2025: the data disk came up offline and read-only after the
    migration, its drive letter gone. Left at OnlineAll: a first boot that falls back to SATA
    moves the data disks again, and they would be new disks once more."""
    old = None
    for i, name in enumerate(control_sets(sys_hv)):
        par = sys_hv.ensure(sys_hv.child(sys_hv.root(), name), 'Services', 'partmgr', 'Parameters')
        if i == 0:
            old = sys_hv.value(par, 'SanPolicy')
        sys_hv.set(par, 'SanPolicy', REG_DWORD, SAN_ONLINE_ALL)
    return old


# --------------------------------------------------------------------------- on the node

def _guest_netconfig(path, run, released=False):
    """The adapters the in-guest preparation saved (their IPv4 is released in the copy already):
    of this run, or of a run by hand (run 'manual') whose stage 2 left released.flag. None when
    there is no such file."""
    try:
        with open(path, 'rb') as fh:
            j = json.loads(fh.read().decode('utf-8-sig'))
    except (OSError, ValueError):
        return None
    if not isinstance(j, dict) or j.get('source') != 'guest':
        return None
    if j.get('run') != run and not (j.get('run') == 'manual' and released):
        return None
    out = []
    for a in j.get('adapters') or []:
        if not isinstance(a, dict) or a.get('dhcp'):
            continue
        guid = str(a.get('setting_id') or a.get('guid') or '')
        ipv4 = [{'ip': x.get('ip'), 'prefix': int(x.get('prefix') or 0), 'mask': mask_of(int(x.get('prefix') or 0))}
                for x in (a.get('ipv4') or []) if isinstance(x, dict) and host_ip(x.get('ip'))
                and 0 < int(x.get('prefix') or 0) <= 32]
        if not (_GUID.match(guid) and ipv4):
            continue
        out.append({'guid': guid.upper(), 'name': '', 'desc': '', 'instance': str(a.get('instance') or ''),
                    'mac': norm_mac(a.get('mac')), 'index': int(a.get('index') or 0), 'ipv4': ipv4,
                    'gateway': [{'ip': g.get('ip'), 'metric': int(g.get('metric') or 0)}
                                for g in (a.get('gateway') or []) if isinstance(g, dict) and host_ip(g.get('ip'))],
                    'dns': _ips(a.get('dns') or [])})
    return out


def stage(root, windows, run, firstboot, pairs, driver_msi='', agent_msi='', uninstall_tools=False):
    """Everything of the first boot onto the mounted volume. driver_msi / agent_msi: the
    packages on the mounted ISO, copied into the work folder. Returns the summary PegaProx
    logs. Raises before the service is registered when any file could not be locked."""
    _check(_RUN.match(str(run)), 'the run id holds characters cmd would act on')
    packages = []
    for src in (driver_msi, agent_msi):
        if src:
            _check(os.path.isfile(src), 'a package is not on the ISO')
            packages.append((os.path.basename(src), src))
    cfg = _ci_dir(_ci_dir(windows, 'System32'), 'config')
    sys_path, soft_path = os.path.join(cfg, 'SYSTEM'), os.path.join(cfg, 'SOFTWARE')
    soft = Hive.open(soft_path)
    ver = windows_version(soft)
    sys_ro = Hive.open(sys_path)
    from_hive = read_adapters(sys_ro)
    work, kept, aside = prepare_work_dir(root, run)
    from_guest = None
    if kept:
        # only what SYSTEM or the Administrators wrote; a run by hand counts only when the
        # copied registry has no static address left
        nc, flag = os.path.join(work, 'netconfig.json'), os.path.join(work, 'released.flag')
        if plain_and_trusted(nc, False):
            from_guest = _guest_netconfig(nc, run, released=not from_hive and plain_and_trusted(flag, False))
        for name in STALE_STATE:
            p = os.path.join(work, name)
            if os.path.lexists(p) and not (os.path.isdir(p) and not os.path.islink(p)):
                os.unlink(p)
    adapters = from_guest if from_guest is not None else from_hive
    code = tools_uninstall_code(sys_ro, soft)
    devs = old_devices(sys_ro)
    moved, stale = match_nics(adapters, pairs)
    names = [n for n, _s in packages]
    data = data_cmd(run, ver['build'], moved, os.path.basename(driver_msi or ''), os.path.basename(agent_msi or ''),
                    code, uninstall_tools, devs)
    netconfig = {'version': 1, 'source': 'guest' if from_guest is not None else 'offline', 'run': run,
                 'build': ver['build'], 'product': ver['product'], 'adapters': moved, 'stale': stale}
    written = []
    try:
        for name, src in packages:
            written.append(put_file(work, name, src=src))
        for name, body in (('firstboot.cmd', firstboot), ('firstboot-data.cmd', data),
                           ('netconfig.json', json.dumps(netconfig, indent=1).encode('utf-8'))):
            written.append(put_file(work, name, body=body))
    except Exception:
        # nothing half locked stays behind for a first boot task to run
        for p in written:
            try:
                os.unlink(p)
            except OSError:
                pass
        raise
    sys_rw = Hive.open(sys_path, write=True)
    sets = register_service(sys_rw)
    san_was = san_online(sys_rw)
    sys_rw.commit()
    return {'build': ver['build'], 'product': ver['product'], 'server': ver['server'],
            'source': netconfig['source'], 'tools_code': bool(code), 'locked': True, 'service': sets,
            'kept': kept, 'moved_aside': aside, 'msis': names,
            'adapters': [{'mac': a['mac'], 'target_mac': a.get('target_mac') or '',
                          'ipv4': [f"{x['ip']}/{x['prefix']}" for x in a['ipv4']],
                          'gateway': [g['ip'] for g in a['gateway']], 'desc': a['desc']} for a in moved],
            'stale': len(stale), 'old_devices': len(devs), 'files': [os.path.basename(p) for p in written],
            'san_policy': san_was}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--windows', required=True)
    ap.add_argument('--run', required=True)
    ap.add_argument('--firstboot', required=True, help='file with firstboot.cmd in base64')
    ap.add_argument('--nics', default='')
    ap.add_argument('--driver-msi', default='', help='the driver package on the mounted ISO')
    ap.add_argument('--agent-msi', default='', help='the guest agent package on the mounted ISO')
    ap.add_argument('--uninstall-tools', default='0')
    a = ap.parse_args(argv)
    try:
        with open(a.firstboot, 'rb') as fh:
            firstboot = base64.b64decode(fh.read(), validate=False)
        summary = stage(a.root, a.windows, a.run, firstboot, parse_pairs(a.nics), a.driver_msi, a.agent_msi,
                        a.uninstall_tools == '1')
    except Exception as e:
        print(f'WINPREP_FAILED {type(e).__name__}: {" ".join(str(e).split())[:300]}')
        return 1
    for name in summary['msis']:
        print('MSI_STAGED ' + name)
    print('WINPREP ' + json.dumps(summary, separators=(',', ':')))
    print('WINPREP_OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
