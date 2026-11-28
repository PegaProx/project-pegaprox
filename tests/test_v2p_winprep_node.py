"""The node's half of the offline Windows preparation (core/v2p_winprep_node.py).

MK Nov 2026 - a Windows guest from ESXi is prepared without any login: on the target node, after
the copy, the helper reads the static IPv4 configuration out of the copied SYSTEM hive, finds the
uninstall entry of the ESXi guest tools through the VMTools service, writes netconfig.json,
firstboot.cmd and its data into <ProgramData>\\KVMMigration and registers the first boot service.

The hives are a fake of the python3-hivex API (the calls the helper makes, nothing more), so the
tests run without hivex. The helper is also checked for what lets it run on a Proxmox node at
all: standard library only, Python 3.7 syntax.
"""
import ast
import base64
import json
import os
import pathlib
import struct
import sys
import types

import pytest

from pegaprox.core import v2p_winprep_node as nh

SRC = pathlib.Path(nh.__file__).read_text(encoding='utf-8')
NET = nh.NET_CLASS
GUID_A = '{11111111-2222-3333-4444-555555555555}'
GUID_B = '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'
GUID_DHCP = '{99999999-8888-7777-6666-555555555555}'
DEV_A = r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF565000B5D2BAFE00'   # MAC 00:50:56:ba:d2:b5
DEV_B = r'PCI\VEN_8086&DEV_100F&SUBSYS_075015AD&REV_01\4&1A2B3C&0&0888'     # e1000, no serial


# --------------------------------------------------------------------------- a fake hivex

class _Node:
    def __init__(self, name):
        self.name, self.children, self.values = name, [], []


class FakeHivex:
    """python3-hivex as the helper uses it: nodes and (key, type, bytes) values"""
    commits = []

    def __init__(self, tree, write=False):
        self._root = tree
        self.write = write

    def root(self):
        return self._root

    def node_children(self, n):
        return list(n.children)

    def node_name(self, n):
        return n.name

    def node_values(self, n):
        return list(n.values)

    def value_key(self, v):
        return v[0]

    def value_value(self, v):
        return v[1], v[2]

    def node_add_child(self, parent, name):
        assert self.write, 'a write to a hive opened read-only'
        c = _Node(name)
        parent.children.append(c)
        return c

    def node_set_value(self, node, val):
        assert self.write, 'a write to a hive opened read-only'
        node.values = [v for v in node.values if v[0].lower() != val['key'].lower()]
        node.values.append((val['key'], val['t'], val['value']))

    def commit(self, _path):
        FakeHivex.commits.append(self)


def _val(key, v):
    if isinstance(v, bool):
        raise TypeError
    if isinstance(v, tuple) and v[0] == 'filetime':
        return (key, 0xFFFF0010, struct.pack('<Q', v[1]))
    if isinstance(v, int):
        return (key, nh.REG_DWORD, struct.pack('<I', v))
    if isinstance(v, tuple) and v[0] == 'expand':
        return (key, nh.REG_EXPAND_SZ, (v[1] + '\x00').encode('utf-16-le'))
    if isinstance(v, list):
        return (key, nh.REG_MULTI_SZ, ('\x00'.join(v) + '\x00\x00').encode('utf-16-le'))
    return (key, nh.REG_SZ, (str(v) + '\x00').encode('utf-16-le'))


def build(spec, name=''):
    """{'Sub': {...}, '@Value': 1} -> a node tree"""
    n = _Node(name)
    for k, v in spec.items():
        if k.startswith('@'):
            n.values.append(_val(k[1:], v))
        else:
            n.children.append(build(v, k))
    return n


def system_spec(ifaces=None, adapters=None, select=1, vmtools=r'"C:\Program Files\ESXiTools\vmtoolsd.exe"', dates=None):
    """A SYSTEM hive: Select, the control set with Tcpip interfaces, Network connections,
    the net Class keys, and the VMTools service. dates: {instance: (last arrival, last
    removal)} as the device properties under Enum hold them"""
    ifaces = ifaces if ifaces is not None else {
        GUID_A: {'@EnableDHCP': 0, '@IPAddress': ['10.0.0.5', '10.0.0.6'], '@SubnetMask': ['255.255.255.0', '255.255.0.0'],
                 '@DefaultGateway': ['10.0.0.1'], '@DefaultGatewayMetric': ['0'], '@NameServer': '10.0.0.2,10.0.0.3'},
        GUID_B: {'@EnableDHCP': 0, '@IPAddress': ['192.168.7.9'], '@SubnetMask': ['255.255.255.128'],
                 '@DefaultGateway': [], '@NameServer': ''},
        GUID_DHCP: {'@EnableDHCP': 1, '@IPAddress': ['0.0.0.0'], '@SubnetMask': ['0.0.0.0']},
    }
    adapters = adapters if adapters is not None else {
        GUID_A: (DEV_A, '0007', 'vmxnet3 Ethernet Adapter', None),
        GUID_B: (DEV_B, '0011', 'Intel(R) PRO/1000 MT Network Connection', None),
        GUID_DHCP: (r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF565000AABBCCFE00', '0003', 'vmxnet3 #2', None),
    }
    cs = {'Services': {'Tcpip': {'Parameters': {'Interfaces': ifaces}}},
          'Control': {'Network': {NET: {}}, 'Class': {NET: {}}}}
    if vmtools:
        cs['Services']['VMTools'] = {'@ImagePath': ('expand', vmtools)}
    for guid, (inst, idx, desc, addr) in adapters.items():
        cs['Control']['Network'][NET][guid] = {'Connection': {'@Name': f'Ethernet {idx}', '@PnPInstanceId': inst}}
        ck = {'@NetCfgInstanceId': guid, '@DriverDesc': desc}
        if addr:
            ck['@NetworkAddress'] = addr
        cs['Control']['Class'][NET][idx] = ck
    for inst, (arrived, removed) in (dates or {}).items():
        enum, hw, iid = inst.split('\\')
        props = {}
        if arrived:
            props['0066'] = {'@': ('filetime', arrived)}
        if removed:
            props['0067'] = {'@': ('filetime', removed)}
        node = cs.setdefault('Enum', {}).setdefault(enum, {}).setdefault(hw, {})
        node[iid] = {'Properties': {'{83da6326-97a6-4088-9453-a1923f573b29}': props}}
    return {'Select': {'@Default': select, '@Current': select}, f'ControlSet{select:03d}': cs}


def software_spec(build=20348, server=True, tools_loc=r'C:\Program Files\ESXiTools' + '\\', code='{ABCDEF01-2345-6789-ABCD-EF0123456789}',
                  wow=False):
    entry = {code: {'@DisplayName': 'Guest tools', '@InstallLocation': tools_loc, '@WindowsInstaller': 1}}
    other = {'{00000000-1111-2222-3333-444444444444}': {'@InstallLocation': r'C:\Program Files\Other', '@WindowsInstaller': 1}}
    unin = dict(other, **({} if wow else entry))
    spec = {'Microsoft': {'Windows NT': {'CurrentVersion': {'@CurrentBuildNumber': str(build), '@ProductName': 'Windows Server 2022 Standard',
                                                             '@InstallationType': 'Server' if server else 'Client'}},
                          'Windows': {'CurrentVersion': {'Uninstall': unin}}}}
    if wow:
        spec['WOW6432Node'] = {'Microsoft': {'Windows': {'CurrentVersion': {'Uninstall': entry}}}}
    return spec


def hv(spec, write=False):
    return nh.Hive(FakeHivex(build(spec), write=write))


# --------------------------------------------------------------------------- it runs on a node

def test_the_helper_needs_nothing_but_the_standard_library_and_hivex():
    tree = ast.parse(SRC)
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split('.')[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods.add((n.module or '').split('.')[0])
    allowed = {'base64', 'json', 'os', 're', 'struct', 'sys', 'argparse', 'hivex'}
    assert mods <= allowed, mods - allowed
    assert 'pegaprox' not in SRC.split('"""', 2)[2], 'the node has nothing of PegaProx'


def test_the_helper_is_python_3_7_syntax():
    # PVE 7 runs Debian 11 (3.9), and the node helper must not need more than that
    ast.parse(SRC, feature_version=(3, 7))


# --------------------------------------------------------------------------- values

@pytest.mark.parametrize('inst,mac', [
    (DEV_A, '005056bad2b5'),
    (r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF290C00AABBCCFE00', '000c29ccbbaa'),
    (DEV_B, ''),
    (r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF565001B5D2BAFE00', ''),   # multicast bit: no MAC
    ('', ''),
])
def test_the_mac_of_an_esxi_adapter_comes_from_its_device_serial(inst, mac):
    assert nh.mac_from_instance(inst) == mac


@pytest.mark.parametrize('mask,prefix', [('255.255.255.0', 24), ('255.255.0.0', 16), ('255.255.255.128', 25),
                                         ('255.0.255.0', None), ('nope', None), ('0.0.0.0', 0)])
def test_a_mask_with_holes_has_no_prefix(mask, prefix):
    assert nh.prefix_of(mask) == prefix
    if prefix:
        assert nh.mask_of(prefix) == mask


# --------------------------------------------------------------------------- reading the copy

def test_the_static_adapters_are_read_with_their_device_and_mac_and_dhcp_is_left_out():
    got = nh.read_adapters(hv(system_spec()))
    assert [a['guid'] for a in got] == [GUID_A, GUID_B]     # by class index 0007, 0011; DHCP gone
    a, b = got
    assert a['ipv4'] == [{'ip': '10.0.0.5', 'prefix': 24, 'mask': '255.255.255.0'},
                         {'ip': '10.0.0.6', 'prefix': 16, 'mask': '255.255.0.0'}]
    assert a['gateway'] == [{'ip': '10.0.0.1', 'metric': 0}] and a['dns'] == ['10.0.0.2', '10.0.0.3']
    assert a['mac'] == '005056bad2b5' and a['instance'] == DEV_A and a['desc'] == 'vmxnet3 Ethernet Adapter'
    assert b['mac'] == '' and b['gateway'] == [] and b['dns'] == []


def test_a_mac_set_on_the_adapter_wins_over_the_serial():
    spec = system_spec(adapters={GUID_A: (DEV_A, '0007', 'vmxnet3', '00-50-56-01-02-03'),
                                 GUID_B: (DEV_B, '0011', 'e1000', None),
                                 GUID_DHCP: (DEV_A, '0003', 'x', None)})
    assert nh.read_adapters(hv(spec))[0]['mac'] == '005056010203'


def test_the_control_set_select_names_is_read_not_a_fixed_one():
    spec = system_spec(select=2)
    spec['ControlSet001'] = {'Services': {'Tcpip': {'Parameters': {'Interfaces': {}}}}}
    assert [a['guid'] for a in nh.read_adapters(hv(spec))] == [GUID_A, GUID_B]


def test_an_interface_of_no_pci_adapter_is_left_out():
    spec = system_spec(adapters={GUID_A: (r'ROOT\VMS_MP\0001', '0007', 'virtual', None),
                                 GUID_B: (DEV_B, '0011', 'e1000', None), GUID_DHCP: (DEV_A, '3', 'x', None)})
    assert [a['guid'] for a in nh.read_adapters(hv(spec))] == [GUID_B]


def test_the_tools_uninstall_entry_is_found_through_the_service_folder():
    assert nh.tools_uninstall_code(hv(system_spec()), hv(software_spec())) == '{ABCDEF01-2345-6789-ABCD-EF0123456789}'
    assert nh.tools_uninstall_code(hv(system_spec()), hv(software_spec(wow=True))) == '{ABCDEF01-2345-6789-ABCD-EF0123456789}'
    # another folder, no service, or no MSI: nothing to uninstall
    assert nh.tools_uninstall_code(hv(system_spec()), hv(software_spec(tools_loc=r'C:\Elsewhere'))) == ''
    assert nh.tools_uninstall_code(hv(system_spec(vmtools=None)), hv(software_spec())) == ''
    sw = software_spec()
    sw['Microsoft']['Windows']['CurrentVersion']['Uninstall']['{ABCDEF01-2345-6789-ABCD-EF0123456789}']['@WindowsInstaller'] = 0
    assert nh.tools_uninstall_code(hv(system_spec()), hv(sw)) == ''


def test_the_lookup_never_names_the_product():
    body = SRC.split('def tools_uninstall_code', 1)[1].split('\ndef ', 1)[0]
    assert 'DisplayName' not in body and 'InstallLocation' in body and 'VMTools' in body


def test_the_old_esxi_network_devices_are_listed_and_nothing_else():
    spec = system_spec(adapters={GUID_A: (DEV_A, '0007', 'a', None), GUID_B: (DEV_B, '0011', 'b', None),
                                 GUID_DHCP: (r'PCI\VEN_1AF4&DEV_1000&SUBSYS_00011AF4&REV_00\3&1&0&18', '0003', 'virtio', None)})
    assert nh.old_devices(hv(spec)) == sorted([DEV_A, DEV_B])


# --------------------------------------------------------------------------- which NIC gets what

ADAPTERS = [
    {'guid': GUID_A, 'mac': '005056bad2b5', 'index': 7, 'instance': DEV_A, 'ipv4': [{'ip': '10.0.0.5', 'prefix': 24}],
     'gateway': [], 'dns': [], 'desc': ''},
    {'guid': GUID_B, 'mac': '', 'index': 11, 'instance': DEV_B, 'ipv4': [{'ip': '192.168.7.9', 'prefix': 25}],
     'gateway': [], 'dns': [], 'desc': ''},
]


def test_an_adapter_with_a_known_mac_gets_its_nic_and_the_others_the_nics_left_in_order():
    pairs = nh.parse_pairs('aaaaaaaaaaaa=bc2411000001,005056bad2b5=bc2411000002')
    moved, stale = nh.match_nics(ADAPTERS, pairs)
    assert [(a['guid'], a['target_mac']) for a in moved] == [(GUID_A, 'bc2411000002'), (GUID_B, 'bc2411000001')]
    assert stale == []


def test_a_static_adapter_of_hardware_the_guest_no_longer_has_stays_as_it_is():
    old = dict(ADAPTERS[0], guid='{12345678-1234-1234-1234-123456789012}', mac='005056999999', index=2)
    moved, stale = nh.match_nics([old] + ADAPTERS, nh.parse_pairs('005056bad2b5=bc2411000002'))
    assert [a['guid'] for a in moved] == [GUID_A] and [a['guid'] for a in stale] == [old['guid'], GUID_B]


def test_without_known_macs_every_adapter_moves_and_the_guest_goes_by_order():
    moved, stale = nh.match_nics(ADAPTERS, [])
    assert [a['target_mac'] for a in moved] == ['', ''] and stale == []


# --------------------------------------------------------------------------- firstboot-data.cmd

def _sets(data):
    out = {}
    for line in data.decode('ascii').split('\r\n'):
        if line.startswith('set "'):
            k, v = line[5:-1].split('=', 1)
            out[k] = v
    return out


def test_the_data_is_set_lines_with_crlf_and_every_value_the_script_reads():
    moved, _ = nh.match_nics([dict(ADAPTERS[0], gateway=[{'ip': '10.0.0.1', 'metric': 25}, {'ip': '10.0.0.254', 'metric': 0}],
                                   dns=['10.0.0.2', '10.0.0.3'], ipv4=[{'ip': '10.0.0.5', 'prefix': 24}, {'ip': '10.0.0.6', 'prefix': 16}])],
                             nh.parse_pairs('005056bad2b5=bc2411000002'))
    data = nh.data_cmd('t1abc', 20348, moved, 'virtio-win-gt-x64.msi', 'qemu-ga-x86_64.msi',
                       '{ABCDEF01-2345-6789-ABCD-EF0123456789}', True, [DEV_A])
    assert data.endswith(b'\r\n') and b'\n' not in data.replace(b'\r\n', b'')
    s = _sets(data)
    assert s['KM_RUN'] == 't1abc' and s['KM_BUILD'] == '20348' and s['KM_NICS'] == '1'
    assert s['KM_REMOVE_DEVICES'] == '1' and s['KM_TOOLS_UNINSTALL'] == '1' and s['KM_OLDDEVS'] == '1'
    assert s['KM_OLDDEV1'] == DEV_A
    assert (s['KM_NIC1_GUID'], s['KM_NIC1_MAC'], s['KM_NIC1_SRCMAC']) == (GUID_A, 'bc2411000002', '005056bad2b5')
    assert (s['KM_NIC1_IPS'], s['KM_NIC1_IP1'], s['KM_NIC1_MASK1'], s['KM_NIC1_IP2'], s['KM_NIC1_MASK2']) == \
        ('2', '10.0.0.5', '255.255.255.0', '10.0.0.6', '255.255.0.0')
    assert (s['KM_NIC1_GWS'], s['KM_NIC1_GW1'], s['KM_NIC1_GWM1'], s['KM_NIC1_GWM2']) == ('2', '10.0.0.1', '25', '0')
    assert s['KM_NIC1_DNS'] == '10.0.0.2 10.0.0.3'


def test_old_windows_removes_no_devices_and_without_a_code_no_tools_uninstall():
    s = _sets(nh.data_cmd('r1', 17763, [], tools_code='', uninstall_tools=True))
    assert s['KM_REMOVE_DEVICES'] == '0' and s['KM_TOOLS_UNINSTALL'] == '0' and s['KM_NICS'] == '0'


@pytest.mark.parametrize('field,bad', [
    ('run', 'r1&calc'), ('run', 'r1%PATH%'), ('driver_msi', 'x".msi'), ('tools_code', '{x} & del'),
])
def test_a_value_cmd_would_act_on_never_reaches_the_data(field, bad):
    kw = {'run': 'r1', 'build': 20348, 'adapters': []}
    kw[field] = bad
    with pytest.raises(ValueError):
        nh.data_cmd(**kw)


def test_an_adapter_value_that_is_no_address_is_dropped_or_refused():
    a = dict(ADAPTERS[0], guid='{bad&guid}')
    with pytest.raises(ValueError):
        nh.data_cmd('r1', 20348, [a])
    a = dict(ADAPTERS[0], instance=r'PCI\VEN_15AD&DEV_07B0\x" & calc', dns=['1.1.1.1 & calc', '8.8.8.8'],
             gateway=[{'ip': '10.0.0.1|x', 'metric': 1}])
    s = _sets(nh.data_cmd('r1', 20348, [a], old_devs=[r'PCI\VEN_15AD&DEV_07B0\a"b']))
    assert s['KM_NIC1_DEV'] == '' and s['KM_NIC1_DNS'] == '8.8.8.8' and s['KM_NIC1_GWS'] == '0' and s['KM_OLDDEVS'] == '0'


# --------------------------------------------------------------------------- the service and the folder

def test_the_service_starts_the_script_detached_in_every_control_set():
    spec = system_spec()
    spec['Select']['@Current'] = 1
    spec['Select']['@Default'] = 1
    h = hv(spec, write=True)
    assert nh.register_service(h) == ['ControlSet001']
    svc = h.child(h.root(), 'ControlSet001', 'Services', nh.SERVICE)
    img = h.value(svc, 'ImagePath')
    assert h.value(svc, 'Start') == 2 and h.value(svc, 'Type') == 0x10 and h.value(svc, 'ObjectName') == 'LocalSystem'
    # the service process ends at once: the service manager would end a long one after 30 s
    assert img.startswith(r'%SystemRoot%\System32\cmd.exe /d /c start ')
    assert img.endswith(r'%SystemDrive%\ProgramData\KVMMigration\firstboot.cmd kvm')
    assert [v for v in svc.values if v[0] == 'ImagePath'][0][1] == nh.REG_EXPAND_SZ


def _sid_str(b, off):
    rev, count = b[off], b[off + 1]
    auth = int.from_bytes(b[off + 2:off + 8], 'big')
    subs = [struct.unpack('<I', b[off + 8 + 4 * i:off + 12 + 4 * i])[0] for i in range(count)]
    return f'S-{rev}-{auth}-' + '-'.join(map(str, subs)), 8 + 4 * count


def test_the_folder_is_left_to_system_and_the_administrators_only():
    sd = nh.security_descriptor(True)
    rev, _, control, o_owner, o_group, o_sacl, o_dacl = struct.unpack('<BBHIIII', sd[:20])
    assert rev == 1 and control == 0x9004 and o_sacl == 0      # self-relative, DACL present + protected
    assert _sid_str(sd, o_owner)[0] == 'S-1-5-32-544' and _sid_str(sd, o_group)[0] == 'S-1-5-18'
    acl_rev, _, size, count, _ = struct.unpack('<BBHHH', sd[o_dacl:o_dacl + 8])
    assert acl_rev == 2 and count == 2 and o_dacl + size == len(sd)
    at, who = o_dacl + 8, []
    for _ in range(count):
        typ, flags, asize, mask = struct.unpack('<BBHI', sd[at:at + 8])
        assert typ == 0 and flags == 0x03 and mask == nh.FILE_ALL_ACCESS
        who.append(_sid_str(sd, at + 8)[0])
        at += asize
    assert who == ['S-1-5-18', 'S-1-5-32-544']
    assert struct.unpack('<BBHI', nh.security_descriptor(False)[o_dacl + 8:o_dacl + 16])[1] == 0


# --------------------------------------------------------------------------- descriptors

def _sid_bytes(s):
    parts = s.split('-')
    subs = [int(x) for x in parts[3:]]
    return struct.pack('<BB', int(parts[1]), len(subs)) + int(parts[2]).to_bytes(6, 'big') + \
        b''.join(struct.pack('<I', x) for x in subs)


def make_sd(owner, aces, dacl=True):
    """A self-relative descriptor: owner, group SYSTEM, a DACL of (type, mask, sid) entries"""
    o, g = _sid_bytes(owner), _sid_bytes('S-1-5-18')
    body = b''
    for typ, mask, sid in aces:
        sb = _sid_bytes(sid)
        body += struct.pack('<BBHI', typ, 0x03, 8 + len(sb), mask) + sb
    acl = struct.pack('<BBHHH', 2, 0, 8 + len(body), len(aces), 0) + body
    off_o, off_g = 20, 20 + len(o)
    off_d = off_g + len(g) if dacl else 0
    return struct.pack('<BBHIIII', 1, 0, 0x8000 | (0x0004 if dacl else 0), off_o, off_g, 0, off_d) + o + g + \
        (acl if dacl else b'')


USER = 'S-1-5-21-1000-2000-3000-1001'
ALL = nh.FILE_ALL_ACCESS
# what ProgramData hands a folder a user makes in it, and the ntfs-3g default of a new file
USER_FOLDER = make_sd(USER, [(0, ALL, 'S-1-5-18'), (0, ALL, 'S-1-5-32-544'), (0, ALL, USER),
                             (0, 0x2 | 0x4 | 0x10 | 0x100, 'S-1-5-32-545')])
NTFS3G_DEFAULT = make_sd('S-1-5-32-544', [(0, ALL, 'S-1-1-0')])


@pytest.mark.parametrize('sd,ok', [
    (nh.security_descriptor(True), True),
    (nh.security_descriptor(False), True),
    (make_sd('S-1-5-18', [(0, ALL, 'S-1-5-18'), (0, ALL, 'S-1-5-32-544'), (0, 0x1200A9, 'S-1-5-32-545')]), True),
    (make_sd('S-1-5-32-544', [(0, ALL, 'S-1-5-32-544'), (1, ALL, 'S-1-1-0')]), True),     # a deny entry
    (make_sd(USER, [(0, ALL, 'S-1-5-18')]), False),                                     # a user owns it
    (USER_FOLDER, False),
    (NTFS3G_DEFAULT, False),
    (make_sd('S-1-5-32-544', [(0, 0x2, 'S-1-5-11')]), False),                           # write data only
    (make_sd('S-1-5-32-544', [(0, 0x40000, USER)]), False),                             # WRITE_DAC only
    (make_sd('S-1-5-32-544', [(5, ALL, 'S-1-5-18')]), False),                           # an object entry
    (make_sd('S-1-5-32-544', [], dacl=False), False),                                   # no DACL at all
    (b'', False), (b'\x01\x00\x04\x80' + b'\xff' * 16, False),
])
def test_only_system_and_the_administrators_may_change_a_trusted_descriptor(sd, ok):
    assert nh.trusted_descriptor(sd) is ok


# --------------------------------------------------------------------------- the whole staging

@pytest.fixture
def volume(tmp_path, monkeypatch):
    """A mounted Windows volume: Windows/System32/config with SYSTEM and SOFTWARE, ProgramData,
    and an ISO with the two packages. Descriptors live in acls (path -> bytes), as the
    system.ntfs_acl attribute of ntfs-3g; setxattr on a link is refused like getxattr."""
    root = tmp_path / 'win'
    cfg = root / 'Windows' / 'System32' / 'config'
    cfg.mkdir(parents=True)
    (root / 'Windows' / 'System32' / 'kernel32.dll').write_bytes(b'MZ kernel32')
    (root / 'ProgramData').mkdir()
    iso = tmp_path / 'iso'
    (iso / 'guest-agent').mkdir(parents=True)
    (iso / 'virtio-win-gt-x64.msi').write_bytes(b'drivers msi')
    (iso / 'guest-agent' / 'qemu-ga-x86_64.msi').write_bytes(b'agent msi')
    trees = {}
    specs = {'SYSTEM': system_spec(), 'SOFTWARE': software_spec()}

    def opener(path, write=False):
        name = os.path.basename(path)
        if name not in trees:
            trees[name] = build(specs[name])
        return FakeHivex(trees[name], write=write)
    for n in ('SYSTEM', 'SOFTWARE'):
        (cfg / n).write_bytes(b'regf')
    monkeypatch.setitem(sys.modules, 'hivex', types.SimpleNamespace(Hivex=opener))
    acls, refuse = {}, []

    def setx(p, k, v, follow_symlinks=True):
        assert k == 'system.ntfs_acl' and follow_symlinks is False
        p = str(p)
        if os.path.islink(p) or any(r(p) for r in refuse):
            raise OSError(95, 'Operation not supported', p)
        acls[p] = v

    def getx(p, k, follow_symlinks=True):
        p = str(p)
        if k == 'system.ntfs_acl' and p in acls:
            return acls[p]
        raise OSError(61, 'No data available', p)
    monkeypatch.setattr(nh.os, 'setxattr', setx, raising=False)
    monkeypatch.setattr(nh.os, 'getxattr', getx, raising=False)
    FakeHivex.commits = []
    return types.SimpleNamespace(root=root, windows=root / 'Windows', trees=trees, specs=specs, acls=acls,
                                 refuse=refuse, iso=iso, pd=root / 'ProgramData',
                                 work=root / 'ProgramData' / 'KVMMigration',
                                 msi=str(iso / 'virtio-win-gt-x64.msi'),
                                 agent=str(iso / 'guest-agent' / 'qemu-ga-x86_64.msi'))


def _service(volume):
    if 'SYSTEM' not in volume.trees:
        return None
    sysh = nh.Hive(FakeHivex(volume.trees['SYSTEM']))
    return sysh.child(sysh.root(), 'ControlSet001', 'Services', nh.SERVICE)


def _stage(volume, pairs='', run='t1', **kw):
    return nh.stage(str(volume.root), str(volume.windows), run, b'@echo off\r\n', nh.parse_pairs(pairs), **kw)


def test_the_staging_writes_the_first_boot_and_the_saved_network(volume):
    got = nh.stage(str(volume.root), str(volume.windows), 't1', b'@echo off\r\n',
                   nh.parse_pairs('005056bad2b5=bc2411000002,=bc2411000003'), volume.msi, volume.agent, True)
    work = volume.work
    assert (work / 'firstboot.cmd').read_bytes() == b'@echo off\r\n'
    s = _sets((work / 'firstboot-data.cmd').read_bytes())
    assert (s['KM_NIC1_GUID'], s['KM_NIC1_MAC']) == (GUID_A, 'bc2411000002')
    assert (s['KM_NIC2_GUID'], s['KM_NIC2_MAC']) == (GUID_B, 'bc2411000003')
    assert s['KM_TOOLS_CODE'] == '{ABCDEF01-2345-6789-ABCD-EF0123456789}' and s['KM_TOOLS_UNINSTALL'] == '1'
    assert (s['KM_DRIVER_MSI'], s['KM_AGENT_MSI']) == ('virtio-win-gt-x64.msi', 'qemu-ga-x86_64.msi')
    # the packages were copied from the ISO by the helper itself
    assert (work / 'virtio-win-gt-x64.msi').read_bytes() == b'drivers msi'
    assert (work / 'qemu-ga-x86_64.msi').read_bytes() == b'agent msi'
    net = json.loads((work / 'netconfig.json').read_text())
    assert net['source'] == 'offline' and net['run'] == 't1' and len(net['adapters']) == 2
    assert got['tools_code'] is True and got['source'] == 'offline' and got['service'] == ['ControlSet001']
    assert got['adapters'][0]['ipv4'] == ['10.0.0.5/24', '10.0.0.6/16'] and got['locked'] is True
    assert got['msis'] == ['virtio-win-gt-x64.msi', 'qemu-ga-x86_64.msi'] and got['moved_aside'] == []
    # the folder and every file written got the descriptor, and the service went into SYSTEM
    written = {'KVMMigration', 'firstboot.cmd', 'firstboot-data.cmd', 'netconfig.json', 'virtio-win-gt-x64.msi',
               'qemu-ga-x86_64.msi'}
    assert {os.path.basename(p) for p in volume.acls} == written
    assert volume.acls[str(work)] == nh.security_descriptor(True)
    assert volume.acls[str(work / 'firstboot-data.cmd')] == nh.security_descriptor(False)
    assert _service(volume) is not None


def test_the_network_the_in_guest_preparation_saved_wins_over_the_released_registry(volume):
    work = volume.work
    work.mkdir()
    volume.acls[str(work)] = nh.security_descriptor(True)      # locked by the in-guest preparation
    saved = {'version': 1, 'source': 'guest', 'run': 't1', 'adapters': [
        {'mac': '00:50:56:AA:BB:CC', 'setting_id': GUID_A, 'index': 12, 'dhcp': False, 'instance': DEV_A,
         'ipv4': [{'ip': '172.16.0.9', 'prefix': 16}], 'gateway': [{'ip': '172.16.0.1', 'metric': 1}], 'dns': ['172.16.0.2']}]}
    (work / 'netconfig.json').write_text(json.dumps(saved))
    volume.acls[str(work / 'netconfig.json')] = make_sd('S-1-5-18', [(0, ALL, 'S-1-5-18'), (0, ALL, 'S-1-5-32-544')])
    got = _stage(volume, '005056aabbcc=bc2411000009')
    s = _sets((work / 'firstboot-data.cmd').read_bytes())
    assert got['source'] == 'guest' and got['kept'] is True and (s['KM_NIC1_IP1'], s['KM_NIC1_MAC']) == ('172.16.0.9', 'bc2411000009')
    # no released.flag: stage 2 did not run, nothing says the guest tools went
    assert got['released'] is False
    # the file of another run is not taken
    saved['run'] = 'other'
    (work / 'netconfig.json').write_text(json.dumps(saved))
    volume.acls[str(work / 'netconfig.json')] = nh.security_descriptor(False)
    assert _stage(volume)['source'] == 'offline'


def test_a_junction_a_user_made_is_moved_aside_and_nothing_goes_through_it(volume):
    # mklink /J C:\ProgramData\KVMMigration C:\Windows\System32 needs no privilege; ntfs-3g
    # shows the junction as a symlink
    system32 = volume.windows / 'System32'
    os.symlink(system32, volume.work)
    got = _stage(volume, '005056bad2b5=bc2411000002', driver_msi=volume.msi)
    assert not set(os.listdir(system32)) & {'firstboot.cmd', 'firstboot-data.cmd', 'netconfig.json', 'virtio-win-gt-x64.msi'}
    assert not [p for p in volume.acls if p.startswith(str(system32))], 'a descriptor went onto System32'
    assert (system32 / 'kernel32.dll').read_bytes() == b'MZ kernel32'
    aside = volume.pd / 'KVMMigration.untrusted-t1'
    assert os.path.islink(aside) and os.readlink(aside) == str(system32)
    assert volume.work.is_dir() and not volume.work.is_symlink()
    assert (volume.work / 'firstboot.cmd').exists() and got['moved_aside'] == ['KVMMigration.untrusted-t1']
    assert got['kept'] is False and _service(volume) is not None


def test_a_folder_a_user_made_first_is_moved_aside_with_what_it_holds(volume):
    # the guest is on DHCP; the user leaves a "run by hand" network and a dangling junction that
    # sorts before everything PegaProx writes
    volume.specs['SYSTEM'] = system_spec(ifaces={GUID_DHCP: {'@EnableDHCP': 1}})
    work = volume.work
    work.mkdir()
    volume.acls[str(work)] = USER_FOLDER
    (work / 'released.flag').write_text('released')
    (work / 'net.done').write_text('done')
    (work / 'boots.txt').write_text('2')
    os.symlink(volume.root / '.NTFS-3G' / 'D:' / 'gone', work / '!a')
    (work / 'netconfig.json').write_text(json.dumps({'source': 'guest', 'run': 'manual', 'adapters': [
        {'setting_id': GUID_A, 'mac': '00:50:56:ba:d2:b5', 'index': 1, 'dhcp': False,
         'ipv4': [{'ip': '10.0.0.50', 'prefix': 24}], 'gateway': [{'ip': '10.0.0.66', 'metric': 1}], 'dns': ['10.0.0.66']}]}))
    got = _stage(volume, '005056bad2b5=bc2411000002')
    s = _sets((volume.work / 'firstboot-data.cmd').read_bytes())
    assert got['source'] == 'offline' and s['KM_NICS'] == '0' and '10.0.0.50' not in json.dumps(got)
    assert sorted(os.listdir(volume.work)) == ['firstboot-data.cmd', 'firstboot.cmd', 'netconfig.json']
    assert sorted(os.listdir(volume.pd / 'KVMMigration.untrusted-t1')) == ['!a', 'boots.txt', 'net.done',
                                                                          'netconfig.json', 'released.flag']
    # every file of the new folder is locked, the service only after that
    for name in os.listdir(volume.work):
        assert volume.acls[str(volume.work / name)] == nh.security_descriptor(False)
    assert _service(volume) is not None


def test_another_case_of_the_name_is_the_same_folder_on_windows(volume):
    (volume.pd / 'kvmmigration').mkdir()
    volume.acls[str(volume.pd / 'kvmmigration')] = nh.security_descriptor(True)
    (volume.pd / 'KVMMIGRATION').mkdir()
    volume.acls[str(volume.pd / 'KVMMIGRATION')] = nh.security_descriptor(True)
    got = _stage(volume)
    assert sorted(got['moved_aside']) == ['KVMMigration.untrusted-t1', 'KVMMigration.untrusted-t1-1']
    assert [e for e in os.listdir(volume.pd) if e.lower() == 'kvmmigration'] == ['KVMMigration']


def test_a_file_that_cannot_be_locked_stops_the_staging_before_the_service(volume, capsys, tmp_path):
    volume.refuse.append(lambda p: p.endswith('firstboot-data.cmd'))
    with pytest.raises(OSError):
        _stage(volume, driver_msi=volume.msi)
    assert _service(volume) is None and FakeHivex.commits == []
    # nothing half locked stays for a first boot task to run
    assert os.listdir(volume.work) == []
    fb = tmp_path / 'fb64'
    fb.write_text(base64.b64encode(b'@echo off\r\n').decode())
    rc = nh.main(['--root', str(volume.root), '--windows', str(volume.windows), '--run', 't1', '--firstboot', str(fb),
                  '--driver-msi', volume.msi])
    out = capsys.readouterr().out
    assert rc == 1 and out.startswith('WINPREP_FAILED ') and 'MSI_STAGED' not in out


def test_a_folder_that_cannot_be_locked_stops_the_staging_too(volume):
    volume.refuse.append(lambda p: p.endswith('KVMMigration'))
    with pytest.raises(OSError):
        _stage(volume)
    assert _service(volume) is None and not (volume.work / 'firstboot.cmd').exists()


def test_a_kept_folder_loses_the_state_of_an_earlier_first_boot_and_its_links(volume):
    work = volume.work
    work.mkdir()
    volume.acls[str(work)] = nh.security_descriptor(True)
    for name in nh.STALE_STATE:
        (work / name).write_text('3')
    (work / 'migrate.log').write_text('kept')
    os.symlink(volume.windows / 'System32' / 'kernel32.dll', work / 'firstboot-data.cmd')
    got = _stage(volume)
    assert got['kept'] is True and got['moved_aside'] == []
    assert not [n for n in nh.STALE_STATE if (work / n).exists()]
    assert (work / 'migrate.log').read_text() == 'kept'
    assert not (work / 'firstboot-data.cmd').is_symlink()
    assert (volume.windows / 'System32' / 'kernel32.dll').read_bytes() == b'MZ kernel32'


def test_a_network_file_a_user_can_write_is_not_taken_from_a_kept_folder(volume):
    work = volume.work
    work.mkdir()
    volume.acls[str(work)] = nh.security_descriptor(True)
    (work / 'netconfig.json').write_text(json.dumps({'source': 'guest', 'run': 't1', 'adapters': [
        {'setting_id': GUID_A, 'mac': '', 'index': 1, 'ipv4': [{'ip': '10.9.9.9', 'prefix': 24}]}]}))
    volume.acls[str(work / 'netconfig.json')] = NTFS3G_DEFAULT
    got = _stage(volume)
    assert got['source'] == 'offline' and '10.9.9.9' not in (work / 'firstboot-data.cmd').read_text()


def test_the_command_line_prints_the_packages_one_summary_line_and_the_end_marker(volume, tmp_path, capsys):
    fb = tmp_path / 'fb64'
    fb.write_text(base64.b64encode(b'@echo off\r\nrem x\r\n').decode())
    rc = nh.main(['--root', str(volume.root), '--windows', str(volume.windows), '--run', 't1',
                  '--firstboot', str(fb), '--nics', '005056bad2b5=bc2411000002', '--uninstall-tools', '0',
                  '--driver-msi', volume.msi, '--agent-msi', volume.agent])
    out = capsys.readouterr().out.splitlines()
    assert rc == 0 and out[-1] == 'WINPREP_OK' and out[-2].startswith('WINPREP {')
    assert out[:2] == ['MSI_STAGED virtio-win-gt-x64.msi', 'MSI_STAGED qemu-ga-x86_64.msi']
    assert json.loads(out[-2][8:])['adapters'][0]['target_mac'] == 'bc2411000002'
    assert (volume.work / 'firstboot.cmd').read_bytes() == b'@echo off\r\nrem x\r\n'


def test_a_failure_of_the_command_line_says_so_on_one_line(volume, tmp_path, capsys):
    rc = nh.main(['--root', str(volume.root), '--windows', str(volume.windows), '--run', 'bad run!',
                  '--firstboot', str(tmp_path / 'missing')])
    out = capsys.readouterr().out
    assert rc == 1 and out.startswith('WINPREP_FAILED ') and out.count('\n') == 1


# --------------------------------------------------------------------------- old adapters without a MAC

DEV_E1000 = r'PCI\VEN_8086&DEV_100F&SUBSYS_075015AD&REV_01\4&1A2B3C&0&0888'
DEV_E1000E = r'PCI\VEN_8086&DEV_10D3&SUBSYS_07D015AD&REV_01\4&2B3C4D&0&00E0'


def _swap_spec(dates):
    """adapter A (e1000, 10.0.0.5, class index 0002) left from an earlier NIC, adapter B
    (e1000e, 10.0.0.9, index 0011) the one the guest has; neither has a MAC in the registry"""
    return system_spec(ifaces={GUID_A: {'@EnableDHCP': 0, '@IPAddress': ['10.0.0.5'], '@SubnetMask': ['255.255.255.0']},
                               GUID_B: {'@EnableDHCP': 0, '@IPAddress': ['10.0.0.9'], '@SubnetMask': ['255.255.255.0']}},
                       adapters={GUID_A: (DEV_E1000, '0002', 'Intel(R) PRO/1000 MT', None),
                                 GUID_B: (DEV_E1000E, '0011', 'Intel(R) 82574L', None)}, dates=dates)


def test_the_device_dates_are_read_from_the_enum_key():
    got = nh.read_adapters(hv(_swap_spec({DEV_E1000: (100, 200), DEV_E1000E: (300, 0)})))
    assert [(a['guid'], a['arrived'], a['removed']) for a in got] == [(GUID_A, 100, 200), (GUID_B, 300, 0)]
    assert [(a['arrived'], a['removed']) for a in nh.read_adapters(hv(_swap_spec(None)))] == [(0, 0), (0, 0)]


@pytest.mark.parametrize('dates', [
    {DEV_E1000: (100, 200), DEV_E1000E: (300, 0)},      # A was seen to go
    {DEV_E1000: (100, 0), DEV_E1000E: (300, 0)},        # B arrived last
    None,                                               # Windows 7: B was installed last
])
def test_an_old_adapter_without_a_mac_does_not_take_the_only_nic(dates):
    moved, stale = nh.match_nics(nh.read_adapters(hv(_swap_spec(dates))), nh.parse_pairs('005056000001=bc2411000001'))
    assert [(a['ipv4'][0]['ip'], a['target_mac']) for a in moved] == [('10.0.0.9', 'bc2411000001')]
    assert [a['ipv4'][0]['ip'] for a in stale] == ['10.0.0.5']


def test_with_a_nic_for_each_both_move_in_the_order_windows_installed_them():
    moved, stale = nh.match_nics(nh.read_adapters(hv(_swap_spec({DEV_E1000: (300, 0), DEV_E1000E: (100, 0)}))),
                                 nh.parse_pairs('=bc2411000001,=bc2411000002'))
    assert [(a['ipv4'][0]['ip'], a['target_mac']) for a in moved] == [('10.0.0.5', 'bc2411000001'),
                                                                     ('10.0.0.9', 'bc2411000002')]
    assert stale == []


@pytest.mark.parametrize('ip', ['224.0.0.1', '239.1.2.3', '255.255.255.255', '127.0.0.1', '0.1.2.3'])
def test_an_address_windows_refuses_never_reaches_the_first_boot(ip):
    spec = system_spec(ifaces={GUID_A: {'@EnableDHCP': 0, '@IPAddress': [ip], '@SubnetMask': ['255.255.255.0'],
                                        '@DefaultGateway': [ip], '@NameServer': ip}})
    assert nh.read_adapters(hv(spec)) == []
    a = dict(ADAPTERS[0], gateway=[{'ip': ip, 'metric': 0}], dns=[ip])
    s = _sets(nh.data_cmd('r1', 20348, [a]))
    assert s['KM_NIC1_GWS'] == '0' and s['KM_NIC1_DNS'] == ''
    with pytest.raises(ValueError):
        nh.data_cmd('r1', 20348, [dict(a, ipv4=[{'ip': ip, 'prefix': 24}])])
    assert not nh.host_ip(ip) and nh.host_ip('10.0.0.5')


# --------------------------------------------------------------------------- data disks online

# Seen on Server 2025: after the migration the data disk was offline and read-only, its drive
# letter gone. Windows Server keeps a disk it sees for the first time offline (SAN policy
# OfflineShared), and on Proxmox VE every data disk sits on a new controller.

def _san(h, cs='ControlSet001'):
    return h.value(h.child(h.root(), cs, 'Services', 'partmgr', 'Parameters'), 'SanPolicy')


@pytest.mark.parametrize('was', [None, 2, 3])
def test_the_san_policy_becomes_online_all_in_every_control_set(was):
    spec = system_spec()
    spec['Select']['@Current'] = 1
    spec['Select']['@Default'] = 2
    spec['ControlSet002'] = system_spec()['ControlSet001']
    if was is not None:
        for cs in ('ControlSet001', 'ControlSet002'):
            spec[cs]['Services']['partmgr'] = {'Parameters': {'@SanPolicy': was}}
    h = hv(spec, write=True)
    assert nh.san_online(h) == was
    assert _san(h, 'ControlSet001') == 1 and _san(h, 'ControlSet002') == 1


def test_the_staging_sets_the_san_policy_and_reports_what_it_was(volume):
    volume.specs['SYSTEM']['ControlSet001']['Services']['partmgr'] = {'Parameters': {'@SanPolicy': 2}}
    got = _stage(volume)
    assert got['san_policy'] == 2
    assert _san(nh.Hive(FakeHivex(volume.trees['SYSTEM']))) == 1


class _LogTask:
    def __init__(self):
        self.lines, self.warnings = [], []

    def log(self, line):
        self.lines.append(line)


@pytest.mark.parametrize('was,said', [(2, 'SAN policy OfflineShared set to OnlineAll'),
                                      (None, 'SAN policy the default of the edition set to OnlineAll'),
                                      (1, None)])
def test_the_migration_log_says_what_the_san_policy_was(monkeypatch, was, said):
    from pegaprox.core import v2p_winprep
    task = _LogTask()
    monkeypatch.setattr(v2p_winprep, 'state', lambda t: {})
    out = 'WINPREP ' + json.dumps({'build': 26100, 'product': 'Windows Server 2025', 'adapters': [],
                                   'service': ['ControlSet001'], 'san_policy': was}) + '\nWINPREP_OK\n'
    assert v2p_winprep.parse_result(task, out) is True
    hits = [l for l in task.lines if 'SAN policy' in l]
    assert (hits and said in hits[0]) if said else not hits, task.lines


def test_a_run_by_hand_that_released_the_guest_is_reported(volume):
    # the lab ran the manual script on ESXi (stage 1, stage 2, shutdown) and migrated the guest
    # without a login: its stage 2 had uninstalled the guest tools, the log said "they stay"
    volume.specs['SYSTEM'] = system_spec(ifaces={GUID_DHCP: {'@EnableDHCP': 1}})
    work = volume.work
    work.mkdir()
    volume.acls[str(work)] = nh.security_descriptor(True)
    trusted = make_sd('S-1-5-32-544', [(0, ALL, 'S-1-5-18'), (0, ALL, 'S-1-5-32-544')])
    (work / 'released.flag').write_text('released')
    volume.acls[str(work / 'released.flag')] = trusted
    (work / 'netconfig.json').write_text(json.dumps({'source': 'guest', 'run': 'manual', 'adapters': [
        {'setting_id': GUID_A, 'mac': '00:50:56:ba:d2:b5', 'index': 1, 'dhcp': False, 'instance': DEV_A,
         'ipv4': [{'ip': '10.0.0.50', 'prefix': 24}], 'gateway': [], 'dns': []}]}))
    volume.acls[str(work / 'netconfig.json')] = trusted
    got = _stage(volume, '005056bad2b5=bc2411000002')
    assert got['source'] == 'guest' and got['released'] is True


@pytest.mark.parametrize('code,prep,nic,said', [
    (True, None, 'virtio', 'ESXi guest tools: uninstalled at the first boot'),
    (True, None, 'vmxnet3', 'ESXi guest tools: stay installed, the VM keeps a device that runs on their drivers'),
    # stage 2 in the guest uninstalled them before its shutdown: nothing is left to find
    (False, 'shut_down', 'virtio', 'ESXi guest tools: no uninstall entry left, the in-guest preparation '
                                   'uninstalled them before its shutdown'),
    (False, 'aborted', 'virtio', 'ESXi guest tools: no uninstall entry found, they stay'),
    # the script run by hand: only its released.flag on the disk says stage 2 ran
    (False, 'released', 'virtio', 'ESXi guest tools: no uninstall entry left, the in-guest preparation '
                                  'uninstalled them before its shutdown'),
    (False, None, 'virtio', 'ESXi guest tools: no uninstall entry found, they stay'),
])
def test_the_migration_log_says_what_becomes_of_the_guest_tools(monkeypatch, code, prep, nic, said):
    from pegaprox.core import v2p_winprep
    task = _LogTask()
    task._net_model = nic
    if prep and prep != 'released':
        task._guest_prep = {'state': prep}
    monkeypatch.setattr(v2p_winprep, 'state', lambda t: {})
    out = 'WINPREP ' + json.dumps({'build': 26100, 'product': 'Windows Server 2025', 'adapters': [],
                                   'service': ['ControlSet001'], 'tools_code': code,
                                   'released': prep == 'released',
                                   'source': 'guest' if prep else 'offline'}) + '\nWINPREP_OK\n'
    assert v2p_winprep.parse_result(task, out) is True
    hits = [ln for ln in task.lines if 'ESXi guest tools:' in ln]
    assert len(hits) == 1 and said + ';' in hits[0], task.lines


def test_the_in_guest_script_sets_the_san_policy_too():
    ps = (pathlib.Path(nh.__file__).parent / 'v2p_guestprep.ps1').read_text(encoding='ascii')
    step = ps.split("Invoke-Step 'data disks online on the new controller'", 1)[1].split('-BestEffort', 1)[0]
    assert r"CreateSubKey('SYSTEM\CurrentControlSet\Services\partmgr\Parameters')" in step
    assert "SetValue('SanPolicy', 1, [Microsoft.Win32.RegistryValueKind]::DWord)" in step
    # before the first boot task is registered: stage 1 ends with it
    assert ps.index("'data disks online on the new controller'") < ps.index("Invoke-Step 'first boot task'")
