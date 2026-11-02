"""Hardware health and disks of a node in Corporate Redesigned (Preview), in the browser.

Round 6 draws the Hardware tab and the Configure > Disks sub tab of a Proxmox VE node in the
preview from web/src/cr_node.js. Hardware: the lm-sensors rows (GET .../sensors) and the rows of
the in-band monitoring (HardwareMonitoringPanel reads GET .../hardware and hands them up) by kind,
with value, Max and Critical where a row carries them and a state worked out from those alone,
the stored temperatures as a chart, and what to do where the in-band monitoring is off. Disks:
disks/list with health, wear and what uses each disk (LVM tree, thin pools, Ceph OSD ids, the ZFS
pool members), temperature and error counters from SMART, read on request only. Whatever is not
in an answer says "not reported", a value that is not a number says so, neither is ever normal.
Classic Corporate keeps its tables.

The pure parts are checked through window.PegaProxNodeHw. PEGAPROX_CR_BUNDLE=<file> serves another
bundle (the counterproof against the build before this stage). Skips without Playwright. LW Nov 2026
"""
import copy
import json
import os
import re

import pytest

from test_corp_redesigned_guard_ui import (DETERMINISTIC, HW_CONSENT, NODE_DISKS, NODE_HW, NODE_IP, NODE_LVM, NODE_NET,
                                           NODE_LVMTHIN, NODE_SENSORS, NODE_SUMMARY, NODE_TEMPS, NODE_ZFS, RF_CONSENT,
                                           _GuardApp, _GuardServer, _corp_cluster)

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None

NODE = '/api/clusters/c1/nodes/pve1'
SENSORS = NODE + '/sensors'
TEMPS = NODE + '/temperature-history'
HW = NODE + '/hardware'
CONSENT = '/api/hardware-monitoring/consent'
DISKS = NODE + '/disks'
LVM = DISKS + '/lvm'
ZFS = DISKS + '/zfs'
TANK = ZFS + '/tank'

# zpool.pool_detail of the pool: one disk by its by-id partition name, one by its kernel name
TANK_DETAIL = {
    'name': 'tank', 'state': 'DEGRADED', 'status': 'One or more devices are faulted.', 'action': '', 'see': '',
    'errors': 'No known data errors', 'data_errors': '', 'scan': None, 'has_errors': True, 'truncated': False,
    'node': 'pve1', 'devices': [],
    'vdevs': [{'name': 'tank', 'state': 'DEGRADED', 'read': 0, 'write': 0, 'cksum': 0, 'msg': '', 'children': [
        {'name': 'mirror-0', 'state': 'DEGRADED', 'read': 0, 'write': 0, 'cksum': 0, 'msg': '', 'children': [
            {'name': 'ata-HDD_4TB_ZC100001-part1', 'state': 'ONLINE', 'read': 0, 'write': 0, 'cksum': 0, 'msg': '',
             'children': []},
            {'name': 'sdb', 'state': 'FAULTED', 'read': 3, 'write': 0, 'cksum': 12, 'msg': 'too many errors',
             'children': []}]}]}]}
# disks/smart as Proxmox VE answers it: text for NVMe and SAS, attributes for SATA
SMART_NVME = {'health': 'PASSED', 'type': 'text', 'text': '\n'.join([
    'SMART/Health Information (NVMe Log 0x02)', 'Critical Warning:                   0x00',
    'Temperature:                        38 Celsius', 'Available Spare:                    100%',
    'Percentage Used:                    3%', 'Data Units Read:                    1,234,567 [632 GB]',
    'Media and Data Integrity Errors:    0', 'Error Information Log Entries:      12', ''])}


def _attr(i, name, value, thr, raw, fail='-'):
    return {'id': f'{i:>3}', 'name': name, 'value': value, 'normalized': value, 'worst': value, 'threshold': thr,
            'fail': fail, 'raw': raw, 'flags': 'PO--CK'}


SMART_SDA = {'health': 'PASSED', 'type': 'ata', 'attributes': [
    _attr(1, 'Raw_Read_Error_Rate', 200, 51, '0'), _attr(5, 'Reallocated_Sector_Ct', 199, 140, '8'),
    _attr(9, 'Power_On_Hours', 60, 0, '29512'), _attr(194, 'Temperature_Celsius', 114, 0, '36 (Min/Max 18/45)'),
    _attr(197, 'Current_Pending_Sector', 200, 0, '0'), _attr(198, 'Offline_Uncorrectable', 200, 0, '0'),
    _attr(199, 'UDMA_CRC_Error_Count', 200, 0, '0')]}
SMART_SAS = {'health': 'OK', 'type': 'text', 'text': '\n'.join([
    'Current Drive Temperature:     35 C', 'Drive Trip Temperature:        68 C',
    'Elements in grown defect list: 2', 'Error counter log:',
    '           Errors Corrected by           Total   Correction     Gigabytes    Total',
    'read:          0        0         0         0          0       1234.567           1',
    'write:         0        0         0         0          0        456.789           0', ''])}


class _HwServer(_GuardServer):
    """The guard fake with the node's sensors, its in-band monitoring and its disks; each answer
    settable while the page runs: a (code, body) pair, 'hold' or 'abort'."""

    def __init__(self, **kw):
        routes = kw.pop('routes', {})
        super().__init__(bundle=BUNDLE, **kw)
        self.routes = {
            ('GET', NODE + '/ip'): (200, NODE_IP),
            ('GET', NODE + '/summary'): (200, NODE_SUMMARY),
            # Configure opens on Network: with its list the sub tabs draw while another read runs
            ('GET', NODE + '/network'): (200, NODE_NET),
            ('GET', NODE + '/network/changes'): (200, {'changes': ''}),
            ('GET', SENSORS): (200, NODE_SENSORS),
            ('GET', TEMPS): (200, NODE_TEMPS),
            ('GET', CONSENT): (200, HW_CONSENT),
            ('GET', '/api/hardware-monitoring/redfish-consent'): (200, RF_CONSENT),
            ('GET', HW): (200, NODE_HW),
            ('GET', DISKS): (200, NODE_DISKS),
            ('GET', LVM): (200, NODE_LVM),
            ('GET', DISKS + '/lvmthin'): (200, NODE_LVMTHIN),
            ('GET', ZFS): (200, NODE_ZFS),
            ('GET', TANK): (200, TANK_DETAIL),
            ('GET', DISKS + '/nvme0n1/smart'): (200, SMART_NVME),
            ('GET', DISKS + '/sda/smart'): (200, SMART_SDA),
            ('GET', DISKS + '/sdb/smart'): (200, {}),
            ('GET', DISKS + '/sdc/smart'): (403, {'error': 'Permission denied: node.view on pve1'}),
            ('GET', DISKS + '/sdd/smart'): (200, {'health': 'UNKNOWN'}),
        }
        self.routes.update(routes)
        self.held = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        how = self.routes.get((req.method, path))
        if how is None:
            return super().handle(route)
        self.calls.append((req.method, path))
        if how == 'abort':
            return route.abort('connectionrefused')
        if how == 'hold':
            self.held.append(route)
            return None
        code, data = how
        return route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def reads(self, path):
        return len([c for c in self.calls if c == ('GET', path)])

    def reads_like(self, pattern):
        return len([c for c in self.calls if c[0] == 'GET' and re.search(pattern, c[1])])


@pytest.fixture(scope='module')
def playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    yield pw
    pw.stop()


@pytest.fixture(scope='module')
def browser(playwright):
    try:
        br = playwright.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture(scope='module')
def firefox(playwright):
    try:
        br = playwright.firefox.launch(headless=True)
    except Exception as e:
        pytest.skip(f'no Firefox for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, viewport=(1600, 1000), br=None, **kw):
        app = _GuardApp(br or browser, _HwServer(layout=layout, **kw), viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


def _open_hardware(page, redesigned=True):
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    if redesigned:
        page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Hardware').click()
    else:
        page.locator('.corp-tab-strip button', has_text='Hardware').first.click()


def _open_disks(page, redesigned=True):
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    if redesigned:
        page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Configure').click()
    else:
        page.locator('.corp-tab-strip button', has_text='Configure').first.click()
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*Disks\s*$')).first.click()


def _settled_hw(page):
    page.locator('[data-cr-nh-src="lm"]:not([data-cr-nh-src-state="loading"])').wait_for(timeout=8000)
    page.locator('[data-cr-nh-src="bmc"]:not([data-cr-nh-src-state="loading"])').wait_for(timeout=8000)


def _row(page, name, src=None):
    sel = f'[data-cr-nh-row="{name}"]' + (f'[data-cr-nh-row-src="{src}"]' if src else '')
    return page.locator(sel).first


def _state(page, name, src=None):
    return _row(page, name, src).locator('[data-cr-nh-state]').get_attribute('data-cr-nh-state')


# --- the pure parts -----------------------------------------------------------------------------

@pytest.fixture(scope='module')
def hw_page(browser):
    app = _GuardApp(browser, _HwServer(layout=LAYOUT))
    if not app.page.evaluate('() => !!window.PegaProxNodeHw'):
        app.close()
        pytest.fail('the bundle has no node hardware helpers (window.PegaProxNodeHw)')
    yield app.page
    app.close()


def _lm(page, row):
    return page.evaluate('(r) => window.PegaProxNodeHw.lmRow(r)', row)


def _bmc(page, row):
    return page.evaluate('(r) => window.PegaProxNodeHw.bmcRow(r)', row)


def test_rules_lm_thresholds_and_states(hw_page):
    base = {'chip': 'coretemp-isa-0000', 'label': 'Core 0', 'kind': 'temp', 'max': 80.0, 'crit': 100.0, 'alarm': False}
    assert _lm(hw_page, dict(base, value=54.0))['state'] == 'normal'
    assert _lm(hw_page, dict(base, value=80.0))['state'] == 'high'
    assert _lm(hw_page, dict(base, value=100.0))['state'] == 'critical'
    assert _lm(hw_page, dict(base, value=60.0, alarm=True))['state'] == 'alarm'
    # only the Critical limit known: below it is normal, at it critical
    assert _lm(hw_page, dict(base, value=60.0, max=None))['state'] == 'normal'
    assert _lm(hw_page, dict(base, value=101.0, max=None))['state'] == 'critical'
    row = _lm(hw_page, dict(base, value=54.0))
    assert row['max'] == {'k': 'num', 'v': 80} and row['crit'] == {'k': 'num', 'v': 100} and row['unit'] == '°C'
    fan = _lm(hw_page, {'chip': 'it8728', 'label': 'fan1', 'kind': 'fan', 'value': 1250.0, 'max': None, 'crit': None})
    assert fan['group'] == 'fan' and fan['unit'] == 'RPM' and fan['state'] == 'nolimit'
    volt = _lm(hw_page, {'label': 'Vcore', 'kind': 'volt', 'value': 1.8, 'max': 1.74})
    assert volt['group'] == 'volt' and volt['state'] == 'high'
    assert _lm(hw_page, {'label': 'power1', 'kind': 'other', 'value': 3})['group'] == 'other'


def test_rules_missing_and_unparseable_values_are_never_normal(hw_page):
    base = {'chip': 'c', 'label': 'temp1', 'kind': 'temp', 'max': 80.0, 'crit': 100.0, 'alarm': False}
    for value, state in ((None, 'none'), ('', 'none'), ('+127.0 (sensor = thermistor)', 'bad'), ('54', 'bad')):
        row = _lm(hw_page, dict(base, value=value))
        assert row['state'] == state, (value, row)
    # a value without any limit, or with a limit that is not a number, is not judged
    assert _lm(hw_page, dict(base, value=40.0, max=None, crit=None))['state'] == 'nolimit'
    bad_limit = _lm(hw_page, dict(base, value=40.0, max='high', crit=None))
    assert bad_limit['state'] == 'nolimit' and bad_limit['max'] == {'k': 'bad', 'raw': 'high'}
    # the alarm flag defaults to false where the chip has none: false alone is never normal
    assert _lm(hw_page, dict(base, value=40.0, max=None, crit=None, alarm=False))['state'] != 'normal'
    # in-band: ok without anything read, text where a number belongs, na and an unknown word
    assert _bmc(hw_page, {'name': 'FAN4', 'kind': 'fan', 'value': None, 'reading': '', 'status': 'ok'})['state'] == 'none'
    txt = _bmc(hw_page, {'name': 'FAN5', 'kind': 'fan', 'value': None, 'reading': 'Disabled', 'status': 'ok'})
    assert txt['state'] == 'bad' and txt['value'] == {'k': 'bad', 'raw': 'Disabled'}
    assert _bmc(hw_page, {'name': 'FAN4', 'kind': 'fan', 'value': None, 'reading': 'No Reading', 'status': 'na'})['state'] == 'none'
    assert _bmc(hw_page, {'name': 'Temp', 'kind': 'temp', 'value': 40, 'reading': '40 degrees C', 'status': 'lnc'})['state'] == 'raw'
    assert _bmc(hw_page, {'name': 'Temp', 'kind': 'temp', 'value': 40, 'reading': '40 degrees C'})['state'] == 'none'
    # a model made of such rows only has no state, it is not normal
    model = hw_page.evaluate('''() => window.PegaProxNodeHw.model({sensors: [
        {label: 'a', kind: 'temp', value: null}, {label: 'b', kind: 'fan', value: 900},
        {label: 'c', kind: 'temp', value: 'n/a', max: 80}]}, null, 'pve1')''')
    assert model['overall'] == 'none' and model['counts'] == {'critical': 0, 'warning': 0, 'normal': 0, 'none': 3}
    failed = hw_page.evaluate('''() => window.PegaProxNodeHw.model({__crFail: {status: 502, error: 'no answer', code: ''}},
        {node: 'pve1', loading: false, consent: false, hw: null}, 'pve1')''')
    assert failed['lm']['state'] == 'error' and failed['inband']['state'] == 'off' and failed['overall'] == 'none'


def test_rules_fans_and_rails_are_never_normal_from_an_upper_limit_alone(hw_page):
    # the answer carries no lower limit: a dead rail, a stopped fan and a sensor error code are all
    # below Max, so below Max is only normal for a temperature that is one
    volt = {'chip': 'it8728', 'label': 'Vcore', 'kind': 'volt', 'max': 1.8, 'crit': None, 'alarm': False}
    assert _lm(hw_page, dict(volt, value=0.0))['state'] == 'belowmax'
    assert _lm(hw_page, dict(volt, value=0.95))['state'] == 'belowmax'
    assert _lm(hw_page, dict(volt, value=0.95, max=None, crit=2.0))['state'] == 'belowmax'
    assert _lm(hw_page, dict(volt, value=1.9))['state'] == 'high'
    fan = {'chip': 'it8728', 'label': 'fan1', 'kind': 'fan', 'max': 20000.0, 'crit': None, 'alarm': False}
    assert _lm(hw_page, dict(fan, value=1250.0))['state'] == 'belowmax'
    assert _lm(hw_page, dict(fan, value=0.0))['state'] == 'zero'
    assert _lm(hw_page, dict(fan, value=0.0, max=None))['state'] == 'zero'
    assert _lm(hw_page, dict(fan, value=0.0, alarm=True))['state'] == 'alarm'
    assert _lm(hw_page, {'label': 'power1', 'kind': 'other', 'value': 3.0, 'max': 10.0})['state'] == 'belowmax'
    temp = {'chip': 'coretemp-isa-0000', 'label': 'Core 0', 'kind': 'temp', 'max': 80.0, 'crit': 100.0, 'alarm': False}
    for v in (-127.0, -128.0, -273.2, -41.0):
        assert _lm(hw_page, dict(temp, value=v))['state'] == 'implausible', v
    assert _lm(hw_page, dict(temp, value=-40.0))['state'] == 'normal'
    # none of these counts as judged, and a model of them has no state
    model = hw_page.evaluate('''() => window.PegaProxNodeHw.model({sensors: [
        {label: 'Vcore', kind: 'volt', value: 0, max: 1.8}, {label: 'fan1', kind: 'fan', value: 0, max: 20000},
        {label: 'temp9', kind: 'temp', value: -127, max: 80}]}, null, 'pve1')''')
    assert model['overall'] == 'none' and model['counts'] == {'critical': 0, 'warning': 0, 'normal': 0, 'none': 3}


def test_rules_in_band_rows_by_kind(hw_page):
    groups = {r['name']: (r['group'], r['state']) for r in (_bmc(hw_page, s) for s in NODE_HW['sensors'])}
    assert groups == {'Inlet Temp': ('temp', 'normal'), 'FAN1': ('fan', 'normal'), 'FAN4': ('fan', 'none'),
                      'PS1 Status': ('psu', 'normal'), 'PS2 Status': ('psu', 'warning'),
                      'Pwr Consumption': ('psu', 'normal'), 'Voltage 1': ('volt', 'normal')}
    assert _bmc(hw_page, {'name': 'Power Supply 2', 'kind': 'discrete', 'reading': 'Present', 'status': 'ok'})['group'] == 'psu'
    assert _bmc(hw_page, {'name': 'Intrusion', 'kind': 'discrete', 'reading': 'Present', 'status': 'ok'})['group'] == 'other'
    m = hw_page.evaluate('(hw) => window.PegaProxNodeHw.model(undefined, {node: "pve1", loading: false, consent: true, hw}, "pve1")', NODE_HW)
    assert m['inband']['state'] == 'ok' and m['inband']['health'] == 'warning' and m['overall'] == 'warning'
    assert m['lm']['state'] == 'loading'


def test_rules_stored_temperatures(hw_page):
    got = hw_page.evaluate('''(s) => window.PegaProxNodeHw.temps({series: s})''',
                           [{'ts': '2026-10-30T06:05:00.123456', 'temp': 50.5}, {'ts': '2026-10-30T06:00:00', 'temp': 48},
                            {'ts': 'yesterday', 'temp': 40}, {'ts': '2026-10-30T06:10:00', 'temp': 'hot'}])
    assert got['state'] == 'ok' and got['vals'] == [48, 50.5] and got['skipped'] == 2 and round(got['ts'][1] - got['ts'][0]) == 300
    assert hw_page.evaluate('() => window.PegaProxNodeHw.temps({series: []}).state') == 'empty'
    assert hw_page.evaluate('() => window.PegaProxNodeHw.temps({__crFail: {status: 500, error: "x"}}).state') == 'error'
    assert hw_page.evaluate('() => window.PegaProxNodeHw.temps({error: "x"}).state') == 'error'


def test_rules_which_disk_a_name_belongs_to(hw_page):
    sda = {'devpath': '/dev/sda', 'by_id_link': '/dev/disk/by-id/ata-HDD_4TB_ZC100001', 'wwn': '0x5000c500a1b2c3d4'}
    nvme = {'devpath': '/dev/nvme0n1'}
    cases = [(sda, '/dev/sda3', True), (sda, 'sda', True), (sda, 'sdab', False), (sda, 'sdab1', False),
             (sda, 'ata-HDD_4TB_ZC100001-part1', True), (sda, '/dev/disk/by-id/ata-HDD_4TB_ZC100001', True),
             (sda, 'ata-HDD_4TB_ZC100002-part1', False), (sda, 'wwn-0x5000c500a1b2c3d4-part2', True),
             (nvme, '/dev/nvme0n1p3', True), (nvme, 'nvme0n11', False), (nvme, 'nvme0n1p', False)]
    for disk, name, want in cases:
        assert hw_page.evaluate('([d, n]) => window.PegaProxNodeHw.owns(d, n)', [disk, name]) is want, (disk, name)


def test_rules_disk_health_and_wear(hw_page):
    H = lambda v: hw_page.evaluate('(v) => window.PegaProxNodeHw.health(v).state', v)
    assert [H(v) for v in ('PASSED', 'OK', 'FAILED!', 'SMART Disabled', 'UNKNOWN', '', None, 'degraded')] == \
           ['ok', 'ok', 'failed', 'off', 'none', 'none', 'none', 'other']
    W = lambda v: hw_page.evaluate('(v) => window.PegaProxNodeHw.wear(v)', v)
    assert W(97) == {'state': 'ok', 'left': 97, 'used': 3}
    assert W('42') == {'state': 'ok', 'left': 42, 'used': 58}
    assert W('N/A')['state'] == 'none' and W(None)['state'] == 'none'
    assert W('lots')['state'] == 'bad' and W(140)['state'] == 'bad'


def test_rules_smart_answers(hw_page):
    S = lambda v: hw_page.evaluate('(v) => window.PegaProxNodeHw.smart(v)', v)
    ata = S(SMART_SDA)
    assert ata['known'] and ata['temp'] == {'k': 'num', 'v': 36}
    assert {e['key']: e['n'] for e in ata['errors']} == {'crNdErrRealloc': 8, 'crNdErrPending': 0, 'crNdErrOffline': 0,
                                                        'crNdErrCrc': 0}
    assert ata['failing'] == []
    worn = S({'attributes': [_attr(5, 'Reallocated_Sector_Ct', 100, 140, '2900')]})
    assert worn['failing'] == ['Reallocated_Sector_Ct']
    nv = S(SMART_NVME)
    assert nv['temp'] == {'k': 'num', 'v': 38} and nv['wearUsed'] == 3 and nv['critWarn'] == 0
    assert {e['key']: e['n'] for e in nv['errors']} == {'crNdErrMedia': 0, 'crNdErrLog': 12}
    sas = S(SMART_SAS)
    assert sas['temp'] == {'k': 'num', 'v': 35}
    assert {e['key']: e['n'] for e in sas['errors']} == {'crNdErrGrown': 2, 'crNdErrSasRead': 1, 'crNdErrSasWrite': 0}
    empty = S({})
    assert not empty['known'] and empty['temp'] == {'k': 'none'} and empty['errors'] == []
    odd = S({'type': 'text', 'text': 'Temperature:   unknown Celsius\nMedia and Data Integrity Errors:  -\n'})
    assert odd['temp'] == {'k': 'bad', 'raw': 'unknown'} and odd['errors'] == [{'key': 'crNdErrMedia', 'bad': '-', 'hard': True}]


def _disk_model(page, read, zfs=None):
    return page.evaluate('([r, z]) => window.PegaProxNodeHw.disks(r, z || {})', [read, zfs])


def test_rules_disk_rows_full_partial_and_empty(hw_page):
    read = [NODE_DISKS, NODE_LVM, NODE_LVMTHIN, NODE_ZFS]
    m = _disk_model(hw_page, read)
    rows = {r['dev']: r for r in m['rows']}
    assert m['state'] == 'ok' and list(rows) == ['nvme0n1', 'sda', 'sdb', 'sdc', 'sdd']
    assert rows['nvme0n1']['uses'] == [{'kind': 'lvm', 'name': 'pve', 'thin': ['data']}]
    assert rows['nvme0n1']['wear'] == {'state': 'ok', 'left': 97, 'used': 3} and rows['nvme0n1']['health']['state'] == 'ok'
    assert rows['sdc']['uses'] == [{'kind': 'lvm', 'name': 'ceph-5a1f', 'thin': []}, {'kind': 'ceph', 'name': '3'}]
    assert rows['sda']['zfsState'] == 'unread' and rows['sda']['uses'] == []
    assert rows['sdb']['health']['state'] == 'failed'
    # the empty row: nothing reported, nothing made up
    sdd = rows['sdd']
    assert sdd['health']['state'] == 'none' and sdd['wear']['state'] == 'none' and sdd['uses'] == [] and sdd['usedText'] == ''
    # with the pool read, both ZFS disks are found with the counts of their vdev
    m2 = _disk_model(hw_page, read, {'tank': {'state': 'ok', 'detail': TANK_DETAIL}})
    rows2 = {r['dev']: r for r in m2['rows']}
    assert rows2['sda']['uses'] == [{'kind': 'zfs', 'name': 'tank', 'vstate': 'ONLINE', 'read': 0, 'write': 0, 'cksum': 0}]
    assert rows2['sdb']['uses'] == [{'kind': 'zfs', 'name': 'tank', 'vstate': 'FAULTED', 'read': 3, 'write': 0, 'cksum': 12}]
    assert rows2['sda']['zfsState'] == ''
    assert {r['dev']: r['zfsState'] for r in _disk_model(hw_page, read, {'tank': {'state': 'error', 'fail': {}}})['rows']}['sda'] == 'failed'
    # failed and empty reads
    fail = {'__crFail': {'status': 502, 'error': 'Node pve1 did not answer', 'code': ''}}
    assert _disk_model(hw_page, [fail, None, None, None])['state'] == 'error'
    assert _disk_model(hw_page, [[], [], [], []])['state'] == 'empty'
    side = _disk_model(hw_page, [NODE_DISKS, fail, NODE_LVMTHIN, NODE_ZFS])
    assert side['side']['lvm'] and not side['side']['thin'] and {r['dev']: r['uses'] for r in side['rows']}['nvme0n1'] == []
    assert hw_page.evaluate('() => window.PegaProxNodeHw.disks(undefined, {}).state') == 'loading'


# --- the hardware tab ----------------------------------------------------------------------------

def test_runtime_sensors_by_kind_with_limits_and_states(open_app):
    app = open_app()
    page = app.page
    _open_hardware(page)
    _settled_hw(page)
    for g in ('temp', 'fan', 'psu', 'volt', 'other'):
        assert page.locator(f'[data-cr-nh-group="{g}"]').count() == 1, g
    assert _state(page, 'Package id 0') == 'normal'
    assert _state(page, 'Core 0') == 'high'
    assert _state(page, 'Core 1') == 'critical'
    assert _state(page, 'temp1') == 'nolimit'
    assert _state(page, 'temp2') == 'none'
    assert _state(page, 'temp3') == 'bad'
    assert _state(page, 'fan1') == 'nolimit' and _state(page, 'fan2') == 'zero'
    assert 'Reported as 0 RPM' in _row(page, 'fan2').inner_text()
    # a rail below its Max alone is not normal: no lower limit is reported
    assert _state(page, 'Vcore') == 'belowmax' and 'Below the upper limit' in _row(page, 'Vcore').inner_text()
    core0 = _row(page, 'Core 0')
    assert core0.locator('[data-cr-nh-cell="value"]').inner_text().strip() == '83.0 °C'
    assert core0.locator('[data-cr-nh-cell="max"]').inner_text().strip() == '80.0 °C'
    assert core0.locator('[data-cr-nh-cell="crit"]').inner_text().strip() == '100.0 °C'
    assert _row(page, 'temp2').locator('[data-cr-nh-cell="value"]').inner_text().strip() == 'not reported'
    assert 'not readable' in _row(page, 'temp3').locator('[data-cr-nh-cell="value"]').inner_text()
    assert _row(page, 'fan1').locator('[data-cr-nh-cell="max"]').inner_text().strip() == 'not reported'
    # the in-band rows sit in the same groups, power supplies in theirs, nothing read is not normal
    psu = page.locator('[data-cr-nh-group="psu"]')
    assert psu.locator('[data-cr-nh-row="PS1 Status"]').count() == 1 and _state(page, 'PS2 Status', 'bmc') == 'warning'
    assert _state(page, 'Pwr Consumption', 'bmc') == 'normal' and _state(page, 'FAN4', 'bmc') == 'none'
    assert page.locator('[data-cr-nh-group="fan"] [data-cr-nh-row="FAN1"]').count() == 1
    assert page.locator('[data-cr-nh-overall]').get_attribute('data-cr-nh-overall') == 'critical'
    counts = page.locator('[data-cr-nh-counts]').inner_text()
    assert 'Critical: 1' in counts and 'Warning or above Max: 2' in counts and 'Normal: 6' in counts and 'Without a state: 8' in counts
    assert page.locator('[data-cr-nh-src="bmc"]').inner_text().startswith('In-band monitoring: health Warning, 7 sensors')
    # the panel keeps its consent, system information and event log; its sensor card is the table above
    assert page.get_by_text('Example Systems').count() == 1 and page.get_by_text('Hardware event log (SEL) (1)').count() == 1
    assert page.get_by_text('Sensors (7)').count() == 0
    _no_errors(app)


def test_runtime_the_stored_temperatures_are_drawn(open_app):
    app = open_app()
    page = app.page
    _open_hardware(page)
    page.locator('[data-cr-nh-hist="ok"] [data-cr-chart="nh-temp"] canvas').wait_for(timeout=8000)
    stats = page.locator('[data-cr-nh-hist-stats]').inner_text()
    assert 'Points: 36' in stats and 'Highest: 56.0 °C' in stats and 'Lowest: 48.0 °C' in stats
    assert app.server.reads(TEMPS) == 1 and app.server.reads(SENSORS) == 1


def test_runtime_a_failed_sensor_read_says_why_and_retries(open_app):
    why = 'SSH is switched off for this cluster, and sensors are read over SSH'
    app = open_app(routes={('GET', SENSORS): (502, {'error': why, 'code': 'SSH_DISABLED'}),
                           ('GET', TEMPS): (500, {'error': 'history read failed: disk I/O error'})})
    page = app.page
    _open_hardware(page)
    _settled_hw(page)
    src = page.locator('[data-cr-nh-src="lm"]')
    assert src.get_attribute('data-cr-nh-src-state') == 'error'
    assert why in src.inner_text() and 'read over SSH' in src.inner_text()
    assert page.locator('[data-cr-nh-row-src="lm"]').count() == 0
    assert page.locator('[data-cr-nh-group="temp"] [data-cr-nh-row="Inlet Temp"]').count() == 1
    assert 'history read failed: disk I/O error' in page.locator('[data-cr-nh-hist="error"]').inner_text()
    app.server.routes[('GET', SENSORS)] = (200, NODE_SENSORS)
    page.locator('[data-cr-nh-retry]').click()
    _row(page, 'Core 0').wait_for(timeout=8000)
    assert app.server.reads(SENSORS) == 2


def test_runtime_in_band_off_says_what_to_do(open_app):
    app = open_app(routes={('GET', CONSENT): (200, dict(HW_CONSENT, enabled=False))})
    page = app.page
    _open_hardware(page)
    _settled_hw(page)
    assert page.locator('[data-cr-nh-src="bmc"]').get_attribute('data-cr-nh-src-state') == 'off'
    assert 'switch it on below' in page.locator('[data-cr-nh-src="bmc"]').inner_text()
    empty = page.locator('[data-cr-nh-empty="psu"]')
    assert 'Power supply states come from the in-band monitoring' in empty.inner_text()
    assert page.locator('[data-cr-nh-row-src="bmc"]').count() == 0
    assert page.get_by_text('Enable hardware monitoring').count() == 1
    assert app.server.reads(HW) == 0
    page.locator('[data-cr-nh-to-bmc]').first.click()
    _no_errors(app)


def test_runtime_while_the_sensors_are_read(open_app):
    app = open_app(routes={('GET', SENSORS): 'hold'})
    page = app.page
    _open_hardware(page)
    page.locator('[data-cr-nh-src="lm"][data-cr-nh-src-state="loading"]').wait_for(timeout=8000)
    assert 'lm-sensors: reading...' in page.locator('[data-cr-nh-src="lm"]').inner_text()
    assert page.locator('[data-cr-nh-overall]').count() == 0
    held = app.server.held.pop()
    held.fulfill(status=200, body=json.dumps(NODE_SENSORS), headers={'Content-Type': 'application/json'})
    _row(page, 'Core 1').wait_for(timeout=8000)


def test_runtime_no_sensors_and_no_history(open_app):
    app = open_app(routes={('GET', SENSORS): (200, {'sensors': [], 'count': 0}),
                           ('GET', TEMPS): (200, {'series': [], 'unit': '°C', 'count': 0}),
                           ('GET', HW): (200, {'available': False, 'reason': 'no BMC found (no /dev/ipmi0)'})})
    page = app.page
    _open_hardware(page)
    _settled_hw(page)
    assert 'found no sensors' in page.locator('[data-cr-nh-src="lm"]').inner_text()
    assert 'no BMC found' in page.locator('[data-cr-nh-src="bmc"]').inner_text()
    assert page.locator('[data-cr-nh-hist="empty"]').count() == 1
    assert page.locator('[data-cr-nh-empty="temp"]').inner_text().strip() == 'None reported.'
    assert page.locator('[data-cr-nh-overall]').get_attribute('data-cr-nh-overall') == 'none'
    assert page.locator('[data-cr-nh-state="normal"]').count() == 0


# --- the disks sub tab ---------------------------------------------------------------------------

def _drow(page, dev):
    return page.locator(f'[data-cr-nd-row="{dev}"]')


def _read_all(page, done):
    """Click Read and wait until the SMART answers of `done` disks are in and the button is back."""
    page.locator('[data-cr-nd-readall]').click()
    page.locator('[data-cr-nd-note]', has_text=f'SMART read for {done} of').wait_for(timeout=8000)
    page.wait_for_function('() => { const b = document.querySelector("[data-cr-nd-readall]"); '
                           'return b && !b.disabled; }', timeout=8000)


def _cell(page, dev, cell):
    return _drow(page, dev).locator(f'[data-cr-nd-cell="{cell}"]').inner_text().strip()


def test_runtime_disk_rows_with_full_partial_and_empty_data(open_app):
    app = open_app()
    page = app.page
    _open_disks(page)
    _drow(page, 'nvme0n1').wait_for(timeout=8000)
    assert page.locator('[data-cr-nd-row]').count() == 5
    assert _cell(page, 'nvme0n1', 'health') == 'PASSED' and _cell(page, 'nvme0n1', 'wear') == '3 % used'
    assert _cell(page, 'nvme0n1', 'use') == 'LVM pve, thin pool data'
    assert _cell(page, 'sdc', 'use') == 'LVM ceph-5a1f\nCeph OSD 3'
    assert _cell(page, 'sda', 'use') == 'ZFS, pool not read yet' and _cell(page, 'sda', 'wear') == 'not reported'
    assert _cell(page, 'sdb', 'health') == 'FAILED!' and 'cr-nh-row-crit' in _drow(page, 'sdb').get_attribute('class')
    assert _cell(page, 'sdc', 'health') == 'not reported'
    assert _drow(page, 'sdc').locator('[data-cr-nd-health="none"]').count() == 1
    assert _cell(page, 'sdd', 'type').startswith('type not reported') and 'model and serial not reported' in _drow(page, 'sdd').inner_text()
    assert _cell(page, 'sdd', 'use') == 'No use reported' and _cell(page, 'sdd', 'temp') == 'not read yet'
    assert page.locator('[data-cr-nd-failed]').inner_text() == 'Health failed: 1'
    assert 'I/O utilization per disk is not reported' in page.locator('[data-cr-nd-io]').inner_text()
    # nothing per disk or per pool on open
    assert app.server.reads_like(r'/smart$') == 0 and app.server.reads(TANK) == 0
    _read_all(page, 4)
    assert app.server.reads_like(r'/disks/[^/]+/smart$') == 5 and app.server.reads(TANK) == 1
    assert _cell(page, 'nvme0n1', 'temp') == '38 °C' and _cell(page, 'sda', 'temp') == '36 °C'
    assert 'Error log entries: 12' in _cell(page, 'nvme0n1', 'errors')
    assert 'Reallocated sectors: 8' in _cell(page, 'sda', 'errors')
    assert _cell(page, 'sda', 'use') == 'ZFS tank'
    sdb = _cell(page, 'sdb', 'errors')
    assert 'ZFS tank read errors: 3' in sdb and 'ZFS tank checksum errors: 12' in sdb
    assert _cell(page, 'sdb', 'use') == 'ZFS tank (FAULTED)' and _cell(page, 'sdb', 'temp') == 'not reported'
    assert _cell(page, 'sdc', 'temp') == 'SMART read failed' and _cell(page, 'sdd', 'temp') == 'not reported'
    assert _cell(page, 'sdd', 'errors') == 'not reported'
    assert 'SMART read for 4 of 5 disks' in page.locator('[data-cr-nd-note]').inner_text()
    _no_errors(app)


def test_runtime_the_smart_detail_stays_reachable(open_app):
    app = open_app()
    page = app.page
    _open_disks(page)
    page.locator('[data-cr-nd-smart="sda"]').click()
    # the module-level SmartModal of the Modern view, as it is (it files PVE's padded ids under the other attributes)
    page.get_by_text('Raw_Read_Error_Rate').first.wait_for(state='attached', timeout=8000)
    page.get_by_text(re.compile(r'SMART .*/dev/sda')).first.wait_for(timeout=8000)
    assert app.server.reads(DISKS + '/sda/smart') == 1 and app.server.reads_like(r'/smart$') == 1
    # the row took the answer too
    assert _cell(page, 'sda', 'temp') == '36 °C'
    _no_errors(app)


def test_runtime_the_disk_list_states(open_app):
    app = open_app(routes={('GET', DISKS): (502, {'error': 'Node pve1 did not answer'})})
    page = app.page
    _open_disks(page)
    err = page.locator('[data-cr-nd-list="error"]')
    err.wait_for(timeout=8000)
    assert 'Node pve1 did not answer' in err.inner_text()
    app.server.routes[('GET', DISKS)] = (200, [])
    err.locator('button').click()
    page.locator('[data-cr-nd-list="empty"]').wait_for(timeout=8000)
    assert 'can also be a failed read' in page.locator('[data-cr-nd-list="empty"]').inner_text()
    app.server.routes[('GET', DISKS)] = 'hold'
    page.locator('[data-cr-nd-reload]').click()
    page.locator('[data-cr-nd-list="empty"]').wait_for(timeout=8000)
    app.server.held.pop().fulfill(status=200, body=json.dumps(NODE_DISKS), headers={'Content-Type': 'application/json'})
    _drow(page, 'sdd').wait_for(timeout=8000)


def test_runtime_disks_while_read_and_a_failed_side_list(open_app):
    app = open_app(routes={('GET', DISKS): 'hold', ('GET', LVM): (500, {'error': 'lvs failed'})})
    page = app.page
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Configure').click()
    page.locator('[data-cr-nn-row="vmbr0"]').wait_for(timeout=8000)
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*Disks\s*$')).first.click()
    page.locator('[data-cr-nd-list="loading"]').wait_for(timeout=8000)
    app.server.held.pop().fulfill(status=200, body=json.dumps(NODE_DISKS), headers={'Content-Type': 'application/json'})
    side = page.locator('[data-cr-nd-side="lvm"]')
    side.wait_for(timeout=8000)
    assert 'lvs failed' in side.inner_text()
    assert _cell(page, 'nvme0n1', 'use') == 'In use: LVM'


# --- classic, layout ------------------------------------------------------------------------------

def test_runtime_classic_corporate_is_unchanged(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _open_hardware(page, redesigned=False)
    page.get_by_text('Package id 0').first.wait_for(timeout=8000)
    page.get_by_text('Sensors (7)').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-nh]').count() == 0
    assert page.get_by_text('Chip', exact=True).count() == 1
    page.locator('.corp-tab-strip button', has_text='Configure').first.click()
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*Disks\s*$')).first.click()
    page.get_by_text('/dev/nvme0n1').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-nd]').count() == 0
    table = page.locator('.corp-datagrid').filter(has=page.get_by_text('/dev/nvme0n1', exact=True))
    assert table.locator('thead th').count() == 4
    assert app.server.reads_like(r'/smart$') == 0


_NO_SIDEWAYS = '() => document.scrollingElement.scrollWidth <= window.innerWidth'
# the app scrolls inside #cr-main, so a too wide pane shows there and not on the document
_MAIN_FITS = "() => { const m = document.getElementById('cr-main'); return !m || m.scrollWidth <= m.clientWidth + 1; }"


@pytest.mark.parametrize('engine,width', [('chromium', 1600), ('chromium', 1280), ('chromium', 1024),
                                          ('firefox', 1600), ('firefox', 1280), ('firefox', 1024)])
def test_runtime_layout_without_sideways_scroll(open_app, firefox, browser, engine, width):
    app = open_app(viewport=(width, 900), br=firefox if engine == 'firefox' else browser)
    page = app.page
    _open_hardware(page)
    _settled_hw(page)
    page.locator('[data-cr-chart="nh-temp"]').wait_for(timeout=8000)
    assert page.evaluate(_NO_SIDEWAYS)
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Configure').click()
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*Disks\s*$')).first.click()
    _drow(page, 'sdd').wait_for(timeout=8000)
    _read_all(page, 4)
    assert page.evaluate(_NO_SIDEWAYS)
    assert page.evaluate(_MAIN_FITS), 'the disks section widens the page'
    scroll = page.locator('[data-cr-nd] .cr-nn-scroll')
    if width >= 1280:
        assert scroll.evaluate('e => e.scrollWidth <= e.clientWidth + 1'), 'the disk table scrolls sideways'
    else:
        # narrow: the table may scroll, but only inside its own box
        assert scroll.evaluate('e => e.getBoundingClientRect().right <= document.getElementById("cr-main").getBoundingClientRect().right + 1')
    _no_errors(app)
