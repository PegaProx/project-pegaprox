"""What the classic VM views (Corporate detail view, Modern compact panel) show of the
guest's Proxmox HA resource, its lock and the guest agent's lists.

- HA: the restart and relocate limits are the resource's own (0 is a real value in
  PVE), a limit the resource does not state is PVE's default and says "Default" (here
  and in the Datacenter HA table), and a list that could not be read (the route's 502
  included) is "unknown", never "disabled". After a toggle the card reads the list
  again instead of printing the values it sent. A guest of an XCP-ng or ESXi
  connection gets no Proxmox HA card and no read of the list.
- Lock: a lock read that failed, or that the server could not do (read: false), is
  "unknown", not "not locked". The Modern panel starts every guest from a clean lock
  state and drops a late answer for the guest shown before, like Corporate (#828).
- Guest agent lists: a field that is not a list (null, an object, a string) renders
  as nothing instead of taking the whole app down; entries that are fine still show.

They drive the built bundle with the fake server of test_ha_ui.py, in Chromium and,
for the cards that got new lines, in Firefox. They skip where Playwright is missing.
NS
"""
import re
import time

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, VM, _App, _FakeServer, _read
from test_ha_node_ui import _NodeHaServer
from test_stale_responses_828 import _SlowServer

G = '/api/clusters/c1/vms/pve1/qemu/100'
HA = '/api/clusters/c1/proxmox-ha/resources'
LOCK_UNREAD = {'locked': False, 'lock_reason': None, 'lock_description': None, 'unlock_command': None,
               'note': 'Could not determine lock status', 'read': False}
NOT_LOCKED = {'locked': False, 'lock_reason': None, 'lock_description': None, 'unlock_command': 'qm unlock 100'}


@pytest.fixture(scope='module')
def engines():
    """One Playwright for the module, a browser per engine on first use."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    started = {}

    def get(name):
        if name not in started:
            try:
                started[name] = getattr(pw, name).launch(headless=True)
            except Exception as e:
                pytest.skip(f'no {name} for Playwright: {e}')
        return started[name]
    yield get
    for br in started.values():
        br.close()
    pw.stop()


@pytest.fixture
def open_vm(engines):
    apps = []

    def _open(layout, engine='chromium', answers=None, cluster=CLUSTER):
        """answers: path (a GET) or (method, path) -> (status, body)."""
        reads = {('GET', G + '/lock'): (200, NOT_LOCKED), ('GET', HA): (200, [])}
        reads.update({(k if isinstance(k, tuple) else ('GET', k)): v for k, v in (answers or {}).items()})
        server = _FakeServer(role='standalone', layout=layout, clusters=[cluster], resources=[VM],
                             metrics=NODE_METRICS, extra=reads)
        app = _App(engines(engine), server)
        apps.append(app)
        page = app.page
        if layout == 'corporate':
            page.locator('.corp-tree-item', has_text='Testi').first.click()
            page.locator('.corp-tree-child', has_text='web01').first.click()
            _wait_unless_gone(app, 'Snapshots')
        else:
            page.get_by_text('Testi').first.click()
            page.locator('button', has_text='Resources').first.click()
            page.get_by_text('web01').first.wait_for(timeout=8000)
            page.locator('button[title="Compact View"]').first.click()
            page.locator('div.cursor-pointer', has_text='web01').first.click()
            _wait_unless_gone(app, 'Quick Actions')
        page.wait_for_timeout(600)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _crashes(app):
    return [e for e in app.errors if 'pageerror' in e]


def _gone(app):
    """A render error unmounts the whole React root: no header, a blank page."""
    return not app.page.evaluate('() => !!document.querySelector("header")')


def _wait_unless_gone(app, text, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if _gone(app) or app.page.get_by_text(text).count():
            return
        app.page.wait_for_timeout(100)
    app.page.get_by_text(text).first.wait_for(timeout=1000)


def _see_or_crash(app, text):
    """Waits for the text, or for the app to go blank: that crash is the failure to report."""
    _wait_unless_gone(app, text)
    assert not _gone(app), f'the app went blank: {app.errors}'
    assert not _crashes(app), app.errors
    app.page.get_by_text(text).first.wait_for(timeout=1000)


def _ha_card(app, layout):
    # by its heading, so the same lookup finds the card of the code before this change
    if layout == 'corporate':
        return app.page.locator("xpath=//span[normalize-space()='Proxmox HA']/../..").first
    return app.page.locator("xpath=//div[contains(@class, 'text-xs') and normalize-space()='Proxmox HA']/..").first


def _ha_button(card):
    return card.locator('button').first


def _limits(card, layout):
    text = re.sub(r'\s+', ' ', card.inner_text())
    if layout == 'corporate':
        m = re.search(r'Max Restart: (\S+) \| Max Relocate: (\S+)', text)
    else:
        m = re.search(r'Max\. Restarts: ?(\S+) Max\. Relocate: ?(\S+)', text)
    assert m, text
    return m.groups()


ENGINES = ['chromium', 'firefox']
LAYOUTS = ['corporate', 'modern']


def test_the_unread_list_key_is_in_every_language_once():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [at for at, _ in starts[1:]] + [len(src)]
    blocks = {lang: src[at:end] for (at, lang), end in zip(starts, ends)}
    assert list(blocks) == ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
    seen = set()
    for lang, block in blocks.items():
        found = re.findall(r"^\s+haResourcesUnread: '((?:[^'\\]|\\.)*)',$", block, re.M)
        assert len(found) == 1, lang
        assert '\u2014' not in found[0] and '\u2013' not in found[0], lang
        # next to the empty-list text it stands in for, not at the pinned end of the block
        lines = block.split('\n')
        at = next(i for i, line in enumerate(lines) if 'haResourcesUnread:' in line)
        assert 'noVmsWithHa:' in lines[at - 1], lang
        seen.add(found[0])
    assert len(seen) == 10


def test_the_default_label_of_an_unstated_limit_is_in_every_language():
    """The HA cards and the Datacenter table reuse 'default' for a limit PVE fills in."""
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [at for at, _ in starts[1:]] + [len(src)]
    for (at, lang), end in zip(starts, ends):
        assert re.search(r"^\s+default: '[^']+',$", src[at:end], re.M), lang
    for name in ('vm_modals.js', 'datacenter.js'):
        assert "t('default'))" in _read('web', 'src', name), name


# -- HA ---------------------------------------------------------------------------------

@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_the_ha_card_shows_the_resources_own_limits(open_vm, layout, engine):
    app = open_vm(layout, engine, {HA: (200, [{'sid': 'vm:100', 'state': 'started', 'max_restart': 0,
                                              'max_relocate': 2}])})
    card = _ha_card(app, layout)
    card.get_by_text(re.compile('Max')).first.wait_for(timeout=5000)
    # 0 is "do not restart" in PVE, not a missing value
    assert _limits(card, layout) == ('0', '2')
    assert not _crashes(app), app.errors


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_limit_the_resource_does_not_state_is_the_default(open_vm, layout):
    # PVE then applies its own default; it is not a number this view has read
    app = open_vm(layout, answers={HA: (200, [{'sid': 'vm:100', 'state': 'started'}])})
    card = _ha_card(app, layout)
    card.get_by_text(re.compile('Max')).first.wait_for(timeout=5000)
    assert _limits(card, layout) == ('Default', 'Default')


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', LAYOUTS)
@pytest.mark.parametrize('status', [502, 500, 403, 404])
def test_runtime_an_unread_ha_list_is_unknown_not_disabled(open_vm, layout, engine, status):
    app = open_vm(layout, engine, {HA: (status, {'error': 'nope'})})
    card = _ha_card(app, layout)
    text = re.sub(r'\s+', ' ', card.inner_text())
    assert 'Unknown' in text, text
    assert 'disabled' not in text.lower() and 'Inactive' not in text, text
    assert 'Max' not in text, text
    # neither "add" nor "remove" is the right offer while the state is not known
    assert _ha_button(card).is_disabled()
    assert not _crashes(app), app.errors


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_guest_outside_ha_still_reads_as_disabled(open_vm, layout):
    """The guard of the old behaviour: a list that was read and lacks the guest."""
    app = open_vm(layout, answers={HA: (200, [{'sid': 'vm:555', 'max_restart': 1}])})
    card = _ha_card(app, layout)
    text = re.sub(r'\s+', ' ', card.inner_text())
    assert ('disabled' if layout == 'corporate' else 'Inactive') in text, text
    assert 'Unknown' not in text and 'Max' not in text, text
    assert _ha_button(card).is_enabled()


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_after_enabling_the_card_shows_what_pve_holds_not_what_was_sent(open_vm, layout):
    app = open_vm(layout, answers={('POST', HA): (200, {'success': True})})
    card = _ha_card(app, layout)
    # what PVE lists once the add went through (another tool may have changed it already)
    app.server.extra[('GET', HA)] = (200, [{'sid': 'vm:100', 'state': 'started', 'max_restart': 1,
                                            'max_relocate': 0}])
    reads = app.server.calls.count(('GET', HA))
    _ha_button(card).click()
    card.get_by_text(re.compile('Max')).first.wait_for(timeout=5000)
    app.page.wait_for_timeout(500)
    assert _limits(card, layout) == ('1', '0')
    # the add itself keeps its defaults for a new resource (the GETs log an empty body)
    posted = [b for b in app.server.bodies[HA] if b]
    assert posted == [{'vmid': 100, 'type': 'vm', 'max_restart': 3, 'max_relocate': 3}]
    # one read after the change, no polling
    assert app.server.calls.count(('GET', HA)) == reads + 1


@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', LAYOUTS)
@pytest.mark.parametrize('kind', ['xcpng', 'esxi'])
def test_runtime_a_guest_of_another_hypervisor_gets_no_proxmox_ha_card(open_vm, layout, kind, engine):
    # those managers have no Proxmox HA: the card could only ever say "unknown"
    app = open_vm(layout, engine, cluster=dict(CLUSTER, cluster_type=kind))
    assert app.page.get_by_text('web01').first.is_visible()
    assert _ha_card(app, layout).count() == 0
    # the rest of the view is still there, nothing slid sideways
    assert app.page.evaluate('() => document.documentElement.scrollWidth <= window.innerWidth + 1')
    assert ('GET', HA) not in app.server.calls
    assert not _crashes(app), app.errors


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_proxmox_guest_keeps_its_ha_card(open_vm, layout):
    """The guard: an explicit 'proxmox' (and the default in every other test) shows it."""
    app = open_vm(layout, cluster=dict(CLUSTER, cluster_type='proxmox'))
    assert _ha_card(app, layout).count() == 1
    assert ('GET', HA) in app.server.calls


# -- the cluster's HA list (Modern settings tab, Cloud HA page) ---------------------------

def _native_ha(app, layout):
    page = app.page
    if layout == 'modern':
        page.get_by_text('Testi').first.click()
        page.get_by_role('button', name='Settings', exact=True).first.click()
        page.get_by_text('Proxmox Native HA').first.wait_for(timeout=5000)
        return page.locator('div.pt-4', has=page.locator('h4', has_text='Proxmox Native HA')).first
    page.get_by_text('High Availability', exact=True).first.click()
    page.locator('.cloud-mounted').first.wait_for(timeout=5000)
    return page.locator('.cloud-mounted').first


@pytest.fixture
def open_ha_list(engines):
    apps = []

    def _open(layout, answer):
        app = _App(engines('chromium'), _NodeHaServer(layout=layout, extra={('GET', HA): answer}))
        apps.append(app)
        return app, _native_ha(app, layout)
    yield _open
    for app in apps:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'cloud'])
def test_runtime_the_cluster_list_shows_a_restart_limit_of_zero(open_ha_list, layout):
    app, box = open_ha_list(layout, (200, [{'sid': 'vm:100', 'max_restart': 0}, {'sid': 'ct:101'}]))
    box.get_by_text('VM 100').first.wait_for(timeout=5000)
    text = re.sub(r'\s+', ' ', box.inner_text())
    assert 'VM 100 Max Restart: 0' in text, text
    assert 'CT 101 Max Restart: Default' in text, text
    assert not _crashes(app), app.errors


@pytest.mark.parametrize('layout', ['modern', 'cloud'])
@pytest.mark.parametrize('status', [502, 500])
def test_runtime_an_unread_cluster_list_does_not_say_no_guests(open_ha_list, layout, status):
    app, box = open_ha_list(layout, (status, {'error': 'nope'}))
    box.get_by_text('The Proxmox HA resources could not be read').first.wait_for(timeout=5000)
    text = box.inner_text()
    assert 'No VMs configured with Proxmox HA' not in text, text
    assert '0 VMs/CTs with Proxmox HA' not in text, text


# -- the Datacenter HA table and its add form (datacenter.js) -------------------------------

@pytest.fixture
def open_dc_ha(engines):
    apps = []

    def _open(rows):
        server = _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM],
                             metrics=NODE_METRICS,
                             extra={('GET', HA): (200, rows), ('POST', HA): (200, {'success': True}),
                                    ('GET', '/api/clusters/c1/resources'): (200, [VM])})
        app = _App(engines('chromium'), server)
        apps.append(app)
        page = app.page
        page.get_by_text('Testi').first.click()
        page.get_by_role('button', name='Datacenter', exact=True).first.click()
        page.get_by_text('Proxmox Native HA').first.click()
        table = page.locator('table', has=page.locator('th', has_text='Max Relocate')).first
        table.wait_for(timeout=8000)
        return app, table
    yield _open
    for app in apps:
        app.ctx.close()


def _dc_row(table, sid):
    row = table.locator('tr', has=table.page.locator('td', has_text=sid)).first
    row.wait_for(timeout=5000)
    cells = [c.strip() for c in row.locator('td').all_inner_texts()]
    return cells[3], cells[4]


def test_runtime_the_datacenter_table_shows_a_zero_and_the_default(open_dc_ha):
    app, table = open_dc_ha([{'sid': 'vm:100', 'state': 'started', 'max_restart': 0, 'max_relocate': 2},
                             {'sid': 'ct:101', 'state': 'started'}])
    assert _dc_row(table, 'vm:100') == ('0', '2')
    # left out: PVE's default, the same wording as the VM cards (not a 1 nobody read)
    assert _dc_row(table, 'ct:101') == ('Default', 'Default')
    assert not _crashes(app), app.errors


def test_runtime_the_datacenter_add_form_keeps_a_zero(open_dc_ha):
    app, table = open_dc_ha([])
    page = app.page
    # the Add of the Resources card the table sits in (the groups card has its own)
    table.locator("xpath=ancestor::div[contains(@class, 'rounded-xl')][1]//button[normalize-space()='Add']").click()
    form = page.locator('div.fixed', has_text='Add: Resource').first
    form.wait_for(timeout=5000)
    restart = form.locator("xpath=.//label[normalize-space()='Max. Restart:']/following-sibling::input")
    relocate = form.locator("xpath=.//label[normalize-space()='Max. Relocate:']/following-sibling::input")
    # a new resource starts at 1/1 as before
    assert (restart.input_value(), relocate.input_value()) == ('1', '1')
    restart.fill('0')
    relocate.fill('0')
    assert (restart.input_value(), relocate.input_value()) == ('0', '0')
    form.locator('select').first.select_option('vm:100')
    form.locator('button', has_text=re.compile(r'^Add$')).click()
    deadline = time.time() + 5
    while time.time() < deadline and not [b for b in app.server.bodies.get(HA, []) if b]:
        page.wait_for_timeout(100)
    posted = [b for b in app.server.bodies.get(HA, []) if b]
    assert posted and posted[-1]['max_restart'] == 0 and posted[-1]['max_relocate'] == 0, posted
    assert posted[-1]['sid'] == 'vm:100'


# -- lock ---------------------------------------------------------------------------------

@pytest.mark.parametrize('engine', ENGINES)
@pytest.mark.parametrize('layout', LAYOUTS)
@pytest.mark.parametrize('answer', [pytest.param((200, LOCK_UNREAD), id='read-false'),
                                    pytest.param((500, {'error': 'boom'}), id='http-500'),
                                    pytest.param((403, {'error': 'no'}), id='http-403')])
def test_runtime_a_lock_that_could_not_be_read_is_unknown(open_vm, layout, engine, answer):
    app = open_vm(layout, engine, {G + '/lock': answer})
    page = app.page
    page.get_by_text('Lock Status: Unknown').first.wait_for(timeout=5000)
    assert page.get_by_text('Lock Status: Unknown').first.is_visible()
    # and it does not turn into a lock either
    assert page.get_by_role('button', name='Unlock').count() == 0
    assert page.locator('.corp-badge-locked').count() == 0
    assert not _crashes(app), app.errors


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_lock_read_that_answered_shows_no_unknown(open_vm, layout):
    app = open_vm(layout)
    page = app.page
    page.wait_for_timeout(300)
    assert page.get_by_text('Lock Status: Unknown').count() == 0
    assert page.locator('.corp-badge-locked').count() == 0


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_locked_guest_still_shows_its_lock(open_vm, layout):
    app = open_vm(layout, answers={G + '/lock': (200, {'locked': True, 'lock_reason': 'backup',
                                                 'lock_description': 'Backup in progress',
                                                 'unlock_command': 'qm unlock 100'})})
    page = app.page
    page.get_by_text('backup').first.wait_for(timeout=5000)
    assert page.get_by_text('Lock Status: Unknown').count() == 0


# Modern: the lock of the guest shown before (#828, as in the Corporate view) --------------

VM_B = dict(VM, vmid=101, name='db01')
G_B = '/api/clusters/c1/vms/pve1/qemu/101'


@pytest.fixture
def open_modern_two(engines):
    apps = []

    def _open(hold=(), **answers):
        base = {G + '/lock': (200, NOT_LOCKED), G_B + '/lock': (200, NOT_LOCKED), HA: (200, [])}
        base.update(answers)
        server = _SlowServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM, VM_B],
                             metrics=NODE_METRICS, answers=base, hold=hold)
        app = _App(engines('chromium'), server)
        apps.append(app)
        page = app.page
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text='Resources').first.click()
        page.get_by_text('db01').first.wait_for(timeout=8000)
        page.locator('button[title="Compact View"]').first.click()
        page.locator('div.cursor-pointer', has_text='db01').first.wait_for(timeout=8000)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _pick(app, name):
    app.page.locator('div.cursor-pointer', has_text=name).first.click()


def _until(app, check, what, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if check():
            return
        app.page.wait_for_timeout(100)
    raise AssertionError(f'timed out waiting for {what}')


def test_runtime_modern_drops_the_previous_guests_unknown_while_the_next_loads(open_modern_two):
    app = open_modern_two(hold={G_B + '/lock'}, **{G + '/lock': (200, LOCK_UNREAD)})
    page = app.page
    _pick(app, 'web01')
    page.get_by_text('Lock Status: Unknown').first.wait_for(timeout=5000)

    _pick(app, 'db01')
    _until(app, lambda: app.server.waiting.get(G_B + '/lock'), "db01's lock read")
    page.wait_for_timeout(300)
    # web01's "unknown" says nothing about db01, whose answer is not in yet
    assert page.get_by_text('Lock Status: Unknown').count() == 0
    app.server.let_go(G_B + '/lock', 200, NOT_LOCKED)
    page.wait_for_timeout(500)
    assert page.get_by_text('Lock Status: Unknown').count() == 0


LATE_LOCK = [
    pytest.param(200, {'locked': True, 'lock_reason': 'backup', 'lock_description': 'lock-of-web01',
                       'unlock_command': 'qm unlock 100'}, id='locked'),
    pytest.param(200, LOCK_UNREAD, id='read-false'),
    pytest.param(500, {'error': 'boom'}, id='http-error'),
]


@pytest.mark.parametrize('status,body', LATE_LOCK)
def test_runtime_modern_a_late_lock_answer_of_the_previous_guest_never_lands(open_modern_two, status, body):
    app = open_modern_two(hold={G + '/lock'})
    page = app.page
    _pick(app, 'web01')
    _until(app, lambda: app.server.waiting.get(G + '/lock'), "web01's lock read")

    _pick(app, 'db01')
    _until(app, lambda: ('GET', G_B + '/lock') in app.server.calls, "db01's lock read")
    page.wait_for_timeout(400)
    app.server.let_go(G + '/lock', status, body)
    page.wait_for_timeout(700)
    assert page.locator('span[title="lock-of-web01"]').count() == 0, "web01's lock landed on db01"
    assert page.get_by_text('Lock Status: Unknown').count() == 0, "web01's unknown landed on db01"
    assert not _crashes(app), app.errors


# -- guest agent lists ------------------------------------------------------------------------

def _agent(value):
    return {'agent_running': True, 'hostname': 'host-of-web01', 'os_pretty_name': 'Debian 13',
            'ip_addresses': value, 'interfaces': value, 'filesystems': value, 'users': value}


def _ip_cell(app, layout):
    page = app.page
    if layout == 'corporate':
        # the first IP row is the one in the header grid of the summary
        row = page.locator('table.corp-property-grid tr', has=page.locator('td', has_text=re.compile(r'^IP$')))
        return row.first.locator('td').nth(1)
    return page.locator("xpath=//div[normalize-space()='IP Address']/following-sibling::div[1]")


BAD = [pytest.param('10.0.0.5', id='string'), pytest.param({'eth0': '10.0.0.5'}, id='object'),
       pytest.param(None, id='null'), pytest.param(7, id='number')]


@pytest.mark.parametrize('layout', LAYOUTS)
@pytest.mark.parametrize('value', BAD)
def test_runtime_a_guest_list_of_the_wrong_shape_does_not_take_the_app_down(open_vm, layout, value):
    app = open_vm(layout, answers={G + '/guest-info': (200, _agent(value)),
                                   G + '/guest-fsinfo': (200, {'filesystems': value})})
    page = app.page
    _see_or_crash(app, 'host-of-web01')
    assert page.get_by_text('web01').first.is_visible()
    if layout == 'corporate':
        assert _ip_cell(app, layout).inner_text().strip() == '-'
    else:
        assert _ip_cell(app, layout).count() == 0


def test_runtime_the_entries_that_are_fine_still_show(open_vm):
    info = dict(_agent(None),
                ip_addresses=['10.0.0.5', None, {'x': 1}, 'fd00::5'],
                interfaces=[{'name': 'ens18', 'mac': 'bc:24:11:00:00:01', 'ips': 'junk'}, None,
                            {'name': 'ens19', 'mac': 'bc:24:11:00:00:02',
                             'ips': [None, {'address': '10.0.1.5', 'prefix': 24}]}],
                filesystems=[None, {'mountpoint': '/srv', 'type': 'ext4', 'used_bytes': 1 << 30,
                                    'total_bytes': 4 << 30, 'used_pct': 25}],
                users=[None, {'user': 'operator', 'login_time': 1700000000}])
    fsinfo = {'filesystems': [None, {'mountpoint': '/data', 'used_pct': 40}]}
    app = open_vm('corporate', answers={G + '/guest-info': (200, info), G + '/guest-fsinfo': (200, fsinfo)})
    page = app.page
    _see_or_crash(app, 'host-of-web01')
    assert _ip_cell(app, 'corporate').inner_text().strip() == '10.0.0.5, fd00::5'
    page.locator('details summary').first.click()
    detail = re.sub(r'\s+', ' ', page.locator('details').first.inner_text())
    for shown in ('ens18', 'bc:24:11:00:00:01', 'ens19', '10.0.1.5/24', '/srv', 'operator'):
        assert shown in detail, (shown, detail)
    assert 'object' not in detail and 'undefined' not in detail, detail
    page.get_by_text('/data').first.wait_for(timeout=5000)


def test_runtime_modern_shows_the_ips_that_are_strings(open_vm):
    info = dict(_agent(None), ip_addresses=['10.0.0.5', None, {'x': 1}])
    app = open_vm('modern', answers={G + '/guest-info': (200, info)})
    _see_or_crash(app, 'host-of-web01')
    assert _ip_cell(app, 'modern').inner_text().strip() == '10.0.0.5'
