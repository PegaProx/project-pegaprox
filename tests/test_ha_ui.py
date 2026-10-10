"""The warm standby in the web UI (#625).

Three pieces: the auth context keeps the `ha` object the server sends on login and
/auth/check, the settings modal gets a High Availability tab for admins, and every
layout shows a banner on a standby. The routes behind the panel are tested with the
API; these read the source and the bundle so the wiring cannot drift apart quietly.

Two traps the tests below hold shut: t() returns the key itself on a miss, so a
missing translation shows up raw instead of falling back, and the Tailwind build is
static, so a class that is not in static/css/tailwind.min.css simply does nothing.

The runtime tests at the end drive the built bundle in headless Chromium against a
fake server; they skip where Playwright is not installed.
LW
"""
import json
import os
import re
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'web', 'src')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


@pytest.fixture(scope='module')
def ctx():
    return _read('web', 'src', 'contexts.js')


@pytest.fixture(scope='module')
def modal():
    return _read('web', 'src', 'settings_modal.js')


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def cloud():
    return _read('web', 'src', 'cloud.js')


@pytest.fixture(scope='module')
def panel(modal):
    """Everything the HA section of settings_modal.js defines, from its header to the end."""
    return modal[modal.index('// PegaProx - High Availability (#625)'):]


@pytest.fixture(scope='module')
def banner(dash):
    start = dash.index('function HaStandbyBanner(')
    return dash[start:dash.index('function ClusterSidebarItem(', start)]


def _function(src, name):
    start = src.index(f'function {name}(')
    nxt = re.search(r'\n        function \w+\(', src[start + 1:])
    return src[start:start + 1 + nxt.start()] if nxt else src[start:]


# -- AuthContext ------------------------------------------------------------------

def test_the_context_keeps_ha_and_defaults_to_standalone(ctx):
    assert "const [ha, setHa] = useState({ role: 'standalone' });" in ctx
    provider = ctx[ctx.index('<AuthContext.Provider value={{'):]
    provider = provider[:provider.index('}}>')]
    assert ' ha,' in provider and 'refreshHa' in provider


def test_ha_comes_from_check_login_and_the_401(ctx):
    check = ctx[ctx.index('const checkSession = async'):ctx.index('const login = async')]
    assert 'applyHa(d.ha);' in check
    assert 'if (errData.ha_role) applyHa({ role: errData.ha_role });' in check
    login = ctx[ctx.index('const login = async'):ctx.index('const updatePreferences')]
    assert 'applyHa(data.ha);' in login


def test_anything_without_a_role_reads_as_standalone(ctx):
    start = ctx.index('const applyHa = (next) => {')
    body = ctx[start:ctx.index('\n            };', start)]
    assert "next.role) ? next : { role: 'standalone' }" in body


def test_only_an_instance_of_a_group_polls_the_banner(ctx):
    # a standby for its sync time, the leader for the banners of an automatic group (#625)
    start = ctx.index('const h = setInterval(refreshHa, ha.automatic === true ? 10000 : 30000);')
    effect = ctx[ctx.rindex('useEffect(', 0, start):ctx.index('}, [', start)]
    assert "if (!isAuthenticated || (ha.role !== 'standby' && ha.role !== 'active')) return;" in effect


# -- settings modal -----------------------------------------------------------------

def test_the_panel_and_its_helpers_exist(panel):
    for name in ('function haRelTime(', 'function HaRoleBadge(', 'function HaRestartOverlay(',
                 'function HaPanel({ t, addToast, getAuthHeaders })'):
        assert name in panel, name


def test_the_tab_is_admin_gated(modal):
    component = _function(modal, 'PegaProxSettingsModal')
    assert 'const { getAuthHeaders, user: currentUser, isAdmin, haStandby } = useAuth();' in component

    button_at = component.index("onClick={() => setActiveTab('ha')}")
    gate_at = component.rindex('{isAdmin && (', 0, button_at)
    # nothing but the button itself between the gate and the handler
    assert component[gate_at:button_at].count('<button') == 1
    assert "{t('pgHaTab')}" in component[button_at:component.index('</button>', button_at)]

    assert "{activeTab === 'ha' && isAdmin && (" in component
    mount = component[component.index("{activeTab === 'ha' && isAdmin && ("):]
    assert mount[:200].count('<HaPanel t={t} addToast={addToast} getAuthHeaders={getAuthHeaders} />') == 1


def test_the_modal_switches_to_the_tab_on_the_banner_event(modal):
    component = _function(modal, 'PegaProxSettingsModal')
    assert "const toHa = () => setActiveTab('ha');" in component
    assert "window.addEventListener('pegaprox-navigate-ha', toHa);" in component
    assert "window.removeEventListener('pegaprox-navigate-ha', toHa);" in component


def test_the_panel_speaks_the_agreed_contract(panel):
    body = _function(panel, 'HaPanel')
    assert '`${API_URL}/ha/status`' in body
    assert "send('POST', 'pairing-code', withPassword('code', { url }))" in body
    assert "send('POST', 'join', withPassword('join', { code: joinCode.trim(), own_url: url, confirm: true }))" in body
    assert "send('POST', 'sync-now'" in body
    assert "send('PUT', 'settings', { interval: n })" in body
    assert "const WORD = { promote: 'PROMOTE', unpair: 'UNPAIR', remove: 'REMOVE' };" in body
    # promote and unpair post to their own name, remove to the member it is about
    assert "const path = what === 'remove' ? `members/${encodeURIComponent(target.instance_id)}/remove` : what;" in body
    assert "const body = { confirm: WORD[what], ...(shutDownNow ? { shut_down: true } : {}), ...(forceNow ? { force: true } : {}) };" in body
    assert "send('POST', path, withPassword('confirm', body))" in body
    # the server's own error text, not a fixed string, and its code next to it
    assert 'await PegaProxApiErrors.message(r, fallback' in body
    assert "const code = (await r.clone().json().catch(() => null))?.code || '';" in body


def test_typed_confirmation_is_exact(panel):
    body = _function(panel, 'HaPanel')
    assert ("disabled={typed !== WORD[confirmAction] || needsPassword('confirm') || (needShutDown && !shutDown) "
            "|| (needForce && !forcePromote) || !!busy}") in body


def test_join_needs_the_checkbox_and_a_code(panel):
    body = _function(panel, 'HaPanel')
    assert "disabled={!joinConfirm || !joinCode.trim() || needsPassword('join') || !!busy}" in body
    assert "t('pgHaJoinWarning')" in body


# -- re-authentication (#625 review) ------------------------------------------------------

def test_every_handover_action_asks_for_the_password(panel):
    """Pairing code, join, promote and unpair each carry the account password."""
    body = _function(panel, 'HaPanel')
    assert "const withPassword = (form, body) => sso ? body : { ...body, user_password: passwords[form] };" in body
    for form in ('code', 'join', 'confirm'):
        assert body.count(f"withPassword('{form}', ") == 1, form
        assert f"passwordInput('{form}', 'pgha-{form}-password')" in body, form
        assert f"reauthNote('{form}', 'pgha-{form}-password')" in body, form
        assert f"needsPassword('{form}')" in body, form
    # promote and unpair share the typed box, and so its password field
    typed_box = body[body.index('const typedBox = '):body.index('if (!status) {')]
    assert "passwordInput('confirm', 'pgha-confirm-password')" in typed_box
    # the pairing-code button waits for the password too
    assert "<button onClick={createCode} disabled={needsPassword('code') || !!busy}" in body
    # the field itself: a current password, kept away from password managers like the
    # root password fields of the auto-install wizard
    field = body[body.index('const passwordInput = (form, id) =>'):body.index('const reauthNote = ')]
    for attr in ('type="password"', 'autoComplete="current-password"', 'data-lpignore="true"',
                 'data-1p-ignore="true"', 'data-bwignore="true"', "{t('pgHaPassword')}"):
        assert attr in field, attr


def test_sso_accounts_type_no_password(panel):
    body = _function(panel, 'HaPanel')
    assert "const sso = ['oidc', 'entra'].includes(user?.auth_source);" in body
    assert "const needsPassword = (form) => !sso && !passwords[form];" in body
    assert "const passwordInput = (form, id) => !sso && (" in body
    assert 'const { refreshHa, user, logout } = useAuth();' in body


def test_a_refused_reauth_stays_at_its_field(panel):
    body = _function(panel, 'HaPanel')
    refused = body[body.index('const reauthRefused = (form, res) => {'):]
    refused = refused[:refused.index('\n            };')]
    assert "res.code !== 'HA_REAUTH' && res.code !== 'HA_REAUTH_RECENT'" in refused
    assert 'setReauth({ form, code: res.code, error: res.error });' in refused
    assert "setPassword(form, '');" in refused
    # each action hands a refusal to it before its usual error path, and a refusal
    # returns before the box closes
    assert "if (!res.ok) { if (!reauthRefused('code', res)) addToast?.(res.error, 'error'); return; }" in body
    assert "if (!res.ok) { if (!reauthRefused('join', res)) setJoinError(res.error); return; }" in body
    confirm = _block(body, 'const confirmed = () => run(confirmAction, async () => {', 'openConfirm(null);')
    refused = confirm[confirm.index('if (!res.ok) {'):]
    assert refused.index("if (reauthRefused('confirm', res)) return;") < refused.index("addToast?.(res.error, 'error');")
    # a stale SSO sign-in gets a way to sign in again
    note = body[body.index('const reauthNote = '):body.index('const membersCard = (')]
    assert "reauth.code === 'HA_REAUTH_RECENT'" in note
    assert 'onClick={() => logout()}' in note
    assert "{t('pgHaSignInAgain')}" in note


def test_a_broken_state_file_hides_promote_and_locks_the_interval(panel):
    body = _function(panel, 'HaPanel')
    assert 'const broken = !!status?.broken;' in body
    standby = body[body.index("{role === 'standby' && ("):]
    promote_at = standby.index("openConfirm('promote')")
    assert standby.rindex('{!broken && !status?.removed && (', 0, promote_at) > standby.rindex('<button onClick={syncNow}', 0, promote_at)
    assert "const typedBox = confirmAction && !(confirmAction === 'promote' && broken) && !removeStale && (" in body
    interval = body[body.index('const intervalCard = ('):body.index('const typedBox = ')]
    assert 'value={interval} disabled={broken}' in interval
    assert 'disabled={!!busy || broken}' in interval
    note = body[body.index('{broken && ('):]
    note = note[:note.index('</div>\n                        )}')]
    assert "t('pgHaBroken')" in note and "t('pgHaBrokenLocked')" in note


def test_roles_render_their_own_cards(panel):
    body = _function(panel, 'HaPanel')
    standalone = body[body.index("{role === 'standalone' && ("):body.index("{role === 'active' && (")]
    active = body[body.index("{role === 'active' && ("):body.index("{role === 'standby' && (")]
    standby = body[body.index("{role === 'standby' && ("):]
    assert '{pairingCard}' in standalone and "t('pgHaJoinTitle')" in standalone
    assert '{membersCard}' not in standalone
    for needle in ('{membersCard}', '{pairingCard}', '{intervalCard}', "openConfirm('unpair')"):
        assert needle in active, needle
    assert "openConfirm('promote')" not in active
    for needle in ('{membersCard}', 'onClick={syncNow}', "openConfirm('promote')", "openConfirm('unpair')",
                   "t('pgHaSkippedColumns')"):
        assert needle in standby, needle
    assert '{pairingCard}' not in standby
    pairing = body[body.index('const pairingCard = ('):body.index('if (!status) {')]
    assert "t('pgHaMakeActiveTitle')" in pairing and "t('pgHaAddStandbyTitle')" in pairing


def test_a_restart_blocks_the_page_and_reloads(panel):
    overlay = _function(panel, 'HaRestartOverlay')
    assert '`${API_URL}/auth/check?t=${Date.now()}`' in overlay
    assert 'setTimeout(tick, 2000)' in overlay
    assert 'elapsed >= 120000' in overlay
    assert 'window.location.reload()' in overlay
    body = _function(panel, 'HaPanel')
    assert "setRestarting('standby')" in body
    assert "setRestarting(what === 'promote' ? 'active' : 'standalone')" in body
    assert '{restarting && <HaRestartOverlay t={t} expectRole={restarting} />}' in body


# -- banner ---------------------------------------------------------------------------

def test_the_banner_shows_on_a_standby_only(banner):
    assert "const standby = ha?.role === 'standby';" in banner
    assert 'if (!standby) return null;' in banner
    # read-only, or carried out on the active while the standby forwards
    assert ": ha.forwarding === true ? 'pgHaBannerForwarding' : 'pgHaBannerStandby')" in banner
    # a server value goes in through a function: a string replacement reads $& and $`
    assert ".replace('{url}', () => ha.peer_url || '-')" in banner
    # the HA tab button is for admins
    assert 'const button = isAdmin && onOpenHa && (' in banner


def test_modern_and_corporate_render_it_next_to_the_password_banner(dash):
    main = dash[dash.index('function PegaProxDashboard('):]
    at = main.index('<PasswordExpiryBanner onChangePassword={() => setShowProfile(true)} />')
    assert main[at:at + 200].count('<HaStandbyBanner onOpenHa={openHaSettings} />') == 1
    # Modern and Corporate share this return; the cloud branch returns before it
    assert main.index('if (isCloud) {') < at
    opener = main[main.index('const openHaSettings = () => {'):]
    opener = opener[:opener.index('};')]
    assert 'setShowSettings(true);' in opener
    assert "new CustomEvent('pegaprox-navigate-ha')" in opener


def test_cloud_renders_it_in_the_shell(cloud):
    shell = _function(cloud, 'CloudShell')
    topbar = shell.index('<CloudTopbar')
    at = shell.index('<HaStandbyBanner cloud onOpenHa={() => {')
    scroll = shell.index('<div className="cloud-content-scroll">')
    assert topbar < at < scroll
    assert "new CustomEvent('pegaprox-navigate-ha')" in shell[at:scroll]
    assert 'onOpenSettings && onOpenSettings();' in shell[at:scroll]


# -- translations -----------------------------------------------------------------------

def _used_keys():
    keys = set()
    for name in sorted(os.listdir(SRC)):
        if name.endswith('.js') and name != 'translations.js':
            keys.update(re.findall(r"t\('(pgHa\w+)'\)", _read('web', 'src', name)))
    # picked by a condition: t(x ? 'a' : 'b'), and the refusal's code-to-key choice
    dash = _read('web', 'src', 'dashboard.js') + _read('web', 'src', 'settings_modal.js')
    keys.update(re.findall(r"\? '(pgHa\w+)'", dash))
    keys.update(re.findall(r": '(pgHa\w+)'\)", dash))
    return sorted(keys)


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = sorted((m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M))
    assert [lang for _, lang in sorted(starts, key=lambda s: LANGS.index(s[1]))] == LANGS
    out = {}
    for i, (pos, lang) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(src)
        out[lang] = src[pos:end]
    return out


def test_the_panel_uses_its_own_keys():
    # the Proxmox HA strings already use ha*; ours are pgHa* so nothing collides
    assert len(_used_keys()) >= 50


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'


def test_no_key_is_defined_that_nothing_uses():
    used = set(_used_keys())
    for lang, block in _blocks().items():
        defined = set(re.findall(r'^ +(pgHa\w+): ', block, re.M))
        assert defined == used, (lang, sorted(defined ^ used))


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in _used_keys():
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_no_em_dash_in_the_new_code(panel, banner):
    new_strings = [line for block in _blocks().values() for line in block.splitlines() if 'pgHa' in line]
    for text in [panel, banner] + new_strings:
        assert '\u2014' not in text


# -- styling ------------------------------------------------------------------------------

def _classes(block):
    names = set()
    for m in re.finditer(r'className=(?:"([^"]*)"|\{`([^`]*)`\})', block):
        txt = m.group(1) if m.group(1) is not None else m.group(2)
        txt = re.sub(r'\$\{[^}]*\}', ' ', txt)
        names.update(n for n in txt.split() if re.match(r'^[a-z]', n))
    for m in re.finditer(r"'([a-z][a-z0-9:/\-\.\[\] ]*)'", block):
        parts = m.group(1).split()
        if parts and any(re.match(r'^(bg|text|border|px|py|rounded|flex)-?', p) for p in parts):
            names.update(parts)
    return names


def test_every_class_is_in_the_static_tailwind_build(panel, banner, modal):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    tab = modal[modal.index("onClick={() => setActiveTab('ha')}"):]
    tab = tab[:tab.index('</button>')]
    ui = _read('web', 'src', 'ui.js')
    names = (_classes(panel) | _classes(banner) | _classes(tab)
             | _classes(_function(ui, 'HaOnActiveLink')) | _classes(_function(ui, 'HaConsoleOnActive')))
    # JS names that sit inside ${...} or class-string constants
    names -= {'card', 'field', 'input', 'btn', 'btnGhost'}
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


# -- bundle ----------------------------------------------------------------------------------

def test_the_bundle_was_rebuilt():
    """web/index.html is generated from web/src; a source-only change ships nothing."""
    bundle = _read('web', 'index.html')
    for needle in ('function HaPanel(', 'function HaStandbyBanner(', 'function HaRestartOverlay(',
                   'pegaprox-navigate-ha', "setActiveTab('ha')", 'refreshHa'):
        assert needle in bundle, needle
    for key in _used_keys():
        assert key in bundle, key


# -- runtime: the built bundle in a real browser ----------------------------------------------
#
# A compile proves nothing about what renders. These load web/index.html in headless
# Chromium with every request intercepted: / is the bundle, /static/* comes from the
# checkout, /api/* is answered below. Skipped where Playwright or its Chromium is not
# installed (CI installs neither).

PEER = 'https://pegaprox-a.example:5000'
SELF = 'https://pegaprox-b.example:5000'
BASE = 'http://pegaprox.test'


def _iso_ago(sec):
    return time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time() - sec))


PASSWORD = 'correct horse'
# the leader and up to two members are active, the 4th member of a group stays a standby
ACTIVE_LIMIT = 3
LIMIT_REFUSED = ('At most 3 instances of a group are active: the leader and two members. '
                 'Make another member a standby first.')
# what the page posts in the background that a standby keeps to itself (app.py)
STANDBY_LOCAL = ('/api/sse/token', '/api/sse/subscribe', '/api/snapshots/overview')


class _FakeServer:
    """Just enough of the HA contract, /auth/check and a restart that takes a few seconds.

    Pairing code, join, promote, unpair and removing a member want the account password
    again, the way the server does: a local account sends user_password, an SSO account
    sends nothing and is refused when its sign-in is too old (sso_stale).
    """

    def __init__(self, role='standby', layout='modern', language='en', admin=True,
                 auth_source='local', broken='', sso_stale=False, live_view=True,
                 restart_pending=None, clusters=None, resources=None, refuse_as_standby=False,
                 autoinstall=None, metrics=None, extra=None, permissions=None, members=None,
                 forward_writes=False, source_active=True, active_down=False, serve_assigned=False,
                 reload_pending=None, last_reload=None):
        self.role, self.layout, self.language, self.admin = role, layout, language, admin
        self.auth_source, self.broken, self.sso_stale = auth_source, broken, sso_stale
        self.down_until = 0.0
        self.role_after_restart = None
        self.calls = []
        self.bodies = {}
        self.fail_pairing_once = False
        self.interval = 30
        self.logged_out = False
        # v2: instance-local live view, whether this process started its managers, and a
        # restart the standby still owes after a changed cluster setup
        self.live_view = live_view
        self.managers_running = live_view if role == 'standby' else True
        self.restart_pending = restart_pending
        # a changed cluster connection is rebuilt in place: waiting for the settle time, and
        # what the last rebuild did ({at, reason, failed})
        self.reload_pending = reload_pending
        self.last_reload = last_reload
        # the cluster list a live standby (or any other role) shows
        self.clusters = clusters or []
        self.resources = resources or []
        self.metrics = metrics or {}
        self.urls = []   # with the query string, which calls drops
        # the page still thinks it is on an active, the instance answers as a standby
        self.refuse_as_standby = refuse_as_standby
        self.autoinstall = autoinstall
        # (method, path) -> (status, body): the reads (and the odd write) a test needs
        self.extra = dict(extra or {})
        self.permissions = list(permissions or [])
        # v3: everyone else in the group, as /api/ha/status lists them. None: the one
        # partner of a pair, whichever role this instance has at the time
        self.members = [dict(m) for m in members] if members is not None else None
        # the group fixes: the open code the status reports (None once spent or expired), the
        # members a removal cannot reach, and what this instance learned about its own removal
        self.pairing_until = None
        self.unreachable = set()
        self.removed = None
        # status requests held back while hold_status is set, answered by release() with the
        # body of the moment they arrived: a poll that was already on its way
        self.hold_status = False
        self.held = []
        # forwarding: the instance-local switch, whether the instance a standby follows answers
        # as active (the server forwards only then), and an active that went away after the page
        # last read the banner: a write then comes back 503, and the next banner says so
        self.forward_writes = forward_writes
        self.source_active = source_active
        self.active_down = active_down
        self.forwarded = []
        # serving users: the leader made this member active (serve in its own record of the
        # leader's member list); it counts on a standby with live view and forwarding on,
        # whether the leader answers or not (then source_active is False). On the leader each
        # member record carries serve, set with PUT /api/ha/members/<id>/serve
        self.serve_assigned = serve_assigned

    def forwarding(self):
        return self.role == 'standby' and self.forward_writes and self.source_active

    def serving(self):
        return (self.role == 'standby' and self.serve_assigned and self.live_view and self.forward_writes
                and not self.removed)

    def actives(self):
        """The leader and every member it made active, this one included when it is one."""
        others = sum(1 for m in self.group() if m.get('serve') is True and m.get('role_seen') != 'active')
        return 1 + others + (1 if self.role == 'standby' and self.serve_assigned else 0)

    def group(self):
        if self.role not in ('active', 'standby'):
            return []
        if self.members is not None:
            return self.members
        standby = self.role == 'standby'
        return [{'instance_id': 'b' * 32, 'url': PEER if standby else SELF, 'fingerprint': '',
                 'role_seen': 'active' if standby else 'standby', 'epoch_seen': 2,
                 'last_contact': _iso_ago(12), 'joined_at': _iso_ago(3600), 'is_source': standby,
                 'last_error': '' if standby else 'Cannot reach the peer: ConnectTimeout'}]

    def standby_count(self):
        others = sum(1 for m in self.group() if m.get('role_seen') != 'active')
        return others + (1 if self.role == 'standby' else 0)

    def _reauth_refusal(self, body):
        if self.auth_source in ('oidc', 'entra'):
            if self.sso_stale:
                return {'error': 'Your sign-in is older than 10 minutes. Sign in again, then retry.',
                        'code': 'HA_REAUTH_RECENT'}
            return None
        if body.get('user_password') != PASSWORD:
            return {'error': 'Incorrect password', 'code': 'HA_REAUTH'}
        return None

    def _source(self):
        return next((m for m in self.group() if m.get('is_source')), None)

    def status(self):
        group = self.group()
        # "peer" stays for older readers: a standby's source, else the first member
        first = self._source() if self.role == 'standby' else (group[0] if group else None)
        peer = None
        if first:
            peer = dict({k: first.get(k) for k in ('instance_id', 'url', 'fingerprint', 'role_seen',
                                                   'epoch_seen', 'last_contact', 'last_error')},
                        paired_at=first.get('joined_at'))
        sync = {}
        if self.role == 'standby':
            sync = {'last_ok_at': _iso_ago(20), 'last_attempt_at': _iso_ago(20), 'last_error': '',
                    'rows': 1234, 'tables': 41, 'source_epoch': 2, 'etag': None,
                    'skipped_columns': {'clusters': ['new_col']},
                    'restart_pending': self.restart_pending, 'reload_pending': self.reload_pending,
                    'last_reload': self.last_reload}
        open_until = self.pairing_until if (self.pairing_until or 0) >= time.time() else None
        return {'role': self.role, 'epoch': 0 if self.role == 'standalone' else 2,
                'instance_id': 'a' * 32, 'interval': self.interval, 'broken': self.broken,
                'pairing_open_until': open_until, 'peer': peer, 'sync': sync,
                'suggested_url': SELF, 'own_fingerprint': '',
                'live_view': self.live_view, 'managers_running': self.managers_running,
                'members': [dict(m, serve=m.get('serve') is True) for m in group], 'max_members': 4,
                'standby_count': self.standby_count(), 'removed': self.removed,
                'forward_writes': self.forward_writes, 'forwarding': self.forwarding(),
                'serve_assigned': self.role == 'standby' and self.serve_assigned, 'serving': self.serving(),
                'actives': self.actives(), 'active_limit': ACTIVE_LIMIT}

    def banner(self):
        if self.role != 'standby':
            return {'role': self.role}
        source = self._source()
        return {'role': 'standby', 'peer_url': source['url'] if source else PEER,
                'last_sync_at': _iso_ago(90), 'live_view': self.live_view,
                'forwarding': self.forwarding(), 'serving': self.serving(),
                'leader_reachable': self.source_active}

    def release(self):
        held, self.held = self.held, []
        for route, data in held:
            route.fulfill(status=200, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def _restart(self, role):
        self.down_until = time.time() + 4
        self.role_after_restart = role

    def _come_back(self):
        """What a fresh process knows: the role it restarted into, managers as the switch says."""
        self.role, self.role_after_restart = self.role_after_restart, None
        self.managers_running = self.live_view if self.role == 'standby' else True
        self.restart_pending = None

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not req.url.startswith(BASE):
            return route.abort()
        if path in ('/', '/index.html'):
            return route.fulfill(status=200, body=_read('web', 'index.html'),
                                 headers={'Content-Type': 'text/html; charset=utf-8'})
        if path.startswith('/static/'):
            fp = os.path.join(ROOT, path.lstrip('/'))
            if os.path.isfile(fp):
                ctype = 'text/css' if fp.endswith('.css') else 'application/javascript'
                with open(fp, 'rb') as fh:
                    return route.fulfill(status=200, body=fh.read(), headers={'Content-Type': ctype})
            return route.fulfill(status=404, body='')
        if not path.startswith('/api/'):
            return route.fulfill(status=404, body='')
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        self.bodies.setdefault(path, []).append(body)

        def answer(data, status=200):
            return route.fulfill(status=status, body=json.dumps(data),
                                 headers={'Content-Type': 'application/json'})

        if (req.method, path) in self.extra:
            status, data = self.extra[(req.method, path)]
            return answer(data, status)
        if path == '/api/auth/check':
            if time.time() < self.down_until:
                return route.abort('connectionrefused')
            if self.logged_out:
                return answer({'authenticated': False, 'ha_role': self.role})
            if self.role_after_restart:
                self._come_back()
            user = {'username': 'admin' if self.admin else 'viewer',
                    'role': 'admin' if self.admin else 'viewer', 'display_name': 'Admin',
                    'ui_layout': self.layout, 'layout_chosen': True, 'theme': '',
                    'language': self.language, 'permissions': self.permissions, 'enabled': True,
                    'auth_source': self.auth_source, 'autoinstall_access': self.autoinstall}
            return answer({'authenticated': True, 'session_id': 'sid', 'user': user,
                           'ha': self.banner(), 'default_theme': 'proxmoxDark'})
        if path == '/api/auth/logout':
            self.logged_out = True
            return answer({'success': True})
        if path == '/api/ha/status':
            if self.hold_status:
                self.held.append((route, self.status()))
                return None
            return answer(self.status())
        if path == '/api/ha/pairing-code' and self.role == 'active' and self.standby_count() >= 3:
            return answer({'error': 'This group already has 3 standbys - remove one first'}, 409)
        removal = re.fullmatch(r'/api/ha/members/([^/]+)/remove', path)
        if removal:
            # the order of the real route: the word, active only, a known member, then the password
            if body.get('confirm') != 'REMOVE':
                return answer({'error': 'Type REMOVE to confirm'}, 400)
            if self.role != 'active':
                return answer({'error': 'Only the active instance removes members'}, 409)
            if not any(m['instance_id'] == removal.group(1) for m in self.group()):
                return answer({'error': 'This instance is not a member of the group'}, 404)
            refusal = self._reauth_refusal(body)
            if refusal:
                return answer(refusal, 403)
            # not a standby under the current epoch: only with the admin's word that it is off
            target = next(m for m in self.group() if m['instance_id'] == removal.group(1))
            if target.get('confirmed_standby') is False and body.get('shut_down') is not True:
                return answer({'code': 'HA_REMOVE_UNCONFIRMED',
                               'error': 'That instance is not confirmed as a standby under the current '
                                        'epoch - confirm it is shut down for good'}, 409)
            self.members = [dict(m) for m in self.group() if m['instance_id'] != removal.group(1)]
            if not self.members:
                # the last standby gone: standalone, as the real server does
                self.role = 'standalone'
            return answer({'success': True, 'told': removal.group(1) not in self.unreachable,
                           'members': self.members})
        serve = re.fullmatch(r'/api/ha/members/([^/]+)/serve', path)
        if serve and req.method == 'PUT':
            # the order of the real route: admin, the leader only, a known member, a bool, the limit
            if not self.admin:
                return answer({'error': 'Admin required'}, 403)
            if self.role != 'active':
                return answer({'error': 'Which instances are active is set on the leader', 'code': 'HA_STANDBY'}, 409)
            target = next((m for m in self.group() if m['instance_id'] == serve.group(1)), None)
            if target is None:
                return answer({'error': 'This instance is not a member of the group'}, 404)
            if not isinstance(body.get('serve'), bool):
                return answer({'error': 'serve is true or false'}, 400)
            if body['serve'] and target.get('serve') is not True and self.actives() >= ACTIVE_LIMIT:
                return answer({'error': LIMIT_REFUSED, 'code': 'HA_ACTIVE_LIMIT'}, 409)
            target['serve'] = body['serve']
            return answer({'success': True, 'serve': target['serve'], 'actives': self.actives()})
        if path in ('/api/ha/pairing-code', '/api/ha/join', '/api/ha/promote', '/api/ha/unpair'):
            refusal = self._reauth_refusal(body)
            if refusal:
                return answer(refusal, 403)
        if path == '/api/ha/settings' and self.broken:
            return answer({'error': 'The HA state file cannot be read - repair or remove it first'}, 409)
        if path == '/api/ha/pairing-code':
            if self.fail_pairing_once:
                self.fail_pairing_once = False
                return answer({'error': 'This instance is already paired - unpair it first'}, 409)
            self.pairing_until = int(time.time()) + 900
            return answer({'code': 'pgxha1_' + 'Q' * 120, 'expires_at': self.pairing_until})
        if path == '/api/ha/join':
            if body.get('confirm') is not True or not body.get('code'):
                return answer({'error': 'confirm missing'}, 400)
            self._restart('standby')
            return answer({'success': True, 'restarting': True})
        if path == '/api/ha/sync-now':
            return answer({'result': 'applied', 'status': self.status()})
        if path == '/api/ha/settings':
            if 'serve_users' in body:
                return answer({'code': 'HA_SERVE_ON_LEADER', 'error': 'Which instances are active is set on the leader'}, 400)
            if 'forward_writes' in body:
                self.forward_writes = bool(body['forward_writes'])
                return answer({'success': True, 'forward_writes': self.forward_writes})
            if 'live_view' in body:
                changed = bool(body['live_view']) != self.live_view
                self.live_view = bool(body['live_view'])
                if changed and self.role == 'standby':
                    self._restart('standby')
                    return answer({'success': True, 'restarting': True})
                return answer({'success': True, 'live_view': self.live_view})
            self.interval = int(body.get('interval') or 30)
            return answer({'success': True, 'interval': self.interval})
        if path == '/api/ha/apply-config':
            if self.role != 'standby':
                return answer({'error': 'Only a standby applies a synced configuration'}, 409)
            # a switched live view restarts, a waiting rebuild runs in place, else nothing
            if self.restart_pending or self.managers_running != self.live_view:
                self._restart('standby')
                return answer({'success': True, 'restarting': True})
            reloaded, self.reload_pending = bool(self.reload_pending), None
            if reloaded:
                self.last_reload = {'at': _iso_ago(0), 'reason': '1 cluster changed', 'failed': []}
            return answer({'success': True, 'restarting': False, 'reloaded': reloaded})
        if req.method == 'GET' and path == '/api/clusters':
            return answer(self.clusters)
        if req.method == 'GET' and self.clusters and path.endswith('/resources'):
            return answer(self.resources)
        if req.method == 'GET' and self.clusters and path.endswith('/metrics'):
            return answer(self.metrics)
        if path == '/api/ha/promote':
            if body.get('confirm') != 'PROMOTE':
                return answer({'error': 'type PROMOTE'}, 400)
            self._restart('active')
            return answer({'success': True, 'epoch': 3, 'restarting': True})
        if path == '/api/ha/unpair':
            if body.get('confirm') != 'UNPAIR':
                return answer({'error': 'type UNPAIR'}, 400)
            was = self.role
            self.removed = None
            if was == 'standby':
                self._restart('standalone')
            else:
                # an active takes the whole group apart
                self.role, self.members = 'standalone', []
            return answer({'success': True, 'restarting': was == 'standby'})
        # the instance-local writes the real standby lets through are never forwarded
        if req.method != 'GET' and self.forwarding() and path not in STANDBY_LOCAL:
            if self.active_down:
                # the next banner no longer says forwarding
                self.source_active = False
                return answer({'code': 'HA_ACTIVE_UNREACHABLE',
                               'error': 'The active instance cannot be reached - act again once it is '
                                        'back, or promote this standby'}, 503)
            self.forwarded.append((req.method, path))
            return answer({'success': True})
        if req.method != 'GET' and (self.role == 'standby' or self.refuse_as_standby):
            return answer({'error': 'This is a standby instance. Make changes on the active instance; '
                                    'they arrive here with the next sync.', 'code': 'HA_STANDBY'}, 409)
        return answer({'error': 'not mocked'}, 404)


@pytest.fixture(scope='module')
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


class _App:
    def __init__(self, browser, server, clock=False):
        self.server = server
        self.ctx = browser.new_context(viewport={'width': 1600, 'height': 1000})
        if clock:
            # Playwright's clock: time runs as usual, and page.clock.run_for() lets a poll interval pass at once
            self.ctx.clock.install()
        # the monthly sponsor modal for admins would sit on top of everything
        self.ctx.add_init_script("""try {
            for (const u of ['admin', 'viewer']) localStorage.setItem('pegaprox_sponsor_v2:' + u, String(Date.now() + 1e10));
            localStorage.setItem('pegaprox-shortcuts-hint-shown', '1');
        } catch (e) {}""")
        self.page = self.ctx.new_page()
        self.errors = []
        self.loads = []
        self.page.on('pageerror', lambda e: self.errors.append(f'pageerror: {e}'))
        self.page.on('console', self._console)
        self.page.on('load', lambda: self.loads.append(time.time()))
        self.page.route('**/*', server.handle)
        self.page.goto(BASE + '/', wait_until='load')
        self.wait_for_app()

    def _console(self, msg):
        # mocked 404s and the refused connections of the simulated restart
        if msg.type == 'error' and 'Failed to load resource' not in msg.text and 'net::ERR' not in msg.text:
            self.errors.append(f'console: {msg.text[:300]}')

    def wait_for_app(self):
        self.page.wait_for_function(
            '() => document.querySelector("header") || document.querySelector(".cloud-shell")', timeout=30000)
        self.page.wait_for_timeout(500)

    def wait_for_reload(self, before, timeout=25):
        deadline = time.time() + timeout
        while time.time() < deadline and len(self.loads) == before:
            self.page.wait_for_timeout(250)
        assert len(self.loads) > before, 'the page did not reload after the restart'
        self.wait_for_app()

    def open_settings(self):
        # "g ," is the settings shortcut in Modern and Corporate
        self.page.locator('body').click(position={'x': 5, 'y': 400})
        self.page.keyboard.press('g')
        self.page.keyboard.press(',')
        self.page.get_by_text('PegaProx Settings').first.wait_for(timeout=5000)

    def see(self, text, timeout=5000):
        self.page.get_by_text(text).first.wait_for(timeout=timeout)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _FakeServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def test_runtime_standby_in_modern_banner_panel_sync_and_promote(open_app):
    app = open_app(role='standby', layout='modern')
    page = app.page
    banner = page.locator('[data-ha-banner="classic"]')
    assert banner.is_visible()
    text = banner.inner_text()
    assert f'Standby instance, synced from {PEER}, last sync' in text
    assert 'minute' in text, text
    # above the header, where the password expiry banner sits
    assert page.evaluate('() => !!(document.querySelector("[data-ha-banner]").compareDocumentPosition('
                         'document.querySelector("header")) & Node.DOCUMENT_POSITION_FOLLOWING)')

    banner.get_by_role('button', name='High Availability').click()
    panel = page.locator('[data-ha-role="standby"]')
    panel.wait_for(timeout=5000)
    body = panel.inner_text()
    for needle in ('Standby', PEER, 'Last successful sync', '1234 rows in 41 tables', 'clusters: new_col',
                   'Sync now', 'Promote to active', 'Unpair'):
        assert needle in body, needle

    page.get_by_role('button', name='Sync now').click()
    app.see('Configuration synced from the active instance')
    assert ('POST', '/api/ha/sync-now') in app.server.calls

    page.get_by_role('button', name='Promote to active').click()
    assert 'steps down to standby as soon as it sees this one' in panel.inner_text()
    confirm = panel.locator('button', has_text='Promote to active').last
    assert confirm.is_disabled()
    page.fill('#pgha-typed', 'promote')
    assert confirm.is_disabled()
    page.fill('#pgha-typed', 'PROMOTE')
    assert confirm.is_disabled(), 'promote must wait for the password'
    page.fill('#pgha-confirm-password', PASSWORD)
    assert confirm.is_enabled()
    before = len(app.loads)
    confirm.click()
    app.see('Restarting PegaProx...', timeout=3000)
    assert app.server.bodies['/api/ha/promote'] == [{'confirm': 'PROMOTE', 'user_password': PASSWORD}]
    # the fake instance is gone for 4 s and comes back active
    app.wait_for_reload(before)
    assert page.locator('[data-ha-banner]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout,kind', [('corporate', 'classic'), ('cloud', 'cloud')])
def test_runtime_standby_banner_in_the_other_layouts(open_app, layout, kind):
    app = open_app(role='standby', layout=layout)
    banner = app.page.locator(f'[data-ha-banner="{kind}"]')
    assert banner.is_visible()
    assert PEER in banner.inner_text()
    if layout == 'cloud':
        assert app.page.locator('.cloud-content [data-ha-banner="cloud"]').count() == 1
    banner.get_by_role('button', name='High Availability').click()
    app.page.locator('[data-ha-role="standby"]').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_a_viewer_gets_the_banner_but_no_button_and_no_tab(open_app):
    app = open_app(role='standby', layout='modern', admin=False)
    banner = app.page.locator('[data-ha-banner="classic"]')
    assert banner.is_visible()
    assert banner.locator('button').count() == 0
    app.open_settings()
    assert app.page.locator('button', has_text='High Availability').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_banner_speaks_german(open_app):
    app = open_app(role='standby', layout='modern', language='de')
    text = app.page.locator('[data-ha-banner="classic"]').inner_text()
    assert f'Standby-Instanz, synchronisiert von {PEER}, letzte Synchronisierung vor' in text, text
    assert app.page.locator('[data-ha-banner] button', has_text='Hochverfügbarkeit').count() == 1
    assert not app.errors, app.errors


def test_runtime_standalone_pairing_code_and_join(open_app):
    app = open_app(role='standalone', layout='modern')
    app.server.fail_pairing_once = True
    page = app.page
    assert page.locator('[data-ha-banner]').count() == 0
    app.open_settings()
    page.locator('button', has_text='High Availability').first.click()
    panel = page.locator('[data-ha-role="standalone"]')
    panel.wait_for(timeout=5000)
    assert 'Make this the active instance' in panel.inner_text()
    assert page.input_value('#pgha-own-url') == SELF
    assert page.input_value('#pgha-join-url') == SELF

    create = page.get_by_role('button', name='Create pairing code')
    assert create.is_disabled(), 'the pairing code must wait for the password'
    page.fill('#pgha-code-password', PASSWORD)
    assert create.is_enabled()

    # a refusal shows the server's words, and keeps the password for the retry
    create.click()
    app.see('This instance is already paired - unpair it first')
    assert page.input_value('#pgha-code-password') == PASSWORD

    create.click()
    box = page.locator('[data-ha-code]')
    box.wait_for(timeout=3000)
    assert app.server.bodies['/api/ha/pairing-code'][-1] == {'url': SELF, 'user_password': PASSWORD}
    assert page.input_value('#pgha-code-password') == '', 'the password outlives its use'
    first = box.inner_text()
    assert 'pgxha1_' in first and 'shown only once' in first
    assert re.search(r'Expires in 1[45]:\d\d', first), first
    assert box.locator('button[title="Copy"]').count() == 1
    page.wait_for_timeout(1300)
    assert box.inner_text() != first, 'the countdown does not tick'

    join = page.get_by_role('button', name='Pair as standby')
    assert join.is_disabled()
    page.fill('#pgha-join-code', 'pgxha1_' + 'Z' * 40)
    assert join.is_disabled(), 'join must wait for the checkbox'
    panel.locator('input[type="checkbox"]').check()
    assert join.is_disabled(), 'join must wait for the password'
    page.fill('#pgha-join-password', PASSWORD)
    assert join.is_enabled()
    before = len(app.loads)
    join.click()
    app.see('Restarting PegaProx...', timeout=3000)
    assert app.server.calls.count(('POST', '/api/ha/join')) == 1
    assert app.server.bodies['/api/ha/join'] == [{'code': 'pgxha1_' + 'Z' * 40, 'own_url': SELF,
                                                  'confirm': True, 'user_password': PASSWORD}]
    app.wait_for_reload(before)
    assert page.locator('[data-ha-banner="classic"]').is_visible()
    assert not app.errors, app.errors


def test_runtime_active_interval_and_unpair(open_app):
    app = open_app(role='active', layout='modern')
    page = app.page
    app.open_settings()
    page.locator('button', has_text='High Availability').first.click()
    panel = page.locator('[data-ha-role="active"]')
    panel.wait_for(timeout=5000)
    body = panel.inner_text()
    for needle in (SELF, 'Last contact', 'ConnectTimeout', 'Interval in seconds', 'Unpair'):
        assert needle in body, needle
    assert 'Promote to active' not in body

    assert page.input_value('#pgha-interval') == '30'
    page.fill('#pgha-interval', '2')
    panel.get_by_role('button', name='Save').click()
    app.see('The interval must be between 5 and 3600 seconds')
    assert ('PUT', '/api/ha/settings') not in app.server.calls
    page.fill('#pgha-interval', '45')
    panel.get_by_role('button', name='Save').click()
    app.see('Interval saved')
    assert app.server.interval == 45

    panel.get_by_role('button', name='Unpair').first.click()
    # an active that unpairs takes the whole group apart (v3)
    assert 'Every standby stops receiving changes' in panel.inner_text()
    page.fill('#pgha-typed', 'UNPAIR')
    page.fill('#pgha-confirm-password', PASSWORD)
    panel.locator('button', has_text='Unpair').last.click()
    # an active that unpairs does not restart: the panel just turns standalone
    page.locator('[data-ha-role="standalone"]').wait_for(timeout=5000)
    assert page.get_by_text('Restarting PegaProx...').count() == 0
    assert not app.errors, app.errors


# -- runtime: re-authentication and the unreadable state file --------------------------------

def _open_ha(app, role):
    if role == 'standby':
        app.page.locator('[data-ha-banner="classic"]').get_by_role('button', name='High Availability').click()
    else:
        app.open_settings()
        app.page.locator('button', has_text='High Availability').first.click()
    panel = app.page.locator(f'[data-ha-role="{role}"]')
    panel.wait_for(timeout=5000)
    return panel


def _follows(page, first, second):
    return page.evaluate('([a, b]) => !!(document.querySelector(a).compareDocumentPosition('
                         'document.querySelector(b)) & Node.DOCUMENT_POSITION_FOLLOWING)', [first, second])


def test_runtime_a_wrong_password_keeps_the_promote_box_open(open_app):
    app = open_app(role='standby', layout='modern')
    page = app.page
    panel = _open_ha(app, 'standby')
    page.get_by_role('button', name='Promote to active').click()
    confirm = panel.locator('button', has_text='Promote to active').last
    page.fill('#pgha-typed', 'PROMOTE')
    page.fill('#pgha-confirm-password', 'wrong')
    confirm.click()

    note = panel.locator('[data-ha-reauth="HA_REAUTH"]')
    note.wait_for(timeout=3000)
    assert 'Incorrect password' in note.inner_text()
    # under the password field, and not as a toast on top
    assert _follows(page, '#pgha-confirm-password', '[data-ha-reauth]')
    assert page.get_by_text('Incorrect password').count() == 1
    # the box stays, the word stays, the password is gone and the button waits for a new one
    assert page.input_value('#pgha-typed') == 'PROMOTE'
    assert page.input_value('#pgha-confirm-password') == ''
    assert page.get_attribute('#pgha-confirm-password', 'aria-invalid') == 'true'
    assert confirm.is_disabled()
    assert page.get_by_text('Restarting PegaProx...').count() == 0
    assert app.server.bodies['/api/ha/promote'] == [{'confirm': 'PROMOTE', 'user_password': 'wrong'}]

    page.fill('#pgha-confirm-password', PASSWORD)
    confirm.click()
    app.see('Restarting PegaProx...', timeout=3000)
    assert app.server.bodies['/api/ha/promote'][-1] == {'confirm': 'PROMOTE', 'user_password': PASSWORD}
    assert not app.errors, app.errors


def test_runtime_a_wrong_password_shows_at_the_card_that_sent_it(open_app):
    app = open_app(role='standalone', layout='modern')
    page = app.page
    panel = _open_ha(app, 'standalone')

    page.fill('#pgha-code-password', 'wrong')
    page.get_by_role('button', name='Create pairing code').click()
    note = panel.locator('[data-ha-reauth="HA_REAUTH"]')
    note.wait_for(timeout=3000)
    assert _follows(page, '#pgha-code-password', '[data-ha-reauth]')
    assert not _follows(page, '#pgha-join-password', '[data-ha-reauth]')
    assert page.input_value('#pgha-code-password') == ''
    assert page.locator('[data-ha-code]').count() == 0

    page.fill('#pgha-join-code', 'pgxha1_' + 'Z' * 40)
    panel.locator('input[type="checkbox"]').check()
    page.fill('#pgha-join-password', 'wrong too')
    join = page.get_by_role('button', name='Pair as standby')
    join.click()
    page.wait_for_function('() => document.querySelector("#pgha-join-password").value === ""', timeout=3000)
    # one note, now at the join card; the join's own error box stays empty
    assert panel.locator('[data-ha-reauth]').count() == 1
    assert _follows(page, '#pgha-join-password', '[data-ha-reauth]')
    assert page.get_attribute('#pgha-code-password', 'aria-invalid') is None
    assert page.input_value('#pgha-join-code') == 'pgxha1_' + 'Z' * 40
    assert join.is_disabled()
    assert page.get_by_text('Restarting PegaProx...').count() == 0
    assert [b.get('user_password') for b in app.server.bodies['/api/ha/join']] == ['wrong too']
    assert not app.errors, app.errors


@pytest.mark.parametrize('auth_source', ['oidc', 'entra'])
def test_runtime_an_sso_account_types_no_password(open_app, auth_source):
    app = open_app(role='standalone', layout='modern', auth_source=auth_source)
    page = app.page
    panel = _open_ha(app, 'standalone')
    assert panel.locator('input[type="password"]').count() == 0
    assert page.locator('#pgha-code-password, #pgha-join-password').count() == 0

    create = page.get_by_role('button', name='Create pairing code')
    assert create.is_enabled()
    create.click()
    page.locator('[data-ha-code]').wait_for(timeout=3000)
    assert app.server.bodies['/api/ha/pairing-code'] == [{'url': SELF}]

    page.fill('#pgha-join-code', 'pgxha1_' + 'Z' * 40)
    panel.locator('input[type="checkbox"]').check()
    assert page.get_by_role('button', name='Pair as standby').is_enabled()
    assert not app.errors, app.errors


def test_runtime_a_stale_sso_sign_in_offers_to_sign_in_again(open_app):
    app = open_app(role='active', layout='modern', auth_source='oidc', sso_stale=True)
    page = app.page
    panel = _open_ha(app, 'active')
    panel.get_by_role('button', name='Unpair').first.click()
    assert page.locator('#pgha-confirm-password').count() == 0
    page.fill('#pgha-typed', 'UNPAIR')
    confirm = panel.locator('button', has_text='Unpair').last
    assert confirm.is_enabled()
    confirm.click()

    note = panel.locator('[data-ha-reauth="HA_REAUTH_RECENT"]')
    note.wait_for(timeout=3000)
    assert 'older than 10 minutes' in note.inner_text()
    assert app.server.bodies['/api/ha/unpair'] == [{'confirm': 'UNPAIR'}]
    assert page.input_value('#pgha-typed') == 'UNPAIR', 'the box closed on a refusal'
    assert app.server.role == 'active'

    note.get_by_role('button', name='Sign in again').click()
    page.wait_for_function('() => !document.querySelector("[data-ha-role]")', timeout=5000)
    assert ('POST', '/api/auth/logout') in app.server.calls
    assert not app.errors, app.errors


def test_runtime_an_unreadable_state_file_offers_no_promote(open_app):
    reason = "Expecting ',' delimiter: line 1 column 244 (char 243)"
    app = open_app(role='standby', layout='modern', broken=reason)
    page = app.page
    panel = _open_ha(app, 'standby')
    note = panel.locator('[data-ha-broken]')
    assert 'The HA state file cannot be read' in note.inner_text()
    assert reason in note.inner_text()
    assert 'Promoting and changing the interval stay locked' in note.inner_text()

    assert panel.locator('button', has_text='Promote to active').count() == 0
    assert page.locator('#pgha-interval').is_disabled()
    save = page.locator('#pgha-interval + button')
    assert save.inner_text() == 'Save' and save.is_disabled()
    # sync and unpair stay
    assert panel.get_by_role('button', name='Sync now').is_enabled()
    assert panel.get_by_role('button', name='Unpair').is_enabled()
    assert ('PUT', '/api/ha/settings') not in app.server.calls
    assert not app.errors, app.errors


def test_a_standby_says_why_its_cluster_list_is_empty():
    """(#625 live test) An empty list on a standby used to say "No clusters configured"
    and offer Add First Cluster and the automated install, both refused there. In v2 it
    is empty until the next sync, or for good while its live view is off, and it says
    which. Sidebar card, Corporate and Modern overview."""
    dash = _read('web', 'src', 'dashboard.js')
    card = dash[dash.index("{t('noClusterSelected')}") - 400:dash.index("{t('noClusterSelected')}")]
    assert "haStandby ? (" in card
    assert ("{ha.live_view === false ? t('pgHaNoClustersLiveOff') : haServing ? t('pgHaNoClustersServing') "
            ": t('pgHaNoClustersHere')}") in card
    assert dash.count('{canAutoInstall && !haStandby && (') == 2   # the card and the sidebar entry

    vm = _read('web', 'src', 'vm_modals.js')
    start = vm.index('function AllClustersOverview(')
    body = vm[start:vm.index('function GroupSettingsModal(', start)]
    assert "const haStandby = haInfo.role === 'standby';" in body
    assert ("const haNoClusters = haInfo.live_view === false ? t('pgHaNoClustersLiveOff')\n"
            "                : haInfo.serving === true ? t('pgHaNoClustersServing') : t('pgHaNoClustersHere');") in body
    # t has to exist before the text is picked
    assert body.index('const { t } = useTranslation();') < body.index('const haNoClusters =')
    assert body.count('{haStandby ? haNoClusters : (') == 2
    assert body.count('{onAutoInstall && !haStandby && (') == 2


# -- v2: a live standby is a read-only view (#625) --------------------------------------------
#
# A standby now starts its managers and shows the clusters. Only the active acts: the
# permission helpers keep the *.view permissions on a standby (admins included), the action
# surfaces that ask for no permission hide their buttons, and a refusal the server still
# sends (409 HA_STANDBY) turns into one translated toast.

def _block(src, start, end):
    at = src.index(start)
    return src[at:src.index(end, at)]


def test_the_context_derives_one_read_only_flag(ctx):
    # forwarding: read-only only while the standby does not forward; haStandby on every one
    assert "const haStandby = ha.role === 'standby';" in ctx
    assert "const haReadOnly = haStandby && ha.forwarding !== true;" in ctx
    provider = ctx[ctx.index('<AuthContext.Provider value={{'):]
    provider = provider[:provider.index('}}>')]
    assert re.search(r'\bhaReadOnly\b', provider) and re.search(r'\bhaStandby\b', provider)
    # isAdmin is left alone: the HA tab, the banner button and promote hang off it
    assert "isAdmin: user?.role === 'admin'," in provider
    helper = _block(ctx, 'function haReadPermission(', '\n        }')
    assert "return typeof permission === 'string' && permission.endsWith('.view');" in helper


@pytest.mark.parametrize('name,helper', [('dashboard.js', 'can'), ('storage.js', 'hasPerm'),
                                         ('security.js', 'hasPerm')])
def test_every_permission_helper_keeps_only_reading_on_a_standby(name, helper):
    src = _read('web', 'src', name)
    found = re.findall(r'const %s = \((\w+)\) => (.*?);\n' % helper, src, re.S)
    assert len(found) == 1, found
    arg, body = found[0]
    # and-ed in front of the admin shortcut, so it holds for admins too
    assert body.startswith('(!haReadOnly || haReadPermission(%s)) &&' % arg), body
    assert 'isAdmin ||' in body
    assert re.search(r'const \{[^}]*\bhaReadOnly\b[^}]*\} = useAuth\(\);', src)


def test_can_answers_as_agreed(ctx, dash):
    """The helper and can() as they are in the source, run in node."""
    import shutil
    import subprocess
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not installed')
    helper = _block(ctx, 'function haReadPermission(', '\n        }') + '\n        }'
    can = re.search(r'const can = \(permission\) => (.*?);\n', dash, re.S).group(1)
    script = helper + """
    const mk = (haReadOnly, isAdmin, user) => (permission) => %s;
    const out = {
        standbyAdmin: ['vm.view', 'vm.start', 'vm.console', 'node.shell', 'cluster.config', 'plugins.view', 'admin.audit']
            .map(mk(true, true, { permissions: [] })),
        standbyUser: ['vm.view', 'vm.start', 'storage.view'].map(mk(true, false, { permissions: ['vm.view', 'vm.start'] })),
        activeAdmin: ['vm.start', 'node.shell'].map(mk(false, true, { permissions: [] })),
        activeUser: ['vm.view', 'vm.start', 'storage.view'].map(mk(false, false, { permissions: ['vm.view', 'vm.start'] })),
        odd: [undefined, null, 5, 'view', '.view'].map(haReadPermission),
    };
    console.log(JSON.stringify(out));
    """ % can
    res = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    assert out['standbyAdmin'] == [True, False, False, False, False, True, False]
    assert out['standbyUser'] == [True, False, False]   # a view permission it does not hold stays off
    assert out['activeAdmin'] == [True, True]
    assert out['activeUser'] == [True, True, False]
    assert out['odd'] == [False, False, False, False, True]


def test_one_ha_standby_branch_in_the_dashboard_authfetch(dash):
    body = _block(dash, 'const authFetch = React.useCallback(async (url, opts = {}) => {', '}, [getAuthHeaders]);')
    assert 'const { timeout, quiet, ...rest } = opts;' in body
    assert 'if ((res.status === 409 || res.status === 503) && haRefusedRef.current) {' in body
    assert ("if ((res.status === 409 && code === 'HA_STANDBY') || "
            "(res.status === 503 && code === 'HA_ACTIVE_UNREACHABLE')) {") in body
    # a 503 on a read: the view that asked says so (haLeaderAway), no toast every poll
    assert "const read = res.status === 503 && (rest.method || 'GET').toUpperCase() === 'GET';" in body
    assert 'const error = haRefusedRef.current(quiet || read, code);' in body
    assert 'return new Response(JSON.stringify({ ...body, error }),' in body
    assert '{ status: res.status, statusText: res.statusText,' in body
    # the only place in the dashboard that knows the codes
    assert dash.count("'HA_STANDBY'") == 1
    assert dash.count("'HA_ACTIVE_UNREACHABLE'") == 2    # the check and the key it picks
    setter = _block(dash, "haRefusedRef.current = (quiet = false, code = '') => {", '};')
    # a member that serves users names the leader, a standby the active instance
    assert ("const msg = t(code === 'HA_ACTIVE_UNREACHABLE' ? (haServing ? 'pgHaLeaderUnreachable' "
            ": 'pgHaActiveUnreachable')") in setter
    assert (": code === 'console' ? 'pgHaConsoleOnActive' : haServing ? 'pgHaServingRefused' "
            ": 'pgHaStandbyRefused');") in setter
    assert "if (!quiet) addToast(msg, 'error');" in setter
    # a refusal may mean forwarding changed: the banner and the buttons are read again
    assert "if (!quiet && code !== 'console') refreshHa?.();" in setter
    # reads that go out as a POST in the background stay silent
    for path in ('/snapshots/overview', '/sse/subscribe'):
        at = dash.index('`${API_URL}%s`' % path)
        assert 'quiet: true' in dash[at:at + 320], path
    # the caller's own error toast with the same words replaces the first (review: a
    # dropped copy took a retry's failure off the screen with the first toast's timer)
    toast = _block(dash, 'const addToast = (message, type = ', '};')
    assert '[...prev.filter(x => x.message !== message || x.type !== type), { id, message, type }]' in toast
    assert 'prev.some(' not in toast


def test_no_optimistic_status_flip_on_a_standby(dash):
    body = _block(dash, 'const handleVmAction = async (resource, action) => {', 'const handleMigrate = ')
    assert 'const flipped = !!expectedStatus[action] && !haReadOnly;' in body
    assert 'if (flipped) {' in body
    assert body.count('_optimistic: true') == 1


@pytest.mark.parametrize('handler,first_act', [
    ('const handleOpenConsole = async (resource) => {', 'setConsoleStack('),
    ('const handleOpenSpice = async (resource) => {', 'await authFetch('),
])
def test_the_dashboard_refuses_a_console_before_opening_it(dash, handler, first_act):
    body = _block(dash, handler, '\n            };')
    # not haReadOnly: a forwarding standby runs no console either, unless it serves users
    guard = "if (haConsolesElsewhere) { haRefusedRef.current?.(false, 'console'); return; }"
    assert guard in body
    assert body.index(guard) < body.index(first_act)
    assert 'haReadOnly' not in body


READ_HANDLERS = {'openConfig', 'openMetrics', 'configNode', 'openSettings', 'openProfile', 'refresh'}
CONSOLE_HANDLERS = {'openConsole', 'openSpice', 'openLxcShell'}


def test_a_standby_hands_the_cloud_shell_nothing_that_acts(dash):
    """A new handler in the bundle has to be sorted: read, or dropped on a standby."""
    start = dash.index('const cloudActions = {')
    bundle = dash[start:dash.index('\n                };', start)]
    keys = set(re.findall(r'^ {20}(\w+):', bundle, re.M))
    assert {'vmAction', 'openConsole', 'refresh'} <= keys
    # consoles go on every standby that does not serve users, what acts only on one that
    # does not forward
    consoles = dash[dash.index('if (haConsolesElsewhere) {', start):]
    consoles = set(re.findall(r"'(\w+)'", consoles[:consoles.index('.forEach(')]))
    assert consoles == CONSOLE_HANDLERS
    drop = dash[dash.index('if (haReadOnly) {', start):]
    drop = drop[:drop.index('.forEach(')]
    dropped = set(re.findall(r"'(\w+)'", drop))
    assert dropped | consoles == keys - READ_HANDLERS, sorted((dropped | consoles) ^ (keys - READ_HANDLERS))
    assert not dropped & consoles


def test_cloud_offers_only_what_it_was_handed(cloud):
    assert "has: (k) => typeof actions?.[k] === 'function'," in cloud
    items = _block(cloud, 'function cloudVmActionItems(', '\n        }')
    for line in items.splitlines():
        if 'onClick: () => act.' not in line or 'act.openMetrics(' in line or 'act.openConfig(' in line:
            continue
        # the console link is there only when the shell hands it over, on a standby
        assert re.match(r'\s+(power && |has\(\'|act\.consoleOnActive && )', line), line
    # no divider left at an end or doubled once entries are gone
    assert 'while (out.length && out[out.length - 1].divider) out.pop();' in items
    assert "const primary = !act.has('vmAction') ? [] : running" in cloud
    assert "{act.has('openConsole') && (" in cloud
    assert "{act.has('openSpice') && r.status === 'running' && r.type === 'qemu' && (" in cloud
    assert "{selCount > 0 && canPower ? (" in cloud
    assert "const canCreate = act.has('createVm');" in cloud
    assert "action={!(q || statusFilter !== 'all') && canCreate ? (" in cloud
    assert "const nodeActions = !isAdmin ? [] : !act.has('nodeAction') ? [" in cloud


def test_the_node_modal_has_no_shell_and_locks_what_changes_on_a_standby():
    src = _read('web', 'src', 'node_modals.js')
    body = src[src.index('function NodeModal('):src.index('function ConsoleModal(')]
    assert 'const { getAuthHeaders, haReadOnly, haConsolesElsewhere } = useAuth();' in body
    # the shell tab stays on every standby and points to the shell on the active, unless
    # the standby serves users
    assert 'const tabs = allTabs;' in body
    # the timeline only reads as well
    assert "const lockedTab = haReadOnly && !['summary', 'performance', 'tasks', 'timeline'].includes(activeTab);" in body
    assert "{activeTab === 'shell' && haConsolesElsewhere && <HaConsoleOnActive />}" in body
    assert "{activeTab === 'shell' && !haConsolesElsewhere && (" in body
    # fullscreen is the same panel behind that gate, no second terminal of its own (#1143)
    assert 'shellFullscreen' not in body
    assert body.count('<NodeShellPanel ') == 1 and '<NodeShellTerminal' not in body
    assert "const haLock = { disabled: lockedTab, 'data-ha-locked': lockedTab ? '' : undefined };" in body
    # (#625 v2 review) no fieldset around all tab bodies any more, it disabled Refresh and
    # SMART too: each tab that changes the node locks its changing parts itself
    assert '<fieldset disabled={lockedTab}' not in body
    tabs = {}
    for m in re.finditer(r"\n( +)\{activeTab === '(\w+)'", body):
        tabs[m.group(2)] = body[m.end():body.index('\n' + m.group(1) + ')}\n', m.end())]
    assert {'summary', 'performance', 'network', 'system', 'hardware', 'disks', 'repos', 'tasks',
            'subscription', 'ceph'} <= set(tabs)
    for name in ('network', 'hardware', 'repos', 'ceph'):
        assert tabs[name].split('\n', 1)[1].lstrip().startswith('<fieldset {...haLock} className="contents">'), name
    for name in ('summary', 'performance', 'tasks', 'timeline'):
        assert 'haLock' not in tabs[name], name

    def locked(tab, needle):
        at = tabs[tab].index(needle)
        return tabs[tab].count('<fieldset {...haLock}', 0, at) > tabs[tab].count('</fieldset>', 0, at)

    # what reads stays usable
    reads = [m.start() for m in re.finditer(re.escape("onClick={() => loadTabData('system')}"), tabs['system'])]
    assert len(reads) == 3                      # sensors, cluster health, syslog
    for at in reads:
        assert not locked('system', tabs['system'][at:at + 60])
    assert not locked('disks', "onClick={() => loadTabData('disks')}")
    assert not locked('disks', 'title="SMART Data"')
    assert not locked('subscription', "onClick={() => loadTabData('subscription')}")
    # what changes the node stays locked
    for needle in ("handleSave('dns'", "handleSave('hosts'", 'showCertUpload: !data.showCertUpload'):
        assert locked('system', needle), needle
    for needle in ('title="Initialize GPT"', 'title="Wipe Disk"', "openDiskModal('lvm')",
                   "openDiskModal('zfs')", "openDiskModal('sr')"):
        assert locked('disks', needle), needle
    assert locked('subscription', 'value={data.newLicenseKey')
    assert locked('subscription', "{t('activateLicense')}")


@pytest.mark.parametrize('name,component', [
    ('tables.js', 'function ResourceTable('),
    ('vm_modals.js', 'function VmDetailPanel('),
    ('vm_modals.js', 'function CorporateVmDetailView('),
])
def test_the_action_surfaces_read_the_flag(name, component):
    src = _read('web', 'src', name)
    body = src[src.index(component):]
    nxt = re.search(r'\n        function \w+\(', body[10:])
    body = body[:10 + nxt.start()] if nxt else body
    head = body[:body.index('const acts = !haReadOnly;') + 40]
    assert re.search(r'const \{[^}]*\bhaReadOnly\b[^}]*\} = useAuth\(\);', head)
    assert body.count('acts &&') + body.count('!acts ?') + body.count('consoles &&') >= 5


def test_the_corporate_detail_view_leaves_the_node_alone_on_a_standby():
    """The console preview grabs a frame on the node, and ?refresh=true runs lvs and can
    lvextend there and write the table; a standby reads what is stored."""
    src = _read('web', 'src', 'vm_modals.js')
    body = _block(src, 'function CorporateVmDetailView(', 'function AllClustersOverview(')
    # on every standby, forwarding or not: a GET is not forwarded and would run here. A
    # serving member grabs the preview itself, the refresh stays off every standby
    assert 'const consoles = !haConsolesElsewhere;' in body
    assert 'if (!isQemu || !isRunning || !consoles) { setConsoleShot(null); return; }' in body
    assert "authFetch(`${base}/efficient-snapshots${haStandby ? '' : '?refresh=true'}`)" in body


def test_the_sidebar_leaves_cluster_changes_to_the_active(dash):
    heading = dash[dash.index("<h2 className=\"text-sm font-semibold text-gray-400 uppercase tracking-wider\">{t('clusters')}</h2>"):]
    heading = heading[:heading.index('{clusters.length === 0 ? (')]
    assert '{isAdmin && !haReadOnly && (' in heading
    item = _block(dash, 'function ClusterSidebarItem(', 'function TopologyView(')
    assert 'const { haReadOnly } = useAuth();' in item
    actions = item[item.index('{!haReadOnly && ('):]
    assert actions.index('<div className="flex gap-0.5 flex-shrink-0">') < actions.index('handleDeleteCluster(cluster.id)')
    create = _block(dash, '{/* Create VM/CT Buttons', 'quick CSV export of the current VM list')
    assert '{!haReadOnly && (<>' in create and "setShowCreateVm('qemu')" in create


def test_the_panel_speaks_the_v2_contract(panel):
    body = _function(panel, 'HaPanel')
    assert "const liveView = status?.live_view !== false;" in body
    assert "send('PUT', 'settings', { live_view: on })" in body
    assert "if (res.data.restarting) { setRestarting('standby'); return; }" in body
    assert "send('POST', 'apply-config', {})" in body
    assert 'const pending = sync.restart_pending || null;' in body
    card = body[body.index('const liveViewCard = ('):body.index('const restartNote = ')]
    assert 'role="switch" aria-checked={liveView}' in card
    assert 'disabled={!!busy || broken}' in card
    assert 'status.managers_running' in card
    note = body[body.index('const restartNote = '):body.index('const typedBox = ')]
    assert 'standby && (pending || liveMismatch) && (' in note
    assert '<button onClick={applyNow} disabled={!!busy}' in note
    # the switch is on every role's page, the note on the standby's
    standalone = body[body.index("{role === 'standalone' && ("):body.index("{role === 'active' && (")]
    active = body[body.index("{role === 'active' && ("):body.index("{role === 'standby' && (")]
    standby = body[body.index("{role === 'standby' && ("):]
    for part in (standalone, active, standby):
        assert '{liveViewCard}' in part
    assert '{restartNote}' in standby


# -- runtime: a live standby in the browser ---------------------------------------------------

CLUSTER = {'id': 'c1', 'name': 'Testi', 'display_name': 'Testi', 'host': '10.0.0.1',
           'connected': True, 'status': 'running', 'cluster_type': 'proxmox', 'enabled': True}
VM = {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'status': 'running', 'node': 'pve1',
      'cpu': 0.05, 'cpu_percent': 5, 'maxcpu': 2, 'mem': 1073741824, 'maxmem': 4294967296,
      'mem_percent': 25, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 3600}
REFUSED = {'en': 'This is a standby instance. Actions and consoles are only available on the active instance.',
           'de': 'Das ist eine Standby-Instanz. Aktionen und Konsolen gibt es nur auf der aktiven Instanz.'}
# what a guest's buttons say, by title or text, in the three views and both layouts
ACTING = {'Start', 'Shutdown', 'Reboot', 'Console', 'Open Console', 'SPICE Console', 'Migrate',
          'Clone', 'Delete', 'Tags', 'Force Stop', 'Force Reset', 'Launch Web Console',
          'Create VM', 'Create Container', 'Take Snapshot', 'Unlock'}


def _labels(page):
    return set(page.evaluate(
        '() => Array.from(document.querySelectorAll("button"))'
        '.filter(b => b.offsetParent !== null)'
        '.map(b => (b.getAttribute("title") || b.innerText || "").trim())'))


def _open_resources(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_modern_shows_the_guests_but_no_action_on_a_standby(open_app, role):
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM], autoinstall='manage')
    page = app.page
    standby = role == 'standby'
    # the sidebar: groups, auto-install and the per-cluster buttons belong to the active
    assert (page.locator('button[title="Manage Groups"]').count() == 0) == standby
    assert (page.get_by_text('Automated Installations').count() == 0) == standby
    assert (page.locator('button[title="Rename Cluster"]').count() == 0) == standby
    _open_resources(app)
    for view in ('Grid View', 'List View', 'Compact View'):
        page.locator(f'button[title="{view}"]').first.click()
        if view == 'Compact View':
            page.get_by_text('Select a VM from the list').wait_for(timeout=3000)
            page.locator('div.cursor-pointer', has_text='web01').first.click()
            page.get_by_text('Quick Actions').wait_for(timeout=3000)
        page.wait_for_timeout(200)
        labels = _labels(page)
        # reading stays in every view, in both roles
        assert 'Configuration' in labels, (view, sorted(labels))
        if standby:
            assert not labels & ACTING, (view, sorted(labels & ACTING))
        else:
            assert {'Shutdown', 'Migrate', 'Delete'} <= labels, (view, sorted(labels & ACTING))
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_corporate_menu_table_and_detail_on_a_standby(open_app, role):
    app = open_app(role=role, layout='corporate', clusters=[CLUSTER], resources=[VM])
    page = app.page
    standby = role == 'standby'

    # the cluster's context menu keeps what reads, for an admin too
    page.locator('.corp-tree-item', has_text='Testi').first.click(button='right')
    menu = page.locator('.corp-context-menu').first
    menu.wait_for(timeout=3000)
    text = menu.inner_text()
    assert 'Refresh' in text
    for entry in ('New VM', 'Rename Cluster', 'Delete Cluster'):
        assert (entry not in text) == standby, (entry, text)
    page.keyboard.press('Escape')
    page.mouse.click(5, 900)

    _open_resources(app)
    labels = _labels(page)
    assert 'Configuration' in labels
    assert bool(labels & ACTING) != standby, sorted(labels & ACTING)

    # the name opens the corporate detail view: no power, console or snapshot changes
    page.locator('span', has_text='web01').first.click()
    page.get_by_text('Snapshots').first.wait_for(timeout=3000)
    labels = _labels(page)
    assert bool(labels & ACTING) != standby, sorted(labels & ACTING)
    # a standby never asks the node for a console frame
    shots = [c for c in app.server.calls if c[1].endswith('/screenshot')]
    assert (not shots) == standby, shots
    page.get_by_text('Snapshots').first.click()
    page.wait_for_timeout(500)
    eff = [u for u in app.server.urls if '/efficient-snapshots' in u]
    assert eff, app.server.calls[-10:]
    assert all(('refresh=true' in u) != standby for u in eff), eff
    assert not app.errors, app.errors


def test_runtime_cloud_offers_no_action_on_a_standby(open_app):
    app = open_app(role='standby', layout='cloud', clusters=[CLUSTER], resources=[VM], autoinstall='manage')
    page = app.page
    assert page.get_by_text('Automated Installs').count() == 0
    page.get_by_text('Virtual Machines').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    labels = _labels(page)
    assert 'New VM' not in labels, sorted(labels)
    page.get_by_text('web01').first.click()
    page.locator('.cloud-detail-actions').wait_for(timeout=3000)
    bar = page.locator('.cloud-detail-actions').inner_text()
    for word in ('Console', 'Shutdown', 'Reboot', 'SPICE'):
        assert word not in bar, bar
    page.locator('.cloud-detail-actions button', has_text='Actions').click()
    page.wait_for_timeout(300)
    menu = page.evaluate('() => Array.from(document.querySelectorAll("[role=menu], .cloud-menu"))'
                         '.map(m => m.innerText).join("\\n")')
    assert 'Metrics' in menu, menu
    for word in ('Start', 'Stop', 'Console', 'Delete', 'Clone', 'Migrate', 'Snapshot'):
        assert word not in menu.split('\n'), (word, menu)
    assert not app.errors, app.errors


@pytest.mark.parametrize('language', ['en', 'de'])
def test_runtime_a_standby_refusal_is_one_translated_toast(open_app, language):
    """The page was loaded on an active that has since stepped down: it still offers the
    buttons, the instance refuses. One toast in the user's language, not the English
    server text next to it."""
    app = open_app(role='active', layout='modern', language=language, clusters=[CLUSTER],
                   resources=[VM], refuse_as_standby=True)
    page = app.page
    page.on('dialog', lambda d: d.accept())
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Ressourcen' if language == 'de' else 'Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    shutdown = 'Herunterfahren' if language == 'de' else 'Shutdown'
    page.locator(f'button[title="{shutdown}"]').first.click()
    app.see(REFUSED[language], timeout=5000)
    page.wait_for_timeout(600)
    assert page.get_by_text(REFUSED[language]).count() == 1
    assert page.get_by_text('they arrive here with the next sync').count() == 0
    assert ('POST', '/api/clusters/c1/vms/pve1/qemu/100/shutdown') in app.server.calls
    assert not app.errors, app.errors


def test_runtime_the_live_view_switch_restarts_a_standby(open_app):
    app = open_app(role='standby', layout='modern')
    page = app.page
    # the sidebar card and the overview both say why the list is empty
    app.see('This is a standby instance. Its clusters appear here after the next sync.')
    assert page.get_by_text('This is a standby instance. Its clusters appear here after the next sync.').count() == 2
    panel = _open_ha(app, 'standby')
    switch = page.get_by_role('switch', name='Connect to the clusters while following the leader')
    assert switch.get_attribute('aria-checked') == 'true'
    text = panel.inner_text()
    assert 'Connected, read only' in text and 'Changing this restarts this instance.' in text
    assert panel.locator('[data-ha-restart-pending]').count() == 0

    before = len(app.loads)
    switch.click()
    app.see('Restarting PegaProx...', timeout=3000)
    assert app.server.bodies['/api/ha/settings'] == [{'live_view': False}]
    app.wait_for_reload(before)
    # back as a standby that does not connect, and the empty list says so
    app.see('It does not connect to the clusters while its live view is off.')
    assert page.get_by_text('It does not connect to the clusters while its live view is off.').count() == 2
    panel = _open_ha(app, 'standby')
    switch = page.get_by_role('switch', name='Connect to the clusters while following the leader')
    assert switch.get_attribute('aria-checked') == 'false'
    assert 'Not connected' in panel.inner_text()
    assert not app.errors, app.errors


def test_runtime_the_live_view_switch_only_saves_elsewhere(open_app):
    app = open_app(role='standalone', layout='modern')
    page = app.page
    panel = _open_ha(app, 'standalone')
    text = panel.inner_text()
    assert 'unless its live view is off' in text          # the join warning
    assert 'Connected, read only' not in text and 'Changing this restarts' not in text
    switch = page.get_by_role('switch', name='Connect to the clusters while following the leader')
    switch.click()
    app.see('Saved. It applies once this instance follows a leader.')
    page.wait_for_function('() => document.querySelector("#pgha-live-view").getAttribute("aria-checked") === "false"',
                           timeout=3000)
    assert app.server.bodies['/api/ha/settings'] == [{'live_view': False}]
    assert page.get_by_text('Restarting PegaProx...').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_pending_restart_applies_now(open_app):
    app = open_app(role='standby', layout='modern',
                   restart_pending={'since': _iso_ago(180), 'reason': 'the live view was switched on'})
    page = app.page
    panel = _open_ha(app, 'standby')
    note = panel.locator('[data-ha-restart-pending]')
    text = note.inner_text()
    # the live view: nothing restarts it on its own, and no connection setting changed
    assert 'The live view was switched since this standby started. It takes effect once this instance restarts.' in text
    assert 'restarts on its own shortly' not in text and 'connection settings' not in text
    assert 'the live view was switched on' in text and 'minutes ago' in text
    # at the top, before the peer and sync cards
    assert _follows(page, '[data-ha-restart-pending]', '#pgha-interval')

    before = len(app.loads)
    note.get_by_role('button', name='Apply now').click()
    app.see('Restarting PegaProx...', timeout=3000)
    assert app.server.calls.count(('POST', '/api/ha/apply-config')) == 1
    app.wait_for_reload(before)
    panel = _open_ha(app, 'standby')
    assert panel.locator('[data-ha-restart-pending]').count() == 0
    assert not app.errors, app.errors


def test_runtime_an_unreadable_state_file_locks_the_live_view_too(open_app):
    app = open_app(role='standby', layout='modern', broken='bad json')
    _open_ha(app, 'standby')
    assert app.page.locator('#pgha-live-view').is_disabled()
    assert not app.errors, app.errors


NODE_METRICS = {'pve1': {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0, 'disk_percent': 10.0,
                         'score': 42.0, 'uptime': 86400, 'loadavg': [0.1, 0.2, 0.3], 'netin': 0, 'netout': 0,
                         'mem_used': 6871947673, 'mem_total': 34359738368, 'disk_used': 10737418240,
                         'disk_total': 107374182400, 'pveversion': 'pve-manager/9.0.3',
                         'kversion': 'Linux 6.14.8-2-pve', 'cpuinfo': {'cpus': 8, 'cores': 4, 'sockets': 1},
                         'maintenance_mode': False, 'is_updating': False}}


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_the_node_shows_but_does_not_change_on_a_standby(open_app, role):
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS)
    page = app.page
    standby = role == 'standby'
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Configuration"]').first.wait_for(timeout=5000)
    # the card: maintenance is the active's
    assert (page.locator('button[title="Enter Maintenance Mode"]').count() == 0) == standby

    page.locator('button[title="Node Configuration"]').first.click()
    page.get_by_text('Proxmox Node').first.wait_for(timeout=5000)
    tabs = page.evaluate('() => Array.from(document.querySelectorAll("button")).map(b => b.innerText.trim())')
    # the shell tab stays on a standby, and opens the shell on the active instead
    assert 'Shell' in tabs, tabs
    if standby:
        page.locator('button', has_text='Shell').last.click()
        link = page.locator('[data-ha-console-elsewhere] a[data-ha-on-active]')
        link.wait_for(timeout=3000)
        assert link.get_attribute('href') == PEER + '/'
        assert link.get_attribute('target') == '_blank'
        assert not [c for c in app.server.calls if 'shell' in c[1] or c[1] == '/api/ws/token']
    # a tab that changes things renders its controls disabled, a reading one does not
    page.locator('button', has_text='System').last.click()
    page.wait_for_timeout(300)
    assert (page.locator('fieldset[data-ha-locked]').count() == 1) == standby
    if standby:
        assert page.evaluate('() => document.querySelector("fieldset[data-ha-locked]").disabled')
    page.locator('button', has_text='Summary').last.click()
    page.wait_for_timeout(200)
    assert page.locator('fieldset[data-ha-locked]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_the_corporate_node_row_offers_no_action_on_a_standby(open_app, role):
    app = open_app(role=role, layout='corporate', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS)
    page = app.page
    standby = role == 'standby'
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    row = page.locator('.corp-node-row', has_text='pve1').first
    row.wait_for(timeout=5000)
    row.get_by_text('pve1').first.click()     # expands the row
    row.locator('.corp-toolbar').wait_for(timeout=3000)
    bar = row.locator('.corp-toolbar').inner_text()
    for word in ('Reboot', 'Shutdown', 'Maintenance'):
        assert (word not in bar) == standby, (word, bar)

    # the node in the tree (selecting the cluster opened it): its menu keeps what reads,
    # the detail view has no shell
    child = page.locator('.corp-tree-child', has_text='pve1').first
    child.wait_for(timeout=5000)
    child.click(button='right')
    menu = page.locator('.corp-context-menu').first
    menu.wait_for(timeout=3000)
    assert ('SSH Console' not in menu.inner_text()) == standby, menu.inner_text()
    # in its place, the way to the active
    assert ('Open on the active instance' in menu.inner_text()) == standby, menu.inner_text()
    page.keyboard.press('Escape')
    page.mouse.click(5, 900)
    child.click()
    strip = page.locator('.corp-tab-strip').last
    strip.get_by_text('Configure').wait_for(timeout=5000)
    assert 'Shell' in strip.inner_text(), strip.inner_text()
    page.locator('.corp-toolbar button', has_text='Actions').last.click()
    dropdown = page.locator('.corp-dropdown').last.inner_text()
    assert 'Node Settings' in dropdown
    assert ('Reboot Node' not in dropdown) == standby, dropdown
    page.mouse.click(5, 900)
    strip.get_by_text('Configure').click()
    page.wait_for_timeout(300)
    assert page.evaluate('() => Array.from(document.querySelectorAll("fieldset")).some(f => f.disabled)') == standby
    assert not app.errors, app.errors


def test_the_node_handlers_refuse_on_a_standby(dash):
    """Anything left that still reaches them: refused with the toast, before a question
    is asked or a request goes out."""
    guard = 'if (haReadOnly) { haRefusedRef.current?.(); return; }'
    for head in ('const handleMaintenanceToggle = async (nodeName, enable, options) => {',
                 'const handleStartUpdate = async (nodeName, reboot) => {',
                 'const handleNodeAction = async (nodeName, action) => {',
                 'const handleForceStop = async (resource) => {'):
        body = _block(dash, head, '\n            };')
        assert guard in body, head
        later = [i for i in (body.find('confirm('), body.find('authFetch(')) if i >= 0]
        assert later and body.index(guard) < min(later), head


def test_the_node_cards_show_but_do_not_change_on_a_standby():
    src = _read('web', 'src', 'tables.js')
    card = src[src.index('function NodeCard('):src.index('function NodeCompactRow(')]
    assert 'const { getAuthHeaders, haReadOnly } = useAuth();' in card
    assert '{!haReadOnly && !isInMaintenance && !isUpdating && (' in card
    assert "{!haReadOnly && (maintenanceTask?.status === 'completed' ||" in card
    assert "{!haReadOnly && (updateTask.status === 'completed' || updateTask.status === 'failed') && (" in card
    row = src[src.index('function NodeCompactRow('):src.index('function ResourceTable(')]
    assert 'const { getAuthHeaders, haReadOnly } = useAuth();' in row
    bar = row[row.index('{/* Action Buttons */}'):row.index('{/* Confirmation Modals */}')]
    assert bar.index('{!haReadOnly && (<>') < bar.index('setShowMaintenanceConfirm(true)')
    assert bar.index('setShowShutdownConfirm(true)') < bar.index('</>)}')
    assert '{!haReadOnly && !metrics.maintenance_acknowledged &&' in row


def test_the_corporate_node_view_shows_but_does_not_change_on_a_standby():
    src = _read('web', 'src', 'node_modals.js')
    body = src[src.index('function CorporateNodeDetailView('):]
    assert 'const { getAuthHeaders, reverseProxyEnabled, haReadOnly, haConsolesElsewhere } = useAuth();' in body
    assert "['summary', 'monitor', 'configure', 'hardware', 'vms', 'shell', 'subscription'].map(tab => (" in body
    assert "{activeDetailTab === 'shell' && haConsolesElsewhere && <HaConsoleOnActive />}" in body
    assert "{activeDetailTab === 'shell' && !haConsolesElsewhere && (" in body
    menu = body[body.index('<div className="corp-dropdown absolute right-0 top-full'):]
    assert menu.index('{!haReadOnly && (<>') < menu.index('onMaintenanceToggle(node, !isMaint)')
    assert menu.index("onNodeAction(node, 'shutdown')") < menu.index('</>)}') < menu.index('onOpenNodeConfig(node)')
    configure = body[body.index("{activeDetailTab === 'configure' && ("):body.index("{activeDetailTab === 'vms' && (")]
    # the sub navigation reads and stays outside the disabled part
    assert configure.index('corp-subnav-item') < configure.index('<fieldset disabled={haReadOnly} className="contents">')
    hw = body[body.index("{activeDetailTab === 'hardware' && ("):]
    assert hw.index('<fieldset disabled={haReadOnly} className="contents">') < hw.index('<HardwareMonitoringPanel')


def test_no_efficient_snapshot_refresh_from_a_standby():
    """GET ?refresh=true runs lvs and maybe lvextend on the node and writes the table."""
    cfg = _read('web', 'src', 'vm_config.js')
    modal = cfg[cfg.index('function ConfigModal('):]
    assert 'const { getAuthHeaders, haReadOnly, haStandby } = useAuth();' in modal[:400]
    # a GET is not forwarded: a forwarding standby would run it itself
    assert "efficient-snapshots${haStandby ? '' : '?refresh=true'}`" in cfg
    for name in ('vm_config.js', 'vm_modals.js'):
        assert 'efficient-snapshots?refresh=true' not in _read('web', 'src', name), name


def test_a_console_window_on_a_standby_says_why(dash):
    body = _block(dash, 'function StandaloneConsole(', 'function App(')
    assert 'const { getAuthHeaders, haConsolesElsewhere } = useAuth();' in body
    guard = "if (haConsolesElsewhere) {\n                    setState({ status: 'standby', clusterId, info: null,"
    assert guard in body
    # checked against the same rules as a real window first, and before anything is fetched
    assert body.index("setState({ status: 'error', error: 'malformed' });") < body.index(guard)
    assert body.index(guard) < body.index('await fetch(')
    assert '}, [consoleKey, haConsolesElsewhere]);' in body
    # it offers the same console on the active
    assert "if (state.status === 'standby') {" in body
    assert '<HaConsoleOnActive vm={state.vm} clusterId={state.clusterId} />' in body


# -- v2 review: the surfaces the first pass missed (#625) -----------------------------------
#
# Each finding of the v2 review gets a source check and, where it renders, a runtime check
# in both roles: the standby hides (or disables) what acts, the active keeps it.

GUARD = 'if (haReadOnly) { haRefusedRef.current?.(); return; }'


def _guarded_before(body, *later):
    """The standby guard comes before the first confirm, request or state change named."""
    assert GUARD in body, body[:120]
    first = [i for i in (body.find(x) for x in later) if i >= 0]
    assert first and body.index(GUARD) < min(first), body[:120]


def test_the_corporate_header_leaves_cluster_changes_to_the_active(dash):
    """verify:frontend:5 - the Corporate overview header had its own rename, re-configure
    and delete next to the read-only context menu."""
    header = _block(dash, '<div className="corp-content-header">', "{t('refreshData')")
    gate = header.index('{!haReadOnly && (<>')
    for action in ('setRenamingCluster(selectedCluster)', 'setReconfigureCluster(selectedCluster)',
                   'handleDeleteCluster(selectedCluster.id)'):
        assert gate < header.index(action) < header.index('</>)}'), action
    # the online badge and the health pill still read
    assert header.index('</>)}') < header.index('<ClusterHealthBadge')
    _guarded_before(_block(dash, 'const handleDeleteCluster = async (clusterId) => {', '\n            };'),
                    'confirm(', 'authFetch(')
    _guarded_before(_block(dash, 'const handleRenameCluster = async () => {', '\n            };'),
                    'confirm(', 'authFetch(')
    _guarded_before(_block(dash, 'const handleReconfigureAuth = async () => {', '\n            };'),
                    'setReconfigureLoading(', 'authFetch(')


def test_esxi_pbs_and_the_add_buttons_stay_on_the_active(dash):
    """verify:frontend:4"""
    # a forwarding standby adds through the active, so these follow the read-only flag
    assert '{!isCorporate && isAdmin && !haReadOnly && (' in dash                 # header Add Cluster
    assert '{!isCorporate && pbsServers.length === 0 && isAdmin && !haReadOnly && (' in dash
    assert '{!isCorporate && vmwareServers.length === 0 && isAdmin && !haReadOnly && (' in dash
    for opener in ('<button onClick={() => setShowAddPBS(true)} className="p-1',
                   "<button onClick={() => { setEditingVMware(null); setVmwareForm({ name: '', host: '', port: 443, "
                   "username: 'root', password: '', ssl_verify: false, notes: '' }); setShowAddVMware(true); }} className=\"p-1"):
        at = dash.index(opener)
        assert '{isAdmin && !haReadOnly && (' in dash[at - 120:at], opener
    # PBS edit/delete, encryption key and auto-verify; ESXi re-configure/delete
    for opener in ('<button onClick={() => { setEditingPBS(selectedPBS);', '<button onClick={() => setShowEncryptionKeyModal(true)}',
                   '<button onClick={() => setShowVerifyScheduleModal(true)}',
                   '<button onClick={() => openVmwareEdit(selectedVMware)} title='):
        at = dash.index(opener)
        assert '{isAdmin && !haReadOnly && (' in dash[at - 220:at], opener
    # the way to the settings of an ESXi server that refuses its password, too (#1142)
    at = dash.index('<button onClick={() => openVmwareEdit(selectedVMware)} data-esxi-error-edit')
    assert "{vmwareError?.code === 'UPSTREAM_AUTH' && isAdmin && !haReadOnly && (" in dash[at - 160:at]
    for head in ('const vmwarePowerAction = async (vmId, action) => {',
                 'const vmwareSnapshotAction = async (vmId, action, data = {}) => {',
                 'const toggleVMwareDRS = async (vmwId, clusterId, enabled, automation) => {',
                 'const toggleVMwareHA = async (vmwId, clusterId, enabled) => {',
                 'const handleDeleteVMware = async (vmwId) => {'):
        _guarded_before(_block(dash, head, '\n            };'), 'confirm(', 'authFetch(', 'setVmwareActionLoading(')
    # every power button, list and detail, and the HA/DRS switches sit behind the flag
    for call in ("onClick={() => vmwarePowerAction(vm.vm || vm.vm_id || vm.id, 'start')}",
                 "onClick={() => vmwarePowerAction(vmwareSelectedVm, 'start')}",
                 'onClick={() => toggleVMwareDRS(selectedVMware.id, cl.cluster, !cl.drs_enabled)}',
                 'onClick={() => toggleVMwareHA(selectedVMware.id, cl.cluster, !cl.ha_enabled)}',
                 "onClick={() => { setVmwareRenameName(vm.name || ''); setShowVmwareRename(true); }} className=\"w-full flex",
                 'onClick={() => fetchMigrationPlan(vmwareSelectedVm)} disabled={vmwareMigrateLoading} className="w-full py-2.5',
                 "onClick={() => vmwareSnapshotAction(vmwareSelectedVm, 'delete'"):
        at = dash.index(call)
        # the DRS switch sits after its automation select, inside the same gate
        assert '!haReadOnly && ' in dash[at - (1800 if 'DRS' in call else 700):at], call
    assert "{vmwareVmTab === 'settings' && (() => {" in dash
    settings = dash[dash.index("{vmwareVmTab === 'settings' && (() => {"):dash.index("{vmwareVmTab === 'config' && (")]
    assert "<fieldset disabled={haReadOnly} className=\"space-y-4 min-w-0\" data-ha-locked={haReadOnly ? '' : undefined}>" in settings
    assert settings.index('{!haReadOnly && (') < settings.index('onClick={() => handleVmwareConfigSave(vmwareSelectedVm)}')


def test_the_toast_for_a_repeated_error_gets_its_own_lifetime(dash):
    """verify:frontend:7 - addToast run in node: the second identical toast replaces the
    first, so the first one's timer no longer takes the newer message off the screen."""
    import shutil
    import subprocess
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not installed')
    fn = _block(dash, 'const addToast = (message, type = ', '\n            };') + '\n            };'
    script = """
    let toasts = [];
    const setToasts = (f) => { toasts = f(toasts); };
    const timers = [];
    const setTimeout = (fn, ms) => timers.push(fn);
    %s
    addToast('VM 100 is locked', 'error');
    const first = toasts.map(x => x.id);
    addToast('VM 100 is locked', 'error');
    const second = toasts.map(x => x.id);
    timers[0]();                        // the first toast's 5 s timer runs out
    const after = toasts.map(x => x.message);
    addToast('something else', 'error');
    addToast('VM 100 is locked', 'success');
    console.log(JSON.stringify({first, second, after, n: toasts.length}));
    """ % fn
    res = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    assert len(out['first']) == 1 and len(out['second']) == 1
    assert out['second'] != out['first']            # replaced, not dropped
    assert out['after'] == ['VM 100 is locked']     # the retry's copy outlives the first timer
    assert out['n'] == 3                            # other text or type: a toast of its own


def test_the_snapshot_overview_deletes_only_for_who_may_and_reads_the_answer(dash):
    """verify:frontend:1"""
    assert "const canDeleteSnaps = can('vm.snapshot');" in dash
    ov = dash[dash.index('const selCount = (sortedSnapshots || []).filter(s => selectedSnaps[snapKey(s)]).length;'):]
    ov = ov[:ov.index('</table>')]
    assert 'return canDeleteSnaps && selCount > 0 ? (' in ov
    assert ov.count('{canDeleteSnaps && (') == 3            # select-all, row checkbox, row delete
    assert ov.count("{canDeleteSnaps && <th className={isCorporate ? 'corp-snap-action'") == 1
    for head in ('const deleteSelectedSnapshots = async (clusterId) => {',
                 'const deleteGlobalSnapshot = async (snap, clusterId) => {'):
        body = _block(dash, head, '\n            };')
        assert 'const res = await authFetch(`${API_URL}/snapshots/delete`' in body
        fail = body.index('if (!res || !res.ok) {')
        assert fail < body.index("'success')")
        assert 'snapDeleteError(data, ' in body[fail:body.index("'success')")]
    bulk = _block(dash, 'const deleteSelectedSnapshots = async (clusterId) => {', '\n            };')
    assert bulk.index('return;\n', bulk.index('if (!res || !res.ok) {')) < bulk.index('setSelectedSnaps({});')
    assert '`${data.deleted ?? chosen.length} snapshot(s) deleted`' in bulk


def test_a_failed_action_puts_the_old_status_back(dash):
    """verify:frontend:9 - the refetch skips data that did not change, so the handler undoes
    its own optimistic flip on every failure path."""
    body = _block(dash, 'const handleVmAction = async (resource, action) => {', 'const handleMigrate = ')
    undo = body[body.index('const unflip = () => {'):]
    undo = undo[:undo.index('\n                };')]
    assert 'if (!flipped) return;' in undo
    assert '? { ...r, status: resource.status, _optimistic: false }' in undo
    assert 'r._optimistic' in undo
    # three failure paths, each undoes before it refetches
    tail = body[body.index('const response = await authFetch('):]
    assert tail.count('unflip();') == 3
    for m in re.finditer(r'fetchClusterResources\(selectedCluster\.id\);', tail):
        assert tail.rindex('unflip();', 0, m.start()) > tail.rindex("updateRecentTask(taskId, 'completed');", 0, m.start())


def test_no_permission_copy_ignores_the_standby():
    """verify:frontend:3 - Site Recovery and Multi-Cluster EVPN read the permission list
    themselves; outside the helpers nothing may read it without the flag."""
    helpers = {'dashboard.js': ['const can = (permission) =>', 'const holds = (permission) =>'],
               'storage.js': ['const hasPerm = (p) =>'], 'security.js': ['const hasPerm = (p) =>']}
    seen = 0
    for name in sorted(os.listdir(SRC)):
        if not name.endswith('.js'):
            continue
        src = _read('web', 'src', name)
        for m in re.finditer(r'\buser\??\.permissions\??\.includes\(', src):
            seen += 1
            stmt = src[src.rindex('\n', 0, src.rindex('const ', 0, m.start())):src.index(';', m.start())]
            if any(h in stmt for h in helpers.get(name, [])):
                continue
            assert 'haReadOnly' in stmt, (name, stmt.strip()[:160])
    assert seen >= 6
    dash = _read('web', 'src', 'dashboard.js')
    sr = _block(dash, 'function SiteRecoveryTab(', 'const [plans, setPlans]')
    assert 'const { haReadOnly } = useAuth();' in sr
    assert "const canManage = !haReadOnly && !!user?.permissions?.includes('site_recovery.manage');" in sr
    assert "const canFailover = !haReadOnly && !!user?.permissions?.includes('site_recovery.failover');" in sr
    assert "canAdminSettings={can('admin.settings')}" in dash
    assert "canManage={can('sdn.manage') && can('admin.settings')}" in dash
    # a plan's mappings and settings save only for who may manage it
    assert '{canManage && <div className="flex justify-end"><button onClick={saveMappings}' in dash
    assert '{canManage && <div className="flex justify-end"><button onClick={saveSettings}' in dash


def test_the_vm_configuration_locks_on_a_standby():
    """verify:frontend:6"""
    cfg = _read('web', 'src', 'vm_config.js')
    modal = _function(cfg, 'ConfigModal')
    assert "const lockedTab = haReadOnly && activeTab !== 'history';" in modal
    fs = modal.index("<fieldset disabled={lockedTab} className=\"contents\" data-ha-locked={lockedTab ? '' : undefined}>")
    fe = modal.index('</fieldset>', fs)
    for tab in ('general', 'disks', 'network', 'snapshots', 'backups', 'replication', 'history', 'firewall',
                'options'):
        assert fs < modal.index("{activeTab === '%s' && (" % tab, fs) < fe, tab
    # the tab strip and the retry after a load error stay outside
    assert modal.index('onClick={() => setActiveTab(tab.id)}') < fs
    assert modal.index('onClick={() => { setConfigError(null); fetchConfig(); }}') < fs
    # no Save (footer) and no Apply (corporate header) on a standby
    assert '{hasChanges && !haReadOnly && (' in modal
    assert ('{!haReadOnly && <button\n                                    onClick={handleSave}\n'
            '                                    disabled={!hasChanges || saving}') in modal


def test_the_update_check_does_not_run_from_a_standby():
    """verify:frontend:2 - opening a cluster's Settings posted the check, which SSHes every
    node and which the standby refuses."""
    sec = _read('web', 'src', 'security.js')
    comp = _function(sec, 'UpdateManagerSection')
    mount = comp[comp.index('// Load cached status from localStorage'):comp.index('// Poll for rolling update status')]
    calls = [m.start() for m in re.finditer(r'checkUpdates\(\)', mount)]
    assert len(calls) == 3
    for at in calls:
        assert '!haReadOnly' in mount[at - 130:at], mount[at - 130:at]
    # a cached result still shows
    assert mount.index('setUpdateStatus({ summary: data.summary') < mount.index('!haReadOnly')
    rolling = comp[comp.index('// #183: auto-refresh update counts'):]
    assert rolling.index('if (haReadOnly) return;') < rolling.index('checkUpdates();')
    assert "{!haReadOnly && <button\n                                    onClick={(e) => { e.stopPropagation(); checkUpdates(true); }}" in comp
    assert "json.code === 'HA_STANDBY' ? (haServing ? t('pgHaServingRefused') : t('pgHaStandbyRefused'))" in comp


def test_closing_an_esxi_vm_never_toasts(dash):
    """verify:frontend:0 - the unwatch on close goes out quiet; the watch itself is left as is."""
    effect = dash[dash.index('// Watch VM detail via SSE'):]
    effect = effect[:effect.index('}, [selectedVMware?.id, vmwareSelectedVm]);')]
    assert 'quiet' not in effect[effect.index("method: 'POST'"):effect.index('watchVm();')]
    assert "method: 'DELETE',\n                            quiet: true" in effect[effect.index('// Unwatch'):]


def test_compliance_stays_a_reading_tab_on_a_standby(dash):
    """info: the tab only reads, so on a standby it stays for whoever reads it on the active;
    its acting buttons still ask the flag."""
    assert ('const holds = (permission) => isAdmin || (Array.isArray(user?.permissions) '
            '&& user.permissions.includes(permission));') in dash
    assert "if (tab.id === 'compliance') return holds('admin.audit') || holds('node.maintenance');" in dash
    # holds() decides this tab, whether a standby offers a console on the active, and the
    # console entries of a member that opens them itself
    assert len(re.findall(r'\bholds\(', dash)) == 4
    assert 'const onActiveItems = (permission, search, disabled = false) => !holds(permission) ? [] : [{' in dash
    assert 'const menuAllows = (i) => !i.perm || (i.console ? holds(i.perm) : can(i.perm));' in dash
    drift = _function(dash, 'DriftTab')
    assert 'const canAct = isAdmin && !haReadOnly;' in drift and '{isAdmin && (' not in drift


@pytest.mark.parametrize('component,flag', [('PowerCarbonTab', 'haReadOnly'), ('CostDashboardTab', 'haReadOnly'),
                                            ('DriftTab', 'haReadOnly'), ('TemplatesLibraryTab', 'haReadOnly'),
                                            # its one button writes this instance's own metrics (v3)
                                            ('InsightsTab', 'haStandby')])
def test_the_admin_buttons_of_the_report_tabs_follow_the_flag(dash, component, flag):
    body = _function(dash, component)
    assert re.search(r'const \{ [^}]*\b%s\b[^}]*\} = useAuth\(\);' % flag, body)
    assert f'const canAct = isAdmin && !{flag};' in body
    assert len(re.findall(r'\bisAdmin\b', body)) == 2        # the prop and canAct
    assert 'canAct' in body.split('const canAct = ', 1)[1]


def test_automation_reports_and_settings_leave_acting_to_the_active(dash):
    """info: the acting controls haReadOnly reaches cheaply."""
    auto = dash[dash.index("{automationSubTab === 'schedules' && ("):dash.index("{automationSubTab === 'snapshots' && (")]
    for opener in ("onClick={() => { setEditingSchedule(null); setShowScheduleModal(true); }}",
                   "setEditingAlert(null);  // #618", "onClick={() => setShowAffinityModal(true)}",
                   "onClick={() => { setEditingScript(null); setShowScriptModal(true); }}",
                   "onClick={() => setShowScriptRunModal(script)}", "onClick={() => deleteClusterAffinityRule(rule.id)}",
                   "onClick={() => { setEditingSchedule(schedule); setShowScheduleModal(true); }}",
                   "onClick={() => openEditAlert(alert)}", "onClick={() => { setEditingScript(script); setShowScriptModal(true); }}"):
        at = auto.index(opener)
        assert '{!haReadOnly && (' in auto[max(0, at - 260):at], opener
    for toggle in ('onClick={() => toggleScheduleEnabled(schedule.id, !schedule.enabled)}\n',
                   'onClick={() => toggleAlertEnabled(alert.id, !alert.enabled)}\n'):
        assert auto[auto.index(toggle) + len(toggle):].lstrip().startswith('disabled={haReadOnly}'), toggle
    # a fired alert is acked through the active like any change (v6)
    assert '{!a.acked_at && !haReadOnly && (' in auto
    # the scripts' Refresh reads
    at = auto.index('onClick={() => loadCustomScripts(')
    assert '{!haReadOnly' not in auto[at - 200:at]
    for head in ('const handleBalanceNow = async () => {', 'const startXhmMigration = async () => {',
                 'const installDebsecan = async (clusterId = null) => {', 'const applyHardening = () => {',
                 'const rollbackHardening = async () => {', 'const runCveScan = async (clusterId = null) => {'):
        _guarded_before(_block(dash, head, '\n            };'), 'authFetch(', 'setHardenConfirm(', 'setCveScanLoading(')
    for button in ('onClick={handleBalanceNow}', 'onClick={() => runCveScan()}', 'onClick={() => installDebsecan()}',
                   'onClick={applyHardening}'):
        at = dash.index(button)
        assert '{!haReadOnly && (' in dash[at - 200:at], button
    assert '{!haReadOnly && <button onClick={startXhmMigration}' in dash


def test_the_cloud_pages_change_nothing_from_a_standby(cloud):
    """info: useCloudMutate backs every change the Cloud secondary pages make."""
    hook = _function(cloud, 'useCloudMutate')
    assert 'const { getAuthHeaders, haReadOnly, haServing } = useAuth();' in hook
    assert 'return { busy, run, acts: !haReadOnly };' in hook
    assert "b && b.code === 'HA_STANDBY' ? (haServing ? t('pgHaServingRefused') : t('pgHaStandbyRefused'))" in hook
    assert '}, [reload, t, haServing]);' in hook
    # every row button that runs a change sits behind the flag
    rows = 0
    for m in re.finditer(r'<CloudRowActions>(.*?)</CloudRowActions>', cloud, re.S):
        inner = m.group(1)
        for call in re.finditer(r'<CloudIconBtn [^\n]*?onClick=\{[^\n]*?(mut\.run\(|setRunFor\()', inner):
            rows += 1
            before = inner[:call.start()]
            assert before.rstrip().endswith('{mut.acts &&') or before.lstrip().startswith('{mut.acts && (<>'), inner[:200]
    assert rows >= 12
    for opener in ("{t('cloud.newRule') || 'New rule'}", "{t('cloud.newScript') || 'New script'}",
                   "{t('cloud.newSchedule') || 'New schedule'}"):
        line = cloud[cloud.rindex('\n', 0, cloud.index(opener)):cloud.index(opener)]
        assert '{mut.acts && <button' in line, opener
    assert '{s.pending && mut.acts ? (' in cloud
    assert cloud.count('right: mut.acts ? <button type="button" className="cloud-link-btn" onClick={() => setModal(') == 2
    assert 'right: vnets.length && mut.acts ? <button' in cloud
    # plugin rescan, reload and disable: refused on every standby, forwarding or not (v3)
    plugins = _function(cloud, 'CloudPlugins')
    assert 'const { haStandby } = useAuth();' in plugins
    line = plugins[plugins.rindex('\n', 0, plugins.index("mut.run('rescan'")):plugins.index("mut.run('rescan'")]
    assert '{!haStandby && <button' in line
    assert 'right: !haStandby && (\n' in plugins
    assert 'mut.acts' not in plugins
    cve = _function(cloud, 'CloudCVE')
    assert 'const { haReadOnly } = useAuth();' in cve
    assert '{!haReadOnly && <button type="button" className="cloud-btn-primary" onClick={scan}' in cve


# -- runtime -----------------------------------------------------------------------------------

ESXI = {'id': 'v1', 'name': 'esx01', 'host': '10.0.0.9', 'port': 443, 'server_type': 'esxi',
        'connected': True, 'status': 'connected', 'enabled': True}
EVM = {'vm': 'vm-1', 'name': 'legacy01', 'power_state': 'POWERED_ON', 'cpu_count': 2,
       'memory_size_MiB': 4096, 'guest_OS': 'UBUNTU_64', 'host': 'esx01.lab'}
PBS = {'id': 'p1', 'name': 'backup01', 'host': '10.0.0.20', 'port': 8007, 'user': 'root@pam',
       'connected': True, 'status': 'connected', 'linked_clusters': []}
ESXI_READS = {('GET', '/api/vmware'): (200, [ESXI]), ('GET', '/api/vmware/v1/vms'): (200, [EVM]),
              ('GET', '/api/vmware/v1/vms/vm-1'): (200, dict(EVM)), ('GET', '/api/pbs'): (200, []),
              # the watch is a read the backend lets a standby register (#625)
              ('POST', '/api/vmware/v1/vms/vm-1/watch'): (200, {'success': True})}
ESXI_POWER = {'Start', 'Stop', 'Shutdown', 'Reset', 'Suspend', 'Console (VMRC)'}
# the real app hands a standby its SSE token (a local write); the fake's refusal would put
# a toast on the screen that has nothing to do with what a test looks at. No token in the
# answer, so the page polls instead of opening a stream.
SSE_TOKEN = {('POST', '/api/sse/token'): (200, {})}

TOASTS_JS = '''() => { const c = Array.from(document.body.children).find(d => d.style && d.style.zIndex === '99999');
    return c ? Array.from(c.children).map(x => x.innerText.trim()) : []; }'''


def _toasts(page):
    return page.evaluate(TOASTS_JS)


def _wait_for_call(app, call, seconds=3):
    deadline = time.time() + seconds
    while time.time() < deadline and call not in app.server.calls:
        app.page.wait_for_timeout(100)
    return call in app.server.calls


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_the_corporate_header_leaves_cluster_changes_to_the_active(open_app, role):
    app = open_app(role=role, layout='corporate', clusters=[CLUSTER], resources=[VM])
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-content-header').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    titles = set(page.evaluate('() => Array.from(document.querySelectorAll(".corp-content-header button"))'
                               '.filter(b => b.offsetParent !== null)'
                               '.map(b => (b.getAttribute("title") || b.innerText || "").trim())'))
    changes = {'Rename Cluster', 'Re-configure Cluster', 'Delete Cluster'}
    if role == 'standby':
        assert not changes & titles, titles
    else:
        assert changes <= titles, titles
    assert 'Refresh' in ' '.join(titles)
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_esxi_and_the_add_buttons_on_a_standby(open_app, role):
    """verify:frontend:4"""
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM], extra=ESXI_READS)
    page = app.page
    standby = role == 'standby'
    page.get_by_text('esx01').first.wait_for(timeout=8000)
    assert (page.locator('header button', has_text='Add Cluster').count() == 0) == standby
    assert (page.locator('button[title="Add ESXi Server"]').count() == 0) == standby
    assert (page.locator('button', has_text='Add Backup Server').count() == 0) == standby

    page.get_by_text('esx01').first.click()
    page.get_by_text('legacy01').first.wait_for(timeout=8000)
    page.wait_for_timeout(300)
    listed = _labels(page)
    assert bool(listed & ESXI_POWER) != standby, sorted(listed & ESXI_POWER)
    page.get_by_text('legacy01').first.click()
    page.locator('button', has_text='Snapshots').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    detail = _labels(page)
    assert bool(detail & ESXI_POWER) != standby, sorted(detail & ESXI_POWER)
    # the more-actions menu (rename, clone, migrate, delete) is in the page, shown on hover
    assert (page.get_by_text('Migrate to Proxmox').count() == 0) == standby
    page.locator('button', has_text='Snapshots').first.click()
    page.wait_for_timeout(200)
    assert (page.get_by_text('Create Snapshot').count() == 0) == standby
    assert not [c for c in app.server.calls if '/power/' in c[1]]
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_the_pbs_toolbar_edits_only_on_the_active(open_app, role):
    """verify:frontend:4"""
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM],
                   extra={('GET', '/api/pbs'): (200, [PBS])})
    page = app.page
    standby = role == 'standby'
    page.get_by_text('backup01').first.wait_for(timeout=8000)
    assert (page.locator('button[title="Add PBS"]').count() == 0) == standby
    page.get_by_text('backup01').first.click()
    page.locator('button', has_text='Encryption Key' if not standby else 'Refresh').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    labels = _labels(page)
    for word in ('Edit', 'Delete', 'Encryption Key', 'Auto Verify'):
        assert (not any(label.endswith(word) for label in labels)) == standby, (word, sorted(labels))


NODE_PATH = '/api/clusters/c1/nodes/pve1'
NODE_READS = {('GET', NODE_PATH + sub): (200, data) for sub, data in {
    '/summary': {'status': 'online', 'uptime': 100, 'cpu': 0.1, 'loadavg': [0, 0, 0],
                 'memory': {'used': 1, 'total': 2}, 'rootfs': {'used': 1, 'total': 2}},
    '/disks': [{'devpath': '/dev/sda', 'model': 'Samsung SSD', 'size': 500107862016, 'type': 'ssd',
                'used': 'LVM', 'health': 'PASSED', 'serial': 'S1'},
               {'devpath': '/dev/sdb', 'model': 'Spare', 'size': 500107862016, 'type': 'hdd',
                'used': 'unused', 'health': 'PASSED', 'serial': 'S2'}],
    '/disks/lvm': [], '/disks/lvmthin': [], '/disks/zfs': [],
    '/disks/sda/smart': {'health': 'PASSED', 'type': 'ata', 'attributes': [
        {'id': 5, 'name': 'Reallocated_Sector_Ct', 'value': 100, 'worst': 100, 'threshold': 10,
         'raw': '0', 'flags': 'PO--CK'}]},
    '/dns': {'search': 'lan', 'dns1': '1.1.1.1'}, '/hosts': {'data': '127.0.0.1 localhost'},
    '/time': {'timezone': 'UTC', 'localtime': 0}, '/syslog': ['hello syslog'], '/certificates': [],
    '/cluster-health': {'quorate': True, 'rings': [], 'services': []},
    '/sensors': {'sensors': [{'chip': 'coretemp', 'label': 'Package id 0', 'type': 'temp', 'value': 42.0}]},
}.items()}


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_the_node_modal_reads_but_changes_nothing_on_a_standby(open_app, role):
    """verify:frontend:8 - Refresh and SMART keep working, the changing parts stay locked."""
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS,
                   extra=NODE_READS)
    page = app.page
    standby = role == 'standby'
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Configuration"]').first.wait_for(timeout=5000)
    page.locator('button[title="Node Configuration"]').first.click()
    page.get_by_text('Proxmox Node').first.wait_for(timeout=5000)

    page.locator('button', has_text='Disks').last.click()
    smart = page.locator('button[title="SMART Data"]').first
    smart.wait_for(timeout=5000)
    assert smart.is_enabled()
    assert page.locator('button[title="Wipe Disk"]').first.is_disabled() == standby
    assert page.locator('button', has_text='Create LVM').first.is_disabled() == standby
    smart.click()
    page.get_by_text('Reallocated_Sector_Ct').first.wait_for(timeout=5000)
    assert ('GET', NODE_PATH + '/disks/sda/smart') in app.server.calls

    # the backdrop closes the SMART view. Clicked below the top edge: this harness has no live
    # updates, so 'Live updates disconnected' sticks to the top about 3 s after the page loads
    # and, on a slow run, catches a click at (5, 5) before the backdrop does
    page.mouse.click(5, 300)
    page.get_by_text('Reallocated_Sector_Ct').first.wait_for(state='hidden', timeout=3000)
    page.locator('button', has_text='System').last.click()
    page.get_by_text('hello syslog').first.wait_for(timeout=5000)
    refresh = page.locator('button[title="Refresh"]').first
    assert refresh.is_enabled()
    before = app.server.calls.count(('GET', NODE_PATH + '/syslog'))
    refresh.click()
    deadline = time.time() + 3
    while time.time() < deadline and app.server.calls.count(('GET', NODE_PATH + '/syslog')) == before:
        page.wait_for_timeout(100)
    assert app.server.calls.count(('GET', NODE_PATH + '/syslog')) == before + 1
    page.get_by_text('hello syslog').first.wait_for(timeout=5000)
    assert page.locator('input[value="1.1.1.1"]').first.is_disabled() == standby
    assert not [c for c in app.server.calls if c[0] != 'GET' and c[1].startswith(NODE_PATH)]
    assert not app.errors, app.errors


def test_runtime_a_retry_that_fails_the_same_way_still_shows(open_app):
    """verify:frontend:7 - on an active: the second identical error replaces the first toast
    and outlives the first one's timer."""
    err = {'error': 'VM 100 is locked (backup)'}
    reboot = ('POST', '/api/clusters/c1/vms/pve1/qemu/100/reboot')
    app = open_app(role='active', layout='modern', clusters=[CLUSTER], resources=[VM], extra={reboot: (500, err)})
    page = app.page
    page.on('dialog', lambda d: d.accept())
    _open_resources(app)
    page.locator('button[title="Reboot"]').first.click()
    deadline = time.time() + 5
    while time.time() < deadline and not any(err['error'] in x for x in _toasts(page)):
        page.wait_for_timeout(10)
    t0 = time.time()
    page.wait_for_timeout(2800)
    page.locator('button[title="Reboot"]').first.click()
    page.wait_for_timeout(max(0, int((t0 + 5.4 - time.time()) * 1000)))
    assert app.server.calls.count(reboot) == 2
    assert [x for x in _toasts(page) if err['error'] in x], 'the retry lost its error'
    assert not app.errors, app.errors


SNAP = {'cluster_id': 'c1', 'node': 'pve1', 'vm_type': 'qemu', 'vmid': 100, 'vm_name': 'web01',
        'snapshot_name': 'before-upgrade', 'snapshot_date': '2026-09-01 10:00', 'age': '29 days'}


def _open_snapshot_overview(app):
    page = app.page
    page.on('dialog', lambda d: d.accept())
    _open_resources(app)
    page.locator('button', has_text='Snapshot Overview').first.click()
    page.get_by_text('before-upgrade').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)


def test_runtime_the_snapshot_overview_lists_but_deletes_nothing_on_a_standby(open_app):
    """verify:frontend:1"""
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM],
                   extra={('POST', '/api/snapshots/overview'): (200, {'snapshots': [SNAP]})})
    _open_snapshot_overview(app)
    page = app.page
    assert page.locator('button[title="Delete snapshot"]').count() == 0
    assert page.locator('table input[type="checkbox"]').count() == 0
    assert ('POST', '/api/snapshots/delete') not in app.server.calls
    assert not app.errors, app.errors


@pytest.mark.parametrize('bulk', [False, True])
def test_runtime_a_refused_snapshot_delete_says_so(open_app, bulk):
    """verify:frontend:1 - on an active the handlers read the answer: no 'deleted' after a
    failure, the server's reason instead."""
    reason = 'Failed to delete before-upgrade: snapshot is locked'
    app = open_app(role='active', layout='modern', clusters=[CLUSTER], resources=[VM],
                   extra={('POST', '/api/snapshots/overview'): (200, {'snapshots': [SNAP]}),
                          ('POST', '/api/snapshots/delete'): (500, {'success': False, 'error': 'No snapshots deleted',
                                                                    'errors': [reason]})})
    _open_snapshot_overview(app)
    page = app.page
    if bulk:
        page.locator('tbody input[type="checkbox"]').first.check()
        page.locator('button', has_text='deleteSelected').first.click()   # the key has no text yet (pre-existing)
    else:
        page.locator('button[title="Delete snapshot"]').first.click(force=True)
    page.get_by_text(reason).first.wait_for(timeout=5000)
    toasts = _toasts(page)
    assert not [x for x in toasts if 'deleted' in x], toasts
    assert app.server.calls.count(('POST', '/api/snapshots/delete')) == 1
    if bulk:   # the selection stays for a retry
        assert page.locator('tbody input[type="checkbox"]').first.is_checked()
    assert not app.errors, app.errors


def test_runtime_a_failed_shutdown_shows_the_guest_running_again(open_app):
    """verify:frontend:9 - the refetch finds nothing changed and skips the repaint; the
    handler puts the status back itself."""
    app = open_app(role='active', layout='modern', clusters=[CLUSTER], resources=[VM],
                   extra={('POST', '/api/clusters/c1/vms/pve1/qemu/100/shutdown'):
                          (500, {'error': 'VM 100 is locked (backup)'})})
    page = app.page
    page.on('dialog', lambda d: d.accept())
    _open_resources(app)
    page.locator('button[title="Shutdown"]').first.click()
    page.get_by_text('VM 100 is locked (backup)').first.wait_for(timeout=5000)
    page.locator('button[title="Shutdown"]').first.wait_for(timeout=2500)
    assert page.locator('button[title="Start"]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_site_recovery_and_evpn_follow_the_flag(open_app, role):
    """verify:frontend:3 - with the permission list the real /auth/check sends an admin."""
    from pegaprox.utils.rbac import get_user_permissions
    perms = sorted(get_user_permissions({'username': 'admin', 'role': 'admin'}))
    remote = dict(CLUSTER, id='c2', name='Remote', display_name='Remote', host='10.0.0.2')
    plan = {'id': 'p1', 'name': 'DR-Plan-One', 'source_cluster': 'c1', 'target_cluster': 'c2', 'status': 'ready',
            'vms': [{'id': 'v1', 'vmid': 100, 'vm_name': 'web01', 'boot_group': 0, 'boot_delay': 30,
                     'vm_type': 'qemu'}], 'network_mappings': {}, 'storage_mappings': {}, 'auto_failover': False}
    vnet = {'id': 'n1', 'name': 'evpn10', 'alias': '', 'zone': 'z1', 'vni': 10010, 'asn': 65000,
            'controller': 'ctl', 'status': 'applied', 'member_clusters': ['c1', 'c2'],
            'per_cluster_status': {'c1': {'status': 'applied'}, 'c2': {'status': 'applied'}}}
    app = open_app(role=role, layout='modern', clusters=[CLUSTER, remote], resources=[VM], permissions=perms,
                   extra={('GET', '/api/site-recovery/plans'): (200, [plan]),
                          ('GET', '/api/site-recovery/plans/p1'): (200, plan),
                          ('GET', '/api/site-recovery/plans/p1/events'): (200, []),
                          ('GET', '/api/cross-cluster-replications'): (200, []),
                          ('GET', '/api/multi-sdn/vnets'): (200, [vnet]),
                          ('GET', '/api/settings/server'): (200, {'multi_sdn_drift_reconcile': False})})
    page = app.page
    standby = role == 'standby'
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Site Recovery').first.click()
    page.get_by_text('DR-Plan-One').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    assert ('Create Plan' not in _labels(page)) == standby
    page.get_by_text('DR-Plan-One').first.click()
    page.wait_for_timeout(800)
    acting = {'Readiness Check', 'DR Drill', 'Test Failover', 'Planned Failover', 'Emergency Failover'}
    if not standby:
        page.get_by_text('Planned Failover').first.wait_for(timeout=5000)
    assert (not acting & _labels(page)) == standby, sorted(acting & _labels(page))

    page.locator('button', has_text='Multi-Cluster EVPN').first.click()
    page.get_by_text('evpn10').first.wait_for(timeout=5000)
    page.get_by_text('evpn10').first.click()
    page.wait_for_timeout(400)
    evpn = {'Create EVPN vNet', 'Scan for drift', 'Re-apply / retry', 'Reconcile drift', 'Forget record',
            'Delete + purge from clusters'}
    assert (not evpn & _labels(page)) == standby, sorted(evpn & _labels(page))
    assert not [c for c in app.server.calls if c[0] != 'GET' and ('site-recovery' in c[1] or 'multi-sdn' in c[1])]
    assert not app.errors, app.errors


VM_CONFIG = {'general': {'name': 'web01', 'description': '', 'tags': ''},
             'hardware': {'cores': 2, 'sockets': 1, 'cpu': 'host', 'memory': '4096', 'balloon': 0,
                          'bios': 'seabios', 'scsihw': 'virtio-scsi-single'},
             'disks': [{'id': 'scsi0', 'value': 'local-lvm:vm-100-disk-0,size=32G', 'storage': 'local-lvm',
                        'size': '32G', 'volume': 'vm-100-disk-0'}],
             'networks': [{'id': 'net0', 'value': 'virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0', 'bridge': 'vmbr0',
                           'model': 'virtio', 'macaddr': 'AA:BB:CC:DD:EE:FF'}],
             'options': {'onboot': 0, 'boot': 'order=scsi0', 'ostype': 'l26', 'agent': '0'},
             'unused_disks': [], 'raw': {'name': 'web01', 'digest': 'x'}, 'status': {'status': 'running'},
             'vmid': 100, 'node': 'pve1', 'type': 'qemu', 'lock': {'locked': False}}


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_the_vm_configuration_changes_nothing_on_a_standby(open_app, role):
    """verify:frontend:6"""
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM],
                   extra={('GET', '/api/clusters/c1/vms/pve1/qemu/100/config'): (200, VM_CONFIG)})
    page = app.page
    standby = role == 'standby'
    _open_resources(app)
    page.locator('button[title="Configuration"]').first.click()
    name = page.locator('input[value="web01"]').first
    name.wait_for(timeout=8000)
    assert name.is_disabled() == standby
    assert (page.locator('fieldset[data-ha-locked]').count() == 1) == standby
    assert (page.locator('button', has_text='Save').count() == 0) == standby
    # History only reads, it stays usable
    page.locator('button', has_text='History').first.click()
    page.wait_for_timeout(300)
    assert page.locator('fieldset[data-ha-locked]').count() == 0
    assert not [c for c in app.server.calls if c[0] != 'GET' and '/qemu/100/' in c[1]]
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_the_settings_tab_checks_for_updates_only_on_the_active(open_app, role):
    """verify:frontend:2"""
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM], extra=SSE_TOKEN)
    page = app.page
    page.get_by_text('Testi').first.click()
    page.wait_for_timeout(800)
    page.locator('button', has_text='Settings').last.click()
    check = ('POST', '/api/clusters/c1/updates/check')
    posted = _wait_for_call(app, check, 3)
    assert posted != (role == 'standby')
    assert not [x for x in _toasts(page) if 'standby' in x.lower()]
    assert not app.errors, app.errors


def test_runtime_closing_an_esxi_vm_on_a_standby_says_nothing(open_app):
    """verify:frontend:0 - the unwatch a standby refuses stays quiet."""
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM],
                   extra={**ESXI_READS, **SSE_TOKEN})
    page = app.page
    page.get_by_text('esx01').first.wait_for(timeout=8000)
    page.get_by_text('esx01').first.click()
    page.get_by_text('legacy01').first.wait_for(timeout=8000)
    page.get_by_text('legacy01').first.click()
    page.locator('button', has_text='Snapshots').first.wait_for(timeout=5000)
    assert ('POST', '/api/vmware/v1/vms/vm-1/watch') in app.server.calls
    page.get_by_text('esx01').first.click()      # back to the list: the view closes
    assert _wait_for_call(app, ('DELETE', '/api/vmware/v1/vms/vm-1/watch'))
    page.wait_for_timeout(500)
    assert not _toasts(page), _toasts(page)
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_compliance_stays_on_a_standby(open_app, role):
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM])
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.wait_for(timeout=5000)
    assert page.locator('button', has_text='Compliance').count() >= 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_automation_changes_nothing_on_a_standby(open_app, role):
    schedule = {'id': 's1', 'cluster_id': 'c1', 'name': 'nightly', 'vmid': 100, 'vm_type': 'qemu',
                'action': 'snapshot', 'schedule_type': 'daily', 'time': '02:00', 'enabled': True}
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM],
                   extra={('GET', '/api/schedules'): (200, [schedule]),
                          ('GET', '/api/clusters/c1/scripts'): (200, [])})
    page = app.page
    standby = role == 'standby'
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Automation').first.click()
    page.get_by_text('nightly').first.wait_for(timeout=5000)
    page.wait_for_timeout(200)
    assert (page.locator('button', has_text='New Schedule').count() == 0) == standby
    assert (page.locator('button[title="Edit"]').count() == 0) == standby
    row = page.locator('tr', has_text='nightly').first
    assert row.locator('button').first.is_disabled() == standby      # the switch still shows the state
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_cloud_backups_change_nothing_on_a_standby(open_app, role):
    job = {'id': 'backup-1', 'enabled': 1, 'schedule': 'daily', 'storage': 'local', 'mode': 'snapshot',
           'vmid': '100', 'node': 'pve1'}
    app = open_app(role=role, layout='cloud', clusters=[CLUSTER], resources=[VM],
                   extra={('GET', '/api/clusters/c1/datacenter/backup'): (200, [job])})
    page = app.page
    standby = role == 'standby'
    page.locator('.cloud-shell').get_by_text('Backups', exact=True).first.click()
    page.locator('.cloud-table-row', has_text='daily').first.wait_for(timeout=5000)
    page.wait_for_timeout(200)
    labels = _labels(page)
    for word in ('Run now', 'Delete'):
        assert (word not in labels) == standby, (word, sorted(labels))
    assert 'Refresh' in ' '.join(labels)
    assert not app.errors, app.errors


# -- v3: a group of up to four instances (#625) --------------------------------------------------
#
# One active and up to three standbys. The panel lists everyone else in the group, marks the
# member a standby pulls from, lets the active remove a standby (typed REMOVE and the password,
# the box promote and unpair use) and keeps handing out codes until the group is full.

def test_the_panel_speaks_the_v3_contract(panel):
    body = _function(panel, 'HaPanel')
    assert 'const members = Array.isArray(status?.members) ? status.members : [];' in body
    assert 'const maxMembers = status?.max_members || 4;' in body
    assert 'const standbyCount = status?.standby_count || 0;' in body
    assert 'const groupFull = standbyCount >= maxMembers - 1;' in body
    # the answer of a removal takes the row away before the next status arrives
    assert 'if (Array.isArray(res.data.members)) setStatus(s => ({ ...(s || {}), members: res.data.members }));' in body
    assert "addToast?.(t('pgHaMemberRemoved'), told === false ? 'info' : 'success');" in body
    # a shown code is gone once the group grows or the role changes
    assert 'useEffect(() => { setCode(null); }, [role, standbyCount]);' in body
    # the peer card is gone for good; nothing reads the old single peer any more
    assert 'peerCard' not in body and 'status?.peer' not in body


def test_the_members_table_shows_what_the_contract_carries(panel):
    body = _function(panel, 'HaPanel')
    card = body[body.index('const membersCard = ('):body.index('const intervalCard = (')]
    for needle in ("{t('pgHaInstanceId')}", "{t('pgHaPeerUrl')}", "{t('pgHaPeerSeen')}", "{t('pgHaEpoch')}",
                   "{t('pgHaLastContact')}", "{t('pgHaLastError')}", "(m.instance_id || '').slice(0, 8)",
                   "{m.url || '-'}",
                   '<HaRoleBadge role={memberRole(m)} serving={m.serve === true} pending={m.serving_seen !== true} t={t} />',
                   "{m.epoch_seen ?? '-'}",
                   '{when(m.last_contact)}', '{m.last_error}', "{t('pgHaSource')}", "t('pgHaNoMembers')"):
        assert needle in card, needle
    assert "data-ha-source={m.is_source ? '' : undefined}" in card
    assert card.index('{m.is_source && (') < card.index("{t('pgHaSource')}")
    # this instance counts too
    assert ".replace('{n}', members.length + 1).replace('{max}', () => maxMembers)" in card
    # Remove only on the active, one per row
    assert "const canRemove = role === 'active';" in body
    remove_at = card.index("openConfirm('remove', m)")
    assert card.rindex('{canRemove && (', 0, remove_at) > card.index('{members.map(m => (')
    assert card.count("openConfirm('remove'") == 1


def test_remove_goes_through_the_box_promote_and_unpair_use(panel):
    body = _function(panel, 'HaPanel')
    opener = _block(body, 'const openConfirm = (what, member = null) => {', '\n            };')
    assert 'setRemoving(member);' in opener and "setPassword('confirm', '');" in opener
    box = body[body.index('const removeStale = '):body.index('const pairingCard = (')]
    assert ("confirmAction === 'remove'\n                && (role !== 'active' || "
            "!members.some(m => m.instance_id === removing?.instance_id));") in box
    assert "t('pgHaRemoveDesc').replace('{name}', () => removing.url || removing.instance_id.slice(0, 8))" in box
    assert "passwordInput('confirm', 'pgha-confirm-password')" in box
    assert "confirmAction === 'remove' ? (needShutDown ? t('pgHaRemoveAnyway') : t('pgHaRemove'))" in box
    # the remove box sits under the table, the unpair box under its button
    active = body[body.index("{role === 'active' && ("):body.index("{role === 'standby' && (")]
    assert active.index('{membersCard}') < active.index("{confirmAction === 'remove' && typedBox}") < active.index('{pairingCard}')
    assert active.index("openConfirm('unpair')") < active.index("{confirmAction !== 'remove' && typedBox}")


def test_the_active_hands_out_codes_until_the_group_is_full(panel):
    body = _function(panel, 'HaPanel')
    pairing = body[body.index('const pairingCard = ('):body.index('if (!status) {')]
    assert "const adding = role === 'active';" in body
    assert "data-ha-pairing={adding && groupFull ? 'full' : 'open'}" in pairing
    assert '{adding && groupFull ? (' in pairing
    full = pairing.index("t('pgHaGroupFull')")
    # the full group gets the note instead of the form, not next to it
    assert full < pairing.index(') : (') < pairing.index('<button onClick={createCode}')
    assert "{adding ? t('pgHaAddStandbyDesc') : t('pgHaMakeActiveDesc')}" in pairing
    # the card is built before the status is there
    assert 'status.pairing_open_until && !code' not in pairing
    assert '{status?.pairing_open_until && !code && (' in pairing


def _member(ch, role='standby', error='', source=False, contact=15, **more):
    """more: what a later server adds per member (confirmed_standby, key_fingerprint)."""
    return dict({'instance_id': ch * 32, 'url': f'https://pegaprox-{ch}.example:5000', 'fingerprint': '',
                 'role_seen': role, 'epoch_seen': 2, 'last_contact': _iso_ago(contact), 'last_error': error,
                 'joined_at': _iso_ago(7200), 'is_source': source}, **more)


def _reload_status(app):
    """Saving the interval reloads the status; the next poll would take ten seconds."""
    before = app.server.calls.count(('GET', '/api/ha/status'))
    app.page.locator('#pgha-interval + button').click()
    deadline = time.time() + 3
    while time.time() < deadline and app.server.calls.count(('GET', '/api/ha/status')) == before:
        app.page.wait_for_timeout(100)
    app.page.wait_for_timeout(300)


def test_runtime_an_active_without_standbys_pairs_the_first(open_app):
    app = open_app(role='active', layout='modern', members=[])
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-members]')
    assert card.get_attribute('data-ha-members') == '0'
    text = card.inner_text()
    assert '1 of 4 instances' in text and 'No other instance in the group yet.' in text
    assert card.locator('table').count() == 0

    pairing = panel.locator('[data-ha-pairing]')
    assert pairing.get_attribute('data-ha-pairing') == 'open'
    assert 'Add a standby' in pairing.inner_text()
    assert page.input_value('#pgha-own-url') == SELF
    create = pairing.get_by_role('button', name='Create pairing code')
    assert create.is_disabled(), 'the pairing code must wait for the password'
    page.fill('#pgha-code-password', PASSWORD)
    create.click()
    box = page.locator('[data-ha-code]')
    box.wait_for(timeout=3000)
    assert app.server.bodies['/api/ha/pairing-code'] == [{'url': SELF, 'user_password': PASSWORD}]
    # an unchanged group keeps the code on screen
    _reload_status(app)
    assert box.is_visible()
    # the first standby takes it: spent, while the card stays open for the next one
    app.server.members.append(_member('b'))
    _reload_status(app)
    card.locator('[data-ha-member]').wait_for(timeout=3000)
    assert '2 of 4 instances' in card.inner_text()
    assert page.locator('[data-ha-code]').count() == 0
    assert pairing.get_attribute('data-ha-pairing') == 'open'
    assert not app.errors, app.errors


def test_runtime_an_active_with_two_standbys_lists_them_and_pairs_a_third(open_app):
    members = [_member('b', error='Cannot reach the peer: ConnectTimeout'), _member('c', contact=40)]
    app = open_app(role='active', layout='modern', members=members)
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-members]')
    assert '3 of 4 instances' in card.inner_text()
    assert card.locator('tbody tr').count() == 2
    headers = [h.strip() for h in card.locator('thead th').all_inner_texts()]
    assert headers == ['Instance', 'Address', 'Seen as', 'Epoch', 'Key', 'Last contact', 'Last error', 'Active', '']
    cells = [c.strip() for c in card.locator(f'[data-ha-member="{"b" * 32}"] td').all_inner_texts()]
    assert cells[:4] == ['bbbbbbbb', 'https://pegaprox-b.example:5000', 'Standby', '2']
    # a member the server says nothing about keys for: no guess either way
    assert cells[4] == '-'
    assert 'seconds ago' in cells[5], cells
    assert cells[6] == 'Cannot reach the peer: ConnectTimeout'
    assert cells[7] == '' and cells[8] == 'Remove'
    assert card.locator(f'[data-ha-member="{"c" * 32}"] td').nth(6).inner_text().strip() == '-'
    # the active pulls from nobody
    assert card.locator('[data-ha-source]').count() == 0
    assert card.get_by_role('button', name='Remove').count() == 2

    pairing = panel.locator('[data-ha-pairing="open"]')
    page.fill('#pgha-code-password', PASSWORD)
    pairing.get_by_role('button', name='Create pairing code').click()
    page.locator('[data-ha-code]').wait_for(timeout=3000)

    # the third standby takes the code: it is spent, and the group is full
    app.server.members.append(_member('d'))
    _reload_status(app)
    page.locator('[data-ha-pairing="full"]').wait_for(timeout=3000)
    assert page.locator('[data-ha-code]').count() == 0
    assert '4 of 4 instances' in card.inner_text()
    assert card.locator('tbody tr').count() == 3
    assert not app.errors, app.errors


def test_runtime_a_full_group_takes_a_standby_again_once_one_is_removed(open_app):
    app = open_app(role='active', layout='modern', members=[_member('b'), _member('c'), _member('d')])
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-members]')
    assert '4 of 4 instances' in card.inner_text()
    pairing = panel.locator('[data-ha-pairing]')
    assert pairing.get_attribute('data-ha-pairing') == 'full'
    assert 'The group is full: 4 instances, the leader included.' in pairing.inner_text()
    assert page.locator('#pgha-own-url, #pgha-code-password').count() == 0
    assert pairing.get_by_role('button', name='Create pairing code').count() == 0

    row = card.locator(f'[data-ha-member="{"c" * 32}"]')
    row.get_by_role('button', name='Remove').click()
    box = panel.locator('[data-ha-confirm="remove"]')
    assert 'https://pegaprox-c.example:5000 leaves the group' in box.inner_text()
    # right under the table, above the pairing card
    assert _follows(page, '[data-ha-members]', '[data-ha-confirm]')
    assert _follows(page, '[data-ha-confirm]', '[data-ha-pairing]')
    confirm = box.get_by_role('button', name='Remove')
    assert confirm.is_disabled()
    page.fill('#pgha-typed', 'remove')
    assert confirm.is_disabled()
    page.fill('#pgha-typed', 'REMOVE')
    assert confirm.is_disabled(), 'remove must wait for the password'

    # a wrong password: the note at the field, the box and the word stay, the row too
    page.fill('#pgha-confirm-password', 'wrong')
    confirm.click()
    note = box.locator('[data-ha-reauth="HA_REAUTH"]')
    note.wait_for(timeout=3000)
    assert 'Incorrect password' in note.inner_text()
    assert _follows(page, '#pgha-confirm-password', '[data-ha-reauth]')
    assert page.input_value('#pgha-typed') == 'REMOVE'
    assert page.input_value('#pgha-confirm-password') == ''
    assert confirm.is_disabled()
    assert card.locator('tbody tr').count() == 3
    path = f'/api/ha/members/{"c" * 32}/remove'
    assert app.server.bodies[path] == [{'confirm': 'REMOVE', 'user_password': 'wrong'}]

    page.fill('#pgha-confirm-password', PASSWORD)
    confirm.click()
    app.see('Removed from the group')
    row.wait_for(state='detached', timeout=3000)
    assert app.server.bodies[path][-1] == {'confirm': 'REMOVE', 'user_password': PASSWORD}
    assert panel.locator('[data-ha-confirm]').count() == 0
    assert card.locator('tbody tr').count() == 2
    # room again for one more
    page.locator('[data-ha-pairing="open"]').wait_for(timeout=3000)
    assert '3 of 4 instances' in card.inner_text()
    assert page.get_by_text('Restarting PegaProx...').count() == 0
    assert not app.errors, app.errors


def test_runtime_an_sso_account_removes_without_a_password(open_app):
    app = open_app(role='active', layout='modern', auth_source='oidc', members=[_member('b'), _member('c')])
    page = app.page
    panel = _open_ha(app, 'active')
    panel.locator(f'[data-ha-member="{"b" * 32}"]').get_by_role('button', name='Remove').click()
    box = panel.locator('[data-ha-confirm="remove"]')
    assert box.locator('input[type="password"]').count() == 0
    page.fill('#pgha-typed', 'REMOVE')
    box.get_by_role('button', name='Remove').click()
    app.see('Removed from the group')
    assert app.server.bodies[f'/api/ha/members/{"b" * 32}/remove'] == [{'confirm': 'REMOVE'}]
    assert panel.locator('[data-ha-member]').count() == 1
    assert not app.errors, app.errors


def test_runtime_the_remove_box_closes_when_the_member_is_gone(open_app):
    app = open_app(role='active', layout='modern', members=[_member('b'), _member('c')])
    page = app.page
    panel = _open_ha(app, 'active')
    panel.locator(f'[data-ha-member="{"c" * 32}"]').get_by_role('button', name='Remove').click()
    panel.locator('[data-ha-confirm="remove"]').wait_for(timeout=3000)
    # another admin removed it meanwhile
    app.server.members = [_member('b')]
    _reload_status(app)
    assert panel.locator('[data-ha-confirm]').count() == 0
    assert not [c for c in app.server.calls if c[1].startswith('/api/ha/members/')]
    assert not app.errors, app.errors


def test_runtime_a_standby_marks_its_source_and_removes_nobody(open_app):
    members = [_member('b', role='active', source=True), _member('c'),
               _member('d', error='Cannot reach the peer: ConnectTimeout')]
    app = open_app(role='standby', layout='modern', members=members)
    page = app.page
    # the banner names the member it pulls from
    assert 'https://pegaprox-b.example:5000' in page.locator('[data-ha-banner="classic"]').inner_text()
    panel = _open_ha(app, 'standby')
    card = panel.locator('[data-ha-members]')
    assert '4 of 4 instances' in card.inner_text()
    source = card.locator('[data-ha-source]')
    assert source.count() == 1
    assert source.get_attribute('data-ha-member') == 'b' * 32
    cells = source.locator('td')
    assert cells.nth(0).locator('span').all_inner_texts() == ['bbbbbbbb', 'Source']
    assert cells.nth(2).inner_text().strip() == 'Active - Leader (automation)'
    assert card.get_by_text('Source', exact=True).count() == 1
    assert card.locator('[data-ha-member]').count() == 3
    # a standby removes nobody and hands out no code
    assert card.get_by_role('button', name='Remove').count() == 0
    assert card.locator('thead th').count() == 7
    assert panel.locator('[data-ha-pairing]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_members_table_scrolls_inside_its_card_on_a_phone(open_app):
    members = [_member('b', role='active', source=True), _member('c'),
               _member('d', error='Cannot reach the peer: ConnectTimeout')]
    app = open_app(role='standby', layout='modern', members=members)
    page = app.page
    page.set_viewport_size({'width': 390, 'height': 900})
    panel = _open_ha(app, 'standby')
    page.wait_for_timeout(300)
    assert page.evaluate('() => document.documentElement.scrollWidth') <= 390
    card = panel.locator('[data-ha-members]')
    assert card.evaluate('el => el.scrollWidth <= el.clientWidth')
    # the rows scroll inside the card: the wrapper does, or on a phone the table itself
    # (index.html makes every table a scrolling block there)
    assert card.locator('table').evaluate('el => Math.max(el.scrollWidth - el.clientWidth, '
                                          'el.parentElement.scrollWidth - el.parentElement.clientWidth) > 0')
    # an address stays on one line instead of breaking up in a squeezed column
    lines = page.evaluate('''() => Array.from(document.querySelectorAll('[data-ha-member] td:nth-child(2)'))
        .map(td => { const r = document.createRange(); r.selectNodeContents(td); return r.getClientRects().length; })''')
    assert lines == [1, 1, 1], lines
    assert not app.errors, app.errors


# -- the group fixes (#625 review) ----------------------------------------------------------------
#
# A member that is not confirmed as a standby under the current epoch goes only with the admin's
# word that it is shut down for good; the answer of a removal says whether the member was told,
# and the panel repeats it as it is; an instance that learned it was removed says so and what to
# do; a code the server no longer has open leaves the screen; Cloud shows toasts at all.

def test_an_unconfirmed_removal_asks_once_more(panel):
    body = _function(panel, 'HaPanel')
    confirm = _block(body, 'const confirmed = () => run(confirmAction, async () => {', '\n            });')
    # shut_down only goes out as the second step: after the refusal and the ticked box
    assert "const shutDownNow = what === 'remove' && unconfirmed && shutDown;" in confirm
    assert confirm.count('shut_down: true') == 1
    refused = confirm[confirm.index('if (!res.ok) {'):confirm.index('openConfirm(null);')]
    at = refused.index("if (what === 'remove' && res.code === 'HA_REMOVE_UNCONFIRMED') {")
    # the box, the word and the password stay for the second step; no error toast
    assert at < refused.index('setUnconfirmed(true);', at) < refused.index('return;', at) \
        < refused.index("addToast?.(res.error, 'error');")
    assert "setPassword('confirm'" not in refused
    # a new box starts without the second step
    opener = _block(body, 'const openConfirm = (what, member = null) => {', '\n            };')
    for reset in ('setUnconfirmed(false);', 'setShutDown(false);'):
        assert reset in opener, reset
    box = body[body.index('const needShutDown = '):body.index('const removalNote = ')]
    assert "const needShutDown = confirmAction === 'remove' && unconfirmed;" in box
    step = box[box.index('{needShutDown && ('):box.index("passwordInput('confirm', 'pgha-confirm-password')")]
    for needle in ('data-ha-unconfirmed', "t('pgHaRemoveUnconfirmed')", "t('pgHaShutDownConfirm')",
                   'checked={shutDown} onChange={e => setShutDown(e.target.checked)}'):
        assert needle in step, needle


def test_the_answer_of_a_removal_is_repeated_as_it_is(panel):
    body = _function(panel, 'HaPanel')
    confirm = _block(body, 'const confirmed = () => run(confirmAction, async () => {', '\n            });')
    assert "const told = typeof res.data.told === 'boolean' ? res.data.told : null;" in confirm
    assert 'setLastRemoval({ name: target.url || target.instance_id.slice(0, 8), told });' in confirm
    note = body[body.index('const removalNote = '):body.index('const removedHere = ')]
    assert "lastRemoval.told === true ? t('pgHaRemovedTold')" in note
    assert "lastRemoval.told === false ? t('pgHaRemovedNotReached')" in note
    # a server that does not say gets no claim either way
    assert ": t('pgHaMemberRemoved')}" in note
    # outside the members card: removing the last standby makes the instance standalone,
    # and a standalone has no members card
    main = body[body.index('<div className="space-y-4" data-ha-role={role}>'):]
    assert main.index('{removalNote}') < main.index("{role === 'standalone' && (")


def test_the_members_table_shows_confirmation_and_key(panel):
    body = _function(panel, 'HaPanel')
    card = body[body.index('const membersCard = ('):body.index('const intervalCard = (')]
    assert "{t('pgHaKey')}" in card
    assert ("data-ha-confirmed={typeof m.confirmed_standby === 'boolean' ? String(m.confirmed_standby) "
            ": undefined}") in card
    assert '{m.confirmed_standby === true && (' in card
    # the active is never a standby, so only the active itself warns about the others
    assert '{m.confirmed_standby === false && canRemove && (' in card
    assert "m.key_fingerprint === ''" in card and "t('pgHaOldSecret')" in card


def test_a_removed_instance_says_so(panel):
    body = _function(panel, 'HaPanel')
    assert 'const removedHere = status?.removed;' in body
    assert "const removedNote = removedHere && role !== 'standalone' && (" in body
    note = body[body.index('const removedNote = '):body.index('const pairingCard = (')]
    for needle in ('data-ha-removed', "t('pgHaRemovedHere')", "t('pgHaRemovedBy')", "t('pgHaRemovedHereNext')"):
        assert needle in note, needle
    main = body[body.index('<div className="space-y-4" data-ha-role={role}>'):]
    assert main.index('{removedNote}') < main.index("{role === 'standalone' && (")


def test_a_shown_code_goes_once_the_server_stops_reporting_it(panel):
    body = _function(panel, 'HaPanel')
    load = _block(body, 'const load = async () => {', '\n            };')
    assert 'const seq = ++loadSeq.current;' in load
    # only an answer to a request sent after the code was made may drop it
    assert 'seq > c.seq && data.pairing_open_until !== c.expires_at' in load
    assert load.index('setCode(c => ') < load.index('setStatus(data);')
    assert 'setCode({ code: res.data.code, expires_at: res.data.expires_at, seq: loadSeq.current });' in body
    # the old rule stays next to it
    assert 'useEffect(() => { setCode(null); }, [role, standbyCount]);' in body


def test_cloud_renders_the_toasts_too(dash):
    main = dash[dash.index('function PegaProxDashboard('):]
    cloud_at = main.index('if (isCloud) {')
    main_return = main.index("style={{ overflowX: 'clip' }}")
    assert main.index('const toastPortal = ReactDOM.createPortal(') < cloud_at
    assert cloud_at < main.index('{toastPortal}', cloud_at) < main_return
    assert main.index('{toastPortal}', main_return) > main_return
    # built once, so the two layouts cannot drift apart
    assert main.count('toasts.map(') == 1


def _wait_for_toast(page, text, seconds=4):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if any(text in t for t in _toasts(page)):
            return True
        page.wait_for_timeout(100)
    return False


def _remove_member(app, panel, ch, password=PASSWORD):
    panel.locator(f'[data-ha-member="{ch * 32}"]').get_by_role('button', name='Remove').click()
    box = panel.locator('[data-ha-confirm="remove"]')
    app.page.fill('#pgha-typed', 'REMOVE')
    app.page.fill('#pgha-confirm-password', password)
    box.get_by_role('button', name='Remove').click()
    return box


def _keyed_members():
    return [_member('b', confirmed_standby=True, key_fingerprint='9f2c41ab'),
            _member('c', confirmed_standby=False, key_fingerprint='')]


def test_runtime_the_members_table_shows_confirmation_and_key(open_app):
    app = open_app(role='active', layout='modern', members=_keyed_members())
    card = _open_ha(app, 'active').locator('[data-ha-members]')
    b = card.locator(f'[data-ha-member="{"b" * 32}"]')
    c = card.locator(f'[data-ha-member="{"c" * 32}"]')
    assert b.get_attribute('data-ha-confirmed') == 'true'
    assert c.get_attribute('data-ha-confirmed') == 'false'
    seen_b, seen_c = b.locator('td').nth(2).inner_text(), c.locator('td').nth(2).inner_text()
    assert 'Standby' in seen_b and 'confirmed' in seen_b and 'not confirmed' not in seen_b, seen_b
    assert 'not confirmed' in seen_c, seen_c
    assert b.locator('td').nth(4).inner_text().strip() == '9f2c41ab'
    assert c.locator('td').nth(4).inner_text().strip() == 'old secret'
    assert c.locator('[data-ha-key="secret"]').count() == 1
    assert not app.errors, app.errors


def test_runtime_a_standby_does_not_call_the_active_unconfirmed(open_app):
    members = [_member('b', role='active', source=True, confirmed_standby=False, key_fingerprint='77aa01cd'),
               _member('c', confirmed_standby=True, key_fingerprint='')]
    app = open_app(role='standby', layout='modern', members=members)
    card = _open_ha(app, 'standby').locator('[data-ha-members]')
    active = card.locator(f'[data-ha-member="{"b" * 32}"]').locator('td').nth(2).inner_text()
    assert 'Active' in active and 'confirmed' not in active, active
    assert 'confirmed' in card.locator(f'[data-ha-member="{"c" * 32}"]').locator('td').nth(2).inner_text()
    assert not app.errors, app.errors


def test_runtime_an_unconfirmed_member_goes_only_with_the_second_confirmation(open_app):
    app = open_app(role='active', layout='modern', members=_keyed_members())
    app.server.unreachable.add('c' * 32)
    page = app.page
    panel = _open_ha(app, 'active')
    row = panel.locator(f'[data-ha-member="{"c" * 32}"]')
    box = _remove_member(app, panel, 'c')
    step = box.locator('[data-ha-unconfirmed]')
    step.wait_for(timeout=3000)
    path = f'/api/ha/members/{"c" * 32}/remove'
    assert app.server.bodies[path] == [{'confirm': 'REMOVE', 'user_password': PASSWORD}]
    assert 'It may still run as an active instance' in step.inner_text()
    # the box no longer promises that a member it cannot reach lets go by itself
    assert 'If it cannot be reached, unpair it there before you use it again.' in box.inner_text()
    # nothing removed, no error toast, the word and the password kept for the second step
    assert row.count() == 1
    assert not any('not confirmed as a standby' in t for t in _toasts(page)), _toasts(page)
    assert page.input_value('#pgha-typed') == 'REMOVE'
    assert page.input_value('#pgha-confirm-password') == PASSWORD
    confirm = box.get_by_role('button', name='Remove anyway')
    assert confirm.is_disabled(), 'the second step waits for the box'
    step.locator('input[type="checkbox"]').check()
    assert 'I confirm this instance is shut down for good' in step.inner_text()
    assert confirm.is_enabled()
    confirm.click()
    row.wait_for(state='detached', timeout=3000)
    assert app.server.bodies[path][-1] == {'confirm': 'REMOVE', 'user_password': PASSWORD, 'shut_down': True}
    assert len(app.server.bodies[path]) == 2
    # the answer said it was not told, and the panel says the same
    note = panel.locator('[data-ha-removal]')
    note.wait_for(timeout=3000)
    assert note.get_attribute('data-ha-removal') == 'not-reached'
    assert 'https://pegaprox-c.example:5000 was not reached' in note.inner_text()
    assert 'Unpair it on that instance before you use it again' in note.inner_text()
    assert _wait_for_toast(page, 'Removed from the group')
    # the next box starts without the second step
    _remove_member(app, panel, 'b')
    panel.locator(f'[data-ha-member="{"b" * 32}"]').wait_for(state='detached', timeout=3000)
    assert app.server.bodies[f'/api/ha/members/{"b" * 32}/remove'] == [{'confirm': 'REMOVE', 'user_password': PASSWORD}]
    assert not app.errors, app.errors


def test_runtime_a_confirmed_member_goes_in_one_step_and_was_told(open_app):
    app = open_app(role='active', layout='modern', members=_keyed_members())
    panel = _open_ha(app, 'active')
    box = _remove_member(app, panel, 'b')
    panel.locator(f'[data-ha-member="{"b" * 32}"]').wait_for(state='detached', timeout=3000)
    path = f'/api/ha/members/{"b" * 32}/remove'
    assert app.server.bodies[path] == [{'confirm': 'REMOVE', 'user_password': PASSWORD}]
    assert box.count() == 0
    note = panel.locator('[data-ha-removal]')
    note.wait_for(timeout=3000)
    assert note.get_attribute('data-ha-removal') == 'told'
    assert 'https://pegaprox-b.example:5000 was told and has left the group.' in note.inner_text()
    # it stays until dismissed or the next action
    note.get_by_role('button', name='Close').click()
    assert panel.locator('[data-ha-removal]').count() == 0
    assert not app.errors, app.errors


def test_runtime_removing_the_last_standby_still_says_whether_it_was_told(open_app):
    app = open_app(role='active', layout='modern', members=[_member('b', confirmed_standby=True)])
    app.server.unreachable.add('b' * 32)
    panel = _open_ha(app, 'active')
    # the server turns standalone once its last member is gone, and the members card goes
    _remove_member(app, panel, 'b')
    note = app.page.locator('[data-ha-role="standalone"] [data-ha-removal="not-reached"]')
    note.wait_for(timeout=5000)
    assert 'https://pegaprox-b.example:5000 was not reached' in note.inner_text()
    assert not app.errors, app.errors


@pytest.mark.parametrize('removed', [True, False])
def test_runtime_a_removed_instance_says_so_and_what_to_do(open_app, removed):
    app = open_app(role='standby', layout='modern',
                   members=[] if removed else [_member('b', role='active', source=True)])
    if removed:
        app.server.removed = {'epoch': 3, 'at': _iso_ago(300), 'by': 'd' * 32}
    page = app.page
    panel = _open_ha(app, 'standby')
    note = panel.locator('[data-ha-removed]')
    if not removed:
        assert note.count() == 0
        assert not app.errors, app.errors
        return
    text = note.inner_text()
    for needle in ('This instance was removed from the group. It stays passive',
                   'Removed by dddddddd under epoch 3', '5 minutes ago',
                   'To use it on its own, unpair it here.'):
        assert needle in text, (needle, text)
    # above everything else the panel shows for the standby
    assert _follows(page, '[data-ha-removed]', '[data-ha-members]')
    # and the way out is where it says
    panel.get_by_role('button', name='Unpair').click()
    assert 'This instance becomes standalone' in panel.locator('[data-ha-confirm="unpair"]').inner_text()
    assert not app.errors, app.errors


def test_runtime_a_standalone_shows_no_removed_note(open_app):
    app = open_app(role='standalone', layout='modern')
    app.server.removed = {'epoch': 3, 'at': _iso_ago(300), 'by': 'd' * 32}
    panel = _open_ha(app, 'standalone')
    assert panel.locator('[data-ha-removed]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('change', ['spent', 'replaced', 'kept'])
def test_runtime_a_code_the_server_no_longer_has_open_leaves_the_screen(open_app, change):
    """verify:robust:2 - a member that was listed already re-pairs with the code, so the count
    stays; or another tab makes a new one. Either way the code on screen is of no use."""
    app = open_app(role='active', layout='modern', members=[_member('b'), _member('c')])
    page = app.page
    panel = _open_ha(app, 'active')
    page.fill('#pgha-code-password', PASSWORD)
    panel.get_by_role('button', name='Create pairing code').click()
    box = page.locator('[data-ha-code]')
    box.wait_for(timeout=3000)
    # the server still has it open: it stays
    _reload_status(app)
    assert box.is_visible()
    if change == 'spent':
        app.server.pairing_until = None
    elif change == 'replaced':
        app.server.pairing_until += 60
    _reload_status(app)
    if change == 'kept':
        assert box.is_visible()
    else:
        box.wait_for(state='detached', timeout=3000)
    assert '3 of 4 instances' in panel.locator('[data-ha-members]').inner_text()
    # a replaced code is still open, just not the one this tab holds
    assert panel.get_by_text('A pairing code is open until').count() == (1 if change == 'replaced' else 0)
    assert not app.errors, app.errors


def test_runtime_a_poll_already_on_its_way_keeps_a_fresh_code(open_app):
    """A poll sent before the code existed and answered after it knows nothing of the code:
    it must not take the shown-once code off the screen."""
    app = open_app(role='active', layout='modern', members=[_member('b')])
    page = app.page
    panel = _open_ha(app, 'active')
    app.server.hold_status = True
    before = app.server.calls.count(('GET', '/api/ha/status'))
    page.locator('#pgha-interval + button').click()
    deadline = time.time() + 3
    while time.time() < deadline and not app.server.held:
        page.wait_for_timeout(100)
    assert len(app.server.held) == 1
    assert app.server.held[0][1]['pairing_open_until'] is None
    app.server.hold_status = False
    page.fill('#pgha-code-password', PASSWORD)
    panel.get_by_role('button', name='Create pairing code').click()
    box = page.locator('[data-ha-code]')
    box.wait_for(timeout=3000)
    # the panel's own status request after the code, answered with the code open
    deadline = time.time() + 3
    while time.time() < deadline and app.server.calls.count(('GET', '/api/ha/status')) < before + 2:
        page.wait_for_timeout(100)
    page.wait_for_timeout(300)
    app.server.release()
    page.wait_for_timeout(800)
    assert box.is_visible(), 'a poll sent before the code was made took it away'
    assert 'pgxha1_' in box.inner_text()
    assert not app.errors, app.errors


def _open_ha_in(app, layout):
    if layout != 'cloud':
        return _open_ha(app, 'active')
    page = app.page
    page.locator('button[title="Settings"]').first.click()
    page.get_by_text('PegaProx Settings').first.wait_for(timeout=5000)
    page.locator('div.fixed.inset-0 button', has_text='High Availability').first.click()
    panel = page.locator('[data-ha-role="active"]')
    panel.wait_for(timeout=5000)
    return panel


@pytest.mark.parametrize('layout', ['cloud', 'modern', 'corporate'])
def test_runtime_every_layout_shows_the_toasts(open_app, layout):
    """verify:robust:3 - Cloud returned before the toast portal, so a refused removal left the
    box open without a word and a successful one said nothing either."""
    refused = f'/api/ha/members/{"b" * 32}/remove'
    app = open_app(role='active', layout=layout, members=[_member('b'), _member('c')],
                   extra={('POST', refused): (500, {'error': 'Removing the member failed: disk full'})})
    page = app.page
    panel = _open_ha_in(app, layout)
    _remove_member(app, panel, 'b')
    assert _wait_for_toast(page, 'Removing the member failed: disk full'), _toasts(page)
    assert panel.locator('[data-ha-confirm="remove"]').count() == 1
    _remove_member(app, panel, 'c')
    assert _wait_for_toast(page, 'Removed from the group'), _toasts(page)
    panel.locator(f'[data-ha-member="{"c" * 32}"]').wait_for(state='detached', timeout=3000)
    assert not app.errors, app.errors


def test_a_promote_the_pull_could_not_prepare_asks_once_more():
    """The promote route pulls from the active first when it still answers and refuses
    with HA_PROMOTE_SYNC when that pull fails. The panel asks once more and only then
    sends force, the way it handles an unconfirmed removal. A removed instance offers no
    promote at all."""
    src = _read('web', 'src', 'settings_modal.js')
    assert "res.code === 'HA_PROMOTE_SYNC'" in src and 'setPromoteSync(true)' in src
    assert "what === 'promote' && promoteSync && forcePromote" in src
    assert '(needForce && !forcePromote)' in src
    assert "{!broken && !status?.removed && (" in src
    tr = _read('web', 'src', 'translations.js')
    for key in ('pgHaPromoteSyncFirst', 'pgHaPromoteSyncFailed', 'pgHaPromoteForce'):
        assert tr.count(f'{key}:') == len(LANGS), key


# -- forwarding: a standby hands changes to the active (#625) -------------------------------------
#
# With forward_writes on and an active that answers, a standby carries out what its users do
# through the active, so the page shows the actions again: haReadOnly is "standby and not
# forwarding". Consoles, shells, SPICE and the console preview still never run on a standby,
# forwarding or not; where the active shows them, a standby shows "Open on the active instance",
# the same view on the active's address (peer_url) in a new tab. A 503 HA_ACTIVE_UNREACHABLE is
# one translated toast, like the 409 HA_STANDBY.

CONSOLE_URL = PEER + '/?console=c1%3Aqemu%3A100%3Apve1'
ON_ACTIVE = 'Open on the active instance'
CONSOLE_LABELS = {'Console', 'Open Console', 'SPICE Console', 'SPICE', 'Launch Web Console', 'Console (VMRC)'}
UNREACHABLE = {'en': 'The active instance cannot be reached. Try again once it is back, or promote this standby.',
               'de': 'Die aktive Instanz ist nicht erreichbar. Versuchen Sie es erneut, sobald sie wieder da ist, '
                     'oder stufen Sie diesen Standby hoch.'}


def test_the_active_address_and_the_console_key(ctx):
    """haActiveHref and haConsoleSearch as they are in the source, run in node: https only,
    a path behind a proxy kept, the console window's key encoded the way #767 reads it."""
    import shutil
    import subprocess
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not installed')
    script = (_block(ctx, 'function haActiveHref(', '\n        }') + '\n        }\n'
              + _block(ctx, 'function haConsoleSearch(', '\n        }') + '\n        }\n' + """
    const vm = { vmid: 100, type: 'qemu', node: 'pve1' };
    console.log(JSON.stringify({
        root: haActiveHref('https://pegaprox-a.example:5000'),
        console: haActiveHref('https://pegaprox-a.example:5000/', haConsoleSearch(vm, 'c1')),
        proxied: haActiveHref(' https://proxy.example/pegaprox ', '?console=x'),
        own: haConsoleSearch({ ...vm, _clusterId: 'c2' }, 'c1'),
        ct: haConsoleSearch({ vmid: 7, type: 'lxc', node: 'n-1.lab' }, 'c1'),
        none: [haConsoleSearch({ vmid: 0, type: 'node', node: 'pve1' }, 'c1'), haConsoleSearch(vm, ''),
               haConsoleSearch(null, 'c1')],
        refused: ['http://pegaprox-a.example:5000', 'javascript:alert(1)', '//evil.example', '', null,
                  undefined, 5, 'https://a b.example', 'https://'].map(u => haActiveHref(u)),
    }));
    """)
    res = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    assert out['root'] == PEER + '/'
    assert out['console'] == CONSOLE_URL
    assert out['proxied'] == 'https://proxy.example/pegaprox/?console=x'
    assert out['own'] == '?console=c2%3Aqemu%3A100%3Apve1'
    assert out['ct'] == '?console=c1%3Alxc%3A7%3An-1.lab'
    assert out['none'] == ['', '', '']
    assert out['refused'] == [None] * 9


def test_the_link_opens_the_same_view_on_the_active():
    ui = _read('web', 'src', 'ui.js')
    link = _function(ui, 'HaOnActiveLink')
    assert 'if (!(settings ? haStandby : haConsolesElsewhere)) return null;' in link
    assert "const href = haActiveHref(ha.peer_url, vm ? haConsoleSearch(vm, clusterId) : '');" in link
    assert 'if (!href) return null;' in link
    assert 'target="_blank" rel="noopener noreferrer" data-ha-on-active={href}' in link
    assert "onClick={() => window.open(href, '_blank', 'noopener,noreferrer')}" in link
    # only the settings link shows on a member that serves users, and it names the leader
    assert "const label = haServing ? t('pgHaOpenOnLeader') : t('pgHaOpenOnActive');" in link
    box = _function(ui, 'HaConsoleOnActive')
    assert "{t('pgHaConsoleOnActive')}" in box
    assert '<HaOnActiveLink vm={vm} clusterId={clusterId}' in box
    ctx = _read('web', 'src', 'contexts.js')
    opener = _block(ctx, 'function haOpenOnActive(', '\n        }')
    assert "if (href) window.open(href, '_blank', 'noopener,noreferrer');" in opener


CONSOLE_OPENERS = ('{consoles && ', '{acts && ', '{!acts ? ', '{consoleShot ? (', '{!consoles && ')


@pytest.mark.parametrize('name,component,links', [
    ('tables.js', 'ResourceTable', 3),
    ('vm_modals.js', 'VmDetailPanel', 1),
    ('vm_modals.js', 'CorporateVmDetailView', 2),
])
def test_every_console_button_asks_the_standby_flag(name, component, links):
    """Forwarding brings the actions back, not the consoles: each console and SPICE button
    sits behind consoles (= !haConsolesElsewhere, only a serving member opens them), and each
    place shows the link instead."""
    body = _function(_read('web', 'src', name), component)
    assert 'const consoles = !haConsolesElsewhere;' in body
    assert re.search(r'const \{[^}]*\bhaConsolesElsewhere\b[^}]*\} = useAuth\(\);', body)
    calls = list(re.finditer(r'=> (onOpenConsole|onOpenSpice)\(', body))
    assert len(calls) >= 2, component
    for m in calls:
        near = max(CONSOLE_OPENERS, key=lambda o: body.rfind(o, 0, m.start()))
        assert near in ('{consoles && ', '{consoleShot ? ('), (component, body[m.start() - 240:m.start()])
    assert body.count('<HaOnActiveLink vm=') == links
    for m in re.finditer(r'<HaOnActiveLink vm=', body):
        near = max(CONSOLE_OPENERS, key=lambda o: body.rfind(o, 0, m.start()))
        assert near == '{!consoles && ', (component, body[m.start() - 240:m.start()])


def test_the_dashboard_sends_every_console_to_the_active(dash):
    # the context menus: node shell and guest console become the way to the active
    assert "...(haConsolesElsewhere ? onActiveItems('node.shell', '', !online) : [" in dash
    assert "...(haConsolesElsewhere ? onActiveItems('vm.console', haConsoleSearch(vm), !isRunning) : [" in dash
    items = _block(dash, 'const onActiveItems = (permission, search, disabled = false) =>', '}];')
    assert "label: t('pgHaOpenOnActive')" in items
    assert "if (!haOpenOnActive(ha?.peer_url, search)) haRefusedRef.current?.(false, 'console');" in items
    # the ESXi console: its button and handler on every standby, the link in its place
    vmrc = _block(dash, 'const openVmwareConsole = async (vmId) => {', '\n            };')
    assert vmrc.index("if (haConsolesElsewhere) { haRefusedRef.current?.(false, 'console'); return; }") < vmrc.index('authFetch(')
    assert '{isOn && !haConsolesElsewhere && (\n' in dash
    at = dash.index('{isOn && haConsolesElsewhere && (')
    assert '<HaOnActiveLink iconOnly' in dash[at:at + 200]
    # the GETs that act on the node stay off every standby: they are not forwarded
    cfg = _read('web', 'src', 'vm_config.js')
    assert "efficient-snapshots${haReadOnly" not in cfg


def test_the_cloud_shell_offers_the_active_for_a_console(cloud):
    shell = _function(cloud, 'CloudShell')
    assert "consoleOnActive: haConsolesElsewhere ? (r) => haOpenOnActive(ha && ha.peer_url, haConsoleSearch(stamp(r))) : null," in shell
    items = _block(cloud, 'function cloudVmActionItems(', '\n        }')
    assert ("act.consoleOnActive && { label: t('pgHaOpenOnActive'), icon: 'ExternalLink', "
            "onClick: () => act.consoleOnActive(r) },") in items
    detail = _function(cloud, 'CloudInstanceDetail')
    assert '{act.consoleOnActive && <HaOnActiveLink vm={r} className="cloud-btn" />}' in detail
    hook = _function(cloud, 'useCloudMutate')
    assert ("b && b.code === 'HA_ACTIVE_UNREACHABLE' ? (haServing ? t('pgHaLeaderUnreachable') "
            ": t('pgHaActiveUnreachable'))") in hook
    assert 'return { busy, run, acts: !haReadOnly };' in hook


def test_the_panel_speaks_the_forwarding_contract(panel):
    body = _function(panel, 'HaPanel')
    assert 'const forwardWrites = status?.forward_writes !== false;' in body
    save = body[body.index('const setForwardWrites = (on) =>'):body.index('const applyNow = ')]
    assert "send('PUT', 'settings', { forward_writes: on })" in save
    assert "addToast?.(t(on ? 'pgHaForwardOn' : 'pgHaForwardOff'), 'success');" in save
    # the banner and the buttons follow at once
    assert 'refreshHa?.();' in save
    card = body[body.index('const forwardCard = ('):body.index('const restartNote = ')]
    assert 'role="switch" aria-checked={forwardWrites}' in card
    assert 'htmlFor="pgha-forward"' in card and 'id="pgha-forward"' in card
    assert 'disabled={!!busy || broken}' in card
    assert "{t('pgHaForwardWrites')}" in card and "{t('pgHaForwardWritesHint')}" in card
    assert 'const forwardPaused = standby && forwardWrites && status?.forwarding === false;' in body
    assert "{forwardPaused && (" in card
    assert "{t(serving ? 'pgHaForwardPausedServing' : 'pgHaForwardPaused')}" in card
    # next to the live view, in every role
    standalone = body[body.index("{role === 'standalone' && ("):body.index("{role === 'active' && (")]
    active = body[body.index("{role === 'active' && ("):body.index("{role === 'standby' && (")]
    standby = body[body.index("{role === 'standby' && ("):]
    assert '{liveViewCard}\n                            {forwardCard}' in standalone
    # a member also says there whether the leader made it active (v8)
    for part, after in ((active, ''), (standby, '                                {assignedCard}\n')):
        assert ('<div className="grid grid-cols-1 md:grid-cols-2 gap-4">\n'
                '                                {liveViewCard}\n'
                '                                {forwardCard}\n'
                + after +
                '                            </div>') in part


def test_the_new_strings_say_no_em_dash_and_keep_the_austrian_flag():
    blocks = _blocks()
    for key in ('pgHaBannerForwarding', 'pgHaOpenOnActive', 'pgHaConsoleOnActive', 'pgHaActiveUnreachable',
                'pgHaForwardWrites', 'pgHaForwardWritesHint', 'pgHaForwardOn', 'pgHaForwardOff',
                'pgHaForwardPaused'):
        for lang, block in blocks.items():
            line = re.search(r'^ +%s: (.*),$' % key, block, re.M)
            assert line, (lang, key)
            assert '\u2014' not in line.group(1), (lang, key)
    # German keeps its (Austrian) flag
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


# -- runtime ------------------------------------------------------------------------------------

def _on_active_links(page):
    """What every visible link or button to the active points at."""
    return page.evaluate('() => Array.from(document.querySelectorAll("[data-ha-on-active]"))'
                         '.filter(a => a.offsetParent !== null).map(a => a.getAttribute("data-ha-on-active"))')


def _serve_the_active(app):
    """The new tab the link opens lands on the fake active instead of a failed lookup."""
    app.ctx.route(PEER + '/**', lambda route: route.fulfill(
        status=200, body='<html><body>active</body></html>', headers={'Content-Type': 'text/html'}))


@pytest.mark.parametrize('role,forward', [('standby', True), ('standby', False), ('active', False)])
def test_runtime_a_forwarding_standby_acts_and_opens_consoles_on_the_active(open_app, role, forward):
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM], forward_writes=forward,
                   autoinstall='manage', extra=SSE_TOKEN)
    page = app.page
    page.on('dialog', lambda d: d.accept())
    standby = role == 'standby'
    acting = not standby or forward
    banner = page.locator('[data-ha-banner="classic"]')
    if standby:
        assert banner.get_attribute('data-ha-forwarding') == ('on' if forward else 'off')
        text = banner.inner_text()
        assert ('What you do here is carried out on the active instance' in text) == forward, text
        assert ('Read-only view' in text) != forward, text
    else:
        assert banner.count() == 0
    # adding clusters goes through the active; automated installs stay off every standby,
    # the answer URL they show would be this instance
    assert (page.locator('button[title="Manage Groups"]').count() > 0) == acting
    assert (page.get_by_text('Automated Installations').count() > 0) == (not standby)

    _open_resources(app)
    for view in ('Grid View', 'List View', 'Compact View'):
        page.locator(f'button[title="{view}"]').first.click()
        if view == 'Compact View':
            page.get_by_text('Select a VM from the list').wait_for(timeout=3000)
            page.locator('div.cursor-pointer', has_text='web01').first.click()
            page.get_by_text('Quick Actions').wait_for(timeout=3000)
        page.wait_for_timeout(200)
        labels = _labels(page)
        assert ({'Shutdown', 'Migrate'} <= labels) == acting, (view, sorted(labels))
        links = _on_active_links(page)
        if standby:
            assert not labels & CONSOLE_LABELS, (view, sorted(labels & CONSOLE_LABELS))
            assert links == [CONSOLE_URL], (view, links)
        else:
            assert labels & CONSOLE_LABELS, (view, sorted(labels))
            assert not links, (view, links)
    if standby:
        # a real link into a new tab, not a button that runs anything here
        link = page.locator('a[data-ha-on-active]').first
        assert link.get_attribute('href') == CONSOLE_URL
        assert link.get_attribute('target') == '_blank'
        assert 'noopener' in link.get_attribute('rel')
    if forward:
        # the action goes out and nothing refuses it
        page.locator('button[title="Grid View"]').first.click()
        page.locator('button[title="Shutdown"]').first.click()
        assert _wait_for_call(app, ('POST', '/api/clusters/c1/vms/pve1/qemu/100/shutdown'))
        page.wait_for_timeout(400)
        assert app.server.forwarded == [('POST', '/api/clusters/c1/vms/pve1/qemu/100/shutdown')]
        assert not [t for t in _toasts(page) if 'standby' in t.lower()], _toasts(page)
    # no console, preview or shell ever asked for on a standby
    if standby:
        assert not [c for c in app.server.calls
                    if c[1].endswith(('/console', '/spice', '/screenshot')) or c[1] == '/api/ws/token']
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_corporate_menus_and_detail_send_consoles_to_the_active(open_app, role):
    app = open_app(role=role, layout='corporate', clusters=[CLUSTER], resources=[VM], forward_writes=True)
    page = app.page
    standby = role == 'standby'
    _serve_the_active(app)
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    vm = page.locator('.corp-tree-child', has_text='web01').first
    vm.wait_for(timeout=5000)
    vm.click(button='right')
    menu = page.locator('.corp-context-menu').first
    menu.wait_for(timeout=3000)
    lines = [x.strip() for x in menu.inner_text().split('\n') if x.strip()]
    # the power menu is there on a forwarding standby too, the consoles are not
    assert 'Power' in lines, lines
    assert ('Console' not in lines and 'SPICE' not in lines) == standby, lines
    assert (ON_ACTIVE in lines) == standby, lines
    if standby:
        with app.ctx.expect_page() as opened:
            menu.get_by_text(ON_ACTIVE).click()
        tab = opened.value
        tab.wait_for_load_state()
        assert tab.url == CONSOLE_URL
        tab.close()
    else:
        page.keyboard.press('Escape')
    page.mouse.click(5, 900)

    _open_resources(app)
    page.locator('span', has_text='web01').first.click()
    page.get_by_text('Snapshots').first.wait_for(timeout=3000)
    page.wait_for_timeout(300)
    labels = _labels(page)
    assert {'Shutdown', 'Reboot'} <= labels, sorted(labels)
    assert bool(labels & CONSOLE_LABELS) != standby, sorted(labels & CONSOLE_LABELS)
    links = _on_active_links(page)
    # the toolbar and the preview tile each carry the link
    assert links == ([CONSOLE_URL, CONSOLE_URL] if standby else []), links
    shots = [c for c in app.server.calls if c[1].endswith('/screenshot')]
    assert (not shots) == standby, shots
    page.get_by_text('Snapshots').first.click()
    page.wait_for_timeout(500)
    eff = [u for u in app.server.urls if '/efficient-snapshots' in u]
    assert eff and all(('refresh=true' in u) != standby for u in eff), eff
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_cloud_forwarding_standby_acts_but_opens_consoles_there(open_app, role):
    app = open_app(role=role, layout='cloud', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   autoinstall='manage')
    page = app.page
    standby = role == 'standby'
    if standby:
        assert page.locator('[data-ha-banner="cloud"]').get_attribute('data-ha-forwarding') == 'on'
    # automated installs stay off every standby, forwarding or not
    assert (page.get_by_text('Automated Installs').count() == 0) == standby
    page.get_by_text('Virtual Machines').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    assert 'New VM' in _labels(page)
    page.get_by_text('web01').first.click()
    bar = page.locator('.cloud-detail-actions')
    bar.wait_for(timeout=3000)
    text = bar.inner_text()
    assert 'Shutdown' in text and 'Reboot' in text, text
    assert ('SPICE' not in text) == standby, text
    links = bar.locator('a[data-ha-on-active]')
    assert links.count() == (1 if standby else 0)
    if standby:
        assert links.first.get_attribute('href') == CONSOLE_URL
        assert ON_ACTIVE in text
    page.locator('.cloud-detail-actions button', has_text='Actions').click()
    page.wait_for_timeout(300)
    menu = page.evaluate('() => Array.from(document.querySelectorAll("[role=menu], .cloud-menu"))'
                         '.map(m => m.innerText).join("\\n")').split('\n')
    menu = [x.strip() for x in menu if x.strip()]
    assert 'Migrate' in menu and 'Delete' in menu, menu
    assert ('Console' not in menu) == standby, menu
    assert (ON_ACTIVE in menu) == standby, menu
    assert not app.errors, app.errors


@pytest.mark.parametrize('language', ['en', 'de'])
def test_runtime_the_active_out_of_reach_is_one_translated_toast(open_app, language):
    """The page reads the banner while the active answers; by the click it no longer does.
    One toast in the user's language, and the banner is read again, so the page turns
    read-only without waiting for the next poll."""
    app = open_app(role='standby', layout='modern', language=language, clusters=[CLUSTER], resources=[VM],
                   forward_writes=True, active_down=True)
    page = app.page
    page.on('dialog', lambda d: d.accept())
    banner = page.locator('[data-ha-banner="classic"]')
    assert banner.get_attribute('data-ha-forwarding') == 'on'
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Ressourcen' if language == 'de' else 'Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    checks = app.server.calls.count(('GET', '/api/auth/check'))
    shutdown = 'Herunterfahren' if language == 'de' else 'Shutdown'
    page.locator(f'button[title="{shutdown}"]').first.click()
    app.see(UNREACHABLE[language], timeout=5000)
    page.wait_for_timeout(600)
    assert page.get_by_text(UNREACHABLE[language]).count() == 1
    assert page.get_by_text('act again once it is back').count() == 0
    assert ('POST', '/api/clusters/c1/vms/pve1/qemu/100/shutdown') in app.server.calls
    # read again at once: forwarding is off now, and so are the buttons
    assert app.server.calls.count(('GET', '/api/auth/check')) > checks
    page.wait_for_function('() => document.querySelector("[data-ha-banner]")'
                           '.getAttribute("data-ha-forwarding") === "off"', timeout=5000)
    page.wait_for_timeout(300)
    assert page.locator(f'button[title="{shutdown}"]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_cloud_helper_names_the_active_out_of_reach(open_app):
    job = {'id': 'backup-1', 'enabled': 1, 'schedule': 'daily', 'storage': 'local', 'mode': 'snapshot',
           'vmid': '100', 'node': 'pve1'}
    app = open_app(role='standby', layout='cloud', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   active_down=True, extra={('GET', '/api/clusters/c1/datacenter/backup'): (200, [job])})
    page = app.page
    said = []

    def dialog(d):
        said.append(d.message)
        d.accept()
    page.on('dialog', dialog)
    page.locator('.cloud-shell').get_by_text('Backups', exact=True).first.click()
    page.locator('.cloud-table-row', has_text='daily').first.wait_for(timeout=5000)
    page.locator('button[title="Run now"]').first.click()
    deadline = time.time() + 4
    while time.time() < deadline and not said:
        page.wait_for_timeout(100)
    assert said == ['Action failed: ' + UNREACHABLE['en']], said
    assert ('POST', '/api/clusters/c1/datacenter/backup/backup-1/run') in app.server.calls
    assert not app.errors, app.errors


def test_runtime_the_forward_switch_turns_a_standby_read_only(open_app):
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM], forward_writes=True)
    page = app.page
    banner = page.locator('[data-ha-banner="classic"]')
    assert banner.get_attribute('data-ha-forwarding') == 'on'
    panel = _open_ha(app, 'standby')
    switch = page.get_by_role('switch', name='Carry out changes through the leader')
    live = page.get_by_role('switch', name='Connect to the clusters while following the leader')
    assert switch.get_attribute('aria-checked') == 'true'
    # next to the live view
    assert page.evaluate('([a, b]) => document.getElementById(a).closest(".grid") === '
                         'document.getElementById(b).closest(".grid")', ['pgha-forward', 'pgha-live-view'])
    assert live.is_visible()
    assert panel.locator('[data-ha-forward-paused]').count() == 0
    switch.click()
    assert _wait_for_toast(page, 'Saved. While following the leader, this instance only shows and changes nothing.'), _toasts(page)
    assert app.server.bodies['/api/ha/settings'][-1] == {'forward_writes': False}
    # no restart for this one, and the banner follows at once
    assert page.locator('[role="alertdialog"]').count() == 0
    page.wait_for_function('() => document.querySelector("[data-ha-banner]")'
                           '.getAttribute("data-ha-forwarding") === "off"', timeout=5000)
    assert 'Read-only view' in banner.inner_text()
    page.wait_for_function('() => document.getElementById("pgha-forward").getAttribute("aria-checked") === "false"',
                           timeout=5000)
    assert not app.errors, app.errors


def test_runtime_the_forward_switch_only_saves_on_an_active(open_app):
    app = open_app(role='active', layout='modern', forward_writes=False)
    page = app.page
    _open_ha(app, 'active')
    switch = page.get_by_role('switch', name='Carry out changes through the leader')
    assert switch.get_attribute('aria-checked') == 'false'
    switch.click()
    assert _wait_for_toast(page, 'Saved. While following the leader, this instance carries out changes through it.'), _toasts(page)
    assert app.server.bodies['/api/ha/settings'][-1] == {'forward_writes': True}
    page.wait_for_function('() => document.getElementById("pgha-forward").getAttribute("aria-checked") === "true"',
                           timeout=5000)
    assert page.locator('[data-ha-banner]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('source_active', [False, True])
def test_runtime_forwarding_on_without_an_active_says_it_is_paused(open_app, source_active):
    """The switch is on, but the instance the standby follows does not answer as active: the
    server does not forward then, the page stays read-only and the panel says why."""
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   source_active=source_active)
    page = app.page
    assert page.locator('[data-ha-banner="classic"]').get_attribute('data-ha-forwarding') == \
        ('on' if source_active else 'off')
    assert (page.locator('button[title="Manage Groups"]').count() > 0) == source_active
    panel = _open_ha(app, 'standby')
    assert page.get_by_role('switch', name='Carry out changes through the leader').get_attribute('aria-checked') == 'true'
    paused = panel.locator('[data-ha-forward-paused]')
    assert paused.count() == (0 if source_active else 1)
    if not source_active:
        assert 'does not answer as the active instance right now' in paused.inner_text()
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_a_console_window_on_a_standby_offers_the_active(open_app, role):
    """A console link (#767) opened on a standby, forwarding or not: nothing is asked for
    here, the window offers the same console on the active."""
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM], forward_writes=True)
    page = app.page
    before = len(app.server.calls)
    page.goto(BASE + '/?console=c1:qemu:100:pve1', wait_until='load')
    if role == 'standby':
        box = page.locator('[data-ha-console-elsewhere]')
        box.wait_for(timeout=10000)
        assert 'Consoles and shells only run on the active instance' in box.inner_text()
        assert box.locator('a[data-ha-on-active]').get_attribute('href') == CONSOLE_URL
        page.wait_for_timeout(300)
        assert [c for c in app.server.calls[before:] if c[1] != '/api/auth/check'] == [], app.server.calls[before:]
        assert not app.errors, app.errors
    else:
        # the active opens the console itself: it looks the cluster up, and offers no link
        assert _wait_for_call(app, ('GET', '/api/clusters'), 10)
        assert page.locator('[data-ha-console-elsewhere]').count() == 0
        assert page.locator('[data-ha-on-active]').count() == 0


@pytest.mark.parametrize('role', ['standby', 'active'])
def test_runtime_esxi_on_a_forwarding_standby(open_app, role):
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM], extra=ESXI_READS,
                   forward_writes=True)
    page = app.page
    standby = role == 'standby'
    page.get_by_text('esx01').first.wait_for(timeout=8000)
    # adding goes through the active again
    assert page.locator('button[title="Add ESXi Server"]').count() == 1
    page.get_by_text('esx01').first.click()
    page.get_by_text('legacy01').first.wait_for(timeout=8000)
    page.get_by_text('legacy01').first.click()
    page.locator('button', has_text='Snapshots').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    detail = _labels(page)
    assert {'Stop', 'Suspend'} & detail, sorted(detail & ESXI_POWER)
    assert ('Console (VMRC)' not in detail) == standby, sorted(detail & ESXI_POWER)
    # no deep link into an ESXi console: the active's start page
    assert _on_active_links(page) == ([PEER + '/'] if standby else [])
    assert not [c for c in app.server.calls if c[1].endswith('/console')]
    assert not app.errors, app.errors


# -- v3: what no standby carries out, forwarding or not ------------------------------------------
#
# app.py keeps some writes refused on every standby (_STANDBY_NOT_FORWARDED): this instance's own
# settings, the code and the plugins of the process, a security key, and rows of the tables each
# instance keeps for itself. Their controls ask haStandby, not haReadOnly. A form that would still
# look editable shows one note in place of its save button, with the link to the active.

def test_the_note_says_why_and_links_the_active():
    note = _function(_read('web', 'src', 'ui.js'), 'HaSettingsOnActive')
    # a member that serves users is no standby to its users: the same note names the leader
    assert ("const text = haServing ? (own ? t('pgHaOwnSettingsOnLeader') : t('pgHaSettingsOnLeader'))\n"
            "                : (own ? t('pgHaOwnSettingsHere') : t('pgHaSettingsOnActive'));") in note
    assert '<span className="flex-1 min-w-0">{text}</span>' in note
    assert "data-ha-settings-on-active={own ? 'own' : 'shared'}" in note
    assert '<HaOnActiveLink settings className=' in note
    # it renders wherever it is put: every caller asks the flag, the note only for its words
    assert 'const { haServing } = useAuth();' in note
    assert 'return null' not in note and 'haStandby' not in note


# (file, what the control is found by, the gate in front of it, how far in front at most).
# Every occurrence counts; the reach keeps the gate of another control further up from passing.
SAVE_NOTE, OWN_NOTE = '{haStandby ? <HaSettingsOnActive /> : (', '{haStandby ? <HaSettingsOnActive own /> : ('
STANDBY_GATES = [
    ('settings_modal.js', 'onClick={saveLdapSettings}', SAVE_NOTE, 300),
    ('settings_modal.js', 'onClick={saveOidcSettings}', SAVE_NOTE, 300),
    ('settings_modal.js', 'onClick={handleSaveSMTPSettings}', SAVE_NOTE, 300),
    ('settings_modal.js', 'syslog_filter_by_selected_cluster: !!serverSettings.syslog_filter_by_selected_cluster,\n',
     OWN_NOTE, 900),
    ('settings_modal.js', 'onClick={handleSaveServerSettings}', OWN_NOTE, 300),
    ('settings_modal.js', 'onClick={handleAcmeRequest}', OWN_NOTE, 300),
    ('settings_modal.js', 'onClick={handleAcmeDnsComplete}', '{acmeResult?.pending_dns && !haStandby && (', 2300),
    ('settings_modal.js', 'onClick={performUpdate}', ') : !haStandby && (', 300),
    ('settings_modal.js', 'onClick={() => { loadBackups(); setShowRollbackModal(true); }}', '{!haStandby && (', 1100),
    ('settings_modal.js', 'onClick={() => refreshPoolCache(selectedPoolCluster)}',
     '{selectedPoolCluster && !haStandby && (', 300),
    ('settings_modal.js', 'await fetch(`${API_URL}/plugins/rescan`', '{!haStandby && <button onClick={async () => {', 300),
    ('settings_modal.js', '() => togglePlugin(plugin.id, plugin.enabled)', 'onClick={haStandby ? undefined : ', 300),
    ('settings_modal.js', "await fetch(`${API_URL}/plugins/${plugin.id}`, { method: 'DELETE'",
     '{!haStandby && <button onClick={async () => {', 400),
    ('security.js', 'onClick={() => setShowImportModal(true)}', SAVE_NOTE, 300),
    ('node_modals.js', 'onClick={openWarn}', OWN_NOTE, 300),
    ('node_modals.js', 'onClick={openRfWarn}', OWN_NOTE, 300),
    ('create_modals.js', 'onClick={register}', '{!haStandby && (', 300),
    ('vm_modals.js', 'onClick={() => saveAutoReconcile(!autoReconcile)}', '{canAdminSettings && !haStandby && (', 300),
]


@pytest.mark.parametrize('name,anchor,gate,reach', STANDBY_GATES,
                         ids=[f'{n}:{a[:40]}' for n, a, _, _ in STANDBY_GATES])
def test_every_control_behind_a_refused_route_asks_the_standby_flag(name, anchor, gate, reach):
    src = _read('web', 'src', name)
    spots = [m.start() for m in re.finditer(re.escape(anchor), src)]
    assert spots, anchor
    for at in spots:
        gate_at = src.rfind(gate, 0, at)
        assert gate_at >= 0 and at - gate_at < reach, (anchor, at - gate_at, src[max(0, at - 300):at])


def test_the_forms_that_save_as_you_type_are_locked_on_a_standby():
    sec = _read('web', 'src', 'security.js')
    for component, save in (('SecuritySettingsSection', 'saveSettings('),
                            ('ComplianceSection', 'saveHardeningSettings(')):
        body = _function(sec, component)
        assert re.search(r'const \{[^}]*\bhaStandby\b[^}]*\} = useAuth\(\);', body), component
        view = body[body.index('\n            return (\n'):]
        start = view.index('<fieldset disabled={haStandby}')
        # the locked parts: the Force Password Reset between two of them is a write of its
        # own, which a forwarding standby hands on (tests/test_ha_leftovers_ui.py)
        spans = [(m.start(), view.index('</fieldset>', m.start()))
                 for m in re.finditer(re.escape('<fieldset disabled={haStandby}'), view)]
        calls = [m.start() for m in re.finditer(re.escape(save), view)]
        assert calls and all(any(s < c < e for s, e in spans) for c in calls), component
        # the note right before the locked part
        assert '{haStandby && <HaSettingsOnActive />}' in view[start - 120:start], component
    # the lockouts and the backup export stay: they are this instance's own and go through
    body = _function(sec, 'SecuritySettingsSection')
    view = body[body.index('\n            return (\n'):]
    assert view.index('</fieldset>') < view.index('onClick={unlockAll}')
    assert view.index('</fieldset>') < view.index('<ConfigBackupSection')


# -- runtime ------------------------------------------------------------------------------------

NOTE = '[data-ha-settings-on-active]'
PLUGIN = {'id': 'hello', 'name': 'Hello', 'version': '1.0', 'enabled': True, 'loaded': True}
SETTINGS_READS = {('GET', '/api/settings/server'): (200, {'domain': 'pegaprox-b.example', 'port': 5000}),
                  ('GET', '/api/plugins'): (200, [PLUGIN])}
# the writes these pages would send and a standby refuses, forwarded or not
REFUSED_WRITES = ('/api/settings/server', '/api/settings/acme/request', '/api/plugins/rescan',
                  '/api/plugins/hello/enable', '/api/plugins/hello/disable', '/api/plugins/hello',
                  '/api/config/restore', '/api/hardware-monitoring/consent',
                  '/api/hardware-monitoring/redfish-consent', '/api/webauthn/register/begin',
                  '/api/pegaprox/update/rollback')


def _notes(page, kind):
    return page.locator(f'{NOTE}[data-ha-settings-on-active="{kind}"]')


def _settings_tab(app, name):
    app.page.get_by_role('button', name=name, exact=True).first.click()
    app.page.wait_for_timeout(300)


@pytest.mark.parametrize('role,forward', [('standby', True), ('standby', False), ('active', False)])
def test_runtime_the_settings_a_standby_never_saves_point_to_the_active(open_app, role, forward):
    app = open_app(role=role, layout='modern', forward_writes=forward, extra={**SETTINGS_READS, **SSE_TOKEN})
    page = app.page
    page.on('dialog', lambda d: d.accept())
    standby = role == 'standby'
    app.open_settings()

    _settings_tab(app, 'Server')
    page.get_by_text('Plugins', exact=True).first.wait_for(timeout=5000)
    page.get_by_text('Hello', exact=True).first.wait_for(timeout=5000)
    labels = _labels(page)
    # the save at the bottom and the certificate request: this instance's own
    assert ('Save Settings' in labels) != standby, sorted(labels)
    assert ('Request Certificate' in labels) != standby, sorted(labels)
    assert _notes(page, 'own').count() == (2 if standby else 0)
    # SMTP is shared: saved on the active, it arrives with the sync
    assert _notes(page, 'shared').count() == (1 if standby else 0)
    assert ('Rescan' in labels) != standby and ('Delete plugin' in labels) != standby, sorted(labels)
    if standby:
        # the way to the active, in a new tab
        link = _notes(page, 'own').first.locator('a[data-ha-on-active]')
        assert link.get_attribute('href') == PEER + '/'
        assert link.get_attribute('target') == '_blank'
        assert 'Change them on the active instance' in _notes(page, 'shared').first.inner_text()
        assert 'set before pairing or after a promotion' in _notes(page, 'own').first.inner_text()
    # the plugin switch shows its state, and switches only where the route runs
    row = page.get_by_text('Hello', exact=True).first.locator('xpath=ancestor::div[contains(@class, "justify-between")][1]')
    row.locator('.toggle-switch.active').click()
    page.wait_for_timeout(400)
    assert (('POST', '/api/plugins/hello/disable') in app.server.calls) != standby

    _settings_tab(app, 'LDAP / AD')
    assert ('Save LDAP Settings' in _labels(page)) != standby
    assert _notes(page, 'shared').count() == (1 if standby else 0)
    _settings_tab(app, 'OIDC / Entra ID')
    assert ('Save OIDC Settings' in _labels(page)) != standby
    assert _notes(page, 'shared').count() == (1 if standby else 0)
    _settings_tab(app, 'Syslog Server')
    assert _notes(page, 'own').count() == (1 if standby else 0)
    _settings_tab(app, 'Security Settings')
    page.get_by_text('Login Protection').first.wait_for(timeout=5000)
    assert _notes(page, 'shared').count() == (2 if standby else 0)     # the settings and the restore
    assert ('Restore Backup' in _labels(page)) != standby
    assert page.evaluate('() => Array.from(document.querySelectorAll("fieldset")).some(f => f.disabled)') == standby
    # the lockouts are this instance's own: still there
    assert page.locator('button[title="Refresh"]').first.is_enabled()
    _settings_tab(app, 'Compliance')
    page.get_by_text('Compliance & Hardening').first.wait_for(timeout=5000)
    assert _notes(page, 'shared').count() == (1 if standby else 0)
    _settings_tab(app, 'Updates')
    page.get_by_text('Current Version').first.wait_for(timeout=5000)
    assert ('View Backups' in _labels(page)) != standby

    if standby:
        assert not [c for c in app.server.calls if c[0] != 'GET' and c[1] in REFUSED_WRITES], app.server.calls
        assert not [t for t in _toasts(page) if 'standby' in t.lower()], _toasts(page)
    assert not app.errors, app.errors


HW_READS = {('GET', '/api/hardware-monitoring/consent'): (200, {
                'enabled': False, 'current_version': 1,
                'warning': {'title': 'Enable hardware monitoring', 'points': ['reads sensors'], 'require_delay_seconds': 0}}),
            ('GET', '/api/hardware-monitoring/redfish-consent'): (200, {
                'enabled': False, 'current_version': 1,
                'warning': {'title': 'Enable out-of-band monitoring', 'points': ['BMC'], 'require_delay_seconds': 0}})}


@pytest.mark.parametrize('role,forward', [('standby', True), ('standby', False), ('active', False)])
def test_runtime_the_hardware_consent_stays_with_each_instance(open_app, role, forward):
    app = open_app(role=role, layout='modern', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS,
                   forward_writes=forward, extra=HW_READS)
    page = app.page
    standby = role == 'standby'
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Configuration"]').first.wait_for(timeout=5000)
    page.locator('button[title="Node Configuration"]').first.click()
    page.get_by_text('Proxmox Node').first.wait_for(timeout=5000)
    page.locator('button', has_text='Hardware').last.click()
    page.get_by_text('Out-of-band (Redfish)').first.wait_for(timeout=5000)
    labels = _labels(page)
    for consent in ('Enable hardware monitoring', 'Enable out-of-band monitoring'):
        assert (consent in labels) != standby, (consent, sorted(labels))
    notes = _notes(page, 'own')
    assert notes.count() == (2 if standby else 0)
    if standby:
        assert notes.first.locator('a[data-ha-on-active]').get_attribute('href') == PEER + '/'
    else:
        # the button on the active opens the warning, the consent itself is not asked for yet
        page.locator('button', has_text='Enable hardware monitoring').first.click()
        page.get_by_text('reads sensors').first.wait_for(timeout=3000)
    assert not [c for c in app.server.calls if c[0] != 'GET' and 'hardware-monitoring' in c[1]]
    assert not app.errors, app.errors


KEY_READS = {('GET', '/api/webauthn/available'): (200, {'available': True, 'host_usable': True}),
             ('GET', '/api/webauthn/credentials'): (200, {'available': True, 'credentials': []})}


@pytest.mark.parametrize('role,forward', [('standby', True), ('standby', False), ('active', False)])
def test_runtime_a_security_key_is_enrolled_on_the_active(open_app, role, forward):
    app = open_app(role=role, layout='modern', forward_writes=forward, extra=KEY_READS)
    page = app.page
    standby = role == 'standby'
    page.locator('header button', has_text='Admin').first.click()
    page.get_by_text('My Profile').first.click()
    page.get_by_role('button', name=re.compile(r'^security$', re.I)).first.click()
    page.get_by_text('Hardware Keys').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    assert ('Add Security Key' in _labels(page)) != standby
    notes = _notes(page, 'shared')
    assert notes.count() == (1 if standby else 0)
    if standby:
        assert notes.first.locator('a[data-ha-on-active]').get_attribute('href') == PEER + '/'
    assert not [c for c in app.server.calls if 'webauthn/register' in c[1]]
    assert not app.errors, app.errors


# -- serving members: a standby that serves users as an active instance (#625) --------------------
#
# The active is the leader: it keeps every automation and the config DB. A standby with live view
# and forwarding on that the leader made active (serve_assigned) serves users; the server then
# reports it as serving. Its role stays standby, so every automation gate stays shut, but to its users it is an
# active instance: consoles, shells, SPICE and the console preview open on it, every change goes
# to the leader. The page asks haConsolesElsewhere (a standby that does not serve) for consoles,
# haStandby for the settings that stay on the leader, haReadOnly for changes.

LEADER = 'Active - Leader (automation)'
SERVING_BANNER = f'Active instance. Automation (HA, balancing, schedules) runs on the leader {PEER}'
LEADER_DOWN = (f'Active instance. The leader {PEER} does not answer: changes are paused, live data and '
               'consoles keep working.')
FORWARDING_BANNER = 'What you do here is carried out on the active instance'
# the per-instance switch of v6, gone since the leader sets who is active (v8)
SERVE_SWITCH = 'Serve users as an active instance'


def test_the_context_derives_the_console_flag(ctx):
    assert "const haConsolesElsewhere = haStandby && ha.serving !== true;" in ctx
    provider = ctx[ctx.index('<AuthContext.Provider value={{'):]
    provider = provider[:provider.index('}}>')]
    for flag in ('haReadOnly', 'haStandby', 'haConsolesElsewhere'):
        assert re.search(r'\b%s\b' % flag, provider), flag


def test_the_three_flags_answer_as_agreed(ctx):
    """The three lines as they are in the source, run in node over every combination."""
    import shutil
    import subprocess
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not installed')
    lines = _block(ctx, 'const haStandby = ', 'return(')
    script = """
    const out = [];
    for (const role of ['standalone', 'active', 'standby'])
      for (const forwarding of [true, false, undefined])
        for (const serving of [true, false, undefined]) {
          const ha = { role, forwarding, serving };
          %s
          out.push([role, String(forwarding), String(serving), haStandby, haReadOnly, haConsolesElsewhere]);
        }
    console.log(JSON.stringify(out));
    """ % lines
    res = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    for role, forwarding, serving, standby, read_only, elsewhere in json.loads(res.stdout):
        assert standby == (role == 'standby')
        assert read_only == (role == 'standby' and forwarding != 'true')
        # a serving member opens consoles itself, whether its leader answers or not
        assert elsewhere == (role == 'standby' and serving != 'true'), (role, forwarding, serving)


def test_the_link_stands_in_for_a_console_only_where_none_opens():
    ui = _read('web', 'src', 'ui.js')
    link = _function(ui, 'HaOnActiveLink')
    assert 'const { ha, haStandby, haConsolesElsewhere, haServing } = useAuth();' in link
    assert 'if (!(settings ? haStandby : haConsolesElsewhere)) return null;' in link
    # the settings note keeps its link on every standby, serving or not
    note = _function(ui, 'HaSettingsOnActive')
    assert '<HaOnActiveLink settings className=' in note
    # every other link stands in for a console
    for name in ('cloud.js', 'dashboard.js', 'tables.js', 'vm_modals.js', 'node_modals.js'):
        assert '<HaOnActiveLink settings' not in _read('web', 'src', name), name


# the console surfaces and the flag each asks, by file
CONSOLE_GATES = [
    ('dashboard.js', "if (haConsolesElsewhere) { haRefusedRef.current?.(false, 'console'); return; }", 3),
    ('dashboard.js', "...(haConsolesElsewhere ? onActiveItems('node.shell', '', !online) : [", 1),
    ('dashboard.js', "...(haConsolesElsewhere ? onActiveItems('vm.console', haConsoleSearch(vm), !isRunning) : [", 1),
    ('dashboard.js', '{isOn && !haConsolesElsewhere && (', 1),
    ('dashboard.js', '{isOn && haConsolesElsewhere && (', 1),
    ('dashboard.js', '}, [consoleKey, haConsolesElsewhere]);', 1),
    ('node_modals.js', "{activeTab === 'shell' && haConsolesElsewhere && <HaConsoleOnActive />}", 1),
    ('node_modals.js', "{activeTab === 'shell' && !haConsolesElsewhere && (", 1),
    ('node_modals.js', "{activeDetailTab === 'shell' && haConsolesElsewhere && <HaConsoleOnActive />}", 1),
    ('node_modals.js', "{activeDetailTab === 'shell' && !haConsolesElsewhere && (", 1),
    ('tables.js', 'const consoles = !haConsolesElsewhere;', 1),
    ('vm_modals.js', 'const consoles = !haConsolesElsewhere;', 2),
    ('cloud.js', 'consoleOnActive: haConsolesElsewhere ? (r) => haOpenOnActive(', 1),
]


@pytest.mark.parametrize('name,gate,count', CONSOLE_GATES, ids=[f'{n}:{g[:48]}' for n, g, _ in CONSOLE_GATES])
def test_every_console_surface_asks_the_console_flag(name, gate, count):
    assert _read('web', 'src', name).count(gate) == count


def test_no_console_surface_asks_the_standby_flag_any_more():
    """haStandby stays for the settings kept on the leader; nothing that opens a console,
    shell, SPICE or the console preview reads it."""
    dash = _read('web', 'src', 'dashboard.js')
    for old in ("if (haStandby) { haRefusedRef.current?.(false, 'console')", "...(haStandby ? onActiveItems(",
                '{isOn && !haStandby && (', '{isOn && haStandby && (', '}, [consoleKey, haStandby]);'):
        assert old not in dash, old
    cloud_actions = dash[dash.index('const cloudActions = {'):]
    assert cloud_actions.index('if (haConsolesElsewhere) {') < cloud_actions.index("['openConsole', 'openSpice', 'openLxcShell']")
    for name in ('tables.js', 'vm_modals.js', 'node_modals.js', 'cloud.js'):
        src = _read('web', 'src', name)
        for old in ('const consoles = !haStandby;', "=== 'shell' && haStandby", "=== 'shell' && !haStandby",
                    '!haStandby && data.shellFullscreen', 'consoleOnActive: haStandby'):
            assert old not in src, (name, old)
    # what runs on the node and is not forwarded still asks haStandby: the snapshot refresh
    vm = _read('web', 'src', 'vm_modals.js')
    assert "authFetch(`${base}/efficient-snapshots${haStandby ? '' : '?refresh=true'}`)" in vm


# the per-instance rows that are forwarded now: they follow haReadOnly again (v6)
FORWARDED_GATES = [
    ('dashboard.js', 'onClick={e => { e.stopPropagation(); ack(ev.id, ', "{canAct && ev.status === 'open' && (", 700),
    ('dashboard.js', 'onClick={clearInbox}', '{items.length > 0 && !haReadOnly && (', 300),
    ('dashboard.js', 'onClick={() => ackAlert(a.id)}', '{!a.acked_at && !haReadOnly && (', 300),
]


@pytest.mark.parametrize('name,anchor,gate,reach', FORWARDED_GATES,
                         ids=[f'{n}:{a[:40]}' for n, a, _, _ in FORWARDED_GATES])
def test_the_forwarded_acknowledgements_follow_the_read_only_flag(name, anchor, gate, reach):
    src = _read('web', 'src', name)
    spots = [m.start() for m in re.finditer(re.escape(anchor), src)]
    assert spots, anchor
    for at in spots:
        gate_at = src.rfind(gate, 0, at)
        assert gate_at >= 0 and at - gate_at < reach, (anchor, at - gate_at, src[max(0, at - 300):at])
        assert '!haStandby' not in src[gate_at:at], anchor
    dash = _read('web', 'src', 'dashboard.js')
    assert 'const canAct = isAdmin && !haReadOnly;' in _function(dash, 'DriftTab')
    assert 'const { haReadOnly } = useAuth();' in _function(dash, 'PushBellButton')


def test_the_banner_names_the_leader_on_a_serving_member(banner):
    assert 'const serving = ha.serving === true;' in banner
    assert 'const leaderDown = serving && ha.leader_reachable === false;' in banner
    assert ("const text = t(leaderDown ? 'pgHaBannerLeaderDown'\n"
            "                    : serving ? 'pgHaBannerServing'\n"
            "                    : ha.forwarding === true ? 'pgHaBannerForwarding' : 'pgHaBannerStandby')") in banner
    assert "'data-ha-serving': serving ? 'on' : 'off'," in banner
    assert "'data-ha-leader': leaderDown ? 'down' : undefined," in banner
    # both layouts carry the same attributes
    assert banner.count('{...data}') == 2


def test_the_panel_speaks_the_serving_contract(panel):
    body = _function(panel, 'HaPanel')
    # v8: no instance switches itself to serving any more, the leader sets it per member
    for gone in ('serve_users', 'serveUsers', 'setServeUsers', 'serveCard', 'pgha-serve"', "'pgHaServeUsers'"):
        assert gone not in body, gone
    # the automation line and the badges
    assert "{role !== 'standalone' && (" in body and "{t('pgHaAutomationLeader')}" in body
    assert '<HaRoleBadge role={role} serving={status.serving === true} t={t} />' in body
    badge = _function(panel, 'HaRoleBadge')
    assert "const shown = role === 'standby' && serving ? (pending ? 'pending' : 'serving') : role;" in badge
    assert "active: t('pgHaRoleLeader'), serving: t('pgHaRoleActive')" in badge
    assert "pending: t('pgHaRoleActivePending')" in badge


OLD_CONSOLE_CLAUSE = {'de': 'Konsolen öffnen sich immer', 'en': 'consoles always open', 'zh': '控制台始终',
                      'pl': 'konsole zawsze', 'fr': r"consoles s\'ouvrent toujours", 'es': 'consolas siempre',
                      'pt': 'consoles sempre', 'ko': '콘솔은 항상', 'it': 'console si aprono sempre'}


def test_the_serving_strings_say_no_em_dash():
    blocks = _blocks()
    for key in ('pgHaRoleLeader', 'pgHaBannerServing', 'pgHaBannerLeaderDown', 'pgHaAutomationLeader',
                'pgHaForwardWritesHint'):
        for lang, block in blocks.items():
            line = re.search(r'^ +%s: (.*),$' % key, block, re.M)
            assert line, (lang, key)
            assert '\u2014' not in line.group(1), (lang, key)
    # the forwarding hint no longer says consoles always open on the active
    for lang, block in blocks.items():
        hint = re.search(r'^ +pgHaForwardWritesHint: (.*),$', block, re.M).group(1)
        assert OLD_CONSOLE_CLAUSE[lang] not in hint, lang
    assert 'consoles open on the leader unless this instance serves users' in blocks['en']
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


# -- runtime ------------------------------------------------------------------------------------

def _console_calls(app, since=0):
    return [c for c in app.server.calls[since:]
            if c[1].endswith(('/console', '/spice', '/screenshot', '/termproxy')) or c[1] == '/api/ws/token']


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_serving_member_opens_consoles_itself(open_app, serve):
    """Serving: the banner calls it an active instance, the consoles are there and nothing
    links to the leader. Not serving (the counterproof): today's forwarding standby."""
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   serve_assigned=serve, autoinstall='manage', extra=SSE_TOKEN)
    page = app.page
    banner = page.locator('[data-ha-banner="classic"]')
    assert banner.get_attribute('data-ha-serving') == ('on' if serve else 'off')
    assert banner.get_attribute('data-ha-leader') is None
    text = banner.inner_text()
    assert (SERVING_BANNER in text) == serve, text
    assert ('Standby instance' in text) != serve, text
    assert (FORWARDING_BANNER in text) != serve, text
    # the automated installs stay with the instance that answers the installer: never a standby
    assert page.get_by_text('Automated Installations').count() == 0

    _open_resources(app)
    for view in ('Grid View', 'List View', 'Compact View'):
        page.locator(f'button[title="{view}"]').first.click()
        if view == 'Compact View':
            page.get_by_text('Select a VM from the list').wait_for(timeout=3000)
            page.locator('div.cursor-pointer', has_text='web01').first.click()
            page.get_by_text('Quick Actions').wait_for(timeout=3000)
        page.wait_for_timeout(200)
        labels = _labels(page)
        assert {'Shutdown', 'Migrate'} <= labels, (view, sorted(labels))
        assert bool(labels & CONSOLE_LABELS) == serve, (view, sorted(labels & CONSOLE_LABELS))
        assert _on_active_links(page) == ([] if serve else [CONSOLE_URL]), view
    assert not _console_calls(app)
    assert not app.errors, app.errors
    if serve:
        # the console opens here: the ticket is asked of this instance
        page.locator('button[title="Grid View"]').first.click()
        page.locator('button[title="Console"], button[title="Open Console"]').first.click()
        assert _wait_for_call(app, ('GET', '/api/clusters/c1/vms/pve1/qemu/100/console'), 5), app.server.calls[-8:]
        assert not [t for t in _toasts(page) if 'active instance' in t], _toasts(page)


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_serving_member_in_corporate_menus_and_detail(open_app, serve):
    app = open_app(role='standby', layout='corporate', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   serve_assigned=serve)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    vm = page.locator('.corp-tree-child', has_text='web01').first
    vm.wait_for(timeout=5000)
    vm.click(button='right')
    menu = page.locator('.corp-context-menu').first
    menu.wait_for(timeout=3000)
    lines = [x.strip() for x in menu.inner_text().split('\n') if x.strip()]
    assert 'Power' in lines, lines
    assert ({'Console', 'SPICE Console'} <= set(lines)) == serve, lines
    assert not ({'Console', 'SPICE Console'} & set(lines)) == serve, lines
    assert (ON_ACTIVE in lines) != serve, lines
    page.keyboard.press('Escape')
    page.mouse.click(5, 900)

    _open_resources(app)
    page.locator('span', has_text='web01').first.click()
    page.get_by_text('Snapshots').first.wait_for(timeout=3000)
    page.wait_for_timeout(300)
    labels = _labels(page)
    assert bool(labels & CONSOLE_LABELS) == serve, sorted(labels & CONSOLE_LABELS)
    assert _on_active_links(page) == ([] if serve else [CONSOLE_URL, CONSOLE_URL])
    # the preview is a console: a serving member grabs it itself
    shots = [c for c in app.server.calls if c[1].endswith('/screenshot')]
    assert bool(shots) == serve, shots
    # the snapshot refresh is no console: lvs on the node stays with the leader either way
    page.get_by_text('Snapshots').first.click()
    page.wait_for_timeout(500)
    eff = [u for u in app.server.urls if '/efficient-snapshots' in u]
    assert eff and not [u for u in eff if 'refresh=true' in u], eff
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_serving_member_in_cloud(open_app, serve):
    app = open_app(role='standby', layout='cloud', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   serve_assigned=serve)
    page = app.page
    banner = page.locator('[data-ha-banner="cloud"]')
    assert banner.get_attribute('data-ha-serving') == ('on' if serve else 'off')
    assert (SERVING_BANNER in banner.inner_text()) == serve
    page.get_by_text('Virtual Machines').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.get_by_text('web01').first.click()
    bar = page.locator('.cloud-detail-actions')
    bar.wait_for(timeout=3000)
    text = bar.inner_text()
    assert 'Shutdown' in text, text
    assert ('SPICE' in text) == serve, text
    assert bar.locator('a[data-ha-on-active]').count() == (0 if serve else 1)
    page.locator('.cloud-detail-actions button', has_text='Actions').click()
    page.wait_for_timeout(300)
    menu = page.evaluate('() => Array.from(document.querySelectorAll("[role=menu], .cloud-menu"))'
                         '.map(m => m.innerText).join("\\n")').split('\n')
    menu = [x.strip() for x in menu if x.strip()]
    assert ('Console' in menu) == serve, menu
    assert (ON_ACTIVE in menu) != serve, menu
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_serving_member_opens_the_node_shell_itself(open_app, serve):
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS,
                   forward_writes=True, serve_assigned=serve)
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Configuration"]').first.wait_for(timeout=5000)
    page.locator('button[title="Node Configuration"]').first.click()
    page.get_by_text('Proxmox Node').first.wait_for(timeout=5000)
    assert not _console_calls(app)
    before = len(app.server.calls)
    page.locator('button', has_text='Shell').last.click()
    page.wait_for_timeout(500)
    assert page.locator('[data-ha-console-elsewhere]').count() == (0 if serve else 1)
    assert (page.get_by_text('Node Shell', exact=True).count() > 0) == serve
    if serve:
        # the terminal asks this instance for its token
        deadline = time.time() + 5
        while time.time() < deadline and ('POST', '/api/ws/token') not in app.server.calls[before:]:
            page.wait_for_timeout(100)
        assert ('POST', '/api/ws/token') in app.server.calls[before:], app.server.calls[before:]
    else:
        assert not _console_calls(app)
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_console_window_on_a_serving_member(open_app, serve):
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   serve_assigned=serve)
    page = app.page
    before = len(app.server.calls)
    page.goto(BASE + '/?console=c1:qemu:100:pve1', wait_until='load')
    if serve:
        # it looks the cluster up and asks this instance for the console, with no link anywhere
        ticket = ('GET', '/api/clusters/c1/vms/pve1/qemu/100/console')
        deadline = time.time() + 10
        while time.time() < deadline and ticket not in app.server.calls[before:]:
            page.wait_for_timeout(100)
        seen = app.server.calls[before:]
        assert ('GET', '/api/clusters') in seen and ticket in seen, seen
        assert seen.index(('GET', '/api/clusters')) < seen.index(ticket)
        assert page.locator('[data-ha-console-elsewhere]').count() == 0
        assert page.locator('[data-ha-on-active]').count() == 0
        assert not [e for e in app.errors if 'pageerror' in e], app.errors
    else:
        page.locator('[data-ha-console-elsewhere]').wait_for(timeout=10000)
        page.wait_for_timeout(300)
        assert [c for c in app.server.calls[before:] if c[1] != '/api/auth/check'] == []


@pytest.mark.parametrize('layout,kind', [('modern', 'classic'), ('cloud', 'cloud')])
@pytest.mark.parametrize('serve', [True, False])
def test_runtime_the_leader_out_of_reach(open_app, layout, kind, serve):
    """The leader does not answer. A serving member says so: changes paused, consoles and live
    data go on. A plain standby (the counterproof) keeps today's read-only banner."""
    app = open_app(role='standby', layout=layout, clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   serve_assigned=serve, source_active=False)
    page = app.page
    banner = page.locator(f'[data-ha-banner="{kind}"]')
    assert banner.get_attribute('data-ha-forwarding') == 'off'
    assert banner.get_attribute('data-ha-leader') == ('down' if serve else None)
    text = banner.inner_text()
    assert (LEADER_DOWN in text) == serve, text
    assert ('If it stays down, promote a member under High Availability.' in text) == serve, text
    assert ('Read-only view' in text) != serve, text
    if layout == 'modern':
        _open_resources(app)
        labels = _labels(page)
        # nothing is forwarded while the leader is away, the consoles stay
        assert 'Shutdown' not in labels, sorted(labels)
        assert bool(labels & CONSOLE_LABELS) == serve, sorted(labels & CONSOLE_LABELS)
    assert not app.errors, app.errors


def test_runtime_the_serving_banner_speaks_german(open_app):
    app = open_app(role='standby', layout='modern', language='de', forward_writes=True, serve_assigned=True)
    text = app.page.locator('[data-ha-banner="classic"]').inner_text()
    assert f'Aktive Instanz. Automatisierung (HA, Lastverteilung, Zeitpläne) läuft auf dem Leader {PEER}' in text, text
    assert not app.errors, app.errors


def _seen(card, ch):
    return card.locator(f'[data-ha-member="{ch * 32}"] td').nth(2).inner_text().strip()


def test_runtime_the_leader_names_its_members(open_app):
    """What the leader set decides the word, what the member said confirms it: made active and
    serving is Active, made active and not confirmed yet is pending, switched off is a standby
    even while the member still serves until its next sync."""
    members = [_member('b', serve=True, serving_seen=True), _member('c', serving_seen=True),
               _member('d', serve=True, serving_seen=False)]
    app = open_app(role='active', layout='modern', members=members)
    panel = _open_ha(app, 'active')
    assert panel.locator('[data-ha-badge]').first.inner_text().strip() == LEADER
    card = panel.locator('[data-ha-members]')
    assert _seen(card, 'b') == 'Active'
    assert _seen(card, 'c') == 'Standby'
    assert _seen(card, 'd') == 'Active (pending)'
    pending = card.locator(f'[data-ha-member="{"d" * 32}"] [data-ha-badge="pending"]')
    assert pending.get_attribute('title').startswith('Made active on the leader, not confirmed by the member yet.')
    line = panel.locator('[data-ha-automation]')
    assert line.inner_text().strip() == (f'{ROLE_DESC["leader"]} '
                                         'Automation such as HA, balancing, schedules and alerts runs only on the leader.')
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_member_names_itself_and_the_leader(open_app, serve):
    """On a member the list comes from the leader with serve in it: the others show as the leader
    set them, and nothing in the table switches anything."""
    members = [_member('b', role='active', source=True), _member('c', serve=True, serving_seen=True),
               _member('d', serve=True)]
    app = open_app(role='standby', layout='modern', members=members, forward_writes=True, serve_assigned=serve)
    panel = _open_ha(app, 'standby')
    assert panel.locator('[data-ha-badge]').first.inner_text().strip() == ('Active' if serve else 'Standby')
    card = panel.locator('[data-ha-members]')
    assert _seen(card, 'b') == LEADER
    assert _seen(card, 'c') == 'Active'
    assert _seen(card, 'd') == 'Active (pending)'
    assert card.get_by_role('switch').count() == 0
    assert card.locator('[data-ha-actives]').count() == 0
    headers = [h.strip() for h in card.locator('thead th').all_inner_texts()]
    assert 'Active' not in headers, headers
    assert panel.locator('[data-ha-automation]').count() == 1
    assert not app.errors, app.errors


def test_runtime_a_standalone_has_no_leader(open_app):
    app = open_app(role='standalone', layout='modern')
    panel = _open_ha(app, 'standalone')
    assert panel.locator('[data-ha-badge]').first.inner_text().strip() == 'Standalone'
    assert panel.locator('[data-ha-automation]').count() == 0
    # live view and forwarding are stored for later; who is active is up to a leader (v8)
    assert app.page.get_by_role('switch', name=SERVE_SWITCH).count() == 0
    assert panel.locator('[data-ha-assigned]').count() == 0
    assert panel.get_by_role('switch').count() == 2
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_serving_member_still_saves_its_settings_on_the_leader(open_app, serve):
    """Serving changes the consoles, not the settings: the notes and their links stay. Their
    words follow the banner: a serving member is the active instance to its users, so the
    notes and the link name the leader; a plain standby keeps its own words."""
    app = open_app(role='standby', layout='modern', forward_writes=True, serve_assigned=serve,
                   extra={**SETTINGS_READS, **SSE_TOKEN})
    page = app.page
    app.open_settings()
    _settings_tab(app, 'Server')
    page.get_by_text('Plugins', exact=True).first.wait_for(timeout=5000)
    assert _notes(page, 'own').count() == 2
    link = _notes(page, 'own').first.locator('a[data-ha-on-active]')
    assert link.get_attribute('href') == PEER + '/'
    assert 'Save Settings' not in _labels(page)
    own = _notes(page, 'own').first.inner_text()
    shared = _notes(page, 'shared').first.inner_text()
    if serve:
        assert own.startswith('This instance does not save these settings.'), own
        assert 'everything else on the leader' in own, own
        assert 'Change them on the leader; they arrive here with the next sync.' in shared, shared
        assert 'standby' not in (own + shared).lower() and 'active instance' not in own + shared
        assert link.inner_text().strip() == 'Open on the leader'
    else:
        assert own.startswith('A standby does not save these settings.'), own
        assert 'Change them on the active instance' in shared, shared
        assert link.inner_text().strip() == ON_ACTIVE
    assert not app.errors, app.errors



# -- review of the serving members: consoles with the leader away, its lists, the rebuild, words --
#
# A member that serves users opens consoles with its leader away too, so a console entry asks
# what the account holds, not the read-only rule. The lists only the leader keeps (drift, firing
# alerts, the push inbox) answer 503 while it is away, and each view says so in place of the
# list. The HA tab shows a cluster connection rebuild that waits and one that failed, and the
# texts a serving member shows name the leader where a standby's say "the active instance".

def test_the_context_derives_the_serving_flag(ctx):
    assert 'const haServing = haStandby && ha.serving === true;' in ctx
    provider = ctx[ctx.index('<AuthContext.Provider value={{'):]
    provider = provider[:provider.index('}}>')]
    assert re.search(r'\bhaServing\b', provider)


def test_the_serving_flag_answers_as_agreed(ctx):
    import shutil
    import subprocess
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not installed')
    lines = _block(ctx, 'const haStandby = ', 'return(')
    script = """
    const out = [];
    for (const role of ['standalone', 'active', 'standby'])
      for (const serving of [true, false, undefined]) {
        const ha = { role, forwarding: true, serving };
        %s
        out.push([role, String(serving), haServing, haConsolesElsewhere]);
      }
    console.log(JSON.stringify(out));
    """ % lines
    res = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    for role, serving, flag, elsewhere in json.loads(res.stdout):
        assert flag == (role == 'standby' and serving == 'true'), (role, serving)
        # on a standby the two are each other's opposite
        if role == 'standby':
            assert flag != elsewhere


def test_a_console_entry_in_the_menu_asks_what_the_account_holds(dash):
    raw = _block(dash, 'const buildContextMenuItemsRaw = ', 'const buildContextMenuItems = ')
    # the three that open something here: the node shell, the console and SPICE
    shell = raw[raw.index("{ perm: 'node.shell', label: t('sshConsole')"):]
    assert shell[:shell.index('\n')].endswith('disabled: !online, console: true },')
    con = raw[raw.index("{ perm: 'vm.console', label: t('console')"):]
    assert con[:con.index('\n')].endswith('disabled: !isRunning, console: true },')
    spice = raw[raw.index("[{ perm: 'vm.console', label: t('spiceConsole')"):]
    assert spice[:spice.index('\n')].endswith('disabled: !isRunning, console: true }] : []),')
    assert len(re.findall(r'console: true', raw)) == 3
    menu = _block(dash, 'const buildContextMenuItems = ', 'while (out.length')
    assert '.filter(menuAllows);' in menu and 'item.submenu.filter(menuAllows);' in menu
    assert 'can(i.perm)' not in menu
    # only on a member that serves users are they in the menu at all; elsewhere the way to
    # the active stands in their place
    assert "...(haConsolesElsewhere ? onActiveItems('node.shell', '', !online) : [" in raw
    assert "...(haConsolesElsewhere ? onActiveItems('vm.console', haConsoleSearch(vm), !isRunning) : [" in raw


def test_the_leader_only_lists_say_when_the_leader_is_away(ctx, dash):
    helper = _block(ctx, 'async function haLeaderAway(res) {', '\n        }')
    assert "if (!res || res.status !== 503) return false;" in helper
    assert "return !!body && body.code === 'HA_ACTIVE_UNREACHABLE';" in helper
    drift = _function(dash, 'DriftTab')
    assert 'const away = (await haLeaderAway(sr)) || (await haLeaderAway(er));' in drift
    assert 'if (away) { setStatus(null); setEvents([]); return; }' in drift
    assert '}, [clusterId, filter, haReadOnly]);' in drift
    assert drift.index('{leaderAway ? (') < drift.index('events.length === 0 ? (')
    bell = _function(dash, 'PushBellButton')
    assert 'const away = await haLeaderAway(r);' in bell
    assert 'if (away) { setItems([]); setUnread(0); return; }' in bell
    assert '{items.length === 0 && !leaderAway && (' in bell
    alerts = _block(dash, 'const loadActiveAlerts = async (clusterId) => {', 'const ackAlert = ')
    assert 'setActiveAlertsAway(await haLeaderAway(r));' in alerts
    for where in ('drift', 'inbox', 'alerts'):
        at = dash.index(f'data-ha-leader-away="{where}"')
        assert "{t('pgHaLeaderAwayView')}" in dash[at:at + 400], where


def test_the_panel_shows_the_rebuild(panel):
    body = _function(panel, 'HaPanel')
    assert "const reloadPending = standby && sync.reload_pending ? sync.reload_pending : null;" in body
    assert "const lastReload = standby && sync.last_reload && typeof sync.last_reload === 'object' ? sync.last_reload : null;" in body
    card = body[body.index('const liveViewCard = ('):body.index('const forwardCard = (')]
    assert "{lastReload && row(t('pgHaLastReload'), (" in card
    assert '{reloadPending && (' in card and "{t('pgHaReloadPending')}" in card
    assert '{reloadFailed.length > 0 && (' in card and "{t('pgHaReloadFailed')}" in card
    assert '<button onClick={applyNow} disabled={!!busy} className={btnGhost}>' in card
    apply = body[body.index('const applyNow = '):body.index('const WORD = ')]
    assert "if (res.data.restarting) { setRestarting('standby'); return; }" in apply
    assert "addToast?.(t(res.data.reloaded ? 'pgHaReloaded' : 'pgHaNothingToApply'), res.data.reloaded ? 'success' : 'info');" in apply


# what each reworded text no longer claims, in English and German
OLD_CLAIMS = {
    'pgHaRestartPending': {'en': ('connection settings changed', 'restarts on its own'),
                           'de': ('Verbindungsdaten', 'von selbst neu')},
    'pgHaNoClustersHere': {'en': ('read-only',), 'de': ('schreibgeschützt',)},
    'pgHaLiveViewHint': {'en': ('Actions and consoles stay on the active instance',),
                         'de': ('Aktionen und Konsolen bleiben auf der aktiven Instanz',)},
}
SERVING_KEYS = ('pgHaSettingsOnLeader', 'pgHaOwnSettingsOnLeader', 'pgHaOpenOnLeader', 'pgHaServingRefused',
                'pgHaLeaderUnreachable', 'pgHaNoClustersServing', 'pgHaLeaderAwayView', 'pgHaReloadPending',
                'pgHaLastReload', 'pgHaReloadFailed', 'pgHaReloaded', 'pgHaNothingToApply')


def test_the_reworded_and_new_strings():
    blocks = _blocks()
    for key, claims in OLD_CLAIMS.items():
        for lang, words in claims.items():
            line = re.search(r'^ +%s: (.*),$' % key, blocks[lang], re.M).group(1)
            for w in words:
                assert w not in line, (lang, key, w)
    for key in SERVING_KEYS:
        values = []
        for lang, block in blocks.items():
            line = re.search(r'^ +%s: (.*),$' % key, block, re.M)
            assert line, (lang, key)
            assert '\u2014' not in line.group(1), (lang, key)
            values.append(line.group(1))
        # translated, not English copied into every language
        assert len(set(values)) == len(LANGS), key
    # what a serving member shows names the leader and never calls it a standby
    for key in ('pgHaSettingsOnLeader', 'pgHaOwnSettingsOnLeader', 'pgHaServingRefused', 'pgHaLeaderUnreachable',
                'pgHaNoClustersServing'):
        line = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        assert 'leader' in line and 'standby' not in line.lower(), key
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


# -- runtime ------------------------------------------------------------------------------------

def _corp_menu(page, item):
    item.wait_for(timeout=5000)
    item.click(button='right')
    menu = page.locator('.corp-context-menu').first
    menu.wait_for(timeout=3000)
    return menu, [x.strip() for x in menu.inner_text().split('\n') if x.strip()]


def _close_menu(page):
    page.keyboard.press('Escape')
    page.mouse.click(5, 900)
    page.wait_for_function('() => !document.querySelector(".corp-context-menu")', timeout=3000)


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_serving_member_keeps_its_console_entries_with_the_leader_away(open_app, serve):
    """(review) The leader stops answering: nothing is forwarded and can() keeps only the
    reading permissions. A serving member still opens its consoles, as its banner says, so the
    tree menus keep Console, SPICE Console and SSH Console, and Console asks this instance. A
    plain standby (the counterproof) offers the way to the active instead."""
    app = open_app(role='standby', layout='corporate', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS,
                   forward_writes=True, serve_assigned=serve, source_active=False)
    page = app.page
    banner = page.locator('[data-ha-banner="classic"]')
    assert banner.get_attribute('data-ha-forwarding') == 'off'
    assert banner.get_attribute('data-ha-leader') == ('down' if serve else None)
    page.locator('.corp-tree-item', has_text='Testi').first.click()

    _, vm = _corp_menu(page, page.locator('.corp-tree-child', has_text='web01').first)
    assert ({'Console', 'SPICE Console'} <= set(vm)) == serve, vm
    assert not ({'Console', 'SPICE Console'} & set(vm)) == serve, vm
    assert (ON_ACTIVE in vm) != serve, vm
    # nothing that acts comes back with them: the leader is away
    assert not {'Start', 'Shutdown', 'Settings', 'Delete'} & set(vm), vm
    _close_menu(page)

    _, node = _corp_menu(page, page.locator('.corp-tree-child', has_text='pve1').first)
    assert ('SSH Console' in node) == serve, node
    assert (ON_ACTIVE in node) != serve, node
    assert 'Enter Maintenance' not in node, node
    _close_menu(page)

    assert not app.errors, app.errors
    if serve:
        # it opens here: the ticket is asked of this instance (the fake has none to give)
        menu, _ = _corp_menu(page, page.locator('.corp-tree-child', has_text='web01').first)
        menu.get_by_text('Console', exact=True).click()
        assert _wait_for_call(app, ('GET', '/api/clusters/c1/vms/pve1/qemu/100/console'), 5), app.server.calls[-8:]
        assert not [t for t in _toasts(page) if 'active instance' in t], _toasts(page)


VIEWER = ['cluster.view', 'node.view', 'vm.view']


@pytest.mark.parametrize('extra_perms,shown', [(['vm.console', 'node.shell'], True), ([], False)])
def test_runtime_with_the_leader_away_a_console_entry_still_needs_its_permission(open_app, extra_perms, shown):
    """The entries stay for who holds vm.console and node.shell, and only for them: a viewer
    without them (the counterproof) gets none, leader away or not."""
    app = open_app(role='standby', layout='corporate', admin=False, permissions=VIEWER + extra_perms,
                   clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, forward_writes=True,
                   serve_assigned=True, source_active=False)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    _, vm = _corp_menu(page, page.locator('.corp-tree-child', has_text='web01').first)
    assert ({'Console', 'SPICE Console'} <= set(vm)) == shown, vm
    assert not ({'Console', 'SPICE Console'} & set(vm)) == shown, vm
    assert ON_ACTIVE not in vm, vm
    _close_menu(page)
    _, node = _corp_menu(page, page.locator('.corp-tree-child', has_text='pve1').first)
    assert ('SSH Console' in node) == shown, node
    assert not app.errors, app.errors


AWAY_READ = (503, {'code': 'HA_ACTIVE_UNREACHABLE',
                   'error': 'The active instance cannot be reached - act again once it is back, or promote this standby'})
DRIFT_EVENT = {'id': 7, 'cluster_id': 'c1', 'kind': 'vm_config', 'scope': 'qemu/100', 'severity': 'warning',
               'status': 'open', 'detected_at': '2026-09-30T10:00:00', 'diff': []}
INBOX_ITEM = {'id': 3, 'title': 'Disk almost full', 'body': 'pve1 local 91%', 'severity': 'warning',
              'created_at': '2026-09-30T10:00:00', 'read_at': None}
FIRING = {'id': 'f1', 'severity': 'critical', 'message': 'CPU above 90 percent', 'triggered_at': '2026-09-30T10:00:00',
          'escalation_step': 0, 'acked_at': None}
LEADER_LISTS = ('/api/push/inbox', '/api/clusters/c1/drift/status', '/api/clusters/c1/drift/events',
                '/api/clusters/c1/active-alerts')
AWAY_VIEW = 'Only the leader (the active instance) keeps this list, and it does not answer right now.'


def _leader_lists(away):
    # the alert rules and scripts are shared configuration, read from this instance either way
    rules = {('GET', '/api/clusters/c1/alerts'): (200, []), ('GET', '/api/clusters/c1/scripts'): (200, [])}
    if away:
        return {**rules, **{('GET', path): AWAY_READ for path in LEADER_LISTS}}
    return {**rules,
            ('GET', '/api/push/inbox'): (200, {'items': [INBOX_ITEM]}),
            ('GET', '/api/clusters/c1/drift/status'): (200, {'baselines': 3, 'by_kind': {'vm_config': {'warning': 1}}}),
            ('GET', '/api/clusters/c1/drift/events'): (200, {'events': [DRIFT_EVENT]}),
            ('GET', '/api/clusters/c1/active-alerts'): (200, {'active_alerts': [FIRING]})}


@pytest.mark.parametrize('away', [True, False])
def test_runtime_the_lists_only_the_leader_keeps_say_when_it_is_away(open_app, away):
    """(review) Drift, firing alerts and the push inbox are the leader's rows. While a member
    cannot reach it they answer 503, not its own copy: each view says so in place of the list,
    offers no Ack on a row from elsewhere, and no read puts a toast up, however often the bell
    asks. Counterproof: the leader answers, and the rows show with their buttons."""
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   serve_assigned=True, extra={**_leader_lists(away), **SSE_TOKEN})
    page = app.page
    checks = app.server.calls.count(('GET', '/api/auth/check'))

    # the bell asked on load; opening it asks again
    page.locator('button[title="Notifications"]').first.click()
    page.wait_for_timeout(500)
    assert app.server.calls.count(('GET', '/api/push/inbox')) >= 2
    assert (page.locator('[data-ha-leader-away="inbox"]').count() == 1) == away
    assert (page.get_by_text('Disk almost full').count() > 0) != away
    assert page.get_by_text('No notifications yet').count() == 0
    if away:
        assert AWAY_VIEW in page.locator('[data-ha-leader-away="inbox"]').inner_text()
    # the popover's backdrop takes the click and closes it
    page.locator('button[title="Notifications"]').first.click(force=True)
    page.wait_for_timeout(200)

    # drift, under Compliance
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Compliance').first.click()
    page.locator('button', has_text='Drift Detection').first.click()
    page.wait_for_timeout(600)
    assert (page.locator('[data-ha-leader-away="drift"]').count() == 1) == away
    # an empty list would say the cluster matches its baseline: not while nobody knows
    assert page.get_by_text('No open drift events').count() == 0
    assert (page.get_by_text('qemu/100').count() > 0) != away
    assert (page.get_by_role('button', name='Ack', exact=True).count() == 1) != away

    # the firing alerts, under Automation > Alerts
    page.locator('button', has_text='Automation').first.click()
    page.get_by_role('button', name='Alerts', exact=True).first.click()
    page.wait_for_timeout(600)
    assert (page.locator('[data-ha-leader-away="alerts"]').count() == 1) == away
    assert (page.get_by_text('CPU above 90 percent').count() > 0) != away
    for path in LEADER_LISTS:
        assert ('GET', path) in app.server.calls, path

    # no toast for a read, and no burst of banner reads either
    assert not [t for t in _toasts(page) if 'cannot be reached' in t or 'does not answer' in t], _toasts(page)
    assert app.server.calls.count(('GET', '/api/auth/check')) - checks <= 1
    assert not app.errors, app.errors


def test_runtime_drift_reads_again_when_forwarding_comes_back(open_app):
    """The drift list loaded while the leader was away is not kept once it is back: the tab
    reads again when forwarding changes, so an Ack only ever names one of the leader's rows."""
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   serve_assigned=True, source_active=False, extra={**_leader_lists(True), **SSE_TOKEN})
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Compliance').first.click()
    page.locator('button', has_text='Drift Detection').first.click()
    page.locator('[data-ha-leader-away="drift"]').wait_for(timeout=5000)
    assert page.locator('[data-ha-banner="classic"]').get_attribute('data-ha-forwarding') == 'off'
    reads = app.server.calls.count(('GET', '/api/clusters/c1/drift/events'))
    # the leader answers again; "Sync now" reads the banner again, which brings forwarding back
    app.server.extra.update(_leader_lists(False))
    app.server.source_active = True
    _open_ha(app, 'standby')
    page.get_by_role('button', name='Sync now').click()
    page.wait_for_function('() => document.querySelector("[data-ha-banner]")'
                           '.getAttribute("data-ha-forwarding") === "on"', timeout=5000)
    page.keyboard.press('Escape')
    deadline = time.time() + 5
    while time.time() < deadline and page.get_by_text('qemu/100').count() == 0:
        page.wait_for_timeout(100)
    assert app.server.calls.count(('GET', '/api/clusters/c1/drift/events')) > reads
    assert page.locator('[data-ha-leader-away="drift"]').count() == 0
    assert page.get_by_text('qemu/100').count() > 0
    assert page.get_by_role('button', name='Ack', exact=True).count() == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('failed', [['cluster:c2', 'pbs:p1'], []])
def test_runtime_the_panel_shows_a_waiting_and_a_failed_rebuild(open_app, failed):
    """A changed cluster connection is rebuilt in place now: the HA tab says one is waiting,
    when the last ran and what it could not build. Apply now runs a waiting one at once and
    says so. Counterproof: a rebuild that built everything shows no red box."""
    app = open_app(role='standby', layout='modern', forward_writes=True,
                   reload_pending={'since': _iso_ago(4), 'reason': '1 cluster changed'},
                   last_reload={'at': _iso_ago(3600), 'reason': '2 clusters changed', 'failed': failed})
    page = app.page
    panel = _open_ha(app, 'standby')
    card = panel.locator('[data-ha-live-view]')
    waiting = card.locator('[data-ha-reload-pending]')
    assert 'This instance rebuilds them in a few seconds.' in waiting.inner_text()
    assert '1 cluster changed' in waiting.inner_text()
    last = card.locator('[data-ha-last-reload]')
    assert 'hour ago' in last.inner_text() and '2 clusters changed' in last.inner_text(), last.inner_text()
    box = card.locator('[data-ha-reload-failed]')
    assert box.count() == (1 if failed else 0)
    if failed:
        text = box.inner_text()
        assert 'Could not be rebuilt' in text and 'cluster:c2' in text and 'pbs:p1' in text, text
    # nothing waits for a restart: the restart note stays away
    assert panel.locator('[data-ha-restart-pending]').count() == 0

    waiting.get_by_role('button', name='Apply now').click()
    assert _wait_for_toast(page, 'The cluster connections were rebuilt with the latest settings.'), _toasts(page)
    assert app.server.calls.count(('POST', '/api/ha/apply-config')) == 1
    assert page.get_by_text('Restarting PegaProx...').count() == 0
    card.locator('[data-ha-reload-pending]').wait_for(state='detached', timeout=5000)
    assert card.locator('[data-ha-reload-failed]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_rebuild_that_already_ran_says_so(open_app):
    """The rebuild ran on its own between the last poll and the click: Apply now says that
    nothing waits, instead of nothing at all."""
    app = open_app(role='standby', layout='modern', reload_pending={'since': _iso_ago(9), 'reason': '1 cluster changed'})
    page = app.page
    panel = _open_ha(app, 'standby')
    waiting = panel.locator('[data-ha-reload-pending]')
    waiting.wait_for(timeout=5000)
    app.server.reload_pending = None
    waiting.get_by_role('button', name='Apply now').click()
    assert _wait_for_toast(page, 'Nothing is waiting to be applied.'), _toasts(page)
    waiting.wait_for(state='detached', timeout=5000)
    assert panel.locator('[data-ha-last-reload]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_standby_with_nothing_rebuilt_shows_no_rebuild(open_app):
    app = open_app(role='standby', layout='modern')
    panel = _open_ha(app, 'standby')
    for what in ('[data-ha-last-reload]', '[data-ha-reload-pending]', '[data-ha-reload-failed]'):
        assert panel.locator(what).count() == 0, what
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_refusal_on_a_serving_member_names_the_leader(open_app, serve):
    """A change a member cannot carry out (409): on a serving member it is not possible here
    and is made on the leader, a plain standby keeps its words (the counterproof)."""
    refused = {('POST', '/api/clusters/c1/vms/pve1/qemu/100/shutdown'):
               (409, {'code': 'HA_STANDBY', 'error': 'This is a standby instance.'})}
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   serve_assigned=serve, extra={**refused, **SSE_TOKEN})
    page = app.page
    page.on('dialog', lambda d: d.accept())
    _open_resources(app)
    page.locator('button[title="Shutdown"]').first.click()
    words = ('This change cannot be made on this instance. Make it on the leader; it arrives here with the next sync.'
             if serve else REFUSED['en'])
    assert _wait_for_toast(page, words), _toasts(page)
    page.wait_for_timeout(400)
    assert len([t for t in _toasts(page) if words in t]) == 1
    if serve:
        assert not [t for t in _toasts(page) if 'standby' in t.lower()], _toasts(page)
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_the_leader_out_of_reach_on_a_serving_member(open_app, serve):
    """503 for a change: on a serving member the leader does not answer, changes are paused,
    promote a member; a plain forwarding standby keeps its own words (the counterproof)."""
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   serve_assigned=serve, active_down=True, extra=SSE_TOKEN)
    page = app.page
    page.on('dialog', lambda d: d.accept())
    _open_resources(app)
    page.locator('button[title="Shutdown"]').first.click()
    words = ('The leader does not answer, so changes are paused. Try again once it is back, or promote a member '
             'under High Availability.' if serve else UNREACHABLE['en'])
    assert _wait_for_toast(page, words), _toasts(page)
    page.wait_for_timeout(400)
    assert len([t for t in _toasts(page) if words in t]) == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_an_empty_list_on_a_serving_member(open_app, serve):
    app = open_app(role='standby', layout='modern', forward_writes=True, serve_assigned=serve)
    page = app.page
    words = ('The clusters of the leader appear here after the next sync.' if serve
             else 'This is a standby instance. Its clusters appear here after the next sync.')
    app.see(words)
    assert page.get_by_text(words).count() == 2
    assert page.get_by_text('read-only, after the next sync').count() == 0
    panel = _open_ha(app, 'standby')
    hint = panel.locator('[data-ha-live-view]').inner_text()
    assert 'consoles open here when this instance serves users' in hint, hint
    assert 'Actions and consoles stay on the active instance' not in hint
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_cloud_keeps_the_consoles_of_a_serving_member_with_the_leader_away(open_app, serve):
    """Cloud hands its shell the console handlers by the console flag alone, so with the
    leader away a serving member keeps Console and SPICE there too, and nothing that acts.
    A plain standby (the counterproof) offers the way to the active."""
    app = open_app(role='standby', layout='cloud', clusters=[CLUSTER], resources=[VM], forward_writes=True,
                   serve_assigned=serve, source_active=False)
    page = app.page
    assert page.locator('[data-ha-banner="cloud"]').get_attribute('data-ha-forwarding') == 'off'
    page.get_by_text('Virtual Machines').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.get_by_text('web01').first.click()
    bar = page.locator('.cloud-detail-actions')
    bar.wait_for(timeout=3000)
    text = bar.inner_text()
    assert 'Shutdown' not in text, text
    assert ('SPICE' in text) == serve, text
    assert bar.locator('a[data-ha-on-active]').count() == (0 if serve else 1)
    page.locator('.cloud-detail-actions button', has_text='Actions').click()
    page.wait_for_timeout(300)
    menu = page.evaluate('() => Array.from(document.querySelectorAll("[role=menu], .cloud-menu"))'
                         '.map(m => m.innerText).join("\\n")').split('\n')
    menu = [x.strip() for x in menu if x.strip()]
    assert ('Console' in menu) == serve, menu
    assert (ON_ACTIVE in menu) != serve, menu
    assert not {'Start', 'Shutdown', 'Migrate', 'Delete'} & set(menu), menu
    assert not app.errors, app.errors


# -- the three kinds of instance in the HA tab (#625) ------------------------------------------
#
# A group has one leader (the automation and the configuration), members that serve users as
# active instances (consoles there, the leader carries out their changes) and plain standbys
# that wait to take over. The tab says which one this is and calls an instance read-only only
# where it is: no forwarding, or the leader does not answer. A serving member is an active
# instance to its users already, so its promote makes it the leader.

ROLE_DESC = {
    'leader': ('This instance is the leader: it holds the configuration the others copy and carries out '
               'the changes they hand it.'),
    'serving': ('This instance serves users as an active instance: consoles open here, and the leader carries '
                'out every change.'),
    'standby': 'This instance is a plain standby: it copies the configuration of the leader and waits to take over.',
}
AUTOMATION = 'Automation such as HA, balancing, schedules and alerts runs only on the leader.'
INTRO = ('Run up to four PegaProx instances as one group. One is the leader: it runs the automation and holds '
         'the configuration, which the others copy.')
# what the old texts said about every standby, in each language
READ_ONLY = {'de': ('schreibgeschützt', 'nur lesend'), 'en': ('read-only', 'read only'), 'zh': ('只读',),
             'pl': ('tylko do odczytu', 'tylko odczyt'), 'fr': ('lecture seule',), 'es': ('solo lectura',),
             'pt': ('somente leitura', 'somente para leitura'), 'ko': ('읽기 전용',), 'it': ('sola lettura',)}
KIND_KEYS = ('pgHaRoleDescLeader', 'pgHaRoleDescActive', 'pgHaRoleDescStandby', 'pgHaForwardPausedServing',
             'pgHaManagersServing', 'pgHaPromoteLeader', 'pgHaPromoteLeaderDesc', 'pgHaPromoteLeaderSyncFailed')
KIND_REWORDED = ('pgHaIntro', 'pgHaLiveView', 'pgHaLiveViewHint', 'pgHaLiveViewSaved', 'pgHaForwardWrites',
                 'pgHaForwardWritesHint', 'pgHaForwardOn', 'pgHaForwardOff', 'pgHaJoinWarning')


def _value(block, key):
    return re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)


def test_the_panel_says_what_each_kind_is(panel):
    body = _function(panel, 'HaPanel')
    assert "const serving = role === 'standby' && status?.serving === true;" in body
    at = body.index('const roleDesc = ')
    desc = body[at:body.index('return (', at)]
    assert "role === 'active' ? t('pgHaRoleDescLeader')" in desc
    assert ": serving ? t('pgHaRoleDescActive')" in desc
    # a removed member waits for nothing
    assert ": role === 'standby' && !status.removed ? t('pgHaRoleDescStandby') : '';" in desc
    assert "data-ha-automation={serving ? 'serving' : role}" in body
    assert "{roleDesc ? `${roleDesc} ${t('pgHaAutomationLeader')}` : t('pgHaAutomationLeader')}" in body


def test_a_serving_member_gets_its_own_words_in_the_tab(panel):
    body = _function(panel, 'HaPanel')
    live = body[body.index('const liveViewCard = ('):body.index('const forwardCard = (')]
    assert "t(serving ? 'pgHaManagersServing' : 'pgHaManagersRunning')" in live
    box = body[body.index('const typedBox = '):body.index('const removalNote = ')]
    assert "(serving ? t('pgHaPromoteLeaderDesc') : `${t('pgHaPromoteDesc')} ${t('pgHaPromoteSyncFirst')}`)" in box
    assert "t(serving ? 'pgHaPromoteLeaderSyncFailed' : 'pgHaPromoteSyncFailed')" in box
    assert "confirmAction === 'promote' ? t(serving ? 'pgHaPromoteLeader' : 'pgHaPromote')" in box
    standby = body[body.index("{role === 'standby' && ("):]
    assert "{t(serving ? 'pgHaPromoteLeader' : 'pgHaPromote')}" in standby


def test_the_words_for_the_three_kinds():
    blocks = _blocks()
    for key in KIND_KEYS + KIND_REWORDED:
        values = [_value(blocks[lang], key) for lang in LANGS]
        for lang, value in zip(LANGS, values):
            assert '\u2014' not in value, (lang, key)
        # translated, not English copied over; Spanish and Portuguese share "Promover a líder"
        assert len(set(values)) >= len(LANGS) - 1, key
    # read-only only where it is: never for the group as a whole, a joining instance, the card
    # title, the role lines or what a serving member is told. The live view hint and a plain
    # standby's paused note keep it, each with its condition
    for lang, block in blocks.items():
        for key in ('pgHaIntro', 'pgHaLiveView', 'pgHaJoinWarning', 'pgHaRoleDescLeader', 'pgHaRoleDescActive',
                    'pgHaRoleDescStandby', 'pgHaForwardPausedServing', 'pgHaManagersServing', 'pgHaActiveHint',
                    'pgHaPromoteLeaderDesc', 'pgHaForwardOn', 'pgHaAssignedOn', 'pgHaMemberServeOn'):
            value = _value(block, key)
            assert not any(w in value for w in READ_ONLY[lang]), (lang, key, value)
        for key in ('pgHaLiveViewHint', 'pgHaForwardPaused', 'pgHaManagersRunning'):
            assert any(w in _value(block, key) for w in READ_ONLY[lang]), (lang, key)
    en = blocks['en']
    intro = _value(en, 'pgHaIntro')
    for words in ('the leader', 'serve users as active instances', 'plain standbys'):
        assert words in intro, words
    hint = _value(en, 'pgHaLiveViewHint')
    assert 'read-only without forwarding or while the leader does not answer' in hint, hint
    assert 'While the leader does not answer, changes are paused' in _value(en, 'pgHaForwardWritesHint')
    for key in ('pgHaForwardWrites', 'pgHaForwardWritesHint', 'pgHaForwardOn', 'pgHaPromoteLeader'):
        value = _value(en, key)
        assert 'leader' in value and 'active instance' not in value, key
    assert _value(en, 'pgHaPromoteLeader') == "'Promote to leader'"
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


# -- runtime ------------------------------------------------------------------------------------

def _kind_app(open_app, kind, **kw):
    if kind == 'leader':
        app = open_app(role='active', layout='modern', **kw)
        return app, _open_ha(app, 'active')
    app = open_app(role='standby', layout='modern', forward_writes=True, serve_assigned=kind == 'serving', **kw)
    return app, _open_ha(app, 'standby')


@pytest.mark.parametrize('kind', ['leader', 'serving', 'standby'])
def test_runtime_the_tab_says_what_each_kind_is(open_app, kind):
    """The intro is the same on every member and names all three kinds; the line below it says
    which one this is. Each kind is the counterproof of the other two."""
    app, panel = _kind_app(open_app, kind)
    text = panel.inner_text()
    assert INTRO in text, text
    assert 'show the clusters read-only while they wait' not in text
    line = panel.locator('[data-ha-automation]')
    assert line.get_attribute('data-ha-automation') == {'leader': 'active'}.get(kind, kind)
    assert line.inner_text().strip() == f'{ROLE_DESC[kind]} {AUTOMATION}'
    for other, words in ROLE_DESC.items():
        assert (words in text) == (other == kind), other
    # the cards name the leader on every kind, and the live view title no longer says read only
    assert app.page.get_by_role('switch', name='Connect to the clusters while following the leader').count() == 1
    assert app.page.get_by_role('switch', name='Carry out changes through the leader').count() == 1
    assert '(read only)' not in text
    assert not app.errors, app.errors


def test_runtime_a_removed_member_is_not_said_to_wait(open_app):
    app = open_app(role='standby', layout='modern', members=[])
    app.server.removed = {'epoch': 3, 'at': _iso_ago(300), 'by': 'd' * 32}
    panel = _open_ha(app, 'standby')
    panel.locator('[data-ha-removed]').wait_for(timeout=5000)
    assert panel.locator('[data-ha-automation]').inner_text().strip() == AUTOMATION
    assert ROLE_DESC['standby'] not in panel.inner_text()
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_serving_member_is_not_called_read_only(open_app, serve):
    """The leader answers. A serving member opens consoles over its cluster connections, so the
    tab does not call them read only; a plain standby (the counterproof) keeps the words."""
    app, panel = _kind_app(open_app, 'serving' if serve else 'standby')
    live = panel.locator('[data-ha-live-view]').inner_text()
    assert ('Connected, consoles open here' in live) == serve, live
    assert ('Connected, read only' in live) != serve, live
    assert panel.locator('[data-ha-forward-paused]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_with_the_leader_away_a_serving_member_only_pauses_changes(open_app, serve):
    """The leader does not answer. A serving member's changes wait, its consoles do not; a plain
    standby (the counterproof) is read-only until it answers again."""
    app, panel = _kind_app(open_app, 'serving' if serve else 'standby', source_active=False)
    paused = panel.locator('[data-ha-forward-paused]')
    assert paused.get_attribute('data-ha-forward-paused') == ('serving' if serve else 'standby')
    text = paused.inner_text()
    assert ('The leader does not answer right now: changes are paused until it does, live data and consoles '
            'keep working here.' in text) == serve, text
    assert ('this standby is read-only' in text) != serve, text
    assert ('Connected, consoles open here' in panel.locator('[data-ha-live-view]').inner_text()) == serve
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_serving_member_promotes_to_leader(open_app, serve):
    """Same request, other words: a serving member is promoted to leader, a plain standby (the
    counterproof) still to active."""
    app, panel = _kind_app(open_app, 'serving' if serve else 'standby')
    page = app.page
    label, other = ('Promote to leader', 'Promote to active') if serve else ('Promote to active', 'Promote to leader')
    assert panel.locator('button', has_text=other).count() == 0
    panel.get_by_role('button', name=label).click()
    box = panel.locator('[data-ha-confirm="promote"]')
    text = box.inner_text()
    assert ('This instance then becomes the leader' in text) == serve, text
    assert ('The current leader steps down as soon as it sees this one.' in text) == serve, text
    assert ('The old active instance steps down to standby' in text) != serve, text
    assert ('If the active instance still answers' in text) != serve, text
    page.fill('#pgha-typed', 'PROMOTE')
    page.fill('#pgha-confirm-password', PASSWORD)
    box.locator('button', has_text=label).click()
    app.see('Restarting PegaProx...', timeout=3000)
    assert app.server.bodies['/api/ha/promote'] == [{'confirm': 'PROMOTE', 'user_password': PASSWORD}]
    assert not app.errors, app.errors


@pytest.mark.parametrize('serve', [True, False])
def test_runtime_a_failed_pull_before_promoting_names_the_leader(open_app, serve):
    refused = {('POST', '/api/ha/promote'): (409, {'code': 'HA_PROMOTE_SYNC',
                                                   'error': 'Could not pull the latest configuration'})}
    app, panel = _kind_app(open_app, 'serving' if serve else 'standby', extra=refused)
    page = app.page
    label = 'Promote to leader' if serve else 'Promote to active'
    panel.get_by_role('button', name=label).click()
    page.fill('#pgha-typed', 'PROMOTE')
    page.fill('#pgha-confirm-password', PASSWORD)
    panel.locator('[data-ha-confirm="promote"] button', has_text=label).click()
    note = panel.locator('[data-ha-promote-sync]')
    note.wait_for(timeout=3000)
    text = note.inner_text()
    assert ('The leader answers, but its latest configuration could not be fetched.' in text) == serve, text
    assert ('The active instance answers' in text) != serve, text
    assert 'Promote anyway, without the latest configuration' in text
    assert not app.errors, app.errors


def test_runtime_a_serving_member_speaks_german(open_app):
    app = open_app(role='standby', layout='modern', language='de', forward_writes=True, serve_assigned=True)
    app.page.locator('[data-ha-banner="classic"]').get_by_role('button', name='Hochverfügbarkeit').click()
    panel = app.page.locator('[data-ha-role="standby"]')
    panel.wait_for(timeout=5000)
    line = panel.locator('[data-ha-automation]').inner_text()
    assert line.startswith('Diese Instanz bedient Benutzer als aktive Instanz: Konsolen öffnen sich hier'), line
    assert panel.get_by_role('button', name='Zum Leader hochstufen').count() == 1
    assert 'Verbunden, Konsolen öffnen sich hier' in panel.inner_text()
    assert not app.errors, app.errors


# -- who is active is set on the leader (#625, v8) ----------------------------------------------
#
# Up to three instances of a group are active: the leader and at most two members, so the 4th
# member always stays a standby. The leader's tab sets it per member (PUT /api/ha/members/<id>/serve)
# and every member gets serve with the member list. A member's tab only shows what the leader made
# it (serve_assigned); it serves from its next sync, with its live view and forwarding on, and
# says so in serving_seen. The per-instance switch of v6 is gone.

CENTRAL_KEYS = ('pgHaActiveCount', 'pgHaActiveHint', 'pgHaActiveLimit', 'pgHaServeMember', 'pgHaMemberServeOn',
                'pgHaMemberServeOff', 'pgHaRoleActivePending', 'pgHaRoleActivePendingHint', 'pgHaAssignedTitle',
                'pgHaAssignedOn', 'pgHaAssignedOff', 'pgHaAssignedNeeds', 'pgHaAssignedHint')
OLD_SERVE_KEYS = ('pgHaServeUsers', 'pgHaServeUsersHint', 'pgHaServeNeeds', 'pgHaServeOn', 'pgHaServeOff')
LIMIT_HINT = 'At most 3 active instances, the leader included. Every other member stays a standby.'
ASSIGNED_HINT = 'Which instances are active is set on the leader, under High Availability.'


def test_the_leader_sets_who_is_active(panel):
    body = _function(panel, 'HaPanel')
    assert 'const activeLimit = status?.active_limit || 3;' in body
    assert 'const activesFull = actives >= activeLimit;' in body
    save = _block(body, 'const setMemberServe = (m, on) =>', 'const applyNow = ')
    assert "send('PUT', `members/${encodeURIComponent(m.instance_id)}/serve`, { serve: on })" in save
    # HA_ACTIVE_LIMIT and every other refusal: the server's words, then the real count
    assert "if (!res.ok) { addToast?.(res.error, 'error'); load(); return; }" in save
    assert "t(serve ? 'pgHaMemberServeOn' : 'pgHaMemberServeOff').replace('{name}', () => memberName(m))" in save
    assert "const canSetActive = role === 'active';" in body
    card = _block(body, 'const membersCard = (', 'const intervalCard = (')
    # one switch per row, only on the leader; a standby is locked at the limit, off always works
    at = card.index('onClick={() => setMemberServe(m, m.serve !== true)}')
    gate = card.rindex('{canSetActive && (', 0, at)
    toggle = card[gate:card.index('</td>', at)]
    assert card.index('{members.map(m => (') < gate
    assert 'role="switch" aria-checked={m.serve === true}' in toggle
    assert 'disabled={!!busy || broken || (activesFull && m.serve !== true)}' in toggle
    assert card.count('setMemberServe(') == 1
    assert '{activesFull && (' in card and "t('pgHaActiveLimit').replace('{max}', () => activeLimit)" in card
    assert ('<HaRoleBadge role={memberRole(m)} serving={m.serve === true} pending={m.serving_seen !== true} t={t} />'
            in card)


def test_a_member_shows_what_the_leader_made_it(panel):
    body = _function(panel, 'HaPanel')
    assert 'const assigned = status?.serve_assigned === true;' in body
    assert 'const assignedIdle = assigned && (!liveView || !forwardWrites);' in body
    card = _block(body, 'const assignedCard = ', 'const restartNote = ')
    # read only: nothing in it switches, saves or sends
    for needle in ('<button', '<input', 'role="switch"', 'onClick', 'send('):
        assert needle not in card, needle
    assert "{t(assigned ? 'pgHaAssignedOn' : 'pgHaAssignedOff')}" in card
    assert '{assignedIdle && (' in card and "{t('pgHaAssignedNeeds')}" in card
    assert "{t('pgHaAssignedHint')}" in card
    # only on a member, next to the two it needs
    assert body.count('{assignedCard}') == 1
    assert '{forwardCard}\n                                {assignedCard}' in body[body.index("{role === 'standby' && ("):]


def test_the_member_badge_answers_as_agreed(panel):
    """memberRole and the badge's choice as they are in the source, run in node over every
    combination of what the member said and what the leader set."""
    import shutil
    import subprocess
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not installed')
    role_line = _block(_function(panel, 'HaPanel'), 'const memberRole = ', '\n')
    shown_line = _block(_function(panel, 'HaRoleBadge'), 'const shown = ', '\n')
    script = """
    %s
    const out = [];
    for (const role_seen of ['active', 'standby', 'standalone', undefined])
      for (const serve of [true, false, undefined])
        for (const serving_seen of [true, false, undefined]) {
          const m = { role_seen, serve, serving_seen };
          const role = memberRole(m);
          const kind = role ? (() => {
            const serving = m.serve === true, pending = m.serving_seen !== true;
            %s
            return shown;
          })() : '-';
          out.push([String(role_seen), String(serve), String(serving_seen), kind]);
        }
    console.log(JSON.stringify(out));
    """ % (role_line, shown_line)
    res = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    for role_seen, serve, serving_seen, kind in json.loads(res.stdout):
        if role_seen == 'active':
            want = 'active'                                  # the leader, whatever else it says
        elif serve == 'true':
            want = 'serving' if serving_seen == 'true' else 'pending'
        else:
            want = {'standby': 'standby', 'standalone': 'standalone'}.get(role_seen, '-')
        assert kind == want, (role_seen, serve, serving_seen, kind)


def test_the_central_strings():
    blocks = _blocks()
    for key in CENTRAL_KEYS + ('pgHaGroupFull',):
        values = [_value(blocks[lang], key) for lang in LANGS]
        for lang, value in zip(LANGS, values):
            assert '\u2014' not in value, (lang, key)
        # translated, not English copied over
        assert len(set(values)) >= len(LANGS) - 1, key
    for lang, block in blocks.items():
        for key in OLD_SERVE_KEYS:
            assert not re.search(r'^ +%s: ' % key, block, re.M), (lang, key)
    en = blocks['en']
    assert _value(en, 'pgHaActiveLimit') == ("'At most {max} active instances, the leader included. "
                                             "Every other member stays a standby.'")
    assert _value(en, 'pgHaAssignedHint') == "'%s'" % ASSIGNED_HINT
    # a full group has the leader in it, not "one of them active" any more
    assert 'one of them active' not in _value(en, 'pgHaGroupFull')
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


# -- runtime ------------------------------------------------------------------------------------

def _serve_switch(card, ch):
    return card.get_by_role('switch', name=f'Active instance: https://pegaprox-{ch}.example:5000')


def _serve_path(ch):
    return f'/api/ha/members/{ch * 32}/serve'


def _until(page, fn, seconds=5):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if fn():
            return True
        page.wait_for_timeout(100)
    return fn()


@pytest.mark.parametrize('n', [0, 1, 2])
def test_runtime_the_leader_sees_who_is_active(open_app, n):
    """The leader with 0, 1 or 2 active members: the count, the switches, the words. At the
    limit, the leader and two members, the 4th member's switch is off and locked with the hint;
    below it nothing is locked (each n the counterproof of the others)."""
    members = [_member(ch, serve=i < n, serving_seen=i < n) for i, ch in enumerate('bcd')]
    app = open_app(role='active', layout='modern', members=members)
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-members]')
    assert card.locator('[data-ha-actives]').inner_text().strip() == f'{n + 1} of 3 active'
    assert panel.locator('[data-ha-badge]').first.inner_text().strip() == LEADER
    for i, ch in enumerate('bcd'):
        switch = _serve_switch(card, ch)
        assert switch.get_attribute('aria-checked') == ('true' if i < n else 'false'), ch
        locked = n == 2 and i >= n
        assert switch.is_disabled() == locked, ch
        assert (switch.get_attribute('title') == LIMIT_HINT) == locked, ch
        assert _seen(card, ch) == ('Active' if i < n else 'Standby'), ch
    limit = card.locator('[data-ha-active-limit]')
    assert limit.count() == (1 if n == 2 else 0)
    if n == 2:
        assert limit.inner_text().strip() == LIMIT_HINT
    assert 'An active member serves users as the leader does' in card.inner_text()
    assert not [c for c in app.server.calls if c[1].endswith('/serve')]
    assert not app.errors, app.errors


def test_runtime_the_leader_makes_members_active_up_to_the_limit(open_app):
    """Two members made active one after the other: pending until each says it serves, then the
    4th is locked and a click on it sends nothing. Switching one off always works and frees the
    place for the 4th."""
    app = open_app(role='active', layout='modern', members=[_member(ch) for ch in 'bcd'])
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-members]')
    actives = card.locator('[data-ha-actives]')

    _serve_switch(card, 'b').click()
    assert _wait_for_toast(page, 'Saved. https://pegaprox-b.example:5000 serves users as an active instance '
                                 'from its next sync.'), _toasts(page)
    assert app.server.bodies[_serve_path('b')] == [{'serve': True}]
    assert _until(page, lambda: _serve_switch(card, 'b').get_attribute('aria-checked') == 'true')
    assert _until(page, lambda: actives.inner_text().strip() == '2 of 3 active'), actives.inner_text()
    # made active, the member has not said yet that it serves
    assert _seen(card, 'b') == 'Active (pending)'
    app.server.members[0]['serving_seen'] = True
    _reload_status(app)
    assert _until(page, lambda: _seen(card, 'b') == 'Active'), _seen(card, 'b')
    assert not _serve_switch(card, 'd').is_disabled()

    _serve_switch(card, 'c').click()
    assert _wait_for_toast(page, 'Saved. https://pegaprox-c.example:5000 serves users as an active instance '
                                 'from its next sync.'), _toasts(page)
    assert _until(page, lambda: actives.inner_text().strip() == '3 of 3 active'), actives.inner_text()
    assert _until(page, lambda: _serve_switch(card, 'd').is_disabled())
    assert card.locator('[data-ha-active-limit]').inner_text().strip() == LIMIT_HINT
    # the active ones stay switchable, the locked one sends nothing
    assert not _serve_switch(card, 'b').is_disabled() and not _serve_switch(card, 'c').is_disabled()
    _serve_switch(card, 'd').click(force=True)
    page.wait_for_timeout(400)
    assert _serve_path('d') not in app.server.bodies

    _serve_switch(card, 'b').click()
    assert _wait_for_toast(page, 'Saved. https://pegaprox-b.example:5000 is a standby again from its next sync.'), \
        _toasts(page)
    assert app.server.bodies[_serve_path('b')] == [{'serve': True}, {'serve': False}]
    assert _until(page, lambda: not _serve_switch(card, 'd').is_disabled())
    assert actives.inner_text().strip() == '2 of 3 active'
    assert card.locator('[data-ha-active-limit]').count() == 0
    assert _seen(card, 'b') == 'Standby'
    _serve_switch(card, 'd').click()
    assert _until(page, lambda: _serve_switch(card, 'd').get_attribute('aria-checked') == 'true')
    assert [m.get('serve') for m in app.server.members] == [False, True, True]
    # nothing went to the per-instance settings route
    assert not [b for b in app.server.bodies.get('/api/ha/settings', []) if 'serve_users' in b]
    assert not app.errors, app.errors


def test_runtime_the_leader_refusing_the_limit_shows_its_words(open_app):
    """Another admin made a member active since this page last looked: the switch still looked
    free, the server refuses with HA_ACTIVE_LIMIT. The toast carries the server's words, the
    switch stays off and the page reads the real count."""
    members = [_member('b', serve=True, serving_seen=True), _member('c'), _member('d')]
    app = open_app(role='active', layout='modern', members=members)
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-members]')
    assert card.locator('[data-ha-actives]').inner_text().strip() == '2 of 3 active'
    app.server.members[1]['serve'] = True
    _serve_switch(card, 'd').click()
    assert _wait_for_toast(page, LIMIT_REFUSED), _toasts(page)
    assert not any('The action failed' in t for t in _toasts(page))
    assert app.server.bodies[_serve_path('d')] == [{'serve': True}]
    assert app.server.members[2].get('serve') is not True
    assert _until(page, lambda: _serve_switch(card, 'd').is_disabled())
    assert _serve_switch(card, 'd').get_attribute('aria-checked') == 'false'
    assert _serve_switch(card, 'c').get_attribute('aria-checked') == 'true'
    assert card.locator('[data-ha-actives]').inner_text().strip() == '3 of 3 active'
    assert card.locator('[data-ha-active-limit]').count() == 1
    assert not app.errors, app.errors


def test_runtime_the_leader_speaks_german_about_who_is_active(open_app):
    app = open_app(role='active', layout='modern', language='de',
                   members=[_member('b', serve=True), _member('c', serve=True, serving_seen=True), _member('d')])
    # open_settings waits for the English title
    app.page.locator('body').click(position={'x': 5, 'y': 400})
    app.page.keyboard.press('g')
    app.page.keyboard.press(',')
    app.page.get_by_text('PegaProx Einstellungen').first.wait_for(timeout=5000)
    app.page.locator('button', has_text='Hochverfügbarkeit').first.click()
    card = app.page.locator('[data-ha-role="active"] [data-ha-members]')
    card.wait_for(timeout=5000)
    assert card.locator('[data-ha-actives]').inner_text().strip() == '3 von 3 aktiv'
    assert _seen(card, 'b') == 'Aktiv (ausstehend)' and _seen(card, 'c') == 'Aktiv'
    assert card.locator('[data-ha-active-limit]').inner_text().strip() == (
        'Höchstens 3 aktive Instanzen, der Leader eingeschlossen. Jedes weitere Mitglied bleibt ein Standby.')
    assert card.get_by_role('switch', name='Aktive Instanz: https://pegaprox-d.example:5000').is_disabled()
    assert not app.errors, app.errors


@pytest.mark.parametrize('assigned,live,forward', [(True, True, True), (False, True, True),
                                                   (True, False, True), (True, True, False)])
def test_runtime_a_member_shows_what_the_leader_made_it(open_app, assigned, live, forward):
    """Read only on the member, with the hint where it is set. Made active, it serves only with
    the live view and forwarding on, and says so when one of them is off; not made active (the
    counterproof) it is a standby whatever the two say."""
    app = open_app(role='standby', layout='modern', live_view=live, forward_writes=forward, serve_assigned=assigned,
                   members=[_member('b', role='active', source=True)])
    page = app.page
    banner = page.locator('[data-ha-banner="classic"]')
    panel = _open_ha(app, 'standby')
    serving = assigned and live and forward
    card = panel.locator('[data-ha-assigned]')
    assert card.get_attribute('data-ha-assigned') == ('on' if assigned else 'off')
    text = card.inner_text()
    assert text.startswith('Active instance'), text
    assert ('The leader made this instance active: users work here as on the leader' in text) == assigned, text
    assert ('The leader keeps this instance a standby.' in text) != assigned, text
    assert ASSIGNED_HINT in text
    # nothing to switch here, not even the old switch
    assert card.locator('button, input, [role="switch"]').count() == 0
    assert page.get_by_role('switch', name=SERVE_SWITCH).count() == 0
    # with the two it needs, which stay where they were
    assert page.get_by_role('switch', name='Connect to the clusters while following the leader').count() == 1
    assert page.get_by_role('switch', name='Carry out changes through the leader').count() == 1
    assert page.evaluate('() => document.querySelector("[data-ha-assigned]").closest(".grid") === '
                         'document.getElementById("pgha-forward").closest(".grid")')
    idle = card.locator('[data-ha-serve-idle]')
    assert idle.count() == (1 if assigned and not (live and forward) else 0)
    if idle.count():
        assert idle.inner_text().strip() == ('Not serving users right now: an active instance needs both the live '
                                             'view and forwarding on, and one of them is off here.')
    assert panel.locator('[data-ha-badge]').first.inner_text().strip() == ('Active' if serving else 'Standby')
    assert banner.get_attribute('data-ha-serving') == ('on' if serving else 'off')
    assert not app.errors, app.errors


def test_runtime_a_member_follows_the_leader_at_its_next_sync(open_app):
    """The leader makes this member active, later a standby again: the next sync brings it, the
    card, the badge and the banner follow without a restart."""
    app = open_app(role='standby', layout='modern', forward_writes=True,
                   members=[_member('b', role='active', source=True)])
    page = app.page
    banner = page.locator('[data-ha-banner="classic"]')
    panel = _open_ha(app, 'standby')
    card = panel.locator('[data-ha-assigned]')
    badge = panel.locator('[data-ha-badge]').first
    assert card.get_attribute('data-ha-assigned') == 'off' and badge.inner_text().strip() == 'Standby'
    for on in (True, False):
        app.server.serve_assigned = on
        panel.get_by_role('button', name='Sync now').click()
        want = 'on' if on else 'off'
        assert _until(page, lambda: card.get_attribute('data-ha-assigned') == want), want
        assert _until(page, lambda: badge.inner_text().strip() == ('Active' if on else 'Standby'))
        assert _until(page, lambda: banner.get_attribute('data-ha-serving') == want), want
        assert ('Active instance. Automation (HA, balancing, schedules) runs on the leader '
                'https://pegaprox-b.example:5000' in banner.inner_text()) == on
    assert page.locator('[role="alertdialog"]').count() == 0
    assert len(app.loads) == 1
    assert not app.errors, app.errors


def test_runtime_a_removed_member_shows_no_assignment(open_app):
    """Removed, a member serves nobody and waits for an unpair: no card about being active."""
    app = open_app(role='standby', layout='modern', forward_writes=True, serve_assigned=True, members=[])
    app.server.removed = {'epoch': 3, 'at': _iso_ago(300), 'by': 'd' * 32}
    panel = _open_ha(app, 'standby')
    panel.locator('[data-ha-removed]').wait_for(timeout=5000)
    assert panel.locator('[data-ha-assigned]').count() == 0
    assert panel.locator('[data-ha-badge]').first.inner_text().strip() == 'Standby'
    assert not app.errors, app.errors
