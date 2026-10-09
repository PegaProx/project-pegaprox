"""Where Automated Installations lives in the three layouts.

The feature moved out of the Settings modal into a global view of its own: a sidebar
entry next to World Map (Modern and Corporate), and an item under INFRASTRUCTURE in
Cloud. A global view in dashboard.js is a boolean flag, and every sibling has to clear
it by hand. Miss one handler and two entries are lit at once, or the page you clicked
away from keeps rendering. That is exactly how All Clusters stayed highlighted next to
World Map and EVPN before, so these read the source and hold the wiring together.

Visibility runs off the server-computed `autoinstall_access`, not can('autoinstall.view'):
the routes also turn away tenant- and cluster-confined callers, and can() cannot see that.
LW
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH = os.path.join(ROOT, 'web', 'src', 'dashboard.js')
CLOUD = os.path.join(ROOT, 'web', 'src', 'cloud.js')
VM_MODALS = os.path.join(ROOT, 'web', 'src', 'vm_modals.js')

# Guests: All Guests, the guest table of every cluster
FLAGS = ['Topology', 'Worldmap', 'XHM', 'MultiSdn', 'Guests', 'AutoInstall']


def _read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


@pytest.fixture(scope='module')
def dash():
    return _read(DASH)


@pytest.fixture(scope='module')
def cloud():
    return _read(CLOUD)


@pytest.fixture(scope='module')
def sidebar(dash):
    """The global block of the tree sidebar, from the zero-cluster card to the groups."""
    start = dash.index('{clusters.length === 0 ? (')
    end = dash.index('{/* Grouped Clusters */}', start)
    return dash[start:end]


@pytest.fixture(scope='module')
def tools(dash):
    """Corporate lists the global views in a Tools section of its own, at the top of the sidebar."""
    start = dash.index('{isCorporate && clusters.length > 0 && (() => {')
    return dash[start:dash.index('})()}', start)]


def _sidebar_handlers(src):
    # the global entries all use a one-line arrow handler
    return re.findall(r'onClick=\{\(\) => \{ ([^}]*setSidebar[^}]*) \}\}', src)


# -- dashboard.js --------------------------------------------------------------

def test_the_gate_is_the_server_flag_not_a_permission_check(dash):
    assert 'const canAutoInstall = !!user?.autoinstall_access;' in dash
    assert "can('autoinstall.view')" not in dash
    assert "can('autoinstall.manage')" not in dash


def test_the_flag_has_state_and_an_intent(dash):
    assert 'const [sidebarAutoInstall, setSidebarAutoInstall] = useState(false);' in dash
    assert 'const [autoInstallIntent, setAutoInstallIntent] = useState(null);' in dash


def test_picking_a_cluster_clears_every_global_view(dash):
    m = re.search(r'useEffect\(\(\) => \{ if \(selectedCluster \|\| selectedPBS \|\| selectedVMware '
                  r'\|\| selectedGroup\) \{([^}]*)\} \}', dash)
    assert m, 'the reset effect moved'
    for flag in FLAGS:
        assert f'setSidebar{flag}(false)' in m.group(1), f'{flag} survives a cluster pick'


def test_every_sibling_entry_clears_the_others(dash, sidebar, tools):
    # All Clusters has its handler inline; Topology, World Map, XHM and EVPN have a named
    # one, shared by the Modern rows and the corporate Tools section. The new entry goes
    # through openAutoInstall
    named = dict(re.findall(r'const open(Topology|Worldmap|Xhm|MultiSdn|Guests) = \(\) => \{ ([^}]*) \};', dash))
    assert sorted(named) == ['Guests', 'MultiSdn', 'Topology', 'Worldmap', 'Xhm'], sorted(named)
    for fn in ('openWorldmap', 'openXhm', 'openMultiSdn', 'openGuests'):
        assert f'onClick={{{fn}}}' in sidebar, fn
    for fn in ('openTopology', 'openWorldmap', 'openXhm', 'openMultiSdn', 'openGuests'):
        assert f'onClick: {fn},' in tools, fn
    handlers = _sidebar_handlers(sidebar) + list(named.values())
    assert len(handlers) >= 5, handlers

    for body in handlers:
        opened = re.findall(r'setSidebar(\w+)\(true\)', body)
        for flag in FLAGS:
            if flag in opened:
                continue
            assert f'setSidebar{flag}(false)' in body, f'{flag} stays on after: {body}'
        # a global view never sits on top of a selection
        for sel in ('setSelectedCluster(null)', 'setSelectedPBS(null)',
                    'setSelectedVMware(null)', 'setSelectedGroup(null)'):
            assert sel in body, f'{sel} missing in: {body}'


def test_open_auto_install_clears_the_rest_and_hands_over_the_intent(dash):
    start = dash.index('const openAutoInstall = (intent = null) => {')
    body = dash[start:dash.index('};', start)]

    assert 'setSidebarAutoInstall(true)' in body
    for flag in FLAGS[:-1]:
        assert f'setSidebar{flag}(false)' in body
    for sel in ('setSelectedCluster(null)', 'setSelectedPBS(null)',
                'setSelectedVMware(null)', 'setSelectedGroup(null)'):
        assert sel in body
    assert 'setAutoInstallIntent(intent)' in body


def test_the_phone_drawer_closes_on_a_global_view(dash):
    start = dash.index('useEffect(() => { setMobileSidebarOpen(false); }, [')
    deps = dash[start:dash.index(']);', start)]
    for flag in FLAGS:
        assert f'sidebar{flag},' in deps or f'sidebar{flag}\n' in deps, f'sidebar{flag} not a dep'


def test_all_clusters_is_not_lit_next_to_another_global_view(dash, sidebar):
    m = re.search(r'const onGlobalView = ([^;]+);', dash)
    assert m, 'onGlobalView is gone'
    assert sorted(re.findall(r'sidebar(\w+)', m.group(1))) == sorted(FLAGS)

    start = sidebar.index('{/* MK: overview button')
    all_clusters = sidebar[start:sidebar.index('</button>', start)]
    # three Modern spots, the Corporate style and both hover handlers
    assert all_clusters.count('onGlobalView') == 6
    assert '!sidebarXHM' not in all_clusters
    assert 'sidebarTopology || sidebarXHM' not in all_clusters


def test_the_entry_sits_right_after_world_map(sidebar, tools):
    world = sidebar.index('Worldmap sidebar entry')
    # the empty-sidebar card further up uses the same gate, so look after World Map;
    # a standby installs nothing and shows neither (#625)
    entry = sidebar.index('{canAutoInstall && !haStandby && (', world)
    xhm = sidebar.index('XHM sidebar')
    assert world < entry < xhm

    button = sidebar[entry:sidebar.index('</button>', entry)]
    assert 'onClick={() => openAutoInstall()}' in button
    assert "t('autoInstall')" in button and "t('autoInstallHint')" in button
    # corporate: the same place in its Tools section, the same gate and handler
    assert re.findall(r"\{ id: '(\w+)', show: ", tools) == ['guests', 'topology', 'worldmap', 'autoinstall', 'xhm', 'mcevpn']
    assert "{ id: 'autoinstall', show: canAutoInstall && !haStandby," in tools
    assert 'onClick: () => openAutoInstall(),' in tools


def test_the_zero_cluster_card_is_the_way_in_before_any_cluster_exists(sidebar):
    """The sidebar entry only renders once a cluster exists. Before that the empty
    card is the only way in - for a view-only account too, or it could not watch the
    first hosts install. A manager lands in the wizard, as the label promises."""
    # up to the cluster list; the card has a ternary of its own now (#625: a standby
    # says why the list is empty instead)
    card = sidebar[:sidebar.index("<div className={isCorporate ? 'space-y-0' : 'space-y-3'}>")]
    assert '{canAutoInstall && !haStandby && (' in card
    assert "openAutoInstall(user?.autoinstall_access === 'manage' ? { wizard: true } : null)" in card
    assert "t('autoInstallFirstHost')" in card and "t('autoInstall')" in card


def test_the_page_mounts_the_panel_as_agreed(dash):
    branch_at = dash.index(') : sidebarAutoInstall ? (')
    overview_at = dash.index('<AllClustersOverview')
    assert branch_at < overview_at, 'the page branch must come before the landing fallback'

    page = dash[branch_at:overview_at]
    assert '<AutoInstallPanel' in page
    for prop in ('t={t}', 'addToast={addToast}', 'getAuthHeaders={getAuthHeaders}',
                 'clusters={clusters}', 'heading={!isCorporate}',
                 'intent={autoInstallIntent}',
                 'onIntentConsumed={() => setAutoInstallIntent(null)}'):
        assert prop in page, prop
    assert 'corp-content-header' in page


def test_the_landing_cta_is_passed_for_managers_only(dash):
    start = dash.index('<AllClustersOverview')
    mount = dash[start:dash.index('/>', dash.index('onAutoInstall=', start))]
    assert ("onAutoInstall={user?.autoinstall_access === 'manage' ? "
            "() => openAutoInstall({ wizard: true }) : undefined}") in mount


# -- vm_modals.js --------------------------------------------------------------

def test_the_landing_empty_states_render_the_cta_only_when_given():
    src = _read(VM_MODALS)
    start = src.index('function AllClustersOverview(')
    sig = src[start:src.index('{', src.index(')', start))]
    assert 'onAutoInstall' in sig

    body = src[start:src.index('function GroupSettingsModal(', start)]
    # Corporate and Modern each have one empty state
    assert body.count('{onAutoInstall && !haStandby && (') == 2   # not on a standby (#625)
    assert body.count('onClick={onAutoInstall}') == 2
    assert body.count("t('autoInstallFirstHost')") == 2


# -- cloud.js ------------------------------------------------------------------

def test_the_cloud_nav_item_is_gated_and_sits_after_hosts(cloud):
    item = ("...(canAutoInstall ? [{ id: 'autoinstall', label: 'Automated Installs', "
            "icon: 'Disc' }] : []),")
    assert item in cloud
    hosts = cloud.index("{ id: 'nodes', label: 'Hosts', icon: 'Cpu' },")
    assert cloud.index(item) > hosts
    assert cloud[hosts:cloud.index(item)].count('{ id:') == 1, 'something slipped in between'
    assert 'function CloudSideNav({ active, onSelect, isAdmin, canAutoInstall,' in cloud


def test_the_cloud_shell_reads_the_flag_off_the_current_user(cloud):
    # not on a standby (#625), like the sidebar entry of the other two layouts. Not on one
    # that forwards either: the answer URL the page shows would be the standby's own
    assert 'const canAutoInstall = !!(currentUser && currentUser.autoinstall_access) && !haStandby;' in cloud
    shell = cloud[cloud.index('function CloudShell('):]
    assert shell.index('const { ha, haStandby, haConsolesElsewhere } = useAuth();') < shell.index('const canAutoInstall =')
    assert 'canAutoInstall={canAutoInstall}' in cloud


def test_every_layout_keeps_the_entry_off_every_standby(dash):
    """A forwarding standby shows the actions again (haReadOnly is false there), but the
    automated installs are served from the instance the page runs on, so every gate asks
    haStandby, the one that holds for every standby."""
    for gate in ('{canAutoInstall && !haReadOnly && (', '{onAutoInstall && !haReadOnly && ('):
        assert gate not in dash, gate
        assert gate not in _read(VM_MODALS), gate
    assert dash.count('{canAutoInstall && !haStandby && (') == 2
    assert dash.count('show: canAutoInstall && !haStandby,') == 1   # the corporate Tools section
    assert ("const { user, sessionId, logout, getAuthHeaders, isAdmin, passwordExpiry, updatePreferences, "
            "ha, haReadOnly, haStandby, haConsolesElsewhere, haServing, refreshHa } = useAuth();") in dash


def test_the_cloud_page_hands_the_panel_the_raw_t(cloud):
    """T returns undefined on a key echo, and the panel calls .replace() on its strings."""
    start = cloud.index("case 'autoinstall':")
    case = cloud[start:cloud.index('break;', start)]
    assert '<AutoInstallPanel t={t}' in case
    assert 't={T}' not in case.split('<AutoInstallPanel', 1)[1].split('/>', 1)[0]
    assert 'canAutoInstall' in case, 'the page must not render past the gate'
    assert 'cloud-mounted' in case


# --- the panel and wizard in settings_modal.js ------------------------------------

@pytest.fixture(scope='module')
def modal():
    return _read('web/src/settings_modal.js')


def _js_regex(src, name):
    m = re.search(r'const ' + name + r' = /\^(.*?)\$/;', src)
    assert m, name
    return m.group(1)


@pytest.mark.parametrize('js_name,py_name', [
    ('AUTOINSTALL_GLOB_RE', '_GLOB_RE'),
    ('AUTOINSTALL_DISK_NAME_RE', '_DISK_NAME_RE'),
])
def test_the_wizard_checks_are_the_server_regexes(modal, js_name, py_name):
    """A stricter client refused /dev/nvme*, which the server takes. The two sides
    have to be the same pattern, so compare the patterns, not samples."""
    import pegaprox.api.auto_install as ai
    js = _js_regex(modal, js_name).replace('\\/', '/')
    assert js == getattr(ai, py_name).pattern, (js, getattr(ai, py_name).pattern)


@pytest.mark.parametrize('value,ok', [
    ('/dev/nvme*', True), ('/dev/sd?', True), ('WDC+*', True), ('enp1s0*', True),
    ('has space', False), ('quote"', False), ('', False),
])
def test_what_the_wizard_accepts_the_server_accepts(value, ok):
    import pegaprox.api.auto_install as ai
    assert bool(ai._GLOB_RE.fullmatch(value)) is ok


def test_the_timezone_check_matches_the_server(modal):
    import pegaprox.api.auto_install as ai
    m = re.search(r"const aiTimezoneOk = \(v\) => /\^(.*?)\$/", modal)
    assert m
    assert m.group(1).replace('\\/', '/') == ai._TZ_RE.pattern
    assert "!v.startsWith('Etc/')" in modal


def test_no_form_element_wraps_a_root_password(modal):
    """A submitted form that then clears or disappears is what makes a browser offer
    to save the node's root password as the PegaProx login."""
    start = modal.index('function AutoInstallPanel(')
    end = modal.index('// PegaProx - Settings Modal')
    block = modal[start:end]
    # comments explain why there is no form and say "<form>" doing so
    code = '\n'.join(l for l in block.splitlines() if not l.lstrip().startswith('//'))
    assert '<form' not in code, 'the auto-install panel or wizard renders a <form>'
    for field in ('id="aiw-pw"', 'id="aiw-pw2"', 'value={hashPw}', 'value={hashPw2}'):
        i = block.index(field)
        line = block[block.rindex('<input', 0, i):block.index('/>', i)]
        assert 'autoComplete="new-password"' in line and 'data-lpignore="true"' in line, field


def test_open_in_editor_needs_an_answer_to_open(modal):
    """With field errors /compose answers 200 and answer ''; opening the editor then
    showed the blank template and dropped everything typed so far."""
    n = modal.count('disabled={!compose || !compose.answer || stale || busy}')
    assert n == 2, n
    assert '{compose && compose.answer && (' in modal
