"""Slices S7 and S8 of the instance group in the web UI: who leads, and whether the group survives a split (#625).

The HA tab gets the split-safety panel (the votes per site, who leads on its own there, the clusters
with node HA and every finding with the server's words), the settings of each member on the leader
(the site, and vote and may lead as switches under the password), Make leader on every data voter
with a vote (on a member for itself, through its own instance), the agent VM of each data member and
of the leader per HA cluster, the status line items of the lease and the danger zone with Force
leader where, and only where, the server offers it. The forms open under the members table. Every
signed-in user gets the banners of a group that fails over automatically: no leader, a takeover, and
for ten minutes a change of the leader, with the addresses for an admin the HA tab is open to only.

On this release the status says auto: null and split_safety: null, and none of it renders. The
runtime tests drive the built bundle in headless Chromium against the fake server of
test_ha_auto_ui.py, with the routes of these slices answering in the order of their checks in
pegaprox/api/ha.py; test_ha_lead_ui_contract.py sends the same bodies to the real routes. They skip
where Playwright is not installed.
LW
"""
import copy
import json
import os
import re

import pytest

from test_ha_auto_ui import (  # noqa: F401  (browser is a fixture)
    B, B_URL, C, C_URL, EM_DASH, NOT_SHIPPED, OWN, W, W_URL, _GroupServer, _auto, _finding, _row, _running,
    _witness, browser)
from test_ha_ui import (
    BASE, CLUSTER, LANGS, PASSWORD, SRC, VM, _App, _block, _blocks, _classes, _member, _open_ha, _read, _toasts,
    _until, _wait_for_toast)

A_URL = 'https://pegaprox-a.example:5000'
NO_LEASE = ('No leader at the moment - changes and automation are paused until the group has one again')
PENDING = 'A switch to automatic failover is under way - try again once it is through'
SITE_ERROR = 'The site is a label of up to 64 characters on one line'
FORCE_WARNING = ('If any of these members still runs somewhere, two instances may act on the clusters both of them '
                 "reach: on a cluster with the cluster claim on until the older one sees this member's claim (up to "
                 '30 s), and steps over SSH are refused there at once; on a cluster without it until the two can '
                 'reach each other again. Tick a member only when it is powered off or destroyed.')
RESIDUAL = ('The cluster claim is off: an SSH step that a former leader had already sent when it froze is not '
            'refused at the node.')
RESTARTING = 'Restarting PegaProx...'
# a time of day as fmtTime gives it, in 24 or 12 hours
TIME = r'[\d:.]+(\s*[APap]\.?\s?[Mm]\.?)?'
# the parts of these slices in settings_modal.js
PARTS = ('HaSplitCard', 'HaLeadCard', 'HaMemberForm', 'haCvText', 'haAutoGate', 'HaAgentVmButton', 'HaAgentVmForm')


def _site(name, voters, candidates=(), members=None, witness=False, survives=True):
    return {'site': name, 'voters': list(voters), 'votes': len(voters), 'candidates': list(candidates),
            'members': list(members if members is not None else voters), 'witness': witness, 'survives_loss': survives}


def _cluster(cid, name, nodes=('pve1', 'pve2', 'pve3'), agents=None, fence=None, verified=(), ready=True, not_ready=(),
             two_node=False, unsafe=False, claim=None, reach_sites=('dc1', 'dc2'), kind='proxmox'):
    agents = agents if agents is not None else {n: 2 for n in nodes}
    return {'id': cid, 'name': name, 'kind': kind, 'nodes': list(nodes), 'agents': agents, 'agent_version': 2,
            'fence': fence if fence is not None else {n: None for n in nodes}, 'fence_verified': list(verified),
            'ready': ready, 'not_ready': list(not_ready), 'two_node': two_node, 'unsafe_two_node': unsafe,
            'claim': claim, 'reach': {OWN: True, B: True}, 'reach_sites': list(reach_sites), 'unreachable_from': {},
            'unreachable_checked_at': None}


def _claim(state='off', epoch=None, instance=None):
    on = state != 'off'
    return {'enabled': on, 'state': state, 'epoch': epoch, 'instance': instance, 'checked_at': None,
            'residual': None if on else RESIDUAL}


def _split(level='ok', findings=(), sites=None, unlabeled=(), clusters=(), voters=3, majority=2, tolerates=1):
    """public_status.split_safety, as split_safety() builds it."""
    sites = sites if sites is not None else [_site('dc-a', [OWN], [OWN]), _site('dc-b', [B], [B]),
                                             _site('dc-c', [C], [C])]
    return {'voters': voters, 'majority': majority, 'tolerates': tolerates, 'level': level, 'sites': sites,
            'unlabeled': list(unlabeled), 'clusters': list(clusters), 'findings': list(findings)}


def _lead(**more):
    """What make_leader_status() adds to lease_status(): nothing in flight, nothing offered."""
    return dict({'transfer': None, 'planned_restart': None, 'last_campaign': None,
                 'make_leader': {'phrase': 'LEADER', 'self': False}, 'forced': None,
                 'force_leader': {'offered': False, 'case': None, 'why': 'not offered', 'cut_out': [],
                                  'warning': FORCE_WARNING, 'phrase': 'FORCE LEADER'},
                 'way_out': '', 'site': '', 'may_lead': True}, **more)


def _offered(case='auto', cut=None, quiet=34.5, reached=1, majority=2):
    return {'offered': True, 'case': case, 'why': '', 'quiet': quiet, 'warning': FORCE_WARNING, 'phrase': 'FORCE LEADER',
            'last_campaign': {'reached': reached, 'majority': majority} if case == 'auto' else None,
            'cut_out': cut if cut is not None else [{'instance_id': B, 'url': B_URL, 'kind': 'data'},
                                                    {'instance_id': W, 'url': W_URL, 'kind': 'witness'}]}


class _LeadServer(_GroupServer):
    """The fake of test_ha_auto_ui.py with the split panel in the status, the banner of an automatic
    group on /auth/check, and the routes of these slices in the order of their checks in
    pegaprox/api/ha.py: the site and the vote of a member, Make leader and Force leader.

    split: public_status.split_safety (None on this release); lease_banner: what lease_banner() adds
    to the banner; after_restart: attributes the process has once it is back from a restart.
    """

    def __init__(self, split=None, split_key=True, lease_banner=None, site='', vote_refusal=None, site_refusal=None,
                 make_answers=(), force_answers=(), after_restart=None, vmid_refusal=None, managed=(), **kw):
        kw.setdefault('shipped', True)
        super().__init__(**kw)
        self.split, self.split_key = copy.deepcopy(split), split_key
        self.lease_banner = copy.deepcopy(lease_banner or {})
        self.site = site
        self.vote_refusal, self.site_refusal = vote_refusal, site_refusal
        # the agent VM: a refusal to answer with, and the clusters with no node HA this instance runs
        self.vmid_refusal, self.managed = vmid_refusal, set(managed)
        self.make_answers, self.force_answers = list(make_answers), list(force_answers)
        self.after_restart = copy.deepcopy(after_restart)

    def status(self):
        out = super().status()
        if self.split_key:
            out.update(split_safety=copy.deepcopy(self.split), site=self.site)
        return out

    def banner(self):
        out = super().banner()
        out.update(copy.deepcopy(self.lease_banner))
        return out

    def _come_back(self):
        super()._come_back()
        if self.after_restart:
            changes, self.after_restart = self.after_restart, None
            for key, value in changes.items():
                setattr(self, key, copy.deepcopy(value))

    def mode_route(self, body):
        # the real switch takes a block about one cluster as a warning (switch_auto_on)
        held = (self.auto or {}).get('findings')
        if held is not None:
            self.auto['findings'] = [dict(f, level='warn') if f['level'] == 'block' and f.get('cluster') else f
                                     for f in held]
        try:
            return super().mode_route(body)
        finally:
            if held is not None and self.auto is not None:
                self.auto['findings'] = held

    def _row(self, iid):
        return next((r for r in (self.auto or {}).get('members', []) if r['instance_id'] == iid), None)

    def _no_lease(self):
        if self.mode() == 'auto' and not (self.auto or {}).get('holds_lease'):
            return 503, {'code': 'HA_NO_LEASE', 'error': NO_LEASE}
        return None

    def _leader_first(self, error):
        if self.role != 'active' or not self.group():
            return 409, {'code': 'HA_STANDBY', 'error': error}
        if self.mode() == 'auto_pending':
            return 409, {'code': 'HA_AUTO_MODE', 'error': PENDING}
        return self._no_lease()

    def lead_route(self, method, path, body):
        m = re.fullmatch(r'/api/ha/members/([^/]+)/(site|vote)', path)
        if m and method == 'PUT':
            iid, what = m.groups()
            known = iid == OWN or self._row(iid) is not None or any(x['instance_id'] == iid for x in self.group())
            if what == 'site':
                site = body.get('site')
                if not isinstance(site, str) or len(site.strip()) > 64 or '\n' in site:
                    return 400, {'error': SITE_ERROR}
                refused = self._leader_first('The site of a member is set on the leader of a group')
                if refused:
                    return refused
                if not known:
                    return 404, {'error': 'That instance is not a member of this group'}
                if self.site_refusal:
                    return self.site_refusal
                label = site.strip()
                if iid == OWN:
                    changed, self.site = label != self.site, label
                    if self.auto:
                        self.auto['site'] = label
                else:
                    row = self._row(iid)
                    changed = row is not None and row.get('site') != label
                    if row is not None:
                        row['site'] = label
                    if (self.auto or {}).get('witness') and self.auto['witness']['instance_id'] == iid:
                        self.auto['witness']['site'] = label
                return 200, {'success': True, 'site': label, 'changed': changed}
            asked = {k: body[k] for k in ('voter', 'may_lead') if k in body}
            if not asked or not all(isinstance(v, bool) for v in asked.values()):
                return 400, {'error': 'voter and may_lead are true or false, one of them at least'}
            if not self.shipped:
                return 409, {'code': 'HA_AUTO_NOT_SHIPPED', 'error': NOT_SHIPPED}
            refused = self._leader_first('Vote and may lead are set on the leader of a group')
            if refused:
                return refused
            if not known:
                return 404, {'error': 'That instance is not a member of this group'}
            refusal = self._reauth_refusal(body)
            if refusal:
                return 403, refusal
            if self.vote_refusal:
                return self.vote_refusal
            if iid == OWN:
                self.auto['may_lead'] = asked.get('may_lead', self.auto.get('may_lead', True))
            else:
                self._row(iid).update(asked)
            return 200, dict({'success': True, 'changed': True, 'automatic': self.mode() == 'auto'}, **asked)
        m = re.fullmatch(r'/api/ha/members/([^/]+)/agent-vmid', path)
        if m and method == 'PUT':
            cid, vmid = body.get('cluster_id'), body.get('vmid')
            if not isinstance(cid, str) or not cid:
                return 400, {'error': 'cluster_id is the id of a cluster'}
            if vmid is not None and (isinstance(vmid, bool) or not isinstance(vmid, int) or vmid < 100):
                return 400, {'error': 'vmid is the id of a VM (100 or more), or null'}
            if not self.shipped:
                return 409, {'code': 'HA_AUTO_NOT_SHIPPED', 'error': NOT_SHIPPED}
            if self.role != 'active' or not self.group():
                return 409, {'code': 'HA_STANDBY', 'error': 'The VM of a member is set on the leader of a group'}
            refused = self._no_lease()
            if refused:
                return refused
            if self.vmid_refusal:
                return self.vmid_refusal
            if cid not in {c['id'] for c in (self.split or {}).get('clusters') or []} | self.managed:
                return 404, {'error': 'Cluster not found'}
            iid = m.group(1)
            if iid != OWN and self._row(iid) is None:
                return 409, {'error': 'That instance is not a member of this group'}
            held = (self.auto if iid == OWN else self._row(iid)).setdefault('agent_vmid', {})
            changed = held.get(cid) != vmid
            if vmid is None:
                held.pop(cid, None)
            else:
                held[cid] = vmid
            return 200, {'success': True, 'changed': changed}
        if path == '/api/ha/make-leader' and method == 'POST':
            if body.get('confirm') != 'LEADER':
                return 400, {'error': 'Type LEADER to confirm'}
            target = body.get('target')
            if target is not None and not (isinstance(target, str) and re.fullmatch(r'[0-9a-f]{32}', target)):
                return 400, {'error': 'target is the instance id of a member'}
            if not self.shipped:
                return 409, {'code': 'HA_AUTO_NOT_SHIPPED', 'error': NOT_SHIPPED}
            if self.mode() != 'auto':
                return 409, {'code': 'HA_MANUAL', 'error': 'This group does not fail over automatically - promote a standby instead'}
            refusal = self._reauth_refusal(body)
            if refusal:
                return 403, refusal
            if self.make_answers:
                return self.make_answers.pop(0)
            if self.role == 'active':
                # the old leader steps down once the member it handed the lead to won
                self._restart('standby')
                return 200, {'success': True, 'result': 'handed', 'target': target}
            self._restart('active')
            return 200, {'success': True, 'result': 'elected', 'target': OWN}
        if path == '/api/ha/force-leader' and method == 'POST':
            if body.get('confirm') != 'FORCE LEADER':
                return 400, {'error': 'Type FORCE LEADER to confirm', 'warning': FORCE_WARNING}
            cut = body.get('cut_out')
            if not isinstance(cut, list) or not all(isinstance(x, str) and re.fullmatch(r'[0-9a-f]{32}', x) for x in cut):
                return 400, {'error': 'cut_out is the list of the instance ids that do not answer'}
            reason = body.get('reason')
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
                return 400, {'error': 'Say why, in up to 500 characters'}
            if not self.shipped:
                return 409, {'code': 'HA_AUTO_NOT_SHIPPED', 'error': NOT_SHIPPED}
            if self.role != 'standby':
                return 409, {'code': 'HA_FORCE_REFUSED', 'error': 'Only a member that follows is forced to lead'}
            refusal = self._reauth_refusal(body)
            if refusal:
                return 403, refusal
            if self.force_answers:
                return self.force_answers.pop(0)
            view = (self.auto or {}).get('force_leader') or {}
            if not view.get('offered'):
                return 409, {'code': 'HA_FORCE_REFUSED', 'error': view.get('why') or 'Force leader is not offered here'}
            if set(cut) != {c['instance_id'] for c in view.get('cut_out') or []}:
                return 409, {'code': 'HA_FORCE_REFUSED', 'error': 'Tick every member that does not answer, each one '
                                                                  'powered off or destroyed'}
            self._restart('active')
            return 200, {'success': True, 'epoch': 9, 'cut_out': sorted(cut), 'restarting': True}
        return None

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        ours = req.url.startswith(BASE) and (re.fullmatch(r'/api/ha/members/[^/]+/(site|vote|agent-vmid)', path)
                                            or path in ('/api/ha/make-leader', '/api/ha/force-leader'))
        if not ours:
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        self.bodies.setdefault(path, []).append(body)
        status, data = self.lead_route(req.method, path, body) or (404, {'error': 'not mocked'})
        return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})


# -- source ---------------------------------------------------------------------------------------------

@pytest.fixture(scope='module')
def modal():
    return _read('web', 'src', 'settings_modal.js')


@pytest.fixture(scope='module')
def ours(modal):
    """Everything these slices add below the cards of stage 2, from their header to the end of the file."""
    return modal[modal.index('// LW Oct 2026 (#625) - whether the group survives a split, and who leads it'):]


@pytest.fixture(scope='module')
def panel(modal):
    start = modal.index('function HaPanel({ t, addToast, getAuthHeaders })')
    return modal[start:modal.index('\n        // ═══', start)]


@pytest.fixture(scope='module')
def leader_banner():
    dash = _read('web', 'src', 'dashboard.js')
    return _block(dash, '// LW Oct 2026 (#625) - a group that fails over automatically tells every signed-in user',
                  '// Cluster Sidebar Item Component')


def test_the_parts_exist_once(modal, ours):
    for name in PARTS:
        assert modal.count(f'function {name}(') == 1, name
    for name in ('HaSplitCard', 'HaLeadCard', 'HaMemberForm', 'haCvText', 'HaAgentVmButton', 'HaAgentVmForm'):
        assert f'function {name}(' in ours, name
    assert _read('web', 'src', 'dashboard.js').count('function HaLeaderBanner(') == 1


def test_the_panel_mounts_them_with_automatic_failover_only(panel):
    cards = _block(panel, 'const groupCards = (leader) => {', 'if (!status) {')
    # this release sends auto: null and split_safety: null, and neither card renders then
    assert ("const split = reported && status.split_safety && typeof status.split_safety === 'object' "
            "? status.split_safety : null;") in cards
    assert '{reported && auto && (' in cards and '<HaLeadCard ' in cards
    assert '{split && (' in cards and '<HaSplitCard ' in cards
    # the leader's controls, held while a switch is pending, during a hand-over and without the lease
    ctl = _block(panel, 'const locked = ', 'const memberForm = ')
    for needle in ("auto?.mode === 'auto_pending' ? t('haAutoLockedPending')", "auto?.transfer ? t('haAutoLockedTransfer')",
                   "auto?.mode === 'auto' && auto.holds_lease !== true ? t('haAutoNoLeader')",
                   "const memberCtl = role === 'active' && autoRows && !broken ? {",
                   "voteLocked: locked || (notShipped ? t('haAutoNotShipped') : ''),"):
        assert needle in ctl, needle


def test_the_requests_are_what_the_routes_read(ours):
    api = _read('pegaprox', 'api', 'ha.py')
    form = _block(ours, 'function HaMemberForm(', 'function HaSplitCard(')
    assert ("const body = what === 'site' ? { site: site.trim() }\n"
            "                    : leader ? (self ? { confirm: phrase } : { target: id, confirm: phrase })\n"
            "                    : { [what]: value };") in form
    # the site goes without a password, vote and Make leader with it (an SSO account sends none)
    assert "what === 'site' || sso ? body : { ...body, user_password: password }" in form
    assert "haGroupSend(getAuthHeaders, leader ? 'POST' : 'PUT', path," in form
    site = _block(api, "@bp.route('/api/ha/members/<instance_id>/site'", "@bp.route('/api/ha/members/<instance_id>/vote'")
    assert "site = _body().get('site')" in site and '_refuse_without_reauth' not in site
    vote = _block(api, "@bp.route('/api/ha/members/<instance_id>/vote'", "@bp.route('/api/ha/mode'")
    assert "asked = {k: data[k] for k in ('voter', 'may_lead') if k in data}" in vote
    assert "_refuse_without_reauth('changing the vote of a member')" in vote
    make = _block(api, "@bp.route('/api/ha/make-leader'", "@bp.route('/api/ha/force-leader'")
    for needle in ("data.get('confirm') != ha.LEADER_PHRASE", "target = data.get('target')",
                   "_refuse_without_reauth('making a member leader')"):
        assert needle in make, needle
    lead = _block(ours, 'function HaLeadCard(', '\n        }\n')
    assert "const body = { confirm: phrase, cut_out: cut.map(c => c.instance_id), reason: reason.trim() };" in lead
    assert "haGroupSend(getAuthHeaders, 'POST', 'force-leader', sso ? body : { ...body, user_password: password }," in lead
    force = _block(api, "@bp.route('/api/ha/force-leader'", "@bp.route('/api/ha/members/<instance_id>/agent-vmid'")
    for needle in ("data.get('confirm') != ha.FORCE_PHRASE", "cut_out = data.get('cut_out')", "reason = data.get('reason')",
                   "_refuse_without_reauth('forcing this member to lead')"):
        assert needle in force, needle
    # the agent VM: cluster and VM id, null to forget it, no password (it names a VM, it acts on none)
    vm = _block(ours, 'function HaAgentVmForm(', 'function HaSplitCard(')
    assert ("haGroupSend(getAuthHeaders, 'PUT', `members/${encodeURIComponent(id)}/agent-vmid`,\n"
            "                                            { cluster_id: cid, vmid }, t('pgHaActionFailed'));") in vm
    assert 'send(r.id, Number(value))' in vm and 'send(r.id, null)' in vm and 'password' not in vm.lower()
    route = _block(api, "@bp.route('/api/ha/members/<instance_id>/agent-vmid'", "\n\n\n")
    assert "cluster_id, vmid = data.get('cluster_id'), data.get('vmid')" in route and '_refuse_without_reauth' not in route
    core = _read('pegaprox', 'core', 'ha.py')
    assert "LEADER_PHRASE = 'LEADER'" in core and "FORCE_PHRASE = 'FORCE LEADER'" in core and 'FORCE_REASON_MAX = 500' in core
    assert 'maxLength={500}' in lead and 'maxLength={64}' in form


def test_force_leader_shows_only_where_the_server_offers_it(ours):
    lead = _block(ours, 'function HaLeadCard(', 'const submit = async () => {')
    assert ("const force = !broken && auto?.force_leader && typeof auto.force_leader === 'object' "
            "&& auto.force_leader.offered === true") in lead
    assert 'useEffect(() => { if (!force) openForce(false); }, [!!force]);' in lead
    # every member it cuts out is ticked, the reason given, the phrase typed exactly, the password there
    assert ("const ready = !busy && cut.every(c => ticked.includes(c.instance_id)) && !!reason.trim() && typed === phrase "
            "&& (sso || !!password);") in _block(ours, 'function HaLeadCard(', 'return (')


def test_the_way_out_hides_plain_promote_and_unpair_only_where_force_leader_is_the_way(panel):
    assert "const wayOut = typeof auto?.way_out === 'string' ? auto.way_out : '';" in panel
    assert "const forceOnly = !!wayOut && auto?.force_leader?.offered === true;" in panel
    assert "const promoteOffered = !(auto && auto.mode && auto.mode !== 'manual') && !forceOnly;" in panel
    standby = panel[panel.index("{role === 'standby' && ("):]
    assert '{!broken && !status?.removed && (promoteOffered ? (' in standby
    assert "{!forceOnly && (\n                                    <button onClick={() => openConfirm('unpair')}" in standby
    assert '{wayOut && (' in standby and '{wayOut}' in standby


def test_the_checklist_takes_a_block_about_one_cluster_as_a_warning(modal):
    assert 'return f.level === \'block\' && f.cluster ? \'warn\' : f.level;' in modal
    card = _block(modal, 'function HaAutoCard(', 'function HaWitnessCard(')
    assert ".flatMap(c => c.findings.filter(f => haAutoGate(f) === 'warn').map(f => f.code)))];" in card
    core = _read('pegaprox', 'core', 'ha.py')
    switch = _block(core, 'def switch_auto_on(', 'def _switch_taken_back(')
    assert "blocks = [f for f in findings if _gate(f) == 'block']" in switch
    assert "open_ = [f for f in findings if _gate(f) == 'warn' and f['code'] not in accept]" in switch
    # the split panel's level goes by the same gate
    assert "return 'warn' if level == 'block' and finding.get('cluster') else level" in _block(core, 'def _gate(', '\n\n\n')
    assert 'LEVELS.index(_gate(f))' in _block(core, 'def split_safety(', 'def _gate(')


def test_the_banner_shows_in_an_automatic_group_only(leader_banner):
    assert 'const automatic = ha?.automatic === true;' in leader_banner
    for needle in ("t('haNoLeader')", "t('haTakeover').replace('{leader}', () => takeover.leader) : t('haTakeoverUnnamed')",
                   "t('haLeaderChanged').replace('{to}', () => changed.to) : t('haLeaderChangedAt')",
                   ".replace('{time}', () => fmtTime(changed.at) || '-')",
                   "const button = isAdmin && onOpenHa && line.kind !== 'leader-changed' && ("):
        assert needle in leader_banner, needle
    # the server names nobody to most users and sends no epoch: a change is the moment and, for an
    # admin, the address it went to
    assert "const changeKey = changed ? `${changed.at}|${named(changed.to)}` : '';" in leader_banner
    assert 'epoch' not in leader_banner
    # only the change can be closed: no leader and a takeover stay while they hold
    assert leader_banner.count('close: true') == 1


def test_every_layout_mounts_the_banner_and_every_role_polls_it():
    dash = _read('web', 'src', 'dashboard.js')
    main = dash[dash.index('function PegaProxDashboard('):]
    at = main.index('<HaCopiesBanner onOpenHa={openHaSettings} />')
    assert main[at:at + 120].count('<HaLeaderBanner onOpenHa={openHaSettings} />') == 1
    shell = _read('web', 'src', 'cloud.js')
    assert shell.count('<HaLeaderBanner cloud onOpenHa={() => {') == 1
    ctx = _read('web', 'src', 'contexts.js')
    # the leader as well as a member: a page opened on it while the group was manual hears the switch
    effect = _block(ctx, "if (!isAuthenticated || (ha.role !== 'standby' && ha.role !== 'active')) return;", '}, [')
    assert 'setInterval(refreshHa, ha.automatic === true ? 10000 : 30000)' in effect
    # and a change the group refuses for want of a leader reads the banner again at once
    lease = _block(ctx, "window.addEventListener('pegaprox-ha-lease', onLease);", '}, [')
    assert "window.removeEventListener('pegaprox-ha-lease', onLease);" in lease
    dash = _read('web', 'src', 'dashboard.js')
    fetcher = _block(dash, 'const authFetch = React.useCallback(async (url, opts = {}) => {', '}, [getAuthHeaders]);')
    assert "if (res.status === 503 && (code === 'HA_NO_LEASE' || code === 'HA_TRANSFER'))" in fetcher
    assert "window.dispatchEvent(new CustomEvent('pegaprox-ha-lease'))" in fetcher
    # the HA tab's two senders, through one helper
    modal = _read('web', 'src', 'settings_modal.js')
    helper = _block(modal, 'function haLeaseRefused(status, code) {', '\n        }\n')
    assert "if (status === 503 && (code === 'HA_NO_LEASE' || code === 'HA_TRANSFER')) {" in helper
    assert "window.dispatchEvent(new CustomEvent('pegaprox-ha-lease'))" in helper
    assert modal.count("new CustomEvent('pegaprox-ha-lease')") == 1
    assert 'haLeaseRefused(r.status, data?.code);' in _block(modal, 'async function haGroupSend(', 'function haLeaseRefused(')
    panel_send = _block(modal, 'const send = async (method, path, body, fallback) => {', '\n            };')
    assert 'haLeaseRefused(r.status, code);' in panel_send


def test_server_words_go_into_a_text_through_a_function(ours, leader_banner):
    seen = 0
    for text in (ours, leader_banner):
        for m in re.finditer(r"\.replace\('\{(\w+)\}', (.{0,6})", text):
            seen += 1
            if m.group(1) not in ('n', 'k', 'v'):
                assert m.group(2).startswith('() =>'), text[m.start():m.start() + 100]
    assert seen >= 30, seen


# -- translations ---------------------------------------------------------------------------------------

BANNER_KEYS = ('haNoLeader', 'haTakeover', 'haLeaderChanged', 'haTakeoverUnnamed', 'haLeaderChangedAt')


def _ours_keys():
    keys = set()
    for name in sorted(os.listdir(SRC)):
        if name.endswith('.js') and name != 'translations.js':
            keys.update(re.findall(r"'((?:haAuto(?:Split|Claim|Force|Forced|Make|Vote|MayLead|Site|Cv|Promis|Behind|"
                                   r"Locked|Lead|Renewed|Transfer|Planned|Unconfirmed|ChangePending|LastChange|Campaign|"
                                   r"InStep|Unreached|CheckSites|CheckClusters|Vmid))\w*)'", _read('web', 'src', name)))
    return sorted(keys)


def _value(block, key):
    m = re.search(r"^ +%s: '(.*)',$" % key, block, re.M)
    return m.group(1).replace("\\'", "'")


def test_the_keys_of_these_slices():
    keys = _ours_keys()
    assert len(keys) >= 95, len(keys)


@pytest.mark.parametrize('lang', LANGS)
def test_the_banner_keys_are_one_block_of_their_own(lang):
    block = _blocks()[lang]
    lines = block.splitlines()
    start = lines.index('                // LW Oct 2026 (#625) - the banners of a group that fails over automatically, for every user')
    end = start + 1 + len(BANNER_KEYS)
    assert [re.match(r'^ +(\w+): ', line).group(1) for line in lines[start + 1:end]] == list(BANNER_KEYS)
    assert lines[end] == ('                // LW Oct 2026 (#625) - stage 2: automatic failover, the witness, '
                          'the time zone of the schedules')
    for key in BANNER_KEYS + tuple(_ours_keys()):
        assert len(re.findall(r'^ +%s: ' % key, block, re.M)) == 1, (lang, key)


def test_placeholders_survive_and_every_text_is_translated():
    blocks = _blocks()
    for key in BANNER_KEYS + tuple(_ours_keys()):
        en = _value(blocks['en'], key)
        for lang in LANGS:
            value = _value(blocks[lang], key)
            assert value.strip(), (lang, key)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)
            assert EM_DASH not in value, (lang, key)
            if lang != 'en':
                assert value != en, (lang, key)
            if lang == 'ko':
                assert '구성원' not in value, key


def test_the_names_in_the_texts_match_the_buttons():
    blocks = _blocks()
    for lang in LANGS:
        # the hint on a member names the button it explains
        assert _value(blocks[lang], 'haAutoMakeLeader').lower()[:4] in _value(blocks[lang], 'haAutoMakeSelfHint').lower(), lang
        assert _value(blocks[lang], 'haAutoForceGo') in _value(blocks[lang], 'haAutoForceOpen'), lang


# -- styling, icons, bundle, house rules ------------------------------------------------------------------

def test_every_class_is_in_the_static_tailwind_build(ours, panel, leader_banner):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(ours) | _classes(leader_banner) | _classes(_block(panel, 'const nameOf = (id) =>', 'const membersCard = ('))
    names |= _classes(_block(panel, '{wayOut && (', '{typedBox}'))
    modal = _read('web', 'src', 'settings_modal.js')
    names |= _classes(_block(modal, 'function HaAutoMemberHead(', 'function HaAutoCard('))
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists(ours, leader_banner):
    icons = set(re.findall(r'^ {12}(\w+): ', _read('web', 'src', 'icons.js'), re.M))
    used = set(re.findall(r'Icons\.(\w+)', ours + leader_banner))
    assert used and used <= icons, sorted(used - icons)


def test_house_rules(ours, leader_banner):
    for text in (ours, leader_banner, _read('tests', 'test_ha_lead_ui.py'), _read('tests', 'test_ha_lead_ui_contract.py')):
        assert EM_DASH not in text
        assert 'VM' + 'ware' not in text and 'v' + 'Center' not in text
    assert ours.count('LW Oct 2026 (#625)') == 1 and leader_banner.count('LW Oct 2026 (#625)') == 1
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for name in PARTS + ('HaLeaderBanner', 'data-ha-split', 'data-ha-force', 'force-leader', 'make-leader'):
        assert name in bundle, name
    for key in BANNER_KEYS + tuple(_ours_keys()):
        assert key in bundle, key


# -- runtime --------------------------------------------------------------------------------------------

@pytest.fixture
def open_app(browser):
    apps = []

    def _open(clock=False, **kw):
        app = _App(browser, _LeadServer(**kw), clock=clock)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _sent(app, path):
    return app.server.bodies.get(path, [])


def _writes(app):
    return [c for c in app.server.calls if c[0] != 'GET' and c[1].startswith('/api/ha/')]


def _standby_members():
    return [_member('b', role='active', source=True), _member('c')]


def _text(locator):
    return re.sub(r'\s+', ' ', locator.inner_text()).strip()


def test_runtime_this_release_shows_none_of_it(open_app):
    """auto null, split_safety null: no panel, no lead card, no switch in the table, and the
    promote button of a member is where it was."""
    for role, members in (('active', None), ('standby', _standby_members())):
        kw = {'role': role, 'shipped': False}
        if members:
            kw['members'] = members
        app = open_app(**kw)
        panel = _open_ha(app, role)
        panel.locator('[data-ha-zone]').wait_for(timeout=3000)
        assert panel.locator('[data-ha-split], [data-ha-lead], [data-ha-member-form], [data-ha-way-out]').count() == 0
        assert panel.locator('[data-ha-members] [role="switch"][data-ha-auto-toggle]').count() == 0
        if role == 'standby':
            assert panel.get_by_role('button', name='Promote to active').count() == 1
        assert app.page.locator('[data-ha-lease-banner]').count() == 0
        assert not _writes(app)
        assert not app.errors, app.errors


SPLITS = {
    'ok': _split(),
    'info': _split('info', findings=[
        _finding('TZ_MISMATCH', 'info', f'{B_URL} runs in time zone America/New_York. The group\'s schedules run in '
                                        'Europe/Vienna whichever member leads.', B),
        dict(_finding('ALL_ONE_SITE', 'info', 'Survives the loss of any 1 member. A site outage stops PegaProx '
                                               'automation until the site is back.'), site='dc1')],
        sites=[_site('dc1', [OWN, B, C], [OWN, B, C], survives=False)],
        clusters=[_cluster('c1', 'lab', claim=_claim('ours', 7, OWN), reach_sites=['dc1']),
                  _cluster('x1', 'pool', kind='other', nodes=(), ready=None, reach_sites=['dc1'])]),
    'warn': _split('warn', findings=[
        dict(_finding('SITE_HOLDS_MAJORITY', 'warn', 'Losing site dc1 stops automation everywhere.'), site='dc1'),
        dict(_finding('NO_SITE_LABELS', 'warn', f'Set a site for each member to check split safety (no site yet: '
                                                f'{C_URL}).'), members=[C]),
        dict(_finding('RECOVERY_NOT_READY', 'warn', 'Cluster lab: node recovery needs agents v2 on every node or a '
                                                    'verified IPMI fence.'), cluster='c1', nodes=['pve2']),
        dict(_finding('TWO_NODE_NO_FENCE', 'warn', 'Two-node cluster edge has no verified hardware fence. PegaProx '
                                                   'will not recover it automatically.'), cluster='c2'),
        dict(_finding('NO_CLAIM', 'warn', 'Cluster far has no SSH access, so it carries no leader claim.'), cluster='c3')],
        sites=[_site('dc1', [OWN, B], [OWN, B], survives=False)], unlabeled=[C],
        clusters=[_cluster('c1', 'lab', agents={'pve1': 2, 'pve2': 1, 'pve3': 0}, fence={'pve1': None, 'pve2': None, 'pve3': 'ipmi'},
                           verified=['pve3'], ready=False, not_ready=['pve2'], claim=_claim('off')),
                  _cluster('c2', 'edge', nodes=('n1', 'n2'), two_node=True, fence={'n1': 'ssh', 'n2': None}, claim=_claim('off')),
                  _cluster('c3', 'far', claim=_claim('unreachable'), reach_sites=[])]),
    'block': _split('block', voters=2, majority=2, tolerates=0, findings=[
        _finding('TZ_MISMATCH', 'info', f'{C_URL} runs in time zone UTC. The group\'s schedules run in Europe/Vienna '
                                        'whichever member leads.', C),
        dict(_finding('FOREIGN_CLAIM', 'block', f'Cluster lab is claimed by {W_URL[8:16]} at epoch 9. Nothing acts on '
                                                'it until the claim is released.'), cluster='c1'),
        _finding('EVEN_VOTERS', 'warn', '2 votes survive the loss of 0.'),
        _finding('TOO_FEW_VOTERS', 'block', 'Automatic failover needs at least 3 votes, this group has 2. Add a data '
                                            'member or a witness.')],
        sites=[_site('dc1', [OWN], [OWN], survives=False), _site('dc2', [B], [], survives=False)],
        clusters=[_cluster('c1', 'lab', claim=_claim('higher', 9, 'f' * 32), two_node=True, unsafe=True),
                  _cluster('c2', 'spare', claim=_claim('unreadable'), ready=None, nodes=())]),
}
LEVEL_TEXT = {'ok': 'OK', 'info': 'Notes', 'warn': 'Warnings', 'block': 'Blocked'}


@pytest.mark.parametrize('level', list(SPLITS))
def test_runtime_the_split_panel_at_every_level(open_app, level):
    """The level, the votes, the sites with who leads there and what their loss does, the members
    without a site, every finding in the server's words (the worst first), and the clusters with
    node HA: recovery, the nodes, two nodes, the claim and where they are reached from."""
    split = SPLITS[level]
    app = open_app(auto=_running(**_lead()), split=split)
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-split]')
    card.wait_for(timeout=3000)
    assert card.get_attribute('data-ha-split') == level
    assert card.locator('h4').inner_text().startswith('Split safety')
    assert card.locator('[data-ha-split-level]').inner_text().strip() == LEVEL_TEXT[level]
    assert card.locator('[data-ha-split-votes]').inner_text().strip() == (
        f"{split['voters']} votes, majority {split['majority']}: survives the loss of {split['tolerates']}")
    rows = card.locator('[data-ha-split-site]')
    assert rows.count() == len(split['sites'])
    for s in split['sites']:
        row = card.locator(f'[data-ha-split-site="{s["site"]}"]')
        assert row.locator('td').first.inner_text().strip() == s['site']
        assert row.locator('[data-ha-split-survives]').get_attribute('data-ha-split-survives') == (
            'yes' if s['survives_loss'] else 'no')
        assert row.locator('[data-ha-split-survives]').inner_text().strip() == (
            'the others elect a leader' if s['survives_loss'] else 'automation stops')
    if level == 'block':
        # who leads on its own there, by the names the table uses
        assert _text(card.locator('[data-ha-split-site="dc1"] td').nth(1)) == 'this instance'
        assert _text(card.locator('[data-ha-split-site="dc2"] td').nth(3)) == '-'
    if level == 'info':
        assert _text(card.locator('[data-ha-split-site="dc1"] td').nth(1)) == f'this instance, {B_URL}, {C_URL}'
    unlabeled = card.locator('[data-ha-split-unlabeled]')
    if split['unlabeled']:
        assert unlabeled.inner_text().strip() == f'No site yet: {C_URL}'
    else:
        assert unlabeled.count() == 0
    found = card.locator('[data-ha-split-finding]').evaluate_all(
        'r => r.map(x => [x.dataset.haSplitFinding, x.dataset.haSplitFindingLevel, x.innerText.trim()])')
    order = {'block': 0, 'warn': 1, 'info': 2}
    want = sorted(split['findings'], key=lambda f: order[f['level']])
    assert found == [[f['code'], f['level'], f['text']] for f in want]
    if not split['findings']:
        assert card.locator('[data-ha-split-nothing]').inner_text().strip() == 'Nothing to look at.'
    clusters = card.locator('[data-ha-split-cluster]')
    assert clusters.count() == len(split['clusters'])
    if level == 'info':
        lab = card.locator('[data-ha-split-cluster="c1"]')
        assert lab.locator('[data-ha-split-ready]').inner_text().strip() == 'ready'
        assert lab.locator('[data-ha-split-claim]').inner_text().strip() == 'epoch 7 by this instance'
        assert lab.locator('[data-ha-split-reach]').inner_text().strip() == 'dc1'
        pool = card.locator('[data-ha-split-cluster="x1"]')
        assert pool.locator('[data-ha-split-ready]').inner_text().strip() == 'node HA of another kind - not checked'
        assert pool.locator('[data-ha-split-two-node]').get_attribute('data-ha-split-two-node') == 'other'
    if level == 'warn':
        lab = card.locator('[data-ha-split-cluster="c1"]')
        assert lab.locator('[data-ha-split-ready]').inner_text().strip() == 'not ready: pve2'
        lab.locator('summary').click()
        nodes = lab.locator('[data-ha-split-node]').evaluate_all('r => r.map(x => x.innerText.trim())')
        assert nodes == ['pve1: agent v2 · no fence', 'pve2: agent v1 · no fence', 'pve3: no agent · fence ipmi, verified']
        assert 'text-yellow-300' in lab.locator('[data-ha-split-node="pve2"]').get_attribute('class')
        edge = card.locator('[data-ha-split-cluster="c2"]')
        assert edge.locator('[data-ha-split-two-node]').inner_text().strip() == 'two-node'
        edge.locator('summary').click()
        assert edge.locator('[data-ha-split-node="n1"]').inner_text().strip() == 'n1: agent v2 · fence ssh, not verified'
        assert edge.locator('[data-ha-split-claim]').inner_text().strip() == 'off'
        far = card.locator('[data-ha-split-cluster="c3"]')
        assert far.locator('[data-ha-split-claim]').inner_text().strip() == 'no SSH - no claim'
        assert far.locator('[data-ha-split-reach]').inner_text().strip() == '-'
        # what a cluster without the claim leaves open, once, in the server's words
        assert card.locator('[data-ha-split-residual]').inner_text().strip() == RESIDUAL
    if level == 'block':
        lab = card.locator('[data-ha-split-cluster="c1"]')
        assert lab.locator('[data-ha-split-claim]').inner_text().strip() == (
            'claimed by ffffffff at epoch 9 - release it in the HA settings of the cluster')
        assert 'text-red-300' in lab.locator('[data-ha-split-claim]').get_attribute('class')
        assert lab.locator('[data-ha-split-two-node]').inner_text().strip() == 'two-node, unsafe recovery on'
        spare = card.locator('[data-ha-split-cluster="c2"]')
        assert spare.locator('[data-ha-split-ready]').inner_text().strip() == 'no nodes known yet'
        assert spare.locator('[data-ha-split-claim]').inner_text().strip() == (
            'a claim file of no instance of this group - release it in the HA settings of the cluster')
        assert card.locator('[data-ha-split-residual]').count() == 0
    assert not _writes(app)
    assert not app.errors, app.errors


@pytest.mark.parametrize('state,text', [
    ('unknown', 'on, not read yet'), ('busy', 'on, not written at the last try'), ('same', 'claimed by eeeeeeee at epoch 4'),
])
def test_runtime_every_claim_state_has_its_words(open_app, state, text):
    claim = _claim(state, 4 if state == 'same' else None, W if state == 'same' else None)
    app = open_app(auto=_running(**_lead()), split=_split(clusters=[_cluster('c1', 'lab', claim=claim)]))
    panel = _open_ha(app, 'active')
    got = panel.locator('[data-ha-split-cluster="c1"] [data-ha-split-claim]')
    # the witness of the group goes by its address
    want = text.replace('eeeeeeee', W_URL)
    assert got.inner_text().strip().startswith(want), got.inner_text()
    assert got.get_attribute('data-ha-split-claim') == state
    assert not app.errors, app.errors


def test_runtime_a_member_reads_the_split_panel(open_app):
    """On a member: the same panel, its own site and may lead as text, nothing to edit or switch."""
    app = open_app(role='standby', members=_standby_members(), split=SPLITS['warn'],
                   auto=_auto(mode='auto', holder=B, lease_left=12.0, **_lead(site='dc-a', may_lead=False)))
    panel = _open_ha(app, 'standby')
    card = panel.locator('[data-ha-split]')
    card.wait_for(timeout=3000)
    me = card.locator('[data-ha-split-self]')
    assert _text(me) == 'This instance Site: dc-a May lead: No'
    assert card.locator('button, [role="switch"]').count() == 0
    assert panel.locator('[data-ha-members] [data-ha-auto-toggle], [data-ha-members] [data-ha-make-leader]').count() == 0
    assert panel.locator('[data-ha-members] th', has_text='May lead').count() == 0
    assert not _writes(app)
    assert not app.errors, app.errors


def test_runtime_the_checklist_knows_sites_and_clusters(open_app):
    """A site missing is amber, a claim of another instance on one cluster is amber too (it stops that
    cluster only), a member in another time zone is something to know: the switch goes on with the
    two amber items ticked, and their codes go out in accept."""
    findings = SPLITS['block']['findings'][:2] + [SPLITS['warn']['findings'][1]]
    app = open_app(auto=_auto(findings=findings, **_lead()), split=_split('block', findings=findings,
                                                                          clusters=SPLITS['block']['clusters']))
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    got = dict(card.locator('[data-ha-auto-check]').evaluate_all('r => r.map(x => [x.dataset.haAutoCheck, x.dataset.haAutoLevel])'))
    assert got == {'votes': 'ok', 'release': 'ok', 'answer': 'ok', 'clock': 'ok', 'zone': 'info', 'sites': 'warn',
                   'clusters': 'warn'}
    assert card.locator('[data-ha-auto-check="sites"]').inner_text().startswith(
        'A site for every member, and no site whose loss stops the group')
    assert card.locator('[data-ha-auto-check="clusters"]').inner_text().startswith(
        'Every cluster with node HA ready for a leader at any site')
    # something to know asks for no tick
    assert card.locator('[data-ha-auto-check="zone"] input[type="checkbox"]').count() == 0
    switch = page.get_by_role('switch', name='Automatic failover')
    assert switch.is_enabled()
    switch.click()
    page.fill('#pgha-auto-password', PASSWORD)
    go = card.get_by_role('button', name='Switch on')
    assert go.is_disabled()
    for key in ('sites', 'clusters'):
        card.locator(f'[data-ha-auto-check="{key}"]').get_by_label('I understand').check()
    assert go.is_enabled()
    go.click()
    assert _wait_for_toast(page, 'Switch to automatic failover started'), _toasts(page)
    assert _sent(app, '/api/ha/mode') == [{'mode': 'auto', 'lease_s': 20, 'accept': ['NO_SITE_LABELS', 'FOREIGN_CLAIM'],
                                           'user_password': PASSWORD}]
    assert not app.errors, app.errors


def test_runtime_without_clusters_the_cluster_item_stays_away(open_app):
    app = open_app(auto=_auto(**_lead()), split=_split())
    panel = _open_ha(app, 'active')
    keys = panel.locator('[data-ha-auto-check]').evaluate_all('r => r.map(x => x.dataset.haAutoCheck)')
    assert 'clusters' not in keys and 'sites' in keys
    assert not app.errors, app.errors


def _leader(**more):
    members = [_row('b', site='dc1', mode='auto', make_leader=True, make_leader_why=''),
               _row('c', site='dc2', mode='auto', make_leader=False,
                    make_leader_why=f'{C_URL} does not answer the renewals of this leader')]
    w = _witness()
    rows = members + [dict(_row('e', kind='witness', may_lead=False, site='dc3', url=W_URL, reach=None),
                           instance_id=W, make_leader=False, make_leader_why='The witness holds no data and never leads')]
    kw = dict(mode='auto', members=rows, holds_lease=True, holder=OWN, lease_left=15.2, epoch=7, **_lead(site='dc-a'))
    kw.update(more)
    out = _auto(**kw)
    out['witness'] = w
    return out


def test_runtime_the_leader_sets_the_site_of_a_member_itself_and_the_witness(open_app):
    app = open_app(auto=_leader(), split=_split(), site='dc-a')
    page = app.page
    panel = _open_ha(app, 'active')
    b = panel.locator(f'[data-ha-member="{B}"]')
    b.get_by_role('button', name=f'Site of {B_URL}').click()
    row = panel.locator(f'[data-ha-member-form-row="{B}"]')
    form = row.locator('[data-ha-member-form="site"]')
    form.wait_for(timeout=3000)
    assert form.inner_text().startswith('The split checks group the votes by site.')
    assert page.input_value('#pgha-member-site') == 'dc1'
    save = form.get_by_role('button', name='Save')
    assert save.is_disabled(), 'nothing changed yet'
    # no password: a label decides nothing
    assert form.locator('input[type="password"]').count() == 0
    page.fill('#pgha-member-site', '  dc9 ')
    save.click()
    assert _wait_for_toast(page, 'Site saved'), _toasts(page)
    row.wait_for(state='detached', timeout=3000)
    assert _until(page, lambda: b.locator('[data-ha-auto-site]').inner_text().strip() == 'dc9')
    # the leader itself, in the split panel, and the witness in its row
    me = panel.locator('[data-ha-split-self]')
    me.get_by_role('button', name='Site of this instance').click()
    panel.locator('[data-ha-split] [data-ha-member-form="site"]').wait_for(timeout=3000)
    page.fill('#pgha-member-site', 'dc1')
    panel.locator('[data-ha-split] [data-ha-member-form="site"]').get_by_role('button', name='Save').click()
    assert _until(page, lambda: me.locator('[data-ha-split-self-site]').inner_text().strip() == 'dc1')
    panel.locator(f'[data-ha-member-witness="{W}"]').get_by_role('button', name=f'Site of {W_URL}').click()
    page.fill('#pgha-member-site', 'dc4')
    panel.locator(f'[data-ha-member-form-row="{W}"]').get_by_role('button', name='Save').click()
    assert _until(page, lambda: panel.locator(f'[data-ha-member-witness="{W}"] [data-ha-auto-site]').inner_text().strip() == 'dc4')
    assert _sent(app, f'/api/ha/members/{B}/site') == [{'site': 'dc9'}]
    assert _sent(app, f'/api/ha/members/{OWN}/site') == [{'site': 'dc1'}]
    assert _sent(app, f'/api/ha/members/{W}/site') == [{'site': 'dc4'}]
    assert not app.errors, app.errors


def test_runtime_a_refused_site_shows_on_its_row(open_app):
    refusal = (409, {'code': 'HA_AUTO_MODE', 'error': PENDING})
    app = open_app(auto=_leader(), split=_split(), site_refusal=refusal)
    page = app.page
    panel = _open_ha(app, 'active')
    panel.locator(f'[data-ha-member="{C}"]').get_by_role('button', name=f'Site of {C_URL}').click()
    page.fill('#pgha-member-site', 'dc7')
    row = panel.locator(f'[data-ha-member-form-row="{C}"]')
    row.get_by_role('button', name='Save').click()
    note = row.locator('[data-ha-member-refused="HA_AUTO_MODE"]')
    note.wait_for(timeout=3000)
    assert note.inner_text().strip() == PENDING
    assert not any(PENDING in t for t in _toasts(page))
    # typing again takes the note away; Cancel closes the form
    page.fill('#pgha-member-site', 'dc8')
    assert row.locator('[data-ha-member-refused]').count() == 0
    row.get_by_role('button', name='Cancel').click()
    row.wait_for(state='detached', timeout=3000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('mode', ['auto', 'manual'])
def test_runtime_vote_and_may_lead_want_the_password(open_app, mode):
    """A switch opens the form under its row with what the change does and the password; the
    request carries the one flag and the password. In automatic mode it is in force once a
    majority holds it, in manual mode the next switch takes it in."""
    auto = _leader() if mode == 'auto' else _leader(mode='manual', leader=False, holds_lease=False, holder=None, lease_left=None)
    app = open_app(auto=auto, split=_split())
    page = app.page
    panel = _open_ha(app, 'active')
    b = panel.locator(f'[data-ha-member="{B}"]')
    b.get_by_role('switch', name=f'Vote: {B_URL}').click()
    form = panel.locator(f'[data-ha-member-form-row="{B}"] [data-ha-member-form="voter"]')
    form.wait_for(timeout=3000)
    assert form.inner_text().startswith(f'{B_URL} no longer votes. In automatic mode this is a change of the voter config')
    save = form.get_by_role('button', name='Save')
    assert save.is_disabled(), 'it waits for the password'
    page.fill('#pgha-member-password', 'wrong')
    save.click()
    note = form.locator('[data-ha-reauth="HA_REAUTH"]')
    note.wait_for(timeout=3000)
    assert note.inner_text().strip() == 'Incorrect password'
    assert page.input_value('#pgha-member-password') == ''
    page.fill('#pgha-member-password', PASSWORD)
    save.click()
    want = ('Saved - in force once a majority of the members holds the change' if mode == 'auto'
            else 'Saved - the next switch to automatic failover takes it into the voter config')
    assert _wait_for_toast(page, want), _toasts(page)
    assert _until(page, lambda: b.get_by_role('switch', name=f'Vote: {B_URL}').get_attribute('aria-checked') == 'false')
    # without a vote it leads no more
    assert _until(page, lambda: b.get_by_role('switch', name=f'May lead: {B_URL}').is_disabled())
    panel.locator('[data-ha-split-self]').get_by_role('switch', name='May lead: this instance').click()
    me = panel.locator('[data-ha-split] [data-ha-member-form="may_lead"]')
    assert me.inner_text().startswith('this instance no longer takes over on its own when the leader fails')
    page.fill('#pgha-member-password', PASSWORD)
    me.get_by_role('button', name='Save').click()
    assert _until(page, lambda: panel.locator('[data-ha-split-self-may-lead]').get_attribute('data-ha-split-self-may-lead') == 'no')
    assert _sent(app, f'/api/ha/members/{B}/vote') == [{'voter': False, 'user_password': 'wrong'},
                                                     {'voter': False, 'user_password': PASSWORD}]
    assert _sent(app, f'/api/ha/members/{OWN}/vote') == [{'may_lead': False, 'user_password': PASSWORD}]
    assert not app.errors, app.errors


def test_runtime_a_refused_vote_shows_on_its_row(open_app):
    refusal = (409, {'code': 'HA_VOTE_REFUSED', 'error': 'Without this vote the group would have fewer than 3 votes, too '
                                                         'few for automatic failover. Add a member or a witness first'})
    app = open_app(auto=_leader(), split=_split(), vote_refusal=refusal)
    page = app.page
    panel = _open_ha(app, 'active')
    panel.locator(f'[data-ha-member="{B}"]').get_by_role('switch', name=f'May lead: {B_URL}').click()
    form = panel.locator(f'[data-ha-member-form-row="{B}"] [data-ha-member-form="may_lead"]')
    assert form.inner_text().startswith(f'{B_URL} no longer takes over on its own when the leader fails')
    page.fill('#pgha-member-password', PASSWORD)
    form.get_by_role('button', name='Save').click()
    note = form.locator('[data-ha-member-refused="HA_VOTE_REFUSED"]')
    note.wait_for(timeout=3000)
    assert note.inner_text().strip() == refusal[1]['error']
    assert _sent(app, f'/api/ha/members/{B}/vote') == [{'may_lead': False, 'user_password': PASSWORD}]
    # the switch opens and closes its own form
    panel.locator(f'[data-ha-member="{B}"]').get_by_role('switch', name=f'May lead: {B_URL}').click()
    panel.locator(f'[data-ha-member-form-row="{B}"]').wait_for(state='detached', timeout=3000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('case', ['pending', 'transfer', 'no_lease'])
def test_runtime_the_controls_are_held_when_the_server_would_refuse(open_app, case):
    """A pending switch, a hand-over (the status line says changes are paused) and a leader without
    its lease: the switches, the site and Make leader are held, each saying why."""
    more = {'pending': dict(mode='auto_pending', switch_waiting=[C], pending={'by': OWN, 'by_url': '', 'own': True,
                                                                            'since': '2026-10-04T10:02:11+00:00', 'text': 'x'}),
            'transfer': dict(transfer={'to': B, 'to_url': B_URL, 'phase': 'catchup', 'left': 8.4}),
            'no_lease': dict(holds_lease=False, holder=None, lease_left=None)}[case]
    app = open_app(auto=_leader(**more), split=_split())
    panel = _open_ha(app, 'active')
    why = {'pending': 'Not while a switch to automatic failover is pending',
           'transfer': 'Not while the lead is handed to another member',
           'no_lease': 'No leader at the moment - changes and automation are paused'}[case]
    b = panel.locator(f'[data-ha-member="{B}"]')
    for control in (b.get_by_role('switch', name=f'Vote: {B_URL}'), b.get_by_role('switch', name=f'May lead: {B_URL}'),
                    b.get_by_role('button', name=f'Site of {B_URL}'),
                    panel.locator('[data-ha-split-self]').get_by_role('switch', name='May lead: this instance')):
        assert control.is_disabled() and control.get_attribute('title') == why
    lead = b.locator('[data-ha-make-leader]')
    assert lead.count() == 1 and lead.is_disabled() and lead.get_attribute('title') == why
    if case == 'transfer':
        assert panel.locator('[data-ha-auto-transfer]').inner_text().strip() == (
            f'Handing the lead to {B_URL} - changes are paused for up to 9 s')
        assert panel.locator('[data-ha-auto-transfer]').get_attribute('data-ha-auto-transfer') == 'catchup'
    assert not _writes(app)
    assert not app.errors, app.errors


def test_runtime_make_leader_on_the_leader(open_app):
    """Every data voter with a vote: a button where the leader would hand over, its reason where not,
    nothing on the witness. The word and the password; the old leader restarts as a standby."""
    app = open_app(auto=_leader(), split=_split())
    page = app.page
    panel = _open_ha(app, 'active')
    b, c = panel.locator(f'[data-ha-member="{B}"]'), panel.locator(f'[data-ha-member="{C}"]')
    assert c.locator('[data-ha-make-leader]').count() == 0
    assert c.locator('[data-ha-make-leader-why]').inner_text().strip() == f'{C_URL} does not answer the renewals of this leader'
    w = panel.locator(f'[data-ha-member-witness="{W}"]')
    assert w.locator('[data-ha-make-leader], [data-ha-make-leader-why]').count() == 0
    b.locator('[data-ha-make-leader]').click()
    form = panel.locator(f'[data-ha-member-form-row="{B}"] [data-ha-member-form="leader"]')
    form.wait_for(timeout=3000)
    assert form.inner_text().startswith(f'{B_URL} takes over the lead. Changes pause while it catches up')
    assert 'Type LEADER to confirm' in form.inner_text()
    go = form.get_by_role('button', name='Make leader')
    page.fill('#pgha-member-password', PASSWORD)
    page.fill('#pgha-member-typed', 'leader')
    assert go.is_disabled(), 'the word is exact'
    page.fill('#pgha-member-typed', 'LEADER')
    assert go.is_enabled()
    before = len(app.loads)
    go.click()
    app.see(RESTARTING, timeout=3000)
    assert _sent(app, '/api/ha/make-leader') == [{'target': B, 'confirm': 'LEADER', 'user_password': PASSWORD}]
    app.wait_for_reload(before)
    assert app.page.locator('[data-ha-banner="classic"]').is_visible()
    assert not app.errors, app.errors


@pytest.mark.parametrize('answer', ['refused', 'catching'])
def test_runtime_make_leader_refused_or_still_catching_up(open_app, answer):
    said = {'refused': (409, {'code': 'HA_TRANSFER_REFUSED',
                              'error': f'{B_URL} could not catch up with the configuration of this leader within 10 s - '
                                       'it goes on leading, and writes are open again'}),
            'catching': (200, {'success': True, 'result': 'catching up', 'target': B})}[answer]
    app = open_app(auto=_leader(), split=_split(), make_answers=[said])
    page = app.page
    panel = _open_ha(app, 'active')
    panel.locator(f'[data-ha-member="{B}"] [data-ha-make-leader]').click()
    row = panel.locator(f'[data-ha-member-form-row="{B}"]')
    page.fill('#pgha-member-typed', 'LEADER')
    page.fill('#pgha-member-password', PASSWORD)
    row.get_by_role('button', name='Make leader').click()
    if answer == 'refused':
        note = row.locator('[data-ha-member-refused="HA_TRANSFER_REFUSED"]')
        note.wait_for(timeout=3000)
        assert note.inner_text().strip() == said[1]['error']
        # the word stays, the password went with the request
        assert page.input_value('#pgha-member-typed') == 'LEADER' and page.input_value('#pgha-member-password') == ''
    else:
        assert _wait_for_toast(page, 'The member is catching up - the lead is handed over once it holds the configuration of now')
        row.wait_for(state='detached', timeout=3000)
    assert page.get_by_text(RESTARTING).count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('width', [1280, 390])
def test_runtime_the_reason_make_leader_is_not_offered_wraps_at_words(open_app, width):
    """In the narrow last cell of a wide table a text that may break anywhere stood one letter per line."""
    auto = _leader(transfer={'to': B, 'to_url': B_URL, 'phase': 'catchup', 'left': 8.4})
    why = 'Not while the lead is handed to another member - try again once the hand-over is through'
    for row in auto['members'][:2]:
        row.update(make_leader=False, make_leader_why=why)
    app = open_app(auto=auto, split=_split())
    app.page.set_viewport_size({'width': width, 'height': 900})
    panel = _open_ha(app, 'active')
    for iid in (B, C):
        box = panel.locator(f'[data-ha-make-leader-why="{iid}"]').bounding_box()
        assert box['width'] >= 150 and box['height'] < 120, (iid, box)
    assert not app.errors, app.errors


@pytest.mark.parametrize('width', [1280, 390])
def test_runtime_a_member_form_goes_under_the_table_and_is_not_cut_off(open_app, width):
    """The form was a row of the table: as wide as the table, and its scroller cut off the text the
    admin confirms with the password. Under the table it takes the width of the card."""
    app = open_app(auto=_leader(), split=_split())
    app.page.set_viewport_size({'width': width, 'height': 900})
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-members]')
    for what, opener in (('voter', panel.locator(f'[data-ha-member="{B}"] [data-ha-auto-toggle="voter"]')),
                         ('leader', panel.locator(f'[data-ha-member="{B}"] [data-ha-make-leader]')),
                         ('site', panel.locator(f'[data-ha-member-witness="{W}"]').get_by_role('button', name=f'Site of {W_URL}'))):
        opener.evaluate('el => el.click()')
        form = card.locator(f'[data-ha-member-form="{what}"]')
        form.wait_for(timeout=3000)
        assert form.evaluate('el => !el.closest(".overflow-x-auto") && !el.closest("table")'), what
        outer = card.bounding_box()
        for part in (form.locator('p').first, form.locator('button').last):
            box = part.bounding_box()
            assert outer['x'] - 1 <= box['x'] and box['x'] + box['width'] <= outer['x'] + outer['width'] + 1, (what, box, outer)
        form.get_by_role('button', name='Cancel').click()
        form.wait_for(state='detached', timeout=3000)
    assert not _writes(app)
    assert not app.errors, app.errors


def _member_auto(**more):
    kw = dict(mode='auto', holds_lease=False, holder=B, lease_left=14.2, acting=False, epoch=7,
              members=[_row('b', holds=True, mode='auto'), _row('c', mode='auto')], **_lead())
    kw.update(more)
    return _auto(**kw)


def test_runtime_make_leader_on_a_member_for_itself(open_app):
    """A member of an automatic group that may lead: no promote (the group elects), Make leader for
    itself through its own instance, and it restarts as the leader once it won."""
    app = open_app(role='standby', members=_standby_members(), split=_split(),
                   auto=_member_auto(make_leader={'phrase': 'LEADER', 'self': True}))
    page = app.page
    panel = _open_ha(app, 'standby')
    assert panel.get_by_role('button', name='Promote to active').count() == 0
    assert panel.get_by_role('button', name='Unpair').count() == 1
    card = panel.locator('[data-ha-lead="self"]')
    assert card.locator('h4').inner_text().strip() == 'Who leads'
    assert _text(card).startswith('Who leads This instance may lead its group.')
    card.get_by_role('button', name='Make this instance leader').click()
    form = card.locator('[data-ha-member-form="leader"]')
    assert form.inner_text().startswith('This instance asks the leader to hand it the lead')
    go = form.get_by_role('button', name='Make this instance leader')
    page.fill('#pgha-member-typed', 'LEADER')
    assert go.is_disabled(), 'it waits for the password'
    page.fill('#pgha-member-password', PASSWORD)
    before = len(app.loads)
    go.click()
    app.see(RESTARTING, timeout=3000)
    assert _sent(app, '/api/ha/make-leader') == [{'confirm': 'LEADER', 'user_password': PASSWORD}]
    app.wait_for_reload(before)
    assert app.page.locator('[data-ha-banner]').count() == 0
    assert not app.errors, app.errors


def test_runtime_no_majority_from_here_brings_force_leader(open_app):
    """The election finds no majority: the refusal stays in the form, and the status read right after
    it offers Force leader."""
    refusal = (409, {'code': 'HA_TRANSFER_REFUSED', 'error': 'Only 1 of the 2 votes a leader needs answer: no majority can '
                                                             'be reached from here. If the members that do not answer are '
                                                             'down for good, Force leader takes over without them'})
    app = open_app(role='standby', members=_standby_members(), split=_split(), make_answers=[refusal],
                   auto=_member_auto(holder=None, lease_left=None, make_leader={'phrase': 'LEADER', 'self': True}))
    page = app.page
    panel = _open_ha(app, 'standby')
    assert panel.locator('[data-ha-force]').count() == 0
    panel.get_by_role('button', name='Make this instance leader').click()
    page.fill('#pgha-member-typed', 'LEADER')
    page.fill('#pgha-member-password', PASSWORD)
    app.server.auto['force_leader'] = _offered()
    app.server.auto['last_campaign'] = {'ago': 1.2, 'kind': 'make_leader', 'reached': 1, 'majority': 2, 'reasons': [],
                                        'unreachable': True}
    panel.locator('[data-ha-member-form="leader"]').get_by_role('button', name='Make this instance leader').click()
    note = panel.locator('[data-ha-member-refused="HA_TRANSFER_REFUSED"]')
    note.wait_for(timeout=3000)
    assert note.inner_text().strip() == refusal[1]['error']
    panel.locator('[data-ha-force="auto"]').wait_for(timeout=3000)
    assert panel.locator('[data-ha-auto-campaign]').inner_text().strip() == (
        'Last election from here 1 s ago: 1 of the 2 votes needed answered')
    assert not app.errors, app.errors


def test_runtime_force_leader_where_it_is_offered(open_app):
    """The danger zone: the server's warning, every member it would cut out ticked one by one, a
    reason, the phrase and the password. Then the restart, and on the forced active what it did."""
    forced = {'epoch': 9, 'at': '2026-10-04T10:12:00+00:00', 'by': 'admin', 'reason': 'site A burned down',
              'case': 'auto', 'cut_out': [B, W], 'onboot_left': {'c1': [101, 102]}}
    after = {'auto': _auto(mode='manual', members=[_row('c')], **_lead(forced=forced)), 'members': [_member('c')]}
    app = open_app(role='standby', members=_standby_members(), split=_split(), after_restart=after,
                   auto=_member_auto(holder=None, lease_left=None, force_leader=_offered()))
    page = app.page
    panel = _open_ha(app, 'standby')
    zone = panel.locator('[data-ha-force="auto"]')
    zone.wait_for(timeout=3000)
    assert zone.locator('h4').inner_text().strip() == 'Danger zone: Force leader'
    assert zone.locator('[data-ha-force-case]').inner_text().strip() == (
        'No leader was heard for 35 s, and the last election from here reached 1 of the 2 votes needed.')
    assert zone.locator('[data-ha-force-form]').count() == 0
    zone.get_by_role('button', name='Force leader...').click()
    assert zone.locator('[data-ha-force-warning]').inner_text().strip() == FORCE_WARNING
    labels = zone.locator('[data-ha-force-member]').evaluate_all('r => r.map(x => x.innerText.trim())')
    assert labels == [f'{B_URL} is powered off or destroyed', f'{W_URL} (Witness) is powered off or destroyed']
    go = zone.get_by_role('button', name='Force leader', exact=True)
    zone.locator(f'[data-ha-force-member="{B}"] input').check()
    page.fill('#pgha-force-reason', 'site A burned down')
    page.fill('#pgha-force-typed', 'FORCE LEADER')
    page.fill('#pgha-force-password', PASSWORD)
    assert go.is_disabled(), 'every member it cuts out is ticked'
    zone.locator(f'[data-ha-force-member="{W}"] input').check()
    assert go.is_enabled()
    page.fill('#pgha-force-typed', 'force leader')
    assert go.is_disabled(), 'the phrase is exact'
    page.fill('#pgha-force-typed', 'FORCE LEADER')
    page.fill('#pgha-force-reason', '   ')
    assert go.is_disabled(), 'it wants a reason'
    page.fill('#pgha-force-reason', ' site A burned down ')
    before = len(app.loads)
    go.click()
    app.see(RESTARTING, timeout=3000)
    assert _sent(app, '/api/ha/force-leader') == [{'confirm': 'FORCE LEADER', 'cut_out': [B, W],
                                                   'reason': 'site A burned down', 'user_password': PASSWORD}]
    app.wait_for_reload(before)
    panel = _open_ha(app, 'active')
    box = panel.locator('[data-ha-forced="9"]')
    box.wait_for(timeout=3000)
    assert box.inner_text().startswith('Forced to lead at epoch 9 by admin · ')
    assert box.locator('[data-ha-forced-reason]').inner_text().strip() == 'Reason: site A burned down'
    assert box.locator('[data-ha-forced-cut]').inner_text().strip() == (
        'Cut out as powered off or destroyed: bbbbbbbb, eeeeeeee')
    assert box.locator('[data-ha-forced-onboot]').inner_text().strip() == (
        'Autostart is still to be switched off on these VMs (cluster: VM ids), tried again with every look at the '
        'group: c1: 101, 102')
    assert 'comes back only through the switch' in box.inner_text()
    assert panel.locator('[data-ha-force]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_refused_force_and_a_wrong_password_stay_in_the_zone(open_app):
    refusal = (409, {'code': 'HA_FORCE_REFUSED', 'error': f'These answer and are not cut out: {B_URL}'})
    app = open_app(role='standby', members=_standby_members(), split=_split(), force_answers=[refusal],
                   auto=_member_auto(holder=None, lease_left=None, force_leader=_offered()))
    page = app.page
    panel = _open_ha(app, 'standby')
    zone = panel.locator('[data-ha-force]')
    zone.get_by_role('button', name='Force leader...').click()
    for who in (B, W):
        zone.locator(f'[data-ha-force-member="{who}"] input').check()
    page.fill('#pgha-force-reason', 'gone')
    page.fill('#pgha-force-typed', 'FORCE LEADER')
    page.fill('#pgha-force-password', 'wrong')
    go = zone.get_by_role('button', name='Force leader', exact=True)
    go.click()
    zone.locator('[data-ha-reauth="HA_REAUTH"]').wait_for(timeout=3000)
    assert page.input_value('#pgha-force-password') == '' and page.input_value('#pgha-force-typed') == 'FORCE LEADER'
    page.fill('#pgha-force-password', PASSWORD)
    go.click()
    note = zone.locator('[data-ha-force-refused="HA_FORCE_REFUSED"]')
    note.wait_for(timeout=3000)
    assert note.inner_text().strip() == refusal[1]['error']
    assert page.get_by_text(RESTARTING).count() == 0
    # Cancel takes everything typed with it
    zone.get_by_role('button', name='Cancel').click()
    zone.get_by_role('button', name='Force leader...').click()
    assert page.input_value('#pgha-force-reason') == '' and page.input_value('#pgha-force-typed') == ''
    assert zone.locator('input[type="checkbox"]:checked').count() == 0
    assert not app.errors, app.errors


def test_runtime_an_offer_the_server_takes_back_closes_the_zone(open_app):
    app = open_app(role='standby', members=_standby_members(), split=_split(),
                   auto=_member_auto(holder=None, lease_left=None, force_leader=_offered()))
    page = app.page
    panel = _open_ha(app, 'standby')
    zone = panel.locator('[data-ha-force]')
    zone.get_by_role('button', name='Force leader...').click()
    zone.locator(f'[data-ha-force-member="{B}"] input').check()
    page.fill('#pgha-force-reason', 'gone')
    # a member answers again: the next status no longer offers it
    app.server.auto['force_leader'] = _lead()['force_leader']
    panel.get_by_role('button', name='Sync now').click()
    zone.wait_for(state='detached', timeout=4000)
    # offered again later: the form starts closed and empty
    app.server.auto['force_leader'] = _offered(cut=[{'instance_id': W, 'url': W_URL, 'kind': 'witness'}])
    panel.get_by_role('button', name='Sync now').click()
    zone.wait_for(timeout=4000)
    assert zone.locator('[data-ha-force-form]').count() == 0
    zone.get_by_role('button', name='Force leader...').click()
    assert page.input_value('#pgha-force-reason') == ''
    assert zone.locator('[data-ha-force-member]').count() == 1
    assert not _sent(app, '/api/ha/force-leader')
    assert not app.errors, app.errors


@pytest.mark.parametrize('case', ['pending', 'unknown'])
def test_runtime_the_other_ways_into_force_leader(open_app, case):
    """A pending switch whose maker is gone, and a member whose only way out is Force leader: plain
    promote and unpair are gone where the server offers it, and way_out says why."""
    way_out = ('This instance holds a manual voter config that follows an automatic one, and no majority of the group '
               'has confirmed it: the group may still fail over automatically elsewhere. It is not promoted or unpaired '
               'by hand - let it reach the group, or use Force leader if the group lost its majority for good')
    mode = 'auto_pending' if case == 'pending' else 'manual'
    app = open_app(role='standby', members=_standby_members(), split=_split(),
                   auto=_member_auto(mode=mode, holder=None, lease_left=None, force_leader=_offered(case=case),
                                     way_out=way_out if case == 'unknown' else ''))
    panel = _open_ha(app, 'standby')
    zone = panel.locator(f'[data-ha-force="{case}"]')
    zone.wait_for(timeout=3000)
    assert zone.locator('[data-ha-force-case]').inner_text().strip() == {
        'pending': 'This member holds a switch to automatic failover whose maker no longer answers.',
        'unknown': 'This member is not promoted or unpaired by hand (see above), and no leader answers.'}[case]
    assert panel.get_by_role('button', name='Promote to active').count() == 0
    if case == 'unknown':
        note = panel.locator('[data-ha-way-out]')
        assert note.get_attribute('data-ha-way-out') == 'force' and note.inner_text().strip() == way_out
        assert panel.get_by_role('button', name='Unpair').count() == 0
    else:
        assert panel.locator('[data-ha-way-out]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_way_out_without_the_offer_keeps_promote_and_says_why(open_app):
    """The status goes by what the watch heard last; the route asks the members again. Without the
    offer promote and unpair stay, and the note says what the server will check."""
    way_out = 'It is not promoted or unpaired by hand - let it reach the group'
    app = open_app(role='standby', members=_standby_members(), split=_split(),
                   auto=_member_auto(mode='manual', holder=None, lease_left=None, way_out=way_out))
    panel = _open_ha(app, 'standby')
    note = panel.locator('[data-ha-way-out]')
    assert note.get_attribute('data-ha-way-out') == 'ask' and note.inner_text().strip() == way_out
    assert panel.get_by_role('button', name='Promote to active').count() == 1
    assert panel.get_by_role('button', name='Unpair').count() == 1
    assert panel.locator('[data-ha-force], [data-ha-lead]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_status_line_on_the_leader(open_app):
    change = {'from': B, 'from_url': B_URL, 'to': OWN, 'to_url': A_URL, 'epoch': 7, 'at': '2026-10-04T10:02:11+00:00'}
    auto = _leader(renewed_ago=1.4, leader_change=change, unconfirmed={'count': 6, 'cv': [7, 1288], 'floor': [7, 1282]},
                   change_pending=True)
    auto['members'][0].update(cv=[7, 1288], behind=0, current=True, promised_to=OWN, promised_left=14.2)
    auto['members'][1].update(cv=[7, 1282], behind=6, current=False, promised_to=None, promised_left=None,
                              unreached_from=[{'cluster': 'c1', 'name': 'lab', 'node': 'pve1'},
                                              {'cluster': 'c1', 'name': 'lab', 'node': 'pve2'}])
    app = open_app(auto=auto, split=_split())
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    assert card.locator('[data-ha-auto-leader]').inner_text().strip() == (
        'Leader: this instance (epoch 7) · lease valid for 15 s · lease renewed 1 s ago')
    assert card.locator('[data-ha-auto-unconfirmed]').inner_text().strip() == '6 changes on the leader are not yet on a majority'
    assert card.locator('[data-ha-auto-change-pending]').inner_text().strip() == 'A change of the voter config is on its way'
    last = card.locator('[data-ha-auto-last-change]')
    assert re.fullmatch(rf'Last leader change {TIME} \({re.escape(B_URL)} -> {re.escape(A_URL)}\)',
                        last.inner_text().strip()), last.inner_text()
    assert last.get_attribute('data-ha-auto-last-change') == '7' and last.get_attribute('title')
    for absent in ('promise', 'behind', 'planned', 'transfer', 'campaign'):
        assert card.locator(f'[data-ha-auto-{absent}]').count() == 0, absent
    b, c = panel.locator(f'[data-ha-member="{B}"]'), panel.locator(f'[data-ha-member="{C}"]')
    assert b.locator('[data-ha-auto-promised]').inner_text().strip() == 'promised to this instance, 14 s'
    assert b.locator('[data-ha-auto-cv]').inner_text().strip() == 'config 7.1288 (current)'
    assert c.locator('[data-ha-auto-cv]').inner_text().strip() == 'config 7.1282 · behind by 6 changes'
    assert c.locator('[data-ha-auto-cv]').get_attribute('data-ha-auto-behind') == '6'
    assert c.locator('[data-ha-auto-unreached]').inner_text().strip() == 'nodes cannot reach it: pve1 (lab), pve2 (lab)'
    assert c.locator('[data-ha-auto-promised]').count() == 0
    assert not app.errors, app.errors


def test_runtime_changes_in_another_epoch_are_not_counted(open_app):
    app = open_app(auto=_leader(unconfirmed={'count': None, 'cv': [8, 3], 'floor': [7, 1290]},
                                leader_change={'from': None, 'from_url': '', 'to': OWN, 'to_url': A_URL, 'epoch': 8,
                                               'at': '2026-10-04T10:02:11+00:00'}), split=_split())
    panel = _open_ha(app, 'active')
    assert panel.locator('[data-ha-auto-unconfirmed]').inner_text().strip() == (
        'Changes on the leader up to 8.3 are not yet on a majority')
    assert panel.locator('[data-ha-auto-unconfirmed]').get_attribute('data-ha-auto-unconfirmed') == 'epoch'
    assert re.fullmatch(rf'Last leader change {TIME} \(to {re.escape(A_URL)}\)',
                        panel.locator('[data-ha-auto-last-change]').inner_text().strip())
    assert not app.errors, app.errors


@pytest.mark.parametrize('behind', [3, 0])
def test_runtime_the_status_line_on_a_member(open_app, behind):
    auto = _member_auto(renewed_ago=2.2, promise={'to': B, 'to_url': B_URL, 'left': 14.2}, leader_cv=[7, 1288],
                        behind=behind, planned_restart={'by': B, 'by_url': B_URL, 'hold_left': 77.5},
                        last_campaign={'ago': 40.2, 'kind': 'timer', 'reached': 1, 'majority': 2, 'reasons': [],
                                       'unreachable': True})
    auto['members'][0].update(cv=[7, 1288], behind=0, current=True)
    app = open_app(role='standby', members=_standby_members(), auto=auto, split=_split())
    panel = _open_ha(app, 'standby')
    card = panel.locator('[data-ha-auto]')
    assert card.locator('[data-ha-auto-leader]').inner_text().strip() == (
        f'Leader: {B_URL} (epoch 7) · lease valid for 14 s · lease renewed 2 s ago')
    assert card.locator('[data-ha-auto-promise]').inner_text().strip() == f'Vote promised to {B_URL} for 14 s'
    assert card.locator('[data-ha-auto-behind]').inner_text().strip() == (
        'Behind the leader by 3 changes' if behind else 'In step with the leader')
    assert card.locator('[data-ha-auto-planned]').inner_text().strip() == (
        f'Leader {B_URL} restarting (planned) - the members hold its lease for 78 s')
    assert card.locator('[data-ha-auto-campaign]').inner_text().strip() == (
        'Last election from here 40 s ago: 1 of the 2 votes needed answered')
    assert card.locator('[data-ha-auto-unconfirmed], [data-ha-auto-change-pending]').count() == 0
    assert panel.locator(f'[data-ha-member="{B}"] [data-ha-auto-cv]').inner_text().strip() == 'config 7.1288 (current)'
    assert not _writes(app)
    assert not app.errors, app.errors


# -- the banners, for every signed-in user ------------------------------------------------------------

def _banner(app, kind):
    return app.page.locator(f'[data-ha-lease-banner="{kind}"]')


VIEWER_PERMS = ['cluster.view', 'node.view', 'vm.view', 'ha.view']


@pytest.mark.parametrize('who', ['admin', 'viewer', 'ha.view'])
@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_no_leader_reaches_every_user_in_every_layout(open_app, who, layout):
    kw = {'admin': who == 'admin', 'permissions': VIEWER_PERMS if who == 'ha.view' else []}
    app = open_app(layout=layout, lease_banner={'automatic': True, 'no_leader': True}, **kw)
    line = _banner(app, 'no-leader')
    line.wait_for(timeout=5000)
    assert line.get_attribute('data-ha-lease-banner-layout') == ('cloud' if layout == 'cloud' else 'classic')
    assert line.inner_text().strip().startswith(
        'No leader at the moment - changes and automation are paused. Consoles keep working.')
    # it stays while it holds: nothing to close; the HA tab only for admins
    assert line.get_by_role('button', name='Close').count() == 0
    assert line.get_by_role('button', name='High Availability').count() == (1 if who == 'admin' else 0)
    if who != 'admin':
        assert line.locator('button').count() == 0
    if who != 'admin' and layout != 'cloud':
        app.open_settings()
        assert app.page.locator('button', has_text='High Availability').count() == 0
    assert not _writes(app)
    assert not app.errors, app.errors


def test_runtime_the_takeover_counts_down_and_the_admin_gets_to_the_tab(open_app):
    app = open_app(lease_banner={'automatic': True, 'takeover': {'leader': B_URL, 'resume_in': 12}})
    line = _banner(app, 'takeover')
    line.wait_for(timeout=5000)
    first = line.inner_text().strip()
    assert re.fullmatch(rf'Leader {re.escape(B_URL)} is taking over - changes resume in 1[12] s\.\s*High Availability',
                        first), first
    app.page.wait_for_timeout(2300)
    later = int(re.search(r'resume in (\d+) s', line.inner_text()).group(1))
    assert later <= 10, line.inner_text()
    line.get_by_role('button', name='High Availability').click()
    app.page.locator('[data-ha-role="active"]').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_the_change_of_the_leader_can_be_closed_and_a_later_one_shows(open_app):
    """For ten minutes after a change (the server stops sending it then); closed, it stays closed,
    and the next change shows again. The banner is read every few seconds in an automatic group."""
    changed = {'to': B_URL, 'from': A_URL, 'at': '2026-10-04T10:02:11+00:00', 'epoch': 8}
    app = open_app(role='standby', members=_standby_members(), admin=False,
                   lease_banner={'automatic': True, 'leader_changed': changed})
    line = _banner(app, 'leader-changed')
    line.wait_for(timeout=5000)
    assert re.fullmatch(rf'Leader changed to {re.escape(B_URL)} at {TIME}\.', line.inner_text().strip()), line.inner_text()
    line.get_by_role('button', name='Close').click()
    line.wait_for(state='detached', timeout=3000)
    reads = app.server.calls.count(('GET', '/api/auth/check'))
    app.server.lease_banner = {'automatic': True, 'takeover': {'leader': C_URL, 'resume_in': 30},
                               'leader_changed': dict(changed, to=C_URL, epoch=9, at='2026-10-04T10:09:40+00:00')}
    _banner(app, 'takeover').wait_for(timeout=12000)
    assert app.server.calls.count(('GET', '/api/auth/check')) > reads
    assert C_URL in _banner(app, 'leader-changed').inner_text()
    # the standby banner of the member is there as before
    assert app.page.locator('[data-ha-banner="classic"]').count() == 1
    assert not app.errors, app.errors


def test_runtime_a_manual_group_gets_no_lease_banner(open_app):
    # lease_banner() sends nothing outside an automatic group; keys without automatic say nothing either
    app = open_app(lease_banner={'no_leader': True, 'leader_changed': {'to': B_URL, 'at': '2026-10-04T10:02:11+00:00'}})
    app.page.wait_for_timeout(500)
    assert app.page.locator('[data-ha-lease-banner]').count() == 0
    assert not app.errors, app.errors


def test_runtime_most_users_read_the_banners_without_addresses(open_app):
    """The server names instances only to an admin the HA tab is open to: everyone else hears that a
    leader takes over and when changes resume, and when the leader changed. Closed by the moment."""
    first = '2026-10-04T10:02:11+00:00'
    app = open_app(clock=True, role='standby', members=_standby_members(), admin=False,
                   lease_banner={'automatic': True, 'takeover': {'resume_in': 12}, 'leader_changed': {'at': first}})
    take, changed = _banner(app, 'takeover'), _banner(app, 'leader-changed')
    take.wait_for(timeout=5000)
    assert re.fullmatch(r'A new leader is taking over - changes resume in 1[12] s\.', take.inner_text().strip()), take.inner_text()
    assert re.fullmatch(rf'The leader changed at {TIME}\.', changed.inner_text().strip()), changed.inner_text()
    assert take.locator('button').count() == 0
    changed.get_by_role('button', name='Close').click()
    changed.wait_for(state='detached', timeout=3000)
    # the same moment again stays closed, a later one shows
    app.server.lease_banner = {'automatic': True, 'leader_changed': {'at': first}}
    app.page.clock.run_for(11000)
    take.wait_for(state='detached', timeout=5000)
    assert _banner(app, 'leader-changed').count() == 0
    app.server.lease_banner = {'automatic': True, 'leader_changed': {'at': '2026-10-04T10:09:40+00:00'}}
    app.page.clock.run_for(11000)
    _banner(app, 'leader-changed').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_a_page_on_the_leader_from_before_the_switch_hears_the_banners(open_app):
    """Opened while the group was manual, the leader's page reads the banner every 30 s, and every
    10 s once the group is automatic: no leader shows without a reload. An instance of its own asks
    nothing."""
    app = open_app(clock=True, admin=False)
    page, calls = app.page, app.server.calls
    page.wait_for_timeout(500)
    reads = calls.count(('GET', '/api/auth/check'))
    app.server.lease_banner = {'automatic': True, 'no_leader': True}
    page.clock.run_for(31000)
    _banner(app, 'no-leader').wait_for(timeout=5000)
    assert calls.count(('GET', '/api/auth/check')) > reads
    reads = calls.count(('GET', '/api/auth/check'))
    app.server.lease_banner = {'automatic': True, 'takeover': {'resume_in': 20}}
    page.clock.run_for(11000)
    _banner(app, 'takeover').wait_for(timeout=5000)
    assert _banner(app, 'no-leader').count() == 0 and calls.count(('GET', '/api/auth/check')) > reads
    alone = open_app(clock=True, role='standalone')
    alone.page.wait_for_timeout(500)
    reads = alone.server.calls.count(('GET', '/api/auth/check'))
    alone.page.clock.run_for(65000)
    alone.page.wait_for_timeout(500)
    assert alone.server.calls.count(('GET', '/api/auth/check')) == reads
    assert not app.errors and not alone.errors, app.errors + alone.errors


def test_runtime_a_change_the_leader_refuses_for_want_of_its_lease_reads_the_banner(open_app):
    """503 HA_NO_LEASE (or HA_TRANSFER) on a change: the banner is read again at once, through the
    HA tab's requests and through every other one (authFetch)."""
    app = open_app(auto=_leader(), split=_split(), vote_refusal=(503, {'code': 'HA_NO_LEASE', 'error': NO_LEASE}))
    page, calls = app.page, app.server.calls
    panel = _open_ha(app, 'active')
    reads = calls.count(('GET', '/api/auth/check'))
    app.server.lease_banner = {'automatic': True, 'no_leader': True}
    panel.locator(f'[data-ha-member="{B}"]').get_by_role('switch', name=f'May lead: {B_URL}').click()
    page.fill('#pgha-member-password', PASSWORD)
    panel.locator(f'[data-ha-member-form-row="{B}"]').get_by_role('button', name='Save').click()
    panel.locator('[data-ha-member-refused="HA_NO_LEASE"]').wait_for(timeout=3000)
    _banner(app, 'no-leader').wait_for(timeout=3000)
    assert calls.count(('GET', '/api/auth/check')) > reads
    # the panel's own requests (who is active, pairing, removal)
    serve = f'/api/ha/members/{B}/serve'
    tab = open_app(auto=_leader(), split=_split(), extra={('PUT', serve): (503, {'code': 'HA_NO_LEASE', 'error': NO_LEASE})})
    panel = _open_ha(tab, 'active')
    reads = tab.server.calls.count(('GET', '/api/auth/check'))
    tab.server.lease_banner = {'automatic': True, 'no_leader': True}
    panel.locator(f'[data-ha-member="{B}"] [data-ha-serve]').click()
    _banner(tab, 'no-leader').wait_for(timeout=3000)
    assert ('PUT', serve) in tab.server.calls and tab.server.calls.count(('GET', '/api/auth/check')) > reads
    # a VM action through authFetch
    shutdown = '/api/clusters/c1/vms/pve1/qemu/100/shutdown'
    other = open_app(role='active', clusters=[CLUSTER], resources=[VM],
                     extra={('POST', shutdown): (503, {'code': 'HA_TRANSFER', 'error': 'The lead is being handed on'})})
    page = other.page
    page.on('dialog', lambda d: d.accept())
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    reads = other.server.calls.count(('GET', '/api/auth/check'))
    other.server.lease_banner = {'automatic': True, 'takeover': {'leader': B_URL, 'resume_in': 9}}
    page.locator('button[title="Shutdown"]').first.click()
    _banner(other, 'takeover').wait_for(timeout=3000)
    assert ('POST', shutdown) in other.server.calls and other.server.calls.count(('GET', '/api/auth/check')) > reads
    assert not app.errors, app.errors


# -- the agent VM of a member, on the leader ---------------------------------------------------------

VM_CLUSTERS = [_cluster('c1', 'lab'), _cluster('c2', 'edge'), _cluster('x1', 'pool', kind='other', nodes=(), ready=None)]


def test_runtime_the_agent_vm_of_a_member_one_row_per_ha_cluster(open_app):
    """Every data member (not the witness) and the leader itself: one row per cluster with node HA of
    the Proxmox kind, and one for a cluster the member is still named on; no password, each row saved
    on its own, a number of 100 or more, Remove where one is set."""
    auto = _leader(agent_vmid={'c1': 100})
    auto['members'][0]['agent_vmid'] = {'c1': 104, 'old': 120}
    app = open_app(auto=auto, split=_split(clusters=VM_CLUSTERS), managed=['old'])
    page = app.page
    panel = _open_ha(app, 'active')
    b = panel.locator(f'[data-ha-member="{B}"]')
    assert b.locator('[data-ha-agent-vmid-set]').inner_text().strip() == 'lab: 104, old: 120'
    assert panel.locator(f'[data-ha-member="{C}"] [data-ha-agent-vmid]').count() == 1
    assert panel.locator(f'[data-ha-member-witness="{W}"] [data-ha-agent-vmid]').count() == 0
    b.get_by_role('button', name=f'Agent VM id of {B_URL}').click()
    row = panel.locator(f'[data-ha-member-form-row="{B}"]')
    form = row.locator('[data-ha-member-form="vmid"]')
    form.wait_for(timeout=3000)
    assert form.inner_text().startswith(f'The VM {B_URL} runs as, per cluster with node HA. Should Force leader cut '
                                        'it out, autostart is switched off on that VM')
    assert form.locator('[data-ha-agent-vmid-row]').evaluate_all('r => r.map(x => x.dataset.haAgentVmidRow)') == [
        'c1', 'c2', 'old']
    assert form.locator('input[type="password"]').count() == 0
    assert page.input_value('#pgha-vmid-c1') == '104' and page.input_value('#pgha-vmid-c2') == ''
    c1, c2 = form.locator('[data-ha-agent-vmid-row="c1"]'), form.locator('[data-ha-agent-vmid-row="c2"]')
    assert c1.get_by_role('button', name='Save').is_disabled(), 'nothing changed'
    assert c2.get_by_role('button', name='Remove').count() == 0
    for bad in ('99', '12a', '-5'):
        page.fill('#pgha-vmid-c2', bad)
        assert c2.get_by_role('button', name='Save').is_disabled(), bad
        assert c2.locator('[data-ha-agent-vmid-bad]').inner_text().strip() == 'A VM id is a number of 100 or more'
    page.fill('#pgha-vmid-c2', '205')
    c2.get_by_role('button', name='Save').click()
    assert _wait_for_toast(page, 'VM id saved'), _toasts(page)
    form.locator('[data-ha-agent-vmid-row="old"]').get_by_role('button', name='Remove').click()
    assert _wait_for_toast(page, 'VM id removed'), _toasts(page)
    # the form stays for the next row; the row of the table says what is set now
    assert _until(page, lambda: b.locator('[data-ha-agent-vmid-set]').inner_text().strip() == 'lab: 104, edge: 205')
    assert form.locator('[data-ha-agent-vmid-row="c2"]').get_by_role('button', name='Remove').count() == 1
    assert _sent(app, f'/api/ha/members/{B}/agent-vmid') == [{'cluster_id': 'c2', 'vmid': 205},
                                                            {'cluster_id': 'old', 'vmid': None}]
    form.get_by_role('button', name='Close').click()
    row.wait_for(state='detached', timeout=3000)
    # the leader itself, in the split panel
    me = panel.locator('[data-ha-split-self]')
    assert me.locator('[data-ha-agent-vmid-set]').inner_text().strip() == 'lab: 100'
    me.get_by_role('button', name='Agent VM id of this instance').click()
    own = panel.locator('[data-ha-split] [data-ha-member-form="vmid"]')
    own.wait_for(timeout=3000)
    assert own.inner_text().startswith('The VM this instance runs as')
    own.locator('[data-ha-agent-vmid-row="c1"]').get_by_role('button', name='Remove').click()
    assert _until(page, lambda: me.locator('[data-ha-agent-vmid-set]').count() == 0)
    assert _sent(app, f'/api/ha/members/{OWN}/agent-vmid') == [{'cluster_id': 'c1', 'vmid': None}]
    assert not app.errors, app.errors


@pytest.mark.parametrize('refusal', ['not_shipped', 'no_lease', 'unknown'])
def test_runtime_a_refused_agent_vm_stays_in_its_form(open_app, refusal):
    said = {'not_shipped': (409, {'code': 'HA_AUTO_NOT_SHIPPED', 'error': NOT_SHIPPED}),
            'no_lease': (503, {'code': 'HA_NO_LEASE', 'error': NO_LEASE}),
            'unknown': (404, {'error': 'Cluster not found'})}[refusal]
    app = open_app(auto=_leader(), split=_split(clusters=VM_CLUSTERS), vmid_refusal=said)
    page = app.page
    panel = _open_ha(app, 'active')
    panel.locator(f'[data-ha-member="{C}"]').get_by_role('button', name=f'Agent VM id of {C_URL}').click()
    page.fill('#pgha-vmid-c1', '310')
    form = panel.locator(f'[data-ha-member-form-row="{C}"] [data-ha-member-form="vmid"]')
    form.locator('[data-ha-agent-vmid-row="c1"]').get_by_role('button', name='Save').click()
    note = form.locator(f'[data-ha-member-refused="{said[1].get("code") or "error"}"]')
    note.wait_for(timeout=3000)
    assert note.inner_text().strip() == said[1]['error']
    assert not any(said[1]['error'] in t for t in _toasts(page))
    # what was typed stays; typing again takes the note away
    assert page.input_value('#pgha-vmid-c1') == '310'
    page.fill('#pgha-vmid-c1', '311')
    assert form.locator('[data-ha-member-refused]').count() == 0
    assert _sent(app, f'/api/ha/members/{C}/agent-vmid') == [{'cluster_id': 'c1', 'vmid': 310}]
    assert not app.errors, app.errors


def test_runtime_the_agent_vm_is_held_where_the_server_would_refuse_and_a_member_reads_none(open_app):
    app = open_app(auto=_leader(holds_lease=False, holder=None, lease_left=None), split=_split(clusters=VM_CLUSTERS))
    panel = _open_ha(app, 'active')
    for button in (panel.locator(f'[data-ha-member="{B}"] [data-ha-agent-vmid]'),
                   panel.locator('[data-ha-split-self] [data-ha-agent-vmid]')):
        assert button.is_disabled() and button.get_attribute('title') == 'No leader at the moment - changes and automation are paused'
    # no cluster with node HA: the form says where the VM is named
    bare = open_app(auto=_leader(), split=_split())
    panel = _open_ha(bare, 'active')
    panel.locator(f'[data-ha-member="{B}"] [data-ha-agent-vmid]').click()
    assert panel.locator('[data-ha-agent-vmid-none]').inner_text().strip() == (
        'No cluster with node HA yet - the VM is named per HA cluster.')
    member = open_app(role='standby', members=_standby_members(), split=_split(clusters=VM_CLUSTERS),
                      auto=_member_auto(agent_vmid={'c1': 100}))
    panel = _open_ha(member, 'standby')
    panel.locator('[data-ha-split]').wait_for(timeout=3000)
    assert panel.locator('[data-ha-agent-vmid]').count() == 0
    assert not _writes(app) and not _writes(bare) and not _writes(member)
    assert not app.errors and not bare.errors and not member.errors


# -- every language -----------------------------------------------------------------------------------

def _shown(page, within):
    return page.evaluate('''(sel) => Array.from(document.querySelectorAll(sel)).flatMap(root => [root.innerText,
        ...Array.from(root.querySelectorAll('[title], [aria-label]')).flatMap(e => [e.getAttribute('title'),
        e.getAttribute('aria-label')]).filter(Boolean)]).join('\\n')''', within)


RAW = re.compile(r'\b(haAuto|haNoLeader|haTakeover|haLeaderChanged|haWitness|haZone|pgHa)\w*')


@pytest.mark.parametrize('lang', [lang for lang in LANGS if lang != 'en'])
def test_runtime_no_key_shows_raw_in_any_language(open_app, lang):
    """The leader with the split panel at its worst, a member form open and every banner; then a
    member with the danger zone open and its status line."""
    blocks = _blocks()
    tab = re.search(r"^ +pgHaTab: '(.*)',$", blocks[lang], re.M).group(1)
    auto = _leader(renewed_ago=1.0, unconfirmed={'count': 2, 'cv': [7, 3], 'floor': [7, 1]}, change_pending=True,
                   leader_change={'from': B, 'from_url': B_URL, 'to': OWN, 'to_url': A_URL, 'epoch': 7,
                                  'at': '2026-10-04T10:02:11+00:00'})
    auto['members'][1].update(cv=[7, 1], behind=2, current=False, promised_to=OWN, promised_left=9.0,
                              unreached_from=[{'cluster': 'c1', 'name': 'lab', 'node': 'pve1'}])
    banner = {'automatic': True, 'takeover': {'leader': B_URL, 'resume_in': 20},
              'leader_changed': {'to': B_URL, 'from': A_URL, 'at': '2026-10-04T10:02:11+00:00', 'epoch': 8}}
    app = open_app(language=lang, auto=auto, split=SPLITS['warn'], lease_banner=banner)
    page = app.page
    # the banner's way to the tab, in the language of the page
    button = page.locator('[data-ha-lease-banner="takeover"] button')
    assert button.inner_text().strip() == tab
    button.click()
    panel = page.locator('[data-ha-role="active"]')
    panel.locator('[data-ha-split]').wait_for(timeout=5000)
    panel.locator(f'[data-ha-member="{B}"] [data-ha-make-leader]').click()
    panel.locator('[data-ha-split] summary').first.click()
    shown = _shown(page, '[data-ha-auto], [data-ha-split], [data-ha-members], [data-ha-lead], [data-ha-lease-banner]')
    assert not RAW.search(shown), RAW.search(shown).group(0)
    for key in ('haAutoSplitTitle', 'haAutoMakeLeader', 'haAutoSplitNotReady'):
        assert re.search(r"^ +%s: '(.*)',$" % key, blocks[lang], re.M).group(1).split('{')[0].strip().replace("\\'", "'") in shown, key
    app.server.role = 'standby'
    app.server.members = _standby_members()
    app.server.auto = _member_auto(holder=None, lease_left=None, force_leader=_offered(), behind=1, leader_cv=[7, 4],
                                   last_campaign={'ago': 3.0, 'kind': 'timer', 'reached': 1, 'majority': 2,
                                                  'reasons': [], 'unreachable': True})
    app.server.lease_banner = {'automatic': True, 'no_leader': True}
    page.reload()
    app.wait_for_app()
    page.locator('[data-ha-banner="classic"] button').first.click()
    zone = page.locator('[data-ha-force]')
    zone.wait_for(timeout=5000)
    zone.locator('button').first.click()
    shown = _shown(page, '[data-ha-auto], [data-ha-lead], [data-ha-lease-banner]')
    assert not RAW.search(shown), RAW.search(shown).group(0)
    assert re.search(r"^ +haNoLeader: '(.*)',$", blocks[lang], re.M).group(1).replace("\\'", "'") in shown
    assert not app.errors, app.errors


def _fragment(value):
    """The longest part of a text between its placeholders."""
    return max((p.strip() for p in re.split(r'\{\w+\}', value)), key=len)


@pytest.mark.parametrize('lang', [lang for lang in LANGS if lang != 'en'])
def test_runtime_the_agent_vm_and_the_banners_without_addresses_in_every_language(open_app, lang):
    blocks = _blocks()
    app = open_app(language=lang, auto=_leader(), split=_split(clusters=VM_CLUSTERS),
                   lease_banner={'automatic': True, 'takeover': {'resume_in': 20},
                                 'leader_changed': {'at': '2026-10-04T10:02:11+00:00'}})
    page = app.page
    _banner(app, 'takeover').wait_for(timeout=5000)
    shown = _shown(page, '[data-ha-lease-banner]')
    assert not RAW.search(shown), RAW.search(shown).group(0)
    for key in ('haTakeoverUnnamed', 'haLeaderChangedAt'):
        assert _fragment(_value(blocks[lang], key)) in shown, key
    page.locator('[data-ha-lease-banner="takeover"] button').click()
    panel = page.locator('[data-ha-role="active"]')
    panel.locator(f'[data-ha-member="{B}"] [data-ha-agent-vmid]').click()
    panel.locator('[data-ha-member-form="vmid"]').wait_for(timeout=5000)
    page.fill('#pgha-vmid-c2', '9')
    shown = _shown(page, '[data-ha-members], [data-ha-split]')
    assert not RAW.search(shown), RAW.search(shown).group(0)
    assert _value(blocks[lang], 'haAutoVmidDesc').replace('{name}', B_URL) in shown
    for key in ('haAutoVmidOpen', 'haAutoVmidBad'):
        assert _value(blocks[lang], key) in shown, key
    assert page.get_attribute('#pgha-vmid-c1', 'placeholder') == _value(blocks[lang], 'haAutoVmidPlaceholder')
    assert panel.get_by_role('button', name=_value(blocks[lang], 'haAutoVmidOf').replace('{name}', C_URL)).count() == 1
    assert not app.errors, app.errors
