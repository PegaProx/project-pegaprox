"""Stage 2 of the instance group in the web UI: automatic failover, the witness, the time zone (#625).

The HA tab of the leader gets a card for automatic failover (the switch with its preconditions
as a checklist, the lease length, whom a pending switch waits for, quarantined voters), one for
the witness (a one-time code with the commands for the witness host, then the witness itself
and its removal) and one for the time zone the schedules run in. The members table gets the
columns the voter config adds. A member reads all of it and changes nothing.

A release without automatic failover says auto: null in the status and refuses the switch and
the witness code with 409 HA_AUTO_NOT_SHIPPED: that is a note on the card, never an error toast
(the beta badge of the release that offers it, tests/test_ha_beta_ui.py). The
runtime tests drive the built bundle in headless Chromium against the fake server of
test_ha_ui.py, with the stage 2 routes answering in the order of their checks in
pegaprox/api/ha.py. They skip where Playwright is not installed.
LW
"""
import copy
import json
import os
import re
import time

import pytest

from test_ha_ui import (  # noqa: F401  (browser is a fixture)
    BASE, LANGS, PASSWORD, SELF, SRC, _App, _FakeServer, _block, _blocks, _classes, _iso_ago, _member, _open_ha,
    _read, _toasts, _until, _wait_for_toast, browser)

OWN = 'a' * 32
B, C, W = 'b' * 32, 'c' * 32, 'e' * 32
B_URL = 'https://pegaprox-b.example:5000'
C_URL = 'https://pegaprox-c.example:5000'
W_URL = 'https://witness.example:5005'
NOT_SHIPPED = 'Automatic failover is not available in this release yet'
NOT_SHIPPED_NOTE = ('Automatic failover is not available in this release yet. Until then the group fails over by '
                    'hand: promote a member when the leader is gone.')
WITNESS_CODE = 'pgxwt1_' + 'W' * 80
ZONES = ('Europe/Vienna', 'America/New_York', 'Asia/Tokyo', 'UTC')
EM_DASH = chr(0x2014)
# the routes these cards send to (Make leader, Force leader and the settings of a member came with
# slices S7 and S8, tests/test_ha_lead_ui.py)
ROUTES = {"'mode'", '`members/${encodeURIComponent(target)}/readmit`', "'witness/pairing-code'", "'witness/remove'",
          "'timezone'"}


def _finding(code, level, text, member=None):
    return {'code': code, 'level': level, 'text': text, 'member': member}


def _row(ch, **more):
    """A member as lease_status lists it."""
    return dict({'instance_id': ch * 32, 'kind': 'data', 'voter': True, 'may_lead': True, 'site': '',
                 'quarantined': False, 'skew': 0.2, 'release': '1.2.0', 'mode': 'manual', 'zone': 'Europe/Vienna',
                 'holds': False, 'reach': {'c1': True}, 'seen_ago': 3.0}, **more)


def _witness(**more):
    """The witness as witness_view shows it."""
    return dict({'instance_id': W, 'kind': 'witness', 'url': W_URL, 'fingerprint': 'AB:CD', 'site': 'dc3',
                 'key_fingerprint': '1f2e3d4c5b6a7980', 'last_heard': 1.2, 'skew': 0.1, 'write_failed': False}, **more)


def _witness_row(view):
    return {'instance_id': view['instance_id'], 'kind': 'witness', 'voter': True, 'may_lead': False,
            'site': view['site'], 'quarantined': False, 'skew': view['skew'], 'release': '1.2.0', 'mode': 'manual',
            'zone': 'UTC', 'holds': False, 'reach': None, 'url': view['url'], 'last_heard': view['last_heard'],
            'seen_ago': 1.0}


def _auto(mode='manual', findings=(), members=None, witness=None, **more):
    """lease_status() as the status carries it in auto, once this release offers automatic failover."""
    rows = list(members) if members is not None else [_row('b'), _row('c')]
    if witness:
        rows.append(_witness_row(witness))
    return dict({'mode': mode, 'lease_s': 20, 'voters': 3, 'majority': 2, 'leader': mode != 'manual',
                 'holds_lease': False, 'acting': True, 'acting_process': True, 'holder': None, 'lease_left': None,
                 'acting_in': None, 'epoch': 2, 'cfg_id': [2, 1], 'voted_for': None, 'switch_waiting': None,
                 'pending': None, 'findings': list(findings), 'reach': {'c1': True}, 'hub_lag_max': 0.01,
                 'boot_hub_lag_max': 0.02, 'members': rows, 'witness': witness}, **more)


class _GroupServer(_FakeServer):
    """The fake of test_ha_ui.py with what stage 2 adds to the status (auto, the time zone) and
    the routes of the cards, in the order of their checks in pegaprox/api/ha.py.

    auto: lease_status() or None (a release without automatic failover); auto_key/zone_key False
    is a server from before stage 2. shipped: whether this release offers automatic failover.
    mode_answers: (status, body) the next mode requests get first, whatever they carry.
    """

    def __init__(self, auto=None, auto_key=True, zone='Europe/Vienna', zone_local='Europe/Vienna', unreadable='',
                 zone_key=True, shipped=False, mode_answers=(), witness_told=True, remove_refusal=None, **kw):
        kw.setdefault('role', 'active')
        if kw['role'] != 'standalone':
            kw.setdefault('members', [_member('b'), _member('c')])
        super().__init__(**kw)
        self.auto = copy.deepcopy(auto)
        self.auto_key, self.zone_key = auto_key, zone_key
        self.zone, self.zone_local, self.unreadable = zone, zone_local, unreadable
        self.shipped = shipped
        self.mode_answers = list(mode_answers)
        self.witness_told = witness_told
        self.remove_refusal = remove_refusal

    def status(self):
        out = super().status()
        if self.auto_key:
            out['auto'] = copy.deepcopy(self.auto)
        if self.zone_key:
            out.update(timezone=self.zone, timezone_local=self.zone_local, timezone_unreadable=self.unreadable)
        return out

    def mode(self):
        return (self.auto or {}).get('mode', 'manual')

    def join_witness(self, view=None):
        view = view or _witness()
        self.auto['witness'] = view
        self.auto['members'] = [r for r in self.auto['members'] if r['kind'] != 'witness'] + [_witness_row(view)]

    def mode_route(self, body):
        want = body.get('mode')
        if want not in ('auto', 'manual'):
            return 400, {'error': 'mode is auto or manual'}
        lease = body.get('lease_s', 20)
        if isinstance(lease, bool) or not isinstance(lease, int) or not 15 <= lease <= 120:
            return 400, {'error': 'The lease is a whole number of seconds, 15 to 120'}
        accept = body.get('accept') if isinstance(body.get('accept'), list) else []
        if want == 'auto' and not self.shipped:
            return 409, {'code': 'HA_AUTO_NOT_SHIPPED', 'error': NOT_SHIPPED}
        if self.role != 'active':
            return 409, {'code': 'HA_STANDBY', 'error': 'Automatic failover is switched on the leader of a group'}
        now = self.mode()
        if want == 'manual' and now == 'manual':
            return 409, {'error': 'This group is in manual mode'}
        refusal = self._reauth_refusal(body)
        if refusal:
            return 403, refusal
        if self.mode_answers:
            return self.mode_answers.pop(0)
        if want == 'manual':
            if now == 'auto_pending':
                self.auto.update(mode='manual', switch_waiting=None, pending=None)
                return 200, {'success': True, 'mode': 'manual', 'result': 'cancelled'}
            return 200, {'success': True, 'mode': 'auto', 'result': 'off'}
        if now == 'auto':
            changed = self.auto['lease_s'] != lease
            self.auto['lease_s'] = lease
            return 200, {'success': True, 'mode': 'auto', 'lease_s': lease, 'changed': changed}
        findings = self.auto['findings']
        if any(f['level'] == 'block' for f in findings):
            return 409, {'code': 'HA_AUTO_REFUSED', 'error': 'Automatic failover cannot be switched on', 'findings': findings}
        if any(f['level'] == 'warn' and f['code'] not in accept for f in findings):
            return 409, {'code': 'HA_AUTO_CONFIRM', 'error': 'Confirm the warnings first', 'findings': findings}
        waiting = sorted(r['instance_id'] for r in self.auto['members'])
        self.auto.update(mode='auto_pending', lease_s=lease, switch_waiting=waiting,
                         pending={'by': OWN, 'by_url': '', 'own': True, 'since': _iso_ago(1), 'text': 'pending'})
        return 200, {'success': True, 'mode': 'auto_pending', 'lease_s': lease, 'waiting': waiting}

    def group_route(self, method, path, body):
        if path == '/api/ha/mode' and method == 'PUT':
            return self.mode_route(body)
        if path == '/api/ha/timezone' and method == 'PUT':
            name = body.get('timezone')
            if not isinstance(name, str) or not name.strip():
                return 400, {'error': 'timezone is the name of a time zone, like Europe/Vienna'}
            if self.role != 'active':
                return 409, {'code': 'HA_STANDBY', 'error': "The group's time zone is set on the leader of a group"}
            if name not in ZONES:
                return 400, {'error': 'That is not a time zone this instance knows - use a name like Europe/Vienna'}
            changed, self.zone = name != self.zone, name
            return 200, {'success': True, 'timezone': name, 'changed': changed}
        if path == '/api/ha/witness/pairing-code' and method == 'POST':
            url = body.get('url')
            if not isinstance(url, str) or not url.startswith('https://'):
                return 400, {'error': 'Enter the https:// address the witness will use to reach this instance'}
            site = body.get('site', '')
            if not isinstance(site, str) or len(site.strip()) > 64:
                return 400, {'error': 'site is a label of up to 64 characters'}
            if not self.shipped:
                return 409, {'code': 'HA_AUTO_NOT_SHIPPED', 'error': NOT_SHIPPED}
            if (self.auto or {}).get('witness'):
                return 409, {'error': 'This group has a witness already - remove it first'}
            refusal = self._reauth_refusal(body)
            if refusal:
                return 403, refusal
            return 200, {'code': WITNESS_CODE, 'expires_at': int(time.time()) + 900, 'commands': {
                'package': f'pegaprox-witness join {WITNESS_CODE} --url https://<witness host>:5005',
                'docker': f'docker run --rm -v pegaprox-witness:/app/witness ghcr.io/pegaprox/pegaprox witness join '
                          f'{WITNESS_CODE} --url https://<witness host>:5005'}}
        if path == '/api/ha/witness/remove' and method == 'POST':
            if body.get('confirm') != 'REMOVE':
                return 400, {'error': 'Type REMOVE to confirm'}
            if self.role != 'active':
                return 409, {'error': 'A witness is added and removed on the leader of a group'}
            if not (self.auto or {}).get('witness'):
                return 404, {'error': 'This group has no witness'}
            refusal = self._reauth_refusal(body)
            if refusal:
                return 403, refusal
            if self.remove_refusal:
                return self.remove_refusal
            self.auto['witness'] = None
            self.auto['members'] = [r for r in self.auto['members'] if r['kind'] != 'witness']
            return 200, {'success': True, 'told': self.witness_told}
        m = re.fullmatch(r'/api/ha/members/([^/]+)/readmit', path)
        if m and method == 'POST':
            if self.mode() != 'auto':
                return 409, {'error': 'This group is in manual mode - nobody is quarantined'}
            refusal = self._reauth_refusal(body)
            if refusal:
                return 403, refusal
            rec = next((r for r in self.auto['members'] if r['instance_id'] == m.group(1)), None)
            if not rec or not rec.get('quarantined'):
                return 409, {'error': 'That member is not quarantined'}
            rec['quarantined'] = False
            return 200, {'success': True}
        return None

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        ours = path.startswith('/api/ha/') and (path in ('/api/ha/mode', '/api/ha/timezone', '/api/ha/witness/pairing-code',
                                                         '/api/ha/witness/remove') or path.endswith('/readmit'))
        if not ours or not req.url.startswith(BASE):
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        self.bodies.setdefault(path, []).append(body)
        status, data = self.group_route(req.method, path, body) or (404, {'error': 'not mocked'})
        return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})


# -- source ---------------------------------------------------------------------------------------------

@pytest.fixture(scope='module')
def modal():
    return _read('web', 'src', 'settings_modal.js')


@pytest.fixture(scope='module')
def stage2(modal):
    """Everything this slice adds below HaPanel, from its header to the end of the file."""
    return modal[modal.index('// LW Oct 2026 (#625) - stage 2 of the group, for HaPanel'):]


@pytest.fixture(scope='module')
def panel(modal):
    start = modal.index('function HaPanel({ t, addToast, getAuthHeaders })')
    return modal[start:modal.index('\n        // ═══', start)]


PARTS = ('HaAutoCard', 'HaWitnessCard', 'HaZoneCard', 'HaGroupPassword', 'HaAutoMemberHead', 'HaAutoMemberCells',
         'haAutoChecklist', 'haFailoverSeconds', 'haGroupSend', 'haSkewText')


def test_the_parts_exist_once(modal, stage2):
    for name in PARTS:
        assert modal.count(f'function {name}(') == 1, name
        assert f'function {name}(' in stage2, name


def test_the_panel_mounts_them_on_the_leader_and_a_member_only(panel):
    standalone = panel[panel.index("{role === 'standalone' && ("):panel.index("{role === 'active' && (")]
    active = panel[panel.index("{role === 'active' && ("):panel.index("{role === 'standby' && (")]
    standby = panel[panel.index("{role === 'standby' && ("):]
    assert 'groupCards(' not in standalone
    assert active.count('{groupCards(true)}') == 1 and 'groupCards(false)' not in active
    assert standby.count('{groupCards(false)}') == 1 and 'groupCards(true)' not in standby
    cards = _block(panel, 'const groupCards = (leader) => {', 'if (!status) {')
    # a removed instance shows none of them: the config it may still hold is the one it left
    assert cards.index('if (status.removed) return null;') < cards.index('const reported')
    # a server from before stage 2 sends neither key, and this release sends auto: null -
    # nothing of the switch or the witness renders then
    assert 'const reported = status.auto != null;' in cards
    assert "const zoned = typeof status.timezone === 'string';" in cards
    assert '{reported && (leader || auto) && (' in cards
    assert 'const witness = reported && (leader || auto?.witness) && (' in cards
    assert 'const zone = zoned && <HaZoneCard {...shared} />;' in cards
    # the columns of the voter config only with data behind them
    assert ("const auto = status?.auto && typeof status.auto === 'object' ? status.auto : null;" in panel)
    assert '{autoRows && <HaAutoMemberHead t={t} cell={cell} ctl={memberCtl} />}' in panel
    assert '{autoRows && <HaAutoMemberCells t={t} cell={cell} row={autoOf(m)} ctl={memberCtl} nameOf={nameOf} />}' in panel
    # the leader's controls in those columns only on the leader, and not with an unreadable state file
    assert "const memberCtl = role === 'active' && autoRows && !broken ? {" in panel


def test_the_requests_are_what_the_routes_read(stage2):
    api = _read('pegaprox', 'api', 'ha.py')
    vote = _read('pegaprox', 'core', 'ha_vote.py')
    # the mode route: mode, lease_s (15 to 120, 20 unless given), accept, and the password
    assert ": what === 'off' ? { mode: 'manual' }" in stage2
    assert ": what === 'lease' ? { mode: 'auto', lease_s: Number(leaseText) }" in stage2
    assert ": { mode: 'auto', lease_s: Number(leaseText), accept };" in stage2
    assert "sso ? body : { ...body, user_password: password }, t('pgHaActionFailed'));" in stage2
    route = _block(api, "@bp.route('/api/ha/mode', methods=['PUT'])", "@bp.route('/api/ha/timezone'")
    for needle in ("want = data.get('mode')", "lease_s = data.get('lease_s', ha_vote.LEASE_DEFAULT)",
                   "accept = data.get('accept') if isinstance(data.get('accept'), list) else []",
                   "_refuse_without_reauth('switching automatic failover')",
                   "return jsonify({'code': 'HA_AUTO_NOT_SHIPPED', 'error': ha_vote.NOT_SHIPPED_ERROR}), 409"):
        assert needle in route, needle
    assert 'const HA_LEASE = { min: 15, max: 120, def: 20 };' in stage2
    for name, value in (('LEASE_MIN', 15), ('LEASE_MAX', 120), ('LEASE_DEFAULT', 20), ('SKEW_LIMIT', 5),
                        ('SITE_MAX', 64)):
        assert re.search(r'^%s = %d$' % (name, value), vote, re.M), name
    assert 'const HA_SKEW_LIMIT = 5;' in stage2 and 'maxLength={64}' in stage2
    # the witness: url, site and the password; removal with the word and the password
    assert "const body = { url: target, site: site.trim() };" in stage2
    assert "haGroupSend(getAuthHeaders, 'POST', 'witness/pairing-code', sso ? body : { ...body, user_password: password }," in stage2
    code = _block(api, "@bp.route('/api/ha/witness/pairing-code'", "@bp.route('/api/ha/witness/remove'")
    for needle in ("url = _https_url(data.get('url'))", "site = data.get('site', '')", "'commands': {",
                   "'package': f\"pegaprox-witness join '{code}'", "'install': install",
                   "'docker': install['docker']", "_refuse_without_reauth('a witness pairing code')"):
        assert needle in code, needle
    # what "Add witness" answers with: one line per way, and what the card says around them
    ways = _block(api, 'def witness_install_commands(', "@bp.route('/api/ha/witness/installer'")
    for key in ("'linux'", "'offline'", "'docker'", "'manual'", "'placeholder'", "'placeholder_in'", "'note'",
                "'firewall'", "'installer_sha256'"):
        assert key in ways, key
    assert "const body = { confirm: 'REMOVE' };" in stage2
    remove = _block(api, "@bp.route('/api/ha/witness/remove'", '# --- node agents')
    assert "_body().get('confirm') != 'REMOVE'" in remove and "_refuse_without_reauth('removing the witness')" in remove
    # re-admit wants the password and nothing else; the zone no password at all
    assert "const path = what === 'readmit' ? `members/${encodeURIComponent(target)}/readmit` : 'mode';" in stage2
    readmit = _block(api, "@bp.route('/api/ha/members/<instance_id>/readmit'", "@bp.route('/api/ha/mode'")
    assert "_refuse_without_reauth('re-admitting a member')" in readmit
    assert "haGroupSend(getAuthHeaders, 'PUT', 'timezone', { timezone: wanted }, t('pgHaActionFailed'))" in stage2
    zone = _block(api, "@bp.route('/api/ha/timezone'", "@bp.route('/api/ha/settings'")
    assert "name = _str(_body().get('timezone'), 100)" in zone and '_refuse_without_reauth' not in zone


def test_every_request_goes_to_a_route_the_cards_were_built_against(stage2):
    """The mode, witness and zone routes, and since slices S7 and S8 Make leader, Force leader and
    the site, vote and agent VM of a member (tests/test_ha_lead_ui.py pins those): nothing else."""
    paths = set(re.findall(r"haGroupSend\(getAuthHeaders, [^,]+, ([^,]+),", stage2))
    assert paths == {'path', "'witness/pairing-code'", "'witness/remove'", "'timezone'", "'force-leader'",
                     '`members/${encodeURIComponent(id)}/agent-vmid`'}, paths
    assert "const path = what === 'readmit' ? `members/${encodeURIComponent(target)}/readmit` : 'mode';" in stage2
    assert ("const path = what === 'site' ? `members/${encodeURIComponent(id)}/site`\n"
            "                    : leader ? 'make-leader' : `members/${encodeURIComponent(id)}/vote`;") in stage2


def test_the_checklist_knows_every_code_the_server_sends(stage2):
    core = _read('pegaprox', 'core', 'ha.py')
    findings = _block(core, 'def auto_findings(', '\ndef _lease_found(')
    codes = set(re.findall(r"_finding\('([A-Z_]+)'", findings))
    assert len(codes) >= 15, codes
    table = _block(stage2, 'const HA_AUTO_CHECKS = [', '];')
    listed = set(re.findall(r"'([A-Z_]{4,})'", table))
    assert codes <= listed, sorted(codes - listed)
    # a code from a later server still shows, under "other"
    assert "(HA_AUTO_CHECKS.find(([, codes]) => codes.includes(f.code)) || ['other'])[0];" in stage2
    assert "if (other.findings.length) items.push(other);" in stage2


def test_the_switch_is_held_by_red_and_wants_ticks_for_amber(stage2):
    card = _block(stage2, 'function HaAutoCard(', 'function HaWitnessCard(')
    assert "const blocked = mode === 'manual' && !!checks && checks.some(c => c.level === 'block');" in card
    assert 'disabled={busy || broken || (!on && (notShipped || blocked))}' in card
    assert "&& (form !== 'on' || (!blocked && amber.every(c => ticked.includes(c.key))));" in card
    # the refusal of this release is a note, and the card says it, not a toast
    assert "if (res.code === 'HA_AUTO_NOT_SHIPPED') { open(null); onNotShipped(); return; }" in card
    assert "{t('haAutoNotShipped')}" in card
    assert 'addToast?.(res.error' not in card


def test_server_words_go_into_a_text_through_a_function(stage2):
    """String.replace reads $& and its kin in a replacement string: an address with one of them
    showed something else."""
    seen = 0
    for key in ('who', 'names', 'zone', 'local', 'list', 'name', 'time', 'epoch', 'm', 'word'):
        for m in re.finditer(r"\.replace\('\{%s\}', (.{0,6})" % key, stage2):
            seen += 1
            if key != 'word':
                assert m.group(1).startswith('() =>'), (key, stage2[m.start():m.start() + 100])
    assert seen >= 12, seen


# -- translations ---------------------------------------------------------------------------------------

def _used_keys():
    keys = set()
    for name in sorted(os.listdir(SRC)):
        if name.endswith('.js') and name != 'translations.js':
            keys.update(re.findall(r"'((?:haAuto|haWitness|haZone)[A-Z]\w*)'", _read('web', 'src', name)))
    return sorted(keys)




def test_the_keys_are_ours_and_used_through_t():
    keys = _used_keys()
    assert len(keys) >= 100, len(keys)
    src = _read('web', 'src', 'settings_modal.js')
    for key in keys:
        assert key in src, key


@pytest.mark.parametrize('lang', LANGS)
def test_every_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'
    defined = set(re.findall(r'^ +((?:haAuto|haWitness|haZone)\w*): ', block, re.M))
    assert defined == set(_used_keys()), sorted(defined ^ set(_used_keys()))


@pytest.mark.parametrize('lang', LANGS)
def test_the_keys_are_one_block_before_the_ha_keys(lang):
    """Right after their comment and right before the comment the pgHa keys start with: the
    other HA blocks (copies, node HA) have their places pinned by their own tests."""
    lines = _blocks()[lang].splitlines()
    start = lines.index('                // LW Oct 2026 (#625) - stage 2: automatic failover, the witness, the time zone of the schedules')
    n = len(_used_keys())
    ours = [re.match(r'^ +(\w+): ', line).group(1) for line in lines[start + 1:start + 1 + n]]
    assert sorted(ours) == _used_keys()
    assert lines[start + 1 + n] == '                // LW Sep 2026 (#625) - high availability for PegaProx itself'


def _value(block, key):
    m = re.search(r"^ +%s: '(.*)',$" % key, block, re.M)
    return m.group(1).replace("\\'", "'")


def test_placeholders_survive_and_every_text_is_translated():
    blocks = _blocks()
    # the badge: Beta is the same word in most of them
    same_word = {'haAutoBeta': 'Beta'}
    for key in _used_keys():
        en = _value(blocks['en'], key)
        for lang in LANGS:
            value = _value(blocks[lang], key)
            assert value.strip(), (lang, key)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)
            assert EM_DASH not in value, (lang, key)
            if lang != 'en' and same_word.get(key) != value:
                assert value != en, (lang, key)


def test_korean_says_member_as_the_other_ha_keys_do():
    ko = _blocks()['ko']
    for key in _used_keys():
        assert '구성원' not in _value(ko, key), key


def test_the_button_names_in_the_texts_match_the_buttons():
    blocks = _blocks()
    for lang in LANGS:
        # "I understand" is ticked at an amber item, the refusal points at the same list
        assert _value(blocks[lang], 'haAutoUnderstand')
        assert '<witness host>' in _value(blocks[lang], 'haWitnessRunOne'), lang


# -- styling, icons, bundle, house rules ------------------------------------------------------------------

def test_every_class_is_in_the_static_tailwind_build(stage2, panel):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(stage2) | _classes(_block(panel, 'const auto = status?.auto', 'const membersCard = ('))
    names |= _classes(_block(panel, '{/* the witness votes and holds nothing', '</tbody>'))
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists(stage2):
    icons = set(re.findall(r'^ {12}(\w+): ', _read('web', 'src', 'icons.js'), re.M))
    used = set(re.findall(r'Icons\.(\w+)', stage2))
    assert used and used <= icons, sorted(used - icons)


def test_house_rules(stage2, panel):
    added = stage2 + _block(panel, 'const auto = status?.auto', 'const membersCard = (')
    for text in (added, _read('tests', 'test_ha_auto_ui.py')):
        assert EM_DASH not in text
        # spelled apart, so this file holds neither word itself
        assert 'VM' + 'ware' not in text and 'v' + 'Center' not in text
    # one author tag per larger block, in the style around it
    assert added.count('LW Oct 2026 (#625)') <= 2
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for name in PARTS + ('data-ha-auto-not-shipped', 'witness/pairing-code', 'pegaprox-witness leave --force'):
        assert name in bundle, name
    for key in _used_keys():
        assert key in bundle, key


# -- runtime --------------------------------------------------------------------------------------------

@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _GroupServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _sent(app, path):
    return app.server.bodies.get(path, [])


def _writes(app):
    return [c for c in app.server.calls if c[0] != 'GET' and c[1].startswith('/api/ha/')]


def _switch(page):
    return page.get_by_role('switch', name='Automatic failover')


def _failover(lease):
    take = 1.1 * (lease + 2) + max(2, 0.05 * lease) + 5
    return round(1.1 * lease + 1 + take), round(1.1 * lease + lease / 4 + 1 + take)


def test_runtime_this_release_offers_no_switch_and_no_witness_form(open_app):
    """auto is null while the release does not offer automatic failover: no switch and no
    witness form that could only be refused, no columns of a voter config. The group's time
    zone works in manual mode and stays."""
    app = open_app()
    page = app.page
    panel = _open_ha(app, 'active')
    panel.locator('[data-ha-zone]').wait_for(timeout=3000)
    assert panel.locator('[data-ha-auto]').count() == 0
    assert panel.locator('[data-ha-witness]').count() == 0
    assert _switch(page).count() == 0
    head = panel.locator('[data-ha-members] thead').inner_text()
    assert 'Site' not in head and 'Vote' not in head
    assert not _writes(app)
    assert not app.errors, app.errors


def test_runtime_a_refused_switch_is_a_note_on_the_card(open_app):
    """A server that reports a voter config and still answers 409 HA_AUTO_NOT_SHIPPED: the
    form asks for the lease and the password, and the refusal turns into a note on the
    card, not into an error toast."""
    app = open_app(auto=_auto())
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    assert card.get_attribute('data-ha-auto') == 'manual'
    assert card.inner_text().startswith('Automatic failover')
    assert card.locator('[data-ha-auto-not-shipped]').count() == 0
    switch = _switch(page)
    assert switch.get_attribute('aria-checked') == 'false' and switch.is_enabled()

    switch.click()
    form = card.locator('[data-ha-auto-form="on"]')
    form.wait_for(timeout=3000)
    assert form.inner_text().startswith('The voter config goes to every member')
    assert page.input_value('#pgha-lease') == '20'
    note = form.locator('[data-ha-auto-lease-note]')
    assert note.inner_text().strip() == 'A failover pauses changes and automation for about 54-59 s at 20 s.'
    button = form.get_by_role('button', name='Switch on')
    assert button.is_disabled(), 'it waits for the password'
    page.fill('#pgha-auto-password', PASSWORD)
    assert button.is_enabled()
    page.fill('#pgha-lease', '200')
    assert form.locator('[data-ha-auto-lease-range]').inner_text().strip() == 'The lease is a whole number of seconds, 15 to 120.'
    assert button.is_disabled()
    page.fill('#pgha-lease', '30')
    lo, hi = _failover(30)
    assert (lo, hi) == (76, 84)
    assert note.inner_text().strip() == f'A failover pauses changes and automation for about {lo}-{hi} s at 30 s.'
    page.fill('#pgha-lease', '20')
    assert not _writes(app)

    button.click()
    shipped = card.locator('[data-ha-auto-not-shipped]')
    shipped.wait_for(timeout=3000)
    assert shipped.inner_text().strip() == NOT_SHIPPED_NOTE
    assert _sent(app, '/api/ha/mode') == [{'mode': 'auto', 'lease_s': 20, 'accept': [], 'user_password': PASSWORD}]
    form.wait_for(state='detached', timeout=3000)
    page.wait_for_timeout(400)
    assert not any('not available' in t for t in _toasts(page)), _toasts(page)
    assert _switch(page).is_disabled() and _switch(page).get_attribute('aria-checked') == 'false'
    # the witness only votes in automatic failover: its card says the same at once
    witness = panel.locator('[data-ha-witness]')
    assert witness.locator('[data-ha-witness-not-shipped]').inner_text().strip() == (
        'A witness votes in automatic failover only, so it can be added once this release offers it.')
    assert witness.locator('#pgha-witness-url').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_witness_code_is_refused_the_same_way(open_app):
    app = open_app(auto=_auto())
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-witness]')
    assert card.get_attribute('data-ha-witness') == 'none'
    assert card.locator('h4').inner_text().strip() == 'Add a witness'
    assert page.input_value('#pgha-witness-url') == SELF
    create = card.get_by_role('button', name='Create witness code')
    assert create.is_disabled(), 'it waits for the password'
    page.fill('#pgha-witness-password', PASSWORD)
    # an address without https:// does not leave the page
    page.fill('#pgha-witness-url', 'http://pegaprox-b.example:5000')
    create.click()
    assert card.locator('[data-ha-witness-refused]').inner_text().strip() == (
        'Enter the https:// address the witness will use to reach this instance')
    assert not _writes(app)
    page.fill('#pgha-witness-url', SELF)
    page.fill('#pgha-witness-site', 'dc3')
    page.fill('#pgha-witness-password', PASSWORD)
    create.click()
    card.locator('[data-ha-witness-not-shipped]').wait_for(timeout=3000)
    assert _sent(app, '/api/ha/witness/pairing-code') == [{'url': SELF, 'site': 'dc3', 'user_password': PASSWORD}]
    assert card.locator('[data-ha-witness-code]').count() == 0
    # and the switch learned it too
    assert panel.locator('[data-ha-auto-not-shipped]').inner_text().strip() == NOT_SHIPPED_NOTE
    assert _switch(page).is_disabled()
    assert not any('not available' in t for t in _toasts(page))
    assert not app.errors, app.errors


CHECKS = {
    'clean': ([], None, {'votes': 'ok', 'release': 'ok', 'answer': 'ok', 'clock': 'ok', 'zone': 'ok', 'sites': 'ok'}),
    'warn': ([_finding('EVEN_VOTERS', 'warn', '4 votes survive the loss of 1, the same as 3 would.')], None,
             {'votes': 'warn', 'release': 'ok', 'answer': 'ok', 'clock': 'ok', 'zone': 'ok', 'sites': 'ok'}),
    'block': ([_finding('TOO_FEW_VOTERS', 'block', 'Automatic failover needs at least 3 votes, this group has 2.'),
               _finding('CLOCK_SKEW', 'block', f'The clock of {B_URL} is 9 s off.', B)], None,
              {'votes': 'block', 'release': 'ok', 'answer': 'ok', 'clock': 'block', 'zone': 'ok', 'sites': 'ok'}),
    'witness': ([_finding('VOTER_DOWN', 'block', f'The witness {W_URL} has not answered within the last 2 minutes.', W),
                 _finding('WITNESS_SAME_SITE', 'warn', 'The witness shares site dc1 with data members.', W)], _witness(),
                {'votes': 'ok', 'release': 'ok', 'answer': 'ok', 'witness': 'block', 'clock': 'ok', 'zone': 'ok',
                 'sites': 'ok'}),
    'other': ([_finding('SOMETHING_NEW', 'warn', 'A check of a later release.')], None,
              {'votes': 'ok', 'release': 'ok', 'answer': 'ok', 'clock': 'ok', 'zone': 'ok', 'sites': 'ok', 'other': 'warn'}),
}


@pytest.mark.parametrize('case', list(CHECKS))
def test_runtime_the_checklist_at_every_level(open_app, case):
    """Red keeps the switch off, amber wants a tick and goes out in accept, green asks nothing;
    a finding about the witness belongs to it, a code nobody knows yet to "other"."""
    findings, witness, want = CHECKS[case]
    app = open_app(auto=_auto(findings=findings, witness=witness), shipped=True)
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    checks = card.locator('[data-ha-auto-checks]')
    assert card.locator('[data-ha-auto-mode]').inner_text().strip() == 'Manual'
    assert checks.locator('div').first.inner_text().strip() == 'Before it can be switched on'
    got = dict(checks.locator('[data-ha-auto-check]').evaluate_all(
        'rows => rows.map(r => [r.dataset.haAutoCheck, r.dataset.haAutoLevel])'))
    assert got == want
    for f in findings:
        assert f['text'] in checks.inner_text(), f
    if case == 'block':
        assert checks.locator('[data-ha-auto-blocked]').inner_text().strip() == (
            'Red items keep the switch off until they are fixed.')
        assert _switch(page).is_disabled()
        assert checks.locator('input[type="checkbox"]').count() == 0
        assert not _writes(app)
        assert not app.errors, app.errors
        return
    if case == 'witness':
        # the witness item is red: nothing to tick, the switch stays off
        assert _switch(page).is_disabled()
        assert 'The witness answers' in checks.inner_text()
        assert not app.errors, app.errors
        return
    _switch(page).click()
    form = card.locator('[data-ha-auto-form="on"]')
    button = form.get_by_role('button', name='Switch on')
    page.fill('#pgha-auto-password', PASSWORD)
    amber = [k for k, level in want.items() if level == 'warn']
    if amber:
        assert form.locator('[data-ha-auto-needs-ticks]').inner_text().strip() == (
            'Tick the amber items in the list above to go ahead.')
        assert button.is_disabled()
        for key in amber:
            checks.locator(f'[data-ha-auto-check="{key}"]').get_by_label('I understand').check()
    assert button.is_enabled()
    button.click()
    assert _wait_for_toast(page, 'Switch to automatic failover started'), _toasts(page)
    assert _sent(app, '/api/ha/mode') == [{'mode': 'auto', 'lease_s': 20,
                                           'accept': [f['code'] for f in findings if f['level'] == 'warn'],
                                           'user_password': PASSWORD}]
    pending = card.locator('[data-ha-auto-pending]')
    pending.wait_for(timeout=3000)
    assert pending.inner_text().startswith(f'Switching on - waiting for {B_URL}, {C_URL}')
    assert card.locator('[data-ha-auto-mode]').inner_text().strip() == 'Switching on'
    assert _switch(page).get_attribute('aria-checked') == 'true'
    assert not app.errors, app.errors


def test_runtime_a_refused_switch_brings_the_servers_list(open_app):
    """The status said nothing stands in the way; the server finds an even number of votes just
    now: the item turns amber with its sentence, and the next try sends its code in accept."""
    even = _finding('EVEN_VOTERS', 'warn', '4 votes survive the loss of 1, the same as 3 would.')
    app = open_app(auto=_auto(members=[_row('b'), _row('c'), _row('d')], voters=4, majority=3), shipped=True,
                   members=[_member('b'), _member('c'), _member('d')],
                   mode_answers=[(409, {'code': 'HA_AUTO_CONFIRM', 'error': 'Confirm the warnings first',
                                        'findings': [even]})])
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    assert card.locator('[data-ha-auto-check="votes"]').get_attribute('data-ha-auto-level') == 'ok'
    _switch(page).click()
    page.fill('#pgha-auto-password', PASSWORD)
    card.get_by_role('button', name='Switch on').click()
    refused = card.locator('[data-ha-auto-refused="HA_AUTO_CONFIRM"]')
    refused.wait_for(timeout=3000)
    assert refused.inner_text().strip() == 'Tick the amber items in the list above to go ahead.'
    votes = card.locator('[data-ha-auto-check="votes"]')
    assert votes.get_attribute('data-ha-auto-level') == 'warn'
    assert even['text'] in votes.inner_text()
    # the password went with the request
    assert page.input_value('#pgha-auto-password') == ''
    page.fill('#pgha-auto-password', PASSWORD)
    assert card.get_by_role('button', name='Switch on').is_disabled()
    votes.get_by_label('I understand').check()
    card.get_by_role('button', name='Switch on').click()
    assert _wait_for_toast(page, 'Switch to automatic failover started'), _toasts(page)
    assert [b.get('accept') for b in _sent(app, '/api/ha/mode')] == [[], ['EVEN_VOTERS']]
    assert not app.errors, app.errors


def test_runtime_a_wrong_password_stays_at_its_field(open_app):
    app = open_app(auto=_auto(), shipped=True)
    page = app.page
    panel = _open_ha(app, 'active')
    _switch(page).click()
    page.fill('#pgha-auto-password', 'wrong')
    panel.get_by_role('button', name='Switch on').click()
    note = panel.locator('[data-ha-auto-form] [data-ha-reauth="HA_REAUTH"]')
    note.wait_for(timeout=3000)
    assert note.inner_text().strip() == 'Incorrect password'
    assert page.input_value('#pgha-auto-password') == ''
    assert page.get_attribute('#pgha-auto-password', 'aria-invalid') == 'true'
    assert panel.locator('[data-ha-auto-refused]').count() == 0
    assert not any('Incorrect password' in t for t in _toasts(page))
    assert not app.errors, app.errors


def _running(**more):
    members = [_row('b', site='dc1', skew=0.4, reach={'c1': True, 'c2': False}, seen_ago=2.6, mode='auto'),
               _row('c', site='dc2', voter=False, may_lead=False, skew=-7.2, reach={'c1': True, 'c2': True},
                    quarantined=True, seen_ago=None, mode='auto')]
    kw = dict(mode='auto', members=members, witness=_witness(), holds_lease=True, holder=OWN, lease_left=15.2,
              epoch=7, findings=[_finding('QUARANTINED', 'warn', f'{C_URL[8:16]} came back with an older state. '
                                                                 'Check it, then re-admit it.', C)])
    kw.update(more)
    return _auto(**kw)


def test_runtime_automatic_mode_status_line_and_member_columns(open_app):
    app = open_app(auto=_running(), shipped=True)
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    assert card.get_attribute('data-ha-auto') == 'auto'
    assert card.locator('[data-ha-auto-mode]').inner_text().strip() == 'Automatic'
    assert _switch(page).get_attribute('aria-checked') == 'true'
    leader = card.locator('[data-ha-auto-leader]')
    assert leader.get_attribute('data-ha-auto-leader') == 'self'
    assert leader.inner_text().strip() == 'Leader: this instance (epoch 7) · lease valid for 15 s'
    assert card.locator('[data-ha-auto-majority]').inner_text().strip() == 'Majority: 2 of 3 votes'
    lease = card.locator('[data-ha-auto-lease]')
    assert lease.get_attribute('data-ha-auto-lease') == '20' and lease.inner_text().startswith('Lease: 20 s')
    assert lease.get_by_role('button', name='Change').count() == 1
    # in automatic mode only what to look at, and nothing to tick
    checks = card.locator('[data-ha-auto-checks]')
    assert checks.locator('div').first.inner_text().strip() == 'What to look at'
    assert checks.locator('[data-ha-auto-check]').evaluate_all('r => r.map(x => x.dataset.haAutoCheck)') == ['answer']
    assert checks.locator('input[type="checkbox"]').count() == 0

    heads = panel.locator('[data-ha-members] thead th').evaluate_all('r => r.map(x => x.innerText.trim())')
    for column in ('Site', 'Vote', 'May lead', 'Clock', 'Reach', 'State'):
        assert column in heads, column
    # no type column (the witness row carries its badge); on the leader vote and may lead are a
    # switch each (tests/test_ha_lead_ui.py), and the member's own controls come before the
    # columns of the voter config
    assert 'Type' not in heads
    assert heads.index('Active') < heads.index('Site') < heads.index('Vote') < heads.index('May lead')
    b = panel.locator(f'[data-ha-member="{B}"]')
    assert b.locator('[data-ha-auto-site]').inner_text().strip() == 'dc1'
    assert b.locator('[data-ha-auto-vote]').get_attribute('data-ha-auto-vote') == 'yes'
    assert b.get_by_role('switch', name=f'Vote: {B_URL}').get_attribute('aria-checked') == 'true'
    assert b.locator('[data-ha-auto-may-lead]').get_attribute('data-ha-auto-may-lead') == 'yes'
    assert b.get_by_role('switch', name=f'May lead: {B_URL}').get_attribute('aria-checked') == 'true'
    assert b.locator('[data-ha-auto-skew]').inner_text().strip() == '+0.4 s'
    reach = b.locator('[data-ha-auto-reach] span')
    assert reach.inner_text().strip() == '1 of 2' and 'text-yellow-300' in reach.get_attribute('class')
    assert reach.get_attribute('title') == 'Clusters with node HA whose API this member reaches'
    assert b.locator('[data-ha-auto-state]').inner_text().strip() == 'heard 3 s ago'
    c = panel.locator(f'[data-ha-member="{C}"]')
    assert c.get_by_role('switch', name=f'Vote: {C_URL}').get_attribute('aria-checked') == 'false'
    assert c.locator('[data-ha-auto-may-lead]').get_attribute('data-ha-auto-may-lead') == 'no'
    # a member without a vote does not lead
    assert c.get_by_role('switch', name=f'May lead: {C_URL}').is_disabled()
    skew = c.locator('[data-ha-auto-skew] span')
    assert skew.inner_text().strip() == '-7.2 s' and 'text-red-300' in skew.get_attribute('class')
    assert c.locator('[data-ha-auto-state]').get_attribute('data-ha-auto-state') == 'quarantined'
    assert 'Quarantined - restored from an old state' in c.locator('[data-ha-auto-state]').inner_text()
    assert 'not heard yet' in c.locator('[data-ha-auto-state]').inner_text()
    w = panel.locator(f'[data-ha-member-witness="{W}"]')
    assert w.locator('[data-ha-badge="witness"]').inner_text().strip() == 'Witness'
    assert w.locator('[data-ha-auto-site]').inner_text().strip() == 'dc3'
    assert w.locator('[data-ha-auto-vote]').inner_text().strip() == 'Yes'
    assert w.locator('[data-ha-auto-may-lead]').get_attribute('data-ha-auto-may-lead') == 'no'
    assert w.locator('[data-ha-auto-reach]').inner_text().strip() == '-'
    # nothing to switch or remove on the witness row, the witness card does that; only its site
    # is set here, as every member's is
    assert w.locator('[role="switch"]').count() == 0
    assert w.locator('button').count() == 1 and w.get_by_role('button', name=f'Site of {W_URL}').count() == 1
    witness = panel.locator('[data-ha-witness="paired"]')
    assert witness.locator('h4').inner_text().strip() == 'Witness'
    assert witness.locator('[data-ha-witness-url]').inner_text().strip() == W_URL
    assert witness.locator('[data-ha-witness-site]').inner_text().strip() == 'dc3'
    assert witness.locator('[data-ha-witness-heard]').inner_text().strip() == '1 s ago'
    assert witness.locator('[data-ha-witness-skew]').inner_text().strip() == '+0.1 s'
    assert not _writes(app)
    assert not app.errors, app.errors


def test_runtime_the_lease_changes_and_the_switch_goes_off(open_app):
    app = open_app(auto=_running(), shipped=True)
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    card.get_by_role('button', name='Change').click()
    form = card.locator('[data-ha-auto-form="lease"]')
    form.wait_for(timeout=3000)
    assert form.inner_text().startswith('Another lease length is a change of the voter config')
    page.fill('#pgha-lease', '10')
    assert form.locator('[data-ha-auto-lease-range]').count() == 1
    page.fill('#pgha-auto-password', PASSWORD)
    assert form.get_by_role('button', name='Save').is_disabled()
    page.fill('#pgha-lease', '30')
    assert form.locator('[data-ha-auto-lease-note]').inner_text().strip() == (
        'A failover pauses changes and automation for about 76-84 s at 30 s.')
    form.get_by_role('button', name='Save').click()
    assert _wait_for_toast(page, 'Lease length saved'), _toasts(page)
    assert _sent(app, '/api/ha/mode') == [{'mode': 'auto', 'lease_s': 30, 'user_password': PASSWORD}]
    assert _until(page, lambda: card.locator('[data-ha-auto-lease]').get_attribute('data-ha-auto-lease') == '30')

    _switch(page).click()
    off = card.locator('[data-ha-auto-form="off"]')
    off.wait_for(timeout=3000)
    assert off.inner_text().startswith('The group goes back to manual mode once a majority of the members holds')
    assert off.locator('#pgha-lease').count() == 0
    page.fill('#pgha-auto-password', PASSWORD)
    off.get_by_role('button', name='Switch off').click()
    assert _wait_for_toast(page, 'Automatic failover switched off'), _toasts(page)
    assert _sent(app, '/api/ha/mode')[-1] == {'mode': 'manual', 'user_password': PASSWORD}
    # the leader keeps its lease until a majority holds the change, and the card says so
    assert card.locator('[data-ha-auto-off-waiting]').inner_text().strip().startswith(
        'Switched off: the group is in manual mode once a majority of the members holds the change.')
    assert not app.errors, app.errors


@pytest.mark.parametrize('who', ['member', 'witness'])
def test_runtime_a_quarantined_voter_is_re_admitted(open_app, who):
    """Listed with Re-admit on the leader; the password goes with the request. A quarantined
    witness goes by its address there."""
    auto = _running()
    if who == 'witness':
        auto['members'] = [dict(r, quarantined=False) for r in auto['members']]
        auto['members'][-1]['quarantined'] = True
    target, label = (C, C_URL) if who == 'member' else (W, W_URL)
    app = open_app(auto=auto, shipped=True)
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    assert card.locator('[data-ha-auto-quarantine]').count() == 1
    row = card.locator(f'[data-ha-auto-quarantine="{target}"]')
    assert row.inner_text().startswith(f'{label}: Quarantined - restored from an old state')
    row.get_by_role('button', name='Re-admit').click()
    form = card.locator('[data-ha-auto-form="readmit"]')
    assert form.inner_text().startswith(f'{label} came back with an older state than it reported before.')
    assert form.get_by_role('button', name='Re-admit').is_disabled()
    page.fill('#pgha-auto-password', PASSWORD)
    form.get_by_role('button', name='Re-admit').click()
    assert _wait_for_toast(page, 'Re-admitted - its votes count again'), _toasts(page)
    assert _sent(app, f'/api/ha/members/{target}/readmit') == [{'user_password': PASSWORD}]
    card.locator('[data-ha-auto-quarantined]').wait_for(state='detached', timeout=3000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('case,want', [
    ('takeover', 'Taking over - acting in 13 s'),
    ('none', 'No leader at the moment - changes and automation are paused'),
    ('other', f'Leader: {B_URL} (epoch 7) · lease valid for 18 s'),
])
def test_runtime_who_leads_as_the_status_says(open_app, case, want):
    more = {'takeover': dict(acting_in=12.3, lease_left=19.0),
            'none': dict(holds_lease=False, holder=None, lease_left=None),
            'other': dict(holds_lease=False, holder=B, lease_left=18.4)}[case]
    app = open_app(auto=_running(**more), shipped=True)
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    if case == 'takeover':
        assert card.locator('[data-ha-auto-taking-over]').inner_text().strip() == want
        assert card.locator('[data-ha-auto-leader]').get_attribute('data-ha-auto-leader') == 'self'
    else:
        leader = card.locator('[data-ha-auto-leader]')
        assert leader.inner_text().strip() == want
        assert leader.get_attribute('data-ha-auto-leader') == case
        assert card.locator('[data-ha-auto-taking-over]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_pending_switch_is_taken_back_on_the_leader(open_app):
    pending = {'by': OWN, 'by_url': '', 'own': True, 'since': '2026-10-03T10:02:11+00:00', 'text': 'pending'}
    app = open_app(auto=_auto(mode='auto_pending', switch_waiting=[C], pending=pending), shipped=True)
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-auto]')
    box = card.locator('[data-ha-auto-pending]')
    assert box.get_attribute('data-ha-auto-pending') == '1'
    assert box.inner_text().startswith(f'Switching on - waiting for {C_URL}')
    assert 'Since ' in box.inner_text()
    assert card.locator('[data-ha-auto-mode]').inner_text().strip() == 'Switching on'
    # the manual active acts until the switch went through: no 'no leader' line meanwhile
    assert card.locator('[data-ha-auto-leader]').count() == 0 and 'No leader' not in card.inner_text()
    _switch(page).click()
    form = card.locator('[data-ha-auto-form="off"]')
    assert form.inner_text().startswith('The pending switch is taken back')
    page.fill('#pgha-auto-password', PASSWORD)
    form.get_by_role('button', name='Take back').click()
    assert _wait_for_toast(page, 'The pending switch was taken back'), _toasts(page)
    assert _sent(app, '/api/ha/mode') == [{'mode': 'manual', 'user_password': PASSWORD}]
    assert _until(page, lambda: card.get_attribute('data-ha-auto') == 'manual')
    assert card.locator('[data-ha-auto-off-waiting]').count() == 0
    assert not app.errors, app.errors


def test_runtime_every_member_holds_it_and_the_switch_waits_for_nobody(open_app):
    app = open_app(auto=_auto(mode='auto_pending', switch_waiting=[]), shipped=True)
    panel = _open_ha(app, 'active')
    box = panel.locator('[data-ha-auto-pending]')
    assert box.get_attribute('data-ha-auto-pending') == '0'
    assert box.inner_text().strip() == ('Switching on - every member has taken it, automatic failover starts in a '
                                        'moment')
    assert not app.errors, app.errors


@pytest.mark.parametrize('pending', ['by', 'group'])
def test_runtime_a_member_reads_and_changes_nothing(open_app, pending):
    """On a standby: what its leader says, no switch, no form, no button that writes; the
    witness and the zone read only too."""
    said = {'by': {'by': B, 'by_url': B_URL, 'own': False, 'since': '2026-10-03T10:02:11+00:00', 'text': 'x'},
            'group': None}[pending]
    app = open_app(role='standby', members=[_member('b', role='active', source=True), _member('c')],
                   auto=_auto(mode='auto_pending', pending=said, witness=_witness(),
                              members=[_row('b', site='dc1'), _row('c')]),
                   zone='Europe/Vienna', zone_local='America/New_York', shipped=True)
    page = app.page
    panel = _open_ha(app, 'standby')
    card = panel.locator('[data-ha-auto]')
    assert card.get_attribute('data-ha-auto') == 'auto_pending'
    assert _switch(page).count() == 0
    assert card.locator('[data-ha-auto-checks], [data-ha-auto-form], button').count() == 0
    text = card.locator('[data-ha-auto-pending]').inner_text()
    if pending == 'by':
        assert text.startswith(f'A switch to automatic failover is pending, started by {B_URL}. Until it is through')
    else:
        assert text.startswith('A switch to automatic failover is pending in this group.')
    witness = panel.locator('[data-ha-witness="paired"]')
    assert witness.locator('button').count() == 0
    zone = panel.locator('[data-ha-zone]')
    assert zone.locator('#pgha-zone').count() == 0
    assert 'The time zone of the group is set on the leader.' in zone.inner_text()
    assert zone.locator('[data-ha-zone-differs]').count() == 1
    # the columns show on a member too
    assert panel.locator(f'[data-ha-member="{B}"] [data-ha-auto-site]').inner_text().strip() == 'dc1'
    page.wait_for_timeout(300)
    assert not [c for c in _writes(app) if c[1].startswith('/api/ha/')]
    assert not app.errors, app.errors


def test_runtime_a_removed_member_shows_its_removal_and_no_card_of_the_group(open_app):
    """Lab E8: removed after Force leader on the other side, with the voter config it left
    still in its state (a build before the fix). The removed note says by whom and what to
    do; no card shows the config it left, its votes or the group's zone."""
    down = [_finding('VOTER_DOWN', 'warn', f'{ch * 8} holds a vote in the voter config and is no member of this '
                     'group (any more).', ch * 32) for ch in 'bc']
    app = open_app(role='standby', members=[],
                   auto=_auto(mode='auto', findings=down, witness=_witness()),
                   zone='Europe/Vienna', shipped=True)
    app.server.removed = {'epoch': 2, 'at': _iso_ago(60), 'by': 'd' * 32}
    panel = _open_ha(app, 'standby')
    note = panel.locator('[data-ha-removed]')
    note.wait_for(timeout=3000)
    assert 'Removed by dddddddd under epoch 2' in note.inner_text()
    assert panel.locator('[data-ha-auto], [data-ha-lead], [data-ha-split], [data-ha-witness], '
                         '[data-ha-zone]').count() == 0
    assert 'holds a vote in the voter config' not in panel.inner_text()
    assert not app.errors, app.errors


def test_runtime_a_member_of_a_release_without_it_shows_nothing_extra(open_app):
    """auto null on a standby: nothing to read, no card; the zone it has."""
    app = open_app(role='standby', members=[_member('b', role='active', source=True)])
    panel = _open_ha(app, 'standby')
    assert panel.locator('[data-ha-auto], [data-ha-witness]').count() == 0
    assert panel.locator('[data-ha-zone]').count() == 1
    assert not app.errors, app.errors


def test_runtime_a_witness_joins_and_is_removed(open_app):
    """The code once, the commands as the server spells them out, then wait until the witness
    shows in the status (it is read every few seconds meanwhile). Removing it wants REMOVE and
    the password; one that did not hear it gets the command for its host."""
    app = open_app(auto=_auto(), shipped=True, witness_told=False)
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-witness]')
    page.fill('#pgha-witness-site', 'dc3')
    page.fill('#pgha-witness-password', PASSWORD)
    card.get_by_role('button', name='Create witness code').click()
    code = card.locator('[data-ha-witness-code]')
    code.wait_for(timeout=3000)
    assert card.get_attribute('data-ha-witness') == 'waiting'
    assert _sent(app, '/api/ha/witness/pairing-code') == [{'url': SELF, 'site': 'dc3', 'user_password': PASSWORD}]
    assert page.input_value('#pgha-witness-password') == ''
    text = code.inner_text()
    assert text.startswith('Witness code, shown only once')
    assert code.locator('[data-ha-witness-command="code"] code').inner_text() == WITNESS_CODE
    assert code.locator('[data-ha-witness-command="package"] code').inner_text() == (
        f'pegaprox-witness join {WITNESS_CODE} --url https://<witness host>:5005')
    assert code.locator('[data-ha-witness-command="docker"] code').inner_text() == (
        f'docker run --rm -v pegaprox-witness:/app/witness ghcr.io/pegaprox/pegaprox witness join {WITNESS_CODE} '
        '--url https://<witness host>:5005')
    assert 'Installed from the .deb package' in text and 'With Docker' in text
    assert re.search(r'Expires in 1[45]:\d\d', text), text
    assert code.locator('[data-ha-witness-waiting]').inner_text().strip() == 'Waiting for the witness to join...'
    assert code.locator('button[title="Copy"]').count() == 3

    # while the code waits the status is read every few seconds, not every ten
    reads = app.server.calls.count(('GET', '/api/ha/status'))
    page.wait_for_timeout(6500)
    assert app.server.calls.count(('GET', '/api/ha/status')) >= reads + 2
    app.server.join_witness()
    card.locator('[data-ha-witness-url]').wait_for(timeout=6000)
    assert card.get_attribute('data-ha-witness') == 'paired'
    assert _wait_for_toast(page, 'The witness joined the group'), _toasts(page)
    assert card.locator('[data-ha-witness-code]').count() == 0

    card.get_by_role('button', name='Remove witness').click()
    box = card.locator('[data-ha-witness-remove]')
    confirm = box.get_by_role('button', name='Remove witness')
    assert confirm.is_disabled()
    page.fill('#pgha-witness-typed', 'remove')
    page.fill('#pgha-witness-password', PASSWORD)
    assert confirm.is_disabled(), 'the word is exact'
    page.fill('#pgha-witness-typed', 'REMOVE')
    confirm.click()
    gone = card.locator('[data-ha-witness-gone]')
    gone.wait_for(timeout=5000)
    assert _sent(app, '/api/ha/witness/remove') == [{'confirm': 'REMOVE', 'user_password': PASSWORD}]
    assert gone.get_attribute('data-ha-witness-gone') == 'not-reached'
    assert gone.inner_text().startswith('The witness was removed, but it did not answer.')
    assert gone.locator('code').inner_text() == 'pegaprox-witness leave --force'
    assert card.get_attribute('data-ha-witness') == 'none'
    assert not app.errors, app.errors


def test_runtime_a_refused_witness_removal_shows_the_servers_words(open_app):
    refused = (409, {'code': 'HA_AUTO_MODE', 'error': 'Without the witness this group would have fewer than 3 votes, '
                                                      'too few for automatic failover. Switch automatic failover off '
                                                      'first'})
    app = open_app(auto=_running(), shipped=True, remove_refusal=refused)
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-witness]')
    card.get_by_role('button', name='Remove witness').click()
    page.fill('#pgha-witness-typed', 'REMOVE')
    page.fill('#pgha-witness-password', PASSWORD)
    card.locator('[data-ha-witness-remove]').get_by_role('button', name='Remove witness').click()
    note = card.locator('[data-ha-witness-refused="HA_AUTO_MODE"]')
    note.wait_for(timeout=3000)
    assert note.inner_text().strip() == refused[1]['error']
    assert card.get_attribute('data-ha-witness') == 'paired'
    assert not app.errors, app.errors


@pytest.mark.parametrize('case', ['same', 'differs', 'none', 'unreadable', 'members', 'local_unknown'])
def test_runtime_the_zone_in_every_state(open_app, case):
    kw = {'same': {}, 'differs': {'zone_local': 'America/New_York'}, 'none': {'zone': ''},
          'unreadable': {'unreadable': 'Europe/Vienna', 'zone': ''},
          'members': {'auto': _auto(members=[_row('b', zone='America/New_York'), _row('c')]), 'shipped': True},
          'local_unknown': {'zone_local': ''}}[case]
    app = open_app(**kw)
    panel = _open_ha(app, 'active')
    zone = panel.locator('[data-ha-zone]')
    text = zone.inner_text()
    assert text.startswith('Time zone of the schedules')
    group = zone.locator('[data-ha-zone-group]')
    if case in ('none', 'unreadable'):
        assert group.inner_text().strip() == 'none set - each instance goes by its own zone'
    else:
        assert group.inner_text().strip() == 'Europe/Vienna'
    shown = {part: zone.locator(f'[data-ha-zone-{part}]').count()
             for part in ('differs', 'unreadable', 'none', 'members')}
    want = {'same': {}, 'differs': {'differs'}, 'none': {'none'}, 'unreadable': {'unreadable'}, 'members': {'members'},
            'local_unknown': {}}[case]
    assert {k for k, n in shown.items() if n} == set(want), shown
    if case == 'differs':
        assert zone.locator('[data-ha-zone-differs]').inner_text().strip() == (
            'This instance runs in America/New_York. The schedules still go by Europe/Vienna on every member, '
            'whichever leads.')
    if case == 'unreadable':
        assert zone.locator('[data-ha-zone-unreadable]').inner_text().strip() == (
            'This host has no time zone data for Europe/Vienna: while it leads, the schedules run by the clock of '
            'this host. Install tzdata here.')
    if case == 'members':
        assert zone.locator('[data-ha-zone-members]').inner_text().strip() == (
            f'Members in another zone: {B_URL} (America/New_York)')
    if case == 'local_unknown':
        assert zone.locator('[data-ha-zone-local]').inner_text().strip() == 'cannot be told'
    assert not app.errors, app.errors


def test_runtime_the_leader_sets_the_zone(open_app):
    app = open_app(zone='', zone_local='Europe/Vienna')
    page = app.page
    panel = _open_ha(app, 'active')
    zone = panel.locator('[data-ha-zone]')
    # prefilled with the zone of this instance, a choice of zones offered
    assert page.input_value('#pgha-zone') == 'Europe/Vienna'
    assert page.locator('#pgha-zone-list option').count() >= 30
    page.fill('#pgha-zone', 'Mars/Olympus')
    zone.get_by_role('button', name='Save').click()
    error = zone.locator('[data-ha-zone-error]')
    error.wait_for(timeout=3000)
    assert error.inner_text().strip() == 'That is not a time zone this instance knows - use a name like Europe/Vienna'
    page.fill('#pgha-zone', 'Asia/Tokyo')
    assert zone.locator('[data-ha-zone-error]').count() == 0
    zone.get_by_role('button', name='Save').click()
    assert _wait_for_toast(page, 'Time zone saved'), _toasts(page)
    assert _sent(app, '/api/ha/timezone') == [{'timezone': 'Mars/Olympus'}, {'timezone': 'Asia/Tokyo'}]
    assert _until(page, lambda: zone.get_attribute('data-ha-zone') == 'Asia/Tokyo')
    # the zone the group has already: nothing to save
    assert zone.get_by_role('button', name='Save').is_disabled()
    assert not app.errors, app.errors


def test_runtime_a_server_from_before_stage_2_shows_none_of_it(open_app):
    app = open_app(auto_key=False, zone_key=False)
    panel = _open_ha(app, 'active')
    assert panel.locator('[data-ha-members]').count() == 1
    assert panel.locator('[data-ha-auto], [data-ha-witness], [data-ha-zone]').count() == 0
    assert 'Automatic failover' not in panel.inner_text()
    assert not app.errors, app.errors


@pytest.mark.parametrize('stale', [False, True])
def test_runtime_an_sso_account_types_no_password(open_app, stale):
    app = open_app(auto=_auto(), shipped=True, auth_source='oidc', sso_stale=stale)
    page = app.page
    panel = _open_ha(app, 'active')
    _switch(page).click()
    form = panel.locator('[data-ha-auto-form="on"]')
    assert form.locator('input[type="password"]').count() == 0
    form.get_by_role('button', name='Switch on').click()
    if stale:
        note = form.locator('[data-ha-reauth="HA_REAUTH_RECENT"]')
        note.wait_for(timeout=3000)
        assert note.get_by_role('button', name='Sign in again').count() == 1
    else:
        assert _wait_for_toast(page, 'Switch to automatic failover started'), _toasts(page)
    assert _sent(app, '/api/ha/mode') == [{'mode': 'auto', 'lease_s': 20, 'accept': []}]
    assert not app.errors, app.errors


@pytest.mark.parametrize('perms', [[], ['cluster.view', 'node.view', 'vm.view', 'ha.view']], ids=['viewer', 'ha.view'])
def test_runtime_who_is_no_admin_gets_no_tab(open_app, perms):
    """The HA tab and its routes are for admins: ha.view alone reaches none of the controls."""
    app = open_app(admin=False, permissions=perms, auto=_running(), shipped=True)
    app.open_settings()
    assert app.page.locator('button', has_text='High Availability').count() == 0
    assert app.page.locator('[data-ha-auto], [data-ha-witness], [data-ha-zone]').count() == 0
    assert not [c for c in app.server.calls if c[1].startswith('/api/ha/') and c[1] != '/api/ha/status']
    assert not app.errors, app.errors


GERMAN = {
    'title': 'Automatisches Failover',
    'leader': 'Leader: diese Instanz (Epoche 7) · Lease noch 15 s gültig',
    'majority': 'Mehrheit: 2 von 3 Stimmen',
    'look': 'Was zu prüfen ist',
    'quarantined': 'In Quarantäne - aus einem alten Stand wiederhergestellt',
    'witness': 'Zeuge',
    'zone': 'Zeitzone der Zeitpläne',
    'differs': 'Diese Instanz läuft in America/New_York.',
}


def _shown(page, within):
    return page.evaluate('''(sel) => Array.from(document.querySelectorAll(sel)).flatMap(root => [root.innerText,
        ...Array.from(root.querySelectorAll('[title]')).map(e => e.getAttribute('title'))]).join('\\n')''', within)


def test_runtime_everything_speaks_german(open_app):
    app = open_app(language='de', auto=_running(), shipped=True, zone_local='America/New_York')
    page = app.page
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press(',')
    page.locator('button', has_text='Hochverfügbarkeit').first.click()
    panel = page.locator('[data-ha-role="active"]')
    panel.wait_for(timeout=5000)
    card = panel.locator('[data-ha-auto]')
    assert card.inner_text().startswith(GERMAN['title'])
    assert card.locator('[data-ha-auto-leader]').inner_text().strip() == GERMAN['leader']
    assert card.locator('[data-ha-auto-majority]').inner_text().strip() == GERMAN['majority']
    assert GERMAN['look'] in card.inner_text()
    assert GERMAN['quarantined'] in panel.locator(f'[data-ha-member="{C}"]').inner_text()
    assert panel.locator('[data-ha-witness] h4').inner_text().strip() == GERMAN['witness']
    assert panel.locator('[data-ha-zone] h4').inner_text().strip() == GERMAN['zone']
    assert panel.locator('[data-ha-zone-differs]').inner_text().startswith(GERMAN['differs'])
    _switch_de = page.get_by_role('switch', name='Automatisches Failover')
    _switch_de.click()
    assert panel.locator('[data-ha-auto-form="off"]').inner_text().startswith('Die Gruppe kehrt in den manuellen Modus')
    shown = _shown(page, '[data-ha-auto], [data-ha-witness], [data-ha-zone], [data-ha-members]')
    assert not re.search(r'\b(haAuto|haWitness|haZone)\w*', shown), shown
    for english in ('Automatic failover', 'What to look at', 'Majority', 'Time zone of the schedules', 'Quarantined',
                    'heard ', 'Remove witness', 'May lead'):
        assert english not in shown, english
    assert not app.errors, app.errors


@pytest.mark.parametrize('lang', [lang for lang in LANGS if lang not in ('en', 'de')])
def test_runtime_no_key_shows_raw_in_any_language(open_app, lang):
    app = open_app(language=lang, auto=_running(), shipped=True, zone_local='America/New_York')
    page = app.page
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press(',')
    tab = _value(_blocks()[lang], 'pgHaTab')
    page.locator('button', has_text=tab).first.click()
    panel = page.locator('[data-ha-role="active"]')
    panel.wait_for(timeout=5000)
    page.locator('#pgha-auto').click()
    panel.locator('[data-ha-auto-form="off"]').wait_for(timeout=3000)
    shown = _shown(page, '[data-ha-auto], [data-ha-witness], [data-ha-zone], [data-ha-members]')
    assert not re.search(r'\b(haAuto|haWitness|haZone|pgHa)\w*', shown), shown
    assert _value(_blocks()[lang], 'haAutoTitle') in shown
    assert not app.errors, app.errors
