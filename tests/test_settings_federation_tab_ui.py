"""The Federation tab of the settings: the switch, and the panel behind it.

The federation is off on a fresh install and an admin switches it on in this tab, so the
tab is there for every admin who sees all clusters (status answers manage: true), on or
off. Off, the tab holds the switch card alone and sends no other federation request; on,
the panel follows. Switching on asks once more, switching off is refused while the
instance still takes part (the server says to leave first), and a value the environment
forces cannot be flipped here.

The source checks read web/src and the bundle and run everywhere. The runtime tests drive
the built bundle in headless Chromium against the fake server of tests/test_ha_ui.py with
the federation routes answered below; they skip where Playwright is not installed.
MK Nov 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import BASE, _App, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
PASSWORD = 'correct horse'
ME = 'a' * 32
# the words that stay as they are in every language: product names and the like
SAME_AS_EN = {'fedCluster', 'fedInstance', 'fedLease', 'fedNodes', 'fedOnline', 'fedMapKindTenant'}


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


@pytest.fixture(scope='module')
def modal():
    return _read('web', 'src', 'settings_modal.js')


@pytest.fixture(scope='module')
def panel(modal):
    start = modal.index('        // LW Nov 2026 - the federation of instances: the switch')
    return modal[start:modal.index('        function HaPanel(', start)]


@pytest.fixture(scope='module')
def gate(modal):
    start = modal.index('            // LW Nov 2026 - the Federation tab carries the switch')
    return modal[start:modal.index('            // Fetch password policy', start)]


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = sorted((m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M))
    out = {}
    for i, (pos, lang) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(src)
        out[lang] = src[pos:end]
    return out


def _value(block, key):
    m = re.search(r"^ {16}%s: '(.*)',$" % key, block, re.M)
    return m.group(1) if m else None


def _used_keys(modal):
    return sorted(set(re.findall(r"t\('(fed[A-Z]\w*)'\)", modal)))


# -- the tab ------------------------------------------------------------------------------

def test_the_tab_follows_manage_not_the_switch(gate, modal):
    """The tab used to show only when the server ran the federation, and the switch lives
    in it: it must show for an admin who sees every cluster, on or off."""
    assert 'd.manage === true' in gate
    assert 'd.enabled' not in gate
    assert 'if (!isOpen || !isAdmin) return;' in gate
    assert '{isAdmin && fedManage && (' in modal
    assert "{activeTab === 'federation' && isAdmin && fedManage && (" in modal
    assert 'fedEnabled' not in modal


def test_off_the_panel_asks_for_nothing_but_the_status(panel):
    """An off server answers every federation route but the status and the switch with
    404: the leases, the clusters and the linked view are read only while it is on."""
    poll = panel[panel.index('            useEffect(() => {\n                let alive = true;'):]
    poll = poll[:poll.index('            }, []);')]
    assert "const on = !!s && s.enabled === true;" in poll
    assert 'if (alive && on) {' in poll
    # nothing is read before the status said on
    before = poll[:poll.index('if (alive && on) {')]
    assert 'refreshLeases' not in before and 'refreshFedClusters' not in before and 'refreshClusters' not in before
    # everything but the switch card sits behind `on`
    body = panel[panel.index('data-fed-panel='):]
    for card in ('{on && !joined && (', '{on && joined && (',
                 '{drOn && !joined && (own.length > 0 || !!leasesError) && ownCard}'):
        assert card in body, card
    # what the disaster recovery holds shows only while it is on as well
    assert 'const drOn = on && !!dr && dr.enabled === true;' in panel


def test_the_switch_asks_before_it_goes_on_and_not_before_it_goes_off(panel):
    card = panel[panel.index('const switchCard = ('):panel.index('const pairingCard = (')]
    assert 'role="switch"' in card and 'aria-checked={on}' in card
    assert 'if (on) flip(false); else setAskOn(true);' in card
    assert 'data-fed-switch-confirm' in card and 'onClick={() => flip(true)}' in card
    flip = panel[panel.index('async function flip(value, untoldOk)'):panel.index('// `judge` reads')]
    assert "fedSend('POST', 'switch', { enabled: value, ...(untoldOk ? { untold_ok: true } : {}) }" in flip
    # a refusal keeps the server's own sentence where the switch is
    assert 'setSwitchError(r.error)' in flip


def test_a_forced_value_and_a_blocked_switch_cannot_be_flipped(panel):
    assert ("const flipDisabled = !status || !!busy || forced || !localOk || (on && status.can_disable !== true);"
            in panel)
    assert "fedFill(t('fedSwitchForced'), { value: on ? '1' : '0' })" in panel
    assert "fedFill(t('fedSwitchBlocked'), { reasons: blockers.map(b => reasonText[b] || b).join(', ') })" in panel


def test_the_password_field_follows_the_reauth_the_server_names(panel):
    """The tab guessed from auth_source, and an OIDC account with a password hash looped
    on FED_REAUTH. The status says which one the server wants."""
    assert "const askPw = !status || status.reauth !== 'recent_session';" in panel
    assert 'auth_source' not in panel and '!sso' not in panel


def test_a_mirrored_admin_gets_no_state_changing_control(panel):
    assert "const localOk = !status || status.local_account !== false;" in panel
    for marker in ('data-fed-make-code', 'data-fed-join', 'data-fed-remove=', 'data-fed-leave disabled',
                   'data-fed-release=', 'data-fed-unenroll=', 'data-fed-adopt=', 'data-fed-enroll=',
                   'data-fed-unmap=', 'data-fed-map-go=', 'data-fed-takeover-all=', 'data-fed-takeover=',
                   'data-fed-renew=', 'data-fed-sync'):
        at = panel.index(marker)
        near = panel[max(0, at - 60):at + 300]
        assert '!localOk' in near, marker


# -- pairing and the member limit ---------------------------------------------------------

def test_the_member_limit_is_the_servers(panel):
    """max_sites counts this instance and create_pairing_code refuses once the members plus
    this one reach it, so a code is offered while members + 1 < max_sites."""
    assert 'const canPairMore = members.length + 1 < maxSites;' in panel
    assert 'status.max_sites' in panel and 'max_members' not in panel
    assert "fedFill(t('fedMaxMembers'), { max: maxSites })" in panel
    assert "fedFill(t('fedFull'), { max: maxSites })" in panel


def test_the_pairing_card_of_a_joined_instance_adds_a_site(panel):
    card = panel[panel.index('const pairingCard = ('):panel.index('// ---- the confirm box')]
    assert "{joined ? t('fedAddSiteTitle') : t('fedStartTitle')}" in card
    assert "{joined ? t('fedAddSiteDesc') : t('fedStartDesc')}" in card
    body = panel[panel.index('data-fed-panel='):]
    assert body.count('{canPairMore && pairingCard}') == 2


def test_the_server_constants_the_panel_repeats():
    """The panel repeats two numbers of the server: keep them in step."""
    from pegaprox.core import federation, federation_lease
    src = _read('web', 'src', 'settings_modal.js')
    assert f'const FED_MIN_SITES_TO_ENROLL = {federation_lease.MIN_SITES_TO_ENROLL};' in src
    assert federation.MAX_SITES == 8 and "status.max_sites > 1) ? status.max_sites : 8;" in src


# -- toasts report success only on success ------------------------------------------------

def test_a_judged_answer_replaces_the_done_toast(panel):
    act = panel[panel.index('async function act('):panel.index('function askConfirm(')]
    assert 'if (verdict) addToast(verdict.text, verdict.kind);' in act
    assert "else addToast(doneToast, 'success');" in act


def test_a_refused_renewal_is_an_error(panel):
    renew = panel[panel.index("act('renew-' + cid"):]
    renew = renew[:renew.index("{t('fedRenew')}")]
    assert 'if (d.renewed === true) return null;' in renew
    assert "return { kind: 'error', text: fedFill(t('fedRenewRefused'), { votes: d.votes || 0, needed: d.needed || 0 }) };" in renew
    assert 'reacquired' not in renew and "kind: 'info', text: t('fedRenewRefused')" not in panel


def test_partial_outcomes_are_warnings(panel):
    assert "kind: 'warning', text: fedFill(t('fedRemovedLocalOnly'), { count: missed })" in panel
    assert "kind: 'warning', text: fedFill(t('fedLeftLocalOnly'), { count: missed })" in panel
    assert "d.manager === false ? { kind: 'warning', text: t('fedAdoptedPending') }" in panel
    assert "kind: 'warning', text: fedFill(t('fedSyncPartial')" in panel
    # a removal that leaves copies of our clusters behind says to change their credentials
    assert 'd.remedy.enrolled_here' in panel and "t('fedRotateAfterRemove')" in panel


def test_the_lease_cell_reads_the_shape_the_server_sends(panel):
    """lease_status gives held, remaining_s, votes, needed, released, lost_to; no term."""
    cell = panel[panel.index('const leaseCell = (cid) => {'):panel.index('const count = (c, field)')]
    for field in ('l.held', 'l.remaining_s', 'l.needed', 'l.released', 'l.lost_to'):
        assert field in cell, field
    assert 'l.valid' not in panel and 'l.term' not in panel


# -- two sites: the owner writes alone, the other site takes over by hand -------------------

def test_two_sites_are_told_by_the_member_count_and_gate_every_new_control(panel):
    """No status field says "two sites": one member besides this instance is it. The card,
    the takeover buttons, the gone-for-good tick and the leave hint all hang on it, so
    three or more sites see the tab as before. Counterproof: twoSites on members.length
    >= 1 shows the card and the takeover to three sites (runtime test below)."""
    assert 'const twoSites = joined && members.length === 1;' in panel
    assert "const silent = (m) => !!m && m.reachable === false && !m.removed_us;" in panel
    assert '{drOn && twoSites && (\n                                <div className={HA_GROUP_CARD} data-fed-two-sites>' in panel
    assert '{drOn && twoSites && silent(m) && m.mirrored_clusters > 0 && (' in panel
    assert 'goneOffered: twoSites && silent(m) })' in panel
    assert 'const byHand = twoSites && silent(members.find(m => m.instance_id === info.owner));' in panel
    assert "if (!r.ok && r.code === 'FED_NO_QUORUM' && twoSites) {" in panel
    assert '{twoSites && <p className="text-xs text-gray-400" data-fed-shadows-two>' in panel


def test_the_takeover_box_wants_the_tick_the_word_and_the_password(panel):
    """Go stays off until the owner-down tick, TAKEOVER and the password are there and the
    server's wait is over; the body states owner_down itself. Counterproof: the Go button
    without !ownerDown lets a takeover go out unticked (runtime test below)."""
    assert "takeover: 'TAKEOVER', takeoverAll: 'TAKEOVER', map: null };" in panel
    assert "setOwnerDown(false); setGone(false); setDropOk(false);" in panel[panel.index('function askConfirm('):]
    run = panel[panel.index('if (takeoverBox) {'):panel.index("if (c.kind === 'leave') {")]
    assert 'if (!ownerDown || waitLeft > 0) return;' in run
    assert "const body = { confirm: 'TAKEOVER', owner_down: true, force: forceOffered && force, ...pw };" in run
    assert "all ? `members/${c.owner}/takeover` : `clusters/${c.id}/takeover`" in run
    assert "|| (takeoverBox && (!ownerDown || waitLeft > 0))}>" in panel
    assert 'checked={ownerDown} onChange={e => setOwnerDown(e.target.checked)}' in panel
    # force only after the server said the owner's field key is missing
    assert "(confirmBox.kind === 'adopt' || (takeoverBox && forceOffered))" in panel
    assert "if (r.code === 'FED_NO_KEY') setForceOffered(true);" in run
    # the wait counts down from what the status said, and from the server's retry_after
    assert 'const wait = Number.isInteger(m.takeover_in_s) ? m.takeover_in_s : 0;' in panel
    assert 'const waitLeft = waitUntil ? Math.max(0, Math.ceil((waitUntil - now) / 1000)) : 0;' in panel
    assert "r.code === 'FED_OWNER_RECENT' && retry > 0 ? { waitUntil: at + retry * 1000 } : {}" in run


def test_a_refused_takeover_keeps_its_box_and_adopt_hands_over_to_it(panel):
    """FED_OWNER_ALIVE and FED_OWNER_RECENT leave the box open with the server's sentence;
    an adoption the server answers FED_USE_TAKEOVER opens the takeover box. Counterproof:
    without the refused field the sentence shows as a toast only."""
    run = panel[panel.index('if (takeoverBox) {'):panel.index("if (c.kind === 'leave') {")]
    assert "if (r.ok || r.code === 'AUTH') return;" in run
    assert 'refused: r.error' in run
    assert 'data-fed-confirm-error>{confirmBox.refused}</p>' in panel
    adopt = panel[panel.index("if (c.kind === 'adopt') {"):panel.index("if (c.kind === 'enroll')")]
    assert "if (!r.ok && r.code === 'FED_USE_TAKEOVER') askTakeover('takeover', c.id, c.name, r.data.owner || c.owner);" in adopt
    send = panel[panel.index('async function fedSend('):panel.index('async function refreshStatus()')]
    assert "data: data || {} };" in send
    # with no answer at all as well: the box reads r.data after a failed request
    assert "return { ok: false, error: fallback, code: '', data: {} };" in send


def test_the_lease_cell_shows_a_lease_held_alone_and_a_takeover(panel):
    """lease_status adds alone and takeover {from, at, by, confirmed_at}. Counterproof: a
    cell that reads l.held first shows a lease held alone as 2 of 2 in green."""
    cell = panel[panel.index('const takenLine = (l) => {'):panel.index('const count = (c, field)')]
    assert cell.index('if (l.held && l.alone) {') < cell.index('} else if (l.held) {')
    assert "fedFill(t('fedLeaseAlone'), { site: otherSite || '-', seconds: l.remaining_s || 0 })" in cell
    assert 'data-fed-lease-alone={cid}' in cell
    assert 'return tk.confirmed_at' in cell and "t('fedTakeoverDone')" in cell and "t('fedTakeoverPending')" in cell
    renew = panel[panel.index("act('renew-' + cid"):]
    renew = renew[:renew.index("{t('fedRenew')}")]
    assert renew.index('if (d.renewed === true && d.alone)') < renew.index('if (d.renewed === true) return null;')


def test_the_stepped_down_note_is_for_a_takeover_only(panel):
    """stepped_down also lists clusters handed on by adoption; the note says "while this
    site did not answer", which is true for a takeover by hand only. Counterproof: without
    the kind check a plain hand-over gets the note."""
    assert "const steppedDown = (leases && leases.stepped_down) || {};" in panel
    assert "const down = steppedDown[cid] && steppedDown[cid].kind === 'takeover' ? steppedDown[cid] : null;" in panel
    assert 'data-fed-stepped-down={cid}' in panel


def test_a_site_gone_for_good_needs_its_own_tick_and_the_drop_its_own(panel):
    run = panel[panel.index("if (c.kind === 'remove') {"):panel.index('if (takeoverBox) {')]
    assert "const goneFor = c.goneOffered && gone ? { gone: true, ...(dropOk ? { drop_clusters: true } : {}) } : {};" in run
    assert "{ confirm: 'REMOVE', ...goneFor, ...pw }" in run
    assert "goneFor.gone ? t('fedRemovedAlone') : t('fedRemoved')" in run
    assert "if (!r.ok && r.code === 'FED_GONE_CLUSTERS') {" in run
    assert "{confirmBox.kind === 'remove' && gone && Array.isArray(confirmBox.goneClusters)" in panel


def test_the_end_banner_and_the_untold_switch(panel):
    """A site the other one removed as gone for good says so instead of "removed"; the
    survivor's switch asks once more while that site has not confirmed it was told, and
    only then sends untold_ok. Counterproof: flipping off at once posts without the confirm
    (runtime)."""
    assert "status.removed.ended" in panel and "t('fedEndedByOther')" in panel
    assert "status.disable_warnings.includes('ended_untold')" in panel
    assert 'if (on && untoldWarn) setAskOff(true); else if (on) flip(false); else setAskOn(true);' in panel
    assert 'onClick={() => flip(false, true)}' in panel
    assert "if (r.code === 'FED_ENDED_UNTOLD') setAskOff(true);" in panel


def test_the_panel_speaks_the_two_site_contract_of_the_server():
    """Each route, word, field and code the panel reads for two sites, next to where the
    server makes it. Counterproof: a field renamed on either side turns this red."""
    panel_src = _read('web', 'src', 'settings_modal.js')
    api = _read('pegaprox', 'api', 'federation.py')
    core = _read('pegaprox', 'core', 'federation.py') + _read('pegaprox', 'core', 'federation_lease.py')
    assert "'/api/federation/clusters/<cluster_id>/takeover'" in api and '`clusters/${c.id}/takeover`' in panel_src
    assert "'/api/federation/members/<instance_id>/takeover'" in api and '`members/${c.owner}/takeover`' in panel_src
    assert "data.get('confirm') != 'TAKEOVER'" in api and "data.get('owner_down') is not True" in api
    assert "data.get('gone') is True" in api and "data.get('drop_clusters') is True" in api
    assert "data.get('untold_ok') is True" in api
    for field in ("'last_heard'", "'takeover_in_s'"):
        assert field in api, field
    assert 'm.last_heard' in panel_src and 'm.takeover_in_s' in panel_src
    for field in ("'alone': bool(rec.get('alone'))", "'confirmed_at'", "out['stepped_down'][cid]", "'stopped_at'"):
        assert field in core, field
    for code in ('FED_USE_TAKEOVER', 'FED_OWNER_ALIVE', 'FED_OWNER_RECENT', 'FED_NO_KEY', 'FED_GONE_CLUSTERS',
                 'FED_ENDED_UNTOLD', 'FED_NO_QUORUM'):
        assert f"code='{code}'" in core, code
        assert f"'{code}'" in panel_src, code
    assert "warnings.append('ended_untold')" in core
    assert "'ended': True" in core and "'clusters': dropped" in core


def test_the_two_site_strings_say_what_the_code_does():
    """Two sites enroll now, the risk of a takeover is said in plain words (in the switch
    card too, which is all a reader sees before switching on), what the old owner did
    meanwhile is said to stay, a removed site that did not confirm its end is not said to
    be untold (the confirmation can be lost), and the German of the risk-bearing keys is
    the agreed one."""
    blocks = _blocks()
    en, de = blocks['en'], blocks['de']
    for lang in LANGS:
        assert 'three' not in (_value(blocks[lang], 'fedEnrollNeedsSites') or '').lower(), lang
    assert _value(en, 'fedEnrollNeedsSites') == 'Enrolling needs a second site: pair one first.'
    assert 'both sites write to the same cluster' in _value(en, 'fedTwoRisk')
    assert 'both sites write to the cluster until they reach each other again' in _value(en, 'fedTakeoverNote')
    assert 'With two sites' in _value(en, 'fedLeasesDesc') and 'With two sites' in _value(en, 'fedAdoptNote')
    assert 'only while a majority' not in _value(en, 'fedSwitchDesc')
    assert 'both sites write to the cluster until they reach each other again' in _value(en, 'fedSwitchDesc')
    assert 'with two by a takeover' not in _value(en, 'fedSwitchDesc')
    assert 'stays in effect and is not undone' in _value(en, 'fedTakeoverNote')
    assert _value(en, 'fedSwitchEndedUntold').startswith('A site this instance removed as gone for good has '
                                                         'not confirmed that it was told')
    assert _value(de, 'fedSwitchDesc') == (
        'Verbindet diese Instanz mit bis zu sieben weiteren PegaProx-Instanzen: Konten werden zwischen den '
        'Standorten gespiegelt, und mit der Disaster Recovery unten lassen sich die Cluster eines endgültig '
        'ausgefallenen Standorts übernehmen. '
        'Ab drei Standorten schützt die Mehrheit einen aufgenommenen Cluster vor zwei Schreibern. Bei zwei '
        'Standorten übernimmt ein Admin einen Cluster von Hand, wenn der andere Standort nicht antwortet; läuft '
        'dieser noch, schreiben beide Standorte auf den Cluster, bis sie einander wieder erreichen.')
    assert ('Dann hört {site} sofort auf. Was er inzwischen auf dem Cluster getan hat, bleibt bestehen und wird '
            'nicht rückgängig gemacht; was er in PegaProx geändert hat, wird nicht übernommen.') in _value(de, 'fedTakeoverNote')
    assert _value(de, 'fedTakeover') == 'Manuelle Übernahme'
    assert _value(de, 'fedTwoRisk').startswith('Eine Übernahme kann einen ausgefallenen Standort nicht von einer '
                                               'ausgefallenen Verbindung unterscheiden.')
    assert _value(de, 'fedTakeoverDown') == ('Ich habe es geprüft: {site} ist ausgefallen, nicht nur von diesem '
                                             'Standort abgeschnitten.')
    assert _value(de, 'fedRemoveGone').startswith('{site} ist endgültig weg. Dieser Standort macht allein weiter')


# -- enrolling and the linked view --------------------------------------------------------

def test_every_local_cluster_can_be_enrolled(panel):
    body = panel[panel.index('data-fed-unenrolled='):]
    body = body[:body.index('</table>')]
    assert 'listed.map(c =>' in body and '.slice(' not in body
    assert 'unenrolled.length > FED_FILTER_FROM' in panel
    # only a Proxmox VE cluster can be enrolled, as the server says
    assert "(c.cluster_type || 'proxmox') === 'proxmox'" in panel


def test_peer_rows_carry_counts_and_say_what_is_left_out(panel):
    view = panel[panel.index('data-fed-clusters'):panel.index('data-fed-shadows')]
    assert "count(c, 'nodes')" in view and "count(c, 'vms')" in view
    assert 'const more = Number.isInteger(p.total) ? p.total - rows.length : 0;' in view
    assert "fedFill(t('fedPeerMore'), { count: more, site })" in view


def test_a_failed_read_of_the_leases_or_the_view_is_said(panel):
    """A failed leases read showed 'no clusters enrolled' and offered every enrolled cluster
    for enrolling; one after a good read kept showing the old lease as held. A failed
    linked view left 'Working...' for good. Each says the error now, and the old answer
    goes."""
    leases = panel[panel.index('async function refreshLeases()'):panel.index('async function refreshFedClusters()')]
    assert "else if (r.code !== 'AUTH') { setLeases(null); setLeasesError(r.error); }" in leases
    assert "setLeasesError('')" in leases
    view = panel[panel.index('async function refreshFedClusters()'):panel.index('async function refreshIdMap()')]
    assert "fedSend('GET', 'clusters', null, t('fedLoadFailed'))" in view
    assert 'setFedClustersError(r.error)' in view
    assert 'data-fed-leases-error' in panel and 'data-fed-clusters-error' in panel
    assert "{own.length === 0 && !leasesError && <p" in panel
    # nobody knows what is enrolled without a leases answer: nothing is offered to enroll
    assert 'const unenrolled = leases ? (clusters || [])' in panel
    # a newer read wins: an older answer landing after it neither brings back the list nor
    # takes the error away, and a switch-off drops the reads still on their way
    for name, part in (('leases', leases), ('view', view)):
        assert f'const seq = ++reads.current.{name};' in part
        assert f'if (seq !== reads.current.{name}) return;' in part
    assert 'if (!value) { reads.current.leases++; reads.current.view++;' in panel


def test_the_filter_stays_while_it_filters(panel):
    """Enrolling one of 13 clusters left 12: the field went away while its text still
    filtered the list to nothing."""
    assert '{(unenrolled.length > FED_FILTER_FROM || needle) && (' in panel


# -- accounts of other sites ----------------------------------------------------------------

def test_the_mapping_is_read_only_while_on(panel):
    """identity-map answers 404 while off like every other federation route."""
    assert "fedSend('GET', 'identity-map'" in panel
    running = panel[panel.index('function refreshRunning()'):panel.index('useEffect(() => {')]
    assert 'refreshIdMap()' in running
    poll = panel[panel.index('            useEffect(() => {\n                let alive = true;'):]
    poll = poll[:poll.index('            }, []);')]
    before = poll[:poll.index('if (alive && on) {')]
    assert 'refreshIdMap' not in before
    assert '{mapCard}' in panel[panel.index('{on && joined && ('):]


def test_a_mapping_wants_the_password_and_no_word_and_unmapping_wants_neither(panel):
    assert 'map: null };' in panel
    assert "if (!c || (confirmWords[c.kind] && typed !== confirmWords[c.kind])) return;" in panel
    run = panel[panel.index("if (c.kind === 'map') {"):panel.index('function unmap(')]
    assert "{ home: c.home, kind: c.mapKind, home_value: c.value, local_value: c.local, ...pw }" in run
    assert "d.pulled === false ? { kind: 'warning', text: fedFill(t('fedMapPending'), { site: c.site }) }" in run
    unmap = panel[panel.index('function unmap('):]
    unmap = unmap[:unmap.index('}\n')]
    assert "local_value: '' }" in unmap and 'user_password' not in unmap and '...pw' not in unmap


def test_waiting_accounts_are_shown_and_counted(panel):
    assert "fedFill(t('fedMapWaiting'), { count: m.unmapped })" in panel
    assert "Number.isInteger(x.quarantined) ? x.quarantined : 0" in panel
    assert "kind: 'info', text: fedFill(t('fedSyncUnmapped'), { count: waiting })" in panel


def test_a_mirrored_user_carries_a_badge_and_no_actions(modal):
    users = modal[modal.index("{user.auth_source === 'oidc' && ("):]
    users = users[:users.index('{/* LW: pagination */}')]
    assert "{user.fed_home && (" in users and "{t('fedMirrorBadge')}" in users
    assert ") : user.fed_home ? (" in users
    actions = users[users.index(') : user.fed_home ? ('):]
    head = actions[:actions.index(') : (')]
    assert 'onClick' not in head and "fedFill(t('fedMirrorBadgeTitle')" in head


# -- translations --------------------------------------------------------------------------

def test_every_fed_key_is_there_once_in_every_language(modal):
    blocks = _blocks()
    used = _used_keys(modal)
    assert len(used) > 120
    for lang in LANGS:
        for key in used:
            n = len(re.findall(r'^ {16}%s: ' % key, blocks[lang], re.M))
            assert n == 1, (lang, key, n)


def test_no_fed_key_is_defined_that_nothing_uses(modal):
    used = set(_used_keys(modal))
    for lang, block in _blocks().items():
        defined = set(re.findall(r'^ {16}(fed[A-Z]\w*): ', block, re.M))
        assert defined == used, (lang, sorted(defined ^ used))


def test_placeholders_survive_and_the_words_are_translated(modal):
    blocks = _blocks()
    for key in _used_keys(modal) + ['apiRefSchemeFedPeer']:
        en = _value(blocks['en'], key)
        assert en, key
        for lang in LANGS:
            value = _value(blocks[lang], key)
            assert value and value.strip(), (lang, key)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)
            if lang != 'en' and key not in SAME_AS_EN:
                assert value != en, f'{lang}.{key} is the English text'


def test_the_new_strings_say_what_the_code_does():
    en = _blocks()['en']
    # the member limit counts this instance, like the server
    assert _value(en, 'fedMaxMembers') == 'up to {max} sites'
    assert 'max.' not in _value(en, 'fedMaxMembers')
    # pairing never hands over keys that make sign-ins work everywhere
    assert 'exchange' not in _value(en, 'fedStartDesc') and 'work everywhere' not in _value(en, 'fedStartDesc')
    # a removal says the copies it holds stay readable and what to do about it
    assert 'stay readable there' in _value(en, 'fedRemoveNote') and 'change their credentials' in _value(en, 'fedRemoveNote')
    assert 'shadows stay' not in _value(en, 'fedRemoveNote')
    assert "federation key" in _value(en, 'fedShadowsDesc') and 'field key' not in _value(en, 'fedShadowsDesc')
    assert 'PEGAPROX_FEDERATION={value}' in _value(en, 'fedSwitchForced')


def test_the_fed_block_sits_before_the_pinned_banner_block():
    for lang, block in _blocks().items():
        head = block.index('// LW Nov 2026 - federation of instances, experimental: the tab carries the switch')
        banner = block.index(' - the banners of a group that fails over automatically, for every user')
        last_fed = max(m.start() for m in re.finditer(r'^ {16}fed[A-Z]\w*: ', block, re.M))
        assert head < last_fed < banner, lang
        assert block.index('apiRefSchemeFedPeer:') < banner, lang


def test_no_dash_of_the_forbidden_kinds_in_the_new_lines(panel):
    lines = [line for block in _blocks().values() for line in block.splitlines()
             if re.match(r'^ {16}(fed[A-Z]\w*|apiRefSchemeFedPeer): ', line)]
    assert len(lines) > 1300
    for text in [panel] + lines:
        assert chr(0x2014) not in text and chr(0x2013) not in text


def test_the_api_reference_names_the_federation_peer_scheme():
    ui = _read('web', 'src', 'ui.js')
    assert "case 'federationPeer': return t('apiRefSchemeFedPeer');" in ui
    spec = json.loads(_read('docs', 'openapi.json'))
    assert 'federationPeer' in spec['components']['securitySchemes']


# -- styling and the bundle ----------------------------------------------------------------

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


def test_every_class_is_in_the_static_tailwind_build(panel):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(panel) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists(panel):
    icons = _read('web', 'src', 'icons.js')
    used = set(re.findall(r'Icons\.([A-Za-z]+)', panel))
    assert {'Globe', 'Power', 'Lock', 'Search', 'X'} <= used
    for name in used:
        assert re.search(r'\b%s: \(' % name, icons), name


def test_the_bundle_was_rebuilt(modal):
    bundle = _read('web', 'index.html')
    for needle in ('function FederationPanel(', 'function fedFill(', 'data-fed-switch', 'd.manage===true',
                   "case'federationPeer'", 'fedSwitchTitle', 'apiRefSchemeFedPeer', 'data-fed-two-sites',
                   'data-fed-owner-down', 'fedTakeoverNote', 'data-fed-remove-gone'):
        assert needle in bundle, needle
    assert 'fedLeaseTerm' not in bundle
    # the bundle carries the server's minimum, not the old three
    assert re.search(r'FED_MIN_SITES_TO_ENROLL\s*=\s*2\b', bundle)
    for lang in LANGS:
        if lang == 'en':
            continue
        data = json.loads(_read('web', 'i18n', f'{lang}.json'))
        data = data.get(lang, data) if isinstance(data, dict) else data
        flat = json.dumps(data, ensure_ascii=False)
        for key in ('fedSwitchTitle', 'fedSwitchForced', 'fedAddSiteTitle', 'fedPeerMore', 'apiRefSchemeFedPeer',
                    'fedTwoRisk', 'fedTakeoverNote', 'fedRemoveGone', 'fedSwitchEndedUntold'):
            assert f'"{key}"' in flat, (lang, key)
        assert '"fedLeaseTerm"' not in flat, lang


# -- runtime: the built bundle in a real browser ----------------------------------------------

def _member(n, site, **kw):
    rec = {'instance_id': str(n) * 32, 'url': f'https://{site}.example:5000', 'site': site,
           'fingerprints': [], 'added_at': 1763200000, 'last_seen': 1763200000, 'reachable': True,
           'removed_us': False, 'fed': 1, 'view_epoch': 3, 'has_key': True, 'mirrored_clusters': 0,
           'identity_sync': {'etag': 'x', 'pulled_at': 1763200000, 'rows': 4}}
    rec.update(kw)
    return rec


FED_DISABLED = {'error': 'The federation is switched off on this instance - an admin switches it on '
                         'in the settings, under Federation', 'code': 'FED_DISABLED'}
LEAVE_FIRST = ('Leave the federation first: this instance still takes part in it (member, mirrors). '
               'Switching off would strand what the other sites rely on')


class _FedServer(_FakeServer):
    """The federation routes on top of the HA fake: the switch with its refusals, the
    status in both states, the reads behind it and the actions the tests drive."""

    def __init__(self, fed=None, **kw):
        kw.setdefault('role', 'standalone')
        super().__init__(**kw)
        self.fed = {'enabled': False, 'forced': False, 'blockers': [], 'manage': True, 'local': True,
                    'reauth': 'password', 'members': [], 'refuse_off': False, 'leases': {},
                    'enrolled': {}, 'hold_s': 0, 'view': {'self': [], 'peers': {}}, 'replies': {},
                    'url': '', 'site': '', 'idmap': None, 'pull_ok': True, 'removed': None, 'warnings': [],
                    'stepped_down': {},
                    # the disaster recovery: on here unless a test says otherwise, as the
                    # leases, the enrollment and the takeover these tests drive need it
                    'dr': True, 'dr_forced': False, 'dr_blockers': []}
        self.fed.update(fed or {})

    def fed_status(self):
        f = self.fed
        blockers = list(f['blockers']) if f['enabled'] else []
        out = {'enabled': f['enabled'], 'forced': f['forced'],
               'can_disable': bool(f['enabled'] and not f['forced'] and not blockers),
               'disable_blockers': blockers, 'manage': f['manage'], 'local_account': f['local'],
               'reauth': f['reauth']}
        if f['enabled'] and f['warnings']:
            out['disable_warnings'] = list(f['warnings'])
        if f['enabled']:
            dr_blockers = list(f['dr_blockers']) if f['dr'] else []
            out['dr'] = {'enabled': f['dr'], 'forced': f['dr_forced'],
                         'can_disable': bool(f['dr'] and not f['dr_forced'] and not dr_blockers),
                         'disable_blockers': dr_blockers}
        if f['enabled'] and f['manage']:
            out.update({'instance_id': ME, 'public_key': 'x', 'site': f['site'], 'url': f['url'],
                        'fingerprints': [], 'max_sites': 8, 'view_epoch': 3, 'removed': f['removed'],
                        'removed_by_some': [], 'view_conflict': False, 'field_key_id': 'abcd1234',
                        'pairing_open': None, 'members': [dict(m) for m in f['members']]})
        return out

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not req.url.startswith(BASE) or not path.startswith('/api/federation/'):
            return super().handle(route)
        self.calls.append((req.method, path))
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        if req.method != 'GET':
            self.bodies.setdefault(path, []).append(body)

        def answer(data, status=200):
            return route.fulfill(status=status, body=json.dumps(data),
                                 headers={'Content-Type': 'application/json'})

        f = self.fed
        if not self.admin:
            return answer({'error': 'Admin required'}, 403)
        if path == '/api/federation/status':
            return answer(self.fed_status())
        if path == '/api/federation/dr':
            value = body.get('enabled')
            if not value and f['dr_blockers']:
                return answer({'code': 'FED_DR_IN_USE', 'blockers': list(f['dr_blockers']),
                               'error': 'Unenroll every cluster first'}, 409)
            f['dr'] = value is True
            return answer(self.fed_status()['dr'])
        if f['enabled'] and not f['dr'] and (
                path == '/api/federation/leases'
                or (req.method == 'POST' and path.startswith('/api/federation/clusters/'))):
            return answer({'code': 'FED_DR_OFF', 'error': 'Disaster recovery is switched off'}, 409)
        if path == '/api/federation/switch':
            value = body.get('enabled')
            if not isinstance(value, bool):
                return answer({'error': 'Send {"enabled": true} or {"enabled": false}', 'code': 'FED_BAD_VALUE'}, 400)
            if f['forced']:
                return answer({'code': 'FED_FORCED', 'blockers': [],
                               'error': f'The server sets this with PEGAPROX_FEDERATION={"1" if f["enabled"] else "0"} '
                                        '- change it there'}, 409)
            if not value and f['enabled'] and (f['refuse_off'] or f['blockers']):
                return answer({'code': 'FED_IN_USE', 'error': LEAVE_FIRST, 'blockers': ['member', 'mirrors']}, 409)
            if not value and f['enabled'] and f['warnings'] and body.get('untold_ok') is not True:
                return answer({'code': 'FED_ENDED_UNTOLD', 'blockers': [], 'sites': ['2' * 32],
                               'error': 'hamburg has not confirmed that it was told this instance carried on alone'}, 409)
            if not value:
                f['warnings'] = []
            f['enabled'] = value
            st = self.fed_status()
            return answer({k: st[k] for k in ('enabled', 'forced', 'can_disable', 'disable_blockers')})
        if not f['enabled']:
            return answer(FED_DISABLED, 404)
        if (req.method, path) in f['replies']:
            status, data = f['replies'][(req.method, path)]
            if status is None:
                # no answer at all: the request fails in the browser
                return route.abort('failed')
            return answer(data, status)
        if path == '/api/federation/leases':
            return answer({'leases': f['leases'], 'promises': {}, 'enrolled': f['enrolled'], 'hold_s': f['hold_s'],
                           'stepped_down': f['stepped_down']})
        if path == '/api/federation/clusters':
            return answer(f['view'])
        if path == '/api/federation/identity-map' and req.method == 'GET':
            return answer(f['idmap']) if f['idmap'] is not None else answer({'error': 'not mocked'}, 404)
        if path == '/api/federation/identity-map' and req.method == 'POST':
            if body.get('local_value') and f['reauth'] == 'password' and body.get('user_password') != PASSWORD:
                return answer({'error': 'The password is not correct', 'code': 'FED_REAUTH'}, 403)
            for e in f['idmap']['members'][body.get('home')]['entries']:
                if (e['kind'], e['home_value']) == (body.get('kind'), body.get('home_value')):
                    e['local_value'] = body.get('local_value') or ''
            return answer({'saved': True, 'pulled': f['pull_ok'], 'report': None})
        if req.method == 'POST' and f['reauth'] == 'password' and body.get('user_password') != PASSWORD \
                and re.search(r'/(pairing-code|join|remove|leave|enroll|release|unenroll|adopt|takeover)$', path):
            return answer({'error': 'The password is not correct', 'code': 'FED_REAUTH'}, 403)
        return answer({'error': 'not mocked'}, 404)


TOAST_SPY = """(() => {
    // a poll, not an observer: the page replaces what an early observer would watch
    window.__toasts = [];
    const seen = new WeakSet();
    setInterval(() => document.querySelectorAll('.toast-enter').forEach(el => {
        if (seen.has(el)) return;
        seen.add(el);
        window.__toasts.push({
            text: el.textContent,
            kind: el.className.includes('red-500') ? 'error' : el.className.includes('green-500') ? 'success' : 'other'});
    }), 50);
})();"""

TAB_LABEL = {'en': 'Federation', 'de': 'Föderation', 'zh': '联邦'}


class _FedApp(_App):
    """_App with a spy on the toasts: they live three seconds, a test reads them later."""

    def __init__(self, browser, server, script=None):
        self.server = server
        self.ctx = browser.new_context(viewport={'width': 1600, 'height': 1000})
        self.ctx.add_init_script("""try {
            for (const u of ['admin', 'viewer']) localStorage.setItem('pegaprox_sponsor_v2:' + u, String(Date.now() + 1e10));
            localStorage.setItem('pegaprox-shortcuts-hint-shown', '1');
        } catch (e) {}""")
        self.ctx.add_init_script(TOAST_SPY)
        if script:
            self.ctx.add_init_script(script)
        self.page = self.ctx.new_page()
        self.errors = []
        self.loads = []
        self.page.on('pageerror', lambda e: self.errors.append(f'pageerror: {e}'))
        self.page.on('console', self._console)
        self.page.route('**/*', server.handle)
        self.page.goto(BASE + '/', wait_until='load')
        self.wait_for_app()

    def toasts(self):
        return self.page.evaluate('() => window.__toasts || []')

    def open_tab(self, lang='en'):
        if lang == 'en':
            self.open_settings()
            self.page.wait_for_timeout(600)
        else:
            # the dialog title is translated too: "g ," and wait for the tab itself
            self.page.locator('body').click(position={'x': 5, 'y': 400})
            self.page.keyboard.press('g')
            self.page.keyboard.press(',')
            try:
                self.page.locator('button', has_text=TAB_LABEL[lang]).first.wait_for(timeout=6000)
            except Exception:
                return False
        tab = self.page.locator('button', has_text=TAB_LABEL[lang])
        if tab.count() == 0:
            return False
        tab.first.click()
        self.page.locator('[data-fed-panel]').first.wait_for(timeout=5000)
        self.page.wait_for_timeout(400)
        return True

    def fed_calls(self, path):
        return sum(1 for c in self.server.calls if c[1] == '/api/federation/' + path)


@pytest.fixture
def open_fed(browser):
    apps = []

    def _open(fed=None, script=None, **kw):
        app = _FedApp(browser, _FedServer(fed=fed, **kw), script=script)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _switch(page):
    return page.locator('#fed-switch')


_OWN = {'pve1': {'name': 'prod', 'owner': ME}}
_HELD = {'pve1': {'held': True, 'remaining_s': 22, 'votes': 2, 'needed': 2, 'released': False,
                  'adopted': False, 'lost_to': ''}}
_LEASES_FAIL = (500, {'error': 'The lease file cannot be read'})
# the first answer of the leases route reaches the panel late, every later one at once
_FIRST_LEASES_LATE = """(() => {
    const orig = window.fetch.bind(window);
    let n = 0;
    window.fetch = async (...a) => {
        const u = String((a[0] && a[0].url) || a[0]);
        const r = await orig(...a);
        if (u.includes('/api/federation/leases') && n++ === 0) await new Promise(res => setTimeout(res, 4000));
        return r;
    };
})();"""


def test_runtime_a_failed_lease_read_is_said_on_a_site_without_peers(open_fed):
    """A site that was removed or left keeps its own enrolled clusters: a failed read of
    their leases says so instead of dropping the card. Counterproof: a good read shows it."""
    ok = open_fed(fed={'enabled': True, 'members': [], 'enrolled': dict(_OWN), 'leases': dict(_HELD)})
    assert ok.open_tab()
    ok.page.locator('[data-fed-lease="pve1"]').wait_for(timeout=5000)
    app = open_fed(fed={'enabled': True, 'members': [], 'enrolled': dict(_OWN), 'leases': dict(_HELD),
                        'replies': {('GET', '/api/federation/leases'): _LEASES_FAIL}})
    assert app.open_tab()
    app.page.locator('[data-fed-leases-error]').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_an_older_lease_answer_does_not_undo_a_newer_failed_read(open_fed):
    """The first read of the leases is still on its way when a join starts a second one,
    which fails: the old answer that lands afterwards brings back neither its lease row nor
    an empty error."""
    app = open_fed(fed={'enabled': True, 'members': [], 'enrolled': dict(_OWN), 'leases': dict(_HELD)},
                   script=_FIRST_LEASES_LATE)
    page = app.page
    assert app.open_tab()
    for _ in range(40):
        if app.fed_calls('leases') >= 1:
            break
        page.wait_for_timeout(100)
    assert app.fed_calls('leases') == 1
    fed = app.server.fed
    fed['replies'][('GET', '/api/federation/leases')] = _LEASES_FAIL
    fed['replies'][('POST', '/api/federation/join')] = (200, {'joined': True})
    fed['members'] = [_member(2, 'hamburg')]
    page.locator('#fed-join-code').fill('pgxfd1_x')
    page.locator('#fed-join-url').fill('https://b.example:5000')
    page.locator('#fed-join-pw').fill(PASSWORD)
    page.locator('[data-fed-join]').click()
    page.locator('[data-fed-self]').wait_for(timeout=3000)
    page.wait_for_timeout(5000)
    assert page.locator('[data-fed-leases-error]').count() == 1
    assert page.locator('[data-fed-lease="pve1"]').count() == 0
    assert not app.errors, app.errors


def test_runtime_off_shows_the_switch_alone_and_switching_on_asks_first(open_fed):
    app = open_fed()
    page = app.page
    assert app.open_tab()
    assert page.locator('[data-fed-panel="off"]').count() == 1
    assert page.locator('[data-fed-switch="off"]').count() == 1
    assert 'Federation (experimental)' in page.locator('[data-fed-switch]').inner_text()
    # the risk of two sites is read before the switch, not only once paired
    assert 'both sites write to the cluster until they reach each other again' in \
        page.locator('[data-fed-switch]').inner_text()
    assert page.locator('[data-fed-pairing]').count() == 0
    # off, nothing but the status was asked
    assert app.fed_calls('leases') == 0 and app.fed_calls('clusters') == 0
    assert _switch(page).get_attribute('aria-checked') == 'false'

    _switch(page).click()
    confirm = page.locator('[data-fed-switch-confirm]')
    confirm.wait_for(timeout=3000)
    assert app.server.bodies.get('/api/federation/switch') is None, 'switched before the confirm'
    page.locator('[data-fed-switch-go]').click()
    page.locator('[data-fed-panel="empty"]').wait_for(timeout=5000)
    assert app.server.bodies['/api/federation/switch'] == [{'enabled': True}]
    assert _switch(page).get_attribute('aria-checked') == 'true'
    # counterproof of the quiet off state: on, the reads behind the switch go out
    page.wait_for_timeout(600)
    assert app.fed_calls('leases') >= 1 and app.fed_calls('clusters') >= 1
    assert page.locator('[data-fed-pairing="issue"]').count() == 1
    assert any(t['text'] == 'Federation switched on.' and t['kind'] == 'success' for t in app.toasts())
    assert not app.errors, app.errors


def test_runtime_switching_off_goes_at_once(open_fed):
    app = open_fed(fed={'enabled': True})
    page = app.page
    assert app.open_tab()
    assert page.locator('[data-fed-panel="empty"]').count() == 1
    _switch(page).click()
    page.locator('[data-fed-panel="off"]').wait_for(timeout=5000)
    assert app.server.bodies['/api/federation/switch'] == [{'enabled': False}]
    assert page.locator('[data-fed-switch-confirm]').count() == 0
    # the spy looks every 50 ms: the toast may come a moment after the panel changed
    page.wait_for_function("() => (window.__toasts || []).some(t => t.text === 'Federation switched off.')",
                           timeout=3000)


def test_runtime_a_refused_switch_off_shows_the_servers_reason(open_fed):
    # the status said it could go off, the server knows better by now
    app = open_fed(fed={'enabled': True, 'refuse_off': True})
    page = app.page
    assert app.open_tab()
    _switch(page).click()
    err = page.locator('[data-fed-switch-error]')
    err.wait_for(timeout=5000)
    assert err.inner_text().startswith('Leave the federation first')
    assert page.locator('[data-fed-panel="empty"]').count() == 1
    assert any(t['text'].startswith('Leave the federation first') and t['kind'] == 'error' for t in app.toasts())


def test_runtime_a_blocked_switch_says_why_and_stays_on(open_fed):
    app = open_fed(fed={'enabled': True, 'blockers': ['member', 'mirrors'], 'members': [_member(2, 'hamburg')]})
    page = app.page
    assert app.open_tab()
    assert _switch(page).is_disabled()
    text = page.locator('[data-fed-switch-blocked]').inner_text()
    assert text == ('Leave the federation first: this instance is a member, '
                    'it holds accounts or clusters of other sites.'), text


@pytest.mark.parametrize('value', [True, False])
def test_runtime_a_forced_switch_cannot_be_flipped(open_fed, value):
    app = open_fed(fed={'enabled': value, 'forced': True})
    page = app.page
    assert app.open_tab()
    assert _switch(page).is_disabled()
    assert _switch(page).get_attribute('aria-checked') == ('true' if value else 'false')
    text = page.locator('[data-fed-switch-forced]').inner_text()
    assert f'PEGAPROX_FEDERATION={"1" if value else "0"}' in text
    _switch(page).click(force=True)
    page.wait_for_timeout(300)
    assert page.locator('[data-fed-switch-confirm]').count() == 0
    assert '/api/federation/switch' not in app.server.bodies


def test_runtime_a_viewer_sees_no_tab_and_asks_nothing(open_fed):
    app = open_fed(admin=False)
    page = app.page
    page.wait_for_timeout(800)
    try:
        app.open_settings()
        page.wait_for_timeout(800)
    except Exception:
        pass   # a viewer may not open the settings at all: then there is no tab either
    assert page.locator('button', has_text='Federation').count() == 0
    # the sidebar asks for the clusters of the other sites, which every account may see;
    # nothing of the tab is read
    assert not [c for c in app.server.calls if c[1].startswith('/api/federation/')
                and c[1] != '/api/federation/linked']


def test_runtime_an_admin_without_manage_sees_no_tab(open_fed):
    app = open_fed(fed={'manage': False})
    app.open_settings()
    app.page.wait_for_timeout(1000)
    assert app.page.locator('button', has_text='Federation').count() == 0
    # counterproof: it asked, and the answer kept the tab away
    assert app.fed_calls('status') == 1


def test_runtime_a_joined_instance_adds_a_site_until_the_federation_is_full(open_fed):
    app = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg')], 'url': 'https://berlin.example:5000',
                        'site': 'berlin'})
    page = app.page
    assert app.open_tab()
    card = page.locator('[data-fed-pairing="issue"]')
    assert card.locator('h4').inner_text() == 'Add a site'
    assert page.locator('#fed-own-url').input_value() == 'https://berlin.example:5000'
    assert page.locator('#fed-own-site').input_value() == 'berlin'
    assert page.locator('[data-fed-max-sites]').inner_text() == 'up to 8 sites'
    assert page.locator('[data-fed-full]').count() == 0

    full = open_fed(fed={'enabled': True, 'members': [_member(n, f'site{n}') for n in range(2, 9)]})
    assert full.open_tab()
    assert full.page.locator('[data-fed-pairing="issue"]').count() == 0
    assert 'The federation has 8 sites' in full.page.locator('[data-fed-full]').inner_text()


def test_runtime_toasts_say_success_only_on_success(open_fed):
    members = [_member(2, 'hamburg', mirrored_clusters=2), _member(3, 'munich')]
    app = open_fed(fed={
        'enabled': True, 'members': members,
        'enrolled': {'pve1': {'name': 'prod', 'owner': ME}},
        'leases': {'pve1': {'held': True, 'remaining_s': 22, 'votes': 3, 'needed': 2, 'released': False,
                            'adopted': False, 'lost_to': ''}},
        'replies': {
            ('POST', '/api/federation/clusters/pve1/renew'): (200, {'cluster': 'pve1', 'renewed': False, 'votes': 1,
                                                                      'needed': 2, 'lost_to': ''}),
            ('POST', f'/api/federation/members/{"2" * 32}/remove'): (200, {
                'removed': '2' * 32, 'not_told': ['3' * 32], 'remedy': {'enrolled_here': ['pve1'], 'note': 'key'}}),
        }})
    page = app.page
    assert app.open_tab()
    assert '3 of 2 votes, 22 s left' in page.locator('[data-fed-lease="pve1"]').inner_text()

    page.locator('[data-fed-renew="pve1"]').click()
    page.wait_for_timeout(600)
    toasts = app.toasts()
    assert any(t['kind'] == 'error' and '(1 of 2 votes)' in t['text'] for t in toasts), toasts
    assert not any(t['text'] == 'Lease renewed.' for t in toasts)

    page.locator(f'[data-fed-remove="{"2" * 8}"]').click()
    box = page.locator('[data-fed-confirm="remove"]')
    box.wait_for(timeout=3000)
    assert '2 clusters of this site are mirrored here' in box.inner_text()
    page.locator('#fed-confirm-word').fill('REMOVE')
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    page.locator('[data-fed-confirm-go]').click()
    page.locator('[data-fed-rotate="remove"]').wait_for(timeout=5000)
    # the spy looks every 50 ms: the toast may come a moment after the panel changed
    page.wait_for_function("() => (window.__toasts || []).some(t => t.text.startsWith('Removed here.'))", timeout=3000)
    toasts = app.toasts()
    assert any(t['kind'] == 'other' and t['text'].startswith('Removed here. 1 sites did not confirm') for t in toasts), toasts
    assert not any(t['text'] == 'Member removed.' for t in toasts)
    assert 'pve1' in page.locator('[data-fed-rotate="remove"]').inner_text()
    assert app.server.bodies[f'/api/federation/members/{"2" * 32}/remove'][-1] == {
        'confirm': 'REMOVE', 'user_password': PASSWORD}


def test_runtime_a_blocked_leave_offers_force(open_fed):
    app = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg')], 'replies': {
        ('POST', '/api/federation/leave'): (409, {'code': 'FED_LEAVE_BLOCKED', 'clusters': ['pve1'],
                                                  'error': 'These clusters are enrolled without a live lease here'})}})
    page = app.page
    assert app.open_tab()
    page.locator('[data-fed-leave]').click()
    page.locator('#fed-confirm-word').fill('LEAVE')
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    assert page.locator('[data-fed-force]').count() == 0
    page.locator('[data-fed-confirm-go]').click()
    page.locator('[data-fed-force="leave"]').wait_for(timeout=5000)
    assert app.server.bodies['/api/federation/leave'][-1]['force'] is False


def test_runtime_every_local_cluster_can_be_enrolled_and_filtered(open_fed):
    clusters = [{'id': f'pve{n:02d}', 'name': f'cluster {n}', 'cluster_type': 'proxmox'} for n in range(1, 16)]
    clusters.append({'id': 'xcp1', 'name': 'xcp', 'cluster_type': 'xcpng'})
    app = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg'), _member(3, 'munich')]},
                   clusters=clusters)
    page = app.page
    assert app.open_tab()
    page.locator('[data-fed-enrollable]').first.wait_for(timeout=5000)
    assert page.locator('[data-fed-enrollable]').count() == 15
    assert page.locator('[data-fed-enrollable="xcp1"]').count() == 0
    assert page.locator('[data-fed-enroll="pve15"]').is_enabled()
    page.locator('[data-fed-filter]').fill('pve1')
    assert page.locator('[data-fed-enrollable]').count() == 6   # pve10 to pve15


def test_runtime_two_sites_enroll(open_fed):
    """Counterproof: FED_MIN_SITES_TO_ENROLL back at 3 disables the button and says three."""
    app = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg')]},
                   clusters=[{'id': 'pve1', 'name': 'one', 'cluster_type': 'proxmox'}])
    assert app.open_tab()
    app.page.locator('[data-fed-enrollable="pve1"]').wait_for(timeout=5000)
    assert app.page.locator('[data-fed-enroll="pve1"]').is_enabled()
    assert app.page.locator('[data-fed-enroll-sites]').count() == 0
    text = app.page.locator('[data-fed-panel]').inner_text()
    assert 'three or more sites:' not in text and 'Enrolling takes' not in text


def test_runtime_peer_rows_show_nodes_guests_and_what_is_left_out(open_fed):
    pid = '2' * 32
    view = {'self': [{'id': 'pve1', 'name': 'prod', 'type': 'proxmox', 'enabled': True, 'enrolled': True,
                      'connected': True, 'nodes': 3, 'vms': 40}],
            'peers': {pid: {'site': 'hamburg', 'total': 150, 'clusters': [
                # a site names the id of an enrolled cluster only
                {**({'id': f'hh{n}'} if n == 0 else {}), 'name': f'hh {n}', 'type': 'proxmox',
                 'enabled': True, 'enrolled': n == 0, 'connected': n != 1,
                 'nodes': 4 if n != 1 else 0, **({'vms': 77} if n != 1 else {})}
                for n in range(100)]}}}
    app = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg')], 'view': view})
    page = app.page
    assert app.open_tab()
    row = page.locator('[data-fed-peer-cluster="hh0"]')
    row.wait_for(timeout=5000)
    cells = row.locator('td').all_inner_texts()
    assert cells[2] == '4' and cells[3] == '77' and 'led at hamburg' in cells[4], cells
    second = page.locator('[data-fed-peer-cluster]').nth(1)
    assert second.locator('td').all_inner_texts()[2] == 'Disconnected'
    assert second.locator('code').count() == 0 and 'hh 1' in second.inner_text()
    assert page.locator('[data-fed-peer-cluster]').count() == 100
    assert page.locator(f'[data-fed-peer-more="{pid[:8]}"]').inner_text() == '50 more clusters of hamburg are not listed.'


def test_runtime_a_mirrored_admin_and_an_sso_account(open_fed):
    app = open_fed(fed={'enabled': True, 'local': False, 'reauth': 'recent_session',
                        'members': [_member(2, 'hamburg')]})
    page = app.page
    assert app.open_tab()
    assert page.locator('[data-fed-local-only]').count() == 1
    assert _switch(page).is_disabled()
    assert page.locator('[data-fed-leave]').is_disabled()
    assert page.locator('[data-fed-make-code]').is_disabled()
    assert page.locator('#fed-code-pw').count() == 0
    # counterproof: a local account with a password gets the field and the buttons
    local = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg')]})
    assert local.open_tab()
    assert local.page.locator('#fed-code-pw').count() == 1
    assert local.page.locator('[data-fed-leave]').is_enabled()


@pytest.mark.parametrize('lang', ['de', 'zh'])
def test_runtime_no_raw_key_in_other_languages(open_fed, lang):
    for fed in ({}, {'enabled': True, 'members': [_member(2, 'hamburg')], 'blockers': ['member'],
                     'enrolled': {'pve1': {'name': 'prod', 'owner': ME}},
                     'leases': {'pve1': {'held': False, 'remaining_s': 0, 'votes': 0, 'needed': 2,
                                         'released': True, 'adopted': False, 'lost_to': ''}}}):
        app = open_fed(fed=fed, language=lang)
        assert app.open_tab(lang), lang
        text = app.page.locator('[data-fed-panel]').inner_text()
        raw = sorted(set(re.findall(r'\bfed[A-Z]\w+', text)))
        assert not raw, (lang, raw)
        assert 'Federation (experimental)' not in text, lang
        assert not app.errors, app.errors


# -- the guide: docs/federation.md -----------------------------------------------------------

@pytest.fixture(scope='module')
def guide():
    return _read('docs', 'federation.md')


def test_the_guide_ships_and_is_linked(guide):
    manifest = json.loads(_read('version.json'))['update_files']
    assert 'docs/federation.md' in manifest
    assert '(docs/federation.md)' in _read('README.md')
    anchors = {re.sub(r'[^a-z0-9 -]', '', h.lower()).replace(' ', '-')
               for h in re.findall(r'^#+ (.+)$', guide, re.M)}
    targets = re.findall(r'\]\(#([^)]+)\)', guide)
    assert len(targets) >= 10
    for target in targets:
        assert target in anchors, target


def test_the_guide_keeps_the_house_rules(guide):
    readme_line = next(line for line in _read('README.md').splitlines() if 'docs/federation.md' in line)
    for text in (guide, readme_line):
        assert chr(0x2014) not in text and chr(0x2013) not in text
        # the hypervisor is ESXi, never its vendor or its managers
        assert not re.search('vm' + 'ware|v' + 'center|v' + 'sphere', text, re.I)
    # with two sites nothing fences the owner: the takeover is the admin's risk, said where
    # the feature is first named
    intro = guide[:guide.index('## Switch it on')]
    for text in (intro, readme_line):
        assert 'until they reach each other again' in text
    assert 'with two by a takeover an admin confirms' not in readme_line


def test_the_numbers_of_the_guide_are_the_codes():
    """Each number the guide states, next to the constant it comes from."""
    from pegaprox.core import federation, federation_lease, ha_wire
    guide = _read('docs', 'federation.md')
    assert federation.MAX_SITES == 8 and 'up to eight PegaProx instances' in guide and '**Eight sites**' in guide
    assert federation_lease.MIN_SITES_TO_ENROLL == 2 and '**Two sites**' in guide
    assert federation.PAIRING_TTL == 15 * 60 and 'valid for 15\n   minutes and one join' in guide
    assert federation.SYNC_INTERVAL == 60 and 'the identity sync, every 60\nseconds' in guide
    assert federation.LEASE_RENEW_AFTER == 10 and federation_lease.LEASE_SECONDS == 30
    assert 'holds a lease of 30 seconds on the cluster, renewed every 10 seconds' in guide
    assert federation_lease.LEASE_SECONDS + federation_lease.LEASE_SKEW == 35 and 'for 35 seconds' in guide
    assert ha_wire.SIGNATURE_WINDOW == 120 and 'valid for\ntwo minutes' in guide
    assert federation.MAX_VIEW_ROWS == 100 and '**100 clusters per site**' in guide
    assert federation.SWITCH_CACHE_SECONDS == 5 and 'a cache of five seconds' in guide
    assert federation.SETTING_KEY == 'federation_enabled' and '`federation_enabled`' in guide
    assert federation.ENV_SWITCH == 'PEGAPROX_FEDERATION'


def test_the_guide_says_what_pairing_never_shares(guide):
    never = guide[guide.index('It never shares:'):guide.index('The trust this takes')]
    assert '**its database master key**' in never
    assert 'TOTP secrets' in never
    # and what a departed site keeps, with the remedy
    behind = guide[guide.index('**What stays behind.**'):guide.index('## HA groups')]
    assert 'change the credentials of those clusters' in behind


def test_the_guide_says_what_mirrors_and_a_forced_off_site_cannot_do(guide):
    """The rules the identity side and the switch enforce, each next to the code it comes
    from: directory accounts sign in at home, the home codes, the last-admin count, what
    PEGAPROX_FEDERATION=0 closes, the settle span and the records of dropped rows."""
    from pegaprox.core import federation, federation_lease
    auth_src = _read('pegaprox', 'api', 'auth.py')
    for code in ('FED_PASSWORD_HOME', 'FED_2FA_HOME'):
        assert f"'{code}'" in auth_src and f'`{code}`' in guide, code
    assert "code='FED_ENROLLED'" in _read('pegaprox', 'core', 'federation.py')
    assert '`FED_ENROLLED`' in guide
    accounts = guide[guide.index('## Accounts of other sites'):guide.index('## Enrolled clusters')]
    assert 'LDAP or OIDC' in accounts and 'signs in at its home only' in accounts
    assert "Only this instance's own admins count" in accounts
    assert 'mirror_switched_off' in _read('pegaprox', 'utils', 'auth.py')
    off = guide[guide.index('## Switch it off'):guide.index('## API')]
    assert 'not read at all' in off and 'mirrored accounts count as disabled' in off
    assert federation_lease.SETTLE_SECONDS == 35
    assert 'has not changed in the last 35 seconds' in guide
    assert federation.MAX_DROPPED == 512 and '(up to 512)' in guide


def _idmap():
    return {'members': {'2' * 32: {'site': 'hamburg', 'entries': [
                {'kind': 'tenant', 'home_value': 'acme', 'local_value': '', 'users': 3},
                {'kind': 'role', 'home_value': 'support', 'local_value': 'viewer', 'users': 2,
                 'mapped_by': 'root', 'mapped_at': 1763200000}]}},
            'local': {'tenants': [{'id': 'default', 'name': 'Default'}, {'id': 'customer-a', 'name': 'Customer A'}],
                      'roles': ['admin', 'user', 'viewer', 'helpdesk']}}


def test_runtime_unmapped_accounts_wait_for_a_mapping(open_fed):
    app = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg', unmapped=3)], 'idmap': _idmap(),
                        'pull_ok': False})
    page = app.page
    assert app.open_tab()
    page.locator('[data-fed-map]').wait_for(timeout=5000)
    assert page.locator('[data-fed-waiting="22222222"]').inner_text() == '3 waiting'
    row = page.locator('[data-fed-map-row="tenant:acme"]')
    assert 'not mapped - no access' in row.inner_text()
    go = page.locator('[data-fed-map-go="tenant:acme"]')
    assert go.is_disabled(), 'mapping before a choice'
    row.locator('select').select_option('customer-a')
    go.click()
    box = page.locator('[data-fed-confirm="map"]')
    box.wait_for(timeout=3000)
    assert 'Give accounts of hamburg access here?' in box.inner_text()
    assert '"acme"' in box.inner_text() and '"customer-a"' in box.inner_text()
    assert page.locator('#fed-confirm-word').count() == 0, 'a mapping asks for no typed word'
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    page.locator('[data-fed-confirm-go]').click()
    page.locator('[data-fed-unmap="tenant:acme"]').wait_for(timeout=5000)
    assert app.server.bodies['/api/federation/identity-map'][-1] == {
        'home': '2' * 32, 'kind': 'tenant', 'home_value': 'acme', 'local_value': 'customer-a', 'user_password': PASSWORD}
    toasts = app.toasts()
    assert any(t['kind'] == 'other' and t['text'].startswith('Mapping saved. hamburg did not answer') for t in toasts), toasts

    # taking a mapping away goes at once, without the password
    page.locator('[data-fed-unmap="role:support"]').click()
    page.locator('[data-fed-map-go="role:support"]').wait_for(timeout=5000)
    assert app.server.bodies['/api/federation/identity-map'][-1] == {
        'home': '2' * 32, 'kind': 'role', 'home_value': 'support', 'local_value': ''}
    assert any(t['kind'] == 'success' and t['text'].startswith('Mapping removed') for t in app.toasts())


def test_runtime_a_mirrored_user_is_marked_in_the_users_list(open_fed):
    users = [{'username': 'bob', 'role': 'viewer', 'enabled': True, 'auth_source': 'local', 'tenant_id': 'default',
              'fed_home': '2' * 32, 'fed_site': 'hamburg'},
             {'username': 'alice', 'role': 'user', 'enabled': True, 'auth_source': 'local', 'tenant_id': 'default',
              'fed_home': '', 'fed_site': ''}]
    app = open_fed(extra={('GET', '/api/users'): (200, users)})
    page = app.page
    app.open_settings()
    badge = page.locator('[data-fed-mirror="bob"]')
    badge.wait_for(timeout=6000)
    assert badge.inner_text() == 'Mirrored' and badge.get_attribute('title') == 'Homed at hamburg - change it there'
    assert page.locator('[data-fed-mirror-actions="bob"]').inner_text() == 'Homed at hamburg - change it there'
    # counterproof: the local user keeps its badge-free row and its buttons
    assert page.locator('[data-fed-mirror="alice"]').count() == 0
    assert page.locator('[data-fed-mirror-actions="alice"]').count() == 0


def test_runtime_a_failed_leases_read_is_said_and_offers_nothing_to_enroll(open_fed):
    """The leases route fails: the card says so instead of 'no clusters enrolled', and no
    cluster is offered for enrolling while it is unknown which ones are. The linked view
    that fails says so instead of working for good. Counterproof: the reads come back and
    the cards fill again."""
    failing = {('GET', '/api/federation/leases'): (500, {'error': 'The lease file cannot be read'}),
               ('GET', '/api/federation/clusters'): (500, {'error': 'The members cannot be asked'})}
    clusters = [{'id': 'pve1', 'name': 'one', 'cluster_type': 'proxmox'}]
    app = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg'), _member(3, 'munich')],
                        'replies': dict(failing)}, clusters=clusters)
    page = app.page
    assert app.open_tab()
    err = page.locator('[data-fed-leases-error]')
    err.wait_for(timeout=5000)
    assert err.inner_text() == 'The lease file cannot be read'
    assert page.locator('[data-fed-own-leases]').inner_text().count('No clusters') == 0
    assert page.locator('[data-fed-enrollable]').count() == 0
    assert page.locator('[data-fed-clusters-error]').inner_text() == 'The members cannot be asked'
    # the next poll (20 s) reads both again
    app.server.fed['replies'] = {}
    page.locator('[data-fed-enrollable="pve1"]').wait_for(timeout=45000)
    assert page.locator('[data-fed-leases-error]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_filter_stays_while_it_filters(open_fed):
    """13 clusters, a filter typed, one of them enrolled: 12 are left and the field with
    its text stays, so the list can be cleared again."""
    clusters = [{'id': f'pve{n:02d}', 'name': f'cluster {n}', 'cluster_type': 'proxmox'} for n in range(1, 14)]
    app = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg'), _member(3, 'munich')]},
                   clusters=clusters)
    page = app.page
    assert app.open_tab()
    page.locator('[data-fed-filter]').wait_for(timeout=5000)
    page.locator('[data-fed-filter]').fill('pve13')
    assert page.locator('[data-fed-enrollable]').count() == 1
    # enrolled meanwhile: the next poll (20 s) of the leases takes it out of the list
    app.server.fed['enrolled'] = {'pve13': {'owner': ME, 'name': 'cluster 13'}}
    page.locator('[data-fed-lease="pve13"]').wait_for(timeout=45000)
    assert page.locator('[data-fed-enrollable]').count() == 0
    assert page.locator('[data-fed-filter]').count() == 1
    page.locator('[data-fed-filter]').fill('')
    assert page.locator('[data-fed-enrollable]').count() == 12


# -- runtime: two sites ----------------------------------------------------------------------

HH = '2' * 32
HEARD = 1763290000
ALIVE = ('hamburg answers right now, so it is not down. Hand the cluster over there (Hand over), then '
         'take it over here with Take over')


def _lease(**kw):
    rec = {'held': True, 'remaining_s': 25, 'votes': 1, 'needed': 2, 'released': False, 'adopted': False,
           'lost_to': '', 'alone': True, 'gen': 1, 'takeover': None}
    rec.update(kw)
    return rec


def _two_sites(**kw):
    """A federation of two: this instance leads pve1 and holds it alone, hamburg has not
    answered for a while and leads hh1 and hh2, of which this instance holds copies."""
    fed = {'enabled': True,
           'members': [_member(2, 'hamburg', reachable=False, last_heard=HEARD, takeover_in_s=0,
                               mirrored_clusters=2)],
           'enrolled': {'pve1': {'name': 'prod', 'owner': ME}, 'hh1': {'name': 'hh one', 'owner': HH},
                        'hh2': {'name': 'hh two', 'owner': HH}},
           'leases': {'pve1': _lease()}}
    fed.update(kw)
    return fed


def test_runtime_two_sites_the_owner_alone_and_a_takeover_by_hand(open_fed):
    """Corporate Redesigned, two sites, hamburg silent: the card says what two sites do and
    what a takeover risks, the lease reads held alone, a cluster taken over here says
    whether hamburg stepped down, the member says since when it is offline and offers Take
    over all, and hamburg's clusters offer Manual takeover in place of adopt. The box keeps
    Go off until tick, word and password; an owner that answers after all keeps it open
    with the server's sentence. Counterproof: Go without !ownerDown goes out unticked."""
    pending = {'from': HH, 'at': HEARD - 600, 'by': 'admin:admin', 'confirmed_at': 0}
    done = dict(pending, confirmed_at=HEARD - 300)
    fed = _two_sites()
    fed['enrolled'].update({'hh0': {'name': 'taken', 'owner': ME}, 'hh8': {'name': 'back', 'owner': ME}})
    fed['leases'].update({'hh0': _lease(gen=3, takeover=pending), 'hh8': _lease(gen=2, takeover=done)})
    app = open_fed(fed=fed, layout='corporate-redesigned')
    page = app.page
    assert app.open_tab()
    card = page.locator('[data-fed-two-sites]')
    card.wait_for(timeout=5000)
    assert 'Two sites: takeover by hand' in card.inner_text()
    assert 'both sites write to the same cluster until they reach each other again' in card.inner_text()
    page.locator('[data-fed-lease-alone="pve1"]').wait_for(timeout=5000)
    assert page.locator('[data-fed-lease-alone="pve1"]').inner_text() == 'held alone, hamburg does not answer, 25 s left'
    assert page.locator('[data-fed-lease="hh0"] [data-fed-takeover-state="pending"]').inner_text().endswith(
        'hamburg has not stepped down yet')
    assert 'hamburg stopped writing by' in page.locator('[data-fed-lease="hh8"] [data-fed-takeover-state="done"]').inner_text()
    assert page.locator('[data-fed-offline-since="22222222"]').inner_text().startswith('offline since ')
    assert page.locator('[data-fed-takeover-all="22222222"]').inner_text() == 'Take over all by hand (2)'
    assert page.locator('[data-fed-adopt="hh1"]').count() == 0
    assert page.locator('[data-fed-shadows-two]').count() == 1

    route = ('POST', '/api/federation/clusters/hh1/takeover')
    app.server.fed['replies'][route] = (409, {'code': 'FED_OWNER_ALIVE', 'owner': HH, 'error': ALIVE})
    page.locator('[data-fed-takeover="hh1"]').click()
    box = page.locator('[data-fed-confirm="takeover"]')
    box.wait_for(timeout=3000)
    assert 'Take over hh one by hand from hamburg?' in box.inner_text()
    assert 'If it still runs, both sites write to the cluster until they reach each other again' in box.inner_text()
    assert 'What it did on the cluster meanwhile stays in effect and is not undone' in box.inner_text()
    assert page.locator('[data-fed-last-heard]').inner_text().startswith('Last heard from hamburg: ')
    go = page.locator('[data-fed-confirm-go]')
    assert go.inner_text() == 'Take over by hand'
    page.locator('#fed-confirm-word').fill('TAKEOVER')
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    assert go.is_disabled(), 'Go before the owner-down tick'
    page.locator('[data-fed-owner-down]').check()
    assert go.is_enabled()
    page.locator('#fed-confirm-word').fill('TAKEOVE')
    assert go.is_disabled()
    page.locator('#fed-confirm-word').fill('TAKEOVER')
    go.click()
    err = page.locator('[data-fed-confirm-error]')
    err.wait_for(timeout=5000)
    assert err.inner_text() == ALIVE and box.count() == 1
    assert app.server.bodies['/api/federation/clusters/hh1/takeover'][-1] == {
        'confirm': 'TAKEOVER', 'owner_down': True, 'force': False, 'user_password': PASSWORD}

    # silent again: the password was for that one request, the tick and the word stay
    app.server.fed['replies'][route] = (200, {'taken_over': 'hh1', 'generation': 4, 'manager': True,
                                              'lease': _lease(gen=4)})
    assert go.is_disabled()
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    go.click()
    box.wait_for(state='detached', timeout=5000)
    page.wait_for_function("() => (window.__toasts || []).some(t => t.text === "
                           "'Taken over. hamburg stops writing as soon as it answers again.' && t.kind === 'success')",
                           timeout=3000)
    assert not app.errors, app.errors


def test_runtime_a_takeover_that_gets_no_answer_keeps_its_box(open_fed):
    """The takeover request gets no answer at all, the network fails: the box stays open
    with the fallback sentence, and the page throws nothing. Counterproof: a result without
    data threw on reading retry_after and left no sentence in the box."""
    route = ('POST', '/api/federation/clusters/hh1/takeover')
    app = open_fed(fed=_two_sites(replies={route: (None, None)}))
    page = app.page
    assert app.open_tab()
    page.locator('[data-fed-takeover="hh1"]').wait_for(timeout=5000)
    page.locator('[data-fed-takeover="hh1"]').click()
    box = page.locator('[data-fed-confirm="takeover"]')
    box.wait_for(timeout=3000)
    page.locator('[data-fed-owner-down]').check()
    page.locator('#fed-confirm-word').fill('TAKEOVER')
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    page.locator('[data-fed-confirm-go]').click()
    err = page.locator('[data-fed-confirm-error]')
    err.wait_for(timeout=5000)
    assert err.inner_text() == 'The action failed.' and box.count() == 1
    assert ('POST', route[1]) in app.server.calls
    assert not app.errors, app.errors


def test_runtime_adopt_hands_over_to_the_takeover_and_the_wait_holds_go(open_fed):
    """hamburg looked reachable, so its cluster offers Take over (adopt); the server finds
    it silent and answers FED_USE_TAKEOVER, and the takeover box opens in its place. hamburg
    was heard three seconds ago: Go stays off with everything filled in until the wait ran
    out. Counterproof: Go without the waitLeft check is on at once."""
    member = _member(2, 'hamburg', reachable=True, last_heard=HEARD, takeover_in_s=3, mirrored_clusters=2)
    use = {'code': 'FED_USE_TAKEOVER', 'owner': HH,
           'error': 'hamburg does not answer. With two sites a cluster whose owner does not answer is taken over by '
                    'hand: use Manual takeover'}
    app = open_fed(fed=_two_sites(members=[member], replies={('POST', '/api/federation/clusters/hh1/adopt'): (409, use)}))
    page = app.page
    assert app.open_tab()
    page.locator('[data-fed-adopt="hh1"]').wait_for(timeout=5000)
    assert page.locator('[data-fed-takeover="hh1"]').count() == 0 and page.locator('[data-fed-takeover-all]').count() == 0
    page.locator('[data-fed-adopt="hh1"]').click()
    page.locator('[data-fed-confirm="adopt"]').wait_for(timeout=3000)
    page.locator('#fed-confirm-word').fill('ADOPT')
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    page.locator('[data-fed-confirm-go]').click()
    page.locator('[data-fed-confirm="takeover"]').wait_for(timeout=5000)
    wait = page.locator('[data-fed-takeover-wait]')
    assert re.fullmatch(r'hamburg was in contact a moment ago\. Manual takeover is possible in [123] s\.', wait.inner_text())
    page.locator('#fed-confirm-word').fill('TAKEOVER')
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    page.locator('[data-fed-owner-down]').check()
    go = page.locator('[data-fed-confirm-go]')
    assert go.is_disabled(), 'Go during the wait'
    wait.wait_for(state='detached', timeout=6000)
    assert go.is_enabled()
    assert '/api/federation/clusters/hh1/takeover' not in app.server.bodies
    assert not app.errors, app.errors


def test_runtime_take_over_all_then_remove_the_site_as_gone_for_good(open_fed):
    """Take over all posts once for the site and reports what did not move; Remove offers
    gone for good, names the clusters not taken over and drops them only with their own
    tick. Counterproof: a remove that ignores the gone tick posts a plain removal."""
    fed = _two_sites()
    fed['enrolled']['hh3'] = {'name': 'hh three', 'owner': HH}
    app = open_fed(fed=fed)
    page = app.page
    assert app.open_tab()
    all_route = ('POST', f'/api/federation/members/{HH}/takeover')
    app.server.fed['replies'][all_route] = (200, {
        'taken': [{'cluster_id': 'hh1', 'generation': 2, 'manager': True}],
        'failed': {'hh2': {'code': 'FED_NO_KEY', 'error': 'The field key of the owner is not held here'}}})
    page.locator('[data-fed-takeover-all="22222222"]').click()
    box = page.locator('[data-fed-confirm="takeoverAll"]')
    box.wait_for(timeout=3000)
    assert 'Take over every cluster of hamburg by hand?' in box.inner_text()
    page.locator('#fed-confirm-word').fill('TAKEOVER')
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    page.locator('[data-fed-owner-down]').check()
    page.locator('[data-fed-confirm-go]').click()
    box.wait_for(state='detached', timeout=5000)
    assert app.server.bodies[all_route[1]][-1] == {'confirm': 'TAKEOVER', 'owner_down': True, 'force': False,
                                                   'user_password': PASSWORD}
    page.wait_for_function("() => (window.__toasts || []).some(t => t.text === "
                           "'1 taken over, 1 not: hh2: The field key of the owner is not held here')", timeout=3000)

    remove = f'/api/federation/members/{HH}/remove'
    app.server.fed['replies'][('POST', remove)] = (409, {
        'code': 'FED_GONE_CLUSTERS', 'clusters': ['hh3'],
        'error': 'hamburg still leads clusters here that were not taken over: hh3'})
    page.locator('[data-fed-remove="22222222"]').click()
    page.locator('[data-fed-confirm="remove"]').wait_for(timeout=3000)
    page.locator('[data-fed-remove-gone]').check()
    page.locator('#fed-confirm-word').fill('REMOVE')
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    page.locator('[data-fed-confirm-go]').click()
    drop = page.locator('[data-fed-remove-gone-drop]')
    drop.wait_for(timeout=5000)
    assert 'were not taken over and are dropped here: hh three.' in drop.inner_text()
    assert app.server.bodies[remove][-1] == {'confirm': 'REMOVE', 'gone': True, 'user_password': PASSWORD}
    app.server.fed['replies'][('POST', remove)] = (200, {'removed': HH, 'gone': True, 'kept': ['pve1'],
                                                         'dropped': ['hh3'], 'site': 'hamburg'})
    page.locator('[data-fed-remove-drop]').check()
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    page.locator('[data-fed-confirm-go]').click()
    page.locator('[data-fed-confirm="remove"]').wait_for(state='detached', timeout=5000)
    assert app.server.bodies[remove][-1] == {'confirm': 'REMOVE', 'gone': True, 'drop_clusters': True,
                                             'user_password': PASSWORD}
    page.wait_for_function("() => (window.__toasts || []).some(t => t.text === "
                           "'Removed. This site carries on alone.' && t.kind === 'success')", timeout=3000)
    assert page.locator('[data-fed-rotate]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_leave_the_other_site_cannot_confirm_points_at_gone_for_good(open_fed):
    no_quorum = {'code': 'FED_NO_QUORUM', 'votes': 1, 'needed': 2,
                 'error': 'A change of the federation needs a majority of its members'}
    app = open_fed(fed=_two_sites(replies={('POST', '/api/federation/leave'): (409, no_quorum)}))
    page = app.page
    assert app.open_tab()
    page.locator('[data-fed-leave]').click()
    page.locator('#fed-confirm-word').fill('LEAVE')
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    page.locator('[data-fed-confirm-go]').click()
    hint = page.locator('[data-fed-leave-two-down]')
    hint.wait_for(timeout=5000)
    assert 'remove hamburg as gone for good instead' in hint.inner_text()
    assert page.locator('[data-fed-force="leave"]').count() == 1
    assert app.server.bodies['/api/federation/leave'][-1]['force'] is False


def test_runtime_three_sites_show_none_of_it(open_fed):
    """A silent member of three is adopted by majority as before: no card, no takeover by
    hand, no gone for good, the lease reads its votes. Counterproof: twoSites on
    members.length >= 1 shows all of it here."""
    members = [_member(2, 'hamburg', reachable=False, last_heard=HEARD, takeover_in_s=0, mirrored_clusters=2),
               _member(3, 'munich')]
    no_quorum = {'code': 'FED_NO_QUORUM', 'votes': 1, 'needed': 2,
                 'error': 'A change of the federation needs a majority of its members'}
    app = open_fed(fed=_two_sites(members=members, leases={'pve1': _lease(votes=2, alone=False)},
                                  replies={('POST', '/api/federation/leave'): (409, no_quorum)}))
    page = app.page
    assert app.open_tab()
    page.locator('[data-fed-shadow="hh1"]').wait_for(timeout=5000)
    assert page.locator('[data-fed-two-sites]').count() == 0
    assert page.locator('[data-fed-takeover], [data-fed-takeover-all], [data-fed-shadows-two], '
                        '[data-fed-lease-alone]').count() == 0
    assert page.locator('[data-fed-adopt="hh1"]').count() == 1
    assert '2 of 2 votes, 25 s left' in page.locator('[data-fed-lease="pve1"]').inner_text()
    assert page.locator('[data-fed-offline-since="22222222"]').count() == 1
    page.locator('[data-fed-remove="22222222"]').click()
    page.locator('[data-fed-confirm="remove"]').wait_for(timeout=3000)
    assert page.locator('[data-fed-remove-gone]').count() == 0
    page.locator('[data-fed-confirm="remove"] button', has_text='Cancel').click()
    page.locator('[data-fed-leave]').click()
    page.locator('#fed-confirm-word').fill('LEAVE')
    page.locator('#fed-confirm-pw').fill(PASSWORD)
    page.locator('[data-fed-confirm-go]').click()
    page.wait_for_function("() => (window.__toasts || []).some(t => t.text.startsWith('A change of the federation'))",
                           timeout=3000)
    assert page.locator('[data-fed-leave-two-down], [data-fed-force="leave"]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_old_owner_sees_the_takeover_and_the_end(open_fed):
    """The site that was taken over shows, on the cluster it now follows, when that
    happened and when it stopped; a plain hand-over gets no such note. A site the other
    one removed as gone for good says so instead of "removed". Counterproof: without the
    kind check hh2 gets the note."""
    stepped = {'hh1': {'owner': HH, 'kind': 'takeover', 'at': HEARD - 3600, 'by': 'admin:root',
                       'stopped_at': HEARD - 60},
               'hh2': {'owner': HH, 'kind': 'adopt', 'at': HEARD - 3600, 'by': 'admin:root',
                       'stopped_at': HEARD - 3500}}
    app = open_fed(fed=_two_sites(members=[_member(2, 'hamburg')], stepped_down=stepped))
    page = app.page
    assert app.open_tab()
    note = page.locator('[data-fed-stepped-down="hh1"]')
    note.wait_for(timeout=5000)
    assert note.inner_text().startswith('Taken over by hand at hamburg on ')
    assert "follows hamburg now. Check the cluster's task log" in note.inner_text()
    assert page.locator('[data-fed-stepped-down="hh2"]').count() == 0
    assert page.locator('[data-fed-adopt="hh1"]').count() == 1

    ended = open_fed(fed={'enabled': True, 'removed': {'by': HH, 'at': HEARD, 'ended': True, 'site': 'hamburg',
                                                       'clusters': ['hh1', 'pve1']}})
    assert ended.open_tab()
    banner = ended.page.locator('[data-fed-ended-by-other]')
    assert banner.inner_text().startswith('hamburg carried on alone and keeps these clusters: hh1, pve1.')
    assert ended.page.locator('[data-fed-was-removed]').count() == 0
    assert not app.errors and not ended.errors, app.errors + ended.errors


def test_runtime_the_survivor_asks_once_more_before_it_switches_off(open_fed):
    """Counterproof: a switch that flips off at once posts before the second ask."""
    app = open_fed(fed={'enabled': True, 'warnings': ['ended_untold']})
    page = app.page
    assert app.open_tab()
    assert 'has not confirmed that it was told this site carried on alone' in page.locator('[data-fed-switch-untold="note"]').inner_text()
    _switch(page).click()
    page.locator('[data-fed-switch-untold="ask"]').wait_for(timeout=3000)
    page.wait_for_timeout(300)
    assert '/api/federation/switch' not in app.server.bodies, 'switched off before the second ask'
    page.locator('[data-fed-switch-off-anyway]').click()
    page.locator('[data-fed-panel="off"]').wait_for(timeout=5000)
    assert app.server.bodies['/api/federation/switch'] == [{'enabled': False, 'untold_ok': True}]


@pytest.mark.parametrize('lang,word', [('de', 'Manuelle Übernahme'), ('zh', '手动接管')])
def test_runtime_two_sites_speak_the_language(open_fed, lang, word):
    """Counterproof: a key missing in the language shows the English text."""
    app = open_fed(fed=_two_sites(), language=lang)
    assert app.open_tab(lang), lang
    page = app.page
    page.locator('[data-fed-two-sites]').wait_for(timeout=5000)
    page.locator('[data-fed-takeover="hh1"]').click()
    page.locator('[data-fed-confirm="takeover"]').wait_for(timeout=3000)
    text = page.locator('[data-fed-panel]').inner_text()
    assert not sorted(set(re.findall(r'\bfed[A-Z]\w+', text))), lang
    assert word in text
    for english in ('Two sites: takeover by hand', 'does not answer', 'Take over by hand', 'offline since'):
        assert english not in text, (lang, english)
    assert not app.errors, app.errors


def test_runtime_a_mirrored_admin_cannot_take_over(open_fed):
    """The server refuses a mirrored admin with FED_MIRROR_ADMIN; the buttons say so first.
    Counterproof: a takeover button without !localOk is on for a mirrored admin."""
    app = open_fed(fed=_two_sites(local=False))
    page = app.page
    assert app.open_tab()
    page.locator('[data-fed-takeover="hh1"]').wait_for(timeout=5000)
    assert page.locator('[data-fed-takeover="hh1"]').is_disabled()
    assert page.locator('[data-fed-takeover-all="22222222"]').is_disabled()
    assert page.locator('[data-fed-remove="22222222"]').is_disabled()



# --- the disaster recovery has a switch of its own --------------------------------------------

def test_runtime_with_disaster_recovery_off_the_tab_offers_none_of_it(open_fed):
    """Off, the enrollment, the leases and the takeover are not offered; the card switches
    it on, and then they are."""
    app = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg'), _member(3, 'berlin')],
                        'dr': False})
    assert app.open_tab()
    page = app.page
    card = page.locator('[data-fed-dr="off"]')
    card.wait_for(timeout=5000)
    assert page.locator('[data-fed-unenrolled], [data-fed-own-leases], [data-fed-shadows]').count() == 0
    assert not page.locator('[data-fed-leases-error]').count()
    before = app.fed_calls('leases')
    page.locator('[data-fed-dr-flip]').click()
    page.locator('[data-fed-dr="on"]').wait_for(timeout=5000)
    assert app.server.bodies['/api/federation/dr'] == [{'enabled': True}]
    # switched on, the leases are read at once, and what they hold is shown again
    page.wait_for_timeout(800)
    assert app.fed_calls('leases') > before


def test_runtime_disaster_recovery_that_holds_clusters_does_not_switch_off(open_fed):
    app = open_fed(fed={'enabled': True, 'members': [_member(2, 'hamburg'), _member(3, 'berlin')],
                        'dr_blockers': ['enrolled']})
    assert app.open_tab()
    page = app.page
    page.locator('[data-fed-dr="on"]').wait_for(timeout=5000)
    assert page.locator('[data-fed-dr-flip]').is_disabled()
    assert page.locator('[data-fed-dr-blocked]').count() == 1
