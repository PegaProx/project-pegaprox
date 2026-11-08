"""The witness card of the HA tab with what "Add witness" answers now (#625 stage 2).

The answer carries one line per way to install the witness (install: linux, offline,
docker, manual), each shown in a code block with a copy button, the note on the
<witness-host> placeholder under the lines that carry it, and the firewall text; where
this instance ships no installer, linux and offline are null and the card says so. An
older server sends only commands, which the card still shows. A witness that runs older
code shows it, with its last update and the command that updates it by hand.

The runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_auto_ui.py, with the answer the real route builds (witness_install_commands).
They skip where Playwright is not installed.
LW
"""
import re

import pytest

from test_ha_auto_ui import (  # noqa: F401  (browser is a fixture)
    EM_DASH, LANGS, PASSWORD, SELF, WITNESS_CODE, _GroupServer, _auto, _finding, _open_ha, _value, _witness,
    browser)
from test_ha_ui import _App, _blocks, _read

PLACEHOLDER_NOTE = 'Replace <witness-host> with the name or address the members reach the witness at.'
FIREWALL = 'Open TCP port 5005 on the witness host for the members of the group, and nothing else.'
NO_INSTALLER = ('This instance ships no witness installer, so there is no Linux line. Use Docker or the line by '
                'hand, or update this instance and create a new code.')


def _install(installer=True, monkeypatch=None, branch='Testing'):
    """What the route answers in install, built by the route's own function, on an
    instance that follows `branch` (on main this release has no Docker line)."""
    import pegaprox.api.ha as ha_api
    if not installer:
        monkeypatch.setattr(ha_api, 'witness_installer', lambda: None)
    return ha_api.witness_install_commands(SELF, WITNESS_CODE, branch=branch)


class _InstallServer(_GroupServer):
    """The fake of the stage 2 cards, with install in the answer of "Add witness"."""

    def __init__(self, install=None, **kw):
        super().__init__(**kw)
        self.install = install

    def group_route(self, method, path, body):
        out = super().group_route(method, path, body)
        if out and out[0] == 200 and path == '/api/ha/witness/pairing-code' and self.install is not None:
            out[1]['install'] = self.install
        return out


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _InstallServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _create(app, lang_create='Create witness code'):
    page = app.page
    panel = _open_ha(app, 'active')
    card = panel.locator('[data-ha-witness]')
    page.fill('#pgha-witness-password', PASSWORD)
    card.get_by_role('button', name=lang_create).click()
    box = card.locator('[data-ha-witness-code]')
    box.wait_for(timeout=3000)
    return card, box


def test_runtime_every_way_in_a_block_of_its_own(open_app):
    install = _install()
    assert install['linux'] and install['offline'] and install['docker'] and install['manual']
    app = open_app(auto=_auto(), shipped=True, install=install)
    card, box = _create(app)
    ways = box.locator('[data-ha-witness-install]')
    assert ways.locator('p').first.inner_text().strip() == (
        'Run one of these on the witness host. The first one fits most hosts:')
    labels = {'linux': 'Linux with systemd (recommended)',
              'offline': 'Linux without internet - the installer comes from this instance',
              'docker': 'Docker, on any host that runs it',
              'manual': 'By hand, in a checkout of this release - you keep the process running'}
    order = box.locator('[data-ha-witness-way]').evaluate_all('r => r.map(x => x.dataset.haWitnessWay)')
    assert order == ['linux', 'offline', 'docker', 'manual']
    for kind, label in labels.items():
        block = box.locator(f'[data-ha-witness-way="{kind}"]')
        assert block.locator(f'[data-ha-witness-command="{kind}"] code').inner_text() == install[kind]
        assert block.locator('div.text-xs').first.inner_text().strip() == label
        assert block.locator('button[title="Copy"]').count() == 1
        note = block.locator('[data-ha-witness-placeholder]')
        if kind in install['placeholder_in']:
            assert note.inner_text().strip() == PLACEHOLDER_NOTE, kind
        else:
            assert note.count() == 0, kind
    assert box.locator('[data-ha-witness-firewall]').inner_text().strip() == FIREWALL
    assert box.locator('[data-ha-witness-no-installer]').count() == 0
    # the code and the four lines, each copied with one click; nothing of the older answer
    assert box.locator('button[title="Copy"]').count() == 5
    assert box.locator('[data-ha-witness-command="package"]').count() == 0
    assert '<witness host>' not in box.inner_text()
    assert not app.errors, app.errors


def test_runtime_without_an_installer_docker_and_by_hand_remain(open_app, monkeypatch):
    install = _install(installer=False, monkeypatch=monkeypatch)
    assert install['linux'] is None and install['offline'] is None
    app = open_app(auto=_auto(), shipped=True, install=install)
    card, box = _create(app)
    assert box.locator('[data-ha-witness-no-installer]').inner_text().strip() == NO_INSTALLER
    assert box.locator('[data-ha-witness-way]').evaluate_all('r => r.map(x => x.dataset.haWitnessWay)') == [
        'docker', 'manual']
    assert box.locator('[data-ha-witness-command="docker"] code').inner_text() == install['docker']
    assert box.locator('[data-ha-witness-placeholder]').count() == 2
    assert box.locator('button[title="Copy"]').count() == 3
    assert box.locator('[data-ha-witness-firewall]').count() == 1
    assert not app.errors, app.errors


def test_runtime_an_older_server_still_gets_its_two_commands(open_app):
    app = open_app(auto=_auto(), shipped=True, install=None)
    card, box = _create(app)
    assert box.locator('[data-ha-witness-install]').count() == 0
    assert box.locator('[data-ha-witness-command="package"] code').inner_text().startswith(
        f'pegaprox-witness join {WITNESS_CODE}')
    assert box.locator('[data-ha-witness-command="docker"]').count() == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('case', ['failed', 'fetch', 'updating', 'off', 'member'])
def test_runtime_a_witness_behind_shows_its_update_and_the_command(open_app, case):
    command = 'sudo pegaprox-witness update'
    update = {'failed': {'state': 'failed', 'release': '9.0.0', 'at': 'x', 'back': True,
                         'error': 'release 9.0.0 (9.0.0-abcdefabcdef) did not come up healthy in 2 starts'},
              'fetch': {'state': 'failed', 'release': '1.2.0', 'at': 'x', 'back': False,
                        'error': 'Cannot reach https://active.example:5000: ReadTimeoutError: timed out'},
              'updating': {'state': 'installed', 'release': '1.2.0', 'error': None, 'at': 'x'},
              'off': None, 'member': None}[case]
    view = _witness(release='1.1.0', wire=2, auto_update=case != 'off', install='systemd', update=update,
                    outdated=True, update_command=command)
    findings = [] if case == 'member' else [dict(_finding('WITNESS_OUTDATED', 'warn', 'The witness runs release '
                                                          '1.1.0 (wire 2), this instance 1.2.0 (wire 2).', view['instance_id']),
                                                 command=command)]
    kw = dict(auto=_auto(findings=findings, witness=view), shipped=True)
    if case == 'member':
        from test_ha_ui import _member
        kw.update(role='standby', members=[_member('b', role='active', source=True)])
    app = open_app(**kw)
    panel = _open_ha(app, 'standby' if case == 'member' else 'active')
    card = panel.locator('[data-ha-witness="paired"]')
    assert card.locator('[data-ha-witness-release]').inner_text().strip() == '1.1.0'
    box = card.locator('[data-ha-witness-outdated]')
    text = box.inner_text()
    assert text.startswith('The witness runs an older release (1.1.0) than this instance.')
    assert ('It updates itself from the leader.' in text) == (case in ('updating', 'member'))
    # by hand only where it does not update itself, or went back from that code; a fetch that
    # failed is tried again with the leader's next word
    assert ('it does not take that code again by itself' in text) == (case == 'failed')
    assert ('it tries again when the leader says so again' in text) == (case == 'fetch')
    by_hand = case in ('failed', 'off')
    assert ('Update it by hand on the witness host:' in text) == by_hand
    assert box.locator('[data-ha-witness-command="update"]').count() == (1 if by_hand else 0)
    if by_hand:
        assert box.locator('[data-ha-witness-command="update"] code').inner_text() == command
    shown = card.locator('[data-ha-witness-update]')
    if case == 'fetch':
        assert shown.inner_text().strip() == f"failed: {update['error']}"
    elif case == 'failed':
        assert shown.get_attribute('data-ha-witness-update') == 'failed'
        assert shown.inner_text().strip() == f"failed: {update['error']}"
        assert 'text-red-300' in shown.get_attribute('class')
    elif case == 'updating':
        assert shown.inner_text().strip() == 'installed, starting into it'
    else:
        assert shown.count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('lang', ['en', 'de'])
def test_runtime_a_witness_ahead_names_the_way_down(open_app, lang):
    command = 'sudo pegaprox-witness update --to-leader'
    view = _witness(release='9.0.0', wire=2, auto_update=True, install='systemd', outdated=False, ahead=True,
                    update_command=None, to_leader_command=command,
                    update={'state': 'current', 'release': '9.0.0', 'error': None, 'at': 'x', 'back': False})
    findings = [dict(_finding('WITNESS_AHEAD', 'warn', 'The witness runs release 9.0.0 (wire 2), newer than this '
                              "instance's 1.2.0 (wire 2).", view['instance_id']), command=command)]
    app = open_app(language=lang, auto=_auto(findings=findings, witness=view), shipped=True)
    blocks = _blocks()
    page = app.page
    if lang == 'en':
        card = _open_ha(app, 'active').locator('[data-ha-witness="paired"]')
    else:
        page.locator('body').click(position={'x': 5, 'y': 400})
        page.keyboard.press('g')
        page.keyboard.press(',')
        page.locator('button', has_text=_value(blocks[lang], 'pgHaTab')).first.click()
        card = page.locator('[data-ha-role="active"] [data-ha-witness="paired"]')
        card.wait_for(timeout=5000)
    box = card.locator('[data-ha-witness-ahead]')
    assert box.inner_text().startswith(_value(blocks[lang], 'haWitnessAhead').replace('{release}', '9.0.0'))
    assert _value(blocks[lang], 'haWitnessToLeader') in box.inner_text()
    assert box.locator('[data-ha-witness-command="to-leader"] code').inner_text() == command
    assert card.locator('[data-ha-witness-outdated]').count() == 0
    assert not app.errors, app.errors


def test_runtime_without_a_docker_image_the_card_says_why(open_app, monkeypatch):
    """A release whose image has no witness (1.2.0 and older), on an instance that does not
    follow Testing: no Docker line, and the card says why where it would be."""
    import pegaprox.constants as constants
    monkeypatch.setattr(constants, 'PEGAPROX_VERSION', '1.2.0')
    install = _install(branch='main')
    assert install['docker'] is None and install['docker_note']
    app = open_app(auto=_auto(), shipped=True, install=install)
    card, box = _create(app)
    assert box.locator('[data-ha-witness-way]').evaluate_all('r => r.map(x => x.dataset.haWitnessWay)') == [
        'linux', 'offline', 'manual']
    note = box.locator('[data-ha-witness-no-docker]')
    assert note.inner_text().strip() == ('The Docker image of release 1.2.0 has no witness yet, so there is no '
                                         'Docker line: use the Linux line, or the line by hand.')
    # it stands where the Docker line would, the placeholder note only under the manual one
    order = box.locator('[data-ha-witness-way], [data-ha-witness-no-docker]').evaluate_all(
        'r => r.map(x => x.dataset.haWitnessWay || "note")')
    assert order == ['linux', 'offline', 'note', 'manual']
    assert box.locator('[data-ha-witness-placeholder]').count() == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('lang', LANGS)
def test_runtime_the_note_without_a_docker_image_speaks_every_language(open_app, monkeypatch, lang):
    import pegaprox.constants as constants
    monkeypatch.setattr(constants, 'PEGAPROX_VERSION', '1.2.0')
    blocks = _blocks()
    app = open_app(language=lang, auto=_auto(), shipped=True, install=_install(branch='main'))
    page = app.page
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press(',')
    page.locator('button', has_text=_value(blocks[lang], 'pgHaTab')).first.click()
    panel = page.locator('[data-ha-role="active"]')
    panel.wait_for(timeout=5000)
    card = panel.locator('[data-ha-witness]')
    page.fill('#pgha-witness-password', PASSWORD)
    card.locator('button', has_text=_value(blocks[lang], 'haWitnessCreate')).click()
    note = card.locator('[data-ha-witness-no-docker]')
    note.wait_for(timeout=3000)
    want = _value(blocks[lang], 'haWitnessNoDockerImage').replace('{version}', '1.2.0').replace("\\'", "'")
    assert note.inner_text().strip() == want
    assert not app.errors, app.errors


def test_runtime_an_update_that_runs_is_up_to_date_not_installed(open_app):
    """'installed' is for the way into an update: a witness that runs the release it
    installed (and never said more, as one of the release before does) is up to date."""
    view = _witness(release='1.2.0', wire=2, install='systemd', auto_update=True, outdated=False,
                    update={'state': 'installed', 'release': '1.2.0', 'error': None,
                            'at': '2026-09-20T08:00:00+00:00', 'back': False})
    app = open_app(auto=_auto(witness=view), shipped=True)
    card = _open_ha(app, 'active').locator('[data-ha-witness="paired"]')
    shown = card.locator('[data-ha-witness-update]')
    assert shown.inner_text().strip() == 'up to date' and shown.get_attribute('data-ha-witness-update') == 'current'
    assert 'installed, starting into it' not in card.inner_text()
    assert not app.errors, app.errors


def test_runtime_a_witness_up_to_date_shows_no_box(open_app):
    view = _witness(release='1.2.0', wire=2, auto_update=True, install='systemd',
                    update={'state': 'current', 'release': '1.2.0', 'error': None, 'at': 'x'}, outdated=False,
                    update_command=None)
    app = open_app(auto=_auto(witness=view), shipped=True)
    card = _open_ha(app, 'active').locator('[data-ha-witness="paired"]')
    assert card.locator('[data-ha-witness-outdated]').count() == 0
    assert card.locator('[data-ha-witness-ahead]').count() == 0
    assert card.locator('[data-ha-witness-update]').inner_text().strip() == 'up to date'
    assert not app.errors, app.errors


@pytest.mark.parametrize('lang', LANGS)
def test_runtime_the_ways_speak_every_language(open_app, lang):
    blocks = _blocks()
    install = _install()
    app = open_app(language=lang, auto=_auto(), shipped=True, install=install)
    page = app.page
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press(',')
    page.locator('button', has_text=_value(blocks[lang], 'pgHaTab')).first.click()
    panel = page.locator('[data-ha-role="active"]')
    panel.wait_for(timeout=5000)
    card = panel.locator('[data-ha-witness]')
    page.fill('#pgha-witness-password', PASSWORD)
    card.locator('button', has_text=_value(blocks[lang], 'haWitnessCreate')).click()
    box = card.locator('[data-ha-witness-install]')
    box.wait_for(timeout=3000)
    text = box.inner_text()
    assert not re.search(r'\b(haWitness|haAuto|pgHa)\w*', text), text
    for key in ('haWitnessRunOneWay', 'haWitnessWayLinux', 'haWitnessWayDocker'):
        assert _value(blocks[lang], key) in text, key
    assert _value(blocks[lang], 'haWitnessFirewall').replace('{port}', '5005') in text
    assert _value(blocks[lang], 'haWitnessPlaceholder').replace('{placeholder}', '<witness-host>') in text
    assert not app.errors, app.errors


# -- source -------------------------------------------------------------------------------------------------

NEW_KEYS = ('haWitnessRunOneWay', 'haWitnessWayLinux', 'haWitnessWayOffline', 'haWitnessWayDocker',
            'haWitnessWayManual', 'haWitnessPlaceholder', 'haWitnessFirewall', 'haWitnessNoInstaller',
            'haWitnessRelease', 'haWitnessLastUpdate', 'haWitnessUpdateFailed', 'haWitnessUpdateInstalled',
            'haWitnessUpdateCurrent', 'haWitnessOutdated', 'haWitnessUpdatesItself', 'haWitnessUpdateByHand',
            'haWitnessUpdateRetries', 'haWitnessUpdateWentBack', 'haWitnessAhead', 'haWitnessToLeader',
            'haWitnessNoDockerImage')


def test_the_new_keys_once_per_language_and_used():
    src = _read('web', 'src', 'settings_modal.js')
    blocks = _blocks()
    for key in NEW_KEYS:
        assert f"t('{key}')" in src, key
        for lang in LANGS:
            assert len(re.findall(r'^ +%s: ' % key, blocks[lang], re.M)) == 1, (lang, key)
            assert EM_DASH not in _value(blocks[lang], key)
    # each anchor the translations were placed at is there once per language
    for lang in LANGS:
        assert len(re.findall(r'^ +haWitnessRemovedNotReached: ', blocks[lang], re.M)) == 1, lang


def test_the_card_reads_install_and_keeps_commands_for_an_older_server():
    src = _read('web', 'src', 'settings_modal.js')
    card = src[src.index('function HaWitnessCard('):src.index('function HaZoneCard(')]
    assert "install: res.data.install && typeof res.data.install === 'object' ? res.data.install : null," in card
    assert "commands: res.data.commands && typeof res.data.commands === 'object' ? res.data.commands : {} });" in card
    for kind in ('linux', 'offline', 'docker', 'manual'):
        assert f"way('{kind}', t(" in card, kind
    assert "{command('package', t('haWitnessPackage'), commands.package)}" in card
    assert "auto.findings.find(f => f && f.code === 'WITNESS_OUTDATED')" in card
    assert "auto.findings.find(f => f && f.code === 'WITNESS_AHEAD')" in card
    assert EM_DASH not in card and card.count('LW Oct 2026 (#625)') <= 1
    bundle = _read('web', 'index.html')
    for key in NEW_KEYS + ('data-ha-witness-install', 'data-ha-witness-outdated', 'data-ha-witness-ahead'):
        assert key in bundle, key
