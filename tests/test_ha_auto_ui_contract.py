"""The stage 2 cards of the HA tab against the real routes (#625).

test_ha_auto_ui.py drives the UI against a fake server and pins the bodies it sends. Here the
same bodies go to pegaprox/api/ha.py in the group harness of the lease tests, and the status the
cards render is read from the real public_status, so the UI and the routes cannot drift apart:
every key a card reads is there, every body passes the checks of its route, and this release
answers the switch and the witness code with the code the UI turns into its note.
LW
"""
from pegaprox.core import ha_vote as hv
from _ha_lease_harness import auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW
from test_ha_members import IDS, URLS, group  # noqa: F401  (the fixture)
from test_ha_ui import _read
from test_ha_witness_group import WURL, host  # noqa: F401  (the fixture)


# what the cards send, as test_ha_auto_ui.py pins it (there with the fake's password)
def ON(pw, accept=()):
    return {'mode': 'auto', 'lease_s': 20, 'accept': list(accept), 'user_password': pw}


def LEASE(pw, lease):
    return {'mode': 'auto', 'lease_s': lease, 'user_password': pw}


def OFF(pw):
    return {'mode': 'manual', 'user_password': pw}


def WITNESS_CODE(pw, url, site):
    return {'url': url, 'site': site, 'user_password': pw}


def WITNESS_REMOVE(pw):
    return {'confirm': 'REMOVE', 'user_password': pw}


def READMIT(pw):
    return {'user_password': pw}


def ZONE(name):
    return {'timezone': name}


# what the cards read
AUTO_KEYS = {'mode', 'lease_s', 'voters', 'majority', 'holds_lease', 'holder', 'lease_left', 'acting_in', 'epoch',
             'switch_waiting', 'pending', 'findings', 'members', 'witness'}
ROW_KEYS = {'instance_id', 'kind', 'voter', 'may_lead', 'site', 'quarantined', 'skew', 'reach', 'seen_ago', 'zone',
            'mode', 'holds'}
WITNESS_KEYS = {'instance_id', 'url', 'site', 'key_fingerprint', 'last_heard', 'skew', 'write_failed'}


def _status(auto, n='a'):
    with auto.g.at(n):
        r = auto.admin.get('/api/ha/status')
    assert r.status_code == 200, r.data
    return r.get_json()


def test_the_ui_tests_pin_these_bodies():
    """The runtime tests assert the bodies with the fake's password: the same shapes as here."""
    ui = _read('tests', 'test_ha_auto_ui.py')
    for literal in ("{'mode': 'auto', 'lease_s': 20, 'accept': [], 'user_password': PASSWORD}",
                    "{'mode': 'auto', 'lease_s': 30, 'user_password': PASSWORD}",
                    "{'mode': 'manual', 'user_password': PASSWORD}",
                    "{'url': SELF, 'site': 'dc3', 'user_password': PASSWORD}",
                    "{'confirm': 'REMOVE', 'user_password': PASSWORD}",
                    "{'user_password': PASSWORD}",
                    "{'timezone': 'Asia/Tokyo'}"):
        assert literal in ui, literal


def test_this_release_answers_with_the_code_the_ui_turns_into_its_note(auto, seed, monkeypatch):
    auto.pair(seed)
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    r = auto.put('a', '/api/ha/mode', ON(ADMIN_PW))
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED'
    r = auto.post('a', '/api/ha/witness/pairing-code', WITNESS_CODE(ADMIN_PW, URLS['a'], 'dc3'))
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED'
    status = _status(auto)
    # auto is there and null: the cards render, with nothing of the voter config
    assert 'auto' in status and status['auto'] is None
    for key in ('timezone', 'timezone_local', 'timezone_unreadable', 'suggested_url'):
        assert isinstance(status[key], str), key


def test_the_status_carries_every_key_the_cards_read(auto, seed):
    auto.form(seed)
    for n in 'ab':
        status = _status(auto, n)
        got = status['auto']
        assert AUTO_KEYS <= set(got), (n, sorted(AUTO_KEYS - set(got)))
        assert got['mode'] == 'auto' and isinstance(got['voters'], int) and isinstance(got['majority'], int)
        for row in got['members']:
            assert ROW_KEYS <= set(row), sorted(ROW_KEYS - set(row))
        for f in got['findings']:
            assert {'code', 'level', 'text', 'member'} <= set(f)
    leader = _status(auto, 'a')['auto']
    assert leader['holds_lease'] is True and leader['holder'] == IDS['a']
    assert isinstance(leader['lease_left'], (int, float)) and leader['lease_s'] == 20


def test_the_switch_bodies_pass_their_route(auto, seed):
    auto.pair(seed)
    # on, then taken back while pending
    r = auto.put('a', '/api/ha/mode', ON(ADMIN_PW))
    assert r.status_code == 200, r.data
    assert r.get_json()['mode'] == 'auto_pending' and sorted(r.get_json()['waiting']) == [IDS['b'], IDS['c']]
    pending = _status(auto)['auto']
    assert pending['mode'] == 'auto_pending' and pending['pending']['own'] is True
    r = auto.put('a', '/api/ha/mode', OFF(ADMIN_PW))
    assert r.status_code == 200 and r.get_json()['result'] == 'cancelled', r.data


def test_the_lease_and_off_bodies_pass_their_route(auto, seed):
    auto.form(seed)
    r = auto.put('a', '/api/ha/mode', LEASE(ADMIN_PW, 30))
    assert r.status_code == 200 and r.get_json()['changed'] is True, r.data
    r = auto.put('a', '/api/ha/mode', OFF(ADMIN_PW))
    assert r.status_code == 200 and r.get_json()['result'] == 'off', r.data


def test_an_even_group_names_the_code_the_ui_ticks(auto, seed):
    auto.pair(seed, 'bcd')
    r = auto.put('a', '/api/ha/mode', ON(ADMIN_PW))
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_CONFIRM'
    codes = {f['code']: f['level'] for f in r.get_json()['findings']}
    assert codes.get('EVEN_VOTERS') == 'warn'
    r = auto.put('a', '/api/ha/mode', ON(ADMIN_PW, accept=['EVEN_VOTERS']))
    assert r.status_code == 200, r.data


def test_the_readmit_body_passes_the_password_check(auto, seed):
    auto.form(seed)
    r = auto.post('a', f"/api/ha/members/{IDS['b']}/readmit", READMIT(ADMIN_PW))
    assert r.status_code == 409 and r.get_json()['error'] == 'That member is not quarantined', r.data
    # the counterproof: without the field the same request stops at the password
    r = auto.post('a', f"/api/ha/members/{IDS['b']}/readmit", {})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'


def test_the_zone_body_passes_its_route(auto, seed):
    auto.pair(seed)
    r = auto.put('a', '/api/ha/timezone', ZONE('Asia/Tokyo'))
    assert r.status_code == 200 and r.get_json()['timezone'] == 'Asia/Tokyo', r.data
    assert _status(auto)['timezone'] == 'Asia/Tokyo'
    r = auto.put('a', '/api/ha/timezone', ZONE('Mars/Olympus'))
    assert r.status_code == 400
    assert r.get_json()['error'] == 'That is not a time zone this instance knows - use a name like Europe/Vienna'


def test_the_witness_bodies_pass_their_routes(auto, host, seed):
    auto.pair(seed, 'b')
    r = auto.post('a', '/api/ha/witness/pairing-code', WITNESS_CODE(ADMIN_PW, URLS['a'], 'dc3'))
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert set(body) >= {'code', 'expires_at', 'commands'} and set(body['commands']) == {'package', 'docker'}
    # quoted: a placeholder left in reaches the witness, which says what to put there (#625)
    assert body['commands']['package'].startswith(f"pegaprox-witness join '{body['code']}' --url 'https://")
    assert host.w.join(body['code'], WURL) == IDS['a']
    host.w.start()
    witness = _status(auto)['auto']
    assert WITNESS_KEYS <= set(witness['witness']), sorted(WITNESS_KEYS - set(witness['witness']))
    assert witness['witness']['site'] == 'dc3' and witness['witness']['url'] == WURL
    assert [r['kind'] for r in witness['members'] if r['instance_id'] == witness['witness']['instance_id']] == ['witness']
    r = auto.post('a', '/api/ha/witness/remove', WITNESS_REMOVE(ADMIN_PW))
    assert r.status_code == 200 and isinstance(r.get_json()['told'], bool), r.data
    assert _status(auto)['auto']['witness'] is None
