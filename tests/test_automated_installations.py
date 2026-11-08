"""Automated installations - PegaProx as the answer-file server for the Proxmox
auto-installer.

An operator stores an answer file, PegaProx hands out a fetch token once, the
prepared ISO POSTs to /api/auto-install/answer with it and gets the file back. The
served file carries a webhook with a callback token of its own, and what the
machine reports there closes its run.

Everything drives the real Flask app. The installer half goes through a RAW test
client: the harness client adds the same-origin and XHR headers a real installer
cannot send, and with those on this would pass even if the CSRF gate turned every
installer away. The payloads are the ones documented on the Proxmox wiki
(Automated_Installation), trimmed.
"""
import copy
import json
import re
import tomllib
from urllib.parse import urlsplit

import pytest

from pegaprox.utils.sha512_crypt import sha512_crypt


ANSWER = """\
[global]
keyboard = "de"
country = "de"
fqdn = "pve01.lab.example.com"
mailto = "root@example.com"
timezone = "Europe/Berlin"
root-password = "hunter2-in-the-rack"

[network]
source = "from-dhcp"

[disk-setup]
filesystem = "ext4"
disk-list = ["sda"]
"""

# what the installer POSTs to the fetch URL (wiki, schema 1.0)
FETCH_BODY = {
    '$schema': {'version': '1.0'},
    'product': {'fullname': 'Proxmox VE', 'product': 'pve', 'enable_btrfs': True},
    'iso': {'release': '9.0', 'isorelease': '1'},
    'dmi': {
        'system': {'serial': 'JH7K2X3', 'name': 'PowerEdge R660', 'sku': 'SKU',
                   'uuid': '6fb36fd4-77a1-57e6-13ae-000000cb48d7'},
        'baseboard': {'name': 'Z13PP-D32 Series', 'serial': '23041870000'},
        'chassis': {'asset_tag': 'To be filled by O.E.M.', 'serial': 'I02308'},
    },
    'network_interfaces': [{'link': 'enp6s18', 'mac': 'aa:bb:cc:dd:ee:01'},
                           {'link': 'enp6s19', 'mac': 'aa:bb:cc:dd:ee:02'}],
}

# what the installer POSTs to the webhook after a successful install (wiki, schema 1.2)
WEBHOOK_BODY = {
    '$schema': {'version': '1.2'},
    'debian-version': '13.1',
    'product': {'fullname': 'Proxmox VE', 'short': 'pve', 'version': '9.0.3'},
    'iso': {'release': '9.0', 'isorelease': '1'},
    'dmi': {'system': {'serial': 'JH7K2X3', 'uuid': '6fb36fd4-77a1-57e6-13ae-000000cb48d7',
                       'name': 'PowerEdge R660'}},
    'filesystem': 'ext4',
    'fqdn': 'pve01.lab.example.com',
    'machine-id': 'b8737afea804482697ffe04db69c73d1',
    'network-interfaces': [{'name': 'lan', 'mac': 'aa:bb:cc:dd:ee:01', 'is-management': True}],
    'ssh-public-host-keys': {'ed25519': 'ssh-ed25519 AAAA root@pve01.lab.example.com'},
}


def _admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _create(client, **over):
    payload = {'name': 'rack-7 node', 'description': 'lab', 'answer': ANSWER}
    payload.update(over)
    r = client.post('/api/auto-install/profiles', json=payload)
    assert r.status_code == 201, r.data
    return r.get_json()


def _raw(api):
    return api.app.test_client()


def _fetch(api, token, info=None, via='header', **kw):
    """The installer's fetch. via='header' is --answer-auth-token, 'query' the
    fallback for ISOs without it."""
    body = FETCH_BODY if info is None else info
    if via == 'header':
        headers = dict(kw.pop('headers', {}) or {})
        headers['Authorization'] = f'Bearer pegaprox:{token}'
        return _raw(api).post('/api/auto-install/answer', json=body,
                              base_url='http://localhost', headers=headers, **kw)
    return _raw(api).post(f'/api/auto-install/answer?token={token}', json=body,
                          base_url='http://localhost', **kw)


def _hook(served):
    return tomllib.loads(served)['post-installation-webhook']


def _report(api, served, body=None):
    """POST to the webhook URL written into a served file, as the installer does."""
    parts = urlsplit(_hook(served)['url'])
    return _raw(api).post(f'{parts.path}?{parts.query}', json=body if body is not None else WEBHOOK_BODY,
                          base_url='http://localhost')


def _runs(client):
    return client.get('/api/auto-install/runs').get_json()


def _profile_row(profile_id):
    from pegaprox.core.db import get_db
    return get_db().conn.cursor().execute(
        'SELECT * FROM auto_install_profiles WHERE id = ?', (profile_id,)).fetchone()


# --- the fetch token ----------------------------------------------------------

def test_the_token_is_handed_out_once_and_never_again(api, seed):
    c = _admin(api, seed)
    created = _create(c)
    token = created['token']
    assert token.startswith('pgxai_')

    again = c.get(f"/api/auto-install/profiles/{created['id']}").get_json()
    listed = c.get('/api/auto-install/profiles').get_json()
    for p in [again] + listed['profiles']:
        assert 'token' not in p
        assert 'token_hash' not in p, 'the hash is not the client\'s business either'
    assert listed['can_manage'] is True
    assert len(again.get('token_hint') or '') < len(token)


def test_the_token_is_not_stored_in_the_clear(api, seed):
    import hashlib
    created = _create(_admin(api, seed))
    row = _profile_row(created['id'])
    assert created['token'] not in row['token_hash']
    assert row['token_hash'] == hashlib.sha256(created['token'].encode()).hexdigest()


def test_rotating_the_token_stops_the_old_one(api, seed):
    c = _admin(api, seed)
    created = _create(c)
    old = created['token']
    assert _fetch(api, old).status_code == 200
    new = c.post(f"/api/auto-install/profiles/{created['id']}/token").get_json()['token']
    assert new != old
    assert _fetch(api, old).status_code == 403
    assert _fetch(api, new).status_code == 200


@pytest.mark.parametrize('via', ['header', 'query'])
def test_the_installer_gets_the_answer_file_without_a_session(api, seed, via):
    """No session, no Origin, no X-Requested-With - the way an ISO arrives, both
    with --answer-auth-token and with the token in the URL."""
    token = _create(_admin(api, seed))['token']
    r = _fetch(api, token, via=via)
    assert r.status_code == 200, r.data
    assert r.headers['Content-Type'] == 'text/plain; charset=utf-8', r.headers['Content-Type']
    body = r.data.decode()
    assert 'pve01.lab.example.com' in body
    assert body.count('[global]') == 1


def test_the_auth_token_name_part_is_ignored(api, seed):
    """--answer-auth-token is name:secret; the name is the operator's label."""
    token = _create(_admin(api, seed))['token']
    r = _raw(api).post('/api/auto-install/answer', json=FETCH_BODY, base_url='http://localhost',
                       headers={'Authorization': f'Bearer rack7-node-a:{token}'})
    assert r.status_code == 200, r.data


def test_a_bad_or_missing_token_is_refused_and_no_run_is_recorded(api, seed):
    c = _admin(api, seed)
    _create(c)
    assert _fetch(api, 'pgxai_not-a-real-token').status_code == 403
    r = _raw(api).post('/api/auto-install/answer', json=FETCH_BODY, base_url='http://localhost')
    assert r.status_code == 403
    assert b'pve01' not in r.data
    assert _runs(c) == []


@pytest.mark.parametrize('field,value', [
    ('enabled', False),
    ('expires_at', '2001-01-01T00:00:00Z'),
])
def test_a_profile_that_is_off_or_expired_serves_nothing(api, seed, field, value):
    c = _admin(api, seed)
    created = _create(c)
    assert c.put(f"/api/auto-install/profiles/{created['id']}", json={field: value}).status_code == 200
    assert _fetch(api, created['token']).status_code == 403


def test_the_use_limit_is_enforced(api, seed):
    token = _create(_admin(api, seed), max_uses=1)['token']
    assert _fetch(api, token).status_code == 200
    assert _fetch(api, token).status_code == 403


# --- the claim: decided after the body was read, not before --------------------

def _between_check_and_claim(monkeypatch, action):
    """Run `action` after the usability pre-check and the body read, right before
    the use is claimed - the window a slowly sent body holds open under gevent."""
    import pegaprox.api.auto_install as ai
    real = ai._summarise_system

    def hooked(info):
        action()
        return real(info)
    monkeypatch.setattr(ai, '_summarise_system', hooked)


def test_two_fetches_cannot_both_take_the_last_use(api, seed, monkeypatch):
    c = _admin(api, seed)
    created = _create(c, max_uses=1)
    from pegaprox.core.db import get_db

    def the_other_fetch_won():
        get_db().conn.execute('UPDATE auto_install_profiles SET uses = 1 WHERE id = ?', (created['id'],))
        get_db().conn.commit()
    _between_check_and_claim(monkeypatch, the_other_fetch_won)

    r = _fetch(api, created['token'])
    assert r.status_code == 403, r.data
    assert b'hunter2' not in r.data
    assert _profile_row(created['id'])['uses'] == 1
    assert _runs(c) == []


@pytest.mark.parametrize('revoke', [
    "UPDATE auto_install_profiles SET enabled = 0 WHERE id = ?",
    "UPDATE auto_install_profiles SET token_hash = 'rotated' WHERE id = ?",
    "UPDATE auto_install_profiles SET expires_at = '2001-01-01T00:00:00+00:00' WHERE id = ?",
])
def test_a_revoke_during_the_fetch_stops_it(api, seed, monkeypatch, revoke):
    c = _admin(api, seed)
    created = _create(c)
    from pegaprox.core.db import get_db

    def revoked():
        get_db().conn.execute(revoke, (created['id'],))
        get_db().conn.commit()
    _between_check_and_claim(monkeypatch, revoked)

    r = _fetch(api, created['token'])
    assert r.status_code == 403, r.data
    assert b'hunter2' not in r.data


# --- the served file --------------------------------------------------------------

def test_the_served_file_calls_back_with_a_run_token_not_the_fetch_token(api, seed):
    """The fetch token opens the answer file. Writing it into that file would put
    it on every installed host, where it keeps fetching the root password."""
    token = _create(_admin(api, seed))['token']
    served = _fetch(api, token).data.decode()
    hook = _hook(served)
    assert hook['url'].startswith('http://localhost/api/auto-install/progress?token=')
    assert token not in served
    assert 'auth-token' not in hook, 'older installers refuse unknown keys in this table'


def test_an_answer_file_with_its_own_webhook_section_is_replaced_not_duplicated(api, seed):
    own = ANSWER + '\n[post-installation-webhook]\nurl = "https://elsewhere.invalid/hook"\n'
    served = _fetch(api, _create(_admin(api, seed), answer=own)['token']).data.decode()
    assert served.count('[post-installation-webhook]') == 1
    assert 'elsewhere.invalid' not in _hook(served)['url']


def test_a_section_after_the_webhook_survives_the_strip(api, seed):
    own = (ANSWER + '\n[post-installation-webhook]\nurl = "https://elsewhere.invalid/hook"\n'
           + '\n[first-boot]\nsource = "from-url"\nurl = "https://example.com/fb"\n')
    served = _fetch(api, _create(_admin(api, seed), answer=own)['token']).data.decode()
    assert tomllib.loads(served)['first-boot']['url'] == 'https://example.com/fb'


def test_a_dotted_webhook_cannot_be_saved(api, seed):
    """We can only replace the table form; a dotted one would end up defined twice
    in the served file and every fetch would 500."""
    # top-level dotted key: it has to come before the first table header
    own = 'post-installation-webhook.url = "https://x.invalid"\n\n' + ANSWER
    r = _admin(api, seed).post('/api/auto-install/profiles', json={'name': 'x', 'answer': own})
    assert r.status_code == 400, r.data


def test_an_explicit_callback_url_wins_and_keeps_its_own_query(api, seed):
    created = _create(_admin(api, seed),
                      callback_url='https://pegaprox.example.com/api/auto-install/progress?via=dmz')
    url = _hook(_fetch(api, created['token']).data.decode())['url']
    assert url.startswith('https://pegaprox.example.com/api/auto-install/progress?')
    assert 'via=dmz' in url and '&token=' in url, url


def test_a_fingerprint_has_to_look_like_one(api, seed):
    r = _admin(api, seed).post('/api/auto-install/profiles',
                               json={'name': 'x', 'answer': ANSWER, 'callback_fingerprint': 'AB:CD'})
    assert r.status_code == 400
    assert 'fingerprint' in r.get_json()['error']


@pytest.mark.parametrize('host', ['evil.example.com"', 'host with spaces'])
def test_a_hostile_host_header_does_not_reach_the_answer_file(api, seed, host):
    """The host lands in a TOML string. An unrecognised one costs the callback
    section, not the install. (werkzeug already answers a Host with a path in it
    with its own 400, so only these two reach the handler.)"""
    token = _create(_admin(api, seed))['token']
    r = _fetch(api, token, headers={'Host': host})
    assert r.status_code == 200, r.data
    parsed = tomllib.loads(r.data.decode())
    assert parsed['global']['root-password'] == 'hunter2-in-the-rack'
    assert 'post-installation-webhook' not in parsed


def test_forwarded_headers_count_only_from_a_trusted_proxy(api, seed, monkeypatch):
    import pegaprox.utils.audit as audit
    token = _create(_admin(api, seed))['token']
    headers = {'X-Forwarded-Host': 'attacker.example.net', 'X-Forwarded-Proto': 'https'}

    monkeypatch.setattr(audit, '_is_trusted_proxy', lambda addr: False)
    url = _hook(_fetch(api, token, headers=dict(headers)).data.decode())['url']
    assert url.startswith('http://localhost/'), url

    monkeypatch.setattr(audit, '_is_trusted_proxy', lambda addr: True)
    hook = _hook(_fetch(api, token, headers=dict(headers)).data.decode())
    assert hook['url'].startswith('https://attacker.example.net/')
    assert 'cert-fingerprint' not in hook, 'behind a proxy the certificate on the wire is not ours'


def test_an_undecryptable_answer_is_a_500_and_costs_no_use(api, seed):
    c = _admin(api, seed)
    created = _create(c, max_uses=1)
    from pegaprox.core.db import get_db
    get_db().conn.execute("UPDATE auto_install_profiles SET answer_encrypted = 'aes256:garbage' WHERE id = ?",
                          (created['id'],))
    get_db().conn.commit()
    r = _fetch(api, created['token'])
    assert r.status_code == 500
    assert _profile_row(created['id'])['uses'] == 0
    assert _runs(c) == []


def test_a_stored_placeholder_hash_is_a_500_and_costs_no_use(api, seed):
    """Saved before the hash check existed, or written behind the API's back. Served,
    it installs a host whose root account nobody can log in to."""
    c = _admin(api, seed)
    created = _create(c, max_uses=1)
    from pegaprox.core.db import get_db
    bad = ANSWER.replace('root-password = "hunter2-in-the-rack"', 'root-password-hashed = "$6$...replace me..."')
    get_db().conn.execute('UPDATE auto_install_profiles SET answer_encrypted = ? WHERE id = ?',
                          (get_db()._encrypt(bad), created['id']))
    get_db().conn.commit()
    r = _fetch(api, created['token'])
    assert r.status_code == 500
    assert b'replace me' not in r.data
    assert _profile_row(created['id'])['uses'] == 0
    assert _runs(c) == []


# --- runs and the webhook ----------------------------------------------------------

def test_a_fetch_shows_up_as_an_installing_machine(api, seed):
    c = _admin(api, seed)
    _fetch(api, _create(c)['token'])
    runs = _runs(c)
    assert len(runs) == 1
    run = runs[0]
    assert run['status'] == 'installing'
    assert run['product'] == 'PowerEdge R660'
    assert run['version'] == '9.0'
    assert run['fingerprint'] == 'serial:JH7K2X3'
    assert run['profile_name'] == 'rack-7 node'
    assert 'callback_token_hash' not in run


def test_the_same_machine_retrying_does_not_become_two_machines(api, seed):
    c = _admin(api, seed)
    token = _create(c)['token']
    _fetch(api, token)
    _fetch(api, token)
    assert len(_runs(c)) == 1


def test_two_machines_on_one_profile_are_two_runs(api, seed):
    c = _admin(api, seed)
    token = _create(c)['token']
    _fetch(api, token)
    other = copy.deepcopy(FETCH_BODY)
    other['dmi']['system']['serial'] = 'OTHER-9'
    _fetch(api, token, info=other)
    assert len(_runs(c)) == 2


@pytest.mark.parametrize('serial,uuid,expected', [
    ('To be filled by O.E.M.', '6fb36fd4-77a1-57e6-13ae-000000cb48d7',
     'uuid:6fb36fd4-77a1-57e6-13ae-000000cb48d7'),
    ('', '00000000-0000-0000-0000-000000000000', 'mac:aa:bb:cc:dd:ee:01'),
])
def test_a_machine_without_a_usable_serial_is_still_recognised(api, seed, serial, uuid, expected):
    """VMs typically report no serial but an SMBIOS uuid."""
    c = _admin(api, seed)
    info = copy.deepcopy(FETCH_BODY)
    info['dmi']['system']['serial'] = serial
    info['dmi']['system']['uuid'] = uuid
    _fetch(api, _create(c)['token'], info=info)
    assert _runs(c)[0]['fingerprint'] == expected


def test_an_oversized_inventory_is_kept_readable(api, seed):
    c = _admin(api, seed)
    fat = dict(FETCH_BODY)
    fat['dmesg'] = 'x' * 200000
    _fetch(api, _create(c)['token'], info=fat)
    run = _runs(c)[0]
    assert run['system_info'].get('truncated') is True, run['system_info']
    assert 'dmesg' in run['system_info']['keys']
    assert run['product'] == 'PowerEdge R660'


def test_the_installers_own_webhook_marks_the_run_installed(api, seed):
    """The real body has no status field; it is sent only after a successful
    install. Reading it as 'still installing' left every real run open for good."""
    c = _admin(api, seed)
    served = _fetch(api, _create(c)['token']).data.decode()
    r = _report(api, served)
    assert r.status_code == 200, r.data
    run = _runs(c)[0]
    assert run['status'] == 'installed'
    assert run['hostname'] == 'pve01.lab.example.com'
    assert run['version'] == '9.0.3'
    assert run['system_info']['post_install']['machine-id'] == 'b8737afea804482697ffe04db69c73d1'


@pytest.mark.parametrize('payload,expected', [
    ({'status': 'installed'}, 'installed'),
    ({'status': 'ok'}, 'installed'),
    ({'success': True}, 'installed'),
    ({'success': False, 'message': 'disk too small'}, 'failed'),
    ({'status': 'error', 'error': 'no nic'}, 'failed'),
    ({'error': 'boom'}, 'failed'),
    ({'something': 'else'}, 'installing'),
])
def test_an_explicit_status_from_a_script_is_honoured(api, seed, payload, expected):
    c = _admin(api, seed)
    served = _fetch(api, _create(c)['token']).data.decode()
    assert _report(api, served, payload).status_code == 200
    assert _runs(c)[0]['status'] == expected


def test_a_callback_token_closes_its_own_run_and_no_other(api, seed):
    c = _admin(api, seed)
    token = _create(c)['token']
    first = _fetch(api, token).data.decode()
    other = copy.deepcopy(FETCH_BODY)
    other['dmi']['system']['serial'] = 'OTHER-9'
    _fetch(api, token, info=other)

    _report(api, first)
    by_fp = {r['fingerprint']: r['status'] for r in _runs(c)}
    assert by_fp == {'serial:JH7K2X3': 'installed', 'serial:OTHER-9': 'installing'}


def test_a_finished_install_can_still_report_after_the_token_is_spent(api, seed):
    c = _admin(api, seed)
    served = _fetch(api, _create(c, max_uses=1)['token']).data.decode()
    assert _report(api, served).status_code == 200
    assert _runs(c)[0]['status'] == 'installed'


def test_the_fetch_token_does_not_work_as_a_callback(api, seed):
    c = _admin(api, seed)
    token = _create(c)['token']
    _fetch(api, token)
    r = _raw(api).post(f'/api/auto-install/progress?token={token}', json={'status': 'failed'},
                       base_url='http://localhost')
    assert r.status_code == 403
    assert _runs(c)[0]['status'] == 'installing'


def test_progress_from_an_unknown_token_is_refused(api, seed):
    c = _admin(api, seed)
    _fetch(api, _create(c)['token'])
    r = _raw(api).post('/api/auto-install/progress?token=nope', json={'status': 'failed'},
                       base_url='http://localhost')
    assert r.status_code == 403
    assert _runs(c)[0]['status'] == 'installing'


# --- who may do what ------------------------------------------------------------

def test_the_answer_file_is_encrypted_at_rest(api, seed):
    created = _create(_admin(api, seed))
    from pegaprox.core.db import get_db
    stored = _profile_row(created['id'])['answer_encrypted']
    assert 'hunter2-in-the-rack' not in stored
    assert get_db()._decrypt(stored) == ANSWER


def _viewer(api, seed):
    return api.as_user(seed.user('watcher', role='viewer', permissions=['autoinstall.view']))


def test_view_only_sees_the_shape_of_the_file_not_the_password(api, seed):
    created = _create(_admin(api, seed))
    body = _viewer(api, seed).get(f"/api/auto-install/profiles/{created['id']}").get_json()
    assert body['answer_redacted'] is True
    assert 'hunter2-in-the-rack' not in body['answer']
    assert 'root-password' in body['answer']
    assert 'pve01.lab.example.com' in body['answer']
    assert _viewer(api, seed).get('/api/auto-install/profiles').get_json()['can_manage'] is False


SECRET = 'S3cr3t-Pa55-9f2c'
# a real hash: a stored value that only looks like a password no longer saves, and
# the hash is still nothing a view-only reader should get to crack offline
HASHED = sha512_crypt(SECRET, 'rackseven0123456')
SPELLINGS = [
    ('quoted key', '"root-password" = "%s"', SECRET),
    ('single-quoted key', "'root-password' = '%s'", SECRET),
    ('snake_case alias', 'root_password = "%s"', SECRET),
    ('multi-line string', 'root-password = """\n%s"""', SECRET),
    ('hashed, inline', 'root-password-hashed = "%s"', HASHED),
]


@pytest.mark.parametrize('label,line,secret', SPELLINGS, ids=[s[0] for s in SPELLINGS])
def test_no_spelling_of_the_password_reaches_a_view_only_reader(api, seed, label, line, secret):
    answer = ANSWER.replace('root-password = "hunter2-in-the-rack"', line % secret)
    created = _create(_admin(api, seed), answer=answer)
    body = _viewer(api, seed).get(f"/api/auto-install/profiles/{created['id']}").get_json()
    assert secret not in body['answer'], (label, body['answer'])


@pytest.mark.parametrize('form', [
    'global = { keyboard = "de", country = "de", fqdn = "pve01.lab.example.com", '
    'mailto = "root@example.com", timezone = "Europe/Berlin", root-password = "%s" }\n',
    'global.keyboard = "de"\nglobal.country = "de"\nglobal.fqdn = "pve01.lab.example.com"\n'
    'global.mailto = "root@example.com"\nglobal.timezone = "Europe/Berlin"\n'
    'global.root-password = "%s"\n',
], ids=['inline table', 'dotted keys'])
def test_a_file_that_cannot_be_blanked_is_not_shown_at_all(api, seed, form):
    rest = ANSWER.split('[network]', 1)[1]
    answer = (form % SECRET) + '\n[network]' + rest
    created = _create(_admin(api, seed), answer=answer)
    body = _viewer(api, seed).get(f"/api/auto-install/profiles/{created['id']}").get_json()
    assert SECRET not in body['answer']


# (#1026) the value check searched the decoded secret in the text, and an escaped or
# line-continued spelling does not contain it: the reader got the secret in that spelling
ESCAPED_SECRET = SECRET[:-1] + '\\u0063'
CONTINUED_SECRET = SECRET[:8] + '\\\n    ' + SECRET[8:]
DOTTED = ('global.keyboard = "de"\nglobal.country = "de"\nglobal.fqdn = "pve01.lab.example.com"\n'
          'global.mailto = "root@example.com"\nglobal.timezone = "Europe/Berlin"\n'
          'global.root-password = "%s"\n\n[network]' + ANSWER.split('[network]', 1)[1])
ESCAPED = [
    ('quoted key, unicode escape', ESCAPED_SECRET,
     ANSWER.replace('root-password = "hunter2-in-the-rack"', '"root-password" = "%s"' % ESCAPED_SECRET)),
    ('dotted key, unicode escape', ESCAPED_SECRET, DOTTED % ESCAPED_SECRET),
    ('line-continued string', CONTINUED_SECRET,
     ANSWER.replace('root-password = "hunter2-in-the-rack"', 'root-password = """%s"""' % CONTINUED_SECRET)),
]


@pytest.mark.parametrize('label,spelled,answer', ESCAPED, ids=[s[0] for s in ESCAPED])
def test_an_escaped_spelling_of_the_password_reaches_no_view_only_reader(api, seed, label, spelled, answer):
    assert tomllib.loads(answer)['global']['root-password'] == SECRET
    created = _create(_admin(api, seed), answer=answer)
    body = _viewer(api, seed).get(f"/api/auto-install/profiles/{created['id']}").get_json()
    shown = body['answer']
    assert SECRET not in shown and SECRET[8:] not in shown and spelled.split('\n')[0] not in shown, (label, shown)
    try:
        decoded = tomllib.loads(shown)
    except tomllib.TOMLDecodeError:
        decoded = {}
    assert SECRET not in json.dumps(decoded), (label, shown)


def test_view_only_cannot_create_or_rotate(api, seed):
    created = _create(_admin(api, seed))
    w = _viewer(api, seed)
    assert w.post('/api/auto-install/profiles', json={'name': 'x', 'answer': ANSWER}).status_code == 403
    assert w.post(f"/api/auto-install/profiles/{created['id']}/token").status_code == 403
    assert w.delete(f"/api/auto-install/profiles/{created['id']}").status_code == 403


def test_a_user_without_either_permission_sees_nothing(api, seed):
    _create(_admin(api, seed))
    nobody = api.as_user(seed.user('nobody', role='user'))
    assert nobody.get('/api/auto-install/profiles').status_code == 403
    assert nobody.get('/api/auto-install/runs').status_code == 403


def test_an_unconfined_operator_with_the_permission_can_manage(api, seed):
    """Not an admin, but sees every cluster and holds autoinstall.manage. A gate
    tested only with admins passes while it refuses every ordinary operator."""
    ops = api.as_user(seed.user('ops', role='user',
                                permissions=['autoinstall.view', 'autoinstall.manage']))
    created = _create(ops)
    assert ops.get('/api/auto-install/profiles').get_json()['can_manage'] is True
    got = ops.get(f"/api/auto-install/profiles/{created['id']}").get_json()
    assert got['answer_redacted'] is False
    assert 'hunter2-in-the-rack' in got['answer']
    assert ops.post(f"/api/auto-install/profiles/{created['id']}/token").status_code == 200


def test_a_tenant_confined_holder_is_turned_away_everywhere(api, seed):
    """Profiles belong to no tenant and carry root passwords. A tenant admin who
    holds both permissions must not read or rewrite another tenant's files."""
    created = _create(_admin(api, seed))
    seed.tenant('globex', ['cluster_globex'])
    t = api.as_user(seed.user('globex_admin', role='user', tenant_id='globex',
                              permissions=['autoinstall.view', 'autoinstall.manage']))
    pid = created['id']
    calls = [
        t.get('/api/auto-install/profiles'),
        t.get(f'/api/auto-install/profiles/{pid}'),
        t.put(f'/api/auto-install/profiles/{pid}', json={'name': 'mine now', 'answer': ANSWER}),
        t.post(f'/api/auto-install/profiles/{pid}/token'),
        t.delete(f'/api/auto-install/profiles/{pid}'),
        t.get('/api/auto-install/runs'),
        t.post('/api/auto-install/profiles', json={'name': 'x', 'answer': ANSWER}),
        t.post('/api/auto-install/password-hash', json={'password': 'long-enough-9'}),
        t.post('/api/auto-install/compose', json={'fields': FIELDS}),
    ]
    for r in calls:
        assert r.status_code == 403, (r.request.path, r.status_code, r.data)
        assert b'tenant' in r.data, r.data         # our gate, not a missing permission
    assert _admin(api, seed).get(f'/api/auto-install/profiles/{pid}').get_json()['name'] == 'rack-7 node'


# --- every session route against every kind of caller ---------------------------

def _session_routes(pid, rid):
    """(method, path, body, needs). The tests above pick routes by hand; this list is
    all of them, so a route added later without a gate shows up here."""
    return [
        ('get', '/api/auto-install/profiles', None, 'view'),
        ('get', f'/api/auto-install/profiles/{pid}', None, 'view'),
        ('get', '/api/auto-install/runs', None, 'view'),
        ('post', '/api/auto-install/profiles', {'name': 'x', 'answer': ANSWER}, 'manage'),
        ('put', f'/api/auto-install/profiles/{pid}', {'name': 'mine now', 'answer': ANSWER}, 'manage'),
        ('post', f'/api/auto-install/profiles/{pid}/token', None, 'manage'),
        ('delete', f'/api/auto-install/profiles/{pid}', None, 'manage'),
        ('post', '/api/auto-install/validate', {'answer': ANSWER}, 'manage'),
        ('post', '/api/auto-install/password-hash', {'password': 'long-enough-9'}, 'manage'),
        ('post', '/api/auto-install/compose', {'fields': FIELDS}, 'manage'),
        ('delete', f'/api/auto-install/runs/{rid}', None, 'manage'),
    ]


def test_the_route_list_above_is_complete(api):
    listed = {(m.upper(), re.sub(r'<[^>]+>', '<x>', p))
              for m, p, _b, _n in _session_routes('<x>', '<x>')}
    served = set()
    for rule in api.app.url_map.iter_rules():
        if rule.rule.startswith('/api/auto-install/') and rule.rule not in (
                '/api/auto-install/answer', '/api/auto-install/progress'):
            for m in rule.methods - {'HEAD', 'OPTIONS'}:
                served.add((m, re.sub(r'<[^>]+>', '<x>', rule.rule)))
    assert served == listed


def _one_install(api, seed):
    a = _admin(api, seed)
    created = _create(a)
    served = _fetch(api, created['token']).get_data(as_text=True)
    return a, created, served, _runs(a)[0]['id']


def _send(client, method, path, body, **kw):
    if body is not None:
        kw['json'] = body
    return getattr(client, method)(path, **kw)


def _stored(pid):
    row = _profile_row(pid)
    return row['name'], row['token_hash'], row['answer_encrypted'], row['enabled']


def test_no_session_route_answers_without_a_login(api, seed):
    a, created, _served, rid = _one_install(api, seed)
    before = _stored(created['id'])
    for method, path, body, _needs in _session_routes(created['id'], rid):
        assert _send(api.anon(), method, path, body).status_code == 401, (method, path)
    assert _stored(created['id']) == before
    assert len(_runs(a)) == 1


@pytest.mark.parametrize('kind', ['no_permission', 'view_only', 'tenant_user', 'capped_admin'])
def test_below_manage_nothing_changes(api, seed, kind):
    """view_only may read, and reads the file blanked. Everyone else gets nothing,
    and none of the refused writes may have touched the profile or its run."""
    a, created, _served, rid = _one_install(api, seed)
    pid = created['id']
    both = ['autoinstall.view', 'autoinstall.manage']
    if kind == 'no_permission':
        c = api.as_user(seed.user('nobody', role='user'))
    elif kind == 'view_only':
        c = _viewer(api, seed)
    elif kind == 'tenant_user':
        seed.tenant('initech', ['cluster_1'])
        c = api.as_user(seed.user('ops2', role='user', tenant_id='initech', permissions=both))
    else:
        # an admin that an LDAP tenant mapping has lowered where they live
        seed.tenant('globex', ['cluster_globex'])
        c = api.as_user(seed.user('gx', role='admin', tenant_id='globex', permissions=both,
                                  tenant_permissions={'globex': {'role': 'user'}}))
    before = _stored(pid)
    for method, path, body, needs in _session_routes(pid, rid):
        r = _send(c, method, path, body)
        if kind == 'view_only' and needs == 'view':
            assert r.status_code == 200, (method, path, r.status_code)
            assert 'hunter2-in-the-rack' not in r.get_data(as_text=True), path
        else:
            assert r.status_code == 403, (kind, method, path, r.status_code, r.data)
    assert _stored(pid) == before
    assert len(_runs(a)) == 1


def test_an_admins_viewer_token_reaches_none_of_it(api, seed):
    from pegaprox.utils.auth import create_api_token
    _a, created, _served, rid = _one_install(api, seed)
    res = create_api_token('root', 'ci', role='viewer')
    assert res.get('success'), res
    auth = {'Authorization': f"Bearer {res['token']}"}
    for method, path, body, _needs in _session_routes(created['id'], rid):
        r = _send(api.anon(), method, path, body, headers=auth)
        assert r.status_code == 403, (method, path, r.status_code)


def test_a_callback_token_does_not_fetch_an_answer(api, seed):
    a, _created, served, _rid = _one_install(api, seed)
    query = urlsplit(_hook(served)['url']).query
    callback_token = query.split('=', 1)[1].split('&', 1)[0]
    assert _fetch(api, callback_token).status_code in (401, 403)
    assert len(_runs(a)) == 1


def test_deleting_a_profile_ends_its_callbacks(api, seed):
    a, created, served, _rid = _one_install(api, seed)
    assert a.delete(f"/api/auto-install/profiles/{created['id']}").status_code == 200
    assert _report(api, served).status_code in (401, 403, 404)


@pytest.mark.parametrize('field,value', [
    ('enabled', 'false'), ('enabled', '0'), ('enabled', 'no'), ('enabled', None), ('enabled', 2),
    ('max_uses', True),
])
def test_enabled_and_max_uses_are_not_read_loosely(api, seed, field, value):
    """A string "false" is truthy. A script that revoked a profile that way got a
    200 and a profile that still served its file."""
    a = _admin(api, seed)
    created = _create(a)
    r = a.put(f"/api/auto-install/profiles/{created['id']}", json={field: value})
    assert r.status_code == 400, (r.status_code, r.data)
    row = _profile_row(created['id'])
    assert row['enabled'] == 1 and row['max_uses'] == 0


def test_enabled_false_still_revokes(api, seed):
    a = _admin(api, seed)
    created = _create(a)
    assert a.put(f"/api/auto-install/profiles/{created['id']}", json={'enabled': False}).status_code == 200
    assert _profile_row(created['id'])['enabled'] == 0
    assert _fetch(api, created['token']).status_code in (401, 403)


# --- validation -------------------------------------------------------------------

@pytest.mark.parametrize('answer,needle', [
    ('not toml at all {{{', 'Not valid TOML'),
    ('[global]\nkeyboard = "de"\n', 'country'),
    (ANSWER.replace('[disk-setup]\nfilesystem = "ext4"\ndisk-list = ["sda"]\n', ''), 'disk-setup'),
    (ANSWER.replace('source = "from-dhcp"', 'source = "magic"'), 'from-dhcp'),
    (ANSWER.replace('fqdn = "pve01.lab.example.com"', 'fqdn = "pve01"'), 'fully qualified'),
    (ANSWER.replace('fqdn = "pve01.lab.example.com"', 'fqdn.source = "from-magic"'), 'fqdn.source'),
    # everything below used to pass here and fail at the rack
    (ANSWER.replace('filesystem = "ext4"', 'filesystem = "zfs"'), 'zfs.raid'),
    (ANSWER.replace('filesystem = "ext4"', 'filesystem = "btrfs"'), 'btrfs.raid'),
    (ANSWER.replace('filesystem = "ext4"', 'filesystem = "zfs"\nzfs.raid = "raid5"'), 'must be one of'),
    # the editor's own template placeholder: saved as is, root could never log in
    (ANSWER.replace('root-password = "hunter2-in-the-rack"', 'root-password-hashed = "$6$...replace me..."'),
     'not a password hash'),
    (ANSWER.replace('root-password = "hunter2-in-the-rack"', 'root-password-hashed = "S3cr3t-Pa55-9f2c"'),
     'not a password hash'),
    # a newline after a real hash would write a second line into chpasswd
    (ANSWER.replace('root-password = "hunter2-in-the-rack"', f'root-password-hashed = "{HASHED}\\n"'),
     'not a password hash'),
    (ANSWER.replace('root-password = "hunter2-in-the-rack"', 'root-password = "hunter7"'), '8 bytes'),
    (ANSWER.replace('disk-list = ["sda"]', 'disk-list = ["sda"]\nfilter.ID_SERIAL = "*S3Z*"'), 'both'),
    (ANSWER.replace('disk-list = ["sda"]', 'disk-list = ["sda", "sdb"]'), 'only one disk'),
    (ANSWER.replace('filesystem = "ext4"\ndisk-list = ["sda"]',
                    'filesystem = "zfs"\nzfs.raid = "raidz-2"\ndisk-list = ["sda", "sdb", "sdc"]'), 'at least 4'),
    (ANSWER.replace('filesystem = "ext4"\ndisk-list = ["sda"]',
                    'filesystem = "zfs"\nzfs.raid = "raid10"\ndisk-list = ["sda", "sdb", "sdc"]'), 'at least 4'),
    (ANSWER.replace('filesystem = "ext4"\ndisk-list = ["sda"]',
                    'filesystem = "btrfs"\nbtrfs.raid = "raid10"\ndisk-list = ["sda", "sdb", "sdc", "sdd", "sde"]'),
     'even number'),
    (ANSWER.replace('filesystem = "ext4"\ndisk-list = ["sda"]',
                    'filesystem = "zfs"\nzfs.raid = "raid1"\ndisk-list = ["sda", "sda"]'), 'same disk twice'),
    (ANSWER.replace('filesystem = "ext4"', 'filesystem = "ext4"\nzfs.ashift = 12'), 'do not apply to ext4'),
    (ANSWER.replace('source = "from-dhcp"', 'source = "from-dhcp"\ncidr = "192.0.2.10/24"'), 'from-dhcp takes no'),
    (ANSWER.replace('keyboard = "de"', 'keyboard = "xx"'), 'keyboard layout'),
    (ANSWER.replace('country = "de"', 'country = "DE"'), 'two-letter'),
    (ANSWER.replace('timezone = "Europe/Berlin"', 'timezone = "Etc/UTC"'), 'Etc/'),
    (ANSWER.replace('mailto = "root@example.com"', 'mailto = "mail@example.invalid"'), 'placeholder'),
    (ANSWER.replace('mailto = "root@example.com"', 'mailto = "root at example"'), 'e-mail address'),
    (ANSWER.replace('fqdn = "pve01.lab.example.com"', 'fqdn = "123.example.com"'), 'all-numeric'),
    (ANSWER.replace('fqdn = "pve01.lab.example.com"', 'fqdn = "pve_01.lab.local"'), 'hyphens'),
    (ANSWER.replace('fqdn = "pve01.lab.example.com"',
                    'fqdn.source = "from-dhcp"\nfqdn.domain = "lab_1.local"'), 'fqdn.domain'),
])
def test_the_validator_catches_what_the_installer_would_refuse(api, seed, answer, needle):
    body = _admin(api, seed).post('/api/auto-install/validate', json={'answer': answer}).get_json()
    assert body['valid'] is False
    assert any(needle in e for e in body['errors']), body['errors']


def test_a_good_answer_file_validates(api, seed):
    body = _admin(api, seed).post('/api/auto-install/validate', json={'answer': ANSWER}).get_json()
    assert body['valid'] is True
    assert any('clear text' in w for w in body['warnings'])


def test_the_dhcp_form_of_fqdn_is_accepted(api, seed):
    """fqdn.source = "from-dhcp" is documented; it used to fail the dot check."""
    answer = ANSWER.replace('fqdn = "pve01.lab.example.com"',
                            'fqdn.source = "from-dhcp"\nfqdn.domain = "lab.example.com"')
    body = _admin(api, seed).post('/api/auto-install/validate', json={'answer': answer}).get_json()
    assert body['valid'] is True, body


def test_a_missing_raid_level_is_an_error_and_the_dotted_key_counts(api, seed):
    """The installer refuses zfs without zfs.raid. This was only a warning, and
    the test here pinned the warning - a profile saved that way stopped at the rack."""
    zfs = ANSWER.replace('filesystem = "ext4"\ndisk-list = ["sda"]',
                         'filesystem = "zfs"\nzfs.raid = "raid1"\ndisk-list = ["sda", "sdb"]')
    c = _admin(api, seed)
    with_raid = c.post('/api/auto-install/validate', json={'answer': zfs}).get_json()
    without = c.post('/api/auto-install/validate',
                     json={'answer': zfs.replace('zfs.raid = "raid1"\n', '')}).get_json()
    assert with_raid['valid'] is True, with_raid
    assert not any('raid' in m for m in with_raid['errors'] + with_raid['warnings']), with_raid
    assert without['valid'] is False
    assert any('raid' in e for e in without['errors']), without['errors']


def test_upper_case_raid_levels_are_what_the_installer_also_takes(api, seed):
    zfs = ANSWER.replace('filesystem = "ext4"\ndisk-list = ["sda"]',
                         'filesystem = "zfs"\nzfs.raid = "RAIDZ-1"\ndisk-list = ["sda", "sdb", "sdc"]')
    body = _admin(api, seed).post('/api/auto-install/validate', json={'answer': zfs}).get_json()
    assert body['valid'] is True, body


def test_an_invalid_answer_file_cannot_be_saved(api, seed):
    c = _admin(api, seed)
    assert c.post('/api/auto-install/profiles', json={'name': 'broken', 'answer': '[global]\n'}).status_code == 400
    assert c.get('/api/auto-install/profiles').get_json()['profiles'] == []


# --- updates, expiry, lifecycle -----------------------------------------------------

def test_editing_without_resending_the_answer_keeps_it(api, seed):
    """The UI can show a blanked file; a save from that screen must not write the
    blanking back over the real password."""
    c = _admin(api, seed)
    created = _create(c)
    r = c.put(f"/api/auto-install/profiles/{created['id']}", json={'name': 'renamed'})
    assert r.status_code == 200, r.data
    full = c.get(f"/api/auto-install/profiles/{created['id']}").get_json()
    assert full['name'] == 'renamed'
    assert 'hunter2-in-the-rack' in full['answer']


def test_a_partial_update_keeps_every_field_it_did_not_send(api, seed):
    """Falling back to the create defaults re-enabled a revoked profile and lifted
    its use limit, expiry and pin on a PUT that only renamed it."""
    c = _admin(api, seed)
    fp = ':'.join(['AB'] * 32)
    created = _create(c, max_uses=1, expires_at='2099-01-01T00:00:00Z', enabled=False,
                      callback_url='https://cb.example.com/p', callback_fingerprint=fp,
                      target_cluster_id='cluster_1', description='keep me')
    assert c.put(f"/api/auto-install/profiles/{created['id']}", json={'name': 'renamed'}).status_code == 200
    got = c.get(f"/api/auto-install/profiles/{created['id']}").get_json()
    assert got['enabled'] is False
    assert got['max_uses'] == 1
    assert got['expires_at'] == '2099-01-01T00:00:00+00:00'
    assert got['callback_url'] == 'https://cb.example.com/p'
    assert got['callback_fingerprint'] == fp
    assert got['target_cluster_id'] == 'cluster_1'
    assert got['description'] == 'keep me'
    assert _fetch(api, created['token']).status_code == 403


@pytest.mark.parametrize('sent,stored', [
    ('2099-01-01T12:00:00Z', '2099-01-01T12:00:00+00:00'),
    ('2099-01-01T14:00:00+02:00', '2099-01-01T12:00:00+00:00'),
    ('2099-01-01T12:00', '2099-01-01T12:00:00+00:00'),
    ('2099-01-01', '2099-01-01T00:00:00+00:00'),
])
def test_an_expiry_is_stored_in_utc_and_does_not_break_the_fetch(api, seed, sent, stored):
    """An offset-aware value used to be accepted and then 500 every fetch, because
    it was compared with a naive local time."""
    c = _admin(api, seed)
    created = _create(c, expires_at=sent)
    assert c.get(f"/api/auto-install/profiles/{created['id']}").get_json()['expires_at'] == stored
    assert _fetch(api, created['token']).status_code == 200


def test_an_unreadable_expiry_fails_closed(api, seed):
    c = _admin(api, seed)
    created = _create(c)
    from pegaprox.core.db import get_db
    get_db().conn.execute("UPDATE auto_install_profiles SET expires_at = 'next tuesday' WHERE id = ?",
                          (created['id'],))
    get_db().conn.commit()
    assert _fetch(api, created['token']).status_code == 403


def test_deleting_a_profile_takes_its_runs_with_it(api, seed):
    c = _admin(api, seed)
    created = _create(c)
    served = _fetch(api, created['token']).data.decode()
    assert c.delete(f"/api/auto-install/profiles/{created['id']}").status_code == 200
    assert _runs(c) == []
    assert _fetch(api, created['token']).status_code == 403
    assert _report(api, served).status_code == 403


# --- guided setup: hashing the root password -----------------------------------------

@pytest.fixture(autouse=True)
def _fresh_hash_budget():
    """The hash limiter is process-wide and every test here hashes as 'root'."""
    import pegaprox.utils.ssh as ssh
    win = ssh._auth_action_windows.get((20, 300))
    if win is not None:
        win.reset()
    yield


def _hash(client, password):
    return client.post('/api/auto-install/password-hash', json={'password': password})


def test_the_password_comes_back_as_a_sha512_crypt_hash(api, seed):
    r = _hash(_admin(api, seed), 'Correct-Horse-9')
    assert r.status_code == 200, r.data
    h = r.get_json()['hash']
    assert re.fullmatch(r'\$6\$rounds=100000\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{86}', h), h
    assert sha512_crypt('Correct-Horse-9', h.split('$')[3], 100000) == h
    assert 'no-store' in r.headers['Cache-Control']


@pytest.mark.parametrize('password', [
    'Short-7',              # 7 characters
    'x' * 65,
    'abcdefg',              # 7 bytes of ASCII
    'eight\x00chars',
    'eight\nchars',
    'tab\there-too',
    12345678,
    None,
], ids=['7 chars', '65 chars', '7 bytes', 'NUL', 'newline', 'tab', 'number', 'missing'])
def test_a_bad_password_is_refused_without_repeating_it(api, seed, password):
    r = _hash(_admin(api, seed), password)
    assert r.status_code == 400, r.data
    assert 'hash' not in r.get_json()
    if isinstance(password, str):
        assert password not in r.get_data(as_text=True)


def test_hashing_stays_off_the_login_semaphore(api, seed, monkeypatch):
    """sha512_crypt holds the GIL, argon2 does not. Queued behind the login's
    semaphore, twenty of these starved the hub and stalled everybody's login for
    seconds, so the endpoint has a one-slot semaphore of its own."""
    import pegaprox.utils.auth as auth
    import pegaprox.api.auto_install as ai

    class Forbidden:
        def __enter__(self):
            raise AssertionError('root-password hashing went through the login semaphore')

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(auth, '_PW_HASH_SEM', Forbidden())
    r = _hash(_admin(api, seed), 'Correct-Horse-9')
    assert r.status_code == 200, r.data
    sem = ai._ROOT_HASH_SEM
    if sem is not None:                        # None only when gevent is missing
        assert sem.counter == 1 and not sem.locked()


def test_hashing_needs_the_manage_permission(api, seed):
    assert _hash(_viewer(api, seed), 'Correct-Horse-9').status_code == 403


def test_hashing_is_rate_limited(api, seed):
    c = _admin(api, seed)
    # refusals count too, so the budget cannot be probed for free with junk
    codes = [_hash(c, 'short').status_code for _ in range(20)]
    assert set(codes) == {400}
    r = _hash(c, 'Correct-Horse-9')
    assert r.status_code == 429
    assert 'hash' not in r.get_json()


def test_the_clear_password_is_kept_nowhere(api, seed, caplog):
    import logging
    from pegaprox.core.db import get_db
    caplog.set_level(logging.DEBUG)
    pw = 'Leak-Canary-7f3e9'
    c = _admin(api, seed)
    r = _hash(c, pw)
    assert r.status_code == 200
    created = _create(c, answer=ANSWER.replace('root-password = "hunter2-in-the-rack"',
                                               f'root-password-hashed = "{r.get_json()["hash"]}"'))
    refused = _hash(c, pw + '\n')
    assert refused.status_code == 400

    assert pw not in r.get_data(as_text=True) + refused.get_data(as_text=True)
    cur = get_db().conn.cursor()
    row = _profile_row(created['id'])
    assert pw not in ' '.join(str(row[k]) for k in row.keys())
    assert pw not in get_db()._decrypt(row['answer_encrypted'])
    audit = cur.execute('SELECT * FROM audit_log').fetchall()
    assert audit, 'the create is audited, so the table was looked at'
    assert pw not in ' '.join(str(v) for a in audit for v in tuple(a))
    assert pw not in caplog.text


# --- guided setup: fields -> answer file -----------------------------------------------

FIELDS = {
    'global': {'keyboard': 'de', 'country': 'de', 'timezone': 'Europe/Berlin',
               'mailto': 'root@example.com', 'fqdn': 'pve01.lab.example.com',
               'root_password_hashed': HASHED},
    'network': {'source': 'from-dhcp'},
    'disk': {'filesystem': 'ext4', 'disk_list': ['sda']},
}

# pinned here rather than read from the module, so a slip in the table shows up
ZFS_MIN = {'raid0': 1, 'raid1': 2, 'raid10': 4, 'raidz-1': 3, 'raidz-2': 4, 'raidz-3': 5}
BTRFS_MIN = {'raid0': 1, 'raid1': 2, 'raid10': 4}
DISKS = ([('ext4', None, 1), ('xfs', None, 1)]
         + [('zfs', level, n) for level, n in ZFS_MIN.items()]
         + [('btrfs', level, n) for level, n in BTRFS_MIN.items()])
NETWORKS = [
    {'source': 'from-dhcp'},
    {'source': 'from-answer', 'cidr': '192.0.2.10/24', 'gateway': '192.0.2.1', 'dns': '192.0.2.53',
     'filter': {'ID_NET_NAME_MAC': '*e43d1afa379a'}},
    {'source': 'from-answer', 'cidr': '2001:db8::10/64', 'gateway': '2001:db8::1', 'dns': '2001:db8::53',
     'filter': {'ID_NET_NAME': 'enp*s0'}},
]
FQDNS = ['pve01.lab.example.com', {'source': 'from-dhcp'},
         {'source': 'from-dhcp', 'domain': 'lab.example.com'}]


def _compose(client, fields):
    r = client.post('/api/auto-install/compose', json={'fields': fields})
    assert r.status_code == 200, r.data
    return r.get_json()


def _expected(fields):
    """The file the fields should turn into, spelled out by hand: kebab-case keys,
    raid as a dotted sub-table, and nothing the installer would refuse."""
    g, net, disk = fields['global'], fields['network'], fields['disk']
    exp_g = {'keyboard': g['keyboard'], 'country': g['country'], 'fqdn': g['fqdn'],
             'mailto': g['mailto'], 'timezone': g['timezone'],
             'root-password-hashed': g['root_password_hashed']}
    exp_net = {'source': net['source']}
    if net['source'] == 'from-answer':
        exp_net.update({k: net[k] for k in ('cidr', 'gateway', 'dns', 'filter')})
    exp_disk = {'filesystem': disk['filesystem']}
    if disk.get('raid'):
        exp_disk[disk['filesystem']] = {'raid': disk['raid']}
    if disk.get('disk_list'):
        exp_disk['disk-list'] = disk['disk_list']
    else:
        exp_disk['filter'] = disk['filter']
    return {'global': exp_g, 'network': exp_net, 'disk-setup': exp_disk}


@pytest.mark.parametrize('select', ['disk-list', 'filter'])
@pytest.mark.parametrize('fs,level,n', DISKS, ids=[f'{d[0]}-{d[1] or "single"}' for d in DISKS])
def test_every_wizard_combination_composes_a_file_the_installer_takes(api, seed, fs, level, n, select):
    c = _admin(api, seed)
    for net in NETWORKS:
        for fqdn in FQDNS:
            f = copy.deepcopy(FIELDS)
            f['global']['fqdn'] = copy.deepcopy(fqdn)
            f['network'] = copy.deepcopy(net)
            f['disk'] = {'filesystem': fs}
            if level:
                f['disk']['raid'] = level
            if select == 'disk-list':
                f['disk']['disk_list'] = [f'sd{chr(97 + i)}' for i in range(n)]
            else:
                f['disk']['filter'] = {'ID_SERIAL': '*SAMSUNG_MZ7L3*'}
            body = _compose(c, f)
            case = (fs, level, select, net['source'], fqdn)
            assert body['valid'] is True, (case, body)
            assert body['errors'] == [] and body['field_errors'] == {}, (case, body)
            assert tomllib.loads(body['answer']) == _expected(f), (case, body['answer'])
            assert 'post-installation-webhook' not in body['answer']
            assert '_' not in ''.join(k for k in tomllib.loads(body['answer'])['global']), 'kebab-case only'


def test_from_dhcp_writes_only_the_source(api, seed):
    """The form keeps its static values when someone switches back to DHCP. Next to
    from-dhcp the installer refuses every one of them."""
    f = copy.deepcopy(FIELDS)
    f['network'] = {'source': 'from-dhcp', 'cidr': '192.0.2.10/24', 'gateway': '192.0.2.1',
                    'dns': '192.0.2.53', 'filter': {'ID_NET_NAME': 'eno1'}}
    body = _compose(_admin(api, seed), f)
    assert body['valid'] is True, body
    assert tomllib.loads(body['answer'])['network'] == {'source': 'from-dhcp'}


def test_a_raid_left_over_from_zfs_is_dropped_for_ext4(api, seed):
    f = copy.deepcopy(FIELDS)
    f['disk']['raid'] = 'raid1'
    body = _compose(_admin(api, seed), f)
    assert body['valid'] is True, body
    assert tomllib.loads(body['answer'])['disk-setup'] == {'filesystem': 'ext4', 'disk-list': ['sda']}


def test_ssh_keys_are_written_and_a_quote_in_a_comment_stays_in_its_string(api, seed):
    keys = ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq0 ops "laptop" \\ x = 1',
            'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7==', '']
    f = copy.deepcopy(FIELDS)
    f['global']['root_ssh_keys'] = keys
    body = _compose(_admin(api, seed), f)
    assert body['valid'] is True, body
    parsed = tomllib.loads(body['answer'])
    assert parsed['global']['root-ssh-keys'] == keys[:2], 'blank lines are no keys'
    assert set(parsed['global']) == set(_expected(FIELDS)['global']) | {'root-ssh-keys'}


def _set(fields, path, value):
    node = fields
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


@pytest.mark.parametrize('path,value,key', [
    (('global', 'mailto'), 'root@example.com\nkeyboard = "us"', 'global.mailto'),
    (('global', 'mailto'), 'root@exa\x00mple.com', 'global.mailto'),
    (('global', 'mailto'), 'ro"ot@example.com', 'global.mailto'),
    (('global', 'fqdn'), {'source': 'from-dhcp', 'domain': 'lab.example.com\n[network]'}, 'global.fqdn'),
    (('global', 'fqdn'), {'source': 'from-dhcp', 'domain': 'lab\x00.example.com'}, 'global.fqdn'),
    (('global', 'fqdn'), {'source': 'from-dhcp', 'domain': 'lab".example.com'}, 'global.fqdn'),
    (('network',), {'source': 'from-answer', 'cidr': '192.0.2.10/24', 'gateway': '192.0.2.1',
                    'dns': '192.0.2.53', 'filter': {'ID_NET_NAME': 'eno1"\nsource = "x'}}, 'network.filter'),
    (('network',), {'source': 'from-answer', 'cidr': '192.0.2.10/24', 'gateway': '192.0.2.1',
                    'dns': '192.0.2.53', 'filter': {'ID_NET_NAME': 'eno\x001'}}, 'network.filter'),
    (('disk',), {'filesystem': 'ext4', 'filter': {'ID_SERIAL': 'S3Z\n[first-boot]'}}, 'disk.filter'),
    (('disk',), {'filesystem': 'ext4', 'filter': {'ID_SERIAL': 'S3Z"'}}, 'disk.filter'),
    (('global', 'root_ssh_keys'), ['ssh-ed25519 AAAA\nssh-rsa AAAB'], 'global.root_ssh_keys'),
    (('global', 'root_ssh_keys'), ['ssh-ed25519 AAAA \x00'], 'global.root_ssh_keys'),
    (('global', 'root_ssh_keys'), ['ssh-ed25519 AAAA"B'], 'global.root_ssh_keys'),
])
def test_control_characters_and_quotes_become_field_errors(api, seed, path, value, key):
    f = copy.deepcopy(FIELDS)
    _set(f, path, value)
    body = _compose(_admin(api, seed), f)
    assert body['valid'] is False
    assert key in body['field_errors'], body
    assert body['answer'] == '', 'nothing half-built goes back'


@pytest.mark.parametrize('path,value,key', [
    (('global', 'keyboard'), 'xx', 'global.keyboard'),
    (('global', 'country'), 'DE', 'global.country'),
    (('global', 'timezone'), 'Etc/UTC', 'global.timezone'),
    (('global', 'mailto'), 'mail@example.invalid', 'global.mailto'),
    (('global', 'fqdn'), '123.example.com', 'global.fqdn'),
    (('global', 'fqdn'), 'pve01', 'global.fqdn'),
    (('global', 'fqdn'), {'source': 'from-magic'}, 'global.fqdn'),
    (('global', 'root_password_hashed'), '$6$...replace me...', 'global.root_password_hashed'),
    (('global', 'root_password_hashed'), HASHED + '\n', 'global.root_password_hashed'),
    (('global', 'root_password_hashed'), '', 'global.root_password_hashed'),
    (('global', 'root_ssh_keys'), 'ssh-ed25519 AAAA', 'global.root_ssh_keys'),
    (('network', 'source'), 'magic', 'network.source'),
    (('network',), {'source': 'from-answer', 'cidr': '192.0.2.10', 'gateway': '192.0.2.1',
                    'dns': '192.0.2.53', 'filter': {'ID_NET_NAME': 'eno1'}}, 'network.cidr'),
    (('network',), {'source': 'from-answer', 'cidr': '192.0.2.10/24', 'gateway': 'fe80::1%eth0',
                    'dns': '192.0.2.53', 'filter': {'ID_NET_NAME': 'eno1'}}, 'network.gateway'),
    (('network',), {'source': 'from-answer', 'cidr': '192.0.2.10/24', 'gateway': '192.0.2.1',
                    'dns': '192.0.2.53, 192.0.2.54', 'filter': {'ID_NET_NAME': 'eno1'}}, 'network.dns'),
    (('network',), {'source': 'from-answer', 'cidr': '192.0.2.10/24', 'gateway': '192.0.2.1',
                    'dns': '192.0.2.53', 'filter': {'ID_NET_NAME_MAC': 'e4:3d:1a:fa:37:9a'}}, 'network.filter'),
    (('network',), {'source': 'from-answer', 'cidr': '192.0.2.10/24', 'gateway': '192.0.2.1',
                    'dns': '192.0.2.53'}, 'network.filter'),
    (('network',), {'source': 'from-answer', 'cidr': '192.0.2.10/24', 'gateway': '192.0.2.1',
                    'dns': '192.0.2.53', 'filter': {'ID_NET_NAME': 'eno1', 'ID_NET_NAME_MAC': '*e43d1afa379a'}},
     'network.filter'),
    (('disk',), {'filesystem': 'zfs', 'disk_list': ['sda', 'sdb']}, 'disk.raid'),
    (('disk',), {'filesystem': 'zfs', 'raid': 'raid5', 'disk_list': ['sda', 'sdb']}, 'disk.raid'),
    (('disk',), {'filesystem': 'zfs', 'raid': 'raid1', 'disk_list': ['sda']}, 'disk.disk_list'),
    (('disk',), {'filesystem': 'btrfs', 'raid': 'raid10', 'disk_list': ['a', 'b', 'c', 'd', 'e']}, 'disk.disk_list'),
    (('disk',), {'filesystem': 'ext4', 'disk_list': ['sda', 'sdb']}, 'disk.disk_list'),
    (('disk',), {'filesystem': 'zfs', 'raid': 'raid1', 'disk_list': ['sda', 'sda']}, 'disk.disk_list'),
    (('disk',), {'filesystem': 'ext4', 'disk_list': ['sda'], 'filter': {'ID_SERIAL': '*'}}, 'disk.disk_list'),
    (('disk',), {'filesystem': 'ext4'}, 'disk.disk_list'),
    (('disk',), {'filesystem': 'ntfs', 'disk_list': ['sda']}, 'disk.filesystem'),
])
def test_a_bad_value_is_reported_against_its_field(api, seed, path, value, key):
    f = copy.deepcopy(FIELDS)
    _set(f, path, value)
    body = _compose(_admin(api, seed), f)
    assert body['valid'] is False
    assert key in body['field_errors'], body
    assert body['errors'], 'the general error list is not empty while valid is False'


@pytest.mark.parametrize('where', ['top', 'global', 'network', 'fqdn'])
@pytest.mark.parametrize('key', ['root_password', 'root-password'])
def test_a_clear_text_password_is_refused_outright(api, seed, where, key):
    """Plain text only ever goes to /password-hash, so it can never end up in a
    rendered file, a stored profile or a request log line of this route."""
    f = copy.deepcopy(FIELDS)
    if where == 'fqdn':
        f['global']['fqdn'] = {'source': 'from-dhcp', key: 'hunter2-in-the-rack'}
    else:
        (f if where == 'top' else f[where])[key] = 'hunter2-in-the-rack'
    r = _admin(api, seed).post('/api/auto-install/compose', json={'fields': f})
    assert r.status_code == 400, r.data
    assert 'password-hash' in r.get_json()['error']
    assert b'hunter2' not in r.data


@pytest.mark.parametrize('path,value,name', [
    (('first_boot',), {'source': 'from-url'}, 'first_boot'),
    (('global', 'subscription_key'), 'pve2c-0123456789', 'subscription_key'),
    (('global', 'root-password-hashed'), HASHED, 'root-password-hashed'),
    (('network', 'interface_name_pinning'), {'enabled': True}, 'interface_name_pinning'),
    (('disk', 'zfs_ashift'), 12, 'zfs_ashift'),
    (('disk', 'filter'), {'ID_VENDOR': 'ATA'}, 'ID_VENDOR'),
    (('global', 'fqdn'), {'source': 'from-dhcp', 'hostname': 'x'}, 'hostname'),
])
def test_an_unknown_field_is_refused_by_name(api, seed, path, value, name):
    f = copy.deepcopy(FIELDS)
    _set(f, path, value)
    r = _admin(api, seed).post('/api/auto-install/compose', json={'fields': f})
    assert r.status_code == 400, r.data
    assert name in r.get_json()['error']


@pytest.mark.parametrize('body', [None, {}, {'fields': 'x'}, {'fields': {'global': []}}, ['fields']])
def test_a_body_that_is_not_the_shape_is_a_400(api, seed, body):
    r = _admin(api, seed).post('/api/auto-install/compose', json=body)
    assert r.status_code == 400, r.data


def test_compose_stores_nothing(api, seed):
    c = _admin(api, seed)
    assert _compose(c, FIELDS)['valid'] is True
    assert c.get('/api/auto-install/profiles').get_json()['profiles'] == []


def test_compose_needs_the_manage_permission(api, seed):
    r = _viewer(api, seed).post('/api/auto-install/compose', json={'fields': FIELDS})
    assert r.status_code == 403


def test_a_composed_file_saves_and_serves(api, seed):
    """The wizard saves what compose showed through the normal create call."""
    c = _admin(api, seed)
    answer = _compose(c, FIELDS)['answer']
    created = _create(c, answer=answer)
    served = _fetch(api, created['token'])
    assert served.status_code == 200, served.data
    parsed = tomllib.loads(served.data.decode())
    assert parsed['global']['root-password-hashed'] == HASHED
    assert 'url' in parsed['post-installation-webhook']


# --- who sees the page -------------------------------------------------------------------

def _flag(api, user):
    body = api.as_user(user).get('/api/auth/check').get_json()
    return body['user']['autoinstall_access']


def test_the_flag_follows_the_same_rule_as_the_routes(api, seed):
    seed.tenant('acme', ['cluster_acme'])
    seed.tenant('globex', ['cluster_globex'])
    both = ['autoinstall.view', 'autoinstall.manage']
    cases = [
        (seed.user('root', role='admin'), 'manage'),
        # admin globally, mapped down to viewer inside its own tenant: the gate
        # refuses it, so the page must not be offered either
        (seed.user('capped', role='admin', tenant_id='acme',
                   tenant_permissions={'acme': {'role': 'viewer', 'extra': both}}), ''),
        (seed.user('watcher', role='viewer', permissions=['autoinstall.view']), 'view'),
        (seed.user('ops', role='user', permissions=both), 'manage'),
        (seed.user('globex_admin', role='user', tenant_id='globex', permissions=both), ''),
        (seed.user('nobody', role='user'), ''),
        # manage does not imply view, and the list route needs view
        (seed.user('manage_only', role='user', permissions=['autoinstall.manage']), ''),
    ]
    for user, expected in cases:
        assert _flag(api, user) == expected, user['username']
        # and what the flag promises holds at the routes
        status = api.as_user(user).get('/api/auto-install/profiles').status_code
        assert (status == 200) == bool(expected), (user['username'], status)


def test_the_flag_fails_closed(api, seed, monkeypatch):
    import pegaprox.utils.rbac as rbac
    admin = seed.user('root', role='admin')

    def broken(*a, **k):
        raise RuntimeError('tenant table unreadable')
    monkeypatch.setattr(rbac, 'get_user_clusters', broken)
    assert _flag(api, admin) == ''


@pytest.mark.parametrize('role,perms,expected', [
    ('admin', [], 'manage'),
    ('viewer', ['autoinstall.view'], 'view'),
    ('user', [], ''),
])
def test_the_login_answer_carries_the_flag(api, db, tmp_path, monkeypatch, role, perms, expected):
    import pegaprox.utils.auth as authmod
    from pegaprox.utils.auth import hash_password
    marker = tmp_path / '.admin_initialized'
    marker.write_text('x')
    monkeypatch.setattr(authmod, 'ADMIN_INITIALIZED_FILE', str(marker))
    salt, pw_hash = hash_password('C0rrect!horse9')
    db.save_user('ops', {'password_salt': salt, 'password_hash': pw_hash, 'role': role,
                         'enabled': True, 'auth_source': 'local', 'permissions': perms})
    r = api.anon().post('/api/auth/login', json={'username': 'ops', 'password': 'C0rrect!horse9'})
    assert r.status_code == 200, r.data
    assert r.get_json()['user']['autoinstall_access'] == expected


# --- noise and logs -----------------------------------------------------------------

def test_refusals_are_audited_but_not_flooded(api, seed):
    import pegaprox.api.auto_install as ai
    ai._refusals.clear()
    _create(_admin(api, seed))
    for _ in range(25):
        _fetch(api, 'pgxai_guess')
    from pegaprox.core.db import get_db
    rows = get_db().conn.cursor().execute(
        "SELECT severity FROM audit_log WHERE action = 'autoinstall.fetch_refused'").fetchall()
    assert 1 <= len(rows) <= ai._REFUSAL_AUDIT_MAX
    assert all(r['severity'] != 'critical' for r in rows)


def test_a_token_in_the_query_string_is_blanked_in_the_access_log():
    from pegaprox.utils.sanitization import redact_request_line
    line = '10.0.0.5 - - [ts] "POST /api/auto-install/answer?token=pgxai_live&via=dmz HTTP/1.1" 200 512 0.01'
    out = redact_request_line(line)
    assert 'pgxai_live' not in out
    assert 'via=dmz' in out and '/api/auto-install/answer' in out


def test_the_spec_says_which_token_the_installer_endpoints_take(api):
    from pegaprox.cli.gen_openapi import build
    paths = build(api.app)
    for path in ('/api/auto-install/answer', '/api/auto-install/progress'):
        op = paths[path]['post']
        assert op['security'] == [{'installToken': []}], (path, op.get('security'))


def test_a_typo_in_an_optional_key_is_flagged(api, seed):
    """The installer refuses unknown keys; better to hear it here than at the rack."""
    answer = ANSWER.replace('timezone = "Europe/Berlin"', 'timezone = "Europe/Berlin"\nreboot-on-eror = true')
    body = _admin(api, seed).post('/api/auto-install/validate', json={'answer': answer}).get_json()
    assert any('reboot-on-eror' in w for w in body['warnings']), body['warnings']



@pytest.mark.parametrize('name', ['/dev/disk/by-id/ata-SAMSUNG_X', 'disk/by-path/pci-0000:00:17.0-ata-1'])
def test_a_by_id_path_is_not_a_disk_name(api, seed, name):
    """disk-list takes the installer's raw disk names. A by-* path matches nothing and
    the install stops at the rack, so neither the editor nor the wizard lets it through."""
    c = _admin(api, seed)
    answer = ANSWER.replace('disk-list = ["sda"]', f'disk-list = ["{name}"]')
    body = c.post('/api/auto-install/validate', json={'answer': answer}).get_json()
    assert body['valid'] is False and any('by-' in e for e in body['errors']), body
    assert c.post('/api/auto-install/validate', json={'answer': ANSWER.replace(
        'disk-list = ["sda"]', 'disk-list = ["cciss/c0d0"]')}).get_json()['valid'] is True
