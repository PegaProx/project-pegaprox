"""The alert channels are one list for the whole installation; three reads of it were not
treated that way.

* POST /api/alert-channels/<id>/test sent the test notification for any alert.manage
  holder, while create, edit and delete of the same list need admin.settings. A tenant
  delegate could ring every other tenant's channel on demand (#989).
* The masked list hid url and token but returned an ntfy topic as it was. Without a
  token the topic is the whole capability: whoever knows it reads and posts the feed
  (#993). The same topic typed into the url showed through the 24+6 character mask.
* /api/alerts/diagnostics filtered the rules to the caller's clusters but still counted
  every rule of the installation, and listed every channel and the number of mail
  recipients to a caller confined to some clusters.
"""
import pytest


TOPIC = 'pp-ops-7f3a9c41'
URL_TOPIC = 'pp-feed-0d9e22b7'


@pytest.fixture
def store(monkeypatch):
    data = {
        'alert_webhooks': [
            {'id': 'slack1', 'name': 'ops', 'type': 'slack',
             'url': 'https://hooks.example/services/T0/B0/SECRETSECRET', 'enabled': True},
            {'id': 'ntfy1', 'name': 'phones', 'type': 'ntfy',
             'url': 'https://ntfy.sh', 'topic': TOPIC, 'enabled': True},
            {'id': 'ntfy2', 'name': 'pager', 'type': 'ntfy',
             'url': f'https://ntfy.example/{URL_TOPIC}', 'enabled': True},
        ],
        'alert_email_recipients': ['a@example.com', 'b@example.com', 'c@example.com'],
    }
    import pegaprox.api.helpers as helpers_mod
    monkeypatch.setattr(helpers_mod, 'load_server_settings', lambda: data)
    monkeypatch.setattr(helpers_mod, 'save_server_settings', lambda s: data.update(s))
    return data


@pytest.fixture
def sent(monkeypatch):
    calls = []
    import pegaprox.utils.webhooks as wh
    monkeypatch.setattr(wh, 'send_to_channel', lambda ch, alert: (calls.append(ch['id']), (True, 'ok'))[1])
    return calls


def _delegate(seed):
    seed.tenant('acme', clusters=['cluster_1'])
    return seed.user('delegate', role='user', tenant_id='acme', permissions=['alert.manage'])


def _settings_admin(seed):
    seed.tenant('acme', clusters=['cluster_1'])
    return seed.user('opsadmin', role='user', tenant_id='acme',
                     permissions=['alert.manage', 'admin.settings'])


# --- the test notification (#989) ------------------------------------------------------

def test_a_delegate_cannot_fire_the_test_at_a_channel(api, db, seed, store, sent):
    r = api.as_user(_delegate(seed)).post('/api/alert-channels/slack1/test')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert sent == [], 'the test notification went out for a tenant delegate'


@pytest.mark.parametrize('who', ['settings_admin', 'admin'])
def test_whoever_manages_the_channels_still_tests_them(api, db, seed, store, sent, who):
    u = _settings_admin(seed) if who == 'settings_admin' else seed.user('root', role='admin')
    r = api.as_user(u).post('/api/alert-channels/slack1/test')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['success'] is True and sent == ['slack1']


# --- the masked list (#993) ------------------------------------------------------------

def test_the_masked_list_keeps_an_ntfy_topic_to_itself(api, db, seed, store):
    r = api.as_user(_delegate(seed)).get('/api/alert-channels')
    assert r.status_code == 200, r.get_data(as_text=True)
    text = r.get_data(as_text=True)
    assert TOPIC not in text, 'the ntfy topic came back in clear'
    assert URL_TOPIC[:8] not in text and URL_TOPIC[-6:] not in text, 'the topic in the url showed through'
    rows = {c['id']: c for c in r.get_json()}
    assert rows['ntfy1']['topic'] == '********'
    assert rows['ntfy2']['url'] == 'https://ntfy.example/…'
    # what the list is for stays: which channel, what kind, on or off
    assert (rows['ntfy1']['name'], rows['ntfy1']['type'], rows['ntfy1']['enabled']) == ('phones', 'ntfy', True)
    assert rows['slack1']['url'].startswith('https://hooks.example/')


def test_the_settings_admin_still_reads_and_keeps_the_topic(api, db, seed, store):
    c = api.as_user(_settings_admin(seed))
    full = {ch['id']: ch for ch in c.get('/api/alert-channels?full=1').get_json()}
    assert full['ntfy1']['topic'] == TOPIC
    # an edit that sends the masked row back renames it and leaves the topic alone
    masked = {ch['id']: ch for ch in c.get('/api/alert-channels').get_json()}['ntfy1']
    r = c.put('/api/alert-channels/ntfy1', json=dict(masked, name='phones 2'))
    assert r.status_code == 200, r.get_data(as_text=True)
    kept = next(ch for ch in store['alert_webhooks'] if ch['id'] == 'ntfy1')
    assert (kept['name'], kept['topic'], kept['url']) == ('phones 2', TOPIC, 'https://ntfy.sh')
    # and a new topic is taken
    assert c.put('/api/alert-channels/ntfy1', json={'topic': 'pp-new'}).status_code == 200
    assert next(ch for ch in store['alert_webhooks'] if ch['id'] == 'ntfy1')['topic'] == 'pp-new'


# --- the diagnostics -------------------------------------------------------------------

@pytest.fixture
def rules(monkeypatch):
    import pegaprox.background.alerts as A
    cfg = {'enabled': True, 'alerts': [
        {'id': 'r1', 'name': 'mine', 'cluster_id': 'cluster_1', 'metric': 'cpu'},
        {'id': 'r2', 'name': 'theirs', 'cluster_id': 'cluster_2', 'metric': 'cpu'},
        {'id': 'r3', 'name': 'theirs too', 'cluster_id': 'cluster_2', 'metric': 'mem'},
    ]}
    monkeypatch.setattr(A, 'load_alerts_config', lambda: cfg)
    return cfg


def test_a_confined_caller_gets_its_own_rule_count_and_nothing_global(api, db, seed, store, rules):
    seed.tenant('other', clusters=['cluster_2'])
    r = api.as_user(_delegate(seed)).get('/api/alerts/diagnostics')
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert [a['id'] for a in body['alerts']] == ['r1']
    assert body['alerts_in_config'] == 1, 'the count was the whole installation\'s'
    assert body['webhook_channels'] is None and body['email_recipients'] is None
    assert 'phones' not in r.get_data(as_text=True)


def test_an_admin_still_sees_the_whole_installation(api, db, seed, store, rules):
    body = api.as_user(seed.user('root', role='admin')).get('/api/alerts/diagnostics').get_json()
    assert body['alerts_in_config'] == 3
    assert body['email_recipients'] == 3
    assert sorted(c['id'] for c in body['webhook_channels']) == ['ntfy1', 'ntfy2', 'slack1']
