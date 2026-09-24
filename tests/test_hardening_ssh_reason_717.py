"""#717 — the compliance dashboard has to say why it is empty.

Reported as "compliance dashboard wont load". It loads; every node in it answers
502 "SSH to <node> failed" and the panel renders the string "err 502" beside each
one, which reads as broken software rather than as a cluster that has no SSH
credentials. Reproduced here on Testi: an API-token cluster, three nodes, three
identical failures, no explanation.

The route now says which of the known reasons it was, and the frontend picks the
sentence so it lands in the user's language. Note the API-token case in
particular: config.pass_ holds the TOKEN SECRET when a cluster authenticates that
way, so "a password is stored" was true and the first version of this reported a
connection failure on exactly the setup the ticket was about. NS
"""
import pytest

CLUSTER = 'cluster_1'
NODE = 'pve1'


def _hardening(client, profile='cis-l1'):
    return client.get(f'/api/clusters/{CLUSTER}/nodes/{NODE}/hardening?profile={profile}')


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


def _mgr(api, **kw):
    """A fake manager carrying the REAL ssh_diagnose, so these drive the shipped
    classification and not a stand-in for it."""
    from pegaprox.core.manager import PegaProxManager
    m = api.make_fake_manager(CLUSTER, check_node_hardening=None)
    m.is_connected = True
    m._is_node_blocked = lambda n: (False, 0)
    # MK Sep 2026 — api_token=True used to set only the _using_api_token flag. That flag
    # is ALSO true for a cluster we minted a token for ourselves on first connect (#110),
    # which keeps its real password for SSH — so it never distinguished the setup this
    # file is about. In production the token id goes in the USERNAME (root@pam!tokenid)
    # and the secret in the password field; that is what makes pass_ the secret, and what
    # ssh_diagnose keys on. Say it here the way the cluster actually says it.
    m._using_api_token = kw.get('api_token', False)
    if kw.get('api_token'):
        m.config.user = kw.get('user', 'root@pam!pegaprox')
    elif 'user' in kw:
        m.config.user = kw['user']
    m.config.ssh_key = kw.get('ssh_key', '')
    m.config.pass_ = kw.get('password', '')
    m.ssh_diagnose = PegaProxManager.ssh_diagnose.__get__(m, PegaProxManager)
    return api.set_manager(CLUSTER, m)


def test_a_manager_without_the_probe_still_gets_an_answer(api, admin):
    """The error path must not be the thing that raises — before this it unpacked
    whatever came back and a manager lacking the method turned a 502 into a 500."""
    m = api.make_fake_manager(CLUSTER, check_node_hardening=None)
    m.is_connected = True
    del m.ssh_diagnose
    api.set_manager(CLUSTER, m)

    r = _hardening(admin)

    assert r.status_code == 502
    assert r.get_json()['code'] == 'SSH_FAILED'


def test_a_token_only_cluster_is_told_it_has_no_ssh_credentials(api, admin):
    """The reported setup: API token, no key, no password."""
    _mgr(api, api_token=True, password='the-token-secret')

    r = _hardening(admin)

    assert r.status_code == 412
    body = r.get_json()
    assert body['code'] == 'SSH_NO_CREDENTIALS'
    assert body['cluster_wide'] is True, 'the dashboard has to know it may stop asking'
    assert 'hint' in body and body['hint']


def test_the_token_secret_is_not_mistaken_for_an_ssh_password(api, admin):
    """config.pass_ is the token secret under API-token auth. Counting it as an SSH
    credential is what made the first version answer "connection failed" here."""
    _mgr(api, api_token=True, password='the-token-secret')

    assert _hardening(admin).get_json()['code'] == 'SSH_NO_CREDENTIALS'


def test_a_real_password_is_a_credential(api, admin):
    """The other direction — do not tell someone who configured a password that they
    have none. Then it really is a connection problem."""
    _mgr(api, api_token=False, password='an-actual-ssh-password')

    r = _hardening(admin)

    assert r.status_code == 502
    assert r.get_json()['code'] == 'SSH_FAILED'
    assert r.get_json()['cluster_wide'] is False


def test_an_ssh_key_is_a_credential(api, admin):
    _mgr(api, api_token=True, ssh_key='-----BEGIN OPENSSH PRIVATE KEY-----')

    assert _hardening(admin).get_json()['code'] == 'SSH_FAILED'


def test_a_node_in_backoff_says_so_instead_of_blaming_credentials(api, admin):
    m = _mgr(api, api_token=True, password='tok')
    m._is_node_blocked = lambda n: (True, 42)

    r = _hardening(admin)

    assert r.status_code == 503
    assert r.get_json()['code'] == 'NODE_BACKOFF'
    assert '42' in r.get_json()['error']


def test_every_code_the_route_can_return_has_a_hint(api, admin):
    from pegaprox.api.reports import _SSH_ERRORS

    for code, (status, hint) in _SSH_ERRORS.items():
        assert 100 <= status < 600, code
        assert hint and hint.endswith('.'), code


def test_the_frontend_translates_the_code_rather_than_the_english_body():
    """The route's error/hint are English. They are the fallback; the sentence the
    operator reads is chosen from the code so it follows their language."""
    dash = open('web/src/dashboard.js', encoding='utf-8').read()

    assert 'const sshReason = (info) =>' in dash
    for code in ('SSH_NO_CREDENTIALS', 'NODE_BACKOFF', 'SSH_FAILED'):
        assert code in dash, code
    assert "|| [info?.error, info?.hint]" in dash, 'no fallback for an unknown code'


def test_the_dashboard_stops_after_a_cluster_wide_reason():
    """Every node would answer the same thing, one second each. On a 100-node estate
    that is 100 seconds of waiting to render one sentence."""
    dash = open('web/src/dashboard.js', encoding='utf-8').read()
    fan = dash[dash.index('const fetchCluster = async (cluster)'):][:2600]

    assert 'info.clusterWide' in fan
    assert '_cluster' in fan


@pytest.mark.parametrize('key', ['unavailable', 'complianceUnavailable',
                                 'sshNoCredentials', 'sshNoCredentialsHint',
                                 'sshNodeBackoff', 'sshNodeBackoffHint',
                                 'sshFailed', 'sshFailedHint'])
def test_the_new_strings_exist_in_every_language(key):
    import re
    src = open('web/src/translations.js', encoding='utf-8').read()
    starts = {m.group(1): m.start()
              for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M)}
    assert len(starts) == 9, sorted(starts)

    order = sorted(starts.items(), key=lambda kv: kv[1])
    for i, (lang, pos) in enumerate(order):
        end = order[i + 1][1] if i + 1 < len(order) else len(src)
        assert re.search(r'^ +%s: ' % key, src[pos:end], re.M), f'{key} missing from {lang}'


def test_a_cluster_whose_token_we_minted_still_counts_its_password(api, admin):
    """MK Sep 2026 — the other half of the same distinction, and a regression this file
    would not have caught. #110 mints an API token on first connect for a cluster the
    operator gave a username and password, sets _using_api_token, and keeps the password
    for SSH. Reading the flag as "pass_ is a token secret" told those clusters they had no
    SSH credentials at all — the most common setup there is."""
    _mgr(api, api_token=True, user='root@pam', password='realpassword')

    body = _hardening(admin).get_json()
    assert body.get('code') != 'SSH_NO_CREDENTIALS', \
        "a minted token does not make the account password disappear"
