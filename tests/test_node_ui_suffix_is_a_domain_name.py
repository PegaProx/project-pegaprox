"""The node UI suffix of a cluster is a domain name or nothing.

The UI appends it to a node name for the "Open in Proxmox" link (pve01 + example.local is
https://pve01.example.local:8006). The cluster routes stored whatever came in: a '/', '@'
or ':' moved the link to another host, and a number or an object was taken live, broke the
link builder in the browser and made every later save of that cluster row fail. Add,
re-configure, PUT and PATCH now take a string of DNS labels (letters, digits, inner
hyphens, separated by dots) or an empty one, and answer 400 for anything else before any
field of the request is applied.
"""
import types

import pytest

import pegaprox.api.clusters as clusters_api
import pegaprox.core.manager as mgrmod
from pegaprox.models.tasks import PegaProxConfig

STORED = 'lab.example'

BAD = ['x@evil.example', 'evil.example/', 'evil.example/#', 'pve.example:8443', 'a b.example',
       '-lead.example', 'trail-.example', 'a..b', 'under_score.example', 'bücher.example',
       'x' * 64 + '.example', ('a' * 60 + '.') * 5, 5, 1.5, True, None, {'a': 1}, ['example']]
# what an operator types, and what is kept of it
GOOD = [('example.local', 'example.local'), ('.example.local', 'example.local'),
        (' Lab-1.Example.COM. ', 'Lab-1.Example.COM'), ('local', 'local'),
        ('xn--bcher-kva.example', 'xn--bcher-kva.example'), ('', '')]


@pytest.fixture
def env(api, seed, monkeypatch):
    monkeypatch.setattr(clusters_api, 'save_config', lambda: True)
    seed.db.save_cluster('c1', dict(name='lab', host='10.40.0.1', user='root@pam', ssl_verification=False,
                                    fallback_hosts=[], ssh_user='', ssh_key='', ssh_port=22,
                                    cluster_type='proxmox', api_port=8006, **{'pass': 'stored-pw'}))
    m = mgrmod.PegaProxManager('c1', PegaProxConfig(seed.db.get_cluster('c1')))
    m.config.node_ui_suffix = STORED
    m.is_connected = True
    api.set_manager('c1', m)
    admin = seed.user('root', role='admin')
    return types.SimpleNamespace(mgr=m, c=api.as_user(admin))


EDITS = [('put', '/api/clusters/c1'), ('patch', '/api/clusters/c1/config')]


@pytest.mark.parametrize('method,url', EDITS)
@pytest.mark.parametrize('value', BAD)
def test_an_edit_with_a_suffix_that_is_no_domain_name_is_refused_whole(env, method, url, value):
    r = getattr(env.c, method)(url, json={'node_ui_suffix': value, 'name': 'renamed'})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'node_ui_suffix' in r.get_json()['error']
    assert env.mgr.config.node_ui_suffix == STORED
    assert env.mgr.config.name == 'lab'


@pytest.mark.parametrize('method,url', EDITS)
def test_a_domain_name_is_taken_and_normalised(env, method, url):
    kept = []
    for value, _ in GOOD:
        r = getattr(env.c, method)(url, json={'node_ui_suffix': value})
        assert r.status_code == 200, r.get_data(as_text=True)
        kept.append(env.mgr.config.node_ui_suffix)
    assert kept == [stored for _, stored in GOOD]
    # an edit that does not name the field leaves it as it is
    env.mgr.config.node_ui_suffix = STORED
    assert getattr(env.c, method)(url, json={'name': 'renamed'}).status_code == 200
    assert env.mgr.config.node_ui_suffix == STORED


# --- add and re-configure ------------------------------------------------------------------

@pytest.fixture
def dialed(monkeypatch):
    """The manager add and re-configure build, recorded instead of connected."""
    built = []

    class _Mgr:
        cluster_type = 'proxmox'
        _token_auto_created = False

        def __init__(self, cid, config):
            self.id, self.config = cid, config
            built.append(self)

        def connect_to_proxmox(self):
            return True

        def start(self):
            pass

    monkeypatch.setattr(clusters_api, 'PegaProxManager', _Mgr)
    from pegaprox.core import node_creds
    monkeypatch.setattr(node_creds, 'check_in_background', lambda *a, **k: None)
    return built


def _cluster(**over):
    body = {'name': 'new', 'host': '10.40.0.9', 'user': 'root@pam', 'pass': 'pw'}
    body.update(over)
    return body


@pytest.mark.parametrize('value', ['x@evil.example', 'evil.example/', 5, {'a': 1}])
def test_adding_a_cluster_with_a_bad_suffix_is_refused_before_it_connects(env, dialed, value):
    r = env.c.post('/api/clusters', json=_cluster(node_ui_suffix=value))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'node_ui_suffix' in r.get_json()['error']
    assert dialed == []
    # the same cluster with a domain name goes in
    r = env.c.post('/api/clusters', json=_cluster(node_ui_suffix=' .Example.local. '))
    assert r.status_code == 201, r.get_data(as_text=True)
    assert [m.config.node_ui_suffix for m in dialed] == ['Example.local']


@pytest.fixture
def reconfigure(env, dialed, monkeypatch):
    import pegaprox.utils.auth as authmod
    monkeypatch.setattr(authmod, 'verify_password', lambda *a, **k: True)

    def send(**over):
        body = _cluster(name='lab', host='10.40.0.1', current_password='typed')
        body.update(over)
        return env.c.post('/api/clusters/c1/reconfigure', json=body)
    return send


@pytest.mark.parametrize('value', ['x@evil.example', 'evil.example/', 5, {'a': 1}])
def test_re_configure_with_a_bad_suffix_is_refused_before_it_connects(reconfigure, dialed, env, value):
    r = reconfigure(node_ui_suffix=value)
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'node_ui_suffix' in r.get_json()['error']
    assert dialed == []
    assert clusters_api.cluster_managers['c1'] is env.mgr
    r = reconfigure(node_ui_suffix='example.local.')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [m.config.node_ui_suffix for m in dialed] == ['example.local']


# --- config restore -------------------------------------------------------------------------

_ADMIN_PW = 'Suffix-Admin-pw-7!'
_BACKUP_PW = 'suffix-backup-pw'


def _restore(api, seed, clusters):
    import io
    import json
    import pegaprox.api.settings as settings_api
    from pegaprox.utils.auth import hash_password
    user = seed.user('root', role='admin')
    salt, pw_hash = hash_password(_ADMIN_PW)
    row = seed.db.get_user('root')
    row.update(password_salt=salt, password_hash=pw_hash)
    seed.db.save_user('root', row)
    data = {'version': 'test', 'export_date': '2026-11-01T10:00:00', 'clusters': clusters}
    blob = settings_api._encrypt_backup(json.dumps(data), _BACKUP_PW)
    r = api.as_user(user).post('/api/config/restore', content_type='multipart/form-data',
                               data={'user_password': _ADMIN_PW, 'backup_password': _BACKUP_PW,
                                     'backup_file': (io.BytesIO(blob), 'x.pegabackup')})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


@pytest.mark.parametrize('value', ['x@evil.example/', 'under_score.example', {'a': 1}])
def test_a_restore_keeps_a_suffix_that_is_no_domain_name_out(api, seed, value):
    """The routes refuse it, so a backup does not bring it in either: the cluster is
    restored without one and the result says so. Before, a string went in as it was and
    anything else kept the whole cluster out of the restore."""
    base = dict(name='lab', host='10.40.0.1', user='root@pam', ssl_verification=False,
                fallback_hosts=[], ssh_user='', ssh_port=22, cluster_type='proxmox', api_port=8006,
                **{'pass': 'stored-pw'})
    res = _restore(api, seed, [dict(base, id='bad', node_ui_suffix=value),
                               dict(base, id='good', node_ui_suffix=' .Lab.example. ')])
    stored = {cid: row['node_ui_suffix'] for cid, row in seed.db.get_all_clusters().items()}
    assert stored == {'bad': '', 'good': 'Lab.example'}, res['errors']
    assert res['restored']['clusters'] == 2
    assert [e for e in res['errors'] if 'node_ui_suffix' in e] == [
        'Cluster bad: node_ui_suffix is not a domain name, the node links go without one']
