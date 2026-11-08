"""A login in a custom image URL is used, not shown.

add_custom_template takes any clean http(s) URL, a mirror that wants a login included
(https://user:password@mirror/...). GET /api/templates/catalog is one list for every
signed-in account, across tenants, and handed that URL back as stored. The deploy log,
which the cluster's viewers read, printed the wget command line with it.

The stored URL stays as typed, the node needs it; what is shown says ****@ instead.
"""
import pytest

import pegaprox.api.templates_lib as tpl

LOGIN = 'mirroruser:S3cret-Mirror-77'
URL = f'https://{LOGIN}@10.0.0.20/images/base.qcow2'
SHOWN = 'https://****@10.0.0.20/images/base.qcow2'


def _add(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post('/api/templates/custom', json={'name': 'base', 'image_url': URL})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['template']


def test_the_catalog_shows_no_login(api, seed):
    created = _add(api, seed)
    assert created['image_url'] == SHOWN
    seed.tenant('other', clusters=['cluster_9'])
    reader = api.as_user(seed.user('someone', role='viewer', tenant_id='other'))
    r = reader.get('/api/templates/catalog')
    assert r.status_code == 200
    assert 'S3cret-Mirror-77' not in r.get_data(as_text=True), 'the catalog handed out the mirror login'
    mine = next(t for t in r.get_json()['templates'] if t['id'] == created['id'])
    assert mine['image_url'] == SHOWN


def test_the_stored_url_keeps_its_login_for_the_node(api, seed):
    created = _add(api, seed)
    assert tpl._lookup_template(created['id'])['image_url'] == URL
    # built-in entries and a custom URL without a login read exactly as before
    admin = api.as_user(seed.user('root', role='admin'))
    plain = 'https://10.0.0.20/images/other.qcow2'
    assert admin.post('/api/templates/custom', json={'name': 'other', 'image_url': plain}).status_code == 200
    listed = admin.get('/api/templates/catalog').get_json()['templates']
    assert [t['image_url'] for t in listed[:len(tpl.CATALOG)]] == [c['image_url'] for c in tpl.CATALOG]
    assert next(t for t in listed if t['name'] == 'other')['image_url'] == plain


class _Chan:
    def __init__(self, rc):
        self.rc = rc

    def recv_exit_status(self):
        return self.rc


class _Out:
    def __init__(self, text='', rc=0):
        self.text, self.channel = text, _Chan(rc)


class _Ssh:
    def __init__(self, fail_wget=False):
        self.cmds, self.fail_wget = [], fail_wget

    def exec_command(self, cmd, **kw):
        self.cmds.append(cmd)
        if self.fail_wget and cmd.startswith('wget'):
            return None, _Out('', 4), _Out(f'{URL}: Connection refused', 4)
        return None, _Out(), _Out()

    def close(self):
        pass


@pytest.mark.parametrize('fail', [False, True], ids=['ran', 'wget failed'])
def test_the_deploy_log_shows_no_login(api, seed, monkeypatch, fail):
    import pegaprox.utils.url_security as us
    created = _add(api, seed)
    ssh = _Ssh(fail_wget=fail)
    mgr = api.make_fake_manager('cl_tpl')
    mgr._ssh_connect.return_value = ssh
    mgr._get_node_ip.return_value = '10.0.0.5'
    monkeypatch.setitem(tpl.cluster_managers, 'cl_tpl', mgr)
    logged = []
    monkeypatch.setattr(tpl, '_update_dep', lambda dep_id, **kw: logged.append(kw))
    monkeypatch.setattr(tpl, '_read_capped', lambda f: f.text)
    monkeypatch.setattr(us, 'sanitize_outbound_url', lambda url, **kw: url)

    tpl._run_deploy('d1', 'cl_tpl', 'pve1', created['id'], 'local-lvm', 9201, 'tpl-base')

    wget = next(c for c in ssh.cmds if c.startswith('wget'))
    assert URL in wget, 'the node has to get the URL with its login'
    text = repr(logged)
    assert 'S3cret-Mirror-77' not in text, text
    assert SHOWN in text
    assert logged[-1]['status'] == ('failed' if fail else 'completed')
