"""The SMBIOS auto-configurator settings of a cluster stay what was saved.

PUT rebuilt the whole dict from its own defaults ('Virtual Machine', 'PVE8') while GET and
the deploy routes fell back to others ('PegaProxManagment', 'v1'), and 'enabled' went back
to False on every save that did not send it. A form that saved one field, or the deploy
flow that saved four, so moved the rest from one set of defaults to the other. Now there
is one set, a save keeps what it leaves out, and the nodes get what the form showed.

MK Nov 2026
"""
import pytest

import pegaprox.api.nodes as nodes

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/smbios-autoconfig'
DEFAULTS = {'enabled': False, 'manufacturer': 'Proxmox', 'product': 'PegaProxManagment',
            'version': 'v1', 'family': 'ProxmoxVE'}
SAVED = {'enabled': True, 'manufacturer': 'Acme', 'product': 'Box 1', 'version': '2.0', 'family': 'Lab'}


@pytest.fixture
def env(api, seed):
    seed.db.save_cluster(CID, {'name': CID, 'host': 'pve', 'user': 'root@pam', 'pass': 'x'})
    m = api.make_fake_manager(CID)
    m.config.name = CID
    m.config.smbios_autoconfig = {}
    api.set_manager(CID, m)
    env = type('Env', (), {})()
    env.mgr, env.db = m, seed.db
    env.client = api.as_user(seed.user('adm', role='admin'))
    return env


def _get(env):
    r = env.client.get(URL)
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def _stored(env):
    return env.db.get_cluster(CID)['smbios_autoconfig']


def test_a_first_save_of_one_field_keeps_the_others_the_form_showed(env):
    shown = _get(env)
    assert shown == DEFAULTS
    r = env.client.put(URL, json={'manufacturer': 'Acme'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _get(env) == dict(shown, manufacturer='Acme')
    assert _stored(env) == dict(shown, manufacturer='Acme')


def test_the_deploy_flow_save_keeps_enabled(env):
    """the deploy flow saves the four text fields and no 'enabled'"""
    env.mgr.config.smbios_autoconfig = dict(SAVED)
    body = {k: SAVED[k] for k in ('manufacturer', 'product', 'version', 'family')}
    assert env.client.put(URL, json=dict(body, product='Box 2')).status_code == 200
    assert _get(env) == dict(SAVED, product='Box 2')
    assert env.client.put(URL, json={'enabled': False}).status_code == 200
    assert _get(env) == dict(SAVED, product='Box 2', enabled=False)


@pytest.mark.parametrize('body', [
    {'enabled': 'yes'},
    {'enabled': 1},
    {'manufacturer': 5},
    {'product': None},
    {'family': ['Lab']},
    {'version': 'v1', 'enabled': 'false'},
    # the value check holds to the end of the string
    {'manufacturer': 'Acme\n'},
])
def test_a_refused_value_changes_nothing(env, body):
    env.mgr.config.smbios_autoconfig = dict(SAVED)
    r = env.client.put(URL, json=body)
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json().get('error')
    assert _get(env) == SAVED


class _Out:
    def __init__(self, text):
        self._blocks = [text.encode(), b'']
        self.channel = type('Chan', (), {'recv_exit_status': lambda self: 0})()

    def read(self, n=-1):
        return self._blocks.pop(0) if self._blocks else b''


class _Ssh:
    def exec_command(self, cmd, timeout=None):
        return None, _Out('active'), _Out('')

    def close(self):
        pass


def _deploy(env, monkeypatch, route):
    written = {}
    monkeypatch.setattr(nodes, '_ssh_write_file', lambda ssh, path, content, mode=None: written.update({path: content}))
    monkeypatch.setattr(nodes, '_ssh_run_checked', lambda ssh, cmd, timeout=30: ('', ''))
    env.mgr._get_node_ip.return_value = '10.0.0.11'
    env.mgr._ssh_connect.return_value = _Ssh()
    status = env.mgr._create_session.return_value.get.return_value
    status.status_code = 200
    status.json.return_value = {'data': [{'type': 'node', 'name': 'pve1'}]}
    path = f'/api/clusters/{CID}/nodes/pve1/smbios-autoconfig/deploy' if route == 'one' else URL + '/deploy-all'
    r = env.client.post(path)
    assert r.status_code == 200 and r.get_json()['success'], r.get_data(as_text=True)
    return written['/opt/pegaprox-smbios-autoconfig.py']


@pytest.mark.parametrize('route', ['one', 'all'])
def test_the_nodes_get_what_the_form_showed(env, monkeypatch, route):
    shown = _get(env)
    assert env.client.put(URL, json={'manufacturer': 'Acme Corp.'}).status_code == 200
    script = _deploy(env, monkeypatch, route)
    assert 'MANUFACTURER = "Acme Corp."' in script
    for key in ('product', 'version', 'family'):
        assert f'{key.upper()} = "{shown[key]}"' in script, key
