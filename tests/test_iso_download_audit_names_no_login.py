"""The ISO download by URL names the source in its audit line without its login.

A private mirror is given as http://user:password@host/..., or with a token in the query.
The node needs the URL as typed and still gets it. The audit line used to carry the first
50 characters of it, and the per-cluster trail is read with cluster.view; it now names
the host and the file, not the login or the token.
"""
import ipaddress
from unittest.mock import MagicMock

import pytest

import pegaprox.utils.url_security as url_security

CID = 'cluster_1'
SECRET = 'Mirr0r-pw'
TOKEN = 'tok3n-value'
MIRROR = 'mirror.example'


def _fake_cluster(api):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = '127.0.0.1', 8006
    m.config.name = 'lab'
    sess = MagicMock()
    sess.post.return_value = MagicMock(status_code=200, json=MagicMock(return_value={'data': 'UPID:dl'}))
    # the status poll finds the task done at once
    sess.get.return_value = MagicMock(status_code=200, json=MagicMock(
        return_value={'data': {'status': 'stopped', 'exitstatus': 'OK'}}))
    m._create_session.return_value = sess
    api.set_manager(CID, m)
    return sess


def test_the_node_gets_the_login_and_the_trail_does_not(api, seed, monkeypatch):
    monkeypatch.setattr(url_security, '_resolve_all', lambda host: [ipaddress.ip_address('93.184.216.34')])
    sess = _fake_cluster(api)
    writer = api.as_user(seed.user('opsuser', role='user'))
    url = f'http://mirroruser:{SECRET}@{MIRROR}/isos/debian.iso?token={TOKEN}'
    r = writer.post(f'/api/clusters/{CID}/datastores/local/download-url',
                    json={'url': url, 'filename': 'debian.iso', 'node': 'pve1'})
    assert r.status_code == 200, r.get_data(as_text=True)
    sent = sess.post.call_args.kwargs['data']['url']
    assert sent == f'http://mirroruser:{SECRET}@93.184.216.34/isos/debian.iso?token={TOKEN}', sent

    viewer = api.as_user(seed.user('vera', role='viewer'))
    r = viewer.get(f'/api/clusters/{CID}/audit?limit=50')
    assert r.status_code == 200, r.get_data(as_text=True)
    rows = [e for e in r.get_json() if e['action'] == 'storage.download']
    assert rows, r.get_json()
    details = rows[0]['details']
    assert 'Started download: debian.iso from http://' in details and '93.184.216.34' in details
    for part in (SECRET, 'mirroruser', TOKEN):
        assert part not in details, details


# The login is taken off by structure: the host follows the netloc's last '@', and a blank
# does not end it. Each part of the password stays out, with a name or an IP as the host.
@pytest.mark.parametrize('password,parts', [
    ('p@ssw0rd', ('p@ssw0rd', 'ssw0rd')),
    ('Sec r3t', ('Sec r3t', 'Sec', 'r3t')),
])
@pytest.mark.parametrize('host', [MIRROR, '93.184.216.34'])
def test_a_login_with_an_at_sign_or_a_blank_stays_out(api, seed, monkeypatch, password, parts, host):
    monkeypatch.setattr(url_security, '_resolve_all', lambda h: [ipaddress.ip_address('93.184.216.34')])
    sess = _fake_cluster(api)
    writer = api.as_user(seed.user('opsuser', role='user'))
    url = f'http://mirroruser:{password}@{host}/isos/debian.iso'
    r = writer.post(f'/api/clusters/{CID}/datastores/local/download-url',
                    json={'url': url, 'filename': 'debian.iso', 'node': 'pve1'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert sess.post.call_args.kwargs['data']['url'] == f'http://mirroruser:{password}@93.184.216.34/isos/debian.iso'

    viewer = api.as_user(seed.user('vera', role='viewer'))
    r = viewer.get(f'/api/clusters/{CID}/audit?limit=50')
    assert r.status_code == 200, r.get_data(as_text=True)
    rows = [e for e in r.get_json() if e['action'] == 'storage.download']
    assert rows, r.get_json()
    details = rows[0]['details']
    assert details.startswith('Started download: debian.iso from http://93.184.216.34/isos/'), details
    for part in parts + ('mirroruser',):
        assert part not in details, details
