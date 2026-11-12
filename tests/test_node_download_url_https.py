"""The node download route hands PVE the pinned address with the certificate check off.

download_from_url in api/storage.py pins the resolved IP into the URL before the node
fetches it, https included, the same as the ISO route in api/vms.py. PVE then compared the
mirror's certificate with that bare IP, and every https download stopped with "The
certificate's owner does not match hostname". The ISO route has always sent
verify-certificates=0 for https, so the two routes are held against each other here.

Real Flask app, faked manager and resolver, no network. MK
"""
import ipaddress
import socket
from unittest.mock import MagicMock

import pytest

import pegaprox.utils.url_security as url_security

NODE_ROUTE = '/api/clusters/cluster_1/nodes/pve1/storage/local/download-url'
ISO_ROUTE = '/api/clusters/cluster_1/datastores/local/download-url'
MIRROR = 'mirror.example.org'
MIRROR_IP = '93.184.216.34'


def _resolver(host):
    if host == MIRROR:
        return [ipaddress.ip_address(MIRROR_IP)]
    raise socket.gaierror(f'name not known: {host}')


@pytest.fixture
def pve(api, seed, monkeypatch):
    monkeypatch.setattr(url_security, '_resolve_all', _resolver)
    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True
    fake.host = '127.0.0.1'
    fake.api_port = 8006
    fake.config.name = 'cluster_1'
    sess = MagicMock()
    started = MagicMock(status_code=200)
    started.json.return_value = {'data': 'UPID:pve1:00001:download:'}
    sess.post.return_value = started
    # the ISO route polls the task in a thread, a stopped task ends that right away
    done = MagicMock(status_code=200)
    done.json.return_value = {'data': {'status': 'stopped', 'exitstatus': 'OK'}}
    sess.get.return_value = done
    fake._create_session.return_value = sess
    api.set_manager('cluster_1', fake)
    admin = seed.user('root', role='admin', tenant_id='default')
    return api.as_user(admin), sess


def _sent(sess):
    """Target and form of the last POST to PVE."""
    call = sess.post.call_args
    return call.args[0], (call.kwargs.get('data') or call.args[1])


def test_https_goes_to_the_pinned_ip_without_the_certificate_check(pve):
    client, sess = pve
    r = client.post(NODE_ROUTE, json={
        'url': f'https://{MIRROR}/images/debian-13-generic-amd64.qcow2',
        'filename': 'debian-13-generic-amd64.qcow2', 'content': 'import'})
    assert r.status_code == 200, r.get_data(as_text=True)
    target, form = _sent(sess)
    assert target == 'https://127.0.0.1:8006/api2/json/nodes/pve1/storage/local/download-url'
    assert form['url'] == f'https://{MIRROR_IP}/images/debian-13-generic-amd64.qcow2'
    assert form['verify-certificates'] == 0
    assert form['content'] == 'import'


def test_a_checksum_still_goes_along_with_https(pve):
    """PVE still checks the bytes when the caller gives a checksum."""
    client, sess = pve
    r = client.post(NODE_ROUTE, json={
        'url': f'https://{MIRROR}/images/debian.qcow2', 'filename': 'debian.qcow2',
        'content': 'import', 'checksum': 'sha512:ab12'})
    assert r.status_code == 200, r.get_data(as_text=True)
    _, form = _sent(sess)
    assert form['verify-certificates'] == 0
    assert form['checksum-algorithm'] == 'sha512' and form['checksum'] == 'ab12'


def test_plain_http_is_pinned_and_has_no_certificate_to_check(pve):
    client, sess = pve
    r = client.post(NODE_ROUTE, json={'url': f'http://{MIRROR}/isos/debian.iso', 'filename': 'debian.iso'})
    assert r.status_code == 200, r.get_data(as_text=True)
    _, form = _sent(sess)
    assert form['url'] == f'http://{MIRROR_IP}/isos/debian.iso'
    assert 'verify-certificates' not in form


@pytest.mark.parametrize('url', [
    f'https://{MIRROR}/isos/debian.iso',   # pinned
    'https://8.8.8.8/isos/debian.iso',     # an address already, left as typed
    f'http://{MIRROR}/isos/debian.iso',
])
def test_both_download_routes_send_pve_the_same_url_and_check(pve, url):
    client, sess = pve
    r = client.post(ISO_ROUTE, json={'url': url, 'filename': 'debian.iso', 'node': 'pve1'})
    assert r.status_code == 200, r.get_data(as_text=True)
    _, iso = _sent(sess)
    r = client.post(NODE_ROUTE, json={'url': url, 'filename': 'debian.iso'})
    assert r.status_code == 200, r.get_data(as_text=True)
    _, node = _sent(sess)
    assert node['url'] == iso['url']
    assert node.get('verify-certificates') == iso.get('verify-certificates')
