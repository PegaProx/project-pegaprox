"""The token of a NetBox or phpIPAM IPAM and the key of a PowerDNS server go only to the
url, and the certificate, they were typed for.

PVE merges an update of /cluster/sdn/ipams/{id} and /cluster/sdn/dns/{id}: a PUT that
only changes 'url' keeps the stored token or key, and the update hook calls the new url
with it right away. A new 'fingerprint', or a 'delete' that drops it, lets another
certificate answer for the same url. The reads no longer return either secret, so such a
change needs it typed again in the same request. A url or fingerprint that is the same
after normalising, or a PUT without either, goes through as before. If the current entry
cannot be read, the PUT is refused rather than guessed.

requests leaves None out of the form body and sends a list or dict item by item, so a
field the check depends on that is not a string is refused before PVE sees the body.
MK Nov 2026
"""
import json
from unittest.mock import MagicMock

import pytest

CID = 'cluster_1'
NB = {'ipam': 'nb', 'type': 'netbox', 'url': 'https://netbox.lab/api', 'token': 'nb-stored-token',
      'fingerprint': 'AA:BB:CC', 'digest': 'd1'}
PDNS = {'dns': 'pdns', 'type': 'powerdns', 'url': 'http://pdns.lab:8081/api/v1/servers/localhost',
        'key': 'pdns-stored-key', 'ttl': 3600, 'digest': 'd2'}


def _reply(data, status=200):
    return MagicMock(status_code=status, text=json.dumps({'data': data}), json=lambda: {'data': data})


@pytest.fixture
def pve(api):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = 'pve', 8006
    s = m._create_session.return_value
    s.reads = {'/cluster/sdn/ipams/nb': NB, '/cluster/sdn/dns/pdns': PDNS}

    def get(url, **kw):
        for tail, entry in s.reads.items():
            if url.endswith(tail):
                return _reply(entry) if entry is not None else _reply(None, 500)
        return _reply(None, 404)
    s.get.side_effect = get
    s.put.return_value = MagicMock(status_code=200, text='{"data":null}')
    api.set_manager(CID, m)
    return s


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('sdnadmin', role='admin'))


IPAM = f'/api/clusters/{CID}/datacenter/sdn/ipams/nb'
DNS = f'/api/clusters/{CID}/datacenter/sdn/dns/pdns'


@pytest.mark.parametrize('path,body', [
    (IPAM, {'url': 'https://elsewhere.example/api'}),
    (IPAM, {'url': 'https://netbox.lab:8443/api'}),
    (IPAM, {'url': 'http://netbox.lab/api'}),
    (IPAM, {'url': 'https://netbox.lab/other', 'token': ''}),
    (DNS, {'url': 'http://elsewhere.example:8081/api/v1/servers/localhost'}),
    (DNS, {'url': 'http://pdns.lab:8082/api/v1/servers/localhost', 'ttl': 60}),
    (IPAM, {'delete': 'url'}),
])
def test_a_new_url_without_the_secret_is_refused_before_pve_sees_it(pve, admin, path, body):
    r = admin.put(path, json=body)
    assert r.status_code == 400, r.get_data(as_text=True)[:300]
    assert r.get_json()['code'] == 'CREDENTIAL_REQUIRED'
    assert not pve.put.called


@pytest.mark.parametrize('path,body', [
    (IPAM, {'url': 'https://elsewhere.example/api', 'token': 'typed-again'}),
    (DNS, {'url': 'http://elsewhere.example:8081/api/v1/servers/localhost', 'key': 'typed-again'}),
    (IPAM, {'fingerprint': '11:22:33', 'token': 'typed-again'}),
    (IPAM, {'delete': 'fingerprint', 'token': 'typed-again'}),
    (DNS, {'fingerprint': '11:22:33', 'key': 'typed-again'}),
])
def test_a_new_url_with_the_secret_typed_again_goes_through(pve, admin, path, body):
    r = admin.put(path, json=body)
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert pve.put.call_args.kwargs['data'] == body


@pytest.mark.parametrize('path,body', [
    (IPAM, {'url': 'HTTPS://NetBox.Lab:443/api/'}),
    (IPAM, {'url': 'https://netbox.lab./api', 'fingerprint': ' aa:bb:cc'}),
    (IPAM, {'url': None, 'fingerprint': None, 'section': '2'}),
    (IPAM, {'token': 'only-the-token'}),
    (DNS, {'url': 'http://pdns.lab:8081/api/v1/servers/localhost', 'ttl': 60}),
    (DNS, {'ttl': 120}),
    (DNS, {'delete': 'ttl,reversemaskv6'}),
])
def test_the_same_url_or_no_url_goes_through_without_the_secret(pve, admin, path, body):
    r = admin.put(path, json=body)
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert pve.put.called


@pytest.mark.parametrize('path,body', [
    (IPAM, {'url': 'https://netbox.lab/api'}),
    (DNS, {'url': 'https://netbox.lab/api'}),
    (IPAM, {'fingerprint': 'AA:BB:CC'}),
])
def test_an_unreadable_entry_refuses_a_url_change(pve, admin, path, body):
    pve.reads = {'/cluster/sdn/ipams/nb': None, '/cluster/sdn/dns/pdns': None}
    r = admin.put(path, json=body)
    assert r.status_code == 400, r.get_data(as_text=True)[:300]
    assert r.get_json()['code'] == 'CREDENTIAL_REQUIRED'
    assert not pve.put.called


def test_a_read_that_raises_refuses_too(pve, admin):
    pve.get.side_effect = ConnectionError('pve went away')
    r = admin.put(IPAM, json={'url': 'https://netbox.lab/api'})
    assert r.status_code == 400
    assert r.get_json()['code'] == 'CREDENTIAL_REQUIRED'
    assert not pve.put.called


@pytest.mark.parametrize('path,body', [
    (IPAM, {'url': 'https://netbox.lab/api', 'fingerprint': '11:22:33'}),
    (IPAM, {'fingerprint': '11:22:33'}),
    (IPAM, {'delete': 'fingerprint'}),
    (IPAM, {'url': 'https://netbox.lab/api', 'delete': 'section;fingerprint'}),
    (IPAM, {'fingerprint': '11:22:33', 'token': '  '}),
    (DNS, {'fingerprint': 'AA:BB:CC'}),
])
def test_a_new_fingerprint_without_the_secret_is_refused_too(pve, admin, path, body):
    r = admin.put(path, json=body)
    assert r.status_code == 400, r.get_data(as_text=True)[:300]
    assert r.get_json()['code'] == 'CREDENTIAL_REQUIRED'
    assert not pve.put.called


# each of these reaches PVE as a url (or a dropped fingerprint) without any token or key
@pytest.mark.parametrize('path,body', [
    (IPAM, {'url': 'https://elsewhere.example/api', 'token': [None]}),
    (IPAM, {'url': 'https://elsewhere.example/api', 'token': [[]]}),
    (IPAM, {'url': 'https://elsewhere.example/api', 'token': ['']}),
    (IPAM, {'url': ['https://elsewhere.example/api']}),
    (IPAM, {'delete': {'fingerprint': 1}}),
    (IPAM, {'fingerprint': ['11:22:33']}),
    (DNS, {'url': 'http://elsewhere.example:8081/x', 'key': [None]}),
    (IPAM, [['url', 'https://elsewhere.example/api']]),
    (DNS, [['url', 'http://elsewhere.example:8081/x']]),
])
def test_a_body_pve_would_read_differently_is_refused(pve, admin, path, body):
    r = admin.put(path, json=body)
    assert r.status_code == 400, r.get_data(as_text=True)[:300]
    assert not pve.put.called


def test_the_put_only_applies_to_the_entry_that_was_compared(pve, admin):
    r = admin.put(IPAM, json={'url': 'https://netbox.lab/api'})
    assert r.status_code == 200
    assert pve.put.call_args.kwargs['data']['digest'] == 'd1'
    pve.put.reset_mock()
    r = admin.put(IPAM, json={'url': 'https://netbox.lab/api', 'digest': 'older'})
    assert r.status_code == 409 and not pve.put.called
