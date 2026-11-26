"""The url, token and key of an SDN IPAM or DNS plugin reach Proxmox VE without whitespace
around them.

PVE 9.3 (pve-network 006bb97e) gives the PowerDNS url and key and the phpIPAM url and token the
pattern \\S+. A value pasted with a space or a line feed at its end was stored before and is
refused now with "value does not match the regex pattern". The create and update routes trim
these three fields before they send them; what is inside a value, and every other field, goes
out as it came. When PVE refuses such a value it names the field next to the bare "Parameter
verification failed."; that reason comes back as the error text, the fields as errors.

MK Nov 2026
"""
import json
from unittest.mock import MagicMock

import pytest

CID = 'cluster_1'
STORED = {'/cluster/sdn/ipams/ipam1': {'ipam': 'ipam1', 'type': 'phpipam', 'url': 'https://ipam.lab/api/pve',
                                       'token': 'stored', 'section': 1, 'digest': 'd1'},
          '/cluster/sdn/dns/pdns': {'dns': 'pdns', 'type': 'powerdns', 'url': 'http://pdns.lab:8081/api/v1/servers/localhost',
                                    'key': 'stored', 'ttl': 3600, 'digest': 'd2'}}


@pytest.fixture
def pve(api):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = 'pve', 8006
    s = m._create_session.return_value

    def get(url, **kw):
        for tail, entry in STORED.items():
            if url.endswith(tail):
                return MagicMock(status_code=200, text=json.dumps({'data': entry}), json=lambda e=entry: {'data': e})
        return MagicMock(status_code=404, text='{"data":null}', json=lambda: {'data': None})
    s.get.side_effect = get
    s.post.return_value = MagicMock(status_code=200, text='{"data":null}')
    s.put.return_value = MagicMock(status_code=200, text='{"data":null}')
    api.set_manager(CID, m)
    return s


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('sdnadmin', role='admin'))


def test_a_new_phpipam_goes_out_trimmed(pve, admin):
    r = admin.post(f'/api/clusters/{CID}/datacenter/sdn/ipams', json={
        'ipam': 'ipam1', 'type': 'phpipam', 'url': ' https://ipam.lab/api/pve \n', 'token': 'tok-123\t ', 'section': 3})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.post.call_args.kwargs['data'] == {
        'ipam': 'ipam1', 'type': 'phpipam', 'url': 'https://ipam.lab/api/pve', 'token': 'tok-123', 'section': 3}


def test_a_new_powerdns_goes_out_trimmed(pve, admin):
    r = admin.post(f'/api/clusters/{CID}/datacenter/sdn/dns', json={
        'dns': 'pdns', 'type': 'powerdns', 'url': 'http://pdns.lab:8081/api/v1/servers/localhost ', 'key': '\nk3y ', 'ttl': 60})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.post.call_args.kwargs['data'] == {
        'dns': 'pdns', 'type': 'powerdns', 'url': 'http://pdns.lab:8081/api/v1/servers/localhost', 'key': 'k3y', 'ttl': 60}


@pytest.mark.parametrize('path,body,sent', [
    ('sdn/ipams/ipam1', {'url': 'https://other.lab/api/pve  ', 'token': ' new-token '},
     {'url': 'https://other.lab/api/pve', 'token': 'new-token'}),
    ('sdn/dns/pdns', {'key': 'new-key\n'}, {'key': 'new-key'}),
    ('sdn/dns/pdns', {'ttl': 120}, {'ttl': 120}),
])
def test_an_update_goes_out_trimmed(pve, admin, path, body, sent):
    r = admin.put(f'/api/clusters/{CID}/datacenter/{path}', json=body)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.put.call_args.kwargs['data'] == sent


def test_whitespace_inside_a_value_is_left_for_pve_to_judge(pve, admin):
    r = admin.post(f'/api/clusters/{CID}/datacenter/sdn/ipams', json={
        'ipam': 'ipam1', 'type': 'phpipam', 'url': 'https://ipam.lab/api pve', 'token': 'two words'})
    assert r.status_code == 200
    sent = pve.post.call_args.kwargs['data']
    assert (sent['url'], sent['token']) == ('https://ipam.lab/api pve', 'two words')


# Formatter/Standard.pm: the fields of raise_param_exc next to the bare message
NO_SPACE = {'url': 'value does not match the regex pattern'}


@pytest.mark.parametrize('method,path,body', [
    ('post', 'sdn/ipams', {'ipam': 'ipam2', 'type': 'phpipam', 'url': 'https://ipam.lab/api pve', 'token': 't'}),
    ('put', 'sdn/ipams/ipam1', {'url': 'https://ipam.lab/api pve', 'token': 't'}),
    ('post', 'sdn/dns', {'dns': 'pdns2', 'type': 'powerdns', 'url': 'http://pdns.lab/api v1', 'key': 'k'}),
    ('put', 'sdn/dns/pdns', {'url': 'http://pdns.lab/api v1', 'key': 'k'}),
])
def test_a_value_pve_refuses_comes_back_with_the_field_it_names(pve, admin, method, path, body):
    said = {'data': None, 'message': 'Parameter verification failed.\n', 'errors': NO_SPACE}
    getattr(pve, method).return_value = MagicMock(status_code=400, text=json.dumps(said), json=lambda: said)
    r = getattr(admin, method)(f'/api/clusters/{CID}/datacenter/{path}', json=body)
    got = r.get_json()
    assert r.status_code == 400, got
    assert got['error'] == 'url: value does not match the regex pattern' and got['errors'] == NO_SPACE
