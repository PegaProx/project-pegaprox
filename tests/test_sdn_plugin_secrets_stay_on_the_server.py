"""The token of a NetBox or phpIPAM IPAM and the key of a PowerDNS server stay on the server.

PVE returns them on every read of /cluster/sdn/ipams and /cluster/sdn/dns, to anyone
with SDN.Audit. PegaProx reads with the cluster's own login and passed the list on as it
came, so a node.view user got both. The SDN tab never shows them, and PVE keeps the
stored value when an update leaves it out, so the three reads now drop them.
MK Nov 2026
"""
import json
from unittest.mock import MagicMock

import pytest

CID = 'cluster_1'
TOKEN = 'nb-0b5e7c1d9a-api-token'
PHP_TOKEN = 'php-41c7e-app-token'
PDNS_KEY = 'pdns-9f2a6-x-api-key'

IPAMS = [{'ipam': 'pve', 'type': 'pve', 'digest': 'd1'},
         {'ipam': 'nb', 'type': 'netbox', 'url': 'https://netbox.lab/api', 'token': TOKEN, 'digest': 'd1'},
         {'ipam': 'php', 'type': 'phpipam', 'url': 'https://ipam.lab/api/pp', 'section': 3,
          'token': PHP_TOKEN, 'digest': 'd1'}]
DNS = [{'dns': 'pdns', 'type': 'powerdns', 'url': 'https://pdns.lab/api/v1/servers/localhost',
        'key': PDNS_KEY, 'ttl': 3600, 'digest': 'd2'}]


def _reply(data):
    return MagicMock(status_code=200, text=json.dumps({'data': data}), json=lambda: {'data': data})


def _fake(api):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = 'pve', 8006

    def get(url, **kw):
        if url.endswith('/cluster/sdn/ipams'):
            return _reply(IPAMS)
        if url.endswith('/cluster/sdn/dns'):
            return _reply(DNS)
        if url.endswith('/cluster/sdn'):
            return _reply({'digest': 'd0'})
        return _reply([])
    m._create_session.return_value.get.side_effect = get
    api.set_manager(CID, m)


@pytest.fixture
def viewer(api, seed):
    _fake(api)
    return api.as_user(seed.user('viewer1', role='viewer'))


@pytest.mark.parametrize('path', ['sdn', 'sdn/ipams', 'sdn/dns'])
def test_a_viewer_reads_the_sdn_without_the_plugin_secrets(viewer, path):
    r = viewer.get(f'/api/clusters/{CID}/datacenter/{path}')
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    body = r.get_data(as_text=True)
    assert TOKEN not in body and PHP_TOKEN not in body and PDNS_KEY not in body, body[:400]


def test_the_lists_keep_everything_else(viewer):
    ipams = viewer.get(f'/api/clusters/{CID}/datacenter/sdn/ipams').get_json()
    assert ipams == [{'ipam': 'pve', 'type': 'pve', 'digest': 'd1'},
                     {'ipam': 'nb', 'type': 'netbox', 'url': 'https://netbox.lab/api', 'digest': 'd1'},
                     {'ipam': 'php', 'type': 'phpipam', 'url': 'https://ipam.lab/api/pp', 'section': 3,
                      'digest': 'd1'}]
    dns = viewer.get(f'/api/clusters/{CID}/datacenter/sdn/dns').get_json()
    assert dns == [{'dns': 'pdns', 'type': 'powerdns', 'url': 'https://pdns.lab/api/v1/servers/localhost',
                    'ttl': 3600, 'digest': 'd2'}]
    overview = viewer.get(f'/api/clusters/{CID}/datacenter/sdn').get_json()
    assert [i['ipam'] for i in overview['ipams']] == ['pve', 'nb', 'php']
    assert overview['dns'][0]['url'].startswith('https://pdns.lab/')


def test_an_admin_does_not_get_them_back_either(api, seed):
    _fake(api)
    admin = api.as_user(seed.user('adm', role='admin'))
    body = admin.get(f'/api/clusters/{CID}/datacenter/sdn').get_data(as_text=True)
    assert TOKEN not in body and PDNS_KEY not in body
