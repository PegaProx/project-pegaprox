"""PVE's POST /cluster/sdn/vnets/{vnet}/subnets requires type=subnet. The Add Subnet dialogs
do not send it, so the route has to."""
from unittest.mock import MagicMock

CID = 'cluster_1'


def _fake(api, status=200, text='{"data":null}'):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = 'pve', 8006
    post = m._create_session.return_value.post
    post.return_value = MagicMock(status_code=status, text=text)
    api.set_manager(CID, m)
    return post


def _add(client, body):
    return client.post(f'/api/clusters/{CID}/datacenter/sdn/vnets/vnet1/subnets', json=body)


def test_the_dialog_body_reaches_pve_with_the_type(api, seed):
    post = _fake(api)
    admin = api.as_user(seed.user('adm', role='admin'))
    r = _add(admin, {'subnet': '10.0.0.0/24', 'gateway': '10.0.0.1', 'snat': 1})
    assert r.status_code == 200
    assert post.call_args.kwargs['data'] == {'subnet': '10.0.0.0/24', 'gateway': '10.0.0.1',
                                             'snat': 1, 'type': 'subnet'}


def test_a_caller_cannot_send_another_type(api, seed):
    post = _fake(api)
    admin = api.as_user(seed.user('adm', role='admin'))
    assert _add(admin, {'subnet': '10.0.0.0/24', 'type': 'vnet'}).status_code == 200
    assert post.call_args.kwargs['data']['type'] == 'subnet'


def test_a_refusal_from_pve_still_reaches_the_caller(api, seed):
    _fake(api, status=400, text='{"errors":{"subnet":"invalid"}}')
    admin = api.as_user(seed.user('adm', role='admin'))
    assert _add(admin, {'subnet': 'nonsense'}).status_code >= 400
