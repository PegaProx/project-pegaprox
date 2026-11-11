"""What Proxmox VE says about a VM firewall rule it refuses reaches the caller.

POST .../vms/<node>/<type>/<vmid>/firewall/rules handed a refusal to upstream_failure with
the status twice, once by position and once as status=. upstream_failure's first parameter
is called status, so the call raised TypeError, the route's own except caught it, and every
refusal went out as a 500 "Failed to create VM firewall rule": the reason PVE gave for a
bad rule was lost, and a 401 or 403 of PVE was not the 502 UPSTREAM_AUTH of #1142.

The status PVE sent now travels as pve_status, as the storage and PBS routes name it.
"""
import pytest

CID = 'c1'
URL = f'/api/clusters/{CID}/vms/pve1/qemu/100/firewall/rules'
RULE = {'type': 'in', 'action': 'NOPE', 'enable': 0}
REASON = {'action': "value 'NOPE' does not have a value in the enumeration 'ACCEPT, DROP, REJECT'"}


class _Resp:
    def __init__(self, status, body=None, text=''):
        self.status_code = status
        self._body = body if body is not None else {}
        self.text = text

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


@pytest.fixture
def admin(api, seed):
    seed.user('root', role='admin')
    return api.as_user({'username': 'root', 'role': 'admin'})


@pytest.fixture
def pve(api):
    fake = api.make_fake_manager(CID)
    fake.is_connected = True
    fake.host, fake.api_port = 'pve1.lab', 8006
    fake.config.name = 'lab'
    session = fake._create_session.return_value
    api.set_manager(CID, fake)
    return session


def test_a_rule_pve_refuses_keeps_its_status_and_its_reason(admin, pve):
    pve.post.return_value = _Resp(400, {'errors': REASON}, text='{"errors":{"action":"..."}}')
    r = admin.post(URL, json=RULE)
    body = r.get_json()
    assert r.status_code == 400, (r.status_code, body)
    assert body['error'] == REASON
    assert body['pve_status'] == 400
    # the cluster was asked, at the rules of that VM
    assert pve.post.call_args.args[0] == 'https://pve1.lab:8006/api2/json/nodes/pve1/qemu/100/firewall/rules'


@pytest.mark.parametrize('upstream', [401, 403])
def test_pve_refusing_the_stored_login_is_a_502_here_as_well(admin, pve, upstream):
    pve.post.return_value = _Resp(upstream, {'data': None}, text='{"data":null}')
    r = admin.post(URL, json=RULE)
    body = r.get_json()
    assert r.status_code == 502, (r.status_code, body)
    assert body['code'] == 'UPSTREAM_AUTH' and body['upstream_status'] == upstream


def test_a_rule_pve_takes_is_a_plain_success(admin, pve):
    """Counterproof for the path: with a 200 of PVE the route answers success."""
    pve.post.return_value = _Resp(200, {'data': None})
    r = admin.post(URL, json={'type': 'in', 'action': 'ACCEPT', 'enable': 0})
    assert r.status_code == 200 and r.get_json() == {'success': True}


def test_a_refusal_with_only_a_message_keeps_that_message(admin, pve):
    """PVE's usual error body: {"data": null, "message": ...}, here for a guest whose
    config is gone. The reason went out as error: null."""
    pve.post.return_value = _Resp(500, {'data': None, 'message': "Configuration file 'nodes/pve1/qemu-server/100.conf' does not exist\n"},
                                  text='{"data":null,"message":"Configuration file \'nodes/pve1/qemu-server/100.conf\' does not exist\n"}')
    r = admin.post(URL, json=RULE)
    body = r.get_json()
    assert r.status_code == 500, (r.status_code, body)
    assert 'does not exist' in (body['error'] or '') and body['pve_status'] == 500, body


def test_a_403_says_which_privilege_pve_missed(admin, pve):
    pve.post.return_value = _Resp(403, {'data': None, 'message': 'Permission check failed (/vms/100, VM.Config.Network)\n'},
                                  text='{"data":null,"message":"Permission check failed (/vms/100, VM.Config.Network)\n"}')
    r = admin.post(URL, json=RULE)
    body = r.get_json()
    assert r.status_code == 502 and body['code'] == 'UPSTREAM_AUTH'
    assert body['error'].endswith('Permission check failed (/vms/100, VM.Config.Network)'), body['error']


def test_a_body_that_is_no_json_goes_out_short_and_a_page_not_at_all(admin, pve):
    """A proxy in front of PVE answers with a page of its own."""
    page = '<html><head><title>502 Bad Gateway</title></head><body>' + 'x' * 5000 + '</body></html>'
    pve.post.return_value = _Resp(502, ValueError('no JSON'), text=page)
    r = admin.post(URL, json=RULE)
    body = r.get_json()
    assert r.status_code == 502 and body['error'] == 'HTTP 502', body
    pve.post.return_value = _Resp(596, ValueError('no JSON'), text='Connection timed out ' * 50)
    body = admin.post(URL, json=RULE).get_json()
    assert body['error'].startswith('Connection timed out') and len(body['error']) <= 200, body
