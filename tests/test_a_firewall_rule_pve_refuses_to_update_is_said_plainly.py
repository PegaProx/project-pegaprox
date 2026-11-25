"""A firewall rule Proxmox VE refuses to change comes back as a readable reason with PVE's status.

pve-firewall 6.0.8 (PVE 9.3) checks the whole rule again on every update, also one that only
toggles 'enable', and refuses rules it took before: an ICMP type with a leading zero, a list or
a range as ICMP type, a security group name over 18 characters. Such a rule stays in the config
with 'errors' and is not applied. The datacenter and VM rule lists hand that field on as it is.
A refused update went out with PVE's raw JSON body as the error text, so the VM tab showed
{"errors":{...},"data":null} in its toast; the datacenter create did the same, and the VM rule
create sent the fields themselves as error.

These routes now all answer with PVE's status, its reason as text ("dport: invalid icmp-type
'010' - leading zeros are not allowed"), the fields as PVE sent them in errors and its status
as pve_status.

MK Nov 2026
"""
import json

import pytest

CID = 'c1'
VM_RULES = f'/api/clusters/{CID}/vms/pve1/qemu/100/firewall/rules'
DC_RULES = f'/api/clusters/{CID}/datacenter/firewall/rules'
ICMP = {'dport': "invalid icmp-type '010' - leading zeros are not allowed"}
GROUP = {'action': 'security group name too long'}
# a rule pve-firewall keeps but no longer applies, as GET .../firewall/rules lists it
KEPT = {'pos': 0, 'type': 'in', 'action': 'ACCEPT', 'proto': 'icmp', 'dport': '010', 'enable': 1,
        'errors': ICMP, 'digest': 'c0ffee'}


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


def _refused(errors):
    # Formatter/Standard.pm: the fields of raise_param_exc next to the bare message
    return _Resp(400, {'data': None, 'message': 'Parameter verification failed.\n', 'errors': errors})


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


@pytest.fixture
def pve(api):
    fake = api.make_fake_manager(CID)
    fake.is_connected = True
    fake.host, fake.api_port = 'pve1.lab', 8006
    fake.config.name = 'lab'
    api.set_manager(CID, fake)
    return fake._create_session.return_value


@pytest.mark.parametrize('url', [VM_RULES, DC_RULES])
def test_the_rule_lists_hand_on_the_errors_of_a_rule_as_they_are(admin, pve, url):
    pve.get.return_value = _Resp(200, {'data': [KEPT]})
    r = admin.get(url)
    assert r.status_code == 200 and r.get_json() == [KEPT]


@pytest.mark.parametrize('url, errors', [(f'{VM_RULES}/0', ICMP), (f'{DC_RULES}/0', ICMP), (f'{DC_RULES}/3', GROUP)])
def test_a_toggle_pve_refuses_says_why_with_its_status(admin, pve, url, errors):
    pve.put.return_value = _refused(errors)
    r = admin.put(url, json={'enable': 0})
    body = r.get_json()
    assert r.status_code == 400, body
    (field, why), = errors.items()
    assert body['error'] == f'{field}: {why}'
    assert body['errors'] == errors and body['pve_status'] == 400
    assert pve.put.call_args.kwargs['data'] == {'enable': 0}


@pytest.mark.parametrize('url', [DC_RULES, VM_RULES])
def test_a_rule_pve_refuses_to_create_says_why(admin, pve, url):
    pve.post.return_value = _refused(ICMP)
    r = admin.post(url, json={'type': 'in', 'action': 'ACCEPT', 'proto': 'icmp', 'dport': '010'})
    body = r.get_json()
    assert r.status_code == 400 and body['error'] == f"dport: {ICMP['dport']}" and body['errors'] == ICMP
    assert body['pve_status'] == 400


@pytest.mark.parametrize('url', [f'{VM_RULES}/0', f'{DC_RULES}/0'])
def test_a_refusal_without_fields_keeps_its_message_and_one_without_either_its_status(admin, pve, url):
    pve.put.return_value = _Resp(500, {'data': None, 'message': 'no rule at position 7\n'})
    body = admin.put(url, json={'enable': 1}).get_json()
    assert body['error'] == 'no rule at position 7' and 'errors' not in body
    pve.put.return_value = _Resp(500, {'data': None})
    r = admin.put(url, json={'enable': 1})
    assert r.status_code == 500 and r.get_json()['error'] == 'HTTP 500'


@pytest.mark.parametrize('url', [f'{VM_RULES}/0', f'{DC_RULES}/0'])
def test_pve_refusing_the_stored_login_is_a_502(admin, pve, url):
    pve.put.return_value = _Resp(403, {'data': None, 'message': 'Permission check failed (/, Sys.Modify)\n'})
    r = admin.put(url, json={'enable': 1})
    body = r.get_json()
    assert r.status_code == 502 and body['code'] == 'UPSTREAM_AUTH'
    assert body['error'].endswith('Permission check failed (/, Sys.Modify)')


@pytest.mark.parametrize('url', [f'{VM_RULES}/0', f'{DC_RULES}/0'])
def test_a_toggle_pve_takes_is_a_plain_success(admin, pve, url):
    pve.put.return_value = _Resp(200, {'data': None})
    r = admin.put(url, json={'enable': 1})
    assert r.status_code == 200 and r.get_json()['success'] is True
