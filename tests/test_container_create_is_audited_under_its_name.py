"""A new container is audited and announced under the name it got.

The create form sends the name of a container as `name`, and the manager takes it from
there when the request has no `hostname` (create_container: hostname, then name, then
ct-<vmid>). The route read only `hostname` for the audit line and for the event it sends
to the open pages, so a container created from the form was logged as "ct-<vmid>" and
showed up in the other pages under that name until their next reload.

The route now names it the way the manager does.
"""
import pytest

import pegaprox.api.vms as vms

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/nodes/n1/lxc'
TEMPLATE = 'local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst'


@pytest.fixture
def created(api, seed, monkeypatch):
    """Posts a container as an admin; hands back the audit lines and the events it caused."""
    said = {'audit': [], 'events': []}
    monkeypatch.setattr(vms, 'log_audit', lambda user, action, details='', **kw: said['audit'].append((action, details)))
    monkeypatch.setattr(vms, 'broadcast_action',
                        lambda action, kind, vmid, data, *a, **kw: said['events'].append((action, kind, vmid, data)))
    monkeypatch.setattr(vms, 'push_immediate_update', lambda *a, **kw: None)
    m = api.make_fake_manager(cluster_id=CID, create_container={'success': True, 'vmid': 902})
    m.is_connected = True
    m.id = CID
    m.config.name = CID
    m.get_pve_version_tuple.return_value = (9, 1)
    api.set_manager(CID, m)
    admin = api.as_user(seed.user('root', role='admin'))

    def post(**names):
        r = admin.post(URL, json=dict({'vmid': 902, 'template': TEMPLATE, 'password': 'chosen-root-pw'}, **names))
        assert r.status_code == 200, r.get_data(as_text=True)
        return said
    return post


def _names(said):
    [(action, details)] = [a for a in said['audit'] if a[0] == 'container.create']
    [(_, kind, vmid, data)] = [e for e in said['events'] if e[0] == 'create']
    assert (kind, vmid) == ('lxc', '902')
    return details, data['name']


def test_a_container_named_in_the_form_is_audited_under_that_name(created):
    details, announced = _names(created(name='web01'))
    assert details == 'Created CT 902 (web01) on n1'
    assert announced == 'web01'


def test_a_hostname_in_the_request_still_wins(created):
    """Counterproof: the field the route already read is read first, as in the manager."""
    details, announced = _names(created(hostname='ct1', name='web01'))
    assert details == 'Created CT 902 (ct1) on n1'
    assert announced == 'ct1'


def test_a_container_without_a_name_keeps_the_placeholder(created):
    details, announced = _names(created())
    assert details == 'Created CT 902 (ct-902) on n1'
    assert announced == 'ct-902'
