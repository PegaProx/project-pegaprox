"""The "start after creation" box of the create dialogs reaches PVE, and it is not a way
around vm.start for someone who may only create."""
from unittest.mock import MagicMock

import pytest

from pegaprox.core.manager import PegaProxManager

CID = 'cluster_1'


class _Manager(PegaProxManager):
    host, api_port, is_connected = 'pve', 8006, True


def _manager():
    m = _Manager.__new__(_Manager)
    m.id, m.api_timeout = CID, 5
    m.logger = MagicMock()
    m.config = MagicMock()
    m.posted = []
    def post(url, **kw):
        m.posted.append((url, kw.get('data') or {}))
        return MagicMock(status_code=200, json=lambda: {'data': 'UPID:x'})
    m._api_post = post
    return m


VM = {'vmid': 100, 'name': 'a', 'cores': 1, 'sockets': 1, 'memory': 512}
CT = {'vmid': 100, 'hostname': 'a', 'template': 'local:vztmpl/x.tar.zst', 'cores': 1, 'memory': 512,
      'password': 'pw-for-a-test', 'storage': 'local', 'disk_size': '4'}


@pytest.mark.parametrize('kind, config, create', [('qemu', VM, 'create_vm'), ('lxc', CT, 'create_container')])
@pytest.mark.parametrize('start, sent', [(True, '1'), (False, None), (None, None)])
def test_the_box_reaches_the_create_call(kind, config, create, start, sent):
    m = _manager()
    body = dict(config)
    if start is not None:
        body['start'] = start
    assert getattr(m, create)('n1', body)['success'] is True
    url, data = m.posted[0]
    assert url.endswith(f'/nodes/n1/{kind}')
    assert data.get('start') == sent


@pytest.mark.parametrize('kind, create', [('qemu', 'create_vm'), ('lxc', 'create_container')])
class TestRoute:
    def _fake(self, api, create):
        fake = api.make_fake_manager(CID, **{create: {'success': True, 'vmid': 100}})
        fake.is_connected = True
        api.set_manager(CID, fake)
        return getattr(fake, create)

    def _post(self, client, kind, body):
        return client.post(f'/api/clusters/{CID}/nodes/n1/{kind}', json=body)

    def test_create_without_start_permission_may_not_ask_for_a_start(self, api, seed, kind, create):
        called = self._fake(api, create)
        user = seed.user('creator', role='viewer', permissions=['vm.create'])
        client = api.as_user(user)
        r = self._post(client, kind, {'vmid': 100, 'start': True})
        assert r.status_code == 403
        assert r.get_json()['required'] == 'vm.start'
        called.assert_not_called()

    def test_the_same_user_still_creates_without_the_box(self, api, seed, kind, create):
        called = self._fake(api, create)
        user = seed.user('creator', role='viewer', permissions=['vm.create'])
        r = self._post(api.as_user(user), kind, {'vmid': 100, 'start': False})
        assert r.status_code == 200
        called.assert_called_once()

    def test_with_both_permissions_the_start_goes_through(self, api, seed, kind, create):
        called = self._fake(api, create)
        user = seed.user('both', role='viewer', permissions=['vm.create', 'vm.start'])
        r = self._post(api.as_user(user), kind, {'vmid': 100, 'start': True})
        assert r.status_code == 200
        assert called.call_args[0][1]['start'] is True

    def test_a_user_without_create_gets_the_create_refusal(self, api, seed, kind, create):
        called = self._fake(api, create)
        user = seed.user('starter', role='viewer', permissions=['vm.start'])
        r = self._post(api.as_user(user), kind, {'vmid': 100, 'start': True})
        assert r.status_code == 403
        called.assert_not_called()
