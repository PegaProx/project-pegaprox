"""Editing a VM setting keeps what the dialog does not show, and shows PVE's own defaults.

- update_network rebuilt a network device from the edit dialog's fields and dropped every
  other part of the stored string: editing the rate of a trunk port turned off its VLAN
  trunks, an LXC device lost its link_down. The stored value is read first and the parts
  the dialog does not own are kept; when it cannot be read nothing is written.
- An unset cpu is PVE's default type (CPUConfig.pm get_default_cpu_type), not 'host': the
  dropdown claimed host, and a CPU flag click wrote cpu=host,flags=..., a silent type change
  that can break a live migration between different hosts.

MK Nov 2026
"""
import json
import logging
import types

import pytest

from pegaprox.core.manager import PegaProxManager


class _Resp:
    def __init__(self, status, data=None):
        self.status_code = status
        self._data = data
        self.text = json.dumps({'data': data})

    def json(self):
        return {'data': self._data}


def _manager(stored, read_status=200):
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(host='192.0.2.10', api_port=8006)
    m.current_host = None
    m.is_connected = True
    m.logger = logging.getLogger('test')
    m.gets, m.puts = [], []

    def get(url, **kw):
        m.gets.append(url)
        return _Resp(read_status, stored if read_status == 200 else None)

    def put(url, data=None, **kw):
        m.puts.append((url, dict(data or {})))
        return _Resp(200)
    m._api_get, m._api_put = get, put
    return m


QEMU_DIALOG = {'model': 'virtio', 'macaddr': 'BC:24:11:AA:BB:CC', 'bridge': 'vmbr0', 'tag': '5', 'firewall': 1,
               'rate': '50', 'queues': '', 'mtu': '', 'link_down': False}


def _sent(m, net_id='net0'):
    assert len(m.puts) == 1, m.puts
    return m.puts[0][1][net_id].split(',')


def test_a_trunk_port_keeps_its_trunks_when_its_rate_changes():
    m = _manager({'net0': 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1,tag=5,trunks=10;20;30'})
    assert m.update_network('pve1', 100, 'qemu', 'net0', QEMU_DIALOG)['success']
    assert m.gets == ['https://192.0.2.10:8006/api2/json/nodes/pve1/qemu/100/config']
    assert _sent(m) == ['virtio=BC:24:11:AA:BB:CC', 'bridge=vmbr0', 'tag=5', 'firewall=1', 'rate=50', 'trunks=10;20;30']


def test_a_part_the_dialog_owns_follows_the_dialog():
    # queues and mtu cleared in the dialog, the model changed: the stored ones go
    stored = 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr1,queues=4,mtu=9000,rate=10,link_down=1,trunks=7'
    m = _manager({'net0': stored})
    m.update_network('pve1', 100, 'qemu', 'net0', dict(QEMU_DIALOG, model='e1000'))
    sent = _sent(m)
    assert sent[0] == 'e1000=BC:24:11:AA:BB:CC'
    assert 'queues=4' not in sent and 'mtu=9000' not in sent and 'link_down=1' not in sent
    assert 'bridge=vmbr0' in sent and 'bridge=vmbr1' not in sent
    assert sent[-1] == 'trunks=7' and sum(p.startswith('virtio') for p in sent) == 0


def test_the_long_model_form_is_owned_too():
    m = _manager({'net1': 'model=virtio,macaddr=BC:24:11:00:00:01,bridge=vmbr0,trunks=3'})
    m.update_network('pve1', 100, 'qemu', 'net1', QEMU_DIALOG)
    sent = _sent(m, 'net1')
    assert not any(p.startswith(('model=', 'macaddr=')) for p in sent), sent
    assert sent[-1] == 'trunks=3'


def test_a_container_keeps_link_down_type_and_trunks():
    m = _manager({'net0': 'name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:02,ip=dhcp,type=veth,link_down=1,trunks=7;8'})
    m.update_network('pve1', 101, 'lxc', 'net0', {'name': 'eth0', 'bridge': 'vmbr0', 'hwaddr': 'BC:24:11:00:00:02',
                                                  'ip': '10.0.0.5/24', 'gw': '10.0.0.1', 'rate': '20'})
    assert m.gets == ['https://192.0.2.10:8006/api2/json/nodes/pve1/lxc/101/config']
    sent = _sent(m)
    assert sent[:6] == ['name=eth0', 'bridge=vmbr0', 'hwaddr=BC:24:11:00:00:02', 'ip=10.0.0.5/24', 'gw=10.0.0.1', 'rate=20']
    assert sent[6:] == ['type=veth', 'link_down=1', 'trunks=7;8']
    assert 'ip=dhcp' not in sent


def test_a_new_device_or_a_plain_one_is_unchanged():
    m = _manager({'net0': 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0'})
    m.update_network('pve1', 100, 'qemu', 'net0', QEMU_DIALOG)
    assert _sent(m) == ['virtio=BC:24:11:AA:BB:CC', 'bridge=vmbr0', 'tag=5', 'firewall=1', 'rate=50']


@pytest.mark.parametrize('status', [403, 500, 596])
def test_an_unread_device_is_not_overwritten(status):
    m = _manager({}, read_status=status)
    out = m.update_network('pve1', 100, 'qemu', 'net0', QEMU_DIALOG)
    assert out['success'] is False and 'nothing was changed' in out['error']
    assert m.puts == []


# --- the CPU type of a config without one ------------------------------------------------------------

def _parsed_cpu(**raw):
    m = PegaProxManager.__new__(PegaProxManager)
    return m._parse_vm_config(dict({'name': 'web01', 'memory': 2048}, **raw), 'qemu')['hardware']['cpu']


@pytest.mark.parametrize('raw,cpu', [
    ({}, 'kvm64'),
    ({'kvm': 0}, 'qemu64'),
    ({'kvm': '0'}, 'qemu64'),
    ({'arch': 'aarch64'}, 'host'),
    ({'arch': 'aarch64', 'kvm': 0}, 'max'),
    ({'cpu': 'x86-64-v2-AES'}, 'x86-64-v2-AES'),
    ({'cpu': 'host,flags=+aes'}, 'host,flags=+aes'),
], ids=['unset', 'no-kvm', 'no-kvm-text', 'aarch64', 'aarch64-no-kvm', 'set', 'set-with-flags'])
def test_an_unset_cpu_is_pves_default_type(raw, cpu):
    assert _parsed_cpu(**raw) == cpu
