"""The SMBIOS status reads give up on a node that does not answer (api/nodes.py).

status-all and the per-node status ran their SSH commands without a timeout. paramiko then
waits up to an hour to open the channel and without end for its output, so one node that
took the SSH login and then hung kept the request open: no answer after minutes. Every
command has the 20 s the starlvm probe has now, and a node that did not finish answering in
that time is reported with an error, not as "not installed", while the other nodes of the
cluster are still read.

The SSH side is a fake: a channel of a hung node raises socket.timeout once its timeout
runs out, as a paramiko channel does, and records the timeout it was given.
"""
import socket

import pytest

CLUSTER = 'cluster_1'
STATUS = {'n1': {'status': 'online'}, 'n2': {'status': 'online'}}


class _Out:
    def __init__(self, answer, timeout):
        self._answer = answer
        self._sent = False
        self.channel = type('Chan', (), {'eof_received': False})()
        self._timeout = timeout

    def read(self, n=-1):
        if self._answer is None:            # the hung node
            if self._timeout is None:
                raise AssertionError('read without a timeout on a node that does not answer')
            raise socket.timeout('timed out')
        if not self._sent:
            self._sent = True
            return self._answer.encode()
        self.channel.eof_received = True
        return b''


class _Ssh:
    def __init__(self, answers):
        self.answers = answers              # command start -> output, None for no answer
        self.timeouts = []
        self.closed = False

    def exec_command(self, cmd, timeout=None, **kw):
        self.timeouts.append(timeout)
        answer = next((a for k, a in self.answers.items() if cmd.startswith(k)), '')
        return None, _Out(answer, timeout), _Out('', timeout)

    def close(self):
        self.closed = True


HEALTHY = {'test -f': 'exists\n', 'systemctl': 'active\n', 'tail': 'ok\n'}
HUNG = {'test -f': None, 'systemctl': None, 'tail': None}


@pytest.fixture
def cluster(api, seed):
    sshs = {'10.0.0.1': _Ssh(HEALTHY), '10.0.0.2': _Ssh(HUNG)}
    m = api.make_fake_manager(CLUSTER)
    m.get_node_status.return_value = STATUS
    m._get_node_ip.side_effect = lambda node: {'n1': '10.0.0.1', 'n2': '10.0.0.2'}[node]
    m._ssh_connect.side_effect = lambda ip, **kw: sshs[ip]
    api.set_manager(CLUSTER, m)
    return api.as_user(seed.user('root_admin', role='admin')), sshs


def test_status_all_reports_the_hung_node_and_reads_the_other(cluster):
    admin, sshs = cluster
    r = admin.get(f'/api/clusters/{CLUSTER}/smbios-autoconfig/status-all')
    assert r.status_code == 200, r.get_data(as_text=True)
    for ssh in sshs.values():
        assert ssh.timeouts and all(t == 20 for t in ssh.timeouts), ssh.timeouts
        assert ssh.closed
    body = r.get_json()
    assert body['n1'] == {'installed': True, 'running': True, 'status': 'active'}
    assert body['n2']['installed'] is False and body['n2']['running'] is False
    assert 'No answer from the node within 20 s' in body['n2']['error']


def test_the_per_node_status_gives_up_too(cluster):
    admin, sshs = cluster
    r = admin.get(f'/api/clusters/{CLUSTER}/nodes/n2/smbios-autoconfig/status')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert sshs['10.0.0.2'].timeouts[:1] == [20] and sshs['10.0.0.2'].closed
    assert 'No answer from the node within 20 s' in r.get_json()['error']
    r = admin.get(f'/api/clusters/{CLUSTER}/nodes/n1/smbios-autoconfig/status')
    assert r.get_json() == {'installed': True, 'running': True, 'status': 'active', 'logs': 'ok'}
    assert all(t == 20 for t in sshs['10.0.0.1'].timeouts)
