"""Removing an ESXi host that the server refuses says why (#1351).

DELETE /api/clusters/<id>/esxi-hosts/<host> answers 500 with its error when the row cannot be
deleted, and the host stays registered. The handler of the Datastore tab, which Corporate
Redesigned calls too, only acted on an ok answer: nothing happened on screen and the click
looked lost. A refusal now shows the server's error, a lost request says the connection failed,
and the host stays in the list either way.

The handler is taken out of web/src/storage.js and run by node with stubs for what it calls.
LW Nov 2026
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
START = '            const disconnectEsxiHost = async (hostId) => {\n'
END = '\n            };\n'


def _handler():
    with open(os.path.join(ROOT, 'web', 'src', 'storage.js'), encoding='utf-8') as fh:
        src = fh.read()
    at = src.index(START)
    return src[at:src.index(END, at) + len(END)]


def _remove(answer):
    """Runs the handler for host h1 against one answer: None is a request that got none."""
    js = """
const said = [], calls = [];
let hosts = [{id: 'h1'}, {id: 'h2'}];
const t = (k) => ({deleteFailed: 'Delete failed', connectionFailed: 'Connection failed'})[k];
const confirm = () => true, alert = (m) => said.push(String(m));
const API_URL = '/api', clusterId = 'c1', selectedEsxi = 'h1';
const setEsxiHosts = (f) => { hosts = f(hosts); }, setSelectedEsxi = () => {}, setEsxiVms = () => {};
const answer = %s;
const authFetch = async (url, opts) => {
    calls.push([url, opts.method]);
    if (!answer) return null;
    return {ok: answer.status < 300, status: answer.status,
            json: async () => { if (answer.body === undefined) throw new SyntaxError('no json'); return answer.body; }};
};
%s
disconnectEsxiHost('h1').then(() => process.stdout.write(JSON.stringify({said, calls, hosts: hosts.map(h => h.id)})));
""" % (json.dumps(answer), _handler())
    run = subprocess.run(['node', '-e', js], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr[-800:]
    return json.loads(run.stdout)


needs_node = pytest.mark.skipif(not shutil.which('node'), reason='needs node')


@needs_node
def test_a_refused_removal_shows_the_error_of_the_server_and_keeps_the_host():
    got = _remove({'status': 500, 'body': {'error': 'Failed to remove the ESXi host from the database'}})
    assert got['calls'] == [['/api/clusters/c1/esxi-hosts/h1', 'DELETE']]
    assert got['said'] == ['Failed to remove the ESXi host from the database']
    assert got['hosts'] == ['h1', 'h2']


@needs_node
def test_a_refusal_without_an_error_names_its_status():
    got = _remove({'status': 502})
    assert got['said'] == ['Delete failed (HTTP 502)']
    assert got['hosts'] == ['h1', 'h2']


@needs_node
def test_a_request_without_an_answer_says_the_connection_failed():
    got = _remove(None)
    assert got['said'] == ['Connection failed']
    assert got['hosts'] == ['h1', 'h2']


@needs_node
def test_a_removal_that_went_through_drops_the_host_and_says_nothing():
    got = _remove({'status': 200, 'body': {'success': True}})
    assert got['said'] == []
    assert got['hosts'] == ['h2']


@needs_node
def test_a_host_removed_elsewhere_already_leaves_the_list_quietly():
    got = _remove({'status': 404, 'body': {'error': 'ESXi storage not found'}})
    assert got['said'] == []
    assert got['hosts'] == ['h2']


def test_corporate_redesigned_removes_through_the_same_handler():
    with open(os.path.join(ROOT, 'web', 'src', 'storage.js'), encoding='utf-8') as fh:
        src = fh.read()
    assert src.count('const disconnectEsxiHost = ') == 1
    assert 'disconnect: disconnectEsxiHost,' in src
    with open(os.path.join(ROOT, 'web', 'src', 'cr_datastore.js'), encoding='utf-8') as fh:
        cr = fh.read()
    assert 'esxi-hosts' not in cr.replace('ds-esxi-hosts', '')
