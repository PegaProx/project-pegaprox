"""An audit row names who did it, what they did and where.

log_audit(user, action, details=None, ip_address=None, cluster=None, ...). The hardening
apply and rollback routes called it as log_audit('node.hardening_applied', {...}): the
row said the action was the user and a dict was the action, with no cluster. The storage
rescan passed the cluster id fourth, which is the IP slot, so the row lost the caller's
address and its cluster. The source check at the end keeps the shape from coming back.
The apply text sorts the controls by outcome (applied, failed, blocked, not applicable), so
a failed one does not read as applied; a rollback counts the controls only partly restored when the
manager's result says so.
NS Nov 2026
"""
import ast
import os
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _last_row(action):
    from pegaprox.core.db import get_db
    row = get_db().conn.execute('SELECT * FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1',
                                (action,)).fetchone()
    return dict(row) if row else None


def _all_rows():
    from pegaprox.core.db import get_db
    return [dict(r) for r in get_db().conn.execute('SELECT user, action, details, cluster FROM audit_log')]


def _hardening_mgr(api):
    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True
    fake.config = types.SimpleNamespace(name='Lab', ssh_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5')
    fake.apply_node_hardening = lambda node, controls, params=None: {
        c: {'success': c != 'pam_faillock'} for c in controls}
    fake.rollback_node_hardening = lambda node, controls: {c: {'success': True} for c in controls}
    api.set_manager('cluster_1', fake)
    return fake


def test_applying_hardening_records_the_admin_the_action_and_the_cluster(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    _hardening_mgr(api)
    r = api.as_user(root).post('/api/clusters/cluster_1/nodes/pve1/hardening',
                               json={'controls': ['default_umask', 'pam_faillock']})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = _last_row('node.hardening_applied')
    assert row is not None, _all_rows()
    assert row['user'] == 'root'
    assert row['cluster'] == 'Lab' and row['cluster_id'] == 'cluster_1'
    assert row['ip_address'] == '127.0.0.1'
    # a sentence like every other row, not a dict printed as text
    assert not row['details'].lstrip().startswith('{'), row['details']
    assert 'pve1' in row['details'] and '1 of 2' in row['details'], row['details']
    # the failed control is listed as failed, never next to the applied one
    assert '(applied: default_umask; failed: pam_faillock)' in row['details'], row['details']
    assert 'blocked' not in row['details'] and 'forced' not in row['details']


def test_a_control_held_back_by_the_ssh_guard_is_listed_as_blocked(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    fake = _hardening_mgr(api)
    fake.config.ssh_key = ''
    r = api.as_user(root).post('/api/clusters/cluster_1/nodes/pve1/hardening',
                               json={'controls': ['default_umask', 'sshd_hardening', 'pam_faillock']})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['results']['sshd_hardening']['blocked'] is True
    row = _last_row('node.hardening_applied')
    assert row and '1 of 3' in row['details'], row
    assert '(applied: default_umask; failed: pam_faillock; blocked: sshd_hardening)' in row['details'], \
        row['details']


def test_nothing_applied_says_none(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    _hardening_mgr(api)
    api.as_user(root).post('/api/clusters/cluster_1/nodes/pve1/hardening', json={'controls': ['pam_faillock']})
    row = _last_row('node.hardening_applied')
    assert row and '0 of 1 controls applied (applied: none; failed: pam_faillock)' in row['details'], row


def test_an_audit_only_control_is_not_listed_as_failed(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    fake = _hardening_mgr(api)
    fake.apply_node_hardening = lambda node, controls, params=None: {
        c: ({'success': False, 'noop': True, 'error': 'audit only'} if c == 'net_protocols'
            else {'success': True}) for c in controls}
    r = api.as_user(root).post('/api/clusters/cluster_1/nodes/pve1/hardening',
                               json={'controls': ['default_umask', 'net_protocols']})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = _last_row('node.hardening_applied')
    assert row and '1 of 2' in row['details'], row
    assert '(applied: default_umask; not applicable: net_protocols)' in row['details'], row['details']
    assert 'failed' not in row['details'], row['details']


def test_a_forced_apply_says_so(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    _hardening_mgr(api)
    r = api.as_user(root).post('/api/clusters/cluster_1/nodes/pve1/hardening',
                               json={'controls': ['sshd_hardening'], 'force': True})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = _last_row('node.hardening_applied')
    assert row and row['user'] == 'root'
    assert 'sshd_hardening' in row['details'] and 'forced' in row['details']


def test_a_rollback_records_the_admin_the_action_and_the_cluster(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    _hardening_mgr(api)
    r = api.as_user(root).post('/api/clusters/cluster_1/nodes/pve2/hardening/rollback',
                               json={'controls': ['default_umask']})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = _last_row('node.hardening_rolled_back')
    assert row is not None, _all_rows()
    assert row['user'] == 'root'
    assert row['cluster'] == 'Lab' and row['cluster_id'] == 'cluster_1'
    assert not row['details'].lstrip().startswith('{'), row['details']
    for word in ('pve2', 'default_umask', '1 of 1'):
        assert word in row['details'], row['details']
    # the manager reported no partial restore, so the text names none
    assert 'partly' not in row['details'], row['details']


def test_a_rollback_says_how_many_were_only_partly_restored(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    fake = _hardening_mgr(api)
    # the shape of a result that carries the flag; one without it is the test above
    fake.rollback_node_hardening = lambda node, controls: {
        'default_umask': {'success': True, 'partial': True},
        'pam_faillock': {'success': True},
        'sshd_hardening': {'success': False, 'partial': True, 'error': 'one of two files restored'}}
    r = api.as_user(root).post('/api/clusters/cluster_1/nodes/pve2/hardening/rollback',
                               json={'controls': ['default_umask', 'pam_faillock', 'sshd_hardening']})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = _last_row('node.hardening_rolled_back')
    assert row and '2 of 3 controls rolled back' in row['details'], row
    assert '2 only partly restored (default_umask, sshd_hardening)' in row['details'], row['details']


class _Resp:
    def __init__(self, data, status=200):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return {'data': self._data}


class _Session:
    def get(self, url, timeout=None):
        if url.endswith('/storage/data'):
            return _Resp({'type': 'dir'})
        if url.endswith('/nodes'):
            return _Resp([{'node': 'pve1', 'status': 'online'}])
        return _Resp({'active': 1, 'enabled': 1, 'total': 10, 'used': 1, 'avail': 9})


def test_a_storage_rescan_keeps_the_address_and_names_the_cluster(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True
    fake.host, fake.api_port = 'pve1.lab', 8006
    fake.config = types.SimpleNamespace(name='Lab')
    fake._create_session = lambda: _Session()
    api.set_manager('cluster_1', fake)
    r = api.as_user(root).post('/api/clusters/cluster_1/datacenter/storage/data/rescan', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = _last_row('storage.rescan')
    assert row is not None, _all_rows()
    assert row['user'] == 'root'
    assert row['ip_address'] == '127.0.0.1', row['ip_address']
    assert row['cluster'] == 'Lab' and row['cluster_id'] == 'cluster_1'


# --- the shape of every call ----------------------------------------------------------------

def _calls():
    for base in ('pegaprox', 'plugins'):
        for d, _, files in os.walk(os.path.join(ROOT, base)):
            for f in files:
                if not f.endswith('.py'):
                    continue
                path = os.path.join(d, f)
                with open(path, encoding='utf-8') as fh:
                    tree = ast.parse(fh.read())
                for n in ast.walk(tree):
                    if isinstance(n, ast.Call):
                        fn = n.func
                        name = fn.id if isinstance(fn, ast.Name) else getattr(fn, 'attr', None)
                        if name == 'log_audit':
                            yield f'{os.path.relpath(path, ROOT)}:{n.lineno}', n


def test_no_call_puts_an_action_or_a_dict_where_the_user_goes():
    found = list(_calls())
    assert len(found) > 300
    bad = []
    for where, call in found:
        args = call.args
        if not args:
            if {k.arg for k in call.keywords} >= {'user', 'action'}:
                continue
            bad.append((where, 'no user'))
            continue
        first = args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str) and '.' in first.value:
            bad.append((where, f'action {first.value!r} as the user'))
        if any(isinstance(a, (ast.Dict, ast.List, ast.Set)) for a in args):
            bad.append((where, 'a dict or list as an argument'))
        if len(args) < 2 and 'action' not in {k.arg for k in call.keywords}:
            bad.append((where, 'no action'))
        # the fourth is the caller's address; a cluster goes by keyword
        if len(args) >= 4 and not _names_an_address(args[3]):
            bad.append((where, f'{ast.unparse(args[3])} in the address slot'))
    assert not bad, bad


ADDRESS_NAMES = {'ip_address', 'remote_addr'}


def _names_an_address(node):
    """request.remote_addr, ip_address and the like, by name. A substring test on the text
    let anything with "ip" in it through, description included."""
    if isinstance(node, ast.Attribute):
        return node.attr in ADDRESS_NAMES
    if isinstance(node, ast.Name):
        return node.id in ADDRESS_NAMES
    return False


@pytest.mark.parametrize('arg,ok', [
    ('request.remote_addr', True), ('ip_address', True), ('remote_addr', True), ('self.ip_address', True),
    ('description', False), ('cluster_id', False), ('ip', False), ('recipient', False), ("'10.0.0.1'", False),
])
def test_the_address_slot_check_goes_by_name(arg, ok):
    assert _names_an_address(ast.parse(arg, mode='eval').body) is ok
