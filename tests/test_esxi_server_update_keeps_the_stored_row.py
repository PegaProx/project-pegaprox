"""An update of an ESXi server starts from what is stored, and a port that is no port is a 400.

PUT /api/vmware/<id> handed the request body to save_vmware_server and VMwareManager as the
whole server, and only the password and linked_clusters were filled in from what was
stored. Everything else fell back to the defaults of the storage layer:

  * the edit dialog sends name, host, port, username, password, ssl_verify and notes, never
    server_type or enabled. A save of a host stored as 'esxi' gave it the default type (the
    console link and the summary took the other branch at once, XHM lost the host at the
    next start), and a disabled server came back enabled
  * a body with the notes only stored an empty host, the name 'ESXi server' and the
    default account

And the port went through int() as the client sent it, so 'abc' or null was a 500 on the
update, on adding a server and on Test Connection, and true or 443.9 were stored as 1 and
443. null and '' mean "not given" now, the stored port (or 443) stays; anything else that
is not a port from 1 to 65535 is a 400.

The routes run through the real app; connect() is replaced, nothing is dialed. MK
"""
import pytest

import pegaprox.globals as ppglobals
from pegaprox.core.vmware import VMwareManager, save_vmware_server

SID = 'esx-lab'
STORED = {'name': 'lab esxi', 'host': '10.0.0.5', 'port': 443, 'username': 'root',
          'password': 'stored-pw', 'server_type': 'esxi', 'ssl_verify': True,
          'notes': 'rack 2', 'linked_clusters': []}


@pytest.fixture
def dials(monkeypatch):
    seen = []

    def connect(self):
        seen.append((self.host, self.port, self.password))
        self.connected = True
        return True
    monkeypatch.setattr(VMwareManager, 'connect', connect)
    return seen


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_adm', role='admin'))


@pytest.fixture
def server(api, dials):
    save_vmware_server(SID, dict(STORED))
    ppglobals.vmware_managers[SID] = VMwareManager(SID, dict(STORED))
    return SID


def _row(sid=SID):
    from pegaprox.core.db import get_db
    db = get_db()
    r = db.conn.cursor().execute('SELECT * FROM vmware_servers WHERE id = ?', (sid,)).fetchone()
    if r is None:
        return None
    r = dict(r)
    r['password'] = db._decrypt(r['pass_encrypted']) if r['pass_encrypted'] else ''
    return r


def _edit_form(**kw):
    """What the edit dialog PUTs (openVmwareEdit / handleUpdateVMware), password left blank."""
    return dict({'name': 'lab esxi', 'host': '10.0.0.5', 'port': 443, 'username': 'root',
                 'password': '', 'ssl_verify': True, 'notes': 'rack 2'}, **kw)


def _kept(row):
    return {k: row[k] for k in ('name', 'host', 'port', 'username', 'password', 'server_type', 'ssl_verify')}


KEPT = {'name': 'lab esxi', 'host': '10.0.0.5', 'port': 443, 'username': 'root',
        'password': 'stored-pw', 'server_type': 'esxi', 'ssl_verify': 1}


# --- what the body does not send stays as stored -------------------------------------------

def test_a_save_of_the_edit_dialog_keeps_an_esxi_host_an_esxi_host(admin, server):
    r = admin.put(f'/api/vmware/{SID}', json=_edit_form(notes='rack 3'))
    assert r.status_code == 200, r.get_json()
    row = _row()
    assert row['notes'] == 'rack 3'
    assert row['server_type'] == 'esxi', row['server_type']
    # the live manager as well: its console link and summary branch read server_type
    assert ppglobals.vmware_managers[SID].server_type == 'esxi'
    assert r.get_json()['server_type'] == 'esxi'


@pytest.mark.parametrize('body', [
    {'notes': 'only the notes'},
    {'notes': ''},
    {'name': 'lab esxi (B)'},
    # null and '' are "not given"
    {'host': '', 'port': None, 'username': None, 'server_type': '', 'notes': 'x'},
    {'port': '', 'name': '', 'password': None, 'ssl_verify': None},
], ids=['notes', 'notes-cleared', 'name', 'nulls-and-empties', 'empty-port'])
def test_a_partial_update_keeps_everything_it_does_not_name(admin, server, dials, body):
    r = admin.put(f'/api/vmware/{SID}', json=body)
    assert r.status_code == 200, (r.status_code, r.get_json())
    row = _row()
    want = dict(KEPT)
    want.update({k: v for k, v in body.items() if k == 'name' and v})
    assert _kept(row) == want, _kept(row)
    if 'notes' in body:
        assert row['notes'] == body['notes']
    else:
        assert row['notes'] == 'rack 2'
    mgr = ppglobals.vmware_managers[SID]
    assert (mgr.host, mgr.port, mgr.username, mgr.password, mgr.server_type) == \
        ('10.0.0.5', 443, 'root', 'stored-pw', 'esxi')
    # the same destination, so the stored credential was used where it was before
    assert dials and dials[-1] == ('10.0.0.5', 443, 'stored-pw'), dials


def test_a_disabled_server_stays_disabled_when_it_is_edited(admin, server, dials):
    r = admin.put(f'/api/vmware/{SID}', json={'enabled': False})
    assert r.status_code == 200, r.get_json()
    assert _row()['enabled'] == 0
    n = len(dials)
    r = admin.put(f'/api/vmware/{SID}', json=_edit_form(notes='parked'))
    assert r.status_code == 200, r.get_json()
    row = _row()
    assert row['notes'] == 'parked'
    assert row['enabled'] == 0, 'a save of the edit dialog switched the server back on'
    assert len(dials) == n, 'a disabled server was connected'
    assert ppglobals.vmware_managers[SID].enabled is False


def test_switching_it_back_on_still_works(admin, server, dials):
    admin.put(f'/api/vmware/{SID}', json={'enabled': False})
    r = admin.put(f'/api/vmware/{SID}', json={'enabled': True})
    assert r.status_code == 200, r.get_json()
    assert _row()['enabled'] == 1 and _row()['server_type'] == 'esxi'
    assert dials[-1] == ('10.0.0.5', 443, 'stored-pw')


# --- the port --------------------------------------------------------------------------------

@pytest.mark.parametrize('port', ['abc', '443x', [443], {'p': 1}, 0, -1, 65536, '70000',
                                  True, 443.9])
def test_a_port_that_is_no_port_is_refused_on_update(admin, server, dials, port):
    before = _row()
    r = admin.put(f'/api/vmware/{SID}', json={'port': port, 'password': 'pw'})
    assert r.status_code == 400, (port, r.status_code)
    assert r.get_json() == {'error': 'Invalid port'}
    assert _row() == before
    # and a real one, as a string, still moves it
    r = admin.put(f'/api/vmware/{SID}', json={'port': '8443', 'password': 'fresh-pw'})
    assert r.status_code == 200, r.get_json()
    assert _row()['port'] == 8443 and _row()['password'] == 'fresh-pw'
    assert dials[-1] == ('10.0.0.5', 8443, 'fresh-pw')
    # a whole number that JSON carries as a float is a port too
    r = admin.put(f'/api/vmware/{SID}', json={'port': 443.0, 'password': 'fresh-pw'})
    assert r.status_code == 200, r.get_json()
    assert _row()['port'] == 443


NEW = {'name': 'new esxi', 'host': '10.0.0.6', 'username': 'root', 'password': 'pw',
       'server_type': 'esxi'}


@pytest.mark.parametrize('port', ['abc', [1], 0, 99999, True, 443.5])
def test_adding_a_server_with_a_port_that_is_no_port_is_a_400(admin, dials, port):
    r = admin.post('/api/vmware', json=dict(NEW, port=port))
    assert r.status_code == 400, (port, r.status_code)
    assert r.get_json() == {'error': 'Invalid port'}
    assert not dials


@pytest.mark.parametrize('port', [None, ''])
def test_adding_a_server_without_a_port_uses_443(admin, dials, port):
    r = admin.post('/api/vmware', json=dict(NEW, port=port))
    assert r.status_code == 201, (r.status_code, r.get_json())
    assert _row(r.get_json()['id'])['port'] == 443
    assert dials == [('10.0.0.6', 443, 'pw')]


@pytest.mark.parametrize('port', ['abc', None, '', 0, True])
def test_test_connection_reads_the_port_the_same_way(admin, dials, port):
    r = admin.post('/api/vmware/test-connection', json=dict(NEW, port=port))
    if port in (None, ''):
        assert r.status_code == 200, (r.status_code, r.get_json())
        assert dials == [('10.0.0.6', 443, 'pw')]
    else:
        assert r.status_code == 400, (port, r.status_code)
        assert r.get_json() == {'error': 'Invalid port'}
        assert not dials
