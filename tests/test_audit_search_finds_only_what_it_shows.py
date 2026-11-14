"""The audit search matches a row's details as it hands them out.

An older row keeps a cloud-init password or a mirror login in the table, and the search
shows such a row masked. Its count and its page used to be matched against the stored
text, so a query for the value answered whether it was there. A details hit now has to
hold in the masked text too; the rest of a row is found as before.
"""
import pytest

CID = 'cluster_1'
ROWS = [
    ('vm.config_changed', 'QEMU 100 config updated: ciuser=deploy, cipassword=0ld-pw, cores=9 [lab]'),
    ('storage.download', 'Started download: debian.iso from http://mirroruser:p@ssw0rd@93.184.216.34/isos/debi... [lab]'),
    ('vm.config_changed', 'QEMU 101 config updated: cipassword=***, cores=4 [lab]'),
]


@pytest.fixture
def admin(api, seed):
    for action, details in ROWS:
        seed.db.add_audit_entry('opsuser', action, details, '10.0.0.7', 'lab', cluster_id=CID)
    return api.as_user(seed.user('root', role='admin'))


def _search(client, q):
    r = client.get('/api/audit/search', query_string={'q': q})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


@pytest.mark.parametrize('q', ['cipassword=0', '0ld-pw', 'mirroruser', 'ssw0rd', ':p@ss'])
def test_a_masked_value_is_not_found_by_its_text(admin, q):
    got = _search(admin, q)
    assert got['total'] == 0 and got['entries'] == [], got
    # what the rows show is still found
    assert _search(admin, 'ciuser=deploy')['total'] == 1
    assert _search(admin, '93.184.216.34/isos')['total'] == 1
    assert _search(admin, 'cores=4')['total'] == 1
    assert _search(admin, 'opsuser')['total'] == len(ROWS)
