"""The node task log hands out a URL in a line without its login.

A download task names its URL as it was given in its log, a mirror login (user:pass@)
in it as well, and the log is read with node.view. Each line keeps the URL, its host and
its path; only the login goes, an '@' or a blank in the password with it.
"""
CL = 'cluster_1'
UPID = 'UPID:pve1:0000A1B2:00003C4D:68AB1F00:download:local:root@pam:'
LINES = [
    'downloading http://mirroruser:p@ssw0rd@93.184.216.34/isos/debian.iso to /var/lib/vz/template/iso/debian.iso',
    'downloading http://mirroruser:Sec r3t@93.184.216.34/isos/debian.iso to /var/lib/vz/template/iso/debian.iso',
    'TASK ERROR: GET http://10.0.0.5:8006 failed for root@pam',
]


def test_a_node_viewer_reads_the_download_log_without_the_login(api, seed):
    m = api.make_fake_manager(CL)
    m.is_connected = True
    m.get_node_task_log.return_value = list(LINES)
    api.set_manager(CL, m)
    viewer = api.as_user(seed.user('vera', role='viewer'))

    r = viewer.get(f'/api/clusters/{CL}/nodes/pve1/tasks/{UPID}/log')
    assert r.status_code == 200, r.get_data(as_text=True)
    got = r.get_json()
    shown = 'downloading http://[REDACTED]@93.184.216.34/isos/debian.iso to /var/lib/vz/template/iso/debian.iso'
    assert got['lines'] == [shown, shown, LINES[2]], got['lines']
    assert got['log'] == '\n'.join(got['lines'])
    for part in ('mirroruser', 'ssw0rd', 'Sec', 'r3t'):
        assert part not in r.get_data(as_text=True), part
