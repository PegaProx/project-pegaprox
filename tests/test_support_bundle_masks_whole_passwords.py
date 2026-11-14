"""The log part of the support bundle masks a password with blanks in it whole.

The log pass masked a password value up to its first blank, which is right for most lines.
The config lines written before they masked secrets carry the password as sent, with
blanks and commas if it had any: the Audit line as cipassword=..., the manager line as
the body it sent ('cipassword': '...'). Both are masked whole now, the rest of the line
stays readable.
"""
import io
import zipfile

from pegaprox.api import settings as settings_mod

PW = 'Bl4nk pass, w0rd'
LINES = [
    "INFO Audit: opsuser - vm.config_changed [lab] - QEMU 100 config updated: "
    f"ciuser=deploy, cipassword={PW}\n",
    f"[PegaProx_lab] INFO: Updating qemu/100 config: {{'ciuser': 'deploy', 'cipassword': '{PW}', 'cores': 2}}\n",
    f"[PegaProx_lab] INFO: Updating lxc/200 config: {{'password': \"it's {PW}\", 'hostname': 'ct1'}}\n",
    "INFO [LDAP] bind password=hunter2 for svc\n",
]


def test_a_password_with_blanks_is_masked_whole(api, seed, tmp_path, monkeypatch):
    (tmp_path / 'pegaprox.log').write_text(''.join(LINES))
    monkeypatch.setattr(settings_mod, 'LOG_DIR', str(tmp_path))
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.get('/api/support-bundle')
    assert r.status_code == 200, r.data[:300]
    with zipfile.ZipFile(io.BytesIO(r.data)) as zf:
        name = next(n for n in zf.namelist() if n.endswith('/pegaprox.log'))
        log = zf.read(name).decode()
    for part in ('Bl4nk', 'pass, w0rd', 'w0rd', 'hunter2'):
        assert part not in log, log
    # what is no password stays as it was
    assert 'QEMU 100 config updated: ciuser=deploy, cipassword=' in log
    assert "{'ciuser': 'deploy', 'cipassword': '[REDACTED]', 'cores': 2}" in log
    assert "'hostname': 'ct1'" in log
    assert log.count('\n') == len(LINES)
