"""redact_url takes the login of a URL up to the last '@' before its path.

A fetcher reads the host as what follows the last '@' of the netloc, so a password may
hold an '@'. The text pattern stopped the login at the first one, wrote [REDACTED]@ for
the part before it and kept the rest of the password as the host. The storage download
route logs the URL it hands the node through it.

A blank in the password ends a login in free text, so that log line takes the login off by
the structure of the URL first, as the ISO download audit line does.
"""
import ipaddress
import logging
from unittest.mock import MagicMock

import pytest

import pegaprox.utils.url_security as url_security
from pegaprox.utils.sanitization import redact_url

CID = 'cluster_1'


@pytest.mark.parametrize('text,shown', [
    ('http://mirroruser:p@ssw0rd@93.184.216.34/isos/debian.iso',
     'http://[REDACTED]@93.184.216.34/isos/[REDACTED]'),
    ('refused: https://root@pam:s3cret@10.0.0.5:8006/api2/json - retrying',
     'refused: https://[REDACTED]@10.0.0.5:8006/api2/[REDACTED] - retrying'),
    ('https://u:a@b@[2001:db8::5]:8443/x', 'https://[REDACTED]@[2001:db8::5]:8443/[REDACTED]'),
])
def test_the_login_goes_to_its_last_at_sign(text, shown):
    assert redact_url(text) == shown
    # an '@' past the path, in the query or after a blank is no login
    assert redact_url('https://hooks.example/a?email=ops@corp.example') == \
        'https://hooks.example/[REDACTED]?email=ops@corp.example'
    assert redact_url('GET http://10.0.0.5:8006 failed for root@pam') == \
        'GET http://10.0.0.5:8006 failed for root@pam'


def test_the_storage_download_log_line_names_no_part_of_the_password(api, seed, monkeypatch, caplog):
    monkeypatch.setattr(url_security, '_resolve_all', lambda h: [ipaddress.ip_address('93.184.216.34')])
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = '127.0.0.1', 8006
    m.config.name = 'lab'
    sess = MagicMock()
    sess.post.return_value = MagicMock(status_code=200, json=MagicMock(return_value={'data': 'UPID:dl'}))
    m._create_session.return_value = sess
    api.set_manager(CID, m)
    caplog.set_level(logging.INFO)

    writer = api.as_user(seed.user('opsuser', role='user'))
    r = writer.post(f'/api/clusters/{CID}/nodes/pve1/storage/local/download-url',
                    json={'url': 'http://mirroruser:p@ssw0rd@mirror.example/isos/debian.iso',
                          'filename': 'debian.iso'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert sess.post.call_args.kwargs['data']['url'] == 'http://mirroruser:p@ssw0rd@93.184.216.34/isos/debian.iso'
    lines = [rec.getMessage() for rec in caplog.records if rec.getMessage().startswith('Downloading ')]
    assert lines, 'no Downloading line'
    assert lines[0].startswith('Downloading http://') and '93.184.216.34/' in lines[0], lines[0]
    assert 'ssw0rd' not in lines[0] and 'mirroruser' not in lines[0], lines[0]


def test_a_blank_in_the_password_does_not_end_the_login_in_the_log_line(api, seed, monkeypatch, caplog):
    monkeypatch.setattr(url_security, '_resolve_all', lambda h: [ipaddress.ip_address('93.184.216.34')])
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = '127.0.0.1', 8006
    m.config.name = 'lab'
    sess = MagicMock()
    sess.post.return_value = MagicMock(status_code=200, json=MagicMock(return_value={'data': 'UPID:dl'}))
    m._create_session.return_value = sess
    api.set_manager(CID, m)
    caplog.set_level(logging.INFO)

    writer = api.as_user(seed.user('opsuser', role='user'))
    r = writer.post(f'/api/clusters/{CID}/nodes/pve1/storage/local/download-url',
                    json={'url': 'http://mirroruser:Sec r3t@mirror.example/isos/debian.iso',
                          'filename': 'debian.iso'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert sess.post.call_args.kwargs['data']['url'] == 'http://mirroruser:Sec r3t@93.184.216.34/isos/debian.iso'
    lines = [rec.getMessage() for rec in caplog.records if rec.getMessage().startswith('Downloading ')]
    assert lines, 'no Downloading line'
    assert lines[0].startswith('Downloading http://93.184.216.34/isos/'), lines[0]
    for part in ('Sec', 'r3t', 'mirroruser'):
        assert part not in lines[0], lines[0]
