# Re-pin must also drop hashed known_hosts lines (|1|salt|hash). OpenSSH's own ssh writes
# them on distributions defaulting to HashKnownHosts; paramiko still enforces them, so
# a text-only removal reported success while the old key kept failing every SSH check.
import base64
import hashlib
import hmac

import paramiko

from pegaprox.utils import ssh_security


def _hashed(host, key):
    salt = b'0123456789abcdef0123'
    mac = hmac.new(salt, host.encode(), hashlib.sha1).digest()
    tok = '|1|%s|%s' % (base64.b64encode(salt).decode(), base64.b64encode(mac).decode())
    return '%s %s %s\n' % (tok, key.get_name(), key.get_base64())


def test_hashed_entries_are_removed(tmp_path, monkeypatch):
    kh = tmp_path / 'known_hosts'
    key = paramiko.RSAKey.generate(1024)
    kh.write_text(_hashed('192.168.88.15', key) + _hashed('[192.168.88.16]:2222', key)
                  + _hashed('192.168.88.99', key))
    monkeypatch.setattr(ssh_security, '_KNOWN_HOSTS', str(kh))
    n = ssh_security.remove_host_keys({'192.168.88.15', '192.168.88.16'}, ports=[2222])
    assert n == 2
    left = kh.read_text().splitlines()
    assert len(left) == 1
    hk = paramiko.hostkeys.HostKeys()
    hk.load(str(kh))
    assert hk.lookup('192.168.88.99') is not None
    assert hk.lookup('192.168.88.15') is None


def test_malformed_hashed_tokens_are_left_alone(tmp_path, monkeypatch):
    kh = tmp_path / 'known_hosts'
    key = paramiko.RSAKey.generate(1024)
    body = key.get_name() + ' ' + key.get_base64() + '\n'
    lines = ['|1|!!notbase64!!|!!notbase64!! ' + body,      # malformed base64
             '|1|c2FsdA== ' + body,                          # missing field
             '|2|c2FsdA==|aGFzaA== ' + body]                 # unsupported version
    kh.write_text(''.join(lines))
    monkeypatch.setattr(ssh_security, '_KNOWN_HOSTS', str(kh))
    assert ssh_security.remove_host_keys({'192.168.88.15'}) == 0
    assert kh.read_text() == ''.join(lines)


def test_comma_separated_hashed_aliases(tmp_path, monkeypatch):
    kh = tmp_path / 'known_hosts'
    key = paramiko.RSAKey.generate(1024)
    other = _hashed('192.168.88.99', key).split(' ', 1)[0]
    mine = _hashed('192.168.88.15', key).split(' ', 1)[0]
    kh.write_text('%s,%s %s %s\n' % (other, mine, key.get_name(), key.get_base64()))
    monkeypatch.setattr(ssh_security, '_KNOWN_HOSTS', str(kh))
    assert ssh_security.remove_host_keys({'192.168.88.15'}) == 1
    assert kh.read_text() == ''
