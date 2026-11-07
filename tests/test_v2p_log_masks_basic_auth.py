"""The V2P task log masks an HTTP Basic login, not only the plain ESXi password.

The 0-byte diagnostic in _ssh_pipe_transfer logs the head of `curl -v`, and curl -v prints
the request headers it sent, 'Authorization: Basic <base64 of user:password>' among them.
_redact masked the password in its plain, URL-encoded and shell-quoted forms only, so the
base64 form reached the task log, which the UI shows and SSE broadcasts. MK
"""
import base64

from pegaprox.core.v2p import V2PMigrationTask


def _task(pw='Esx1-pass word'):
    t = V2PMigrationTask.__new__(V2PMigrationTask)
    t.esxi_password = pw
    return t


def test_a_basic_header_of_the_esxi_login_is_masked():
    pw = 'Esx1-pass word'
    token = base64.b64encode(f'root:{pw}'.encode()).decode()
    out = _task(pw)._redact(f'> GET /folder/x HTTP/1.1\n> Authorization: Basic {token}\n> Host: esx')

    assert token not in out
    assert 'Authorization: Basic ********' in out
    assert '> Host: esx' in out


def test_any_basic_header_is_masked_whatever_its_case():
    token = base64.b64encode(b'admin:other').decode()
    out = _task()._redact(f'< x\n> authorization:   basic {token}\r\n')

    assert token not in out


def test_the_plain_password_stays_masked_and_other_text_untouched():
    out = _task('s3cret')._redact('qemu-img: auth failed for s3cret on host esx01')

    assert out == 'qemu-img: auth failed for ******** on host esx01'
