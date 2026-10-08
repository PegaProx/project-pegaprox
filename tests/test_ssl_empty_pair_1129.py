# #1129: the 1.3.0 VM appliance shipped config/ssl/cert.pem and key.pem at 0 bytes.
# Its image build booted PegaProx once and killed the VM right after the self-signed
# pair was generated, before the data reached the disk. Every start on a user's VM
# then found both files present, could not load them and refused to come up (#633
# fail-closed), so the service never started.
#
# An empty pair holds no key material, so it is treated like a missing one and
# generated. A pair where one half has content still fails closed: regenerating
# would throw that half away. And generation writes through a temp file + rename,
# so an interrupted write can no longer leave empty files behind. MK Oct 2026

import os
import stat

import pytest

from pegaprox import app as app_module


def _resolve(cert, key):
    return app_module._resolve_ssl_context(reverse_proxy=False, cert_file=str(cert), key_file=str(key))


@pytest.fixture
def ssl_dir(tmp_path):
    d = tmp_path / 'ssl'
    d.mkdir()
    return d / 'cert.pem', d / 'key.pem'


def _loads(cert, key):
    return app_module._unloadable(str(cert), str(key)) is None


def test_an_empty_pair_is_generated(ssl_dir):
    cert, key = ssl_dir
    cert.write_bytes(b'')
    key.write_bytes(b'')

    assert _resolve(cert, key) == (str(cert), str(key))
    assert cert.read_bytes().startswith(b'-----BEGIN CERTIFICATE-----')
    assert _loads(cert, key)
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600


def test_an_empty_cert_next_to_a_missing_key_is_generated(ssl_dir):
    cert, key = ssl_dir
    cert.write_bytes(b'')

    assert _resolve(cert, key) == (str(cert), str(key))
    assert _loads(cert, key)


@pytest.mark.parametrize('empty', ['cert', 'key'])
def test_one_empty_half_next_to_real_content_still_refuses(ssl_dir, empty):
    cert, key = ssl_dir
    app_module._generate_self_signed(str(cert), str(key), 'pegaprox.test', 'PegaProx')
    kept = key if empty == 'cert' else cert
    before = kept.read_bytes()
    (cert if empty == 'cert' else key).write_bytes(b'')

    with pytest.raises(SystemExit):
        _resolve(cert, key)
    assert kept.read_bytes() == before


def test_generation_leaves_no_temp_files_and_a_loadable_pair(ssl_dir):
    cert, key = ssl_dir
    app_module._generate_self_signed(str(cert), str(key), 'pegaprox.test', 'PegaProx')

    assert sorted(p.name for p in cert.parent.iterdir()) == ['cert.pem', 'key.pem']
    assert _loads(cert, key)
    assert stat.S_IMODE(os.stat(cert).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600


def test_a_failed_write_does_not_leave_an_empty_target(ssl_dir, monkeypatch):
    cert, key = ssl_dir
    real_fsync = os.fsync

    def failing_fsync(fd):
        raise OSError(5, 'Input/output error')

    monkeypatch.setattr(os, 'fsync', failing_fsync)
    with pytest.raises(OSError):
        app_module._generate_self_signed(str(cert), str(key), 'pegaprox.test', 'PegaProx')
    monkeypatch.setattr(os, 'fsync', real_fsync)

    assert not key.exists() and not cert.exists()
    # and the next start generates a fresh pair over the leftover temp file
    assert _resolve(cert, key) == (str(cert), str(key))
    assert _loads(cert, key)


def test_short_writes_still_produce_the_whole_file(ssl_dir, monkeypatch):
    cert, key = ssl_dir
    real_write = os.write

    def short_write(fd, data):
        return real_write(fd, bytes(data[:100]))

    monkeypatch.setattr(os, 'write', short_write)
    app_module._generate_self_signed(str(cert), str(key), 'pegaprox.test', 'PegaProx')
    monkeypatch.setattr(os, 'write', real_write)

    assert key.read_bytes().rstrip().endswith(b'-----END PRIVATE KEY-----')
    assert cert.read_bytes().rstrip().endswith(b'-----END CERTIFICATE-----')
    assert _loads(cert, key)


def test_a_write_that_runs_out_of_space_leaves_the_target_alone(ssl_dir, monkeypatch):
    cert, key = ssl_dir
    key.write_bytes(b'old key')
    real_write = os.write
    calls = []

    def filling_disk(fd, data):
        calls.append(fd)
        if len(calls) > 1:
            raise OSError(28, 'No space left on device')
        return real_write(fd, bytes(data[:100]))

    monkeypatch.setattr(os, 'write', filling_disk)
    with pytest.raises(OSError):
        app_module._write_atomic(str(key), b'x' * 1000, 0o600)
    monkeypatch.setattr(os, 'write', real_write)

    assert key.read_bytes() == b'old key'
