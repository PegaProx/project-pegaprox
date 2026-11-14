"""What the first run against a real QNetd host found.

  1. The CA a QNetd host hands out is the qnetd-cacert.crt of corosync-qnetd-certutil, and
     the helper's own init writes it the same way: certutil's listing of the CA first, the
     PEM after it. PegaProx took only PEM or DER and refused every real host with "the CA
     in the answer is no certificate". The pin is on the certificate itself, so the same
     CA keeps its pin when the listing in front of it reads differently.
  2. A QNetd host without a way to its package sources (the lab container had a gateway
     but no internet) held Check for the full 600 s and then said only "the helper did not
     answer init": apt-get waited on every package, tried each again, then the update and
     the second install waited once more. The helper now asks apt where it would fetch
     from and tries those hosts first (one lookup and one connect each, 15 s at most), and
     all of its apt-get runs together end before PegaProx stops waiting. The preflight of a
     setup that installs corosync-qdevice does the same on every node that lacks it.

MK Oct 2026
"""
import base64
import datetime
import hashlib
import os
import shutil
import socket
import subprocess
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pegaprox.core import qnetd


def _ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'QNet CA')])
    now = datetime.datetime(2026, 10, 21, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(101)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER), cert.public_bytes(serialization.Encoding.PEM)


def _stock_file(pem, listing_note=b''):
    # what corosync-qnetd-certutil -i writes: certutil -L -n "QNet CA", then the same with -a
    listing = (b'Certificate:\n    Data:\n        Version: 3 (0x2)\n        Serial Number: 101 (0x65)\n'
               b'        Issuer: "CN=QNet CA"\n        Subject: "CN=QNet CA"\n' + listing_note +
               b'    Certificate Trust Flags:\n        SSL Flags:\n            Valid CA\n\n')
    return listing + pem.replace(b'\n', b'\r\n', 2)


def _answer(raw):
    return {'ok': True, 'ca_b64': base64.b64encode(raw).decode()}


def test_the_stock_ca_file_is_a_certificate():
    der, pem = _ca()
    stock = _stock_file(pem)
    assert stock.startswith(b'Certificate:')
    assert qnetd._looks_like_pem_or_der(stock, 'crt')
    raw, fp = qnetd._ca_fingerprint(_answer(stock))
    # the nodes get the file as it is, corosync-qdevice-net-certutil -i reads that form
    assert raw == stock
    assert fp == hashlib.sha256(der).hexdigest()


def test_the_same_ca_keeps_its_pin_in_every_form():
    der, pem = _ca()
    pins = {qnetd._ca_fingerprint(_answer(form))[1]
            for form in (_stock_file(pem), _stock_file(pem, b'        Fingerprint (SHA-256):\n'), pem)}
    assert pins == {hashlib.sha256(der).hexdigest()}


@pytest.mark.parametrize('raw', [
    b'Certificate:\n    Data:\n        Version: 3 (0x2)\n',                    # a listing alone
    b'Certificate:\n-----BEGIN CERTIFICATE-----\n!!not base64!!\n-----END CERTIFICATE-----\n',
    b'Certificate request:\n-----BEGIN NEW CERTIFICATE REQUEST-----\nQUFB\n-----END NEW CERTIFICATE REQUEST-----\n',
])
def test_a_listing_without_a_certificate_is_still_refused(raw):
    assert not qnetd._looks_like_pem_or_der(raw, 'crt')
    with pytest.raises(qnetd.HelperError):
        qnetd._ca_fingerprint(_answer(raw))


def test_requests_and_signed_certificates_are_read_as_before():
    der, pem = _ca()
    assert qnetd._looks_like_pem_or_der(der, 'crt')
    assert qnetd._looks_like_pem_or_der(pem, 'crt')
    assert not qnetd._looks_like_pem_or_der(pem, 'crq')
    # a listing in front is only how a CA comes, never a certificate request
    assert not qnetd._looks_like_pem_or_der(_stock_file(pem), 'crq')


# --- 2. package sources out of reach -----------------------------------------------------------

import test_qnetd_helper as qh                                       # noqa: E402
from test_qnetd_core import FakeCluster, _agree, _checks, _clean, _run, world   # noqa: E402,F401

H = qh.H

# apt-get and apt-config as far as the probe and an install ask them: the answers come from
# files next to them (the helper hands its children a clean environment)
FAKE_APT = r'''#!/bin/sh
HERE=$(dirname "$0")
echo "apt-get $*" >> "$HERE/calls.txt"
case " $* " in
  *" --print-uris "*) [ -f "$HERE/uris.txt" ] && cat "$HERE/uris.txt"; exit "$(cat "$HERE/uris.rc" 2>/dev/null || echo 0)" ;;
  *" indextargets "*) [ -f "$HERE/repos.txt" ] && cat "$HERE/repos.txt"; exit 0 ;;
  *" update "*) exit 0 ;;
esac
if [ -f "$HERE/apt-fails.txt" ]; then cat "$HERE/apt-fails.txt" >&2; exit 100; fi
cp -p "$HERE"/apt-stash/* "$HERE"/
exit 0
'''

FAKE_APT_CONFIG = r'''#!/bin/sh
HERE=$(dirname "$0")
echo 'APT "";'
echo 'APT::Architecture "amd64";'
[ -f "$HERE/proxy.txt" ] && cat "$HERE/proxy.txt"
exit 0
'''


def _put(d, name, text):
    with open(os.path.join(d, name), 'w') as fh:
        fh.write(text)


def _uris(d, uris, rc=0):
    _put(d, 'uris.txt', ''.join(f"'{u}' x.deb 1 SHA256:00\n" for u in uris))
    _put(d, 'uris.rc', str(rc))


def _closed_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def mirror():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    s.listen(16)
    yield s.getsockname()[1]
    s.close()


@pytest.fixture
def box(tmp_path):
    """A QNetd host where init has to install corosync-qnetd and the NSS tools."""
    b = qh.FakeBins(tmp_path)
    b.write('apt-get', FAKE_APT)
    b.write('apt-config', FAKE_APT_CONFIG)
    stash = os.path.join(b.bin, 'apt-stash')
    os.makedirs(stash)
    for name in ('certutil', 'corosync-qnetd'):
        shutil.move(os.path.join(b.bin, name), os.path.join(stash, name))
    return b


def _installs(b):
    return [c for c in b.calls() if c.startswith('apt-get') and ' install ' in c and '--print-uris' not in c]


def test_without_a_way_to_its_sources_init_says_so_in_seconds(box):
    port = _closed_port()
    _uris(box.bin, [f'http://127.0.0.1:{port}/debian/pool/main/c/corosync-qnetd.deb'])
    started = time.monotonic()
    rc, ans = box.helper('init')
    assert time.monotonic() - started < 10
    assert rc == 1 and ans['code'] == 'no_package_sources', ans
    assert f'127.0.0.1: no connection to port {port}' in ans['error']
    assert 'install corosync-qnetd libnss3-tools by hand' in ans['error']
    # apt-get itself never ran: nothing installed, nothing half done
    assert _installs(box) == [] and not os.path.exists(os.path.join(box.bin, 'corosync-qnetd'))
    assert not os.path.exists(box.db)


def test_a_name_that_does_not_resolve_is_named(box):
    _uris(box.bin, ['http://pegaprox-no-such-mirror.invalid/debian/pool/x.deb'])
    rc, ans = box.helper('init')
    assert rc == 1 and ans['code'] == 'no_package_sources', ans
    # NXDOMAIN where there is a resolver, a lookup that never answers where there is none
    assert 'pegaprox-no-such-mirror.invalid: no ' in ans['error']
    assert _installs(box) == []


def test_one_source_that_answers_is_enough(box, mirror):
    _uris(box.bin, [f'http://127.0.0.1:{_closed_port()}/a.deb'])
    _put(box.bin, 'repos.txt', f'http://127.0.0.1:{mirror}/debian/\n')
    rc, ans = box.helper('init')
    assert rc == 0 and ans['installed'] is True, ans
    assert len(_installs(box)) == 1


@pytest.mark.parametrize('setup', ['proxy', 'file_source', 'mirror_method', 'no_lists_no_sources'])
def test_what_the_probe_cannot_tell_is_left_to_apt_get(box, setup):
    closed = f'http://127.0.0.1:{_closed_port()}/a.deb'
    if setup == 'proxy':
        _uris(box.bin, [closed])
        _put(box.bin, 'proxy.txt', 'Acquire::http::Proxy "http://192.0.2.1:3128/";\n')
    elif setup == 'file_source':
        _uris(box.bin, [], rc=100)
        _put(box.bin, 'repos.txt', f'{closed}\nfile:/srv/mirror/debian/\n')
    elif setup == 'mirror_method':
        _uris(box.bin, [], rc=100)
        _put(box.bin, 'repos.txt', 'mirror+file:/etc/apt/mirrors.txt\n')
    else:
        _uris(box.bin, [], rc=100)
    rc, ans = box.helper('init')
    assert rc == 0 and ans['installed'] is True, ans
    if setup == 'proxy':
        # a proxy in apt's configuration: apt-get is not even asked for its sources
        assert not [c for c in box.calls() if '--print-uris' in c]


def test_nothing_to_fetch_tries_no_host(box):
    _uris(box.bin, [])
    rc, ans = box.helper('init')
    assert rc == 0 and ans['installed'] is True, ans
    assert not [c for c in box.calls() if 'indextargets' in c]


def test_apt_get_that_cannot_reach_a_source_is_named_as_such(box, mirror):
    _uris(box.bin, [f'http://127.0.0.1:{mirror}/a.deb'])
    _put(box.bin, 'apt-fails.txt', "Err:1 http://deb.debian.org/debian trixie/main amd64 corosync-qnetd\n"
                                   "  Temporary failure resolving 'deb.debian.org'\n"
                                   "E: Unable to fetch some archives, maybe run apt-get update\n")
    rc, ans = box.helper('init')
    assert rc == 1 and ans['code'] == 'no_package_sources', ans
    assert "Temporary failure resolving 'deb.debian.org'" in ans['error']
    assert len(_installs(box)) == 2 and len([c for c in box.calls() if ' update' in c]) == 1


def test_every_apt_get_of_an_init_ends_before_pegaprox_stops_waiting():
    # the probe, then install, update and install again on one deadline, then certutil and
    # systemctl: all inside the time PegaProx gives init
    assert H.T_PROBE + H.T_APT + H.T_KEYGEN / 3 < qnetd.OP_TIMEOUT['init']
    assert 'apt-config' in H.BINARIES and all(os.path.isabs(p) for p in H.BINARIES['apt-config'])


@pytest.mark.parametrize('netloc,want', [
    ('deb.debian.org', ('deb.debian.org', 80)),
    ('user:secret@mirror.example:8080', ('mirror.example', 8080)),
    ('[2001:db8::7]:3142', ('2001:db8::7', 3142)),
    ('[2001:db8::7]', ('2001:db8::7', 80)),
])
def test_source_hosts_are_read_as_apt_writes_them(tmp_path, netloc, want):
    b = qh.FakeBins(tmp_path)
    b.write('apt-get', FAKE_APT)
    b.write('apt-config', FAKE_APT_CONFIG)
    _uris(b.bin, [f'http://{netloc}/debian/pool/x.deb'])
    host = H.Host.__new__(H.Host)
    host.bin_dir = b.bin
    assert H._apt_targets(host, os.path.join(b.bin, 'apt-get')) == [want]


@pytest.mark.parametrize('netloc', ['ev$(id)il', 'host:99999', '[::1', 'x\x00y'])
def test_a_source_host_of_a_strange_shape_stops_the_probe(tmp_path, netloc):
    b = qh.FakeBins(tmp_path)
    b.write('apt-get', FAKE_APT)
    b.write('apt-config', FAKE_APT_CONFIG)
    _put(b.bin, 'uris.txt', f"'http://{netloc}/x.deb' x.deb 1 SHA256:00\n")
    host = H.Host.__new__(H.Host)
    host.bin_dir = b.bin
    assert H._apt_targets(host, os.path.join(b.bin, 'apt-get')) is None


# --- the same on the nodes, in the preflight ----------------------------------------------------

NEEDS = [shutil.which(t) for t in ('bash', 'getent', 'timeout')]


def _node(tmp_path, *, uris=None, uris_rc=0, repos='', proxy=''):
    d = tmp_path / 'nodebin'
    d.mkdir(exist_ok=True)
    for name, text in (('apt-get', FAKE_APT), ('apt-config', FAKE_APT_CONFIG)):
        (d / name).write_text(text)
        (d / name).chmod(0o755)
    _uris(str(d), uris or [], rc=uris_rc)
    _put(str(d), 'repos.txt', repos)
    if proxy:
        _put(str(d), 'proxy.txt', proxy)
    started = time.monotonic()
    p = subprocess.run(['bash', '-c', qnetd.SOURCES_SCRIPT], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env={'PATH': f'{d}:/usr/bin:/bin', 'HOME': str(tmp_path)}, cwd=str(tmp_path), timeout=60)
    assert p.returncode == 0, p.stderr
    return qnetd._kv(p.stdout.decode()), time.monotonic() - started, d


needs_tools = pytest.mark.skipif(not all(NEEDS), reason='bash, getent or timeout missing')


@needs_tools
def test_a_node_without_its_sources_is_told_in_seconds(tmp_path):
    port = _closed_port()
    kv, took, _d = _node(tmp_path, uris=[f'http://127.0.0.1:{port}/debian/pool/corosync-qdevice.deb'])
    assert kv['src'] == 'none' and kv['why'] == f'127.0.0.1: no connection to port {port}'
    assert took < 15


@needs_tools
def test_a_node_that_reaches_one_source_passes(tmp_path, mirror):
    kv, _took, _d = _node(tmp_path, uris=[f'http://127.0.0.1:{_closed_port()}/a.deb'],
                          repos=f'http://127.0.0.1:{mirror}/debian/\nhttp://127.0.0.1:{mirror}/debian-security/\n')
    assert kv == {'src': 'ok'}


@needs_tools
def test_a_node_without_lists_is_asked_about_its_configured_sources(tmp_path):
    port = _closed_port()
    kv, _took, _d = _node(tmp_path, uris_rc=100, repos=f'https://127.0.0.1:{port}/debian/pve/\n')
    assert kv['src'] == 'none' and kv['why'] == f'127.0.0.1: no connection to port {port}'


@needs_tools
@pytest.mark.parametrize('case', ['proxy', 'file', 'mirror', 'many', 'strange_host'])
def test_what_a_node_cannot_tell_is_left_to_apt_get(tmp_path, case):
    closed = f'http://127.0.0.1:{_closed_port()}/a.deb'
    kw = {'uris': [closed]}
    if case == 'proxy':
        kw['proxy'] = 'Acquire::https::Proxy "http://192.0.2.1:3128";\n'
    elif case == 'file':
        kw['repos'] = 'file:/srv/mirror/\n'
    elif case == 'mirror':
        kw['repos'] = 'mirror+http://192.0.2.1/mirrors.txt\n'
    elif case == 'many':
        kw['repos'] = ''.join(f'http://192.0.2.{i}/debian/\n' for i in range(1, 18))
    else:
        kw['uris'] = [f'http://ev$(touch {tmp_path}/pwned)il/x.deb']
    kv, _took, _d = _node(tmp_path, **kw)
    assert kv == {'src': 'unknown'}
    assert not (tmp_path / 'pwned').exists()


@needs_tools
def test_a_node_with_nothing_to_fetch_passes_without_a_probe(tmp_path):
    kv, _took, d = _node(tmp_path, uris=[])
    assert kv == {'src': 'ok'}
    with open(d / 'calls.txt') as fh:
        assert 'indextargets' not in fh.read()


def _sources_answer(world, monkeypatch, answers):
    orig = world.cluster.answer

    def answer(node, script, data):
        if script == getattr(qnetd, 'SOURCES_SCRIPT', None):
            return answers.get(node, (0, 'src=ok\n', ''))
        return orig(node, script, data)
    monkeypatch.setattr(world.cluster, 'answer', answer)


def _sources_asked(world):
    return [n for n, s, d in world.cluster.all_calls() if s == getattr(qnetd, 'SOURCES_SCRIPT', None)]


def test_the_preflight_names_a_node_without_its_sources(world, monkeypatch):
    world.cluster.pkg['pve2'] = False
    _sources_answer(world, monkeypatch, {'pve2': (0, 'src=none\nwhy=deb.debian.org: no address\n', '')})
    report = qnetd.inspect('c1', world.mgr, world.rec(), install_packages=True)
    pk = next(c for c in report['checks'] if c['id'] == 'packages')
    assert pk['ok'] is False and report['ok'] is False
    assert 'pve2 (deb.debian.org: no address)' in pk['message'] and 'by hand' in pk['message']
    # asked only of the node that lacks the package
    assert _sources_asked(world) == ['pve2']


def test_a_setup_stops_in_the_preflight_and_never_runs_apt_get(world, monkeypatch):
    world.cluster.pkg['pve2'] = False
    _sources_answer(world, monkeypatch, {'pve2': (0, 'src=none\nwhy=deb.debian.org: no address\n', '')})
    job = qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', '')
    view = _run(job, qnetd.run_setup, world.rec(), _agree(world, {'install_packages': True}))
    assert view['state'] != 'done'
    assert not [n for n, s, d in world.cluster.all_calls() if s == qnetd.APT_SCRIPT]
    assert not world.cluster.conf_written


@pytest.mark.parametrize('answer', [(0, 'src=ok\n', ''), (0, 'src=unknown\n', ''), (1, '', 'broke'), None])
def test_a_node_whose_sources_are_fine_or_unknown_goes_on(world, monkeypatch, answer):
    world.cluster.pkg['pve2'] = False
    _sources_answer(world, monkeypatch, {'pve2': answer})
    assert qnetd.inspect('c1', world.mgr, world.rec(), install_packages=True)['ok'] is True


def test_the_sources_are_not_asked_without_an_install(world, monkeypatch):
    world.cluster.pkg['pve2'] = False
    _sources_answer(world, monkeypatch, {})
    assert _checks(qnetd.inspect('c1', world.mgr, world.rec()))['packages'] is False
    assert _sources_asked(world) == []
    world.cluster.pkg['pve2'] = True
    assert qnetd.inspect('c1', world.mgr, world.rec(), install_packages=True)['ok'] is True
    assert _sources_asked(world) == []


# --- a rollback that did not go through on a node ----------------------------------------------

def test_a_node_that_could_not_clean_up_fails_the_rollback(world, monkeypatch):
    world.cluster.fail['p12'] = 1
    orig = world.cluster.answer

    def answer(node, script, data):
        if script == qnetd.CLEANUP_SCRIPT and node == 'pve2':
            return 1, '', "rm: cannot remove '/etc/corosync/qdevice': Read-only file system"
        return orig(node, script, data)
    monkeypatch.setattr(world.cluster, 'answer', answer)
    job = qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', '')
    view = _run(job, qnetd.run_setup, world.rec(), _agree(world))
    row = view['clusters']['c1']
    assert view['state'] == 'failed' and row['rolled_back'] is False
    rb = [s for s in view['steps'] if s['step'] == 'rollback']
    assert any(s['state'] == 'failed' and 'pve2: rm: cannot remove' in s['message'] for s in rb)
    assert not any(s['state'] == 'ok' and 'removed from every node' in s['message'] for s in rb)
