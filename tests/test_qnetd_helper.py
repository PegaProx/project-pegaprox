"""packaging/qnetd/pegaprox-qnetd-helper, run as a subprocess against a config directory of
the test (PEGAPROX_QNETD_CONFIG_DIR / _BIN_DIR, honoured for an unprivileged run only).

Two kinds of binaries. The stand-ins below (FakeBins) give certutil, systemctl,
corosync-qnetd(-tool) and apt-get: they run everywhere, CI included, and log what they
were asked. Where the real NSS tools are there (on PATH, or an unpacked corosync-qnetd /
corosync-qdevice / libnss3-tools under PEGAPROX_TEST_NSS_ROOT), the tests marked
`needs_nss` run the real certutil and the stock corosync-qnetd-certutil and
corosync-qdevice-net-certutil (copies with their fixed /etc paths pointed at the test)
against the helper, both ways round; without them they are skipped.

MK Oct 2026
"""
import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER = os.path.join(ROOT, 'packaging', 'qnetd', 'pegaprox-qnetd-helper')


def load_helper():
    sys.dont_write_bytecode, before = True, sys.dont_write_bytecode
    try:
        loader = importlib.machinery.SourceFileLoader('pegaprox_qnetd_helper_t', HELPER)
        mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
        loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = before
    return mod


H = load_helper()


def slurp(path):
    with open(path, 'rb') as fh:
        return fh.read()


# --- DER, to make requests without openssl --------------------------------------------------

def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


OID_CN = tlv(0x06, b'\x55\x04\x03')
RSA = tlv(0x30, tlv(0x06, bytes.fromhex('2a864886f70d010101')) + b'\x05\x00')
SHA256_RSA = tlv(0x30, tlv(0x06, bytes.fromhex('2a864886f70d01010b')) + b'\x05\x00')


def name_der(cn, tag=0x13):
    return tlv(0x30, tlv(0x31, tlv(0x30, OID_CN + tlv(tag, cn.encode()))))


def spki_der(seed):
    modulus = b'\x00' + hashlib.sha256(seed.encode()).digest() * 8
    return tlv(0x30, RSA + tlv(0x03, b'\x00' + tlv(0x30, tlv(0x02, modulus) + tlv(0x02, b'\x01\x00\x01'))))


def make_crq(cn, key='k1', attrs=b'', subject=None):
    """A PKCS#10 request shaped as corosync-qdevice-net-certutil -r makes it (the signature is
    not checked by the stand-in certutil, the real one checks it)."""
    cri = tlv(0x30, tlv(0x02, b'\x00') + (subject if subject is not None else name_der(cn))
              + spki_der(key) + tlv(0xa0, attrs))
    return tlv(0x30, cri + SHA256_RSA + tlv(0x03, b'\x00' + b'\x11' * 32))


# an extensionRequest asking for basicConstraints CA:TRUE, as openssl req -addext makes it
EXT_REQUEST = tlv(0x30, tlv(0x06, bytes.fromhex('2a864886f70d01090e')) + tlv(0x31, tlv(0x30, tlv(
    0x30, tlv(0x06, b'\x55\x1d\x13') + b'\x01\x01\xff' + tlv(0x04, tlv(0x30, b'\x01\x01\xff'))))))


# --- stand-ins ------------------------------------------------------------------------------
# The helper hands its children a clean environment (PATH, LANG, LC_ALL): the stand-ins read
# their settings from flag files next to themselves and log there.

FAKE_CERTUTIL = r'''#!PYTHON -I
import base64, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]


def flag(name):
    return os.path.exists(os.path.join(HERE, 'flag-' + name))


def opt(o):
    return args[args.index(o) + 1] if o in args else None


with open(os.path.join(HERE, 'calls.txt'), 'a') as fh:
    fh.write('certutil ' + ' '.join(args) + '\n')
with open(os.path.join(HERE, 'certutil.jsonl'), 'a') as fh:
    fh.write(json.dumps({'argv': args, 'env': sorted(os.environ), 'cwd': os.getcwd()}) + '\n')
db = opt('-d')


def load():
    with open(os.path.join(db, 'cert9.db')) as fh:
        return json.load(fh)


def save(d):
    with open(os.path.join(db, 'cert9.db'), 'w') as fh:
        json.dump(d, fh)


def ln(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + ln(len(body)) + body


def rd(buf, pos):
    tag, first = buf[pos], buf[pos + 1]
    pos += 2
    if first < 0x80:
        n = first
    else:
        k = first & 0x7f
        n = int.from_bytes(buf[pos:pos + k], 'big')
        pos += k
    return tag, pos, pos + n


if '-N' in args:
    os.makedirs(db, exist_ok=True)
    for n in ('cert9.db', 'key4.db', 'pkcs11.txt'):
        with open(os.path.join(db, n), 'w') as fh:
            fh.write('{}' if n == 'cert9.db' else 'x')
    sys.exit(0)
if '-S' in args:
    if '-x' in args and flag('fail-ca'):
        print('certutil: fake failure making the CA', file=sys.stderr)
        sys.exit(255)
    d = load()
    if opt('-c') and opt('-c') not in d:
        sys.exit(255)
    answers = sys.stdin.read() if '-2' in args else ''
    d[opt('-n')] = {'subject': opt('-s'), 'serial': opt('-m'), 'trust': opt('-t'), 'ca': '-x' in args,
                    'answers': answers, 'key': os.urandom(8).hex()}
    save(d)
    sys.exit(0)
if '-L' in args:
    d = load()
    nick = opt('-n')
    if nick not in d:
        print('certutil: Could not find cert: %s' % nick, file=sys.stderr)
        sys.exit(255)
    if '-a' in args:
        print('-----BEGIN CERTIFICATE-----')
        print(base64.b64encode(json.dumps(d[nick], sort_keys=True).encode()).decode())
        print('-----END CERTIFICATE-----')
    else:
        print('Certificate:\n    Subject: "%s"' % d[nick]['subject'])
    sys.exit(0)
if '-C' in args:
    out, crq = opt('-o'), opt('-i')
    with open(os.path.join(HERE, 'sign.jsonl'), 'a') as fh:
        fh.write(json.dumps({'dir': os.path.dirname(crq),
                             'mode': os.stat(os.path.dirname(crq)).st_mode & 0o777}) + '\n')
    open(out, 'wb').close()       # the real one leaves this behind when it fails
    if flag('fail-sign'):
        print('certutil: unable to create cert (fake)', file=sys.stderr)
        sys.exit(255)
    if opt('-c') not in load():
        sys.exit(255)
    der = open(crq, 'rb').read()
    _t, cs, _ce = rd(der, 0)
    _t, ics, _ice = rd(der, cs)
    _t, _vs, ve = rd(der, ics)
    _t, _ss, se = rd(der, ve)
    _t, _ks, ke = rd(der, se)
    subject, spki = der[ve:se], der[se:ke]
    if flag('other-key'):
        spki = spki[:-8] + b'\x42' * 8
    alg = tlv(0x30, tlv(0x06, bytes.fromhex('2a864886f70d01010b')) + b'\x05\x00')
    issuer = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, b'\x55\x04\x03') + tlv(0x13, b'QNet CA'))))
    validity = tlv(0x30, tlv(0x17, b'261020000000Z') + tlv(0x18, b'21261020000000Z'))
    tbs = tlv(0x30, tlv(0xa0, tlv(0x02, b'\x02')) + tlv(0x02, int(opt('-m')).to_bytes(4, 'big')) + alg
              + issuer + validity + subject + spki)
    with open(out, 'wb') as fh:
        fh.write(tlv(0x30, tbs + alg + tlv(0x03, b'\x00' + b'\x5a' * 32)))
    sys.exit(0)
sys.exit(2)
'''

# state-active is corosync-qnetd's; the other units (the helper socket) are only logged
FAKE_SYSTEMCTL = r'''#!/bin/sh
HERE=$(dirname "$0")
echo "systemctl $*" >> "$HERE/calls.txt"
case " $* " in *corosync-qnetd*) ;; *) exit 0 ;; esac
case "$1" in
    is-active) [ -f "$HERE/state-active" ] && exit 0; exit 3 ;;
    enable) case " $* " in *" --now "*) touch "$HERE/state-active" ;; esac; exit 0 ;;
    restart|start) touch "$HERE/state-active"; exit 0 ;;
    disable) rm -f "$HERE/state-active"; exit 0 ;;
esac
exit 0
'''

# -s prints status.txt (the TLS line of a running corosync-qnetd) where the test wrote one
FAKE_TOOL = r'''#!/bin/sh
HERE=$(dirname "$0")
echo "corosync-qnetd-tool $*" >> "$HERE/calls.txt"
[ -f "$HERE/state-tool-down" ] && { echo "Can't connect to QNetd socket" >&2; exit 1; }
case " $* " in *" -s "*) [ -f "$HERE/status.txt" ] && cat "$HERE/status.txt"; exit 0 ;; esac
[ -f "$HERE/listing.txt" ] && cat "$HERE/listing.txt"
exit 0
'''

FAKE_QNETD = r'''#!PYTHON -I
import os, signal, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, 'calls.txt'), 'a') as fh:
    fh.write('corosync-qnetd ' + ' '.join(sys.argv[1:]) + '\n')
if os.path.exists(os.path.join(HERE, 'state-qnetd-dies')):
    time.sleep(1)
    sys.exit(3)
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
while True:
    time.sleep(0.2)
'''

FAKE_APT = r'''#!/bin/sh
HERE=$(dirname "$0")
echo "apt-get $* DEBIAN_FRONTEND=${DEBIAN_FRONTEND:-}" >> "$HERE/calls.txt"
[ -d "$HERE/apt-stash" ] || exit 100
case " $* " in *" install "*) cp -p "$HERE"/apt-stash/* "$HERE"/ ;; esac
exit 0
'''

LISTING = '''QNetd address:			*:5403
TLS:				Supported (client certificate required)
Connected clients:		2
Connected clusters:		1
Cluster "PVE-Lab":
    Algorithm:		Fifty-Fifty split (KAP Tie-breaker)
    Tie-breaker:	Node with lowest node ID
    Node ID 1:
        Client address:		::ffff:192.0.2.11:41234
        HB interval:		8000ms
        Configured node list:	1, 2
        Ring ID:		1.1c
        Membership node list:	1, 2
        Heuristics:		Undefined (membership: Undefined, regular: Undefined)
        TLS active:		Yes (client certificate verified)
        Vote:			ACK (ACK)
    Node ID 2:
        Client address:		[2001:db8::12]:50122
        HB interval:		8000ms
        Configured node list:	1, 2
        Ring ID:		1.1c
        Membership node list:	1, 2
        Heuristics:		Undefined (membership: Undefined, regular: Undefined)
        TLS active:		Yes (client certificate verified)
        Vote:			No change (ACK)
'''


class FakeBins:
    """A bin directory of stand-ins (and, with real=, the real NSS binaries) plus the
    config and run directories of one test host."""

    def __init__(self, base, real=None):
        self.base = str(base)
        self.bin = os.path.join(self.base, 'bin')
        self.conf = os.path.join(self.base, 'etc', 'corosync', 'qnetd')
        self.run_dir = os.path.join(self.base, 'run')
        for d in (self.bin, self.conf, self.run_dir):
            os.makedirs(d, exist_ok=True)
        self.write('systemctl', FAKE_SYSTEMCTL)
        self.write('corosync-qnetd-tool', FAKE_TOOL)
        self.write('corosync-qnetd', FAKE_QNETD)
        self.write('apt-get', FAKE_APT)
        if real:
            os.symlink(real['certutil'], os.path.join(self.bin, 'certutil'))
        else:
            self.write('certutil', FAKE_CERTUTIL)

    def write(self, name, text, where=None):
        path = os.path.join(where or self.bin, name)
        with open(path, 'w') as fh:
            fh.write(text.replace('PYTHON', sys.executable))
        os.chmod(path, 0o755)
        return path

    def flag(self, name, on=True):
        path = os.path.join(self.bin, name)
        if on:
            open(path, 'w').close()
        elif os.path.exists(path):
            os.unlink(path)

    def listing(self, text):
        with open(os.path.join(self.bin, 'listing.txt'), 'w') as fh:
            fh.write(text)

    def calls(self):
        try:
            with open(os.path.join(self.bin, 'calls.txt')) as fh:
                return fh.read().splitlines()
        except FileNotFoundError:
            return []

    def jsonl(self, name):
        try:
            with open(os.path.join(self.bin, name)) as fh:
                return [json.loads(ln) for ln in fh if ln.strip()]
        except FileNotFoundError:
            return []

    @property
    def db(self):
        return os.path.join(self.conf, 'nssdb')

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith('PEGAPROX_QNETD_') and not k.startswith('SUDO_')}
        env.update(PEGAPROX_QNETD_CONFIG_DIR=self.conf, PEGAPROX_QNETD_BIN_DIR=self.bin,
                   PEGAPROX_QNETD_RUN_DIR=self.run_dir)
        env.update(extra)
        return env

    def helper(self, *args, stdin=None, raw=None, env=None):
        """(rc, answer) of one helper run."""
        data = raw if raw is not None else (json.dumps(stdin).encode() if stdin is not None else b'')
        proc = subprocess.run([sys.executable, '-I', HELPER] + list(args), input=data,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
                              env=env or self.env(), cwd=self.base)
        lines = proc.stdout.decode().splitlines()
        assert len(lines) == 1, (proc.stdout, proc.stderr)
        return proc.returncode, json.loads(lines[0])

    def sign(self, name, crq, **req):
        req['crq_b64'] = base64.b64encode(crq).decode()
        return self.helper('sign', '--name', name, stdin=req)


@pytest.fixture
def host(tmp_path):
    return FakeBins(tmp_path)


# --- the real NSS tools, where there are any -------------------------------------------------

def nss_tools():
    roots = [os.environ['PEGAPROX_TEST_NSS_ROOT']] if os.environ.get('PEGAPROX_TEST_NSS_ROOT') else []
    roots.append('/')
    for root in roots:
        certutil = os.path.join(root, 'usr', 'bin', 'certutil')
        if not os.access(certutil, os.X_OK):
            continue
        rc = subprocess.run([certutil, '-H'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=20).returncode
        if rc in (126, 127):
            continue
        return {'certutil': certutil, 'bin': os.path.dirname(certutil),
                'pk12util': os.path.join(root, 'usr', 'bin', 'pk12util'),
                'qnetd_certutil': os.path.join(root, 'usr', 'bin', 'corosync-qnetd-certutil'),
                'qdevice_certutil': os.path.join(root, 'usr', 'sbin', 'corosync-qdevice-net-certutil')}
    return None


NSS = nss_tools()
needs_nss = pytest.mark.skipif(NSS is None, reason='no NSS certutil here (CI): set PEGAPROX_TEST_NSS_ROOT')
needs_stock = pytest.mark.skipif(
    NSS is None or not shutil.which('bash')
    or not all(os.path.isfile(NSS[k]) for k in ('qnetd_certutil', 'qdevice_certutil', 'pk12util')),
    reason='no stock corosync certutil scripts here')


def stock_qnetd_certutil(where, conf):
    """corosync-qnetd-certutil with its CONFIG_DIR pointed at conf."""
    with open(NSS['qnetd_certutil']) as fh:
        text = fh.read()
    assert 'CONFIG_DIR="/etc/corosync/qnetd"' in text
    path = os.path.join(where, 'corosync-qnetd-certutil')
    with open(path, 'w') as fh:
        fh.write(text.replace('CONFIG_DIR="/etc/corosync/qnetd"', 'CONFIG_DIR="%s"' % conf))
    return path


def stock_node(where):
    """corosync-qdevice-net-certutil of one node, its /etc/corosync/qdevice/net under where."""
    with open(NSS['qdevice_certutil']) as fh:
        text = fh.read()
    assert 'BASE_DIR="/etc/corosync/qdevice/net"' in text
    os.makedirs(os.path.join(where, 'net'), exist_ok=True)
    path = os.path.join(where, 'corosync-qdevice-net-certutil')
    with open(path, 'w') as fh:
        fh.write(text.replace('BASE_DIR="/etc/corosync/qdevice/net"', 'BASE_DIR="%s"' % os.path.join(where, 'net')))
    return path


def bash(script, *args):
    env = dict(os.environ, PATH=NSS['bin'] + os.pathsep + os.environ['PATH'])
    return subprocess.run(['bash', script] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=120, env=env, cwd=os.path.dirname(script))


def node_crq(where, cluster, ca_file):
    """A request as a node makes it: corosync-qdevice-net-certutil -i, then -r -n."""
    tool = stock_node(where)
    assert bash(tool, '-i', '-c', ca_file).returncode == 0
    p = bash(tool, '-r', '-n', cluster)
    assert p.returncode == 0, p.stderr
    with open(os.path.join(where, 'net', 'nssdb', 'qdevice-net-node.crq'), 'rb') as fh:
        return tool, fh.read()


def nicks(db):
    out = subprocess.run([NSS['certutil'], '-L', '-d', db], stdout=subprocess.PIPE, timeout=30).stdout.decode()
    return sorted(ln.rsplit(None, 1)[0].strip() for ln in out.splitlines()[4:] if ln.strip())


def ca_pem(db):
    return subprocess.run([NSS['certutil'], '-L', '-d', db, '-n', 'QNet CA', '-a'], stdout=subprocess.PIPE,
                          timeout=30).stdout


# --- version, init ---------------------------------------------------------------------------

def test_version_names_the_protocol_and_what_is_installed(host):
    rc, ans = host.helper('version')
    assert rc == 0 and ans['ok'] is True
    assert ans['protocol'] == H.PROTOCOL == 2
    # protocol 2: the ops it takes and the package manager init would use
    assert ans['ops'] == ['version', 'init', 'ca', 'sign', 'status', 'uuid', 'firewall']
    assert ans['package_manager'] == 'apt' and ans['packages'] == ['corosync-qnetd', 'libnss3-tools']
    assert ans['qnetd_installed'] is True and ans['certutil_installed'] is True
    assert ans['initialised'] is False and ans['active'] is False and ans['mode'] == 'systemd'
    with open(HELPER, 'rb') as fh:
        assert ans['sha256'] == hashlib.sha256(fh.read()).hexdigest()
    os.unlink(os.path.join(host.bin, 'certutil'))
    rc, ans = host.helper('version')
    assert rc == 0 and ans['certutil_installed'] is False


def test_init_makes_the_ca_once_and_never_again(host):
    rc, ans = host.helper('init')
    assert rc == 0, ans
    assert ans == {'ok': True, 'active': True, 'created': True, 'installed': False, 'tls_set': False}
    names = sorted(os.listdir(host.db))
    # the files of corosync-qnetd-certutil -i, no others
    assert names == ['cert9.db', 'key4.db', 'noise.txt', 'pkcs11.txt', 'pwdfile.txt', 'qnetd-cacert.crt',
                     'serial.txt']
    with open(os.path.join(host.db, 'cert9.db')) as fh:
        db = json.load(fh)
    assert db['QNet CA']['subject'] == 'CN=QNet CA' and db['QNet CA']['trust'] == 'CT,,'
    assert db['QNet CA']['ca'] is True and db['QNet CA']['answers'] == 'y\n0\ny\n'
    assert db['QNetd Cert']['subject'] == 'CN=Qnetd Server' and db['QNetd Cert']['trust'] == 'u,u,u'
    assert (db['QNet CA']['serial'], db['QNetd Cert']['serial']) == ('101', '102')
    calls = [c['argv'] for c in host.jsonl('certutil.jsonl')]
    assert all(('-v' not in a) or a[a.index('-v') + 1] == '1200' for a in calls)
    assert oct(os.stat(host.db).st_mode & 0o777) == '0o750'
    for n in ('cert9.db', 'key4.db', 'pwdfile.txt', 'noise.txt', 'serial.txt'):
        assert oct(os.stat(os.path.join(host.db, n)).st_mode & 0o777) == '0o640', n
    assert 'systemctl enable --now corosync-qnetd.service' in host.calls()

    before = {n: slurp(os.path.join(host.db, n)) for n in names}
    rc, ans = host.helper('init')
    assert rc == 0 and ans['created'] is False and ans['active'] is True
    after = {n: slurp(os.path.join(host.db, n)) for n in sorted(os.listdir(host.db))}
    assert after == before
    assert not [a for a in [c['argv'] for c in host.jsonl('certutil.jsonl')][len(calls):] if '-S' in a or '-N' in a]


def test_init_puts_back_a_missing_export_and_never_touches_a_foreign_database(host):
    assert host.helper('init')[0] == 0
    ca_file = os.path.join(host.db, 'qnetd-cacert.crt')
    first = slurp(ca_file)
    os.unlink(ca_file)
    rc, ans = host.helper('init')
    assert rc == 0 and ans['created'] is False
    assert slurp(ca_file) == first
    # a database without the QNet CA is someone else's: left alone, init refuses
    with open(os.path.join(host.db, 'cert9.db'), 'w') as fh:
        json.dump({'Other': {'subject': 'CN=x'}}, fh)
    rc, ans = host.helper('init')
    assert rc == 1 and ans['code'] == 'not_initialised'
    with open(os.path.join(host.db, 'cert9.db')) as fh:
        assert json.load(fh) == {'Other': {'subject': 'CN=x'}}


def test_init_takes_back_a_half_made_database(host):
    host.flag('flag-fail-ca')
    rc, ans = host.helper('init')
    assert rc == 1 and 'making the CA' in ans['error'] and 'fake failure' in ans['error']
    # nothing of the failed run stays: the next init starts clean instead of finding a
    # database without a CA
    assert not os.path.exists(host.db)
    host.flag('flag-fail-ca', on=False)
    rc, ans = host.helper('init')
    assert rc == 0 and ans['created'] is True


def test_init_installs_the_packages_with_apt_get_only_where_missing(host):
    stash = os.path.join(host.bin, 'apt-stash')
    os.makedirs(stash)
    for name in ('certutil', 'corosync-qnetd'):
        shutil.move(os.path.join(host.bin, name), os.path.join(stash, name))
    rc, ans = host.helper('init')
    assert rc == 0 and ans['installed'] is True and ans['created'] is True, ans
    apt = [c for c in host.calls() if c.startswith('apt-get')]
    assert apt == ['apt-get -q -y -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confdef '
                   '-o Dpkg::Options::=--force-confold install --no-install-recommends corosync-qnetd '
                   'libnss3-tools DEBIAN_FRONTEND=noninteractive']
    rc, ans = host.helper('init')
    assert rc == 0 and ans['installed'] is False
    assert len([c for c in host.calls() if c.startswith('apt-get')]) == 1


def test_init_without_apt_get_says_what_to_install(host):
    os.unlink(os.path.join(host.bin, 'corosync-qnetd'))
    os.unlink(os.path.join(host.bin, 'apt-get'))
    rc, ans = host.helper('init')
    assert rc == 1 and ans['code'] == 'not_installed'
    assert 'no apt-get' in ans['error'] and 'nss-tools' in ans['error']
    assert not os.path.exists(host.db)


def test_children_get_a_clean_environment_and_absolute_paths(host):
    env = host.env(SECRET_TOKEN='do-not-pass', LD_PRELOAD='/nowhere.so', PYTHONPATH='/nowhere')
    rc, _ans = host.helper('init', env=env)
    assert rc == 0
    rows = host.jsonl('certutil.jsonl')
    assert rows
    for row in rows:
        assert set(row['env']) <= {'PATH', 'LANG', 'LC_ALL', 'LC_CTYPE'}, row['env']
        assert row['cwd'] == '/'


def test_the_helper_source_keeps_to_its_rules():
    with open(HELPER) as fh:
        text = fh.read()
    assert text.startswith('#!/usr/bin/python3 -I\n')
    assert 'shell=True' not in text and 'os.system' not in text and 'os.popen' not in text
    # one place runs commands, always with a timeout and a clean environment
    assert text.count('subprocess.run(') == 1
    assert 'timeout=timeout, env=env' in text
    assert text.count('subprocess.Popen(') == 1      # corosync-qnetd under the sidecar
    for path in sum(H.BINARIES.values(), ()):
        assert os.path.isabs(path)
    assert chr(0x2014) not in text
    import re
    assert re.search(r'^PROTOCOL = 2$', text, re.M)


# --- the command line ------------------------------------------------------------------------

@pytest.mark.parametrize('argv', [
    [], ['bogus'], ['version', 'x'], ['version', '--name', 'pve'], ['init', '--force'], ['status', '-v'],
    ['sign'], ['sign', '--name'], ['sign', '--name=pve'], ['sign', '-n', 'pve'],
    ['sign', '--name', 'pve', '--name', 'x'], ['sign', '--name', 'pve', 'extra'], ['--name', 'pve', 'sign'],
    ['uuid', '--', 'x'], ['firewall'], ['firewall', '--name'], ['firewall', '--name=pve'], ['firewall', 'pve'],
    ['firewall', '--name', 'pve', '--port', '22'], ['firewall', '--name', 'x;id'],
])
def test_strict_argv(host, argv):
    rc, ans = host.helper(*argv)
    assert rc == 1 and ans['ok'] is False and ans['code'] == 'bad_request'
    assert not host.jsonl('certutil.jsonl')


@pytest.mark.parametrize('name', ['', '-pve', 'pve-', 'a' * 16, 'p.ve', 'p ve', '../x', 'x;id', 'x/y', 'pve\n',
                                  'üml', '*', 'pve$(id)', 'cluster_1'])
def test_sign_refuses_a_name_outside_the_allowlist(host, name):
    assert host.helper('init')[0] == 0
    rc, ans = host.sign(name, make_crq(name or 'x'))
    assert rc == 1 and ans['code'] == 'bad_request' and 'name' in ans['error']
    assert not host.jsonl('sign.jsonl')


@pytest.mark.parametrize('name', ['a', 'pve', 'PVE-Lab-01', 'a' * 15, '2node'])
def test_sign_takes_a_name_inside_the_allowlist(host, name):
    assert host.helper('init')[0] == 0
    rc, ans = host.sign(name, make_crq(name))
    assert rc == 0, ans


def test_stdin_is_capped_and_has_to_be_a_request(host):
    assert host.helper('init')[0] == 0
    big = json.dumps({'crq_b64': 'A' * (70 * 1024)}).encode()
    rc, ans = host.helper('sign', '--name', 'pve', raw=big)
    assert rc == 1 and ans['code'] == 'bad_request' and 'larger than' in ans['error']
    for raw in (b'[1, 2]', b'not json', b'\xff\xfe', b''):
        rc, ans = host.helper('sign', '--name', 'pve', raw=raw)
        assert rc == 1 and ans['code'] == 'bad_request', raw
    rc, ans = host.helper('sign', '--name', 'pve', stdin={'crq_b64': base64.b64encode(make_crq('pve')).decode(),
                                                          'force': True})
    assert rc == 1 and 'takes no force' in ans['error']
    rc, ans = host.helper('sign', '--name', 'pve', stdin={'crq_b64': 'not base64!'})
    assert rc == 1 and ans['code'] == 'bad_request'
    # 16 KiB of request at most, decoded
    rc, ans = host.sign('pve', make_crq('pve') + b'\x00' * (17 * 1024))
    assert rc == 1 and 'too large' in ans['error']
    assert not host.jsonl('sign.jsonl')


# --- sign ------------------------------------------------------------------------------------

def test_sign_gives_the_certificate_and_files_it_as_the_stock_tool(host):
    assert host.helper('init')[0] == 0
    crq = make_crq('pve')
    rc, ans = host.sign('pve', crq)
    assert rc == 0 and ans['replaced'] is False
    crt = base64.b64decode(ans['crt_b64'])
    with open(os.path.join(host.db, 'cluster-pve.crt'), 'rb') as fh:
        assert fh.read() == crt
    cn, key = H.parse_cert(crt)
    assert cn == 'pve' and key == H.parse_crq(crq)[1]
    argv = [c['argv'] for c in host.jsonl('certutil.jsonl') if '-C' in c['argv']][0]
    assert argv[argv.index('-v') + 1] == '1200' and argv[argv.index('-c') + 1] == 'QNet CA'
    assert argv[argv.index('-m') + 1] == '103'
    with open(os.path.join(host.db, 'serial.txt')) as fh:
        assert fh.read() == '103\n'
    # the request went to certutil from a private directory, gone afterwards
    signed = host.jsonl('sign.jsonl')
    assert signed[0]['mode'] == 0o700 and not os.path.exists(signed[0]['dir'])


def test_a_request_with_attributes_is_never_signed(host):
    """certutil -C copies requested extensions into the certificate: a basicConstraints
    CA:TRUE would make the cluster a sub-CA of the QNetd."""
    assert host.helper('init')[0] == 0
    rc, ans = host.sign('pve', make_crq('pve', attrs=EXT_REQUEST))
    assert rc == 1 and ans['code'] == 'bad_request' and 'attributes' in ans['error']
    assert not host.jsonl('sign.jsonl')
    assert not os.path.exists(os.path.join(host.db, 'cluster-pve.crt'))


@pytest.mark.parametrize('subject', [
    tlv(0x30, b''),                                                          # no CN at all
    tlv(0x30, tlv(0x31, tlv(0x30, OID_CN + tlv(0x13, b'pve'))) * 2),          # two RDNs
    tlv(0x30, tlv(0x31, tlv(0x30, OID_CN + tlv(0x13, b'pve')) * 2)),          # two values in one
    tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, b'\x55\x04\x0a') + tlv(0x13, b'pve')))),   # O=, not CN=
    tlv(0x30, tlv(0x31, tlv(0x30, OID_CN + tlv(0x04, b'pve')))),             # not a string type
])
def test_the_subject_has_to_be_exactly_cn_of_the_cluster(host, subject):
    assert host.helper('init')[0] == 0
    rc, ans = host.sign('pve', make_crq('pve', subject=subject))
    assert rc == 1 and ans['code'] == 'bad_request'
    assert not host.jsonl('sign.jsonl')


def test_a_request_for_another_name_or_no_request_at_all_is_refused(host):
    assert host.helper('init')[0] == 0
    rc, ans = host.sign('pve', make_crq('other'))
    assert rc == 1 and 'is for "other"' in ans['error']
    for junk in (b'\x30\x03\x02\x01\x00', b'hello', make_crq('pve')[:-3], make_crq('pve') + b'\x00',
                 b'\x30\x84\x00\x00\x00\x10' + b'\x00' * 16):
        rc, ans = host.sign('pve', junk)
        assert rc == 1 and ans['code'] == 'bad_request', junk
    pem = b'-----BEGIN NEW CERTIFICATE REQUEST-----\n' + base64.encodebytes(make_crq('pve')) \
        + b'-----END NEW CERTIFICATE REQUEST-----\n'
    rc, ans = host.sign('pve', pem)
    assert rc == 0, ans
    assert not host.jsonl('sign.jsonl')[1:]


def test_sign_before_init_is_refused(host):
    rc, ans = host.sign('pve', make_crq('pve'))
    assert rc == 1 and ans['code'] == 'not_initialised'


def test_another_key_for_a_name_on_file_needs_replace(host):
    assert host.helper('init')[0] == 0
    first = make_crq('pve', key='k1')
    assert host.sign('pve', first)[0] == 0
    on_file = slurp(os.path.join(host.db, 'cluster-pve.crt'))
    rc, ans = host.sign('pve', make_crq('pve', key='k2'))
    assert rc == 1 and ans['code'] == 'name_exists' and 'replace' in ans['error']
    assert slurp(os.path.join(host.db, 'cluster-pve.crt')) == on_file
    # the same key again: the same cluster, signed without asking
    rc, ans = host.sign('pve', first)
    assert rc == 0 and ans['replaced'] is False
    # the admin said so
    rc, ans = host.sign('pve', make_crq('pve', key='k2'), replace=True)
    assert rc == 0 and ans['replaced'] is True
    assert H.parse_cert(slurp(os.path.join(host.db, 'cluster-pve.crt')))[1] == \
        H.parse_crq(make_crq('pve', key='k2'))[1]
    rc, ans = host.sign('pve', make_crq('pve', key='k3'), replace='yes')
    assert rc == 1 and ans['code'] == 'bad_request'


def test_names_differing_in_case_are_the_same_name(host):
    """qnetd matches a client certificate to the cluster name as it matches a host name."""
    assert host.helper('init')[0] == 0
    assert host.sign('PVE', make_crq('PVE', key='k1'))[0] == 0
    rc, ans = host.sign('pve', make_crq('pve', key='k2'))
    assert rc == 1 and ans['code'] == 'name_exists' and 'cluster-PVE.crt' in ans['error']


def test_a_connected_name_is_never_signed_for_another_key(host):
    assert host.helper('init')[0] == 0          # the stand-in service is active from here
    host.listing(LISTING)
    # nothing on file for it (another PegaProx, or pvecm and a removed file): still refused,
    # replace or not
    for replace in (False, True):
        rc, ans = host.sign('pve-lab', make_crq('pve-lab'), replace=replace)
        assert rc == 1 and ans['code'] == 'name_in_use', ans
    assert not host.jsonl('sign.jsonl')
    # its own key, on file from before, is the cluster itself
    host.listing('')
    assert host.sign('PVE-Lab', make_crq('PVE-Lab', key='own'))[0] == 0
    host.listing(LISTING)
    assert host.sign('PVE-Lab', make_crq('PVE-Lab', key='own'))[0] == 0
    rc, ans = host.sign('PVE-Lab', make_crq('PVE-Lab', key='intruder'), replace=True)
    assert rc == 1 and ans['code'] == 'name_in_use'
    # another name next to it is fine
    assert host.sign('other', make_crq('other'))[0] == 0


def test_signing_blind_is_refused(host):
    """The QNetd runs and its tool does not answer: which clusters it serves is unknown."""
    assert host.helper('init')[0] == 0
    host.flag('state-tool-down')
    rc, ans = host.sign('pve', make_crq('pve'))
    assert rc == 1 and ans['code'] == 'status_unknown'
    # not running at all: nothing can be connected
    host.flag('state-active', on=False)
    assert host.sign('pve', make_crq('pve'))[0] == 0


def test_a_failed_signing_leaves_the_certificate_on_file(host):
    assert host.helper('init')[0] == 0
    assert host.sign('pve', make_crq('pve'))[0] == 0
    path = os.path.join(host.db, 'cluster-pve.crt')
    before = slurp(path)
    host.flag('flag-fail-sign')
    rc, ans = host.sign('pve', make_crq('pve'))
    assert rc == 1 and 'signing the cluster certificate failed' in ans['error']
    assert slurp(path) == before
    host.flag('flag-fail-sign', on=False)
    host.flag('flag-other-key')
    rc, ans = host.sign('pve', make_crq('pve'))
    assert rc == 1 and 'does not match' in ans['error']
    assert slurp(path) == before
    assert not [n for n in os.listdir(host.db) if n.startswith('.pegaprox-')]


def test_ca_hands_out_the_export_as_is(host):
    rc, ans = host.helper('ca')
    assert rc == 1 and ans['code'] == 'not_initialised'
    assert host.helper('init')[0] == 0
    rc, ans = host.helper('ca')
    assert rc == 0
    with open(os.path.join(host.db, 'qnetd-cacert.crt'), 'rb') as fh:
        assert base64.b64decode(ans['ca_b64']) == fh.read()
    # never through a symlink
    os.rename(os.path.join(host.db, 'qnetd-cacert.crt'), os.path.join(host.base, 'elsewhere'))
    os.symlink(os.path.join(host.base, 'elsewhere'), os.path.join(host.db, 'qnetd-cacert.crt'))
    rc, ans = host.helper('ca')
    assert rc == 1


# --- status, uuid ----------------------------------------------------------------------------

def test_status_reads_the_listing(host):
    rc, ans = host.helper('status')
    assert rc == 0 and ans == {'ok': True, 'active': False, 'clusters': [], 'raw': '', 'tls_required': None,
                               'certificates': []}
    assert host.helper('init')[0] == 0
    host.listing(LISTING)
    rc, ans = host.helper('status')
    assert rc == 0 and ans['active'] is True and ans['raw'] == LISTING
    assert ans['clusters'] == [{
        'name': 'PVE-Lab', 'algorithm': 'Fifty-Fifty split (KAP Tie-breaker)',
        'tie_breaker': 'Node with lowest node ID',
        'nodes': [{'node_id': 1, 'addr': '::ffff:192.0.2.11:41234', 'vote': 'ACK (ACK)',
                   'tls': 'Yes (client certificate verified)'},
                  {'node_id': 2, 'addr': '[2001:db8::12]:50122', 'vote': 'No change (ACK)',
                   'tls': 'Yes (client certificate verified)'}]}]
    assert ('corosync-qnetd-tool -l -v -p %s/corosync-qnetd.sock' % host.run_dir) in host.calls()
    host.flag('state-tool-down')
    rc, ans = host.helper('status')
    assert rc == 1 and ans['code'] == 'status_unknown'


def test_status_raw_is_capped():
    many = ''.join('Cluster "c%d":\n    Node ID 1:\n        Vote:\t\t\tACK (ACK)\n' % i for i in range(6000))
    clusters = H.parse_listing(many)
    assert len(clusters) == 5000
    assert len(H.parse_listing('Cluster "x":\n' + '    Node ID 1:\n' * 600)[0]['nodes']) == 512
    assert H.parse_listing('garbage\nNode ID 1:\n') == []


def test_status_names_the_clusters_with_a_certificate_on_file(host):
    """The names a sign would find a certificate on file for, so a plan can say so before the
    run: names only, the ones a cluster can have, sorted."""
    rc, ans = host.helper('status')
    assert rc == 0 and ans['certificates'] == []         # no NSS database yet
    assert host.helper('init')[0] == 0
    for name in ('pve', 'Lab-2', 'PVE'):
        rc, _ans = host.sign(name, make_crq(name, key=name))
        assert rc == 0 or name == 'PVE'                  # another key for the name pve
    # whatever else lies in the directory is no cluster certificate of a name PVE allows
    for junk in ('cluster-a_b.crt', 'cluster-x.y.crt', 'cluster-.crt', 'cluster-%s.crt' % ('a' * 16),
                 'cluster--pve.crt', 'cluster-pve.crt.bak', 'cluster-other.p12', 'cluster-$(id).crt',
                 'Cluster-up.crt'):
        open(os.path.join(host.db, junk), 'w').close()
    rc, ans = host.helper('status')
    assert rc == 0 and ans['certificates'] == ['Lab-2', 'pve']
    # nothing of what the files hold goes out with them
    held = slurp(os.path.join(host.db, 'cluster-pve.crt'))
    text = json.dumps(ans)
    assert base64.b64encode(held).decode() not in text and 'CERTIFICATE' not in text
    assert set(ans) == {'ok', 'active', 'clusters', 'raw', 'tls_required', 'certificates'}


def test_status_lists_at_most_max_certs_names(tmp_path):
    db = tmp_path / 'nssdb'
    db.mkdir()
    for i in range(H.MAX_CERTS + 25):
        (db / ('cluster-c%05d.crt' % i)).touch()
    names = H.cert_names(types.SimpleNamespace(db_dir=str(db)))
    assert H.MAX_CERTS == 4096 and len(names) == H.MAX_CERTS
    assert names == sorted(names) and names[0] == 'c00000'
    # no NSS directory holds none; one that cannot be listed says nothing
    assert H.cert_names(types.SimpleNamespace(db_dir=str(tmp_path / 'missing'))) == []
    (tmp_path / 'plain').touch()
    assert H.cert_names(types.SimpleNamespace(db_dir=str(tmp_path / 'plain'))) is None
    # sign finds the very same files, without regard to case
    (db / 'cluster-PVE.crt').touch()
    host = types.SimpleNamespace(db_dir=str(db), path=lambda n: os.path.join(str(db), n))
    assert H._existing_certs(host, 'pve') == [str(db / 'cluster-PVE.crt')]
    assert 'PVE' in H.cert_names(host)


def test_uuid_reads_the_smbios_uuid_or_nothing(tmp_path):
    f = tmp_path / 'product_uuid'
    f.write_text('4C4C4544-0035-5910-8044-B4C04F4A4D32\n')
    assert H.read_product_uuid(str(f)) == '4c4c4544-0035-5910-8044-b4c04f4a4d32'
    for bad in ('not a uuid', '00000000-0000-0000-0000-000000000000', 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF',
                '4c4c4544-0035-5910-8044-b4c04f4a4d32; id', ''):
        f.write_text(bad)
        assert H.read_product_uuid(str(f)) == '', bad
    assert H.read_product_uuid(str(tmp_path / 'missing')) == ''
    host = H.Host('sidecar', {'PEGAPROX_QNETD_HOST_UUID': '4C4C4544-0035-5910-8044-B4C04F4A4D32'})
    assert host.host_uuid == '4c4c4544-0035-5910-8044-b4c04f4a4d32'
    assert H.Host('sidecar', {'PEGAPROX_QNETD_HOST_UUID': 'x; rm -rf /'}).host_uuid == ''
    # the CLI is never told a uuid by its environment
    assert H.Host('systemd', {'PEGAPROX_QNETD_HOST_UUID': '4c4c4544-0035-5910-8044-b4c04f4a4d32'}).host_uuid == ''


def test_uuid_op_answers(host):
    rc, ans = host.helper('uuid')
    assert rc == 0 and set(ans) == {'ok', 'product_uuid'}
    assert ans['product_uuid'] == '' or H.UUID_RE.fullmatch(ans['product_uuid'])


# --- privileges -------------------------------------------------------------------------------

def test_overrides_are_refused_as_root(monkeypatch, capsys):
    env = {'PEGAPROX_QNETD_CONFIG_DIR': '/tmp/evil'}
    assert H.overrides_allowed({}) is (os.geteuid() != 0)
    monkeypatch.setattr(H.os, 'geteuid', lambda: 0)
    assert H.overrides_allowed({}) is False
    with pytest.raises(H.Refused) as e:
        H.Host('systemd', env)
    assert e.value.code == 'bad_request'
    for var in H.OVERRIDES:
        with pytest.raises(H.Refused):
            H.Host('systemd', {var: '/tmp/x'})
    # no override given: the fixed paths
    host = H.Host('systemd', {})
    assert host.config_dir == '/etc/corosync/qnetd' and host.bin_dir is None
    assert host.bin('certutil') in (None, '/usr/bin/certutil')
    # the command line answers with the refusal
    monkeypatch.setenv('PEGAPROX_QNETD_CONFIG_DIR', '/tmp/evil')
    umask = os.umask(0o022)
    try:
        assert H.main(['version']) == 1
    finally:
        os.umask(umask)
    ans = json.loads(capsys.readouterr().out)
    assert ans['ok'] is False and 'unprivileged' in ans['error']


def test_overrides_are_refused_under_sudo(monkeypatch):
    if os.geteuid() == 0:
        pytest.skip('runs as root')
    for var in ('SUDO_USER', 'SUDO_UID', 'SUDO_COMMAND'):
        assert H.overrides_allowed({var: 'x'}) is False
        with pytest.raises(H.Refused):
            H.Host('systemd', {var: 'x', 'PEGAPROX_QNETD_BIN_DIR': '/tmp/bin'})
    monkeypatch.setattr(H.os, 'getuid', lambda: 0)
    assert H.overrides_allowed({}) is False


def test_overrides_are_refused_under_sudo_end_to_end(host):
    rc, ans = host.helper('version', env=host.env(SUDO_USER='pegaprox'))
    assert rc == 1 and 'unprivileged' in ans['error']


# --- the socket of the sidecar -----------------------------------------------------------------

def short_dir():
    # a Unix socket path has room for about 100 characters
    return tempfile.mkdtemp(prefix='pq-', dir='/tmp')


@pytest.fixture
def served(host, monkeypatch):
    monkeypatch.setattr(H, 'MAX_CLIENTS', 2)
    monkeypatch.setattr(H, 'READ_WAIT', 1)
    sock_dir = short_dir()
    env = host.env()
    assert host.helper('init')[0] == 0
    side = H.Host('sidecar', env)
    alive = {'up': True}
    side.qnetd_alive = lambda: alive['up']
    server = H.SocketServer(side, os.path.join(sock_dir, 'run', 'helper.sock'))
    server.start()
    yield server, alive
    server.close()
    shutil.rmtree(sock_dir, ignore_errors=True)


def raw_ask(path, data, wait=10):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(wait)
    s.connect(path)
    s.sendall(data)
    out = b''
    while b'\n' not in out:
        chunk = s.recv(65536)
        if not chunk:
            break
        out += chunk
    s.close()
    return json.loads(out.decode())


def test_socket_round_trip(served, host):
    server, alive = served
    st = os.stat(server.path)
    assert stat.S_ISSOCK(st.st_mode) and oct(st.st_mode & 0o777) == '0o660'
    assert oct(os.stat(os.path.dirname(server.path)).st_mode & 0o777) == '0o770'
    ans = H.ask(server.path, {'op': 'version'})
    assert ans['ok'] is True and ans['protocol'] == 2 and ans['mode'] == 'sidecar' and ans['active'] is True
    # the sidecar never installs anything
    assert ans['package_manager'] is None and ans['packages'] == []
    alive['up'] = False
    assert H.ask(server.path, {'op': 'version'})['active'] is False
    ans = H.ask(server.path, {'op': 'sign', 'name': 'pve', 'crq_b64': base64.b64encode(make_crq('pve')).decode()})
    assert ans['ok'] is True and H.parse_cert(base64.b64decode(ans['crt_b64']))[0] == 'pve'
    ans = H.ask(server.path, {'op': 'ca'})
    assert ans['ok'] is True and b'BEGIN CERTIFICATE' in base64.b64decode(ans['ca_b64'])
    # what the command line refuses, the socket refuses
    for req, code in (({}, 'bad_request'), ({'op': 'bogus'}, 'bad_request'), ({'op': 'version', 'name': 'x'}, 'bad_request'),
                      ({'op': 'sign', 'name': 'x;id', 'crq_b64': 'AA=='}, 'bad_request'),
                      ({'op': 'status', 'extra': 1}, 'bad_request'), ({'op': 7}, 'bad_request')):
        ans = H.ask(server.path, req)
        assert ans['ok'] is False and ans['code'] == code, req
    assert raw_ask(server.path, b'[1]\n')['code'] == 'bad_request'
    assert raw_ask(server.path, b'{"op": "version"')['code'] == 'bad_request'
    # one line of at most 64 KiB
    ans = raw_ask(server.path, b'{"op": "version", "pad": "' + b'x' * (70 * 1024) + b'"}\n')
    assert ans['ok'] is False and 'too large' in ans['error']


def test_a_slow_client_never_holds_the_others(served):
    server, _alive = served
    slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    slow.connect(server.path)
    slow.sendall(b'{"op": "ver')          # and then nothing
    t = time.monotonic()
    assert H.ask(server.path, {'op': 'version'})['ok'] is True
    assert time.monotonic() - t < 1.0
    # every slot taken by a silent client: the next one hears busy at once, not after them
    slow2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    slow2.connect(server.path)
    time.sleep(0.2)
    t = time.monotonic()
    ans = H.ask(server.path, {'op': 'version'})
    assert ans['code'] == 'busy' and time.monotonic() - t < 0.5
    # and each silent one is let go after its deadline
    slow.settimeout(5)
    assert json.loads(slow.recv(4096).decode())['code'] == 'bad_request'
    slow.close()
    slow2.close()
    time.sleep(0.2)
    assert H.ask(server.path, {'op': 'version'})['ok'] is True


def test_socket_start_refuses_what_is_not_its_own(tmp_path, host):
    d = short_dir()
    try:
        path = os.path.join(d, 'helper.sock')
        with open(path, 'w') as fh:
            fh.write('a file')
        server = H.SocketServer(H.Host('sidecar', host.env()), path)
        with pytest.raises(H.Refused):
            server.start()
        assert slurp(path).decode() == 'a file'
        with pytest.raises(H.Refused):
            H.socket_path({'PEGAPROX_QNETD_SOCKET': 'relative/helper.sock'})
        with pytest.raises(H.Refused):
            H.socket_path({'PEGAPROX_QNETD_SOCKET': '/run/x/../y/helper.sock'})
        assert H.socket_path({}) == '/run/pegaprox-qnetd/helper.sock'
    finally:
        shutil.rmtree(d, ignore_errors=True)


SIDECAR = ('import importlib.machinery, importlib.util, sys; sys.dont_write_bytecode = True; '
           'l = importlib.machinery.SourceFileLoader("h", sys.argv[1]); '
           'm = importlib.util.module_from_spec(importlib.util.spec_from_loader("h", l)); '
           'l.exec_module(m); sys.exit(m.sidecar_main(sys.argv[2:]))')


def start_sidecar(host, sock, entry=False):
    env = host.env(PEGAPROX_QNETD_SOCKET=sock)
    if entry:
        argv = [sys.executable, os.path.join(ROOT, 'pegaprox_multi_cluster.py'), 'qnetd', 'run']
    else:
        argv = [sys.executable, '-c', SIDECAR, HELPER, 'run']
    return subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=host.base)


def wait_for(path, proc, secs=20):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if os.path.exists(path):
            return True
        if proc.poll() is not None:
            return False
        time.sleep(0.1)
    return False


def test_the_sidecar_runs_qnetd_and_the_socket_until_told_to_stop(host):
    d = short_dir()
    sock = os.path.join(d, 'sock', 'helper.sock')
    proc = start_sidecar(host, sock)
    try:
        assert wait_for(sock, proc), proc.communicate(timeout=10)
        ans = H.ask(sock, {'op': 'version'})
        assert ans['ok'] and ans['active'] is True and ans['initialised'] is True
        end = time.monotonic() + 10
        while not [c for c in host.calls() if c.startswith('corosync-qnetd ')] and time.monotonic() < end:
            time.sleep(0.05)
        qnetd = [c for c in host.calls() if c.startswith('corosync-qnetd ')][0]
        assert qnetd == ('corosync-qnetd -f -s req -S local_socket_file=%s/corosync-qnetd.sock,'
                         'lock_file=%s/corosync-qnetd.pid,'
                         'nss_db_dir=%s' % (host.run_dir, host.run_dir, host.db))
        # no package, no service: the sidecar never runs apt-get or systemctl
        assert H.ask(sock, {'op': 'init'})['ok'] is True
        assert not [c for c in host.calls() if c.startswith(('apt-get', 'systemctl enable'))]
        env = host.env(PEGAPROX_QNETD_SOCKET=sock)
        assert subprocess.run([sys.executable, '-c', SIDECAR, HELPER, 'health'], env=env, timeout=30,
                              stdout=subprocess.PIPE).returncode == 0
        host.flag('state-tool-down')
        out = subprocess.run([sys.executable, '-c', SIDECAR, HELPER, 'health'], env=env, timeout=30,
                             stdout=subprocess.PIPE)
        assert out.returncode == 1 and b'IPC socket' in out.stdout
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(20) == 0
        assert not os.path.exists(sock)
        assert subprocess.run([sys.executable, '-c', SIDECAR, HELPER, 'health'], env=env, timeout=30,
                              stdout=subprocess.PIPE).returncode == 1
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=10)
        shutil.rmtree(d, ignore_errors=True)


def test_the_sidecar_ends_with_its_qnetd(host):
    host.flag('state-qnetd-dies')
    d = short_dir()
    try:
        proc = start_sidecar(host, os.path.join(d, 'helper.sock'))
        _out, err = proc.communicate(timeout=30)
        assert proc.returncode == 1
        assert b'corosync-qnetd ended with 3' in err
        assert not os.path.exists(os.path.join(d, 'helper.sock'))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_the_sidecar_refuses_to_start_without_its_tools(host):
    os.unlink(os.path.join(host.bin, 'certutil'))
    d = short_dir()
    try:
        proc = start_sidecar(host, os.path.join(d, 'helper.sock'))
        _out, err = proc.communicate(timeout=30)
        assert proc.returncode == 1 and b'certutil is not installed' in err
        assert not [c for c in host.calls() if c.startswith('corosync-qnetd ')]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_the_entrypoint_runs_the_sidecar_without_gevent(host):
    host.flag('state-qnetd-dies')
    d = short_dir()
    try:
        proc = start_sidecar(host, os.path.join(d, 'helper.sock'), entry=True)
        out, err = proc.communicate(timeout=60)
        assert proc.returncode == 1 and b'corosync-qnetd ended with 3' in err
        assert b'Gevent monkey-patching applied' not in out
        env = host.env(PEGAPROX_QNETD_SOCKET=os.path.join(d, 'helper.sock'))
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'pegaprox_multi_cluster.py'), 'qnetd', 'health'],
                           env=env, stdout=subprocess.PIPE, timeout=60, cwd=host.base)
        assert p.returncode == 1 and b'unhealthy' in p.stdout
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'pegaprox_multi_cluster.py'), 'qnetd', 'bogus'],
                           env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, cwd=host.base)
        assert p.returncode == 2 and b'qnetd run|health' in p.stderr
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --- the real NSS tools ---------------------------------------------------------------------

@needs_nss
def test_real_init_is_idempotent(tmp_path):
    host = FakeBins(tmp_path, real=NSS)
    rc, ans = host.helper('init')
    assert rc == 0 and ans['created'] is True, ans
    assert nicks(host.db) == ['QNet CA', 'QNetd Cert']
    ca = ca_pem(host.db)
    export = slurp(os.path.join(host.db, 'qnetd-cacert.crt'))
    assert export.startswith(b'Certificate:') and ca.strip() in export
    key = slurp(os.path.join(host.db, 'key4.db'))
    rc, ans = host.helper('init')
    assert rc == 0 and ans['created'] is False
    assert ca_pem(host.db) == ca
    assert slurp(os.path.join(host.db, 'qnetd-cacert.crt')) == export
    assert slurp(os.path.join(host.db, 'key4.db')) == key
    with open(os.path.join(host.db, 'serial.txt')) as fh:
        assert fh.read() == '102\n'


@needs_stock
def test_real_init_keeps_a_ca_the_stock_tool_made(tmp_path):
    host = FakeBins(tmp_path, real=NSS)
    tool = stock_qnetd_certutil(str(tmp_path), host.conf)
    p = bash(tool, '-i', '-G')
    assert p.returncode == 0, p.stderr
    ca = ca_pem(host.db)
    stock_files = sorted(os.listdir(host.db))
    rc, ans = host.helper('init')
    assert rc == 0 and ans['created'] is False
    assert ca_pem(host.db) == ca and sorted(os.listdir(host.db)) == stock_files
    # and a request signed by the helper on the stock database
    node, crq = node_crq(str(tmp_path / 'node'), 'stockdb', os.path.join(host.db, 'qnetd-cacert.crt'))
    rc, ans = host.sign('stockdb', crq)
    assert rc == 0, ans


@needs_stock
def test_real_sign_with_a_node_request_and_back(tmp_path):
    """The whole exchange with the stock node tool: CA in, request out, signed, imported
    and exported as the p12 the other nodes get."""
    host = FakeBins(tmp_path, real=NSS)
    assert host.helper('init')[0] == 0
    ca_file = tmp_path / 'qnetd-cacert.crt'
    ca_file.write_bytes(base64.b64decode(host.helper('ca')[1]['ca_b64']))
    node, crq = node_crq(str(tmp_path / 'node1'), 'pve2', str(ca_file))
    cn, key = H.parse_crq(crq)
    assert cn == 'pve2'
    rc, ans = host.sign('pve2', crq)
    assert rc == 0, ans
    crt = base64.b64decode(ans['crt_b64'])
    assert H.parse_cert(crt) == ('pve2', key)
    crt_file = tmp_path / 'node1' / 'net' / 'nssdb' / 'cluster-pve2.crt'
    crt_file.write_bytes(crt)
    p = bash(node, '-M', '-c', str(crt_file))
    assert p.returncode == 0, p.stderr
    assert (tmp_path / 'node1' / 'net' / 'nssdb' / 'qdevice-net-node.p12').stat().st_size > 0
    # the stock tool keeps signing on this database, its serials after ours
    other, crq2 = node_crq(str(tmp_path / 'node2'), 'other', str(ca_file))
    (tmp_path / 'req.crq').write_bytes(crq2)
    p = bash(stock_qnetd_certutil(str(tmp_path), host.conf), '-s', '-c', str(tmp_path / 'req.crq'), '-n', 'other')
    assert p.returncode == 0, p.stderr
    with open(os.path.join(host.db, 'serial.txt')) as fh:
        assert fh.read() == '104\n'
    # a second node of pve2 with a key of its own: refused without replace
    _n, crq3 = node_crq(str(tmp_path / 'node3'), 'pve2', str(ca_file))
    rc, ans = host.sign('pve2', crq3)
    assert rc == 1 and ans['code'] == 'name_exists'


@needs_nss
def test_real_certutil_refuses_a_request_with_a_broken_signature(tmp_path):
    host = FakeBins(tmp_path, real=NSS)
    assert host.helper('init')[0] == 0
    rc, ans = host.sign('pve', make_crq('pve'))      # a made-up signature
    assert rc == 1 and 'signing the cluster certificate failed' in ans['error']
    assert not os.path.exists(os.path.join(host.db, 'cluster-pve.crt'))
