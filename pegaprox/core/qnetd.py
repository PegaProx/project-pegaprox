# -*- coding: utf-8 -*-
"""QNetd hosts, and the QDevice of a Proxmox VE cluster set up against one - MK Oct 2026

A QNetd host is reached through one small root helper (packaging/qnetd/pegaprox-qnetd-helper,
PROTOCOL below) in one of three ways:

  local    PegaProx's own machine: the root-owned socket unit packaging/qnetd/install.sh
           sets up (pegaprox-qnetd-helper.socket, LOCAL_SOCKET) starts the helper for each
           connection. One JSON line in and one out, as with the sidecar. PegaProx cannot
           replace a root-owned helper, so an older one is reported ("re-run install.sh")
           and not used.
  ssh      any Linux host: a stored login (password or key, sealed in the database), the
           host key pinned on first use like every other SSH target. The helper runs as
           root or through `sudo -n`; a missing or older one is copied over and installed
           root-owned when the login may do that, into directories only root can change.
  sidecar  the QNetd container next to a Docker install: one JSON line in and one out on
           a Unix socket (PEGAPROX_QNETD_SOCKET).

The CA key never leaves the QNetd host. What PegaProx carries is what `pvecm qdevice setup`
copies with scp: the CA certificate to every node, the certificate request from one node to
the QNetd, the signed certificate back, and the PKCS#12 bundle from that node to the others.
The bundle holds the cluster's private key: it travels on the stdin of the command that
imports it, into a mktemp directory (0700) that is removed again, never on an argument
list and never in a file anybody else can read. No node needs access to the QNetd host.

corosync.conf is written by Proxmox's own perl (cfs_lock_file + atomic_write_conf), the
same section pvecm writes, so `pvecm qdevice remove` works on a QDevice set up here, and
remove is exactly that command on one node. A setup that fails after it changed the first
node is rolled back the way remove cleans up.

Scale: everything per cluster goes out per node with run_per_node (FANOUT at a time), the
check whether the QNetd host is a guest of the cluster is one grep over the guest configs,
and a QNetd host's status is read at most every FRESH seconds; the alert rule only reads
what is kept here (alert_view).
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import math
import os
import re
import shlex
import socket
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from pegaprox.utils.ssh import bare_host, read_capped

log = logging.getLogger(__name__)

PROTOCOL = 2                       # the helper protocol this PegaProx speaks (2: firewall)
HELPER_PATH = '/usr/lib/pegaprox/qnetd/pegaprox-qnetd-helper'
# where install.sh puts the helper; both root's, neither group nor world writable
HELPER_DIRS = ('/usr/lib/pegaprox', '/usr/lib/pegaprox/qnetd')
LOCAL_SOCKET = '/run/pegaprox-qnetd/local.sock'      # pegaprox-qnetd-helper.socket
SOCKET_ENV = 'PEGAPROX_QNETD_SOCKET'
SOCKET_DEFAULT = '/run/pegaprox-qnetd/helper.sock'   # the sidecar's
DEFAULT_PORT = 5403
KINDS = ('local', 'ssh', 'sidecar')
OPS = ('version', 'init', 'ca', 'sign', 'status', 'uuid', 'firewall')
OP_TIMEOUT = {'version': 15, 'init': 600, 'ca': 30, 'sign': 60, 'status': 30, 'uuid': 15, 'firewall': 120}

# what init installs on the QNetd host, by the package manager its version answer names
QNETD_PACKAGES = {'apt': ('corosync-qnetd', 'libnss3-tools'), 'dnf': ('corosync-qnetd', 'nss-tools'),
                  'yum': ('corosync-qnetd', 'nss-tools'), 'zypper': ('corosync-qnetd', 'mozilla-nss-tools')}
FW_ACTIONS = ('inspect', 'allow', 'remove')
FW_BACKENDS = ('pve-firewall', 'firewalld', 'ufw', 'nftables', 'iptables', 'none')
FW_MANAGED = ('firewalld', 'ufw')              # the ones the helper changes itself
FW_SOURCES_MAX = 64
# the helper's refusals of an allow that come before it changed any rule; after any other
# failure some of the rules may be in (ufw took the first address, then refused one)
FW_REFUSED_BEFORE = ('bad_request', 'busy', 'not_supported', 'state_untrusted', 'state_full', 'firewall_unmanaged')
DIGEST_RE = re.compile(r'^[0-9a-f]{64}\Z')
PLAN_CHANGED = 'The plan changed since you agreed: check again'
# warnings the digest leaves out: unverified_host has its own option, firewall_manual is
# about a firewall PegaProx does not change (the port check blocks without it), and
# ha_resources about guests the setup does not touch, read best-effort
PLAN_UNAGREED_WARNINGS = ('unverified_host', 'firewall_manual', 'ha_resources')
CONNECT_TIMEOUT = 10
ANSWER_MAX = 1024 * 1024           # one helper answer (status carries up to 64 KiB of raw text)
CERTS_MAX = 4096                   # the cluster names a status answer lists certificates for
FILE_MAX = 16 * 1024               # a decoded CA, CRQ or CRT
P12_MAX = 64 * 1024
HELPER_MAX = 512 * 1024            # the helper script we would copy to an ssh host

FRESH = 30                         # a status read this recent is handed out again
SERVE_MAX = 300                    # older than this a read says nothing about now
REFRESH_EVERY = 60                 # what the alert loop keeps fresh in the background
FAIL_STREAK = 2                    # failed reads in a row before a host counts as down

FANOUT = 8
NODE_TIMEOUT = 60
APT_TIMEOUT = 900
PVECM_TIMEOUT = 300
NODE_OUT_MAX = 256 * 1024
NODE_ERR_MAX = 16 * 1024
BULK_MAX = 200
KEEP_SECONDS = 6 * 3600
KEEP_FINISHED = 50
LOG_MAX = 3000

# PVE's own rule for a cluster name (a DNS label, at most 15): it ends up in a certificate
# CN, a file name on the QNetd and the helper's --name
CLUSTER_NAME_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?\Z')
HOST_NAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}\Z')
DISPLAY_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}\Z')
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
SSH_USER_RE = re.compile(r'^[a-z_][a-z0-9_.-]{0,31}\Z')
JOB_ID_RE = re.compile(r'^[0-9a-f]{16}\Z')
_B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}\Z')
_PROTOCOL_LINE = re.compile(rb'^PROTOCOL\s*=\s*([0-9]{1,4})\s*(?:#.*)?$', re.M)

NODE_STORE = '/etc/corosync/qdevice/net/nssdb'


class HelperError(Exception):
    """A helper call without a usable answer. The text is short and holds no secret;
    `code` is the helper's own word for a refusal (name_exists, name_in_use, ...)."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code if isinstance(code, str) and re.match(r'^[a-z_]{1,40}\Z', code) else None


class NodeError(Exception):
    """A node PegaProx cannot run a command on, or a command that failed there."""


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def clean_cluster_name(value):
    return value if isinstance(value, str) and CLUSTER_NAME_RE.match(value) else None


def clean_address(value):
    """The bare host name or address the nodes dial, or None. No zone index, no
    loopback or unspecified address, no leading '-'."""
    if not isinstance(value, str):
        return None
    value = bare_host(value.strip())
    if not value or len(value) > 253 or '%' in value:
        return None
    import ipaddress
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return value if HOST_NAME_RE.match(value) and not value.startswith('-') else None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return None
    return str(ip)


def clean_source(value):
    """One address the QNetd port is opened for: a single IP address (no network, no
    name), not loopback, unspecified or multicast, an IPv4-mapped one as IPv4. Or None."""
    if not isinstance(value, str) or not 2 <= len(value.strip()) <= 45 or '%' in value or '/' in value:
        return None
    import ipaddress
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if getattr(ip, 'ipv4_mapped', None) is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return None
    return str(ip)


def clean_sources(values):
    """The sorted addresses of `values`, duplicates dropped; None when one is not a single
    address or there are more than FW_SOURCES_MAX."""
    if not isinstance(values, (list, tuple)) or len(values) > FW_SOURCES_MAX:
        return None
    out = set()
    for v in values:
        c = clean_source(v)
        if c is None:
            return None
        out.add(c)
    return sorted(out)


def clean_port(value, default):
    if value is None or value == '':
        return default
    if isinstance(value, bool):
        return None
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _short(text, limit=300):
    """One line of remote text for a log or an answer."""
    text = ' '.join(str(text or '').split())
    return text[:limit]


def _b64_file(value, limit):
    """The bytes of a base64 file payload, or HelperError."""
    if not isinstance(value, str) or not value or len(value) > limit * 4 // 3 + 8:
        raise HelperError('a file in the answer is missing or too large')
    value = value.strip()
    if not _B64_RE.match(value):
        raise HelperError('a file in the answer is not base64')
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise HelperError('a file in the answer is not base64')
    if not raw or len(raw) > limit:
        raise HelperError('a file in the answer is empty or too large')
    return raw


_PEM_CRT_RE = re.compile(rb'-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+?)-----END CERTIFICATE-----')


def _pem_cert(raw):
    """The bytes of the first PEM certificate in raw, or None."""
    m = _PEM_CRT_RE.search(raw)
    if not m:
        return None
    try:
        return base64.b64decode(re.sub(rb'\s+', b'', m.group(1)), validate=True) or None
    except (binascii.Error, ValueError):
        return None


def _looks_like_pem_or_der(raw, what):
    """A certificate (request) as certutil writes it: PEM text with the header, or DER.
    A CA also comes as the qnetd-cacert.crt of corosync-qnetd-certutil (and of the helper's
    init): certutil's listing of it first, the same in PEM after it."""
    if what == 'crt' and raw.startswith(b'Certificate:'):
        return _pem_cert(raw) is not None
    if raw.startswith(b'-----BEGIN '):
        if what == 'crq' and b'CERTIFICATE REQUEST' not in raw[:64]:
            return False
        if what == 'crt' and b'CERTIFICATE' not in raw[:64]:
            return False
        return True
    return raw[:1] == b'\x30'          # a DER SEQUENCE


# ---------------------------------------------------------------------------
# transports - all three speak the same ops and give the same answers
# ---------------------------------------------------------------------------

def _request(op, name=None, data=None):
    if op not in OPS:
        raise HelperError(f'unknown helper op {op!r}')
    if name is not None and not clean_cluster_name(name):
        raise HelperError('invalid cluster name')
    if op in ('sign', 'firewall') and name is None:
        raise HelperError(f'{op} needs a cluster name')
    body = {}
    if op == 'firewall':
        # the port is never part of it: the helper opens corosync-qnetd's own and no other
        data = data if isinstance(data, dict) else {}
        action = data.get('action')
        if action not in FW_ACTIONS or set(data) - {'action', 'sources'}:
            raise HelperError('invalid firewall request')
        body['action'] = action
        if data.get('sources') is not None:
            sources = clean_sources(data['sources'])
            # remove with an empty list would read as "every rule of the cluster"
            if action == 'inspect' or not sources:
                raise HelperError('invalid firewall sources')
            body['sources'] = sources
        elif action == 'allow':
            raise HelperError('allow needs the addresses of the nodes')
        return body
    if data:
        if op != 'sign':
            raise HelperError(f'{op} takes no request data')
        crq = data.get('crq_b64')
        if not isinstance(crq, str) or not _B64_RE.match(crq) or len(crq) > FILE_MAX * 2:
            raise HelperError('invalid certificate request')
        body['crq_b64'] = crq
        if data.get('replace') is True:
            body['replace'] = True
    return body


def _no_json_constant(name):
    raise ValueError(f'{name} is not JSON')


def _parse_answer(raw):
    if isinstance(raw, str):
        raw = raw.encode('utf-8', 'replace')
    if len(raw) > ANSWER_MAX:
        raise HelperError('the helper answer is too large')
    text = raw.decode('utf-8', 'replace').strip()
    if not text:
        raise HelperError('the helper gave no answer')
    try:
        # NaN/Infinity are no JSON, and nesting past the recursion limit is no answer either
        ans = json.loads(text, parse_constant=_no_json_constant)
    except (ValueError, RecursionError):
        raise HelperError('the helper answer is no JSON')
    if not isinstance(ans, dict) or not isinstance(ans.get('ok'), bool):
        raise HelperError('the helper answer is not what the helper protocol says')
    return ans


def _argv(op, name):
    return [HELPER_PATH, op] + (['--name', name] if name else [])


class _UnixHelper:
    """The helper behind a Unix socket: one JSON request line per connection, one JSON
    answer line back (the protocol of the helper's `serve` and of the sidecar). One
    deadline for the whole call: each recv has its own timeout, and a socket that sends a
    byte now and then would otherwise hold the caller as long as it liked."""
    kind = None
    what = 'the QNetd helper'
    missing = ''

    def __init__(self, path):
        self.path = path

    def call(self, op, name=None, data=None):
        body = _request(op, name, data)
        body['op'] = op
        if name:
            body['name'] = name
        line = (json.dumps(body) + '\n').encode()
        deadline = time.monotonic() + OP_TIMEOUT[op]
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(OP_TIMEOUT[op])
            s.connect(self.path)
            s.sendall(line)
            buf = b''
            while b'\n' not in buf and len(buf) <= ANSWER_MAX:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise socket.timeout()
                s.settimeout(left)
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            raise HelperError(f'{self.what} did not answer {op} within {OP_TIMEOUT[op]} s')
        except (FileNotFoundError, ConnectionRefusedError):
            raise HelperError(f'{self.what} does not listen at {self.path}{self.missing}')
        except PermissionError:
            raise HelperError(f'PegaProx may not use {self.path} (its owner or group is not PegaProx\'s)'
                              f'{self.missing}')
        except OSError as e:
            raise HelperError(f'the socket of {self.what} does not answer ({type(e).__name__})')
        finally:
            try:
                s.close()
            except OSError:
                pass
        return _parse_answer(buf.split(b'\n', 1)[0])

    @contextmanager
    def session(self):
        yield self.call


class LocalTransport(_UnixHelper):
    """The helper on this machine, through the socket unit install.sh sets up: systemd
    starts it as root for each connection. No sudo, nothing on an argument list."""
    kind = 'local'
    what = 'the QNetd helper of this host'
    missing = ': run packaging/qnetd/install.sh as root'

    def __init__(self, path=None):
        super().__init__(path or LOCAL_SOCKET)


class SidecarTransport(_UnixHelper):
    """One JSON line to the QNetd container's socket and one back."""
    kind = 'sidecar'
    what = 'the QNetd container'

    def __init__(self, path=None):
        super().__init__(path or os.environ.get(SOCKET_ENV) or SOCKET_DEFAULT)


def _cut(chan, fired):
    fired.set()
    try:
        chan.close()
    except Exception:
        pass


def _exec_bounded(client, cmd, data, timeout, limit):
    """(rc, out, err) of one command over SSH, with a deadline for the whole of it. The
    channel timeout only bounds each read: a host that drips its answer a byte at a time
    would hold the caller (a job and its claims, the status lock of a host) as long as it
    liked. At the deadline the channel is closed and socket.timeout raised."""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    fired = threading.Event()
    timer = threading.Timer(max(1.0, float(timeout)), _cut, args=(stdout.channel, fired))
    timer.daemon = True
    timer.start()
    try:
        try:
            if data:
                stdin.write(data)
                stdin.flush()
        except (OSError, EOFError):
            pass                         # the exit status says what happened
        try:
            stdin.channel.shutdown_write()
        except Exception:
            pass
        out = read_capped(stdout, limit)
        err = read_capped(stderr, NODE_ERR_MAX)
        rc = stdout.channel.recv_exit_status()
    finally:
        timer.cancel()
    if fired.is_set():
        raise socket.timeout(f'no answer within {timeout} s')
    return rc, out, err


def _load_key(paramiko, text):
    import io
    for cls in ('Ed25519Key', 'ECDSAKey', 'RSAKey'):
        klass = getattr(paramiko, cls, None)
        if klass is None:
            continue
        try:
            return klass.from_private_key(io.StringIO(text))
        except Exception:
            continue
    return None


class SshTransport:
    """The helper on another host, over a stored SSH login."""
    kind = 'ssh'

    def __init__(self, rec):
        self.host = bare_host(rec.get('ssh_host') or rec.get('address') or '')
        self.port = int(rec.get('ssh_port') or 22)
        self.user = rec.get('ssh_user') or 'root'
        self._password = rec.get('password') or ''
        self._key = rec.get('ssh_key') or ''

    def _connect(self):
        from pegaprox.utils.concurrent import get_paramiko
        from pegaprox.utils.ssh_security import secure_ssh_client, persist_host_keys
        if not clean_address(self.host) or not SSH_USER_RE.match(self.user):
            raise HelperError('the SSH login of this QNetd host is not valid')
        paramiko = get_paramiko()
        if paramiko is None:
            raise HelperError('paramiko is not installed')
        client = secure_ssh_client(paramiko)
        kw = dict(hostname=self.host, port=self.port, username=self.user, timeout=CONNECT_TIMEOUT,
                  banner_timeout=CONNECT_TIMEOUT, auth_timeout=CONNECT_TIMEOUT,
                  allow_agent=False, look_for_keys=False)
        if self._key:
            pkey = _load_key(paramiko, self._key)
            if pkey is None:
                raise HelperError('the stored SSH key cannot be read')
            kw['pkey'] = pkey
        if self._password:
            kw['password'] = self._password
        if 'pkey' not in kw and 'password' not in kw:
            raise HelperError('no SSH password or key is stored for this QNetd host')
        try:
            client.connect(**kw)
        except Exception as e:
            try:
                client.close()
            except Exception:
                pass
            low = str(e).lower()
            if 'host key' in low or type(e).__name__ == 'BadHostKeyException':
                raise HelperError('the SSH host key of the QNetd host is not the pinned one')
            if type(e).__name__ == 'AuthenticationException':
                raise HelperError('the QNetd host refused the SSH login')
            raise HelperError(f'SSH to the QNetd host failed ({type(e).__name__})')
        persist_host_keys(client)
        return client

    @staticmethod
    def _exec(client, cmd, data=b'', timeout=30, limit=ANSWER_MAX):
        return _exec_bounded(client, cmd, data, timeout, limit)

    def _prefix(self, client):
        rc, out, _e = self._exec(client, 'id -u', timeout=15, limit=64)
        return '' if rc == 0 and out.strip() == '0' else 'sudo -n '

    def _call_on(self, client, prefix, op, name=None, data=None):
        body = _request(op, name, data)
        cmd = prefix + ' '.join(shlex.quote(a) for a in _argv(op, name))
        try:
            rc, out, err = self._exec(client, cmd, json.dumps(body).encode() if body else b'',
                                      timeout=OP_TIMEOUT[op], limit=ANSWER_MAX)
        except socket.timeout:
            raise HelperError(f'the helper did not answer {op} within {OP_TIMEOUT[op]} s')
        except Exception as e:
            raise HelperError(f'the SSH session to the QNetd host broke off ({type(e).__name__})')
        if '[... output truncated' in out:
            raise HelperError('the helper answer is too large')
        try:
            return _parse_answer(out)
        except HelperError:
            # the login worked and no helper answered: missing, broken or not ours to run.
            # Check installs it where the login may (install_problems says whether)
            first = _short(err.splitlines()[0] if err else '', 200)
            raise HelperError(f'the helper did not run on the QNetd host (exit {rc})'
                              + (f': {first}' if first else ''), 'no_helper')

    def call(self, op, name=None, data=None):
        with self.session() as call:
            return call(op, name, data)

    @contextmanager
    def session(self):
        client = self._connect()
        try:
            try:
                prefix = self._prefix(client)
            except Exception as e:
                raise HelperError(f'the SSH session to the QNetd host broke off ({type(e).__name__})')
            yield lambda op, name=None, data=None: self._call_on(client, prefix, op, name, data)
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _install_problem(self, client, prefix):
        """What stops install_helper on this login, as one text, or ''. Reads only."""
        if prefix:
            rc, _o, _e = self._exec(client, 'sudo -n true', timeout=15, limit=64)
            if rc != 0:
                return ('the SSH user can neither log in as root nor sudo without a '
                        'password: install the helper on the QNetd host by hand')
        # as root: a directory the login cannot read would look missing to it. Once both
        # are root's and closed to others nobody else can swap them, and a missing one
        # can only be made by root (its parent is /usr/lib)
        rc, out, _e = self._exec(client, f"{prefix}sh -c {shlex.quote(dir_probe_script(HELPER_DIRS))}",
                                 timeout=15, limit=4096)
        problems = unsafe_dirs(out if rc == 0 else '', HELPER_DIRS)
        if problems:
            return ('refusing to install the helper on the QNetd host: ' + '; '.join(problems)
                    + ' - make it a plain directory of root, mode 0755, then run Check again')
        return ''

    def install_problem(self):
        """Whether install_helper would go through, for a plan: '' or what stops it.
        sudo -n true and a stat of the two directories, nothing that changes the host."""
        client = self._connect()
        try:
            return self._install_problem(client, self._prefix(client))
        finally:
            try:
                client.close()
            except Exception:
                pass

    def install_helper(self, payload):
        """Copy our helper over and install it root-owned. Only where the login is root
        or may sudo without a password, and only into directories nobody but root can
        change (install.sh's safe_dir): the file there runs as root. The copy goes into a
        private mktemp directory first."""
        client = self._connect()
        try:
            prefix = self._prefix(client)
            problem = self._install_problem(client, prefix)
            if problem:
                raise HelperError(problem)
            rc, out, _e = self._exec(client, 'umask 077 && mktemp -d', timeout=15, limit=512)
            tmp = out.strip()
            if rc != 0 or not re.match(r'^/[A-Za-z0-9._/-]{1,200}\Z', tmp or ''):
                raise HelperError('no private temporary directory on the QNetd host')
            try:
                sftp = client.open_sftp()
                try:
                    with sftp.file(f'{tmp}/pegaprox-qnetd-helper', 'wb') as fh:
                        fh.write(payload)
                    sftp.chmod(f'{tmp}/pegaprox-qnetd-helper', 0o700)
                finally:
                    sftp.close()
                dest = shlex.quote(HELPER_PATH)
                src = shlex.quote(f'{tmp}/pegaprox-qnetd-helper')
                folder = shlex.quote(os.path.dirname(HELPER_PATH))
                cmd = (f"{prefix}install -d -o root -g root -m 0755 -- {folder} && "
                       f"{prefix}install -o root -g root -m 0755 -- {src} {dest}")
                rc, _o, err = self._exec(client, cmd, timeout=30, limit=4096)
                if rc != 0:
                    raise HelperError(f'installing the helper failed: {_short(err, 200)}')
            finally:
                self._exec(client, f'rm -rf -- {shlex.quote(tmp)}', timeout=15, limit=64)
        finally:
            try:
                client.close()
            except Exception:
                pass


def dir_probe_script(dirs):
    """One line per directory: '<path> dir <uid> <octal mode>', '<path> link', '<path>
    other' or '<path> none'. The paths are fixed ones of ours, quoted all the same."""
    lines = []
    for d in dirs:
        q = shlex.quote(d)
        lines.append(f'if [ -L {q} ]; then echo {q} link; '
                     f'elif [ -d {q} ]; then echo {q} dir $(stat -c "%u %a" {q}); '
                     f'elif [ -e {q} ]; then echo {q} other; else echo {q} none; fi')
    return '\n'.join(lines) + '\n'


def unsafe_dirs(text, dirs):
    """What is wrong with the directories as dir_probe_script saw them, one text each; a
    directory it did not report counts as wrong (nothing is installed blind)."""
    seen = {}
    for line in str(text or '').splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in dirs:
            seen[parts[0]] = parts[1:]
    out = []
    for d in dirs:
        got = seen.get(d)
        if not got:
            out.append(f'{d} could not be checked')
        elif got[0] == 'none':
            continue
        elif got[0] == 'link':
            out.append(f'{d} is a symlink')
        elif got[0] != 'dir':
            out.append(f'{d} is not a directory')
        elif len(got) != 3 or not got[1].isdigit() or not re.match(r'^[0-7]{3,4}\Z', got[2]):
            out.append(f'{d} could not be checked')
        elif got[1] != '0':
            out.append(f'{d} belongs to uid {got[1]}, not root')
        elif int(got[2], 8) & 0o022:
            out.append(f'{d} is writable by group or others (mode {got[2]})')
    return out


def transport_for(rec):
    kind = rec.get('kind')
    if kind == 'local':
        return LocalTransport()
    if kind == 'sidecar':
        return SidecarTransport()
    if kind == 'ssh':
        return SshTransport(rec)
    raise HelperError(f'unknown QNetd host kind {kind!r}')


def _ok(ans, what):
    """The answer of a call that has to succeed."""
    if not ans.get('ok'):
        raise HelperError(f"{what}: {_short(ans.get('error') or 'the helper refused', 200)}", ans.get('code'))
    return ans


def _version_info(ans):
    try:
        proto = int(ans.get('protocol'))
    except (TypeError, ValueError, OverflowError):     # 1e999 parses as infinity
        proto = 0
    ops = ans.get('ops')
    ops = [o for o in ops[:32] if isinstance(o, str) and re.match(r'^[a-z_]{1,20}\Z', o)] \
        if isinstance(ops, list) else []
    pm = ans.get('package_manager')
    pkgs = ans.get('packages')
    pkgs = [x for x in pkgs[:8] if isinstance(x, str) and re.match(r'^[a-z0-9][a-z0-9+.-]{0,63}\Z', x)] \
        if isinstance(pkgs, list) else []
    return {'protocol': proto, 'expected_protocol': PROTOCOL, 'outdated': proto < PROTOCOL,
            'qnetd_installed': bool(ans.get('qnetd_installed')),
            'certutil_installed': bool(ans.get('certutil_installed')),
            'ops': ops, 'firewall_op': 'firewall' in ops,
            'package_manager': pm if isinstance(pm, str) and pm in QNETD_PACKAGES else None,
            'packages': pkgs}


def local_helper_copy():
    """(bytes, protocol) of the helper this PegaProx ships, or (None, 0)."""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for path in (os.path.join(root, 'packaging', 'qnetd', 'pegaprox-qnetd-helper'), HELPER_PATH):
        try:
            with open(path, 'rb') as fh:
                data = fh.read(HELPER_MAX + 1)
        except OSError:
            continue
        if len(data) > HELPER_MAX or not data.startswith(b'#!'):
            continue
        m = _PROTOCOL_LINE.search(data)
        if m:
            return data, int(m.group(1))
    return None, 0


_avail = {}
_avail_lock = threading.Lock()


def transports_available(max_age=60):
    """Whether this machine can be a QNetd host itself: {'local': {...}, 'sidecar': {...}}.
    Each is asked `version` on its socket, where there is one."""
    import stat
    now = time.time()
    with _avail_lock:
        hit = _avail.get('v')
        if hit and 0 <= now - hit[0] < max_age:
            return hit[1]
    out = {}
    for kind, tr in (('local', LocalTransport()), ('sidecar', SidecarTransport())):
        try:
            there = stat.S_ISSOCK(os.stat(tr.path).st_mode)
        except OSError:
            there = False
        if not there:
            out[kind] = {'available': False, 'reason': 'no helper socket - run packaging/qnetd/install.sh as root'
                         if kind == 'local' else 'no helper socket'}
            continue
        try:
            info = _version_info(_ok(tr.call('version'), 'version'))
            out[kind] = dict(info, available=not info['outdated'],
                             reason='helper outdated, re-run install.sh' if info['outdated'] else '')
        except HelperError as e:
            out[kind] = {'available': False, 'reason': str(e)}
    with _avail_lock:
        _avail['v'] = (now, out)
    return out


# ---------------------------------------------------------------------------
# QNetd host checks and status
# ---------------------------------------------------------------------------

def _ca_fingerprint(ans):
    raw = _b64_file(ans.get('ca_b64'), FILE_MAX)
    if not _looks_like_pem_or_der(raw, 'crt'):
        raise HelperError('the CA in the answer is no certificate')
    # pinned on the certificate, not on the file: the listing in front of it is certutil's
    # wording, which an NSS update on the QNetd host may change for the very same CA
    cert = _pem_cert(raw)
    return raw, hashlib.sha256(cert if cert is not None else raw).hexdigest()


def _pin_ca(rec, fingerprint, learn):
    """The CA of a host is pinned the first time it answers: a local or sidecar host on
    another machine after a switch, or a reinstalled host, would sign with another CA."""
    pinned = rec.get('ca_sha256') or ''
    if not pinned:
        if learn:
            from pegaprox.core.db import get_db
            get_db().set_qnetd_ca_pin(rec['id'], fingerprint)
            rec['ca_sha256'] = fingerprint
        return
    if pinned != fingerprint:
        raise HelperError('the CA of this QNetd host is not the one PegaProx pinned: it is another '
                          'host or was set up again. Reset the CA pin if that is intended')


def check_host(rec, init=True, upgrade=True):
    """A write: make the helper usable and the QNetd running. For an ssh host a missing
    or older helper is installed first where the login may. Never raises."""
    out = {'ok': False, 'helper_installed': False, 'active': None, 'tls_required': None, 'error': ''}
    tr = None
    try:
        tr = transport_for(rec)
        try:
            info = _version_info(_ok(tr.call('version'), 'version'))
        except HelperError as e:
            info, first = None, e
        if rec.get('kind') == 'ssh' and upgrade and (info is None or info['outdated']):
            payload, proto = local_helper_copy()
            if payload is None or proto < PROTOCOL:
                raise (first if info is None else HelperError('the helper on the QNetd host is outdated'))
            tr.install_helper(payload)
            out['helper_installed'] = True
            info = _version_info(_ok(tr.call('version'), 'version'))
        elif info is None:
            raise first
        out.update(info)
        if info['outdated']:
            raise HelperError('the helper is outdated: re-run packaging/qnetd/install.sh on that host'
                              if rec.get('kind') == 'local' else 'the helper is outdated')
        with tr.session() as call:
            if init:
                ans = _ok(call('init'), 'init')
                out['active'] = bool(ans.get('active'))
            _raw, fp = _ca_fingerprint(_ok(call('ca'), 'ca'))
            _pin_ca(rec, fp, learn=True)
            out['ca_sha256'] = fp
            st = _ok(call('status'), 'status')
            if not init:
                out['active'] = bool(st.get('active'))
            out['tls_required'] = _tls(st)
        out['ok'] = bool(out['active'])
        if not out['active']:
            out['error'] = 'corosync-qnetd is not running on the QNetd host'
    except HelperError as e:
        out['error'] = str(e)
    except Exception as e:
        log.warning(f"[qnetd] check of {rec.get('id')} failed: {type(e).__name__}: {e}")
        out['error'] = f'the check failed ({type(e).__name__})'
    _forget_status(rec.get('id'))
    return out


_status = {}       # qnetd_id -> view
_status_locks = {}
_status_guard = threading.Lock()


def _status_lock(host_id):
    with _status_guard:
        lk = _status_locks.get(host_id)
        if lk is None:
            lk = _status_locks[host_id] = threading.Lock()
        return lk


def _forget_status(host_id):
    _status.pop(host_id, None)


def _clean_clusters(value):
    out = []
    for c in (value if isinstance(value, list) else [])[:2000]:
        if not isinstance(c, dict):
            continue
        nodes = []
        for n in (c.get('nodes') if isinstance(c.get('nodes'), list) else [])[:64]:
            if not isinstance(n, dict):
                continue
            row = {'node_id': n.get('node_id') if isinstance(n.get('node_id'), int) else None,
                   'addr': _short(n.get('addr'), 100)}
            for k in ('vote', 'tls'):
                row[k] = _short(n.get(k), 60) if isinstance(n.get(k), str) else None
            nodes.append(row)
        out.append({'name': _short(c.get('name'), 64), 'algorithm': _short(c.get('algorithm'), 60),
                    'tie_breaker': _short(c.get('tie_breaker'), 60), 'nodes': nodes})
    return out


def _cert_names(value):
    """The cluster names a status answer says the QNetd host holds a certificate for. None
    where it does not say (a helper of an older build) or says anything but a list of
    cluster names: then nobody here can tell."""
    if not isinstance(value, list) or len(value) > CERTS_MAX:
        return None
    if not all(isinstance(v, str) and CLUSTER_NAME_RE.match(v) for v in value):
        return None
    return list(value)


def _tls(st):
    """tls_required of a status answer: True or False as the helper said, else None."""
    value = st.get('tls_required')
    return value if isinstance(value, bool) else None


def read_status(rec, now=None):
    """Ask the host now: version, status and CA. Raises nothing."""
    now = time.time() if now is None else now
    prev = _status.get(rec['id']) or {}
    view = {'qnetd_id': rec['id'], 'at': now,
            'read_at': datetime.fromtimestamp(now, timezone.utc).isoformat(timespec='seconds'),
            'ok': False, 'active': None, 'protocol': None, 'outdated': None, 'clusters': [],
            'raw': '', 'tls_required': None, 'error': ''}
    try:
        tr = transport_for(rec)
        with tr.session() as call:
            info = _version_info(_ok(call('version'), 'version'))
            view.update(protocol=info['protocol'], outdated=info['outdated'])
            if info['outdated']:
                raise HelperError('the helper is outdated')
            st = _ok(call('status'), 'status')
            _raw, fp = _ca_fingerprint(_ok(call('ca'), 'ca'))
            _pin_ca(rec, fp, learn=False)
        view.update(ok=True, active=bool(st.get('active')), clusters=_clean_clusters(st.get('clusters')),
                    raw=str(st.get('raw') or '')[:64 * 1024], tls_required=_tls(st))
    except HelperError as e:
        view['error'] = str(e)
    except Exception as e:
        log.debug(f"[qnetd] status of {rec.get('id')}: {type(e).__name__}: {e}")
        view['error'] = f'the status read failed ({type(e).__name__})'
    healthy = view['ok'] and view['active']
    view['streak'] = 0 if healthy else int(prev.get('streak') or 0) + 1
    return view


def status(rec, max_age=FRESH, now=None):
    """The status of a host no older than max_age; callers at the same time wait for the
    one read, and a failed read is kept as long as a good one."""
    with _status_lock(rec['id']):
        at = time.time() if now is None else now
        hit = _status.get(rec['id'])
        if hit is not None and 0 <= at - hit['at'] < max_age:
            return hit
        view = read_status(rec, now=at)
        _status[rec['id']] = view
        return view


def cached_status(host_id, now=None):
    hit = _status.get(host_id)
    now = time.time() if now is None else now
    if hit is None or not 0 <= now - hit['at'] < SERVE_MAX:
        return None
    return hit


def public_status(view, now=None):
    if not view:
        return None
    now = time.time() if now is None else now
    out = {k: view.get(k) for k in ('qnetd_id', 'ok', 'active', 'protocol', 'outdated', 'clusters',
                                    'raw', 'tls_required', 'error', 'read_at', 'streak')}
    out['age'] = max(0, int(now - view['at']))
    out['expected_protocol'] = PROTOCOL
    return out


_refreshing = threading.Event()


def kick_refresh(now=None, cluster_ids=None):
    """From the alert loop: read, in the background, the QNetd hosts the clusters in
    `cluster_ids` (the ones a qnetd rule watches; None: every attached cluster) vote
    through, each at most every REFRESH_EVERY (never more often than the FRESH cache of
    the status route). One refresh at a time, on the tick's clock."""
    if _refreshing.is_set():
        return False
    try:
        from pegaprox.core.db import get_db
        db = get_db()
        wanted = None if cluster_ids is None else set(cluster_ids)
        attached = {a['qnetd_id'] for a in db.list_qnetd_attachments()
                    if wanted is None or a['cluster_id'] in wanted}
    except Exception as e:
        log.debug(f"[qnetd] attachments unreadable: {e}")
        return False
    now = time.time() if now is None else now
    due = [h for h in attached if (now - (_status.get(h) or {}).get('at', 0)) >= REFRESH_EVERY]
    if not due:
        return False
    _refreshing.set()

    def work():
        from pegaprox.core import ha
        try:
            from pegaprox.utils.concurrent import run_per_node
            recs = {}
            for h in due:
                rec = db.get_qnetd_host(h, secrets=True)
                if rec:
                    recs[h] = rec
            # version, status and ca change nothing on the host; in an automatic group a
            # plain thread's SSH command is refused unless it says it reads
            with ha.reading():
                run_per_node({h: (lambda _h, r=rec: status(r, max_age=REFRESH_EVERY, now=now))
                              for h, rec in recs.items()}, max_concurrent=4, timeout=120)
        except Exception as e:
            log.debug(f"[qnetd] background refresh failed: {e}")
        finally:
            _refreshing.clear()
    threading.Thread(target=work, daemon=True, name='qnetd-status').start()
    return True


def alert_view(cid, now=None):
    """What the qnetd alert rule of a cluster looks at: one row per QNetd host the cluster
    is attached to, from the cache only. None when the attachments cannot be read. No
    name, address or error: whoever sees the cluster's alerts sees what the rule raised.

      state  ok | down (unreachable, or the helper refused) | inactive (corosync-qnetd not
             running) | outdated | unknown (no read recent enough, or not FAIL_STREAK
             failures in a row yet)
    """
    try:
        from pegaprox.core.db import get_db
        db = get_db()
        rows = db.list_qnetd_attachments(cluster_id=cid)
    except Exception as e:
        log.debug(f"[qnetd] attachments of {cid} unreadable: {e}")
        return None
    out = []
    for a in rows:
        rec = db.get_qnetd_host(a['qnetd_id'])
        if rec is None:
            continue
        v = cached_status(rec['id'], now=now)
        state = 'unknown'
        if v is not None:
            if v['ok'] and v['active']:
                state = 'ok'
            elif int(v.get('streak') or 0) >= FAIL_STREAK:
                state = 'outdated' if v.get('outdated') else ('inactive' if v['ok'] else 'down')
        out.append({'qnetd_id': rec['id'], 'state': state, 'read_at': v['read_at'] if v else None})
    return out


# ---------------------------------------------------------------------------
# commands on the cluster nodes
# ---------------------------------------------------------------------------

class NodeShell:
    """One SSH login to a node through the manager's own connection code (its credentials,
    the pinned host key, the IPv6 address handling and the HA transport guard), with
    stdin. Commands run as root: directly, or with `sudo -n` for a non-root login."""

    def __init__(self, mgr, node):
        self.node = node
        ip = mgr.member_node_ip(node)
        if not ip:
            raise NodeError(f'node {node}: no address of it answers')
        failure = {}
        client = mgr._ssh_connect(ip, retries=2, retry_delay=1.0, connect_timeout=15, failure=failure)
        if client is None:
            raise NodeError(f"node {node}: PegaProx cannot log in over SSH "
                            f"({failure.get('kind') or 'failed'})")
        self._client = client
        rc, out, _e = self._exec('id -u', None, 15, 64)
        self._prefix = '' if rc == 0 and out.strip() == '0' else 'sudo -n '

    def _exec(self, cmd, data, timeout, limit):
        return _exec_bounded(self._client, cmd, data, timeout, limit)

    def run(self, script, data=None, timeout=NODE_TIMEOUT, limit=NODE_OUT_MAX):
        """(rc, out, err) of a bash script as root. The script carries no secret: whatever
        is secret comes as `data` on stdin."""
        try:
            return self._exec(f"{self._prefix}bash -c {shlex.quote(script)}", data, timeout, limit)
        except socket.timeout:
            return 124, '', f'no answer within {timeout} s'
        except Exception as e:
            return 255, '', f'{type(e).__name__}'

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass


def _open_shell(mgr, node):
    return NodeShell(mgr, node)


def _budget(count, each):
    return min(1800, max(1, math.ceil(count / FANOUT)) * (each + 5))


def _per_node(shells, fn, each=NODE_TIMEOUT):
    """{node: result or None} of fn(shell) on every shell, FANOUT at a time."""
    from pegaprox.utils.concurrent import run_per_node
    if not shells:
        return {}
    return run_per_node({n: (lambda _n, s=s: fn(s)) for n, s in shells.items()},
                        max_concurrent=FANOUT, timeout=_budget(len(shells), each))


def _open_shells(mgr, nodes):
    """({node: shell}, {node: error}) for the nodes, opened FANOUT at a time."""
    from pegaprox.utils.concurrent import run_per_node

    def one(node):
        try:
            return _open_shell(mgr, node)
        except NodeError as e:
            return str(e)
        except Exception as e:
            return f'node {node}: {type(e).__name__}'
    got = run_per_node({n: one for n in nodes}, max_concurrent=FANOUT, timeout=_budget(len(nodes), 60))
    shells, errors = {}, {}
    for n in nodes:
        r = got.get(n)
        if r is None or isinstance(r, str):
            errors[n] = r or f'node {n}: no SSH login in time'
        else:
            shells[n] = r
    return shells, errors


def _close(shells):
    for s in (shells or {}).values():
        try:
            s.close()
        except Exception:
            pass


def _kv(text):
    out = {}
    for line in str(text or '').splitlines():
        k, sep, v = line.partition('=')
        if sep and re.match(r'^[a-z_]{1,20}$', k):
            out[k] = v.strip()
    return out


# The address a node sends from towards the QNetd: the first address of the name (getent
# resolves numeric ones as they are) the kernel has a route for, and the src of that route.
# These are what the firewall of the QNetd host is opened for.
_SOURCE_PROBE = r'''{ getent ahosts "$1" 2>/dev/null || printf '%s\n' "$1"; } |
awk '!seen[$1]++ { print $1 }' | head -n 8 |
while read -r a; do
  s=$(ip -o route get "$a" 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }')
  if [ -n "$s" ]; then printf '%s\n' "$s"; break; fi
done
'''


# What a node has. The QNetd address and port reach bash's /dev/tcp and the source probe
# as positional arguments of an inner bash, never as part of its program text.
def probe_script(host, port):
    qh = shlex.quote(host)
    return (
        "q() { command -v \"$1\" >/dev/null 2>&1 && echo 1 || echo 0; }\n"
        "echo \"pkg=$(q corosync-qdevice)\"\n"
        "echo \"certutil=$(q corosync-qdevice-net-certutil)\"\n"
        f"if [ -d {NODE_STORE} ]; then echo store=1; else echo store=0; fi\n"
        "echo \"uuid=$(head -c 64 /sys/class/dmi/id/product_uuid 2>/dev/null)\"\n"
        "if timeout 5 bash -c 'exec 3<>\"/dev/tcp/$1/$2\"' _ "
        f"{qh} {shlex.quote(str(int(port)))} >/dev/null 2>&1; "
        "then echo port=1; else echo port=0; fi\n"
        f"echo \"src=$(timeout 10 bash -c {shlex.quote(_SOURCE_PROBE)} _ {qh} 2>/dev/null"
        " | head -n 1 | head -c 64)\"\n")


_PERL_READ = r'''use strict; use warnings;
use PVE::Cluster; use PVE::Corosync;
my $conf = PVE::Cluster::cfs_read_file("corosync.conf");
die "corosync.conf is unreadable\n" if ref($conf) ne "HASH" || ref($conf->{main}) ne "HASH";
my $main = $conf->{main};
my $quorum = ref($main->{quorum}) eq "HASH" ? $main->{quorum} : {};
print "name=", ($main->{totem}->{cluster_name} // ""), "\n";
print "device=", (defined($quorum->{device}) ? 1 : 0), "\n";
print "two_node=", ($quorum->{two_node} // 0), "\n";
'''

# The section `pvecm qdevice setup` writes (ffsplit, votes 1), under the same lock and
# through the same writer. Host and port come in as arguments and are checked again here.
_PERL_ADD = r'''use strict; use warnings;
use PVE::Cluster; use PVE::Corosync;
my ($host, $port) = @ARGV;
die "invalid QNetd host\n" if !defined($host)
    || $host !~ /\A(?:[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}|[0-9A-Fa-f:.]{2,45})\z/;
die "invalid QNetd port\n" if !defined($port) || $port !~ /\A[0-9]{1,5}\z/ || $port < 1 || $port > 65535;
my $code = sub {
    my $conf = PVE::Cluster::cfs_read_file("corosync.conf");
    my $quorum_section = $conf->{main}->{quorum};
    die "corosync.conf has no quorum section\n" if ref($quorum_section) ne "HASH";
    die "Qdevice already configured, must be removed before setting up new one!\n"
        if defined($quorum_section->{device});
    my $qdev_section = {
        model => "net",
        "net" => {
            tls => "on",
            host => $host,
            algorithm => "ffsplit",
        },
    };
    $qdev_section->{net}->{port} = $port if $port != 5403;
    $qdev_section->{votes} = 1;
    $quorum_section->{device} = $qdev_section;
    PVE::Corosync::atomic_write_conf($conf);
};
PVE::Cluster::cfs_lock_file("corosync.conf", 10, $code);
die $@ if $@;
print "written\n";
'''

# Rollback: take out the entry this setup wrote, and only that one.
_PERL_DEL = r'''use strict; use warnings;
use PVE::Cluster; use PVE::Corosync;
my ($host) = @ARGV;
die "invalid QNetd host\n" if !defined($host)
    || $host !~ /\A(?:[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}|[0-9A-Fa-f:.]{2,45})\z/;
my $removed = 0;
my $code = sub {
    my $conf = PVE::Cluster::cfs_read_file("corosync.conf");
    my $quorum_section = $conf->{main}->{quorum};
    return if ref($quorum_section) ne "HASH" || !defined($quorum_section->{device});
    my $net = $quorum_section->{device}->{net};
    die "the QDevice entry names another QNetd host, left as it is\n"
        if ref($net) ne "HASH" || ($net->{host} // "") ne $host;
    delete $quorum_section->{device};
    PVE::Corosync::atomic_write_conf($conf);
    $removed = 1;
};
PVE::Cluster::cfs_lock_file("corosync.conf", 10, $code);
die $@ if $@;
print $removed ? "removed\n" : "absent\n";
'''


def conf_read_script():
    return f"perl -e {shlex.quote(_PERL_READ)}"


def conf_add_script(host, port):
    """The command that adds the quorum.device section. host and port are validated
    here and once more inside the perl; they reach it as arguments, not as code."""
    host = clean_address(host)
    port = clean_port(port, None)
    if not host or not port:
        raise ValueError('invalid QNetd address')
    return f"perl -e {shlex.quote(_PERL_ADD)} -- {shlex.quote(host)} {shlex.quote(str(port))}"


def conf_del_script(host):
    host = clean_address(host)
    if not host:
        raise ValueError('invalid QNetd address')
    return f"perl -e {shlex.quote(_PERL_DEL)} -- {shlex.quote(host)}"


def own_vm_script(product_uuid):
    """One grep over every guest config of the cluster for the QNetd host's SMBIOS UUID."""
    if not UUID_RE.match(product_uuid or ''):
        raise ValueError('invalid UUID')
    pattern = f'^smbios1:.*uuid={product_uuid}([^0-9a-f-]|$)'
    return ("grep -r -l -i -E --include='*.conf' -e "
            f"{shlex.quote(pattern)} -- /etc/pve/nodes; rc=$?; echo \"rc=$rc\" >&2; exit $rc")


# A file reaches the node on stdin, as base64, into a directory only root can enter, and
# the directory goes again whatever happens.
_STAGED = ("set -e\numask 077\nd=$(mktemp -d)\ntrap 'rm -rf \"$d\"' EXIT\n"
           "base64 -d > \"$d/{file}\"\n")


def ca_import_script():
    return _STAGED.format(file='qnetd-cacert.crt') + \
        'corosync-qdevice-net-certutil -i -c "$d/qnetd-cacert.crt" >/dev/null\n'


def crq_script(name):
    if not clean_cluster_name(name):
        raise ValueError('invalid cluster name')
    return ("set -e\n"
            f"corosync-qdevice-net-certutil -r -n {shlex.quote(name)} >/dev/null\n"
            f"base64 -w0 {NODE_STORE}/qdevice-net-node.crq\n")


def crt_import_script(name):
    if not clean_cluster_name(name):
        raise ValueError('invalid cluster name')
    f = f'cluster-{name}.crt'
    return _STAGED.format(file=f) + \
        f'corosync-qdevice-net-certutil -M -c "$d/{f}" >/dev/null\n' \
        f'base64 -w0 {NODE_STORE}/qdevice-net-node.p12\n'


def p12_import_script():
    return _STAGED.format(file='qdevice-net-node.p12') + \
        'corosync-qdevice-net-certutil -m -c "$d/qdevice-net-node.p12" >/dev/null\n'


START_SCRIPT = 'systemctl start corosync-qdevice && systemctl enable corosync-qdevice'
RELOAD_SCRIPT = 'corosync-cfgtool -R'
STORE_RESET_SCRIPT = f'rm -rf -- {NODE_STORE}'
CLEANUP_SCRIPT = ('systemctl stop corosync-qdevice >/dev/null 2>&1; '
                  'systemctl disable corosync-qdevice >/dev/null 2>&1; '
                  'rm -rf -- /etc/corosync/qdevice')
APT_SCRIPT = ('DEBIAN_FRONTEND=noninteractive apt-get install -y -q '
              '-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold corosync-qdevice')
REMOVE_SCRIPT = 'pvecm qdevice remove'

# Whether apt on a node gets to the package sources it would install corosync-qdevice
# from: one lookup and one connect per host, all at once. Without DNS or a route, apt-get
# waits on every try and holds the packages step for APT_TIMEOUT. src=unknown where that
# cannot be told from here (a proxy, file:, cdrom:, mirror+ and the like): apt-get decides.
SOURCES_SCRIPT = r'''export LANG=C LC_ALL=C
unknown() { echo src=unknown; exit 0; }
command -v apt-get >/dev/null 2>&1 || unknown
apt-config dump 2>/dev/null | grep -qE '^Acquire::[A-Za-z]+::Proxy' && unknown
if pkgs=$(apt-get -qq install --print-uris corosync-qdevice 2>/dev/null); then
  [ -n "$pkgs" ] || { echo src=ok; exit 0; }
else
  pkgs=''
fi
lists=$(apt-get indextargets --no-release-info --format '$(REPO_URI)' 2>/dev/null)
# one line per scheme://host[:port]; a line without :// (file:, cdrom:) stays as it is
targets=$(printf '%s\n%s\n' "$pkgs" "$lists" | sed -e "s/^'//" -e 's/[ '"'"'].*//' \
  -e 's|^\([A-Za-z][A-Za-z0-9+.-]*://[^/]*\).*|\1|' | grep -v '^$' | sort -u)
[ -n "$targets" ] || unknown
[ "$(printf '%s\n' "$targets" | wc -l)" -le 16 ] || unknown
d=$(mktemp -d) || unknown
trap 'rm -rf "$d"' EXIT
i=0
while read -r uri; do
  i=$((i + 1))
  case $uri in http://*) port=80 ;; https://*) port=443 ;; *) unknown ;; esac
  hp=${uri#*://}; hp=${hp%%/*}; hp=${hp##*@}
  if [[ $hp =~ ^\[([0-9A-Fa-f:.]{2,45})\](:([0-9]{1,5}))?$ ]] || [[ $hp =~ ^([A-Za-z0-9._-]{1,253})(:([0-9]{1,5}))?$ ]]; then
    h=${BASH_REMATCH[1]}; port=${BASH_REMATCH[3]:-$port}
  else
    unknown
  fi
  (
    if ! timeout 8 getent ahosts "$h" >/dev/null 2>&1; then echo "$h: no address" >"$d/$i"
    elif timeout 5 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$h" "$port" >/dev/null 2>&1; then echo ok >"$d/$i"
    else echo "$h: no connection to port $port" >"$d/$i"; fi
  ) &
done <<<"$targets"
wait
if grep -qx ok "$d"/* 2>/dev/null; then echo src=ok; exit 0; fi
echo src=none
echo "why=$(head -n 1 "$d/1" 2>/dev/null)"
'''
SOURCES_TIMEOUT = 40


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------

def _cluster_status(mgr):
    from pegaprox.core import qdevice
    status, data, _err = qdevice._get(mgr, None, '/cluster/status')
    if status != 200 or not isinstance(data, list):
        return None
    return data


class _Ctx:
    """What a preflight found, for the setup that follows it; in plan mode also what the
    plan is made of."""

    def __init__(self):
        self.shells, self.first, self.name, self.nodes = {}, None, None, []
        self.missing_pkg, self.stores = [], []
        self.product_uuid = ''
        self.sources = {}              # node -> the address it sends from towards the QNetd
        # plan mode: what the run sets up on the QNetd host, and what its firewall said
        self.qnetd = {'helper': None, 'packages': None, 'tls': False, 'ca': False, 'start': False}
        self.deferred = False          # no current helper there yet: the run brings it first
        # a certificate of an earlier setup for this name on the QNetd host: True, False,
        # None where that cannot be told
        self.cert_on_file = None
        self.firewall = None
        self.firewall_error = ''
        self.firewall_open = False     # the run opens the port for the nodes


class _Deferred(Exception):
    """Plan mode: the QNetd side cannot be read before the run puts a current helper there."""


def _fw_list(value):
    """The addresses in a firewall answer's rules, added or removed ([{source, port}] or
    plain strings); anything that is not a single address is dropped."""
    out = []
    for r in (value if isinstance(value, list) else [])[:FW_SOURCES_MAX * 4]:
        c = clean_source(r.get('source') if isinstance(r, dict) else r)
        if c and c not in out:
            out.append(c)
    return out


def _fw_view(ans, fallback_port):
    backend = ans.get('backend') if isinstance(ans.get('backend'), str) and ans['backend'] in FW_BACKENDS else None
    blocking = ans.get('blocking')
    manual = ''.join(ch for ch in str(ans.get('manual') or '')[:4096] if ch == '\n' or ch.isprintable())
    return {'backend': backend, 'managed': ans.get('managed') is True and backend in FW_MANAGED,
            'blocking': blocking if isinstance(blocking, bool) else None,
            'port': clean_port(ans.get('port'), None) or fallback_port,
            'rules': _fw_list(ans.get('rules')), 'manual': manual.strip()}


def manual_rules(backend, port, sources):
    """What an admin runs (for pve-firewall: puts under [RULES] of host.fw) to open `port`
    for `sources` on a firewall PegaProx does not change; the helper's own lines win."""
    lines = []
    for s in sources:
        v6 = ':' in s
        if backend == 'pve-firewall':
            lines.append(f'IN ACCEPT -source {s} -p tcp -dport {port}')
        elif backend == 'nftables':
            lines.append(f"nft add rule inet filter input {'ip6' if v6 else 'ip'} saddr {s} tcp dport {port} accept")
        elif backend == 'iptables':
            lines.append(f"{'ip6tables' if v6 else 'iptables'} -I INPUT -p tcp -s {s} --dport {port} -j ACCEPT")
    return '\n'.join(lines)


FW_PLACEHOLDER = '<node address>'          # what the helper's lines hold without sources


def expand_manual(text, sources):
    """The helper's lines for a firewall it does not change, with its placeholder replaced
    by each node address that fits the line (iptables/ip6tables, ip/ip6 saddr; an inet
    table takes both). Lines without the placeholder stay as they are."""
    out = []
    for line in str(text or '').splitlines():
        if FW_PLACEHOLDER not in line:
            if not line.startswith('# ip6 saddr for a node') and line not in out:
                out.append(line)
            continue
        inet = ' rule inet ' in f' {line}'
        for src in sources:
            v6 = ':' in src
            cand = line
            if (line.startswith('iptables ') and v6) or (line.startswith('ip6tables ') and not v6):
                continue
            if ' ip saddr ' in line and v6:
                if not inet:
                    continue
                cand = line.replace(' ip saddr ', ' ip6 saddr ')
            elif ' ip6 saddr ' in line and not v6:
                if not inet:
                    continue
                cand = line.replace(' ip6 saddr ', ' ip saddr ')
            cand = cand.replace(FW_PLACEHOLDER, src)
            if cand not in out:
                out.append(cand)
    return '\n'.join(out)


def _install_problem(rec):
    """For a plan: what stops the run from putting its helper on this ssh host, or ''."""
    payload, proto = local_helper_copy()
    if payload is None or proto < PROTOCOL:
        return f'this PegaProx has no helper of protocol {PROTOCOL} to put on the QNetd host'
    probe = getattr(transport_for(rec), 'install_problem', None)
    if probe is None:
        return ''
    try:
        return probe() or ''
    except HelperError as e:
        return str(e)
    except Exception as e:
        return f'the SSH session to the QNetd host broke off ({type(e).__name__})'


def _blocking(report, confirm):
    """The messages of the checks that stop a setup."""
    return [c['message'] for c in report['checks']
            if c['blocking'] and c['ok'] is not True
            and not (c['id'] == 'not_own_vm' and c['ok'] is None and confirm)]


def inspect(cid, mgr, rec, install_packages=False, confirm_unverified=False, busy=True, ctx=None,
            plan=False, open_firewall=False, replace_certificate=False):
    """The preflight of a QDevice setup of cluster `cid` against QNetd host `rec`.

    Every check names what it found. ok of a check: True passed, False failed, None could
    not tell. The report is ok when every blocking check passed; the one exception is
    not_own_vm=None, which a caller may confirm (confirm_unverified). With `ctx` the open
    node logins are left in it for the setup, else closed here.

    A certificate of an earlier setup for the cluster's name on the QNetd host (and no
    cluster of that name connected) fails cert_on_file unless replace_certificate: the
    sign step would refuse it (name_exists) half way through the run.

    plan=True reads for plan(): what the run sets up on the QNetd host itself (the helper
    of an ssh host, corosync-qnetd, its CA, TLS, the service, and with open_firewall the
    port on a firewall the helper changes) goes into ctx instead of failing a check, and
    a check that can only be made after that is deferred (deferred: True, not blocking;
    the run's preflight makes it). The helper is asked nothing that changes the host:
    version, status, ca, uuid and firewall inspect."""
    from pegaprox.core.db import get_db
    checks = []
    report = {'ok': False, 'cluster_id': cid, 'cluster_name': None, 'qnetd_id': rec['id'],
              'qnetd_name': rec['name'], 'qnetd_address': rec['address'], 'qnetd_port': rec['port'],
              'install_packages': bool(install_packages), 'needs_confirmation': False,
              'node_count': 0, 'nodes': [], 'checks': checks,
              'read_at': datetime.now(timezone.utc).isoformat(timespec='seconds')}

    def check(cid_, ok, message, blocking=True, deferred=False):
        row = {'id': cid_, 'ok': ok, 'blocking': blocking and not deferred, 'message': message}
        if deferred:
            row['deferred'] = True
        checks.append(row)
        return ok

    def done():
        report['needs_confirmation'] = any(c['id'] == 'not_own_vm' and c['ok'] is None and not c.get('deferred')
                                           for c in checks)
        report['ok'] = bool(checks) and all(
            c['ok'] is True or not c['blocking']
            or (c['id'] == 'not_own_vm' and c['ok'] is None and confirm_unverified)
            for c in checks)
        return report

    own = ctx if ctx is not None else _Ctx()
    kind = rec.get('kind')
    try:
        if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
            check('cluster_type', False, 'Only a Proxmox VE cluster has corosync')
            return done()
        if not getattr(mgr, 'is_connected', False):
            check('cluster_connected', False, 'The cluster is not connected')
            return done()
        if busy:
            holder = busy_with(cid, rec['id'])
            check('busy', holder is None, f'Another QDevice job runs: {holder}' if holder
                  else 'No other QDevice job runs on this cluster or QNetd host')

        entries = _cluster_status(mgr)
        if entries is None:
            check('cluster_status', False, 'The cluster status cannot be read')
            return done()
        nodes = sorted((e for e in entries if isinstance(e, dict) and e.get('type') == 'node'
                        and isinstance(e.get('name'), str)), key=lambda e: e['name'])
        cl = next((e for e in entries if isinstance(e, dict) and e.get('type') == 'cluster'), None)
        count = len(nodes)
        report['node_count'] = count
        own.nodes = [n['name'] for n in nodes]
        check('node_count_even', count >= 2 and count % 2 == 0,
              f'{count} nodes' + ('' if count >= 2 and count % 2 == 0 else
                                  ': a QDevice is supported for an even number of nodes only'))
        offline = [n['name'] for n in nodes if not n.get('online')]
        check('nodes_online', not offline,
              'All nodes are online' if not offline else f"Offline: {', '.join(offline)}")
        check('quorate', bool(cl and cl.get('quorate')),
              'The cluster is quorate' if cl and cl.get('quorate') else 'The cluster is not quorate')

        address = clean_address(rec.get('address'))
        node_addrs = {bare_host(str(n.get('ip') or '')).lower() for n in nodes} | \
                     {str(n['name']).lower() for n in nodes}
        check('not_a_node', bool(address) and address.lower() not in node_addrs,
              'The QNetd host is no node of this cluster' if address and address.lower() not in node_addrs
              else 'The QNetd address is a node of this cluster: its vote would fall with that node')

        # the QNetd side: version, status, uuid and CA in one session
        q = own.qnetd
        product_uuid, qnetd_clusters, qnetd_certs, helper_ok, info = None, None, None, False, None
        try:
            with transport_for(rec).session() as call:
                try:
                    info = _version_info(_ok(call('version'), 'version'))
                except HelperError as e:
                    if plan and kind == 'ssh' and e.code == 'no_helper':
                        q['helper'] = 'install'
                        raise _Deferred()
                    raise
                if info['outdated']:
                    if plan and kind == 'ssh':
                        q['helper'] = 'update'
                        raise _Deferred()
                    raise HelperError('the helper on the QNetd host is outdated'
                                      + (': re-run packaging/qnetd/install.sh' if kind == 'local' else
                                         ': run Check on the QNetd host'))
                if not info['qnetd_installed'] or not info['certutil_installed']:
                    if not plan or kind == 'sidecar':
                        raise HelperError('corosync-qnetd is not installed: run Check on the QNetd host')
                    pm = info['package_manager']
                    if pm is None:
                        raise HelperError('corosync-qnetd or the NSS tools are missing on the QNetd host, and '
                                          'it has no package manager PegaProx knows (apt, dnf, yum, zypper): '
                                          'install them there by hand')
                    q['packages'] = {'package_manager': pm, 'packages': info['packages'] or list(QNETD_PACKAGES[pm])}
                    # the helper requires TLS on a corosync-qnetd it installs itself, only
                    q['tls'] = not info['qnetd_installed']
                st = _ok(call('status'), 'status')
                if not st.get('active'):
                    if not plan or kind == 'sidecar':
                        raise HelperError('corosync-qnetd is not running: run Check on the QNetd host')
                    q['start'] = True
                qnetd_clusters = _clean_clusters(st.get('clusters'))
                qnetd_certs = _cert_names(st.get('certificates'))
                try:
                    _raw, fp = _ca_fingerprint(_ok(call('ca'), 'ca'))
                    _pin_ca(rec, fp, learn=False)
                except HelperError as e:
                    if not (plan and kind != 'sidecar' and e.code == 'not_initialised'):
                        raise
                    q['ca'] = True
                try:
                    u = str(_ok(call('uuid'), 'uuid').get('product_uuid') or '').strip().lower()
                    product_uuid = u if UUID_RE.match(u) else ''
                except HelperError:
                    product_uuid = ''
            helper_ok = True
            todo = q['packages'] or q['ca'] or q['start']
            check('qnetd_ready', True, f"The QNetd host answers (helper protocol {info['protocol']})"
                  + ('; the setup sets up corosync-qnetd there first' if todo else ' and corosync-qnetd runs'))
        except _Deferred:
            own.deferred = True
            problem = _install_problem(rec)
            if problem:
                check('qnetd_ready', False, problem)
            else:
                check('qnetd_ready', True, ('The QNetd host has no PegaProx helper yet' if q['helper'] == 'install'
                                            else 'The helper on the QNetd host is outdated')
                      + ': the setup puts the one of this PegaProx there first, then sets up corosync-qnetd')
        except HelperError as e:
            check('qnetd_ready', False, str(e))

        # every online node: packages, an old certificate store, the QNetd port and the
        # address the node sends from towards it
        online = [n['name'] for n in nodes if n.get('online')]
        shells, errors = _open_shells(mgr, online) if online else ({}, {})
        own.shells = shells
        rows = {n['name']: {'node': n['name'], 'online': bool(n.get('online')), 'ssh': n['name'] in shells,
                            'packages': None, 'old_store': None, 'port_open': None, 'source_address': None,
                            'error': errors.get(n['name'])} for n in nodes}
        check('node_access', not errors and len(shells) == count,
              'PegaProx can run commands on every node' if not errors and len(shells) == count
              else '; '.join(sorted(errors.values()))[:600] or 'Not every node can be reached')

        probes = _per_node(shells, lambda s: s.run(probe_script(address or '', rec['port']), timeout=30), 30) \
            if address else {}
        node_uuids = {}
        for n, res in probes.items():
            if res is None or res[0] != 0:
                rows[n]['error'] = rows[n]['error'] or f"probe failed: {_short(res[2] if res else 'no answer')}"
                continue
            kv = _kv(res[1])
            u = (kv.get('uuid') or '').strip().lower()
            if UUID_RE.match(u):
                node_uuids[n] = u
            rows[n].update(packages=kv.get('pkg') == '1' and kv.get('certutil') == '1',
                           old_store=kv.get('store') == '1', port_open=kv.get('port') == '1',
                           source_address=clean_source(kv.get('src')))
        own.sources = {n: r['source_address'] for n, r in rows.items()}
        missing = [n for n, r in rows.items() if r['packages'] is False]
        unknown = [n for n, r in rows.items() if r['packages'] is None]
        own.missing_pkg = missing
        # a node without a way to its package sources is named here, before anything
        # changes, not after the packages step waited APT_TIMEOUT on it
        cut = {}
        if missing and install_packages and not unknown:
            got = _per_node({n: shells[n] for n in missing},
                            lambda s: s.run(SOURCES_SCRIPT, timeout=SOURCES_TIMEOUT), SOURCES_TIMEOUT)
            for n, res in got.items():
                kv = _kv(res[1]) if res is not None and res[0] == 0 else {}
                if kv.get('src') == 'none':
                    cut[n] = _short(kv.get('why') or 'no package source answers', 120)
        if unknown:
            check('packages', False, f"Not known on: {', '.join(unknown)}")
        elif missing and install_packages and cut:
            check('packages', False, ('apt cannot reach the package sources of '
                                      + '; '.join(f'{n} ({w})' for n, w in sorted(cut.items()))
                                      + ' - install corosync-qdevice there by hand, or give the node '
                                        'DNS and a route to its mirror')[:600])
        elif missing and install_packages:
            check('packages', True, f"corosync-qdevice will be installed on: {', '.join(missing)}")
        else:
            check('packages', not missing, 'corosync-qdevice is installed on every node' if not missing
                  else f"corosync-qdevice is missing on: {', '.join(missing)} (or install it with the setup)")
        own.stores = [n for n, r in rows.items() if r['old_store']]
        if own.stores:
            check('old_store', True, f"An unused QDevice certificate store is replaced on: "
                                     f"{', '.join(own.stores)}", blocking=False)
        report['nodes'] = [rows[n['name']] for n in nodes]

        # corosync.conf and the guests, both through one node
        first = next((n for n in sorted(shells)), None)
        own.first = first
        name = None
        if first is None:
            check('corosync_conf', False, 'No node to read corosync.conf through')
        else:
            rc, out, err = shells[first].run(conf_read_script(), timeout=30)
            kv = _kv(out) if rc == 0 else {}
            if rc != 0 or 'device' not in kv:
                check('corosync_conf', False, f'corosync.conf cannot be read: {_short(err, 200)}')
            else:
                name = clean_cluster_name(kv.get('name'))
                report['cluster_name'] = name or kv.get('name')
                check('cluster_name', bool(name), f'Cluster name {name}' if name else
                      'The cluster name is not one PVE allows (letters, digits, -, at most 15)')
                check('no_qdevice', kv.get('device') == '0',
                      'No QDevice is configured yet' if kv.get('device') == '0'
                      else 'The cluster has a QDevice already: remove it first')
                two = kv.get('two_node', '0') not in ('', '0')
                check('two_node', not two, 'two_node is not set' if not two
                      else 'corosync.conf sets two_node, which a QDevice does not go together with')
        own.name = name

        # the firewall of the QNetd host: its rules are kept per cluster name
        if plan and name and helper_ok and kind != 'sidecar':
            if not info['firewall_op']:
                own.firewall_error = 'the helper on the QNetd host has no firewall operation'
            else:
                try:
                    own.firewall = _fw_view(_ok(transport_for(rec).call(
                        'firewall', name=name, data={'action': 'inspect'}), 'firewall'), rec['port'])
                except HelperError as e:
                    own.firewall_error = str(e)
        fw = own.firewall
        if plan and open_firewall:
            sources = sorted({s for s in own.sources.values() if s})
            nosrc = [n for n in own.nodes if not own.sources.get(n)]
            if kind == 'sidecar':
                check('firewall', False, 'Docker publishes the port of the QNetd container itself: open it on '
                                         'the Docker host, PegaProx does not')
            elif own.deferred:
                own.firewall_open = True
            elif fw is None:
                check('firewall', False, own.firewall_error or 'The firewall of the QNetd host cannot be read')
            elif fw['backend'] == 'none' or fw['blocking'] is False:
                check('firewall', True, 'No firewall of the QNetd host blocks the port: nothing to open')
            elif not fw['managed']:
                manual = (expand_manual(fw['manual'], sources) if sources else fw['manual']) or \
                    manual_rules(fw['backend'], fw['port'], sources)
                check('firewall', False, f"PegaProx does not change {fw['backend'] or 'this firewall'} on the "
                                         f"QNetd host: open TCP port {fw['port']} for the nodes by hand"
                      + (f': {manual}' if manual else ''))
            else:
                own.firewall_open = True
            if own.firewall_open and nosrc:
                own.firewall_open = False
                check('firewall', False, f"Which address {', '.join(nosrc)} send from towards the QNetd host "
                                         "cannot be told: open the port by hand")
            elif own.firewall_open:
                check('firewall', True, f"The setup opens TCP port {fw['port'] if fw else rec['port']} on the "
                                        f"QNetd host for {', '.join(sources)}")

        closed = [n for n, r in rows.items() if r['port_open'] is not True]
        if not closed:
            check('qnetd_port', True, f"Every node reaches {address}:{rec['port']}")
        elif plan and (own.deferred or q['start']):
            check('qnetd_port', None, f"Not reachable yet from: {', '.join(closed)} (port {rec['port']}): "
                                      "checked again once corosync-qnetd runs", deferred=True)
        elif plan and own.firewall_open:
            check('qnetd_port', None, f"Not reachable yet from: {', '.join(closed)} (port {rec['port']}): the "
                                      "setup opens the port, then checks again", deferred=True)
        else:
            hint = ''
            if plan and fw and fw['managed'] and not open_firewall:
                hint = f": PegaProx can open it in the firewall of the QNetd host ({fw['backend']})"
            check('qnetd_port', False, f"Not reachable from: {', '.join(closed)} (port {rec['port']}){hint}")

        if name:
            # without regard to case, as qnetd matches a certificate to its cluster name: a
            # certificate for pve is one for PVE as well
            low = name.lower()
            attached = get_db().list_qnetd_attachments(qnetd_id=rec['id'])
            clash = [a for a in attached
                     if str(a['cluster_name'] or '').lower() == low and a['cluster_id'] != cid]
            listed = qnetd_clusters is not None and any(c['name'].lower() == low for c in qnetd_clusters)
            mine = any(a['cluster_id'] == cid for a in attached)
            if clash:
                check('name_unique', False, f'Another cluster named {name} votes through this QNetd host')
            elif listed and not mine:
                check('name_unique', False, f'A cluster named {name} is connected to this QNetd host already')
            elif qnetd_clusters is None and own.deferred:
                check('name_unique', None, 'Which clusters the QNetd host serves is read once the helper is '
                                           'there', deferred=True)
            elif qnetd_clusters is None:
                check('name_unique', None if not helper_ok else False,
                      'The clusters of the QNetd host cannot be read')
            else:
                check('name_unique', True, f'No other cluster named {name} uses this QNetd host')

            # a certificate an earlier setup left there for this name (the helper keeps it
            # when a QDevice goes): sign refuses another key for it without replace, half
            # way through the run. One of a cluster that is connected, or of another
            # cluster of PegaProx, is name_unique's to refuse
            held = None if qnetd_certs is None or qnetd_clusters is None else \
                any(c.lower() == low for c in qnetd_certs)
            if held is False and len(qnetd_certs) >= CERTS_MAX:
                held = None                 # the list may have stopped before this name
            own.cert_on_file = held
            if clash or listed or held is False:
                pass
            elif held is None:
                found = f'one of an earlier setup for {name} is found when the setup signs'
                check('cert_on_file', None,
                      f'Whether the QNetd host holds a certificate for a cluster named {name} from an earlier setup '
                      'is read once the helper is there' if own.deferred
                      else f'The helper on the QNetd host does not list the certificates it holds: {found}'
                      if qnetd_clusters is not None else f'The certificates of the QNetd host cannot be read: {found}',
                      deferred=True)
            elif replace_certificate:
                check('cert_on_file', True, f'The setup replaces the certificate the QNetd host holds for a cluster '
                                            f'named {name} from an earlier setup')
            else:
                check('cert_on_file', False, f'The QNetd host holds a certificate for a cluster named {name} from an '
                                             'earlier setup. Replacing it is only right when that cluster is this one, '
                                             'set up again, or one that is gone')

        if product_uuid is None and own.deferred:
            check('not_own_vm', None, 'Whether the QNetd host is a guest of this cluster is checked once the '
                                      'helper is there', deferred=True)
        elif product_uuid is None:
            check('not_own_vm', False, 'Not checked: the QNetd host did not answer')
        elif not product_uuid:
            check('not_own_vm', None, 'The QNetd host has no readable SMBIOS UUID: PegaProx cannot tell '
                                      'whether it is a guest of this cluster. Confirm that it is not')
        elif any(u == product_uuid for u in node_uuids.values()):
            # the node itself under another address, or a container on it: no VM config
            # holds that UUID, the grep below would find nothing
            same = sorted(n for n, u in node_uuids.items() if u == product_uuid)
            check('not_own_vm', False, f"The QNetd host has the SMBIOS UUID of node {', '.join(same)}: it is "
                                       "that node or runs in a container on it, and its vote would fall with it")
        elif first is None:
            check('not_own_vm', None, 'No node to look through the guest configs')
        else:
            own.product_uuid = product_uuid
            rc, out, err = shells[first].run(own_vm_script(product_uuid), timeout=60, limit=64 * 1024)
            hits = [ln for ln in out.splitlines() if ln.strip()]
            if hits:
                m = re.search(r'/qemu-server/([0-9]{1,9})\.conf$', hits[0])
                check('not_own_vm', False, 'The QNetd host is a guest of this cluster'
                      + (f' (VM {m.group(1)})' if m else '') + ': its vote would fall with that node')
            elif rc == 1:
                check('not_own_vm', True, 'The QNetd host is no guest of this cluster')
            else:
                check('not_own_vm', None, 'The guest configs could not be searched')
        return done()
    finally:
        if ctx is None:
            _close(own.shells)


# ---------------------------------------------------------------------------
# the plan an admin agrees to
# ---------------------------------------------------------------------------

def plan_opts(opts):
    """The four options of a setup, as booleans."""
    opts = opts if isinstance(opts, dict) else {}
    return {k: opts.get(k) is True for k in ('install_packages', 'open_firewall', 'replace_certificate',
                                             'confirm_unverified_host')}


def _qnetd_view(rec):
    """The QNetd host as a plan names it: as the nodes dial it, and for an ssh host the
    machine PegaProx logs in to (the helper, the packages and the firewall rules go there;
    what SshTransport connects to)."""
    view = {'id': rec.get('id'), 'kind': rec.get('kind'), 'address': rec.get('address'),
            'port': clean_port(rec.get('port'), None)}
    if rec.get('kind') == 'ssh':
        view['ssh'] = {'host': bare_host(str(rec.get('ssh_host') or rec.get('address') or '')),
                       'port': clean_port(rec.get('ssh_port'), 22), 'user': rec.get('ssh_user') or 'root'}
    return view


def plan_basis(cid, name, nodes, missing_pkg, rec, opts, sources, stores=()):
    """What a plan rests on: the cluster and its nodes, the QNetd host, the options, and
    what follows from them on the nodes (the ones that get corosync-qdevice, the unused
    certificate stores that go, the addresses the port opens for). The job holds the
    preflight it makes after the QNetd host step to the basis of the plan agreed to."""
    o = plan_opts(opts)
    body = {'cluster_id': cid, 'cluster_name': name, 'nodes': sorted(nodes), 'qnetd': _qnetd_view(rec),
            'install_packages': o['install_packages'], 'open_firewall': o['open_firewall'],
            'replace_certificate': o['replace_certificate'],
            'confirm_unverified_host': o['confirm_unverified_host'], 'stores': sorted(stores)}
    if o['install_packages']:
        body['missing_pkg'] = sorted(missing_pkg)
    if o['open_firewall']:
        body['sources'] = sorted(set(sources))
    return body


def plan_digest(basis, items=(), warnings=()):
    """sha256 hex of what the admin agrees to, in one canonical JSON form: the basis, every
    item of the plan as it acts (id, where, node, params; the text is only how it reads)
    and the warnings shown with it (but PLAN_UNAGREED_WARNINGS). When any of it differs at
    the run, the admin agreed to another plan."""
    body = dict(basis)
    body['items'] = [{k: i.get(k) for k in ('id', 'where', 'node', 'params')} for i in items]
    body['warnings'] = sorted({w.get('id') for w in warnings if w.get('id') not in PLAN_UNAGREED_WARNINGS})
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def ha_members():
    """How many PegaProx instances the HA group has as this one knows it; 1 without one."""
    try:
        from pegaprox.core import ha
        return 1 + len(ha.members() or [])
    except Exception:
        return 1


def _ha_resource_count(mgr):
    """The PVE HA resources of the cluster that are not disabled or ignored. 0 where they
    cannot be read: the warning is left out then, nothing depends on it."""
    try:
        data = mgr.get_proxmox_ha_resources()
    except Exception:
        return 0
    if not isinstance(data, list):
        return 0
    return sum(1 for r in data if isinstance(r, dict) and r.get('state') not in ('disabled', 'ignored'))


def _plan_items(report, ctx, rec, o, sources):
    items = []

    def item(id_, where, text, **params):
        items.append({'id': id_, 'where': where, 'node': None, 'params': params, 'text': text})

    q = ctx.qnetd
    if q['helper'] == 'install':
        item('qnetd_helper_install', 'qnetd', f'Install the PegaProx helper on the QNetd host ({HELPER_PATH}, '
                                              'owned by root)', path=HELPER_PATH)
    elif q['helper'] == 'update':
        item('qnetd_helper_update', 'qnetd', 'Replace the outdated PegaProx helper on the QNetd host with the '
                                             f'one of this PegaProx ({HELPER_PATH})', path=HELPER_PATH)
    if ctx.deferred:
        # what init does then, the helper tells once it is there: each only where needed
        item('qnetd_packages', 'qnetd', 'Install corosync-qnetd and the NSS tools with the package manager of '
                                        'the QNetd host where they are missing',
             package_manager=None, packages=None, if_needed=True)
        item('qnetd_ca', 'qnetd', 'Create the QNetd certificate authority where there is none '
                                  '(/etc/corosync/qnetd/nssdb)', if_needed=True)
        item('qnetd_tls', 'qnetd', 'Require TLS from the nodes (-s req) on a corosync-qnetd this setup '
                                   'installs, and restart it', if_needed=True)
        item('qnetd_start', 'qnetd', 'Enable and start corosync-qnetd where it does not run', if_needed=True)
    else:
        if q['packages']:
            pm, pk = q['packages']['package_manager'], q['packages']['packages']
            item('qnetd_packages', 'qnetd', f"Install {' and '.join(pk)} with {pm} on the QNetd host",
                 package_manager=pm, packages=list(pk))
        if q['ca']:
            item('qnetd_ca', 'qnetd', 'Create the QNetd certificate authority (/etc/corosync/qnetd/nssdb)')
        if q['tls']:
            item('qnetd_tls', 'qnetd', 'Require TLS from the nodes (-s req in the options of corosync-qnetd) '
                                       'and restart it')
        if q['start']:
            item('qnetd_start', 'qnetd', 'Enable and start corosync-qnetd')
    if ctx.firewall_open:
        fw = ctx.firewall or {}
        port = fw.get('port') or rec['port']
        backend = fw.get('backend')
        item('firewall_open', 'qnetd', f"Open TCP port {port} in the firewall of the QNetd host "
                                       f"({backend or 'ufw or firewalld, whichever is active'}) for "
                                       f"{', '.join(sources)}, and nothing else",
             backend=backend, port=port, sources=list(sources))
    # only where there is one to replace, or nobody can tell yet: the sign step replaces a
    # certificate only for a plan that lists this item
    if o['replace_certificate'] and ctx.name and ctx.cert_on_file is not False:
        item('cert_replace', 'qnetd', f'Replace the certificate the QNetd host holds for a cluster named '
                                      f'{ctx.name}', cluster_name=ctx.name)
    nodes = list(ctx.nodes)
    if o['install_packages'] and ctx.missing_pkg:
        item('node_packages', 'node', f"Install corosync-qdevice with apt-get on {', '.join(ctx.missing_pkg)}",
             nodes=sorted(ctx.missing_pkg))
    if ctx.stores:
        # not in the item list of the contract: the run removes these, so the admin sees it
        item('node_store_reset', 'node', f"Remove the unused QDevice certificate store ({NODE_STORE}) on "
                                         f"{', '.join(ctx.stores)}", nodes=sorted(ctx.stores))
    if nodes:
        item('node_certs', 'node', f"Import the QNetd CA and the certificate of cluster {ctx.name} on "
                                   f"{', '.join(nodes)} ({NODE_STORE})", nodes=nodes)
    address, port = clean_address(rec.get('address')), rec['port']
    item('corosync_conf', 'cluster', 'Add the quorum.device section to corosync.conf: model net, TLS on, '
                                     f'algorithm ffsplit, one vote, host {address}'
                                     + (f', port {port}' if port != DEFAULT_PORT else ''),
         address=address, port=port)
    if nodes:
        item('qdevice_service', 'node', f"Enable and start corosync-qdevice on {', '.join(nodes)}", nodes=nodes)
    item('corosync_reload', 'cluster', 'Reload the corosync configuration (corosync-cfgtool -R)')
    count = report.get('node_count') or 0
    if count:
        item('votes', 'cluster', f'The cluster has {count + 1} votes instead of {count}: one more from the QDevice',
             before=count, after=count + 1)
    return items


def _plan_firewall(ctx, rec, o, sources):
    fw = ctx.firewall
    if fw is None and not o['open_firewall']:
        return None
    fw = fw or {'backend': None, 'managed': None, 'blocking': None, 'port': rec['port'], 'manual': ''}
    manual = ''
    if fw['backend'] not in (None, 'none') and not fw['managed']:
        manual = (expand_manual(fw['manual'], sources) if sources else fw['manual']) or \
            manual_rules(fw['backend'], fw['port'], sources)
    return {'requested': o['open_firewall'], 'backend': fw['backend'], 'managed': fw['managed'],
            'blocking': fw['blocking'], 'port': fw['port'], 'sources': list(sources), 'manual': manual}


def _plan_warnings(mgr, report, ctx, rec, firewall):
    out = []

    def warn(id_, text, **params):
        out.append({'id': id_, 'params': params, 'text': text})

    members = ha_members()
    if rec.get('kind') in ('local', 'sidecar') and members > 1:
        warn('ha_group_local', f"PegaProx runs as a group of {members} instances: a {rec['kind']} QNetd host is the "
                               'machine of the one that acts now, and after a switchover the nodes reach no QNetd '
                               'there. Use a Linux host over SSH outside the group, the witness host for example',
             kind=rec['kind'], members=members)
    if report.get('needs_confirmation'):
        warn('unverified_host', 'PegaProx cannot tell whether the QNetd host is a guest of this cluster. If it is '
                                'one, its vote falls with the node it runs on')
    if firewall and firewall['manual'] and firewall['blocking'] is not False:
        warn('firewall_manual', f"PegaProx does not change the firewall of the QNetd host ({firewall['backend']}): "
                                f"open TCP port {firewall['port']} for the nodes by hand",
             backend=firewall['backend'], manual=firewall['manual'])
    n = _ha_resource_count(mgr) if report.get('node_count') else 0
    if n:
        warn('ha_resources', f'{n} guest(s) of this cluster are Proxmox HA resources. The setup does not touch '
                             'them: it adds the QDevice vote to corosync and nothing else', count=n)
    return out


def plan(cid, mgr, rec, opts, busy=True):
    """What a QDevice setup of cluster `cid` against QNetd host `rec` with `opts` would
    change, read only: nothing is installed, initialised, opened or written anywhere (see
    inspect plan=True). The setup is started with the digest of the plan the admin saw
    and agreed to; the job reads the plan again before it acts and stops at plan_changed
    when the digest differs.

      {ok, preflight, plan: {digest, items}, firewall, warnings}

    ok: nothing blocks that the run does not set up itself."""
    return _plan(cid, mgr, rec, opts, busy)[0]


def _plan(cid, mgr, rec, opts, busy=True):
    """(plan, its basis)."""
    o = plan_opts(opts)
    ctx = _Ctx()
    try:
        report = inspect(cid, mgr, rec, install_packages=o['install_packages'],
                         confirm_unverified=o['confirm_unverified_host'], busy=busy, ctx=ctx, plan=True,
                         open_firewall=o['open_firewall'], replace_certificate=o['replace_certificate'])
    finally:
        _close(ctx.shells)
        ctx.shells = {}
    sources = sorted({s for s in ctx.sources.values() if s})
    firewall = _plan_firewall(ctx, rec, o, sources)
    basis = plan_basis(cid, ctx.name, ctx.nodes, ctx.missing_pkg, rec, o, sources, ctx.stores)
    items = _plan_items(report, ctx, rec, o, sources)
    warnings = _plan_warnings(mgr, report, ctx, rec, firewall)
    return {'ok': bool(report['ok']), 'preflight': report,
            'plan': {'digest': plan_digest(basis, items, warnings), 'items': items},
            'firewall': firewall, 'warnings': warnings}, basis


# ---------------------------------------------------------------------------
# jobs
# ---------------------------------------------------------------------------

_jobs = {}
_claims = {'qnetd': {}, 'cluster': {}}
_lock = threading.Lock()


class Busy(Exception):
    pass


class Job:
    def __init__(self, kind, qnetd_id, cluster_ids, user, ip):
        self.id = uuid.uuid4().hex[:16]
        self.kind = kind                      # setup | remove | bulk
        self.qnetd_id = qnetd_id
        self.cluster_ids = list(cluster_ids)
        self.user, self.ip = user, ip
        self.state = 'running'                # running | done | failed | partial
        self.error = ''
        self.created, self.finished = time.time(), None
        self.steps = []
        self.clusters = {c: {'state': 'waiting', 'cluster_name': None, 'failed_step': None,
                             'error': '', 'code': None, 'rolled_back': None, 'preflight': None}
                         for c in cluster_ids}

    def log(self, cid, step, state, message=''):
        with _lock:
            if len(self.steps) < LOG_MAX:
                self.steps.append({'at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                                   'cluster_id': cid, 'step': step, 'state': state,
                                   'message': _short(message, 500)})

    def view(self):
        with _lock:
            return {'id': self.id, 'kind': self.kind, 'qnetd_id': self.qnetd_id,
                    'cluster_ids': list(self.cluster_ids), 'user': self.user, 'state': self.state,
                    'error': self.error,
                    'created_at': datetime.fromtimestamp(self.created, timezone.utc).isoformat(timespec='seconds'),
                    'finished_at': datetime.fromtimestamp(self.finished, timezone.utc).isoformat(
                        timespec='seconds') if self.finished else None,
                    'clusters': {c: dict(v) for c, v in self.clusters.items()},
                    'steps': [dict(s) for s in self.steps]}


def busy_with(cid=None, qnetd_id=None):
    """The job holding this cluster or QNetd host, as a short text, or None."""
    with _lock:
        jid = (_claims['cluster'].get(cid) if cid else None) or \
              (_claims['qnetd'].get(qnetd_id) if qnetd_id else None)
        job = _jobs.get(jid) if jid else None
        return f'{job.kind} job {job.id}' if job else None


def _prune_locked(now):
    over = sorted((j for j in _jobs.values() if j.state != 'running'), key=lambda j: j.finished or j.created)
    for j in over[:max(0, len(over) - KEEP_FINISHED)]:
        _jobs.pop(j.id, None)
    for j in list(_jobs.values()):
        if j.state != 'running' and now - (j.finished or j.created) > KEEP_SECONDS:
            _jobs.pop(j.id, None)


def register(job):
    """Take the job in and claim its QNetd host (setup and bulk) and its clusters. Busy
    when another job holds one of them."""
    with _lock:
        _prune_locked(time.time())
        if job.qnetd_id and job.kind != 'remove' and job.qnetd_id in _claims['qnetd']:
            raise Busy('Another QDevice job runs against this QNetd host')
        taken = [c for c in job.cluster_ids if c in _claims['cluster']]
        if taken:
            raise Busy(f"Another QDevice job runs on cluster {taken[0]}")
        if job.qnetd_id and job.kind != 'remove':
            _claims['qnetd'][job.qnetd_id] = job.id
        for c in job.cluster_ids:
            _claims['cluster'][c] = job.id
        _jobs[job.id] = job
    return job


def _release(job):
    with _lock:
        if _claims['qnetd'].get(job.qnetd_id) == job.id:
            _claims['qnetd'].pop(job.qnetd_id, None)
        for c in job.cluster_ids:
            if _claims['cluster'].get(c) == job.id:
                _claims['cluster'].pop(c, None)


def get_job(job_id):
    with _lock:
        return _jobs.get(job_id) if isinstance(job_id, str) else None


def jobs():
    with _lock:
        _prune_locked(time.time())
        return sorted(_jobs.values(), key=lambda j: j.created, reverse=True)


def launch(job, fn, *args):
    from pegaprox.core import ha

    def run():
        try:
            fn(job, *args)
        except Exception as e:
            log.error(f"[qnetd] job {job.id} broke off: {type(e).__name__}: {e}", exc_info=True)
            with _lock:
                job.state, job.error = 'failed', 'The job broke off - see the PegaProx log'
        finally:
            with _lock:
                if job.state == 'running':
                    job.state = 'done'
                job.finished = time.time()
            _release(job)
    threading.Thread(target=ha.as_job(run, f'qdevice {job.kind} {job.id}'), daemon=True,
                     name=f'qdevice-{job.kind}-{job.id}').start()


class _StepFailed(Exception):
    def __init__(self, step, message):
        super().__init__(message)
        self.step, self.message = step, message


def _all_ok(job, cid, step, results, nodes, what):
    """Raise _StepFailed unless every node answered rc 0."""
    bad = []
    for n in nodes:
        r = results.get(n)
        if r is None:
            bad.append(f'{n}: no answer in time')
        elif r[0] != 0:
            bad.append(f'{n}: {_short(r[2] or r[1], 200) or f"exit {r[0]}"}')
    if bad:
        raise _StepFailed(step, f"{what} failed on " + '; '.join(bad))
    job.log(cid, step, 'ok', f"{what}: {len(nodes)} node(s)")


def _rollback(job, cid, ctx, wrote_conf, address):
    """Like `pvecm qdevice remove`: the device entry out if this setup wrote it, the
    QDevice state off every node, the daemon stopped. Returns True when all went."""
    ok = True
    first = ctx.shells.get(ctx.first) if ctx.first else None
    if wrote_conf and first is not None:
        rc, out, err = first.run(conf_del_script(address), timeout=60)
        if rc != 0:
            ok = False
            job.log(cid, 'rollback', 'failed', f'corosync.conf: {_short(err, 200)}')
        elif 'absent' in (out or '').split():
            # the write that got no answer had not gone through: nothing to reload either
            wrote_conf = False
            job.log(cid, 'rollback', 'ok', 'corosync.conf has no QDevice entry')
        else:
            job.log(cid, 'rollback', 'ok', 'QDevice entry taken out of corosync.conf')
    res = _per_node(ctx.shells, lambda s: s.run(CLEANUP_SCRIPT, timeout=60))
    left = [n for n in ctx.shells if res.get(n) is None]
    # a node that answered but could not take its QDevice state away still has it
    broke = sorted(n for n in ctx.shells if res.get(n) is not None and res[n][0] != 0)
    if left or broke:
        ok = False
        why = ([f"no answer from {', '.join(left)}"] if left else []) + \
            [f'{n}: {_short(res[n][2], 120) or "rc " + str(res[n][0])}' for n in broke]
        job.log(cid, 'rollback', 'failed', '; '.join(why)[:600])
    else:
        job.log(cid, 'rollback', 'ok', 'QDevice state removed from every node, daemon stopped')
    if wrote_conf and first is not None:
        rc, _o, err = first.run(RELOAD_SCRIPT, timeout=60)
        if rc != 0:
            ok = False
            job.log(cid, 'rollback', 'failed', f'corosync-cfgtool -R: {_short(err, 200)}')
    return ok


def _port_closed(mgr, rec, nodes):
    """The nodes that do not reach the QNetd port right now (tried on each of them)."""
    address = clean_address(rec.get('address'))
    shells, errors = _open_shells(mgr, nodes)
    try:
        res = _per_node(shells, lambda s: s.run(probe_script(address or '', rec['port']), timeout=30), 30) \
            if address else {}
    finally:
        _close(shells)
    return sorted(n for n in nodes if n in errors or res.get(n) is None or res[n][0] != 0
                  or _kv(res[n][1]).get('port') != '1')


def _qnetd_host_step(job, cid, rec, shared):
    """check_host with init and upgrade: once per job, after the first cluster whose plan
    the admin agreed to; a later cluster of a bulk run takes over what it gave."""
    if shared.get('host') is None:
        job.log(cid, 'qnetd_host', 'running', 'Setting up the QNetd host')
        res = check_host(rec, init=True, upgrade=True)
        shared['host'] = True if res.get('ok') else (res.get('error') or 'the QNetd host is not ready')
        if shared['host'] is True:
            job.log(cid, 'qnetd_host', 'ok', 'QNetd host ready' + (', helper installed' if res.get('helper_installed')
                                                                   else ''))
    elif shared['host'] is True:
        job.log(cid, 'qnetd_host', 'ok', 'The QNetd host was set up earlier in this run')
    if shared['host'] is not True:
        raise _StepFailed('qnetd_host', f"The QNetd host could not be set up: {shared['host']}")


def _open_firewall(job, cid, mgr, rec, p, name, fw):
    """Open the QNetd port for the nodes' addresses, then every node has to reach it. What
    the helper added goes into fw['added'] at once, for a rollback."""
    sources = list((p.get('firewall') or {}).get('sources') or [])
    job.log(cid, 'firewall', 'running', f"Opening the QNetd port for {', '.join(sources)}")
    with transport_for(rec).session() as call:
        # what the helper holds for this name already is not this job's to take away
        held = _fw_view(_ok(call('firewall', name=name, data={'action': 'inspect'}), 'firewall'),
                        rec['port'])['rules']
        try:
            ans = _ok(call('firewall', name=name, data={'action': 'allow', 'sources': sources}), 'firewall')
        except Exception as e:
            # an allow can break off part-way (ufw took one address and refused the next,
            # the time ran out, the answer never came): what went in is written down on the
            # QNetd host, so the rollback asks for every address it did not hold before
            if not (isinstance(e, HelperError) and e.code in FW_REFUSED_BEFORE):
                fw['added'] = [s for s in sources if s not in held]
            raise
    # only what we asked for: a rollback never takes away a rule of another address
    fw['added'] = [s for s in _fw_list(ans.get('added')) if s in sources]
    view = _fw_view(ans, rec['port'])
    job.log(cid, 'firewall', 'ok', f"{view['backend'] or 'firewall'}: port {view['port']} opened for "
            + (', '.join(fw['added']) if fw['added'] else 'nobody new, every address was allowed already'))
    closed = _port_closed(mgr, rec, [n['node'] for n in p['preflight'].get('nodes') or []])
    if closed:
        raise _StepFailed('firewall', f"Port {rec['port']} of the QNetd host is still not reachable from: "
                                      f"{', '.join(closed)}")
    job.log(cid, 'firewall', 'ok', f"Every node reaches {rec['address']}:{rec['port']}")


def _close_firewall(job, cid, rec, name, sources, step):
    """Take out the rules of `sources` (all of the cluster's when None). Never raises; True
    when the helper did it."""
    data = {'action': 'remove'}
    if sources is not None:
        data['sources'] = list(sources)
    try:
        ans = _ok(transport_for(rec).call('firewall', name=name, data=data), 'firewall')
    except HelperError as e:
        job.log(cid, step, 'failed' if step == 'rollback' else 'warning',
                f'The firewall rules for {name} on the QNetd host stay: {e}')
        return False
    except Exception as e:
        job.log(cid, step, 'failed' if step == 'rollback' else 'warning',
                f'The firewall rules for {name} on the QNetd host stay ({type(e).__name__})')
        return False
    removed = _fw_list(ans.get('removed'))
    if removed or step == 'rollback':
        job.log(cid, step, 'ok', f"Firewall rules for {name} taken out on the QNetd host: "
                + (', '.join(removed) or 'none were left'))
    return True


def _held_name(report):
    """Whether a report fails at a certificate an earlier setup left on the QNetd host for
    the cluster's name: the code of the replace the UI offers (as for sign's refusal)."""
    return any(c.get('id') == 'cert_on_file' and c.get('ok') is False for c in report.get('checks') or [])


def _plan_step(job, cid, mgr, rec, opts):
    """The plan of `cid`, read again and held to the digest the admin agreed to: nothing
    changes anywhere before it matched. (plan, basis); raises _StepFailed."""
    from pegaprox.utils.audit import log_audit
    from pegaprox.core import ha
    agreed = (opts.get('consents') or {}).get(cid)
    o = plan_opts(opts)                    # what the digest covers, and nothing looser
    row = job.clusters[cid]
    if not ha.is_active():
        raise _StepFailed('plan', 'This instance no longer acts on the clusters (standby)')
    if not isinstance(agreed, str) or not DIGEST_RE.match(agreed):
        with _lock:
            row['code'] = 'consent_required'
        raise _StepFailed('plan', 'Nobody agreed to the plan of this cluster')
    job.log(cid, 'plan', 'running', 'Reading the plan again')
    p, basis = _plan(cid, mgr, rec, o, busy=False)
    with _lock:
        row['preflight'] = p['preflight']
        row['cluster_name'] = p['preflight'].get('cluster_name')
    if not hmac.compare_digest(p['plan']['digest'], agreed):
        with _lock:
            row['code'] = 'plan_changed'
        raise _StepFailed('plan', PLAN_CHANGED)
    ids = [i['id'] for i in p['plan']['items']]
    log_audit(job.user, 'qdevice.consent', f"{job.user} agreed to the QDevice plan {agreed} with QNetd host "
                                           f"{rec['name']}: {', '.join(ids)}",
              ip_address=job.ip, cluster=getattr(getattr(mgr, 'config', None), 'name', None) or cid,
              cluster_id=cid)
    if not p['ok']:
        if _held_name(p['preflight']):
            with _lock:
                row['code'] = 'name_exists'
        raise _StepFailed('plan', '; '.join(_blocking(p['preflight'], o['confirm_unverified_host']))[:600]
                          or 'The plan has a check that does not pass')
    job.log(cid, 'plan', 'ok', f'The plan you agreed to holds ({len(ids)} changes)')
    return p, basis


def _agree_plan(job, cid, mgr, rec, opts):
    """The plan step of one cluster of a bulk run, before the run changes anything:
    (plan, basis), or None when the cluster failed there."""
    row = job.clusters[cid]
    try:
        return _plan_step(job, cid, mgr, rec, opts)
    except (_StepFailed, HelperError, ValueError) as e:
        if isinstance(e, HelperError) and e.code:
            with _lock:
                row['code'] = e.code
        _failed(job, cid, mgr, rec, _Ctx(), row, 'plan', e.message if isinstance(e, _StepFailed) else str(e),
                False, False)
    except Exception as e:
        log.error(f"[qnetd] plan of {cid} broke off: {type(e).__name__}: {e}", exc_info=True)
        _failed(job, cid, mgr, rec, _Ctx(), row, 'plan', f'{type(e).__name__} - see the PegaProx log', False, False)
    return None


def _setup_one(job, cid, mgr, rec, opts, shared=None, agreed=None):
    """The plan the admin agreed to, read again (or `agreed`, the (plan, basis) of a plan
    step a bulk run made before it changed anything); then the QNetd host, its firewall,
    the preflight and the steps of `pvecm qdevice setup` 4-10 with PegaProx relaying the
    files. Returns True when the cluster has its QDevice."""
    from pegaprox.core.db import get_db
    from pegaprox.core import qdevice
    from pegaprox.utils.audit import log_audit
    from pegaprox.core import ha
    shared = {} if shared is None else shared
    raw, opts = opts, plan_opts(opts)
    row = job.clusters[cid]
    ctx = _Ctx()
    changed = wrote_conf = False
    fw = {'name': None, 'added': []}
    step = 'plan'
    try:
        if agreed is None:
            agreed = _plan_step(job, cid, mgr, rec, raw)
        elif not ha.is_active():
            raise _StepFailed('plan', 'This instance no longer acts on the clusters (standby)')
        elif _qnetd_view(rec) != agreed[1]['qnetd']:
            # the QNetd host record is not the one this plan was held to
            with _lock:
                row['code'] = 'plan_changed'
            raise _StepFailed('plan', PLAN_CHANGED)
        p, basis = agreed
        ids = [i['id'] for i in p['plan']['items']]
        fw['name'] = clean_cluster_name(p['preflight'].get('cluster_name'))
        # a certificate of an earlier setup goes only where the plan agreed to says so: the
        # option alone, with nothing on file when the plan was read, replaces nothing
        replace = bool(opts.get('replace_certificate')) and 'cert_replace' in ids

        if any(i.startswith('qnetd_') for i in ids):
            step = 'qnetd_host'
            _qnetd_host_step(job, cid, rec, shared)
        if 'firewall_open' in ids:
            step = 'firewall'
            _open_firewall(job, cid, mgr, rec, p, fw['name'], fw)

        step = 'preflight'
        job.log(cid, step, 'running', 'Checking the cluster and the QNetd host')
        report = inspect(cid, mgr, rec, install_packages=opts.get('install_packages'),
                         confirm_unverified=opts.get('confirm_unverified_host'), busy=False, ctx=ctx,
                         replace_certificate=replace)
        with _lock:
            row['preflight'] = report
            row['cluster_name'] = report.get('cluster_name')
        if not report['ok']:
            if _held_name(report):
                # found only now that the helper there lists its certificates: before any node
                with _lock:
                    row['code'] = 'name_exists'
            failed = _blocking(report, opts.get('confirm_unverified_host'))
            raise _StepFailed('preflight', '; '.join(failed)[:600] or 'The preflight did not pass')
        # the QNetd host step may have taken minutes (in a bulk run, the clusters before this
        # one too): what the setup now acts on (the nodes, the ones that get corosync-qdevice,
        # the stores that go, their addresses) is still what was agreed to. The QNetd items
        # of the plan are done by now, the basis covers all the rest
        now = plan_basis(cid, ctx.name, ctx.nodes, ctx.missing_pkg, rec, opts,
                         [a for a in ctx.sources.values() if a], ctx.stores)
        if now != basis:
            with _lock:
                row['code'] = 'plan_changed'
            raise _StepFailed('preflight', PLAN_CHANGED)
        job.log(cid, step, 'ok', 'Every check passed')
        name, first, shells = ctx.name, ctx.first, ctx.shells
        address, port = clean_address(rec['address']), rec['port']

        if ctx.missing_pkg:
            step = 'packages'
            job.log(cid, step, 'running', f"Installing corosync-qdevice on {', '.join(ctx.missing_pkg)}")
            res = _per_node({n: shells[n] for n in ctx.missing_pkg},
                            lambda s: s.run(APT_SCRIPT, timeout=APT_TIMEOUT, limit=64 * 1024), APT_TIMEOUT)
            _all_ok(job, cid, step, res, ctx.missing_pkg, 'apt-get install corosync-qdevice')

        step = 'qnetd_init'
        tr = transport_for(rec)
        with tr.session() as call:
            ans = _ok(call('init'), 'init')
            if not ans.get('active'):
                raise _StepFailed(step, 'corosync-qnetd does not run on the QNetd host')
            job.log(cid, step, 'ok', 'QNetd initialised and running')
            step = 'qnetd_ca'
            ca, fp = _ca_fingerprint(_ok(call('ca'), 'ca'))
            _pin_ca(rec, fp, learn=True)
            job.log(cid, step, 'ok', f'CA certificate fetched (sha256 {fp[:16]})')

        nodes = sorted(shells)
        changed = True                      # from here on a failure is rolled back
        if ctx.stores:
            step = 'node_store_reset'
            res = _per_node({n: shells[n] for n in ctx.stores}, lambda s: s.run(STORE_RESET_SCRIPT, timeout=30))
            _all_ok(job, cid, step, res, ctx.stores, 'Removing the unused certificate store')

        step = 'node_ca'
        ca_in = base64.b64encode(ca) + b'\n'
        res = _per_node(shells, lambda s: s.run(ca_import_script(), data=ca_in))
        _all_ok(job, cid, step, res, nodes, 'CA certificate imported')

        step = 'node_crq'
        rc, out, err = shells[first].run(crq_script(name), limit=4 * FILE_MAX)
        if rc != 0:
            raise _StepFailed(step, f'{first}: {_short(err, 300)}')
        crq = _b64_file(out.strip(), FILE_MAX)
        if not _looks_like_pem_or_der(crq, 'crq'):
            raise _StepFailed(step, f'{first}: the certificate request is not one')
        job.log(cid, step, 'ok', f'Certificate request made on {first}')

        step = 'qnetd_sign'
        with tr.session() as call:
            # never sign through a helper older than this protocol, also one swapped in
            # since the preflight
            if _version_info(_ok(call('version'), 'version'))['outdated']:
                raise _StepFailed(step, 'the helper on the QNetd host is outdated')
            # an older certificate for this name (the cluster set up before, with another
            # key) is only replaced when the plan agreed to says so; the helper refuses it
            # for a name that is connected whatever is asked
            ans = _ok(call('sign', name=name, data={'crq_b64': base64.b64encode(crq).decode(),
                                                    'replace': replace}),
                      'sign')
        crt = _b64_file(ans.get('crt_b64'), FILE_MAX)
        if not _looks_like_pem_or_der(crt, 'crt'):
            raise _StepFailed(step, 'the QNetd host answered with no certificate')
        job.log(cid, step, 'ok', f'Cluster certificate for {name} signed')

        step = 'node_crt'
        rc, out, err = shells[first].run(crt_import_script(name), data=base64.b64encode(crt) + b'\n',
                                         limit=4 * P12_MAX)
        if rc != 0:
            raise _StepFailed(step, f'{first}: {_short(err, 300)}')
        p12 = _b64_file(out.strip(), P12_MAX)          # the cluster key: memory only, never logged
        out = None
        job.log(cid, step, 'ok', f'Signed certificate imported on {first}')

        step = 'node_p12'
        p12_in = base64.b64encode(p12) + b'\n'
        try:
            res = _per_node(shells, lambda s: s.run(p12_import_script(), data=p12_in))
        finally:
            p12 = p12_in = None
        _all_ok(job, cid, step, res, nodes, 'Cluster certificate and key imported')

        step = 'corosync_conf'
        rc, _o, err = shells[first].run(conf_add_script(address, port), timeout=60)
        if rc != 0:
            # no answer (a timeout, a dropped login) does not mean nothing was written: the
            # rollback looks and takes out an entry naming this host. Only the perl's own
            # refusal of a device that was there already leaves corosync.conf alone
            wrote_conf = 'already configured' not in (err or '')
            raise _StepFailed(step, _short(err, 300) or f'exit {rc}')
        wrote_conf = True
        job.log(cid, step, 'ok', f'quorum.device written (net, tls on, ffsplit, host {address})')

        step = 'qdevice_start'
        res = _per_node(shells, lambda s: s.run(START_SCRIPT, timeout=60))
        _all_ok(job, cid, step, res, nodes, 'corosync-qdevice started and enabled')

        step = 'corosync_reload'
        rc, _o, err = shells[first].run(RELOAD_SCRIPT, timeout=60)
        if rc != 0:
            raise _StepFailed(step, _short(err, 300) or f'exit {rc}')
        job.log(cid, step, 'ok', 'corosync configuration reloaded')

        get_db().save_qnetd_attachment(cid, rec['id'], name, job.user)
        qdevice._views.pop(cid, None)
        _forget_status(rec['id'])
        with _lock:
            row.update(state='done')
        log_audit(job.user, 'qdevice.setup', f"QDevice set up for cluster {name} with QNetd host "
                                             f"{rec['name']} ({address}:{port})",
                  ip_address=job.ip, cluster=getattr(getattr(mgr, 'config', None), 'name', None) or cid,
                  cluster_id=cid)
        return True
    except (_StepFailed, HelperError, ValueError) as e:
        failed_step = e.step if isinstance(e, _StepFailed) else step
        message = e.message if isinstance(e, _StepFailed) else str(e)
        if isinstance(e, HelperError) and e.code:
            with _lock:
                row['code'] = e.code
        return _failed(job, cid, mgr, rec, ctx, row, failed_step, message, changed, wrote_conf, fw)
    except Exception as e:
        log.error(f"[qnetd] setup of {cid} broke off at {step}: {type(e).__name__}: {e}", exc_info=True)
        return _failed(job, cid, mgr, rec, ctx, row, step, f'{type(e).__name__} - see the PegaProx log',
                       changed, wrote_conf, fw)
    finally:
        _close(ctx.shells)


def _failed(job, cid, mgr, rec, ctx, row, step, message, changed, wrote_conf, fw=None):
    from pegaprox.utils.audit import log_audit
    job.log(cid, step, 'failed', message)
    rolled = None
    if changed:
        job.log(cid, 'rollback', 'running', 'Undoing the setup on the nodes')
        try:
            rolled = _rollback(job, cid, ctx, wrote_conf, rec['address'])
        except Exception as e:
            log.error(f"[qnetd] rollback of {cid} failed: {type(e).__name__}: {e}")
            job.log(cid, 'rollback', 'failed', type(e).__name__)
            rolled = False
    if fw and fw.get('added') and fw.get('name'):
        # exactly the rules this job added: one an admin had, or another job's, stays
        job.log(cid, 'rollback', 'running', 'Taking out the firewall rules this setup added')
        went = _close_firewall(job, cid, rec, fw['name'], fw['added'], 'rollback')
        rolled = went if rolled is None else (rolled and went)
    with _lock:
        row.update(state='failed', failed_step=step, error=_short(message, 600), rolled_back=rolled)
    try:
        from pegaprox.core import qdevice
        qdevice._views.pop(cid, None)
        log_audit(job.user, 'qdevice.setup_failed',
                  f"QDevice setup with QNetd host {rec['name']} failed at {step}"
                  + ('' if rolled is None else (', rolled back' if rolled else ', rollback incomplete')),
                  ip_address=job.ip, cluster=getattr(getattr(mgr, 'config', None), 'name', None) or cid,
                  cluster_id=cid)
    except Exception:
        pass
    return False


def run_setup(job, rec, opts):
    from pegaprox.globals import cluster_managers
    cid = job.cluster_ids[0]
    mgr = cluster_managers.get(cid)
    with _lock:
        job.clusters[cid]['state'] = 'running'
    if mgr is None:
        job.log(cid, 'plan', 'failed', 'The cluster is gone from PegaProx')
        with _lock:
            job.clusters[cid].update(state='failed', failed_step='plan', error='The cluster is gone')
            job.state = 'failed'
        return
    ok = _setup_one(job, cid, mgr, rec, opts)
    with _lock:
        job.state = 'done' if ok else 'failed'
        if not ok:
            job.error = job.clusters[cid]['error']


def run_bulk(job, rec, opts):
    """Every cluster after the other against one QNetd host; one that fails stops none of
    the rest. Every plan is held to its consent first, before the run changes anything:
    the QNetd host step is a change, and a plan read after it no longer lists the host
    work the admin agreed to for that cluster as well."""
    from pegaprox.globals import cluster_managers
    from pegaprox.core import ha
    from pegaprox.utils.audit import log_audit
    shared, held = {}, []

    def standby():
        if ha.is_active():
            return False
        with _lock:
            for c in job.cluster_ids:
                if job.clusters[c]['state'] == 'waiting':
                    job.clusters[c].update(state='skipped', error='This instance is a standby now')
        return True

    def cluster_and_host(cid):
        mgr = cluster_managers.get(cid)
        fresh = get_qnetd(rec['id']) if mgr is not None else None
        if mgr is not None and fresh is not None:
            return mgr, fresh
        why, error = (('The cluster is gone from PegaProx', 'The cluster is gone') if mgr is None
                      else ('The QNetd host was deleted', 'The QNetd host is gone'))
        job.log(cid, 'plan', 'failed', why)
        with _lock:
            job.clusters[cid].update(state='failed', failed_step='plan', error=error)
        return None

    for cid in job.cluster_ids:
        if standby():
            break
        got = cluster_and_host(cid)
        agreed = _agree_plan(job, cid, got[0], got[1], opts) if got else None
        if agreed is not None:
            held.append((cid, agreed))
    for cid, agreed in held:
        if standby():
            break
        got = cluster_and_host(cid)
        if got is None:
            continue
        with _lock:
            job.clusters[cid]['state'] = 'running'
        # the QNetd host is set up once, for the first cluster that gets this far
        _setup_one(job, cid, got[0], got[1], opts, shared, agreed)
    with _lock:
        states = [v['state'] for v in job.clusters.values()]
        job.state = 'done' if all(s == 'done' for s in states) else \
            ('failed' if not any(s == 'done' for s in states) else 'partial')
    done = sum(1 for s in states if s == 'done')
    try:
        log_audit(job.user, 'qdevice.bulk_setup',
                  f"QDevice bulk setup with QNetd host {rec['name']}: {done} of {len(states)} cluster(s) done",
                  ip_address=job.ip)
    except Exception:
        pass


def _drop_firewall(job, cid, att):
    """After a removal: the firewall rules the helper keeps for the cluster's name go too.
    Whatever goes wrong is a warning in the job log, the removal stands."""
    name = clean_cluster_name(att.get('cluster_name'))
    rec = get_qnetd(att.get('qnetd_id'))
    if rec is None or name is None or rec.get('kind') == 'sidecar':
        return
    try:
        with transport_for(rec).session() as call:
            info = _version_info(_ok(call('version'), 'version'))
        if info['outdated'] or not info['firewall_op']:
            job.log(cid, 'firewall', 'warning', f'The helper on the QNetd host is outdated: firewall rules for '
                                                f'{name} there, if any, stay')
            return
    except HelperError as e:
        job.log(cid, 'firewall', 'warning', f'The firewall rules for {name} on the QNetd host stay: {e}')
        return
    except Exception as e:
        job.log(cid, 'firewall', 'warning', f'The firewall rules for {name} on the QNetd host stay '
                                            f'({type(e).__name__})')
        return
    _close_firewall(job, cid, rec, name, None, 'firewall')


def run_remove(job):
    """`pvecm qdevice remove` on one node; it cleans every node itself. Then the
    attachment goes."""
    from pegaprox.globals import cluster_managers
    from pegaprox.core.db import get_db
    from pegaprox.core import qdevice
    from pegaprox.utils.audit import log_audit
    cid = job.cluster_ids[0]
    row = job.clusters[cid]
    mgr = cluster_managers.get(cid)
    with _lock:
        row['state'] = 'running'

    def fail(step, msg):
        job.log(cid, step, 'failed', msg)
        with _lock:
            row.update(state='failed', failed_step=step, error=_short(msg, 600))
            job.state, job.error = 'failed', _short(msg, 600)

    if mgr is None:
        return fail('remove', 'The cluster is gone from PegaProx')
    entries = _cluster_status(mgr)
    if entries is None:
        return fail('remove', 'The cluster status cannot be read')
    nodes = sorted(e['name'] for e in entries if isinstance(e, dict) and e.get('type') == 'node'
                   and e.get('online') and isinstance(e.get('name'), str))
    shell, errors = None, []
    for n in nodes:
        try:
            shell = _open_shell(mgr, n)
            break
        except NodeError as e:
            errors.append(str(e))
    if shell is None:
        return fail('remove', '; '.join(errors)[:600] or 'No node of the cluster is online')
    try:
        job.log(cid, 'remove', 'running', f'pvecm qdevice remove on {shell.node}')
        rc, out, err = shell.run(REMOVE_SCRIPT, timeout=PVECM_TIMEOUT, limit=64 * 1024)
    finally:
        shell.close()
    text = f'{out}\n{err}'
    absent = 'No QDevice configured' in text
    if rc != 0 and not absent:
        return fail('remove', _short(err or out, 400) or f'exit {rc}')
    job.log(cid, 'remove', 'ok', 'The cluster had no QDevice' if absent and rc != 0 else 'QDevice removed')
    att = get_db().list_qnetd_attachments(cluster_id=cid)
    get_db().delete_qnetd_attachment(cid)
    qdevice._views.pop(cid, None)
    for a in att:
        _forget_status(a['qnetd_id'])
        try:
            _drop_firewall(job, cid, a)
        except Exception as e:
            job.log(cid, 'firewall', 'warning', f'The firewall rules on the QNetd host stay ({type(e).__name__})')
    with _lock:
        row['state'] = 'done'
        job.state = 'done'
    log_audit(job.user, 'qdevice.removed', 'QDevice removed' + (
        f" (was on QNetd host {att[0]['qnetd_id']})" if att else ''), ip_address=job.ip,
        cluster=getattr(getattr(mgr, 'config', None), 'name', None) or cid, cluster_id=cid)


# ---------------------------------------------------------------------------
# hosts
# ---------------------------------------------------------------------------

def get_qnetd(host_id, secrets=True):
    from pegaprox.core.db import get_db
    if not isinstance(host_id, str) or not re.match(r'^[0-9a-f]{12}\Z', host_id):
        return None
    return get_db().get_qnetd_host(host_id, secrets=secrets)


def clean_host(data, old=None):
    """(fields, password, ssh_key, error) of a host as the API sends it. password and
    ssh_key are None where the request leaves them as they are."""
    if not isinstance(data, dict):
        return None, None, None, 'The request body must be a JSON object'
    old = old or {}
    f = {}
    name = data.get('name', old.get('name'))
    if not isinstance(name, str) or not DISPLAY_NAME_RE.match(name.strip()):
        return None, None, None, 'name: letters, digits, space, . _ -, at most 64'
    f['name'] = name.strip()
    kind = data.get('kind', old.get('kind'))
    if kind not in KINDS:
        return None, None, None, 'kind must be local, ssh or sidecar'
    f['kind'] = kind
    address = clean_address(data.get('address', old.get('address')))
    if not address:
        return None, None, None, 'address: the host name or IP address the cluster nodes reach the QNetd at'
    f['address'] = address
    port = clean_port(data.get('port', old.get('port')), DEFAULT_PORT)
    if port is None:
        return None, None, None, 'port must be 1 to 65535'
    f['port'] = port
    password = ssh_key = None
    if kind == 'ssh':
        ssh_host = clean_address(data.get('ssh_host', old.get('ssh_host')) or address)
        if not ssh_host:
            return None, None, None, 'ssh_host: a host name or IP address'
        ssh_port = clean_port(data.get('ssh_port', old.get('ssh_port')), 22)
        if ssh_port is None:
            return None, None, None, 'ssh_port must be 1 to 65535'
        user = data.get('ssh_user', old.get('ssh_user')) or 'root'
        if not isinstance(user, str) or not SSH_USER_RE.match(user):
            return None, None, None, 'ssh_user: a login name'
        f.update(ssh_host=ssh_host, ssh_port=ssh_port, ssh_user=user)
        if 'password' in data:
            password = data.get('password')
            if password is None:
                password = ''
            if not isinstance(password, str) or len(password) > 512 or '\x00' in password:
                return None, None, None, 'password: text up to 512 characters'
        if 'ssh_key' in data:
            ssh_key = data.get('ssh_key') or ''
            if not isinstance(ssh_key, str) or len(ssh_key) > 16384 or \
                    (ssh_key and 'PRIVATE KEY-----' not in ssh_key):
                return None, None, None, 'ssh_key: a private key in PEM or OpenSSH format'
            if ssh_key:
                from pegaprox.utils.concurrent import get_paramiko
                pk = get_paramiko()
                if pk is not None and _load_key(pk, ssh_key) is None:
                    return None, None, None, 'ssh_key: the key cannot be read (encrypted keys are not supported)'
        has_pw = bool(password) if password is not None else bool(old.get('has_password'))
        has_key = bool(ssh_key) if ssh_key is not None else bool(old.get('has_ssh_key'))
        if not has_pw and not has_key:
            return None, None, None, 'an ssh host needs a password or a private key'
    else:
        # nothing to log in with: whatever was stored goes
        f.update(ssh_host='', ssh_port=22, ssh_user='')
        password = ssh_key = ''
    return f, password, ssh_key, None


def public_host(rec, attachments=None, now=None):
    out = {k: rec.get(k) for k in ('id', 'name', 'kind', 'address', 'port', 'ssh_host', 'ssh_port',
                                   'ssh_user', 'has_password', 'has_ssh_key', 'ca_sha256',
                                   'created_by', 'created_at', 'updated_at')}
    out['attachments'] = [{k: a.get(k) for k in ('cluster_id', 'cluster_name', 'attached_at', 'attached_by')}
                          for a in (attachments or [])]
    st = public_status(cached_status(rec['id'], now=now), now=now)
    if st:
        st.pop('raw', None)            # the list stays small; the status route has it
    out['status'] = st
    return out


def reset_for_tests():
    with _lock:
        _jobs.clear()
        _claims['qnetd'].clear()
        _claims['cluster'].clear()
    _status.clear()
    _avail.clear()
    _refreshing.clear()
