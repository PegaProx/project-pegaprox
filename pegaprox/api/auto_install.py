# -*- coding: utf-8 -*-
"""
Automated installations - MK Sep 2026.

Answer-file server for the Proxmox VE auto-installer. The ISO is prepared with

    proxmox-auto-install-assistant prepare-iso pve.iso --fetch-from http \
        --url 'https://pegaprox.example.com/api/auto-install/answer' \
        --answer-auth-token 'pegaprox:<token>' [--cert-fingerprint '<sha256>']

At boot the installer POSTs its hardware inventory there and gets the answer file
back, and that POST is what the run list shows. An installer too old for
--answer-auth-token can carry the token in the URL instead (?token=...). That works,
but then it sits in every access log between the machine and us.

A profile is picked by its token, not by DMI matching. The file carries the root
password, and with matching an unauthenticated POST gets to choose which file it is
handed.

Every served file gets its own [post-installation-webhook], pointing back here with
a callback token that belongs to that one run. A finished machine can close its own
run and nothing else, and the fetch token never ends up on the installed host.
"""
import re
import json
import uuid
import hmac
import time
import hashlib
import secrets
import logging
import ipaddress
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from flask import Blueprint, jsonify, request, Response

from pegaprox.constants import SSL_CERT_FILE, SSL_DIR
from pegaprox.globals import cluster_managers
from pegaprox.core.db import get_db
from pegaprox.utils.auth import require_auth, build_authz_user
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.utils.ssh import check_auth_action_rate_limit
from pegaprox.utils.sha512_crypt import sha512_crypt
from pegaprox.api.helpers import safe_error, load_server_settings, effective_reverse_proxy

bp = Blueprint('auto_install', __name__)

# Hostname, IPv4 or bracketed IPv6, optional port. The value ends up inside a TOML
# string in the served file, so anything else is dropped rather than escaped.
_HOST_RE = re.compile(r'^(?:[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]{2,45}\])(?::\d{1,5})?$')
_CLUSTER_ID_RE = re.compile(r'^[A-Za-z0-9_.\-]{0,64}$')

_MAX_SYSTEM_INFO = 64 * 1024
_MAX_ANSWER = 256 * 1024
_RUNS_KEPT_PER_PROFILE = 1000

_STATUSES = ('installing', 'installed', 'failed')

# Values a view-only reader must never get back. The installer also takes the
# snake_case spellings, so those count too. A subscription key is not a login, but
# it is somebody's paid key.
_SECRET_KEYS = ('root-password', 'root_password', 'root-password-hashed',
                'root_password_hashed', 'subscription-key', 'subscription_key')

_UNREDACTABLE = ('# This answer file cannot be shown to your role: a secret in it is written\n'
                 '# in a form that cannot be blanked line by line. Ask someone who can edit it.\n')

# DMI serials that vendors ship as placeholders. Keying runs on one of these would
# fold every machine of that model into a single row.
_JUNK_SERIALS = {'', 'none', 'unknown', 'to be filled by o.e.m.', 'system serial number',
                 'default string', '0123456789', 'not specified', 'n/a'}
_JUNK_UUIDS = {'', '00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff',
               '03000200-0400-0500-0006-000700080009'}


def _utcnow():
    return datetime.now(timezone.utc)


def _stamp(dt=None):
    """ISO timestamp in UTC with the offset spelled out, so the browser reads it
    as UTC and so two stamps compare correctly as plain strings."""
    return (dt or _utcnow()).astimezone(timezone.utc).isoformat(timespec='seconds')


def _parse_stamp(value):
    """Aware UTC datetime or ValueError. A value without an offset is taken as UTC,
    which is what the UI sends (toISOString) and what we store."""
    dt = datetime.fromisoformat(str(value).strip().replace('Z', '+00:00'))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _hash_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _new_token():
    # url-safe, no characters that need quoting on the prepare-iso command line
    return 'pgxai_' + secrets.token_urlsafe(32)


def _present_token_hint(token):
    return token[:12]


def _s(value, limit):
    """str() only for things that already are strings. The installer sends nested
    objects under names that sound like plain fields (product is a dict), and a
    repr in the run list is worse than a blank."""
    return value.strip()[:limit] if isinstance(value, str) else ''


# --- answer file ------------------------------------------------------------

def _parse_toml(text):
    """(data, error). tomllib is stdlib from Python 3.11. On an older interpreter
    every check fails with this message and nothing gets saved or served."""
    try:
        import tomllib
    except ImportError:      # pragma: no cover
        return None, 'TOML parsing needs Python 3.11 or newer'
    try:
        return tomllib.loads(text), None
    except Exception as e:
        return None, str(e)


# What the installer knows. It refuses anything else in these places outright
# (deny_unknown_fields), so a typo in an optional key only shows up at the rack.
_KNOWN_SECTIONS = ('global', 'network', 'disk-setup', 'post-installation-webhook', 'first-boot')
_KNOWN_GLOBAL = ('keyboard', 'country', 'fqdn', 'mailto', 'timezone', 'root-password',
                 'root_password', 'root-password-hashed', 'reboot-on-error', 'reboot-mode',
                 'root-ssh-keys', 'subscription-key')

_WEBHOOK_HEADER = re.compile(r'^\s*\[\s*post-installation-webhook\s*\]\s*$')
_ANY_TABLE = re.compile(r'^\s*\[')

# The rules below are shared by validate_answer and build_answer, so a file the
# guided setup writes is judged exactly like one typed into the editor. They come
# from the installer's own types (proxmox-installer-types, proxmox-network-types).
# Every pattern is used with fullmatch: a bare '$' would let a trailing newline in.
_KEYBOARDS = ('de', 'de-ch', 'dk', 'en-gb', 'en-us', 'es', 'fi', 'fr', 'fr-be', 'fr-ca', 'fr-ch',
              'hu', 'is', 'it', 'jp', 'lt', 'mk', 'nl', 'no', 'pl', 'pt', 'pt-br', 'se', 'si', 'tr')
# least number of disks per raid level; raid10 also needs an even count
_RAID_MIN = {'zfs': {'raid0': 1, 'raid1': 2, 'raid10': 4, 'raidz-1': 3, 'raidz-2': 4, 'raidz-3': 5},
             'btrfs': {'raid0': 1, 'raid1': 2, 'raid10': 4}}
# the one options table each filesystem may carry
_FS_OPTIONS = {'ext4': 'lvm', 'xfs': 'lvm', 'zfs': 'zfs', 'btrfs': 'btrfs'}

# What `chpasswd --encrypted` on the new node can verify: sha512-crypt, sha256-crypt,
# yescrypt, bcrypt. The value lands in /etc/shadow unchecked, so anything else is a
# root account nobody can log in to. The alphabet also keeps ':' and newlines out,
# which would break the chpasswd line.
_CRYPT_RE = re.compile(r'\$6\$(?:rounds=[0-9]{1,9}\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}'
                       r'|\$5\$(?:rounds=[0-9]{1,9}\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}'
                       r'|\$y\$[./0-9A-Za-z]+\$[./0-9A-Za-z]{1,86}\$[./0-9A-Za-z]{43}'
                       r'|\$2[aby]\$[0-9]{2}\$[./0-9A-Za-z]{53}')
# the <input type="email"> pattern, which is what the installer checks against
_EMAIL_RE = re.compile(r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                       r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*")
_MAIL_PLACEHOLDER = 'mail@example.invalid'
_COUNTRY_RE = re.compile(r'[a-z]{2}')
_TZ_RE = re.compile(r'[A-Za-z][A-Za-z0-9_+\-]*(?:/[A-Za-z0-9_+\-]+){0,2}')
_LABEL_RE = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?')


def _unprintable(value):
    return any(ch < ' ' or ch == '\x7f' or '\ud800' <= ch <= '\udfff' for ch in value)


def _fqdn_problem(name, host=True):
    """Why the installer's Fqdn parser would refuse `name`, or None. host=False is
    for fqdn.domain, which only gets the DHCP host name put in front of it."""
    if len(name) > 253:
        return 'is longer than 253 characters'
    labels = name.split('.')
    if not all(_LABEL_RE.fullmatch(label) for label in labels):
        return ('may only use letters, digits and hyphens, in dot-separated parts '
                'that do not start or end with a hyphen')
    if host and len(labels) < 2:
        return 'must be fully qualified (host.domain.tld)'
    if host and labels[0].isdigit():
        return 'must not have an all-numeric host name'
    return None


def _keyboard_problem(value):
    return None if value in _KEYBOARDS else 'is not a keyboard layout the installer knows (de, en-us, fr-ch, ...)'


def _country_problem(value):
    if isinstance(value, str) and _COUNTRY_RE.fullmatch(value):
        return None
    return 'must be a two-letter country code in lower case (de, at, us, ...)'


def _timezone_problem(value):
    if not isinstance(value, str) or not _TZ_RE.fullmatch(value):
        return 'must be a time zone name such as Europe/Berlin'
    if value.startswith('Etc/'):
        # not in the installer's zone table; plain "UTC" is
        return 'must be a regional zone such as Europe/Berlin, or UTC - the installer refuses Etc/ zones'
    return None


def _mailto_problem(value):
    if not isinstance(value, str) or not _EMAIL_RE.fullmatch(value):
        return 'does not look like an e-mail address'
    if value == _MAIL_PLACEHOLDER:
        return "is the installer's placeholder address"
    return None


def _hashed_problem(value):
    if isinstance(value, str) and _CRYPT_RE.fullmatch(value):
        return None
    return 'is not a password hash - use the hash button above the editor, or mkpasswd -m sha-512'


def _raid_level(fs, value):
    """The level in lower case, or None. The installer takes raid1 and RAID1, not Raid1."""
    if not isinstance(value, str) or value not in (value.lower(), value.upper()):
        return None
    level = value.lower()
    return level if level in _RAID_MIN.get(fs, {}) else None


def _disk_list_problem(fs, level, disks):
    if len(set(disks)) != len(disks):
        return 'names the same disk twice'
    if fs in ('ext4', 'xfs') and len(disks) > 1:
        return f'can hold only one disk for {fs} - use zfs or btrfs for more'
    if level:
        need = _RAID_MIN[fs][level]
        if len(disks) < need:
            return f'needs at least {need} disks for {fs} {level}, got {len(disks)}'
        if level == 'raid10' and len(disks) % 2:
            return f'needs an even number of disks for {fs} raid10, got {len(disks)}'
    return None


def validate_answer(text):
    """(errors, warnings) for an answer file, checked the way the installer checks it.

    Errors are what the installer refuses. Warnings work but are usually a mistake,
    and unknown keys stay warnings on purpose: a newer ISO may know them.
    """
    errors, warnings = [], []
    if not isinstance(text, str) or not text.strip():
        return ['The answer file is empty'], []
    if len(text) > _MAX_ANSWER:
        return ['The answer file is too large (max 256 KB)'], []

    data, err = _parse_toml(text)
    if err:
        return [f'Not valid TOML: {err}'], []

    g = data.get('global')
    if not isinstance(g, dict):
        errors.append('Missing [global] section')
        g = {}
    for key, check in (('keyboard', _keyboard_problem), ('country', _country_problem),
                       ('mailto', _mailto_problem), ('timezone', _timezone_problem)):
        if not g.get(key):
            errors.append(f'[global] is missing "{key}"')
            continue
        problem = check(g[key])
        if problem:
            errors.append(f'[global] "{key}" {problem}')

    unknown = sorted(k for k in data if k not in _KNOWN_SECTIONS)
    if unknown:
        warnings.append('The installer rejects sections it does not know: ' + ', '.join(unknown))
    unknown = sorted(k for k in g if k not in _KNOWN_GLOBAL)
    if unknown:
        warnings.append('[global] has keys the installer may not know: ' + ', '.join(unknown))

    fqdn = g.get('fqdn')
    if isinstance(fqdn, dict):
        # fqdn.source = "from-dhcp", optionally with fqdn.domain as the fallback
        if fqdn.get('source') != 'from-dhcp':
            errors.append('[global] fqdn.source must be "from-dhcp"')
        domain = fqdn.get('domain')
        if domain:      # the installer reads '' as unset
            problem = _fqdn_problem(domain, host=False) if isinstance(domain, str) else 'must be text'
            if problem:
                errors.append(f'[global] fqdn.domain {problem}')
    elif isinstance(fqdn, str) and fqdn:
        problem = _fqdn_problem(fqdn)
        if problem:
            errors.append(f'[global] "fqdn" {problem}')
    else:
        errors.append('[global] is missing "fqdn" (a name, or fqdn.source = "from-dhcp")')

    plain = g.get('root-password') or g.get('root_password')
    hashed = g.get('root-password-hashed') or g.get('root_password_hashed')
    if not plain and not hashed:
        errors.append('[global] needs either "root-password" or "root-password-hashed"')
    elif plain and hashed:
        errors.append('[global] has both "root-password" and "root-password-hashed" - pick one')
    elif plain:
        # the installer counts bytes, not characters
        if not isinstance(plain, str) or len(plain.encode('utf-8', 'replace')) < 8:
            errors.append('[global] "root-password" must be at least 8 bytes long')
    else:
        problem = _hashed_problem(hashed)
        if problem:
            errors.append(f'[global] "root-password-hashed" {problem}')

    net = data.get('network')
    if not isinstance(net, dict):
        errors.append('Missing [network] section')
    else:
        source = net.get('source')
        if source not in ('from-dhcp', 'from-answer'):
            errors.append('[network] "source" must be "from-dhcp" or "from-answer"')
        elif source == 'from-answer':
            for key in ('cidr', 'dns', 'gateway', 'filter'):
                if not net.get(key):
                    errors.append(f'[network] source=from-answer also needs "{key}"')
        else:
            static = [k for k in ('cidr', 'dns', 'gateway', 'filter') if k in net]
            if static:
                errors.append('[network] source=from-dhcp takes no ' + ', '.join(static)
                              + ' - the installer refuses the file')

    disk = data.get('disk-setup')
    if not isinstance(disk, dict):
        errors.append('Missing [disk-setup] section')
    else:
        fs = disk.get('filesystem')
        known = fs if isinstance(fs, str) and fs in _FS_OPTIONS else None
        if not fs:
            errors.append('[disk-setup] is missing "filesystem"')
        elif not known:
            warnings.append(f'[disk-setup] filesystem "{fs}" is not one the installer normally offers')

        disks, flt = disk.get('disk-list'), disk.get('filter')
        if not disks and not flt:
            errors.append('[disk-setup] needs "disk-list" or "filter" so the installer knows where to write')
        elif disks and flt:
            errors.append('[disk-setup] has both "disk-list" and "filter" - the installer takes one')
        if disks and not (isinstance(disks, list) and all(isinstance(d, str) and d for d in disks)):
            errors.append('[disk-setup] "disk-list" must be a list of disk names')
            disks = None
        elif disks and any(_is_disk_path(d) for d in disks):
            errors.append('[disk-setup] "disk-list" takes raw disk names such as sda or nvme0n1, '
                          'not /dev/disk/by-* paths - use a filter to select by ID')

        level = None
        # zfs.raid = "raid1" is a dotted key, so it parses to {'zfs': {'raid': ...}}
        if known in _RAID_MIN:
            sub = disk.get(known)
            raid = sub.get('raid') if isinstance(sub, dict) else None
            if not raid:
                errors.append(f'[disk-setup] {known} needs {known}.raid ('
                              + ', '.join(_RAID_MIN[known]) + ') - the installer refuses the file without it')
            else:
                level = _raid_level(known, raid)
                if not level:
                    errors.append(f'[disk-setup] {known}.raid must be one of ' + ', '.join(_RAID_MIN[known]))
        if known:
            wrong = [t for t in ('lvm', 'zfs', 'btrfs') if t != _FS_OPTIONS[known] and t in disk]
            if wrong:
                errors.append('[disk-setup] ' + ', '.join(f'{t}.*' for t in wrong)
                              + f' options do not apply to {known}')
        if disks:
            problem = _disk_list_problem(known, level, disks)
            if problem:
                errors.append(f'[disk-setup] "disk-list" {problem}')

    if 'post-installation-webhook' in data:
        if any(_WEBHOOK_HEADER.match(line) for line in text.splitlines()):
            warnings.append('The [post-installation-webhook] section is replaced by PegaProx so it can track the install')
        else:
            # dotted or inline form: we can only replace the table form, and two
            # definitions of the same table are a parse error on the installer
            errors.append('Write post-installation-webhook as its own [post-installation-webhook] table, '
                          'or leave it out - PegaProx adds its own')

    if plain:
        warnings.append('This answer file stores the root password in clear text. '
                        '"root-password-hashed" is the better habit.')
    return errors, warnings


# --- guided setup: fields -> answer file -----------------------------------------

class ComposeRefused(Exception):
    """The fields are not in the shape the guided setup sends. A 400 rather than a
    field error; the message may name a key but never a value."""


# exactly what the wizard sends; everything else is refused
_COMPOSE_SHAPE = {
    'global': ('keyboard', 'country', 'timezone', 'mailto', 'fqdn', 'root_password_hashed', 'root_ssh_keys'),
    'network': ('source', 'cidr', 'gateway', 'dns', 'filter'),
    'disk': ('filesystem', 'raid', 'disk_list', 'filter'),
}
_FQDN_TABLE_KEYS = ('source', 'domain')
_NIC_FILTER_KEYS = ('ID_NET_NAME_MAC', 'ID_NET_NAME')
_DISK_FILTER_KEYS = ('ID_SERIAL', 'ID_SERIAL_SHORT', 'ID_WWN', 'ID_MODEL', 'DEVNAME')
# a clear password only ever goes to /password-hash
_PLAINTEXT_KEYS = ('root_password', 'root-password')

_MAX_FIELD = 255
_MAX_SSH_KEYS = 50
_SSH_KEY_RE = re.compile(r'(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com'
                         r'|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}(?: [^\x00-\x1f\x7f]*)?')
_MAC_GLOB_RE = re.compile(r'\*[0-9a-f]{12}')
_GLOB_RE = re.compile(r'[A-Za-z0-9_.:+\-/*?\[\]!]{1,128}')
_DISK_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:\-/]{0,63}')


def _is_disk_path(name):
    """/dev/disk/by-id/... and friends. disk-list takes the installer's raw disk
    names (sda, nvme0n1, cciss/c0d0), so a by-* path never matches anything and the
    install stops at the rack with no disk found."""
    n = name[5:] if name.startswith('/dev/') else name
    return n.startswith('disk/')
_IP_RE = re.compile(r'[0-9A-Fa-f.:]{2,45}')
_CIDR_RE = re.compile(r'[0-9A-Fa-f.:]{2,45}/[0-9]{1,3}')

_TOML_ESCAPES = {'\\': '\\\\', '"': '\\"', '\b': '\\b', '\t': '\\t', '\n': '\\n', '\f': '\\f', '\r': '\\r'}


def _toml_str(value):
    """A TOML basic string with everything escaped that the spec says must be.
    _toml_escape only does backslash and quote, which is enough for our own URL but
    not for text somebody typed."""
    out = []
    for ch in str(value):
        if ch in _TOML_ESCAPES:
            out.append(_TOML_ESCAPES[ch])
        elif ch < ' ' or ch == '\x7f':
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def _emit_toml(model):
    """Sections holding strings, lists of strings and one level of sub-tables, the
    latter as dotted keys the way the Proxmox wiki writes them."""
    def val(v):
        return _toml_str(v) if isinstance(v, str) else '[' + ', '.join(_toml_str(x) for x in v) + ']'

    lines = []
    for section, table in model.items():
        lines.append(f'[{section}]')
        for key, value in table.items():
            if isinstance(value, dict):
                lines.extend(f'{key}.{sub} = {val(v)}' for sub, v in value.items())
            else:
                lines.append(f'{key} = {val(value)}')
        lines.append('')
    return '\n'.join(lines)


def _has_plaintext_key(node):
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if any(k in _PLAINTEXT_KEYS for k in cur):
                return True
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return False


def _table(where, value, allowed):
    """The dict at `where`, or ComposeRefused. {} when it was left out."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ComposeRefused(f'{where} must be an object')
    unknown = sorted(str(k)[:64] for k in value if k not in allowed)
    if unknown:
        raise ComposeRefused(f'Unknown field in {where}: ' + ', '.join(unknown[:5]))
    return value


def _cidr_problem(value):
    try:
        if _CIDR_RE.fullmatch(value):
            ipaddress.ip_interface(value)
            return None
    except ValueError:
        pass
    return 'must be an address with its prefix length, e.g. 192.0.2.10/24'


def _ip_problem(value):
    try:
        if _IP_RE.fullmatch(value):
            ipaddress.ip_address(value)
            return None
    except ValueError:
        pass
    return 'must be a single IP address'


def build_answer(fields):
    """(text, field_errors) for the guided setup. Pure: nothing is stored or logged.

    Takes exactly the shape the wizard sends. Anything else, and any clear-text
    password key anywhere in it, raises ComposeRefused. A bad value comes back in
    field_errors under its dotted key ('disk.raid'), and then text is '' - nothing
    half-built gets shown. The file is written from a model and parsed back, and
    the two have to agree; if they ever do not, that is our bug and it raises.
    """
    if not isinstance(fields, dict):
        raise ComposeRefused('fields must be an object')
    if _has_plaintext_key(fields):
        raise ComposeRefused('Compose takes root_password_hashed only. Send the password to '
                             '/api/auto-install/password-hash first.')
    _table('fields', fields, tuple(_COMPOSE_SHAPE))
    g = _table('global', fields.get('global'), _COMPOSE_SHAPE['global'])
    net = _table('network', fields.get('network'), _COMPOSE_SHAPE['network'])
    disk = _table('disk', fields.get('disk'), _COMPOSE_SHAPE['disk'])
    # filter keys are checked even where the value ends up unused
    nic_filter = _table('network.filter', net.get('filter'), _NIC_FILTER_KEYS)
    disk_filter = _table('disk.filter', disk.get('filter'), _DISK_FILTER_KEYS)
    fqdn = g.get('fqdn')
    if isinstance(fqdn, dict):
        _table('global.fqdn', fqdn, _FQDN_TABLE_KEYS)

    errs = {}

    def need(key, value, check):
        """A required single-line string, or None with its field error set."""
        name = key.split('.', 1)[1].replace('_', '-')
        if value is None or value == '':
            errs[key] = f'"{name}" is required'
        elif not isinstance(value, str):
            errs[key] = f'"{name}" must be text'
        elif _unprintable(value):
            errs[key] = f'"{name}" must not contain control characters'
        elif len(value) > _MAX_FIELD:
            errs[key] = f'"{name}" is too long'
        else:
            problem = check(value)
            if not problem:
                return value
            errs[key] = f'"{name}" {problem}'
        return None

    def one_filter(key, filters, check_value, hint):
        """The single {property: glob} a filter may hold, or None."""
        if len(filters) != 1:
            errs[key] = 'Give exactly one property to match on'
            return None
        (prop, pattern), = filters.items()
        if not isinstance(pattern, str) or _unprintable(pattern) or not check_value(prop, pattern):
            errs[key] = hint
            return None
        return {prop: pattern}

    # [global]
    out_g = {}
    for key, check in (('keyboard', _keyboard_problem), ('country', _country_problem)):
        value = need(f'global.{key}', g.get(key), check)
        if value:
            out_g[key] = value
    if isinstance(fqdn, dict):
        if fqdn.get('source') != 'from-dhcp':
            errs['global.fqdn'] = 'fqdn.source must be "from-dhcp"'
        else:
            table = {'source': 'from-dhcp'}
            domain = fqdn.get('domain')
            if domain not in (None, ''):
                if not isinstance(domain, str) or _unprintable(domain):
                    errs['global.fqdn'] = 'The fallback domain must be plain text'
                else:
                    problem = _fqdn_problem(domain, host=False)
                    if problem:
                        errs['global.fqdn'] = f'The fallback domain {problem}'
                    else:
                        table['domain'] = domain
            out_g['fqdn'] = table
    else:
        value = need('global.fqdn', fqdn, _fqdn_problem)
        if value:
            out_g['fqdn'] = value
    for key, check in (('mailto', _mailto_problem), ('timezone', _timezone_problem)):
        value = need(f'global.{key}', g.get(key), check)
        if value:
            out_g[key] = value
    value = need('global.root_password_hashed', g.get('root_password_hashed'), _hashed_problem)
    if value:
        out_g['root-password-hashed'] = value

    ssh_keys = g.get('root_ssh_keys')
    if ssh_keys not in (None, []):
        if not isinstance(ssh_keys, list) or not all(isinstance(k, str) for k in ssh_keys):
            errs['global.root_ssh_keys'] = 'root-ssh-keys must be a list of public keys'
        else:
            ssh_keys = [k for k in ssh_keys if k]      # a blank line in the textarea is no key
            if len(ssh_keys) > _MAX_SSH_KEYS:
                errs['global.root_ssh_keys'] = f'At most {_MAX_SSH_KEYS} SSH keys'
            elif any(_unprintable(k) for k in ssh_keys):
                errs['global.root_ssh_keys'] = 'Each SSH key goes on one line, without control characters'
            elif not all(len(k) <= 16384 and _SSH_KEY_RE.fullmatch(k) for k in ssh_keys):
                errs['global.root_ssh_keys'] = 'Not an OpenSSH public key (ssh-ed25519 AAAA... comment)'
            elif ssh_keys:
                out_g['root-ssh-keys'] = ssh_keys

    # [network]
    out_net = {}
    source = net.get('source')
    if source == 'from-dhcp':
        # leftovers from the static form are dropped: the installer refuses them here
        out_net['source'] = 'from-dhcp'
    elif source == 'from-answer':
        out_net['source'] = 'from-answer'
        for key, check in (('cidr', _cidr_problem), ('dns', _ip_problem), ('gateway', _ip_problem)):
            value = need(f'network.{key}', net.get(key), check)
            if value:
                out_net[key] = value
        if not nic_filter:
            errs['network.filter'] = 'Pick the network port, by its MAC address or its interface name'
        else:
            by_mac = lambda prop, v: bool((_MAC_GLOB_RE if prop == 'ID_NET_NAME_MAC' else _GLOB_RE).fullmatch(v))
            picked = one_filter('network.filter', nic_filter, by_mac,
                                'Match the port by MAC (*e43d1afa379a, 12 lower-case hex digits) '
                                'or by name (letters, digits and * ? [ ])')
            if picked:
                out_net['filter'] = picked
    elif source in (None, ''):
        errs['network.source'] = '"source" is required'
    else:
        errs['network.source'] = '"source" must be "from-dhcp" or "from-answer"'

    # [disk-setup]
    out_disk = {}
    fs, level = disk.get('filesystem'), None
    if fs in (None, ''):
        errs['disk.filesystem'] = '"filesystem" is required'
    elif not (isinstance(fs, str) and fs in _FS_OPTIONS):
        errs['disk.filesystem'] = '"filesystem" must be ext4, xfs, zfs or btrfs'
        fs = None
    else:
        out_disk['filesystem'] = fs
        if fs in _RAID_MIN:
            # a raid left over from an earlier zfs pick means nothing for ext4/xfs
            raid = disk.get('raid')
            if raid in (None, ''):
                errs['disk.raid'] = f'{fs} needs a raid level'
            elif not (isinstance(raid, str) and raid in _RAID_MIN[fs]):
                errs['disk.raid'] = f'The raid level for {fs} is one of ' + ', '.join(_RAID_MIN[fs])
            else:
                level = raid
                out_disk[fs] = {'raid': raid}

    disks = disk.get('disk_list')
    if disks is not None and not isinstance(disks, list):
        raise ComposeRefused('disk.disk_list must be a list')
    if disks and disk_filter:
        errs['disk.disk_list'] = 'Pick the disks by name or with a filter, not both'
    elif disks:
        if (len(disks) > 64 or not all(isinstance(d, str) and _DISK_NAME_RE.fullmatch(d)
                                       and not _is_disk_path(d) for d in disks)):
            errs['disk.disk_list'] = 'Disks are named the way the kernel does, e.g. sda or nvme0n1, not /dev/disk/by-* paths'
        else:
            problem = _disk_list_problem(fs, level, disks)
            if problem:
                errs['disk.disk_list'] = f'The disk list {problem}'
            else:
                out_disk['disk-list'] = disks
    elif disk_filter:
        picked = one_filter('disk.filter', disk_filter, lambda prop, v: bool(_GLOB_RE.fullmatch(v)),
                            'The filter value may use letters, digits, _ . : + - / and the wildcards * ? [ ]')
        if picked:
            out_disk['filter'] = picked
    else:
        errs['disk.disk_list'] = 'Pick the disks, by name or with a filter'

    if errs:
        return '', errs

    model = {'global': out_g, 'network': out_net, 'disk-setup': out_disk}
    text = _emit_toml(model)
    parsed, err = _parse_toml(text)
    if err or parsed != model:
        raise RuntimeError('the composed answer file does not parse back to its fields')
    return text, {}


def _strip_webhook_section(text):
    """Drop a [post-installation-webhook] table so ours doesn't collide with it."""
    out, skipping = [], False
    for line in text.splitlines():
        if _WEBHOOK_HEADER.match(line):
            skipping = True
            continue
        if skipping:
            if _ANY_TABLE.match(line):
                skipping = False
            else:
                continue
        out.append(line)
    return '\n'.join(out)


def _toml_escape(value):
    return str(value).replace('\\', '\\\\').replace('"', '\\"')


def _with_token(url, token):
    """Add token= to a URL that may already carry a query of its own."""
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != 'token']
    query.append(('token', token))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def own_cert_fingerprint():
    """SHA-256 fingerprint of config/ssl/cert.pem in the colon-separated upper-hex
    form Proxmox prints, or ''."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        with open(SSL_CERT_FILE, 'rb') as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        return ':'.join(f'{b:02X}' for b in cert.fingerprint(hashes.SHA256()))
    except Exception as e:
        logging.debug(f"[autoinstall] could not fingerprint {SSL_CERT_FILE}: {e}")
        return ''


def self_signed_fingerprint():
    """Our fingerprint if the certificate is self-signed, else ''.

    Only a self-signed certificate needs pinning, and pinning one from a CA would
    break every ISO prepared before its next renewal."""
    try:
        from pegaprox.core.acme import get_cert_info
        info = get_cert_info(SSL_DIR) or {}
    except Exception:
        info = {}
    return own_cert_fingerprint() if info.get('is_self_signed') else ''


def _public_base():
    """(scheme, host, direct) for the address the installer should call back on.

    host is '' when nothing usable came in. direct is False when a proxy sits in
    front, in which case the certificate on the wire is not ours.
    """
    from pegaprox.utils.audit import _is_trusted_proxy
    settings = load_server_settings() or {}
    behind = effective_reverse_proxy(settings)
    trusted = bool(request.remote_addr and _is_trusted_proxy(request.remote_addr))

    scheme = request.scheme
    host = request.host or ''
    forwarded = False
    if trusted:
        # same rule as the webauthn host and the CSRF origin check: forwarded
        # headers count only when a proxy we trust set them
        fwd_host = (request.headers.get('X-Forwarded-Host') or '').split(',')[0].strip()
        fwd_proto = (request.headers.get('X-Forwarded-Proto') or '').split(',')[0].strip().lower()
        if fwd_host:
            host, forwarded = fwd_host, True
        if fwd_proto in ('http', 'https'):
            scheme, forwarded = fwd_proto, True

    domain = (settings.get('domain') or '').strip()
    if domain:
        if behind or forwarded:
            host = domain
        else:
            # keep the port the installer used to reach us
            port = host.rsplit(':', 1)[1] if ':' in host and not host.endswith(']') else ''
            host = f'{domain}:{port}' if port else domain

    if not _HOST_RE.match(host):
        logging.warning(f"[autoinstall] refusing to build a callback URL from host {host!r}")
        return '', '', False
    return scheme, host, not (behind or forwarded)


def callback_target(profile):
    """(url, fingerprint) for the webhook section. An explicit per-profile URL wins."""
    url = (profile.get('callback_url') or '').strip()
    fp = (profile.get('callback_fingerprint') or '').strip()
    if url:
        return url, fp
    scheme, host, direct = _public_base()
    if not host:
        return '', ''
    url = f'{scheme}://{host}/api/auto-install/progress'
    if not fp and scheme == 'https' and direct:
        fp = self_signed_fingerprint()
    return url, fp


def render_answer(profile, callback_token):
    """The stored answer plus our webhook section. Returns (text, error)."""
    answer = profile.get('answer') or ''
    if profile.get('answer_unreadable') or not answer.strip():
        return None, 'the stored answer file could not be read'
    body = _strip_webhook_section(answer).rstrip()
    url, fp = callback_target(profile)
    if url:
        lines = [body, '', '[post-installation-webhook]',
                 f'url = "{_toml_escape(_with_token(url, callback_token))}"']
        if fp:
            lines.append(f'cert-fingerprint = "{_toml_escape(fp)}"')
        body = '\n'.join(lines)
    body += '\n'
    # check what goes out, not what came in: a file the installer refuses leaves a
    # machine sitting at the installer prompt, and a 500 here is the better outcome
    errors, _warnings = validate_answer(body)
    if errors:
        return None, errors[0]
    return body, None


def _secret_values(node):
    found = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k in _SECRET_KEYS and isinstance(v, str) and v:
                found.append(v)
            else:
                found.extend(_secret_values(v))
    elif isinstance(node, list):
        for v in node:
            found.extend(_secret_values(v))
    return found


def _strings(node):
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for v in node.values() for s in _strings(v)]
    if isinstance(node, list):
        return [s for v in node for s in _strings(v)]
    return []


def redact_answer(text):
    """Blank secret values for a view-only reader, and fail closed.

    The line rewrite handles the usual `key = "value"`. TOML has four more ways to
    write the same key (quoted, dotted, inline table, multi-line string), so the
    result is checked against the parsed file, and if any secret survived the reader
    gets a placeholder instead of the text.
    """
    out = []
    for line in (text or '').splitlines():
        stripped = line.lstrip()
        key = stripped.split('=', 1)[0].strip() if '=' in stripped else ''
        if key in _SECRET_KEYS:
            out.append(f'{line[:len(line) - len(stripped)]}{key} = "********"')
        else:
            out.append(line)
    redacted = '\n'.join(out)
    data, err = _parse_toml(text or '')
    if err:
        return _UNREDACTABLE
    found = _secret_values(data)
    # as written: a secret copied into a comment is in no parsed value
    if any(value in redacted for value in found):
        return _UNREDACTABLE
    # NS Oct 2026 - and as decoded: a \u escape or a line-continued string reads back as the
    # secret without spelling it out, and half a rewritten multi-line string does not
    # parse at all (#1026)
    shown, err = _parse_toml(redacted)
    if err or any(value in s for s in _strings(shown) for value in found):
        return _UNREDACTABLE
    return redacted


# --- storage ----------------------------------------------------------------

_PROFILE_COLS = ('id', 'name', 'description', 'answer_encrypted', 'target_cluster_id',
                 'callback_url', 'callback_fingerprint', 'token_hash', 'token_hint',
                 'enabled', 'max_uses', 'uses', 'expires_at', 'created_at', 'created_by',
                 'updated_at', 'updated_by')


def _row_to_profile(row, with_answer=False):
    keys = row.keys()
    p = {k: (row[k] if k in keys else None) for k in _PROFILE_COLS}
    answer = ''
    unreadable = False
    if p.pop('answer_encrypted', None):
        try:
            answer = get_db()._decrypt(row['answer_encrypted']) or ''
        except Exception as e:
            logging.error(f"[autoinstall] could not decrypt answer for {p.get('id')}: {e}")
            unreadable = True
    p['enabled'] = bool(p.get('enabled'))
    p['max_uses'] = int(p.get('max_uses') or 0)
    p['uses'] = int(p.get('uses') or 0)
    p['answer_unreadable'] = unreadable
    if with_answer:
        p['answer'] = answer
    return p, answer


def _load_profile(profile_id):
    c = get_db().conn.cursor()
    c.execute('SELECT * FROM auto_install_profiles WHERE id = ?', (profile_id,))
    row = c.fetchone()
    if not row:
        return None, ''
    return _row_to_profile(row, with_answer=True)


def _profile_for_token(token):
    """Lookup by the token's hash; the plaintext is never stored."""
    if not isinstance(token, str) or not token:
        return None
    th = _hash_token(token)
    c = get_db().conn.cursor()
    c.execute('SELECT * FROM auto_install_profiles WHERE token_hash = ?', (th,))
    row = c.fetchone()
    if not row or not hmac.compare_digest(str(row['token_hash']), th):
        return None
    profile, _ = _row_to_profile(row, with_answer=True)
    return profile


def _run_for_callback_token(token):
    if not isinstance(token, str) or not token:
        return None
    th = _hash_token(token)
    c = get_db().conn.cursor()
    c.execute('SELECT * FROM auto_install_runs WHERE callback_token_hash = ?', (th,))
    row = c.fetchone()
    if not row or not hmac.compare_digest(str(row['callback_token_hash']), th):
        return None
    return {k: row[k] for k in row.keys()}


def _request_token():
    """Bearer header first, then ?token=.

    --answer-auth-token sends `Authorization: Bearer <name>:<secret>`. The name is
    free text for the operator and our tokens never contain a colon, so the secret
    is whatever follows the last one.
    """
    auth = request.headers.get('Authorization', '')
    if auth[:7].lower() == 'bearer ':
        return auth[7:].strip().rsplit(':', 1)[-1].strip()
    return (request.args.get('token') or '').strip()


def _profile_usable(profile):
    """(ok, reason). Fails closed on an expiry it cannot read."""
    if not profile.get('enabled'):
        return False, 'disabled'
    expires = profile.get('expires_at') or ''
    if expires:
        try:
            if _parse_stamp(expires) <= _utcnow():
                return False, 'expired'
        except (ValueError, TypeError):
            logging.warning(f"[autoinstall] profile {profile.get('id')} has an unreadable expiry {expires!r}")
            return False, 'unreadable expiry'
    max_uses = int(profile.get('max_uses') or 0)
    if max_uses and int(profile.get('uses') or 0) >= max_uses:
        return False, 'use limit reached'
    return True, ''


# --- admin API --------------------------------------------------------------

def _sees_every_cluster(user):
    """The scope rule behind both the route gate and the UI flag, kept in one place
    so the two cannot drift apart."""
    from pegaprox.utils.rbac import get_user_clusters
    return get_user_clusters(user, include_pools=False) is None


def _caller():
    session = getattr(request, 'session', None) or {}
    return build_authz_user(session.get('user', ''), session)


def _refuse_confined_caller():
    """403 unless the caller sees every cluster.

    Profiles belong to no tenant. One answer file can build a host for any cluster
    and it carries that host's root password, so a tenant-confined role holding
    autoinstall.* would otherwise read and rewrite every other tenant's files.
    """
    try:
        unconfined = _sees_every_cluster(_caller())
    except Exception as e:
        logging.warning(f"[autoinstall] could not resolve the caller's cluster scope: {e}")
        unconfined = False
    if not unconfined:
        return jsonify({'error': 'Automated installations are only available to accounts '
                                 'that are not limited to a tenant or to specific clusters'}), 403
    return None


def _may_manage():
    from pegaprox.utils.rbac import has_permission
    return has_permission(_caller(), 'autoinstall.manage')


def autoinstall_access(username, session):
    """'manage', 'view' or '' - whether the UI shows the page, and with which buttons.

    MK Sep 2026 - the permission list the browser holds cannot answer this: can()
    is true for every admin, but an admin capped in their own tenant is still turned
    away by the gate above. '' unless the account holds autoinstall.view (the list
    and run routes need it, manage alone does not reach them) and sees every
    cluster. Fails closed.
    """
    from pegaprox.utils.rbac import has_permission
    try:
        user = build_authz_user(username or '', session or {})
        if not has_permission(user, 'autoinstall.view'):
            return ''
        if not _sees_every_cluster(user):
            return ''
        return 'manage' if has_permission(user, 'autoinstall.manage') else 'view'
    except Exception as e:
        logging.warning(f"[autoinstall] could not resolve access for {username!r}: {e}")
        return ''


def _public_profile(profile, answer=None):
    out = dict(profile)
    out.pop('answer', None)
    out.pop('token_hash', None)
    cluster = cluster_managers.get(out.get('target_cluster_id') or '')
    label = getattr(getattr(cluster, 'config', None), 'name', '') if cluster else ''
    out['target_cluster_name'] = label if isinstance(label, str) else ''
    if answer is not None:
        out['answer'] = answer
    return out


def _with_targets(out, profile):
    url, fp = callback_target(profile)
    out['callback_effective_url'] = url
    out['callback_effective_fingerprint'] = fp
    # what prepare-iso needs to trust us; '' behind a proxy or with a CA certificate
    out['fetch_fingerprint'] = '' if effective_reverse_proxy() else self_signed_fingerprint()
    return out


@bp.route('/api/auto-install/profiles', methods=['GET'])
@require_auth(perms=['autoinstall.view'])
def list_profiles():
    """Profile metadata. The answer file is a separate read since it carries the
    root password. can_manage is resolved here with token flooring applied, which
    the permission list the browser holds does not do."""
    denied = _refuse_confined_caller()
    if denied:
        return denied
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT profile_id, status, COUNT(*) AS n FROM auto_install_runs '
                  'GROUP BY profile_id, status')
        counts = {}
        for r in c.fetchall():
            counts.setdefault(r['profile_id'], {})[r['status']] = r['n']
        c.execute('SELECT * FROM auto_install_profiles ORDER BY name COLLATE NOCASE')
        profiles = []
        for row in c.fetchall():
            p, _ = _row_to_profile(row)
            p['run_counts'] = counts.get(p['id'], {})
            profiles.append(_public_profile(p))
        return jsonify({'profiles': profiles, 'can_manage': _may_manage()})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not list installation profiles')}), 500


@bp.route('/api/auto-install/profiles/<profile_id>', methods=['GET'])
@require_auth(perms=['autoinstall.view'])
def get_profile(profile_id):
    """The answer comes back blanked unless the caller may also edit it."""
    denied = _refuse_confined_caller()
    if denied:
        return denied
    try:
        profile, answer = _load_profile(profile_id)
        if not profile:
            return jsonify({'error': 'Profile not found'}), 404
        may_edit = _may_manage()
        out = _public_profile(profile, answer if may_edit else redact_answer(answer))
        out['answer_redacted'] = not may_edit
        return jsonify(_with_targets(out, profile))
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not read the installation profile')}), 500


def _profile_payload(data, existing=None):
    """(fields, error), shared by create and update.

    On update a key the caller did not send keeps its stored value. Falling back to
    the create defaults instead would let a PUT with only a new name re-enable a
    revoked profile and lift its use limit and expiry.
    """
    def pick(key, default):
        if key in data:
            return data.get(key)
        if existing is not None:
            return existing.get(key, default)
        return default

    name = (pick('name', '') or '').strip()
    if not name:
        return None, 'A name is required'
    if len(name) > 120:
        return None, 'The name is too long (max 120 characters)'

    answer = pick('answer', None)
    if existing is not None and 'answer' not in data and existing.get('answer_unreadable'):
        return None, 'The stored answer file cannot be read - send a new one'
    if not isinstance(answer, str) or not answer.strip():
        return None, 'The answer file is required'
    errors, _warnings = validate_answer(answer)
    if errors:
        return None, errors[0] if len(errors) == 1 else 'The answer file has %d problems' % len(errors)

    target = (pick('target_cluster_id', '') or '').strip()
    # deliberately not checked against the live cluster list: the cluster a new node
    # is meant for is often not added yet
    if not _CLUSTER_ID_RE.match(target):
        return None, 'target_cluster_id is not a valid cluster id'

    callback_url = (pick('callback_url', '') or '').strip()
    if callback_url and not callback_url.startswith(('http://', 'https://')):
        return None, 'callback_url must be an http:// or https:// URL'
    if len(callback_url) > 500:
        return None, 'callback_url is too long'
    fp = (pick('callback_fingerprint', '') or '').strip().upper()
    if fp and not re.match(r'^[0-9A-F]{2}(:[0-9A-F]{2}){31}$', fp):
        return None, 'callback_fingerprint must be a SHA-256 fingerprint (32 colon-separated hex bytes)'

    # a string "false" is truthy, so a script revoking a profile that way left it live
    enabled = pick('enabled', True)
    if enabled not in (True, False, 0, 1):
        return None, 'enabled must be true or false'

    raw_uses = pick('max_uses', 0)
    if isinstance(raw_uses, bool):
        return None, 'max_uses must be a number'
    try:
        max_uses = int(raw_uses or 0)
    except (TypeError, ValueError):
        return None, 'max_uses must be a number'
    if max_uses < 0 or max_uses > 10000:
        return None, 'max_uses must be between 0 (unlimited) and 10000'

    expires_at = (pick('expires_at', '') or '').strip()
    if expires_at:
        try:
            expires_at = _stamp(_parse_stamp(expires_at))
        except (ValueError, TypeError):
            return None, 'expires_at must be an ISO timestamp'

    return {
        'name': name,
        'description': (pick('description', '') or '').strip()[:500],
        'answer': answer,
        'target_cluster_id': target,
        'callback_url': callback_url,
        'callback_fingerprint': fp,
        'max_uses': max_uses,
        'expires_at': expires_at,
        'enabled': 1 if enabled else 0,
    }, None


@bp.route('/api/auto-install/profiles', methods=['POST'])
@require_auth(perms=['autoinstall.manage'])
def create_profile():
    """The token is returned here and never again; only its hash is stored."""
    denied = _refuse_confined_caller()
    if denied:
        return denied
    try:
        fields, err = _profile_payload(request.get_json(silent=True) or {})
        if err:
            return jsonify({'error': err}), 400

        token = _new_token()
        pid = str(uuid.uuid4())
        user = request.session.get('user', 'system')
        db = get_db()
        c = db.conn.cursor()
        c.execute('''INSERT INTO auto_install_profiles
                       (id, name, description, answer_encrypted, target_cluster_id,
                        callback_url, callback_fingerprint, token_hash, token_hint,
                        enabled, max_uses, uses, expires_at, created_at, created_by,
                        updated_at, updated_by)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?)''',
                  (pid, fields['name'], fields['description'], db._encrypt(fields['answer']),
                   fields['target_cluster_id'], fields['callback_url'], fields['callback_fingerprint'],
                   _hash_token(token), _present_token_hint(token), fields['enabled'],
                   fields['max_uses'], fields['expires_at'], _stamp(), user, _stamp(), user))
        db.conn.commit()
        log_audit(user, 'autoinstall.profile_created', f"Automated install profile '{fields['name']}'")

        profile, answer = _load_profile(pid)
        out = _with_targets(_public_profile(profile, answer), profile)
        out['token'] = token
        return jsonify(out), 201
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not create the installation profile')}), 500


@bp.route('/api/auto-install/profiles/<profile_id>', methods=['PUT'])
@require_auth(perms=['autoinstall.manage'])
def update_profile(profile_id):
    denied = _refuse_confined_caller()
    if denied:
        return denied
    try:
        existing, _answer = _load_profile(profile_id)
        if not existing:
            return jsonify({'error': 'Profile not found'}), 404
        fields, err = _profile_payload(request.get_json(silent=True) or {}, existing=existing)
        if err:
            return jsonify({'error': err}), 400

        user = request.session.get('user', 'system')
        db = get_db()
        c = db.conn.cursor()
        c.execute('''UPDATE auto_install_profiles
                        SET name = ?, description = ?, answer_encrypted = ?, target_cluster_id = ?,
                            callback_url = ?, callback_fingerprint = ?, enabled = ?, max_uses = ?,
                            expires_at = ?, updated_at = ?, updated_by = ?
                      WHERE id = ?''',
                  (fields['name'], fields['description'], db._encrypt(fields['answer']),
                   fields['target_cluster_id'], fields['callback_url'], fields['callback_fingerprint'],
                   fields['enabled'], fields['max_uses'], fields['expires_at'], _stamp(), user, profile_id))
        db.conn.commit()
        log_audit(user, 'autoinstall.profile_updated', f"Automated install profile '{fields['name']}'")
        profile, answer = _load_profile(profile_id)
        return jsonify(_with_targets(_public_profile(profile, answer), profile))
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not update the installation profile')}), 500


@bp.route('/api/auto-install/profiles/<profile_id>/token', methods=['POST'])
@require_auth(perms=['autoinstall.manage'])
def rotate_token(profile_id):
    """New token, old one dead. This is the revoke button for every ISO already
    prepared from this profile. The use counter starts over with it."""
    denied = _refuse_confined_caller()
    if denied:
        return denied
    try:
        profile, _ = _load_profile(profile_id)
        if not profile:
            return jsonify({'error': 'Profile not found'}), 404
        token = _new_token()
        user = request.session.get('user', 'system')
        db = get_db()
        c = db.conn.cursor()
        c.execute('''UPDATE auto_install_profiles
                        SET token_hash = ?, token_hint = ?, uses = 0, updated_at = ?, updated_by = ?
                      WHERE id = ?''',
                  (_hash_token(token), _present_token_hint(token), _stamp(), user, profile_id))
        db.conn.commit()
        log_audit(user, 'autoinstall.token_rotated', f"Automated install profile '{profile.get('name')}'")
        return jsonify(_with_targets({'token': token, 'token_hint': _present_token_hint(token)}, profile))
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not rotate the token')}), 500


@bp.route('/api/auto-install/profiles/<profile_id>', methods=['DELETE'])
@require_auth(perms=['autoinstall.manage'])
def delete_profile(profile_id):
    denied = _refuse_confined_caller()
    if denied:
        return denied
    try:
        profile, _ = _load_profile(profile_id)
        if not profile:
            return jsonify({'error': 'Profile not found'}), 404
        user = request.session.get('user', 'system')
        db = get_db()
        c = db.conn.cursor()
        c.execute('DELETE FROM auto_install_runs WHERE profile_id = ?', (profile_id,))
        c.execute('DELETE FROM auto_install_profiles WHERE id = ?', (profile_id,))
        db.conn.commit()
        log_audit(user, 'autoinstall.profile_deleted', f"Automated install profile '{profile.get('name')}'")
        return jsonify({'message': 'Profile deleted'})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not delete the installation profile')}), 500


@bp.route('/api/auto-install/validate', methods=['POST'])
@require_auth(perms=['autoinstall.manage'])
def validate_endpoint():
    denied = _refuse_confined_caller()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    errors, warnings = validate_answer(data.get('answer'))
    return jsonify({'valid': not errors, 'errors': errors, 'warnings': warnings})


# PAM on the node checks this hash at every root login, so it has to stay cheap
# there (~70 ms in libcrypt); here it is ~150 ms of pure Python per call
_ROOT_HASH_ROUNDS = 100000
_ROOT_HASH_SEM = None


def _hash_root_password(pw):
    """sha512_crypt in the threadpool, one at a time.

    Not through the login's _pw_hash_offload: that semaphore admits eight and is
    sized for argon2, which lets go of the GIL. This loop does not (every update is
    far below hashlib's release threshold), so eight of them together starved the
    hub for seconds and queued everybody's login behind them. With one slot the
    throughput is the same and the hub keeps breathing.
    """
    global _ROOT_HASH_SEM
    try:
        from gevent import get_hub
        from gevent.lock import BoundedSemaphore
    except Exception:
        return sha512_crypt(pw, None, _ROOT_HASH_ROUNDS)
    if _ROOT_HASH_SEM is None:
        _ROOT_HASH_SEM = BoundedSemaphore(1)
    with _ROOT_HASH_SEM:
        return get_hub().threadpool.apply(sha512_crypt, (pw, None, _ROOT_HASH_ROUNDS))


def _root_password_problem(pw):
    if not isinstance(pw, str):
        return 'A password is required'
    # the installer's minimum is 8 bytes, Proxmox's own schema caps it at 64
    if not 8 <= len(pw) <= 64 or len(pw.encode('utf-8', 'replace')) < 8:
        return 'The password must be 8 to 64 characters long'
    if _unprintable(pw):
        return 'The password must not contain control characters'
    return None


@bp.route('/api/auto-install/password-hash', methods=['POST'])
@require_auth(perms=['autoinstall.manage'])
def password_hash_endpoint():
    """Turn a root password into the $6$ hash an answer file carries.

    The only place a clear root password reaches us. It is hashed and dropped: not
    logged, not audited, not stored, and never repeated in an error.
    """
    denied = _refuse_confined_caller()
    if denied:
        return denied
    user = request.session.get('user', '')
    # literal budget: the limiter keeps one window per distinct pair
    if not check_auth_action_rate_limit(f'autoinstall_hash:{user}', max_attempts=20, window=300):
        resp = jsonify({'error': 'Too many attempts. Try again in 5 minutes.'})
        resp.headers['Retry-After'] = '300'
        return resp, 429
    data = request.get_json(silent=True)
    pw = data.get('password') if isinstance(data, dict) else None
    problem = _root_password_problem(pw)
    if problem:
        return jsonify({'error': problem}), 400
    try:
        hashed = _hash_root_password(pw)
    except Exception as e:
        logging.error(f"[autoinstall] hashing a root password failed: {type(e).__name__}")
        return jsonify({'error': 'Could not hash the password'}), 500
    resp = jsonify({'hash': hashed})
    # the app sets this for every /api/ answer anyway; this one should not depend on that
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@bp.route('/api/auto-install/compose', methods=['POST'])
@require_auth(perms=['autoinstall.manage'])
def compose_endpoint():
    """The guided setup's answer file, built from its fields and checked like any
    other. Nothing is stored: the wizard saves what it showed through the normal
    create call, so there is one save path and one set of rules."""
    denied = _refuse_confined_caller()
    if denied:
        return denied
    data = request.get_json(silent=True)
    try:
        text, field_errors = build_answer(data.get('fields') if isinstance(data, dict) else None)
    except ComposeRefused as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not compose the answer file')}), 500
    if field_errors:
        return jsonify({'answer': '', 'valid': False, 'errors': list(field_errors.values()),
                        'warnings': [], 'field_errors': field_errors})
    errors, warnings = validate_answer(text)
    return jsonify({'answer': text, 'valid': not errors, 'errors': errors,
                    'warnings': warnings, 'field_errors': {}})


@bp.route('/api/auto-install/runs', methods=['GET'])
@require_auth(perms=['autoinstall.view'])
def list_runs():
    """Newest 500. Each profile keeps its last 1000 runs, older ones are pruned
    when a new machine checks in."""
    denied = _refuse_confined_caller()
    if denied:
        return denied
    try:
        c = get_db().conn.cursor()
        profile_id = (request.args.get('profile_id') or '').strip()
        query = ('SELECT r.*, p.name AS profile_name FROM auto_install_runs r '
                 'LEFT JOIN auto_install_profiles p ON p.id = r.profile_id ')
        if profile_id:
            c.execute(query + 'WHERE r.profile_id = ? ORDER BY r.started_at DESC LIMIT 500', (profile_id,))
        else:
            c.execute(query + 'ORDER BY r.started_at DESC LIMIT 500')
        runs = []
        for row in c.fetchall():
            run = {k: row[k] for k in row.keys()}
            run.pop('callback_token_hash', None)
            try:
                run['system_info'] = json.loads(run.get('system_info') or '{}')
            except (ValueError, TypeError):
                run['system_info'] = {}
            runs.append(run)
        return jsonify(runs)
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not list installation runs')}), 500


@bp.route('/api/auto-install/runs/<run_id>', methods=['DELETE'])
@require_auth(perms=['autoinstall.manage'])
def delete_run(run_id):
    denied = _refuse_confined_caller()
    if denied:
        return denied
    try:
        db = get_db()
        c = db.conn.cursor()
        c.execute('DELETE FROM auto_install_runs WHERE id = ?', (run_id,))
        db.conn.commit()
        if not c.rowcount:
            return jsonify({'error': 'Run not found'}), 404
        log_audit(request.session.get('user', 'system'), 'autoinstall.run_cleared', run_id)
        return jsonify({'message': 'Run cleared'})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not clear the run')}), 500


# --- installer-facing endpoints: no session, a token is the whole gate --------

def _machine_fingerprint(info):
    """A stable id for the machine, so a retried fetch updates its run instead of
    adding one. Serial, then the SMBIOS uuid (VMs usually have no serial but a
    uuid), then the lowest MAC. Nothing usable means a new row every time, which
    is the safe direction: two rows confuse, one row covering two machines lies."""
    if not isinstance(info, dict):
        return ''
    dmi = info.get('dmi') if isinstance(info.get('dmi'), dict) else {}
    system = dmi.get('system') if isinstance(dmi.get('system'), dict) else {}
    serial = _s(system.get('serial'), 128)
    if serial.lower() not in _JUNK_SERIALS:
        return f'serial:{serial}'
    smbios_uuid = _s(system.get('uuid'), 64).lower()
    if smbios_uuid not in _JUNK_UUIDS:
        return f'uuid:{smbios_uuid}'
    # the fetch payload says network_interfaces, the webhook network-interfaces
    nics = info.get('network_interfaces') or info.get('network-interfaces') or []
    macs = sorted(_s(n.get('mac'), 32).lower() for n in nics if isinstance(n, dict))
    macs = [m for m in macs if m and m != '00:00:00:00:00:00']
    return f'mac:{macs[0]}' if macs else ''


def _summarise_system(info):
    """(hostname, hardware, version) for the run list, read defensively from
    whatever the installer sent."""
    if not isinstance(info, dict):
        return '', '', ''
    dmi = info.get('dmi') if isinstance(info.get('dmi'), dict) else {}
    system = dmi.get('system') if isinstance(dmi.get('system'), dict) else {}
    hardware = ' '.join(x for x in (_s(system.get('manufacturer'), 60),
                                    _s(system.get('name') or system.get('product'), 120)) if x)
    iso = info.get('iso') if isinstance(info.get('iso'), dict) else {}
    product = info.get('product') if isinstance(info.get('product'), dict) else {}
    version = _s(product.get('version'), 40) or _s(iso.get('release'), 40)
    hostname = _s(info.get('fqdn'), 253) or _s(info.get('hostname'), 253)
    return hostname, hardware[:120], version


def _bounded_json(info):
    """The inventory, small enough to keep. Cutting the dumped string would store
    something that no longer parses, and the run list would silently show {}."""
    raw = json.dumps(info)
    if len(raw) <= _MAX_SYSTEM_INFO:
        return raw
    return json.dumps({'truncated': True, 'bytes': len(raw), 'keys': sorted(info.keys())[:40]})


_refusals = {}
_refusals_lock = threading.Lock()
_REFUSAL_WINDOW = 60
_REFUSAL_AUDIT_MAX = 10


def _reject(reason, token, status=403):
    """One answer for every refusal, so a prober cannot tell an unknown token from
    a spent one. Audited, but only the first few per address and minute - guessing
    a 256-bit token is hopeless, and past that the rows are only noise that would
    crowd real events out of the SIEM queue."""
    ip = get_client_ip()
    now = time.monotonic()
    with _refusals_lock:
        start, n = _refusals.get(ip, (now, 0))
        if now - start > _REFUSAL_WINDOW:
            start, n = now, 0
        _refusals[ip] = (start, n + 1)
        if len(_refusals) > 4096:
            _refusals.clear()
    hint = (token[:12] + '...') if token else 'missing'
    if n < _REFUSAL_AUDIT_MAX:
        log_audit('installer', 'autoinstall.fetch_refused', f'{reason} (token {hint})', ip_address=ip)
    else:
        logging.debug(f"[autoinstall] refused {ip}: {reason}")
    return jsonify({'error': 'Invalid or expired installation token'}), status


@bp.route('/api/auto-install/answer', methods=['POST'])
def serve_answer():
    """Where the prepared ISO asks for its answer file. Plain-text TOML back."""
    token = _request_token()
    if not token:
        return _reject('no token presented', '')
    try:
        profile = _profile_for_token(token)
        if not profile:
            return _reject('unknown token', token)
        ok, why = _profile_usable(profile)
        if not ok:
            return _reject(why, token)
        if profile.get('answer_unreadable'):
            logging.error(f"[autoinstall] profile {profile['id']} has an answer file that cannot be decrypted")
            return jsonify({'error': 'The stored answer file could not be read'}), 500

        # get_json can yield under gevent while a slow body trickles in, so nothing
        # decided above is still true afterwards - see the claim below
        info = request.get_json(silent=True)
        if not isinstance(info, dict):
            info = {}
        hostname, hardware, version = _summarise_system(info)
        fingerprint = _machine_fingerprint(info)

        callback_token = secrets.token_urlsafe(32)
        body, err = render_answer(profile, callback_token)
        if err:
            logging.error(f"[autoinstall] profile {profile['id']} rendered an invalid answer file: {err}")
            return jsonify({'error': 'The stored answer file could not be rendered'}), 500

        db = get_db()
        c = db.conn.cursor()
        now = _stamp()
        # the use is claimed here, in one statement, so two fetches racing for the
        # last use - or a fetch racing a revoke or a rotate - cannot both win
        c.execute('''UPDATE auto_install_profiles SET uses = uses + 1
                      WHERE id = ? AND token_hash = ? AND enabled = 1
                        AND (max_uses = 0 OR uses < max_uses)
                        AND (expires_at IS NULL OR expires_at = '' OR expires_at > ?)''',
                  (profile['id'], _hash_token(token), now))
        if c.rowcount != 1:
            return _reject('revoked, expired or used up while the request was in flight', token)

        existing = None
        if fingerprint:
            c.execute('''SELECT id FROM auto_install_runs WHERE profile_id = ? AND fingerprint = ?
                          ORDER BY started_at DESC LIMIT 1''', (profile['id'], fingerprint))
            existing = c.fetchone()
        run_values = (hostname, hardware, version, _bounded_json(info), get_client_ip(),
                      _hash_token(callback_token), now, now)
        if existing:
            c.execute('''UPDATE auto_install_runs
                            SET status = 'installing', hostname = ?, product = ?, version = ?,
                                system_info = ?, message = '', client_ip = ?,
                                callback_token_hash = ?, started_at = ?, updated_at = ?
                          WHERE id = ?''', run_values + (existing['id'],))
        else:
            c.execute('''INSERT INTO auto_install_runs
                           (hostname, product, version, system_info, client_ip,
                            callback_token_hash, started_at, updated_at,
                            id, profile_id, status, fingerprint, message)
                         VALUES (?,?,?,?,?,?,?,?,?,?,'installing',?,'')''',
                      run_values + (str(uuid.uuid4()), profile['id'], fingerprint))
            c.execute('''DELETE FROM auto_install_runs WHERE profile_id = ? AND id NOT IN
                           (SELECT id FROM auto_install_runs WHERE profile_id = ?
                             ORDER BY started_at DESC LIMIT ?)''',
                      (profile['id'], profile['id'], _RUNS_KEPT_PER_PROFILE))
        db.conn.commit()

        log_audit('installer', 'autoinstall.answer_served',
                  f"profile '{profile.get('name')}' -> {hardware or 'unknown hardware'}",
                  ip_address=get_client_ip())
        return Response(body, mimetype='text/plain')
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not serve the answer file')}), 500


def _webhook_status(payload):
    """installing / installed / failed for a callback body.

    The installer's own webhook fires only after a successful install and has no
    status field at all: it describes the new system ($schema, fqdn, machine-id,
    ssh-public-host-keys, ...). An authenticated body of that shape is 'installed'.
    Explicit fields are for anything else that posts here, a first-boot script or
    curl, and a body we cannot read either way leaves the run where it was.
    """
    if not isinstance(payload, dict):
        return 'installing', ''
    explicit = payload.get('status') or payload.get('state') or ''
    explicit = explicit.strip().lower() if isinstance(explicit, str) else ''
    message = payload.get('message') or payload.get('error') or ''
    message = message[:2000] if isinstance(message, str) else ''
    if explicit in _STATUSES:
        return explicit, message
    if explicit in ('ok', 'success', 'succeeded', 'done', 'finished', 'complete', 'completed'):
        return 'installed', message
    if explicit in ('error', 'failure', 'aborted'):
        return 'failed', message
    if isinstance(payload.get('success'), bool):
        return ('installed' if payload['success'] else 'failed'), message
    if payload.get('error'):
        return 'failed', message
    if any(k in payload for k in ('$schema', 'machine-id', 'ssh-public-host-keys')):
        return 'installed', ''
    return 'installing', ''


@bp.route('/api/auto-install/progress', methods=['POST'])
def installer_progress():
    """[post-installation-webhook] target. Authenticated by the callback token of
    one run, which is only in the file served to that machine."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = {}
    # ?token= is what we write into the webhook URL; a body "token" is what an
    # installer sends when the section carries auth-token
    body_token = payload.get('token') if isinstance(payload.get('token'), str) else ''
    token = _request_token() or body_token.strip()
    if not token:
        return _reject('no callback token', '')
    try:
        run = _run_for_callback_token(token)
        if not run:
            return _reject('unknown callback token', token)
        # a disabled or spent profile must still be able to close a run it started,
        # otherwise that run sits at 'installing' for good
        status, message = _webhook_status(payload)
        hostname, _hardware, version = _summarise_system(payload)
        try:
            info = json.loads(run.get('system_info') or '{}')
        except (ValueError, TypeError):
            info = {}
        if not isinstance(info, dict):
            info = {}
        report = {k: v for k, v in payload.items() if k != 'token'}
        if report:
            info['post_install'] = report
        db = get_db()
        c = db.conn.cursor()
        c.execute('''UPDATE auto_install_runs
                        SET status = ?, message = ?, hostname = ?, version = ?,
                            system_info = ?, updated_at = ?
                      WHERE id = ?''',
                  (status, message, hostname or run.get('hostname') or '',
                   version or run.get('version') or '', _bounded_json(info), _stamp(), run['id']))
        db.conn.commit()
        log_audit('installer', 'autoinstall.progress',
                  f"run {run['id'][:8]} -> {status}", ip_address=get_client_ip())
        return jsonify({'message': 'Recorded', 'status': status})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not record installation progress')}), 500
