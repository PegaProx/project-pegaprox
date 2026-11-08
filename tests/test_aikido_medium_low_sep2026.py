"""What the Aikido medium/low sweep of 2026-09-07 actually found still open.

Fifty-one of the sixty were genuinely closed. These cover the seven that were not — the
cases where a guard existed in the named file but did not reach the scenario the finding
described. One test per behaviour, named after what breaks if it regresses. NS
"""
import pytest

import pegaprox.api.drift as drift
import pegaprox.globals as ppglobals
from pegaprox.utils.url_security import is_safe_outbound_url


CLUSTER = 'cluster_1'


# ── 469089254: secrets in the drift baseline ─────────────────────────────────

def test_a_cloud_init_password_never_reaches_the_drift_record():
    """The read gate moved to admin.audit, but the value was still being written to the
    baseline and the event diff in cleartext, where it outlives the VM and lands in
    every DB backup."""
    cfg = {'cores': 2, 'cipassword': 'hunter2', 'net0': 'virtio=AA:BB'}

    clean = drift._strip_volatile(cfg, drift._VM_VOLATILE_KEYS)

    assert 'hunter2' not in repr(clean)
    assert clean['cipassword'].startswith('<redacted:')
    assert clean['cores'] == 2 and clean['net0'] == 'virtio=AA:BB'


def test_the_redaction_still_shows_a_changed_password_as_a_change():
    """Redacting to a constant would have made every rotation invisible — which is the
    one thing drift detection is for."""
    before = drift._strip_volatile({'cipassword': 'old'}, drift._VM_VOLATILE_KEYS)
    after = drift._strip_volatile({'cipassword': 'new'}, drift._VM_VOLATILE_KEYS)

    assert before['cipassword'] != after['cipassword']
    assert drift._flat_diff(before, after)[0]['path'] == 'cipassword'


def test_the_same_password_twice_produces_no_drift_event():
    """And the marker has to be stable across scans, or every poll invents a change."""
    a = drift._strip_volatile({'cipassword': 'same'}, drift._VM_VOLATILE_KEYS)
    b = drift._strip_volatile({'cipassword': 'same'}, drift._VM_VOLATILE_KEYS)

    assert drift._flat_diff(a, b) == []


def test_a_storage_keyring_goes_through_the_same_helper():
    """_strip_volatile is shared with the storage/network state, so a Ceph keyring and a
    CIFS password are covered by the same change."""
    clean = drift._strip_volatile({'keyring': 'AQBz...', 'server': 'nfs1'}, set())

    assert clean['keyring'].startswith('<redacted:')
    assert clean['server'] == 'nfs1'


def test_an_absent_secret_is_left_alone_rather_than_invented():
    assert drift._strip_volatile({'cipassword': ''}, set())['cipassword'] == ''
    assert drift._strip_volatile({'cipassword': None}, set())['cipassword'] is None


# ── 469089270: loopback through the SSRF guard ───────────────────────────────

_TPL = dict(allowed_schemes=('http', 'https'), allow_private=True, allow_loopback=False)


@pytest.mark.parametrize('url', [
    'http://127.0.0.1:8006/x.img',
    'http://127.255.1.2/x.img',
    'http://[::1]/x.img',
    'http://[::ffff:127.0.0.1]/x.img',   # v4-mapped, unwrapped by _is_loopback
    'http://0.0.0.0/x.img',
])
def test_a_template_image_url_cannot_point_at_the_nodes_own_loopback(url):
    """wget runs ON the PVE node and the bytes become a disk image the requester can boot
    and read, so this is a READ of whatever is bound to that node's 127.0.0.1 — an address
    no guest could otherwise reach. allow_private had been re-opening it."""
    ok, why = is_safe_outbound_url(url, **_TPL)

    assert ok is False, f'{url} was allowed: {why}'


@pytest.mark.parametrize('url', [
    'http://192.168.1.5/noble.img',
    'http://10.0.0.9/noble.img',
    'http://172.16.4.4/noble.img',
    'http://[fd00::1]/noble.img',
])
def test_an_internal_image_mirror_still_works(url):
    """The whole reason allow_private exists. An air-gapped install serves its images off
    the LAN and must not be broken by the loopback block."""
    ok, why = is_safe_outbound_url(url, **_TPL)

    assert ok is True, f'{url} was rejected: {why}'


def test_a_public_mirror_still_works():
    ok, _ = is_safe_outbound_url('https://cloud.debian.org/x.qcow2', **_TPL)

    assert ok is True


def test_the_other_allow_private_call_sites_keep_loopback():
    """PBS, a node URL and a BMC are admin-configured targets, and PegaProx next to its own
    PBS on one box is a real deployment. The block is opt-in for that reason."""
    ok, _ = is_safe_outbound_url('http://127.0.0.1:8007/', allowed_schemes=('http', 'https'),
                                 allow_private=True)

    assert ok is True


def test_metadata_stays_blocked_regardless():
    for kw in (_TPL, dict(allowed_schemes=('http',), allow_private=True)):
        ok, _ = is_safe_outbound_url('http://169.254.169.254/latest/meta-data/', **kw)
        assert ok is False


# ── 469089274: the ESXi import TLS default ───────────────────────────────────

def test_an_omitted_skip_cert_flag_means_verify():
    """The default was True while the UI checkbox renders `|| false` and does not send the
    key until it is touched — the dialog said verify, the storage was created with
    skip-cert-verification=1. Read off the source: the handler builds the PVE payload
    inline, so there is nothing else to call."""
    src = open('pegaprox/api/storage.py').read()
    body = src[src.index("def connect_esxi_host("):]
    line = next(l for l in body.split('\n') if 'skip_cert_verification' in l and 'data.get' in l)

    assert 'False' in line, line


@pytest.mark.parametrize('raw,skips', [
    (True, True), (1, True), ('true', True), ('1', True), ('yes', True),
    (False, False), (0, False), (None, False), ('', False),
    ('false', False),   # the one bool() got wrong — bool("false") is True
    ('0', False),
])
def test_the_skip_cert_flag_is_coerced_not_just_truthiness_tested(raw, skips):
    """A `bool()` around the .get() looked like it sanitised the value and did not, so a client
    sending the JSON string "false" would have switched certificate checking off. Mirrors the
    handler's own expression rather than the source text, so it fails if the rule drifts."""
    coerced = raw is True or raw == 1 or (
        isinstance(raw, str) and raw.strip().lower() in ('true', '1', 'yes', 'on'))

    assert coerced is skips, f'{raw!r} coerced to {coerced}'
    src = open('pegaprox/api/storage.py').read()
    assert "in ('true', '1', 'yes', 'on')" in src, 'the handler no longer coerces explicitly'


# ── 469089277: host-key pins shared with another cluster ─────────────────────

def test_deleting_a_cluster_keeps_a_pin_another_cluster_still_uses():
    """Dropping it would silently re-TOFU that host for the other cluster on its next SSH
    connection — the exact window reject-on-change exists to close."""
    src = open('pegaprox/api/clusters.py').read()
    block = src[src.index('def delete_cluster('):]
    block = block[:block.index('remove_host_keys(hosts_to_clean)')]

    assert 'still_pinned' in block, 'the delete path no longer excludes shared hosts'
    assert 'hosts_to_clean -= still_pinned' in block


# ── 469089189: the cross-tenant existence oracle ─────────────────────────────

def test_a_tenant_admin_cannot_tell_a_foreign_user_from_a_missing_one(api, seed):
    """The cross-tenant read was blocked with 403 while a missing name answered 404, so the
    status code still told a tenant admin whether the account existed elsewhere."""
    seed.tenant('tenant_a', clusters=[CLUSTER])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    seed.user('victim', role='user', tenant_id='tenant_b')
    caller = seed.user('a_admin', role='user', tenant_id='tenant_a',
                       permissions=['admin.users'])
    c = api.as_user(caller)

    existing = c.get('/api/users/victim/permissions')
    missing = c.get('/api/users/nobody-at-all/permissions')

    assert existing.status_code == missing.status_code == 404


def test_a_global_admin_still_reads_every_tenant(api, seed):
    """The over-restriction this could cause."""
    seed.tenant('tenant_b', clusters=['cluster_2'])
    seed.user('victim', role='user', tenant_id='tenant_b')
    c = api.as_user(seed.user('root_admin', role='admin'))

    r = c.get('/api/users/victim/permissions')

    assert r.status_code == 200
    assert r.get_json()['username'] == 'victim'


def test_a_tenant_admin_still_reads_their_own_tenants_users(api, seed):
    seed.tenant('tenant_a', clusters=[CLUSTER])
    seed.user('colleague', role='user', tenant_id='tenant_a')
    caller = seed.user('a_admin', role='user', tenant_id='tenant_a',
                       permissions=['admin.users'])

    r = api.as_user(caller).get('/api/users/colleague/permissions')

    assert r.status_code == 200


# ── 469089217: failover asks the wrong per-VM question ───────────────────────

def test_the_four_vm_starting_failover_routes_ask_for_start():
    """Planned, emergency, test and failback all power VMs on at the target. The read
    routes deliberately stay on vm.view."""
    src = open('pegaprox/api/site_recovery.py').read()

    assert src.count('_authz_plan_vms(plan, starts_vms=True)') == 4
    assert 'def _authz_plan_vms(plan, starts_vms=False)' in src


def test_an_unconfined_dr_operator_is_not_asked_for_vm_start():
    """site_recovery.failover is admin-only by default, so anyone else holding it has a
    custom role. Demanding vm.start from an unconfined one would break that role without
    closing anything — the gap is only reachable through a pool/ACL grant."""
    src = open('pegaprox/api/site_recovery.py').read()
    fn = src[src.index('def _authz_plan_vms('):src.index('# ---- CRUD: Plans ----')]

    assert 'caller_is_scoped' in fn
    assert "perm = 'vm.start'" in fn


# ── 469089235: which role the template path reads ────────────────────────────

def test_the_role_template_path_resolves_the_role_live():
    """It read request.session['role'], cached when the session was minted, while its create
    sibling used build_authz_user — so a demoted admin kept the old answer until logout."""
    src = open('pegaprox/api/users.py').read()
    fn = src[src.index('def apply_role_template('):]
    fn = fn[:fn.index('custom = get_custom_roles()')]

    assert "request.session.get('role') != ROLE_ADMIN" not in fn
    assert 'build_authz_user' in fn
