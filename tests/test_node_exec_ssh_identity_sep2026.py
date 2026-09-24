"""_pve_node_exec offered root + the web password to somebody else's hypervisor.

Observed live on a real cluster: one console-tile screenshot produced two
`Authentication (keyboard-interactive) failed.` entries against a node whose own SSH
banner reads "All activities are monitored and logged. Unauthorized access will be
prosecuted to the fullest extent of law." The screendump behind those tiles runs on
every poll, so this was a steady trickle, not a one-off — and a fail2ban response is
IP-wide, which takes :8006 with it and drops the API, the console and SSE together.

Three separate causes, all of them here:
  * the user was hardcoded to 'root' while core/xhm.py has always honoured ssh_user
  * nothing asked whether an SSH credential exists at all, though ssh_diagnose knows
  * the circuit breaker's 'auth failed' pattern matches nothing paramiko ever says,
    so the throttle that should have stopped the repetition never engaged
MK
"""
import pytest

from pegaprox.utils import ssh as ssh_mod


class _Cfg:
    def __init__(self, **kw):
        self.pass_ = kw.get('pass_', 'webpw')
        self.ssh_user = kw.get('ssh_user', '')
        self.ssh_key = kw.get('ssh_key', '')
        self.user = kw.get('user', 'root@pam')


class _Mgr:
    id = 'c1'
    host = '10.0.0.1'
    api_port = 8006

    def __init__(self, diag=None, **cfg):
        self.config = _Cfg(**cfg)
        self._diag = diag
        self.failures = []

    def _is_node_blocked(self, node): return (False, 0)
    def _register_node_failure(self, node): self.failures.append(node)
    def _reset_node_failures(self, node): pass
    def _get_node_ip(self, node): return '10.0.0.7'
    def ssh_diagnose(self, node): return self._diag
    def _api_post(self, *a, **k): raise RuntimeError('no API exec')


@pytest.fixture(autouse=True)
def _no_ip_cache():
    ssh_mod._node_ip_cache.clear()
    yield
    ssh_mod._node_ip_cache.clear()


def test_the_configured_ssh_user_is_used(monkeypatch):
    seen = {}
    monkeypatch.setattr(ssh_mod, '_ssh_exec',
                        lambda host, user, pwd, cmd, **k: seen.update(user=user) or (0, 'ok', ''))
    mgr = _Mgr(ssh_user='pegaprox')
    ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert seen['user'] == 'pegaprox', "still hardcoding root, as core/xhm.py never did"


def test_root_remains_the_default_when_none_is_configured(monkeypatch):
    seen = {}
    monkeypatch.setattr(ssh_mod, '_ssh_exec',
                        lambda host, user, pwd, cmd, **k: seen.update(user=user) or (0, 'ok', ''))
    ssh_mod._pve_node_exec(_Mgr(), 'n1', 'true')
    assert seen['user'] == 'root'


def test_a_cluster_with_no_ssh_credential_is_never_offered_to_sshd(monkeypatch):
    """The token-only case (#717): config.pass_ holds the TOKEN SECRET, and handing that
    to sshd is a failed root login on the customer's node for no possible benefit."""
    called = []
    monkeypatch.setattr(ssh_mod, '_ssh_exec',
                        lambda *a, **k: called.append(1) or (0, '', ''))
    mgr = _Mgr(diag=('SSH_NO_CREDENTIALS', 'api token only, no ssh key or password'))
    rc, out, err = ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert rc == 1
    assert not called, "attempted SSH anyway"
    assert 'ssh' in err.lower() or 'token' in err.lower()


def test_other_diagnoses_do_not_block_the_attempt(monkeypatch):
    """Only 'no credentials' is a reason not to try. Backoff is handled separately and a
    None diagnosis means nothing known explains it — both must still reach sshd."""
    called = []
    monkeypatch.setattr(ssh_mod, '_ssh_exec',
                        lambda *a, **k: called.append(1) or (0, 'ok', ''))
    mgr = _Mgr(diag=('NODE_BACKOFF', 'in backoff'))
    ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert called, "a non-credential diagnosis must not suppress the call"


def test_a_manager_without_the_classifier_still_works(monkeypatch):
    """Older managers predate ssh_diagnose; they must not start raising here."""
    called = []
    monkeypatch.setattr(ssh_mod, '_ssh_exec',
                        lambda *a, **k: called.append(1) or (0, 'ok', ''))
    mgr = _Mgr()
    del mgr.__class__.ssh_diagnose          # simulate the old shape
    try:
        rc, out, err = ssh_mod._pve_node_exec(mgr, 'n1', 'true')
        assert called and rc == 0
    finally:
        _Mgr.ssh_diagnose = lambda self, node: self._diag


# ── the breaker pattern that never matched ──

@pytest.mark.parametrize('err', [
    'Authentication (keyboard-interactive) failed.',
    'Authentication failed.',
    'M1(ki-transport): Authentication (keyboard-interactive) failed.',
    'Permission denied (publickey,password).',
])
def test_an_auth_rejection_trips_the_node_breaker(monkeypatch, err):
    monkeypatch.setattr(ssh_mod, '_ssh_exec', lambda *a, **k: (255, '', err))
    mgr = _Mgr()
    ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert mgr.failures == ['n1'], f"breaker sat idle through {err!r} — the repetition is the damage"


@pytest.mark.parametrize('err', [
    "rm: cannot remove '/etc/x': Permission denied",
    "cat: /root/secret: Permission denied",
])
def test_a_command_that_is_merely_denied_does_not_mark_the_node_dead(monkeypatch, err):
    """A bare 'permission denied' is also what a COMMAND says when it fails. Treating that
    as a dead node would take a perfectly healthy hypervisor out of the UI."""
    monkeypatch.setattr(ssh_mod, '_ssh_exec', lambda *a, **k: (1, '', err))
    mgr = _Mgr()
    ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert mgr.failures == [], f"{err!r} wrongly marked the node unreachable"


def test_an_api_token_cluster_with_an_ssh_key_is_still_never_offered_the_secret(monkeypatch):
    """The hole the first round left open. ssh_diagnose answers "no credentials" only
    when there is neither a key nor a usable password, so key + API token comes back
    clean — but _ssh_exec cannot use a key, so config.pass_ (the TOKEN SECRET) went to
    sshd in its place, through every auth method it owns, on every screendump poll."""
    called = []
    monkeypatch.setattr(ssh_mod, '_ssh_exec',
                        lambda *a, **k: called.append(1) or (0, 'ok', ''))
    # the operator typed a token id as the username — that is what makes pass_ the
    # secret. (_using_api_token alone does not: we set it ourselves for clusters whose
    # token we minted, and those keep a real password.)
    mgr = _Mgr(user='root@pam!pegaprox', ssh_key='-----BEGIN OPENSSH PRIVATE KEY-----',
               pass_='pve-token-secret')
    mgr._using_api_token = True
    rc, out, err = ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert rc == 1
    assert not called, "handed the API token secret to sshd as a password"
    assert 'password' in err.lower()


def test_a_key_only_cluster_is_not_attempted_either(monkeypatch):
    """Same shape without the token: a key is stored, no password. This path is
    password-only, so trying is a guaranteed-failed root login, not a fallback."""
    called = []
    monkeypatch.setattr(ssh_mod, '_ssh_exec',
                        lambda *a, **k: called.append(1) or (0, 'ok', ''))
    mgr = _Mgr(ssh_key='-----BEGIN OPENSSH PRIVATE KEY-----', pass_='')
    rc, out, err = ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert rc == 1 and not called


def test_a_real_password_still_goes_through_even_with_a_key_present(monkeypatch):
    """The guard must not turn into "a key is stored, so give up" — a cluster with both
    still authenticates by password here, and that is the normal case."""
    seen = {}
    monkeypatch.setattr(ssh_mod, '_ssh_exec',
                        lambda host, user, pwd, cmd, **k: seen.update(pwd=pwd) or (0, 'ok', ''))
    mgr = _Mgr(ssh_key='-----BEGIN OPENSSH PRIVATE KEY-----', pass_='realpw')
    rc, out, err = ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert rc == 0 and seen['pwd'] == 'realpw'


def test_the_secret_never_reaches_the_error_text(monkeypatch):
    """Whatever we refuse to send must not leak into a message the UI renders."""
    monkeypatch.setattr(ssh_mod, '_ssh_exec', lambda *a, **k: (0, 'ok', ''))
    mgr = _Mgr(user='root@pam!pegaprox', ssh_key='k', pass_='pve-token-secret')
    mgr._using_api_token = True
    _, _, err = ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert 'pve-token-secret' not in err


def test_the_refusal_names_the_reason_it_actually_checked(monkeypatch):
    """CodeAnt (daily scan, 16.09) flagged this line. The first version said "a stored SSH
    key is not usable on this path" in every case — but the branch is also reached with no
    credential at all, when ssh_diagnose raised and never got to say so itself. Asserting a
    key that isn't there sends the operator looking for the wrong thing."""
    monkeypatch.setattr(ssh_mod, '_ssh_exec', lambda *a, **k: (0, 'ok', ''))

    class _Boom(_Mgr):
        def ssh_diagnose(self, node): raise RuntimeError('classifier missing')

    bare = _Boom(pass_='', ssh_key='')
    _, _, err = ssh_mod._pve_node_exec(bare, 'n1', 'true')
    assert 'no SSH password is stored' in err
    assert 'ssh key' not in err.lower(), f"claims a key that was never configured: {err}"

    keyed = _Boom(pass_='', ssh_key='-----BEGIN OPENSSH PRIVATE KEY-----')
    _, _, err = ssh_mod._pve_node_exec(keyed, 'n1', 'true')
    assert 'ssh key' in err.lower() and 'password only' in err.lower()

    tok = _Mgr(user='root@pam!pegaprox', pass_='pve-token-secret', ssh_key='k')
    tok._using_api_token = True
    _, _, err = ssh_mod._pve_node_exec(tok, 'n1', 'true')
    assert 'api token' in err.lower()
    assert 'pve-token-secret' not in err


# ── the regression the first round introduced ────────────────────────────────

def test_a_cluster_whose_token_we_minted_keeps_its_ssh_password(monkeypatch):
    """The #110 path: operator gives username + password, we create our own API token on
    first connect and switch REST to it — "keep password for SSH", as that code says. It
    sets _using_api_token=True while config.pass_ is still the account password. Gating on
    _using_api_token took node commands away from the most ordinary setup there is:
    screendumps, V2P, XHM and the compliance checks all run through here."""
    seen = {}
    monkeypatch.setattr(ssh_mod, '_ssh_exec',
                        lambda host, user, pwd, cmd, **k: seen.update(pwd=pwd) or (0, 'ok', ''))
    mgr = _Mgr(user='root@pam', pass_='realpassword')   # no '!' — not a token id
    mgr._using_api_token = True                          # we minted one
    rc, out, err = ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert rc == 0, f"refused a usable password: {err}"
    assert seen.get('pwd') == 'realpassword'


def test_an_operator_supplied_token_id_still_never_reaches_sshd(monkeypatch):
    """#717 unchanged: when the USERNAME is the token id, pass_ is the token secret."""
    called = []
    monkeypatch.setattr(ssh_mod, '_ssh_exec', lambda *a, **k: called.append(1) or (0, 'ok', ''))
    mgr = _Mgr(user='root@pam!pegaprox', pass_='the-token-secret', ssh_key='k')
    mgr._using_api_token = True
    rc, _, err = ssh_mod._pve_node_exec(mgr, 'n1', 'true')
    assert rc == 1 and not called
    assert 'the-token-secret' not in err
