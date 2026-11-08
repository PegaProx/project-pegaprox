"""A token cluster with an SSH key offered its token secret to sshd once the key was refused.

On a cluster that authenticates with an API token, config.user is 'user@realm!tokenid' and
config.pass_ is the token SECRET. ssh_blocked_reason knew that, but a stored key was enough
for it to say go - and the SSH ladders then ran key, BatchMode, sshpass with config.pass_.
Any node that did not take the key got the Proxmox token as a password, in its auth log
and in front of whatever sits in the PAM stack. #717 class, found again in
_ssh_node_output_ex (the cluster claim, the ceph flags) and in a dozen copies of the same
ladder in the HA code, the BMC probe, the content sync and the migration paths.

The rule now lives in one place, ssh_password_for() / ssh_password_to_offer(). These tests
stub the wire (node_cmd for the ssh/sshpass subprocesses, the paramiko client for the
rest), refuse every attempt the way a node does that does not know the key, and look at
what was offered. The mirror runs every ladder again for an account-password cluster,
including the #110 one whose token we minted ourselves. MK
"""
import ast
import os
import subprocess
import types

import pytest

from pegaprox.models.tasks import PegaProxConfig

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# what pass_ holds in each setup - kept out of names a scanner reads as a credential
TOKEN_SIDE = 'tok-0f3a-for-the-api-only'
ACCOUNT_SIDE = 'acct-7c1e-a-real-login'
KEY_TEXT = ('-----BEGIN OPENSSH PRIVATE KEY-----\n'
            'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n'
            '-----END OPENSSH PRIVATE KEY-----\n')


def _cfg(user, stored, **kw):
    data = {'name': 'c', 'host': '10.0.0.1', 'user': user, 'pass': stored, 'ssh_key': KEY_TEXT}
    data.update(kw)
    return PegaProxConfig(data)


def _token_cluster(**kw):
    return _cfg('root@pam!automation', TOKEN_SIDE, **kw)


def _account_cluster(**kw):
    return _cfg('root@pam', ACCOUNT_SIDE, **kw)


def _manager(cfg, minted_token=False):
    """A bare manager with just what the ladders touch. A real one would connect."""
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = cfg
    m.id = 'c1'
    m.current_host = None
    m._using_api_token = minted_token
    quiet = lambda *a, **k: None
    m.logger = types.SimpleNamespace(info=quiet, debug=quiet, warning=quiet, error=quiet,
                                     critical=quiet)
    m._last_ssh_block_logged = None
    m.is_connected = True
    m.ha_config = {'storage_heartbeat_path': '/mnt/pve/shared', 'two_node_mode': True,
                   'node_agent_installed': {}}
    m.ha_node_status = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    m._get_node_ip = lambda node: '10.0.0.7'
    m._ha_get_node_ip = lambda node: '10.0.0.7'
    m._ha_get_all_node_ips = lambda node: ['10.0.0.7']
    m._ha_check_vm_locks_on_storage = lambda node: {'has_active_locks': False}
    m._ha_claimed = lambda cmd, exact=True: cmd
    m._ha_detect_fence_strategy = lambda: 'quorum'
    m.get_node_status = lambda: {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    nodes = types.SimpleNamespace(status_code=200, json=lambda: {'data': [{'node': 'pve1'}]})
    m._create_session = lambda: types.SimpleNamespace(get=lambda url, timeout=10: nodes)
    return m


class _Wire:
    """Every ssh/sshpass that leaves for a node, refused like a node that does not take
    the key."""

    def __init__(self):
        self.sent = []

    def __call__(self, argv, **kw):
        env = kw.get('env') or {}
        self.sent.append((list(argv), env.get('SSHPASS')))
        return subprocess.CompletedProcess(argv, 255, '', 'Permission denied (publickey,password).')

    def offered(self):
        return [pw for argv, pw in self.sent if argv[:1] == ['sshpass']]


@pytest.fixture
def wire(monkeypatch):
    import pegaprox.core.manager as mgr_mod
    w = _Wire()
    monkeypatch.setattr(mgr_mod, 'node_cmd', w)
    # `which sshpass` in _ssh_run_command_with_password: say it is there, so a password
    # that gets that far really goes out instead of falling back to BatchMode
    sub = types.SimpleNamespace(**{k: getattr(subprocess, k) for k in dir(subprocess)
                                   if not k.startswith('__')})
    sub.run = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, '/usr/bin/sshpass\n', '')
    monkeypatch.setattr(mgr_mod, 'subprocess', sub)
    return w


def _spy_password_steps(m):
    """What each password step was handed - the real step still runs behind it."""
    from pegaprox.core.manager import PegaProxManager
    handed = []
    for name in ('_ssh_run_command_with_password', '_ssh_run_command_with_password_output'):
        real = getattr(PegaProxManager, name)

        def spy(host, user, cmd, password, *a, _real=real, **kw):
            handed.append(password)
            return _real(m, host, user, cmd, password, *a, **kw)
        setattr(m, name, spy)
    return handed


def _bmc_probe(m):
    from pegaprox.core import bmc
    return bmc.read_node_bmc_inband(m, 'pve1')


def _real_fence_strategy(m):
    # _manager stubs it for the agent installer; this ladder wants the real one
    from pegaprox.core.manager import PegaProxManager
    return PegaProxManager._ha_detect_fence_strategy(m)


LADDERS = {
    'ssh_node_output_ex': lambda m: m._ssh_node_output_ex('pve1', 'true'),
    'native_maintenance_on': lambda m: m._try_native_ha_maintenance(
        'pve1', types.SimpleNamespace(native_ha=False)),
    'native_maintenance_off': lambda m: m._try_disable_native_ha_maintenance('pve1'),
    'check_failed_node': lambda m: m._ha_check_node_via_ssh('pve1'),
    'stop_guests_on_failed_node': lambda m: m._ha_ssh_stop_vms_on_node(
        'pve1', vmids=[101], reachable_ips=['10.0.0.7']),
    'agent_ssh': lambda m: m._ha_agent_ssh('10.0.0.7', 'true'),
    'fence_strategy': _real_fence_strategy,
    'heartbeat_cleanup': lambda m: m._ha_cleanup_storage_heartbeat(),
    'install_node_agent': lambda m: m._ha_install_node_agent('pve1'),
    'force_quorum': lambda m: m._ha_try_force_quorum('pve1'),
    'restore_quorum': lambda m: m._ha_check_restore_quorum(),
    'move_vm_config': lambda m: m._ha_move_vm_config(101, 'qemu', 'pve1', 'pve2'),
    'bmc_inband_probe': _bmc_probe,
}


@pytest.mark.parametrize('ladder', sorted(LADDERS))
def test_a_refused_key_does_not_hand_the_token_secret_to_sshd(wire, ladder):
    m = _manager(_token_cluster())
    handed = _spy_password_steps(m)

    LADDERS[ladder](m)

    assert TOKEN_SIDE not in handed, \
        f'{ladder}: the API token secret went to a password step after the key was refused'
    assert TOKEN_SIDE not in wire.offered(), f'{ladder}: sshpass carried the API token secret'
    assert TOKEN_SIDE not in str(wire.sent)
    assert wire.sent, f'{ladder}: nothing reached the wire - the stub tested nothing'


@pytest.mark.parametrize('ladder', sorted(LADDERS))
def test_an_account_password_is_still_offered(wire, ladder):
    """The mirror - username + password is the ordinary setup and keeps its SSH."""
    m = _manager(_account_cluster())
    handed = _spy_password_steps(m)

    LADDERS[ladder](m)

    assert ACCOUNT_SIDE in handed, f'{ladder}: the account password was not offered any more'
    assert ACCOUNT_SIDE in wire.offered()


@pytest.mark.parametrize('ladder', ['ssh_node_output_ex', 'agent_ssh', 'force_quorum',
                                    'bmc_inband_probe'])
def test_a_token_we_minted_ourselves_keeps_the_password(wire, ladder):
    """#110: we minted the token on first connect, _using_api_token is True, and pass_ is
    still the account password. Keying on the flag would take SSH from these."""
    m = _manager(_account_cluster(), minted_token=True)
    handed = _spy_password_steps(m)

    LADDERS[ladder](m)

    assert ACCOUNT_SIDE in handed


# ------------------------------------------------- the paths with their own paramiko

class _Channel:
    def __init__(self, code):
        self.code = code

    def recv_exit_status(self):
        return self.code

    def shutdown_write(self):
        pass


class _Stream:
    def __init__(self, sink=None, code=1):
        self.channel = _Channel(code)
        self.sink = sink

    def write(self, data):
        self.sink.append(data)

    def flush(self):
        pass

    def read(self):
        return b''


class _Client:
    """A connected client whose commands all fail - what the content sync sees from a
    source node whose scp to the target is refused."""

    def __init__(self, log):
        self.log = log

    def exec_command(self, cmd, timeout=None):
        self.log.append(('cmd', cmd))
        sink = []
        self.log.append(('stdin', sink))
        return _Stream(sink), _Stream(code=1), _Stream()

    def open_sftp(self):
        raise IOError('no sftp here')

    def close(self):
        pass


def _sync(m):
    log = []
    m._ssh_connect = lambda host, *a, **k: _Client(log)
    m._get_syncable_storage = lambda *a: (None, None)
    m.member_node_ip = lambda node: '10.0.0.7'
    m._resolve_storage_path = lambda *a: '/var/lib/vz/template/iso'
    m.sync_content_to_nodes('pve1', 'local', 'debian.iso')
    piped = [''.join(entry[1]) for entry in log if entry[0] == 'stdin']
    cmds = [entry[1] for entry in log if entry[0] == 'cmd']
    return piped, cmds


def test_the_content_sync_does_not_pipe_the_token_secret_to_the_source_node():
    """sync_content_to_nodes feeds the password to `sshpass -e` ON the source node, for
    its scp to the target - the secret left this process for two machines."""
    piped, cmds = _sync(_manager(_token_cluster()))

    assert not any(TOKEN_SIDE in p for p in piped), 'the API token secret went to scp on the node'
    assert not any('sshpass' in c for c in cmds)
    assert cmds, 'no scp was tried at all'


def test_the_content_sync_still_uses_an_account_password():
    piped, cmds = _sync(_manager(_account_cluster()))

    assert any(ACCOUNT_SIDE in p for p in piped)
    assert any('sshpass -e' in c for c in cmds)


def test_the_migration_ssh_offers_nothing_when_there_is_no_password(monkeypatch):
    """core/xhm.py: the key is passed as a path it never is, so on a token cluster the
    migration went straight to keyboard-interactive and password auth with the secret.
    It gets '' from ssh_password_for now (test_the_rule) and must not send even that."""
    paramiko = pytest.importorskip('paramiko')
    from pegaprox.core import xhm
    tried = []

    class _Transport:
        def __init__(self, *a, **k):
            tried.append(('transport', a))

        def connect(self):
            raise paramiko.SSHException('stub')

        def close(self):
            pass

    class _SSHClient(paramiko.SSHClient):
        def connect(self, *a, **kw):
            tried.append(('connect', kw.get('password')))
            raise paramiko.AuthenticationException('stub')

    monkeypatch.setattr(paramiko, 'Transport', _Transport)
    monkeypatch.setattr(paramiko, 'SSHClient', _SSHClient)

    with pytest.raises(Exception):
        xhm._connect_ssh('10.0.0.7', 'root', '', key_path=KEY_TEXT)
    assert tried == [], f'something was offered to sshd: {tried}'

    with pytest.raises(paramiko.AuthenticationException):
        xhm._connect_ssh('10.0.0.7', 'root', ACCOUNT_SIDE, key_path=KEY_TEXT)
    assert ('connect', ACCOUNT_SIDE) in tried


# ------------------------------------------------------------------ the rule itself

@pytest.mark.parametrize('cfg,expected', [
    (_token_cluster(), ''),
    (_token_cluster(ssh_key=''), ''),
    (_account_cluster(), ACCOUNT_SIDE),
    (_account_cluster(ssh_key=''), ACCOUNT_SIDE),
    (_account_cluster(ssh_disabled=True), ''),
    (_cfg('root@pam', ''), ''),
], ids=['token+key', 'token', 'account+key', 'account', 'ssh-off', 'nothing-stored'])
def test_the_rule(cfg, expected):
    from pegaprox.utils.ssh import ssh_password_for
    assert ssh_password_for(cfg) == expected
    assert _manager(cfg).ssh_password_to_offer() == expected


def test_ssh_blocked_reason_still_answers_the_same():
    assert _manager(_token_cluster()).ssh_blocked_reason() is None        # the key counts
    assert _manager(_token_cluster(ssh_key='')).ssh_blocked_reason() == 'SSH_NO_CREDENTIALS'
    assert _manager(_account_cluster(ssh_key='')).ssh_blocked_reason() is None
    assert _manager(_account_cluster(ssh_disabled=True)).ssh_blocked_reason() == 'SSH_DISABLED'


# ------------------------------------------------------- the source, all of pegaprox/**
#
# A password step anywhere that is handed config.pass_ - directly, through a variable
# assigned from it (a walrus too), or through a function of ours that passes one of its
# parameters on to a step - is the bug again. Sinks: the password ladder helpers and the
# other SSH entry points by name, paramiko's positional password slot in connect(), a
# password=/ssh_password=/SSHPASS= keyword, ['password'] / ['SSHPASS'] slots, an SSHPASS
# dict entry, a command string that mentions sshpass, and .write() (the scp stdin of the
# content sync).

# where each SSH entry point takes its password: name -> (positions, keyword names).
# Positions leave out self, which is how the methods are called.
_PASSWORD_STEPS = {
    '_ssh_run_command_with_password': ({3}, {'password'}),
    '_ssh_run_command_with_password_output': ({3}, {'password'}),
    '_connect_ssh': ({2}, {'password'}),
    '_ssh_exec': ({2}, {'password'}),
    'get_pooled_transport': ({3}, {'password'}),
    'connect': ({3}, {'password'}),             # paramiko SSHClient.connect
    'auth_password': ({1}, {'password'}),
    'acquire': ({5}, {'ssh_password'}),         # vnc_tunnel
    '_get_or_create_client': ({5}, {'ssh_password'}),
}
_PASSWORD_KEYWORDS = {'password', 'ssh_password', 'SSHPASS'}
_PASSWORD_SLOTS = {'password', 'SSHPASS'}

# pass_ that is not a PVE cluster's: XenAPI logs in with a real account password, and the
# ESXi side of a migration carries the ESXi host's own password
_OTHER_HYPERVISOR_FILES = {'pegaprox/core/xcpng.py'}
_OTHER_HYPERVISOR_NAMES = {('pegaprox/core/xhm.py', 'esxi_pass')}


def _reads_pass(node):
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and n.attr == 'pass_':
            return True
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'getattr'
                and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)
                and n.args[1].value == 'pass_'):
            return True
    return False


def _names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _callee(call):
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, 'id', None)


def _scopes(tree):
    """Outermost functions - a closure shares its parent's names."""
    stack = list(tree.body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield n
        elif isinstance(n, ast.ClassDef):
            stack.extend(n.body)


def _says_sshpass(node):
    return any(isinstance(n, ast.Constant) and isinstance(n.value, str)
               and 'sshpass' in n.value.lower() for n in ast.walk(node))


def _fixed_sinks(n, writes=True):
    """What node n hands to sshd, apart from the password steps."""
    hits = []
    if isinstance(n, ast.Call):
        hits += [k.value for k in n.keywords if k.arg in _PASSWORD_KEYWORDS]
        name = _callee(n)
        if name == 'write' and writes:
            hits += list(n.args)
        elif name == 'format' and _says_sshpass(n.func):
            hits += list(n.args) + [k.value for k in n.keywords]
    elif isinstance(n, ast.Assign):
        for t in n.targets:
            if (isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                    and t.slice.value in _PASSWORD_SLOTS):
                hits.append(n.value)
    elif isinstance(n, ast.Dict):
        hits += [v for k, v in zip(n.keys, n.values)
                 if isinstance(k, ast.Constant) and k.value == 'SSHPASS']
    elif isinstance(n, (ast.JoinedStr, ast.BinOp)) and _says_sshpass(n):
        # f"SSHPASS={pw} sshpass -e ssh ..." run on a node, as v2p does for ESXi
        hits.append(n)
    return hits


def _step_sinks(call, steps):
    at, by_name = steps.get(_callee(call), ((), ()))
    return ([a for i, a in enumerate(call.args) if i in at]
            + [k.value for k in call.keywords if k.arg in by_name])


def _flows(scope):
    """Each assignment in scope: (reads pass_, names read, names written)."""
    out = []
    for n in ast.walk(scope):
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and n.value is not None:
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            out.append((_reads_pass(n.value), _names(n.value),
                        {x.id for t in targets for x in ast.walk(t) if isinstance(x, ast.Name)}))
    return out


def _tainted(flows, seed=(), from_pass=True, allowed=()):
    tainted = set(seed)
    changed = True
    while changed:
        changed = False
        for reads, names, written in flows:
            if (from_pass and reads) or names & tainted:
                new = written - set(allowed) - tainted
                if new:
                    tainted |= new
                    changed = True
    return tainted


def _password_params(trees):
    """The password steps plus our own functions that pass a parameter of theirs into
    one: name -> (positions, keyword names). A call to such a helper with config.pass_ in
    that place is the same leak one step removed."""
    steps = dict(_PASSWORD_STEPS)
    funcs = []
    for tree in trees:
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nodes = list(ast.walk(fn))
                fixed = [h for n in nodes for h in _fixed_sinks(n, writes=False)]
                calls = [n for n in nodes if isinstance(n, ast.Call)]
                funcs.append((fn, fixed, calls, None))
    for _ in range(4):
        grew = False
        for i, (fn, fixed, calls, flows) in enumerate(funcs):
            if fn.name in steps:
                continue
            sinks = fixed + [h for c in calls for h in _step_sinks(c, steps)]
            if not sinks:
                continue
            if flows is None:
                flows = _flows(fn)
                funcs[i] = (fn, fixed, calls, flows)
            pos = [p.arg for p in fn.args.posonlyargs + fn.args.args]
            if pos[:1] in (['self'], ['cls']):
                pos = pos[1:]
            at, by_name = set(), set()
            for j, p in enumerate(pos + [p.arg for p in fn.args.kwonlyargs]):
                reach = _tainted(flows, {p}, from_pass=False)
                if any(_names(h) & reach for h in sinks):
                    by_name.add(p)
                    if j < len(pos):
                        at.add(j)
            if by_name:
                steps[fn.name] = (at, by_name)
                grew = True
        if not grew:
            break
    return steps


def _leaks(src, rel, steps=None):
    if rel in _OTHER_HYPERVISOR_FILES:
        return []
    tree = src if isinstance(src, ast.AST) else ast.parse(src)
    if steps is None:
        steps = _password_params([tree])
    allowed = {name for f, name in _OTHER_HYPERVISOR_NAMES if f == rel}
    found = []
    for scope in _scopes(tree):
        tainted = _tainted(_flows(scope), allowed=allowed)
        for n in ast.walk(scope):
            hits = _fixed_sinks(n) + (_step_sinks(n, steps) if isinstance(n, ast.Call) else [])
            if any(_reads_pass(h) or _names(h) & tainted for h in hits):
                at = f'{rel}:{n.lineno} in {scope.name}()'
                if at not in found:
                    found.append(at)
    return found


def _package_files():
    base = os.path.join(ROOT, 'pegaprox')
    for d, _dirs, files in os.walk(base):
        for f in files:
            if f.endswith('.py'):
                path = os.path.join(d, f)
                yield os.path.relpath(path, ROOT).replace(os.sep, '/'), path


def test_no_ssh_password_step_in_pegaprox_is_handed_config_pass_():
    parsed = []
    for rel, path in _package_files():
        with open(path, encoding='utf-8') as fh:
            parsed.append((rel, ast.parse(fh.read())))
    # a helper in one module is called from another (utils/ssh.py from core/xhm.py)
    steps = _password_params([tree for _rel, tree in parsed])
    found = []
    for rel, tree in parsed:
        found += _leaks(tree, rel, steps)
    assert not found, ('config.pass_ reaches an SSH password step - on a token cluster that is '
                       'the API token secret. Use ssh_password_for(config) / '
                       f'ssh_password_to_offer(): {found}')


def test_the_source_check_sees_the_old_ladder():
    """Counterproof for the check above: the shape that shipped is caught, the fix is not."""
    old = (
        'class M:\n'
        '    def ladder(self, ip, cmd):\n'
        '        ssh_password = self.config.pass_\n'
        '        def go():\n'
        '            return self._ssh_run_command_with_password_output(ip, "root", cmd, ssh_password)\n'
        '        if self.config.pass_:\n'
        '            self._ssh_run_command_with_password(ip, "root", cmd, self.config.pass_)\n'
        '        kw = {}\n'
        '        kw["password"] = getattr(self.config, "pass_", "")\n'
        '        return go()\n'
    )
    assert len(_leaks(old, 'pegaprox/core/manager.py')) == 3
    fixed = old.replace('self.config.pass_', 'self.ssh_password_to_offer()') \
               .replace('getattr(self.config, "pass_", "")', 'self.ssh_password_to_offer()')
    assert _leaks(fixed, 'pegaprox/core/manager.py') == []


# shapes of the same leak that exist elsewhere in this codebase (v2p, ssh_pool, xhm)
_OTHER_SHAPES = {
    'paramiko_positional': (
        'def f(self, host):\n'
        '    c = paramiko.SSHClient()\n'
        '    c.connect(host, 22, "root", self.config.pass_)\n'),
    'ssh_pool_positional': (
        'def f(self, host):\n'
        '    return get_pooled_transport(host, 22, "root", self.config.pass_)\n'),
    'sshpass_command_on_a_node': (
        'def f(self, ssh, host):\n'
        '    safe = shlex.quote(self.config.pass_)\n'
        '    ssh.exec_command(f"SSHPASS={safe} sshpass -e ssh root@{host} true")\n'),
    'walrus': (
        'def f(self, ip):\n'
        '    if (pw := self.config.pass_):\n'
        '        self._ssh_run_command_with_password(ip, "root", "true", pw)\n'),
    'through_a_helper': (
        'class M:\n'
        '    def a(self, ip):\n'
        '        return self._go(ip, self.config.pass_)\n'
        '    def _go(self, ip, pw):\n'
        '        return self._ssh_run_command_with_password(ip, "root", "true", pw)\n'),
    'env_update_keyword': (
        'def f(self, ip):\n'
        '    env = dict(os.environ)\n'
        '    env.update(SSHPASS=self.config.pass_)\n'
        '    node_cmd(["sshpass", "-e", "ssh", ip, "true"], env=env)\n'),
}


@pytest.mark.parametrize('shape', sorted(_OTHER_SHAPES))
def test_the_source_check_sees_the_other_shapes(shape):
    src = _OTHER_SHAPES[shape]
    assert _leaks(src, 'pegaprox/core/manager.py'), f'{shape}: config.pass_ reaches sshd unseen'
    fixed = src.replace('self.config.pass_', 'self.ssh_password_to_offer()')
    assert _leaks(fixed, 'pegaprox/core/manager.py') == []


@pytest.mark.parametrize('step', ['_ssh_run_command_with_password',
                                  '_ssh_run_command_with_password_output'])
def test_a_password_step_refuses_the_token_secret_it_is_handed(wire, step):
    """The net under the source check: a future ladder that reaches for config.pass_ again
    on a token cluster gets refused by the step itself, before sshpass."""
    m = _manager(_token_cluster())
    getattr(m, step)('10.0.0.7', 'root', 'true', m.config.pass_)
    assert TOKEN_SIDE not in str(wire.sent)

    a = _manager(_account_cluster())
    getattr(a, step)('10.0.0.7', 'root', 'true', a.config.pass_)
    assert ACCOUNT_SIDE in wire.offered()


# ------------------------------------------- the cluster edit routes and the '!' marker

@pytest.mark.parametrize('verb,path', [('put', '/api/clusters/cluster_1'),
                                       ('patch', '/api/clusters/cluster_1/config')])
def test_the_cluster_edit_cannot_take_the_token_marker_away(api, seed, wire, verb, path):
    """The edit routes took 'user' but never 'pass'. {"user": "root@pam"} on a token cluster
    kept the token secret in pass_ with the '!' gone, and from then on - saved, so after a
    restart too - every ladder offered the secret to sshd. The user name is half of the
    credential; it changes together with the other half, through /reconfigure."""
    admin = seed.user('root', role='admin', tenant_id='default')
    m = _manager(_token_cluster())
    api.set_manager('cluster_1', m)

    r = getattr(api.as_user(admin), verb)(path, json={'user': 'root@pam', 'migration_threshold': 30})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['updated_fields'] == ['migration_threshold']   # the rest still lands
    assert m.config.user == 'root@pam!automation'
    handed = _spy_password_steps(m)
    m._ssh_node_output_ex('pve1', 'true')
    assert TOKEN_SIDE not in handed
    assert TOKEN_SIDE not in wire.offered()


def test_the_941_cluster_keeps_no_ssh_after_a_user_edit(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    m = _manager(_token_cluster(ssh_key=''))
    api.set_manager('cluster_1', m)

    r = api.as_user(admin).put('/api/clusters/cluster_1', json={'user': 'root@pam'})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert m.ssh_blocked_reason() == 'SSH_NO_CREDENTIALS'


# ------------------------------------- SSH switched off, and the paths with their own key

def _openssh_identity():
    """A key paramiko can load - the fake KEY_TEXT never gets as far as connect()."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()).decode()


@pytest.fixture
def logins(monkeypatch):
    """Every paramiko login attempt, refused - which of pkey/password it carried."""
    paramiko = pytest.importorskip('paramiko')
    tried = []

    def connect(self, *a, **kw):
        tried.append(sorted(k for k in kw if k in ('pkey', 'password')))
        raise paramiko.AuthenticationException('not in a test')

    monkeypatch.setattr(paramiko.SSHClient, 'connect', connect)
    return tried


def _rfb_manager(cfg):
    m = _manager(cfg)
    m.mint_console_auth_ticket = lambda with_csrf=False: ('PVE:ticket', 'csrf')
    vncproxy = types.SimpleNamespace(status_code=200,
                                     json=lambda: {'data': {'ticket': 'PVEVNC:x', 'port': '5900'}})
    m._create_session = lambda: types.SimpleNamespace(post=lambda *a, **k: vncproxy)
    return m


@pytest.mark.parametrize('ssh_off', [True, False], ids=['ssh-off', 'mirror'])
def test_the_console_tile_tunnel_stays_shut_with_ssh_off(monkeypatch, ssh_off):
    """vnc_tunnel=True and SSH switched off (#941): the tile screenshot opened its SSH
    tunnel with the stored key all the same, on every poll."""
    import websocket
    from pegaprox.api import vms
    from pegaprox.utils import vnc_tunnel
    asked = []

    def acquire(**kw):
        asked.append(kw['pve_host'])
        raise IOError('no tunnel in a test')

    def no_pve(*a, **k):
        raise IOError('no PVE in a test')

    monkeypatch.setattr(vnc_tunnel, 'acquire', acquire)
    monkeypatch.setattr(websocket, 'create_connection', no_pve)
    m = _rfb_manager(_account_cluster(ssh_key=_openssh_identity(), ssh_disabled=ssh_off,
                                      vnc_tunnel=True))
    with pytest.raises(IOError):
        vms._screenshot_via_rfb(m, 'pve1', 'qemu', 101)
    assert asked == ([] if ssh_off else ['10.0.0.1'])


def _own_nodes(fn):
    """The nodes of fn without those of the functions nested in it."""
    stack, out = list(fn.body), []
    while stack:
        n = stack.pop()
        out.append(n)
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(n))
    return out


def test_every_console_tunnel_asks_whether_ssh_may_go_out():
    """The tile screenshot, vnc_poll and the console websocket each read vnc_tunnel and
    went straight to the SSH tunnel. Only _vnc_tunnel_wanted reads the setting now."""
    with open(os.path.join(ROOT, 'pegaprox', 'api', 'vms.py'), encoding='utf-8') as fh:
        tree = ast.parse(fh.read())
    readers, openers = set(), set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in _own_nodes(fn):
            if (isinstance(n, ast.Call) and _callee(n) == 'getattr' and len(n.args) >= 2
                    and isinstance(n.args[1], ast.Constant) and n.args[1].value == 'vnc_tunnel'):
                readers.add(fn.name)
            if (isinstance(n, ast.Attribute) and n.attr == 'acquire'
                    and isinstance(n.value, ast.Name) and n.value.id == '_vt'):
                openers.add(fn.name)
    assert readers == {'_vnc_tunnel_wanted'}
    assert openers == {'_screenshot_via_rfb', 'vnc_poll', 'vnc_handler'}


def test_the_tunnel_pool_opens_no_socket_without_anything_to_log_in_with(logins):
    from pegaprox.utils import vnc_tunnel
    with pytest.raises(Exception):
        vnc_tunnel.SshVncTunnelPool()._get_or_create_client('c1', '10.0.0.7', 'root', 22, '', '')
    assert logins == []


def _membership_manager(cfg):
    m = _manager(cfg)
    m.nodes_in_maintenance = {}
    nodes = types.SimpleNamespace(status_code=200, json=lambda: {'data': [
        {'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}]})
    m._create_session = lambda: types.SimpleNamespace(get=lambda url, timeout=10: nodes)
    return m


@pytest.mark.parametrize('ssh_off', [True, False], ids=['ssh-off', 'mirror'])
def test_removing_a_node_does_not_log_in_with_ssh_off(api, seed, logins, ssh_off):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _membership_manager(
        _account_cluster(ssh_key=_openssh_identity(), ssh_disabled=ssh_off)))

    r = api.as_user(admin).delete('/api/clusters/cluster_1/nodes/pve2/cluster-membership',
                                  json={'confirm': True})

    if ssh_off:
        assert r.status_code == 409, r.get_data(as_text=True)
        assert r.get_json()['code'] == 'SSH_DISABLED'
        assert logins == []
    else:
        assert logins and logins[0] == ['pkey']


@pytest.mark.parametrize('ssh_off', [True, False], ids=['ssh-off', 'mirror'])
def test_the_deep_storage_rescan_does_not_log_in_with_ssh_off(api, seed, logins, monkeypatch,
                                                              ssh_off):
    import threading
    from pegaprox import globals as _g
    import pegaprox.api.storage as storage_api
    admin = seed.user('root', role='admin', tenant_id='default')
    m = _manager(_account_cluster(ssh_key=_openssh_identity(), ssh_disabled=ssh_off))

    def get(url, **k):
        if url.endswith('/storage/lvm1'):
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': {
                'type': 'lvm', 'vgname': 'vg1'}})
        if url.endswith('/nodes'):
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': [
                {'node': 'pve1', 'status': 'online'}]})
        return types.SimpleNamespace(status_code=200, json=lambda: {'data': {}})
    m._create_session = lambda: types.SimpleNamespace(get=get)
    api.set_manager('cluster_1', m)
    monkeypatch.setattr(storage_api, 'get_connected_manager', lambda cid: (m, None))
    monkeypatch.setattr(_g, '_ssh_semaphore', threading.BoundedSemaphore(4))

    r = api.as_user(admin).post('/api/clusters/cluster_1/datacenter/storage/lvm1/rescan',
                                json={'deep_scan': True})

    assert r.status_code == 200, r.get_data(as_text=True)
    actions = r.get_json()['results'][0]['actions']
    if ssh_off:
        assert logins == []
        assert {'action': 'deep_scan', 'status': 'skipped', 'code': 'SSH_DISABLED'}.items() \
            <= actions[0].items()
        assert any(a['action'] == 'lvm_scan_api' for a in actions)   # the API rescan still ran
    else:
        assert logins == [['pkey']]
