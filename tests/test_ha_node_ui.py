"""The node side of HA in the web UI: slice S6 of #625.

The HA settings of a cluster (dashboard.js) show which self-fence agent each node runs
and check them, the switch for unsafe two-node recovery and what the safety rules do,
the fence of each node, and the cluster claim. Switching HA off shows what the server
says was left behind, and the HA page of the cloud layout gets one line each for an
outdated agent and for unsafe two-node recovery.

As in test_ha_ui.py: source checks so the wiring cannot drift apart quietly, the
translations (t() falls back to English, so a missing key reads as English), the static
Tailwind build, and runtime tests that drive the built bundle in headless Chromium. Their
fake server is
the one of test_ha_ui.py with the cluster HA routes on top, answering the way
pegaprox/api/clusters.py does. A server from before S6 sends none of the new keys:
the settings then look the way they did.
LW
"""
import json
import re
import time

import pytest

from test_ha_ui import (BASE, CLUSTER, LANGS, NODE_METRICS, PASSWORD, _App, _FakeServer, _block,  # noqa: F401
                        _blocks, _classes, _function, _read, _toasts, browser)

NODES = ('pve1', 'pve2')
HA_CLUSTER = dict(CLUSTER, ha_enabled=True)
METRICS = {n: dict(NODE_METRICS['pve1']) for n in NODES}
OWN = 'a' * 32
OTHER = 'c' * 32
MEMBERS = ['https://pegaprox-a.example:5000', 'https://pegaprox-b.example:5000']

# the server's own words, as pegaprox/core/manager.py and pegaprox/api/clusters.py send them
UNSAFE_WARNING = ('Unsafe two-node recovery is on: when a node fails, quorum is forced on the other one '
                  'without proof that the failed node is off. In a network split both nodes can then run the '
                  'same VM. Configure IPMI fencing for the nodes and switch this off.')
OUTDATED = ('The self-fence agent on {nodes} is version 1: it pings one PegaProx address and does not go by '
            'the quorum of the cluster. It keeps running as it is. Install the self-fence agent again from the '
            'HA settings to replace it with version {version}.')
OUTDATED_SETTINGS = ('A change of the PegaProx VM ID or of the two-node settings does not reach the version 1 '
                     'agent on {nodes}: it keeps the settings it was installed with until the self-fence agent '
                     'is installed again from the HA settings.')
SURVIVOR_NOTE = ('Under the safety rules a node that loses quorum stops its own guests: when it is the last node '
                 'left, PegaProx brings back the guests of the failed nodes after a verified fence, and the last '
                 "node's own guests stay stopped until an admin starts them. The 'unsafe two-node recovery' switch "
                 'keeps the old behaviour (the leader decides, the survivor keeps its guests) at the old risk.')
CLAIM_WARNING = ('With the cluster claim on, PegaProx writes the file /etc/pve/pegaprox/claim into the cluster '
                 'file system of this cluster (and takes the lock directory /etc/pve/priv/lock/pegaprox-claim '
                 'while it does). The file names the PegaProx instance that acts on the cluster. Node recovery '
                 "then runs only while the claim is this instance's, and its SSH steps are refused at the node "
                 'otherwise.')
CLAIM_RESIDUAL = ('The cluster claim is off: an SSH step that a former leader had already sent when it froze is '
                  'not refused at the node.')
CLAIM_BY_HAND = (f'read -r e i _ < /etc/pve/pegaprox/claim && [ "$i" = {OWN} ] && [ "$e" -le 2 ] 2>/dev/null '
                 '&& rm -f /etc/pve/pegaprox/claim && rmdir /etc/pve/pegaprox')
CLAIM_NOT_REMOVED = ('The cluster claim could not be removed (no node of the cluster answered): '
                     '/etc/pve/pegaprox/claim may still be there. To remove it by hand, run on one node of the '
                     f'cluster, which has to be quorate for it: `{CLAIM_BY_HAND}`')
AGENTS_BY_HAND = ('systemctl disable --now pegaprox-fence-agent.service pegaprox-agent.service; '
                  'rm -f /usr/local/bin/pegaprox-fence-agent.sh /usr/local/bin/pegaprox-agent.sh '
                  '/etc/systemd/system/pegaprox-fence-agent.service /etc/systemd/system/pegaprox-agent.service; '
                  'systemctl daemon-reload')
AGENTS_LEFT = (f'Not listed by the cluster, agents may still run on: pve2. SSH to those nodes and run '
               f'`{AGENTS_BY_HAND}`')
FENCE_TYPES = ('ipmi', 'ssh', 'proxmox')
IPMI_PVE1 = {'pve1': {'type': 'ipmi', 'host': '10.0.0.101', 'user': 'ADMIN', 'password': 'bmc-secret'}}


def _iso_ago(sec):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - sec))


def _agent(version, current=True, active=True, mode='tiebreak', away=()):
    """One node in the answer of the agent check (_parse_agent_check plus current/outdated)."""
    return {'fence_agent': {'version': version, 'mode': mode if version != 1 else 'v1', 'active': active,
                            'sha256': 'f' * 64 if version else '', 'legacy_shared_name': version == 1,
                            'current': current, 'outdated': 0 < version < 2},
            'node_agent': {'installed': False, 'active': False},
            'members_unreachable': list(away)}


CHECK = {'nodes': {'pve1': _agent(2), 'pve2': _agent(1, current=False, away=[MEMBERS[1]]), 'pve3': None},
         'expected_version': 2, 'mode': 'tiebreak', 'strategy': 'quorum', 'members': MEMBERS}


class _NodeHaServer(_FakeServer):
    """The fake of test_ha_ui.py, an active instance with one HA cluster, plus the cluster
    HA routes: the status, ha/config, the agent check, the claim, disable and the install.

    old: a server from before S6, its status carries none of the new keys.
    keep_masked_unsafe: one that keeps the unsafe switch stored while nothing forces quorum.
    """

    def __init__(self, old=False, two_node=True, unsafe=False, fencing=None, versions=None,
                 installed=NODES, minority=False, claim=None, claim_write='ours', claim_removal='removed',
                 check=None, check_refusal=None, config_refusal=None, disable=None, ha_enabled=True,
                 fence_types=None, keep_masked_unsafe=False, **kw):
        kw.setdefault('role', 'active')
        kw.setdefault('clusters', [dict(HA_CLUSTER, ha_enabled=ha_enabled)])
        kw.setdefault('metrics', METRICS)
        super().__init__(**kw)
        self.old = old
        self.ha_enabled = ha_enabled
        self.two_node = two_node
        self.unsafe = unsafe
        # {node: {type, host, user, password}} as stored, BMC password included
        self.fencing = {n: dict(f) for n, f in (fencing or {}).items()}
        self.fence_types = fence_types
        self.versions = dict(versions or {})
        self.installed = list(installed)
        self.minority = minority
        # {enabled, state, instance, epoch, checked_at}
        self.claim = dict(claim or {'enabled': False})
        self.claim_write = claim_write
        self.claim_removal = claim_removal
        self.check = check
        self.check_refusal = check_refusal
        self.config_refusal = config_refusal
        self.disable = disable
        # a server from before the switch was dropped with forced quorum: it keeps it underneath
        self.keep_masked_unsafe = keep_masked_unsafe
        self.installs = 0

    # -- what GET .../ha/status says ----------------------------------------------------------

    def fencing_status(self):
        return {n: {'type': f['type'], 'host': f.get('host', ''), 'user': f.get('user', ''),
                    'password_set': bool(f.get('password')),
                    'verifiable': f['type'] == 'ipmi' and bool(f.get('host')) and bool(f.get('password'))}
                for n, f in sorted(self.fencing.items())}

    def claim_status(self):
        on = self.claim.get('enabled') is True
        return {'enabled': on, 'path': '/etc/pve/pegaprox/claim',
                'state': (self.claim.get('state') or 'unknown') if on else 'off',
                'epoch': self.claim.get('epoch') if on else None,
                'instance': self.claim.get('instance') if on else None,
                'checked_at': self.claim.get('checked_at') if on else None,
                'warning': CLAIM_WARNING, 'residual': None if on else CLAIM_RESIDUAL}

    def ha_status(self):
        sbp = {'quorum_enabled': True, 'have_quorum': True, 'last_quorum_check': None, 'self_fence_enabled': True,
               'watchdog_enabled': False, 'recovery_delay': 30, 'quorum_hosts': [], 'quorum_gateway': '',
               'quorum_required_votes': 2, 'verify_network': True, 'two_node_mode': self.two_node,
               'force_quorum_on_failure': self.two_node, 'storage_heartbeat_enabled': False,
               'storage_heartbeat_path': '', 'storage_heartbeat_timeout': 30, 'poison_pill_enabled': True,
               'strict_fencing': False, 'last_heartbeat_write': None, 'pegaprox_vmid': '',
               'fence_strategy': {'strategy': 'quorum', 'reason': 'two votes and two_node', 'expected_votes': 2,
                                  'has_qdevice': False, 'detected_at': None, 'detection_reason': 'detected'},
               'fence_strategy_warning': None}
        status = {'enabled': self.ha_enabled, 'check_interval': 10, 'failure_threshold': 3,
                  'nodes': {n: {'status': 'online', 'last_seen': None, 'consecutive_failures': 0} for n in NODES},
                  'recovery_in_progress': [], 'fallback_hosts': [], 'split_brain_prevention': sbp,
                  'cluster_health': {'online_nodes': 2, 'total_nodes': 2, 'is_2_node_cluster': True,
                                     'status': 'healthy'},
                  'discovered_storages': [], 'block_storages': [], 'auto_protection_active': False,
                  'self_fence_installed': bool(self.installed), 'self_fence_nodes': list(self.installed)}
        if self.old:
            return status
        unsafe = self.unsafe and self.two_node
        fencing = self.fencing_status()
        sbp.update({
            'unsafe_two_node_recovery': unsafe,
            'unsafe_two_node_warning': UNSAFE_WARNING if unsafe else None,
            'verified_fence_required': self.two_node and not unsafe,
            'fenced_survivor_note': SURVIVOR_NOTE if self.two_node and self.minority and not unsafe else None,
            'verified_fence_configured': any(f['verifiable'] for f in fencing.values()),
            'fencing': fencing,
        })
        if self.fence_types:
            sbp['fence_types'] = list(self.fence_types)
        outdated = sorted(n for n, v in self.versions.items() if 0 < v < 2)
        status['fence_agent'] = {
            'expected_version': 2, 'versions': dict(self.versions),
            'nodes': {n: {'version': v, 'outdated': n in outdated, 'earliest_recovery': 60 if v == 2 else 50}
                      for n, v in sorted(self.versions.items())},
            'outdated': outdated,
            'outdated_warning': OUTDATED.format(nodes=', '.join(outdated), version=2) if outdated else None,
            'outdated_settings_warning': OUTDATED_SETTINGS.format(nodes=', '.join(outdated)) if outdated else None,
            'unchecked': sorted(set(self.installed) - set(self.versions)),
            'fence_delay': 30,
        }
        status['cluster_claim'] = self.claim_status()
        return status

    # -- the routes, in the order of their checks in pegaprox/api/clusters.py --------------------

    def config(self, data):
        if self.config_refusal:
            return self.config_refusal
        was_on = self.unsafe is True and (self.two_node or self.keep_masked_unsafe)
        if (data.get('unsafe_two_node_recovery') is True and not was_on
                and data.get('confirm_unsafe_two_node') != 'UNSAFE'):
            return 400, {'error': 'Type UNSAFE to confirm: with this on, quorum is forced on the surviving node '
                                  'without proof that the failed node is off, and both can run the same VM in a '
                                  'network split', 'code': 'HA_UNSAFE_CONFIRM'}
        fencing = None
        if 'fencing' in data:
            fencing = {n: dict(f) for n, f in self.fencing.items()}
            for node, entry in data['fencing'].items():
                if entry is None or not entry.get('type'):
                    fencing.pop(node, None)
                    continue
                kind = entry['type']
                if kind not in FENCE_TYPES:
                    return 400, {'error': f'fencing: {node}: type must be one of ipmi, ssh, proxmox',
                                 'code': 'HA_FENCING_INVALID'}
                stored = fencing.get(node) or {}
                fence = {'type': kind}
                for key in ('host', 'user'):
                    if entry.get(key):
                        fence[key] = entry[key]
                password = entry.get('password') or (stored.get('password') if stored.get('type') == kind else None)
                if password:
                    fence['password'] = password
                if kind == 'ipmi' and not (fence.get('host') and fence.get('password')):
                    return 400, {'error': f'fencing: {node}: an IPMI fence needs the host and the password of '
                                          'the BMC', 'code': 'HA_FENCING_INVALID'}
                fencing[node] = fence
        for key in ('recovery_delay', 'failure_threshold'):
            if key in data and (not isinstance(data[key], (int, float)) or isinstance(data[key], bool)):
                return 400, {'error': f'{key} must be a number, zero or more', 'code': 'HA_TIMING_INVALID'}
        forced_before = self.two_node
        if 'two_node_mode' in data:
            self.two_node = bool(data['two_node_mode'])
        if 'unsafe_two_node_recovery' in data:
            self.unsafe = data['unsafe_two_node_recovery'] is True
        # without forced quorum the stored switch goes off, and forcing quorum anew is a new
        # setup: unsafe only when the request switches it on itself (update_ha_config)
        if not self.keep_masked_unsafe and (not self.two_node or (
                not forced_before and data.get('unsafe_two_node_recovery') is not True)):
            self.unsafe = False
        if fencing is not None:
            self.fencing = fencing
        return 200, {'message': 'HA-Konfiguration gespeichert', 'status': self.ha_status()}

    def agent_check(self):
        if self.check_refusal:
            return self.check_refusal
        report = json.loads(json.dumps(self.check))
        nodes = report['nodes']
        # what it found is what the status reports from now on; a silent node keeps its version
        for node, info in nodes.items():
            if info and info['fence_agent']['version']:
                self.versions[node] = info['fence_agent']['version']
            elif info:
                self.versions.pop(node, None)
        report['unreachable'] = sorted(n for n, i in nodes.items() if i is None)
        report['outdated'] = sorted(n for n, i in nodes.items() if i and 0 < i['fence_agent']['version'] < 2)
        report['outdated_warning'] = (OUTDATED.format(nodes=', '.join(report['outdated']), version=2)
                                      if report['outdated'] else None)
        report['not_current'] = sorted(n for n, i in nodes.items()
                                       if i and i['fence_agent']['version'] == 2 and not i['fence_agent']['current'])
        return 200, report

    def claim_route(self, body):
        action = body.get('action')
        if action not in ('enable', 'disable', 'release'):
            return 400, {'error': 'action must be enable, disable or release'}
        phrase = {'enable': 'WRITE CLAIM', 'release': 'RELEASE CLAIM'}.get(action)
        if phrase and body.get('confirm') != phrase:
            return 400, {'error': f'Type {phrase} to confirm', 'code': 'HA_CLAIM_CONFIRM', 'warning': CLAIM_WARNING}
        if action == 'release' and self.claim.get('enabled') is not True:
            return 409, {'error': 'The cluster claim is off for this cluster'}
        if self.auth_source in ('oidc', 'entra'):
            if self.sso_stale:
                return 403, {'error': 'Sign in again, then retry within 10 minutes', 'code': 'HA_REAUTH_RECENT'}
        elif body.get('user_password') != PASSWORD:
            return 403, {'error': 'The password is not correct', 'code': 'HA_REAUTH'}
        if action == 'disable':
            state = self.claim_removal
            warning = by_hand = None
            if state not in ('removed', 'absent'):
                warning, by_hand = CLAIM_NOT_REMOVED, CLAIM_BY_HAND
            self.claim = {'enabled': False}
            return 200, {'claim': self.claim_status(), 'removed': state, 'warning': warning, 'by_hand': by_hand}
        if action == 'enable':
            self.claim = {'enabled': True, 'state': self.claim_write, 'epoch': 2 if self.claim_write == 'ours' else 5,
                          'instance': OWN if self.claim_write == 'ours' else OTHER, 'checked_at': _iso_ago(1)}
            return 200, {'claim': self.claim_status()}
        if self.claim.get('state') == 'ours':
            return 409, {'error': "The claim is this instance's already", 'claim': self.claim_status()}
        self.claim = {'enabled': True, 'state': 'ours', 'epoch': 2, 'instance': OWN, 'checked_at': _iso_ago(1)}
        return 200, {'claim': self.claim_status()}

    def ha_route(self, method, sub, body):
        if method == 'GET' and sub in ('', '/status'):
            return 200, self.ha_status()
        if method == 'PUT' and sub == '/config':
            return self.config(body)
        if method == 'POST' and sub == '/agent-check':
            return self.agent_check()
        if method == 'POST' and sub == '/claim':
            return self.claim_route(body)
        if method == 'POST' and sub == '/install-self-fence':
            self.installs += 1
            return 200, {'message': 'Self-fence agent installation started', 'status': 'installing'}
        if method == 'POST' and sub == '/disable':
            self.ha_enabled = False
            self.clusters = [dict(c, ha_enabled=False) for c in self.clusters]
            return 200, dict({'message': 'HA disabled', 'agents_uninstalled': 2, 'agents_total': 2,
                              'agents_failed': [], 'agents_unconfirmed': [], 'claim': None,
                              'storage_cleanup': None, 'status': self.ha_status(), 'warning': None},
                             **(self.disable or {}))
        if method == 'POST' and sub == '/enable':
            self.ha_enabled = True
            return 200, {'message': 'High Availability aktiviert', 'status': self.ha_status()}
        return 404, {'error': 'not mocked'}

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/clusters/c1/ha(/[a-z-]+)?', path)
        if not req.url.startswith(BASE) or not m:
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        self.bodies.setdefault(path, []).append(body)
        status, data = self.ha_route(req.method, m.group(1) or '', body)
        return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})


# -- source ------------------------------------------------------------------------------------

@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def cloud():
    return _read('web', 'src', 'cloud.js')


@pytest.fixture(scope='module')
def node_ui(dash):
    """Everything the node HA parts are made of, from their header to the dashboard."""
    start = dash.index('// Node HA in the HA settings of a cluster (#625)')
    return dash[start:dash.index('function PegaProxDashboard(', start)]


@pytest.fixture(scope='module')
def modal(dash):
    """The HA settings of a cluster, the modal the dashboard renders."""
    start = dash.index('{/* HA Split-Brain Prevention Settings Modal */}')
    return dash[start:dash.index('{/* Sponsor footer.', start)]


@pytest.fixture(scope='module')
def notes(cloud):
    """CloudHaNodeNotes with its comment, and nothing of what follows it."""
    start = cloud.index('// LW Oct 2026 (#625) - the HA page of this layout')
    return cloud[start:cloud.index('\n        }\n', cloud.index('function CloudHaNodeNotes(', start)) + 11]


PARTS = ('HaNodeWarnings', 'HaNodeAgents', 'HaNodeSafety', 'HaNodeFencing', 'HaNodeClaim', 'HaNodeDisableReport',
         'HaNodeText', 'HaNodeCommand', 'haNodeSend', 'haNodeClaimKind')


def test_the_parts_exist(node_ui):
    for name in PARTS:
        assert node_ui.count(f'function {name}(') == 1, name


def test_each_part_stays_away_without_its_key(node_ui):
    """A server from before S6 sends none of it: nothing of these renders then."""
    stays_away = {
        'HaNodeWarnings': ("const unsafe = sbp.unsafe_two_node_recovery === true;",
                           "sbp.verified_fence_required === true && sbp.verified_fence_configured === false",
                           "if (!unsafe && !noFence) return null;"),
        'HaNodeAgents': ("if (!fa || typeof fa !== 'object') return null;",),
        'HaNodeSafety': ("const known = typeof sbp.unsafe_two_node_recovery === 'boolean';",
                         "if (!known && !sbp.fenced_survivor_note) return null;"),
        'HaNodeFencing': ("if (!stored || typeof stored !== 'object') return null;",),
        'HaNodeClaim': ("if (!claim || typeof claim !== 'object') return null;",),
    }
    for name, needles in stays_away.items():
        body = _function(node_ui, name)
        for needle in needles:
            assert needle in body, (name, needle)


def test_the_modal_mounts_every_part_where_it_belongs(modal):
    # wide enough for the tables, and only when one of the parts renders: a status from before
    # them keeps the width the modal had
    assert ('data-ha-cluster-settings className={`bg-proxmox-card border border-proxmox-border rounded-xl w-full '
            "${haNodePartsShown(haStatus) ? 'max-w-3xl' : 'max-w-xl'} max-h-[85vh] overflow-hidden`}") in modal
    warnings = modal.index('<HaNodeWarnings status={haStatus} t={t} />')
    strategy = modal.index('const fs = haStatus?.split_brain_prevention?.fence_strategy;')
    self_fence = modal.index("{t('selfFenceProtection')}")
    install = modal.index('onClick={installSelfFence}')
    agents = modal.index('<HaNodeAgents t={t} clusterId={selectedCluster.id} status={haStatus}')
    two_node = modal.index('{/* 2-Node Cluster Mode */}')
    safety = modal.index('<HaNodeSafety t={t} clusterId={selectedCluster.id} status={haStatus}')
    basic = modal.index('{/* Basic Settings */}')
    advanced_end = modal.index('</details>')
    fencing = modal.index('<HaNodeFencing t={t} clusterId={selectedCluster.id} status={haStatus}')
    claim = modal.index('<HaNodeClaim t={t} clusterId={selectedCluster.id} status={haStatus}')
    footer = modal.index('{/* Footer */}')
    assert warnings < strategy < self_fence < install < agents < two_node < safety < basic < advanced_end
    assert advanced_end < fencing < claim < footer
    # on a standby that does not forward, and for an account without ha.config, what would be
    # refused is disabled; the claim is for admins and says so itself
    for part in ('HaNodeAgents', 'HaNodeSafety', 'HaNodeFencing'):
        mount = modal[modal.index(f'<{part} '):]
        assert 'locked={haReadOnly || !haWrite} />' in mount[:mount.index('/>') + 2], part
    mount = modal[modal.index('<HaNodeClaim '):]
    assert 'locked={haReadOnly} />' in mount[:mount.index('/>') + 2]
    # the fence table knows the nodes of the cluster even before a fence is set
    assert 'nodeNames={Object.keys(clusterMetrics || {})}' in modal
    assert '{haDisableReport && (' in modal
    assert '<HaNodeDisableReport report={haDisableReport} onClose={() => setHaDisableReport(null)} t={t} />' in modal


def test_the_install_button_is_the_way_to_upgrade(dash, modal):
    # one install route in the whole dashboard: the button calls the shared handler
    assert dash.count('/ha/install-self-fence`') == 1
    handler = dash[dash.index('const installSelfFence = async () => {'):]
    handler = handler[:handler.index('\n            };')]
    assert 'setHaAgentCheck(null);' in handler
    # a refused install says so; it said nothing before
    assert "addToast(await PegaProxApiErrors.message(res, t('operationFailed')), 'error');" in handler
    button = modal[modal.index('const upgrade = Array.isArray(fa?.outdated) && fa.outdated.length > 0;'):]
    button = button[:button.index('})()}')]
    # offered only to who may install: the route wants ha.config
    assert "if (!haWrite || (haStatus?.self_fence_installed && !upgrade && !repair)) return null;" in button
    assert ".some(n => n && n.fence_agent && !n.fence_agent.current);" in button
    assert "upgrade ? t('haNodeUpgradeAgent').replace('{version}', () => fa.expected_version || 2)" in button
    assert ": repair && haStatus?.self_fence_installed ? t('haNodeInstallAgain')" in button
    assert ": t('installSelfFenceAgent')}" in button


def test_the_agent_check_asks_the_route_and_reloads_the_status(node_ui, dash):
    body = _function(node_ui, 'HaNodeAgents')
    assert "haNodeSend(authFetch, `${API_URL}/clusters/${clusterId}/ha/agent-check`, 'POST', {}," in body
    run = body[body.index('const runCheck = async () => {'):body.index('const agentOf = ')]
    assert (run.index('if (!res.ok) { setError(res.error); return; }') < run.index('onCheck(res.data);')
            < run.index('onReload();'))
    # the reload keeps what the admin typed into the form above: fetchHAStatus would reset it
    reload = dash[dash.index('const reloadHaStatus = async () => {'):]
    reload = reload[:reload.index('\n            };')]
    # and it updates only a status that was loaded: the settings may have been reopened
    assert 'setHaStatus(s => s ? data : s)' in reload and 'setHaSettings' not in reload
    assert 'selectedClusterRef.current?.id === id' in reload
    # an earlier agent is marked at its row; the server's words say what that means
    assert "agent.kind === 'earlier' && (" in body
    assert '{outdatedText && <p>{outdatedText}</p>}' in body
    assert '{fa.outdated_settings_warning && <p>{fa.outdated_settings_warning}</p>}' in body
    assert "t('haNodeFenceDelay').replace('{n}', fa.fence_delay)" in body


def test_unsafe_recovery_goes_on_only_with_the_word(node_ui):
    assert "const HA_NODE_UNSAFE_WORD = 'UNSAFE';" in node_ui
    body = _function(node_ui, 'HaNodeSafety')
    assert ("const body = on ? { unsafe_two_node_recovery: true, confirm_unsafe_two_node: typed }\n"
            "                    : { unsafe_two_node_recovery: false };") in body
    assert ("haNodeSend(authFetch, `${API_URL}/clusters/${clusterId}/ha/config`, 'PUT', body, "
            "t('operationFailed'))") in body
    assert 'disabled={typed !== HA_NODE_UNSAFE_WORD || busy || locked}' in body
    # off at once, on through the box with the risk in it
    assert 'if (unsafe) { save(false); return; }' in body
    assert "t('haNodeUnsafeRisk')" in body
    # nothing to switch where quorum is not forced
    assert 'disabled={busy || locked || (!unsafe && !forces)}' in body
    assert 'const forces = !!(sbp.two_node_mode || sbp.force_quorum_on_failure);' in body
    assert '{sbp.fenced_survivor_note}' in body


def test_the_fence_form_sends_what_changed_and_never_shows_a_password(node_ui):
    assert "const HA_NODE_FENCE_TYPES = ['ipmi', 'ssh', 'proxmox'];" in node_ui
    body = _function(node_ui, 'HaNodeFencing')
    assert ('const types = Array.isArray(sbp.fence_types) && sbp.fence_types.length ? sbp.fence_types '
            ': HA_NODE_FENCE_TYPES;') in body
    # the stored row starts with an empty password, whatever the status says
    assert "return { type: f.type || '', host: f.host || '', user: f.user || '', password: '' };" in body
    assert "...(row.password ? { password: row.password } : {})," in body
    assert '} : null;' in body
    assert ("haNodeSend(authFetch, `${API_URL}/clusters/${clusterId}/ha/config`, 'PUT', { fencing }, "
            "t('operationFailed'))") in body
    # the refusal names the node: shown at its row
    assert "res.code === 'HA_FENCING_INVALID'" in body
    assert "setRowError({ node, error: why.slice(node.length + 2) });" in body
    field = body[body.index('<input type="password"'):]
    field = field[:field.index('/>')]
    for attr in ('autoComplete="new-password"', 'data-lpignore="true"', 'data-1p-ignore="true"',
                 'data-bwignore="true"', "placeholder={keeps ? t('haNodeFenceUnchanged') : ''}",
                 'value={row.password}'):
        assert attr in field, attr
    assert 'const keeps = !!was?.password_set && row.type === was.type;' in body
    assert 'disabled={!changed.length || busy || locked}' in body
    # a typed BMC password goes with the request: after a refusal the rows keep the rest
    request = body[body.index('const save = async () => {'):body.index('if (!res.ok) {')]
    assert request.index('} finally {') < request.index(
        "setDraft(d => Object.fromEntries(Object.entries(d).map(([n, row]) => [n, { ...row, password: '' }])));")


def test_the_settings_of_one_cluster_never_show_another(dash):
    """They opened with what the last cluster's status said, and an answer for a cluster that
    was no longer selected filled them: the next click wrote that into the other cluster."""
    fetch = dash[dash.index('const fetchHAStatus = async (clusterId) => {'):]
    fetch = fetch[:fetch.index('\n            };')]
    assert (fetch.index('if (selectedClusterRef.current?.id !== clusterId) return;') < fetch.index('setHaStatus(data);')
            < fetch.index('setHaSettings({'))
    # the form starts from the defaults, not from the last cluster's values
    assert ('onClick={() => { setShowHaSettings(true); setHaAgentCheck(null); setHaStatus(null); '
            'setHaStatusError(null); setHaSettings(haSettingsDefaults); fetchHAStatus(selectedCluster.id); }}') in dash
    assert 'const [haSettings, setHaSettings] = useState(haSettingsDefaults);' in dash


def test_the_form_shows_once_the_status_of_this_cluster_is_here(dash, modal):
    """Until then the form held the last cluster's values, and Save wrote them to this one; a
    status that could not be read left them there for good."""
    fetch = _block(dash, 'const fetchHAStatus = async (clusterId) => {', '\n            };')
    assert "if (selectedClusterRef.current?.id === clusterId) setHaStatusError({ text });" in fetch
    assert fetch.index('setHaStatus(data);') < fetch.index('setHaStatusError(null);')
    assert "failed(await PegaProxApiErrors.message(response, ''));" in fetch
    assert "console.error('fetching HA status:', err);\n                    failed('');" in fetch
    body = modal[modal.index("<div className=\"p-4 overflow-y-auto\""):modal.index('{/* Footer */}')]
    pending = body[body.index('{!haStatus ? ('):body.index(') : (<>')]
    assert pending.index('haStatusError ? (') < pending.index("{t('haSettingsLoadFailed')}") \
        < pending.index('{haStatusError.text && ') < pending.index("{t('loading')}")
    assert 'data-ha-settings-error' in pending and 'data-ha-settings-loading' in pending
    # every part of the form comes after it, none before
    assert body.index(') : (<>') < body.index('<HaNodeWarnings status={haStatus} t={t} />')
    assert body.rstrip().endswith('</>)}\n                                </div>')
    save = _block(dash, 'const handleSaveHASettings = async () => {', '\n            };')
    assert 'if (!selectedCluster || !haStatus || !haWrite || haReadOnly) return;' in save
    footer = modal[modal.index('{/* Footer */}'):]
    assert 'onClick={handleSaveHASettings}\n' \
           '                                        disabled={!haStatus || !haWrite || haReadOnly}' in footer


def test_a_late_answer_of_a_part_fills_only_its_own_cluster(dash, modal):
    """A part asked for c1 and the answer came once c2 was selected: it filled c2's settings."""
    body = _function(dash, 'PegaProxDashboard')
    assert 'const haFor = (id, set) => (v) => { if (selectedClusterRef.current?.id === id) set(v); };' in body
    # a status answer only updates a status that was loaded (the settings may be reopening)
    assert "const haStatusFor = (id) => haFor(id, (v) => setHaStatus(s => s ? (typeof v === 'function' ? v(s) : v) : s));" in body
    for part, prop in (('HaNodeAgents', 'onCheck={haFor(selectedCluster.id, setHaAgentCheck)}'),
                       ('HaNodeSafety', 'onStatus={haStatusFor(selectedCluster.id)}'),
                       ('HaNodeFencing', 'onStatus={haStatusFor(selectedCluster.id)}'),
                       ('HaNodeClaim', 'onStatus={haStatusFor(selectedCluster.id)}')):
        mount = modal[modal.index(f'<{part} '):]
        assert prop in mount[:mount.index('/>')], part
    assert 'onStatus={setHaStatus}' not in modal and 'onCheck={setHaAgentCheck}' not in modal


def test_ha_view_alone_gets_no_live_form(modal):
    """The node parts were locked for ha.view alone; the form around them, its Save and the
    uninstall of the agents were not."""
    sets = modal.count('setHaSettings({...haSettings')
    assert sets == 8
    assert modal.count('<fieldset disabled={!haWrite || haReadOnly} className="min-w-0">') == 3
    # every field of the form sits in one of them
    inside = ''.join(_block(modal[at:], '<fieldset', '</fieldset>')
                     for at in [m.start() for m in re.finditer('<fieldset ', modal)])
    assert inside.count('setHaSettings({...haSettings') == sets
    # the node parts stay outside: their copy buttons are for everyone
    assert '<HaNode' not in inside
    uninstall = re.search(r"\{haWrite && \(\n( +)<button\n(.*?)\n\1</button>\n +\)\}", modal, re.S)
    assert uninstall and '/ha/uninstall-self-fence`' in uninstall.group(2) and "{t('uninstall')}" in uninstall.group(2)
    assert modal.count('/ha/uninstall-self-fence`') == 1


def test_who_may_write_is_asked_like_everywhere_else(dash):
    main = _function(dash, 'PegaProxDashboard')
    assert "const haWrite = can('ha.config');" in main
    assert main.index('const can = (permission) =>') < main.index("const haWrite = can('ha.config');")


def test_the_form_saves_an_unsafe_switch_that_reads_off_as_off(dash):
    """Stored on under a 2-node mode that was off, the status says off; saving 2-node mode
    made it live without the typed word. The server drops it too (test_ha_node_safety.py)."""
    save = dash[dash.index('const handleSaveHASettings = async () => {'):]
    save = save[:save.index('\n            };')]
    assert ("...(haStatus?.split_brain_prevention?.unsafe_two_node_recovery === false\n"
            "                                ? { unsafe_two_node_recovery: false } : {}),") in save
    # never on from the form: that is the switch with its word
    assert 'unsafe_two_node_recovery: true' not in save and 'confirm_unsafe_two_node' not in save


def test_the_modal_widens_only_for_the_parts(node_ui):
    shown = _function(node_ui, 'haNodePartsShown')
    # each part's own first check
    for needle in ("typeof sbp.unsafe_two_node_recovery === 'boolean'", '!!sbp.fenced_survivor_note',
                   'sbp.verified_fence_required === true && sbp.verified_fence_configured === false',
                   'isObj(status?.fence_agent)', 'isObj(sbp.fencing)', 'isObj(status?.cluster_claim)'):
        assert needle in shown, needle


def test_the_claim_wants_password_and_words(node_ui):
    assert "const HA_NODE_CLAIM_WORD = { enable: 'WRITE CLAIM', release: 'RELEASE CLAIM' };" in node_ui
    assert "const HA_NODE_CLAIM_FOREIGN = ['higher', 'same', 'unreadable'];" in node_ui
    body = _function(node_ui, 'HaNodeClaim')
    assert "const sso = ['oidc', 'entra'].includes(user?.auth_source);" in body
    assert 'const ready = !!action && (sso || !!password) && (!word || typed === word);' in body
    assert ("const body = { action: what, ...(word ? { confirm: typed } : {}), "
            "...(sso ? {} : { user_password: password }) };") in body
    assert ("haNodeSend(authFetch, `${API_URL}/clusters/${clusterId}/ha/claim`, 'POST', body, "
            "t('operationFailed'))") in body
    assert 'disabled={!ready || busy || locked}' in body
    # the route is for admins
    assert 'disabled={busy || locked || !isAdmin}' in body
    assert '{foreign && isAdmin && !action && (' in body
    # the password goes with every request, refused or not; a stale SSO sign-in can sign in again
    request = body[body.index('const send = async () => {'):body.index('const now = res.data')]
    assert request.index('} finally {') < request.index("setPassword('');")
    assert "setPassword('');" not in body[body.index('if (!res.ok) {'):body.index('open(null);\n')]
    assert "refused.code === 'HA_REAUTH_RECENT'" in body and 'onClick={() => logout()}' in body
    # the server's texts: what the claim does, what is missing while it is off, what was left
    for needle in ('{claim.warning && ', '{claim.residual && (', '<HaNodeText text={answer.warning} t={t} />',
                   '<HaNodeCommand value={answer.by_hand} t={t} />'):
        assert needle in body, needle


def test_a_command_in_server_text_gets_a_copy_button(node_ui):
    text = _function(node_ui, 'HaNodeText')
    assert "const parts = String(text || '').split('`');" in text
    assert 'if (parts.length % 2 === 0) return <div className={className}>{text}</div>;' in text
    assert 'i % 2 ? <HaNodeCommand key={i} value={part.trim()} t={t} />' in text
    command = _function(node_ui, 'HaNodeCommand')
    assert '<CopyButton value={value} size="md" title={t(\'copy\')}' in command


def test_ha_disable_shows_what_was_left(dash):
    toggle = dash[dash.index('const handleHAToggle = async (enable) => {'):]
    toggle = toggle[:toggle.index('\n            };')]
    assert 'const done = enable ? null : await response.json().catch(() => null);' in toggle
    assert toggle.index('if (done && done.warning) setHaDisableReport({ ...done, cluster: selectedCluster.name });') \
        < toggle.index("else addToast(enable ? t('haEnabled') : t('haDisabled'));")
    report = _function(dash, 'HaNodeDisableReport')
    assert 'role="alertdialog"' in report
    assert '<HaNodeText text={report.warning} t={t} className="text-sm text-gray-200" />' in report
    for needle in ("t('haNodeDisableFailed')", "t('haNodeDisableUnconfirmed')"):
        assert needle in report


def test_the_cloud_ha_page_gets_its_lines(cloud, notes):
    shell = _function(cloud, 'CloudShell')
    case = shell[shell.index("case 'ha':"):]
    case = case[:case.index('break;')]
    assert ('<CloudHaNodeNotes clusterId={cid} t={t} authFetch={authFetch} /><ProxmoxHaSection clusterId={cid} />'
            in case)
    assert 'authFetch(`${API_URL}/clusters/${clusterId}/ha/status`)' in notes
    assert 'if (!ha || !ha.enabled) return null;' in notes
    assert 'const unsafe = sbp.unsafe_two_node_recovery === true;' in notes
    assert 'const outdated = Array.isArray(fa.outdated) ? fa.outdated : [];' in notes
    # and the guests an interrupted recovery left, which this layout can only name
    assert 'if (!outdated.length && !unsafe && !left.length) return null;' in notes
    assert "t('haNodeUnsafeSwitch')" in notes and "t('haNodeCloudOutdated')" in notes
    assert "t('haNodeIrTitle')" in notes and "t('haNodeIrCloudHint')" in notes


# -- translations --------------------------------------------------------------------------------

def _used_keys():
    src = _read('web', 'src', 'dashboard.js') + _read('web', 'src', 'cloud.js')
    return sorted(set(re.findall(r"'(haNode[A-Z]\w*)'", src)))


# keys of other features the node HA parts use as well
REUSED = ('yes', 'no', 'node', 'type', 'host', 'user', 'password', 'copy', 'close', 'cancel', 'enabled',
          'operationFailed', 'installSelfFenceAgent', 'selfFenceInstalling', 'error', 'haEnabled', 'haDisabled',
          'pgHaTypeToConfirm', 'pgHaPassword', 'pgHaSignInAgain')
# the same word in English and the language, or a number
SAME_AS_EN = {'haNodeColAgent', 'haNodeColMode', 'haNodeSeconds', 'haNodeAgentCurrent', 'haNodeClaimStandby',
              'haNodeFencingTitle'}


def test_the_parts_use_their_own_keys():
    keys = _used_keys()
    assert len(keys) >= 80, len(keys)
    # none of them is a key of something else
    other = re.findall(r'^ +(ha[A-Z]\w*): ', _read('web', 'src', 'translations.js'), re.M)
    assert not {k for k in other if not k.startswith('haNode')} & set(keys)


@pytest.mark.parametrize('lang', LANGS)
def test_every_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'
    for key in REUSED:
        assert re.search(r'^ +%s: ' % key, block, re.M), (lang, key)


def test_no_key_is_defined_that_nothing_uses():
    used = set(_used_keys())
    for lang, block in _blocks().items():
        defined = set(re.findall(r'^ +(haNode\w+): ', block, re.M))
        assert defined == used, (lang, sorted(defined ^ used))


@pytest.mark.parametrize('lang', LANGS)
def test_the_keys_are_one_block_at_the_end_of_the_language(lang):
    """Another change adds keys next to the HA keys that are there: these stay apart."""
    block = _blocks()[lang]
    body = block[:block.index('\n            },')]
    lines = [line for line in body.splitlines() if line.strip()]
    n = len(_used_keys())
    assert all(re.match(r'^ {16}haNode\w+: \'.*\',$', line) for line in lines[-n:]), lang
    assert lines[-n - 1].strip().startswith('// node HA'), lines[-n - 1]
    assert not any('haNode' in line for line in lines[:-n - 1]), lang


def _value(block, key):
    return re.search(r"^ +%s: '(.*)',$" % key, block, re.M).group(1)


def test_placeholders_survive_and_the_words_are_translated():
    blocks = _blocks()
    for key in _used_keys():
        en = _value(blocks['en'], key)
        for lang, block in blocks.items():
            value = _value(block, key)
            assert value.strip(), (lang, key)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)
            if lang != 'en' and key not in SAME_AS_EN:
                assert value != en, f'{lang}.{key} is the English text'


# the HA keys: the instance group, the node parts and the copies, the Proxmox HA strings, and
# what the split-brain dialog and the HA section of the cluster settings show
HA_KEY = re.compile(r'^(?:pgHa|ha[A-Z]|highAvailability|selfFence|splitBrain|twoNode|enable2NodeMode|enableTwoNode|'
                    r'fenceStrategy|proxmoxNativeHa|pegaproxVmRecovery|installSelfFence|confirmUninstallAgent|'
                    r'fallback|noFallbackHosts)\w*$')


@pytest.mark.parametrize('lang', LANGS)
def test_no_ha_key_is_defined_twice_in_a_language(lang):
    """The last definition wins: in de a later one put the English 'High Availability (HA)'
    over the translated one."""
    keys = [k for k in re.findall(r'^ +(\w+): ', _blocks()[lang], re.M) if HA_KEY.match(k)]
    assert len(keys) > 300, len(keys)
    twice = sorted({k for k in keys if keys.count(k) > 1})
    assert not twice, (lang, twice)
    assert _value(_blocks()['de'], 'highAvailability') == 'Hochverfügbarkeit (HA)'


def test_the_split_brain_dialog_says_what_the_agent_does_now(modal):
    """It described the first agent (a node that reaches the manager or another node stays up,
    two-node mode forces quorum when a node fails). Now: quorum first; with two votes or forced
    quorum the instances are asked who leads; nothing a fence stopped starts again; forced
    quorum only after a fence that was read back, unless unsafe two-node recovery is on."""
    assert "{t('selfFenceExplain')}" in modal and "{t('twoNodeModeDesc')}" in modal
    blocks = _blocks()
    en_explain, en_two = _value(blocks['en'], 'selfFenceExplain'), _value(blocks['en'], 'twoNodeModeDesc')
    for needle in ('Quorum decides first', 'three or more votes (a QDevice counts)', 'loses quorum stops its own VMs',
                   'Where quorum cannot decide (two votes, or quorum gets forced)',
                   'asks the PegaProx instances who leads', 'when no leader answers',
                   'on two nodes without a QDevice (fence strategy WAIT) it only logs this and keeps them running',
                   'not started again on that node automatically, the PegaProx VM aside'):
        assert needle in en_explain, needle
    for needle in ('only after the failed node was powered off and read back as off', 'Fencing per node',
                   'unless unsafe two-node recovery is on'):
        assert needle in en_two, needle
    for lang, block in blocks.items():
        explain, two = _value(block, 'selfFenceExplain'), _value(block, 'twoNodeModeDesc')
        # the old words, and the arrows that stood for 'then' (up arrow, right arrow)
        assert chr(0x2191) not in explain and chr(0x2192) not in explain, lang
        assert 'manager' not in explain.lower(), lang
        # the same names the node parts give them in this language
        assert _value(block, 'haNodeColInstances').lower() in explain.lower(), lang
        assert _value(block, 'haNodeUnsafeSwitch').lower() in two.lower(), lang
        assert _value(block, 'haNodeFencingTitle').lower() in two.lower(), lang
        assert chr(0x2014) not in explain + two, lang
        if lang != 'en':
            assert explain != en_explain and two != en_two, lang
        # the agent of a two-node cluster without a QDevice keeps the VMs running, under the
        # name the strategy banner shows; the fence delay says so too
        assert 'QDevice' in explain and 'WAIT' in explain, lang
        assert 'WAIT' in _value(block, 'haNodeFenceDelay'), lang


def test_what_the_dialog_says_is_what_the_agent_does():
    """Each clause of selfFenceExplain against pegaprox/core/manager.py, so a change of the
    agent cannot leave the text behind."""
    src = _read('pegaprox', 'core', 'manager.py')
    # a QDevice counts as a vote, and three of them make the strategy quorum; two votes without
    # one make it wait
    assert 'expected = max(expected, len(listed) + (1 if has_qdevice else 0))' in src
    detect = _block(src, 'if expected >= 3 or has_qdevice:', 'self._ha_persist_fence_strategy(decision, \'detection-skipped')
    assert detect.index("decision['strategy'] = 'quorum'") < detect.index("decision['strategy'] = 'wait'")
    script = _block(src, "_SELF_FENCE_AGENT_SCRIPT = r'''", "\n'''\n")
    check = _block(script, 'check() {', '\n}\n')
    # quorum: not quorate is enough; tiebreak: no majority asks the leader, no answer fences
    assert check.index('quorum)') < check.index('WHY="not quorate"') < check.index('tiebreak)')
    assert check.index('if leader_answers; then') < check.index('and no PegaProx leader answers"')
    fence = _block(script, 'self_fence() {', '\n}\n')
    # WAIT logs and returns before anything is stopped
    wait = fence.index('if [ "$FENCE_STRATEGY" = "wait" ]; then')
    assert wait < fence.index('Keeping VMs running') < fence.index('return') < fence.index('stop_all_vms')
    # nothing it stopped is started again from here; the PegaProx VM by watch_pegaprox
    assert 'qm start' not in fence and 'pct start' not in fence
    watch = _block(script, 'watch_pegaprox() {', '\n}\n')
    assert 'try_restart_pegaprox_vm' in watch
    assert 'qm start $PEGAPROX_VMID' in _block(script, 'try_restart_pegaprox_vm() {', '\n}\n')


def test_no_em_dash_in_anything_new(node_ui, modal, notes):
    new_lines = [line for block in _blocks().values() for line in block.splitlines() if 'haNode' in line]
    # older comments in the modal have their own; the lines of the node parts do not
    new_lines += [line for line in modal.splitlines() if re.search(r'HaNode|haNode|data-ha-node|haAgentCheck', line)]
    for text in [node_ui, notes] + new_lines:
        assert '\u2014' not in text, text[:200]


def test_the_austrian_flag_stays():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9', label: 'DE'" in _read('web', 'src', 'contexts.js')


# -- styling, icons, bundle --------------------------------------------------------------------

def test_every_class_is_in_the_static_tailwind_build(node_ui, modal, notes):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(node_ui) | _classes(modal) | _classes(notes)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists(node_ui, notes):
    icons = _read('web', 'src', 'icons.js')
    used = set(re.findall(r'Icons\.(\w+)', node_ui + notes))
    assert used
    for name in used:
        assert re.search(r'^ {12}%s: ' % name, icons, re.M), name


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for name in PARTS + ('CloudHaNodeNotes', 'reloadHaStatus', 'installSelfFence', 'data-ha-cluster-settings'):
        assert name in bundle, name
    for key in _used_keys():
        assert key in bundle, key


# -- runtime: the built bundle in a real browser -------------------------------------------------

@pytest.fixture
def open_node_app(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _NodeHaServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _open_ha_settings(app, settings='Settings', button='Split-Brain Prevention', wait='[data-ha-node-safety]'):
    """The cluster, its Settings tab, the HA settings. Waits for the part that shows the
    status arrived (an old server: for the request)."""
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name=settings, exact=True).first.click()
    page.get_by_role('button', name=re.compile(button)).click()
    modal = page.locator('[data-ha-cluster-settings]')
    modal.wait_for(timeout=5000)
    if wait:
        modal.locator(wait).first.wait_for(timeout=5000)
    else:
        _wait_for(page, lambda: ('GET', '/api/clusters/c1/ha/status') in app.server.calls)
        page.wait_for_timeout(500)
    return modal


def _wait_for(page, fn, seconds=5):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if fn():
            return True
        page.wait_for_timeout(100)
    return fn()


def _wait_for_toast(page, text, seconds=5):
    return _wait_for(page, lambda: any(text in t for t in _toasts(page)), seconds)


def _puts(app):
    return app.server.bodies.get('/api/clusters/c1/ha/config', [])


def _no_raw_keys(modal):
    text = modal.inner_text()
    assert 'haNode' not in text and 'pgHa' not in text, text


def test_runtime_agents_per_node_check_and_upgrade(open_node_app):
    app = open_node_app(versions={'pve1': 2, 'pve2': 1}, check=CHECK)
    page = app.page
    modal = _open_ha_settings(app)
    agents = modal.locator('[data-ha-node-agents]')
    pve1, pve2 = agents.locator('[data-ha-node-agent="pve1"]'), agents.locator('[data-ha-node-agent="pve2"]')
    assert pve1.get_attribute('data-ha-node-agent-kind') == 'current'
    assert 'Version 2' in pve1.inner_text() and '60 s' in pve1.inner_text()
    assert pve2.get_attribute('data-ha-node-agent-kind') == 'earlier'
    assert 'Earlier agent (version 1)' in pve2.inner_text() and '50 s' in pve2.inner_text()
    assert pve2.locator('[data-ha-node-outdated]').inner_text() == 'Outdated'
    assert pve1.locator('[data-ha-node-outdated]').count() == 0
    # the server's words on what the earlier agent does and does not get
    warning = agents.locator('[data-ha-node-outdated-warning]').inner_text()
    assert OUTDATED.format(nodes='pve2', version=2) in warning
    assert OUTDATED_SETTINGS.format(nodes='pve2') in warning
    assert 'Fence delay: 30 s.' in agents.locator('[data-ha-node-fence-delay]').inner_text()
    # installed, but an earlier agent runs: the install button is back, and says what it does
    install = modal.locator('[data-ha-node-install]')
    assert install.get_attribute('data-ha-node-install') == 'upgrade'
    assert install.inner_text().strip().endswith('Upgrade the self-fence agent to version 2')
    assert _follows(page, '[data-ha-node-install]', '[data-ha-node-agents]')

    # the check reads the nodes: what runs, and which instances a node cannot reach
    reads = app.server.calls.count(('GET', '/api/clusters/c1/ha/status'))
    agents.get_by_role('button', name='Check agents').click()
    agents.locator('[data-ha-node-silent]').wait_for(timeout=5000)
    assert app.server.calls.count(('POST', '/api/clusters/c1/ha/agent-check')) == 1
    head = agents.locator('thead').inner_text()
    for column in ('Running', 'Mode', 'Current script', 'PegaProx instances'):
        assert column in head, column
    row1 = pve1.inner_text()
    assert 'tiebreak' in row1 and 'Yes' in row1 and 'Reaches all' in row1, row1
    row2 = pve2.inner_text()
    assert 'v1' in row2 and 'No' in row2 and '1 of 2 out of reach' in row2, row2
    assert MEMBERS[1] in agents.locator('[data-ha-node-cannot-reach="pve2"]').inner_text()
    assert agents.locator('[data-ha-node-cannot-reach="pve1"]').count() == 0
    assert 'Did not answer' in agents.locator('[data-ha-node-agent="pve3"]').inner_text()
    assert 'Did not answer the check: pve3' in agents.inner_text()
    # what it found is the status from now on
    assert _wait_for(page, lambda: app.server.calls.count(('GET', '/api/clusters/c1/ha/status')) > reads)

    install.click()
    assert _wait_for_toast(page, 'Installing agent')
    assert app.server.installs == 1
    # the check is out of date once the agents are replaced
    _wait_for(page, lambda: agents.locator('[data-ha-node-silent]').count() == 0)
    assert 'Running' not in agents.locator('thead').inner_text()
    _no_raw_keys(modal)
    assert not app.errors, app.errors


def test_runtime_a_refused_check_says_why_and_unchecked_nodes_ask_for_one(open_node_app):
    app = open_node_app(versions={}, check_refusal=(502, {'error': 'The cluster did not list its nodes'}))
    modal = _open_ha_settings(app)
    agents = modal.locator('[data-ha-node-agents]')
    for node in NODES:
        row = agents.locator(f'[data-ha-node-agent="{node}"]')
        assert row.get_attribute('data-ha-node-agent-kind') == 'unchecked'
        assert 'Installed, not checked yet' in row.inner_text()
    assert 'Check the agents to see which one each node runs.' in agents.inner_text()
    # installed and nothing known to be outdated: no install button, as before
    assert modal.locator('[data-ha-node-install]').count() == 0
    agents.get_by_role('button', name='Check agents').click()
    error = agents.locator('[data-ha-node-check-error]')
    error.wait_for(timeout=5000)
    assert error.inner_text() == 'The cluster did not list its nodes'
    assert agents.locator('[data-ha-node-silent]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_check_that_finds_a_stale_script_offers_the_install_again(open_node_app):
    check = {'nodes': {'pve1': _agent(2), 'pve2': _agent(2, current=False)}, 'expected_version': 2,
             'mode': 'quorum', 'strategy': 'quorum', 'members': []}
    app = open_node_app(versions={'pve1': 2, 'pve2': 2}, check=check)
    modal = _open_ha_settings(app)
    assert modal.locator('[data-ha-node-install]').count() == 0
    agents = modal.locator('[data-ha-node-agents]')
    agents.get_by_role('button', name='Check agents').click()
    install = modal.locator('[data-ha-node-install]')
    install.wait_for(timeout=5000)
    assert install.get_attribute('data-ha-node-install') == 'again'
    assert install.inner_text().strip().endswith('Install the self-fence agent again')
    assert ('The agent on pve2 is not the script this instance would install now. Install the self-fence agent '
            'again to replace it.') in agents.inner_text()
    # quorum mode asks no instance: nothing to reach
    assert agents.locator('[data-ha-node-agent="pve1"] [data-ha-node-unreachable="0"]').inner_text() == '-'
    assert not app.errors, app.errors


def _follows(page, first, second):
    return page.evaluate('([a, b]) => !!(document.querySelector(a).compareDocumentPosition('
                         'document.querySelector(b)) & Node.DOCUMENT_POSITION_FOLLOWING)', [first, second])


def test_runtime_unsafe_recovery_is_a_banner_and_switches_off_at_once(open_node_app):
    app = open_node_app(unsafe=True, minority=True)
    page = app.page
    modal = _open_ha_settings(app)
    banner = modal.locator('[data-ha-node-unsafe]')
    assert banner.is_visible()
    assert banner.get_attribute('role') == 'alert'
    assert 'Unsafe two-node recovery is on' in banner.inner_text()
    assert UNSAFE_WARNING in banner.inner_text()
    # the first thing in the settings
    assert _follows(page, '[data-ha-node-unsafe]', '[data-ha-node-agents]')
    assert _follows(page, '[data-ha-node-unsafe]', '[data-ha-node-safety]')
    # not required while unsafe: no word on a missing fence, no survivor note
    assert modal.locator('[data-ha-node-no-fence]').count() == 0
    assert modal.locator('[data-ha-node-survivor]').count() == 0

    switch = page.get_by_role('switch', name='Unsafe two-node recovery')
    assert switch.get_attribute('aria-checked') == 'true'
    switch.click()
    _wait_for(page, lambda: switch.get_attribute('aria-checked') == 'false')
    # off needs no word
    assert _puts(app) == [{'unsafe_two_node_recovery': False}]
    assert modal.locator('[data-ha-node-unsafe-confirm]').count() == 0
    assert _wait_for_toast(page, 'Unsafe two-node recovery switched off')
    assert modal.locator('[data-ha-node-unsafe]').count() == 0
    # now the rules hold, and nothing can be read back yet
    no_fence = modal.locator('[data-ha-node-no-fence]')
    assert no_fence.is_visible()
    assert 'Not recovered automatically' in no_fence.inner_text()
    assert 'until an IPMI fence is set under Fencing per node' in no_fence.inner_text()
    assert modal.locator('[data-ha-node-survivor]').inner_text().strip() == SURVIVOR_NOTE
    _no_raw_keys(modal)
    assert not app.errors, app.errors


def test_runtime_unsafe_recovery_goes_on_only_with_the_word_typed(open_node_app):
    app = open_node_app(unsafe=False)
    page = app.page
    modal = _open_ha_settings(app)
    assert modal.locator('[data-ha-node-unsafe]').count() == 0
    assert modal.locator('[data-ha-node-no-fence]').is_visible()
    switch = page.get_by_role('switch', name='Unsafe two-node recovery')
    assert switch.get_attribute('aria-checked') == 'false'
    switch.click()
    box = modal.locator('[data-ha-node-unsafe-confirm]')
    box.wait_for(timeout=3000)
    assert 'In a network split both nodes can then run the same VM and write to the same disks.' in box.inner_text()
    assert 'Type UNSAFE to confirm' in box.inner_text()
    on = box.get_by_role('button', name='Switch on')
    assert on.is_disabled()
    for wrong in ('unsafe', 'UNSAF', 'UNSAFE '):
        page.fill('#ha-node-unsafe-typed', wrong)
        assert on.is_disabled(), wrong
    assert _puts(app) == []
    page.fill('#ha-node-unsafe-typed', 'UNSAFE')
    assert on.is_enabled()
    on.click()
    modal.locator('[data-ha-node-unsafe]').wait_for(timeout=5000)
    assert _puts(app) == [{'unsafe_two_node_recovery': True, 'confirm_unsafe_two_node': 'UNSAFE'}]
    assert switch.get_attribute('aria-checked') == 'true'
    assert box.count() == 0
    assert modal.locator('[data-ha-node-no-fence]').count() == 0
    assert _wait_for_toast(page, 'Unsafe two-node recovery switched on')
    assert not app.errors, app.errors


def test_runtime_a_refused_switch_shows_the_server_words(open_node_app):
    app = open_node_app(unsafe=False, config_refusal=(403, {'error': 'Permission denied: ha.config required'}))
    page = app.page
    modal = _open_ha_settings(app)
    page.get_by_role('switch', name='Unsafe two-node recovery').click()
    page.fill('#ha-node-unsafe-typed', 'UNSAFE')
    modal.locator('[data-ha-node-unsafe-confirm]').get_by_role('button', name='Switch on').click()
    error = modal.locator('[data-ha-node-unsafe-error]')
    error.wait_for(timeout=5000)
    assert error.inner_text() == 'Permission denied: ha.config required'
    # the box stays for another try, the switch where it was
    assert modal.locator('[data-ha-node-unsafe-confirm]').count() == 1
    assert page.get_by_role('switch', name='Unsafe two-node recovery').get_attribute('aria-checked') == 'false'
    assert modal.locator('[data-ha-node-unsafe]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_switch_waits_for_forced_quorum(open_node_app):
    app = open_node_app(two_node=False, unsafe=True)
    modal = _open_ha_settings(app)
    switch = app.page.get_by_role('switch', name='Unsafe two-node recovery')
    # stored on, but meaningless without forced quorum: the status says off, nothing warns
    assert switch.get_attribute('aria-checked') == 'false'
    assert switch.is_disabled()
    idle = modal.locator('[data-ha-node-unsafe-idle]').inner_text()
    assert 'Enable the 2-node cluster mode and save it first.' in idle
    for part in ('[data-ha-node-unsafe]', '[data-ha-node-no-fence]', '[data-ha-node-survivor]'):
        assert modal.locator(part).count() == 0, part
    assert not app.errors, app.errors


def test_runtime_fencing_per_node(open_node_app):
    app = open_node_app(fencing=IPMI_PVE1)
    page = app.page
    modal = _open_ha_settings(app)
    table = modal.locator('[data-ha-node-fencing]')
    save = table.get_by_role('button', name='Save fencing')
    assert save.is_disabled()
    # a stored fence: its values, the password never; it can be read back
    assert page.locator('select[aria-label="Type pve1"]').input_value() == 'ipmi'
    assert page.input_value('input[aria-label="Host pve1"]') == '10.0.0.101'
    assert page.input_value('input[aria-label="User pve1"]') == 'ADMIN'
    pw1 = page.locator('input[aria-label="Password pve1"]')
    assert pw1.input_value() == '' and pw1.get_attribute('type') == 'password'
    assert pw1.get_attribute('placeholder') == 'unchanged'
    assert 'bmc-secret' not in page.content()
    assert table.locator('[data-ha-node-fence="pve1"] [data-ha-node-verifiable]').inner_text() == 'Read back'
    # a node without one: every field but the type waits for it
    assert page.locator('select[aria-label="Type pve2"]').input_value() == ''
    assert page.locator('input[aria-label="Host pve2"]').is_disabled()
    options = page.eval_on_selector_all('select[aria-label="Type pve2"] option', 'os => os.map(o => o.value)')
    assert options == ['', 'ipmi', 'ssh', 'proxmox']

    # IPMI without the BMC password: refused, and the refusal sits at its row
    page.select_option('select[aria-label="Type pve2"]', 'ipmi')
    assert page.locator('input[aria-label="Password pve2"]').get_attribute('placeholder') == ''
    page.fill('input[aria-label="Host pve2"]', '10.0.0.102')
    save.click()
    error = table.locator('[data-ha-node-fence-error="pve2"]')
    error.wait_for(timeout=5000)
    assert error.inner_text() == 'an IPMI fence needs the host and the password of the BMC'
    # only the row that changed went out
    assert _puts(app) == [{'fencing': {'pve2': {'type': 'ipmi', 'host': '10.0.0.102', 'user': ''}}}]
    assert app.server.fencing == IPMI_PVE1

    page.fill('input[aria-label="Password pve2"]', 'other-secret')
    assert error.count() == 0, 'the error goes once the row is edited'
    save.click()
    assert _wait_for_toast(page, 'Fencing saved')
    assert _puts(app)[-1] == {'fencing': {'pve2': {'type': 'ipmi', 'host': '10.0.0.102', 'user': '',
                                                   'password': 'other-secret'}}}
    assert app.server.fencing['pve2'] == {'type': 'ipmi', 'host': '10.0.0.102', 'password': 'other-secret'}
    # saved: the field is empty again, the password kept
    pw2 = page.locator('input[aria-label="Password pve2"]')
    _wait_for(page, lambda: pw2.get_attribute('placeholder') == 'unchanged')
    assert pw2.input_value() == ''
    assert save.is_disabled()

    # another type does not keep the stored password: the field says nothing then
    page.select_option('select[aria-label="Type pve1"]', 'ssh')
    assert pw1.get_attribute('placeholder') == ''
    # no fence takes it away
    page.select_option('select[aria-label="Type pve1"]', '')
    save.click()
    assert _wait_for(page, lambda: 'pve1' not in app.server.fencing)
    assert _puts(app)[-1] == {'fencing': {'pve1': None}}
    _wait_for(page, lambda: table.locator('[data-ha-node-fence="pve1"] [data-ha-node-verifiable]').count() == 0)
    # no request ever carried a password nobody typed
    assert all('bmc-secret' not in json.dumps(b) for b in _puts(app))
    _no_raw_keys(modal)
    assert not app.errors, app.errors


def test_runtime_the_fence_types_come_from_the_server_when_it_names_them(open_node_app):
    app = open_node_app(fence_types=('ipmi', 'redfish'))
    _open_ha_settings(app)
    options = app.page.eval_on_selector_all('select[aria-label="Type pve1"] option', 'os => os.map(o => o.value)')
    assert options == ['', 'ipmi', 'redfish']
    assert not app.errors, app.errors


def test_runtime_the_claim_goes_on_with_password_and_words(open_node_app):
    app = open_node_app()
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    card = modal.locator('[data-ha-node-claim]')
    assert card.get_attribute('data-ha-node-claim') == 'off'
    assert card.locator('[data-ha-node-claim-state]').inner_text() == 'Off'
    assert CLAIM_WARNING in card.inner_text()
    assert card.locator('[data-ha-node-claim-residual]').inner_text() == CLAIM_RESIDUAL
    switch = page.get_by_role('switch', name='Cluster claim')
    assert switch.get_attribute('aria-checked') == 'false'
    switch.click()
    form = card.locator('[data-ha-node-claim-form="enable"]')
    form.wait_for(timeout=3000)
    write = form.get_by_role('button', name='Write the claim')
    assert write.is_disabled()
    page.fill('#ha-node-claim-password', 'wrong password')
    assert write.is_disabled(), 'the words are missing'
    page.fill('#ha-node-claim-typed', 'write claim')
    assert write.is_disabled()
    page.fill('#ha-node-claim-typed', 'WRITE CLAIM')
    assert write.is_enabled()
    # a wrong password: refused at the form, the field emptied for the next try
    write.click()
    refused = form.locator('[data-ha-node-claim-refused="HA_REAUTH"]')
    refused.wait_for(timeout=5000)
    assert 'The password is not correct' in refused.inner_text()
    assert page.input_value('#ha-node-claim-password') == ''
    assert page.input_value('#ha-node-claim-typed') == 'WRITE CLAIM'
    assert write.is_disabled()
    assert switch.get_attribute('aria-checked') == 'false'

    page.fill('#ha-node-claim-password', PASSWORD)
    write.click()
    _wait_for(page, lambda: switch.get_attribute('aria-checked') == 'true')
    assert app.server.bodies['/api/clusters/c1/ha/claim'][-1] == {'action': 'enable', 'confirm': 'WRITE CLAIM',
                                                                  'user_password': PASSWORD}
    assert card.locator('[data-ha-node-claim-state]').inner_text() == 'This instance'
    assert card.locator('[data-ha-node-claim-means]').inner_text() == 'The cluster carries the claim of this instance.'
    assert 'Instance aaaaaaaa, epoch 2' in card.inner_text()
    assert 'Last read ' in card.inner_text()
    assert card.locator('[data-ha-node-claim-residual]').count() == 0
    assert card.locator('[data-ha-node-claim-form]').count() == 0
    assert _wait_for_toast(page, 'Cluster claim switched on')
    _no_raw_keys(modal)
    assert not app.errors, app.errors


def test_runtime_a_claim_written_over_a_foreign_one_says_so(open_node_app):
    app = open_node_app(claim_write='higher')
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    page.get_by_role('switch', name='Cluster claim').click()
    page.fill('#ha-node-claim-password', PASSWORD)
    page.fill('#ha-node-claim-typed', 'WRITE CLAIM')
    modal.get_by_role('button', name='Write the claim').click()
    card = modal.locator('[data-ha-node-claim]')
    card.locator('[data-ha-node-claim-state="foreign"]').wait_for(timeout=5000)
    means = ('Another PegaProx instance holds the claim under a higher epoch. This instance is the stale one and '
             'recovers no node of this cluster.')
    assert card.locator('[data-ha-node-claim-means]').inner_text() == means
    assert _wait_for_toast(page, means)
    assert not app.errors, app.errors


def test_runtime_a_foreign_claim_is_taken_over_with_its_words(open_node_app):
    app = open_node_app(claim={'enabled': True, 'state': 'higher', 'epoch': 5, 'instance': OTHER,
                               'checked_at': _iso_ago(120)})
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    card = modal.locator('[data-ha-node-claim]')
    assert card.locator('[data-ha-node-claim-state]').inner_text() == 'Another instance'
    assert 'Instance cccccccc, epoch 5' in card.inner_text()
    assert card.locator('[data-ha-node-claim-residual]').count() == 0
    card.get_by_role('button', name='Take over the claim').click()
    form = card.locator('[data-ha-node-claim-form="release"]')
    form.wait_for(timeout=3000)
    assert 'Do it only when the other PegaProx instance no longer acts on this cluster.' in form.inner_text()
    assert 'Type RELEASE CLAIM to confirm' in form.inner_text()
    take = form.get_by_role('button', name='Take over the claim')
    page.fill('#ha-node-claim-password', PASSWORD)
    page.fill('#ha-node-claim-typed', 'WRITE CLAIM')
    assert take.is_disabled(), 'the words of the other action do not count'
    page.fill('#ha-node-claim-typed', 'RELEASE CLAIM')
    take.click()
    card.locator('[data-ha-node-claim-state="ours"]').wait_for(timeout=5000)
    assert app.server.bodies['/api/clusters/c1/ha/claim'] == [{'action': 'release', 'confirm': 'RELEASE CLAIM',
                                                               'user_password': PASSWORD}]
    assert card.get_by_role('button', name='Take over the claim').count() == 0
    assert _wait_for_toast(page, 'The claim was taken over')
    assert not app.errors, app.errors


@pytest.mark.parametrize('removal', ['removed', 'unreachable'])
def test_runtime_switching_the_claim_off_says_what_became_of_the_file(open_node_app, removal):
    app = open_node_app(claim={'enabled': True, 'state': 'ours', 'epoch': 2, 'instance': OWN,
                               'checked_at': _iso_ago(30)}, claim_removal=removal)
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    card = modal.locator('[data-ha-node-claim]')
    switch = page.get_by_role('switch', name='Cluster claim')
    assert switch.get_attribute('aria-checked') == 'true'
    switch.click()
    form = card.locator('[data-ha-node-claim-form="disable"]')
    form.wait_for(timeout=3000)
    # off wants the password, no words
    assert page.locator('#ha-node-claim-typed').count() == 0
    off = form.get_by_role('button', name='Switch off')
    assert off.is_disabled()
    page.fill('#ha-node-claim-password', PASSWORD)
    off.click()
    answer = card.locator('[data-ha-node-claim-answer]')
    answer.wait_for(timeout=5000)
    assert app.server.bodies['/api/clusters/c1/ha/claim'] == [{'action': 'disable', 'user_password': PASSWORD}]
    assert switch.get_attribute('aria-checked') == 'false'
    assert card.locator('[data-ha-node-claim-residual]').inner_text() == CLAIM_RESIDUAL
    commands = answer.locator('[data-ha-node-command]')
    if removal == 'removed':
        assert answer.inner_text() == 'The claim file was removed from the cluster.'
        assert commands.count() == 0
        assert _wait_for_toast(page, 'Cluster claim switched off')
    else:
        text = answer.inner_text()
        assert 'The cluster claim could not be removed (no node of the cluster answered)' in text
        # the command once, on a line of its own, with a copy button
        assert commands.count() == 1
        assert commands.locator('code').inner_text() == CLAIM_BY_HAND
        assert commands.locator('button[title="Copy"]').count() == 1
        assert '`' not in text
    _no_raw_keys(modal)
    assert not app.errors, app.errors


@pytest.mark.parametrize('stale', [False, True])
def test_runtime_an_sso_account_types_no_password_for_the_claim(open_node_app, stale):
    app = open_node_app(auth_source='oidc', sso_stale=stale)
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    page.get_by_role('switch', name='Cluster claim').click()
    form = modal.locator('[data-ha-node-claim-form="enable"]')
    form.wait_for(timeout=3000)
    assert page.locator('#ha-node-claim-password').count() == 0
    page.fill('#ha-node-claim-typed', 'WRITE CLAIM')
    form.get_by_role('button', name='Write the claim').click()
    if stale:
        refused = form.locator('[data-ha-node-claim-refused="HA_REAUTH_RECENT"]')
        refused.wait_for(timeout=5000)
        assert refused.get_by_role('button', name='Sign in again').count() == 1
    else:
        modal.locator('[data-ha-node-claim-state="ours"]').wait_for(timeout=5000)
    assert app.server.bodies['/api/clusters/c1/ha/claim'] == [{'action': 'enable', 'confirm': 'WRITE CLAIM'}]
    assert not app.errors, app.errors


def _ha_switch(page):
    """The HA switch in the Settings tab of the cluster."""
    return page.locator('label', has_text=re.compile(r'^HA Enabled$')).locator('.toggle-switch')


@pytest.mark.parametrize('left', [True, False])
def test_runtime_ha_disable_shows_what_was_left_behind(open_node_app, left):
    disable = {'warning': f'{AGENTS_LEFT} {CLAIM_NOT_REMOVED}', 'agents_unconfirmed': ['pve2'],
               'claim': {'state': 'unreachable', 'removed': False, 'path': '/etc/pve/pegaprox/claim',
                         'instance': None, 'epoch': None, 'warning': CLAIM_NOT_REMOVED,
                         'by_hand': CLAIM_BY_HAND}} if left else None
    app = open_node_app(disable=disable)
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name='Settings', exact=True).first.click()
    switch = _ha_switch(page)
    switch.wait_for(timeout=5000)
    switch.click()
    assert _wait_for(page, lambda: ('POST', '/api/clusters/c1/ha/disable') in app.server.calls)
    report = page.locator('[data-ha-node-disable-report]')
    if not left:
        assert _wait_for_toast(page, 'HA disabled')
        page.wait_for_timeout(300)
        assert report.count() == 0
        assert not app.errors, app.errors
        return
    report.wait_for(timeout=5000)
    text = report.inner_text()
    assert 'HA is off, but something was left behind' in text and 'Testi' in text
    assert report.locator('[data-ha-node-disable-unconfirmed]').inner_text() == 'Not confirmed as removed on: pve2'
    assert report.locator('[data-ha-node-disable-failed]').count() == 0
    assert 'Not listed by the cluster, agents may still run on: pve2.' in text
    assert 'The cluster claim could not be removed' in text
    # both commands to run by hand, each once, each with its copy button
    codes = report.locator('[data-ha-node-command] code').all_inner_texts()
    assert codes == [AGENTS_BY_HAND, CLAIM_BY_HAND]
    assert report.locator('[data-ha-node-command] button[title="Copy"]').count() == 2
    # instead of the plain success toast
    page.wait_for_timeout(300)
    assert not any(t.strip() == 'HA disabled' for t in _toasts(page)), _toasts(page)
    report.get_by_role('button', name='Close').click()
    assert report.count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('case', ['warns', 'old', 'off', 'clean'])
def test_runtime_the_cloud_ha_page_has_one_line_each(open_node_app, case):
    kw = {'warns': dict(unsafe=True, versions={'pve1': 2, 'pve2': 1}),
          'old': dict(old=True, unsafe=True, versions={'pve2': 1}),
          'off': dict(ha_enabled=False, unsafe=True, versions={'pve2': 1}),
          'clean': dict(versions={'pve1': 2, 'pve2': 2})}[case]
    app = open_node_app(layout='cloud', **kw)
    page = app.page
    page.get_by_text('High Availability', exact=True).first.click()
    assert _wait_for(page, lambda: ('GET', '/api/clusters/c1/ha/status') in app.server.calls)
    notes = page.locator('[data-ha-node-cloud]')
    if case != 'warns':
        page.wait_for_timeout(800)
        assert notes.count() == 0
        assert not app.errors, app.errors
        return
    notes.wait_for(timeout=5000)
    unsafe = notes.locator('[data-ha-node-cloud-line="unsafe"]')
    outdated = notes.locator('[data-ha-node-cloud-line="outdated"]')
    assert unsafe.inner_text().strip() == 'Unsafe two-node recovery: Enabled'
    assert unsafe.get_attribute('title') == UNSAFE_WARNING
    assert outdated.inner_text().strip() == 'Outdated self-fence agent: pve2'
    assert outdated.get_attribute('title') == OUTDATED.format(nodes='pve2', version=2)
    assert 'haNode' not in notes.inner_text()
    assert not app.errors, app.errors


@pytest.mark.parametrize('installed', [NODES, ()])
def test_runtime_an_old_server_renders_the_settings_as_before(open_node_app, installed):
    app = open_node_app(old=True, installed=installed, unsafe=True)
    page = app.page
    modal = _open_ha_settings(app, wait=None)
    for part in ('unsafe', 'no-fence', 'agents', 'safety', 'fencing', 'claim', 'survivor'):
        assert modal.locator(f'[data-ha-node-{part}]').count() == 0, part
    text = modal.inner_text()
    for needle in ('Self-Fence Protection', 'Enable 2-Node Cluster Mode', 'Recovery Delay', 'Advanced Settings'):
        assert needle in text, needle
    install = modal.locator('[data-ha-node-install]')
    if installed:
        assert 'Self-Fence Protection Active' in text
        assert install.count() == 0
    else:
        assert 'Self-Fence Agent not installed' in text
        assert install.get_attribute('data-ha-node-install') == 'install'
        assert install.inner_text().strip().endswith('Install Self-Fence Agent')
        install.click()
        assert _wait_for(page, lambda: app.server.installs == 1)
    _no_raw_keys(modal)
    # the form saves the way it did
    modal.get_by_role('button', name='Save Settings').click()
    assert _wait_for(page, lambda: len(_puts(app)) == 1)
    sent = _puts(app)[0]
    assert sent['two_node_mode'] is True and 'unsafe_two_node_recovery' not in sent and 'fencing' not in sent
    assert not app.errors, app.errors


def test_runtime_corporate_shows_the_same_settings(open_node_app):
    """Modern and Corporate share the modal: the parts are there in Corporate as well."""
    app = open_node_app(layout='corporate', unsafe=True, versions={'pve1': 2, 'pve2': 1}, fencing=IPMI_PVE1,
                        claim={'enabled': True, 'state': 'same', 'epoch': 2, 'instance': OTHER,
                               'checked_at': _iso_ago(60)})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    modal = _open_ha_settings(app)
    for part in ('unsafe', 'agents', 'safety', 'fencing', 'claim'):
        assert modal.locator(f'[data-ha-node-{part}]').count() == 1, part
    assert modal.locator('[data-ha-node-unsafe]').is_visible()
    assert modal.locator('[data-ha-node-claim-state="foreign"]').count() == 1
    assert ('Another PegaProx instance holds the claim under the same epoch: two instances act on this cluster. '
            'Node recovery is refused here.') in modal.locator('[data-ha-node-claim-means]').inner_text()
    assert modal.get_by_role('button', name='Take over the claim').count() == 1
    _no_raw_keys(modal)
    assert not app.errors, app.errors


def test_runtime_the_node_parts_speak_german(open_node_app):
    app = open_node_app(language='de', unsafe=True, versions={'pve1': 2, 'pve2': 1})
    modal = _open_ha_settings(app, settings='Einstellungen', button='Split-Brain Prävention')
    text = modal.inner_text()
    for needle in ('Unsichere Zwei-Node-Wiederherstellung ist an', 'Self-Fence Agent pro Node', 'Agents prüfen',
                   'Früherer Agent (Version 1)', 'Veraltet', 'Self-Fence Agent auf Version 2 aktualisieren',
                   'Sicherheitsregeln für die Node-Wiederherstellung', 'Fencing pro Node', 'Cluster-Claim'):
        assert needle in text, needle
    # the server's words stay as they are
    assert UNSAFE_WARNING in text
    _no_raw_keys(modal)
    assert not app.errors, app.errors


# -- runtime: who may write, another cluster, what stays after a request, an old status --------

VIEW = ['cluster.view', 'node.view', 'vm.view', 'ha.view']


@pytest.mark.parametrize('perms,writes', [(VIEW, False), (VIEW + ['ha.config'], True)], ids=['ha.view', 'ha.config'])
def test_runtime_with_ha_view_alone_nothing_can_be_changed(open_node_app, perms, writes):
    """The parts were locked on a read-only standby only: an account with ha.view got live
    buttons for routes that want ha.config. With it they stay live (the counterproof)."""
    app = open_node_app(admin=False, permissions=perms, versions={'pve1': 2, 'pve2': 1}, fencing=IPMI_PVE1,
                        check=CHECK)
    page = app.page
    modal = _open_ha_settings(app)
    controls = {
        'check agents': modal.locator('[data-ha-node-agents]').get_by_role('button', name='Check agents'),
        'unsafe switch': page.get_by_role('switch', name='Unsafe two-node recovery'),
        'fence type': page.locator('select[aria-label="Type pve1"]'),
        'fence host': page.locator('input[aria-label="Host pve1"]'),
        'fence password': page.locator('input[aria-label="Password pve1"]'),
    }
    assert {name: c.is_enabled() for name, c in controls.items()} == {name: writes for name in controls}
    # the install that replaces the agent of an earlier PegaProx is not offered at all
    assert modal.locator('[data-ha-node-install]').count() == (1 if writes else 0)
    # the claim is for admins either way, and says so
    assert page.get_by_role('switch', name='Cluster claim').is_disabled()
    assert 'Only administrators switch the cluster claim.' in modal.locator('[data-ha-node-claim]').inner_text()
    if writes:
        modal.locator('[data-ha-node-agents]').get_by_role('button', name='Check agents').click()
        assert _wait_for(page, lambda: ('POST', '/api/clusters/c1/ha/agent-check') in app.server.calls)
    else:
        # what is set still shows
        assert page.locator('select[aria-label="Type pve1"]').input_value() == 'ipmi'
        assert modal.locator('[data-ha-node-agent="pve2"]').get_attribute('data-ha-node-agent-kind') == 'earlier'
        assert not [c for c in app.server.calls if c[0] != 'GET' and '/ha' in c[1]]
    assert not app.errors, app.errors


class _TwoClusters(_NodeHaServer):
    """c1 as the fake has it, and a second cluster c2: safe, no fence, its claim off. The
    status reads of a cluster in `hold` wait until release() answers them."""

    def __init__(self, **kw):
        c2 = dict(HA_CLUSTER, id='c2', name='Zweit', display_name='Zweit', host='10.0.0.2')
        kw.setdefault('clusters', [dict(HA_CLUSTER), c2])
        super().__init__(**kw)
        self.hold = set()
        self.held = []

    def c2_status(self):
        status = self.ha_status()
        status['split_brain_prevention'].update(unsafe_two_node_recovery=False, unsafe_two_node_warning=None,
                                                fencing={}, verified_fence_required=True,
                                                verified_fence_configured=False)
        status['cluster_claim'] = dict(status['cluster_claim'], enabled=False, state='off', instance=None,
                                       epoch=None, checked_at=None)
        return status

    def answer_status(self, route, cid):
        body = self.ha_status() if cid == 'c1' else self.c2_status()
        route.fulfill(status=200, body=json.dumps(body), headers={'Content-Type': 'application/json'})

    def release(self):
        held, self.held = self.held, []
        for route, cid in held:
            self.answer_status(route, cid)

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/clusters/(c[12])/ha/status', path)
        if not (m and req.method == 'GET' and req.url.startswith(BASE)):
            return super().handle(route)
        self.calls.append(('GET', path))
        if m.group(1) in self.hold:
            self.held.append((route, m.group(1)))
            return None
        return self.answer_status(route, m.group(1))


def _close_ha_settings(page):
    page.keyboard.press('Escape')
    if page.locator('[data-ha-cluster-settings]').count():
        page.mouse.click(5, 5)
    page.locator('[data-ha-cluster-settings]').wait_for(state='detached', timeout=5000)


def _open_c2_settings(app):
    page = app.page
    page.get_by_text('Zweit').first.click()
    page.wait_for_timeout(500)
    page.get_by_role('button', name='Settings', exact=True).first.click()
    page.get_by_role('button', name=re.compile('Split-Brain Prevention')).click()
    modal = page.locator('[data-ha-cluster-settings]')
    modal.wait_for(timeout=5000)
    return modal


@pytest.fixture
def two_clusters(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _TwoClusters(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


C1_UNSAFE = dict(unsafe=True, fencing=IPMI_PVE1, claim={'enabled': True, 'state': 'ours', 'epoch': 2, 'instance': OWN,
                                                       'checked_at': _iso_ago(10)})


def test_runtime_the_second_cluster_never_shows_the_first_ones_state(two_clusters):
    """Until its own status arrives the settings of c2 showed c1's unsafe banner, fence and
    claim, and a click on them wrote to c2."""
    app = two_clusters(**C1_UNSAFE)
    page = app.page
    modal = _open_ha_settings(app)
    assert modal.locator('[data-ha-node-unsafe]').count() == 1
    _close_ha_settings(page)
    app.server.hold.add('c2')
    m2 = _open_c2_settings(app)
    assert _wait_for(page, lambda: any(cid == 'c2' for _, cid in app.server.held))
    page.wait_for_timeout(500)
    assert m2.locator('[data-ha-node-unsafe]').count() == 0
    assert m2.locator('[data-ha-node-claim]').count() == 0
    assert page.locator('select[aria-label="Type pve1"]').count() == 0
    app.server.hold.clear()
    app.server.release()
    m2.locator('[data-ha-node-claim="off"]').wait_for(timeout=5000)
    assert m2.locator('[data-ha-node-unsafe]').count() == 0
    assert page.locator('select[aria-label="Type pve1"]').input_value() == ''
    assert not [c for c in app.server.calls if c[0] != 'GET' and '/ha' in c[1]]
    assert not app.errors, app.errors


def test_runtime_a_late_answer_for_the_first_cluster_does_not_fill_the_second(two_clusters):
    app = two_clusters(**C1_UNSAFE)
    page = app.page
    _open_ha_settings(app)
    _close_ha_settings(page)
    # c1's status asked for again, answered only once c2 is selected and its settings open
    app.server.hold.add('c1')
    page.get_by_role('button', name=re.compile('Split-Brain Prevention')).click()
    assert _wait_for(page, lambda: any(cid == 'c1' for _, cid in app.server.held))
    _close_ha_settings(page)
    app.server.hold.clear()
    m2 = _open_c2_settings(app)
    m2.locator('[data-ha-node-claim="off"]').wait_for(timeout=5000)
    app.server.release()
    page.wait_for_timeout(1000)
    assert m2.locator('[data-ha-node-claim]').get_attribute('data-ha-node-claim') == 'off'
    assert m2.locator('[data-ha-node-unsafe]').count() == 0
    assert page.locator('select[aria-label="Type pve1"]').input_value() == ''
    assert not app.errors, app.errors


class _HeldClusters(_NodeHaServer):
    """c1 as the fake has it, c2 a fake of its own behind the same routes. Any HA request of
    either that is in `hold` as (method, path) waits until release() answers it, with the state
    at that time. c2_refusal: what the status reads of c2 get instead, (status code, body)."""

    def __init__(self, c2=None, c2_refusal=None, **kw):
        c2_cluster = dict(HA_CLUSTER, id='c2', name='Zweit', display_name='Zweit', host='10.0.0.2')
        kw.setdefault('clusters', [dict(HA_CLUSTER), c2_cluster])
        super().__init__(**kw)
        self.c2 = _NodeHaServer(**(c2 or {}))
        self.c2_refusal = c2_refusal
        self.hold = set()
        self.held = []

    def answer(self, route, cid, method, sub, body):
        if cid == 'c2' and method == 'GET' and self.c2_refusal:
            status, data = self.c2_refusal
            text = data if isinstance(data, str) else json.dumps(data)
            kind = 'text/html' if isinstance(data, str) else 'application/json'
            return route.fulfill(status=status, body=text, headers={'Content-Type': kind})
        status, data = (self if cid == 'c1' else self.c2).ha_route(method, sub, body)
        return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def release(self):
        held, self.held = self.held, []
        for args in held:
            self.answer(*args)

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/clusters/(c[12])/ha(/[a-z-]+)?', path)
        if not (m and req.url.startswith(BASE)):
            return _FakeServer.handle(self, route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        self.bodies.setdefault(path, []).append(body)
        args = (route, m.group(1), req.method, m.group(2) or '', body)
        if (req.method, path) in self.hold:
            self.held.append(args)
            return None
        return self.answer(*args)

    def holds(self, method, path):
        return any((a[2], '/api/clusters/%s/ha%s' % (a[1], a[3])) == (method, path) for a in self.held)


@pytest.fixture
def held_clusters(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _HeldClusters(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _send_claim(app, modal):
    app.page.get_by_role('switch', name='Cluster claim').click()
    app.page.fill('#ha-node-claim-password', PASSWORD)
    app.page.fill('#ha-node-claim-typed', 'WRITE CLAIM')
    modal.get_by_role('button', name='Write the claim').click()


def _send_unsafe_off(app, modal):
    app.page.get_by_role('switch', name='Unsafe two-node recovery').click()


def _send_fence(app, modal):
    app.page.select_option('select[aria-label="Type pve2"]', 'ipmi')
    app.page.fill('input[aria-label="Host pve2"]', '10.0.0.102')
    app.page.fill('input[aria-label="Password pve2"]', 'bmc-two')
    modal.get_by_role('button', name='Save fencing').click()


def _send_check(app, modal):
    modal.locator('[data-ha-node-agents]').get_by_role('button', name='Check agents').click()


# the part, how c1 is set up, what the part sends for c1, and how
LATE = {
    'claim': ({}, ('POST', '/api/clusters/c1/ha/claim'), _send_claim),
    'unsafe': (C1_UNSAFE, ('PUT', '/api/clusters/c1/ha/config'), _send_unsafe_off),
    'fencing': ({'fencing': IPMI_PVE1}, ('PUT', '/api/clusters/c1/ha/config'), _send_fence),
    'agents': ({'versions': {'pve1': 2, 'pve2': 1}, 'check': CHECK}, ('POST', '/api/clusters/c1/ha/agent-check'),
               _send_check),
}


def _shown(page, modal):
    """What the settings of a cluster show of the parts."""
    return {
        'claim': modal.locator('[data-ha-node-claim]').get_attribute('data-ha-node-claim'),
        'unsafe': modal.locator('[data-ha-node-unsafe]').count(),
        'fence': [page.locator(f'select[aria-label="Type {n}"]').input_value() for n in NODES],
        'agents': modal.locator('[data-ha-node-agent]').evaluate_all(
            'rows => rows.map(r => r.dataset.haNodeAgent + ":" + r.dataset.haNodeAgentKind)'),
        'silent': modal.locator('[data-ha-node-silent]').count(),
    }


@pytest.mark.parametrize('part', list(LATE))
def test_runtime_a_late_answer_of_a_part_does_not_fill_the_next_cluster(held_clusters, part):
    """A part asked for c1, its answer came once c2's settings were open: c2 showed c1's claim,
    fence, unsafe banner or agent check, and the next click on them went to c2."""
    setup, request, send = LATE[part]
    app = held_clusters(c2={'versions': {'pve1': 2, 'pve2': 2}}, **setup)
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    app.server.hold.add(request)
    send(app, modal)
    assert _wait_for(page, lambda: app.server.holds(*request))
    _close_ha_settings(page)
    m2 = _open_c2_settings(app)
    m2.locator('[data-ha-node-claim="off"]').wait_for(timeout=5000)
    before = _shown(page, m2)
    assert before['claim'] == 'off' and before['unsafe'] == 0 and before['fence'] == ['', ''], before
    app.server.release()
    page.wait_for_timeout(1000)
    assert not app.server.held
    assert _shown(page, m2) == before
    assert not [c for c in app.server.calls if c[0] != 'GET' and c[1].startswith('/api/clusters/c2/ha')]
    assert not app.errors, app.errors


def _c1_values(server):
    """c1 with values a form left over from it would carry into c2."""
    status = server.ha_status

    def read():
        s = status()
        s['split_brain_prevention'].update(recovery_delay=111, quorum_gateway='10.1.1.1')
        s['failure_threshold'] = 7
        return s
    server.ha_status = read


def _form_fields(modal):
    return modal.locator('input[type="number"], input[type="checkbox"], input[placeholder="192.168.1.1"]')


def test_runtime_the_form_waits_for_the_status_of_its_cluster(held_clusters):
    """c1's values stayed in the form while c2's status was on its way, and Save wrote them to
    c2. Now the form waits for c2's status, and then holds c2's values."""
    app = held_clusters(two_node=True, c2={'two_node': False})
    _c1_values(app.server)
    page = app.page
    modal = _open_ha_settings(app)
    assert modal.locator('input[type="number"]').first.input_value() == '111'
    _close_ha_settings(page)
    app.server.hold.add(('GET', '/api/clusters/c2/ha/status'))
    m2 = _open_c2_settings(app)
    assert _wait_for(page, lambda: app.server.holds('GET', '/api/clusters/c2/ha/status'))
    page.wait_for_timeout(500)
    assert m2.locator('[data-ha-settings-loading]').inner_text().strip() == 'Loading...'
    assert _form_fields(m2).count() == 0 and 'Enable 2-Node Cluster Mode' not in m2.inner_text()
    save = m2.get_by_role('button', name='Save Settings')
    assert save.is_disabled()
    app.server.hold.clear()
    app.server.release()
    m2.locator('[data-ha-node-safety]').wait_for(timeout=5000)
    assert m2.locator('[data-ha-settings-loading]').count() == 0
    assert [f.input_value() for f in m2.locator('input[type="number"]').all()] == ['30', '3']
    assert not m2.locator('label', has_text='Enable 2-Node Cluster Mode').locator('input').is_checked()
    save.click()
    assert _wait_for(page, lambda: app.server.bodies.get('/api/clusters/c2/ha/config'))
    sent = app.server.bodies['/api/clusters/c2/ha/config'][0]
    assert (sent['recovery_delay'], sent['failure_threshold'], sent['quorum_gateway'], sent['two_node_mode']) == \
        (30, 3, '', False)
    assert '/api/clusters/c1/ha/config' not in app.server.bodies
    assert not app.errors, app.errors


@pytest.mark.parametrize('refusal,words', [
    ((503, {'error': 'Cluster not reachable'}), 'Cluster not reachable'),
    ((500, '<html><body>Internal Server Error</body></html>'), None),
], ids=['server-words', 'no-words'])
def test_runtime_a_status_that_cannot_be_read_shows_why_and_no_form(held_clusters, refusal, words):
    app = held_clusters(two_node=True, c2={'two_node': False}, c2_refusal=refusal)
    _c1_values(app.server)
    page = app.page
    _open_ha_settings(app)
    _close_ha_settings(page)
    m2 = _open_c2_settings(app)
    error = m2.locator('[data-ha-settings-error]')
    error.wait_for(timeout=5000)
    lines = [line.strip() for line in error.inner_text().split('\n') if line.strip()]
    assert lines == ['The HA settings of this cluster could not be read.'] + ([words] if words else [])
    assert _form_fields(m2).count() == 0 and m2.locator('[data-ha-node-safety]').count() == 0
    assert m2.get_by_role('button', name='Save Settings').is_disabled()
    page.wait_for_timeout(500)
    assert not [c for c in app.server.calls if c[0] != 'GET' and '/ha' in c[1]]
    assert not app.errors, app.errors


@pytest.mark.parametrize('perms,writes', [(VIEW, False), (VIEW + ['ha.config'], True)], ids=['ha.view', 'ha.config'])
def test_runtime_with_ha_view_alone_the_form_is_read_only(open_node_app, perms, writes):
    """The parts were locked for ha.view alone, the form around them was not: Save wrote it
    and Uninstall was offered. With ha.config all of it stays live (the counterproof)."""
    app = open_node_app(admin=False, permissions=perms, versions={'pve1': 2, 'pve2': 2})
    page = app.page
    modal = _open_ha_settings(app)
    form = {
        'pegaprox vm': modal.locator('select:not([aria-label])'),
        '2-node mode': modal.locator('label', has_text='Enable 2-Node Cluster Mode').locator('input'),
        'recovery delay': modal.locator('input[type="number"]').nth(0),
        'failure threshold': modal.locator('input[type="number"]').nth(1),
        'self-fencing': modal.locator('details input[type="checkbox"]').nth(0),
        'network check': modal.locator('details input[type="checkbox"]').nth(1),
        'quorum hosts': modal.locator('input[placeholder="8.8.8.8, 1.1.1.1"]'),
        'gateway': modal.locator('input[placeholder="192.168.1.1"]'),
        'save': modal.get_by_role('button', name='Save Settings'),
    }
    assert {name: c.is_enabled() for name, c in form.items()} == {name: writes for name in form}
    assert modal.get_by_role('button', name='Uninstall').count() == (1 if writes else 0)
    # what is set still shows
    assert form['recovery delay'].input_value() == '30'
    if writes:
        form['save'].click()
        assert _wait_for(page, lambda: len(_puts(app)) == 1)
    else:
        page.wait_for_timeout(300)
        assert not _puts(app)
    assert not app.errors, app.errors


WAIT_REASON = ('2-node cluster (expected_votes=2) WITHOUT qdevice - corosync loses quorum on every single-node '
               'reboot in this topology, so auto-fencing would take the whole cluster down on planned maintenance. '
               'Add a qdevice to upgrade to quorum-mode.')


def test_runtime_the_dialog_next_to_a_wait_strategy(open_node_app):
    """Two nodes without a QDevice: the agents run with strategy wait and keep the VMs running.
    The dialog promised a fence there; it now says what happens."""
    app = open_node_app(versions={'pve1': 2, 'pve2': 2})
    status = app.server.ha_status

    def wait():
        s = status()
        s['split_brain_prevention']['fence_strategy'] = {
            'strategy': 'wait', 'reason': WAIT_REASON, 'expected_votes': 2, 'has_qdevice': False,
            'detected_at': None, 'detection_reason': 'detected'}
        return s
    app.server.ha_status = wait
    modal = _open_ha_settings(app)
    assert modal.locator('h4', has_text='Fence strategy').inner_text().strip().upper() == 'FENCE STRATEGY: WAIT'
    text = modal.inner_text()
    assert ('Where quorum cannot decide (two votes, or quorum gets forced), a node without a majority asks the '
            'PegaProx instances who leads and stops its VMs when no leader answers; on two nodes without a QDevice '
            '(fence strategy WAIT) it only logs this and keeps them running.') in text
    assert modal.locator('[data-ha-node-fence-delay]').inner_text().strip() == (
        'Fence delay: 30 s. When a node is out of order that long, its version 2 agent stops its guests (under '
        'fence strategy WAIT it only logs this and keeps them running); the recovery of the node never starts '
        'earlier.')
    assert not app.errors, app.errors


def test_runtime_server_words_with_dollar_signs_show_as_sent(open_node_app):
    """The holder of the claim and the nodes that did not answer come from the server: a $& or
    $` in them stood for the placeholder or the text before it."""
    instance = "$&$`$'" + 'c' * 26
    check = json.loads(json.dumps(CHECK))
    check['nodes']['p$`3'] = None
    app = open_node_app(versions={'pve1': 2, 'pve2': 1}, check=check,
                        claim={'enabled': True, 'state': 'same', 'epoch': 2, 'instance': instance,
                               'checked_at': _iso_ago(60)})
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    assert modal.locator(f'[data-ha-node-claim] span[title="{instance}"]').inner_text().strip() == \
        "Instance $&$`$'cc, epoch 2"
    agents = modal.locator('[data-ha-node-agents]')
    agents.get_by_role('button', name='Check agents').click()
    assert _wait_for(page, lambda: 'Did not answer the check: p$`3, pve3' in agents.inner_text()), agents.inner_text()
    assert not app.errors, app.errors


# every string held in the hooks of the mounted components: what a request left in React state
STATE_HOLDING_JS = '''(secret) => {
    const seenFibers = new Set();
    const hits = [];
    const visit = (v, depth, where, seen) => {
        if (v == null || depth > 6) return;
        if (typeof v === 'string') { if (v.includes(secret)) hits.push(where); return; }
        if (typeof v !== 'object' || seen.has(v)) return;
        if (v instanceof Node || v instanceof Window) return;
        seen.add(v);
        if (v.$$typeof) return;
        for (const k of Object.keys(v)) {
            if (['_owner', 'return', 'child', 'sibling', 'stateNode', 'alternate'].includes(k)) continue;
            try { visit(v[k], depth + 1, where + '.' + k, seen); } catch (e) {}
        }
    };
    for (const el of document.querySelectorAll('*')) {
        const key = Object.keys(el).find(k => k.startsWith('__reactFiber$'));
        if (!key) continue;
        let f = el[key];
        while (f && !seenFibers.has(f)) {
            seenFibers.add(f);
            const name = (f.type && (f.type.name || f.type.displayName)) || '?';
            if (typeof f.type === 'function') {
                for (let h = f.memoizedState, i = 0; h && i < 200; h = h.next, i++) {
                    visit(h.memoizedState, 0, name + '#hook' + i, new Set());
                }
            }
            f = f.return;
        }
    }
    return Array.from(new Set(hits));
}'''


def _held(page, secret):
    return page.evaluate(STATE_HOLDING_JS, secret)


@pytest.mark.parametrize('refusal', [(500, {'error': 'Operation failed'}), (403, {'error': 'The password is not '
                                     'correct', 'code': 'HA_REAUTH'})], ids=['500', 'reauth'])
def test_runtime_the_claim_password_goes_with_every_request(open_node_app, refusal):
    app = open_node_app()
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    switch = page.get_by_role('switch', name='Cluster claim')
    switch.click()
    form = modal.locator('[data-ha-node-claim-form="enable"]')
    page.fill('#ha-node-claim-typed', 'WRITE CLAIM')
    # a 500 for a password that is right: refused all the same
    typed = PASSWORD if refusal[0] == 500 else 'NOT-THE-PASSWORD-77'
    page.fill('#ha-node-claim-password', typed)
    app.server.claim_route = lambda body: refusal
    form.get_by_role('button', name='Write the claim').click()
    form.locator('[data-ha-node-claim-refused]').wait_for(timeout=5000)
    assert page.input_value('#ha-node-claim-password') == ''
    assert _held(page, typed) == []
    # the words stay, the next try wants the password again
    assert page.input_value('#ha-node-claim-typed') == 'WRITE CLAIM'
    del app.server.claim_route
    page.fill('#ha-node-claim-password', PASSWORD)
    form.get_by_role('button', name='Write the claim').click()
    assert _wait_for(page, lambda: switch.get_attribute('aria-checked') == 'true')
    assert _held(page, PASSWORD) == []
    assert not app.errors, app.errors


def test_runtime_a_bmc_password_goes_with_a_refused_request(open_node_app):
    app = open_node_app(fencing=IPMI_PVE1, config_refusal=(500, {'error': 'Operation failed'}))
    page = app.page
    modal = _open_ha_settings(app)
    page.select_option('select[aria-label="Type pve2"]', 'ipmi')
    page.fill('input[aria-label="Host pve2"]', '10.0.0.102')
    secret = 'BMC-AFTER-REFUSAL'
    page.fill('input[aria-label="Password pve2"]', secret)
    save = modal.get_by_role('button', name='Save fencing')
    save.click()
    modal.locator('[data-ha-node-fencing-error]').wait_for(timeout=5000)
    assert _held(page, secret) == []
    assert page.input_value('input[aria-label="Password pve2"]') == ''
    # the rest of the row stays for the next try
    assert page.locator('select[aria-label="Type pve2"]').input_value() == 'ipmi'
    assert page.input_value('input[aria-label="Host pve2"]') == '10.0.0.102'
    app.server.config_refusal = None
    page.fill('input[aria-label="Password pve2"]', secret)
    save.click()
    assert _wait_for_toast(page, 'Fencing saved')
    assert app.server.fencing['pve2'] == {'type': 'ipmi', 'host': '10.0.0.102', 'password': secret}
    assert _held(page, secret) == []
    assert not app.errors, app.errors


@pytest.mark.parametrize('old', [True, False], ids=['old-status', 'node-parts'])
def test_runtime_the_modal_is_wider_only_for_the_node_parts(open_node_app, old):
    app = open_node_app(old=old, versions={'pve1': 2, 'pve2': 2})
    modal = _open_ha_settings(app, wait=None if old else '[data-ha-node-agents]')
    classes = modal.get_attribute('class').split()
    assert ('max-w-xl' in classes, 'max-w-3xl' in classes) == ((True, False) if old else (False, True))
    # 36rem against 48rem
    assert modal.bounding_box()['width'] == (576 if old else 768)
    assert not app.errors, app.errors


@pytest.mark.parametrize('server', ['fixed', 'before'])
def test_runtime_saving_two_node_mode_does_not_bring_unsafe_recovery_back(open_node_app, server):
    """Stored on while 2-node mode was off: the status says off, and saving 2-node mode made it
    live with no word typed and nothing on screen. The form saves it as off; the server drops it
    as well (test_ha_node_safety.py), and a server from before that still ends up safe."""
    app = open_node_app(two_node=False, unsafe=True, keep_masked_unsafe=server == 'before')
    page = app.page
    modal = _open_ha_settings(app)
    assert page.get_by_role('switch', name='Unsafe two-node recovery').get_attribute('aria-checked') == 'false'
    modal.locator('label', has_text='Enable 2-Node Cluster Mode').first.click()
    modal.get_by_role('button', name='Save Settings').click()
    assert _wait_for(page, lambda: len(_puts(app)) == 1)
    sent = _puts(app)[0]
    assert sent['two_node_mode'] is True and sent['unsafe_two_node_recovery'] is False
    assert 'confirm_unsafe_two_node' not in sent
    assert app.server.unsafe is False and app.server.ha_status()['split_brain_prevention']['unsafe_two_node_recovery'] is False
    # opened again: the rules hold, the switch is off and can now be switched (with its word)
    modal = _open_ha_settings(app, settings='Settings')
    assert modal.locator('[data-ha-node-unsafe]').count() == 0
    switch = page.get_by_role('switch', name='Unsafe two-node recovery')
    assert switch.get_attribute('aria-checked') == 'false' and switch.is_enabled()
    assert not app.errors, app.errors


def test_runtime_the_form_leaves_an_unsafe_switch_that_is_on_alone(open_node_app):
    """The counterproof: on and shown as on, the form sends nothing about it."""
    app = open_node_app(two_node=True, unsafe=True)
    page = app.page
    modal = _open_ha_settings(app)
    modal.get_by_role('button', name='Save Settings').click()
    assert _wait_for(page, lambda: len(_puts(app)) == 1)
    assert 'unsafe_two_node_recovery' not in _puts(app)[0]
    assert app.server.unsafe is True
    assert not app.errors, app.errors
