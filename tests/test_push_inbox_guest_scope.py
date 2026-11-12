"""The push inbox and the browser wake-up carry what the active-alerts list shows the same
subscriber, and nothing else.

A subscriber confined in the cluster - a pool grant in its own tenant or on another
tenant's cluster, a guest ACL, a default-tenant account with a pool grant - gets the
alerts of the guests it may view and the cluster's own. A node's alerts go to cluster-wide
subscribers with node.view. The admin and a cluster-wide viewer keep every alert.

The rules are made through the alert route, the alerts come from the metric loop, the
rolling-update event and an event rule, and the inbox is read through its route. Only the
browser wake-up is recorded instead of sent.
"""
import time
import types

import pytest

import pegaprox.api.push as push
import pegaprox.background.alert_events as alert_events
import pegaprox.background.alerts as alerts
import pegaprox.utils.rbac as rbac
from pegaprox.api.helpers import caller_is_scoped

CID = 'cluster_1'
CONFINED = ('carol', 'dave', 'erin', 'dflt')


def _guest(vmid, name, cpu):
    return {'vmid': vmid, 'name': name, 'type': 'qemu', 'node': 'pve1', 'status': 'running',
            'cpu': cpu, 'mem': 1, 'maxmem': 2, 'disk': 1, 'maxdisk': 2}


@pytest.fixture
def world(api, seed, db, monkeypatch):
    """tenant_x owns cluster_1; VM 100 db-a is in pool_a, VM 200 web-b in pool_b.

    carol   viewer of tenant_x, pool grant on pool_a
    dave    viewer of tenant_y, pool grant on pool_a (tenant_y does not own cluster_1)
    erin    viewer of tenant_x, guest ACL on VM 100
    dflt    viewer of the default tenant, pool grant on pool_a
    wide    viewer of tenant_x without a grant: cluster-wide
    nonode  viewer of tenant_x with node.view denied: cluster-wide, no node pages
    root    admin
    """
    seed.tenant('tenant_x', clusters=[CID])
    seed.tenant('tenant_y', clusters=['cluster_2'])
    users = {
        'carol': seed.user('carol', role='viewer', tenant_id='tenant_x'),
        'dave': seed.user('dave', role='viewer', tenant_id='tenant_y'),
        'erin': seed.user('erin', role='viewer', tenant_id='tenant_x'),
        'dflt': seed.user('dflt', role='viewer'),
        'wide': seed.user('wide', role='viewer', tenant_id='tenant_x'),
        'nonode': seed.user('nonode', role='viewer', tenant_id='tenant_x', denied=['node.view']),
        'root': seed.user('root', role='admin'),
    }
    for name in ('carol', 'dave', 'dflt'):
        seed.pool(CID, 'pool_a', name, ['pool.view'])
    seed.vm_acl(CID, 100, ['erin'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'100:qemu': 'pool_a', '200:qemu': 'pool_b'},
                                            'timestamp': time.time(), 'refreshing': False}

    mgr = api.make_fake_manager(cluster_id=CID,
                                get_vm_resources=[_guest(100, 'db-a', 0.96), _guest(200, 'web-b', 0.95)],
                                get_node_summary={'cpu': 0.99})
    mgr.config = types.SimpleNamespace(name=CID, check_interval=300, host='h', enabled=True)
    api.set_manager(CID, mgr)

    push._ensure_inbox_table()      # made at import, before this test's database
    push.register_alert_handler()
    for name in users:
        db.execute("INSERT INTO push_subscriptions (username, endpoint, p256dh, auth, created_at) "
                   "VALUES (?, ?, ?, ?, ?)",
                   (name, f'https://push.example/{name}', 'p256', 'secret', time.strftime('%Y-%m-%dT%H:%M:%S')))
    woken = []
    monkeypatch.setattr(push, '_wake_user', woken.append)
    monkeypatch.setattr(alerts, '_alert_last_sent', {})

    clients = {name: api.as_user(u) for name, u in users.items()}

    def rule(target_type, target_id, metric='cpu', **extra):
        body = dict({'name': f'{metric} {target_id or CID}', 'metric': metric, 'operator': '>',
                     'threshold': 90, 'target_type': target_type, 'target_id': target_id,
                     'channels': []}, **extra)
        r = clients['root'].post(f'/api/clusters/{CID}/alerts', json=body)
        assert r.status_code == 200, r.get_data(as_text=True)
        return r.get_json()['alert']

    def inbox(name):
        r = clients[name].get('/api/push/inbox')
        assert r.status_code == 200, r.get_data(as_text=True)
        return ' | '.join(f"{i['title']} :: {i['body']}" for i in r.get_json()['items'])

    def active(name):
        r = clients[name].get(f'/api/clusters/{CID}/active-alerts')
        assert r.status_code == 200, r.get_data(as_text=True)
        return ' | '.join(f"{i['target_name']} {i['message']}" for i in r.get_json()['active_alerts'])

    return types.SimpleNamespace(users=users, rule=rule, inbox=inbox, active=active, woken=woken)


@pytest.mark.parametrize('who', CONFINED)
def test_a_confined_subscriber_gets_the_metric_alerts_of_its_own_guests(world, who):
    world.rule('vm', '200')
    world.rule('vm', '100')
    alerts.check_and_send_alerts()

    # the setup confines them: VM 100 yes, VM 200 no, and the list says the same
    user = world.users[who]
    assert caller_is_scoped(user, CID) is True
    assert rbac.user_can_access_vm(user, CID, 100, 'vm.view') is True
    assert rbac.user_can_access_vm(user, CID, 200, 'vm.view') is False
    listed = world.active(who)
    assert 'db-a' in listed and 'web-b' not in listed, listed

    # the admin and a cluster-wide viewer keep both
    for name in ('root', 'wide'):
        assert caller_is_scoped(world.users[name], CID) is False
        got = world.inbox(name)
        assert 'db-a' in got and 'web-b' in got, (name, got)

    got = world.inbox(who)
    assert 'db-a' in got, got
    assert 'web-b' not in got, got
    # one wake-up, for the one alert it got
    assert world.woken.count(who) == 1, world.woken


@pytest.mark.parametrize('source', ['metric', 'rolling_update'])
def test_a_node_alert_reaches_the_cluster_wide_subscribers_with_node_view(world, source):
    if source == 'metric':
        world.rule('node', 'pve-node-7')
        alerts.check_and_send_alerts()
    else:
        world.rule('cluster', '', metric='rolling_update')
        assert alerts.emit_rolling_update_reboot_event(CID, 'pve-node-7') is True

    assert 'pve-node-7' in world.active('root')
    for name in ('root', 'wide'):
        assert 'pve-node-7' in world.inbox(name), name
    for name in CONFINED + ('nonode',):
        assert 'pve-node-7' not in world.active(name), name
        assert 'pve-node-7' not in world.inbox(name), (name, world.inbox(name))
        assert name not in world.woken, (name, world.woken)


def test_an_event_rule_and_its_resolved_notes_keep_to_the_guests_a_subscriber_sees(world):
    rule = world.rule('cluster', '', metric='replication', threshold=60, notify_resolved=True)
    guests = {100: {'vmid': 100, 'name': 'db-a'}, 200: {'vmid': 200, 'name': 'web-b'}}
    jobs = [{'id': '100-0', 'guest': 100, 'source': 'pve1', 'target': 'pve2'},
            {'id': '200-0', 'guest': 200, 'source': 'pve1', 'target': 'pve2'}]

    def tick(status):
        seen = {'guests': guests, 'replication': {'jobs': jobs, 'status': {j['id']: dict(status) for j in jobs}}}
        alert_events._evaluate(alerts, rule, CID, seen, [], {}, time.time())

    tick({'fail_count': 2, 'error': 'storage gone', 'last_sync': time.time() - 30})
    tick({'fail_count': 0, 'error': '', 'last_sync': time.time()})

    root = world.inbox('root')
    assert 'Replication 200-0 of web-b (200) is failing' in root, root
    assert 'Resolved: replication 200-0' in root, root
    got = world.inbox('carol')
    # its own guest's alert and the note that it is fine again both reach it
    assert 'Replication 100-0 of db-a (100) is failing' in got, got
    assert 'Resolved: replication 100-0' in got, got
    assert '200-0' not in got and 'web-b' not in got, got


def test_a_guest_alert_that_names_no_vmid_stays_out_of_a_confined_inbox(world):
    push._alert_handler({'alert_name': 'CPU high', 'message': 'Vm web-b: cpu is 95.0%',
                         'severity': 'warning', 'target_type': 'vm', 'target_id': '',
                         'target_name': 'web-b', 'cluster_id': CID})
    assert 'web-b' in world.inbox('root')
    for name in CONFINED:
        assert 'web-b' not in world.inbox(name), name


def test_the_resolved_note_of_a_metric_rule_keeps_to_the_guests_a_subscriber_sees(world):
    rule = {'id': 'r1', 'name': 'CPU high', 'channels': []}
    alerts._send_metric_resolved([(rule, CID, 'cpu', 'vm', '100', 'db-a', 90, '>'),
                                  (rule, CID, 'cpu', 'vm', '200', 'web-b', 90, '>')])
    root = world.inbox('root')
    assert 'Vm db-a: cpu is no longer > 90%' in root and 'web-b' in root, root
    for name in CONFINED:
        got = world.inbox(name)
        assert 'Vm db-a: cpu is no longer > 90%' in got, (name, got)
        assert 'web-b' not in got, (name, got)
