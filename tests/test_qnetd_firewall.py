"""The firewall op of packaging/qnetd/pegaprox-qnetd-helper (helper protocol 2): the port of
corosync-qnetd opened with ufw or firewalld for the addresses of one cluster's nodes, and
exactly those rules taken out again.

The helper runs as a subprocess against the stand-ins of test_qnetd_helper plus stand-ins
of ufw, firewall-cmd, nft, iptables, ip6tables and pve-firewall in its bin directory
(PEGAPROX_QNETD_BIN_DIR). ufw and firewall-cmd keep their rules in a JSON file next to
themselves and behave as the real ones do where it matters here: ufw keeps one rule of a
shape and takes over its comment when it is added again with another, and deletes only
the rule with exactly the comment given. Every call is logged with its argv.

MK Oct 2026
"""
import json
import os
import subprocess
import sys
import time

import pytest

from test_qnetd_helper import FAKE_SYSTEMCTL, HELPER, FakeBins, load_helper

H = load_helper()

FAKE_UFW = r'''#!PYTHON -I
import fcntl, json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
lock = open(os.path.join(HERE, 'fake-fw.lock'), 'a')
fcntl.flock(lock, fcntl.LOCK_EX)
with open(os.path.join(HERE, 'fw.jsonl'), 'a') as fh:
    fh.write(json.dumps({'tool': 'ufw', 'argv': args}) + '\n')
path = os.path.join(HERE, 'ufw.json')
try:
    with open(path) as fh:
        st = json.load(fh)
except FileNotFoundError:
    st = {'active': True, 'default': 'deny', 'rules': [], 'lines': []}


def save():
    with open(path, 'w') as fh:
        json.dump(st, fh)


def flag(n):
    return os.path.exists(os.path.join(HERE, 'flag-' + n))


if flag('ufw-slow'):
    time.sleep(0.3)
if args == ['status']:
    print('Status: active\n\nTo   Action   From' if st['active'] else 'Status: inactive')
    sys.exit(0)
if args == ['status', 'verbose']:
    print('Status: active\nLogging: on (low)\nDefault: %s (incoming), allow (outgoing), disabled (routed)'
          % st['default'] if st['active'] else 'Status: inactive')
    sys.exit(0)
if args == ['show', 'added']:
    if flag('ufw-list-fails'):
        print('ERROR: fake listing failure', file=sys.stderr)
        sys.exit(1)
    print("Added user rules (see 'ufw status' for running firewall):")
    lines = list(st['lines']) + ['ufw allow from %s to any port %s proto tcp%s' % (
        r['src'], r['port'], " comment '%s'" % r['comment'] if r['comment'] else '') for r in st['rules']]
    print('\n'.join(lines) if lines else '(None)')
    sys.exit(0)
remove = args[:1] == ['delete']
spec = args[1:] if remove else list(args)
comment = ''
if 'comment' in spec:
    i = spec.index('comment')
    comment = spec[i + 1]
    spec = spec[:i] + spec[i + 2:]
if len(spec) != 9 or spec[:4] != ['allow', 'proto', 'tcp', 'from'] or spec[5:8] != ['to', 'any', 'port']:
    print('ERROR: the fake ufw does not know this rule', file=sys.stderr)
    sys.exit(1)
src, port = spec[4], spec[8]
if not remove:
    count = os.path.join(HERE, 'ufw-adds')
    n = (int(open(count).read()) if os.path.exists(count) else 0) + 1
    with open(count, 'w') as fh:
        fh.write(str(n))
    fail = os.path.join(HERE, 'ufw-fail-at')
    if os.path.exists(fail) and int(open(fail).read()) == n:
        print('ERROR: fake failure adding a rule', file=sys.stderr)
        sys.exit(1)
same = [r for r in st['rules'] if r['src'] == src and r['port'] == port]
if remove:
    hit = [r for r in same if r['comment'] == comment]
    if not hit:
        print('Could not delete non-existent rule')
        sys.exit(0)
    st['rules'].remove(hit[0])
    save()
    print('Rule deleted')
    sys.exit(0)
if same:
    if same[0]['comment'] == comment:
        print('Skipping adding existing rule')
    else:
        same[0]['comment'] = comment
        save()
        print('Rule updated')
    sys.exit(0)
st['rules'].append({'src': src, 'port': port, 'comment': comment})
save()
if flag('ufw-add-then-fail'):
    print('ERROR: fake failure after the rule went in', file=sys.stderr)
    sys.exit(1)
print('Rule added' + (' (v6)' if ':' in src else ''))
'''

FAKE_FIREWALLD = r'''#!PYTHON -I
import fcntl, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
lock = open(os.path.join(HERE, 'fake-fw.lock'), 'a')
fcntl.flock(lock, fcntl.LOCK_EX)
with open(os.path.join(HERE, 'fw.jsonl'), 'a') as fh:
    fh.write(json.dumps({'tool': 'firewall-cmd', 'argv': args}) + '\n')
path = os.path.join(HERE, 'firewalld.json')
with open(path) as fh:
    st = json.load(fh)


def save():
    with open(path, 'w') as fh:
        json.dump(st, fh)


if args == ['--state']:
    print('running' if st['running'] else 'not running')
    sys.exit(0 if st['running'] else 252)
if not st['running']:
    print('FirewallD is not running', file=sys.stderr)
    sys.exit(252)
if args == ['--get-default-zone']:
    print(st['default'])
    sys.exit(0)
perm = '--permanent' in args
zone = next((a.split('=', 1)[1] for a in args if a.startswith('--zone=')), st['default'])
if zone not in st['zones']:
    print('Error: INVALID_ZONE: %s' % zone, file=sys.stderr)
    sys.exit(112)
z = st['zones'][zone]
key = 'perm' if perm else 'live'
if '--list-rich-rules' in args:
    print('\n'.join(z[key]))
    sys.exit(0)
if '--list-ports' in args:
    print(' '.join(z['ports']))
    sys.exit(0)
if '--get-target' in args:
    if not perm:
        print('Error: --get-target needs --permanent', file=sys.stderr)
        sys.exit(2)
    print(z['target'])
    sys.exit(0)
adds = [a.split('=', 1)[1] for a in args if a.startswith('--add-rich-rule=')]
drops = [a.split('=', 1)[1] for a in args if a.startswith('--remove-rich-rule=')]
fail = os.path.join(HERE, 'fwd-fail-' + key)
fail_at = int(open(fail).read()) if os.path.exists(fail) else -1
for n, rule in enumerate(adds):
    if n == fail_at:
        save()
        print('Error: INVALID_RULE: fake failure', file=sys.stderr)
        sys.exit(107)
    if rule in z[key]:
        print('Warning: ALREADY_ENABLED: %s' % rule, file=sys.stderr)
    else:
        z[key].append(rule)
for rule in drops:
    if rule in z[key]:
        z[key].remove(rule)
    else:
        print('Warning: NOT_ENABLED: %s' % rule, file=sys.stderr)
if adds or drops:
    save()
    print('success')
    sys.exit(0)
sys.exit(2)
'''

FAKE_NFT = r'''#!/bin/sh
HERE=$(dirname "$0")
echo "nft $*" >> "$HERE/calls.txt"
[ -f "$HERE/flag-nft-fails" ] && { echo "Error: fake" >&2; exit 1; }
[ "$*" = "list chains" ] && [ -f "$HERE/nft.txt" ] && cat "$HERE/nft.txt"
exit 0
'''

FAKE_IPTABLES = r'''#!/bin/sh
HERE=$(dirname "$0")
n=$(basename "$0")
echo "$n $*" >> "$HERE/calls.txt"
if [ -f "$HERE/flag-$n-drop" ]; then echo "-P INPUT DROP"; else echo "-P INPUT ACCEPT"; fi
echo "-A INPUT -i lo -j ACCEPT"
'''

FAKE_PVE_FIREWALL = r'''#!/bin/sh
HERE=$(dirname "$0")
echo "pve-firewall $*" >> "$HERE/calls.txt"
if [ -f "$HERE/flag-pvefw-enabled" ]; then echo "Status: enabled/running"; else echo "Status: disabled/running"; fi
'''

# pve-firewall.service is active only where the test says so
SYSTEMCTL = FAKE_SYSTEMCTL.replace(
    'case " $* " in *corosync-qnetd*)',
    'case " $* " in *pve-firewall*) [ -f "$HERE/state-pvefw" ] && exit 0; exit 3 ;; esac\n'
    'case " $* " in *corosync-qnetd*)', 1)

NFT_DROP = '''table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy drop;
\t}
}
'''


class FwHost(FakeBins):
    """A QNetd host of the test with the firewall stand-ins it is given."""

    def __init__(self, base):
        FakeBins.__init__(self, base)
        self.write('systemctl', SYSTEMCTL)
        self.state = os.path.join(self.base, 'state')

    def env(self, **extra):
        env = FakeBins.env(self, **extra)
        env.setdefault('PEGAPROX_QNETD_STATE_DIR', self.state)
        return env

    @property
    def state_file(self):
        return os.path.join(self.state, 'firewall.json')

    def ufw(self, active=True, default='deny', rules=(), lines=()):
        self.write('ufw', FAKE_UFW)
        self.put_json('ufw.json', {'active': active, 'default': default, 'rules': list(rules),
                                   'lines': list(lines)})

    def firewalld(self, zone='public', perm=(), live=(), ports=(), target='default', running=True):
        self.write('firewall-cmd', FAKE_FIREWALLD)
        self.put_json('firewalld.json', {'running': running, 'default': zone, 'zones': {
            zone: {'perm': list(perm), 'live': list(live), 'ports': list(ports), 'target': target}}})

    def put_json(self, name, obj):
        with open(os.path.join(self.bin, name), 'w') as fh:
            json.dump(obj, fh)

    def get_json(self, name):
        with open(os.path.join(self.bin, name)) as fh:
            return json.load(fh)

    def ufw_rules(self):
        return self.get_json('ufw.json')['rules']

    def zone(self, name='public'):
        return self.get_json('firewalld.json')['zones'][name]

    def fw_calls(self, tool=None):
        return [r['argv'] for r in self.jsonl('fw.jsonl') if tool is None or r['tool'] == tool]

    def changes(self):
        """The calls that change a firewall."""
        out = []
        for argv in self.fw_calls():
            if argv[:1] in (['allow'], ['delete']) or any(a.startswith(('--add-', '--remove-')) for a in argv):
                out.append(argv)
        return out

    def fw(self, name='pve', env=None, **req):
        return self.helper('firewall', '--name', name, stdin=req, env=env)

    def saved(self):
        with open(self.state_file) as fh:
            return json.load(fh)


@pytest.fixture
def fw(tmp_path):
    return FwHost(tmp_path)


def ufw_add(src, port=5403, name='pve'):
    return ['allow', 'proto', 'tcp', 'from', src, 'to', 'any', 'port', str(port), 'comment', 'pegaprox-qnetd ' + name]


def rich(src, port=5403):
    return 'rule family="%s" source address="%s" port port="%d" protocol="tcp" accept' % (
        'ipv6' if ':' in src else 'ipv4', src, port)


# --- inspect ---------------------------------------------------------------------------------

def test_inspect_without_a_firewall_changes_nothing(fw):
    rc, ans = fw.fw(action='inspect')
    assert rc == 0, ans
    assert ans == {'ok': True, 'backend': 'none', 'managed': False, 'port': 5403, 'blocking': False,
                   'rules': [], 'added': [], 'removed': [], 'manual': ''}
    # read-only: not even the state directory is made
    assert not os.path.exists(fw.state)


def test_inspect_names_ufw_and_whether_it_blocks(fw):
    fw.ufw()
    rc, ans = fw.fw(action='inspect')
    assert rc == 0 and ans['backend'] == 'ufw' and ans['managed'] is True and ans['blocking'] is True
    assert ans['manual'] == ''
    fw.ufw(lines=['ufw allow 5403/tcp'])
    assert fw.fw(action='inspect')[1]['blocking'] is False
    fw.ufw(default='allow')
    assert fw.fw(action='inspect')[1]['blocking'] is False
    fw.ufw(active=False)
    assert fw.fw(action='inspect')[1]['backend'] == 'none'
    assert not fw.changes()


def test_inspect_names_firewalld_before_ufw(fw):
    fw.ufw()
    fw.firewalld()
    rc, ans = fw.fw(action='inspect')
    assert rc == 0 and ans['backend'] == 'firewalld' and ans['managed'] is True and ans['blocking'] is True
    fw.firewalld(target='ACCEPT')
    assert fw.fw(action='inspect')[1]['blocking'] is False
    fw.firewalld(ports=['22/tcp', '5403/tcp'])
    assert fw.fw(action='inspect')[1]['blocking'] is False
    fw.firewalld(running=False)
    assert fw.fw(action='inspect')[1]['backend'] == 'ufw'


def test_inspect_and_the_request_say_which_cluster_the_rules_are_of(fw):
    fw.ufw()
    assert fw.fw('a', action='allow', sources=['192.0.2.11'])[0] == 0
    assert fw.fw('b', action='allow', sources=['192.0.2.21'])[0] == 0
    assert fw.fw('a', action='inspect')[1]['rules'] == [{'source': '192.0.2.11', 'port': 5403}]
    assert fw.fw('b', action='inspect')[1]['rules'] == [{'source': '192.0.2.21', 'port': 5403}]
    assert fw.fw('c', action='inspect')[1]['rules'] == []


# --- the request -----------------------------------------------------------------------------

@pytest.mark.parametrize('req', [
    {}, {'action': 'open'}, {'action': 7}, {'action': ['allow']},
    {'action': 'inspect', 'sources': []}, {'action': 'inspect', 'sources': ['192.0.2.11']},
    {'action': 'allow'}, {'action': 'allow', 'sources': []}, {'action': 'allow', 'sources': '192.0.2.11'},
    {'action': 'allow', 'sources': ['192.0.2.11'], 'port': 22},
    {'action': 'allow', 'sources': ['192.0.2.11'], 'proto': 'udp'},
    {'action': 'remove', 'sources': None}, {'action': 'remove', 'zone': 'trusted'},
])
def test_a_request_of_another_shape_is_refused(fw, req):
    fw.ufw()
    rc, ans = fw.fw(**req)
    assert rc == 1 and ans['code'] == 'bad_request', ans
    assert not fw.changes() and not os.path.exists(fw.state)


@pytest.mark.parametrize('source', [
    '192.0.2.0/24', '2001:db8::/64', 'qnetd.example.com', 'localhost', '0.0.0.0', '::', '127.0.0.1', '::1',
    '::ffff:127.0.0.1', '224.0.0.1', 'ff02::1', 'fe80::1%eth0', 'fe80::1%eth0 port 22', ' 192.0.2.11',
    '192.0.2.11 ', '192.0.2.011', '01.2.3.4', '192.0.2.256', '1.2.3', '', 5, None, ['192.0.2.11'],
    {'source': '192.0.2.11'}, "192.0.2.11' accept", '192.0.2.11" accept', 'a' * 100, '192.0.2.11\n',
])
def test_a_source_that_is_not_one_plain_address_is_refused(fw, source):
    fw.ufw()
    rc, ans = fw.fw(action='allow', sources=['192.0.2.10', source])
    assert rc == 1 and ans['code'] == 'bad_request', ans
    assert not fw.changes()


def test_at_most_64_sources(fw):
    fw.ufw()
    many = ['192.0.2.%d' % n for n in range(1, 66)]
    rc, ans = fw.fw(action='allow', sources=many)
    assert rc == 1 and ans['code'] == 'bad_request' and '64' in ans['error']
    assert not fw.changes()


def test_the_name_is_the_tag_and_has_to_be_a_cluster_name(fw):
    fw.ufw()
    for name in ('x;id', '-pve', 'a' * 16, 'pve$(id)', 'p ve'):
        rc, ans = fw.fw(name, action='inspect')
        assert rc == 1 and ans['code'] == 'bad_request', name
    rc, ans = fw.helper('firewall', stdin={'action': 'inspect'})
    assert rc == 1 and ans['code'] == 'bad_request'


# --- the port --------------------------------------------------------------------------------

def _defaults(fw, text, mode=0o644, where='default'):
    path = os.path.join(fw.base, 'etc', where, 'corosync-qnetd')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as fh:
        fh.write(text)
    os.chmod(path, mode)
    return path


def test_the_port_is_corosync_qnetds_own_never_the_requests(fw):
    fw.ufw()
    _defaults(fw, '# options\nCOROSYNC_QNETD_OPTIONS="-s req -p 5999"\n')
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'], port=22)
    assert rc == 1 and ans['code'] == 'bad_request' and not fw.changes()
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 0 and ans['port'] == 5999, ans
    assert fw.changes() == [ufw_add('192.0.2.11', 5999)]
    assert ans['added'] == [{'source': '192.0.2.11', 'port': 5999}]
    # in a group of options, and on RHEL in /etc/sysconfig
    os.unlink(os.path.join(fw.base, 'etc', 'default', 'corosync-qnetd'))
    _defaults(fw, 'COROSYNC_QNETD_OPTIONS="-dp 6001"\nCOROSYNC_QNETD_RUNAS="coroqnetd"\n', where='sysconfig')
    assert fw.fw(action='inspect')[1]['port'] == 6001


@pytest.mark.parametrize('text,mode', [
    ('COROSYNC_QNETD_OPTIONS="-p 22"\n', 0o664),             # group could have written it
    ('COROSYNC_QNETD_OPTIONS="-p 22"\n', 0o646),
    ('COROSYNC_QNETD_OPTIONS="$(cat /etc/port)"\n', 0o644),  # not plain
    ('COROSYNC_QNETD_OPTIONS="-p"\n', 0o644),
    ('COROSYNC_QNETD_OPTIONS="-p 70000"\n', 0o644),
    ('COROSYNC_QNETD_OPTIONS="-p ssh"\n', 0o644),
])
def test_a_port_that_cannot_be_told_plainly_opens_nothing(fw, text, mode):
    fw.ufw()
    _defaults(fw, text, mode)
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 1 and ans['ok'] is False, ans
    assert not fw.changes()


def test_a_symlinked_options_file_is_not_followed(fw):
    fw.ufw()
    real = os.path.join(fw.base, 'elsewhere')
    with open(real, 'w') as fh:
        fh.write('COROSYNC_QNETD_OPTIONS="-p 22"\n')
    os.makedirs(os.path.join(fw.base, 'etc', 'default'))
    os.symlink(real, os.path.join(fw.base, 'etc', 'default', 'corosync-qnetd'))
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 1 and not fw.changes()


# --- ufw ---------------------------------------------------------------------------------------

def test_ufw_allow_adds_one_rule_per_source_and_writes_each_down(fw):
    fw.ufw(lines=['ufw allow 22/tcp'])
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11', '::ffff:192.0.2.12', '2001:DB8::13', '192.0.2.11'])
    assert rc == 0, ans
    # IPv4-mapped as IPv4, IPv6 canonical, the duplicate dropped; argv lists, nothing else
    assert fw.changes() == [ufw_add('192.0.2.11'), ufw_add('192.0.2.12'), ufw_add('2001:db8::13')]
    want = [{'source': '192.0.2.11', 'port': 5403}, {'source': '192.0.2.12', 'port': 5403},
            {'source': '2001:db8::13', 'port': 5403}]
    assert ans['added'] == want and ans['rules'] == want and ans['removed'] == []
    assert ans['backend'] == 'ufw' and ans['managed'] is True and ans['manual'] == ''
    assert fw.saved() == {'pve': [dict(r, backend='ufw') for r in want]}
    assert oct(os.stat(fw.state).st_mode & 0o777) == '0o700'
    assert oct(os.stat(fw.state_file).st_mode & 0o777) == '0o600'
    # once more: they are there, nothing is added
    n = len(fw.changes())
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11', '192.0.2.12'])
    assert rc == 0 and ans['added'] == [] and len(fw.changes()) == n
    assert [f for f in os.listdir(fw.state)] == ['firewall.json']


def test_remove_takes_out_what_it_added_and_nothing_else(fw):
    admin = [{'src': '192.0.2.50', 'port': '5403', 'comment': 'monitoring'}]
    fw.ufw(rules=admin, lines=['ufw allow 22/tcp'])
    assert fw.fw(action='allow', sources=['192.0.2.11', '192.0.2.12'])[0] == 0
    n = len(fw.changes())
    rc, ans = fw.fw(action='remove')
    assert rc == 0, ans
    assert fw.changes()[n:] == [['delete'] + ufw_add('192.0.2.11'), ['delete'] + ufw_add('192.0.2.12')]
    assert fw.ufw_rules() == admin
    assert ans['removed'] == [{'source': '192.0.2.11', 'port': 5403}, {'source': '192.0.2.12', 'port': 5403}]
    assert ans['rules'] == [] and fw.saved() == {}
    # nothing left to take out: no call at all
    n = len(fw.changes())
    assert fw.fw(action='remove')[0] == 0 and len(fw.changes()) == n


def test_remove_with_sources_takes_out_only_those_and_an_empty_list_nothing(fw):
    fw.ufw()
    assert fw.fw(action='allow', sources=['192.0.2.11', '192.0.2.12', '192.0.2.13'])[0] == 0
    n = len(fw.changes())
    rc, ans = fw.fw(action='remove', sources=[])
    assert rc == 0 and ans['removed'] == [] and len(fw.changes()) == n
    rc, ans = fw.fw(action='remove', sources=['192.0.2.12', '192.0.2.99'])
    assert rc == 0 and ans['removed'] == [{'source': '192.0.2.12', 'port': 5403}]
    assert fw.changes()[n:] == [['delete'] + ufw_add('192.0.2.12')]
    assert [r['src'] for r in fw.ufw_rules()] == ['192.0.2.11', '192.0.2.13']


@pytest.mark.parametrize('comment', ['', 'mine', 'pegaprox-qnetd pve'])
def test_an_admins_identical_rule_is_neither_taken_over_nor_deleted(fw, comment):
    """ufw would take an identical rule over (its comment replaced by the helper's), and
    delete it with the helper's: the helper adds nothing next to it and writes nothing
    down - also where the comment looks like its own, since no record says it is."""
    admin = [{'src': '192.0.2.11', 'port': '5403', 'comment': comment}]
    fw.ufw(rules=admin)
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11', '192.0.2.12'])
    assert rc == 0, ans
    assert ans['already'] == ['192.0.2.11'] and ans['added'] == [{'source': '192.0.2.12', 'port': 5403}]
    assert fw.changes() == [ufw_add('192.0.2.12')]
    assert fw.ufw_rules()[0] == admin[0]
    rc, ans = fw.fw(action='remove')
    assert rc == 0
    assert [c for c in fw.changes() if c[0] == 'delete'] == [['delete'] + ufw_add('192.0.2.12')]
    assert fw.ufw_rules() == admin


@pytest.mark.parametrize('comment', ['mine', 'pegaprox-qnetd pve'])
def test_a_rule_ufw_skips_or_updates_is_not_taken_as_the_helpers(fw, comment):
    # ufw holds a rule of this shape that its listing does not show in a form the helper
    # reads: ufw itself says so on the add (Rule updated, Skipping), and nothing is written down
    fw.ufw(rules=[{'src': '192.0.2.11', 'port': '5403', 'comment': comment}])
    fw.write('ufw', FAKE_UFW.replace("if args == ['show', 'added']:",
                                     "if args == ['show', 'added']:\n    print('(None)')\n    sys.exit(0)\nif False:"))
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 0 and ans['already'] == ['192.0.2.11'] and ans['added'] == [], ans
    assert not os.path.exists(fw.state_file)


def test_a_rule_line_the_helper_cannot_read_is_left_to_the_admin(fw):
    # ufw writes a comment with a quote in it as it is: the line does not parse, and the
    # rule in it may be the very one the helper would add (and ufw take over)
    fw.ufw(lines=["ufw allow from 192.0.2.11 to any port 5403 proto tcp comment 'the admin's'"])
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11', '192.0.2.12'])
    assert rc == 0 and ans['already'] == ['192.0.2.11'], ans
    assert fw.changes() == [ufw_add('192.0.2.12')]


def test_a_rule_that_went_in_before_ufw_failed_is_written_down(fw):
    fw.ufw()
    fw.flag('flag-ufw-add-then-fail')
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 1 and ans['code'] == 'firewall_failed', ans
    assert fw.saved() == {'pve': [{'source': '192.0.2.11', 'port': 5403, 'backend': 'ufw'}]}
    fw.flag('flag-ufw-add-then-fail', on=False)
    assert fw.fw(action='remove')[0] == 0 and fw.ufw_rules() == []


def test_a_source_two_clusters_share_stays_until_the_last_one_goes(fw):
    fw.ufw()
    assert fw.fw('alpha', action='allow', sources=['192.0.2.11'])[0] == 0
    rc, ans = fw.fw('beta', action='allow', sources=['192.0.2.11', '192.0.2.21'])
    assert rc == 0 and ans['added'] == [{'source': '192.0.2.11', 'port': 5403}, {'source': '192.0.2.21', 'port': 5403}]
    # one rule for 192.0.2.11, added for alpha
    assert fw.changes() == [ufw_add('192.0.2.11', name='alpha'), ufw_add('192.0.2.21', name='beta')]
    rc, ans = fw.fw('alpha', action='remove')
    assert rc == 0 and ans['removed'] == [{'source': '192.0.2.11', 'port': 5403}]
    assert ans['kept'] == [{'source': '192.0.2.11', 'port': 5403}]
    assert not [c for c in fw.changes() if c[0] == 'delete']
    assert sorted(r['src'] for r in fw.ufw_rules()) == ['192.0.2.11', '192.0.2.21']
    assert set(fw.saved()) == {'beta'}
    rc, ans = fw.fw('beta', action='remove')
    assert rc == 0
    # deleted with the comment it carries, the one of alpha
    assert [c for c in fw.changes() if c[0] == 'delete'] == [['delete'] + ufw_add('192.0.2.11', name='alpha'),
                                                              ['delete'] + ufw_add('192.0.2.21', name='beta')]
    assert fw.ufw_rules() == [] and fw.saved() == {}


def test_a_rule_someone_gave_another_comment_is_theirs_and_stays(fw):
    fw.ufw()
    assert fw.fw(action='allow', sources=['192.0.2.11'])[0] == 0
    state = fw.get_json('ufw.json')
    state['rules'][0]['comment'] = 'kept by the admin'
    fw.put_json('ufw.json', state)
    rc, ans = fw.fw(action='remove')
    assert rc == 0 and ans['kept'] == [{'source': '192.0.2.11', 'port': 5403}]
    assert not [c for c in fw.changes() if c[0] == 'delete']
    assert fw.ufw_rules()[0]['comment'] == 'kept by the admin' and fw.saved() == {}


def test_a_rule_deleted_by_hand_is_put_back_on_allow(fw):
    fw.ufw()
    assert fw.fw(action='allow', sources=['192.0.2.11'])[0] == 0
    fw.ufw()                                    # the admin flushed ufw
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 0 and ans['added'] == [] and ans['rules'] == [{'source': '192.0.2.11', 'port': 5403}]
    assert fw.changes() == [ufw_add('192.0.2.11'), ufw_add('192.0.2.11')]
    assert len(fw.saved()['pve']) == 1


def test_ufw_failing_halfway_keeps_what_it_added_written_down(fw):
    fw.ufw()
    with open(os.path.join(fw.bin, 'ufw-fail-at'), 'w') as fh:
        fh.write('2')
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11', '192.0.2.12', '192.0.2.13'])
    assert rc == 1 and ans['code'] == 'firewall_failed' and 'fake failure' in ans['error'], ans
    assert fw.saved() == {'pve': [{'source': '192.0.2.11', 'port': 5403, 'backend': 'ufw'}]}
    # what it added goes with the removal (the rollback of a failed setup)
    rc, ans = fw.fw(action='remove', sources=['192.0.2.11'])
    assert rc == 0 and fw.ufw_rules() == [] and fw.saved() == {}


def test_a_failed_removal_keeps_the_record(fw):
    fw.ufw()
    assert fw.fw(action='allow', sources=['192.0.2.11'])[0] == 0
    fw.flag('flag-ufw-list-fails')
    rc, ans = fw.fw(action='remove')
    assert rc == 1 and ans['code'] == 'firewall_failed'
    assert fw.saved() == {'pve': [{'source': '192.0.2.11', 'port': 5403, 'backend': 'ufw'}]}
    fw.flag('flag-ufw-list-fails', on=False)
    assert fw.fw(action='remove')[0] == 0 and fw.ufw_rules() == []


def test_ufw_gone_takes_its_rules_with_it(fw):
    fw.ufw()
    assert fw.fw(action='allow', sources=['192.0.2.11'])[0] == 0
    os.unlink(os.path.join(fw.bin, 'ufw'))
    rc, ans = fw.fw(action='remove')
    assert rc == 0 and ans['removed'] == [{'source': '192.0.2.11', 'port': 5403}] and fw.saved() == {}


# --- firewalld ---------------------------------------------------------------------------------

def test_firewalld_gets_permanent_and_live_rich_rules_in_the_default_zone(fw):
    fw.firewalld(zone='internal', perm=['rule family="ipv4" source address="10.0.0.0/8" accept'])
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11', '2001:db8::13'])
    assert rc == 0, ans
    assert ans['backend'] == 'firewalld' and ans['managed'] is True and ans['manual'] == ''
    adds = [c for c in fw.changes()]
    assert adds == [
        ['--permanent', '--zone=internal', '--add-rich-rule=' + rich('192.0.2.11'),
         '--add-rich-rule=' + rich('2001:db8::13')],
        ['--zone=internal', '--add-rich-rule=' + rich('192.0.2.11'), '--add-rich-rule=' + rich('2001:db8::13')],
    ]
    # no reload: that would drop runtime rules of the admin
    assert not [c for c in fw.fw_calls('firewall-cmd') if '--reload' in c]
    z = fw.zone('internal')
    assert z['perm'][1:] == [rich('192.0.2.11'), rich('2001:db8::13')] and z['live'] == z['perm'][1:]
    assert fw.saved() == {'pve': [{'source': '192.0.2.11', 'port': 5403, 'backend': 'firewalld', 'zone': 'internal'},
                                  {'source': '2001:db8::13', 'port': 5403, 'backend': 'firewalld', 'zone': 'internal'}]}
    rc, ans = fw.fw(action='remove')
    assert rc == 0, ans
    z = fw.zone('internal')
    assert z['perm'] == ['rule family="ipv4" source address="10.0.0.0/8" accept'] and z['live'] == []
    assert fw.saved() == {}


def test_firewalld_leaves_an_admins_identical_rich_rule_alone(fw):
    fw.firewalld(perm=[rich('192.0.2.11')], live=[rich('192.0.2.11')])
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 0 and ans['already'] == ['192.0.2.11'] and ans['added'] == []
    assert not fw.changes()
    assert fw.fw(action='remove')[0] == 0
    assert not fw.changes() and fw.zone()['perm'] == [rich('192.0.2.11')]


def test_firewalld_failing_halfway_writes_down_what_it_took(fw):
    fw.firewalld()
    with open(os.path.join(fw.bin, 'fwd-fail-perm'), 'w') as fh:
        fh.write('1')
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11', '192.0.2.12'])
    assert rc == 1 and ans['code'] == 'firewall_failed', ans
    assert fw.zone()['perm'] == [rich('192.0.2.11')]
    assert fw.saved() == {'pve': [{'source': '192.0.2.11', 'port': 5403, 'backend': 'firewalld', 'zone': 'public'}]}
    os.unlink(os.path.join(fw.bin, 'fwd-fail-perm'))
    assert fw.fw(action='remove')[0] == 0
    assert fw.zone()['perm'] == [] and fw.saved() == {}


def test_firewalld_rules_go_from_the_zone_they_were_added_to(fw):
    fw.firewalld(zone='internal')
    assert fw.fw(action='allow', sources=['192.0.2.11'])[0] == 0
    state = fw.get_json('firewalld.json')
    state['default'] = 'public'
    state['zones']['public'] = {'perm': [], 'live': [], 'ports': [], 'target': 'default'}
    fw.put_json('firewalld.json', state)
    assert fw.fw(action='remove')[0] == 0
    assert fw.zone('internal')['perm'] == [] and fw.zone('internal')['live'] == []


def test_firewalld_not_running_keeps_the_records(fw):
    fw.firewalld()
    assert fw.fw(action='allow', sources=['192.0.2.11'])[0] == 0
    state = fw.get_json('firewalld.json')
    state['running'] = False
    fw.put_json('firewalld.json', state)
    rc, ans = fw.fw(action='remove')
    assert rc == 1 and ans['code'] == 'firewall_failed'
    assert len(fw.saved()['pve']) == 1


# --- firewalls the helper does not change ---------------------------------------------------------

def test_nftables_with_a_policy_of_drop_gets_the_lines_to_run(fw):
    fw.write('nft', FAKE_NFT)
    with open(os.path.join(fw.bin, 'nft.txt'), 'w') as fh:
        fh.write(NFT_DROP)
    rc, ans = fw.fw(action='inspect')
    assert rc == 0 and ans['backend'] == 'nftables' and ans['managed'] is False and ans['blocking'] is True
    assert 'nft insert rule inet filter input ip saddr <node address> tcp dport 5403 accept' in ans['manual']
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11', '2001:db8::13'])
    assert rc == 1 and ans['code'] == 'firewall_unmanaged', ans
    lines = ans['manual'].splitlines()
    assert 'nft insert rule inet filter input ip saddr 192.0.2.11 tcp dport 5403 accept' in lines
    assert 'nft insert rule inet filter input ip6 saddr 2001:db8::13 tcp dport 5403 accept' in lines
    assert lines[0] in ans['error'] and ans['backend'] == 'nftables' and ans['port'] == 5403
    # the forward chain is no business of the QNetd
    assert not [ln for ln in lines if ' forward ' in ln]
    assert not os.path.exists(fw.state_file)


def test_iptables_with_a_policy_of_drop_gets_the_lines_to_run(fw):
    fw.write('iptables', FAKE_IPTABLES)
    fw.write('ip6tables', FAKE_IPTABLES)
    rc, ans = fw.fw(action='inspect')
    assert rc == 0 and ans['backend'] == 'none' and ans['blocking'] is False
    fw.flag('flag-iptables-drop')
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11', '2001:db8::13'])
    assert rc == 1 and ans['code'] == 'firewall_unmanaged' and ans['backend'] == 'iptables'
    assert 'iptables -I INPUT -p tcp -s 192.0.2.11 --dport 5403 -j ACCEPT' in ans['manual'].splitlines()
    # ip6tables lets IPv6 through: no line for it
    assert not [ln for ln in ans['manual'].splitlines() if ln.startswith('ip6tables ')]


def test_pve_firewall_gets_the_host_fw_lines(fw):
    fw.write('pve-firewall', FAKE_PVE_FIREWALL)
    fw.ufw()                                    # never reached: pve-firewall comes first
    rc, ans = fw.fw(action='inspect')
    assert rc == 0 and ans['backend'] == 'ufw'      # the service does not run
    fw.flag('state-pvefw')
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 0 and ans['backend'] == 'pve-firewall' and ans['blocking'] is False and ans['added'] == []
    assert 'IN ACCEPT -source 192.0.2.11 -p tcp -dport 5403 # pegaprox-qnetd pve' in ans['manual']
    fw.flag('flag-pvefw-enabled')
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 1 and ans['code'] == 'firewall_unmanaged' and ans['blocking'] is True
    assert '/host.fw' in ans['manual']
    assert not fw.changes()


def test_no_firewall_allows_without_adding_anything(fw):
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 0 and ans['backend'] == 'none' and ans['added'] == [] and ans['manual'] == ''
    assert not os.path.exists(fw.state_file)


# --- where the op does not run -----------------------------------------------------------------

def test_the_sidecar_refuses(fw):
    side = H.Host('sidecar', fw.env())
    for req in ({'action': 'inspect'}, {'action': 'allow', 'sources': ['192.0.2.11']}):
        ans = H.dispatch(side, 'firewall', 'pve', req)
        assert ans['ok'] is False and ans['code'] == 'not_supported'
        assert 'Docker publishes port 5403 itself' in ans['error']
    # and through its socket line
    ans = H.handle_line(side, b'{"op": "firewall", "name": "pve", "action": "inspect"}')
    assert ans['code'] == 'not_supported'
    assert not os.path.exists(fw.state)


def test_a_host_without_systemd_refuses(fw):
    fw.ufw()
    os.unlink(os.path.join(fw.bin, 'systemctl'))
    rc, ans = fw.fw(action='allow', sources=['192.0.2.11'])
    assert rc == 1 and ans['code'] == 'not_supported' and not fw.changes()


def test_the_line_protocol_of_the_socket_carries_the_request(fw):
    fw.ufw()
    host = H.Host('systemd', fw.env())
    ans = H.handle_line(host, json.dumps({'op': 'firewall', 'name': 'pve', 'action': 'allow',
                                          'sources': ['192.0.2.11']}).encode())
    assert ans['ok'] is True and ans['added'] == [{'source': '192.0.2.11', 'port': 5403}], ans
    ans = H.handle_line(host, b'{"op": "firewall", "name": "pve", "action": "allow", "sources": ["192.0.2.11"], '
                              b'"port": 22}')
    assert ans['code'] == 'bad_request'


def test_the_state_directory_override_is_for_an_unprivileged_run_only(monkeypatch):
    assert 'PEGAPROX_QNETD_STATE_DIR' in H.OVERRIDES
    monkeypatch.setattr(H.os, 'geteuid', lambda: 0)
    with pytest.raises(H.Refused):
        H.Host('systemd', {'PEGAPROX_QNETD_STATE_DIR': '/tmp/evil'})
    assert H.Host('systemd', {}).state_dir == '/var/lib/pegaprox-qnetd'


def test_installsh_unsets_the_state_override():
    with open(os.path.join(os.path.dirname(HELPER), 'install.sh')) as fh:
        text = fh.read()
    unset = text[text.index('    unset PEGAPROX_QNETD_CONFIG_DIR'):]
    assert 'PEGAPROX_QNETD_STATE_DIR' in unset[:unset.index('|| true')]


# --- the state file ------------------------------------------------------------------------------

GOOD = {'pve': [{'source': '192.0.2.11', 'port': 5403, 'backend': 'ufw'}]}


def _plant(fw, how):
    os.makedirs(fw.state, mode=0o700, exist_ok=True)
    os.chmod(fw.state, 0o700)
    data = json.dumps(GOOD)
    if how == 'file-symlink':
        other = os.path.join(fw.base, 'elsewhere.json')
        with open(other, 'w') as fh:
            fh.write(data)
        os.chmod(other, 0o600)
        os.symlink(other, fw.state_file)
        return other
    if how == 'dir-symlink':
        os.rmdir(fw.state)
        real = os.path.join(fw.base, 'real-state')
        os.makedirs(real, mode=0o700)
        os.symlink(real, fw.state)
        return real
    if how == 'dir-mode':
        os.chmod(fw.state, 0o755)
        return None
    if how == 'hardlink':
        with open(fw.state_file, 'w') as fh:
            fh.write(data)
        os.chmod(fw.state_file, 0o600)
        os.link(fw.state_file, os.path.join(fw.base, 'second-name'))
        return None
    if how == 'not-a-file':
        os.mkdir(fw.state_file)
        return None
    texts = {
        'file-mode': (data, 0o644),
        'damaged': ('{"pve": [', 0o600),
        'not-an-object': ('[1, 2]', 0o600),
        'a-network': (json.dumps({'pve': [{'source': '192.0.2.0/24', 'port': 5403, 'backend': 'ufw'}]}), 0o600),
        'not-canonical': (json.dumps({'pve': [{'source': '2001:DB8::1', 'port': 5403, 'backend': 'ufw'}]}), 0o600),
        'loopback': (json.dumps({'pve': [{'source': '127.0.0.1', 'port': 5403, 'backend': 'ufw'}]}), 0o600),
        'port-text': (json.dumps({'pve': [{'source': '192.0.2.11', 'port': '22', 'backend': 'ufw'}]}), 0o600),
        'port-bool': (json.dumps({'pve': [{'source': '192.0.2.11', 'port': True, 'backend': 'ufw'}]}), 0o600),
        'port-zero': (json.dumps({'pve': [{'source': '192.0.2.11', 'port': 0, 'backend': 'ufw'}]}), 0o600),
        'backend': (json.dumps({'pve': [{'source': '192.0.2.11', 'port': 5403, 'backend': 'nftables'}]}), 0o600),
        'extra-key': (json.dumps({'pve': [dict(GOOD['pve'][0], cmd='rm -rf /')]}), 0o600),
        'zone-missing': (json.dumps({'pve': [{'source': '192.0.2.11', 'port': 5403, 'backend': 'firewalld'}]}), 0o600),
        'zone-odd': (json.dumps({'pve': [{'source': '192.0.2.11', 'port': 5403, 'backend': 'firewalld',
                                          'zone': 'a b'}]}), 0o600),
        'tag': (json.dumps({'x;id': GOOD['pve']}), 0o600),
        'twice': (json.dumps({'pve': GOOD['pve'] * 2}), 0o600),
        'empty': ('', 0o600),
    }
    text, mode = texts[how]
    with open(fw.state_file, 'w') as fh:
        fh.write(text)
    os.chmod(fw.state_file, mode)
    return None


@pytest.mark.parametrize('how', [
    'file-symlink', 'dir-symlink', 'dir-mode', 'hardlink', 'not-a-file', 'file-mode', 'damaged', 'not-an-object',
    'a-network', 'not-canonical', 'loopback', 'port-text', 'port-bool', 'port-zero', 'backend', 'extra-key',
    'zone-missing', 'zone-odd', 'tag', 'twice', 'empty',
])
def test_a_state_that_is_not_the_helpers_stops_every_change(fw, how):
    fw.ufw(rules=[{'src': '192.0.2.11', 'port': '5403', 'comment': 'pegaprox-qnetd pve'}])
    target = _plant(fw, how)
    before = open(target).read() if target and os.path.isfile(target) else None
    for req in ({'action': 'allow', 'sources': ['192.0.2.12']}, {'action': 'remove'}, {'action': 'inspect'}):
        rc, ans = fw.fw(**req)
        assert rc == 1 and ans['code'] == 'state_untrusted', (how, req, ans)
    assert not fw.changes()
    assert fw.ufw_rules() == [{'src': '192.0.2.11', 'port': '5403', 'comment': 'pegaprox-qnetd pve'}]
    if before is not None:
        assert open(target).read() == before
    if how == 'dir-symlink':
        assert os.listdir(target) == []


def test_a_state_directory_of_another_user_is_refused(fw, monkeypatch):
    fw.ufw()
    assert fw.fw(action='allow', sources=['192.0.2.11'])[0] == 0
    host = H.Host('systemd', fw.env())
    me = os.geteuid()
    monkeypatch.setattr(H.os, 'geteuid', lambda: me + 1)
    ans = H.dispatch(host, 'firewall', 'pve', {'action': 'remove'})
    assert ans['code'] == 'state_untrusted' and 'not the helper' in ans['error']
    monkeypatch.undo()
    assert fw.ufw_rules()[0]['src'] == '192.0.2.11'


def _addrs(n, net):
    return ['10.%d.%d.%d' % (net, i // 250, i % 250 + 1) for i in range(n)]


def _seed(fw, state):
    os.makedirs(fw.state, mode=0o700, exist_ok=True)
    os.chmod(fw.state, 0o700)
    with open(fw.state_file, 'w') as fh:
        json.dump(state, fh)
    os.chmod(fw.state_file, 0o600)


def test_an_allow_past_what_one_name_may_hold_is_refused_before_any_rule(fw):
    """The helper reads back at most 256 rules per cluster name. Written down, a 257th
    would make the file one it refuses as damaged, and from then on every firewall op of
    the host is refused, the removal of these very rules included."""
    fw.firewalld()
    for net in range(1, 5):                            # 4 x 64: all one name holds
        rc, ans = fw.fw('pve', action='allow', sources=_addrs(64, net))
        assert rc == 0 and len(ans['added']) == 64, ans
    zone, saved = fw.zone(), fw.saved()
    rc, ans = fw.fw('pve', action='allow', sources=['10.1.0.1', '10.9.0.1'])
    assert rc == 1 and ans['code'] == 'state_full' and '256' in ans['error'], ans
    assert fw.zone() == zone and fw.saved() == saved
    # an address the name holds already is no new rule
    rc, ans = fw.fw('pve', action='allow', sources=['10.1.0.1'])
    assert rc == 0 and ans['added'] == [], ans
    # and the op goes on for the host: another name, then the removal of all 256
    assert fw.fw('other', action='allow', sources=['192.0.2.7'])[0] == 0
    rc, ans = fw.fw('pve', action='remove')
    assert rc == 0 and len(ans['removed']) == 256, ans
    assert set(fw.saved()) == {'other'}


def test_an_allow_for_a_name_past_the_most_names_is_refused(fw):
    fw.ufw()
    row = {'source': '192.0.2.1', 'port': 5403, 'backend': 'ufw'}
    _seed(fw, {'n%d' % i: [row] for i in range(10000)})
    rc, ans = fw.fw('pve', action='allow', sources=['192.0.2.9'])
    assert rc == 1 and ans['code'] == 'state_full', ans
    assert not fw.changes() and 'pve' not in fw.saved()
    # one of the names it holds still gets a rule
    rc, ans = fw.fw('n7', action='allow', sources=['192.0.2.9'])
    assert rc == 0 and [r['source'] for r in ans['added']] == ['192.0.2.9'], ans
    assert len(fw.saved()) == 10000


def test_room_measures_the_file_it_would_write(monkeypatch):
    row = {'source': '192.0.2.1', 'port': 5403, 'backend': 'ufw'}
    state = {'pve': [row]}
    new = dict(row, source='192.0.2.2')
    monkeypatch.setattr(H, 'MAX_STATE', len(H._state_bytes(dict(state, pve=[row, new]))))
    H._room(state, 'pve', [row, new])                 # just fits
    monkeypatch.setattr(H, 'MAX_STATE', H.MAX_STATE - 1)
    with pytest.raises(H.Refused) as e:
        H._room(state, 'pve', [row, new])
    assert e.value.code == 'state_full'
    H._room(state, 'pve', [row])                      # nothing new: nothing to measure
    # what _room lets through, the reader takes back
    assert H._check_state(json.loads(H._state_bytes(state)), 'x') == state


def test_concurrent_calls_lose_no_record(fw):
    """Two allows at once (two clusters set up in parallel): the lock on the state directory
    keeps the read, the change and the write of one from crossing the other's."""
    fw.ufw()
    fw.flag('flag-ufw-slow')
    procs = []
    for name, src in (('alpha', '192.0.2.11'), ('beta', '192.0.2.21'), ('gamma', '192.0.2.31')):
        procs.append(subprocess.Popen([sys.executable, '-I', HELPER, 'firewall', '--name', name],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=fw.env(), cwd=fw.base))
        procs[-1].stdin.write(json.dumps({'action': 'allow', 'sources': [src]}).encode())
        procs[-1].stdin.close()
    t = time.monotonic()
    for p in procs:
        out = p.stdout.read()
        assert p.wait(120) == 0, (out, p.stderr.read())
        p.stdout.close()
        p.stderr.close()
    assert time.monotonic() - t < 100
    assert sorted(fw.saved()) == ['alpha', 'beta', 'gamma']
    assert sorted(r['src'] for r in fw.ufw_rules()) == ['192.0.2.11', '192.0.2.21', '192.0.2.31']


# --- the source --------------------------------------------------------------------------------

def test_the_firewall_code_keeps_to_the_rules():
    with open(HELPER) as fh:
        text = fh.read()
    body = text[text.index('# --- the firewall (op firewall)'):text.index('HANDLERS = {')]
    # every tool through run() with a fixed path, never a shell or a port from the request
    assert 'subprocess' not in body and 'shell' not in body.replace('shlex', '')
    assert "req.get('port')" not in body and "req['port']" not in body
    for name in ('ufw', 'firewall-cmd', 'nft', 'iptables', 'ip6tables', 'pve-firewall'):
        assert H.BINARIES[name] and all(os.path.isabs(p) for p in H.BINARIES[name]), name
    assert H.REQUEST_KEYS['firewall'] == ('action', 'sources')
    assert 'firewall' in H.OPS and 'firewall' in H.NAMED_OPS


def test_the_op_ends_before_pegaprox_stops_waiting():
    # the lock of another run, then every tool call on one budget, then the answer
    from pegaprox.core import qnetd
    wait = qnetd.OP_TIMEOUT.get('firewall')
    if wait is None:
        pytest.skip('this PegaProx does not ask the firewall op yet')
    assert H.LOCK_WAIT_FIREWALL + H.T_FIREWALL_ALL + H.T_SHORT < wait
    assert H.T_FIREWALL <= H.T_FIREWALL_ALL
