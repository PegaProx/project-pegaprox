"""Warm standby for PegaProx itself (#625).

Up to four instances form a group: one ACTIVE and up to three STANDBYs. The active
runs as always. A standby keeps the UI up, pulls the shared configuration from the
active every few seconds, refuses writes and lets none of the background loops act.
An admin promotes a standby by hand. Every member follows the active with the
highest epoch, and an active that learns about a newer one steps down and becomes
its standby. Two actives under the same epoch (two admins promoting two standbys at
once) are settled by the instance id: the higher one stays, the other steps down.

The group is a star with the active in the middle. A standby pairs with the active,
never with another standby; the active hands the member list to every standby with
each snapshot, so they know each other by the time one of them is promoted.

Every instance has an Ed25519 key pair and signs each call to another member over
method, path, a digest of the body, the time, a nonce and the instance id of the
receiver; the member list carries the public keys. A captured call is worth nothing
at another member, and nothing at the same one after two minutes, a second time, or
once the receiver has restarted: the nonces it saw are memory only, so a call older
than its process is refused like one from outside the window. The members' clocks
have to agree within SIGNATURE_WINDOW. A pair from before the groups presented a
secret instead ('<id>:<secret>', the other side holding its hash): such a member is
still taken with that header until it has published a key, and an instance on this
release sends its key along with every such call until the other side says it holds
it (_auth_for). The key is taken that way only from the partner of such a pair, the
one other instance that knows the secret. The group format with hashes that came
between the two was never released and has no such path: there every member had
seen every other member's secret, so a secret proves nothing about a key sent with
it. Its members keep going by their secrets until they pair again.

A member the active removes stays on record as removed (a tombstone, handed out
with the member list): its calls get 410 HA_REMOVED everywhere, and an instance
that hears so from a member lets go of the group and stays passive. A standby that
holds a tombstone for a member its active still lists (the active was promoted while
it could not hear about the removal) hands it back (take_tombstones).

The live view (on unless an admin switches it off, per instance): a standby starts
its cluster, PBS and ESXi managers as well and lets them read, so the UI shows the
clusters as they are. They act on nothing - every path that would is gated on
is_active(). Settings the managers read when they use them are handed over in
place after each sync; once a change to how they connect has settled, the managers
it concerns are stopped and built again in this process (reload_managers), so the
users signed in here stay signed in. Only a switched live view or a new role
restarts the process. With the live view off a standby starts no managers at all.

The active tells its members after each change it takes (nudge_members, POST
/api/ha/peer/changed), and they pull within seconds instead of at their next poll.

Forwarded writes (on unless an admin switches them off, per instance): a write the
standby would refuse goes to the active it follows instead, when a user signed in on
the standby sends it from the browser. The standby vouches for that user: a signed
peer call carries the request and the username, and the active checks the account
against its own users table and runs the request through its own routing, as that
user and with that user's rights there (api/ha.py peer_forward). An API token is
nobody the standby can vouch for, its writes are refused as before. A write that went
through is followed by a pull right away (pull_soon), so it shows here at once.

Active members: the leader makes up to two of its members active as well, on its own
HA page (set_member_serve, ACTIVE_LIMIT). Users are served there as on the leader -
they sign in, see the clusters live and open consoles there, and every change is
forwarded. The flag travels with the member list; the role stays standby, so the
leader alone runs what acts on its own.

What travels:
  * pairing - the standby POSTs the one-time code and its public key to the active
    and gets back the field key (.pegaprox_aes256.key), the active's public key and
    the member list, sealed with a key derived from the code.
    Encrypted columns then copy 1:1, including ones added later; a value still in
    the old Fernet format is resealed on its way out.
  * sync - GET /api/ha/peer/snapshot returns every table in SYNC_TABLES plus the host
    key pins, the login background, the plugins' config.json files and the member
    list. Instance-local tables and settings stay put.

Nothing a member holds goes with the DELETE of a sync unseen (#625, stage 2): the
active counts its configuration (cv), every snapshot names the history its data went
through, and a member that holds anything outside of it keeps a copy in
config/ha_orphans first. See "config version" further down.

A state file from before the groups holds a single peer. It reads as a group of two
(_from_pair_format), and both sides keep talking without pairing again.

Automatic failover (stage 2, off until ha_vote.AUTO_MODE_SHIPPED): a group of three
votes or more can elect its leader by majority instead. The leader then holds a lease
its members renew, acts only while it holds it, and a member takes over by itself once
the lease of a lost leader ran out. The rules are in ha_vote.py; the section
"automatic failover" at the end of this file runs them. Manual mode stays the default
and is what everything above describes.

State lives in config/ha_state.json, next to the key files and just as private.
It is never part of a snapshot.

MK Sep 2026
"""
import base64
import collections
import contextlib
import errno
import functools
import gzip
import hashlib
import hmac
import importlib
import json
import logging
import os
import random
import re
import secrets
import stat
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from pegaprox import witness_boot
from pegaprox.constants import CONFIG_DIR, BRANDING_DIR, PLUGINS_DIR, PEGAPROX_VERSION
from pegaprox.core import ha_vote, ha_wire

ROLE_STANDALONE = 'standalone'
ROLE_ACTIVE = 'active'
ROLE_STANDBY = 'standby'

STATE_FILE = os.path.join(CONFIG_DIR, 'ha_state.json')
AES_KEY_FILE = os.path.join(CONFIG_DIR, '.pegaprox_aes256.key')
KNOWN_HOSTS_FILE = os.path.join(CONFIG_DIR, '.ssh_known_hosts')
# held by the one process that runs on this config directory (lock_config_dir)
LOCK_FILE = os.path.join(CONFIG_DIR, '.pegaprox.lock')
# Lies next to the state file while this instance is in a group, and the database holds
# the same fact as a local setting, so a restored database carries it along. With the
# state file gone, either one keeps the instance passive (_load, check_markers_at_boot).
MEMBER_MARKER = '.ha-member'
MEMBER_SETTING = 'ha_member_of'
# what this process exits with when something is meant to start it again: systemd
# restarts on it (Restart=on-failure), Docker by its restart policy. Never 0
EXIT_RESTART = 75

SNAPSHOT_FORMAT = 1
CODE_PREFIX = ha_wire.CODE_PREFIX
PAIRING_TTL = 15 * 60
DEFAULT_INTERVAL = 30
# the sender's instance id; '<id>:<secret>' from a member paired before the keys
PEER_HEADER = ha_wire.PEER_HEADER
PEER_TS_HEADER = ha_wire.PEER_TS_HEADER
PEER_NONCE_HEADER = ha_wire.PEER_NONCE_HEADER
PEER_SIG_HEADER = ha_wire.PEER_SIG_HEADER
# our public key, along with a call that still carries the old secret
PEER_KEY_HEADER = 'X-PegaProx-Peer-Key'
# the answer to it: the receiver holds the key this call was signed with
PEER_KEYED_HEADER = 'X-PegaProx-Peer-Keyed'
# the sha256 of the body, as signed: a receiver can check who sent a large call before
# it reads the body (signed_before_body), and the body against it afterwards
PEER_BODY_HEADER = ha_wire.PEER_BODY_HEADER
# with the pull of a snapshot: the config version the member holds, [epoch, seq, segment,
# leader] as JSON (note_config_etag)
PEER_CV_HEADER = 'X-PegaProx-Peer-Cv'
# how far a signed call's time may be off, either way
SIGNATURE_WINDOW = ha_wire.SIGNATURE_WINDOW
_NONCES_PER_SENDER = ha_wire.NONCES_PER_SENDER
# /peer/status and the snapshot say they come from this release: members, keys, tombstones
GROUP_MARK = ha_wire.GROUP_MARK
# /peer/status says so once this release speaks the lease protocol of automatic failover.
# A mark of its own: a release before it compares GROUP_MARK for equality
LEASE_MARK = ha_wire.LEASE_MARK
# the highest epoch any member reads, holds or hands on. A promotion that would go past
# it is refused: an epoch nobody can read would leave two actives that never settle
EPOCH_MAX = 2 ** 31 - 1
# one active and up to three standbys
MAX_MEMBERS = 4
MAX_TOMBSTONES = 16
GROUP_FULL_ERROR = f'This group already has {MAX_MEMBERS - 1} standbys - remove one first'
REMOVED_ERROR = 'This instance was removed from the group'
# the instances users are served on: the leader and up to two members it makes active
# (set_member_serve). Whoever is left of a full group stays a standby
ACTIVE_LIMIT = 3
ACTIVE_LIMIT_ERROR = (f'A group has at most {ACTIVE_LIMIT} active instances, the leader '
                      'included - make one of the others a standby first')
# the pull of a pass: at most this long, at least the floor whatever the interval,
# and short when the watch of the same pass could not reach the source
PULL_TIMEOUT = 60
PULL_TIMEOUT_FLOOR = 20
PULL_TIMEOUT_UNREACHABLE = 10
# how long a promotion waits for a sync that is under way, as pull_before_promote does
PROMOTE_PULL_WAIT = 20

# A write a standby forwards: the peer route that takes it on the active, and the key
# the active marks the call it runs for the standby with in the WSGI environ (the
# session made for it, the standby, the client address). A client cannot set an
# environ key of that name; headers arrive as HTTP_*.
FORWARD_PATH = '/api/ha/peer/forward'
# the calls of automatic failover (ha_vote.py): a vote or pre-vote, and the leader's renewal
VOTE_PATH = '/api/ha/peer/vote'
RENEW_PATH = '/api/ha/peer/renew'
# the leader hands its term to a member: that member votes at once (design 7.1)
CAMPAIGN_PATH = '/api/ha/peer/campaign'
LEASE_PATHS = {'vote': VOTE_PATH, 'renew': RENEW_PATH, 'campaign': CAMPAIGN_PATH}
# a member asks the leader to hand it the lead, or to take it out of the group (7.1, 7.4)
TRANSFER_PATH = '/api/ha/peer/transfer'
LEAVE_PATH = '/api/ha/peer/leave'
FINGERPRINT_PATH = '/api/ha/peer/fingerprint'
FORWARD_ENVIRON = 'pegaprox.ha_forward'
FORWARD_MAX_BODY = 50 * 1024 * 1024
# The browser waits for it, and some writes run a while before they answer (a clone
# with cloud-init waits up to 10 minutes for its task). Connecting has its own, short
# limit: an active that is gone costs a click seconds, not minutes.
FORWARD_TIMEOUT = 900
FORWARD_CONNECT_TIMEOUT = 15
FORWARD_READ_TIMEOUT = 30
_FORWARD_CHUNK = 1024 * 1024
# The reads a forwarding standby hands on as well: the progress of jobs that live in the
# process, or in the tables of its own, of the instance that started them. A job
# started through a standby runs on the active, and without these the standby would
# show no progress at all (nor the cutover of a migration that waits for one). And the
# views only the active's own tables hold, because only its loops fill them
# (LEADER_ONLY_READS). A GET rule, as app.url_map writes it; the active serves nothing
# else as a forwarded read.
#
# Leader-only: the alerts that fire, drift, the push inbox and the migration history.
# A standby has rows of its own in those tables, under ids of its own (from when it
# acted, or from before it joined), and an ack picked from such a list would name
# another row on the active. When the active does not answer, a forwarding standby
# says so (api/ha.py _forward_read) instead of showing its own; the progress of a job
# falls back to the standby's copy.
LEADER_ONLY_READS = frozenset((
    '/api/clusters/<cluster_id>/active-alerts',
    '/api/clusters/<cluster_id>/drift/status',
    '/api/clusters/<cluster_id>/drift/events',
    '/api/push/inbox',
    '/api/migration-history',
    '/api/clusters/<cluster_id>/vms/<int:vmid>/migration-history',
    '/api/clusters/<cluster_id>/balance-history',
))
# The task lists of an XCP-ng pool. PegaProx follows the XAPI tasks it started itself, in
# the process that started them (core/xcpng.py _active_tasks), so a member lists none of
# what its users start through the leader. A Proxmox cluster keeps a task log of its own
# that every instance reads there: these go to the leader for an XCP-ng pool only
# (forwards_read).
XCPNG_TASK_READS = frozenset((
    '/api/clusters/<cluster_id>/tasks',
    '/api/clusters/<cluster_id>/nodes/<node>/tasks',
    '/api/clusters/<cluster_id>/nodes/<node>/tasks/<path:upid>/log',
))
FORWARDED_READS = LEADER_ONLY_READS | XCPNG_TASK_READS | frozenset((
    '/api/vmware/migrations',
    '/api/vmware/migrations/<mid>',
    '/api/xhm/migrations',
    '/api/xhm/migrations/<mid>',
    '/api/clusters/<cluster_id>/updates/status',
    # what the node list shows of both, for every node at once (api/vms.py)
    '/api/clusters/<cluster_id>/node-progress',
    '/api/clusters/<cluster_id>/nodes/<node_name>/update',
    '/api/clusters/<cluster_id>/nodes/<node_name>/maintenance',
    '/api/clusters/<cluster_id>/datastores/<storage_name>/download-status/<task_id>',
    '/api/pbs/<pbs_id>/update',
    '/api/clusters/<cluster_id>/backup-verify/<task_id>',
    '/api/clusters/<cluster_id>/backup-verify/active',
    '/api/clusters/<cluster_id>/backup-verify/history',
    '/api/clusters/<cluster_id>/iso-sync/last-result',
    '/api/clusters/<cluster_id>/migrations',
    '/api/cluster-groups/<group_id>/lb-history',
    '/api/clusters/<cluster_id>/templates/deployments',
    '/api/templates/deployments/<dep_id>',
    '/api/clusters/<cluster_id>/oci/jobs',
    '/api/dr-drills/<drill_id>',
    '/api/site-recovery/plans/<plan_id>/drills',
    '/api/site-recovery/plans/<plan_id>/events',
    # the boot screenshots of a test failover, in the same instance's tables as its event
    '/api/site-recovery/plans/<plan_id>/events/<event_id>/screenshots/<int:vmid>',
    '/api/clusters/<cluster_id>/snapshot-policies/<pid>/runs',
    # a bulk migration runs in the process of the instance that started it (#952)
    '/api/bulk-migrations',
    '/api/bulk-migrations/<run_id>',
))
# The one rule every plugin route is served behind (api/plugins.py plugin_proxy). A
# plugin handler serves every method from one function and most never look at which
# one they got, so a GET of a plugin may change something as well: a forwarding
# standby reads it from the active, like the reads above, and runs none here. Not the
# ones that open a console (PLUGIN_CONSOLE_PATHS): the browser connects to the
# instance that opened it, so a standby that serves users opens them itself, any
# other refuses them (app.py).
PLUGIN_PROXY_RULE = '/api/plugins/<plugin_id>/api/<path:subpath>'
PLUGIN_CONSOLE_PATHS = frozenset(('vm/console',))
# The writes that open a console. Every caller of the console token opens one; the
# others hand out a ticket or carry the session (vnc-poll is a whole VNC transport over
# POST). A console belongs to the instance the browser is on: a standby that serves
# users opens them itself, any other refuses them (app.py), and none is ever handed to
# the active (api/ha.py _forward_envelope). The GET routes and the WebSockets ask
# api/ha.py standby_console_refusal / consoles_here themselves.
CONSOLE_WRITES = frozenset((
    ('POST', '/api/ws/token'),
    ('POST', '/api/clusters/<cluster_id>/nodes/<node>/shell'),
    ('POST', '/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/termproxy'),
    ('POST', '/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/vnc-poll'),
    ('POST', '/api/vmware/<vmware_id>/vms/<vm_id>/console'),
))

# Shared configuration. Everything else in the database is per host: sessions,
# audit trail, metrics, run and event history, runtime alerts. A table that is in
# neither list is not synced; tests/test_ha_core.py fails until it is placed.
SYNC_TABLES = (
    'server_settings', 'users', 'user_folders', 'user_favorites', 'api_tokens',
    'webauthn_credentials', 'custom_roles', 'tenants', 'vm_acls', 'pool_permissions',
    'clusters', 'cluster_groups', 'node_maintenance', 'balancing_excluded_vms',
    'balancing_excluded_pools', 'affinity_rules', 'vm_tags', 'alerts', 'cluster_alerts',
    'alert_mutes', 'scheduled_tasks', 'scheduled_actions', 'update_schedules', 'custom_scripts',
    'node_bmc_endpoints', 'esxi_storages', 'storage_clusters', 'pbs_servers',
    'vmware_servers', 'xcpng_pools', 'xcpng_pool_members', 'xcpng_vmid_map',
    'cross_cluster_replications', 'efficient_snapshots', 'site_recovery_plans',
    'site_recovery_vms', 'snapshot_policies', 'drift_baselines', 'multi_cluster_vnets',
    'siem_targets', 'push_subscriptions', 'plugin_state', 'status_incidents',
    'custom_cloud_templates', 'power_rates', 'cost_rates', 'auto_install_profiles',
    'pegaprox_kv',
    # Proxmox HA rules a rolling update switched off: whoever acts next switches them on (#954)
    'suspended_ha_rules',
    # node recoveries an automatic leader left half done (5.6); made on its first write
    'ha_recovery_journal',
)
LOCAL_TABLES = (
    'sessions', 'audit_log', 'task_users', 'migration_history', 'metrics_history',
    'active_alerts', 'site_recovery_events', 'cve_history', 'backup_verifications',
    'status_uptime', 'cloud_init_deployments', 'dr_drills', 'dr_drill_checks',
    # the boot screenshots of a test failover, beside the event they belong to
    'site_recovery_screenshots',
    'snapshot_runs', 'drift_events', 'auto_install_runs', 'push_inbox',
    'balance_recommendations', 'logs', 'logs_fts',
    # who wrote what on the active, and the change counter behind cv_tick
    'ha_change_journal', 'ha_cv_dirty',
)

# server_settings keys that describe this host, not the deployment
LOCAL_SETTING_KEYS = frozenset((
    'domain', 'port', 'ssl_enabled', 'http_redirect_port', 'reverse_proxy_enabled',
    'trusted_proxies', 'proxy_bind_address', 'oidc_redirect_uri', 'syslog_enabled',
    'syslog_retention_days', 'alert_last_notified_version', 'hardware_monitoring',
    'hardware_monitoring_redfish', MEMBER_SETTING,
))
LOCAL_SETTING_PREFIXES = ('acme_',)

# Columns every login, token use or push delivery writes. They still travel in
# the body, but leaving them out of the etag keeps a busy active from forcing a
# full transfer on nearly every poll.
# A standby writes some of them itself: a passkey sign-in there counts sign_count up,
# a plugin it loads notes its own error. Out of the etag, they are also no change of
# its own that the next sync would have to keep a copy of (_why_not_carried).
VOLATILE_COLUMNS = {
    'users': ('last_login', 'last_ldap_sync', 'last_oidc_sync'),
    'api_tokens': ('last_used_at', 'last_used_ip'),
    'webauthn_credentials': ('last_used_at', 'last_used_ip', 'sign_count'),
    'push_subscriptions': ('last_used_at', 'failures'),
    'plugin_state': ('loaded_at', 'error'),
    'siem_targets': ('last_status', 'last_ok_at', 'last_error_at', 'last_error',
                     'sent_count', 'error_count'),
}

# Encrypted columns, the same inventory db.rotate_encryption_key walks. A value
# still in the pre-2026 Fernet format is resealed under the field key on its way
# into a snapshot, because the standby holds our field key but not our Fernet key.
ENCRYPTED_COLUMNS = {
    'users': ('totp_secret_encrypted', 'totp_pending_secret_encrypted'),
    'clusters': ('pass_encrypted', 'ssh_key_encrypted', 'api_token_secret_encrypted',
                 'ha_settings'),
    'esxi_storages': ('password_encrypted',),
    'node_bmc_endpoints': ('bmc_password_encrypted',),
    'pbs_servers': ('pass_encrypted', 'api_token_secret_encrypted', 'ssh_key_encrypted'),
    'vmware_servers': ('pass_encrypted',),
    'auto_install_profiles': ('answer_encrypted',),
}
SECRET_SETTING_KEYS = ('smtp_password', 'ldap_bind_password', 'oidc_client_secret')

_MAX_BRANDING_BYTES = 8 * 1024 * 1024
_MAX_PLUGIN_CONFIG_BYTES = 256 * 1024
_MAX_PLUGIN_CONFIG_TOTAL = 2 * 1024 * 1024
_PLUGIN_ID_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')
_TABLE_NAME_RE = re.compile(r'^[a-z_][a-z0-9_]*$')
_COLUMN_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}')

_ID_RE = re.compile(r'[0-9a-f]{32}')
_SEGMENT_RE = re.compile(r'[0-9a-f]{16}')
_MARK_RE = re.compile(r'[0-9a-f]{8}')
_SEQ_MAX = 2 ** 53
# <epoch>-<seq>-<UTC time>-<digest of what it holds>
_ORPHAN_NAME_RE = re.compile(r'[0-9]{1,10}-[0-9]{1,16}-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}')
_TRIGGER_NAME_RE = re.compile(r'ha_cv_[a-z0-9_]{1,80}')
_SECRET_HASH_RE = re.compile(r'[0-9a-f]{64}')
_FP_RE = re.compile(r'[0-9A-F]{2}(:[0-9A-F]{2}){31}')
# an Ed25519 public key or signature, base64 of the raw bytes
_PUBLIC_KEY_RE = re.compile(r'[A-Za-z0-9+/]{43}=')
_SIGNATURE_RE = re.compile(r'[A-Za-z0-9+/]{86}==')
_NONCE_RE = re.compile(r'[A-Za-z0-9_-]{16,64}')
_TS_RE = re.compile(r'[0-9]{1,12}')
_DIGEST_RE = re.compile(r'[0-9a-f]{64}')

# A standby reloads the managers a change to how they connect is about once the new
# settings have held for RELOAD_SETTLE seconds, so a burst of edits is one reload.
# The active tells its members about NUDGE_DELAY seconds after a change, so edits made
# in one go (a dialog that saves twice, the API token the active makes on the first
# connect and saves right after) reach a member with the same note, or with the next
# one NUDGE_SPACING later. A later edit costs one more reconnect of that one manager,
# nobody's session: the minute this was before was for a restart.
RELOAD_SETTLE = 10
BOOT_PULL_TIMEOUT = 10

# The active's note to its members after a change: NUDGE_DELAY seconds after the first
# write, and while writes keep coming one every NUDGE_SPACING seconds, the last one
# after the last write. Each note carries the etag of the configuration, worked out
# once for every member, and a member that holds it pulls nothing. That walk over the
# shared tables is what a note costs the active (about 0.4 s at 40k synced rows): at
# most one per NUDGE_SPACING, under 5% of one core however busy it is. Ten seconds is
# also the RELOAD_SETTLE a member waits before a new connection takes effect, and a
# third of the default poll.
NUDGE_PATH = '/api/ha/peer/changed'
NUDGE_DELAY = 2
NUDGE_SPACING = 10
NUDGE_TIMEOUT = 5

# The config version (#625, stage 2). A history names the last LINEAGE_KEEP segments
# the data went through; a member further back than that keeps a copy at its next sync.
CV_ZERO = (0, 0)
LINEAGE_KEEP = 64
# Every step of the cv gets a random mark, and a snapshot carries the marks of the last
# STEPS_KEEP steps: a member that holds one of them under another mark holds content the
# leader never handed out under that number (its state went back to an earlier one).
STEPS_KEEP = 128
# What a member held and a snapshot did not carry over. A copy goes only when an admin
# dismisses it; past ORPHANS_ALERT_BYTES, or that share of the free space, the instance
# says so and still deletes nothing.
ORPHANS_DIR = os.path.join(CONFIG_DIR, 'ha_orphans')
ORPHANS_ALERT_BYTES = 200 * 1024 * 1024
ORPHANS_ALERT_SHARE = 0.10
# A copy on disk: the gzip'd JSON sealed with AES-256-GCM, after a magic and the
# fingerprint of the key it is sealed under. With SQLCipher that is a key derived from
# the master key of the key store (ORPHAN_MAGIC_MASTER): the field key lies in the
# config directory, next to the copies, and the master key need not. On plain SQLite,
# where the rows are readable in the database file anyway, it is the field key
# (ORPHAN_MAGIC). The meta file next to a copy stays readable and holds nothing of the
# rows (_ORPHAN_META_KEYS).
ORPHAN_SUFFIX = '.json.gz.enc'
ORPHAN_MAGIC = b'PGXHAO1\n'
ORPHAN_MAGIC_MASTER = b'PGXHAO2\n'
ORPHAN_KEY_INFO = b'pegaprox-ha-orphans'
# A copy names every row, file and journal line it holds in its meta file, as a keyed
# digest, so the same rows are not kept a second time. Past this many it names none:
# the status reads the meta files with every poll.
ORPHAN_ITEMS_MAX = 512
# how long dismissing a copy waits for a sync that is under way
DISMISS_WAIT = 10
# The change journal: one line per write request on the active, in the database
# JOURNAL_DELAY seconds after the first one that waits, JOURNAL_KEEP lines at most.
JOURNAL_KEEP = 20000
JOURNAL_PENDING_MAX = 2000
JOURNAL_DELAY = 1
# The tick of an automatic leader (cv_tick), every CV_TICK seconds. Measured on a
# generated 10k-VM dataset (42.7k rows in 46 shared tables, SQLCipher): one etag walk
# takes 0.40 s, 0.10 s of it the SELECTs alone, so a tick that always walks would cost
# 13% of a core for nothing. Triggers on the shared tables count the changes into
# ha_cv_dirty instead (2-10 us a changed row, 10 us to read), and the tick walks only
# when the count or a file moved. The triggers are looked over whenever the schema
# changed, and every TRIGGER_CHECK seconds anyway; nothing but the tick relies on them.
CV_TICK = 3
TRIGGER_PREFIX = 'ha_cv_'
TRIGGER_CHECK = 60

_lock = threading.RLock()
_state = None
_loop_started = False
# the stored etag is dropped once per process start: an upgrade or a restored
# database changes what we hold without the active knowing
_etag_checked = False
# and the first sync of a process reads the rows here whatever the change mark says
_mark_checked = False


def _fresh_run():
    return {
        'started': time.monotonic(),
        'managers': False,          # main() started the cluster, PBS and ESXi managers
        'signature': None,          # manager_signature() the running managers stand for
        'items': None,              # the per-connection digests behind it, to name a change
        'live_view': None,          # the live view this process runs with, once known
        'live_view_changed': None,  # when set_live_view last changed it
        'reload': None,             # a change to how they connect, waiting to settle
        'last_reload': None,        # when the last reload ran, why, and what it could not build
        'restarting': False,
    }


# What the running managers were built from. Memory only: the signature is taken
# from the decrypted passwords and keys, so it never goes near the state file.
_run = _fresh_run()
_pull_lock = threading.Lock()
# one reload at a time, whoever asks: its timer, a pull, the admin's "apply now"
_reload_lock = threading.Lock()
# the nonces of signed calls taken within the window, per (receiver, sender). Memory
# only, so a call signed before this process started is not taken at all. The start is
# lease time: see _process_started
_nonce_lock = threading.Lock()
_seen_nonces = {}
# the signed calls of this release carry stream nonces instead (ha_wire.take_stream):
# what this process took per (receiver, sender, share), and the streams it numbers its
# own calls in, per receiver - one for the votes and renewals, one for every other call
_seen_streams = {}
_lease_stream = {'id': ha_wire.new_stream(), 'seq': {}}
_call_stream = {'id': ha_wire.new_stream(), 'seq': {}}
_PROCESS_STARTED = ha_vote.ha_clock()
# what the last look at the group could not reach, for the pull of the same pass
_last_watch = {'at': None, 'unreachable': frozenset()}
# the member this standby pulls from, when the last try to reach it (watch, pull or a
# forwarded write) got no answer at all; the next answer clears it. Forwarding waits
# for that answer instead of holding every write until it times out
_silent_source = {'id': None}
# journal lines that wait for the database; last_id is the highest id written there,
# filled_to the highest one that has its cv
_journal_lock = threading.Lock()
_journal = {'pending': [], 'dropped': 0, 'last_id': None, 'filled_to': 0, 'due': False}
# cv_tick: the change count and file marks it last walked at, and when it last looked
# over the triggers (monotonic), and SQLite's schema version at that look
_tick = {'seen': None, 'checked': None, 'schema': None}
# how many copies ORPHANS_DIR holds (None until counted), and whether it was said that
# they are past the limit; not_kept is the copy that could not be written, as it was
# last audited
_orphans = {'count': None, 'over_said': False, 'not_kept': None}
# automatic failover: what runs the lease of each instance in this process, by instance
# id (_LeaseRuntime). One in production; the tests run a whole group in one process
_rts = {}
# whether the filesystem of the state file refused to sync a directory at all (None
# until one was synced): a vote written there may not survive a power cut
_dir_sync = {'unsupported': None}
# on while the lease store writes: that write has to be on disk, directory included
_vote_write = {'on': False}


class HaError(Exception):
    """Something the admin (or the peer) should be told as is."""


class PeerUnreachable(HaError):
    """The member did not answer at all: network, timeout or a certificate we cannot trust."""


class PeerNoAnswer(PeerUnreachable):
    """The member took the call and then sent no answer, in time or at all: whatever
    the call asked for may have happened there."""


class PeerRefused(HaError):
    """The member answered and turned the call away (401, or 410 once it removed us)."""

    def __init__(self, message, status, code=''):
        super().__init__(message)
        self.status, self.code = status, code


class RemoveUnconfirmed(HaError):
    """remove_member: the member was not seen as a standby under the current epoch."""


class SyncRunning(HaError):
    """A sync holds the pull lock for longer than the caller waits for it."""


class ActiveLimit(HaError):
    """set_member_serve: one more active member would make more than ACTIVE_LIMIT."""


class AutoMode(HaError):
    """Something only a manual group does was asked of an automatic one, or of one that
    is switching to it: a promotion by hand, the removal of a member."""


# --- state ---------------------------------------------------------------------

def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _default_state():
    return {
        'role': ROLE_STANDALONE,
        'epoch': 0,
        'instance_id': uuid.uuid4().hex,
        'interval': DEFAULT_INTERVAL,
        # what this instance signs every call to another member with (base64 of the raw
        # Ed25519 private key), made when it first pairs
        'signing_key': None,
        # the secret a group from before the keys presented; gone once every member
        # holds our public key
        'member_secret': None,
        # every OTHER member: {instance id: {url, fingerprint, public_key, secret_hash,
        # serve, pair_secret, role_seen, epoch_seen, serving_seen, last_contact,
        # last_error, joined_at, group_seen, key_acked}}. serve is the leader's word
        # and travels with the member list; the rest is what this instance noted
        'members': {},
        # members the active took out: {instance id: {epoch, at, by, public_key,
        # secret_hash}}, so their calls get 410 and no stale list takes them back
        'tombstones': {},
        # set when a member told us we were removed: {epoch, at, by}
        'removed': None,
        # on a standby, the member it pulls from
        'source': None,
        'pairing': None,
        'sync': {},
    }
    # Only once automatic failover was switched on in the group, and absent before:
    #   lease     what ha_vote.Node writes down (mode, epoch, voted_for, gen, cfg,
    #             cfg_chain, floor_cv, led, released, campaign_after, promised), and
    #             pending_since while the config held is a pending switch (status page)
    #   witness   {instance_id, url, fingerprint, public_key, site} of the group's
    #             witness, never one of 'members' (MAX_MEMBERS counts data members)
    #   timezone  the zone the group's schedules are evaluated in (schedule_now)
    #   group_mode  on a standby, what the instance it follows said about the group's
    #             mode with the pairing or its last snapshot, kept only where the voter
    #             config held here does not say the same: it stands in for a config
    #             this member does not hold (mode), and opens the way out for one that
    #             missed the switch back to manual mode (unpair_refusal)
    # The leader of an automatic group has role 'leader' in the file. In memory that is
    # ROLE_ACTIVE with 'leader' set, so every reader of the role sees an active.


def _from_pair_format(st):
    """A state file from before the groups: one 'peer' with the secret we present to it
    (secret_out) and the hash of the one it presents to us (secret_in_hash). That is a
    group of two, and it reads as one. Our secret_out becomes the secret we present to
    every member, and the other side holds its hash already, so neither side pairs
    again - whichever of the two is upgraded first. Only in memory; the file takes
    the new form with the next write.

    The record is marked pair_secret: its secret was made for this pair and nobody
    else has seen it, so a key the member sends along with it is its own
    (peer_verdict)."""
    p = st.pop('peer', None)
    if 'members' in st or not isinstance(p, dict):
        return st
    pid = p.get('instance_id')
    st['members'] = {}
    if isinstance(pid, str) and pid:
        st['member_secret'] = p.get('secret_out') or None
        st['members'][pid] = {
            'url': p.get('url') or '',
            'fingerprint': p.get('fingerprint') or '',
            'secret_hash': p.get('secret_in_hash') or '',
            'pair_secret': True,
            'role_seen': p.get('role_seen'),
            'epoch_seen': p.get('epoch_seen') or 0,
            'last_contact': p.get('last_contact'),
            'last_error': p.get('last_error') or '',
            'joined_at': p.get('paired_at'),
        }
        if st.get('role') == ROLE_STANDBY:
            st['source'] = pid
    return st


def _key_backups():
    """The .pre-ha copies of our own field key. Only join() writes them, so one
    being there means this instance was a standby at some point."""
    folder = os.path.dirname(AES_KEY_FILE) or '.'
    prefix = os.path.basename(AES_KEY_FILE) + '.pre-ha.'
    try:
        return sorted(fn for fn in os.listdir(folder) if fn.startswith(prefix))
    except OSError:
        return []


def _marker_path():
    return os.path.join(os.path.dirname(STATE_FILE) or '.', MEMBER_MARKER)


def _in_group(st):
    return bool(st.get('members')) or st.get('role') in (ROLE_ACTIVE, ROLE_STANDBY)


def _membership_left_behind():
    """Why this instance was in a group although no state file says so: a .pre-ha key
    backup (it joined once) or the member marker. None when neither is there."""
    if _key_backups():
        return 'joined a pair before'
    if os.path.exists(_marker_path()):
        return 'belongs to a group'
    return None


def _missing_state(why):
    """The stand-in for a state file that is gone from an instance that was in a group:
    an acting standalone here would run next to the group on its key and its
    configuration."""
    return dict(_default_state(), role=ROLE_STANDBY,
                broken=f'The HA state file is missing, but this instance {why} - restore '
                       'config/ha_state.json and restart, or unpair it')


def _load():
    global _state
    with _lock:
        if _state is not None:
            return _state
        st = None
        try:
            with open(STATE_FILE, 'r', encoding='utf-8') as fh:
                st = json.load(fh)
            if not isinstance(st, dict):
                raise ValueError('not a JSON object')
            # a note an older build saved; this file reads fine
            st.pop('broken', None)
        except FileNotFoundError:
            st = None
            why = _membership_left_behind()
            if why:
                # in a group once and the file is gone (a restore from before the
                # pairing, a hand-made "reset")
                logging.error(f"[HA] {STATE_FILE} is missing but this instance {why} - "
                              "staying passive until it is restored or unpaired")
                st = _missing_state(why)
        except Exception as e:
            # a state file we cannot read must not turn a standby into an acting
            # instance: stay standby until someone looks
            logging.error(f"[HA] {STATE_FILE} is unreadable ({e}) - staying passive until it is fixed")
            st = dict(_default_state(), role=ROLE_STANDBY, broken=str(e)[:200])
        if not isinstance(st, dict):
            st = _default_state()
        base = _default_state()
        base.update(_from_pair_format(st))
        base.pop('leader', None)
        if base.get('lease') is not None and _lease(base) is None:
            # votes and the voter config are in there: an instance that cannot read
            # them must neither vote nor lead
            logging.error(f"[HA] the lease state in {STATE_FILE} cannot be read - staying "
                          "passive until it is fixed")
            base.update(role=ROLE_STANDBY, broken='the lease state cannot be read')
        elif base.get('role') == ha_vote.ROLE_LEADER and _lease(base) is not None:
            # the leader of an automatic group: an active, with the lease in force
            base.update(role=ROLE_ACTIVE, leader=True)
        if _lease(base) is not None and base['lease'].get('mode') != base['lease']['cfg']['body']['mode']:
            # the mode is what the newest voter config says, whatever stands next to it
            base['lease'] = dict(base['lease'], mode=base['lease']['cfg']['body']['mode'])
        if base.get('role') not in (ROLE_STANDALONE, ROLE_ACTIVE, ROLE_STANDBY):
            base['role'] = ROLE_STANDBY
        for field in ('members', 'tombstones'):
            ms = base.get(field) if isinstance(base.get(field), dict) else {}
            base[field] = {k: v for k, v in ms.items() if isinstance(k, str) and isinstance(v, dict)}
        if not isinstance(base.get('removed'), dict):
            base['removed'] = None
        # the per-instance switch of a build before the leader decided who serves:
        # read as nothing, and gone from the file with the next write
        base.pop('serve_users', None)
        # nothing is written until something changes: an instance that never pairs
        # never grows a state file
        _state = base
        return _state


def _write_locked(st, strict=None):
    """Write `st` as the state file.

    Refuses the stand-in _load built for a file it could not read: saving it would
    replace the only copy of the peer record and the secrets with a fresh
    identity. unpair() is the one way out, and it drops the note first.

    A write a vote or a promise rests on (_LeaseStore.save sets _vote_write for it)
    raises when the directory could not be synced as well: the rename is not on disk
    before that. `strict` overrides that, True or False.
    """
    strict = _vote_write['on'] if strict is None else strict
    if st.get('broken'):
        raise HaError('The HA state file cannot be read - restore config/ha_state.json and '
                      'restart, or unpair this instance')
    tmp = STATE_FILE + '.tmp'
    out = {k: v for k, v in st.items() if k not in ('broken', 'leader')}
    if st.get('leader') and st.get('role') == ROLE_ACTIVE:
        # a release before automatic failover reads this role as unknown and stays passive
        out['role'] = ha_vote.ROLE_LEADER
    data = json.dumps(out, indent=2, sort_keys=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, STATE_FILE)
    # the rename is only on disk once the directory is: until then a power cut can bring
    # back the file from before, epoch and all
    _fsync_dir(STATE_FILE, strict=strict)
    try:
        os.chmod(STATE_FILE, 0o600)
    except OSError:
        pass


def _fsync_dir(path, strict=False):
    """fsync the directory `path` sits in. Never raises unless `strict`: the file itself
    is written already, and a filesystem that cannot sync a directory says so in the log.

    With `strict` a directory that cannot be opened or synced raises: the caller's write
    is one a vote rests on, and it is not on disk. A filesystem that does not sync
    directories at all (EINVAL, ENOTSUP) is let through even then, noted in _dir_sync,
    and shows as a finding (auto_findings)."""
    try:
        fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    except OSError:
        if strict:
            raise
        return
    try:
        os.fsync(fd)
        _dir_sync['unsupported'] = False
    except OSError as e:
        unsupported = e.errno in (errno.EINVAL, getattr(errno, 'ENOTSUP', errno.EINVAL))
        if strict and not unsupported:
            raise
        if not (unsupported and _dir_sync['unsupported']):
            # said once for a file system that never does, each time for anything else
            logging.warning(f"[HA] could not sync the directory of {path}: {e}")
        if unsupported:
            _dir_sync['unsupported'] = True
    finally:
        os.close(fd)


def _note_marker(st):
    """MEMBER_MARKER in step with `st`: there while it is in a group, gone once it is a
    standalone again. A failed write costs the marker, never the commit."""
    path = _marker_path()
    try:
        if _in_group(st):
            if not os.path.exists(path):
                _write_private(path, (st['instance_id'] + '\n').encode())
                _fsync_dir(path)
        elif os.path.exists(path):
            os.unlink(path)
            _fsync_dir(path)
    except OSError as e:
        logging.warning(f"[HA] could not update {path}: {e}")


# MK Oct 2026 (#625) - what this instance knew about its group, next to the state file:
# whether the group ever failed over automatically, the newest voter config held and
# the witness. It only grows while the instance stays in its group, so a state file put
# back from an older copy shows up as behind it (way_out_refusal), and a promotion still
# finds the witness that copy never knew. Nothing is written before automatic failover
# ships, and a group that never went automatic writes nothing but the witness.

GROUP_SEEN_SUFFIX = '.group'
_group_seen_cache = {}


def _group_seen_path():
    return STATE_FILE + GROUP_SEEN_SUFFIX


def _group_seen(st):
    """{auto, cfg_id, witness} this instance noted while in its group, None when nothing
    was noted (or it was noted by another instance id)."""
    path = _group_seen_path()
    if path not in _group_seen_cache:
        try:
            with open(path, encoding='utf-8') as fh:
                rec = json.load(fh)
        except (OSError, ValueError):
            rec = None
        _group_seen_cache[path] = rec if isinstance(rec, dict) else None
    rec = _group_seen_cache[path]
    if not rec or rec.get('instance_id') != st.get('instance_id'):
        return None
    return {'auto': rec.get('auto') is True, 'cfg_id': ha_vote.pair(rec.get('cfg_id')),
            'witness': _clean_witness(rec.get('witness'))}


def _note_group_seen(st):
    """After a commit: what `st` knows about the group, where it knows more than the
    note says. Never lowers it, never raises."""
    if not ha_vote.AUTO_MODE_SHIPPED or st.get('broken') or not _in_group(st):
        return
    lease = _lease(st)
    chain = (list(lease.get('cfg_chain') or []) + [lease['cfg']]) if lease is not None else []
    auto = (st.get('leader') is True or st.get('group_mode') in (ha_vote.MODE_AUTO, ha_vote.MODE_PENDING)
            or any(isinstance(c, dict) and (c.get('body') or {}).get('mode') in (ha_vote.MODE_AUTO, ha_vote.MODE_PENDING)
                   for c in chain))
    cfg_id = ha_vote.pair(lease['cfg']['id']) if lease is not None else None
    witness = _witness(st)
    seen = _group_seen(st)
    if seen is not None:
        grows = ((auto and not seen['auto']) or (cfg_id is not None and (seen['cfg_id'] is None or cfg_id > seen['cfg_id']))
                 or (witness is not None and witness != seen['witness']))
        if not grows:
            return
        auto = auto or seen['auto']
        if cfg_id is None or (seen['cfg_id'] is not None and seen['cfg_id'] > cfg_id):
            cfg_id = seen['cfg_id']
        witness = witness or seen['witness']
    elif not auto and witness is None:
        return
    rec = {'instance_id': st['instance_id'], 'auto': auto,
           'cfg_id': list(cfg_id) if cfg_id is not None else None, 'witness': witness}
    try:
        _write_private(_group_seen_path(), json.dumps(rec, sort_keys=True).encode())
        _group_seen_cache[_group_seen_path()] = rec
    except OSError as e:
        logging.warning(f"[HA] could not note what this instance knows about its group: {e}")


def _drop_group_seen():
    """The instance left its group (or joins a new one): what it knew goes with it."""
    path = _group_seen_path()
    _group_seen_cache.pop(path, None)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        logging.warning(f"[HA] could not remove {path}: {e}")


def _commit_locked(new):
    """Write `new`, then make it the state. Memory never runs ahead of the file:
    a failed write leaves both as they were."""
    if new.get('leader') and new.get('role') != ROLE_ACTIVE:
        new = {k: v for k, v in new.items() if k != 'leader'}
    before = (_state.get('role'), _state.get('epoch'), _state.get('leader'), _state.get('lease'))
    try:
        _write_locked(new)
    except OSError:
        if _vote_write['on'] and _state and os.path.exists(STATE_FILE):
            # a strict write that failed at the directory sync has its rename in place
            # already: the caller keeps what it had, and so does the file the next start
            # reads (a refused vote, a config the mode route said was not written)
            try:
                _write_locked(_state, strict=False)
            except Exception as e:
                logging.error(f"[HA] could not put the state file back after a failed write: {e}")
        raise
    _note_marker(new)
    _note_group_seen(new)
    _state.clear()
    _state.update(new)
    rt = _rts.get(new.get('instance_id'))
    if rt is not None and rt.node is not None and not rt.saving:
        # role, epoch or lease state changed past the node that runs the lease (a
        # promotion by hand, a removal): it is built again from the file
        if (before[:3] != (new.get('role'), new.get('epoch'), new.get('leader'))
                or before[3] is not new.get('lease')):
            rt.stale = True


def _note_member_in_db(instance):
    """MEMBER_SETTING in this instance's database: its id while it is in a group, ''
    once it is not. Never raises."""
    try:
        from pegaprox.core.db import get_db
        get_db().save_server_setting(MEMBER_SETTING, instance)
    except Exception as e:
        logging.warning(f"[HA] could not note the group membership in the database: {e}")


def _drop_recovery_locks(instance):
    """This instance's recovery lock files on the clusters' shared storage go when its
    epoch starts to count in another group, or in none: a file from before stands in the
    way of that group's active (PegaProxManager._ha_acquire_recovery_lock). Never raises."""
    try:
        from pegaprox.core.manager import drop_own_recovery_locks
        drop_own_recovery_locks(instance)
    except Exception as e:
        logging.warning(f"[HA] could not remove this instance's recovery lock files: {e}")


def check_markers_at_boot():
    """main(), before the boot check. The state file decides when it is there: the
    database marker follows it, and an instance paired before the markers existed gets
    its marker file now. When the file is gone and only the database says this instance
    is in a group (a database restored without its config directory), it stays passive
    like _load does for the marker file. Never raises; returns a short status string."""
    global _state
    try:
        from pegaprox.core.db import get_db
        held = get_db().get_server_setting(MEMBER_SETTING) or ''
    except Exception as e:
        logging.warning(f"[HA] could not read {MEMBER_SETTING} from the database: {e}")
        return 'no database'
    with _lock:
        st = _load()
        if st.get('broken'):
            return 'broken'
        if _in_group(st):
            _note_marker(st)
            mine = st['instance_id']
        elif held and not os.path.exists(STATE_FILE):
            why = 'belongs to a group, as its database says'
            logging.error(f"[HA] {STATE_FILE} is missing but this instance {why} - staying "
                          "passive until it is restored or unpaired")
            _state = _missing_state(why)
            return 'missing'
        else:
            mine = ''
    if held != mine:
        _note_member_in_db(mine)
    return 'member' if mine else 'standalone'


def _update(**changes):
    with _lock:
        _load()
        _commit_locked(dict(_state, **changes))
        return dict(_state)


def _update_sync(**changes):
    with _lock:
        _load()
        sync = dict(_state.get('sync') or {})
        sync.update(changes)
        _commit_locked(dict(_state, sync=sync))


def _note_members(notes):
    """{member id: changes} into the member records, one write for all of them, and
    none when nothing changes (a member that stays down keeps the same error). A
    member that left meanwhile stays gone."""
    with _lock:
        _load()
        ms = dict(_state.get('members') or {})
        hit = False
        for mid, changes in notes.items():
            if mid in ms:
                merged = dict(ms[mid], **changes)
                if merged != ms[mid]:
                    ms[mid] = merged
                    hit = True
        if hit:
            _commit_locked(dict(_state, members=ms))


def reset_for_tests():
    """Forget the cached state so the next call rereads STATE_FILE."""
    global _state
    with _lock:
        _state = None
        _group_seen_cache.clear()


def role():
    return _load().get('role', ROLE_STANDALONE)


def is_standby():
    return role() == ROLE_STANDBY


def is_active():
    """True when this instance may act: change a cluster, fire schedules, send mail.

    A standalone instance is active too. Only a standby holds back; with the live
    view its managers still read (managers_wanted), and nothing more.

    In an automatic group the leader may act only while it holds the lease, in the
    process that held it at its start, and a new leader only once the takeover wait
    is over. Worked out on every call: a lease that ran out closes every gate at once.
    """
    st = _load()
    if st['role'] == ROLE_STANDBY:
        return False
    if not _lease_mode(st):
        return True
    node = _lease_live(st)
    return node is not None and node.is_active()


def holds_lease():
    """True when this instance is the one the group follows right now: what it hands out
    is the group's configuration. Anywhere but in an automatic group that is every
    instance that is no standby; there, the leader while its lease is valid, the
    takeover wait included."""
    st = _load()
    if not _lease_mode(st):
        return st['role'] != ROLE_STANDBY
    node = _lease_live(st)
    return node is not None and node.holds_lease()


def acting_process():
    """True in the process that came up to act: what is started once at boot (the HA
    monitor, the plugin backgrounds) goes by this, and whatever it starts waits while
    is_active() is false. Anywhere but in an automatic group that is every instance
    that is no standby; there, the leader's process once a majority renewed its lease."""
    st = _load()
    if not _lease_mode(st):
        return st['role'] != ROLE_STANDBY
    rt = _rts.get(st['instance_id'])
    return st['role'] == ROLE_ACTIVE and rt is not None and rt.acting and not rt.stale


def instance_id():
    return _load()['instance_id']


def epoch():
    return int(_load().get('epoch') or 0)


def lock_holder():
    """(instance id, epoch) for a lock on shared storage. The id goes to disk first: a
    standalone that never paired has saved nothing, gets a new id at every start, and
    would read its own lock from before a restart as somebody else's."""
    with _lock:
        st = _load()
        if not st.get('broken') and not os.path.exists(STATE_FILE):
            _commit_locked(dict(st))
        return st['instance_id'], int(st.get('epoch') or 0)


def _epoch_value(value, low=0):
    """`value` when it is an epoch, None for anything else: a whole number from `low`
    to EPOCH_MAX. The one check for every epoch another member sends or reports, and
    for every one this instance takes over from it."""
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= EPOCH_MAX:
        return None
    return value


def _joined_order(ms):
    """Member ids in the order they joined, the id settling a tie."""
    return sorted(ms, key=lambda mid: (str(ms[mid].get('joined_at') or ''), mid))


def members():
    """Every other member of the group in the order they joined, as copies that
    carry their instance_id."""
    ms = _load().get('members') or {}
    return [dict(ms[mid], instance_id=mid) for mid in _joined_order(ms)]


def member(member_id):
    """The record of one member with its instance_id, None for anybody else."""
    rec = (_load().get('members') or {}).get(member_id) if isinstance(member_id, str) else None
    return dict(rec, instance_id=member_id) if rec else None


def own_url():
    """The address this instance is known at in its group: the one it gave out with
    its last pairing code, or the one it joined with (kept up to date from the
    leader's member list). '' when it has neither."""
    return _load().get('own_url') or ''


def source_id():
    """The member a standby pulls from, None on any other instance or when it has
    lost it (the active unpaired while this one could not be told)."""
    st = _load()
    sid = st.get('source')
    if st['role'] != ROLE_STANDBY or sid not in (st.get('members') or {}):
        return None
    return sid


def peer():
    """The one member, for code that needs only one: on a standby the member it pulls
    from, anywhere else the first member. None when there is none."""
    if role() == ROLE_STANDBY:
        return member(source_id())
    ms = members()
    return ms[0] if ms else None


def standby_count():
    """Standbys in the group as this instance knows it: on the active its members, on
    a standby everybody but the member it pulls from, itself included."""
    st = _load()
    n = len(st.get('members') or {})
    if st['role'] == ROLE_ACTIVE:
        return n
    if st['role'] == ROLE_STANDBY and n:
        return n + 1 - (1 if source_id() else 0)
    return 0


def group_full():
    """True when this instance has MAX_MEMBERS - 1 other members and takes no more."""
    return len(_load().get('members') or {}) >= MAX_MEMBERS - 1


def _seen_in_group(rec):
    """A member known to run this release: it answered with the group mark, or it has
    a public key, which only this release makes."""
    return bool(rec.get('group_seen') or rec.get('public_key'))


def group_waiting():
    """The first member not yet seen running this release, None when there is none.
    A release from before the groups takes calls from its one peer only, so a
    further standby would be refused there and stranded once it is promoted."""
    for rec in members():
        if not _seen_in_group(rec):
            return rec
    return None


def _group_waiting_error(rec):
    return (f"{rec.get('url') or rec['instance_id']} has not answered as a member of a group "
            "yet - update it to this release and let it answer once before adding a standby")


def _confirmed_standby(rec, st):
    """The member answered as a standby under our current epoch."""
    return (rec.get('role_seen') == ROLE_STANDBY
            and int(rec.get('epoch_seen') or 0) == int(st.get('epoch') or 0))


# --- the live view -------------------------------------------------------------

def live_view():
    """Whether a standby runs its managers read-only, so its UI shows live data.

    Per instance and never part of a snapshot; on until an admin switches it off.
    Means nothing on an active instance, whose managers always run."""
    value = _load().get('live_view', True)
    return value if isinstance(value, bool) else True


def set_live_view(value):
    """Switch the live view of this instance. Returns True when it changed.

    Only saved: a standby runs with the new value after its next start, which
    apply_config_now() brings about."""
    if not isinstance(value, bool):
        raise HaError('live_view is true or false')
    with _lock:
        before = live_view()
        if _run['live_view'] is None:
            # nothing has changed it in this process yet, so this is what it runs with
            _run['live_view'] = before
        if value == before:
            return False
        _update(live_view=value)
        _run['live_view_changed'] = _now()
    return True


def managers_wanted():
    """True when this process starts its cluster, PBS and ESXi managers: always on an
    instance that acts, on a standby only with the live view on.

    A state file that cannot be read keeps them down. Whether the admin switched
    the live view off is in the part we cannot read."""
    st = _load()
    if st['role'] != ROLE_STANDBY:
        return True
    return not st.get('broken') and live_view()


# --- forwarded writes ------------------------------------------------------------

def forward_writes():
    """Whether this instance, as a standby, hands the writes it refuses to the active.

    Per instance and never part of a snapshot; on until an admin switches it off."""
    value = _load().get('forward_writes', True)
    return value if isinstance(value, bool) else True


def set_forward_writes(value):
    """Switch forward_writes. Returns True when it changed. Nothing holds on to the
    value, the next write goes by it."""
    if not isinstance(value, bool):
        raise HaError('forward_writes is true or false')
    with _lock:
        if value == forward_writes():
            return False
        _update(forward_writes=value)
    return True


def leader_reachable():
    """On a standby: the member it pulls from last answered as active, and did answer
    the last time this instance tried. False on every other instance. A standby that
    was removed, or cannot read its state file, has no such member."""
    st = _load()
    if st['role'] != ROLE_STANDBY:
        return False
    rec = (st.get('members') or {}).get(st.get('source'))
    return (bool(rec) and rec.get('role_seen') == ROLE_ACTIVE
            and _silent_source['id'] != st.get('source'))


def forwarding():
    """True when a write this standby refuses goes to the active right now: forwarding
    is on and the leader is reachable. False on every other instance."""
    return leader_reachable() and forward_writes()


def forwards_read(rule, view_args=None):
    """Whether a standby reads `rule`, a GET as app.url_map writes it, on the leader while
    it forwards: every rule of FORWARDED_READS, those of XCPNG_TASK_READS for an XCP-ng
    pool only. The leader takes each of them whatever the cluster (api/ha.py
    _forwarded_read)."""
    if rule not in FORWARDED_READS:
        return False
    if rule not in XCPNG_TASK_READS:
        return True
    from pegaprox.globals import cluster_managers
    mgr = cluster_managers.get((view_args or {}).get('cluster_id'))
    return getattr(mgr, 'cluster_type', None) == 'xcpng'


# --- serving users ---------------------------------------------------------------

def serve_assigned():
    """Whether the leader made this standby one of the group's active instances: its
    own entry in the member list from the leader says serve. Users are served here
    then the way the leader serves them: they sign in here, see the clusters live and
    open their consoles here, and every change goes to the leader. The role stays
    standby, so nothing that acts on its own starts here (is_active).

    Set on the leader (set_member_serve) and taken with each sync (_adopt_group).
    False on every other instance: the leader is active anyway, and a member that was
    promoted has nobody above it to say so."""
    st = _load()
    return st['role'] == ROLE_STANDBY and st.get('serve_assigned') is True


def actives():
    """How many instances of the group serve users, as this instance knows the group:
    the leader and every member it made active. 1 on a standalone instance. A standby
    does not count the flag of the member it pulls from: that one is the leader, and
    a flag it had before its promotion is gone with the next sync."""
    st = _load()
    src = st.get('source') if st['role'] == ROLE_STANDBY else None
    n = 1 + sum(1 for mid, rec in (st.get('members') or {}).items()
                if mid != src and rec.get('serve') is True)
    return n + (1 if serve_assigned() else 0)


def set_member_serve(member_id, value):
    """Leader: make the member one of the group's active instances (True), or a standby
    again (False). Returns (changed, actives after it). The flag goes out with the
    member list, and the member takes it with its next sync.

    At most ACTIVE_LIMIT, the leader included: one more raises ActiveLimit. Counted and
    written under the state lock, so two admins asking at once cannot both take the
    last place. Back to standby always goes through."""
    if not isinstance(value, bool):
        raise HaError('serve is true or false')
    with _lock:
        st = _load()
        if st['role'] != ROLE_ACTIVE:
            raise HaError('Only the leader sets which instances are active')
        ms = dict(st.get('members') or {})
        if not isinstance(member_id, str) or member_id not in ms:
            raise HaError('That instance is not a member of this group')
        count = actives()
        if (ms[member_id].get('serve') is True) == value:
            return False, count
        if value and count >= ACTIVE_LIMIT:
            raise ActiveLimit(ACTIVE_LIMIT_ERROR)
        ms[member_id] = dict(ms[member_id], serve=value)
        _commit_locked(dict(st, members=ms))
    return True, count + (1 if value else -1)


def serving():
    """True when this standby serves users now: the leader made it active, and the two
    it needs are on, the live view (clusters to show and consoles to open) and
    forwarding (the changes go to the leader). False on every other instance, and on a
    standby that was removed from the group or has lost the member it pulls from: its
    accounts and rights are those of its last sync, and nothing the leader changes
    reaches it any more. A leader that is only out of reach keeps it serving."""
    st = _load()
    if st['role'] != ROLE_STANDBY or st.get('removed') or source_id() is None:
        return False
    return serve_assigned() and live_view() and forward_writes()


def consoles_here():
    """Whether consoles, shells and SPICE open on this instance: everywhere but on a
    standby that does not serve users."""
    return not is_standby() or serving()


def sign_in_digest(username):
    """A digest of this instance's copy of the account's password hash and salt, ''
    when there is no such account. A standby sends it with a forwarded write: an
    active whose copy differs has changed the password since, and the session the
    standby vouches for is one the next sync would end (_end_sessions)."""
    from pegaprox.core.db import get_db
    try:
        row = get_db().conn.cursor().execute(
            'SELECT password_hash, password_salt FROM users WHERE username = ?', (username,)).fetchone()
    except Exception as e:
        logging.warning(f"[HA] could not read the sign-in of {username!r}: {e}")
        return ''
    if row is None:
        return ''
    return hashlib.sha256(b'pegaprox-ha-sign-in:' + json.dumps([row[0], row[1]]).encode()).hexdigest()


def _note_source_heard(member_id, heard):
    """Whether the member this standby pulls from answered the last call to it."""
    if heard:
        if _silent_source['id'] == member_id:
            _silent_source['id'] = None
    elif member_id:
        _silent_source['id'] = member_id


# --- what the managers connect with -----------------------------------------------

# Everything a manager is built from and holds on to once connected (the current
# host, the auth mode, the SSH pool). A change here needs a new manager, which a
# standby builds in place of the old one. Fallback hosts, the HA settings, updated_at
# and the display and balancing fields stay out: the active rewrites some of them on
# its own, and the managers read the rest each time they use them.
# (kind, table, only enabled rows, columns)
_IDENTITY = (
    ('cluster', 'clusters', False,
     ('cluster_type', 'host', 'user', 'pass_encrypted', 'api_port', 'ssl_verification',
      'api_token_user', 'api_token_secret_encrypted', 'ssh_user', 'ssh_key_encrypted',
      'ssh_port', 'ssh_disabled')),
    ('pbs', 'pbs_servers', True,
     ('host', 'port', 'user', 'pass_encrypted', 'api_token_id', 'api_token_secret_encrypted',
      'fingerprint', 'ssl_verify', 'ssh_user', 'ssh_port', 'ssh_key_encrypted')),
    ('vmware', 'vmware_servers', True,
     ('host', 'port', 'username', 'pass_encrypted', 'server_type', 'ssl_verify')),
)
_IDENTITY_LABELS = {'cluster': ('cluster', 'clusters'), 'pbs': ('PBS server', 'PBS servers'),
                    'vmware': ('ESXi server', 'ESXi servers')}
_UNREADABLE = '\x00unreadable'

# Read by the managers at the moment they use them, so a sync hands them over in
# place: what the active's cluster routes set on mgr.config (PUT /api/clusters/<id>,
# location, backup SLA) less the connection fields above, plus the fallback hosts
# and SMBIOS settings the active changes without an admin. ha_enabled and
# ha_settings are the exception: a PVE manager copies them when it is built, so
# _hand_over_ha_view refreshes those copies as well.
_REFRESH_CLUSTER_FIELDS = (
    'name', 'enabled', 'check_interval', 'migration_threshold', 'migration_tolerance',
    'migration_cooldown', 'auto_migrate', 'balance_containers', 'balance_local_disks', 'dry_run', 'ha_enabled',
    'ha_settings', 'excluded_nodes', 'predictive_balancing', 'predictive_threshold',
    'balance_cpu_weight', 'balance_mem_weight', 'balance_io_weight', 'cpu_baseline',
    'vnc_tunnel', 'proxlb_tags_enabled', 'proxlb_pins_auto_migrate', 'proxlb_pins_strict',
    'node_ui_suffix', 'backup_sla_max_age_hours',
    'latitude', 'longitude', 'location_label', 'fallback_hosts', 'smbios_autoconfig',
)
_REFRESH_SERVER_FIELDS = ('name', 'notes', 'linked_clusters')


def _plain(db, value):
    """A sealed column as the manager sees it. One we cannot open gets a fixed marker:
    a fresh nonce on every save must not read as a change."""
    if not value:
        return ''
    try:
        return db._decrypt(value)
    except Exception:
        return _UNREADABLE


def _identity_items():
    """{'<kind>:<id>': digest} over every cluster and every enabled PBS and ESXi server.

    Taken from the decrypted values: each save on the active seals the secrets
    again under a new nonce, and that alone must not reload anything."""
    from pegaprox.core.db import get_db
    db = get_db()
    cur = db.conn.cursor()
    present = _existing_tables(cur)
    items = {}
    for kind, table, enabled_only, columns in _IDENTITY:
        if table not in present:
            continue
        cur.execute(f'SELECT * FROM "{table}"' + (' WHERE enabled = 1' if enabled_only else ''))
        for row in cur.fetchall():
            row = dict(row)
            h = hashlib.sha256()
            for col in columns:
                v = row.get(col)
                _hash_value(h, _plain(db, v) if col.endswith('_encrypted') else v)
            items[f"{kind}:{row['id']}"] = h.hexdigest()
    return items


def _signature_of(items):
    h = hashlib.sha256(b'pegaprox-ha-managers')
    for key in sorted(items):
        _hash_value(h, key)
        _hash_value(h, items[key])
    return h.hexdigest()


def manager_signature():
    """A digest of how the cluster, PBS and ESXi managers connect: which ones there are,
    host, user, credentials, ports, TLS and SSH settings, cluster and server type.

    Held in memory only, never written anywhere."""
    return _signature_of(_identity_items())


def _describe_change(before, after):
    """'1 cluster added, 2 PBS servers changed' - counts and kinds, no names or values."""
    parts = []
    if before is not None:
        for kind, (one, many) in _IDENTITY_LABELS.items():
            b = {k: v for k, v in before.items() if k.startswith(kind + ':')}
            a = {k: v for k, v in after.items() if k.startswith(kind + ':')}
            for word, n in (('added', len(a.keys() - b.keys())),
                            ('removed', len(b.keys() - a.keys())),
                            ('changed', sum(1 for k in a.keys() & b.keys() if a[k] != b[k]))):
                if n:
                    parts.append(f'{n} {one if n == 1 else many} {word}')
    return ', '.join(parts) or 'the connection settings changed'


def note_managers_started(signature):
    """main(), right after the managers came up: the manager_signature() they started
    from. A sync that changes it reloads the managers it concerns on a standby
    (reload_managers)."""
    try:
        items = _identity_items()
    except Exception as e:
        logging.warning(f"[HA] could not read what the managers were started from: {e}")
        items = None
    with _lock:
        _run.update(managers=True, signature=signature, items=items, live_view=live_view(),
                    reload=None)


def _refresh_managers():
    """Hand what the running managers read at the moment of use over to them, the way
    the active's PUT /api/clusters/<id> does: setattr on mgr.config, no stop and no
    start. On a standby also the HA view and the PegaProx node maintenance, which a
    PVE manager otherwise only reads at its start. Returns how many values changed."""
    from pegaprox import globals as g
    from pegaprox.core.db import get_db
    db = get_db()
    changed = 0
    for cid, data in (db.get_all_clusters() or {}).items():
        mgr = g.cluster_managers.get(cid)
        cfg = getattr(mgr, 'config', None)
        if cfg is None or getattr(mgr, 'cluster_type', None) == 'esxi':
            continue
        ha_changed = False
        for key in _REFRESH_CLUSTER_FIELDS:
            if key in data and hasattr(cfg, key) and getattr(cfg, key) != data[key]:
                setattr(cfg, key, data[key])
                changed += 1
                ha_changed = ha_changed or key in ('ha_enabled', 'ha_settings')
        if is_active():
            continue
        try:
            if ha_changed:
                _hand_over_ha_view(mgr, cfg)
            follow = getattr(mgr, '_follow_persisted_maintenance', None)
            if follow is not None:
                changed += int(follow() or 0)
        except Exception as e:
            logging.warning(f"[HA] could not refresh the HA or maintenance view of cluster {cid}: {e}")
    cur = db.conn.cursor()
    for registry, table in ((g.pbs_managers, 'pbs_servers'), (g.vmware_managers, 'vmware_servers')):
        if not registry:
            continue
        cur.execute(f'SELECT id, name, notes, linked_clusters FROM "{table}"')
        for row in cur.fetchall():
            mgr = registry.get(row['id'])
            if mgr is None:
                continue
            try:
                linked = json.loads(row['linked_clusters'] or '[]')
            except (TypeError, ValueError):
                linked = []
            fresh = {'name': row['name'], 'notes': row['notes'], 'linked_clusters': linked}
            for key in _REFRESH_SERVER_FIELDS:
                value = fresh[key]
                if getattr(mgr, key, None) != value:
                    setattr(mgr, key, value)
                    changed += 1
    return changed


def _hand_over_ha_view(mgr, cfg):
    """A PVE manager copies ha_enabled and ha_settings into its own fields when it is
    built, and the HA page (get_ha_status) reads those copies, not mgr.config. On a
    standby the HA monitor never runs, so the copies are only a view: rebuild them
    from the synced row. Wherever a monitor runs they are its own and stay as they are."""
    apply = getattr(mgr, '_apply_ha_settings', None)
    if apply is None or getattr(mgr, 'ha_thread', None) is not None:
        return
    settings = getattr(cfg, 'ha_settings', None)
    mgr.ha_enabled = bool(getattr(cfg, 'ha_enabled', False))
    apply(settings if isinstance(settings, dict) else {})


def _follow_plugin_state():
    """A standby runs a plugin exactly when the leader's synced state says so
    (api/plugins.py follow_synced_state). Never raises."""
    if not is_standby():
        return
    try:
        from pegaprox.api.plugins import follow_synced_state
        loaded, unloaded = follow_synced_state()
        if loaded or unloaded:
            logging.info(f"[HA] sync: plugins loaded {loaded or '-'}, unloaded {unloaded or '-'}")
    except Exception as e:
        logging.warning(f"[HA] could not follow the plugin state after a sync: {e}")


def _after_sync_applied():
    """A sync changed our database: refresh the running managers in place, and when
    their connection settings changed, note a reload. Never raises."""
    if not _run['managers']:
        return
    try:
        n = _refresh_managers()
        if n:
            logging.info(f"[HA] sync: handed {n} changed setting(s) to the running managers")
    except Exception as e:
        logging.warning(f"[HA] could not refresh the running managers after a sync: {e}")
    try:
        items = _identity_items()
    except Exception as e:
        logging.warning(f"[HA] could not read the connection settings after a sync: {e}")
        return
    _note_signature(_signature_of(items), items)


def _note_signature(sig, items):
    with _lock:
        pending = _run['reload']
        if sig == _run['signature']:
            if pending:
                # changed and changed back before it settled
                _run['reload'] = None
                logging.warning("[HA] the connection settings are back to what the managers "
                                "run with - nothing to reload")
            return
        if pending and pending['signature'] == sig:
            return
        reason = _describe_change(_run['items'], items)
        _run['reload'] = {'signature': sig, 'since': time.monotonic(), 'since_iso': _now(),
                          'reason': reason}
    logging.warning(f"[HA] connection settings changed on the active instance ({reason}) - "
                    f"reloading those managers once they have held for {RELOAD_SETTLE}s")
    # a second past it: the timer's clock and time.monotonic() need not agree to the
    # millisecond, and a timer that comes early finds nothing due
    _reload_later(RELOAD_SETTLE + 1)


def _later(delay, fn, name):
    """fn in a thread of its own, `delay` seconds from now (a greenlet under gevent)."""
    t = threading.Timer(delay, fn)
    t.daemon = True
    t.name = name
    t.start()


def _reload_later(delay):
    try:
        _later(delay, _reload_if_due, 'ha-reload')
    except Exception as e:
        # the next pull looks again
        logging.warning(f"[HA] could not schedule the reload of the managers: {e}")


def _live_view_switch():
    """'on' or 'off' when a standby's live view is not the one this process runs with."""
    running = _run['live_view']
    if running is None or not is_standby():
        return ''
    now = live_view()
    return '' if now == running else ('on' if now else 'off')


def _reload_wait():
    """Seconds until the waiting reload may run, 0 once it may, None when none waits."""
    # read once: a sync that brings the old settings back clears it meanwhile
    pending = _run['reload']
    if not pending or _run['restarting'] or not is_standby():
        return None
    return max(0.0, pending['since'] + RELOAD_SETTLE - time.monotonic())


def _reload_if_due():
    """The reload that waits, once it has settled: from its timer, and after every pull
    in case the timer never came. Returns True when it reloaded something."""
    if _reload_wait() != 0:
        return False
    return reload_managers()


def reload_managers(wait=False):
    """A standby with the live view: bring the running managers in line with how the
    configuration says they connect, in this process. A cluster, PBS or ESXi server
    that is new is built and started the way main() starts it (app._start_managers),
    read-only like every manager on a standby; one that is gone is stopped and dropped;
    one whose connection changed is stopped and built again. The others keep running,
    and so does every session and console of this instance.

    One at a time. Another caller gets False at once, or with `wait` (the admin's
    "apply now") waits for the one that runs. The configuration is read under the pull
    lock, never halfway through a sync; a sync that lands while the managers are being
    rebuilt notes its change, which is reloaded after this one. Returns True when a
    manager was added, dropped or rebuilt."""
    got = _reload_lock.acquire(timeout=PULL_TIMEOUT + 5) if wait else _reload_lock.acquire(False)
    if not got:
        return False
    started_with = _run['reload']
    try:
        return _reload_locked()
    finally:
        _reload_lock.release()
        pending = _run['reload']
        if pending and pending is not started_with:
            # came in meanwhile, and its timer may have found the lock taken
            _reload_later(max(0.0, pending['since'] + RELOAD_SETTLE - time.monotonic()) + 1)


def _reload_locked():
    # a restart is on its way, or about to be asked for: it takes the managers along
    if not is_standby() or not _run['managers'] or _run['restarting'] or _live_view_switch():
        return False
    if not _pull_lock.acquire(timeout=PULL_TIMEOUT + 5):
        logging.warning("[HA] a sync is taking long - the managers are reloaded after it")
        return False
    try:
        from pegaprox.core.db import get_db
        items = _identity_items()
        clusters = get_db().get_all_clusters()
    except Exception as e:
        logging.warning(f"[HA] could not read the connection settings to reload the managers: {e}")
        return False
    finally:
        _pull_lock.release()
    before = _run['items']
    if before is None:
        # what they started from could not be read at the start: every running one
        # counts as changed
        before = {key: None for key in _running_keys()}
    added = sorted(items.keys() - before.keys())
    removed = sorted(before.keys() - items.keys())
    changed = sorted(k for k in items.keys() & before.keys() if items[k] != before[k])
    sig = _signature_of(items)
    reason = _describe_change(before, items)
    failed = _rebuild(added, removed, changed, clusters) if added or removed or changed else None
    with _lock:
        _run.update(signature=sig, items=dict(items))
        pending = _run['reload']
        if pending and pending['signature'] == sig:
            _run['reload'] = None
        if failed is not None:
            _run['last_reload'] = {'at': _now(), 'reason': reason, 'failed': failed}
    if failed is None:
        return False
    _after_rebuild(items)
    note = f" - could not build {', '.join(failed)}" if failed else ''
    _audit('ha.managers_reloaded', reason + note)
    logging.warning(f"[HA] reloaded the managers for the configuration of the active "
                    f"instance: {reason}{note}")
    return True


def _after_rebuild(built):
    """A sync that landed while the managers were being rebuilt handed its rows to the
    old, stopped ones and was compared with what ran before, so one that undid the
    change cleared the reload it is owed now. Once more under the pull lock, against the
    managers that run now: hand the rows over in place, and note a reload when how they
    connect is no longer `built`. A sync that holds the lock meanwhile does both itself."""
    if not _pull_lock.acquire(timeout=PULL_TIMEOUT + 5):
        return
    try:
        try:
            _refresh_managers()
        except Exception as e:
            logging.warning(f"[HA] could not refresh the reloaded managers: {e}")
        items = _identity_items()
    except Exception as e:
        logging.warning(f"[HA] could not read the connection settings after the reload: {e}")
        return
    finally:
        _pull_lock.release()
    if items != built:
        _note_signature(_signature_of(items), items)


def _registries():
    from pegaprox import globals as g
    return {'cluster': g.cluster_managers, 'pbs': g.pbs_managers, 'vmware': g.vmware_managers}


def _running_keys():
    regs = _registries()
    keys = {f'pbs:{mid}' for mid in list(regs['pbs'])} | {f'vmware:{mid}' for mid in list(regs['vmware'])}
    # an ESXi host is listed among the clusters too (XHM), and counts as its vmware entry
    return keys | {f'cluster:{mid}' for mid, mgr in list(regs['cluster'].items())
                   if getattr(mgr, 'cluster_type', None) != 'esxi'}


def _drop(regs, kind, mid, mgr):
    """Take `mgr` out of its registry, and an ESXi host's cluster entry with it. Only
    that object: a newer one under the same id stays."""
    if mgr is None:
        return
    if regs[kind].get(mid) is mgr:
        regs[kind].pop(mid, None)
    if kind == 'vmware':
        entry = regs['cluster'].get(mid)
        if getattr(entry, 'cluster_type', None) == 'esxi' and getattr(entry, '_vmware', None) is mgr:
            regs['cluster'].pop(mid, None)


def _rebuild(added, removed, changed, clusters):
    """Stop what is gone or changed, build what is new or changed, drop what is gone.
    Returns the keys that could not be built; their managers are gone as well, like
    the ones a start cannot build.

    A changed manager stays in its registry, stopped, until the new one takes its
    place, so a request in between still finds the cluster. stop() acts on nothing
    here: it ends the manager's own threads, and the self-fence agents are stopped only
    where the HA monitor ran and this instance acts (manager.stop_ha_monitor)."""
    from pegaprox.app import _start_managers
    regs = _registries()
    old = {}
    for key in removed + changed:
        kind, _, mid = key.partition(':')
        mgr = old[key] = regs[kind].get(mid)
        # PBS and ESXi servers have no loop of their own to stop
        if kind == 'cluster' and mgr is not None:
            try:
                mgr.stop()
            except Exception as e:
                logging.warning(f"[HA] could not stop the manager of cluster {mid}: {e}")
    fresh = added + changed
    for key in fresh:
        kind, _, mid = key.partition(':')
        if kind == 'cluster' and mid in clusters:
            # one at a time: a cluster that cannot be built keeps none of the others back
            try:
                _start_managers({mid: clusters[mid]}, only=())
            except Exception as e:
                logging.warning(f"[HA] could not start the manager of cluster {mid}: {e}")
    servers = [key for key in fresh if not key.startswith('cluster:')]
    if servers:
        try:
            _start_managers({}, only=servers)
        except Exception as e:
            logging.warning(f"[HA] could not start the PBS and ESXi managers: {e}")
    for key in removed:
        kind, _, mid = key.partition(':')
        _drop(regs, kind, mid, old[key])
    failed = []
    for key in fresh:
        kind, _, mid = key.partition(':')
        mgr = regs[kind].get(mid)
        if mgr is None or mgr is old.get(key):
            failed.append(key)
            _drop(regs, kind, mid, old.get(key))
        elif kind == 'vmware':
            # rebuilt, and no ESXi host any more: its old cluster entry goes
            _drop(regs, 'vmware', mid, old.get(key))
    return failed


def _restart_for_config(reason):
    with _lock:
        if _run['restarting']:
            return False
        _run['restarting'] = True
    _audit('ha.restart_for_config', reason)
    logging.warning(f"[HA] restarting to pick up the configuration of the active instance: {reason}")
    restart_process(f'configuration changed on the active instance: {reason}')
    return True


def apply_config_now():
    """The admin's "apply now" on a standby. A live view switched since this process
    started restarts it at once. A change to how the managers connect, waiting or not
    looked at yet, is reloaded now, past the settle time.

    Returns 'restart' when a restart is on its way, 'reload' when managers were
    reloaded, False when there is nothing to apply. Raises HaError anywhere but on a
    standby."""
    if not is_standby():
        raise HaError('Only a standby takes its configuration from the active instance')
    switch = _live_view_switch()
    if switch:
        return 'restart' if _restart_for_config(f'the live view was switched {switch}') else False
    if _run['managers'] and reload_managers(wait=True):
        return 'reload'
    return False


def _restart_pending():
    """public_status: None, or since and reason of the restart this standby waits for:
    a live view switched since it started."""
    if not is_standby():
        return None
    switch = _live_view_switch()
    if switch:
        return {'since': _run['live_view_changed'] or _now(),
                'reason': f'the live view was switched {switch}'}
    return None


def _reload_pending():
    """public_status: None, or since and reason of the reload that waits to settle."""
    pending = _run['reload'] if is_standby() else None
    return {'since': pending['since_iso'], 'reason': pending['reason']} if pending else None


# --- secrets and codes ---------------------------------------------------------

def _hash_secret(value):
    return hashlib.sha256(('pegaprox-ha:' + (value or '')).encode()).hexdigest()


# The key pairs, the signature over a peer call and the sealed pairing answer are in
# ha_wire.py, which the witness uses as well (MK Oct 2026, #625)

def _new_signing_key():
    """A fresh Ed25519 private key, as the state file keeps it."""
    return ha_wire.new_signing_key()


def _private_key(value):
    return ha_wire.private_key(value)


def _public_of(private):
    return ha_wire.public_of(private)


def _public_key(value):
    """The Ed25519 public key in `value` (base64 of the raw 32 bytes), None for anything
    else, a point of small order included."""
    return ha_wire.public_key(value)


def peer_key_fingerprint(public_key):
    """A short digest of a member's public key for the status page, '' without one."""
    if not _public_key(public_key):
        return ''
    return hashlib.sha256(b'pegaprox-ha-peer-key:' + base64.b64decode(public_key)).hexdigest()[:16]


def own_public_key():
    """The public key of this instance, '' until it has one."""
    value = _load().get('signing_key')
    try:
        return _public_of(_private_key(value)) if value else ''
    except Exception:
        return ''


def _wire_body(json_body):
    """The bytes a peer call carries, the same ones its signature covers."""
    return ha_wire.wire_body(json_body)


def _body_digest(body):
    return ha_wire.body_digest(body)


def _to_sign(method, path, body, ts, nonce, receiver, sender, digest=None):
    return ha_wire.to_sign(method, path, body, ts, nonce, receiver, sender, digest)


def _stream_nonce(stream, receiver):
    """The next nonce of `stream` (_lease_stream, _call_stream) towards `receiver`."""
    with _nonce_lock:
        seq = stream['seq'].get(receiver, 0) + 1
        stream['seq'][receiver] = seq
    return ha_wire.stream_nonce(stream['id'], seq)


def _takes_streams(receiver):
    """Whether `receiver` takes stream nonces on its signed calls: every member, and a
    witness that said it speaks wire 2 or later in its last status answer. A witness of
    the first wire (or one not heard yet) gets random nonces, as it always did (N-1)."""
    st = _load()
    if receiver != ((st.get('witness') or {}).get('instance_id')):
        return True
    rt = _rts.get(st.get('instance_id'))
    wire = ((rt.seen.get(receiver) if rt is not None else None) or {}).get('wire') or 1
    return wire >= 2


def _signed_headers(private, sender, receiver, method, path, body):
    # numbered, not random (_fresh_nonce): a vote or a renewal may come many times a
    # second, and so may the writes a serving member forwards. Each has a stream of its
    # own, and the receiver a share of its own for each: forwarded writes never use up
    # what the renewals need. A witness of the first wire takes neither (N-1)
    if not _takes_streams(receiver):
        return ha_wire.signed_headers(private, sender, receiver, method, path, body, time.time())
    stream = _lease_stream if path in (VOTE_PATH, RENEW_PATH) else _call_stream
    return ha_wire.signed_headers(private, sender, receiver, method, path, body, time.time(),
                                  _stream_nonce(stream, receiver))


class _Signer:
    """Who this instance is to the other members, read once: a caller that fans out
    hands it to every call instead of reading the state in each of them."""

    def __init__(self, instance_id, private=None, secret=None):
        self.instance_id, self.private, self.secret = instance_id, private, secret
        self.public_key = _public_of(private) if private is not None else ''


# the last _Signer made, by (instance id, key, secret) it was made from
_signer_made = {}


def _signer():
    """This instance's _Signer. Makes the key pair on first use, once it is paired: a
    group from before the keys has none yet. A key is written before it is used, or a
    member would take one that a restart forgets. When it cannot be written, the old
    secret alone still reaches the members that hold its hash."""
    with _lock:
        st = _load()
        if not st.get('signing_key') and (st.get('members') or st.get('member_secret')):
            try:
                _commit_locked(dict(st, signing_key=_new_signing_key()))
            except Exception as e:
                logging.warning(f"[HA] could not save a key pair for the peer calls: {e}")
            st = _load()
        value, secret = st.get('signing_key'), st.get('member_secret') or None
        if not value and not secret:
            raise HaError('Not paired')
        made = (st['instance_id'], value, secret)
        held = _signer_made.get('signer')
        if held is not None and held[0] == made:
            # read again for every lease call: the key is parsed once
            return held[1]
        private = None
        if value:
            try:
                private = _private_key(value)
            except Exception as e:
                if not secret:
                    raise HaError(f'The key pair in the HA state file cannot be read ({type(e).__name__})')
        signer = _Signer(st['instance_id'], private, secret)
        if private is not None or not value:
            _signer_made['signer'] = (made, signer)
        return signer


def _auth_for(signer, receiver, legacy=False):
    """The headers of one call to `receiver`, as auth for _peer_call: signed, and with
    `legacy` also the old '<id>:<secret>' and our public key, for a member that may
    not hold that key yet. It records the key from such a call and says so in the
    answer (PEER_KEYED_HEADER); a member from before the keys goes by the secret."""
    def auth(method, path, body):
        h = {}
        if signer.private is not None:
            h.update(_signed_headers(signer.private, signer.instance_id, receiver, method, path, body))
        if legacy and signer.secret:
            h[PEER_HEADER] = f'{signer.instance_id}:{signer.secret}'
            if signer.public_key:
                h[PEER_KEY_HEADER] = signer.public_key
        if PEER_HEADER not in h:
            raise HaError('Not paired')
        return h
    return auth


def forget_seen_nonces():
    """For tests: start the replay cache over."""
    with _nonce_lock:
        _seen_nonces.clear()
        _seen_streams.clear()


def _fresh_nonce(receiver, sender, nonce, ts, lease=False):
    """True the first time `nonce` comes from `sender` within the window. Only called
    once the signature is good, so nobody else can fill a member's share. The votes and
    renewals of automatic failover (`lease`) have a share of their own: a member that
    forwards many writes must not use up what its renewals need, nor the other way. This
    release numbers every signed call (a stream nonce), so neither a confirm round before
    every write nor a member forwarding writes fills a share. A random nonce, from a
    member on a release before (a group updates one member at a time), goes to the
    random share of its kind as before."""
    with _nonce_lock:
        if ha_wire.is_stream_nonce(nonce):
            said = ha_wire.take_stream(_seen_streams.setdefault((receiver, sender, bool(lease)), {}),
                                       nonce, ts, time.time())
        else:
            seen = _seen_nonces.setdefault((receiver, sender, 'lease') if lease else (receiver, sender), {})
            said = ha_wire.take_nonce(seen, nonce, ts, time.time(), _NONCES_PER_SENDER)
    if said == 'full':
        logging.warning(f"[HA] member {sender} sent more signed calls than the replay "
                        "cache holds - refusing until they age out")
    return said == 'ok'


def _process_started():
    """When this process started, by the wall clock as it reads now. Worked out from the
    lease clock, which never steps: a wall clock that was ahead at the start and that NTP
    set back since would otherwise refuse every member's call for as long as it was off."""
    return int(time.time() - (ha_vote.ha_clock() - _PROCESS_STARTED))


def _signature_check(headers, method, path, body, sender, public_key, receiver):
    """'ok' when the signature headers hold for this call, from `sender` under
    `public_key` and for `receiver`, inside the window and with a nonce not seen
    before. 'skewed' for a good signature from outside the window: the member's clock
    is off, or the call is an old one. A call signed before this process started is
    one of those too, since the nonces seen until then are gone. '' for anything else."""
    now = time.time()
    said = ha_wire.signature_verdict(headers, method, path, body, sender, public_key, receiver,
                                     now, _process_started())
    if said == 'window':
        ts = int(headers.get(PEER_TS_HEADER))
        logging.warning(f"[HA] a signed call from member {sender} is {int(now) - ts}s "
                        "off our clock - are the clocks of the members in sync?")
        return 'skewed'
    if said == 'early':
        # whether we took it before the restart is not known any more: a member whose
        # clock is behind hears HA_CLOCK for that long, a replay nothing better
        logging.info(f"[HA] a signed call from member {sender} is older than this process")
        return 'skewed'
    if said != 'ok':
        return ''
    return 'ok' if _fresh_nonce(receiver, sender, headers.get(PEER_NONCE_HEADER),
                                int(headers.get(PEER_TS_HEADER)),
                                lease=path in (VOTE_PATH, RENEW_PATH)) else ''


def _signature_ok(headers, method, path, body, sender, public_key, receiver):
    return _signature_check(headers, method, path, body, sender, public_key, receiver) == 'ok'


def signed_before_body(headers, method, path):
    """Before the body of a large peer call is read: True when its headers carry a
    good signature, inside the window, from a member we hold a key of, over the body
    digest they name. Nothing more - the nonce is not spent here and the body is not
    known yet; peer_verdict checks both once it is read, and a body that is not the
    one named fails there."""
    try:
        claimed = (headers.get(PEER_HEADER) or '').partition(':')[0]
        digest = headers.get(PEER_BODY_HEADER)
        ts, nonce, sig = (headers.get(PEER_TS_HEADER), headers.get(PEER_NONCE_HEADER),
                          headers.get(PEER_SIG_HEADER))
        if not (isinstance(digest, str) and _DIGEST_RE.fullmatch(digest)
                and all(isinstance(v, str) for v in (ts, nonce, sig))
                and _ID_RE.fullmatch(claimed) and _TS_RE.fullmatch(ts)
                and _NONCE_RE.fullmatch(nonce) and _SIGNATURE_RE.fullmatch(sig)):
            return False
        if abs(time.time() - int(ts)) > SIGNATURE_WINDOW or int(ts) < _process_started():
            return False
        st = _load()
        rec = (st.get('members') or {}).get(claimed) or {}
        key = _public_key(rec.get('public_key')) if rec.get('public_key') else None
        if key is None:
            return False
        from cryptography.exceptions import InvalidSignature
        try:
            key.verify(base64.b64decode(sig), _to_sign(method, path, None, ts, nonce,
                                                       st['instance_id'], claimed, digest))
        except (InvalidSignature, ValueError):
            return False
        return True
    except Exception as e:
        logging.debug(f"[HA] could not check the headers of a peer call: {e}")
        return False


def _legacy_ok(secret, digest):
    return (bool(secret) and isinstance(digest, str) and bool(digest)
            and hmac.compare_digest(_hash_secret(secret), digest))


def _record_key(member_id, public_key):
    """A member from before the keys has shown it holds `public_key`: from now on only
    its signed calls count. True when we hold the key afterwards."""
    with _lock:
        st = _load()
        ms = dict(st.get('members') or {})
        rec = ms.get(member_id)
        if rec is None:
            return False
        if rec.get('public_key'):
            return rec['public_key'] == public_key
        ms[member_id] = dict(rec, public_key=public_key)
        try:
            _commit_locked(dict(st, members=ms))
        except Exception as e:
            logging.warning(f"[HA] could not record the key of member {member_id}: {e}")
            return False
    logging.info(f"[HA] member {member_id} signs its calls from now on")
    return True


def peer_verdict(headers, method, path, body):
    """Who sent a peer call: ('member', record), ('removed', tombstone), ('skewed',
    record) or (None, None).

    `headers` is the request's, `path` its path (a peer call carries no query
    string), `body` is every byte of it. A member with a public key on record needs a
    good signature, made for us. One with only the hash of a secret (paired before
    the keys) needs that secret. A key it sends along with a signature over this very
    call is its key from then on, but only when the secret was made for our pair
    (pair_secret): a member list from the active can carry the hash of a secret as
    well, and more instances than the member itself may know that one. The record
    carries keyed=True when we hold the key the call was signed with. 'skewed' is a
    member whose signature is good but whose time is outside the window (or before
    our start): refused, but told why, since that is a clock to fix and no sign
    that it was removed. A removed member is known by the same credentials, so
    the answer it gets tells it and nobody else that it is out."""
    raw = headers.get(PEER_HEADER) if headers is not None else None
    if not isinstance(raw, str) or not raw:
        return None, None
    claimed, _, secret = raw.partition(':')
    if not _ID_RE.fullmatch(claimed):
        return None, None
    st = _load()
    me = st['instance_id']
    rec = (st.get('members') or {}).get(claimed)
    if rec is not None:
        rec = dict(rec, instance_id=claimed)
        if rec.get('public_key'):
            check = _signature_check(headers, method, path, body, claimed, rec['public_key'], me)
            if check == 'ok':
                return 'member', dict(rec, keyed=True)
            if check == 'skewed':
                return 'skewed', rec
            return None, None
        if not _legacy_ok(secret, rec.get('secret_hash')):
            return None, None
        offered, keyed = headers.get(PEER_KEY_HEADER), False
        if (rec.get('pair_secret') is True and isinstance(offered, str) and _public_key(offered)
                and _signature_ok(headers, method, path, body, claimed, offered, me)):
            keyed = _record_key(claimed, offered)
        return 'member', dict(rec, keyed=keyed)
    tomb = (st.get('tombstones') or {}).get(claimed)
    if tomb:
        # an old call of a removed member hears the same, whatever its time
        if tomb.get('public_key') and _signature_check(headers, method, path, body, claimed,
                                                       tomb['public_key'], me):
            return 'removed', dict(tomb, instance_id=claimed)
        if tomb.get('secret_hash') and _legacy_ok(secret, tomb['secret_hash']):
            return 'removed', dict(tomb, instance_id=claimed)
    return None, None


def verify_peer(headers, method='GET', path='', body=b''):
    """The member record (with its instance_id) when a peer call is from a member, else
    None. See peer_verdict."""
    kind, who = peer_verdict(headers, method, path, body)
    return who if kind == 'member' else None


def key_fingerprint(key=None):
    """A short, domain-separated digest of the field key, never the key itself."""
    if key is None:
        from pegaprox.core.db import get_db
        key = get_db().aes_key or b''
    return hashlib.sha256(b'pegaprox-ha-key-fp:' + key).hexdigest()[:16]


def _seal_key(code_secret, salt):
    return ha_wire.seal_key(code_secret, salt)


def _seal(code_secret, payload, aad):
    return ha_wire.seal(code_secret, payload, aad)


def _unseal(code_secret, blob, aad):
    return ha_wire.unseal(code_secret, blob, aad)


def _valid_host(host):
    return ha_wire.valid_host(host)


def valid_https_url(url):
    """`url` as https://host[:port][/path] with the trailing slash gone, or ''.

    One shape for every address that travels: the admin routes, the address a
    pairing code carries and the one a standby sends. The host is a DNS name, an
    IPv4 address or a bracketed IPv6 address. No user info, query, fragment,
    percent escapes, whitespace or control characters. Too long is refused, not cut.
    """
    return ha_wire.valid_https_url(url)


def encode_code(url, fingerprint, secret, active_id):
    return ha_wire.encode_code(CODE_PREFIX, url, fingerprint, secret, active_id)


def decode_code(code):
    try:
        return ha_wire.decode_code(CODE_PREFIX, code)
    except ha_wire.WireError as e:
        raise HaError(str(e))


def create_pairing_code(own_url, fingerprint):
    """On the instance that will be active, or already is. Returns (code, expires_at).

    One code at a time; a new one replaces the old. It is good for PAIRING_TTL. The
    address and pin it carries are also what the member list says about this instance.
    """
    with _lock:
        st = _load()
        if st['role'] == ROLE_STANDBY:
            raise HaError('A standby cannot hand out pairing codes - promote it first')
        why = _pairing_refusal(st)
        if why:
            raise HaError(why)
        if len(st.get('members') or {}) >= MAX_MEMBERS - 1:
            raise HaError(GROUP_FULL_ERROR)
        waiting = group_waiting()
        if waiting:
            raise HaError(_group_waiting_error(waiting))
        secret = secrets.token_urlsafe(32)
        expires = int(time.time()) + PAIRING_TTL
        changes = dict(pairing={'code_hash': _hash_secret(secret), 'expires': expires},
                       own_url=own_url, own_fingerprint=fingerprint or '')
        if not st.get('signing_key'):
            changes['signing_key'] = _new_signing_key()
        _update(**changes)
    return encode_code(own_url, fingerprint, secret, st['instance_id']), expires


def _credentials(rec):
    return {'public_key': rec.get('public_key') or '', 'secret_hash': rec.get('secret_hash') or ''}


def _member_list(st):
    """The group as the active hands it out: the active itself and every member, each
    with address, pin, public key and, for a member paired before the keys, the hash
    of its secret. A member also with serve, whether the active made it one of the
    active instances; the active itself is one anyway. Sorted, so the etag stays put."""
    out = []
    own = {'public_key': '', 'secret_hash': ''}
    if st.get('signing_key'):
        try:
            own['public_key'] = _public_of(_private_key(st['signing_key']))
        except Exception as e:
            logging.warning(f"[HA] the key pair in the state file cannot be read: {e}")
    if st.get('member_secret'):
        own['secret_hash'] = _hash_secret(st['member_secret'])
    if own['public_key'] or own['secret_hash']:
        out.append(dict(own, instance_id=st['instance_id'], url=st.get('own_url') or '',
                        fingerprint=st.get('own_fingerprint') or ''))
        if st.get('agent_vmid'):
            out[-1]['agent_vmid'] = st['agent_vmid']
        # the active keeps its vote: a member promoted after its vote was taken says so
        out[-1].update({k: v for k, v in _member_marks(st).items() if k != 'voter'})
    for mid, rec in (st.get('members') or {}).items():
        out.append(dict(_credentials(rec), instance_id=mid, url=rec.get('url') or '',
                        fingerprint=rec.get('fingerprint') or '', serve=rec.get('serve') is True))
        # the VM it runs as per cluster, where an admin named it (set_agent_vmid)
        if rec.get('agent_vmid'):
            out[-1]['agent_vmid'] = rec['agent_vmid']
        out[-1].update(_member_marks(rec))
    return sorted(out, key=lambda e: e['instance_id'])


# MK Oct 2026 (#625) - what an admin sets per member on the leader: the site label and, in
# a release with automatic failover, vote and may lead. Kept on the member records (the
# leader's own in its state) and handed out with the member list, so a member that leads
# one day starts from the same; only what differs from the default goes along
_MEMBER_MARKS = ('site', 'voter', 'may_lead')
_SITE_BAD_RE = re.compile(r'[\x00-\x1f\x7f]')


def _clean_site(value):
    """A site label as an admin sets it or a member list carries it: up to SITE_MAX
    characters on one line, '' for none. None for anything that is no label."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if len(value) > ha_vote.SITE_MAX or _SITE_BAD_RE.search(value):
        return None
    return value


def _member_marks(rec):
    """The marks of a member record (or of the leader's own state) as the member list
    carries them: the site when it has one, vote and may lead only when taken."""
    out = {}
    site = _clean_site(rec.get('site'))
    if site:
        out['site'] = site
    for key in ('voter', 'may_lead'):
        if rec.get(key) is False:
            out[key] = False
    return out


def _clean_entries(entries):
    """{instance id: {url, fingerprint, public_key, secret_hash, serve}} from a member
    list as it arrives, one entry per id. Each needs a public key or the hash of a
    secret. Whatever is not well formed is left out; an address that is not plain https
    counts as unknown, a pin without an address as none, and serve as False unless it
    is true."""
    out = {}
    if not isinstance(entries, list):
        return out
    for e in entries[:MAX_MEMBERS * 2]:
        if not isinstance(e, dict):
            continue
        mid, digest, key = e.get('instance_id'), e.get('secret_hash'), e.get('public_key')
        if not (isinstance(mid, str) and _ID_RE.fullmatch(mid)):
            continue
        digest = digest if isinstance(digest, str) and _SECRET_HASH_RE.fullmatch(digest) else ''
        key = key if _public_key(key) else ''
        if not digest and not key:
            continue
        url = valid_https_url(e.get('url')) if e.get('url') else ''
        fp = e.get('fingerprint')
        fp = fp.strip().upper() if isinstance(fp, str) and url else ''
        if fp and not _FP_RE.fullmatch(fp):
            fp = ''
        out.setdefault(mid, {'url': url, 'fingerprint': fp, 'public_key': key, 'secret_hash': digest,
                             'serve': e.get('serve') is True})
        vmids = _clean_agent_vmid(e.get('agent_vmid'))
        if vmids and out[mid].get('public_key') == key:
            out[mid]['agent_vmid'] = vmids
        if out[mid].get('public_key') == key and out[mid].get('secret_hash') == digest:
            out[mid].update(_member_marks(e))
    return out


def _clean_tombstones(entries):
    """{instance id: {epoch, at, by, public_key, secret_hash}} from a tombstone list as
    it arrives. The credentials say which instance is out: one that pairs again comes
    with a new key and is not taken for it."""
    out = {}
    if not isinstance(entries, list):
        return out
    for e in entries[:MAX_TOMBSTONES * 2]:
        if not isinstance(e, dict):
            continue
        mid, ep, at, by = e.get('instance_id'), e.get('epoch'), e.get('at'), e.get('by')
        if not (isinstance(mid, str) and _ID_RE.fullmatch(mid)):
            continue
        if _epoch_value(ep) is None:
            continue
        creds = _clean_entries([dict(e, url='', fingerprint='')]).get(mid)
        if not creds:
            continue
        out[mid] = {'epoch': ep, 'at': at if isinstance(at, str) and len(at) <= 40 else '',
                    'by': by if isinstance(by, str) and _ID_RE.fullmatch(by) else '',
                    'public_key': creds['public_key'], 'secret_hash': creds['secret_hash']}
    return out


def _tombstone_list(st):
    return sorted((dict(t, instance_id=mid) for mid, t in (st.get('tombstones') or {}).items()),
                  key=lambda e: e['instance_id'])


def _bounded_tombstones(tombs):
    keep = sorted(tombs, key=lambda mid: (int(tombs[mid].get('epoch') or 0),
                                          str(tombs[mid].get('at') or ''), mid))[-MAX_TOMBSTONES:]
    return {mid: tombs[mid] for mid in keep}


def _merged_tombstones(local, incoming, me):
    """Ours and the ones that came with a member list, the later of two for one id."""
    out = dict(local or {})
    for mid, t in (incoming or {}).items():
        old = out.get(mid)
        if old is None or (int(t['epoch']), t['at']) > (int(old.get('epoch') or 0), str(old.get('at') or '')):
            out[mid] = t
    out.pop(me, None)
    return _bounded_tombstones(out)


def _matches_tombstone(rec, tomb):
    """The member record is the instance the tombstone is about."""
    if not tomb:
        return False
    key, digest = tomb.get('public_key'), tomb.get('secret_hash')
    return bool((key and rec.get('public_key') == key) or (digest and rec.get('secret_hash') == digest))


# --- pairing -------------------------------------------------------------------

PAIRING_CODE_ERROR = 'The pairing code is wrong or has expired'


def pairing_code_ok(code_secret):
    """Whether `code_secret` is the open pairing code of this instance. Nothing is spent:
    the pair route asks before it says anything about the group to its caller."""
    pairing = _load().get('pairing') or {}
    return bool(isinstance(code_secret, str) and pairing.get('code_hash')
                and int(pairing.get('expires') or 0) >= int(time.time())
                and hmac.compare_digest(_hash_secret(code_secret), pairing['code_hash']))


def accept_pairing(code_secret, standby_id, standby_url, standby_fp, standby_public_key):
    """Active side of the handshake. Returns the response body for the standby.

    The standby sends its public key. Up to MAX_MEMBERS - 1 standbys; an instance
    that is a member already takes its old place again (it unpaired while we could
    not be told), and one we removed comes back with the new key it pairs with."""
    with _lock:
        st = _load()
        if not pairing_code_ok(code_secret):
            raise HaError(PAIRING_CODE_ERROR)
        if st['role'] == ROLE_STANDBY:
            raise HaError('This instance cannot take a standby right now')
        why = _pairing_refusal(st)
        if why:
            raise HaError(why)
        if not re.match(r'^[0-9a-f]{32}$', standby_id or '') or standby_id == st['instance_id']:
            raise HaError('The standby did not identify itself')
        ms = dict(st.get('members') or {})
        if len([mid for mid in ms if mid != standby_id]) >= MAX_MEMBERS - 1:
            raise HaError(GROUP_FULL_ERROR)
        for mid, rec in ms.items():
            if mid != standby_id and not _seen_in_group(rec):
                raise HaError(_group_waiting_error(dict(rec, instance_id=mid)))
        if _takes_a_vote_too_many(st, standby_id):
            # it comes back with a new key and without the vote it had: the change that
            # says so would leave too few votes and be refused, and the config would go
            # on naming a voter that cannot answer
            raise HaError(AUTO_REPAIR_ERROR)
        # a public key: a standby from before the keys sends the hash of a secret (or
        # the secret itself) and is refused here
        if not _public_key(standby_public_key):
            raise HaError('The standby did not send a usable public key - update it to '
                          'this release and pair again')
        if standby_url and not isinstance(standby_url, str):
            raise HaError('The standby address must be https://host[:port][/path]')
        if standby_url and standby_url.strip():
            # stored, shown and used as the base of every call to the standby
            standby_url = valid_https_url(standby_url)
            if not standby_url:
                raise HaError('The standby address must be https://host[:port][/path]')
        else:
            standby_url = ''
        standby_fp = (standby_fp or '').strip().upper()
        if standby_fp and not _FP_RE.fullmatch(standby_fp):
            raise HaError('The standby sent a malformed certificate fingerprint')

        from pegaprox.core.db import get_db
        field_key = get_db().aes_key
        if not field_key or len(field_key) != 32:
            raise HaError('This instance has no field key to share')

        signing_key = st.get('signing_key') or _new_signing_key()
        new_epoch = max(1, int(st.get('epoch') or 0))
        if _epoch_value(new_epoch) is None:
            # the standby would refuse the answer and still stand in our member list
            raise HaError('This instance holds an epoch no member can read - unpair it here, '
                          'then pair again')
        ms[standby_id] = {
            'url': standby_url,
            'fingerprint': standby_fp,
            'public_key': standby_public_key,
            'role_seen': ROLE_STANDBY,
            'epoch_seen': new_epoch,
            'last_contact': None,
            'last_error': '',
            'joined_at': _now(),
            'group_seen': True,
        }
        if _lease_mode(st):
            # it joins the voter config without a vote (_lease_member_joined), and its
            # record says the same for the next switch
            ms[standby_id]['voter'] = False
        tombs = dict(st.get('tombstones') or {})
        tombs.pop(standby_id, None)
        new = dict(st, role=ROLE_ACTIVE, epoch=new_epoch, pairing=None, signing_key=signing_key,
                   members=ms, source=None, tombstones=tombs, removed=None)
        if st['role'] == ROLE_STANDALONE:
            # the group is formed here, and nothing of a group this instance was in before
            # goes into it. Its schedules keep the hours they have on this instance,
            # whichever member leads later (schedule_now)
            for key in _GROUP_KEYS:
                new.pop(key, None)
            if local_timezone():
                new['timezone'] = local_timezone()
            _drop_group_seen()
        _commit_locked(new)
        _note_member_in_db(st['instance_id'])
        _drop_recovery_locks(st['instance_id'])
        # the member list too, so the new standby can verify every other member the
        # day one of them is promoted, and who is out
        payload = {'field_key': base64.b64encode(field_key).decode(),
                   'public_key': _public_of(_private_key(signing_key)),
                   'members': _member_list(new),
                   'tombstones': _tombstone_list(new)}
        if _mode_said(new) != ha_vote.MODE_MANUAL:
            # the newcomer knows from its first moment that nobody is promoted by hand
            # here, whether or not a renewal of the leader ever reaches it
            payload['mode'] = _mode_said(new)
        sealed = _seal(code_secret, payload, aad=standby_id)
        out = {'instance_id': st['instance_id'], 'epoch': new_epoch, 'sealed': sealed,
               'key_fp': key_fingerprint(field_key)}
    # in an automatic group the newcomer goes into the voter config, without a vote
    _lease_member_joined(standby_id, standby_public_key)
    return out


def _check_can_join(st, info):
    if st['role'] != ROLE_STANDALONE or st.get('members'):
        raise HaError('Only a standalone, unpaired instance can become a standby')
    if info['instance_id'] == st['instance_id']:
        raise HaError('That code was made on this instance')


def join(code, own_url, own_fingerprint):
    """Standby side: pair with the active behind `code`, adopt its field key.

    The caller restarts the process afterwards. Until the active has answered, the
    sealed payload has opened and every field of the answer checks out, the only
    write is the withdrawal of this instance's own open pairing code.
    """
    info = decode_code(code)
    raw_url = own_url.strip() if isinstance(own_url, str) else ''
    own_url = valid_https_url(raw_url) if raw_url else ''
    if raw_url and not own_url:
        raise HaError("This instance's address must be https://host[:port][/path]")
    with _lock:
        st = _load()
        _check_can_join(st, info)
        me = st['instance_id']
        if st.get('pairing'):
            # a code of our own, redeemed while we wait for the other active, would
            # make us its active and then be overwritten below: one pairing at a time
            _commit_locked(dict(st, pairing=None))
    # a fresh key pair for every group this instance joins; only the public half leaves
    my_key = _new_signing_key()
    body = {'code': info['secret'], 'instance_id': me, 'url': own_url,
            'fingerprint': own_fingerprint or '', 'public_key': _public_of(_private_key(my_key))}
    resp = _peer_call('POST', info['url'], info['fingerprint'], '/api/ha/peer/pair',
                      json_body=body, auth=None)
    if resp.status_code != 200:
        raise HaError(_peer_error(resp, 'The active instance refused the pairing'))
    try:
        data = resp.json()
    except Exception:
        data = None
    if not isinstance(data, dict):
        raise HaError('The answer from the active instance could not be read')
    if data.get('instance_id') != info['instance_id']:
        raise HaError('The instance that answered is not the one that made the code')
    try:
        opened = _unseal(info['secret'], data.get('sealed') or '', aad=me)
        field_key = base64.b64decode(opened['field_key'])
        active_key = opened.get('public_key')
        group = opened.get('members', [])
        tombs = opened.get('tombstones', [])
        said = opened.get('mode')
    except Exception:
        raise HaError('The answer from the active instance could not be opened')
    if len(field_key) != 32 or key_fingerprint(field_key) != data.get('key_fp'):
        raise HaError('The field key from the active instance is not intact')
    new_epoch = data.get('epoch')
    if (_epoch_value(new_epoch, low=1) is None
            or not _public_key(active_key)
            or not isinstance(group, list) or not isinstance(tombs, list)):
        raise HaError('The answer from the active instance is incomplete')
    others = _clean_entries(group)
    others.pop(me, None)
    others.pop(info['instance_id'], None)
    tombs = _clean_tombstones(tombs)
    tombs.pop(me, None)

    with _lock:
        st = _load()
        if st['role'] == ROLE_STANDALONE and not st.get('members') and st['instance_id'] == me:
            now = _now()
            ms = {info['instance_id']: {
                'url': info['url'], 'fingerprint': info['fingerprint'], 'public_key': active_key,
                'role_seen': ROLE_ACTIVE, 'epoch_seen': new_epoch, 'last_contact': now,
                'last_error': '', 'joined_at': now, 'group_seen': True}}
            for mid in sorted(others)[:MAX_MEMBERS - 2]:
                if _matches_tombstone(others[mid], tombs.get(mid)):
                    continue
                ms[mid] = dict(others[mid], role_seen=None, epoch_seen=0, last_contact=None,
                               last_error='', joined_at=now)
            # standby first, key second: if the key write fails we are a passive
            # standby whose sync refuses a key mismatch, not a standalone that acts
            # on a foreign key. Both under the lock, so accept_pairing cannot seal
            # the adopted key to anybody in between. joined: the first snapshot replaces
            # this instance's configuration, as the admin confirmed it would
            # nothing a group from before decided comes along (its votes, its zone)
            new = {k: v for k, v in st.items() if k not in _GROUP_KEYS}
            if said in (ha_vote.MODE_AUTO, ha_vote.MODE_PENDING):
                new['group_mode'] = said
            _drop_group_seen()
            _commit_locked(dict(new, role=ROLE_STANDBY, epoch=new_epoch, pairing=None, sync={},
                                signing_key=my_key, member_secret=None, members=ms,
                                tombstones=_bounded_tombstones(tombs), removed=None,
                                source=info['instance_id'], serve_assigned=False,
                                cv={'joined': True}, change_gap=None,
                                own_url=own_url or st.get('own_url') or ''))
            try:
                _install_field_key(field_key)
            except Exception as e:
                try:
                    _update_sync(last_error=f'The field key from the active instance could not be written: {e}'[:300])
                except Exception as e2:
                    # the same full disk, usually - the HaError below still says what happened
                    logging.warning(f"[HA] could not note the failed key write either: {e2}")
                raise HaError('Paired, but the field key could not be written - check the config '
                              'directory and pair again')
            _note_member_in_db(me)
            _drop_recovery_locks(me)
            return peer()

    # something paired with us while the call was out. The active has taken us as
    # its standby by now; tell it, so it does not wait for one that never comes.
    try:
        _peer_call('POST', info['url'], info['fingerprint'], '/api/ha/peer/unpaired',
                   auth=_auth_for(_Signer(me, _private_key(my_key)), info['instance_id']),
                   timeout=10)
    except Exception as e:
        logging.warning(f"[HA] could not tell {info['url']} that the join was dropped: {e}")
    raise HaError('This instance changed its pairing while joining - try again')


def _install_field_key(new_key):
    """Adopt the active's field key, keeping ours as a dated .pre-ha backup (which
    also marks this instance as one that joined a pair)."""
    from pegaprox.core.db import get_db
    if os.path.exists(AES_KEY_FILE):
        with open(AES_KEY_FILE, 'rb') as fh:
            old_key = fh.read()
        base = f"{AES_KEY_FILE}.pre-ha.{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        backup, n = base, 0
        while True:
            try:
                fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                n += 1
                backup = f'{base}.{n}'
        with os.fdopen(fd, 'wb') as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(old_key)
            fh.flush()
            os.fsync(fh.fileno())
    # the swap itself is a key rotation onto the given key: what stays local and was
    # sealed or signed with our own key (acme_* secrets, the VAPID key until the first
    # sync, every audit signature) is re-sealed under the new one in the same
    # transaction that writes the key file, instead of being stranded
    stats = get_db().rotate_encryption_key(new_key=new_key)
    if not stats.get('success'):
        raise HaError('Could not adopt the field key: '
                      + (stats.get('error') or '; '.join(stats.get('errors') or []) or 'unknown error'))


def unpair(said=(), leader_agreed=False):
    """Leave the group. A standby becomes standalone, which means it starts acting
    after the restart the caller schedules; an active becomes standalone and the
    members go on without it. Telling the members is the caller's part.

    The one write allowed on a state file _load could not read: it is the way out,
    and the note about the broken file goes with it. Raises AutoMode where the group
    fails over automatically (unpair_refusal).
    """
    with _lock:
        st = _load()
        why = unpair_refusal(st, said=said, leader_agreed=leader_agreed)
        if why:
            raise AutoMode(why)
        was = st['role']
        zone = group_timezone()
        new = {k: v for k, v in st.items() if k != 'broken'}
        # the key pair goes too: the next group gets a fresh one. So does the epoch: a
        # standalone has nobody to be ordered against, and the next group counts anew
        # (one at the ceiling would otherwise refuse every promotion there as well)
        new.update(members={}, source=None, member_secret=None, signing_key=None, pairing=None,
                   sync={}, tombstones={}, removed=None, role=ROLE_STANDALONE, epoch=0,
                   serve_assigned=False, cv=None, change_gap=None)
        # what the group decided goes with it: its votes, its witness, its time zone
        for key in _GROUP_KEYS:
            new.pop(key, None)
        _commit_locked(new)
        _drop_group_seen()
    _group_left(st['instance_id'], zone)
    # now, not at the next boot: the route restarts only a former standby
    _note_member_in_db('')
    _drop_recovery_locks(st['instance_id'])
    return was


def _mark_removed(by, their_epoch):
    """A member says this instance is out of the group: let go of every member and
    stay passive, an active included, until an admin unpairs it. Returns the role it
    had, None when nothing changed. Never raises."""
    try:
        with _lock:
            st = _load()
            if st.get('broken') or st['role'] == ROLE_STANDALONE:
                return None
            if st.get('removed') and not st.get('members'):
                # heard it already, from another member
                return None
            if _epoch_value(their_epoch) is None:
                their_epoch = int(st.get('epoch') or 0)
            was = st['role']
            # out of the group, so out of its votes as well
            kept = {k: v for k, v in st.items()
                    if k not in ('lease', 'leader', 'witness', 'witness_pairing', 'group_mode')}
            _commit_locked(dict(kept, role=ROLE_STANDBY, members={}, source=None, sync={}, pairing=None,
                                epoch=max(int(st.get('epoch') or 0), their_epoch),
                                removed={'epoch': their_epoch, 'at': _now(), 'by': by},
                                serve_assigned=False))
            _lease_drop(st['instance_id'])
    except Exception as e:
        logging.error(f"[HA] member {by} says this instance was removed, and that could not be "
                      f"saved: {e}")
        return None
    logging.warning(f"[HA] member {by} says this instance was removed from the group (epoch "
                    f"{their_epoch}) - passive until it is unpaired")
    if was == ROLE_ACTIVE:
        flush_journal()
    _audit('ha.removed', f"removed from the group, as member {by} says (epoch {their_epoch}); "
                         f"this instance was {was} and stays passive until it is unpaired")
    return was


def _removed_answer(rec, resp):
    """A member answered 410 HA_REMOVED: it holds a tombstone for us. Taken from any
    member, since the answer came from its address under its pin."""
    try:
        data = resp.json()
    except Exception:
        data = None
    if not isinstance(data, dict) or data.get('code') != 'HA_REMOVED':
        return None
    their = _epoch_value(data.get('epoch'))
    if their is None:
        their = int(rec.get('epoch_seen') or 0)
    return _mark_removed(rec['instance_id'], their)


def _speaks_for_group(peer_id, timeout=3):
    """The epoch under which `peer_id` speaks for the group to us, None when it does
    not: on a standby the member it pulls from or one it has seen active; otherwise
    the member has to answer as active right now, under at least our epoch (an active
    wants it newer, or the same and the tie won)."""
    st = _load()
    rec = (st.get('members') or {}).get(peer_id)
    if rec is None:
        return None
    mine = int(st.get('epoch') or 0)
    if st['role'] == ROLE_STANDBY and (peer_id == st.get('source') or rec.get('role_seen') == ROLE_ACTIVE):
        return max(mine, int(rec.get('epoch_seen') or 0))
    try:
        their_role, their_epoch = _ask(dict(rec, instance_id=peer_id), _signer(), timeout)[:2]
    except Exception as e:
        logging.warning(f"[HA] could not ask member {peer_id} whether it is active: {e}")
        return None
    _note_members({peer_id: {'role_seen': their_role, 'epoch_seen': their_epoch}})
    if their_role != ROLE_ACTIVE:
        return None
    if st['role'] == ROLE_ACTIVE:
        wins = their_epoch > mine or (their_epoch == mine and _wins_tie(peer_id, st['instance_id']))
    else:
        wins = their_epoch >= mine
    return their_epoch if wins else None


def forget_peer(peer_id, whole_group=False):
    """A member told us it left the group. Only that member itself may say so, and
    only about itself: we drop it and keep the others. Returns 'group' when this
    instance let go of the whole group, 'member' when it dropped the caller, '' when
    nothing changed.

    whole_group is the active telling us that it removed us: we are out of the group
    then, let go of every member and stay passive (_mark_removed). Taken only from the
    instance the group follows (_speaks_for_group); from anybody else it is a plain
    leave. When we have to ask the member first, it already holds the tombstone and
    answers 410, and we let go right there (_removed_answer): that is the same
    'group'. An active whose last member left is standalone again."""
    st = _load()
    if not isinstance(peer_id, str) or peer_id not in (st.get('members') or {}):
        return ''
    if whole_group:
        their = _speaks_for_group(peer_id)
        if their is not None and _mark_removed(peer_id, their) is not None:
            return 'group'
        after = _load()
        if (after.get('removed') or {}).get('by') == peer_id and not after.get('members'):
            return 'group'
    with _lock:
        st = _load()
        ms = dict(st.get('members') or {})
        if peer_id not in ms:
            return ''
        was = st['role']
        zone = group_timezone()
        ms.pop(peer_id)
        new = dict(st, members=ms)
        if new.get('source') not in ms:
            new['source'] = None
        alone = not ms and was == ROLE_ACTIVE
        if alone:
            new.update(role=ROLE_STANDALONE, member_secret=None)
            # the group is gone, and what it decided with it, as in unpair: a lease
            # nobody renews would shut this instance for good, and its zone would go
            # into the next group
            for key in _GROUP_KEYS:
                new.pop(key, None)
        _commit_locked(new)
        if alone:
            _drop_group_seen()
    if alone:
        _group_left(st['instance_id'], zone)
        _note_member_in_db('')
    return 'member'


REMOVE_UNCONFIRMED_ERROR = ('This instance has not answered as a standby under the current '
                            'epoch - it may still be active. Let it come back and follow this '
                            'one first, or confirm that it is shut down for good')


def member_confirmed(member_id):
    """The member answered as a standby under our current epoch (see remove_member)."""
    st = _load()
    rec = (st.get('members') or {}).get(member_id)
    return bool(rec) and _confirmed_standby(rec, st)


def refresh_member(member_id, timeout=5):
    """Ask one member for its role and epoch now and note the answer. Never raises:
    a member that does not answer simply stays as the last tick left it."""
    rec = member(member_id)
    if not rec:
        return
    try:
        their_role, their_epoch, mark, serving_seen = _ask(rec, _signer(), timeout)[:4]
    except Exception as e:
        logging.info(f"[HA] member {rec.get('url') or member_id} did not answer the check: {e}")
        return
    note = {'last_contact': _now(), 'role_seen': their_role, 'epoch_seen': their_epoch,
            'serving_seen': serving_seen, 'last_error': ''}
    if mark == GROUP_MARK:
        note['group_seen'] = True
    try:
        _note_members({member_id: note})
    except Exception as e:
        logging.warning(f"[HA] could not note the member's answer: {e}")


def remove_member(member_id, shut_down=False):
    """Active: take a standby out of the group. Returns its record, for the caller to
    tell it and the others.

    Only a member seen as a standby under our epoch, unless the admin says it is shut
    down for good (shut_down): an old active that is simply down would otherwise come
    back to a group that refuses it, and act. It stays on record as removed (a
    tombstone), handed out with the member list, so its calls get 410 everywhere and
    a stale member list does not take it back. Removing the last one makes this
    instance standalone, as that standby's own unpairing would.

    In an automatic group only the lease holder removes a member, and the member leaves
    the voter config first, one change at a time; never below MIN_VOTERS (7.4)."""
    if not shut_down and not member_confirmed(member_id):
        # the last tick may predate our epoch (a promotion minutes ago): ask it now
        # rather than send the admin to the shut-down confirmation for nothing
        refresh_member(member_id)
    st = _load()
    if st['role'] == ROLE_ACTIVE and mode(st) == ha_vote.MODE_AUTO and _lease_mode(st):
        if _switching_off(st):
            raise HaError(SWITCHING_OFF_ERROR)
        if not isinstance(member_id, str) or member_id not in (st.get('members') or {}):
            raise HaError('That instance is not a member of this group')
        if not shut_down and not member_confirmed(member_id):
            raise RemoveUnconfirmed(REMOVE_UNCONFIRMED_ERROR)
        _remove_voter(member_id)
    with _lock:
        st = _load()
        if st['role'] != ROLE_ACTIVE:
            raise HaError('Only the active instance removes members')
        if mode(st) != ha_vote.MODE_MANUAL and not (_lease_mode(st) and holds_lease()):
            # a pending switch, or a leader without its lease
            raise AutoMode(AUTO_PENDING_ERROR if mode(st) == ha_vote.MODE_PENDING else AUTO_REMOVE_ERROR)
        ms = dict(st.get('members') or {})
        if not isinstance(member_id, str) or member_id not in ms:
            raise HaError('That instance is not a member of this group')
        if not shut_down and not _confirmed_standby(ms[member_id], st):
            raise RemoveUnconfirmed(REMOVE_UNCONFIRMED_ERROR)
        rec = dict(ms.pop(member_id), instance_id=member_id)
        tombs = dict(st.get('tombstones') or {})
        tombs[member_id] = dict(_credentials(rec), epoch=int(st.get('epoch') or 0), at=_now(),
                                by=st['instance_id'])
        zone = group_timezone()
        new = dict(st, members=ms, tombstones=_bounded_tombstones(tombs))
        if not ms:
            new.update(role=ROLE_STANDALONE, member_secret=None)
            for key in _GROUP_KEYS:
                new.pop(key, None)
        _commit_locked(new)
        if not ms:
            _drop_group_seen()
    if not ms:
        _group_left(st['instance_id'], zone)
        _note_member_in_db('')
    return rec


def tombstone(member_id):
    """The tombstone of a removed member, None for anybody else."""
    t = (_load().get('tombstones') or {}).get(member_id)
    return dict(t, instance_id=member_id) if t else None


def note_member_removed(by_id, member_id, their_epoch):
    """The active took `member_id` out of the group and tells us right away, not only
    with the next member list: drop it and keep its tombstone. Taken only from the
    instance the group follows (_speaks_for_group). Returns True when it was dropped."""
    st = _load()
    if (not isinstance(member_id, str) or member_id == st['instance_id']
            or member_id == by_id or member_id not in (st.get('members') or {})):
        return False
    if _epoch_value(their_epoch) is None:
        return False
    if _speaks_for_group(by_id) is None:
        return False
    with _lock:
        st = _load()
        ms = dict(st.get('members') or {})
        rec = ms.pop(member_id, None)
        if rec is None:
            return False
        tombs = dict(st.get('tombstones') or {})
        tombs[member_id] = dict(_credentials(rec), epoch=their_epoch, at=_now(), by=by_id)
        new = dict(st, members=ms, tombstones=_bounded_tombstones(tombs))
        if new.get('source') == member_id:
            new['source'] = None
        _commit_locked(new)
    logging.warning(f"[HA] member {by_id} removed member {member_id} from the group")
    return True


def take_tombstones(sender_id, entries):
    """Active: the member `sender_id` holds tombstones (`entries`, as a member list
    carries them) for members we still list. The removal happened while we could not
    hear about it, and we were promoted since. Taken for a member only when the
    tombstone names the credentials we hold for it, and when that member has not
    answered as a standby under our epoch, asked once more now: a removed instance
    never does, so no member takes a live standby out this way. Returns the ids
    taken out."""
    offered = _clean_tombstones(entries)
    st = _load()
    ms = st.get('members') or {}
    if st['role'] != ROLE_ACTIVE or sender_id not in ms:
        return []
    maybe = [mid for mid in sorted(offered) if mid in ms and mid not in (sender_id, st['instance_id'])
             and _matches_tombstone(ms[mid], offered[mid])]
    for mid in maybe:
        if not member_confirmed(mid):
            refresh_member(mid)
    taken = []
    with _lock:
        st = _load()
        ms = dict(st.get('members') or {})
        if st['role'] != ROLE_ACTIVE or sender_id not in ms:
            return []
        tombs = dict(st.get('tombstones') or {})
        for mid in maybe:
            rec = ms.get(mid)
            if rec is None or not _matches_tombstone(rec, offered[mid]) or _confirmed_standby(rec, st):
                continue
            ms.pop(mid)
            tombs[mid] = offered[mid]
            taken.append(mid)
        if taken:
            _commit_locked(dict(st, members=ms, tombstones=_bounded_tombstones(tombs)))
    for mid in taken:
        logging.warning(f"[HA] member {sender_id} holds a tombstone for member {mid}: out of the "
                        "group here too")
    return taken


# --- promotion and stepping down -------------------------------------------------

def promote():
    """Standby to active under a new epoch, one above every epoch this instance has
    seen in the group. The caller restarts the process. What a member was known to
    hold and this instance does not is noted as change_gap, audited and shown.

    A sync that is under way finishes first, for up to PROMOTE_PULL_WAIT seconds: the
    promotion comes after it or before it, never in the middle. One that is still out
    by then (its source does not answer) no longer applies: apply_snapshot looks at
    the role again before it replaces anything."""
    if mode() != ha_vote.MODE_MANUAL:
        raise AutoMode(promote_refusal())
    said = _members_say_auto()
    if said is not None:
        # this instance holds no voter config that says so (it was restored from an
        # older state, or no renewal of the leader ever reached it): the members do
        who = 'The witness' if said.get('kind') == ha_vote.KIND_WITNESS else 'Member'
        raise AutoMode(f"{who} {said.get('url') or said['instance_id'][:8]} says this group "
                       'fails over automatically: its members elect the leader, and none is '
                       'promoted by hand')
    # a manual config nobody confirmed, or a state older than what this instance knew
    # about its group: Force leader is the way out, never a plain promotion (S7)
    why = way_out_check()
    if why:
        raise AutoMode(why)
    waited = _pull_lock.acquire(timeout=PROMOTE_PULL_WAIT)
    try:
        new_epoch, gap = _promote()
    finally:
        if waited:
            _pull_lock.release()
    if gap:
        _say_change_gap(gap)
    return new_epoch


def _promote():
    with _lock:
        st = _load()
        if st.get('broken'):
            # the stand-in for an unreadable file has no members and a fresh identity:
            # an active made from it could never tell the real active to step down
            raise HaError('The HA state file cannot be read - restore config/ha_state.json '
                          'and restart before promoting')
        if st['role'] != ROLE_STANDBY:
            raise HaError('Only a standby can be promoted')
        if st.get('removed'):
            # an active of its own would act next to the group that took it out
            raise HaError(f'{REMOVED_ERROR} - unpair it here first')
        if mode(st) != ha_vote.MODE_MANUAL:
            # the group elects its leader; one made by hand would act next to it
            raise AutoMode(promote_refusal(st))
        ms = st.get('members') or {}
        seen = max([int(rec.get('epoch_seen') or 0) for rec in ms.values()] + [0])
        new_epoch = max(int(st.get('epoch') or 0), seen) + 1
        if new_epoch > EPOCH_MAX:
            # no member could read it: the old active would never step down to us
            raise HaError('The group has reached the highest epoch there is - unpair every '
                          'instance and pair them again')
        gap = _gap_at_promotion(st)
        cvr = _cv_record(st)
        if cvr is not None and cvr.get('joined'):
            # never synced: what it holds is its own, with no history behind it
            cvr = None
        # whoever was active may not be once it hears about us
        ms = {mid: dict(rec, role_seen=None) if rec.get('role_seen') == ROLE_ACTIVE else dict(rec)
              for mid, rec in ms.items()}
        # the members keep the serve flags the old leader gave them; ours is no flag
        # any more, the leader is active anyway
        new = {k: v for k, v in st.items() if k != 'group_mode'}
        _commit_locked(dict(new, epoch=new_epoch, role=ROLE_ACTIVE, members=ms, source=None,
                            serve_assigned=False, cv=cvr, change_gap=gap))
    return new_epoch, gap


def _wins_tie(one, other):
    """Two actives under the same epoch: the higher instance id stays active."""
    return str(one) > str(other)


def step_down(new_epoch, by_peer_id, holds_lease=False):
    """Active to standby of `by_peer_id`, because that member is active under a newer
    epoch, or under ours and wins the tie. A member that holds the lease of an automatic
    group (`holds_lease`) needs no tie: a majority follows it. A switch to automatic
    failover this instance started and that is still pending is taken back with the
    same write (_switch_taken_back). Returns True when this call changed the role; the
    caller restarts the process then."""
    with _lock:
        st = _load()
        ms = st.get('members') or {}
        if not isinstance(by_peer_id, str) or by_peer_id not in ms or st['role'] != ROLE_ACTIVE:
            return False
        if _epoch_value(new_epoch) is None or _lease_mode(st):
            # an automatic leader leaves by its lease and the votes, not on a member's word
            return False
        mine = int(st.get('epoch') or 0)
        if new_epoch < mine or (new_epoch == mine and not holds_lease
                                and not _wins_tie(by_peer_id, st['instance_id'])):
            return False
        ms = dict(ms)
        ms[by_peer_id] = dict(ms[by_peer_id], role_seen=ROLE_ACTIVE, epoch_seen=new_epoch)
        new = dict(st, role=ROLE_STANDBY, epoch=new_epoch, sync={}, members=ms, source=by_peer_id)
        back = _switch_taken_back(st, automatic=holds_lease)
        if back is not None:
            new['lease'] = back
        _commit_locked(new)
    logging.warning(f"[HA] stepped down: member {by_peer_id} is active with epoch {new_epoch}")
    if back is not None:
        _tell_switch_back(back, new_epoch, skip=by_peer_id)
    # who wrote what while this instance led, before the restart takes what still waits
    flush_journal()
    return True


def step_aside(new_epoch, reason):
    """Active to a passive standby that follows nobody yet: the group has moved on
    without us (a member reports a newer epoch and no active under it answers), or
    every member refuses us. The next look at the group follows the active once one
    answers under at least that epoch. Returns True when this call changed the role;
    the caller restarts the process then."""
    with _lock:
        st = _load()
        if st['role'] != ROLE_ACTIVE or _lease_mode(st):
            return False
        mine = int(st.get('epoch') or 0)
        new_epoch = mine if _epoch_value(new_epoch) is None else new_epoch
        new = dict(st, role=ROLE_STANDBY, epoch=max(mine, new_epoch),
                   source=None, sync={'last_error': f'Stepped aside: {reason}'[:300]})
        # as in step_down: a standby could not take its pending switch back any more
        back = _switch_taken_back(st)
        if back is not None:
            new['lease'] = back
        _commit_locked(new)
    logging.warning(f"[HA] stepped aside to a passive standby: {reason}")
    if back is not None:
        _tell_switch_back(back, new['epoch'])
    flush_journal()
    return True


def restart_process(reason):
    """Restart so managers and loops come up in the new role, a moment from now so the
    answer to whoever asked gets out first. See leave_process for how."""
    def _go():
        time.sleep(1.5)
        logging.warning(f"[HA] restarting: {reason}")
        leave_process()
    threading.Thread(target=_go, daemon=True, name='ha-restart').start()


# --- this process --------------------------------------------------------------
#
# MK Oct 2026 (#625) - a role change is a restart, and the restart is what stops every
# thread still at work in the old role. Children were left out of it: an execv keeps
# the pid, so an ssh or ipmitool started by the old role ran on next to the new one,
# and `sudo systemctl restart` cannot work under the unit's NoNewPrivileges anyway.

# process groups of children started for a step that must not outlive this process
# (ssh, ipmitool), in a session of their own
_child_lock = threading.Lock()
_child_groups = set()
_config_lock = {'fd': None}


def register_child_group(pgid):
    with _child_lock:
        _child_groups.add(int(pgid))


def forget_child_group(pgid):
    with _child_lock:
        _child_groups.discard(int(pgid))


def _children():
    """[(pid, process group)] of this process's children, from /proc. Empty without it."""
    me, out = os.getpid(), []
    try:
        names = os.listdir('/proc')
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(f'/proc/{name}/stat', 'rb') as fh:
                raw = fh.read()
            # "pid (comm) state ppid pgrp ...", and comm may hold spaces and parentheses
            fields = raw[raw.rindex(b')') + 2:].split()
            if int(fields[1]) == me:
                out.append((int(name), int(fields[2])))
        except (OSError, ValueError, IndexError):
            continue
    return out


def kill_children():
    """SIGKILL every registered process group and every child of this process: a child
    in a group of its own takes its group along, one in ours goes alone. Never raises."""
    import signal
    own = os.getpgrp()
    with _child_lock:
        groups = set(_child_groups)
    loners = []
    for pid, pgrp in _children():
        if pgrp == own:
            loners.append(pid)
        else:
            groups.add(pgrp)
    for pgrp in groups:
        if pgrp > 1 and pgrp != own:
            try:
                os.killpg(pgrp, signal.SIGKILL)
            except OSError:
                pass
    for pid in loners:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _supervised():
    """Only when the admin says so (PEGAPROX_SUPERVISED=1): something starts this process
    again once it exits. Not guessed from systemd: an exit counts against the unit's
    start limit (5 in 120 s in systemd/pegaprox.service), and a few role changes in a
    row would leave the service failed. Without it the children die first and the
    process execs itself, as before."""
    return os.environ.get('PEGAPROX_SUPERVISED', '').strip().lower() in ('1', 'true', 'yes')


def leave_process():
    """The way out for a restart. The children die first, then the process exits with
    EXIT_RESTART where a supervisor starts it again (systemd also kills what is left in
    the unit's cgroup, Docker the container), or it execs itself. Never returns."""
    kill_children()
    if not _supervised():
        try:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as e:
            logging.error(f"[HA] could not exec PegaProx again ({e}) - exiting with {EXIT_RESTART}")
    os._exit(EXIT_RESTART)


def lock_config_dir(path=None):
    """F1: hold an exclusive flock on LOCK_FILE for as long as this process runs. Two
    processes on one config directory share the database, the state file and the
    instance id, and both act. The descriptor is close-on-exec, so an execv restart
    lets go of it and the new image takes it again.

    Raises HaError when another process holds it. Without flock (no fcntl, a
    filesystem that has no locks) it warns and goes on; returns the descriptor or None."""
    path = path or LOCK_FILE
    try:
        import fcntl
    except ImportError:
        return None
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as e:
        logging.warning(f"[HA] cannot open {path} ({e}) - running without the config directory lock")
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        try:
            holder = os.pread(fd, 16, 0).decode(errors='replace').strip()
        except OSError:
            holder = ''
        os.close(fd)
        if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            who = f'process {holder}' if holder.isdigit() else 'process'
            raise HaError(f'Another PegaProx {who} runs on {os.path.dirname(os.path.abspath(path))} '
                          '- one config directory takes one process')
        logging.warning(f"[HA] cannot lock {path} ({e}) - running without the config directory lock")
        return None
    try:
        os.ftruncate(fd, 0)
        os.pwrite(fd, f'{os.getpid()}\n'.encode(), 0)
    except OSError:
        pass
    _config_lock['fd'] = fd
    return fd


# --- snapshot ------------------------------------------------------------------

def _is_local_setting(key):
    return key in LOCAL_SETTING_KEYS or key.startswith(LOCAL_SETTING_PREFIXES)


def _enc(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {'$b64': base64.b64encode(bytes(value)).decode()}
    return value


def _dec(value):
    if isinstance(value, dict) and '$b64' in value:
        return base64.b64decode(value['$b64'])
    return value


def _existing_tables(cur):
    cur.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table'")
    return {r[0]: r[1] for r in cur.fetchall()}


def _hash_value(h, v):
    # typed and length-prefixed, so no two different rows feed the same bytes
    if v is None:
        h.update(b'n;')
    elif isinstance(v, (bytes, bytearray, memoryview)):
        v = bytes(v)
        h.update(b'b%d:' % len(v))
        h.update(v)
    elif isinstance(v, int):
        h.update(b'i%d;' % v)
    elif isinstance(v, float):
        h.update(b'f' + repr(v).encode() + b';')
    else:
        v = str(v).encode('utf-8', 'surrogatepass')
        h.update(b's%d:' % len(v))
        h.update(v)


def _default_values(dflt):
    """What a row reads in a column nobody set, from the default as PRAGMA table_info
    gives it: None when the column declares none (the row reads NULL), else the values
    that stand for it, as text and as a number."""
    if not isinstance(dflt, str) or dflt.strip().upper() == 'NULL':
        return None
    lit = dflt.strip()
    if len(lit) >= 2 and lit[0] == lit[-1] == "'":
        lit = lit[1:-1].replace("''", "'")
    out = [lit]
    for number in (int, float):
        try:
            out.append(number(lit))
            break
        except ValueError:
            pass
    return frozenset(out)


def _row_plan(name, cols, coldefs):
    """How a row of `name` is hashed: (index, tag, default values) of every column
    outside VOLATILE_COLUMNS, in the order of the names."""
    masked = VOLATILE_COLUMNS.get(name, ())
    plan = []
    for i, c in enumerate(cols):
        if c in masked:
            continue
        tag = c.lower().encode('utf-8', 'surrogatepass')
        plan.append((tag, i, b'c%d:' % len(tag) + tag, _default_values((coldefs.get(c) or ['', None])[1])))
    return [p[1:] for p in sorted(plan)]


def _row_digest(values, plan):
    """One row as (column name, value) pairs. A column that holds what nobody set (its
    default, NULL where it declares none) is left out, so a row hashes the same before
    and after ALTER TABLE ADD COLUMN, and in whatever order the columns come."""
    h = hashlib.sha256()
    for i, tag, unset in plan:
        v = values[i]
        if v is None:
            if unset is None:
                continue
        elif unset is not None and v in unset:
            continue
        h.update(tag)
        _hash_value(h, v)
    return h.digest()


class _Digests:
    """The two hashes a walk feeds. etag takes all a snapshot carries, the definition of
    every table included: a member pulls again when the active got a column. data takes
    the rows and the files alone and skips a table without rows, so it stays what it was
    through a step that changes no row (the column an upgrade adds, a table the code
    makes on first use): it says whether anything was changed here (_why_not_carried)."""

    def __init__(self):
        self.etag = hashlib.sha256(b'pegaprox-ha-snapshot')
        self.data = hashlib.sha256(b'pegaprox-ha-data')

    def update(self, raw):
        self.etag.update(raw)
        self.data.update(raw)

    def table(self, name, sql, cols, rows):
        rows = b''.join(sorted(rows))
        h = self.etag
        h.update(b'T')
        _hash_value(h, name)
        _hash_value(h, sql)
        _hash_value(h, '\x00'.join(cols))
        h.update(b'%d;' % (len(rows) // 32))
        h.update(rows)
        if rows:
            h = self.data
            h.update(b'T')
            _hash_value(h, name)
            h.update(b'%d;' % (len(rows) // 32))
            h.update(rows)

    def done(self):
        return self.etag.hexdigest()[:32], self.data.hexdigest()[:32]


def _reseal_legacy(db, value, label, stuck):
    """A legacy Fernet token as AES-256-GCM under the field key, anything else as is.

    Only a token our own Fernet key opens is touched; its HMAC rules out a string
    that merely looks like one. Nothing is written back here.
    """
    if not isinstance(value, str) or not value.startswith('gAAAA'):
        return value
    fernet, aesgcm = getattr(db, 'fernet', None), getattr(db, 'aesgcm', None)
    if fernet is None or aesgcm is None:
        return value
    try:
        plain = fernet.decrypt(value.encode()).decode('utf-8')
    except Exception:
        stuck.append(label)
        return value
    return db._encrypt_with_key(plain, aesgcm)


def _reseal_setting(db, key, raw, stuck):
    # server_settings values are JSON text; a very old row may be a bare string
    try:
        value, encoded = json.loads(raw), True
    except (TypeError, ValueError):
        value, encoded = raw, False
    if key == 'webpush_vapid_keypair':
        if not isinstance(value, dict):
            return raw
        pem = _reseal_legacy(db, value.get('private_pem'), f'server_settings.{key}', stuck)
        if pem == value.get('private_pem'):
            return raw
        value = dict(value, private_pem=pem)
    else:
        new = _reseal_legacy(db, value, f'server_settings.{key}', stuck)
        if new == value:
            return raw
        value = new
    return json.dumps(value) if encoded else value


def _row_converter(db, name, cols, stuck):
    """What a row of `name` looks like on the wire, or None when it goes as stored."""
    if name == 'server_settings':
        if 'key' not in cols or 'value' not in cols:
            return None
        ki, vi = cols.index('key'), cols.index('value')

        def convert_setting(vals):
            key = str(vals[ki])
            if key not in SECRET_SETTING_KEYS and key != 'webpush_vapid_keypair':
                return vals
            out = list(vals)
            out[vi] = _reseal_setting(db, key, vals[vi], stuck)
            return out
        return convert_setting
    enc = [i for i, c in enumerate(cols) if c in ENCRYPTED_COLUMNS.get(name, ())]
    if not enc:
        return None

    def convert(vals):
        if not any(isinstance(vals[i], str) and vals[i].startswith('gAAAA') for i in enc):
            return vals
        out = list(vals)
        for i in enc:
            out[i] = _reseal_legacy(db, vals[i], f'{name}.{cols[i]}', stuck)
        return out
    return convert


def _plugin_configs():
    """(plugin id, bytes, text) for each plugins/<id>/config.json worth sending: a
    regular file, valid JSON, within the per-file and total caps."""
    try:
        names = sorted(os.listdir(PLUGINS_DIR))
    except OSError:
        return []
    out, total = [], 0
    for pid in names:
        if not _PLUGIN_ID_RE.fullmatch(pid):
            continue
        path = os.path.join(PLUGINS_DIR, pid, 'config.json')
        try:
            st = os.lstat(path)
            if (not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_PLUGIN_CONFIG_BYTES
                    or total + st.st_size > _MAX_PLUGIN_CONFIG_TOTAL):
                continue
            with open(path, 'rb') as fh:
                raw = fh.read(_MAX_PLUGIN_CONFIG_BYTES + 1)
            if len(raw) > _MAX_PLUGIN_CONFIG_BYTES:
                continue
            text = raw.decode('utf-8')
            json.loads(text)
        except (OSError, ValueError):
            continue
        total += len(raw)
        out.append((pid, raw, text))
    return out


def _walk_files(h, body):
    """The file half of _walk_snapshot, into the hashes `h` (_Digests): each file as the
    digest of its content."""
    files = {}
    try:
        with open(KNOWN_HOSTS_FILE, 'rb') as fh:
            raw = fh.read()
        text = raw.decode('utf-8')
    except (OSError, ValueError):
        pass
    else:
        h.update(b'F:ssh_known_hosts;')
        _hash_value(h, hashlib.sha256(raw).digest())
        if body:
            files['ssh_known_hosts'] = text

    branding, total = {}, 0
    try:
        names = sorted(os.listdir(BRANDING_DIR))
    except OSError:
        names = []
    for fn in names:
        path = os.path.join(BRANDING_DIR, fn)
        try:
            if fn.startswith('.') or not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            if total + size > _MAX_BRANDING_BYTES:
                continue
            with open(path, 'rb') as fh:
                data = fh.read()
        except OSError:
            continue
        total += size
        h.update(b'F:branding;')
        _hash_value(h, fn)
        _hash_value(h, hashlib.sha256(data).digest())
        if body:
            branding[fn] = base64.b64encode(data).decode()
    if body:
        files['branding'] = branding

    configs = {}
    for pid, raw, text in _plugin_configs():
        h.update(b'F:plugin_config;')
        _hash_value(h, pid)
        _hash_value(h, hashlib.sha256(raw).digest())
        if body:
            configs[pid] = text
    if body:
        files['plugin_config'] = configs
    return files


def _walk_tables(body):
    """The table half of _walk_snapshot: (the hashes so far, tables, stuck). On the
    connection of whoever calls, so inside a transaction it sees what that one wrote."""
    from pegaprox.core.db import get_db
    db = get_db()
    cur = db.conn.cursor()
    present = _existing_tables(cur)
    h = _Digests()
    tables, stuck = {}, []
    for name in SYNC_TABLES:
        if name not in present:
            continue
        cur.execute(f'PRAGMA table_info("{name}")')
        coldefs = {r[1]: [r[2] or '', r[4]] for r in cur.fetchall()}
        cur.execute(f'SELECT * FROM "{name}"')
        cols = [d[0] for d in cur.description]
        plan = _row_plan(name, cols, coldefs)
        convert = _row_converter(db, name, cols, stuck) if body else None
        digests, rows = [], []
        for r in cur:
            vals = tuple(r)
            if name == 'server_settings' and _is_local_setting(str(vals[0])):
                continue
            digests.append(_row_digest(vals, plan))
            if body:
                rows.append([_enc(v) for v in (convert(vals) if convert else vals)])
        h.table(name, present[name] or '', cols, digests)
        if body:
            tables[name] = {'sql': present[name], 'columns': cols, 'rows': rows,
                            'coldefs': coldefs}
    return h, tables, stuck


def _walk_snapshot(body):
    """(etag, tables, files, stuck, data): the etag of what a snapshot carries, with
    body=True its tables and files, and the digest of the rows and files alone (see
    _Digests).

    Each row is hashed on its own with VOLATILE_COLUMNS left out, and the row digests
    are sorted, so neither a login nor an INSERT OR REPLACE that moves a row changes
    either one. They are taken from the values as stored: a resealed legacy value is
    randomized and would change them on every build.
    """
    h, tables, stuck = _walk_tables(body)
    files = _walk_files(h, body)
    etag, data = h.done()
    return etag, tables, files, sorted(set(stuck)), data


def warn_stuck(stuck):
    if stuck:
        logging.warning("[HA] values in the legacy Fernet format that this instance cannot "
                        f"open go to the standby as they are: {', '.join(stuck)} - "
                        "save them again here")


def snapshot_meta():
    """Who we are, read under the state lock. Taken on the hub and handed to
    build_snapshot and snapshot_etag, so the threadpool worker never touches a gevent
    lock. On the active it carries the member list for the standbys."""
    st = _load()
    meta = dict(instance_id=st['instance_id'], role=st['role'],
                epoch=int(st.get('epoch') or 0), key_fp=key_fingerprint(), group=GROUP_MARK)
    if st['role'] == ROLE_ACTIVE:
        meta['members'] = _member_list(st)
        meta['tombstones'] = _tombstone_list(st)
        # what the group has besides its members, only once it has it: the zone its
        # schedules run in. The witness always, None when there is none: a member drops
        # the one it holds once the leader removed it
        if st.get('timezone'):
            meta['timezone'] = st['timezone']
        meta['witness'] = _witness(st)
        # and its mode, for a member that holds no voter config (yet): it must not take
        # the group for a manual one
        if _mode_said(st) != ha_vote.MODE_MANUAL:
            meta['mode'] = _mode_said(st)
        # the voter config it holds: a member that holds the same manual one knows from a
        # manual active that its switch back went through (_manual_known)
        if _lease(st) is not None:
            meta['cfg_digest'] = ha_vote.cfg_digest(st['lease']['cfg'])
    return meta


def _group_etag(etag, meta):
    """The etag of tables and files, with the member list and the tombstones folded in
    when there are any: a standby added or removed, or made active, reaches every
    standby with its next poll, not only once the configuration changes as well."""
    group, tombs = meta.get('members'), meta.get('tombstones')
    if not group and not tombs:
        return etag
    h = hashlib.sha256(b'pegaprox-ha-group')
    _hash_value(h, etag)
    _hash_value(h, meta.get('instance_id'))
    _hash_value(h, int(meta.get('epoch') or 0))
    for e in group or []:
        for key in ('instance_id', 'url', 'fingerprint', 'public_key', 'secret_hash'):
            _hash_value(h, e.get(key))
        # only when set: a group where nobody serves keeps the etag it had before
        if e.get('serve') is True:
            h.update(b'S')
        # the VMs an admin named for it (set_agent_vmid), as for serve
        if e.get('agent_vmid'):
            h.update(b'V')
            _hash_value(h, json.dumps(e['agent_vmid'], sort_keys=True))
        # site, vote and may lead, as for serve
        if e.get('site'):
            h.update(b'T')
            _hash_value(h, e['site'])
        if e.get('voter') is False:
            h.update(b'N')
        if e.get('may_lead') is False:
            h.update(b'L')
    for t in tombs or []:
        h.update(b'R')
        for key in ('instance_id', 'epoch', 'at', 'by', 'public_key', 'secret_hash'):
            _hash_value(h, t.get(key))
    # only when set, as for serve
    if meta.get('timezone'):
        h.update(b'Z')
        _hash_value(h, meta['timezone'])
    if meta.get('witness'):
        h.update(b'W')
        for key in _WITNESS_KEYS:
            _hash_value(h, meta['witness'].get(key))
    if meta.get('mode'):
        h.update(b'M')
        _hash_value(h, meta['mode'])
    if meta.get('cfg_digest'):
        h.update(b'C')
        _hash_value(h, meta['cfg_digest'])
    return h.hexdigest()[:32]


def build_snapshot(meta=None, stuck=None, raw=None):
    """Everything a standby needs, as a JSON-ready dict.

    From the threadpool, pass `meta` from snapshot_meta() and a `stuck` list to
    collect the legacy values that could not be resealed; the caller logs them on
    the hub. Called without them it does both itself, and puts the config version on
    the snapshot (stamp_snapshot). From the threadpool that is the caller's part too,
    back on the hub: `raw`, a list, gets the etag of the tables and files for it, and
    the digest of the rows and files alone."""
    own = meta is None
    meta = meta or snapshot_meta()
    upto = journal_mark() if own else None
    etag, tables, files, found, data = _walk_snapshot(body=True)
    if stuck is None:
        warn_stuck(found)
    else:
        stuck.extend(found)
    if raw is not None:
        raw.extend((etag, data))
    snap = dict(tables=tables, files=files, format=SNAPSHOT_FORMAT, generated_at=_now(),
                etag=_group_etag(etag, meta), **meta)
    if own:
        stamp_snapshot(snap, etag, upto, data)
    return snap


def snapshot_etag(meta=None, raw=None):
    """The etag build_snapshot(meta) would put on a snapshot now, without building the
    body: a poll that ends in 304 reads and hashes, nothing more. From the threadpool,
    pass `meta` from snapshot_meta(); `raw`, a list, gets the etag of the tables and
    files alone and the digest of their rows, for the config version (note_config_etag,
    on the hub)."""
    meta = meta or snapshot_meta()
    walked = _walk_snapshot(body=False)
    if raw is not None:
        raw.extend((walked[0], walked[4]))
    return _group_etag(walked[0], meta)


def snapshot_bytes(snap):
    return gzip.compress(json.dumps(snap, default=str).encode(), compresslevel=6)


def apply_snapshot(snap):
    """Replace every SYNC table with the snapshot's rows, in one transaction.

    Refuses a snapshot that is not from the member we pull from, not from an active
    instance, from an older epoch, sealed under a different field key, or older than
    the one held from the same leader (_refuse_older). What is here and the snapshot
    does not carry over is kept in ORPHANS_DIR first; when it cannot be kept, nothing
    is applied. Nor when this instance is no longer a standby of that member by the
    time the look at what is here is over. Takes the member list and the epoch that
    come with it. Returns a summary; captured names the copy, None when none was needed.
    """
    global _mark_checked
    p = peer() if is_standby() else None
    if not p:
        raise HaError('Not paired')
    if snap.get('format') != SNAPSHOT_FORMAT:
        raise HaError('The active instance sends a snapshot format this version does not read - update both to the same release')
    if snap.get('instance_id') != p.get('instance_id'):
        raise HaError('The snapshot is not from the paired instance')
    if snap.get('role') != ROLE_ACTIVE:
        raise HaError('The paired instance is not active')
    their_epoch = _epoch_value(snap.get('epoch') or 0)
    if their_epoch is None:
        raise HaError('The active instance sent an epoch this version does not read')
    if their_epoch < epoch():
        raise HaError('The paired instance runs an older epoch than this one')
    if snap.get('key_fp') != key_fingerprint():
        raise HaError('The field key changed on the active instance (key rotation?) - pair again')
    lineage = _clean_hist(snap.get('hist'))
    if lineage and (lineage[-1][3] != p['instance_id'] or lineage[-1][0] != their_epoch):
        # a history that does not end with its sender under this epoch names nothing
        lineage = None
    st = _load()
    _refuse_older(st, lineage)

    from pegaprox.core.db import get_db
    db = get_db()
    conn = db.conn
    cur = conn.cursor()
    tables = snap.get('tables') or {}
    summary = {'tables': 0, 'rows': 0, 'skipped_columns': {}, 'created': [], 'captured': None}
    first, _mark_checked = not _mark_checked, True
    kept, held, mark = [], None, None
    try:
        if conn.in_transaction:
            conn.commit()
        # What says whether somebody wrote here while we look: the count of the triggers
        # on the shared tables, where the last sync left them complete and the schema
        # has not moved since. Anywhere else SQLite's own count, which moves with every
        # commit, a log line or a metric included.
        seen = _change_mark()
        counted = _triggers_whole(_cv_record(st), seen)
        version = None if counted else _data_version(conn)
        # before anything is wiped; raises when a copy is needed and cannot be written
        kept.append(_keep_not_carried(st, snap, lineage, their_epoch, mark=None if first else seen))
        cur.execute('BEGIN IMMEDIATE')
        # The look gave the hub away, for seconds on a large configuration: a promotion
        # with force, a removal or another member to follow may have come in between,
        # and this snapshot is no longer ours to take. Nothing yields from here to the
        # commit.
        again = peer() if is_standby() else None
        if not again or again['instance_id'] != p['instance_id'] or their_epoch < epoch():
            raise HaError('This instance changed its role or the member it follows while '
                          'the sync was under way - not applied')
        # somebody wrote here while we looked (a request that was on its way when this
        # instance stepped down)
        wrote = (_change_mark() != seen) if counted else (_data_version(conn) != version)
        # or the copy the look ended at is gone. dismiss_orphan waits for the pull lock,
        # and still an apply that runs without it must not wipe rows that a copy held
        # only while it looked
        gone = bool(kept[0]) and not orphan_path(kept[0]['name'])
        if gone:
            kept.pop()
        if wrote or gone:
            # once more, now that nobody else can
            kept.append(_keep_not_carried(st, snap, lineage, their_epoch, inline=True))
        # the rows of the sync are no change made here: no trigger counts them
        _drop_change_triggers(cur, tables)
        cur.execute('PRAGMA defer_foreign_keys = ON')
        before = _sign_in_rows(cur)
        present = _existing_tables(cur)
        for name in SYNC_TABLES:
            t = tables.get(name)
            if name not in present:
                if not t:
                    continue
                sql = t.get('sql') or ''
                if not re.match(r'^\s*CREATE TABLE\s+(IF NOT EXISTS\s+)?"?' + re.escape(name) + r'"?\s*\(', sql):
                    raise HaError(f'Refusing the table definition sent for {name}')
                cur.execute(sql)
                summary['created'].append(name)
            cur.execute(f'PRAGMA table_info("{name}")')
            local_cols = [r[1] for r in cur.fetchall()]
            if name == 'server_settings':
                cur.execute('SELECT key FROM server_settings')
                for (key,) in cur.fetchall():
                    if not _is_local_setting(str(key)):
                        cur.execute('DELETE FROM server_settings WHERE key = ?', (key,))
            else:
                cur.execute(f'DELETE FROM "{name}"')
            if not t:
                continue
            # A column the active has and we do not yet: columns that code adds on first
            # use (custom_scripts.deleted_at and friends) or a newer release. Leaving it
            # out lost data (a soft-deleted script came back as live), so add it without
            # a type; every ALTER in our own migrations checks or tolerates an existing
            # column. Only a name that is not a plain identifier is left out.
            missing = []
            have = {c.lower() for c in local_cols}
            for c in t.get('columns') or []:
                if isinstance(c, str) and c.lower() in have:
                    continue                # SQLite column names ignore case
                if isinstance(c, str) and _COLUMN_NAME_RE.fullmatch(c):
                    _add_column(cur, name, c, (t.get('coldefs') or {}).get(c))
                    local_cols.append(c)
                    have.add(c.lower())
                    summary.setdefault('added_columns', {}).setdefault(name, []).append(c)
                else:
                    missing.append(c)
            if missing:
                summary['skipped_columns'][name] = missing
            cols = [c for c in t.get('columns') or [] if isinstance(c, str) and c.lower() in have]
            idx = [t['columns'].index(c) for c in cols]
            if not cols:
                continue
            placeholders = ','.join('?' * len(cols))
            collist = ','.join(f'"{c}"' for c in cols)
            stmt = f'INSERT OR REPLACE INTO "{name}" ({collist}) VALUES ({placeholders})'
            n = 0
            for row in t.get('rows') or []:
                # only a blob comes as a dict, and a call for every value adds up
                values = [_dec(v) if type(v) is dict else v for v in (row[i] for i in idx)]
                if name == 'server_settings' and _is_local_setting(str(values[cols.index('key')])):
                    continue
                cur.execute(stmt, values)
                n += 1
            summary['tables'] += 1
            summary['rows'] += n
        if 'ha_change_journal' in present:
            # every line in there is settled by now: its change is in this snapshot, or
            # in the copy just kept
            cur.execute('DELETE FROM ha_change_journal')
        try:
            # The triggers again, and what they count to before the commit lets the next
            # writer in: whatever is written here later moves it, and is a change of our
            # own. The hash of what the sync left is worked out after the commit, off
            # the hub (_hash_applied).
            _make_change_triggers(cur)
            mark = _change_mark()
        except Exception as e:
            mark = None
            logging.warning(f"[HA] could not count the changes made here from this sync on: {e}")
        if mark is None:
            try:
                # without the count, the hash itself has to be taken in here
                held = _walk_tables(body=False)[0]
            except Exception as e:
                logging.warning(f"[HA] could not hash the tables of the sync: {e}")
        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        # a copy that was written stays, whatever became of the apply
        _say_kept(kept, snap, their_epoch)
        if isinstance(e, CaptureFailed):
            _say_not_kept(e, snap)
        raise

    # the rows are in; nothing below raises, so a caller that got here can count them
    with _journal_lock:
        _journal['pending'] = []
    _orphans['not_kept'] = None
    summary['captured'] = _say_kept(kept, snap, their_epoch, wiped=True)
    after = _sign_in_rows(conn.cursor())
    if before is not None and after is not None:
        _end_sessions(sorted(u for u, row in before.items() if after.get(u) != row))
    summary['file_errors'] = _apply_files(snap.get('files') or {})
    problem = _adopt_group(snap)
    if problem:
        summary['file_errors'].append(problem)
    summary['tombstones_owed'] = _tombstones_owed(snap)
    rec = _note_applied(snap, lineage, their_epoch, held, mark)
    _after_apply()
    if rec and rec.get('mark'):
        # last: it gives the hub away once more, and everything else is in place
        _hash_applied(rec)
    return summary


def _merged_members(st, sender, entries, tombstones=None):
    """Our member records after the member list `entries` from `sender`, the active we
    pull from. Whoever the active no longer lists is gone, whoever a tombstone names
    stays gone (a stale list from a promoted standby must not take a removed member
    back), and we never list ourselves. The sender stays whatever its list says, and
    keeps the address we reached it on; for the others the list is the word on
    address, pin and keys, except that a key we hold is not given up for the hash of a
    secret, and on whether the active made them active (serve). What we noted about
    each member ourselves (roles seen, contact, errors) stays."""
    me, local = st['instance_id'], st.get('members') or {}
    tombs = (st.get('tombstones') or {}) if tombstones is None else tombstones
    listed = _clean_entries(entries)
    listed.pop(me, None)
    out = {}
    for mid in [sender] + sorted(m for m in listed if m != sender):
        entry, old = listed.get(mid), local.get(mid)
        if entry is None:
            if mid == sender and old:
                out[mid] = dict(old)
            continue
        rec = dict(old or {'role_seen': None, 'epoch_seen': 0, 'last_contact': None,
                           'last_error': '', 'joined_at': _now()})
        if entry['public_key']:
            if rec.get('public_key') and rec['public_key'] != entry['public_key']:
                # paired again: it holds our key only once it says so
                rec['key_acked'] = False
            rec['public_key'], rec['secret_hash'] = entry['public_key'], entry['secret_hash']
        else:
            rec['secret_hash'] = entry['secret_hash']
        if not (mid == sender and old and old.get('url')) and entry['url']:
            rec['url'], rec['fingerprint'] = entry['url'], entry['fingerprint']
        rec.setdefault('url', '')
        rec.setdefault('fingerprint', '')
        rec['serve'] = entry['serve']
        if entry.get('agent_vmid'):
            rec['agent_vmid'] = entry['agent_vmid']
        else:
            rec.pop('agent_vmid', None)
        for key in _MEMBER_MARKS:
            if key in entry:
                rec[key] = entry[key]
            else:
                rec.pop(key, None)
        if mid != sender and _matches_tombstone(rec, tombs.get(mid)):
            continue
        out[mid] = rec
        if len(out) >= MAX_MEMBERS - 1:
            break
    return out


def _adopt_group(snap):
    """A standby takes the member list, the tombstones and the epoch of the active it
    pulled from, once the rows are in, and from its own entry in that list whether the
    active made it one of the active instances (serve_assigned): from the next request
    on, no restart. Tombstones add up: an active that stepped down keeps the ones it
    made. An active from before the groups sends no list: ours stays. Never raises;
    returns what the sync status should say when the state could not be saved."""
    try:
        with _lock:
            st = _load()
            sender = snap.get('instance_id')
            if st['role'] != ROLE_STANDBY or st.get('source') != sender:
                return ''
            new = dict(st)
            tombs = st.get('tombstones') or {}
            if isinstance(snap.get('tombstones'), list):
                tombs = _merged_tombstones(tombs, _clean_tombstones(snap['tombstones']),
                                           st['instance_id'])
                new['tombstones'] = tombs
            if isinstance(snap.get('members'), list):
                new['members'] = _merged_members(st, sender, snap['members'], tombs)
                # not listed at all is no flag either
                own = _clean_entries(snap['members']).get(st['instance_id']) or {}
                new['serve_assigned'] = own.get('serve') is True
                # the VM it runs as, as the leader holds it: should it lead one day, its
                # own entry of the list it hands out carries it on (Force leader, 7.3)
                if own.get('agent_vmid'):
                    new['agent_vmid'] = own['agent_vmid']
                else:
                    new.pop('agent_vmid', None)
                # its site, vote and may lead as well, the leader's word like the rest: a
                # member whose vote was taken counts the votes as the leader does
                for key in _MEMBER_MARKS:
                    if key in own:
                        new[key] = own[key]
                    else:
                        new.pop(key, None)
                # MK Oct 2026 (#625) - where the leader reaches this member; after a
                # promotion it is also what the node agents are given to ask
                if own.get('url'):
                    new['own_url'] = own['url']
            their_epoch = _epoch_value(snap.get('epoch') or 0)
            if (their_epoch is not None and their_epoch > int(st.get('epoch') or 0)
                    and not _lease_mode(st)):
                # never back to an active from before this one. Not in an automatic
                # group: there the epoch is the term, and it moves with a vote or a
                # renewal, which write down who it went to
                new['epoch'] = their_epoch
            # the zone the group's schedules run in and its witness, the leader's word
            # like the member list. A leader that sends neither changes neither
            zone = snap.get('timezone')
            if _zone_name(zone):
                # kept even where this host cannot read it: the status page names it as
                # unreadable here (timezone_unreadable), and it is the group's all the same
                new['timezone'] = zone
            if _zone_name(zone) and _zone(zone) is None and zone not in _zones_unknown:
                # no tzdata for it on this host; said once per process
                _zones_unknown.add(zone)
                logging.error(f"[HA] the group's time zone {zone!r} is not known on this host - "
                              "install tzdata, or schedules run by the local clock here once this "
                              "instance leads")
            witness = _clean_witness(snap.get('witness'))
            if witness and witness['instance_id'] != st['instance_id']:
                new['witness'] = witness
            elif 'witness' in snap and snap['witness'] is None:
                # a leader that says it has none (an older one sends no key at all)
                new.pop('witness', None)
            # the group's mode as the instance we follow says it. Kept where the voter
            # config held here does not say the same: none here and an automatic group
            # (nobody is promoted by hand then), or an automatic one here and a group
            # that went back to manual (this instance missed it, and may leave by hand)
            said = snap.get('mode')
            said = said if said in (ha_vote.MODE_AUTO, ha_vote.MODE_PENDING) else ha_vote.MODE_MANUAL
            lease = st.get('lease') if isinstance(st.get('lease'), dict) else {}
            held = lease.get('mode') if lease.get('mode') in ha_vote.MODES else ha_vote.MODE_MANUAL
            new.pop('group_mode', None)
            if said != held and ha_vote.MODE_MANUAL in (said, held):
                new['group_mode'] = said
            valid = _lease(st)
            digest = ha_vote.cfg_digest(valid['cfg']) if valid is not None else None
            if (said == held == ha_vote.MODE_MANUAL and digest is not None
                    and snap.get('cfg_digest') == digest and valid.get('settled') != digest):
                # the instance this standby follows runs the group by hand with the very
                # config held here, its lease no longer in force: a switch back held here
                # is the group's (_manual_known)
                new['lease'] = dict(valid, settled=digest)
            if new != st:
                _commit_locked(new)
        return ''
    except Exception as e:
        logging.warning(f"[HA] could not take the member list from the active instance: {e}")
        return f'the member list was not saved ({type(e).__name__}: {e})'


def _tombstones_owed(snap):
    """The tombstones we hold for members that the member list in `snap` still names:
    the removal reached us and not the active we pull from, which was promoted while it
    could not hear about it. As a tombstone list, for take_tombstones on that active;
    [] when there are none."""
    if not isinstance(snap.get('members'), list):
        return []
    st = _load()
    sender = snap.get('instance_id')
    if st['role'] != ROLE_STANDBY or st.get('source') != sender:
        return []
    tombs = st.get('tombstones') or {}
    listed = _clean_entries(snap['members'])
    return [dict(tombs[mid], instance_id=mid) for mid in sorted(listed)
            if mid not in (sender, st['instance_id']) and _matches_tombstone(listed[mid], tombs.get(mid))]


def _sign_in_rows(cur):
    """username -> (password hash, salt, enabled), or None when it cannot be read."""
    try:
        cur.execute('SELECT username, password_hash, password_salt, enabled FROM users')
        return {r[0]: (r[1], r[2], r[3]) for r in cur.fetchall()}
    except Exception as e:
        logging.warning(f"[HA] could not read the users around a sync: {e}")
        return None


def _end_sessions(usernames):
    """Sessions live per instance. A password reset, a disable or a delete on the
    active ends the user's sessions there, but only the new row reaches us: end
    them here as well. Best effort; a failure is logged and the sync stands."""
    steps = (
        ('pegaprox.utils.auth', 'invalidate_all_user_sessions'),
        ('pegaprox.utils.realtime', 'invalidate_user_ws_tokens'),
        ('pegaprox.utils.realtime', 'invalidate_user_sse_tokens'),
    )
    for username in usernames:
        for mod, fn in steps:
            try:
                getattr(importlib.import_module(mod), fn)(username)
            except Exception as e:
                logging.warning(f"[HA] {mod}.{fn}({username!r}) after sync: {e}")
    if usernames:
        logging.info(f"[HA] sync: ended the sessions of {len(usernames)} user(s) whose "
                     "sign-in changed on the active instance")


_COLUMN_TYPE_RE = re.compile(r'[A-Za-z][A-Za-z0-9_ ]{0,31}(\(\d{1,5}(,\s*\d{1,5})?\))?')
_COLUMN_DEFAULT_RE = re.compile(r"-?\d{1,18}(\.\d{1,18})?|'(?:[^']|''){0,256}'|NULL", re.IGNORECASE)


def _add_column(cur, table, column, coldef):
    """ALTER TABLE ... ADD COLUMN with the active's declared type and default when
    both are plain, so a later migration that finds the column already there still
    gets the default it would have set. Anything else: a column without a type."""
    ctype, dflt = (list(coldef) + ['', None])[:2] if isinstance(coldef, (list, tuple)) else ('', None)
    parts = [f'ALTER TABLE "{table}" ADD COLUMN "{column}"']
    if isinstance(ctype, str) and _COLUMN_TYPE_RE.fullmatch(ctype.strip()):
        parts.append(ctype.strip())
    if isinstance(dflt, str) and _COLUMN_DEFAULT_RE.fullmatch(dflt.strip()):
        parts.append('DEFAULT ' + dflt.strip())
    try:
        cur.execute(' '.join(parts))
    except Exception:
        if len(parts) == 1:
            raise
        cur.execute(parts[0])


def _apply_files(files):
    """The host key pins, the login background and the plugins' config.json files.

    Runs once the rows are committed, so it never raises: a file that cannot be
    written must not make a sync whose rows are in look failed. Returns what the
    sync status should say about it, [] when all went well."""
    problems = []
    kh = files.get('ssh_known_hosts')
    if isinstance(kh, str):
        try:
            _write_private(KNOWN_HOSTS_FILE, kh.encode())
        except Exception as e:
            logging.warning(f"[HA] could not write the SSH host key pins: {e}")
            problems.append(f'the SSH host key pins were not written ({type(e).__name__}: {e})')
    branding = files.get('branding')
    if isinstance(branding, dict):
        try:
            os.makedirs(BRANDING_DIR, exist_ok=True)
        except Exception as e:
            logging.warning(f"[HA] could not create the branding folder: {e}")
            problems.append(f'the login background was not written ({type(e).__name__}: {e})')
            branding = {}
        for fn, b64 in branding.items():
            if not re.match(r'^[A-Za-z0-9_.\-]{1,64}$', fn) or fn.startswith('.'):
                continue
            try:
                _write_private(os.path.join(BRANDING_DIR, fn), base64.b64decode(b64), mode=0o644)
            except Exception as e:
                logging.warning(f"[HA] could not write branding file {fn}: {e}")
    configs = files.get('plugin_config')
    if isinstance(configs, dict):
        total = 0
        for pid, text in sorted(configs.items()):
            if not isinstance(pid, str) or not _PLUGIN_ID_RE.fullmatch(pid) or not isinstance(text, str):
                continue
            total += len(text.encode('utf-8'))
            if total > _MAX_PLUGIN_CONFIG_TOTAL:
                logging.warning("[HA] the plugin configurations in the snapshot exceed the size cap")
                break
            try:
                _apply_plugin_config(pid, text)
            except Exception as e:
                logging.warning(f"[HA] could not write the configuration of plugin {pid}: {e}")
    return problems


def _apply_plugin_config(pid, text):
    """Write plugins/<pid>/config.json, only into a plugin this instance has.
    Returns True when the file changed."""
    data = text.encode('utf-8')
    if len(data) > _MAX_PLUGIN_CONFIG_BYTES:
        return False
    json.loads(text)
    folder = os.path.join(PLUGINS_DIR, pid)
    if not os.path.isdir(folder):
        # a snapshot never creates a plugin directory
        return False
    path = os.path.join(folder, 'config.json')
    mode = 0o600
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    if st is not None:
        if not stat.S_ISREG(st.st_mode):
            return False
        with open(path, 'rb') as fh:
            if fh.read() == data:
                return False
        mode = stat.S_IMODE(st.st_mode)
    _write_private(path, data, mode=mode)
    return True


def _write_private(path, data, mode=0o600):
    tmp = path + '.ha-tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'wb') as fh:
        # O_CREAT's mode is cut by the umask and ignored for a leftover tmp file
        os.fchmod(fh.fileno(), mode)
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _after_apply():
    """Caches that do not reread the database on their own."""
    steps = (
        ('pegaprox.utils.rbac', 'invalidate_roles_cache'),
        ('pegaprox.utils.rbac', 'invalidate_tenants_cache'),
        ('pegaprox.utils.rbac', 'invalidate_vm_acls_cache'),
        ('pegaprox.utils.rbac', 'invalidate_pool_cache'),
        ('pegaprox.api.settings', 'load_ip_whitelist'),
        ('pegaprox.api.storage', 'load_esxi_config'),
        ('pegaprox.api.storage', 'load_storage_clusters'),
    )
    for mod, fn in steps:
        try:
            getattr(importlib.import_module(mod), fn)()
        except Exception as e:
            logging.debug(f"[HA] {mod}.{fn} after sync: {e}")


# --- config version and changes not carried over ---------------------------------
#
# MK Oct 2026 (#625) - a sync replaces every shared table on a member, and whatever the
# member held that the snapshot did not carry went with the DELETE: what a former
# active took after its last hand-out, what a standby held of an active that was
# replaced by force. Now the data says where it comes from. The active steps its
# config version (cv) whenever what it hands out changed, and every instance keeps
# the cv of what it holds next to the digest its own rows and files had at that
# moment (data_at_cv; etag_at_cv is the etag of the same walk, which the definition of
# the tables is part of). A member whose rows still have that digest, and whose cv is
# part of the history a snapshot names, holds nothing the snapshot lacks. Any other
# member compares row by row and keeps what differs in ORPHANS_DIR before the wipe:
# sealed (_copy_key), audited, listed in the status, gone only when an admin dismisses
# it. A copy that cannot be written refuses the snapshot. In every mode.
#
# A member also keeps the triggers of the tick (ha_cv_dirty) between two syncs, and the
# count they stood at when the last one committed (mark). While that count, the schema
# and the files are what they were, nothing was changed here and nothing is read or
# hashed before the wipe; the hashes are for when it moved.
#
# cv = (epoch, seq). An entry is [epoch, seq, segment id, leader id]: every instance
# that leads writes a segment of its own, so two actives under one epoch (two
# promotions at once) or a leader whose state file came back from a backup never give
# one cv two contents. hist is the last cv of each segment the data went through,
# oldest first; its last entry is the cv of the data here. A cv and the base it started
# from alone are not enough: a member two leaders behind sits below the base of a
# history it was never part of.
#
# A leader whose state went back (the config directory from a backup, a VM snapshot)
# counts on in the segment it had, and one number then names two contents. Two things
# catch that. A member says what it holds with every pull (PEER_CV_HEADER): more of
# the segment than the leader knows of, and the leader goes on in a new one. And every
# step has a random mark (steps): a member that holds a step under another mark than
# the snapshot names for it compares row by row.
#
# The cv steps when a snapshot, a poll or a note to the members finds the tables
# changed, so the cv on a snapshot always stands for its content. The leader of an
# automatic group also ticks (cv_tick), for the changes nobody pulls or notes.

class CaptureFailed(HaError):
    """What this instance holds and a snapshot does not carry could not be kept."""

    def __init__(self, why, cause):
        super().__init__('This instance holds changes the snapshot does not carry, and could '
                         f'not keep a copy of them ({type(cause).__name__}) - not applied. Free '
                         'up space in the config directory')
        self.why, self.cause = why, cause


def _cv_record(st):
    rec = st.get('cv')
    return rec if isinstance(rec, dict) else None


def _clean_hist(value):
    """A history as the state file or a snapshot carries it, None when it is none: up to
    LINEAGE_KEEP entries [epoch, seq, segment id, leader id], the epochs in order and no
    segment twice."""
    if not isinstance(value, list) or not value or len(value) > LINEAGE_KEEP:
        return None
    out, segments = [], set()
    for entry in value:
        if not isinstance(entry, list) or len(entry) != 4:
            return None
        ep, seq, seg, by = entry
        if (_epoch_value(ep) is None or isinstance(seq, bool) or not isinstance(seq, int)
                or not 0 <= seq < _SEQ_MAX
                or not isinstance(seg, str) or not _SEGMENT_RE.fullmatch(seg) or seg in segments
                or not isinstance(by, str) or not _ID_RE.fullmatch(by)
                or (out and ep < out[-1][0])):
            return None
        segments.add(seg)
        out.append([ep, seq, seg, by])
    return out


def _hist_of(rec):
    return (_clean_hist(rec.get('hist')) or []) if rec else []


def _clean_steps(value):
    """The marks of the last steps as the state file or a snapshot carries them, up to
    STEPS_KEEP entries [segment id, seq, mark]; [] for anything else."""
    if not isinstance(value, list) or len(value) > STEPS_KEEP:
        return []
    out = []
    for entry in value:
        if not isinstance(entry, list) or len(entry) != 3:
            return []
        seg, seq, mark = entry
        if (not isinstance(seg, str) or not _SEGMENT_RE.fullmatch(seg) or isinstance(seq, bool)
                or not isinstance(seq, int) or not 0 <= seq < _SEQ_MAX
                or not isinstance(mark, str) or not _MARK_RE.fullmatch(mark)):
            return []
        out.append([seg, seq, mark])
    return out


def _step_mark(steps, entry):
    """The mark `steps` has for the cv `entry`, None when they do not reach that far."""
    return next((mark for seg, seq, mark in steps if seg == entry[2] and seq == entry[1]), None)


def _one_cv(value):
    """One entry as another member reports it, None for anything else."""
    got = _clean_hist([value]) if isinstance(value, list) else None
    return got[0] if got else None


def _last_cv(st):
    """The newest entry of the history held, None before there is one. Asked with every
    lease call: a history is checked once (a write puts a new list in, none is changed
    in place)."""
    rec = _cv_record(st)
    hist = rec.get('hist') if rec else None
    seen = _hist_checked[0]
    if seen is not None and seen[0] is hist:
        return seen[1]
    clean = _clean_hist(hist) if hist is not None else None
    last = tuple(clean[-1]) if clean else None
    _hist_checked[0] = (hist, last)
    return last


_hist_checked = [None]


def config_version(st=None):
    """(epoch, seq) of the configuration this instance holds, CV_ZERO before it has one."""
    last = _last_cv(st or _load())
    return (last[0], last[1]) if last else CV_ZERO


def cv_entry(st=None):
    """[epoch, seq, segment id, leader id] of the configuration here, None before it has one."""
    last = _last_cv(st or _load())
    return list(last) if last else None


def held_cv(value):
    """PEER_CV_HEADER as a member sent it with its pull: the entry, None for anything
    that is none."""
    if not isinstance(value, str) or not 0 < len(value) <= 256:
        return None
    try:
        return _one_cv(json.loads(value))
    except ValueError:
        return None


def _covered(entry, hist):
    """Whether the history `hist` went through the cv `entry`: it has that segment, and
    left it no earlier."""
    return any(h[0] == entry[0] and h[2] == entry[2] and h[1] >= entry[1] for h in hist)


def _newer_cv(old, new):
    """Whether the entry `new` a member reported replaces `old`, the one noted before.
    Within a segment only a higher one does: an answer that took long must not put the
    note back. Another segment is that member on another history."""
    old = _one_cv(old)
    return old is None or old[2] != new[2] or new[1] > old[1]


def _in_pool(fn):
    """fn() in gevent's threadpool, so the hub serves on while it reads and hashes;
    inline without a hub. fn takes no gevent lock and logs nothing."""
    try:
        from gevent import get_hub
        pool = get_hub().threadpool
    except Exception:
        return fn()
    return pool.apply(fn)


def _ahead_in(segment, st, held=None):
    """The highest seq a member says it holds of `segment`, -1 when none holds any:
    what the watch noted of each (cv_seen), and `held`, the entry the member that pulls
    right now sent along."""
    best = -1
    for seen in [rec.get('cv_seen') for rec in (st.get('members') or {}).values()] + [held]:
        seen = _one_cv(seen)
        if seen and seen[2] == segment:
            best = max(best, seen[1])
    return best


def note_config_etag(raw, upto=None, data=None, held=None):
    """The active, after it worked out `raw`, the etag of its shared tables and files as
    _walk_snapshot returns it: one step of cv when that changed since the last step, in
    a segment of its own (begun here when it leads from data it did not hand out
    itself). `data` is the digest of the rows and files of the same walk, kept next to
    it. Journal lines up to the id `upto`, written before that walk began, get the cv.
    `held` is the entry the member this is worked out for says it holds (held_cv).
    Returns the record, None anywhere but on an active with members. Raises HaError
    when the step cannot be saved: no snapshot may leave under a cv that stands for
    other content."""
    with _lock:
        st = _load()
        if st['role'] != ROLE_ACTIVE or not st.get('members') or not raw:
            return None
        old = _cv_record(st)
        rec = {k: v for k, v in (old or {}).items() if k not in ('joined', 'from')}
        hist = _hist_of(old)
        me, ep = st['instance_id'], int(st.get('epoch') or 0)
        last = hist[-1] if hist else None
        changed, segments = rec.get('etag_at_cv') != raw, len(hist)
        if last is None or last[0] != ep or last[3] != me:
            # we lead from what we hold. Under the same epoch (another active was
            # promoted at the same time) the count goes on, so (epoch, seq) never goes
            # back
            rec['base_cv'] = [last[0], last[1]] if last else list(CV_ZERO)
            hist.append([ep, last[1] if last and last[0] == ep else 0, secrets.token_hex(8), me])
        elif _ahead_in(last[2], st, held) > last[1]:
            # a member holds more of our segment than we know of: this state file went
            # back (a restored backup). From here on it is a segment of its own, above
            # all of that, so the member keeps a copy instead of taking what we hand out
            # for the continuation of what it has
            rec['base_cv'] = [last[0], last[1]]
            hist.append([ep, _ahead_in(last[2], st, held), secrets.token_hex(8), me])
            changed = True
        if changed:
            hist[-1][1] += 1
            rec.update(etag_at_cv=raw, data_at_cv=data, at=_now())
            # what a sync left here as a member (_note_applied) is not what is here now
            rec.pop('mark', None)
        if changed or len(hist) > segments:
            # the mark of this step: a member that holds the same number under another
            # one holds other content (_why_not_carried)
            steps = _clean_steps(rec.get('steps'))
            steps.append([hist[-1][2], hist[-1][1], secrets.token_hex(4)])
            rec['steps'] = steps[-STEPS_KEEP:]
        rec['hist'] = hist[-LINEAGE_KEEP:]
        if rec != old:
            try:
                _commit_locked(dict(st, cv=rec))
            except Exception as e:
                raise HaError(f'The config version could not be saved: {e}')
        entry = list(rec['hist'][-1])
    if upto:
        _fill_journal(entry, upto)
    return rec


def stamp_snapshot(snap, raw, upto=None, data=None, held=None):
    """The config version on a snapshot whose tables and files have the etag `raw`: cv,
    base_cv, the history it carries (hist), when its cv stepped (cv_at) and the marks
    of its last steps (steps). Anywhere but on an active with members the snapshot
    stays without. `data` and `held` as for note_config_etag, and it raises HaError
    like that one."""
    rec = note_config_etag(raw, upto, data, held)
    hist = _hist_of(rec)
    if hist:
        snap.update(cv=hist[-1][:2], hist=hist, base_cv=rec.get('base_cv') or list(CV_ZERO),
                    cv_at=rec.get('at'), steps=_clean_steps(rec.get('steps')))
    return snap


def _refuse_older(st, lineage):
    """The order guard: a member never applies a snapshot older than the one it holds
    from the same leader. Pulls go one at a time (_pull_lock), and still a retry or an
    answer that took long can hand in an older snapshot after a newer one, which would
    put the member back below what it told the group it holds."""
    mine = _hist_of(_cv_record(st))
    if not mine or not lineage:
        return
    m, t = mine[-1], lineage[-1]
    if t[0] == m[0] and t[2] == m[2] and t[1] < m[1]:
        raise HaError(f'The snapshot is older than the configuration this instance holds '
                      f'({t[0]}.{t[1]} against {m[0]}.{m[1]}) - not applied')


def _rows_not_sent(snap):
    """The shared tables that hold rows here and that `snap` does not carry at all: its
    sender runs a release that does not share them, and the sync empties them all the
    same. Only reads, on the caller's connection."""
    sent = snap.get('tables') if isinstance(snap.get('tables'), dict) else {}
    from pegaprox.core.db import get_db
    cur = get_db().conn.cursor()
    present = _existing_tables(cur)
    out = []
    for name in SYNC_TABLES:
        if sent.get(name) or name not in present:
            continue
        if name == 'server_settings':
            rows = [k for (k,) in cur.execute('SELECT key FROM server_settings').fetchall()
                    if not _is_local_setting(str(k))]
        else:
            rows = cur.execute(f'SELECT 1 FROM "{name}" LIMIT 1').fetchall()
        if rows:
            out.append(name)
    return out


def _why_not_carried(st, snap, lineage, their_epoch, data_here, mark=None):
    """'' when `snap` is known to carry everything this instance holds, else why that
    cannot be shown. data_here() gives the digest of the rows and files now; it is
    asked only when the histories fit, and not at all when `mark` (_change_mark, as
    it is now) is still the one the last sync left: nothing was written here since."""
    rec = _cv_record(st)
    sender = snap.get('instance_id')
    if rec is not None and rec.get('joined'):
        # the first snapshot after the join replaces what the admin agreed to replace
        return ''
    missing = _rows_not_sent(snap)
    if missing:
        # a history says what the sender was handed, not what its release hands on
        return f"the snapshot carries no {', '.join(missing)}, and there are rows of it here"
    if rec is None:
        sync = st.get('sync') or {}
        if sync.get('last_ok_at') and sync.get('source_epoch') == int(st.get('epoch') or 0) == their_epoch:
            # synced by a release before the config version and pulling on under the
            # same epoch: what is here came from that active
            return ''
        return 'this instance has no record of where its configuration came from'
    mine = _hist_of(rec)
    if mine and lineage is not None:
        e, s, _seg, by = mine[-1]
        if not _covered(mine[-1], lineage):
            return (f'the configuration here is at {e}.{s} (led by {by[:8]}), which the '
                    'snapshot does not carry')
        here = _step_mark(_clean_steps(rec.get('steps')), mine[-1])
        there = _step_mark(_clean_steps(snap.get('steps')), mine[-1])
        if here and there and here != there:
            # the same number, made twice: the sender went back to an earlier state
            # and counted on from there
            return (f'the snapshot names {e}.{s}, the config version held here, for '
                    'other content')
    elif rec.get('from') != [sender, their_epoch]:
        # one side cannot name its history (a release before it): only the next pull
        # from the very instance and epoch the data here came from continues it
        return 'neither side can show that the snapshot carries what is here'
    if mark is not None and rec.get('mark') == mark:
        return ''
    if not rec.get('data_at_cv') or data_here() != rec['data_at_cv']:
        return 'the configuration here changed after it was last synced or handed out'
    return ''


def _is_default(value, coldef):
    """Whether `value` is what a row has in a column nobody set: NULL, or the declared
    default (coldef as the walk reads it, [type, default as SQL text])."""
    if value is None:
        return True
    dflt = coldef[1] if isinstance(coldef, (list, tuple)) and len(coldef) > 1 else None
    try:
        return value in (_default_values(dflt) or ())
    except TypeError:
        # a blob as the walk encodes it
        return False


def _row_keys(name, cols, rows, other_cols, coldefs=None):
    """One text per row of `name` that is equal for two rows a sync would not tell
    apart: the columns both sides have, by name, VOLATILE_COLUMNS left out. With
    `coldefs` (the rows here) a column only this side has counts where a row holds more
    than its default in it, which the snapshot cannot carry; a column only the snapshot
    has takes nothing from here. None for a row that takes no part (one of the
    instance's own settings, or one that is no row)."""
    masked = {c.lower() for c in VOLATILE_COLUMNS.get(name, ())}
    other = {c.lower() for c in other_cols if isinstance(c, str)}
    shared, own = [], []
    for i, c in enumerate(cols):
        if isinstance(c, str) and c.lower() not in masked:
            (shared if c.lower() in other else own).append((c.lower(), i))
    shared.sort()
    key_at = next((i for c, i in shared + own if c == 'key'), None) if name == 'server_settings' else None
    out = []
    for row in rows:
        if not isinstance(row, list) or len(row) != len(cols):
            out.append(None)
            continue
        if key_at is not None and _is_local_setting(str(row[key_at])):
            out.append(None)
            continue
        key = [[c, row[i]] for c, i in shared]
        if coldefs is not None:
            extra = [[c, row[i]] for c, i in own if not _is_default(row[i], coldefs.get(cols[i]))]
            if extra:
                key.append(['\x00only-here', extra])
        out.append(json.dumps(key, default=str, separators=(',', ':')))
    return out


def _lines(text):
    return {line.strip() for line in text.splitlines() if line.strip()}


def _differences(tables, files, snap):
    """What applying `snap` would take away or change here: (rows, files, counts). rows
    holds, per table, the rows here that the snapshot does not carry, as the walk read
    them (sealed values stay sealed); files the files it would overwrite with other
    content, as they are here; counts per table how many rows are only here and how
    many only in the snapshot, and under 'files' the names. All empty when the snapshot
    holds exactly what is here."""
    theirs = snap.get('tables') if isinstance(snap.get('tables'), dict) else {}
    rows_kept, counts = {}, {}
    for name in SYNC_TABLES:
        a = tables.get(name) or {}
        b = theirs.get(name) if isinstance(theirs.get(name), dict) else {}
        acols, arows = a.get('columns') or [], a.get('rows') or []
        bcols = b.get('columns') if isinstance(b.get('columns'), list) else []
        brows = b.get('rows') if isinstance(b.get('rows'), list) else []
        if not arows and not brows:
            continue
        there = collections.Counter(k for k in _row_keys(name, bcols, brows, acols) if k is not None)
        mine = []
        for row, key in zip(arows, _row_keys(name, acols, arows, bcols, a.get('coldefs') or {})):
            if key is None:
                continue
            if there.get(key, 0) > 0:
                there[key] -= 1
            else:
                mine.append(row)
        only_there = sum(there.values())
        if mine or only_there:
            counts[name] = {'only_here': len(mine), 'only_there': only_there}
        if mine:
            rows_kept[name] = {'columns': acols, 'rows': mine}
    sent = snap.get('files') if isinstance(snap.get('files'), dict) else {}
    files_kept, names = {}, []
    kh = sent.get('ssh_known_hosts')
    if isinstance(kh, str) and _lines(kh) != _lines(files.get('ssh_known_hosts') or ''):
        files_kept['ssh_known_hosts'] = files.get('ssh_known_hosts') or ''
        names.append('ssh_known_hosts')
    # only what _apply_files would write: a well-formed name, a plugin that is here
    held = files.get('branding') or {}
    for fn, data in sorted(sent['branding'].items()) if isinstance(sent.get('branding'), dict) else ():
        if (isinstance(fn, str) and re.match(r'^[A-Za-z0-9_.\-]{1,64}$', fn) and not fn.startswith('.')
                and held.get(fn) != data):
            names.append(f'branding/{fn}')
            if fn in held:
                files_kept.setdefault('branding', {})[fn] = held[fn]
    held = files.get('plugin_config') or {}
    for pid, text in sorted(sent['plugin_config'].items()) if isinstance(sent.get('plugin_config'), dict) else ():
        if (isinstance(pid, str) and _PLUGIN_ID_RE.fullmatch(pid) and held.get(pid) != text
                and os.path.isdir(os.path.join(PLUGINS_DIR, pid))):
            names.append(f'plugins/{pid}/config.json')
            if pid in held:
                files_kept.setdefault('plugin_config', {})[pid] = held[pid]
    if names:
        counts['files'] = names
    return rows_kept, files_kept, counts


def _orphan_meta(name):
    try:
        with open(os.path.join(ORPHANS_DIR, name + '.meta.json'), 'rb') as fh:
            data = json.loads(fh.read(1024 * 1024))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# What the meta file of a copy holds, in the clear next to the sealed copy: where and
# why it was kept, the keys it is under, counts and digests. No row, no file content
# and no journal line.
_ORPHAN_META_KEYS = ('kind', 'format', 'captured_at', 'instance_id', 'role', 'reason', 'key_fp',
                     'seal', 'seal_fp', 'cv', 'hist', 'replaced_by')
# what a copy begins with, by the kind of key it is sealed under
_ORPHAN_MAGICS = {'field': ORPHAN_MAGIC, 'master': ORPHAN_MAGIC_MASTER}


def _field_key():
    """The field key, for the copies of an instance on plain SQLite. Raises HaError
    without one: a copy never goes to disk in the clear."""
    from pegaprox.core.db import get_db
    key = get_db().aes_key
    if not isinstance(key, bytes) or len(key) != 32:
        raise HaError('This instance has no field key to seal a copy under')
    return key


def _master_key():
    """The master key of the key store where the database is SQLCipher, None on plain
    SQLite. It is the key this process opened its database with: the key store holds it
    in memory from the first connection on, so nothing is read from disk here. Raises
    HaError when it cannot be had."""
    from pegaprox.core import dbcrypto
    if not dbcrypto.is_encrypted():
        return None
    try:
        from pegaprox.core.keystore import load_master_key
        key = load_master_key().key_raw
    except Exception as e:
        # the reason may name a path, never the key; the type is enough here
        raise HaError(f'The master key of this instance could not be loaded ({type(e).__name__})')
    if not isinstance(key, bytes) or len(key) != 32:
        raise HaError('This instance has no master key to seal a copy under')
    return key


def _copy_key():
    """(key, kind) for the copies kept from now on: what they are sealed under, and what
    their items are keyed with. With SQLCipher a key derived from the master key
    ('master'), which exists in memory only; on plain SQLite the field key ('field').
    Raises HaError without one."""
    master = _master_key()
    if master is None:
        return _field_key(), 'field'
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=ORPHAN_KEY_INFO).derive(master), 'master'


def _copy_key_now():
    """(kind, fingerprint) of the key the copies are sealed under now, (None, None)
    when this instance has none. Never raises."""
    try:
        key, kind = _copy_key()
    except Exception:
        return None, None
    return kind, key_fingerprint(key)


def _copy_head(key, kind):
    """What a copy sealed under `key` begins with: the magic of its kind and the
    fingerprint of the key."""
    return _ORPHAN_MAGICS[kind] + key_fingerprint(key).encode()


def _seal_copy(name, data, key, kind='field'):
    """`data`, the gzip'd JSON of the copy `name`, as it goes to disk: the head
    (_copy_head), a nonce and the AES-256-GCM ciphertext. The head and the name are
    bound in, so a file put under another name does not open."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    head = _copy_head(key, kind)
    nonce = os.urandom(12)
    return head + nonce + AESGCM(key).encrypt(nonce, data, head + name.encode())


def _older_key(fp):
    """The field key with the fingerprint `fp` that this instance held before, from the
    file a rotation or a join left next to the key file. None when it is gone."""
    fn = _older_keys().get(fp)
    if not fn:
        return None
    try:
        with open(os.path.join(os.path.dirname(AES_KEY_FILE) or '.', fn), 'rb') as fh:
            key = fh.read(64)
    except OSError:
        return None
    # still that key: the file was listed a moment ago, by what it held then
    return key if key_fingerprint(key) == fp else None


def _key_of_copy(kind, fp):
    """The key that opens a copy whose head names the fingerprint `fp` of a key of
    `kind`. Raises HaError that says why this instance does not have it."""
    if kind == 'master':
        if _master_key() is None:
            raise HaError(f'This copy is sealed under a master key (fingerprint {fp}), and this '
                          'instance runs without an encrypted database - it cannot be opened on '
                          'this instance')
        key = _copy_key()[0]
        if key_fingerprint(key) != fp:
            raise HaError(f'This copy is sealed under another master key (fingerprint {fp}) than '
                          'the one this instance runs with: the key store changed, or the copy '
                          'came here from another host - it cannot be opened on this instance')
        return key
    # the field key: of an instance on plain SQLite, or from before its database was
    # encrypted
    try:
        key = _field_key()
    except HaError:
        key = None
    if key is None or key_fingerprint(key) != fp:
        key = _older_key(fp)
    if key is None:
        raise HaError(f'This copy is sealed under an earlier field key (fingerprint {fp}), from '
                      'before a key rotation or a join, and the backup of that key is no longer '
                      'next to the key file - it cannot be opened on this instance')
    return key


def open_orphan(name):
    """The copy `name` as the gzip'd JSON it was sealed from, None when there is none.
    A copy sealed under a field key from before a rotation or a join opens with the
    file that still holds that key. Raises HaError that says why when it does not open:
    the key it names is not one this instance has, or the file was changed."""
    path = orphan_path(name)
    if not path:
        return None
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        with open(path, 'rb') as fh:
            raw = fh.read()
    except OSError as e:
        raise HaError(f'The copy could not be read ({type(e).__name__})')
    cut = len(ORPHAN_MAGIC) + 16
    head, nonce, sealed = raw[:cut], raw[cut:cut + 12], raw[cut + 12:]
    kind = next((k for k, magic in _ORPHAN_MAGICS.items() if raw.startswith(magic)), None)
    fp = head[len(ORPHAN_MAGIC):].decode('ascii', 'replace')
    if kind is None or len(sealed) < 16 or not re.fullmatch('[0-9a-f]{16}', fp):
        raise HaError('This file is not a copy as this instance seals them - it was changed '
                      'or cut short')
    key = _key_of_copy(kind, fp)
    try:
        return AESGCM(key).decrypt(nonce, sealed, head + name.encode())
    except InvalidTag:
        raise HaError('This copy does not open under the key it names - the file was '
                      'changed or damaged')


def _capture_items(rows_kept, files_kept, journal, key):
    """One digest for every row, file and journal line a copy would hold, sorted, and one
    over all of them. A row counts without created_at and VOLATILE_COLUMNS, whatever the
    order of its columns: an account that is made here again after a sync replaced it
    (a sign-in under way while this instance steps down still provisions one) is the
    same row every time. Keyed with `key`, the key the copy is sealed under, so the
    meta file they go into says nothing about the rows."""
    sub = hashlib.sha256(b'pegaprox-ha-orphan-items:' + key).digest()

    def digest(*parts, size=8):
        text = json.dumps(parts, default=str, separators=(',', ':'))
        return hashlib.blake2b(text.encode('utf-8', 'surrogatepass'), digest_size=size,
                               key=sub).hexdigest()
    items = set()
    for name, t in rows_kept.items():
        masked = {c.lower() for c in VOLATILE_COLUMNS.get(name, ())} | {'created_at'}
        cols = sorted((c.lower(), i) for i, c in enumerate(t['columns']) if c.lower() not in masked)
        for row in t['rows']:
            items.add(digest('row', name, [[c, row[i]] for c, i in cols]))
    for kind, held in files_kept.items():
        for fn, content in sorted(held.items()) if isinstance(held, dict) else (('', held),):
            items.add(digest('file', kind, fn, content))
    for line in journal:
        items.add(digest('journal', [line.get(k) for k in ('at', 'user', 'method', 'path', 'via', 'cv')]))
    items = sorted(items)
    return items, digest('copy', items, size=6)


def _copy_whole(name, size, meta, key, kind):
    """Whether the sealed file of the copy `name` opens under `key`, the key in use:
    `size`, its length, is the one its meta file names, it begins as a copy sealed now
    does (_copy_head), and its seal holds under its own name. Not one that was cut
    short, damaged or put under another name, nor one under a key from before."""
    if not meta or isinstance(meta.get('bytes'), bool) or meta.get('bytes') != size:
        return False
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    head = _copy_head(key, kind)
    try:
        with open(os.path.join(ORPHANS_DIR, name + ORPHAN_SUFFIX), 'rb') as fh:
            raw = fh.read()
    except OSError:
        return False
    cut = len(head)
    if not raw.startswith(head) or len(raw) < cut + 12 + 16:
        return False
    try:
        AESGCM(key).decrypt(raw[cut:cut + 12], raw[cut + 12:], head + name.encode())
    except InvalidTag:
        return False
    return True


def _kept_already(tag, items, key, kind):
    """The copy that holds what a new one would: the one with the tag `tag` (the very
    same rows, files and journal lines), else, when every one of `items` is in a copy
    that is still here, the copy that holds most of them. None when something would be
    kept for the first time. Only a copy that opens under the key in use counts
    (_copy_whole, `head` as a copy sealed now begins): what no admin can get back out
    stands for no row."""
    files = _orphan_files()
    for name, size in files:
        if name.endswith('-' + tag) and _copy_whole(name, size, _orphan_meta(name), key, kind):
            return name
    if not items or len(items) > ORPHAN_ITEMS_MAX:
        return None
    want, found, best = set(items), set(), (0, None)
    for name, size in files:
        meta = _orphan_meta(name) or {}
        held = meta.get('items')
        if not isinstance(held, list):
            continue
        held = want.intersection(i for i in held if isinstance(i, str))
        if not held or not _copy_whole(name, size, meta, key, kind):
            continue
        found |= held
        if len(held) > best[0]:
            best = (len(held), name)
    return best[1] if found == want else None


def _write_capture(head, snap, journal, key):
    """What is here and `snap` does not carry, with `head` and the journal lines, sealed
    under `key` (_copy_key, of the kind head['seal'] names) into ORPHANS_DIR. Returns
    (name, new, counts): (None, False, {}) when there is nothing to keep, because the
    snapshot holds exactly what is here or only has more (no row and no file here would
    go, and no journal line says somebody wrote here); new is False when copies that
    are still here hold all of it already (_kept_already: an apply that failed after it
    kept them and is tried again, an account that is made here again after every sync),
    and name is that copy.

    Runs in the threadpool, or inline inside the apply's transaction: no state lock, no
    logging, no commit."""
    tables, files = _walk_snapshot(body=True)[1:3]
    rows_kept, files_kept, counts = _differences(tables, files, snap)
    if not counts or not (rows_kept or files_kept or journal):
        return None, False, {}
    items, tag = _capture_items(rows_kept, files_kept, journal, key)
    os.makedirs(ORPHANS_DIR, mode=0o700, exist_ok=True)
    os.chmod(ORPHANS_DIR, 0o700)
    again = _kept_already(tag, items, key, head['seal'])
    if again:
        return again, False, counts
    cv = head['cv'] or list(CV_ZERO)
    at = datetime.now(timezone.utc)
    while True:
        name = f"{cv[0]}-{cv[1]}-{at.strftime('%Y%m%dT%H%M%SZ')}-{tag}"
        base = os.path.join(ORPHANS_DIR, name)
        if not os.path.lexists(base + ORPHAN_SUFFIX) and not os.path.lexists(base + '.meta.json'):
            break
        # the same rows under the same cv within one second, in a copy that no longer
        # counts (cut short, damaged): it stays as it is until an admin dismisses it
        at += timedelta(seconds=1)
    data = _seal_copy(name, gzip.compress(
        json.dumps(dict(head, name=name, differences=counts, journal=journal, tables=rows_kept,
                        files=files_kept), default=str).encode(), compresslevel=6), key, head['seal'])
    meta = dict({k: head.get(k) for k in _ORPHAN_META_KEYS}, name=name, differences=counts,
                journal_rows=len(journal), bytes=len(data), repeats=0, last_at=None,
                items=items if len(items) <= ORPHAN_ITEMS_MAX else None)
    try:
        _write_private(base + ORPHAN_SUFFIX, data)
        _write_private(base + '.meta.json', json.dumps(meta, default=str).encode())
    except Exception:
        for path in (base + ORPHAN_SUFFIX, base + '.meta.json', base + ORPHAN_SUFFIX + '.ha-tmp',
                     base + '.meta.json.ha-tmp'):
            try:
                os.unlink(path)
            except OSError:
                pass
        raise
    return name, True, counts


def _keep_not_carried(st, snap, lineage, their_epoch, inline=False, mark=None):
    """apply_snapshot, before the DELETE: a copy of what is here and the snapshot does
    not carry over. Returns {name, new, why, differences}, None when it carries
    everything. Raises CaptureFailed when the copy could not be written. `inline` reads
    on the caller's connection, inside its transaction, instead of in the threadpool.
    `mark` as for _why_not_carried. Neither logs nor audits: _say_kept does, once the
    transaction is over."""
    run = (lambda fn: fn()) if inline else _in_pool
    why = _why_not_carried(st, snap, lineage, their_epoch,
                           lambda: run(lambda: _walk_snapshot(body=False)[4]), mark)
    if not why:
        return None
    mine = _hist_of(_cv_record(st))
    try:
        # taken here, on the hub: the worker gets the key, not the way to it
        key, kind = _copy_key()
        from pegaprox.core.db import get_db
        head = {
            'kind': 'pegaprox-ha-orphans', 'format': 1, 'captured_at': _now(),
            'instance_id': st['instance_id'], 'role': st['role'], 'reason': why,
            # two keys: the sealed values in the copy stay as they are in the database,
            # under the field key of this moment (key_fp); the copy as a whole is
            # sealed under `key` (seal, seal_fp)
            'key_fp': key_fingerprint() if get_db().aes_key else None,
            'seal': kind, 'seal_fp': key_fingerprint(key),
            'cv': mine[-1] if mine else None, 'hist': mine,
            'replaced_by': {'instance_id': snap.get('instance_id'), 'epoch': their_epoch,
                            'cv': lineage[-1] if lineage else None},
        }
        journal = _journal_not_in(lineage)
        name, new, counts = run(lambda: _write_capture(head, snap, journal, key))
    except Exception as e:
        raise CaptureFailed(why, e)
    if name is None:
        return None
    return {'name': name, 'new': new, 'why': why, 'differences': counts}


def _note_repeat(name):
    """A sync took away once more what the copy `name` holds already: counted in its meta
    file, with the time. No second copy, no audit row: an account that is made here
    again after every sync would add one of each per sign-in."""
    meta = _orphan_meta(name)
    if meta is None:
        return
    repeats = meta.get('repeats')
    meta.update(repeats=(repeats if isinstance(repeats, int) and repeats > 0 else 0) + 1,
                last_at=_now())
    _write_private(os.path.join(ORPHANS_DIR, name + '.meta.json'),
                   json.dumps(meta, default=str).encode())


def _say_kept(kept, snap, their_epoch, wiped=False):
    """Log and audit the copies an apply kept, each new one once. `wiped` says the apply
    went through: what an older copy holds already and went again is counted on that
    copy (_note_repeat). Returns the name of the last one, None when there was none.
    Never raises."""
    name, sender, said = None, snap.get('instance_id'), set()
    for item in kept:
        if not item:
            continue
        name = item['name']
        if name in said:
            continue
        said.add(name)
        try:
            if not item['new']:
                if wiped:
                    _note_repeat(name)
                    logging.info(f"[HA] the snapshot from {sender} does not carry changes "
                                 f"that are kept already, in {name}: {item['why']}")
                continue
            _orphans['count'] = None
            _fsync_dir(os.path.join(ORPHANS_DIR, name))
            logging.error(f"[HA] changes not carried over by the snapshot from {sender}: "
                          f"{item['why']} - kept in {os.path.join(ORPHANS_DIR, name)}{ORPHAN_SUFFIX}")
            _audit('ha.changes_not_carried_over',
                   f"kept as {name}: the snapshot from {sender} (epoch {their_epoch}) does not "
                   f"carry them, {item['why']}; {json.dumps(item['differences'])}"[:1000])
            _check_orphan_space()
        except Exception as e:
            logging.warning(f"[HA] kept {name}, and could not say so: {e}")
    return name


def _say_not_kept(error, snap):
    """Logged on every try. Audited once per sender, reason and kind of error, and again
    only after a sync went through: the loop tries again every interval, for as long as
    the disk stays full, and each audit row goes onto that disk."""
    sender = snap.get('instance_id')
    logging.error(f"[HA] the snapshot from {sender} does not carry what this instance holds "
                  f"({error.why}), and no copy of it could be kept - not applied: {error.cause}")
    what = (sender, error.why, type(error.cause).__name__)
    if _orphans.get('not_kept') == what:
        return
    _orphans['not_kept'] = what
    _audit('ha.changes_not_kept', f'snapshot from {sender} refused, no copy could be kept '
                                  f'({type(error.cause).__name__}): {error.why}'[:500])


def _data_version(conn):
    """SQLite's count of commits other connections made to the database, as this
    connection sees it. It moves when anybody else wrote, never for a write of our own."""
    return conn.execute('PRAGMA data_version').fetchone()[0]


def _change_mark():
    """What moves when somebody writes to a shared table or file here, and stays for
    anything else: [the count of the triggers, SQLite's schema version, a digest of
    _files_mark]. None while the count cannot be read (no sync made the triggers yet)."""
    try:
        n = _dirty_count()
        if n is None:
            return None
        return [n, _schema_version(), hashlib.sha256(repr(_files_mark()).encode()).hexdigest()[:16]]
    except Exception:
        return None


# read_mark: when it last looked the triggers over (monotonic), and the schema then
_read_look = {'checked': None, 'schema': None}
_read_look_lock = threading.Lock()


def read_mark():
    """The leader, before and after a read that may change shared configuration (app.py:
    a plugin's GET, and every read a member hands over): _change_mark, which moves with
    every change to a shared table or file here. A read that moved it is told to the
    members like a write. None on any other instance, and while it cannot be counted.

    The leader of a manual group runs no cv_tick, so the triggers are looked over here:
    when the count cannot be read, when the schema moved since the last look, and every
    TRIGGER_CHECK seconds anyway. Never raises."""
    try:
        st = _load()
        if st['role'] != ROLE_ACTIVE or not st.get('members'):
            return None
        last = _read_look['checked']
        mark = None
        if (last is not None and time.monotonic() - last < TRIGGER_CHECK
                and _read_look['schema'] == _schema_version()):
            mark = _change_mark()
        if mark is None:
            with _read_look_lock:
                ensure_change_triggers()
                _read_look.update(checked=time.monotonic(), schema=_schema_version())
            mark = _change_mark()
        return mark
    except Exception as e:
        logging.debug(f"[HA] no change count around a read: {e}")
        return None


def _triggers_whole(rec, mark):
    """Whether the count in `mark` saw every change since the sync that wrote the record
    `rec`: that sync left a trigger on every shared table, and the schema has not moved
    since. A table or column made later has no trigger yet, and one that was rebuilt
    lost its own."""
    held = rec.get('mark') if rec else None
    return bool(mark) and isinstance(held, list) and len(held) == 3 and held[1] == mark[1]


def _note_applied(snap, lineage, their_epoch, held, mark=None):
    """The record once a snapshot is in: its history and the marks of its steps, who it
    came from, and what says whether anything was changed here since. That is `mark`,
    the count of the triggers and the schema version as the apply's transaction left
    them (_change_mark), with the files as they are now; _hash_applied adds the etag and
    the digest of the rows. Without a count those two come from `held`, the tables as
    hashed inside the transaction. Returns the record, None when it was not written.
    Never raises: without it the next sync compares row by row, and keeps a copy it
    would not have needed."""
    try:
        etag = data = None
        if held is not None:
            _walk_files(held, False)
            etag, data = held.done()
        at = snap.get('cv_at') if lineage and isinstance(snap.get('cv_at'), str) else None
        rec = {'hist': lineage or [], 'etag_at_cv': etag, 'data_at_cv': data,
               'from': [snap.get('instance_id'), their_epoch], 'at': at[:40] if at else None,
               'steps': _clean_steps(snap.get('steps')) if lineage else []}
        now = _change_mark() if mark else None
        if now:
            # the files went in after the commit
            rec['mark'] = mark[:2] + now[2:]
        with _lock:
            st = _load()
            if st['role'] == ROLE_STANDBY:
                _commit_locked(dict(st, cv=rec))
                return rec
    except Exception as e:
        logging.warning(f"[HA] could not note the config version of the sync: {e}")
    return None


def _hash_applied(rec):
    """etag_at_cv and data_at_cv for the record `rec` a sync just wrote: what the tables
    and files hash to with the snapshot in. Walked in the threadpool after the commit,
    where it stalled the hub for 0.4 s at 10k VMs inside the transaction. The hashes
    stand for what the sync left only when the mark of the record still holds after the
    walk (the count never goes back); a write since the commit leaves the record
    without them, and the next sync compares row by row. Returns True when they were
    noted. Never raises."""
    def look():
        walked = _walk_snapshot(body=False)
        return walked[0], walked[4], _change_mark()
    try:
        etag, data, after = _in_pool(look)
        if after != rec['mark']:
            return False
        with _lock:
            st = _load()
            if st['role'] != ROLE_STANDBY or _cv_record(st) != rec:
                return False
            _commit_locked(dict(st, cv=dict(rec, etag_at_cv=etag, data_at_cv=data)))
        return True
    except Exception as e:
        logging.warning(f"[HA] could not hash what the sync left here: {e}")
        return False


def _orphan_files():
    """(name, bytes) of every copy kept here, newest first."""
    try:
        names = os.listdir(ORPHANS_DIR)
    except OSError:
        return []
    out = []
    for fn in names:
        name = fn[:-len(ORPHAN_SUFFIX)] if fn.endswith(ORPHAN_SUFFIX) else ''
        if not _ORPHAN_NAME_RE.fullmatch(name):
            continue
        try:
            out.append((name, os.path.getsize(os.path.join(ORPHANS_DIR, fn))))
        except OSError:
            continue
    # the third part of the name is the time
    out.sort(key=lambda nb: (nb[0].split('-')[2], nb[0]), reverse=True)
    return out


def orphan_count():
    """How many copies wait for an admin to look at them. Counted once and after every
    change, the banner asks with each page."""
    if _orphans['count'] is None:
        _orphans['count'] = len(_orphan_files())
    return _orphans['count']


def _older_keys():
    """{fingerprint: file name} of the field keys this instance held before the one it
    uses now: what a key rotation (.backup.) and a join (.pre-ha.) leave next to the
    key file."""
    folder, base = os.path.dirname(AES_KEY_FILE) or '.', os.path.basename(AES_KEY_FILE)
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return {}
    out = {}
    for fn in names:
        if not fn.startswith((base + '.backup.', base + '.pre-ha.')):
            continue
        try:
            with open(os.path.join(folder, fn), 'rb') as fh:
                key = fh.read(64)
        except OSError:
            continue
        if len(key) == 32:
            out.setdefault(key_fingerprint(key), fn)
    return out


def orphan_captures(limit=50):
    """The copies of what this instance held and a snapshot did not carry over, newest
    first, `limit` at most: name, size and what the meta file next to each says. A copy
    names two keys.

    seal is the key the copy itself is sealed under: under says which kind ('master', a
    key derived from the master key of the key store, as with SQLCipher; 'field', the
    field key, as on plain SQLite), fp its fingerprint, current whether this instance
    seals under that very key now, backup the file that still holds a field key from
    before a rotation or a join, and opens whether this instance has the key at all. A
    copy under another master key (the key store changed, the copy came from another
    host) has current and opens False: it does not open here.

    key is the field key the sealed values inside the copy are under, as they were in
    the database: its fingerprint (fp), whether that is the field key in use (current)
    and, once the key was rotated or replaced by a join, the file next to the key file
    that still holds it (backup, None when there is none: those values no longer
    decrypt).

    Either is None for a copy that does not name that key. repeats and last_at say how
    often, and when last, a sync took the same rows away again without a second copy."""
    files = _orphan_files()[:limit]
    if not files:
        return []
    out, older = [], []
    kind_now, seal_now = _copy_key_now()
    field_now = key_fingerprint()

    def backup(fp):
        if not older:
            older.append(_older_keys())
        return older[0].get(fp)
    for name, size in files:
        meta = _orphan_meta(name) or {}
        key, fp = None, meta.get('key_fp')
        if isinstance(fp, str) and fp:
            key = {'fp': fp, 'current': fp == field_now,
                   'backup': None if fp == field_now else backup(fp)}
        # a copy from before the two keys had names is sealed under its field key
        under, sfp = meta.get('seal') or 'field', meta.get('seal_fp') or fp
        seal = None
        if isinstance(sfp, str) and sfp and under == 'master':
            mine = (kind_now, seal_now) == ('master', sfp)
            seal = {'under': 'master', 'fp': sfp, 'current': mine, 'backup': None, 'opens': mine}
        elif isinstance(sfp, str) and sfp and under == 'field':
            held = sfp == field_now
            kept = None if held else backup(sfp)
            seal = {'under': 'field', 'fp': sfp, 'current': held and kind_now == 'field',
                    'backup': kept, 'opens': held or bool(kept)}
        repeats = meta.get('repeats')
        out.append({'name': name, 'bytes': size, 'captured_at': meta.get('captured_at'),
                    'reason': meta.get('reason'), 'cv': meta.get('cv'),
                    'replaced_by': meta.get('replaced_by'), 'differences': meta.get('differences'),
                    'journal_rows': meta.get('journal_rows'), 'key': key, 'seal': seal,
                    'repeats': repeats if isinstance(repeats, int) else 0,
                    'last_at': meta.get('last_at')})
    return out


def orphan_path(name):
    """The file of the copy `name`, None for anything that is not one."""
    if not isinstance(name, str) or not _ORPHAN_NAME_RE.fullmatch(name):
        return None
    path = os.path.join(ORPHANS_DIR, name + ORPHAN_SUFFIX)
    return path if os.path.isfile(path) else None


def dismiss_orphan(name, by):
    """An admin has looked at the copy `name`: it goes, the only way one ever does.
    Returns True when it was there.

    Before a sync or after it, never inside one: between its look at what is here and
    its wipe, a sync counts on the copies it found (_kept_already). So this waits for
    the pull lock, DISMISS_WAIT seconds at most, and raises SyncRunning when a sync
    holds it for longer (its source does not answer, or the configuration is large).
    Nothing else is held while it waits, and only the files go under the lock."""
    if not orphan_path(name):
        return False
    if not _pull_lock.acquire(timeout=DISMISS_WAIT):
        raise SyncRunning('A sync is running right now - the copy is still here, try again '
                          'in a moment')
    try:
        path = orphan_path(name)
        if not path:
            return False
        for p in (path, os.path.join(ORPHANS_DIR, name + '.meta.json')):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
        _fsync_dir(path)
        _orphans['count'] = None
    finally:
        _pull_lock.release()
    _audit('ha.changes_dismissed', f'{by} dismissed {name}, a copy of changes not carried over')
    _check_orphan_space()
    return True


def _orphans_over(total):
    try:
        vfs = os.statvfs(ORPHANS_DIR if os.path.isdir(ORPHANS_DIR) else os.path.dirname(ORPHANS_DIR))
        free = vfs.f_bavail * vfs.f_frsize
    except (OSError, ValueError):
        free = None
    return total > ORPHANS_ALERT_BYTES or (free is not None and total > ORPHANS_ALERT_SHARE * free)


def orphans_summary():
    """The copies for the status. seal says what a copy kept now is sealed under (under,
    fp as on an item), None when this instance has no key for one: held against the
    seal of a copy that does not open here, it tells which instance does open it."""
    files = _orphan_files()
    total = sum(size for _name, size in files)
    under, fp = _copy_key_now()
    return {'count': len(files), 'bytes': total, 'over_limit': _orphans_over(total),
            'seal': {'under': under, 'fp': fp} if under else None,
            'items': orphan_captures()}


def _check_orphan_space():
    """Said once each time the copies pass ORPHANS_ALERT_BYTES or ORPHANS_ALERT_SHARE of
    the free space. Nothing is deleted for it."""
    files = _orphan_files()
    total = sum(size for _name, size in files)
    over = _orphans_over(total)
    if over and not _orphans['over_said']:
        logging.error(f"[HA] {len(files)} copies of changes not carried over take "
                      f"{total // 1024} KiB in {ORPHANS_DIR} - review and dismiss them")
        _audit('ha.orphans_space', f'{len(files)} copies of changes not carried over take '
                                   f'{total} bytes - review and dismiss them')
    _orphans['over_said'] = over


# The change journal, a LOCAL table: who wrote what on the active, and the cv that
# first carried it. It goes into the copy a member keeps of what a snapshot did not
# carry over, so the rows in there have a name and a request next to them.

def note_write(user, method, path, via=''):
    """The active, after a write request went through (app.py, next to nudge_members):
    one line of the change journal. It waits in memory and goes into the database
    JOURNAL_DELAY seconds later with the lines that came meanwhile, so no write pays a
    commit for it; a process killed in between loses those lines, never the rows they
    are about. Returns True when it took the line. Never raises."""
    try:
        st = _load()
        if st['role'] != ROLE_ACTIVE or not st.get('members'):
            return False
        line = (_now(), str(user or '')[:128], str(method or '')[:8], str(path or '')[:512],
                str(via or '')[:256])
        with _journal_lock:
            pending = _journal['pending']
            if len(pending) >= JOURNAL_PENDING_MAX:
                # the database has not taken them for a while: the oldest go, counted
                del pending[0]
                _journal['dropped'] += 1
            pending.append(line)
            due, _journal['due'] = _journal['due'], True
        if not due:
            try:
                _journal_later()
            except Exception:
                # the next note to the members flushes as well
                with _journal_lock:
                    _journal['due'] = False
        return True
    except Exception:
        return False


def _journal_later():
    _later(JOURNAL_DELAY, _journal_run, 'ha-journal')


def _journal_run():
    with _journal_lock:
        _journal['due'] = False
    flush_journal()


def _journal_table(cur):
    cur.execute('CREATE TABLE IF NOT EXISTS ha_change_journal (id INTEGER PRIMARY KEY AUTOINCREMENT, '
                'at TEXT NOT NULL, user TEXT, method TEXT, path TEXT, via TEXT, cv TEXT)')


def journal_mark():
    """The id of the last journal line in the database: lines up to it were written
    before a walk that starts now, so their changes are in it. Read from the table once
    per process, for the lines a restart left without a cv."""
    with _journal_lock:
        last = _journal['last_id']
    if last is None:
        try:
            from pegaprox.core.db import get_db
            last = get_db().conn.execute('SELECT MAX(id) FROM ha_change_journal').fetchone()[0] or 0
        except Exception:
            last = 0
        with _journal_lock:
            if _journal['last_id'] is None:
                _journal['last_id'] = last
            last = _journal['last_id']
    return last


def flush_journal():
    """The journal lines that wait, into the database in one transaction; the last
    JOURNAL_KEEP stay. Returns how many went in. Never raises: lines that could not be
    written wait for the next flush."""
    with _journal_lock:
        lines, _journal['pending'] = _journal['pending'], []
        dropped, _journal['dropped'] = _journal['dropped'], 0
    if dropped:
        logging.warning(f"[HA] {dropped} line(s) of the change journal were dropped")
    if not lines:
        return 0
    conn = None
    try:
        from pegaprox.core.db import get_db
        conn = get_db().conn
        cur = conn.cursor()
        _journal_table(cur)
        cur.executemany('INSERT INTO ha_change_journal (at, user, method, path, via) '
                        'VALUES (?, ?, ?, ?, ?)', lines)
        last = cur.execute('SELECT MAX(id) FROM ha_change_journal').fetchone()[0] or 0
        cur.execute('DELETE FROM ha_change_journal WHERE id <= ?', (last - JOURNAL_KEEP,))
        conn.commit()
    except Exception as e:
        try:
            if conn is not None:
                conn.rollback()
        except Exception:
            pass
        with _journal_lock:
            _journal['pending'][:0] = lines
            del _journal['pending'][:-JOURNAL_PENDING_MAX]
        logging.warning(f"[HA] could not write the change journal: {e}")
        return 0
    with _journal_lock:
        _journal['last_id'] = max(_journal['last_id'] or 0, last)
    return len(lines)


def _fill_journal(entry, upto):
    """The cv `entry` on the journal lines up to the id `upto` that have none yet.
    Never raises."""
    with _journal_lock:
        if upto <= _journal['filled_to']:
            return
    conn = None
    try:
        from pegaprox.core.db import get_db
        conn = get_db().conn
        conn.execute('UPDATE ha_change_journal SET cv = ? WHERE cv IS NULL AND id <= ?',
                     (json.dumps(entry), upto))
        conn.commit()
    except Exception as e:
        try:
            if conn is not None:
                conn.rollback()
        except Exception:
            pass
        logging.warning(f"[HA] could not note the config version in the change journal: {e}")
        return
    with _journal_lock:
        _journal['filled_to'] = max(_journal['filled_to'], upto)


def _journal_not_in(lineage):
    """The journal lines whose change the history `lineage` does not carry, or that have
    no cv yet, oldest first, the ones still waiting in memory at the end. Only reads:
    it runs inside the apply's transaction as well."""
    try:
        from pegaprox.core.db import get_db
        rows = get_db().conn.execute('SELECT id, at, user, method, path, via, cv FROM '
                                     'ha_change_journal ORDER BY id').fetchall()
    except Exception:
        # no journal was ever written here
        rows = []
    out = []
    for r in rows:
        try:
            cv = _one_cv(json.loads(r[6])) if r[6] else None
        except ValueError:
            cv = None
        if cv is None or not lineage or not _covered(cv, lineage):
            out.append({'id': r[0], 'at': r[1], 'user': r[2], 'method': r[3], 'path': r[4],
                        'via': r[5], 'cv': cv})
    with _journal_lock:
        waiting = list(_journal['pending'])
    out.extend({'id': None, 'at': at, 'user': user, 'method': method, 'path': path, 'via': via,
                'cv': None} for at, user, method, path, via in waiting)
    return out


# The tick. Triggers on the shared tables count every change into ha_cv_dirty, an UPDATE
# only when a column outside VOLATILE_COLUMNS took another value; the tick reads the
# count and walks only when it moved, or when a file the snapshot carries did.

def _change_triggers(cur):
    """{trigger name: statement} for every shared table there is."""
    bump = 'BEGIN UPDATE ha_cv_dirty SET n = n + 1 WHERE id = 1; END'
    out = {}
    present = _existing_tables(cur)
    for name in SYNC_TABLES:
        if name not in present:
            continue
        cur.execute(f'PRAGMA table_info("{name}")')
        masked = {c.lower() for c in VOLATILE_COLUMNS.get(name, ())}
        # every column, whatever its name: the count is what says a member is in step
        watched = ['"' + r[1].replace('"', '""') + '"' for r in cur.fetchall()
                   if r[1].lower() not in masked]
        when = ' OR '.join(f'NEW.{c} IS NOT OLD.{c}' for c in watched) or '0'
        for kind, event, cond in (('i', 'INSERT', ''), ('d', 'DELETE', ''),
                                  ('u', 'UPDATE', f' WHEN {when}')):
            trig = f'{TRIGGER_PREFIX}{name}_{kind}'
            out[trig] = f'CREATE TRIGGER "{trig}" AFTER {event} ON "{name}"{cond} {bump}'
    return out


def _make_change_triggers(cur):
    """The counter and its triggers, on the cursor of whoever calls and inside its
    transaction: made where they are missing, made again where a rebuilt table or a new
    column left one stale, dropped from a table that is no longer shared. Returns how
    many it made."""
    cur.execute('CREATE TABLE IF NOT EXISTS ha_cv_dirty (id INTEGER PRIMARY KEY '
                'CHECK (id = 1), n INTEGER NOT NULL DEFAULT 0)')
    cur.execute('INSERT OR IGNORE INTO ha_cv_dirty (id, n) VALUES (1, 0)')
    want = _change_triggers(cur)
    cur.execute("SELECT name, sql FROM sqlite_master WHERE type = 'trigger'")
    have = {n: s for n, s in cur.fetchall() if _TRIGGER_NAME_RE.fullmatch(str(n))}
    made = 0
    for trig in sorted(set(have) - set(want)):
        cur.execute(f'DROP TRIGGER IF EXISTS "{trig}"')
    for trig, sql in want.items():
        if have.get(trig) == sql:
            continue
        if trig in have:
            cur.execute(f'DROP TRIGGER IF EXISTS "{trig}"')
        cur.execute(sql)
        made += 1
    return made


def ensure_change_triggers():
    """The tick's counter and its triggers, looked over in a transaction of its own
    (_make_change_triggers). Returns how many it made."""
    from pegaprox.core.db import get_db
    conn = get_db().conn
    try:
        made = _make_change_triggers(conn.cursor())
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return made


def _drop_change_triggers(cur, sent):
    """Inside the apply's transaction, before the rows of the sync go in: the triggers
    would fire for every row it deletes and inserts (0.4 s more on a full apply at 10k
    VMs), and count what is no change made here. The apply makes them again once the
    rows are in: on a member they say whether anything was written between two syncs
    (_change_mark). A table that holds no row here and gets none from `sent`, the
    tables of the snapshot, keeps its own: nothing fires there, and a trigger takes
    0.3 ms to drop and make again."""
    cur.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
    have = {str(r[0]) for r in cur.fetchall() if _TRIGGER_NAME_RE.fullmatch(str(r[0]))}
    if not have:
        return
    present, gone = _existing_tables(cur), []
    for name in SYNC_TABLES:
        own = [trig for trig in (f'{TRIGGER_PREFIX}{name}_{kind}' for kind in 'idu') if trig in have]
        if not own or name not in present:
            continue
        t = sent.get(name)
        if ((isinstance(t, dict) and t.get('rows'))
                or cur.execute(f'SELECT 1 FROM "{name}" LIMIT 1').fetchone()):
            gone += own
    for trig in gone:
        cur.execute(f'DROP TRIGGER IF EXISTS "{trig}"')
    if gone:
        _tick.update(seen=None, checked=None, schema=None)


def _dirty_count():
    from pegaprox.core.db import get_db
    row = get_db().conn.execute('SELECT n FROM ha_cv_dirty WHERE id = 1').fetchone()
    return int(row[0]) if row else None


def _schema_version():
    """SQLite's count of changes to the schema: it moves with every table, column or
    trigger made or dropped, by whichever connection."""
    from pegaprox.core.db import get_db
    return get_db().conn.execute('PRAGMA schema_version').fetchone()[0]


def _files_mark():
    """Size and time of every file a snapshot carries: no trigger sees those."""
    paths = [KNOWN_HOSTS_FILE]
    for folder, leaf in ((BRANDING_DIR, None), (PLUGINS_DIR, 'config.json')):
        try:
            names = sorted(os.listdir(folder))
        except OSError:
            continue
        paths += [os.path.join(folder, fn, leaf) if leaf else os.path.join(folder, fn) for fn in names]
    out = []
    for path in paths:
        try:
            st = os.stat(path)
        except OSError:
            continue
        out.append((path, st.st_size, st.st_mtime_ns))
    return tuple(out)


def cv_tick(force=False):
    """The leader of an automatic group, every CV_TICK seconds: one step of cv when the
    shared tables or files changed since its last walk, and a note to the members, so a
    change the automation makes goes out within seconds as well. It walks only when the
    count of the triggers or a file moved, once after it made a trigger, and every time
    while the count cannot be read. Returns 'idle' (not an active with members),
    'clean', 'same' or 'stepped'.

    The lease loop calls it once automatic mode is in (S3). A manual group goes without:
    there the cv steps when a snapshot, a poll or a note to the members goes out."""
    st = _load()
    if st['role'] != ROLE_ACTIVE or not st.get('members'):
        return 'idle'
    seen, made = None, 0
    try:
        now = time.monotonic()
        if (force or _tick['checked'] is None or now - _tick['checked'] >= TRIGGER_CHECK
                or _schema_version() != _tick['schema']):
            # A table or a column the code makes on first use (api_tokens, pegaprox_kv,
            # custom_scripts.deleted_at) has no trigger until this look, and what was
            # written there before it was not counted. The schema version says so at
            # the next tick; a trigger made here is one walk whatever the count says.
            made = ensure_change_triggers()
            _tick.update(checked=now, schema=_schema_version())
        n = _dirty_count()
        seen = (n, _files_mark()) if n is not None else None
    except Exception as e:
        logging.warning(f"[HA] cannot read the change count of the config version, walking "
                        f"on every tick: {e}")
    if not force and not made and seen is not None and seen == _tick['seen']:
        return 'clean'
    flush_journal()
    before = cv_entry()
    from pegaprox.api.ha import current_etag
    current_etag()
    _tick['seen'] = seen
    if cv_entry() == before:
        return 'same'
    nudge_members()
    return 'stepped'


# The change gap: what an instance that takes the lead knows it does not have.

def note_leader_cv(member_id, cv, at=None):
    """A standby, when the member it pulls from says which cv it is at (with its note
    about a change): kept on that member's record, for the change gap should this
    instance take the lead before it has pulled that far. Returns True when it was
    news. Never raises."""
    try:
        entry, rec = _one_cv(cv), member(member_id)
        if entry is None or rec is None or not _newer_cv(rec.get('cv_seen'), entry):
            return False
        _note_members({member_id: {'cv_seen': entry,
                                   'cv_seen_at': at[:40] if isinstance(at, str) else None}})
        return True
    except Exception as e:
        logging.warning(f"[HA] could not note the config version of member {member_id}: {e}")
        return False


def change_gap(mine, heard, heard_at=None):
    """`heard`, the newest cv another member reported, against `mine`, the history held
    here. None when that much is here, or nothing usable was heard. from and count are
    None when the changes sit on another line of history and cannot be counted."""
    seen = _one_cv(heard)
    if seen is None or _covered(seen, mine):
        return None
    match = next((h for h in mine if h[0] == seen[0] and h[2] == seen[2]), None)
    return {'epoch': seen[0], 'from': match[1] + 1 if match else None, 'to': seen[1],
            'count': seen[1] - match[1] if match else None, 'by': seen[3],
            'until': heard_at[:40] if isinstance(heard_at, str) else None}


def _gap_at_promotion(st):
    """promote(): the change gap against the newest cv any member reported (cv_seen on
    its record, from the watch and from the active's notes). None for none."""
    best = None
    for mid, rec in sorted((st.get('members') or {}).items()):
        seen = _one_cv(rec.get('cv_seen'))
        if seen and (best is None or seen[:2] > best[0][:2]):
            best = (seen, rec.get('cv_seen_at'), mid)
    if best is None:
        return None
    gap = change_gap(_hist_of(_cv_record(st)), best[0], best[1])
    if gap:
        gap.update(member=best[2], noted_at=_now())
    return gap


def _say_change_gap(gap):
    what = (f"changes {gap['epoch']}.{gap['from']} to {gap['epoch']}.{gap['to']}" if gap.get('count')
            else f"changes up to {gap['epoch']}.{gap['to']}")
    until = f" until {gap['until']}" if gap.get('until') else ''
    text = f"{what}, made on {gap['by'][:8]}{until}, are not on this instance"
    logging.warning(f"[HA] took the lead without them: {text}")
    _audit('ha.change_gap', text)


# --- talking to the other members ----------------------------------------------

def _new_session(fingerprint):
    import requests
    sess = requests.Session()
    if fingerprint:
        from pegaprox.core.pbs import _PinnedFingerprintAdapter
        sess.mount('https://', _PinnedFingerprintAdapter(fingerprint))
    return sess


# F9: one pinned session per member address for the calls that come every few seconds,
# so they ride on a kept-alive connection instead of a TLS handshake each. {base url:
# (fingerprint, session)}; a new pin or address gets a new session.
_sessions_lock = threading.Lock()
_kept_sessions = {}
_MAX_KEPT_SESSIONS = 2 * MAX_MEMBERS


def _kept_session(base_url, fingerprint):
    key = base_url.rstrip('/')
    gone = []
    with _sessions_lock:
        held = _kept_sessions.pop(key, None)
        if held and held[0] == fingerprint:
            _kept_sessions[key] = held
            return held[1]
        if held:
            gone.append(held[1])
        sess = _new_session(fingerprint)
        _lean_session(sess, key, fingerprint)
        _kept_sessions[key] = (fingerprint, sess)
        # a member that moved leaves its old address behind
        while len(_kept_sessions) > _MAX_KEPT_SESSIONS:
            gone.append(_kept_sessions.pop(next(iter(_kept_sessions)))[1])
    for old in gone:
        _close_kept(old)
    return sess


# MK Oct 2026 (#625) - an automatic leader renews before every write, so a lease call has
# to be cheap. Through requests one cost this kind of host about 1.4 ms of CPU (the
# environment read for proxies and a CA bundle, settings, cookies and hooks merged, every
# header checked, the answer's headers parsed by the email module), more than the round
# trip on a LAN. A kept session therefore carries a link of its own (_LeaseLink):
# kept-alive TLS connections, pinned to the member's fingerprint as the session's adapter
# pins them or checked against the CA bundle requests would use, one write per call and
# a small parser for the answer. The environment is read once, when the session is made;
# where a proxy applies, or the pin is not a SHA-256 one, the calls take the session as
# before. The link keeps as many connections as a member can have calls out from the
# confirm rounds, so none of them waits for a TLS handshake.
_KEPT_POOL = ha_vote.CONFIRM_PER_VOTER + 4
_KEPT_ANSWER_MAX = 4 * 1024 * 1024
_KEPT_HEAD_MAX = 64 * 1024
_PIN_HEX_RE = re.compile(r'[0-9a-f]{64}')
_STATUS_RE = re.compile(r'[1-5][0-9]{2}')
_LENGTH_RE = re.compile(r'[0-9]{1,9}')
_CHUNK_RE = re.compile(rb'[0-9a-fA-F]{1,8}')
_HEAD_BREAK_RE = re.compile(r'[\r\n\x00]')


class _KeptAnswer:
    """What _peer_call hands back for a call that went over a link: the part of a
    requests.Response its callers read."""

    def __init__(self, status, content, headers):
        self.status_code, self.content, self.headers = status, content, headers

    def json(self):
        return json.loads(self.content)


class _AnswerHeaders(dict):
    """The headers of an answer over a link, by lower-case name; get() takes any case."""

    def get(self, name, default=None):
        return dict.get(self, name.lower(), default)


class _LeaseLink:
    """Kept-alive TLS connections to one member, for the calls of its kept session."""

    def __init__(self, url, ctx, pin):
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        self.host, self.port, self.netloc = parts.hostname, parts.port or 443, parts.netloc
        self.prefix = parts.path.rstrip('/')
        self.ctx, self.pin = ctx, pin
        self.idle = []
        self.lock = threading.Lock()
        self.closed = False

    def _connect(self, timeout):
        import socket
        import ssl
        raw = socket.create_connection((self.host, self.port), timeout=timeout)
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock = self.ctx.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise
        if self.pin and not hmac.compare_digest(
                hashlib.sha256(sock.getpeercert(binary_form=True) or b'').hexdigest(), self.pin):
            sock.close()
            raise ssl.SSLError('the certificate does not match the pinned fingerprint')
        return sock

    def _take(self):
        import select
        while True:
            with self.lock:
                if not self.idle:
                    return None
                sock = self.idle.pop()
            try:
                # one the member closed while it sat here reads as readable (EOF)
                stale = bool(select.select([sock], [], [], 0)[0])
            except (OSError, ValueError):
                stale = True
            if not stale:
                return sock
            sock.close()

    def _give(self, sock):
        with self.lock:
            if not self.closed and len(self.idle) < _KEPT_POOL:
                self.idle.append(sock)
                return
        sock.close()

    def close(self):
        with self.lock:
            self.closed = True
            idle, self.idle = self.idle, []
        for sock in idle:
            try:
                sock.close()
            except OSError:
                pass

    def post(self, method, target, body, headers, timeout):
        """(status, headers, body) of one call. Raises PeerUnreachable while the call is
        not out yet, PeerNoAnswer once it is."""
        import ssl
        lines = [f'{method} {target} HTTP/1.1', f'Host: {self.netloc}', f'Content-Length: {len(body)}']
        lines += [f'{k}: {v}' for k, v in headers.items()]
        if _HEAD_BREAK_RE.search(''.join(lines)):
            raise HaError('A peer call header carries a line break')
        data = ('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1') + body
        deadline = time.monotonic() + timeout
        sock, sent = self._take(), False
        try:
            if sock is None:
                sock = self._connect(timeout)
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            sock.sendall(data)
            sent = True
            status, hdrs, content, keep = self._answer(sock, deadline)
        except Exception as e:
            if sock is not None:
                sock.close()
            if sent:
                raise PeerNoAnswer(f'The peer took the call but sent no answer: {type(e).__name__}')
            if isinstance(e, ssl.SSLError):
                raise PeerUnreachable(
                    f'The peer certificate does not match the pinned fingerprint ({type(e).__name__})'
                    if self.pin else 'The peer certificate is not trusted by a CA, and no fingerprint '
                    f'is pinned for it ({type(e).__name__})')
            raise PeerUnreachable(f'Cannot reach the peer: {type(e).__name__}')
        if keep:
            self._give(sock)
        else:
            sock.close()
        return status, hdrs, content

    @staticmethod
    def _recv(sock, deadline, eof_ok=False):
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('no answer in time')
        sock.settimeout(left)
        chunk = sock.recv(65536)
        if not chunk and not eof_ok:
            raise ConnectionError('closed before the answer was complete')
        return chunk

    def _answer(self, sock, deadline):
        buf = b''
        while b'\r\n\r\n' not in buf:
            if len(buf) > _KEPT_HEAD_MAX:
                raise ValueError('answer head too long')
            buf += self._recv(sock, deadline)
        top, _, rest = buf.partition(b'\r\n\r\n')
        lines = top.decode('latin-1').split('\r\n')
        parts = lines[0].split(' ', 2)
        if len(parts) < 2 or parts[0] not in ('HTTP/1.1', 'HTTP/1.0') or not _STATUS_RE.fullmatch(parts[1]):
            raise ValueError('not an HTTP answer')
        status = int(parts[1])
        if status < 200:
            # this link sends no Expect, so an honest member never answers with an interim
            # head; the final one would be left on the socket for the next call to read
            raise ValueError('interim answer')
        hdrs = _AnswerHeaders()
        for line in lines[1:]:
            k, sep, v = line.partition(':')
            if not sep:
                raise ValueError('broken header line')
            hdrs[k.strip().lower()] = v.strip()
        keep = parts[0] == 'HTTP/1.1' and hdrs.get('connection', '').lower() != 'close'
        coding = hdrs.get('transfer-encoding', '').lower()
        if status in (204, 304):
            content = b''
        elif coding:
            if coding != 'chunked':
                raise ValueError('unknown transfer encoding')
            content, rest = self._chunks(sock, rest, deadline)
        elif 'content-length' in hdrs:
            if not _LENGTH_RE.fullmatch(hdrs['content-length']):
                raise ValueError('broken content length')
            n = int(hdrs['content-length'])
            if n > _KEPT_ANSWER_MAX:
                raise ValueError('answer too large')
            while len(rest) < n:
                rest += self._recv(sock, deadline)
            content, rest = rest[:n], rest[n:]
        else:
            # no length: the answer ends where the member closes
            keep = False
            while True:
                chunk = self._recv(sock, deadline, eof_ok=True)
                if not chunk:
                    break
                rest += chunk
                if len(rest) > _KEPT_ANSWER_MAX:
                    raise ValueError('answer too large')
            content, rest = rest, b''
        # bytes after the answer: whatever comes next on this connection cannot be matched
        return status, hdrs, content, keep and not rest

    def _chunks(self, sock, rest, deadline):
        out = bytearray()
        while True:
            while b'\r\n' not in rest:
                if len(rest) > _KEPT_HEAD_MAX:
                    raise ValueError('chunk head too long')
                rest += self._recv(sock, deadline)
            line, _, rest = rest.partition(b'\r\n')
            size_text = line.split(b';')[0].strip()
            if not _CHUNK_RE.fullmatch(size_text):
                raise ValueError('broken chunk size')
            size = int(size_text, 16)
            if size == 0:
                while True:
                    while b'\r\n' not in rest:
                        if len(rest) > _KEPT_HEAD_MAX:
                            raise ValueError('trailer too long')
                        rest += self._recv(sock, deadline)
                    line, _, rest = rest.partition(b'\r\n')
                    if not line:
                        return bytes(out), rest
            if len(out) + size > _KEPT_ANSWER_MAX:
                raise ValueError('answer too large')
            while len(rest) < size + 2:
                rest += self._recv(sock, deadline)
            if rest[size:size + 2] != b'\r\n':
                raise ValueError('broken chunk')
            out += rest[:size]
            rest = rest[size + 2:]


def _lean_session(sess, url, fingerprint):
    """Give a kept session its link (_LeaseLink), where it can have one."""
    import requests
    import ssl
    if not isinstance(sess, requests.Session):
        return
    pin = (fingerprint or '').replace(':', '').lower()
    if pin and not _PIN_HEX_RE.fullmatch(pin):
        return
    env = sess.merge_environment_settings(url, {}, None, not pin, None)
    if env.get('proxies'):
        return
    if pin:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        verify = env.get('verify')
        if not isinstance(verify, str):
            from requests.utils import DEFAULT_CA_BUNDLE_PATH
            verify = DEFAULT_CA_BUNDLE_PATH
        ctx = (ssl.create_default_context(capath=verify) if os.path.isdir(verify)
               else ssl.create_default_context(cafile=verify))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    sess.pegaprox_lean = _LeaseLink(url, ctx, pin)


def _kept_send(sess, method, path, body, headers, timeout):
    """The call over the kept session's link, None where it takes the session."""
    link = getattr(sess, 'pegaprox_lean', None)
    if link is None:
        return None
    status, hdrs, content = link.post(method, link.prefix + path, body or b'', headers, timeout)
    return _KeptAnswer(status, content, hdrs)


def _close_kept(sess):
    link = getattr(sess, 'pegaprox_lean', None)
    if link is not None:
        link.close()
    sess.close()


def drop_kept_session(base_url, sess=None):
    """Close the kept session for `base_url` (only if it is still `sess`, when given)."""
    with _sessions_lock:
        held = _kept_sessions.get(base_url.rstrip('/'))
        if not held or (sess is not None and held[1] is not sess):
            return
        del _kept_sessions[base_url.rstrip('/')]
    _close_kept(held[1])


# the address check of the kept calls, by url: (ok, why, lease time of the check). A name
# is looked up by the check, and a lease call comes before every write of the leader; a
# connection that is up stays with the address it was opened to whatever the check says
_PEER_URL_RECHECK = 30
_peer_urls = {}


def _peer_url_ok(url, kept):
    from pegaprox.utils.url_security import is_safe_outbound_url
    now = ha_clock()
    held = _peer_urls.get(url) if kept else None
    if held is not None and 0 <= now - held[2] < _PEER_URL_RECHECK:
        return held[:2]
    ok, why = is_safe_outbound_url(url, allowed_schemes=('https',), allow_private=True)
    if kept:
        if len(_peer_urls) > 64:
            _peer_urls.clear()
        _peer_urls[url] = (ok, why, now)
    return ok, why


def _quiet_insecure_warning():
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass


def _peer_call(method, base_url, fingerprint, path, json_body=None, auth=None,
               headers=None, timeout=15, keep_alive=False):
    """One HTTPS call to another instance. `auth` is None (the pairing call) or a
    callable (method, path, body) -> headers, from _auth_for, that signs exactly the
    bytes sent here. `keep_alive` sends it on the member's kept session (F9) instead
    of one of its own."""
    import requests
    url = base_url.rstrip('/') + path
    ok, why = _peer_url_ok(url, keep_alive)
    if not ok:
        raise HaError(f'The peer address is not allowed: {why}')
    body = _wire_body(json_body)
    h = {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'}
    if body:
        h['Content-Type'] = 'application/json'
    if auth is not None:
        h.update(auth(method, path, body))
    if headers:
        h.update(headers)
    sess = _kept_session(base_url, fingerprint) if keep_alive else _new_session(fingerprint)
    verify = not fingerprint
    # answered: the session gave an answer back. unreached: the call never got out, and
    # nothing of it is left in the session (the link closed the socket that failed, the
    # pool dropped a connection that did not come up): the kept session stays, so a
    # member that refuses or drops connections costs no new session per call
    answered = unreached = False
    data = body or None
    if body and path == FORWARD_PATH:
        # The envelope of an upload is larger than what the receiving app takes with a
        # Content-Length before any route has seen the call (PEGAPROX_MAX_REQUEST_SIZE).
        # Sent in chunks, it meets the cap the forward route sets for itself instead.
        data = (body[i:i + _FORWARD_CHUNK] for i in range(0, len(body), _FORWARD_CHUNK))
    try:
        # a kept session sends over its link where it has one (_lean_session)
        resp = _kept_send(sess, method, path, body, h, timeout) if keep_alive and data is body \
            and body else None
        if resp is None:
            _quiet_insecure_warning()
            resp = sess.request(method, url, data=data, headers=h, verify=verify,
                                timeout=timeout, allow_redirects=False)
        answered = True
        return resp
    except PeerUnreachable as e:
        # from the link (_LeaseLink.post), which closed the socket that failed. One it
        # took and did not answer (PeerNoAnswer) drops the session below
        unreached = not isinstance(e, PeerNoAnswer)
        raise
    except requests.exceptions.SSLError as e:
        unreached = True
        if fingerprint:
            raise PeerUnreachable(f'The peer certificate does not match the pinned fingerprint ({type(e).__name__})')
        raise PeerUnreachable('The peer certificate is not trusted by a CA, and no fingerprint is '
                              f'pinned for it ({type(e).__name__})')
    except (requests.exceptions.ReadTimeout, requests.exceptions.ChunkedEncodingError) as e:
        raise PeerNoAnswer(f'The peer took the call but sent no answer: {type(e).__name__}')
    except requests.exceptions.ConnectionError as e:
        # connected, then dropped before an answer came: the call may have run there.
        # Refused, unresolvable or timed out while connecting: it never got there
        from urllib3.exceptions import ProtocolError
        if (not isinstance(e, requests.exceptions.ConnectTimeout) and e.args
                and isinstance(e.args[0], ProtocolError)):
            raise PeerNoAnswer(f'The peer took the call but sent no answer: {type(e).__name__}')
        unreached = True
        raise PeerUnreachable(f'Cannot reach the peer: {type(e).__name__}')
    except requests.exceptions.RequestException as e:
        unreached = True
        raise PeerUnreachable(f'Cannot reach the peer: {type(e).__name__}')
    finally:
        if not keep_alive:
            sess.close()
        elif not answered and not unreached:
            # a call that got out and broke may leave what broke in the pool: the next
            # call starts afresh
            drop_kept_session(base_url, sess)


def _peer_error(resp, fallback):
    try:
        return (resp.json() or {}).get('error') or f'{fallback} (HTTP {resp.status_code})'
    except Exception:
        return f'{fallback} (HTTP {resp.status_code})'


def _error_text(e):
    return (str(e) if isinstance(e, HaError) else f'{type(e).__name__}: {e}')[:300]


def _answer_header(resp, name):
    headers = getattr(resp, 'headers', None)
    try:
        return headers.get(name) if headers is not None else None
    except Exception:
        return None


def _note_key_acked(member_id):
    """The member holds our public key now: no more old secret towards it. Once every
    member does, the secret is dropped altogether."""
    try:
        with _lock:
            st = _load()
            ms = dict(st.get('members') or {})
            if member_id not in ms or ms[member_id].get('key_acked'):
                return
            ms[member_id] = dict(ms[member_id], key_acked=True)
            new = dict(st, members=ms)
            if st.get('member_secret') and all(r.get('key_acked') for r in ms.values()):
                new['member_secret'] = None
                logging.info("[HA] every member holds our key - the old secret is dropped")
            _commit_locked(new)
    except Exception as e:
        logging.warning(f"[HA] could not note that member {member_id} holds our key: {e}")


def call_member(rec, method, path, json_body=None, headers=None, timeout=15, signer=None):
    """One signed call to the member `rec` (a record from members()). `signer` is ours,
    read beforehand by a caller that fans out (_signer).

    A member that is not known to hold our key yet also gets the old secret and the
    key, if this instance still has a secret from before the keys. An answer of
    410 HA_REMOVED means that member removed us: we let go of the group here."""
    if not rec or not rec.get('url'):
        raise HaError('No address known for this member')
    signer = signer or _signer()
    legacy = bool(signer.secret) and not rec.get('key_acked')
    resp = _peer_call(method, rec['url'], rec.get('fingerprint') or '', path,
                      json_body=json_body, auth=_auth_for(signer, rec['instance_id'], legacy),
                      headers=headers, timeout=timeout)
    if legacy and signer.private is not None and _answer_header(resp, PEER_KEYED_HEADER) == '1':
        _note_key_acked(rec['instance_id'])
    if resp.status_code == 410:
        _removed_answer(rec, resp)
    return resp


def _fan_out(jobs, timeout):
    """Run the callables in `jobs` side by side and wait at most `timeout` seconds for
    all of them. Returns [(result, None) or (None, exception)] in the order given; a
    job still out when the time is up counts as failed, a single one as well.

    Under gevent these threads are greenlets: a call waiting on the network costs a
    socket, and a member that does not answer holds up none of the others."""
    results = [None] * len(jobs)

    def run(i, job):
        try:
            results[i] = (job(), None)
        except Exception as e:
            results[i] = (None, e)
    threads = [threading.Thread(target=run, args=(i, job), daemon=True, name='ha-member-call')
               for i, job in enumerate(jobs)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    late = HaError('The member did not answer in time')
    return [r if r is not None else (None, late) for r in list(results)]


def tell_members(method, path, json_body=None, timeout=10, only=None, note=True, answers=None):
    """The same call to every member, or to the ids in `only`, side by side.

    Returns {member id: None when it answered 200, else what went wrong}, and notes
    the failures on the member records unless `note` is False. `answers`, a dict, gets
    {member id: its JSON body} of the ones that answered 200. Never raises."""
    try:
        signer = _signer()
        targets = [m for m in members() if only is None or m['instance_id'] in only]
    except Exception as e:
        logging.warning(f"[HA] cannot call the members: {e}")
        return {mid: _error_text(e) for mid in (only or [])}
    results = _fan_out([lambda rec=rec: call_member(rec, method, path, json_body=json_body,
                                                    timeout=timeout, signer=signer)
                        for rec in targets], timeout + 5)
    out, notes = {}, {}
    for rec, (resp, err) in zip(targets, results):
        mid = rec['instance_id']
        if err is None and resp.status_code != 200:
            err = HaError(_peer_error(resp, f'The member refused {path}'))
        if err is None and answers is not None:
            try:
                body = resp.json()
            except Exception:
                body = None
            answers[mid] = body if isinstance(body, dict) else {}
        out[mid] = None if err is None else _error_text(err)
        if err is not None and note:
            notes[mid] = {'last_error': out[mid]}
    try:
        _note_members(notes)
    except Exception as e:
        logging.warning(f"[HA] could not note the member errors: {e}")
    return out


def pull_once(timeout=PULL_TIMEOUT):
    """Standby: fetch and apply one snapshot from the member it pulls from. Returns a
    short status string.

    Also where a reload of the managers that has settled goes out, should its timer
    not have come (see reload_managers): after a sync, and on the polls that find
    nothing new."""
    # one pull at a time: "sync now" and the loop would otherwise apply side by side,
    # and the file writes share their temporary names
    if not _pull_lock.acquire(timeout=timeout + 5):
        return 'busy'
    try:
        result = _pull(timeout)
    finally:
        _pull_lock.release()
    if result in ('applied', 'unchanged', 'failed'):
        _reload_if_due()
    return result


def forward_write(envelope, timeout=FORWARD_TIMEOUT):
    """Standby: hand one write to the member it pulls from, as a signed call whose body
    is `envelope` (api/ha.py forward_to_active builds it). Returns the answer; raises
    PeerUnreachable when the active cannot be reached, and PeerNoAnswer (one of those)
    when it took the call and sent nothing back: the write may have happened there.
    Until the active answers again, forwarding() is False."""
    src = peer() if is_standby() else None
    if not src:
        raise HaError('Not paired')
    try:
        resp = call_member(src, 'POST', FORWARD_PATH, json_body=envelope,
                           timeout=(FORWARD_CONNECT_TIMEOUT, timeout))
    except PeerNoAnswer:
        # it got there: the active is busy with it, or went down while at it
        raise
    except PeerUnreachable:
        _note_source_heard(src['instance_id'], False)
        raise
    _note_source_heard(src['instance_id'], True)
    return resp


_soon_lock = threading.Lock()
_soon = {'wanted': False, 'running': False}


def _in_background(fn, name):
    threading.Thread(target=fn, daemon=True, name=name).start()


def pull_soon():
    """Standby: one pull right away, in the background, after a write it forwarded went
    through or once the active said its configuration changed (/api/ha/peer/changed),
    so the change shows here without waiting for the interval. Asks that come in
    while that pull runs get one more pull after it, not one each. Returns True when
    it started a run."""
    with _soon_lock:
        _soon['wanted'] = True
        if _soon['running']:
            return False
        _soon['running'] = True
    try:
        _in_background(_pull_soon_run, 'ha-pull-soon')
    except Exception as e:
        with _soon_lock:
            _soon['running'] = False
        logging.warning(f"[HA] could not start a sync out of turn: {e}")
        return False
    return True


def _pull_soon_run():
    finished = False
    try:
        while True:
            with _soon_lock:
                if not _soon['wanted']:
                    _soon['running'] = False
                    finished = True
                    return
                _soon['wanted'] = False
            try:
                if is_standby() and peer():
                    pull_once(timeout=PULL_TIMEOUT_FLOOR)
            except Exception as e:
                logging.warning(f"[HA] a sync out of turn failed: {_error_text(e)}")
    finally:
        if not finished:
            # killed halfway: the next ask starts a run of its own
            with _soon_lock:
                _soon['running'] = False


_nudge_lock = threading.Lock()
# last: when the last note went out (monotonic), for the spacing under a run of writes
_nudge = {'due': False, 'last': None}


def nudge_members():
    """The active, after a write went through (app.py): tell every member that the
    configuration changed, and one that does not hold it yet pulls it now rather than
    at its next poll. The note goes NUDGE_DELAY seconds after the write, and no sooner
    than NUDGE_SPACING after the one before; writes until then go with the same note.
    Returns True when it set one up. Never raises: the write is done either way."""
    try:
        st = _load()
        if st['role'] != ROLE_ACTIVE or not st.get('members'):
            return False
        with _nudge_lock:
            if _nudge['due']:
                return False
            _nudge['due'] = True
            last = _nudge.get('last')
        delay = NUDGE_DELAY
        if last is not None:
            delay = max(delay, last + NUDGE_SPACING - time.monotonic())
        _later(delay, _nudge_run, 'ha-nudge')
    except Exception as e:
        with _nudge_lock:
            _nudge['due'] = False
        logging.warning(f"[HA] could not set up the note to the members about a change: {e}")
        return False
    return True


def _nudge_run():
    # cleared first: a write that comes in while the calls are out gets a call of its
    # own, its change may be newer than what the members fetch now
    with _nudge_lock:
        _nudge['due'] = False
        _nudge['last'] = time.monotonic()
    try:
        if role() != ROLE_ACTIVE:
            return
        # the journal lines of the writes this note is about, before the walk that
        # steps the cv for them
        flush_journal()
        body = None
        try:
            # once for all of them, off the hub like the etag of a poll: a write that
            # changed nothing they hold (a VM started, a test mail) costs no member a pull
            from pegaprox.api.ha import current_etag
            body = {'etag': current_etag()}
            # and where the configuration is at, for a member that takes the lead before
            # it has pulled that far (change_gap)
            body.update(peer_cv())
        except Exception as e:
            # without one every member pulls, as from a release before the etag
            logging.warning(f"[HA] could not work out the etag for the note to the members: {e}")
        # not noted on the member records: a member that misses one (down, or on a
        # release without the route) is not wrong, it pulls at its next poll
        missed = {mid: err for mid, err in tell_members(
            'POST', NUDGE_PATH, json_body=body, timeout=NUDGE_TIMEOUT, note=False).items() if err}
    except Exception as e:
        logging.warning(f"[HA] could not tell the members about a change: {e}")
        return
    for mid, err in missed.items():
        logging.info(f"[HA] member {mid} did not take the note about a change ({err}) - "
                     "it pulls at its next poll")


def holds_etag(etag):
    """Standby: whether the last sync it applied is the configuration `etag` stands for,
    as the active's note about a change names it (nudge_members). Never before the first
    pull of this process, which is a full one whatever the etag says."""
    if not _etag_checked or not isinstance(etag, str) or not etag:
        return False
    return etag == (_load().get('sync') or {}).get('etag')


def pull_before_promote(timeout=15):
    """The promote route, before this standby becomes active: one pull from the member
    it follows, so a planned failover starts from the configuration, the member list
    and the tombstones of now. Returns (True, '') when it is fine to go on: the pull
    worked, there is nothing to pull from, or the source did not answer at all (the
    failover this is for). (False, why) when the source answered and the pull failed,
    or this instance was removed meanwhile."""
    if not is_standby() or not peer():
        return True, ''
    if not _pull_lock.acquire(timeout=timeout + 5):
        return False, 'a sync is running right now - try again in a moment'
    try:
        result, answered, error = _pull_detail(timeout)
    finally:
        _pull_lock.release()
    if result in ('applied', 'unchanged', 'not paired', 'not a standby'):
        return True, ''
    if result == 'removed':
        return False, REMOVED_ERROR
    if result == 'source switched':
        rec = peer() or {}
        return False, (f"the group has an active instance, {rec.get('url') or rec.get('instance_id')}, "
                       "and this standby follows it from now on")
    if not answered:
        return True, ''
    return False, error or result


def boot_pull(timeout=BOOT_PULL_TIMEOUT):
    """main(), on a standby with the live view on, before the managers start: one
    short pull, so they start from the active's configuration of now and not from
    the one this instance stopped with. Never raises."""
    try:
        if not is_standby() or not peer():
            return 'idle'
        return pull_once(timeout=timeout)
    except Exception as e:
        logging.warning(f"[HA] pull at start failed: {e}")
        return 'error'


def _finish_pull(sid, sync, member=None):
    """The outcome of a pull in one write: the sync status and what it says about the
    source. Nothing is written when nothing changed."""
    with _lock:
        st = _load()
        new = dict(st, sync=dict(st.get('sync') or {}, **sync))
        ms = st.get('members') or {}
        if member and sid in ms:
            new['members'] = dict(ms, **{sid: dict(ms[sid], **member)})
        if new != st:
            _commit_locked(new)


def _pull(timeout):
    return _pull_detail(timeout)[0]


def _pull_detail(timeout):
    """(result, answered, error): answered is True once the source sent an HTTP answer."""
    global _etag_checked
    if not is_standby():
        return 'not a standby', False, ''
    src = peer()
    if not src:
        # nothing to pull from, and writing here would replace a state file that
        # _load could not read with a fresh one
        return 'not paired', False, ''
    sid = src['instance_id']
    with _lock:
        first, _etag_checked = not _etag_checked, True
    started = _now()
    committed = answered = False
    try:
        # the first pull after a start is a full one: an upgrade may have added
        # columns, a restored database may hold other rows, and the active's etag
        # knows about neither
        etag = None if first else (_load().get('sync') or {}).get('etag')
        headers = {'If-None-Match': etag} if etag else {}
        held = cv_entry()
        if held:
            # what this instance holds: an active whose state went back learns it from
            # the pull itself, before it hands out a number that is taken
            headers[PEER_CV_HEADER] = json.dumps(held, separators=(',', ':'))
        resp = call_member(src, 'GET', '/api/ha/peer/snapshot', headers=headers or None,
                           timeout=timeout)
        answered = True
        _note_source_heard(sid, True)
        if resp.status_code == 304:
            now = _now()
            _finish_pull(sid, {'last_attempt_at': started, 'last_ok_at': now, 'last_error': ''},
                         {'last_contact': now, 'last_error': ''})
            return 'unchanged', True, ''
        if resp.status_code == 410 and _load().get('removed'):
            return 'removed', True, REMOVED_ERROR
        if resp.status_code == 409:
            switched = _take_follow_hint(src, resp, timeout)
            if switched:
                return switched, True, ''
        if resp.status_code != 200:
            raise HaError(_peer_error(resp, 'The active instance refused the snapshot'))
        snap = resp.json()
        seen = {'last_contact': _now(), 'role_seen': snap.get('role'),
                'epoch_seen': int(snap.get('epoch') or 0), 'last_error': ''}
        if snap.get('group') == GROUP_MARK:
            seen['group_seen'] = True
        summary = apply_snapshot(snap)
        committed = True
        problems = summary.get('file_errors') or []
        # an etag stands for all of the content; with columns left out or a file not
        # written we hold less than that, and a 304 would keep it so (after an
        # upgrade, or once the file can be written again)
        etag = None if summary['skipped_columns'] or problems else snap.get('etag')
        owed = summary.get('tombstones_owed') or []
        if owed and not _hand_back_tombstones(src, owed):
            # the next pull is a full one and finds them again
            etag = None
        note = ('The configuration was applied, but ' + '; '.join(problems)) if problems else ''
        _finish_pull(sid, {'last_attempt_at': started, 'last_ok_at': _now(), 'last_error': note[:300],
                           'etag': etag, 'source_epoch': int(snap.get('epoch') or 0),
                           'rows': summary['rows'], 'tables': summary['tables'],
                           'skipped_columns': summary['skipped_columns']}, seen)
        return 'applied', True, ''
    except Exception as e:
        msg = _error_text(e)
        if not answered and isinstance(e, PeerUnreachable):
            _note_source_heard(sid, False)
        try:
            _finish_pull(sid, dict({'last_attempt_at': started, 'last_error': msg},
                                   **({'etag': None} if first else {})))
        except Exception as e2:
            logging.warning(f"[HA] could not note the failed sync: {e2}")
        logging.warning(f"[HA] sync failed: {msg}")
        return 'failed', answered, msg
    finally:
        # the database holds the new rows now, whatever failed after the commit: the
        # managers are compared against them, or a new connection setting would never
        # restart anything while that failure lasts
        if committed:
            _after_sync_applied()
            _follow_plugin_state()


def _hand_back_tombstones(src, owed):
    """Tell the active we pull from about the members it lists and we hold tombstones
    for (_tombstones_owed). True once it has heard, whether it took them or not."""
    try:
        resp = call_member(src, 'POST', '/api/ha/peer/tombstones', json_body={'tombstones': owed},
                           timeout=10)
    except Exception as e:
        logging.warning(f"[HA] could not hand the tombstones back to {src.get('url')}: {_error_text(e)}")
        return False
    if resp.status_code != 200:
        logging.warning(f"[HA] {src.get('url')} did not take the tombstones: "
                        f"{_peer_error(resp, 'refused')}")
        return False
    return True


def follow_hint():
    """What a standby tells a member that asks it for a snapshot: the member it follows,
    as that member is to be reached and checked. None when it follows nobody it has
    seen active."""
    st = _load()
    if st['role'] != ROLE_STANDBY or st.get('removed'):
        return None
    sid = st.get('source')
    rec = (st.get('members') or {}).get(sid)
    if not rec or rec.get('role_seen') != ROLE_ACTIVE or not rec.get('public_key') or not rec.get('url'):
        return None
    return {'instance_id': sid, 'url': rec['url'], 'fingerprint': rec.get('fingerprint') or '',
            'public_key': rec['public_key'],
            'epoch': max(int(st.get('epoch') or 0), int(rec.get('epoch_seen') or 0))}


def _take_follow_hint(src, resp, timeout):
    """The member we pull from is not active and names the one it follows. It is a
    member we trust, so we take the name, but only once that instance answers a signed
    status call as active under that very epoch, at least ours. Returns 'source
    switched', or None when the hint is not taken."""
    try:
        hint = (resp.json() or {}).get('follow')
    except Exception:
        return None
    if not isinstance(hint, dict):
        return None
    entry = _clean_entries([hint]).get(hint.get('instance_id'))
    their = hint.get('epoch')
    st = _load()
    me = st['instance_id']
    if (not entry or not entry['public_key'] or not entry['url']
            or _epoch_value(their, low=int(st.get('epoch') or 0)) is None):
        return None
    hid = hint['instance_id']
    if hid in (me, src['instance_id']) or _matches_tombstone(entry, (st.get('tombstones') or {}).get(hid)):
        return None
    known = (st.get('members') or {}).get(hid)
    if known is None and len(st.get('members') or {}) >= MAX_MEMBERS - 1:
        logging.warning(f"[HA] {src.get('url')} follows {entry['url']}, and there is no room "
                        "for another member here")
        return None
    rec = dict(known or entry, instance_id=hid)
    try:
        said = _ask(rec, _signer(), timeout=min(10, timeout))
        their_role, their_epoch, group = said[:3]
        if len(said) > 5:
            _note_lease_seen(hid, said[5])
    except Exception as e:
        logging.warning(f"[HA] {src.get('url')} follows {entry['url']}, which did not confirm it: {e}")
        return None
    if their_role != ROLE_ACTIVE or their_epoch != their:
        return None
    if mode() == ha_vote.MODE_AUTO and not _says_it_holds(hid):
        # in an automatic group only the member that holds the lease is followed
        return None
    with _lock:
        st = _load()
        ms = dict(st.get('members') or {})
        if st['role'] != ROLE_STANDBY or st.get('source') != src['instance_id']:
            return None
        if hid not in ms and len(ms) >= MAX_MEMBERS - 1:
            return None
        base = ms.get(hid) or dict(entry, joined_at=_now(), last_error='')
        ms[hid] = dict(base, role_seen=ROLE_ACTIVE, epoch_seen=their_epoch, last_contact=_now(),
                       group_seen=bool(base.get('group_seen') or group == GROUP_MARK))
        _commit_locked(dict(st, members=ms, source=hid,
                            sync=dict(st.get('sync') or {}, etag=None, last_error='')))
    logging.warning(f"[HA] {src.get('url')} is not active and follows {entry['url']}, which "
                    f"answers as active with epoch {their_epoch} - following it from now on")
    _audit('ha.follow_hint', f"following {entry['url']} (epoch {their_epoch}), as "
                             f"{src.get('url') or src['instance_id']} does")
    return 'source switched'


def _ask(rec, signer, timeout):
    """(role, epoch, group mark, serving, cv, lease) as the member `rec` reports them,
    serving False and cv (None, None) from a release that does not say; cv is (the entry
    of the configuration it holds, when that last stepped). lease is what it says about
    automatic failover (_lease_seen), None from a release or a member that says nothing.
    Raises PeerRefused when it turns us away (401, 410), HaError when it does not answer
    usably."""
    sent = _wall()
    resp = call_member(rec, 'GET', '/api/ha/peer/status', timeout=timeout, signer=signer)
    back = _wall()
    if resp.status_code in (401, 410):
        try:
            data = resp.json()
        except Exception:
            data = None
        data = data if isinstance(data, dict) else {}
        said = data.get('instance_id')
        if said is not None and said != rec['instance_id']:
            # set up anew at that address, say: its refusal is not the member's
            raise HaError('Another instance answers at the address of this member')
        raise PeerRefused(_peer_error(resp, 'The member refused the status call'),
                          resp.status_code, data.get('code') or '')
    if resp.status_code != 200:
        raise HaError(_peer_error(resp, 'The member refused the status call'))
    data = resp.json()
    if not isinstance(data, dict):
        raise HaError('The member sent a status this version does not read')
    said = data.get('instance_id')
    if said is not None and said != rec['instance_id']:
        raise HaError('Another instance answers at the address of this member')
    their_role, their_epoch = data.get('role'), _epoch_value(data.get('epoch') or 0)
    if their_role not in (ROLE_STANDALONE, ROLE_ACTIVE, ROLE_STANDBY):
        their_role = None
    if their_epoch is None:
        raise HaError('The member sent an epoch this version does not read')
    cv = _one_cv(data.get('cv'))
    at = data.get('cv_at') if cv and isinstance(data.get('cv_at'), str) else None
    return (their_role, their_epoch, data.get('group'), data.get('serving') is True,
            (cv, at[:40] if at else None), _lease_seen(data, sent, back))


def _ask_members(timeout, refused=None):
    """Ask every member for its role and epoch, side by side and each within `timeout`.
    Notes contact or error on every record (one write, none when nothing changed) and
    returns {member id: (role, epoch)} of the members that answered. `refused`, a dict,
    gets {member id: HTTP status} of the ones that turned us away."""
    ms = members()
    if not ms:
        return {}
    signer = _signer()
    results = _fan_out([lambda rec=rec: _ask(rec, signer, timeout) for rec in ms], timeout + 5)
    answers, notes, unreachable, now = {}, {}, set(), _now()
    for rec, (value, err) in zip(ms, results):
        mid = rec['instance_id']
        if err is not None:
            notes[mid] = {'last_error': _error_text(err)}
            _note_lease_gone(mid)
            if isinstance(err, PeerRefused) and err.code != 'HA_CLOCK':
                if refused is not None:
                    refused[mid] = err.status
            elif not isinstance(err, PeerRefused):
                unreachable.add(mid)
            else:
                # it knows us and says our clocks differ: no sign that we are out
                logging.warning(f"[HA] member {rec.get('url') or mid} refuses our calls: {err}")
            continue
        answers[mid] = value[:2]
        notes[mid] = {'last_contact': now, 'role_seen': value[0], 'epoch_seen': value[1],
                      'serving_seen': value[3], 'last_error': ''}
        if value[4][0] is not None and _newer_cv(rec.get('cv_seen'), value[4][0]):
            # what it holds: for the change gap at a promotion, and for an active to
            # see its own segment held further than it knows (note_config_etag)
            notes[mid].update(cv_seen=value[4][0], cv_seen_at=value[4][1])
        if value[2] == GROUP_MARK:
            notes[mid]['group_seen'] = True
        if len(value) > 5:
            _note_lease_seen(mid, value[5])
    _last_watch.update(at=time.monotonic(), unreachable=frozenset(unreachable))
    src = source_id()
    if src in answers or src in unreachable:
        _note_source_heard(src, src in answers)
    try:
        _note_members(notes)
    except Exception as e:
        # the answers stand: a full disk must not keep the leader from telling another
        # active to step down, which needs no write of ours
        logging.warning(f"[HA] could not note the member answers: {e}")
    return answers


def _holder_seen(answers, mine):
    """(epoch, member id) of a member that answered as the holder of the lease at an
    epoch at least ours, None when none did. An active that holds no lease leaves for
    it (4.10): a majority renews that member, so it is the one the group follows, and
    not an active made by hand next to it."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        return None
    return max(((e, mid) for mid, (r, e) in answers.items()
                if r == ROLE_ACTIVE and e >= mine and _says_it_holds(mid)), default=None)


def _leader(answers, own=None):
    """(epoch, instance id) of the instance the group follows: the active with the
    highest epoch, a tie going to the higher instance id. `own` is this instance when
    it is active. None when nobody is."""
    actives = [(e, mid) for mid, (r, e) in answers.items() if r == ROLE_ACTIVE]
    if own:
        actives.append(own)
    return max(actives) if actives else None


def check_peer_at_boot(timeout=5):
    """Ask every member once, before managers and loops start.

    An instance that comes back as active may have been replaced while it was
    down. When a member is active under a newer epoch (or under ours, and wins the
    tie) we step down to it right here, without a restart, so the caller comes up as
    a standby and nothing acts on the old configuration. The same when a member says
    we were removed ('removed'), when every member refuses us or one reports a newer
    epoch that no active answers under ('stepped aside'). Never raises; returns a
    short status string.
    """
    try:
        st = _load()
        if ha_vote.AUTO_MODE_SHIPPED and (_lease_mode(st) or mode(st) == ha_vote.MODE_AUTO):
            # an automatic group: the lease decides who leads, not the highest epoch
            # among the answers (4.9)
            return lease_boot()
        if role() != ROLE_ACTIVE or not members():
            return 'idle'
        mine, me, n = epoch(), instance_id(), len(members())
        refused = {}
        answers = _ask_members(timeout, refused)
        if _load().get('removed'):
            # a member holds a tombstone for us: we come up passive, nothing restarts
            return 'removed'
        if not answers and not refused:
            return 'unreachable'
        holder = _holder_seen(answers, mine)
        if holder is not None and step_down(holder[0], holder[1], holds_lease=True):
            rec = member(holder[1]) or {}
            _audit('ha.stepped_down', f"at start: member {rec.get('url') or holder[1]} holds "
                                      f"the lease of the group at epoch {holder[0]}")
            return 'stepped down'
        top = _leader(answers, (mine, me))
        if top[1] != me and step_down(top[0], top[1]):
            rec = member(top[1]) or {}
            _audit('ha.stepped_down', f"at start: member {rec.get('url') or top[1]} "
                                      f"is active with epoch {top[0]}")
            return 'stepped down'
        aside = _moved_on(answers, refused, mine, n)
        if top[1] == me and aside and step_aside(*aside):
            _audit('ha.stepped_aside', f'at start: {aside[1]}')
            return 'stepped aside'
        return 'ok'
    except Exception as e:
        logging.warning(f"[HA] member check at start failed: {e}")
        return 'error'


def _moved_on(answers, refused, mine, n):
    """(epoch, reason) when an active that leads among the answers has still been left
    behind: every one of its `n` members refused it, or a member reports an epoch
    above ours while no active under that epoch answered (it would lead otherwise).
    Unreachable members prove nothing and count for neither. None when neither holds."""
    if n and len(refused) == n:
        return mine, f'every member ({n}) refused this instance'
    if answers:
        seen, mid = max((e, m) for m, (_r, e) in answers.items())
        if seen > mine:
            rec = member(mid) or {}
            return seen, (f"member {rec.get('url') or mid} reports epoch {seen}, above this "
                          f"instance's {mine}, and no active under it answers")
    return None


def watch_once(timeout=10):
    """One look at the group, every tick on every paired instance. Never promotes
    anything.

    Every member is asked for its role and epoch. The group follows the active with
    the highest epoch, a tie going to the higher instance id. An active that is not
    that one steps down and becomes its standby; the one that is tells every other
    active it sees to step down. An active the group has moved on from, or that every
    member refuses, steps aside to a passive standby (_moved_on). A standby pulls from
    the leader from then on (_follow). A member that removed us says so (410), and we
    let go of the group."""
    st = _load()
    was = st['role']
    if was == ROLE_STANDALONE or not st.get('members'):
        return 'idle'
    # our epoch as it was before the calls; a member may step us down meanwhile
    mine, me, n = int(st.get('epoch') or 0), st['instance_id'], len(st['members'])
    refused = {}
    answers = _ask_members(timeout, refused)
    if _load().get('removed'):
        if was == ROLE_ACTIVE:
            restart_process('removed from the group')
        return 'removed'
    if role() != was:
        # stepped down while the calls were out; that path restarts us already
        return 'idle'
    if mode() == ha_vote.MODE_AUTO:
        return _watch_auto(was, mine, answers)
    if was == ROLE_STANDBY:
        return _follow(answers, mine)
    holder = _holder_seen(answers, mine)
    if holder is not None and step_down(holder[0], holder[1], holds_lease=True):
        rec = member(holder[1]) or {}
        _audit('ha.stepped_down', f"member {rec.get('url') or holder[1]} holds the lease of "
                                  f"the group at epoch {holder[0]}")
        restart_process('stepped down to standby')
        return 'stepped down'
    top = _leader(answers, (mine, me))
    if top[1] != me:
        if step_down(top[0], top[1]):
            rec = member(top[1]) or {}
            _audit('ha.stepped_down', f"member {rec.get('url') or top[1]} is active "
                                      f"with epoch {top[0]}")
            restart_process('stepped down to standby')
            return 'stepped down'
        return 'ok'
    aside = _moved_on(answers, refused, mine, n)
    if aside:
        if step_aside(*aside):
            _audit('ha.stepped_aside', aside[1])
            restart_process('stepped aside to standby')
            return 'stepped aside'
        return 'ok'
    others = [mid for mid, (r, _e) in answers.items() if r == ROLE_ACTIVE]
    if not others:
        return 'ok' if answers else 'unreachable'
    told = tell_members('POST', '/api/ha/peer/step-down', json_body={'epoch': mine},
                        timeout=timeout, only=others)
    if all(told.get(mid) is None for mid in others):
        return 'told peer to step down'
    return 'peer refused to step down'


def _follow(answers, mine):
    """A standby's half of watch_once: pull from the leader among the members that
    answered as active under at least our epoch. When none did, the member we pull
    from stays what it is and the pull says what is wrong; a standby never promotes
    itself."""
    top = _leader({mid: a for mid, a in answers.items() if a[1] >= mine})
    if top is None:
        return 'no active member' if answers else 'unreachable'
    if top[1] == source_id():
        return 'ok'
    with _lock:
        st = _load()
        if st['role'] != ROLE_STANDBY or top[1] not in (st.get('members') or {}):
            return 'idle'
        before = st.get('source')
        # a full pull from the new one: an etag of the old one says nothing here
        _commit_locked(dict(st, source=top[1], sync=dict(st.get('sync') or {}, etag=None)))
    logging.warning(f"[HA] following {top[1]} from now on, active with epoch {top[0]} "
                    f"(was following {before or 'nobody'})")
    return 'source switched'


def _audit(action, details):
    try:
        from pegaprox.utils.audit import log_audit
        log_audit('system', action, details)
    except Exception:
        pass


def _pull_timeout(started, interval):
    """The timeout of the pull in the pass that began at `started` (monotonic): short
    when the watch of this pass could not reach the source, else what is left of the
    interval, within PULL_TIMEOUT_FLOOR and PULL_TIMEOUT. A source that is gone then
    costs a pass seconds, not a minute and more."""
    at, unreachable = _last_watch['at'], _last_watch['unreachable']
    if at is not None and at >= started and source_id() in unreachable:
        return PULL_TIMEOUT_UNREACHABLE
    left = interval - (time.monotonic() - started)
    return int(max(PULL_TIMEOUT_FLOOR, min(PULL_TIMEOUT, left)))


def _loop():
    # give the app a moment to come up before the first call
    time.sleep(5)
    while True:
        r = None
        started = time.monotonic()
        try:
            r = role()
            if r != ROLE_STANDALONE and _load().get('members'):
                watch_once()
                _lease_housekeeping()
                stamps_settle()
                # the cluster claims (6.3, Q4 b), on a greenlet of their own, and the
                # autostart of the VMs a Force leader cut out (7.3); neither does
                # anything where nothing asks for it
                claim_watch_soon()
                forced_onboot_pass()
        except Exception as e:
            logging.error(f"[HA] loop: {e}")
        try:
            # only when this pass started as a standby: one that just stepped down
            # restarts first
            if r == ROLE_STANDBY and is_standby() and peer():
                interval = int(_load().get('interval') or DEFAULT_INTERVAL)
                pull_once(timeout=_pull_timeout(started, interval))
        except Exception as e:
            logging.error(f"[HA] loop: {e}")
        interval = int(_load().get('interval') or DEFAULT_INTERVAL)
        # a reload of the managers goes out on its timer; should that not come, still
        # when it has settled and not up to an hour later
        wait = _reload_wait()
        if wait is not None:
            interval = min(interval, int(wait) + 1)
        time.sleep(max(5, min(interval, 3600)))


def start_loop():
    """Idempotent. Runs in every role; it only works when paired."""
    global _loop_started
    with _lock:
        if _loop_started:
            return
        _loop_started = True
    threading.Thread(target=_loop, daemon=True, name='ha-peer').start()
    # automatic failover: the lease loop, when this instance has lease state to run
    lease_start()


def _member_view(rec, src, st):
    """A member record as the status page shows it: no secret, no hash, the public key
    only as a short fingerprint ('' while the member still goes by its old secret)."""
    return {
        'instance_id': rec['instance_id'],
        'url': rec.get('url') or '',
        'fingerprint': rec.get('fingerprint') or '',
        'role_seen': rec.get('role_seen'),
        'epoch_seen': rec.get('epoch_seen'),
        'confirmed_standby': _confirmed_standby(rec, st),
        # the leader made it active, and the member said it serves users (a standby of
        # theirs the UI calls active)
        'serve': rec.get('serve') is True,
        'serving_seen': rec.get('serving_seen') is True,
        'key_fingerprint': peer_key_fingerprint(rec.get('public_key')),
        'last_contact': rec.get('last_contact'),
        'last_error': rec.get('last_error') or '',
        'joined_at': rec.get('joined_at'),
        'is_source': rec['instance_id'] == src,
        # where it runs, as an admin labelled it on the leader ('' for no label)
        'site': _clean_site(rec.get('site')) or '',
    }


def public_status():
    st = _load()
    p = peer() or {}
    src = source_id()
    pairing = st.get('pairing') or {}
    removed = st.get('removed')
    # the checks of automatic failover once, for the card and the split-safety panel
    checks = _group_checks(st) if ha_vote.AUTO_MODE_SHIPPED else None
    return {
        'role': st['role'],
        'epoch': int(st.get('epoch') or 0),
        'instance_id': st['instance_id'],
        'interval': int(st.get('interval') or DEFAULT_INTERVAL),
        'live_view': live_view(),
        # the switch, and whether a refused write goes to the active right now
        'forward_writes': forward_writes(),
        'forwarding': forwarding(),
        # whether the leader made this standby active, and whether it serves users right
        # now; how many instances serve them, and how many may
        'serve_assigned': serve_assigned(),
        'serving': serving(),
        'actives': actives(),
        'active_limit': ACTIVE_LIMIT,
        'managers_running': bool(_run['managers']),
        'broken': st.get('broken') or '',
        # set once a member told this instance it was removed; it is passive then
        'removed': {'epoch': removed.get('epoch'), 'at': removed.get('at'), 'by': removed.get('by')}
                   if removed else None,
        'pairing_open_until': pairing.get('expires') if pairing.get('code_hash') and
                              int(pairing.get('expires') or 0) >= int(time.time()) else None,
        # the member a standby pulls from, or the first one; kept for what reads one peer
        'peer': {
            'instance_id': p.get('instance_id'),
            'url': p.get('url'),
            'fingerprint': p.get('fingerprint'),
            'paired_at': p.get('joined_at'),
            'role_seen': p.get('role_seen'),
            'epoch_seen': p.get('epoch_seen'),
            'last_contact': p.get('last_contact'),
            'last_error': p.get('last_error') or '',
        } if p else None,
        'members': [_member_view(rec, src, st) for rec in members()],
        'max_members': MAX_MEMBERS,
        'standby_count': standby_count(),
        'sync': dict(st.get('sync') or {}, etag=None, restart_pending=_restart_pending(),
                     reload_pending=_reload_pending(), last_reload=_run['last_reload']),
        'config_version': _cv_status(st),
        # what a member was known to hold when this instance took the lead without it
        'change_gap': st.get('change_gap') if isinstance(st.get('change_gap'), dict) else None,
        # what was here and a snapshot did not carry over, until an admin dismisses it
        'orphans': orphans_summary(),
        # the zone the group's schedules are evaluated in ('' while it has none: each
        # instance goes by its own), and the zone of this instance
        'timezone': group_timezone(),
        'timezone_local': local_timezone(),
        # the group's zone where this host has no time zone data for it: its schedules
        # run by the clock of this host while it leads ('' when there is none such)
        'timezone_unreadable': _zone_unreadable(st),
        # where this instance runs, as an admin labelled it on the leader
        'site': _clean_site(st.get('site')) or '',
        # automatic failover: None until this release offers it
        'auto': lease_status(st, checks) if checks is not None else None,
        # whether the group survives the loss of a site, and what stands in the way:
        # the findings the switch goes by (split_safety); None until this release
        # offers automatic failover, and on an instance of its own
        'split_safety': split_safety(st, checks) if checks is not None else None,
    }


def _cv_status(st):
    rec = _cv_record(st) or {}
    hist = _hist_of(rec)
    last = hist[-1] if hist else None
    return {'cv': last[:2] if last else list(CV_ZERO), 'segment': last[2] if last else None,
            'by': last[3] if last else None, 'base_cv': rec.get('base_cv'), 'at': rec.get('at'),
            'etag_known': bool(rec.get('etag_at_cv')), 'joined': bool(rec.get('joined'))}


def peer_cv():
    """What this instance tells a member about the configuration it holds: cv, the
    entry, and cv_at, when it last stepped. {} before it has one."""
    st = _load()
    entry = cv_entry(st)
    if entry is None:
        return {}
    return {'cv': entry, 'cv_at': (_cv_record(st) or {}).get('at')}


def banner():
    """What every logged-in user sees about this instance, nothing more. orphans, only
    when there are any: how many copies of changes that were not carried over wait
    here; the UI shows that to admins."""
    st = _load()
    out = {'role': st['role']}
    if st['role'] == ROLE_STANDBY:
        p = peer() or {}
        # removed: the group took it out, and it stays passive until an admin unpairs it
        out.update(peer_url=p.get('url') or '',
                   last_sync_at=(st.get('sync') or {}).get('last_ok_at') or '',
                   removed=bool(st.get('removed')))
    if orphan_count():
        out['orphans'] = orphan_count()
    return out


# --- automatic failover ----------------------------------------------------------
#
# MK Oct 2026 (#625) - stage 2: the group elects its leader by majority, and the leader
# holds a lease that every renewal a majority answers extends. The rules are in
# ha_vote.py, without any I/O of their own. This part runs one ha_vote.Node per
# instance: its state is the 'lease' block of the state file, its calls are signed peer
# calls (VOTE_PATH, RENEW_PATH), its clock is CLOCK_BOOTTIME. The rest of the code asks
# three things, further up: is_active() (may this instance act), holds_lease() (is it
# the one the group follows) and acting_process() (did this process come up to act).
#
# A group runs in manual mode until an admin switches it (switch_auto_on), and the
# server refuses that while ha_vote.AUTO_MODE_SHIPPED is off. Until then nothing here
# runs, answers or shows: no loop, no call, nothing more in a status answer.

AUTO_MODE_ERROR = ('This group fails over automatically: its members elect the leader, and '
                   'none is promoted by hand. Switch automatic failover off on the leader first')
AUTO_REMOVE_ERROR = 'Switch automatic failover off before removing a member'
AUTO_UNPAIR_ERROR = ('This group fails over automatically, and an instance that leaves it by '
                     'hand would go on acting next to the leader its members elect, or take '
                     'a vote with it. Switch automatic failover off on the leader first')
AUTO_REPAIR_ERROR = ('This instance holds a vote in a group that fails over automatically, and '
                     'pairing it again would take that vote and leave too few. Switch '
                     'automatic failover off on the leader first')
AUTO_PENDING_ERROR = 'A switch to automatic failover is under way - try again once it is through'
NO_LEASE_ERROR = ('No leader at the moment - changes and automation are paused until the '
                  'group has one again')
# for a caller nobody has checked: nothing about who leads, or for how long not
NO_LEASE_ANON_ERROR = 'Changes are paused on this instance at the moment - try again shortly'
LEASE_RANGE_ERROR = (f'The lease is a whole number of seconds, {ha_vote.LEASE_MIN} to '
                     f'{ha_vote.LEASE_MAX}')
# what the node writes down, as the 'lease' block keeps it next to mode and epoch
_LEASE_KEYS = ('voted_for', 'gen', 'cfg', 'cfg_chain', 'floor_cv', 'led', 'released',
               'campaign_after', 'promised')
_WITNESS_KEYS = ('instance_id', 'url', 'fingerprint', 'public_key', 'site')
# what a group decided, in the state file of each of its instances: gone when the
# instance is on its own again, and never taken into the next group
_GROUP_KEYS = ('lease', 'leader', 'witness', 'witness_pairing', 'timezone', 'group_mode', 'agent_vmid',
               'site', 'may_lead', 'leader_seen')
# a vote round and a renewal both have two seconds (ha_vote.Timings)
LEASE_CALL_TIMEOUT = 2
# how long a status answer counts for the checks before the switch
LEASE_SEEN_FRESH = 120
LEASE_IDLE = 1.0
# a manual active that a member renews a lease with looks at the group at most this often
LOOK_SPACING = 10
WATCHDOG_TICK = 0.5
REACH_TIMEOUT = 5
REACH_HOSTS = 3
_TZ_NAME_RE = re.compile(r'[A-Za-z0-9_+\-]{1,32}(/[A-Za-z0-9_+\-]{1,32}){0,2}')
# files of the zone directory that name no place (see _zone)
_NO_ZONE = frozenset(('localtime', 'posixrules', 'Factory'))
# every stamp a schedule compares schedule_now() with: (table, key column, stamp column)
_SCHEDULE_STAMPS = (('snapshot_policies', 'id', 'last_run_at'),
                    ('scheduled_tasks', 'id', 'last_run'),
                    ('scheduled_actions', 'id', 'last_run'),
                    ('update_schedules', 'cluster_id', 'last_run'),
                    ('update_schedules', 'cluster_id', 'next_run'))
# the zone those stamps are in, written with them (a synced setting: it travels with them)
STAMPS_ZONE_SETTING = 'ha_stamps_zone'
# one change of the zone the stamps are in at a time
_zone_lock = threading.Lock()
_zones = {}
_zones_unknown = set()
_local_zone = {'name': None}


class NoLease(HaError):
    """An automatic group, and this instance does not hold its lease right now."""


class StateNotWritten(HaError):
    """What was asked for is not on disk, and nothing of it took effect: the state file,
    or the database for the schedules' stamps, could not be written."""


class AutoRefused(HaError):
    """switch_auto_on: what stands in the way (findings), or what the admin has to accept
    first (confirm)."""

    def __init__(self, message, findings, confirm=False):
        super().__init__(message)
        self.findings, self.confirm = findings, confirm


def ha_clock():
    """Lease time (ha_vote.ha_clock). The tests hand every member a clock of its own."""
    return ha_vote.ha_clock()


def _wall():
    return time.time()


def _lease(st):
    """The lease block of a state, None when it has none or one that cannot be read."""
    rec = st.get('lease')
    if not isinstance(rec, dict):
        return None
    cfg = rec.get('cfg')
    # asked on every lease call: the check of the very same block is kept (a write
    # puts new objects in, nothing changes a block in place)
    seen = _lease_checked[0]
    if seen is not None and seen[0] is rec and seen[1] is cfg and seen[2] is rec.get('cfg_chain'):
        return seen[3]
    ok = not (not isinstance(cfg, dict) or ha_vote.pair(cfg.get('id')) is None
              or ha_vote.body_error(cfg.get('body'))
              or not isinstance(rec.get('cfg_chain') or [], list))
    _lease_checked[0] = (rec, cfg, rec.get('cfg_chain'), rec if ok else None)
    return rec if ok else None


_lease_checked = [None]


def mode(st=None):
    """'manual', 'auto_pending' or 'auto', as the newest voter config held here says.
    A standby that holds none goes by what the instance it follows said with the
    pairing or its last snapshot (group_mode): a member no renewal of the leader has
    reached, or one restored from before the switch, is in an automatic group all the
    same. A config held here outranks that word; one that lags behind the group is the
    leader's to bring up to date, and a promotion asks the members besides
    (_members_say_auto). The leader's switch back to manual mode is the group's mode
    only once a majority holds it: until then its lease is in force, and it says
    automatic. Manual for every group that never switched."""
    st = st or _load()
    rec = st.get('lease')
    if isinstance(rec, dict):
        value = rec.get('mode')
        if value == ha_vote.MODE_MANUAL and st.get('leader') is True:
            return ha_vote.MODE_AUTO
        return value if value in ha_vote.MODES else ha_vote.MODE_MANUAL
    said = st.get('group_mode')
    if st.get('role') == ROLE_STANDBY and said in (ha_vote.MODE_AUTO, ha_vote.MODE_PENDING):
        return said
    return ha_vote.MODE_MANUAL


def _mode_said(st):
    """The group's mode as the instance its members follow tells them, with the pairing
    answer, every snapshot and every status answer: automatic for as long as its lease
    is in force."""
    return ha_vote.MODE_AUTO if _lease_mode(st) else mode(st)


def _note_pending(block, held):
    """Since when the lease block `block` holds the pending switch it holds, for the
    status page: noted when that config gets here (`held` is the block before), gone
    once the config held is another one."""
    if block.get('mode') != ha_vote.MODE_PENDING:
        block.pop('pending_since', None)
        return
    same = (isinstance(held, dict) and held.get('mode') == ha_vote.MODE_PENDING
            and isinstance(held.get('cfg'), dict) and held['cfg'].get('id') == block['cfg']['id']
            and held['cfg'].get('by') == block['cfg'].get('by'))
    since = held.get('pending_since') if same else None
    block['pending_since'] = since if isinstance(since, str) and since else _now()


def pending_switch(st=None):
    """The switch to automatic failover that is pending on this instance, None when none
    is: who started it (`by`, the maker of the pending voter config, with its address
    where this instance knows it), whether that is this instance (`own`), since when
    the config is held here, and the sentence the status page and a refused promotion
    say. Until the switch is through, or taken back on the instance that started it, a
    member that holds it is not promoted by hand; this is where an admin reads why."""
    st = st or _load()
    if mode(st) != ha_vote.MODE_PENDING:
        return None
    rec = st.get('lease') if isinstance(st.get('lease'), dict) else {}
    cfg = rec.get('cfg') if isinstance(rec.get('cfg'), dict) else {}
    by = cfg.get('by') if isinstance(cfg.get('by'), str) else None
    since = rec.get('pending_since') if isinstance(rec.get('pending_since'), str) else None
    own = by is not None and by == st['instance_id']
    url = ((st.get('members') or {}).get(by) or {}).get('url') or ''
    when = f' since {since}' if since else ''
    if own:
        text = (f'A switch to automatic failover is pending{when}: it was started on this '
                'instance and waits for every member to take it')
    elif by:
        text = (f'A switch to automatic failover is pending here{when}. {url or by[:8]} started '
                'it, and until it is through or taken back there, this instance is not '
                'promoted by hand')
    else:
        # no voter config here says so: the instance this standby follows did
        text = ('A switch to automatic failover is pending in this group, as the instance this '
                'one follows said. Until it is through or taken back there, this instance is '
                'not promoted by hand')
    return {'by': by, 'by_url': url, 'own': own, 'since': since, 'text': text}


def promote_refusal(st=None):
    """Why this instance is not promoted by hand, '' in a manual group: the group elects
    its leader, or a switch to that is pending, and then who started it and since when."""
    st = st or _load()
    if mode(st) == ha_vote.MODE_MANUAL:
        return ''
    pending = pending_switch(st)
    return pending['text'] if pending else AUTO_MODE_ERROR


def _lease_mode(st):
    """Whether the lease is in force on this instance: automatic mode, or a leader whose
    switch back to manual has not reached a majority yet. Read on every is_active()."""
    rec = st.get('lease')
    if not isinstance(rec, dict):
        return False
    value = rec.get('mode')
    return value == ha_vote.MODE_AUTO or (value == ha_vote.MODE_MANUAL and st.get('leader') is True)


def lease_in_force():
    """Whether this instance is in an automatic group, where the lease decides who acts."""
    return _lease_mode(_load())


def unpair_refusal(st=None, said=(), leader_agreed=False):
    """Why this instance cannot leave its group by hand right now, '' when it can.

    In an automatic group nobody does: a leader that left would go on acting on its
    own while the members it left elect the next one, and a voter that left would stay
    in the voter config as a vote that never answers. Until that is a change of the
    voter config the leader makes, automatic failover is switched off first. The active
    that started a switch takes it back first, or its members wait on a config nobody
    drives. Open all the same: a state file that cannot be read and an instance the
    group took out (the way out for both), a release that does not run automatic
    failover, and a standby whose leader says the group is manual again while the
    config held here still says automatic - it missed the switch back, and pairing it
    again is how it catches up.

    MK Oct 2026 (#625, S7): a member of an automatic group leaves through its leader,
    which takes it out of the voter config first (unpair_needs_leader,
    leave_through_leader; then `leader_agreed`); the leader itself hands its lead on
    first. Nor does a member whose way out is Force leader (way_out_refusal, `said` as
    there)."""
    st = st or _load()
    if (not ha_vote.AUTO_MODE_SHIPPED or st.get('broken') or st.get('removed')
            or st['role'] == ROLE_STANDALONE):
        return ''
    rec = st.get('lease')
    held = rec.get('mode') if isinstance(rec, dict) else None
    if held == ha_vote.MODE_AUTO or _lease_mode(st):
        if st['role'] == ROLE_STANDBY and (st.get('group_mode') == ha_vote.MODE_MANUAL or leader_agreed):
            return ''
        return AUTO_LEAVE_LEADER_ERROR if st.get('leader') else AUTO_UNPAIR_ERROR
    if held == ha_vote.MODE_PENDING and st['role'] == ROLE_ACTIVE:
        return AUTO_PENDING_ERROR
    return way_out_refusal(st, said)


def unpair_needs_leader(st=None):
    """A follower of an automatic group: its unpairing goes through the leader (7.4).
    Not where its vote is one the group cannot do without (fewer than MIN_VOTERS would
    be left): that is refused here, as the leader would, before anybody is asked."""
    st = st or _load()
    if not (ha_vote.AUTO_MODE_SHIPPED and st['role'] == ROLE_STANDBY and not st.get('removed')
            and not st.get('broken') and unpair_refusal(st) == AUTO_UNPAIR_ERROR):
        return False
    lease = _lease(st)
    me = st['instance_id']
    if lease is None or me not in ha_vote.voter_ids(lease['cfg']['body']):
        return True
    return not _too_few_without(lease['cfg']['body'], me)


def unpair_check():
    """(why this instance is not unpaired by hand, '' when it is; what the members said
    just now). A manual config nobody confirmed asks the members first."""
    why = unpair_refusal()
    said = []
    if why == MANUAL_UNKNOWN_ERROR:
        said = _members_said()[1]
        why = unpair_refusal(said=said)
    return why, said


def way_out_check():
    """way_out_refusal, with the members asked where the manual config held here wants
    a majority that holds it as well."""
    why = way_out_refusal()
    if why == MANUAL_UNKNOWN_ERROR:
        why = way_out_refusal(said=_members_said()[1])
    return why


def _takes_a_vote_too_many(st, member_id):
    """accept_pairing in an automatic group: `member_id` is a voter of the voter config,
    and without its vote the group would have fewer than it needs."""
    lease = _lease(st)
    if lease is None or not _lease_mode(st):
        return False
    return member_id in ha_vote.voter_ids(lease['cfg']['body']) and _too_few_without(lease['cfg']['body'], member_id)


def _too_few_without(body, member_id):
    """Whether the voter config `body` without `member_id` holds fewer than MIN_VOTERS
    votes, or fewer than that which count (a quarantined member votes on paper only)."""
    voters = [v for v in ha_vote.voter_ids(body) if v != member_id]
    quarantined = set(body.get('quarantined') or ())
    return len(voters) < ha_vote.MIN_VOTERS or len([v for v in voters if v not in quarantined]) < ha_vote.MIN_VOTERS


def _lease_drop(instance):
    """The instance left its group: what runs its lease in this process ends (the
    loop, the etag tick and the watchdog return at their next pass, as after
    lease_stop), and the runtime goes, so a group it joins later starts a fresh one."""
    rt = _rts.pop(instance, None)
    if rt is not None:
        rt.stop = True
        rt.armed = False
        rt.wake.set()
        rt.halt.set()


def _group_left(instance, zone):
    """This instance is on its own again: its lease runtime ends, and the last-run
    stamps go from the group's zone (`zone`, '' when it had none) back to the clock of
    this instance, which schedules are evaluated by from here on. Called once the state
    is written, outside the state lock."""
    _lease_drop(instance)
    _rezone_stamps(zone, '')


def _members_say_auto(timeout=5):
    return _members_said(timeout)[0]


def _members_said(timeout=5):
    """Before a promotion by hand: the record of a member that says this group fails
    over automatically, or is switching to it, None when none that answers does. The
    promotion asks its own state first (mode); this is for the instance whose state
    does not know - restored from before the switch, never reached by a renewal, or
    holding a switch back to manual mode that never reached a majority. A member that
    holds the lease always counts. Where the manual voter config held here is known to
    be the group's (_manual_known), a member with an older config missed the switch
    back, and one without any only repeats what it was told at its last pull: those
    count for nothing.

    The witness is asked as well and answers like a member (its record comes back with
    kind 'witness'): of two data members and a witness it is the only voter besides
    the leader. It never holds a lease itself, so a promise it keeps counts as the
    lease of the one it names. So is the witness this instance noted while in its group
    (_group_seen), where its state names another one or none: a state put back from
    before the witness was paired knows none. _members_said returns that record and
    what each member said ([(member id, its status or None)], for way_out_refusal)."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        return None, []
    st = _load()
    recs = members()
    if st['role'] != ROLE_STANDBY or not recs:
        return None, []
    for witness in (_witness(st), (_group_seen(st) or {}).get('witness')):
        if witness and witness.get('url') and all(r['instance_id'] != witness['instance_id'] for r in recs):
            # signed only, as _ask_witness: the witness takes no old secret
            recs.append(dict(witness, key_acked=True, kind=ha_vote.KIND_WITNESS))
    lease = _lease(st)
    mine = ha_vote.pair(lease['cfg']['id']) if lease is not None else None
    try:
        signer = _signer()
        results = _fan_out([lambda rec=rec: _ask(rec, signer, timeout) for rec in recs], timeout + 1)
    except Exception as e:
        logging.warning(f"[HA] could not ask the members about the group's mode: {e}")
        return None, []
    said = [(rec['instance_id'], value[5] if err is None and len(value) > 5 else None)
            for rec, (value, err) in zip(recs, results)]
    known = lease is not None and _manual_known(st, lease, said)
    for rec, (_mid, seen) in zip(recs, said):
        if not seen or seen.get('mode') == ha_vote.MODE_MANUAL:
            continue
        if seen.get('holds') is True:
            return rec, said
        if rec.get('kind') == ha_vote.KIND_WITNESS and seen.get('holder'):
            return rec, said
        theirs = seen.get('cfg_id')
        if known and (theirs is None or theirs < mine):
            continue
        return rec, said
    return None, said


def _manual_known(st, lease, said=()):
    """Whether the manual voter config of `lease` is the group's mode for certain. One
    that follows an automatic config is a switch back that a leader made, and the
    group's only once a majority of the voters before it hold it (4.13). This instance
    knows that when it committed the switch itself, when the instance it follows said
    so as a manual active (settled, _adopt_group), or when it and the members that
    answer now (`said`, [(member id, what its status said)]) are such a majority, by
    the digest of the config. Any other manual config was made where no lease was in
    force, by a manual active."""
    cfg = lease['cfg']
    if cfg['body'].get('mode') != ha_vote.MODE_MANUAL:
        return False
    chain = lease.get('cfg_chain') or []
    prev = chain[-1] if chain and isinstance(chain[-1], dict) else None
    if prev is None or (prev.get('body') or {}).get('mode') != ha_vote.MODE_AUTO:
        return True
    digest = ha_vote.cfg_digest(cfg)
    if lease.get('settled') == digest:
        return True
    try:
        if ha_vote.cfg_digest(prev) != cfg.get('prev'):
            return False
        view = ha_vote.CfgView(prev)
    except Exception:
        return False
    holders = {st['instance_id']} | {mid for mid, seen in said
                                     if isinstance(seen, dict) and seen.get('cfg_digest') == digest}
    return len(holders & view.counting) >= view.m


def _clean_witness(value):
    """A witness record as the state file or a snapshot carries it, None for anything else."""
    if not isinstance(value, dict):
        return None
    entry = _clean_entries([dict(value, secret_hash='')]).get(value.get('instance_id'))
    if not entry or not entry['public_key']:
        return None
    site = value.get('site')
    return {'instance_id': value['instance_id'], 'url': entry['url'],
            'fingerprint': entry['fingerprint'], 'public_key': entry['public_key'],
            'site': site if isinstance(site, str) and len(site) <= ha_vote.SITE_MAX else ''}


def _witness(st):
    return _clean_witness(st.get('witness'))


# The group's time zone. Members may run in different zones, and a schedule has to fire
# at the same hour whichever of them leads: it is evaluated in the zone the group was
# formed in (the leader's then), until an admin picks another on the leader.

def _zone_name(name):
    """Whether `name` can name a place as an IANA zone does, whether or not this host has
    the data for it: localtime is each host's own zone, posixrules and Factory are no
    zone, and the right/ tree counts leap seconds."""
    return (isinstance(name, str) and _TZ_NAME_RE.fullmatch(name) is not None
            and name not in _NO_ZONE and not name.startswith(('posix/', 'right/')))


def _zone(name):
    """The time zone `name` (an IANA name), None for anything this host does not know,
    and for what is no place (_zone_name)."""
    if not _zone_name(name):
        return None
    if name not in _zones:
        if len(_zones) > 64:
            _zones.clear()
        try:
            from zoneinfo import ZoneInfo
            _zones[name] = ZoneInfo(name)
        except Exception:
            _zones[name] = None
    return _zones[name]


def _runs_by(zone):
    """Whether this process runs by `zone`: its offset to UTC is the one libc gives, now
    and at two other times of the year, so a zone that only shares today's offset is
    not taken for it."""
    now = time.time()
    try:
        for at in (now, now + 121 * 86400, now + 243 * 86400):
            there = datetime.fromtimestamp(at, timezone.utc).astimezone(zone).utcoffset()
            if there is None or there.total_seconds() != time.localtime(at).tm_gmtoff:
                return False
    except (OverflowError, OSError, ValueError):
        return False
    return True


def local_timezone():
    """The IANA name of the zone this instance runs in, '' when it cannot be told. Asked
    the way libc decides it: TZ when it is set, else where /etc/localtime points, and
    /etc/timezone last, which libc never reads and nothing keeps in step. A TZ that is
    no IANA name (a POSIX string) is a zone without a name. Whatever name comes out is
    checked against the clock the process runs by (_runs_by)."""
    if _local_zone['name'] is None:
        found = []
        if os.environ.get('TZ') is not None:
            found.append(os.environ['TZ'].lstrip(':'))
        else:
            try:
                found.append(os.path.realpath('/etc/localtime').partition('zoneinfo/')[2])
            except OSError:
                pass
            try:
                with open('/etc/timezone', encoding='utf-8') as fh:
                    found.append(fh.read().strip())
            except OSError:
                pass
        _local_zone['name'] = next((name for name in found if name and _zone(name) is not None
                                    and _runs_by(_zone(name))), '')
    return _local_zone['name']


def group_timezone():
    """The zone the group's schedules are evaluated in, '' on an instance of its own and
    in a group that has none yet (one formed before this release)."""
    st = _load()
    if st['role'] == ROLE_STANDALONE and not st.get('members'):
        return ''
    name = st.get('timezone')
    return name if _zone(name) is not None else ''


def _zone_unreadable(st):
    """The group's zone as the leader sent it, where this host cannot read it (no tzdata):
    '' when there is none such."""
    if st['role'] == ROLE_STANDALONE and not st.get('members'):
        return ''
    name = st.get('timezone')
    return name if _zone_name(name) and _zone(name) is None else ''


def schedule_now():
    """The time schedules go by: the wall time in the group's zone, without a tzinfo, as
    datetime.now() has none. On an instance of its own, and in a group without a zone,
    it is datetime.now() and nothing else."""
    name = group_timezone()
    if not name:
        return datetime.now()
    return datetime.now(_zone(name)).replace(tzinfo=None)


def schedule_at(ts):
    """schedule_now() as it read at the wall time `ts` (seconds since the epoch)."""
    name = group_timezone()
    if not name:
        return datetime.fromtimestamp(ts)
    return datetime.fromtimestamp(ts, _zone(name)).replace(tzinfo=None)


def _rezoned(stamp, old, new):
    """The wall time `stamp` (without a zone, as the schedules write it) of the zone
    `old`, as the same moment reads in `new`; None is the zone this process runs in.
    Whatever is no such stamp comes back as it is."""
    if not isinstance(stamp, str) or not stamp:
        return stamp
    short = len(stamp) == 16 and stamp[10] == ' '
    try:
        at = datetime.strptime(stamp, '%Y-%m-%d %H:%M') if short else datetime.fromisoformat(stamp)
    except ValueError:
        return stamp
    if at.tzinfo is not None:
        return stamp
    there = at.replace(tzinfo=old) if old is not None else at.astimezone()
    here = (there.astimezone(new) if new is not None else there.astimezone()).replace(tzinfo=None)
    if short:
        return here.strftime('%Y-%m-%d %H:%M')
    # in the form it had: some are written with a blank between date and time
    return here.isoformat(sep=' ' if len(stamp) > 10 and stamp[10] == ' ' else 'T')


def _rezone_stamps(old, new, strict=False):
    """The zone the schedules go by changes from `old` to `new` ('' is the zone this
    process runs in): every last-run stamp moves with it. They are wall times and are
    compared with schedule_now(); left in the old zone, an hourly schedule would skip
    the hours between the two zones, or fire a second time. On the leader they travel
    to the members with the next sync, like the zone. The zone they are in now goes
    into the database in the same transaction (STAMPS_ZONE_SETTING, travelling with
    them), so a move that a crash cut off from the state file is finished later
    (stamps_settle). Returns how many stamps it moved; when the move fails nothing
    moved, and with `strict` it raises StateNotWritten then instead of logging."""
    if (old or '') == (new or ''):
        return 0
    a, b = (_zone(old) if old else None), (_zone(new) if new else None)
    if (old and a is None) or (new and b is None):
        return 0
    moved = 0
    conn = None
    try:
        from pegaprox.core.db import get_db
        conn = get_db().conn
        cur = conn.cursor()
        tables = _existing_tables(cur)
        for table, key, col in _SCHEDULE_STAMPS:
            if table not in tables:
                continue
            try:
                cur.execute(f'SELECT "{key}", "{col}" FROM "{table}" WHERE "{col}" IS NOT NULL')
            except Exception:
                # a database from before the column: no stamp there to move
                continue
            for row in cur.fetchall():
                at = _rezoned(row[1], a, b)
                if at != row[1]:
                    cur.execute(f'UPDATE "{table}" SET "{col}" = ? WHERE "{key}" = ?', (at, row[0]))
                    moved += 1
        if 'server_settings' in tables:
            if new:
                cur.execute('INSERT OR REPLACE INTO server_settings (key, value) VALUES (?, ?)',
                            (STAMPS_ZONE_SETTING, json.dumps(new)))
            else:
                # the host's own clock again, on an instance of its own: nothing to finish
                cur.execute('DELETE FROM server_settings WHERE key = ?', (STAMPS_ZONE_SETTING,))
        conn.commit()
    except Exception as e:
        logging.error(f"[HA] could not move the last-run stamps to the new time zone: {e}")
        try:
            if conn is not None:
                conn.rollback()
        except Exception:
            pass
        if strict:
            raise StateNotWritten('The last-run stamps of the schedules could not be moved to the '
                                  'new time zone (the database did not take the change) - the zone '
                                  'stays as it was')
        return 0
    if moved:
        logging.info(f"[HA] {moved} last-run stamp(s) moved from {old or 'the local zone'} to "
                     f"{new or 'the local zone'}")
    return moved


def _stamps_zone():
    """The zone the last-run stamps in the database are in, as the move that last put
    them there says (_rezone_stamps); None when no move ever said so."""
    try:
        from pegaprox.core.db import get_db
        value = get_db().get_server_setting(STAMPS_ZONE_SETTING)
    except Exception:
        return None
    return value if isinstance(value, str) and value else None


def stamps_settle():
    """With every look at the group, on the instance that may act: the stamps are in the
    group's zone. A change of the zone writes the database first and the state file
    after it; a process that died in between left them in the zone the database names,
    and they move to the group's now. Never raises; returns how many stamps moved."""
    try:
        zone = group_timezone()
        if not zone or not is_active():
            return 0
        with _zone_lock:
            held = _stamps_zone()
            if held is None or held == zone or _zone(held) is None:
                return 0
            moved = _rezone_stamps(held, zone)
        if moved:
            _audit('ha.timezone_changed', f"{moved} last-run stamp(s) moved from {held} to {zone}, "
                                          "where a change of the zone was cut short")
        return moved
    except Exception as e:
        logging.warning(f"[HA] could not look at the zone of the last-run stamps: {e}")
        return 0


def set_group_timezone(name):
    """Leader: the zone the group's schedules go by from now on. Returns True when it
    changed; the members take it with their next sync. The last-run stamps move to the
    new zone first (_rezone_stamps), and the zone is the group's only once they did:
    StateNotWritten when the database or the state file did not take it, and nothing
    changed then."""
    if _zone(name) is None:
        if _zone('UTC') is None:
            raise HaError('This host has no time zone data - install tzdata (pip install tzdata, '
                          'or the tzdata package of the system)')
        raise HaError('That is not a time zone this instance knows - use a name like Europe/Vienna')
    with _zone_lock:
        with _lock:
            st = _load()
            if st['role'] != ROLE_ACTIVE:
                raise HaError("The group's time zone is set on the leader")
            if _lease_mode(st) and not is_active():
                raise NoLease(NO_LEASE_ERROR)
            if st.get('timezone') == name:
                return False
            before = group_timezone()
        # the database first, outside the state lock: a writer that holds it does not
        # hold up every reader of the state. From where the stamps are, which is the
        # group's zone unless a change before this one was cut short
        held = _stamps_zone()
        src = held if held and _zone(held) is not None else before
        _rezone_stamps(src, name, strict=True)
        with _lock:
            st = _load()
            try:
                if st['role'] != ROLE_ACTIVE or group_timezone() != before:
                    raise HaError("The group's time zone changed meanwhile - try again")
                _commit_locked(dict(st, timezone=name))
                return True
            except Exception as e:
                failed = e
        # back where the state file says they are; if that fails as well, the next look
        # at the group moves them (stamps_settle)
        _rezone_stamps(name, before or src)
        if isinstance(failed, HaError):
            raise failed
        raise StateNotWritten(f"The time zone could not be saved ({_error_text(failed)}) - it stays "
                              'as it was')


class _LeaseRuntime:
    """What runs the lease of one instance in this process: its node, what the node wants
    sent and what it reported, and what the watch last heard from each member. Memory
    only; a restart starts it over, and the hold after a start covers what it forgot."""

    def __init__(self, instance):
        self.instance = instance
        self.lock = threading.RLock()
        self.node = None
        self.gen = 0                    # counts the nodes built; an answer to an older one is dropped
        self.jumps = 0                  # clock jumps the loop saw: a token from before one is void
        self.stale = False              # role, epoch or lease state moved past the node
        self.saving = False             # the node itself is writing the state
        self.outbox = collections.deque()
        self.events = collections.deque()
        self.wake = threading.Event()
        # lease time of the loop's next pass while it waits for it (None while a pass
        # runs), and when the node wants its next tick, said by whoever just called it:
        # the loop is woken only for a tick earlier than the one it waits for
        self.wake_at = None
        self.due = None
        self.halt = threading.Event()
        self.stop = False
        self.loop = False               # the lease loop runs
        self.acting = False             # this process leads and a majority renewed its lease
        self.came_up = False            # it leads since its start (the boot check), not by the switch
        self.boot_check = False         # lease_boot runs: nothing has started for a role yet
        self.armed = False              # the watchdog counts from the loop's first majority round
        self.exit_at = None             # lease time at which the way out was asked for
        self.seen = {}                  # member id -> what its last status answer said
        self.acked = {}                 # member id -> when it last acked a renewal (lease time)
        self.reach = {'at': None, 'clusters': {}}
        self.write_failed = None        # why the last write of the lease state failed
        self.looked = None              # when a renewal last had a manual active look (lease time)
        self.fp_told = (None, frozenset())
        self.said = set()
        self.born = time.monotonic()
        self.lag_max = 0.0
        self.boot_lag_max = 0.0
        self.witness_asked = None       # (node gen, what) the voter config was asked to name
        self.planned = None             # (leader, until) while a planned restart holds the lease
        self.takeover = None            # (leader, until): the winner's takeover wait, as a member reckons it
        self.renewed_at = None          # start of the last round of this leader a majority answered
        self.switch_heard = None        # when the instance that started a pending switch was last heard
        # the claim watch: last pass, cluster -> (what it saw, look again from), the
        # clusters whose write still runs, and the one pass that may run
        self.claims = {'at': None, 'seen': {}, 'jobs': set(), 'busy': threading.Lock()}
        self.witness_told = None        # (what the witness was told of an update, when)


def _rt():
    me = _load()['instance_id']
    rt = _rts.get(me)
    if rt is None:
        rt = _rts.setdefault(me, _LeaseRuntime(me))
    return rt


def _lease_live(st):
    """The node the predicates ask, None when there is none to ask: no lock, no build."""
    rt = _rts.get(st['instance_id'])
    if rt is None or rt.stale:
        return None
    node = rt.node
    return None if node is None or node.dead else node


class _LeaseStore:
    """The node's state file: the 'lease' block of ours, with role and epoch where every
    other reader looks for them. save() is on disk, file and directory, before it
    returns, and raises when it is not."""

    def __init__(self, rt):
        self.rt = rt

    def load(self):
        st = _load()
        lease = _lease(st)
        if lease is None:
            return None
        out = {k: lease.get(k) for k in _LEASE_KEYS}
        out['cfg_chain'] = list(lease.get('cfg_chain') or [])
        out['gen'] = lease['gen'] if type(lease.get('gen')) is int else 0
        if lease.get('epoch') != st.get('epoch'):
            # the epoch moved by hand since (a promotion, a sync in manual mode):
            # nobody was voted for in it
            out['voted_for'] = None
        out['role'] = (ha_vote.ROLE_STANDBY if st['role'] == ROLE_STANDBY
                       else ha_vote.ROLE_LEADER if st.get('leader') else ha_vote.ROLE_ACTIVE)
        out['epoch'] = int(st.get('epoch') or 0)
        out['cv'] = out['base_cv'] = config_version(st)
        return out

    def save(self, new):
        rt = self.rt
        with _lock:
            st = _load()
            if st['instance_id'] != rt.instance or st.get('broken'):
                raise HaError('The HA state of this instance cannot be written')
            lease = dict(st.get('lease') or {})
            for key in _LEASE_KEYS:
                lease[key] = new.get(key)
            # as JSON keeps them: memory and file say the same
            lease['floor_cv'] = list(new['floor_cv']) if new.get('floor_cv') is not None else None
            if new.get('led'):
                lease['led'] = dict(new['led'], cv=list(new['led'].get('cv') or CV_ZERO))
            lease.update(epoch=new['epoch'], mode=new['cfg']['body']['mode'])
            _note_pending(lease, st.get('lease'))
            role = ROLE_STANDBY if new['role'] == ha_vote.ROLE_STANDBY else ROLE_ACTIVE
            if role == ROLE_ACTIVE and st.get('leader') and new['role'] != ha_vote.ROLE_LEADER:
                # the leader that commits its switch back to manual mode: a majority holds
                # it, and this instance knows so whatever it is later (_manual_known)
                lease['settled'] = ha_vote.cfg_digest(new['cfg'])
            out = dict(st, lease=lease, role=role, epoch=new['epoch'])
            out.pop('leader', None)
            if new['role'] == ha_vote.ROLE_LEADER:
                out['leader'] = True
            if role == ROLE_ACTIVE and st['role'] == ROLE_STANDBY:
                out.update(_lead_taken(st))
                out.pop('group_mode', None)
            elif role == ROLE_STANDBY and st['role'] == ROLE_ACTIVE:
                # it follows whoever holds the lease next; a renewal names it
                why = ('No longer the leader of the group' if st.get('leader') else
                       'Stepped down: the group fails over automatically, and its members elect '
                       'the leader')
                out.update(source=None, sync={'last_error': why})
            # file and directory, or it is no vote (under the state lock, like the write)
            rt.saving, _vote_write['on'] = True, True
            try:
                _commit_locked(out)
            except Exception as e:
                # shown on this instance and to its members until a write succeeds again:
                # a voter that cannot write gives no vote, and nothing else would say why
                rt.write_failed = _error_text(e)[:200]
                raise
            finally:
                rt.saving, _vote_write['on'] = False, False
            rt.write_failed = None


def _lead_taken(st):
    """What goes with the role when a standby takes the lead by votes, as _promote does
    it for a promotion by hand."""
    cvr = _cv_record(st)
    if cvr is not None and cvr.get('joined'):
        cvr = None
    ms = {mid: dict(rec, role_seen=None) if rec.get('role_seen') == ROLE_ACTIVE else dict(rec)
          for mid, rec in (st.get('members') or {}).items()}
    return dict(members=ms, source=None, serve_assigned=False, cv=cvr,
                change_gap=_gap_at_promotion(st))


class _LeaseHooks:
    """What the node hands back: the way out, and what it did. Called from inside the
    node, between a write and the promise that rests on it: nothing here logs, writes
    or waits. _lease_events does that once the node let go."""

    def __init__(self, rt):
        self.rt = rt

    def restart(self, why):
        self.rt.events.append(('exit', {'why': why}))

    def event(self, name, info):
        rt = self.rt
        if name in ('promise', 'round'):
            return
        if name == 'lease':
            if rt.loop:
                rt.armed = True
            t0 = info.get('t0')
            if type(t0) in (int, float) and (rt.renewed_at is None or t0 > rt.renewed_at):
                # "lease renewed N s ago" on the status page
                rt.renewed_at = t0
            return
        if name == 'clock_jump':
            # a token from before the step of the clock is void (design 4.2): the next
            # call waits for a round that started after it
            rt.jumps += 1
        if name == 'booted' or (name == 'elected' and info.get('why') == 'switch'):
            # at once: acting_process() goes by it
            rt.acting = True
            # a leader that came up by a start has a gap behind it (5.7), one that took
            # the lead by the switch has none
            rt.came_up = name == 'booted'
        elif name in ('boot_standby', 'step_down', 'manual'):
            # no lease is in force here any more, so the watchdog has none to watch: the
            # last lease_until of a leader that went back to manual mode stays where it
            # was, and would read as a lease that ran out
            rt.acting = False
            rt.armed = False
        rt.events.append((name, info))

    def snapshot(self):
        return None

    def apply_snapshot(self, frm, ans):
        # the catch-up pull of a stale candidate is not wired yet: it loses this round
        # and the fresher voter campaigns
        return None


def _cfg_signed(public_key, message, sig):
    return ha_wire.cfg_signed(public_key, message, sig)


def _lease_node(rt=None):
    """The node of this instance, built from the state file when it has lease state and
    no node runs yet, or one the state moved past. None without lease state, on an
    instance that is out of the group, while automatic mode is not shipped, and once
    the node asked for the way out."""
    rt = rt or _rt()
    with rt.lock:
        st = _load()
        if (not ha_vote.AUTO_MODE_SHIPPED or _lease(st) is None or st.get('broken')
                or st.get('removed') or st['role'] == ROLE_STANDALONE):
            if rt.node is not None and not rt.node.dead:
                rt.node, rt.acting, rt.armed = None, False, False
            rt.stale = False
            return None
        node = rt.node
        if node is not None and node.dead:
            return None
        if node is not None and not rt.stale:
            return node
        try:
            private = _signer().private
            if private is None:
                raise HaError('no key pair to sign a voter config with')
            rt.gen += 1
            gen = rt.gen
            rt.stale, rt.armed, rt.acting = False, False, False
            rt.outbox.clear()
            # the jitter of the election timer, nothing secret
            rt.node = node = ha_vote.Node(
                st['instance_id'], ha_vote.KIND_DATA, store=_LeaseStore(rt),
                clock=lambda: ha_clock(), wall=lambda: _wall(),
                send=lambda to, kind, body, tag: rt.outbox.append((to, kind, body, tag, gen)),
                hooks=_LeaseHooks(rt), rng=random.Random(),
                sign=lambda message: base64.b64encode(private.sign(message)).decode(),
                verify=_cfg_signed, boot_id=ha_vote.read_boot_id(),
                lower_reach=lambda: _lower_reach(rt))
        except Exception as e:
            rt.node = None
            why = _error_text(e)
            if ('no_node', why) not in rt.said:
                # every pass of the loop comes by here: said once
                rt.said.add(('no_node', why))
                rt.events.append(('no_node', {'why': why}))
            return None
        if node.view.mode == ha_vote.MODE_PENDING:
            # a switch this instance started and a restart cut short is taken back: the
            # members hold the pending config and wait for a word (no-op anywhere else)
            node.switch_cancel()
        return node


def _lease_sync_cv(node):
    """The node votes and counts by the cv of the configuration held here."""
    cv = config_version()
    if cv != node.cv:
        node.set_cv(cv)


def _lease_events(rt):
    """What the node reported, said and audited outside of it."""
    while rt.events:
        try:
            name, info = rt.events.popleft()
        except IndexError:
            return
        try:
            _lease_event(rt, name, info)
        except Exception as e:
            logging.warning(f"[HA] could not handle the lease event {name}: {e}")


def _label(member_id):
    rec = member(member_id) or {}
    return rec.get('url') or str(member_id)[:8]


def _lease_event(rt, name, info):
    me = rt.instance[:8]
    if name == 'exit':
        why = info['why']
        rt.exit_at = ha_clock()
        if why != 'won the election':
            # whatever this instance started while it led must not outlive the lease
            kill_children()
        logging.warning(f"[HA] {me}: {why} - restarting")
        restart_process(f'automatic failover: {why}')
    elif name == 'elected':
        acks = sorted(_label(i) for i in info.get('acks') or () if i != rt.instance)
        if info.get('why') == 'switch':
            text = f"automatic failover is on: this instance leads with a lease at epoch {info['epoch']}"
            logging.warning(f"[HA] {text}")
            _audit('ha.auto_on', text)
            _note_leader(rt.instance, info['epoch'])
            # the mode travels with the snapshot too, for a member without a voter config
            nudge_members()
            return
        text = (f"elected leader at epoch {info['epoch']} ({info.get('why')}), by the votes of "
                f"{', '.join(acks) or 'nobody else'}")
        logging.warning(f"[HA] {me}: {text}")
        _audit('ha.elected', text)
        # before the restart, and before the renewal that tells the members (_lease_fetch)
        _note_leader(rt.instance, info['epoch'], prev=rt.node.leader_seen if rt.node is not None else None)
        gap = _load().get('change_gap')
        if isinstance(gap, dict):
            _say_change_gap(gap)
    elif name == 'booted':
        logging.warning(f"[HA] {me}: holds the lease at start, acting from {info.get('acting_from'):.1f} "
                        "(lease clock)")
    elif name == 'acting':
        logging.warning(f"[HA] {me}: acting start epoch={info.get('epoch')}")
    elif name == 'boot_standby':
        text = f"came up as a standby: {info.get('why')}"
        logging.warning(f"[HA] {me}: {text}")
        _audit('ha.lease_lost', text)
        flush_journal()
        if not rt.boot_check:
            # past the boot check this process came up as the leader: managers, monitor
            # and the rest started for that role, so it starts over as what it is now
            rt.exit_at = ha_clock()
            kill_children()
            restart_process('automatic failover: lost the lease while starting')
    elif name == 'lease_lost':
        now = ha_clock()
        ms = [m['instance_id'] for m in members()]
        # whoever acked one of the last two rounds was there until the end
        t = rt.node.t if rt.node is not None else ha_vote.Timings()
        window = 2 * (t.R + t.renew_timeout)
        reached = [m for m in ms if now - rt.acked.get(m, -1e9) <= window]
        text = (f"lost the lease ({info.get('why')}); still heard: "
                f"{', '.join(_label(m) for m in reached) or 'nobody'}; not heard any more: "
                f"{', '.join(_label(m) for m in ms if m not in reached) or 'nobody'}")
        logging.error(f"[HA] {me}: {text}")
        _audit('ha.lease_lost', text)
    elif name == 'step_down':
        logging.warning(f"[HA] {me}: acting stop: {info.get('why')}")
        if info.get('by_hand'):
            _audit('ha.stepped_down', f"this instance, active by hand, is a standby now: {info.get('why')}")
        # who wrote what while this instance led, before the restart takes what waits
        flush_journal()
    elif name == 'switch_off_dropped':
        text = ('automatic failover was not switched off: no majority of the members took the '
                'change before this instance lost the lead, and the group goes on failing over '
                'automatically')
        logging.warning(f"[HA] {me}: {text}")
        _audit('ha.auto_off_dropped', text)
    elif name == 'cfg':
        why, cfg = info.get('why'), info.get('cfg') or {}
        logging.info(f"[HA] {me}: voter config {cfg.get('id')} ({why})")
        if why == 'quarantine':
            before = set((info.get('prev') or {}).get('body', {}).get('quarantined') or ())
            for mid in set(cfg.get('body', {}).get('quarantined') or ()) - before:
                text = (f"{_label(mid)} came back with an older state than it reported before - "
                        "its votes do not count until an admin re-admits it")
                logging.error(f"[HA] {text}")
                _audit('ha.member_quarantined', text)
    elif name == 'manual':
        text = 'automatic failover is off: a majority holds the change, this instance stays active'
        logging.warning(f"[HA] {text}")
        _audit('ha.auto_off', text)
        nudge_members()
    elif name == 'switch_pending':
        _audit('ha.auto_pending', 'the switch to automatic failover is on its way to the members')
    elif name == 'switch_cancelled':
        text = 'the switch to automatic failover was taken back: the group stays in manual mode'
        logging.warning(f"[HA] {text}")
        _audit('ha.auto_cancelled', text)
    elif name == 'suspect':
        logging.error(f"[HA] member {_label(info.get('voter'))} reports generation {info.get('gen')} "
                      f"after {info.get('seen')}: its state went back")
    elif name == 'change_refused':
        text = (f"a change of the voter config was refused ({info.get('why')}): the config "
                "stays as it was")
        logging.error(f"[HA] {me}: {text}")
        _audit('ha.voter_config_refused', text)
    elif name == 'transfer':
        logging.warning(f"[HA] {me}: handing the lead to {_label(info.get('to'))}: writes paused "
                        "until it caught up")
    elif name == 'acting_stop':
        logging.warning(f"[HA] {me}: acting stop: {info.get('why')}")
    elif name == 'transfer_refused':
        text = f"the lead was not handed on ({info.get('why')}): this instance goes on leading"
        logging.warning(f"[HA] {me}: {text}")
        _audit('ha.transfer_refused', text)
    elif name == 'campaign_failed':
        logging.info(f"[HA] {me}: {info.get('kind')} at epoch {info.get('epoch')} failed: "
                     f"{info.get('reached')} of the {info.get('m')} votes needed answered")
    elif name in ('write_failed', 'no_node'):
        logging.error(f"[HA] {me}: lease {name}: {info}")
    elif name == 'adopt_refused':
        logging.warning(f"[HA] {me}: the voter config from member {_label(info.get('from'))} "
                        f"was not taken: {info.get('why')}")
    else:
        logging.debug(f"[HA] {me}: lease {name}: {info}")


def _lease_dispatch(rt):
    """Send what the node queued, each call on its own, so a member that does not answer
    holds up none of the others. Tests leave the queue alone and deliver by hand."""
    while rt.outbox:
        try:
            item = rt.outbox.popleft()
        except IndexError:
            return
        try:
            _lease_call_spawn(lambda item=item: _lease_deliver(rt, item))
        except Exception as e:
            logging.warning(f"[HA] could not send a lease call: {e}")


def _lease_call_spawn(fn):
    """Run one lease call in the background. Under gevent a greenlet of its own: a
    threading.Thread costs about as much to start as the call takes to sign (MK Oct 2026,
    #625: a confirm round before every write)."""
    if _threads_are_greenlets():
        from gevent import spawn
        spawn(fn)
    else:
        _in_background(fn, 'ha-lease-call')


def _threads_are_greenlets():
    if _gevent_threads[0] is None:
        try:
            from gevent import monkey
            _gevent_threads[0] = bool(monkey.is_module_patched('threading'))
        except ImportError:
            _gevent_threads[0] = False
    return _gevent_threads[0]


_gevent_threads = [None]


def _lease_after(rt, wake=True):
    """After every call into the node, outside its lock: say what it reported, take the
    way out it asked for, send what it wants sent, and let the loop work out its next
    pass."""
    due, rt.due = rt.due, None
    _lease_events(rt)
    _lease_dispatch(rt)
    if wake:
        at = rt.wake_at
        if due is None or at is None or due < at:
            rt.wake.set()


def _lease_target(member_id):
    st = _load()
    rec = (st.get('members') or {}).get(member_id)
    if rec is not None:
        return dict(rec, instance_id=member_id)
    witness = _witness(st)
    return witness if witness and witness['instance_id'] == member_id else None


def _lease_fetch(item):
    """One call of the node as a signed peer call: the answer, None for none."""
    to, kind, body = item[:3]
    path = LEASE_PATHS.get(kind)
    rec = _lease_target(to)
    if path is None or rec is None or not rec.get('url'):
        return None
    if kind == 'renew':
        # where the leader's configuration is at, for the change gap of a member that
        # takes the lead before it has pulled that far
        held = peer_cv()
        if held:
            body = dict(body, leader_cv=held['cv'], leader_cv_at=held.get('cv_at'))
        # since when this instance leads, so every member names the same moment
        seen = _leader_seen(_load())
        if seen is not None and seen['id'] == _load()['instance_id'] and seen['since']:
            body = dict(body, leader_since=seen['since'])
    try:
        # on the member's kept session: a TLS handshake per call would cost renewals
        resp = _peer_call('POST', rec['url'], rec.get('fingerprint') or '', path, json_body=body,
                          auth=_auth_for(_signer(), to), timeout=LEASE_CALL_TIMEOUT, keep_alive=True)
    except HaError as e:
        logging.debug(f"[HA] {kind} to {rec.get('url')}: {_error_text(e)}")
        return None
    if resp.status_code == 200:
        try:
            data = resp.json()
        except Exception:
            data = None
        return data if isinstance(data, dict) else None
    if resp.status_code == 410:
        _removed_answer(rec, resp)
    elif resp.status_code == 401:
        try:
            if (resp.json() or {}).get('code') == 'HA_CLOCK':
                return {'ok': False, 'granted': False, 'reason': 'HA_CLOCK'}
        except Exception:
            pass
    return None


def _lease_answer(rt, item, ans):
    to, kind, _body, tag, gen = item
    with rt.lock:
        node = rt.node
        if node is None or rt.gen != gen or node.dead:
            return
        if kind == 'renew' and isinstance(ans, dict) and ans.get('ok') is True:
            rt.acked[to] = ha_clock()
        seen = rt.seen.get(to) if isinstance(ans, dict) and 'write_failed' in ans else None
        if seen is not None:
            # the witness says with every answer whether it can write its state: a
            # renewal it acks needs no write, the vote at the next failover does
            seen['write_failed'] = ans['write_failed'] is True
        node.on_answer(to, tag, ans)
        rt.due = node.next_wake()


def _lease_deliver(rt, item):
    """One call the node queued, sent, and its answer handed back to the node."""
    ans = None
    try:
        ans = _lease_fetch(item)
    except Exception as e:
        logging.warning(f"[HA] a lease call to member {item[0]} failed: {e}")
    _lease_answer(rt, item, ans)
    _lease_after(rt)


def _lease_no(reason):
    ans = {'ok': False, 'granted': False, 'reason': reason, 'epoch': epoch()}
    if reason == 'MODE_MANUAL' and _lease(_load()) is None:
        # no voter config here at all, and no write counted: the leader sends its chain
        # again, and a voter that reported more before shows as one whose state went
        # back (it is quarantined until an admin looked)
        ans.update(cfg_id=[0, 0], gen=0)
    return ans


def _anchor_error(st, sender, cfg):
    """'' when the voter config `cfg` can be the one this member's chain starts from."""
    body = cfg.get('body')
    if ha_vote.body_error(body):
        return 'it is no voter config'
    records = {rec['id']: rec for rec in body['voters']}
    signer = records.get(cfg.get('by'))
    if not signer or not signer.get('voter') or not _cfg_signed(
            signer['public_key'], bytes.fromhex(ha_vote.cfg_digest(cfg)), cfg.get('sig')):
        return 'none of its voters signed it'
    mine = records.get(st['instance_id'])
    if not mine or mine['public_key'] != own_public_key():
        return 'it does not name this instance with its key'
    ms = st.get('members') or {}
    if sender not in records:
        return 'it does not name its sender'
    for mid, rec in records.items():
        held = (ms.get(mid) or {}).get('public_key')
        if held and held != rec['public_key']:
            return f'it names member {mid[:8]} with another key than the one held here'
    return ''


def _gives_way(lease, sender, epoch):
    """Whether the voter config held here gives way to a chain of `sender`, the active
    this member follows, that does not hang off it. A manual one does. A pending one
    does when `sender` did not make it and switches at an epoch (`epoch`, as its round
    says) above the one that config was made in: the maker steps down to that active
    and never the other way, and the active takes no round of an older term, so the
    switch this member leaves can never be committed on the ack it gave before. Under
    one epoch the two settle who leads first, and the maker that steps down hands the
    manual config out itself (_tell_switch_back). An automatic config never gives way."""
    held = lease.get('mode')
    if held == ha_vote.MODE_MANUAL:
        return True
    if held != ha_vote.MODE_PENDING or lease['cfg'].get('by') == sender:
        return False
    return type(epoch) is int and epoch > ha_vote.pair(lease['cfg']['id'])[0]


def _lease_adopt(rt, sender, body, replace=False):
    """A member without lease state takes the group's voter config from the instance it
    follows: the oldest config of the chain that call carries which names this instance
    is where its own chain starts (one that joined later is in none of the older ones).
    That is the trust a sync has (the whole configuration comes from there), and still
    the config has to hold together: signed by one of its own data voters, naming this
    instance and every member known here with the keys held here. With `replace`, a
    member in manual mode whose chain the sender's does not hang off (the active
    founded it anew) starts over the same way, from a config newer than its own. So
    does a member that holds a pending switch another instance started, once the active
    it follows now switches at a later epoch: nobody drives the switch it holds any
    more, and the config of that active is the group's (_gives_way). Returns the node,
    None when nothing was taken."""
    with _lock:
        st = _load()
        if (st['role'] != ROLE_STANDBY or st.get('source') != sender or st.get('removed')
                or st.get('broken')):
            return None
        chain = body.get('chain')
        if not isinstance(chain, list) or not 0 < len(chain) <= ha_vote.CFG_KEEP + 1:
            return None
        cfgs = sorted((c for c in chain if isinstance(c, dict) and ha_vote.pair(c.get('id'))),
                      key=lambda c: ha_vote.pair(c['id']))
        if not cfgs:
            return None
        held = _lease(st)
        if held is not None:
            if not replace or not _gives_way(held, sender, body.get('epoch')):
                return None
            top = ha_vote.pair(held['cfg']['id'])
            cfgs = [c for c in cfgs if ha_vote.pair(c['id']) > top]
        anchor, why = None, 'it carries no voter config newer than the one held here'
        for cfg in cfgs:
            why = _anchor_error(st, sender, cfg)
            if not why:
                anchor = cfg
                break
        if anchor is None:
            rt.events.append(('adopt_refused', {'from': sender, 'why': why}))
            return None
        mine = int(st.get('epoch') or 0)
        fresh = ha_vote.new_state(anchor, role=ha_vote.ROLE_STANDBY, epoch=mine)
        block = {k: fresh.get(k) for k in _LEASE_KEYS}
        block.update(floor_cv=list(CV_ZERO), epoch=mine, mode=anchor['body']['mode'])
        _note_pending(block, held)
        if held is not None:
            # the count of its writes goes on, and so does a vote given under this epoch
            block['gen'] = held.get('gen') if type(held.get('gen')) is int else 0
            if held.get('epoch') == mine:
                block['voted_for'] = held.get('voted_for')
        try:
            _commit_locked(dict(st, lease=block))
        except Exception as e:
            rt.events.append(('write_failed', {'error': str(e)}))
            return None
    if rt.node is not None:
        rt.stale = True
    return _lease_node(rt)


def _lease_heard(sender, body):
    """A renewal this standby took: the sender holds the lease, so it is the member to
    pull from, whatever the watch last saw. And where its configuration is at."""
    try:
        with _lock:
            st = _load()
            ms = st.get('members') or {}
            rec = ms.get(sender)
            if st['role'] != ROLE_STANDBY or rec is None:
                return
            new, before = st, st.get('source')
            if before != sender:
                # a full pull from the new one: an etag of the old one says nothing here
                new = dict(new, source=sender, sync=dict(st.get('sync') or {}, etag=None))
            if rec.get('role_seen') != ROLE_ACTIVE:
                new = dict(new, members=dict(ms, **{sender: dict(rec, role_seen=ROLE_ACTIVE)}))
            seen = _leader_seen_after(st, sender, body.get('epoch'), prev=before,
                                      since=body.get('leader_since'))
            if seen is not None:
                new = dict(new, leader_seen=seen)
            if new is not st:
                _commit_locked(new)
                if before != sender:
                    logging.warning(f"[HA] following {sender} from now on, it holds the lease "
                                    f"(was following {before or 'nobody'})")
        _note_source_heard(sender, True)
        heard = _one_cv(body.get('leader_cv'))
        if note_leader_cv(sender, body.get('leader_cv'), body.get('leader_cv_at')) \
                and heard != cv_entry():
            # a note about a change that did not get here is made up for with the renewal
            pull_soon()
    except Exception as e:
        logging.warning(f"[HA] could not note the renewal of member {sender}: {e}")


def lease_request(sender, kind, body):
    """A vote, a pre-vote or a renewal from the member `sender`, as the peer routes take
    it. Returns the node's answer; a refusal with its reason while this instance has no
    lease state, or automatic mode is not shipped."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        return _lease_no('NOT_SHIPPED')
    rt = _rt()
    took = False
    with rt.lock:
        node = _lease_node(rt)
        # a round that hands out the manual config which took a switch back
        # (_hand_switch_back) is for a member that holds a pending config, and for
        # nobody else: its sender need not lead, so no chain starts from its word here
        # and no term ends on it. Such a member takes it by its chain, whoever sends
        # it - one that ends in a manual config and hangs off a config held here, each
        # link signed by a voter of the one before (ha_vote.newer_chain). The witness
        # goes by the same rule (ha_vote.takes_switch_back)
        stray = not ha_vote.takes_switch_back(body, node.view.mode if node is not None else None)
        if node is None and kind == 'renew' and not stray and _lease(_load()) is None:
            node = _lease_adopt(rt, sender, body)
        if stray:
            ans = _lease_no('NOT_PENDING')
        elif node is None:
            ans = _lease_no('GONE' if rt.node is not None and rt.node.dead else 'MODE_MANUAL')
        else:
            _lease_sync_cv(node)
            ans = node.on_request(sender, kind, body)
            if (ans.get('reason') == 'CFG_GAP' and kind == 'renew' and body.get('switch') is True
                    and node.view.mode != ha_vote.MODE_AUTO):
                # which config held here gives way is _lease_adopt's to say (_gives_way)
                again = _lease_adopt(rt, sender, body, replace=True)
                if again is not None:
                    node = again
                    ans = node.on_request(sender, kind, body)
            took = (kind == 'renew' and ans.get('ok') is True
                    and node.view.mode == ha_vote.MODE_AUTO)
            if took:
                # a planned restart of the leader: the members say so for its hold (7.2)
                hold = body.get('hold_s')
                rt.planned = ((sender, ha_clock() + min(hold, ha_vote.HOLD_MAX))
                              if body.get('planned') is True and type(hold) in (int, float) and hold > 0
                              else None)
                if type(hold) in (int, float) and hold > 0 and body.get('planned') is not True:
                    # the winner's one renewal before its restart: it acts once its
                    # takeover wait is over, about W_take from its vote (the banner)
                    rt.takeover = (sender, ha_clock() + node.t.W_take)
            elif (kind == 'renew' and body.get('switch') is True and ans.get('ok') is True
                  and node.view.mode == ha_vote.MODE_PENDING and node.view.cfg.get('by') == sender):
                # the instance that started the switch still drives it (Force leader, Q13)
                rt.switch_heard = ha_clock()
            rt.due = node.next_wake()
    if took:
        _lease_heard(sender, body)
    elif kind == 'renew' and body.get('switch') is not True:
        _look_soon(rt)
    elif kind == 'renew' and body.get('taken_back') is True and body.get('settled') is True:
        _settled_by(sender, body, ans)
    _lease_after(rt)
    if rt.node is not None and not rt.loop:
        lease_start()
    return ans


def _settled_by(sender, body, ans):
    """A manual config handed out by the active of the manual group (_switch_back_again,
    settled) is the group's: noted as known (_manual_known, MK Oct 2026 #625 S7), once it
    is the config held here. Never raises."""
    try:
        seg = body.get('chain') if isinstance(body.get('chain'), list) else []
        top = seg[-1] if seg and isinstance(seg[-1], dict) else None
        with _lock:
            st = _load()
            lease = _lease(st)
            if (top is None or lease is None or st['role'] != ROLE_STANDBY
                    or sender not in (st.get('members') or {})):
                return
            digest = ha_vote.cfg_digest(lease['cfg'])
            if (lease.get('mode') != ha_vote.MODE_MANUAL or ha_vote.cfg_digest(top) != digest
                    or ans.get('cfg_digest') != digest or lease.get('settled') == digest):
                return
            _commit_locked(dict(st, lease=dict(lease, settled=digest)))
    except Exception as e:
        logging.warning(f"[HA] could not note the manual config of member {sender} as the group's: {e}")


def _look_soon(rt):
    """A member renews a lease with this instance, which is a manual active: that member
    says it leads an automatic group. This instance looks at the group now, in the
    background (the holder rule of watch_once), not at its next pass, which may be up
    to an hour away. At most one look every LOOK_SPACING seconds."""
    st = _load()
    if st['role'] != ROLE_ACTIVE or st.get('leader'):
        return
    now = ha_clock()
    if rt.looked is not None and 0 <= now - rt.looked < LOOK_SPACING:
        return
    rt.looked = now

    def look():
        try:
            watch_once()
        except Exception as e:
            logging.warning(f"[HA] could not look at the group after a renewal: {e}")
    _lease_spawn(look, 'ha-look')


def lease_step():
    """One pass of the lease loop: tick the node and send what it wants sent. Returns
    the seconds until the next pass is due, None when the node asks for none."""
    rt = _rt()
    with rt.lock:
        node = _lease_node(rt)
        if node is None:
            wait = None
        else:
            _lease_sync_cv(node)
            node.tick()
            wake = node.next_wake()
            wait = None if wake is None else max(0.0, wake - ha_clock())
    _lease_after(rt, wake=False)
    return wait


def _lease_loop(rt):
    while not rt.stop:
        wait = None
        try:
            wait = lease_step()
        except Exception as e:
            logging.error(f"[HA] lease loop: {e}")
        wait = LEASE_IDLE if wait is None else min(max(wait, 0.005), LEASE_IDLE)
        asked = time.monotonic()
        rt.wake_at = ha_clock() + wait
        woken = rt.wake.wait(wait)
        rt.wake_at = None
        rt.wake.clear()
        if not woken:
            # how late the hub let this greenlet run: a stall as long as the lease
            # costs it (hub_lag_max in the status)
            late = time.monotonic() - asked - wait
            if late > rt.lag_max:
                rt.lag_max = late
            if asked - rt.born < 300 and late > rt.boot_lag_max:
                rt.boot_lag_max = late


def _cv_loop(rt):
    """The etag tick of an automatic leader, next to the lease loop and never in it: a
    walk over the shared tables must not hold a renewal up."""
    while not rt.stop:
        try:
            # not while the lead is being handed on: the member it goes to catches up
            # with a configuration that holds still (7.1)
            if _lease_mode(_load()) and is_active() and not handing_over() and cv_tick() == 'stepped':
                rt.wake.set()
        except Exception as e:
            logging.warning(f"[HA] config version tick: {e}")
        rt.halt.wait(CV_TICK)


def _lease_spawn(fn, name):
    _in_background(fn, name)


def lease_start():
    """Start the lease loop, the etag tick and the watchdog of this instance, once per
    process and only when there is lease state to run. From start_loop, and again
    whenever lease state appeared since (a switch, the first renewal). Returns True when
    it started them."""
    if not ha_vote.AUTO_MODE_SHIPPED or _lease(_load()) is None:
        return False
    rt = _rt()
    with rt.lock:
        if rt.loop:
            return False
        rt.loop = True
        node = _lease_node(rt)
        if node is not None and rt.acting and node.lease_mode() and not node.holds_lease():
            # the start took longer than the lease of the round before it (4.9), which
            # is no reason to step down. A node of its own sends a round at once and has
            # fifteen seconds for a majority; the gates stay closed until it has one
            rt.stale = True
            _lease_node(rt)
            rt.acting = True
    _lease_spawn(lambda: _lease_loop(rt), 'ha-lease')
    _lease_spawn(lambda: _cv_loop(rt), 'ha-cv-tick')
    _watchdog_start(rt)
    _lease_after(rt)
    return True


def lease_stop():
    """End the loops of this instance's lease runtime. They return at their next pass."""
    rt = _rts.get(_load()['instance_id'])
    if rt is None:
        return
    rt.stop = True
    rt.wake.set()
    rt.halt.set()


def _lease_sleep(seconds):
    time.sleep(seconds)


def _lease_pump(rt, done, deadline):
    """Run the node by hand until done() or the deadline (monotonic): tick, send what it
    queued side by side, hand the answers back. For the boot check, where no loop runs."""
    while True:
        with rt.lock:
            node = rt.node
            if node is None or node.dead:
                return
            _lease_sync_cv(node)
            node.tick()
            calls = list(rt.outbox)
            rt.outbox.clear()
        if calls:
            results = _fan_out([lambda item=item: _lease_fetch(item) for item in calls],
                               LEASE_CALL_TIMEOUT + 1)
            for item, (ans, err) in zip(calls, results):
                _lease_answer(rt, item, ans if err is None else None)
            rt.due = None
        _lease_events(rt)
        if done() or time.monotonic() >= deadline:
            return
        if not rt.outbox:
            with rt.lock:
                wake = rt.node.next_wake() if rt.node is not None else None
                wait = 0.2 if wake is None else wake - ha_clock()
            _lease_sleep(min(max(wait, 0.05), 1.0))


def lease_boot():
    """check_peer_at_boot in an automatic group (4.9), before anything here can act. A
    leader on disk sends renewal rounds at the epoch it won until a majority answers,
    for fifteen seconds at most. With one, this is the acting process, and it acts once
    the takeover wait is over. Without one, or when a member is at a higher epoch, it
    goes on as a standby, in this process and without a restart. Any other role only
    starts its node: the hold after a start counts from here. Returns a short status."""
    rt = _rt()
    rt.boot_check = True
    try:
        with rt.lock:
            node = _lease_node(rt)
        if node is None:
            _lease_events(rt)
            return 'no lease state to run'
        st = _load()
        if not (st['role'] == ROLE_ACTIVE and st.get('leader')):
            _lease_events(rt)
            return f'automatic group, {st["role"]}'
        _lease_pump(rt, lambda: rt.acting or _load()['role'] != ROLE_ACTIVE,
                    time.monotonic() + node.t.boot_wait + LEASE_CALL_TIMEOUT + 1)
    finally:
        rt.boot_check = False
    if rt.acting and _load()['role'] == ROLE_ACTIVE:
        return 'lease held'
    if _load()['role'] == ROLE_ACTIVE:
        # neither a majority nor a refusal in time: the lease loop goes on asking, and
        # nothing acts before it has one
        return 'no majority yet'
    return 'no majority - standby'


# The watchdog: when the hub is blocked, nothing above runs, and an instance whose
# lease ran out must still be gone within G. It is a native thread that takes no gevent
# lock, logs nothing through the patched handlers and reads only what one attribute
# read gives it.

def _watchdog_due(rt, now):
    """Why the process has to go now, '' while it does not. `now` is lease time."""
    node = rt.node
    grace = ha_vote.Timings().G
    if rt.exit_at is not None and now > rt.exit_at + grace:
        return 'the restart after losing the lease did not come'
    if (rt.armed and node is not None and not node.dead and node.lease_mode()
            and node.acting_process() and now > node.lease_until + node.t.G):
        return 'the lease ran out and the process did not step down'
    return ''


def _watchdog_leave(why):
    """Kill what this process started, say one line on fd 2, and take the exit path."""
    import signal
    own = os.getpgrp()
    groups = ()
    for _ in range(3):
        try:
            groups = tuple(_child_groups)
            break
        except RuntimeError:
            continue
    for pgrp in groups:
        if pgrp > 1 and pgrp != own:
            try:
                os.killpg(pgrp, signal.SIGKILL)
            except OSError:
                pass
    for pid, pgrp in _children():
        try:
            if pgrp == own:
                os.kill(pid, signal.SIGKILL)
            elif pgrp > 1:
                os.killpg(pgrp, signal.SIGKILL)
        except OSError:
            pass
    try:
        os.write(2, f'{time.strftime("%Y-%m-%d %H:%M:%S")} [HA] watchdog: {why} - leaving\n'.encode())
    except OSError:
        pass
    if not _supervised():
        try:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception:
            pass
    os._exit(EXIT_RESTART)


def _watchdog_run(rt, sleep, leave=None):
    while not rt.stop:
        sleep(WATCHDOG_TICK)
        why = _watchdog_due(rt, ha_vote.ha_clock())
        if why:
            (leave or _watchdog_leave)(why)
            return


def _watchdog_start(rt):
    """The watchdog on a thread the hub does not schedule, sleeping with the real sleep."""
    try:
        from gevent import monkey
        start = monkey.get_original('_thread', 'start_new_thread')
        sleep = monkey.get_original('time', 'sleep')
    except Exception:
        import _thread
        start, sleep = _thread.start_new_thread, time.sleep
    start(_watchdog_run, (rt, sleep))


# What the watch learns about each member besides role and epoch, kept in memory: the
# checks before the switch and the status page read it.

def _lease_seen(data, sent, back):
    """What a status answer says about automatic failover, None when it says nothing (a
    release before it, or one that does not offer it yet). The skew is the member's
    wall clock against ours at the middle of the call."""
    if data.get('lease_mark') != LEASE_MARK:
        return None
    wall, skew = data.get('wall'), None
    if type(wall) in (int, float) and abs(wall) < 1e12:
        skew = round(wall - (sent + back) / 2, 3)
    lease = data.get('lease') if isinstance(data.get('lease'), dict) else {}
    reach = data.get('reach') if isinstance(data.get('reach'), dict) else {}
    said = data.get('mode')
    by = data.get('pending_by')
    digest = data.get('cfg_digest')
    wire, install, update, code = data.get('wire'), data.get('install'), data.get('update'), data.get('code')
    return {
        'mark': LEASE_MARK, 'skew': skew, 'rtt': round(back - sent, 3),
        'release': str(data.get('release') or '')[:32],
        'zone': str(data.get('zone') or '')[:64],
        'mode': said if said in ha_vote.MODES else ha_vote.MODE_MANUAL,
        # who made the pending config it holds, None when it holds none or does not say
        'pending_by': by[:64] if isinstance(by, str) and by else None,
        # the voter config it holds, None when it holds none
        'cfg_id': ha_vote.pair(data.get('cfg_id')),
        'cfg_digest': digest if isinstance(digest, str) and _DIGEST_RE.fullmatch(digest) else None,
        'dir_sync': data.get('dir_sync') is not False,
        # its last write of the lease state failed: no vote and no renewal that needs one
        'write_failed': data.get('write_failed') is True,
        'holds': lease.get('holds') is True,
        'holder': lease.get('holder') if isinstance(lease.get('holder'), str) else None,
        'reach': {str(k)[:64]: v is True for k, v in list(reach.items())[:256]},
        # a witness says which calls it speaks (none: the first one, 1) and how it is kept
        # up to date (_witness_update_check)
        'wire': wire if type(wire) is int and 0 < wire < 1000 else None,
        'auto_update': data.get('auto_update') is True,
        'install': install if install in witness_boot.INSTALL_KINDS else '',
        'update': (dict({k: (str(v)[:200] if v is not None else None) for k, v in update.items()
                         if k in ('state', 'release', 'error', 'at')}, back=update.get('back') is True)
                   if isinstance(update, dict) else None),
        # the bundle its code came from, '' where no bundle named it (_witness_other_code)
        'code': code if isinstance(code, str) and witness_boot.NAME_RE.fullmatch(code) else '',
    }


def _note_lease_seen(member_id, seen):
    if not ha_vote.AUTO_MODE_SHIPPED:
        return
    _rt().seen[member_id] = dict(seen or {'mark': None}, at=time.monotonic())


def _note_lease_gone(member_id):
    """The member did not answer the last time it was asked: what it said before that
    counts for nothing in the checks before the switch."""
    rt = _rts.get(_load()['instance_id'])
    if rt is not None:
        rt.seen.pop(member_id, None)


def _ask_witness():
    """The witness is no member, so the watch does not ask it: its status, for the skew
    and the checks before the switch. Never raises."""
    witness = _witness(_load())
    if not witness or not witness.get('url'):
        return
    try:
        # signed only: the witness takes no old secret, and should never see one
        _note_lease_seen(witness['instance_id'], _ask(dict(witness, key_acked=True), _signer(), 5)[5])
    except Exception as e:
        logging.info(f"[HA] the witness did not answer: {_error_text(e)}")


def _says_it_holds(member_id):
    seen = _rt().seen.get(member_id) or {}
    return seen.get('holds') is True and time.monotonic() - seen.get('at', -1e9) < LEASE_SEEN_FRESH


def peer_lease_status():
    """What /peer/status says about automatic failover, once this release offers it:
    the mark, the wall clock (for the skew), the release, the mode and who holds the
    lease as this instance sees it, and the clusters it reaches. pending_by, while the
    config held here is a pending switch: the instance that made it. The mode is the
    group's as this instance tells its members (automatic while a lease is in force
    here); the config it holds goes by id and digest."""
    st = _load()
    rt = _rt()
    out = {'lease_mark': LEASE_MARK, 'wall': _wall(), 'release': PEGAPROX_VERSION,
           'zone': local_timezone(), 'kind': ha_vote.KIND_DATA, 'mode': _mode_said(st),
           'reach': dict(rt.reach['clusters'])}
    held = _lease(st)
    if held is not None:
        out['cfg_id'] = list(held['cfg']['id'])
        out['cfg_digest'] = ha_vote.cfg_digest(held['cfg'])
        if held.get('mode') == ha_vote.MODE_PENDING and isinstance(held['cfg'].get('by'), str):
            out['pending_by'] = held['cfg']['by']
    if _dir_sync['unsupported']:
        out['dir_sync'] = False
    if rt.write_failed:
        out['write_failed'] = True
    node = _lease_live(st)
    if node is not None:
        holds = node.lease_mode() and node.holds_lease()
        holder = st['instance_id'] if holds else None
        if not holds and node.promise_to and ha_clock() < node.promise_until:
            holder = node.promise_to
        out.update(lease={'holds': holds, 'holder': holder, 'epoch': node.epoch},
                   voted_for=node.st.get('voted_for'), cfg_id=list(node.view.id),
                   cfg_digest=ha_vote.cfg_digest(node.view.cfg), gen=node.st.get('gen'))
    return out


def _watch_auto(was, mine, answers):
    """watch_once in an automatic group, with what the members answered ({member id:
    (role, epoch)}). The answers are for the status page, the clock skew and the reach;
    who leads is the lease's business. Three things follow from them all the same: a
    leader that sees a member at a higher epoch leaves (4.7); one that holds its lease
    tells every member that answers as an active at an epoch at most its own to step
    down - an active made by hand next to it leaves on that word, even when its own
    calls do not get out; and a standby pulls from the member that says it holds the
    lease."""
    rt = _rt()
    st = _load()
    if was == ROLE_ACTIVE:
        node = _lease_live(st)
        led = node.led_epoch if node is not None and st.get('leader') else None
        ahead = max(((e, mid) for mid, (_r, e) in answers.items()), default=None)
        if led is not None and ahead is not None and ahead[0] > led:
            with rt.lock:
                node.step_down(f'member {ahead[1][:8]} is at epoch {ahead[0]}')
            _lease_after(rt)
            return 'stepped down'
        others = [mid for mid, (r, e) in answers.items() if r == ROLE_ACTIVE and e <= (led or 0)]
        if led is not None and others and node.holds_lease():
            told = tell_members('POST', '/api/ha/peer/step-down',
                                json_body={'epoch': led, 'holds_lease': True}, only=others)
            for mid in others:
                if told.get(mid) is None:
                    logging.warning(f"[HA] told {_label(mid)}, an active next to the lease held "
                                    f"here, to step down")
            return 'told peer to step down'
        return 'ok' if answers else 'unreachable'
    holders = [(e, mid) for mid, (_r, e) in answers.items() if e >= mine and _says_it_holds(mid)]
    if not holders:
        return 'no leader' if answers else 'unreachable'
    top = max(holders)[1]
    if top == st.get('source'):
        return 'ok'
    with _lock:
        st = _load()
        if st['role'] != ROLE_STANDBY or top not in (st.get('members') or {}):
            return 'idle'
        before = st.get('source')
        _commit_locked(dict(st, source=top, sync=dict(st.get('sync') or {}, etag=None)))
    logging.warning(f"[HA] following {top} from now on, it holds the lease "
                    f"(was following {before or 'nobody'})")
    return 'source switched'


# --- the switch, and what the leader decides ---------------------------------------

def _voter_body(st, lease_s, quarantined=()):
    """The body of a voter config in manual mode for the group as the member list has it
    now: this instance, every member (voter, may_lead and site as their records say,
    a vote and the lead for each unless an admin took them) and the witness."""
    # the leader keeps its vote whatever its record says (set_member_vote); a member goes
    # by the leader's word on its own vote, as it came with the member list (_adopt_group)
    own_vote = st['role'] == ROLE_ACTIVE or st.get('voter') is not False
    voters = [{'id': st['instance_id'], 'public_key': own_public_key(), 'voter': own_vote,
               'may_lead': st.get('may_lead') is not False, 'site': _clean_site(st.get('site')) or ''}]
    for mid, rec in (st.get('members') or {}).items():
        voters.append({'id': mid, 'public_key': rec.get('public_key') or '',
                       'voter': rec.get('voter') is not False,
                       'may_lead': rec.get('may_lead') is not False,
                       'site': _clean_site(rec.get('site')) or ''})
    witness = _witness(st)
    body = {'mode': ha_vote.MODE_MANUAL, 'lease_s': lease_s,
            'voters': sorted(voters, key=lambda rec: rec['id']),
            'witness': {'id': witness['instance_id'], 'public_key': witness['public_key'],
                        'site': witness['site']} if witness else None,
            'quarantined': []}
    ids = set(ha_vote.voter_ids(body))
    body['quarantined'] = sorted(q for q in quarantined if q in ids)
    return body


def _finding(code, level, text, member_id=None):
    return {'code': code, 'level': level, 'text': text, 'member': member_id}


def _one_vote_less(n):
    """What a voter that gives no vote costs a group of `n` votes, said as a sentence."""
    left = n - 1
    spare = left - ha_vote.majority(n)
    if spare < 0:
        then = 'no leader can be elected until it can'
    elif spare == 0:
        then = 'one more failure may stop automation'
    else:
        then = f'the group survives the loss of {spare} more'
    return f'The group has one vote less, {left} of its {n}: {then}.'


def _founds_chain(st):
    """Whether a switch started on this instance would found a chain of voter configs:
    it holds none, or one it is no data voter of (it joined later and was promoted)."""
    lease = _lease(st)
    return lease is None or st['instance_id'] not in ha_vote.CfgView(lease['cfg']).data


def _holds_a_chain_of_its_own(seen, st):
    """Whether a chain founded on this instance would stand next to one the member
    holds, going by its last status answer `seen`: it is in automatic mode, or it holds
    a pending switch somebody still drives. A pending switch is nobody's any more, and
    the member takes the config made here in its place (_gives_way), when another
    instance made it that leads no longer - a standby as it last answered here, or out
    of the group - and in an epoch before this one."""
    said = seen.get('mode')
    if said != ha_vote.MODE_PENDING:
        return said == ha_vote.MODE_AUTO
    by, held = seen.get('pending_by'), seen.get('cfg_id')
    if by is None or by == st['instance_id'] or held is None:
        return True
    maker = (st.get('members') or {}).get(by)
    if maker is not None and maker.get('role_seen') != ROLE_STANDBY:
        return True
    return int(st.get('epoch') or 0) <= held[0]


def auto_findings(st=None, lease_s=ha_vote.LEASE_DEFAULT):
    """What stands in the way of automatic failover in this group (level 'block') or
    weakens it ('warn'), and what an admin should know about it ('info'), as this
    instance sees it from the last answers of its members and the clusters it runs:
    [{code, level, text, member}], with site or cluster where a finding is about one.
    In a group that runs automatically the same list says what to look at; nothing
    blocks there. The switch refuses on a block, wants the code of every warn ticked,
    and takes a block about one cluster (FOREIGN_CLAIM) as a warn: it stops nothing but
    that cluster. The split-safety panel shows this very list (split_safety)."""
    return _group_checks(st, lease_s)['findings']


def _group_checks(st=None, lease_s=ha_vote.LEASE_DEFAULT):
    """auto_findings, and what the split-safety panel shows next to them: {findings,
    body (the voter config the checks went by), running, layout (_site_layout),
    clusters (_cluster_checks)}. One pass, so the switch and the panel agree."""
    st = st or _load()
    rt = _rt()
    now = time.monotonic()
    lease = _lease(st)
    # by the config held: a leader whose switch back is not through yet says what its
    # members do, and they hold the manual config already
    running = lease is not None and lease.get('mode') == ha_vote.MODE_AUTO
    out = []
    body = lease['cfg']['body'] if running else _voter_body(st, lease_s)
    n = len(ha_vote.voter_ids(body))
    if n < ha_vote.MIN_VOTERS:
        out.append(_finding('TOO_FEW_VOTERS', 'block',
                            f'Automatic failover needs at least {ha_vote.MIN_VOTERS} votes, this '
                            f'group has {n}. Add a data member or a witness.'))
    named = {rec['id']: rec for rec in body.get('voters') or ()}
    if body.get('witness'):
        named[body['witness']['id']] = body['witness']
    founding = not running and _founds_chain(st)
    # whoever acked one of the last two rounds holds the config and is in automatic
    # mode, whatever its status said when the watch last asked
    t = rt.node.t if rt.node is not None else ha_vote.Timings()
    acked = {mid for mid, at in list(rt.acked.items())
             if ha_clock() - at <= 2 * (t.R + t.renew_timeout)}
    targets = [dict(rec, instance_id=mid) for mid, rec in sorted((st.get('members') or {}).items())]
    if _witness(st):
        targets.append(_witness(st))
    wid = (_witness(st) or {}).get('instance_id')
    for rec in targets:
        mid = rec['instance_id']
        label = rec.get('url') or mid[:8]
        if mid == wid:
            label = f'the witness {label}'
        start = len(out)
        seen = rt.seen.get(mid)
        if running and mid not in named:
            out.append(_finding('NOT_IN_CONFIG', 'warn', f'{label} is ' + (
                'paired' if mid == wid else 'a member') + ', and the voter config does not name '
                'it (yet): it neither votes nor is it counted.', mid))
        elif running and named[mid].get('public_key') != rec.get('public_key'):
            out.append(_finding('KEY_MISMATCH', 'warn', f'The voter config names {label} with '
                                'another key than the one it paired with: it was paired again, '
                                'and its vote does not answer. Switch automatic failover off '
                                'and on again to take the group as it is now.', mid))
        if not rec.get('public_key'):
            out.append(_finding('OLD_RELEASE', 'block', f'{label} still goes by the secret of an '
                                'earlier pairing. It has to answer once on this release.', mid))
        elif not seen or now - seen['at'] > LEASE_SEEN_FRESH:
            out.append(_finding('VOTER_DOWN', 'warn' if running else 'block',
                                f'{label} has not answered within the last '
                                f'{LEASE_SEEN_FRESH // 60} minutes.'
                                + (' One more failure may stop automation.' if running else ''), mid))
        elif seen.get('mark') != LEASE_MARK:
            out.append(_finding('DOWNGRADED' if running else 'OLD_RELEASE',
                                'warn' if running else 'block',
                                f'{label} runs a release without automatic failover.'
                                + (' Switch automatic failover off before downgrading a member.'
                                   if running else ' Update it first.'), mid))
        else:
            # the witness by its wire: the calls it speaks, not the release it came with
            other = (_witness_outdated(seen, label, mid, running) or _witness_ahead(seen, label, mid, running)
                     if mid == wid else None)
            if other is not None:
                out.append(other)
            elif seen.get('release') != PEGAPROX_VERSION and mid != wid:
                out.append(_finding('RELEASE_MISMATCH', 'warn' if running else 'block',
                                    f"{label} runs release {seen.get('release') or 'unknown'}, this "
                                    f'instance {PEGAPROX_VERSION}. Every member has to run the '
                                    'same release.', mid))
            skew = seen.get('skew')
            if skew is None or abs(skew) > ha_vote.SKEW_LIMIT:
                off = 'an unknown time' if skew is None else f'{abs(skew):.0f} s'
                out.append(_finding('CLOCK_SKEW', 'warn' if running else 'block',
                                    f'The clock of {label} is {off} off. Automatic failover needs '
                                    f'{ha_vote.SKEW_LIMIT} s or less (NTP).', mid))
            if running and mid not in acked and (seen.get('mode') != ha_vote.MODE_AUTO
                                                 or seen.get('cfg_id') is None):
                # restored from before the switch, paired again, or never reached by a
                # renewal: a vote on paper that answers none
                out.append(_finding('MEMBER_MANUAL', 'warn', f'{label} holds no voter config of '
                                    'this group or is not in automatic mode: it neither votes '
                                    'nor renews the lease. One more failure may stop '
                                    'automation.', mid))
            elif founding and _holds_a_chain_of_its_own(seen, st):
                # the voter config made here would start a chain of its own, next to the
                # one that member holds
                out.append(_finding('MEMBER_AUTO', 'block', f'{label} says this group fails over '
                                    'automatically already, or is switching to it, and this '
                                    'instance holds no voter config of that. Let this instance '
                                    'follow the leader the group has, or unpair that member.', mid))
            if seen.get('dir_sync') is False:
                out.append(_finding('NO_DIR_SYNC', 'warn', f'The file system {label} keeps its '
                                    'state on cannot sync a directory: a vote it gives may not '
                                    'survive a power cut.', mid))
            if seen.get('write_failed') and mid == wid:
                # it acks the renewals that need no write all the same, and would first
                # say no at the vote that decides a failover
                out.append(_finding('STATE_NOT_WRITTEN', 'warn', f'{label} cannot write its state '
                                    'file: it gives no vote and takes no renewal that needs a '
                                    'write until it can. ' + _one_vote_less(n) + ' Check the '
                                    'disk of the witness host.', mid))
            elif seen.get('write_failed'):
                out.append(_finding('STATE_NOT_WRITTEN', 'warn', f'{label} could not write its HA '
                                    'state file the last time it tried: it gives no vote and '
                                    'takes no renewal that needs a write until it can. '
                                    + _one_vote_less(n) + ' Check its disk.', mid))
            if running and rec.get('role_seen') == ROLE_ACTIVE and not seen.get('holds'):
                out.append(_finding('ACTIVE_WITHOUT_LEASE', 'warn', f'{label} answers as an '
                                    'active and holds no lease: an instance made active by hand '
                                    'acts next to the leader the group elects. The leader tells '
                                    'it to step down.', mid))
        # a sentence that starts with the address (or the short id) keeps it as it is
        for f in out[start:]:
            if not f['text'].startswith(rec.get('url') or mid[:8]):
                f['text'] = f['text'][:1].upper() + f['text'][1:]
    if running:
        # a voter that left by hand, or was never a member of this instance's list: its
        # vote stands in the config and never answers
        here = {t['instance_id'] for t in targets} | {st['instance_id']}
        for vid in ha_vote.voter_ids(body):
            if vid not in here:
                out.append(_finding('VOTER_DOWN', 'warn', f'{vid[:8]} holds a vote in the voter '
                                    'config and is no member of this group (any more). One more '
                                    'failure may stop automation. Switch automatic failover off '
                                    'and on again to take the group as it is now.', vid))
    for mid in body.get('quarantined') or ():
        out.append(_finding('QUARANTINED', 'warn', f'{_label(mid)} came back with an older state. '
                            'Check it, then re-admit it.', mid))
    layout = _site_layout(st, body)
    w = body.get('witness') or {}
    wsite = layout['of'].get(w.get('id')) if w else ''
    # only where the data members span more than its site: in a group at one site the
    # witness has no third site to go to (design 3.4)
    if (wsite and any(layout['of'].get(v) == wsite for v in layout['data'])
            and any(layout['of'].get(v) not in ('', wsite) for v in layout['data'])):
        out.append(dict(_finding('WITNESS_SAME_SITE', 'warn', f"The witness shares site {wsite} with "
                                 'data members: losing that site may stop automation. It belongs at a '
                                 'third site.', w.get('id')), site=wsite))
    if n >= ha_vote.MIN_VOTERS and n % 2 == 0:
        lost = max(0, len(layout['counting']) - ha_vote.majority(n))
        out.append(_finding('EVEN_VOTERS', 'warn',
                            f"{n} votes survive the loss of {lost or 'no member'}, the same as {n - 1} would: the "
                            f'extra vote adds no tolerance, and a split into two halves of {n // 2} '
                            'leaves no leader on either side. Make one member a non-voter or add '
                            'a witness.'))
    if _zone_unreadable(st):
        out.append(_finding('ZONE_UNREADABLE', 'warn' if running else 'block',
                            f"This host has no time zone data for {st['timezone']}, the zone of "
                            "the group's schedules: they run by the clock of this host while it "
                            'leads. Install tzdata here.'))
    elif _zone(st.get('timezone')) is None and (running or not local_timezone()):
        # before the switch the group takes the zone of this instance where that can be
        # told (switch_auto_on); a group that runs without one evaluates its schedules by
        # the clock of whichever member leads
        out.append(_finding('NO_GROUP_ZONE', 'warn' if running else 'block',
                            'This group has no time zone for its schedules'
                            + (': they run by the clock of whichever member leads, and a failover '
                               'to a member in another zone shifts them. Set one.' if running else
                               ', and the zone of this instance cannot be told. Set one first.')))
    if _dir_sync['unsupported']:
        out.append(_finding('NO_DIR_SYNC', 'warn', 'The file system this instance keeps its state '
                            'on cannot sync a directory: a vote it gives may not survive a power '
                            'cut.'))
    if rt.write_failed:
        out.append(_finding('STATE_NOT_WRITTEN', 'warn', 'This instance could not write its HA '
                            f'state file the last time it tried ({rt.write_failed}): it gives no '
                            'vote and takes no renewal that needs a write until it can. Check '
                            'its disk.'))
    out += _site_findings(st, layout, n)
    clusters, found = _cluster_checks(st, layout)
    out += found
    out += _zone_findings(st, targets, wid)
    return {'findings': out, 'body': body, 'running': running, 'layout': layout, 'clusters': clusters}


# --- split safety (design 3.4 and 8) ---------------------------------------------------
#
# MK Oct 2026 (#625) - whether the group survives the loss of a site, from the sites an
# admin labelled the members with, and whether the clusters with node HA are ready for a
# leader that sits wherever the majority is (6.2). One pass in _group_checks: the switch's
# checklist and the split-safety panel read the same findings.

LEVELS = ('ok', 'info', 'warn', 'block')
LEADER_CHANGED_SHOWN = 600


def _site_of(st, iid, body=None):
    """The site label of the instance `iid` as this instance holds it: its own, a
    member's record, the witness record (or the voter config's word for a witness it
    holds no record of). '' for none."""
    if iid == st['instance_id']:
        return _clean_site(st.get('site')) or ''
    rec = (st.get('members') or {}).get(iid)
    if rec is not None:
        return _clean_site(rec.get('site')) or ''
    w = _witness(st)
    if w and w['instance_id'] == iid:
        return w['site'] or ''
    bw = (body or {}).get('witness') or {}
    return (_clean_site(bw.get('site')) or '') if bw.get('id') == iid else ''


def _site_layout(st, body):
    """The voters of `body` by site: {sites: [{site, voters, votes, candidates, members,
    witness, survives_loss}], unlabeled: [voter ids], candidates: [ids], data: [data
    voter ids], counting: [voter ids], of: {id: site}, n, m}. A candidate leads on its
    own (a data voter with may lead that is not quarantined); members lists every
    instance with that label, voters or not. survives_loss: the group elects a leader on
    its own once that site is gone (3.4: the votes that count elsewhere make a majority,
    and a candidate is among them). A quarantined vote is in n and m and counts nowhere."""
    voters = ha_vote.voter_ids(body)
    n = len(voters)
    m = ha_vote.majority(n) if n else 0
    quarantined = set(body.get('quarantined') or ())
    counting = [v for v in voters if v not in quarantined]
    wid = (body.get('witness') or {}).get('id')
    records = {r['id']: r for r in body.get('voters') or ()}
    data = [v for v in voters if v != wid]
    candidates = [v for v in data if records.get(v, {}).get('may_lead') and v not in quarantined]
    everyone = set(voters) | set(records) | {st['instance_id']} | set(st.get('members') or {})
    if wid:
        everyone.add(wid)
    of = {iid: _site_of(st, iid, body) for iid in everyone}
    sites = {}
    for iid in sorted(everyone):
        if of[iid]:
            sites.setdefault(of[iid], {'site': of[iid], 'voters': [], 'candidates': [], 'members': [],
                                       'witness': False})['members'].append(iid)
    for v in voters:
        if of[v]:
            entry = sites[of[v]]
            entry['voters'].append(v)
            entry['witness'] = entry['witness'] or v == wid
            if v in candidates:
                entry['candidates'].append(v)
    for entry in sites.values():
        entry['votes'] = len(entry['voters'])
        entry['survives_loss'] = bool(n and _counting_outside(counting, entry) >= m
                                      and any(c not in entry['candidates'] for c in candidates))
    return {'sites': [sites[s] for s in sorted(sites)], 'unlabeled': [v for v in voters if not of[v]],
            'candidates': candidates, 'data': data, 'counting': counting, 'of': of, 'n': n, 'm': m}


def _counting_outside(counting, entry):
    """The votes that count and are not at the site of `entry` (_site_layout)."""
    return sum(1 for v in counting if v not in entry['voters'])


def _names(st, ids):
    return ', '.join(_who(st, i) for i in ids)


def _who(st, iid):
    """How an instance is named in a text: its address, the short id where none is known."""
    if not iid:
        return ''
    if iid == st['instance_id']:
        return st.get('own_url') or iid[:8]
    rec = (st.get('members') or {}).get(iid)
    if rec is not None:
        return rec.get('url') or iid[:8]
    w = _witness(st)
    if w and w['instance_id'] == iid:
        return f"the witness {w['url'] or iid[:8]}"
    return iid[:8]


def _site_findings(st, layout, n):
    """What the sites say about a split (3.4), and who leads on its own."""
    out = []
    m, sites, candidates = layout['m'], layout['sites'], layout['candidates']
    if n and not candidates:
        out.append(_finding('NO_CANDIDATE', 'warn', 'No member leads on its own (may lead is off for '
                            'every data member with a vote): when the leader fails, automation stops '
                            'until an admin uses Make leader.'))
    if layout['unlabeled']:
        out.append(dict(_finding('NO_SITE_LABELS', 'warn', 'Set a site for each member to check split '
                                 f"safety (no site yet: {_names(st, layout['unlabeled'])})."),
                        members=list(layout['unlabeled'])))
        return out
    if n < ha_vote.MIN_VOTERS or not sites:
        # TOO_FEW_VOTERS says what there is to say
        return out
    counting = layout['counting']
    if len(sites) == 1:
        k = max(0, len(counting) - m)
        lost = 'no member' if not k else f"any {k} member{'' if k == 1 else 's'}"
        out.append(dict(_finding('ALL_ONE_SITE', 'info', f'Survives the loss of {lost}. A site outage '
                                 'stops PegaProx automation until the site is back.'), site=sites[0]['site']))
        return out
    fatal = [e for e in sites if _counting_outside(counting, e) < m]
    if len(sites) == 2 and len(fatal) == 2:
        out.append(_finding('TWO_SITES_NO_THIRD_VOTE', 'warn', 'Two sites need a third vote at a third '
                            'location, or a WAN cut stops automation in both.'))
    else:
        for e in fatal:
            out.append(dict(_finding('SITE_HOLDS_MAJORITY', 'warn', f"Losing site {e['site']} stops "
                                     'automation everywhere.'), site=e['site']))
    lead = sorted({layout['of'][c] for c in candidates})
    if len(lead) == 1 and lead[0] not in {e['site'] for e in fatal}:
        out.append(dict(_finding('CANDIDATES_ONE_SITE', 'warn', f'Only members in {lead[0]} lead on '
                                 f'their own. Losing {lead[0]} stops automation until an admin uses '
                                 '"Make leader".'), site=lead[0]))
    return out


def _zone_findings(st, targets, wid):
    """TZ_MISMATCH: a member that runs in another zone than the group's schedules. Since
    the owner decision of 01.10.2026 (Q11) members may: the schedules run in the group's
    zone whichever member leads, so this is something to know, not to fix."""
    zone = _zone(st.get('timezone')) and st['timezone']
    if not zone:
        return []
    rt, now, out = _rt(), time.monotonic(), []
    for rec in targets:
        mid = rec['instance_id']
        seen = rt.seen.get(mid) or {}
        theirs = seen.get('zone')
        if (mid == wid or not theirs or now - seen.get('at', -1e9) > LEASE_SEEN_FRESH
                or theirs == zone):
            continue
        out.append(_finding('TZ_MISMATCH', 'info', f"{rec.get('url') or mid[:8]} runs in time zone "
                            f"{theirs}. The group's schedules run in {zone} whichever member leads.",
                            mid))
    return out


def _cluster_nodes(mgr):
    """The node names of a cluster as its manager knows them without asking it: the HA
    monitor's view, the agents seen and the fences configured."""
    names = set()
    for source in (getattr(mgr, 'ha_node_status', None), (mgr.ha_config or {}).get('fence_agent_versions'),
                   (mgr.ha_config or {}).get('fencing')):
        if isinstance(source, dict):
            names.update(k for k in list(source) if isinstance(k, str) and k)
    return sorted(names)


def _cluster_row(st, cid, mgr, layout, reach_of, url_ids):
    """One cluster with node HA for the split-safety panel, and its findings. Only what
    the manager holds in memory: nothing here goes to a node."""
    name = str(getattr(getattr(mgr, 'config', None), 'name', None) or cid)
    row = {'id': cid, 'name': name, 'kind': 'proxmox', 'nodes': [], 'agents': {},
           'agent_version': None, 'fence': {}, 'fence_verified': [], 'ready': None, 'not_ready': [],
           'two_node': False, 'unsafe_two_node': False, 'claim': None,
           'reach': {iid: ok for iid, ok in reach_of.items() if ok is not None},
           'reach_sites': [], 'unreachable_from': {}, 'unreachable_checked_at': None}
    sites = sorted({layout['of'].get(iid) for iid, ok in row['reach'].items()
                    if ok and iid in layout['data'] and layout['of'].get(iid)})
    row['reach_sites'] = sites
    found = []
    # only where every other site with a data voter said it does not reach it: a site
    # nobody heard from says nothing
    others = [[row['reach'][v] for v in e['voters'] if v in layout['data'] and v in row['reach']]
              for e in layout['sites'] if e['site'] not in sites and any(v in layout['data'] for v in e['voters'])]
    if len(sites) == 1 and others and all(said and not any(said) for said in others) and not layout['unlabeled']:
        found.append(dict(_finding('CLUSTER_ONE_SITE', 'info', f'Cluster {name} is reachable only from '
                                   f'members in site {sites[0]}.'), cluster=cid, site=sites[0]))
    if not callable(getattr(mgr, '_ha_claim_status', None)):
        # node HA of another kind (an XCP-ng pool): none of the rules of 6.2 apply
        row['kind'] = 'other'
        return row, found
    cfg = mgr.ha_config or {}
    nodes = _cluster_nodes(mgr)
    want = getattr(mgr, 'FENCE_AGENT_VERSION', 2)
    seen = cfg.get('fence_agent_versions') if isinstance(cfg.get('fence_agent_versions'), dict) else {}
    agents = {n: (seen.get(n) if type(seen.get(n)) is int else 0) for n in nodes}
    fencing = cfg.get('fencing') if isinstance(cfg.get('fencing'), dict) else {}
    fence = {n: (str((fencing.get(n) or {}).get('type') or '').lower() or None) for n in nodes}
    verified = [n for n in nodes if mgr._ha_fence_readable(n)]
    not_ready = [n for n in nodes if agents[n] != want and n not in verified]
    strategy = cfg.get('fence_strategy') if isinstance(cfg.get('fence_strategy'), dict) else {}
    votes = strategy.get('expected_votes')
    # corosync's word where it was read (a qdevice makes two nodes three votes), the
    # node count where not
    two = bool(mgr._ha_forces_quorum() or strategy.get('two_node_flag') is True
               or (votes == 2 if type(votes) is int else len(nodes) == 2))
    unsafe = bool(mgr._ha_unsafe_two_node())
    claim = mgr._ha_claim_status()
    row.update(nodes=nodes, agents=agents, agent_version=want, fence=fence, fence_verified=verified,
               ready=(not not_ready) if nodes else None, not_ready=not_ready, two_node=two,
               unsafe_two_node=unsafe,
               claim={k: claim.get(k) for k in ('enabled', 'state', 'epoch', 'instance', 'checked_at', 'residual')})
    # who the nodes of a two-node cluster could not reach, at the last agent check
    checked = cfg.get('agent_unreachable') if isinstance(cfg.get('agent_unreachable'), dict) else {}
    for node, urls in sorted((checked.get('nodes') or {}).items()):
        for url in urls if isinstance(urls, list) else ():
            iid = url_ids.get(str(url).rstrip('/'), str(url))
            row['unreachable_from'].setdefault(iid, []).append(node)
    row['unreachable_checked_at'] = checked.get('at') if isinstance(checked.get('at'), str) else None
    fenceless = two and not unsafe and (not nodes or len(verified) < len(nodes))
    if fenceless:
        found.append(dict(_finding('TWO_NODE_NO_FENCE', 'warn', f'Two-node cluster {name} has no verified '
                                   'hardware fence. PegaProx will not recover it automatically.'), cluster=cid))
    elif not row['ready']:
        found.append(dict(_finding('RECOVERY_NOT_READY', 'warn', f'Cluster {name}: node recovery needs '
                                   'agents v2 on every node or a verified IPMI fence.'), cluster=cid,
                          nodes=list(not_ready)))
    state = claim.get('state')
    if claim.get('enabled') and state == 'unreachable':
        found.append(dict(_finding('NO_CLAIM', 'warn', f'Cluster {name} has no SSH access, so it carries no '
                                   'leader claim.'), cluster=cid))
    elif claim.get('enabled') and state in ('higher', 'same', 'unreadable', 'foreign'):
        who, ep = claim.get('instance'), claim.get('epoch')
        if who and ep is not None:
            text = (f'Cluster {name} is claimed by {_who(st, who)} at epoch {ep}. Nothing acts on it until '
                    'the claim is released.')
        else:
            text = (f'Cluster {name} carries a claim file that names no instance of this group. Nothing '
                    'acts on it until the claim is released.')
        found.append(dict(_finding('FOREIGN_CLAIM', 'block', text), cluster=cid))
    return row, found


def _cluster_checks(st, layout):
    """([cluster row], [finding]) for every cluster with node HA this instance runs a
    manager for (an instance that runs none, a standby with the live view off, has
    none). A cluster whose manager cannot say is left out; never raises."""
    try:
        from pegaprox.globals import cluster_managers
        todo = [(str(cid), mgr) for cid, mgr in sorted(list(cluster_managers.items()), key=lambda x: str(x[0]))
                if getattr(mgr, 'ha_enabled', False) is True]
    except Exception:
        return [], []
    if not todo:
        return [], []
    rt, now, me = _rt(), time.monotonic(), st['instance_id']
    fresh = {mid: seen for mid, seen in list(rt.seen.items())
             if now - seen.get('at', -1e9) <= LEASE_SEEN_FRESH and isinstance(seen.get('reach'), dict)}
    url_ids = {(rec.get('url') or '').rstrip('/'): mid for mid, rec in (st.get('members') or {}).items()
               if rec.get('url')}
    if st.get('own_url'):
        url_ids[st['own_url'].rstrip('/')] = me
    rows, found = [], []
    for cid, mgr in todo:
        reach_of = {me: rt.reach['clusters'].get(cid)}
        for mid, seen in fresh.items():
            reach_of[mid] = seen['reach'].get(cid)
        try:
            row, said = _cluster_row(st, cid, mgr, layout, reach_of, url_ids)
        except Exception as e:
            logging.debug(f"[HA] split safety: cluster {cid}: {e}")
            continue
        rows.append(row)
        found += said
    return rows, found


def split_safety(st=None, checks=None):
    """public_status.split_safety, once this release offers automatic failover, on an
    instance of a group: {voters, majority, tolerates, level, sites, unlabeled,
    clusters, findings}. findings is auto_findings, the list the switch goes by; level
    is the worst of them as the switch takes them (_gate: a block about one cluster is a
    warn there), 'ok' for none. tolerates: how many of the votes that count may go (a
    quarantined one does not count). None on an instance of its own and while automatic
    failover is not offered."""
    st = st or _load()
    if not ha_vote.AUTO_MODE_SHIPPED or st['role'] == ROLE_STANDALONE:
        return None
    checks = checks or _group_checks(st)
    layout, findings = checks['layout'], checks['findings']
    worst = max((LEVELS.index(_gate(f)) for f in findings if _gate(f) in LEVELS), default=0)
    return {'voters': layout['n'], 'majority': layout['m'],
            'tolerates': max(0, len(layout['counting']) - layout['m']),
            'level': LEVELS[worst], 'sites': layout['sites'], 'unlabeled': layout['unlabeled'],
            'clusters': checks['clusters'], 'findings': findings}


def _gate(finding):
    """What a finding does to the switch (switch_auto_on): a block about one cluster
    stops nothing but that cluster, so it wants a tick like a warn."""
    level = finding.get('level')
    return 'warn' if level == 'block' and finding.get('cluster') else level


def _lease_found(st, lease_s):
    """The lease state a manual active starts the switch from: a voter config in manual
    mode that names the group as it is now. The first one founds the chain. Later the
    chain goes on with one more config when the group changed since, and it starts over
    when this instance is no data voter of the chain it holds (it joined later and was
    promoted): the members take a new start from the instance they follow
    (_lease_adopt). Never where that would found a chain while a member says the group
    is automatic already. Called under the state lock; raises HaError."""
    me, ep = st['instance_id'], int(st.get('epoch') or 0)
    if _founds_chain(st):
        # never next to a chain the group holds: its members would take the calls of two
        # leaders (auto_findings says the same before, as MEMBER_AUTO)
        rt, now = _rt(), time.monotonic()
        for mid in st.get('members') or {}:
            seen = rt.seen.get(mid) or {}
            if now - seen.get('at', -1e9) <= LEASE_SEEN_FRESH and _holds_a_chain_of_its_own(seen, st):
                raise HaError(f'Member {_label(mid)} says this group fails over automatically '
                              'already, or is switching to it')
    private = _signer().private
    if private is None:
        raise HaError('This instance has no key pair to sign a voter config with')

    def sign(message):
        return base64.b64encode(private.sign(message)).decode()
    held = _lease(st)
    kept = (held['cfg']['body'].get('quarantined') or ()) if held else ()
    body = _voter_body(st, lease_s, kept)
    why = ha_vote.body_error(body)
    if why:
        raise HaError(f'The group cannot vote as it is ({why})')
    if held is None:
        fresh = ha_vote.new_state(ha_vote.make_cfg(None, ep, me, body, sign),
                                  role=ha_vote.ROLE_ACTIVE, epoch=ep)
        block = {k: fresh.get(k) for k in _LEASE_KEYS}
        block['floor_cv'] = list(CV_ZERO)
    else:
        prev = held['cfg']
        if prev['body'] == body:
            return
        block = dict(held)
        if held.get('epoch') != ep:
            # the epoch moved by hand since the vote on record: it is of another epoch
            block['voted_for'] = None
        if me in ha_vote.CfgView(prev).data:
            block['cfg'] = ha_vote.make_cfg(prev, ep, me, body, sign)
            block['cfg_chain'] = (list(held.get('cfg_chain') or []) + [prev])[-ha_vote.CFG_KEEP:]
        else:
            pid = ha_vote.pair(prev['id'])
            cfg = {'id': [max(ep, pid[0]), pid[1] + 1], 'prev': '', 'by': me, 'body': body}
            cfg['sig'] = sign(bytes.fromhex(ha_vote.cfg_digest(cfg)))
            block.update(cfg=cfg, cfg_chain=[])
    block.update(epoch=ep, mode=ha_vote.MODE_MANUAL)
    _commit_locked(dict(st, lease=block))


def switch_auto_on(lease_s=ha_vote.LEASE_DEFAULT, accept=()):
    """Leader of a manual group: start the switch to automatic failover (4.13). The
    voter config goes to every member as pending. Once all of them hold it, this
    instance commits automatic mode and leads with a lease from then on; a member that
    does not take it within ten minutes takes the group back to manual mode. `accept`
    names the warnings the admin ticked. Raises AutoRefused with the findings that
    stand in the way or want a tick, HaError for anything else. Returns the ids of the
    members it waits for."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        raise HaError(ha_vote.NOT_SHIPPED_ERROR)
    if type(lease_s) is not int or not ha_vote.LEASE_MIN <= lease_s <= ha_vote.LEASE_MAX:
        raise HaError(LEASE_RANGE_ERROR)
    rt = _rt()
    zoned = None
    if role() == ROLE_ACTIVE and mode() == ha_vote.MODE_MANUAL:
        # what every member says right now, not what the watch heard a while ago
        try:
            _ask_members(5)
            _ask_witness()
        except Exception as e:
            logging.warning(f"[HA] could not ask the members before the switch: {e}")
    with rt.lock:
        with _lock:
            st = _load()
            if st.get('broken'):
                raise HaError('The HA state file cannot be read')
            if mode(st) != ha_vote.MODE_MANUAL or st.get('leader'):
                raise HaError('Automatic failover is on already, or on its way')
            if st['role'] != ROLE_ACTIVE or not st.get('members'):
                raise HaError('Automatic failover is switched on on the leader of a group')
            findings = auto_findings(st, lease_s)
            # a block about one cluster stops nothing but that cluster: it wants a tick
            # (_gate, which the split-safety panel's level goes by as well)
            blocks = [f for f in findings if _gate(f) == 'block']
            if blocks:
                raise AutoRefused(blocks[0]['text'], findings)
            open_ = [f for f in findings if _gate(f) == 'warn' and f['code'] not in accept]
            if open_:
                raise AutoRefused(open_[0]['text'], findings, confirm=True)
            if _zone(st.get('timezone')) is None and local_timezone():
                # a group from before the group zone: its schedules ran by this
                # instance's clock so far, and keep those hours whichever member leads
                # from now on (the findings refused a zone that cannot be told)
                st = dict(st, timezone=local_timezone())
                _commit_locked(st)
                zoned = st['timezone']
            _lease_found(st, lease_s)
        if rt.node is not None:
            rt.stale = True
        node = _lease_node(rt)
        if node is None:
            raise HaError('The voter config could not be started')
        why = node.switch_on()
        if why:
            raise HaError(ha_vote.NOT_SHIPPED_ERROR if why == 'NOT_SHIPPED' else
                          f'The switch could not be started ({why})')
        waiting = sorted(node.view.members - {st['instance_id']})
    _lease_after(rt)
    lease_start()
    if zoned:
        _audit('ha.timezone_changed', f"schedules are evaluated in {zoned} from now on, the zone "
                                      "of this instance (the group had none)")
        nudge_members()
    return waiting


def _switch_taken_back(st, automatic=False):
    """An active stops leading by hand (step_down, step_aside) while a switch to
    automatic failover it started is still pending: its lease block with that switch
    taken back, one more voter config in manual mode, for the write that changes the
    role. As a standby it can take nothing back, and it and every member that took the
    pending config would hold it for good, with none among them to promote.

    None when no switch of its own is pending here, when the config cannot be signed,
    and where the group fails over automatically already (`automatic`, or a member
    said so when it was last asked): a manual config here would let this instance be
    promoted by hand inside that group. A member that says automatic with a config
    older than the pending one held here is no such group: it missed a switch back
    this chain went through, and says so until it campaigns. Called under the state
    lock; never raises."""
    lease = _lease(st)
    me = st['instance_id']
    if (not ha_vote.AUTO_MODE_SHIPPED or lease is None or lease.get('mode') != ha_vote.MODE_PENDING
            or lease['cfg'].get('by') != me):
        return None
    try:
        rt = _rts.get(me)
        # however long ago: an answer that is out of date costs a config of its own
        # that this instance keeps, never a promotion by hand next to a leader. The
        # witness holds no lease; a promise it keeps is the lease of the one it names
        said = list(rt.seen.items()) if rt is not None else ()
        pending = ha_vote.pair(lease['cfg']['id'])
        wid = (_witness(st) or {}).get('instance_id')
        if automatic or any(seen.get('holds') is True or (
                mid == wid and seen.get('holder') and seen.get('mode') != ha_vote.MODE_MANUAL) or (
                seen.get('mode') == ha_vote.MODE_AUTO
                and (seen.get('cfg_id') is None or seen['cfg_id'] >= pending)) for mid, seen in said):
            return None
        private = _signer().private
        if private is None:
            return None
        prev = lease['cfg']
        # under the epoch the switch was made in: a standby that takes it back is at the
        # epoch of the active it follows, whose own configs have to come after this one
        cfg = ha_vote.make_cfg(prev, ha_vote.pair(prev['id'])[0], me,
                               dict(prev['body'], mode=ha_vote.MODE_MANUAL),
                               lambda message: base64.b64encode(private.sign(message)).decode())
    except Exception as e:
        logging.warning(f"[HA] could not take the pending switch back before leaving the lead: {e}")
        return None
    block = dict(lease, cfg=cfg, mode=ha_vote.MODE_MANUAL,
                 cfg_chain=(list(lease.get('cfg_chain') or []) + [prev])[-ha_vote.CFG_KEEP:],
                 # one more write of the lease state, counted like the node's own
                 gen=(lease['gen'] if type(lease.get('gen')) is int else 0) + 1)
    block.pop('pending_since', None)
    return block


def _hand_switch_back(lease, epoch, targets, me, settled=False):
    """The manual config of `lease`, which took a pending switch back, to the members in
    `targets`: one switch round as the node sends it after a cancel, side by side and
    each with the two seconds of a lease call, marked taken_back: only a member that
    holds a pending config takes anything from it, and only what hangs off a config it
    holds (lease_request). `epoch` is the one this instance (`me`) is at now. `settled`:
    the sender is the active of the manual group, so the config is the group's, and the
    member knows that from here on (_manual_known). Returns the ids that hold the config
    after it."""
    cfg = lease['cfg']
    body = {'epoch': epoch, 'leader': me, 'switch': True, 'taken_back': True,
            'lease_s': cfg['body']['lease_s'], 'chain': list(lease.get('cfg_chain') or []) + [cfg]}
    if settled:
        body['settled'] = True
    results = _fan_out([lambda mid=mid: _lease_fetch((mid, 'renew', body)) for mid in targets],
                       LEASE_CALL_TIMEOUT + 1)
    digest = ha_vote.cfg_digest(cfg)
    return [mid for mid, (ans, err) in zip(targets, results)
            if err is None and isinstance(ans, dict) and ans.get('cfg_digest') == digest]


def _tell_switch_back(lease, epoch, skip=None):
    """After _switch_taken_back, once the state is written and before the process
    leaves: the members hear of it (_hand_switch_back). `skip` is the member this
    instance stepped down to, an active that takes no config. A member this does not
    reach gets it with a later look at the group (_switch_back_again), or takes the
    config of the active it follows once that one switches (_gives_way). Never raises."""
    try:
        cfg = lease['cfg']
        targets = sorted(ha_vote.CfgView(cfg).members - {cfg['by'], skip})
        took = _hand_switch_back(lease, epoch, targets, cfg['by'])
        text = ('the switch to automatic failover was taken back: this instance, which started '
                f'it, leads no more ({len(took)} of {len(targets)} other member(s) hold the manual '
                'config)')
        logging.warning(f"[HA] {text}")
        _audit('ha.auto_cancelled', text)
    except Exception as e:
        logging.warning(f"[HA] could not tell the members that the switch was taken back: {e}")


def _switch_back_again():
    """With every look at the group: a member that still says it holds a pending switch
    to automatic failover, older than the manual voter config held here, gets the chain
    up to that config. It was away while the switch went through and back, or the word
    of the instance that took the switch back did not reach it; a manual active sends
    no renewals, and a pending member never campaigns, so nothing else reaches it.
    Three instances hand it out: the active of a manual group, whatever lies between
    the pending config and its own; the instance that took its own switch back as it
    left the lead; and the instance that started a switch still pending here while it
    is a standby, once the active it follows answers as a manual one - it takes its
    switch back first, as it would have when it left the lead (_switch_taken_back).
    Never while a member says it holds a lease. Returns the ids that took the config."""
    st = _load()
    lease, me = _lease(st), st['instance_id']
    if lease is None or st.get('removed') or st.get('broken'):
        return []
    rt, now = _rt(), time.monotonic()
    known = st.get('members') or {}
    fresh = {mid: seen for mid, seen in list(rt.seen.items())
             if mid in known and now - seen.get('at', -1e9) <= LEASE_SEEN_FRESH}
    if any(seen.get('holds') is True for seen in fresh.values()):
        return []
    cfg = lease['cfg']
    before = (lease.get('cfg_chain') or [None])[-1]
    own_back = (isinstance(before, dict) and before.get('by') == me and cfg.get('by') == me
                and (before.get('body') or {}).get('mode') == ha_vote.MODE_PENDING)
    if st['role'] == ROLE_STANDBY and lease.get('mode') == ha_vote.MODE_PENDING and cfg.get('by') == me:
        src = st.get('source')
        if not ((fresh.get(src) or {}).get('mode') == ha_vote.MODE_MANUAL
                and (known.get(src) or {}).get('role_seen') == ROLE_ACTIVE):
            return []
        with _lock:
            st = _load()
            back = _switch_taken_back(st) if st['role'] == ROLE_STANDBY else None
            if back is None:
                return []
            _commit_locked(dict(st, lease=back))
        lease = back
        text = (f'the switch to automatic failover was taken back: this instance, which started it, '
                f'is a standby of {_label(src)}, which runs the group by hand')
        logging.warning(f"[HA] {text}")
        _audit('ha.auto_cancelled', text)
    elif lease.get('mode') != ha_vote.MODE_MANUAL or st.get('leader') or not (
            st['role'] == ROLE_ACTIVE or own_back):
        return []
    mine = ha_vote.pair(lease['cfg']['id'])
    targets = sorted(mid for mid, seen in fresh.items()
                     if seen.get('mode') == ha_vote.MODE_PENDING and seen.get('cfg_id') is not None
                     and seen['cfg_id'] < mine)
    if not targets:
        return []
    took = _hand_switch_back(lease, int(st.get('epoch') or 0), targets, me,
                             settled=st['role'] == ROLE_ACTIVE and not st.get('leader'))
    if took:
        logging.warning(f"[HA] {len(took)} member(s) that still held a pending switch took the "
                        "manual config held here")
    return took


def switch_auto_off():
    """Leader: back to manual mode (4.13), in force once a majority holds the change; no
    member that is out of reach holds it up. Until then the lease is in force and the
    group's mode is automatic (mode); a leader that loses its lease first drops the
    change. On the instance that started a switch that is still pending: take that
    back. Returns 'off' or 'cancelled'; raises StateNotWritten when the change could
    not be written."""
    rt = _rt()
    with rt.lock:
        node = _lease_node(rt)
        if node is not None and node.view.mode == ha_vote.MODE_MANUAL and node.lease_mode():
            raise HaError('Automatic failover is being switched off: it is off once a majority of '
                          'the members holds the change')
        if node is None or node.view.mode == ha_vote.MODE_MANUAL:
            raise HaError('This group is in manual mode')
        if node.view.mode == ha_vote.MODE_PENDING:
            if node.switch_cancel():
                raise HaError('The switch is pending on the instance that started it - take it '
                              'back there')
            done = 'cancelled'
        else:
            why = node.switch_off()
            if why == 'BUSY':
                raise HaError('A change of the voter config is on its way - try again in a moment')
            if why == 'WRITE_FAILED':
                raise StateNotWritten('The voter config could not be written to the state file - '
                                      'automatic failover stays on')
            if why:
                raise NoLease('Automatic failover is switched off on the leader, while it holds '
                              'the lease')
            done = 'off'
    _lease_after(rt)
    return done


def set_lease_seconds(lease_s):
    """Leader of an automatic group: another lease length, as a change of the voter
    config. Returns True when one was asked for."""
    if type(lease_s) is not int or not ha_vote.LEASE_MIN <= lease_s <= ha_vote.LEASE_MAX:
        raise HaError(LEASE_RANGE_ERROR)
    rt = _rt()
    with rt.lock:
        node = _lease_node(rt)
        if node is None or not node.is_active():
            raise NoLease(NO_LEASE_ERROR)
        if node.view.mode != ha_vote.MODE_AUTO:
            raise HaError('Automatic failover is being switched off: it is off once a majority of '
                          'the members holds the change')
        if node.view.lease_s == lease_s:
            return False
        node.change_cfg(lambda body: dict(body, lease_s=lease_s))
    _lease_after(rt)
    return True


def readmit_member(member_id):
    """Leader: take a quarantined voter back, after an admin looked at it. Its acks and
    votes count again once the change reached a majority."""
    rt = _rt()
    with rt.lock:
        node = _lease_node(rt)
        if node is None or not node.is_active():
            raise NoLease(NO_LEASE_ERROR)
        why = node.readmit(member_id)
    if why == 'NOT_QUARANTINED':
        raise HaError('That member is not quarantined')
    if why:
        raise NoLease(NO_LEASE_ERROR)
    _lease_after(rt)


def _pairing_refusal(st):
    """Why this instance takes no new member right now, '' when it does: a switch to
    automatic failover is under way, or the group is automatic and this instance does
    not hold its lease."""
    if mode(st) == ha_vote.MODE_PENDING:
        return AUTO_PENDING_ERROR
    if _lease_mode(st) and not holds_lease():
        return NO_LEASE_ERROR
    return ''


def _lease_member_joined(member_id, public_key):
    """accept_pairing in an automatic group: the newcomer goes into the voter config,
    without a vote until an admin gives it one. An instance that pairs again comes with
    a new key and loses the vote it had. Never raises."""
    try:
        st = _load()
        node = _lease_live(st) if _lease_mode(st) else None
        if node is None:
            return

        def add(body):
            voters = [rec for rec in body['voters'] if rec['id'] != member_id]
            voters.append({'id': member_id, 'public_key': public_key, 'voter': False,
                           'may_lead': True, 'site': ''})
            return dict(body, voters=sorted(voters, key=lambda rec: rec['id']),
                        quarantined=[q for q in body.get('quarantined') or () if q != member_id])
        rt = _rt()
        with rt.lock:
            node.change_cfg(add)
        rt.wake.set()
    except Exception as e:
        logging.warning(f"[HA] could not put member {member_id} into the voter config: {e}")


def when_active(fn, name):
    """Run fn once this instance may act: at once where it may already, which in a
    manual group is every instance that is no standby. In the leader's process of an
    automatic group whose takeover wait is still on it runs in the background as soon
    as is_active() says so, and never when the process stops leading first. On a
    standby it does not run. Returns True when fn ran at once."""
    if is_active():
        fn()
        return True
    if not acting_process():
        return False

    def wait():
        while acting_process():
            if is_active():
                try:
                    fn()
                except Exception as e:
                    logging.error(f"[HA] {name}, started once this instance may act: {e}")
                return
            time.sleep(1)
    _lease_spawn(wait, name)
    return False


def _lease_wait(done, seconds):
    done.wait(seconds)


def confirm_lease(need=ha_vote.Timings().need):
    """True once a majority renewed this leader's lease in a round that started after
    this call, with at least `need` seconds of it left. In manual mode and on an
    instance of its own it is the role, at once. A caller that no round out can serve
    starts one at once; past ha_vote.CONFIRM_IN_FLIGHT rounds out, callers share the
    next one (ha_vote.Node.confirm). A write costs about one round trip to the fastest
    majority.

    A yes leaves a token in this thread (or greenlet) for the transport guard: one call
    goes out on it while `need` seconds of that lease are left, the next one asks for a
    round of its own (guard). A no leaves none: this thread is in no confirmed step any
    more. In manual mode there is none, the guard asks for none there."""
    st = _load()
    if not _lease_mode(st):
        return st['role'] != ROLE_STANDBY
    rt = _rt()
    done, said = threading.Event(), []
    with rt.lock:
        node = _lease_node(rt)
        if node is None:
            _guard_tls.token = None
            return False
        gen = rt.gen

        def answer(ok):
            # where the lease and the clock checks stand as the round comes back is what
            # the token goes by
            said.append((bool(ok), node.lease_until, rt.jumps))
            done.set()
        node.confirm(need, answer)
        limit = node.t.confirm_timeout + node.t.renew_timeout + 1
        rt.due = node.next_wake()
    _lease_after(rt)
    _lease_wait(done, limit)
    ok = bool(said and said[0][0])
    _guard_tls.token = _Token(rt.instance, gen, said[0][2], said[0][1], float(need)) if ok else None
    return ok


def no_lease():
    """None while this instance may take a change. In an automatic group, on the leader
    whose lease is not there (yet): what to tell the caller, {error, retry_after};
    retry_after is None while nobody knows when."""
    st = _load()
    if st['role'] == ROLE_STANDBY or not _lease_mode(st):
        return None
    node = _lease_live(st)
    if node is not None and node.is_active():
        return None
    if node is not None and node.holds_lease() and node.acting_from < float('inf'):
        wait = max(1, int(node.acting_from - ha_clock()) + 1)
        return {'error': f'The leader is taking over - changes resume in {wait} s',
                'retry_after': wait}
    return {'error': NO_LEASE_ERROR, 'retry_after': None}


# --- who leads, as each instance saw it change (the status line and the banners) ---
#
# MK Oct 2026 (#625) - 'leader_seen' in the state file: {id, epoch, from, since}, the
# leader this instance last knew and since when it leads (from: the one before it). The
# winner notes it when it wins, a member with the first renewal of a new leader, taking
# the moment the leader sends along so every member names the same one. since stays
# None while this instance saw no change (the switch, the first leader it knew).

def _leader_seen(st):
    rec = st.get('leader_seen')
    if (not isinstance(rec, dict) or not isinstance(rec.get('id'), str) or not _ID_RE.fullmatch(rec['id'])
            or _epoch_value(rec.get('epoch')) is None):
        return None
    frm, since = rec.get('from'), rec.get('since')
    return {'id': rec['id'], 'epoch': rec['epoch'],
            'from': frm if isinstance(frm, str) and _ID_RE.fullmatch(frm) else None,
            'since': since if _since_ok(since) else None}


def _since_ok(value):
    """Whether `value` is a moment a leader may say it leads since: an ISO time with its
    zone, not ahead of this clock by more than the signature window."""
    if not isinstance(value, str) or not 0 < len(value) <= 40:
        return False
    try:
        at = datetime.fromisoformat(value)
    except ValueError:
        return False
    return at.tzinfo is not None and at.timestamp() <= time.time() + SIGNATURE_WINDOW


def _leader_seen_after(st, leader_id, epoch, prev=None, since=None):
    """The record after this instance learned that `leader_id` leads at `epoch`, None when
    it stays as it is. `prev` is the leader it knew where the record names none, `since`
    what the leader says (taken only when it can be one, _since_ok)."""
    if not isinstance(leader_id, str) or not _ID_RE.fullmatch(leader_id) or _epoch_value(epoch) is None:
        return None
    old = _leader_seen(st)
    if old is not None and epoch < old['epoch']:
        return None
    if old is not None and old['id'] == leader_id:
        return dict(old, epoch=epoch) if epoch > old['epoch'] else None
    before = (old or {}).get('id') or (prev if isinstance(prev, str) and _ID_RE.fullmatch(prev) else None)
    if before == leader_id:
        before = None
    return {'id': leader_id, 'epoch': epoch, 'from': before,
            'since': (since if _since_ok(since) else _now()) if before else None}


def _note_leader(leader_id, epoch, prev=None):
    """This instance leads now (it won, or switched the group on). Never raises."""
    try:
        with _lock:
            st = _load()
            seen = _leader_seen_after(st, leader_id, epoch, prev=prev)
            if seen is not None:
                _commit_locked(dict(st, leader_seen=seen))
    except Exception as e:
        logging.warning(f"[HA] could not note the change of the leader: {e}")


def _leader_change(st):
    """The last change of the leader this instance saw: {from, from_url, to, to_url,
    epoch, at}, None when it saw none."""
    seen = _leader_seen(st)
    if seen is None or not seen['since']:
        return None
    return {'from': seen['from'], 'from_url': _who(st, seen['from']) if seen['from'] else '',
            'to': seen['id'], 'to_url': _who(st, seen['id']), 'epoch': seen['epoch'], 'at': seen['since']}


def lease_banner(st=None, names=False):
    """What every signed-in user is told about an automatic group, {} anywhere else (a
    manual group, an instance of its own). automatic: true, and at most one of
    no_leader (true: changes and automation are paused, consoles keep working) and
    takeover ({resume_in}: the leader acts in about that many seconds), and
    leader_changed ({at}) for LEADER_CHANGED_SHOWN after a change. With `names`, for
    an admin the HA tab is open to, the addresses as well: takeover.leader and
    leader_changed.to and .from. No epoch of the lease for anyone."""
    st = st or _load()
    if not ha_vote.AUTO_MODE_SHIPPED or not _lease_mode(st):
        return {}
    out = {'automatic': True}
    node = _lease_live(st)
    clock = ha_clock()
    taker = None
    if st.get('leader') and st['role'] == ROLE_ACTIVE:
        if node is not None and node.is_active():
            pass
        elif node is not None and node.holds_lease() and node.acting_from < float('inf'):
            taker, out['takeover'] = st['instance_id'], {'resume_in': max(1, int(node.acting_from - clock) + 1)}
        else:
            out['no_leader'] = True
    elif node is not None:
        if node.promise_to and clock < node.promise_until:
            rt = _rt()
            take = rt.takeover
            if take is not None and take[0] == node.promise_to and clock < take[1]:
                taker, out['takeover'] = take[0], {'resume_in': max(1, int(take[1] - clock) + 1)}
        else:
            out['no_leader'] = True
    if taker is not None and names:
        out['takeover']['leader'] = _who(st, taker)
    change = _leader_change(st)
    if change is not None:
        try:
            ago = time.time() - datetime.fromisoformat(change['at']).timestamp()
        except ValueError:
            ago = None
        if ago is not None and ago <= LEADER_CHANGED_SHOWN:
            out['leader_changed'] = {'at': change['at']}
            if names:
                out['leader_changed'].update(to=change['to_url'], **{'from': change['from_url'] or None})
    return out


def _cv_pair(value):
    return list(value[:2]) if isinstance(value, (list, tuple)) and len(value) >= 2 else None


def _behind(mine, theirs):
    """How many changes `mine` (epoch, seq) is behind `theirs`, None where that cannot be
    counted (another epoch: another line of history)."""
    if mine is None or theirs is None or mine[0] != theirs[0]:
        return None
    return max(0, theirs[1] - mine[1])


def lease_status(st=None, checks=None):
    """Automatic failover on the status page: the mode, who holds the lease as this
    instance sees it, what the voter config says about each member, what the watch
    last heard from it, and the findings (auto_findings). pending, while a switch to
    automatic failover is pending here: who started it and since when (pending_switch),
    which is why a promotion by hand is refused on this instance.

    The status line (MK Oct 2026, #625): renewed_ago (seconds since the last round of
    this leader a majority answered, on a member since the last renewal it took),
    leader_change, unconfirmed (on the leader: {count, cv, floor}, the changes it holds
    that no majority holds yet; count None where they sit in another epoch), promise
    (this member's: {to, to_url, left}), leader_cv and behind (this member against the
    leader it follows), change_pending (the leader waits for a change of the voter
    config, and takes no other). Per member: cv, behind and current (as the leader saw
    it answer), promised_to and promised_left, unreached_from ([{cluster, name, node}],
    the nodes of a two-node cluster that could not reach it at the last agent check).

    In a manual group the members' marks (vote, may lead, site) are read from the
    member records, which the next switch takes into the voter config."""
    st = st or _load()
    rt = _rt()
    now = time.monotonic()
    node = _lease_live(st)
    lease = _lease(st)
    held = lease['cfg']['body'] if lease else None
    if held is not None and (lease.get('mode') != ha_vote.MODE_MANUAL or _lease_mode(st)):
        body = held
    else:
        body = _voter_body(st, held['lease_s'] if held else ha_vote.LEASE_DEFAULT)
    quarantined = set(body.get('quarantined') or ())
    voters = ha_vote.voter_ids(body)
    me = st['instance_id']
    findings = checks['findings'] if checks is not None else auto_findings(st)
    clusters = checks['clusters'] if checks is not None else _cluster_checks(st, _site_layout(st, body))[0]
    out = {
        'mode': mode(st), 'lease_s': body.get('lease_s'), 'voters': len(voters),
        'majority': ha_vote.majority(len(voters)) if voters else 0,
        'leader': bool(st.get('leader')), 'holds_lease': False, 'acting': is_active(),
        'acting_process': acting_process(), 'holder': None, 'lease_left': None, 'acting_in': None,
        'epoch': int(st.get('epoch') or 0), 'cfg_id': lease['cfg']['id'] if lease else None,
        'voted_for': None, 'switch_waiting': None, 'pending': pending_switch(st),
        'findings': findings,
        'reach': dict(rt.reach['clusters']),
        'hub_lag_max': round(rt.lag_max, 3), 'boot_hub_lag_max': round(rt.boot_lag_max, 3),
        'site': _site_of(st, me, body), 'may_lead': st.get('may_lead') is not False,
        'renewed_ago': None, 'leader_change': _leader_change(st), 'unconfirmed': None, 'promise': None,
        'leader_cv': None, 'behind': None, 'change_pending': False,
    }
    clock = ha_clock()
    holds = False
    if node is not None:
        holds = node.lease_mode() and node.holds_lease()
        out.update(holds_lease=holds, voted_for=node.st.get('voted_for'))
        if holds:
            out.update(holder=me, lease_left=round(max(0.0, node.lease_until - clock), 1))
            if not node.is_active() and node.acting_from < float('inf'):
                out['acting_in'] = round(max(0.0, node.acting_from - clock), 1)
            if rt.renewed_at is not None:
                out['renewed_ago'] = round(max(0.0, clock - rt.renewed_at), 1)
            cv, floor = _cv_pair(node.cv), _cv_pair(node.floor)
            if cv is not None and floor is not None and floor < cv:
                out['unconfirmed'] = {'count': _behind(floor, cv), 'cv': cv, 'floor': floor}
            out['change_pending'] = node.change_pending()
        elif node.promise_to and clock < node.promise_until:
            out.update(holder=node.promise_to, lease_left=round(node.promise_until - clock, 1))
            out['promise'] = {'to': node.promise_to, 'to_url': _who(st, node.promise_to),
                              'left': round(node.promise_until - clock, 1)}
        if not holds and node.heard_at is not None:
            out['renewed_ago'] = round(max(0.0, clock - node.heard_at), 1)
        if node.switch is not None and not node.switch.get('cancelled'):
            out['switch_waiting'] = sorted(
                mid for mid in node.view.members - {me}
                if (rt.seen.get(mid) or {}).get('mode') != ha_vote.MODE_PENDING)
    ms = st.get('members') or {}
    if not holds:
        # where the leader this member follows is at, as it said with its renewals
        lead = out['holder'] or st.get('source')
        theirs = _one_cv((ms.get(lead) or {}).get('cv_seen')) if lead else None
        mine = cv_entry(st)
        if theirs is not None:
            out['leader_cv'] = theirs[:2]
            if mine is not None and mine[2] == theirs[2]:
                out['behind'] = max(0, theirs[1] - mine[1])
    unreached = {}
    for row in clusters:
        for iid, nodes in (row.get('unreachable_from') or {}).items():
            unreached.setdefault(iid, []).extend({'cluster': row['id'], 'name': row['name'], 'node': n}
                                                 for n in nodes)
    t = node.t if node is not None else ha_vote.Timings()
    window = 2 * (t.R + t.renew_timeout)

    def promised(iid):
        # the leader counts on the promise of every voter that acked one of its last rounds
        if holds and clock - rt.acked.get(iid, -1e9) <= window:
            return me, round(max(0.0, rt.acked[iid] + t.P - clock), 1)
        seen = rt.seen.get(iid) or {}
        if now - seen.get('at', -1e9) <= LEASE_SEEN_FRESH and isinstance(seen.get('holder'), str):
            return seen['holder'], None
        return None, None

    def as_cv(iid):
        if holds:
            theirs = _cv_pair(node.cv_seen(iid))
            return theirs, _behind(theirs, _cv_pair(node.cv))
        if iid == out['holder'] and out['leader_cv'] is not None:
            return out['leader_cv'], 0
        return None, None

    rows = []
    leading = node is not None and st.get('leader') and node.lease_mode()
    for rec in body.get('voters') or ():
        if rec['id'] == me:
            continue
        seen = rt.seen.get(rec['id']) or {}
        # Make leader on this row, from here: the leader says whether it would hand over
        why = _transfer_refusal(st, rt, node, rec['id']) if leading else ''
        to, left = promised(rec['id'])
        cv, behind = as_cv(rec['id'])
        rows.append({'instance_id': rec['id'], 'kind': ha_vote.KIND_DATA, 'voter': rec.get('voter'),
                     'may_lead': rec.get('may_lead'), 'site': _site_of(st, rec['id'], body),
                     'quarantined': rec['id'] in quarantined, 'skew': seen.get('skew'),
                     'release': seen.get('release'), 'mode': seen.get('mode'),
                     'zone': seen.get('zone'),
                     'holds': seen.get('holds') is True, 'reach': seen.get('reach'),
                     'seen_ago': round(now - seen['at'], 1) if 'at' in seen else None,
                     'make_leader': bool(leading and not why), 'make_leader_why': why,
                     'agent_vmid': dict((ms.get(rec['id']) or {}).get('agent_vmid') or {}),
                     'cv': cv, 'behind': behind, 'current': behind == 0,
                     'promised_to': to, 'promised_left': left,
                     'unreached_from': unreached.get(rec['id'], [])})
    witness = _witness(st)
    if witness:
        seen = rt.seen.get(witness['instance_id']) or {}
        to, left = promised(witness['instance_id'])
        rows.append({'instance_id': witness['instance_id'], 'kind': ha_vote.KIND_WITNESS,
                     'voter': True, 'may_lead': False, 'site': witness['site'],
                     'quarantined': witness['instance_id'] in quarantined, 'skew': seen.get('skew'),
                     'release': seen.get('release'), 'mode': seen.get('mode'),
                     'wire': seen.get('wire') or (1 if seen.get('mark') else None),
                     'zone': seen.get('zone'), 'holds': False,
                     'reach': None, 'url': witness['url'],
                     'last_heard': (witness_view(st) or {}).get('last_heard'),
                     'seen_ago': round(now - seen['at'], 1) if 'at' in seen else None,
                     'make_leader': False, 'make_leader_why': 'The witness holds no data and never leads',
                     'agent_vmid': {}, 'cv': None, 'behind': None, 'current': False,
                     'promised_to': to, 'promised_left': left, 'unreached_from': []})
    out['members'] = rows
    out['witness'] = witness_view(st)
    out['agent_vmid'] = dict(st.get('agent_vmid') or {})
    out.update(make_leader_status(st, node, rt))
    return out


# --- what each instance measures and announces -----------------------------------

def _reaches(mgr):
    hosts = [getattr(mgr, 'host', None)]
    hosts += list(getattr(getattr(mgr, 'config', None), 'fallback_hosts', None) or [])
    for host in [h for h in hosts if isinstance(h, str) and h][:REACH_HOSTS]:
        try:
            resp = mgr._create_session().get(
                f"https://{host}:{mgr.api_port}/api2/json/version", timeout=REACH_TIMEOUT)
            # an answer is an answer: a ticket that ran out says the API is there
            if resp.status_code in (200, 401):
                return True
        except Exception:
            continue
    return False


def measure_reach():
    """{cluster id: bool} for every cluster with node HA: whether its API answers from
    this instance, one GET /version each, side by side. An instance that runs no
    managers (a standby with the live view off) reaches none. A candidate that reaches
    fewer of them than another voter waits longer before it campaigns (4.6)."""
    from pegaprox.globals import cluster_managers
    todo = [(cid, mgr) for cid, mgr in list(cluster_managers.items())
            if getattr(mgr, 'ha_enabled', False) is True]
    results = _fan_out([lambda mgr=mgr: _reaches(mgr) for _cid, mgr in todo],
                       REACH_HOSTS * REACH_TIMEOUT + 1) if todo else []
    clusters = {str(cid): err is None and ok is True for (cid, _m), (ok, err) in zip(todo, results)}
    _rt().reach = {'at': time.monotonic(), 'clusters': clusters}
    return clusters


def _lower_reach(rt):
    """Whether another voter reported, within the last two minutes, that it reaches more
    clusters with node HA than this instance does."""
    now = time.monotonic()
    mine = sum(1 for ok in rt.reach['clusters'].values() if ok)
    best = 0
    for seen in list(rt.seen.values()):
        if now - seen.get('at', -1e9) <= LEASE_SEEN_FRESH and isinstance(seen.get('reach'), dict):
            best = max(best, sum(1 for ok in seen['reach'].values() if ok))
    return mine < best


def announce_fingerprint():
    """Tell every member the certificate pin that reaches this instance, when it is not
    the one last announced: a self-signed certificate made anew, or a change between
    self-signed and one a CA signed. Signed like every peer call, so the members take
    it on the key they hold; our own calls still reach them, their pins did not
    change. A member that did not answer is told again with the next look at the
    group. Returns the ids told now."""
    st = _load()
    if (st['role'] == ROLE_STANDALONE or not st.get('members') or st.get('removed')
            or st.get('broken')):
        return []
    from pegaprox.api.ha import _own_fingerprint
    mine = _own_fingerprint() or ''
    if st.get('announced_fp', st.get('own_fingerprint')) == mine:
        return []
    rt = _rt()
    fp, told = rt.fp_told
    if fp != mine:
        told = frozenset()
    signer = _signer()
    todo = [m for m in members() if m['instance_id'] not in told]
    results = _fan_out([lambda rec=rec: call_member(rec, 'POST', FINGERPRINT_PATH,
                                                    json_body={'fingerprint': mine}, timeout=10,
                                                    signer=signer) for rec in todo], 15)
    # 404 and 405 are a release without the route: it keeps the pin it has, and asking
    # it again changes nothing
    now = sorted(rec['instance_id'] for rec, (resp, err) in zip(todo, results)
                 if err is None and resp.status_code in (200, 404, 405))
    told = told | frozenset(now)
    rt.fp_told = (mine, told)
    if all(m['instance_id'] in told for m in members()):
        try:
            _update(announced_fp=mine, own_fingerprint=mine)
        except Exception as e:
            logging.warning(f"[HA] could not note the announced certificate pin: {e}")
    if now:
        logging.warning(f"[HA] announced a new certificate pin to {len(now)} member(s)")
        _audit('ha.fingerprint_announced', f"new certificate pin told to {len(now)} member(s)")
    return now


def take_fingerprint(member_id, fingerprint):
    """A member says which certificate pin reaches it from now on, '' for a certificate
    a CA signed. Returns True when the pin held here changed. Part of automatic
    failover: while that is not shipped, the pin stays the one taken at pairing."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        raise HaError(ha_vote.NOT_SHIPPED_ERROR)
    if not isinstance(fingerprint, str):
        raise HaError('fingerprint is a SHA-256 certificate fingerprint, or empty')
    fp = fingerprint.strip().upper()
    if fp and not _FP_RE.fullmatch(fp):
        raise HaError('fingerprint is a SHA-256 certificate fingerprint, or empty')
    with _lock:
        st = _load()
        ms = dict(st.get('members') or {})
        rec = ms.get(member_id)
        if rec is None or (rec.get('fingerprint') or '') == fp:
            return False
        ms[member_id] = dict(rec, fingerprint=fp)
        _commit_locked(dict(st, members=ms))
    if rec.get('url'):
        # the kept session is pinned to the old one
        drop_kept_session(rec['url'])
    return True


def _say_downgraded(rt):
    """The leader of an automatic group, about a member that answers without the mark: it
    runs a release that knows nothing of the lease, and could be promoted by hand there."""
    st = _load()
    if not (st.get('leader') and mode(st) == ha_vote.MODE_AUTO):
        return
    for mid, seen in list(rt.seen.items()):
        if seen.get('mark') != LEASE_MARK and mid in (st.get('members') or {}) and mid not in rt.said:
            rt.said.add(mid)
            text = (f"{_label(mid)} answers as a release without automatic failover - switch it "
                    "off before downgrading a member")
            logging.error(f"[HA] {text}")
            _audit('ha.member_downgraded', text)


def _lease_housekeeping():
    """With every look at the group, once this release offers automatic failover: the
    certificate pin this instance announced, the clusters it reaches, the lease loop
    when lease state appeared since the start, and a member that was downgraded."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        return
    rt = _rt()
    known = set(_load().get('members') or {})
    witness = _witness(_load())
    if witness:
        known.add(witness['instance_id'])
    for mid in [m for m in rt.seen if m not in known]:
        rt.seen.pop(mid, None)
    for step in (announce_fingerprint, measure_reach, _ask_witness, _witness_update_check, lease_start,
                 lambda: _say_downgraded(rt), _switch_back_again, _witness_into_config):
        try:
            step()
        except Exception as e:
            logging.warning(f"[HA] lease housekeeping: {e}")


# --- the witness -------------------------------------------------------------------
#
# MK Oct 2026 (#625) - the third vote of a group with two data members, a process of its
# own (pegaprox/witness.py) that holds no configuration of the deployment. The leader
# pairs it with a code of its own prefix: the same sealed exchange a member pairs with,
# minus what a vote does not need - no field key, no snapshot, no member list. Its record
# lives under 'witness', never in 'members' (MAX_MEMBERS counts data members), and
# travels to the members with the snapshot meta. In an automatic group the voter config
# follows the record, one change at a time (_witness_into_config).

WITNESS_LEADER_ERROR = 'A witness is added and removed on the leader of a group'
WITNESS_EXISTS_ERROR = 'This group has a witness already - remove it first'
WITNESS_NONE_ERROR = 'This group has no witness'
AUTO_WITNESS_REMOVE_ERROR = (f'Without the witness this group would have fewer than '
                             f'{ha_vote.MIN_VOTERS} votes, too few for automatic failover. Switch '
                             'automatic failover off first, or add a data member')
WITNESS_PAIR_PATH = '/api/ha/peer/pair-witness'
WITNESS_LEAVE_PATH = '/api/ha/peer/witness-leave'
WITNESS_UNPAIRED_PATH = '/api/ha/peer/unpaired'
SWITCHING_OFF_ERROR = ('Automatic failover is being switched off: it is off once a majority of '
                       'the members holds the change')


def _switching_off(st):
    """A leader whose switch back to manual mode has not reached a majority yet: its
    lease is in force, and the voter config takes no other change until then (as
    set_lease_seconds says)."""
    lease = _lease(st)
    return _lease_mode(st) and lease is not None and lease['cfg']['body'].get('mode') == ha_vote.MODE_MANUAL


def witness():
    """The record of the group's witness, None when it has none."""
    return _witness(_load())


def witness_refusal(st=None):
    """Why this instance pairs no witness right now, '' when it does: only the leader of
    a group, in a release that offers automatic failover, and one witness at most."""
    st = st or _load()
    if not ha_vote.AUTO_MODE_SHIPPED:
        return ha_vote.NOT_SHIPPED_ERROR
    if st.get('broken') or st['role'] != ROLE_ACTIVE or not st.get('members'):
        return WITNESS_LEADER_ERROR
    why = _pairing_refusal(st)
    if why:
        return why
    if _switching_off(st):
        return SWITCHING_OFF_ERROR
    if _witness(st):
        return WITNESS_EXISTS_ERROR
    return ''


def _witness_unheard():
    """The first member whose last answer to this process did not speak the lease
    protocol, None when every one did: no witness before the whole group runs a release
    that knows it (10)."""
    rt = _rt()
    for rec in members():
        if (rt.seen.get(rec['instance_id']) or {}).get('mark') != LEASE_MARK:
            return rec
    return None


def create_witness_code(own_url, fingerprint, site=''):
    """Leader: a one-time code for `pegaprox-witness join`, good for PAIRING_TTL. A new
    one replaces an open one. `site` is where the witness runs, for the split checks.
    Returns (code, expires_at)."""
    if not isinstance(site, str) or len(site.strip()) > ha_vote.SITE_MAX:
        raise HaError(f'The site is a label of up to {ha_vote.SITE_MAX} characters')
    if ha_vote.AUTO_MODE_SHIPPED and role() == ROLE_ACTIVE:
        try:
            # what every member says right now, not what the watch heard a while ago
            _ask_members(5)
        except Exception as e:
            logging.warning(f"[HA] could not ask the members before pairing a witness: {e}")
    with _lock:
        st = _load()
        why = witness_refusal(st)
        if why:
            raise HaError(why)
        waiting = _witness_unheard()
        if waiting:
            raise HaError(f"{waiting.get('url') or waiting['instance_id'][:8]} has not answered on a "
                          "release with automatic failover yet - update it and let it answer once "
                          "before adding a witness")
        secret = secrets.token_urlsafe(32)
        expires = int(time.time()) + PAIRING_TTL
        _commit_locked(dict(st, witness_pairing={'code_hash': _hash_secret(secret), 'expires': expires,
                                                 'site': site.strip()},
                            own_url=own_url, own_fingerprint=fingerprint or ''))
    return ha_wire.encode_code(ha_wire.WITNESS_CODE_PREFIX, own_url, fingerprint, secret,
                               st['instance_id']), expires


def witness_code_ok(code_secret):
    """Whether `code_secret` is the open witness code of this instance. Nothing is spent."""
    pairing = _load().get('witness_pairing') or {}
    return bool(isinstance(code_secret, str) and isinstance(pairing, dict) and pairing.get('code_hash')
                and int(pairing.get('expires') or 0) >= int(time.time())
                and hmac.compare_digest(_hash_secret(code_secret), pairing['code_hash']))


def accept_witness(code_secret, witness_id, url, fingerprint, public_key):
    """The leader's half of `pegaprox-witness join`. Returns the answer for the witness:
    the leader's id and epoch, and sealed with the code the leader's public key, the
    voter config with the configs before it, the epoch, the mode and the floor. No field
    key and no snapshot: accept_pairing always seals the field key, so the witness has
    a function of its own.

    In a manual group the record goes into the voter config right away (the first
    config founds the chain the members take at the switch); in an automatic group
    that is a change of the config the lease holder makes once the one before reached
    a majority, and the witness learns it with the next renewal."""
    with _lock:
        st = _load()
        if not witness_code_ok(code_secret):
            raise HaError(PAIRING_CODE_ERROR)
        why = witness_refusal(st)
        if why:
            raise HaError(why)
        ms = st.get('members') or {}
        if (not isinstance(witness_id, str) or not _ID_RE.fullmatch(witness_id)
                or witness_id == st['instance_id'] or witness_id in ms
                or witness_id in (st.get('tombstones') or {})):
            raise HaError('The witness did not identify itself')
        if (not _public_key(public_key) or public_key == own_public_key()
                or any(rec.get('public_key') == public_key for rec in ms.values())):
            raise HaError('The witness did not send a usable public key - update it to this release')
        url = valid_https_url(url) if isinstance(url, str) else ''
        if not url:
            raise HaError('The witness address must be https://host[:port][/path]')
        fp = fingerprint.strip().upper() if isinstance(fingerprint, str) else ''
        if fp and not _FP_RE.fullmatch(fp):
            raise HaError('The witness sent a malformed certificate fingerprint')
        site = (st.get('witness_pairing') or {}).get('site') or ''
        rec = {'instance_id': witness_id, 'url': url, 'fingerprint': fp, 'public_key': public_key,
               'site': site if isinstance(site, str) and len(site) <= ha_vote.SITE_MAX else ''}
        new = {k: v for k, v in st.items() if k != 'witness_pairing'}
        new['witness'] = rec
        automatic = _lease_mode(st)
        if automatic:
            _commit_locked(new)
        else:
            held = _lease(st)
            _lease_found(new, held['cfg']['body']['lease_s'] if held else ha_vote.LEASE_DEFAULT)
            if _witness(_load()) != rec:
                # the voter config said so already: the record goes in on its own
                _commit_locked(dict(new, lease=_load().get('lease')))
        st = _load()
        lease = _lease(st)
        if lease is None:
            raise HaError('The voter config could not be made')
        payload = {'public_key': own_public_key(), 'epoch': int(st.get('epoch') or 0),
                   'chain': list(lease.get('cfg_chain') or []) + [lease['cfg']],
                   'mode': _mode_said(st)}
        node = _lease_live(st) if automatic else None
        if node is not None:
            payload['floor_cv'] = list(node.floor)
        out = {'instance_id': st['instance_id'], 'epoch': int(st.get('epoch') or 0),
               'sealed': _seal(code_secret, payload, aad=witness_id)}
    if automatic:
        _witness_into_config()
    return out


def remove_witness():
    """Leader: take the witness out of the group. Returns its record, for the caller to
    tell it. Refused in an automatic group where that would leave fewer than three
    votes, and on a leader that does not hold the lease; there the voter config follows
    with the next change (_witness_into_config)."""
    with _lock:
        st = _load()
        if st['role'] != ROLE_ACTIVE:
            raise HaError(WITNESS_LEADER_ERROR)
        rec = _witness(st)
        if rec is None:
            raise HaError(WITNESS_NONE_ERROR)
        if mode(st) == ha_vote.MODE_PENDING:
            raise AutoMode(AUTO_PENDING_ERROR)
        if _switching_off(st):
            raise HaError(SWITCHING_OFF_ERROR)
        automatic = _lease_mode(st)
        if automatic:
            lease = _lease(st)
            left = [v for v in ha_vote.voter_ids(lease['cfg']['body']) if v != rec['instance_id']]
            if len(left) < ha_vote.MIN_VOTERS:
                raise AutoMode(AUTO_WITNESS_REMOVE_ERROR)
            if not is_active():
                raise NoLease(NO_LEASE_ERROR)
        _commit_locked({k: v for k, v in st.items() if k not in ('witness', 'witness_pairing')})
    if automatic:
        _witness_into_config()
    return rec


def _witness_into_config():
    """Leader of an automatic group: the voter config names the witness this instance
    holds a record of, and no other. Asked once per node, as a change of the config;
    the node makes it once the change before reached a majority. Never below three
    votes: a config that names a witness without a record keeps it, and the findings
    say so. Returns 'add', 'remove' or ''."""
    st = _load()
    if st['role'] != ROLE_ACTIVE or not _lease_mode(st):
        return ''
    rt = _rt()
    with rt.lock:
        node = _lease_live(st)
        if (node is None or not node.is_active() or node.transfer is not None
                or node.view.mode != ha_vote.MODE_AUTO):
            # and nothing while a switch back to manual mode is under way
            return ''
        rec = _witness(st)
        want = ({'id': rec['instance_id'], 'public_key': rec['public_key'], 'site': rec['site']}
                if rec else None)
        held = node.view.cfg['body'].get('witness') or None
        if held == want:
            return ''
        if want is None and node.view.n - 1 < ha_vote.MIN_VOTERS:
            return ''
        asked = (rt.gen, json.dumps(want, sort_keys=True))
        if rt.witness_asked == asked:
            return ''
        rt.witness_asked = asked
        node.change_cfg(lambda body: dict(body, witness=want))
    rt.wake.set()
    return 'add' if want else 'remove'


def witness_verdict(headers, method, path, body):
    """Who sent a call that names the witness as its sender: ('witness', record) for a
    good signature under the key held for it, ('skewed', record) for one from outside
    the window, (None, None) for anything else."""
    rec = witness()
    raw = headers.get(PEER_HEADER) if headers is not None else None
    if rec is None or raw != rec['instance_id']:
        return None, None
    check = _signature_check(headers, method, path, body, raw, rec['public_key'], instance_id())
    if check == 'ok':
        return 'witness', rec
    if check == 'skewed':
        return 'skewed', rec
    return None, None


def call_witness(rec, method, path, json_body=None, timeout=10):
    """One signed call to the witness `rec`: our key only, never an old secret."""
    if not rec or not rec.get('url'):
        raise HaError('No address known for the witness')
    return _peer_call(method, rec['url'], rec.get('fingerprint') or '', path, json_body=json_body,
                      auth=_auth_for(_signer(), rec['instance_id']), timeout=timeout)


def witness_view(st=None):
    """The witness on the status page: its record without the key, a short digest of
    the key, when it was last heard (a status answer, or a renewal it acked: seconds
    ago) and its clock against ours. None when the group has none."""
    st = st or _load()
    rec = _witness(st)
    if rec is None:
        return None
    rt = _rts.get(st['instance_id'])
    heard, skew, unwritten = None, None, False
    if rt is not None:
        seen = rt.seen.get(rec['instance_id']) or {}
        if 'at' in seen:
            heard = time.monotonic() - seen['at']
            skew = seen.get('skew')
        unwritten = seen.get('write_failed') is True
        if rec['instance_id'] in rt.acked:
            acked = ha_clock() - rt.acked[rec['instance_id']]
            heard = acked if heard is None else min(heard, acked)
    seen = (rt.seen.get(rec['instance_id']) if rt is not None else None) or {}
    behind = bool(seen.get('mark')) and _witness_behind(seen)
    ahead = bool(seen.get('mark')) and _witness_ahead_of_us(seen)
    return {'instance_id': rec['instance_id'], 'kind': ha_vote.KIND_WITNESS, 'url': rec['url'],
            'fingerprint': rec['fingerprint'], 'site': rec['site'],
            'key_fingerprint': peer_key_fingerprint(rec['public_key']),
            'last_heard': round(max(0.0, heard), 1) if heard is not None else None, 'skew': skew,
            # it cannot write its state, and gives no vote until it can (auto_findings)
            'write_failed': unwritten,
            # its code against this instance's, and how it is kept up to date
            'release': seen.get('release'), 'wire': seen.get('wire') or (1 if seen.get('mark') else None),
            'auto_update': seen.get('auto_update') is True, 'install': seen.get('install') or '',
            'update': seen.get('update'), 'outdated': behind,
            'update_command': witness_boot.update_command(seen.get('install')) if behind else None,
            # newer code than this instance's: by hand down to it, never by itself
            'ahead': ahead,
            'to_leader_command': witness_boot.update_command(seen.get('install'), to_leader=True) if ahead else None}


# --- keeping the witness up to date -----------------------------------------------------
#
# MK Oct 2026 (#625) - the witness host has no updater of its own, and the members change
# the wire now and then. The leader keeps it up: its own witness code as one signed
# bundle (witness_bundle, at /api/ha/witness/bundle for the installer with the open code
# and for the paired witness by its signature), and a word to the witness when it runs
# newer code and the data voters hold a majority without it (_witness_update_check). The
# witness fetches, checks and starts into it (witness.py, Witness.run_update).

WITNESS_UPDATE_PATH = '/api/ha/peer/witness-update'
# what the witness runs (tests/test_ha_witness_delivery.py follows its imports), and its
# unit for the installer: nothing else goes into the bundle
WITNESS_BUNDLE_FILES = ('pegaprox/__init__.py', 'pegaprox/witness.py', 'pegaprox/witness_boot.py',
                        'pegaprox/core/__init__.py', 'pegaprox/core/ha_vote.py',
                        'pegaprox/core/ha_wire.py', 'pegaprox/utils/__init__.py',
                        'pegaprox/utils/ratelimit.py', 'pegaprox/utils/url_security.py',
                        'systemd/pegaprox-witness.service')
WITNESS_BUNDLE_OPTIONAL = ('systemd/pegaprox-witness.service',)
# how often the leader says it again to a witness that stays behind
WITNESS_TELL_EVERY = 300
_bundle_held = {}


def code_root():
    """The directory this instance runs from (pegaprox/ and packaging/ are in it)."""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def pack_bundle(entries):
    """{name: bytes} as a tar.gz with fixed times and owners, in name order: the same files
    make the same archive, and the same digest, on every member."""
    import io
    import tarfile
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode='wb', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for name in sorted(entries):
                info = tarfile.TarInfo(name)
                info.size, info.mtime, info.mode = len(entries[name]), 0, 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                tar.addfile(info, io.BytesIO(entries[name]))
    return buf.getvalue()


def _bundle_archive():
    """(archive, file names, SHA-256) of this instance's witness code (pack_bundle), built
    once per set of file stamps. The unit is left out where this instance has none (an
    install from a checkout before deploy.sh copied it): the installer writes its own."""
    root = code_root()
    stamps = []
    for rel in WITNESS_BUNDLE_FILES:
        try:
            st = os.stat(os.path.join(root, *rel.split('/')))
        except FileNotFoundError:
            if rel not in WITNESS_BUNDLE_OPTIONAL:
                raise
            continue
        stamps.append((rel, st.st_mtime_ns, st.st_size))
    key = (tuple(stamps), PEGAPROX_VERSION, ha_wire.WITNESS_WIRE)
    held = _bundle_held.get('archive')
    if held is not None and held[0] == key:
        return held[1]
    entries = {}
    for rel, _mtime, _size in stamps:
        with open(os.path.join(root, *rel.split('/')), 'rb') as fh:
            entries[rel] = fh.read()
    # what the witness reads its release from (witness.release); the leader's own, as
    # this file is not one of its files
    entries['version.json'] = (json.dumps({'version': PEGAPROX_VERSION, 'wire': ha_wire.WITNESS_WIRE},
                                          sort_keys=True) + '\n').encode()
    archive = pack_bundle(entries)
    out = (archive, sorted(entries), hashlib.sha256(archive).hexdigest())
    _bundle_held['archive'] = (key, out)
    return out


def witness_bundle():
    """This instance's witness code as the witness takes it: {manifest, sig, archive}.
    The manifest names the release, the wire, the archive's size, SHA-256 and files and
    who signs; the signature (ha_wire.bundle_message) is by this instance's key, which
    the witness knows from the voter config. Raises HaError."""
    try:
        archive, files, digest = _bundle_archive()
    except OSError as e:
        raise HaError(f'The witness code of this instance is incomplete ({type(e).__name__})')
    signer = _signer()
    if signer.private is None:
        raise HaError('This instance has no key pair to sign the witness code with')
    manifest = {'release': PEGAPROX_VERSION, 'wire': ha_wire.WITNESS_WIRE, 'sha256': digest,
                'size': len(archive), 'files': files, 'by': signer.instance_id,
                'name': witness_boot.bundle_name(PEGAPROX_VERSION, digest)}
    return {'manifest': manifest,
            'sig': base64.b64encode(signer.private.sign(ha_wire.bundle_message(manifest))).decode(),
            'archive': base64.b64encode(archive).decode()}


def _witness_behind(seen):
    """Whether the witness, by its last status answer `seen`, runs older code than this
    instance: an older release, or the same one on an older wire."""
    return witness_boot.release_key(seen.get('release'), seen.get('wire') or 1) < \
        witness_boot.release_key(PEGAPROX_VERSION, ha_wire.WITNESS_WIRE)


def _witness_outdated(seen, label, mid, running):
    """The WITNESS_OUTDATED finding for a witness behind this instance, None for one that
    is not. One wire behind is talked to as it is (N-1): a warning, while it updates
    itself or until it is updated by hand. Further behind refuses the switch."""
    if not _witness_behind(seen):
        return None
    wire = seen.get('wire') or 1
    near = wire >= ha_wire.WITNESS_WIRE - 1
    command = witness_boot.update_command(seen.get('install'))
    last = seen.get('update') or {}
    text = (f"{label} runs release {seen.get('release') or 'unknown'} (wire {wire}), this instance "
            f"{PEGAPROX_VERSION} (wire {ha_wire.WITNESS_WIRE}). ")
    if seen.get('auto_update') and last.get('state') != 'failed':
        text += 'It updates itself from the leader once every data voter renewed the lease with it.'
    elif seen.get('auto_update') and last.get('back') is True:
        # code that did not come up there is not taken again by itself (witness.py, _told)
        text += (f"Its last update failed: {last.get('error') or 'no reason given'}. It went back from that "
                 f"code and does not take it again by itself - update it by hand once that is fixed: "
                 f"{command or 'see docs/ha-witness.md'}")
    elif seen.get('auto_update'):
        # a fetch that did not get through (the leader out of reach for a moment): the next
        # word of the leader tries again, nothing to do by hand
        text += (f"Its last try to fetch the update failed: {last.get('error') or 'no reason given'}. It "
                 f"tries again when the leader says so again (every {WITNESS_TELL_EVERY // 60} minutes).")
    elif command:
        text += f'Automatic updates are off on the witness. Update it by hand: {command}'
    else:
        text += ('It cannot update itself. Remove it here and add it again: "Add witness" shows the '
                 'commands.')
    if not near:
        text += ' It is too old to vote with this release.'
    finding = _finding('WITNESS_OUTDATED', 'warn' if near or running else 'block', text, mid)
    finding['command'] = command
    return finding


def _own_bundle_name():
    """The name of this instance's witness bundle (<release>-<digest>), '' where its code
    is incomplete."""
    try:
        return witness_boot.bundle_name(PEGAPROX_VERSION, _bundle_archive()[2])
    except OSError:
        return ''


def _witness_other_code(seen):
    """Whether the witness, by its last status answer `seen`, runs other code than this
    instance under the same release and wire (a fix pushed under the same release string):
    told by the name of the bundle its code came from. A witness that runs code no bundle
    named (the image's own, a checkout) is not told apart."""
    if not seen.get('code') or witness_boot.release_key(seen.get('release'), seen.get('wire') or 1) != \
            witness_boot.release_key(PEGAPROX_VERSION, ha_wire.WITNESS_WIRE):
        return False
    own = _own_bundle_name()
    return bool(own) and seen['code'] != own


def _witness_ahead_of_us(seen):
    """Whether the witness, by its last status answer `seen`, runs newer code than this
    instance (a leader that went back to an older release after the witness updated)."""
    return witness_boot.release_key(seen.get('release'), seen.get('wire') or 1) > \
        witness_boot.release_key(PEGAPROX_VERSION, ha_wire.WITNESS_WIRE)


def _witness_ahead(seen, label, mid, running):
    """The WITNESS_AHEAD finding for a witness that runs newer code than this instance,
    None for one that does not. Judged by the wire, the calls it speaks: on the same wire
    or one apart it votes as it is, a warning that names both releases and the way down
    (update --to-leader, by hand only). Further apart refuses the switch."""
    if not _witness_ahead_of_us(seen):
        return None
    wire = seen.get('wire') or 1
    near = abs(wire - ha_wire.WITNESS_WIRE) <= 1
    command = witness_boot.update_command(seen.get('install'), to_leader=True)
    text = (f"{label} runs release {seen.get('release') or 'unknown'} (wire {wire}), newer than this "
            f"instance's {PEGAPROX_VERSION} (wire {ha_wire.WITNESS_WIRE}). ")
    text += ('It votes with this release as it is. ' if near else
             'Its calls are too far from this release to vote with it. ')
    text += (f'To bring it down to the release of this instance, run on the witness host: {command}' if command
             else 'To bring it down to this release, remove it here and add it again: "Add witness" shows the '
                  'commands.')
    finding = _finding('WITNESS_AHEAD', 'warn' if near or running else 'block', text, mid)
    finding['command'] = command
    return finding


def _data_voters_renewed(node, rt):
    """Leader of an automatic group: whether every data voter of the voter config acked
    one of the last two renewal rounds, so that they hold a majority without the witness."""
    t = node.t
    fresh = 2 * (t.R + t.renew_timeout)
    now = ha_clock()
    data = node.view.data & node.view.counting
    if len(data) < node.view.m:
        return False
    return all(mid == node.me or now - rt.acked.get(mid, -1e9) <= fresh for mid in data)


def _witness_update_check():
    """Leader: a witness that runs other code is told so, with what this instance runs and
    where its bundle is (and the other data voters' addresses), at most every
    WITNESS_TELL_EVERY. update: true only for older code, while the data voters hold a
    majority without the witness (every one renewed recently, or a manual group, where
    the witness gives no vote that counts) and the witness updates itself: it fetches the
    bundle and starts into it, and its vote is missing for that long. A witness with the
    updates off, or ahead of this instance, is told all the same, for its own status and
    update --to-leader. Other code of this very release (by the bundle it came from) is
    told as older code is. Returns what it said, None for nothing. Never raises."""
    try:
        st = _load()
        rec = _witness(st)
        if st['role'] != ROLE_ACTIVE or rec is None or not rec.get('url'):
            return None
        rt = _rt()
        seen = rt.seen.get(rec['instance_id']) or {}
        behind = _witness_behind(seen) or _witness_other_code(seen)
        # a witness ahead of this instance is told too, never to update: it keeps what this
        # instance runs, and its admin takes that by hand (update --to-leader)
        if seen.get('mark') != LEASE_MARK or time.monotonic() - seen.get('at', -1e9) > LEASE_SEEN_FRESH \
                or not (behind or _witness_ahead_of_us(seen)):
            return None
        safe = False
        if mode(st) == ha_vote.MODE_MANUAL and not _lease_mode(st):
            safe = True
        elif _lease_mode(st):
            with rt.lock:
                node = _lease_live(st)
                safe = (node is not None and node.is_active() and node.transfer is None
                        and node.switch is None and node.view.mode == ha_vote.MODE_AUTO
                        and _data_voters_renewed(node, rt))
        update = bool(safe and behind and seen.get('auto_update'))
        # which code exactly: a witness where that code did not come up says so and stays
        # as it is, instead of fetching and starting into it again; and of the same release
        # it tells other code apart by it
        name = _own_bundle_name()
        said = (rec['instance_id'], PEGAPROX_VERSION, ha_wire.WITNESS_WIRE, update, name)
        told = rt.witness_told
        if told is not None and told[0] == said and time.monotonic() - told[1] < WITNESS_TELL_EVERY:
            return None
        rt.witness_told = (said, time.monotonic())
        # where the witness fetches: this instance, and the other data voters where it cannot
        # reach this one at own_url (an address only the members may reach)
        others = [{'instance_id': mid, 'url': m['url'], 'fingerprint': m.get('fingerprint') or ''}
                  for mid, m in sorted((st.get('members') or {}).items())
                  if isinstance(m, dict) and m.get('url') and m.get('voter') is not False]
        body = {'release': PEGAPROX_VERSION, 'wire': ha_wire.WITNESS_WIRE, 'update': update,
                'url': st.get('own_url') or '', 'fingerprint': st.get('own_fingerprint') or '',
                'voters': others[:8]}
        if name:
            body['name'] = name
        resp = call_witness(rec, 'POST', WITNESS_UPDATE_PATH, json_body=body, timeout=10)
        ans = resp.json() if resp.status_code == 200 else None
        ans = ans if isinstance(ans, dict) else {}
        if ans.get('accepted') is True:
            logging.warning(f"[HA] told the witness {rec['url']} to update to release {PEGAPROX_VERSION}")
            _audit('ha.witness_update', f"the witness {rec['url']} updates from release "
                                        f"{seen.get('release') or 'unknown'} to {PEGAPROX_VERSION}")
        return {'update': update, 'status': resp.status_code, 'answer': ans}
    except Exception as e:
        logging.info(f"[HA] could not tell the witness about release {PEGAPROX_VERSION}: {_error_text(e)}")
        return None


def check_not_a_witness_dir(path=None):
    """main(): a PegaProx instance never runs on the state directory of a witness."""
    folder = path or os.path.dirname(os.path.abspath(LOCK_FILE))
    if os.path.exists(os.path.join(folder, ha_wire.WITNESS_STATE_NAME)):
        raise HaError(f'{folder} is the state directory of a PegaProx witness - run PegaProx on a '
                      'config directory of its own')


# --- make leader, planned restarts, Force leader, removal (design 7) ------------------
#
# MK Oct 2026 (#625) - what an admin does with the lead of an automatic group. "Make
# leader" hands the lead on: the leader pauses writes, lets the member catch up, stops
# acting and hands its next term to exactly that member, which votes at once (7.1).
# Without an answering leader the member campaigns at once instead, with the pre-vote
# and every rule. A planned restart of the leader asks the members to hold its lease
# until it is back (7.2). Force leader is the way out of a group that lost its majority
# for good: the member becomes the manual active of the group at a new epoch, and the
# members it cut out are out of the group (7.3). Members leave and are removed only on
# the lease holder, one change of the voter config at a time (7.4).

LEADER_PHRASE = 'LEADER'
FORCE_PHRASE = 'FORCE LEADER'
FORCE_REASON_MAX = 500
# the leader waits this long for the member it hands the lead to (TRANSFER_CATCHUP), the
# member for the election that follows
TRANSFER_WAIT = ha_vote.TRANSFER_CATCHUP + LEASE_CALL_TIMEOUT + 2
CAMPAIGN_WAIT = ha_vote.CATCHUP_TIMEOUT + 3 * LEASE_CALL_TIMEOUT + 2
HANDED_WAIT = 2 * LEASE_CALL_TIMEOUT + 2
# a change of the voter config is on disk within a few renewal rounds
CFG_CHANGE_WAIT = 10
# the claim watch: once per watch pass at most, on a greenlet of its own, at most this
# many clusters at once and CLAIM_WATCH_NODES nodes of each (30 s apiece over SSH); a
# foreign claim it cannot act on is looked at again after CLAIM_REPEAT, a cluster that
# answered late or not at all after CLAIM_RETRY
CLAIM_WATCH = 30
CLAIM_WATCH_AT_ONCE = 8
CLAIM_WATCH_NODES = 2
CLAIM_WATCH_WAIT = CLAIM_WATCH_NODES * 30 + 5
CLAIM_REPEAT = 600
CLAIM_RETRY = 120
# Force leader sets autostart off on the cut-out members' VMs; a cluster that does not
# answer is tried again at the next passes, this many in all
ONBOOT_TRIES = 20

TRANSFER_ERROR = ('The leader is handing its role to another member - changes resume in a '
                  'few seconds')
AUTO_REMOVE_FEW_ERROR = (f'Without this member the group would have fewer than '
                         f'{ha_vote.MIN_VOTERS} votes, too few for automatic failover. Switch '
                         'automatic failover off first, or add a member or a witness')
AUTO_REMOVE_FEW_COUNTING_ERROR = (f'Without this member fewer than {ha_vote.MIN_VOTERS} votes of the group '
                                  'would count (a quarantined member votes on paper only), too few for '
                                  'automatic failover. Re-admit the quarantined member first')
AUTO_REMOVE_SELF_ERROR = 'The leader does not remove itself - make another member leader first'
AUTO_LEAVE_LEADER_ERROR = ('This instance leads a group that fails over automatically - make '
                           'another member leader first, then unpair it there')
NO_LEADER_TO_LEAVE_ERROR = ('This group fails over automatically and no leader answers, so '
                            'nobody can take this instance out of its voter config. Wait for '
                            'the leader, or use Force leader if the group lost its majority for good')
MANUAL_UNKNOWN_ERROR = ('This instance holds a manual voter config that follows an automatic one, '
                        'and no majority of the group has confirmed it: the group may still fail '
                        'over automatically elsewhere. It is not promoted or unpaired by hand - '
                        'let it reach the group, or use Force leader if the group lost its '
                        'majority for good')
RESTORED_ERROR = ('The state of this instance is older than what it knew about its group (it was '
                  'put back from a copy): the group fails over automatically and may have a '
                  'leader. It is not promoted or unpaired by hand - let it reach the group, or '
                  'use Force leader if the group lost its majority for good')
FORCE_WARNING = ('If any of these members still runs somewhere, two instances may act on the '
                 'clusters both of them reach: on a cluster with the cluster claim on until the '
                 "older one sees this member's claim (up to 30 s), and steps over SSH are refused "
                 'there at once; on a cluster without it until the two can reach each other '
                 'again. Tick a member only when it is powered off or destroyed.')
FORCE_FOLLOW = 'the group has a leader or an active - follow it'


class TransferRefused(HaError):
    """Make leader: why the lead is not handed on, or why the election did not win it."""


class ForceRefused(HaError):
    """Force leader: why it is not offered here, or what the request got wrong."""


class _Until:
    """A condition _lease_wait can wait for: polled here, stepped in the tests."""

    def __init__(self, cond):
        self.cond = cond

    def is_set(self):
        return bool(self.cond())

    def wait(self, seconds):
        end = time.monotonic() + seconds
        while not self.cond():
            if time.monotonic() >= end:
                return False
            time.sleep(0.1)
        return True


def handing_over():
    """Whether this instance is the leader of an automatic group that hands its lead on
    right now: writes are paused (503 HA_TRANSFER) until it went through or failed."""
    st = _load()
    if not st.get('leader'):
        return False
    node = _lease_live(st)
    return node is not None and node.transfer is not None


def _known_leader(st, node=None):
    """The record of the member that leads this member's automatic group as far as it
    knows: the holder of its promise, a member that said it holds the lease, the member
    it pulls from. None when it knows none."""
    ms = st.get('members') or {}
    names = []
    if node is not None and node.promise_to and ha_clock() < node.promise_until:
        names.append(node.promise_to)
    names += sorted(mid for mid in ms if _says_it_holds(mid))
    if st.get('source'):
        names.append(st['source'])
    for mid in names:
        if mid in ms:
            return dict(ms[mid], instance_id=mid)
    return None


def _transfer_refusal(st, rt, node, target):
    """Why the leader does not hand its lead to `target` right now, '' when it does: the
    target has to be able to win (a data voter that is not quarantined, answers the
    renewals, holds the newest voter config and can write its state)."""
    if node is None or not st.get('leader') or not node.lease_mode():
        return 'This instance does not lead an automatic group'
    if node.view.mode != ha_vote.MODE_AUTO:
        return SWITCHING_OFF_ERROR
    if node.transfer is not None:
        return 'The lead is being handed on already'
    if not node.is_active():
        return NO_LEASE_ERROR
    if target == st['instance_id']:
        return 'This instance leads already'
    rec = node.view.records.get(target)
    label = _label(target)
    if rec is None or not rec.get('voter'):
        return f'{label} holds no vote in this group: only a data member with a vote leads'
    if target not in node.view.counting:
        return f'{label} is quarantined (it came back with an older state): re-admit it first'
    t = node.t
    if ha_clock() - rt.acked.get(target, -1e9) > 2 * (t.R + t.renew_timeout):
        return f'{label} does not answer the renewals of this leader'
    if (rt.seen.get(target) or {}).get('write_failed'):
        return f'{label} cannot write its HA state file, so it cannot vote for itself'
    if node.cfg_seen(target) != node.view.id:
        return f'{label} does not hold the newest voter config yet - try again in a few seconds'
    return ''


def _nudge_one(member_id):
    """The note about a change, to one member and now: it pulls what it does not hold."""
    try:
        from pegaprox.api.ha import current_etag
        body = {'etag': current_etag()}
        body.update(peer_cv())
        tell_members('POST', NUDGE_PATH, json_body=body, timeout=NUDGE_TIMEOUT,
                     only=[member_id], note=False)
    except Exception as e:
        logging.info(f"[HA] could not tell {_label(member_id)} to catch up: {e}")


def hand_over(target):
    """Leader of an automatic group: hand the lead to the member `target` (7.1). Writes
    pause, the target is told to pull, and once it holds the configuration of now this
    instance stops acting and hands it the next term; the target votes at once, and this
    instance steps down when it votes for it. Returns 'handed' once the term went out
    ('catching up' when the node still waits past TRANSFER_WAIT). Raises TransferRefused
    when the target cannot win or did not catch up in time (writes are open again then),
    NoLease without the lease."""
    rt = _rt()
    with rt.lock:
        st = _load()
        node = _lease_node(rt)
        why = _transfer_refusal(st, rt, node, target)
        if why:
            raise (NoLease if why == NO_LEASE_ERROR else TransferRefused)(why)
        code = node.transfer_to(target)
        if code:
            raise TransferRefused(f'The lead was not handed on ({code})')
        rt.due = node.next_wake()
    _lease_after(rt)
    _lease_spawn(lambda: _nudge_one(target), 'ha-transfer-nudge')
    _lease_wait(_Until(lambda: node.dead or node.transfer is None or node.transfer.get('phase') != 'catchup'),
                TRANSFER_WAIT)
    with rt.lock:
        phase = (node.transfer or {}).get('phase')
        if node.dead or phase in ('release', 'wait'):
            return 'handed'
        if phase == 'catchup':
            return 'catching up'
    raise TransferRefused(f'{_label(target)} could not catch up with the configuration of this leader '
                          f'within {ha_vote.TRANSFER_CATCHUP} s - it goes on leading, and writes are '
                          'open again')


def _campaign_refusal(node, before):
    """Why the election this member just ran did not make it the leader."""
    failed = node.last_failed
    if failed is None or failed is before:
        return 'The election did not finish in time - look at the status in a moment'
    reached, m = failed['reached'], failed['m']
    if reached >= m:
        if 'PROMISED' in failed['reasons']:
            return 'The leader holds a majority - this member is cut off from it'
        return (f'A majority answers ({reached} of the {m} votes needed) and refused: '
                f"{', '.join(r for r in failed['reasons'] if r) or 'no reason given'}")
    return (f'Only {reached} of the {m} votes a leader needs answer: no majority can be reached '
            'from here. If the members that do not answer are down for good, Force leader takes '
            'over without them')


def make_leader(target=None):
    """'Make leader' (7.1). On the leader: hand the lead to `target` (hand_over). On a
    data voter, for itself: ask the leader to hand it over, and where no leader answers,
    campaign at once (pre-vote and every rule kept). Returns 'handed' (the leader let go
    and the vote is out), 'elected' (this instance won and restarts) or 'catching up'.
    Raises TransferRefused with the reason, NoLease, HaError."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        raise HaError(ha_vote.NOT_SHIPPED_ERROR)
    st = _load()
    me = st['instance_id']
    target = target or me
    if st.get('leader') and _lease_mode(st):
        if target == me:
            raise TransferRefused('This instance leads already')
        return hand_over(target)
    if target != me:
        raise TransferRefused('Another member is made leader on the leader, or on that member itself')
    if st['role'] != ROLE_STANDBY or mode(st) != ha_vote.MODE_AUTO or st.get('removed'):
        raise HaError('Make leader is for a member of a group that fails over automatically')
    rt = _rt()
    with rt.lock:
        node = _lease_node(rt)
        if node is None or node.view.mode != ha_vote.MODE_AUTO or not node.view.candidate(me, timer=False):
            raise TransferRefused('This instance holds no vote in the voter config of its group, or '
                                  'is quarantined: it cannot lead')
        leader = _known_leader(st, node)
    if leader is not None:
        try:
            resp = call_member(leader, 'POST', TRANSFER_PATH, json_body={}, timeout=TRANSFER_WAIT + 5)
        except PeerNoAnswer:
            # it took the call: whether it handed over shows in the term it hands on
            resp = None
        except HaError as e:
            logging.info(f"[HA] the leader {leader.get('url')} did not answer the request to "
                         f"hand over ({_error_text(e)}) - campaigning")
            leader, resp = None, None
        if resp is not None and resp.status_code != 200:
            raise TransferRefused(_peer_error(resp, 'The leader did not hand over'))
        if leader is not None:
            # the leader let go once this member caught up; the call that starts the vote
            # here follows its last round
            _lease_wait(_Until(lambda: node.dead or node.campaigning()), HANDED_WAIT)
            if node.campaigning():
                _lease_wait(_Until(lambda: node.dead or not node.campaigning()), CAMPAIGN_WAIT)
            if node.dead:
                return 'elected'
            if resp is None:
                raise TransferRefused('The leader took the request and did not answer - look at the '
                                      'status in a moment')
            return 'handed'
    with rt.lock:
        before = node.last_failed
        if node.campaign_now('make_leader'):
            raise TransferRefused('This instance cannot campaign right now - look at the status in a moment')
        rt.due = node.next_wake()
    _lease_after(rt)
    _lease_wait(_Until(lambda: node.dead or not node.campaigning()), CAMPAIGN_WAIT)
    if node.dead:
        return 'elected'
    raise TransferRefused(_campaign_refusal(node, before))


def planned_restart(reason, hold_s=ha_vote.PLANNED_HOLD):
    """Before a restart an admin asked for (an update, a rollback, the restart button) on
    the leader of an automatic group: stop acting and ask the members to hold the lease
    for hold_s while this instance is gone; after the start it renews at the epoch it won
    and goes on leading, with no failover (7.2). The caller restarts as it would anyway;
    the watchdog sees to it should that not come. A no-op returning False anywhere else,
    a manual group and an instance of its own included. Never raises."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        return False
    try:
        return _planned_restart(reason, hold_s)
    except Exception as e:
        logging.error(f"[HA] the planned restart could not ask the members to hold the lease: {e}")
        return False


def _planned_restart(reason, hold_s):
    st = _load()
    if not (st.get('leader') and _lease_mode(st)):
        return False
    rt = _rt()
    with rt.lock:
        node = _lease_live(st)
        if node is None or not node.holds_lease() or node.planned_restart(hold_s):
            return False
        calls = list(rt.outbox)
        rt.outbox.clear()
        # the caller restarts: the node's own way out is not taken a second time
        events = [e for e in rt.events if e[0] != 'exit']
        rt.events.clear()
        rt.exit_at = ha_clock()
    for name, info in events:
        try:
            _lease_event(rt, name, info)
        except Exception as e:
            logging.warning(f"[HA] could not handle the lease event {name}: {e}")
    held = []
    if calls:
        results = _fan_out([lambda item=item: _lease_fetch(item) for item in calls], LEASE_CALL_TIMEOUT + 1)
        held = [_label(item[0]) for item, (ans, err) in zip(calls, results)
                if err is None and isinstance(ans, dict) and ans.get('ok') is True]
    kill_children()
    hold = min(hold_s, ha_vote.HOLD_MAX)
    text = (f"planned restart ({reason}): stopped acting, {', '.join(held) or 'no member'} "
            f"hold{'s' if len(held) == 1 else ''} the lease for {hold} s; if this instance is not "
            'back by then, the members elect another leader')
    logging.warning(f"[HA] {text}")
    _audit('ha.planned_restart', text)
    flush_journal()
    return True


# --- the way out of a group that is or was automatic (S7, from the S5 attack) ---

def way_out_refusal(st=None, said=()):
    """Why this instance takes neither a promotion by hand nor an unpairing by hand right
    now, '' when it may. A member of a group that has ever been automatic whose manual
    voter config is not known to be the group's (_manual_known; `said` is what the
    members answered just now), or whose state is older than what it knew about the
    group (_group_seen: a copy put back), could act next to the leader the others elect.
    Its only way out without the leader is Force leader.

    Known limit: a member restored as a whole (a VM snapshot rolled back, the whole config
    directory put back) brings its state file and the note next to it back from the same
    moment. From before the switch it cannot be told from a live member that never saw
    automatic failover, and this says ''. The HA guide tells the operator: never roll a
    member back while its group runs; unpair it and pair it again."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        return ''
    st = st or _load()
    if st.get('broken') or st.get('removed') or st['role'] == ROLE_STANDALONE:
        return ''
    lease = _lease(st)
    if (lease is not None and lease.get('mode') == ha_vote.MODE_MANUAL and not st.get('leader')
            and not _manual_known(st, lease, said)):
        return MANUAL_UNKNOWN_ERROR
    seen = _group_seen(st)
    if seen is not None and seen['auto'] and seen['cfg_id'] is not None:
        held = ha_vote.pair(lease['cfg']['id']) if lease is not None else None
        if held is None or held < seen['cfg_id']:
            return RESTORED_ERROR
    return ''


def _group_says(timeout=5):
    """What every member and every witness this instance knows of answers now: its own
    witness and the one its group note names (an older state may know none). [(record,
    status or None, error or None)], status as _ask returns it."""
    st = _load()
    targets = [dict(rec, instance_id=mid) for mid, rec in sorted((st.get('members') or {}).items())]
    known = {t['instance_id'] for t in targets}
    for w in (_witness(st), (_group_seen(st) or {}).get('witness')):
        if w and w.get('url') and w['instance_id'] not in known:
            known.add(w['instance_id'])
            # signed only: the witness takes no old secret
            targets.append(dict(w, key_acked=True, kind=ha_vote.KIND_WITNESS))
    if not targets:
        return []
    try:
        signer = _signer()
    except HaError:
        return [(rec, None, HaError('Not paired')) for rec in targets]
    results = _fan_out([lambda rec=rec: _ask(rec, signer, timeout) for rec in targets], timeout + 1)
    return [(rec, value if err is None else None, err) for rec, (value, err) in zip(targets, results)]


# --- Force leader (7.3, Q3 b, Q13 b) ---

def _force_case(st, node):
    """Which way out Force leader would be here: 'auto' (a data voter of an automatic
    group), 'pending' (a member holding a switch another instance started), 'unknown'
    (way_out_refusal), None for none."""
    if st['role'] != ROLE_STANDBY or st.get('removed') or st.get('broken'):
        return None
    lease = _lease(st)
    if lease is not None and lease.get('mode') == ha_vote.MODE_AUTO:
        return 'auto' if node is not None and st['instance_id'] in node.view.data else None
    if (lease is not None and lease.get('mode') == ha_vote.MODE_PENDING
            and lease['cfg'].get('by') != st['instance_id']):
        return 'pending'
    if way_out_refusal(st):
        return 'unknown'
    return None


def _force_voters(st):
    """{voter id: kind} of the group as this instance holds it, itself left out."""
    lease = _lease(st)
    me = st['instance_id']
    if lease is not None:
        view = ha_vote.CfgView(lease['cfg'])
        return {v: (ha_vote.KIND_WITNESS if v == view.witness else ha_vote.KIND_DATA)
                for v in view.voters if v != me}
    out = {mid: ha_vote.KIND_DATA for mid in st.get('members') or {}}
    for w in (_witness(st), (_group_seen(st) or {}).get('witness')):
        if w:
            out[w['instance_id']] = ha_vote.KIND_WITNESS
    return out


def _quiet_for(st, rt, node):
    """Seconds since this member last heard a leader (a renewal; the switch rounds of a
    pending switch), or since it started."""
    if node is None:
        return time.monotonic() - rt.born
    now = ha_clock()
    last = node.heard_at if node.heard_at is not None else node.started
    if rt.switch_heard is not None:
        last = max(last, rt.switch_heard)
    return now - last


def force_leader_view(st=None, probe=False):
    """Whether Force leader is offered on this instance, and for which members: {offered,
    case, why, cut_out: [{instance_id, url, kind}], quiet, last_campaign}. With `probe`
    every member and witness is asked now, as the route does before it acts; without, the
    status page goes by what the watch heard last."""
    st = st or _load()
    out = {'offered': False, 'case': None, 'why': '', 'cut_out': [], 'epochs': [],
           'warning': FORCE_WARNING, 'phrase': FORCE_PHRASE}
    if not ha_vote.AUTO_MODE_SHIPPED:
        out['why'] = ha_vote.NOT_SHIPPED_ERROR
        return out
    rt = _rt()
    node = _lease_live(st)
    case = _force_case(st, node)
    out['case'] = case
    if case is None:
        out['why'] = ('Force leader is the way out for a member of a group that fails over '
                      'automatically and lost its majority')
        return out
    me = st['instance_id']
    t = node.t if node is not None else ha_vote.Timings()
    quiet = _quiet_for(st, rt, node)
    out['quiet'] = round(quiet, 1)
    if node is not None and node.promise_to and ha_clock() < node.promise_until:
        out['why'] = (f'{_label(node.promise_to)} holds the promise of this member for '
                      f'{node.promise_until - ha_clock():.0f} s more: the group has a leader')
        return out
    if quiet < t.P + t.L / 2:
        out['why'] = (f'A leader was heard {quiet:.0f} s ago: Force leader is offered once no '
                      f'leader was heard for {t.P + t.L / 2:.0f} s')
        return out
    if case == 'auto':
        failed = node.last_failed
        since = node.heard_at if node.heard_at is not None else node.started
        if failed is None or failed['at'] < since:
            out['why'] = ('No election ran from here since the leader went quiet - use Make leader '
                          'first: Force leader is offered when it finds no majority')
            return out
        out['last_campaign'] = {'reached': failed['reached'], 'majority': failed['m']}
        if failed['reached'] >= failed['m']:
            out['why'] = (f"The last election reached a majority ({failed['reached']} of the "
                          f"{failed['m']} votes needed): the group can still elect a leader")
            return out
    voters = _force_voters(st)
    if probe:
        answers = {rec['instance_id']: (seen, err) for rec, seen, err in _group_says()}
        if _load().get('removed'):
            out['why'] = REMOVED_ERROR
            return out
    else:
        now = time.monotonic()
        ms = st.get('members') or {}
        # the role from the same look of the watch
        answers = {mid: (((ms.get(mid) or {}).get('role_seen'), None, None, None, None, seen), None)
                   for mid, seen in list(rt.seen.items())
                   if now - seen.get('at', -1e9) <= LEASE_SEEN_FRESH}
    # MK Oct 2026 (#625) - 'pending' and 'unknown' need no failed election, so what
    # answers decides: an active, a member that fails over automatically or holds a
    # switch other than the one held here, and the group has somebody to follow
    maker = _lease(st)['cfg'].get('by') if case == 'pending' else None
    allowed = {me, maker} - {None}
    reached, said = set(), []
    for mid, (value, err) in answers.items():
        if value is None and not isinstance(err, PeerRefused):
            continue
        reached.add(mid)
        if value is None:
            if case in ('pending', 'unknown'):
                # it is there and refuses this instance's calls: nothing it said is known,
                # and it may be the leader, the active or the maker. Counted as reached it
                # would not be cut out either (a clock far off refuses every member)
                out['why'] = (f'{_label(mid)} answers but refuses the calls of this instance (the '
                              f'clocks are more than {ha_wire.SIGNATURE_WINDOW} s apart, or it does '
                              'not know this instance): fix that first')
                return out
            continue
        if value[1] is not None:
            out['epochs'].append(value[1])
        seen = value[5] if len(value) > 5 else None
        said.append((mid, seen))
        if case == 'pending' and mid == maker:
            out['why'] = (f'{_label(mid)}, which started the switch, answers: take the switch back '
                          'there, or let it go through')
            return out
        if case in ('pending', 'unknown') and value[0] == ROLE_ACTIVE:
            out['why'] = f'{_label(mid)} answers as an active instance: {FORCE_FOLLOW}'
            return out
        if not isinstance(seen, dict):
            continue
        if seen.get('holds') is True or (seen.get('holder') and seen.get('mode') != ha_vote.MODE_MANUAL
                                         and seen.get('holder') != me):
            who = seen.get('holder') if seen.get('holds') is not True else mid
            out['why'] = (f"{_label(mid)} answers, and {'it holds' if who == mid else _label(who) + ' holds'} "
                          'the lease: the group has a leader. Follow it, or make this member leader there')
            return out
        if case == 'pending' and seen.get('mode') == ha_vote.MODE_AUTO:
            out['why'] = (f'{_label(mid)} fails over automatically: the switch went through. This '
                          'member takes the config from its leader')
            return out
        if case == 'unknown' and seen.get('mode') == ha_vote.MODE_AUTO:
            out['why'] = f'{_label(mid)} answers and fails over automatically: {FORCE_FOLLOW}'
            return out
        if (case in ('pending', 'unknown') and seen.get('mode') == ha_vote.MODE_PENDING
                and seen.get('pending_by') not in allowed):
            out['why'] = (f"{_label(mid)} holds a switch to automatic failover that "
                          f"{_label(seen.get('pending_by')) if seen.get('pending_by') else 'another instance'} "
                          f'started: {FORCE_FOLLOW}')
            return out
    if case == 'unknown':
        lease = _lease(st)
        if lease is not None and lease.get('mode') == ha_vote.MODE_MANUAL and _manual_known(st, lease, said) \
                and not way_out_refusal(st, said):
            out['why'] = ('The members that answer confirm the manual config of this instance: '
                          'promote it as usual')
            return out
    if case == 'auto':
        view = node.view
        count = len(({me} | reached) & view.counting)
        if count >= view.m:
            out['why'] = (f'{count} of the {view.n} votes answer, a majority: the group can still '
                          'elect a leader - use Make leader')
            return out
    noted = (_group_seen(st) or {}).get('witness') or {}
    out['cut_out'] = [{'instance_id': vid, 'kind': kind,
                       'url': (_lease_target(vid) or (noted if noted.get('instance_id') == vid else {})).get('url') or ''}
                      for vid, kind in sorted(voters.items()) if vid not in reached]
    out['offered'] = True
    return out


def _forced_config(st, lease, epoch, cut_out):
    """The lease block of the forced leader: one more voter config, in manual mode at its
    new epoch, without the members it cut out, chained to the one it held so the members
    that took that one take this one from its answers (a candidate asks for votes and
    hears MODE_MANUAL with the chain). Known as the group's: this instance is its manual
    active from now on."""
    private = _signer().private
    if private is None:
        raise HaError('This instance has no key pair to sign a voter config with')
    me = st['instance_id']
    prev = lease['cfg']
    body = dict(prev['body'], mode=ha_vote.MODE_MANUAL)
    body['voters'] = [rec for rec in body.get('voters') or () if rec['id'] not in cut_out]
    if (body.get('witness') or {}).get('id') in cut_out:
        body['witness'] = None
    ids = set(ha_vote.voter_ids(body))
    body['quarantined'] = [q for q in body.get('quarantined') or () if q in ids]
    if ha_vote.body_error(body):
        raise HaError(f'The voter config cannot be made ({ha_vote.body_error(body)})')

    def sign(message):
        return base64.b64encode(private.sign(message)).decode()
    chain = list(lease.get('cfg_chain') or [])
    if me in ha_vote.CfgView(prev).data:
        cfg = ha_vote.make_cfg(prev, epoch, me, body, sign)
        chain = (chain + [prev])[-ha_vote.CFG_KEEP:]
    else:
        # no data voter of the config held: a chain of its own, as _lease_found does
        pid = ha_vote.pair(prev['id'])
        cfg = {'id': [max(epoch, pid[0]), pid[1] + 1], 'prev': '', 'by': me, 'body': body}
        cfg['sig'] = sign(bytes.fromhex(ha_vote.cfg_digest(cfg)))
        chain = []
    block = dict(lease, cfg=cfg, cfg_chain=chain, mode=ha_vote.MODE_MANUAL, epoch=epoch,
                 voted_for=None, led=None, released=None, campaign_after=None,
                 gen=(lease['gen'] if type(lease.get('gen')) is int else 0) + 1,
                 settled=ha_vote.cfg_digest(cfg))
    block.pop('pending_since', None)
    return block


def force_leader(cut_out, reason, user='system'):
    """Force leader (7.3): this member becomes the manual active of its group at an epoch
    above every one it has seen. `cut_out` names every voter that does not answer, each
    confirmed by the admin as powered off or destroyed, `reason` says why. The members in
    it are out of the group (tombstones: they hear 410 and go passive when they come
    back), the witness among them is let go, the voter config goes to manual mode, and
    automatic failover comes back only through the switch with all its checks. After the
    restart the caller schedules, this instance writes its claim on every cluster with
    the claim on (marked forced) and sets autostart off on the VMs of the cut-out members
    an admin named (agent_vmid). Returns {epoch, cut_out, case}; raises ForceRefused."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        raise ForceRefused(ha_vote.NOT_SHIPPED_ERROR)
    reason = reason.strip() if isinstance(reason, str) else ''
    if not reason or len(reason) > FORCE_REASON_MAX or any(ord(ch) < 32 for ch in reason):
        raise ForceRefused(f'Say why, in up to {FORCE_REASON_MAX} characters on one line')
    if not isinstance(cut_out, list) or not all(isinstance(x, str) for x in cut_out):
        raise ForceRefused('cut_out is the list of the members that do not answer')
    view = force_leader_view(probe=True)
    if not view['offered']:
        raise ForceRefused(view['why'])
    expected = {c['instance_id'] for c in view['cut_out']}
    given = set(cut_out)
    if given - expected:
        raise ForceRefused('These answer and are not cut out: '
                           f"{', '.join(_label(x) for x in sorted(given - expected))}")
    if expected - given:
        raise ForceRefused('Tick every member that does not answer, each one powered off or destroyed: '
                           f"{', '.join(_label(x) for x in sorted(expected - given))}")
    rt = _rt()
    with rt.lock:
        with _lock:
            st = _load()
            if st['role'] != ROLE_STANDBY or st.get('removed') or st.get('broken'):
                raise ForceRefused('Only a member that follows is forced to lead')
            me = st['instance_id']
            ms = dict(st.get('members') or {})
            lease = _lease(st)
            seen = [int(st.get('epoch') or 0)] + [int(rec.get('epoch_seen') or 0) for rec in ms.values()]
            seen += [e for e in view['epochs'] if type(e) is int]
            if lease is not None:
                seen += [int(lease.get('epoch') or 0), ha_vote.pair(lease['cfg']['id'])[0],
                         int((lease.get('led') or {}).get('epoch') or 0)]
            new_epoch = max(seen) + 1
            if new_epoch > EPOCH_MAX:
                raise ForceRefused('The group has reached the highest epoch there is')
            tombs = dict(st.get('tombstones') or {})
            onboot = {}
            for mid in sorted(given):
                rec = ms.pop(mid, None)
                if rec is None:
                    continue
                tombs[mid] = dict(_credentials(rec), epoch=new_epoch, at=_now(), by=me)
                for cid, vmid in sorted((rec.get('agent_vmid') or {}).items()):
                    onboot.setdefault(cid, []).append(vmid)
            new = {k: v for k, v in st.items() if k not in ('group_mode', 'leader')}
            if (_witness(st) or {}).get('instance_id') in given:
                new.pop('witness', None)
            if lease is not None:
                new['lease'] = _forced_config(st, lease, new_epoch, given)
            cvr = _cv_record(st)
            if cvr is not None and cvr.get('joined'):
                cvr = None
            new.update(role=ROLE_ACTIVE, epoch=new_epoch, source=None, serve_assigned=False,
                       members={mid: dict(rec, role_seen=None) if rec.get('role_seen') == ROLE_ACTIVE
                                else dict(rec) for mid, rec in ms.items()},
                       tombstones=_bounded_tombstones(tombs), cv=cvr, change_gap=_gap_at_promotion(st),
                       forced={'epoch': new_epoch, 'at': _now(), 'by': str(user)[:64], 'reason': reason,
                               'case': view['case'], 'cut_out': sorted(given), 'onboot': onboot,
                               'tries': 0})
            _commit_locked(new)
            # the note of the group starts over from this state: one put back from before
            # the switch holds no voter config, and the old note would call it a copy
            _drop_group_seen()
            _note_group_seen(new)
        rt.stale = True
    _lease_after(rt)
    text = (f"forced to lead by {user} at epoch {new_epoch} ({view['case']}), manual mode: "
            f"{reason}; cut out as powered off or destroyed: "
            f"{', '.join(_label(x) for x in sorted(given)) or 'nobody'}")
    # the route writes the audit line under the admin's name
    logging.critical(f"[HA] {text}")
    _forced_alert(new_epoch, given)
    return {'epoch': new_epoch, 'cut_out': sorted(given), 'case': view['case']}


def _forced_alert(epoch, cut_out):
    """Force leader is a break-glass: it goes out on both paths every other alert takes,
    the plugin hook (push and whatever registered there) and the webhook channels, and
    as an ha_status event. Not with the reason: that is the admin's own text, and goes
    to the audit row. Never raises."""
    st = _load()
    me = st.get('own_url') or st['instance_id'][:8]
    message = (f'PegaProx instance {me} was forced to lead its HA group at epoch {epoch} and runs '
               f'in manual mode from now on; {len(cut_out)} member(s) cut out as powered off or '
               'destroyed. See the audit log.')
    alert = {'alert_name': 'HA group: Force leader', 'severity': 'critical', 'metric': 'ha_forced_leader',
             'target_type': 'instance', 'target_name': me, 'cluster_id': '',
             'current_value': f'epoch {epoch}', 'timestamp': _now(), 'message': message}
    try:
        from pegaprox.globals import _notification_handlers
        for handler in list(_notification_handlers):
            try:
                handler(alert)
            except Exception as e:
                logging.debug(f"[HA] notification handler failed: {e}")
    except Exception as e:
        logging.warning(f"[HA] could not hand the Force leader alert on: {e}")
    try:
        # the handlers above are the plugin hook, not the channels (#815)
        from pegaprox.utils.webhooks import send_to_channels
        send_to_channels(alert)
    except Exception as e:
        logging.warning(f"[HA] webhook dispatch of the Force leader alert failed: {e}")
    try:
        from pegaprox.globals import cluster_managers
        from pegaprox.utils.realtime import broadcast_sse
        # every cluster this instance acts on from now on
        broadcast_sse('ha_status', {'event': 'ha.forced_leader', 'message': message, 'epoch': epoch,
                                    'severity': 'critical'}, target_clusters=sorted(cluster_managers))
    except Exception as e:
        logging.debug(f"[HA] could not push the Force leader event: {e}")


def claim_forced():
    """Whether the claim this instance writes at its epoch is a forced one (7.3)."""
    st = _load()
    forced = st.get('forced') if isinstance(st.get('forced'), dict) else {}
    return st['role'] == ROLE_ACTIVE and forced.get('epoch') == int(st.get('epoch') or 0)


def forced_onboot_pass():
    """On the instance Force leader made the active, with every look at the group:
    autostart off on the VMs of the members it cut out, where an admin named them
    (agent_vmid) and their cluster answers (A5), so a node that boots does not start an
    instance the admin powered off. Each VM once; a cluster that does not answer is
    tried again at the next passes, ONBOOT_TRIES in all. Returns what was done now."""
    st = _load()
    forced = st.get('forced') if isinstance(st.get('forced'), dict) else None
    if (not forced or not forced.get('onboot') or st['role'] != ROLE_ACTIVE
            or forced.get('epoch') != int(st.get('epoch') or 0) or not is_active()):
        return []
    # the role in manual mode, at once; a round should automatic failover be on again
    if not confirm_step('autostart off on the VMs of the cut-out members'):
        return []
    from pegaprox.globals import cluster_managers
    left, done = {}, []
    for cid, vmids in sorted(forced['onboot'].items()):
        mgr = cluster_managers.get(cid)
        try:
            found = {str(r.get('vmid')): r for r in (mgr.get_vm_resources() or [])} if mgr else {}
        except Exception as e:
            logging.info(f"[HA] could not read the guests of cluster {cid}: {e}")
            found = {}
        for vmid in vmids:
            r = found.get(str(vmid))
            ok = False
            if r is not None and r.get('node'):
                try:
                    ok = bool((mgr.update_vm_config(r['node'], int(vmid), r.get('type') or 'qemu',
                                                    {'onboot': 0}) or {}).get('success'))
                except Exception as e:
                    logging.warning(f"[HA] could not switch autostart off for {cid}/{vmid}: {e}")
            if ok:
                done.append(f'{cid}/{vmid}')
            else:
                left.setdefault(cid, []).append(vmid)
    tries = int(forced.get('tries') or 0) + 1
    if tries >= ONBOOT_TRIES and left:
        _audit('ha.forced_onboot', 'autostart could not be switched off for the VMs of the cut-out '
                                   f"members: {json.dumps(left, sort_keys=True)} - do it by hand")
        left = {}
    with _lock:
        st = _load()
        if isinstance(st.get('forced'), dict) and st['forced'].get('epoch') == forced.get('epoch'):
            _commit_locked(dict(st, forced=dict(st['forced'], onboot=left, tries=tries)))
    if done:
        _audit('ha.forced_onboot', f"autostart switched off for the VMs of the cut-out members: {', '.join(done)}")
    return done


# --- removal and leaving (7.4) ---

def _remove_voter(member_id):
    """Leader of an automatic group: `member_id` out of the voter config, one change at
    a time, and back once that is on disk. Never below MIN_VOTERS, never the leader
    itself. Raises NoLease, AutoMode or HaError, and then nothing changed."""
    rt = _rt()
    with rt.lock:
        st = _load()
        node = _lease_node(rt)
        if node is None or not st.get('leader') or not node.is_active():
            raise NoLease(NO_LEASE_ERROR)
        if node.view.mode != ha_vote.MODE_AUTO:
            raise HaError(SWITCHING_OFF_ERROR)
        if member_id == st['instance_id']:
            raise AutoMode(AUTO_REMOVE_SELF_ERROR)
        if node.transfer is not None:
            raise HaError(TRANSFER_ERROR)
        if member_id not in node.view.records:
            return
        left = [v for v in node.view.voters if v != member_id]
        if member_id in node.view.voters and len(left) < ha_vote.MIN_VOTERS:
            raise AutoMode(AUTO_REMOVE_FEW_ERROR)
        # a quarantined member votes on paper only: what is left has to count
        if member_id in node.view.voters and len(node.view.counting - {member_id}) < ha_vote.MIN_VOTERS:
            raise AutoMode(AUTO_REMOVE_FEW_COUNTING_ERROR)

        def drop(body):
            return dict(body, voters=[rec for rec in body['voters'] if rec['id'] != member_id],
                        quarantined=[q for q in body.get('quarantined') or () if q != member_id])
        node.change_cfg(drop)
        rt.due = node.next_wake()
    _lease_after(rt)
    _lease_wait(_Until(lambda: node.dead or member_id not in node.view.records), CFG_CHANGE_WAIT)
    with rt.lock:
        if member_id in node.view.records:
            node.cancel_change(drop)
            raise HaError('The change of the voter config did not go through in time (a change '
                          'before it waits for a majority) - try again in a moment')


def member_leaves(member_id):
    """Leader of an automatic group: the member `member_id` unpairs (its route asked us
    first, 7.4). Out of the voter config, then out of the member list with a tombstone,
    as remove_member leaves one: should our answer get lost, the member's next call hears
    410 and it lets go of the group there. Raises NoLease, AutoMode, HaError."""
    st = _load()
    if not _lease_mode(st) or not st.get('leader'):
        raise HaError('This instance does not lead an automatic group')
    if member_id not in (st.get('members') or {}):
        raise HaError('That instance is not a member of this group')
    _remove_voter(member_id)
    with _lock:
        st = _load()
        ms = dict(st.get('members') or {})
        rec = ms.pop(member_id, None)
        if rec is None:
            return
        tombs = dict(st.get('tombstones') or {})
        tombs[member_id] = dict(_credentials(rec), epoch=int(st.get('epoch') or 0), at=_now(),
                                by=st['instance_id'])
        zone = group_timezone()
        new = dict(st, members=ms, tombstones=_bounded_tombstones(tombs))
        if not ms:
            new.update(role=ROLE_STANDALONE, member_secret=None)
            for key in _GROUP_KEYS:
                new.pop(key, None)
        _commit_locked(new)
        if not ms:
            _drop_group_seen()
    if not ms:
        _group_left(st['instance_id'], zone)
        _note_member_in_db('')


def leave_through_leader():
    """A member of an automatic group unpairs: the leader takes it out of the voter
    config first (7.4). Returns the leader's record; raises AutoMode when no leader
    answers or it refuses.

    A leader that took this instance out before, whose answer got lost, holds its
    tombstone and answers 410 (call_member lets go of the group here): this instance is
    out, and leaves. A 401 is no such answer - an instance that left the group since
    answers every call with it, and the group would keep counting this vote."""
    st = _load()
    rt = _rt()
    with rt.lock:
        node = _lease_live(st)
    leader = _known_leader(st, node)
    if leader is None:
        raise AutoMode(NO_LEADER_TO_LEAVE_ERROR)
    try:
        resp = call_member(leader, 'POST', LEAVE_PATH, json_body={}, timeout=CFG_CHANGE_WAIT + 10)
    except HaError as e:
        raise AutoMode(f'{NO_LEADER_TO_LEAVE_ERROR} ({_error_text(e)})')
    if resp.status_code == 410 and _load().get('removed'):
        return leader
    if resp.status_code != 200:
        raise AutoMode(_peer_error(resp, 'The leader did not take this instance out'))
    return leader


# --- the claim watch (4.10, 6.3, Q4 b) ---

def _step_down_for_claim(st, who, their, reason):
    me = st['instance_id']
    if _lease_mode(st):
        rt = _rt()
        with rt.lock:
            node = _lease_live(st)
            if node is None:
                return 'idle'
            node.step_down(reason)
        _lease_after(rt)
        _audit('ha.stepped_down', f'the claim watch: {reason}')
        return 'stepped down'
    if who != me and step_down(their, who):
        _audit('ha.stepped_down', f'the claim watch: {reason}')
        restart_process('stepped down to standby')
        return 'stepped down'
    if step_aside(their, reason):
        _audit('ha.stepped_aside', f'the claim watch: {reason}')
        restart_process('stepped aside to standby')
        return 'stepped aside'
    return 'ok'


# what _ha_claim_ensure says when no node took the write (manager._CLAIM_PASSING)
_CLAIM_NO_ANSWER = ('busy', 'unreachable', 'readonly', 'failed')


def claim_watch_soon():
    """The loop's way to the claim watch: on a greenlet of its own, one pass at a time, so
    a cluster whose nodes do not answer never holds up the look at the group. Returns True
    when it started a pass. Never raises."""
    try:
        st = _load()
        if st['role'] != ROLE_ACTIVE or not st.get('members'):
            return False
        watched = _rt().claims
    except Exception as e:
        logging.warning(f"[HA] claim watch: {e}")
        return False
    if not watched['busy'].acquire(blocking=False):
        return False

    def run():
        try:
            claim_watch()
        except Exception as e:
            logging.error(f"[HA] claim watch: {e}")
        finally:
            watched['busy'].release()
    try:
        _lease_spawn(run, 'ha-claim-watch')
    except Exception as e:
        watched['busy'].release()
        logging.warning(f"[HA] could not start the claim watch: {e}")
        return False
    return True


def _claim_job(watched, cid, mgr):
    """The claim write of one cluster as the watch sends it, on CLAIM_WATCH_NODES nodes at
    most. It stays in watched['jobs'] until it returned, late or not."""
    job = as_job(mgr._ha_claim_ensure, 'the claim watch')

    def run():
        try:
            return job(limit=CLAIM_WATCH_NODES)
        finally:
            watched['jobs'].discard(cid)
    return run


def claim_watch(force=False):
    """Every look at the group, on the active of a manual group and on the leader of an
    automatic one: the claim of every cluster with node HA and the claim switched on
    (6.3), at most once per CLAIM_WATCH. Ours goes on where it is lower or missing (the
    write is a compare-and-swap); a claim of this instance or of a member at a higher
    epoch means this one is the stale one, and it steps down. One of an instance this
    group does not know is refused there and said (_ha_claim_ensure), not followed.
    Nothing where no cluster has the claim on. Returns what it did.

    The loop runs it through claim_watch_soon. A cluster is asked on CLAIM_WATCH_NODES
    of its nodes, never while its write from a pass before still runs, and one that
    answered late or not at all is left alone for CLAIM_RETRY."""
    st = _load()
    if st['role'] != ROLE_ACTIVE or not st.get('members') or st.get('removed') or st.get('broken'):
        return 'idle'
    if not is_active():
        return 'idle'
    watched = _rt().claims
    now = time.monotonic()
    if not force and watched['at'] is not None and 0 <= now - watched['at'] < CLAIM_WATCH:
        return 'cached'
    from pegaprox.globals import cluster_managers
    todo = []
    for cid, mgr in sorted(list(cluster_managers.items()), key=lambda x: str(x[0])):
        on = getattr(mgr, '_ha_claim_enabled', None)
        if getattr(mgr, 'ha_enabled', False) is not True or not callable(on) or not on():
            continue
        if cid in watched['jobs']:
            continue
        last = watched['seen'].get(cid)
        if last is not None and last[1] is not None and now < last[1]:
            # a foreign claim this watch cannot act on, or no answer: looked at again later
            continue
        todo.append((cid, mgr))
    watched['at'] = now
    if not todo:
        return 'none'
    results = []
    for i in range(0, len(todo), CLAIM_WATCH_AT_ONCE):
        batch = todo[i:i + CLAIM_WATCH_AT_ONCE]
        watched['jobs'].update(cid for cid, _m in batch)
        try:
            results += _fan_out([_claim_job(watched, cid, mgr) for cid, mgr in batch], CLAIM_WATCH_WAIT)
        except Exception:
            # the threads did not start: these clusters are asked again at the next pass
            watched['jobs'].difference_update(cid for cid, _m in batch)
            raise
    # the state as it is now: the look at the group went on meanwhile
    st = _load()
    if st['role'] != ROLE_ACTIVE or st.get('removed') or not is_active():
        return 'idle'
    me, mine = st['instance_id'], int(st.get('epoch') or 0)
    ms = st.get('members') or {}
    now = time.monotonic()
    for (cid, mgr), (res, err) in zip(todo, results):
        if err is not None or not isinstance(res, dict) or res.get('state') in _CLAIM_NO_ANSWER:
            # late, failed, or no node took it
            watched['seen'][cid] = (None, now + CLAIM_RETRY)
            continue
        state, who, their = res.get('state'), res.get('instance'), res.get('epoch')
        stale = state == 'higher' and type(their) is int and their > mine and (who == me or who in ms)
        foreign = state in ('higher', 'same', 'unreadable') and not stale
        watched['seen'][cid] = ((state, who, their), now + CLAIM_REPEAT if foreign else None)
        if stale:
            name = getattr(getattr(mgr, 'config', None), 'name', None) or cid
            whose = 'a newer copy of this instance' if who == me else _label(who)
            return _step_down_for_claim(st, who, their, f'cluster {name} carries the claim of {whose} '
                                                       f"at epoch {their}, above this instance's {mine}")
    return 'ok'


# --- what an admin sets per member ---

def set_agent_vmid(member_id, cluster_id, vmid):
    """Leader: the VM the member `member_id` (this instance included) runs as on cluster
    `cluster_id`, None to forget it. Force leader switches autostart off on it when it
    cuts that member out (7.3). It travels with the member list. Returns True when it
    changed."""
    if not isinstance(cluster_id, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', cluster_id):
        raise HaError('cluster_id is the id of a cluster')
    if vmid is not None and (isinstance(vmid, bool) or not isinstance(vmid, int) or not 100 <= vmid <= 999999999):
        raise HaError('vmid is the id of a VM (100 or more), or null')
    with _lock:
        st = _load()
        if st['role'] != ROLE_ACTIVE or not st.get('members'):
            raise HaError('The VM of a member is set on the leader of a group')
        if _lease_mode(st) and not is_active():
            raise NoLease(NO_LEASE_ERROR)
        me = st['instance_id']
        ms = dict(st.get('members') or {})
        if member_id != me and member_id not in ms:
            raise HaError('That instance is not a member of this group')
        held = dict((st.get('agent_vmid') if member_id == me else ms[member_id].get('agent_vmid')) or {})
        if held.get(cluster_id) == vmid or (vmid is None and cluster_id not in held):
            return False
        if vmid is None:
            held.pop(cluster_id, None)
        else:
            held[cluster_id] = vmid
        if member_id == me:
            _commit_locked(dict(st, agent_vmid=held))
        else:
            ms[member_id] = dict(ms[member_id], agent_vmid=held)
            _commit_locked(dict(st, members=ms))
    return True


SITE_LEADER_ERROR = 'The site of a member is set on the leader of a group'
VOTE_LEADER_ERROR = 'Vote and may lead are set on the leader of a group'
SITE_ERROR = f'The site is a label of up to {ha_vote.SITE_MAX} characters on one line'
NOT_A_MEMBER_ERROR = 'That instance is not a member of this group'
VOTE_OWN_ERROR = 'The leader keeps its own vote - make another member leader first'
VOTE_WITNESS_ERROR = 'The witness always votes and never leads - remove it to take its vote'
VOTE_FEW_ERROR = (f'Without this vote the group would have fewer than {ha_vote.MIN_VOTERS} votes, too '
                  'few for automatic failover. Add a member or a witness first')
VOTE_FEW_COUNTING_ERROR = (f'Without this vote fewer than {ha_vote.MIN_VOTERS} votes of the group would count '
                           '(a quarantined member votes on paper only), too few for automatic failover. '
                           'Re-admit the quarantined member first')
VOTE_BUSY_ERROR = 'A change of the voter config is on its way - try again in a moment'
VOTE_MAJORITY_ERROR = ('After this change the members that answer would not make a majority of the '
                       'votes, and the leader would lose its lease. Bring the members that do not '
                       'answer back first')


class VoteRefused(HaError):
    """set_member_vote: a rule of the voter config stands in the way (design 4.12)."""


def set_member_site(member_id, site):
    """Leader: the site the instance `member_id` runs at (this instance, a member or the
    witness), '' for none. A label for the split checks (_site_findings): it decides
    nothing about who votes, leads or acts, so a manual group takes it too, whether or
    not this release offers automatic failover. It travels with the member list, the
    witness's with its record; in an automatic group the voter config follows the
    witness record (_witness_into_config). Not while a switch to automatic failover is
    pending (the pending config names the sites it was made with), and in an automatic
    group only while this instance may act. Returns True when it changed."""
    label = _clean_site(site)
    if label is None:
        raise HaError(SITE_ERROR)
    witness_changed = False
    with _lock:
        st = _load()
        if st['role'] != ROLE_ACTIVE or not st.get('members') or st.get('removed') or st.get('broken'):
            raise HaError(SITE_LEADER_ERROR)
        if mode(st) == ha_vote.MODE_PENDING:
            raise AutoMode(AUTO_PENDING_ERROR)
        if _lease_mode(st) and not is_active():
            raise NoLease(NO_LEASE_ERROR)
        me, ms, w = st['instance_id'], dict(st.get('members') or {}), _witness(st)
        if member_id == me:
            if (_clean_site(st.get('site')) or '') == label:
                return False
            new = dict(st, site=label) if label else {k: v for k, v in st.items() if k != 'site'}
        elif member_id in ms:
            if (_clean_site(ms[member_id].get('site')) or '') == label:
                return False
            rec = dict(ms[member_id], site=label)
            if not label:
                rec.pop('site')
            ms[member_id] = rec
            new = dict(st, members=ms)
        elif w is not None and member_id == w['instance_id']:
            if w['site'] == label:
                return False
            new = dict(st, witness=dict(w, site=label))
            witness_changed = True
        else:
            raise HaError(NOT_A_MEMBER_ERROR)
        _commit_locked(new)
    if witness_changed and _lease_mode(_load()):
        _witness_into_config()
    return True


def set_member_vote(member_id, voter=None, may_lead=None):
    """Leader: whether the data member `member_id` (this instance included) votes and may
    lead on its own. In an automatic group a change of the voter config (4.12): under a
    confirm round, one change at a time (refused while one waits or is on its way),
    never below MIN_VOTERS votes that count (a quarantined one does not), never the vote
    of the leader itself, never a vote for a member that does not answer the renewals,
    and never one after which the members that answer would not make a majority. Back
    once the change is on disk, in force once a majority holds it; the member record
    follows. In a manual group the member records, which the next switch takes into the
    voter config (_voter_body); the leader keeps its vote there too, and a member counts
    its own as the leader's member list says. Returns True when something changed.
    Raises VoteRefused, NoLease, AutoMode or HaError, and then nothing changed."""
    if not ha_vote.AUTO_MODE_SHIPPED:
        raise HaError(ha_vote.NOT_SHIPPED_ERROR)
    asked = {k: v for k, v in (('voter', voter), ('may_lead', may_lead)) if v is not None}
    if not asked or not all(type(v) is bool for v in asked.values()):
        raise HaError('voter and may_lead are true or false, one of them at least')
    st = _load()
    if st['role'] != ROLE_ACTIVE or not st.get('members') or st.get('removed') or st.get('broken'):
        raise HaError(VOTE_LEADER_ERROR)
    if mode(st) == ha_vote.MODE_PENDING:
        raise AutoMode(AUTO_PENDING_ERROR)
    me = st['instance_id']
    if (_witness(st) or {}).get('instance_id') == member_id:
        raise VoteRefused(VOTE_WITNESS_ERROR)
    if member_id != me and member_id not in (st.get('members') or {}):
        raise HaError(NOT_A_MEMBER_ERROR)
    if member_id == me and asked.get('voter') is False:
        raise VoteRefused(VOTE_OWN_ERROR)
    automatic = _lease_mode(st)
    if automatic:
        changed = _vote_in_config(member_id, asked)
    else:
        with _lock:
            st = _load()
            body = _voter_body(st, ha_vote.LEASE_DEFAULT)
            rec = next((r for r in body['voters'] if r['id'] == member_id), None)
            if rec is None:
                raise HaError(NOT_A_MEMBER_ERROR)
            if asked.get('voter') is False and rec['voter'] and len(ha_vote.voter_ids(body)) - 1 < ha_vote.MIN_VOTERS:
                raise VoteRefused(VOTE_FEW_ERROR)
            changed = any(rec[k] != v for k, v in asked.items())
    if changed:
        try:
            _vote_marks(member_id, asked)
        except Exception as e:
            if not automatic:
                # in a manual group the record is the change itself: nothing changed
                raise
            # the voter config holds the change already and decides; the record that a
            # later switch reads is what failed
            logging.warning(f"[HA] the vote of {member_id} changed in the voter config, but its "
                            f"member record could not be written: {e}")
    return changed


def _vote_marks(member_id, asked):
    """The member record (this instance's own state for itself) after a change of vote
    or may lead: only what differs from the default is kept."""
    with _lock:
        st = _load()
        if member_id == st['instance_id']:
            rec, ms = dict(st), None
        else:
            ms = dict(st.get('members') or {})
            if member_id not in ms:
                return
            rec = dict(ms[member_id])
        for key, value in asked.items():
            if key == 'voter' and ms is None:
                continue
            if value:
                rec.pop(key, None)
            else:
                rec[key] = False
        _commit_locked(rec if ms is None else dict(st, members=dict(ms, **{member_id: rec})))


def _vote_in_config(member_id, asked):
    """set_member_vote in an automatic group: one change of the voter config, made by
    the node of this leader once a majority confirmed its lease again."""
    if not confirm_lease(NEED_STEP):
        raise NoLease(NO_LEASE_ERROR)
    rt = _rt()
    with rt.lock:
        st = _load()
        node = _lease_node(rt)
        if node is None or not st.get('leader') or not node.is_active():
            raise NoLease(NO_LEASE_ERROR)
        if node.view.mode != ha_vote.MODE_AUTO:
            raise HaError(SWITCHING_OFF_ERROR)
        if node.transfer is not None:
            raise HaError(TRANSFER_ERROR)
        if node.change_pending():
            raise VoteRefused(VOTE_BUSY_ERROR)
        rec = node.view.records.get(member_id)
        if rec is None:
            raise VoteRefused(f'{_label(member_id)} is not in the voter config yet - try again in a moment')
        want = dict(rec, **asked)
        if want == rec:
            return False

        def change(body):
            voters = [dict(r, **asked) if r['id'] == member_id else r for r in body['voters']]
            out = dict(body, voters=voters)
            if asked.get('voter') is False:
                out['quarantined'] = [q for q in body.get('quarantined') or () if q != member_id]
            return out
        after = ha_vote.CfgView({'id': list(node.view.id), 'body': change(node.view.cfg['body'])})
        if asked.get('voter') is False and rec.get('voter') and after.n < ha_vote.MIN_VOTERS:
            raise VoteRefused(VOTE_FEW_ERROR)
        # a quarantined vote stands in n and answers nothing: the floor is three that count
        if asked.get('voter') is False and rec.get('voter') and len(after.counting) < ha_vote.MIN_VOTERS:
            raise VoteRefused(VOTE_FEW_COUNTING_ERROR)
        t = node.t
        window = 2 * (t.R + t.renew_timeout)
        # this leader, and every voter that acked one of its last rounds
        heard = {st['instance_id']} | {v for v in after.voters if ha_clock() - rt.acked.get(v, -1e9) <= window}
        if asked.get('voter') is True and not rec.get('voter') and member_id not in heard:
            raise VoteRefused(f'{_label(member_id)} does not answer the renewals of this leader: a vote '
                              'it cannot give would only take one from the majority')
        if len(heard & after.counting) < after.m:
            raise VoteRefused(VOTE_MAJORITY_ERROR)
        node.change_cfg(change)
        rt.due = node.next_wake()
    _lease_after(rt)
    _lease_wait(_Until(lambda: node.dead or node.view.records.get(member_id) == want), CFG_CHANGE_WAIT)
    with rt.lock:
        if node.view.records.get(member_id) != want:
            node.cancel_change(change)
            raise HaError('The change of the voter config did not go through in time - try again in a moment')
    return True


def _clean_agent_vmid(value):
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in list(value.items())[:64]
            if isinstance(k, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', k)
            and type(v) is int and 100 <= v <= 999999999}


# --- on the status page ---

def make_leader_status(st, node, rt):
    """For the status page: what Make leader, a planned restart and Force leader look like
    from here (field names in lease_status)."""
    out = {'transfer': None, 'planned_restart': None, 'last_campaign': None,
           'make_leader': {'phrase': LEADER_PHRASE, 'self': False}}
    now = ha_clock()
    if node is not None and node.transfer is not None:
        t = node.transfer
        out['transfer'] = {'to': t['to'], 'to_url': (_lease_target(t['to']) or {}).get('url') or '',
                           'phase': t['phase'], 'left': round(max(0.0, t['until'] - now), 1)}
    if rt.planned is not None and now < rt.planned[1]:
        by = rt.planned[0]
        out['planned_restart'] = {'by': by, 'by_url': (_lease_target(by) or {}).get('url') or '',
                                  'hold_left': round(rt.planned[1] - now, 1)}
    if node is not None and node.last_failed is not None:
        f = node.last_failed
        out['last_campaign'] = {'ago': round(max(0.0, now - f['at']), 1), 'kind': f['kind'],
                                'reached': f['reached'], 'majority': f['m'], 'reasons': f['reasons'],
                                'unreachable': f['reached'] < f['m']}
    out['make_leader']['self'] = bool(
        node is not None and st['role'] == ROLE_STANDBY and node.view.mode == ha_vote.MODE_AUTO
        and node.view.candidate(st['instance_id'], timer=False))
    forced = st.get('forced') if isinstance(st.get('forced'), dict) else None
    out['forced'] = ({k: forced.get(k) for k in ('epoch', 'at', 'by', 'reason', 'case', 'cut_out')}
                     | {'onboot_left': forced.get('onboot') or {}}) if forced else None
    out['force_leader'] = {k: v for k, v in force_leader_view(st).items() if k != 'epochs'}
    out['way_out'] = way_out_refusal(st)
    return out


# --- the transport guard (design 5.3) ------------------------------------------------
#
# MK Oct 2026 (#625) - the gates above decide whether a loop starts a step. What the
# step sends to a cluster, a node or a BMC leaves this process through a short list of
# exits (ha_transport.py; the whole list is in tests/test_ha_exits.py), and each of
# them asks guard() right before the call goes out.
#
# Anywhere but in an automatic group guard() returns at once and nothing is asked that
# was not asked before. In an automatic group a call that changes something goes out
# only from the lease holder while it may act, and only after a majority renewed the
# lease in a round that started after the call was asked for: a local clock cannot see
# a pause that held it, the voters can. confirm_lease() leaves a token for one call in
# the thread or greenlet that asked; the step's first call goes out on it, every further
# call (the next guest a recovery stops, the next command of a user job, the next write
# of a request) asks for a round of its own, shared with whoever waits for one at the
# time. A call that is sent once more, or whose connection came up late, is checked
# again on its token. A background thread that never confirmed is refused: a step
# without its confirm is a bug, not a call to make. Reads pass everywhere, so do the
# console proxies, the logins and, in a GET, the SSH commands that read for it.

NEED_SAME_GOAL = 0.0                     # stopping the failed node and its guests (5.4)
NEED_STEP = ha_vote.Timings().need       # every other step that changes a cluster

GUARD_NO_LEASE = 'this instance does not hold the lease of its group'
GUARD_NO_TOKEN = 'no step in this thread confirmed the lease first'
GUARD_RAN_OUT = 'the lease confirmed for this step ran out'
GUARD_UNCONFIRMED = 'no majority confirmed the lease for this call'


class GuardRefused(NoLease):
    """A call that would change something outside this process, refused at its exit in
    an automatic group. Says which call and why."""

    def __init__(self, action, why):
        super().__init__(f'{action} refused: {why}')
        self.action, self.why = action, why


class _Token:
    """What a confirmed round leaves in the thread that asked: whose node and which build
    of it, how many clock jumps its loop had seen, where the lease stood as the round came
    back, the need of the step, and whether a call went out on it already."""

    __slots__ = ('instance', 'gen', 'jumps', 'until', 'need', 'used')

    def __init__(self, instance, gen, jumps, until, need):
        self.instance, self.gen, self.jumps = instance, gen, jumps
        self.until, self.need, self.used = until, need, False


# per thread, a greenlet under gevent: token (a _Token), reading (depth of reading()
# blocks), job (what as_job runs), request (the method of the request a fan-out
# started from) and refused (where that request notes a refusal, _refusals)
_guard_tls = threading.local()
_guard_said = set()
_READ_METHODS = frozenset(('GET', 'HEAD'))
# the refusals at the exits during a request, in its WSGI environ: most routes take the
# GuardRefused for a failed cluster call, and app.py answers 503 HA_NO_LEASE for them
GUARD_REFUSED_ENVIRON = 'pegaprox.ha_guard_refused'


def guard_on():
    """Whether the exits ask anything here at all: only while the lease is in force."""
    return _lease_mode(_load())


def _request_method():
    """The method of the request to this instance that this thread serves, '' when none."""
    said = getattr(_guard_tls, 'request', '')
    if said:
        return said
    try:
        from flask import has_request_context, request
        return request.method if has_request_context() else ''
    except Exception:
        return ''


def _in_request():
    return bool(_request_method())


def _refusals():
    """The list a refusal at an exit goes into for the request this thread serves: the
    one carry() handed a fan-out of it, or the request's own. None outside a request."""
    said = getattr(_guard_tls, 'refused', None)
    if said is not None:
        return said
    try:
        from flask import has_request_context, request
        if has_request_context():
            return request.environ.setdefault(GUARD_REFUSED_ENVIRON, [])
    except Exception:
        pass
    return None


def _token_fits(st, tok, need=None):
    """`tok` is from the node of this instance as it runs now, no clock jump came since,
    and it leaves the need of the step that asked for it, or `need` where the exit asks
    for more."""
    rt = _rts.get(st['instance_id'])
    return (tok is not None and rt is not None and tok.instance == st['instance_id']
            and tok.gen == rt.gen and tok.jumps == rt.jumps
            and ha_clock() <= tok.until - max(tok.need, need or 0.0))


def _clock_look(rt):
    """The node's look at the clock, under its lock, as a tick takes it (ha_vote
    Node.watch_clock). A step it finds counts in rt.jumps at once; the loop is woken for
    the round the step asks for."""
    jumps = rt.jumps
    with rt.lock:
        node = rt.node
        if node is not None:
            node.watch_clock()
    if rt.jumps != jumps:
        _lease_after(rt)


def _guard_refuse(action, why):
    said = _refusals()
    if said is not None:
        said.append(why)
    if (action, why) not in _guard_said:
        # each exit once: a loop that keeps trying must not fill the log
        if len(_guard_said) > 512:
            _guard_said.clear()
        _guard_said.add((action, why))
        logging.error(f"[HA] {action} refused at the transport: {why}")
    raise GuardRefused(action, why)


def guard(action, kind=None, need=None, again=False):
    """Right before a call that changes something leaves for a cluster, a node or a BMC.
    `action` names it (method and path, or the command). kind 'console' and 'login'
    pass in every role, 'cheap' needs the lease and no round (a spare PVE API token does
    no harm), 'ssh' passes in a GET as a read. `need` is lease time the call itself
    wants left, on top of what the step that confirmed asked for (5.4). `again` for the
    same call once more (a new login, a fallback, the connection now up): the token it
    went out on is checked, no new round while that still fits. Raises GuardRefused in
    an automatic group, never anywhere else."""
    st = _load()
    if not _lease_mode(st) or kind in ('console', 'login') or getattr(_guard_tls, 'reading', 0):
        return
    if kind == 'ssh' and _request_method() in _READ_METHODS:
        # a GET answered here, on the leader or a member that serves users: the command
        # is how the read gets to the node, and an SSH command cannot say so itself
        return
    node = _lease_live(st)
    if node is None or not node.is_active():
        _guard_refuse(action, GUARD_NO_LEASE)
    if kind == 'cheap':
        return
    tok = getattr(_guard_tls, 'token', None)
    rt = _rts.get(st['instance_id'])
    if tok is not None and rt is not None:
        # the node sees a step of its clock only when it looks: a pause that held the
        # lease clock moved the wall clock alone, and the token from before it is void
        # (rt.jumps) once the node looked
        _clock_look(rt)
    if _token_fits(st, tok, need) and (again or not tok.used):
        tok.used = True
        return
    # a round of its own, where this thread may ask for one: in a step that confirmed
    # (each further command of it), in a user job, in a request to this instance
    step = tok is not None and rt is not None and tok.instance == st['instance_id'] and tok.gen == rt.gen
    asks = bool(getattr(_guard_tls, 'job', None)) or _in_request()
    if step or asks:
        want = max(need or 0.0, tok.need if step else 0.0, NEED_STEP if asks else 0.0)
        if confirm_lease(want):
            fresh = getattr(_guard_tls, 'token', None)
            if _token_fits(st, fresh, need):
                fresh.used = True
                return
        _guard_refuse(action, GUARD_UNCONFIRMED)
    _guard_refuse(action, GUARD_RAN_OUT if tok is not None else GUARD_NO_TOKEN)


@contextlib.contextmanager
def reading():
    """Around calls that change nothing but leave through an exit that cannot tell a read
    from a write (an SSH command, POST /nodes/<n>/execute): the guard lets them pass in
    this thread. Keep it tight, a write inside it goes out unasked."""
    _guard_tls.reading = getattr(_guard_tls, 'reading', 0) + 1
    try:
        yield
    finally:
        _guard_tls.reading -= 1


_CARRIED = (('request', ''), ('token', None), ('reading', 0), ('job', None), ('refused', None))


def carry(fn):
    """fn as it runs in another thread or greenlet, with what this one may send: its
    token, its reads, the request it serves and the job it runs. A fan-out carries it,
    or the calls of a confirmed step it spreads out go out unconfirmed and are refused.
    A refusal in fn is noted for that request too. Once fn is done the worker has what
    it had before, so nothing fn confirmed serves its next task. fn itself where the
    lease is not in force."""
    if not guard_on():
        return fn
    ctx = ([_request_method()] + [getattr(_guard_tls, k, d) for k, d in _CARRIED[1:-1]]
           + [_refusals()])

    @functools.wraps(fn)
    def run(*args, **kwargs):
        saved = [getattr(_guard_tls, k, d) for k, d in _CARRIED]
        for (k, _d), v in zip(_CARRIED, ctx):
            setattr(_guard_tls, k, v)
        try:
            return fn(*args, **kwargs)
        finally:
            for (k, _d), v in zip(_CARRIED, saved):
                setattr(_guard_tls, k, v)
    return run


def as_job(fn, what):
    """A user job that runs on in a thread of its own after the request that started it
    returned (an evacuation, a node update, a migration, a deploy). In an automatic group
    each call it sends asks for a round of its own at the exit, as a step of an automation
    confirms before it starts. fn itself where the lease is not in force (a job started
    before a switch to automatic failover carries no mark, and its writes after the
    switch are refused at the exit)."""
    if not guard_on():
        return fn

    @functools.wraps(fn)
    def run(*args, **kwargs):
        saved = (getattr(_guard_tls, 'job', None), getattr(_guard_tls, 'token', None))
        _guard_tls.job, _guard_tls.token = what, None
        try:
            return fn(*args, **kwargs)
        finally:
            # what the job confirmed is gone with it: the thread may run something else next
            _guard_tls.job, _guard_tls.token = saved
    return run


def confirm_step(what, need=NEED_STEP):
    """confirm_lease() before a step of an automation that cannot be taken back (5.2),
    and a log line when the answer is no: a leader that lost its lease starts no new
    step. In manual mode and on an instance of its own it is the role, at once."""
    if confirm_lease(need):
        return True
    if guard_on():
        logging.warning(f"[HA] {what}: not started - the lease of this instance could not be confirmed")
    return False


# --- interrupted recoveries (design 5.6) ---------------------------------------------
#
# A node recovery the leader started and did not finish (the lease went, the process
# ended) is written down step by step in ha_recovery_journal, a shared table: the next
# leader pulls it with the configuration and says what is left. Guests whose config was
# moved off the failed node and did not start are listed; nothing resumes them by itself
# (an admin starts them, PegaProxManager.ha_start_moved_vms). A guest the worker moved
# while the failed node was online and did not start on purpose (step 'hold') is listed
# apart and never started from here: the node may still run it without a config.
# Written in an automatic group only, where another instance takes over; nothing
# changes anywhere else.

RECOVERY_KEEP = 256
_recovery_live = set()
_recovery_lock = threading.Lock()


def _recovery_table(cur):
    cur.execute('CREATE TABLE IF NOT EXISTS ha_recovery_journal (id TEXT PRIMARY KEY, run TEXT NOT NULL, '
                'cluster_id TEXT NOT NULL, node TEXT NOT NULL, epoch INTEGER NOT NULL, '
                'instance_id TEXT NOT NULL, step TEXT NOT NULL, vmid INTEGER, done INTEGER NOT NULL '
                'DEFAULT 0, at TEXT)')


def _recovery_write(sql, args):
    try:
        from pegaprox.core.db import get_db
        conn = get_db().conn
        with _recovery_lock:
            cur = conn.cursor()
            _recovery_table(cur)
            cur.execute(sql, args)
            conn.commit()
        return True
    except Exception as e:
        logging.error(f"[HA] could not write the recovery journal: {e}")
        return False


def recovery_begin(cluster_id, node):
    """A node recovery starts: the id of its run, None where nothing is written down."""
    st = _load()
    if not _lease_mode(st):
        return None
    run = f"{int(st.get('epoch') or 0)}.{st['instance_id'][:12]}.{secrets.token_hex(4)}"
    with _recovery_lock:
        _recovery_live.add(run)
    recovery_step(run, cluster_id, node, 'begin', done=True)
    return run


# The step that takes a guest's config off the failed node. Its 'begun' row (and the hold
# written just before it) goes to the members at once (_send_on), before the step's confirm
# round: a leader gone right after leaves the next leader a journal that names the guest.
# The round carries the new cv to the voters, and a voter that holds less pulls right away
# (_lease_heard). One send-on per guest: each is a walk of the shared tables (about 0.4 s at
# 10k guests) in the recovery's own time. A lost 'start' row costs nothing - the guest runs
# and drops out, or sits stopped on the target with its move listed.
_SENT_AT_ONCE = frozenset(('move_config',))


def _recovery_key(run, step, vmid):
    return f"{run}/{step}" + (f"/{vmid}" if vmid is not None else '')


def recovery_step(run, cluster_id, node, step, vmid=None, done=False):
    """Before (done False) and after (done True) a step of the run."""
    if run is None:
        return
    st = _load()
    _recovery_write('INSERT OR REPLACE INTO ha_recovery_journal (id, run, cluster_id, node, epoch, '
                    'instance_id, step, vmid, done, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (_recovery_key(run, step, vmid), run, str(cluster_id), str(node),
                     int(st.get('epoch') or 0), st['instance_id'], step,
                     None if vmid is None else int(vmid), 1 if done else 0, _now()))
    if not done and step in _SENT_AT_ONCE:
        _send_on('the recovery journal')


def recovery_clear(run, step, vmid=None):
    """Take back the row of a step that turned out not to be needed (a hold the look
    after the move did not confirm)."""
    if run is not None:
        _recovery_write('DELETE FROM ha_recovery_journal WHERE id = ?', (_recovery_key(run, step, vmid),))


def recovery_drop_guests(run, vmids):
    """The rows of guests that started: nothing is left to say about them, whatever else
    keeps their run."""
    vmids = sorted({int(v) for v in vmids or ()})
    if run is not None and vmids:
        _recovery_write(f"DELETE FROM ha_recovery_journal WHERE run = ? AND vmid IN "
                        f"({', '.join('?' * len(vmids))})", (str(run), *vmids))


def _steps_begun(rec, vmid):
    return {s.rsplit(' ', 1)[0] for s in rec['open'] if s.rsplit(' ', 1)[-1] == str(vmid)}


def recovery_end(run, locate=None):
    """The worker is done with the run. A run that left a guest moved and not started,
    or a step on a guest begun and not finished, stays in the journal and is listed as
    interrupted from now on, here as well, until the guest started
    (PegaProxManager.ha_start_moved_vms) or the next leader took the run over: its
    record is returned for the worker to report. A step begun on a guest is kept only
    where the guest's config may have left the failed node - its start began, or its
    move did and `locate()` (the guests as the cluster lists them now, {vmid: entry},
    None when unread) does not show it there; one whose config still sits there is
    the monitor's again. A guest held on purpose ('hold') keeps the run listed and was
    reported by the worker already. Any other run is forgotten - a step on the failed
    node that did not finish is done again by the next pass of the monitor, the guests'
    configs still sit there. A run cut short by the lease stays as it is, for the next
    leader. The rows of the guests that started go either way. None where nothing is
    kept to report."""
    if run is None:
        return None
    with _recovery_lock:
        _recovery_live.discard(run)
    if not is_active():
        return None
    _recovery_write('DELETE FROM ha_recovery_journal WHERE run = ? AND vmid IN (SELECT vmid FROM '
                    'ha_recovery_journal WHERE run = ? AND step = ? AND done = 1)', (run, run, 'start'))
    left = recovery_leftovers(run=run)
    rec = left[0] if left else None
    if rec and rec['guests_open']:
        where, keep = False, []
        for vmid in rec['guests_open']:
            begun = _steps_begun(rec, vmid)
            if 'start' not in begun and 'move_config' in begun:
                if where is False:
                    try:
                        where = locate() if locate else None
                    except Exception:
                        where = None
                if where is not None and (where.get(vmid) or {}).get('node') == rec['node']:
                    continue
            elif 'start' not in begun:
                # nothing began that takes the config away
                continue
            keep.append(vmid)
        for vmid in set(rec['guests_open']) - set(keep):
            _recovery_write('DELETE FROM ha_recovery_journal WHERE run = ? AND vmid = ?', (run, int(vmid)))
            rec['open'] = [s for s in rec['open'] if s.rsplit(' ', 1)[-1] != str(vmid)]
        rec['guests_open'] = keep
    if rec and (rec['moved'] or rec['guests_open'] or rec['held']):
        return rec if rec['moved'] or rec['guests_open'] else None
    _recovery_write('DELETE FROM ha_recovery_journal WHERE run = ?', (run,))
    return None


def recovery_forget(runs):
    """An admin dealt with what these runs left."""
    for run in runs or ():
        _recovery_write('DELETE FROM ha_recovery_journal WHERE run = ?', (str(run),))


_recovery_said = {}


def recovery_leftovers(cluster_id=None, run=None):
    """The recovery runs that stopped half way, none of this process's live ones, or
    the one run `run`: [{run, cluster_id, node, epoch, instance_id, at, moved_at, open:
    [step], guests_open: [vmid], moved: [vmid], held: [vmid]}], oldest first. moved names
    the guests whose config left the failed node and that no step started, guests_open
    those with a step begun and not finished, held those moved while the failed node was
    online and not started on purpose, or whose look at the node never finished (a
    'hold' begun); whether they run now is the cluster's to say. moved_at is when the
    first config of the run began to move (None before any did). The newest
    RECOVERY_KEEP runs of the cluster, each with all its rows; more than that kept is
    said once per count."""
    try:
        from pegaprox.core.db import get_db
        cur = get_db().conn.cursor()
        if 'ha_recovery_journal' not in _existing_tables(cur):
            return []
        cols = 'SELECT run, cluster_id, node, epoch, instance_id, step, vmid, done, at FROM ha_recovery_journal'
        with _recovery_lock:
            live = sorted(_recovery_live)
        if run is not None:
            cur.execute(cols + ' WHERE run = ? ORDER BY at, id', (str(run),))
            rows = cur.fetchall()
        else:
            where, args = [], []
            if cluster_id is not None:
                where.append('cluster_id = ?')
                args.append(str(cluster_id))
            if live:
                where.append(f"run NOT IN ({', '.join('?' * len(live))})")
                args += live
            cond = (' WHERE ' + ' AND '.join(where)) if where else ''
            # whole runs, the newest first: a kept run of a large node, or another
            # cluster's, never pushes a later one out of what is read
            cur.execute(f'SELECT run FROM ha_recovery_journal{cond} GROUP BY run '
                        'ORDER BY MAX(at) DESC, run DESC LIMIT ?', (*args, RECOVERY_KEEP + 1))
            picked = [r[0] for r in cur.fetchall()]
            if len(picked) > RECOVERY_KEEP:
                cur.execute(f'SELECT COUNT(DISTINCT run) FROM ha_recovery_journal{cond}', args)
                _say_runs_kept(cluster_id, cur.fetchone()[0])
                picked = picked[:RECOVERY_KEEP]
            rows = []
            if picked:
                cur.execute(cols + f" WHERE run IN ({', '.join('?' * len(picked))}) ORDER BY at, id", picked)
                rows = cur.fetchall()
    except Exception as e:
        logging.warning(f"[HA] could not read the recovery journal: {e}")
        return []
    runs = {}
    for rid, cid, node, epoch, iid, step, vmid, done, at in rows:
        if rid in live:
            continue
        rec = runs.setdefault(rid, {'run': rid, 'cluster_id': cid, 'node': node, 'epoch': epoch,
                                    'instance_id': iid, 'at': at, 'moved_at': None, 'open': [],
                                    'guests_open': [], 'moved': set(), 'started': set(), 'held': set()})
        if step == 'move_config' and rec['moved_at'] is None:
            rec['moved_at'] = at
        if step == 'hold' and vmid is not None:
            # begun counts as well: the leader was gone before its look at the node said
            rec['held'].add(vmid)
        elif not done:
            rec['open'].append(step if vmid is None else f'{step} {vmid}')
            if vmid is not None and vmid not in rec['guests_open']:
                rec['guests_open'].append(vmid)
        elif step == 'move_config' and vmid is not None:
            rec['moved'].add(vmid)
        elif step == 'start' and vmid is not None:
            rec['started'].add(vmid)
    out = []
    for rec in runs.values():
        held = rec.pop('held')
        rec['moved'] = sorted(rec.pop('moved') - rec.pop('started') - held)
        rec['guests_open'] = [v for v in rec['guests_open'] if v not in held]
        rec['held'] = sorted(held)
        out.append(rec)
    return out


def _say_runs_kept(cluster_id, total):
    where = f'cluster {cluster_id}' if cluster_id is not None else 'all clusters'
    if _recovery_said.get(where) == total:
        return
    _recovery_said[where] = total
    text = (f"{total} interrupted node recoveries are kept for {where}: the oldest "
            f"{total - RECOVERY_KEEP} are not listed until newer ones are started or dismissed")
    logging.warning(f"[HA] {text}")
    _audit('ha.recovery_journal_full', text)


# --- schedules across a change of leader (design 5.7) --------------------------------

_missed_said = {}


def _largest_skew():
    rt = _rts.get(_load()['instance_id'])
    now = time.monotonic()
    skews = [abs(s['skew']) for s in (list(rt.seen.values()) if rt else ())
             if type(s.get('skew')) in (int, float) and now - s.get('at', -1e9) <= LEASE_SEEN_FRESH]
    # nothing measured yet: the most automatic mode allows
    return max(skews) if skews else float(ha_vote.SKEW_LIMIT)


def _acting_wall(node):
    """acting_from of `node` as a wall time."""
    return _wall() - (ha_clock() - node.acting_from)


def schedule_held():
    """True while the minute that runs now began before this leader may fire schedules:
    before it acts, plus the largest clock skew to a member (5 s while none was
    measured), so a minute the former leader may have fired is not fired again. A leader
    that took the lead in its own process (the switch) had no former leader, and its own
    last runs are here: nothing held. False anywhere but in an automatic group."""
    st = _load()
    if not _lease_mode(st):
        return False
    node = _lease_live(st)
    if node is None or not node.is_active():
        return True
    rt = _rts.get(st['instance_id'])
    if rt is None or not rt.came_up:
        return False
    wall = _wall()
    return wall - (wall % 60) < _acting_wall(node) + _largest_skew()


def schedule_fire_first():
    """At most once (5.7): in an automatic group a schedule writes its last run before it
    acts (a one-time schedule switches itself off with it), and schedule_fired() sends
    that to the members, so a leader that takes over in between does not fire it again.
    Anywhere else the order stays as it was."""
    return guard_on()


def schedule_fired():
    """The last run of a schedule is written: in an automatic group the members get it now,
    before the schedule acts, not with the next etag tick."""
    _send_on('the last run of a schedule')


def _send_on(what):
    """In an automatic group: the cv steps for what was just written and the members hear
    of it now (cv_tick, which tells them), not with the next etag tick."""
    if not guard_on():
        return
    try:
        cv_tick()
    except Exception as e:
        logging.warning(f"[HA] could not send {what} on at once: {e}")


def missed_schedule_window(kind):
    """Once per acting process of a leader that came up by a restart (a takeover, or a
    restart of its own) and per kind of schedule: (from, to) as wall times, the stretch
    in which no leader fired schedules, from before the last renewal its process could
    have heard to the end of what schedule_held() skips. None otherwise, and anywhere
    but in an automatic group."""
    st = _load()
    if not _lease_mode(st):
        return None
    node = _lease_live(st)
    if node is None or not node.is_active():
        return None
    t = node.t
    rt = _rts.get(st['instance_id'])
    if rt is None or not rt.came_up:
        # it took the lead in this process (the switch to automatic mode): no gap
        return None
    mark = (st['instance_id'], rt.gen, node.acting_from)
    if _missed_said.get(kind) == mark:
        return None
    _missed_said[kind] = mark
    # the vote round it won, from take_after on this boot; W_take covers the restart
    # after it, so it lies no further back than that from the start of this process (a
    # take_after from long ago is a restart of a leader that kept the lease)
    take = ((st.get('lease') or {}).get('led') or {}).get('take_after') or {}
    won = node.started - t.W_take
    if take.get('boot_id') == node.boot_id and type(take.get('at')) in (int, float):
        won = min(max(take['at'] - t.W_take, won), node.started)
    # its timer fired at most P + L/4 (+ L/2 at a lower reach) after the last renewal it
    # heard, and the vote took T_vote
    heard = _wall() - (ha_clock() - won) - (t.P + t.L / 4 + t.L / 2 + t.T_vote)
    return heard, _acting_wall(node) + _largest_skew()


def missed_schedules(kind, names, window):
    """Say and audit which schedules of `kind` fell in `window` and did not run."""
    if not names:
        return
    a, b = (datetime.fromtimestamp(x).strftime('%Y-%m-%d %H:%M:%S') for x in window)
    text = (f"{len(names)} {kind} fell due between {a} and {b} while the group changed its "
            f"leader and did not run: {', '.join(sorted(names)[:20])}")
    logging.warning(f"[HA] {text}")
    _audit('ha.schedules_missed', text)
