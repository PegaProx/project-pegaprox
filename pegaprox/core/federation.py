"""The federation of PegaProx instances: up to eight sites, each leading its own clusters.

Instances pair by a one-time code. From then on they form a federation:

  * the member view: who belongs, as one agreed list {epoch, members}. Every change (a
    join, a removal, a member leaving) takes a majority lock first and moves the epoch by
    one, so two halves of a split network can neither shrink nor grow the federation on
    their own. A change carries the voters' signed grants of the lock and its committer's
    signature over the change, and counts once a majority of the old view took it; a
    member behind replays the signed changes, and a view no majority took is rolled back
    (catch_up). One change at a time per process (_one_change).
  * identities: users, API tokens and passkeys homed at one member are mirrored to the
    others, which never write them. Tenants and roles are not copied: an admin of the
    receiving member maps them onto its own, and until then a mirror cannot sign in.
  * leases: a cluster a member enrolled is written only while a majority of the view
    backs that member's lease on it, or, with two members, the owner holds it alone while
    the other one is silent (pegaprox/core/federation_lease.py). Every write leaves this
    process through an exit of core/ha_transport.py, and each exit asks guard_exit() for
    the cluster it writes to.
  * cluster mirrors and adoption: an enrolled cluster's row travels to every member with
    its credentials wrapped under the owner's federation field key (never the database
    key). When a member is gone for good another one adopts its clusters, or, with two
    members, takes them over by hand. Every change of a cluster's owner leaves a signed,
    numbered ownership record (the pegaprox_kv key federation_ownership); a site of two
    that carries on alone keeps a signed end record for the site it removed.

Where state lives. The deployment-wide identity of this instance (instance id, signing
key, federation field key, the agreed view, tombstones, the field keys of the others) is
one row of the synced table pegaprox_kv, its secrets sealed under the database key, so an
HA standby holds the same identity and a promotion moves nothing: an HA group is one
member. What belongs to this host alone (the leases it holds, the promises it gave as a
voter, the clock mark those are valid under, an open pairing code) is
config/federation_leases.json. Everything a hot path reads is cached in _runtime.

The switch. Off by default: the server setting federation_enabled, which an admin turns
on in the settings and which travels to an HA standby with the settings. The environment
variable PEGAPROX_FEDERATION forces it ('1' on, '0' off). Off, every hook outside this
module, federation_lease.py and api/federation.py asks enabled() and goes no further (one
exception, forget_inherited, below), and the routes answer 404 FED_DISABLED except the
switch and its status.

Trust model: a member's administrators are trusted administrators of the federation (its
admins are admins at every member once mapped). The protocol defends against honest
faults - partitions, restarts, reboots, failovers, stale backups, delayed messages - and
bounds what a misbehaving member can grow (promises, view size, bodies, answers, the call
budget). It does not claim to tolerate a malicious member; removal by a majority is the
remedy, and it reaches every member: no single member can change a view on its own (a
commit and a caught-up view both need a majority's signed grants and the committer's
signature over the change, so a member relaying another's commit cannot swap it, and a
caught-up view takes no member record from the relaying member's word) or hold the
members lock for longer than one change.

An HA standby that leaves its group drops the identity it held (forget_inherited): a
standalone host acting as the same member next to the active would be a second writer.
It does so with the switch off as well, the one deliberate exception to the switch: the
identity row is all it looks for, and switched on later the host would be that member
again. An active that still has standbys does not unpair while the switch is on
(ha.unpair_refusal): its standbys keep the identity, and the two would be one member
twice.

MK Nov 2026
"""
import base64
import contextlib
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import threading
import time

from pegaprox.constants import CONFIG_DIR
from pegaprox.core import ha_wire

# the wire this release speaks; a member refuses a federation call of another mark
FED_MARK = 1
# a code that pairs a federation member, never an HA standby or a witness: the three
# prefixes must not be taken for each other
CODE_PREFIX = 'pgxfd1_'
# the first line of everything a federation peer signs: its own domain, so a signature
# for the HA group ('pegaprox-ha-peer-1' in ha_wire.to_sign) is refused here
SIGN_DOMAIN = 'pegaprox-fed-peer-1'
# and of what a member signs over its answer to a signed call
ANSWER_DOMAIN = 'pegaprox-fed-answer-2'
ANSWER_HEADER = 'X-PegaProx-Fed-Answer'
# one code, fifteen minutes, one member: as the HA pairing does it
PAIRING_TTL = 15 * 60
# a federation is a handful of sites, this instance counted
MAX_SITES = 8
# what a peer call may carry: a batch of 256 lease asks fits
MAX_PEER_BODY = 64 * 1024
# what an answer of a member may weigh before it is read
MAX_ANSWER = 256 * 1024
# an identity snapshot holds rows, not a member list
MAX_SNAPSHOT_ANSWER = 16 * 1024 * 1024
SITE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
CLUSTER_ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
# the CSRF gate in app.py takes exactly this word from an /api call that carries no
# Origin, as it does an HA peer call; every federation call on the wire says it
PEER_XHR = 'XMLHttpRequest'
# the lease id that guards a change of the member view. A cluster id starts with a
# letter or a digit, so it never collides with this one
MEMBERS_LOCK = '@members'
LEASE_RENEW_AFTER = 10
SYNC_INTERVAL = 60
CONNECT_TIMEOUT = 3
VOTE_TIMEOUT = 5
# removed members whose late calls still hear 410, oldest out first
MAX_TOMBSTONES = 64
# the last view changes kept with their signed lock grants, for a member that catches up
MAX_COMMITS = 16
# cluster ids whose rows this instance dropped, with the member that led them
MAX_DROPPED = 512
# what a voter signs when it grants the members lock: its own domain, so no other
# signature of a member reads as one
LOCK_DOMAIN = 'pegaprox-fed-lock-1'
# and of what a committer signs over the whole change it made with that lock: a grant
# names the committer and the base view, never the change
COMMIT_DOMAIN = 'pegaprox-fed-commit-1'
# what a site signs over a change of a cluster's owner it made (enroll, adopt, takeover)
OWNER_DOMAIN = 'pegaprox-fed-owner-1'
# what a site signs when it carries on alone after removing the other site of a two
END_DOMAIN = 'pegaprox-fed-end-1'
OWNERSHIP_KEY = 'federation_ownership'
OWNER_FIELDS = ('cluster_id', 'gen', 'kind', 'owner', 'from', 'at', 'by')
# on an equal generation a takeover goes before an adoption, an adoption before an enroll
KIND_RANK = {'enroll': 0, 'adopt': 1, 'takeover': 2}
# ownership records kept: every cluster eight sites can lead, and history
MAX_OWNER_RECORDS = 4096
# cluster ids an end record names; its 410 answer must stay under MAX_ANSWER
MAX_END_CLUSTERS = 2048
MAX_FINGERPRINTS = 4
# the rows of one member the linked view shows
MAX_VIEW_ROWS = 100
CLUSTER_TYPES = ('proxmox', 'xcpng', 'esxi')

IDENTITY_KEY = 'federation_identity'
LEASE_FILE = os.path.join(CONFIG_DIR, 'federation_leases.json')

STATUS_PATH = '/api/federation/peer/status'
JOIN_PATH = '/api/federation/peer/join'
VIEW_PATH = '/api/federation/peer/view'
MEMBERSHIP_PATH = '/api/federation/peer/membership'
MEMBER_UPDATE_PATH = '/api/federation/peer/member-update'
FIELD_KEY_PATH = '/api/federation/peer/field-key'
LEASE_PATH = '/api/federation/peer/lease-vote'
IDENTITIES_PATH = '/api/federation/peer/identities'
CLUSTERS_PATH = '/api/federation/peer/clusters'
END_TAKEN_PATH = '/api/federation/peer/end-taken'

SWITCH_CACHE_SECONDS = 5
IDENTITY_CACHE_SECONDS = 5
CLUSTERS_BODY_SECONDS = 15
# where a refusal at a cluster exit is noted for the request, as ha.GUARD_REFUSED_ENVIRON
FED_REFUSED_ENVIRON = 'pegaprox.fed_refused'

_lock = threading.RLock()
_sessions_lock = threading.Lock()
_PROCESS_STARTED = time.time()


class FederationError(Exception):
    """What the admin reads, with the sentence for it. `code` is the machine word a route
    answers with, `blockers` what stands in the way of switching off, and `extra` any
    further field of the answer (votes, needed, clusters)."""

    def __init__(self, msg='', code=None, blockers=None, **extra):
        super().__init__(msg)
        self.code = code
        self.blockers = list(blockers or [])
        self.extra = extra


class LeaseRefused(Exception):
    """A write to an enrolled cluster refused at its exit: this instance holds no live
    lease on it. Not a subclass of ha.NoLease, the answer differs (409 FED_NO_LEASE)."""

    def __init__(self, cluster_id, action=''):
        super().__init__(f'{action or "write"} to cluster {cluster_id} refused: this '
                         'instance holds no live federation lease on it')
        self.cluster_id, self.action = cluster_id, action


def _fresh_runtime(lease_file):
    return {
        'lease_file': lease_file,
        # a call signed before this moment is refused: the nonces seen until then are gone
        'started': _PROCESS_STARTED,
        'nonces': {},
        # the stand-in the tests hand over; nothing in production sets it
        'transport': None,
        'switch': None, 'switch_held': False, 'forget_pending': None,
        'identity': None, 'signer': None, 'fkeys': {},
        'owners': None, 'leases': None, 'boot_id': None,
        'seen': {}, 'clusters_body': None, 'sessions': {}, 'url_ok': {},
        'removed_by': {}, 'view_conflict': False, 'statuses': {}, 'self_pushed': {},
        'pairing_busy': None, 'workers': None, 'dead_views': [], 'peer_views': {},
        # the ownership records, cached like the identity; when each member last gave a
        # signed sign of life (on the lease clock) and last answered (wall clock, shown);
        # the end records members answered with; the clusters an enroll is under way for
        'ownership': None, 'heard': {}, 'answered': {}, 'ended_by': {},
        'fresh_enrolls': set(),
    }


# what belongs to this process and this host. The tests swap the whole dict per side
_runtime = _fresh_runtime(LEASE_FILE)
_said = set()


def _say_once(key, msg, level=logging.WARNING):
    if key in _said:
        return
    if len(_said) > 512:
        _said.clear()
    _said.add(key)
    logging.log(level, msg)


def reset_for_tests(lease_file=None):
    """Forget every cache and stop the workers: the next call reads the identity and the
    lease file afresh. The process start stays what it was. What the exits keep of the
    clusters' commands and clients goes too (ha_transport)."""
    stop_workers()
    _runtime.clear()
    _runtime.update(_fresh_runtime(lease_file or LEASE_FILE))
    from pegaprox.core import ha_transport
    ha_transport.forget_tracked()


def _db():
    from pegaprox.core.db import get_db
    return get_db()


def _ha_standby():
    try:
        from pegaprox.core import ha
        return ha.is_standby()
    except Exception:
        return False


def _ha_active():
    try:
        from pegaprox.core import ha
        return ha.is_active()
    except Exception:
        return False


# --- the switch ----------------------------------------------------------------------
#
# MK Nov 2026 - the switch is a server setting an admin flips in the settings. It is
# read through a cache of a few seconds, so the cluster write gate, the cluster reads and
# the logins make no database query per request; a toggle clears the cache at once. A
# change the cache sees (a toggle, the setting arriving with the HA sync, an automatic
# promotion) starts or stops the workers, without a restart.
ENV_SWITCH = 'PEGAPROX_FEDERATION'
SETTING_KEY = 'federation_enabled'

FED_DISABLED_ERROR = ('The federation is switched off on this instance - an admin '
                      'switches it on in the settings, under Federation')
LEAVE_FIRST_ERROR = ('Leave the federation first: this instance still takes part in it '
                     '({reasons}). Switching off would strand what the other sites rely on')


def forced():
    """'on' or 'off' when PEGAPROX_FEDERATION says '1' or '0', None when the setting
    decides. Any other value is ignored, with one warning per process."""
    raw = os.environ.get(ENV_SWITCH)
    if raw is None or raw == '':
        return None
    if raw == '1':
        return 'on'
    if raw == '0':
        return 'off'
    _say_once(('env', raw), f'[FED] {ENV_SWITCH}={raw!r} is neither 1 nor 0 - ignored, '
                            'the federation setting decides')
    return None


def enabled():
    """True when this process runs the federation at all. Never while an identity this
    host inherited as an HA standby still waits to be dropped (forget_inherited)."""
    if _forget_pending():
        return False
    f = forced()
    if f is not None:
        return f == 'on'
    return _switch_setting()


def _forget_mark_path():
    return os.path.join(os.path.dirname(os.path.abspath(_runtime['lease_file'])),
                        'federation_forget_pending')


def _forget_pending():
    """The host-local mark of a drop of an inherited identity that did not go through,
    looked at once per SWITCH_CACHE_SECONDS. Kept in a file next to the lease file, which
    the HA sync never carries."""
    held = _runtime.get('forget_pending')
    now = time.monotonic()
    if held is not None and 0 <= now - held[1] < SWITCH_CACHE_SECONDS:
        return held[0]
    value = os.path.exists(_forget_mark_path())
    _runtime['forget_pending'] = (value, now)
    return value


def _set_forget_mark(on):
    path = _forget_mark_path()
    try:
        if on:
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('the federation identity this host inherited is still to be dropped\n')
        else:
            os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        logging.error(f'[FED] the mark of an inherited identity to drop could not be '
                      f'{"written" if on else "removed"} at {path}: {e}')
    _runtime['forget_pending'] = None


def retry_forget():
    """At the start: an inherited identity whose drop did not go through is dropped now.
    Until then the federation stays off here (enabled). Without the mark it reads nothing."""
    if not _forget_pending():
        return False
    return forget_inherited('an earlier drop of it did not go through')


def _switch_setting():
    held = _runtime.get('switch')
    now = time.monotonic()
    if held is not None and 0 <= now - held[1] < SWITCH_CACHE_SECONDS:
        return held[0]
    try:
        value = _db().get_server_setting(SETTING_KEY, False) is True
    except Exception as e:
        # a read that fails keeps what was known (off before the first good read)
        value = held[0] if held is not None else bool(_runtime.get('switch_held'))
        _say_once('switch-read', f'[FED] the federation setting could not be read, '
                                 f'it stays {"on" if value else "off"}: {e}')
        _runtime['switch'] = (value, now)
        return value
    _runtime['switch'] = (value, now)
    if value != bool(_runtime.get('switch_held')):
        _runtime['switch_held'] = value
        _switch_changed(value)
    return value


def _switch_changed(value):
    try:
        if value:
            start_workers()
        else:
            stop_workers()
        logging.info(f'[FED] the federation is switched {"on" if value else "off"}')
    except Exception as e:
        logging.warning(f'[FED] the workers did not follow the switch: {e}')


def disable_blockers():
    """What keeps this instance from switching off: a subset of 'member' (the view holds
    another member, or the others removed this instance while it still holds enrolled
    rows), 'lease' (an enrolled row of its own or a live lease) and 'mirrors' (accounts
    or clusters of other sites). Admin route only, the queries are plain."""
    out = []
    me = instance_id()
    ident = identity() or {}
    conn = _db().conn
    own_rows = bool(me) and conn.execute(
        'SELECT 1 FROM clusters WHERE fed_owner = ? LIMIT 1', (me,)).fetchone() is not None
    if members() or (ident.get('removed') and own_rows):
        out.append('member')
    lease = own_rows
    if not lease:
        from pegaprox.core import federation_lease as fl
        lease = fl.holds_any_lease()
    if lease:
        out.append('lease')
    mirrors = False
    for table in ('users', 'api_tokens', 'webauthn_credentials'):
        try:
            if conn.execute(f"SELECT 1 FROM {table} WHERE fed_home != '' LIMIT 1").fetchone():
                mirrors = True
                break
        except Exception as e:
            if 'no such table' not in str(e):
                raise
    if not mirrors:
        mirrors = conn.execute("SELECT 1 FROM clusters WHERE fed_owner NOT IN ('', ?) LIMIT 1",
                               (me,)).fetchone() is not None
    if mirrors:
        out.append('mirrors')
    return out


def untold_ends():
    """The sites this instance removed as gone for good that have not confirmed they were
    told: switched off, this instance could no longer tell them."""
    return sorted(iid for iid, rec in ((identity() or {}).get('ended') or {}).items()
                  if not rec.get('told_at'))


def switch_status():
    """{'enabled', 'forced', 'can_disable', 'disable_blockers'}: what the settings card of
    the switch reads, with 'disable_warnings' ['ended_untold'] while a site this instance
    removed as gone for good has not confirmed that it was told. Off, nothing of the
    identity is read for it."""
    on = enabled()
    f = forced()
    blockers, warnings = [], []
    if on:
        try:
            blockers = disable_blockers()
        except Exception as e:
            # a state that cannot be read cannot be shown to be free either
            logging.warning(f'[FED] could not tell what keeps the federation on: {e}')
            blockers = ['member', 'lease', 'mirrors']
        try:
            if untold_ends():
                warnings.append('ended_untold')
        except Exception as e:
            logging.warning(f'[FED] could not read the end records: {e}')
    out = {'enabled': on, 'forced': f is not None,
           'can_disable': bool(on and f is None and not blockers),
           'disable_blockers': blockers}
    if warnings:
        out['disable_warnings'] = warnings
    return out


def set_enabled(value, untold_ok=False):
    """Switch the federation on or off for the whole deployment. Raises FederationError
    FED_FORCED while the environment decides, FED_IN_USE (with blockers) for a switch off
    while this instance still takes part, FED_ENDED_UNTOLD (with sites) for a switch off
    while a site removed as gone for good has not confirmed that it was told, unless
    `untold_ok`. Returns switch_status()."""
    if not isinstance(value, bool):
        raise FederationError('Say true or false', code='FED_BAD_VALUE')
    f = forced()
    if f is not None:
        raise FederationError(f'The server sets this with {ENV_SWITCH}='
                              f'{"1" if f == "on" else "0"} - change it there',
                              code='FED_FORCED')
    if not value and enabled():
        blockers = disable_blockers()
        if blockers:
            raise FederationError(LEAVE_FIRST_ERROR.format(reasons=', '.join(blockers)),
                                  code='FED_IN_USE', blockers=blockers)
        untold = untold_ends()
        if untold and not untold_ok:
            site = (((identity() or {}).get('ended') or {}).get(untold[0]) or {}).get('site') \
                or untold[0][:8]
            raise FederationError(f'{site} has not confirmed that it was told this instance '
                                  'carried on alone. If it still runs and was never told, it '
                                  'keeps writing the clusters this instance kept. Switch off '
                                  'anyway only when it is shut down for good',
                                  code='FED_ENDED_UNTOLD', sites=untold)
    _db().save_server_setting(SETTING_KEY, value)
    _runtime['switch'] = (value, time.monotonic())
    _runtime['switch_held'] = value
    if value:
        if not _ha_standby():
            ensure_identity()
        start_workers()
    else:
        stop_workers()
    return switch_status()


# --- the disaster recovery switch ----------------------------------------------------
#
# MK Nov 2026 - enrolled clusters, leases, adoption and takeover are the federation's
# disaster recovery, a part an admin switches on apart from the rest (the linked mode:
# pairing, accounts, other sites' clusters in the own UI). Off, the default, no lease
# round runs, no cluster is enrolled, adopted or taken over, no field key is handed out
# and no ownership record is pushed. The write gate lets a cluster no federation owns
# pass at its first check and, as with the federation off, refuses a row a federation
# still owns. Read through a cache like the federation switch; PEGAPROX_FEDERATION_DR
# forces it the same way.
DR_ENV_SWITCH = 'PEGAPROX_FEDERATION_DR'
DR_SETTING_KEY = 'federation_dr_enabled'

DR_OFF_ERROR = ('Disaster recovery is switched off on this instance - an admin switches it '
                'on in the settings, under Federation')
DR_IN_USE_ERROR = ('Unenroll every cluster first: disaster recovery still holds clusters here '
                   '({reasons})')


def dr_forced():
    """'on' or 'off' when PEGAPROX_FEDERATION_DR says '1' or '0', None when the setting
    decides."""
    raw = os.environ.get(DR_ENV_SWITCH)
    if raw is None or raw == '':
        return None
    if raw in ('1', '0'):
        return 'on' if raw == '1' else 'off'
    _say_once(('dr-env', raw), f'[FED] {DR_ENV_SWITCH}={raw!r} is neither 1 nor 0 - ignored, '
                               'the disaster recovery setting decides')
    return None


def dr_enabled():
    """True while the federation runs and its disaster recovery is switched on."""
    if not enabled():
        return False
    f = dr_forced()
    if f is not None:
        return f == 'on'
    held = _runtime.get('dr')
    now = time.monotonic()
    if held is not None and 0 <= now - held[1] < SWITCH_CACHE_SECONDS:
        return held[0]
    try:
        value = _db().get_server_setting(DR_SETTING_KEY, False) is True
    except Exception as e:
        value = held[0] if held is not None else False
        _say_once('dr-read', f'[FED] the disaster recovery setting could not be read, it '
                             f'stays {"on" if value else "off"}: {e}')
    _runtime['dr'] = (value, now)
    return value


def dr_blockers():
    """What keeps disaster recovery from switching off: 'enrolled' (a cluster row a
    federation owns, enrolled here or another site's copy) and 'lease' (a lease this
    instance holds or a promise it gave as a voter)."""
    from pegaprox.core import federation_lease as fl
    out = []
    if _db().conn.execute("SELECT 1 FROM clusters WHERE fed_owner != '' LIMIT 1").fetchone():
        out.append('enrolled')
    if fl.holds_any_lease() or fl.backed_candidates():
        out.append('lease')
    return out


def dr_status():
    """{'enabled', 'forced', 'can_disable', 'disable_blockers'} of disaster recovery."""
    on = dr_enabled()
    blockers = []
    if on:
        try:
            blockers = dr_blockers()
        except Exception as e:
            logging.warning(f'[FED] could not tell what keeps disaster recovery on: {e}')
            blockers = ['enrolled', 'lease']
    return {'enabled': on, 'forced': dr_forced() is not None,
            'can_disable': bool(on and dr_forced() is None and not blockers),
            'disable_blockers': blockers}


def set_dr_enabled(value):
    """Switch disaster recovery on or off for the deployment. FED_DISABLED while the
    federation is off, FED_FORCED while PEGAPROX_FEDERATION_DR decides, FED_DR_IN_USE
    (with blockers) for a switch off while a cluster is still enrolled or a lease or
    promise is held. Returns dr_status()."""
    if not isinstance(value, bool):
        raise FederationError('Say true or false', code='FED_BAD_VALUE')
    if not enabled():
        raise FederationError(FED_DISABLED_ERROR, code='FED_DISABLED')
    f = dr_forced()
    if f is not None:
        raise FederationError(f'The server sets this with {DR_ENV_SWITCH}='
                              f'{"1" if f == "on" else "0"} - change it there',
                              code='FED_FORCED')
    if not value and dr_enabled():
        blockers = dr_blockers()
        if blockers:
            raise FederationError(DR_IN_USE_ERROR.format(reasons=', '.join(blockers)),
                                  code='FED_DR_IN_USE', blockers=blockers)
    was_on = dr_enabled()
    _db().save_server_setting(DR_SETTING_KEY, value)
    _runtime['dr'] = (value, time.monotonic())
    if value and not was_on:
        # the snapshots pulled while it was off left the cluster copies and the ownership
        # records out: the etags go, so the next sync takes every snapshot whole
        try:
            conn = _db().conn
            conn.execute('DELETE FROM federation_sync_state')
            conn.commit()
        except Exception as e:
            logging.warning(f'[FED] the next sync may skip the cluster copies: {e}')
    return dr_status()


def sites_without_dr():
    """The sites of the view that do not say, right now, that their disaster recovery is
    on: a cluster is enrolled only while every site holds it on, so none of them refuses
    the lease votes and copies it is asked for."""
    def ask(item):
        iid, rec = item
        status, body, _h = call_peer(iid, 'GET', STATUS_PATH, read_timeout=5)
        ok = status == 200 and isinstance(body, dict) and body.get('dr') is True
        return None if ok else (rec.get('site') or iid[:8])
    return sorted(s for s in _parallel(ask, sorted(members().items())) if s)


# --- the identity: one row of the synced table pegaprox_kv ----------------------------

def _blank_identity():
    return {'v': 1, 'instance_id': '', 'self': {'url': '', 'site': '', 'fingerprints': []},
            'signing_key': '', 'field_key': '', 'field_key_id': '',
            'view': {'epoch': 0, 'members': {}}, 'tombstones': {}, 'peer_keys': {},
            'removed': None, 'dropped': {}, 'commits': [], 'view_prev': None,
            'handed_over': {}, 'adopted': {}, 'drop_pending': {}, 'ended': {}}


def _normalized(raw):
    ident = _blank_identity()
    if not isinstance(raw, dict):
        return ident
    for key in ('instance_id', 'signing_key', 'field_key', 'field_key_id'):
        if isinstance(raw.get(key), str):
            ident[key] = raw[key]
    if isinstance(raw.get('self'), dict):
        s = raw['self']
        ident['self'] = {'url': s.get('url') if isinstance(s.get('url'), str) else '',
                         'site': s.get('site') if isinstance(s.get('site'), str) else '',
                         'fingerprints': _clean_fps(s.get('fingerprints'))}
    view = raw.get('view') if isinstance(raw.get('view'), dict) else {}
    epoch = view.get('epoch')
    ident['view'] = {'epoch': epoch if isinstance(epoch, int) and not isinstance(epoch, bool)
                     and epoch >= 0 else 0,
                     'members': {k: v for k, v in (view.get('members') or {}).items()
                                 if isinstance(v, dict) and ha_wire.ID_RE.fullmatch(k or '')}
                     if isinstance(view.get('members'), dict) else {}}
    for key in ('tombstones', 'peer_keys', 'dropped', 'handed_over', 'adopted',
                'drop_pending', 'ended'):
        if isinstance(raw.get(key), dict):
            ident[key] = {k: v for k, v in raw[key].items() if isinstance(v, dict)}
    if isinstance(raw.get('removed'), dict):
        ident['removed'] = raw['removed']
    if isinstance(raw.get('commits'), list):
        ident['commits'] = [c for c in raw['commits'] if isinstance(c, dict)][-MAX_COMMITS:]
    prev = raw.get('view_prev')
    if (isinstance(prev, dict) and isinstance(prev.get('members'), dict)
            and isinstance(prev.get('epoch'), int) and not isinstance(prev.get('epoch'), bool)):
        ident['view_prev'] = {'epoch': prev['epoch'],
                              'members': {k: v for k, v in prev['members'].items()
                                          if isinstance(v, dict)
                                          and ha_wire.ID_RE.fullmatch(k or '')}}
    return ident


def _read_identity_row(conn):
    try:
        row = conn.execute('SELECT v FROM pegaprox_kv WHERE k = ?', (IDENTITY_KEY,)).fetchone()
    except Exception as e:
        if 'no such table' in str(e):
            return None
        raise FederationError(f'The federation identity cannot be read: {e}')
    if row is None:
        return None
    try:
        return _normalized(json.loads(row[0]))
    except Exception as e:
        raise FederationError(f'The federation identity in the database is unreadable - '
                              f'restore the database, or leave the federation and pair '
                              f'again: {e}')


def identity():
    """The federation identity of this deployment as a dict, None before the first pairing
    or switch-on made one. Cached for a few seconds; every local write drops the cache.
    Callers do not change what they get - _mutate_identity is the way to write."""
    held = _runtime.get('identity')
    now = time.monotonic()
    if held is not None and 0 <= now - held[1] < IDENTITY_CACHE_SECONDS:
        return held[0]
    ident = _read_identity_row(_db().conn)
    _runtime['identity'] = (ident, now)
    return ident


def _begin(conn):
    try:
        conn.execute('BEGIN IMMEDIATE')
    except Exception:
        # a transaction of this connection is open already; the statements join it
        pass


def _mutate_identity(fn):
    """`fn(identity)` in one transaction under the lock; written when it returned True.
    Returns the identity as it is afterwards."""
    with _lock:
        conn = _db().conn
        conn.execute('CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)')
        _begin(conn)
        try:
            ident = _read_identity_row(conn) or _blank_identity()
            if fn(ident) is True:
                conn.execute('INSERT OR REPLACE INTO pegaprox_kv (k, v) VALUES (?, ?)',
                             (IDENTITY_KEY, json.dumps(ident, sort_keys=True,
                                                       separators=(',', ':'))))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            _runtime['identity'] = None
        return ident


def instance_id(create=False):
    """This deployment's id in the federation, '' while there is none. A read never makes
    one; create=True does (ensure_identity)."""
    ident = identity()
    iid = (ident or {}).get('instance_id') or ''
    if iid or not create:
        return iid
    return ensure_identity()


def ensure_identity():
    """Make the instance id, the signing key and the federation field key once. An HA
    standby never makes them (it receives them with the sync): there it answers what it
    holds, '' when that is nothing."""
    if _ha_standby():
        return instance_id()
    db = _db()

    def go(ident):
        changed = False
        if not ident.get('instance_id'):
            ident['instance_id'] = secrets.token_hex(16)
            changed = True
        if not ident.get('signing_key'):
            ident['signing_key'] = db._encrypt(ha_wire.new_signing_key())
            changed = True
        if not ident.get('field_key'):
            raw = os.urandom(32)
            ident['field_key'] = db._encrypt(base64.b64encode(raw).decode())
            ident['field_key_id'] = hashlib.sha256(raw).hexdigest()[:8]
            changed = True
        return changed
    return _mutate_identity(go)['instance_id']


def _clean_fps(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out = []
    for fp in value:
        if isinstance(fp, str) and ha_wire.FP_RE.fullmatch(fp.strip().upper()):
            fp = fp.strip().upper()
            if fp not in out:
                out.append(fp)
    return out[:MAX_FINGERPRINTS]


def _clean_site(site):
    if not isinstance(site, str):
        return ''
    site = site.strip()
    return site if SITE_RE.fullmatch(site) else ''


def _member_record(iid, rec):
    """A member record as this code keeps it, or None: a 32-hex id, an https address and
    a usable Ed25519 key at the least. What walks in from a peer is checked here."""
    if not isinstance(rec, dict) or not ha_wire.ID_RE.fullmatch(iid or ''):
        return None
    url = ha_wire.valid_https_url(rec.get('url') if isinstance(rec.get('url'), str) else '')
    key = rec.get('public_key') if isinstance(rec.get('public_key'), str) else ''
    if not url or ha_wire.public_key(key) is None:
        return None
    fps = _clean_fps(rec.get('fingerprints') if 'fingerprints' in rec else rec.get('fingerprint'))
    out = {'url': url, 'public_key': key, 'site': _clean_site(rec.get('site')),
           'fingerprints': fps}
    for field in ('added_at',):
        v = rec.get(field)
        out[field] = v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0
    by = rec.get('added_by')
    out['added_by'] = by[:80] if isinstance(by, str) else ''
    return out


def members():
    """{instance_id: record} of the other members of the agreed view."""
    view = ((identity() or {}).get('view') or {}).get('members') or {}
    return {iid: dict(rec, instance_id=iid) for iid, rec in view.items()}


def member_record(iid):
    rec = (((identity() or {}).get('view') or {}).get('members') or {}).get(iid)
    return dict(rec, instance_id=iid) if rec else None


def tombstones():
    return dict((identity() or {}).get('tombstones') or {})


def view_has_members():
    """True while the identity row lists another member, whatever the switch says (an HA
    group asks before it splits). A row that cannot be read counts as one with members."""
    try:
        return bool(members())
    except Exception:
        return True


def view_epoch():
    return int(((identity() or {}).get('view') or {}).get('epoch') or 0)


def view_ids():
    """Every id of the view, this instance included, sorted."""
    me = instance_id()
    ids = set(members())
    if me:
        ids.add(me)
    return sorted(ids)


def needed(count):
    """The majority of `count` voters."""
    return count // 2 + 1


def dropped_records():
    """{cluster id: member} of the rows this instance dropped and who led them."""
    return {cid: rec.get('owner') for cid, rec in
            ((identity() or {}).get('dropped') or {}).items()
            if isinstance(rec.get('owner'), str) and rec.get('owner')}


def _age(rec, key):
    """How old a kept record is, for the bounds: its time, then the order it was noted
    in. The identity row is stored with sorted keys, so the order of a dict read back
    says nothing about age."""
    at, n = rec.get(key), rec.get('n')
    return (at if isinstance(at, (int, float)) and not isinstance(at, bool) else 0,
            n if isinstance(n, int) and not isinstance(n, bool) else 0)


def _next_n(held):
    return 1 + max((r['n'] for r in held.values()
                    if isinstance(r.get('n'), int) and not isinstance(r.get('n'), bool)),
                   default=0)


def note_dropped(rows):
    """Remember cluster rows this instance dropped, [(cluster id, the member that led
    it)], bounded. Past MAX_DROPPED the oldest record of the member named most often
    goes: a member that piles up records loses its own first, and nobody's records are
    pushed below an even share. Never inside another transaction of the connection: this
    commits."""
    rows = [(cid, owner) for cid, owner in rows if cid and owner]
    if not rows:
        return
    from collections import Counter

    def go(ident):
        held = ident.setdefault('dropped', {})
        n, now = _next_n(held), int(time.time())
        for cid, owner in rows:
            held[cid] = {'owner': owner, 'at': now, 'n': n}
            n += 1
        while len(held) > MAX_DROPPED:
            per = Counter(r.get('owner') for r in held.values())
            top = max(per.values())
            held.pop(min((k for k, r in held.items() if per[r.get('owner')] == top),
                         key=lambda k: _age(held[k], 'at')))
        return True
    try:
        _mutate_identity(go)
    except Exception as e:
        logging.warning(f'[FED] could not note {len(rows)} dropped cluster row(s): {e}')


def handed_over_ids():
    """The clusters led here that an admin handed over (released). Kept in the identity
    row, so a promoted standby, or a host whose lease file was removed, still knows."""
    return set(((identity() or {}).get('handed_over') or {}))


def adopted_from():
    """{cluster id: the member it was adopted from} of the clusters this instance adopted
    while the voters' rows may still name the old owner: its asks for them carry the
    adoption flag, from whichever host of its HA group asks."""
    return {cid: rec.get('from') or '' for cid, rec in
            ((identity() or {}).get('adopted') or {}).items()}


def _mark_clusters(key, add=None, drop=()):
    """Add ids to, or drop them from, one of the per-cluster marks of the identity row
    ('handed_over', 'adopted'). `add` is {cluster id: extra fields}. Bounded like the
    dropped records. Never inside another transaction of the connection: this commits."""
    add = {c: dict(v or {}) for c, v in (add or {}).items() if c}
    drop = set(c for c in drop if c)
    if not add and not drop:
        return

    def go(ident):
        held = ident.setdefault(key, {})
        changed = False
        for cid in drop:
            changed = held.pop(cid, None) is not None or changed
        n, now = _next_n(held), int(time.time())
        for cid, extra in add.items():
            rec = dict(extra, at=now, n=n)
            if {k: v for k, v in (held.get(cid) or {}).items() if k not in ('at', 'n')} \
                    != extra or cid not in held:
                held[cid] = rec
                n += 1
                changed = True
        while len(held) > MAX_DROPPED:
            held.pop(min(held, key=lambda k: _age(held[k], 'at')))
        return changed
    _mutate_identity(go)


# --- ownership records -------------------------------------------------------------------
#
# MK Nov 2026 - every change of a cluster's owner (an enroll, an adoption, a takeover by
# hand) leaves a record the new owner signs, with a generation that grows per cluster. The
# records are kept in a row of their own in pegaprox_kv (the HA sync carries it, and an
# identity write does not parse them), made and exchanged in every view size and acted on
# in a view of two only, where one of two is no majority: there they fence a takeover and
# settle which site leads a cluster both rows claim (federation_lease.take_records).

def _blank_ownership():
    # seq only grows: a record stored later always gets a number past every echo
    return {'v': 1, 'seq': 0, 'records': {}, 'acked': {}, 'ok': {}}


def _normalized_ownership(raw):
    own = _blank_ownership()
    if not isinstance(raw, dict):
        return own
    seq = raw.get('seq')
    if isinstance(seq, int) and not isinstance(seq, bool) and seq > 0:
        own['seq'] = seq
    for key in ('records', 'ok'):
        if isinstance(raw.get(key), dict):
            own[key] = {k: v for k, v in raw[key].items() if isinstance(v, dict)}
    if isinstance(raw.get('acked'), dict):
        own['acked'] = {k: v for k, v in raw['acked'].items()
                        if isinstance(v, int) and not isinstance(v, bool)}
    return own


def _read_ownership_row(conn):
    try:
        row = conn.execute('SELECT v FROM pegaprox_kv WHERE k = ?',
                           (OWNERSHIP_KEY,)).fetchone()
    except Exception as e:
        if 'no such table' in str(e):
            return _blank_ownership()
        raise FederationError(f'The ownership records cannot be read: {e}')
    if row is None:
        return _blank_ownership()
    try:
        return _normalized_ownership(json.loads(row[0]))
    except Exception as e:
        raise FederationError(f'The ownership records in the database are unreadable: {e}')


def ownership():
    """{'seq', 'records', 'acked', 'ok'}: the newest ownership record this instance holds
    per cluster id, the highest record number each member echoed, and the clusters the
    other member of a view of two granted this instance (federation_lease). Cached like the
    identity; callers do not change what they get."""
    held = _runtime.get('ownership')
    now = time.monotonic()
    if held is not None and 0 <= now - held[1] < IDENTITY_CACHE_SECONDS:
        return held[0]
    own = _read_ownership_row(_db().conn)
    _runtime['ownership'] = (own, now)
    return own


def _ownership_in_tx(conn, fn):
    """`fn(ownership)` inside the caller's open transaction, under the caller's _lock;
    written when it returned True. The caller commits and drops the cache after that."""
    own = _read_ownership_row(conn)
    if fn(own) is True:
        conn.execute('INSERT OR REPLACE INTO pegaprox_kv (k, v) VALUES (?, ?)',
                     (OWNERSHIP_KEY, json.dumps(own, sort_keys=True, separators=(',', ':'))))
    _runtime['ownership'] = None
    return own


def _mutate_ownership(fn):
    """`fn(ownership)` in one transaction under the lock; written when it returned True."""
    with _lock:
        conn = _db().conn
        conn.execute('CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)')
        _begin(conn)
        try:
            own = _ownership_in_tx(conn, fn)
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            _runtime['ownership'] = None
        return own


def _reset_ownership():
    """A new federation, or none: the records, the echoes and the grants start afresh."""
    def go(own):
        if own == _blank_ownership():
            return False
        own.clear()
        own.update(_blank_ownership())
        return True
    _mutate_ownership(go)


def _owner_message(rec):
    body = {k: rec[k] for k in OWNER_FIELDS}
    return '\n'.join((OWNER_DOMAIN, json.dumps(body, sort_keys=True,
                                               separators=(',', ':')))).encode()


def sign_owner_record(cluster_id, gen, kind, from_, by):
    """This instance's signed word that it leads `cluster_id` from now on."""
    rec = {'cluster_id': cluster_id, 'gen': int(gen), 'kind': kind, 'owner': instance_id(),
           'from': from_ or '', 'at': int(time.time()), 'by': str(by or '')[:80]}
    rec['sig'] = base64.b64encode(signing_key().sign(_owner_message(rec))).decode()
    return rec


def wire_record(rec):
    """A record as it travels: the signed fields and the signature, nothing kept locally."""
    return {k: rec.get(k) for k in OWNER_FIELDS + ('sig',)}


def valid_owner_record(raw, entries=None):
    """The clean wire form of a record, or None: well formed and signed by a member of the
    view (this instance included) under the key the view holds for it. A record of a signer
    outside the view is nobody's word."""
    if not isinstance(raw, dict):
        return None
    cid, gen, kind, owner = (raw.get(k) for k in ('cluster_id', 'gen', 'kind', 'owner'))
    frm, at, by, sig = (raw.get(k) for k in ('from', 'at', 'by', 'sig'))
    if not (isinstance(cid, str) and CLUSTER_ID_RE.fullmatch(cid)):
        return None
    if isinstance(gen, bool) or not isinstance(gen, int) or not 1 <= gen <= 2 ** 53:
        return None
    if not isinstance(kind, str) or kind not in KIND_RANK:
        return None
    if not (isinstance(owner, str) and ha_wire.ID_RE.fullmatch(owner)):
        return None
    if not ((frm == '' and kind == 'enroll') or (
            isinstance(frm, str) and ha_wire.ID_RE.fullmatch(frm) and frm != owner)):
        return None
    if isinstance(at, bool) or not isinstance(at, int) or not 0 < at < 1e11:
        return None
    if not isinstance(by, str) or len(by) > 80 or not isinstance(sig, str) or len(sig) > 200:
        return None
    if entries is None:
        entries = _view_entries(identity() or {})
    key = ha_wire.public_key(entries.get(owner))
    if key is None:
        return None
    rec = {'cluster_id': cid, 'gen': gen, 'kind': kind, 'owner': owner, 'from': frm,
           'at': at, 'by': by, 'sig': sig}
    try:
        key.verify(base64.b64decode(sig, validate=True), _owner_message(rec))
    except Exception:
        return None
    return rec


def _record_order(rec):
    gen, at = rec.get('gen'), rec.get('at')
    return (gen if isinstance(gen, int) else 0, KIND_RANK.get(rec.get('kind'), -1),
            at if isinstance(at, int) else 0, str(rec.get('owner') or ''))


def record_beats(new, old):
    """Whether record `new` comes after `old` (anything comes after None): by generation,
    then a takeover before an adoption before an enroll, then by time, then by owner. A
    total order, the same at every site."""
    return old is None or _record_order(new) > _record_order(old)


def known_gen(cluster_id, own=None):
    """The generation of the record held for `cluster_id`, 0 for none."""
    rec = ((own if own is not None else ownership()).get('records') or {}).get(cluster_id)
    gen = (rec or {}).get('gen')
    return gen if isinstance(gen, int) and not isinstance(gen, bool) else 0


def store_record(own, rec, conn=None, **local):
    """Keep `rec` in `own` as the record of its cluster, under the next number, with its
    local fields (stopped_at, confirmed_at) fresh unless given. Bounded."""
    own['seq'] = int(own.get('seq') or 0) + 1
    kept = dict(wire_record(rec), n=own['seq'], stopped_at=0, confirmed_at=0)
    kept.update(local)
    own['records'][rec['cluster_id']] = kept
    if len(own['records']) > MAX_OWNER_RECORDS:
        _bound_records(own, conn if conn is not None else _db().conn)


def _bound_records(own, conn):
    """Past MAX_OWNER_RECORDS the oldest go: those of ids with no row here first, then
    those of rows this instance does not lead. A record of a row led here never goes."""
    records = own['records']
    rows = {r['id']: r['fed_owner'] or '' for r in conn.execute(
        'SELECT id, fed_owner FROM clusters').fetchall()}
    me = instance_id()
    dead = sorted((cid in rows, int(r.get('n') or 0), cid) for cid, r in records.items()
                  if rows.get(cid) != me)
    for _row, _n, cid in dead[:len(records) - MAX_OWNER_RECORDS]:
        del records[cid]


def _lock_message(voter, candidate, digest, epoch):
    return '\n'.join((LOCK_DOMAIN, voter, candidate, digest, str(epoch))).encode()


def lock_cert(candidate, digest, epoch):
    """This voter's signed grant of the members lock to `candidate` at view (digest,
    epoch). A commit carries a majority of them, so a member that did not vote itself can
    tell a change the federation backed from one a single member made up."""
    sig = signing_key().sign(_lock_message(instance_id(), candidate, digest, epoch))
    return base64.b64encode(sig).decode()


def _certified(certs, candidate, digest, epoch, entries):
    """How many distinct members of `entries` ({id: public key}) signed the members lock
    for `candidate` at view (digest, epoch) in `certs`."""
    if not isinstance(certs, dict):
        return 0
    n = 0
    for voter, sig in list(certs.items())[:2 * MAX_SITES]:
        key = ha_wire.public_key(entries.get(voter)) if isinstance(voter, str) else None
        if key is None or not isinstance(sig, str) or len(sig) > 200:
            continue
        try:
            key.verify(base64.b64decode(sig, validate=True),
                       _lock_message(voter, candidate, digest, epoch))
        except Exception:
            continue
        n += 1
    return n


def _commit_message(by, epoch, base, digest, wire):
    return '\n'.join((COMMIT_DOMAIN, by, str(epoch), base, digest,
                      json.dumps(wire, sort_keys=True, separators=(',', ':')))).encode()


def _sign_commit(epoch, base, digest, wire):
    """This instance's signature over a view change it commits."""
    msg = _commit_message(instance_id(), epoch, base, digest, wire)
    return base64.b64encode(signing_key().sign(msg)).decode()


def _commit_signed(c, entries):
    """Whether commit `c` carries the signature of its committer (c['by']) over epoch,
    base, digest and the change, under the key `entries` ({id: public key}, the view the
    commit starts from) holds for it. The lock grants say who held the lock at that view;
    this says what that member changed with it, so a member that hands on another
    member's commit cannot swap the change and keep the grants."""
    by, sig = c.get('by'), c.get('sig')
    key = ha_wire.public_key(entries.get(by)) if isinstance(by, str) else None
    if key is None or not isinstance(sig, str) or len(sig) > 200:
        return False
    try:
        key.verify(base64.b64decode(sig, validate=True),
                   _commit_message(by, c['epoch'], c['base'], c['digest'], c['change']))
    except Exception:
        return False
    return True


def _public_of_ct(ct):
    held = _runtime.get('signer')
    if held is not None and held[0] == ct:
        return held[2]
    key = _open_signing_key(ct)
    pub = ha_wire.public_of(key)
    _runtime['signer'] = (ct, key, pub)
    return pub


def _open_signing_key(ct):
    if not ct:
        raise FederationError('This instance has no federation identity yet - switch the '
                              'federation on first', code='FED_NO_IDENTITY')
    try:
        return ha_wire.private_key(_db()._decrypt(ct))
    except Exception as e:
        raise FederationError(f'The federation signing key cannot be opened - restore the '
                              f'database key, or leave the federation and pair again: {e}')


def signing_key():
    """This instance's Ed25519 private key, opened once per ciphertext."""
    ct = (identity() or {}).get('signing_key') or ''
    held = _runtime.get('signer')
    if held is not None and held[0] == ct and ct:
        return held[1]
    _public_of_ct(ct)
    return _runtime['signer'][1]


def public_key():
    """This instance's Ed25519 public key, base64 of the raw 32 bytes."""
    return _public_of_ct((identity() or {}).get('signing_key') or '')


def _view_entries(ident):
    """{instance id: public key} of every id of the view in `ident`, its own included."""
    entries = {iid: rec.get('public_key') or ''
               for iid, rec in ((ident.get('view') or {}).get('members') or {}).items()}
    if ident.get('instance_id') and ident.get('signing_key'):
        entries[ident['instance_id']] = _public_of_ct(ident['signing_key'])
    return entries


def _digest(entries):
    lines = '\n'.join(f'{iid} {entries[iid]}' for iid in sorted(entries))
    return hashlib.sha256(lines.encode()).hexdigest()[:32]


def view_digest():
    """The digest of the agreed view: the ids and keys of every member, this instance
    included. A voter counts a candidate's ask only when both hold the same."""
    ident = identity()
    if not ident or not ident.get('instance_id'):
        return ''
    return _digest(_view_entries(ident))


def own_site():
    return ((identity() or {}).get('self') or {}).get('site') or ''


def own_url():
    return ((identity() or {}).get('self') or {}).get('url') or ''


def set_own_site(site):
    """The label of this instance in the federation. An empty or unusable label never
    wipes what is set."""
    site = _clean_site(site)
    if not site:
        return own_site()

    def go(ident):
        if ident['self'].get('site') == site:
            return False
        ident['self']['site'] = site
        return True
    _mutate_identity(go)
    return site


def _set_self(url=None, fingerprints=None):
    def go(ident):
        changed = False
        if url and ident['self'].get('url') != url:
            ident['self']['url'] = url
            changed = True
        if fingerprints is not None and ident['self'].get('fingerprints') != fingerprints:
            ident['self']['fingerprints'] = fingerprints
            changed = True
        return changed
    _mutate_identity(go)


def _started():
    return _runtime['started']


# --- the lease file: what belongs to this host alone ----------------------------------

def _blank_leases():
    return {'v': 1, 'clock': {}, 'hold_until': 0.0, 'view_changed': 0.0, 'round_mark': 0.0,
            'my_leases': {}, 'promises': {}, 'pairing': None, 'pairing_spent': None,
            'epoch_kept': None}


def _load_lease_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as e:
        raise FederationError(f'The federation lease file cannot be read - remove '
                              f'config/federation_leases.json; this instance then holds '
                              f'its votes for one lease span: {e}')
    st = _blank_leases()
    if isinstance(raw, dict):
        for key in st:
            if key in raw and isinstance(raw[key], type(st[key]) if st[key] is not None else object):
                st[key] = raw[key]
        for key in ('hold_until', 'view_changed', 'round_mark'):
            if isinstance(raw.get(key), (int, float)) and not isinstance(raw.get(key), bool):
                st[key] = float(raw[key])
    for key in ('my_leases', 'promises'):
        st[key] = {k: v for k, v in (st.get(key) or {}).items() if isinstance(v, dict)}
    return st


def _lease_state():
    """The host-local lease state, loaded once per process and kept in memory; the clock
    check runs on the load. A lease this instance held on its own vote (a view of two with
    the other site silent) does not survive the restart: the other site may have taken the
    cluster over meanwhile, and the next round, which asks it, says so before any write."""
    with _lock:
        st = _runtime.get('leases')
        if st is not None:
            return st
        loaded = _load_lease_file(_runtime['lease_file'])
        missing = loaded is None
        st = loaded or _blank_leases()
        closed = False
        for rec in st['my_leases'].values():
            if rec.get('alone') and rec.get('expires'):
                rec['expires'] = 0
                closed = True
        _runtime['leases'] = st
        from pegaprox.core import federation_lease as fl
        if fl.check_clock(st, missing=missing) or closed:
            _save_leases(st)
        return st


def _save_leases(st):
    path = _runtime['lease_file']
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    tmp = f'{path}.tmp.{os.getpid()}.{threading.get_ident()}'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(st, fh, separators=(',', ':'), sort_keys=True)
            fh.write('\n')
            # a promise is on disk before the vote that gave it leaves
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)


def _mutate_leases(fn):
    """`fn(state)` under the lock; saved when it returned True. Returns the state."""
    with _lock:
        st = _lease_state()
        if fn(st) is True:
            _save_leases(st)
        return st


# --- a signed federation peer call -----------------------------------------------------

def _to_sign(method, path, body, ts, nonce, receiver, sender, digest=None):
    return '\n'.join((SIGN_DOMAIN, method.upper(), path,
                      digest if digest is not None else ha_wire.body_digest(body),
                      ts, nonce, receiver, sender)).encode()


def signed_headers(receiver, method, path, body=None, now=None):
    """The peer headers of one federation call we make to `receiver` (its instance id),
    signed with our key over this federation's own domain."""
    body = ha_wire.wire_body(body) if body is not None else b''
    now = time.time() if now is None else now
    sender = instance_id()
    ts, digest = str(int(now)), ha_wire.body_digest(body)
    nonce = secrets.token_urlsafe(18)
    sig = signing_key().sign(_to_sign(method, path, body, ts, nonce, receiver, sender, digest))
    return {ha_wire.PEER_HEADER: sender, ha_wire.PEER_TS_HEADER: ts,
            ha_wire.PEER_NONCE_HEADER: nonce,
            ha_wire.PEER_SIG_HEADER: base64.b64encode(sig).decode(),
            ha_wire.PEER_BODY_HEADER: digest,
            'Content-Type': 'application/json',
            'X-Requested-With': PEER_XHR}


def signature_verdict(headers, method, path, body, sender, public_b64, receiver, now,
                      started):
    """What the signature headers of one federation call say, before any nonce is spent:
    'ok', '' for no good signature at all, 'window' for a good one from outside
    ha_wire.SIGNATURE_WINDOW, 'early' for one signed before this process started."""
    ts, nonce, sig = (headers.get(ha_wire.PEER_TS_HEADER),
                      headers.get(ha_wire.PEER_NONCE_HEADER),
                      headers.get(ha_wire.PEER_SIG_HEADER))
    if not all(isinstance(v, str) for v in (ts, nonce, sig)):
        return ''
    if not (ha_wire.TS_RE.fullmatch(ts) and ha_wire.NONCE_RE.fullmatch(nonce)
            and ha_wire.SIGNATURE_RE.fullmatch(sig)):
        return ''
    key = ha_wire.public_key(public_b64)
    if key is None:
        return ''
    from cryptography.exceptions import InvalidSignature
    try:
        key.verify(base64.b64decode(sig),
                   _to_sign(method, path, body, ts, nonce, receiver, sender))
    except (InvalidSignature, ValueError):
        return ''
    if abs(now - int(ts)) > ha_wire.SIGNATURE_WINDOW:
        return 'window'
    if int(ts) < started:
        return 'early'
    return 'ok'


def clock_refusal(verdict, now, started, ts):
    """The 403 body for a good signature whose time is not, in this federation's name."""
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        ts = 0
    if verdict == 'early':
        return {'code': 'FED_CLOCK', 'clock': 'early',
                'error': f'The receiving instance started {max(0, int(now - started))} s '
                         f'ago, and the call was signed before that by the clock of the '
                         f'sender, which is {max(0, int(now) - ts)} s behind it (or the '
                         'call is an old one). Set both clocks by NTP'}
    return {'code': 'FED_CLOCK', 'clock': 'window',
            'error': f'The clocks of the two instances are more than '
                     f'{ha_wire.SIGNATURE_WINDOW} seconds apart - set both by NTP'}


def _heard_now():
    """When a member was heard: on the lease clock, which no wall clock step moves."""
    from pegaprox.core import federation_lease as fl
    return fl._lease_now()


def peer_verdict(headers, method, path, body):
    """Who sent a federation peer call: ('member', record), ('removed', tombstone),
    ('ended', end entry), ('skewed', record) or (None, None). The nonce is spent under the
    lock, on the 'ok' verdict alone, once: a replayed call is nobody's, however good its
    signature. 'ended' is the other site of a federation of two that this instance removed
    as gone for good, whatever became of the tombstones since (a new pairing replaces
    them), until that site is paired again."""
    raw = headers.get(ha_wire.PEER_HEADER) if headers is not None else None
    if not isinstance(raw, str) or not raw:
        return None, None
    claimed = raw.partition(':')[0]
    if not ha_wire.ID_RE.fullmatch(claimed):
        return None, None
    ident = identity()
    if not ident or not ident.get('instance_id'):
        return None, None
    me = ident['instance_id']
    now = time.time()
    rec = (ident['view'].get('members') or {}).get(claimed)
    if rec is not None and isinstance(rec.get('public_key'), str):
        check = signature_verdict(headers, method, path, body, claimed,
                                  rec['public_key'], me, now, _started())
        if check == 'ok':
            with _lock:
                nonces = _runtime['nonces'].setdefault(claimed, {})
                if ha_wire.take_nonce(nonces, headers.get(ha_wire.PEER_NONCE_HEADER),
                                      int(headers.get(ha_wire.PEER_TS_HEADER) or 0),
                                      now) != 'ok':
                    return None, None
            # seen in memory only: a write per call would churn the HA change journal
            _runtime['seen'][claimed] = int(now)
            _runtime.setdefault('heard', {})[claimed] = _heard_now()
            return 'member', dict(rec, instance_id=claimed)
        if check in ('window', 'early'):
            return 'skewed', dict(rec, instance_id=claimed, skew=check)
        return None, None
    tomb = (ident.get('tombstones') or {}).get(claimed)
    if tomb is not None and isinstance(tomb.get('public_key'), str):
        check = signature_verdict(headers, method, path, body, claimed,
                                  tomb['public_key'], me, now, _started())
        if check in ('ok', 'window', 'early'):
            return 'removed', dict(tomb, instance_id=claimed)
    ended = (ident.get('ended') or {}).get(claimed)
    if ended is not None and isinstance(ended.get('public_key'), str):
        check = signature_verdict(headers, method, path, body, claimed,
                                  ended['public_key'], me, now, _started())
        if check in ('ok', 'window', 'early'):
            return 'ended', dict(ended, instance_id=claimed)
    return None, None


def _answer_message(method, path, nonce, status, raw, responder, requester):
    return '\n'.join((ANSWER_DOMAIN, method.upper(), path, nonce, str(int(status)),
                      hashlib.sha256(raw or b'').hexdigest(), responder,
                      requester)).encode()


def answer_signature(method, path, nonce, status, raw, requester):
    """The signature this instance puts on its answer to a signed member call: bound to
    the request's own nonce, so a captured answer replays nowhere."""
    msg = _answer_message(method, path, nonce, status, raw, instance_id(), requester)
    return base64.b64encode(signing_key().sign(msg)).decode()


def _answer_ok(headers, method, path, nonce, status, raw, responder, requester, public_b64):
    sig = None
    for k, v in (headers or {}).items():
        if isinstance(k, str) and k.lower() == ANSWER_HEADER.lower():
            sig = v
            break
    if not isinstance(sig, str) or not ha_wire.SIGNATURE_RE.fullmatch(sig):
        return False
    key = ha_wire.public_key(public_b64)
    if key is None:
        return False
    from cryptography.exceptions import InvalidSignature
    try:
        key.verify(base64.b64decode(sig),
                   _answer_message(method, path, nonce, status, raw, responder, requester))
        return True
    except (InvalidSignature, ValueError):
        return False


# --- the outbound transport -------------------------------------------------------------

_fp_provider = {'fn': None}


def set_fingerprint_provider(fn):
    """api/federation.py hands its own_fingerprints over at import, so the core can carry
    this instance's certificate fingerprints without importing Flask."""
    _fp_provider['fn'] = fn


def own_fingerprints():
    fn = _fp_provider['fn']
    if fn is None:
        return []
    try:
        return _clean_fps(fn())
    except Exception as e:
        _say_once('own-fps', f'[FED] could not read this instance\'s fingerprints: {e}')
        return []


def _url_ok(url):
    """The outbound address check of ha.py: https only, private networks allowed, metadata
    addresses never. Cached per address for half a minute."""
    held = _runtime['url_ok'].get(url)
    now = time.monotonic()
    if held is not None and 0 <= now - held[2] < 30:
        return held[0]
    from pegaprox.utils.url_security import is_safe_outbound_url
    try:
        ok, why = is_safe_outbound_url(url, allowed_schemes=('https',), allow_private=True)
    except Exception as e:
        ok, why = False, str(e)
    if len(_runtime['url_ok']) > 64:
        _runtime['url_ok'].clear()
    _runtime['url_ok'][url] = (ok, why, now)
    if not ok:
        _say_once(('url', url), f'[FED] refused to call {url}: {why}')
    return ok


def _session_for(url, fingerprint):
    """One kept session per member address and pin; a new pin or address replaces the
    old one, and the table holds two per site at most."""
    import requests
    key = (url, fingerprint)
    with _sessions_lock:
        sessions = _runtime['sessions']
        sess = sessions.get(key)
        if sess is not None:
            return sess
        for old in [k for k in sessions if k[0] == url]:
            _close_quietly(sessions.pop(old))
        while len(sessions) >= 2 * MAX_SITES:
            _close_quietly(sessions.pop(next(iter(sessions))))
        sess = requests.Session()
        sess.headers['User-Agent'] = 'PegaProx-Federation/2'
        if fingerprint:
            from pegaprox.core.pbs import _PinnedFingerprintAdapter
            sess.mount('https://', _PinnedFingerprintAdapter(fingerprint))
        sessions[key] = sess
        return sess


def _close_quietly(sess):
    try:
        sess.close()
    except Exception:
        pass


def _read_capped(resp, cap):
    chunks, size = [], 0
    for chunk in resp.iter_content(chunk_size=65536):
        size += len(chunk or b'')
        if size > cap:
            return None
        chunks.append(chunk)
    return b''.join(chunks)


def _send(url, fingerprints, method, path, body=None, headers=None, read_timeout=10,
          cap=MAX_ANSWER, answer_from=None, answer_key=None):
    """One call to another instance: (status, json or None, headers). Never raises.

    The address passes the outbound check, a pinned fingerprint is the verification
    (`verify` is passed per request, so a CA bundle in the environment cannot turn a
    pinned call back into CA verification), the fingerprints are tried in order (the two
    hosts of an HA group), a redirect is a failure, and the answer is read streamed up to
    `cap`. With `answer_from` the answer must carry that member's signature over the
    request nonce, or it counts as no answer."""
    data = ha_wire.wire_body(body) if body is not None else None
    h = {'X-Requested-With': PEER_XHR, 'Accept': 'application/json'}
    if data is not None:
        h['Content-Type'] = 'application/json'
    h.update(headers or {})
    transport = _runtime.get('transport')
    if transport is not None:
        try:
            status, raw, rh = transport(url, method, path, data, h)
        except Exception as e:
            logging.warning(f'[FED] call to {url}{path} failed: {e}')
            return 0, None, {}
        if raw is not None and len(raw) > cap:
            logging.warning(f'[FED] answer of {url}{path} over {cap} bytes - refused')
            return 0, None, {}
    else:
        status, raw, rh = _wire_call(url, fingerprints, method, path, data, h,
                                     read_timeout, cap)
        if not status:
            return 0, None, {}
    rh = dict(rh or {})
    if answer_from is not None:
        nonce = h.get(ha_wire.PEER_NONCE_HEADER) or ''
        requester = h.get(ha_wire.PEER_HEADER) or ''
        if not _answer_ok(rh, method, path, nonce, status, raw, answer_from, requester,
                          answer_key or ''):
            _say_once(('unsigned', answer_from, path),
                      f'[FED] the answer of {answer_from} to {path} carries no good '
                      f'signature - taken as no answer')
            return 0, None, {}
    try:
        parsed = json.loads(raw) if raw else None
    except Exception:
        parsed = None
    return status, parsed, rh


def _wire_call(url, fingerprints, method, path, data, headers, read_timeout, cap):
    import requests
    if not url or not _url_ok(url + path):
        return 0, None, {}
    pins = list(fingerprints or []) or ['']
    for i, fp in enumerate(pins):
        sess = _session_for(url, fp)
        try:
            resp = sess.request(method, url + path, data=data, headers=headers,
                                verify=not fp, allow_redirects=False, stream=True,
                                timeout=(CONNECT_TIMEOUT, read_timeout))
        except requests.exceptions.SSLError as e:
            if i + 1 < len(pins):
                # the other host of an HA group answers under the next pin
                continue
            logging.warning(f'[FED] call to {url}{path}: the certificate matches no pin ({e})')
            return 0, None, {}
        except Exception as e:
            logging.warning(f'[FED] call to {url}{path} failed: {type(e).__name__}')
            return 0, None, {}
        try:
            # 304 is the conditional identity pull's "nothing changed", no redirect
            if 300 <= resp.status_code < 400 and resp.status_code != 304:
                logging.warning(f'[FED] {url}{path} answered a redirect - not followed')
                return 0, None, {}
            raw = _read_capped(resp, cap)
            if raw is None:
                logging.warning(f'[FED] answer of {url}{path} over {cap} bytes - refused')
                return 0, None, {}
            return resp.status_code, raw, dict(resp.headers)
        except Exception as e:
            logging.warning(f'[FED] answer of {url}{path} broke off: {type(e).__name__}')
            return 0, None, {}
        finally:
            resp.close()
    return 0, None, {}


def _call(iid, rec, method, path, body=None, read_timeout=10, extra_headers=None,
          cap=MAX_ANSWER):
    """One signed call to member `iid` at the address of `rec`, its answer checked
    against the key in `rec`."""
    if not rec or not rec.get('url'):
        return 0, None, {}
    try:
        h = signed_headers(iid, method, path, body)
    except FederationError as e:
        logging.warning(f'[FED] cannot sign a call to {iid}: {e}')
        return 0, None, {}
    if extra_headers:
        # a plain HTTP header a proxy may touch (If-None-Match): not signed, the worst a
        # wrong one does is fetch a body that was due anyway
        h.update({k: v for k, v in extra_headers.items()
                  if isinstance(k, str) and isinstance(v, str)})
    status, data, rh = _send(rec['url'], rec.get('fingerprints') or [], method, path, body,
                             h, read_timeout, cap, answer_from=iid,
                             answer_key=rec.get('public_key') or '')
    if status:
        # a signed answer: the member runs and reaches us, whatever it said
        _runtime.setdefault('heard', {})[iid] = _heard_now()
        _runtime.setdefault('answered', {})[iid] = int(time.time())
    if status == 410 and isinstance(data, dict) and data.get('code') == 'FED_REMOVED':
        _runtime['removed_by'][iid] = int(time.time())
        if isinstance(data.get('end'), dict):
            _runtime.setdefault('ended_by', {})[iid] = data['end']
    return status, data, rh


def call_peer(iid, method, path, body=None, read_timeout=10, extra_headers=None,
              cap=MAX_ANSWER):
    """One signed call to a member of the view by its instance id: (status, json or None,
    headers). Raises nothing."""
    return _call(iid, member_record(iid), method, path, body, read_timeout,
                 extra_headers, cap)


def _parallel(fn, items, max_workers=None):
    """fn over items side by side, results in the order of items. A call that raises
    gives None. Each worker runs in a copy of the caller's context."""
    items = list(items)
    if not items:
        return []

    def safe(item):
        try:
            return fn(item)
        except Exception as e:
            logging.warning(f'[FED] a member call failed: {e}')
            return None
    if len(items) == 1:
        return [safe(items[0])]
    import contextvars
    from concurrent.futures import ThreadPoolExecutor
    workers = max(1, min(len(items), max_workers or len(items), 2 * MAX_SITES))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(contextvars.copy_context().run, safe, item) for item in items]
        return [f.result() for f in futures]


# --- pairing --------------------------------------------------------------------------

PAIRING_CODE_ERROR = ('The pairing code is not one this instance made, or it has expired '
                      '- make a new one on the federation page')


def own_enrolled_ids():
    """The cluster rows this instance leads as enrolled."""
    me = instance_id()
    if not me:
        return []
    try:
        return [r['id'] for r in _db().conn.execute(
            'SELECT id FROM clusters WHERE fed_owner = ? ORDER BY id', (me,)).fetchall()]
    except Exception as e:
        raise FederationError(f'The clusters table cannot be read: {e}')


def _refuse_pairing_with_old_rows():
    """An instance on its own that still holds rows it enrolled in a federation it left
    (or was removed from) pairs with nobody: a new partner knows nothing of those ids and
    would back their leases, while the old federation may have adopted the clusters."""
    if members():
        return
    held = own_enrolled_ids()
    if held:
        raise FederationError('This instance still has clusters enrolled in a federation it '
                              f'is no longer part of: {", ".join(held[:10])}. Another site '
                              'may have adopted them meanwhile, so they stay closed. '
                              'Unenroll them with force (they are then this instance\'s '
                              'own again), then pair', code='FED_ENROLLED', clusters=held)


def create_pairing_code(url, fingerprint=''):
    """A one-time code for the instance that is to join. One code is open at a time; a new
    one replaces it. The fingerprint defaults to this instance's certificate. Returns
    (code, expires_at)."""
    url = ha_wire.valid_https_url(url)
    if not url:
        raise FederationError('Enter the https:// address the joining instance will use '
                              'to reach this one')
    fingerprint = (fingerprint or '').strip().upper()
    if fingerprint and not ha_wire.FP_RE.fullmatch(fingerprint):
        raise FederationError('The certificate fingerprint is malformed')
    if len(members()) + 1 >= MAX_SITES:
        raise FederationError(f'The federation has {MAX_SITES} sites, the most it can hold',
                              code='FED_FULL')
    _refuse_pairing_with_old_rows()
    me = ensure_identity()
    if not me:
        raise FederationError('A standby takes part in the federation of its active - '
                              'pair there', code='FED_STANDBY')
    mine = own_fingerprints()
    if not fingerprint:
        fingerprint = mine[0] if mine else ''
    fps = _clean_fps(([fingerprint] if fingerprint else []) + mine)
    _set_self(url=url, fingerprints=fps)
    secret = secrets.token_hex(32)
    expires = int(time.time()) + PAIRING_TTL

    def go(st):
        # only a hash of the secret is kept, as the HA pairing keeps its code: the answer
        # to a join is sealed under the secret the joiner presents
        st['pairing'] = {'secret_hash': _code_hash(secret), 'url': url,
                         'fingerprint': fingerprint, 'expires': expires}
        return True
    _mutate_leases(go)
    return ha_wire.encode_code(CODE_PREFIX, url, fingerprint, secret, me), expires


def _code_hash(secret):
    return hashlib.sha256(('pegaprox-fed-code-1\n' + str(secret)).encode()).hexdigest()


def pairing_open():
    """The open code's address and end, None when there is none."""
    pairing = _lease_state().get('pairing') or {}
    if pairing.get('secret_hash') and int(pairing.get('expires') or 0) > time.time():
        return {'url': pairing.get('url') or '', 'expires_at': pairing.get('expires')}
    return None


def accept_join(code, url, joiner_id, joiner_key, site, fingerprints=None, joiner_dr=False):
    """The issuer's half of a join: check the code without spending it, add the member
    through a view change (a majority of the view takes the lock), spend the code, answer
    with the view sealed under the code's secret. Raises FederationError with what the
    joining instance reads; FED_NO_QUORUM, FED_FULL and FED_DR_OFF_AT leave the code open.

    While a cluster is enrolled here, the joiner must have its disaster recovery on
    (`joiner_dr`, its own word): it would count in every majority of the leases and refuse
    each vote."""
    if not isinstance(code, str):
        raise FederationError(PAIRING_CODE_ERROR, code='FED_CODE')
    try:
        parts = ha_wire.decode_code(CODE_PREFIX, code, 'a federation pairing code')
    except ha_wire.WireError as e:
        raise FederationError(str(e), code='FED_CODE')
    url = ha_wire.valid_https_url(url)
    if not url:
        raise FederationError('The joining instance did not send a usable https:// address',
                              code='FED_CODE')
    if not ha_wire.ID_RE.fullmatch(joiner_id or ''):
        raise FederationError('The joining instance did not send a usable instance id',
                              code='FED_CODE')
    if ha_wire.public_key(joiner_key) is None:
        raise FederationError('The joining instance did not send a usable public key',
                              code='FED_CODE')
    me = instance_id()
    if not me or joiner_id == me:
        raise FederationError('This instance cannot pair with itself', code='FED_CODE')
    if joiner_dr is not True and _db().conn.execute(
            "SELECT 1 FROM clusters WHERE fed_owner != '' LIMIT 1").fetchone():
        raise FederationError('Clusters of this federation are enrolled, and the joining '
                              'instance has its disaster recovery off: switch it on there '
                              'first, under Federation', code='FED_DR_OFF_AT')
    secret = parts['secret']
    with _lock:
        st = _lease_state()
        pairing = st.get('pairing') or {}
        held = pairing.get('secret_hash') or ''
        fresh = bool(held and pairing.get('expires', 0) >= time.time()
                     and secrets.compare_digest(held, _code_hash(secret)))
        if not fresh:
            # the joiner this code was spent on asks again: its answer got lost on the
            # way, and the change that added it is made already
            rec = members().get(joiner_id) or {}
            if not (_spent_on(st, secret, joiner_id, joiner_key)
                    and rec.get('public_key') == joiner_key):
                raise FederationError(PAIRING_CODE_ERROR, code='FED_CODE')
        elif _runtime.get('pairing_busy') == held:
            raise FederationError('That pairing code is being used right now',
                                  code='FED_CODE')
        else:
            _runtime['pairing_busy'] = held
    if not fresh:
        return _join_answer(secret, parts, joiner_id, identity() or {}, [])
    try:
        if joiner_id in members():
            raise FederationError('That instance is a member already - remove it first, '
                                  'then pair again', code='FED_CODE')
        if len(members()) + 1 >= MAX_SITES:
            raise FederationError(f'The federation has {MAX_SITES} sites, the most it can '
                                  'hold', code='FED_FULL')
        _refuse_pairing_with_old_rows()
        rec = {'url': url, 'public_key': joiner_key, 'site': _clean_site(site),
               'fingerprints': _clean_fps(fingerprints or [])}
        with _one_change():
            out = _view_change({'op': 'add', 'instance_id': joiner_id, 'member': rec},
                               by=f'pairing:{joiner_id}')

        def spend(st):
            if (st.get('pairing') or {}).get('secret_hash') != held:
                return False
            st['pairing'] = None
            # kept until the code would have run out, for this joiner alone
            st['pairing_spent'] = {'secret_hash': held, 'joiner': joiner_id,
                                   'key': joiner_key,
                                   'expires': int(pairing.get('expires') or 0)}
            return True
        _mutate_leases(spend)
    finally:
        _runtime['pairing_busy'] = None
    return _join_answer(secret, parts, joiner_id, out['ident'], out['not_told'])


def _spent_on(st, secret, joiner_id, joiner_key):
    """Whether `secret` is the code this instance spent on the joiner `joiner_id` with
    the key `joiner_key`, and would still be valid."""
    spent = st.get('pairing_spent')
    if not isinstance(spent, dict) or not isinstance(spent.get('secret_hash'), str):
        return False
    return (int(spent.get('expires') or 0) >= time.time()
            and secrets.compare_digest(spent['secret_hash'], _code_hash(secret))
            and spent.get('joiner') == joiner_id and spent.get('key') == joiner_key)


def _join_answer(secret, parts, joiner_id, snap, not_told):
    """The view a joiner takes, sealed under the code's secret."""
    me = instance_id()
    ident = identity() or {}
    epoch = int((snap.get('view') or {}).get('epoch') or 0)
    view = {iid: _wire_record(r) for iid, r in ((snap.get('view') or {}).get('members')
                                                 or {}).items() if iid != joiner_id}
    view[me] = {'url': own_url() or parts['url'], 'public_key': public_key(),
                'site': own_site(),
                'fingerprints': ident.get('self', {}).get('fingerprints')
                or _clean_fps([parts['fingerprint']] if parts['fingerprint'] else [])}
    body = {'view': {'epoch': epoch, 'members': view},
            'tombstones': {iid: {'public_key': t.get('public_key') or ''}
                           for iid, t in (snap.get('tombstones') or {}).items()
                           if iid != joiner_id}}
    sealed = ha_wire.seal(secret, body, f'federation-join:{me}:{joiner_id}')
    return {'sealed': sealed, 'members': sorted(set(view) | {joiner_id}),
            'not_told': not_told}


def _wire_record(rec):
    return {'url': rec.get('url') or '', 'public_key': rec.get('public_key') or '',
            'site': rec.get('site') or '', 'fingerprints': list(rec.get('fingerprints') or [])}


def join(code, own_url_, site='', fingerprints=None):
    """The joining half: hand the code to the instance that made it, take the view it
    answers under the code's seal as this instance's own. The call carries no signature -
    the issuer does not know this instance's key yet - so the code in the body is what
    lets it through, and the seal on the answer tells the issuer apart from anybody else."""
    if members():
        raise FederationError('This instance is a member of a federation already - leave '
                              'it first', code='FED_ALREADY_MEMBER')
    _refuse_pairing_with_old_rows()
    try:
        parts = ha_wire.decode_code(CODE_PREFIX, code, 'a federation pairing code')
    except ha_wire.WireError as e:
        raise FederationError(str(e))
    own_url_ = ha_wire.valid_https_url(own_url_)
    if not own_url_:
        raise FederationError('Enter the https:// address the other instances will use to '
                              'reach this one')
    me = ensure_identity()
    if not me:
        raise FederationError('A standby takes part in the federation of its active - '
                              'pair there', code='FED_STANDBY')
    # the lease file is read while the view is still empty: a voter that never voted
    # holds for nobody, while a file that went missing under a view with members holds
    _lease_state()
    site = _clean_site(site)
    if site:
        set_own_site(site)
    fps = _clean_fps(fingerprints) if fingerprints else own_fingerprints()
    _set_self(url=own_url_, fingerprints=fps)
    body = {'code': code, 'url': own_url_, 'instance_id': me, 'public_key': public_key(),
            'site': site or own_site(), 'fingerprints': fps, 'dr': dr_enabled()}
    pins = [parts['fingerprint']] if parts['fingerprint'] else []
    status, answer, _h = _send(parts['url'], pins, 'POST', JOIN_PATH, body)
    if status in (403, 409):
        raise FederationError((answer or {}).get('error')
                              or 'The other instance refused the pairing code',
                              code=(answer or {}).get('code') if status == 409 else None)
    if status != 200 or not isinstance(answer, dict) or not isinstance(answer.get('sealed'), str):
        raise FederationError('The conversation with the other instance failed - '
                              'unreachable, or it did not answer a member list')
    try:
        opened = ha_wire.unseal(parts['secret'], answer['sealed'],
                                f'federation-join:{parts["instance_id"]}:{me}')
    except Exception:
        raise FederationError('The answer of the other instance did not open under the '
                              'pairing code - a wrong instance answered, or the code was '
                              'spent')
    view = opened.get('view') if isinstance(opened, dict) else None
    listed = view.get('members') if isinstance(view, dict) else None
    epoch = view.get('epoch') if isinstance(view, dict) else None
    if (not isinstance(listed, dict) or parts['instance_id'] not in listed
            or not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1):
        raise FederationError('The answer of the other instance carries no member list')
    kept = {}
    for iid, rec in listed.items():
        if iid == me:
            continue
        r = _member_record(iid, rec)
        if r is None:
            raise FederationError(f'The member list of the other instance names a member '
                                  f'this instance cannot use ({str(iid)[:32]})')
        if iid == parts['instance_id'] and not r['fingerprints'] and parts['fingerprint']:
            r['fingerprints'] = [parts['fingerprint']]
        r['added_at'] = int(time.time())
        r['added_by'] = f'pairing:{parts["instance_id"]}'
        kept[iid] = r
    if len(kept) + 1 > MAX_SITES:
        raise FederationError(f'The member list of the other instance is longer than '
                              f'{MAX_SITES} sites')
    tombs = {}
    for iid, t in list((opened.get('tombstones') or {}).items())[:MAX_TOMBSTONES]:
        if (isinstance(t, dict) and ha_wire.ID_RE.fullmatch(iid or '') and iid != me
                and iid not in kept and ha_wire.public_key(t.get('public_key')) is not None):
            # older than any removal this instance makes itself, in the order received
            tombs[iid] = {'public_key': t['public_key'], 'removed_at': 0, 'removed_by': '',
                          'n': len(tombs) + 1}

    def go(ident):
        ident['view'] = {'epoch': epoch, 'members': kept}
        ident['tombstones'] = tombs
        for iid in kept:
            (ident.get('ended') or {}).pop(iid, None)
        ident['peer_keys'] = {}
        ident['removed'] = None
        ident['commits'] = []
        ident['view_prev'] = None
        ident['handed_over'] = {}
        ident['adopted'] = {}
        ident['drop_pending'] = {}
        return True
    _mutate_identity(go)
    _reset_ownership()
    from pegaprox.core import federation_lease as fl
    fl.note_view_change()
    fl.drop_owner_cache()
    # the keys and the accounts of the issuer come along at once, best effort: the sync
    # loop covers what this misses. The field keys only serve the disaster recovery
    if dr_enabled():
        try:
            fetch_field_keys()
        except Exception as e:
            logging.warning(f'[FED] fetching the field keys after the join failed: {e}')
    pull_identities(parts['instance_id'])
    return {'joined': parts['instance_id'], 'members': sorted(kept)}


# --- the member view ---------------------------------------------------------------------

def _tombstone(ident, iid, rec, by):
    tombs = ident.setdefault('tombstones', {})
    tombs.pop(iid, None)
    tombs[iid] = {'public_key': (rec or {}).get('public_key') or '',
                  'removed_at': int(time.time()), 'removed_by': str(by)[:80],
                  'n': _next_n(tombs)}
    while len(tombs) > MAX_TOMBSTONES:
        # the oldest removal goes, by its time: the dict's order is the ids' order once
        # the row was read back
        tombs.pop(min(tombs, key=lambda k: _age(tombs[k], 'removed_at')))


def _wire_change(change):
    """The wire form of a change: op and instance id, plus the record an add brings."""
    wire = {'op': change['op'], 'instance_id': change['instance_id']}
    if change['op'] == 'add':
        wire.update(_wire_record(change.get('member') or change))
    return wire


def _change_view(ident, wire, by, base):
    """One change (wire form) applied to `ident` in place. Returns (epoch, digest) of the
    view it gives, or None when `ident` is not at `base` or the change does not fit it.
    A removal of this instance itself gives the result and leaves `ident` alone."""
    me = ident.get('instance_id') or ''
    entries = _view_entries(ident)
    if _digest(entries) != base:
        return None
    view = ident['view']['members']
    iid = wire.get('instance_id')
    new_epoch = int(ident['view'].get('epoch') or 0) + 1
    if wire.get('op') == 'add':
        rec = _member_record(iid, wire)
        if rec is None or iid == me or iid in view or len(view) + 1 >= MAX_SITES:
            return None
        rec['added_at'] = int(time.time())
        rec['added_by'] = str(by)[:80]
        view[iid] = rec
        ident.setdefault('tombstones', {}).pop(iid, None)
        # paired again: its old end record could pass for one of the new view, which the
        # same two sites give the same digest
        (ident.get('ended') or {}).pop(iid, None)
        entries[iid] = rec['public_key']
    elif wire.get('op') == 'remove':
        if iid not in entries:
            return None
        entries.pop(iid)
        if iid == me:
            return new_epoch, _digest(entries)
        _tombstone(ident, iid, view.pop(iid), by)
        ident.setdefault('peer_keys', {}).pop(iid, None)
    else:
        return None
    ident['view']['epoch'] = new_epoch
    return new_epoch, _digest(entries)


def _record_change(ident, prev_view, commit):
    """Keep the change just taken with its signed grants (bounded), and the view before
    it, which a change no majority took is rolled back to."""
    ident['view_prev'] = prev_view
    kept = [c for c in ident.get('commits') or []
            if isinstance(c.get('epoch'), int) and c['epoch'] < commit['epoch']]
    ident['commits'] = (kept + [commit])[-MAX_COMMITS:]


def _kept_certs(certs):
    if not isinstance(certs, dict):
        return {}
    return {k: v for k, v in list(certs.items())[:2 * MAX_SITES]
            if isinstance(k, str) and ha_wire.ID_RE.fullmatch(k)
            and isinstance(v, str) and len(v) <= 200}


# One change of the member view at a time in this process. A second change started while
# the first is under way (two admins, a removal and a pairing) would get the members lock
# as a renewal of the first one's and commit from the same base view.
_change_lock = threading.Lock()


@contextlib.contextmanager
def _one_change():
    """Hold the change lock for a join, a removal or a leave; FED_BUSY when another one
    is under way here, in this thread or another."""
    if not _change_lock.acquire(blocking=False):
        raise FederationError('Another change of the federation is under way on this '
                              'instance - try again in a moment', code='FED_BUSY')
    try:
        yield
    finally:
        _change_lock.release()


def _view_change(change, by):
    """One change of the view - {'op': 'add', 'instance_id', 'member': record} or
    {'op': 'remove', 'instance_id'} - made under a majority lock and committed to every
    member of the old view. Returns {'epoch': n, 'not_told': [ids]}. Raises FederationError
    FED_NO_QUORUM when no majority grants the lock, or when fewer than a majority of the
    old view take the commit.

    This instance takes its own change only once a majority of the old view took it: a
    change that reached fewer stays a change of nobody here (the members that took it go
    back to the view the others hold, see catch_up), so a lost commit followed by another
    member's change from the same view cannot leave two views of one epoch, and a removed
    member's data is not dropped for a removal that did not happen.

    The commit carries this instance's signature over the change (_commit_signed), and
    the callers hold _one_change() around it."""
    import copy
    from pegaprox.core import federation_lease as fl
    me = instance_id()
    old = members()
    base = view_digest()
    ids = view_ids()
    r = fl.lease_round(only={MEMBERS_LOCK}).get(MEMBERS_LOCK) or {}
    if not r.get('held'):
        fl.release_lock(to=sorted(old))
        votes, need = r.get('votes', 0), r.get('needed', needed(len(ids)))
        if (r.get('refusals') or {}).get('taken'):
            raise FederationError(f'A change of the federation needs a majority of its '
                                  f'members: {votes} of {len(ids)} agreed - a takeover is not '
                                  f'known at every site yet; try again in a few seconds',
                                  code='FED_NO_QUORUM', votes=votes, needed=need)
        raise FederationError(f'A change of the federation needs a majority of its '
                              f'members: {votes} of {len(ids)} agreed, {need} are needed. '
                              f'A split network cannot shrink or grow the federation on '
                              f'one side', code='FED_NO_QUORUM', votes=votes, needed=need)
    try:
        if not fl.holds(MEMBERS_LOCK):
            raise FederationError('The lock on the federation ran out before the change '
                                  'was made - try again', code='FED_NO_QUORUM')
        iid = change['instance_id']
        wire = _wire_change(change)
        probe = copy.deepcopy(identity() or _blank_identity())
        res = _change_view(probe, wire, by, base)
        if res is None:
            raise FederationError('The federation changed meanwhile - try again',
                                  code='FED_VIEW')
        commit = {'epoch': res[0], 'base': base, 'digest': res[1], 'change': wire,
                  'certs': _kept_certs(fl.lock_certs()), 'by': me,
                  'sig': _sign_commit(res[0], base, res[1], wire)}
        targets = sorted(old)
        told = _parallel(lambda t: _call(t, old[t], 'POST', MEMBERSHIP_PATH, commit,
                                         read_timeout=VOTE_TIMEOUT)[0], targets)
        acked = [t for t, st in zip(targets, told) if st == 200]
        not_told = sorted(t for t in targets if t not in acked)
        need = needed(len(ids))
        if 1 + len(acked) < need:
            raise FederationError(f'The change reached {1 + len(acked)} of {len(ids)} '
                                  f'members, {need} are needed: nothing changed here. '
                                  f'Members that took it go back to the view the others '
                                  f'hold; try again when the sites answer',
                                  code='FED_NO_QUORUM', votes=1 + len(acked), needed=need,
                                  not_told=not_told)
        if iid != me:
            out = {}

            def go(ident):
                prev = copy.deepcopy(ident['view'])
                if _change_view(ident, wire, by, base) != res:
                    out['moved'] = True
                    return False
                _record_change(ident, prev, dict(commit))
                return True
            _mutate_identity(go)
            if out.get('moved'):
                raise FederationError('The federation changed meanwhile - try again',
                                      code='FED_VIEW')
            fl.note_view_change()
            if change['op'] == 'remove':
                _drop_member_data(iid)
            # a majority held the view this change was made from
            _settle_drops(res[0] - 1)
    finally:
        # the members that voted for the lock give it back; a new member never held it
        fl.release_lock(to=sorted(old))
    if change['op'] == 'remove' and change['instance_id'] != me and not members():
        fl.return_alone('the last other site was removed')
    return {'epoch': res[0], 'not_told': not_told, 'ident': probe}


def apply_membership(sender, body):
    """A committed view change from `sender`: applied when this instance's live promise
    for the members lock names the sender, the commit is derived from this instance's
    view (base digest), moves the epoch by exactly one, carries the signed lock grants of
    a majority of that view and the sender's own signature over the change. Returns
    {'epoch': n}; raises FederationError FED_NO_LOCK, FED_VIEW or FED_BAD_CHANGE.

    A removal takes the member out of the view at once and ends its accounts' sessions;
    what this instance holds of it goes only once a majority shows it took the change
    (_defer_drop): the change may be one too few took, and then it is rolled back. A
    removal that leaves this instance alone in the view settles at once: no member is
    left that could roll it back."""
    import copy
    from pegaprox.core import federation_lease as fl
    if not isinstance(body, dict):
        raise FederationError('That is no view change', code='FED_BAD_CHANGE')
    epoch, base, digest, change = (body.get('epoch'), body.get('base'), body.get('digest'),
                                   body.get('change'))
    if (not isinstance(epoch, int) or isinstance(epoch, bool) or not isinstance(base, str)
            or not isinstance(digest, str) or not isinstance(change, dict)
            or change.get('op') not in ('add', 'remove')
            or not ha_wire.ID_RE.fullmatch(change.get('instance_id') or '')
            or body.get('by') != sender):
        raise FederationError('That is no view change', code='FED_BAD_CHANGE')
    if not fl.promised_to(MEMBERS_LOCK, sender):
        raise FederationError('This instance did not grant the sender the lock on the '
                              'federation', code='FED_NO_LOCK', epoch=view_epoch())
    me = instance_id()
    iid = change['instance_id']
    wire = _wire_change(change)
    certs = _kept_certs(body.get('certs'))
    sig = body.get('sig') if isinstance(body.get('sig'), str) else ''
    signed = {'epoch': epoch, 'base': base, 'digest': digest, 'change': wire, 'by': sender,
              'sig': sig}
    out = {}

    def go(ident):
        entries = _view_entries(ident)
        view = ident['view']['members']
        if _digest(entries) != base or epoch != int(ident['view'].get('epoch') or 0) + 1:
            out['view'] = True
            return False
        if change['op'] == 'add':
            if _member_record(iid, change) is None or iid == me or iid in view:
                out['bad'] = 'the member it adds is not one this instance can take'
                return False
            if len(view) + 1 >= MAX_SITES:
                out['bad'] = f'the federation holds {MAX_SITES} sites already'
                return False
        elif iid not in entries:
            out['bad'] = 'the member it removes is not in the view'
            return False
        probe = copy.deepcopy(ident)
        got = _change_view(probe, wire, f'peer:{sender}', base)
        if got is None or got[1] != digest:
            out['view'] = True
            return False
        # one promise of this instance is not enough: a member could get it with a single
        # ask and commit to this voter alone. The grants of a majority of the view travel
        # with the commit, each signed by its voter
        if _certified(certs, sender, base, epoch - 1, entries) < needed(len(entries)):
            out['nolock'] = True
            return False
        # kept and handed on to members that catch up: they check it, so it is checked
        # here before it is kept
        if not _commit_signed(signed, entries):
            out['bad'] = 'it carries no signature of the member that made it'
            return False
        if change['op'] == 'remove' and iid == me:
            out['self'] = True
            return False
        prev = copy.deepcopy(ident['view'])
        _change_view(ident, wire, f'peer:{sender}', base)
        _record_change(ident, prev, dict(signed, certs=certs))
        return True
    _mutate_identity(go)
    if out.get('view'):
        raise FederationError('That change does not follow the view this instance holds',
                              code='FED_VIEW', epoch=view_epoch())
    if out.get('bad'):
        raise FederationError(f'That change cannot be taken: {out["bad"]}',
                              code='FED_BAD_CHANGE')
    if out.get('nolock'):
        raise FederationError('That change carries no majority of signed grants of the lock '
                              'on the federation', code='FED_NO_LOCK', epoch=view_epoch())
    site = (member_record(sender) or {}).get('site') or sender[:8]
    from pegaprox.utils.audit import log_audit
    if out.get('self'):
        _become_removed(by=sender)
        return {'epoch': epoch, 'removed': True}
    fl.note_view_change()
    # the grants of this change show that a majority held the view it was made from: a
    # removal taken here before is one a majority took
    _settle_drops(epoch - 1)
    if change['op'] == 'remove':
        _defer_drop(iid, epoch)
        if not members():
            _settle_drops(epoch)
        log_audit('system', 'federation.member_removed',
                  f'member {iid} removed from the federation, told by {site}',
                  ip_address='federation')
        if not members():
            fl.return_alone('the last other site left')
    else:
        log_audit('system', 'federation.member_added',
                  f'member {iid} ({change.get("url")}) added to the federation, told by '
                  f'{site}', ip_address='federation')
    return {'epoch': epoch}


def peer_status_body():
    """What /peer/status answers: who we are, the view we hold, the id of our field key
    and a count of what this instance manages. No names, no addresses of clusters, no
    credentials."""
    ident = identity() or {}
    body = {'instance_id': ident.get('instance_id') or '', 'fed': FED_MARK,
            'site': own_site(), 'view': {'epoch': view_epoch(), 'digest': view_digest()},
            'field_key_id': ident.get('field_key_id') or '', 'dr': dr_enabled(),
            'summary': {}}
    try:
        from pegaprox import globals as g
        body['summary'] = {'clusters': len(getattr(g, 'cluster_managers', None) or {})}
    except Exception:
        pass
    return body


def peer_view_body():
    """What /peer/view answers: the whole view for a member that is behind, this
    instance's own record included, the tombstones, and the last changes with their signed
    lock grants - the chain a member behind replays from its own view."""
    ident = identity() or {}
    me = ident.get('instance_id') or ''
    view = {iid: _wire_record(r) for iid, r in members().items()}
    if me:
        view[me] = {'url': own_url(), 'public_key': public_key(), 'site': own_site(),
                    'fingerprints': list(ident.get('self', {}).get('fingerprints') or [])}
    return {'instance_id': me, 'view': {'epoch': view_epoch(), 'members': view},
            'tombstones': {iid: {'public_key': t.get('public_key') or ''}
                           for iid, t in tombstones().items()},
            'commits': list(ident.get('commits') or [])}


def catch_up():
    """Ask every member where its view stands and move this instance's view to where the
    federation is.

    A view a majority of the members (this one counted) holds is where the federation is:
    nothing to do. Otherwise a newer view is taken by replaying the changes a member that
    holds it kept, each checked against the signed lock grants of a majority of the view
    it was made from and its committer's signature over the change (_adopt_view): no
    single member can make a view up, nor swap the change of another member's commit.

    A view no majority holds may come from a change that did not reach a majority: its
    committer then never took it (see _view_change). The committer takes a change only
    once a majority of the view before it took it, so when the members of that earlier
    view that answer with another view, none of them ahead of the one held here, are a
    majority of it, no majority took the change (_no_majority_took). Such a view is
    rolled back to the view before it (and taken again only from a majority), and the
    newer view of the others is replayed from there. Who else holds it, and what its
    committer answers, decide nothing: replies get lost after a change was applied.

    Alone in the view, there is nobody to ask: a removal still pending (_defer_drop)
    settles, as no member is left that could roll it back."""
    me = instance_id()
    roster = members()
    if me and not roster:
        _settle_drops(view_epoch())
    if not me or not roster:
        return {'adopted': False}
    own = (view_epoch(), view_digest())
    order = sorted(roster)
    answers = _parallel(lambda iid: call_peer(iid, 'GET', STATUS_PATH, read_timeout=5), order)
    reports, statuses = {}, {}
    for iid, ans in zip(order, answers):
        status, body, _h = ans or (0, None, {})
        if status != 200 or not isinstance(body, dict) or body.get('instance_id') != iid:
            continue
        _runtime['removed_by'].pop(iid, None)
        if isinstance(body.get('field_key_id'), str):
            statuses[iid] = body['field_key_id']
        got = _reported_view(body)
        if got is not None:
            reports[iid] = got
    _runtime['statuses'] = statuses
    _note_peer_views(reports)
    need = needed(len(view_ids()))
    if 1 + sum(1 for r in reports.values() if r == own) >= need:
        _runtime['view_conflict'] = False
        _settle_drops(own[0])
        return {'adopted': False}
    if _take_newer(reports, own):
        _runtime['view_conflict'] = False
        return {'adopted': True}
    if _no_majority_took(own, reports) and _roll_back(own):
        _take_newer(reports, (view_epoch(), view_digest()))
        _runtime['view_conflict'] = False
        return {'adopted': True, 'rolled_back': True}
    conflict = any(e == own[0] and d != own[1] for e, d in reports.values())
    if conflict:
        _say_once(('view-conflict', own),
                  f'[FED] a member holds view {own[0]} with another member list than this '
                  f'instance, and neither has a majority behind it yet - nothing is adopted',
                  logging.ERROR)
    _runtime['view_conflict'] = conflict
    return {'adopted': False}


def _reported_view(body):
    view = body.get('view') if isinstance(body.get('view'), dict) else {}
    e, d = view.get('epoch'), view.get('digest')
    if isinstance(e, int) and not isinstance(e, bool) and isinstance(d, str):
        return e, d
    return None


def _note_peer_views(reports):
    """A member whose view moved since the last sync (it caught up, or rolled back) may
    hold an older record of this instance than the one it was told: the next push of the
    own record goes to it again."""
    seen = _runtime.setdefault('peer_views', {})
    for iid, r in reports.items():
        if seen.get(iid) not in (None, r):
            _runtime['self_pushed'].pop(iid, None)
        seen[iid] = r


def _no_majority_took(own, reports):
    """Whether the answers show that no majority of the view before `own` (view_prev)
    took the change that gave `own`: members of that earlier view answering with another
    view, none of them ahead of `own`, are a majority of it. Members of view_prev that the
    view held here no longer lists (the member a removal took out) are asked as well. A
    member ahead of `own` may have passed through it and is not counted; this instance
    holds `own` and is not counted either."""
    ident = identity() or {}
    prev = ident.get('view_prev')
    if not prev or prev.get('epoch') != own[0] - 1:
        return False
    me = ident.get('instance_id') or ''
    earlier = {k: v for k, v in (prev.get('members') or {}).items() if k != me}
    held = members()
    extra = sorted(i for i in earlier if i not in reports and i not in held)
    asked = {iid: r for iid, r in reports.items() if iid in earlier}
    got = _parallel(lambda i: _call(i, earlier[i], 'GET', STATUS_PATH, read_timeout=5), extra)
    for iid, ans in zip(extra, got):
        status, body, _h = ans or (0, None, {})
        if status == 200 and isinstance(body, dict) and body.get('instance_id') == iid:
            r = _reported_view(body)
            if r is not None:
                asked[iid] = r
    others = sum(1 for r in asked.values() if r != own and r[0] <= own[0])
    return others >= needed(len(earlier) + 1)


def _take_newer(reports, own):
    """Replay the newest view the most members report from a member that holds it. A view
    a rollback here gave up on is taken again only when a majority reports it. True when
    a view was taken."""
    from collections import Counter
    dead = {tuple(v) for v in _runtime.get('dead_views') or []}
    need = needed(len(view_ids()))
    counts = Counter(r for r in reports.values() if r[0] > own[0])
    counts = Counter({r: n for r, n in counts.items() if r not in dead or n >= need})
    for want, _n in sorted(counts.items(), key=lambda kv: (kv[1], kv[0][0]), reverse=True):
        for iid in sorted(i for i, r in reports.items() if r == want):
            status, body, _h = call_peer(iid, 'GET', VIEW_PATH, read_timeout=5)
            if status == 200 and _adopt_view(body, iid):
                return True
    if counts:
        _say_once(('no-replay', own),
                  f'[FED] the members hold a newer view than {own[0]}, and no chain of signed '
                  f'changes they kept leads there from the view held here (more than '
                  f'{MAX_COMMITS} changes behind, or a list nobody signed) - leave and pair '
                  f'again if it stays so')
    return False


def _valid_commit(c):
    if not isinstance(c, dict):
        return None
    epoch, change = c.get('epoch'), c.get('change')
    if (not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1
            or not isinstance(c.get('base'), str) or not isinstance(c.get('digest'), str)
            or not isinstance(change, dict) or change.get('op') not in ('add', 'remove')
            or not ha_wire.ID_RE.fullmatch(change.get('instance_id') or '')
            or not ha_wire.ID_RE.fullmatch(c.get('by') or '')):
        return None
    sig = c.get('sig')
    return {'epoch': epoch, 'base': c['base'][:64], 'digest': c['digest'][:64],
            'change': _wire_change(change), 'certs': _kept_certs(c.get('certs')),
            'by': c['by'], 'sig': sig if isinstance(sig, str) and len(sig) <= 200 else ''}


def _replay(ident, commits):
    """Walk `commits` forward from the view in `ident` (a copy this function may change).
    Each one must follow the view before it, come from a member of that view, carry
    signed lock grants of a majority of it, and carry that member's own signature over
    the change. Returns (ident at the end, the view before the last step, the member that
    removed this instance or None, the commits taken)."""
    import copy
    by_epoch = {}
    for raw in commits:
        c = _valid_commit(raw)
        if c is not None:
            by_epoch.setdefault(c['epoch'], c)
    me = ident.get('instance_id') or ''
    applied, prev_view = [], None
    while True:
        epoch = int(ident['view'].get('epoch') or 0)
        c = by_epoch.get(epoch + 1)
        if c is None:
            break
        entries = _view_entries(ident)
        base = _digest(entries)
        if c['base'] != base or c['by'] not in entries:
            break
        if _certified(c['certs'], c['by'], base, epoch, entries) < needed(len(entries)):
            break
        if not _commit_signed(c, entries):
            break
        wire = c['change']
        if wire['op'] == 'remove' and wire['instance_id'] == me:
            entries.pop(me, None)
            if _digest(entries) != c['digest']:
                break
            return ident, prev_view, c['by'], applied + [c]
        trial = copy.deepcopy(ident)
        got = _change_view(trial, wire, f'catch-up:{c["by"]}', base)
        if got is None or got[1] != c['digest']:
            break
        prev_view = copy.deepcopy(ident['view'])
        ident = trial
        applied.append(c)
    return ident, prev_view, None, applied


def _adopt_view(body, from_iid):
    """Take the view of member `from_iid` by replaying the changes it kept from the view
    held here (_replay). A view no chain of signed changes leads to is not taken, whatever
    epoch it claims.

    The member records come from the replay alone: a member the chain adds with the
    record in its commit, which its committer signed, and every other member with the
    record held here. The listing of `from_iid` signs nothing of another member's address
    or fingerprints, so nothing of it is taken: a member changes its own record itself,
    with a member update."""
    import copy
    if from_iid not in members() or not isinstance(body, dict):
        return False
    commits = body.get('commits') if isinstance(body.get('commits'), list) else []
    held = identity()
    if not held or not held.get('instance_id'):
        return False
    start = copy.deepcopy(held)
    end, prev_view, removed_by, applied = _replay(copy.deepcopy(held), commits[:4 * MAX_COMMITS])
    if not applied:
        return False
    if removed_by:
        _become_removed(by=removed_by)
        return True
    before = set(members())

    def go(ident):
        if ident['view'] != start['view']:
            return False
        ident['view'] = end['view']
        ident['tombstones'] = end.get('tombstones') or {}
        ident['peer_keys'] = {k: v for k, v in (ident.get('peer_keys') or {}).items()
                              if k in end['view']['members']}
        for c in applied:
            _record_change(ident, prev_view, c)
        return True
    if _mutate_identity(go)['view'] != end['view']:
        return False
    from pegaprox.core import federation_lease as fl
    fl.note_view_change()
    gone = sorted(before - set(end['view']['members']))
    # a removal with a later change of the chain on top of it was taken by a majority (that
    # change carries the grants of a majority of the view after it); the last change of
    # the chain may be one too few took, so a removal there waits like one told directly
    last = int(end['view'].get('epoch') or 0)
    removed_at = {c['change']['instance_id']: c['epoch'] for c in applied
                  if c['change'].get('op') == 'remove'}
    for iid in gone:
        if removed_at.get(iid, 0) >= last:
            _defer_drop(iid, last)
        else:
            _drop_member_data(iid)
    _settle_drops(last - 1)
    added = sorted(set(end['view']['members']) - before)
    site = (member_record(from_iid) or {}).get('site') or from_iid[:8]
    logging.info(f'[FED] took view {end["view"]["epoch"]} from {from_iid}')
    try:
        from pegaprox.utils.audit import log_audit
        log_audit('system', 'federation.view_caught_up',
                  f'view {end["view"]["epoch"]} taken from {site} ({len(applied)} change(s)'
                  f'{", added " + ", ".join(i[:8] for i in added) if added else ""}'
                  f'{", removed " + ", ".join(i[:8] for i in gone) if gone else ""})',
                  ip_address='federation')
    except Exception as e:
        logging.warning(f'[FED] the caught-up view could not be audited: {e}')
    if not members():
        fl.return_alone('the changes caught up leave no other site')
    return True


def _roll_back(own):
    """The view held here is held by no majority: back to the view before its last change.
    False when there is none to go back to (a view a pairing handed over)."""
    import copy
    ident = identity() or {}
    prev = ident.get('view_prev')
    if not prev or prev.get('epoch') != own[0] - 1:
        return False
    dead = _runtime.setdefault('dead_views', [])
    dead.append(list(own))
    del dead[:-8]
    before = set(members())

    def go(ident):
        if (int(ident['view'].get('epoch') or 0), _digest(_view_entries(ident))) != own:
            return False
        ident['view'] = copy.deepcopy(prev)
        ident['view_prev'] = None
        ident['commits'] = [c for c in ident.get('commits') or []
                            if isinstance(c.get('epoch'), int) and c['epoch'] < own[0]]
        for iid in prev.get('members') or {}:
            (ident.get('tombstones') or {}).pop(iid, None)
        return True
    _mutate_identity(go)
    if (view_epoch(), view_digest()) == own:
        return False
    from pegaprox.core import federation_lease as fl
    fl.note_view_change()
    for iid in sorted(before - set(members())):
        _drop_member_data(iid)
    # a removal that was rolled back: the member is in the view again and keeps its data
    _settle_drops(-1)
    logging.warning(f'[FED] view {own[0]} was held by no majority of the members: back to '
                    f'view {own[0] - 1}')
    try:
        from pegaprox.utils.audit import log_audit
        log_audit('system', 'federation.view_rolled_back',
                  f'view {own[0]} was taken by too few members and was rolled back to view '
                  f'{own[0] - 1}', ip_address='federation')
    except Exception as e:
        logging.warning(f'[FED] the rollback could not be audited: {e}')
    return True


def remove_member(iid, by, gone=False, drop_clusters=False):
    """Take a member out, with a majority of the view behind it. Returns {'removed',
    'not_told', 'remedy'}: the copies of this instance's enrolled clusters the removed
    member already holds stay readable there, and rotating those clusters' credentials
    is what cuts it off. `gone`: the other site of a federation of two is gone for good
    and this instance carries on alone (_remove_gone)."""
    me = instance_id()
    if iid == me:
        raise FederationError('This instance leaves - use leave', code='FED_SELF')
    if gone:
        with _one_change():
            return _remove_gone(iid, by, drop_clusters)
    if iid not in members():
        raise FederationError('No such member of this federation', code='FED_NOT_MEMBER')
    try:
        enrolled_here = [r['id'] for r in _db().conn.execute(
            'SELECT id FROM clusters WHERE fed_owner = ? ORDER BY id', (me,)).fetchall()]
    except Exception:
        enrolled_here = []
    with _one_change():
        out = _view_change({'op': 'remove', 'instance_id': iid}, by)
    return {'removed': iid, 'not_told': out['not_told'],
            'remedy': {'enrolled_here': enrolled_here, 'note': 'key'}}


# MK Nov 2026 - a federation of two cannot remove a member by majority once the other site
# is gone for good: one of two is none. The survivor removes it alone, behind the live
# checks of a manual takeover, carries on as a federation of one (its clusters are its own
# again) and keeps a signed end record. Should the removed site ever call again, it is
# answered 410 with that record and gives up every cluster the survivor kept.

def _end_message(end):
    body = {k: end[k] for k in ('by', 'member', 'base', 'epoch', 'at', 'clusters')}
    return '\n'.join((END_DOMAIN, json.dumps(body, sort_keys=True,
                                             separators=(',', ':')))).encode()


def sign_end(member, base, epoch, clusters):
    """This instance's signed word that it carried on alone without `member`, made at the
    view (base digest, epoch) the two held, keeping `clusters`."""
    end = {'by': instance_id(), 'member': member, 'base': base, 'epoch': int(epoch),
           'at': int(time.time()), 'clusters': sorted(clusters)}
    end['sig'] = base64.b64encode(signing_key().sign(_end_message(end))).decode()
    return end


def valid_end(end, iid):
    """Whether `end` is the signed word of member `iid`, the other site of the view of two
    held here, that it carried on alone without this instance, made at this very view."""
    if not isinstance(end, dict) or end.get('by') != iid or end.get('member') != instance_id():
        return False
    clusters, epoch, at, sig = (end.get(k) for k in ('clusters', 'epoch', 'at', 'sig'))
    if not (isinstance(clusters, list) and len(clusters) <= MAX_END_CLUSTERS
            and all(isinstance(c, str) and CLUSTER_ID_RE.fullmatch(c) for c in clusters)):
        return False
    if any(isinstance(v, bool) or not isinstance(v, int) for v in (epoch, at)):
        return False
    if not isinstance(sig, str) or len(sig) > 200:
        return False
    if iid not in members() or len(view_ids()) != 2 or end.get('base') != view_digest() \
            or epoch != view_epoch():
        # the same two sites paired again hold the same digest. The survivor drops the
        # record at the new pairing, and the epoch tells most of the views apart as well
        return False
    key = ha_wire.public_key((member_record(iid) or {}).get('public_key'))
    if key is None:
        return False
    try:
        key.verify(base64.b64decode(sig, validate=True), _end_message(end))
    except Exception:
        return False
    return True


def end_for(iid):
    """The end record this instance keeps for a site it removed as gone for good."""
    return ((((identity() or {}).get('ended') or {}).get(iid)) or {}).get('end')


def note_end_told(iid):
    """The removed site said it took its end record and stopped the clusters it names
    (END_TAKEN_PATH): noted once. Being answered with the record is not enough - the
    answer can be lost, or the record refused there."""
    rec = ((identity() or {}).get('ended') or {}).get(iid)
    if not rec or rec.get('told_at'):
        return

    def go(ident):
        held = (ident.get('ended') or {}).get(iid)
        if not held or held.get('told_at'):
            return False
        held['told_at'] = int(time.time())
        return True
    try:
        _mutate_identity(go)
    except Exception as e:
        logging.warning(f'[FED] could not note that {iid} was told of the end: {e}')


def _remove_gone(iid, by, drop_clusters):
    """Remove the other site of a federation of two as gone for good, alone. Refused on a
    standby, with three or more sites, in the hold or the settle span, while that site was
    heard from lately or answers now, and while it leads clusters here that were not taken
    over, unless `drop_clusters` drops their copies. This instance is a federation of one
    afterwards: its enrolled clusters are its own again."""
    from pegaprox.core import federation_lease as fl
    if _ha_standby() or not _ha_active():
        raise FederationError('This instance is not the acting host of its HA group - ask its '
                              'active', code='FED_STANDBY')
    if iid not in members():
        raise FederationError('No such member of this federation', code='FED_NOT_MEMBER')
    if len(view_ids()) != 2:
        raise FederationError('With three or more sites a removal goes by majority: remove it '
                              'without "gone for good"', code='FED_NOT_TWO_SITES')
    rec = member_record(iid)
    site = rec.get('site') or iid[:8]
    hold, settle = fl.hold_left(), fl.settle_left()
    if hold > 0:
        raise FederationError(f'This host restarted or took over in its HA group and votes '
                              f'again in {int(math.ceil(hold))} s', code='FED_HOLD',
                              retry_after=int(math.ceil(hold)))
    if settle > 0:
        raise FederationError(f'The member list changed a moment ago; try again in '
                              f'{int(math.ceil(settle))} s', code='FED_SETTLING',
                              retry_after=int(math.ceil(settle)))
    wait = fl.takeover_wait(iid)
    if wait > 0:
        raise FederationError(f'{site} was in contact a moment ago; try again in {wait} s',
                              code='FED_PEER_RECENT',
                              retry_after=wait, member=iid)
    if call_peer(iid, 'GET', STATUS_PATH, read_timeout=5)[0]:
        raise FederationError(f'{site} answers right now: remove it with its agreement, '
                              'without "gone for good"', code='FED_PEER_ANSWERS', member=iid)
    me = instance_id()
    conn = _db().conn
    try:
        theirs = [r['id'] for r in conn.execute(
            'SELECT id FROM clusters WHERE fed_owner = ? ORDER BY id', (iid,)).fetchall()]
        led = [r['id'] for r in conn.execute(
            'SELECT id FROM clusters WHERE fed_owner = ? ORDER BY id', (me,)).fetchall()]
    except Exception as e:
        raise FederationError(f'The clusters table cannot be read: {e}')
    if theirs and not drop_clusters:
        raise FederationError(f'{site} still leads clusters here that were not taken over: '
                              f'{", ".join(theirs[:20])}. Take them over first, or confirm '
                              'that their copies are dropped here', code='FED_GONE_CLUSTERS',
                              clusters=theirs)
    if len(led) > MAX_END_CLUSTERS:
        raise FederationError(f'This instance leads more than {MAX_END_CLUSTERS} clusters; an '
                              'end record cannot name them all', code='FED_FULL')
    base = view_digest()
    end = sign_end(iid, base, view_epoch(), led)
    with _lock:
        _begin(conn)
        try:
            ident = _read_identity_row(conn) or _blank_identity()
            if _digest(_view_entries(ident)) != base or iid not in ident['view']['members']:
                raise FederationError('The federation changed meanwhile - try again',
                                      code='FED_VIEW')
            view = ident['view']
            _tombstone(ident, iid, view['members'].pop(iid), by)
            view['epoch'] = int(view.get('epoch') or 0) + 1
            ident.setdefault('peer_keys', {}).pop(iid, None)
            ident['view_prev'] = None
            ident['commits'] = []
            ended = ident.setdefault('ended', {})
            ended[iid] = {'public_key': rec.get('public_key') or '', 'url': rec.get('url') or '',
                          'site': rec.get('site') or '', 'at': int(time.time()), 'end': end,
                          'told_at': 0}
            while len(ended) > 2 * MAX_SITES:
                ended.pop(min(ended, key=lambda k: _age(ended[k], 'at')))
            conn.execute('INSERT OR REPLACE INTO pegaprox_kv (k, v) VALUES (?, ?)',
                         (IDENTITY_KEY, json.dumps(ident, sort_keys=True,
                                                   separators=(',', ':'))))
            # the clusters led here are this instance's own from now on, unfenced: no other
            # site is left that could hold them
            conn.execute("UPDATE clusters SET fed_owner = '' WHERE fed_owner = ?", (me,))
            conn.execute('DELETE FROM pegaprox_kv WHERE k = ?', (OWNERSHIP_KEY,))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            _runtime['identity'] = None
            _runtime['ownership'] = None
            fl.drop_owner_cache()
    _drop_member_data(iid)
    fl.forget_leases(led)
    fl._unmark(*led)
    note_dropped((cid, me) for cid in led)
    fl.note_view_change()
    logging.warning(f'[FED] {iid} removed as gone for good by {by}: this instance carries on '
                    f'alone and keeps {len(led)} cluster(s)')
    return {'removed': iid, 'gone': True, 'kept': led, 'dropped': theirs, 'site': site}


# the sync tick and the lease round both take it, and its call to the other site lets the
# other one in: a second run would find the clusters dropped already and say none were kept
_end_lock = threading.Lock()


def take_end():
    """The removed side of a removal as gone for good: an end record a member answered
    with (_call notes it) is taken once valid_end says it holds. True when this instance
    took one and is out of the federation now. One at a time: a record noted while one is
    taken no longer holds once it is through."""
    with _end_lock:
        noted = _runtime.get('ended_by') or {}
        while noted:
            iid, end = noted.popitem()
            if valid_end(end, iid):
                noted.clear()
                _take_end(iid, end)
                return True
            logging.warning(f'[FED] {iid} answered with an end record that does not hold '
                            'here - ignored')
        return False


def _take_end(iid, end):
    """The other site carried on alone and keeps `end['clusters']`: the ones led here stop
    and go, this instance leaves the federation, and its other enrolled clusters are its
    own again (no site is left that could hold them)."""
    from pegaprox.core import federation_lease as fl
    me = instance_id()
    site = (member_record(iid) or {}).get('site') or iid[:8]
    kept = set(end.get('clusters') or [])
    try:
        led = [r['id'] for r in _db().conn.execute(
            'SELECT id FROM clusters WHERE fed_owner = ? ORDER BY id', (me,)).fetchall()]
    except Exception as e:
        logging.warning(f'[FED] the end record of {iid} waits, the clusters cannot be read: {e}')
        return False
    dropped = [cid for cid in led if cid in kept]
    fl.drop_kept(dropped, iid)
    # while it is still a member here: until this arrives the other site warns before it
    # is switched off, as it could tell this instance nothing more then
    status = call_peer(iid, 'POST', END_TAKEN_PATH, {'sig': end.get('sig')}, read_timeout=5)[0]
    if status != 200:
        logging.warning(f'[FED] {site} was not told that this instance took its end record '
                        f'({status or "no answer"})')
    _wipe_membership('ended')
    fl._finish_unenroll([cid for cid in led if cid not in kept])

    def go(ident):
        ident['removed'] = {'by': iid, 'at': int(time.time()), 'ended': True,
                            'site': site, 'clusters': dropped}
        return True
    _mutate_identity(go)
    when = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(end.get('at') or 0))
    logging.warning(f'[FED] {site} carried on alone and keeps {len(kept)} cluster(s): this '
                    'instance left the federation')
    try:
        from pegaprox.utils.audit import log_audit
        log_audit('system', 'federation.ended_by_other_site',
                  f'{site} carried on alone on {when} and keeps '
                  f'{", ".join(dropped) or "none of the clusters led here"}: this instance '
                  'stopped writing to them and left the federation; its other enrolled '
                  'clusters are its own again', ip_address='federation')
    except Exception as e:
        logging.warning(f'[FED] the end of the federation could not be audited: {e}')
    return True


def _defer_drop(iid, epoch):
    """A removal this instance took from another member (view `epoch`): the member is out
    of the view, its mirrored accounts are disabled here and their sessions end now. The
    accounts, mappings, grants, cluster rows and key stay until a majority shows it took
    the change (_settle_drops): dropped for a change that is rolled back, the mappings,
    grants and favorites would not come back with the next pull. Its sync state goes, so
    after a rollback that next pull is a whole one and brings the accounts back as the
    home has them."""
    def go(ident):
        ident.setdefault('drop_pending', {})[iid] = {'epoch': int(epoch),
                                                    'at': int(time.time())}
        return True
    _mutate_identity(go)
    names = []
    try:
        conn = _identities_conn()
        names = [r['username'] for r in conn.execute(
            'SELECT username FROM users WHERE fed_home = ?', (iid,)).fetchall()]
        conn.execute('UPDATE users SET enabled = 0 WHERE fed_home = ?', (iid,))
        conn.execute('DELETE FROM federation_sync_state WHERE peer = ?', (iid,))
        conn.commit()
    except Exception as e:
        logging.warning(f'[FED] could not disable the accounts of {iid}: {e}')
    for name in names:
        _end_sessions_of(name)
    _runtime['seen'].pop(iid, None)
    _runtime['self_pushed'].pop(iid, None)


def _drops_pending():
    """Members whose removal waits for a majority (_defer_drop). Their data stays until
    _settle_drops, so the orphan sweeps leave it as well."""
    return set((identity() or {}).get('drop_pending') or {})


def _settle_drops(upto):
    """Pending removals (_defer_drop) whose change a majority took - made at view `upto`
    or before - drop what this instance holds of the member. A member that is in the view
    again (its removal was rolled back) keeps everything. Never raises."""
    try:
        pending = (identity() or {}).get('drop_pending') or {}
        if not pending:
            return
        view = members()
        back = [iid for iid in pending if iid in view]
        done = [iid for iid, rec in pending.items() if iid not in view
                and int((rec or {}).get('epoch') or 0) <= int(upto)]
        if not back and not done:
            return
        for iid in done:
            _drop_member_data(iid)

        def go(ident):
            held = ident.setdefault('drop_pending', {})
            for iid in back + done:
                held.pop(iid, None)
            return True
        _mutate_identity(go)
    except Exception as e:
        logging.warning(f'[FED] the data of removed members could not be settled: {e}')


def _drop_member_data(iid):
    """What this instance holds of a member that is out: its mirrored accounts, its
    cluster rows, its field key. The promises given to it stay: they run out by themselves,
    and dropping a live one could let another candidate in while the removed holder may
    still write for the rest of its lease."""
    try:
        drop_mirror_rows(iid)
    except Exception as e:
        logging.warning(f'[FED] could not drop the account mirrors of {iid}: {e}')
    dropped = []
    try:
        conn = _db().conn
        dropped = [r['id'] for r in conn.execute(
            'SELECT id FROM clusters WHERE fed_owner = ?', (iid,)).fetchall()]
        conn.execute('DELETE FROM clusters WHERE fed_owner = ?', (iid,))
        conn.execute('DELETE FROM federation_sync_state WHERE peer = ?', (iid,))
        conn.commit()
    except Exception as e:
        logging.warning(f'[FED] could not drop the cluster mirrors of {iid}: {e}')
    # the ids stay on record with the member that led them (federation_lease.cast_votes)
    note_dropped((cid, iid) for cid in dropped)

    def go(ident):
        return ident.setdefault('peer_keys', {}).pop(iid, None) is not None
    try:
        _mutate_identity(go)
    except Exception as e:
        logging.warning(f'[FED] could not drop the field key of {iid}: {e}')

    def records(own):
        # its clusters went with it; a record it signed is nobody's word any more
        gone = [cid for cid, r in own['records'].items() if r.get('owner') == iid]
        for cid in gone:
            del own['records'][cid]
        echoed = own['acked'].pop(iid, None) is not None
        return bool(gone) or echoed
    try:
        _mutate_ownership(records)
    except Exception as e:
        logging.warning(f'[FED] could not drop the ownership records of {iid}: {e}')
    _runtime['fkeys'].pop(iid, None)
    _runtime['seen'].pop(iid, None)
    _runtime['removed_by'].pop(iid, None)
    _runtime.setdefault('ended_by', {}).pop(iid, None)
    _runtime['self_pushed'].pop(iid, None)
    _runtime.setdefault('peer_views', {}).pop(iid, None)
    from pegaprox.core import federation_lease as fl
    fl.drop_owner_cache()


def _wipe_membership(reason):
    """Forget every member and everything mirrored of them. Rows this instance still has
    enrolled stay enrolled, closed and released: a view of one holds no lease, and no
    later round reopens them on its own - the federation may have adopted them meanwhile.
    Only an unenroll with force (or an enroll, once paired again) does; pairing is refused
    while they are there (_refuse_pairing_with_old_rows)."""
    pending = set(((identity() or {}).get('drop_pending') or {}))
    for iid in sorted(set(members()) | pending):
        _drop_member_data(iid)

    def go(ident):
        ident['view'] = {'epoch': 0, 'members': {}}
        ident['tombstones'] = {}
        ident['peer_keys'] = {}
        ident['commits'] = []
        ident['view_prev'] = None
        ident['handed_over'] = {}
        ident['adopted'] = {}
        ident['drop_pending'] = {}
        return True
    _mutate_identity(go)
    _reset_ownership()
    me = instance_id()
    try:
        enrolled = {r['id'] for r in _db().conn.execute(
            'SELECT id FROM clusters WHERE fed_owner = ?', (me,)).fetchall()}
    except Exception:
        enrolled = set()

    def leases(st):
        st['promises'] = {}
        held = st['my_leases']
        st['my_leases'] = {cid: dict(held.get(cid) or {}, expires=0, released=True,
                                     rseq=int((held.get(cid) or {}).get('rseq') or 0) + 1)
                           for cid in enrolled}
        st['pairing'] = None
        st['pairing_spent'] = None
        return True
    _mutate_leases(leases)
    from pegaprox.core import federation_lease as fl
    fl.drop_owner_cache()
    logging.info(f'[FED] membership wiped ({reason})')


def _become_removed(by):
    """The others removed this instance: forget them, note who said it."""
    _wipe_membership('removed')

    def go(ident):
        ident['removed'] = {'by': str(by)[:64], 'at': int(time.time())}
        return True
    _mutate_identity(go)
    logging.warning(f'[FED] this instance was removed from the federation (told by {by})')
    try:
        from pegaprox.utils.audit import log_audit
        log_audit('system', 'federation.removed',
                  f'this instance was removed from the federation, told by {by}',
                  ip_address='federation')
    except Exception as e:
        logging.warning(f'[FED] the removal could not be audited: {e}')


def removed_by_some():
    """Members that answered 410 to this instance lately, the view's own only."""
    view = set(members())
    return sorted(iid for iid in _runtime['removed_by'] if iid in view)


def _check_removed_by():
    """A majority of the view says this instance was removed: it lets go."""
    said = removed_by_some()
    if said and len(said) >= needed(len(view_ids())):
        _become_removed(by=said[0])
        return True
    return False


def leave(force=False):
    """Leave the federation. Every enrolled row with a live lease is unenrolled first, all
    of them in one notice and one release per member; a row without one blocks the leave
    unless forced (it stays enrolled and closed). The removal of this instance takes a
    majority like any other; forced, a leave without one goes ahead locally. Returns
    {'left': True, 'not_told': [ids]}."""
    with _one_change():
        return _leave(force)


def _leave(force):
    from pegaprox.core import federation_lease as fl
    me = instance_id()
    try:
        own = [r['id'] for r in _db().conn.execute(
            'SELECT id FROM clusters WHERE fed_owner = ? ORDER BY id', (me,)).fetchall()] if me else []
    except Exception as e:
        raise FederationError(f'The clusters table cannot be read: {e}')
    try:
        _done, blocked = fl.unenroll_clusters(own)
    except FederationError as e:
        logging.warning(f'[FED] unenrolling before the leave failed: {e}')
        try:
            blocked = own_enrolled_ids()
        except FederationError:
            blocked = list(own)
    if blocked and not force:
        raise FederationError('These clusters are enrolled without a live lease here, so '
                              'they cannot be unenrolled cleanly: '
                              f'{", ".join(blocked)}. Leave with force to keep them enrolled '
                              'and closed, then unenroll them with force',
                              code='FED_LEAVE_BLOCKED', clusters=blocked)
    not_told = []
    if members():
        try:
            not_told = _view_change({'op': 'remove', 'instance_id': me}, by='left')['not_told']
        except FederationError as e:
            if e.code != 'FED_NO_QUORUM' or not force:
                raise
            not_told = sorted(members())
    _wipe_membership('left')

    def go(ident):
        if ident.get('removed') is None:
            return False
        ident['removed'] = None
        return True
    _mutate_identity(go)
    return {'left': True, 'not_told': not_told}


def apply_member_update(sender, body):
    """A member's word about its own record: its address, site label and fingerprints.
    Not part of the view digest, no lock: nobody else's record moves with it."""
    if not isinstance(body, dict):
        raise FederationError('That is no member record', code='FED_BAD_CHANGE')
    old = member_record(sender)
    if old is None:
        raise FederationError('Not a member', code='FED_NOT_MEMBER')
    rec = _member_record(sender, {'url': body.get('url'), 'public_key': old['public_key'],
                                  'site': body.get('site'),
                                  'fingerprints': body.get('fingerprints')})
    if rec is None:
        raise FederationError('That member record is not usable', code='FED_BAD_CHANGE')

    def go(ident):
        held = ident['view']['members'].get(sender)
        if held is None:
            return False
        new = dict(held, url=rec['url'], site=rec['site'] or held.get('site') or '',
                   fingerprints=rec['fingerprints'])
        if new == held:
            return False
        ident['view']['members'][sender] = new
        return True
    _mutate_identity(go)
    return {'updated': True}


def _push_self_update():
    """Tell the members when this instance's address, site or certificate changed (a
    renewed self-signed certificate keeps the federation reachable)."""
    fps = own_fingerprints()
    ident = identity() or {}
    if fps and fps != (ident.get('self') or {}).get('fingerprints'):
        _set_self(fingerprints=fps)
        ident = identity() or {}
    me_rec = {'url': own_url(), 'site': own_site(),
              'fingerprints': list((ident.get('self') or {}).get('fingerprints') or [])}
    if not me_rec['url']:
        return
    mark = hashlib.sha256(json.dumps(me_rec, sort_keys=True).encode()).hexdigest()
    due = [iid for iid in sorted(members()) if _runtime['self_pushed'].get(iid) != mark]
    for iid, ans in zip(due, _parallel(
            lambda i: call_peer(i, 'POST', MEMBER_UPDATE_PATH, me_rec, read_timeout=5), due)):
        if ans and ans[0] == 200:
            _runtime['self_pushed'][iid] = mark


def forget_inherited(reason):
    """This host held its HA group's federation identity as a standby (the sync carried
    it) and has left the group. Standalone it would act as that same member next to the
    active: lease the member's clusters as well, push its own certificate as the member's,
    leave in the member's name. So what it inherited goes: the switch goes off here, the
    identity row, the cluster rows the federation owns or mirrors, the mirrored accounts,
    the mappings, the sync state and the lease file. The member itself, the active, keeps
    all of it.

    It runs whenever the identity row is there, with the switch off as well (the one thing
    of the federation that does): switched on later, the host would be that member again.
    Without the row it touches nothing. Returns True when there was an identity to forget.
    Never raises; a failure is logged and leaves the federation off here until a later
    drop goes through (_forget_pending, retry_forget at the start)."""
    try:
        conn = _db().conn
        try:
            had = conn.execute('SELECT 1 FROM pegaprox_kv WHERE k = ?',
                               (IDENTITY_KEY,)).fetchone() is not None
        except Exception as e:
            # a row that cannot be looked for may be there: dropping is the safe side
            had = 'no such table' not in str(e)
        if not had:
            _set_forget_mark(False)
            return False
        # off here until the drop went through, PEGAPROX_FEDERATION=1 included: a drop that
        # fails half way leaves the member's identity on a host that no longer is it
        _set_forget_mark(True)
        _drop_inherited(conn)
        _set_forget_mark(False)
    except Exception as e:
        logging.error(f'[FED] the federation identity this host held could not be dropped '
                      f'({reason}); the federation stays off here and the drop is tried '
                      f'again at the next start: {e}')
        return False
    logging.warning(f'[FED] the federation identity this host held is gone ({reason}); '
                    'the federation is switched off here')
    try:
        from pegaprox.utils.audit import log_audit
        log_audit('system', 'federation.identity_dropped',
                  f'the federation identity this host held as an HA standby was dropped '
                  f'({reason})', ip_address='federation')
    except Exception as e:
        logging.warning(f'[FED] dropping the inherited identity could not be audited: {e}')
    return True


def _drop_inherited(conn):
    stop_workers()
    db = _db()
    db.save_server_setting(SETTING_KEY, False)
    _runtime['switch'] = (False, time.monotonic())
    _runtime['switch_held'] = False
    homes = set()
    for table in IDENTITY_TABLES:
        try:
            homes |= {r[0] for r in conn.execute(
                f'SELECT DISTINCT fed_home FROM "{table}" WHERE fed_home != \'\'').fetchall()}
        except Exception as e:
            if 'no such table' not in str(e):
                raise
    for home in sorted(h for h in homes if h):
        drop_mirror_rows(home)
    conn.execute("DELETE FROM clusters WHERE fed_owner != ''")
    for table in ('federation_identity_map', 'federation_sync_state'):
        try:
            conn.execute(f'DELETE FROM {table}')
        except Exception as e:
            if 'no such table' not in str(e):
                raise
    conn.execute('DELETE FROM pegaprox_kv WHERE k IN (?, ?)', (IDENTITY_KEY, OWNERSHIP_KEY))
    conn.commit()
    try:
        os.unlink(_runtime['lease_file'])
    except FileNotFoundError:
        pass
    for key in ('identity', 'leases', 'owners', 'signer', 'clusters_body', 'ownership'):
        _runtime[key] = None
    _runtime['fkeys'] = {}


# --- federation field keys -----------------------------------------------------------------
#
# MK Nov 2026 - pairing never hands over the database key. Each member draws its own
# 32-byte federation field key; the credential columns of the cluster rows it mirrors to
# the others travel wrapped under it ('fedk1:'), deterministic AES-GCM with the owner, the
# cluster and the column as associated data. Equal input gives equal output, so the
# snapshot etag stays put and no nonce ever repeats for a different value. A member
# fetches the others' keys over a signed call; a removed member's key is deleted with its
# mirrors.
FIELD_PREFIX = 'fedk1:'


def _key_from_ct(ct, slot):
    held = _runtime['fkeys'].get(slot)
    if held is not None and held[0] == ct:
        return held[1]
    raw = base64.b64decode(_db()._decrypt(ct), validate=True)
    if len(raw) != 32:
        raise ValueError('a federation field key is 32 bytes')
    _runtime['fkeys'][slot] = (ct, raw)
    return raw


def _own_field_key():
    ident = identity() or {}
    ct = ident.get('field_key') or ''
    if not ct:
        raise FederationError('This instance has no federation field key yet',
                              code='FED_NO_KEY')
    try:
        return _key_from_ct(ct, ''), ident.get('field_key_id') or ''
    except Exception as e:
        raise FederationError(f'The federation field key cannot be opened: {e}',
                              code='FED_NO_KEY')


def _peer_key(iid):
    """(raw key, key id) of member `iid`'s field key, None when this instance holds none."""
    held = ((identity() or {}).get('peer_keys') or {}).get(iid)
    if not held or not held.get('key'):
        return None
    try:
        return _key_from_ct(held['key'], iid), held.get('key_id') or ''
    except Exception as e:
        _say_once(('peer-key', iid), f'[FED] the field key of {iid} cannot be opened: {e}')
        return None


def _aad(owner, cluster_id, column):
    return b'pegaprox-fed-cred-1\n' + f'{owner}\n{cluster_id}\n{column}'.encode()


def wrap_credential(plain, cluster_id, column):
    """A credential of one of this instance's enrolled clusters, wrapped for the mirrors."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw, kid = _own_field_key()
    aad = _aad(instance_id(), cluster_id, column)
    data = (plain or '').encode()
    nonce = hmac.new(raw, b'nonce\n' + aad + b'\n' + data, hashlib.sha256).digest()[:12]
    ct = AESGCM(raw).encrypt(nonce, data, aad)
    return f'{FIELD_PREFIX}{kid}:{base64.b64encode(nonce + ct).decode()}'


def unwrap_credential(value, owner, cluster_id, column):
    """The plain credential of a mirror value `owner` wrapped. Raises FederationError on a
    key this instance does not hold, a key id that does not match, or a failed tag."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not isinstance(value, str) or not value.startswith(FIELD_PREFIX):
        raise FederationError('That value is not wrapped under a federation field key')
    kid, _, blob = value[len(FIELD_PREFIX):].partition(':')
    key = _peer_key(owner)
    if key is None:
        raise FederationError(f'The field key of {owner} is not held here', code='FED_NO_KEY')
    raw, held_kid = key
    if kid != held_kid:
        raise FederationError(f'The value was wrapped under another field key of {owner} '
                              'than the one held here', code='FED_NO_KEY')
    try:
        data = base64.b64decode(blob, validate=True)
        return AESGCM(raw).decrypt(data[:12], data[12:],
                                   _aad(owner, cluster_id, column)).decode()
    except Exception as e:
        raise FederationError(f'The wrapped value did not open: {type(e).__name__}')


def field_key_body():
    """What /peer/field-key answers: this instance's own federation field key."""
    raw, kid = _own_field_key()
    return {'instance_id': instance_id(), 'key_id': kid,
            'field_key': base64.b64encode(raw).decode()}


def fetch_field_keys(statuses=None):
    """Fetch the field key of every member this instance holds none of, or one whose key id
    differs from what its status reported. Returns the ids fetched."""
    held = (identity() or {}).get('peer_keys') or {}
    statuses = statuses if statuses is not None else _runtime.get('statuses') or {}
    due = [iid for iid in sorted(members())
           if iid not in held or (statuses.get(iid) and held[iid].get('key_id') != statuses[iid])]
    got = {}
    for iid, ans in zip(due, _parallel(
            lambda i: call_peer(i, 'GET', FIELD_KEY_PATH, read_timeout=5), due)):
        status, body, _h = ans or (0, None, {})
        if status != 200 or not isinstance(body, dict) or body.get('instance_id') != iid:
            continue
        try:
            raw = base64.b64decode(body.get('field_key') or '', validate=True)
        except Exception:
            continue
        kid = hashlib.sha256(raw).hexdigest()[:8]
        if len(raw) != 32 or body.get('key_id') != kid:
            continue
        got[iid] = {'key': _db()._encrypt(base64.b64encode(raw).decode()), 'key_id': kid}
    if got:
        def go(ident):
            view = ident['view']['members']
            keys = ident.setdefault('peer_keys', {})
            changed = False
            for iid, rec in got.items():
                if iid in view and keys.get(iid, {}).get('key_id') != rec['key_id']:
                    keys[iid] = rec
                    changed = True
            return changed
        _mutate_identity(go)
    return sorted(got)


# --- identity federation -------------------------------------------------------------------
#
# What travels between the members: the users, their API tokens and their passkeys, each row
# saying which instance it is homed at. A row homed at A is a mirror on B and C: the login
# stack reads it like a local row (the password hash and the token hashes travel, so a token
# drawn at A works at B and C), but only the home writes it. Every snapshot is the whole set
# of rows homed at its sender, so a row the snapshot no longer lists is gone at the home and
# goes here too.
#
# Tenants and roles do not travel, and nothing a home names resolves by name here: a tenant
# id or a custom role name reaches a local one only through a mapping an admin of this
# instance made (federation_identity_map). A mirror whose tenant or role is not mapped is
# stored quarantined - disabled, in a tenant nobody holds, with a role that grants nothing -
# until it is. The builtin roles (admin, user, viewer) are code and pass by name.
#
# The columns are an allowlist: what a user is and may do travels, the workbench (theme,
# layout, avatar, last_login, a pending TOTP enrolment) stays where it is set, and nothing a
# directory or an identity provider derived travels at all.

IDENTITY_TABLES = ('users', 'api_tokens', 'webauthn_credentials')
IDENTITY_KIND = {'users': 'user', 'api_tokens': 'token', 'webauthn_credentials': 'passkey'}
# a security key is identity too: without it a key-only account signs in at a mirror on the
# password alone. The credentials travel as base64 (the columns are BLOBs).
BLOB_COLUMNS = {'webauthn_credentials': ('credential_id', 'public_key', 'user_handle')}
JSON_COLUMNS = {'permissions', 'tenant_permissions', 'denied_permissions'}
FLAG_COLUMNS = {'totp_enabled', 'enabled', 'portal_only', 'force_password_change', 'revoked'}
IDENTITY_COLUMNS = {
    'users': ('username', 'password_salt', 'password_hash', 'role', 'permissions',
              'tenant', 'created_at', 'password_expiry', 'totp_enabled', 'enabled',
              'auth_source', 'display_name', 'email', 'tenant_permissions',
              'denied_permissions', 'portal_only', 'force_password_change'),
    'api_tokens': ('token_hash', 'token_prefix', 'username', 'name', 'role',
                   'permissions', 'expires_at', 'created_at', 'revoked'),
    'webauthn_credentials': ('username', 'credential_id', 'public_key', 'transports',
                             'aaguid', 'name', 'user_handle', 'created_at'),
}
IDENTITY_KEYS = {'users': ('username',), 'api_tokens': ('token_hash',),
                 'webauthn_credentials': ('credential_id',)}
# Columns a mirror writes empty however the row comes. A TOTP secret is sealed under the
# home's database key and no other instance can open it; totp_enabled still travels, and the
# login sends such an account to its home unless a passkey can stand in.
PER_TABLE_CLEAR = {'users': ('totp_secret_encrypted',)}

# the tenant and the role a quarantined mirror is stored with. A tenant id the app makes
# never holds a colon, so no tenant of this instance is ever this one
QUARANTINE = 'fed:unmapped'
MAP_KINDS = ('tenant', 'role')
# the mapping table holds what the homes actually use, and no more than this per home: an
# unmapped value past it gets no row, and the accounts naming it stay quarantined
MAX_MAP_ROWS = 256
MAX_MAP_VALUE = 128
# routine audit entries one apply writes before it sums the rest up in one more
AUDIT_ROUTINE_CAP = 50
# conflict lines one report carries; past it they are counted
MAX_REPORT_CONFLICTS = 100


def _identities_conn():
    from pegaprox.core.db import get_db
    return get_db().conn


def identity_rows(table, home=None):
    """The rows of `table` homed at `home` (this instance when left out), as dicts of the
    columns that travel. Raises FederationError when the table cannot be read: an empty
    list would read as "the home holds nothing", and the puller's diff would delete every
    mirror it keeps of it."""
    if table not in IDENTITY_TABLES:
        return []
    cols = ', '.join(f'"{c}"' for c in IDENTITY_COLUMNS[table])
    keys = IDENTITY_KEYS[table]
    order = ', '.join(f'COALESCE("{k}", \'\')' for k in keys)
    sql = f'SELECT {cols} FROM "{table}" WHERE fed_home = ? ORDER BY {order}'
    try:
        cur = _identities_conn().execute(sql, (home if home is not None else '',))
    except Exception as e:
        raise FederationError(f'The {table} table cannot be read for the snapshot: {e}')
    blobs = BLOB_COLUMNS.get(table) or ()
    out = []
    for r in cur.fetchall():
        row = dict(r)
        for c in blobs:
            if isinstance(row.get(c), (bytes, bytearray, memoryview)):
                row[c] = base64.b64encode(bytes(row[c])).decode()
        out.append(row)
    return out


def identity_snapshot_body():
    """What /peer/identities answers: the rows homed here, the clusters led here and every
    ownership record this instance holds, with the etag over all of it. Nothing homed at a
    peer is served - a member answers for itself alone. The records ride along so a site
    that lost one (an HA failover before the sync carried it) gets it back; the puller
    takes them before the cluster rows (_pull_identities)."""
    body = {'home': instance_id(), 'fed': FED_MARK, 'etag': '', 'rows': {}}
    canon = ''
    for table in IDENTITY_TABLES:
        rows = identity_rows(table)
        body['rows'][table] = rows
        canon += json.dumps(rows, separators=(',', ':'), sort_keys=True)
    c_rows, c_canon = _cluster_mirror_body()
    body['clusters'] = c_rows
    records = [wire_record(r) for _cid, r in sorted((ownership().get('records') or {}).items())]
    body['records'] = records
    r_canon = json.dumps(records, separators=(',', ':'), sort_keys=True)
    body['etag'] = hashlib.sha256((canon + c_canon + r_canon).encode()).hexdigest()
    return body


def _key_where(keys):
    """The WHERE of a table's key columns, NULL read as ''."""
    return ' AND '.join(f'COALESCE("{k}", \'\') = COALESCE(?, \'\')' for k in keys)


def _key_of(row, keys):
    """The key values of an incoming row, or None when the row is no identity (a missing,
    empty or non-string key)."""
    vals = tuple('' if row.get(k) is None else row.get(k) for k in keys)
    if not all(isinstance(v, str) for v in vals) or not vals[0]:
        return None
    return vals


def _wire_key(raw):
    return tuple(base64.b64encode(bytes(v)).decode()
                 if isinstance(v, (bytes, bytearray, memoryview)) else v for v in raw)


def _held_rows(conn, table, keys, incoming):
    """The rows `table` already holds at an incoming snapshot's keys, keyed by the wire key:
    every column that travels, the cleared ones and fed_home, so the apply can tell an
    unchanged row from a changed one. One SELECT per chunk of keys, not one per row."""
    blobs = BLOB_COLUMNS.get(table) or ()
    want = {}
    for row in incoming:
        if not isinstance(row, dict):
            continue
        kv = _key_of(row, keys)
        if kv is None:
            continue
        try:
            want[kv] = tuple(base64.b64decode(v, validate=True) for v in kv) if blobs else kv
        except Exception:
            continue
    if not want:
        return {}
    cols = [c for c in IDENTITY_COLUMNS[table] if c not in keys]
    cols += list(PER_TABLE_CLEAR.get(table) or ())
    sel = ', '.join(f'"{c}"' for c in (*keys, *cols, 'fed_home'))
    # SQLite bounds the parameters of one statement, so the asks go in chunks
    chunk = max(1, 400 // len(keys))
    out = {}
    items = list(want.items())
    for i in range(0, len(items), chunk):
        part = items[i:i + chunk]
        where = ' OR '.join(f'({_key_where(keys)})' for _ in part)
        params = [v for _, sql_keys in part for v in sql_keys]
        for r in conn.execute(f'SELECT {sel} FROM "{table}" WHERE {where}', params).fetchall():
            wire = _wire_key(tuple('' if r[k] is None else r[k] for k in keys))
            if wire in want:
                out[wire] = dict(r)
    return out


def _comparable(values):
    """Values as the table holds them, for the compare: flags as 0/1, NULL as '', blobs as
    bytes."""
    out = {}
    for c, v in values.items():
        if c in FLAG_COLUMNS:
            v = 1 if v else 0
        elif v is None:
            v = ''
        elif isinstance(v, (bytearray, memoryview)):
            v = bytes(v)
        out[c] = v
    return out


def _plain_json(value):
    """Whether `value` is the string of a JSON array or object, or empty - what the JSON
    columns of the identity tables hold."""
    if not isinstance(value, str) or not value:
        return value is None or value == ''
    try:
        return isinstance(json.loads(value), (list, dict))
    except Exception:
        return False


def _json_of(value, kind):
    try:
        got = json.loads(value) if isinstance(value, str) and value else kind()
    except Exception:
        return kind()
    return got if isinstance(got, kind) else kind()


def _conflict(report, text):
    if len(report['conflicts']) < MAX_REPORT_CONFLICTS:
        report['conflicts'].append(text)
    else:
        report['conflicts_more'] = report.get('conflicts_more', 0) + 1


def _label(table, row):
    """How an audit entry names a row: never a hash, and short."""
    user = str(row.get('username') or '')[:64]
    if table == 'users':
        return f'user "{user}"'
    if table == 'api_tokens':
        return f'token "{str(row.get("name") or row.get("token_prefix") or "")[:64]}" of "{user}"'
    return f'passkey "{str(row.get("name") or "")[:64]}" of "{user}"'


# --- tenants and roles: an explicit mapping, quarantine until mapped -------------------------

def _map_rows(conn, home):
    """{(kind, home_value): (local_value, users)} of `home`. Raises FederationError when the
    table cannot be read: the apply then refuses the snapshot, nothing widens on a failed
    read."""
    try:
        rows = conn.execute('SELECT kind, home_value, local_value, users FROM '
                            'federation_identity_map WHERE home = ?', (home,)).fetchall()
    except Exception as e:
        raise FederationError(f'The identity mapping cannot be read: {e}')
    return {(r['kind'], r['home_value']): (r['local_value'] or '', int(r['users'] or 0))
            for r in rows}


def identity_map(home):
    """{(kind, home_value): local_value} of `home`; '' is a value nobody mapped yet."""
    return {k: v[0] for k, v in _map_rows(_identities_conn(), home).items()}


def _local_scope(conn):
    """(tenant ids, {custom role: tenant ids it is defined for, '' for global}) of this
    instance. The default tenant always counts. Raises FederationError on a failed read."""
    from pegaprox.utils.rbac import DEFAULT_TENANT_ID
    try:
        tenants = {r[0] for r in conn.execute('SELECT id FROM tenants').fetchall() if r[0]}
        roles = {}
        for r in conn.execute("SELECT name, COALESCE(tenant_id, '') FROM custom_roles "
                              "WHERE fed_home = ''").fetchall():
            if r[0]:
                roles.setdefault(r[0], set()).add(r[1] or '')
    except Exception as e:
        raise FederationError(f'The tenants and roles of this instance cannot be read: {e}')
    tenants.add(DEFAULT_TENANT_ID)
    return tenants, roles


def _resolve_role(role, tenant, maps, scope):
    """(local role or None, the (kind, value) the role names or None). A builtin passes; a
    custom role only through its mapping, and only to a role that resolves for `tenant`
    here (a builtin, a global custom role, or one of that tenant's)."""
    from pegaprox.models.permissions import BUILTIN_ROLES
    if role in BUILTIN_ROLES:
        return role, None
    named = ('role', role)
    mapped = maps.get(named, ('', 0))[0]
    if not mapped:
        return None, named
    if mapped in BUILTIN_ROLES:
        return mapped, named
    where = scope[1].get(mapped) or set()
    if '' in where or (tenant and tenant in where):
        return mapped, named
    return None, named


def _resolve_user(row, maps, scope):
    """(patch or None, named, why) for a mirrored user. `patch` holds the local tenant, role
    and tenant overrides when every one of them resolves through the mapping; None means the
    row is stored quarantined, and `why` says what is missing. `named` is every tenant and
    custom role value the row names, mapped or not.

    No override is ever dropped to make a row fit: an override can lower an admin in their
    own tenant, and leaving it out would widen them."""
    from pegaprox.utils.rbac import DEFAULT_TENANT_ID
    tenants = scope[0]
    named, why = set(), []

    def tenant_of(value):
        value = value if isinstance(value, str) and value else DEFAULT_TENANT_ID
        named.add(('tenant', value))
        local = maps.get(('tenant', value), ('', 0))[0]
        return value, (local if local and local in tenants else '')

    t_home, t_local = tenant_of(row.get('tenant'))
    if not t_local:
        why.append(f'tenant "{t_home[:40]}" is not mapped')
    role = row.get('role')
    local_role = None
    if not isinstance(role, str) or not role:
        why.append('it names no role')
    else:
        local_role, n = _resolve_role(role, t_local, maps, scope)
        if n:
            named.add(n)
        if local_role is None:
            why.append(f'role "{role[:40]}" is not mapped for its tenant')
    raw = row.get('tenant_permissions')
    overrides = json.loads(raw) if isinstance(raw, str) and raw else {}
    out_tp = {}
    if not isinstance(overrides, dict):
        why.append('its tenant overrides are unreadable')
        overrides = {}
    for key, ov in overrides.items():
        k_home, k_local = tenant_of(key)
        if not k_local:
            why.append(f'tenant "{k_home[:40]}" of an override is not mapped')
            continue
        if not isinstance(ov, dict):
            why.append('an override is unreadable')
            continue
        ov = dict(ov)
        o_role = ov.get('role')
        if isinstance(o_role, str) and o_role:
            lr, n = _resolve_role(o_role, k_local, maps, scope)
            if n:
                named.add(n)
            if lr is None:
                why.append(f'role "{o_role[:40]}" of an override is not mapped')
                continue
            ov['role'] = lr
        elif o_role is not None:
            why.append('an override names no readable role')
            continue
        if k_local in out_tp and out_tp[k_local] != ov:
            why.append(f'two overrides land on tenant "{k_local[:40]}" here')
            continue
        out_tp[k_local] = ov
    if why:
        return None, named, ', '.join(why)
    return ({'tenant': t_local, 'role': local_role,
             'tenant_permissions': json.dumps(out_tp, sort_keys=True, separators=(',', ':'))},
            named, '')


def _resolve_token_role(role, owner_tenant, maps, scope):
    """(local role or None, named) for a mirrored API token. A token without a role or with
    a builtin one passes; a custom role only through its mapping, for the owner's tenant
    here. None: the token is not mirrored."""
    if not isinstance(role, str) or not role:
        return role, None
    return _resolve_role(role, owner_tenant, maps, scope)


def _quarantined(values):
    return dict(values, tenant=QUARANTINE, role=QUARANTINE, permissions='[]',
                tenant_permissions='{}', enabled=0)


def _note_unmapped(conn, home, held, seen):
    """Bring the mapping rows of `home` in line with what this apply saw, inside its
    transaction: a row for every value seen (local_value '' until an admin maps it), the
    account count where it moved, and the unmapped rows nobody names any more deleted. A
    mapped row is never deleted here - the admin's decision survives a home that drops a
    tenant for a while. Nothing is written when nothing moved: the table rides the HA sync,
    and a needless write would count as a change there.

    The rows nobody names any more go first, so they do not count against MAX_MAP_ROWS:
    a value that replaces one at the cap gets its row in the same apply."""
    rows = len(held)
    for (kind, value), (local, n) in held.items():
        if (kind, value) in seen:
            continue
        if not local:
            conn.execute('DELETE FROM federation_identity_map WHERE home = ? AND kind = ? '
                         'AND home_value = ?', (home, kind, value))
            rows -= 1
        elif n:
            conn.execute('UPDATE federation_identity_map SET users = 0 WHERE home = ? AND '
                         'kind = ? AND home_value = ?', (home, kind, value))
    for (kind, value), n in sorted(seen.items()):
        have = held.get((kind, value))
        if have is None:
            if not isinstance(value, str) or not value or len(value) > MAX_MAP_VALUE:
                continue
            if rows >= MAX_MAP_ROWS:
                _say_once(('map-full', home), f'[FED] the identity mapping of {home[:8]} holds '
                                              f'{MAX_MAP_ROWS} rows - further unmapped values '
                                              f'get none, their accounts stay quarantined')
                continue
            conn.execute('INSERT INTO federation_identity_map (home, kind, home_value, '
                         "local_value, users) VALUES (?, ?, ?, '', ?)", (home, kind, value, n))
            rows += 1
        elif have[1] != n:
            conn.execute('UPDATE federation_identity_map SET users = ? WHERE home = ? AND '
                         'kind = ? AND home_value = ?', (n, home, kind, value))


def _quarantine_mapped(conn, home, kind, old_local):
    """The mirrors of `home` that resolved through a mapping to `old_local`, quarantined at
    once - with the home unreachable too. May catch more than the mapping did (another value
    mapped to the same local one, a builtin role of that name); the re-pull after the change
    puts those back. Returns the usernames, whose sessions end."""
    col = 'tenant' if kind == 'tenant' else 'role'
    pattern = f'"{old_local}"'
    where = (f'fed_home = ? AND ("{col}" = ? OR '
             f"instr(COALESCE(tenant_permissions, ''), ?) > 0)")
    names = [r['username'] for r in conn.execute(
        f'SELECT username FROM users WHERE {where}', (home, old_local, pattern)).fetchall()]
    if names:
        conn.execute(f"UPDATE users SET enabled = 0, tenant = ?, role = ?, permissions = '[]', "
                     f"tenant_permissions = '{{}}' WHERE {where}",
                     (QUARANTINE, QUARANTINE, home, old_local, pattern))
    if kind == 'role':
        # a token resolved through the role the same way; the re-pull brings back what
        # still resolves
        conn.execute('DELETE FROM api_tokens WHERE fed_home = ? AND role = ?', (home, old_local))
    return names


def map_identity(home, kind, home_value, local_value, by):
    """Map a tenant or a role a member's accounts name onto one of this instance ('' takes
    the mapping away). Taking a mapping away or moving it quarantines the accounts that
    resolved through it at once; then the member is pulled again, so every account resolves
    against the new mapping now. Returns {'saved', 'pulled', 'report'}.

    Raises FederationError: FED_NOT_MEMBER, FED_MAP_INVALID, FED_MAP_UNKNOWN (no account of
    that member names the value), or without a code when the tables cannot be read."""
    from pegaprox.models.permissions import BUILTIN_ROLES
    if home not in members():
        raise FederationError('No such member of this federation', code='FED_NOT_MEMBER')
    if kind not in MAP_KINDS or not isinstance(home_value, str) or not home_value \
            or not isinstance(local_value, str) or len(local_value) > MAX_MAP_VALUE:
        raise FederationError('Say which tenant or role to map, and onto what',
                              code='FED_MAP_INVALID')
    conn = _identities_conn()
    names = []
    _begin(conn)
    try:
        row = conn.execute('SELECT local_value FROM federation_identity_map WHERE home = ? '
                           'AND kind = ? AND home_value = ?', (home, kind, home_value)).fetchone()
        if row is None:
            raise FederationError(f'No account of that site names the {kind} "{home_value}"',
                                  code='FED_MAP_UNKNOWN')
        if local_value:
            tenants, roles = _local_scope(conn)
            known = local_value in tenants if kind == 'tenant' \
                else (local_value in BUILTIN_ROLES or local_value in roles)
            if not known:
                raise FederationError(f'This instance has no {kind} "{local_value}"',
                                      code='FED_MAP_INVALID')
        old = row['local_value'] or ''
        if old and old != local_value:
            names = _quarantine_mapped(conn, home, kind, old)
        if old != local_value:
            conn.execute('UPDATE federation_identity_map SET local_value = ?, mapped_by = ?, '
                         'mapped_at = ? WHERE home = ? AND kind = ? AND home_value = ?',
                         (local_value, str(by)[:80] if local_value else '',
                          int(time.time()) if local_value else 0, home, kind, home_value))
        # the etag goes, so the pull below takes the whole snapshot again
        conn.execute('DELETE FROM federation_sync_state WHERE peer = ?', (home,))
        conn.commit()
    except FederationError:
        _rollback(conn)
        raise
    except Exception as e:
        _rollback(conn)
        raise FederationError(f'The identity mapping cannot be written: {e}')
    for name in names:
        _end_sessions_of(name)
    report = pull_identities(home)
    pulled = isinstance(report, dict) and not report.get('failed')
    return {'saved': True, 'pulled': pulled, 'report': report}


def identity_map_view():
    """What the mapping card shows: the entries of every member and what this instance
    offers to map onto."""
    from pegaprox.models.permissions import BUILTIN_ROLES
    conn = _identities_conn()
    roster = members()
    out = {iid: {'site': rec.get('site') or '', 'entries': []}
           for iid, rec in sorted(roster.items())}
    for r in conn.execute('SELECT home, kind, home_value, local_value, users, mapped_by, '
                          'mapped_at FROM federation_identity_map '
                          'ORDER BY home, kind DESC, home_value').fetchall():
        if r['home'] not in out:
            continue
        entry = {'kind': r['kind'], 'home_value': r['home_value'],
                 'local_value': r['local_value'] or '', 'users': int(r['users'] or 0)}
        if entry['local_value']:
            entry['mapped_by'] = r['mapped_by'] or ''
            entry['mapped_at'] = int(r['mapped_at'] or 0)
        out[r['home']]['entries'].append(entry)
    from pegaprox.utils.rbac import DEFAULT_TENANT_ID
    tenants = [{'id': r['id'], 'name': r['name'] or r['id']} for r in conn.execute(
        'SELECT id, name FROM tenants ORDER BY name').fetchall()]
    if not any(t['id'] == DEFAULT_TENANT_ID for t in tenants):
        tenants.insert(0, {'id': DEFAULT_TENANT_ID, 'name': 'Default'})
    custom = sorted({r[0] for r in conn.execute(
        "SELECT name FROM custom_roles WHERE fed_home = ''").fetchall() if r[0]})
    return {'members': out,
            'local': {'tenants': tenants,
                      'roles': list(BUILTIN_ROLES) + [r for r in custom
                                                      if r not in BUILTIN_ROLES]}}


def unmapped_counts():
    """{home: accounts that wait for a mapping} - the sum over each home's unmapped rows."""
    try:
        return {r[0]: int(r[1] or 0) for r in _identities_conn().execute(
            "SELECT home, SUM(users) FROM federation_identity_map WHERE local_value = '' "
            "GROUP BY home").fetchall()}
    except Exception as e:
        logging.warning(f'[FED] could not count the accounts waiting for a mapping: {e}')
        return {}


def _quarantined_count(home):
    try:
        return int(_identities_conn().execute(
            'SELECT COUNT(*) FROM users WHERE fed_home = ? AND tenant = ?',
            (home, QUARANTINE)).fetchone()[0])
    except Exception:
        return 0


# --- the apply -----------------------------------------------------------------------------

def _rollback(conn):
    try:
        conn.rollback()
    except Exception:
        pass


def _access_raised(kind, old, new):
    """Why a change of a resolved row raises what it may do here, '' when it does not.
    `old` None is an insert. A row that leaves quarantine because an admin here mapped it
    is not asked this: the mapping is audited with who made it."""
    why = []
    if kind == 'user':
        if old is None:
            return 'arrived as admin' if new.get('role') == 'admin' else ''
        if new.get('role') == 'admin' and old.get('role') != 'admin':
            why.append('role raised to admin')
        gained = sorted(set(map(str, _json_of(new.get('permissions'), list)))
                        - set(map(str, _json_of(old.get('permissions'), list))))
        if gained:
            more = f' and {len(gained) - 5} more' if len(gained) > 5 else ''
            why.append(f'permissions added: {" ".join(gained[:5])}{more}')
        lifted = sorted(set(map(str, _json_of(old.get('denied_permissions'), list)))
                        - set(map(str, _json_of(new.get('denied_permissions'), list))))
        if lifted:
            more = f' and {len(lifted) - 5} more' if len(lifted) > 5 else ''
            why.append(f'denials lifted: {" ".join(lifted[:5])}{more}')
        if old.get('portal_only') and not new.get('portal_only'):
            why.append('no longer held to the portal')
        old_tp = _json_of(old.get('tenant_permissions'), dict)
        for tid, ov in sorted(_json_of(new.get('tenant_permissions'), dict).items()):
            was = old_tp.get(tid) if isinstance(old_tp.get(tid), dict) else {}
            if isinstance(ov, dict) and ov.get('role') == 'admin' and was.get('role') != 'admin':
                why.append(f'override for tenant {str(tid)[:40]} raised to admin')
    elif kind == 'token':
        if old is None:
            return 'arrived as admin' if new.get('role') == 'admin' else ''
        if old.get('revoked') and not new.get('revoked'):
            why.append('a revoked token came back')
        if new.get('role') == 'admin' and old.get('role') != 'admin':
            why.append('role raised to admin')
    return ', '.join(why)


def _audit_applied(home, changes, raised):
    """The receiver's record of what a snapshot changed here, written after the commit: one
    warning entry for every change that raised access, one routine entry per other changed
    row up to AUDIT_ROUTINE_CAP, then one entry that sums up the rest. An unchanged row is
    no entry. `changes` holds (kind, label, op, detail) with op '+', '~' or '-'; `raised`
    holds (label, reason)."""
    if not changes and not raised:
        return
    try:
        from pegaprox.utils.audit import log_audit
    except Exception as e:
        logging.warning(f'[FED] the applied snapshot could not be audited: {e}')
        return
    src = home[:8]
    try:
        for label, reason in raised:
            log_audit('system', 'federation.identity_escalated',
                      f'{label} from {src}: {reason}', ip_address='federation')
            logging.warning(f'[FED] {label} from {src}: {reason}')
        for _kind, label, _op, detail in changes[:AUDIT_ROUTINE_CAP]:
            log_audit('system', 'federation.identity_applied', f'{label} from {src}: {detail}',
                      ip_address='federation')
        rest = changes[AUDIT_ROUTINE_CAP:]
        if rest:
            parts = []
            for kind, plural in (('user', 'users'), ('token', 'tokens'),
                                 ('passkey', 'passkeys'), ('cluster', 'clusters')):
                ops = [c[2] for c in rest if c[0] == kind]
                if ops:
                    parts.append(f'{plural} +{ops.count("+")} ~{ops.count("~")} '
                                 f'-{ops.count("-")}')
            log_audit('system', 'federation.identity_applied',
                      f'and {len(rest)} more from {src}: {", ".join(parts)}',
                      ip_address='federation')
    except Exception as e:
        logging.warning(f'[FED] the applied snapshot could not be audited: {e}')


def _write_row(conn, table, keys, sql_keys, values, held, home):
    """Insert a mirror row, or update the held one of this home."""
    clear = PER_TABLE_CLEAR.get(table) or ()
    names = list(values)
    if held is None:
        fields = [*keys, *names, *clear, 'fed_home']
        quoted = ', '.join(f'"{f}"' for f in fields)
        conn.execute(f'INSERT INTO "{table}" ({quoted}) VALUES ({", ".join("?" * len(fields))})',
                     [*sql_keys, *(values[c] for c in names), *([''] * len(clear)), home])
    else:
        sets = ', '.join([*(f'"{c}" = ?' for c in names), *(f'"{c}" = \'\'' for c in clear)])
        conn.execute(f'UPDATE "{table}" SET {sets} WHERE {_key_where(keys)} AND fed_home = ?',
                     [*(values[c] for c in names), *sql_keys, home])


def _incoming_values(table, row):
    """The non-key columns of an incoming row as they are written: blobs decoded, flags as
    0/1. None when a blob does not decode."""
    keys = IDENTITY_KEYS[table]
    blobs = BLOB_COLUMNS.get(table) or ()
    values = {}
    for c in IDENTITY_COLUMNS[table]:
        if c in keys:
            continue
        v = row.get(c)
        if c in blobs and isinstance(v, str):
            try:
                v = base64.b64decode(v, validate=True)
            except Exception:
                return None
        elif c in FLAG_COLUMNS:
            v = 1 if v else 0
        elif v is not None and not isinstance(v, (str, int, float, bytes)):
            return None
        values[c] = v
    return values


def _apply_users(conn, home, incoming, maps, scope, seen, report, changes, raised, ended):
    table, keys = 'users', IDENTITY_KEYS['users']
    held_rows = _held_rows(conn, table, keys, incoming)
    keep = set()
    for row in incoming:
        if not isinstance(row, dict):
            continue
        kv = _key_of(row, keys)
        if kv is None:
            continue
        name = kv[0]
        bad = [c for c in IDENTITY_COLUMNS[table] if c in JSON_COLUMNS
               and not _plain_json(row.get(c))]
        values = _incoming_values(table, row)
        if bad or values is None:
            _conflict(report, f'user "{name[:64]}" carries no readable '
                              f'{bad[0] if bad else "row"} - skipped')
            # the home still lists it: the mirror stays with its grants here, signed out
            # until a row that reads comes, since this one may disable it or change its
            # password
            keep.add(kv)
            held = held_rows.get(kv)
            if held is not None and held['fed_home'] == home and held.get('enabled'):
                conn.execute('UPDATE users SET enabled = 0 WHERE username = ? AND fed_home = ?',
                             (name, home))
                ended.add(name)
                changes.append(('user', _label(table, row), '~',
                                'unreadable at the home, signed out here'))
            continue
        held = held_rows.get(kv)
        if held is not None and held['fed_home'] != home:
            # a local row, or another member's mirror: never written by this snapshot
            _conflict(report, f'user "{name[:64]}" is homed here or at another member')
            continue
        patch, named, why = _resolve_user(row, maps, scope)
        for value in named:
            seen[value] += 1
        values = dict(values, **patch) if patch is not None else _quarantined(values)
        if patch is None:
            report['quarantined'] += 1
        keep.add(kv)
        label = _label(table, row)
        new = _comparable(values)
        if held is None:
            _write_row(conn, table, keys, kv, values, None, home)
            report['applied'] += 1
            reason = _access_raised('user', None, new) if patch is not None else ''
            if reason:
                raised.append((label, reason))
            else:
                changes.append(('user', label, '+', 'added' if patch is not None
                                else 'added, waits for a mapping here'))
            continue
        old = _comparable({c: held.get(c) for c in values})
        old['totp_secret_encrypted'] = held.get('totp_secret_encrypted') or ''
        new['totp_secret_encrypted'] = ''
        if old == new:
            report['unchanged'] += 1
            continue
        _write_row(conn, table, keys, kv, values, held, home)
        report['updated'] += 1
        was_q = old.get('tenant') == QUARANTINE
        if patch is None:
            detail = 'waits for a mapping here' if was_q else 'quarantined, waits for a mapping here'
            changes.append(('user', label, '~', detail))
        elif was_q:
            changes.append(('user', label, '~', 'mapped here'))
        else:
            reason = _access_raised('user', old, new)
            if reason:
                raised.append((label, reason))
            else:
                changes.append(('user', label, '~', 'updated'))
        if (old.get('password_hash') != new.get('password_hash')
                or (old.get('enabled') and not new.get('enabled'))
                or (patch is None and not was_q)):
            ended.add(name)
    # a mirror of this home that the snapshot no longer lists is gone at the home: gone
    # here too. Local rows and other members' mirrors are not in the WHERE and stay.
    for held_row in conn.execute('SELECT username FROM users WHERE fed_home = ?',
                                 (home,)).fetchall():
        name = held_row['username']
        if (name,) not in keep and _drop_row(conn, table, keys, (name,), home, ended):
            report['deleted'] += 1
            changes.append(('user', _label(table, {'username': name}), '-', 'deleted'))


def _apply_credentials(conn, home, table, incoming, maps, scope, seen, report, changes,
                       raised):
    """Tokens and passkeys of the home's users. One belongs here only when the user it
    names is a mirror of that same home - a local account, another member's mirror or a
    user nobody holds is a conflict, and a held copy of such a row goes with the diff."""
    keys = IDENTITY_KEYS[table]
    kind = IDENTITY_KIND[table]
    owners = {r['username']: (r['tenant'] or '') for r in conn.execute(
        'SELECT username, tenant FROM users WHERE fed_home = ?', (home,)).fetchall()}
    held_rows = _held_rows(conn, table, keys, incoming)
    keep = set()
    for row in incoming:
        if not isinstance(row, dict):
            continue
        kv = _key_of(row, keys)
        if kv is None:
            continue
        label = _label(table, row)
        bad = [c for c in IDENTITY_COLUMNS[table] if c in JSON_COLUMNS
               and not _plain_json(row.get(c))]
        values = _incoming_values(table, row)
        sql_keys = kv
        if table in BLOB_COLUMNS:
            try:
                sql_keys = tuple(base64.b64decode(v, validate=True) for v in kv)
            except Exception:
                values = None
        if bad or values is None:
            _conflict(report, f'{label} is not readable - skipped')
            continue
        held = held_rows.get(kv)
        if held is not None and held['fed_home'] != home:
            _conflict(report, f'{label} is homed here or at another member')
            continue
        username = row.get('username')
        if not isinstance(username, str) or username not in owners:
            _conflict(report, f'{label} names a user that is not a mirror of '
                              f'{home[:8]} here - not mirrored')
            continue
        if table == 'api_tokens':
            role, named = _resolve_token_role(row.get('role'), owners[username], maps, scope)
            if named:
                seen[named] += 0
            if role is None:
                _conflict(report, f'{label} carries a role that is not mapped here - '
                                  f'not mirrored')
                continue
            values['role'] = role
        keep.add(kv)
        new = _comparable(values)
        if held is None:
            _write_row(conn, table, keys, sql_keys, values, None, home)
            report['applied'] += 1
            reason = _access_raised(kind, None, new)
            if reason:
                raised.append((label, reason))
            else:
                changes.append((kind, label, '+', 'added'))
            continue
        old = _comparable({c: held.get(c) for c in values})
        if old == new:
            report['unchanged'] += 1
            continue
        _write_row(conn, table, keys, sql_keys, values, held, home)
        report['updated'] += 1
        reason = _access_raised(kind, old, new)
        if reason:
            raised.append((label, reason))
        else:
            changes.append((kind, label, '~', 'updated'))
    sel = ', '.join(f'"{c}"' for c in (*keys, 'username', 'name'))
    for held_row in conn.execute(f'SELECT {sel} FROM "{table}" WHERE fed_home = ?',
                                 (home,)).fetchall():
        raw = tuple(held_row[k] for k in keys)
        if _wire_key(raw) in keep:
            continue
        cur = conn.execute(f'DELETE FROM "{table}" WHERE {_key_where(keys)} AND fed_home = ?',
                           (*raw, home))
        if cur.rowcount:
            report['deleted'] += 1
            changes.append((kind, _label(table, dict(held_row)), '-', 'deleted'))


def apply_identity_snapshot(body, sender):
    """Take a snapshot member `sender` signed for us: its users, tokens and passkeys
    mirrored, resolved through the mapping, our own rows never touched. Returns the report
    the admin route shows; raises FederationError for a body that is no snapshot of that
    member, or when the mapping or the local tenants cannot be read (nothing is written
    then).

    Only what really changed is written and audited: a held row equal to what it would
    become is left alone."""
    if not isinstance(body, dict) or body.get('fed') != FED_MARK \
            or not isinstance(body.get('rows'), dict):
        raise FederationError('That answer is no identity snapshot')
    home = body.get('home') or ''
    if not isinstance(home, str) or not ha_wire.ID_RE.fullmatch(home) or home == instance_id():
        raise FederationError('That snapshot names no member of this federation')
    if sender != home:
        raise FederationError('That snapshot claims a home its sender is not')
    if member_record(sender) is None:
        raise FederationError('That snapshot\'s sender is no member of this federation')
    tables = {}
    for table in IDENTITY_TABLES:
        rows = body['rows'].get(table)
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            raise FederationError(f'That snapshot carries no list of {table}')
        tables[table] = rows
    report = {'applied': 0, 'updated': 0, 'deleted': 0, 'unchanged': 0, 'quarantined': 0,
              'conflicts': []}
    changes, raised, ended = [], [], set()
    from collections import Counter
    seen = Counter()
    conn = _identities_conn()
    _begin(conn)
    try:
        held_map = _map_rows(conn, home)
        maps = held_map
        scope = _local_scope(conn)
        # users first, in the same transaction: a token of a user this snapshot brings
        # finds its owner
        _apply_users(conn, home, tables['users'], maps, scope, seen, report, changes,
                     raised, ended)
        for table in ('api_tokens', 'webauthn_credentials'):
            _apply_credentials(conn, home, table, tables[table], maps, scope, seen, report,
                               changes, raised)
        _note_unmapped(conn, home, held_map, seen)
        # the clusters the home leads become mirrors in the same transaction - one
        # snapshot, one commit, and the etag below only says 'pulled' when both went in
        # (with the disaster recovery off, no copy of another site's cluster is kept)
        _apply_cluster_mirrors(home, body.get('clusters') if dr_enabled() else None,
                               report, changes)
        conn.commit()
    except Exception:
        _rollback(conn)
        raise
    if report['deleted']:
        # the grants of a dropped user went inside the transaction
        _db().invalidate_grant_caches()
    _finish_cluster_mirrors(home, report)
    # a mirror that went, was disabled, re-passworded or quarantined does not keep a
    # sign-in at this site
    for name in sorted(ended):
        _end_sessions_of(name)
    _audit_applied(home, changes, raised)
    _note_pull(home, body.get('etag') or '', report)
    return report


def _drop_row(conn, table, keys, sql_keys, home, dropped_users):
    """Delete one mirrored row of `home` (and for a user what hangs on it: grants, favorites,
    open sessions) - but only when the row really is that home's mirror. A local account of
    the same name is never touched by a member's snapshot. Returns whether a row went."""
    kwhere = _key_where(keys)
    if table == 'users':
        name = sql_keys[0]
        check = conn.execute(f'SELECT fed_home FROM "{table}" WHERE {kwhere}',
                             sql_keys).fetchone()
        if check is None or check['fed_home'] != home:
            return False
        # inside the snapshot's transaction: a purge that committed on its own would land
        # half a snapshot, and a later failure would roll back only the rest
        _db().purge_user_grants(name, commit=False)
        conn.execute('DELETE FROM user_favorites WHERE username = ?', (name,))
        dropped_users.add(name)
    cur = conn.execute(f'DELETE FROM "{table}" WHERE {kwhere} AND fed_home = ?',
                       (*sql_keys, home))
    return bool(cur.rowcount)


def _end_sessions_of(username):
    try:
        from pegaprox.utils.auth import invalidate_all_user_sessions
        invalidate_all_user_sessions(username)
    except Exception as e:
        logging.warning(f"[FED] could not end the sessions of {username}: {e}")


def _note_pull(home, etag, report):
    try:
        conn = _identities_conn()
        conn.execute(
            'INSERT INTO federation_sync_state (peer, etag, pulled_at, rows) '
            'VALUES (?, ?, ?, ?) ON CONFLICT(peer) DO UPDATE SET etag = excluded.etag, '
            'pulled_at = excluded.pulled_at, rows = excluded.rows',
            (home, etag, int(time.time()),
             report.get('applied', 0) + report.get('updated', 0) + report.get('unchanged', 0)))
        conn.commit()
    except Exception as e:
        logging.warning(f"[FED] could not note the pull of {home}: {e}")


def foreign_home(table, key_vals):
    """The instance a row of an identity table is homed at: '' when it is ours or nobody's.
    The guards in the routes ask this before a write goes through - the home decides,
    everything else refuses with the instance it names."""
    if table not in IDENTITY_TABLES:
        return ''
    try:
        row = _identities_conn().execute(
            f'SELECT fed_home FROM "{table}" WHERE {_key_where(IDENTITY_KEYS[table])}',
            tuple(key_vals)).fetchone()
    except Exception as e:
        # fail closed for the guards: a table that cannot be read is no reason to treat a
        # row as anybody's to write
        raise FederationError(f'The {table} table cannot be read: {e}')
    home = (row['fed_home'] if row is not None else '') or ''
    return home if home and home != instance_id() else ''


def sync_state():
    """What the status shows: the last pull of every member."""
    try:
        cur = _identities_conn().execute(
            'SELECT peer, etag, pulled_at, rows FROM federation_sync_state')
        return {r['peer']: {'etag': r['etag'], 'pulled_at': r['pulled_at'],
                            'rows': r['rows']} for r in cur.fetchall()}
    except Exception:
        return {}


# one pull per member at a time: the worker, the admin's sync, a mapping and a join all
# pull, and a snapshot fetched first but applied last would put an older state back (an
# account the home disabled meanwhile enabled again) and keep the older etag
_pull_locks = {}
_pull_locks_guard = threading.Lock()


def _pull_lock(sender):
    with _pull_locks_guard:
        lock = _pull_locks.get(sender)
        if lock is None:
            if len(_pull_locks) >= 4 * MAX_SITES:
                for k in [k for k, v in _pull_locks.items() if not v.locked()]:
                    _pull_locks.pop(k, None)
            lock = _pull_locks[sender] = threading.Lock()
        return lock


def pull_identities(sender, extra_headers=None):
    """Pull the identities of member `sender`: 304 when nothing changed since the last pull,
    else the snapshot applied. The answer carries the member's signature over this request's
    nonce (checked in _send). Returns a report or None for nothing to do; raises nothing.
    The fetch and the apply of one member hold its pull lock: a second pull waits and then
    fetches afresh."""
    with _pull_lock(sender):
        return _pull_identities(sender, extra_headers)


def _pull_identities(sender, extra_headers=None):
    rec = member_record(sender)
    if rec is None or not rec.get('url'):
        return None
    headers = dict(extra_headers or {})
    state = sync_state().get(sender) or {}
    if state.get('etag'):
        headers['If-None-Match'] = state['etag']
    status, body, _h = call_peer(sender, 'GET', IDENTITIES_PATH, None, extra_headers=headers,
                                 cap=MAX_SNAPSHOT_ANSWER)
    if status == 304 and state.get('etag'):
        _note_pull(sender, state['etag'], {'unchanged': state.get('rows') or 0})
        return {'unchanged': True, 'quarantined': _quarantined_count(sender)}
    if status == 304:
        # nothing was held that this could confirm - a wrong answer, not a shortcut
        logging.warning(f"[FED] identity pull from {sender} answered 304 unsolicited")
        return {'failed': True}
    if status != 200 or not isinstance(body, dict):
        logging.warning(f"[FED] identity pull from {sender} answered {status or 'nothing'}")
        return {'failed': True}
    if body.get('etag') and state.get('etag') == body.get('etag'):
        _note_pull(sender, state['etag'], {'unchanged': state.get('rows') or 0})
        return {'unchanged': True, 'quarantined': _quarantined_count(sender)}
    if isinstance(body.get('records'), list) and body['records'] and dr_enabled():
        # before the cluster rows: a cluster this instance took over and lost in an HA
        # failover is led here again first, and its row is not dropped as one the
        # sender no longer lists
        from pegaprox.core import federation_lease as fl
        if not fl.take_records(sender, body['records'], cap=MAX_OWNER_RECORDS)['echo']:
            logging.warning(f'[FED] the ownership records of {sender} could not be stored - '
                            'its snapshot waits for the next sync')
            return {'failed': True}
    try:
        return apply_identity_snapshot(body, sender)
    except Exception as e:
        logging.warning(f"[FED] identity pull from {sender} refused: {e}")
        return {'failed': True}


def drop_orphan_mirrors():
    """Mirrors of an instance that is no member of the view any more - a removal whose drop
    broke off half way, a database restored from another federation - go. Nothing happens
    on a standby or when the view cannot be read. Returns the homes dropped."""
    if _ha_standby():
        return []
    try:
        keep = set(members()) | _drops_pending()
        me = instance_id()
    except Exception as e:
        logging.warning(f'[FED] the orphan sweep of mirrored accounts is skipped: {e}')
        return []
    homes = set()
    conn = _identities_conn()
    try:
        for table in IDENTITY_TABLES:
            homes |= {r[0] for r in conn.execute(
                f'SELECT DISTINCT fed_home FROM "{table}" WHERE fed_home != \'\'').fetchall()}
        homes |= {r[0] for r in conn.execute(
            'SELECT DISTINCT home FROM federation_identity_map').fetchall()}
    except Exception as e:
        logging.warning(f'[FED] the orphan sweep of mirrored accounts cannot read: {e}')
        return []
    gone = sorted(h for h in homes if h and h not in keep and h != me)
    for home in gone:
        drop_mirror_rows(home)
    if gone:
        logging.info(f'[FED] dropped the mirrored accounts of {len(gone)} instance(s) that are '
                     f'no members any more')
    return gone


def sync_identities():
    """Sweep the mirrors of instances that left, then pull every member; the report the
    admin route shows. One member's failure to answer never stops the others."""
    drop_orphan_mirrors()
    out = {}
    for iid in sorted(members()):
        out[iid] = pull_identities(iid) or {'failed': True}
    return out


def drop_mirror_rows(home):
    """Everything this instance mirrored of `home` goes when the member goes: the account
    rows, their mapping, the grants and favorites of its users and the sessions they opened
    here."""
    try:
        conn = _identities_conn()
        names = [r['username'] for r in conn.execute(
            'SELECT username FROM users WHERE fed_home = ?', (home,)).fetchall()]
        for table in IDENTITY_TABLES:
            conn.execute(f'DELETE FROM "{table}" WHERE fed_home = ?', (home,))
        conn.execute('DELETE FROM federation_sync_state WHERE peer = ?', (home,))
        conn.execute('DELETE FROM federation_identity_map WHERE home = ?', (home,))
        conn.commit()
        try:
            for name in names:
                _db().purge_user_grants(name)
                conn.execute('DELETE FROM user_favorites WHERE username = ?', (name,))
            conn.commit()
        except Exception as e:
            logging.warning(f"[FED] could not purge the grants of {home}'s users: {e}")
        for name in names:
            _end_sessions_of(name)
    except Exception as e:
        logging.warning(f"[FED] could not drop the mirrors of {home}: {e}")


# --- cluster mirrors ------------------------------------------------------------------------
#
# What a member leads, the others mirror: an enrolled cluster's row, its credentials
# wrapped under the owner's federation field key, travels with the identity snapshot. A
# mirror is not managed here (no manager, no listing, the reads of the database leave it
# out), it is the copy an adoption opens when the owner is gone for good.

CLUSTER_SYNC_COLUMNS = ('id', 'name', 'host', 'user', 'pass_encrypted',
                        'ssl_verification', 'migration_threshold',
                        'migration_tolerance', 'migration_cooldown',
                        'check_interval', 'auto_migrate',
                        'balance_containers', 'balance_local_disks', 'dry_run',
                        'enabled', 'ha_enabled', 'fallback_hosts', 'ssh_user',
                        'ssh_key_encrypted', 'ssh_port', 'api_port', 'ha_settings',
                        'created_at', 'updated_at', 'cluster_type',
                        'transfer_network', 'api_token_user',
                        'api_token_secret_encrypted',
                        # the workbench settings of the row travel too: an adopted
                        # cluster keeps its grouping, its place on the map and its
                        # balancing policy instead of standing there reset
                        'group_id', 'display_name', 'sort_order',
                        'latitude', 'longitude', 'location_label', 'node_ui_suffix',
                        'excluded_nodes', 'smbios_autoconfig',
                        'proxlb_tags_enabled', 'proxlb_pins_auto_migrate',
                        'proxlb_pins_strict', 'predictive_balancing',
                        'predictive_threshold', 'balance_cpu_weight',
                        'balance_mem_weight', 'balance_io_weight', 'cpu_baseline',
                        'vnc_tunnel', 'ssh_disabled', 'backup_sla_max_age_hours')
CLUSTER_ENCRYPTED_COLUMNS = ('pass_encrypted', 'ssh_key_encrypted', 'ha_settings',
                             'api_token_secret_encrypted')


def enrolled_cluster_rows():
    """The cluster rows this instance leads, as the snapshot carries them: the credential
    columns opened with the database key and wrapped under the federation field key. A
    table that cannot be read raises: an empty list would read as "nothing led", and the
    puller's diff would delete every mirror of this instance's clusters.

    A credential that does not open here travels as null, not as '': an empty value is a
    credential that was taken away, and the mirrors would drop the last copy they can open
    after this site is gone (_apply_cluster_mirrors keeps what it holds for a null)."""
    try:
        cur = _identities_conn().execute(
            'SELECT %s FROM clusters WHERE fed_owner = ? ORDER BY id'
            % ', '.join(f'"{c}"' for c in CLUSTER_SYNC_COLUMNS), (instance_id(),))
        rows = [dict(r) for r in cur.fetchall()]
    except Exception as e:
        raise FederationError(f'The clusters table cannot be read for the snapshot: {e}')
    db = _db()
    for row in rows:
        for col in CLUSTER_ENCRYPTED_COLUMNS:
            value = row.get(col)
            if not value:
                row[col] = ''
                continue
            try:
                row[col] = wrap_credential(db._decrypt(value), row['id'], col)
            except Exception as e:
                _say_once(('wrap', row['id'], col),
                          f"[FED] {col} of cluster {row['id']} does not open here; the "
                          f"other sites keep the copy they hold: {e}")
                row[col] = None
    return rows


def _cluster_mirror_body():
    """The clusters section of the snapshot, with the canonical form the etag covers."""
    rows = enrolled_cluster_rows()
    return rows, json.dumps(rows, separators=(',', ':'), sort_keys=True)


def _apply_cluster_mirrors(home, rows_in, report, changes=None):
    """The mirror half of the cluster sync, inside the snapshot's transaction. A mirror's
    owner is the member this instance itself backed last: a row arrives as `home`'s mirror
    when nothing here names another owner, a mirror of another member moves to `home`
    only when this instance's own promise for the cluster names `home`, and a row led here
    becomes `home`'s mirror only on the evidence federation_lease.may_convert() asks for.
    A local row is never touched. Credential columns must be empty or wrapped ('fedk1:'),
    so no foreign database ciphertext ever lands here; a null one did not open at the home
    (enrolled_cluster_rows), and a mirror of that home keeps the value it holds. Each
    changed row is one entry in `changes`, which the identity half audits with its own
    (_audit_applied)."""
    if not isinstance(rows_in, list):
        return
    if changes is None:
        changes = []
    from pegaprox.core import federation_lease as fl
    conn = _identities_conn()
    me = instance_id()
    cols = CLUSTER_SYNC_COLUMNS
    rest = [c for c in cols if c != 'id']
    view = members()
    backed = fl.backed_candidates()
    report.setdefault('unchanged', 0)
    lost = report.setdefault('clusters_lost', [])
    keep = set()
    sel = ', '.join(f'"{c}"' for c in rest)
    for row in rows_in:
        if not isinstance(row, dict):
            continue
        cid = row.get('id')
        if not isinstance(cid, str) or not CLUSTER_ID_RE.fullmatch(cid):
            continue
        keep.add(cid)
        bad = [c for c in CLUSTER_ENCRYPTED_COLUMNS if row.get(c) not in (None, '')
               and not (isinstance(row.get(c), str) and row[c].startswith(FIELD_PREFIX))]
        if bad:
            report['conflicts'].append(f'cluster "{cid}" carries {bad[0]} that is not '
                                       f'wrapped under a federation field key - skipped')
            continue
        values = [row.get(c) if c not in CLUSTER_ENCRYPTED_COLUMNS else (row.get(c) or '')
                  for c in rest]
        held = conn.execute(f'SELECT fed_owner, {sel} FROM clusters WHERE id = ?',
                            (cid,)).fetchone()
        sets = ', '.join(f'"{c}" = ?' for c in rest)
        if held is None:
            other = backed.get(cid)
            if other and other != home and other in view:
                report['conflicts'].append(f'cluster "{cid}": this instance backs '
                                           f'{other[:8]} for it - waiting for that member')
                continue
            conn.execute(f'INSERT INTO clusters ("id", {sel}, fed_owner) VALUES '
                         f'({", ".join("?" * (len(cols) + 1))})', [cid] + values + [home])
            report['applied'] += 1
            changes.append(('cluster', f'cluster "{cid}"', '+', 'added'))
            continue
        owner = held['fed_owner'] or ''
        if owner == home:
            # a credential the home could not open comes as null: the copy held stays
            values = [held[c] if c in CLUSTER_ENCRYPTED_COLUMNS and row.get(c) is None else v
                      for c, v in zip(rest, values)]
            if all(held[c] == v for c, v in zip(rest, values)):
                report['unchanged'] += 1
                continue
            conn.execute(f'UPDATE clusters SET {sets} WHERE id = ? AND fed_owner = ?',
                         values + [cid, home])
            report['updated'] += 1
            changes.append(('cluster', f'cluster "{cid}"', '~', 'updated'))
        elif not owner:
            report['conflicts'].append(f'cluster "{cid}" homed here')
        elif owner == me:
            if fl.may_convert(cid, home):
                conn.execute(f'UPDATE clusters SET {sets}, fed_owner = ? WHERE id = ? '
                             f'AND fed_owner = ?', values + [home, cid, me])
                report['updated'] += 1
                lost.append(cid)
                changes.append(('cluster', f'cluster "{cid}"', '~', f'now led by {home[:8]}'))
            else:
                report['conflicts'].append(f'cluster "{cid}" is led here - not another '
                                           f'member\'s to write')
        elif backed.get(cid) == home:
            conn.execute(f'UPDATE clusters SET {sets}, fed_owner = ? WHERE id = ? AND '
                         f'fed_owner = ?', values + [home, cid, owner])
            report['updated'] += 1
            changes.append(('cluster', f'cluster "{cid}"', '~', f'now led by {home[:8]}'))
        else:
            report.setdefault('ignored', []).append(cid)
    # a mirror of the home that the snapshot no longer lists is gone at the home
    for held_row in conn.execute('SELECT id FROM clusters WHERE fed_owner = ?',
                                 (home,)).fetchall():
        if held_row['id'] not in keep:
            conn.execute('DELETE FROM clusters WHERE id = ? AND fed_owner = ?',
                         (held_row['id'], home))
            report['deleted'] += 1
            report.setdefault('clusters_dropped', []).append(held_row['id'])
            changes.append(('cluster', f'cluster "{held_row["id"]}"', '-', 'deleted'))


def _finish_cluster_mirrors(home, report):
    """After the snapshot committed: the owner cache goes, and a cluster this instance
    lost to `home` stops being managed here."""
    from pegaprox.core import federation_lease as fl
    fl.drop_owner_cache()
    # on record only now: noting them inside the snapshot's transaction would commit it
    note_dropped((cid, home) for cid in report.pop('clusters_dropped', []) or [])
    for cid in report.pop('clusters_lost', []) or []:
        fl.note_lost(cid, home)


# --- the clusters of the federation (the linked view) --------------------------------------
#
# What every member leads, asked live at each member on demand: no copy, the owner
# answers. Names and counts alone; credentials never leave their host.

def own_clusters_body():
    """This instance's clusters, enrolled or not: names, type, counts, and whether the
    federation's rule holds on them. Built once per CLUSTERS_BODY_SECONDS however many
    members ask; mirrors of other members are not this instance's to report."""
    held = _runtime.get('clusters_body')
    now = time.monotonic()
    if held is not None and 0 <= now - held[1] < CLUSTERS_BODY_SECONDS:
        return held[0]
    out = []
    try:
        rows = _db().conn.execute(
            "SELECT id, name, cluster_type, enabled, fed_owner FROM clusters "
            "ORDER BY name").fetchall()
    except Exception as e:
        logging.warning(f"[FED] could not read the clusters for the view: {e}")
        rows = []
    me = instance_id()
    mgrs = None
    for r in rows:
        if r['fed_owner'] and r['fed_owner'] != me:
            continue
        rec = {'id': r['id'], 'name': r['name'], 'type': r['cluster_type'] or 'proxmox',
               'enabled': bool(r['enabled']), 'enrolled': bool(r['fed_owner'])}
        try:
            if mgrs is None:
                from pegaprox import globals as g
                mgrs = getattr(g, 'cluster_managers', None) or {}
            mgr = mgrs.get(r['id'])
            if mgr is not None:
                rec['connected'] = bool(getattr(mgr, 'is_connected', False)
                                        or getattr(mgr, 'connected', False))
                node_status = mgr.get_node_status() if rec['connected'] else {}
                if isinstance(node_status, dict):
                    rec['nodes'] = len(node_status)
                guests = None
                if rec['connected']:
                    try:
                        guests = mgr.get_vm_resources(max_age=15)
                    except TypeError:
                        guests = mgr.get_vms()
                if isinstance(guests, list):
                    rec['vms'] = len(guests)
        except Exception as e:
            logging.debug(f"[FED] no counts for {r['id']}: {e}")
        out.append(rec)
    _runtime['clusters_body'] = (out, now)
    return out


def peer_clusters_body():
    """What /peer/clusters answers. A cluster that is not enrolled goes without its id:
    the others know an id once the cluster is enrolled, and an id known before would let
    a member claim it first (enroll a row of its own under it)."""
    own = own_clusters_body()
    rows = [r if r.get('enrolled') else {k: v for k, v in r.items() if k != 'id'}
            for r in own[:MAX_VIEW_ROWS]]
    return {'instance_id': instance_id(), 'clusters': rows, 'total': len(own)}


def _count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) \
        and 0 <= value < 100000 else None


def _view_row(r):
    """One row of a member's linked view as the tab shows it. An enrolled row carries its
    id; a row that is not enrolled comes without one (peer_clusters_body)."""
    if not isinstance(r, dict):
        return None
    enrolled = r.get('enrolled') is True
    cid = r.get('id')
    if enrolled and not (isinstance(cid, str) and CLUSTER_ID_RE.fullmatch(cid)):
        return None
    out = {'name': str(r.get('name') or '')[:80],
           'type': r.get('type') if r.get('type') in CLUSTER_TYPES else 'other',
           'enabled': r.get('enabled') is True, 'enrolled': enrolled}
    if enrolled:
        out['id'] = cid
    for field in ('nodes', 'vms'):
        n = _count(r.get(field))
        if n is not None:
            out[field] = n
    if isinstance(r.get('connected'), bool):
        out['connected'] = r['connected']
    return out


def federation_clusters():
    """The clusters of every member, asked at every member side by side. One member's
    silence costs its line, never the list; a member with more than MAX_VIEW_ROWS
    clusters shows that many and says how many it has in all."""
    roster = sorted(members().items())

    def ask(item):
        iid, rec = item
        entry = {'site': rec.get('site') or '', 'clusters': None, 'total': 0}
        status, body, _h = call_peer(iid, 'GET', CLUSTERS_PATH, read_timeout=5)
        if status == 200 and isinstance(body, dict) and isinstance(body.get('clusters'), list):
            rows = [x for x in (_view_row(r) for r in body['clusters'][:MAX_VIEW_ROWS]) if x]
            total = body.get('total')
            entry['clusters'] = rows
            entry['total'] = total if (isinstance(total, int) and not isinstance(total, bool)
                                       and len(rows) <= total < 1000000) else len(rows)
        return iid, entry
    out = {'self': own_clusters_body(), 'peers': {}}
    for got in _parallel(ask, roster, max_workers=MAX_SITES - 1):
        if got is not None:
            out['peers'][got[0]] = got[1]
    return out


# --- the workers -------------------------------------------------------------------------
#
# MK Nov 2026 - two loops, started when the switch goes on (at boot, at a toggle, or when
# the setting arrives with the HA sync) and stopped when it goes off. Each tick does
# nothing unless the federation is on and this instance is the acting one of its HA
# group: a standby keeps the identity it received and votes for nobody.

def start_workers():
    """Start the sync loop (every SYNC_INTERVAL) and the lease loop (every
    LEASE_RENEW_AFTER). True when they started now, False when they were running."""
    with _lock:
        held = _runtime.get('workers')
        if held is not None and not held['stop'].is_set():
            return False
        stop = threading.Event()
        _runtime['workers'] = {'stop': stop}
    sync = threading.Thread(target=_loop, args=(stop, SYNC_INTERVAL, _sync_tick),
                            daemon=True, name='federation-sync')
    lease = threading.Thread(target=_loop, args=(stop, LEASE_RENEW_AFTER, _lease_tick),
                             daemon=True, name='federation-lease')
    sync.start()
    lease.start()
    logging.info(f'[FED] workers started: sync ({SYNC_INTERVAL}s), leases '
                 f'({LEASE_RENEW_AFTER}s)')
    return True


def stop_workers():
    """Stop both loops; they end at their next wait. True when they were running."""
    with _lock:
        held = _runtime.get('workers')
        _runtime['workers'] = None
    if held is None:
        return False
    held['stop'].set()
    return True


def workers_running():
    held = _runtime.get('workers')
    return bool(held is not None and not held['stop'].is_set())


def _loop(stop, every, tick):
    due = time.monotonic() + every
    while True:
        if stop.wait(max(0.0, due - time.monotonic())):
            return
        # a fixed schedule: the next tick is due `every` after this one was, however
        # long this one takes; a tick that ran past several is not caught up
        due += every
        if due < time.monotonic():
            due = time.monotonic() + every
        try:
            if enabled() and _ha_active() and instance_id():
                tick()
        except Exception as e:
            _say_once(('tick', getattr(tick, '__name__', ''), str(e)[:80]),
                      f'[FED] {getattr(tick, "__name__", "a tick")} failed: {e}')


def _sync_tick():
    from pegaprox.core import federation_lease as fl
    if take_end():
        return
    if _check_removed_by():
        return
    dr = dr_enabled()
    if dr:
        # a crash between a shrink to one and the return of the clusters is repaired here
        fl.return_alone('repair')
    catch_up()
    if dr:
        fetch_field_keys()
        fl.push_records()
    _push_self_update()
    # with no member left this still sweeps the mirrors of the ones that went
    sync_identities()
    _sweep_cluster_orphans()


def _lease_tick():
    if not dr_enabled():
        return
    from pegaprox.core import federation_lease as fl
    fl.lease_round(tick=True)


def _sweep_cluster_orphans():
    """Cluster rows of a member that is no longer in the view (a removal whose drop broke
    off half way, a database restored from another federation)."""
    me = instance_id()
    if not me:
        return 0
    try:
        keep = ['', me] + sorted(set(members()) | _drops_pending())
    except Exception as e:
        logging.warning(f'[FED] the sweep of orphaned cluster mirrors is skipped: {e}')
        return 0
    try:
        conn = _db().conn
        marks = ", ".join("?" * len(keep))
        gone = [(r['id'], r['fed_owner']) for r in conn.execute(
            f'SELECT id, fed_owner FROM clusters WHERE fed_owner NOT IN ({marks})',
            keep).fetchall()]
        cur = conn.execute(f'DELETE FROM clusters WHERE fed_owner NOT IN ({marks})', keep)
        conn.commit()
        note_dropped(gone)
        if cur.rowcount:
            from pegaprox.core import federation_lease as fl
            fl.drop_owner_cache()
            logging.info(f'[FED] dropped {cur.rowcount} cluster mirror(s) of members that '
                         'are gone')
        return cur.rowcount
    except Exception as e:
        logging.warning(f'[FED] the sweep of orphaned cluster mirrors failed: {e}')
        return 0


# --- the cluster write gate: the exits ask here ---------------------------------------------
#
# Every write to a cluster, a node or a BMC leaves this process through an exit of
# core/ha_transport.py (a guarded session, a guarded SSH client, node_cmd), and each exit
# that knows its cluster asks guard_exit() before the call goes out, whatever route or
# worker sends it. An unenrolled cluster costs the cached switch and one dict lookup.
# Reads, consoles and logins always pass.

_fed_tls = threading.local()


def _refusal_list():
    """Where a refusal at an exit is noted for the request this thread serves: the list
    ha.carry handed a fan-out of it, or the request's own environ."""
    said = getattr(_fed_tls, 'refused', None)
    if said is not None:
        return said
    try:
        from flask import has_request_context, request
        if has_request_context():
            return request.environ.setdefault(FED_REFUSED_ENVIRON, [])
    except Exception:
        pass
    return None


def bind_refusals(said):
    """For ha.carry: the fan-out thread notes its refusals where its request does.
    Returns what the thread held before."""
    prev = getattr(_fed_tls, 'refused', None)
    _fed_tls.refused = said
    return prev


def guard_exit(cluster_id, action, kind=None):
    """Right before a write leaves for cluster `cluster_id`: raises LeaseRefused unless
    this instance may write there (an unenrolled cluster, or an enrolled one this
    instance holds a live lease on).

    A thaw of the guest agent (kind 'thaw') passes: it only resumes the guest's file system
    I/O. Every thaw in pegaprox/ follows a freeze of its own, which needed the lease
    (test_federation_write_gate pins that). Sent after the lease went, the worst it does is
    end a freeze another site made for its own snapshot, which is then only
    crash-consistent. Refused, it would leave the guest frozen, every write in it hanging,
    until somebody thaws it by hand.

    With the federation off the exits do not ask (ha_transport checks the switch first),
    and the cluster reads leave every row a federation owns out, so no manager writes one.
    A caller that asks anyway is refused for such a row: nothing fences it while off.

    Returns True when the call went out as a write past the lease check (a cluster that
    is not enrolled counts as well), False when it passed as a read, a console, a login or
    a thaw: what is under way is kept for cut_cluster only after a write."""
    if not cluster_id or kind in ('console', 'login', 'thaw'):
        return False
    if not dr_enabled():
        # with disaster recovery off nothing is leased: a row nobody owns is this
        # instance's alone, a row a federation still owns is fenced as with the switch off
        try:
            owner = cluster_owner(cluster_id)
        except FederationError:
            owner = 'unknown'
        if not owner:
            return True
        _say_once(('refused-off', cluster_id), f'[FED] {action} to cluster {cluster_id} '
                                               'refused: it is enrolled in a federation whose '
                                               'disaster recovery is switched off here')
        raise LeaseRefused(cluster_id, action)
    from pegaprox.core import ha
    if kind == 'ssh' and ha.in_read_request():
        # a GET answered here: the command is how the read gets to the node
        return False
    if ha.reading_now():
        return False
    try:
        ok = takes_writes_for(cluster_id)
    except FederationError:
        ok = False
    if ok:
        return True
    said = _refusal_list()
    if said is not None:
        said.append(cluster_id)
    _say_once(('refused', cluster_id, action),
              f'[FED] {action} to cluster {cluster_id} refused at the exit: this instance '
              f'holds no live federation lease on it')
    raise LeaseRefused(cluster_id, action)


# The lease work lives in federation_lease.py. These names stay here so the hooks outside
# the federation, and the tripwires of the switch-off test, have one module to look at.

def takes_writes_for(cluster_id):
    """Whether a write on `cluster_id` may go out now. Raises FederationError when the
    owner table cannot be read."""
    from pegaprox.core import federation_lease as fl
    return fl.takes_writes_for(cluster_id)


def is_enrolled(cluster_id):
    """Whether a federation owns the row of `cluster_id` (enrolled here, or a mirror).
    True when the owner table cannot be read: the caller then treats it as fenced."""
    from pegaprox.core import federation_lease as fl
    try:
        return bool(fl._owner_map().get(cluster_id))
    except FederationError:
        return True


def worker_takes_writes_for(cluster_id):
    """takes_writes_for for the background workers: False when it cannot tell. With
    disaster recovery off, a cluster no federation owns is this instance's alone."""
    try:
        if not dr_enabled():
            return not cluster_owner(cluster_id)
        return takes_writes_for(cluster_id)
    except FederationError:
        return False


def cluster_owner(cluster_id):
    from pegaprox.core import federation_lease as fl
    return fl.cluster_owner(cluster_id)


def cast_votes(sender, body):
    from pegaprox.core import federation_lease as fl
    return fl.cast_votes(sender, body)


def lease_round(only=None, adopt=frozenset()):
    from pegaprox.core import federation_lease as fl
    return fl.lease_round(only=only, adopt=adopt)


def release(cluster_id):
    from pegaprox.core import federation_lease as fl
    return fl.release(cluster_id)


def forget_deleted_cluster(cluster_id, owner):
    """A cluster row this instance deleted (the cluster route). Its lease is given back
    and forgotten; a row it led (`owner`, the row's fed_owner before the delete) stays on
    record as its own, as an unenroll leaves one. With no row and no record its vote
    would back a stale former owner's plain ask for the id, which a majority could then
    lease again - beside a cluster re-added here from the same hosts."""
    from pegaprox.core import federation_lease as fl
    me = instance_id()
    if owner and owner == me:
        note_dropped([(cluster_id, me)])
    fl.forget_cluster(cluster_id)


def drop_owner_cache():
    from pegaprox.core import federation_lease as fl
    fl.drop_owner_cache()
