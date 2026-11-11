# Multi-Site HA: Three Leader Sites (Variant A, Stage 1)

NS Nov 2026

This document describes the stage 1 backend of variant A. Everything sits
behind the `ha_sites` switch in the group state and is off by default.
With the switch off, the code behaves exactly as it does today.

## Terms

- **Site**: one PegaProx instance in an HA group. Up to `MAX_MEMBERS` (4)
  instances form a group.
- **Group leader**: the instance the group follows, elected as today by
  `ha_vote`. It writes global data and coordinates the group.
- **Leader site**: an instance the group leader marked to serve users
  (`set_member_serve`) and that holds a site lease. Up to `ACTIVE_LIMIT`
  (3) instances may serve. Each of them leads the clusters assigned to it.
- **Home**: for each cluster, the leader site that acts on it. Stored in
  `homes: {cluster_id: instance_id}` in the group state, with a
  `homes_epoch` that grows on every change.
- **Witness**: the `witness.py` process, the fourth vote when the group
  has only three data-bearing members.

## What changes

Today exactly one instance acts (`is_active()`): the group leader. Every
write goes to it, every schedule runs there, every cluster is managed from
there. With the switch on, up to three leader sites each manage their own
set of clusters. Users connect to any serving instance; a write for a
cluster goes to its home site, just as a standby today forwards to the
leader.

### Data classes

- **global** (users, roles, tenants, settings, blueprints, alert rules):
  written only by the group leader, replicated by the full snapshot as
  today. Tables in `TABLE_CLASS` with class `'global'`.
- **per cluster** (tags, VM ACLs, drift baselines, schedules, deployments,
  histories): written only by the home site. Other sites receive row-level
  changes through the change log (`ha_cluster_changes`). Tables with class
  `'cluster'`. Every cluster table has a `cluster_id` column.
- **local** (metrics, syslog, sessions): never replicated. Tables with
  class `'local'`; they sit in `LOCAL_TABLES` as today.

The full list of tables and their class is in the PR text and enforced
by a test.

## The switch

`ha_sites` is a boolean in the group state (`core/ha.py`, `_load` /
`_update`, stored by `_commit_locked`). It spreads with the member list
(`_adopt_group`), like the `serve` flag today. It never enters
`server_settings` or the DB snapshot.

Only the group leader may switch it on (an admin route in `api/ha.py`
with `@require_auth` and the same permission as the other group routes
there). The switch-on is refused with 409 when:

- fewer than 4 voters exist (3 leader sites plus a fourth member or
  witness);
- a member reports a different `SCHEMA_VERSION`;
- a member does not know the switch (an older release: it would silently
  ignore the homes table and act as if it owned every cluster).

Switching off is the same route with `ha_sites: false`. It takes effect
with the next vote round: every site closes its gates, the group leader
reverts to acting on every cluster.

## Cluster-to-home assignment

The group state carries `homes: {cluster_id: instance_id}` and
`homes_epoch: int`. They spread with the member list and are stored
atomically (`_commit_locked`).

A cluster without an entry has the group leader as its home. A newly
added cluster does too.

### Change by vote

Only the group leader proposes a change. It becomes valid when at least
`VOTE_THRESHOLD` (3 of 4) voters accept it with the same
`homes_epoch + 1`. The transport is the existing signed voting calls
(`ha_vote`, `ha_wire`): a new vote kind `'homes'` travels the same
`VOTE_PATH`, signed and replay-protected exactly like the existing lease
votes.

Two proposals at once: at most one gathers a majority; the other is
dropped (a voter that already accepted a different proposal for the same
`homes_epoch + 1` refuses).

### Witness

`witness.py` answers the `'homes'` vote kind. The witness has no cluster
state and no preference between homes; it accepts whatever the group
leader proposed, provided the signature is valid and the nonce is fresh.
This is the same trust model the witness already has for leader votes.

## Site lease and gates

Each leader site holds its own **site lease**, renewed by majority, on
the pattern of the leader lease (`RENEW_PATH`, `ha_vote`, `ha_clock()`,
`WRITE_LEASE_MARGIN`). The group leader's lease is unchanged.

New gates in `core/ha.py`:

- `is_active_for(cluster_id)`:
  - Switch off: exactly `is_active()`.
  - Switch on: this instance is the home for that cluster (from the last
    valid `homes`), it holds a valid site lease, its `homes_epoch` is
    current, and the takeover wait is over.
  - Recomputed on every call, like `is_active()`.

- `takes_writes_for(cluster_id)`: the same, plus
  `WRITE_LEASE_MARGIN` of lease remaining.

### Exclusivity guarantee

No two instances are `is_active_for` for the same cluster at any point,
including during a network partition. The mechanism:

1. The old home's site lease expires (the clock moves past
   `lease_until` plus the takeover wait).
2. The group leader proposes a new `homes` without the expired site.
3. A majority accepts; `homes_epoch` grows.
4. The new home opens its gate only when its `homes_epoch` is current
   and the takeover wait has passed.

The old home cannot hold its gate open past the takeover wait, because
`is_active_for` checks the lease clock on every call. The new home
cannot open before the takeover wait, for the same reason the existing
leader election works: the wait is longer than any clock skew between
the sites.

## Takeover

When a site lease expires (plus the takeover wait), the group leader
proposes a new assignment. The expired site's clusters go to the leader
site with the fewest clusters, ties broken by the smaller `instance_id`.
The vote from above applies.

If the expired site is the group leader itself, the existing leader
election runs first. After a new group leader is in place, it proposes
the new assignment.

A returning old home with a stale `homes_epoch` acts on no cluster
until it has adopted the current assignment (it does so on its next
snapshot pull, `_adopt_group`).

## Write forwarding

The write gate in `app.py`:

- A write on a route with `<cluster_id>` whose cluster has a different
  home is forwarded to that home site, via the existing forwarding path
  (`FORWARD_PATH`, `FORWARD_ENVIRON`, the same session and identity
  handling, the same time limits). The receiver checks
  `takes_writes_for(cid)`.
- Writes without a cluster go to the group leader, as today.
- When the home is unreachable, the answer is the same the standby gives
  without a leader. The write is never executed locally.

Reads stay local, with the same exceptions as today: the cluster routes
in `LEADER_ONLY_READS` and `XCPNG_TASK_READS` go to the cluster's home;
the global ones go to the group leader.

## Change log (per-cluster replication)

When the switch is on, `cluster` tables are left out of the full
snapshot. The home site writes a change log entry in the same
transaction as the change itself:

    ha_cluster_changes(cluster_id, seq, homes_epoch, tbl, op, pk, row_json, ts)

`seq` is strictly increasing per cluster. Other sites pull via a new
signed peer call `GET /api/ha/peer/cluster-changes?cluster_id=&after=`,
apply in order, and track their position per cluster.

After a takeover, the new home first pulls what the old home still had
(if reachable), then writes with the new `homes_epoch`. An entry with a
stale `homes_epoch` is applied nowhere.

Encrypted values are treated as the snapshot treats them today: the
`*_encrypted` column value goes into `row_json` as stored, never
decrypted to plaintext.

The log is bounded: entries older than a retention window or confirmed
by all sites are dropped. A site too far behind gets the full cluster
state instead (the home writes a snapshot entry into the log).

gevent: reading, applying, and cleanup never run on the hub
(`run_heavy_read` / `run_heavy_write` / `run_off_hub`).

## Failure cases

### A leader site goes down

1. Its site lease expires (no renewals from it).
2. After the takeover wait, the group leader proposes moving its
   clusters to another leader site.
3. A majority accepts; `homes_epoch` grows.
4. The new home opens its gates after the takeover wait.
5. The old home, when it comes back, has a stale `homes_epoch` and
   acts on nothing until it catches up.

No two instances act on the same cluster: the old home's lease is
expired and its `is_active_for` checks fail on every call.

### Network partition 2:2

With 4 voters (3 sites plus witness or a 4th member), a 2:2 split
means no majority. No site can renew its lease, no new homes assignment
passes, and every site closes its gates as its lease expires. Users
get read-only on all sites. The split heals when the network does.

If the witness is on a third network segment and can reach a majority
with one site, that side keeps its quorum and acts.

### Witness goes down

With the witness down, 3 of 4 voters remain. The vote threshold is 3,
so the group still has a majority as long as all three leader sites
are up. If one of them goes down too, only 2 votes remain: no majority,
no lease renewal, gates close (read-only everywhere).

### Group leader goes down

1. The existing leader election runs (the leader lease expires, a new
   leader campaigns, wins the vote).
2. The new group leader finds the expired site's clusters (the old
   leader's) without a home.
3. It proposes a new assignment to the remaining leader sites.
4. The vote applies; the takeover wait gives the old leader time to
   close its gates.

### Old home comes back

The returning instance has a stale `homes_epoch`. Its
`is_active_for(cid)` checks fail because it compares its epoch against
the one in the group state. It catches up on its next snapshot pull,
which brings the current `homes` and `homes_epoch`. Only then does it
act on the clusters now assigned to it.

## What stage 1 does not do

- No web UI (the admin route is API only).
- No packaging changes, installer changes, or witness-installation
  changes.
- No changes to the existing leader election, the leader lease, or the
  snapshot format when the switch is off.
- No multi-writer for global tables; the group leader still writes
  them alone.
- No cross-site console routing (a console goes to the instance the
  browser is connected to, as today).
- No bandwidth management for the change log on WAN links.

## Decisions

- The vote threshold is 3 of 4, matching the existing leader lease
  renewals. A 2-of-4 majority would let two sides both think they have
  quorum during a partition.
- The witness accepts any homes proposal from the group leader. This
  is the same trust model as leader votes: the witness cannot tell
  which cluster belongs where, so it trusts the group leader the group
  already trusts to run the election.
- `homes` lives in the group state file, not in the database. It
  spreads with the member list, is atomic with it, and never enters
  the snapshot the standby applies (the standby gets it from
  `_adopt_group`, the same way it gets `serve`).
- A cluster without a home entry defaults to the group leader. This
  is the safest default: a new cluster starts on the instance that
  already writes global data, and the group leader can move it to
  another site once the operator says so.
- The change log is in the same database as the tables it tracks, in
  the same transaction. A separate log database would need its own
  two-phase commit, which stage 1 does not attempt.
