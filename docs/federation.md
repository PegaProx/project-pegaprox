# Federation: PegaProx instances at several sites

> **Experimental.** The federation is new and off on every install until an admin
> switches it on. Try it with test instances before you rely on it. Once an instance has
> paired, it has to leave the federation before it can be switched off again.

A federation joins up to eight PegaProx instances, one per site. Each site keeps leading
its own clusters; the federation adds four things on top:

- **Accounts travel.** Users, API tokens and passkeys of each site are mirrored to the
  other sites. A mirror is read-only: an account is changed at the site it belongs to
  (its home), and the other sites refuse the change. A mirrored account signs in at
  another site only after an admin there has mapped its tenant (and a custom role) onto
  one of that site.
- **Enrolled clusters are written only with a majority.** A Proxmox VE cluster you enroll
  is written by its site only while a majority of the sites backs that site's lease on
  it. When the network splits, the side without the majority stops writing to it instead
  of two sites writing at once.
- **Clusters of a lost site can be adopted.** Every site holds a copy of every enrolled
  cluster's row. When a site is gone for good, another one takes its clusters over.
- **One view of everything.** The Federation tab lists the clusters of every site, asked
  live at the site that leads them.

Contents: [Switch it on](#switch-it-on) - [Pair two sites](#pair-two-sites) -
[What pairing shares](#what-pairing-shares) - [Accounts of other sites](#accounts-of-other-sites) -
[Enrolled clusters and leases](#enrolled-clusters-and-leases) -
[Adopting a cluster](#adopting-a-cluster) - [Removing a site, leaving](#removing-a-site-leaving) -
[HA groups](#ha-groups) - [Limits](#limits) - [Switch it off](#switch-it-off) -
[API](#api) - [Troubleshooting](#troubleshooting)

## Switch it on

Open **Settings > Federation** as an admin who sees every cluster (an admin confined to a
tenant or to some clusters does not get the tab). The card at the top is the switch.
Switching on asks once more, then this instance creates its federation identity (an
instance id and its keys) and starts two background jobs: the identity sync, every 60
seconds, and the lease rounds, every 10 seconds. No restart is needed, and nothing is
shared until you pair it with another instance.

Behind the card is the server setting `federation_enabled` (off by default). It belongs to
the whole deployment: on an HA group it travels to the standbys with the settings sync.
The general settings form does not save it; only the switch does, and every switch is in
the audit log (`federation.switched_on`, `federation.switched_off`). The server reads the
setting through a cache of five seconds, so a standby that receives it follows within
that time.

The environment variable `PEGAPROX_FEDERATION` overrides the setting:

| Value | Effect |
|---|---|
| `1` | always on |
| `0` | always off |
| unset or empty | the setting decides |
| anything else | ignored, with one warning in the log; the setting decides |

A forced value cannot be changed in the UI: the switch is greyed out and says which value
the server was started with, and the API answers `409 FED_FORCED`. Change the variable
where the service is started (a systemd drop-in with
`Environment=PEGAPROX_FEDERATION=1`, or `-e PEGAPROX_FEDERATION=1` for Docker) and restart
the service.

While the federation is off, every route under `/api/federation/` answers
`404 FED_DISABLED`, except the status and the switch itself, and nothing of it runs.

## Pair two sites

Every instance must reach every other one over HTTPS at the address you give it. Private
networks are fine; plain HTTP, redirects and cloud metadata addresses are refused.

1. On the first instance, switch the federation on and fill in **Start a federation**:
   its own address (as the others will reach it), a site label such as `berlin`, and your
   password. **Create code** shows a one-time code (`pgxfd1_...`). It is valid for 15
   minutes and one join; a new code replaces an open one.
2. On the second instance, switch the federation on and fill in **Join a federation**:
   the code, this instance's own address and its site label, and your password.
3. For the next site, use **Add a site** on any instance that is already a member and
   join with that code. Joining takes the agreement of a majority of the members.

Pairing, joining, removing, leaving, enrolling, releasing, unenrolling and adopting all ask
for the account password again, as the HA pairing does. An account that signs in through
OIDC and has no password must have signed in within the last 10 minutes instead. API
tokens cannot do these steps.

**Certificates.** With PegaProx's own self-signed certificate, the code carries its
fingerprint and the other instances pin it. Behind a reverse proxy, or with a certificate
from a CA, they check it against the CA as any HTTPS client does.

**Clocks.** Every call between members is signed with the sender's key and is valid for
two minutes. Keep the clocks of all sites within that (NTP); a member whose clock is
further off is refused with `FED_CLOCK`.

## What pairing shares

With every other member, an instance shares:

- its member record: instance id, public signing key, address, site label and
  certificate fingerprints;
- the accounts homed at it: users with their password hashes, API tokens as hashes, and
  the public keys of passkeys;
- the rows of the clusters it enrolled, with their credentials (password, API token
  secret, SSH key) sealed under its **federation key**, a key of its own that exists only
  for this purpose;
- its federation key, which the members fetch over a signed call. So every member can
  open the credentials of every enrolled cluster: that is what lets a member adopt the
  cluster when the owner is gone;
- on request, the names, types, node and guest counts of all its clusters (the linked
  view). Nothing else of a cluster that is not enrolled ever leaves the instance.

It never shares:

- **its database master key**, nor the key file that seals the fields of its own
  database. Every instance keeps its own;
- TOTP secrets. A mirrored account that uses TOTP signs in at its home, or uses a passkey
  as the second factor elsewhere;
- credentials of clusters that are not enrolled;
- sessions, and the personal settings of a user (theme, layout, language and the like).

The trust this takes: the admins of every member are admins of the federation. The
federation protects against honest faults (network splits, restarts, failovers, old
backups); it does not protect against a member whose admins act against the others.
Removing such a member by majority is the remedy, see below: no single member can change
the member list on its own, its own removal included, because every change carries the
signed agreement of a majority. Pair only instances whose admins you trust as your own.

## Accounts of other sites

Nothing an account names resolves by name on another site: a tenant called `customer` at
one site and a tenant called `customer` at another are not the same, and neither are two
`default` tenants. So a mirrored account arrives **quarantined**: it is stored, but
disabled and without tenant or role, and it cannot sign in until an admin of the
receiving site maps what it names.

- Its **tenant** always needs a mapping onto a tenant here, `default` included.
- Its **role** passes as it is when it is one of the built-in roles (admin, user,
  viewer). A custom role needs a mapping onto a role here; custom roles themselves do not
  travel.
- Per-tenant overrides of the account need their tenants and roles mapped as well; an
  override is never dropped to make an account fit.
- A mirrored API token comes along only when its role is a built-in one or a mapped one.

**Accounts of other sites** in the tab lists, per site, every tenant and custom role its
accounts name, with how many accounts name it. **Map** asks for your password; the site
is then pulled at once, and if it does not answer, its accounts follow at the next sync.
**Remove mapping** asks for nothing and takes effect at once, even while the other site
is unreachable: the accounts that resolved through it are quarantined again and their
sessions end. Mappings stay when a site stops naming a value for a while, travel to the
standbys of an HA group, and go when the site is removed or this instance leaves. A site
can fill at most 256 mapping entries here; values beyond that stay unmapped and their
accounts quarantined.

The users list marks mirrored accounts as **Mirrored** and offers no changes for them.

**Directory and single sign-on accounts.** An account that comes from LDAP or OIDC at its
home signs in at its home only. Mirrors carry no LDAP or OIDC link (no `oidc_sub`, no
directory groups), and the directory and the identity provider of another site never
take a mirror over or sign it in. Once mapped, the account's API tokens work at the other
sites as well.

**Passwords and second factors stay at the home.** A mirrored account with TOTP signs in
at another site only with a passkey; without one it is sent to its home
(`409 FED_2FA_HOME`). A passkey belongs to the domain it was registered for, so one
registered at the home works only at sites that serve the same domain. Password changes,
password resets and enrolling a second factor happen at the home; the other sites refuse
them (`409 FED_FOREIGN`), and a mirrored account whose home asks for a new password is
sent there to set it (`409 FED_PASSWORD_HOME`). A site that forces two-factor
authentication for everybody cannot be used by a mirrored account without one.

**Admins of this instance.** Only this instance's own admins count for the protection of
the last admin: a mirrored admin does not, because removing its site drops the account.

## Enrolled clusters and leases

**Clusters under federation rule** lists the clusters this instance enrolled; **Not
enrolled yet** lists its local Proxmox VE clusters, all of them, with a filter once there
are more than twelve. Enrolling needs:

- three or more sites. With two, any outage of one would stop the other from writing;
- a Proxmox VE cluster. PBS servers, QNetd hosts, XCP-ng pools and ESXi hosts are not
  enrolled and not fenced.

The enrolling site holds a lease of 30 seconds on the cluster, renewed every 10 seconds
by a majority vote of the sites. A cluster id can be enrolled by one site only: an enroll
of an id another site leads is refused, and the local cluster stays as it was. Every write PegaProx sends to that cluster (API calls,
SSH commands, background jobs such as balancing and rolling updates) is checked against
the lease first. Without a live lease the write is not sent: the API answers
`409 FED_NO_LEASE` and the UI says so. A plain restart of the service keeps the leases
and the votes a site gave. A site whose host rebooted, that took over in its HA group, or
that lost its lease file closes its leases and votes for nobody for 35 seconds, so no
promise it gave before can be broken.

- **Renew** runs one round now. If the majority does not back the lease, the tab says so
  as an error: writes stay closed until it does.
- **Hand over** releases the lease so another site can adopt the cluster. The cluster
  stays enrolled here and is not written from here until you enroll it again.
- **Unenroll** makes the cluster this instance's alone again. It needs the live lease and
  a majority of the sites confirming that they dropped their copy. When the other sites
  are gone for good and none of them adopted it, unenroll with force (offered after the
  refusal); if a site did adopt it meanwhile, two sites then write to it.

Every site remembers which enrolled clusters it dropped its copy of, and which site led
them (up to 512). A site that was cut off while its cluster was adopted, and maybe
unenrolled by its new owner later, finds a majority naming the new leader when it comes
back: its row becomes a copy of that site's cluster and it stops writing to it.

## Adopting a cluster

**Shadows** lists the copies of clusters other sites enrolled. **Take over** adopts one.
It works only when:

- the owner does not answer, or it handed the cluster over;
- the owner is still a member: adopt the clusters of a lost site **before** you remove it,
  because removing it deletes its copies;
- a majority of the sites grants this instance the lease, past the old owner's lease;
- the member list has not changed in the last 35 seconds at the sites that vote. A lease
  counted before two changes of the member list could otherwise still run while a
  majority of the new list backs the adoption; the tab then says to try again shortly;
- this instance holds the owner's federation key. Without it, adopt with force: the
  cluster comes over without its credentials, and you enter them again.

The credentials are opened with the owner's federation key and stored under this
instance's database key. The root passwords stored per node and the old site's HA claim on the
cluster do not come along. If the cluster cannot be reached right after the adoption, the
adoption stands and the connection is tried again at the next start.

## Removing a site, leaving

**Remove** takes a member out, with a majority of the federation behind it. This
instance, and every member that hears of it, deletes the removed member's mirrored
accounts (their sessions end), its cluster copies and its federation key. The answer
names the members that did not confirm; they take the new member list from the first
member they reach that has it, replaying the changes since their own list, each signed by
a majority. The tab warns before a removal that deletes copies of the member's clusters.

A change of the member list (a join, a removal, a leave) counts only once a majority of
the members took it. When fewer confirm, the change is refused with `FED_NO_QUORUM` and
nothing changes on the instance that made it; a member that took it anyway goes back to
the list the others hold at its next sync. One change runs at a time: a member that keeps
the lock on the member list for more than 30 seconds is made to wait, so it cannot block
its own removal.

**Leave** takes this instance out. Its enrolled clusters are unenrolled first; one without
a live lease blocks the leave, and the tab then offers to leave with force (that cluster
stays enrolled here and closed, unenroll it with force afterwards). The leave itself
needs a majority like any other change; forced, it goes ahead here alone. This instance
then deletes every membership, every mirrored account and cluster copy and every key of
the others; the others delete what they held of it as they hear of it.

**Clusters enrolled here, after a removal or a leave.** A site that was removed, or left
with force, keeps the clusters it had enrolled, closed and released: the federation may
have adopted them meanwhile. Such a site pairs with nobody (`409 FED_ENROLLED`) until its
admin unenrolls those clusters with force, which makes them its own again. Check first
that no other site adopted them.

**What stays behind.** Whatever a site already holds when it is removed, or when you
leave, stays readable there if that site kept it (because it never heard of the change,
or because it has a backup): the credentials of the clusters that were enrolled here, and
the password hashes of the accounts that were homed here. The federation cannot take
those back. If that matters, **change the credentials of those clusters** (the password,
API token or SSH key on the cluster, and the same in its PegaProx connection settings)
and have the users change their passwords. After a removal, the tab lists the clusters
whose credentials the removed site may still hold. New credentials only travel to the
sites that are still members.

## HA groups

An HA group of PegaProx instances (an active and its standbys) is **one** member of a
federation:

- its federation identity (instance id, keys, member list) lives in the database and
  travels to the standbys with the HA sync, so a standby that is promoted carries on as
  the same member; at the promotion its leases close and it waits the 35 seconds
  described under [Enrolled clusters and leases](#enrolled-clusters-and-leases);
- pair and manage it on the active. A standby answers the other sites with
  `503 FED_STANDBY` and does not pair;
- use the group's service address as the address of the site; the fingerprints of all
  hosts of the group are pinned, so the federation keeps reaching the group after a
  failover;
- an instance that is a member of a federation cannot join another HA group as a standby
  (`409 FED_MEMBER`): it would take over the identity of that group's active. Leave the
  federation first.

## Limits

- **Eight sites** at most, this instance included. The tab offers a pairing code while
  one more site fits.
- **Three sites** before a cluster can be enrolled.
- **Proxmox VE clusters only** under leases.
- **100 clusters per site** in the linked view; for a site with more, the tab says how
  many are not listed.
- **Experimental**: the protocol may still change between releases. Keep all sites on the
  same PegaProx version.

## Switch it off

Switching off is refused (`409 FED_IN_USE`) while the instance still takes part: while it
is a member, leads enrolled clusters, or holds accounts or clusters of other sites. The
switch card says which of these holds it, and the answer says to leave the federation
first. So:

1. unenroll the clusters this instance enrolled, or let **Leave** do it;
2. **Leave** the federation;
3. switch it off. The background jobs stop at once, without a restart.

`PEGAPROX_FEDERATION=0` forces the federation off without leaving, and it is meant for an
emergency only. On a site that still takes part:

- its enrolled clusters and the cluster copies of other sites are not read at all: no
  manager runs for them and nothing is written to them, because nothing fences those
  writes while the federation is off;
- mirrored accounts count as disabled: they cannot sign in, and their sessions, API
  tokens, consoles and live streams are refused;
- the other sites see it as unreachable and keep counting it in their majorities. After
  35 seconds they may adopt its clusters.

To take a site out for good, leave the federation first. A database of a federation
member restored onto a plain install behaves the same while the federation is off there.

## API

The admin routes take a session or an admin API token, like the rest of the API, and a
state-changing call passes the same CSRF check as every other API write. The steps that
need the password, as listed above, refuse API tokens. All of them are in `docs/openapi.json`.

| Route | What it does |
|---|---|
| `GET /api/federation/status` | the switch (`enabled`, `forced`, `can_disable`, `disable_blockers`), and while on this instance and its members |
| `POST /api/federation/switch` | `{"enabled": true}` or `false` |
| `POST /api/federation/pairing-code` | a one-time code for the next site |
| `POST /api/federation/join` | join with a code |
| `POST /api/federation/members/<id>/remove` | remove a member (`{"confirm": "REMOVE"}`) |
| `POST /api/federation/leave` | leave (`{"confirm": "LEAVE", "force": false}`) |
| `POST /api/federation/sync` | pull the accounts of every member now |
| `GET`, `POST /api/federation/identity-map` | the tenants and roles of the other sites and their mappings; map one (`{"home", "kind", "home_value", "local_value"}`, `""` takes a mapping away) |
| `GET /api/federation/leases` | the leases this instance holds, and the enrolled clusters it knows with their owners |
| `GET /api/federation/clusters` | the linked view |
| `POST /api/federation/clusters/<id>/enroll`, `release`, `unenroll`, `adopt`, `renew` | the cluster steps above |

The routes under `/api/federation/peer/` are for the members only. They take no session:
each call is signed with the calling member's key and every answer is signed back.

## Troubleshooting

| Code | Meaning |
|---|---|
| `FED_DISABLED` | the federation is switched off on that instance |
| `FED_FORCED` | `PEGAPROX_FEDERATION` decides; change it where the service starts |
| `FED_IN_USE` | switching off while still taking part: leave first |
| `FED_REAUTH`, `FED_REAUTH_RECENT` | the password is missing or wrong; an OIDC account without a password signs in again first |
| `FED_FULL` | eight sites already |
| `FED_NO_QUORUM` | no majority answered or agreed; check the network between the sites. Right after a change of the member list, an adoption waits 35 seconds |
| `FED_TOO_FEW_SITES` | enrolling needs three sites |
| `FED_NO_LEASE` | this instance holds no live lease on the cluster; another site may lead it, or the lease ran out in a split |
| `FED_LEAVE_BLOCKED` | an enrolled cluster has no live lease; leave with force, then unenroll it with force |
| `FED_FOREIGN` | the account or cluster belongs to another site; change it there |
| `FED_2FA_HOME` | a mirrored account with TOTP and no passkey signs in at its home |
| `FED_PASSWORD_HOME` | the home of a mirrored account asks for a new password; set it there |
| `FED_ENROLLED` | this instance left (or was removed from) a federation with clusters still enrolled; unenroll them with force before it pairs again |
| `FED_STANDBY` | a standby of an HA group; use its active |
| `FED_MEMBER` | an instance in a federation cannot become an HA standby; leave first |
| `FED_CLOCK` | the clocks of two sites are more than two minutes apart |

The log lines of the federation start with `[FED]`.
