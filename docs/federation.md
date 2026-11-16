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
- **Enrolled clusters are fenced.** With three or more sites, a Proxmox VE cluster you
  enroll is written by its site only while a majority of the sites backs that site's lease
  on it; when the network splits, the side without the majority stops writing to it. With
  two sites the owner writes on its own, and the other site takes a cluster over only when
  an admin there confirms that the owner is down (see [Two sites](#two-sites)).
- **Clusters of a lost site can be taken over.** Every site holds a copy of every enrolled
  cluster's row. When a site is gone, another one takes its clusters over: by majority
  with three or more sites, by hand with two.
- **One view of everything.** The Federation tab lists the clusters of every site, asked
  live at the site that leads them.

Contents: [Switch it on](#switch-it-on) - [Pair two sites](#pair-two-sites) -
[What pairing shares](#what-pairing-shares) - [Accounts of other sites](#accounts-of-other-sites) -
[Enrolled clusters and leases](#enrolled-clusters-and-leases) - [Two sites](#two-sites) -
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
`404 FED_DISABLED`, except the status and the switch itself, and nothing of it runs, with
one exception: an HA standby that unpairs drops the federation identity it holds (see
[HA groups](#ha-groups)).

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

If the joining instance gets no answer (the network broke off right after the others had
taken it in), join again with the same code: until it runs out, the code answers that
same instance once more, and no other.

Pairing, joining, removing, leaving, enrolling, releasing, unenrolling, adopting and taking
over by hand all ask for the account password again, as the HA pairing does. An account
that signs in through OIDC and has no password must have signed in within the last 10
minutes instead. API tokens cannot do these steps.

**Certificates.** With PegaProx's own self-signed certificate, the code carries its
fingerprint and the other instances pin it. Behind a reverse proxy, or with a certificate
from a CA, they check it against the CA as any HTTPS client does.

**Clocks.** Every call between members is signed with the sender's key and is valid for
two minutes. Keep the clocks of all sites within that (NTP); a member whose clock is
further off is refused with `FED_CLOCK`. A clock that NTP steps back a little does not
interrupt the leases. On Linux that holds across a restart of the service too; where the
system gives no boot clock or boot id (PegaProx on Windows or macOS), every start of the
service counts as a reboot (see [Enrolled clusters and leases](#enrolled-clusters-and-leases)).

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
  view). The id of a cluster goes with it only once the cluster is enrolled. Nothing else
  of a cluster that is not enrolled ever leaves the instance.

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
signed agreement of a majority and the signature of the member that made it. A member
that hands a change on to a site that is behind cannot alter it, and it cannot change
the address or the certificate another member has at that site. Pair only instances
whose admins you trust as your own.

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
An account that its home deletes goes at the next sync, with what was granted to it here,
and its sessions end. One that its home still lists but whose row does not read is kept
with its grants, disabled and signed out, until a row that reads arrives; the audit log
says so.

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
sent there to set it (`409 FED_PASSWORD_HOME`). Where a site forces two-factor
authentication for everybody, a mirrored account counts as enrolled once it has a passkey
from its home; without one it cannot use that site, and it enrolls at its home.

**Admins of this instance.** Only this instance's own admins count for the protection of
the last admin: a mirrored admin does not, because removing its site drops the account.
A mirrored admin cannot change the federation of this instance (pair, remove, leave,
enroll, adopt, take over, map) or start a catch-up, an account pull or a lease round, and
it does not administer this instance's accounts, tenants and roles either: creating,
changing or deleting a user, setting its password, resetting its second factor or its
OIDC sign-in binding, resetting the password age of every account, restoring a
configuration backup, and the tenant and role pages answer `403 FED_MIRROR_ADMIN`.
Otherwise it could create a local admin and make those changes under that account.

For the same reason it does not change who signs in here through LDAP or OIDC, or with
which role:
- the role: the group mappings, the admin, user and viewer groups, the default role and
  the automatic creation of accounts of both, and for LDAP the group search base and
  filter (which decide the groups a user is found in);
- the source: whether LDAP and OIDC are on, the LDAP server, port, TLS settings, CA,
  bind DN and password, base DN, user filter and username attribute, and the OIDC
  provider, cloud, authority, tenant, client id and secret, audiences, username claim and
  its verification switches. A directory or provider it runs would hand the groups above
  to any account it makes up there.

A save of the server settings that changes any of them is refused as a whole with
`403 FED_MIRROR_ADMIN`, before anything of it is stored. The settings page sends the
whole form, so a mirrored admin that saves other settings with these as they are stored
(the passwords as the mask) is not refused. The sign-ins themselves are unchanged.

## Enrolled clusters and leases

**Clusters under federation rule** lists the clusters this instance enrolled; **Not
enrolled yet** lists its local Proxmox VE clusters, all of them, with a filter once there
are more than twelve. Enrolling needs:

- two or more sites. With two, both must answer when you enroll, see
  [Two sites](#two-sites);
- a Proxmox VE cluster. PBS servers, QNetd hosts, XCP-ng pools and ESXi hosts are not
  enrolled and not fenced.

The enrolling site holds a lease of 30 seconds on the cluster, renewed every 10 seconds
by a majority vote of the sites (with two sites, see [Two sites](#two-sites)). A cluster
id can be enrolled by one site only: an enroll of an id another site leads is refused,
and the local cluster stays as it was. Every
write PegaProx sends to that cluster (API calls, SSH commands, background jobs such as
balancing and rolling updates) is checked against the lease first. Without a live lease
the write is not sent: the API answers `409 FED_NO_LEASE` and the UI says so. The check
is made again once the connection of a request is up, so a connect that stalls past the
end of the lease sends nothing. What is still under way on the cluster when the lease is
handed over or runs out (a node command such as an upgrade or a copy, an open SSH or SFTP
connection) is stopped, at once for a hand-over or when another site turns out to lead
the cluster, and within a second for a lease that ran out. An upgrade cut off this way
stops half way: finish it on the node (`dpkg --configure -a`, then the upgrade again).
That holds for what a write went out through: a command or a connection that only reads
(a page that lists, a status read over SSH) needs no lease and is left to finish. One
write passes without the lease: the thaw of a guest's file systems after a snapshot froze
them. Each thaw follows a freeze of the same run, and that freeze needed the lease. Sent
after the lease went, the worst a thaw does is end a freeze another site made for its own
snapshot, which is then only crash-consistent; refused, the guest would hang on every
write until somebody thaws it by hand. Runs that start in several steps (a failover, a
test failover and its cleanup, a failback, a cross-cluster migration, a multi-cluster
vnet) check the lease of the clusters they write before they start; a dry run only reads
and needs none. On Linux a
plain restart of the service keeps the leases and the votes a site gave (a lease a site of
two held alone waits for the first renewal after the start, about 10 seconds): the leases run
on the boot clock, which goes on through the restart, and the boot id tells a restart from a
reboot. Where either is missing (PegaProx on Windows or macOS), a restart counts as a reboot.
A site whose host rebooted, that took over in its HA group, that lost its lease file, or that
restarted without that clock closes its leases and votes for nobody for 35 seconds, so no
promise it gave before can be broken. An
active that takes its first standby, or leaves its HA group, stays the same host and
keeps its leases and votes.

**After a change of the member list** (a join, a removal, a leave) every site backs no
lease for 35 seconds, renewals included: a lease counted before two such changes could
otherwise still run while a majority of the new list backs another site. So writes to
enrolled clusters pause after each change, for up to about half a minute, and the leases
come back by themselves. With two sites the owner's own lease pauses the same way. An
enroll right after a pairing is refused with the same reason; try again a little later.

- **Renew** runs one round now. If the majority does not back the lease, the tab says so
  as an error: writes stay closed until it does.
- **Hand over** releases the lease so another site can adopt the cluster. It stops at
  once what this instance still runs on the cluster (a node upgrade, a copy, an open SSH
  connection). The cluster stays enrolled here and is not written from here until you
  enroll it again. The hand-over is kept with the federation identity, so it also holds
  after a failover of an HA group or a lease file that was removed.
- **Unenroll** makes the cluster this instance's alone again. It needs the live lease and
  a majority of the sites confirming that they dropped their copy, and it stops nothing
  that runs on the cluster. When the other sites are gone for good and none of them
  adopted it, unenroll with force (offered after the refusal); if a site did adopt it
  meanwhile, two sites then write to it.

Every site remembers which enrolled clusters it dropped its copy of, and which site led
them, where it saw that site lead the cluster itself (up to 512). A site that deletes a
cluster it leads keeps such a record of it too. Past that, the site
named most often loses its oldest records first. A site that was cut off while its cluster
was adopted, and maybe unenrolled by its new owner later, finds a majority naming the new
leader when it comes back: its row becomes a copy of that site's cluster and it stops
writing to it.

## Two sites

A federation of two sites enrolls clusters too. One of two is no majority, so it works
differently from three or more sites:

- **The owner keeps writing.** Enrolling needs both sites to answer. After that the site that
  enrolled a cluster renews its lease every 10 seconds with the other site, and while the other
  site gives no answer at all (it is down, its PegaProx is stopped or switched off, the link
  between the sites is cut) it renews the lease alone and keeps writing. The tab shows the lease
  as **held alone**. A site that answers but does not agree (another member list, a clock more
  than two minutes off) stops the renewal instead: the writes wait until the two agree again. To
  let a site write alone in that case, stop PegaProx at the other one.
- **Nothing moves on its own.** The other site never takes a cluster over by itself, however
  long the owner stays silent. **Take over** works only when the owner answers and handed the
  cluster over.
- **Manual takeover, when the owner is down.** An admin of the other site takes the cluster
  over with **Manual takeover** on the cluster, or **Take over all by hand** on the site, the
  counterpart of `pvecm expected 1` on a Proxmox VE cluster. It asks for the password, the word
  `TAKEOVER` and a tick that the owning site is down. It is refused while the owner answers
  (`FED_OWNER_ALIVE`: use **Hand over** there) and for 35 seconds after this site last heard
  from it (`FED_OWNER_RECENT`).

**The risk is the admin's.** A takeover cannot tell a site that is down from a link that is
down. If the owning site still runs, both sites write to the cluster from the takeover on,
until they reach each other again. Take over only when you know that the owning site is down:
its PegaProx stopped, its hosts are off, or the site is offline.

**When the old owner comes back.** A takeover is signed and carries a number that grows with
every change of the cluster's owner. The site that took over sends it with its calls to the old
owner until the old owner confirms it, puts it in its answers to the old owner, and both sites
compare all such records once a minute. At the first contact the old owner stops at once what
it still runs on the cluster (as at a hand-over), turns its row into a copy of the new owner's
and drops its copy of the credentials; the new owner's copy follows with the next sync. Nothing
it changed in PegaProx after the takeover is taken over. What it sent to the cluster in the
meantime cannot be undone: the tab of both sites shows when the takeover happened and when the
old owner stopped, so you can check the cluster's task log for that span. If the site that took
over is down too when the old owner starts again, the old owner writes again until it reaches
the other site. The same holds for a site whose database was restored from a backup taken
before a takeover, or before it handed over a cluster that the other site then took over.

**Restarts and HA groups.** On Linux a plain restart keeps the leases both sites backed; a
lease held alone waits for the first renewal after the start, about 10 seconds, so a site that
was taken over hears of it before it writes. A site whose host rebooted, whose HA group failed
over, or whose service restarted without a boot clock (see
[Enrolled clusters and leases](#enrolled-clusters-and-leases)) writes nothing for 35 seconds,
then alone again if the other site is silent. A standby never
takes a cluster over. A standby that the HA sync last reached before a cluster moved to the
other site (a takeover, or a hand-over the other site took over) still has the cluster as its
own: if the group fails over to it while the other site cannot reach it, it writes the cluster
alone after those 35 seconds, beside the site that leads it now, until the two reach each other.
Then it stops at once.

**Moving a cluster back.** Hand it over at the site that has it, then **Take over** at the other
one while both answer.

**A third site** makes the federation decide by majority again. The join needs both sites, and a
takeover the other site has not confirmed yet holds the join off for a few seconds. After the
join every site holds every lease for 35 seconds, so there is no moment with two writers; writes
to enrolled clusters pause for up to about half a minute.

**Back to two sites.** After the member list shrinks to two, a site writes a cluster alone only
once the other site has answered for that cluster once. If the other site is down at that moment,
the cluster waits until it answers.

**Keep a local admin account at each site.** In a disaster the accounts of the lost site are
copies at the other one, and a copied account does not take clusters over
(`FED_MIRROR_ADMIN`).

## Adopting a cluster

**Shadows** lists the copies of clusters other sites enrolled. With three or more sites,
**Take over** adopts one. It works only when:

- the owner does not answer, or it handed the cluster over;
- the owner is still a member: adopt the clusters of a lost site **before** you remove it,
  because removing it deletes its copies;
- a majority of the sites grants this instance the lease, past the old owner's lease;
- the member list has not changed in the last 35 seconds at the sites that vote (see
  [Enrolled clusters and leases](#enrolled-clusters-and-leases)); the tab then says to try
  again shortly;
- this instance holds the owner's federation key. Without it, adopt with force: the
  cluster comes over without its credentials, and you enter them again.

The credentials are opened with the owner's federation key and stored under this
instance's database key. The adoption is kept with the federation identity until the other
sites hold the new owner, so a standby of this instance that takes over right after it
carries on with the adopted cluster. The root passwords stored per node and the old
site's HA claim on the cluster do not come along. If the cluster cannot be reached right
after the adoption, the adoption stands and the connection is tried again at the next
start.

With two sites, adopting needs the owner to answer and to have handed the cluster over; a
cluster whose site does not answer is taken over by hand (see [Two sites](#two-sites)).

## Removing a site, leaving

**Remove** takes a member out, with a majority of the federation behind it. This
instance, and every member that hears of it, deletes the removed member's mirrored
accounts (their sessions end), its cluster copies and its federation key. A member that
hears of it disables those accounts at once and deletes them, with the mappings of their
tenants and roles, once it sees that a majority took the removal: a removal that too few
took is rolled back, and the mappings would not come back with the accounts. If it is
rolled back, those accounts sign in again after the next sync with their site (every 60
seconds, or **Sync now**); the sessions that ended do not come back. A member
that the removal leaves alone in the member list (the other site of a federation of two
left, or was removed) has nobody left who could roll it back: it deletes them at once,
and they no longer keep its switch on. The answer names the members that did not confirm;
they take the new member list from the first member they reach that has it, replaying the
changes since their own list, each signed by a majority. The tab warns before a removal
that deletes copies of the member's clusters.

**With two sites** a removal needs both. When the other site is gone for good, take over the
clusters of it you want to keep, then **Remove** it with *gone for good*. This is refused while
it answers, and for 35 seconds after this site last heard from it. Clusters of it you did not
take over are named once more, and their copies are dropped only after you confirm. This site
then carries on alone: the federation ends here, the clusters it leads become its own again (they
do not close), and the accounts, mappings and cluster copies of the other site are deleted here.
This site keeps what it needs to tell the other site: if that site comes back after all and
calls here, it is told at once, stops writing every cluster this site kept, drops its copies of
them, and its other clusters become its own. That works only while this site keeps the
federation switched on and keeps its address. Afterwards this site can pair with a new site as a
new federation.

A change of the member list (a join, a removal, a leave) counts only once a majority of
the members took it. When fewer confirm, the change is refused with `FED_NO_QUORUM` and
nothing changes on the instance that made it; a member that took it anyway goes back to
the list the others hold at a later sync, once the members of the list before the change
that answer with another list are a majority of it. A confirmation that got lost does not
undo a change a majority took: the instance that made it takes it over from the others.
One change runs at a time: on one instance a second change is refused with `FED_BUSY`
while the first is under way, and a member that keeps the lock on the member list for
more than 30 seconds is made to wait, so it cannot block its own removal.

**Leave** takes this instance out. Its enrolled clusters are unenrolled first, all of them
in one step with each member; one without a live lease blocks the leave, and the tab then
offers to leave with force (that cluster stays enrolled here and closed, unenroll it with
force afterwards). The leave itself needs a majority like any other change; forced, it
goes ahead here alone. This instance then deletes every membership, every mirrored account
and cluster copy and every key of the others; the others delete what they held of it as
they hear of it. With two sites, when the other site leaves or you remove it with its
agreement, the clusters this instance enrolled become its own again at once: no site is left
that could hold them.

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
  the same member. Its own votes wait the 35 seconds described under
  [Enrolled clusters and leases](#enrolled-clusters-and-leases), while the other sites
  keep renewing its leases;
- a standby that leaves its group (**Unpair** on the standby, also after the active
  removed it) is a new standalone instance, not a second copy of the member: it drops the
  federation identity it held, the federation's cluster rows and mirrored accounts, and
  switches the federation off on itself. The active stays the member. This happens
  whenever the standby holds the identity, also when the federation is switched off on
  it (`PEGAPROX_FEDERATION=0` there, or the setting off): switched on later, it would
  otherwise act as the member next to the active. It is the one thing of the federation
  that runs while the switch is off. Should that drop fail (a database write refused), the
  federation stays off on that host, `PEGAPROX_FEDERATION=1` included, and the next start
  of the service tries the drop again;
- the active does not unpair while the federation is on and its group still has
  standbys (`409 HA_FEDERATION`): the standbys keep the identity, so the active and the
  group would both act as the same member. Remove the standbys on the active first (a
  standby that is gone for good is removed as before), or unpair them. Switching the
  federation off is no way around it: a standby promoted later would still hold the
  identity. The same holds while it is forced off with `PEGAPROX_FEDERATION=0` and still
  a member. An active without standbys unpairs as before and stays the member;
- pair and manage it on the active. A standby answers the other sites with
  `503 FED_STANDBY` and does not pair;
- use the group's service address as the address of the site; the fingerprints of all
  hosts of the group are pinned, so the federation keeps reaching the group after a
  failover;
- an instance that is a member of a federation cannot join another HA group as a standby
  (`409 FED_MEMBER`): it would take over the identity of that group's active. Leave the
  federation first;
- a manual takeover and a removal of a site that is gone for good run on the active only; a
  standby never takes over. The takeover is kept with the federation identity, so a standby
  promoted right after it carries on with the cluster; if the HA sync had not carried it yet,
  it comes back from the other site with the next sync. A standby that answers instead of its
  active counts as no answer for the other site of a federation of two.

## Limits

- **Eight sites** at most, this instance included. The tab offers a pairing code while
  one more site fits.
- **Two sites** before a cluster can be enrolled. With two, a cluster of a site that is down
  is taken over by hand.
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
  35 seconds they may adopt its clusters; with two sites, an admin there may take them over
  by hand, and switched on again this site gives them up at its first contact;
- a standby of its HA group that unpairs still drops the federation identity it holds,
  and the active does not unpair while it has standbys (see [HA groups](#ha-groups)).

After this instance removed a site as gone for good, switching off asks once more while that
site has not been told (`409 FED_ENDED_UNTOLD`): switched off, this instance can no longer
tell it.

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
| `POST /api/federation/members/<id>/remove` | remove a member (`{"confirm": "REMOVE"}`; with two sites and the other one gone for good, `"gone": true`) |
| `POST /api/federation/members/<id>/takeover` | take over by hand every cluster of that site, or the ones in `clusters`, two sites only (`{"confirm": "TAKEOVER", "owner_down": true, "force": false}`) |
| `POST /api/federation/leave` | leave (`{"confirm": "LEAVE", "force": false}`) |
| `POST /api/federation/sync` | pull the accounts of every member now |
| `GET`, `POST /api/federation/identity-map` | the tenants and roles of the other sites and their mappings; map one (`{"home", "kind", "home_value", "local_value"}`, `""` takes a mapping away) |
| `GET /api/federation/leases` | the leases this instance holds, and the enrolled clusters it knows with their owners |
| `GET /api/federation/clusters` | the linked view |
| `POST /api/federation/clusters/<id>/enroll`, `release`, `unenroll`, `adopt`, `renew` | the cluster steps above |
| `POST /api/federation/clusters/<id>/takeover` | take over by hand, two sites only (`{"confirm": "TAKEOVER", "owner_down": true, "force": false}`) |

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
| `FED_NO_QUORUM` | no majority answered or agreed, or a takeover is not known at every site yet; check the network between the sites. Right after a change of the member list, every lease waits 35 seconds |
| `FED_BUSY` | another change of the member list is under way on this instance; try again in a moment |
| `FED_MIRROR_ADMIN` | a mirrored admin changes neither the federation nor the accounts, tenants and roles of this instance, nor who signs in through LDAP or OIDC and with which role, nor restores a backup; use an account of this instance |
| `FED_TOO_FEW_SITES` | enrolling needs a second site |
| `FED_OWNER_ALIVE` | the owner of the cluster answers: hand the cluster over there, then take it over here |
| `FED_OWNER_RECENT` | the owner was in contact less than 35 seconds ago; try again after the time the answer names |
| `FED_USE_TAKEOVER` | two sites, and the owner does not answer: its cluster is taken over by hand |
| `FED_NOT_TWO_SITES` | a takeover by hand and a removal as gone for good are for a federation of two sites |
| `FED_HOLD`, `FED_SETTLING` | this host restarted or took over in its HA group, or the member list changed a moment ago; try again after the time the answer names |
| `FED_NOTHING_TO_TAKE` | the site leads no cluster this instance holds a copy of |
| `FED_PEER_ANSWERS`, `FED_PEER_RECENT` | the site to remove as gone for good answers, or was in contact less than 35 seconds ago: remove it with its agreement, or wait |
| `FED_GONE_CLUSTERS` | the site to remove still leads clusters here that were not taken over: take them over, or confirm that their copies are dropped |
| `FED_ENDED_UNTOLD` | switching off while a site removed as gone for good was never told; switch off anyway only when it is shut down for good |
| `FED_NO_LEASE` | this instance holds no live lease on the cluster; another site may lead it, or the lease ran out in a split |
| `FED_LEAVE_BLOCKED` | an enrolled cluster has no live lease; leave with force, then unenroll it with force |
| `FED_FOREIGN` | the account or cluster belongs to another site; change it there |
| `FED_2FA_HOME` | a mirrored account with TOTP and no passkey signs in at its home |
| `FED_PASSWORD_HOME` | the home of a mirrored account asks for a new password; set it there |
| `FED_ENROLLED` | this instance left (or was removed from) a federation with clusters still enrolled; unenroll them with force before it pairs again |
| `FED_STANDBY` | a standby of an HA group; use its active |
| `FED_MEMBER` | an instance in a federation cannot become an HA standby; leave first |
| `HA_FEDERATION` | the active of an HA group does not unpair while the federation is on and it has standbys; remove or unpair the standbys first |
| `FED_CLOCK` | the clocks of two sites are more than two minutes apart |
| `FED_UNAVAILABLE` | `503`: this instance cannot read right now where an account, an API token or another row is homed (a busy or unreadable database), so it refuses the change, a token revoke included, rather than guess; try again in a moment |

Registering or removing a passkey answers `503` without a code while the account cannot be
read, with the federation switched off as well: it may be a mirror. Try again in a moment.

The log lines of the federation start with `[FED]`.
