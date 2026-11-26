# Proxmox VE permissions

PegaProx talks to a Proxmox VE cluster over its API, and to the nodes over SSH for the
features that need a shell. `root@pam` with its password is the simple way to connect a
cluster: everything works. To keep the API access narrow, give PegaProx an account or an
API token of its own with a role that holds only what PegaProx uses. That role narrows the
API only: the features that need a shell still log in to the nodes over SSH as root or as a
user with `sudo` (see [What no role gives](#what-no-role-gives)).

The role is built from the same table the connection check compares a cluster's
privileges against (`pegaprox/core/conncheck.py`, `PRIVILEGE_NEEDS`). PegaProx shows it,
ready to copy, in two places:

- **Add Cluster**, Proxmox VE tab: *Least-privilege role for the API*;
- **Check connection** of a cluster: *Least-privilege role for PegaProx*.

Over the API it is `GET /api/pve-role-recipe` (permission `cluster.add` or
`cluster.config`), with `?features=` (a comma list of the optional features below, empty
for none, all of them without the parameter), `?pve=8|9`, `?user=`, `?token=` and
`?role=`.

## The role

Always in the role, for the features that use the API:

| Feature | Privileges |
| --- | --- |
| Node and cluster status | `Sys.Audit` |
| Guest list | `VM.Audit` |
| Start, stop and reboot | `VM.PowerMgmt` |
| Migration, load balancing, maintenance mode | `VM.Migrate` |
| Consoles | `VM.Console` |
| Snapshots | `VM.Snapshot`, `VM.Snapshot.Rollback` |
| Backups | `VM.Backup` |
| Creating and deleting guests | `VM.Allocate` |
| Cloning and templates | `VM.Clone` |
| Hardware changes | `VM.Config.CPU`, `VM.Config.Memory`, `VM.Config.Disk`, `VM.Config.Network`, `VM.Config.Options`, `VM.Config.CDROM`, `VM.Config.HWType`, `VM.Config.Cloudinit` |
| Guest agent data (IP addresses) | `VM.GuestAgent.Audit` (PVE 9), `VM.Monitor` (PVE 8) |
| Storage view | `Datastore.Audit` |
| Adding and moving disks | `Datastore.AllocateSpace` |
| Guest network cards on bridges and vnets | `SDN.Use` |
| Resource pools and pool-based access, the pool editor, guests created into a pool | `Pool.Audit`, `Pool.Allocate` |

Optional, each adds to the role:

| Feature | `features=` | Privileges |
| --- | --- | --- |
| ISO and template uploads | `uploads` | `Datastore.AllocateTemplate` |
| Node network and settings, apt refresh | `nodeConfig` | `Sys.Modify` |
| Node reboot and shutdown | `nodePower` | `Sys.PowerMgmt` |
| Node syslog | `syslog` | `Sys.Syslog` |
| SDN view | `sdn` | `SDN.Audit` |
| Resource mappings (PCI, USB, directories) and their editors | `mappings` | `Mapping.Audit`, `Mapping.Use`, `Mapping.Modify` |
| Storage replication jobs | `replication` | `VM.Replicate` |
| Proxmox HA resources and rules | `haConfig` | `Sys.Console` |
| Taking in guests from another cluster: cross-cluster migration and replication, Site Recovery | `remoteMigration` | `Sys.Incoming` |

The role goes on `/` and propagates, so it reaches every guest, storage and node.

Not in the recipe: the SDN editor (zones, vnets, subnets: `SDN.Allocate`) and adding or
changing storage, PBS included (`Datastore.Allocate`). A role for those needs the
privilege added by hand.

## With an API token (recommended)

Run on one node as root (PVE 9, every optional feature):

```
pveum role add PegaProx --privs "Sys.Audit,VM.Audit,VM.PowerMgmt,VM.Migrate,VM.Console,VM.Snapshot,VM.Snapshot.Rollback,VM.Backup,VM.Allocate,VM.Clone,VM.Config.CPU,VM.Config.Memory,VM.Config.Disk,VM.Config.Network,VM.Config.Options,VM.Config.CDROM,VM.Config.HWType,VM.Config.Cloudinit,VM.GuestAgent.Audit,Datastore.Audit,Datastore.AllocateSpace,Datastore.AllocateTemplate,VM.Replicate,SDN.Use,Pool.Audit,Pool.Allocate,Mapping.Audit,Mapping.Use,Mapping.Modify,Sys.PowerMgmt,Sys.Modify,Sys.Syslog,Sys.Console,SDN.Audit,Sys.Incoming"
pveum user add pegaprox@pve --comment "PegaProx"
pveum aclmod / --users pegaprox@pve --roles PegaProx
pveum user token add pegaprox@pve pegaprox --privsep 1 --comment "PegaProx"
pveum aclmod / --tokens 'pegaprox@pve!pegaprox' --roles PegaProx
```

The token keeps privilege separation: it holds what both the user and its own ACL allow,
so both get the role. `pveum user token add` prints the secret once. In PegaProx add the
cluster with `pegaprox@pve!pegaprox` as user name and the secret as password.

On PVE 8 write `VM.Monitor` instead of `VM.GuestAgent.Audit`. Where the role exists
already, `pveum role modify PegaProx --privs "..."` sets the list.

## With an account and password

The same role, without the token:

```
pveum role add PegaProx --privs "..."
pveum user add pegaprox@pve --comment "PegaProx"
pveum passwd pegaprox@pve
pveum aclmod / --users pegaprox@pve --roles PegaProx
```

Add the cluster with `pegaprox@pve` and that password. PegaProx creates an API token of
its own at the first login and keeps the password for what a token cannot do.

Under an API token policy of the cluster (Proxmox VE 9.3, Datacenter > Options > API Token
Policy) that token gets the longest lifetime the policy allows, a year where it only wants
an expiry. PegaProx keeps that end with the token in its database, since the role above
may not read its own token, and renews it before it ends: it looks at the end every five
minutes, and once two days are left (a fifth of the lifetime where that is less) it logs in
with the password, makes a new token, stores it and deletes the old one. It goes by the end
of the token, not by the policy of the day: a token that got an end is renewed also after
the policy was relaxed, and the new one then has none. Where there is no password
login, for an account with two-factor login or a cluster without a stored password, the
token renews itself: with a new token, stored before the old one is deleted. Only where
Proxmox refuses that and the policy lets a new secret extend the end (*Allow Extension on
Regenerate*) does it renew its secret in place, since Proxmox drops the old secret as it
does so. Proxmox lets a token do either only where its account may manage its own tokens:
`User.Modify` on the account's group, and for a token without privilege separation
`Permissions.Modify` on `/` and `Realm.AllocateUser` on the realm, all of which the
Administrator role has and the role above does not. When neither way works, PegaProx says
so once per lifetime of the token, in the log at warning level and as an alert to the push
notifications and the alert channels, with the time the token ends, and tries again six
hours later, sooner as the end comes near. A user.cfg lock or a restart of pveproxy is
tried again after a quarter of an hour and said only once half the time before the end is
gone. A new secret whose answer never arrives, or one the database of PegaProx could not
store (it tries again every few minutes, also while a refusal waits for its next try), is a
critical alert at once. A new token whose answer never arrives may still have been made:
PegaProx notes its name before it asks and deletes it at the next look, also after a
restart. A token made by an older PegaProx has no kept end; PegaProx reads it over the
token, or once over the password login. Where neither may read it, PegaProx says so once,
in the log at info level and without an alert, since a token made before the cluster had a
policy has no end at all. A kept end that has passed while Proxmox still takes the token,
as after its *Expire* was changed on the cluster by hand, counts as one neither may read.
What PegaProx starts by itself (the renewal, the cross-cluster balancer and scheduled
replication into a cluster whose token may make no token) counts every password login that
fails, refused or without an answer, as from a realm whose LDAP or AD server is slow or
down: each counts on a lockout of the realm and on a fail2ban of pveproxy. The next one
goes out after half an hour at the earliest, and a third only once the second is two days
old, the time the fail2ban jail in the Proxmox VE wiki keeps a count for its three tries, so
a directory that stays down does not get PegaProx's address banned. A migration started by
hand logs in at once, and a login that works ends the wait, as does a new password stored
for the cluster. Each renewal is in the audit log. A token typed in by hand, and
a cluster added with a token as its login, are never renewed; a token without an end, as
on a cluster that never had such a policy, sees no change. Should the
token still run out, PegaProx logs in with the password right away, makes a new one and
deletes the old one. An account with two-factor login cannot log in that way: the cluster
then says its token has expired, and needs an API token as its login or two-factor login
off for one connect. A policy that requires privilege separation gets
no such token, since it would hold no right without ACLs of its own: PegaProx stays on
password logins and logs a warning. *Rotate API Token* in the cluster settings gives the
token a new secret in place on Proxmox VE 9.2 and later (over the password login where
Proxmox refuses it to the token itself); before 9.2 it makes a new token and deletes the
old one after.

## What no role gives

- **SSH to the nodes**: node shell, rolling updates, SMBIOS auto configuration, custom
  node scripts, hardening and CVE checks, the self-fence agents of the 2-node HA, the
  transfer network check, file restore into containers and ESXi migration. Store an SSH
  key in the cluster settings (for root, or a user with `sudo`), or give single nodes a
  root password of their own under *Node credentials*. Every one of them logs in as the
  *SSH user* of the cluster, root when it is empty; a user other than root needs
  passwordless `sudo` on every node. The cluster password goes along only when the
  cluster is connected with that same `@pam` account (`root@pam` for root), never the
  password of a `@pve` or LDAP account. ESXi migration offers the key first and a
  password after it, and the target node itself needs port 22 of the ESXi host: the
  SSHFS mount runs there. A cluster can switch SSH off entirely.
- **root@pam**: raw PCI and USB devices on a VM, most LXC feature flags and creating or
  removing Ceph OSDs. Proxmox keeps these to `root@pam` and refuses them to every API
  token, `root@pam`'s own included; PegaProx needs the `root@pam` password for them.
- **A password instead of a token typed in as user name**: the text terminal of guests
  (xterm.js), and cross-cluster migration, replication and Site Recovery into this
  cluster, for which PegaProx creates a temporary API token on the target. That token
  holds what the account holds, so the target's role needs `Sys.Incoming` as well
  (`remoteMigration`). The token of a migration, whether started by hand, by the
  cross-cluster balancer, by a Site Recovery run or by a cross-cluster replication run,
  stays on the target for as long as its task runs, and PegaProx deletes it 30 seconds
  after the task has ended, trying twice more a few minutes apart when the target does not
  take the delete. A Site Recovery or replication run waits for that end itself, however
  long the copy takes, and takes its result from how the task ended. Two limits delete the
  token earlier, each with a warning in the log: a task whose status cannot be read for two
  hours in a row, and a task that still reports running after seven days. Every migration
  gets a token of its own, `pegaprox-migrate-<epoch>-<hex>`, `xclb-<group>-<vmid>-<hex>`,
  `pegaprox-sr-<hex>` or `xcrepl-<job>-<number>` in `pveum user token list <user>`,
  created with an expiry eight days ahead. A token PegaProx did not get to delete, after a
  restart or a lost lease during the migration, stays listed there until it is deleted by
  hand, and Proxmox refuses it once its expiry has passed. Where the API token policy of the
  target cluster allows a shorter lifetime, the token gets that one, and a migration still
  running when it ends loses its access to the target; the log says so when the token is
  made. A policy that requires privilege separation refuses these migrations into the
  cluster up front: the token holds the rights of the account without it.

## What works with a connection

**Check connection** lists per feature whether it works with how the cluster is
connected, and what the ones that do not still need: a privilege on a path, SSH (off, or
no key and no password), a password login, `root@pam`. It answers from the privileges the
last check read, the SSH settings and the kind of login; showing it sends nothing to the
cluster. *Read the privileges* asks the cluster once more. The same list is in the
cluster's *Re-configure* dialog. Over the API it is `GET /api/clusters/<id>/capabilities`
(`?refresh=1` to read the privileges again), with `cluster.config` on the whole cluster.
