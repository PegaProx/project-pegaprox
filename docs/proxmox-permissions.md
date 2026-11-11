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
  (`remoteMigration`). The token of a migration started by hand or by the cross-cluster
  balancer stays on the target for as long as its task runs, and PegaProx deletes it 30
  seconds after the task has ended. A PegaProx restart during the migration leaves it on
  the target: `pveum user token list <user>` shows it as `pegaprox-migrate-<epoch>` or
  `xclb-<group>-<vmid>`.

## What works with a connection

**Check connection** lists per feature whether it works with how the cluster is
connected, and what the ones that do not still need: a privilege on a path, SSH (off, or
no key and no password), a password login, `root@pam`. It answers from the privileges the
last check read, the SSH settings and the kind of login; showing it sends nothing to the
cluster. *Read the privileges* asks the cluster once more. The same list is in the
cluster's *Re-configure* dialog. Over the API it is `GET /api/clusters/<id>/capabilities`
(`?refresh=1` to read the privileges again), with `cluster.config` on the whole cluster.
