# Proxmox VE permissions

PegaProx talks to a Proxmox VE cluster over its API, and to the nodes over SSH for the
features that need a shell. `root@pam` with its password is the simple way to connect a
cluster: everything works. For production the recommended setup is an account or an API
token of its own with a role that holds only what PegaProx uses.

The role is built from the same table the connection check compares a cluster's
privileges against (`pegaprox/core/conncheck.py`, `PRIVILEGE_NEEDS`). PegaProx shows it,
ready to copy, in two places:

- **Add Cluster**, Proxmox VE tab: *Least-privilege account or token*;
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
| Resource pools and pool-based access | `Pool.Audit` |

Optional, each adds to the role:

| Feature | `features=` | Privileges |
| --- | --- | --- |
| ISO and template uploads | `uploads` | `Datastore.AllocateTemplate` |
| Node network and settings, apt refresh | `nodeConfig` | `Sys.Modify` |
| Node reboot and shutdown | `nodePower` | `Sys.PowerMgmt` |
| Node syslog | `syslog` | `Sys.Syslog` |
| SDN view | `sdn` | `SDN.Audit` |
| Resource mappings (PCI, USB, directories) | `mappings` | `Mapping.Audit`, `Mapping.Use` |
| Storage replication jobs | `replication` | `VM.Replicate` |
| Proxmox HA resources and rules | `haConfig` | `Sys.Console` |

The role goes on `/` and propagates, so it reaches every guest, storage and node.

## With an API token (recommended)

Run on one node as root (PVE 9, every optional feature):

```
pveum role add PegaProx --privs "Sys.Audit,VM.Audit,VM.PowerMgmt,VM.Migrate,VM.Console,VM.Snapshot,VM.Snapshot.Rollback,VM.Backup,VM.Allocate,VM.Clone,VM.Config.CPU,VM.Config.Memory,VM.Config.Disk,VM.Config.Network,VM.Config.Options,VM.Config.CDROM,VM.Config.HWType,VM.Config.Cloudinit,VM.GuestAgent.Audit,Datastore.Audit,Datastore.AllocateSpace,Datastore.AllocateTemplate,VM.Replicate,SDN.Use,Pool.Audit,Mapping.Audit,Mapping.Use,Sys.PowerMgmt,Sys.Modify,Sys.Syslog,Sys.Console,SDN.Audit"
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
  root password of their own under *Node credentials*. ESXi migration signs in by
  password only. A cluster can switch SSH off entirely.
- **root@pam**: raw PCI and USB devices on a VM, most LXC feature flags and creating or
  removing Ceph OSDs. Proxmox keeps these to `root@pam` and refuses them to every API
  token, `root@pam`'s own included; PegaProx needs the `root@pam` password for them.
- **A password instead of a token typed in as user name**: the text terminal of guests
  (xterm.js), and cross-cluster migration, replication and Site Recovery into this
  cluster, for which PegaProx creates a temporary API token on the target.

## What works with a connection

**Check connection** lists per feature whether it works with how the cluster is
connected, and what the ones that do not still need: a privilege on a path, SSH (off, or
no key and no password), a password login, `root@pam`. It answers from the privileges the
last check read, the SSH settings and the kind of login; showing it sends nothing to the
cluster. *Read the privileges* asks the cluster once more. The same list is in the
cluster's *Re-configure* dialog. Over the API it is `GET /api/clusters/<id>/capabilities`
(`?refresh=1` to read the privileges again), with `cluster.config` on the whole cluster.
