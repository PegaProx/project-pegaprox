# QDevice: the external vote for Proxmox clusters

A Proxmox cluster stays writable only while a majority of its votes is online. A cluster
of two nodes has two votes: when one node goes down - a crash, or just a reboot for an
update - the other one is left with half, loses quorum, and stops starting, migrating or
changing guests until its partner is back.

A **QDevice** adds one more vote from outside the cluster. Each node runs
`corosync-qdevice`; a host outside the cluster runs `corosync-qnetd` and decides, in a
split, which side gets its vote. Two nodes plus the QDevice make three votes, and the node
that is left keeps two of them.

PegaProx sets this up for you, keeps an eye on it and takes it out again. It does what
`pvecm qdevice setup` does, with one difference: PegaProx carries the certificates between
the QNetd host and the nodes itself. No node needs an SSH login on the QNetd host, and the
QNetd host never needs root SSH from the cluster.

One run per cluster does everything, the QNetd host included - but only after PegaProx has
shown you, cluster by cluster, what it is going to change where, and you agreed to exactly
that (see [Set up a cluster](#set-up-a-cluster)).

## When you want one

- **Clusters of two nodes.** This is what it is made for. Rolling updates in PegaProx stop
  at every node of a 2-node cluster without one (the quorum gate), and count the QDevice
  vote with one.
- **Clusters with an even number of nodes** (4, 6, ...): a split down the middle leaves
  both halves without a majority; the QDevice vote decides.
- **Not for an odd number of nodes.** PegaProx refuses those, as `pvecm qdevice setup`
  does without `--force`: there the QNetd would carry N-1 votes and become the single point
  of failure it is meant to remove.

One QNetd serves many clusters. Fifty 2-node clusters on one QNetd are fine. Keep in mind
that they all lose their third vote together when that one QNetd goes down (they stay
quorate while both of their nodes run). Spread them over two QNetd hosts if that worries
you: each cluster hangs on exactly one.

## Where the QNetd runs

When you add a QNetd host, PegaProx asks **Where corosync-qnetd runs**:

| Kind in the UI | Where | How PegaProx reaches it |
|---|---|---|
| **This PegaProx host** (`local`) | the host PegaProx runs on (git, apt, rpm or appliance install) | a root-owned systemd socket, set up once by `install.sh` |
| **Linux host over SSH** (`ssh`) | any Linux host - the PegaProx witness host is the best place | an SSH login stored in PegaProx (root, or a user with passwordless sudo) |
| **Docker sidecar** (`sidecar`) | Docker: a second container from the PegaProx image | a Unix socket in a volume only the two containers share |

**In a PegaProx HA pair (or group), use an `ssh` QNetd host, not `local` or `sidecar`:**
the witness host, for example. A `local` QNetd is the machine of the instance that acts: it
runs on one member, goes down with that member, and after a switchover "local" is another
machine with another CA. A sidecar is the same: its socket is in a volume of one Docker
host, which the other members cannot reach. The witness host is outside both members and
at a third site already. A member's own machine works as an `ssh` host too, for a cluster
it is not a VM of.

What all of them need:

- **Outside the clusters it votes for.** A QNetd that runs as a VM of the cluster goes down
  with its node, which is exactly the failure it is there for. PegaProx reads the SMBIOS
  uuid of the QNetd host (`/sys/class/dmi/id/product_uuid`) and refuses to set up a
  cluster that has a VM with that uuid, or a node with it (the QNetd on a node, or in a
  container on one). Other clusters on the same QNetd are not affected.
- **At a third site, ideally.** Next to one of the two nodes, a power cut in that room
  takes two votes. The PegaProx witness host is at a third site already, which is why it is
  the best place.
- **TCP port 5403** reachable from every node of every cluster that uses it. The link to
  the QNetd is TCP with TLS and has none of the latency limits of the corosync links: a
  QNetd at another site or in the cloud is fine. With ufw or firewalld on the QNetd host,
  PegaProx opens it for the nodes of each cluster on request ([The firewall](#the-firewall)).
- **Linux with python 3.6 or later** (the helper is a python script) and, for `local` and
  `ssh`, **systemd**. corosync-qnetd and the NSS tools are installed automatically with the
  package manager of the host: apt-get on Debian and Ubuntu (`corosync-qnetd`,
  `libnss3-tools`), dnf or yum on RHEL, its rebuilds and Fedora (`corosync-qnetd`,
  `nss-tools`), zypper on SUSE (`corosync-qnetd`, `mozilla-nss-tools`). On RHEL and its
  rebuilds they are in the High Availability repository, and on SLES in the High
  Availability extension: enable that first. Elsewhere install the two by hand.
- **Each cluster name once per QNetd.** The QNetd tells clusters apart by their corosync
  cluster name only. PegaProx refuses a second cluster with the same name - also one it
  does not manage that is connected to that QNetd - and treats `PVE` and `pve` as the same
  name, as the QNetd does.

## How it works

On the QNetd host, everything goes through one small, root-owned script:
`/usr/lib/pegaprox/qnetd/pegaprox-qnetd-helper`. It does a fixed set of things and nothing
else: say its version (helper protocol 2: also the operations it knows and the package
manager it would use), set up corosync-qnetd and its CA (`init`), hand out the CA
certificate, sign the certificate request of a cluster, report which clusters and nodes are
connected, whether TLS is required and which cluster names it holds a certificate for (the
names only), read the SMBIOS uuid, and open or close the port of
corosync-qnetd for the nodes of one cluster (`firewall`, see [The firewall](#the-firewall)).
It checks every field itself.

The CA and its key live where corosync-qnetd keeps them, in `/etc/corosync/qnetd/nssdb`,
made exactly as `corosync-qnetd-certutil` makes them. A QNetd that was set up before with
`pvecm qdevice setup` or by hand keeps its CA: the helper never makes a CA where there is
one. The stock tools keep working next to it.

When you set up a cluster, PegaProx:

1. works out the plan again and compares it with the one you agreed to; any difference
   stops the run before anything changes (see [Set up a cluster](#set-up-a-cluster));
2. makes the QNetd host ready where the plan says so: the helper copied or updated (ssh
   hosts), corosync-qnetd and the NSS tools installed, the CA made, TLS required,
   corosync-qnetd started;
3. opens the port of corosync-qnetd for the nodes, where you ticked it, and tests it from
   every node again;
4. checks everything (see below) and stops with the reason if anything is off;
5. installs `corosync-qdevice` on the nodes that lack it, where you ticked it;
6. puts the QNetd CA certificate on every node (`corosync-qdevice-net-certutil -i`);
7. makes a certificate request on one node (`-r -n <cluster name>`), has the helper sign
   it, imports it on that node (`-M`) and copies the resulting p12 to the other nodes (`-m`);
8. adds the `quorum.device` section to `corosync.conf` with Proxmox's own code, exactly
   as `pvecm qdevice setup` writes it (model net, TLS on, algorithm ffsplit, one vote);
9. enables and starts `corosync-qdevice` on every node and reloads corosync.

Files go to the nodes through private temp directories and are deleted afterwards. If a
step fails halfway, PegaProx rolls back as `pvecm qdevice remove` does (the device entry
out again, `/etc/corosync/qdevice` removed on all nodes, the service stopped), takes out
the firewall rules this run added for the cluster, and tells you the step that failed.
Because the result is what `pvecm` writes, `pvecm qdevice remove` on a node works on a
QDevice PegaProx set up, and the other way round.

The CA key never leaves the QNetd host. Whoever has it can make certificates the QNetd
accepts for any cluster name, so treat that host like any other piece of your cluster
infrastructure.

## Set up the QNetd host

The commands below are run as root (`sudo -i` first, or however you become root).

### On the PegaProx host: apt package, rpm package or appliance

```sh
sh /usr/lib/pegaprox/qnetd/install.sh
```

It puts the helper root-owned into `/usr/lib/pegaprox/qnetd/` (the package did that
already), runs its `init` - which installs corosync-qnetd and the NSS tools with apt-get,
dnf, yum or zypper where they are missing, requires TLS on a corosync-qnetd it installed
(see [TLS](#tls)), makes the CA where there is none and starts corosync-qnetd - and sets up
the socket PegaProx reaches the helper through:

- `/etc/systemd/system/pegaprox-qnetd-helper.socket` listens on
  `/run/pegaprox-qnetd/local.sock`, owned by root and the group `pegaprox`, mode 0660
  (the directory 0755). `Accept=yes`: each connection starts its own
  `pegaprox-qnetd-helper@.service`, at most 8 at a time.
- `/etc/systemd/system/pegaprox-qnetd-helper@.service` runs
  `/usr/lib/pegaprox/qnetd/pegaprox-qnetd-helper serve` as root with the connection as its
  stdin and stdout: one JSON request line in, one JSON answer line out, the protocol of
  the Docker sidecar. The helper asks the kernel who is at the other end (`SO_PEERCRED`)
  and answers root and the user `pegaprox` only, whatever the file mode says. The unit
  keeps what the helper never needs away from it (`PrivateTmp`, `ProtectHome=read-only`,
  `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectHostname`, `RestrictRealtime`,
  `LockPersonality`, `RestrictAddressFamilies`) and nothing that would stop `init` from
  running apt-get, dpkg (also on a package dpkg has to finish first, a kernel one
  included), dnf, yum or zypper, `certutil` and `systemctl`, or `firewall` from running
  ufw or firewall-cmd.

There is no sudo rule, and the PegaProx unit keeps all its own hardening
(`NoNewPrivileges` included): PegaProx itself never becomes root. The rpm unit runs
PegaProx as root; there is no group `pegaprox` then, and the socket belongs to root alone.
If an earlier build of this installer left a sudo rule (`/etc/sudoers.d/pegaprox-qnetd`)
and a drop-in for the pegaprox unit behind, it removes both and asks you to restart
PegaProx once (`systemctl restart pegaprox`). Files of those names it did not write stay.

At the end it prints the address and port to enter in PegaProx. Running it again is safe:
it changes nothing that is in place.

### On the PegaProx host: git install

The installer and the helper of a git install are in `/opt/PegaProx`, which belongs to the
service user `pegaprox`.
**Do not run `sh /opt/PegaProx/packaging/qnetd/install.sh` as root.**
Whatever runs as `pegaprox` - PegaProx itself, or someone who took it over - can change
every file there, so that command would run a script the service user could have
rewritten, as root, and install a helper it could have rewritten as a root-owned file that
runs as root on every request. The installer warns when its copy can be changed by
another user.

Run it from a copy only root can write instead, taken from the release you run:

```sh
d=$(mktemp -d)
git clone --depth 1 --branch v1.5.0 https://github.com/PegaProx/project-pegaprox.git "$d/src"
# the same files as in /opt/PegaProx? Any difference: find out why before going on
cmp "$d/src/packaging/qnetd/pegaprox-qnetd-helper" /opt/PegaProx/packaging/qnetd/pegaprox-qnetd-helper
sh "$d/src/packaging/qnetd/install.sh"
rm -rf "$d"
```

Use the tag of the version your PegaProx shows. `mktemp -d` makes a directory only root
can enter. The installer copies itself to `/usr/lib/pegaprox/qnetd/install.sh`, root-owned:
use that copy for `--uninstall` later. Everything else is as for the packages above.

### On the witness host

Add `--qnetd` to the witness installer. On a new witness, append it to the line
**Add witness** shows (after `--code -`); on a witness that runs already:

```sh
sh /opt/pegaprox-witness/install.sh --qnetd
```

It installs corosync-qnetd (apt-get, dnf, yum or zypper), makes its CA where the package
did not and starts it. Nothing of PegaProx goes there for it: add the witness host in
PegaProx as a **Linux host over SSH** (next section) and PegaProx puts its helper there
itself. TCP 5403 has to be open for the cluster nodes: with ufw or firewalld PegaProx does
that per cluster when you tick it in the setup ([The firewall](#the-firewall)), otherwise
open it yourself. A corosync-qnetd the installer put there itself requires TLS (`-s req`,
see [TLS](#tls)); one that was there before stays as it was. See also
[the witness](ha-witness.md).

### Any other Linux host (ssh)

Nothing to install by hand on Debian, Ubuntu, RHEL and its rebuilds, Fedora or SUSE (on
RHEL and SLES, enable the High Availability repository or extension first). Add the host in
PegaProx with an SSH login - under QNetd hosts, or right in the setup of a cluster - and
press **Check**, or let the setup do it: PegaProx installs its helper (and, through the
helper's `init`, corosync-qnetd with TLS required) on first contact, and keeps the helper up
to date. Before the first **Check** of a host, PegaProx lists what it is going to do there
as root (the helper into `/usr/lib/pegaprox/qnetd`, corosync-qnetd and the NSS tools with
the package manager, the CA, TLS required, the service started) and does it only once you
confirm. The host key is pinned on first use, as for every other SSH target of PegaProx.
Passwords and private keys are stored encrypted, and changing the SSH host or port of a
stored login needs the password or key typed again: the login never follows a new address
on its own.

PegaProx copies its helper only into `/usr/lib/pegaprox` and `/usr/lib/pegaprox/qnetd` that
are root's, plain directories (no symlinks) and not writable by group or others, or not
there yet. Otherwise **Check** refuses with the directory and what is wrong with it.

The login can be:

- **root**, best with a key;
- **a user with passwordless sudo**: PegaProx runs `sudo -n` on that host for the helper
  and for installing it;
- **a user allowed to run the helper only.** Install the helper once by hand (copy
  `pegaprox-qnetd-helper` from any PegaProx install) and give that user a rule for it on
  that host (`visudo -f /etc/sudoers.d/pegaprox-qnetd`):

  ```
  qnetd-admin ALL=(root) NOPASSWD: /usr/lib/pegaprox/qnetd/pegaprox-qnetd-helper
  ```

  ```sh
  install -d -o root -g root -m 0755 /usr/lib/pegaprox/qnetd
  install -o root -g root -m 0755 pegaprox-qnetd-helper /usr/lib/pegaprox/qnetd/
  ```

  PegaProx cannot update a helper there; it says when the helper is outdated, and you
  copy the new one the same way.

### Docker (sidecar)

The PegaProx image carries corosync-qnetd. A second container from the same image runs
the QNetd with the command `qnetd run`: corosync-qnetd on port 5403, with TLS required,
and the helper on a Unix socket. The PegaProx container reaches that socket through a
volume the two of them share; the NSS database with the CA key is a volume of the sidecar
alone.

`docker-compose.yml` has the service `pegaprox-qnetd` in the profile `qdevice`: a plain
`docker compose up -d` leaves it out, nothing needs uncommenting. The `pegaprox` service
always mounts the socket volume `pegaprox-qnetd-sock` (empty and unused without the
sidecar). Hand over the SMBIOS uuid of the Docker host once, in `.env` next to the file,
then start both:

```sh
echo "PEGAPROX_QNETD_HOST_UUID=$(sudo cat /sys/class/dmi/id/product_uuid)" >> .env
docker compose --profile qdevice up -d
```

Use `--profile qdevice` with every later `docker compose up`, `pull` or `stop` that should
include the sidecar (or put `COMPOSE_PROFILES=qdevice` into `.env`).

With `docker run`:

```sh
docker volume create pegaprox-qnetd
docker volume create pegaprox-qnetd-sock
docker run -d --name pegaprox-qnetd --restart unless-stopped -p 5403:5403 \
  -v pegaprox-qnetd:/etc/corosync/qnetd -v pegaprox-qnetd-sock:/run/pegaprox-qnetd \
  -e PEGAPROX_QNETD_HOST_UUID="$(cat /sys/class/dmi/id/product_uuid)" \
  --health-cmd 'python3 pegaprox_multi_cluster.py qnetd health' \
  ghcr.io/pegaprox/pegaprox:latest qnetd run
```

and start the PegaProx container with `-v pegaprox-qnetd-sock:/run/pegaprox-qnetd` too.

- Use **named volumes** as above. A new named volume takes owner and mode from the image;
  a bind mount Docker creates belongs to root, and the sidecar refuses a socket directory
  that is not its own.
- A container cannot read the SMBIOS uuid of its host. Hand it over with
  `PEGAPROX_QNETD_HOST_UUID` (the content of `/sys/class/dmi/id/product_uuid` on the Docker
  host, readable by root) so PegaProx can check that the Docker host is not a VM of the
  cluster. The compose file takes it from `.env` and mounts nothing of the host for it: a
  bind mount of that file would keep the container from starting on a host that has none.
  Left empty, PegaProx cannot tell and asks you to confirm.
- Docker publishes port 5403 itself, past the rules of ufw or firewalld on the Docker
  host. PegaProx does not change the firewall of a Docker host (the sidecar cannot), so the
  setup has no firewall option there: limit who reaches 5403 on the Docker host or the
  network in front of it ([The firewall](#the-firewall)).
- `qnetd health` is healthy when the helper answers on its socket and corosync-qnetd
  answers on its own. If either of them stops, the container ends and Docker restarts it.
- PegaProx finds the socket at `/run/pegaprox-qnetd/helper.sock`, or where
  `PEGAPROX_QNETD_SOCKET` says (set it in both containers then).

## Add it in PegaProx

Everything about QNetd hosts is for administrators; a tenant or pool-confined account does
not see it. Under Settings > High Availability > **QNetd hosts**, press
**Add QNetd host**, choose where corosync-qnetd runs (**This PegaProx host**,
**Linux host over SSH** or **Docker sidecar**), and give the **Address for the nodes** with
its port (5403 unless you changed it). For a **Linux host over SSH** also the SSH host
(empty: the address above), SSH port, SSH user and a password or private key. The kinds
that cannot work on this machine say why (no helper socket, for example).

Then press **Check** on the host's card. The first time (and for a host whose helper does
not speak protocol 2 yet) PegaProx first lists what Check does there as root and goes on
only once you confirm. Then it asks the helper for its version, installs or updates the
helper where it may, sets up corosync-qnetd and its CA (`init`) and shows whether it runs.
You can skip this step: the setup of a cluster does the same when its plan says so.
**Read status** shows which clusters and nodes are connected, how they voted, and whether
corosync-qnetd requires TLS from the nodes. **Edit** changes a host (its kind, address and
port stay while clusters vote through it); **Learn the CA of this host again** is for a
QNetd host you set up anew on purpose - PegaProx pins the CA the first time and refuses a
host whose CA changed. **Delete** forgets a host no cluster uses.

The address is what goes into `corosync.conf` of each cluster. Use an address or a name
every node resolves; IPv6 addresses work.

## Set up a cluster

Press **Set up QDevice** next to the nodes of the cluster. PegaProx also suggests it: a
cluster with an even number of nodes and no QDevice shows a notice with that button (to
administrators who may manage QNetd hosts; **Hide for 30 days** hides it for that
cluster), and a rolling update that waits at the quorum gate of such a cluster offers it
next to **Continue anyway** - once the QDevice is set up and connected, **Continue** passes
the gate by itself.

The setup is a wizard in three steps:

1. **Where** corosync-qnetd runs: a QNetd host PegaProx knows already, with its state; a
   **New Linux host over SSH**, with its login right there (PegaProx saves the host first,
   nothing more - nothing is installed or changed on it before you agree to the plan); or
   **This PegaProx host** and **Docker sidecar**, where this machine offers them. In a
   PegaProx HA group the last two warn: they sit with one member only (see
   [Where the QNetd runs](#where-the-qnetd-runs)).
2. **Options**: **Install corosync-qdevice where it is missing** (ticked by default) and
   **Open port 5403 on the QNetd host for the cluster nodes** (ticked by default where the
   QNetd host runs ufw or firewalld and that blocks the port; otherwise unticked with the
   reason, and for a firewall PegaProx does not change, the lines to run there with a copy
   button). A sidecar has no firewall option: Docker publishes its port itself.
3. **Review**: what PegaProx will do, grouped by where - on the QNetd host (the helper
   copied or updated, corosync-qnetd and the NSS tools installed with its package manager,
   the CA made, TLS required, the service started, the port opened for exactly these node
   addresses with ufw or firewalld), on each node (corosync-qdevice installed, the CA and
   the cluster certificate put in place, corosync-qdevice started) and in the cluster
   (the `quorum.device` section in `corosync.conf` with address and port, corosync
   reloaded, the expected votes before and after) - with the warnings and the checks
   below. Tick **I agree that PegaProx makes these changes on <cluster>**, then
   **Start setup**.

Working out the plan changes nothing anywhere. Any change of an option works it out again
and takes the tick away. **Start setup** sends your agreement along with a fingerprint of
the plan you saw: every step of it with what it acts on (what is set up on the QNetd host,
the firewall rules with their addresses, the nodes that get corosync-qdevice or lose an
unused certificate store, the `corosync.conf` entry), the cluster and its nodes, the QNetd
host with address, port and the SSH login PegaProx reaches it by, every option, and a
warning about what the setup brings with it (a QNetd host that sits with one member of a
PegaProx HA group; not the count of HA resources, which the setup does not touch). The
server refuses a setup without it (`consent_required`), and the job works the plan out
once more right before it acts: if anything differs from what you agreed to, it stops
before the first change with "The plan changed since you agreed: check again"
(`plan_changed`). After the QNetd host step it checks once more that the nodes are still
the ones agreed to (same nodes, packages, certificate stores and addresses) before it
touches any of them. The agreement lands in the audit log with the user, the cluster and
the steps of the plan.

The checks, and every one of them has to pass (where the run fixes something itself, the
plan says so instead):

- an even number of nodes, all online, and the cluster quorate;
- no QDevice configured yet;
- `corosync-qdevice` installed on every node - or ticked
  **Install corosync-qdevice where it is missing**, and PegaProx runs
  `apt-get install corosync-qdevice` on the nodes (they need a working package source: the
  check tries the package sources of each node that lacks the package and names a node
  that cannot reach them; install the package there by hand);
- the QNetd host ready (helper there and current, corosync-qnetd running) - for an ssh
  host the run installs or updates the helper and sets up corosync-qnetd itself;
- port 5403 of the QNetd reachable **from every node** (tested on the nodes, not from
  PegaProx; with the firewall option on ufw or firewalld, the run opens it and tests again);
- the cluster name not in use on that QNetd - by another cluster of PegaProx or by one
  that is connected to it from elsewhere;
- no certificate of an earlier setup for that name on the QNetd host - or the plan replaces
  it (see below);
- the QNetd host not a VM of this cluster, and not one of its nodes.

**Check again** works the plan out once more. When the QNetd host has no readable SMBIOS
uuid (or the guest configs could not be searched), PegaProx cannot tell whether it is a
guest of the cluster; then, and only then, it offers
**I confirm the QNetd host is not a guest of this cluster**. A QNetd host it found to be
a VM or a node of the cluster is never offered for confirmation. Closing the window leaves
a started job running; its log shows each step.

The QNetd host keeps the certificate of a cluster when its QDevice is removed. If it holds
one for a cluster of the same name - this cluster set up there before, or a cluster that is
gone - the plan says so before you agree: the check **Certificate of an earlier setup on the
QNetd host** fails and offers **Replace the certificate**. Press it only when you know which
cluster that was. It reads the plan again with the replacement in it (an item on the QNetd
host) and takes your tick away: that is a new plan to agree to. The setup replaces a
certificate only where the plan you agreed to lists that item. The helper never replaces it
while a cluster of that name is connected; that cluster fails the check of the name instead.

A helper that does not list its certificates yet (one of an older build, or one the setup
puts on the QNetd host first) leaves that check to the run: then the setup finds the
certificate in its own check after the QNetd host step, before it touches a node, or at
the latest when it signs, and offers **Replace the certificate and try again**, again with
a new plan to agree to.

**Set up several clusters** on a QNetd host's card sets up several clusters against that
host in one run: **Select every cluster with an even node count** (or pick them) and check
them. Each cluster then shows its own plan and its own agreement tick; the setup starts
once every selected cluster is agreed to (untick the ones you do not want), and the server
refuses a run that does not carry an agreement for every cluster in it. Every cluster is
compared with its plan first, before the run changes anything; then the QNetd host is made
ready once for the run, and each cluster is checked and set up on its own; one failure does not stop the others, and you get a result per cluster.
A cluster whose name the QNetd host holds a certificate for says so in its row, with
**Replace the certificate**: every plan is read again with the replacement (only the plans
of clusters with such a certificate list it) and every tick goes.
**Replace their certificates and try again** retries the ones whose name the QNetd host
still held. One run at a time per QNetd host.

Setup, removal, every agreement and every change to a QNetd host land in the audit log.

## TLS

Every QDevice PegaProx (or `pvecm qdevice setup`) sets up speaks TLS (`tls: on` in
`corosync.conf`). corosync-qnetd itself lets a client go without TLS by default (`-s on`),
and such a client is asked for no certificate: whoever reaches the port could join the
vote under any cluster name. With `-s req` (TLS required; the binary takes `req`, not the
man page's `required`) only clients with a certificate from the QNetd CA get in.

- The **sidecar** runs corosync-qnetd with `-s req`.
- Where the **helper installs corosync-qnetd itself** (a fresh host: `install.sh` on the
  PegaProx host, or **Check** or the setup on an ssh host without corosync-qnetd), it sets
  `-s req` in `COROSYNC_QNETD_OPTIONS` of the unit's environment file -
  `/etc/default/corosync-qnetd` on Debian and Ubuntu, `/etc/sysconfig/corosync-qnetd` on
  RHEL, its rebuilds and SUSE (the one the package put there; else the one the unit
  reads) - keeps every other option there, and restarts corosync-qnetd. The NSS database
  it makes belongs to the owner and group of `/etc/corosync/qnetd`, as with
  `corosync-qnetd-certutil` (`coroqnetd` on RHEL, where the package gives it that
  directory; root with the group `coroqnetd` on Debian), so the daemon reads it.
- The **witness installer's `--qnetd`** does the same for a corosync-qnetd it installs,
  in the file of the distribution (`/etc/default` or `/etc/sysconfig`), as long as the
  options line is the one the package ships.
- A corosync-qnetd that **was there before** (set up by `pvecm` or by hand) is left as its
  admin set it up. **Read status** shows "TLS from the
  nodes: not required (-s on)" with a warning on the host's card, and `install.sh` says so
  too. Require it by hand:

```sh
# /etc/default/corosync-qnetd (on RHEL, its rebuilds and SUSE: /etc/sysconfig/corosync-qnetd)
COROSYNC_QNETD_OPTIONS="-s req"
```

```sh
systemctl restart corosync-qnetd
```

Keep any options that were in that line (`-p` for another port, for example). Clusters
that do not speak TLS lose their vote from that QNetd; none that PegaProx set up.

## The firewall

On the QNetd host, TCP 5403 has to be open for the nodes of the clusters that use it, and
nothing else needs to be. The setup of a cluster can do that: tick
**Open port 5403 on the QNetd host for the cluster nodes**. PegaProx then opens the port
for exactly the addresses the nodes use towards the QNetd host - each node tells which
(`ip route get` to the QNetd address), the plan lists them - and only for those. The port
is the one corosync-qnetd listens on, read from its own options on the QNetd host (`-p`,
5403 where none is set): the helper never takes a port from PegaProx, so it cannot open
any other.

| On the QNetd host | What PegaProx does |
|---|---|
| **firewalld** running | one rich rule per node address in the default zone, `rule family="ipv4" source address="<node>" port port="5403" protocol="tcp" accept`, both in the permanent configuration and in the running firewall (no reload) |
| **ufw** active | one rule per node address, `ufw allow proto tcp from <node> to any port 5403 comment 'pegaprox-qnetd <cluster>'` |
| **pve-firewall** running (the QNetd host is a node of another Proxmox cluster) | nothing: it shows the rules for `/etc/pve/nodes/<node>/host.fw` to add by hand |
| an **nftables** or **iptables** policy of drop on input | nothing: it shows the `nft insert rule ...` or `iptables -I INPUT ...` lines to run, and to keep in the configuration of that firewall |
| no firewall | nothing to do |

Why only ufw and firewalld: both are made for that - one rule added or taken out by
command, next to the admin's own, kept across a reboot by the firewall itself. The rules
of pve-firewall belong to the configuration of that Proxmox cluster, and a ruleset of
nftables or iptables belongs to whoever wrote it, with its own order and its own way of
being saved: PegaProx writes into neither. Where such a firewall blocks the port, the
options and the plan name the lines to run there (with a copy button); with the firewall
option ticked anyway, the run stops before anything changes on the nodes
(`firewall_unmanaged`). Run them, then check again. Where PegaProx cannot tell which
firewall runs (the helper is not on the host yet), the plan says so, and the run checks
the port from every node after it.

Only what PegaProx added is ever taken out again. The helper writes every rule it added,
with its cluster, into `/var/lib/pegaprox-qnetd/firewall.json` (root's, 0700 and 0600), and
removes only rules written down there:

- **Remove QDevice** takes out the rules added for that cluster; a failed setup takes out
  the ones its run added, also those of an allow that broke off part-way (ufw took the
  first address and refused the next, or the answer did not come in time). A rule that cannot be taken out is a warning in the job log; the
  removal of the QDevice goes on.
- A rule that was there before - yours, also one exactly like PegaProx's - is never
  written down and never deleted, and PegaProx adds nothing next to it.
- Two clusters whose nodes come from the same address share one rule; it stays until the
  last of them goes.
- A ufw rule you gave another comment is yours from then on: it stays.
- A state file that is not the helper's (a symlink, another owner, other modes, a second
  hard link, anything that does not read back as the helper wrote it) stops every change
  of the firewall (`state_untrusted`) rather than act on a rule that may not be PegaProx's.

The firewalld rules go into the default zone. Where the interface the nodes come in on
belongs to another zone, the rules do not apply to them: the test from the nodes then
fails, and the port is yours to open in that zone.

**Docker:** Docker publishes port 5403 of the sidecar itself, past the rules of ufw or
firewalld on the Docker host. PegaProx does not change the firewall of a Docker host; limit
who reaches 5403 there (`DOCKER-USER` chain, or the network in front of it).

**By hand**, for example:

```sh
ufw allow proto tcp from 192.0.2.0/24 to any port 5403
nft add rule inet filter input ip saddr 192.0.2.0/24 tcp dport 5403 accept
```

For IPv6 nodes, the same for their prefix. A QNetd host over SSH also needs SSH from the
PegaProx host(s). The `local` and `sidecar` kinds need no port for PegaProx itself.

## Check it

- **In PegaProx:** **Read status** on the QNetd host's card (connected clusters, nodes,
  votes, TLS) and the QDevice view of each cluster (the view of the nodes).
- **On the QNetd host:** `corosync-qnetd-tool -l` lists the connected clusters,
  `corosync-qnetd-tool -s` says whether TLS is required; `systemctl status corosync-qnetd`
  (or `docker logs pegaprox-qnetd`).
- **On a node:** `pvecm status` shows the `Qdevice` vote; `corosync-qdevice-tool -s`
  shows the connection to the QNetd.

The alert rule **QNetd host down** raises **one alert per QNetd host** a cluster votes
through when that host did not answer twice in a row or its corosync-qnetd stopped - not
one per node; the QDevice rule of each cluster (from the nodes' side) stays as it is. It is
an administrator's rule, like the QNetd hosts it watches: only an administrator can set it
up or change it, and a rule nobody of them stands behind (one made through the plain
alert API, or whose administrator is one no more) watches nothing. Its alerts name no
QNetd host, address or error - everyone who sees the cluster sees its alerts; which host
and why is on the QNetd hosts list. PegaProx reads the QNetd hosts of the clusters such a
rule watches in the background, each at most once a minute, and **Read status** at most
every 30 seconds.

## Updates

| Install | The helper | corosync-qnetd |
|---|---|---|
| apt, rpm, appliance | comes with every package update into `/usr/lib/pegaprox/qnetd/`; the socket units stay | the distribution's updates |
| git | after an update of PegaProx, run the installer again from a root-owned copy of the new release (see [git install](#on-the-pegaprox-host-git-install)), never from `/opt/PegaProx`. PegaProx cannot replace a root-owned helper; it says "outdated, re-run install.sh" until you do | the distribution's updates |
| Docker | pull the new image and recreate both containers (`docker compose --profile qdevice pull && docker compose --profile qdevice up -d`) | comes with the image |
| ssh (root or passwordless sudo) | **Check** installs a newer helper itself | the distribution's updates |
| ssh (a user for the helper only) | copy the new helper by hand (see above) | the distribution's updates |

This release speaks **helper protocol 2** (the firewall operation and the package managers
besides apt-get). A helper of protocol 1 counts as outdated until it is replaced as above:
an ssh host gets the new one on the next **Check** or setup (shown in the plan as an update
of the helper), a `local` host says "outdated, re-run install.sh" - on a git install from a
root-owned copy of the new release, as always, never from `/opt/PegaProx`.

A helper replaced in place is used from the next request on: the socket starts a new
helper for each connection, nothing needs a restart. Updating corosync-qnetd restarts it
for a moment. The clusters keep quorum while all their nodes run; plan it outside rolling
updates of those clusters.

## Remove

**A cluster's QDevice:** **Remove QDevice** in the cluster's QDevice view (type `REMOVE`
to confirm). PegaProx runs `pvecm qdevice remove` on one node, drops the attachment, and
has the helper take out the firewall rules it added for that cluster on the QNetd host
(only those, see [The firewall](#the-firewall); one it cannot take out is a warning in the
job log). `pvecm qdevice remove` by hand on a node does the same on the cluster side, but
leaves those rules on the QNetd host: delete them there by hand (ufw: the rules with the
comment `pegaprox-qnetd <cluster>`; firewalld: the rich rules for the node addresses). The
cluster's certificate stays on the QNetd host; it is harmless there, and the plan of a later
setup of a cluster of that name shows it and offers to replace it.

**A QNetd host from PegaProx:** **Delete** on its card, once no cluster uses it any more.

**The QNetd on the PegaProx host** (`local`), as root - after removing the QDevices that
vote through it, so their firewall rules go (`--uninstall` leaves `/var/lib/pegaprox-qnetd`
and the firewall alone):

```sh
sh /usr/lib/pegaprox/qnetd/install.sh --uninstall           # the socket and the helper
sh /usr/lib/pegaprox/qnetd/install.sh --uninstall --purge   # ... and the CA
```

`--uninstall` runs `systemctl disable --now pegaprox-qnetd-helper.socket`, deletes
`pegaprox-qnetd-helper.socket` and `pegaprox-qnetd-helper@.service` from
`/etc/systemd/system` and the helper from `/usr/lib/pegaprox/qnetd` (on an apt or rpm
install the helper belongs to the package and stays until the package goes). It keeps
corosync-qnetd and its CA: clusters keep their vote. `--purge` also deletes the CA and its
NSS database - every cluster certificate of that QNetd becomes worthless - and refuses
while a cluster is still connected. The packages stay; remove them with the package
manager once you are done (`apt-get purge corosync-qnetd`, `dnf remove corosync-qnetd`,
`zypper remove corosync-qnetd`). By hand, the same is:

```sh
systemctl disable --now pegaprox-qnetd-helper.socket
rm -f /etc/systemd/system/pegaprox-qnetd-helper.socket /etc/systemd/system/pegaprox-qnetd-helper@.service
systemctl daemon-reload
```

**Docker:** stop and remove the sidecar with `docker compose --profile qdevice rm -sf pegaprox-qnetd`
and start without the profile from then on. Delete its volume (the CA) with
`docker volume rm <project>_pegaprox-qnetd` - `docker volume ls` shows the name compose gave
it. Never `docker compose down -v`: that deletes the volumes of PegaProx too. The socket
volume stays mounted in the `pegaprox` service and is harmless empty.

**Witness host or another ssh host:** remove the QDevices that vote through it first (so
their firewall rules go), then as root on that host remove the package (`apt-get purge
corosync-qnetd`, `dnf remove corosync-qnetd` or `zypper remove corosync-qnetd`; the CA goes
with the package's NSS database where the package made it, else
`rm -rf /etc/corosync/qnetd/nssdb`) and `rm -rf /usr/lib/pegaprox/qnetd /var/lib/pegaprox-qnetd`.
Removing the witness (`--uninstall`) leaves corosync-qnetd alone on purpose.

## Security notes

- **The CA key** stays on the QNetd host (`/etc/corosync/qnetd/nssdb`, readable by root
  and the `coroqnetd` group the daemon runs as) or in the sidecar's volume. PegaProx only
  ever gets the CA certificate and the signed cluster certificates.
- **The helper signs only what a node asks for:** a certificate request for exactly
  `CN=<cluster name>` and nothing else. `certutil` copies every extension a request asks
  for into the certificate it signs - a request asking to be a CA would come back as a
  sub-CA - so a request with any extension or attribute is refused.
- **The socket** belongs to root and the group `pegaprox` (mode 0660), and the helper
  answers only root and the user `pegaprox`, by the kernel's word on the peer
  (`SO_PEERCRED`). It takes one request line of at most 64 KiB, its fixed operations and
  nothing else. Under root its paths are fixed; none of its settings come from the
  environment. Every child process gets a clean environment and a time limit.
- **The helper file** is root's, in directories that are root's and not writable by
  others - on the PegaProx host (`install.sh`) and on an ssh host (**Check**) alike.
- **TLS required** where PegaProx installed corosync-qnetd; see [TLS](#tls) for one that
  was there before.
- **The firewall operation** opens one port, the one corosync-qnetd's own options name
  (never one from the request), for single node addresses only (no networks, names, zone
  indexes, loopback, multicast or unspecified addresses; at most 64 per call). It runs ufw
  and firewall-cmd with fixed paths and argument lists, never through a shell, and only
  takes out rules written down in its own state file (root's, 0700 and 0600, refused when
  it is anything else). In the sidecar, and on a host without systemd, it changes nothing
  (`not_supported`).
- **Nothing changes without your agreement:** the plan is read-only, and the server starts
  no setup (single, several clusters, or the wizard) without an agreement that matches the
  plan of that very cluster as it is when the run starts.
- **Package sources** are the host's own. zypper never runs with `--gpg-auto-import-keys`:
  a repository whose key it does not know makes the install fail. dnf and yum run with
  `-y`, and import a key that the configuration of a repository on that host names
  (`gpgkey=`), as they would for an admin who answers yes.

## Troubleshooting

**"no helper socket - run packaging/qnetd/install.sh as root"** or
**"outdated, re-run install.sh"** - run the installer of your install type (above). For a
git install, after every update, from a root-owned copy.

**"PegaProx may not use /run/pegaprox-qnetd/local.sock"** - the socket's group is not
the one PegaProx runs as. Run the installer again; it sets the group `pegaprox`, or root
where there is no such group.

**"this socket answers root and pegaprox only"** - something other than PegaProx asked
the helper. `journalctl -u 'pegaprox-qnetd-helper@*'` names the uid.

**`name_exists`** - the QNetd holds a certificate for a cluster of that name with another
key (in the plan: the check **Certificate of an earlier setup on the QNetd host**). If that
was this cluster before, or a cluster that is gone, use **Replace the certificate** in the
plan, or **Replace the certificate and try again** after a run that stopped there.

**`name_in_use`** - a cluster of that name is connected to the QNetd right now. A cluster
cannot be renamed easily in Proxmox: use another QNetd host for one of the two.

**`status_unknown`** - corosync-qnetd runs but does not say which clusters it serves. Look
at `systemctl status corosync-qnetd` and `corosync-qnetd-tool -l` on the QNetd host.
PegaProx signs nothing for a new cluster until it can tell.

**"refusing to install the helper on the QNetd host"** - `/usr/lib/pegaprox` or
`/usr/lib/pegaprox/qnetd` there is a symlink, belongs to another user or is writable by
group or others. Make it a plain directory of root, mode 0755, then press **Check** again.

**Port 5403 not reachable from a node** - the check names the node. With ufw or firewalld
on the QNetd host, tick **Open port 5403 on the QNetd host for the cluster nodes**;
otherwise open the firewall of the QNetd host (and any firewall on the way) for it. With
firewalld, check that the interface the nodes come in on is in the default zone. Test on
the node with `nc -zv <qnetd> 5403`.

**`consent_required`** - a setup was started without an agreement to its plan (or, for
several clusters, without one for each of them). Open the setup, review the plan and tick
the agreement.

**`plan_changed`** - "The plan changed since you agreed: check again". Between your
agreement and the start something differed: a node, the QNetd host (its address, port or
SSH login, or what has to be set up there), a package to install, a certificate store to
remove, a node address for the firewall, an option, a warning. Found in the `plan` step,
nothing was changed. Found in the `preflight` step (a node changed while the QNetd host
was set up): the QNetd host stays set up (helper, packages, CA, TLS, the service; the next
setup uses it as it is), the firewall rules this setup added are taken out again, and
nothing on the nodes or in `corosync.conf` was touched. Either way, look at the new plan
and agree again.

**`firewall_unmanaged`** - the QNetd host runs pve-firewall, or an nftables or iptables
policy that drops the port, which PegaProx does not change. The message and the plan name
the lines to run there; run them (and keep them in that firewall's configuration), then
check again.

**`firewall_failed`** - ufw or firewall-cmd refused (the message says what it said). The
rules added before that are written down on the QNetd host, and the rollback of the failed
setup takes them out again (one the cluster's record held before the setup stays); fix the
firewall, then try again.

**`state_full`** - the helper writes down at most 256 rules per cluster name, rules for at
most 10000 cluster names and 1 MiB in `firewall.json`. An allow past that is refused
before it adds a rule: a fuller file would be one the helper no longer reads, and every
firewall change on that host would stop, the removal of these rules included. Many setups
with changing node addresses get there; remove the QDevice of that cluster (its rules go
with it), then set it up again.

**`state_untrusted`** - `/var/lib/pegaprox-qnetd` or its `firewall.json` on the QNetd host
is not as the helper left it (a symlink, another owner or mode, a hard link, damaged).
The helper changes no firewall rule until it is: look at what is there, then make it
root's again (`chmod 0700 /var/lib/pegaprox-qnetd`, `chmod 0600 .../firewall.json`) or move
the file away (then PegaProx no longer knows its rules there: delete them by hand).

**`not_supported`** (firewall) - the QNetd runs in the Docker sidecar (Docker publishes
the port itself: limit it on the Docker host) or on a host without systemd: open the port
by hand.

**`corosync-qdevice` missing on a node** - tick
**Install corosync-qdevice where it is missing**, or `apt install corosync-qdevice` on
each node.

**"dnf finds no corosync-qnetd"** (or yum, zypper) - on RHEL and its rebuilds,
corosync-qnetd is in the High Availability repository: `dnf config-manager --set-enabled
highavailability` (Rocky, Alma), the High Availability Add-On on RHEL; on SLES the High
Availability extension. Then check again.

**"apt-get cannot reach the package sources"** (or dnf, yum, zypper) - the QNetd host (on
**Check**) or a node (in the checks of a setup) has no DNS or no route to its mirror. Before apt-get runs,
PegaProx asks apt where it would fetch from and tries each of those hosts once (a DNS
lookup and a connect, 15 s at most), instead of letting apt-get wait for minutes and
retry; dnf and yum get short download time limits and two retries instead. Give the host
DNS and a route to its mirror, or install the packages by hand (corosync-qnetd and the NSS
tools on the QNetd host, `corosync-qdevice` on a node), then check again. With a proxy in apt's configuration, or a `file:`, `cdrom:` or `mirror+`
source, nothing is tried up front and apt-get decides.

**The old NSS database format** (`cert8.db`, from very old installs) - convert it once on
the QNetd host:
`certutil -N -d sql:/etc/corosync/qnetd/nssdb -f /etc/corosync/qnetd/nssdb/pwdfile.txt -@ /etc/corosync/qnetd/nssdb/pwdfile.txt`

**Docker: "no helper socket"** - the socket volume is not mounted in both containers, or
the sidecar does not run (`docker logs pegaprox-qnetd`; with compose, started with
`--profile qdevice`?). "belongs to another user": use a named volume, not a bind mount. No
SMBIOS uuid: set `PEGAPROX_QNETD_HOST_UUID` (in `.env` for compose).

**Logs** - `journalctl -u corosync-qnetd` on the QNetd host,
`journalctl -u pegaprox-qnetd-helper.socket -u 'pegaprox-qnetd-helper@*'` for the helper
socket on the PegaProx host, `journalctl -u corosync-qdevice` on a node,
`docker logs pegaprox-qnetd` for the sidecar.
