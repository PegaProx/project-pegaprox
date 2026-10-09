# The PegaProx witness

> **Beta.** The witness belongs to automatic failover, which is new in this release and
> ships as a beta. Try it in your setup before you rely on it; you can switch back to
> manual failover at any time. Every group stays in manual mode until an admin switches
> it on, on the leader's HA page (the Automatic failover card and its checklist).

Automatic failover needs at least three votes. A group of two PegaProx instances has
two. The witness is the third: a small process that votes, never leads, and holds no
data of your deployment - no database, no cluster passwords, no users. It keeps its own
key, its TLS certificate and its vote, nothing else.

## Where it runs

- **At a third site**, with its own network path to every PegaProx instance of the
  group. If it sits in the same room as one of them, losing that room loses two votes.
- **On a host of its own.** A Raspberry Pi, a small VM, an LXC container or a VPS is
  plenty: about 40 MB of memory and one TCP port (5005).
- **Never on a host that runs PegaProx.** The installer refuses that.
- **With the right time.** Its clock has to be within 5 seconds of the members: run NTP
  (systemd-timesyncd or chrony) on it.

Linux with systemd and python 3.9 or later. These work out of the box, python and its
modules from the distribution: Debian 11 and later, Ubuntu 22.04 and later, Raspberry Pi
OS 11 and later, Fedora. On RHEL, Rocky Linux and AlmaLinux 9, python3-cryptography and
python3-requests come from the distribution and python3-gevent only from EPEL: with EPEL
enabled (`dnf install epel-release`) everything comes from packages; without it the
installer says so and takes gevent from PyPI into a virtualenv next to the distribution's
modules (it never enables EPEL itself). On RHEL, Rocky Linux and AlmaLinux 8 and on
openSUSE Leap 15, where python3 is 3.6, the installer installs python3.11 (or python39)
next to it with dnf or zypper, and takes the modules the distribution has no package of
(gevent at least) from PyPI into a virtualenv. Anything else that runs Docker works too.

## Install it

On the leader's HA page, use **Add witness**. It makes a one-time code (good for
15 minutes) and shows one command per way to install, with the code in it. Copy the one
you want and run it on the witness host. That is all.

### Linux (recommended)

The line looks like this (yours carries your code and the checksum of your leader's
installer):

```sh
cd "$(mktemp -d)" && for u in https://raw.githubusercontent.com/PegaProx/project-pegaprox/main/packaging/witness/install.sh https://updates.pegaprox.com/packaging/witness/install.sh; do curl -fsSL --connect-timeout 10 --max-time 120 -o install.sh "$u" && echo '<sha256>  install.sh' | sha256sum -c --status && break; rm -f install.sh; done; [ -f install.sh ] || curl -fsSLko install.sh --noproxy '*' 'https://<leader>:5000/api/ha/witness/installer'; { echo '<sha256>  install.sh' | sha256sum -c || { echo 'pegaprox-witness: no install.sh that matches this line - ...' >&2; false; }; } && printf '%s\n' '<code>' | $([ "$(id -u)" -eq 0 ] || echo sudo) sh install.sh --code -
```

It downloads the installer from GitHub, or from updates.pegaprox.com (the mirror of the
GitHub repository) when GitHub does not answer, and runs it only if it matches the
checksum your leader worked out from its own copy. Where neither has that exact file
(your leader runs another release than the one on GitHub, or the host has no internet),
it takes the installer from your leader instead - `-k` there only because the checksum
is checked before anything runs. Each of the two downloads gives up after 10 seconds
without a connection (two minutes in all), so a host whose way out is dropped gets to
the leader in about 20 seconds.

The code goes to the installer on its input (`printf` is part of your shell, and
`--code -` reads it from there), never as an argument: any user of the witness host
could read an argument in the process list until the code is used.

The installer then:

1. installs python3, python3-cryptography, python3-gevent and python3-requests with
   apt, dnf, yum or zypper, each package on its own where dnf, yum or zypper would drop
   all of them for one they do not find (what has no package comes from PyPI into a
   virtualenv in /opt/pegaprox-witness/venv that sees the system's packages),
2. creates the system user `pegaprox-witness` and its state directory
   /var/lib/pegaprox-witness,
3. fetches the witness code from your leader (pinned to the leader's certificate, the
   fingerprint is in the code) into /opt/pegaprox-witness/&lt;version&gt;,
4. installs the command `pegaprox-witness` in /usr/local/bin, linked from /usr/bin (sudo
   on RHEL and its rebuilds only looks in /usr/bin and /usr/sbin), and the systemd unit
   `pegaprox-witness`,
5. pairs with the leader, starts the witness and tells you what to open in the firewall.

It works out the address the members reach the witness at (this host's address towards
the leader, IPv4 or IPv6 - the witness listens on both), and checks at the end that the
witness answers there. Behind NAT, or to use a DNS name, add
`--url https://witness.example.com:5005`.

Options: `--port 5005`, `--allow <network>` (see below), `--no-auto-update`. With
`--url`, the witness listens on the port the address names (give `--port` too only with
the same number); an address without a port, or two different ports, is refused before
the code is used: a NAT that maps one port to another is not supported.

The witness and the installer talk to the members directly, never through a proxy that
the environment names (`https_proxy` in /etc/environment, for example): the line fetches
the installer from your leader with `--noproxy '*'` too, as a proxy often does not reach
it (Squid, for one, only tunnels to port 443 by default). Only the downloads from GitHub
and the mirror go through a proxy where one is set.

**Run it again** to repair the witness: `sudo sh /opt/pegaprox-witness/install.sh`. It
puts back the command and the unit, updates from the leader and brings the start script
(/opt/pegaprox-witness/boot.py) up to date with the newest code that came up healthy on
this host. The settings of the run before (`--port`, `--allow`, `--no-auto-update`) stay
unless you give them again. The same line from "Add witness" works too, but only while
the leader runs the release that made it: it carries the checksum of that release's
installer. Once the leader runs another release, the line stops with "no install.sh that
matches this line" and says where to go instead - `sudo sh /opt/pegaprox-witness/install.sh`
on a host where the witness is installed, else a new code with **Add witness**.

**A paired witness keeps its address.** The members call it at the address it paired
with, so a run with another `--url` or `--port` stops and changes nothing (and so does a
run that finds the witness listening on another port than that address names). To move
it: remove the witness on the leader's HA page (Remove witness), make a new code there
with **Add witness**, and run its line with the new `--url` or `--port`.

**A new code on a host that is paired already** (you removed the witness on the leader,
or want it in another group): the installer asks the group it is paired with first. If
that group let the witness go, it leaves here and pairs with the new code. If that group
still counts the witness, or cannot be asked, it stops and says what to do: remove the
witness there (or run the installer with `--uninstall`, or `--uninstall --force` where
the old group is gone for good), then run the line again.

### Without internet

"Add witness" also shows an offline line. It takes the installer from your leader
directly and checks it the same way:

```sh
cd "$(mktemp -d)" && curl -fsSLko install.sh --noproxy '*' 'https://<leader>:5000/api/ha/witness/installer' && { echo '<sha256>  install.sh' | sha256sum -c || { echo 'pegaprox-witness: no install.sh that matches this line - ...' >&2; false; }; } && printf '%s\n' '<code>' | $([ "$(id -u)" -eq 0 ] || echo sudo) sh install.sh --code -
```

The host still needs its distribution's packages (a local mirror is fine), and all
three modules have to come from them: without internet there is no PyPI to fall back
on. On RHEL, Rocky Linux and AlmaLinux 9 that means EPEL (or your local mirror of it)
for python3-gevent: `dnf install epel-release` first. On RHEL, Rocky Linux and AlmaLinux
8 the distribution has no gevent for the python3.11 the installer puts next to python3:
give the host a way to PyPI (a proxy, or a local package index pip is set up for), or
use Docker.

### Docker

```sh
docker run -d --name pegaprox-witness --restart unless-stopped -p 5005:5005 -v pegaprox-witness:/app/witness ghcr.io/pegaprox/pegaprox:<version> witness run --join '<code>' --url 'https://<witness-host>:5005'
```

Replace `<witness-host>` with the name or address the members reach this host at - the
container cannot know it (left in, the witness refuses it and says so). The image is
that of your leader's release; a leader that follows the Testing branch names
`ghcr.io/pegaprox/pegaprox-testing:latest`, which every push to Testing builds. Release
1.2.0 and older have no witness in their image: a leader that runs one of them (and
does not follow Testing) shows no Docker line, and says so - use the Linux line there.
The release image is built for amd64, arm64 and 32-bit ARM (armv7, from the release
after 1.2.0 on), the Testing image for amd64 and arm64: on a 32-bit Raspberry Pi OS with
the Testing image, Docker answers "no matching manifest" - use the Linux line there.
The first start pairs with the code; every start after just
runs (the code is used up by then, that is fine). Its state lives in the volume
`pegaprox-witness`. With a new code on a volume that is still paired, it pairs anew only
once the old group let the witness go; otherwise `docker logs pegaprox-witness` says
what to do.

### By hand, from a checkout

In a checkout of the repository at your leader's release, with python3-cryptography,
python3-gevent and python3-requests installed:

```sh
python3 pegaprox_multi_cluster.py witness run --join '<code>' --url 'https://<witness-host>:5005'
```

The state goes to ./witness (or `--dir`). You start that process yourself and keep it
running (a reboot does not start it again). It starts itself again into an update it
fetched from the leader, and goes back to the code before it when that does not come up,
in the same process.

## The firewall

The members call the witness on TCP port 5005. Open that port for the addresses of the
members and nothing else (the installer prints the rule for ufw, firewalld or nftables,
for the address family the witness paired with), for example:

```sh
ufw allow proto tcp from 192.0.2.10 to any port 5005
ufw allow proto tcp from 198.51.100.20 to any port 5005
```

Where you cannot firewall it, let the witness do it: run the installer again with
`--allow 192.0.2.0/24 --allow 198.51.100.0/24` (or set `PEGAPROX_WITNESS_ALLOW`). Every
other address is then closed at once.

The witness itself only calls out to the leader, for pairing, leaving and updates.

**The leader's IP allow list** (Settings > Security): the installation goes through it
like any other caller - the offline line's download from the leader, the installer
fetching the witness code with the open code, the pairing. Add the witness host's
address there for the installation. Where the line itself cannot download the installer
it says so, and a 403 in curl's message above it is the allow list; the installer says
"the leader's IP allow list refuses this host - add &lt;address&gt; there" with the address
the leader sees. Once
paired, the witness signs its calls with its own key, and those pass the list as a
member's signed calls do: its updates and its leaving work without an entry (a blacklist
entry still refuses it).

## Check it

On the witness host:

```sh
sudo pegaprox-witness status
```

`"paired": true`, the leader's address and `"writable": true` mean it is ready;
`release` is the release the service runs. The state belongs to the user
`pegaprox-witness`, so the command needs `sudo` (or that user). Every command of
`pegaprox-witness` runs the code that ran before an update that has not come up yet, and
gives up after a few minutes at most instead of waiting for ever.
`systemctl status pegaprox-witness` and `journalctl -u pegaprox-witness` show the
service. On the leader, the HA tab lists the witness with the last time it was heard,
its clock offset and its release.

## Updates

The witness keeps itself up to date. When your leader runs a newer release and every
data member has renewed the lease with it (so they have a majority without the
witness), the leader tells the witness. The witness fetches the code from the leader -
or, where it cannot reach the leader's own address, from the address it paired with or
another data member it knows - checks the signature of a data member and the checksum,
installs it next to the running code and restarts into it. A fetch that does not get
through is tried again when the leader says it again (every five minutes).

A new release is on trial until it has run for three minutes answering on its port. If
it stops before that, or is not healthy within four and a half minutes, the start counts
as failed; after two failed starts the witness goes back to the previous code and does
not take that same code again by itself. Code that never answers on its port within 105
seconds (it hangs) spends both starts at once: the next start goes back, so the vote is
missing for less than two minutes. The leader then shows WITNESS_OUTDATED with the
failure and the command to update by hand, which takes it again once the cause is fixed
(or a fixed release on the leader goes in by itself). Once the new code came up, its
last update reads "up to date".

Code that changes under the same release (a fix on the Testing branch, which keeps its
release number) reaches the witness too: the leader names the bundle it serves
(release and checksum), and a witness whose code came from another bundle of that
release takes it, by itself or with `update` by hand. A witness that runs the image's own
code (Docker) takes it by hand only.

- **Turn it off:** run the installer again with `--no-auto-update` (on again with
  `--auto-update`); in Docker add `-e PEGAPROX_WITNESS_AUTO_UPDATE=0`. The leader then
  shows WITNESS_OUTDATED with the command to update by hand.
- **By hand:** `sudo pegaprox-witness update` (installer); in Docker
  `docker exec pegaprox-witness python3 pegaprox_multi_cluster.py witness update && docker restart pegaprox-witness`.
- **Docker:** updates go into the volume, so they survive a container recreate. A newer
  image always wins over older code in the volume.
- A witness one wire version behind its leader keeps voting while it updates.
- **A witness ahead of its leader** (the leader went back to an older release after the
  witness updated): on the same wire version or one apart it keeps voting, and the leader
  shows WITNESS_AHEAD with both releases. It never goes down by itself. To bring it down
  to the leader's release: `sudo pegaprox-witness update --to-leader` (in Docker
  `docker exec pegaprox-witness python3 pegaprox_multi_cluster.py witness update --to-leader && docker restart pegaprox-witness`).
  That holds until the leader moves on to a newer release: running the installer again,
  or a newer image, does not bring the newer code back.

## Remove it

On the witness host:

```sh
sudo pegaprox-witness uninstall
```

It leaves the group first and then removes the service, the command, the code, the
state and the user. In automatic mode the leader refuses to let the witness go while
that would leave fewer than three votes: switch automatic failover off first, or add a
data member. `sudo pegaprox-witness uninstall --force` removes it even when the leader
cannot be told; then also use **Remove witness** on the leader's HA page.

Docker: stop it, let it leave from its volume, then remove both (the running witness
holds its state, so `leave` runs in a container of its own, of the image it runs):

```sh
docker stop pegaprox-witness
docker run --rm -v pegaprox-witness:/app/witness ghcr.io/pegaprox/pegaprox:<version> witness leave
docker rm pegaprox-witness && docker volume rm pegaprox-witness
```

## Troubleshooting

**The leader shows the witness as not heard.** Port 5005 is not reachable from the
members. From a member: `curl -k https://<witness>:5005/api/ha/peer/status` must answer
(with a 401 - that is right, it only answers members in full). Check the firewall on the
witness host and in between, the `--allow` list, and that `--url` is an address the
members can reach.

**CLOCK_SKEW, or HA_CLOCK in the log.** The clocks are more than 5 seconds apart (more
than 120 seconds refuses every call). Run NTP on the witness host and the members:
`timedatectl` should say "System clock synchronized: yes".

**"does not match the pin in the code".** The certificate at the leader's address is
not the leader's: a proxy in between, or the leader's certificate changed after the
code was made. Make a new code on the leader. A leader behind a reverse proxy with a
certificate from a CA has no pin, and the witness checks the chain instead.

**"The pairing code is not valid" (a used or expired code).** A code is good for 15
minutes and one witness. Make a new one with "Add witness". In Docker, a container that
was never paired keeps restarting with the old code: remove it and run the new line.

**"PegaProx runs on this host".** The installer found pegaprox.service or a PegaProx on
port 5000. Put the witness on another host.

**The witness does not start after an update.** It goes back to the previous code on
the next start by itself (after two failed starts within its first three minutes).
`sudo pegaprox-witness status` shows `last_update`, the journal says why.

**"it answers on this host, but not at <address>".** The installer worked out an address
the witness does not answer at. Remove it (`sudo pegaprox-witness uninstall`), make a new
code with Add witness (the first one is used up by then) and run its line with
`--url https://<an address of this host>:5005`.

**"this witness is paired as <address>".** A run of the installer with another `--url` or
`--port` - see "A paired witness keeps its address" above.

**"cannot be read by this user".** The state belongs to the user `pegaprox-witness`:
run the command with `sudo`.

**"sudo: pegaprox-witness: command not found".** sudo looks in its own path (on RHEL
and its rebuilds /sbin, /bin, /usr/sbin and /usr/bin only). The installer links
/usr/bin/pegaprox-witness to /usr/local/bin/pegaprox-witness; where a file of that name
was there before, it leaves it and says so - call `sudo /usr/local/bin/pegaprox-witness`.

**"the leader's IP allow list refuses this host".** See the firewall section above: add
the address it names on the leader (Settings > Security), then run the line again.

**"python3-gevent is in EPEL".** RHEL, Rocky Linux or AlmaLinux 9 without EPEL: the
installer takes gevent from PyPI instead; where it cannot reach PyPI, run
`dnf install epel-release` and the line again.

**"no install.sh that matches this line".** The line carries the checksum of the
installer of the release your leader ran when it made the code. Run
`sudo sh /opt/pegaprox-witness/install.sh` on a witness host that is installed, or make a
new code with Add witness.

**"could not download install.sh from ...".** Nothing came from GitHub, the mirror or
your leader. A new code does not help here: the line above it is curl's own reason.
Check the leader's address as this host reaches it, a firewall in between, and a 403,
which is the leader's IP allow list - add this host in Settings > Security.

**"--url ... still holds the placeholder".** The Docker or manual line was run as it was
copied: put the name or address the members reach the witness at in place of
`<witness-host>`.

**"this host is still paired with another group".** A new code on a witness host that
is paired already - see "A new code on a host that is paired already" above.
