# Node addresses and ports

PegaProx reaches a cluster at one host and talks to Proxmox VE there. For anything that
has to go to a particular node — SSH, the node shell, a failover onto it — it resolves
that node's own management address out of the API and dials it on the cluster's SSH port
(`ssh_port`, default 22) or API port (`api_port`, default 8006).

That holds for a cluster whose nodes PegaProx can route to. It does not hold when the
nodes sit behind a forward: one public address with a port per node, a jump host, a node
moved behind its own firewall. There the addresses the nodes report for themselves are
exactly the ones PegaProx cannot reach, and one port per cluster cannot name five
listeners on one address.

**Node endpoints** name what deviates, per node.

## Setting them

In the cluster's **Settings** tab, section *Node addresses and ports*: one row per node,
with an address, an SSH port and a GUI port. Every field is optional and an empty one
means "as the cluster" — which is every field of every node until an operator fills one
in. A cluster with no entries behaves exactly as before.

Over the API it is the field `node_endpoints` of `PUT /api/clusters/<id>`,
`PATCH /api/clusters/<id>/config` and `POST /api/clusters`:

```json
{
  "node_endpoints": {
    "node01": {"host": "203.0.113.9", "ssh_port": 2201, "api_port": 8006},
    "node02": {"host": "203.0.113.9", "ssh_port": 2202, "api_port": 8007},
    "node03": {"ssh_port": 2203}
  }
}
```

`host` is a bare host name or address: no scheme, no path, and no port glued to it
(the port has its own field). The ports are 1..65535, the keys node names, and the map
takes at most 512 nodes. Anything else is a 400, naming the node and the field, rather
than a save that silently drops what was typed; adding a cluster, a re-configure and an
edit check it alike, and a backup restore drops a map that does not pass. A node whose
entry ends up empty is not stored.

Changing it needs `cluster.config` on the whole cluster.

### It needs the credential again

A new address or a changed port moves where the cluster's password or API token secret
is offered, so the same rule applies as to `host`, `fallback_hosts` and `ssh_port`: the
request has to carry the credential again (`pass`, or `api_token_secret` on a token
cluster), else it is refused with `CREDENTIAL_REQUIRED`. The UI asks for it and sends it
with the save. An entry whose address and ports are a listener the cluster already uses
(its host or a fallback host on its SSH and API port, or another node's entry) is not a
move and needs nothing. The same address on another port is a move.

Like the other endpoint edits, a node's own stored root password is dropped by the move
rather than carried to the new address.

## What uses them

An entry with a `host` replaces address discovery for that node, before the probing and
before the per-node circuit breaker: there is nothing to probe and nothing that can fail,
so the address is simply the answer. It is used by

- every SSH connection to the node (node shell, updates, maintenance mode, the HA checks
  and the SSH fence, Ceph/`rbd`, storage, the LVM snapshot probe, the connection check,
  removing a node, the relayed cross-cluster replication);
- the reachability probe that decides whether a node answers at all;
- a failover of the API connection onto that node, when it answers on the cluster's API
  port: everything after the connect pairs the host with the cluster's `api_port`;
- the *Open in Proxmox* links, at its address and its GUI port.

The SSH port is picked by node name, not by address: several nodes behind one address on
different ports are told apart only by the name, which is why the node travels with the
address into the connection. A node's own port goes only with its own address: where
PegaProx dials another address of that node (one it reports for itself, a transfer
address, the cluster host as a last resort) it uses the cluster's port.

Migrations **between** the nodes of one cluster are not affected: those are Proxmox VE's
own traffic on its own network, and PegaProx only asks for them. A **transfer network**
address is not affected either — that is the node's own address on a directly reachable
network, so it answers on the cluster's SSH port, not on whatever forwards the node's
management address. Neither is the opt-in VNC SSH tunnel, which goes to the cluster's
connected host on the cluster's SSH port.

## What they do not do

They do not make PegaProx a reverse proxy, and they are not a way to put one in front of
Proxmox VE. The connection is still direct TLS to the node: a forward may move the port,
but nothing may terminate the TLS on the way — an intermediate hop that re-encrypts is
a hop that can read and change everything on it.

They also do not change the cluster's own connection. `host`, `ssh_port` and `api_port`
on the cluster stay what PegaProx connects to and what every node without an entry uses.
