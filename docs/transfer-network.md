# Transfer network of a cluster

By default every remote migration PegaProx starts towards a Proxmox VE cluster goes to
that cluster's management host: the host (or fallback host) PegaProx itself is
connected to. The disk data of the guest then crosses the management network. A cluster
can name a dedicated network for this traffic instead, its **transfer network**.

Set it in the cluster's **Settings** tab, section *Transfer Network*, as a network in
CIDR notation, IPv4 or IPv6 (for example `10.20.0.0/24` or `fd00:20::/64`). Empty means
off. Over the API it is the field `transfer_network` of `PUT /api/clusters/<id>` and
`PATCH /api/clusters/<id>/config`; PegaProx stores the network address
(`10.20.0.5/24` becomes `10.20.0.0/24`) and refuses anything that is not a network
(400), as well as loopback, link-local, multicast and catch-all networks. Changing it
needs `cluster.config` on the whole cluster; it is set on the active instance and
reaches the standbys with the next sync.

## What uses it

The setting belongs to the cluster that **receives** the traffic. Every remote migration
PegaProx starts towards it dials the target node at that node's address in the network:

- a cross-cluster migration by hand, one guest or many (`POST /api/cross-cluster-migrate`);
- a full cross-cluster replication run (snapshot, clone, remote migrate);
- a Site Recovery failover or failback (planned; an emergency failover migrates nothing);
- the cross-cluster load balancer.

The raw route `POST /api/clusters/<id>/vms/<node>/<type>/<vmid>/remote-migrate` takes a
complete target endpoint from its caller and is not changed.

A remote migration lands on the node it dials. Where a target node is named (by hand,
by the replication job, by the balancer), that node's address is used. Site Recovery
names none: it takes the node behind the management host when that node has an address
in the network, else the first online node that has one.

Migrations between the nodes of one cluster are not affected. Proxmox VE already has a
setting for those, the datacenter option *migration network*. The section shows its
current value for reference; it is changed under Datacenter > Options > Migration
Settings.

## How the address and certificate are found

A node's address is read from the node's own network configuration
(`/nodes/<node>/network`): the first address inside the network, an interface that is
up before one that is down. The configuration is cached for ten minutes per node.
Opening the settings never fans out to the nodes: it shows what is cached and reads the
missing nodes once in the background (shown as *reading network config...* meanwhile).

The certificate fingerprint handed to Proxmox VE in the target endpoint is the one the
node reports for itself through the API PegaProx is signed in to (`pveproxy-ssl.pem` if
present, else `pve-ssl.pem`), never what answers on the transfer address. A host on the
transfer network that is not the node is refused by the source node.

## When it cannot be used

If the target node has no address in the network, its network configuration or its
certificate cannot be read, or the node is not a member of the cluster, the migration
goes to the management host as before, and PegaProx says so:

- the cluster log of the source cluster (`logs/<cluster>.log`) names the reason each time;
- the audit log gets an entry `migration.transfer_network_fallback`, once an hour per
  node and reason;
- a migration by hand shows a warning toast, and its answer carries
  `transfer_network: {network, node, via, host, reason}` with `via: "management"`;
- a Site Recovery run shows it in its progress.

The settings list each node's address and marks the nodes that have none.

## Replication relayed by PegaProx

The incremental replication of Ceph RBD and ZFS disks does not use remote migrate:
PegaProx runs the exporter on the source node and the importer on the target node over
SSH and relays the data itself. For each of the two nodes it uses the transfer address
of that node's cluster only when

- PegaProx reaches it over SSH, and
- the SSH host key presented there is the one already pinned for the node's management
  address (`config/.ssh_known_hosts`).

The connection to the transfer address is checked against that pin before any
credential is sent, and nothing new is pinned for it. If either condition fails, the
management address is used and the transfer address is not tried again for ten minutes.
A node whose management address has never been connected to has no pin yet: its first
run goes over the management address.

## Testing reachability

With a network saved, the section can test from one node of a source cluster whether
the transfer addresses of all nodes answer on port 8006, the port the remote migration
uses (`POST /api/clusters/<id>/transfer-network/check` with
`{"source_cluster": ..., "source_node": ...}`). PegaProx logs in to that node over SSH
once, through the same path as its other node checks, and opens one TCP connection per
address from there in parallel; nothing is changed. It needs `cluster.config` on both
clusters, and SSH to the source cluster (a cluster with SSH switched off or without SSH
credentials is refused with the reason). On a standby it is forwarded to the active or
refused, like any other action.

`GET /api/clusters/<id>/transfer-network` returns the per-node view (`cluster.view`);
`?network=<cidr>` previews another network before it is saved.
