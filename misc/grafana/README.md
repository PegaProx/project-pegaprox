# PegaProx Grafana Dashboard

## PegaProx API Token
Access to metrics exposed by PegaProx is secured and requires proper authentication. This ensures that only authorized systems or users can retrieve monitoring data from the exporter endpoint.

To authenticate against the exporter, an API token must be provided with each request. This token acts as a credential and is required for all metric queries.

### Obtaining an API Token
It is recommended to create a dedicated technical account for monitoring purposes. Using a separate account improves security, auditability, and avoids unintended side effects from personal user accounts.

Follow these steps to generate a suitable API token:
* Log in to PegaProx with an administrative or authorized user account.
* Navigate to the User Settings section.
* Create a new API key for the technical account.
* Assign read-only permissions to the API key to restrict access strictly to metric retrieval.
* Copy and securely store the generated API token.

## Prometheus Exporter
To collect metrics from PegaProx, you need to configure Prometheus to scrape the built-in exporter endpoint. Since the metrics endpoint is secured, a few additional settings are required compared to a default scrape job.

PegaProx exposes its metrics over HTTPS on port 5000 under the path /api/metrics. Because of this, you must explicitly enable TLS in your Prometheus configuration. In addition, authentication is required, so you need to create an API token in PegaProx and pass it along with each request.

```
- job_name: 'pegaprox'
  metrics_path: /api/metrics
  scheme: https
  authorization:
    type: Bearer
    credentials: pgx_token123token123
  tls_config:
    insecure_skip_verify: true
  static_configs:
    - targets: ['pegaprox01.int.gyptazy.com:5000']
```

### Storage, replication and backup series
Next to the cluster, node and guest gauges the exporter has, per cluster:

| Series | Labels | Where it comes from |
|---|---|---|
| `pegaprox_storage_used_bytes`, `pegaprox_storage_total_bytes`, `pegaprox_storage_active` | `node` (empty for a shared storage), `storage`, `type`, `shared`, `sr_uuid` on XCP-ng | Proxmox VE: one `/cluster/resources?type=storage` per cluster, shared with the health score and the storage overview for 30 seconds. A shared storage is one series, not one per node. XCP-ng: the SR list of the pool. |
| `pegaprox_storage_inactive_nodes` | as above | Nodes that list a shared storage without having it active. |
| `pegaprox_replication_last_sync_timestamp_seconds`, `pegaprox_replication_last_sync_age_seconds`, `pegaprox_replication_fail_count`, `pegaprox_replication_failed`, `pegaprox_replication_enabled` | `job`, `vmid`, `node` (source), `target` | The replication job list and the status of each source node, read at most once a minute. |
| `pegaprox_guest_last_backup_timestamp_seconds`, `pegaprox_guest_last_backup_age_seconds` | the guest labels | The newest backup of each guest in the snapshot lists of the PBS servers linked to the cluster and in the vzdump files on its backup storages, the scan behind the backup column of the VM list, read at most every ten minutes. Templates are left out. |
| `pegaprox_guest_disk_read_bytes_total`, `pegaprox_guest_disk_write_bytes_total` | the guest labels | `/cluster/resources`, next to the network counters. |
| `pegaprox_cluster_source_up` | `source` = `storage`, `replication` or `backups` | 1 when the last read of that source answered in full. |

A timestamp of 0 means never: a replication job that never synced, a guest without a backup. Those have no age series. Replication and backup reads run in the background, so the first scrape after a start has `pegaprox_cluster_source_up` 0 for them. A job whose source node did not answer, and the backup ages of a scan that did not finish, are left out rather than shown as fine.

Examples:
```
pegaprox_storage_used_bytes / pegaprox_storage_total_bytes > 0.9
pegaprox_replication_failed == 1
pegaprox_guest_last_backup_age_seconds > 86400 * 2
time() - pegaprox_guest_last_backup_timestamp_seconds > 86400 * 2
```

### Node health and guest tag series
| Series | Labels | Where it comes from |
|---|---|---|
| `pegaprox_node_clock_offset_seconds` | `node` | The node's clock minus the clock of the PegaProx host, from `/nodes/<node>/time` of every online node, read at most every five minutes and shared with the node clock drift alert. Proxmox answers whole seconds, so read it as about 0.5 s plus half the round trip either way. |
| `pegaprox_node_temperature_celsius` | `node` | The hottest sensor of the node from the 5-minute hardware poll (lm-sensors or the kernel's hwmon over SSH). A scrape reads the cache only. |
| `pegaprox_node_power_watts` | `node` | The power draw the node's BMC reports (in-band IPMI or Redfish), from the same poll, for nodes whose hardware health PegaProx is allowed to read. |
| `pegaprox_node_pressure_some_percent`, `pegaprox_node_pressure_full_percent` | `node`, `resource` = `cpu`, `memory` or `io` | Pressure stall information: the share of time in which some (or all non-idle) tasks waited, 10 s average, from the newest point of the node's RRD, read once a minute. Proxmox VE 9 and later; a node whose RRD has none is asked again an hour later. |
| `pegaprox_guest_pressure_some_percent`, `pegaprox_guest_pressure_full_percent` | the guest labels, `resource` | The same for running guests, where Proxmox VE lists it with the guests in `/cluster/resources`. Never read per guest. |
| `pegaprox_guest_tag_info` | `cluster_id`, `cluster`, `vmid`, `tag` | Always 1: one series per tag of a guest, the Proxmox tags and the tags set in PegaProx, in lower case, at most 10 per guest. |
| `pegaprox_cluster_source_up` | `source` = `clock` or `node_pressure` | 1 when every online node answered the last read. |
| `pegaprox_cluster_qdevice_connected` | `node` | 1 when the QDevice daemon (corosync-qdevice) of the node is connected to the QNetd host, 0 when it is not or the node runs no daemon while the cluster has a QDevice. From `/cluster/config/qdevice` of each node PegaProx can reach at an address of its own (the API host and the fallback hosts); the other nodes have no series. A scrape never reads it: it is the last read of the QDevice view in the UI or of the QDevice alert rule, at most 30 seconds apart while either runs, and left out once it is older than 5 minutes. Clusters without a QDevice have no series. |

The tags are their own series so the guest series keep their labels when a tag changes. Join them on `cluster_id` and `vmid`:
```
pegaprox_guest_cpu_percent * on(cluster_id, vmid) group_left() pegaprox_guest_tag_info{tag="prod"}
count by (tag) (pegaprox_guest_tag_info)
max by (cluster, node) (abs(pegaprox_node_clock_offset_seconds)) > 2
pegaprox_node_pressure_some_percent{resource="io"} > 20
min by (cluster) (pegaprox_cluster_qdevice_connected) == 0
```

Node clock drift, guest restart loops and a QDevice that is not connected are alert rules in PegaProx as well (Automation > Alerts), with one message when it starts and one when it clears, through e-mail, push and the webhook channels like every alert.

The QNetd host of a QDevice is no Proxmox node. PegaProx sees it only through the QDevice daemons of the cluster nodes, so there is no CPU, memory or update series for it: watch it with an exporter on that host itself.

## Grafana Dashboard
You can simply import the dashboard or JSON file to your Grafana instance.

| File | What it shows |
|---|---|
| `pegaprox_grafana_dashboard_v1.1.json` | Clusters, nodes, guests, sessions, PBS and ESXi connectivity |
| `pegaprox_grafana_dashboard_node_health_v1.0.json` | Clock offset, temperature, measured power and CPU, memory and IO pressure per node |
| `pegaprox_grafana_dashboard_guests_by_tag_v1.0.json` | Load, network, disk, pressure and backup age of the guests that carry the tags you pick |