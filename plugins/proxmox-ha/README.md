# proxmox-ha — PegaProx Plugin

Adds Proxmox native HA (High Availability) resource management to PegaProx.

PegaProx does not currently expose Proxmox's `/cluster/ha/resources` API surface. This plugin bridges that gap by routing HA operations through the existing authenticated cluster manager session — no additional credentials required.

## Features

- List all HA-managed resources in a cluster
- Register a VM or container as an HA resource
- Update HA resource settings (state, restart/relocate limits)
- Remove a VM or container from HA management

## Installation

1. Copy the `proxmox-ha/` folder into your PegaProx `plugins/` directory:
   ```
   plugins/
   └── proxmox-ha/
       ├── __init__.py
       ├── manifest.json
       └── README.md
   ```

2. In the PegaProx UI go to **Settings → Plugins** and enable **Proxmox HA Resources**.

3. The plugin registers the route `/api/plugins/proxmox-ha/api/ha` automatically.

> **Note:** The `plugins/` directory must be bind-mounted into the container. In `docker-compose.yml`:
> ```yaml
> volumes:
>   - ./plugins:/app/plugins
> ```

## Authentication

All requests require a valid PegaProx Bearer token (the same token used for all other PegaProx API calls):

```
Authorization: Bearer <your-pegaprox-token>
```

## API Reference

All endpoints are prefixed with `/api/plugins/proxmox-ha/api/ha`.

---

### List all HA resources

```
GET /api/plugins/proxmox-ha/api/ha?cluster_id=<id>
```

**Response:**
```json
{
  "data": [
    { "sid": "vm:100", "state": "started", "max_restart": 1, "max_relocate": 1 },
    { "sid": "vm:101", "state": "started", "max_restart": 1, "max_relocate": 1 }
  ]
}
```

---

### Get a specific HA resource

```
GET /api/plugins/proxmox-ha/api/ha?cluster_id=<id>&sid=vm:<vmid>
```

**Response:**
```json
{
  "data": { "sid": "vm:100", "state": "started", "max_restart": 1, "max_relocate": 1 }
}
```

---

### Add a VM to HA

```
POST /api/plugins/proxmox-ha/api/ha
Content-Type: application/json

{
  "cluster_id": "<id>",
  "sid": "vm:<vmid>",
  "state": "started",
  "max_restart": 1,
  "max_relocate": 1
}
```

| Field | Required | Values | Default |
|---|---|---|---|
| `cluster_id` | yes | PegaProx cluster ID | — |
| `sid` | yes | `vm:<vmid>` or `ct:<vmid>` | — |
| `state` | no | `started`, `stopped`, `enabled`, `disabled` | `started` |
| `max_restart` | no | integer | Proxmox default |
| `max_relocate` | no | integer | Proxmox default |

**Response:**
```json
{ "message": "Added vm:100 to HA resources" }
```

---

### Update an HA resource

```
PUT /api/plugins/proxmox-ha/api/ha
Content-Type: application/json

{
  "cluster_id": "<id>",
  "sid": "vm:<vmid>",
  "state": "stopped",
  "max_restart": 2
}
```

At least one of `state`, `max_restart`, or `max_relocate` must be provided.

**Response:**
```json
{ "message": "Updated HA resource vm:100" }
```

---

### Remove a VM from HA

```
DELETE /api/plugins/proxmox-ha/api/ha?cluster_id=<id>&sid=vm:<vmid>
```

**Response:**
```json
{ "message": "Removed vm:100 from HA resources" }
```

---

## Error Responses

| Status | Meaning |
|---|---|
| `400` | Missing or invalid parameters |
| `404` | HA resource not found |
| `502` | Proxmox returned an unexpected status; `detail` field contains the Proxmox error |
| `500` | Unexpected plugin error |

Example error:
```json
{
  "error": "Proxmox returned 400",
  "detail": "sid already exists in HA resources"
}
```

## Compatibility

- **PegaProx:** 0.9.3 Beta or later
- **Proxmox VE:** 7.x and 8.x
