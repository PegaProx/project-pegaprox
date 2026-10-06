# Central image library

PegaProx can create VMs from one central catalog on separate Proxmox VE hosts.
Add each standalone host as a connection in PegaProx; the hosts do not need to
join a PVE cluster or share storage. Existing VM management continues through
the selected connection.

## Use

1. Open **Automation → Images & templates → Central image library**.
2. As an administrator, upload an installation `.iso` or an uncompressed
   x86-64 Cloud-init disk (`.img` / `.qcow2`). Alternatively, add a public HTTP(S)
   URL. The existing curated cloud-image catalog is also available here.
3. Choose **Create VM**, select a connection and node, enter the VM name,
   and confirm the storage, bridge and resource defaults.
4. For a cloud image, provide SSH public keys and a Cloud-init username.
   Networking uses DHCP. Choose a disk at least as large as the image's virtual
   disk. For an ISO, select storage supporting `iso` and complete installation
   through the VM console. Windows installations may need VirtIO drivers and
   additional configuration; this is not an unattended Windows installer.
5. Follow the job's progress below the catalog. After completion, manage the
   VM through the existing VM list, console and lifecycle controls.

The **Cloud-Init Template Library** view remains available for creating reusable
node-local templates. Central provisioning creates a regular VM directly.

## Requirements and storage

- PegaProx needs API access and **root SSH/SFTP access** to the selected node.
  Configure SSH credentials and host-key trust through the existing connection
  settings. API-token authentication alone cannot transfer/import images.
- VM storage must support `images`; ISO provisioning also requires storage
  supporting `iso`. Network bridges and online nodes are discovered from PVE.
- Central files live in `<PEGAPROX_CONFIG_DIR>/image-library/`, next to the
  database. Persist/back up the entire config directory (including images).
  The config filesystem and target storage need sufficient space. Cloud images
  temporarily also occupy the target node's `/tmp` during import.
- `PEGAPROX_IMAGE_MAX_GB` limits each file (default **20 GiB**). The existing
  `PEGAPROX_UPLOAD_MAX_GB` HTTP upload limit and any reverse-proxy request limit
  also apply. For larger uploads, adjust those limits and the proxy timeout.
- Two provisioning jobs can run concurrently per PegaProx process; additional
  requests return HTTP 429. Deployment uses the existing single-process server.

URLs are downloaded by PegaProx on first use, then reused centrally. Only public
HTTP(S) destinations are allowed; redirects are rechecked. Upload private-network
or offline images instead. Supply the publisher's SHA-256 to verify a URL download
or upload. Uploaded files always have their SHA-256 recorded. Transfer to the
node is verified against the central file's hash before creating a VM.

Cloud disks are transferred to a temporary node file, imported, attached using
the actual volume ID returned by `qm config`, resized and configured for
Cloud-init. Temporary disks and key files are removed after the job. ISO files
use content-addressed names in the selected ISO storage, allowing reuse on that
node. There is no requirement to pre-upload the ISO to each node.

Removing a custom image deletes its catalog entry and central file; clearing a
curated image's cache keeps its catalog entry. Both operations refuse images
with active jobs. **Copies in PVE ISO storage remain**, because existing VMs may
still reference them; remove those copies through the normal PVE storage tools
after checking their users. A cached URL image remains fixed until removed and
re-added (or its curated cache cleared).

## Permissions, failures and HA

This first version is an administrator workflow. Catalog reads require
`cluster.view`; adding/removing images also requires `admin.settings`; VM
creation requires `vm.create`. Target and job endpoints verify the connection's
scope. Restricted tokens and tenant-downgraded admins cannot use the admin
workflow. Source URLs, credentials and SSH public keys are absent from job
records and public catalog responses.

Failures after a successful `qm create` attempt to destroy only the VM created
by that job. A rejected `qm create`, including an existing VMID collision, never
authorizes deleting that VMID. If rollback fails, the job reports the remaining
VMID for manual inspection. Jobs interrupted by a server restart are marked
failed and **never replayed automatically**: inspect the target and recorded
VMID before retrying, as the remote VM could already exist.

The catalog, cache and job history are **instance-local**. They are excluded
from PegaProx HA database synchronization because that does not transfer image
files. Use the same PegaProx instance for this workflow; an HA takeover does not
provide automatic image-library replication. Outbound node operations use the
existing HA transport guard and job context.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/images` | Common catalog, cached status and defaults |
| `POST /api/images` | Add URL: `name`, `kind`, `source_url`, optional `sha256` / `default_user` |
| `POST /api/images/upload` | Multipart `file`, `name`, `kind`, optional `sha256` / `default_user` |
| `DELETE /api/images/<id>` | Remove custom image or evict curated cache |
| `GET /api/clusters/<id>/images/targets[?node=<name>]` | Online nodes; selected node's storage and bridges |
| `POST /api/clusters/<id>/images/provision` | Queue VM creation; returns `job_id` (HTTP 202) |
| `GET /api/clusters/<id>/images/jobs` | Most recent 50 jobs on this connection |

Provision JSON includes `image_id`, `node`, `name`, `storage`, `bridge`, optional
`cores`, `memory` (MiB), `disk_gb` (GiB), `vmid` and `start` (boolean).
Cloud images require `sshkeys` and optionally `ciuser`. ISO images require
`iso_storage` and optionally `ostype` (`l26`, `win10`, `win11`, `other`);
Windows 11's TPM/firmware requirements must be configured separately.
