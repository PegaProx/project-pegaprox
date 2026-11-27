# Windows guests in an ESXi migration

A Windows guest moved from ESXi to Proxmox VE needs more than its disks: the VirtIO drivers,
its static IPv4 configuration on the new network adapter, the ESXi guest tools gone, and the
disks on VirtIO SCSI. PegaProx does all of it on its own for every Windows guest. Nothing has
to be typed in and nothing in the guest has to be done by hand; the source VM on ESXi is not
changed, so giving a migration up needs nothing but powering the source on again.

## What happens

1. **Planning.** The guest counts as Windows by its ESXi guest OS (or the `ostype` you chose).
   PegaProx looks for `virtio-win.iso` on the target node (`virtio_iso_path`,
   `/var/lib/vz/template/iso/`, `/mnt/pve/<target storage>/template/iso/`,
   `/var/lib/pegaprox/`). When there is none and the migration may install packages
   (`allow_package_install`, on by default), it downloads
   `https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso`
   over HTTPS with certificate checking into `/var/lib/vz/template/iso/virtio-win.iso`; the
   task log shows its sha256. The download is one item of the node package plan of the review;
   it gives up after 55 minutes, and a download that was cut off leaves no file behind.
2. **The VM** is created with the controller VirtIO SCSI single and VirtIO network adapters
   (where you left them on auto).
3. **After the copy** (the VM stopped), PegaProx mounts the Windows volume of the boot disk on
   the node, adds the drivers, and reads from the copied registry: the static IPv4 addresses,
   masks, gateways and DNS servers of every adapter, which adapter each one belongs to (its
   MAC where Windows or ESXi kept one; adapters of hardware the guest no longer has stay as
   they are), the uninstall entry of the ESXi guest tools (found
   through the folder of the program the `VMTools` service runs) and the old ESXi network
   devices. It stages, in `C:\ProgramData\KVMMigration`, the driver and guest agent packages
   of the ISO, `netconfig.json` (the saved network), `firstboot.cmd` and its data, and a
   one-shot SYSTEM service `PegaProxFirstBoot`. The folder and every file in it are left to
   SYSTEM and the Administrators before the service is registered; if that cannot be done,
   no service is registered. Any user of the guest may create a folder in `ProgramData`: a
   `KVMMigration` there already that is a link or a junction, or that someone other than
   SYSTEM and the Administrators can change, is moved aside as `KVMMigration.untrusted-<run>`
   (a warning names it) and nothing in it is used.
4. **The first boot on Proxmox VE** runs `firstboot.cmd` as SYSTEM, before anyone logs on. It
   uses console tools only (reg, sc, netsh, pnputil, msiexec), so no PowerShell execution
   policy can stop it:
   - the VirtIO drivers and the QEMU guest agent are installed, `vioscsi` and `viostor`
     start at boot;
   - the interface of the old adapter loses its static address (no "the IP address is
     already assigned to another adapter"), the saved address goes onto the new adapter: by
     MAC (the source's MAC when "preserve MAC" is on, else the MAC Proxmox gave that NIC),
     else by order;
   - the old ESXi network devices are removed where Windows can (pnputil `/remove-device`,
     Windows 10 2004 and Server 2022 or later; older versions keep them as hidden devices
     without an address);
   - the ESXi guest tools are uninstalled, never while a disk or a NIC still runs on one of
     their drivers (pvscsi, vmxnet3); when that fails their service is disabled;
   - every step goes to `C:\ProgramData\KVMMigration\migrate.log`, the outcome to
     `firstboot.json`, and the script removes its service. An address that could not be put
     back is tried again at the next two boots.
5. **The two-stage boot.** Windows 8 and later do not bind the VirtIO SCSI driver at an early
   boot from offline registry changes alone (Server 2025 stopped with
   INACCESSIBLE_BOOT_DEVICE). So the first boot runs with the boot disk on SATA (AHCI) and a
   VirtIO SCSI device present (the other disks, or a 1 GiB temporary disk): Plug and Play
   installs the driver for it. PegaProx checks through the guest agent that `vioscsi` is
   bound and starts at boot, shuts the guest down, moves the boot disk to `scsi0`, removes the
   temporary disk and boots again. With "start after migration" off it does the same and
   shuts the VM down at the end. Windows 7 and Server 2008 R2 start on IDE instead of SATA.

PegaProx reads `firstboot.json` and the log through the guest agent and puts the outcome
into the migration log; anything that did not work is a warning of the migration, never a
failed migration.

## When it does not run, and what then

| Case | Outcome |
|---|---|
| no `virtio-win.iso` and the download failed or is not allowed | the guest keeps the controller and NIC model of the source, warning |
| `install_virtio_drivers: false` | no preparation, no two-stage boot |
| Live Mirror (`sshfs_boot`) | the guest boots on the target before anything can be staged: controller and NICs of the source |
| the injection failed after the copy | the NICs go back to the model of the source, the disks to the controller and bus of the source |
| the driver package was not on the ISO, or the first boot could not be staged | the NICs go back to the model of the source (nothing would install the VirtIO network driver), the disks to the controller of the source |
| the guest agent does not answer in the first boot, or `vioscsi` is not bound | the disks stay on (or go back to) SATA, warning |
| the second boot from VirtIO SCSI does not come up | the boot disk goes back to SATA and the guest starts from there, warning |

Over the API: `install_virtio_drivers` (absent = on for Windows, false = off),
`two_stage_boot` (absent or null = the rule above, false = off, true is refused where it
cannot run), `virtio_iso_path`, `allow_package_install`. The dry run answers
`windows_prep` and `two_stage` with what will happen.

## With a Windows login (optional)

With `guest_prep: true`, `guest_user` and `guest_password` (in the wizard: "Prepare Windows
in the running guest"), PegaProx prepares the guest before the copy as well, over the
guest operations of the ESXi host. This needs the ESXi server connected over SOAP, the
ESXi guest tools running in the guest and an account with a full administrator token: with
UAC on, that is the built-in Administrator (or a domain admin where UAC remote restrictions
are off). The login is used for this and nothing else; it is never stored, logged or
returned. `POST /api/vmware/<id>/vms/<vm_id>/guest-login` checks it with one login attempt
(at most 5 checks per guest and 15 over all guests in 5 minutes).

The preparation runs the script of `GET /api/vmware/guest-prep-script` in the guest: drivers
into the Driver Store, the virtio-win guest tools and the guest agent installed, `vioscsi`
and `viostor` as boot drivers, the static IPv4 saved, the first boot task registered. At the
switchover it releases the static IPv4 from the old adapter, uninstalls the ESXi guest tools
and shuts the guest down; PegaProx does not power the source on again.

If the guest tools do not run, the login is refused, the token is filtered by UAC, a group
policy blocks the script, or anything fails before the guest is released, PegaProx says why
and prepares the guest offline as above: the migration goes on. If the copy or the
switchover fails after the guest was released, PegaProx powers the source on again in ESXi
and mounts the installer of the ESXi guest tools; the first boot task in the guest finds
itself on ESXi, reinstalls the tools from that CD, puts the saved address back on the ESXi
adapter and removes itself. PegaProx unmounts the installer once the tools run again. The
task starts nothing it finds on a drive: the installer has to be on a CD drive and carry a
valid signature of the publisher of the guest tools the guest had (saved before they were
uninstalled); it is copied into `C:\ProgramData\KVMMigration`, checked again there, and that
copy runs. This one check uses PowerShell (`-ExecutionPolicy Bypass`), nothing else on Windows
can check a signature.

## By hand

The script of `GET /api/vmware/guest-prep-script` (`Prepare-KvmMigration.ps1`) can also be
run by an administrator in the guest on ESXi, with `virtio-win.iso` in a CD drive:

    powershell -ExecutionPolicy Bypass -File Prepare-KvmMigration.ps1

It does the same as the in-guest preparation and shuts the guest down (`-NoShutdown` leaves
that to you). Migrate the guest afterwards and do not power it on again on ESXi; the first
boot on Proxmox VE takes the saved network from it.
