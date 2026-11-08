#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# PegaProx Proxmox VE Appliance Creator
#
# Create a Proxmox VE LXC template with PegaProx pre-installed and configured
# for automated and quicker deployments.
#
# (C) 2026 Florian Paul Azim Hoberg @gyptazy <contact@gyptazy.com>
# License: AGPL-3.0-or-later
#
# Usage:
#   SNAPSHOT build:
#     ./proxmox-lxc-appliance-creator.sh
#
#   Release build:
#     ./proxmox-lxc-appliance-creator.sh --release v0.6.2
#
###############################################################################

CTID=999
HOSTNAME=pegaprox-dev999
TEMPLATE="local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst"
STORAGE="local-lvm"
PASSWORD="admin123"
CORES=2
MEMORY=4096
DISK=30
BRIDGE="vmbr0"
ARTIFACT_DIR="/opt/pegaprox-templates/"
TODAY=$(date +%F)
RELEASE="SNAPSHOT"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)
      RELEASE="$2"
      shift 2
      ;;
    --release=*)
      RELEASE="${1#*=}"
      shift
      ;;
    --artifact-dir=*)
      ARTIFACT_DIR="${1#*=}"
      shift
      ;;
    --TEMPLATE=*)
      TEMPLATE="${1#*=}"
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--release v0.6.2] [--artifact-dir /path/to/artifacts] [--TEMPLATE template-name]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo "Creating PegaProx LXC template..."
echo "Using release: $RELEASE"

shopt -s nullglob dotglob
files=(/opt/pegaprox-templates/*)
if [ ${#files[@]} -eq 0 ]; then
  echo "Directory $ARTIFACT_DIR is empty - continuing..."
else
  echo "Directory $ARTIFACT_DIR is not empty!"
  exit 1
fi

echo "Container $CTID ($HOSTNAME) will be created using template $TEMPLATE."
pct create $CTID $TEMPLATE \
  --hostname $HOSTNAME \
  --password $PASSWORD \
  --cores $CORES \
  --memory $MEMORY \
  --rootfs $STORAGE:${DISK} \
  --net0 name=eth0,bridge=$BRIDGE,ip=dhcp \
  --unprivileged 1 \
  --features keyctl=1,nesting=1

echo "Starting container $CTID ($HOSTNAME)."
pct start $CTID
echo "Container $CTID ($HOSTNAME) created and started."

echo "Installing PegaProx in container $CTID ($HOSTNAME)."
pct exec $CTID -- bash -c "apt-get update && apt-get -y upgrade && apt-get -y install sudo curl git"
if [[ "$RELEASE" == "SNAPSHOT" ]]; then
  pct exec $CTID -- bash -c "cd /opt/ && git clone https://github.com/PegaProx/project-pegaprox.git && cd project-pegaprox && bash deploy.sh --port=5000"
else
  pct exec $CTID -- bash -c "cd /opt/ && git clone https://github.com/PegaProx/project-pegaprox.git && cd project-pegaprox && git checkout $RELEASE && bash deploy.sh --port=5000"
fi
echo "PegaProx installation in container $CTID ($HOSTNAME) completed."

echo "Cleaning up container $CTID ($HOSTNAME) before creating template."
pct exec $CTID -- bash -c "apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && history -c"
pct stop $CTID

echo "Creating LXC template from container $CTID ($HOSTNAME)."
pct template $CTID
mkdir -p $ARTIFACT_DIR
vzdump $CTID --mode stop --compress zstd --dumpdir $ARTIFACT_DIR
echo "LXC template created and stored in $ARTIFACT_DIR."

if [[ "$RELEASE" == "SNAPSHOT" ]]; then
  mv "$ARTIFACT_DIR"/*.tar.zst \
     "$ARTIFACT_DIR/pegaprox-template-SNAPSHOT-$TODAY.tar.zst"
  echo "Template created at:  $ARTIFACT_DIR/pegaprox-template-SNAPSHOT-$TODAY.tar.zst"
else
  mv "$ARTIFACT_DIR"/*.tar.zst \
     "$ARTIFACT_DIR/pegaprox-template-$RELEASE.tar.zst"
  echo "Template created at:  $ARTIFACT_DIR/pegaprox-template-$RELEASE.tar.zst"
fi

echo "Cleaning up: destroying container $CTID ($HOSTNAME)."
pct destroy "$CTID"
echo "Process completed successfully."