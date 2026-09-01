#!/usr/bin/env bash
# Build a signed APT repository (flat dists/pool layout) from one or more .deb files.
# Prototype for hosting PegaProx's own Debian package on GitHub Pages, so users can
# `apt install pegaprox` from us instead of relying on a third-party repo.
#
# Proven locally with dpkg-deb + apt-ftparchive + gpg (the exact tools this uses).
# The signing key must already be imported into the active GNUPGHOME before calling
# this (in CI: import ${{ secrets.APT_GPG_PRIVATE_KEY }}; locally: your own key).
#
# Usage:
#   packaging/apt/build-apt-repo.sh <deb-dir> <out-dir> <gpg-key-id> [suite] [component]
#     <deb-dir>    directory containing the .deb(s) to publish
#     <out-dir>    directory to write the repo into (served as the Pages root)
#     <gpg-key-id> the signing key's fingerprint or uid/email (must be in GNUPGHOME)
#     [suite]      default: stable
#     [component]  default: main
set -euo pipefail

DEB_DIR=${1:?deb-dir required}
OUT=${2:?out-dir required}
KEY=${3:?gpg-key-id required}
SUITE=${4:-stable}
COMP=${5:-main}
ORIGIN=${APT_ORIGIN:-PegaProx}

command -v apt-ftparchive >/dev/null || { echo "apt-ftparchive missing (apt: apt-utils)"; exit 1; }
command -v gpg >/dev/null || { echo "gpg missing"; exit 1; }

# arch:all package → we still publish a binary-all index plus the arch indexes apt asks for.
ARCHES="all amd64 arm64"

rm -rf "$OUT"
mkdir -p "$OUT/pool/$COMP/p/pegaprox"
cp "$DEB_DIR"/*.deb "$OUT/pool/$COMP/p/pegaprox/"

cd "$OUT"
for a in $ARCHES; do
  mkdir -p "dists/$SUITE/$COMP/binary-$a"
  # arch:all debs are surfaced under every requested arch so `apt-get install` on any host resolves.
  apt-ftparchive --arch "$a" packages "pool/$COMP" > "dists/$SUITE/$COMP/binary-$a/Packages"
  gzip -kf "dists/$SUITE/$COMP/binary-$a/Packages"
done

apt-ftparchive \
  -o "APT::FTPArchive::Release::Origin=$ORIGIN" \
  -o "APT::FTPArchive::Release::Label=$ORIGIN" \
  -o "APT::FTPArchive::Release::Suite=$SUITE" \
  -o "APT::FTPArchive::Release::Codename=$SUITE" \
  -o "APT::FTPArchive::Release::Components=$COMP" \
  -o "APT::FTPArchive::Release::Architectures=$ARCHES" \
  release "dists/$SUITE" > "dists/$SUITE/Release"

# Detached + inline signatures (apt accepts either; ship both).
gpg --batch --yes --default-key "$KEY" -abs  -o "dists/$SUITE/Release.gpg" "dists/$SUITE/Release"
gpg --batch --yes --default-key "$KEY" --clearsign -o "dists/$SUITE/InRelease" "dists/$SUITE/Release"

# Public key users pin with `signed-by=`.
gpg --armor --export "$KEY" > "pegaprox-archive-keyring.asc"

# A tiny landing page so the Pages root isn't a bare directory listing.
cat > index.html <<HTML
<!doctype html><meta charset=utf-8><title>PegaProx APT repository</title>
<h1>PegaProx APT repository</h1>
<p>Add it with:</p>
<pre>curl -fsSL https://pegaprox.github.io/apt/pegaprox-archive-keyring.asc \\
  | sudo gpg --dearmor -o /etc/apt/keyrings/pegaprox.gpg
echo "deb [signed-by=/etc/apt/keyrings/pegaprox.gpg] https://pegaprox.github.io/apt $SUITE $COMP" \\
  | sudo tee /etc/apt/sources.list.d/pegaprox.list
sudo apt-get update && sudo apt-get install pegaprox</pre>
HTML

echo "Built signed apt repo in $OUT:"
find . -type f | sort
