#!/usr/bin/env bash
# Build a signed APT repository (dists/ + pool/) from a directory of .deb files.
#
#   packaging/apt/build-apt-repo.sh <deb-dir> <out-dir> <key-fingerprint> [keyring.asc]
#
#   <deb-dir>          the .debs to publish: pegaprox (every version that should stay
#                      installable) and the python3-* packages trixie does not carry
#   <out-dir>          written from scratch, served as the root of the repository
#   <key-fingerprint>  the signing key, already in the active GNUPGHOME
#   [keyring.asc]      the public key users pin with signed-by. When given it is copied
#                      next to dists/ and an index.html with the install lines is written;
#                      the smoke test leaves it out.
#
# One suite, trixie, one component, main. Every package is Architecture: all; apt-ftparchive
# lists them in binary-all and in each of binary-amd64/arm64, so either kind of host finds
# them whether or not its apt reads binary-all. Release gets Origin/Label PegaProx and is
# signed twice, InRelease (inline) and Release.gpg (detached).
#
# Env: APT_SUITE (trixie), APT_COMPONENT (main), APT_ARCHES ("all amd64 arm64"),
#      APT_SITE_URL (https://apt.pegaprox.com, only used for index.html)
#
# NS Oct 2026 - grew from the single-package prototype: several packages, old pegaprox
# versions stay in the pool, the key comes from the repo instead of the signing keyring.
set -euo pipefail

DEB_DIR=${1:?deb-dir required}
OUT=${2:?out-dir required}
KEY=${3:?key fingerprint required}
KEYRING=${4:-}
SUITE=${APT_SUITE:-trixie}
COMP=${APT_COMPONENT:-main}
ARCHES=${APT_ARCHES:-all amd64 arm64}
SITE_URL=${APT_SITE_URL:-https://apt.pegaprox.com}

for tool in apt-ftparchive dpkg-deb gpg gzip; do
  command -v "$tool" >/dev/null || { echo "build-apt-repo: $tool is missing" >&2; exit 1; }
done
[[ $KEY =~ ^[0-9A-F]{40}$ ]] || { echo "build-apt-repo: give the full fingerprint, not '$KEY'" >&2; exit 1; }

shopt -s nullglob
debs=("$DEB_DIR"/*.deb)
[ ${#debs[@]} -gt 0 ] || { echo "build-apt-repo: no .deb in $DEB_DIR" >&2; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

# pool/main/<first letter>/<package>/<package>_<version>_<arch>.deb, the usual layout.
# A package version that turns up twice must be the same file both times.
declare -A seen=()
for deb in "${debs[@]}"; do
  pkg=$(dpkg-deb -f "$deb" Package)
  ver=$(dpkg-deb -f "$deb" Version)
  arch=$(dpkg-deb -f "$deb" Architecture)
  [[ $pkg =~ ^[a-z0-9][a-z0-9.+-]+$ && $ver =~ ^[0-9A-Za-z.+~:-]+$ ]] \
    || { echo "build-apt-repo: $deb has an odd Package/Version ('$pkg' '$ver')" >&2; exit 1; }
  [[ " $ARCHES " == *" $arch "* ]] \
    || { echo "build-apt-repo: $deb is $arch, the repo carries $ARCHES" >&2; exit 1; }
  dest="pool/$COMP/${pkg:0:1}/$pkg/${pkg}_${ver#*:}_${arch}.deb"
  sum=$(sha256sum "$deb" | cut -d' ' -f1)
  if [ -n "${seen[$dest]:-}" ]; then
    [ "${seen[$dest]}" = "$sum" ] && continue
    echo "build-apt-repo: two different files for $pkg $ver ($arch)" >&2
    exit 1
  fi
  seen[$dest]=$sum
  mkdir -p "$OUT/$(dirname "$dest")"
  cp "$deb" "$OUT/$dest"
done

cd "$OUT"
for a in $ARCHES; do
  dir="dists/$SUITE/$COMP/binary-$a"
  mkdir -p "$dir"
  apt-ftparchive --arch "$a" packages "pool/$COMP" > "$dir/Packages"
  gzip -9nkf "$dir/Packages"
  # apt-ftparchive skips a .deb it cannot read with a warning only: count them
  listed=$(grep -c '^Package: ' "$dir/Packages" || true)
  want=0
  for dest in "${!seen[@]}"; do
    case "$dest" in *_all.deb|*_"$a".deb) want=$((want + 1)) ;; esac
  done
  [ "$listed" -eq "$want" ] \
    || { echo "build-apt-repo: binary-$a lists $listed packages, the pool has $want for it" >&2; exit 1; }
done

# written next to dists/ first: apt-ftparchive must not find a half-written Release
# of its own while it hashes the suite
apt-ftparchive \
  -o "APT::FTPArchive::Release::Origin=PegaProx" \
  -o "APT::FTPArchive::Release::Label=PegaProx" \
  -o "APT::FTPArchive::Release::Suite=$SUITE" \
  -o "APT::FTPArchive::Release::Codename=$SUITE" \
  -o "APT::FTPArchive::Release::Components=$COMP" \
  -o "APT::FTPArchive::Release::Architectures=$ARCHES" \
  -o "APT::FTPArchive::Release::Description=PegaProx packages for Debian $SUITE" \
  release "dists/$SUITE" > Release.tmp
mv Release.tmp "dists/$SUITE/Release"

# the "!" makes gpg sign with exactly this key, never with a subkey it would pick itself
gpg --batch --yes --local-user "$KEY!" --digest-algo SHA512 --armor --detach-sign \
  -o "dists/$SUITE/Release.gpg" "dists/$SUITE/Release"
gpg --batch --yes --local-user "$KEY!" --digest-algo SHA512 --clearsign \
  -o "dists/$SUITE/InRelease" "dists/$SUITE/Release"

if [ -n "$KEYRING" ]; then
  fpr=$(gpg --show-keys --with-colons "$KEYRING" | awk -F: '$1 == "fpr" { print $10; exit }')
  [ "$fpr" = "$KEY" ] || { echo "build-apt-repo: $KEYRING is $fpr, the repo is signed by $KEY" >&2; exit 1; }
  cp "$KEYRING" pegaprox-archive-keyring.asc
  pretty=$(sed -E 's/(....)/\1 /g; s/ $//; s/^(.{24}) /\1  /' <<< "$fpr")
  rows=$(awk -F': ' '$1 == "Package" { p = $2 } $1 == "Version" { print "<tr><td>" p "</td><td>" $2 "</td></tr>" }' \
    "dists/$SUITE/$COMP/binary-all/Packages" | sort -u)
  cat > index.html <<HTML
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PegaProx APT repository</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 52rem; margin: 2rem auto; padding: 0 1rem; color: #1d2330; background: #fff; }
  pre { background: #f2f4f7; padding: 1rem; overflow-x: auto; }
  code, pre { font-family: ui-monospace, monospace; font-size: 14px; }
  td { padding: 0 1.5rem 0 0; }
  @media (prefers-color-scheme: dark) { body { color: #e6e9ef; background: #14171f; } pre { background: #222734; } }
</style>
<h1>PegaProx APT repository</h1>
<p>Signed packages of <a href="https://pegaprox.com">PegaProx</a> for Debian $SUITE (amd64 and arm64).</p>
<pre>sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL $SITE_URL/pegaprox-archive-keyring.asc -o /etc/apt/keyrings/pegaprox.asc
echo "deb [signed-by=/etc/apt/keyrings/pegaprox.asc] $SITE_URL $SUITE $COMP" \\
  | sudo tee /etc/apt/sources.list.d/pegaprox.list
sudo apt-get update && sudo apt-get install pegaprox</pre>
<p>Signing key: <code>$pretty</code><br>
Check it with <code>gpg --show-keys /etc/apt/keyrings/pegaprox.asc</code> before the first <code>apt-get update</code>.</p>
<h2>Packages</h2>
<table>
$rows
</table>
HTML
fi

echo "Signed repository in $OUT:"
find . -type f | sort
