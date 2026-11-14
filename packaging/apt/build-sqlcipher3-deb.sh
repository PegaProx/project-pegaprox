#!/usr/bin/env bash
# python3-sqlcipher3 for one architecture, for the appliance images (release-images.yml).
#
#   build-sqlcipher3-deb.sh <amd64|arm64> <out-dir>
#
# Downloads the wheels of python-debs/requirements.txt for that machine, hash-checked, and
# builds them with build-python-debs.py: the pins and the script apt.pegaprox.com is built
# with, so the image's package is the repo's. Leaves <out-dir>/python3-sqlcipher3.deb.
#
# NS Nov 2026 (#1226) - the image builds took the python3-sqlcipher3_0.6.4_all.deb from
# gyptazy's CDN. It says Architecture: all and holds the x86_64 module only: on arm64 it
# installed, the import failed and PegaProx ran on plain SQLite.
set -euo pipefail

arch=${1:?expected amd64 or arm64}
out=${2:?expected an output directory}
case $arch in
  amd64) machine=x86_64 ;;
  arm64) machine=aarch64 ;;
  *) echo "build-sqlcipher3-deb: no wheel machine for $arch" >&2; exit 1 ;;
esac

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# trixie's Python, as in apt-repo.yml; --no-deps, the file has every wheel it needs
python3 -m pip download --disable-pip-version-check --no-cache-dir --isolated \
  --no-deps --require-hashes --only-binary=:all: --index-url https://pypi.org/simple \
  --platform "manylinux_2_28_$machine" --python-version 3.13 --implementation cp --abi cp313 \
  -r "$here/python-debs/requirements.txt" -d "$work/wheels"
python3 -I "$here/build-python-debs.py" --arch "$arch" "$work/wheels" "$work/debs"

debs=("$work"/debs/python3-sqlcipher3_*_"$arch".deb)
if [ "${#debs[@]}" -ne 1 ] || [ ! -f "${debs[0]}" ]; then
  echo "build-sqlcipher3-deb: expected one python3-sqlcipher3 for $arch, got: ${debs[*]}" >&2
  exit 1
fi
deb=${debs[0]}
got=$(dpkg-deb -f "$deb" Architecture)
if [ "$got" != "$arch" ]; then
  echo "build-sqlcipher3-deb: $(basename "$deb") is Architecture: $got" >&2
  exit 1
fi
# the module of this machine, the one the CDN package did not have for arm64. Listed into a
# variable first: grep -q leaving the pipe early is a SIGPIPE, and pipefail a failed check
listing=$(dpkg-deb -c "$deb")
if ! grep -q "/sqlcipher3/_sqlite3\.cpython-313-$machine-linux-gnu\.so$" <<<"$listing"; then
  echo "build-sqlcipher3-deb: $(basename "$deb") has no $machine module" >&2
  exit 1
fi

mkdir -p "$out"
cp "$deb" "$out/python3-sqlcipher3.deb"
dpkg-deb -f "$out/python3-sqlcipher3.deb" Package Version Architecture Depends
echo "$(basename "$deb") -> $out/python3-sqlcipher3.deb"
sha256sum "$out/python3-sqlcipher3.deb"
