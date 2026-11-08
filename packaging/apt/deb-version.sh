#!/usr/bin/env bash
# Prints the Debian version of the pegaprox package for an upstream version
# (the "version" of version.json when none is given).
#
#   packaging/apt/deb-version.sh            -> 1.4.0
#   packaging/apt/deb-version.sh 1.5.0-rc1  -> 1.5.0~rc1
#
# NS Oct 2026 - the third-party repo publishes the same release as "<version>-1" (and -2
# on a rebuild). Until that is settled with its maintainer, our build of a release sorts
# BELOW theirs, so a host that has both repos keeps the package it already has. That is
# decided by SUFFIX below and nowhere else:
#
#   SUFFIX=""           1.4.0           < 1.4.0-1     ours yields (now)
#   SUFFIX="+pegaprox1" 1.4.0+pegaprox1 > 1.4.0-N     ours wins
#
# A newer release of ours still beats an older one of theirs either way (1.4.1 > 1.4.0-1).
# debian/source/format is "3.0 (native)", and a native package has no Debian revision,
# so the result never carries a '-'. A pre-release in version.json ("1.5.0-rc1") turns
# into "1.5.0~rc1", which sorts below the 1.5.0 it leads up to.
set -euo pipefail

SUFFIX=""

here=$(cd "$(dirname "$0")" && pwd)
upstream=${1:-$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["version"])' "$here/../../version.json")}

if ! [[ $upstream =~ ^[0-9]+(\.[0-9]+)*(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$ ]]; then
  echo "deb-version: '$upstream' is not a version we cut (1.4.0, 1.4.0.1, 1.5.0-rc1)" >&2
  exit 1
fi
if ! [[ $SUFFIX =~ ^(\+[0-9A-Za-z.]+)?$ ]]; then
  echo "deb-version: SUFFIX must be empty or start with '+' (got '$SUFFIX')" >&2
  exit 1
fi

echo "${upstream/-/\~}${SUFFIX}"
