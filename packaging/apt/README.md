# PegaProx APT repository

`https://apt.pegaprox.com` is PegaProx's own signed APT repository for Debian trixie. It is
built and published by [`.github/workflows/apt-repo.yml`](../../.github/workflows/apt-repo.yml)
on GitHub Pages: on every published release, and when someone runs the workflow by hand
from `main`. Nothing is uploaded from a laptop.

## Install (what users run)

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://apt.pegaprox.com/pegaprox-archive-keyring.asc -o /etc/apt/keyrings/pegaprox.asc
gpg --show-keys /etc/apt/keyrings/pegaprox.asc     # optional, compare with the fingerprint below
echo "deb [signed-by=/etc/apt/keyrings/pegaprox.asc] https://apt.pegaprox.com trixie main" \
  | sudo tee /etc/apt/sources.list.d/pegaprox.list
sudo apt-get update && sudo apt-get install pegaprox
```

Signing key: **`5E04 573B 4064 7A94 F0DE  28F8 493A F556 F30B 55C1`**
(ed25519, `PegaProx Repository Signing Key <apt@pegaprox.com>`, no expiry). The public key
is [`pegaprox-archive-keyring.asc`](pegaprox-archive-keyring.asc) in this directory, and the
site serves that very file.

Debian trixie only, amd64 and arm64. Every package in the repo is `Architecture: all`; the
rest of what PegaProx needs comes from trixie itself. The repo carries:

| package | from |
|---|---|
| `pegaprox` | built from `debian/` of the released tag, every release since the repo went live stays in the pool |
| `python3-flask-sock` | the flask-sock wheel from PyPI, pinned in [`python-debs/requirements.txt`](python-debs/requirements.txt) |
| `python3-xenapi` | the XenAPI wheel from PyPI, pinned there as well |

Two things a `.deb` install does without, because trixie has nothing that fits:

- **WebAuthn hardware keys.** trixie's `python3-fido2` is 1.2; with 1.x the options PegaProx
  hands to the browser keep raw bytes and `register/begin` fails in `jsonify` (PegaProx
  wants 2.2.1, see `requirements.txt`). The package does not depend on it, so WebAuthn stays
  off, as `api/webauthn.py` intends when fido2 is missing. TOTP works.
- **Full database encryption.** `sqlcipher3` is not packaged in Debian. `core/dbcrypto.py`
  falls back to plain SQLite and the Fernet encryption of the secret fields stays;
  `/usr/bin/pegaprox/pegaprox-wrapper --keystore-status` (as the `pegaprox` user, in
  `/var/lib/pegaprox`) reports the backend as `sqlite-plain`. An encrypted database brought
  over from a Docker or pip install does not open there ("file is not a database").

## How the workflow builds it

Each job gets only what it needs:

| job | runs when | may | does |
|---|---|---|---|
| `build` | always | read the repo | `dpkg-buildpackage -b` of `debian/` in a pinned `debian:trixie` container, the two python3 debs from wheels fetched with `pip download --require-hashes --no-deps`, then the smoke test below |
| `publish` | release (not a pre-release), or a manual run from `main` | read releases and attestations, **the signing key** | collects the pegaprox debs of the earlier releases and this run's debs, signs `dists/` with [`build-apt-repo.sh`](build-apt-repo.sh) |
| `deploy` | after `publish` | Pages (`github-pages` environment) | puts the signed tree on Pages |
| `attach` | release | write the release | adds `pegaprox_<version>_all.deb` to the release |
| `attest` | release | OIDC token, attestations | signed build provenance for every deb of the run |

The job with the key builds nothing: no pip, no `dpkg-buildpackage`, no container. It also
checks that the key in the secret is the one in `pegaprox-archive-keyring.asc` and stops
otherwise, and after signing it verifies `InRelease` and `Release.gpg` with `gpgv` against
the committed key only, the way apt on a user's host will.

**Smoke test.** The build job signs a repository of exactly the debs it just made with a
key it generates for that step, serves it on `127.0.0.1`, and in a fresh `debian:trixie`
container adds it with `signed-by` next to Debian's own sources and nothing else, then
`apt-get install pegaprox` ([`smoke-install.sh`](smoke-install.sh)). It checks the installed
version, imports every module the package depends on and lists the optional ones
([`deb_imports.py`](deb_imports.py)), then boots that tree with `systemd-nspawn` the way
`release-images.yml` tests the LXC template and waits for PegaProx to answer on port 5000.

**Old versions.** Pages replaces the whole site on each deploy, so the pool is rebuilt every
time from the `pegaprox_*_all.deb` assets of the earlier releases. Each one is checked with
`gh attestation verify` against this workflow and that release's tag before it is signed
again; an asset without that provenance is left out with a warning (anyone with write access
could otherwise add a file to an old release and have the next publish sign it). A version
that is out keeps its bytes: a run from `main` whose version is already released does not
replace the released file, and a release that collides with an earlier one fails. The repo
holds the newest ten pegaprox versions (`KEEP_EARLIER` earlier ones plus the current one):
Pages caps a site at 1 GB and a deb is about 10 MB. Older debs stay downloadable from their
GitHub release.

**Trying a change.** Run the workflow by hand from any branch other than `main`, e.g.
`Testing`: that is a dry run, build and smoke test only. publish, deploy, attach and attest
are skipped, and the signing key is not touched.

**One publish at a time.** Releases and runs from `main` share one concurrency group, so a
later run always sees the asset an earlier one attached. GitHub keeps only the newest
waiting run of a group: if a third one arrives while one runs and one waits, the waiting one
is cancelled. When that was a release, run it again, or its `.deb` and provenance are missing.

## Version scheme

The third-party repository the README and the appliance images use today publishes release
`X` as `X-1`. Until that is settled with its maintainer, ours sorts below it for the same
release, so a host with both repositories keeps the package it already has; a newer release
of ours still wins over an older one of theirs.

| release | ours | theirs | apt picks |
|---|---|---|---|
| 1.4.0 | `1.4.0` | `1.4.0-1` | theirs |
| 1.4.1 (theirs still on 1.4.0) | `1.4.1` | `1.4.0-1` | ours |
| 1.5.0-rc1 in `version.json` | `1.5.0~rc1` | | below `1.5.0` |

`debian/source/format` is `3.0 (native)`, and a native package cannot carry a Debian
revision, so our version never contains a `-`; a pre-release turns its `-` into `~`.
[`deb-version.sh`](deb-version.sh) computes it, and the build job writes it into a new
`debian/changelog` entry dated with the commit.

**To switch** (ours ahead of theirs), change the one line `SUFFIX=""` in `deb-version.sh` to
`SUFFIX="+pegaprox1"`: `1.4.0+pegaprox1` sorts above `1.4.0-1`, `-2` and so on, and above our
own `1.4.0`, so hosts on our repo move along. Nothing else changes;
`tests/test_apt_repo_version_scheme.py` checks whichever way the line points.

Pre-releases get their `.deb` and provenance on the GitHub release but do not go into the
repository: everything in it is what `apt upgrade` installs on production hosts. A
pre-release that is later marked as a full release joins with the next publish.

## Dependencies

`debian/control` has to name every library PegaProx imports, including the ones imported
inside a function: `python3-defusedxml` (XCP-ng) and `python3-requests-toolbelt` (ISO upload)
were missing and only failed when that code ran.
`tests/test_debian_depends_cover_imports.py` reads every import of `pegaprox/`,
`pegaprox_multi_cluster.py`, the bundled plugins and the scripts PegaProx writes out at
runtime, maps it through `DEPENDS` in [`deb_imports.py`](deb_imports.py) and checks Depends.
A new import means a line there and in `debian/control`, or an entry in `OPTIONAL` with the
reason PegaProx runs without it.

For a library trixie does not package: add the pinned wheel to `python-debs/requirements.txt`
(version and sha256 from PyPI, and give a fresh upstream release two weeks), an entry in
`PACKAGES` of [`build-python-debs.py`](build-python-debs.py) with the Debian names of its
requirements, and `python-debs/<package>.copyright`. Only pure-Python wheels
(`py3-none-any`) are handled. They are rebuilt on every run, and the same wheel in the same
pinned trixie image gives the same `.deb` byte for byte, so a publish does not change files
apt has already seen. Moving `TRIXIE_IMAGE` in the workflow may change those bytes once.

## The signing key

- Private key: `APT_GPG_PRIVATE_KEY`, ASCII-armored, no passphrase, a secret of the
  environment `apt-signing` (Settings, Environments), not of the repository. That environment
  only deploys from `main` and `v*` tags, so a workflow file on any other branch cannot read
  the key. Only the `publish` job names the environment.
- Public key: `packaging/apt/pegaprox-archive-keyring.asc`. The workflow refuses to sign when
  the two do not belong together.
- Signing uses the primary key (`--local-user <fingerprint>!`), so the key needs the sign
  capability on its primary, as ed25519 `[SC]` has.

**Rotating it** (also the plan when the key leaks):

1. Make the new key offline:
   ```bash
   export GNUPGHOME=$(mktemp -d)
   gpg --batch --pinentry-mode loopback --passphrase '' \
     --quick-gen-key 'PegaProx Repository Signing Key <apt@pegaprox.com>' ed25519 sign never
   gpg --armor --export <new-fingerprint> > packaging/apt/pegaprox-archive-keyring.asc
   gpg --armor --export-secret-keys <new-fingerprint>     # goes into the secret, then shred it
   ```
2. In one go: commit the new `pegaprox-archive-keyring.asc` to `main`, replace the secret, and
   update the fingerprint in this README. A run between the two steps fails the key check,
   which is the point.
3. Run the workflow from `main`. The whole repository is signed with the new key from then on.
4. Hosts that pinned the old key get `NO_PUBKEY` on `apt-get update` until they fetch the key
   again with the `curl` line above. Announce it before step 3, unless the old key leaked.
   A leaked key is also revoked: publish its revocation certificate next to the new key.

## Pages and its cache

GitHub Pages answers with `Cache-Control: max-age=600` through a CDN that cannot be purged.
For up to ten minutes after a deploy a client may get the new `InRelease` with an old
`Packages`, or the other way round, and `apt-get update` reports a hash sum mismatch. It goes
away by itself; run `apt-get update` again a few minutes later. The repository only changes
on a release or a manual run, so this window is rare.

The custom domain is set on the Pages site. Until the `apt.pegaprox.com` CNAME record exists
in DNS and GitHub has issued the certificate for it, the URL above does not answer.

## Not switched over yet

`README.md` and `release-images.yml` still install from the third-party repository. They
move to this one once its maintainer and we have agreed how the two repositories relate
(and with that, which way `SUFFIX` points).
