# PegaProx APT repository — prototype

A **self-hosted, GPG-signed APT repository on GitHub Pages**, so users can

```bash
sudo apt-get install pegaprox
```

from us directly — instead of relying on a third-party Debian repo. It also unblocks the
release **appliance build**: `release-images.yml` currently `apt-get install pegaprox`s from
`packages.gyptazy.com`, whose published `.deb` lagged behind our source (that's how the
`.ssh_ws_server.py` postinst break shipped). Pointing the appliance build at *our* repo — built
from *our* `debian/` on every release — removes that lag.

## What's here

| file | role |
|------|------|
| `packaging/apt/build-apt-repo.sh` | takes a dir of `.deb`s → builds a signed `dists/`+`pool/` tree (`apt-ftparchive` + `gpg`). Runs **identically locally and in CI** — what you prove locally is what ships. |
| `.github/workflows/apt-repo.yml` | CI: build the `.deb` from `debian/` (version from `version.json`) → sign → publish to Pages. |

Both were **proven end-to-end locally** this session (`dpkg-deb` → `apt-ftparchive` → `gpg`, `InRelease`
verified). The workflow uses `dpkg-buildpackage` in CI so the real `debian/` packaging (install map +
postinst + service) is honoured verbatim.

## One-time setup

1. **Signing key** (dedicated, passphrase-less so CI is non-interactive):
   ```bash
   export GNUPGHOME=$(mktemp -d); chmod 700 "$GNUPGHOME"
   gpg --batch --gen-key <<'EOF'
   %no-protection
   Key-Type: eddsa
   Key-Curve: ed25519
   Key-Usage: sign
   Name-Real: PegaProx Repository Signing Key
   Name-Email: apt@pegaprox.com
   Expire-Date: 0
   %commit
   EOF
   FPR=$(gpg --list-keys --with-colons apt@pegaprox.com | awk -F: '/^fpr:/{print $10; exit}')
   gpg --armor --export-secret-keys "$FPR"   # → paste into the secret below, then shred the file
   ```
2. **Repo secret**: Settings → Secrets → Actions → `APT_GPG_PRIVATE_KEY` = the armored **private** key.
3. **Pages**: Settings → Pages → Source = **GitHub Actions**.

The **public** key ships in the repo output as `pegaprox-archive-keyring.asc`; users pin it with `signed-by`.

## User install snippet

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://pegaprox.github.io/project-pegaprox/pegaprox-archive-keyring.asc \
  | sudo tee /etc/apt/keyrings/pegaprox.asc >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/pegaprox.asc] https://pegaprox.github.io/project-pegaprox stable main" \
  | sudo tee /etc/apt/sources.list.d/pegaprox.list
sudo apt-get update && sudo apt-get install pegaprox
```

The package is `Architecture: all`, so that one line serves amd64 **and** arm64. A custom domain
(`apt.pegaprox.com` via CNAME) can replace the `pegaprox.github.io/project-pegaprox` base later without
users changing their `sources.list`.

## Known gaps (prototype → production)

- **Version precedence vs gyptazy.** Our native build produces `pegaprox_1.1.0` (no `-N` revision);
  gyptazy publishes `1.1.0-1`, which dpkg ranks **higher**. So if a host has *both* repos enabled, apt
  still prefers gyptazy's (broken) package. Fixes: ship *only* our repo for pegaprox, or add an
  `apt` pin (`Pin: origin pegaprox.github.io` / `Pin-Priority: 1001`), or bump our version scheme.
- **Deps are not mirrored yet.** Most `Depends:` resolve from stock Debian, but **4 are gyptazy-only**
  (`python3-flask-sock`, `python3-flask-sockets`, `python3-simple-websocket`, `python3-xenapi`). To make
  the repo *self-contained* (our repo + stock Debian, no gyptazy line), mirror those four `all` `.deb`s
  into `pool/main/` too. Verify with `apt-get install --simulate pegaprox` on a clean trixie and add any
  still-unresolved names. Until then, users keep gyptazy's repo enabled for the deps.
- **Pages CDN cache window.** Right after a publish, the Pages CDN (~10-min edge cache, no purge API) can
  briefly serve a fresh `Packages` against a stale `InRelease` → a transient `Hash Sum mismatch` that
  clears on retry. Publishing per-release (not per-commit) shrinks the window; a purgeable CDN removes it.
- **Version retention.** This prototype uses the artifact-based Pages deploy, which *replaces* the whole
  site each publish — only the latest `.deb` stays in the pool (fine for "install the latest"). If you
  want old versions to survive for incremental fleet upgrades, publish to a `gh-pages` branch with
  `keep_files: true` instead.
- **Pages limits.** ~1 GB site / ~100 GB-month bandwidth soft caps — fine for a lean single-package repo;
  front with a real CDN/object storage if the pool + traffic grow.
- **Pin the 3rd-party actions to SHAs** (checkout / upload-pages-artifact / deploy-pages) before this is
  anything but a prototype, matching the other workflows here.

## Wiring the appliance build to our repo (later)

In `release-images.yml`, replace the gyptazy repo line + `apt-get install pegaprox` with our repo (keep
gyptazy for the 4 deps until they're mirrored), so the LXC/VM appliance always installs the freshly-built
package. See [[appliance-build-gyptazy-deb]].
