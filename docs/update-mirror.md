# Update mirror

updates.pegaprox.com is the second source of every update. The in-app updater and
`update.sh` read `version.json`, `archive/main.tar.gz` and single files from it when
GitHub does not answer. It is a Bunny storage zone (`updates-pegaprox-com`) behind a Bunny
pull zone, and `.github/workflows/mirror.yml` keeps it equal to `main`, with
`.github/scripts/mirror_to_bunny.py` doing the work. Before this workflow, an hourly lftp
cron on an outside server did that.

## What the zone holds

- Every file git tracks in the `main` commit, except names starting with `.git` (so no
  `.github/`, `.gitignore` or `plugins/.gitkeep`) and names ending in `.bak`. Untracked
  files never get there, whatever lies around in the checkout.
- `archive/main.tar.gz`: the same files plus `.gitignore` and `plugins/.gitkeep`, under one
  top directory `project-pegaprox-main/`, the layout of GitHub's own archive.
- `archive/main.tar.gz.sha256`: one line as `sha256sum` prints it, `<hex>  main.tar.gz`.

Nothing else: what `main` no longer has is deleted from the zone. A file named `SHA256SUMS`
is never published, here or in the archive: `update.sh` holds GitHub's archive against such
a file on the mirror and would stop every update.

The archive comes out byte for byte the same for the same commit (sorted entries, the
commit time on every entry, owner 0 without names, modes from git, gzip without name or
time). The cron's archive had its files at the top (`./pegaprox_multi_cluster.py`); the
in-app updater only looks one directory down, so it never used that archive and fell back
to single files. `update.sh` takes either.

## When it syncs

- On every push to `main`.
- Every hour at :17, which repairs whatever a failed run left behind.
- By hand: Actions, "Update mirror", "Run workflow" on `main`.

A sync compares the SHA-256 of every file with the checksum the zone reports and uploads
only what differs (Bunny checks each upload against the `Checksum` header). It uploads the
single files first, several at a time, then one after the other
`archive/main.tar.gz.sha256`, `archive/main.tar.gz` and `version.json`, and deletes only
after that. So an install never reads a version whose files or archive are not there yet,
and nothing a version still lists is gone. The archive goes up as late as it can because of
the in-app updater (see "Halfway through a sync" below). If any upload fails, after
retries, the run stops before `version.json` and before deleting anything, and the next
run picks up from there. The log ends with a line like
`synced 64f62631d924: 3 uploaded, 1464 unchanged, 0 deleted, 21093120 bytes sent`.

## Halfway through a sync

A Bunny storage zone has no way to switch many files at once, so while a sync runs, and
after one that failed until the next run, the zone holds files of two releases. What each
updater reads, when GitHub does not answer:

- The in-app updater reads `version.json`, then `archive/main.tar.gz`, and compares the
  `version.json` inside the archive with it. Equal: it installs the archive, which is
  whole. Not equal and both from the mirror: it installs nothing and says the mirror is
  between two releases (HTTP 503, try again later). Only when the archive cannot be
  downloaded or unpacked does it take single files, by the list in `version.json`.
- `update.sh` reads only the version number from `version.json`, then installs whatever
  archive it downloads (whole, of one release) and warns when its version differs. It too
  takes single files only when no archive can be downloaded.
- No updater reads `archive/main.tar.gz.sha256`, it is there for people checking by hand.

With the upload order above, the archive matches `version.json` all through a sync except
between the uploads of the archive and of `version.json` (two requests, or until the next
run if `version.json` is the upload that failed). A run that fails anywhere before the
archive leaves the old archive with the old `version.json`. Between the `.sha256` and the
archive the `.sha256` belongs to the new archive, so a check by hand then reports a
mismatch, never a match for the wrong file.

What stays: the single files are ahead of `version.json` from the start of a sync until it
ends, and an updater that takes single files then gets a mix with nothing to tell it so.
Neither updater checks single files against a list of hashes, and adding one is a change to
both updaters first. A `SHA256SUMS` file in the zone in particular would stop every
`update.sh` run (see above). That only bites an install that cannot reach GitHub and cannot
use the archive from the mirror either. An update run once the mirror is through puts it
right, both updaters always apply the whole release.

## Jobs, environment, secret

- `build` has no secret. It builds the tree and the archive and signs build provenance for
  the archive. An archive that already has an attestation from this workflow on `main` is
  not signed again (the hourly runs of an unchanged `main` produce the same file).
- `sync` runs in the environment `mirror`, which deploys only from `main`. The zone
  password is the environment secret `BUNNY_STORAGE_PASSWORD` and reaches only the sync
  step. The job builds the tree again and stops unless the archive has the digest `build`
  attested. When its commit is no longer the head of `main` (a re-run of an old run), it
  leaves the zone alone instead of rolling it back.

A run from any other branch only builds, which is how a change to the workflow or the
script is tried on Testing. The script reads the password from `BUNNY_STORAGE_PASSWORD`
only, never from an argument, and never prints it (leading and trailing whitespace is
dropped, any other control character refuses the run). It talks HTTPS with the default
certificate checks and follows no redirect.

`mirror.yml` is one of the publishers of the release watchdog (docs/release-watchdog.md):
a freeze disables it. The baseline also lists the `mirror` environment, so a missing
environment, or one that deploys from anything but `main`, raises an alarm.

## Setting up

The "only from `main`" above is a setting nobody but a repository admin can make, and
GitHub creates an unprotected `mirror` environment by itself the first time a job names
it. So, in this order, before `mirror.yml` reaches `main` (and before the baseline with
the `mirror` entry reaches `Testing`, or the watchdog's Testing run reports it missing):

1. Settings, Environments, New environment, name `mirror`.
2. Deployment branches and tags: "Selected branches and tags", add the rule `main`
   (branch), nothing else. No tag rule.
3. Environment secrets, Add secret: `BUNNY_STORAGE_PASSWORD`, the password of the storage
   zone `updates-pegaprox-com` (Bunny dashboard, the zone's "FTP & API Access" tab; not the
   account API key).
   Never as a repository secret: `secrets.BUNNY_STORAGE_PASSWORD` reads a repository secret
   too, and that one every branch can reach. The watchdog cannot list secrets and would not
   notice.
4. Only then merge to `main`. Optionally run a dry run first (below).

If the environment got created by itself already, open it and do steps 2 and 3 there.

## Dry run

Actions, "Update mirror", "Run workflow" on `main`, tick `dry_run`. The log lists what would
be uploaded and deleted and writes nothing. Locally, with the zone password at hand:

    git fetch origin main
    BUNNY_STORAGE_PASSWORD=... python3 .github/scripts/mirror_to_bunny.py --ref origin/main --dry-run

`--ref` defaults to `HEAD`, and a local checkout is usually on Testing. So anything but
`--tree-only` stops unless the commit is the head of `origin/main`; `--any-ref` skips that
check. Fetch first: a stale `origin/main` passes the check and would roll the mirror back.

Without network and without a password, the tree and the archive of any commit:

    python3 .github/scripts/mirror_to_bunny.py --tree-only --ref origin/main --out /tmp/mirror

## Checking the archive

    curl -fsSLO https://updates.pegaprox.com/archive/main.tar.gz
    gh attestation verify main.tar.gz -R PegaProx/project-pegaprox \
      --signer-workflow PegaProx/project-pegaprox/.github/workflows/mirror.yml --source-ref refs/heads/main

The attestation names the commit the archive was built from. Building that commit with
`--tree-only` gives the same sha256 (with the same Python and zlib).

## Bunny API, as used

Checked against Bunny's published API reference (November 2026): `PUT /<zone>/<path>`
uploads the raw body, `AccessKey` carries the zone password, the optional `Checksum` header
is "the SHA256 checksum of the uploaded content in HEX format (UPPERCASE)" and makes the
server reject a mismatch, success is 201. `GET /<zone>/<dir>/` lists a directory as a JSON
array with `ObjectName`, `IsDirectory`, `Length` and more. `DELETE /<zone>/<path>` removes
a file and, for a directory, everything in it; the script only deletes directories it
emptied first. The listing's `Checksum` field (upper-case SHA-256, null for directories) is
not in the official reference, only in client libraries; the script treats a missing one
as "differs" and uploads that file again.

## Limits

- The pull zone's cache is not purged after a sync (neither did the cron), so a changed
  file can take until its cache time runs out to show up on updates.pegaprox.com. Each
  file runs out on its own, so for that time the pull zone can serve files of two
  releases side by side whatever order they were uploaded in, with what "Halfway through
  a sync" describes.
- The watchdog checks the `mirror` environment's branch rule, not where the secret lives:
  a repository secret of the same name it cannot see (the workflow token cannot list
  secrets).
- A sync can only be as current as `main`; the mirror carries no Testing.
