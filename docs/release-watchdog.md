# Release watchdog

A workflow that watches how PegaProx gets released and stops the publishing workflows when
something does not add up: `.github/workflows/watchdog.yml` runs
`.github/scripts/watchdog.py` every ten minutes and holds what the GitHub API says against
`.github/watchdog/baseline.json`.

It is the first of three layers. A watcher outside GitHub and signed updates are separate
work and not part of this one. Read the limits at the end before relying on it.

## What it checks

Each run reads the current state and looks back to the start of the last successful
scheduled run (at least 40 minutes, at most three days; the event feed 6 hours further,
because GitHub delivers it late at times). So a run that GitHub started late, skipped, or
that failed leaves no gap, and an alarm stays until it is acknowledged. Nothing is stored
between runs.

| Check | Alarm when |
|---|---|
| coverage | (no alarm) no scheduled run at all for more than three days: the time before is reported as not checked and the run fails once |
| settings | the default branch is no longer `main`, the repository is private, archived or disabled, or Pages is off |
| collaborators | someone has access who is not in `collaborators`, someone lost it, or a role changed |
| branches | `main` or `Testing` is gone, `main` points at a tree that is the tree of no recent Testing commit and is no "merge Testing into main" whose second parent is on Testing with the same tree, or `main` carries an older version than the newest release tag of the baseline |
| pins | `watchdog.py` or `baseline.json` on `main` or `Testing` is not the file whose sha256 the `watchdog.yml` next to it pins |
| pushes | a force push, a deletion or a re-creation of `main` or `Testing`, a push whose new head does not descend from the old one, a push by someone not in `allowed_actors`, a move of `main` by someone not in `release_managers`, or a move of `main` to a lower version |
| workflow-files | a commit that changes `.github/workflows/`, `.github/scripts/`, `.github/watchdog/` or `packaging/apt/` (a rename out of them counts) was authored by someone not in `allowed_authors`; a push that changes the watchdog's own three files by someone not in `watchdog_maintainers`; a workflow file on `main` or `Testing` that neither list of the baseline knows |
| tags | a release tag of the baseline is gone or points elsewhere, or a new `v*` tag is not on `main` (and did not come from Testing) or is not `v` plus the `version` in `version.json` at its commit |
| releases | a release was published by someone outside `release_managers` or for a tag that failed the tag check, an asset was uploaded by anyone but GitHub Actions, or an asset changed in the window while no run of `apt-repo.yml`, `release-images.yml` or `sbom.yml` that passes the run check was going |
| events | anyone added as a collaborator, the repository made public, a `v*` tag or `main`/`Testing` deleted, a push to `main`, a `v*` tag or a release by someone outside `release_managers`, a push to `Testing` by someone outside the team |
| rulesets | one of the three rulesets is gone, not active, or its rules, conditions or bypass actors differ, or it was edited after the baseline was taken |
| workflow-runs | a run of a workflow the baseline does not know; a publisher run started by someone outside the team, from another repository, or on a commit that is on neither `main` nor `Testing`; a run of a known workflow from a side branch that changed that workflow file |
| update-manifest | `version.json` on `main`, on `Testing`, on updates.pegaprox.com or at any head `main` or `Testing` had in the window sends the updater to an archive or a mirror that is not ours, carries an unknown URL, or lists an odd path in `update_files` |
| environments | `apt-signing` or `github-pages` deploys from anything but `main` and `v*`, or Pages no longer serves apt.pegaprox.com |

Runs of a fork's pull request are only noted: GitHub gives them a read-only token and no
secrets, and anyone can open one, so they must not be able to freeze publishing.

What it cannot read is listed as **not checked**, with the reason, and never counts as
passed. Most of it fails the run (red, exit 2, no freeze), so the next run covers that time
again. A few items are expected and do not fail it: the bypass actors of a ruleset (GitHub
shows them only to repository admins), the Pages settings and the collaborator list if the
workflow token may not read them, the mirror when it is down, and an event feed that does
not reach back far enough (it holds 300 events, and anyone can fill it with comments).

A check that crashes on what the API returned raises an alarm (`crash:<check>:<id>`), so
data shaped to break a check does not switch it off.

## The watchdog's own files

`watchdog.yml` pins the sha256 of `watchdog.py` and `baseline.json`. Any token that can push
can change those two files; changing `watchdog.yml` needs the workflow scope. If the files
on `main` do not match, the run does not start the script at all: the act job disables the
five publishers from a list in `watchdog.yml` itself, cancels their runs and fails. On
`Testing` the pins check reports the mismatch.

After changing either file, put the new sums into both "Pinned files" steps of
`watchdog.yml`:

    sha256sum .github/scripts/watchdog.py .github/watchdog/baseline.json

`tests/test_release_watchdog_workflow.py` fails until they match. Push the files and the
new sums together: a Testing head with only one of them raises a pins alarm on the next
scheduled run.

## What happens on an alarm

1. The run fails. GitHub mails a failed scheduled run to the person who last changed the
   cron line of the workflow (or last enabled it). Nothing goes to an issue, a PR or a
   comment: a public post would announce the incident.
2. On `main`, from the schedule or a manual run, the act job freezes publishing. It
   disables these workflows and cancels their queued, waiting and running runs:
   - `apt-repo.yml` signs and deploys apt.pegaprox.com and attaches the .deb
   - `docker-testing.yml` pushes ghcr.io/pegaprox/pegaprox-testing on every Testing push
   - `docker.yml` pushes the release images to ghcr.io and Docker Hub
   - `release-images.yml` attaches the VM and LXC images to the release
   - `sbom.yml` attaches the SBOM to the release

   Everything else keeps running, the watchdog too. `push-create-snapshot-deb-builds.yml`
   only keeps a .deb as a run artifact for 14 days and is not frozen.
3. If the repository secret `WATCHDOG_NOTIFY_URL` is set (an https URL of a push service),
   it gets one line when a freeze starts or ends, nothing more.

A push to `main` or `Testing` runs the checks as well, report-only: it shows what it found
and what a freeze would do, and changes nothing. The same goes for a local run.

The run page and its summary are public, like every run of a public repository. The
summary says which check failed and on what, so it should be read with that in mind.

## Freeze by hand

Actions, "Release watchdog", "Run workflow" on `main`, action `freeze`. That needs no alarm.

## Unfreeze

1. Find out what the alarm was (the summary of the failed run lists each alarm with a key).
2. If it was fine (a deliberate change), either fix the baseline (below) or put its key into
   the repository variable `WATCHDOG_ACK` (Settings, Secrets and variables, Actions,
   Variables), keys separated by spaces, copied from the summary as they are. A key names
   that one finding: the same object with another problem gets another key and alarms
   again. An acknowledged alarm shows as a note.
3. Actions, "Release watchdog", "Run workflow" on `main`, action `unfreeze`, and `UNFREEZE`
   in the confirm field.

An alarm does not clear by itself: the runs after it keep failing, and every one of them
looks back to the last successful one, until the alarm is fixed or acknowledged (at most
three days; then what caused it falls out of the look-back). Then the next scheduled run is
green and the window is back to 40 minutes. When no scheduled run happened at all for more
than three days, the first run afterwards fails once for that gap.

If the watchdog itself is broken: disable "Release watchdog" in the Actions tab and enable
the five workflows above by hand.

## Releasing

Push `main` and the tag together, `git push --atomic origin main v1.4.2`. A tag that a run
sees before `main` has it is reported as not checked (red, no freeze) while its commit came
from Testing, and as an alarm otherwise.

## Changing the baseline

`baseline.json` is code: change it on Testing together with the pins in `watchdog.yml`, it
counts once it is on `main`. The usual cases:

- A new workflow: add it to `publishers` or `others` (and to `attach_to_releases` if it has
  `contents: write`). A test fails until it is sorted. On Testing the new baseline counts
  for Testing as soon as its pins match, so the new workflow does not alarm there.
- A ruleset or a collaborator changed on purpose: run
  `python3 .github/scripts/watchdog.py snapshot` with an admin token
  (`GITHUB_TOKEN=$(gh auth token)`) and take over its `rulesets` or `collaborators`.
- Someone new releases or maintains the watchdog: `release_managers`, `watchdog_maintainers`.
- A new release tag needs nothing: it is checked by the rule. To pin it against moving, add it
  to `tags` (the `snapshot` output has them).
- A deliberate commit straight on `main`: add its id to `accepted_main_heads`, or acknowledge
  `main-head:<id>` in `WATCHDOG_ACK` until the next release.

Locally, report-only: `GITHUB_TOKEN=$(gh auth token) python3 .github/scripts/watchdog.py check`.
`--window-min` widens the look-back.

## Limits

- It lives in the repository it watches. An admin (or a token with admin rights) can edit
  it, change `WATCHDOG_ACK`, change the rulesets, or switch everything off.
- Write access is enough to switch it off. One call (`PUT .../actions/workflows/watchdog.yml/disable`)
  with any token that can push (classic `repo` scope, or Actions write on a fine-grained
  token or an app) disables the watchdog: no run, no failed run, no mail. The same access
  enables a frozen publisher again. The freeze buys time, it does not lock anyone out. Only
  a watcher outside GitHub (stage 2) can notice this: it has to poll the state of
  `watchdog.yml` and the time of its last successful scheduled run.
- `main` is only protected against force pushes and deletion. Any token with write access
  can push to it; the watchdog alarms when that is not a release manager, minutes later.
- The pins stop a token without the workflow scope from replacing the script or the
  baseline. A token or app with the workflow scope can change `watchdog.yml` and the pins in
  the same commit. On Testing that alarms when the pusher is not in `watchdog_maintainers`
  or an author is not on the list; a leaked token of the maintainer passes both.
- A leaked token of a team member looks like that team member. The watchdog sees who
  pushed, not whether it was really them, and the author of a commit is whatever the pusher
  wrote into it.
- It comes after the fact. `apt-repo.yml` (about 2 minutes), `sbom.yml` (1) and
  `docker-testing.yml` (5 to 10) finish before the next run can freeze them. Scheduled runs
  start late when GitHub is busy (a weekly cron of this repository started up to 8 hours
  late in October), and GitHub switches off schedules in a public repository after 60
  days without activity. The next run covers the time back to the last successful one, so
  nothing is overlooked, but it is seen late.
- The tag ruleset forbids moving and deleting `v*` tags, not creating them, and
  `apt-signing` deploys from any `v*` tag. A token or app with the workflow scope can tag a
  side-branch commit with its own `apt-repo.yml`, publish a release on it and reach the
  signing key within seconds; the watchdog alarms on the tag and the run afterwards.
- `DOCKERHUB_TOKEN` is a repository secret, so a workflow on any branch of this repository
  can use it. A side-branch run of an unknown or changed workflow alarms, after it ran.
- A deleted release or a deleted asset is not noticed. An asset swap is noticed while the
  new upload is inside the window and no vetted publisher run was going at that moment.
- A run that deletes its own record is invisible to the run check; the asset and tag
  checks are what is left.
- Deleting the run history of the watchdog makes the next run look like the first one, with
  the standard window.
- A freeze stops the next publication. Images, packages and release files already out stay
  out. The update mirror updates.pegaprox.com follows `main` by itself and is not frozen;
  the watchdog only checks that its `version.json` points at our archive.

What would close most of these, outside this repository's files: a ruleset on `main` that
restricts updates to the admin, a `creation` rule on the tag ruleset with only the admin
allowed to bypass it, a required reviewer on the `apt-signing` environment,
`DOCKERHUB_TOKEN` moved into an environment that only `main` and `v*` reach, immutable
releases, a first job in every publisher that runs `watchdog.py check` from `main` before
anything is published, and the outside watcher of stage 2.
