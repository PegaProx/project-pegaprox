"""What starts the witness (#625 stage 2): it picks the code to run and keeps the way back.

The witness updates itself from its group: the leader's code bundle (ha.witness_bundle),
signed by a data voter, goes next to the code that runs, and the process exits for
systemd or Docker to start it again (witness.py, Witness.run_update); a witness run by
hand starts this file again in place (RUNNER). This file starts it then. No update replaces it, so a bundle that does not come up cannot take the way
back with it: the installer copies it to /opt/pegaprox-witness/boot.py, and in the
Docker image pegaprox_multi_cluster.py runs it for the command `witness`.

Two places hold code:
  base     what was installed by hand: /opt/pegaprox-witness/current (the installer),
           the image's /app, or a checkout
  updates  <state dir>/code/<release>-<digest>, with the links current and previous:
           what the witness unpacked itself, in the state directory or volume it keeps

The newer of the two by release and wire version runs, the base on a tie: a fresh
install or a newer image wins over an older update. Two exceptions: the leader's older
code taken by hand (update --to-leader) runs while it is the code the updates hold, a
newer base or not (mark_down), and code of the base's own release that the witness took
because the leader runs it (a fix under the same release string) wins the tie
(mark_same). Code that never came up healthy here is on trial while there is something
to go back to: it gets TRIES starts of `run`, and the start after that marks it bad,
goes back to the code before it and says so in update.json. The witness marks its code
healthy once it ran SOAK seconds answering on its own port (Witness.upkeep): code that
answers once and fails a little later is still on trial, and every exit before that
counts. A watchdog in RUNNER ends a start on trial that does not answer within
WATCH_UP, or is not healthy within WATCH_OK - code that hangs before its own check
runs; one that never answered spends all of its tries at once. The witness takes no
update to code marked bad by itself. Every other command (status, update, leave, the
installer's checks) runs the code that ran before an update that has not come up yet,
and ends after COMMAND_LIMIT seconds whatever it waits for.

Started as root, it first becomes the owner of the state directory, as the witness
itself does: the updates are written by that user and are never run as root.

Standard library only: nothing is chosen yet when this runs.

MK Oct 2026 (#625)
"""
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import time

TRIES = 2
# code on trial that does not answer on its port within HEALTH_BOUND gives up, and it is
# healthy once it ran SOAK seconds answering there (witness.py, Witness.upkeep). The
# watchdog of RUNNER gives it a margin on top: it is for code that hangs, not for the
# checks the code makes itself
HEALTH_BOUND = 90
SOAK = 180
WATCH_UP = HEALTH_BOUND + 15
WATCH_OK = SOAK + HEALTH_BOUND
WATCH_STEP = 3
# how long a command other than run may take (RUNNER): update fetches from a few members,
# a minute each at most; the rest asks one member or none
COMMAND_LIMIT = 120
COMMAND_LIMITS = {'update': 300}
UPDATES = 'code'
HEALTH = 'health.json'
# what the witness keeps about its updates, next to its state (witness.py): the go-back
# below writes the failure there too, for the leader to show
UPDATE_NAME = 'update.json'
# the bundle a tree was unpacked from, kept next to it: the installer checks it again as
# root before it takes the tree for /opt/pegaprox-witness (install.sh, refresh_base)
BUNDLE_SUFFIX = '.bundle.json'
# versions kept in the updates besides current and previous
KEEP = 2
MAX_BUNDLE = 8 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_FILES = 64
EXIT_CONFIG = 78
RELEASE_RE = re.compile(r'[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}')
NAME_RE = re.compile(r'[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}-[0-9a-f]{12}')
DIGEST_RE = re.compile(r'[0-9a-f]{64}')
# what a bundle may hold and nothing else: the modules of the witness, its unit and the
# version file the leader writes into it
FILE_RE = re.compile(r'pegaprox/(?:[a-z_][a-z0-9_]*/){0,2}[a-z_][a-z0-9_]*\.py'
                     r'|systemd/pegaprox-witness\.service|version\.json')
REQUIRED = ('pegaprox/__init__.py', 'pegaprox/witness.py', 'pegaprox/witness_boot.py', 'version.json')
_WIRE_RE = re.compile(r'^WITNESS_WIRE\s*=\s*([0-9]{1,3})\s*$', re.M)
_VERSION_RE = re.compile(r'^PEGAPROX_VERSION\s*=\s*["\']([^"\']{1,32})["\']', re.M)
# how a chosen tree runs: a fresh interpreter that sees that tree and no other. It is
# this file's, not the tree's: code on trial that stops with 78 (a setting to fix by
# hand, which systemd does not restart) stops with 1 instead, so the next start counts
# against its trial and the one after goes back. A witness nobody supervises (run by
# hand, PEGAPROX_WITNESS_AGAIN) starts this file again in place into an update, and
# after a start on trial that failed. On trial a watchdog thread, started before
# anything of the tree is imported, ends the start (PEGAPROX_WITNESS_WATCH, runner_env)
# when the tree did not answer on its port within WATCH_UP or is not healthy within
# WATCH_OK, as health.json says: it keeps the functions it needs from before the tree's
# monkey patching, and ends the process without waiting on anything the tree holds. Code
# that never answered spends all of its tries there (spend_trial, done here without the
# tree's code): the next start goes back at once instead of hanging as long again, and the
# vote is missing for one WATCH_UP, not TRIES of them. A command other than run ends after
# PEGAPROX_WITNESS_LIMIT seconds (command_limit), whatever it waits for
RUNNER = ('import os, sys\n'
          'sys.path.insert(0, os.environ["PEGAPROX_WITNESS_CODE_DIR"])\n'
          'trial = os.environ.get("PEGAPROX_WITNESS_TRIAL") == "1"\n'
          'again = os.environ.get("PEGAPROX_WITNESS_AGAIN")\n'
          'def start_again():\n'
          '    import json\n'
          '    cmd = json.loads(again)\n'
          '    env = {k: v for k, v in os.environ.items() if k not in (\n'
          '        "PEGAPROX_WITNESS_CODE_DIR", "PEGAPROX_WITNESS_TRIAL", "PEGAPROX_WITNESS_AGAIN",\n'
          '        "PEGAPROX_WITNESS_WATCH", "PEGAPROX_WITNESS_LIMIT")}\n'
          '    os.execve(cmd[0], cmd + sys.argv[1:], env)\n'
          'limit = os.environ.get("PEGAPROX_WITNESS_LIMIT")\n'
          'if limit and limit.isdigit():\n'
          '    import threading, time\n'
          '    def give_up(limit=int(limit), nap=time.sleep):\n'
          '        nap(limit)\n'
          '        os.write(2, ("pegaprox-witness: this command did not finish within %d s - "\n'
          '                     "stopped\\n" % limit).encode())\n'
          '        os._exit(1)\n'
          '    threading.Thread(target=give_up, name="pegaprox-witness-limit", daemon=True).start()\n'
          'watch = os.environ.get("PEGAPROX_WITNESS_WATCH") if trial else None\n'
          'if watch:\n'
          '    import json, threading, time\n'
          '    watch, nap, clock = json.loads(watch), time.sleep, time.monotonic\n'
          '    def spend(health):\n'
          '        held = health.get("trial")\n'
          '        if not isinstance(held, dict) or held.get("path") != watch["tree"]:\n'
          '            return\n'
          '        held["tries"] = watch["tries"]\n'
          '        tmp = "%s.tmp-%d" % (watch["health"], os.getpid())\n'
          '        try:\n'
          '            with open(tmp, "w", encoding="utf-8") as fh:\n'
          '                json.dump(health, fh, indent=2, sort_keys=True)\n'
          '                fh.flush()\n'
          '                os.fsync(fh.fileno())\n'
          '            os.replace(tmp, watch["health"])\n'
          '        except OSError:\n'
          '            pass\n'
          '    def watchdog(begun=clock()):\n'
          '        while True:\n'
          '            nap(watch["step"])\n'
          '            try:\n'
          '                with open(watch["health"], encoding="utf-8") as fh:\n'
          '                    health = json.load(fh)\n'
          '            except (OSError, ValueError):\n'
          '                health = {}\n'
          '            health = health if isinstance(health, dict) else {}\n'
          '            if watch["tree"] in (health.get("ok") or ()):\n'
          '                return\n'
          '            held = health.get("trial") if isinstance(health.get("trial"), dict) else {}\n'
          '            up = held.get("path") == watch["tree"] and bool(held.get("up"))\n'
          '            spent = clock() - begun\n'
          '            if spent > watch["ok"] or (not up and spent > watch["up"]):\n'
          '                said = "come up healthy" if up else "answer on its port"\n'
          '                os.write(2, ("pegaprox-witness: this code on trial did not %s within %d s - "\n'
          '                             "this start counts as failed\\n" % (said, spent)).encode())\n'
          '                if not up:\n'
          '                    spend(health)\n'
          '                if again:\n'
          '                    start_again()\n'
          '                os._exit(1)\n'
          '    threading.Thread(target=watchdog, name="pegaprox-witness-watchdog", daemon=True).start()\n'
          'try:\n'
          '    from pegaprox.witness import main\n'
          '    code = main(sys.argv[1:])\n'
          'except KeyboardInterrupt:\n'
          '    code = 130\n'
          'except SystemExit as e:\n'
          '    code = e.code\n'
          'except BaseException:\n'
          '    import traceback\n'
          '    traceback.print_exc()\n'
          '    code = 1\n'
          'if code is None:\n'
          '    code = 0\n'
          'elif not isinstance(code, int):\n'
          '    print(code, file=sys.stderr)\n'
          '    code = 1\n'
          'if again and (code == 75 or (trial and code not in (0, 130))):\n'
          '    sys.stdout.flush()\n'
          '    sys.stderr.flush()\n'
          '    start_again()\n'
          'sys.exit(1 if trial and code == 78 else code)\n')
# the options of pegaprox-witness that take a value, before its command
_VALUED = ('--dir', '--host', '--port', '--allow')
# how a witness was installed (PEGAPROX_WITNESS_INSTALL), and how it is updated by hand
# there. The leader shows these from the kind its witness names, never a command the
# witness sends
INSTALL_KINDS = ('systemd', 'docker', 'manual')
UPDATE_COMMANDS = {
    'systemd': 'sudo pegaprox-witness update',
    'docker': 'docker exec pegaprox-witness python3 pegaprox_multi_cluster.py witness update '
              '&& docker restart pegaprox-witness',
    'manual': 'python3 pegaprox_multi_cluster.py witness update, then start the witness again',
}
_EXEC_ENV = ('PEGAPROX_WITNESS_CODE_DIR', 'PEGAPROX_WITNESS_TRIAL', 'PEGAPROX_WITNESS_AGAIN',
             'PEGAPROX_WITNESS_WATCH', 'PEGAPROX_WITNESS_LIMIT')


class BootError(Exception):
    """Said to the admin as it is."""


def update_command(kind, to_leader=False):
    """The command that updates a witness installed as `kind` by hand, None for a witness
    that names no kind: one from before the updates, or not started through this file.
    `to_leader`: the one that takes the leader's code even where it is older."""
    cmd = UPDATE_COMMANDS.get(kind)
    if cmd and to_leader:
        cmd = cmd.replace('witness update', 'witness update --to-leader', 1)
    return cmd


def release_key(release, wire=0):
    """How code sorts: by the numbers of its release, a pre-release ('1.3.0-rc1') below
    the release, then by its wire version (ha_wire.WITNESS_WIRE)."""
    text = str(release or '')
    m = re.match(r'([0-9]{1,9}(?:\.[0-9]{1,9})*)(.*)', text)
    nums = [int(x) for x in m.group(1).split('.')][:6] if m else []
    nums += [0] * (6 - len(nums))
    rest = m.group(2) if m else text
    try:
        wire = int(wire or 0)
    except (TypeError, ValueError):
        wire = 0
    return tuple(nums), 0 if rest else 1, rest, wire


def code_version(path):
    """(release, wire) of the witness code in `path`, None when it holds none. Read from
    the files, never imported: the release as witness.release() reads it."""
    if not path or not os.path.isfile(os.path.join(path, 'pegaprox', 'witness.py')):
        return None
    release = ''
    try:
        with open(os.path.join(path, 'pegaprox', 'constants.py'), encoding='utf-8') as fh:
            found = _VERSION_RE.search(fh.read())
        release = found.group(1) if found else ''
    except OSError:
        pass
    if not release:
        try:
            with open(os.path.join(path, 'version.json'), encoding='utf-8') as fh:
                release = str(json.load(fh).get('version') or '')
        except (OSError, ValueError, AttributeError):
            release = ''
    wire = 1
    try:
        with open(os.path.join(path, 'pegaprox', 'core', 'ha_wire.py'), encoding='utf-8') as fh:
            found = _WIRE_RE.search(fh.read())
        wire = int(found.group(1)) if found else 1
    except OSError:
        pass
    return release[:32], wire


def default_dir():
    """The state directory: PEGAPROX_WITNESS_DIR, else the one systemd made for the unit
    (STATE_DIRECTORY), else /var/lib/pegaprox-witness where that exists, else ./witness."""
    for var in ('PEGAPROX_WITNESS_DIR', 'STATE_DIRECTORY'):
        value = (os.environ.get(var) or '').strip()
        if value:
            # systemd may hand over several, separated by colons: ours is the first
            return value.split(':')[0]
    if os.path.isdir('/var/lib/pegaprox-witness'):
        return '/var/lib/pegaprox-witness'
    return os.path.abspath('witness')


def command_limit(argv):
    """How many seconds the command of `argv` may take, None for run, which serves until
    it is stopped."""
    _folder, command = command_of(argv)
    return None if command == 'run' else COMMAND_LIMITS.get(command, COMMAND_LIMIT)


def command_of(argv):
    """(the --dir given or None, the command) of a pegaprox-witness command line."""
    folder, i = None, 0
    while i < len(argv):
        arg = argv[i]
        name, eq, value = arg.partition('=')
        if name in _VALUED:
            if not eq:
                i += 1
                value = argv[i] if i < len(argv) else ''
            if name == '--dir':
                folder = value
        elif arg in ('-h', '--help'):
            return folder, 'help'
        elif not arg.startswith('-'):
            return folder, arg
        i += 1
    return folder, 'run'


# --- what came up healthy -----------------------------------------------------------

def load_health(root):
    try:
        with open(os.path.join(root, HEALTH), encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {}
    data = data if isinstance(data, dict) else {}
    trial = data.get('trial') if isinstance(data.get('trial'), dict) else {}
    down = data.get('down') if isinstance(data.get('down'), dict) else {}
    same = data.get('same') if isinstance(data.get('same'), str) else ''
    return {'ok': [p for p in data.get('ok') or () if isinstance(p, str)][-32:],
            'bad': [p for p in data.get('bad') or () if isinstance(p, str)][-32:],
            'trial': trial, 'down': down, 'same': same}


def save_health(root, health):
    """True when it is on disk. A health file that cannot be written means no trial: what
    cannot count its starts cannot go back either."""
    try:
        os.makedirs(root, mode=0o700, exist_ok=True)
        path = os.path.join(root, HEALTH)
        tmp = f'{path}.tmp-{os.getpid()}'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(health, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def mark_up(state, path):
    """The code in `path`, on trial, answers on its port: the watchdog of RUNNER gives it
    until WATCH_OK to come up healthy now, not WATCH_UP. Each start of `run` starts a
    trial record of its own (choose), so this is said again at every start."""
    root = os.path.join(state, UPDATES)
    real = os.path.realpath(path)
    health = load_health(root)
    if health['trial'].get('path') != real or health['trial'].get('up'):
        return True
    health['trial'] = dict(health['trial'], up=int(time.time()))
    return save_health(root, health)


def mark_stopped(state, path):
    """The code in `path`, on trial, answered on its port and was stopped on a signal (a
    restart, a reboot, the installer run again): that start is no failed one, and the
    next start of `run` does not count it against the trial."""
    root = os.path.join(state, UPDATES)
    real = os.path.realpath(path)
    health = load_health(root)
    if health['trial'].get('path') != real or not health['trial'].get('up'):
        return True
    health['trial'] = dict(health['trial'], stopped=True)
    return save_health(root, health)


def spend_trial(state, path):
    """The code in `path`, on trial, never answered on its port: this start counts as all
    of its TRIES, and the next start goes back to the code before it at once. The
    watchdog of RUNNER does the same for code that hangs."""
    root = os.path.join(state, UPDATES)
    real = os.path.realpath(path)
    health = load_health(root)
    if health['trial'].get('path') != real:
        return True
    health['trial'] = dict(health['trial'], tries=TRIES)
    return save_health(root, health)


def mark_ok(state, path):
    """The code in `path` came up healthy (it ran SOAK seconds answering on its port): no
    trial for it from now on, and the installer may take it for the base."""
    root = os.path.join(state, UPDATES)
    real = os.path.realpath(path)
    health = load_health(root)
    if real not in health['ok']:
        health['ok'].append(real)
    health['bad'] = [p for p in health['bad'] if p != real]
    if health['trial'].get('path') == real:
        health['trial'] = {}
    return save_health(root, health)


def is_bad(state, name):
    """Whether the update tree `name` failed here: it did not come up in its trial, and an
    update to that same code is not taken again by itself."""
    root = os.path.join(state, UPDATES)
    return os.path.realpath(os.path.join(root, name)) in load_health(root)['bad']


def forget_bad(state, path):
    """An update by hand takes the code in `path` again, with a trial of its own."""
    root = os.path.join(state, UPDATES)
    real = os.path.realpath(path)
    health = load_health(root)
    if real not in health['bad'] and health['trial'].get('path') != real:
        return True
    health['bad'] = [p for p in health['bad'] if p != real]
    if health['trial'].get('path') == real:
        health['trial'] = {}
    return save_health(root, health)


def mark_down(state, path):
    """The admin took the leader's code in `path` by hand although it is older (update
    --to-leader): it runs from now on even where the base is newer, for as long as it is
    the code the updates hold - a new base (the installer run again, a new image) does not
    undo it, the leader's next newer release does (and None, which drops the hold)."""
    root = os.path.join(state, UPDATES)
    health = load_health(root)
    version = code_version(path) if path else None
    health['down'] = {'version': list(version)} if version else {}
    return save_health(root, health)


def _held_down(health, found):
    """The updates candidate of `found` when update --to-leader holds it, else None."""
    held = (health.get('down') or {}).get('version')
    return next((c for c in found if c[0] == 'updates' and isinstance(held, list) and list(c[2]) == held), None)


def mark_same(state, path):
    """The witness took the code in `path` because its leader runs it, of the same release
    as the code that ran (a fix pushed under the same release string): on a tie with the
    base it wins (choose), where an update of the base's release would lose otherwise."""
    root = os.path.join(state, UPDATES)
    health = load_health(root)
    health['same'] = os.path.realpath(path) if path else ''
    return save_health(root, health)


def note_failed(state, path, release, error):
    """The update in `path` did not come up: said in UPDATE_NAME the way the witness says
    a failed update (Witness.note_update), so its status and the leader show it, with
    back: the witness went back from it, and takes that code again only by hand. The
    rest of that file stays as it is."""
    file = os.path.join(state, UPDATE_NAME)
    try:
        with open(file, encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {}
    data = data if isinstance(data, dict) else {}
    data['last'] = {'state': 'failed', 'release': release, 'name': os.path.basename(path), 'back': True,
                    'error': error[:200], 'at': time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime())}
    tmp = f'{file}.tmp-{os.getpid()}'
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, file)
        return True
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


# --- which code runs ----------------------------------------------------------------

def _candidates(base, root):
    out = []
    v = code_version(base) if base else None
    if v:
        out.append(('base', os.path.realpath(base), v))
    cur = os.path.join(root, 'current')
    v = code_version(cur) if os.path.lexists(cur) else None
    if v and os.path.realpath(cur) not in [c[1] for c in out]:
        out.append(('updates', os.path.realpath(cur), v))
    return out


def _previous(root, health):
    prev = os.path.join(root, 'previous')
    if os.path.lexists(prev) and code_version(prev) and os.path.realpath(prev) not in health['bad']:
        return os.path.realpath(prev)
    return None


def _go_back(root, health):
    """The update that did not come up goes: current points at previous again, or at
    nothing, and then the base runs."""
    prev = _previous(root, health)
    try:
        if prev:
            _link(os.path.join(root, 'current'), os.path.basename(prev))
            os.unlink(os.path.join(root, 'previous'))
        else:
            os.unlink(os.path.join(root, 'current'))
    except OSError:
        pass


def choose(base, state, counting=True, say=None):
    """(the tree to run, whether it runs on trial). `counting`: a start of `run`, which
    counts against the trial of code that never came up healthy here. Any other command
    runs the code that ran before an update that has not come up yet: previous where it
    came up, else the base - a command next to the service never starts code nobody
    tried while there is other code."""
    say = say or (lambda _text: None)
    root = os.path.join(state, UPDATES)
    health = load_health(root)
    for _ in range(4):
        found = _candidates(base, root)
        if not found:
            raise BootError(f'No witness code found (base {base or "-"}, updates {root})')
        usable = [c for c in found if c[1] not in health['bad']]
        if not usable:
            # everything here failed once: the code installed by hand all the same
            return found[0][1], False
        same = health.get('same')
        best = _held_down(health, usable) or max(
            usable, key=lambda c: (release_key(*c[2]), c[0] == 'updates' and c[1] == same, c[0] == 'base'))
        kind, path, version = best
        prev = _previous(root, health) if kind == 'updates' else None
        others = len(usable) > 1 or prev
        if not counting and kind == 'updates' and path not in health['ok'] and others:
            installed = next((c[1] for c in usable if c[0] == 'base'), None)
            return (prev if prev in health['ok'] else installed or prev), False
        if not counting or path in health['ok'] or not others:
            return path, False
        trial = health['trial']
        tries = trial.get('tries', 0) if trial.get('path') == path else 0
        if not isinstance(tries, int):
            tries = TRIES
        elif trial.get('path') == path and trial.get('up') and trial.get('stopped'):
            # the start before answered and was stopped cleanly: not a failed one
            tries = max(0, tries - 1)
        if tries >= TRIES:
            health['bad'].append(path)
            health['trial'] = {}
            if kind == 'updates':
                if health.get('same') == path:
                    # the same-release code it came from wins the tie with the base again
                    health['same'] = _previous(root, health) or ''
                _go_back(root, health)
            save_health(root, health)
            say(f'{path} did not come up healthy in {TRIES} starts - going back to the code before it')
            # the witness that starts next says so in its status: the leader shows it and
            # does not hand it this code again (Witness._told)
            note_failed(state, path, version[0],
                        f'release {version[0] or "?"} ({os.path.basename(path)}) did not come up healthy in '
                        f'{TRIES} starts - back on the code before it, and that code is not taken again '
                        'by itself')
            continue
        health['trial'] = {'path': path, 'tries': tries + 1, 'at': int(time.time())}
        if not save_health(root, health):
            return path, False
        return path, True
    raise BootError('No witness code here comes up healthy')


# --- a bundle -----------------------------------------------------------------------

def bundle_name(release, digest):
    return f'{release}-{digest[:12]}'


def check_bundle(archive, manifest):
    """The bundle `archive` against its `manifest`, before anything of it is unpacked:
    the release, the size and the SHA-256, and members that are plain files FILE_RE
    allows, each once and none too large, exactly those the manifest lists and the
    required ones among them. Returns the name it unpacks under. Raises BootError."""
    if not isinstance(manifest, dict) or not isinstance(archive, (bytes, bytearray)):
        raise BootError('The code bundle is incomplete')
    release, digest, files = manifest.get('release'), manifest.get('sha256'), manifest.get('files')
    if not isinstance(release, str) or not RELEASE_RE.fullmatch(release):
        raise BootError('The code bundle names no release')
    if len(archive) > MAX_BUNDLE or manifest.get('size') != len(archive):
        raise BootError('The code bundle has the wrong size')
    if not isinstance(digest, str) or hashlib.sha256(archive).hexdigest() != digest:
        raise BootError('The code bundle does not match its digest')
    if (not isinstance(files, list) or not 0 < len(files) <= MAX_FILES
            or not all(isinstance(f, str) for f in files) or len(set(files)) != len(files)):
        raise BootError('The code bundle lists no files')
    names, total = [], 0
    try:
        with tarfile.open(fileobj=io.BytesIO(bytes(archive)), mode='r:gz') as tar:
            while True:
                m = tar.next()
                if m is None:
                    break
                total += m.size
                if (not m.isreg() or not FILE_RE.fullmatch(m.name) or m.size > MAX_FILE
                        or total > MAX_FILES * MAX_FILE or len(names) >= MAX_FILES):
                    raise BootError(f'The code bundle holds what it may not: {m.name[:80]}')
                names.append(m.name)
    except (tarfile.TarError, OSError, EOFError) as e:
        raise BootError(f'The code bundle cannot be read: {type(e).__name__}')
    if sorted(names) != sorted(files) or len(set(names)) != len(names):
        raise BootError('The code bundle holds other files than it lists')
    missing = [f for f in REQUIRED if f not in names]
    if missing:
        raise BootError(f'The code bundle lacks {missing[0]}')
    return bundle_name(release, digest)


def install_bundle(archive, manifest, root, mode=0o755):
    """Unpack the bundle under `root`/<name> next to what is there, checked first
    (check_bundle). Returns the path. A tree of that name that was unpacked whole before
    is the same code, and is kept as it is."""
    name = check_bundle(archive, manifest)
    os.makedirs(root, mode=0o700, exist_ok=True)
    dest = os.path.join(root, name)
    try:
        with open(os.path.join(dest, '.complete'), encoding='utf-8') as fh:
            if fh.read().strip() == manifest['sha256'] and code_version(dest):
                return dest
    except OSError:
        pass
    tmp = f'{dest}.tmp-{os.getpid()}'
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, mode=mode)
    try:
        with tarfile.open(fileobj=io.BytesIO(bytes(archive)), mode='r:gz') as tar:
            for m in tar.getmembers():
                target = os.path.join(tmp, *m.name.split('/'))
                os.makedirs(os.path.dirname(target), mode=mode, exist_ok=True)
                with tar.extractfile(m) as src, open(target, 'wb') as out:
                    out.write(src.read(MAX_FILE + 1))
                os.chmod(target, 0o644)
        with open(os.path.join(tmp, '.complete'), 'w', encoding='utf-8') as fh:
            fh.write(manifest['sha256'] + '\n')
        if os.path.lexists(dest):
            shutil.rmtree(dest)
        os.rename(tmp, dest)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return dest


def _link(path, target):
    tmp = f'{path}.tmp-{os.getpid()}'
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    os.symlink(target, tmp)
    os.replace(tmp, path)


def switch(root, name):
    """current points at `name` from now on, previous at what current pointed at."""
    cur = os.path.join(root, 'current')
    old = os.path.realpath(cur) if os.path.lexists(cur) else None
    if old and os.path.isdir(old) and os.path.basename(old) != name:
        _link(os.path.join(root, 'previous'), os.path.basename(old))
    _link(cur, name)


def prune(root, keep=KEEP):
    """The versions under `root` but current, previous and the `keep` newest go, and so
    do the leftovers of an unpack that did not finish."""
    try:
        names = os.listdir(root)
    except OSError:
        return
    held = {os.path.basename(os.path.realpath(os.path.join(root, link)))
            for link in ('current', 'previous') if os.path.lexists(os.path.join(root, link))}
    now = time.time()
    versions = []
    for name in names:
        path = os.path.join(root, name)
        if '.tmp-' in name and os.path.isdir(path) and now - os.path.getmtime(path) > 3600:
            shutil.rmtree(path, ignore_errors=True)
        elif NAME_RE.fullmatch(name) and name not in held and not os.path.islink(path):
            versions.append((os.path.getmtime(path), path))
    versions.sort()
    for _mtime, path in (versions[:-keep] if keep else versions):
        shutil.rmtree(path, ignore_errors=True)
    # and the bundle each tree was unpacked from goes with it
    for name in names:
        tree = name[:-len(BUNDLE_SUFFIX)]
        if name.endswith(BUNDLE_SUFFIX) and NAME_RE.fullmatch(tree) and not os.path.isdir(os.path.join(root, tree)):
            try:
                os.unlink(os.path.join(root, name))
            except OSError:
                pass


# --- the start ----------------------------------------------------------------------

def drop_root(state):
    """Started as root: become the owner of the state directory, as witness._drop_root
    does, before any code of it is looked at."""
    if not hasattr(os, 'geteuid') or os.geteuid() != 0 or not os.path.isdir(state):
        return
    owner = os.stat(state)
    if owner.st_uid == 0:
        return
    # root's supplementary groups would stay with the process otherwise
    os.setgroups([])
    os.setgid(owner.st_gid)
    os.setuid(owner.st_uid)


def runner_env(path, trial=False, install='', again=None, environ=None, state=None, base=None, limit=None):
    """The environment the witness of the tree `path` runs in (RUNNER). `again`, the
    command line that starts this file again, for a witness nobody supervises. `state`,
    the state directory: on trial the watchdog reads health.json there. `base`, the code
    installed by hand. `limit`, the seconds a command other than run may take."""
    env = {k: v for k, v in (os.environ if environ is None else environ).items() if k not in _EXEC_ENV}
    env.update(PEGAPROX_WITNESS_CODE_DIR=path, PEGAPROX_WITNESS_TRIAL='1' if trial else '0')
    if install:
        env['PEGAPROX_WITNESS_INSTALL'] = install
    if again:
        env['PEGAPROX_WITNESS_AGAIN'] = json.dumps(list(again))
    if base:
        env['PEGAPROX_WITNESS_BASE'] = base
    if limit:
        env['PEGAPROX_WITNESS_LIMIT'] = str(int(limit))
    if trial and state:
        env['PEGAPROX_WITNESS_WATCH'] = json.dumps({
            'health': os.path.join(state, UPDATES, HEALTH), 'tree': os.path.realpath(path),
            'up': WATCH_UP, 'ok': WATCH_OK, 'step': WATCH_STEP, 'tries': TRIES})
    return env


def run(path, argv, trial=False, install='', again=None, state=None, base=None):
    """Replace this process with the witness of the tree `path`."""
    env = runner_env(path, trial, install, again, state=state, base=base, limit=command_limit(argv))
    sys.stdout.flush()
    sys.stderr.flush()
    os.execve(sys.executable, [sys.executable, '-I', '-c', RUNNER] + list(argv), env)


def main(argv=None, base=None, install=None, start=run, again=None):
    """`again`: how this file is started (the interpreter, the script and what comes
    before the witness's own arguments), for the witness run by hand to start it again
    in place (RUNNER); this file run as a script when not given."""
    argv = list(sys.argv[1:] if argv is None else argv)
    base = base or os.environ.get('PEGAPROX_WITNESS_BASE') or \
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    install = install or os.environ.get('PEGAPROX_WITNESS_INSTALL') or 'manual'
    folder, command = command_of(argv)
    state = os.path.abspath(folder or default_dir())

    def say(text):
        print(f'pegaprox-witness: {text}', file=sys.stderr, flush=True)
    try:
        drop_root(state)
        path, trial = choose(base, state, counting=command == 'run', say=say)
    except (BootError, OSError) as e:
        say(str(e))
        return EXIT_CONFIG
    if install != 'manual' or command != 'run':
        # systemd and Docker start it again themselves
        return start(path, argv, trial, install, None, state, base)
    return start(path, argv, trial, install, again or [sys.executable, os.path.abspath(__file__)], state, base)


if __name__ == '__main__':
    sys.exit(main())
