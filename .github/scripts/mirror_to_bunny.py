#!/usr/bin/env python3
"""The update mirror: main on updates.pegaprox.com, synced to its Bunny storage zone.

NS Nov 2026 - takes over from the hourly lftp cron on the old box. Run by
.github/workflows/mirror.yml, docs/update-mirror.md has the rest. The zone holds what that
cron put there: every file of the commit except .git*, .github/ and *.bak, plus
archive/main.tar.gz and archive/main.tar.gz.sha256, and nothing else. A file named
SHA256SUMS is never published: update.sh would hold GitHub's archive against it and stop.

The archive comes out byte for byte the same for the same commit (sorted entries, the
commit time as mtime, owner 0 without names, modes from git, gzip without name or time),
so the build job can attest it and the sync job can check it uploads that very file.
Unlike the cron's it has a top directory, project-pegaprox-main/ like GitHub's own: the
in-app updater only looks one level down for pegaprox_multi_cluster.py and dropped to
single files with the old flat one. update.sh takes either.

The sync lists the zone, uploads what differs (Bunny checks the Checksum header), then
archive/main.tar.gz.sha256 and version.json last, so version.json never announces an
archive that is not up yet, and deletes what main no longer has. A failed upload stops
the run before version.json and before any delete.

    mirror_to_bunny.py --tree-only --ref origin/main --out DIR   build the tree and the archive, no network
    mirror_to_bunny.py --ref origin/main --dry-run               compare with the zone, write nothing
    mirror_to_bunny.py --ref origin/main                         sync

--ref defaults to HEAD, which in the workflow is the checkout of main. A local checkout is
usually on Testing, so anything but --tree-only stops unless the commit is the head of
origin/main (git fetch first, or a stale main rolls the mirror back). --any-ref skips that.

The zone password comes from BUNNY_STORAGE_PASSWORD only, never from an argument, and is
never printed. stdlib only.
"""
import argparse
import gzip
import hashlib
import http.client
import io
import json
import os
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DEFAULT_ZONE_URL = 'https://storage.bunnycdn.com/updates-pegaprox-com'
PASSWORD_ENV = 'BUNNY_STORAGE_PASSWORD'
ZONE_URL_ENV = 'BUNNY_STORAGE_URL'
ARCHIVE_TOP = 'project-pegaprox-main'
ARCHIVE = 'archive/main.tar.gz'
ARCHIVE_SUM = 'archive/main.tar.gz.sha256'
MANIFEST = 'version.json'
# uploaded after everything else, in this order
LAST = (ARCHIVE_SUM, MANIFEST)
# a tree without these is a broken checkout, not a release: syncing it would delete the mirror
REQUIRED = (MANIFEST, 'pegaprox_multi_cluster.py')
MODES = {'100644': 0o644, '100755': 0o755}
RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}
RETRIES = 4
TIMEOUT = 60


class MirrorError(Exception):
    pass


class ZoneError(MirrorError):
    pass


# ---------------------------------------------------------------------------------------
# what goes where

def _parts(path):
    return path.split('/')


def in_zone(path):
    """The cron's lftp ran with --exclude-glob .git* .github* *.bak, which match a name at
    any depth (.gitignore and plugins/.gitkeep never reached the zone), and archive/ is ours."""
    parts = _parts(path)
    if parts[0] == 'archive' or parts[-1] == 'SHA256SUMS':
        return False
    return not any(p.startswith('.git') or p.endswith('.bak') for p in parts)


def in_archive(path):
    """The cron's tar left out .git, .github and archive only, so .gitignore and
    plugins/.gitkeep are in the archive, as in GitHub's."""
    parts = _parts(path)
    if parts[0] == 'archive' or parts[-1] == 'SHA256SUMS':
        return False
    return not any(p in ('.git', '.github') or p.endswith('.bak') for p in parts)


# ---------------------------------------------------------------------------------------
# the tree

def _git(root, *args):
    r = subprocess.run(['git', '-C', str(root), *args], capture_output=True, check=False)
    if r.returncode:
        raise MirrorError(f'git {args[0]} failed: {r.stderr.decode("utf-8", "replace").strip()[:300]}')
    return r.stdout


def resolve(root, ref):
    return _git(root, 'rev-parse', '--verify', '--end-of-options', f'{ref}^{{commit}}').decode().strip()


def main_head(root):
    """origin/main in the checkout, None when there is none. actions/checkout of main
    fetches the commit into refs/remotes/origin/main, so in the workflow it is HEAD."""
    try:
        return resolve(root, 'refs/remotes/origin/main')
    except MirrorError:
        return None


def tracked_entries(root, ref='HEAD'):
    """(commit, commit time, [(path, mode, blob)]) of every file of the commit. What git
    does not track never ships, whatever lies around in the checkout."""
    commit = resolve(root, ref)
    ctime = int(_git(root, 'show', '-s', '--format=%ct', commit).decode().strip())
    entries, odd = [], []
    for rec in _git(root, 'ls-tree', '-r', '-z', '--full-tree', commit).split(b'\0'):
        if not rec:
            continue
        meta, _, raw = rec.partition(b'\t')
        mode, otype, blob = meta.decode('ascii').split()
        try:
            path = raw.decode('utf-8')
        except UnicodeDecodeError:
            odd.append(f'{raw!r} (not UTF-8)')
            continue
        parts = _parts(path)
        if any(p in ('', '.', '..') for p in parts) or any(ord(c) < 32 or c in '\\\x7f' for c in path):
            odd.append(repr(path))
        elif otype != 'blob' or mode not in MODES:
            # a symlink or a submodule: the zone has no such thing, and the updater does not
            # expect one in the archive either
            odd.append(f'{path} (mode {mode})')
        else:
            entries.append((path, MODES[mode], blob))
    if odd:
        raise MirrorError('not mirrored, fix the tree: ' + ', '.join(odd[:10]))
    entries.sort()
    return commit, ctime, entries


def _blobs(root, blobs):
    """The contents of the blobs in order, through one git cat-file."""
    proc = subprocess.Popen(['git', '-C', str(root), 'cat-file', '--batch'],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        for blob in blobs:
            proc.stdin.write(blob.encode('ascii') + b'\n')
            proc.stdin.flush()
            head = proc.stdout.readline().split()
            if len(head) != 3 or head[1] != b'blob':
                raise MirrorError(f'git cat-file: {blob} is no blob')
            size = int(head[2])
            data = proc.stdout.read(size)
            proc.stdout.read(1)
            if len(data) != size:
                raise MirrorError(f'git cat-file: {blob} came back short')
            yield data
    finally:
        proc.stdin.close()
        proc.stdout.close()
        proc.wait()


def write_archive(path, members, mtime):
    """members: [(repo path, mode, bytes)]. The same members and mtime always give the
    same bytes (with the same Python and zlib)."""
    dirs = {''}
    for rel, _, _ in members:
        parts = _parts(rel)[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add('/'.join(parts[:i]))
    items = [(f'{ARCHIVE_TOP}/{d}/' if d else f'{ARCHIVE_TOP}/', None, None) for d in dirs]
    items += [(f'{ARCHIVE_TOP}/{rel}', mode, data) for rel, mode, data in members]
    # a directory sorts right before what it holds, its name being their prefix
    items.sort(key=lambda it: it[0])
    with open(path, 'wb') as raw, \
            gzip.GzipFile(filename='', mode='wb', fileobj=raw, compresslevel=9, mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT, encoding='utf-8') as tar:
        for name, mode, data in items:
            info = tarfile.TarInfo(name.rstrip('/'))
            info.mtime = mtime
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            if data is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
            else:
                info.mode = mode
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))


class Tree:
    def __init__(self, out, commit, files, digest):
        self.out = Path(out)
        self.commit = commit
        self.files = files          # zone path -> (SHA-256 upper-case hex, size)
        self.digest = digest        # of archive/main.tar.gz, lower-case like sha256sum

    def read(self, rel):
        return self.out.joinpath(*_parts(rel)).read_bytes()


def build_tree(root, out, ref='HEAD'):
    """Write the zone's content into out (new or empty) and return what is in it."""
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise MirrorError(f'{out} is not empty')
    out.mkdir(parents=True, exist_ok=True)
    commit, ctime, entries = tracked_entries(root, ref)
    wanted = [e for e in entries if in_zone(e[0]) or in_archive(e[0])]
    files, members = {}, []
    for (rel, mode, _), data in zip(wanted, _blobs(root, [e[2] for e in wanted])):
        if in_zone(rel):
            dest = out.joinpath(*_parts(rel))
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            os.chmod(dest, mode)
            files[rel] = (hashlib.sha256(data).hexdigest().upper(), len(data))
        if in_archive(rel):
            members.append((rel, mode, data))
    missing = [r for r in REQUIRED if r not in files]
    if missing:
        raise MirrorError(f'{commit[:12]} has no {", ".join(missing)}: not a PegaProx tree, nothing published')
    arc = out.joinpath(*_parts(ARCHIVE))
    arc.parent.mkdir(parents=True, exist_ok=True)
    write_archive(arc, members, ctime)
    data = arc.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    # what sha256sum prints, two spaces and all
    line = f'{digest}  {arc.name}\n'.encode('ascii')
    out.joinpath(*_parts(ARCHIVE_SUM)).write_bytes(line)
    for rel, blob in ((ARCHIVE, data), (ARCHIVE_SUM, line)):
        os.chmod(out.joinpath(*_parts(rel)), 0o644)
        files[rel] = (hashlib.sha256(blob).hexdigest().upper(), len(blob))
    return Tree(out, commit, files, digest)


# ---------------------------------------------------------------------------------------
# the storage zone (Bunny Edge Storage API)

def check_zone_url(url):
    u = urllib.parse.urlsplit(url or '')
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment \
            or not u.path.strip('/'):
        raise MirrorError('the zone URL must look like https://storage.bunnycdn.com/<zone>')
    return url.rstrip('/')


def mask(text, secret):
    """text with the password replaced, also in the form repr gives it as str or bytes (a
    backslash doubled, a quote escaped), which is how an exception tends to quote it."""
    text = str(text)
    if not secret:
        return text
    forms = {secret, repr(secret)[1:-1], repr(secret.encode('utf-8', 'backslashreplace'))[2:-1]}
    for form in sorted(forms, key=len, reverse=True):
        text = text.replace(form, '***')
    return text


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # the AccessKey would go along to wherever a redirect points
    def redirect_request(self, *args, **kwargs):
        return None


class Zone:
    def __init__(self, url, password, jobs=6, sleep=time.sleep, retries=RETRIES):
        self.base = check_zone_url(url)
        self._key = password
        self.jobs = jobs
        self.sleep = sleep
        self.retries = retries
        # the default context: certificates and host name checked
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())

    def __repr__(self):
        return f'Zone({self.base})'

    def url(self, rel, directory=False):
        path = '/'.join(urllib.parse.quote(p, safe='') for p in _parts(rel) if p)
        if not path:
            return f'{self.base}/'
        # a listing or a directory delete ends in a slash, a file never does
        return f'{self.base}/{path}' + ('/' if directory else '')

    def request(self, method, rel, body=None, headers=None, directory=False, missing_ok=False):
        where = f'{method} /{rel}'
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(self.url(rel, directory), data=body, method=method,
                                         headers={'AccessKey': self._key, **(headers or {})})
            why = ''
            try:
                with self._opener.open(req, timeout=TIMEOUT) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as e:
                if e.code == 404 and missing_ok:
                    return 404, b''
                detail = ''
                try:
                    detail = e.read(200).decode('utf-8', 'replace').strip()
                except Exception:
                    pass
                # a server that echoes the request back must not put the key into a log
                detail = mask(detail, self._key)
                why = f'HTTP {e.code}' + (f' {detail}' if detail else '')
                if e.code == 401:
                    why += ' (is BUNNY_STORAGE_PASSWORD the password of this zone?)'
                if e.code not in RETRY_STATUS:
                    raise ZoneError(f'{where}: {why}') from None
            except urllib.error.URLError as e:
                if isinstance(e.reason, ssl.SSLCertVerificationError):
                    raise ZoneError(f'{where}: certificate not trusted ({e.reason.verify_message})') from None
                why = str(e.reason) if isinstance(e.reason, str) else f'{type(e.reason).__name__}: {e.reason}'
            except (ConnectionError, TimeoutError, http.client.HTTPException, ssl.SSLError) as e:
                why = f'{type(e).__name__}: {e}'
            if attempt < self.retries:
                self.sleep(min(2 ** attempt, 30))
        raise ZoneError(f'{where}: {why}, gave up after {self.retries + 1} tries')

    def _list_dir(self, rel):
        _, data = self.request('GET', rel, directory=True)
        try:
            items = json.loads(data)
        except ValueError:
            raise ZoneError(f'GET /{rel}: no JSON listing') from None
        if not isinstance(items, list):
            raise ZoneError(f'GET /{rel}: the listing is no list')
        return rel, items

    def list(self):
        """({path: (Checksum upper-case or None, Length)}, {directory}) of the whole zone."""
        files, dirs, pending = {}, set(), ['']
        with ThreadPoolExecutor(self.jobs) as pool:
            while pending:
                found = []
                for rel, items in pool.map(self._list_dir, pending):
                    for it in items:
                        name = it.get('ObjectName') if isinstance(it, dict) else None
                        if not isinstance(name, str) or not name or '/' in name or name in ('.', '..'):
                            raise ZoneError(f'GET /{rel}: odd entry {str(it)[:80]}')
                        path = rel + name
                        if it.get('IsDirectory'):
                            dirs.add(path)
                            found.append(path + '/')
                        else:
                            cs = it.get('Checksum')
                            files[path] = (cs.upper() if isinstance(cs, str) and cs else None, it.get('Length'))
                pending = found
        return files, dirs

    def put(self, rel, data, checksum):
        self.request('PUT', rel, body=data,
                     headers={'Checksum': checksum, 'Content-Type': 'application/octet-stream'})

    def delete(self, rel, directory=False):
        # gone already is what a delete wants
        self.request('DELETE', rel, directory=directory, missing_ok=True)


# ---------------------------------------------------------------------------------------
# the sync

def _parents(path):
    parts = _parts(path)[:-1]
    return {'/'.join(parts[:i]) for i in range(1, len(parts) + 1)}


def plan(local, remote_files, remote_dirs):
    """(upload, unchanged, delete files, delete directories), each sorted."""
    upload, same = [], []
    for rel, (cs, size) in sorted(local.items()):
        have = remote_files.get(rel)
        (same if have == (cs, size) else upload).append(rel)
    delete = sorted(set(remote_files) - set(local))
    local_dirs = set().union(*(_parents(p) for p in local)) if local else set()
    clash = sorted((set(remote_files) & local_dirs) | (remote_dirs & set(local)))
    if clash:
        raise MirrorError('a file in the zone where main has a directory or the other way round, '
                          'remove it there by hand: ' + ', '.join(clash[:10]))
    # deepest first, so a directory is empty by the time it goes
    gone = sorted(remote_dirs - local_dirs, key=lambda d: (-d.count('/'), d))
    return upload, same, delete, gone


def sync(tree, zone, dry_run=False, say=print):
    remote_files, remote_dirs = zone.list()
    upload, same, delete, gone = plan(tree.files, remote_files, remote_dirs)
    size = sum(tree.files[r][1] for r in upload)
    head = tree.commit[:12]
    if dry_run:
        for rel in upload:
            say(f'would upload {rel} ({tree.files[rel][1]} bytes)')
        for rel in delete:
            say(f'would delete {rel}')
        for d in gone:
            say(f'would delete {d}/')
        say(f'dry run {head}: {len(upload)} to upload, {len(same)} unchanged, '
            f'{len(delete) + len(gone)} to delete, {size} bytes to send; nothing written')
        return True

    sent = {'files': 0, 'bytes': 0}

    def send(rel):
        data = tree.read(rel)
        cs = hashlib.sha256(data).hexdigest().upper()
        if cs != tree.files[rel][0]:
            raise MirrorError(f'{rel} changed on disk since the build')
        zone.put(rel, data, cs)
        return rel, len(data)

    failed = []
    first = [r for r in upload if r not in LAST]
    with ThreadPoolExecutor(zone.jobs) as pool:
        futures = {pool.submit(send, rel): rel for rel in first}
        for fut in as_completed(futures):
            if fut.cancelled():
                continue
            try:
                rel, n = fut.result()
            except Exception as e:
                failed.append(f'{futures[fut]}: {e}')
                for other in futures:
                    other.cancel()
                continue
            sent['files'] += 1
            sent['bytes'] += n
            say(f'uploaded {rel}')
    if not failed:
        for rel in (r for r in LAST if r in upload):
            try:
                _, n = send(rel)
            except Exception as e:
                failed.append(f'{rel}: {e}')
                break
            sent['files'] += 1
            sent['bytes'] += n
            say(f'uploaded {rel}')
    if failed:
        for f in failed:
            say(f'FAILED {f}')
        say(f'stopped {head}: {sent["files"]} uploaded, {len(failed)} failed, {len(same)} unchanged, '
            f'0 deleted, {sent["bytes"]} bytes sent; the rest of the uploads, version.json last, '
            'and every delete held back for the next run')
        return False

    deleted = 0
    with ThreadPoolExecutor(zone.jobs) as pool:
        futures = {pool.submit(zone.delete, rel): rel for rel in delete}
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                failed.append(f'{futures[fut]}: {e}')
                continue
            deleted += 1
            say(f'deleted {futures[fut]}')
    for d in gone:
        if any(f.startswith(d + '/') for f in failed):
            continue
        try:
            zone.delete(d, directory=True)
        except Exception as e:
            failed.append(f'{d}/: {e}')
            continue
        deleted += 1
        say(f'deleted {d}/')
    for f in failed:
        say(f'FAILED delete {f}')
    say(f'synced {head}: {sent["files"]} uploaded, {len(same)} unchanged, {deleted} deleted, '
        f'{sent["bytes"]} bytes sent' + (f', {len(failed)} deletes failed' if failed else ''))
    return not failed


# ---------------------------------------------------------------------------------------

class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse would repeat whatever it did not understand, a password passed by
        # mistake included
        self.exit(2, f'{self.prog}: {message.split(":")[0]}\n')


def main(argv=None, env=None, sleep=time.sleep, stdout=None, stderr=None):
    env = os.environ if env is None else env
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    # pasted from a file or set with gh secret set < file, it brings a newline along, and
    # http.client puts a header value it refuses, password and all, into its ValueError
    secret = env.get(PASSWORD_ENV, '').strip()

    def scrub(text):
        return mask(text, secret)

    def say(line):
        print(scrub(line), file=stdout, flush=True)

    def fail(line, code=2):
        print(scrub(line), file=stderr, flush=True)
        return code

    ap = _Parser(prog='mirror_to_bunny.py', description=__doc__.splitlines()[0])
    ap.add_argument('--root', default='.', help='the git checkout (default: .)')
    ap.add_argument('--ref', default='HEAD', help='the commit to mirror (default: HEAD)')
    ap.add_argument('--out', help='directory for the tree, new or empty (default: a temporary one)')
    ap.add_argument('--tree-only', action='store_true', help='build the tree and the archive, no network')
    ap.add_argument('--dry-run', action='store_true', help='compare with the zone, write nothing')
    ap.add_argument('--zone-url', help=f'default: ${ZONE_URL_ENV} or {DEFAULT_ZONE_URL}')
    ap.add_argument('--jobs', type=int, default=6, help='parallel requests, 1 to 8 (default: 6)')
    ap.add_argument('--expect-archive-sha256', default='', metavar='HEX',
                    help='stop unless the archive has this sha256 (the attested one)')
    ap.add_argument('--any-ref', action='store_true',
                    help='sync or compare a commit that is not the head of origin/main')
    args, extra = ap.parse_known_args(argv)
    if extra:
        return fail(f'{ap.prog}: {len(extra)} unknown argument(s), not shown; '
                    f'the password goes in ${PASSWORD_ENV}, never on the command line')
    if args.tree_only and not args.out:
        return fail('--tree-only needs --out')
    try:
        zone_url = None
        if not args.tree_only:
            zone_url = check_zone_url(args.zone_url or env.get(ZONE_URL_ENV) or DEFAULT_ZONE_URL)
            if not secret:
                return fail(f'{PASSWORD_ENV} is not set: it is the password of the storage zone')
            if not all(' ' <= c <= '~' for c in secret):
                return fail(f'{PASSWORD_ENV} holds a control or non-ASCII character, which no zone '
                            'password has: copy it again, nothing was sent')
        with tempfile.TemporaryDirectory(prefix='mirror-') as tmp:
            ref = args.ref
            if not args.tree_only and not args.any_ref:
                # from a Testing checkout the default HEAD would put Testing on every
                # install's update mirror
                ref, head = resolve(args.root, args.ref), main_head(args.root)
                if ref != head:
                    return fail(f'{ref[:12]} is not the head of origin/main '
                                f'({head[:12] if head else "no origin/main here"}): the mirror carries '
                                'main. Use --ref origin/main after a git fetch, or --any-ref if you mean it')
            tree = build_tree(args.root, args.out or os.path.join(tmp, 'tree'), ref)
            say(f'built {tree.commit[:12]}: {len(tree.files)} files, {ARCHIVE} sha256 {tree.digest}')
            want = args.expect_archive_sha256.strip().lower()
            if want and want != tree.digest:
                return fail(f'{ARCHIVE} has sha256 {tree.digest}, not the expected {want[:64]}: '
                            'nothing uploaded')
            if args.tree_only:
                return 0
            zone = Zone(zone_url, secret, jobs=max(1, min(8, args.jobs)), sleep=sleep)
            return 0 if sync(tree, zone, dry_run=args.dry_run, say=say) else 1
    except MirrorError as e:
        return fail(f'error: {e}')
    except Exception:
        return fail('error: ' + traceback.format_exc())


if __name__ == '__main__':
    sys.exit(main())
