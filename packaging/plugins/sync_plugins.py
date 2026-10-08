#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bring the plugins PegaProx ships into the directory it loads them from.

NS Oct 2026 (#1134) - a package install had no plugins at all: debian/install never
shipped plugins/, and the service loads them from its working directory
(/var/lib/pegaprox/plugins), not from next to the code. The package now ships them
read-only and the postinst runs this on every install and upgrade. The Docker image
runs it on every start, update.sh and deploy.sh on every run.

    sync_plugins.py SOURCE TARGET [--owner USER:GROUP]

- a plugin of SOURCE that TARGET does not have is copied whole
- in one TARGET has, every file SOURCE ships is replaced, except the plugin's settings:
  config.json (the settings dialog, the plugin itself and the HA sync write it) stays
  as it is once it exists
- what only TARGET has is left alone: files a plugin wrote, __pycache__, and every
  plugin folder SOURCE does not ship (one the admin added)
- as root with --owner, the bundled plugins' folders end up owned by that user, kept
  settings included. Without root the owner is left alone
- nothing in TARGET is followed through a symlink: it belongs to the service user, and
  this runs as root

Exit status 0 when every plugin went in, 1 when one did not (the others still do).
"""
import argparse
import errno
import grp
import os
import pwd
import shutil
import stat
import sys

STATE_FILES = frozenset({'config.json'})
DIR_MODE = 0o750
FILE_MODE = 0o640
# a config.json written here may get a key or a token later
STATE_MODE = 0o600
_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC
_NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | _CLOEXEC


class Refused(OSError):
    """Something in the target where a plain directory belongs: left alone."""


def _exists(name, dir_fd):
    try:
        os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _open_dir(name, parent_fd):
    """The directory name in parent_fd, created when missing, never through a symlink."""
    created = False
    try:
        os.mkdir(name, DIR_MODE, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        pass
    try:
        fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            raise Refused(e.errno, f'{name} is a symlink or not a directory, left alone') from None
        raise
    if created:
        os.fchmod(fd, DIR_MODE)     # mkdir went through the umask
    return fd


def _copy_file(src_path, dir_fd, name, mode, owner):
    """Write name in dir_fd from src_path: a new file, renamed over the old one, so a
    symlink planted there is replaced, never written through."""
    tmp = f'.{name}.sync-tmp'
    try:
        os.unlink(tmp, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, _NEW_FILE_FLAGS, mode, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, 'wb') as out, open(src_path, 'rb') as src:
            shutil.copyfileobj(src, out)
            os.fchmod(out.fileno(), mode)
            if owner:
                os.fchown(out.fileno(), *owner)
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        raise


def _sync_tree(src_dir, dst_fd, owner, top, kept):
    """Copy src_dir into the open directory dst_fd. top: the plugin's own folder, where
    its settings are."""
    with os.scandir(src_dir) as it:
        entries = sorted(it, key=lambda e: e.name)
    for entry in entries:
        if entry.is_symlink():
            continue
        if entry.is_dir():
            if entry.name == '__pycache__':
                continue
            fd = _open_dir(entry.name, dst_fd)
            try:
                _sync_tree(entry.path, fd, owner, False, kept)
            finally:
                os.close(fd)
        elif entry.is_file():
            if entry.name.endswith(('.pyc', '.pyo')):
                continue
            state = top and entry.name in STATE_FILES
            if state and _exists(entry.name, dst_fd):
                kept.append(entry.name)
                continue
            _copy_file(entry.path, dst_fd, entry.name, STATE_MODE if state else FILE_MODE, owner)


def _hand_over(dir_fd, owner):
    """Everything under dir_fd to owner. A symlink, a special file and a file with a
    second hard link stay as they are."""
    os.fchown(dir_fd, *owner)
    with os.scandir(dir_fd) as it:
        entries = list(it)
    for entry in entries:
        st = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            fd = os.open(entry.name, _DIR_FLAGS, dir_fd=dir_fd)
            try:
                _hand_over(fd, owner)
            finally:
                os.close(fd)
        elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
            os.chown(entry.name, *owner, dir_fd=dir_fd, follow_symlinks=False)


def sync(source, target, owner=None, say=print):
    """Bring every plugin of source into target. owner: (uid, gid) to hand the bundled
    plugins to, or None. Returns the plugins that did not go in."""
    source = os.path.abspath(source)
    target = os.path.abspath(target)
    if not os.path.isdir(source):
        say(f'pegaprox plugins: {source} is not there, nothing to bring in')
        return ['*']
    if os.path.realpath(source) == os.path.realpath(target):
        return []
    parent, leaf = os.path.split(target)
    os.makedirs(parent, exist_ok=True)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC)
    try:
        root_fd = _open_dir(leaf, pfd)
    except OSError as e:
        say(f'pegaprox plugins: {target}: {e.strerror or e}')
        return ['*']
    finally:
        os.close(pfd)
    failed = []
    try:
        if owner:
            os.fchown(root_fd, *owner)
        for name in sorted(os.listdir(source)):
            path = os.path.join(source, name)
            if name.startswith(('.', '_')) or os.path.islink(path) or not os.path.isdir(path):
                continue
            existed = _exists(name, root_fd)
            kept = []
            try:
                fd = _open_dir(name, root_fd)
                try:
                    _sync_tree(path, fd, owner, True, kept)
                    if owner:
                        _hand_over(fd, owner)
                finally:
                    os.close(fd)
            except OSError as e:
                failed.append(name)
                say(f'pegaprox plugins: {name}: {e.strerror or e}')
                continue
            note = f', kept {", ".join(kept)}' if kept else ''
            say(f'pegaprox plugins: {name} {"updated" if existed else "installed"}{note}')
    finally:
        os.close(root_fd)
    return failed


def _parse_owner(spec):
    user, _, group = spec.partition(':')
    if user.isdigit():
        uid = int(user)
        gid = None
    else:
        pw = pwd.getpwnam(user)
        uid, gid = pw.pw_uid, pw.pw_gid
    if group:
        gid = int(group) if group.isdigit() else grp.getgrnam(group).gr_gid
    if gid is None:
        raise ValueError('a numeric user needs a group')
    return uid, gid


def main(argv=None):
    ap = argparse.ArgumentParser(description='Bring the bundled PegaProx plugins into the '
                                             'plugin directory, keeping their settings.')
    ap.add_argument('source', help='the plugins as shipped (read-only)')
    ap.add_argument('target', help='the directory PegaProx loads its plugins from')
    ap.add_argument('--owner', help='USER:GROUP the bundled plugins go to (as root only)')
    args = ap.parse_args(argv)
    owner = None
    if args.owner:
        try:
            owner = _parse_owner(args.owner)
        except (KeyError, ValueError) as e:
            ap.error(f'--owner {args.owner}: {e}')
        if os.geteuid() != 0:
            # only root hands files to another user; the caller's own files stay its own
            owner = None
    return 1 if sync(args.source, args.target, owner) else 0


if __name__ == '__main__':
    sys.exit(main())
