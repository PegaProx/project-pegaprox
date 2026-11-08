#!/usr/bin/env python3
"""Turn the pinned pure-Python wheels of packaging/apt/python-debs/ into .debs.

    python3 -I packaging/apt/build-python-debs.py <wheel-dir> <out-dir>

Two of the libraries pegaprox depends on are not in trixie (flask-sock, XenAPI). They
are pure Python, so the package is the wheel's files under /usr/lib/python3/dist-packages,
a control file naming the Debian packages of the wheel's own requirements, copyright and
changelog under /usr/share/doc, and the py3compile/py3clean calls dh_python3 would have
written. No .pyc ships; py3compile writes them on the target and py3clean takes them away.

The wheel-dir holds exactly what `pip download --require-hashes` fetched from
python-debs/requirements.txt. Every file is checked against the wheel's RECORD, every
requirement of the wheel must map to a Depends entry here, and the same wheel gives the
same .deb (dates from the wheel, root ownership, no build-time paths).

NS Oct 2026
"""
import base64
import calendar
import email.parser
import gzip
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
COPYRIGHT_DIR = os.path.join(HERE, 'python-debs')
MAINTAINER = 'PegaProx Team <apt@pegaprox.com>'
# Debian revision of our builds: "0.7.0-0pegaprox1" sorts below a "0.7.0-1" that Debian
# (or anyone else) may package later, so a real package of the same version wins
REVISION = '0pegaprox1'

# PyPI name (normalised) -> the .deb. `requires` maps the wheel's Requires-Dist onto Debian
# packages; a requirement that is not listed here stops the build.
PACKAGES = {
    'flask-sock': {
        'deb': 'python3-flask-sock',
        'requires': {'flask': 'python3-flask', 'simple-websocket': 'python3-simple-websocket'},
        'description': 'WebSocket support for Flask (Python 3)',
    },
    'xenapi': {
        'deb': 'python3-xenapi',
        'requires': {},
        'description': 'XenAPI SDK for XenServer and XCP-ng (Python 3)',
    },
}

DIST_PACKAGES = 'usr/lib/python3/dist-packages'
# pip's own bookkeeping, no place for it in a tree dpkg owns
DROP_FROM_DIST_INFO = {'RECORD', 'INSTALLER', 'REQUESTED', 'direct_url.json'}
WHEEL_NAME = re.compile(r'^(?P<name>[A-Za-z0-9_.]+)-(?P<version>[A-Za-z0-9_.!+]+)-py3-none-any\.whl$')

POSTINST = 'if command -v py3compile >/dev/null 2>&1; then\n\tpy3compile -p {deb}\nfi\n'
PRERM = 'if command -v py3clean >/dev/null 2>&1; then\n\tpy3clean -p {deb}\nfi\n'


def _norm(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def _fail(msg):
    sys.exit(f'build-python-debs: {msg}')


def _record(zf, dist_info):
    out = {}
    for line in zf.read(f'{dist_info}/RECORD').decode('utf-8').splitlines():
        path, digest, _size = line.rsplit(',', 2)
        if digest:
            out[path] = digest
    return out


def _matches_record(data, digest):
    algo, _, want = digest.partition('=')
    if algo != 'sha256':
        return False
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode() == want


def _depends(meta, spec):
    """python3:any plus the Debian package of every unconditional Requires-Dist."""
    deps = ['python3:any']
    for line in meta.get_all('Requires-Dist') or []:
        req, _, marker = line.partition(';')
        if 'extra' in marker:
            continue
        if marker.strip():
            _fail(f'{spec["deb"]}: "{line}" has a marker, map it by hand')
        m = re.match(r'\s*([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*\(?([^)]*)\)?\s*$', req)
        if not m:
            _fail(f'{spec["deb"]}: cannot read requirement "{line}"')
        name, constraint = _norm(m.group(1)), m.group(2).replace(' ', '')
        deb = spec['requires'].get(name)
        if not deb:
            _fail(f'{spec["deb"]}: the wheel requires {name}, which has no Debian package in PACKAGES')
        # a plain lower bound carries over; anything fancier is for a human to translate
        if constraint and not re.fullmatch(r'>=[0-9][0-9A-Za-z.]*', constraint):
            _fail(f'{spec["deb"]}: {name}{constraint} is more than a lower bound, map it by hand')
        deps.append(f'{deb} (>= {constraint[2:]})' if constraint else deb)
    return deps


def _homepage(meta):
    if meta['Home-page']:
        return meta['Home-page']
    for url in meta.get_all('Project-URL') or []:
        label, _, link = url.partition(',')
        if label.strip().lower() in ('homepage', 'source', 'source code'):
            return link.strip()
    return ''


def _unpack(zf, fname, dist_info, site):
    record = _record(zf, dist_info)
    for info in zf.infolist():
        n = info.filename
        if n.endswith('/'):
            continue
        parts = n.split('/')
        if n.startswith('/') or '..' in parts:
            _fail(f'{fname}: refusing the path {n}')
        if parts[0].endswith('.data'):
            _fail(f'{fname}: {parts[0]} installs outside dist-packages, not handled here')
        if n.endswith(('.pyc', '.pyo')) or '__pycache__' in parts:
            continue
        if parts[0] == dist_info and parts[-1] in DROP_FROM_DIST_INFO:
            continue
        data = zf.read(n)
        if n not in record or not _matches_record(data, record[n]):
            _fail(f'{fname}: {n} does not match the RECORD of its wheel')
        dest = os.path.join(site, *parts)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'wb') as fh:
            fh.write(data)


def _write_docs(root, spec, deb_version, meta, epoch):
    doc = os.path.join(root, 'usr', 'share', 'doc', spec['deb'])
    os.makedirs(doc)
    shutil.copyfile(os.path.join(COPYRIGHT_DIR, f'{spec["deb"]}.copyright'), os.path.join(doc, 'copyright'))
    stamp = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime(epoch))
    entry = (f'{spec["deb"]} ({deb_version}) trixie; urgency=medium\n\n'
             f'  * {meta["Name"]} {meta["Version"]} from PyPI, for the PegaProx APT repository.\n\n'
             f' -- {MAINTAINER}  {stamp}\n')
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, compresslevel=9, mtime=0) as gz:
        gz.write(entry.encode('utf-8'))
    with open(os.path.join(doc, 'changelog.Debian.gz'), 'wb') as fh:
        fh.write(buf.getvalue())


def _installed_size(root):
    kib = 0
    for dirpath, dirnames, filenames in os.walk(root):
        kib += len(dirnames)
        kib += sum((os.path.getsize(os.path.join(dirpath, f)) + 1023) // 1024 for f in filenames)
    return kib


def _write_control(root, spec, deb_version, meta):
    md5 = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            with open(p, 'rb') as fh:
                md5.append((os.path.relpath(p, root), hashlib.md5(fh.read()).hexdigest()))
    size = _installed_size(root)
    control_dir = os.path.join(root, 'DEBIAN')
    os.makedirs(control_dir)
    with open(os.path.join(control_dir, 'md5sums'), 'w', encoding='utf-8') as fh:
        fh.writelines(f'{h}  {p}\n' for p, h in sorted(md5))
    fields = [
        ('Package', spec['deb']),
        ('Version', deb_version),
        ('Architecture', 'all'),
        ('Maintainer', MAINTAINER),
        ('Installed-Size', str(size)),
        ('Depends', ', '.join(_depends(meta, spec))),
        ('Section', 'python'),
        ('Priority', 'optional'),
    ]
    if _homepage(meta):
        fields.append(('Homepage', _homepage(meta)))
    fields.append(('Description', f'{spec["description"]}\n'
                   f' {meta["Name"]} {meta["Version"]} as published on PyPI, packaged for the\n'
                   f' PegaProx APT repository because Debian trixie does not carry it.'))
    with open(os.path.join(control_dir, 'control'), 'w', encoding='utf-8') as fh:
        fh.writelines(f'{k}: {v}\n' for k, v in fields)
    for name, body in (('postinst', POSTINST), ('prerm', PRERM)):
        path = os.path.join(control_dir, name)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('#!/bin/sh\nset -e\n\n' + body.format(deb=spec['deb']))
        os.chmod(path, 0o755)
    return control_dir


def build(wheel_path, out_dir):
    fname = os.path.basename(wheel_path)
    m = WHEEL_NAME.match(fname)
    if not m:
        _fail(f'{fname} is not a pure-Python py3-none-any wheel')
    spec = PACKAGES.get(_norm(m.group('name')))
    if not spec:
        _fail(f'{fname}: nothing in PACKAGES for {_norm(m.group("name"))}')
    upstream = m.group('version')
    deb_version = f'{upstream}-{REVISION}'

    work = tempfile.mkdtemp(prefix=f'{spec["deb"]}-')
    try:
        root = os.path.join(work, 'root')
        with zipfile.ZipFile(wheel_path) as zf:
            metas = [n for n in zf.namelist() if re.fullmatch(r'[^/]+\.dist-info/METADATA', n)]
            if len(metas) != 1:
                _fail(f'{fname}: expected one .dist-info, found {metas}')
            dist_info = metas[0].split('/')[0]
            meta = email.parser.Parser().parsestr(zf.read(metas[0]).decode('utf-8'))
            if _norm(meta['Name']) != _norm(m.group('name')) or meta['Version'] != upstream:
                _fail(f'{fname}: its METADATA says {meta["Name"]} {meta["Version"]}')
            wheel = email.parser.Parser().parsestr(zf.read(f'{dist_info}/WHEEL').decode('utf-8'))
            if (wheel['Root-Is-Purelib'] or '').strip().lower() != 'true':
                _fail(f'{fname} is not purelib')
            # every date in the package comes from the wheel
            epoch = max(calendar.timegm(i.date_time + (0, 0, 0)) for i in zf.infolist())
            _unpack(zf, fname, dist_info, os.path.join(root, DIST_PACKAGES))

        _write_docs(root, spec, deb_version, meta, epoch)
        control_dir = _write_control(root, spec, deb_version, meta)

        for dirpath, _dirs, files in os.walk(root):
            os.chmod(dirpath, 0o755)
            for f in files:
                if dirpath != control_dir or f not in ('postinst', 'prerm'):
                    os.chmod(os.path.join(dirpath, f), 0o644)
        for dirpath, _dirs, files in os.walk(root, topdown=False):
            for f in files:
                os.utime(os.path.join(dirpath, f), (epoch, epoch))
            os.utime(dirpath, (epoch, epoch))

        os.makedirs(out_dir, exist_ok=True)
        target = os.path.join(out_dir, f'{spec["deb"]}_{deb_version}_all.deb')
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '--build', root, target],
                       check=True, stdout=subprocess.DEVNULL,
                       env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)))
        print(target)
        return target
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv):
    if len(argv) != 3:
        sys.exit('usage: build-python-debs.py <wheel-dir> <out-dir>')
    wheel_dir, out_dir = argv[1], argv[2]
    wheels = sorted(f for f in os.listdir(wheel_dir) if f.endswith('.whl'))
    names = {_norm(WHEEL_NAME.match(w).group('name')) for w in wheels if WHEEL_NAME.match(w)}
    if len(wheels) != len(PACKAGES) or names != set(PACKAGES):
        _fail(f'expected one wheel each for {sorted(PACKAGES)}, found {wheels}')
    for w in wheels:
        build(os.path.join(wheel_dir, w), out_dir)


if __name__ == '__main__':
    main(sys.argv)
