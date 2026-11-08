#!/usr/bin/env python3
"""HEAD every image in the cloud-init catalog and fail with the ones that are gone.

NS Oct 2026 - the catalog in pegaprox/api/templates_lib.py points at distribution
mirrors, and a release that reaches end of life drops off them without notice: the
Fedora 40 entry had been answering 404 long before anyone noticed. The
image-catalog-check workflow runs this weekly and whenever the catalog changes.

The list is parsed out of the source with ast rather than imported, so this runs on a
bare python3 without the app's dependencies and the catalog stays in one place.

    python3 scripts/check_image_catalog.py             # every URL plus the eol dates
    python3 scripts/check_image_catalog.py --offline   # only the eol dates

Exit 0 when every image answers and no entry is past its eol, 1 otherwise.
"""
import argparse
import ast
import datetime
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG_FILE = os.path.join(ROOT, 'pegaprox', 'api', 'templates_lib.py')
USER_AGENT = 'pegaprox-image-catalog-check (+https://github.com/PegaProx/project-pegaprox)'


def load_catalog():
    """The CATALOG list literal from the module source."""
    with open(CATALOG_FILE, encoding='utf-8') as fh:
        tree = ast.parse(fh.read(), filename=CATALOG_FILE)
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'CATALOG'):
            return ast.literal_eval(node.value)
    raise ValueError(f'no CATALOG = [...] in {CATALOG_FILE}')


class _KeepMethod(urllib.request.HTTPRedirectHandler):
    # urllib turns a redirected HEAD into a GET, and a GET here is a whole disk image
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.method = req.get_method()
        return new


_opener = urllib.request.build_opener(_KeepMethod)


def _ask(url, method, timeout):
    headers = {'User-Agent': USER_AGENT}
    if method == 'GET':
        headers['Range'] = 'bytes=0-0'
    req = urllib.request.Request(url, method=method, headers=headers)
    with _opener.open(req, timeout=timeout) as resp:
        return resp.status, resp.geturl(), resp.headers.get('Content-Type', '')


def probe(url, timeout=30):
    """None when the image answers, otherwise why not. Some servers refuse HEAD, so a
    405/403/501 is asked again as a one-byte ranged GET."""
    try:
        try:
            status, final, ctype = _ask(url, 'HEAD', timeout)
        except urllib.error.HTTPError as e:
            if e.code not in (403, 405, 501):
                raise
            status, final, ctype = _ask(url, 'GET', timeout)
    except urllib.error.HTTPError as e:
        return f'HTTP {e.code} from {e.filename or url}'
    except (urllib.error.URLError, OSError, ValueError) as e:
        return f'{type(e).__name__}: {getattr(e, "reason", e)}'
    if status not in (200, 206):
        return f'HTTP {status} from {final}'
    # a mirror's error or index page, not a disk image
    if ctype.split(';')[0].strip().lower() == 'text/html':
        return f'HTML page instead of an image at {final}'
    return None


def check_url(url, attempts=3, pause=5.0, timeout=30):
    """probe() with retries: a redirector that picks a random mirror can land on one
    bad mirror, a release that left all of them fails every time."""
    why = None
    for i in range(attempts):
        why = probe(url, timeout=timeout)
        if why is None:
            return None
        if i + 1 < attempts:
            time.sleep(pause * (i + 1))
    return why


def eol_problem(entry, today, warn_days):
    """('error' | 'warning' | None, text) for the entry's eol date."""
    raw = entry.get('eol')
    if not raw:
        return 'error', 'no eol date'
    try:
        eol = datetime.date.fromisoformat(raw)
    except (TypeError, ValueError):
        return 'error', f'eol {raw!r} is not YYYY-MM-DD'
    if eol < today:
        return 'error', f'past its end of life ({raw}), replace it'
    if (eol - today).days <= warn_days:
        return 'warning', f'end of life on {raw}, plan the replacement'
    return None, ''


def run(catalog, offline=False, today=None, warn_days=60, attempts=3, pause=5.0,
        timeout=30, out=print):
    """Check every entry, report, return the number of errors."""
    today = today or datetime.date.today()
    errors, warnings = [], []
    for entry in catalog:
        level, text = eol_problem(entry, today, warn_days)
        if level == 'error':
            errors.append((entry.get('id', '?'), text))
        elif level == 'warning':
            warnings.append((entry.get('id', '?'), text))

    if not offline:
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(
                lambda e: check_url(e.get('image_url', ''), attempts, pause, timeout), catalog))
        for entry, why in zip(catalog, results):
            out(f"{'ok  ' if why is None else 'DEAD'}  {entry.get('id', '?'):<16} {entry.get('image_url', '')}")
            if why is not None:
                errors.append((entry.get('id', '?'), why))

    gha = os.environ.get('GITHUB_ACTIONS') == 'true'
    for tid, text in warnings:
        out(f'::warning title=Image catalog::{tid}: {text}' if gha else f'warning: {tid}: {text}')
    if errors:
        out(f'\n{len(errors)} problem(s) in {os.path.relpath(CATALOG_FILE, ROOT)}:')
        for tid, text in errors:
            out(f'::error title=Image catalog::{tid}: {text}' if gha else f'  {tid}: {text}')
    else:
        out(f'\nall {len(catalog)} catalog entries are fine')

    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        try:
            with open(summary, 'a', encoding='utf-8') as fh:
                fh.write('### Cloud image catalog\n\n')
                if not errors and not warnings:
                    fh.write(f'All {len(catalog)} entries answer and are supported.\n')
                for tid, text in errors:
                    fh.write(f'- :x: `{tid}`: {text}\n')
                for tid, text in warnings:
                    fh.write(f'- :warning: `{tid}`: {text}\n')
        except OSError:
            pass
    return len(errors)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--offline', action='store_true', help='only check the eol dates')
    ap.add_argument('--warn-days', type=int, default=60,
                    help='warn this many days before an eol (default 60)')
    args = ap.parse_args(argv)
    catalog = load_catalog()
    return 1 if run(catalog, offline=args.offline, warn_days=args.warn_days) else 0


if __name__ == '__main__':
    sys.exit(main())
