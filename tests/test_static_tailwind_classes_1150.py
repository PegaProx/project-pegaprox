"""#1150: a class the static Tailwind build does not have does nothing.

Tailwind is a static build (static/css/tailwind.min.css), made once. An arbitrary value
written into web/src since then (z-[10010], max-w-[180px] ...) has no rule unless the HTML
shell spells it out. The PBS dialogs' z-[10010] was such a class: the dialog had no z-index,
and the sticky header of a corporate data grid painted over it.
"""

import glob
import os
import re

import pytest

from test_ha_ui import PBS, _App, _FakeServer, browser  # noqa: F401


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Arbitrary values that were already without a rule when this check came in. They are
# layout and colour details, not stacking; each one wants its own look before it gets a rule.
KNOWN_WITHOUT_RULE = {
    'bg-[#1a2e38]', 'bg-[var(--corp-card-bg)]', 'border-[#344955]', 'border-[#3a5565]',
    'border-[#49afd9]', 'border-[var(--corp-border-medium)]',
    'drop-shadow-[0_8px_20px_rgba(229,112,0,0.35)]', 'hover:scale-[1.03]', 'max-h-[150px]',
    'max-h-[40rem]', 'max-w-[180px]', 'max-w-[220px]', 'max-w-[520px]', 'max-w-[60px]',
    'min-h-[120px]', 'min-h-[38px]', 'min-w-[12rem]', 'min-w-[16px]', 'min-w-[180px]',
    'min-w-[20rem]', 'min-w-[90px]', 'text-[#5a7a8a]', 'text-[10.5px]',
}


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _escaped(name):
    return re.sub(r'([\[\]\.\/:%#(),!])', r'\\\1', name)


def _arbitrary_classes():
    found = set()
    for path in glob.glob(os.path.join(ROOT, 'web', 'src', '*.js')):
        src = open(path, encoding='utf-8').read()
        found.update(m.group(1) for m in re.finditer(
            r'(?<![\w-])((?:[a-z]+:)*-?[a-z][a-z0-9-]*-\[[^\]\s"\'`{}]+\](?:/\d+)?)', src))
    return found


def test_every_arbitrary_class_has_a_rule():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    missing = sorted(c for c in _arbitrary_classes()
                     if _escaped(c) not in css and c not in KNOWN_WITHOUT_RULE)
    assert not missing, f'no rule in the static build or the shell: {missing}'


def test_every_z_index_class_has_a_rule():
    # stacking breaks silently; none of these may ever wait on the list above
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    layers = sorted(c for c in _arbitrary_classes() if re.match(r'^(?:[a-z]+:)*-?z-\[', c))
    assert layers and all(_escaped(c) in css for c in layers), layers
    assert not {c for c in KNOWN_WITHOUT_RULE if 'z-[' in c}


def test_the_known_list_only_holds_what_is_still_missing():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    used = _arbitrary_classes()
    stale = sorted(c for c in KNOWN_WITHOUT_RULE if c not in used or _escaped(c) in css)
    assert not stale, f'gone from web/src or has a rule now, drop it from the list: {stale}'


TASKS = [{'upid': f'UPID:pbs:{i:08X}:0:0:6A1B2C{i:02X}:backup:store:root@pam:', 'worker_type': 'backup',
          'status': 'OK', 'starttime': 1780000000 - i * 600, 'endtime': 1780000000 - i * 600 + 30}
         for i in range(10)]
READS = {
    ('GET', '/api/pbs'): (200, [PBS]),
    ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
    ('GET', '/api/pbs/p1/datastores'): (200, [{'name': 'alpha', 'total': 1000, 'used': 400,
                                              'avail': 600, 'detail': {}}]),
    ('GET', '/api/pbs/p1/tasks'): (200, TASKS),
    ('GET', '/api/pbs/verify-schedule'): (200, {'enabled': False, 'weekly_count': 5, 'day': 'sun',
                                                'hour': 4, 'scope': 'latest_per_vm'}),
}

# every sticky data-grid header that sits under the open dialog: what is painted there?
COVERED_JS = '''() => {
    const dialog = [...document.querySelectorAll('div.fixed.inset-0')]
        .map(o => o.firstElementChild).find(d => d && d.innerText.includes('Auto Backup Verification'));
    if (!dialog) return null;
    const box = dialog.getBoundingClientRect();
    const out = [];
    for (const th of document.querySelectorAll('.corp-datagrid th')) {
        const r = th.getBoundingClientRect();
        const y = r.top + r.height / 2;
        if (r.height === 0 || y <= box.top + 2 || y >= box.bottom - 2) continue;
        const x = Math.min(Math.max(box.left + box.width / 2, r.left + 1), r.right - 1);
        if (x <= box.left || x >= box.right) continue;
        const hit = document.elementFromPoint(x, y);
        out.push(!!hit && dialog.contains(hit));
    }
    return out;
}'''


def test_the_verify_dialog_stays_above_the_corporate_table_headers(browser):
    app = _App(browser, _FakeServer(role='standalone', layout='corporate', extra=READS))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        header = page.locator('.corp-datagrid th').filter(has_text=re.compile('Type', re.I)).first
        header.wait_for(timeout=5000)
        # the header row in the middle of the screen, where the dialog opens
        header.evaluate("th => th.scrollIntoView({block: 'center'})")
        page.get_by_role('button', name=re.compile('Auto Verify')).first.click()
        page.get_by_text('Auto Backup Verification').first.wait_for(timeout=5000)

        covered = page.evaluate(COVERED_JS)
        assert covered, 'no data-grid header under the dialog to check'
        assert all(covered), covered
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
