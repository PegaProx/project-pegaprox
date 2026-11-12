"""Every Tailwind utility web/src uses has a rule in what the page loads.

static/css/tailwind.min.css is a static build, made once, and a utility written into web/src
since then does nothing until the HTML shell spells it out. More than 200 had no rule: among
them w-80, so the Modern bell popover came out 112 px wide with its heading cut to 'Noti',
and max-h-72, so its inbox list grew with every entry instead of scrolling. The shell has a
rule for each of them now, with Tailwind's values and in its order.

The source checks read the spacing, size, grid, border width and colour utilities out of web/src,
with every variant, and look for their rule, so CI sees a new one without a rule. The proxmox and
theme colours are CSS variables, which Tailwind cannot give an opacity, so their rules with one are
written in the channel format of the static build. The browser checks drive the built
bundle in headless Chromium with the fake server of the pixel guard and skip where Playwright
or the browser is not installed.
"""
import glob
import os
import re

import pytest

from test_corp_redesigned_guard_ui import _GuardApp, _GuardServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

VARIANTS = r'(?:[a-z]+(?:-[a-z]+)?:)*'
SCALE = re.compile(r'(?<![\w:/\[.-])(' + VARIANTS + r'-?(?:w|h|min-w|min-h|max-w|max-h|p[xytrbl]?|m[xytrbl]?|gap(?:-[xy])?'
                   r'|space-[xy]|inset(?:-[xy])?|top|right|bottom|left|z|grid-cols|col-span)'
                   r'-(?:\d+(?:\.5)?|px|auto|full|screen))(?![\w/\[.-])')
PALETTE = ('slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|'
           'violet|purple|fuchsia|pink|rose')
# proxmox-orange, theme-success and the others of the shell's config
THEMED = r'(?:proxmox|theme)-[a-z]+'
COLOUR = re.compile(r'(?<![\w:/\[.-])(' + VARIANTS + r'(?:bg|text|border(?:-[trblxy])?|ring|from|via|to|placeholder'
                    r'|accent|divide|outline|decoration|fill|stroke|shadow)-(?:(?:' + PALETTE + r')-(?:50|[1-9]00|950)'
                    r'|' + THEMED + r')(?:/\d{1,3})?)(?![\w/\[.-])')
BORDER = re.compile(r'(?<![\w:/\[.-])(' + VARIANTS + r'border(?:-[trblxy])?(?:-[0248])?)(?![\w/\[.-])')
# the channel variables of the shell's :root and the static build's fallback for each
CHANNELS = {'orange': ('primary', '229,112,0'), 'dark': ('dark', '15,20,25'), 'darker': ('darker', '8,11,14'),
            'card': ('card', '22,27,34'), 'border': ('border', '48,54,61'), 'hover': ('hover', '28,33,40')}


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _css():
    return _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')


def _escaped(name):
    return re.sub(r'([\[\]\.\/:%#(),!])', r'\\\1', name)


def _used(pattern):
    found = {}
    for path in sorted(glob.glob(os.path.join(ROOT, 'web', 'src', '*.js'))):
        if path.endswith('translations.js'):
            continue
        for m in pattern.finditer(_read(path)):
            found.setdefault(m.group(1), os.path.basename(path))
    return found


def _without_rule(found):
    css = _css()
    return sorted(f'{c} ({f})' for c, f in found.items()
                  if not re.search(r'\.' + re.escape(_escaped(c)) + r'(?![\w\\-])', css))


def test_every_spacing_size_and_grid_utility_has_a_rule():
    found = _used(SCALE)
    assert {'w-80', 'max-h-72', 'sm:grid-cols-2', 'lg:grid-cols-6'} <= set(found)
    assert not _without_rule(found), _without_rule(found)


def test_every_colour_utility_has_a_rule():
    found = _used(COLOUR)
    assert {'text-amber-300', 'bg-red-500/15', 'hover:bg-red-500/25', 'bg-proxmox-orange/80',
            'hover:file:bg-proxmox-orange/30', 'divide-proxmox-border/40'} <= set(found)
    assert not _without_rule(found), _without_rule(found)


def test_every_border_width_utility_has_a_rule():
    found = _used(BORDER)
    assert {'border-b', 'border-2', 'last:border-0', 'last:border-b-0'} <= set(found)
    assert not _without_rule(found), _without_rule(found)


def test_the_proxmox_colours_with_an_opacity_use_the_theme_channels():
    """Tailwind leaves out a var() colour with an opacity, the rule takes the channels of the theme."""
    shell = _read('web', 'index.html.original')
    block = shell[shell.index('href="/static/css/tailwind.min.css"'):]
    block = block[:block.index('</style>')]
    rules = re.findall(r'^\s*(\.[^\s{]*?proxmox-([a-z]+)\\/(\d+)[^{]*?) \{ ([^}]*) \}$', block, re.M)
    assert len(rules) >= 15, rules
    for selector, name, alpha, body in rules:
        var, fallback = CHANNELS[name]
        assert body.endswith(f'rgba(var(--color-{var}-rgb,{fallback}),{int(alpha) / 100:g});'), (selector, body)


def test_the_rules_have_tailwinds_values_and_come_after_the_build():
    shell = _read('web', 'index.html.original')
    link = shell.index('href="/static/css/tailwind.min.css"')
    for rule in ('.w-80 { width: 20rem; }', '.max-h-72 { max-height: 18rem; }',
                 '.sm\\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }',
                 '.text-amber-300 { --tw-text-opacity: 1; color: rgb(252 211 77 / var(--tw-text-opacity, 1)); }'):
        assert shell.count(rule) == 1 and shell.index(rule) > link, rule
    # Tailwind writes a wider breakpoint after a narrower one: a grid with sm:grid-cols-2 and md:grid-cols-4
    # keeps its four columns from 768 px on, one with md:grid-cols-4 and lg:grid-cols-7 its seven from 1024,
    # so the build's own wider rules of those properties follow the added narrower ones again
    sm, md, lg = (shell.index(f'.{c} {{') for c in ('sm\\:grid-cols-2', 'md\\:grid-cols-4', 'lg\\:grid-cols-7'))
    assert link < sm < md < lg


INBOX = [{'id': i, 'title': f'Node pve{i} is offline', 'severity': 'critical', 'url': '/',
          'body': 'The node stopped answering its cluster peers and the guests on it were moved elsewhere. '
                  'Check the network and the power of the host.',
          'created_at': f'2026-10-30T08:{i:02d}:00', 'read_at': None} for i in range(8)]


@pytest.fixture
def modern(browser):  # noqa: F811
    apps = []

    def _open(width=1600, language='en'):
        server = _GuardServer(layout='modern', language=language,
                              extra={('GET', '/api/push/inbox'): (200, {'items': INBOX})})
        app = _GuardApp(browser, server, storage={'pegaprox-language': language}, viewport=(width, 1000))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


POPOVER = '''() => {
  const bell = document.querySelector('header button[title="Notifications"]');
  const pop = bell && bell.parentElement.querySelector(':scope > div.absolute');
  if (!pop) return null;
  const list = pop.querySelector('.overflow-y-auto');
  const head = pop.querySelector('.text-sm.font-semibold');
  const r = pop.getBoundingClientRect();
  return {width: r.width, left: r.left, right: r.right, inner: innerWidth,
          listHeight: list.getBoundingClientRect().height, listMax: getComputedStyle(list).maxHeight,
          listScroll: list.scrollHeight, rows: list.querySelectorAll('a').length,
          heading: head.innerText, headingCut: head.scrollWidth > head.clientWidth + 1};
}'''


def test_runtime_the_overview_keeps_its_seven_tiles_in_a_row(modern):
    """grid-cols-2 md:grid-cols-4 lg:grid-cols-7: the md rule written again must not win over the lg one."""
    app = modern(1600)
    page = app.page
    page.locator('.lg\\:grid-cols-7').first.wait_for(timeout=8000)
    cols = page.evaluate("getComputedStyle(document.querySelector('.lg\\\\:grid-cols-7')).gridTemplateColumns.split(' ').length")
    assert cols == 7, cols
    page.set_viewport_size({'width': 900, 'height': 1000})
    page.wait_for_timeout(300)
    cols = page.evaluate("getComputedStyle(document.querySelector('.lg\\\\:grid-cols-7')).gridTemplateColumns.split(' ').length")
    assert cols == 4, cols


@pytest.mark.parametrize('width', [1600, 1280])
def test_runtime_the_bell_popover_is_320_wide_and_its_list_scrolls(modern, width):
    app = modern(width)
    page = app.page
    page.locator('header button[title="Notifications"]').first.click()
    page.wait_for_function(POPOVER.replace('if (!pop) return null;', 'if (!pop || !pop.querySelector("a")) return null;'),
                           timeout=8000)
    got = page.evaluate(POPOVER)
    # w-80 is 20rem
    assert got['width'] == 320, got
    assert got['left'] >= 0 and got['right'] <= got['inner'], got
    assert got['heading'] == 'Notifications' and not got['headingCut'], got
    # max-h-72 is 18rem: eight entries are taller than that, the list scrolls instead of growing
    assert got['rows'] == 8 and got['listMax'] == '288px', got
    assert got['listHeight'] == 288 and got['listScroll'] > 288, got
    assert not app.errors, app.errors


ROW = '''(hovered) => {
  const bell = document.querySelector('header button[title="Notifications"]');
  const row = bell.parentElement.querySelector(':scope > div.absolute .overflow-y-auto a');
  return {bg: getComputedStyle(row).backgroundColor,
          dark: getComputedStyle(document.documentElement).getPropertyValue('--color-dark-rgb')};
}'''


def _rgba(css):
    m = re.fullmatch(r'rgba?\(([^)]*)\)', css.strip())
    assert m, css
    parts = [float(p) for p in m.group(1).replace('/', ',').split(',')]
    return parts if len(parts) == 4 else parts + [1.0]


def _channels(var):
    return [float(p) for p in var.split(',')]


def test_runtime_an_inbox_entry_darkens_under_the_pointer(modern):
    """hover:bg-proxmox-dark/60 over the bg-proxmox-dark/30 of an unread entry."""
    app = modern(1600)
    page = app.page
    page.locator('header button[title="Notifications"]').first.click()
    page.wait_for_function(POPOVER.replace('if (!pop) return null;', 'if (!pop || !pop.querySelector("a")) return null;'),
                           timeout=8000)
    page.mouse.move(5, 995)
    rest = page.evaluate(ROW)
    assert _rgba(rest['bg']) == _channels(rest['dark']) + [0.3], rest
    page.locator('header button[title="Notifications"]').first.locator('xpath=..').locator(
        ':scope > div.absolute .overflow-y-auto a').first.hover()
    page.wait_for_timeout(100)
    over = page.evaluate(ROW)
    assert _rgba(over['bg']) == _channels(over['dark']) + [0.6], over


# class, state, the element the colour is read from, property, channel variable, opacity
PROBES = [
    # a rule of the static build, so a failure below is the rule and not the probe
    ('bg-proxmox-orange/20', '', '', 'backgroundColor', 'primary', 0.2),
    ('bg-proxmox-orange/80', '', '', 'backgroundColor', 'primary', 0.8),
    ('bg-proxmox-dark/40', '', '', 'backgroundColor', 'dark', 0.4),
    ('border border-proxmox-border/30', '', '', 'borderTopColor', 'border', 0.3),
    ('border border-proxmox-border/40', '', '', 'borderTopColor', 'border', 0.4),
    ('border border-proxmox-border/60', '', '', 'borderTopColor', 'border', 0.6),
    # the spinner of the scan buttons: a faint ring with a solid top
    ('border-2 border-proxmox-orange/40 border-t-proxmox-orange', '', '', 'borderRightColor', 'primary', 0.4),
    ('border-2 border-proxmox-orange/40 border-t-proxmox-orange', '', '', 'borderTopColor', 'primary', 1),
    ('divide-y divide-proxmox-border/40', '', 'second', 'borderTopColor', 'border', 0.4),
    ('hover:bg-proxmox-dark/40', 'hover', '', 'backgroundColor', 'dark', 0.4),
    ('hover:bg-proxmox-dark/60', 'hover', '', 'backgroundColor', 'dark', 0.6),
    ('hover:bg-proxmox-darker/40', 'hover', '', 'backgroundColor', 'darker', 0.4),
    ('hover:bg-proxmox-orange/10', 'hover', '', 'backgroundColor', 'primary', 0.1),
    ('bg-proxmox-orange hover:bg-proxmox-orange/80', 'hover', '', 'backgroundColor', 'primary', 0.8),
    ('border border-[#3a5565] focus:border-proxmox-orange/50', 'focus', '', 'borderTopColor', 'primary', 0.5),
    ('file:bg-proxmox-orange/20 hover:file:bg-proxmox-orange/30', '', 'file', 'backgroundColor', 'primary', 0.2),
    ('file:bg-proxmox-orange/20 hover:file:bg-proxmox-orange/30', 'hover', 'file', 'backgroundColor', 'primary', 0.3),
]

PROBE_MOUNT = '''(probes) => {
  const host = document.createElement('div');
  host.id = 'tw-probe';
  host.style.cssText = 'position:fixed;left:0;top:0;width:320px;z-index:2147483647;background:#fff;padding:4px';
  probes.forEach(([cls, state, read], i) => {
    let el;
    if (read === 'file') {
      el = document.createElement('input');
      el.type = 'file';
    } else if (state === 'focus') {
      el = document.createElement('input');
    } else {
      el = document.createElement('div');
      el.style.height = '12px';
    }
    if (read === 'second') el.innerHTML = '<div style="height:4px"></div><div style="height:4px"></div>';
    el.className = cls;
    el.dataset.probe = i;
    el.style.width = '300px';
    el.style.display = 'block';
    host.appendChild(el);
  });
  // the last row of a list drops its bottom border
  const list = document.createElement('div');
  list.dataset.probe = 'list';
  list.innerHTML = '<div class="border-b border-proxmox-border last:border-b-0" style="height:4px"></div>'.repeat(2);
  host.appendChild(list);
  document.body.appendChild(host);
}'''

PROBE_READ = '''([i, read, prop, varName]) => {
  let el = document.querySelector(`[data-probe="${i}"]`);
  if (read === 'second') el = el.children[1];
  const style = getComputedStyle(el, read === 'file' ? '::file-selector-button' : null);
  return {value: style[prop], channels: getComputedStyle(document.documentElement).getPropertyValue(`--color-${varName}-rgb`)};
}'''


def test_runtime_the_proxmox_colours_with_an_opacity_and_last_border_b_0_apply(modern):
    """Each rule the static build lacked, on an element in the loaded page, in its state."""
    app = modern(1600)
    page = app.page
    page.evaluate(PROBE_MOUNT, [[cls, state, read] for cls, state, read, *_ in PROBES])
    wrong = []
    for i, (cls, state, read, prop, var, alpha) in enumerate(PROBES):
        target = page.locator(f'[data-probe="{i}"]')
        page.mouse.move(5, 995)
        page.evaluate('document.activeElement && document.activeElement.blur()')
        if state == 'hover':
            # the button of a file input sits at its left end
            target.hover(position={'x': 8, 'y': 8} if read == 'file' else None)
        elif state == 'focus':
            target.focus()
        got = page.evaluate(PROBE_READ, [i, read, prop, var])
        want = _channels(got['channels']) + [float(alpha)]
        if _rgba(got['value']) != want:
            wrong.append((cls, state, read, prop, got['value'], want))
    rows = page.evaluate('''() => [...document.querySelector('[data-probe="list"]').children]
                              .map(r => getComputedStyle(r).borderBottomWidth)''')
    if rows != ['1px', '0px']:
        wrong.append(('last:border-b-0', rows))
    assert not wrong, wrong
    assert not app.errors, app.errors
