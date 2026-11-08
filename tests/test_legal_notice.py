"""The Appropriate Legal Notices have to actually be in the interface.

The NOTICE file makes a §7(b) claim about specific things the program displays.
That claim is only as good as the display: if the login screen, the sidebar or the
About panel stops rendering its notice, the term in NOTICE points at nothing and
the attribution argument goes with it. These assert the two halves stay in step.

Verified in a browser too — present is not the same as on-screen, and the console
window caught exactly that (a fixed overlay sitting on top of the strip). NS
"""
import re

import pytest


SRC = 'web/src/'
# every surface that must carry the short notice, and the file it lives in
SURFACES = [
    ('auth.js', 3),        # login screen + setup wizard (form and done states)
    ('dashboard.js', 6),   # 2FA gate, layout picker, console window, sidebar, footer, nag
    ('cloud.js', 2),       # cloud nav + cloud sponsor footer
]


def _read(name):
    return open(SRC + name, encoding='utf-8').read()


def test_the_notice_is_defined_once_and_shared():
    ui = _read('ui.js')

    assert ui.count('function LegalNotice(') == 1
    assert 'id="pegaprox-legal-notice"' in ui


def test_the_notice_says_what_section_7b_requires_it_to_say():
    ui = _read('ui.js')

    assert '© 2025-2026 PegaProx Team' in ui
    assert 'AGPL-3.0' in ui and 'LICENSE' in ui
    assert 'https://pegaprox.com' in ui and 'project-pegaprox' in ui


@pytest.mark.parametrize('name,count', SURFACES)
def test_every_surface_still_renders_it(name, count):
    """A dropped <LegalNotice /> is a silent change — nothing throws, the line just
    stops being there. NOTICE names these surfaces by name."""
    assert _read(name).count('<LegalNotice') == count, \
        f'{name} should mount the notice {count}x'


def test_it_is_legible_rather_than_inherited():
    """body carries no colour of its own — every text colour here comes from a utility
    class — so `inherit` resolves to black and the notice vanished into the dark skins.
    Measured in a browser afterwards: 5.4-10.2 contrast across modern dark, corporate
    dark and corporate light, all above the 4.5 AA threshold."""
    ui = _read('ui.js')

    assert "color: 'var(--color-text, #cbd5e1)'" in ui
    # the links inherit — from the notice, which now has a real colour to give them.
    # A second `inherit` would mean the container went back to borrowing black.
    assert ui.split('function LegalNotice(')[1][:1600].count("color: 'inherit'") == 1


def test_it_wraps_inside_a_224px_sidebar():
    """The tight case. nowrap segments were the first attempt and overflowed it — 315px of
    content in a 223px box. NBSP glues each separator to the word before it, the normal
    space after lets the line break there."""
    ui = _read('ui.js')

    assert '\\u00A0· ' in ui
    assert "whiteSpace: 'nowrap'" not in ui.split('function LegalNotice(')[1][:1400]


def test_the_console_window_leaves_room_for_it():
    """ConsoleModal is a position:fixed overlay — without the inset it covers the strip
    and the notice is rendered but off-screen, which is not 'displayed'."""
    modals = _read('node_modals.js')
    dash = _read('dashboard.js')

    assert 'bottom: LEGAL_STRIP_H' in modals
    assert 'calc(100vh - ${LEGAL_STRIP_H}px)' in modals
    assert 'height: LEGAL_STRIP_H' in dash


def test_the_about_panel_carries_the_full_notice():
    """§0 wants the copyright, the absence of warranty, the right to convey, and where to
    read the license; §13 wants the source offer. The short line links here for them."""
    about = _read('settings_modal.js')

    for phrase in ('© 2025-2026 PegaProx Team',
                   'WITHOUT ANY WARRANTY',
                   'redistribute it and/or modify',
                   'GNU Affero General Public License, version 3',
                   'section 13 of the license',
                   '/blob/main/NOTICE'):
        assert phrase in about, phrase


def test_notice_file_and_interface_agree():
    """NOTICE claims specific things are displayed. If it names a surface the bundle no
    longer has, the §7(b) term points at nothing."""
    notice = open('NOTICE', encoding='utf-8').read()

    assert 'Appropriate Legal Notices' in notice
    assert 'Settings -> About' in notice
    assert re.search(r'AGPL-3\.0 . Source', notice), 'NOTICE no longer quotes the notice line'
    # the term has to stay narrow — a §7 additional term that reaches past the
    # enumerated cases is a further restriction a recipient may simply strike out
    assert 'this term covers the notices described above' in notice


def test_the_funding_link_rides_along_with_the_notice():
    """The widest honest reach we have: the notice renders on every surface, so putting the
    donation link inside that element puts it on every surface too — login, setup, sidebar,
    console window, cloud nav, footer. That is worth more than a clause could be."""
    ui = _read('ui.js')
    notice = ui[ui.index('function LegalNotice('):]
    notice = notice[:notice.index('function _hexToRgb')]

    assert 'opencollective.com/pegaprox' in notice


def test_the_notice_term_does_not_claim_the_funding_link():
    """The whole point of keeping it narrow. A §7 additional term reaching past the
    enumerated cases is a further restriction a recipient may strike out — and they would
    strike the attribution next to it at the same time. NOTICE names the four attribution
    elements and stops there; the donate link lives in the element without being claimed."""
    notice = open('NOTICE', encoding='utf-8').read()

    assert 'opencollective' not in notice.lower()
    assert 'donat' not in notice.lower()
    assert 'this term covers the notices described above' in notice


def test_the_page_footer_and_the_notice_stay_coupled():
    """The sponsor block cannot be made unremovable — §7 does not reach a funding appeal,
    and a term that tried would be a further restriction a recipient may strike out. What
    IS actionable is that the footer carries an Appropriate Legal Notice, so deleting the
    footer deletes that too. That only holds while the two live in the same element: move
    the notice out and stripping the footer becomes a clean, lawful edit."""
    dash = open(SRC + 'dashboard.js', encoding='utf-8').read()
    start = dash.index('<footer className="border-t border-proxmox-border')
    end = dash.index('</footer>', start)
    footer = dash[start:end]

    assert '<LegalNotice' in footer, 'the notice left the footer — the coupling is gone'
    assert 'opencollective.com/pegaprox' in footer
    assert 'SponsorSlot' in footer


def test_the_footer_is_not_rendered_conditionally():
    """A footer behind a flag is a footer someone can turn off without editing anything."""
    dash = open(SRC + 'dashboard.js', encoding='utf-8').read()
    before = dash[:dash.index('<footer className="border-t border-proxmox-border')]

    assert before.rstrip().endswith('*/}'), \
        'something now gates the footer; it used to render unconditionally'


def test_the_shipped_bundle_carries_it():
    bundle = open('web/index.html', encoding='utf-8').read()

    assert 'pegaprox-legal-notice' in bundle
    assert '2025-2026 PegaProx Team' in bundle
