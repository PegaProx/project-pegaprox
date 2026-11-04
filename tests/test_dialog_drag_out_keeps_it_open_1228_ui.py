"""A drag out of a dialog does not close it (#1228).

Selecting the text of a field and letting go of the mouse on the dimmed backdrop made the
browser click the backdrop (the nearest element holding both ends of the drag), and the
backdrops close their dialog on click, so Add Cluster lost what was typed. constants.js
drops such a click before React sees it. Every other click goes through: on the backdrop
itself, a button pressed on its icon and let go on its label, a checkbox let go on its label.

Runtime tests drive the built bundle in headless Chromium with the fake server of
test_ha_ui.py and skip where Playwright is not installed. LW Nov 2026
"""
import re

import pytest

from test_ha_ui import CLUSTER, _App, _FakeServer, browser  # noqa: F401  (browser is a fixture)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        kw.setdefault('role', 'standalone')
        kw.setdefault('clusters', [CLUSTER])
        app = _App(browser, _FakeServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _add_cluster(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('button[title="Add Cluster"]').first.click()
    else:
        page.locator('button', has_text='Add Cluster').first.click()
        page.get_by_role('button', name=re.compile(r'^Proxmox VE')).first.click()
    form = page.locator('form').filter(has=page.locator('[data-pve-role-toggle]')).first
    form.wait_for(timeout=5000)
    return form


def _drag(page, start, end):
    page.mouse.move(*start)
    page.mouse.down()
    page.mouse.move(*end, steps=8)
    page.mouse.up()
    page.wait_for_timeout(300)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_selecting_text_out_onto_the_backdrop_keeps_add_cluster_open(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    form = _add_cluster(app, layout)
    field = form.locator('input[type="text"], input:not([type])').first
    field.fill('lab-cluster-with-a-long-name')
    box = field.bounding_box()
    # press in the field, select towards its start and leave the dialog over the backdrop
    _drag(page, (box['x'] + box['width'] - 8, box['y'] + box['height'] / 2), (4, 4))
    assert form.is_visible(), 'the drag closed the dialog'
    assert field.input_value() == 'lab-cluster-with-a-long-name'
    # a click that starts and ends on the backdrop still closes it
    page.mouse.click(4, 4)
    form.wait_for(state='detached', timeout=5000)
    assert not app.errors, app.errors


def _probe(page):
    """A button with an icon, a checkbox in a label and a field in a clickable box, each
    counting the clicks that reach it."""
    page.evaluate("""() => {
        const host = document.createElement('div');
        host.id = 'probe';
        host.style.cssText = 'position:fixed;left:40px;top:40px;width:420px;height:200px;background:#fff;z-index:99999';
        host.innerHTML = `
            <button id="pb" style="display:flex;gap:30px;padding:8px"><svg width="20" height="20"><rect width="20" height="20"/></svg><span>Label of the button</span></button>
            <label id="pl" style="display:flex;gap:30px;margin-top:10px"><input id="pc" type="checkbox"><span>Label of the box</span></label>
            <div id="pd" style="margin-top:10px;padding:20px;background:#eee"><input id="pi" value="some text to select" style="width:160px"></div>`;
        document.body.appendChild(host);
        window.__clicks = {button: 0, box: 0};
        document.getElementById('pb').addEventListener('click', () => { window.__clicks.button++; });
        document.getElementById('pd').addEventListener('click', (e) => { if (e.target.id === 'pd') window.__clicks.box++; });
    }""")


def _center(page, selector):
    b = page.locator(selector).bounding_box()
    return (b['x'] + b['width'] / 2, b['y'] + b['height'] / 2)


def test_runtime_other_clicks_go_through(open_app):
    app = open_app()
    page = app.page
    page.wait_for_timeout(500)
    _probe(page)
    # pressed on the icon, let go on the label: the button's click
    _drag(page, _center(page, '#pb svg'), _center(page, '#pb span'))
    assert page.evaluate('window.__clicks.button') == 1
    # pressed on the checkbox, let go on its label: still ticks it
    _drag(page, _center(page, '#pc'), _center(page, '#pl span'))
    assert page.evaluate("document.getElementById('pc').checked") is True
    # pressed in the field, let go on the box around it: that click is the one dropped
    box = page.locator('#pd').bounding_box()
    _drag(page, _center(page, '#pi'), (box['x'] + box['width'] - 6, box['y'] + 6))
    assert page.evaluate('window.__clicks.box') == 0
    # and a click on the box itself reaches it
    page.mouse.click(box['x'] + box['width'] - 6, box['y'] + 6)
    assert page.evaluate('window.__clicks.box') == 1
    assert not app.errors, app.errors
