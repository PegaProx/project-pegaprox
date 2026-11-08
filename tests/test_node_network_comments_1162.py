"""Node interface comments in the built UI, using fixture API responses (#1162)."""

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, NODE_PATH, NODE_READS, VM, _App, _FakeServer, browser

expect = pytest.importorskip('playwright.sync_api').expect


NETWORK = NODE_PATH + '/network'
COMMENT = 'Management <uplink> & storage; ' + 'rack 12 / migration fabric ' * 20
INTERFACES = [
    {'iface': 'vmbr0', 'type': 'bridge', 'cidr': '192.0.2.10/24', 'comments': COMMENT},
    {'iface': 'bond0', 'type': 'bond', 'comments': 'Storage fabric'},
    {'iface': 'eno1', 'type': 'eth', 'comments': ''},
    {'iface': 'vmbr0.316', 'type': 'vlan'},
]


@pytest.fixture
def network_app(browser):
    apps = []

    def open_app(layout='corporate', role='active', interfaces=None):
        extra = dict(NODE_READS)
        extra[('GET', NETWORK)] = (200, INTERFACES if interfaces is None else interfaces)
        for method, path in [('PUT', NETWORK + '/vmbr0'), ('POST', NETWORK),
                             ('PUT', NETWORK), ('DELETE', NETWORK)]:
            extra[(method, path)] = (200, {'message': 'ok'})
        app = _App(browser, _FakeServer(role=role, layout=layout, clusters=[CLUSTER],
                                       resources=[VM], metrics=NODE_METRICS, extra=extra))
        apps.append(app)
        page = app.page
        if layout == 'modern':
            page.get_by_text('Testi').first.click()
            page.locator('button[title="Node Configuration"]').first.click()
            page.get_by_role('button', name='Network', exact=True).last.click()
        else:
            page.locator('.corp-tree-item', has_text='Testi').first.click()
            page.locator('.corp-tree-child', has_text='pve1').first.click()
            page.locator('.corp-tab-strip').last.get_by_text('Configure').click()
        return app

    yield open_app
    for app in apps:
        app.ctx.close()


@pytest.mark.parametrize('role', ['active', 'standby'])
def test_corporate_comments_are_visible_truncated_and_readable_on_hover(network_app, role):
    app = network_app(role=role)
    table = app.page.locator('.corp-datagrid').filter(has=app.page.get_by_text('vmbr0', exact=True))
    expect(table.get_by_role('columnheader', name='Comment', exact=True)).to_be_visible()
    for iface in INTERFACES:
        row = table.get_by_role('row').filter(has=app.page.get_by_text(iface['iface'], exact=True))
        cell = row.get_by_role('cell').nth(5)
        comment = iface.get('comments', '')
        assert cell.text_content() == comment
        assert cell.get_attribute('title') == comment
        assert row.get_by_title('Edit', exact=True).is_disabled() == (role == 'standby')
    long_cell = table.locator('td[title]').filter(has_text=COMMENT)
    long_cell.hover()
    assert long_cell.evaluate("""el => {
        const css = getComputedStyle(el);
        return css.whiteSpace === 'nowrap' && css.textOverflow === 'ellipsis'
            && css.overflow === 'hidden' && el.scrollWidth > el.clientWidth;
    }""")
    assert not [c for c in app.server.calls if c[0] != 'GET' and c[1].startswith(NODE_PATH)]
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


def test_empty_network_table_spans_the_comment_column(network_app):
    app = network_app(interfaces=[])
    empty = app.page.get_by_role('cell', name='No network interfaces', exact=True)
    expect(empty).to_be_visible()
    assert empty.get_attribute('colspan') == '7'


def _field(page, label):
    return page.locator('label').filter(has_text=label).locator('..').locator('input[type="text"]')


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_comment_survives_address_edit_apply_revert_and_can_be_changed(network_app, layout):
    app = network_app(layout=layout)
    page = app.page
    edit = page.get_by_title('Edit', exact=True).first
    edit.click()
    expect(_field(page, 'Comment')).to_have_value(COMMENT)
    _field(page, 'IPv4/CIDR').fill('192.0.2.20/24')
    with page.expect_response(lambda r: r.request.method == 'GET' and r.url.endswith(NETWORK)):
        with page.expect_request(lambda r: r.method == 'PUT' and r.url.endswith(NETWORK + '/vmbr0')) as request:
            page.get_by_role('button', name='Save', exact=True).click()
    assert request.value.post_data_json['comments'] == COMMENT
    assert request.value.post_data_json['cidr'] == '192.0.2.20/24'
    if layout == 'modern':
        # The existing Modern refresh keeps the editor open after saving.
        page.get_by_role('button', name='Cancel', exact=True).click()

    for name, method in [('Apply Configuration' if layout == 'modern' else 'Apply', 'PUT'),
                         ('Revert', 'DELETE')]:
        page.once('dialog', lambda dialog: dialog.accept())
        with page.expect_request(lambda r: r.method == method and r.url.endswith(NETWORK)):
            page.get_by_role('button', name=name, exact=True).click()
        # The refreshed fixture config still reaches the editor, without a comment rewrite.
        edit.click()
        expect(_field(page, 'Comment')).to_have_value(COMMENT)
        page.get_by_role('button', name='Cancel', exact=True).click()

    for comment in ['Management uplink', '']:
        edit.click()
        _field(page, 'Comment').fill(comment)
        with page.expect_response(lambda r: r.request.method == 'GET' and r.url.endswith(NETWORK)):
            with page.expect_request(lambda r: r.method == 'PUT' and r.url.endswith(NETWORK + '/vmbr0')) as request:
                page.get_by_role('button', name='Save', exact=True).click()
        assert request.value.post_data_json['comments'] == comment
        if layout == 'modern':
            page.get_by_role('button', name='Cancel', exact=True).click()

    page.get_by_role('button', name='Create', exact=True).first.click()
    page.get_by_role('button', name='Linux Bridge', exact=True).click()
    _field(page, 'Name').fill('vmbr9')
    _field(page, 'Comment').fill('New storage bridge')
    with page.expect_request(lambda r: r.method == 'POST' and r.url.endswith(NETWORK)) as request:
        page.get_by_role('button', name='Create', exact=True).last.click()
    assert request.value.post_data_json['iface'] == 'vmbr9'
    assert request.value.post_data_json['comments'] == 'New storage bridge'
    assert not [e for e in app.errors if 'pageerror' in e], app.errors
