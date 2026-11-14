"""Cluster display names are literal text in the copied update report (#1192)."""
import pytest

from test_ha_ui import browser  # noqa: F401
from test_update_list_copy_ui_1192 import (  # noqa: F401 - ui is a fixture
    CLUSTER, WATCH_COPY, _copied, _copy_button, _rows, _section, _wait_listed, _wait_toast, ui,
)


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
@pytest.mark.parametrize('name', ['finance-$&', 'finance-$$', "finance-$'", 'finance-$`'])
def test_runtime_cluster_names_are_copied_literally(ui, layout, name):
    other = dict(CLUSTER, id='cluster_other', name='Other', display_name='Other')
    app = ui(layout=layout, clusters=[other, dict(CLUSTER, name=name, display_name=name)])
    page = app.page
    button = _copy_button(app, layout, name)
    if layout == 'cloud':
        assert page.locator('.cloud-cluster-select').input_value() == CLUSTER['id']
    _wait_listed(app)
    page.evaluate(WATCH_COPY)
    button.click()
    _wait_toast(app, 'Update list copied to the clipboard')
    (text,) = _copied(app)
    assert text.splitlines()[0] == f'Pending updates - {name}'
    assert _rows(_section(text, 'pve1 - ')) == [
        ['Package', 'Current version', 'New', 'Type'],
        ['pve-manager', '8.2.4', '8.2.7', 'Update'],
        ['proxmox-kernel-6.8', '6.8.12-2', '6.8.12-4', 'Kernel'],
    ]
    assert _rows(_section(text, 'pbs-main - ')) == [
        ['Package', 'Version'], ['proxmox-backup-server', '3.2.8-1'],
    ]
    assert not app.errors, app.errors
