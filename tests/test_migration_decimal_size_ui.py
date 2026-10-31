"""Fractional PVE disk sizes contribute to the cross-cluster migration warning."""

import pytest

from test_ha_ui import browser  # noqa: F401
from test_migration_preflight_ui import xc_app, _cross_dialog, SRC_CFG  # noqa: F401


@pytest.mark.parametrize('size, expected', [('0.5T', '512'), ('100.5G', '101'), ('102912M', '101')])
def test_a_fractional_disk_still_triggers_the_large_live_migration_warning(xc_app, size, expected):
    """The >100 GiB warning includes fractional terabytes and gigabytes."""
    config = dict(SRC_CFG, scsi0=f'local-lvm:vm-100-disk-0,size={size}')
    app = xc_app(src_cfg=config)
    page = _cross_dialog(app)
    warning = page.get_by_text('Large Disk Detected', exact=True)
    warning.wait_for(timeout=5000)
    assert f'({expected} GB)' in warning.locator('..').inner_text()
    assert not app.errors, app.errors


def test_small_disks_do_not_trigger_the_large_disk_warning(xc_app):
    """A fractional disk below the warning threshold stays a normal live move."""
    app = xc_app(src_cfg=dict(SRC_CFG, scsi0='local-lvm:vm-100-disk-0,size=99.5G'))
    page = _cross_dialog(app)
    assert page.get_by_text('Large Disk Detected', exact=True).count() == 0
    assert not app.errors, app.errors
