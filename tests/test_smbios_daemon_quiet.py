"""The SMBIOS auto-configurator a node runs (SMBIOS_SCRIPT_TEMPLATE) stays quiet in its
steady state: the re-create check asks needs_smbios_update() for every configured VM on
every cycle, so that check must not log (#969). Its lines go out at once under systemd.

MK Oct 2026
"""
import re

from pegaprox.api.nodes import SMBIOS_SCRIPT_TEMPLATE


def _daemon():
    """The script as the deploy route renders it, loaded without running main()."""
    script = SMBIOS_SCRIPT_TEMPLATE.format(manufacturer='Proxmox', product='PegaProx', version='v1',
                                           family='ProxmoxVE')
    ns = {'__name__': 'smbios_daemon'}
    exec(compile(script, 'smbios_daemon.py', 'exec'), ns)
    return ns


def test_a_configured_vm_is_checked_without_a_log_line():
    ns = _daemon()
    logged = []
    ns['log_message'] = logged.append
    ns['get_current_smbios'] = lambda vmid: 'uuid=1,manufacturer=UHJveG1veA==,product=UGVnYVByb3g=,base64=1'
    for _ in range(3):
        assert ns['needs_smbios_update'](101) is False
    assert logged == []
    # a VM without one still needs it
    ns['get_current_smbios'] = lambda vmid: ''
    assert ns['needs_smbios_update'](102) is True


def test_its_lines_are_flushed_at_once():
    body = SMBIOS_SCRIPT_TEMPLATE[SMBIOS_SCRIPT_TEMPLATE.index('def log_message'):]
    body = body[:body.index('\ndef ', 1)]
    assert re.search(r'print\(log_entry, flush=True\)', body)
