"""A first boot that does not report is a warning of the run, on every path.

Seen on a lab run of Windows Server 2025 with the in-guest preparation and the two-stage boot:
the first boot task's report never came, the run logged "did not report within 20 min, going
on" and ended COMPLETED without a single warning, while the guest had no network at all.
"""
import json

from pegaprox.core import v2p_twostage as ts, v2p_winprep as wp

from test_v2p_two_stage_boot import lab, _task  # noqa: F401 (lab: a fixture)

FB = {'version': 1, 'run': 't1', 'platform': 'kvm', 'state': 'applied', 'boots': 1, 'tools': 'removed',
      'devices': 'removed', 'adapters': [{'n': 1, 'ip': '10.0.0.5', 'index': '12', 'by': 'mac', 'applied': True}]}
FB_PATH = r'C:\ProgramData\KVMMigration\firstboot.json'


def _up(lb):
    lb.pve.running = True
    lb.pve.boots = ['order=sata0']


def test_the_two_stage_boot_warns_when_the_report_never_comes(lab):
    lb = lab()
    _up(lb)
    t = _task()
    ts._firstboot(lb.pve, t, 60)
    assert any('the first boot task did not report within 1 min' in w and 'static IPv4' in w
               and 'migrate.log' in w for w in t.warnings), t.warnings


def test_a_report_that_comes_is_no_warning(lab):
    lb = lab(files={FB_PATH: json.dumps(FB)})
    _up(lb)
    t = _task()
    ts._firstboot(lb.pve, t, 60)
    assert t.warnings == []
    assert any('static IPv4 10.0.0.5 is on interface 12' in ln for ln in t.log_lines)


def test_a_start_without_the_two_stage_boot_warns_when_the_agent_stays_silent(lab):
    lb = lab(agent_boots=())
    _up(lb)
    t = _task()
    wp.first_boot_report(lb.pve, t, agent_wait=60, wait=60)
    assert any('the guest agent did not answer within 1 min' in w for w in t.warnings), t.warnings


def test_a_start_without_the_two_stage_boot_warns_when_the_report_never_comes(lab):
    lb = lab()
    _up(lb)
    t = _task()
    wp.first_boot_report(lb.pve, t, agent_wait=60, wait=60)
    assert any('the first boot task did not report within 1 min' in w for w in t.warnings), t.warnings
