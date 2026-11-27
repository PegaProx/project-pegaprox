"""The Windows login of the in-guest preparation never leaves the SOAP calls (MK Nov 2026).

Per migration, never stored, never logged, never returned: not in the task log, its warnings,
to_dict (which the migration history stores), a node command or what a node command reads from
stdin, the guest's files, the audit. Wiped once the guest was released, on a fallback and at the
end of the run. A sentinel login runs through the whole in-guest flow of test_v2p_guestprep_flow.
"""
import json
import shlex
import urllib.parse

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import v2p_guestprep as gp
from test_v2p_guestprep_flow import lab, Waits, Session, WORK  # noqa: F401 (fixture)

SENTINEL_PW = 'Zq7#Sentinel "pw" & %TEMP% !x'
SENTINEL_USER = 'CORP\\sentinel.admin'


def _all_text(lab):
    t = lab.task
    out = ['\n'.join(t.log_lines), json.dumps(t.to_dict()), json.dumps(t.warnings), str(t.error or ''),
           json.dumps(t.config, default=str)]
    out += lab.node.cmds + [str(v) for v in lab.node.stdin.values()]
    out += [v.decode('latin-1') if isinstance(v, bytes) else str(v) for v in lab.guest.files.values()]
    out += [' '.join(str(x) for x in c) for c in lab.guest.calls]
    return '\n'.join(out)


def _forms(pw):
    return {pw, urllib.parse.quote(pw, safe=''), shlex.quote(pw), json.dumps(pw)[1:-1]}


@pytest.fixture
def sentinel(lab):
    t = lab.task
    t.guest_user, t._guest_password = SENTINEL_USER, SENTINEL_PW
    return lab


def test_the_login_reaches_only_the_session_through_the_whole_flow(sentinel, monkeypatch):
    lab = sentinel
    assert gp.probe(lab.esxi, lab.pve, lab.task) is True
    assert gp.prepare(lab.esxi, lab.pve, lab.task) is True
    monkeypatch.setattr(v2p, '_wait_power_state', Waits(lab.esxi, [True]))
    assert gp.go(lab.esxi, lab.pve, lab.task) == 'off'
    text = _all_text(lab)
    for form in _forms(SENTINEL_PW) | {SENTINEL_USER, 'sentinel.admin'}:
        assert form not in text, form
    # the sessions had it, each closed afterwards
    assert {s.password for s in Session.instances} == {None}
    assert lab.task._guest_password == '' and lab.task.guest_user == ''


@pytest.mark.parametrize('broken', ['login', 'status'])
def test_a_fallback_wipes_the_login_and_names_none_of_it(sentinel, broken):
    lab = sentinel
    from pegaprox.core.esxi_guestops import GuestOpsError
    if broken == 'login':
        lab.guest.fail['validate'] = GuestOpsError('login', 'the guest refused the Windows login')
        gp.probe(lab.esxi, lab.pve, lab.task)
    else:
        gp.probe(lab.esxi, lab.pve, lab.task)
        lab.guest.reads['status.json'] = json.dumps({'run': 't1', 'stage': 'failed', 'error': f'x {SENTINEL_USER}'[:2]})
        gp.prepare(lab.esxi, lab.pve, lab.task)
    assert lab.task._guest_prep['state'] == 'fallback'
    assert lab.task._guest_password == '' and lab.task.guest_user == ''
    text = _all_text(lab)
    for form in _forms(SENTINEL_PW) | {SENTINEL_USER}:
        assert form not in text


def test_the_end_of_the_run_wipes_it_from_the_task_and_its_config():
    cfg = {'esxi_password': 'pw', 'guest_prep': True, 'guest_user': SENTINEL_USER, 'guest_password': SENTINEL_PW}
    t = v2p.V2PMigrationTask('t9', 'vw1', 'vm-1', 'c', 'n', 's', config=cfg)
    assert 'guest_password' not in t.config and 'guest_user' not in t.config
    d = json.dumps(t.to_dict())
    assert SENTINEL_PW not in d and SENTINEL_USER.replace('\\', '\\\\') not in d
    t._scrub_credentials()
    assert t._guest_password == '' and t.guest_user == ''


def test_the_log_masks_every_spelling_of_the_password_and_the_transfer_tickets():
    t = v2p.V2PMigrationTask('t9', 'vw1', 'vm-1', 'c', 'n', 's',
                             config={'esxi_password': 'pw', 'guest_prep': True, 'guest_password': SENTINEL_PW})
    for form in _forms(SENTINEL_PW):
        t.log(f'oops {form} end')
    t.log('PUT https://esx1.lab/guestFile?id=17&token=abcdef0123 HTTP/1.1')
    text = '\n'.join(t.log_lines)
    for form in _forms(SENTINEL_PW):
        assert form not in text
    assert 'token=abcdef0123' not in text and 'guestFile?********' in text
