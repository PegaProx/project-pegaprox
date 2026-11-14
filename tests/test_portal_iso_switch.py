"""The Client Portal's ISO mount follows the hoster's allow_iso_mount switch.

The page drew the ISO button on `allow_iso_mount`, but the config route never sent it, so the
button never showed. The routes behind it did not ask the switch either: a hoster who listed
ISOs (allowed_isos, iso_storage) with the switch off still had them mounted through the API.
And the drive was taken as given and written as a key of the guest's config, so any key
(scsi0, net0, args) could be set to "<iso>,media=cdrom". MK Nov 2026
"""
import ast
import os
import re
from types import SimpleNamespace
from unittest import mock

import pytest

import plugins.client_portal as portal

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ISO = 'local:iso/debian.iso'
LISTED = {'allowed_isos': [ISO], 'iso_storage': 'local'}


def _page_settings():
    html = open(os.path.join(ROOT, 'plugins', 'client_portal', 'portal.html'), encoding='utf-8').read()
    return set(re.findall(r'\bc\.([a-z_]+)', html)) | set(re.findall(r'\bS\.cfg\.([a-z_]+)', html))


def _sent_settings():
    src = open(os.path.join(ROOT, 'plugins', 'client_portal', '__init__.py'), encoding='utf-8').read()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == '_get_portal_config')
    ret = next(n for n in ast.walk(fn) if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict))
    return {k.value for k in ret.value.keys}


def test_the_page_gets_every_setting_it_draws_on():
    missing = _page_settings() - _sent_settings()
    assert not missing, missing


@pytest.mark.parametrize('cfg,shown', [({'allow_iso_mount': True}, True), ({'allow_iso_mount': False}, False), ({}, False)])
def test_the_switch_reaches_the_page(monkeypatch, cfg, shown):
    monkeypatch.setattr(portal, '_load_config', lambda: dict(cfg))
    from flask import Flask
    with Flask(__name__).test_request_context():
        assert portal._get_portal_config()['allow_iso_mount'] is shown


@pytest.fixture
def pve(monkeypatch):
    """A connected cluster c1 with VM 100 on n1; _api_post records what would reach PVE."""
    mgr = SimpleNamespace(is_connected=True, host='192.0.2.10', config=SimpleNamespace(name='c1'),
                          get_vm_resources=lambda: [{'vmid': 100, 'node': 'n1', 'type': 'qemu'}],
                          get_node_status=lambda: {'n1': {'status': 'online'}},
                          get_iso_list=lambda node, storage: [{'volid': ISO, 'size': 1}],
                          _api_post=mock.Mock(return_value=SimpleNamespace(status_code=200, text='')))
    monkeypatch.setitem(portal.cluster_managers, 'c1', mgr)
    monkeypatch.setattr(portal, 'user_can_access_vm', lambda *a, **kw: True)
    monkeypatch.setattr('pegaprox.utils.auth.build_authz_user', lambda username, session: {'username': username, 'role': 'user'})
    monkeypatch.setattr('pegaprox.utils.audit.log_audit', lambda *a, **kw: None)
    return mgr


def _call(handler, body=None):
    from flask import Flask, request
    with Flask(__name__).test_request_context(json=body or {}):
        request.session = {'user': 'alice'}
        res = handler()
    return res if isinstance(res, tuple) else (res, 200)


ROUTES = {
    'list': (lambda: portal._list_allowed_isos(), None),
    'mount': (lambda: portal._mount_iso(), {'cluster_id': 'c1', 'vmid': 100, 'iso': ISO}),
    'unmount': (lambda: portal._unmount_iso(), {'cluster_id': 'c1', 'vmid': 100}),
}


@pytest.mark.parametrize('route', sorted(ROUTES))
@pytest.mark.parametrize('switch', [False, None])
def test_with_the_switch_off_no_iso_route_answers(pve, monkeypatch, route, switch):
    cfg = dict(LISTED) if switch is None else dict(LISTED, allow_iso_mount=switch)
    monkeypatch.setattr(portal, '_load_config', lambda: cfg)
    handler, body = ROUTES[route]
    res, status = _call(handler, body)
    assert status == 403 and 'not enabled' in res['error'], (route, res)
    assert not pve._api_post.called


def test_with_the_switch_on_an_allowed_iso_goes_into_the_cdrom(pve, monkeypatch):
    monkeypatch.setattr(portal, '_load_config', lambda: dict(LISTED, allow_iso_mount=True))
    res, status = _call(*ROUTES['list'])
    assert status == 200 and [i['volid'] for i in res['isos']] == [ISO]
    res, status = _call(*ROUTES['mount'])
    assert status == 200 and res.get('success'), res
    assert pve._api_post.call_args.kwargs['data'] == {'ide2': f'{ISO},media=cdrom'}
    res, status = _call(*ROUTES['unmount'])
    assert status == 200 and pve._api_post.call_args.kwargs['data'] == {'ide2': 'none,media=cdrom'}


@pytest.mark.parametrize('route', ['mount', 'unmount'])
@pytest.mark.parametrize('drive', ['scsi0', 'net0', 'args', 'ide4', 'sata6', 'ide2;x', '', 7])
def test_a_drive_that_is_no_cdrom_slot_is_refused(pve, monkeypatch, route, drive):
    monkeypatch.setattr(portal, '_load_config', lambda: dict(LISTED, allow_iso_mount=True))
    handler, body = ROUTES[route]
    res, status = _call(handler, dict(body, drive=drive))
    assert status == 400 and 'CD-ROM' in res['error'], (drive, res)
    assert not pve._api_post.called


@pytest.mark.parametrize('drive', ['ide0', 'ide3', 'sata0', 'sata5'])
def test_every_cdrom_slot_is_taken(pve, monkeypatch, drive):
    monkeypatch.setattr(portal, '_load_config', lambda: dict(LISTED, allow_iso_mount=True))
    res, status = _call(ROUTES['mount'][0], dict(ROUTES['mount'][1], drive=drive))
    assert status == 200, res
    assert list(pve._api_post.call_args.kwargs['data']) == [drive]
