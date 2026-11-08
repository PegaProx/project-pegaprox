"""The portal's power buttons ask the same entry of allowed_actions as the server (#1239).

_vm_power maps each action to a permission (perm_map) and refuses it with "Action not
allowed by hoster" unless the hoster lists that permission in allowed_actions. The Reboot
button was drawn on vm.start while the server asks vm.restart, so with the shipped config it
was offered and always refused. Every button that calls pAction or pConsole is held against
the entry the server checks for what it calls. MK Nov 2026
"""
import ast
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTAL = os.path.join(ROOT, 'plugins', 'client_portal')


def _perm_map():
    src = open(os.path.join(PORTAL, '__init__.py'), encoding='utf-8').read()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == 'perm_map' for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('perm_map not found in _vm_power')


def _buttons():
    html = open(os.path.join(PORTAL, 'portal.html'), encoding='utf-8').read()
    found = []
    for m in re.finditer(r"al\.includes\('([a-z.]+)'\)\)acts\+=`[^`]*?onclick=\"(pAction|pConsole)\(([^)]*)\)", html):
        gate, fn, args = m.groups()
        action = 'console' if fn == 'pConsole' else re.findall(r"'([a-z]+)'", args)[0]
        found.append((gate, action))
    return found


def test_every_power_button_asks_what_the_server_asks():
    perm = _perm_map()
    buttons = _buttons()
    assert {a for _, a in buttons} >= {'start', 'stop', 'shutdown', 'reboot', 'console'}, buttons
    for gate, action in buttons:
        expected = 'vm.console' if action == 'console' else perm[action]
        assert gate == expected, (action, gate, expected)


def test_the_shipped_config_offers_no_action_the_server_refuses():
    import json
    cfg = json.load(open(os.path.join(PORTAL, 'config.json'), encoding='utf-8'))
    offered = {a for gate, a in _buttons() if gate in cfg['allowed_actions']}
    perm = _perm_map()
    for action in offered - {'console'}:
        assert perm[action] in cfg['allowed_actions'], action
