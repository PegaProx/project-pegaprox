"""The login check of the ESXi wizard shows no answer that was about another guest or login.

"Check login" asks the server whether the Windows login works in the guest, which takes a few
seconds. Picking another guest or typing in the login fields meanwhile cleared the result, and
the answer that came after it was shown anyway: "the login works" for a guest or a password
nobody had checked. The shipped functions run in node here with an answer held back until the
change.

LW Nov 2026
"""
import json
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf-8');
const piece = (from, endMark) => {
    const a = src.indexOf(from);
    if (a < 0) { console.error('missing ' + from); process.exit(2); }
    return src.slice(a, src.indexOf(endMark, a) + endMark.length);
};
const seqDecl = src.indexOf('const v2pGuestLoginSeq = useRef(0);') >= 0
    ? piece('const v2pGuestLoginSeq = useRef(0);', '\n') + piece('const resetV2pGuestLogin = ', '\n')
    : 'const resetV2pGuestLogin = () => setV2pGuestLogin(null);\n';
const check = piece('const checkV2pGuestLogin = async () => {', '\n            };\n');

async function run(change) {
    const shown = [];
    let answer;
    const held = new Promise(r => { answer = r; });
    const useRef = (v) => ({ current: v });
    const setV2pGuestLogin = (v) => shown.push(v);
    const authFetch = () => held;
    const API_URL = '', selectedVMware = { id: 'v1' }, vmwareSelectedVm = 'vm-7';
    const vmwareMigrateForm = { guest_user: 'Administrator', guest_password: 'pw' };
    const fns = eval('(() => {' + seqDecl + check + 'return { checkV2pGuestLogin, resetV2pGuestLogin }; })()');
    const pending = fns.checkV2pGuestLogin();
    if (change) fns.resetV2pGuestLogin();   // another guest picked, or the login edited
    answer({ ok: true, json: async () => ({ ok: true, user: 'Administrator' }) });
    await pending;
    return shown[shown.length - 1];
}

(async () => {
    console.log(JSON.stringify({ changed: await run(true), kept: await run(false) }));
})();
"""


def test_an_answer_after_the_guest_or_login_changed_is_not_shown(tmp_path):
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped wizard functions')
    harness = tmp_path / 'guest_login.js'
    harness.write_text(_HARNESS, encoding='utf-8')
    p = subprocess.run(['node', str(harness), os.path.join(REPO, 'web/src/dashboard.js')],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    got = json.loads(p.stdout)
    assert got['changed'] is None, got
    assert got['kept'] == {'ok': True, 'user': 'Administrator'}, got


def test_every_way_that_clears_the_result_ends_a_running_check():
    with open(os.path.join(REPO, 'web/src/dashboard.js'), encoding='utf-8') as fh:
        src = fh.read()
    assert 'setV2pGuestLogin(null)' not in src.replace(
        'const resetV2pGuestLogin = () => { v2pGuestLoginSeq.current++; setV2pGuestLogin(null); };', '')
