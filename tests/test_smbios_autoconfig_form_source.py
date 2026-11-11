"""The SMBIOS Auto-Configurator form in the cluster settings edits the saved SMBIOS settings
of the cluster (GET / PUT /api/clusters/<id>/smbios-autoconfig).

Its inputs were bound to selectedCluster.smbios_manufacturer and friends and saved through
updateConfig, a PATCH of the cluster config. Those are no cluster fields: the PATCH answered
200 with nothing updated, the form said "Settings saved" and the next refresh showed the
defaults again. The form never read the stored settings.

Source checks, they run without a browser. LW Nov 2026
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, 'web', 'src')
FIELDS = ('manufacturer', 'product', 'version', 'family')


def _read(name):
    with open(os.path.join(WEB, name), encoding='utf-8') as fh:
        return fh.read()


def _section():
    src = _read('security.js')
    start = src.index('function SmbiosAutoConfigSection(')
    end = re.compile(r'\n        (function |// )').search(src, start)
    return src[start:end.start() if end else len(src)]


def _fn(body, name, why=''):
    """the body of `const name = async (...) => { ... };` inside the section"""
    m = re.search(rf'const {name} = async \([^)]*\) => \{{(.*?)\n            \}};', body, re.S)
    assert m, why or f'{name} not found'
    return m.group(1)


def test_no_cluster_field_carries_the_smbios_settings():
    for name in sorted(os.listdir(WEB)):
        if name.endswith('.js'):
            src = _read(name)
            assert not re.search(r"updateConfig\(\s*['\"]smbios_", src), name
            assert not re.search(r'\.smbios_(manufacturer|product|version|family|enabled)\b', src), name
    mount = re.search(r'<SmbiosAutoConfigSection\b(.*?)/>', _read('dashboard.js'), re.S)
    assert mount and 'updateConfig' not in mount.group(1)
    assert 'updateConfig' not in _section()


def test_the_form_shows_the_saved_settings_of_its_cluster():
    sec = _section()
    load = _fn(sec, 'loadSmbiosSettings', 'the form never reads the saved settings')
    assert re.search(r'authFetch\(`\$\{API_URL\}/clusters/\$\{cid\}/smbios-autoconfig`\)', load)
    # a late answer for the cluster before does not land in the form
    assert re.search(r'if \(smbiosCluster\.current !== cid\) return;', load)
    assert re.search(r'setSmbiosForm\(data\);\s*setSmbiosSaved\(data\);', load)
    effect = re.search(r'useEffect\(\(\) => \{(.*?)\}, \[clusterId\]\);', sec, re.S)
    assert effect and 'loadSmbiosSettings()' in effect.group(1) and 'setSmbiosForm(null)' in effect.group(1)
    for field in FIELDS:
        assert f'value={{smbiosForm?.{field} ?? \'\'}}' in sec, field
        assert f'setSmbiosForm(f => ({{ ...f, {field}: v }}))' in sec, field


def test_a_save_sends_every_field_and_says_saved_only_when_the_server_took_it():
    sec = _section()
    save = _fn(sec, 'saveSmbiosSettings', 'the form has no save that looks at the answer')
    assert "method: 'PUT'" in save
    body = re.search(r'body: JSON\.stringify\(\{(.*?)\}\)', save, re.S).group(1)
    for key in ('enabled',) + FIELDS:
        assert re.search(rf'\b{key}: ', body), key
    # the error of the server, and no success before res.ok
    fail = save.index('if (!res.ok)')
    assert re.search(r'if \(!res\.ok\) \{\s*addToast\(result\.error \|\|', save)
    assert "'success'" not in save[:fail]
    assert re.search(r'return false;\s*\}', save[fail:])
    form = _fn(sec, 'saveSmbiosForm')
    assert re.search(r"if \(await saveSmbiosSettings\(smbiosForm\)\) addToast\(t\('settingsSaved'\)", form)
    assert re.search(r'onClick=\{saveSmbiosForm\}', sec)


def test_deploy_saves_the_form_first_and_stops_when_that_fails():
    deploy = _fn(_section(), 'deployToAll')
    saved = re.search(r'if \(!\(await saveSmbiosSettings\(smbiosForm\)\)\) return;', deploy)
    assert saved, 'deploy does not wait for the save'
    assert saved.start() < deploy.index('/smbios-autoconfig/deploy-all')
