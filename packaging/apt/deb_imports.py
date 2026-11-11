#!/usr/bin/env python3
"""Which Debian package brings each third-party module PegaProx imports.

Two readers: tests/test_debian_depends_cover_imports.py checks every import in
pegaprox/**, pegaprox_multi_cluster.py and the bundled plugins against this map and
against debian/control, and the smoke test of the apt-repo workflow runs this file on
a fresh trixie install of the .deb, where every module of DEPENDS has to import.

A module that PegaProx can run without goes into OPTIONAL with the reason, never into
DEPENDS with a comment.

NS Oct 2026
"""
import importlib
import sys

# import name -> Debian package (trixie, or built by packaging/apt/build-python-debs.py)
DEPENDS = {
    'flask': 'python3-flask',
    'flask_cors': 'python3-flask-cors',
    'flask_sock': 'python3-flask-sock',
    'flask_compress': 'python3-flask-compress',
    'werkzeug': 'python3-werkzeug',
    'simple_websocket': 'python3-simple-websocket',
    'wsproto': 'python3-wsproto',
    'gevent': 'python3-gevent',
    'greenlet': 'python3-greenlet',
    'geventwebsocket': 'python3-gevent-websocket',
    'websockets': 'python3-websockets',
    'websocket': 'python3-websocket',
    'requests': 'python3-requests',
    'requests_toolbelt': 'python3-requests-toolbelt',
    'urllib3': 'python3-urllib3',
    'cryptography': 'python3-cryptography',
    'OpenSSL': 'python3-openssl',
    'argon2': 'python3-argon2',
    'jwt': 'python3-jwt',
    'pyotp': 'python3-pyotp',
    'qrcode': 'python3-qrcode',
    'PIL': 'python3-pil',
    'ldap3': 'python3-ldap3',
    'paramiko': 'python3-paramiko',
    'dns': 'python3-dnspython',
    'defusedxml': 'python3-defusedxml',
    'pyVmomi': 'python3-pyvmomi',
    'pyVim': 'python3-pyvmomi',
    'XenAPI': 'python3-xenapi',
    # NS Nov 2026 (#1226): built by the repo from the manylinux wheels, amd64 and arm64
    'sqlcipher3': 'python3-sqlcipher3',
}

# import name -> why the package does not depend on it
OPTIONAL = {
    'fido2': 'WebAuthn hardware keys. api/webauthn.py switches the feature off when the '
             'import fails. trixie has python3-fido2 1.2, and with 1.x dict(options) keeps '
             'bytes, so register/begin fails in jsonify; requirements.txt asks for 2.2.1.',
    'apprise': 'Extra senders of the bundled notifications plugin, which loads without it. '
               'Not packaged in trixie.',
    # the codings of the page (pegaprox/utils/index_page.py) besides gzip, the modules
    # flask-compress takes for them; without one the page goes out in the others
    'brotli': 'The br variant of the page, offered only when the module imports.',
    'brotlicffi': 'Taken instead of brotli where it is installed, as flask-compress does.',
    'backports': 'backports.zstd, the zstd variant of the page before Python 3.14.',
    'compression': 'compression.zstd, the zstd variant of the page from Python 3.14 on '
                   '(standard library there).',
}

# NS Nov 2026 - the module the smoke test imports for an OPTIONAL entry where the name says
# too little: backports imports as soon as any backports.* package is installed, and
# compression is there on 3.14 also when the interpreter was built without zstd
PROBE = {
    'backports': 'backports.zstd',
    'compression': 'compression.zstd',
}


def main():
    missing = []
    for mod in sorted(DEPENDS, key=str.lower):
        try:
            importlib.import_module(mod)
            print(f'  ok        {mod:18} ({DEPENDS[mod]})')
        except Exception as e:
            missing.append(mod)
            print(f'  MISSING   {mod:18} ({DEPENDS[mod]}): {type(e).__name__}: {e}')
    print('optional:')
    for mod in sorted(OPTIONAL, key=str.lower):
        name = PROBE.get(mod, mod)
        try:
            m = importlib.import_module(name)
            ver = getattr(m, '__version__', '')
            print(f'  available {name} {ver}'.rstrip())
        except Exception as e:
            print(f'  absent    {name} ({type(e).__name__}) - {OPTIONAL[mod]}')
    if missing:
        print('modules the package depends on do not import: ' + ', '.join(missing))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
