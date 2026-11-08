# #725 (nvaert1986) — an ACME cert PegaProx issues successfully was never served,
# because the ACME code wrote to the retired <root>/ssl (SSL_DIR_LEGACY) while the
# TLS listener loads from config/ssl (SSL_DIR). The two diverged when the cert store
# moved to config/ on 2026-06-01. The fix unifies all the ACME/renew sites onto
# constants.SSL_DIR, so what's written is what's served.

import os
from pegaprox import constants


def test_acme_writes_where_the_tls_listener_reads():
    # cert.pem / key.pem written into SSL_DIR must land exactly at the paths the
    # listener loads (SSL_CERT_FILE / SSL_KEY_FILE) — same single source of truth.
    assert os.path.join(constants.SSL_DIR, 'cert.pem') == constants.SSL_CERT_FILE
    assert os.path.join(constants.SSL_DIR, 'key.pem') == constants.SSL_KEY_FILE


def test_ssl_dir_is_config_ssl_not_the_retired_legacy_dir():
    assert constants.SSL_DIR == os.path.join(constants.CONFIG_DIR, 'ssl')
    assert constants.SSL_DIR != constants.SSL_DIR_LEGACY   # the June-2026 move


def test_no_retired_ssl_heuristic_left_in_acme_paths():
    # Regression guard: the exact divergence was a duplicated
    #   if Path('/usr/lib/pegaprox').exists(): ssl_dir = '/var/lib/pegaprox/ssl'
    # heuristic that wrote outside config/ssl. It must not come back in the ACME /
    # renewal code paths. (Read the source rather than import app.py, which has
    # heavy import-time side effects.)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for rel in ('pegaprox/api/settings.py', 'pegaprox/app.py'):
        with open(os.path.join(root, rel), encoding='utf-8') as f:
            src = f.read()
        assert '/var/lib/pegaprox/ssl' not in src, \
            f"{rel} still carries the retired <root>/ssl heuristic (#725)"
