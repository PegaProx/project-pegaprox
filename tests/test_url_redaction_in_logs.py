"""Eight findings said the same thing from different files: the URL we log is the credential.

Three different shapes, all of them real here:

  * `https://user:pass@host/` keeps the password in netloc, and urlsplit().netloc
    INCLUDES userinfo - which is how the SIEM TLS-downgrade warning came to print one.
  * A Slack or Teams webhook URL has no userinfo at all. The secret IS the path, so
    logging the URL on a delivery failure hands it over whole.
  * A pre-signed download URL carries it in the query.

Logs are read by operators, shipped to SIEM and pasted into support bundles, so this is
a disclosure with a long tail. utils/webhooks.py already had a redactor - and guarded
exactly one of its four log lines with it.

Aikido ai_pentest 700487653 / 700488201-family (siem, storage, templates, webhooks). MK
"""
import inspect
import re

import pytest

from pegaprox.utils.sanitization import redact_url


# --- the redactor ------------------------------------------------------------------

def test_userinfo_goes():
    out = redact_url('https://admin:hunter2@siem.example/ingest')

    assert 'hunter2' not in out and 'admin' not in out
    assert 'siem.example' in out


def test_a_secret_path_goes_but_the_service_stays():
    """You still need to know WHICH webhook failed."""
    out = redact_url('https://hooks.slack.com/services/T01/B02/SUPERSECRET')

    assert 'SUPERSECRET' not in out and 'B02' not in out
    assert 'hooks.slack.com' in out and 'services' in out


def test_a_signed_query_parameter_goes():
    out = redact_url('https://cdn.example/img.qcow2?X-Amz-Signature=abcdef&v=2')

    assert 'abcdef' not in out
    assert 'v=2' in out, 'harmless parameters are worth keeping'


@pytest.mark.parametrize('name', ['token', 'api_key', 'password', 'sig', 'auth',
                                  'access_token', 'client_secret'])
def test_every_secret_ish_parameter_name_goes(name):
    out = redact_url(f'https://x.example/a?{name}=VALUE')

    assert 'VALUE' not in out


def test_a_url_inside_an_exception_string_is_caught():
    """Callers pass whole exception texts through here - requests repeats the URL."""
    out = redact_url('ConnectionError: refused to https://u:p@host:8443/a/b/c - retrying')

    assert 'u:p' not in out and '/b/c' not in out
    assert 'retrying' in out and 'host:8443' in out


def test_text_that_is_not_a_url_is_untouched():
    assert redact_url('nothing to see here') == 'nothing to see here'


def test_empty_input_is_returned_as_is():
    assert redact_url('') == ''
    assert redact_url(None) is None


def test_a_plain_url_is_still_readable():
    """Over-redacting makes the log useless and people turn it off."""
    out = redact_url('https://pbs.example/admin/datastore')

    assert 'pbs.example' in out and 'admin' in out


# --- the call sites ----------------------------------------------------------------

def _body(fn):
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return inspect.getsource(fn)


def test_the_failover_webhook_logs_a_redacted_url():
    import pegaprox.background.site_recovery as sr

    src = inspect.getsource(sr)
    i = src.index('[SR] Webhook failed')
    line = src[src.rindex('\n', 0, i):src.index('\n', i)]
    assert 'redact_url(' in line, line


def test_the_siem_warning_drops_userinfo():
    """netloc includes it; this printed user:pass@host."""
    import pegaprox.api.siem as siem

    body = _body(siem._warn_tls_downgrade)
    assert "rpartition('@')" in body or 'redact_url' in body


def test_the_siem_warning_actually_drops_it():
    import pegaprox.api.siem as siem
    from urllib.parse import urlsplit

    netloc = urlsplit('https://admin:hunter2@siem.example/x').netloc
    host = netloc.rpartition('@')[2] or ''

    assert host == 'siem.example'
    assert 'hunter2' not in host


def test_every_webhook_log_line_is_redacted_now():
    """The redactor was there and guarded one line out of four."""
    import pegaprox.utils.webhooks as wh

    src = inspect.getsource(wh)
    offenders = []
    for n, line in enumerate(src.splitlines(), 1):
        if re.search(r'logging\.(info|warning|error|debug)\(', line):
            if ('detail' in line or '{e}' in line or 'url' in line.lower()):
                if '_redact_webhook_url(' not in line and 'redact_url(' not in line:
                    offenders.append(line.strip())

    assert offenders == [], offenders


def test_the_webhook_redactor_also_runs_the_general_one():
    """Its own patterns only know the shapes we had already seen."""
    import pegaprox.utils.webhooks as wh

    out = wh._redact_webhook_url('failed: https://user:pw@example.com/a/b')
    assert 'user:pw' not in out


def test_the_storage_download_logs_a_redacted_url():
    import pegaprox.api.storage as st

    src = inspect.getsource(st)
    i = src.index('Error downloading from URL')
    line = src[src.rindex('\n', 0, i):src.index('\n', i)]
    assert 'redact_url(' in line, line


def test_every_module_that_calls_the_redactor_can_actually_reach_it():
    """The full suite caught this one: the import landed inside a trailing comment in
    storage.py, so the name was used and never defined - a NameError on the error path
    of a download, which is exactly where nobody looks until a customer hits it."""
    import importlib
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    users = []
    for path in list((root / 'pegaprox').rglob('*.py')) + list((root / 'plugins').rglob('*.py')):
        text = path.read_text(encoding='utf-8')
        calls = [l for l in text.splitlines()
                 if 'redact_url(' in l and not l.strip().startswith('#')
                 and 'def redact_url' not in l and 'import' not in l]
        if calls:
            users.append(str(path.relative_to(root)))

    assert users, 'nothing calls it, which means this test is measuring nothing'
    missing = []
    for rel in users:
        mod = rel[:-3].replace('/', '.')
        m = importlib.import_module(mod)
        if not hasattr(m, 'redact_url') and not hasattr(m, '_redact_webhook_url'):
            missing.append(rel)

    assert missing == [], missing
