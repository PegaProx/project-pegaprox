"""A handler that logs a request body whole logs the credential in it.

pegaprox/api/storage.py built `pve_data` as a verbatim copy of the create-storage
request and wrote it at DEBUG. For a pbs target that body REQUIRES `password`
(see required_fields in the same function); cifs and the iscsi variants carry one
too. Running with --debug is ordinary here, so the backup server's password went
into the application log in the clear.

Nothing in the logging path caught it. sanitize_log_message() is a control-
character sanitiser and nothing more — measured, it passes `password=x`,
`'password': 'x'` and `Authorization: Bearer ...` straight through — and
redact_url() only looks at URLs. The one place that had solved this,
core/manager.py, solved it with a dict comprehension for the single key it knew
about (`target-endpoint`, a cleartext PVEAPIToken from a Jul 2026 pentest
finding). Correct, and it reached one line, which is why storage.py went on
leaking.

redact_secrets() is that idea behind the shared hint list, and both sites now use
it. test_the_migration_token_is_still_redacted is the reason this file matters
more than the fix: `target-endpoint` matches NONE of redact_url's hints, so
routing the old comprehension through the shared rule re-opened the pentest
finding until _SECRET_KEY_EXTRA_HINTS was added. Generalising a narrow fix can
lose the case the narrow fix existed for. Aikido ai_pentest 700489555. MK
"""
import pytest

from pegaprox.utils.sanitization import redact_secrets, redact_url


def test_a_storage_create_payload_loses_its_password():
    payload = {'storage': 'pbs01', 'type': 'pbsvm', 'server': 'pbs.example.com',
               'username': 'backup@pbs', 'password': 'S3cret-PBS-pw', 'datastore': 'store1'}
    out = redact_secrets(payload)

    assert 'S3cret-PBS-pw' not in str(out)
    assert out['password'] == '***REDACTED***'


def test_the_migration_token_is_still_redacted():
    """The regression guard. `target-endpoint` carries a full-rights, non-expiring
    PVEAPIToken and matches none of the query-parameter hints — the shared rule
    needs its own mapping-key list or this silently comes back."""
    out = redact_secrets({'target': 'pve2', 'bwlimit': 100,
                          'target-endpoint': 'apitoken=PVEAPIToken=root@pam!m=SECRET,host=10.0.0.1'})

    assert 'SECRET' not in str(out), f'the migration token came back: {out}'
    assert out['target-endpoint'] == '***REDACTED***'


def test_everything_worth_debugging_survives():
    """The mirror. A redactor that eats the diagnostics is a redactor nobody keeps."""
    out = redact_secrets({'storage': 'pbs01', 'type': 'pbsvm', 'server': 'pbs.example.com',
                          'username': 'backup@pbs', 'password': 'x', 'datastore': 'store1'})

    assert out['storage'] == 'pbs01'
    assert out['type'] == 'pbsvm'
    assert out['server'] == 'pbs.example.com'
    assert out['datastore'] == 'store1'


def test_an_unset_value_does_not_start_reading_as_set():
    out = redact_secrets({'password': '', 'api_token_secret': None, 'server': 'x'})
    assert out['password'] == ''
    assert out['api_token_secret'] is None


def test_nested_configs_are_walked():
    out = redact_secrets({'name': 'c1', 'connection': {'user': 'root@pam', 'password': 'p'}})
    assert out['connection']['password'] == '***REDACTED***'
    assert out['connection']['user'] == 'root@pam'


def test_a_matching_key_holding_a_whole_config_is_redacted_whole():
    """A key that matches wins over walking into it. `credentials: {...}` should
    not be opened up and published one leaf at a time just because the leaf names
    happen not to match — the outer name already said what it holds."""
    out = redact_secrets({'name': 'c1', 'credentials': {'bearer': 'xyz', 'realm': 'pam'}})
    assert out['credentials'] == '***REDACTED***'
    assert 'xyz' not in str(out)


def test_a_non_mapping_is_returned_untouched():
    assert redact_secrets('just a string') == 'just a string'
    assert redact_secrets(None) is None


def test_redact_url_behaviour_is_unchanged():
    """The extra hints are mapping-only on purpose: redact_url has its own tests
    and its own callers, and widening it here would be a change nobody asked for."""
    out = redact_url('https://h/api?endpoint=https://elsewhere&token=abc')
    assert 'abc' not in out
    assert 'elsewhere' in out


def test_the_storage_route_calls_it():
    """Pins the wiring, because the helper existing proves nothing on its own —
    that was the whole shape of this finding."""
    import inspect
    import pegaprox.api.storage as storage
    src = inspect.getsource(storage.create_storage)
    assert 'redact_secrets(pve_data)' in src, 'the create-storage log is raw again'
