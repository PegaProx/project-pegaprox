"""Two findings from the daily scan, both in code written the day before.

1. Every anchored validator in sanitization.py ended in `$`. In Python `$` also matches
   immediately BEFORE a trailing newline, so `re.match(r'^[a-z]+$', 'abc\\n')` is a match.
   Six validators therefore accepted a value with a newline glued to the end, two of which
   gate values that reach a root shell on a PVE node UNQUOTED, and one of which gates a
   path segment handed to the PVE API.

2. The auth-action rate limiter grew a bucket cap, and the eviction picked
   `next(iter(dict))` - on an insertion-ordered dict that is the FIRST bucket created,
   i.e. one of the literal ones the login paths have counted in since boot. Evicting a
   window resets it, so the defence against a caller-chosen budget would have cleared the
   limit protecting password change and TOTP verification.

MK
"""
import pytest

from pegaprox.utils import sanitization as SAN


# The validator, a value it must accept, and what the value gates.
_VALIDATORS = [
    (SAN.validate_sdn_id, 'zone1', 'a PVE SDN path segment'),
    (SAN.validate_snapshot_name, 'snap1', 'a PVE snapshot path segment'),
    (SAN.validate_content_filename, 'debian.iso', 'a filename in an SSH shell command'),
    (SAN.validate_esxi_path_component, 'datastore1', 'an UNQUOTED ESXi name in a root shell'),
    (SAN.validate_storage_name, 'local-lvm', 'a storage id in pvesm/qm'),
    (SAN.validate_hostname, 'pve1.example', 'a hostname'),
]


@pytest.mark.parametrize('fn,good,what', _VALIDATORS,
                         ids=[f.__name__ for f, _g, _w in _VALIDATORS])
def test_a_trailing_newline_is_not_a_valid_value(fn, good, what):
    """The property, not the pattern: no validator may accept `good + '\\n'`.

    Deliberately asserts on behaviour rather than on the regex text. Checking that the
    source says `\\Z` would pass against any string containing those two characters and
    would say nothing about what the function actually accepts.
    """
    assert fn(good) is True, f'{fn.__name__} stopped accepting a legitimate value'
    assert fn(good + '\n') is False, (
        f'{fn.__name__} accepts a trailing newline; this value becomes {what}')


@pytest.mark.parametrize('fn,good,_what', _VALIDATORS,
                         ids=[f.__name__ for f, _g, _w in _VALIDATORS])
def test_an_embedded_newline_was_never_accepted_either(fn, good, _what):
    """The neighbouring case, so a fix for the trailing one cannot reopen this."""
    assert fn(good + '\nrm -rf /') is False
    assert fn('\n' + good) is False


def test_email_too():
    assert SAN.validate_email('a@b.de') is True
    assert SAN.validate_email('a@b.de\n') is False


def test_the_budget_cap_refuses_rather_than_evicting_an_established_window():
    """A caller-chosen budget must not be able to reset somebody else's rate limit.

    Measures the property that matters: after the map is full, the window that the real
    login path has been counting in still remembers its count. The old code evicted that
    window, which handed an attacker a reset of the very limiter guarding password change.
    """
    from pegaprox.utils import ssh as SSH

    SSH._auth_action_windows.clear()
    try:
        # The established bucket: spend its whole budget, the way a real brute-force would.
        assert SSH.check_auth_action_rate_limit('victim', max_attempts=2, window=300) is True
        assert SSH.check_auth_action_rate_limit('victim', max_attempts=2, window=300) is True
        assert SSH.check_auth_action_rate_limit('victim', max_attempts=2, window=300) is False

        # Now flood with distinct budgets, as a request-derived value would.
        for i in range(SSH._AUTH_ACTION_MAX_BUCKETS + 6):
            SSH.check_auth_action_rate_limit('attacker', max_attempts=1, window=100 + i)

        assert len(SSH._auth_action_windows) <= SSH._AUTH_ACTION_MAX_BUCKETS, \
            'the registry grew past its cap'
        assert SSH.check_auth_action_rate_limit('victim', max_attempts=2, window=300) is False, \
            'the established window was evicted - the rate limit got reset by the flood'
    finally:
        SSH._auth_action_windows.clear()
