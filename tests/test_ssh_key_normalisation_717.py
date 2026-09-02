# #717 — a configured SSH key that PegaProx could not load looked exactly like a node
# refusing it. OpenSSH will not read a private key file that lacks a trailing newline, or
# one with CRLF endings: it prints `Load key "...": invalid format`, then has no identity
# to offer, so the node answers `Permission denied (publickey).` and PegaProx told the
# operator to add an SSH key they had already added. Reporter's sshd journal confirmed it:
# `Connection closed by authenticating user root ... [preauth]` with no `Failed publickey`
# line at all — the key never reached the wire.
#
# Invariants: (1) whatever we write for `ssh -i` is loadable, (2) an absent key is refused
# up front rather than written as an empty file, (3) the load failure survives into the log
# instead of being trimmed away, and (4) the hint names the key, not the node.

from pegaprox.core.manager import (
    _normalise_private_key,
    _ssh_stderr_excerpt,
    _ssh_auth_hint,
)


BODY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"


# ---- (1) the file we write is loadable ----

def test_missing_trailing_newline_is_added():
    # the reporter's case: pasted from an editor selection, no final newline
    assert _normalise_private_key(BODY).endswith('-----END OPENSSH PRIVATE KEY-----\n')


def test_crlf_is_converted_to_lf():
    out = _normalise_private_key(BODY.replace('\n', '\r\n'))

    assert '\r' not in out
    assert out.endswith('\n')


def test_bare_cr_is_converted_to_lf():
    out = _normalise_private_key(BODY.replace('\n', '\r'))

    assert '\r' not in out
    assert out == BODY + '\n'


def test_already_correct_key_is_unchanged():
    good = BODY + '\n'

    assert _normalise_private_key(good) == good


def test_surrounding_whitespace_does_not_survive():
    assert _normalise_private_key('\n\n  ' + BODY + '  \n\n') == BODY + '\n'


# ---- (2) an absent key is refused, not written as an empty file ----

def test_empty_and_blank_keys_return_empty():
    for missing in ('', '   ', '\n', '\r\n', None):
        assert _normalise_private_key(missing) == ''


# ---- (3) the load failure survives into the log ----

LOAD_FAIL_STDERR = (
    'Load key "/tmp/tmp1234.key": invalid format\n'
    'root@192.0.2.18: Permission denied (publickey).\n'
)


def test_excerpt_keeps_the_load_failure():
    out = _ssh_stderr_excerpt(LOAD_FAIL_STDERR)

    # both halves matter: what failed, and what the node then said
    assert 'invalid format' in out
    assert 'Permission denied' in out


def test_excerpt_still_returns_last_line_when_nothing_failed_to_load():
    stderr = '***  banner  ***\nroot@192.0.2.18: Permission denied (publickey).\n'

    assert _ssh_stderr_excerpt(stderr) == 'root@192.0.2.18: Permission denied (publickey).'


def test_excerpt_respects_the_cap():
    assert len(_ssh_stderr_excerpt(LOAD_FAIL_STDERR, max_chars=20)) == 20


# ---- (4) the hint names the key, not the node ----

def test_hint_for_unloadable_key_points_at_the_key():
    hint = _ssh_auth_hint(LOAD_FAIL_STDERR)

    assert 'could not be loaded' in hint
    # the #717 misfire: telling someone who HAS configured a key to add one
    assert 'add an authorized SSH key' not in hint


def test_hint_for_a_genuine_key_only_node_is_unchanged():
    hint = _ssh_auth_hint('root@192.0.2.18: Permission denied (publickey).')

    assert 'add an authorized SSH key' in hint


def test_hint_for_changed_host_key_is_unchanged():
    hint = _ssh_auth_hint('Host key verification failed.')

    assert 're-pin' in hint or 'host key changed' in hint
