# #717 — a compliance 502 where every node failed SSH was, underneath, a bare
# 'Permission denied (publickey).' from nodes running `PermitRootLogin without-password`
# (root password auth refused). _ssh_auth_hint turns that opaque line into the actual fix.

from pegaprox.core.manager import _ssh_auth_hint


def test_publickey_only_means_add_a_key():
    # the reporter's exact stderr: server offered ONLY publickey, refused the password
    h = _ssh_auth_hint("root@192.168.100.15: Permission denied (publickey).")
    assert h and 'key auth only' in h and 'without-password' in h


def test_both_methods_offered_but_wrong_password():
    # '(publickey,password)' => password IS an accepted method, the credential was wrong.
    # Only when a password went out (sshpass), see test_ssh_hint_says_what_was_sent_1156
    h = _ssh_auth_hint("root@host: Permission denied (publickey,password).", tried='password')
    assert h and 'password rejected' in h.lower()
    assert 'without-password' not in h


def test_host_key_changed():
    h = _ssh_auth_hint("Host key verification failed.")
    assert h and 'host key' in h.lower()


def test_bare_permission_denied_defaults_to_key_advice():
    h = _ssh_auth_hint("Permission denied")
    assert h and 'key' in h.lower()


def test_non_auth_failures_return_none():
    assert _ssh_auth_hint("ssh: connect to host x port 22: Connection refused") is None
    assert _ssh_auth_hint("ssh: Could not resolve hostname x") is None
    assert _ssh_auth_hint("") is None
    assert _ssh_auth_hint(None) is None


def test_multiline_banner_before_the_error_still_classifies():
    # OpenSSH dumps the AUP banner before the real error; classify on the whole blob
    blob = ("*" * 70 + "\nAuthorized use only. Activity is monitored.\n" +
            "root@node: Permission denied (publickey).")
    h = _ssh_auth_hint(blob)
    assert h and 'key auth only' in h
