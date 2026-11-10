"""#1226 - docs/SECURITY.md section 5 (LoadCredentialEncrypted) on an encrypted database.

Since the Debian package depends on python3-sqlcipher3, its databases are encrypted with
/etc/pegaprox/secret.key from the first start, like those of deploy.sh. The setup used to
generate a NEW key for the credential: the database then did not open ('unknown-key'), the
check of step 6 still passed because the [KEYSTORE] line is logged before the database is
opened, and step 7 shredded /etc/pegaprox/secret.key, the one key that opened it, or
config/.pegaprox.key, which is also the Fernet key of old field values. The hint deploy.sh
gives for a key still in config/ moved that file away as well.

NS Nov 2026
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _setup():
    doc = (ROOT / 'docs' / 'SECURITY.md').read_text(encoding='utf-8')
    sec = doc[doc.index('## 5. systemd LoadCredentialEncrypted'):]
    return sec[sec.index('### Setup'):sec.index('### Recovering from a TPM2 reset')]


def _steps():
    parts = re.split(r'^(\d)\. ', _setup(), flags=re.M)
    return {int(n): body for n, body in zip(parts[1::2], parts[2::2])}


def _commands(text):
    """The shell lines of the code blocks, continuations joined."""
    out = []
    for block in re.findall(r'```(?:bash)?\n(.*?)```', text, flags=re.S):
        for line in block.replace('\\\n', ' ').splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                out.append(' '.join(line.split()))
    return out


def test_the_credential_is_made_from_the_key_in_use_never_a_new_one():
    setup = _setup()
    assert 'token_bytes' not in setup and 'urandom' not in setup and 'openssl rand' not in setup
    wraps = [c for c in _commands(_steps()[2]) if 'systemd-creds encrypt' in c]
    assert len(wraps) == 2
    for cmd in wraps:
        source, _, wrap = cmd.partition(' | ')
        assert '--print-key' in source and wrap.startswith('sudo systemd-creds encrypt --name=db-key ')
        # stdin, so the key never lands in a file on the way
        assert ' - /etc/pegaprox/secret.key.cred' in wrap
        # as the service user, in the directory the service runs in: config/ is relative to it
        assert source == ("sudo -u pegaprox sh -c 'cd /var/lib/pegaprox && "
                          "/usr/bin/pegaprox/pegaprox-wrapper --print-key'")
    # the wrapper there is the package's, and runs the entry point with the arguments
    install = [ln.split() for ln in (ROOT / 'debian' / 'install').read_text().splitlines()]
    assert ['debian/pegaprox-wrapper', 'usr/bin/pegaprox'] in install
    wrapper = (ROOT / 'debian' / 'pegaprox-wrapper').read_text()
    assert 'exec /usr/bin/python3 /usr/lib/pegaprox/pegaprox_multi_cluster.py "$@"' in wrapper


def test_the_check_is_that_pegaprox_started_not_only_the_keystore_line():
    step6 = _steps()[6]
    cmds = _commands(step6)
    assert any('journalctl' in c and r'\[FATAL\]' in c for c in cmds)
    assert 'systemctl is-active pegaprox' in cmds
    assert 'before the database is opened' in step6


def test_a_key_file_is_removed_only_after_the_check_and_never_config_pegaprox_key():
    steps = _steps()
    assert sorted(steps) == list(range(1, 8))
    removing = [n for n, body in steps.items()
                if any(re.search(r'\b(shred|rm|mv)\b', c) for c in _commands(body))]
    assert removing == [7]
    assert _commands(steps[7]) == ['sudo shred -u /etc/pegaprox/secret.key']
    assert 'step 6 passed' in steps[7] and 'copy of step 3' in steps[7]
    doc = (ROOT / 'docs' / 'SECURITY.md').read_text(encoding='utf-8')
    for cmd in _commands(doc):
        if re.search(r'\b(shred|rm|mv)\b', cmd):
            assert '.pegaprox.key' not in cmd, cmd


def test_deploy_sh_tells_to_copy_the_legacy_key_not_to_move_it():
    """The hint deploy.sh prints for an install that still has its key in config/."""
    hint = [ln for ln in (ROOT / 'deploy.sh').read_text(encoding='utf-8').splitlines()
            if 'Migrate with' in ln]
    assert len(hint) == 1
    assert 'sudo cp \\"$LEGACY_KEY\\" \\"$SYS_KEY\\"' in hint[0]
    assert not re.search(r'\b(mv|rm|shred)\b', hint[0])
