# community-scripts/ProxmoxVE #16745 — the default_umask hardening control (CIS umask 027)
# edits /etc/login.defs + /etc/profile. umask 027 in a login shell propagates to `pct create`
# (template extracted under the caller's umask), so community LXC scripts land /etc at 750 and
# DNS breaks in the container. rollback_node_hardening restores a control from its backup_files
# snapshot, so the control must DECLARE backup_files to be reversible — it previously did not.

from pegaprox.core.manager import PegaProxManager


def _ctrl(cid):
    return PegaProxManager.CIS_CHECKS[cid]


def test_default_umask_is_reversible():
    c = _ctrl('default_umask')
    assert c.get('backup_files'), \
        "default_umask must declare backup_files so it can be rolled back (#16745)"


def test_default_umask_backup_covers_the_files_it_edits():
    c = _ctrl('default_umask')
    bf = set(c['backup_files'])
    assert '/etc/login.defs' in bf and '/etc/profile' in bf
    # a backed-up file that the apply never touches would be a pointless snapshot; and a file the
    # apply edits but doesn't back up can't be restored — both directions must line up here.
    apply = c['apply']
    for f in c['backup_files']:
        assert f in apply, f"backup_files lists {f} but the apply script never edits it"


def test_default_umask_apply_still_sets_027():
    # reversibility must not have weakened the actual CIS hardening
    apply = _ctrl('default_umask')['apply']
    assert 'UMASK           027' in apply
    assert 'umask 027' in apply
