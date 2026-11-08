"""What the workflows run is fixed by commit and digest, not by a tag that can move.

apt-repo.yml was the one workflow still on version tags (checkout@v4,
upload-pages-artifact@v3, deploy-pages@v4), in the job that imports the APT signing key
(#978). The Docker workflows pinned their actions, but setup-qemu-action and
setup-buildx-action each pull an image of their own (tonistiigi/binfmt, moby/buildkit) by a
moving tag, in jobs that may push to GHCR (#982). Both are pinned now: every action to a
commit with the tag it was resolved from as a comment, every image those two pull to a digest.
NS Oct 2026
"""
import glob
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = sorted(glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml')))
USES = re.compile(r'^\s*(?:-\s+)?uses:\s*(\S+)(.*)$', re.M)
DIGEST = r'@sha256:[0-9a-f]{64}'


def _read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def _steps(text, action):
    """The text of every step that uses `action`, up to the next step."""
    out = []
    for m in re.finditer(rf'uses:\s*{re.escape(action)}@', text):
        rest = text[m.end():]
        nxt = re.search(r'\n {4,8}- ', rest)
        out.append(rest[:nxt.start()] if nxt else rest)
    return out


def test_there_are_workflows_to_check():
    names = {os.path.basename(p) for p in WORKFLOWS}
    assert {'apt-repo.yml', 'docker.yml', 'docker-testing.yml', 'release-images.yml'} <= names


@pytest.mark.parametrize('path', WORKFLOWS, ids=os.path.basename)
def test_every_action_is_pinned_to_a_commit_with_its_tag(path):
    text = _read(path)
    for ref, rest in USES.findall(text):
        if ref.startswith('./'):
            continue
        action, _, pin = ref.partition('@')
        assert re.fullmatch(r'[0-9a-f]{40}', pin), f'{os.path.basename(path)}: {ref} is not pinned to a commit'
        assert re.match(r'\s+#\s*v\d+\.\d+\.\d+\s*$', rest), \
            f'{os.path.basename(path)}: {action} has no "# vX.Y.Z" comment'


def test_the_apt_job_with_the_signing_key_runs_no_tag():
    text = _read(os.path.join(ROOT, '.github', 'workflows', 'apt-repo.yml'))
    refs = [ref for ref, _ in USES.findall(text)]
    assert {r.split('@')[0] for r in refs} == {'actions/checkout', 'actions/upload-pages-artifact',
                                               'actions/deploy-pages', 'actions/upload-artifact',
                                               'actions/download-artifact', 'actions/attest'}
    assert not [r for r in refs if re.search(r'@v\d', r)], refs
    # NS Oct 2026 - the repo went live with a job per privilege. Pages and its OIDC token
    # get a job of their own, so the job that holds the key runs nothing but these three;
    # the signed tree reaches the deploy job as a plain artifact
    publish = text[text.index('\n  publish:\n'):text.index('\n  deploy:\n')]
    assert 'secrets.APT_GPG_PRIVATE_KEY' in publish
    in_publish = {ref.split('@')[0] for ref, _ in USES.findall(publish)}
    assert in_publish == {'actions/checkout', 'actions/download-artifact', 'actions/upload-artifact'}


# A composite action runs the actions it names itself, and a commit pin on the outer one does
# not pin those. Every composite we use is listed with the commits whose action.yml was read
# and found to pin its inner actions by commit too. upload-pages-artifact v3.0.1 (56afc609)
# called actions/upload-artifact@v4 by tag in the job with pages and id-token write; v4.0.0
# pins it to ea165f8d (v4.6.2). A bump has to be read again and added here.
CHECKED_COMPOSITES = {
    'actions/upload-pages-artifact': {'7b1f4a764d45c48632c6b24a0339c27f5614fb0b'},
}


@pytest.mark.parametrize('path', WORKFLOWS, ids=os.path.basename)
def test_composite_actions_are_on_a_commit_whose_inner_pins_were_checked(path):
    for ref, _ in USES.findall(_read(path)):
        action, _, pin = ref.partition('@')
        if action in CHECKED_COMPOSITES:
            assert pin in CHECKED_COMPOSITES[action], \
                f'{os.path.basename(path)}: {ref} - read its action.yml for unpinned uses: first'


@pytest.mark.parametrize('path', WORKFLOWS, ids=os.path.basename)
def test_the_images_of_the_setup_actions_are_pinned_by_digest(path):
    text = _read(path)
    for step in _steps(text, 'docker/setup-qemu-action'):
        assert re.search(rf'\n\s+image:\s*\S+:qemu-v[\d.]+{DIGEST}\s*\n', step + '\n'), step
    for step in _steps(text, 'docker/setup-buildx-action'):
        assert re.search(rf'\n\s+driver-opts:\s*image=\S+:v[\d.]+{DIGEST}\s*\n', step + '\n'), step


def test_the_setup_actions_are_where_the_digests_are_needed():
    """docker.yml and docker-testing.yml use both, the release images the binfmt one."""
    counts = {}
    for path in WORKFLOWS:
        text = _read(path)
        counts[os.path.basename(path)] = (len(_steps(text, 'docker/setup-qemu-action')),
                                          len(_steps(text, 'docker/setup-buildx-action')))
    assert counts['docker.yml'] == (1, 1)
    assert counts['docker-testing.yml'] == (1, 1)
    assert counts['release-images.yml'][0] == 1


def test_one_digest_per_image_across_the_workflows():
    """The same image at the same digest everywhere, so a bump cannot leave one behind."""
    seen = {}
    for path in WORKFLOWS:
        for name, digest in re.findall(r'(tonistiigi/binfmt|moby/buildkit):\S+@(sha256:[0-9a-f]{64})', _read(path)):
            seen.setdefault(name, set()).add(digest)
    assert set(seen) == {'tonistiigi/binfmt', 'moby/buildkit'}
    assert all(len(d) == 1 for d in seen.values()), seen


def test_no_long_dash_in_the_workflow_lines_of_this_change():
    for path in WORKFLOWS:
        for line in _read(path).splitlines():
            if '(#978)' in line or '(#982)' in line or '@sha256:' in line:
                assert '\N{EM DASH}' not in line, line
