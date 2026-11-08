"""Every hop of a template image's redirect chain passes the check the first URL passes.

The deploy checked the image URL against the SSRF guard (private LAN yes, the node's own
loopback and metadata no) and then ran a plain `wget` on the node, which follows up to 20
redirects to any host on its own. A public URL that answered 302 to http://127.0.0.1:...
got the reply of a service on the node's loopback imported as a disk the requester can
boot and read. The deploy now asks the node for each hop itself (HEAD, or the first byte
of a GET where HEAD is refused), checks each one like the first URL, stops after 10, and
downloads the end of the chain with redirects off. The legit chains (a distro redirector
to a mirror, a release asset to its signed storage URL) still download, and a login in
the URL only goes to the origin it was written for.
MK Oct 2026
"""
import shlex
import socket
from urllib.parse import urljoin

import pytest

import pegaprox.api.templates_lib as tpl
import pegaprox.utils.url_security as us
from tests.conftest import make_fake_manager

DNS = {
    'images.example.org': '203.0.113.7',
    'mirror.example.net': '198.51.100.9',
    'cdn.example.net': '198.51.100.10',
    'github.example.com': '203.0.113.20',
    'assets.example.net': '198.51.100.11',
    'rebind.example.net': '127.0.0.1',
}


def _wget_s(url, status, loc, spider):
    """What `wget -S` prints for one answer (LC_ALL=C)."""
    lines = (['Spider mode enabled. Check if remote file exists.'] if spider else []) + [
        f'--2026-10-19 08:00:00--  {url}',
        'Connecting to 203.0.113.7:443... connected.',
        'HTTP request sent, awaiting response... ',
        f'  HTTP/1.1 {status} Whatever',
        '  Server: nginx',
    ]
    if loc:
        lines += [f'  Location: {loc}', f'Location: {loc} [following]', '0 redirections exceeded.']
    return '\n'.join(lines) + '\n'


class _Chan:
    def __init__(self, rc):
        self.rc = rc

    def recv_exit_status(self):
        return self.rc


class _Out:
    def __init__(self, text='', rc=0):
        self.text, self.channel = text, _Chan(rc)


class _Node:
    """A PVE node and the web as it sees it: web[url] is (status, Location) for any method,
    or {'HEAD': ..., 'GET': ...}. A URL not listed is a file that is there. wget is played
    as it behaves: it follows redirects unless told --max-redirect=0."""

    def __init__(self, web):
        self.web, self.cmds, self.fetched = web, [], []

    def answer(self, url, method):
        a = self.web.get(url, (200, None))
        return a[method] if isinstance(a, dict) else a

    def exec_command(self, cmd, **kw):
        self.cmds.append(cmd)
        toks = shlex.split(cmd)
        if 'wget' not in toks:
            return None, _Out(), _Out()
        spider = '--spider' in toks
        if '2>&1' in toks:
            # a check of one hop: its headers are the answer
            url = toks[-2]
            status, loc = self.answer(url, 'HEAD' if spider else 'GET')
            return None, _Out(_wget_s(url, status, loc, spider), 0 if status < 300 else 8), _Out()
        url, follow = toks[-1], '--max-redirect=0' not in toks
        for _ in range(21):
            self.fetched.append(url)
            status, loc = self.answer(url, 'GET')
            if 300 <= status < 400 and loc:
                if not follow:
                    return None, _Out('', 8), _Out('0 redirections exceeded.', 8)
                url = urljoin(url, loc)
                continue
            rc = 0 if status < 400 else 8
            return None, _Out('', rc), _Out('' if rc == 0 else f'ERROR {status}', rc)
        return None, _Out('', 8), _Out('20 redirections exceeded.', 8)

    def close(self):
        pass


@pytest.fixture
def deploy(monkeypatch):
    def fake_dns(host, port, *a, **kw):
        if host not in DNS:
            raise socket.gaierror('unknown host')
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (DNS[host], 0))]
    monkeypatch.setattr(us.socket, 'getaddrinfo', fake_dns)
    monkeypatch.setattr(tpl, '_read_capped', lambda f: f.text)

    def go(url, web):
        node = _Node(web)
        mgr = make_fake_manager('cl_redir')
        mgr._ssh_connect.return_value = node
        mgr._get_node_ip.return_value = '10.0.0.5'
        monkeypatch.setitem(tpl.cluster_managers, 'cl_redir', mgr)
        monkeypatch.setattr(tpl, '_lookup_template', lambda tid: {
            'id': 'custom-x', 'name': 'x', 'image_url': url, 'cores': 2, 'memory': 2048})
        logged = []
        monkeypatch.setattr(tpl, '_update_dep', lambda dep_id, **kw: logged.append(kw))
        tpl._run_deploy('d1', 'cl_redir', 'pve1', 'custom-x', 'local-lvm', 9301, 'tpl-x')
        return node, logged
    return go


def _download(node):
    return next(c for c in node.cmds if c.startswith('wget'))


START = 'https://images.example.org/base.qcow2'


@pytest.mark.parametrize('target', [
    'http://127.0.0.1:8080/secret',
    'http://[::1]:8080/secret',
    'http://169.254.169.254/latest/meta-data/',
    'http://rebind.example.net/secret',
    'file:///etc/shadow',
])
def test_a_redirect_the_first_url_could_not_be_is_refused(deploy, target):
    node, logged = deploy(START, {START: (302, target)})

    assert logged[-1]['status'] == 'failed'
    assert 'rejected by SSRF guard' in logged[-1]['error']
    assert node.fetched == [], f'the node downloaded {node.fetched}'
    assert not any(c.startswith('qm ') for c in node.cmds)


def test_a_redirect_only_a_get_shows_is_checked_too(deploy):
    """Servers that refuse HEAD are asked with the first byte of a GET."""
    node, logged = deploy(START, {START: {'HEAD': (405, None), 'GET': (302, 'http://127.0.0.1:8006/')}})

    assert logged[-1]['status'] == 'failed'
    assert 'rejected by SSRF guard' in logged[-1]['error']
    assert node.fetched == []
    assert any("Range: bytes=0-0" in c for c in node.cmds)


def test_the_download_itself_follows_no_redirect(deploy):
    """A server that tells the check 200 and the download 302 makes the download fail."""
    node, logged = deploy(START, {START: {'HEAD': (200, None), 'GET': (302, 'http://127.0.0.1:8080/secret')}})

    assert '--max-redirect=0' in shlex.split(_download(node))
    assert node.fetched == [START]
    assert logged[-1]['status'] == 'failed'


def test_a_mirror_redirect_still_downloads_from_the_mirror(deploy):
    mirror = 'https://mirror.example.net/debian/base.qcow2'
    node, logged = deploy(START, {START: (302, mirror), mirror: (200, None)})

    assert logged[-1]['status'] == 'completed', logged[-1]
    toks = shlex.split(_download(node))
    assert toks[:3] == ['wget', '-q', '--max-redirect=0'] and toks[-1] == mirror
    # the file keeps the name of the URL the template has
    assert toks[-2].endswith('/base.qcow2')
    assert node.fetched == [mirror]


def test_a_release_asset_with_a_signed_relative_chain_still_downloads(deploy):
    url = 'https://github.example.com/o/r/releases/download/v1/disk.img'
    signed = 'https://assets.example.net/blob/abc?sv=2025&sig=x%2By&se=2026-10-19T08:05Z'
    web = {url: (302, '/o/r/releases/assets/1'),
           'https://github.example.com/o/r/releases/assets/1': (302, signed),
           signed: {'HEAD': (403, None), 'GET': (206, None)}}
    node, logged = deploy(url, web)

    assert logged[-1]['status'] == 'completed', logged[-1]
    assert shlex.split(_download(node))[-1] == signed
    assert node.fetched == [signed]


def test_ten_redirects_are_followed_and_the_eleventh_is_not(deploy):
    chain = [f'https://images.example.org/r{i}' for i in range(12)]
    web = {chain[i]: (302, chain[i + 1]) for i in range(11)}

    node, logged = deploy(chain[0], dict(web, **{chain[10]: (200, None)}))
    assert logged[-1]['status'] == 'completed'
    assert shlex.split(_download(node))[-1] == chain[10]

    node, logged = deploy(chain[0], web)
    assert logged[-1]['status'] == 'failed'
    assert 'more than 10' in logged[-1]['error']
    assert node.fetched == []


LOGIN = 'mirroruser:S3cret-77'
HOME = f'https://{LOGIN}@10.0.0.20'


def test_a_login_goes_to_its_own_origin_only(deploy):
    web = {f'{HOME}/images/a.qcow2': (302, '/images/b.qcow2'),
           f'{HOME}/images/b.qcow2': (302, 'http://10.0.0.20/images/c.qcow2'),
           'http://10.0.0.20/images/c.qcow2': (302, 'https://cdn.example.net/c.qcow2'),
           'https://cdn.example.net/c.qcow2': (200, None)}
    node, logged = deploy(f'{HOME}/images/a.qcow2', web)

    assert logged[-1]['status'] == 'completed', logged[-1]
    with_login = [c for c in node.cmds if 'S3cret-77' in c]
    # the relative hop on the same origin kept it, the downgrade to http and the CDN did not
    assert len(with_login) == 2
    assert all(shlex.split(c)[-2].startswith(HOME + '/') for c in with_login)
    assert shlex.split(_download(node))[-1] == 'https://cdn.example.net/c.qcow2'
    assert 'S3cret-77' not in repr(logged)


def test_a_chain_that_ends_on_its_own_origin_keeps_the_login_out_of_the_log(deploy):
    web = {f'{HOME}/images/a.qcow2': (302, f'{HOME}/images/b.qcow2'.replace(LOGIN + '@', ''))}
    node, logged = deploy(f'{HOME}/images/a.qcow2', web)

    assert logged[-1]['status'] == 'completed', logged[-1]
    assert shlex.split(_download(node))[-1] == f'{HOME}/images/b.qcow2'
    text = repr(logged)
    assert 'S3cret-77' not in text, text
    assert 'https://****@10.0.0.20/images/b.qcow2' in text


def test_a_url_without_redirects_downloads_as_before(deploy):
    node, logged = deploy(START, {})

    assert logged[-1]['status'] == 'completed'
    assert shlex.split(_download(node))[-1] == START
    assert node.fetched == [START]


def test_the_answer_is_read_from_the_last_response_the_server_sent():
    out = ('Spider mode enabled. Check if remote file exists.\n'
           '--2026-10-19 08:33:21--  http://u:*password*@127.0.0.1:37321/auth\n'
           'HTTP request sent, awaiting response... \n'
           '  HTTP/1.0 401 Unauthorized\n'
           '  WWW-Authenticate: Basic realm="x"\n'
           'Authentication selected: Basic realm="x"\n'
           'HTTP request sent, awaiting response... \n'
           '  HTTP/1.0 302 Found\n'
           '  location: /next.img\n'
           'Location: /elsewhere.img [following]\n'
           '0 redirections exceeded.\n')
    assert tpl._wget_answer(out) == (302, '/next.img')
    assert tpl._wget_answer('  HTTP/1.1 200 OK\n  Content-Length: 5\n') == (200, None)
    assert tpl._wget_answer('') == (None, None)
    assert tpl._wget_answer('wget: unable to resolve host address\n') == (None, None)
