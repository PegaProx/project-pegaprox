"""Containers from OCI images (api/oci_catalog.py): the routes, the job, and who may.

Proxmox VE is faked at the HTTP layer of the manager (_api_get / _api_post) and answers
the way the API viewer documents the calls - pve-docs/api-viewer/apidoc.js, read for
PVE 9.1/9.2, quoted where each one is faked. A call outside the documented parameters
is refused the way PVE refuses it ("Parameter verification failed."), so a request
this module builds wrong fails here first.

MK Oct 2026
"""
import random
import re
import time

import pytest

import pegaprox.api.oci_catalog as oci
from test_ha_api import ha_env, _standby_of_active, _active_with_standby, _audit  # noqa: F401

BASE = 'https://10.0.0.1:8006/api2/json'
_REAL_SPAWN = oci._spawn
REF = 'docker.io/library/nginx:stable-alpine'
# the readable part and a digest of the exact reference (#1063)
NGINX_ARCHIVE = 'docker.io_library_nginx_stable-alpine_e28e1e3689705bcf'
DEPLOY = '/api/clusters/cluster_1/oci/deploy'

# --- what the API viewer says ----------------------------------------------------------------
#
# POST /nodes/{node}/storage/{storage}/oci-registry-pull - "Pull an OCI image from a registry."
#   reference  "The reference to the OCI image to download."  (pattern below)
#   filename   "Custom destination file name of the OCI image. Caution: This will be
#              normalized!"  optional, minLength 1, maxLength 255
#   returns    string (the UPID of the task)
#   additionalProperties 0
PVE_REFERENCE = (r'^(?:(?:[a-zA-Z\d]|[a-zA-Z\d][a-zA-Z\d-]*[a-zA-Z\d])'
                 r'(?:\.(?:[a-zA-Z\d]|[a-zA-Z\d][a-zA-Z\d-]*[a-zA-Z\d]))*(?::\d+)?/)?[a-z\d]+'
                 r'(?:(?:[._]|__|[-]*)[a-z\d]+)*(?:/[a-z\d]+(?:(?:[._]|__|[-]*)[a-z\d]+)*)*'
                 r':\w[\w.-]{0,127}$')
PULL_PARAMS = {'reference', 'filename'}

# POST /nodes/{node}/lxc - "Create or restore a container."  additionalProperties 0
#   ostemplate  "The OS template or backup file."  maxLength 255
#   env         "The container runtime environment as NUL-separated list. Replaces any
#               lxc.environment.runtime entries in the config."
#   returns     string (the UPID)
LXC_PARAMS = {'arch', 'bwlimit', 'cmode', 'console', 'cores', 'cpulimit', 'cpuunits', 'debug',
              'description', 'dev[n]', 'entrypoint', 'env', 'features', 'force', 'ha-managed',
              'hookscript', 'hostname', 'ignore-unpack-errors', 'lock', 'memory', 'mp[n]',
              'nameserver', 'net[n]', 'onboot', 'ostemplate', 'ostype', 'password', 'pool',
              'protection', 'restore', 'rootfs', 'searchdomain', 'ssh-public-keys', 'start',
              'startup', 'storage', 'swap', 'tags', 'template', 'timezone', 'tty', 'unique',
              'unprivileged', 'unused[n]', 'vmid'}
PVE_ENV = r'(?:\w+=[^\x00-\x08\x0a-\x1F\x7F]*)(?:\0\w+=[^\x00-\x08\x0a-\x1F\x7F]*)*'

# GET /nodes/{node}/tasks/{upid}/status - status enum running|stopped, exitstatus optional
# GET /nodes/{node}/tasks/{upid}/log - "Read task log." items {n: line number, t: line text}
# GET /nodes/{node}/storage/{storage}/content - content "Only list content of this type.",
#     items carry volid "Volume identifier."


def _pve_archive(storage, filename):
    """Where PVE puts the pull (pve-storage Status.pm oci_registry_pull):
    normalize_content_filename($param->{filename} // $reference) . ".tar", which keeps what
    follows the last slash and turns everything outside [a-zA-Z0-9_.-] into '_'."""
    name = re.sub(r'^.*[/\\]', '', filename)
    name = re.sub(r'[^a-zA-Z0-9_.-]', '_', name)
    return f'{storage}:vztmpl/{name}.tar'


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = str(body)
        self.headers = {'Content-Type': 'application/json'}

    def json(self):
        return self._body


def _ok(data):
    return _Resp(200, {'data': data})


def _refused(message, errors=None, status=400):
    body = {'data': None, 'message': message}
    if errors:
        body['errors'] = errors
    return _Resp(status, body)


class FakePve:
    def __init__(self, versions=None, pull_exit='OK', pull_log=None, create_exit='OK',
                 pull_refusal=None, on_storage=(), nextid=(105,)):
        versions = versions or {'pve1': '9.1.1', 'pve2': '9.2.0'}
        self.node_status = {}
        for node, ver in versions.items():
            if ver == 'offline':
                self.node_status[node] = {'status': 'offline', 'offline': True}
            else:
                self.node_status[node] = {'status': 'online', 'offline': False,
                                          'pveversion': f'pve-manager/{ver}/42db4a6cf33dac83' if ver else ''}
        self.storages = [
            {'storage': 'local', 'type': 'dir', 'content': 'iso,vztmpl,backup', 'enabled': 1, 'active': 1},
            {'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir', 'enabled': 1, 'active': 1},
            {'storage': 'isos', 'type': 'nfs', 'content': 'iso', 'enabled': 1, 'active': 1},
        ]
        self.content = {'local': [{'volid': v, 'content': 'vztmpl', 'format': 'tar'} for v in on_storage]}
        self.pull_exit, self.pull_log, self.create_exit = pull_exit, pull_log or [], create_exit
        self.pull_refusal = pull_refusal
        self.nextid = list(nextid)
        self.posts = []
        self.gets = []
        self.tasks = {}
        self._n = 0

    def manager(self, api, cluster_id='cluster_1'):
        m = api.make_fake_manager(cluster_id)
        m.host, m.api_port = '10.0.0.1', 8006
        m.config.name = cluster_id
        m.is_connected = True
        m.get_node_status.side_effect = lambda: self.node_status
        m.get_storage_list.side_effect = lambda node: self.storages
        m.get_next_vmid.side_effect = lambda: {'success': True, 'vmid': self.nextid.pop(0) if len(self.nextid) > 1 else self.nextid[0]}
        m._api_get.side_effect = self.get
        m._api_post.side_effect = self.post
        api.set_manager(cluster_id, m)
        return m

    def _task(self, node, kind, exitstatus, done=None):
        self._n += 1
        upid = f'UPID:{node}:0000{self._n:04X}:0001:6700AABB:{kind}:x:root@pam:'
        # running on the first look, stopped on the second: the job has to wait
        self.tasks[upid] = {'looks': 0, 'exitstatus': exitstatus, 'done': done, 'node': node}
        return upid

    def post(self, url, data=None, **kw):
        assert url.startswith(BASE), url
        path = url[len(BASE):]
        self.posts.append((path, dict(data or {})))
        m = re.fullmatch(r'/nodes/([^/]+)/storage/([^/]+)/oci-registry-pull', path)
        if m:
            node, storage = m.groups()
            extra = set(data) - PULL_PARAMS
            if extra:
                return _refused('Parameter verification failed.', {k: 'property is not defined in schema' for k in extra})
            if not re.match(PVE_REFERENCE, data.get('reference', ''), re.ASCII):
                return _refused('Parameter verification failed.', {'reference': 'value does not match the regex pattern'})
            if 'filename' in data and not 1 <= len(data['filename']) <= 255:
                return _refused('Parameter verification failed.', {'filename': 'length is out of range'})
            if self.pull_refusal:
                return _refused(self.pull_refusal, status=500)
            if not any(s['storage'] == storage and 'vztmpl' in s['content'] for s in self.storages):
                return _refused(f"storage '{storage}' is not configured for content-type 'vztmpl'\n", status=500)
            volid = _pve_archive(storage, data.get('filename') or data['reference'])
            if any(v['volid'] == volid for v in self.content.get(storage, [])):
                return _refused(f"refusing to override existing file '{volid}'\n", status=500)

            def done():
                self.content.setdefault(storage, []).append({'volid': volid, 'content': 'vztmpl', 'format': 'tar'})
            return _ok(self._task(node, 'ociregistrypull', self.pull_exit, done if self.pull_exit == 'OK' else None))
        m = re.fullmatch(r'/nodes/([^/]+)/lxc', path)
        if m:
            sent = {re.sub(r'^(net|mp|dev|unused)\d+$', r'\1[n]', k) for k in data}
            if sent - LXC_PARAMS:
                return _refused('Parameter verification failed.', {k: 'property is not defined in schema' for k in sent - LXC_PARAMS})
            if len(str(data.get('ostemplate', ''))) > 255 or int(data.get('vmid', 0)) < 100:
                return _refused('Parameter verification failed.', {'ostemplate': 'bad'})
            if 'env' in data and not re.fullmatch(PVE_ENV, data['env'], re.ASCII):
                return _refused('Parameter verification failed.', {'env': 'value does not match the regex pattern'})
            store = data['ostemplate'].split(':', 1)[0]
            if not any(v['volid'] == data['ostemplate'] for v in self.content.get(store, [])):
                return _refused(f"volume '{data['ostemplate']}' does not exist\n", status=500)
            return _ok(self._task(m.group(1), 'vzcreate', self.create_exit))
        return _refused(f'Method POST {path} not implemented', status=501)

    def get(self, url, params=None, **kw):
        assert url.startswith(BASE), url
        path = url[len(BASE):]
        self.gets.append((path, dict(params or {})))
        m = re.fullmatch(r'/nodes/([^/]+)/tasks/([^/]+)/(status|log)', path)
        if m:
            from urllib.parse import unquote
            upid = unquote(m.group(2))
            task = self.tasks.get(upid)
            if task is None:
                return _refused('no such task', status=500)
            if m.group(3) == 'log':
                lines = ['skopeo copy docker://... oci-archive:...'] + self.pull_log + [f"TASK ERROR: {task['exitstatus']}"]
                return _ok([{'n': i + 1, 't': t} for i, t in enumerate(lines)])
            task['looks'] += 1
            if task['looks'] < 2:
                return _ok({'status': 'running', 'upid': upid, 'node': task['node']})
            if task['done']:
                task['done']()
                task['done'] = None
            return _ok({'status': 'stopped', 'exitstatus': task['exitstatus'], 'upid': upid, 'node': task['node']})
        m = re.fullmatch(r'/nodes/([^/]+)/storage/([^/]+)/content', path)
        if m:
            items = self.content.get(m.group(2), [])
            if (params or {}).get('content'):
                items = [v for v in items if v['content'] == params['content']]
            return _ok(items)
        return _refused(f'Method GET {path} not implemented', status=501)


@pytest.fixture(autouse=True)
def _jobs_inline(monkeypatch):
    """The job runs inside the request here (its thread is tested once below) and does not
    sleep between two looks at a task."""
    with oci._jobs_lock:
        oci._jobs.clear()
    monkeypatch.setattr(oci, '_POLL_S', 0)
    monkeypatch.setattr(oci, '_spawn', oci._run)
    yield
    with oci._jobs_lock:
        oci._jobs.clear()


@pytest.fixture
def admin(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES ('cluster_1', 'cluster_1', '10.0.0.1', 'root@pam', 'x')''')
    return api.as_user(seed.user('root', role='admin'))


def _deploy(client, **over):
    body = {'reference': REF, 'node': 'pve1', 'storage': 'local', 'rootfs_storage': 'local-lvm',
            'disk_gb': 2, 'hostname': 'nginx', 'cores': 1, 'memory': 256, 'swap': 256}
    body.update(over)
    return client.post(DEPLOY, json=body)


def _job(resp):
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return oci._jobs[resp.get_json()['job']['id']]


# --- the catalog and the nodes -----------------------------------------------------------------

def test_the_catalog_names_pullable_images_and_the_preview(api, seed):
    viewer = api.as_user(seed.user('watcher', role='viewer'))
    r = viewer.get('/api/oci/catalog')
    assert r.status_code == 200
    d = r.get_json()
    assert d['technology_preview'] is True and d['min_pve'] == '9.1'
    assert len(d['images']) >= 5
    for img in d['images']:
        assert re.match(PVE_REFERENCE, img['reference'], re.ASCII), img
        assert oci.reference_problem(img['reference']) is None
        assert {'id', 'name', 'description', 'cores', 'memory', 'disk_gb'} <= set(img)
    assert api.anon().get('/api/oci/catalog').status_code == 401


def test_the_nodes_say_which_can_and_why_the_others_cannot(api, admin):
    FakePve(versions={'pve1': '9.1.1', 'pve2': '8.4.14', 'pve3': 'offline', 'pve4': '',
                      'pve5': '9.2.0', 'pve6': '10.0.1'}).manager(api)
    r = admin.get('/api/clusters/cluster_1/oci/nodes')
    assert r.status_code == 200, r.data
    rows = {n['node']: n for n in r.get_json()['nodes']}
    assert rows['pve1']['supported'] and rows['pve1']['pve_version'] == '9.1.1'
    assert rows['pve5']['supported'] and rows['pve6']['supported']
    assert (rows['pve2']['supported'], rows['pve2']['reason'], rows['pve2']['pve_version']) == (False, 'too_old', '8.4.14')
    assert (rows['pve3']['supported'], rows['pve3']['reason']) == (False, 'offline')
    assert (rows['pve4']['supported'], rows['pve4']['reason']) == (False, 'unknown_version')


def test_a_node_status_read_costs_no_call_per_node(api, admin):
    pve = FakePve(versions={f'pve{i}': '9.1.1' for i in range(100)})
    m = pve.manager(api)
    assert admin.get('/api/clusters/cluster_1/oci/nodes').status_code == 200
    assert m.get_node_status.call_count == 1
    assert not pve.gets and not pve.posts


# --- the main scenario -------------------------------------------------------------------------

def test_a_deploy_pulls_the_image_then_creates_the_container_from_it(api, admin):
    pve = FakePve()
    pve.manager(api)
    job = _job(_deploy(admin, env=['TZ=Europe/Vienna', 'GREETING=hello there'], vlan=20))
    assert job['status'] == 'completed', job['error']
    assert job['reused'] is False and job['vmid'] == 105

    (pull_path, pull), (create_path, create) = pve.posts
    assert pull_path == '/nodes/pve1/storage/local/oci-registry-pull'
    assert pull == {'reference': REF, 'filename': NGINX_ARCHIVE}
    assert create_path == '/nodes/pve1/lxc'
    # the template is the file PVE made of the pull, by its own naming rule
    assert create['ostemplate'] == _pve_archive('local', pull['filename']) \
        == f'local:vztmpl/{NGINX_ARCHIVE}.tar'
    assert create['vmid'] == 105 and create['hostname'] == 'nginx'
    assert create['rootfs'] == 'local-lvm:2'
    assert create['net0'] == 'name=eth0,bridge=vmbr0,ip=dhcp,tag=20'
    assert (create['cores'], create['memory'], create['swap']) == (1, 256, 256)
    assert create['unprivileged'] == 1 and create['start'] == 1
    assert create['env'] == 'TZ=Europe/Vienna\0GREETING=hello there'
    assert 'password' not in create
    # it waited for the pull to stop before it created anything
    from urllib.parse import unquote
    assert [unquote(p) for p, _ in pve.gets].count(f"/nodes/pve1/tasks/{job['pull_upid']}/status") == 2
    assert job['pull_upid'].startswith('UPID:pve1:') and ':ociregistrypull:' in job['pull_upid']
    assert ':vzcreate:' in job['create_upid']

    from pegaprox.api.helpers import get_task_user
    assert get_task_user(job['pull_upid']) == 'root' and get_task_user(job['create_upid']) == 'root'
    audit = _audit('container.create')
    assert len(audit) == 1 and REF in audit[0]['details'] and 'CT 105' in audit[0]['details']
    # the environment may hold secrets: it is not kept once it was sent
    assert job['_spec']['env'] == []
    listed = admin.get('/api/clusters/cluster_1/oci/jobs').get_json()['jobs']
    assert [j['id'] for j in listed] == [job['id']]
    assert not any(k.startswith('_') for k in listed[0])


def test_an_image_already_on_the_storage_is_not_pulled_again(api, admin):
    pve = FakePve(on_storage=[f'local:vztmpl/{NGINX_ARCHIVE}.tar'])
    pve.manager(api)
    job = _job(_deploy(admin))
    assert job['status'] == 'completed', job['error']
    assert job['reused'] is True
    assert [p for p, _ in pve.posts] == ['/nodes/pve1/lxc']
    assert ('/nodes/pve1/storage/local/content', {'content': 'vztmpl'}) in pve.gets


def test_a_static_address_and_no_start(api, admin):
    pve = FakePve()
    pve.manager(api)
    job = _job(_deploy(admin, ip='10.0.0.5/24', gw='10.0.0.1', start=False, bridge='vmbr1', vmid=4242))
    assert job['status'] == 'completed', job['error']
    create = pve.posts[-1][1]
    assert create['net0'] == 'name=eth0,bridge=vmbr1,ip=10.0.0.5/24,gw=10.0.0.1'
    assert create['start'] == 0 and create['vmid'] == 4242 and 'env' not in create


def test_a_failed_pull_says_what_skopeo_said_and_creates_nothing(api, admin):
    pve = FakePve(pull_exit="command 'skopeo copy docker://docker.io/library/nginx:nope' failed: exit code 1",
                  pull_log=['time="2026-10-05T10:00:00Z" level=fatal msg="manifest unknown"'])
    pve.manager(api)
    job = _job(_deploy(admin, reference='docker.io/library/nginx:nope'))
    assert job['status'] == 'failed'
    assert 'The pull failed' in job['error'] and 'manifest unknown' in job['error']
    assert [p for p, _ in pve.posts] == ['/nodes/pve1/storage/local/oci-registry-pull']
    failed = _audit('container.create_failed')
    assert len(failed) == 1 and 'manifest unknown' in failed[0]['details']


def test_a_pull_pve_refuses_shows_its_message_as_text(api, admin):
    pve = FakePve(pull_refusal="Install 'skopeo' to pull OCI images from registries.\n")
    pve.manager(api)
    job = _job(_deploy(admin))
    assert job['status'] == 'failed'
    assert "Install 'skopeo' to pull OCI images from registries." in job['error']
    assert [p for p, _ in pve.posts] == ['/nodes/pve1/storage/local/oci-registry-pull']


def test_a_failed_create_is_a_failed_job(api, admin):
    pve = FakePve(create_exit='unable to create CT 105 - no space left')
    pve.manager(api)
    job = _job(_deploy(admin))
    assert job['status'] == 'failed' and 'no space left' in job['error']


def test_the_id_is_taken_again_when_the_first_was_used_meanwhile(api, admin):
    pve = FakePve(nextid=(105, 107))
    pve.manager(api)
    job = _job(_deploy(admin))
    assert job['status'] == 'completed', job['error']
    assert job['vmid'] == 107 and pve.posts[-1][1]['vmid'] == 107


def test_two_jobs_at_once_do_not_get_the_same_free_id(api, admin, monkeypatch):
    """/cluster/nextid answers the lowest id nobody holds yet, and PVE holds it only once
    the create ran. Two jobs that ask in between would both get it; the second create
    would then fail on an id the first one took."""
    monkeypatch.setattr(oci, '_spawn', _REAL_SPAWN)
    pve = FakePve(on_storage=[f'local:vztmpl/{NGINX_ARCHIVE}.tar'])
    m = pve.manager(api)
    taken = set()

    def nextid():
        vmid = 105
        while vmid in taken:
            vmid += 1
        return {'success': True, 'vmid': vmid}

    plain_post = pve.post

    def post(url, data=None, **kw):
        if url.endswith('/lxc'):
            time.sleep(0.3)           # PVE takes a moment before the id is held
            if data['vmid'] in taken:
                return _refused(f"CT {data['vmid']} already exists on node 'pve1'\n", status=500)
            taken.add(data['vmid'])
        return plain_post(url, data=data, **kw)
    m.get_next_vmid.side_effect = nextid
    m._api_post.side_effect = post
    ids = [_deploy(admin, hostname=f'web{i}').get_json()['job']['id'] for i in range(2)]
    deadline = time.time() + 15
    while time.time() < deadline and any(oci._jobs[i]['status'] not in ('completed', 'failed') for i in ids):
        time.sleep(0.05)
    jobs = [oci._jobs[i] for i in ids]
    assert [j['status'] for j in jobs] == ['completed', 'completed'], [j['error'] for j in jobs]
    assert sorted(j['vmid'] for j in jobs) == [105, 106]


def test_the_job_runs_in_a_thread_of_its_own_as_a_user_job(api, admin, monkeypatch):
    """In an automatic group each call of a user job asks for the lease (#625): the job
    goes through ha.as_job like the template deploy, in a thread of its own."""
    from pegaprox.core import ha
    seen = []
    real_as_job = ha.as_job
    monkeypatch.setattr(ha, 'as_job', lambda fn, what: seen.append(what) or real_as_job(fn, what))
    monkeypatch.setattr(oci, '_spawn', _REAL_SPAWN)
    pve = FakePve()
    pve.manager(api)
    r = _deploy(admin)
    assert r.status_code == 200
    job_id = r.get_json()['job']['id']
    assert seen == [f'oci deploy {job_id}']
    deadline = time.time() + 10
    rows = []
    while time.time() < deadline:
        rows = admin.get('/api/clusters/cluster_1/oci/jobs').get_json()['jobs']
        if rows and rows[0]['status'] in ('completed', 'failed'):
            break
        time.sleep(0.05)
    assert rows and rows[0]['id'] == job_id and rows[0]['status'] == 'completed', rows


# --- refused before anything is sent ------------------------------------------------------------

def test_a_node_older_than_9_1_is_refused_and_nothing_is_sent(api, admin):
    pve = FakePve(versions={'pve1': '8.4.14', 'pve2': '9.1.1'})
    pve.manager(api)
    r = _deploy(admin)
    assert r.status_code == 400
    assert r.get_json()['reason'] == 'too_old' and '9.1' in r.get_json()['error']
    assert not pve.posts and not oci._jobs
    assert _deploy(admin, node='pve2').status_code == 200


@pytest.mark.parametrize('over,needle', [
    ({'node': 'pve9'}, 'not a node'),
    ({'storage': 'isos'}, 'takes no container templates'),
    ({'storage': 'local-lvm'}, 'takes no container templates'),
    ({'rootfs_storage': 'local'}, 'takes no container disks'),
    ({'storage': 'nowhere'}, 'has no storage'),
])
def test_node_and_storages_must_fit(api, admin, over, needle):
    pve = FakePve()
    pve.manager(api)
    r = _deploy(admin, **over)
    assert r.status_code in (400, 404), r.data
    assert needle in r.get_json()['error']
    assert not pve.posts


@pytest.mark.parametrize('over', [
    {'reference': 'docker.io/library/nginx'},             # no tag
    {'reference': 'ghcr.io/Owner/app:1'},                 # upper case in the path
    {'reference': 'a' * 300 + ':1'},
    {'reference': 'nginx:1;reboot'},
    {'reference': None},
    {'env': ['A=1', 'NOT A PAIR']},
    {'env': ['BELL=\x07']},
    {'env': ['K=v'] * 65},
    {'hostname': 'bad_host'},
    {'ip': '10.0.0.5'},                                   # no prefix length
    {'ip': 'dhcp', 'gw': '10.0.0.1'},
    {'cores': 0}, {'memory': 8}, {'vmid': 99}, {'vlan': 5000}, {'disk_gb': 'lots'},
    {'bridge': 'vmbr0,firewall=1'},
    {'storage': 'local:evil'},
    {'storage': 'l'}, {'rootfs_storage': '-lvm'},         # pve-storage-id (parse_id)
    {'node': 'pve_1'}, {'node': '../pve1'},               # pve-node
])
def test_what_pve_would_refuse_is_refused_here(api, admin, over):
    pve = FakePve()
    pve.manager(api)
    r = _deploy(admin, **over)
    assert r.status_code == 400, (over, r.data)
    assert not pve.posts and not oci._jobs


@pytest.mark.parametrize('value', [False, 0, '0', 'false', 'no'])
def test_every_spelling_of_no_keeps_the_container_stopped(api, admin, value):
    pve = FakePve()
    pve.manager(api)
    assert _job(_deploy(admin, start=value))['status'] == 'completed'
    assert pve.posts[-1][1]['start'] == 0


@pytest.mark.parametrize('over', [{'cores': 1.5}, {'cores': True}, {'memory': 1e400}])
def test_a_number_that_is_not_a_whole_one_is_refused(api, admin, over):
    pve = FakePve()
    pve.manager(api)
    assert _deploy(admin, **over).status_code == 400
    assert not pve.posts


def test_a_body_that_is_no_object_is_refused(api, admin):
    pve = FakePve()
    pve.manager(api)
    for body in ([REF], 'nginx', 5):
        assert admin.post(DEPLOY, json=body).status_code == 400, body
    assert not pve.posts and not oci._jobs


def test_no_free_id_from_the_cluster_is_a_clear_refusal(api, admin):
    pve = FakePve()
    m = pve.manager(api)
    m.get_next_vmid.side_effect = lambda: {'success': False, 'error': 'connection refused'}
    r = _deploy(admin)
    assert r.status_code == 502 and 'CT ID' in r.get_json()['error']
    assert not pve.posts


@pytest.mark.parametrize('ref', ['localhost:5000/team/app:1', '127.0.0.1:2375/x/y:1', '169.254.169.254/latest/meta:x',
                                 '0.0.0.0:80/x/y:1'])
def test_the_node_is_not_sent_to_its_own_loopback_or_a_metadata_address(api, admin, ref):
    """The node pulls as root from wherever the reference points (the SSRF gate of the
    cloud image URLs in templates_lib, applied to the registry)."""
    assert oci.reference_problem(ref) is None, ref
    pve = FakePve()
    pve.manager(api)
    r = _deploy(admin, reference=ref)
    assert r.status_code == 400 and 'does not pull from' in r.get_json()['error'], r.data
    assert not pve.posts and not oci._jobs


def test_a_registry_on_the_lan_is_fine_and_docker_hub_needs_no_lookup(api, admin, monkeypatch):
    import socket
    pve = FakePve()
    pve.manager(api)
    job = _job(_deploy(admin, reference='10.0.0.50:5000/team/app:1.2'))
    assert job['status'] == 'completed', job['error']
    assert pve.posts[0][1] == {'reference': '10.0.0.50:5000/team/app:1.2',
                               'filename': oci.archive_name('10.0.0.50:5000/team/app:1.2')}
    assert pve.posts[0][1]['filename'].startswith('10.0.0.50_5000_team_app_1.2_')
    assert oci.registry_of('library/nginx:1') == oci.registry_of('nginx:1') == 'docker.io'
    assert oci.registry_of('ghcr.io/owner/app:1') == 'ghcr.io'

    def no_dns(*a, **kw):
        raise AssertionError('Docker Hub was looked up')
    monkeypatch.setattr(socket, 'getaddrinfo', no_dns)
    assert oci.registry_problem('docker.io/library/nginx:1') is None
    assert oci.registry_problem('team/app:1') is None


def test_a_non_proxmox_cluster_is_refused(api, admin):
    m = api.make_fake_manager('cluster_1', cluster_type='xcpng')
    api.set_manager('cluster_1', m)
    assert admin.get('/api/clusters/cluster_1/oci/nodes').status_code == 400
    assert _deploy(admin).status_code == 400


# --- the reference check -------------------------------------------------------------------------

def test_the_reference_check_takes_exactly_what_the_pve_pattern_takes():
    pattern = re.compile(PVE_REFERENCE, re.ASCII)
    rnd = random.Random(625)
    alphabet = 'abA0._-/:'
    taken = 0
    for _ in range(40000):
        s = ''.join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 11)))
        expected = pattern.match(s) is not None and not s.endswith('\n')
        assert (oci.reference_problem(s) is None) == expected, s
        taken += expected
    assert taken > 300, 'the sample hardly ever hit a valid reference'
    for ref in ('nginx:1', 'docker.io/library/nginx:stable-alpine', 'localhost:5000/a/b:t',
                'Registry.Example.com/team/app_name__x:v1.2-rc', 'a-b--c/d.e:latest'):
        assert oci.reference_problem(ref) is None, ref
        assert pattern.match(ref), ref


def test_the_reference_check_does_not_backtrack_on_a_near_miss():
    # the PVE pattern takes seconds on 24 characters and doubles every one more
    started = time.perf_counter()
    assert oci.reference_problem('a' * 250 + '!:1') is not None
    assert oci.reference_problem('a-' * 120 + 'A:1') is not None
    assert oci.reference_problem('x.' * 100 + '/' + 'b_' * 20 + '!:1') is not None
    assert time.perf_counter() - started < 0.1


def test_names_are_checked_the_way_pve_common_checks_them():
    """pve-common src/PVE/JSONSchema.pm:
    parse_id (pve-storage-id): length($id) < 2 dies, then m/^[a-z][a-z0-9\\-\\_\\.]*[a-z0-9]\\z/i
    pve_verify_dns_name: $namere = "([a-zA-Z0-9]([a-zA-Z0-9\\-]*[a-zA-Z0-9])?)"; /^(${namere}\\.)*${namere}\\z/
    pve_verify_node_name: m/^([a-zA-Z0-9]([a-zA-Z0-9\\-]*[a-zA-Z0-9])?)\\z/"""
    namere = r'([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)'
    pve = {
        oci._STORAGE_ID: lambda s: len(s) >= 2 and re.fullmatch(r'[a-z][a-z0-9\-\_\.]*[a-z0-9]', s, re.I | re.ASCII),
        oci._HOSTNAME: lambda s: re.fullmatch(rf'({namere}\.)*{namere}', s, re.ASCII),
        oci._NODE: lambda s: re.fullmatch(namere, s, re.ASCII),
    }
    rnd = random.Random(91)
    for _ in range(20000):
        s = ''.join(rnd.choice('aZ0-._') for _ in range(rnd.randint(1, 8)))
        for ours, theirs in pve.items():
            assert bool(ours.fullmatch(s)) == bool(theirs(s)), (ours.pattern, s)


def test_the_archive_name_keeps_the_registry():
    assert oci.archive_name('docker.io/library/nginx:1') != oci.archive_name('ghcr.io/library/nginx:1')
    # PVE's normalisation leaves our name as it is
    for ref in ('docker.io/library/nginx:1', 'localhost:5000/a/b:t'):
        name = oci.archive_name(ref)
        assert _pve_archive('s', name) == f's:vztmpl/{name}.tar'


@pytest.mark.parametrize('a,b', [
    ('example.com:5000/team:tag', 'example.com/5000/team:tag'),
    ('registry.example/a_b/c:t', 'registry.example/a/b_c:t'),
    ('ghcr.io/team/app_x:y', 'ghcr.io/team/app:x_y'),
])
def test_two_references_never_share_an_archive(a, b):
    """'/', ':' and '_' all became _, so a reference anyone may type could name the file
    another one pulled, and a deploy reused it (#1063)."""
    assert oci.reference_problem(a) is None and oci.reference_problem(b) is None
    assert oci.archive_name(a) != oci.archive_name(b)
    # and the same reference keeps its one file, which is what reuse rests on
    assert oci.archive_name(a) == oci.archive_name(a)
    assert _pve_archive('s', oci.archive_name(b)) == f's:vztmpl/{oci.archive_name(b)}.tar'


def test_a_colliding_reference_pulls_its_own_archive(api, admin):
    """The storage holds what the pull of the first reference left; the second pulls."""
    first, second = '10.0.0.50:5000/team:tag', '10.0.0.50/5000/team:tag'
    pve = FakePve(on_storage=[f'local:vztmpl/{oci.archive_name(first)}.tar'])
    pve.manager(api)
    job = _job(_deploy(admin, reference=second))
    assert job['status'] == 'completed', job['error']
    assert job['reused'] is False, 'the deploy took the archive another reference pulled'
    pull = dict(pve.posts)['/nodes/pve1/storage/local/oci-registry-pull']
    assert pull == {'reference': second, 'filename': oci.archive_name(second)}


# --- who may -------------------------------------------------------------------------------------

def _callers(api, seed):
    seed.tenant('globex', ['cluster_globex'])
    seed.tenant('initech', ['cluster_other'])
    seed.pool('cluster_1', 'pool-a', 'poolie', ['vm.view', 'vm.create'])
    return {
        'no_permission': api.as_user(seed.user('ops', role='user')),
        'viewer': api.as_user(seed.user('watcher', role='viewer')),
        'pool_confined': api.as_user(seed.user('poolie', role='user', permissions=['vm.create'])),
        # an admin an LDAP mapping lowered to user in its own tenant, holding vm.create there
        'confined_admin': api.as_user(seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={
            'globex': {'role': 'user', 'extra': ['vm.create']}})),
        'other_tenant': api.as_user(seed.user('milton', role='user', tenant_id='initech',
                                              permissions=['vm.create', 'cluster.view'])),
    }


@pytest.mark.parametrize('kind,gate', [
    ('no_permission', 'Permission denied'),
    ('viewer', 'Permission denied'),
    # holds vm.create in its pool, and placing a guest is not something a pool grant covers
    ('pool_confined', 'affects the whole cluster'),
    ('confined_admin', 'Access denied to this cluster'),
    ('other_tenant', 'Access denied to this cluster'),
])
def test_nobody_below_an_unconfined_creator_places_a_container(api, admin, seed, kind, gate):
    pve = FakePve()
    pve.manager(api)
    client = _callers(api, seed)[kind]
    r = client.get('/api/clusters/cluster_1/oci/nodes')
    assert r.status_code == 403 and gate in r.get_json()['error'], (kind, r.data)
    r = _deploy(client)
    assert r.status_code == 403 and gate in r.get_json()['error'], (kind, r.data)
    assert not pve.posts and not oci._jobs


ROUTES = {('GET', '/api/oci/catalog'), ('GET', '/api/clusters/<cluster_id>/oci/nodes'),
          ('POST', '/api/clusters/<cluster_id>/oci/deploy'), ('GET', '/api/clusters/<cluster_id>/oci/jobs')}


def test_the_route_list_of_this_matrix_is_complete(api):
    served = {(m, rule.rule) for rule in api.app.url_map.iter_rules()
              if rule.endpoint.startswith('oci_catalog.') for m in rule.methods - {'HEAD', 'OPTIONS'}}
    assert served == ROUTES


def test_an_admins_viewer_token_places_nothing(api, admin):
    from pegaprox.utils.auth import create_api_token
    pve = FakePve()
    pve.manager(api)
    res = create_api_token('root', 'ci', role='viewer')
    assert res.get('success'), res
    auth = {'Authorization': f"Bearer {res['token']}"}
    assert api.anon().get('/api/clusters/cluster_1/oci/nodes', headers=auth).status_code == 403
    assert api.anon().post(DEPLOY, json={'reference': REF, 'node': 'pve1', 'storage': 'local',
                                         'rootfs_storage': 'local-lvm'}, headers=auth).status_code == 403
    # reading the catalog and the runs is what a viewer may
    assert api.anon().get('/api/oci/catalog', headers=auth).status_code == 200
    assert api.anon().get('/api/clusters/cluster_1/oci/jobs', headers=auth).status_code == 200
    assert not pve.posts and not oci._jobs


def test_an_unconfined_operator_with_the_permission_may(api, admin, seed):
    pve = FakePve()
    pve.manager(api)
    ops = api.as_user(seed.user('ops', role='user', permissions=['vm.create']))
    assert ops.get('/api/clusters/cluster_1/oci/nodes').status_code == 200
    job = _job(_deploy(ops))
    assert job['status'] == 'completed' and job['started_by'] == 'ops'


def test_anonymous_gets_nothing(api, admin):
    FakePve().manager(api)
    anon = api.anon()
    assert anon.get('/api/clusters/cluster_1/oci/nodes').status_code == 401
    assert anon.post(DEPLOY, json={}).status_code == 401
    assert anon.get('/api/clusters/cluster_1/oci/jobs').status_code == 401


def test_the_runs_list_is_scoped_like_the_containers_it_names(api, admin, seed):
    pve = FakePve()
    m = pve.manager(api)
    m.get_vm_resources.return_value = []
    _job(_deploy(admin))
    callers = _callers(api, seed)
    assert callers['other_tenant'].get('/api/clusters/cluster_1/oci/jobs').status_code == 403
    # a pool-confined caller reaches the cluster, but not a CT outside the pool
    m.get_pools.return_value = []
    r = callers['pool_confined'].get('/api/clusters/cluster_1/oci/jobs')
    assert r.status_code == 200 and r.get_json()['jobs'] == []
    # ...and does see it once the CT is in their pool
    import pegaprox.utils.rbac as rbac
    m.get_pools.return_value = [{'poolid': 'pool-a'}]
    m.get_pool_members.return_value = {'members': [{'vmid': 105, 'type': 'lxc'}]}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache.clear()
    r = callers['pool_confined'].get('/api/clusters/cluster_1/oci/jobs')
    assert [j['vmid'] for j in r.get_json()['jobs']] == [105]
    assert len(admin.get('/api/clusters/cluster_1/oci/jobs').get_json()['jobs']) == 1


def test_a_tenant_range_holds_for_the_id_picked_and_for_the_one_typed(api, admin, seed):
    import pegaprox.utils.rbac as rbac
    seed.db.save_tenant('tenant_a', {'id': 'tenant_a', 'name': 'A', 'clusters': ['cluster_1'],
                                     'vmid_range_start': 200, 'vmid_range_end': 299})
    rbac.invalidate_tenants_cache()
    pve = FakePve(nextid=(105,))
    pve.manager(api)
    bob = api.as_user(seed.user('bob', role='user', tenant_id='tenant_a', permissions=['vm.create']))
    r = _deploy(bob)
    assert r.status_code == 403 and '200-299' in r.get_json()['error']
    assert _deploy(bob, vmid=150).status_code == 403
    assert not pve.posts
    assert _job(_deploy(bob, vmid=250))['status'] == 'completed'


def test_a_range_check_that_cannot_run_refuses(api, admin, monkeypatch):
    import pegaprox.utils.rbac as rbac
    pve = FakePve()
    pve.manager(api)
    monkeypatch.setattr(rbac, 'check_tenant_vmid', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('db gone')))
    r = _deploy(admin)
    assert r.status_code == 403 and 'VMID range' in r.get_json()['error']
    assert not pve.posts


def test_a_blocking_quota_refuses(api, admin, monkeypatch):
    import pegaprox.utils.rbac as rbac
    pve = FakePve()
    pve.manager(api)
    monkeypatch.setattr(rbac, 'check_tenant_quota', lambda *a, **kw: {
        'ok': False, 'enforce': 'block', 'violations': ['memory'], 'usage': {}, 'quota': {}})
    r = _deploy(admin)
    assert r.status_code == 403 and 'quota' in r.get_json()['error']
    assert not pve.posts


# --- standby (#625) ------------------------------------------------------------------------------

def test_a_standby_creates_nothing(ha_env, seed):  # noqa: F811
    api = ha_env.api
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES ('cluster_1', 'cluster_1', '10.0.0.1', 'root@pam', 'x')''')
    pve = FakePve()
    pve.manager(api)
    root = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = _deploy(root)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert not pve.posts and not oci._jobs
    # reading stays open there
    assert root.get('/api/clusters/cluster_1/oci/nodes').status_code == 200
    # counterproof: the active it pairs with does
    _active_with_standby(ha_env)
    assert _job(_deploy(root))['status'] == 'completed'


def test_a_forwarding_standby_reads_the_runs_of_the_active():
    from pegaprox.core import ha
    assert '/api/clusters/<cluster_id>/oci/jobs' in ha.FORWARDED_READS
