# -*- coding: utf-8 -*-
"""A thin client for the PegaProx REST API.

Every call carries the linked user's own API token (Authorization: Bearer pgx_...),
so PegaProx checks the user's permissions exactly as it does in the web interface.
The bot never holds more rights than the person behind the chat.
"""
from urllib.parse import quote

import requests
import urllib3


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def _q(part):
    return quote(str(part), safe='')


class PegaProx:
    def __init__(self, base_url, token, verify=False, timeout=30, session=None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.verify = verify
        self.timeout = timeout
        self.http = session or requests.Session()
        if verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # -- core ---------------------------------------------------------------
    def request(self, method, path, json=None, params=None):
        if not path.startswith('/'):
            path = '/' + path
        try:
            r = self.http.request(
                method.upper(), self.base_url + path, json=json, params=params,
                headers={'Authorization': f'Bearer {self.token}', 'Accept': 'application/json',
                         # PegaProx's CSRF gate wants this on every write
                         'X-Requested-With': 'XMLHttpRequest'},
                verify=self.verify, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as e:
            raise ApiError(0, f'PegaProx недоступен: {e.__class__.__name__}')
        try:
            body = r.json()
        except ValueError:
            body = None
        if r.status_code >= 400:
            msg = ''
            if isinstance(body, dict):
                msg = body.get('error') or body.get('message') or ''
            raise ApiError(r.status_code, msg or f'HTTP {r.status_code}')
        return body

    def get(self, path, **params):
        return self.request('GET', path, params=params or None)

    def post(self, path, json=None):
        return self.request('POST', path, json=json if json is not None else {})

    # -- who am I -----------------------------------------------------------
    def me(self):
        return self.get('/api/me/permissions')

    # -- clusters and nodes ---------------------------------------------------
    def clusters(self):
        data = self.get('/api/clusters')
        return data if isinstance(data, list) else (data or {}).get('clusters', [])

    def nodes(self, cid):
        data = self.get(f'/api/clusters/{_q(cid)}/nodes')
        return data if isinstance(data, list) else (data or {}).get('nodes', [])

    def node_action(self, cid, node, action):
        return self.post(f'/api/clusters/{_q(cid)}/nodes/{_q(node)}/action/{_q(action)}')

    def tasks(self, cid, limit=15):
        data = self.get(f'/api/clusters/{_q(cid)}/tasks', limit=limit)
        return data if isinstance(data, list) else (data or {}).get('tasks', [])

    def datastores(self, cid):
        return self.get(f'/api/clusters/{_q(cid)}/datastores') or {}

    # -- guests -------------------------------------------------------------
    def vms(self, cid):
        return (self.get(f'/api/clusters/{_q(cid)}/vms') or {}).get('vms', [])

    def _vm(self, cid, node, vtype, vmid):
        return f'/api/clusters/{_q(cid)}/vms/{_q(node)}/{_q(vtype)}/{int(vmid)}'

    def vm_action(self, cid, node, vtype, vmid, action):
        return self.post(f'{self._vm(cid, node, vtype, vmid)}/{_q(action)}')

    def snapshots(self, cid, node, vtype, vmid):
        data = self.get(f'{self._vm(cid, node, vtype, vmid)}/snapshots')
        return data if isinstance(data, list) else (data or {}).get('snapshots', [])

    def create_snapshot(self, cid, node, vtype, vmid, name, description=''):
        return self.post(f'{self._vm(cid, node, vtype, vmid)}/snapshots',
                         {'snapname': name, 'description': description})

    def rollback_snapshot(self, cid, node, vtype, vmid, name):
        return self.post(f'{self._vm(cid, node, vtype, vmid)}/snapshots/{_q(name)}/rollback')

    def delete_snapshot(self, cid, node, vtype, vmid, name):
        return self.request('DELETE', f'{self._vm(cid, node, vtype, vmid)}/snapshots/{_q(name)}')

    def backups(self, cid, node, vtype, vmid):
        data = self.get(f'{self._vm(cid, node, vtype, vmid)}/backups')
        return data if isinstance(data, list) else (data or {}).get('backups', [])

    def create_backup(self, cid, node, vtype, vmid, storage, mode='snapshot'):
        return self.post(f'{self._vm(cid, node, vtype, vmid)}/backups/create',
                         {'storage': storage, 'mode': mode, 'compress': 'zstd',
                          'notes': 'Telegram'})

    def migrate(self, cid, node, vtype, vmid, target, online=True):
        return self.post(f'{self._vm(cid, node, vtype, vmid)}/migrate',
                         {'target': target, 'online': bool(online)})

    # -- firewall -------------------------------------------------------------
    def dc_firewall_options(self, cid):
        return self.get(f'/api/clusters/{_q(cid)}/datacenter/firewall/options') or {}

    def set_dc_firewall_enabled(self, cid, enabled):
        return self.request('PUT', f'/api/clusters/{_q(cid)}/datacenter/firewall/options',
                            json={'enable': 1 if enabled else 0})

    def dc_firewall_rules(self, cid):
        return self.get(f'/api/clusters/{_q(cid)}/datacenter/firewall/rules') or []

    def set_dc_firewall_rule(self, cid, pos, enabled):
        return self.request('PUT', f'/api/clusters/{_q(cid)}/datacenter/firewall/rules/{int(pos)}',
                            json={'enable': 1 if enabled else 0})

    def vm_firewall_rules(self, cid, node, vtype, vmid):
        return self.get(f'/api/clusters/{_q(cid)}/vms/{_q(node)}/{_q(vtype)}/{int(vmid)}/firewall/rules') or []

    def set_vm_firewall_rule(self, cid, node, vtype, vmid, pos, enabled):
        return self.request(
            'PUT', f'/api/clusters/{_q(cid)}/vms/{_q(node)}/{_q(vtype)}/{int(vmid)}/firewall/rules/{int(pos)}',
            json={'enable': 1 if enabled else 0})

    # -- alerts -------------------------------------------------------------
    def active_alerts(self, cid):
        return (self.get(f'/api/clusters/{_q(cid)}/active-alerts') or {}).get('active_alerts', [])

    def ack_alert(self, cid, fired_id):
        return self.post(f'/api/clusters/{_q(cid)}/active-alerts/{_q(fired_id)}/ack')
