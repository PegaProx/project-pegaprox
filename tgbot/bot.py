# -*- coding: utf-8 -*-
"""Telegram bot for PegaProx.

Each Telegram user links their own PegaProx account by sending an API token
(PegaProx: My profile -> API tokens). Every action then goes through the PegaProx
REST API under that token, so the user can do in Telegram exactly what their
PegaProx role allows, and nothing more. Actions are written to the PegaProx audit
log under the user's name, as in the web interface.
"""
import json
import logging
import re
import secrets
import threading
import time
from collections import OrderedDict

from . import views as v
from .pegaprox_client import ApiError, PegaProx
from .panel_users import PanelUsersMixin

log = logging.getLogger('tgbot')

PAGE = 8
GUEST_ACTIONS = {
    'start': ('▶️ Start', False, 'Start'),
    'shutdown': ('⏻ Shutdown', True, 'Shutdown'),
    'reboot': ('🔄 Reboot', True, 'Reboot'),
    'stop': ('⏹ Stop (hard)', True, 'Hard stop'),
    'reset': ('⚡ Reset', True, 'Reset'),
    'suspend': ('⏸ Suspend', False, 'Suspend'),
    'resume': ('⏯ Resume', False, 'Resume'),
}
TOKEN_RE = re.compile(r'^pgx_[0-9a-f]{4}_[A-Za-z0-9_\-]{20,}$')
TOKEN_ANYWHERE_RE = re.compile(r'pgx_[0-9a-f]{4}_[A-Za-z0-9_\-]{20,}')
PRIVATE_ONLY = 'User management works only in a private chat with the bot.'
SNAP_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_\-]{1,39}$')

HELP = (
    "<b>Proxmox management through PegaProx</b>\n\n"
    "The bot acts as your PegaProx user, with the same permissions.\n\n"
    "<b>How to connect</b>\n"
    "1. In PegaProx open \"My Profile → API Tokens\" and create a token.\n"
    "2. Send it here in a private chat: <code>/login pgx_...</code>\n"
    "   The bot deletes the message with the token right away.\n\n"
    "<b>Commands</b>\n"
    "/menu: main menu (clusters, nodes, VMs and containers)\n"
    "/find <i>text</i>: find a VM/CT by name or ID\n"
    "/users: PegaProx users and their roles\n"
    "/alerts: active alerts\n"
    "/notify on|off: push new alerts\n"
    "/whoami: your role and permissions\n"
    "/api <i>METHOD /api/path [JSON]</i>: any PegaProx API call\n"
    "/logout: unlink the account\n"
)

COMMANDS = [
    ('menu', 'Main menu'), ('find', 'Find a VM/CT'), ('users', 'PegaProx users'), ('alerts', 'Active alerts'),
    ('notify', 'Notifications on/off'), ('whoami', 'My permissions'), ('login', 'Link an account'),
    ('logout', 'Unlink the account'), ('api', 'API request'), ('help', 'Help'),
]


class Callbacks:
    """Inline buttons carry at most 64 bytes, so they point at a stored context."""

    def __init__(self, limit=20000):
        self._items = OrderedDict()
        self._limit = limit
        self._lock = threading.Lock()

    def put(self, owner, action, **ctx):
        key = secrets.token_urlsafe(6)
        with self._lock:
            self._items[key] = (owner, action, ctx)
            while len(self._items) > self._limit:
                self._items.popitem(last=False)
        return key

    def get(self, key):
        with self._lock:
            return self._items.get(key)


class Bot(PanelUsersMixin):
    def __init__(self, cfg, tg, store, api_factory=None):
        self.cfg = cfg
        self.tg = tg
        self.store = store
        self.cb = Callbacks()
        self.pending = {}  # tg user id -> {'kind': ..., ctx}
        self._api_factory = api_factory or (lambda token: PegaProx(cfg.pegaprox_url, token, cfg.verify_tls))
        self._stop = threading.Event()

    # ------------------------------------------------------------------ plumbing
    def api(self, uid):
        token = self.store.token(uid)
        if not token:
            raise ApiError(401, 'no linked account')
        return self._api_factory(token)

    def btn(self, uid, label, action, **ctx):
        return {'text': label, 'callback_data': self.cb.put(uid, action, **ctx)}

    def allowed(self, uid):
        return not self.cfg.allowed_ids or uid in self.cfg.allowed_ids

    def run(self):
        self.tg.set_commands(COMMANDS)
        if self.cfg.alert_poll:
            threading.Thread(target=self._alert_loop, name='alerts', daemon=True).start()
        offset = None
        log.info('Bot started, PegaProx at %s', self.cfg.pegaprox_url)
        while not self._stop.is_set():
            for upd in self.tg.updates(offset):
                offset = upd['update_id'] + 1
                try:
                    self.handle_update(upd)
                except Exception:
                    log.exception('update %s failed', upd.get('update_id'))

    def stop(self):
        self._stop.set()

    def handle_update(self, upd):
        if 'callback_query' in upd:
            return self.on_callback(upd['callback_query'])
        msg = upd.get('message')
        if msg and msg.get('text'):
            return self.on_message(msg)

    # ------------------------------------------------------------------ messages
    def on_message(self, msg):
        uid = msg['from']['id']
        chat = msg['chat']['id']
        text = msg['text'].strip()
        private = msg['chat'].get('type') == 'private'
        has_token = bool(TOKEN_ANYWHERE_RE.search(text))
        if has_token and (not private or not self.allowed(uid)):
            # a token must not stay in a group or reach a bot that won't use it
            gone = self.tg.delete(chat, msg['message_id'])
            warn = ('I deleted the message with the token' if gone
                    else 'I could not delete the message with the token')
            if not self.allowed(uid):
                return self.tg.send(chat, f'Access to this bot is closed. Your Telegram id: <code>{uid}</code>\n'
                                          f'{warn}; revoke that token in PegaProx.')
            return self.tg.send(chat, f'{warn}. Send tokens only in a private chat with the bot, '
                                      'and revoke this one in PegaProx.')
        if not self.allowed(uid):
            return self.tg.send(chat, f'Access to this bot is closed. Your Telegram id: <code>{uid}</code>')
        try:
            return self._on_text(msg, uid, chat, text)
        except ApiError as err:
            return self.error(chat, err)

    def _on_text(self, msg, uid, chat, text):
        if text.startswith('/'):
            cmd, _, arg = text.partition(' ')
            cmd = cmd[1:].split('@', 1)[0].lower()
            arg = arg.strip()
            self.pending.pop(uid, None)
            handler = getattr(self, f'cmd_{cmd}', None)
            if handler is None:
                return self.tg.send(chat, 'Unknown command. /help')
            if cmd not in ('start', 'help', 'login') and not self.store.get(uid):
                return self.tg.send(chat, 'Link your PegaProx account first: /login <i>token</i>. More: /help')
            return handler(msg, uid, chat, arg)
        pend = self.pending.pop(uid, None)
        if pend:
            return self.on_input(msg, uid, chat, text, pend)
        if TOKEN_RE.match(text):  # a token pasted without /login
            return self.cmd_login(msg, uid, chat, text)
        return self.tg.send(chat, 'Open /menu or see /help')

    def cmd_start(self, msg, uid, chat, arg):
        if self.store.get(uid):
            return self.cmd_menu(msg, uid, chat, arg)
        return self.tg.send(chat, HELP)

    def cmd_help(self, msg, uid, chat, arg):
        return self.tg.send(chat, HELP)

    def cmd_login(self, msg, uid, chat, arg):
        if arg:
            self.tg.delete(chat, msg['message_id'])
        if msg['chat'].get('type') != 'private':
            return self.tg.send(chat, 'Send the token only in a private chat with the bot. '
                                      'If you sent it here, revoke the token in PegaProx.')
        token = arg.strip()
        if not TOKEN_RE.match(token):
            return self.tg.send(chat, 'Send a PegaProx API token: <code>/login pgx_...</code>\n'
                                      'You can create one under "My Profile → API Tokens".')
        try:
            me = self._api_factory(token).me()
        except ApiError as err:
            if err.status in (401, 403):
                return self.tg.send(chat, '❌ PegaProx did not accept the token: it is wrong, revoked or expired.')
            return self.tg.send(chat, f'❌ Could not check the token: {v.e(err.message)}')
        self.store.link(uid, token, {'role': me.get('effective_role') or me.get('role'),
                                     'tg_name': msg['from'].get('username') or msg['from'].get('first_name')})
        log.info('Telegram user %s linked (role %s)', uid, me.get('role'))
        self.tg.send(chat, f"✅ Account linked. PegaProx role: <b>{v.e(me.get('effective_role') or me.get('role'))}</b>.\n"
                           'New alerts will be sent here (/notify off to stop).')
        return self.cmd_menu(msg, uid, chat, '')

    def cmd_logout(self, msg, uid, chat, arg):
        self.store.unlink(uid)
        return self.tg.send(chat, 'Account unlinked. The token itself still works: '
                                  'revoke it in PegaProx ("My Profile → API Tokens").')

    def cmd_whoami(self, msg, uid, chat, arg):
        try:
            me = self.api(uid).me()
        except ApiError as err:
            return self.error(chat, err)
        perms = me.get('permissions') or []
        return self.tg.send(chat, f"Role: <b>{v.e(me.get('effective_role') or me.get('role'))}</b>\n"
                                  f"Tenant: {v.e(me.get('tenant_id'))}\n"
                                  f"Permissions ({len(perms)}): <code>{v.e(', '.join(sorted(perms))[:3500])}</code>")

    def cmd_notify(self, msg, uid, chat, arg):
        on = arg.lower() not in ('off', '0', 'no')
        self.store.set_notify(uid, on)
        return self.tg.send(chat, 'Alert notifications are on.' if on else 'Notifications are off.')

    def cmd_menu(self, msg, uid, chat, arg):
        return self.show_clusters(uid, chat)

    def cmd_alerts(self, msg, uid, chat, arg):
        return self.show_all_alerts(uid, chat)

    def cmd_find(self, msg, uid, chat, arg):
        if not arg:
            self.pending[uid] = {'kind': 'find'}
            return self.tg.send(chat, 'Type a VM/CT name or ID:')
        return self.find(uid, chat, arg)

    def cmd_api(self, msg, uid, chat, arg):
        parts = arg.split(None, 2)
        if len(parts) < 2 or parts[0].upper() not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE') \
                or not parts[1].startswith('/api/'):
            return self.tg.send(chat, 'Usage: <code>/api GET /api/clusters</code>\n'
                                      'or <code>/api POST /api/path {"key": "value"}</code>')
        body = None
        if len(parts) == 3:
            try:
                body = json.loads(parts[2])
            except ValueError:
                return self.tg.send(chat, 'The request body must be JSON.')
        try:
            res = self.api(uid).request(parts[0], parts[1], json=body)
        except ApiError as err:
            return self.error(chat, err)
        out = v.e(json.dumps(res, ensure_ascii=False, indent=1))
        if len(out) > 3800:
            cut = out[:3800]
            amp = cut.rfind('&')
            if amp > cut.rfind(';'):  # don't leave half an HTML entity
                cut = cut[:amp]
            out = cut + '\n…'
        return self.tg.send(chat, f'<pre>{out}</pre>')

    def on_input(self, msg, uid, chat, text, pend):
        kind = pend['kind']
        if kind.startswith('pp_'):
            return self.pp_input(msg, uid, chat, text, pend)
        if kind == 'find':
            return self.find(uid, chat, text)
        if kind == 'snapname':
            if not SNAP_RE.match(text):
                self.pending[uid] = pend
                return self.tg.send(chat, 'Snapshot name: Latin letters, digits, _ and -, starting with a letter. Try again:')
            g = pend['g']
            return self._do(uid, chat, None, lambda a: a.create_snapshot(g['cid'], g['node'], g['type'], g['vmid'], text,
                                                                          'Telegram'),
                            f"Creating snapshot <b>{v.e(text)}</b>", back=('snaps', {'g': g}))

    # ------------------------------------------------------------------ callbacks
    def on_callback(self, q):
        uid = q['from']['id']
        msg = q.get('message') or {}
        chat = (msg.get('chat') or {}).get('id', uid)
        mid = msg.get('message_id')
        item = self.cb.get(q.get('data') or '')
        if not item or item[0] != uid:
            self.tg.answer(q['id'], 'This button has expired, open /menu', alert=True)
            return
        if not self.allowed(uid) or not self.store.get(uid):
            self.tg.answer(q['id'], 'No account linked: /login', alert=True)
            return
        _, action, ctx = item
        if (action == 'users' or action.startswith('pp_')) and (msg.get('chat') or {}).get('type') != 'private':
            self.tg.answer(q['id'], PRIVATE_ONLY, alert=True)
            return
        self.tg.answer(q['id'])
        handler = getattr(self, f'cb_{action}')
        try:
            return handler(uid, chat, mid, **ctx)
        except ApiError as err:
            return self.error(chat, err, mid)

    def screen(self, chat, mid, text, kb):
        if mid:
            return self.tg.edit(chat, mid, text, kb)
        return self.tg.send(chat, text, kb)

    def error(self, chat, err, mid=None, kb=None):
        if err.status == 401:
            text = '❌ PegaProx rejected the token (revoked or expired). Link again: /login'
        elif err.status == 403:
            text = f'⛔ Permission denied: {v.e(err.message)}'
        else:
            text = f'❌ Error: {v.e(err.message)}'
        return self.screen(chat, mid, text, kb) if mid else self.tg.send(chat, text, kb)

    def _do(self, uid, chat, mid, call, done_text, back=None):
        kb = None
        if back:
            kb = [[self.btn(uid, '« Back', back[0], **back[1])]]
        try:
            res = call(self.api(uid))
        except ApiError as err:
            return self.error(chat, err, mid, kb)
        detail = ''
        if isinstance(res, dict):
            task = res.get('task') or res.get('upid') or res.get('data')
            if isinstance(task, str) and task.startswith('UPID'):
                detail = f'\nTask: <code>{v.e(task)}</code>'
            elif res.get('message'):
                detail = f"\n{v.e(res['message'])}"
        return self.screen(chat, mid, f'✅ {done_text}{detail}', kb)

    # clusters ------------------------------------------------------------------
    def show_clusters(self, uid, chat, mid=None):
        try:
            clusters = self.api(uid).clusters()
        except ApiError as err:
            return self.error(chat, err, mid)
        if not clusters:
            return self.screen(chat, mid, 'No clusters available.', None)
        kb = [[self.btn(uid, v.cluster_line(c), 'cluster', cid=c['id'], cname=v.cluster_name(c))] for c in clusters]
        kb.append([self.btn(uid, '🔔 Alerts', 'all_alerts'), self.btn(uid, '🔍 Search', 'ask_find')])
        kb.append([self.btn(uid, '👥 Users', 'users')])
        return self.screen(chat, mid, '<b>Clusters</b>', kb)

    def cb_clusters(self, uid, chat, mid):
        return self.show_clusters(uid, chat, mid)

    def cb_cluster(self, uid, chat, mid, cid, cname):
        api = self.api(uid)
        lines = [f'<b>{v.e(cname)}</b>']
        try:
            nodes = api.nodes(cid)
            online = sum(1 for n in nodes if n.get('status') == 'online')
            lines.append(f'Nodes: {online} of {len(nodes)} online')
        except ApiError as err:
            lines.append(f'Nodes: {v.e(err.message)}')
        try:
            vms = api.vms(cid)
            running = sum(1 for x in vms if x.get('status') == 'running')
            lines.append(f'Guests: {running} of {len(vms)} running')
        except ApiError:
            pass
        c = dict(cid=cid, cname=cname)
        kb = [
            [self.btn(uid, '🖥 Nodes', 'nodes', **c), self.btn(uid, '📦 VMs and CTs', 'guests', page=0, **c)],
            [self.btn(uid, '📋 Tasks', 'tasks', **c), self.btn(uid, '🔔 Alerts', 'alerts', **c)],
            [self.btn(uid, '🛡 Firewall', 'fw', **c), self.btn(uid, '💽 Storage', 'storage', **c)],
            [self.btn(uid, '🔄 Refresh', 'cluster', **c), self.btn(uid, '« Clusters', 'clusters')],
        ]
        return self.screen(chat, mid, '\n'.join(lines), kb)

    # nodes ---------------------------------------------------------------------
    def cb_nodes(self, uid, chat, mid, cid, cname):
        try:
            nodes = self.api(uid).nodes(cid)
        except ApiError as err:
            return self.error(chat, err, mid)
        c = dict(cid=cid, cname=cname)
        lines = [f'<b>{v.e(cname)}: nodes</b>'] + [v.node_line(n) for n in nodes]
        kb = [[self.btn(uid, n.get('node') or n.get('name'), 'node', node=n.get('node') or n.get('name'), **c)]
              for n in nodes]
        kb.append([self.btn(uid, '« Back', 'cluster', **c)])
        return self.screen(chat, mid, '\n'.join(lines), kb)

    def cb_node(self, uid, chat, mid, cid, cname, node):
        try:
            nodes = self.api(uid).nodes(cid)
        except ApiError as err:
            return self.error(chat, err, mid)
        n = next((x for x in nodes if (x.get('node') or x.get('name')) == node), {'node': node, 'status': '?'})
        c = dict(cid=cid, cname=cname, node=node)
        kb = [[self.btn(uid, '🔄 Reboot', 'confirm_node', act='reboot', **c),
               self.btn(uid, '⏻ Shutdown', 'confirm_node', act='shutdown', **c)],
              [self.btn(uid, '🔄 Refresh', 'node', **c), self.btn(uid, '« Nodes', 'nodes', cid=cid, cname=cname)]]
        return self.screen(chat, mid, v.node_text(n) + '\n\nPegaProx allows reboot and shutdown '
                                                        'only for a node in maintenance mode.', kb)

    def cb_confirm_node(self, uid, chat, mid, cid, cname, node, act):
        c = dict(cid=cid, cname=cname, node=node)
        word = 'Reboot' if act == 'reboot' else 'Shut down'
        kb = [[self.btn(uid, f'✅ Yes, {word.lower()}', 'node_do', act=act, **c),
               self.btn(uid, 'Cancel', 'node', **c)]]
        return self.screen(chat, mid, f'{word} node <b>{v.e(node)}</b>?', kb)

    def cb_node_do(self, uid, chat, mid, cid, cname, node, act):
        return self._do(uid, chat, mid, lambda a: a.node_action(cid, node, act),
                        f"Node {v.e(node)}: {'reboot' if act == 'reboot' else 'shutdown'} started",
                        back=('node', dict(cid=cid, cname=cname, node=node)))

    # guests --------------------------------------------------------------------
    def cb_guests(self, uid, chat, mid, cid, cname, page=0):
        try:
            vms = self.api(uid).vms(cid)
        except ApiError as err:
            return self.error(chat, err, mid)
        c = dict(cid=cid, cname=cname)
        pages = max(1, (len(vms) + PAGE - 1) // PAGE)
        page = min(max(0, page), pages - 1)
        chunk = vms[page * PAGE:(page + 1) * PAGE]
        kb = [[self.btn(uid, v.guest_button(x), 'guest', g=self._g(cid, cname, x))] for x in chunk]
        nav = []
        if page > 0:
            nav.append(self.btn(uid, '‹', 'guests', page=page - 1, **c))
        if page < pages - 1:
            nav.append(self.btn(uid, '›', 'guests', page=page + 1, **c))
        if nav:
            kb.append(nav)
        kb.append([self.btn(uid, '🔍 Search', 'ask_find'), self.btn(uid, '« Back', 'cluster', **c)])
        return self.screen(chat, mid, f'<b>{v.e(cname)}: VMs and containers</b> ({len(vms)}), page {page + 1}/{pages}', kb)

    @staticmethod
    def _g(cid, cname, x):
        return {'cid': cid, 'cname': cname, 'node': x.get('node'), 'type': x.get('type'),
                'vmid': int(x.get('vmid')), 'name': x.get('name') or ''}

    def _fresh(self, uid, g):
        """Re-read the guest: it may have moved or changed state since the button was drawn."""
        for x in self.api(uid).vms(g['cid']):
            if int(x.get('vmid')) == int(g['vmid']):
                return x
        return None

    def cb_guest(self, uid, chat, mid, g):
        try:
            x = self._fresh(uid, g)
        except ApiError as err:
            return self.error(chat, err, mid)
        if not x:
            return self.screen(chat, mid, f"Guest {g['vmid']} not found.",
                               [[self.btn(uid, '« Back', 'guests', cid=g['cid'], cname=g['cname'], page=0)]])
        g = self._g(g['cid'], g['cname'], x)
        st = x.get('status')
        acts = ['start'] if st == 'stopped' else (['resume', 'stop'] if st in ('paused', 'suspended')
                                                  else ['shutdown', 'reboot', 'stop', 'suspend'])
        if g['type'] == 'qemu' and st == 'running':
            acts.append('reset')
        if g['type'] == 'lxc':
            acts = [a for a in acts if a not in ('reset',)]
        row, kb = [], []
        for a in acts:
            row.append(self.btn(uid, GUEST_ACTIONS[a][0], 'guest_act', g=g, act=a))
            if len(row) == 2:
                kb.append(row)
                row = []
        if row:
            kb.append(row)
        kb += [[self.btn(uid, '📸 Snapshots', 'snaps', g=g), self.btn(uid, '💾 Backups', 'backups', g=g)],
               [self.btn(uid, '🚚 Migrate', 'migrate', g=g), self.btn(uid, '🛡 Firewall', 'vmfw', g=g)],
               [self.btn(uid, '🔄 Refresh', 'guest', g=g),
                self.btn(uid, '« List', 'guests', cid=g['cid'], cname=g['cname'], page=0)]]
        return self.screen(chat, mid, v.guest_text(x, g['cname']), kb)

    def cb_guest_act(self, uid, chat, mid, g, act, ok=False):
        label, needs_confirm, word = GUEST_ACTIONS[act]
        if needs_confirm and not ok:
            kb = [[self.btn(uid, f'✅ Yes: {word.lower()}', 'guest_act', g=g, act=act, ok=True),
                   self.btn(uid, 'Cancel', 'guest', g=g)]]
            return self.screen(chat, mid, f"{word}: <b>{v.e(g['name'])}</b> ({g['vmid']})?", kb)
        return self._do(uid, chat, mid, lambda a: a.vm_action(g['cid'], g['node'], g['type'], g['vmid'], act),
                        f"{word}: {v.e(g['name'])} ({g['vmid']})", back=('guest', {'g': g}))

    # snapshots -------------------------------------------------------------------
    def cb_snaps(self, uid, chat, mid, g):
        try:
            snaps = [s for s in self.api(uid).snapshots(g['cid'], g['node'], g['type'], g['vmid'])
                     if s.get('name') != 'current']
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'guest', g=g)]])
        lines = [f"<b>Snapshots of {v.e(g['name'])} ({g['vmid']})</b>"] + ([v.snapshot_line(s) for s in snaps] or ['No snapshots'])
        kb = [[self.btn(uid, f"↩️ {s['name']}", 'snap', g=g, snap=s['name'])] for s in snaps[-10:]]
        kb.append([self.btn(uid, '➕ Create', 'snap_new', g=g), self.btn(uid, '« Back', 'guest', g=g)])
        return self.screen(chat, mid, '\n'.join(lines), kb)

    def cb_snap(self, uid, chat, mid, g, snap):
        kb = [[self.btn(uid, '↩️ Roll back', 'snap_do', g=g, snap=snap, op='rollback'),
               self.btn(uid, '🗑 Delete', 'snap_do', g=g, snap=snap, op='delete')],
              [self.btn(uid, '« Snapshots', 'snaps', g=g)]]
        return self.screen(chat, mid, f"Snapshot <b>{v.e(snap)}</b> of {v.e(g['name'])} ({g['vmid']})", kb)

    def cb_snap_do(self, uid, chat, mid, g, snap, op, ok=False):
        word = 'Roll back to' if op == 'rollback' else 'Delete'
        if not ok:
            kb = [[self.btn(uid, '✅ Yes', 'snap_do', g=g, snap=snap, op=op, ok=True),
                   self.btn(uid, 'Cancel', 'snap', g=g, snap=snap)]]
            warn = '\nThe current state of the guest will be lost.' if op == 'rollback' else ''
            return self.screen(chat, mid, f'{word} snapshot <b>{v.e(snap)}</b>?{warn}', kb)
        if op == 'rollback':
            call = lambda a: a.rollback_snapshot(g['cid'], g['node'], g['type'], g['vmid'], snap)
        else:
            call = lambda a: a.delete_snapshot(g['cid'], g['node'], g['type'], g['vmid'], snap)
        return self._do(uid, chat, mid, call,
                        f"{'Rollback to' if op == 'rollback' else 'Deleting'} snapshot {v.e(snap)}",
                        back=('snaps', {'g': g}))

    def cb_snap_new(self, uid, chat, mid, g):
        self.pending[uid] = {'kind': 'snapname', 'g': g}
        default = time.strftime('tg_%Y%m%d_%H%M')
        kb = [[self.btn(uid, f'Create "{default}"', 'snap_auto', g=g, name=default)],
              [self.btn(uid, 'Cancel', 'snaps', g=g)]]
        return self.screen(chat, mid, 'Type a name for the new snapshot or press the button:', kb)

    def cb_snap_auto(self, uid, chat, mid, g, name):
        self.pending.pop(uid, None)
        return self._do(uid, chat, mid, lambda a: a.create_snapshot(g['cid'], g['node'], g['type'], g['vmid'], name,
                                                                     'Telegram'),
                        f'Creating snapshot <b>{v.e(name)}</b>', back=('snaps', {'g': g}))

    # backups ---------------------------------------------------------------------
    def cb_backups(self, uid, chat, mid, g):
        try:
            items = self.api(uid).backups(g['cid'], g['node'], g['type'], g['vmid'])
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'guest', g=g)]])
        items = sorted(items, key=lambda b: b.get('ctime') or 0, reverse=True)
        lines = [f"<b>Backups of {v.e(g['name'])} ({g['vmid']})</b>"] + ([v.backup_line(b) for b in items[:10]] or ['No backups'])
        kb = [[self.btn(uid, '➕ Back up now', 'backup_store', g=g), self.btn(uid, '« Back', 'guest', g=g)]]
        return self.screen(chat, mid, '\n'.join(lines), kb)

    def cb_backup_store(self, uid, chat, mid, g):
        try:
            ds = self.api(uid).datastores(g['cid'])
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'backups', g=g)]])
        names = []
        shared = ds.get('shared') or []
        if isinstance(shared, dict):
            shared = list(shared.values())
        local = (ds.get('local') or {}).get(g['node']) or []
        for s in list(shared) + list(local):
            if 'backup' in (s.get('content') or '') and s.get('storage') not in names:
                names.append(s.get('storage'))
        if not names:
            return self.screen(chat, mid, 'No backup storage available on this node.',
                               [[self.btn(uid, '« Back', 'backups', g=g)]])
        kb = [[self.btn(uid, f'💽 {n}', 'backup_do', g=g, storage=n)] for n in names]
        kb.append([self.btn(uid, 'Cancel', 'backups', g=g)])
        return self.screen(chat, mid, 'Where to store the backup (snapshot mode, zstd)?', kb)

    def cb_backup_do(self, uid, chat, mid, g, storage):
        return self._do(uid, chat, mid, lambda a: a.create_backup(g['cid'], g['node'], g['type'], g['vmid'], storage),
                        f"Backup of {v.e(g['name'])} to {v.e(storage)} started", back=('backups', {'g': g}))

    # migration -------------------------------------------------------------------
    def cb_migrate(self, uid, chat, mid, g):
        try:
            nodes = self.api(uid).nodes(g['cid'])
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'guest', g=g)]])
        targets = [n.get('node') or n.get('name') for n in nodes
                   if n.get('status') == 'online' and (n.get('node') or n.get('name')) != g['node']]
        if not targets:
            return self.screen(chat, mid, 'No other online node to migrate to.',
                               [[self.btn(uid, '« Back', 'guest', g=g)]])
        kb = [[self.btn(uid, f'➡️ {t}', 'migrate_do', g=g, target=t)] for t in targets]
        kb.append([self.btn(uid, 'Cancel', 'guest', g=g)])
        return self.screen(chat, mid, f"Migrate <b>{v.e(g['name'])}</b> from {v.e(g['node'])} to:", kb)

    def cb_migrate_do(self, uid, chat, mid, g, target, ok=False):
        if not ok:
            kb = [[self.btn(uid, '✅ Migrate', 'migrate_do', g=g, target=target, ok=True),
                   self.btn(uid, 'Cancel', 'guest', g=g)]]
            return self.screen(chat, mid, f"Migrate <b>{v.e(g['name'])}</b> ({g['vmid']}) to <b>{v.e(target)}</b>?", kb)
        try:
            x = self._fresh(uid, g)
        except ApiError as err:
            return self.error(chat, err, mid)
        online = bool(x and x.get('status') == 'running')
        return self._do(uid, chat, mid, lambda a: a.migrate(g['cid'], g['node'], g['type'], g['vmid'], target, online),
                        f"Migration of {v.e(g['name'])} to {v.e(target)} started",
                        back=('guests', dict(cid=g['cid'], cname=g['cname'], page=0)))

    # firewall --------------------------------------------------------------------
    def cb_fw(self, uid, chat, mid, cid, cname):
        api = self.api(uid)
        c = dict(cid=cid, cname=cname)
        try:
            opts = api.dc_firewall_options(cid)
            rules = api.dc_firewall_rules(cid)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'cluster', **c)]])
        on = str(opts.get('enable', 0)) in ('1', 'True', 'true')
        lines = [f"<b>Datacenter firewall of {v.e(cname)}</b>",
                 f"State: {'✅ enabled' if on else '⛔ disabled'}",
                 f"Policy in: {v.e(opts.get('policy_in', 'DROP'))}, out: {v.e(opts.get('policy_out', 'ACCEPT'))}",
                 ''] + ([v.fw_rule_line(r) for r in rules[:30]] or ['No rules'])
        kb = [[self.btn(uid, '⛔ Disable firewall' if on else '✅ Enable firewall', 'fw_toggle', on=not on, **c)]]
        row = []
        for r in rules[:20]:
            r_on = str(r.get('enable', 0)) in ('1', 'True', 'true')
            row.append(self.btn(uid, f"{'⛔' if r_on else '✅'} #{r.get('pos')}", 'fw_rule', pos=r.get('pos'), on=not r_on, **c))
            if len(row) == 4:
                kb.append(row)
                row = []
        if row:
            kb.append(row)
        kb.append([self.btn(uid, '🔄 Refresh', 'fw', **c), self.btn(uid, '« Back', 'cluster', **c)])
        return self.screen(chat, mid, '\n'.join(lines) + '\n\nThe #N buttons turn a rule on or off.', kb)

    def cb_fw_toggle(self, uid, chat, mid, cid, cname, on, ok=False):
        c = dict(cid=cid, cname=cname)
        if not ok:
            kb = [[self.btn(uid, '✅ Yes', 'fw_toggle', on=on, ok=True, **c), self.btn(uid, 'Cancel', 'fw', **c)]]
            warn = ('\nMake sure there are rules that allow the web UI and SSH, '
                    'or you may lock yourself out.') if on else ''
            return self.screen(chat, mid, f"{'Enable' if on else 'Disable'} the datacenter firewall?{warn}", kb)
        return self._do(uid, chat, mid, lambda a: a.set_dc_firewall_enabled(cid, on),
                        f"Firewall {'enabled' if on else 'disabled'}", back=('fw', c))

    def cb_fw_rule(self, uid, chat, mid, cid, cname, pos, on):
        try:
            self.api(uid).set_dc_firewall_rule(cid, pos, on)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'fw', cid=cid, cname=cname)]])
        return self.cb_fw(uid, chat, mid, cid, cname)

    def cb_vmfw(self, uid, chat, mid, g):
        try:
            rules = self.api(uid).vm_firewall_rules(g['cid'], g['node'], g['type'], g['vmid'])
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'guest', g=g)]])
        lines = [f"<b>Firewall {v.e(g['name'])} ({g['vmid']})</b>"] + ([v.fw_rule_line(r) for r in rules[:30]] or ['No rules'])
        kb, row = [], []
        for r in rules[:20]:
            r_on = str(r.get('enable', 0)) in ('1', 'True', 'true')
            row.append(self.btn(uid, f"{'⛔' if r_on else '✅'} #{r.get('pos')}", 'vmfw_rule', g=g, pos=r.get('pos'), on=not r_on))
            if len(row) == 4:
                kb.append(row)
                row = []
        if row:
            kb.append(row)
        kb.append([self.btn(uid, '🔄 Refresh', 'vmfw', g=g), self.btn(uid, '« Back', 'guest', g=g)])
        return self.screen(chat, mid, '\n'.join(lines), kb)

    def cb_vmfw_rule(self, uid, chat, mid, g, pos, on):
        try:
            self.api(uid).set_vm_firewall_rule(g['cid'], g['node'], g['type'], g['vmid'], pos, on)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'vmfw', g=g)]])
        return self.cb_vmfw(uid, chat, mid, g)

    # storage, tasks --------------------------------------------------------------
    def cb_storage(self, uid, chat, mid, cid, cname):
        c = dict(cid=cid, cname=cname)
        try:
            ds = self.api(uid).datastores(cid)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'cluster', **c)]])
        shared = ds.get('shared') or []
        if isinstance(shared, dict):
            shared = list(shared.values())
        lines = [f'<b>Storage of {v.e(cname)}</b>']
        for s in shared:
            lines.append(f"🌐 <b>{v.e(s.get('storage'))}</b> ({v.e(s.get('type'))}) "
                         f"{v.size(s.get('used'))} of {v.size(s.get('total'))} ({v.pct(s.get('used'), s.get('total'))})")
        for node, items in (ds.get('local') or {}).items():
            for s in items:
                lines.append(f"🖥 {v.e(node)}/<b>{v.e(s.get('storage'))}</b> ({v.e(s.get('type'))}) "
                             f"{v.size(s.get('used'))} of {v.size(s.get('total'))} ({v.pct(s.get('used'), s.get('total'))})")
        return self.screen(chat, mid, '\n'.join(lines),
                           [[self.btn(uid, '🔄 Refresh', 'storage', **c), self.btn(uid, '« Back', 'cluster', **c)]])

    def cb_tasks(self, uid, chat, mid, cid, cname):
        c = dict(cid=cid, cname=cname)
        try:
            tasks = self.api(uid).tasks(cid, limit=15)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'cluster', **c)]])
        lines = [f'<b>Latest tasks of {v.e(cname)}</b>'] + ([v.task_line(t) for t in tasks[:15]] or ['No tasks'])
        return self.screen(chat, mid, '\n'.join(lines),
                           [[self.btn(uid, '🔄 Refresh', 'tasks', **c), self.btn(uid, '« Back', 'cluster', **c)]])

    # alerts ------------------------------------------------------------------------
    def cb_alerts(self, uid, chat, mid, cid, cname):
        c = dict(cid=cid, cname=cname)
        try:
            alerts = self.api(uid).active_alerts(cid)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Back', 'cluster', **c)]])
        text = f'<b>Alerts of {v.e(cname)}</b>\n\n' + ('\n\n'.join(v.alert_text(a) for a in alerts[:10]) or 'No active alerts ✅')
        kb = [[self.btn(uid, f"✔️ Acknowledge #{a['id']}", 'ack', cid=cid, cname=cname, fid=a['id'])]
              for a in alerts[:10] if not a.get('acked_at')]
        kb.append([self.btn(uid, '🔄 Refresh', 'alerts', **c), self.btn(uid, '« Back', 'cluster', **c)])
        return self.screen(chat, mid, text, kb)

    def cb_ack(self, uid, chat, mid, cid, cname, fid, back='alerts'):
        try:
            self.api(uid).ack_alert(cid, fid)
        except ApiError as err:
            return self.error(chat, err, mid)
        if back == 'none':
            return self.screen(chat, mid, f'✔️ Alert #{v.e(fid)} acknowledged', None)
        return self.cb_alerts(uid, chat, mid, cid, cname)

    def cb_all_alerts(self, uid, chat, mid):
        return self.show_all_alerts(uid, chat, mid)

    def show_all_alerts(self, uid, chat, mid=None):
        api = self.api(uid)
        try:
            clusters = api.clusters()
        except ApiError as err:
            return self.error(chat, err, mid)
        blocks = []
        for c in clusters:
            try:
                for a in api.active_alerts(c['id']):
                    blocks.append(v.alert_text(a, v.cluster_name(c)))
            except ApiError:
                continue
        text = '<b>Active alerts</b>\n\n' + ('\n\n'.join(blocks[:15]) or 'No active alerts ✅')
        return self.screen(chat, mid, text, [[self.btn(uid, '« Clusters', 'clusters')]])

    # search ------------------------------------------------------------------------
    def cb_ask_find(self, uid, chat, mid):
        self.pending[uid] = {'kind': 'find'}
        return self.screen(chat, mid, 'Type a VM/CT name or ID:', None)

    def find(self, uid, chat, query):
        q = query.strip().lower()
        try:
            api = self.api(uid)
            clusters = api.clusters()
        except ApiError as err:
            return self.error(chat, err)
        found = []
        for c in clusters:
            try:
                for x in api.vms(c['id']):
                    if q == str(x.get('vmid')) or q in (x.get('name') or '').lower():
                        found.append((c, x))
            except ApiError:
                continue
        if not found:
            return self.tg.send(chat, f'Nothing found for "{v.e(query)}".')
        kb = [[self.btn(uid, f'{v.guest_button(x)} @ {v.cluster_name(c)}'[:60], 'guest',
                        g=self._g(c['id'], v.cluster_name(c), x))] for c, x in found[:20]]
        return self.tg.send(chat, f'Found: {len(found)}', kb)

    # alert notifications -------------------------------------------------------------
    def _alert_loop(self):
        while not self._stop.wait(self.cfg.alert_poll):
            try:
                self.poll_alerts()
            except Exception:
                log.exception('alert poll failed')

    def poll_alerts(self):
        for uid in self.store.linked_ids():
            rec = self.store.get(uid) or {}
            if not rec.get('notify', True) or not self.allowed(uid):
                continue
            try:
                api = self.api(uid)
                clusters = api.clusters()
            except ApiError:
                continue
            for c in clusters:
                try:
                    alerts = api.active_alerts(c['id'])
                except ApiError:
                    continue
                by_key = {f"{c['id']}:{a.get('id')}:{a.get('triggered_at')}": a for a in alerts
                          if not a.get('acked_at') and not a.get('muted_until')}
                for key in self.store.mark_seen(uid, list(by_key)):
                    a = by_key[key]
                    kb = [[self.btn(uid, '✔️ Acknowledge', 'ack', cid=c['id'], cname=v.cluster_name(c),
                                    fid=a['id'], back='none')]]
                    self.tg.send(uid, '🔔 ' + v.alert_text(a, v.cluster_name(c)), kb)
