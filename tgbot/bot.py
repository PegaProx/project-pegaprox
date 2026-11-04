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

log = logging.getLogger('tgbot')

PAGE = 8
GUEST_ACTIONS = {
    'start': ('▶️ Запустить', False, 'Запуск'),
    'shutdown': ('⏻ Выключить', True, 'Корректное выключение'),
    'reboot': ('🔄 Перезагрузить', True, 'Перезагрузка'),
    'stop': ('⏹ Стоп (жёстко)', True, 'Жёсткая остановка'),
    'reset': ('⚡ Reset', True, 'Сброс'),
    'suspend': ('⏸ Пауза', False, 'Пауза'),
    'resume': ('⏯ Продолжить', False, 'Продолжение'),
}
TOKEN_RE = re.compile(r'^pgx_[0-9a-f]{4}_[A-Za-z0-9_\-]{20,}$')
SNAP_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_\-]{1,39}$')

HELP = (
    "<b>Управление Proxmox через PegaProx</b>\n\n"
    "Бот работает от имени вашего пользователя PegaProx и с теми же правами.\n\n"
    "<b>Как подключиться</b>\n"
    "1. В PegaProx откройте «Мой профиль → API-токены» и создайте токен.\n"
    "2. Пришлите его сюда в личном чате: <code>/login pgx_...</code>\n"
    "   Сообщение с токеном бот сразу удалит.\n\n"
    "<b>Команды</b>\n"
    "/menu: главное меню (кластеры, ноды, VM и контейнеры)\n"
    "/find <i>текст</i>: найти VM/CT по имени или номеру\n"
    "/alerts: активные оповещения\n"
    "/notify on|off: присылать новые оповещения\n"
    "/whoami: ваша роль и права\n"
    "/api <i>METHOD /api/путь [JSON]</i>: любой запрос к API PegaProx\n"
    "/logout: отвязать аккаунт\n"
)

COMMANDS = [
    ('menu', 'Главное меню'), ('find', 'Найти VM/CT'), ('alerts', 'Активные оповещения'),
    ('notify', 'Уведомления вкл/выкл'), ('whoami', 'Мои права'), ('login', 'Подключить аккаунт'),
    ('logout', 'Отвязать аккаунт'), ('api', 'Запрос к API'), ('help', 'Справка'),
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


class Bot:
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
        return self._api_factory(token) if token else None

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
        if not self.allowed(uid):
            return self.tg.send(chat, f'Доступ к боту закрыт. Ваш Telegram id: <code>{uid}</code>')
        if text.startswith('/'):
            cmd, _, arg = text.partition(' ')
            cmd = cmd[1:].split('@', 1)[0].lower()
            arg = arg.strip()
            self.pending.pop(uid, None)
            handler = getattr(self, f'cmd_{cmd}', None)
            if handler is None:
                return self.tg.send(chat, 'Неизвестная команда. /help')
            if cmd not in ('start', 'help', 'login') and not self.store.get(uid):
                return self.tg.send(chat, 'Сначала подключите аккаунт PegaProx: /login <i>токен</i>. Подробнее: /help')
            return handler(msg, uid, chat, arg)
        pend = self.pending.pop(uid, None)
        if pend:
            return self.on_input(msg, uid, chat, text, pend)
        if TOKEN_RE.match(text):  # a token pasted without /login
            return self.cmd_login(msg, uid, chat, text)
        return self.tg.send(chat, 'Откройте /menu или посмотрите /help')

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
            return self.tg.send(chat, 'Токен можно присылать только в личном чате с ботом. '
                                      'Если вы отправили его здесь, отзовите токен в PegaProx.')
        token = arg.strip()
        if not TOKEN_RE.match(token):
            return self.tg.send(chat, 'Пришлите API-токен PegaProx: <code>/login pgx_...</code>\n'
                                      'Создать его можно в «Мой профиль → API-токены».')
        try:
            me = self._api_factory(token).me()
        except ApiError as err:
            if err.status in (401, 403):
                return self.tg.send(chat, '❌ PegaProx не принял токен: он неверный, отозван или истёк.')
            return self.tg.send(chat, f'❌ Не удалось проверить токен: {v.e(err.message)}')
        self.store.link(uid, token, {'role': me.get('effective_role') or me.get('role'),
                                     'tg_name': msg['from'].get('username') or msg['from'].get('first_name')})
        log.info('Telegram user %s linked (role %s)', uid, me.get('role'))
        self.tg.send(chat, f"✅ Аккаунт подключён. Роль в PegaProx: <b>{v.e(me.get('effective_role') or me.get('role'))}</b>.\n"
                           'Новые оповещения буду присылать сюда (/notify off, чтобы выключить).')
        return self.cmd_menu(msg, uid, chat, '')

    def cmd_logout(self, msg, uid, chat, arg):
        self.store.unlink(uid)
        return self.tg.send(chat, 'Аккаунт отвязан. Сам токен по-прежнему действует: '
                                  'отзовите его в PegaProx («Мой профиль → API-токены»).')

    def cmd_whoami(self, msg, uid, chat, arg):
        try:
            me = self.api(uid).me()
        except ApiError as err:
            return self.error(chat, err)
        perms = me.get('permissions') or []
        return self.tg.send(chat, f"Роль: <b>{v.e(me.get('effective_role') or me.get('role'))}</b>\n"
                                  f"Тенант: {v.e(me.get('tenant_id'))}\n"
                                  f"Права ({len(perms)}): <code>{v.e(', '.join(sorted(perms))[:3500])}</code>")

    def cmd_notify(self, msg, uid, chat, arg):
        on = arg.lower() not in ('off', 'выкл', '0', 'no')
        self.store.set_notify(uid, on)
        return self.tg.send(chat, 'Уведомления об оповещениях включены.' if on else 'Уведомления выключены.')

    def cmd_menu(self, msg, uid, chat, arg):
        return self.show_clusters(uid, chat)

    def cmd_alerts(self, msg, uid, chat, arg):
        return self.show_all_alerts(uid, chat)

    def cmd_find(self, msg, uid, chat, arg):
        if not arg:
            self.pending[uid] = {'kind': 'find'}
            return self.tg.send(chat, 'Введите имя или номер VM/CT:')
        return self.find(uid, chat, arg)

    def cmd_api(self, msg, uid, chat, arg):
        parts = arg.split(None, 2)
        if len(parts) < 2 or parts[0].upper() not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE') \
                or not parts[1].startswith('/api/'):
            return self.tg.send(chat, 'Формат: <code>/api GET /api/clusters</code>\n'
                                      'или <code>/api POST /api/путь {"key": "value"}</code>')
        body = None
        if len(parts) == 3:
            try:
                body = json.loads(parts[2])
            except ValueError:
                return self.tg.send(chat, 'Тело запроса должно быть JSON.')
        try:
            res = self.api(uid).request(parts[0], parts[1], json=body)
        except ApiError as err:
            return self.error(chat, err)
        out = json.dumps(res, ensure_ascii=False, indent=1)
        if len(out) > 3800:
            out = out[:3800] + '\n…'
        return self.tg.send(chat, f'<pre>{v.e(out)}</pre>')

    def on_input(self, msg, uid, chat, text, pend):
        kind = pend['kind']
        if kind == 'find':
            return self.find(uid, chat, text)
        if kind == 'snapname':
            if not SNAP_RE.match(text):
                self.pending[uid] = pend
                return self.tg.send(chat, 'Имя снапшота: латиница, цифры, _ и -, начинается с буквы. Ещё раз:')
            g = pend['g']
            return self._do(uid, chat, None, lambda a: a.create_snapshot(g['cid'], g['node'], g['type'], g['vmid'], text,
                                                                          'Telegram'),
                            f"Снапшот <b>{v.e(text)}</b> создаётся", back=('snaps', {'g': g}))

    # ------------------------------------------------------------------ callbacks
    def on_callback(self, q):
        uid = q['from']['id']
        msg = q.get('message') or {}
        chat = (msg.get('chat') or {}).get('id', uid)
        mid = msg.get('message_id')
        item = self.cb.get(q.get('data') or '')
        if not item or item[0] != uid:
            self.tg.answer(q['id'], 'Кнопка устарела, откройте /menu', alert=True)
            return
        if not self.allowed(uid) or not self.store.get(uid):
            self.tg.answer(q['id'], 'Аккаунт не подключён: /login', alert=True)
            return
        _, action, ctx = item
        self.tg.answer(q['id'])
        handler = getattr(self, f'cb_{action}')
        return handler(uid, chat, mid, **ctx)

    def screen(self, chat, mid, text, kb):
        if mid:
            return self.tg.edit(chat, mid, text, kb)
        return self.tg.send(chat, text, kb)

    def error(self, chat, err, mid=None, kb=None):
        if err.status == 401:
            text = '❌ PegaProx отклонил токен (отозван или истёк). Подключитесь заново: /login'
        elif err.status == 403:
            text = f'⛔ Недостаточно прав: {v.e(err.message)}'
        else:
            text = f'❌ Ошибка: {v.e(err.message)}'
        return self.screen(chat, mid, text, kb) if mid else self.tg.send(chat, text, kb)

    def _do(self, uid, chat, mid, call, done_text, back=None):
        kb = None
        if back:
            kb = [[self.btn(uid, '« Назад', back[0], **back[1])]]
        try:
            res = call(self.api(uid))
        except ApiError as err:
            return self.error(chat, err, mid, kb)
        detail = ''
        if isinstance(res, dict):
            task = res.get('task') or res.get('upid') or res.get('data')
            if isinstance(task, str) and task.startswith('UPID'):
                detail = f'\nЗадача: <code>{v.e(task)}</code>'
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
            return self.screen(chat, mid, 'Нет доступных кластеров.', None)
        kb = [[self.btn(uid, v.cluster_line(c), 'cluster', cid=c['id'], cname=v.cluster_name(c))] for c in clusters]
        kb.append([self.btn(uid, '🔔 Оповещения', 'all_alerts'), self.btn(uid, '🔍 Поиск', 'ask_find')])
        return self.screen(chat, mid, '<b>Кластеры</b>', kb)

    def cb_clusters(self, uid, chat, mid):
        return self.show_clusters(uid, chat, mid)

    def cb_cluster(self, uid, chat, mid, cid, cname):
        api = self.api(uid)
        lines = [f'<b>{v.e(cname)}</b>']
        try:
            nodes = api.nodes(cid)
            online = sum(1 for n in nodes if n.get('status') == 'online')
            lines.append(f'Ноды: {online} из {len(nodes)} в сети')
        except ApiError as err:
            lines.append(f'Ноды: {v.e(err.message)}')
        try:
            vms = api.vms(cid)
            running = sum(1 for x in vms if x.get('status') == 'running')
            lines.append(f'Гости: {running} из {len(vms)} запущены')
        except ApiError:
            pass
        c = dict(cid=cid, cname=cname)
        kb = [
            [self.btn(uid, '🖥 Ноды', 'nodes', **c), self.btn(uid, '📦 VM и CT', 'guests', page=0, **c)],
            [self.btn(uid, '📋 Задачи', 'tasks', **c), self.btn(uid, '🔔 Оповещения', 'alerts', **c)],
            [self.btn(uid, '🛡 Firewall', 'fw', **c), self.btn(uid, '💽 Хранилища', 'storage', **c)],
            [self.btn(uid, '🔄 Обновить', 'cluster', **c), self.btn(uid, '« Кластеры', 'clusters')],
        ]
        return self.screen(chat, mid, '\n'.join(lines), kb)

    # nodes ---------------------------------------------------------------------
    def cb_nodes(self, uid, chat, mid, cid, cname):
        try:
            nodes = self.api(uid).nodes(cid)
        except ApiError as err:
            return self.error(chat, err, mid)
        c = dict(cid=cid, cname=cname)
        lines = [f'<b>{v.e(cname)}: ноды</b>'] + [v.node_line(n) for n in nodes]
        kb = [[self.btn(uid, n.get('node') or n.get('name'), 'node', node=n.get('node') or n.get('name'), **c)]
              for n in nodes]
        kb.append([self.btn(uid, '« Назад', 'cluster', **c)])
        return self.screen(chat, mid, '\n'.join(lines), kb)

    def cb_node(self, uid, chat, mid, cid, cname, node):
        try:
            nodes = self.api(uid).nodes(cid)
        except ApiError as err:
            return self.error(chat, err, mid)
        n = next((x for x in nodes if (x.get('node') or x.get('name')) == node), {'node': node, 'status': '?'})
        c = dict(cid=cid, cname=cname, node=node)
        kb = [[self.btn(uid, '🔄 Перезагрузить', 'confirm_node', act='reboot', **c),
               self.btn(uid, '⏻ Выключить', 'confirm_node', act='shutdown', **c)],
              [self.btn(uid, '🔄 Обновить', 'node', **c), self.btn(uid, '« Ноды', 'nodes', cid=cid, cname=cname)]]
        return self.screen(chat, mid, v.node_text(n) + '\n\nPegaProx разрешает перезагрузку и выключение '
                                                        'только ноды в режиме обслуживания.', kb)

    def cb_confirm_node(self, uid, chat, mid, cid, cname, node, act):
        c = dict(cid=cid, cname=cname, node=node)
        word = 'Перезагрузить' if act == 'reboot' else 'Выключить'
        kb = [[self.btn(uid, f'✅ Да, {word.lower()}', 'node_do', act=act, **c),
               self.btn(uid, 'Отмена', 'node', **c)]]
        return self.screen(chat, mid, f'{word} ноду <b>{v.e(node)}</b>?', kb)

    def cb_node_do(self, uid, chat, mid, cid, cname, node, act):
        return self._do(uid, chat, mid, lambda a: a.node_action(cid, node, act),
                        f"Нода {v.e(node)}: {'перезагрузка' if act == 'reboot' else 'выключение'} запущено",
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
        kb.append([self.btn(uid, '🔍 Поиск', 'ask_find'), self.btn(uid, '« Назад', 'cluster', **c)])
        return self.screen(chat, mid, f'<b>{v.e(cname)}: VM и контейнеры</b> ({len(vms)}), стр. {page + 1}/{pages}', kb)

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
            return self.screen(chat, mid, f"Гость {g['vmid']} не найден.",
                               [[self.btn(uid, '« Назад', 'guests', cid=g['cid'], cname=g['cname'], page=0)]])
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
        kb += [[self.btn(uid, '📸 Снапшоты', 'snaps', g=g), self.btn(uid, '💾 Бэкапы', 'backups', g=g)],
               [self.btn(uid, '🚚 Миграция', 'migrate', g=g), self.btn(uid, '🛡 Firewall', 'vmfw', g=g)],
               [self.btn(uid, '🔄 Обновить', 'guest', g=g),
                self.btn(uid, '« Список', 'guests', cid=g['cid'], cname=g['cname'], page=0)]]
        return self.screen(chat, mid, v.guest_text(x, g['cname']), kb)

    def cb_guest_act(self, uid, chat, mid, g, act, ok=False):
        label, needs_confirm, word = GUEST_ACTIONS[act]
        if needs_confirm and not ok:
            kb = [[self.btn(uid, f'✅ Да: {word.lower()}', 'guest_act', g=g, act=act, ok=True),
                   self.btn(uid, 'Отмена', 'guest', g=g)]]
            return self.screen(chat, mid, f"{word}: <b>{v.e(g['name'])}</b> ({g['vmid']})?", kb)
        return self._do(uid, chat, mid, lambda a: a.vm_action(g['cid'], g['node'], g['type'], g['vmid'], act),
                        f"{word}: {v.e(g['name'])} ({g['vmid']})", back=('guest', {'g': g}))

    # snapshots -------------------------------------------------------------------
    def cb_snaps(self, uid, chat, mid, g):
        try:
            snaps = [s for s in self.api(uid).snapshots(g['cid'], g['node'], g['type'], g['vmid'])
                     if s.get('name') != 'current']
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'guest', g=g)]])
        lines = [f"<b>Снапшоты {v.e(g['name'])} ({g['vmid']})</b>"] + ([v.snapshot_line(s) for s in snaps] or ['Нет снапшотов'])
        kb = [[self.btn(uid, f"↩️ {s['name']}", 'snap', g=g, snap=s['name'])] for s in snaps[-10:]]
        kb.append([self.btn(uid, '➕ Создать', 'snap_new', g=g), self.btn(uid, '« Назад', 'guest', g=g)])
        return self.screen(chat, mid, '\n'.join(lines), kb)

    def cb_snap(self, uid, chat, mid, g, snap):
        kb = [[self.btn(uid, '↩️ Откатить', 'snap_do', g=g, snap=snap, op='rollback'),
               self.btn(uid, '🗑 Удалить', 'snap_do', g=g, snap=snap, op='delete')],
              [self.btn(uid, '« Снапшоты', 'snaps', g=g)]]
        return self.screen(chat, mid, f"Снапшот <b>{v.e(snap)}</b> у {v.e(g['name'])} ({g['vmid']})", kb)

    def cb_snap_do(self, uid, chat, mid, g, snap, op, ok=False):
        word = 'Откатить на' if op == 'rollback' else 'Удалить'
        if not ok:
            kb = [[self.btn(uid, '✅ Да', 'snap_do', g=g, snap=snap, op=op, ok=True),
                   self.btn(uid, 'Отмена', 'snap', g=g, snap=snap)]]
            warn = '\nТекущее состояние гостя будет потеряно.' if op == 'rollback' else ''
            return self.screen(chat, mid, f'{word} снапшот <b>{v.e(snap)}</b>?{warn}', kb)
        if op == 'rollback':
            call = lambda a: a.rollback_snapshot(g['cid'], g['node'], g['type'], g['vmid'], snap)
        else:
            call = lambda a: a.delete_snapshot(g['cid'], g['node'], g['type'], g['vmid'], snap)
        return self._do(uid, chat, mid, call,
                        f"{'Откат на' if op == 'rollback' else 'Удаление'} снапшот {v.e(snap)}",
                        back=('snaps', {'g': g}))

    def cb_snap_new(self, uid, chat, mid, g):
        self.pending[uid] = {'kind': 'snapname', 'g': g}
        default = time.strftime('tg_%Y%m%d_%H%M')
        kb = [[self.btn(uid, f'Создать «{default}»', 'snap_auto', g=g, name=default)],
              [self.btn(uid, 'Отмена', 'snaps', g=g)]]
        return self.screen(chat, mid, 'Введите имя нового снапшота или нажмите кнопку:', kb)

    def cb_snap_auto(self, uid, chat, mid, g, name):
        self.pending.pop(uid, None)
        return self._do(uid, chat, mid, lambda a: a.create_snapshot(g['cid'], g['node'], g['type'], g['vmid'], name,
                                                                     'Telegram'),
                        f'Снапшот <b>{v.e(name)}</b> создаётся', back=('snaps', {'g': g}))

    # backups ---------------------------------------------------------------------
    def cb_backups(self, uid, chat, mid, g):
        try:
            items = self.api(uid).backups(g['cid'], g['node'], g['type'], g['vmid'])
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'guest', g=g)]])
        items = sorted(items, key=lambda b: b.get('ctime') or 0, reverse=True)
        lines = [f"<b>Бэкапы {v.e(g['name'])} ({g['vmid']})</b>"] + ([v.backup_line(b) for b in items[:10]] or ['Бэкапов нет'])
        kb = [[self.btn(uid, '➕ Сделать бэкап', 'backup_store', g=g), self.btn(uid, '« Назад', 'guest', g=g)]]
        return self.screen(chat, mid, '\n'.join(lines), kb)

    def cb_backup_store(self, uid, chat, mid, g):
        try:
            ds = self.api(uid).datastores(g['cid'])
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'backups', g=g)]])
        names = []
        shared = ds.get('shared') or []
        if isinstance(shared, dict):
            shared = list(shared.values())
        local = (ds.get('local') or {}).get(g['node']) or []
        for s in list(shared) + list(local):
            if 'backup' in (s.get('content') or '') and s.get('storage') not in names:
                names.append(s.get('storage'))
        if not names:
            return self.screen(chat, mid, 'Нет хранилищ для бэкапов, доступных этой ноде.',
                               [[self.btn(uid, '« Назад', 'backups', g=g)]])
        kb = [[self.btn(uid, f'💽 {n}', 'backup_do', g=g, storage=n)] for n in names]
        kb.append([self.btn(uid, 'Отмена', 'backups', g=g)])
        return self.screen(chat, mid, 'Куда сохранить бэкап (режим snapshot, сжатие zstd)?', kb)

    def cb_backup_do(self, uid, chat, mid, g, storage):
        return self._do(uid, chat, mid, lambda a: a.create_backup(g['cid'], g['node'], g['type'], g['vmid'], storage),
                        f"Бэкап {v.e(g['name'])} в {v.e(storage)} запущен", back=('backups', {'g': g}))

    # migration -------------------------------------------------------------------
    def cb_migrate(self, uid, chat, mid, g):
        try:
            nodes = self.api(uid).nodes(g['cid'])
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'guest', g=g)]])
        targets = [n.get('node') or n.get('name') for n in nodes
                   if n.get('status') == 'online' and (n.get('node') or n.get('name')) != g['node']]
        if not targets:
            return self.screen(chat, mid, 'Нет других нод в сети для миграции.',
                               [[self.btn(uid, '« Назад', 'guest', g=g)]])
        kb = [[self.btn(uid, f'➡️ {t}', 'migrate_do', g=g, target=t)] for t in targets]
        kb.append([self.btn(uid, 'Отмена', 'guest', g=g)])
        return self.screen(chat, mid, f"Перенести <b>{v.e(g['name'])}</b> с {v.e(g['node'])} на:", kb)

    def cb_migrate_do(self, uid, chat, mid, g, target, ok=False):
        if not ok:
            kb = [[self.btn(uid, '✅ Перенести', 'migrate_do', g=g, target=target, ok=True),
                   self.btn(uid, 'Отмена', 'guest', g=g)]]
            return self.screen(chat, mid, f"Перенести <b>{v.e(g['name'])}</b> ({g['vmid']}) на <b>{v.e(target)}</b>?", kb)
        try:
            x = self._fresh(uid, g)
        except ApiError as err:
            return self.error(chat, err, mid)
        online = bool(x and x.get('status') == 'running')
        return self._do(uid, chat, mid, lambda a: a.migrate(g['cid'], g['node'], g['type'], g['vmid'], target, online),
                        f"Миграция {v.e(g['name'])} на {v.e(target)} запущена",
                        back=('guests', dict(cid=g['cid'], cname=g['cname'], page=0)))

    # firewall --------------------------------------------------------------------
    def cb_fw(self, uid, chat, mid, cid, cname):
        api = self.api(uid)
        c = dict(cid=cid, cname=cname)
        try:
            opts = api.dc_firewall_options(cid)
            rules = api.dc_firewall_rules(cid)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'cluster', **c)]])
        on = str(opts.get('enable', 0)) in ('1', 'True', 'true')
        lines = [f"<b>Firewall датацентра {v.e(cname)}</b>",
                 f"Состояние: {'✅ включён' if on else '⛔ выключен'}",
                 f"Политика входящих: {v.e(opts.get('policy_in', 'DROP'))}, исходящих: {v.e(opts.get('policy_out', 'ACCEPT'))}",
                 ''] + ([v.fw_rule_line(r) for r in rules[:30]] or ['Правил нет'])
        kb = [[self.btn(uid, '⛔ Выключить firewall' if on else '✅ Включить firewall', 'fw_toggle', on=not on, **c)]]
        row = []
        for r in rules[:20]:
            r_on = str(r.get('enable', 0)) in ('1', 'True', 'true')
            row.append(self.btn(uid, f"{'⛔' if r_on else '✅'} #{r.get('pos')}", 'fw_rule', pos=r.get('pos'), on=not r_on, **c))
            if len(row) == 4:
                kb.append(row)
                row = []
        if row:
            kb.append(row)
        kb.append([self.btn(uid, '🔄 Обновить', 'fw', **c), self.btn(uid, '« Назад', 'cluster', **c)])
        return self.screen(chat, mid, '\n'.join(lines) + '\n\nКнопки #N включают или выключают правило.', kb)

    def cb_fw_toggle(self, uid, chat, mid, cid, cname, on, ok=False):
        c = dict(cid=cid, cname=cname)
        if not ok:
            kb = [[self.btn(uid, '✅ Да', 'fw_toggle', on=on, ok=True, **c), self.btn(uid, 'Отмена', 'fw', **c)]]
            warn = ('\nУбедитесь, что есть правила, разрешающие доступ к веб-интерфейсу и SSH, '
                    'иначе можно потерять доступ.') if on else ''
            return self.screen(chat, mid, f"{'Включить' if on else 'Выключить'} firewall датацентра?{warn}", kb)
        return self._do(uid, chat, mid, lambda a: a.set_dc_firewall_enabled(cid, on),
                        f"Firewall {'включён' if on else 'выключен'}", back=('fw', c))

    def cb_fw_rule(self, uid, chat, mid, cid, cname, pos, on):
        try:
            self.api(uid).set_dc_firewall_rule(cid, pos, on)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'fw', cid=cid, cname=cname)]])
        return self.cb_fw(uid, chat, mid, cid, cname)

    def cb_vmfw(self, uid, chat, mid, g):
        try:
            rules = self.api(uid).vm_firewall_rules(g['cid'], g['node'], g['type'], g['vmid'])
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'guest', g=g)]])
        lines = [f"<b>Firewall {v.e(g['name'])} ({g['vmid']})</b>"] + ([v.fw_rule_line(r) for r in rules[:30]] or ['Правил нет'])
        kb, row = [], []
        for r in rules[:20]:
            r_on = str(r.get('enable', 0)) in ('1', 'True', 'true')
            row.append(self.btn(uid, f"{'⛔' if r_on else '✅'} #{r.get('pos')}", 'vmfw_rule', g=g, pos=r.get('pos'), on=not r_on))
            if len(row) == 4:
                kb.append(row)
                row = []
        if row:
            kb.append(row)
        kb.append([self.btn(uid, '🔄 Обновить', 'vmfw', g=g), self.btn(uid, '« Назад', 'guest', g=g)])
        return self.screen(chat, mid, '\n'.join(lines), kb)

    def cb_vmfw_rule(self, uid, chat, mid, g, pos, on):
        try:
            self.api(uid).set_vm_firewall_rule(g['cid'], g['node'], g['type'], g['vmid'], pos, on)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'vmfw', g=g)]])
        return self.cb_vmfw(uid, chat, mid, g)

    # storage, tasks --------------------------------------------------------------
    def cb_storage(self, uid, chat, mid, cid, cname):
        c = dict(cid=cid, cname=cname)
        try:
            ds = self.api(uid).datastores(cid)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'cluster', **c)]])
        shared = ds.get('shared') or []
        if isinstance(shared, dict):
            shared = list(shared.values())
        lines = [f'<b>Хранилища {v.e(cname)}</b>']
        for s in shared:
            lines.append(f"🌐 <b>{v.e(s.get('storage'))}</b> ({v.e(s.get('type'))}) "
                         f"{v.size(s.get('used'))} из {v.size(s.get('total'))} ({v.pct(s.get('used'), s.get('total'))})")
        for node, items in (ds.get('local') or {}).items():
            for s in items:
                lines.append(f"🖥 {v.e(node)}/<b>{v.e(s.get('storage'))}</b> ({v.e(s.get('type'))}) "
                             f"{v.size(s.get('used'))} из {v.size(s.get('total'))} ({v.pct(s.get('used'), s.get('total'))})")
        return self.screen(chat, mid, '\n'.join(lines),
                           [[self.btn(uid, '🔄 Обновить', 'storage', **c), self.btn(uid, '« Назад', 'cluster', **c)]])

    def cb_tasks(self, uid, chat, mid, cid, cname):
        c = dict(cid=cid, cname=cname)
        try:
            tasks = self.api(uid).tasks(cid, limit=15)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'cluster', **c)]])
        lines = [f'<b>Последние задачи {v.e(cname)}</b>'] + ([v.task_line(t) for t in tasks[:15]] or ['Задач нет'])
        return self.screen(chat, mid, '\n'.join(lines),
                           [[self.btn(uid, '🔄 Обновить', 'tasks', **c), self.btn(uid, '« Назад', 'cluster', **c)]])

    # alerts ------------------------------------------------------------------------
    def cb_alerts(self, uid, chat, mid, cid, cname):
        c = dict(cid=cid, cname=cname)
        try:
            alerts = self.api(uid).active_alerts(cid)
        except ApiError as err:
            return self.error(chat, err, mid, [[self.btn(uid, '« Назад', 'cluster', **c)]])
        text = f'<b>Оповещения {v.e(cname)}</b>\n\n' + ('\n\n'.join(v.alert_text(a) for a in alerts[:10]) or 'Активных оповещений нет ✅')
        kb = [[self.btn(uid, f"✔️ Подтвердить #{a['id']}", 'ack', cid=cid, cname=cname, fid=a['id'])]
              for a in alerts[:10] if not a.get('acked_at')]
        kb.append([self.btn(uid, '🔄 Обновить', 'alerts', **c), self.btn(uid, '« Назад', 'cluster', **c)])
        return self.screen(chat, mid, text, kb)

    def cb_ack(self, uid, chat, mid, cid, cname, fid, back='alerts'):
        try:
            self.api(uid).ack_alert(cid, fid)
        except ApiError as err:
            return self.error(chat, err, mid)
        if back == 'none':
            return self.screen(chat, mid, f'✔️ Оповещение #{v.e(fid)} подтверждено', None)
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
        text = '<b>Активные оповещения</b>\n\n' + ('\n\n'.join(blocks[:15]) or 'Активных оповещений нет ✅')
        return self.screen(chat, mid, text, [[self.btn(uid, '« Кластеры', 'clusters')]])

    # search ------------------------------------------------------------------------
    def cb_ask_find(self, uid, chat, mid):
        self.pending[uid] = {'kind': 'find'}
        return self.screen(chat, mid, 'Введите имя или номер VM/CT:', None)

    def find(self, uid, chat, query):
        api = self.api(uid)
        q = query.strip().lower()
        try:
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
            return self.tg.send(chat, f'Ничего не найдено по «{v.e(query)}».')
        kb = [[self.btn(uid, f'{v.guest_button(x)} @ {v.cluster_name(c)}'[:60], 'guest',
                        g=self._g(c['id'], v.cluster_name(c), x))] for c, x in found[:20]]
        return self.tg.send(chat, f'Найдено: {len(found)}', kb)

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
            api = self.api(uid)
            if not api:
                continue
            try:
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
                    kb = [[self.btn(uid, '✔️ Подтвердить', 'ack', cid=c['id'], cname=v.cluster_name(c),
                                    fid=a['id'], back='none')]]
                    self.tg.send(uid, '🔔 ' + v.alert_text(a, v.cluster_name(c)), kb)
