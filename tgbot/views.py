# -*- coding: utf-8 -*-
"""Text formatting for the bot's screens (Russian)."""
import html
from datetime import datetime

STATUS_ICON = {'running': '🟢', 'stopped': '🔴', 'paused': '🟡', 'suspended': '🟡'}
TYPE_LABEL = {'qemu': 'VM', 'lxc': 'CT'}
SEV_ICON = {'critical': '🔥', 'warning': '⚠️', 'info': 'ℹ️'}


def e(s):
    return html.escape(str(s if s is not None else ''), quote=False)


def size(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return '?'
    for unit in ('Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ'):
        if abs(n) < 1024 or unit == 'ПБ':
            return f'{n:.0f} {unit}' if unit == 'Б' else f'{n:.1f} {unit}'
        n /= 1024


def pct(part, total):
    try:
        return f'{100.0 * float(part) / float(total):.0f}%'
    except (TypeError, ValueError, ZeroDivisionError):
        return '?'


def uptime(sec):
    try:
        sec = int(sec)
    except (TypeError, ValueError):
        return '?'
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return f'{d} д {h} ч' if d else f'{h} ч {m} мин'


def when(ts):
    if ts in (None, ''):
        return '?'
    try:
        if isinstance(ts, (int, float)) or str(ts).isdigit():
            return datetime.fromtimestamp(int(ts)).strftime('%d.%m %H:%M')
        return datetime.fromisoformat(str(ts).replace('Z', '+00:00')).strftime('%d.%m %H:%M')
    except (ValueError, OSError):
        return str(ts)[:16]


def cluster_name(c):
    return c.get('display_name') or c.get('name') or c.get('id')


def cluster_line(c):
    icon = '🟢' if c.get('connected') else '🔴'
    return f"{icon} {cluster_name(c)}"


def node_line(n):
    icon = '🟢' if n.get('status') == 'online' else '🔴'
    name = n.get('node') or n.get('name')
    cpu = n.get('cpu')
    cpu_s = f'{float(cpu) * 100:.0f}%' if isinstance(cpu, (int, float)) else '?'
    return (f"{icon} <b>{e(name)}</b>  CPU {cpu_s}, RAM {pct(n.get('mem'), n.get('maxmem'))}"
            f" ({size(n.get('mem'))} из {size(n.get('maxmem'))})")


def node_text(n):
    name = n.get('node') or n.get('name')
    lines = [f"🖥 Нода <b>{e(name)}</b>",
             f"Статус: {e(n.get('status', '?'))}"]
    if n.get('status') == 'online':
        cpu = n.get('cpu')
        if isinstance(cpu, (int, float)):
            lines.append(f"CPU: {float(cpu) * 100:.0f}% из {e(n.get('maxcpu', '?'))} ядер")
        lines.append(f"RAM: {size(n.get('mem'))} из {size(n.get('maxmem'))} ({pct(n.get('mem'), n.get('maxmem'))})")
        if n.get('maxdisk'):
            lines.append(f"Диск: {size(n.get('disk'))} из {size(n.get('maxdisk'))}")
        if n.get('uptime'):
            lines.append(f"Аптайм: {uptime(n.get('uptime'))}")
    if n.get('maintenance_mode') or n.get('maintenance'):
        lines.append('🛠 На обслуживании')
    return '\n'.join(lines)


def guest_button(v):
    icon = STATUS_ICON.get(v.get('status'), '⚪')
    return f"{icon} {v.get('vmid')} {v.get('name') or ''} ({TYPE_LABEL.get(v.get('type'), v.get('type'))})"[:60]


def guest_text(v, cname):
    icon = STATUS_ICON.get(v.get('status'), '⚪')
    return (f"{icon} <b>{e(v.get('name') or '')}</b> ({TYPE_LABEL.get(v.get('type'), e(v.get('type')))} {e(v.get('vmid'))})\n"
            f"Кластер: {e(cname)}\nНода: {e(v.get('node'))}\nСостояние: {e(v.get('status', '?'))}")


def task_line(t):
    status = t.get('status') or ('выполняется' if not t.get('endtime') else '?')
    ok = status == 'OK'
    icon = '✅' if ok else ('⏳' if not t.get('endtime') else '❌')
    target = t.get('id') or ''
    return (f"{icon} {when(t.get('starttime'))} <b>{e(t.get('type', '?'))}</b> {e(target)} "
            f"на {e(t.get('node', '?'))} ({e(t.get('user', ''))}){'' if ok else ': ' + e(status)}")


def alert_text(a, cname=None):
    icon = SEV_ICON.get((a.get('severity') or '').lower(), '⚠️')
    lines = [f"{icon} <b>{e(a.get('message') or a.get('metric') or 'Оповещение')}</b>"]
    if cname:
        lines.append(f"Кластер: {e(cname)}")
    target = ' '.join(x for x in (a.get('target_type'), a.get('target_name')) if x)
    if target:
        lines.append(f"Объект: {e(target)}")
    if a.get('metric'):
        val = a.get('current_value')
        thr = a.get('threshold')
        lines.append(f"{e(a.get('metric'))}: {e(val)}" + (f" (порог {e(a.get('operator') or '')} {e(thr)})" if thr not in (None, '') else ''))
    lines.append(f"С {when(a.get('triggered_at'))}")
    if a.get('acked_at'):
        lines.append(f"Подтверждено: {e(a.get('acked_by') or '')}")
    return '\n'.join(lines)


def fw_rule_line(r):
    on = str(r.get('enable', 0)) in ('1', 'True', 'true')
    parts = [r.get('type', ''), r.get('action', '')]
    if r.get('macro'):
        parts.append(r['macro'])
    if r.get('proto'):
        parts.append(r['proto'])
    if r.get('source'):
        parts.append('из ' + r['source'])
    if r.get('dest'):
        parts.append('в ' + r['dest'])
    if r.get('dport'):
        parts.append('порт ' + str(r['dport']))
    if r.get('iface'):
        parts.append(r['iface'])
    text = ' '.join(str(p) for p in parts if p)
    comment = f" ({r['comment']})" if r.get('comment') else ''
    return f"{'✅' if on else '⛔'} #{r.get('pos')} {e(text)}{e(comment)}"


def snapshot_line(s):
    return f"📸 <b>{e(s.get('name'))}</b> {when(s.get('snaptime'))} {e(s.get('description') or '')}".strip()


def backup_line(b):
    return f"💾 {when(b.get('ctime'))} {e(b.get('storage') or '')} {size(b.get('size'))} <code>{e(b.get('volid', ''))}</code>"
