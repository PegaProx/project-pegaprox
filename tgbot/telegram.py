# -*- coding: utf-8 -*-
"""Minimal Telegram Bot API client (long polling), so the bot needs only `requests`."""
import logging
import time

import requests

log = logging.getLogger('tgbot.telegram')


class Telegram:
    def __init__(self, token, session=None, base='https://api.telegram.org'):
        self.url = f'{base}/bot{token}/'
        self.http = session or requests.Session()

    def call(self, method, **params):
        params = {k: v for k, v in params.items() if v is not None}
        try:
            r = self.http.post(self.url + method, json=params, timeout=params.get('timeout', 0) + 30)
            data = r.json()
        except (requests.RequestException, ValueError) as e:
            log.warning('Telegram %s failed: %s', method, e.__class__.__name__)
            return None
        if not data.get('ok'):
            log.warning('Telegram %s: %s', method, data.get('description'))
            return None
        return data.get('result')

    def updates(self, offset=None, timeout=50):
        res = self.call('getUpdates', offset=offset, timeout=timeout,
                        allowed_updates=['message', 'callback_query'])
        if res is None:
            time.sleep(3)
            return []
        return res

    def send(self, chat_id, text, keyboard=None, **kw):
        return self.call('sendMessage', chat_id=chat_id, text=text[:4096], parse_mode='HTML',
                         disable_web_page_preview=True,
                         reply_markup={'inline_keyboard': keyboard} if keyboard else None, **kw)

    def edit(self, chat_id, message_id, text, keyboard=None):
        res = self.call('editMessageText', chat_id=chat_id, message_id=message_id, text=text[:4096],
                        parse_mode='HTML', disable_web_page_preview=True,
                        reply_markup={'inline_keyboard': keyboard} if keyboard else None)
        if res is None:  # message too old or unchanged: send a fresh one
            return self.send(chat_id, text, keyboard)
        return res

    def answer(self, callback_id, text=None, alert=False):
        return self.call('answerCallbackQuery', callback_query_id=callback_id, text=text,
                         show_alert=alert or None)

    def delete(self, chat_id, message_id):
        return self.call('deleteMessage', chat_id=chat_id, message_id=message_id)

    def set_commands(self, commands):
        return self.call('setMyCommands', commands=[{'command': c, 'description': d} for c, d in commands])
