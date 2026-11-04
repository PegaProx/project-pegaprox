# -*- coding: utf-8 -*-
"""Linked accounts: Telegram user id -> PegaProx API token.

Tokens are encrypted with a key kept next to the data file (both 0600). Whoever reads
the data directory as root can still use the tokens, so keep the directory private;
the encryption protects against the file leaking on its own (backups, copies).
"""
import json
import os
import threading

from cryptography.fernet import Fernet, InvalidToken


class Store:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        self._path = os.path.join(data_dir, 'accounts.json')
        self._key_path = os.path.join(data_dir, 'secret.key')
        self._lock = threading.Lock()
        self._fernet = Fernet(self._load_key())
        self._data = self._read()

    def _load_key(self):
        if os.path.exists(self._key_path):
            with open(self._key_path, 'rb') as f:
                return f.read().strip()
        key = Fernet.generate_key()
        fd = os.open(self._key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(key)
        return key

    def _read(self):
        if not os.path.exists(self._path):
            return {}
        with open(self._path, encoding='utf-8') as f:
            return json.load(f)

    def _write(self):
        tmp = self._path + '.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(self._data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self._path)

    def link(self, tg_id, token, info=None):
        with self._lock:
            self._data[str(tg_id)] = {
                'token': self._fernet.encrypt(token.encode()).decode(),
                'info': info or {},
                'notify': True,
                'seen_alerts': [],
            }
            self._write()

    def unlink(self, tg_id):
        with self._lock:
            existed = self._data.pop(str(tg_id), None) is not None
            if existed:
                self._write()
            return existed

    def token(self, tg_id):
        rec = self._data.get(str(tg_id))
        if not rec:
            return None
        try:
            return self._fernet.decrypt(rec['token'].encode()).decode()
        except (InvalidToken, KeyError):
            return None

    def get(self, tg_id):
        return self._data.get(str(tg_id))

    def set_notify(self, tg_id, on):
        with self._lock:
            rec = self._data.get(str(tg_id))
            if rec:
                rec['notify'] = bool(on)
                self._write()

    def mark_seen(self, tg_id, keys, keep=500):
        """Remember alert ids already sent. Returns the ids that are new."""
        with self._lock:
            rec = self._data.get(str(tg_id))
            if not rec:
                return []
            seen = rec.get('seen_alerts') or []
            known = set(seen)
            new = [k for k in keys if k not in known]
            if new:
                rec['seen_alerts'] = (seen + new)[-keep:]
                self._write()
            return new

    def linked_ids(self):
        return [int(k) for k in list(self._data.keys())]
