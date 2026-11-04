# -*- coding: utf-8 -*-
"""Bot settings, read from the environment (or an env file passed with --env).

TG_BOT_TOKEN        token from @BotFather (required)
PEGAPROX_URL        address of PegaProx, default https://127.0.0.1:5000
PEGAPROX_VERIFY_TLS "true", "false" or a path to a CA bundle. Default "false",
                    because PegaProx on the same host usually runs a self-signed cert.
TG_ALLOWED_IDS      optional comma-separated Telegram user ids allowed to use the bot
TG_DATA_DIR         where linked accounts are stored, default /var/lib/pegaprox-tg-bot
TG_ALERT_POLL       seconds between checks for new alerts, default 60 (0 turns it off)
"""
import os
from dataclasses import dataclass, field


def _parse_env_file(path):
    out = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
                v = v[1:-1]
            out[k.strip()] = v
    return out


def _verify(value):
    v = (value or '').strip()
    if v.lower() in ('', '0', 'false', 'no', 'off'):
        return False
    if v.lower() in ('1', 'true', 'yes', 'on'):
        return True
    return v  # a CA bundle path


@dataclass
class Config:
    bot_token: str
    pegaprox_url: str = 'https://127.0.0.1:5000'
    verify_tls: object = False
    allowed_ids: set = field(default_factory=set)
    data_dir: str = '/var/lib/pegaprox-tg-bot'
    alert_poll: int = 60

    @classmethod
    def load(cls, env_file=None, environ=None):
        env = dict(os.environ if environ is None else environ)
        if env_file:
            file_env = _parse_env_file(env_file)
            file_env.update({k: v for k, v in env.items() if k in file_env and v})
            env.update(file_env)
        token = (env.get('TG_BOT_TOKEN') or '').strip()
        if not token:
            raise SystemExit('TG_BOT_TOKEN is not set')
        ids = set()
        for part in (env.get('TG_ALLOWED_IDS') or '').replace(';', ',').split(','):
            part = part.strip()
            if part:
                try:
                    ids.add(int(part))
                except ValueError:
                    raise SystemExit(f'TG_ALLOWED_IDS: "{part}" is not a number')
        try:
            poll = int(env.get('TG_ALERT_POLL') or 60)
        except ValueError:
            raise SystemExit('TG_ALERT_POLL must be a number of seconds')
        return cls(
            bot_token=token,
            pegaprox_url=(env.get('PEGAPROX_URL') or 'https://127.0.0.1:5000').rstrip('/'),
            verify_tls=_verify(env.get('PEGAPROX_VERIFY_TLS')),
            allowed_ids=ids,
            data_dir=env.get('TG_DATA_DIR') or '/var/lib/pegaprox-tg-bot',
            alert_poll=max(0, poll),
        )
