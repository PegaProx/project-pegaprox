# -*- coding: utf-8 -*-
"""Run the bot: python -m tgbot [--env /etc/pegaprox-tg-bot.env]"""
import argparse
import logging

from .bot import Bot
from .config import Config
from .store import Store
from .telegram import Telegram


def main():
    p = argparse.ArgumentParser(prog='python -m tgbot', description='Telegram bot for PegaProx')
    p.add_argument('--env', help='env file with TG_BOT_TOKEN, PEGAPROX_URL and the rest')
    p.add_argument('--debug', action='store_true')
    args = p.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    # the token is part of every Telegram URL: keep urllib3 from logging request lines
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    cfg = Config.load(args.env)
    Bot(cfg, Telegram(cfg.bot_token), Store(cfg.data_dir)).run()


if __name__ == '__main__':
    main()
