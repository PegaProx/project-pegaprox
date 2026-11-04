#!/bin/bash
# Installs the Telegram bot for PegaProx as a systemd service.
# Run as root from the repository checkout:  bash tgbot/deploy/install.sh
# Works on the PegaProx host itself or on any other Debian/Ubuntu host that reaches it.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST=/opt/pegaprox-tg-bot
ENV_FILE=/etc/pegaprox-tg-bot.env
UNIT=/etc/systemd/system/pegaprox-tg-bot.service

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi

if ! command -v python3 >/dev/null || ! python3 -m venv --help >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-venv
fi

id pegaprox-tg-bot >/dev/null 2>&1 || useradd --system --home-dir /var/lib/pegaprox-tg-bot --shell /usr/sbin/nologin pegaprox-tg-bot

mkdir -p "$DEST"
rm -rf "$DEST/tgbot"
cp -r "$SRC" "$DEST/tgbot"
find "$DEST/tgbot" -name '__pycache__' -prune -exec rm -rf {} +
[ -x "$DEST/venv/bin/python" ] || python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q -r "$DEST/tgbot/requirements.txt"

if [ ! -f "$ENV_FILE" ]; then
    install -m 0640 -o root -g pegaprox-tg-bot "$SRC/deploy/pegaprox-tg-bot.env.example" "$ENV_FILE"
    echo "Created $ENV_FILE: put the bot token (TG_BOT_TOKEN) there, then run:"
    echo "  systemctl restart pegaprox-tg-bot"
fi

install -m 0644 "$SRC/deploy/pegaprox-tg-bot.service" "$UNIT"
systemctl daemon-reload
systemctl enable pegaprox-tg-bot >/dev/null
if grep -q '^TG_BOT_TOKEN=123456:ABC' "$ENV_FILE"; then
    echo "Bot installed but not started: TG_BOT_TOKEN in $ENV_FILE is still the example."
else
    systemctl restart pegaprox-tg-bot
    echo "Bot started. Logs: journalctl -u pegaprox-tg-bot -f"
fi
