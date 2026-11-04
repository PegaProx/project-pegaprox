# Telegram bot for PegaProx

The bot manages Proxmox through PegaProx. Each Telegram user links their own PegaProx
account, and the bot acts with that user's permissions: no more and no less than in the web UI.
Every action lands in the PegaProx audit log under that user.

It is a separate process that talks only to the PegaProx REST API, so it needs no changes to
PegaProx itself and can run on the PegaProx host or on any other host that reaches it.

## Features

- Clusters: health, nodes online, guests running.
- Nodes: CPU, RAM, disk, uptime; reboot and shutdown (PegaProx allows these only for a node
  in maintenance mode).
- VMs and containers: paged list, `/find`, start, shutdown, reboot, stop, reset, suspend.
  Destructive actions ask for confirmation.
- Snapshots: list, create (own name or automatic), rollback, delete.
- Backups: list, run a backup to a chosen storage (vzdump, snapshot mode, zstd).
- Migration to another node (live for a running VM).
- Firewall: datacenter (on/off, rules on/off) and the rules of a single VM/CT.
- Storage and the latest cluster tasks.
- Alerts: list active ones, acknowledge, and the bot pushes new ones (`/notify off` turns it off).
- PegaProx users (`/users` or the "👥 Users" button): list, create, change role, enable and
  disable, set a new password, reset 2FA, delete. Needs the `admin.users` permission; PegaProx's
  own limits (tenants, no role above your own, no deleting yourself or the last admin) apply as
  in the web UI. Passwords are taken only in a private chat, and the bot deletes the message
  right away.
- `/api METHOD /api/path [JSON]`: any PegaProx API call when the buttons are not enough,
  for example `/api GET /api/clusters/<id>/ha/status`.

## Install

Needs Debian/Ubuntu with access to PegaProx and to `api.telegram.org`. Usually that is the same
host or LXC that runs PegaProx.

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy its token.
2. On the host, from the repository checkout:
   ```bash
   sudo bash tgbot/deploy/install.sh
   ```
   The script installs the bot to `/opt/pegaprox-tg-bot` with its own venv, and creates the
   `pegaprox-tg-bot` system user, the settings file `/etc/pegaprox-tg-bot.env` and the
   `pegaprox-tg-bot` service.
3. Put the token into `/etc/pegaprox-tg-bot.env` (`TG_BOT_TOKEN=...`) and start it:
   ```bash
   sudo systemctl restart pegaprox-tg-bot
   journalctl -u pegaprox-tg-bot -f
   ```

### Settings (`/etc/pegaprox-tg-bot.env`)

| Variable | Default | Meaning |
|---|---|---|
| `TG_BOT_TOKEN` | | token from @BotFather, required |
| `PEGAPROX_URL` | `https://127.0.0.1:5000` | PegaProx address |
| `PEGAPROX_VERIFY_TLS` | `true` | `true`, a path to a CA bundle, or `false` for PegaProx's self-signed certificate on the same host (refused for any other host) |
| `TG_ALLOWED_IDS` | empty | comma-separated Telegram user ids; when set, everyone else is refused |
| `TG_ALERT_POLL` | `60` | seconds between checks for new alerts, `0` turns notifications off |
| `TG_DATA_DIR` | `/var/lib/pegaprox-tg-bot` | where linked accounts are stored (see below for another path) |

If PegaProx runs on another host, set its address in `PEGAPROX_URL` and either give it a
certificate the system trusts or point `PEGAPROX_VERIFY_TLS` at the CA bundle that signed it.
The bot refuses to start with `PEGAPROX_VERIFY_TLS=false` for anything but a loopback address,
since every request carries the user's API token.

The service runs with `ProtectSystem=strict`, so only `/var/lib/pegaprox-tg-bot` is writable.
For another `TG_DATA_DIR`, create the directory for the bot user first, then allow writes to it:

```bash
sudo install -d -m 0700 -o pegaprox-tg-bot -g pegaprox-tg-bot /path/to/data
sudo systemctl edit pegaprox-tg-bot    # add: [Service]  ReadWritePaths=/path/to/data
sudo systemctl restart pegaprox-tg-bot
```

The HTTP client is `requests`, so the standard `HTTPS_PROXY` / `NO_PROXY` variables work in the
same file if `api.telegram.org` is only reachable through a proxy. Keep the PegaProx address in
`NO_PROXY` in that case.

## Linking an account

1. In PegaProx: "My profile → API tokens" → create a token. The token's role can be lower than
   your own, for example `viewer` if Telegram should only be able to look.
2. In a private chat with the bot: `/login pgx_...`. The bot checks the token and deletes the
   message right away.
3. `/menu` opens the clusters.

`/logout` unlinks the account; revoke the token in PegaProx afterwards. If the token is revoked or
the user loses a permission, the bot loses it at once, since PegaProx checks every call itself.

## Security

- Tokens are stored encrypted (`accounts.json` plus the key `secret.key`, both mode 0600).
  The data directory must be readable only by the bot user.
- A token is accepted only in a private chat; in a group the bot deletes the message and asks the
  user to revoke the token.
- Buttons are bound to the user who opened them: someone else's buttons in a group do nothing.
- `TG_ALLOWED_IDS` closes the bot to everyone else entirely.

## Running by hand and tests

```bash
python -m tgbot --env /etc/pegaprox-tg-bot.env --debug
python -m pytest tests/test_tgbot.py tests/test_tgbot_users.py tests/test_tgbot_against_pegaprox.py tests/test_ha_exits.py
```
