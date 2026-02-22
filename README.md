# ☁️ openclaw-skill-nextcloud

> OpenClaw skill — Nextcloud file management and sharing via WebDAV + OCS API

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-skill-blue)](https://openclaw.ai)
[![ClawHub](https://img.shields.io/badge/ClawHub-nextcloud-green)](https://clawhub.ai/rwx-g/nextcloud)

Full Nextcloud client for OpenClaw agents. Covers file/folder management (WebDAV) and sharing, tags, favorites, and user info (OCS). Includes interactive setup wizard, connection + permission validation, and a behavior restriction system via `config.json`.

## Install

```bash
clawhub install nextcloud
```

Or manually:

```bash
git clone https://github.com/rwx-g/openclaw-skill-nextcloud \
  ~/.openclaw/workspace/skills/nextcloud
```

## Setup

```bash
python3 scripts/setup.py   # credentials + permissions + connection test
python3 scripts/init.py    # validate all configured permissions
```

You'll need a Nextcloud **App Password**: Settings → Security → App passwords.

## What it can do

| Category | Operations |
|----------|-----------|
| Files | create, read, write, rename, move, copy |
| Folders | create, rename, move, copy |
| Search | search by filename (DASL) |
| Sharing | public links, user shares, permissions, expiry, password |
| Tags | list, create, assign, remove (system tags) |
| Favorites | toggle |
| Account | quota, user info, server capabilities |

## Configuration

Credentials → `~/.openclaw/secrets/nextcloud_creds` (chmod 600, never committed)

Behavior → `config.json` in skill directory:

```json
{
  "base_path": "/Jarvis",
  "allow_write": true,
  "allow_delete": false,
  "allow_share": true,
  "readonly_mode": false,
  "share_default_permissions": 1,
  "share_default_expire_days": null
}
```

## Requirements

- Python 3.9+
- `requests` (`pip install requests`)
- Network access to Nextcloud instance

## Documentation

- [SKILL.md](SKILL.md) — full skill instructions, CLI reference, templates
- [references/api.md](references/api.md) — WebDAV + OCS endpoint reference
- [references/troubleshooting.md](references/troubleshooting.md) — common errors and fixes

## License

[MIT](LICENSE)
