---
name: nextcloud
description: "Nextcloud file and folder management via WebDAV + OCS API. Use when: (1) creating, reading, writing, renaming, moving, copying, or deleting files/folders, (2) listing or searching directory contents, (3) creating public or user share links, (4) toggling favorites or managing system tags, (5) checking storage quota. NOT for: Nextcloud Talk, Calendar/Contacts (use CalDAV), app management (requires admin), or large binary transfers."
homepage: https://github.com/rwx-g/openclaw-skill-nextcloud
compatibility: Python 3.9+ · requests · network access to Nextcloud instance
metadata:
  {
    "openclaw": {
      "emoji": "☁️",
      "requires": { "env": ["NC_URL", "NC_USER", "NC_PASS"] },
      "primaryEnv": "NC_PASS"
    }
  }
ontology:
  reads: []
  writes: [files, folders, shares, tags, favorites]
---

# Nextcloud Skill

Full Nextcloud client: WebDAV (files/folders) + OCS (sharing, tags, user info).
Credentials: `~/.openclaw/secrets/nextcloud_creds` · Config: `config.json` in skill dir.

## Trigger phrases

Load this skill immediately when the user says anything like:

- "upload / save / write this file on Nextcloud / NC / cloud"
- "create a folder on Nextcloud", "mkdir in NC"
- "share this / create a share link / get a public link for [file or folder]"
- "list / browse / show what's in [folder] on Nextcloud"
- "search for [file] in NC", "find [file] on Nextcloud"
- "read / get / download [file] from Nextcloud"
- "rename / move / copy [file] on Nextcloud"
- "check my storage quota", "how much space on NC"
- "tag this file", "mark as favorite on Nextcloud"

## Quick Start

```bash
python3 scripts/nextcloud.py config    # verify credentials + active config
python3 scripts/nextcloud.py quota     # test connection + show storage
python3 scripts/nextcloud.py ls /      # list root directory
```

## Setup

```bash
python3 scripts/setup.py   # interactive: credentials + permissions + connection test
python3 scripts/init.py    # validate all configured permissions against live instance
```

**Manual** — `~/.openclaw/secrets/nextcloud_creds` (chmod 600):
```
NC_URL=https://cloud.example.com
NC_USER=username
NC_PASS=app-password
```
App password: Nextcloud → Settings → Security → App passwords.

**config.json** — behavior restrictions:

| Key | Default | Effect |
|-----|---------|--------|
| `base_path` | `"/"` | Restrict agent to subtree (e.g. `"/Jarvis"`) |
| `allow_write` | `true` | mkdir, write, rename, copy |
| `allow_delete` | `true` | delete files and folders |
| `allow_share` | `true` | create/manage share links |
| `readonly_mode` | `false` | override: block all writes |
| `share_default_permissions` | `1` | 1=read-only, 31=full |
| `share_default_expire_days` | `null` | auto-expire shares (days) |

## Module usage

```python
from scripts.nextcloud import NextcloudClient
nc = NextcloudClient()
nc.write_file("/Jarvis/notes.md", "# Notes\n...")
nc.mkdir("/Jarvis/Articles")
link = nc.create_share_link("/Jarvis/report.pdf")
print(link["url"])
```

## CLI reference

```bash
# Files & folders
python3 scripts/nextcloud.py mkdir /path/folder
python3 scripts/nextcloud.py write /path/file.md --content "# Title"
python3 scripts/nextcloud.py write /path/file.md --file local.md
python3 scripts/nextcloud.py read  /path/file.md
python3 scripts/nextcloud.py rename /old /new
python3 scripts/nextcloud.py copy   /src /dst
python3 scripts/nextcloud.py delete /path
python3 scripts/nextcloud.py exists /path          # exit 0/1

# Listing & search
python3 scripts/nextcloud.py ls /path --depth 2 --json
python3 scripts/nextcloud.py search "keyword" --path /folder --limit 20

# Favorites & tags
python3 scripts/nextcloud.py favorite /path/file.md
python3 scripts/nextcloud.py tags
python3 scripts/nextcloud.py tag-create "research"
python3 scripts/nextcloud.py tag-assign <file_id> <tag_id>

# Sharing
python3 scripts/nextcloud.py share /path                     # read-only public link
python3 scripts/nextcloud.py share /path --permissions 31 --expire 2025-12-31
python3 scripts/nextcloud.py share /path --password secret --no-download
python3 scripts/nextcloud.py shares /path                    # list existing shares
python3 scripts/nextcloud.py share-delete <share_id>

# Account
python3 scripts/nextcloud.py quota
python3 scripts/nextcloud.py config
```

## Templates

### Save a report and share it
```python
nc = NextcloudClient()
nc.mkdir("/Reports/2025")
nc.write_file("/Reports/2025/summary.md", report_content)
link = nc.create_share_link("/Reports/2025/summary.md", permissions=1)
# → return link["url"] to the user
```

### Structured workspace setup
```bash
python3 scripts/nc_setup.py --root Jarvis --folders Articles,LinkedIn,Recherche,Veille
```

### Append to a running log
```python
nc.append_to_file("/Jarvis/log.md", f"\n## {today}\n{entry}\n")
```

### Read and update a JSON list
```python
items = nc.read_json("/Jarvis/Veille/articles.json")
items["articles"].append(new_article)
nc.write_json("/Jarvis/Veille/articles.json", items)
```

### Tag a file after creation
```python
ls = nc.list_dir("/Jarvis/Articles", depth=1)
file_id = next(f["file_id"] for f in ls if f["name"] == "article.md")
tags = nc.get_tags()
tag_id = next(t["id"] for t in tags if t["name"] == "published")
nc.assign_tag(file_id, tag_id)
```

## Ideas
- Sandbox the agent with `base_path: "/Jarvis"` — it can't touch anything else
- Store agent-produced Markdown files and auto-share a read-only link in the reply
- Use `append_to_file` for rolling logs or changelogs
- Use `write_json` + `read_json` for persistent state between sessions
- Auto-tag files by category (research / draft / published)

## Share permissions
`1`=Read · `2`=Update · `4`=Create · `8`=Delete · `16`=Share · `31`=All

## Combine with

| Skill | Workflow |
|-------|----------|
| **ghost** | Write a post → save Markdown draft to NC → publish to Ghost |
| **summarize** | Summarize a URL → save summary as `.md` to NC → create share link |
| **gmail** | Receive an attachment → save to NC → share link back to sender |
| **obsidian** | Sync Obsidian vault notes to NC for remote backup |
| **self-improving-agent** | Log agent learnings to NC for persistent, searchable history |

## API reference
See `references/api.md` for WebDAV/OCS endpoint details, PROPFIND properties, and error codes.

## Troubleshooting
See `references/troubleshooting.md` for common errors and fixes.
