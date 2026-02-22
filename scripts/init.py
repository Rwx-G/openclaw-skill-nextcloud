#!/usr/bin/env python3
"""
init.py — Validate the Nextcloud skill configuration.
Tests the connection and each configured permission against the real instance.
All test artifacts are cleaned up automatically.

Usage: python3 scripts/init.py
"""

import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nextcloud import NextcloudClient, NextcloudError, PermissionDeniedError

SKILL_DIR   = Path(__file__).resolve().parent.parent
CONFIG_FILE = SKILL_DIR / "config.json"
CREDS_FILE  = Path.home() / ".openclaw" / "secrets" / "nextcloud_creds"
LOG_DIR     = SKILL_DIR / ".skill-logs"

TEST_DIR  = "__skill_test__"
TEST_FILE = f"{TEST_DIR}/test.txt"
TEST_CONTENT = "nextcloud-skill-init-check"


class Results:
    def __init__(self):
        self.passed  = []
        self.failed  = []
        self.skipped = []
        self._entries = []

    def _record(self, status: str, label: str, detail: str = ""):
        self._entries.append({
            "ts":     datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": status,
            "check":  label,
            "detail": detail,
        })

    def ok(self, label: str, detail: str = ""):
        self.passed.append(label)
        self._record("pass", label, detail)
        suffix = f"  {detail}" if detail else ""
        print(f"  ✓  {label}{suffix}")

    def fail(self, label: str, reason: str = ""):
        self.failed.append(label)
        self._record("fail", label, reason)
        suffix = f"  → {reason}" if reason else ""
        print(f"  ✗  {label}{suffix}")

    def skip(self, label: str, reason: str = ""):
        self.skipped.append(label)
        self._record("skip", label, reason)
        print(f"  ~  {label}  (skipped: {reason})")

    def summary(self):
        total   = len(self.passed) + len(self.failed)
        skipped = len(self.skipped)
        print(f"\n  {len(self.passed)}/{total} checks passed", end="")
        if skipped:
            print(f", {skipped} skipped (disabled in config)", end="")
        print()
        if self.failed:
            print("\n  Failed checks:")
            for f in self.failed:
                print(f"    ✗  {f}")

    def write_log(self):
        """Append structured results to .skill-logs/init.jsonl"""
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            log_file = LOG_DIR / "init.jsonl"
            run_entry = {
                "ts":      datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "skill":   "nextcloud",
                "passed":  len(self.passed),
                "failed":  len(self.failed),
                "skipped": len(self.skipped),
                "checks":  self._entries,
            }
            with log_file.open("a") as f:
                f.write(json.dumps(run_entry) + "\n")
            print(f"\n  Log written → {log_file}")
        except Exception as e:
            print(f"\n  (Log write failed: {e})")


def _prefixed(path: str, base: str) -> str:
    """Ensure path is inside base_path."""
    base = base.rstrip("/") or ""
    return f"{base}/{path}"


def main():
    print("┌─────────────────────────────────────────┐")
    print("│   Nextcloud Skill — Init Check          │")
    print("└─────────────────────────────────────────┘")

    # ── Pre-flight ─────────────────────────────────────────────────────────────
    if not CREDS_FILE.exists():
        print(f"\n✗ Credentials not found: {CREDS_FILE}")
        print("  Run setup.py first:  python3 scripts/setup.py")
        sys.exit(1)

    try:
        nc = NextcloudClient()
    except NextcloudError as e:
        print(f"\n✗ {e}")
        sys.exit(1)

    cfg  = nc.cfg
    base = cfg.get("base_path", "/").rstrip("/") or ""
    ro   = cfg.get("readonly_mode", False)
    r    = Results()

    test_dir  = _prefixed(TEST_DIR,  base)
    test_file = _prefixed(TEST_FILE, base)
    share_id  = None

    # ── 1. Connection ──────────────────────────────────────────────────────────
    print("\n● Connection\n")
    try:
        info  = nc.get_user_info()
        quota = info.get("quota", {})
        used  = quota.get("used",  0)
        total = quota.get("total", 0)
        def _fmt(b):
            for unit in ("B", "KB", "MB", "GB", "TB"):
                if abs(b) < 1024.0: return f"{b:.1f} {unit}"
                b /= 1024.0
            return f"{b:.1f} PB"
        storage = f"{_fmt(used)} / {_fmt(total)}" if total > 0 else _fmt(used)
        r.ok("Connect", f"user={info.get('id', '?')}  storage={storage}")
    except Exception as e:
        r.fail("Connect", str(e))
        print("\n  Cannot proceed without a valid connection. Check credentials.")
        r.summary()
        sys.exit(1)

    # ── 2. Scope / base_path ───────────────────────────────────────────────────
    print("\n● Scope\n")
    try:
        items = nc.list_dir(base or "/")
        r.ok("Read base_path", f"path='{base or '/'}' ({len(items)} items)")
    except Exception as e:
        r.fail("Read base_path", str(e))

    # ── 3. Write ───────────────────────────────────────────────────────────────
    print("\n● Write permissions\n")

    if ro:
        r.skip("Write (mkdir)",  "readonly_mode=true")
        r.skip("Write (file)",   "readonly_mode=true")
    elif not cfg.get("allow_write", True):
        r.skip("Write (mkdir)",  "allow_write=false")
        r.skip("Write (file)",   "allow_write=false")
    else:
        try:
            nc.mkdir(test_dir)
            r.ok("Write (mkdir)", f"created {test_dir}")
        except Exception as e:
            r.fail("Write (mkdir)", str(e))

        try:
            nc.write_file(test_file, TEST_CONTENT)
            r.ok("Write (file)", f"created {test_file}")
        except Exception as e:
            r.fail("Write (file)", str(e))

    # ── 4. Read ────────────────────────────────────────────────────────────────
    if not ro and cfg.get("allow_write", True) and nc.exists(test_file):
        try:
            content = nc.read_file(test_file)
            if content.strip() == TEST_CONTENT:
                r.ok("Read (file)", "content matches")
            else:
                r.fail("Read (file)", f"unexpected content: {content[:40]!r}")
        except Exception as e:
            r.fail("Read (file)", str(e))

    # ── 5. Share ───────────────────────────────────────────────────────────────
    print("\n● Share permissions\n")

    if not cfg.get("allow_share", True):
        r.skip("Share (create)", "allow_share=false")
        r.skip("Share (delete)", "allow_share=false")
    elif ro:
        r.skip("Share (create)", "readonly_mode=true")
        r.skip("Share (delete)", "readonly_mode=true")
    else:
        target = test_dir if nc.exists(test_dir) else (base or "/")
        try:
            share = nc.create_share_link(target, permissions=1)
            share_id = share.get("share_id")
            r.ok("Share (create)", f"url={share.get('url')}")
        except Exception as e:
            r.fail("Share (create)", str(e))

        if share_id:
            if not cfg.get("allow_delete", True):
                # When allow_delete=false the server may also deny OCS share deletion
                # for non-owner contexts (Nextcloud 33+). Skip gracefully.
                r.skip("Share (delete)", "allow_delete=false → skipping (server may deny)")
            else:
                try:
                    nc.delete_share(share_id)
                    share_id = None
                    r.ok("Share (delete)")
                except Exception as e:
                    r.fail("Share (delete)", str(e))

    # ── 6. Delete ──────────────────────────────────────────────────────────────
    print("\n● Delete permissions\n")

    if ro:
        r.skip("Delete (file)",   "readonly_mode=true")
        r.skip("Delete (folder)", "readonly_mode=true")
    elif not cfg.get("allow_delete", True):
        r.skip("Delete (file)",   "allow_delete=false")
        r.skip("Delete (folder)", "allow_delete=false")
    else:
        if nc.exists(test_file):
            try:
                nc.delete(test_file)
                r.ok("Delete (file)", f"removed {test_file}")
            except Exception as e:
                r.fail("Delete (file)", str(e))

        if nc.exists(test_dir):
            try:
                nc.delete(test_dir)
                r.ok("Delete (folder)", f"removed {test_dir}")
            except Exception as e:
                r.fail("Delete (folder)", str(e))

    # ── Cleanup: best-effort delete of test artifacts ─────────────────────────
    # If allow_delete=false AND the NC server enforces it (403), we can't clean
    # up programmatically — expected behaviour, not a bug.

    # Clean up dangling share link (best-effort; OCS delete, not WebDAV)
    if share_id is not None:
        try:
            nc.delete_share(share_id)
        except Exception:
            pass  # non-fatal; share links expire naturally

    leftover = []
    for path in [test_file, test_dir]:
        if nc.exists(path):
            if not nc._force_delete(path):
                leftover.append(path)
    if leftover:
        print(f"\n  ℹ  Test folder left in Nextcloud (delete disabled on server):")
        for p in leftover:
            print(f"     {p}")
        print(f"     → Delete manually: Nextcloud → Files → /Jarvis/__skill_test__/")

    # ── 7. Server capabilities ─────────────────────────────────────────────────
    print("\n● Server\n")
    try:
        caps  = nc.get_capabilities()
        nc_ver = caps.get("version", {}).get("string", "?")
        r.ok("Capabilities", f"Nextcloud {nc_ver}")
    except Exception as e:
        r.fail("Capabilities", str(e))

    # ── Summary ────────────────────────────────────────────────────────────────
    print("\n┌─────────────────────────────────────────┐")
    print("│   Init check complete                   │")
    print("└─────────────────────────────────────────┘")
    r.summary()

    r.write_log()

    if r.failed:
        print("\n  Review config.json and nextcloud_creds, then re-run setup.py.\n")
        sys.exit(1)
    else:
        print("\n  Skill is ready to use. ✓\n")


if __name__ == "__main__":
    main()
