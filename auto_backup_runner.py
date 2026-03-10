import json
import os
import sys
import datetime as dt

import config

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
os.chdir(BASE_DIR)

from web_app import normalize_backup_mode, run_full_backup, save_auto_backup_status


SETTINGS_PATH = os.path.abspath(config.auto_backup_settings_file)


def load_settings():
    if not os.path.exists(SETTINGS_PATH):
        raise FileNotFoundError(f"Auto backup settings file not found: {SETTINGS_PATH}")

    with open(SETTINGS_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main():
    settings = load_settings()

    if not settings.get("enabled"):
        save_auto_backup_status("idle", "Auto backup is disabled.")
        print("Auto backup is disabled. Nothing to do.")
        return 0

    org_id = (settings.get("org_id") or "").strip()
    network_id = (settings.get("network_id") or "").strip()
    backup_mode = normalize_backup_mode(settings.get("backup_mode", "full_enterprise"))

    if not org_id or not network_id:
        raise ValueError("Auto backup settings are incomplete: org_id and network_id are required.")

    started_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_auto_backup_status(
        "running",
        f"Auto backup is running ({backup_mode}).",
        started_at=started_at,
    )

    success = run_full_backup(org_id=org_id, network_id=network_id, backup_mode=backup_mode)
    finished_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if success:
        save_auto_backup_status(
            "success",
            "Auto backup completed successfully.",
            started_at=started_at,
            finished_at=finished_at,
        )
        return 0

    save_auto_backup_status(
        "error",
        "Auto backup finished with errors.",
        last_error="Backup job reported an error. Check operation logs and scheduler result.",
        started_at=started_at,
        finished_at=finished_at,
    )
    return 0


if __name__ == "__main__":
    exit_code = 0
    try:
        exit_code = int(main() or 0)
    except Exception as exc:
        finished_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_auto_backup_status(
            "error",
            "Auto backup failed to start or crashed.",
            last_error=str(exc),
            finished_at=finished_at,
        )
        print(f"Auto backup runner failed: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(exit_code)
