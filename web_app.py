from flask import Flask, render_template, request, redirect, url_for, flash
import meraki
import config
import os
import csv
import json
import threading
import datetime as dt
import re
import subprocess
import sys
from flask import jsonify

from backupFunctions import (
    backupWirelessComplete,
    backupSecuritySdwanSettings,
    backupSwitchSettings,
)
from restoreFunctions import (
    restoreWirelessComplete,
    restoreSecuritySdwanSettings,
    restoreSwitch,
    fullDeepRestore,
)

app = Flask(__name__)
app.secret_key = "meraki_enterprise_secret_key"

LOG_DIRECTORY = os.path.abspath(config.log_directory)
os.makedirs(LOG_DIRECTORY, exist_ok=True)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
AUTO_BACKUP_SETTINGS_PATH = os.path.abspath(config.auto_backup_settings_file)
AUTO_BACKUP_TASK_NAME = config.auto_backup_task_name
AUTO_BACKUP_BACKUP_PATH = os.path.abspath(config.backup_directory)
AUTO_BACKUP_STATUS_PATH = os.path.join(BASE_DIR, "auto_backup_status.json")

# ===== MERAKI DASHBOARD =====
dashboard = meraki.DashboardAPI(
    config.API_KEY,
    suppress_logging=False,
    log_path=LOG_DIRECTORY
)

# ===== GLOBAL STATE =====
operation_logs = []
MAX_LOGS = 500
is_backup_running = False
is_restore_running = False


ALLOWED_BACKUP_MODES = {"wireless", "security_sdwan", "switching", "full_enterprise"}
AUTO_BACKUP_ALL_ORGS = "__all_orgs__"
SCHEDULE_INTERVAL_OPTIONS = [
    ("hourly:1", "last hr."),
    ("daily:1", "24 hr."),
    ("daily:7", "7 days"),
    ("daily:14", "14 days"),
    ("daily:30", "30 days"),
]
ALLOWED_SCHEDULE_INTERVALS = {value for value, _ in SCHEDULE_INTERVAL_OPTIONS}


def default_auto_backup_settings():
    return {
        "enabled": False,
        "org_id": "",
        "network_id": "__all__",
        "backup_mode": "full_enterprise",
        "schedule_interval": "daily:7",
        "frequency_days": 7,
        "run_time": "02:00",
        "backup_path": AUTO_BACKUP_BACKUP_PATH,
        "task_name": AUTO_BACKUP_TASK_NAME,
    }


def normalize_backup_mode(mode: str) -> str:
    mode_value = (mode or "").strip()
    if mode_value not in ALLOWED_BACKUP_MODES:
        return "full_enterprise"
    return mode_value


def normalize_schedule_interval(value, fallback_days=7):
    interval_value = str(value or "").strip().lower()
    if interval_value in ALLOWED_SCHEDULE_INTERVALS:
        return interval_value

    try:
        days = max(1, int(fallback_days))
    except (TypeError, ValueError):
        days = 7

    fallback_value = f"daily:{days}"
    if fallback_value in ALLOWED_SCHEDULE_INTERVALS:
        return fallback_value
    return "daily:7"


def parse_schedule_interval(value):
    schedule_type, multiplier = normalize_schedule_interval(value).split(":", 1)
    return schedule_type.upper(), str(int(multiplier))


def load_auto_backup_settings():
    settings = default_auto_backup_settings()
    if os.path.exists(AUTO_BACKUP_SETTINGS_PATH):
        try:
            with open(AUTO_BACKUP_SETTINGS_PATH, "r", encoding="utf-8") as fh:
                saved = json.load(fh)
            if isinstance(saved, dict):
                settings.update(saved)
        except Exception:
            pass
    settings["backup_mode"] = normalize_backup_mode(settings.get("backup_mode", "full_enterprise"))
    settings["schedule_interval"] = normalize_schedule_interval(
        settings.get("schedule_interval"),
        settings.get("frequency_days", 7),
    )
    settings["frequency_days"] = int(settings["schedule_interval"].split(":", 1)[1]) if settings["schedule_interval"].startswith("daily:") else 1
    settings["backup_path"] = AUTO_BACKUP_BACKUP_PATH
    settings["task_name"] = AUTO_BACKUP_TASK_NAME
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(settings.get("run_time", ""))):
        settings["run_time"] = default_auto_backup_settings()["run_time"]
    return settings


def save_auto_backup_settings_file(settings: dict):
    payload = default_auto_backup_settings()
    payload.update(settings)
    payload["backup_mode"] = normalize_backup_mode(payload.get("backup_mode", "full_enterprise"))
    payload["schedule_interval"] = normalize_schedule_interval(
        payload.get("schedule_interval"),
        payload.get("frequency_days", 7),
    )
    payload["frequency_days"] = int(payload["schedule_interval"].split(":", 1)[1]) if payload["schedule_interval"].startswith("daily:") else 1
    payload["enabled"] = bool(payload.get("enabled"))
    payload["backup_path"] = AUTO_BACKUP_BACKUP_PATH
    payload["task_name"] = AUTO_BACKUP_TASK_NAME

    with open(AUTO_BACKUP_SETTINGS_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    return payload


def default_auto_backup_status():
    return {
        "state": "idle",
        "message": "No auto backup has run yet.",
        "last_started_at": "-",
        "last_finished_at": "-",
        "last_updated_at": "-",
        "last_error": "-",
    }


def load_auto_backup_status():
    status = default_auto_backup_status()
    if os.path.exists(AUTO_BACKUP_STATUS_PATH):
        try:
            with open(AUTO_BACKUP_STATUS_PATH, "r", encoding="utf-8") as fh:
                saved = json.load(fh)
            if isinstance(saved, dict):
                status.update(saved)
        except Exception:
            pass
    return status


def save_auto_backup_status(
    state: str,
    message: str,
    last_error: str = "",
    started_at: str = "",
    finished_at: str = "",
):
    status = load_auto_backup_status()
    timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status["state"] = state
    status["message"] = message
    status["last_updated_at"] = timestamp
    if started_at:
        status["last_started_at"] = started_at
    if finished_at:
        status["last_finished_at"] = finished_at
    status["last_error"] = last_error or "-"

    with open(AUTO_BACKUP_STATUS_PATH, "w", encoding="utf-8") as fh:
        json.dump(status, fh, indent=2, ensure_ascii=False)

    return status


def parse_schtasks_list_output(output: str):
    values = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def get_auto_backup_task_status():
    status = {
        "task_name": AUTO_BACKUP_TASK_NAME,
        "exists": "No",
        "status": "Not created",
        "next_run_time": "-",
        "last_run_time": "-",
        "last_result": "-",
        "task_to_run": "-",
    }

    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", AUTO_BACKUP_TASK_NAME, "/FO", "LIST", "/V"],
            capture_output=True,
            text=True,
            check=True,
            cwd=BASE_DIR,
        )
        values = parse_schtasks_list_output(result.stdout)
        status.update(
            {
                "exists": "Yes",
                "status": values.get("Status", "Unknown"),
                "next_run_time": values.get("Next Run Time", "-"),
                "last_run_time": values.get("Last Run Time", "-"),
                "last_result": values.get("Last Result", "-"),
                "task_to_run": values.get("Task To Run", "-"),
            }
        )
    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:
        status["status"] = "schtasks not available"

    return status


def build_auto_backup_task_command():
    python_executable = sys.executable
    runner_path = os.path.join(BASE_DIR, "auto_backup_runner.py")
    return f'"{python_executable}" "{runner_path}"'


def create_or_update_auto_backup_task(settings: dict):
    schedule_type, modifier = parse_schedule_interval(settings.get("schedule_interval"))
    subprocess.run(
        [
            "schtasks",
            "/Create",
            "/TN",
            AUTO_BACKUP_TASK_NAME,
            "/SC",
            schedule_type,
            "/MO",
            modifier,
            "/ST",
            settings["run_time"],
            "/TR",
            build_auto_backup_task_command(),
            "/F",
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=BASE_DIR,
    )


def delete_auto_backup_task():
    subprocess.run(
        ["schtasks", "/Delete", "/TN", AUTO_BACKUP_TASK_NAME, "/F"],
        capture_output=True,
        text=True,
        check=True,
        cwd=BASE_DIR,
    )


def sync_auto_backup_task_from_settings():
    settings = load_auto_backup_settings()
    if not settings.get("enabled"):
        return

    try:
        create_or_update_auto_backup_task(settings)
        add_log("Auto backup task synced to Windows Task Scheduler")
    except Exception as exc:
        add_log(f"Auto backup task sync failed: {exc}")


def add_log(message: str):
    timestamp = dt.datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {message}"

    operation_logs.append(log_entry)

    if len(operation_logs) > MAX_LOGS:
        operation_logs.pop(0)

    print(f"[WEB LOG] {message}")


def load_organizations():
    try:
        return dashboard.organizations.getOrganizations()
    except Exception as e:
        add_log(f"Error loading organizations: {str(e)}")
        return []


def load_networks_for_org(org_id: str):
    if not org_id or org_id == AUTO_BACKUP_ALL_ORGS:
        return []
    try:
        networks = dashboard.organizations.getOrganizationNetworks(org_id)
        add_log(f"Selected Org ID: {org_id}")
        add_log(f"Found {len(networks)} networks in organization")
        return networks
    except Exception as e:
        add_log(f"Error loading networks: {str(e)}")
        return []


def _safe_name(value: str) -> str:
    text = (value or "").strip()
    text = re.sub(r'[<>:"/\\|?*]+', "", text)
    text = text.replace(",", "")
    text = re.sub(r"\s+", "_", text)
    return text or "Unknown"


def create_snapshot_folder(org_name: str, network_label: str, backup_mode: str):
    timestamp = dt.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    safe_org = _safe_name(org_name)
    if backup_mode == "full_enterprise":
        snapshot_name = f"{safe_org}_{timestamp}"
    else:
        safe_network = _safe_name(network_label)
        snapshot_name = f"{safe_org}_{safe_network}_{timestamp}"

    snapshot_path = os.path.join(config.backup_directory, snapshot_name)
    os.makedirs(snapshot_path, exist_ok=True)

    return snapshot_path, snapshot_name


def get_all_snapshots():
    backup_root = config.backup_directory

    if not os.path.exists(backup_root):
        return []

    snapshots = sorted(
        [
            f for f in os.listdir(backup_root)
            if os.path.isdir(os.path.join(backup_root, f))
        ],
        key=lambda name: os.path.getmtime(os.path.join(backup_root, name)),
        reverse=True
    )

    return snapshots


def create_export_folder(org_name: str):
    timestamp = dt.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    safe_org = org_name.replace(" ", "_").replace(",", "")
    export_root = os.path.join(config.backup_directory, "exports")
    os.makedirs(export_root, exist_ok=True)

    export_name = f"{safe_org}_{timestamp}"
    export_path = os.path.join(export_root, export_name)
    os.makedirs(export_path, exist_ok=True)
    return export_path, export_name


def _csv_cell(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    if value is None:
        return ""
    return value


def write_csv_records(file_path: str, rows: list):
    headers = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                headers.append(key)

    with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _csv_cell(row.get(k)) for k in headers})


def normalize_network_name(name: str) -> str:
    return (name or "").strip().lower().replace(" ", "_")


def find_latest_snapshot_folder_for_network(network_name: str):
    snapshots = get_all_snapshots()
    if not snapshots:
        return None, None

    target_normalized = normalize_network_name(network_name)
    for snap in snapshots:
        snapshot_network_root = os.path.join(
            config.backup_directory,
            snap,
            "network"
        )
        if not os.path.exists(snapshot_network_root):
            continue

        for folder in os.listdir(snapshot_network_root):
            if normalize_network_name(folder) == target_normalized:
                return os.path.join(snapshot_network_root, folder), snap

    return None, None


def snapshot_has_mode_data(network_folder: str, backup_mode: str) -> bool:
    """
    Check whether the selected snapshot folder has data for the requested restore mode.
    """
    if not network_folder or not os.path.exists(network_folder):
        return False

    if backup_mode == "wireless":
        return os.path.exists(os.path.join(network_folder, "wireless"))
    if backup_mode == "security_sdwan":
        return os.path.exists(os.path.join(network_folder, "security_sdwan"))
    if backup_mode == "switching":
        return os.path.exists(os.path.join(network_folder, "switch"))

    # full_enterprise: require at least one major component folder
    return any(
        os.path.exists(os.path.join(network_folder, component))
        for component in ("wireless", "security_sdwan", "switch")
    )


def find_latest_snapshot_folder_for_network_and_mode(network_name: str, backup_mode: str):
    snapshots = get_all_snapshots()
    if not snapshots:
        return None, None

    target_normalized = normalize_network_name(network_name)
    for snap in snapshots:
        snapshot_network_root = os.path.join(
            config.backup_directory,
            snap,
            "network"
        )
        if not os.path.exists(snapshot_network_root):
            continue

        for folder in os.listdir(snapshot_network_root):
            if normalize_network_name(folder) != target_normalized:
                continue

            candidate = os.path.join(snapshot_network_root, folder)
            if snapshot_has_mode_data(candidate, backup_mode):
                return candidate, snap

    return None, None


def find_snapshot_folder_for_network_and_mode(snapshot_name: str, network_name: str, backup_mode: str):
    if not snapshot_name:
        return None, None

    snapshot_network_root = os.path.join(
        config.backup_directory,
        snapshot_name,
        "network"
    )
    if not os.path.exists(snapshot_network_root):
        return None, None

    target_normalized = normalize_network_name(network_name)
    for folder in os.listdir(snapshot_network_root):
        if normalize_network_name(folder) != target_normalized:
            continue
        candidate = os.path.join(snapshot_network_root, folder)
        if snapshot_has_mode_data(candidate, backup_mode):
            return candidate, snapshot_name

    return None, None


def find_mode_compatible_folders_in_snapshot(snapshot_name: str, backup_mode: str):
    """
    Return all network folders in a snapshot that can satisfy the requested mode.
    """
    if not snapshot_name:
        return []

    snapshot_network_root = os.path.join(
        config.backup_directory,
        snapshot_name,
        "network"
    )
    if not os.path.exists(snapshot_network_root):
        return []

    matches = []
    for folder in os.listdir(snapshot_network_root):
        candidate = os.path.join(snapshot_network_root, folder)
        if not os.path.isdir(candidate):
            continue
        if snapshot_has_mode_data(candidate, backup_mode):
            matches.append((candidate, folder))

    return matches


def find_snapshot_folder_for_source_network_and_mode(
    snapshot_name: str,
    source_network_name: str,
    backup_mode: str
):
    if not snapshot_name or not source_network_name:
        return None, None

    snapshot_network_root = os.path.join(
        config.backup_directory,
        snapshot_name,
        "network"
    )
    if not os.path.exists(snapshot_network_root):
        return None, None

    target_normalized = normalize_network_name(source_network_name)
    for folder in os.listdir(snapshot_network_root):
        if normalize_network_name(folder) != target_normalized:
            continue
        candidate = os.path.join(snapshot_network_root, folder)
        if snapshot_has_mode_data(candidate, backup_mode):
            return candidate, snapshot_name

    return None, None


def resolve_target_networks(org_id: str, network_id: str):
    org_networks = dashboard.organizations.getOrganizationNetworks(org_id)
    if network_id == "__all__":
        return org_networks

    for net in org_networks:
        if net["id"] == network_id:
            return [net]

    raise Exception("Cannot find target network from API")


def enrich_network_with_details(network: dict):
    """
    Ensure fields like configTemplateId are present by fetching network detail.
    """
    network_id = network.get("id")
    if not network_id:
        return network
    try:
        detail = dashboard.networks.getNetwork(network_id)
        merged = dict(network)
        merged.update(detail or {})
        return merged
    except Exception:
        return network


def log_template_binding_status(network: dict):
    network_name = network.get("name", network.get("id", "Unknown"))
    config_template_id = network.get("configTemplateId")
    if config_template_id:
        add_log(
            f"Template Binding: {network_name} is bound to config template ({config_template_id})"
        )
    else:
        add_log(f"Template Binding: {network_name} is not bound to config template")


def export_clients_usage_csv(org_id: str, org_name: str, network_id: str):
    target_networks = resolve_target_networks(org_id, network_id)
    export_path, export_name = create_export_folder(org_name)

    client_rows = []
    usage_rows = []

    for target_network in target_networks:
        target_net_id = target_network["id"]
        target_net_name = target_network["name"]
        add_log(f"Exporting client list for: {target_net_name}")

        try:
            clients = dashboard.networks.getNetworkClients(
                target_net_id,
                timespan=7 * 24 * 60 * 60,
                perPage=1000,
                total_pages="all"
            )
        except Exception as e:
            add_log(f"Client export skipped ({target_net_name}): {e}")
            continue

        for client in clients:
            row = {
                "networkId": target_net_id,
                "networkName": target_net_name,
            }
            row.update(client)
            client_rows.append(row)

        client_ids = [c.get("id") or c.get("mac") or c.get("ip") for c in clients]
        client_ids = [cid for cid in client_ids if cid]

        chunk_size = 100
        for i in range(0, len(client_ids), chunk_size):
            chunk = client_ids[i:i + chunk_size]
            try:
                usage_items = dashboard.networks.getNetworkClientsUsageHistories(
                    target_net_id,
                    clients=",".join(chunk),
                    timespan=7 * 24 * 60 * 60,
                    perPage=1000,
                    total_pages="all"
                )
            except Exception as e:
                add_log(f"Usage history export skipped chunk ({target_net_name}): {e}")
                continue

            for item in usage_items:
                row = {
                    "networkId": target_net_id,
                    "networkName": target_net_name,
                }
                row.update(item)
                usage_rows.append(row)

    if client_rows:
        write_csv_records(os.path.join(export_path, "client_list.csv"), client_rows)
    if usage_rows:
        write_csv_records(os.path.join(export_path, "client_usage_history.csv"), usage_rows)

    return export_name, export_path, len(client_rows), len(usage_rows)


def export_sm_inventory_csv(org_id: str, org_name: str, network_id: str):
    target_networks = resolve_target_networks(org_id, network_id)
    export_path, export_name = create_export_folder(org_name)

    device_rows = []
    user_rows = []
    unsupported_networks = 0

    sm_device_fields = [
        "ownerEmail",
        "ownerUsername",
        "lastUser",
        "ip",
        "publicIp",
        "systemType",
        "osName",
        "serialNumber",
        "tags",
        "url",
    ]

    for target_network in target_networks:
        target_net_id = target_network["id"]
        target_net_name = target_network["name"]
        add_log(f"Exporting SM inventory for: {target_net_name}")

        try:
            devices = dashboard.sm.getNetworkSmDevices(
                target_net_id,
                fields=sm_device_fields,
                perPage=1000,
                total_pages="all"
            )
            for device in devices:
                row = {
                    "networkId": target_net_id,
                    "networkName": target_net_name,
                }
                row.update(device)
                device_rows.append(row)
        except Exception as e:
            error_text = str(e).lower()
            if (
                "only supports systems manager network" in error_text
                or "does not contain a systems manager network" in error_text
            ):
                unsupported_networks += 1
                add_log(
                    f"SM device export skipped ({target_net_name}): this network is not Systems Manager-enabled"
                )
            else:
                add_log(f"SM device export failed ({target_net_name})")

        try:
            users = dashboard.sm.getNetworkSmUsers(target_net_id)
            for user in users:
                row = {
                    "networkId": target_net_id,
                    "networkName": target_net_name,
                }
                row.update(user)
                user_rows.append(row)
        except Exception as e:
            error_text = str(e).lower()
            if "does not contain a systems manager network" in error_text:
                add_log(
                    f"SM user export skipped ({target_net_name}): this network is not Systems Manager-enabled"
                )
            else:
                add_log(f"SM user export failed ({target_net_name})")

    if device_rows:
        write_csv_records(os.path.join(export_path, "sm_device_inventory.csv"), device_rows)
    if user_rows:
        write_csv_records(os.path.join(export_path, "sm_users.csv"), user_rows)

    return export_name, export_path, len(device_rows), len(user_rows), unsupported_networks


def run_full_backup(org_id: str, network_id: str, backup_mode: str = "full_enterprise"):
    global is_backup_running

    try:
        backup_mode = normalize_backup_mode(backup_mode)
        is_backup_running = True
        add_log("Starting Backup (Snapshot Mode)")
        add_log(f"Backup Mode: {backup_mode}")

        orgs = dashboard.organizations.getOrganizations()
        if str(org_id) == AUTO_BACKUP_ALL_ORGS:
            if network_id != "__all__":
                raise Exception("All organizations mode requires All networks.")
            target_orgs = orgs
            add_log(f"Backing up ALL organizations ({len(target_orgs)} total)")
        else:
            target_org = None

            for org in orgs:
                if str(org["id"]) == str(org_id):
                    target_org = org
                    break

            if not target_org:
                raise Exception("Organization not found from API")

            target_orgs = [target_org]

        class DummyLogger:
            def info(self, msg):
                print(f"[LOGGER INFO] {msg}")

            def error(self, msg):
                print(f"[LOGGER ERROR] {msg}")

            def warning(self, msg):
                print(f"[LOGGER WARNING] {msg}")

        logger = DummyLogger()

        for target_org in target_orgs:
            current_org_id = str(target_org["id"])
            org_name = target_org["name"]
            add_log(f"Target Organization: {org_name}")

            networks = dashboard.organizations.getOrganizationNetworks(current_org_id)
            if network_id == "__all__":
                target_networks = networks
                snapshot_network_label = "All Network"
                add_log(f"Backing up ALL networks in org ({len(target_networks)} total)")
            else:
                target_network = None
                for net in networks:
                    if net["id"] == network_id:
                        target_network = net
                        break

                if not target_network:
                    raise Exception("Target Network not found")

                target_networks = [target_network]
                snapshot_network_label = target_network["name"]
                add_log(f"Backing up Network: {target_network['name']}")

            snapshot_path, snapshot_name = create_snapshot_folder(
                org_name,
                snapshot_network_label,
                backup_mode
            )
            add_log(f"Created Snapshot: {snapshot_name}")

            for target_network in target_networks:
                target_network = enrich_network_with_details(target_network)
                net_name = target_network.get("name", target_network.get("id", "Unknown"))
                log_template_binding_status(target_network)
                add_log(f"Processing backup for network: {net_name}")

                if backup_mode in ("wireless", "full_enterprise"):
                    try:
                        add_log("Backing up Wireless (full scope)...")
                        backupWirelessComplete(
                            target_network,
                            snapshot_path,
                            dashboard,
                            logger,
                            org_id=current_org_id
                        )
                    except Exception as e:
                        add_log(f"Wireless Backup Skipped ({net_name}): {str(e)}")

                if backup_mode in ("security_sdwan", "full_enterprise"):
                    try:
                        add_log("Backing up Security & SD-WAN settings...")
                        backupSecuritySdwanSettings(target_network, snapshot_path, dashboard, logger)
                    except Exception as e:
                        add_log(f"Security & SD-WAN Backup Skipped ({net_name}): {str(e)}")

                if backup_mode in ("switching", "full_enterprise"):
                    try:
                        add_log("Backing up Switch Settings...")
                        backupSwitchSettings(
                            target_network,
                            snapshot_path,
                            dashboard,
                            logger,
                            org_id=current_org_id
                        )
                    except Exception as e:
                        add_log(f"Switch Backup Skipped ({net_name}): {str(e)}")

            if backup_mode == "switching":
                try:
                    add_log("Running bundled Switching export: Clients + Usage CSV...")
                    export_name, export_path, client_count, usage_count = export_clients_usage_csv(
                        current_org_id,
                        org_name,
                        network_id
                    )
                    add_log(
                        f"Client/Usage CSV Export Completed: {export_name} "
                        f"(clients={client_count}, usage={usage_count}, path={export_path})"
                    )
                except Exception as e:
                    add_log(f"Client/Usage Export Error: {e}")

                try:
                    add_log("Running bundled Switching export: SM Inventory CSV...")
                    export_name, export_path, device_count, user_count, unsupported_networks = export_sm_inventory_csv(
                        current_org_id,
                        org_name,
                        network_id
                    )
                    if device_count == 0 and user_count == 0 and unsupported_networks > 0:
                        add_log("SM Inventory export skipped: selected network(s) are not Systems Manager-enabled")
                    else:
                        add_log(
                            f"SM Inventory CSV Export Completed: {export_name} "
                            f"(devices={device_count}, users={user_count}, path={export_path})"
                        )
                except Exception as e:
                    add_log(f"SM Inventory Export Error: {e}")

        add_log("Backup Snapshot Completed Successfully")
        return True

    except Exception as e:
        add_log(f"Backup Error: {str(e)}")
        return False

    finally:
        is_backup_running = False
        add_log("Backup Job Finished")


def run_full_restore(
    org_id: str,
    network_id: str,
    backup_mode: str = "full_enterprise",
    selected_snapshot_name: str = "",
    selected_source_network_name: str = ""
):
    global is_restore_running

    try:
        backup_mode = normalize_backup_mode(backup_mode)
        is_restore_running = True
        add_log("===== RESTORE STARTED =====")
        add_log(f"Restore Mode: {backup_mode}")
        if selected_snapshot_name:
            add_log(f"Restore Snapshot Selection: {selected_snapshot_name}")
        else:
            add_log("Restore Snapshot Selection: latest matching snapshot (auto)")
        if selected_source_network_name:
            add_log(f"Restore Source Network Selection: {selected_source_network_name}")
        target_networks = resolve_target_networks(org_id, network_id)
        if network_id == "__all__":
            add_log(f"Restoring ALL networks in org ({len(target_networks)} total)")

        restored_count = 0
        skipped_count = 0
        failed_count = 0

        for target_network in target_networks:
            try:
                target_network = enrich_network_with_details(target_network)
                target_net_name = target_network["name"]
                target_net_id = target_network["id"]
                log_template_binding_status(target_network)

                if selected_snapshot_name and selected_source_network_name:
                    target_folder, selected_snapshot = find_snapshot_folder_for_source_network_and_mode(
                        selected_snapshot_name,
                        selected_source_network_name,
                        backup_mode
                    )
                elif selected_snapshot_name:
                    target_folder, selected_snapshot = find_snapshot_folder_for_network_and_mode(
                        selected_snapshot_name,
                        target_net_name,
                        backup_mode
                    )
                else:
                    target_folder, selected_snapshot = find_latest_snapshot_folder_for_network_and_mode(
                        target_net_name,
                        backup_mode
                    )
                if (
                    not target_folder
                    and selected_snapshot_name
                    and not selected_source_network_name
                ):
                    # Cross-network restore fallback:
                    # allow using the snapshot when it contains exactly one compatible source network.
                    compatible_folders = find_mode_compatible_folders_in_snapshot(
                        selected_snapshot_name,
                        backup_mode
                    )
                    if len(compatible_folders) == 1:
                        target_folder, source_network_name = compatible_folders[0]
                        selected_snapshot = selected_snapshot_name
                        add_log(
                            f"Cross-network restore enabled: source snapshot network "
                            f"'{source_network_name}' -> target network '{target_net_name}'"
                        )
                    elif len(compatible_folders) > 1:
                        add_log(
                            f"Restore skipped (snapshot {selected_snapshot_name} has multiple "
                            f"{backup_mode} source networks; cannot auto-pick for {target_net_name})"
                        )
                        skipped_count += 1
                        continue

                if not target_folder:
                    if selected_snapshot_name:
                        add_log(
                            f"Restore skipped (snapshot {selected_snapshot_name} has no {backup_mode} data): "
                            f"{target_net_name}"
                        )
                    else:
                        add_log(f"Restore skipped (no {backup_mode} snapshot data): {target_net_name}")
                    skipped_count += 1
                    continue

                if selected_snapshot_name:
                    add_log(f"Using Selected Snapshot: {selected_snapshot}")
                else:
                    add_log(f"Using Latest Matching Snapshot: {selected_snapshot}")
                add_log(f"Restoring for network: {target_net_name}")

                if backup_mode == "wireless":
                    restoreWirelessComplete(target_net_id, target_folder, dashboard)
                elif backup_mode == "security_sdwan":
                    restoreSecuritySdwanSettings(target_net_id, target_folder, dashboard)
                elif backup_mode == "switching":
                    restoreSwitch(
                        target_net_id,
                        target_folder,
                        dashboard,
                        org_id=org_id,
                        target_network=target_network
                    )
                else:
                    fullDeepRestore(
                        target_net_id,
                        target_folder,
                        dashboard,
                        org_id=org_id,
                        target_network=target_network
                    )

                restored_count += 1

            except Exception as e:
                failed_count += 1
                add_log(f"Restore failed for network {target_network.get('name', 'Unknown')}: {e}")

        if failed_count > 0:
            add_log(
                f"RESTORE COMPLETED WITH ERRORS: restored={restored_count}, "
                f"skipped={skipped_count}, failed={failed_count}"
            )
        else:
            add_log(f"RESTORE SUCCESS (Snapshot Applied): restored={restored_count}, skipped={skipped_count}")

    except Exception as e:
        add_log(f"Restore Error: {str(e)}")

    finally:
        is_restore_running = False
        add_log("Restore Job Finished")


@app.route("/", methods=["GET", "POST"])
def index():
    orgs = []
    networks = []
    snapshots = get_all_snapshots()

    selected_org = request.values.get("org_id")
    selected_network = request.values.get("network_id")
    selected_backup_mode = normalize_backup_mode(request.values.get("backup_mode", "full_enterprise"))
    selected_snapshot = request.values.get("snapshot_name", "")
    selected_source_network = request.values.get("source_network_name", "")
    source_networks = []


    orgs = load_organizations()
    if orgs:
        add_log("Loaded Organizations from Meraki API")

    if not selected_org and orgs:
        selected_org = str(orgs[0]["id"])

    if selected_org:
        networks = load_networks_for_org(selected_org)
        if not selected_network and networks:
            selected_network = networks[0]["id"]

    if selected_snapshot:
        source_networks = [
            folder_name
            for _, folder_name in find_mode_compatible_folders_in_snapshot(
                selected_snapshot,
                selected_backup_mode
            )
        ]
        if selected_source_network and selected_source_network not in source_networks:
            selected_source_network = ""

    return render_template(
        "index.html",
        orgs=orgs,
        networks=networks,
        selected_org=selected_org,
        selected_network=selected_network,
        selected_backup_mode=selected_backup_mode,
        selected_snapshot=selected_snapshot,
        selected_source_network=selected_source_network,
        snapshots=snapshots,
        source_networks=source_networks,
        logs=operation_logs,
        is_backup_running=is_backup_running,
        is_restore_running=is_restore_running
    )


@app.route("/auto-backup-settings", methods=["GET"])
def auto_backup_settings():
    settings = load_auto_backup_settings()
    orgs = load_organizations()
    if orgs:
        add_log("Loaded Organizations from Meraki API")

    selected_org = request.args.get("org_id") or settings.get("org_id") or (str(orgs[0]["id"]) if orgs else "")
    selected_network = settings.get("network_id", "__all__")
    networks = load_networks_for_org(selected_org) if selected_org else []

    if selected_org == AUTO_BACKUP_ALL_ORGS:
        selected_network = "__all__"

    if networks and selected_network != "__all__":
        network_ids = {str(net["id"]) for net in networks}
        if str(selected_network) not in network_ids:
            selected_network = "__all__"

    settings["org_id"] = selected_org
    settings["network_id"] = selected_network

    return render_template(
        "auto_backup_settings.html",
        orgs=orgs,
        networks=networks,
        selected_org=selected_org,
        selected_network=selected_network,
        settings=settings,
        schedule_interval_options=SCHEDULE_INTERVAL_OPTIONS,
        backup_path=AUTO_BACKUP_BACKUP_PATH,
        task_status=get_auto_backup_task_status(),
        auto_backup_status=load_auto_backup_status(),
    )


@app.route("/auto-backup-status", methods=["GET"])
def auto_backup_status():
    return jsonify(load_auto_backup_status())


@app.route("/auto-backup-settings/save", methods=["POST"])
def save_auto_backup_settings():
    org_id = (request.form.get("org_id") or "").strip()
    network_id = (request.form.get("network_id") or "").strip()
    backup_mode = normalize_backup_mode(request.form.get("backup_mode", "full_enterprise"))
    schedule_interval = normalize_schedule_interval(request.form.get("schedule_interval"), 7)
    run_time = (request.form.get("run_time") or "").strip()
    enabled = request.form.get("enabled") == "1"

    if not org_id:
        flash("Please select an organization before saving the schedule.", "danger")
        return redirect(url_for("auto_backup_settings"))

    if org_id == AUTO_BACKUP_ALL_ORGS:
        network_id = "__all__"

    if not network_id:
        flash("Please select a network before saving the schedule.", "danger")
        return redirect(url_for("auto_backup_settings", org_id=org_id))

    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", run_time):
        flash("Run time must be in HH:MM format.", "danger")
        return redirect(url_for("auto_backup_settings", org_id=org_id))

    settings = save_auto_backup_settings_file(
        {
            "enabled": enabled,
            "org_id": org_id,
            "network_id": network_id,
            "backup_mode": backup_mode,
            "schedule_interval": schedule_interval,
            "run_time": run_time,
        }
    )

    try:
        if enabled:
            create_or_update_auto_backup_task(settings)
            flash("Auto backup schedule saved and synced to Windows Task Scheduler.", "success")
        else:
            try:
                delete_auto_backup_task()
            except subprocess.CalledProcessError:
                pass
            flash("Auto backup settings saved with schedule disabled.", "info")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        flash(f"Settings were saved, but Windows Task Scheduler update failed: {detail}", "warning")

    return redirect(url_for("auto_backup_settings", org_id=org_id))


@app.route("/auto-backup-settings/delete", methods=["POST"])
def delete_auto_backup_schedule():
    settings = load_auto_backup_settings()
    settings["enabled"] = False
    save_auto_backup_settings_file(settings)

    try:
        delete_auto_backup_task()
        flash("Scheduled task deleted successfully.", "success")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        flash(f"Local settings were disabled, but scheduled task deletion failed: {detail}", "warning")

    return redirect(url_for("auto_backup_settings", org_id=settings.get("org_id", "")))


@app.route("/execute_action", methods=["POST"])
def execute_action():
    global is_backup_running, is_restore_running

    org_id = request.form.get("org_id")
    network_id = request.form.get("network_id")
    action = request.form.get("action")
    backup_mode = normalize_backup_mode(request.form.get("backup_mode", "full_enterprise"))
    snapshot_name = (request.form.get("snapshot_name") or "").strip()
    source_network_name = (request.form.get("source_network_name") or "").strip()

    if not org_id or not network_id:
        flash("กรุณาเลือก Organization และ Network ก่อน", "danger")
        return redirect(url_for("index", org_id=org_id or "", network_id=network_id or ""))

    try:
        orgs = dashboard.organizations.getOrganizations()
    except Exception:
        orgs = []
    target_org = next((org for org in orgs if str(org["id"]) == str(org_id)), None)
    org_name = target_org["name"] if target_org else f"org_{org_id}"

    if action == "backup":
        if is_backup_running:
            flash("Backup กำลังทำงานอยู่", "warning")
            return redirect(url_for("index", org_id=org_id, network_id=network_id))

        if is_restore_running:
            flash("Restore กำลังทำงานอยู่", "warning")
            return redirect(url_for("index", org_id=org_id, network_id=network_id))

        add_log("Manual Backup Triggered (Full Snapshot from Dashboard)")

        thread = threading.Thread(
            target=run_full_backup,
            args=(org_id, network_id, backup_mode)
        )
        thread.daemon = True
        thread.start()

        flash("Full Backup Snapshot Started", "info")

    elif action == "restore":
        if is_restore_running:
            flash("Restore กำลังทำงานอยู่", "warning")
            return redirect(url_for("index", org_id=org_id, network_id=network_id))

        if is_backup_running:
            flash("Backup กำลังทำงานอยู่", "warning")
            return redirect(url_for("index", org_id=org_id, network_id=network_id))

        thread = threading.Thread(
            target=run_full_restore,
            args=(org_id, network_id, backup_mode, snapshot_name, source_network_name)
        )
        thread.daemon = True
        thread.start()

        if snapshot_name:
            flash(f"Restore Started (Snapshot: {snapshot_name})", "info")
        else:
            flash("Restore Started (Latest matching snapshot)", "info")

    return redirect(
        url_for(
            "index",
            org_id=org_id,
            network_id=network_id,
            backup_mode=backup_mode,
            snapshot_name=snapshot_name,
            source_network_name=source_network_name
        )
    )


if __name__ == "__main__":
    add_log("Meraki Enterprise Backup & Restore Dashboard Started")
    sync_auto_backup_task_from_settings()
    app.run(host="0.0.0.0", port=5000, debug=True)
