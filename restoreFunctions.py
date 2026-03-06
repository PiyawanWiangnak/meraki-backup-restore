import os
import json
import re
import ipaddress
from urllib.parse import urlparse


# ==============================
# 🔧 HELPER: LOAD JSON SAFE
# ==============================
def load_json_safe(file_path):
    if not os.path.exists(file_path):
        print(f"[RESTORE SKIP] File not found: {file_path}")
        return None

    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ==============================
# 📡 RESTORE SSIDs (MR)
# ==============================
def restoreSsids(network_id, network_folder, dashboard):
    ssids_file = os.path.join(
        network_folder,
        "ssids",
        "ssids.json"
    )

    print(f"[RESTORE] Looking for SSID file: {ssids_file}")

    ssids = load_json_safe(ssids_file)
    if not ssids:
        return

    print(f"[RESTORE] Found {len(ssids)} SSIDs in snapshot")

    for ssid in ssids:
        try:
            number = ssid.get("number")
            name = ssid.get("name")
            enabled = ssid.get("enabled", False)
            auth_mode = ssid.get("authMode", "open")
            encryption = ssid.get("encryptionMode", "open")
            ip_assignment = ssid.get("ipAssignmentMode", "NAT mode")

            if encryption is None:
                encryption = "open"

            print(f"[RESTORE] SSID {number}: {name}")

            dashboard.wireless.updateNetworkWirelessSsid(
                network_id,
                number,
                name=name,
                enabled=enabled,
                authMode=auth_mode,
                encryptionMode=encryption,
                ipAssignmentMode=ip_assignment
            )

        except Exception as e:
            print(f"[RESTORE ERROR] SSID {number}: {str(e)}")

    print("[RESTORE DONE] SSIDs restored")


# ==============================
# 🛜 RESTORE WIRELESS SETTINGS
# ==============================
def restoreWirelessSettings(network_id, network_folder, dashboard):
    file_path = os.path.join(
        network_folder,
        "wireless",
        "wireless_settings.json"
    )

    settings = load_json_safe(file_path)
    if not settings:
        return

    try:
        print("[RESTORE] Wireless global settings")
        dashboard.wireless.updateNetworkWirelessSettings(
            network_id,
            **settings
        )
    except Exception as e:
        print(f"[RESTORE ERROR] Wireless settings: {str(e)}")


# ==============================
# 🖧 RESTORE SWITCH PORTS (MS)
# ==============================
def _load_json_if_exists(file_path):
    if not os.path.exists(file_path):
        return None
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _ensure_list(payload):
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        # Common wrappers from some endpoints/backups.
        for key in ("items", "data", "rules", "servers", "alerts"):
            if isinstance(payload.get(key), list):
                return payload.get(key)
        return [payload]
    return []


def _ensure_dict(payload):
    return payload if isinstance(payload, dict) else {}


def _drop_keys(payload, *keys):
    if not isinstance(payload, dict):
        return {}
    blocked = set(keys)
    return {k: v for k, v in payload.items() if k not in blocked}


def _is_valid_meraki_serial(value):
    if not isinstance(value, str):
        return False
    return re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", value.strip().upper()) is not None


def _is_valid_ip_or_cidr_or_any(value):
    if not isinstance(value, str):
        return False
    token = value.strip()
    if token.lower() == "any":
        return True
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def _is_valid_http_url(value):
    if not isinstance(value, str):
        return False
    token = value.strip()
    if not token:
        return False
    parsed = urlparse(token)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _network_has_appliance(dashboard, network_id):
    try:
        devices = dashboard.networks.getNetworkDevices(network_id)
    except Exception:
        devices = []
    for device in devices:
        model = str(device.get("model", "")).upper()
        product_type = str(device.get("productType", "")).lower()
        if model.startswith("MX") or product_type == "appliance":
            return True
    # Fallback: some networks expose appliance product type even when no MX serial
    # appears in getNetworkDevices yet.
    try:
        network_detail = dashboard.networks.getNetwork(network_id)
        product_types = _ensure_list(network_detail.get("productTypes"))
        normalized = {str(p).lower() for p in product_types}
        if "appliance" in normalized:
            return True
    except Exception:
        pass
    return False


def _collect_snapshot_lan_subnets(security_root):
    subnets = []

    single_lan = _load_json_if_exists(os.path.join(security_root, "single_lan.json"))
    if isinstance(single_lan, dict):
        subnet = single_lan.get("subnet")
        if isinstance(subnet, str) and subnet.strip():
            subnets.append(subnet.strip())

    vlans = _ensure_list(_load_json_if_exists(os.path.join(security_root, "vlans.json")))
    for vlan in vlans:
        if not isinstance(vlan, dict):
            continue
        subnet = vlan.get("subnet")
        if isinstance(subnet, str) and subnet.strip():
            subnets.append(subnet.strip())

    return subnets


def _collect_target_lan_subnets(network_id, dashboard):
    subnets = []

    try:
        single_lan = dashboard.appliance.getNetworkApplianceSingleLan(network_id)
        if isinstance(single_lan, dict):
            subnet = single_lan.get("subnet")
            if isinstance(subnet, str) and subnet.strip():
                subnets.append(subnet.strip())
    except Exception:
        pass

    try:
        vlans = _ensure_list(dashboard.appliance.getNetworkApplianceVlans(network_id))
        for vlan in vlans:
            if not isinstance(vlan, dict):
                continue
            subnet = vlan.get("subnet")
            if isinstance(subnet, str) and subnet.strip():
                subnets.append(subnet.strip())
    except Exception:
        pass

    return subnets


def _ip_is_in_any_subnet(ip_text, subnets):
    if not isinstance(ip_text, str):
        return False
    token = ip_text.strip()
    if not token:
        return False
    try:
        ip_obj = ipaddress.ip_address(token)
    except ValueError:
        return False

    for subnet in subnets:
        try:
            if ip_obj in ipaddress.ip_network(subnet, strict=False):
                return True
        except ValueError:
            continue
    return False


def _sanitize_ssid_l3_firewall_payload(payload, ssid_number):
    if not isinstance(payload, dict):
        return {}
    cleaned = dict(payload)
    rules = _ensure_list(cleaned.get("rules"))
    cleaned_rules = []

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        rule_clean = dict(rule)
        dst_cidr = rule_clean.get("destCidr", rule_clean.get("dstCidr"))
        if isinstance(dst_cidr, str):
            token = dst_cidr.strip()
            if token.lower() == "local lan":
                token = "any"
            elif token.lower() == "any":
                token = "any"
            if not _is_valid_ip_or_cidr_or_any(token):
                print(
                    f"[RESTORE WARN] SSID {ssid_number} firewall_l3 rule {idx} skipped "
                    f"(invalid destCidr: {dst_cidr})"
                )
                continue
            rule_clean["destCidr"] = token
        else:
            rule_clean["destCidr"] = "any"
        rule_clean.pop("dstCidr", None)
        cleaned_rules.append(rule_clean)

    cleaned["rules"] = cleaned_rules
    return cleaned


def _sanitize_splash_payload(payload):
    if not isinstance(payload, dict):
        return {}
    cleaned = dict(payload)
    cleaned.pop("ssidNumber", None)

    use_splash = bool(cleaned.get("useSplashUrl", False))
    splash_url = cleaned.get("splashUrl")
    if use_splash:
        if not _is_valid_http_url(splash_url):
            cleaned["useSplashUrl"] = False
            cleaned.pop("splashUrl", None)
    else:
        cleaned.pop("splashUrl", None)

    use_redirect = bool(cleaned.get("useRedirectUrl", False))
    redirect_url = cleaned.get("redirectUrl")
    if use_redirect:
        if not _is_valid_http_url(redirect_url):
            cleaned["useRedirectUrl"] = False
            cleaned.pop("redirectUrl", None)
    else:
        cleaned.pop("redirectUrl", None)

    # Remove null md5 blobs that break strict schema validation in some orgs.
    for key in ("splashImage", "splashPrepaidFront", "splashLogo"):
        blob = cleaned.get(key)
        if isinstance(blob, dict) and blob.get("md5") is None:
            cleaned.pop(key, None)

    guest_sponsorship = cleaned.get("guestSponsorship")
    if isinstance(guest_sponsorship, dict):
        duration = guest_sponsorship.get("durationInMinutes")
        if duration is None:
            guest_sponsorship.pop("durationInMinutes", None)
        elif not isinstance(duration, int):
            try:
                guest_sponsorship["durationInMinutes"] = int(duration)
            except Exception:
                guest_sponsorship.pop("durationInMinutes", None)
        cleaned["guestSponsorship"] = guest_sponsorship

    # Some orgs reject null/structured welcomeMessage; keep only plain string.
    welcome_message = cleaned.get("welcomeMessage")
    if welcome_message is None:
        cleaned.pop("welcomeMessage", None)
    elif not isinstance(welcome_message, str):
        cleaned["welcomeMessage"] = str(welcome_message)

    theme_id = cleaned.get("themeId")
    if theme_id is None:
        cleaned.pop("themeId", None)
    elif not isinstance(theme_id, str):
        cleaned.pop("themeId", None)

    billing = cleaned.get("billing")
    if isinstance(billing, dict):
        prepaid_fast_login = billing.get("prepaidAccessFastLoginEnabled")
        if prepaid_fast_login is None:
            billing["prepaidAccessFastLoginEnabled"] = False
        elif not isinstance(prepaid_fast_login, bool):
            billing["prepaidAccessFastLoginEnabled"] = bool(prepaid_fast_login)
        cleaned["billing"] = billing

    return cleaned


def _sanitize_ssid_hotspot20_payload(payload):
    if not isinstance(payload, dict):
        return {}

    valid_network_access_types = {
        "Chargeable public network",
        "Emergency services only network",
        "Free public network",
        "Personal device network",
        "Private network",
        "Private network with guest access",
        "Test or experimental",
        "Wildcard",
    }

    cleaned = dict(payload)
    enabled = bool(cleaned.get("enabled", False))
    cleaned["enabled"] = enabled

    network_access_type = cleaned.get("networkAccessType")
    if isinstance(network_access_type, str):
        network_access_type = network_access_type.strip()
    if network_access_type not in valid_network_access_types:
        cleaned.pop("networkAccessType", None)

    operator = cleaned.get("operator")
    if isinstance(operator, dict):
        if operator.get("name") is None:
            operator.pop("name", None)
        if operator:
            cleaned["operator"] = operator
        else:
            cleaned.pop("operator", None)

    venue = cleaned.get("venue")
    if isinstance(venue, dict):
        if venue.get("name") is None:
            venue.pop("name", None)
        if venue.get("type") is None:
            venue.pop("type", None)
        if venue:
            cleaned["venue"] = venue
        else:
            cleaned.pop("venue", None)

    return cleaned


def _sanitize_ssid_vpn_payload(payload):
    if not isinstance(payload, dict):
        return {}
    cleaned = dict(payload)

    request_ip = cleaned.get("requestIp")
    if request_ip is None:
        cleaned.pop("requestIp", None)
    elif not isinstance(request_ip, str):
        cleaned.pop("requestIp", None)

    failover = cleaned.get("failover")
    if isinstance(failover, dict):
        failover_request_ip = failover.get("requestIp")
        if failover_request_ip is None or not isinstance(failover_request_ip, str):
            failover.pop("requestIp", None)
        cleaned["failover"] = failover

    concentrator = cleaned.get("concentrator")
    if isinstance(concentrator, dict) and not concentrator:
        cleaned.pop("concentrator", None)

    return cleaned


def _build_ssid_base_fallback_payload(payload):
    if not isinstance(payload, dict):
        return payload, False

    fallback = dict(payload)
    changed = False

    wpa_mode = fallback.get("wpaEncryptionMode")
    if isinstance(wpa_mode, str) and "WPA3" in wpa_mode.upper():
        fallback["wpaEncryptionMode"] = "WPA2 only"
        changed = True

    if str(fallback.get("authMode", "")).lower() == "open":
        if "wpaEncryptionMode" in fallback:
            fallback.pop("wpaEncryptionMode", None)
            changed = True

    return fallback, changed


def _dedupe_switch_acl_rules(rules):
    deduped = []
    seen = set()
    for rule in _ensure_list(rules):
        if not isinstance(rule, dict):
            continue
        key = (
            str(rule.get("comment", "")).strip().lower(),
            str(rule.get("policy", "")).strip().lower(),
            str(rule.get("ipVersion", "")).strip().lower(),
            str(rule.get("protocol", "")).strip().lower(),
            str(rule.get("srcCidr", "")).strip().lower(),
            str(rule.get("srcPort", "")).strip().lower(),
            str(rule.get("dstCidr", "")).strip().lower(),
            str(rule.get("dstPort", "")).strip().lower(),
            str(rule.get("vlan", "")).strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rule)
    return deduped


def _sanitize_switch_stp_payload(stp_payload, valid_serials):
    if not isinstance(stp_payload, dict):
        return {}
    cleaned = dict(stp_payload)
    priorities = _ensure_list(cleaned.get("stpBridgePriority"))
    filtered_priorities = []
    for item in priorities:
        if not isinstance(item, dict):
            continue
        switches = [s for s in _ensure_list(item.get("switches")) if isinstance(s, str) and s in valid_serials]
        if not switches:
            continue
        item_clean = dict(item)
        item_clean["switches"] = switches
        filtered_priorities.append(item_clean)
    if filtered_priorities:
        cleaned["stpBridgePriority"] = filtered_priorities
    else:
        cleaned.pop("stpBridgePriority", None)
    return cleaned


def restoreWirelessComplete(network_id, network_folder, dashboard):
    wireless_root = os.path.join(network_folder, "wireless")
    ssid_root = os.path.join(wireless_root, "ssids")
    radio_root = os.path.join(wireless_root, "device_radio")

    # 1) Network-wide wireless settings
    restoreWirelessSettings(network_id, network_folder, dashboard)

    bluetooth = _load_json_if_exists(os.path.join(wireless_root, "bluetooth_settings.json"))
    if bluetooth is not None:
        try:
            dashboard.wireless.updateNetworkWirelessBluetoothSettings(network_id, **bluetooth)
            print("[RESTORE] Wireless bluetooth settings restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Wireless bluetooth settings: {e}")

    # Air Marshal restore
    air_marshal_settings = _load_json_if_exists(os.path.join(wireless_root, "air_marshal_settings.json")) or []
    if isinstance(air_marshal_settings, dict):
        settings_list = [air_marshal_settings]
    elif isinstance(air_marshal_settings, list):
        settings_list = air_marshal_settings
    else:
        settings_list = []

    if settings_list:
        setting = settings_list[0]
        default_policy = setting.get("defaultPolicy")
        if default_policy:
            try:
                dashboard.wireless.updateNetworkWirelessAirMarshalSettings(
                    network_id,
                    defaultPolicy=default_policy
                )
                print("[RESTORE] Air Marshal settings restored")
            except Exception as e:
                print(f"[RESTORE ERROR] Air Marshal settings: {e}")

    air_marshal_rules = _load_json_if_exists(os.path.join(wireless_root, "air_marshal_rules.json")) or []
    if isinstance(air_marshal_rules, dict):
        rules_list = [air_marshal_rules]
    elif isinstance(air_marshal_rules, list):
        rules_list = air_marshal_rules
    else:
        rules_list = []

    for rule in rules_list:
        rule_type = rule.get("type")
        match = rule.get("match")
        if not rule_type or not match:
            continue

        rule_id = rule.get("ruleId") or rule.get("id")
        if rule_id:
            try:
                dashboard.wireless.updateNetworkWirelessAirMarshalRule(
                    network_id,
                    rule_id,
                    type=rule_type,
                    match=match
                )
                print(f"[RESTORE] Air Marshal rule updated: {rule_id}")
                continue
            except Exception:
                pass

        try:
            dashboard.wireless.createNetworkWirelessAirMarshalRule(
                network_id,
                type=rule_type,
                match=match
            )
            print("[RESTORE] Air Marshal rule created")
        except Exception as e:
            print(f"[RESTORE ERROR] Air Marshal rule: {e}")

    # 2) SSID base config (includes access control + availability fields)
    ssids = _load_json_if_exists(os.path.join(ssid_root, "ssids.json"))
    if ssids is None:
        # backward compatibility with old snapshots
        ssids = _load_json_if_exists(os.path.join(network_folder, "ssids", "ssids.json"))
    ssids = _ensure_list(ssids)

    if ssids:
        print(f"[RESTORE] Found {len(ssids)} SSIDs in snapshot")

    for ssid in ssids:
        if not isinstance(ssid, dict):
            continue
        number = ssid.get("number")
        if number is None:
            continue

        try:
            ssid_payload = _drop_keys(ssid, "number")
            dashboard.wireless.updateNetworkWirelessSsid(network_id, number, **ssid_payload)
            print(f"[RESTORE] SSID {number} base settings restored")
        except Exception as e:
            fallback_payload, can_retry = _build_ssid_base_fallback_payload(ssid_payload)
            if can_retry:
                try:
                    dashboard.wireless.updateNetworkWirelessSsid(
                        network_id,
                        number,
                        **fallback_payload
                    )
                    print(
                        f"[RESTORE WARN] SSID {number} base settings restored with fallback "
                        f"(downgraded unsupported WPA3 mode to WPA2 only)"
                    )
                except Exception as retry_error:
                    print(
                        f"[RESTORE ERROR] SSID {number} base settings: {e} "
                        f"(retry failed: {retry_error})"
                    )
            else:
                print(f"[RESTORE ERROR] SSID {number} base settings: {e}")

        ssid_path = os.path.join(ssid_root, str(number))
        if not os.path.exists(ssid_path):
            continue

        per_ssid_updates = [
            ("firewall_l3.json", dashboard.wireless.updateNetworkWirelessSsidFirewallL3FirewallRules),
            ("firewall_l7.json", dashboard.wireless.updateNetworkWirelessSsidFirewallL7FirewallRules),
            ("traffic_shaping.json", dashboard.wireless.updateNetworkWirelessSsidTrafficShapingRules),
            ("splash_settings.json", dashboard.wireless.updateNetworkWirelessSsidSplashSettings),
            ("schedules.json", dashboard.wireless.updateNetworkWirelessSsidSchedules),
            ("hotspot20.json", dashboard.wireless.updateNetworkWirelessSsidHotspot20),
            ("bonjour_forwarding.json", dashboard.wireless.updateNetworkWirelessSsidBonjourForwarding),
            ("vpn.json", dashboard.wireless.updateNetworkWirelessSsidVpn),
        ]

        for file_name, api_call in per_ssid_updates:
            payload = _load_json_if_exists(os.path.join(ssid_path, file_name))
            if payload is None:
                continue
            try:
                if file_name == "vpn.json" and isinstance(payload, dict):
                    vpn_payload = _sanitize_ssid_vpn_payload(payload)
                    api_call(network_id, number, **vpn_payload)
                    print(f"[RESTORE] SSID {number} {file_name} restored")
                    continue
                if file_name == "firewall_l3.json":
                    fw_payload = _sanitize_ssid_l3_firewall_payload(payload, number)
                    api_call(network_id, number, **fw_payload)
                    print(f"[RESTORE] SSID {number} {file_name} restored")
                    continue
                if file_name == "splash_settings.json":
                    splash_payload = _sanitize_splash_payload(payload)
                    api_call(network_id, number, **splash_payload)
                    print(f"[RESTORE] SSID {number} {file_name} restored")
                    continue
                if file_name == "hotspot20.json":
                    hotspot20_payload = _sanitize_ssid_hotspot20_payload(payload)
                    api_call(network_id, number, **hotspot20_payload)
                    print(f"[RESTORE] SSID {number} {file_name} restored")
                    continue
                api_call(network_id, number, **payload)
                print(f"[RESTORE] SSID {number} {file_name} restored")
            except Exception as e:
                if file_name == "vpn.json":
                    print(
                        f"[RESTORE SKIP] SSID {number} {file_name}: {e} "
                        f"(VPN target network reference may not exist in destination org)"
                    )
                else:
                    print(f"[RESTORE ERROR] SSID {number} {file_name}: {e}")

        identity_psks = _ensure_list(_load_json_if_exists(os.path.join(ssid_path, "identity_psks.json")))
        for psk in identity_psks:
            if not isinstance(psk, dict):
                continue
            identity_psk_id = psk.get("identityPskId") or psk.get("id")
            if not identity_psk_id:
                continue
            try:
                dashboard.wireless.updateNetworkWirelessSsidIdentityPsk(
                    network_id,
                    number,
                    identity_psk_id,
                    **psk,
                )
                print(f"[RESTORE] SSID {number} identity PSK {identity_psk_id} restored")
            except Exception as e:
                print(f"[RESTORE ERROR] SSID {number} identity PSK {identity_psk_id}: {e}")

    # 3) RF profiles (radio/power policy set)
    rf_profiles = _ensure_list(_load_json_if_exists(os.path.join(wireless_root, "rf_profiles.json")))
    for profile in rf_profiles:
        if not isinstance(profile, dict):
            continue
        rf_profile_id = profile.get("id")
        if not rf_profile_id:
            continue
        try:
            dashboard.wireless.updateNetworkWirelessRfProfile(network_id, rf_profile_id, **profile)
            print(f"[RESTORE] RF profile restored: {rf_profile_id}")
        except Exception as e:
            print(f"[RESTORE ERROR] RF profile {rf_profile_id}: {e}")

    # 4) AP-level radio overrides (per device)
    if os.path.exists(radio_root):
        for filename in os.listdir(radio_root):
            if not filename.endswith(".json"):
                continue
            serial = filename[:-5]
            payload = _load_json_if_exists(os.path.join(radio_root, filename))
            if payload is None:
                continue
            try:
                dashboard.wireless.updateDeviceWirelessRadioSettings(serial, **payload)
                print(f"[RESTORE] Device radio restored: {serial}")
            except Exception as e:
                print(f"[RESTORE ERROR] Device radio {serial}: {e}")

    print("[RESTORE DONE] Wireless complete restore completed")


def restoreSwitch(network_id, network_folder, dashboard, org_id=None, target_network=None):
    switch_root = os.path.join(network_folder, "switch")

    if not os.path.exists(switch_root):
        print("[RESTORE SKIP] No switch folder")
        return

    # Configure > Switch Settings
    switch_settings = _load_json_if_exists(os.path.join(switch_root, "switch_settings.json"))
    if switch_settings:
        try:
            dashboard.switch.updateNetworkSwitchSettings(network_id, **switch_settings)
            print("[RESTORE] Switch settings restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch settings: {e}")

    # Configure > ACL
    acl = _load_json_if_exists(os.path.join(switch_root, "acl.json"))
    if acl and isinstance(acl, dict):
        try:
            acl_rules = _dedupe_switch_acl_rules(acl.get("rules", []))
            dashboard.switch.updateNetworkSwitchAccessControlLists(
                network_id,
                rules=acl_rules
            )
            original_count = len(_ensure_list(acl.get("rules", [])))
            if len(acl_rules) < original_count:
                print(
                    f"[RESTORE WARN] Switch ACL deduplicated: removed {original_count - len(acl_rules)} "
                    "duplicate rule(s)"
                )
            print("[RESTORE] Switch ACL restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch ACL: {e}")

    # Configure > Access Policies
    access_policies = _ensure_list(_load_json_if_exists(os.path.join(switch_root, "access_policies.json")))
    existing_policies = []
    try:
        existing_policies = dashboard.switch.getNetworkSwitchAccessPolicies(network_id)
    except Exception:
        pass
    existing_by_name = {p.get("name"): p for p in existing_policies if p.get("name")}

    for policy in access_policies:
        if not isinstance(policy, dict):
            continue
        policy_name = policy.get("name")
        if not policy_name:
            continue
        existing = existing_by_name.get(policy_name)
        try:
            if existing:
                access_policy_number = existing.get("accessPolicyNumber")
                dashboard.switch.updateNetworkSwitchAccessPolicy(
                    network_id,
                    access_policy_number,
                    **policy
                )
            else:
                if "radiusServers" in policy and "radiusAccountingEnabled" in policy:
                    dashboard.switch.createNetworkSwitchAccessPolicy(
                        network_id,
                        name=policy_name,
                        radiusServers=policy.get("radiusServers", []),
                        radiusAccountingEnabled=policy.get("radiusAccountingEnabled", False),
                        **policy
                    )
                else:
                    continue
            print(f"[RESTORE] Switch access policy restored: {policy_name}")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch access policy {policy_name}: {e}")

    # Configure > Port Schedules
    port_schedules = _ensure_list(_load_json_if_exists(os.path.join(switch_root, "port_schedules.json")))
    existing_schedules = []
    try:
        existing_schedules = dashboard.switch.getNetworkSwitchPortSchedules(network_id)
    except Exception:
        pass
    existing_schedule_by_name = {s.get("name"): s for s in existing_schedules if s.get("name")}

    for schedule in port_schedules:
        if not isinstance(schedule, dict):
            continue
        schedule_name = schedule.get("name")
        if not schedule_name:
            continue
        existing = existing_schedule_by_name.get(schedule_name)
        try:
            if existing:
                dashboard.switch.updateNetworkSwitchPortSchedule(
                    network_id,
                    existing.get("id"),
                    **schedule
                )
            else:
                dashboard.switch.createNetworkSwitchPortSchedule(
                    network_id,
                    name=schedule_name,
                    **schedule
                )
            print(f"[RESTORE] Switch port schedule restored: {schedule_name}")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch port schedule {schedule_name}: {e}")

    # Configure > Routing & DHCP (network-level)
    dhcp_policy = _load_json_if_exists(os.path.join(switch_root, "dhcp_server_policy.json"))
    if dhcp_policy:
        try:
            dashboard.switch.updateNetworkSwitchDhcpServerPolicy(network_id, **dhcp_policy)
            print("[RESTORE] Switch DHCP server policy restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch DHCP policy: {e}")

    arp_servers = _ensure_list(_load_json_if_exists(os.path.join(switch_root, "arp_trusted_servers.json")))
    existing_arp = []
    try:
        existing_arp = dashboard.switch.getNetworkSwitchDhcpServerPolicyArpInspectionTrustedServers(
            network_id,
            total_pages="all"
        )
    except Exception:
        pass
    existing_arp_by_mac_vlan = {
        f"{x.get('mac')}|{x.get('vlan')}": x for x in existing_arp
    }

    for server in arp_servers:
        if not isinstance(server, dict):
            continue
        key = f"{server.get('mac')}|{server.get('vlan')}"
        try:
            existing = existing_arp_by_mac_vlan.get(key)
            if existing and existing.get("trustedServerId"):
                dashboard.switch.updateNetworkSwitchDhcpServerPolicyArpInspectionTrustedServer(
                    network_id,
                    existing.get("trustedServerId"),
                    **server
                )
            else:
                dashboard.switch.createNetworkSwitchDhcpServerPolicyArpInspectionTrustedServer(
                    network_id,
                    mac=server.get("mac"),
                    vlan=server.get("vlan"),
                    ipv4=server.get("ipv4", {})
                )
            print(f"[RESTORE] ARP trusted server restored: {key}")
        except Exception as e:
            print(f"[RESTORE ERROR] ARP trusted server {key}: {e}")

    ospf = _load_json_if_exists(os.path.join(switch_root, "routing_ospf.json"))
    if ospf:
        try:
            ospf_payload = dict(ospf) if isinstance(ospf, dict) else {}
            areas = _ensure_list(ospf_payload.get("areas"))
            v3 = _ensure_dict(ospf_payload.get("v3"))
            v3_areas = _ensure_list(v3.get("areas"))
            ospf_enabled = bool(ospf_payload.get("enabled", False))
            v3_enabled = bool(v3.get("enabled", False))
            if ospf_enabled and not areas:
                print("[RESTORE SKIP] Switch OSPF skipped: enabled but no areas")
            else:
                if not ospf_enabled:
                    ospf_payload.pop("areas", None)
                if v3_enabled and not v3_areas:
                    print("[RESTORE WARN] Switch OSPF v3 disabled during restore: no v3 areas in snapshot")
                    v3_enabled = False
                if v3_enabled:
                    ospf_payload["v3"] = v3
                else:
                    ospf_payload.pop("v3", None)
                if not ospf_enabled and not v3_enabled:
                    print("[RESTORE SKIP] Switch OSPF skipped: both OSPF and OSPFv3 disabled")
                    ospf_payload = None
                if not ospf_payload:
                    pass
                else:
                    dashboard.switch.updateNetworkSwitchRoutingOspf(network_id, **ospf_payload)
                    print("[RESTORE] Switch OSPF restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch OSPF: {e}")

    multicast = _load_json_if_exists(os.path.join(switch_root, "routing_multicast.json"))
    if multicast:
        try:
            dashboard.switch.updateNetworkSwitchRoutingMulticast(network_id, **multicast)
            print("[RESTORE] Switch multicast restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch multicast: {e}")

    # Other switch global settings
    stp = _load_json_if_exists(os.path.join(switch_root, "stp.json"))
    if stp:
        try:
            valid_serials = set()
            try:
                current_devices = dashboard.networks.getNetworkDevices(network_id)
                valid_serials = {
                    d.get("serial")
                    for d in _ensure_list(current_devices)
                    if isinstance(d, dict) and d.get("serial")
                }
            except Exception:
                pass
            stp_payload = _sanitize_switch_stp_payload(stp, valid_serials)
            dashboard.switch.updateNetworkSwitchStp(network_id, **stp_payload)
            if isinstance(stp, dict) and isinstance(stp_payload, dict):
                original = len(_ensure_list(stp.get("stpBridgePriority")))
                final = len(_ensure_list(stp_payload.get("stpBridgePriority")))
                if final < original:
                    print(
                        f"[RESTORE WARN] Switch STP filtered out {original - final} "
                        "bridge-priority entry(ies) for missing switches"
                    )
            print("[RESTORE] Switch STP restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch STP: {e}")

    mtu = _load_json_if_exists(os.path.join(switch_root, "mtu.json"))
    if mtu:
        try:
            dashboard.switch.updateNetworkSwitchMtu(network_id, **mtu)
            print("[RESTORE] Switch MTU restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch MTU: {e}")

    dscp = _load_json_if_exists(os.path.join(switch_root, "dscp_to_cos.json"))
    if dscp and isinstance(dscp, dict):
        try:
            dashboard.switch.updateNetworkSwitchDscpToCosMappings(
                network_id,
                mappings=dscp.get("mappings", [])
            )
            print("[RESTORE] Switch DSCP-to-CoS mappings restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch DSCP-to-CoS mappings: {e}")

    qos_rules = _ensure_list(_load_json_if_exists(os.path.join(switch_root, "qos_rules.json")))
    existing_qos = []
    try:
        existing_qos = dashboard.switch.getNetworkSwitchQosRules(network_id)
    except Exception:
        pass
    existing_qos_by_vlan_proto = {
        f"{x.get('vlan')}|{x.get('protocol')}|{x.get('srcPort')}|{x.get('dstPort')}": x
        for x in existing_qos
    }

    restored_qos_ids = []
    for rule in qos_rules:
        if not isinstance(rule, dict):
            continue
        key = f"{rule.get('vlan')}|{rule.get('protocol')}|{rule.get('srcPort')}|{rule.get('dstPort')}"
        try:
            existing = existing_qos_by_vlan_proto.get(key)
            if existing and existing.get("id"):
                dashboard.switch.updateNetworkSwitchQosRule(network_id, existing.get("id"), **rule)
                restored_qos_ids.append(existing.get("id"))
            else:
                created = dashboard.switch.createNetworkSwitchQosRule(
                    network_id,
                    vlan=rule.get("vlan"),
                    **rule
                )
                new_id = created.get("id") if isinstance(created, dict) else None
                if new_id:
                    restored_qos_ids.append(new_id)
            print(f"[RESTORE] Switch QoS rule restored: {key}")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch QoS rule {key}: {e}")

    qos_order = _load_json_if_exists(os.path.join(switch_root, "qos_rules_order.json"))
    if qos_order and isinstance(qos_order, dict):
        rule_ids = qos_order.get("ruleIds") or restored_qos_ids
        if rule_ids:
            try:
                dashboard.switch.updateNetworkSwitchQosRulesOrder(network_id, ruleIds=rule_ids)
                print("[RESTORE] Switch QoS rule order restored")
            except Exception as e:
                print(f"[RESTORE ERROR] Switch QoS rule order: {e}")

    link_aggs = _ensure_list(_load_json_if_exists(os.path.join(switch_root, "link_aggregations.json")))
    existing_aggs = []
    try:
        existing_aggs = dashboard.switch.getNetworkSwitchLinkAggregations(network_id)
    except Exception:
        pass
    existing_agg_by_ports = {
        json.dumps(x.get("switchPorts", []), sort_keys=True): x
        for x in existing_aggs
    }

    for agg in link_aggs:
        if not isinstance(agg, dict):
            continue
        agg_ports_key = json.dumps(agg.get("switchPorts", []), sort_keys=True)
        try:
            existing = existing_agg_by_ports.get(agg_ports_key)
            if existing and existing.get("id"):
                dashboard.switch.updateNetworkSwitchLinkAggregation(
                    network_id,
                    existing.get("id"),
                    **agg
                )
            else:
                dashboard.switch.createNetworkSwitchLinkAggregation(network_id, **agg)
            print("[RESTORE] Switch link aggregation restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch link aggregation: {e}")

    # Configure > Staged Upgrades
    firmware = _load_json_if_exists(os.path.join(switch_root, "firmware_upgrades.json"))
    if firmware:
        try:
            dashboard.networks.updateNetworkFirmwareUpgrades(network_id, **firmware)
            print("[RESTORE] Switch staged upgrades restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Switch staged upgrades: {e}")

    # Configure > Port Profiles (template-bound network only)
    if org_id and target_network and target_network.get("configTemplateId"):
        config_template_id = target_network.get("configTemplateId")
        profile_ports_root = os.path.join(switch_root, "port_profile_ports")
        if os.path.exists(profile_ports_root):
            for filename in os.listdir(profile_ports_root):
                if not filename.endswith(".json"):
                    continue
                profile_id = filename[:-5]
                ports = _ensure_list(_load_json_if_exists(os.path.join(profile_ports_root, filename)))
                for port in ports:
                    if not isinstance(port, dict):
                        continue
                    port_id = port.get("portId")
                    if not port_id:
                        continue
                    try:
                        clean_port = _drop_keys(port, "portId")
                        dashboard.switch.updateOrganizationConfigTemplateSwitchProfilePort(
                            org_id,
                            config_template_id,
                            profile_id,
                            port_id,
                            **clean_port
                        )
                    except Exception as e:
                        print(f"[RESTORE ERROR] Port profile {profile_id} port {port_id}: {e}")
            print("[RESTORE] Switch port profiles restored (template)")

    # Device-level configs: ports + routing interfaces/static routes + per-interface DHCP
    devices_root = os.path.join(switch_root, "devices")
    legacy_devices_root = switch_root
    if os.path.exists(devices_root) or os.path.exists(legacy_devices_root):
        print("[RESTORE] Restoring Switch device-level settings...")
        root_to_use = devices_root if os.path.exists(devices_root) else legacy_devices_root
        for serial in os.listdir(root_to_use):
            serial_root = os.path.join(root_to_use, serial)
            if not os.path.isdir(serial_root):
                continue
            if not (
                os.path.exists(os.path.join(serial_root, "ports.json"))
                or os.path.exists(os.path.join(serial_root, "routing_interfaces.json"))
                or os.path.exists(os.path.join(serial_root, "routing_static_routes.json"))
            ):
                continue

            ports = _ensure_list(_load_json_if_exists(os.path.join(serial_root, "ports.json")))
            for port in ports:
                if not isinstance(port, dict):
                    continue
                port_id = port.get("portId")
                if port_id is None:
                    continue
                try:
                    clean_port = _drop_keys(port, "portId")
                    dashboard.switch.updateDeviceSwitchPort(serial, port_id, **clean_port)
                except Exception as e:
                    print(f"[RESTORE ERROR] Switch {serial} Port {port_id}: {e}")

            interfaces = _ensure_list(_load_json_if_exists(os.path.join(serial_root, "routing_interfaces.json")))
            existing_if = []
            try:
                existing_if = dashboard.switch.getDeviceSwitchRoutingInterfaces(serial)
            except Exception:
                pass
            existing_if_by_name = {x.get("name"): x for x in existing_if if x.get("name")}

            for interface in interfaces:
                if not isinstance(interface, dict):
                    continue
                interface_id = interface.get("interfaceId")
                interface_name = interface.get("name")
                try:
                    clean_interface = _drop_keys(interface, "interfaceId")
                    if interface_id:
                        dashboard.switch.updateDeviceSwitchRoutingInterface(
                            serial,
                            interface_id,
                            **clean_interface
                        )
                    elif interface_name and interface_name in existing_if_by_name:
                        dashboard.switch.updateDeviceSwitchRoutingInterface(
                            serial,
                            existing_if_by_name[interface_name].get("interfaceId"),
                            **clean_interface
                        )
                    elif interface_name:
                        create_interface = _drop_keys(clean_interface, "name")
                        dashboard.switch.createDeviceSwitchRoutingInterface(
                            serial,
                            name=interface_name,
                            **create_interface
                        )
                except Exception as e:
                    print(f"[RESTORE ERROR] Switch {serial} routing interface {interface_name}: {e}")

            interface_dhcp = _load_json_if_exists(os.path.join(serial_root, "routing_interface_dhcp.json")) or {}
            for interface_id, dhcp_cfg in interface_dhcp.items():
                try:
                    dashboard.switch.updateDeviceSwitchRoutingInterfaceDhcp(serial, interface_id, **dhcp_cfg)
                except Exception as e:
                    print(f"[RESTORE ERROR] Switch {serial} DHCP {interface_id}: {e}")

            static_routes = _ensure_list(_load_json_if_exists(os.path.join(serial_root, "routing_static_routes.json")))
            if not static_routes:
                continue
            existing_routes = []
            try:
                existing_routes = dashboard.switch.getDeviceSwitchRoutingStaticRoutes(serial)
            except Exception:
                pass
            existing_route_by_name = {x.get("name"): x for x in existing_routes if x.get("name")}

            for route in static_routes:
                if not isinstance(route, dict):
                    continue
                route_name = route.get("name")
                route_id = route.get("staticRouteId")
                try:
                    clean_route = _drop_keys(route, "staticRouteId", "name", "subnet", "nextHopIp")
                    if route_id:
                        dashboard.switch.updateDeviceSwitchRoutingStaticRoute(
                            serial,
                            route_id,
                            **clean_route
                        )
                    elif route_name and route_name in existing_route_by_name:
                        dashboard.switch.updateDeviceSwitchRoutingStaticRoute(
                            serial,
                            existing_route_by_name[route_name].get("staticRouteId"),
                            **clean_route
                        )
                    elif route.get("subnet") and route.get("nextHopIp"):
                        dashboard.switch.createDeviceSwitchRoutingStaticRoute(
                            serial,
                            subnet=route.get("subnet"),
                            nextHopIp=route.get("nextHopIp"),
                            **clean_route
                        )
                except Exception as e:
                    print(f"[RESTORE ERROR] Switch {serial} static route {route_name}: {e}")

    print("[RESTORE DONE] Switch full restore completed")


# ==============================
# 🌐 RESTORE NETWORK-WIDE (SYSLOG/SNMP/ALERTS)
# ==============================
def restoreNetworkWide(network_id, network_folder, dashboard):
    nw_folder = os.path.join(network_folder, "network_wide")

    if not os.path.exists(nw_folder):
        print("[RESTORE SKIP] No network_wide folder")
        return

    # Configure > General
    network_info = _load_json_if_exists(os.path.join(nw_folder, "network_info.json"))
    if network_info:
        try:
            network_info_payload = dict(network_info) if isinstance(network_info, dict) else {}
            # Never rename target network during restore.
            network_info_payload.pop("name", None)
            if not isinstance(network_info_payload.get("enrollmentString"), str):
                network_info_payload.pop("enrollmentString", None)
            dashboard.networks.updateNetwork(network_id, **network_info_payload)
            print("[RESTORE] Network general info restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Network general info: {e}")

    network_settings = _load_json_if_exists(os.path.join(nw_folder, "network_settings.json"))
    if network_settings:
        try:
            dashboard.networks.updateNetworkSettings(network_id, **network_settings)
            print("[RESTORE] Network administration settings restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Network administration settings: {e}")

    # Configure > Administration
    syslog = _load_json_if_exists(os.path.join(nw_folder, "syslog.json"))
    if syslog:
        try:
            dashboard.networks.updateNetworkSyslogServers(
                network_id,
                servers=syslog.get("servers", [])
            )
            print("[RESTORE] Syslog restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Syslog: {e}")

    snmp = _load_json_if_exists(os.path.join(nw_folder, "snmp.json"))
    if snmp:
        try:
            snmp_payload = dict(snmp) if isinstance(snmp, dict) else {}
            if not isinstance(snmp_payload.get("communityString"), str):
                snmp_payload.pop("communityString", None)
            dashboard.networks.updateNetworkSnmp(network_id, **snmp_payload)
            print("[RESTORE] SNMP restored")
        except Exception as e:
            print(f"[RESTORE ERROR] SNMP: {e}")

    traffic_analysis = _load_json_if_exists(os.path.join(nw_folder, "traffic_analysis.json"))
    if traffic_analysis:
        try:
            dashboard.networks.updateNetworkTrafficAnalysis(network_id, **traffic_analysis)
            print("[RESTORE] Traffic analysis settings restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Traffic analysis settings: {e}")

    netflow = _load_json_if_exists(os.path.join(nw_folder, "netflow.json"))
    if netflow:
        try:
            dashboard.networks.updateNetworkNetflow(network_id, **netflow)
            print("[RESTORE] NetFlow settings restored")
        except Exception as e:
            print(f"[RESTORE ERROR] NetFlow settings: {e}")

    # Configure > Alerts
    alerts = _load_json_if_exists(os.path.join(nw_folder, "alerts.json"))
    if alerts:
        try:
            dashboard.networks.updateNetworkAlertsSettings(network_id, **alerts)
            print("[RESTORE] Alerts restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Alerts: {e}")

    # Configure > Group Policies
    group_policies = _ensure_list(_load_json_if_exists(os.path.join(nw_folder, "group_policies.json")))
    existing_policies = []
    try:
        existing_policies = dashboard.networks.getNetworkGroupPolicies(network_id)
    except Exception:
        pass
    existing_policy_by_name = {p.get("name"): p for p in existing_policies if p.get("name")}

    for policy in group_policies:
        if not isinstance(policy, dict):
            continue
        name = policy.get("name")
        if not name:
            continue
        existing = existing_policy_by_name.get(name)
        try:
            if existing and existing.get("groupPolicyId"):
                dashboard.networks.updateNetworkGroupPolicy(
                    network_id,
                    existing.get("groupPolicyId"),
                    **policy
                )
            else:
                create_payload = dict(policy)
                create_payload.pop("name", None)
                dashboard.networks.createNetworkGroupPolicy(network_id, name=name, **create_payload)
            print(f"[RESTORE] Group policy restored: {name}")
        except Exception as e:
            message = str(e)
            if "Content Filtering settings are not supported" in message:
                try:
                    fallback_policy = dict(policy)
                    fallback_policy.pop("contentFiltering", None)
                    if existing and existing.get("groupPolicyId"):
                        dashboard.networks.updateNetworkGroupPolicy(
                            network_id,
                            existing.get("groupPolicyId"),
                            **fallback_policy
                        )
                    else:
                        fallback_create = dict(fallback_policy)
                        fallback_create.pop("name", None)
                        dashboard.networks.createNetworkGroupPolicy(
                            network_id,
                            name=name,
                            **fallback_create
                        )
                    print(
                        f"[RESTORE WARN] Group policy restored without contentFiltering (unsupported): {name}"
                    )
                    continue
                except Exception as retry_e:
                    print(f"[RESTORE ERROR] Group policy {name}: {e} (retry failed: {retry_e})")
                    continue
            print(f"[RESTORE ERROR] Group policy {name}: {e}")

    # Configure > Users (Meraki Auth)
    meraki_auth_users = _ensure_list(_load_json_if_exists(os.path.join(nw_folder, "meraki_auth_users.json")))
    existing_users = []
    try:
        existing_users = dashboard.networks.getNetworkMerakiAuthUsers(network_id)
    except Exception:
        pass
    existing_user_by_key = {}
    for u in existing_users:
        if not isinstance(u, dict):
            continue
        key = (u.get("email"), u.get("accountType"))
        if key[0]:
            existing_user_by_key[key] = u

    for user in meraki_auth_users:
        if not isinstance(user, dict):
            continue
        email = user.get("email")
        if not email:
            continue
        account_type = user.get("accountType")
        if account_type == "Client VPN":
            print(f"[RESTORE SKIP] Meraki auth user {email} (Client VPN accountType)")
            continue

        valid_authz = []
        for auth in _ensure_list(user.get("authorizations")):
            if not isinstance(auth, dict):
                continue
            if auth.get("ssidNumber") is None:
                continue
            auth_clean = {
                "ssidNumber": auth.get("ssidNumber"),
                "authorizedZone": auth.get("authorizedZone"),
                "expiresAt": auth.get("expiresAt"),
            }
            valid_authz.append({k: v for k, v in auth_clean.items() if v is not None})
        if not valid_authz:
            print(f"[RESTORE SKIP] Meraki auth user {email} (no valid authorizations)")
            continue

        existing = existing_user_by_key.get((email, account_type))
        try:
            existing_user_id = existing.get("id") or existing.get("merakiAuthUserId")
            update_payload = _drop_keys(
                user,
                "id",
                "email",
                "createdAt",
                "accountType",
                "isAdmin",
                "authorizations",
            )
            if user.get("isAdmin"):
                update_payload.pop("name", None)
            update_payload["authorizations"] = valid_authz
            if existing and existing_user_id:
                dashboard.networks.updateNetworkMerakiAuthUser(
                    network_id,
                    existing_user_id,
                    **update_payload
                )
            else:
                create_payload = dict(update_payload)
                dashboard.networks.createNetworkMerakiAuthUser(
                    network_id,
                    email=email,
                    authorizations=valid_authz,
                    **create_payload
                )
            print(f"[RESTORE] Meraki auth user restored: {email}")
        except Exception as e:
            print(f"[RESTORE ERROR] Meraki auth user {email}: {e}")

    # Configure > VLAN Profiles
    vlan_profiles = _ensure_list(_load_json_if_exists(os.path.join(nw_folder, "vlan_profiles.json")))
    existing_profiles = []
    try:
        existing_profiles = dashboard.networks.getNetworkVlanProfiles(network_id)
    except Exception:
        pass
    existing_by_iname = {p.get("iname"): p for p in existing_profiles if p.get("iname")}

    for profile in vlan_profiles:
        if not isinstance(profile, dict):
            continue
        iname = profile.get("iname")
        if not iname:
            continue
        try:
            if iname in existing_by_iname:
                dashboard.networks.updateNetworkVlanProfile(
                    network_id,
                    iname=iname,
                    name=profile.get("name"),
                    vlanNames=profile.get("vlanNames", []),
                    vlanGroups=profile.get("vlanGroups", [])
                )
            else:
                dashboard.networks.createNetworkVlanProfile(
                    network_id,
                    iname=iname,
                    name=profile.get("name"),
                    vlanNames=profile.get("vlanNames", []),
                    vlanGroups=profile.get("vlanGroups", [])
                )
            print(f"[RESTORE] VLAN profile restored: {iname}")
        except Exception as e:
            print(f"[RESTORE ERROR] VLAN profile {iname}: {e}")

    assignments = _ensure_list(_load_json_if_exists(os.path.join(nw_folder, "vlan_profile_assignments_by_device.json")))
    if assignments:
        current_serials = set()
        try:
            current_devices = dashboard.networks.getNetworkDevices(network_id)
            current_serials = {
                d.get("serial")
                for d in _ensure_list(current_devices)
                if isinstance(d, dict) and d.get("serial")
            }
        except Exception:
            pass
        grouped = {}
        for item in assignments:
            if not isinstance(item, dict):
                continue
            vlan_profile = item.get("vlanProfile")
            if not vlan_profile:
                continue
            key = json.dumps(vlan_profile, sort_keys=True)
            if key not in grouped:
                grouped[key] = {"vlanProfile": vlan_profile, "serials": [], "stackIds": []}

            serial = item.get("serial")
            stack_id = item.get("stackId")
            if serial:
                grouped[key]["serials"].append(serial)
            if stack_id:
                grouped[key]["stackIds"].append(stack_id)

        for payload in grouped.values():
            payload["serials"] = sorted(set(payload["serials"]))
            payload["stackIds"] = sorted(set(payload["stackIds"]))
            if current_serials:
                payload["serials"] = [s for s in payload["serials"] if s in current_serials]
            if not payload["serials"] and not payload["stackIds"]:
                continue
            try:
                dashboard.networks.reassignNetworkVlanProfilesAssignments(
                    network_id,
                    serials=payload["serials"],
                    stackIds=payload["stackIds"],
                    vlanProfile=payload["vlanProfile"]
                )
                print("[RESTORE] VLAN profile assignments restored")
            except Exception as e:
                print(f"[RESTORE ERROR] VLAN profile assignments: {e}")

    # Configure > Webhooks
    payload_templates = _ensure_list(_load_json_if_exists(os.path.join(nw_folder, "webhooks_payload_templates.json")))
    existing_templates = []
    try:
        existing_templates = dashboard.networks.getNetworkWebhooksPayloadTemplates(network_id)
    except Exception:
        pass
    existing_template_by_name = {x.get("name"): x for x in existing_templates if x.get("name")}

    for template in payload_templates:
        if not isinstance(template, dict):
            continue
        name = template.get("name")
        if not name:
            continue
        try:
            existing = existing_template_by_name.get(name)
            if existing and existing.get("payloadTemplateId"):
                dashboard.networks.updateNetworkWebhooksPayloadTemplate(
                    network_id,
                    existing.get("payloadTemplateId"),
                    **template
                )
            else:
                create_payload = dict(template)
                create_payload.pop("name", None)
                dashboard.networks.createNetworkWebhooksPayloadTemplate(
                    network_id,
                    name=name,
                    **create_payload
                )
            print(f"[RESTORE] Webhook payload template restored: {name}")
        except Exception as e:
            print(f"[RESTORE ERROR] Webhook payload template {name}: {e}")

    http_servers = _ensure_list(_load_json_if_exists(os.path.join(nw_folder, "webhooks_http_servers.json")))
    existing_servers = []
    try:
        existing_servers = dashboard.networks.getNetworkWebhooksHttpServers(network_id)
    except Exception:
        pass
    existing_server_by_name = {x.get("name"): x for x in existing_servers if x.get("name")}

    for server in http_servers:
        if not isinstance(server, dict):
            continue
        name = server.get("name")
        if not name:
            continue
        try:
            existing = existing_server_by_name.get(name)
            if existing and existing.get("id"):
                dashboard.networks.updateNetworkWebhooksHttpServer(
                    network_id,
                    existing.get("id"),
                    **server
                )
            elif server.get("url"):
                create_payload = dict(server)
                create_payload.pop("name", None)
                create_payload.pop("url", None)
                dashboard.networks.createNetworkWebhooksHttpServer(
                    network_id,
                    name=name,
                    url=server.get("url"),
                    **create_payload
                )
            print(f"[RESTORE] Webhook HTTP server restored: {name}")
        except Exception as e:
            print(f"[RESTORE ERROR] Webhook HTTP server {name}: {e}")

    # Configure > Add Devices (best-effort: claim missing devices from snapshot)
    snapshot_devices = _ensure_list(_load_json_if_exists(os.path.join(nw_folder, "network_devices.json")))
    if snapshot_devices:
        try:
            current_devices = dashboard.networks.getNetworkDevices(network_id)
            current_serials = {d.get("serial") for d in current_devices if d.get("serial")}
            snapshot_serials = [d.get("serial") for d in snapshot_devices if isinstance(d, dict) and d.get("serial")]
            missing_serials = [s for s in snapshot_serials if s not in current_serials]
            if missing_serials:
                dashboard.networks.claimNetworkDevices(network_id, serials=missing_serials)
                print(f"[RESTORE] Claimed missing devices: {len(missing_serials)}")
        except Exception as e:
            print(f"[RESTORE ERROR] Add devices (claim missing serials): {e}")


# ==============================
# 🔥 FULL DEEP RESTORE (ENTERPRISE)
# ==============================
def restoreSecuritySdwanSettings(network_id, network_folder, dashboard):
    security_root = os.path.join(network_folder, "security_sdwan")
    if not os.path.exists(security_root):
        print("[RESTORE SKIP] No security_sdwan folder")
        return

    if not _network_has_appliance(dashboard, network_id):
        print("[RESTORE SKIP] Security/SD-WAN skipped: target network has no MX appliance")
        return

    # Addressing & VLANs / DHCP
    firmware = _load_json_if_exists(os.path.join(security_root, "firmware_upgrades.json"))
    if firmware:
        try:
            dashboard.networks.updateNetworkFirmwareUpgrades(network_id, **firmware)
            print("[RESTORE] MX firmware upgrades policy restored")
        except Exception as e:
            print(f"[RESTORE ERROR] MX firmware upgrades policy: {e}")

    appliance_settings = _load_json_if_exists(os.path.join(security_root, "appliance_settings.json"))
    if appliance_settings:
        try:
            dashboard.appliance.updateNetworkApplianceSettings(network_id, **appliance_settings)
            print("[RESTORE] Appliance settings restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Appliance settings: {e}")

    vlans_settings = _load_json_if_exists(os.path.join(security_root, "vlans_settings.json"))
    target_vlans_enabled = None
    try:
        current_vlans_settings = dashboard.appliance.getNetworkApplianceVlansSettings(network_id)
        if isinstance(current_vlans_settings, dict):
            target_vlans_enabled = current_vlans_settings.get("vlansEnabled")
    except Exception:
        pass

    if vlans_settings:
        try:
            dashboard.appliance.updateNetworkApplianceVlansSettings(network_id, **vlans_settings)
            print("[RESTORE] VLAN settings restored")
            if isinstance(vlans_settings, dict):
                target_vlans_enabled = vlans_settings.get("vlansEnabled", target_vlans_enabled)
        except Exception as e:
            error_text = str(e)
            if "Invalid port forwarding rule" in error_text:
                try:
                    dashboard.appliance.updateNetworkApplianceFirewallPortForwardingRules(network_id, rules=[])
                    print("[RESTORE WARN] Port forwarding rules temporarily cleared for VLAN settings update")
                    dashboard.appliance.updateNetworkApplianceVlansSettings(network_id, **vlans_settings)
                    print("[RESTORE] VLAN settings restored (after clearing existing port forwarding rules)")
                    if isinstance(vlans_settings, dict):
                        target_vlans_enabled = vlans_settings.get("vlansEnabled", target_vlans_enabled)
                except Exception as retry_e:
                    print(f"[RESTORE ERROR] VLAN settings: {e} (retry failed: {retry_e})")
            else:
                print(f"[RESTORE ERROR] VLAN settings: {e}")

    single_lan = _load_json_if_exists(os.path.join(security_root, "single_lan.json"))
    if single_lan:
        if target_vlans_enabled is True:
            print("[RESTORE SKIP] Single LAN skipped: destination network currently has VLANs enabled")
        else:
            try:
                dashboard.appliance.updateNetworkApplianceSingleLan(network_id, **single_lan)
                print("[RESTORE] Single LAN restored")
            except Exception as e:
                print(f"[RESTORE ERROR] Single LAN: {e}")

    vlans = _load_json_if_exists(os.path.join(security_root, "vlans.json")) or []
    existing_vlans = []
    try:
        existing_vlans = dashboard.appliance.getNetworkApplianceVlans(network_id)
    except Exception:
        pass
    existing_vlan_ids = {str(v.get("id")) for v in existing_vlans}

    for vlan in vlans:
        vlan_id = vlan.get("id")
        if vlan_id is None:
            continue
        try:
            # Avoid duplicated API args (e.g. networkId/id/name) when using positional params.
            vlan_payload = _drop_keys(vlan, "networkId", "id", "name")
            if str(vlan_id) in existing_vlan_ids:
                dashboard.appliance.updateNetworkApplianceVlan(network_id, vlan_id, **vlan_payload)
            else:
                create_vlan_payload = dict(vlan_payload)
                dashboard.appliance.createNetworkApplianceVlan(
                    network_id,
                    id=vlan_id,
                    name=vlan.get("name", f"VLAN {vlan_id}"),
                    **create_vlan_payload
                )
            print(f"[RESTORE] VLAN restored: {vlan_id}")
        except Exception as e:
            print(f"[RESTORE ERROR] VLAN {vlan_id}: {e}")

    ports = _load_json_if_exists(os.path.join(security_root, "ports.json")) or []
    appliance_ports_supported = True
    if ports:
        try:
            dashboard.appliance.getNetworkAppliancePorts(network_id)
        except Exception as e:
            appliance_ports_supported = False
            print(f"[RESTORE SKIP] MX ports skipped: {e}")
    for port in ports:
        if not appliance_ports_supported:
            break
        port_id = port.get("number") or port.get("portId")
        if port_id is None:
            continue
        try:
            dashboard.appliance.updateNetworkAppliancePort(network_id, port_id, **port)
        except Exception as e:
            print(f"[RESTORE ERROR] MX port {port_id}: {e}")

    # Firewall
    fw_l3 = _load_json_if_exists(os.path.join(security_root, "firewall_l3.json"))
    if fw_l3:
        try:
            fw_l3_payload = dict(fw_l3) if isinstance(fw_l3, dict) else {}
            rules = _ensure_list(fw_l3_payload.get("rules"))
            for rule in rules:
                if isinstance(rule, dict) and "syslogEnabled" in rule:
                    # Avoid hard fail when syslog server is missing on target.
                    rule["syslogEnabled"] = False
            fw_l3_payload["rules"] = rules
            dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(network_id, **fw_l3_payload)
            print("[RESTORE] Firewall L3 restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Firewall L3: {e}")

    fw_l7 = _load_json_if_exists(os.path.join(security_root, "firewall_l7.json"))
    if fw_l7:
        try:
            dashboard.appliance.updateNetworkApplianceFirewallL7FirewallRules(network_id, **fw_l7)
            print("[RESTORE] Firewall L7 restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Firewall L7: {e}")

    one_to_many = _load_json_if_exists(os.path.join(security_root, "firewall_one_to_many_nat.json"))
    if one_to_many and isinstance(one_to_many, dict):
        try:
            dashboard.appliance.updateNetworkApplianceFirewallOneToManyNatRules(
                network_id,
                rules=one_to_many.get("rules", [])
            )
            print("[RESTORE] Firewall 1:Many NAT restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Firewall 1:Many NAT: {e}")

    one_to_one = _load_json_if_exists(os.path.join(security_root, "firewall_one_to_one_nat.json"))
    if one_to_one and isinstance(one_to_one, dict):
        try:
            dashboard.appliance.updateNetworkApplianceFirewallOneToOneNatRules(
                network_id,
                rules=one_to_one.get("rules", [])
            )
            print("[RESTORE] Firewall 1:1 NAT restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Firewall 1:1 NAT: {e}")

    inbound_fw = _load_json_if_exists(os.path.join(security_root, "firewall_inbound.json"))
    if inbound_fw:
        try:
            inbound_payload = dict(inbound_fw) if isinstance(inbound_fw, dict) else {}
            syslog_default_rule = inbound_payload.get("syslogDefaultRule")
            if not isinstance(syslog_default_rule, bool):
                inbound_payload.pop("syslogDefaultRule", None)
            dashboard.appliance.updateNetworkApplianceFirewallInboundFirewallRules(network_id, **inbound_payload)
            print("[RESTORE] Inbound firewall restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Inbound firewall: {e}")

    pfw = _load_json_if_exists(os.path.join(security_root, "firewall_port_forwarding.json"))
    if pfw and isinstance(pfw, dict):
        try:
            lan_subnets = _collect_target_lan_subnets(network_id, dashboard)
            if not lan_subnets:
                lan_subnets = _collect_snapshot_lan_subnets(security_root)
            filtered_rules = []
            for rule in _ensure_list(pfw.get("rules")):
                if not isinstance(rule, dict):
                    continue
                lan_ip = rule.get("lanIp")
                if lan_subnets and isinstance(lan_ip, str) and not _ip_is_in_any_subnet(lan_ip, lan_subnets):
                    print(
                        f"[RESTORE SKIP] Port forwarding rule skipped (lanIp {lan_ip} not in snapshot LAN subnets)"
                    )
                    continue
                filtered_rules.append(rule)
            dashboard.appliance.updateNetworkApplianceFirewallPortForwardingRules(
                network_id,
                rules=filtered_rules
            )
            print("[RESTORE] Port forwarding restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Port forwarding: {e}")

    cfw = _load_json_if_exists(os.path.join(security_root, "firewall_cellular.json"))
    if cfw:
        try:
            dashboard.appliance.updateNetworkApplianceFirewallCellularFirewallRules(network_id, **cfw)
            print("[RESTORE] Cellular firewall restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Cellular firewall: {e}")

    icfw = _load_json_if_exists(os.path.join(security_root, "firewall_inbound_cellular.json"))
    if icfw:
        try:
            dashboard.appliance.updateNetworkApplianceFirewallInboundCellularFirewallRules(network_id, **icfw)
            print("[RESTORE] Inbound cellular firewall restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Inbound cellular firewall: {e}")

    fw_settings = _load_json_if_exists(os.path.join(security_root, "firewall_settings.json"))
    if fw_settings:
        try:
            dashboard.appliance.updateNetworkApplianceFirewallSettings(network_id, **fw_settings)
            print("[RESTORE] Firewall settings restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Firewall settings: {e}")

    # Site-to-site VPN / Routing
    s2s = _load_json_if_exists(os.path.join(security_root, "vpn_site_to_site.json"))
    if s2s:
        try:
            s2s_payload = dict(s2s)
            s2s_mode = s2s_payload.pop("mode", "none")
            dashboard.appliance.updateNetworkApplianceVpnSiteToSiteVpn(
                network_id,
                mode=s2s_mode,
                **s2s_payload
            )
            print("[RESTORE] Site-to-site VPN restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Site-to-site VPN: {e}")

    bgp = _load_json_if_exists(os.path.join(security_root, "vpn_bgp.json"))
    if bgp and "enabled" in bgp:
        try:
            bgp_payload = dict(bgp)
            bgp_enabled = bgp_payload.pop("enabled", False)
            dashboard.appliance.updateNetworkApplianceVpnBgp(
                network_id,
                enabled=bgp_enabled,
                **bgp_payload
            )
            print("[RESTORE] VPN BGP restored")
        except Exception as e:
            print(f"[RESTORE ERROR] VPN BGP: {e}")

    static_routes = _load_json_if_exists(os.path.join(security_root, "routing_static_routes.json")) or []
    existing_routes = []
    try:
        existing_routes = dashboard.appliance.getNetworkApplianceStaticRoutes(network_id)
    except Exception:
        pass
    existing_route_by_name = {r.get("name"): r for r in existing_routes if r.get("name")}

    for route in static_routes:
        route_id = route.get("staticRouteId")
        route_name = route.get("name")
        try:
            if route_id:
                dashboard.appliance.updateNetworkApplianceStaticRoute(network_id, route_id, **route)
            elif route_name and route_name in existing_route_by_name:
                dashboard.appliance.updateNetworkApplianceStaticRoute(
                    network_id,
                    existing_route_by_name[route_name].get("staticRouteId"),
                    **route
                )
            elif route.get("name") and route.get("subnet") and route.get("gatewayIp"):
                create_route_payload = dict(route)
                create_route_payload.pop("name", None)
                create_route_payload.pop("subnet", None)
                create_route_payload.pop("gatewayIp", None)
                dashboard.appliance.createNetworkApplianceStaticRoute(
                    network_id,
                    name=route.get("name"),
                    subnet=route.get("subnet"),
                    gatewayIp=route.get("gatewayIp"),
                    **create_route_payload
                )
            print(f"[RESTORE] Static route restored: {route_name}")
        except Exception as e:
            print(f"[RESTORE ERROR] Static route {route_name}: {e}")

    # SD-WAN & Traffic Shaping
    tsh = _load_json_if_exists(os.path.join(security_root, "traffic_shaping.json"))
    if tsh:
        try:
            dashboard.appliance.updateNetworkApplianceTrafficShaping(network_id, **tsh)
            print("[RESTORE] Traffic shaping restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Traffic shaping: {e}")

    tsh_rules = _load_json_if_exists(os.path.join(security_root, "traffic_shaping_rules.json"))
    if tsh_rules:
        try:
            dashboard.appliance.updateNetworkApplianceTrafficShapingRules(network_id, **tsh_rules)
            print("[RESTORE] Traffic shaping rules restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Traffic shaping rules: {e}")

    uplink_bw = _load_json_if_exists(os.path.join(security_root, "traffic_shaping_uplink_bandwidth.json"))
    if uplink_bw:
        try:
            dashboard.appliance.updateNetworkApplianceTrafficShapingUplinkBandwidth(network_id, **uplink_bw)
            print("[RESTORE] Uplink bandwidth restored")
        except Exception as e:
            err = str(e).lower()
            if "wan2" in err:
                try:
                    uplink_bw_payload = dict(uplink_bw) if isinstance(uplink_bw, dict) else {}
                    limits = uplink_bw_payload.get("bandwidthLimits")
                    if isinstance(limits, dict):
                        limits.pop("wan2", None)
                        uplink_bw_payload["bandwidthLimits"] = limits
                    dashboard.appliance.updateNetworkApplianceTrafficShapingUplinkBandwidth(
                        network_id,
                        **uplink_bw_payload
                    )
                    print("[RESTORE] Uplink bandwidth restored (wan1-only fallback)")
                except Exception as e2:
                    print(f"[RESTORE ERROR] Uplink bandwidth fallback: {e2}")
            else:
                print(f"[RESTORE ERROR] Uplink bandwidth: {e}")

    uplink_sel = _load_json_if_exists(os.path.join(security_root, "traffic_shaping_uplink_selection.json"))
    if uplink_sel:
        try:
            dashboard.appliance.updateNetworkApplianceTrafficShapingUplinkSelection(network_id, **uplink_sel)
            print("[RESTORE] Uplink selection restored")
        except Exception as e:
            err = str(e).lower()
            if "unsupported for networks without a failover capable mx" in err:
                print(f"[RESTORE SKIP] Uplink selection skipped: {e}")
            else:
                print(f"[RESTORE ERROR] Uplink selection: {e}")

    # Threat protection / content filtering
    content = _load_json_if_exists(os.path.join(security_root, "content_filtering.json"))
    if content:
        try:
            content_payload = dict(content) if isinstance(content, dict) else {}
            blocked_categories = []
            for item in _ensure_list(content_payload.get("blockedUrlCategories")):
                if isinstance(item, str):
                    blocked_categories.append(item)
                elif isinstance(item, dict):
                    cid = item.get("id") or item.get("name")
                    if isinstance(cid, str):
                        blocked_categories.append(cid)
            content_payload["blockedUrlCategories"] = blocked_categories
            content_payload["blockedUrlPatterns"] = [
                x for x in _ensure_list(content_payload.get("blockedUrlPatterns")) if isinstance(x, str)
            ]
            content_payload["allowedUrlPatterns"] = [
                x for x in _ensure_list(content_payload.get("allowedUrlPatterns")) if isinstance(x, str)
            ]
            dashboard.appliance.updateNetworkApplianceContentFiltering(network_id, **content_payload)
            print("[RESTORE] Content filtering restored")
        except Exception as e:
            print(f"[RESTORE ERROR] Content filtering: {e}")

    malware = _load_json_if_exists(os.path.join(security_root, "security_malware.json"))
    if malware and "mode" in malware:
        try:
            malware_payload = dict(malware)
            malware_mode = malware_payload.pop("mode", None)
            dashboard.appliance.updateNetworkApplianceSecurityMalware(
                network_id,
                mode=malware_mode,
                **malware_payload
            )
            print("[RESTORE] Malware protection restored")
        except Exception as e:
            err = str(e).lower()
            if "not supported by this network" in err or "not supported" in err:
                print(f"[RESTORE SKIP] Malware protection skipped: {e}")
            else:
                print(f"[RESTORE ERROR] Malware protection: {e}")

    intrusion = _load_json_if_exists(os.path.join(security_root, "security_intrusion.json"))
    if intrusion:
        try:
            dashboard.appliance.updateNetworkApplianceSecurityIntrusion(network_id, **intrusion)
            print("[RESTORE] Intrusion protection restored")
        except Exception as e:
            err = str(e).lower()
            if "not supported by this network" in err or "not supported" in err:
                print(f"[RESTORE SKIP] Intrusion protection skipped: {e}")
            else:
                print(f"[RESTORE ERROR] Intrusion protection: {e}")

    warm_spare = _load_json_if_exists(os.path.join(security_root, "warm_spare.json"))
    if warm_spare and "enabled" in warm_spare:
        try:
            warm_spare_payload = dict(warm_spare)
            warm_spare_enabled = warm_spare_payload.pop("enabled", False)
            primary_serial = warm_spare_payload.get("primarySerial")
            if primary_serial is None or primary_serial == "":
                warm_spare_payload.pop("primarySerial", None)
            elif not _is_valid_meraki_serial(primary_serial):
                print("[RESTORE WARN] Warm spare skipped: invalid primarySerial in snapshot")
                warm_spare_payload.pop("primarySerial", None)
                warm_spare_enabled = False
            spare_serial = warm_spare_payload.get("spareSerial")
            if spare_serial is None or spare_serial == "":
                warm_spare_payload.pop("spareSerial", None)
            elif not _is_valid_meraki_serial(spare_serial):
                print("[RESTORE WARN] Warm spare skipped: invalid spareSerial in snapshot")
                warm_spare_payload.pop("spareSerial", None)
                warm_spare_enabled = False
            if warm_spare_enabled and (
                not warm_spare_payload.get("primarySerial") or not warm_spare_payload.get("spareSerial")
            ):
                print("[RESTORE WARN] Warm spare disabled: primary/spare serial missing")
                warm_spare_enabled = False
            dashboard.appliance.updateNetworkApplianceWarmSpare(
                network_id,
                enabled=warm_spare_enabled,
                **warm_spare_payload
            )
            print("[RESTORE] Warm spare restored")
        except Exception as e:
            err = str(e).lower()
            if "primary mx not found" in err or "not supported" in err:
                print(f"[RESTORE SKIP] Warm spare skipped: {e}")
            else:
                print(f"[RESTORE ERROR] Warm spare: {e}")

    # Wireless concentrator related (if available in MX mode)
    mx_ssids = _load_json_if_exists(os.path.join(security_root, "mx_ssids.json")) or []
    for ssid in mx_ssids:
        number = ssid.get("number")
        if number is None:
            continue
        try:
            dashboard.appliance.updateNetworkApplianceSsid(network_id, number, **ssid)
        except Exception:
            pass

    mx_rf_profiles = _load_json_if_exists(os.path.join(security_root, "mx_rf_profiles.json")) or []
    for profile in mx_rf_profiles:
        rf_profile_id = profile.get("id")
        if not rf_profile_id:
            continue
        try:
            dashboard.appliance.updateNetworkApplianceRfProfile(network_id, rf_profile_id, **profile)
        except Exception:
            pass

    print("[RESTORE DONE] Security & SD-WAN restore completed")


def fullDeepRestore(network_id, network_folder, dashboard, org_id=None, target_network=None):
    """
    Enterprise Disaster Recovery Restore Order:
    1. Security & SD-WAN
    2. Wireless
    3. Switch
    """
    print("========== FULL DEEP RESTORE START ==========")

    restoreSecuritySdwanSettings(network_id, network_folder, dashboard)
    restoreWirelessComplete(network_id, network_folder, dashboard)
    restoreSwitch(
        network_id,
        network_folder,
        dashboard,
        org_id=org_id,
        target_network=target_network
    )

    print("========== FULL DEEP RESTORE COMPLETED ==========")
