import os
import json
import datetime
import meraki
from config import API_KEY, backup_directory


# ===== MERAKI DASHBOARD =====
dashboard = meraki.DashboardAPI(
    API_KEY,
    suppress_logging=True,
    output_log=False,
    print_console=False
)


# ===== SAFE JSON SAVE =====
def saveFile(path, filename, data):
    os.makedirs(path, exist_ok=True)
    file_path = os.path.join(path, filename)

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


# ===== CREATE SNAPSHOT FOLDER (FIXED DATETIME BUG) =====
def create_backup_folder(org_name):
    timestamp = datetime.datetime.now().isoformat().replace(":", "-")
    safe_org = org_name.replace(" ", "_").replace(",", "")
    folder = os.path.join(backup_directory, f"{safe_org}_{timestamp}")
    os.makedirs(folder, exist_ok=True)
    return folder


# =========================================================
# 🌐 NETWORK-WIDE BACKUP (Syslog / SNMP / Alerts)
# =========================================================
def backupSyslogSettings(net, snapshot_path, dashboard, logger):
    try:
        network_id = net["id"]
        network_name = net["name"].replace(" ", "_").replace("/", "_")

        base_path = os.path.join(snapshot_path, "network", network_name, "network_wide")
        os.makedirs(base_path, exist_ok=True)

        # Configure: General + Administration + Alerts + Group Policies + Users + VLAN Profiles + Add Devices
        configure_calls = [
            ("network_info.json", dashboard.networks.getNetwork),
            ("network_settings.json", dashboard.networks.getNetworkSettings),
            ("syslog.json", dashboard.networks.getNetworkSyslogServers),
            ("snmp.json", dashboard.networks.getNetworkSnmp),
            ("alerts.json", dashboard.networks.getNetworkAlertsSettings),
            ("group_policies.json", dashboard.networks.getNetworkGroupPolicies),
            ("meraki_auth_users.json", dashboard.networks.getNetworkMerakiAuthUsers),
            ("vlan_profiles.json", dashboard.networks.getNetworkVlanProfiles),
            ("traffic_analysis.json", dashboard.networks.getNetworkTrafficAnalysis),
            ("netflow.json", dashboard.networks.getNetworkNetflow),
            ("webhooks_http_servers.json", dashboard.networks.getNetworkWebhooksHttpServers),
            ("webhooks_payload_templates.json", dashboard.networks.getNetworkWebhooksPayloadTemplates),
            ("network_devices.json", dashboard.networks.getNetworkDevices),
        ]

        for file_name, api_call in configure_calls:
            try:
                payload = api_call(network_id)
                saveFile(base_path, file_name, payload)
            except Exception:
                pass

        try:
            vlan_assignments = dashboard.networks.getNetworkVlanProfilesAssignmentsByDevice(
                network_id,
                total_pages="all"
            )
            saveFile(base_path, "vlan_profile_assignments_by_device.json", vlan_assignments)
        except Exception:
            pass

        # Monitor snapshots: Clients / Topology / Intelligent Capture / Event Log / Map & Floor Plans
        monitor_path = os.path.join(base_path, "monitor")
        os.makedirs(monitor_path, exist_ok=True)

        try:
            clients = dashboard.networks.getNetworkClients(
                network_id,
                timespan=24 * 60 * 60,
                perPage=1000,
                total_pages="all"
            )
            saveFile(monitor_path, "clients.json", clients)
        except Exception:
            pass

        try:
            topology = dashboard.networks.getNetworkTopologyLinkLayer(network_id)
            saveFile(monitor_path, "topology_link_layer.json", topology)
        except Exception:
            pass

        try:
            intelligent_capture = dashboard.networks.getNetworkTrafficAnalysis(network_id)
            saveFile(monitor_path, "intelligent_capture.json", intelligent_capture)
        except Exception:
            pass

        try:
            events = dashboard.networks.getNetworkEvents(
                network_id,
                timespan=7 * 24 * 60 * 60,
                perPage=1000,
                total_pages="all"
            )
            saveFile(monitor_path, "event_log.json", events)
        except Exception:
            pass

        try:
            floor_plans = dashboard.networks.getNetworkFloorPlans(network_id)
            saveFile(monitor_path, "floor_plans.json", floor_plans)

            floor_plan_details = {}
            for floor in floor_plans:
                floor_id = floor.get("floorPlanId")
                if not floor_id:
                    continue
                try:
                    floor_detail = dashboard.networks.getNetworkFloorPlan(network_id, floor_id)
                    floor_plan_details[str(floor_id)] = floor_detail
                except Exception:
                    pass
            saveFile(monitor_path, "floor_plan_details.json", floor_plan_details)
        except Exception:
            pass

        logger.info(f"Network-wide backup completed: {network_name}")

    except Exception as e:
        logger.warning(f"Network-wide backup skipped: {str(e)}")


# =========================================================
# 🛜 WIRELESS (MR) BASIC BACKUP
# =========================================================
def backupMrWirelessSettings(net, snapshot_path, dashboard, logger):
    try:
        network_id = net["id"]
        network_name = net["name"].replace(" ", "_")

        base_path = os.path.join(snapshot_path, "network", network_name, "wireless")
        os.makedirs(base_path, exist_ok=True)

        wireless_settings = dashboard.wireless.getNetworkWirelessSettings(network_id)
        saveFile(base_path, "wireless_settings.json", wireless_settings)

        logger.info(f"Wireless settings backup completed: {network_name}")

    except Exception as e:
        logger.warning(f"Wireless settings skipped (non-wireless network?): {str(e)}")


# =========================================================
# 📡 SSID BACKUP (0-14)
# =========================================================
def backupSsids(net, snapshot_path, dashboard, logger):
    try:
        network_id = net["id"]
        network_name = net["name"].replace(" ", "_")

        base_path = os.path.join(snapshot_path, "network", network_name, "ssids")
        os.makedirs(base_path, exist_ok=True)

        ssids = dashboard.wireless.getNetworkWirelessSsids(network_id)
        saveFile(base_path, "ssids.json", ssids)

        logger.info(f"SSIDs backup completed: {network_name}")

    except Exception as e:
        logger.warning(f"SSID backup skipped: {str(e)}")


# =========================================================
# 🖧 SWITCH (MS) BASIC BACKUP
# =========================================================
def backupWirelessComplete(net, snapshot_path, dashboard, logger, org_id=None):
    """
    Backup wireless configuration as complete as possible with API support.
    Includes:
    - Network wireless settings
    - Bluetooth settings
    - SSIDs (base config / access control / availability fields)
    - Per-SSID: L3/L7 firewall, traffic shaping, splash, schedules, hotspot 2.0, bonjour, vpn, identity PSKs
    - RF profiles
    - Device radio settings (MR only)
    """
    network_id = net["id"]
    network_name = net["name"].replace(" ", "_").replace("/", "_")

    wireless_root = os.path.join(snapshot_path, "network", network_name, "wireless")
    ssid_root = os.path.join(wireless_root, "ssids")
    radio_root = os.path.join(wireless_root, "device_radio")
    os.makedirs(ssid_root, exist_ok=True)
    os.makedirs(radio_root, exist_ok=True)

    try:
        wireless_settings = dashboard.wireless.getNetworkWirelessSettings(network_id)
        saveFile(wireless_root, "wireless_settings.json", wireless_settings)
    except Exception as e:
        logger.warning(f"Wireless settings backup skipped: {e}")

    # Air Marshal settings/rules are organization-scoped read APIs, filtered by networkId.
    if org_id:
        try:
            am_settings = dashboard.wireless.getOrganizationWirelessAirMarshalSettingsByNetwork(
                org_id,
                networkIds=[network_id],
                total_pages="all"
            )
            saveFile(wireless_root, "air_marshal_settings.json", am_settings)
        except Exception as e:
            logger.warning(f"Air Marshal settings backup skipped: {e}")

        try:
            am_rules = dashboard.wireless.getOrganizationWirelessAirMarshalRules(
                org_id,
                networkIds=[network_id],
                total_pages="all"
            )
            saveFile(wireless_root, "air_marshal_rules.json", am_rules)
        except Exception as e:
            logger.warning(f"Air Marshal rules backup skipped: {e}")

    try:
        # Monitoring snapshot for audit/troubleshooting (not used for restore).
        am_scan = dashboard.wireless.getNetworkWirelessAirMarshal(network_id)
        saveFile(wireless_root, "air_marshal_scan_results.json", am_scan)
    except Exception:
        pass

    try:
        bluetooth = dashboard.wireless.getNetworkWirelessBluetoothSettings(network_id)
        saveFile(wireless_root, "bluetooth_settings.json", bluetooth)
    except Exception as e:
        logger.warning(f"Bluetooth settings backup skipped: {e}")

    ssids = []
    try:
        ssids = dashboard.wireless.getNetworkWirelessSsids(network_id)
        saveFile(ssid_root, "ssids.json", ssids)
    except Exception as e:
        logger.warning(f"SSIDs backup skipped: {e}")

    for ssid in ssids:
        number = ssid.get("number")
        if number is None:
            continue

        ssid_path = os.path.join(ssid_root, str(number))
        os.makedirs(ssid_path, exist_ok=True)

        endpoint_calls = [
            ("firewall_l3.json", dashboard.wireless.getNetworkWirelessSsidFirewallL3FirewallRules),
            ("firewall_l7.json", dashboard.wireless.getNetworkWirelessSsidFirewallL7FirewallRules),
            ("traffic_shaping.json", dashboard.wireless.getNetworkWirelessSsidTrafficShapingRules),
            ("splash_settings.json", dashboard.wireless.getNetworkWirelessSsidSplashSettings),
            ("schedules.json", dashboard.wireless.getNetworkWirelessSsidSchedules),
            ("hotspot20.json", dashboard.wireless.getNetworkWirelessSsidHotspot20),
            ("bonjour_forwarding.json", dashboard.wireless.getNetworkWirelessSsidBonjourForwarding),
            ("vpn.json", dashboard.wireless.getNetworkWirelessSsidVpn),
        ]

        for file_name, api_call in endpoint_calls:
            try:
                payload = api_call(network_id, number)
                saveFile(ssid_path, file_name, payload)
            except Exception:
                pass

        try:
            identity_psks = dashboard.wireless.getNetworkWirelessSsidIdentityPsks(network_id, number)
            saveFile(ssid_path, "identity_psks.json", identity_psks)
        except Exception:
            pass

    try:
        rf_profiles = dashboard.wireless.getNetworkWirelessRfProfiles(network_id)
        saveFile(wireless_root, "rf_profiles.json", rf_profiles)
    except Exception as e:
        logger.warning(f"RF profiles backup skipped: {e}")

    try:
        devices = dashboard.networks.getNetworkDevices(network_id)
        for device in devices:
            model = device.get("model", "")
            serial = device.get("serial")
            if not serial or not model.startswith("MR"):
                continue
            try:
                radio_settings = dashboard.wireless.getDeviceWirelessRadioSettings(serial)
                saveFile(radio_root, f"{serial}.json", radio_settings)
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Device radio settings backup skipped: {e}")

    logger.info(f"Wireless complete backup completed: {network_name}")


def backupSwitchSettings(net, snapshot_path, dashboard, logger, org_id=None):
    try:
        network_id = net["id"]
        network_name = net["name"].replace(" ", "_").replace("/", "_")

        base_path = os.path.join(snapshot_path, "network", network_name, "switch")
        os.makedirs(base_path, exist_ok=True)

        # Configure > Switch Settings
        try:
            switch_settings = dashboard.switch.getNetworkSwitchSettings(network_id)
            saveFile(base_path, "switch_settings.json", switch_settings)
        except Exception as e:
            logger.warning(f"Switch settings backup skipped: {e}")

        # Configure > ACL
        try:
            acl = dashboard.switch.getNetworkSwitchAccessControlLists(network_id)
            saveFile(base_path, "acl.json", acl)
        except Exception as e:
            logger.warning(f"Switch ACL backup skipped: {e}")

        # Configure > Access Policies
        try:
            access_policies = dashboard.switch.getNetworkSwitchAccessPolicies(network_id)
            saveFile(base_path, "access_policies.json", access_policies)
        except Exception as e:
            logger.warning(f"Switch access policies backup skipped: {e}")

        # Configure > Port Schedules
        try:
            port_schedules = dashboard.switch.getNetworkSwitchPortSchedules(network_id)
            saveFile(base_path, "port_schedules.json", port_schedules)
        except Exception as e:
            logger.warning(f"Switch port schedules backup skipped: {e}")

        # Configure > Routing & DHCP (network-level)
        try:
            dhcp_policy = dashboard.switch.getNetworkSwitchDhcpServerPolicy(network_id)
            saveFile(base_path, "dhcp_server_policy.json", dhcp_policy)
        except Exception as e:
            logger.warning(f"Switch DHCP policy backup skipped: {e}")

        try:
            arp_trusted = dashboard.switch.getNetworkSwitchDhcpServerPolicyArpInspectionTrustedServers(
                network_id,
                total_pages="all"
            )
            saveFile(base_path, "arp_trusted_servers.json", arp_trusted)
        except Exception as e:
            logger.warning(f"Switch ARP trusted servers backup skipped: {e}")

        try:
            ospf = dashboard.switch.getNetworkSwitchRoutingOspf(network_id)
            saveFile(base_path, "routing_ospf.json", ospf)
        except Exception as e:
            logger.warning(f"Switch OSPF backup skipped: {e}")

        try:
            multicast = dashboard.switch.getNetworkSwitchRoutingMulticast(network_id)
            saveFile(base_path, "routing_multicast.json", multicast)
        except Exception as e:
            logger.warning(f"Switch multicast backup skipped: {e}")

        # Other switch global settings commonly under Switch Settings
        try:
            stp = dashboard.switch.getNetworkSwitchStp(network_id)
            saveFile(base_path, "stp.json", stp)
        except Exception:
            pass
        try:
            mtu = dashboard.switch.getNetworkSwitchMtu(network_id)
            saveFile(base_path, "mtu.json", mtu)
        except Exception:
            pass
        try:
            dscp_cos = dashboard.switch.getNetworkSwitchDscpToCosMappings(network_id)
            saveFile(base_path, "dscp_to_cos.json", dscp_cos)
        except Exception:
            pass
        try:
            link_aggregations = dashboard.switch.getNetworkSwitchLinkAggregations(network_id)
            saveFile(base_path, "link_aggregations.json", link_aggregations)
        except Exception:
            pass
        try:
            qos_rules = dashboard.switch.getNetworkSwitchQosRules(network_id)
            saveFile(base_path, "qos_rules.json", qos_rules)
            qos_order = dashboard.switch.getNetworkSwitchQosRulesOrder(network_id)
            saveFile(base_path, "qos_rules_order.json", qos_order)
        except Exception:
            pass

        # Configure > Staged Upgrades (network firmware policy)
        try:
            firmware_upgrades = dashboard.networks.getNetworkFirmwareUpgrades(network_id)
            saveFile(base_path, "firmware_upgrades.json", firmware_upgrades)
        except Exception as e:
            logger.warning(f"Switch staged upgrades backup skipped: {e}")

        # Configure > Port Profiles (template-bound network only)
        config_template_id = net.get("configTemplateId")
        if org_id and config_template_id:
            try:
                switch_profiles = dashboard.switch.getOrganizationConfigTemplateSwitchProfiles(
                    org_id,
                    config_template_id
                )
                saveFile(base_path, "port_profiles.json", switch_profiles)

                profiles_root = os.path.join(base_path, "port_profile_ports")
                os.makedirs(profiles_root, exist_ok=True)
                for profile in switch_profiles:
                    profile_id = profile.get("switchProfileId") or profile.get("profileId") or profile.get("id")
                    if not profile_id:
                        continue
                    try:
                        ports = dashboard.switch.getOrganizationConfigTemplateSwitchProfilePorts(
                            org_id,
                            config_template_id,
                            profile_id
                        )
                        saveFile(profiles_root, f"{profile_id}.json", ports)
                    except Exception:
                        pass
            except Exception as e:
                logger.warning(f"Switch port profiles backup skipped: {e}")

        # Monitor snapshots + device-level config
        devices = dashboard.networks.getNetworkDevices(network_id)
        devices_path = os.path.join(base_path, "devices")
        os.makedirs(devices_path, exist_ok=True)

        for device in devices:
            model = device.get("model", "")
            if not model.startswith("MS"):
                continue
            serial = device.get("serial")
            if not serial:
                continue

            switch_folder = os.path.join(devices_path, serial)
            os.makedirs(switch_folder, exist_ok=True)

            try:
                ports = dashboard.switch.getDeviceSwitchPorts(serial)
                saveFile(switch_folder, "ports.json", ports)
            except Exception:
                pass

            # Routing & DHCP device-level
            try:
                interfaces = dashboard.switch.getDeviceSwitchRoutingInterfaces(serial)
                saveFile(switch_folder, "routing_interfaces.json", interfaces)
                dhcp_by_interface = {}
                for interface in interfaces:
                    interface_id = interface.get("interfaceId")
                    if not interface_id:
                        continue
                    try:
                        dhcp_cfg = dashboard.switch.getDeviceSwitchRoutingInterfaceDhcp(serial, interface_id)
                        dhcp_by_interface[str(interface_id)] = dhcp_cfg
                    except Exception:
                        pass
                saveFile(switch_folder, "routing_interface_dhcp.json", dhcp_by_interface)
            except Exception:
                pass

            try:
                static_routes = dashboard.switch.getDeviceSwitchRoutingStaticRoutes(serial)
                saveFile(switch_folder, "routing_static_routes.json", static_routes)
            except Exception:
                pass

            # Monitor snapshots
            try:
                port_statuses = dashboard.switch.getDeviceSwitchPortsStatuses(serial)
                saveFile(switch_folder, "monitor_port_statuses.json", port_statuses)
            except Exception:
                pass

        try:
            dhcp_seen = dashboard.switch.getNetworkSwitchDhcpV4ServersSeen(network_id)
            saveFile(base_path, "monitor_dhcp_v4_servers_seen.json", dhcp_seen)
        except Exception:
            pass

        try:
            arp_warn = dashboard.switch.getNetworkSwitchDhcpServerPolicyArpInspectionWarningsByDevice(network_id)
            saveFile(base_path, "monitor_arp_warnings_by_device.json", arp_warn)
        except Exception:
            pass

        logger.info(f"Switch full backup completed: {network_name}")

    except Exception as e:
        logger.warning(f"Switch backup skipped: {str(e)}")


# =========================================================
# 🧠 FULL DEEP BACKUP (ENTERPRISE: MR + MS + MX + VLAN + FW)
# =========================================================
def backupSecuritySdwanSettings(net, snapshot_path, dashboard, logger):
    """
    Backup MX Security & SD-WAN settings (best-effort by API support).
    """
    try:
        network_id = net["id"]
        network_name = net["name"].replace(" ", "_").replace("/", "_")

        base_path = os.path.join(snapshot_path, "network", network_name, "security_sdwan")
        os.makedirs(base_path, exist_ok=True)

        endpoint_calls = [
            ("firmware_upgrades.json", dashboard.networks.getNetworkFirmwareUpgrades),
            ("appliance_settings.json", dashboard.appliance.getNetworkApplianceSettings),
            ("single_lan.json", dashboard.appliance.getNetworkApplianceSingleLan),
            ("vlans_settings.json", dashboard.appliance.getNetworkApplianceVlansSettings),
            ("vlans.json", dashboard.appliance.getNetworkApplianceVlans),
            ("ports.json", dashboard.appliance.getNetworkAppliancePorts),
            ("firewall_l3.json", dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules),
            ("firewall_l7.json", dashboard.appliance.getNetworkApplianceFirewallL7FirewallRules),
            ("firewall_one_to_many_nat.json", dashboard.appliance.getNetworkApplianceFirewallOneToManyNatRules),
            ("firewall_one_to_one_nat.json", dashboard.appliance.getNetworkApplianceFirewallOneToOneNatRules),
            ("firewall_inbound.json", dashboard.appliance.getNetworkApplianceFirewallInboundFirewallRules),
            ("firewall_port_forwarding.json", dashboard.appliance.getNetworkApplianceFirewallPortForwardingRules),
            ("firewall_cellular.json", dashboard.appliance.getNetworkApplianceFirewallCellularFirewallRules),
            ("firewall_inbound_cellular.json", dashboard.appliance.getNetworkApplianceFirewallInboundCellularFirewallRules),
            ("firewall_settings.json", dashboard.appliance.getNetworkApplianceFirewallSettings),
            ("vpn_site_to_site.json", dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn),
            ("vpn_bgp.json", dashboard.appliance.getNetworkApplianceVpnBgp),
            ("routing_static_routes.json", dashboard.appliance.getNetworkApplianceStaticRoutes),
            ("traffic_shaping.json", dashboard.appliance.getNetworkApplianceTrafficShaping),
            ("traffic_shaping_rules.json", dashboard.appliance.getNetworkApplianceTrafficShapingRules),
            ("traffic_shaping_uplink_bandwidth.json", dashboard.appliance.getNetworkApplianceTrafficShapingUplinkBandwidth),
            ("traffic_shaping_uplink_selection.json", dashboard.appliance.getNetworkApplianceTrafficShapingUplinkSelection),
            ("content_filtering.json", dashboard.appliance.getNetworkApplianceContentFiltering),
            ("security_malware.json", dashboard.appliance.getNetworkApplianceSecurityMalware),
            ("security_intrusion.json", dashboard.appliance.getNetworkApplianceSecurityIntrusion),
            ("warm_spare.json", dashboard.appliance.getNetworkApplianceWarmSpare),
            ("mx_ssids.json", dashboard.appliance.getNetworkApplianceSsids),
            ("mx_rf_profiles.json", dashboard.appliance.getNetworkApplianceRfProfiles),
        ]

        for file_name, api_call in endpoint_calls:
            try:
                payload = api_call(network_id)
                saveFile(base_path, file_name, payload)
            except Exception:
                pass

        # Monitor snapshots
        try:
            security_events = dashboard.appliance.getNetworkApplianceSecurityEvents(
                network_id,
                timespan=7 * 24 * 60 * 60,
                perPage=1000,
                total_pages="all"
            )
            saveFile(base_path, "monitor_security_events.json", security_events)
        except Exception:
            pass

        try:
            uplinks_usage = dashboard.appliance.getNetworkApplianceUplinksUsageHistory(
                network_id,
                timespan=7 * 24 * 60 * 60
            )
            saveFile(base_path, "monitor_uplinks_usage_history.json", uplinks_usage)
        except Exception:
            pass

        logger.info(f"Security & SD-WAN backup completed: {network_name}")

    except Exception as e:
        logger.warning(f"Security & SD-WAN backup skipped: {str(e)}")


def backupFullDeepNetwork(net, snapshot_path, dashboard, logger):
    """
    TRUE ENTERPRISE BACKUP:
    - MR (Wireless + SSID + Firewall + Traffic)
    - MS (Switch Ports - detailed)
    - MX (Firewall + VLAN + VPN)
    - Network-wide (Syslog, SNMP, Alerts)
    """
    try:
        network_id = net["id"]
        network_name = net["name"]
        safe_name = network_name.replace(" ", "_").replace("/", "_")

        deep_path = os.path.join(
            snapshot_path,
            "network",
            safe_name,
            "FULL_DEEP"
        )
        os.makedirs(deep_path, exist_ok=True)

        logger.info(f"===== FULL DEEP BACKUP START: {network_name} =====")

        # =========================
        # 🌐 NETWORK-WIDE
        # =========================
        try:
            syslog = dashboard.networks.getNetworkSyslogServers(network_id)
            saveFile(deep_path, "syslog.json", syslog)

            snmp = dashboard.networks.getNetworkSnmp(network_id)
            saveFile(deep_path, "snmp.json", snmp)

            alerts = dashboard.networks.getNetworkAlertsSettings(network_id)
            saveFile(deep_path, "alerts.json", alerts)
        except Exception as e:
            logger.warning(f"Network-wide deep backup skip: {e}")

        # =========================
        # 🛜 WIRELESS (MR ADVANCED)
        # =========================
        try:
            ssids = dashboard.wireless.getNetworkWirelessSsids(network_id)
            saveFile(deep_path, "ssids_full.json", ssids)

            wireless_settings = dashboard.wireless.getNetworkWirelessSettings(network_id)
            saveFile(deep_path, "wireless_settings.json", wireless_settings)

            # SSID Firewall + Traffic Shaping
            for i in range(15):
                try:
                    fw = dashboard.wireless.getNetworkWirelessSsidFirewallL3FirewallRules(network_id, i)
                    saveFile(deep_path, f"ssid_{i}_firewall.json", fw)
                except:
                    pass

                try:
                    ts = dashboard.wireless.getNetworkWirelessSsidTrafficShapingRules(network_id, i)
                    saveFile(deep_path, f"ssid_{i}_traffic.json", ts)
                except:
                    pass

        except Exception as e:
            logger.warning(f"Wireless deep backup skipped: {e}")

        # =========================
        # 🔐 MX (Firewall + VLAN + VPN)
        # =========================
        try:
            l3 = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(network_id)
            saveFile(deep_path, "mx_l3_firewall.json", l3)
        except Exception as e:
            logger.warning(f"L3 Firewall skip (no MX?): {e}")

        try:
            l7 = dashboard.appliance.getNetworkApplianceFirewallL7FirewallRules(network_id)
            saveFile(deep_path, "mx_l7_firewall.json", l7)
        except Exception as e:
            logger.warning(f"L7 Firewall skip: {e}")

        try:
            vlans = dashboard.appliance.getNetworkApplianceVlans(network_id)
            saveFile(deep_path, "mx_vlans.json", vlans)
        except Exception as e:
            logger.warning(f"VLAN backup skip: {e}")

        try:
            vpn = dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn(network_id)
            saveFile(deep_path, "mx_vpn.json", vpn)
        except Exception as e:
            logger.warning(f"VPN backup skip: {e}")

        # =========================
        # 🖧 SWITCH (MS - DETAILED)
        # =========================
        try:
            devices = dashboard.networks.getNetworkDevices(network_id)

            for device in devices:
                model = device.get("model", "")
                if model.startswith("MS"):
                    serial = device["serial"]

                    switch_folder = os.path.join(deep_path, "switch", serial)
                    os.makedirs(switch_folder, exist_ok=True)

                    ports = dashboard.switch.getDeviceSwitchPorts(serial)
                    saveFile(switch_folder, "ports.json", ports)

        except Exception as e:
            logger.warning(f"Switch deep backup skip: {e}")

        logger.info(f"===== FULL DEEP BACKUP COMPLETED: {network_name} =====")

    except Exception as e:
        logger.error(f"FULL DEEP BACKUP FAILED: {str(e)}")
