"""
Complete rewrite of devices/views.py
Implements all J-Web tabs: Configure, Monitor, Maintain, Troubleshoot
with full sub-section support and a proper dashboard.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import urllib.error
import urllib.request

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.staticfiles import finders
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from integrations.services.juniper_ssh import JuniperSSHClient, JuniperSSHError
from jobs.models import CommandJob

from .faceplates import get_faceplate, port_is_inverted, port_position
from .forms import (
    CommitPreferenceForm,
    InterfaceConfigForm,
    LagConfigForm,
    ManualSetForm,
    ManualShowForm,
    NtpServerForm,
    PingForm,
    SnmpCommunityForm,
    StaticRouteForm,
    SwitchDeviceForm,
    SystemSettingsForm,
    VlanConfigForm,
)
from .models import GeminiApiCredential, PendingConfigChange, SwitchConfigSnapshot, SwitchDevice


GEMINI_PORT_DETECTION_PROMPT = (
    "Draw one tight rectangle around every physical network port opening in this switch faceplate image. "
    "Include Ethernet RJ45 ports and SFP/SFP+ ports. "
    "Do not include LEDs, buttons, vents, the display, labels, or screw holes. "
    "Do not group ports together. Return one rectangle per physical port. "
    "Return only JSON in this exact shape: "
    "{\"ports\":[{\"left\":0,\"top\":0,\"width\":0,\"height\":0}]}. "
    "All values are percentages of the complete image width and height."
)


# ---------------------------------------------------------------------------
# Navigation structure  tab -> [(section_key, label), ...]
# ---------------------------------------------------------------------------
NAV = {
    "configure": [
        ("dashboard", "Dashboard"),
        ("interfaces_ports", "Interfaces › Ports"),
        ("interfaces_lag", "Interfaces › Link Aggregation"),
        ("switching_vlans", "Switching › VLAN"),
        ("switching_stp", "Switching › STP"),
        ("switching_igmp", "Switching › IGMP Snooping"),
        ("switching_lldp", "Switching › LLDP"),
        ("security_filters", "Security › Firewall Filters"),
        ("security_dot1x", "Security › 802.1X"),
        ("security_port_sec", "Security › Port Security"),
        ("routing", "Routing Options"),
        ("system_identity", "System › Identity"),
        ("system_datetime", "System › Date & Time"),
        ("system_management", "System › Management Access"),
        ("system_ntp", "System › NTP"),
        ("system_snmp", "System › SNMP"),
        ("system_reboot", "System › Reboot / Halt"),
        ("services_dhcp", "Services › DHCP"),
        ("cli_tools", "CLI Tools"),
    ],
    "monitor": [
        ("mon_chassis", "Chassis Information"),
        ("mon_interfaces", "Interface Status & Traffic"),
        ("mon_switching", "Ethernet Switching"),
        ("mon_stp", "Spanning Tree"),
        ("mon_routing", "Routing Information"),
        ("mon_bgp", "BGP"),
        ("mon_ospf", "OSPF"),
        ("mon_arp", "ARP Table"),
        ("mon_mac", "MAC Table"),
        ("mon_lldp", "LLDP Neighbors"),
        ("mon_poe", "PoE"),
        ("mon_alarms", "Active Alarms"),
        ("mon_syslog", "System Log"),
        ("mon_dot1x", "802.1X Authentication"),
        ("mon_port_sec", "Port Security"),
    ],
    "maintain": [
        ("maintain_reboot", "Reboot / Halt"),
        ("maintain_ping", "Ping Host"),
        ("maintain_traceroute", "Traceroute"),
        ("maintain_cli", "CLI Terminal"),
    ],
    "troubleshoot": [
        ("ts_interfaces", "Interface Faults"),
        ("ts_manual_show", "Manual Show Command"),
        ("ts_manual_set", "Manual Set Commands"),
    ],
}

ALL_SECTIONS = {key for sections in NAV.values() for key, _ in sections}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _client(device: SwitchDevice) -> JuniperSSHClient:
    return JuniperSSHClient(
        host=device.management_ip,
        username=device.username,
        password=device.password,
        port=device.ssh_port,
    )


def _device_url(device: SwitchDevice, tab: str = "configure", section: str | None = None) -> str:
    base = f"/devices/{device.pk}/?tab={tab}"
    if section:
        return f"{base}&section={section}"
    return base


# ---------------------------------------------------------------------------
# Dashboard data parsers
# ---------------------------------------------------------------------------
def _parse_health(routing_engine_output: str, chassis_env_output: str) -> dict:
    """Extract structured health metrics from show chassis outputs."""
    h: dict = {
        "memory_pct": None,
        "cpu_load": None,
        "temp_c": None,
        "fan_status": "Unknown",
        "flash_pct": None,
    }
    for line in routing_engine_output.splitlines():
        m = re.search(r"Memory utilization\s+(\d+)\s+percent", line, re.I)
        if m:
            h["memory_pct"] = int(m.group(1))
        m = re.search(r"CPU utilization\s+(\d+)\s+percent", line, re.I)
        if m:
            h["cpu_load"] = int(m.group(1))
        m = re.search(r"Idle\s+(\d+)\s+percent", line, re.I)
        if m:
            h["cpu_load"] = 100 - int(m.group(1))
        m = re.search(r"(\d+)\s+degrees\s+C", line, re.I)
        if m:
            h["temp_c"] = int(m.group(1))
    for line in chassis_env_output.splitlines():
        m = re.search(r"fan.*\b(OK|Failed|Absent)\b", line, re.I)
        if m:
            h["fan_status"] = m.group(1).upper()
    return h


def _parse_system_info(version_output: str, uptime_output: str) -> dict:
    """Extract structured system info fields."""
    info: dict = {
        "hostname": "",
        "model": "",
        "junos_version": "",
        "boot_image": "",
        "uptime": "",
        "last_commit": "",
        "inventory": "1 FPC",
    }
    for line in version_output.splitlines():
        m = re.match(r"^Hostname:\s+(.+)$", line.strip())
        if m:
            info["hostname"] = m.group(1).strip()
        m = re.match(r"^Model:\s+(.+)$", line.strip())
        if m:
            info["model"] = m.group(1).strip()
        m = re.match(r"^Junos:\s+(.+)$", line.strip())
        if m:
            info["junos_version"] = m.group(1).strip()
        m = re.match(r"^JUNOS Base OS boot \[(.+?)\]", line.strip())
        if m:
            info["boot_image"] = m.group(1).strip()
    for line in uptime_output.splitlines():
        m = re.search(r"System booted:\s+.+?\((.+?) ago\)", line)
        if m:
            info["uptime"] = m.group(1).strip()
        m = re.search(r"Last configured:\s+(.+?)\s+by\s+(\S+)", line)
        if m:
            info["last_commit"] = m.group(1).strip()
    return info


def _parse_capacity(terse_output: str, vlans_output: str, switching_summary: str) -> dict:
    """Extract capacity utilization numbers."""
    cap: dict = {
        "active_ports": 0,
        "total_ports": 0,
        "mac_used": 0,
        "mac_supported": 16000,
        "vlans_configured": 0,
        "vlans_supported": 4094,
    }
    for line in terse_output.splitlines():
        columns = line.split()
        if not columns or "." in columns[0]:
            continue
        m = re.match(r"^(ge|xe|et|fe)\S+\s+up\s+up", line.strip())
        if m:
            cap["active_ports"] += 1
        m = re.match(r"^(ge|xe|et|fe)\S+\s+(up|down)", line.strip())
        if m:
            cap["total_ports"] += 1
    for line in switching_summary.splitlines():
        m = re.search(r"Total entries\s*:\s*(\d+)", line, re.I)
        if m:
            cap["mac_used"] = int(m.group(1))
    vlan_count = 0
    for line in vlans_output.splitlines():
        m = re.match(r"^(\S+)\s+(\d+)", line.strip())
        if m and m.group(2) != "0":
            vlan_count += 1
    cap["vlans_configured"] = vlan_count
    return cap


def _parse_alarms(alarms_output: str) -> list[dict]:
    """Parse 'show system alarms' output into list of alarm dicts."""
    alarms = []
    for line in alarms_output.splitlines():
        m = re.match(
            r"^\s*(\d{4}-\d{2}-\d{2}\s+\S+)\s+(Major|Minor|Unknown)\s+(.+)$",
            line,
            re.I,
        )
        if m:
            alarms.append({"time": m.group(1), "severity": m.group(2), "description": m.group(3).strip()})
    return alarms


def _parse_ports_for_diagram(terse_output: str) -> list[dict]:
    """Parse terse output into port list for visual diagram."""
    ports = []
    for line in terse_output.splitlines():
        m = re.match(r"^(ge|xe|et|fe|ae)-?\d+/\d+/\d+\s+(up|down)\s+(up|down)", line.strip())
        if m:
            ports.append(_visual_port(line.split()[0], m.group(2), m.group(3)))
    return ports


def _port_label(name: str) -> str:
    match = re.match(r"^(?:ge|xe|et|fe)-\d+/\d+/(\d+)$", name)
    if match:
        return str(int(match.group(1)) + 1)
    match = re.search(r"(\d+)$", name)
    return match.group(1) if match else name


def _port_kind(name: str) -> str:
    if name.startswith(("xe-", "et-")):
        return "uplink"
    if name.startswith("ae"):
        return "lag"
    if name.startswith(("me", "em")):
        return "mgmt"
    return "access"


def _visual_port(
    name: str,
    admin: str = "unknown",
    link: str = "unknown",
    port_layout: dict | None = None,
    model: str | None = None,
) -> dict:
    default_position = _default_port_position(name, model)
    position = _port_position(name, port_layout, model)
    inverted = _port_is_inverted(name, model)
    custom_layout = (port_layout or {}).get(name)
    if isinstance(custom_layout, dict) and isinstance(custom_layout.get("inverted"), bool):
        inverted = custom_layout["inverted"]
    return {
        "name": name,
        "admin": admin,
        "link": link,
        "label": _port_label(name),
        "kind": _port_kind(name),
        "inverted": inverted,
        "left": position[0],
        "top": position[1],
        "width": position[2],
        "height": position[3],
        "default_left": default_position[0],
        "default_top": default_position[1],
        "default_width": default_position[2],
        "default_height": default_position[3],
    }


def _port_is_inverted(name: str, model: str | None = None) -> bool:
    return port_is_inverted(name, model)


def _default_port_position(name: str, model: str | None = None) -> tuple[float, float, float, float]:
    return port_position(name, model)


def _clean_layout_value(value: object, fallback: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    try:
        number = float(value) if isinstance(value, (int, float, str)) else fallback
    except (TypeError, ValueError):
        number = fallback
    return round(min(max(number, minimum), maximum), 3)


def _port_position(name: str, port_layout: dict | None = None, model: str | None = None) -> tuple[float, float, float, float]:
    default_left, default_top, default_width, default_height = _default_port_position(name, model)
    if not port_layout:
        return (default_left, default_top, default_width, default_height)
    custom = port_layout.get(name)
    if not isinstance(custom, dict):
        return (default_left, default_top, default_width, default_height)
    width = _clean_layout_value(custom.get("width"), default_width, 0.2, 25.0)
    height = _clean_layout_value(custom.get("height"), default_height, 0.2, 25.0)
    left = _clean_layout_value(custom.get("left"), default_left, 0.0, 100.0 - width)
    top = _clean_layout_value(custom.get("top"), default_top, 0.0, 100.0 - height)
    return (left, top, width, height)


def _visual_ports_for_device(device: SwitchDevice, snapshot: SwitchConfigSnapshot | None) -> list[dict]:
    port_layout = device.port_layout or {}
    model = (snapshot.system_info or {}).get("model", "") if snapshot else ""
    cached_ports = (snapshot.interfaces or {}).get("ports_diagram", []) if snapshot else []
    ports = []
    for port in cached_ports:
        name = port.get("name", "")
        if not name:
            continue
        ports.append(_visual_port(name, port.get("admin", "unknown"), port.get("link", "unknown"), port_layout, model))
    return ports


def _sanitize_port_layout(layout: object, allowed_names: set[str], model: str | None = None) -> dict:
    if not isinstance(layout, dict):
        return {}
    cleaned = {}
    for name, values in layout.items():
        if name not in allowed_names or not isinstance(values, dict):
            continue
        default_left, default_top, default_width, default_height = _default_port_position(name, model)
        width = _clean_layout_value(values.get("width"), default_width, 0.2, 25.0)
        height = _clean_layout_value(values.get("height"), default_height, 0.2, 25.0)
        cleaned[name] = {
            "left": _clean_layout_value(values.get("left"), default_left, 0.0, 100.0 - width),
            "top": _clean_layout_value(values.get("top"), default_top, 0.0, 100.0 - height),
            "width": width,
            "height": height,
        }
        if isinstance(values.get("inverted"), bool):
            cleaned[name]["inverted"] = values["inverted"]
    return cleaned


def _extract_json_payload(text: str) -> object:
    clean = text.strip()
    if clean.startswith("```"):
        clean = re.sub(r"^```(?:json)?", "", clean).strip()
        clean = re.sub(r"```$", "", clean).strip()
    match = re.search(r"(\{.*\}|\[.*\])", clean, re.S)
    if match:
        clean = match.group(1)
    return json.loads(clean)


def _png_dimensions(image_path: str) -> tuple[int, int]:
    with open(image_path, "rb") as image_file:
        header = image_file.read(24)
    if header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR":
        return (100, 100)
    return struct.unpack(">II", header[16:24])


def _coordinate_number(value: object) -> float | None:
    if not isinstance(value, (int, float, str)):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _sanitize_detected_port_candidates(candidates: object, image_width: int = 100, image_height: int = 100) -> list[dict]:
    if isinstance(candidates, dict):
        candidates = candidates.get("ports", [])
    if not isinstance(candidates, list):
        return []
    cleaned = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue

        raw_left = candidate.get("left", candidate.get("x"))
        raw_top = candidate.get("top", candidate.get("y"))
        raw_width = candidate.get("width", candidate.get("w"))
        raw_height = candidate.get("height", candidate.get("h"))
        raw_values = [_coordinate_number(value) for value in (raw_left, raw_top, raw_width, raw_height)]
        if any(value is None for value in raw_values):
            continue
        left_raw, top_raw, width_raw, height_raw = raw_values
        if left_raw is None or top_raw is None or width_raw is None or height_raw is None:
            continue
        raw_values = [left_raw, top_raw, width_raw, height_raw]
        if max(raw_values) <= 1.0:
            left_value, top_value, width_value, height_value = [value * 100.0 for value in raw_values]
        elif max(raw_values) > 100.0:
            left_value = raw_values[0] * 100.0 / image_width
            top_value = raw_values[1] * 100.0 / image_height
            width_value = raw_values[2] * 100.0 / image_width
            height_value = raw_values[3] * 100.0 / image_height
        else:
            left_value, top_value, width_value, height_value = raw_values
        width = _clean_layout_value(width_value, 0.0, 0.2, 25.0)
        height = _clean_layout_value(height_value, 0.0, 0.2, 25.0)
        if not width or not height:
            continue
        cleaned.append(
            {
                "left": _clean_layout_value(left_value, 0.0, 0.0, 100.0 - width),
                "top": _clean_layout_value(top_value, 0.0, 0.0, 100.0 - height),
                "width": width,
                "height": height,
            }
        )
    return cleaned


def _stored_gemini_api_key() -> str:
    return GeminiApiCredential.objects.filter(provider="gemini").values_list("api_key", flat=True).first() or ""


def _gemini_key_status() -> dict:
    credential = GeminiApiCredential.objects.filter(provider="gemini").first()
    env_key = os.environ.get("GEMINI_API_KEY", "")
    if env_key:
        masked = f"{env_key[:4]}...{env_key[-4:]}" if len(env_key) > 8 else "********"
        return {"has_key": True, "source": "environment", "masked_key": masked}
    if credential:
        return {"has_key": True, "source": "webui", "masked_key": credential.masked_key()}
    return {"has_key": False, "source": "none", "masked_key": ""}


def _snapshot_has_operational_dashboard_data(snapshot: SwitchConfigSnapshot) -> bool:
    interfaces = snapshot.interfaces or {}
    system_info = snapshot.system_info or {}
    health_info = snapshot.health_info or {}
    return bool(
        interfaces.get("terse")
        and interfaces.get("ports_diagram")
        and any(system_info.get(key) for key in ("hostname", "model", "junos_version", "uptime"))
        and health_info.get("cpu_load") is not None
        and any(health_info.get(key) for key in ("memory_pct", "temp_c"))
    )


# ---------------------------------------------------------------------------
# Config cache sync
# ---------------------------------------------------------------------------
def _sync_config_cache(device: SwitchDevice) -> tuple[SwitchConfigSnapshot, bool]:
    """
    Sync device config cache.  Uses at most 2 SSH connections:
      1. Quick version check — returns early if nothing changed.
      2. Full batched snapshot (all show commands + full config) in one session.
    """
    c = _client(device)
    snapshot, _ = SwitchConfigSnapshot.objects.get_or_create(device=device)

    # --- Quick version check (1 SSH connection) ---
    version = c.get_configuration_version()
    if snapshot.config_version == version and snapshot.config_hash and _snapshot_has_operational_dashboard_data(snapshot):
        # Version unchanged; skip the expensive full sync
        return snapshot, False

    # --- Full batched sync in a single SSH session ---
    version, raw_config, ops = c.get_full_snapshot()
    config_hash = hashlib.sha256(raw_config.encode()).hexdigest()

    if snapshot.config_hash == config_hash and _snapshot_has_operational_dashboard_data(snapshot):
        # Version bumped but content identical and operational data is already present.
        snapshot.config_version = version
        snapshot.save(update_fields=["config_version"])
        return snapshot, False

    system_info = _parse_system_info(ops.get("system_info", ""), ops.get("uptime", ""))
    health_info = _parse_health(ops.get("health", ""), ops.get("chassis_env", ""))

    snapshot.config_version = version
    snapshot.config_hash = config_hash
    snapshot.raw_config = raw_config
    snapshot.system_info = system_info
    snapshot.health_info = health_info
    snapshot.alarms = {"list": ops.get("alarms", ""), "parsed": _parse_alarms(ops.get("alarms", ""))}
    snapshot.interfaces = {
        "terse": ops.get("interfaces", ""),
        "detail": ops.get("interfaces_detail", ""),
        "ports_diagram": _parse_ports_for_diagram(ops.get("interfaces", "")),
    }
    snapshot.vlans = {
        "list": ops.get("vlans", ""),
        "stp": ops.get("stp", ""),
        "igmp": ops.get("igmp", ""),
        "lldp": ops.get("lldp", ""),
    }
    snapshot.routing = {
        "summary": ops.get("route_summary", ""),
        "bgp": ops.get("bgp", ""),
        "ospf": ops.get("ospf", ""),
        "arp": ops.get("arp", ""),
        "config": ops.get("routing_config", ""),
    }
    snapshot.security = {
        "firewall_set": ops.get("security", ""),
        "dot1x": ops.get("dot1x", ""),
        "port_security": ops.get("port_security", ""),
    }
    snapshot.services = {
        "system_services_set": ops.get("services", ""),
        "dhcp": ops.get("dhcp", ""),
        "snmp": ops.get("snmp", ""),
        "ntp_config": ops.get("ntp_config", ""),
    }
    snapshot.monitor = {
        "mac_table": ops.get("mac_table", ""),
        "poe": ops.get("poe", ""),
        "processes": ops.get("system_processes", ""),
        "switching_summary": ops.get("ethernet_switching", ""),
        "chassis_fpc": ops.get("chassis_fpc", ""),
    }
    snapshot.save()
    return snapshot, True


# ---------------------------------------------------------------------------
# Staged-change helpers
# ---------------------------------------------------------------------------
def _build_compare_text(staged: list[PendingConfigChange]) -> str:
    if not staged:
        return "No pending staged changes."
    lines: list[str] = []
    for i, ch in enumerate(staged, 1):
        lines.append(f"[{i}] {ch.summary}")
        lines.extend(ch.commands.splitlines())
        lines.append("")
    return "\n".join(lines).strip()


def _execute_commit(device: SwitchDevice, request, staged: list[PendingConfigChange]):
    commands = [c for ch in staged for c in ch.commands.splitlines() if c.strip()]
    job = CommandJob.objects.create(device=device, action="commit_staged_changes", command="\n".join(commands))
    try:
        output = _client(device).run_config_set_commands(commands)
        job.status = CommandJob.STATUS_SUCCESS
        job.output = output
        now = timezone.now()
        for ch in staged:
            ch.status = PendingConfigChange.STATUS_COMMITTED
            ch.updated_at = now
            ch.save(update_fields=["status", "updated_at"])
        messages.success(request, "Staged changes committed successfully.")
    except JuniperSSHError as exc:
        job.status = CommandJob.STATUS_ERROR
        job.output = str(exc)
        messages.error(request, f"Commit failed: {exc}")
    job.completed_at = timezone.now()
    job.save(update_fields=["status", "output", "completed_at"])


def _stage_or_commit(*, device, request, action, summary, commands, tab="configure", section):
    change = PendingConfigChange.objects.create(
        device=device, created_by=request.user,
        action=action, summary=summary, commands="\n".join(commands),
    )
    if device.commit_mode == SwitchDevice.COMMIT_MODE_VALIDATE_AND_COMMIT:
        if request.user.has_perm("devices.commit_staged_changes"):
            _execute_commit(device, request, [change])
            if request.user.has_perm("devices.sync_cached_config"):
                try:
                    _sync_config_cache(device)
                except JuniperSSHError:
                    messages.warning(request, "Committed but cache refresh failed.")
        else:
            messages.warning(request, "Immediate mode active but no commit permission — change queued.")
    else:
        messages.success(request, "Change staged. Use Compare → Commit, or Discard.")
    return redirect(_device_url(device, tab=tab, section=section))


# ---------------------------------------------------------------------------
# Config parsers (for tables)
# ---------------------------------------------------------------------------
def _extract_system_from_set_config(raw_config: str) -> dict[str, str]:
    initial: dict[str, str] = {}
    patterns = {
        "hostname": r"^set system host-name\s+(.+)$",
        "domain_name": r"^set system domain-name\s+(.+)$",
        "name_server": r"^set system name-server\s+(.+)$",
        "ntp_server": r"^set system ntp server\s+(.+)$",
        "timezone": r"^set system time-zone\s+(.+)$",
    }
    for line in raw_config.splitlines():
        for key, pat in patterns.items():
            m = re.match(pat, line.strip())
            if m:
                initial[key] = m.group(1).strip()
    return initial


def _parse_vlans(raw_config: str) -> list[dict]:
    vlans: dict[str, dict] = {}

    def _v(name: str) -> dict:
        return vlans.setdefault(name, {
            "name": name, "id": 0, "id_list": "", "description": "",
            "interfaces": [], "mac_aging": "", "filter_in": "", "filter_out": "",
            "l3_interface": "",
        })

    for line in raw_config.splitlines():
        line = line.strip()
        m = re.match(r"^set vlans (\S+) vlan-id (\d+)$", line)
        if m:
            _v(m.group(1))["id"] = int(m.group(2)); continue
        m = re.match(r"^set vlans (\S+) vlan-id-list (.+)$", line)
        if m:
            _v(m.group(1))["id_list"] = m.group(2).strip(); continue
        m = re.match(r"^set vlans (\S+) description (.+)$", line)
        if m:
            _v(m.group(1))["description"] = m.group(2).strip().strip('"'); continue
        m = re.match(r"^set vlans (\S+) mac-table-aging-time (\d+)$", line)
        if m:
            _v(m.group(1))["mac_aging"] = m.group(2); continue
        m = re.match(r"^set vlans (\S+) filter input (\S+)$", line)
        if m:
            _v(m.group(1))["filter_in"] = m.group(2); continue
        m = re.match(r"^set vlans (\S+) filter output (\S+)$", line)
        if m:
            _v(m.group(1))["filter_out"] = m.group(2); continue
        m = re.match(r"^set vlans (\S+) l3-interface (\S+)$", line)
        if m:
            _v(m.group(1))["l3_interface"] = m.group(2); continue
        m = re.match(
            r"^set interfaces (\S+) unit \d+ family ethernet-switching vlan members (\S+)$",
            line,
        )
        if m:
            iface, vname = m.group(1), m.group(2)
            v = _v(vname)
            if iface not in v["interfaces"]:
                v["interfaces"].append(iface)
    return sorted(vlans.values(), key=lambda v: (v.get("id", 0) or 0, v.get("name", "")))


def _parse_irb_addresses(raw_config: str) -> dict[str, dict]:
    """Returns {irb_unit: {inet, inet6}} e.g. {"irb.10": {"inet": "10.0.0.1/24", "inet6": ""}}"""
    irb: dict[str, dict] = {}
    for line in raw_config.splitlines():
        line = line.strip()
        m = re.match(r"^set interfaces irb unit (\d+) family inet address (\S+)$", line)
        if m:
            irb.setdefault(f"irb.{m.group(1)}", {"inet": "", "inet6": ""})["inet"] = m.group(2)
            continue
        m = re.match(r"^set interfaces irb unit (\d+) family inet6 address (\S+)$", line)
        if m:
            irb.setdefault(f"irb.{m.group(1)}", {"inet": "", "inet6": ""})["inet6"] = m.group(2)
    return irb


def _parse_interfaces(raw_config: str, terse_output: str) -> list[dict]:
    ifaces: dict[str, dict] = {}

    def _d(name: str) -> dict:
        return {"name": name, "description": "", "admin": "unknown", "link": "unknown", "mode": "", "vlans": [], "mtu": "", "native_vlan": "", "inet": "", "inet6": ""}

    for line in terse_output.splitlines():
        m = re.match(r"^((?:ge|xe|et|fe|ae|em|lo|me)\S+)\s+(up|down)\s+(up|down)", line)
        if m and "." not in m.group(1):
            ifaces.setdefault(m.group(1), _d(m.group(1)))
            ifaces[m.group(1)]["admin"] = m.group(2)
            ifaces[m.group(1)]["link"] = m.group(3)

    for line in raw_config.splitlines():
        line = line.strip()
        m = re.match(r"^set interfaces ([\w./:-]+) description (.+)$", line)
        if m and "." not in m.group(1):
            ifaces.setdefault(m.group(1), _d(m.group(1)))
            ifaces[m.group(1)]["description"] = m.group(2).strip().strip('"')
            continue
        m = re.match(r"^set interfaces ([\w./:-]+) mtu (\d+)$", line)
        if m:
            ifaces.setdefault(m.group(1), _d(m.group(1)))
            ifaces[m.group(1)]["mtu"] = m.group(2)
            continue
        m = re.match(r"^set interfaces ([\w./:-]+) disable$", line)
        if m and "." not in m.group(1):
            ifaces.setdefault(m.group(1), _d(m.group(1)))
            ifaces[m.group(1)]["admin"] = "disabled"
            continue
        m = re.match(
            r"^set interfaces ([\w./:-]+) unit \d+ family ethernet-switching port-mode (trunk|access)$", line
        )
        if m:
            ifaces.setdefault(m.group(1), _d(m.group(1)))
            ifaces[m.group(1)]["mode"] = m.group(2)
            continue
        m = re.match(
            r"^set interfaces ([\w./:-]+) unit \d+ family ethernet-switching vlan members (\S+)$", line
        )
        if m:
            ifaces.setdefault(m.group(1), _d(m.group(1)))
            if m.group(2) not in ifaces[m.group(1)]["vlans"]:
                ifaces[m.group(1)]["vlans"].append(m.group(2))
        m = re.match(
            r"^set interfaces ([\w./:-]+) unit \d+ family ethernet-switching native-vlan-id (\S+)$", line
        )
        if m:
            ifaces.setdefault(m.group(1), _d(m.group(1)))
            ifaces[m.group(1)]["native_vlan"] = m.group(2)
            continue
        m = re.match(r"^set interfaces ([\w./:-]+) unit \d+ family inet address (\S+)$", line)
        if m and "." not in m.group(1):
            ifaces.setdefault(m.group(1), _d(m.group(1)))
            ifaces[m.group(1)]["inet"] = m.group(2)
            continue
        m = re.match(r"^set interfaces ([\w./:-]+) unit \d+ family inet6 address (\S+)$", line)
        if m and "." not in m.group(1):
            ifaces.setdefault(m.group(1), _d(m.group(1)))
            ifaces[m.group(1)]["inet6"] = m.group(2)
            continue

    def _sort_key(x: dict) -> tuple:
        n = x["name"]
        m = re.match(r"(\D+)-(\d+)/(\d+)/(\d+)", n)
        if m:
            return (0, m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)))
        m2 = re.match(r"(ae|lo)(\d+)", n)
        if m2:
            return (1, m2.group(1), 0, 0, int(m2.group(2)))
        return (2, n, 0, 0, 0)

    return sorted(ifaces.values(), key=_sort_key)


def _parse_lags(raw_config: str, terse_output: str) -> list[dict]:
    """Parse ae (aggregated ethernet) interfaces from set config + terse output."""
    lags: dict[str, dict] = {}

    def _d(name: str) -> dict:
        return {"name": name, "description": "", "admin": "unknown", "link": "unknown",
                "lacp_mode": "off", "min_links": "", "members": []}

    # Seed from terse output (admin/link state)
    for line in terse_output.splitlines():
        m = re.match(r"^(ae\d+)\s+(up|down)\s+(up|down)", line)
        if m and "." not in m.group(1):
            lags.setdefault(m.group(1), _d(m.group(1)))
            lags[m.group(1)]["admin"] = m.group(2)
            lags[m.group(1)]["link"] = m.group(3)

    # Parse set config lines
    for line in raw_config.splitlines():
        line = line.strip()
        # ae interface itself
        m = re.match(r"^set interfaces (ae\d+) description (.+)$", line)
        if m:
            lags.setdefault(m.group(1), _d(m.group(1)))
            lags[m.group(1)]["description"] = m.group(2).strip().strip('"')
            continue
        m = re.match(r"^set interfaces (ae\d+) aggregated-ether-options lacp (active|passive)", line)
        if m:
            lags.setdefault(m.group(1), _d(m.group(1)))
            lags[m.group(1)]["lacp_mode"] = m.group(2)
            continue
        m = re.match(r"^set interfaces (ae\d+) aggregated-ether-options minimum-links (\d+)", line)
        if m:
            lags.setdefault(m.group(1), _d(m.group(1)))
            lags[m.group(1)]["min_links"] = m.group(2)
            continue
        # Member port binding: set interfaces ge-0/0/X ether-options 802.3ad aeN
        m = re.match(r"^set interfaces ((?:ge|xe|et|fe)\S+) ether-options 802\.3ad (ae\d+)$", line)
        if m:
            member, ae = m.group(1), m.group(2)
            if "." not in member:
                lags.setdefault(ae, _d(ae))
                if member not in lags[ae]["members"]:
                    lags[ae]["members"].append(member)

    return sorted(lags.values(), key=lambda x: int(re.sub(r"\D", "", x["name"]) or "0"))


def _parse_static_routes(raw_config: str) -> list[dict]:
    """Parse static routes from set config."""
    routes: dict[str, dict] = {}
    for line in raw_config.splitlines():
        line = line.strip()
        m = re.match(r"^set routing-options static route (\S+) next-hop (\S+)$", line)
        if m:
            prefix, nh = m.group(1), m.group(2)
            routes.setdefault(prefix, {"prefix": prefix, "next_hops": []})
            if nh not in routes[prefix]["next_hops"]:
                routes[prefix]["next_hops"].append(nh)
        m2 = re.match(r"^set routing-options static route (\S+) discard$", line)
        if m2:
            prefix = m2.group(1)
            routes.setdefault(prefix, {"prefix": prefix, "next_hops": []})
            if "discard" not in routes[prefix]["next_hops"]:
                routes[prefix]["next_hops"].append("discard")
    return sorted(routes.values(), key=lambda r: r["prefix"])


def _parse_ntp_servers(raw_config: str) -> list[dict]:
    """Parse NTP servers from set config."""
    servers: list[dict] = []
    seen: set = set()
    for line in raw_config.splitlines():
        line = line.strip()
        m = re.match(r"^set system ntp server (\S+)(.*)", line)
        if m:
            ip = m.group(1)
            prefer = "prefer" in m.group(2)
            if ip not in seen:
                servers.append({"ip": ip, "prefer": prefer})
                seen.add(ip)
    return servers


def _parse_snmp_communities(raw_config: str) -> list[dict]:
    """Parse SNMP communities from set config."""
    communities: dict[str, dict] = {}
    for line in raw_config.splitlines():
        line = line.strip()
        m = re.match(r"^set snmp community (\S+) authorization (read-only|read-write)$", line)
        if m:
            c, auth = m.group(1), m.group(2)
            communities[c] = {"community": c, "authorization": auth}
        m2 = re.match(r"^set snmp community (\S+)$", line)
        if m2:
            c = m2.group(1)
            communities.setdefault(c, {"community": c, "authorization": "read-only"})
    return sorted(communities.values(), key=lambda x: x["community"])


def _parse_lldp_config(raw_config: str) -> dict:
    """Parse LLDP interface configuration from set config.

    Returns dict with keys:
      enabled_interfaces: list of interface names that have explicit LLDP config
      all_enabled: True if 'set protocols lldp interface all' is present
      disabled_interfaces: list of interfaces with LLDP disabled
    """
    result: dict = {"all_enabled": False, "enabled_interfaces": [], "disabled_interfaces": []}
    for line in raw_config.splitlines():
        line = line.strip()
        if re.match(r"^set protocols lldp interface all$", line):
            result["all_enabled"] = True
        elif re.match(r"^set protocols lldp interface all disable$", line):
            result["all_enabled"] = False
        m = re.match(r"^set protocols lldp interface (\S+)$", line)
        if m and m.group(1) != "all":
            iface = m.group(1)
            if iface not in result["enabled_interfaces"]:
                result["enabled_interfaces"].append(iface)
        m2 = re.match(r"^set protocols lldp interface (\S+) disable$", line)
        if m2:
            iface = m2.group(1)
            if iface not in result["disabled_interfaces"]:
                result["disabled_interfaces"].append(iface)
    result["enabled_interfaces"].sort()
    result["disabled_interfaces"].sort()
    return result


def _parse_mgmt_services(raw_config: str) -> dict:
    """Parse system services configuration from set config."""
    services = {
        "ssh": False,
        "telnet": False,
        "netconf": False,
        "https": False,
        "http": False,
        "ftp": False,
    }
    ssh_root_login = ""
    for line in raw_config.splitlines():
        line = line.strip()
        if re.match(r"^set system services ssh$", line):
            services["ssh"] = True
        if re.match(r"^set system services ssh root-login (\S+)$", line):
            services["ssh"] = True
            m = re.match(r"^set system services ssh root-login (\S+)$", line)
            if m:
                ssh_root_login = m.group(1)
        if re.match(r"^set system services telnet$", line):
            services["telnet"] = True
        if re.match(r"^set system services netconf ssh$", line):
            services["netconf"] = True
        if re.match(r"^set system services web-management https?$", line):
            services["https"] = True
        if re.match(r"^set system services web-management http$", line):
            services["http"] = True
        if re.match(r"^set system services ftp$", line):
            services["ftp"] = True
    services["ssh_root_login"] = ssh_root_login
    return services


# ---------------------------------------------------------------------------
# Main render helper
# ---------------------------------------------------------------------------
def _render(
    request,
    device: SwitchDevice,
    tab: str,
    section: str,
    switch_add_form: SwitchDeviceForm | None = None,
    switch_edit_form: SwitchDeviceForm | None = None,
    switch_modal_tab: str | None = None,
    switch_modal_open: bool = False,
):
    snapshot = SwitchConfigSnapshot.objects.filter(device=device).first()
    raw = snapshot.raw_config if snapshot else ""
    terse = (snapshot.interfaces or {}).get("terse", "") if snapshot else ""

    devices = SwitchDevice.objects.all()
    pending = list(PendingConfigChange.objects.filter(device=device, status=PendingConfigChange.STATUS_PENDING).order_by("created_at"))
    jobs = CommandJob.objects.filter(device=device).order_by("-created_at")[:20]
    recent_jobs = CommandJob.objects.select_related("device").order_by("-created_at")[:10]
    system_initial = _extract_system_from_set_config(raw) if raw else {}
    model_name = (snapshot.system_info or {}).get("model", "") if snapshot else ""
    faceplate = get_faceplate(model_name)
    if switch_modal_tab is None:
        if request.user.has_perm("devices.add_switchdevice"):
            switch_modal_tab = "add"
        elif request.user.has_perm("devices.change_switchdevice"):
            switch_modal_tab = "edit"
        else:
            switch_modal_tab = "delete"

    # Derive capacity for dashboard
    capacity = {}
    if snapshot:
        capacity = _parse_capacity(
            terse,
            (snapshot.vlans or {}).get("list", ""),
            (snapshot.monitor or {}).get("switching_summary", ""),
        )

    ctx = {
        "device": device,
        "devices": devices,
        "device_count": devices.count(),
        "active_device_count": devices.filter(is_active=True).count(),
        "tab": tab,
        "section": section,
        "nav": NAV,
        "snapshot": snapshot,
        "visual_ports": _visual_ports_for_device(device, snapshot),
        "faceplate_image": faceplate["image"],
        "faceplate_display_image": faceplate["display_image"],
        "faceplate_alt": faceplate["alt"],
        "has_port_map": bool(device.port_layout),
        "pending_changes": pending,
        "compare_text": _build_compare_text(pending),
        "jobs": jobs,
        "switch_add_form": switch_add_form or SwitchDeviceForm(prefix="add"),
        "switch_edit_form": switch_edit_form or SwitchDeviceForm(instance=device, prefix="edit"),
        "switch_modal_tab": switch_modal_tab,
        "switch_modal_open": switch_modal_open,
        "gemini_key_status": _gemini_key_status(),
        "commit_preference_form": CommitPreferenceForm(initial={"commit_mode": device.commit_mode}),
        "system_form": SystemSettingsForm(initial=system_initial),
        "vlan_form": VlanConfigForm(),
        "interface_form": InterfaceConfigForm(),
        "manual_show_form": ManualShowForm(),
        "manual_set_form": ManualSetForm(),
        "ping_form": PingForm(),
        "vlans_list": _parse_vlans(raw),
        "irb_addresses": _parse_irb_addresses(raw),
        "interfaces_list": _parse_interfaces(raw, terse),
        "lags_list": _parse_lags(raw, terse),
        "lag_form": LagConfigForm(),
        "static_routes": _parse_static_routes(raw),
        "static_route_form": StaticRouteForm(),
        "ntp_servers": _parse_ntp_servers(raw),
        "ntp_form": NtpServerForm(),
        "snmp_communities": _parse_snmp_communities(raw),
        "snmp_form": SnmpCommunityForm(),
        "lldp_config": _parse_lldp_config(raw),
        "mgmt_services": _parse_mgmt_services(raw),
        "capacity": capacity,
        "recent_jobs": recent_jobs,
        "commit_mode_label": dict(SwitchDevice.COMMIT_MODE_CHOICES).get(device.commit_mode, device.commit_mode),
        "last_ping": CommandJob.objects.filter(device=device, action="ping").order_by("-created_at").first(),
        "last_traceroute": CommandJob.objects.filter(device=device, action="traceroute").order_by("-created_at").first(),
        "last_manual_show": CommandJob.objects.filter(device=device, action="show").order_by("-created_at").first(),
        "section_template": f"devices/sections/{section}.html",
    }
    return render(request, "devices/device_detail.html", ctx)


# ---------------------------------------------------------------------------
# Global dashboard (device picker)
# ---------------------------------------------------------------------------
@login_required
@permission_required("devices.access_dashboard", raise_exception=True)
def dashboard(request):
    last_device_id = request.session.get("last_switch_device_id")
    if last_device_id:
        last_device = SwitchDevice.objects.filter(pk=last_device_id).first()
        if last_device:
            return redirect("devices:detail", device_id=last_device.pk)

    first_device = SwitchDevice.objects.order_by("pk").first()
    if first_device:
        return redirect("devices:detail", device_id=first_device.pk)

    devices = SwitchDevice.objects.all()
    recent_jobs = CommandJob.objects.select_related("device").order_by("-created_at")[:10]
    return render(
        request,
        "dashboard.html",
        {
            "devices": devices,
            "device_count": devices.count(),
            "active_device_count": devices.filter(is_active=True).count(),
            "recent_jobs": recent_jobs,
        },
    )


# ---------------------------------------------------------------------------
# Device list / create
# ---------------------------------------------------------------------------
@login_required
@permission_required("devices.view_switchdevice", raise_exception=True)
def device_list(request):
    return render(request, "devices/device_list.html", {"devices": SwitchDevice.objects.all()})


@login_required
@permission_required("devices.add_switchdevice", raise_exception=True)
def device_create(request):
    if request.method == "POST":
        form = SwitchDeviceForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Device saved.")
            return redirect("devices:list")
    else:
        form = SwitchDeviceForm()
    return render(request, "devices/device_form.html", {"form": form})


@login_required
@permission_required("devices.add_switchdevice", raise_exception=True)
def device_create_modal(request):
    if request.method != "POST":
        return redirect("dashboard")
    form = SwitchDeviceForm(request.POST, prefix="add")
    if form.is_valid():
        device = form.save()
        messages.success(request, "Switch added.")
        return redirect("devices:detail", device_id=device.pk)
    messages.error(request, "Switch could not be added. Check the form values.")
    current_device = SwitchDevice.objects.order_by("pk").first()
    if current_device:
        return _render(
            request,
            current_device,
            "configure",
            "dashboard",
            switch_add_form=form,
            switch_modal_tab="add",
            switch_modal_open=True,
        )
    return redirect("dashboard")


@login_required
@permission_required("devices.change_switchdevice", raise_exception=True)
def device_update_modal(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect("devices:detail", device_id=device.pk)
    form = SwitchDeviceForm(request.POST, instance=device, prefix="edit")
    if form.is_valid():
        form.save()
        messages.success(request, "Switch updated.")
    else:
        messages.error(request, "Switch could not be updated. Check the form values.")
        return _render(
            request,
            device,
            "configure",
            "dashboard",
            switch_edit_form=form,
            switch_modal_tab="edit",
            switch_modal_open=True,
        )
    return redirect("devices:detail", device_id=device.pk)


@login_required
@permission_required("devices.delete_switchdevice", raise_exception=True)
def device_delete_modal(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect("devices:detail", device_id=device.pk)
    device_name = device.name
    device.delete()
    if request.session.get("last_switch_device_id") == device_id:
        del request.session["last_switch_device_id"]
    messages.success(request, f"Switch {device_name} deleted.")
    return redirect("dashboard")


# ---------------------------------------------------------------------------
# Device detail — main entry point
# ---------------------------------------------------------------------------
@login_required
@permission_required("devices.view_switchdevice", raise_exception=True)
def device_detail(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    request.session["last_switch_device_id"] = device.pk
    tab = request.GET.get("tab", "configure")
    if tab not in NAV:
        tab = "configure"
    section = request.GET.get("section", NAV[tab][0][0])
    valid_sections = {k for k, _ in NAV[tab]}
    if section not in valid_sections:
        section = NAV[tab][0][0]
    return _render(request, device, tab, section)


# ---------------------------------------------------------------------------
# Commit options
# ---------------------------------------------------------------------------
@login_required
@permission_required("devices.compare_staged_changes", raise_exception=True)
def compare_staged_changes(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    return _render(request, device, "configure", "compare")


@login_required
@permission_required("devices.manage_commit_preference", raise_exception=True)
def set_commit_preference(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device))
    form = CommitPreferenceForm(request.POST)
    if form.is_valid():
        device.commit_mode = form.cleaned_data["commit_mode"]
        device.save(update_fields=["commit_mode", "updated_at"])
        label = dict(SwitchDevice.COMMIT_MODE_CHOICES).get(device.commit_mode, device.commit_mode)
        messages.success(request, f"Commit preference updated to: {label}.")
    return redirect(_device_url(device))


@login_required
@permission_required("devices.commit_staged_changes", raise_exception=True)
def commit_staged_changes(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device))
    staged = list(PendingConfigChange.objects.filter(device=device, status=PendingConfigChange.STATUS_PENDING).order_by("created_at"))
    if not staged:
        messages.info(request, "No staged changes to commit.")
        return redirect(_device_url(device))
    _execute_commit(device, request, staged)
    if request.user.has_perm("devices.sync_cached_config"):
        try:
            _sync_config_cache(device)
        except JuniperSSHError:
            messages.warning(request, "Committed, but cache refresh failed.")
    return redirect(_device_url(device))


@login_required
@permission_required("devices.discard_staged_changes", raise_exception=True)
def discard_staged_changes(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device))
    staged = PendingConfigChange.objects.filter(device=device, status=PendingConfigChange.STATUS_PENDING)
    count = staged.count()
    if count == 0:
        messages.info(request, "No staged changes to discard.")
    else:
        staged.update(status=PendingConfigChange.STATUS_DISCARDED, updated_at=timezone.now())
        messages.success(request, f"Discarded {count} staged change(s).")
    return redirect(_device_url(device))


# ---------------------------------------------------------------------------
# Cache sync
# ---------------------------------------------------------------------------
@login_required
@permission_required("devices.sync_cached_config", raise_exception=True)
def sync_config_cache(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device))

    from .tasks import sync_device_cache as _sync_task

    task = _sync_task.delay(device_id)

    # Store task ID so the polling endpoint can report status
    SwitchConfigSnapshot.objects.filter(device=device).update(sync_task_id=task.id)

    # If the request expects JSON (e.g., JS fetch), return task info immediately
    if request.headers.get("Accept") == "application/json":
        return JsonResponse({"task_id": task.id, "status": "queued"})

    messages.info(request, "Cache sync started in the background — the page will update automatically.")
    return redirect(_device_url(device))


@login_required
@permission_required("devices.sync_cached_config", raise_exception=True)
def sync_status(request, device_id: int):
    """
    JSON endpoint polled by the frontend to check sync task progress.
    Returns task state and current snapshot metadata.
    """
    device = get_object_or_404(SwitchDevice, pk=device_id)
    snapshot = SwitchConfigSnapshot.objects.filter(device=device).first()

    task_id = snapshot.sync_task_id if snapshot else ""
    task_state = "UNKNOWN"

    if task_id:
        from celery.result import AsyncResult

        result = AsyncResult(task_id)
        task_state = result.state  # PENDING / STARTED / SUCCESS / FAILURE / RETRY

    return JsonResponse(
        {
            "task_id": task_id,
            "task_state": task_state,
            "synced_at": snapshot.synced_at.isoformat() if snapshot else None,
            "config_version": snapshot.config_version if snapshot else "",
        }
    )


@login_required
@permission_required("devices.view_switchdevice", raise_exception=True)
@permission_required("devices.view_live_snmp_status", raise_exception=True)
def live_interface_status(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if not device.snmp_enabled:
        return JsonResponse({"enabled": False, "interfaces": []})

    from integrations.services.snmp import SnmpPollError, collect_interface_status

    try:
        interfaces = collect_interface_status(
            device.management_ip,
            device.snmp_community,
            port=device.snmp_port,
            timeout=device.snmp_timeout,
        )
    except SnmpPollError as exc:
        return JsonResponse({"enabled": True, "error": str(exc), "interfaces": []}, status=503)

    return JsonResponse(
        {
            "enabled": True,
            "interfaces": [interface.as_dict() for interface in interfaces],
            "polled_at": timezone.now().isoformat(),
        }
    )


@login_required
@permission_required("devices.view_switchdevice", raise_exception=True)
@permission_required("devices.manage_port_layout", raise_exception=True)
def save_port_layout(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    snapshot = SwitchConfigSnapshot.objects.filter(device=device).first()
    allowed_names = set()
    allowed_names.update(port["name"] for port in _visual_ports_for_device(device, snapshot))
    model = (snapshot.system_info or {}).get("model", "") if snapshot else ""
    cleaned = _sanitize_port_layout(payload.get("ports", {}), allowed_names, model)
    device.port_layout = cleaned
    device.save(update_fields=["port_layout", "updated_at"])
    return JsonResponse({"status": "ok", "ports": cleaned})


@login_required
@permission_required("devices.view_switchdevice", raise_exception=True)
@permission_required("devices.manage_port_layout", raise_exception=True)
def gemini_detect_port_layout(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    api_key = os.environ.get("GEMINI_API_KEY") or _stored_gemini_api_key()
    if not api_key:
        return JsonResponse({"error": "GEMINI_API_KEY is not configured."}, status=503)

    snapshot = SwitchConfigSnapshot.objects.filter(device=device).first()
    model_name = (snapshot.system_info or {}).get("model", "") if snapshot else ""
    faceplate = get_faceplate(model_name)
    image_path = finders.find(faceplate["display_image"]) or finders.find(faceplate["image"]) or finders.find("img/juniper-ex3300-faceplate.svg")
    if isinstance(image_path, list):
        image_path = image_path[0] if image_path else None
    if not image_path:
        return JsonResponse({"error": "No faceplate image found."}, status=404)

    with open(image_path, "rb") as image_file:
        image_data = base64.b64encode(image_file.read()).decode("ascii")

    model = os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
    mime_type = "image/jpeg" if str(image_path).lower().endswith((".jpg", ".jpeg")) else "image/png"
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": GEMINI_PORT_DETECTION_PROMPT},
                    {"inline_data": {"mime_type": mime_type, "data": image_data}},
                ]
            }
        ],
        "generationConfig": {"temperature": 0, "response_mime_type": "application/json"},
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    request_data = json.dumps(payload).encode("utf-8")
    gemini_request = urllib.request.Request(url, data=request_data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(gemini_request, timeout=30) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return JsonResponse({"error": exc.read().decode("utf-8", errors="replace")}, status=502)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return JsonResponse({"error": str(exc)}, status=502)

    try:
        text = response_payload["candidates"][0]["content"]["parts"][0]["text"]
        image_width, image_height = faceplate["display_dimensions"] if str(image_path).endswith(("-cropped.jpg", "-cropped.png")) else faceplate["dimensions"]
        ports = _sanitize_detected_port_candidates(_extract_json_payload(text), image_width, image_height)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        return JsonResponse({"error": f"Gemini returned an unreadable response: {exc}"}, status=502)

    return JsonResponse({"status": "ok", "source": "gemini", "ports": ports, "count": len(ports)})


@login_required
@permission_required("devices.view_switchdevice", raise_exception=True)
@permission_required("devices.manage_gemini_api_key", raise_exception=True)
def gemini_api_key(request, device_id: int):
    get_object_or_404(SwitchDevice, pk=device_id)
    if request.method == "GET":
        return JsonResponse(_gemini_key_status())
    if request.method != "POST":
        return JsonResponse({"error": "GET or POST required"}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    if payload.get("delete"):
        GeminiApiCredential.objects.filter(provider="gemini").delete()
        return JsonResponse(_gemini_key_status())

    api_key = str(payload.get("api_key", "")).strip()
    if len(api_key) < 16:
        return JsonResponse({"error": "API key is too short."}, status=400)
    GeminiApiCredential.objects.update_or_create(provider="gemini", defaults={"api_key": api_key})
    return JsonResponse(_gemini_key_status())


# ---------------------------------------------------------------------------
# Configure › Interfaces
# ---------------------------------------------------------------------------
@login_required
@permission_required("devices.run_operational_commands", raise_exception=True)
def refresh_status(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="interfaces_ports"))
    job = CommandJob.objects.create(device=device, action="refresh_interfaces", command="show interfaces terse")
    try:
        out = _client(device).run_show_command("show interfaces terse")
        job.status = CommandJob.STATUS_SUCCESS
        job.output = out
        # Update cached terse output without full re-sync
        snap, _ = SwitchConfigSnapshot.objects.get_or_create(device=device)
        ifaces = dict(snap.interfaces) if snap.interfaces else {}
        ifaces["terse"] = out
        ifaces["ports_diagram"] = _parse_ports_for_diagram(out)
        snap.interfaces = ifaces
        snap.save(update_fields=["interfaces"])
        messages.success(request, "Interface status refreshed.")
    except JuniperSSHError as exc:
        job.status = CommandJob.STATUS_ERROR
        job.output = str(exc)
        messages.error(request, f"Refresh failed: {exc}")
    job.completed_at = timezone.now()
    job.save(update_fields=["status", "output", "completed_at"])
    return redirect(_device_url(device, section="interfaces_ports"))


@login_required
@permission_required("devices.manage_interfaces", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def apply_interface(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="interfaces_ports"))
    form = InterfaceConfigForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Please correct the interface fields.")
        return redirect(_device_url(device, section="interfaces_ports"))
    data = form.cleaned_data
    iface = data["interface_name"]
    modal_type = data.get("modal_type", "") or ""
    commands: list[str] = []

    if modal_type == "vlan_options":
        mode = data.get("port_mode", "none") or "none"
        if mode in ("access", "trunk"):
            commands.append(f"delete interfaces {iface} unit 0 family ethernet-switching vlan members")
            commands.append(f"set interfaces {iface} unit 0 family ethernet-switching port-mode {mode}")
            for v in [v.strip() for v in data.get("vlan_members", "").split(",") if v.strip()]:
                commands.append(f"set interfaces {iface} unit 0 family ethernet-switching vlan members {v}")
        native = data.get("native_vlan", "").strip()
        if native:
            commands.append(f"set interfaces {iface} unit 0 family ethernet-switching native-vlan-id {native}")

    elif modal_type == "link_options":
        if data.get("description") is not None:
            if data["description"]:
                commands.append(f'set interfaces {iface} description "{data["description"]}"')
            else:
                commands.append(f"delete interfaces {iface} description")
        if data.get("mtu"):
            commands.append(f"set interfaces {iface} mtu {data['mtu']}")
        speed = data.get("speed", "")
        if speed:
            commands.append(f"set interfaces {iface} ether-options speed {speed}")
            commands.append(f"set interfaces {iface} ether-options no-auto-negotiation")
        else:
            commands.append(f"delete interfaces {iface} ether-options speed")
            commands.append(f"set interfaces {iface} ether-options auto-negotiation")
        duplex = data.get("duplex", "")
        if duplex:
            commands.append(f"set interfaces {iface} ether-options duplex {duplex}")
        else:
            commands.append(f"delete interfaces {iface} ether-options duplex")
        if data.get("flow_control"):
            commands.append(f"set interfaces {iface} ether-options flow-control")
        else:
            commands.append(f"delete interfaces {iface} ether-options flow-control")

    elif modal_type == "ip_options":
        inet = data.get("l3_inet", "").strip()
        if inet:
            commands.append(f"set interfaces {iface} unit 0 family inet address {inet}")
        else:
            commands.append(f"delete interfaces {iface} unit 0 family inet address")
        inet6 = data.get("l3_inet6", "").strip()
        if inet6:
            commands.append(f"set interfaces {iface} unit 0 family inet6 address {inet6}")
        else:
            commands.append(f"delete interfaces {iface} unit 0 family inet6 address")

    else:
        if data.get("description") is not None and data["description"] != "":
            commands.append(f'set interfaces {iface} description "{data["description"]}"')
        if data.get("mtu"):
            commands.append(f"set interfaces {iface} mtu {data['mtu']}")
        mode = data.get("port_mode", "none") or "none"
        if mode == "access":
            commands.append(f"set interfaces {iface} unit 0 family ethernet-switching port-mode access")
            if data.get("access_vlan"):
                commands.append(f"set interfaces {iface} unit 0 family ethernet-switching vlan members {data['access_vlan'].strip()}")
        elif mode == "trunk":
            commands.append(f"set interfaces {iface} unit 0 family ethernet-switching port-mode trunk")
            for v in [v.strip() for v in data.get("trunk_vlans", "").split(",") if v.strip()]:
                commands.append(f"set interfaces {iface} unit 0 family ethernet-switching vlan members {v}")
        elif data.get("access_vlan"):
            commands.append(f"set interfaces {iface} unit 0 family ethernet-switching port-mode access")
            commands.append(f"set interfaces {iface} unit 0 family ethernet-switching vlan members {data['access_vlan'].strip()}")
        commands.append(f"delete interfaces {iface} disable" if data.get("enabled") else f"set interfaces {iface} disable")

    return _stage_or_commit(device=device, request=request, action="interface", summary=f"Interface {iface} update", commands=commands, section="interfaces_ports")


@login_required
@permission_required("devices.manage_interfaces", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def disable_port(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="interfaces_ports"))
    iface = request.POST.get("interface_name", "").strip()
    if not re.match(r"^[\w./:-]+$", iface):
        messages.error(request, "Invalid interface name.")
        return redirect(_device_url(device, section="interfaces_ports"))
    enable = request.POST.get("enable", "false").lower() == "true"
    if enable:
        commands = [f"delete interfaces {iface} disable"]
        summary = f"Enable port {iface}"
    else:
        commands = [f"set interfaces {iface} disable"]
        summary = f"Disable port {iface}"
    return _stage_or_commit(device=device, request=request, action="interface", summary=summary, commands=commands, section="interfaces_ports")


@login_required
@permission_required("devices.manage_interfaces", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def apply_lag(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="interfaces_lag"))
    form = LagConfigForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Please correct the LAG fields.")
        return redirect(_device_url(device, section="interfaces_lag"))
    data = form.cleaned_data
    ae = data["lag_name"].strip()  # e.g. ae0
    commands: list[str] = []
    # Ensure chassis aggregated-devices count is set (idempotent)
    commands.append("set chassis aggregated-devices ethernet device-count 8")
    if data.get("description"):
        commands.append(f'set interfaces {ae} description "{data["description"]}"')
    lacp = data.get("lacp_mode", "off")
    if lacp in ("active", "passive"):
        commands.append(f"set interfaces {ae} aggregated-ether-options lacp {lacp}")
    if data.get("min_links"):
        commands.append(f"set interfaces {ae} aggregated-ether-options minimum-links {data['min_links']}")
    for member in [m.strip() for m in data.get("member_interfaces", "").split(",") if m.strip()]:
        commands.append(f"delete interfaces {member} ether-options")
        commands.append(f"set interfaces {member} ether-options 802.3ad {ae}")
    return _stage_or_commit(device=device, request=request, action="lag",
                            summary=f"LAG {ae} config", commands=commands, section="interfaces_lag")


@login_required
@permission_required("devices.manage_interfaces", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def delete_lag(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="interfaces_lag"))
    ae = request.POST.get("lag_name", "").strip()
    if not re.match(r"^ae\d+$", ae):
        messages.error(request, "Invalid LAG name.")
        return redirect(_device_url(device, section="interfaces_lag"))
    # Remove all member bindings then delete the ae interface
    snapshot = SwitchConfigSnapshot.objects.filter(device=device).first()
    raw = snapshot.raw_config if snapshot else ""
    lags = _parse_lags(raw, "")
    lag = next((l for l in lags if l["name"] == ae), None)
    commands: list[str] = []
    if lag:
        for member in lag["members"]:
            commands.append(f"delete interfaces {member} ether-options 802.3ad")
    commands.append(f"delete interfaces {ae}")
    return _stage_or_commit(device=device, request=request, action="lag",
                            summary=f"Delete LAG {ae}", commands=commands, section="interfaces_lag")


@login_required
@permission_required("devices.manage_interfaces", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def set_lag_device_count(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="interfaces_lag"))
    enable = bool(request.POST.get("enable_aggregation"))
    try:
        count = max(1, min(64, int(request.POST.get("device_count", 8))))
    except (ValueError, TypeError):
        count = 8
    if enable:
        commands = [f"set chassis aggregated-devices ethernet device-count {count}"]
    else:
        commands = ["delete chassis aggregated-devices ethernet device-count"]
    return _stage_or_commit(device=device, request=request, action="lag",
                            summary=f"Set LAG device-count {count}", commands=commands,
                            section="interfaces_lag")


@login_required
@permission_required("devices.manage_vlans", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def apply_vlan(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="switching_vlans"))
    form = VlanConfigForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Please correct the VLAN fields.")
        return redirect(_device_url(device, section="switching_vlans"))
    data = form.cleaned_data
    vname = re.sub(r"[^\w-]", "", data["vlan_name"])
    if not vname:
        messages.error(request, "Invalid VLAN name.")
        return redirect(_device_url(device, section="switching_vlans"))

    commands: list[str] = []
    edit_mode = data.get("edit_mode") or "add"
    original = re.sub(r"[^\w-]", "", data.get("original_vlan_name") or "")

    # If renaming: delete old VLAN definition first
    if edit_mode == "edit" and original and original != vname:
        commands.append(f"delete vlans {original}")

    # VLAN ID / Range
    id_type = data.get("id_type") or "id"
    if id_type == "range" and data.get("vlan_range"):
        vrange = data["vlan_range"].strip()
        if not re.match(r"^[\d,\s\-]+$", vrange):
            messages.error(request, "Invalid VLAN range format.")
            return redirect(_device_url(device, section="switching_vlans"))
        commands.append(f"set vlans {vname} vlan-id-list {vrange}")
    elif data.get("vlan_id"):
        commands.append(f"set vlans {vname} vlan-id {data['vlan_id']}")
    else:
        messages.error(request, "A VLAN ID or VLAN Range is required.")
        return redirect(_device_url(device, section="switching_vlans"))

    if data.get("description"):
        commands.append(f'set vlans {vname} description "{data["description"]}"')
    if data.get("mac_aging"):
        commands.append(f"set vlans {vname} mac-table-aging-time {data['mac_aging']}")
    if data.get("filter_in"):
        fin = re.sub(r"[^\w-]", "", data["filter_in"])
        commands.append(f"set vlans {vname} filter input {fin}")
    if data.get("filter_out"):
        fout = re.sub(r"[^\w-]", "", data["filter_out"])
        commands.append(f"set vlans {vname} filter output {fout}")

    # L3 Interface (RVI / IRB)
    if data.get("l3_interface"):
        l3 = data["l3_interface"].strip()
        if re.match(r"^irb\.\d+$", l3):
            commands.append(f"set vlans {vname} l3-interface {l3}")
            unit = l3.split(".")[1]
            if data.get("l3_inet"):
                commands.append(f"set interfaces irb unit {unit} family inet address {data['l3_inet'].strip()}")
            if data.get("l3_inet6"):
                commands.append(f"set interfaces irb unit {unit} family inet6 address {data['l3_inet6'].strip()}")
        else:
            messages.error(request, "L3 Interface must be in the form irb.<unit> (e.g. irb.10).")
            return redirect(_device_url(device, section="switching_vlans"))

    # Ports tab — single interface assignment
    if data.get("interface_name"):
        iface = re.sub(r"[^\w./:-]", "", data["interface_name"])
        mode = data.get("interface_mode") or "access"
        commands.append(f"set interfaces {iface} unit 0 family ethernet-switching port-mode {mode}")
        commands.append(f"set interfaces {iface} unit 0 family ethernet-switching vlan members {vname}")

    summary = f"VLAN {vname}" + (f" (ID {data['vlan_id']})" if data.get("vlan_id") else f" (range {data.get('vlan_range', '')})")
    return _stage_or_commit(device=device, request=request, action="vlan", summary=summary, commands=commands, section="switching_vlans")


@login_required
@permission_required("devices.manage_vlans", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def delete_vlan(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="switching_vlans"))
    vlan_name = request.POST.get("vlan_name", "").strip()
    if not vlan_name or not re.match(r"^[\w-]+$", vlan_name):
        messages.error(request, "Invalid VLAN name.")
        return redirect(_device_url(device, section="switching_vlans"))
    return _stage_or_commit(device=device, request=request, action="delete_vlan", summary=f"Delete VLAN {vlan_name}", commands=[f"delete vlans {vlan_name}"], section="switching_vlans")


@login_required
@permission_required("devices.manage_vlans", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def remove_vlan_member(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="switching_vlans"))
    vlan_name = request.POST.get("vlan_name", "").strip()
    iface = request.POST.get("interface_name", "").strip()
    if not vlan_name or not re.match(r"^[\w-]+$", vlan_name):
        messages.error(request, "Invalid VLAN name.")
        return redirect(_device_url(device, section="switching_vlans"))
    if not iface or not re.match(r"^[\w./:-]+$", iface):
        messages.error(request, "Invalid interface name.")
        return redirect(_device_url(device, section="switching_vlans"))
    commands = [f"delete interfaces {iface} unit 0 family ethernet-switching vlan members {vlan_name}"]
    return _stage_or_commit(device=device, request=request, action="vlan",
                            summary=f"Remove {iface} from VLAN {vlan_name}",
                            commands=commands, section="switching_vlans")


# ---------------------------------------------------------------------------
# Configure › System Properties
# ---------------------------------------------------------------------------
@login_required
@permission_required("devices.manage_system_settings", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def apply_system_settings(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="system_identity"))
    form = SystemSettingsForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Please correct the system settings.")
        return redirect(_device_url(device, section="system_identity"))
    data = form.cleaned_data
    commands = [f"set system host-name {data['hostname']}"]
    if data.get("domain_name"):
        commands.append(f"set system domain-name {data['domain_name']}")
    if data.get("name_server"):
        commands.append(f"set system name-server {data['name_server']}")
    if data.get("ntp_server"):
        commands.append(f"set system ntp server {data['ntp_server']}")
    if data.get("timezone"):
        commands.append(f"set system time-zone {data['timezone']}")
    return _stage_or_commit(device=device, request=request, action="system_settings", summary=f"System settings: {data['hostname']}", commands=commands, section="system_identity")


@login_required
@permission_required("devices.manage_system_settings", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def apply_ntp_server(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="system_ntp"))
    form = NtpServerForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Invalid NTP server details.")
        return redirect(_device_url(device, section="system_ntp"))
    data = form.cleaned_data
    ip = data["ntp_server"]
    cmd = f"set system ntp server {ip}"
    if data.get("prefer"):
        cmd += " prefer"
    return _stage_or_commit(device=device, request=request, action="ntp",
                            summary=f"Add NTP server {ip}", commands=[cmd], section="system_ntp")


@login_required
@permission_required("devices.manage_system_settings", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def delete_ntp_server(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="system_ntp"))
    ip = request.POST.get("ntp_server", "").strip()
    if not ip:
        messages.error(request, "NTP server IP required.")
        return redirect(_device_url(device, section="system_ntp"))
    return _stage_or_commit(device=device, request=request, action="ntp",
                            summary=f"Delete NTP server {ip}",
                            commands=[f"delete system ntp server {ip}"], section="system_ntp")


@login_required
@permission_required("devices.manage_system_settings", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def apply_snmp_community(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="system_snmp"))
    form = SnmpCommunityForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Invalid SNMP community details.")
        return redirect(_device_url(device, section="system_snmp"))
    data = form.cleaned_data
    community = data["community"]
    auth = data.get("authorization", "read-only")
    return _stage_or_commit(device=device, request=request, action="snmp",
                            summary=f"SNMP community {community}",
                            commands=[f"set snmp community {community} authorization {auth}"],
                            section="system_snmp")


@login_required
@permission_required("devices.manage_system_settings", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def delete_snmp_community(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="system_snmp"))
    community = request.POST.get("community", "").strip()
    if not community or not re.match(r"^[\w\-]+$", community):
        messages.error(request, "Invalid community string.")
        return redirect(_device_url(device, section="system_snmp"))
    return _stage_or_commit(device=device, request=request, action="snmp",
                            summary=f"Delete SNMP community {community}",
                            commands=[f"delete snmp community {community}"],
                            section="system_snmp")


@login_required
@permission_required("devices.manage_system_settings", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def apply_static_route(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="routing"))
    form = StaticRouteForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Invalid static route details.")
        return redirect(_device_url(device, section="routing"))
    data = form.cleaned_data
    prefix = data["prefix"].strip()
    nh = data["next_hop"].strip()
    return _stage_or_commit(device=device, request=request, action="routing",
                            summary=f"Static route {prefix} via {nh}",
                            commands=[f"set routing-options static route {prefix} next-hop {nh}"],
                            section="routing")


@login_required
@permission_required("devices.manage_system_settings", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def delete_static_route(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, section="routing"))
    prefix = request.POST.get("prefix", "").strip()
    if not prefix:
        messages.error(request, "Prefix required.")
        return redirect(_device_url(device, section="routing"))
    return _stage_or_commit(device=device, request=request, action="routing",
                            summary=f"Delete static route {prefix}",
                            commands=[f"delete routing-options static route {prefix}"],
                            section="routing")


# ---------------------------------------------------------------------------
# Maintain › Ping / Traceroute
# ---------------------------------------------------------------------------
@login_required
@permission_required("devices.run_operational_commands", raise_exception=True)
def run_ping(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, tab="maintain", section="maintain_ping"))
    form = PingForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Invalid ping parameters.")
        return redirect(_device_url(device, tab="maintain", section="maintain_ping"))
    host = form.cleaned_data["host"]
    count = form.cleaned_data.get("count") or 5
    job = CommandJob.objects.create(device=device, action="ping", command=f"ping {host} count {count}")
    try:
        out = _client(device).run_ping(host, count)
        job.status = CommandJob.STATUS_SUCCESS
        job.output = out
        messages.success(request, f"Ping to {host} completed.")
    except JuniperSSHError as exc:
        job.status = CommandJob.STATUS_ERROR
        job.output = str(exc)
        messages.error(request, f"Ping failed: {exc}")
    job.completed_at = timezone.now()
    job.save(update_fields=["status", "output", "completed_at"])
    return redirect(_device_url(device, tab="maintain", section="maintain_ping"))


@login_required
@permission_required("devices.run_operational_commands", raise_exception=True)
def run_traceroute(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, tab="maintain", section="maintain_traceroute"))
    host = request.POST.get("host", "").strip()
    if not host:
        messages.error(request, "Host is required.")
        return redirect(_device_url(device, tab="maintain", section="maintain_traceroute"))
    job = CommandJob.objects.create(device=device, action="traceroute", command=f"traceroute {host}")
    try:
        out = _client(device).run_traceroute(host)
        job.status = CommandJob.STATUS_SUCCESS
        job.output = out
        messages.success(request, f"Traceroute to {host} completed.")
    except JuniperSSHError as exc:
        job.status = CommandJob.STATUS_ERROR
        job.output = str(exc)
        messages.error(request, f"Traceroute failed: {exc}")
    job.completed_at = timezone.now()
    job.save(update_fields=["status", "output", "completed_at"])
    return redirect(_device_url(device, tab="maintain", section="maintain_traceroute"))


# ---------------------------------------------------------------------------
# Troubleshoot › Manual Commands
# ---------------------------------------------------------------------------
@login_required
@permission_required("devices.run_manual_commands", raise_exception=True)
def manual_show_command(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, tab="troubleshoot", section="ts_manual_show"))
    form = ManualShowForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Please correct the manual show command.")
        return redirect(_device_url(device, tab="troubleshoot", section="ts_manual_show"))
    data = form.cleaned_data
    command = data["show_command"].strip()
    reason = data.get("reason", "").strip()
    job = CommandJob.objects.create(
        device=device, action="manual_show_edge_case",
        command=command if not reason else f"{command}\n# reason: {reason}",
    )
    try:
        out = _client(device).run_show_command(command)
        job.status = CommandJob.STATUS_SUCCESS
        job.output = out
        messages.success(request, "Show command executed.")
    except JuniperSSHError as exc:
        job.status = CommandJob.STATUS_ERROR
        job.output = str(exc)
        messages.error(request, f"Show command failed: {exc}")
    job.completed_at = timezone.now()
    job.save(update_fields=["status", "output", "completed_at"])
    return redirect(_device_url(device, tab="troubleshoot", section="ts_manual_show"))


@login_required
@permission_required("devices.run_manual_commands", raise_exception=True)
@permission_required("devices.stage_config_changes", raise_exception=True)
def manual_set_commands(request, device_id: int):
    device = get_object_or_404(SwitchDevice, pk=device_id)
    if request.method != "POST":
        return redirect(_device_url(device, tab="troubleshoot", section="ts_manual_set"))
    form = ManualSetForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Please correct the manual set command fields.")
        return redirect(_device_url(device, tab="troubleshoot", section="ts_manual_set"))
    data = form.cleaned_data
    commands = [l.strip() for l in data["set_commands"].splitlines() if l.strip()]
    if not commands:
        messages.error(request, "At least one command is required.")
        return redirect(_device_url(device, tab="troubleshoot", section="ts_manual_set"))
    reason = data.get("reason", "").strip()
    return _stage_or_commit(
        device=device, request=request, action="manual_set_edge_case",
        summary=f"Manual: {reason}" if reason else "Manual edge-case set commands",
        commands=commands, tab="troubleshoot", section="ts_manual_set",
    )
