from __future__ import annotations

import socket
from typing import Iterable

import paramiko

# Unique sentinel used to delimit sections in a batched CLI session
_JWEB_SEP = "===JWEB_SEP==="


class JuniperSSHError(Exception):
    pass


class JuniperSSHClient:
    def __init__(self, host: str, username: str, password: str, port: int = 22, timeout: int = 12):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout

    def run_show_command(self, command: str) -> str:
        prepared = f"{command} | no-more"
        return self._run_single(prepared)

    def run_config_set_commands(self, set_commands: Iterable[str], commit_comment: str = "Committed from central web tool") -> str:
        commands = [c.strip() for c in set_commands if c.strip()]
        if not commands:
            raise JuniperSSHError("No configuration commands were provided.")

        script_lines = ["configure"]
        script_lines.extend(commands)
        script_lines.extend(
            [
                "show | compare",
                f'commit comment "{commit_comment}" and-quit',
            ]
        )

        script = "\n".join(script_lines) + "\n"
        return self._run_cli_stdin(script)

    def get_configuration_version(self) -> str:
        output = self.run_show_command("show system commit")
        for line in output.splitlines():
            clean = line.strip()
            if clean:
                return clean
        return ""

    def get_full_set_configuration(self) -> str:
        return self.run_show_command("show configuration | display set")

    # ------------------------------------------------------------------
    # Batched snapshot: single SSH session for everything
    # ------------------------------------------------------------------

    _SHOW_COMMANDS: dict[str, str] = {
        # Dashboard panels
        "system_info": "show version",
        "uptime": "show system uptime",
        "health": "show chassis routing-engine",
        "chassis_env": "show chassis environment",
        "chassis_fpc": "show chassis fpc",
        "alarms": "show system alarms",
        "ethernet_switching": "show ethernet-switching table summary",
        # Configure sections
        "interfaces": "show interfaces terse",
        "interfaces_detail": "show interfaces detail",
        "vlans": "show vlans",
        "stp": "show spanning-tree bridge",
        "igmp": "show igmp snooping membership",
        "lldp": "show lldp neighbors",
        # Monitor sections
        "route_summary": "show route summary",
        "bgp": "show bgp summary",
        "ospf": "show ospf neighbor",
        "arp": "show arp",
        "mac_table": "show ethernet-switching table",
        "poe": "show poe interface",
        "system_processes": "show system processes summary",
        # Config display sections
        "security": "show configuration firewall | display set",
        "dot1x": "show configuration protocols dot1x | display set",
        "port_security": "show configuration ethernet-switching-options | display set",
        "lldp_config": "show configuration protocols lldp | display set",
        "dhcp": "show configuration system services dhcp | display set",
        "routing_config": "show configuration routing-options | display set",
        "services": "show configuration system services | display set",
        "snmp": "show configuration snmp | display set",
        "ntp_config": "show configuration system ntp | display set",
    }

    def get_full_snapshot(self) -> tuple[str, str, dict[str, str]]:
        """
        Fetch version, full set config, and all operational show commands in a
        single SSH session.  Returns (version, raw_config, ops_snapshot_dict).
        """
        script_lines: list[str] = []

        # Version / commit info
        script_lines.append(f'run echo "{_JWEB_SEP}__version__"')
        script_lines.append("show system commit | no-more")

        # Full set configuration
        script_lines.append(f'run echo "{_JWEB_SEP}__raw_config__"')
        script_lines.append("show configuration | display set | no-more")

        # All operational show commands
        for key, cmd in self._SHOW_COMMANDS.items():
            script_lines.append(f'run echo "{_JWEB_SEP}{key}"')
            script_lines.append(f"{cmd} | no-more")

        script = "\n".join(script_lines) + "\n"
        output = self._run_cli_stdin(script, timeout=180)
        sections = self._parse_sentinel_sections(output)

        version_raw = sections.get("__version__", "")
        # Skip CLI prompt lines (contain @ and >) when extracting version
        version = ""
        for line in version_raw.splitlines():
            stripped = line.strip()
            if stripped and not (("@" in stripped or stripped.startswith(">"))):
                version = stripped
                break

        raw_config = sections.get("__raw_config__", "")
        ops: dict[str, str] = {k: sections.get(k, "") for k in self._SHOW_COMMANDS}
        if not raw_config and not any(ops.values()):
            version = self.get_configuration_version()
            raw_config = self.get_full_set_configuration()
            ops = self.get_operational_snapshot()
        return version, raw_config, ops

    def _parse_sentinel_sections(self, output: str) -> dict[str, str]:
        sections: dict[str, str] = {}
        current_key: str | None = None
        current_lines: list[str] = []
        for line in output.splitlines():
            if line.startswith(_JWEB_SEP):
                if current_key is not None:
                    sections[current_key] = "\n".join(current_lines).strip()
                current_key = line[len(_JWEB_SEP):]
                current_lines = []
            else:
                current_lines.append(line)
        if current_key is not None:
            sections[current_key] = "\n".join(current_lines).strip()
        return sections

    def get_operational_snapshot(self) -> dict[str, str]:
        """Legacy per-command snapshot (26 SSH connections). Use get_full_snapshot() instead."""
        snapshot: dict[str, str] = {}
        for key, command in self._SHOW_COMMANDS.items():
            try:
                snapshot[key] = self.run_show_command(command)
            except JuniperSSHError:
                snapshot[key] = ""
        return snapshot

    def run_ping(self, host: str, count: int = 5) -> str:
        return self.run_show_command(f"ping {host} count {count} rapid")

    def run_traceroute(self, host: str) -> str:
        return self.run_show_command(f"traceroute {host}")

    def _run_single(self, command: str) -> str:
        return self._run_exec(f"cli -c '{command}'")

    def _run_cli_stdin(self, script: str, timeout: int = 60) -> str:
        """Execute a multi-line Junos CLI script by piping it to the cli binary's stdin."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                look_for_keys=False,
                allow_agent=False,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
            stdin, stdout, stderr = client.exec_command("cli", timeout=timeout)
            stdin.write(script)
            stdin.channel.shutdown_write()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            if err.strip() and "warning" not in err.lower():
                raise JuniperSSHError(err.strip())
            return out.strip() if out.strip() else err.strip()
        except (paramiko.SSHException, socket.error) as exc:
            raise JuniperSSHError(str(exc)) from exc
        finally:
            client.close()

    def _run_exec(self, command: str) -> str:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                look_for_keys=False,
                allow_agent=False,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
            stdin, stdout, stderr = client.exec_command(command)
            stdin.close()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")

            if err.strip() and "warning" not in err.lower():
                raise JuniperSSHError(err.strip())
            return out.strip() if out.strip() else err.strip()
        except (paramiko.SSHException, socket.error) as exc:
            raise JuniperSSHError(str(exc)) from exc
        finally:
            client.close()
