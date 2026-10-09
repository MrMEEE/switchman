from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


def run_ad_hoc_show(host: str, username: str, password: str, command: str) -> str:
    """Run a Junos show command through ansible-core as an optional backend."""
    inventory = (
        "[junos]\n"
        f"{host} ansible_user={username} ansible_password={password} "
        "ansible_connection=network_cli ansible_network_os=junipernetworks.junos.junos\n"
    )
    playbook = (
        "- hosts: junos\n"
        "  gather_facts: no\n"
        "  tasks:\n"
        "    - name: run show command\n"
        "      junipernetworks.junos.junos_command:\n"
        "        commands:\n"
        f"          - {command}\n"
    )

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        inv = root / "inventory.ini"
        pb = root / "playbook.yml"
        inv.write_text(inventory, encoding="utf-8")
        pb.write_text(playbook, encoding="utf-8")

        cmd = ["ansible-playbook", "-i", str(inv), str(pb)]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)
    return result.stdout
