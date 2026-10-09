from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SnmpInterfaceStatus:
    name: str
    admin: str
    link: str
    in_octets: int | None = None
    out_octets: int | None = None

    @property
    def total_octets(self) -> int | None:
        if self.in_octets is None and self.out_octets is None:
            return None
        return (self.in_octets or 0) + (self.out_octets or 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "admin": self.admin,
            "link": self.link,
            "in_octets": self.in_octets,
            "out_octets": self.out_octets,
            "total_octets": self.total_octets,
        }


class SnmpPollError(Exception):
    pass


IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"

ADMIN_STATUS = {
    1: "up",
    2: "down",
    3: "testing",
}

OPER_STATUS = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}


def _decode_index(oid: object) -> str:
    return str(oid).split(".")[-1]


def _as_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


async def _walk(host: str, community: str, port: int, timeout: float, oid: str, max_rows: int = 128) -> dict[str, object]:
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            walk_cmd,
        )
    except ImportError as exc:
        raise SnmpPollError("SNMP support requires the pysnmp package to be installed.") from exc

    values: dict[str, object] = {}
    try:
        transport = await UdpTransportTarget.create((host, port), timeout=timeout, retries=0)
        iterator = walk_cmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographic_mode=False,
        )
        async for error_indication, error_status, error_index, var_binds in iterator:
            if error_indication:
                if values:
                    break
                raise SnmpPollError(str(error_indication))
            if error_status:
                if values:
                    break
                raise SnmpPollError(f"{error_status.prettyPrint()} at {error_index}")
            for name, value in var_binds:
                values[_decode_index(name)] = value.prettyPrint() if hasattr(value, "prettyPrint") else value
                if len(values) >= max_rows:
                    return values
    except SnmpPollError:
        raise
    except Exception as exc:
        raise SnmpPollError(str(exc)) from exc
    return values


async def _safe_walk(host: str, community: str, port: int, timeout: float, oid: str) -> dict[str, object]:
    try:
        return await asyncio.wait_for(
            _walk(host, community, port, timeout, oid),
            timeout=max(4.0, min(8.0, timeout * 5)),
        )
    except (SnmpPollError, asyncio.TimeoutError):
        return {}


async def _collect_interface_status(host: str, community: str, port: int, timeout: float) -> list[SnmpInterfaceStatus]:
    names = await _safe_walk(host, community, port, timeout, IF_NAME)
    if not names:
        names = await _safe_walk(host, community, port, timeout, IF_DESCR)
    if not names:
        return []

    admin, oper, in_octets, out_octets = await asyncio.gather(
        _safe_walk(host, community, port, timeout, IF_ADMIN_STATUS),
        _safe_walk(host, community, port, timeout, IF_OPER_STATUS),
        _safe_walk(host, community, port, timeout, IF_HC_IN_OCTETS),
        _safe_walk(host, community, port, timeout, IF_HC_OUT_OCTETS),
    )

    if not in_octets:
        in_octets = await _safe_walk(host, community, port, timeout, IF_IN_OCTETS)
    if not out_octets:
        out_octets = await _safe_walk(host, community, port, timeout, IF_OUT_OCTETS)

    statuses = []
    for index, name in names.items():
        interface_name = _first_non_empty(name)
        if not interface_name.startswith(("ge-", "xe-", "et-", "fe-", "ae")) or "." in interface_name:
            continue
        statuses.append(
            SnmpInterfaceStatus(
                name=interface_name,
                admin=ADMIN_STATUS.get(_as_int(admin.get(index)) or 0, "unknown"),
                link=OPER_STATUS.get(_as_int(oper.get(index)) or 0, "unknown"),
                in_octets=_as_int(in_octets.get(index)),
                out_octets=_as_int(out_octets.get(index)),
            )
        )
    return statuses


def collect_interface_status(host: str, community: str, port: int = 161, timeout: float = 1.0) -> list[SnmpInterfaceStatus]:
    try:
        return asyncio.run(_collect_interface_status(host, community, port, timeout))
    except SnmpPollError:
        raise
    except Exception as exc:
        raise SnmpPollError(str(exc)) from exc


def _first_non_empty(*values: object) -> str:
    for value in values:
        if value not in (None, ""):
            return str(value)
    return ""


