from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys
from typing import List

from scapy.all import conf


def lab_cidrs() -> List[ipaddress.IPv4Network]:
    raw = os.getenv("LAB_CIDRS", "10.10.10.0/24")
    networks = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        networks.append(ipaddress.ip_network(item, strict=False))
    return networks


def resolve_host(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise SystemExit(f"[!] No pude resolver {target!r}: {exc}") from exc


def require_lab_ip(ip_or_host: str) -> str:
    ip_raw = resolve_host(ip_or_host)
    ip_addr = ipaddress.ip_address(ip_raw)

    if not any(ip_addr in network for network in lab_cidrs()):
        allowed = ", ".join(str(network) for network in lab_cidrs())
        raise SystemExit(
            f"[!] Objetivo fuera del laboratorio: {ip_or_host} -> {ip_raw}. "
            f"Rangos permitidos: {allowed}"
        )

    return str(ip_addr)


def require_lab_cidr(cidr: str) -> str:
    network = ipaddress.ip_network(cidr, strict=False)
    allowed = lab_cidrs()

    if not any(network.subnet_of(item) or network == item for item in allowed):
        allowed_s = ", ".join(str(item) for item in allowed)
        raise SystemExit(f"[!] CIDR fuera del laboratorio: {network}. Permitidos: {allowed_s}")

    return str(network)


def iface() -> str:
    return os.getenv("LAB_IFACE", "eth0")


def setup_scapy(verbose: bool = False) -> None:
    conf.verb = 1 if verbose else 0


def print_banner(title: str) -> None:
    line = "=" * len(title)
    print(line)
    print(title)
    print(line)


def parse_ports(raw: str) -> List[int]:
    ports = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start_s, end_s = item.split("-", 1)
            start, end = int(start_s), int(end_s)
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(item))

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise argparse.ArgumentTypeError(f"Puertos inválidos: {invalid}")

    return sorted(set(ports))


def require_root_hint() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Advertencia: Scapy normalmente requiere root/capacidades NET_RAW.", file=sys.stderr)


def mac_for_ip(ip: str) -> str:
    from scapy.all import getmacbyip

    mac = getmacbyip(ip)
    if not mac:
        raise SystemExit(f"[!] No pude obtener MAC para {ip}. ¿El host está activo?")
    return mac
