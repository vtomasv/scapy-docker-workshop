#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time

from scapy.all import IP, TCP, RandShort, sr1, send

from common import parse_ports, print_banner, require_lab_ip, require_root_hint, setup_scapy


def scan_port(target_ip: str, port: int, timeout: float) -> str:
    sport = int(RandShort())
    syn = IP(dst=target_ip) / TCP(sport=sport, dport=port, flags="S", seq=1000)
    ans = sr1(syn, timeout=timeout)

    if ans is None:
        return "filtered|no-response"

    if ans.haslayer(TCP):
        flags = ans[TCP].flags

        if flags & 0x12 == 0x12:  # SYN+ACK
            rst = IP(dst=target_ip) / TCP(sport=sport, dport=port, flags="R", seq=ans[TCP].ack)
            send(rst)
            return "open"

        if flags & 0x14 == 0x14:  # RST+ACK
            return "closed"

        return f"tcp-flags={flags}"

    return ans.summary()


def main():
    parser = argparse.ArgumentParser(description="TCP SYN scan didáctico con Scapy.")
    parser.add_argument("--target", default="web-server")
    parser.add_argument("--ports", default="22,53,80,8080,9998,9999")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--delay", type=float, default=0.15, help="Pausa entre paquetes para evitar ráfagas.")
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    target_ip = require_lab_ip(args.target)
    ports = parse_ports(args.ports)

    print_banner(f"TCP SYN scan Scapy -> {args.target} ({target_ip})")

    for port in ports:
        result = scan_port(target_ip, port, args.timeout)
        print(f"{target_ip}:{port:<5} {result}")
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
