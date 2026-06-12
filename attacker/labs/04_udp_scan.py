#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time

from scapy.all import DNS, DNSQR, ICMP, IP, UDP, Raw, sr1

from common import parse_ports, print_banner, require_lab_ip, require_root_hint, setup_scapy


def payload_for_port(port: int):
    if port == 53:
        return DNS(rd=1, qd=DNSQR(qname="demo.local"))
    return Raw(b"SCAPY-LAB-UDP-PROBE")


def scan_udp_port(target_ip: str, port: int, timeout: float) -> str:
    pkt = IP(dst=target_ip) / UDP(dport=port) / payload_for_port(port)
    ans = sr1(pkt, timeout=timeout)

    if ans is None:
        return "open|filtered or no-response"

    if ans.haslayer(ICMP):
        icmp = ans[ICMP]
        if icmp.type == 3 and icmp.code == 3:
            return "closed icmp-port-unreachable"
        return f"icmp type={icmp.type} code={icmp.code}"

    if ans.haslayer(UDP):
        return "open udp-response"

    return ans.summary()


def main():
    parser = argparse.ArgumentParser(description="UDP scan didáctico con Scapy.")
    parser.add_argument("--target", default="dns-server")
    parser.add_argument("--ports", default="53,123,9999")
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--delay", type=float, default=0.2)
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    target_ip = require_lab_ip(args.target)
    ports = parse_ports(args.ports)

    print_banner(f"UDP scan Scapy -> {args.target} ({target_ip})")

    for port in ports:
        result = scan_udp_port(target_ip, port, args.timeout)
        print(f"{target_ip}:{port:<5}/udp {result}")
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
