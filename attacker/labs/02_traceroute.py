#!/usr/bin/env python3
from __future__ import annotations

import argparse

from scapy.all import ICMP, IP, sr1

from common import print_banner, require_lab_ip, require_root_hint, setup_scapy


def main():
    parser = argparse.ArgumentParser(description="Traceroute didáctico manipulando TTL con Scapy.")
    parser.add_argument("--target", default="web-server")
    parser.add_argument("--max-ttl", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=1.5)
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    target_ip = require_lab_ip(args.target)

    print_banner(f"Traceroute Scapy -> {args.target} ({target_ip})")

    for ttl in range(1, args.max_ttl + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / ICMP()
        ans = sr1(pkt, timeout=args.timeout)

        if ans is None:
            print(f"{ttl:2d}  *")
            continue

        if ans.src == target_ip:
            print(f"{ttl:2d}  {ans.src}  destino alcanzado")
            break

        icmp_type = ans.getlayer(ICMP).type if ans.haslayer(ICMP) else "?"
        print(f"{ttl:2d}  {ans.src}  ICMP type={icmp_type}")


if __name__ == "__main__":
    main()
