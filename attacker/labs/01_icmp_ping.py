#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time

from scapy.all import ICMP, IP, Raw, sr1

from common import print_banner, require_lab_ip, require_root_hint, setup_scapy


def main():
    parser = argparse.ArgumentParser(description="ICMP ping artesanal con Scapy.")
    parser.add_argument("--target", default="victim-client", help="IP o nombre dentro del laboratorio.")
    parser.add_argument("--count", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=1.5)
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    target_ip = require_lab_ip(args.target)

    print_banner(f"ICMP ping Scapy -> {args.target} ({target_ip})")

    for seq in range(1, args.count + 1):
        packet = IP(dst=target_ip, ttl=64) / ICMP(id=0xCAFE, seq=seq) / Raw(b"SCAPY-LAB")
        start = time.time()
        reply = sr1(packet, timeout=args.timeout)
        elapsed_ms = (time.time() - start) * 1000

        if reply and reply.haslayer(ICMP):
            print(
                f"seq={seq} reply={reply[IP].src} "
                f"ttl={reply[IP].ttl} type={reply[ICMP].type} "
                f"rtt={elapsed_ms:.2f} ms"
            )
        else:
            print(f"seq={seq} timeout")

        time.sleep(0.3)


if __name__ == "__main__":
    main()
