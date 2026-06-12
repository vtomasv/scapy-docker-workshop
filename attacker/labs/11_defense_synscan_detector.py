#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from collections import defaultdict, deque

from scapy.all import IP, TCP, sniff

from common import iface, print_banner, require_root_hint, setup_scapy


def main():
    parser = argparse.ArgumentParser(description="Detector simple de TCP SYN scan con Scapy.")
    parser.add_argument("--iface", default=iface())
    parser.add_argument("--window", type=float, default=10.0)
    parser.add_argument("--threshold", type=int, default=6, help="Cantidad de puertos distintos en la ventana.")
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    print_banner("TCP SYN scan detector")
    print(f"[*] window={args.window}s threshold={args.threshold} puertos distintos")
    print("[*] Ctrl+C para salir.")

    events = defaultdict(deque)

    def handle(pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        tcp = pkt[TCP]
        ip = pkt[IP]

        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            return

        key = (ip.src, ip.dst)
        now = time.time()
        events[key].append((now, tcp.dport))

        while events[key] and now - events[key][0][0] > args.window:
            events[key].popleft()

        ports = {port for _, port in events[key]}

        if len(ports) >= args.threshold:
            print(
                f"[ALERTA] posible SYN scan {ip.src} -> {ip.dst}: "
                f"{len(ports)} puertos en {args.window:.0f}s {sorted(ports)}"
            )
            events[key].clear()
        else:
            print(f"[SYN] {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}")

    sniff(iface=args.iface, filter="tcp", prn=handle, store=False)


if __name__ == "__main__":
    main()
