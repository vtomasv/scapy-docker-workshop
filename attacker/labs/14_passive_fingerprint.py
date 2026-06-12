#!/usr/bin/env python3
from __future__ import annotations

import argparse

from scapy.all import IP, TCP, sniff

from common import iface, print_banner, require_root_hint, setup_scapy


def guess_ttl(observed_ttl: int) -> str:
    if observed_ttl <= 64:
        return "probable Linux/Unix ttl inicial 64"
    if observed_ttl <= 128:
        return "probable Windows ttl inicial 128"
    return "probable dispositivo de red ttl inicial 255"


def main():
    parser = argparse.ArgumentParser(description="Fingerprinting pasivo simple basado en TTL y opciones TCP.")
    parser.add_argument("--iface", default=iface())
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    print_banner("Passive fingerprint lab")
    print("[*] Genera tráfico con curl/ping desde victim-client. Ctrl+C para salir.")

    seen = set()

    def handle(pkt):
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        key = ip.src
        if key in seen:
            return
        seen.add(key)

        summary = f"{ip.src:<15} ttl={ip.ttl:<3} {guess_ttl(ip.ttl)}"

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            opts = ",".join(name for name, _ in tcp.options)
            summary += f" tcp_window={tcp.window} tcp_options={opts}"

        print(summary)

    sniff(iface=args.iface, prn=handle, store=False)


if __name__ == "__main__":
    main()
