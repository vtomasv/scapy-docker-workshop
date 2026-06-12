#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from collections import defaultdict

from scapy.all import ARP, sniff

from common import iface, print_banner, require_root_hint, setup_scapy


def main():
    parser = argparse.ArgumentParser(description="Detector simple de ARP spoofing con Scapy.")
    parser.add_argument("--iface", default=iface())
    parser.add_argument("--window", type=float, default=120.0, help="Ventana de memoria en segundos.")
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    print_banner("ARP spoofing detector")
    print("[*] Observando respuestas ARP. Ctrl+C para salir.")

    ip_to_macs = defaultdict(dict)

    def cleanup(now: float):
        for ip in list(ip_to_macs.keys()):
            for mac in list(ip_to_macs[ip].keys()):
                if now - ip_to_macs[ip][mac] > args.window:
                    del ip_to_macs[ip][mac]
            if not ip_to_macs[ip]:
                del ip_to_macs[ip]

    def handle(pkt):
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]

        if arp.op != 2:
            return

        now = time.time()
        cleanup(now)

        ip = arp.psrc
        mac = arp.hwsrc.lower()

        known_macs = set(ip_to_macs[ip].keys())
        ip_to_macs[ip][mac] = now

        if known_macs and mac not in known_macs:
            all_macs = ", ".join(sorted(ip_to_macs[ip].keys()))
            print(f"[ALERTA] IP {ip} anunciada por múltiples MAC: {all_macs}")
        else:
            print(f"[ARP] {ip} is-at {mac}")

    sniff(iface=args.iface, filter="arp", prn=handle, store=False)


if __name__ == "__main__":
    main()
