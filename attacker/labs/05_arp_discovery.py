#!/usr/bin/env python3
from __future__ import annotations

import argparse

from scapy.all import ARP, Ether, srp

from common import iface, print_banner, require_lab_cidr, require_root_hint, setup_scapy


def main():
    parser = argparse.ArgumentParser(description="Descubrimiento ARP de hosts en la LAN de laboratorio.")
    parser.add_argument("--subnet", default="10.10.10.0/24")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--iface", default=iface())
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    subnet = require_lab_cidr(args.subnet)

    print_banner(f"ARP discovery -> {subnet}")

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(pkt, timeout=args.timeout, iface=args.iface)

    if not answered:
        print("Sin respuestas ARP.")
        return

    print(f"{'IP':<16} {'MAC'}")
    print("-" * 34)
    for _, reply in answered:
        print(f"{reply.psrc:<16} {reply.hwsrc}")


if __name__ == "__main__":
    main()
