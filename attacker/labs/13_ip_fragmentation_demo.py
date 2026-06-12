#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time

from scapy.all import IP, UDP, Raw, fragment, send

from common import print_banner, require_lab_ip, require_root_hint, setup_scapy


def main():
    parser = argparse.ArgumentParser(description="Demo de fragmentación IP con Scapy.")
    parser.add_argument("--target", default="api-server")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--fragsize", type=int, default=24)
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    target_ip = require_lab_ip(args.target)

    print_banner(f"IP fragmentation demo -> {target_ip}:{args.port}")

    payload = b"ECHO|200|" + b"A" * 200
    pkt = IP(dst=target_ip, id=0xBEEF) / UDP(dport=args.port) / Raw(payload)

    fragments = fragment(pkt, fragsize=args.fragsize)
    print(f"Paquete original len={len(bytes(pkt))} fragmentos={len(fragments)} fragsize={args.fragsize}")

    for idx, frag in enumerate(fragments, start=1):
        flags = frag.sprintf("%IP.flags%")
        print(f"[{idx}] id={frag.id} offset={frag.frag} flags={flags} len={len(bytes(frag))}")
        send(frag, verbose=False)
        time.sleep(0.1)

    print("Fragmentos enviados. Revisa logs de api-server.")


if __name__ == "__main__":
    main()
