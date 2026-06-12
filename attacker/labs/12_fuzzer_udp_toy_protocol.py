#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import string
import time

from scapy.all import IP, UDP, Raw, sr1

from common import print_banner, require_lab_ip, require_root_hint, setup_scapy


def cases():
    base = [
        b"PING",
        b"ECHO|5|hello",
        b"ECHO|4|hello",
        b"ECHO|999|short",
        b"TIME|0|",
        b"UNKNOWN|3|abc",
        b"NO_SEPARATOR",
        b"|||",
        b"ECHO|abc|hello",
        b"ECHO|-1|x",
        b"ECHO|300|" + b"A" * 300,
    ]

    for item in base:
        yield item

    for _ in range(20):
        payload = "".join(random.choice(string.printable) for _ in range(random.randint(0, 300)))
        declared = random.choice([len(payload), len(payload) + 1, 0, 999, -1])
        cmd = random.choice(["ECHO", "TIME", "PING", "X", ""])
        yield f"{cmd}|{declared}|{payload}".encode("utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser(description="Fuzzing básico del protocolo UDP toy.")
    parser.add_argument("--target", default="api-server")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--delay", type=float, default=0.1)
    args = parser.parse_args()

    require_root_hint()
    setup_scapy()

    target_ip = require_lab_ip(args.target)

    print_banner(f"UDP toy protocol fuzzing -> {target_ip}:{args.port}")

    for i, payload in enumerate(cases(), start=1):
        pkt = IP(dst=target_ip) / UDP(dport=args.port) / Raw(payload)
        ans = sr1(pkt, timeout=args.timeout)
        response = bytes(ans[Raw].load).decode("utf-8", errors="replace").strip() if ans and ans.haslayer(Raw) else "<no response>"
        print(f"[{i:02d}] sent={payload[:80]!r} response={response!r}")
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
