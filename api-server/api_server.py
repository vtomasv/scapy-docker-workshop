from __future__ import annotations

import socket
import threading
import time


UDP_HOST = "0.0.0.0"
UDP_PORT = 9999
TCP_HOST = "0.0.0.0"
TCP_PORT = 9998


def parse_toy_protocol(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="replace").strip()

    if text == "PING":
        return b"PONG\n"

    if "|" not in text:
        return b"ERR expected CMD|LEN|DATA or PING\n"

    parts = text.split("|", 2)
    if len(parts) != 3:
        return b"ERR malformed frame\n"

    cmd, declared_len_raw, payload = parts

    try:
        declared_len = int(declared_len_raw)
    except ValueError:
        return b"ERR length is not numeric\n"

    actual_len = len(payload.encode("utf-8"))

    if declared_len != actual_len:
        return f"ERR length mismatch declared={declared_len} actual={actual_len}\n".encode()

    if len(payload) > 256:
        return b"ERR payload too large\n"

    if cmd.upper() == "ECHO":
        return f"OK {payload}\n".encode()

    if cmd.upper() == "TIME":
        return f"OK {time.time()}\n".encode()

    return f"ERR unknown command {cmd!r}\n".encode()


def udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_HOST, UDP_PORT))
    print(f"[api-server] UDP toy protocol listening on {UDP_HOST}:{UDP_PORT}", flush=True)

    while True:
        data, addr = sock.recvfrom(4096)
        print(f"[api-server] UDP from {addr}: {data!r}", flush=True)
        response = parse_toy_protocol(data)
        sock.sendto(response, addr)


def tcp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((TCP_HOST, TCP_PORT))
    sock.listen(64)
    print(f"[api-server] TCP echo listening on {TCP_HOST}:{TCP_PORT}", flush=True)

    while True:
        conn, addr = sock.accept()
        print(f"[api-server] TCP connection from {addr}", flush=True)
        with conn:
            conn.sendall(b"Scapy lab TCP echo. Send bytes, receive bytes. Ctrl+] or close to exit.\n")
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(b"ECHO: " + data)


def main():
    threading.Thread(target=udp_server, daemon=True).start()
    threading.Thread(target=tcp_server, daemon=True).start()

    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
