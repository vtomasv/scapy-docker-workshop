from __future__ import annotations

import socketserver
from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR


RECORDS = {
    "demo.local.": "10.10.10.30",
    "web.local.": "10.10.10.30",
    "api.local.": "10.10.10.40",
}


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        client_ip, client_port = self.client_address

        try:
            request = DNSRecord.parse(data)
        except Exception as exc:
            print(f"[dns-server] parse error from {self.client_address}: {exc}", flush=True)
            return

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
            q=request.q,
        )

        qname = str(request.q.qname).lower()
        qtype = QTYPE[request.q.qtype]

        if qtype in ("A", "ANY") and qname in RECORDS:
            ip = RECORDS[qname]
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=30))
            print(f"[dns-server] {client_ip}:{client_port} {qname} -> {ip}", flush=True)
        else:
            print(f"[dns-server] {client_ip}:{client_port} {qname} type={qtype} -> NX/no answer", flush=True)

        sock.sendto(reply.pack(), self.client_address)


def main():
    server = socketserver.ThreadingUDPServer(("0.0.0.0", 53), DNSHandler)
    print("[dns-server] UDP DNS toy server listening on 0.0.0.0:53", flush=True)
    print(f"[dns-server] records={RECORDS}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
