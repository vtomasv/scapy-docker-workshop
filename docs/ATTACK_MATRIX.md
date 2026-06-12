# Matriz de casos ofensivos y defensivos

| Caso | Técnica | Protocolo | Riesgo real | Demo lab | Detección | Mitigación |
|---|---|---|---|---|---|---|
| 01 | Ping artesanal | ICMP | Reconocimiento | Enviar Echo Request | Logs/firewall | Rate limit, filtrado selectivo |
| 02 | Traceroute TTL | IP/ICMP | Mapeo de rutas | Manipular TTL | ICMP Time Exceeded | Filtrado/segmentación |
| 03 | SYN scan | TCP | Enumeración de servicios | SYN/SYN-ACK/RST | Detector SYN | Firewall, IDS, tarpitting |
| 04 | UDP scan | UDP/ICMP | Enumeración ambigua | DNS/UDP probes | ICMP/logs UDP | Filtrado UDP, rate limit |
| 05 | ARP discovery | ARP | Descubrimiento LAN | Broadcast ARP | ARP monitor | Segmentación L2 |
| 06 | ARP spoofing | ARP | MITM LAN | Poison victim/peer | IP->MAC changes | DAI, ARP estático, VLANs |
| 07 | HTTP sniffing | HTTP | Robo de credenciales | Captura POST dummy | NIDS, logs | TLS, HSTS, cookies seguras |
| 08 | DNS spoofing | DNS/UDP | Redirección | Respuesta DNS falsa | DNS monitor | DNSSEC, resolvers confiables |
| 09 | TCP RST injection | TCP | Corte de sesión | RST forjado | RST anómalos | TLS no evita corte, pero protege contenido; redes confiables |
| 10 | SYN flood simbólico | TCP | DoS | Tasa limitada | SYN detector | SYN cookies, rate limit |
| 11 | Fuzzing toy | UDP app | Crash/parser bugs | Protocolo propio | Logs app | Validación, límites, manejo de errores |
| 12 | Fragmentación IP | IP | Evasión/DoS | Fragmentos Scapy | IDS reassembly | Normalización y política de fragmentos |
