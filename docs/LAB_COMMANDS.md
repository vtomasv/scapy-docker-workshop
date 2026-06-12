# Comandos rápidos de laboratorio

## Setup

```bash
docker compose build
docker compose up -d
docker compose ps
```

## Terminales recomendadas

```bash
docker compose exec attacker bash
docker compose exec victim-client bash
docker compose logs -f web-server
```

## Reconocimiento

```bash
cd /labs
python 01_icmp_ping.py --target victim-client
python 02_traceroute.py --target web-server
python 03_tcp_syn_scan.py --target web-server --ports 22,53,80,8080,9998,9999
python 04_udp_scan.py --target dns-server --ports 53,123,9999
python 05_arp_discovery.py --subnet 10.10.10.0/24
```

## Ataque LAN controlado

```bash
python 06_arp_spoof_lab.py --victim victim-client --peer web-server
python 07_http_sniff_lab.py --port 8080
```

En víctima:

```bash
curl -v -X POST http://10.10.10.30:8080/login -d 'username=demo&password=demo'
```

## Defensa

```bash
python 10_defense_arp_detector.py
python 11_defense_synscan_detector.py
```

## Bonus

```bash
python 12_fuzzer_udp_toy_protocol.py --target api-server
python 13_ip_fragmentation_demo.py --target api-server
python 14_passive_fingerprint.py
python 15_symbolic_syn_flood.py --target api-server --count 40 --delay 0.05
```
