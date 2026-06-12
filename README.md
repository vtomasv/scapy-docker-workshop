# Scapy Docker Workshop

Laboratorio reproducible para una clase de 3 horas sobre Scapy aplicado a pruebas de redes y hacking ético.

> **Uso autorizado solamente.** Este repositorio está diseñado para ejecutarse en redes Docker internas, con servicios toy y rangos de laboratorio. No uses estos scripts contra sistemas, redes o direcciones IP que no controles o donde no tengas autorización explícita.

## Objetivos

- Construir, enviar, recibir y analizar paquetes con Scapy.
- Demostrar reconocimiento activo: ICMP, traceroute, TCP SYN scan, UDP scan.
- Demostrar ataques LAN controlados: ARP discovery, ARP spoofing, sniffing HTTP, DNS spoofing.
- Entender ataques TCP controlados: TCP RST injection y DoS simbólico.
- Implementar detectores simples con Scapy: ARP spoofing y SYN scan.
- Discutir mitigaciones por capa.

## Requisitos

- Docker Engine reciente.
- Docker Compose v2.
- Linux recomendado. En macOS/Windows con Docker Desktop algunas demos L2, especialmente ARP spoofing y sniffing, pueden comportarse distinto por la virtualización de red.

## Levantar el laboratorio

```bash
docker compose build
docker compose up -d
docker compose ps
```

Entrar al contenedor atacante:

```bash
docker compose exec attacker bash
```

Entrar al cliente víctima:

```bash
docker compose exec victim-client bash
```

Ver logs de servicios:

```bash
docker compose logs -f web-server
docker compose logs -f api-server
docker compose logs -f dns-server
```

Apagar:

```bash
docker compose down
```

## Topología

```text
Red Docker interna: lab_lan 10.10.10.0/24

10.10.10.10  attacker       Python + Scapy + tcpdump
10.10.10.20  victim-client  curl, dig, ping, generador de tráfico
10.10.10.30  web-server     Flask HTTP vulnerable de laboratorio
10.10.10.40  api-server     TCP/UDP toy protocol
10.10.10.53  dns-server     DNS UDP toy para demo.local
10.10.10.60  monitor        tcpdump + Scapy defensivo
```

La red `lab_lan` está marcada como `internal: true` para reducir exposición accidental. Los servicios no publican puertos hacia el host.

## Scripts principales

Desde el contenedor `attacker`:

```bash
cd /labs

python 01_icmp_ping.py --target victim-client
python 02_traceroute.py --target web-server --max-ttl 5
python 03_tcp_syn_scan.py --target web-server --ports 22,53,80,8080,9998,9999
python 04_udp_scan.py --target dns-server --ports 53,123,9999
python 05_arp_discovery.py --subnet 10.10.10.0/24
python 10_defense_arp_detector.py
python 11_defense_synscan_detector.py
python 12_fuzzer_udp_toy_protocol.py --target api-server
python 13_ip_fragmentation_demo.py --target api-server
python 14_passive_fingerprint.py
```

## Demos con interacción

### Generar tráfico HTTP desde la víctima

En una terminal:

```bash
docker compose exec victim-client bash
```

Dentro de `victim-client`:

```bash
/opt/traffic-generator.sh
```

O manualmente:

```bash
curl -v http://10.10.10.30:8080/
curl -v -X POST http://10.10.10.30:8080/login \
  -d 'username=demo&password=demo'
```

### Sniffing HTTP controlado

En `attacker`:

```bash
python 07_http_sniff_lab.py --iface eth0 --port 8080
```

Si el tráfico no pasa por el atacante, primero ejecutar ARP spoofing controlado contra `victim-client` y `web-server`.

### ARP spoofing controlado

Terminal 1, en `attacker`:

```bash
python 06_arp_spoof_lab.py --victim victim-client --peer web-server
```

Terminal 2, en `attacker`:

```bash
python 07_http_sniff_lab.py --iface eth0 --port 8080
```

Terminal 3, en `victim-client`:

```bash
curl -v -X POST http://10.10.10.30:8080/login \
  -d 'username=demo&password=demo'
```

Detección defensiva en `monitor` o `attacker`:

```bash
python 10_defense_arp_detector.py
```

### DNS spoofing controlado

Terminal 1, en `attacker`:

```bash
python 06_arp_spoof_lab.py --victim victim-client --peer dns-server
```

Terminal 2, en `attacker`:

```bash
python 08_dns_spoof_lab.py --victim victim-client --domain demo.local --spoof-ip 10.10.10.40
```

Terminal 3, en `victim-client`:

```bash
dig @10.10.10.53 demo.local
```

### TCP RST injection controlado

Terminal 1, en `attacker`:

```bash
python 06_arp_spoof_lab.py --victim victim-client --peer web-server
```

Terminal 2, en `attacker`:

```bash
python 09_tcp_rst_lab.py --victim victim-client --server web-server --port 8080
```

Terminal 3, en `victim-client`:

```bash
curl -v http://10.10.10.30:8080/slow
```

## Agenda sugerida para 3 horas

Ver `docs/TEACHING_PLAN.md`.

## Matriz ataque/defensa

Ver `docs/ATTACK_MATRIX.md`.

## Subir a GitHub

Como el conector actual de ChatGPT no expone una acción para crear repositorios nuevos, crea un repo vacío en GitHub llamado, por ejemplo:

```text
scapy-docker-workshop
```

Luego puedes subir este árbol:

```bash
cd scapy-docker-workshop
git init
git add .
git commit -m "Initial Scapy Docker workshop"
git branch -M main
git remote add origin git@github.com:vtomasv/scapy-docker-workshop.git
git push -u origin main
```

También puedes indicarme el nombre de un repositorio existente y puedo crear los archivos allí con el conector.
