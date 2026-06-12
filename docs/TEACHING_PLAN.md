# Plan de clase de 3 horas

## Resultado esperado

Al final de la clase, los estudiantes deberían poder:

1. Crear paquetes con Scapy.
2. Enviar y recibir tráfico ICMP, TCP, UDP, DNS y ARP.
3. Explicar cómo funcionan reconocimiento, spoofing y sniffing en una LAN.
4. Ejecutar demos de ataque solo en un entorno autorizado.
5. Implementar detectores simples con Scapy.
6. Proponer mitigaciones por capa.

## Agenda

| Bloque | Tiempo | Contenido | Scripts |
|---|---:|---|---|
| 1 | 0:00-0:10 | Ética, alcance y reglas del laboratorio | README |
| 1 | 0:10-0:25 | Topología Docker y verificación | docker compose ps |
| 1 | 0:25-0:40 | Scapy básico, capas y paquetes | 01_icmp_ping.py |
| 2 | 0:40-1:05 | Reconocimiento ICMP y traceroute | 01, 02 |
| 2 | 1:05-1:25 | TCP SYN scan y UDP scan | 03, 04 |
| 3 | 1:25-1:40 | ARP discovery | 05 |
| 3 | 1:40-2:05 | ARP spoofing + HTTP sniffing | 06, 07 |
| 3 | 2:05-2:15 | Pausa | - |
| 4 | 2:15-2:35 | DNS spoofing controlado | 06, 08 |
| 4 | 2:35-2:45 | TCP RST injection | 06, 09 |
| 4 | 2:45-2:55 | Defensa con Scapy | 10, 11 |
| 4 | 2:55-3:00 | Cierre, mitigaciones y preguntas | Matriz |

## Recomendaciones para dictar la clase

- Tener las imágenes Docker preconstruidas antes de la clase.
- Probar las demos ARP en la misma plataforma donde se dictará.
- Abrir 3 terminales: attacker, victim-client y logs.
- Mantener tcpdump o el detector defensivo visible durante los ataques.
- Repetir siempre: autorización, alcance, red de laboratorio y mitigación.
