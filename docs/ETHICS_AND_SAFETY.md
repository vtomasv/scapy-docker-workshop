# Ética y seguridad

Este taller es para hacking ético, docencia y pruebas autorizadas.

## Reglas obligatorias

1. Ejecutar los scripts solo dentro de las redes Docker del laboratorio.
2. No apuntar a IPs externas, redes corporativas o redes públicas.
3. No usar credenciales reales.
4. No publicar puertos del laboratorio hacia Internet.
5. No remover los controles de rango de los scripts.
6. No aumentar tasas de DoS simbólico.
7. Cada demostración ofensiva debe discutirse junto con detección y mitigación.

## Controles implementados

- Red Docker `internal: true`.
- Servicios sin `ports:` publicados hacia host.
- Validación de rangos mediante `LAB_CIDRS`.
- Scripts de DoS limitados por `count` y `delay`.
- Servicios vulnerables son toy services.
