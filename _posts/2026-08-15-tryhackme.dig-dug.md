---
title: "Dig Dug"
date: 2026-08-15 21:53:00 -0400
description: "Enumeración DNS contra un servidor configurado de forma no estándar, descubriendo una flag oculta en un registro TXT mediante consultas directas con dig."
categories: [TryHackMe, Cyber Security 101]
tags: [DNS, dig, enumeration, fácil, CTF]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Cyber Security 101 — Dig Dug
> - **Dificultad:** Fácil
> - **Categoría:** OSINT / Reconocimiento
> - **Técnicas Clave:** Enumeración DNS, consulta directa a servidor DNS autoritativo, análisis de registros TXT, intento de transferencia de zona (AXFR)

---

## Introducción

**Dig Dug** es una sala de TryHackMe orientada al reconocimiento mediante **enumeración DNS**. El objetivo es interactuar con un servidor DNS en la IP `10.65.164.237` que, según la descripción del reto, solo responde a un "tipo especial de solicitud" para el dominio `givemetheflag.com`.

La sala pone a prueba la comprensión de cómo funciona el protocolo DNS, la importancia de consultar directamente al servidor autoritativo y la capacidad de interpretar respuestas no convencionales.

---

## Reconocimiento

### Descripción del Objetivo

La máquina objetivo (`10.65.164.237`) actúa como servidor DNS autoritativo para el dominio `givemetheflag.com`. Sin embargo, el reto indica que el comportamiento del servidor es "extraño": no responde de manera estándar y requiere una interacción específica para revelar información sensible.

> La clave está en entender que `givemetheflag.com` **no existe en Internet pública**. Es un dominio ficticio creado exclusivamente para este laboratorio, por lo que ningún resolver DNS público (como Google `8.8.8.8` o Cloudflare `1.1.1.1`) tendrá registros de él.
{: .prompt-info }

### Herramientas Disponibles

El AttackBox de TryHackMe incluye las herramientas estándar de enumeración DNS:

- `dig` — Cliente DNS flexible y detallado.
- `nslookup` — Cliente DNS interactivo/sencillo.
- `host` — Consultas DNS rápidas.
- `dnsenum` / `fierce` — Automatización de enumeración DNS.

Dado el nombre de la sala (**Dig Dug**), `dig` es la herramienta principal recomendada.

---

## Enumeración DNS

### Paso 1: Consulta Directa al Servidor Autoritativo

El primer paso lógico es consultar **directamente** al servidor DNS objetivo, omitiendo el resolver configurado por defecto en el sistema. Esto se logra con el modificador `@` en `dig`:

```bash
dig @10.65.164.237 givemetheflag.com
```

> El modificador `@<IP>` le indica a `dig` que envíe el paquete UDP directamente a la dirección IP especificada (puerto 53), ignorando por completo la configuración de `/etc/resolv.conf`.
{: .prompt-tip }

### Análisis de la Respuesta

El servidor respondió con lo siguiente:

```
; <<>> DiG 9.18.28 <<>> @10.65.164.237 givemetheflag.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35035
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;givemetheflag.com.         IN      A

;; ANSWER SECTION:
givemetheflag.com.  0       IN      TXT     "flag{0767ccd06e79853318f25aeb08ff83e2}"

;; Query time: 202 msec
;; SERVER: 10.65.164.237#53(10.65.164.237) (UDP)
;; WHEN: Sat Aug 15 21:33:27 -04 2026
;; MSG SIZE  rcvd: 86
```

#### Hallazgos Clave

1. **Discrepancia de Tipo de Registro**: En la `QUESTION SECTION` se solicitó un registro de tipo **A** (dirección IPv4), pero la `ANSWER SECTION` devolvió un registro de tipo **TXT**. Esto indica que el servidor DNS está configurado de forma no estándar, respondiendo con un registro TXT independientemente del tipo de consulta recibida.

2. **TTL = 0**: El campo TTL (Time To Live) del registro es `0` segundos. Esto significa que el registro **no debe ser cacheado** por ningún resolver intermedio. En un CTF, esto fuerza a cada participante a consultar directamente al servidor autoritativo, evitando que la respuesta se propague o se almacene en caché local.

3. **Flag `aa` (Authoritative Answer)**: Confirma que `10.65.164.237` es efectivamente el servidor autoritativo para este dominio.

### Paso 2: Intento de Transferencia de Zona (AXFR)

Como paso de enumeración adicional, se probó una **transferencia de zona DNS (AXFR)**. AXFR es un tipo de consulta que solicita la transferencia completa de todos los registros de una zona DNS. Si el servidor está mal configurado, esta técnica revelaría la totalidad de los subdominios, registros y la topología completa del dominio.

```bash
dig @10.65.164.237 givemetheflag.com AXFR
```

Resultado:

```
;; Connection to 10.65.164.237#53(10.65.164.237) for givemetheflag.com failed: connection refused.
;; no servers could be reached
```

> La transferencia de zona fue **rechazada**. Esto es una configuración de seguridad correcta: el servidor no permite que clientes no autorizados descarguen la base de datos DNS completa mediante AXFR.
{: .prompt-warning }

---

## Explotación / Obtención de la Flag

La flag se obtuvo directamente en el **Paso 1**, sin necesidad de explotación adicional. El reto se centró en la **observación y el análisis correcto de la respuesta DNS**.

**Flag:**

```
flag{0767ccd06e79853318f25aeb08ff83e2}
```

---

## Conclusión / Retroalimentación

### Aprendizajes Clave

1. **Consulta Directa con `@`**: Entender que `dig @<IP>` permite saltar el resolver del sistema y hablar directamente con un servidor DNS específico es fundamental en entornos de laboratorio donde los dominios no existen en Internet pública.

2. **Análisis de Respuestas No Convencionales**: No siempre la respuesta será del tipo solicitado. En CTFs, los servidores DNS pueden estar configurados para devolver registros TXT, CNAME u otros tipos independientemente de la consulta inicial. Leer cuidadosamente la `ANSWER SECTION` es crítico.

3. **Interpretación del TTL**: Un TTL de `0` es una señal de alerta. En producción, esto puede indicar DNS dinámico, balanceo de carga o, como en este caso, una configuración diseñada para evitar el cacheo y forzar consultas directas.

4. **AXFR como Vector de Enumeración**: Aunque en este reto no fue exitoso, probar la transferencia de zona es un paso estándar en auditorías de seguridad. Un AXFR abierto es una vulnerabilidad grave que expone toda la infraestructura DNS de una organización.

### Feedback de la Sala

**Dig Dug** es una sala excelente para principiantes en el mundo del reconocimiento y la enumeración DNS. No requiere explotación compleja, pero exige que el participante comprenda el funcionamiento interno del protocolo DNS, la diferencia entre un resolver recursivo y un servidor autoritativo, y cómo interpretar el output de `dig` correctamente.

La dificultad es adecuada: el reto guía al usuario a través de la lógica de "¿por qué no funciona una consulta normal?" hasta llegar a la solución mediante la consulta directa. Es un excelente punto de partida antes de enfrentar retos más complejos de OSINT o reconocimiento de infraestructura.
