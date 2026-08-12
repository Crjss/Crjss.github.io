---
title: "Packed Light"
date: 2026-07-30 09:30:00 -0400
description: "Análisis forense de tráfico de red para descubrir un canal encubierto (covert channel) que exfiltra datos byte a byte mediante cookies HTTP cifradas con XOR, resuelto mediante un Known-Plaintext Attack."
categories: [TryHackMe, Hacker Holidays]
tags: [forensics, pcap, covert-channel, xor, known-plaintext-attack, tshark, python, easy]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays — Packed Light
> - **Dificultad:** Fácil
> - **Categoría:** Forensics
> - **Técnicas Clave:** Análisis de tráfico PCAP, identificación de covert channels, criptoanálisis XOR (Known-Plaintext Attack), automatización con Python/tshark

---

## Introducción

En este reto de la serie *Hacker Holidays* de TryHackMe, nos enfrentamos a una captura de red (`traffic.pcapng`) proveniente de la red de invitados de un hotel. La premisa es clara: alguien está "robando toallas" — exfiltrando datos de forma encubierta — a través de tráfico que a primera vista parece ordinario. El desafío consiste en identificar el canal encubierto, reensamblar los datos fragmentados y descifrarlos para obtener la flag.

> La historia del reto y las pistas de `@0xMia` son fundamentales. En forense de red, el enunciado y el contexto narrativo suelen contener el 80 % de la orientación inicial.
{: .prompt-info }

---

## Reconocimiento y Análisis Inicial

### Pistas del briefing

Las pistas clave que orientan la investigación son:

- **"Laptop pinging random :8080 address every single second like clockwork"** → Existe tráfico automatizado con una periodicidad exacta de 1 segundo hacia el puerto 8080.
- **"Request headers are giving not a real app"** → El secreto reside en los encabezados HTTP (cookies, user-agent, etc.), no en el cuerpo de las peticiones.
- **"What is with the crypto"** → Los datos exfiltrados están ofuscados o cifrados.

### Inspección general del tráfico

El primer paso consiste en filtrar el PCAP para observar únicamente las peticiones HTTP y obtener una visión de alto nivel:

```bash
tshark -r traffic.pcapng -Y "http.request" -T fields   -e http.request.method   -e http.request.uri   -e http.user_agent   -e http.host
```

**Hallazgos:**

1. La primera petición es legítima: un usuario descarga `/temp/updates.py` con un navegador Chrome estándar.
2. A partir de ahí, se observa un bucle infinito de peticiones `GET /` con un `User-Agent` no estándar: `ByteLotusClient/1.1`.

> El `User-Agent` anómalo es un indicador de compromiso (IoC) clásico. Cuando el tráfico es "demasiado regular", hay que sospechar de automatización maliciosa.
{: .prompt-tip }

---

## Identificación del Canal Encubierto (Covert Channel)

Un **canal encubierto** es una técnica donde el atacante oculta información dentro de un protocolo legítimo para evadir firewalls, IDS/IPS y otras soluciones de seguridad perimetral.

Dado que la URI (`/`) y el `User-Agent` no variaban, el siguiente paso lógico es inspeccionar **todos** los encabezados HTTP de cada petición:

```bash
tshark -r traffic.pcapng -Y "http.request" -T fields   -e http.request.line   -e http.file_data
```

### El hallazgo clave 🎯

Cada petición lleva una cookie `hotel_sess_state` con un valor diferente y aparentemente inocuo:

```text
Cookie: hotel_sess_state=HA==
Cookie: hotel_sess_state=AA==
Cookie: hotel_sess_state=BQ==
Cookie: hotel_sess_state=Mw==
...
```

**Conclusión:** El malware está exfiltrando información **un byte a la vez**, empaquetado en valores Base64 dentro de la cookie `hotel_sess_state`, enviando una petición cada segundo. Una "toalla de hotel dobladita" en cada paquete.

> Los covert channels en metadatos de protocolo (headers, cookies, campos de timing) son extremadamente difíciles de detectar con firmas tradicionales porque no violan la sintaxis del protocolo.
{: .prompt-warning }

---

## Criptoanálisis: Known-Plaintext Attack sobre XOR

### Confirmación de cifrado adicional

Tomamos la primera cookie (`HA==`) y la decodificamos de Base64:

```python
import base64
base64.b64decode("HA==")  # b'\x1c' → byte decimal 28
```

El byte `28` (`0x1C`) no es un carácter ASCII imprimible. Esto confirma que, además del encoding Base64, existe una capa de cifrado adicional. Dada la simplicidad del reto y la pista sobre "crypto", el cifrado más probable es **XOR**.

### Ataque de texto plano conocido (KPA)

La propiedad matemática del cifrado XOR (`⊕`) es la siguiente:

```
Texto Plano ⊕ Clave = Texto Cifrado
Texto Plano ⊕ Texto Cifrado = Clave
```

En los retos de TryHackMe, sabemos con **certeza absoluta** que las flags comienzan con el prefijo `THM{`. Esto nos proporciona un texto plano conocido de 4 caracteres, suficiente para derivar la clave.

**Cálculo:**

- Texto plano conocido: `T` → ASCII `84`
- Texto cifrado interceptado (primer byte): `28`
- Clave: `84 ⊕ 28 = 62`

La clave de cifrado es el byte `62` (carácter ASCII `>`).

> El Known-Plaintext Attack es una de las técnicas más poderosas en criptoanálisis. Siempre que conozcas un fragmento del mensaje original, puedes revertir operaciones simétricas simples como XOR o Vigenère.
{: .prompt-tip }

---

## Automatización y Recuperación de la Flag

Extraer 30+ cookies manualmente, decodificarlas de Base64 y aplicar XOR byte a byte sería tedioso y propenso a errores. Automatizamos todo el flujo con un script en Python que orquesta `tshark`:

```python
import subprocess
import base64

# 1. Extraer todas las cookies hotel_sess_state del PCAP en orden
cmd = (
    "tshark -r traffic.pcapng "
    '-Y "http.cookie contains \"hotel_sess_state\"" '
    "-T fields -e http.cookie"
)
output = subprocess.check_output(cmd, shell=True).decode("utf-8")

raw_bytes = []
for line in output.strip().split("
"):
    for item in line.split(";"):
        item = item.strip()
        if item.startswith("hotel_sess_state="):
            b64_val = item.split("=")[1]
            if b64_val:
                raw_bytes.append(base64.b64decode(b64_val)[0])

# 2. Derivar la clave XOR sabiendo que la flag empieza con 'T'
key = raw_bytes[0] ^ ord("T")

# 3. Decodificar cada byte aplicando XOR con la clave descubierta
flag = "".join(chr(b ^ key) for b in raw_bytes)

print(f"[*] Clave descubierta: {key}")
print(f"[+] Flag final: {flag}")
```

### Ejecución y resultado

```text
[*] Clave descubierta: 62
[+] Flag final: THM{V3r4_1s_w4tch1ng_0veR_y0u}
```

> **Nota de seguridad:** En entornos de producción, evita `shell=True` en `subprocess`. Aquí se mantiene por brevedad didáctica, pero para herramientas reutilizables es preferible pasar la lista de argumentos directamente o usar librerías como `pyshark`.
{: .prompt-warning }

---

## Conclusión / Retroalimentación

### Aprendizajes clave

1. **No ignores el contexto narrativo:** Las pistas del briefing y los posts de `@0xMia` aceleraron enormemente la orientación inicial. En CTFs forenses, el 80 % del trabajo es saber *dónde* mirar.

2. **La regularidad es sospechosa:** Tráfico con periodicidad exacta (1 petición/segundo), URI fija y `User-Agent` inusual son indicadores clásicos de beaconing o exfiltración automatizada.

3. **Los covert channels en headers son stealth:** Al no alterar el cuerpo de las peticiones ni generar volúmenes anómalos de datos, este tipo de técnicas pasan desapercibidas para muchas soluciones DLP y NIDS basadas en volumetría.

4. **XOR + KPA = Game Over:** Un cifrado tan simple como XOR se derrumba completamente ante un ataque de texto plano conocido. En competiciones reales (y en malware real), esto subraya la importancia de usar claves únicas por sesión y algoritmos robustos.

### Feedback de la sala

- **Dificultad ajustada:** El reto es *Easy* pero no trivial. Requiere conectar varios conceptos (análisis de PCAP, covert channels, criptoanálisis básico), lo que lo convierte en una excelente introducción a forense de red.
- **Narrativa cohesiva:** La metáfora de "la toalla de hotel" y el personaje de VERA hacen que el reto sea memorable y didáctico.
- **Recomendación:** Ideal para practicar antes de retos forenses de dificultad media donde los covert channels pueden involucrar DNS tunneling, ICMP tunneling o timing channels más sofisticados.

---

*Happy Hacking! 🏴‍☠️*
